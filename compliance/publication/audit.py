#!/usr/bin/env python3
"""Offline publication evidence collector. Findings are not release clearance."""
import argparse
import base64
import bz2
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[2]
MIB = 1024 * 1024
PATTERNS = {
    'private-key-marker': rb'-----BEGIN (?:[A-Z0-9]+ )*(?:PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----|PuTTY-User-Key-File-[23]:',
    'aws-access-key-shape': rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b',
    'github-token-shape': rb'\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{40,255})\b',
    'slack-token-shape': rb'\bxox[baprs]-[A-Za-z0-9-]{20,255}',
    'google-api-key-shape': rb'\bAIza[0-9A-Za-z_-]{35}\b',
    'jwt-shape': rb'\beyJ[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{8,2048}',
    'credential-url-shape': rb'(?i)\b(?:https?|ssh|postgres(?:ql)?|mysql|mongodb|redis)://[^\s/:@<>"\x27]{1,100}:[^\s/@<>"\x27]{1,200}@',
    'credential-assignment-shape': rb'(?i)\b(?:aws_secret_access_key|client_secret|api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd)\b[\x20\t"\x27]{0,4}[:=][\x20\t]{0,4}["\x27][^\r\n"\x27]{8,200}["\x27]',
}
RULES = {name: re.compile(pattern) for name, pattern in PATTERNS.items()}
# All file content is withheld, including likely false positives and upstream keys.
LIMITATIONS = [
    'Heuristic credential shapes are not comprehensive; no entropy, DER key, encrypted/encoded secret, or semantic credential validation.',
    'No network, revocation checks, remote-ref query, signatures, or license/redistribution permission determination.',
    'Public-byte classification means exact member SHA-256 equality to locally locked upstream bytes; locks are trust inputs, not independent signatures.',
    'Git scope is locally advertised refs, HEAD, reflog-reachable objects and all index stages; expired reflogs, unreachable objects and unrelated repositories are excluded.',
    'Git commit/tag bytes are scanned, but reflog messages, Git config, hooks, LFS remote content and submodule repositories are not scanned.',
    'Repository working-tree/untracked bytes are not implied by an index/history audit; only an explicit candidate scan covers a candidate working tree.',
    'ZIP, TAR, gzip, bzip2 and xz are inspected without extraction. Unsupported containers, bound hits and invalid members remain coverage findings.',
    'Binary signatures and filenames are triage hints, not proof of unintended artifacts; firmware and upstream binary test fixtures require review.',
    'This is a bounded point-in-time observation, not an atomic snapshot; before/after fingerprints detect observed changes, not adversarial races.',
    'Archive links are never followed. Sparse and special members are not expanded. An upstream match never suppresses the original finding.',
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def text(data):
    return data.decode('utf-8', 'surrogateescape')


def safe_name(name):
    return (isinstance(name, str) and bool(name) and not name.startswith('/')
            and not re.match(r'^[A-Za-z]:', name) and '\\' not in name
            and not any(ord(c) < 32 or ord(c) == 127 for c in name)
            and all(p not in ('', '.', '..') for p in name.split('/')))


def safe_link(name, target, hard=False):
    if not target or target.startswith('/') or '\\' in target or re.match(r'^[A-Za-z]:', target):
        return False
    if any(ord(c) < 32 or ord(c) == 127 for c in target):
        return False
    stack = [] if hard else name.split('/')[:-1]
    for part in target.split('/'):
        if part == '..':
            if not stack:
                return False
            stack.pop()
        elif part not in ('', '.'):
            stack.append(part)
    return True


class AuditError(Exception):
    def __init__(self, kind, **details):
        super().__init__(kind)
        self.record = dict(type=kind, **details)


@dataclass
class Limits:
    file_bytes: int = 128 * MIB
    expanded_bytes: int = 1024 * MIB
    stream_bytes: int = 512 * MIB
    members: int = 100000
    depth: int = 8
    seconds: int = 120
    git_seconds: int = 60
    git_batch_bytes: int = 16 * MIB


class Budget:
    def __init__(self, limits):
        self.limits = limits
        self.bytes = 0
        self.members = 0
        self.started = time.monotonic()

    def check(self):
        if time.monotonic() - self.started > self.limits.seconds:
            raise AuditError('archive-time-bound')

    def charge(self, count):
        self.check()
        self.bytes += count
        if self.bytes > self.limits.expanded_bytes:
            raise AuditError('archive-expanded-byte-bound')

    def member(self):
        self.check()
        self.members += 1
        if self.members > self.limits.members:
            raise AuditError('archive-member-bound')


def bounded_read(stream, cap, budget=None):
    chunks, size = [], 0
    while True:
        if budget:
            budget.check()
        block = stream.read(min(MIB, cap - size + 1))
        if not block:
            return b''.join(chunks)
        size += len(block)
        if budget:
            budget.charge(len(block))
        if size > cap:
            raise AuditError('file-or-stream-byte-bound')
        chunks.append(block)


def read_regular(path, cap):
    # Do not dereference any symlink component, including the last component.
    path = Path(os.path.abspath(path))
    for part in (path, *path.parents):
        if part.is_symlink():
            raise AuditError('filesystem-symlink-not-followed', path=str(path))
    before = path.stat()
    if not stat.S_ISREG(before.st_mode):
        raise AuditError('filesystem-special-file', path=str(path))
    if before.st_size > cap:
        raise AuditError('filesystem-file-byte-bound', path=str(path), size=before.st_size)
    with path.open('rb') as stream:
        data = bounded_read(stream, cap)
    after = path.stat()
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
        raise AuditError('filesystem-file-changed', path=str(path))
    return data


def archive_kind(data, path):
    lower = path.lower()
    if data.startswith(b'\x1f\x8b'):
        return 'gzip'
    if data.startswith(b'BZh'):
        return 'bzip2'
    if data.startswith(b'\xfd7zXZ\x00'):
        return 'xz'
    if data.startswith((b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08')) or lower.endswith(('.zip', '.whl', '.jar')):
        return 'zip'
    if data[257:262] == b'ustar' or lower.endswith('.tar'):
        return 'tar'
    if lower.endswith(('.gz', '.tgz', '.bz2', '.tbz2', '.xz', '.txz')):
        return 'invalid-compressed'
    if data.startswith((b'7z\xbc\xaf\x27\x1c', b'Rar!', b'\x28\xb5\x2f\xfd', b'!<arch>\n')) or lower.endswith(('.7z', '.rar', '.zst', '.lz', '.lzma', '.cpio', '.rpm', '.deb', '.iso', '.dmg')):
        return 'unsupported'
    return None


def artifact_types(path, data):
    name = path.lower().split('!')[-1]
    parts = name.split('/')
    base = parts[-1]
    types = []
    if any(p in ('.ssh', '.aws', '.gnupg', '.kube', '.docker', '.lima', '.git') for p in parts) or base in ('.netrc', '.env', 'credentials', 'id_rsa', 'id_ed25519', 'id_dsa', 'authorized_keys'):
        types.append('sensitive-path')
    if name.endswith(('.qcow', '.qcow2', '.vmdk', '.vdi', '.vhd', '.vhdx', '.vmem', '.vmsn', '.sav', '.img', '.iso')) or data.startswith((b'QFI\xfb', b'KDMV', b'vhdxfile')):
        types.append('vm-disk-or-state-shape')
    if name.endswith(('.pid', '.sock', '.socket', '.log', '.pyc', '.o', '.a', '.dylib', '.so', '.exe', '.dll', '.dmp', '.core')) or base in ('.ds_store', 'build.ninja', 'compile_commands.json', 'cmakecache.txt') or any(p in ('__pycache__', '.venv', 'node_modules') for p in parts):
        types.append('generated-or-build-artifact-shape')
    if data.startswith((b'\x7fELF', b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xce', b'MZ', b'\xca\xfe\xba\xbe')):
        types.append('executable-binary-magic')
    return types


class Scanner:
    def __init__(self, limits=None, inspect=True, on_bytes=None, trusted_members=None):
        self.trusted_members = trusted_members or {}
        self.limits = limits or Limits()
        self.inspect = inspect
        self.on_bytes = on_bytes
        self.findings = []
        self.archives = []
        self.counts = Counter()

    def finding(self, kind, path, context, digest=None, **extra):
        self.findings.append(dict(type=kind, path=path, **context, **({'sha256': digest} if digest else {}), **extra))

    def scan(self, data, path, context=None, depth=0, budget=None, source_member=False):
        context = context or {}
        budget = budget or Budget(self.limits)
        digest = sha(data)
        self.counts['byte_records'] += 1
        self.counts['bytes_including_containers'] += len(data)
        if self.on_bytes:
            self.on_bytes(path, digest, data)
        # Provenance hashes original members, not recursive interpretations of test containers.
        if source_member and not self.inspect:
            return
        if self.inspect:
            for kind in artifact_types(path, data):
                self.finding(kind, path, context, digest)
        kind = archive_kind(data, path)
        if not kind:
            self.counts['leaf_records'] += 1
            if self.inspect:
                for rule, pattern in RULES.items():
                    if pattern.search(data):
                        self.finding(rule, path, context, digest)
            return
        record = dict(path=path, sha256=digest, size=len(data), format=kind, depth=depth, **context)
        self.archives.append(record)
        upstream = self.trusted_members.get(digest, [])
        compressed_vm_fixture = (kind in ('gzip', 'bzip2', 'xz')
            and 'vm-disk-or-state-shape' in artifact_types(path.rsplit('.', 1)[0], b'')
            and any(re.search(r'(?:/|!)(?:tests?|testdata)/', item['member']) for item in upstream))
        if compressed_vm_fixture:
            record.update(status='exact-locked-upstream-test-container-not-expanded',
                          descendant_members=0, expanded_bytes_charged=0, finding_count=1)
            self.finding('exact-locked-upstream-vm-test-container-not-expanded', path, context, digest)
            return
        start_members, start_bytes, start_findings = budget.members, budget.bytes, len(self.findings)
        try:
            budget.check()
            if depth >= self.limits.depth:
                raise AuditError('archive-depth-bound')
            if kind in ('unsupported', 'invalid-compressed'):
                raise AuditError('unsupported-or-invalid-container')
            if kind in ('gzip', 'bzip2', 'xz'):
                opener = {'gzip': gzip.open, 'bzip2': bz2.BZ2File, 'xz': lzma.LZMAFile}[kind]
                with opener(io.BytesIO(data), 'rb') as stream:
                    expanded = bounded_read(stream, self.limits.stream_bytes, budget)
                suffix = path.lower()
                child = path + '!decompressed'
                if suffix.endswith(('.tar.gz', '.tar.bz2', '.tar.xz', '.tgz', '.tbz2', '.txz')):
                    child += '.tar'
                self.scan(expanded, child, context, depth + 1, budget)
            elif kind == 'tar':
                seen = set()
                with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
                    for member in archive:
                        budget.member()
                        name = member.name.rstrip('/')
                        child = path + '!' + name
                        if not safe_name(name):
                            self.finding('unsafe-archive-member-path', child, context, digest, sha256_subject='containing-archive')
                            continue
                        if name in seen:
                            self.finding('duplicate-archive-member', child, context, digest, sha256_subject='containing-archive')
                        seen.add(name)
                        if member.issym() or member.islnk():
                            link = member.linkname.encode('utf-8', 'surrogateescape')
                            self.finding('archive-link-not-followed' if safe_link(name, member.linkname, member.islnk()) else 'unsafe-archive-link', child, context, sha(link))
                            continue
                        if member.isdir():
                            continue
                        if not member.isfile() or member.issparse():
                            self.finding('special-or-sparse-archive-member', child, context, digest, sha256_subject='containing-archive')
                            continue
                        if member.size > self.limits.file_bytes:
                            self.finding('archive-member-byte-bound', child, context, digest, size=member.size, sha256_subject='containing-archive')
                            continue
                        with archive.extractfile(member) as stream:
                            content = bounded_read(stream, self.limits.file_bytes, budget)
                        self.scan(content, child, context, depth + 1, budget, source_member=True)
            elif kind == 'zip':
                seen = set()
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    if len(archive.infolist()) > self.limits.members:
                        raise AuditError('archive-member-bound')
                    for member in archive.infolist():
                        budget.member()
                        name = member.filename.rstrip('/')
                        child = path + '!' + name
                        if not safe_name(name):
                            self.finding('unsafe-archive-member-path', child, context, digest, sha256_subject='containing-archive')
                            continue
                        if name in seen:
                            self.finding('duplicate-archive-member', child, context, digest, sha256_subject='containing-archive')
                        seen.add(name)
                        mode = member.external_attr >> 16
                        if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)):
                            self.finding('zip-link-or-special-member-not-followed', child, context, digest, sha256_subject='containing-archive')
                            continue
                        if member.is_dir():
                            continue
                        if member.flag_bits & 1:
                            self.finding('encrypted-archive-member', child, context, digest, sha256_subject='containing-archive')
                            continue
                        if member.file_size > self.limits.file_bytes:
                            self.finding('archive-member-byte-bound', child, context, digest, size=member.file_size, sha256_subject='containing-archive')
                            continue
                        with archive.open(member) as stream:
                            content = bounded_read(stream, self.limits.file_bytes, budget)
                        self.scan(content, child, context, depth + 1, budget, source_member=True)
            record['status'] = 'bounded-inspection-complete'
        except (AuditError, OSError, EOFError, ValueError, RuntimeError, tarfile.TarError, zipfile.BadZipFile, NotImplementedError) as exc:
            issue = exc.record['type'] if isinstance(exc, AuditError) else 'invalid-or-unreadable-archive'
            self.finding(issue, path, context, digest)
            record['status'] = 'incomplete'
        record['descendant_members'] = budget.members - start_members
        record['expanded_bytes_charged'] = budget.bytes - start_bytes
        record['finding_count'] = len(self.findings) - start_findings


class GitReader:
    def __init__(self, repository, limits=None):
        self.repository = Path(repository).resolve()
        self.limits = limits or Limits()
        self.commands = []
        self.env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        self.env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_SYSTEM=os.devnull,
                        GIT_CONFIG_GLOBAL=os.devnull, GIT_OPTIONAL_LOCKS='0',
                        GIT_TERMINAL_PROMPT='0', GIT_NO_REPLACE_OBJECTS='1',
                        GIT_NO_LAZY_FETCH='1', GIT_ALLOW_PROTOCOL='', LC_ALL='C')

    def run(self, arguments, data=None, allowed=(0,)):
        command = ['git', '--no-pager', '--no-optional-locks', '-c', 'core.fsmonitor=false',
                   '-c', 'core.hooksPath=/dev/null', '-c', 'gc.auto=0', '-c', 'maintenance.auto=false',
                   '-c', 'protocol.allow=never', '-C', str(self.repository)] + arguments
        record = dict(arguments=arguments, input_sha256=sha(data) if data is not None else None)
        self.commands.append(record)
        try:
            result = subprocess.run(command, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=self.limits.git_seconds, env=self.env, check=False)
        except subprocess.TimeoutExpired as exc:
            record.update(returncode=None, timeout_seconds=self.limits.git_seconds)
            raise AuditError('git-timeout', arguments=arguments) from exc
        record.update(returncode=result.returncode, stdout_bytes=len(result.stdout),
                      stdout_sha256=sha(result.stdout), stderr_bytes=len(result.stderr), stderr_sha256=sha(result.stderr))
        if result.returncode not in allowed:
            raise AuditError('git-command-failed', arguments=arguments, returncode=result.returncode,
                             stderr_sha256=sha(result.stderr))
        return result.stdout


def parse_entries(data):
    entries = []
    for raw in data.split(b'\0'):
        if raw:
            header, path = raw.split(b'\t', 1)
            a, b, c = header.split()
            if b in (b'blob', b'tree', b'commit'):
                entries.append(dict(mode=text(a), type=text(b), oid=text(c), path=text(path)))
            else:
                entries.append(dict(mode=text(a), oid=text(b), stage=int(c), path=text(path)))
    return entries


def git_snapshot(git):
    result = {}
    for label, args in (
        ('head', ['rev-parse', '--verify', 'HEAD']),
        ('refs', ['for-each-ref', '--format=%(refname) %(objectname) %(objecttype)']),
        ('reflogs', ['reflog', 'show', '--all', '--format=%H %gD']),
        ('index', ['ls-files', '--stage', '-z']),
    ):
        result[label] = git.run(args)
    return result


def audit_git(repository, scanner, git=None):
    git = git or GitReader(repository, scanner.limits)
    report = dict(repository=str(Path(repository).resolve()), scope='existing-local-git-history-and-index', commands=git.commands)
    try:
        report['git_version'] = text(git.run(['--version'])).strip()
        top = text(git.run(['rev-parse', '--show-toplevel'])).strip()
        if Path(top).resolve() != Path(repository).resolve():
            raise AuditError('repository-root-mismatch')
        before = git_snapshot(git)
        report['head'] = text(before['head']).strip()
        report['refs'] = [dict(zip(('name', 'oid', 'type'), text(line).split(' '))) for line in before['refs'].splitlines()]
        report['reflogs'] = [dict(zip(('oid', 'selector'), text(line).split(' ', 1))) for line in before['reflogs'].splitlines()]
        report['index_entries'] = parse_entries(before['index'])
        report['count_objects'] = dict(line.split(': ', 1) for line in text(git.run(['count-objects', '-v'])).splitlines())
        report['shallow'] = text(git.run(['rev-parse', '--is-shallow-repository'])).strip()
        if report['shallow'] != 'false':
            scanner.finding('shallow-history-incomplete', str(repository), {'scope': 'git'})
        refs_raw = git.run(['rev-list', '--objects', '--all', 'HEAD'])
        union_raw = git.run(['rev-list', '--objects', '--all', '--reflog', 'HEAD'])
        ref_ids = {text(line.split(b' ', 1)[0]) for line in refs_raw.splitlines()}
        union_ids = {text(line.split(b' ', 1)[0]) for line in union_raw.splitlines()}
        report['commits_refs'] = text(git.run(['rev-list', '--all', 'HEAD'])).splitlines()
        report['commits_refs_and_reflogs'] = text(git.run(['rev-list', '--all', '--reflog', 'HEAD'])).splitlines()
        paths = defaultdict(set)
        modes = defaultdict(set)
        index_ids = set()
        for entry in report['index_entries']:
            if entry['mode'] == '160000':
                scanner.finding('gitlink-not-traversed', entry['path'], {'scope': 'git-index', 'oid': entry['oid']})
                continue
            paths[entry['oid']].add(entry['path'])
            modes[entry['oid']].add(entry['mode'])
            index_ids.add(entry['oid'])
            if entry['stage']:
                scanner.finding('unmerged-index-stage', entry['path'], {'scope': 'git-index', 'oid': entry['oid']})
        tree_fingerprints = {}
        for commit in report['commits_refs_and_reflogs']:
            raw = git.run(['ls-tree', '-r', '-z', '--full-tree', commit])
            tree_fingerprints[commit] = sha(raw)
            for entry in parse_entries(raw):
                paths[entry['oid']].add(entry['path'])
                modes[entry['oid']].add(entry['mode'])
                if entry['type'] == 'commit':
                    scanner.finding('gitlink-not-traversed', entry['path'], {'scope': 'git-history', 'oid': entry['oid']})
        report['commit_tree_listing_sha256'] = tree_fingerprints
        all_ids = sorted(union_ids | index_ids)
        raw = git.run(['cat-file', '--batch-check'], ('\n'.join(all_ids) + '\n').encode())
        objects = []
        for line in raw.splitlines():
            fields = text(line).split()
            if len(fields) != 3 or fields[1] not in ('blob', 'tree', 'commit', 'tag'):
                raise AuditError('missing-or-invalid-git-object-metadata', metadata_sha256=sha(line))
            oid, kind, size = fields
            objects.append(dict(oid=oid, type=kind, size=int(size), paths=sorted(paths[oid]), modes=sorted(modes[oid]),
                                reachable_from_refs_or_head=oid in ref_ids, reachable_from_reflogs_only=oid in union_ids - ref_ids,
                                in_index=oid in index_ids))
        if len(objects) != len(all_ids) or [x['oid'] for x in objects] != all_ids:
            raise AuditError('git-object-inventory-mismatch')
        report['objects'] = objects
        report['counts'] = dict(objects_refs_or_head=len(ref_ids), objects_refs_head_reflogs=len(union_ids),
                                objects_reflogs_only=len(union_ids - ref_ids), index_entries=len(report['index_entries']),
                                index_unique_blobs=len(index_ids), index_only_objects=len(index_ids - union_ids),
                                commits_refs=len(report['commits_refs']), commits_refs_and_reflogs=len(report['commits_refs_and_reflogs']),
                                **Counter(x['type'] for x in objects))
        batch, batch_size = [], 0

        def consume(items):
            if not items:
                return
            raw = git.run(['cat-file', '--batch'], ('\n'.join(x['oid'] for x in items) + '\n').encode())
            stream = io.BytesIO(raw)
            for item in items:
                fields = text(stream.readline()).strip().split()
                if fields != [item['oid'], item['type'], str(item['size'])]:
                    raise AuditError('git-batch-header-mismatch', oid=item['oid'])
                content = stream.read(item['size'])
                if len(content) != item['size'] or stream.read(1) != b'\n':
                    raise AuditError('git-batch-content-truncated', oid=item['oid'])
                item['sha256'] = sha(content)
                item['scan'] = 'inspected'
                context = dict(scope='git-object', oid=item['oid'], object_type=item['type'], object_paths=item['paths'])
                label = item['paths'][0] if item['paths'] else 'git-object/' + item['oid']
                scanner.scan(content, label, context)
                for alias in item['paths'][1:]:
                    for kind in artifact_types(alias, b''):
                        scanner.finding(kind, alias, context, item['sha256'])
                if '120000' in item['modes']:
                    scanner.finding('git-symlink-target-not-followed', label, context, item['sha256'])
            if stream.read(1):
                raise AuditError('git-batch-trailing-bytes')

        for item in objects:
            if item['type'] == 'tree':
                continue
            if item['size'] > scanner.limits.file_bytes:
                item['scan'] = 'skipped-byte-bound'
                scanner.finding('git-object-byte-bound', 'git-object/' + item['oid'], {'scope': 'git-object', 'oid': item['oid']}, size=item['size'])
                continue
            if batch and batch_size + item['size'] > scanner.limits.git_batch_bytes:
                consume(batch)
                batch, batch_size = [], 0
            batch.append(item)
            batch_size += item['size']
        consume(batch)
        after = git_snapshot(git)
        report['snapshot_fingerprints'] = {k: dict(before_sha256=sha(before[k]), after_sha256=sha(after[k]), equal=before[k] == after[k]) for k in before}
        report['stable_observed_metadata'] = before == after
        if before != after:
            scanner.finding('repository-changed-during-audit', str(repository), {'scope': 'git'})
        report['complete_object_enumeration'] = True
        report['scanned_blob_count'] = sum(x['type'] == 'blob' and x.get('scan') == 'inspected' for x in objects)
    except (AuditError, OSError, ValueError) as exc:
        report['error'] = exc.record if isinstance(exc, AuditError) else {'type': type(exc).__name__}
        report['complete_object_enumeration'] = False
        scanner.finding('git-audit-incomplete', str(repository), {'scope': 'git'})
    return report


def zip_h1(data, prefix, limits=None):
    limits = limits or Limits()
    rows, seen = [], set()
    budget = Budget(limits)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for member in archive.infolist():
            budget.member()
            name = member.filename
            if not safe_name(name.rstrip('/')) or not name.startswith(prefix + '/') or name in seen:
                raise AuditError('invalid-module-zip-path')
            seen.add(name)
            if member.is_dir():
                continue
            if stat.S_IFMT(member.external_attr >> 16) not in (0, stat.S_IFREG) or member.flag_bits & 1:
                raise AuditError('invalid-module-zip-member')
            with archive.open(member) as stream:
                content = bounded_read(stream, limits.file_bytes, budget)
            rows.append((name, sha(content)))
    encoded = ''.join(digest + '  ' + name + '\n' for name, digest in sorted(rows)).encode()
    return 'h1:' + base64.b64encode(hashlib.sha256(encoded).digest()).decode()


class Provenance:
    def __init__(self, root, limits):
        self.root, self.limits = Path(root), limits
        self.members = defaultdict(list)
        self.records = []
        self.issues = []
        self.lock_fingerprints = {}

    def load(self, relative):
        data = read_regular(self.root / relative, self.limits.file_bytes)
        self.lock_fingerprints[relative] = sha(data)
        return json.loads(data)

    def add(self, path, expected, lock, capture=None):
        relative = str(path.relative_to(self.root))
        record = dict(path=relative, lock=lock, expected_sha256=expected)
        self.records.append(record)
        data = read_regular(path, self.limits.file_bytes)
        record['actual_sha256'] = sha(data)
        if sha(data) != expected:
            record['verified'] = False
            raise AuditError('provenance-archive-hash-mismatch', path=relative)
        record['verified'] = True
        staged = defaultdict(list)

        def observe(member, digest, content):
            staged[digest].append(dict(archive=relative, archive_sha256=expected, member=member, lock=lock))
            if capture:
                capture(member, content)

        scanner = Scanner(self.limits, inspect=False, on_bytes=observe)
        scanner.scan(data, relative, {'scope': 'provenance'})
        record['nested_member_containers_hashed_not_expanded'] = True
        record['member_byte_records'] = scanner.counts['byte_records']
        record['coverage_findings'] = scanner.findings
        # Exact inspected member bytes remain useful even when unrelated archive links are skipped.
        for digest, observations in staged.items():
            self.members[digest].extend(observations)
        return data

    def build(self):
        def attempt(function):
            try:
                function()
            except (AuditError, OSError, ValueError, zipfile.BadZipFile) as exc:
                self.issues.append(exc.record if isinstance(exc, AuditError) else {'type': type(exc).__name__})

        sources = self.load('sources.lock.json')
        go_sum = {}

        def capture_lima(path, content):
            if path.endswith('!' + sources['sources']['lima']['archive_root'] + '/go.sum'):
                for line in content.decode().splitlines():
                    module, version, digest = line.split()
                    go_sum[module, version] = digest

        for name, spec in sources['sources'].items():
            if not safe_name(spec['filename']):
                raise AuditError('unsafe-lock-filename')
            attempt(lambda name=name, spec=spec: self.add(self.root / 'downloads' / spec['filename'], spec['sha256'], 'sources.lock.json', capture_lima if name == 'lima' else None))
        deps = self.load('dependencies.lock.json')
        for name, spec in deps['inputs'].items():
            if not safe_name(spec['filename']):
                raise AuditError('unsafe-lock-filename')
            if name == 'go' or spec['filename'].endswith(('.tar.gz', '.tar.xz', '.whl')) and name != 'llvm':
                attempt(lambda spec=spec: self.add(self.root / 'downloads' / spec['filename'], spec['sha256'], 'dependencies.lock.json'))
        historical = self.load('compliance/notices/historical-go.lock.json')
        if not safe_name(historical['filename']):
            raise AuditError('unsafe-lock-filename')
        attempt(lambda: self.add(self.root / 'compliance/source-delivery/archives' / historical['filename'], historical['sha256'], 'compliance/notices/historical-go.lock.json'))
        acquisition = self.load('compliance/source-delivery/acquisition.json')
        for item in acquisition['items']:
            if item['kind'] != 'go-module':
                continue

            def module(item=item):
                if not safe_name(item['destination']):
                    raise AuditError('unsafe-module-destination')
                path = self.root / 'compliance/source-delivery' / item['destination']
                data = read_regular(path, self.limits.file_bytes)
                expected = go_sum.get((item['module'], item['version']))
                if not expected or expected != item['h1'] or zip_h1(data, item['module'] + '@' + item['version'], self.limits) != expected:
                    raise AuditError('module-not-authenticated-by-locked-lima-go-sum', path=str(path.relative_to(self.root)))
                self.add(path, sha(data), 'sources.lock.json -> exact Lima go.sum -> ' + expected)
                self.records[-1]['go_h1'] = expected
            attempt(module)
        self.lock_fingerprints_after = {}
        for relative, digest in self.lock_fingerprints.items():
            after = sha(read_regular(self.root / relative, self.limits.file_bytes))
            self.lock_fingerprints_after[relative] = after
            if digest != after:
                raise AuditError('provenance-lock-changed', path=relative)

    def classify(self, finding):
        matches = self.members.get(finding.get('sha256'), [])
        if not matches:
            finding['classification'] = 'unresolved-review-required'
            return
        finding['upstream_exact_matches'] = matches
        finding['provenance_match_subject'] = finding.get('sha256_subject', 'reported-byte-record')
        if finding.get('sha256_subject') == 'containing-archive':
            finding['classification'] = 'exact-locked-upstream-container-bytes'
            finding['clearance'] = False
            return
        # Test naming is only a role hint; exact bytes, not that hint, establish provenance.
        test_role = any(re.search(r'(?i)(?:/|!)(?:tests?|testdata|crypto/testsuite)(?:/|!)', m['member']) for m in matches)
        finding['classification'] = 'exact-locked-upstream-test-bytes' if test_role else 'exact-locked-upstream-bytes'
        finding['clearance'] = False


def audit_directory(root, scanner, scope, expected=None, skip_git=False):
    root = Path(root)
    report = dict(root=str(root.resolve()), scope=scope, files=[], skipped_directories=[])
    expected = expected or {}
    observed = set()
    if root.is_symlink() or not root.is_dir():
        scanner.finding('missing-or-symlink-audit-directory', str(root), {'scope': scope})
        return report
    for current, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs[:]):
            path = Path(current) / name
            relative = str(path.relative_to(root))
            if path.is_symlink() or skip_git and name == '.git':
                dirs.remove(name)
                report['skipped_directories'].append(relative)
                if path.is_symlink():
                    scanner.finding('filesystem-symlink-not-followed', relative, {'scope': scope})
        dirs.sort()
        for name in sorted(files):
            path = Path(current) / name
            relative = str(path.relative_to(root))
            observed.add(relative)
            context = {'scope': scope}
            try:
                data = read_regular(path, scanner.limits.file_bytes)
                record = dict(path=relative, sha256=sha(data), size=len(data))
                report['files'].append(record)
                if relative in expected:
                    entry = expected[relative]
                    record['manifest_match'] = entry['sha256'] == sha(data) and entry['size'] == len(data)
                    if not record['manifest_match']:
                        scanner.finding('saved-payload-manifest-mismatch', relative, context, sha(data))
                scanner.scan(data, relative, context)
            except (AuditError, OSError) as exc:
                scanner.finding(exc.record['type'] if isinstance(exc, AuditError) else 'filesystem-read-error', relative, context)
    for missing in sorted(set(expected) - observed):
        scanner.finding('saved-payload-missing', missing, {'scope': scope})
    report['file_count'] = len(report['files'])
    report['bytes'] = sum(item['size'] for item in report['files'])
    report['expected_payload_count'] = len(expected)
    return report


def summarize(report):
    findings = report['findings']
    report['summary'] = dict(findings=len(findings), by_type=dict(sorted(Counter(x['type'] for x in findings).items())),
                             by_scope=dict(sorted(Counter(x['scope'] for x in findings).items())),
                             by_classification=dict(sorted(Counter(x['classification'] for x in findings).items())))
    report['publication_cleared'] = False
    report['status'] = 'review-required'
    report['blockers'] = [
        'Audit findings and unsupported/skipped coverage require explicit review; no automatic clearance.',
        'The existing repository is not the new review export. Its refs/history must not be represented as a future candidate audit.',
        'A separate audit of the completed output/source-publication-review-20260915 candidate remains required unless explicitly recorded here.',
        'Credential heuristics and exact public-byte matches do not resolve combined-work permission or other release-review blockers.',
    ]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, default=ROOT / 'output/source-publication')
    parser.add_argument('--candidate', type=Path, help='Separately scan all working-tree bytes without following links; exclude .git directories.')
    parser.add_argument('--no-repository', action='store_true')
    parser.add_argument('--no-workspace-payloads', action='store_true')
    args = parser.parse_args(argv)
    limits = Limits()
    scanner = Scanner(limits)
    report = dict(format=1, started_utc=datetime.now(timezone.utc).isoformat(), network='forbidden',
                  writes='compliance/publication/history-audit.json only', limits=asdict(limits), limitations=LIMITATIONS,
                  future_candidate='output/source-publication-review-20260915', candidate_audited=False)
    provenance = Provenance(ROOT, limits)
    try:
        provenance.build()
    except (AuditError, OSError, ValueError, KeyError) as exc:
        provenance.issues.append(exc.record if isinstance(exc, AuditError) else {'type': type(exc).__name__})
    report['provenance'] = dict(archives=provenance.records, issues=provenance.issues,
                                lock_sha256=provenance.lock_fingerprints,
                                lock_sha256_after=getattr(provenance, 'lock_fingerprints_after', {}),
                                authority='Existing local source/dependency locks and locked Lima archive go.sum; no new network authentication. Firmware observed acquisition pins are not used to classify keys as public.')
    report['scanner_sha256'] = sha(read_regular(Path(__file__), limits.file_bytes))
    scanner.trusted_members = provenance.members
    if not args.no_repository:
        report['repository'] = audit_git(args.repository, scanner)
    if not args.no_workspace_payloads:
        delivery = ROOT / 'compliance/source-delivery'
        try:
            manifest_bytes = read_regular(delivery / 'manifest.json', limits.file_bytes)
            manifest = json.loads(manifest_bytes)
            expected = {x['path']: x for x in manifest['files']}
            report['saved_source_delivery'] = audit_directory(delivery, scanner, 'current-workspace-source-delivery', expected)
            report['saved_source_delivery']['manifest_sha256'] = sha(manifest_bytes)
        except (AuditError, OSError, ValueError, KeyError) as exc:
            scanner.finding('source-delivery-audit-incomplete', str(delivery), {'scope': 'current-workspace-source-delivery'})
        firmware_expected = {}
        try:
            firmware_lock_bytes = read_regular(ROOT / 'compliance/firmware/acquisition-lock.json', limits.file_bytes)
            firmware_lock = json.loads(firmware_lock_bytes)
            firmware_expected = {x['path'][len('sources/'):]: x for x in firmware_lock['inputs'] if x['path'].startswith('sources/')}
            report['firmware_observed_acquisition_lock_sha256'] = sha(firmware_lock_bytes)
        except (AuditError, OSError, ValueError, KeyError):
            scanner.finding('firmware-acquisition-lock-unreadable', 'compliance/firmware/acquisition-lock.json', {'scope': 'current-workspace-firmware-sources'})
        report['saved_firmware_sources'] = audit_directory(ROOT / 'compliance/firmware/sources', scanner, 'current-workspace-firmware-sources', firmware_expected)
    if args.candidate:
        report['candidate'] = audit_directory(args.candidate, scanner, 'candidate-working-tree', skip_git=True)
        report['candidate_audited'] = True
    for finding in scanner.findings:
        provenance.classify(finding)
    report['findings'], report['archives'] = scanner.findings, scanner.archives
    report['scanner_counts'] = dict(scanner.counts)
    report['finished_utc'] = datetime.now(timezone.utc).isoformat()
    summarize(report)
    output = ROOT / 'compliance/publication/history-audit.json'
    if output.is_symlink():
        raise AuditError('refuse-report-symlink')
    output.write_text(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + '\n')
    print(json.dumps(dict(report=str(output.relative_to(ROOT)), status=report['status'], publication_cleared=False,
                          git_counts=report.get('repository', {}).get('counts'), summary=report['summary']), sort_keys=True))
    return 1  # Evidence completion is deliberately not release clearance.


if __name__ == '__main__':
    raise SystemExit(main())
