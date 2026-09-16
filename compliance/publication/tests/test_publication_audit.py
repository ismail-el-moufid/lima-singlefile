import base64
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import unittest
from unittest.mock import patch
import zipfile

SPEC = importlib.util.spec_from_file_location('publication_audit', Path(__file__).resolve().parents[1] / 'audit.py')
audit = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = audit
SPEC.loader.exec_module(audit)


def key():
    return b'-----BEGIN ' + b'RSA PRIVATE KEY-----\nfixture-only-never-a-real-key\n'


def tar(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w') as archive:
        for name, value in entries:
            info = tarfile.TarInfo(name)
            if isinstance(value, tuple):
                info.type, info.linkname = value
                archive.addfile(info)
            else:
                info.size = len(value)
                archive.addfile(info, io.BytesIO(value))
    return out.getvalue()


def zipped(entries):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return out.getvalue()


class ScannerTests(unittest.TestCase):
    def scan(self, data, name='input', limits=None):
        scanner = audit.Scanner(limits)
        scanner.scan(data, name, {'scope': 'test'})
        return scanner

    def test_private_key_redacted(self):
        scanner = self.scan(key())
        self.assertEqual(scanner.findings[0]['type'], 'private-key-marker')
        self.assertNotIn('fixture-only', json.dumps(scanner.findings))
        self.assertEqual(scanner.findings[0]['sha256'], audit.sha(key()))

    def test_nested_zip_compressed_tar(self):
        data = zipped([('sources.tar.gz', gzip.compress(tar([('test/key.pem', key())])))])
        scanner = self.scan(data, 'bundle.zip')
        self.assertTrue(any(f['type'] == 'private-key-marker' and '!test/key.pem' in f['path'] for f in scanner.findings))
        self.assertEqual(len(scanner.archives), 3)

    def test_unsafe_member_and_escaping_link(self):
        data = tar([('../escape', key()), ('/absolute', key()), ('C:/x', key()), ('a\\b', key()),
                    ('safe/link', (tarfile.SYMTYPE, '../../outside'))])
        scanner = self.scan(data, 'sources.tar')
        self.assertEqual(sum(f['type'] == 'unsafe-archive-member-path' for f in scanner.findings), 4)
        self.assertIn('unsafe-archive-link', [f['type'] for f in scanner.findings])

    def test_duplicate_member_scans_both(self):
        scanner = self.scan(tar([('x', b'ok'), ('x', key())]), 'x.tar')
        self.assertEqual({f['type'] for f in scanner.findings}, {'duplicate-archive-member', 'private-key-marker'})

    def test_member_size_bound(self):
        scanner = self.scan(tar([('x', b'x' * 20)]), 'x.tar', audit.Limits(file_bytes=10))
        self.assertIn('archive-member-byte-bound', [f['type'] for f in scanner.findings])

    def test_expansion_and_depth_bounds(self):
        scanner = self.scan(gzip.compress(b'x' * 1000), 'x.gz', audit.Limits(expanded_bytes=20))
        self.assertIn('archive-expanded-byte-bound', [f['type'] for f in scanner.findings])
        scanner = self.scan(gzip.compress(gzip.compress(key())), 'x.gz', audit.Limits(depth=1))
        self.assertIn('archive-depth-bound', [f['type'] for f in scanner.findings])

    def test_member_count_bound(self):
        scanner = self.scan(tar([('a', b'a'), ('b', b'b')]), 'x.tar', audit.Limits(members=1))
        self.assertIn('archive-member-bound', [f['type'] for f in scanner.findings])

    def test_corrupt_and_unsupported(self):
        for name, data in [('x.zip', b'PK\x03\x04broken'), ('x.gz', b'\x1f\x8bgarbage'), ('x.zst', b'opaque')]:
            scanner = self.scan(data, name)
            self.assertEqual(scanner.archives[0]['status'], 'incomplete')
            self.assertTrue(scanner.findings)

    def test_vm_and_executable(self):
        self.assertIn('vm-disk-or-state-shape', audit.artifact_types('renamed', b'QFI\xfbmore'))
        self.assertIn('executable-binary-magic', audit.artifact_types('tool', b'\x7fELFmore'))

    def test_public_match_requires_exact_hash(self):
        provenance = audit.Provenance(Path('.'), audit.Limits())
        provenance.members[audit.sha(key())].append({'archive': 'locked.tar', 'archive_sha256': 'a' * 64,
                                                    'member': 'locked.tar!tests/key.pem', 'lock': 'sources.lock.json'})
        yes = self.scan(key()).findings[0]
        no = self.scan(key() + b'changed').findings[0]
        provenance.classify(yes)
        provenance.classify(no)
        self.assertEqual(yes['classification'], 'exact-locked-upstream-test-bytes')
        self.assertFalse(yes['clearance'])
        self.assertEqual(no['classification'], 'unresolved-review-required')

    def test_module_h1_and_mutation(self):
        name = 'example.org/m@v1/a'
        expected = 'h1:' + base64.b64encode(hashlib.sha256((audit.sha(b'abc') + '  ' + name + '\n').encode()).digest()).decode()
        self.assertEqual(audit.zip_h1(zipped([(name, b'abc')]), 'example.org/m@v1'), expected)
        self.assertNotEqual(audit.zip_h1(zipped([(name, b'abd')]), 'example.org/m@v1'), expected)
        with self.assertRaises(audit.AuditError):
            audit.zip_h1(zipped([('../escape', b'abc')]), 'example.org/m@v1')

    def test_git_nul_paths_and_index_stages(self):
        oid = 'a' * 40
        raw = ('100644 ' + oid + ' 2\tnew\nline\0').encode()
        self.assertEqual(audit.parse_entries(raw)[0], dict(mode='100644', oid=oid, stage=2, path='new\nline'))
        raw = ('120000 blob ' + oid + '\tlink\0').encode()
        self.assertEqual(audit.parse_entries(raw)[0]['type'], 'blob')

    def test_git_readonly_environment_and_error_redaction(self):
        with patch.dict('os.environ', {'GIT_DIR': '/bad', 'GIT_CONFIG_COUNT': '1'}):
            reader = audit.GitReader(Path('.'))
        result = subprocess.CompletedProcess([], 128, b'', b'never-show-this-secret')
        with patch.object(audit.subprocess, 'run', return_value=result) as run:
            with self.assertRaises(audit.AuditError) as raised:
                reader.run(['rev-parse', '--verify', 'HEAD'])
            args, kwargs = run.call_args
            self.assertIn('--no-pager', args[0])
            self.assertIn('--no-optional-locks', args[0])
            self.assertIn('core.fsmonitor=false', args[0])
            self.assertEqual(kwargs['env']['GIT_ALLOW_PROTOCOL'], '')
            self.assertNotIn('GIT_DIR', kwargs['env'])
            self.assertNotIn('GIT_CONFIG_COUNT', kwargs['env'])
            self.assertEqual(kwargs['timeout'], 60)
            self.assertNotIn('never-show', json.dumps(raised.exception.record))
            self.assertNotIn('never-show', json.dumps(reader.commands))

    def test_git_timeout(self):
        reader = audit.GitReader(Path('.'))
        with patch.object(audit.subprocess, 'run', side_effect=subprocess.TimeoutExpired('git', 60)):
            with self.assertRaises(audit.AuditError):
                reader.run(['rev-parse', 'HEAD'])
        self.assertEqual(reader.commands[0]['timeout_seconds'], 60)

    def test_provenance_hashes_members_without_expanding_test_bombs(self):
        seen = {}
        scanner = audit.Scanner(audit.Limits(expanded_bytes=20000), inspect=False,
                                on_bytes=lambda path, digest, data: seen.update({path: digest}))
        scanner.scan(tar([('tests/disk.img.gz', gzip.compress(b'x' * 100000)),
                          ('tests/later.pem', key())]), 'locked.tar')
        self.assertIn('locked.tar!tests/later.pem', seen)
        self.assertFalse(scanner.findings)

    def test_exact_vm_fixture_skip_is_explicit_and_hash_gated(self):
        data = gzip.compress(b'QFI\xfb' + b'x' * 1000)
        scanner = audit.Scanner(trusted_members={audit.sha(data): [{'member': 'locked.tar!tests/disk.qcow2.gz'}]})
        scanner.scan(data, 'tests/disk.qcow2.gz', {'scope': 'test'})
        self.assertEqual(scanner.findings[0]['type'], 'exact-locked-upstream-vm-test-container-not-expanded')
        scanner = audit.Scanner()
        scanner.scan(data, 'tests/disk.qcow2.gz', {'scope': 'test'})
        self.assertNotIn('exact-locked-upstream-vm-test-container-not-expanded', [f['type'] for f in scanner.findings])
        self.assertIn('vm-disk-or-state-shape', [f['type'] for f in scanner.findings])

    def test_full_git_audit_includes_history_reflog_and_index_only_blobs(self):
        c1, c2, b1, b2, b3 = (c * 40 for c in 'abcde')
        index = ('100644 ' + b1 + ' 0\tcurrent\0' + '100644 ' + b3 + ' 0\tstaged-only\0').encode()
        tree1 = ('100644 blob ' + b1 + '\tcurrent\0').encode()
        tree2 = ('100644 blob ' + b2 + '\tdeleted\nkey\0').encode()
        objects = {c1: ('commit', b'old commit'), c2: ('commit', b'reflog commit'),
                   b1: ('blob', b'ordinary'), b2: ('blob', key()), b3: ('blob', b'staged')}
        repository = Path('.').resolve()

        class FakeGit:
            commands = []

            def run(self, args, data=None):
                if args == ['--version']:
                    return b'git fixture\n'
                if args == ['rev-parse', '--show-toplevel']:
                    return str(repository).encode() + b'\n'
                if args == ['rev-parse', '--verify', 'HEAD']:
                    return (c1 + '\n').encode()
                if args[0] == 'for-each-ref':
                    return ('refs/heads/main ' + c1 + ' commit\n').encode()
                if args[0] == 'reflog':
                    return (c2 + ' HEAD@{0}\n').encode()
                if args[0] == 'ls-files':
                    return index
                if args[0] == 'count-objects':
                    return b'count: 5\n'
                if args == ['rev-parse', '--is-shallow-repository']:
                    return b'false\n'
                if args[0] == 'rev-list':
                    ids = [c1, b1] if '--objects' in args else [c1]
                    if '--reflog' in args:
                        ids += [c2, b2] if '--objects' in args else [c2]
                    return ('\n'.join(ids) + '\n').encode()
                if args[0] == 'ls-tree':
                    return tree1 if args[-1] == c1 else tree2
                if args[0] == 'cat-file':
                    rows = []
                    for oid in data.decode().splitlines():
                        kind, content = objects[oid]
                        rows.append((oid + ' ' + kind + ' ' + str(len(content)) + '\n').encode())
                        if args[1] == '--batch':
                            rows.append(content + b'\n')
                    return b''.join(rows)
                raise AssertionError(args)

        scanner = audit.Scanner()
        report = audit.audit_git(repository, scanner, FakeGit())
        self.assertTrue(report['complete_object_enumeration'])
        self.assertTrue(report['stable_observed_metadata'])
        self.assertEqual(report['counts']['objects_reflogs_only'], 2)
        self.assertEqual(report['counts']['index_only_objects'], 1)
        self.assertEqual(report['scanned_blob_count'], 3)
        finding = next(f for f in scanner.findings if f['type'] == 'private-key-marker')
        self.assertEqual(finding['oid'], b2)
        self.assertEqual(finding['path'], 'deleted\nkey')

    def test_safe_links(self):
        self.assertTrue(audit.safe_link('a/b', '../c'))
        self.assertFalse(audit.safe_link('a', '../c'))
        self.assertFalse(audit.safe_link('a/b', '../c', hard=True))

    def test_no_automatic_clearance(self):
        report = {'findings': []}
        audit.summarize(report)
        self.assertFalse(report['publication_cleared'])
        self.assertEqual(report['status'], 'review-required')


if __name__ == '__main__':
    unittest.main()
