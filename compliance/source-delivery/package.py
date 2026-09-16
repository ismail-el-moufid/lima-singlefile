#!/usr/bin/env python3
"""Bounded, offline source delivery. No network calls and no archive extraction."""
import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import shutil
import stat
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
BUNDLE = 'compliance/source-delivery'
MAX_FILE = 128 * 1024 * 1024
MAX_PACKAGE = 256 * 1024 * 1024
MAX_EXPANDED = 1024 * 1024 * 1024
MAX_MEMBERS = 100000
SOURCE_NAMES = {'lima', 'qemu', 'libslirp', 'keycodemapdb',
                'berkeley-softfloat-3', 'berkeley-testfloat-3'}
DEPENDENCIES = ('glib', 'proxy-libintl', 'libffi', 'zlib', 'ninja', 'pkgconf')
WHEELS = ('meson', 'pycotap', 'packaging', 'tomli')
GO_ROOT_FILES = {'LICENSE', 'PATENTS', 'README.md', 'CONTRIBUTING.md',
                 'SECURITY.md', 'VERSION', 'go.env', 'codereview.cfg'}
GO_SOURCE_DIRS = {'src', 'api', 'test', 'misc', 'doc', 'lib'}
GAPS = [
    {'id': 'combined-work-permission', 'status': 'blocked',
     'detail': 'Full combined-work permission blocker persists; source delivery supplies no new grant or redistribution clearance.'},
    {'id': 'modified-static-relink', 'status': 'not-tested',
     'detail': 'No modified GLib/proxy-libintl rebuild, install, final relink or runtime acceptance test was performed for this package.'},
    {'id': 'offline-build', 'status': 'not-demonstrated',
     'detail': '52 binary-selected module archives plus available pinned go.mod metadata are not a proven complete build/test graph.'},
    {'id': 'toolchain-prerequisites', 'status': 'external-prerequisites',
     'detail': 'Locked Go and LLVM binary distributions omitted. bootstrap.py still requires them, Python with venv/ensurepip, and an installed Apple SDK/toolchain. Go source bootstrapping needs an older Go compiler.'},
    {'id': 'go-optional-prebuilt-objects', 'status': 'excluded',
     'detail': 'Host source subset excludes bin/, pkg/ and every .syso, including race/BoringCrypto objects and test fixtures. Optional modes need additional upstream build inputs.'},
    {'id': 'firmware-source', 'status': 'separate-unresolved-audit',
     'detail': 'Original QEMU archive retains bundled firmware bytes/notices; additional firmware archives and unresolved source/build matches remain in compliance/firmware. This package does not close those gaps.'},
    {'id': 'bit-identical-recreation', 'status': 'not-tested',
     'detail': 'No byte-identical recreation claimed; corresponding-source obligations must be assessed under the applicable licenses, not a universal identical-binary rule.'},
    {'id': 'export-integration', 'status': 'pending-main-exporter',
     'detail': 'Main exporter must retain allowlist additions and referenced build/overlay inputs; generating this manifest does not change the exporter.'},
]


def require(value, message):
    if not value:
        raise ValueError(message)


def safe_name(name):
    require(isinstance(name, str) and bool(name), 'Unsafe empty path')
    p = PurePosixPath(name)
    require(name != '.' and not p.is_absolute() and p.as_posix() == name
            and not any(x in {'.', '..', '.git'} for x in p.parts)
            and not any(ord(c) < 32 or c in '\\:' for c in name),
            'Unsafe path: ' + repr(name))
    return name


def safe_path(root, name):
    safe_name(name)
    root = Path(root).absolute()
    require(not any(p.is_symlink() for p in [root, *root.parents]),
            'Symlink root: ' + str(root))
    path = root
    for part in PurePosixPath(name).parts:
        path = path / part
        require(not path.is_symlink(), 'Symlink path: ' + str(path))
    return path


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_record(path):
    require(path.is_file() and not path.is_symlink(), 'Missing regular file: ' + str(path))
    require(path.stat().st_size <= MAX_FILE, 'File exceeds bound: ' + str(path))
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return {'sha256': h.hexdigest(), 'size': path.stat().st_size}


def check_record(path, expected):
    actual = file_record(path)
    require(actual['sha256'] == expected['sha256'], 'SHA-256 mismatch: ' + str(path))
    if 'size' in expected:
        require(actual['size'] == expected['size'], 'Size mismatch: ' + str(path))
    return actual


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON key: ' + key)
        result[key] = value
    return result


def load(path):
    return json.loads(path.read_text(), object_pairs_hook=unique_object)


def publish(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    # Existing bytes must agree; never silently replace another agent/user's work.
    if path.exists():
        require(path.read_bytes() == data, 'Existing output differs: ' + str(path))
        return
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
        temporary = Path(f.name)
        f.write(data)
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def json_data(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def escape(value):
    return ''.join('!' + c.lower() if 'A' <= c <= 'Z' else c for c in value)


def hash1(files):
    h = hashlib.sha256()
    for name, data in sorted(files):
        safe_name(name)
        h.update((sha(data) + '  ' + name + '\n').encode())
    return 'h1:' + base64.b64encode(h.digest()).decode()


def zip_h1(path, prefix=None):
    with zipfile.ZipFile(path) as z:
        members = z.infolist()
        require(len(members) <= MAX_MEMBERS, 'ZIP member bound')
        require(len({m.filename for m in members}) == len(members), 'Duplicate ZIP member')
        require(sum(m.file_size for m in members) <= MAX_EXPANDED, 'ZIP expanded bound')
        files = []
        for m in members:
            safe_name(m.filename.rstrip('/'))
            require(not stat.S_ISLNK(m.external_attr >> 16), 'Symlink ZIP member')
            require(m.file_size <= MAX_FILE, 'ZIP member size bound')
            require(prefix is None or m.filename.startswith(prefix + '/'), 'Wrong module ZIP root')
            files.append((m.filename, z.read(m)))
        return hash1(files)


def tar_members(archive):
    members = archive.getmembers()
    require(len(members) <= MAX_MEMBERS, 'TAR member bound')
    require(sum(m.size for m in members) <= MAX_EXPANDED, 'TAR expanded bound')
    names = set()
    for m in members:
        name = m.name.rstrip('/')
        safe_name(name)
        require(name not in names, 'Duplicate TAR member: ' + name)
        names.add(name)
        require(m.isfile() or m.isdir() or m.issym() or m.islnk(), 'Special TAR member')
        require(m.size <= MAX_FILE, 'TAR member size bound')
        if m.issym() or m.islnk():
            require(not m.linkname.startswith('/') and '\\' not in m.linkname
                    and not any(ord(c) < 32 for c in m.linkname), 'Unsafe TAR link')
            target = posixpath.normpath(posixpath.join(posixpath.dirname(name), m.linkname)
                                       if m.issym() else m.linkname)
            safe_name(target)
            require(target.split('/')[0] == name.split('/')[0], 'Escaping TAR link')
    return members


def go_selected(name):
    parts = PurePosixPath(name).parts
    return (len(parts) >= 2 and parts[0] == 'go' and not name.endswith('.syso')
            and (parts[1] in GO_SOURCE_DIRS or (len(parts) == 2 and parts[1] in GO_ROOT_FILES)))


def derive(root):
    sources = load(safe_path(root, 'sources.lock.json'))['sources']
    deps = load(safe_path(root, 'dependencies.lock.json'))['inputs']
    notices = load(safe_path(root, 'compliance/notices/manifest.json'))
    historical = load(safe_path(root, 'compliance/notices/historical-go.lock.json'))
    require(set(sources) == SOURCE_NAMES, 'Expected exactly six locked sources')
    for key in ('sha256', 'size', 'filename'):
        require(historical[key] == historical['catalog']['file_record'][key], 'Historical catalog mismatch')
    items = []

    def add(origin, destination, kind, expected, **extra):
        actual = check_record(safe_path(root, origin), expected)
        safe_name(destination)
        item = dict(origin=origin, destination=destination, kind=kind, **actual, **extra)
        items.append(item)
        return item

    for name, spec in sorted(sources.items()):
        add('downloads/' + spec['filename'], 'archives/' + spec['filename'],
            'locked-source', spec, component=name, url=spec['url'], lock='sources.lock.json')
    for name in DEPENDENCIES + WHEELS:
        spec = deps[name]
        add('downloads/' + spec['filename'], 'archives/' + spec['filename'],
            'dependency-source' if name in DEPENDENCIES else 'python-build-tool-wheel',
            spec, component=name, url=spec['url'], lock='dependencies.lock.json')
    add('compliance/notices/inputs/' + historical['filename'],
        'archives/' + historical['filename'], 'historical-go-source', historical,
        component=historical['version'], url=historical['url'], lock='compliance/notices/historical-go.lock.json')
    host = add('downloads/' + deps['go']['filename'], 'archives/go1.22.12-source-subset.tar.gz',
               'host-go-source-subset', deps['go'], component='go1.22.12',
               url=deps['go']['url'], lock='dependencies.lock.json', transform='go-source-members-v1')
    host['provenance'] = 'go1.22.12-members.json'

    # Anchor graph metadata to the unmodified, SHA-256-locked Lima archive.
    with tarfile.open(safe_path(root, 'downloads/' + sources['lima']['filename'])) as t:
        graph = {}
        for name in ('go.mod', 'go.sum'):
            graph[name] = t.extractfile(sources['lima']['archive_root'] + '/' + name).read()
            require(graph[name] == safe_path(root, 'src/lima/' + name).read_bytes(), 'Local Lima graph differs from locked original')
    sums = {}
    for line in graph['go.sum'].decode().splitlines():
        name, version, checksum = line.split()
        require((name, version) not in sums or sums[name, version] == checksum, 'Conflicting go.sum')
        sums[name, version] = checksum
    modules = {}
    for binary, spec in notices['binaries'].items():
        for m in spec['modules']:
            key = (m['path'], m['version'])
            if key in modules:
                require(modules[key]['zip_h1'] == m['zip_h1'], 'Conflicting binary module h1')
            else:
                modules[key] = dict(m, binaries=[])
            modules[key]['binaries'].append(binary)
    require(len(modules) == 52, 'Expected 52 unique host+guest modules')
    for (name, version), m in sorted(modules.items()):
        require(sums.get((name, version)) == m['zip_h1'], 'Module not pinned in Lima go.sum')
        relative = escape(name) + '/@v/' + escape(version) + '.zip'
        origin = 'cache/modules/cache/download/' + relative
        path = safe_path(root, origin)
        require(zip_h1(path, name + '@' + version) == m['zip_h1'], 'Module h1 mismatch: ' + name)
        add(origin, 'modules/' + relative, 'go-module', file_record(path),
            module=name, version=version, h1=m['zip_h1'], binaries=sorted(m['binaries']),
            url='https://proxy.golang.org/' + relative, lock='compliance/notices/manifest.json + src/lima/go.sum')
    missing_mod = []
    for (name, version), checksum in sorted(sums.items()):
        if not version.endswith('/go.mod'):
            continue
        version = version[:-7]
        relative = escape(name) + '/@v/' + escape(version) + '.mod'
        origin = 'cache/modules/cache/download/' + relative
        path = safe_path(root, origin)
        if not path.is_file():
            missing_mod.append({'module': name, 'version': version, 'h1': checksum})
            continue
        require(hash1([('go.mod', path.read_bytes())]) == checksum, 'go.mod h1 mismatch: ' + relative)
        add(origin, 'modules/' + relative, 'go-mod-metadata', file_record(path),
            module=name, version=version, h1=checksum, lock='src/lima/go.sum',
            url='https://proxy.golang.org/' + relative)
    # .info is useful to a file:// proxy but is not authenticated by Go h1.
    for name, version in sorted(modules):
        relative = escape(name) + '/@v/' + escape(version) + '.info'
        path = safe_path(root, 'cache/modules/cache/download/' + relative)
        if path.is_file():
            require(load(path)['Version'] == version, 'Wrong cached .info version')
            add('cache/modules/cache/download/' + relative, 'modules/' + relative,
                'go-info-metadata', file_record(path), module=name, version=version,
                authentication='Local SHA-256 only; .info is not covered by Go h1')
    references = {'bootstrap.py', 'build.py', 'build_support.py', 'build_native.py',
                  'link_lima.py', 'prepare_sources.py', 'sources.lock.json',
                  'dependencies.lock.json', 'source-overlays.json', 'build-contract.json',
                  'native/overrides.json', 'src/lima/go.mod', 'src/lima/go.sum',
                  'compliance/notices/manifest.json', 'compliance/notices/historical-go.lock.json',
                  'compliance/notices/inputs/go-release-catalog.json',
                  'compliance/guest-agent/manifest.json', 'compliance/linkage/inventory.json',
                  'compliance/firmware/source-catalog.json', 'compliance/firmware/acquisition-lock.json'}
    for filename, key in [('source-overlays.json', 'overlays'), ('native/overrides.json', 'overrides')]:
        for entry in load(safe_path(root, filename))[key]:
            check_record(safe_path(root, entry['file']), entry)
            references.add(entry['file'])
    refs = [dict(path=p, **file_record(safe_path(root, p))) for p in sorted(references)]
    require(len({i['destination'] for i in items}) == len(items), 'Duplicate destination')
    require(sum(i['size'] for i in items) <= MAX_PACKAGE, 'Acquisition byte bound')
    return {'format': 1, 'network': 'forbidden', 'items': items, 'export_references': refs,
            'missing_go_mod_metadata': missing_mod, 'bounds': {'file_bytes': MAX_FILE,
            'package_bytes': MAX_PACKAGE, 'expanded_archive_bytes': MAX_EXPANDED,
            'archive_members': MAX_MEMBERS}}


def make_go_subset(source, target):
    members = []
    excluded = []
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=target.parent) as temp:
        temporary = Path(temp) / 'subset.tar.gz'
        with tarfile.open(source) as upstream, temporary.open('wb') as raw:
            with gzip.GzipFile(fileobj=raw, filename='', mode='wb', mtime=0) as gz:
                with tarfile.open(fileobj=gz, mode='w|', format=tarfile.PAX_FORMAT) as out:
                    for m in sorted(tar_members(upstream), key=lambda x: x.name):
                        if not m.isfile():
                            continue
                        if not go_selected(m.name):
                            excluded.append({'path': m.name, 'size': m.size})
                            continue
                        data = upstream.extractfile(m).read()
                        members.append({'path': m.name, 'sha256': sha(data), 'size': len(data), 'mode': m.mode})
                        info = tarfile.TarInfo(m.name)
                        info.size, info.mode = len(data), m.mode
                        out.addfile(info, io.BytesIO(data))
        require(any(m['path'] == 'go/src/runtime/runtime.go' for m in members), 'Missing Go runtime source')
        publish(target, temporary.read_bytes())
    return {'format': 1, 'origin': 'downloads/go1.22.12.darwin-amd64.tar.gz',
            'origin_record': file_record(source), 'selection': 'go-source-members-v1',
            'members': members, 'excluded_regular_members': excluded,
            'metadata_policy': 'Contents/names/modes preserved; uid/gid/names/mtime normalized. Not an upstream source release archive.'}


def local_evidence(root):
    paths = ['build/self-contained/qemu/compile_commands.json',
             'build/self-contained/qemu/build.ninja', 'build/self-contained/glib/build.ninja',
             'build/self-contained/glib/compile_commands.json',
             'build/self-contained/native/libqemu-embedded.a',
             'build/self-contained/native/libqemuutil-go.a',
             'build/self-contained/sources/lima/cmd/limactl/native_link_flags.go',
             'build/self-contained/stamps/glib.json',
             'prefix/lib/libglib-2.0.a', 'prefix/lib/libgthread-2.0.a',
             'prefix/lib/libintl.a', 'prefix/lib/libffi.a', 'prefix/lib/libz.a',
             'prefix/lib/libslirp.a']
    evidence = []
    for p in paths:
        path = safe_path(root, p)
        evidence.append(dict(path=p, available=path.is_file(), exported=False,
                             **(file_record(path) if path.is_file() else {})))
    return evidence


def build(root=ROOT):
    bundle = safe_path(root, BUNDLE)
    plan = derive(root)
    # Pin selection before materialization; a differing prior plan fails closed.
    publish(safe_path(bundle, 'acquisition.json'), json_data(plan))
    records = []
    for item in plan['items']:
        source = safe_path(root, item['origin'])
        check_record(source, item)
        target = safe_path(bundle, item['destination'])
        if item['kind'] == 'host-go-source-subset':
            provenance = make_go_subset(source, target)
            p = safe_path(bundle, item['provenance'])
            publish(p, json_data(provenance))
            records.append(dict(path=item['provenance'], kind='member-provenance', **file_record(p)))
        else:
            # Copies are originals, including original notices, not re-tarred extracts.
            if tarfile.is_tarfile(source):
                with tarfile.open(source) as t:
                    tar_members(t)
            elif zipfile.is_zipfile(source):
                zip_h1(source)
            publish(target, source.read_bytes())
        records.append(dict(path=item['destination'], kind=item['kind'], **file_record(target)))
    total = sum(r['size'] for r in records)
    require(total <= MAX_PACKAGE, 'Output byte bound')
    counts = {k: sum(r['kind'] == k for r in records) for k in sorted({r['kind'] for r in records})}
    manifest = {'format': 1, 'acquisition': file_record(bundle / 'acquisition.json'),
                'files': records, 'payload_bytes': total, 'counts': counts,
                'redistribution_cleared': False, 'gaps': GAPS,
                'missing_go_mod_metadata': plan['missing_go_mod_metadata'],
                'local_relink_inputs': local_evidence(root),
                'local_evidence_caution': 'Terminal-inspected live files exist even where older linkage gap prose says unavailable. Presence/hashes do not prove build identity or successful modified relinking; these private artifacts are not shipped.'}
    publish(safe_path(bundle, 'manifest.json'), json_data(manifest))
    additions = []
    for p in sorted(bundle.rglob('*')):
        if p.is_file() and p.name != 'export-allowlist.json' and '__pycache__' not in p.parts:
            relative = p.relative_to(root).as_posix()
            additions.append(dict(path=relative, **file_record(safe_path(root, relative))))
    test = 'tests/test_source_delivery.py'
    additions.append(dict(path=test, **file_record(safe_path(root, test))))
    allowlist = {'format': 1, 'path_base': 'repository-root', 'additions': additions,
                 'required_retained_files': plan['export_references'],
                 'self': BUNDLE + '/export-allowlist.json',
                 'self_hash_policy': 'Exporter hashes this file in its outer manifest; no recursive self-hash.',
                 'permission': 'None conferred. Preserve original third-party notices and existing firmware/notices export selections.'}
    publish(safe_path(bundle, 'export-allowlist.json'), json_data(allowlist))
    print(json.dumps({'counts': counts, 'payload_bytes': total,
                      'missing_go_mod_metadata': len(plan['missing_go_mod_metadata']),
                      'path': str(bundle)}, indent=2))


def verify(root=ROOT, with_inputs=False):
    bundle = safe_path(root, BUNDLE)
    manifest = load(safe_path(bundle, 'manifest.json'))
    check_record(safe_path(bundle, 'acquisition.json'), manifest['acquisition'])
    plan = load(safe_path(bundle, 'acquisition.json'))
    require(manifest['redistribution_cleared'] is False and manifest['gaps'] == GAPS, 'Gap status changed')
    require(plan['network'] == 'forbidden' and len(plan['items']) <= 1000, 'Invalid acquisition scope')
    records = {r['path']: r for r in manifest['files']}
    require(len(records) == len(manifest['files']), 'Duplicate payload path')
    expected = {i['destination'] for i in plan['items']}
    require(len(expected) == len(plan['items']), 'Duplicate acquisition destination')
    expected.update(i['provenance'] for i in plan['items'] if 'provenance' in i)
    require(set(records) == expected, 'Payload/acquisition coverage mismatch')
    require(sum(r['size'] for r in records.values()) == manifest['payload_bytes'] <= MAX_PACKAGE, 'Payload byte count')
    for r in records.values():
        check_record(safe_path(bundle, r['path']), r)
    for item in plan['items']:
        p = safe_path(bundle, item['destination'])
        if with_inputs:
            check_record(safe_path(root, item['origin']), item)
        if item['kind'] != 'host-go-source-subset':
            check_record(p, item)
        if item['kind'] == 'go-module':
            require(zip_h1(p, item['module'] + '@' + item['version']) == item['h1'], 'Packaged module h1 mismatch')
        elif item['kind'] == 'go-mod-metadata':
            require(hash1([('go.mod', p.read_bytes())]) == item['h1'], 'Packaged go.mod h1 mismatch')
        elif item['kind'] == 'host-go-source-subset':
            provenance = load(safe_path(bundle, item['provenance']))
            require(provenance['origin_record'] == {k: item[k] for k in ('sha256', 'size')}, 'Go origin mismatch')
            actual = []
            with tarfile.open(p) as t:
                for member in tar_members(t):
                    require(member.isfile() and go_selected(member.name), 'Non-source Go member')
                    data = t.extractfile(member).read()
                    actual.append(dict(path=member.name, sha256=sha(data), size=len(data), mode=member.mode))
            require(actual == provenance['members'], 'Go member provenance mismatch')
    counts = {k: sum(r['kind'] == k for r in records.values()) for k in sorted({r['kind'] for r in records.values()})}
    require(counts == manifest['counts'], 'Counts mismatch')
    require(counts['locked-source'] == 6 and counts['go-module'] == 52
            and counts['dependency-source'] == 6 and counts['historical-go-source'] == 1
            and counts['host-go-source-subset'] == 1, 'Required source coverage')
    allow = load(safe_path(bundle, 'export-allowlist.json'))
    require(allow['required_retained_files'] == plan['export_references'], 'Export references mismatch')
    names = [r['path'] for r in allow['additions']]
    require(len(names) == len(set(names)), 'Duplicate export addition')
    actual_files = {p.relative_to(root).as_posix() for p in bundle.rglob('*')
                    if p.is_file() and p.name != 'export-allowlist.json' and '__pycache__' not in p.parts}
    require(set(names) == actual_files | {'tests/test_source_delivery.py'}, 'Export addition coverage mismatch')
    for r in allow['additions'] + allow['required_retained_files']:
        check_record(safe_path(root, r['path']), r)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['build', 'verify'])
    parser.add_argument('--with-inputs', action='store_true', help='Also rehash original local caches (not needed by recipient)')
    args = parser.parse_args()
    if args.command == 'build':
        build()
    else:
        m = verify(with_inputs=args.with_inputs)
        print('Verified %d payload files, %d bytes; redistribution remains blocked.' % (len(m['files']), m['payload_bytes']))


if __name__ == '__main__':
    main()
