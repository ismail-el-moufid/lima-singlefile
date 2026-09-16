#!/usr/bin/env python3
"""Offline retained firmware/source evidence; no extraction, builds or clearance."""
import argparse
import base64
import bz2
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import audit_firmware


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(data):
    return {"size": len(data), "sha256": sha(data)}


def git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def safe_path(base, name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or '..' in path.parts or str(path) != name:
        raise ValueError("Unsafe input path: " + name)
    result = base / name
    if result.is_symlink() or not result.resolve().is_relative_to(base.resolve()):
        raise ValueError("Input escapes evidence directory: " + name)
    return result


def verify_inputs(directory=HERE):
    lock = json.loads((directory / 'acquisition-lock.json').read_text())
    for item in lock['inputs']:
        path = safe_path(directory, item['path'])
        if identity(path.read_bytes()) != {k: item[k] for k in ('size', 'sha256')}:
            raise ValueError('Evidence checksum mismatch: ' + item['path'])
        if item['kind'] == 'source_archive':
            with tarfile.open(path) as bundle:
                if bundle.pax_headers.get('comment') != item['revision']:
                    raise ValueError('Archive commit metadata mismatch: ' + item['path'])
                names = set()
                for member in bundle:
                    if member.name in names:
                        raise ValueError('Duplicate source archive member: ' + member.name)
                    names.add(member.name)
                    p = PurePosixPath(member.name)
                    if p.is_absolute() or '..' in p.parts or p.parts[0] != item['archive_root']:
                        raise ValueError('Unexpected source archive member: ' + member.name)
                for relative in item['required_members']:
                    member = bundle.getmember(item['archive_root'] + '/' + relative)
                    if not member.isfile():
                        raise ValueError('Missing regular source member: ' + relative)
                    if sha(bundle.extractfile(member).read()) != item['member_evidence'][relative]:
                        raise ValueError('Source member checksum mismatch: ' + relative)
    return lock


def classify(name):
    """Never silently classify an unfamiliar top-level asset as covered."""
    if '/' in name:
        first = name.split('/')[0]
        return {'keymaps': 'keymaps', 'descriptors': 'descriptors',
                'optionrom': 'qemu-optionrom', 's390-ccw': 's390',
                'vof': 'vof'}.get(first, 'unclassified')
    if name in ('bios.bin', 'bios-256k.bin', 'bios-microvm.bin') or name.startswith('vgabios'):
        return 'seabios'
    if name.startswith('pxe-'):
        return 'ipxe-legacy'
    if name.startswith('efi-'):
        return 'ipxe-efi'
    if name == 'qboot.rom':
        return 'qboot'
    if name.startswith('edk2-'):
        return 'edk2'
    if name.startswith('openbios-') or name in ('QEMU,tcx.bin', 'QEMU,cgthree.bin'):
        return 'openbios'
    if name.startswith('opensbi-'):
        return 'opensbi'
    if name.startswith('hppa-firmware'):
        return 'seabios-hppa'
    if name.startswith('npcm'):
        return 'vbootrom'
    if name.endswith(('.dtb', '.dts')):
        return 'device-trees'
    return {
        'slof.bin': 'slof', 'skiboot.lid': 'skiboot', 'pnv-pnor.bin': 'pnv-nvram',
        'palcode-clipper': 'palcode', 'qemu_vga.ndrv': 'mac-drivers',
        'u-boot.e500': 'u-boot-e500', 'u-boot-sam460-20100605.bin': 'u-boot-sam460',
        's390-ccw.img': 's390', 'vof.bin': 'vof', 'vof-nvram.bin': 'vof-nvram',
        'kvmvapic.bin': 'qemu-optionrom', 'linuxboot.bin': 'qemu-optionrom',
        'linuxboot_dma.bin': 'qemu-optionrom', 'multiboot.bin': 'qemu-optionrom',
        'multiboot_dma.bin': 'qemu-optionrom', 'pvh.bin': 'qemu-optionrom',
        'README': 'support', 'meson.build': 'support', 'qemu-nsis.bmp': 'artwork',
        'qemu-nsis.ico': 'artwork', 'qemu.rsrc': 'artwork', 'qemu_logo.svg': 'artwork',
        'firmware-COPYING': 'support', 'firmware-COPYING.LIB': 'support',
        'firmware-notices.txt': 'support',
    }.get(name, 'unclassified')


def historical_records(directory=HERE):
    records = {}
    for path in sorted((directory / 'evidence').glob('*.json')):
        data = json.loads(path.read_text())
        if not isinstance(data, dict) or 'files' not in data:
            continue
        for entry in data['files']:
            if entry['filename'].startswith('pc-bios/'):
                records.setdefault(entry['filename'][8:], []).append({
                    'evidence': str(path.relative_to(directory)),
                    'qemu_commit': data['sha'], 'git_blob_sha1': entry['sha'],
                })
    return records


def decompressed_identity(data):
    decoder = bz2.BZ2Decompressor()
    plain = decoder.decompress(data, max_length=128 * 1024 * 1024 + 1)
    if len(plain) > 128 * 1024 * 1024 or not decoder.eof or decoder.unused_data:
        raise ValueError('Oversized, incomplete or concatenated bzip2 firmware')
    return identity(plain)


def generate(root=ROOT, directory=HERE):
    lock = verify_inputs(directory)
    catalog = json.loads((directory / 'source-catalog.json').read_text())
    comparison = audit_firmware.audit(root=root)
    spec = json.loads((root / 'sources.lock.json').read_text())['sources']['qemu']
    history = historical_records(directory)
    pc_bios = root / 'src/qemu/pc-bios'
    retained = {}
    for path in sorted(pc_bios.rglob('*')):
        if path.is_symlink():
            raise ValueError('Unexpected retained symlink: ' + str(path))
        if path.is_file():
            name = path.relative_to(pc_bios).as_posix()
            data = path.read_bytes()
            row = {'path': 'src/qemu/pc-bios/' + name, 'group': classify(name),
                   **identity(data), 'archive_status': 'not_in_archive'}
            if name.endswith('.bz2'):
                row['decompressed'] = decompressed_identity(data)
            if name in history:
                row['historical_byte_evidence'] = [
                    dict(record, matches=git_blob(data) == record['git_blob_sha1'])
                    for record in history[name]
                ]
            if '/' not in name and row['group'] not in ('support', 'artwork', 'edk2'):
                strings = re.findall(rb'[ -~]{8,}', data)
                signals = [s.decode('ascii') for s in strings if re.search(
                    rb'rel-1\.16\.3|iPXE v1\.|gcc:|GCC:|U-Boot 20|powerpc-linux-gcc', s)]
                if signals:
                    row['version_string_evidence'] = signals
            retained[name] = row
    prefix = spec['archive_root'] + '/pc-bios/'
    seen = set()
    archive_only = []
    with tarfile.open(root / 'downloads' / spec['filename']) as bundle:
        for member in bundle:
            if not member.name.startswith(prefix) or member.isdir():
                continue
            name = member.name[len(prefix):]
            if name in seen or not member.isfile():
                raise ValueError('Ambiguous/non-regular pc-bios archive member: ' + name)
            seen.add(name)
            if name not in retained:
                archive_only.append(name)
                continue
            record = retained[name]
            record['archive_member'] = member.name
            record['archive_identity'] = identity(bundle.extractfile(member).read())
            record['archive_status'] = ('matches' if record['archive_identity'] ==
                                        {k: record[k] for k in ('size', 'sha256')}
                                        else 'differs')
    manifest = json.loads((root / audit_firmware.RESOURCE_DIR / 'manifest.json').read_text())
    discrepancies = {r['name']: r for r in comparison['discrepancies']}
    embedded = []
    for item in manifest['resources']:
        name = item['name']
        embedded.append({k: item[k] for k in ('name', 'size', 'sha256')} | {
            'group': classify(name),
            'archive_status': discrepancies.get(name, {}).get('status', 'matches'),
        })
    recipes = {}
    for path in sorted((root / 'src/qemu/roms').iterdir()):
        if path.is_file():
            recipes[str(path.relative_to(root))] = identity(path.read_bytes())
    return {
        'format': 1,
        'scope': 'All retained pc-bios regular files plus all embedded resources; not a publication/staging audit',
        'source_provenance_cleared': False, 'redistribution_cleared': False,
        'firmware_rebuilt': False,
        'qemu_archive': comparison['archive'],
        'catalog_sha256': sha((directory / 'source-catalog.json').read_bytes()),
        'acquisition_lock_sha256': sha((directory / 'acquisition-lock.json').read_bytes()),
        'acquired_sources': [x for x in lock['inputs'] if x['kind'] == 'source_archive'],
        'retained_file_count': len(retained), 'retained_files': list(retained.values()),
        'archive_files_not_retained': sorted(archive_only),
        'embedded_resources': embedded, 'embedded_discrepancies': comparison['discrepancies'],
        'recipe_files': recipes,
        'groups': catalog['groups'],
        'unclassified_paths': [r['path'] for r in retained.values() if r['group'] == 'unclassified'],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Compare stored inventory; 0 means evidence consistency only')
    args = parser.parse_args(argv)
    try:
        report = generate()
        if args.check:
            if report != json.loads((HERE / 'retained-inventory.json').read_text()):
                raise ValueError('Stored inventory differs; investigate before regenerating')
            print('Firmware inventory consistent; source/redistribution gates remain unresolved.')
            return 0
        print(json.dumps(report, indent=2, sort_keys=True))
        return 2
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print('firmware inventory: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
