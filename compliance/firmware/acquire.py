#!/usr/bin/env python3
"""Verify frozen firmware evidence, or reacquire missing pinned source archives."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from inventory import HERE, identity, safe_path, verify_inputs


def acquire(directory=HERE):
    lock = json.loads((directory / 'acquisition-lock.json').read_text())
    for item in lock['inputs']:
        if item['kind'] != 'source_archive':
            continue
        path = safe_path(directory, item['path'])
        expected = {key: item[key] for key in ('size', 'sha256')}
        if path.exists():
            if identity(path.read_bytes()) != expected:
                raise ValueError('Existing archive differs; refusing overwrite: ' + str(path))
            continue
        if not item['url'].startswith('https://gitlab.com/qemu-project/'):
            raise ValueError('Unapproved source endpoint in acquisition lock')
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=path.parent, suffix='.part', delete=False) as stream:
                temporary = Path(stream.name)
            subprocess.run([
                'curl', '--fail', '--silent', '--show-error', '--location',
                '--proto', '=https', '--proto-redir', '=https',
                '--connect-timeout', '15', '--max-time', '90',
                '--max-filesize', str(item['size']), item['url'], '-o', str(temporary),
            ], check=True, timeout=95)
            if identity(temporary.read_bytes()) != expected:
                raise ValueError('Downloaded archive checksum mismatch: ' + item['path'])
            # A racing writer must not be overwritten, even with matching bytes.
            os.link(temporary, path)
            print('Acquired ' + item['path'])
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    verify_inputs(directory)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fetch', action='store_true', help='Network: fetch only missing locked source archives, never refresh metadata')
    args = parser.parse_args(argv)
    try:
        if args.fetch:
            acquire()
        else:
            verify_inputs()
        print('Frozen evidence verified; firmware source completeness is NOT established.')
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('firmware acquisition: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
