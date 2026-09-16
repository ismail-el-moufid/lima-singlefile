"""Offline retained-source evidence tests; no firmware builds or network."""
import bz2
import contextlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / 'compliance/firmware'
sys.path.insert(0, str(HERE))
import inventory
import acquire


class InputTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)

    def fixture(self):
        path = self.directory / 'source.tar.gz'
        data = b'implementation source'
        with tarfile.open(path, 'w:gz', format=tarfile.PAX_FORMAT,
                          pax_headers={'comment': 'a' * 40}) as bundle:
            member = tarfile.TarInfo('source/Makefile')
            member.size = len(data)
            bundle.addfile(member, io.BytesIO(data))
        item = dict(inventory.identity(path.read_bytes()), path=path.name,
                    kind='source_archive', revision='a' * 40,
                    archive_root='source', required_members=['Makefile'],
                    member_evidence={'Makefile': inventory.sha(data)},
                    url='https://gitlab.com/qemu-project/example/source.tar.gz')
        self.lock = {'inputs': [item]}
        self.save()
        return path, item

    def save(self):
        (self.directory / 'acquisition-lock.json').write_text(json.dumps(self.lock))

    def test_archive_commit_and_member_hashes_are_verified(self):
        path, item = self.fixture()
        self.assertEqual(inventory.verify_inputs(self.directory), self.lock)
        item['revision'] = 'b' * 40
        self.save()
        with self.assertRaisesRegex(ValueError, 'commit metadata'):
            inventory.verify_inputs(self.directory)
        item['revision'] = 'a' * 40
        item['member_evidence']['Makefile'] = '0' * 64
        self.save()
        with self.assertRaisesRegex(ValueError, 'member checksum'):
            inventory.verify_inputs(self.directory)
        path.write_bytes(b'corrupted')
        with self.assertRaisesRegex(ValueError, 'Evidence checksum'):
            inventory.verify_inputs(self.directory)

    def test_unsafe_paths_and_symlinks_rejected(self):
        for name in ('../escape', '/absolute', 'a/../b', 'a//b'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                inventory.safe_path(self.directory, name)
        link = self.directory / 'link'
        link.symlink_to(self.directory / 'missing')
        with self.assertRaises(ValueError):
            inventory.safe_path(self.directory, 'link')

    def test_bzip2_rejects_incomplete_or_concatenated_streams(self):
        compressed = bz2.compress(b'firmware')
        self.assertEqual(inventory.decompressed_identity(compressed), inventory.identity(b'firmware'))
        for data in (compressed[:-2], compressed + compressed):
            with self.assertRaises(ValueError):
                inventory.decompressed_identity(data)

    def test_acquisition_never_downloads_or_overwrites_existing_files(self):
        path, _ = self.fixture()
        with mock.patch.object(acquire.subprocess, 'run') as run:
            acquire.acquire(self.directory)
            run.assert_not_called()
            path.write_bytes(b'user data')
            with self.assertRaisesRegex(ValueError, 'refusing overwrite'):
                acquire.acquire(self.directory)
            run.assert_not_called()
            self.assertEqual(path.read_bytes(), b'user data')

    def test_unfamiliar_assets_are_not_silently_covered(self):
        self.assertEqual(inventory.classify('new-firmware.bin'), 'unclassified')
        self.assertEqual(inventory.classify('edk2-aarch64-secure-code.fd.bz2'), 'edk2')
        self.assertEqual(inventory.classify('QEMU,tcx.bin'), 'openbios')
        self.assertEqual(inventory.classify('vof-nvram.bin'), 'vof-nvram')

    def test_cli_consistency_does_not_imply_clearance(self):
        report = {'source_provenance_cleared': False, 'redistribution_cleared': False}
        with mock.patch.object(inventory, 'generate', return_value=report):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(inventory.main([]), 2)
            self.assertEqual(json.loads(output.getvalue()), report)


class ProjectInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # One complete offline regeneration checks the real archive, blob and sources.
        cls.report = inventory.generate()

    def test_stored_report_is_exact_and_covers_every_retained_file(self):
        self.assertEqual(self.report, json.loads((HERE / 'retained-inventory.json').read_text()))
        files = {p.relative_to(ROOT).as_posix() for p in (ROOT / 'src/qemu/pc-bios').rglob('*') if p.is_file()}
        self.assertEqual({r['path'] for r in self.report['retained_files']}, files)
        self.assertEqual(self.report['unclassified_paths'], [])
        self.assertTrue(all(r['archive_status'] == 'matches' for r in self.report['retained_files']))
        self.assertEqual(self.report['archive_files_not_retained'], [])

    def test_vars_and_clearance_gates_remain_unresolved(self):
        self.assertFalse(self.report['source_provenance_cleared'])
        self.assertFalse(self.report['redistribution_cleared'])
        self.assertFalse(self.report['firmware_rebuilt'])
        expected = json.loads((HERE / 'archive-comparison.json').read_text())['discrepancies']
        self.assertEqual(self.report['embedded_discrepancies'], expected)
        self.assertEqual(len(self.report['embedded_resources']), 77)
        self.assertEqual(sum(r['archive_status'] != 'matches' for r in self.report['embedded_resources']), 2)
        self.assertTrue(all(not g['source_provenance_cleared'] for g in self.report['groups'].values()))

    def test_candidate_archives_do_not_substitute_current_pins(self):
        sources = {s['revision']: s for s in self.report['acquired_sources']}
        groups = self.report['groups']
        self.assertEqual(len(sources), 11)
        for name, revision in (
            ('ipxe-legacy', '7aee315f61aaf1be6d2fff26339f28a1137231a5'),
            ('slof', 'ee03aec2c106a699aaddd2d3dd52cbd7b7e8d544'),
            ('seabios-hppa', '1c516b481339f511d83a4afba9a48d1ac904e93e'),
        ):
            self.assertIn(sources[revision]['path'], groups[name]['acquired_source_archives'])
            self.assertNotEqual(revision, groups[name]['locked_tree_gitlink_candidate_only']['revision'])
        self.assertEqual(groups['edk2']['acquired_source_archives'], [])
        self.assertIn('20d2e5a125e34fc8501026613a71549b2a1a3e54', sources)
        self.assertTrue(all(not s['nested_sources_complete'] for s in sources.values()))

    def test_historical_x86_blob_matches_and_non_x86_scope(self):
        rows = self.report['retained_files']
        for group, count in (('ipxe-legacy', 6), ('ipxe-efi', 8), ('qboot', 1)):
            selected = [r for r in rows if r['group'] == group]
            self.assertEqual(len(selected), count)
            self.assertTrue(all(any(e['matches'] for e in r['historical_byte_evidence']) for r in selected))
        groups = {r['group'] for r in rows}
        self.assertTrue({'openbios', 'opensbi', 'slof', 'skiboot', 'seabios-hppa',
                         'u-boot-e500', 'u-boot-sam460', 'palcode', 'mac-drivers',
                         's390', 'vof', 'vof-nvram', 'pnv-nvram', 'vbootrom',
                         'device-trees'}.issubset(groups))


if __name__ == '__main__':
    unittest.main()
