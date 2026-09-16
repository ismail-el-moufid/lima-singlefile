"""Offline fixtures for the read-only firmware archive evidence tool."""

import bz2
import contextlib
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import audit_firmware as audit


class FirmwareArchiveTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.archive = Path(directory.name) / "qemu.tar"
        self.blob = b"firstsecond"
        self.manifest = {
            "format": 1,
            "resources": [
                {
                    "name": "first.bin",
                    "offset": 0,
                    "size": 5,
                    "sha256": audit.sha256(b"first"),
                },
                {
                    "name": "second.bin",
                    "offset": 5,
                    "size": 6,
                    "sha256": audit.sha256(b"second"),
                },
            ],
        }

    def bundle(self, entries):
        with tarfile.open(self.archive, "w") as bundle:
            for name, data in entries:
                member = tarfile.TarInfo("qemu/pc-bios/" + name)
                if data is None:
                    member.type = tarfile.SYMTYPE
                    member.linkname = "first.bin"
                    bundle.addfile(member)
                else:
                    member.size = len(data)
                    bundle.addfile(member, io.BytesIO(data))
        return {
            "filename": "qemu.tar",
            "revision": "fixture",
            "archive_root": "qemu",
            "sha256": audit.sha256(self.archive.read_bytes()),
        }

    def compare(self, spec):
        return audit.compare_archive(self.manifest, self.blob, self.archive, spec)

    def test_direct_and_compressed_members_match_without_clearance(self):
        spec = self.bundle(
            [("first.bin", b"first"), ("second.bin.bz2", bz2.compress(b"second"))]
        )
        report = self.compare(spec)
        self.assertEqual(report["matches"], ["first.bin", "second.bin"])
        self.assertEqual(report["matched_count"], 2)
        self.assertEqual(report["discrepancies"], [])
        self.assertIs(report["source_provenance_cleared"], False)
        self.assertIs(report["redistribution_cleared"], False)

    def test_renamed_notice_resources_use_original_archive_paths(self):
        self.blob = b"noticenoticenotice"
        self.manifest["resources"] = []
        paths = {
            "firmware-COPYING": "COPYING",
            "firmware-COPYING.LIB": "COPYING.LIB",
            "firmware-notices.txt": "pc-bios/README",
        }
        spec = self.bundle([])
        with tarfile.open(self.archive, "w") as bundle:
            for index, (name, path) in enumerate(paths.items()):
                member = tarfile.TarInfo("qemu/" + path)
                member.size = 6
                bundle.addfile(member, io.BytesIO(b"notice"))
                self.manifest["resources"].append(
                    {
                        "name": name,
                        "offset": index * 6,
                        "size": 6,
                        "sha256": audit.sha256(b"notice"),
                    }
                )
        spec["sha256"] = audit.sha256(self.archive.read_bytes())
        report = self.compare(spec)
        self.assertEqual(report["matches"], sorted(paths))
        self.assertEqual(report["discrepancies"], [])

    def test_missing_and_changed_assets_remain_explicit(self):
        report = self.compare(self.bundle([("first.bin", b"changed")]))
        self.assertEqual(report["matched_count"], 0)
        changed, missing = report["discrepancies"]
        self.assertEqual(changed["status"], "differs_from_archive")
        self.assertEqual(changed["archive_sha256"], audit.sha256(b"changed"))
        self.assertEqual(missing["status"], "missing_from_archive")
        self.assertEqual(missing["name"], "second.bin")

    def test_corrupt_archive_and_blob_are_rejected(self):
        spec = self.bundle([])
        self.archive.write_bytes(b"corrupt")
        with self.assertRaisesRegex(ValueError, "Input checksum mismatch"):
            self.compare(spec)
        self.blob = b"wrongsecond"
        with self.assertRaisesRegex(ValueError, "Embedded resource checksum mismatch"):
            self.compare(spec)

    def test_duplicate_ambiguous_and_symlink_members_are_rejected(self):
        for entries in (
            [("first.bin", b"first"), ("first.bin", b"first")],
            [("first.bin", b"first"), ("first.bin.bz2", bz2.compress(b"first"))],
            [("first.bin", None)],
        ):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                self.compare(self.bundle(entries))

    def test_invalid_resource_names_bounds_and_duplicates_are_rejected(self):
        original = self.manifest["resources"][0].copy()
        for changes in (
            {"name": "../escape"},
            {"name": "/absolute"},
            {"name": "first//bin"},
            {"offset": -1},
            {"offset": 99},
            {"size": -1},
            {"size": True},
            {"name": "second.bin"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.manifest["resources"][0] = dict(original, **changes)
                audit.resource_records(self.manifest, self.blob)

    def test_cli_distinguishes_discrepancies_from_invalid_inputs(self):
        for differences, expected in (
            ([], 0),
            ([{"status": "missing_from_archive"}], 2),
        ):
            with mock.patch.object(
                audit, "audit", return_value={"discrepancies": differences}
            ):
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(audit.main([]), expected)
                self.assertEqual(
                    json.loads(output.getvalue())["discrepancies"], differences
                )
        with mock.patch.object(audit, "audit", side_effect=ValueError("bad checksum")):
            with contextlib.redirect_stderr(io.StringIO()) as output:
                self.assertEqual(audit.main([]), 1)
            self.assertIn("bad checksum", output.getvalue())


class ProjectEvidenceTests(unittest.TestCase):
    def test_stored_report_matches_locked_inputs_and_keeps_known_gaps(self):
        root = audit.ROOT
        report = json.loads(
            (root / "compliance/firmware/archive-comparison.json").read_text()
        )
        spec = json.loads((root / "sources.lock.json").read_text())["sources"]["qemu"]
        self.assertEqual(
            report["archive"],
            {
                key: spec[key]
                for key in ("filename", "revision", "sha256", "archive_root")
            },
        )
        resource_dir = root / audit.RESOURCE_DIR
        for name, key in (
            ("manifest.json", "manifest_sha256"),
            ("builtin-data.bin", "blob_sha256"),
        ):
            self.assertEqual(
                audit.sha256((resource_dir / name).read_bytes()), report[key]
            )
        resources = json.loads((resource_dir / "manifest.json").read_text())[
            "resources"
        ]
        expected = {item["name"] for item in resources}
        differences = {item["name"]: item["status"] for item in report["discrepancies"]}
        self.assertEqual(
            differences,
            {
                "edk2-i386-vars.fd": "differs_from_archive",
                "edk2-i386-secure-vars.fd": "missing_from_archive",
            },
        )
        self.assertEqual(report["resource_count"], 77)
        self.assertEqual(report["matched_count"], 75)
        self.assertEqual(len(report["matches"]), 75)
        self.assertEqual(set(report["matches"]) | set(differences), expected)
        self.assertFalse(set(report["matches"]) & set(differences))
        self.assertIs(report["source_provenance_cleared"], False)
        self.assertIs(report["redistribution_cleared"], False)


if __name__ == "__main__":
    unittest.main()
