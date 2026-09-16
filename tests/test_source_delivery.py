"""Offline source-delivery integrity, hostile input and honest-gap tests."""

import importlib.util
import io
import json
import stat
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "source_delivery", ROOT / "compliance/source-delivery/package.py"
)
package = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(package)


class SourceDeliveryTests(unittest.TestCase):
    def test_actual_package_bytes_and_original_pins(self):
        manifest = package.verify(ROOT)
        self.assertEqual(manifest["counts"]["locked-source"], 6)
        self.assertEqual(manifest["counts"]["go-module"], 52)
        self.assertEqual(manifest["counts"]["dependency-source"], 6)
        self.assertGreater(manifest["counts"]["go-mod-metadata"], 52)
        self.assertGreater(manifest["payload_bytes"], 50 * 1024 * 1024)
        self.assertLessEqual(manifest["payload_bytes"], package.MAX_PACKAGE)
        plan = package.load(ROOT / package.BUNDLE / "acquisition.json")
        selected = {
            (i["module"], i["version"])
            for i in plan["items"]
            if i["kind"] == "go-module"
        }
        notices = package.load(ROOT / "compliance/notices/manifest.json")
        expected = {
            (m["path"], m["version"])
            for b in notices["binaries"].values()
            for m in b["modules"]
        }
        self.assertEqual(selected, expected)
        host = next(i for i in plan["items"] if i["kind"] == "host-go-source-subset")
        self.assertNotEqual(
            host["destination"].split("/")[-1], host["origin"].split("/")[-1]
        )
        provenance = package.load(ROOT / package.BUNDLE / host["provenance"])
        self.assertTrue(any(m["path"] == "go/LICENSE" for m in provenance["members"]))
        self.assertTrue(
            any(m["path"].startswith("go/src/runtime/") for m in provenance["members"])
        )
        self.assertFalse(
            any(
                "/bin/" == m["path"][:5]
                or m["path"].startswith(("go/bin/", "go/pkg/"))
                or m["path"].endswith(".syso")
                for m in provenance["members"]
            )
        )

    def test_gap_status_is_explicit_and_not_clearance(self):
        manifest = package.load(ROOT / package.BUNDLE / "manifest.json")
        self.assertIs(manifest["redistribution_cleared"], False)
        self.assertEqual(manifest["gaps"], package.GAPS)
        gaps = {g["id"]: g["status"] for g in manifest["gaps"]}
        self.assertEqual(gaps["combined-work-permission"], "blocked")
        self.assertEqual(gaps["modified-static-relink"], "not-tested")
        self.assertEqual(gaps["offline-build"], "not-demonstrated")
        self.assertEqual(gaps["export-integration"], "pending-main-exporter")
        # Availability describes the producer snapshot, not the recipient checkout.
        for item in manifest["local_relink_inputs"]:
            self.assertIs(item["exported"], False)
            self.assertIsInstance(item["available"], bool)
            if item["available"]:
                self.assertEqual(len(item["sha256"]), 64)
                self.assertGreater(item["size"], 0)

    def test_original_producer_inputs_when_available(self):
        plan = package.load(ROOT / package.BUNDLE / "acquisition.json")
        manifest = package.load(ROOT / package.BUNDLE / "manifest.json")
        records = [(item["origin"], item) for item in plan["items"]]
        records.extend(
            (item["path"], item)
            for item in manifest["local_relink_inputs"]
            if item["available"]
        )
        missing = []
        for name, record in records:
            path = package.safe_path(ROOT, name)
            if path.exists():
                package.check_record(path, record)
            else:
                missing.append(name)
        if missing:
            self.skipTest(
                "Producer-only inputs unavailable: %d (first: %s)"
                % (len(missing), missing[0])
            )

    def test_tampered_payload_is_rejected(self):
        plan = package.load(ROOT / package.BUNDLE / "acquisition.json")
        item = next(i for i in plan["items"] if i["component"] == "proxy-libintl")
        original = (ROOT / package.BUNDLE / item["destination"]).read_bytes()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "archive.tar.gz"
            path.write_bytes(original)
            package.check_record(path, item)
            path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                package.check_record(path, item)

    def test_go_h1_is_computed_from_bytes_not_ziphash(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "module.zip"
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("example.org/m@v1.0.0/go.mod", "module example.org/m\n")
            expected = package.hash1(
                [("example.org/m@v1.0.0/go.mod", b"module example.org/m\n")]
            )
            self.assertEqual(package.zip_h1(path, "example.org/m@v1.0.0"), expected)
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("example.org/m@v1.0.0/go.mod", "module tampered\n")
            self.assertNotEqual(package.zip_h1(path, "example.org/m@v1.0.0"), expected)
            self.assertNotEqual(
                package.hash1([("go.mod", b"a")]), package.hash1([("go.mod", b"b")])
            )

    def test_unsafe_filesystem_paths(self):
        for value in [
            "",
            ".",
            "..",
            "../outside",
            "/absolute",
            "a/../b",
            "a//b",
            "a/./b",
            "a\\b",
            "C:/outside",
            "a\nb",
            "a\x00b",
            ".git/config",
        ]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                package.safe_name(value)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "real").mkdir()
            (root / "link").symlink_to(root / "real", target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "Symlink"):
                package.safe_path(root, "link/archive")
            with self.assertRaisesRegex(ValueError, "Symlink"):
                package.safe_path(root / "link", "archive")

    def test_unsafe_zip_members_and_wrong_module_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.zip"
            for name in ["../escape", "/absolute", "root/../../escape", "root\\escape"]:
                with zipfile.ZipFile(path, "w") as z:
                    z.writestr(name, b"x")
                with self.subTest(name=name), self.assertRaises(ValueError):
                    package.zip_h1(path)
            with zipfile.ZipFile(path, "w") as z:
                info = zipfile.ZipInfo("module/link")
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                z.writestr(info, "../escape")
            with self.assertRaisesRegex(ValueError, "Symlink"):
                package.zip_h1(path)
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("wrong@v1.0.0/file", b"x")
            with self.assertRaisesRegex(ValueError, "Wrong module"):
                package.zip_h1(path, "right@v1.0.0")

    def test_unsafe_tar_paths_links_special_files_and_duplicates(self):
        for name, kind, link in [
            ("../escape", tarfile.REGTYPE, ""),
            ("root/link", tarfile.SYMTYPE, "../../escape"),
            ("root/link", tarfile.LNKTYPE, "/absolute"),
            ("root/device", tarfile.CHRTYPE, ""),
        ]:
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode="w") as t:
                info = tarfile.TarInfo(name)
                info.type, info.linkname = kind, link
                t.addfile(info)
            data.seek(0)
            with tarfile.open(fileobj=data) as t, self.subTest(name=name, kind=kind):
                with self.assertRaises(ValueError):
                    package.tar_members(t)
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w") as t:
            t.addfile(tarfile.TarInfo("root/duplicate"))
            t.addfile(tarfile.TarInfo("root/duplicate"))
        data.seek(0)
        with (
            tarfile.open(fileobj=data) as t,
            self.assertRaisesRegex(ValueError, "Duplicate"),
        ):
            package.tar_members(t)

    def test_refuses_different_existing_outputs_and_duplicate_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "output"
            package.publish(p, b"original")
            package.publish(p, b"original")
            with self.assertRaisesRegex(ValueError, "Existing output differs"):
                package.publish(p, b"replacement")
            self.assertEqual(p.read_bytes(), b"original")
        with self.assertRaisesRegex(ValueError, "Duplicate JSON key"):
            json.loads(
                '{"path":"a","path":"b"}', object_pairs_hook=package.unique_object
            )


if __name__ == "__main__":
    unittest.main()
