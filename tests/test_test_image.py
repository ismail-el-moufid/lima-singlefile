"""Offline fixture/validator tests; never invoke QEMU or start a VM.

Run: python3 -B -m unittest discover -s tests -p test_test_image.py -v
"""

import builtins
import hashlib
import json
import re
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "tests"))
import validate_native as native

import fetch_test_image as image


def fixture_spec(data):
    return {
        "url": "https://example.invalid/fixture.iso",
        "filename": "fixture.iso",
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }


class TestImageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = b"offline image fixture\0\xff\n"
        self.path = self.root / "fixture.iso"
        self.path.write_bytes(self.data)
        self.spec = fixture_spec(self.data)
        self.lock = self.root / "fixtures.lock.json"
        self.save()

    def save(self):
        self.lock.write_text(
            json.dumps({"format": 1, "fixtures": {image.FIXTURE: self.spec}})
        )

    def test_import_has_no_bootstrap_or_filesystem_write_side_effects(self):
        original_import = builtins.__import__

        def checked_import(name, *args, **kwargs):
            if name == "bootstrap":
                raise AssertionError("bootstrap must be imported lazily")
            return original_import(name, *args, **kwargs)

        with (
            mock.patch("builtins.__import__", side_effect=checked_import),
            mock.patch.object(
                Path, "mkdir", side_effect=AssertionError("unexpected write")
            ),
            mock.patch.object(
                Path, "read_text", side_effect=AssertionError("unexpected lock read")
            ),
        ):
            result = runpy.run_path(
                str(PROJECT / "fetch_test_image.py"), run_name="fixture_import_test"
            )
        self.assertTrue(callable(result["fetch_test_image"]))

    def test_downloader_receives_only_supported_locked_fields(self):
        download = mock.Mock(return_value=self.path)
        result = image.fetch_test_image(download=download, lock_path=self.lock)
        self.assertEqual(result, self.path)
        download.assert_called_once_with(
            {key: self.spec[key] for key in ("url", "sha256", "filename", "size")}
        )
        self.assertEqual(self.path.read_bytes(), self.data)

    def test_missing_or_non_regular_image_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Missing/non-regular"):
            image.verify_image(self.root / "missing.iso", self.spec)
        link = self.root / "link.iso"
        link.symlink_to(self.path)
        with self.assertRaisesRegex(ValueError, "Missing/non-regular"):
            image.verify_image(link, self.spec)

    def test_sha256_mismatch_is_rejected_without_modifying_image(self):
        self.spec["sha256"] = "0" * 64
        self.save()
        with self.assertRaisesRegex(ValueError, "sha256 mismatch"):
            image.fetch_test_image(download=lambda spec: self.path, lock_path=self.lock)
        self.assertEqual(self.path.read_bytes(), self.data)

    def test_sha512_is_checked_even_when_sha256_matches(self):
        self.spec["sha512"] = "0" * 128
        self.save()
        with self.assertRaisesRegex(ValueError, "sha512 mismatch"):
            image.fetch_test_image(download=lambda spec: self.path, lock_path=self.lock)
        self.assertEqual(self.path.read_bytes(), self.data)

    def test_size_mismatch_is_rejected(self):
        self.spec["size"] += 1
        self.save()
        with self.assertRaisesRegex(ValueError, "size mismatch"):
            image.fetch_test_image(download=lambda spec: self.path, lock_path=self.lock)

    def test_bad_lock_fails_before_downloading(self):
        mutations = (
            ("filename", "../escape.iso"),
            ("sha256", "invalid"),
            ("sha512", "invalid"),
            ("size", True),
            ("size", 0),
            ("url", "http://example.invalid/fixture.iso"),
            ("url", "https://user:password@example.invalid/fixture.iso"),
        )
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                self.spec = fixture_spec(self.data)
                self.spec[field] = value
                self.save()
                download = mock.Mock(side_effect=AssertionError("unexpected download"))
                with self.assertRaises(ValueError):
                    image.fetch_test_image(download=download, lock_path=self.lock)
                download.assert_not_called()

    def test_downloader_failure_propagates_without_touching_existing_image(self):
        download = mock.Mock(side_effect=RuntimeError("offline"))
        with self.assertRaisesRegex(RuntimeError, "offline"):
            image.fetch_test_image(download=download, lock_path=self.lock)
        self.assertEqual(self.path.read_bytes(), self.data)


class ProjectFixtureTests(unittest.TestCase):
    def test_locked_url_and_sha512_match_the_existing_alpine_template(self):
        spec = image.load_fixture()
        metadata = json.loads(image.LOCKFILE.read_text())
        template = (PROJECT / metadata["template"]).read_text()
        match = re.search(
            r'- location: "([^\"]+)"\s+arch: "x86_64"\s+digest: "sha512:([0-9a-f]{128})"',
            template,
        )
        self.assertIsNotNone(match)
        self.assertEqual((spec["url"], spec["sha512"]), match.groups())
        self.assertEqual(spec["filename"], spec["url"].rsplit("/", 1)[1])
        self.assertEqual(spec["size"], 65011712)
        self.assertEqual(
            spec["sha256"],
            "07274016d23aef83a0c8a90995e0381f73db1638026dea233a67c21ccf124747",
        )

    def test_existing_cached_alpine_image_if_available(self):
        spec = image.load_fixture()
        path = PROJECT / "downloads" / spec["filename"]
        if not path.is_file():
            self.skipTest(
                "optional cached Alpine image is absent; no download attempted"
            )
        self.assertEqual(image.verify_image(path, spec), path)


class NativeValidatorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = b"embedded firmware fixture\0\xff"
        self.spec = {
            "name": native.FIRMWARE_NAME,
            "size": len(self.data),
            "sha256": hashlib.sha256(self.data).hexdigest(),
        }
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text(json.dumps({"format": 1, "resources": [self.spec]}))

    def suite(self, data=None):
        suite = native.Suite.__new__(native.Suite)
        suite.firmware = dict(self.spec)
        suite.fixtures = self.root
        suite.current = {}
        suite.info = mock.Mock(return_value={"virtual-size": self.spec["size"]})

        def img(*args, **kwargs):
            if args[0] == "info":
                self.assertEqual(args[-1], "builtin:__native_validation_missing__.fd")
                return 1, "", "resource not found"
            if args[0] == "resize":
                self.assertEqual(args[-2], native.BUILTIN)
                return 1, "", "read-only firmware"
            self.assertEqual(
                args[:6], ("convert", "-f", "raw", "-O", "raw", native.BUILTIN)
            )
            Path(args[-1]).write_bytes(self.data if data is None else data)
            return 0, "", ""

        suite.img = mock.Mock(side_effect=img)
        return suite

    def test_validator_paths_are_repository_relative(self):
        self.assertEqual(native.ROOT, PROJECT)
        self.assertEqual(native.TESTS, PROJECT / "tests")
        self.assertEqual(native.BINARY, PROJECT / "output/limactl")
        self.assertEqual(
            native.RESOURCE_MANIFEST,
            PROJECT / "src/qemu/util/builtin-resources/manifest.json",
        )
        self.assertFalse(hasattr(native, "FIRMWARE"))

    def test_loads_pinned_firmware_identity_without_external_firmware_file(self):
        self.assertEqual(native.load_firmware_spec(self.manifest), self.spec)
        actual = native.load_firmware_spec()
        self.assertEqual(actual["size"], 3653632)
        self.assertEqual(
            actual["sha256"],
            "d23e35c96cbf47468e5c7c2ce82cfa0c825d4e916bb6bacbf3d8d81556350fe3",
        )

    def test_missing_manifest_is_actionable(self):
        with self.assertRaisesRegex(
            native.Failure, "Cannot read embedded resource manifest"
        ):
            native.load_firmware_spec(self.root / "missing.json")

    def test_missing_duplicate_or_invalid_resource_is_rejected(self):
        cases = [
            [],
            [self.spec, self.spec],
            [dict(self.spec, sha256="wrong")],
            [dict(self.spec, size=0)],
            [dict(self.spec, size=True)],
        ]
        for resources in cases:
            with self.subTest(resources=resources):
                self.manifest.write_text(
                    json.dumps({"format": 1, "resources": resources})
                )
                with self.assertRaises(native.Failure):
                    native.load_firmware_spec(self.manifest)

    def test_otool_is_discovered_through_bounded_xcrun(self):
        tool = self.root / "otool"
        tool.write_text("not executed by this test")
        tool.chmod(0o700)
        completed = subprocess.CompletedProcess(
            [], 0, stdout=str(tool) + "\n", stderr=""
        )
        with (
            mock.patch.object(native.shutil, "which", return_value="/usr/bin/xcrun"),
            mock.patch.object(native.subprocess, "run", return_value=completed) as run,
        ):
            self.assertEqual(native.discover_otool(), str(tool))
        self.assertEqual(run.call_args.args[0], ["/usr/bin/xcrun", "--find", "otool"])
        self.assertEqual(run.call_args.kwargs["timeout"], 10)
        self.assertTrue(run.call_args.kwargs["check"])

    def test_missing_or_failing_xcrun_is_actionable(self):
        with mock.patch.object(native.shutil, "which", return_value=None):
            with self.assertRaisesRegex(native.Failure, "xcrun is required"):
                native.discover_otool()
        for error in (
            subprocess.CalledProcessError(1, ["xcrun"]),
            subprocess.TimeoutExpired(["xcrun"], 10),
        ):
            with (
                self.subTest(error=error),
                mock.patch.object(
                    native.shutil, "which", return_value="/usr/bin/xcrun"
                ),
                mock.patch.object(native.subprocess, "run", side_effect=error),
            ):
                with self.assertRaisesRegex(native.Failure, "Cannot locate otool"):
                    native.discover_otool()

    def test_unusable_discovered_otool_is_rejected(self):
        completed = subprocess.CompletedProcess(
            [], 0, stdout="relative/otool\n", stderr=""
        )
        with (
            mock.patch.object(native.shutil, "which", return_value="/usr/bin/xcrun"),
            mock.patch.object(native.subprocess, "run", return_value=completed),
        ):
            with self.assertRaisesRegex(native.Failure, "unusable otool path"):
                native.discover_otool()

    def test_missing_binary_fails_before_creating_validation_fixtures(self):
        with (
            mock.patch.object(native, "BINARY", self.root / "missing-limactl"),
            mock.patch.object(
                native.tempfile,
                "mkdtemp",
                side_effect=AssertionError("unexpected fixture creation"),
            ),
        ):
            with self.assertRaisesRegex(
                native.Failure, "missing single-file executable"
            ):
                native.Suite()

    def test_missing_manifest_fails_before_creating_validation_fixtures(self):
        binary = self.root / "limactl"
        binary.write_bytes(b"not executed")
        with (
            mock.patch.object(native, "BINARY", binary),
            mock.patch.object(
                native,
                "load_firmware_spec",
                side_effect=native.Failure("missing manifest"),
            ),
            mock.patch.object(
                native.tempfile,
                "mkdtemp",
                side_effect=AssertionError("unexpected fixture creation"),
            ),
        ):
            with self.assertRaisesRegex(native.Failure, "missing manifest"):
                native.Suite()

    def test_builtin_read_compares_info_and_converted_bytes_to_manifest(self):
        suite = self.suite()
        suite.builtin_read()
        suite.info.assert_called_once_with(native.BUILTIN, "raw")
        self.assertEqual(suite.current["firmware"]["sha256"], self.spec["sha256"])
        self.assertEqual(
            suite.current["firmware"]["expected_sha256"], self.spec["sha256"]
        )
        self.assertNotIn("original", suite.current["firmware"])

    def test_builtin_read_rejects_wrong_virtual_size(self):
        suite = self.suite()
        suite.info.return_value = {"virtual-size": self.spec["size"] + 1}
        with self.assertRaisesRegex(native.Failure, "virtual size mismatch"):
            suite.builtin_read()
        suite.img.assert_not_called()

    def test_readonly_rejection_verifies_manifest_hash_after_attempt(self):
        suite = self.suite()
        suite.builtin_rejections()
        self.assertEqual(
            [call.args[0] for call in suite.img.call_args_list],
            ["info", "resize", "convert"],
        )
        self.assertEqual(
            suite.current["firmware_after_rejection"]["sha256"], self.spec["sha256"]
        )
        self.assertEqual(
            suite.current["firmware_after_rejection"]["bytes"], self.spec["size"]
        )

    def test_readonly_rejection_does_not_hide_changed_firmware_bytes_or_size(self):
        for data in (b"x" * len(self.data), self.data + b"x"):
            with self.subTest(data=data):
                with self.assertRaisesRegex(native.Failure, "differs from manifest"):
                    self.suite(data).builtin_rejections()

    def test_successful_resize_is_still_a_failure(self):
        suite = self.suite()
        suite.img.side_effect = [(1, "", "resource not found"), (0, "", "")]
        with self.assertRaisesRegex(native.Failure, "readonly resize was not rejected"):
            suite.builtin_rejections()


if __name__ == "__main__":
    unittest.main()
