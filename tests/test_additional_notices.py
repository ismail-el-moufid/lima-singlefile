#!/usr/bin/env python3
"""Additional notices integrity; optional retained-archive verification, no builds.

ADDITIONAL_NOTICES_VERIFY_SOURCES=1 enables the slow source recheck. No tests
fetch inputs. Disposable fixtures are confined to compliance/notices/inputs/.
"""

import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
import stat
import tarfile
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "compliance/notices"
SPEC = importlib.util.spec_from_file_location(
    "additional_notices", BUNDLE / "collect.py"
)
notices = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(notices)


class BundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = notices.load_json(BUNDLE / "manifest.json")

    def altered_manifest(self, change):
        manifest = copy.deepcopy(self.manifest)
        change(manifest)
        real_load = notices.load_json
        return mock.patch.object(
            notices,
            "load_json",
            side_effect=lambda p: (
                manifest if p == BUNDLE / "manifest.json" else real_load(p)
            ),
        )

    def test_offline_integrity_has_no_subprocess_or_network(self):
        with (
            mock.patch.object(
                notices.subprocess, "run", side_effect=AssertionError("subprocess")
            ),
            mock.patch.object(
                notices.subprocess,
                "check_output",
                side_effect=AssertionError("subprocess"),
            ),
        ):
            result = notices.verify()
        self.assertEqual(result["host_modules"], 48)
        self.assertEqual(result["components"], 59)
        self.assertEqual(result["notices"], 1383)
        self.assertFalse(result["source_archives_rechecked"])

    def test_partial_scope_is_not_legal_clearance(self):
        scope = self.manifest["scope"]
        for key in (
            "file_level_inventory_complete",
            "firmware_notice_inventory_complete",
            "source_delivery_complete",
            "relinking_materials_complete",
            "redistribution_cleared",
        ):
            self.assertIs(scope[key], False, key)

    def test_binary_and_runtime_identities_are_distinct(self):
        host, guest = (self.manifest["binaries"][k] for k in ("host", "guest"))
        self.assertEqual(
            host["sha256"],
            "3a4fe1e0b19879b1e60dbb0fca8ff9be9d47f66260c115c1cd6e01a93b013218",
        )
        self.assertEqual(
            guest["sha256"],
            "b10989ec96ac40392b4d49494577fe308de8d6e734c5024722be82cdd29c464c",
        )
        self.assertEqual(
            (host["go_version"], guest["go_version"]), ("go1.22.12", "go1.19.2")
        )
        self.assertEqual(
            (host["settings"]["GOOS"], guest["settings"]["GOOS"]), ("darwin", "linux")
        )
        self.assertEqual((len(host["modules"]), len(guest["modules"])), (48, 9))
        runtime = {
            c["id"]: c for c in self.manifest["components"] if c["kind"] == "runtime"
        }
        self.assertEqual(
            runtime["go-host"]["archive"]["sha256"],
            "e7bbe07e96f0bd3df04225090fe1e7852ed33af37c43a23e16edbbb3b90a5b7c",
        )
        self.assertEqual(
            runtime["go-guest"]["archive"]["sha256"],
            "2ce930d70a931de660fdaf271d70192793b1b240272645bf0275779f6704df6b",
        )
        for component in runtime.values():
            members = {n["source_path"] for n in component["notices"]}
            self.assertTrue({"go/LICENSE", "go/PATENTS"} <= members)
        historical = notices.historical_spec(BUNDLE)
        self.assertEqual(historical["size"], 26534465)
        self.assertEqual(historical["catalog"]["file_record"]["version"], "go1.19.2")

    def test_required_nested_notice_and_patent_texts(self):
        components = {c["id"]: c for c in self.manifest["components"]}
        required = {
            "host-modules/github.com/AlecAivazis/survey/v2@v2.3.6": {
                "LICENSE",
                "terminal/LICENSE.txt",
            },
            "host-modules/github.com/containerd/containerd@v1.6.9": {
                "LICENSE",
                "NOTICE",
            },
            "host-modules/github.com/coreos/go-semver@v0.3.0": {"LICENSE", "NOTICE"},
            "host-modules/github.com/digitalocean/go-libvirt@v0.0.0-20201209184759-e2a69bcd5bd1": {
                "LICENSE.md",
                "internal/go-xdr/LICENSE",
            },
            "host-modules/github.com/nxadm/tail@v1.4.8": {
                "LICENSE",
                "ratelimiter/Licence",
            },
            "host-modules/google.golang.org/grpc@v1.47.0": {"LICENSE", "NOTICE.txt"},
            "host-modules/google.golang.org/protobuf@v1.28.0": {"LICENSE", "PATENTS"},
            "glib": {
                "COPYING",
                "glib/pcre/COPYING",
                "glib/gstrfuncs.c",
                "glib/gnulib/asnprintf.c",
            },
            "proxy-libintl": {"COPYING", "libintl.c", "libintl.h"},
            "libslirp": {"COPYRIGHT", "src/slirp.c"},
            "zlib": {"LICENSE", "zlib.h"},
            "qemu": {
                "LICENSE",
                "COPYING",
                "COPYING.LIB",
                "pc-bios/edk2-licenses.txt",
                "pc-bios/README",
            },
        }
        for cid, wanted in required.items():
            with self.subTest(component=cid):
                component = components[cid]
                prefix = component["archive_root"] + "/"
                members = {
                    n["source_path"][len(prefix) :] for n in component["notices"]
                }
                self.assertTrue(wanted <= members, wanted - members)
        modules = [c for c in components.values() if c["kind"] == "host-module"]
        self.assertEqual(sum(len(c["notices"]) for c in modules), 79)
        for c in modules:
            if c["path"].startswith("golang.org/x/"):
                self.assertIn(
                    c["archive_root"] + "/PATENTS",
                    {n["source_path"] for n in c["notices"]},
                )

    def test_existing_guest_bundle_is_unchanged_and_intact(self):
        guest_dir = ROOT / "compliance/guest-agent"
        guest = notices.load_json(guest_dir / "manifest.json")
        self.assertEqual(
            notices.file_hash(guest_dir / "manifest.json"),
            self.manifest["guest_manifest_sha256"],
        )
        self.assertEqual(len(guest["modules"]), 9)
        records = guest["lima"]["notices"] + [
            n for c in guest["modules"] for n in c["notices"]
        ]
        self.assertEqual(len(records), 12)
        for n in records:
            self.assertEqual(notices.file_hash(guest_dir / n["path"]), n["sha256"])
        actual = {
            p.relative_to(guest_dir).as_posix()
            for p in guest_dir.rglob("*")
            if p.is_file()
        }
        self.assertEqual(
            actual, {n["path"] for n in records} | {"README.md", "manifest.json"}
        )

    def test_missing_module_is_rejected(self):
        with self.altered_manifest(lambda m: m["components"].pop(0)):
            with self.assertRaisesRegex(ValueError, "48 host modules"):
                notices.verify()

    def test_duplicate_notice_is_rejected(self):
        def change(m):
            m["components"][0]["notices"].append(
                copy.deepcopy(m["components"][0]["notices"][0])
            )

        with self.altered_manifest(change):
            with self.assertRaisesRegex(ValueError, "Duplicate output"):
                notices.verify()

    def test_wrong_member_root_is_rejected(self):
        def change(m):
            m["components"][0]["notices"][0]["source_path"] = "other/LICENSE"

        with self.altered_manifest(change):
            with self.assertRaisesRegex(ValueError, "Wrong source member root"):
                notices.verify()

    def test_wrong_member_output_mapping_is_rejected(self):
        def change(m):
            n = m["components"][0]["notices"][0]
            n["path"] = n["path"] + ".wrong"

        with self.altered_manifest(change):
            with self.assertRaisesRegex(ValueError, "output/member mapping"):
                notices.verify()

    def test_lock_mismatch_is_rejected(self):
        def change(m):
            next(c for c in m["components"] if c["id"] == "go-host")["archive"][
                "sha256"
            ] = "0" * 64

        with self.altered_manifest(change):
            with self.assertRaisesRegex(ValueError, "Archive lock mismatch"):
                notices.verify()

    def test_payload_corruption_is_rejected_without_writing_bundle(self):
        target = BUNDLE / self.manifest["components"][0]["notices"][0]["path"]
        real_hash = notices.file_hash
        with mock.patch.object(
            notices,
            "file_hash",
            side_effect=lambda p: "0" * 64 if p == target else real_hash(p),
        ):
            with self.assertRaisesRegex(ValueError, "Packaged file mismatch"):
                notices.verify()

    @unittest.skipUnless(
        os.environ.get("ADDITIONAL_NOTICES_VERIFY_SOURCES") == "1",
        "opt-in retained archive/binary recheck",
    )
    def test_full_retained_archive_recollection(self):
        result = notices.verify(sources=True)
        self.assertTrue(result["source_archives_rechecked"])
        self.assertEqual(result["notices"], 1383)
        historical = notices.historical_spec(BUNDLE)
        catalog = ROOT / historical["catalog"]["local_response"]
        if catalog.exists():
            self.assertEqual(
                notices.file_hash(catalog), historical["catalog"]["response_sha256"]
            )
            release = next(
                r
                for r in json.loads(catalog.read_bytes())
                if r["version"] == "go1.19.2"
            )
            self.assertIn(historical["catalog"]["file_record"], release["files"])


class CollectorUnitTests(unittest.TestCase):
    def setUp(self):
        inputs = BUNDLE / "inputs"
        inputs.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="test-notices-", dir=inputs)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def zip_bytes(self, entries, compression=zipfile.ZIP_STORED):
        output = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(output, "w", compression=compression) as archive:
                for name, data in entries:
                    archive.writestr(name, data)
        return output.getvalue()

    def test_h1_matches_hash1_vector_independent_of_zip_container(self):
        entries = [
            ("example.com/m@v1.0.0/z", b"two"),
            ("example.com/m@v1.0.0/a", b"one"),
        ]
        expected_input = (
            hashlib.sha256(b"one").hexdigest()
            + "  example.com/m@v1.0.0/a\n"
            + hashlib.sha256(b"two").hexdigest()
            + "  example.com/m@v1.0.0/z\n"
        ).encode()
        expected = (
            "h1:" + base64.b64encode(hashlib.sha256(expected_input).digest()).decode()
        )
        first = self.zip_bytes(entries)
        second = self.zip_bytes(list(reversed(entries)), zipfile.ZIP_DEFLATED)
        self.assertNotEqual(
            hashlib.sha256(first).digest(), hashlib.sha256(second).digest()
        )
        for data in (first, second):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                self.assertEqual(notices.zip_h1(archive), expected)

    def test_h1_rejects_duplicates_traversal_and_newlines(self):
        cases = [
            ([("a", b"one"), ("a", b"two")], "Duplicate"),
            ([("../a", b"one")], "Unsafe"),
            ([("a\nb", b"one")], "Unsafe"),
        ]
        for entries, error in cases:
            with self.subTest(entries=entries):
                with zipfile.ZipFile(io.BytesIO(self.zip_bytes(entries))) as archive:
                    with self.assertRaisesRegex(ValueError, error):
                        notices.zip_h1(archive)

    def test_h1_rejects_zip_symlinks(self):
        info = zipfile.ZipInfo("example.com/m@v1.0.0/LICENSE")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(
            io.BytesIO(self.zip_bytes([(info, b"elsewhere")]))
        ) as archive:
            with self.assertRaisesRegex(ValueError, "Symlink ZIP"):
                notices.zip_h1(archive)

    def test_module_escaping_and_build_record_parsing(self):
        self.assertEqual(
            notices.escape_module("github.com/AlecAivazis/survey/v2"),
            "github.com/!alec!aivazis/survey/v2",
        )
        text = "binary: go1.22.12\n\tpath\texample.com/main\n\tdep\texample.com/mod\tv1.0.0\th1:abc\n\tbuild\tGOOS=darwin\n"
        record = notices.parse_build(text)
        self.assertEqual(record["modules"][0]["path"], "example.com/mod")
        self.assertEqual(record["settings"], {"GOOS": "darwin"})
        with self.assertRaisesRegex(ValueError, "replacements"):
            notices.parse_build(text + "\t=>\texample.com/other\tv1.0.0\th1:def\n")
        with self.assertRaisesRegex(ValueError, "Duplicate module"):
            notices.parse_build(text + "\tdep\texample.com/mod\tv1.0.0\th1:abc\n")

    def test_named_notice_rule(self):
        for name in (
            "LICENSE",
            "nested/LICENSE.txt",
            "nested/Licence",
            "NOTICE.txt",
            "PATENTS",
            "COPYING.LIB",
            "COPYRIGHT",
            "edk2-licenses.txt",
            "AUTHORS",
        ):
            self.assertTrue(notices.is_named_notice(name), name)
        for name in ("licensecheck.sh", "license.c", "README.md", "unlicensed.go"):
            self.assertFalse(notices.is_named_notice(name), name)

    def test_header_bytes_preserve_adjacent_spdx_and_copyright_comments(self):
        prefix = b"/* SPDX-License-Identifier: MIT */\r\n/* Copyright Example\r\n * Permission is hereby granted.\r\n */"
        data = prefix + b"\r\n#include <stdio.h>\n"
        start, end = notices.leading_notice(data)
        self.assertEqual(data[start:end], prefix)
        self.assertIsNone(
            notices.leading_notice(b"int main() {}\n/* Copyright later */")
        )
        self.assertIsNone(notices.leading_notice(b"/* Just a description */\nint x;"))

    def test_header_selection_is_bounded(self):
        self.assertTrue(notices.header_candidate("glib", "glib/gnulib/asnprintf.c"))
        self.assertFalse(notices.header_candidate("glib", "glib/tests/test.c"))
        self.assertTrue(notices.header_candidate("go-host", "src/runtime/example.go"))
        self.assertFalse(notices.header_candidate("go-host", "src/cmd/compile/main.go"))
        self.assertFalse(
            notices.header_candidate("go-guest", "src/runtime/example_test.go")
        )
        self.assertFalse(notices.header_candidate("qemu", "hw/block/example.c"))
        self.assertTrue(notices.header_candidate("zlib", "zlib.h"))
        self.assertFalse(notices.header_candidate("zlib", "contrib/example.c"))

    def test_safe_paths_and_symlink_rejection(self):
        for path in (
            "",
            "/tmp/escape",
            "../escape",
            "a/../escape",
            "a//b",
            "a/./b",
            "a\\b",
            "a\nb",
            ".git/config",
        ):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    notices.safe_name(path)
        (self.root / "link").symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "Symlink"):
            notices.safe_path(self.root, "link/file")

    def test_duplicate_json_keys_rejected(self):
        path = self.root / "fixture.json"
        path.write_text('{"format": 1, "format": 2}')
        with self.assertRaisesRegex(ValueError, "Duplicate JSON"):
            notices.load_json(path)

    def test_publish_is_idempotent_and_never_overwrites_differing_files(self):
        files = {"texts/example/LICENSE": b"original\r\n"}
        notices.publish(files, self.root)
        notices.publish(files, self.root)
        with self.assertRaisesRegex(ValueError, "Refusing to overwrite"):
            notices.publish(
                {"new.txt": b"new", "texts/example/LICENSE": b"changed"}, self.root
            )
        self.assertFalse((self.root / "new.txt").exists())
        self.assertEqual(
            (self.root / "texts/example/LICENSE").read_bytes(), b"original\r\n"
        )

    def tar_component(self, members):
        path = self.root / "fixture.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            for name, data in members:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return {
            "id": "libslirp",
            "archive_root": "fixture",
            "notices": [],
            "archive": {
                "path": "fixture.tar.gz",
                "sha256": notices.file_hash(path),
                "size": path.stat().st_size,
            },
        }

    def test_tar_collection_preserves_full_members_and_header_provenance(self):
        source = b"/* Copyright example */\nint x;\n"
        component = self.tar_component(
            [("fixture/COPYRIGHT", b"authentic\r\n"), ("fixture/src/test.c", source)]
        )
        files = {}
        notices.scan_tar(component, files, self.root)
        self.assertEqual(files["texts/libslirp/files/COPYRIGHT"], b"authentic\r\n")
        self.assertEqual(
            files["texts/libslirp/headers/src/test.c.txt"], b"/* Copyright example */"
        )
        header = next(n for n in component["notices"] if "byte_range" in n)
        self.assertEqual(header["source_sha256"], hashlib.sha256(source).hexdigest())
        self.assertEqual(header["byte_range"], [0, len(b"/* Copyright example */")])

    def test_tar_checksum_failure_prevents_collection(self):
        component = self.tar_component([("fixture/LICENSE", b"authentic")])
        component["archive"]["sha256"] = "0" * 64
        files = {}
        with self.assertRaisesRegex(ValueError, "Archive SHA-256 mismatch"):
            notices.scan_tar(component, files, self.root)
        self.assertEqual(files, {})

    def test_tar_duplicate_and_unsafe_members_rejected(self):
        for members, error in [
            ([("fixture/LICENSE", b"a"), ("fixture/LICENSE", b"b")], "Duplicate tar"),
            ([("fixture/../../LICENSE", b"a")], "Unsafe path"),
        ]:
            with self.subTest(error=error):
                component = self.tar_component(members)
                with self.assertRaisesRegex(ValueError, error):
                    notices.scan_tar(component, {}, self.root)

    def test_module_h1_mismatch_prevents_notice_output(self):
        name, version = "example.com/m", "v1.0.0"
        path = self.root / "cache/modules/cache/download/example.com/m/@v/v1.0.0.zip"
        path.parent.mkdir(parents=True)
        path.write_bytes(
            self.zip_bytes([("example.com/m@v1.0.0/LICENSE", b"authentic")])
        )
        module = {"path": name, "version": version, "zip_h1": "h1:wrong"}
        files = {}
        with self.assertRaisesRegex(ValueError, "Go h1 mismatch"):
            notices.module_component(
                module, self.root, files, {"example.com/m v1.0.0 h1:wrong"}
            )
        self.assertEqual(files, {})


if __name__ == "__main__":
    unittest.main()
