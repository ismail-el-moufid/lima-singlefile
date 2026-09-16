#!/usr/bin/env python3
"""Offline guest-agent notice integrity; no caches, Go tools, builds or downloads.

Run: python3 -B -m unittest discover -s tests -p test_guest_agent_notices.py -v
"""

import hashlib
import json
import unittest
from pathlib import Path, PurePosixPath

PROJECT = Path(__file__).resolve().parents[1]
BUNDLE = PROJECT / "compliance/guest-agent"
AGENT_PATH = "src/lima/pkg/embeddedassets/lima-guestagent.Linux-x86_64"
AGENT_SHA256 = "b10989ec96ac40392b4d49494577fe308de8d6e734c5024722be82cdd29c464c"
LIMA_REVISION = "6b6073ff536ea3ae7605129489a33ed2ba11fc46"
EXPECTED_MODULES = {
    "github.com/elastic/go-libaudit/v2": (
        "v2.3.2",
        "go-libaudit-v2",
        ("LICENSE.txt", "NOTICE.txt"),
    ),
    "github.com/gorilla/mux": ("v1.8.0", "mux", ("LICENSE",)),
    "github.com/sirupsen/logrus": ("v1.9.0", "logrus", ("LICENSE",)),
    "github.com/spf13/cobra": ("v1.6.1", "cobra", ("LICENSE.txt",)),
    "github.com/spf13/pflag": ("v1.0.5", "pflag", ("LICENSE",)),
    "github.com/yalue/native_endian": ("v1.0.2", "native_endian", ("LICENSE",)),
    "go.uber.org/atomic": ("v1.7.0", "atomic", ("LICENSE.txt",)),
    "go.uber.org/multierr": ("v1.7.0", "multierr", ("LICENSE.txt",)),
    "golang.org/x/sys": (
        "v0.0.0-20220811171246-fbc7d0a398ab",
        "x-sys",
        ("LICENSE", "PATENTS"),
    ),
}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key: " + key)
        result[key] = value
    return result


def digest(data):
    return hashlib.sha256(data).hexdigest()


class GuestAgentNoticesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(
            (BUNDLE / "manifest.json").read_text(), object_pairs_hook=unique_object
        )

    def notice_records(self):
        return [
            notice
            for module in self.manifest["modules"]
            for notice in module["notices"]
        ] + self.manifest["lima"]["notices"]

    def test_scope_is_explicitly_incomplete(self):
        self.assertEqual(self.manifest["format"], 1)
        scope = self.manifest["scope"]
        self.assertIs(scope["go_runtime_packaged"], False)
        self.assertIs(scope["file_level_inventory_complete"], False)
        self.assertIs(scope["redistribution_cleared"], False)

    def test_exact_bundle_inventory(self):
        expected_files = {"README.md", "manifest.json", "lima/LICENSE"}
        for _, slug, names in EXPECTED_MODULES.values():
            expected_files.update("modules/" + slug + "/" + n for n in names)
        records = self.notice_records()
        recorded_paths = [n["path"] for n in records]
        self.assertEqual(len(recorded_paths), 12)
        self.assertEqual(len(recorded_paths), len(set(recorded_paths)))
        self.assertEqual(
            set(recorded_paths), expected_files - {"README.md", "manifest.json"}
        )
        expected_directories = {
            parent.as_posix()
            for name in expected_files
            for parent in PurePosixPath(name).parents
            if parent != PurePosixPath(".")
        }
        self.assertTrue(BUNDLE.is_dir())
        self.assertFalse(BUNDLE.is_symlink())
        actual_files, actual_directories = set(), set()
        for path in BUNDLE.rglob("*"):
            relative = path.relative_to(BUNDLE).as_posix()
            self.assertFalse(path.is_symlink(), relative)
            if path.is_dir():
                actual_directories.add(relative)
            else:
                self.assertTrue(path.is_file(), relative)
                actual_files.add(relative)
        self.assertEqual(actual_files, expected_files)
        self.assertEqual(actual_directories, expected_directories)

    def test_expected_modules_and_archive_member_paths(self):
        modules = self.manifest["modules"]
        self.assertEqual(len(modules), 9)
        self.assertEqual({m["path"] for m in modules}, set(EXPECTED_MODULES))
        for module in modules:
            with self.subTest(module=module["path"]):
                version, slug, names = EXPECTED_MODULES[module["path"]]
                self.assertEqual(module["version"], version)
                self.assertEqual(len(module["notices"]), len(names))
                self.assertEqual(
                    {n["path"]: n["source_path"] for n in module["notices"]},
                    {
                        "modules/" + slug + "/" + name: module["path"]
                        + "@"
                        + version
                        + "/"
                        + name
                        for name in names
                    },
                )
                self.assertEqual(
                    module["archive"]["path"],
                    "cache/modules/cache/download/"
                    + module["path"]
                    + "/@v/"
                    + version
                    + ".zip",
                )
                self.assertRegex(module["archive"]["sha256"], r"\A[0-9a-f]{64}\Z")

    def test_notice_sizes_and_hashes(self):
        for notice in self.notice_records():
            with self.subTest(path=notice["path"]):
                relative = PurePosixPath(notice["path"])
                self.assertFalse(relative.is_absolute())
                self.assertNotIn("..", relative.parts)
                self.assertEqual(relative.as_posix(), notice["path"])
                path = BUNDLE / relative
                self.assertIn(BUNDLE.resolve(), path.resolve().parents)
                self.assertFalse(path.is_symlink())
                data = path.read_bytes()
                self.assertGreater(len(data), 0)
                self.assertEqual(len(data), notice["size"])
                self.assertRegex(notice["sha256"], r"\A[0-9a-f]{64}\Z")
                self.assertEqual(digest(data), notice["sha256"])

    def test_module_h1_checksums_match_go_sum_and_agent_record(self):
        sums = set((PROJECT / "src/lima/go.sum").read_text().splitlines())
        agent = (PROJECT / AGENT_PATH).read_bytes()
        for module in self.manifest["modules"]:
            with self.subTest(module=module["path"]):
                path, version, checksum = (
                    module["path"],
                    module["version"],
                    module["zip_h1"],
                )
                self.assertRegex(checksum, r"\Ah1:[A-Za-z0-9+/]{43}=\Z")
                self.assertIn(" ".join((path, version, checksum)), sums)
                # Go embeds the module build record as text in this pinned binary.
                self.assertIn(
                    ("dep\t" + "\t".join((path, version, checksum)) + "\n").encode(),
                    agent,
                )

    def test_guest_agent_identity(self):
        record = self.manifest["guest_agent"]
        self.assertEqual(record["path"], AGENT_PATH)
        self.assertEqual(record["size"], 7135232)
        self.assertEqual(record["sha256"], AGENT_SHA256)
        agent = PROJECT / AGENT_PATH
        self.assertFalse(agent.is_symlink())
        data = agent.read_bytes()
        self.assertEqual(len(data), record["size"])
        self.assertEqual(digest(data), record["sha256"])
        self.assertEqual(record["go_version"], "go1.19.2")
        self.assertEqual(record["goos"], "linux")
        self.assertEqual(record["goarch"], "amd64")
        self.assertEqual(record["goamd64"], "v1")
        self.assertIs(record["cgo_enabled"], False)
        self.assertEqual(record["lima_version"], "v0.13.0")
        self.assertEqual(record["vcs_revision"], LIMA_REVISION)
        self.assertIs(record["vcs_modified"], False)
        self.assertEqual(
            record["ldflags"],
            "-s -w -X github.com/lima-vm/lima/pkg/version.Version=v0.13.0",
        )

    def test_lima_license_and_locked_source_identity(self):
        record = self.manifest["lima"]
        lock = json.loads((PROJECT / "sources.lock.json").read_text())["sources"][
            "lima"
        ]
        self.assertEqual(record["path"], "github.com/lima-vm/lima")
        self.assertEqual(record["version"], "v0.13.0")
        self.assertEqual(record["revision"], LIMA_REVISION)
        self.assertEqual(record["revision"], lock["revision"])
        self.assertEqual(
            record["archive"],
            {
                "path": "downloads/" + lock["filename"],
                "sha256": lock["sha256"],
                "archive_root": lock["archive_root"],
            },
        )
        self.assertEqual(len(record["notices"]), 1)
        notice = record["notices"][0]
        self.assertEqual(notice["path"], "lima/LICENSE")
        self.assertEqual(notice["source_path"], lock["archive_root"] + "/LICENSE")
        self.assertEqual(
            (BUNDLE / "lima/LICENSE").read_bytes(),
            (PROJECT / "src/lima/LICENSE").read_bytes(),
        )


if __name__ == "__main__":
    unittest.main()
