#!/usr/bin/env python3
"""Offline source preparation tests; no builds or downloads.

Run: python3 -B -m unittest discover -s tests -p test_sources.py -v
For the full pinned-archive reconstruction test, set SOURCE_ARCHIVE_CACHE to an
os.pathsep-separated list of archive cache directories. downloads/ is also checked.
All extracted fixtures live in TemporaryDirectory, never the existing src trees.
"""

import hashlib
import io
import json
import os
import runpy
import shutil
import stat
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))
import prepare_sources as sources


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n")


def extract_fixture(archive, destination):
    """Test-only implementation of the agreed stripped, no-overwrite API.

    Inputs are generated fixtures or checksum-verified cached archives. Reject
    special files, escaping links, duplicate files and symlink parents anyway.
    Production extraction remains the bootstrap teammate's responsibility.
    """
    destination = Path(destination)
    if os.path.lexists(destination):
        raise FileExistsError(destination)
    with tempfile.TemporaryDirectory(dir=destination.parent) as temporary:
        stage = Path(temporary)
        root_name = None
        directories = []
        with tarfile.open(archive) as bundle:
            for member in bundle:
                parts = sources.relative_path(member.name.rstrip("/")).parts
                if root_name is None:
                    root_name = parts[0]
                if parts[0] != root_name:
                    raise ValueError("multiple archive roots")
                if len(parts) == 1:
                    if not member.isdir():
                        raise ValueError("archive root must be a directory")
                    continue
                relative = PurePosixPath(*parts[1:]).as_posix()
                target = sources.safe_path(stage, relative)
                target.parent.mkdir(parents=True, exist_ok=True)
                if member.isdir():
                    target.mkdir(exist_ok=True)
                    directories.append((target, member.mode & 0o777))
                elif member.isfile():
                    with (
                        bundle.extractfile(member) as stream,
                        target.open("xb") as output,
                    ):
                        shutil.copyfileobj(stream, output)
                    target.chmod(member.mode & 0o777)
                elif member.issym():
                    resolved = (target.parent / member.linkname).resolve()
                    if stage not in resolved.parents:
                        raise ValueError("escaping archive symlink")
                    target.symlink_to(member.linkname)
                else:
                    raise ValueError("unsupported archive member: " + member.name)
        for path, mode in reversed(directories):
            path.chmod(mode)
        if os.path.lexists(destination):
            raise FileExistsError(destination)
        stage.rename(destination)


def archive_files(archive):
    result = {}
    with tarfile.open(archive) as bundle:
        for member in bundle:
            parts = PurePosixPath(member.name).parts
            if len(parts) < 2 or member.isdir():
                continue
            name = PurePosixPath(*parts[1:]).as_posix()
            if member.issym():
                result[name] = {"type": "symlink", "target": member.linkname}
            elif member.isfile():
                result[name] = {
                    "type": "file",
                    "sha256": digest(bundle.extractfile(member).read()),
                    "mode": member.mode & 0o777,
                }
            else:
                raise AssertionError("unexpected archive file type: " + member.name)
    return result


class SourcePreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "project"
        self.root.mkdir()
        self.cache = Path(temporary.name) / "cache"
        self.cache.mkdir()
        self.destination = self.root / "build/self-contained/sources"
        self.requests = []
        self.extractions = []
        self.lock = {"format": 1, "sources": {}, "copies": []}
        names = (
            "lima",
            "qemu",
            "libslirp",
            "keycodemapdb",
            "berkeley-softfloat-3",
            "berkeley-testfloat-3",
        )
        for name in names:
            contents = {"existing.txt": ("upstream " + name + "\n").encode()}
            if name == "lima":
                contents["cmd/limactl/keep.go"] = b"package main\n"
            if name == "qemu":
                contents["scripts/tool.py"] = b"# fixture\n"
                for project in ("berkeley-softfloat-3", "berkeley-testfloat-3"):
                    for filename in ("meson.build", "meson_options.txt"):
                        path = "subprojects/packagefiles/" + project + "/" + filename
                        data = (project + " " + filename + "\n").encode()
                        contents[path] = data
                        self.lock["copies"].append(
                            {
                                "from": "qemu/" + path,
                                "to": "qemu/subprojects/" + project + "/" + filename,
                                "sha256": digest(data),
                            }
                        )
            archive = self.cache / (name + ".tar.gz")
            with tarfile.open(archive, "w:gz") as bundle:
                top = tarfile.TarInfo("upstream-" + name)
                top.type = tarfile.DIRTYPE
                top.mode = 0o755
                bundle.addfile(top)
                if name == "qemu":
                    stub = tarfile.TarInfo(top.name + "/subprojects/keycodemapdb")
                    stub.type = tarfile.DIRTYPE
                    stub.mode = 0o755
                    bundle.addfile(stub)
                for relative, data in contents.items():
                    info = tarfile.TarInfo(top.name + "/" + relative)
                    info.size = len(data)
                    info.mode = 0o644
                    bundle.addfile(info, io.BytesIO(data))
                alias = tarfile.TarInfo(top.name + "/alias")
                alias.type = tarfile.SYMTYPE
                alias.linkname = "existing.txt"
                bundle.addfile(alias)
            self.lock["sources"][name] = {
                "url": "https://example.invalid/" + archive.name,
                "sha256": sources.sha256(archive),
                "filename": archive.name,
                "archive_root": "upstream-" + name,
                "revision": "a" * 40,
                "destination": name
                if name in sources.SOURCE_NAMES
                else "qemu/subprojects/" + name,
            }
        self.manifest = {"format": 1, "overlays": []}
        for name in ("lima", "qemu"):
            self.add_overlay(
                name,
                "existing.txt",
                b"local modification\n",
                ("upstream " + name + "\n").encode(),
            )
        self.add_overlay("lima", "asset.bin", b"\0preserved binary asset\xff", None)
        self.save()

    def add_overlay(self, source, path, data, preimage):
        relative = "src/" + source + "/" + path
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(0o644)
        self.manifest["overlays"].append(
            {
                "source": source,
                "path": path,
                "file": relative,
                "sha256": digest(data),
                "mode": 0o644,
                "upstream_sha256": digest(preimage) if preimage is not None else None,
                "upstream_mode": 0o644 if preimage is not None else None,
            }
        )

    def save(self):
        write_json(self.root / "sources.lock.json", self.lock)
        write_json(self.root / "source-overlays.json", self.manifest)

    def download(self, spec):
        self.assertEqual(set(spec), {"url", "sha256", "filename"})
        self.requests.append(spec)
        return self.cache / spec["filename"]

    def extract(self, archive, destination):
        self.extractions.append(destination)
        extract_fixture(archive, destination)

    def prepare(self, **kwargs):
        return sources.prepare_sources(
            self.root, download=self.download, extract=self.extract, **kwargs
        )

    def assert_unpublished(self):
        self.assertFalse(self.destination.exists())
        self.assertFalse(list(self.destination.parent.glob(".sources.stage-*")))
        self.assertFalse((self.destination.parent / ".sources.prepare.lock").exists())

    def test_import_has_no_bootstrap_or_filesystem_write_side_effects(self):
        with (
            mock.patch(
                "importlib.import_module",
                side_effect=AssertionError("unexpected import"),
            ),
            mock.patch.object(
                Path, "mkdir", side_effect=AssertionError("unexpected write")
            ),
        ):
            result = runpy.run_path(
                str(PROJECT / "prepare_sources.py"), run_name="source_import_test"
            )
        self.assertTrue(callable(result["prepare_sources"]))

    def test_prepare_populates_overlays_subprojects_and_reuses_without_bootstrap(self):
        originals = sources.snapshot(self.root / "src")
        result = self.prepare()
        self.assertEqual(set(result), set(sources.SOURCE_NAMES))
        self.assertEqual(len(self.requests), 6)
        self.assertEqual(len(self.extractions), 6)
        self.assertEqual(
            (result["lima"] / "existing.txt").read_bytes(), b"local modification\n"
        )
        self.assertTrue((result["lima"] / "alias").is_symlink())
        for recipe in self.lock["copies"]:
            self.assertEqual(
                sources.sha256(self.destination / recipe["to"]), recipe["sha256"]
            )
        self.assertEqual(sources.snapshot(self.root / "src"), originals)
        with mock.patch.object(
            sources, "bootstrap_api", side_effect=AssertionError("unexpected bootstrap")
        ):
            self.assertEqual(sources.prepare_sources(self.root), result)

    def test_known_generated_files_survive_reuse_without_becoming_overlays(self):
        self.prepare()
        flags = self.destination / "lima/cmd/limactl/native_link_flags.go"
        flags.write_text("generated local linker flags\n")
        bytecode = self.destination / "qemu/scripts/__pycache__/tool.cpython-39.pyc"
        bytecode.parent.mkdir()
        bytecode.write_bytes(b"disposable bytecode")
        self.requests.clear()
        self.prepare()
        self.assertFalse(self.requests)
        self.assertEqual(flags.read_text(), "generated local linker flags\n")
        self.assertEqual(bytecode.read_bytes(), b"disposable bytecode")

    def test_overlay_hash_mismatch_fails_before_downloads(self):
        (self.root / self.manifest["overlays"][0]["file"]).write_text(
            "unrecorded modification"
        )
        with self.assertRaisesRegex(sources.SourceError, "overlay hash mismatch"):
            self.prepare()
        self.assertFalse(self.requests)
        self.assert_unpublished()

    def test_preimage_hash_mismatch_discards_only_staging(self):
        self.manifest["overlays"][0]["upstream_sha256"] = "0" * 64
        self.save()
        with self.assertRaisesRegex(
            sources.SourceError, "upstream preimage hash mismatch"
        ):
            self.prepare()
        self.assert_unpublished()
        self.assertEqual(
            (self.root / "src/lima/existing.txt").read_bytes(), b"local modification\n"
        )

    def test_added_overlay_cannot_overwrite_upstream_file(self):
        self.manifest["overlays"][0].update(upstream_sha256=None, upstream_mode=None)
        self.save()
        with self.assertRaisesRegex(sources.SourceError, "collides with upstream"):
            self.prepare()
        self.assert_unpublished()

    def test_overlay_changed_during_download_is_rechecked(self):
        def changed_download(spec):
            result = self.download(spec)
            (self.root / "src/lima/existing.txt").write_text(
                "changed during preparation"
            )
            return result

        with self.assertRaisesRegex(sources.SourceError, "overlay hash mismatch"):
            sources.prepare_sources(
                self.root, download=changed_download, extract=self.extract
            )
        self.assert_unpublished()

    def test_archive_hash_is_checked_even_with_injected_downloader(self):
        (self.cache / "lima.tar.gz").write_bytes(b"wrong archive")
        with self.assertRaisesRegex(sources.SourceError, "archive hash mismatch"):
            self.prepare()
        self.assert_unpublished()

    def test_copy_recipe_hash_is_checked(self):
        self.lock["copies"][0]["sha256"] = "0" * 64
        self.save()
        with self.assertRaisesRegex(sources.SourceError, "Meson overlay hash mismatch"):
            self.prepare()
        self.assert_unpublished()

    def test_overlay_input_symlink_is_rejected(self):
        path = self.root / "src/lima/existing.txt"
        outside = self.root / "outside.txt"
        outside.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(outside)
        with self.assertRaisesRegex(sources.SourceError, "symlink"):
            self.prepare()
        self.assertFalse(self.requests)

    def test_preimage_symlink_is_rejected(self):
        self.add_overlay("lima", "alias", b"replacement", b"upstream lima\n")
        self.save()
        with self.assertRaisesRegex(sources.SourceError, "symlink"):
            self.prepare()
        self.assert_unpublished()

    def test_unsafe_overlay_path_is_rejected(self):
        self.manifest["overlays"][0]["path"] = "../escape"
        self.save()
        with self.assertRaisesRegex(sources.SourceError, "Invalid relative path"):
            self.prepare()
        self.assertFalse(self.requests)

    def test_download_only_downloads_every_archive_without_overlay_inputs(self):
        (self.root / "source-overlays.json").unlink()
        result = self.prepare(download_only=True)
        self.assertEqual(set(result), set(self.lock["sources"]))
        self.assertEqual(len(self.requests), 6)
        self.assertFalse(self.extractions)
        self.assertFalse((self.root / "build").exists())

    def test_source_content_drift_is_preserved_and_rejected(self):
        self.prepare()
        changed = self.destination / "lima/existing.txt"
        changed.write_text("user edit must survive")
        with self.assertRaisesRegex(
            sources.SourceError, "source drift.*lima/existing.txt"
        ):
            self.prepare()
        self.assertEqual(changed.read_text(), "user edit must survive")

    def test_added_files_and_executable_mode_drift_are_rejected(self):
        self.prepare()
        added = self.destination / "qemu/user-added.c"
        added.write_text("user addition")
        with self.assertRaisesRegex(sources.SourceError, "source drift"):
            self.prepare()
        self.assertEqual(added.read_text(), "user addition")
        added.unlink()
        changed = self.destination / "qemu/existing.txt"
        changed.chmod(0o755)
        with self.assertRaisesRegex(sources.SourceError, "source drift"):
            self.prepare()
        self.assertEqual(stat.S_IMODE(changed.stat().st_mode), 0o755)

    def test_changed_inputs_reject_stale_snapshot_without_overwrite(self):
        self.prepare()
        before = (self.destination / sources.STAMP).read_bytes()
        self.lock["description"] = "updated inputs"
        self.save()
        with self.assertRaisesRegex(sources.SourceError, "stale inputs"):
            self.prepare()
        self.assertEqual((self.destination / sources.STAMP).read_bytes(), before)

    def test_unstamped_existing_destination_is_not_overwritten(self):
        self.destination.mkdir(parents=True)
        keep = self.destination / "keep.txt"
        keep.write_text("existing work")
        with self.assertRaisesRegex(sources.SourceError, "no preparation stamp"):
            self.prepare()
        self.assertFalse(self.requests)
        self.assertEqual(keep.read_text(), "existing work")

    def test_original_source_tree_cannot_be_a_destination(self):
        with self.assertRaisesRegex(sources.SourceError, "original sources"):
            self.prepare(destination=self.root / "src/new-generated-tree")
        self.assertFalse(self.requests)
        self.assertFalse((self.root / "src/new-generated-tree").exists())

    def test_existing_lock_is_never_removed(self):
        self.destination.parent.mkdir(parents=True)
        lock = self.destination.parent / ".sources.prepare.lock"
        lock.write_text("another preparation")
        with self.assertRaisesRegex(sources.SourceError, "Preparation lock exists"):
            self.prepare()
        self.assertEqual(lock.read_text(), "another preparation")

    def test_destination_appearing_during_preparation_is_preserved(self):
        def extract_and_race(archive, target):
            self.extract(archive, target)
            if not self.destination.exists():
                self.destination.mkdir()
                (self.destination / "keep.txt").write_text("concurrent work")

        with self.assertRaisesRegex(sources.SourceError, "Destination appeared"):
            sources.prepare_sources(
                self.root, download=self.download, extract=extract_and_race
            )
        self.assertEqual((self.destination / "keep.txt").read_text(), "concurrent work")
        self.assertFalse(list(self.destination.parent.glob(".sources.stage-*")))


class ProjectRecipeTests(unittest.TestCase):
    def test_native_override_metadata_matches_local_files_and_qemu_bases(self):
        metadata, _ = sources.read_json(PROJECT / "native/overrides.json")
        expected = {
            "os-posix.c",
            "util/main-loop.c",
            "util/qemu-thread-posix.c",
            "util/oslib-posix.c",
        }
        self.assertEqual({entry["path"] for entry in metadata["overrides"]}, expected)
        for entry in metadata["overrides"]:
            self.assertEqual(entry["source"], "qemu")
            self.assertTrue(entry["file"].startswith("native/overrides/"))
            sources.verify_file(
                sources.safe_path(PROJECT, entry["file"]),
                entry["sha256"],
                "native override",
            )
            sources.verify_file(
                sources.safe_path(PROJECT, "src/qemu/" + entry["path"]),
                entry["upstream_sha256"],
                "native base",
            )

    def test_full_cached_reconstruction_and_overlay_completeness(self):
        lock, _ = sources.load_lock(PROJECT)
        manifest, _ = sources.load_overlays(PROJECT, lock)
        self.assertEqual(len(lock["sources"]), 6)
        self.assertEqual(len(lock["copies"]), 4)
        locations = [
            Path(p)
            for p in os.environ.get("SOURCE_ARCHIVE_CACHE", "").split(os.pathsep)
            if p
        ]
        locations.append(PROJECT / "downloads")
        archives = {}
        missing = []
        for name, spec in lock["sources"].items():
            found = next(
                (
                    p / spec["filename"]
                    for p in locations
                    if (p / spec["filename"]).is_file()
                ),
                None,
            )
            if found is None:
                missing.append(spec["filename"])
            else:
                archives[name] = found
        if missing:
            self.skipTest(
                "Set SOURCE_ARCHIVE_CACHE for cached archives: " + ", ".join(missing)
            )
        originals = sources.snapshot(PROJECT / "src")
        pristine = {name: archive_files(path) for name, path in archives.items()}
        overlays = {
            entry["source"] + "/" + entry["path"]: entry
            for entry in manifest["overlays"]
        }
        expected_overlay_paths = set()
        for source in ("lima", "qemu"):
            local = PROJECT / "src" / source
            baseline = pristine[source]
            excluded_subprojects = [
                s["destination"]
                for n, s in lock["sources"].items()
                if n not in sources.SOURCE_NAMES
            ]
            for relative, base in baseline.items():
                self.assertTrue(
                    os.path.lexists(local / relative),
                    "Missing original upstream file: " + source + "/" + relative,
                )
            for path in local.rglob("*"):
                if path.is_dir() and not path.is_symlink():
                    continue
                relative = path.relative_to(local).as_posix()
                target = source + "/" + relative
                if sources.generated_path(target) or any(
                    target.startswith(p + "/") for p in excluded_subprojects
                ):
                    continue
                base = baseline.get(relative)
                if path.is_symlink():
                    self.assertEqual(
                        base, {"type": "symlink", "target": os.readlink(path)}, target
                    )
                    continue
                actual = sources.sha256(path)
                if (
                    base is None
                    or base.get("sha256") != actual
                    or base["mode"] & 0o111 != stat.S_IMODE(path.stat().st_mode) & 0o111
                ):
                    expected_overlay_paths.add(target)
                    self.assertIn(
                        target, overlays, "Unlisted local modification: " + target
                    )
                    entry = overlays[target]
                    self.assertEqual(
                        entry["upstream_sha256"],
                        base["sha256"] if base else None,
                        target,
                    )
                    self.assertEqual(entry["sha256"], actual, target)
            for relative, base in baseline.items():
                if base["type"] == "symlink":
                    self.assertTrue(
                        (local / relative).is_symlink(), source + "/" + relative
                    )
        self.assertEqual(set(overlays), expected_overlay_paths)
        self.assertIn("lima/pkg/embeddedassets/examples/experimental/vz.yaml", overlays)
        self.assertEqual(
            overlays["lima/pkg/embeddedassets/lima-guestagent.Linux-x86_64"]["sha256"],
            "b10989ec96ac40392b4d49494577fe308de8d6e734c5024722be82cdd29c464c",
        )
        self.assertEqual(
            overlays["qemu/util/builtin-resources/builtin-data.bin"]["sha256"],
            "4f4a697785e3e70a6d514d31ae54cd246e4d9aa77a4f8918d0005c20eb90bbf6",
        )
        requests = []

        def download(spec):
            self.assertEqual(set(spec), {"url", "sha256", "filename"})
            requests.append(spec["filename"])
            return next(
                path for path in archives.values() if path.name == spec["filename"]
            )

        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "sources"
            result = sources.prepare_sources(
                PROJECT, destination, download=download, extract=extract_fixture
            )
            self.assertEqual(len(requests), 6)
            self.assertEqual(set(result), set(sources.SOURCE_NAMES))
            expected = {}
            for name, files in pristine.items():
                prefix = lock["sources"][name]["destination"]
                expected.update(
                    {prefix + "/" + path: entry for path, entry in files.items()}
                )
            for target, entry in overlays.items():
                expected[target] = {
                    "type": "file",
                    "sha256": entry["sha256"],
                    "mode": entry["mode"],
                }
            for recipe in lock["copies"]:
                expected[recipe["to"]] = expected[recipe["from"]]
            stamp, _ = sources.read_json(destination / sources.STAMP)
            actual = {
                path: entry
                for path, entry in stamp["tree"].items()
                if entry["type"] != "directory"
            }
            self.assertEqual(actual, expected)
            with mock.patch.object(
                sources,
                "bootstrap_api",
                side_effect=AssertionError("reuse must be offline"),
            ):
                self.assertEqual(sources.prepare_sources(PROJECT, destination), result)
            self.assertEqual(
                sources.snapshot(PROJECT / "src"),
                originals,
                "Original src trees changed",
            )


if __name__ == "__main__":
    unittest.main()
