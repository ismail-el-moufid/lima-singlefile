"""Offline tests: python3 -B -m unittest discover -s tests -p test_bootstrap.py -v."""

import hashlib
import importlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bootstrap
import build_support


class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.archive = self.root / "fixture.tar"
        self.destination = self.root / "unpacked"

    def tar(self, entries):
        """Entries are (name, kind, bytes-or-link-target)."""
        with tarfile.open(self.archive, "w") as archive:
            for name, kind, value in entries:
                member = tarfile.TarInfo(name)
                member.mode = 0o755 if kind == "dir" else 0o644
                if kind == "file":
                    member.size = len(value)
                    archive.addfile(member, io.BytesIO(value))
                else:
                    member.type = {
                        "dir": tarfile.DIRTYPE,
                        "symlink": tarfile.SYMTYPE,
                        "hardlink": tarfile.LNKTYPE,
                        "fifo": tarfile.FIFOTYPE,
                    }[kind]
                    if kind in {"symlink", "hardlink"}:
                        member.linkname = value
                    archive.addfile(member)
        return self.archive

    def reject(self, entries):
        self.tar(entries)
        with self.assertRaises((ValueError, OSError)):
            bootstrap.extract(self.archive, self.destination)
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.root.glob(".unpacked.extract-*")), [])

    def test_strip_root_files_directories_and_safe_links(self):
        self.tar(
            [
                ("./release", "dir", None),
                ("./release/lib", "dir", None),
                ("./release/lib/alias", "hardlink", "release/lib/data"),
                ("./release/bin/tool", "symlink", "../lib/data"),
                ("./release/lib/data", "file", b"hello"),
                ("./release/bin/alias", "symlink", "tool"),
            ]
        )
        result = bootstrap.extract(self.archive, self.destination)
        self.assertEqual(result, self.destination)
        self.assertEqual((result / "bin/alias").read_bytes(), b"hello")
        self.assertEqual(
            (result / "lib/alias").stat().st_ino, (result / "lib/data").stat().st_ino
        )
        self.assertFalse((result / "release").exists())

    def test_empty_existing_directory_is_allowed(self):
        self.destination.mkdir()
        self.tar([("r/file", "file", b"data")])
        bootstrap.extract(self.archive, self.destination)
        self.assertEqual((self.destination / "file").read_bytes(), b"data")

    def test_nonempty_destination_is_never_replaced(self):
        self.destination.mkdir()
        (self.destination / "mine").write_bytes(b"keep")
        self.tar([("r/file", "file", b"data")])
        with self.assertRaises(FileExistsError):
            bootstrap.extract(self.archive, self.destination)
        self.assertEqual((self.destination / "mine").read_bytes(), b"keep")
        self.assertFalse((self.destination / "file").exists())

    def test_symlink_destination_is_never_followed(self):
        real = self.root / "real"
        real.mkdir()
        self.destination.symlink_to(real, target_is_directory=True)
        self.tar([("r/file", "file", b"data")])
        with self.assertRaises(FileExistsError):
            bootstrap.extract(self.archive, self.destination)
        self.assertEqual(list(real.iterdir()), [])

    def test_traversal_and_absolute_paths(self):
        for name in (
            "../outside",
            "r/../outside",
            "/outside",
            "r/../../outside",
            "r\\evil",
            "C:/evil",
        ):
            with self.subTest(name=name):
                self.reject([(name, "file", b"bad")])
        self.assertFalse((self.root / "outside").exists())

    def test_multiple_roots_duplicates_special_files_and_empty_tar(self):
        for entries in (
            [("a/file", "file", b"a"), ("b/file", "file", b"b")],
            [("r/file", "file", b"a"), ("r/file", "file", b"b")],
            [("r/pipe", "fifo", None)],
            [("r", "file", b"not a directory")],
            [],
        ):
            with self.subTest(entries=entries):
                self.reject(entries)

    def test_escaping_symlink_targets(self):
        for link in ("../../escape", "/tmp/escape", "C:/escape", "..\\escape"):
            with self.subTest(link=link):
                self.reject([("r/link", "symlink", link)])

    def test_member_cannot_traverse_symlink_or_file(self):
        for entries in (
            [("r/link", "symlink", "dir"), ("r/link/file", "file", b"bad")],
            [("r/link/file", "file", b"bad"), ("r/link", "symlink", "dir")],
            [("r/file", "file", b"bad"), ("r/file/child", "file", b"bad")],
        ):
            self.reject(entries)

    def test_symlink_cycles_and_indirect_escape(self):
        self.reject([("r/a", "symlink", "b"), ("r/b", "symlink", "a")])
        self.reject([("r/a", "symlink", "dir/.."), ("r/dir", "symlink", "..")])

    def test_hardlinks_reject_missing_outside_symlink_and_cycle(self):
        for entries in (
            [("r/h", "hardlink", "other/file")],
            [("r/h", "hardlink", "r/../file")],
            [("r/h", "hardlink", "/r/file")],
            [("r/h", "hardlink", "r/missing")],
            [
                ("r/h", "hardlink", "r/s"),
                ("r/s", "symlink", "file"),
                ("r/file", "file", b"x"),
            ],
            [("r/a", "hardlink", "r/b"), ("r/b", "hardlink", "r/a")],
        ):
            self.reject(entries)

    def test_forward_hardlink_chain(self):
        self.tar(
            [
                ("r/a", "hardlink", "r/b"),
                ("r/b", "hardlink", "r/c"),
                ("r/c", "file", b"x"),
            ]
        )
        bootstrap.extract(self.archive, self.destination)
        self.assertEqual((self.destination / "a").read_bytes(), b"x")

    def test_failed_publication_cleans_staging(self):
        self.tar([("r/file", "file", b"data")])
        with mock.patch.object(
            bootstrap.os, "rename", side_effect=OSError("publish failed")
        ):
            with self.assertRaisesRegex(OSError, "publish failed"):
                bootstrap.extract(self.archive, self.destination)
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.root.glob(".unpacked.extract-*")), [])

    def test_executable_mode_without_setuid(self):
        with tarfile.open(self.archive, "w") as archive:
            member = tarfile.TarInfo("r/tool")
            member.mode = 0o4755
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
        bootstrap.extract(self.archive, self.destination)
        self.assertEqual((self.destination / "tool").stat().st_mode & 0o7777, 0o755)


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.patch = mock.patch.object(bootstrap, "DOWNLOADS", self.root)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.good = b"verified archive bytes"
        self.spec = {
            "url": "https://example.invalid/source.tar",
            "filename": "source.tar",
            "sha256": hashlib.sha256(self.good).hexdigest(),
        }
        self.target = self.root / "source.tar"

    def fetch_good(self, url, target):
        self.assertEqual(url, self.spec["url"])
        target.write_bytes(self.good)
        self.assertNotEqual(target, self.target)

    def test_download_and_cached_reverification(self):
        with mock.patch.object(
            bootstrap, "_fetch", side_effect=self.fetch_good
        ) as fetch:
            self.assertEqual(bootstrap.download(self.spec), self.target)
            self.assertEqual(bootstrap.download(self.spec), self.target)
            fetch.assert_called_once()
        self.assertEqual(self.target.read_bytes(), self.good)
        self.assertEqual(list(self.root.glob("*.part")), [])

    def test_checksum_failure_never_publishes(self):
        with mock.patch.object(
            bootstrap, "_fetch", side_effect=lambda u, p: p.write_bytes(b"wrong")
        ):
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                bootstrap.download(self.spec)
        self.assertFalse(self.target.exists())
        self.assertFalse(any(p.name.endswith(".part") for p in self.root.iterdir()))

    def test_transfer_failure_preserves_bad_cache_and_cleans_partial(self):
        self.target.write_bytes(b"old corrupt cache")

        def fail(url, target):
            target.write_bytes(b"partial")
            raise subprocess.CalledProcessError(22, ["curl"])

        with mock.patch.object(bootstrap, "_fetch", side_effect=fail):
            with self.assertRaises(subprocess.CalledProcessError):
                bootstrap.download(self.spec)
        self.assertEqual(self.target.read_bytes(), b"old corrupt cache")
        self.assertFalse(any(p.name.endswith(".part") for p in self.root.iterdir()))

    def test_corrupt_cache_is_quarantined_after_verified_replacement(self):
        self.target.write_bytes(b"corrupt")
        with mock.patch.object(bootstrap, "_fetch", side_effect=self.fetch_good):
            bootstrap.download(self.spec)
        self.assertEqual(self.target.read_bytes(), self.good)
        quarantined = list(self.root.glob("source.tar.corrupt-*"))
        self.assertEqual(len(quarantined), 1)
        self.assertEqual(quarantined[0].read_bytes(), b"corrupt")

    def test_invalid_metadata_and_cache_symlinks(self):
        for change in (
            {"filename": "../escape"},
            {"filename": "x\\y"},
            {"sha256": "bad"},
            {"url": "http://example.invalid/file"},
            {"url": "file:///tmp/file"},
            {"url": "https://user:password@example.invalid/file"},
            {"size": -1},
        ):
            with self.subTest(change=change):
                with mock.patch.object(bootstrap, "_fetch") as fetch:
                    with self.assertRaises(ValueError):
                        bootstrap.download(dict(self.spec, **change))
                    fetch.assert_not_called()
        other = self.root / "other"
        other.write_bytes(self.good)
        self.target.symlink_to(other)
        with self.assertRaises(ValueError):
            bootstrap.download(self.spec)

    def test_size_mismatch_is_not_published(self):
        with mock.patch.object(bootstrap, "_fetch", side_effect=self.fetch_good):
            with self.assertRaisesRegex(ValueError, "Size mismatch"):
                bootstrap.download(dict(self.spec, size=1))
        self.assertFalse(self.target.exists())

    def test_curl_tls_retry_and_timeout_contract(self):
        with mock.patch.object(bootstrap.subprocess, "run") as run:
            bootstrap._fetch(self.spec["url"], self.target)
        args = run.call_args.args[0]
        self.assertEqual(args[:2], ["/usr/bin/curl", "--disable"])
        for flag in ("--proto", "--proto-redir"):
            self.assertEqual(args[args.index(flag) + 1], "=https")
        self.assertNotIn("--insecure", args)
        self.assertIn("--retry", args)
        self.assertIn("--connect-timeout", args)
        self.assertIn("--max-time", args)
        self.assertTrue(run.call_args.kwargs["check"])
        self.assertEqual(run.call_args.kwargs["timeout"], 1000)


class StateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        for name, path in (("ROOT", self.root), ("BUILD", self.root / "build")):
            patch = mock.patch.object(bootstrap, name, path)
            patch.start()
            self.addCleanup(patch.stop)
        self.work = self.root / "build/work"
        self.output = self.root / "prefix/lib.a"

    def install(self):
        self.work.mkdir(parents=True, exist_ok=True)
        self.output.parent.mkdir(parents=True, exist_ok=True)
        self.output.write_bytes(b"archive")
        return [self.output]

    def step(self, key=None, action=None):
        bootstrap._step(
            "fixture",
            key or {"sdk": "10.15", "input": "pinned"},
            self.work,
            [self.output],
            action or self.install,
        )

    def test_completed_step_reuses_only_verified_outputs(self):
        self.step()
        action = mock.Mock(side_effect=AssertionError("must not rebuild"))
        self.step(action=action)
        action.assert_not_called()
        self.output.write_bytes(b"modified")
        with self.assertRaisesRegex(RuntimeError, "output changed"):
            self.step(action=action)

    def test_changed_sdk_flags_or_inputs_fail_without_touching_outputs(self):
        self.step()
        with self.assertRaisesRegex(RuntimeError, "Obsolete bootstrap"):
            self.step(key={"sdk": "11.0", "input": "pinned"})
        self.assertEqual(self.output.read_bytes(), b"archive")

    def test_unowned_workspace_and_outputs_are_refused(self):
        self.work.mkdir(parents=True)
        (self.work / "user-file").write_bytes(b"keep")
        with self.assertRaisesRegex(RuntimeError, "Unowned nonempty"):
            self.step()
        self.assertEqual((self.work / "user-file").read_bytes(), b"keep")

    def test_pending_step_can_resume_same_inputs(self):
        def interrupt():
            self.work.mkdir(parents=True)
            raise RuntimeError("interrupted")

        with self.assertRaisesRegex(RuntimeError, "interrupted"):
            self.step(action=interrupt)
        self.step()
        self.assertEqual(self.output.read_bytes(), b"archive")

    def test_unowned_unrelated_prefix_contents_are_preserved(self):
        unrelated = self.root / "prefix/lib/libslirp.a"
        unrelated.parent.mkdir(parents=True)
        unrelated.write_bytes(b"previous slirp install")
        bootstrap._managed(self.root / "prefix")
        self.step()
        self.assertEqual(unrelated.read_bytes(), b"previous slirp install")
        self.assertEqual(self.output.read_bytes(), b"archive")

    def test_prefix_conflicts_checked_before_any_publication(self):
        first, second = self.root / "first", self.root / "second"
        first.write_bytes(b"one")
        second.write_bytes(b"two")
        conflict = self.root / "prefix/existing"
        conflict.parent.mkdir()
        conflict.write_bytes(b"user data")
        target = self.root / "prefix/new"
        with self.assertRaises(FileExistsError):
            bootstrap._install_files([(first, target), (second, conflict)])
        self.assertFalse(target.exists())
        self.assertEqual(conflict.read_bytes(), b"user data")

    def test_identical_partial_install_is_resumable(self):
        source = self.root / "source"
        source.write_bytes(b"content")
        target = self.root / "prefix/file"
        bootstrap._install_files([(source, target)])
        bootstrap._install_files([(source, target)])
        self.assertEqual(target.read_bytes(), b"content")


class SupportTests(unittest.TestCase):
    def test_native_sources_do_not_share_atomic_source_snapshot(self):
        self.assertEqual(
            bootstrap.DEPENDENCY_SOURCES,
            build_support.BUILD / "dependency-sources",
        )
        self.assertEqual(build_support.SOURCES, build_support.BUILD / "sources")
        self.assertNotEqual(bootstrap.DEPENDENCY_SOURCES, build_support.SOURCES)
        self.assertNotIn(build_support.SOURCES, bootstrap.DEPENDENCY_SOURCES.parents)

    def test_imports_do_not_run_preflight_or_commands(self):
        with mock.patch.object(
            subprocess,
            "check_output",
            side_effect=AssertionError("preflight on import"),
        ):
            with mock.patch.object(
                subprocess, "run", side_effect=AssertionError("command on import")
            ):
                importlib.reload(build_support)
                importlib.reload(bootstrap)

    def test_lock_metadata(self):
        inputs = bootstrap.load_lock()
        self.assertEqual(inputs["go"]["version"], "1.22.12")
        self.assertEqual(inputs["llvm"]["version"], "10.0.1")
        self.assertEqual(inputs["glib"]["version"], "2.66.8")
        self.assertNotIn("slirp", inputs)

    def test_environment_isolated_and_catalina_flags_retained(self):
        tools = {
            "ar": "/apple/bin/ar",
            "ranlib": "/apple/bin/ranlib",
            "ld": "/apple/bin/ld",
            "clang": "/apple/bin/clang",
            "sdk": "/apple/sdk",
            "sdk_version": "10.15",
        }
        with mock.patch.dict(
            os.environ,
            {
                "CPATH": "/poison",
                "PYTHONPATH": "/poison",
                "GOFLAGS": "-mod=mod",
                "GOPROXY": "https://poison",
                "MAKEFLAGS": "-e",
                "LIMA_COMPILER": "llvm",
            },
        ):
            env = build_support._environment(tools)
        for name in ("CPATH", "PYTHONPATH", "GOFLAGS", "MAKEFLAGS"):
            self.assertNotIn(name, env)
        self.assertEqual(env["CC"], str(build_support.LLVM / "clang"))
        self.assertEqual(env["CXX"], str(build_support.LLVM / "clang++"))
        self.assertEqual(env["OBJC"], env["CC"])
        self.assertEqual(env["PATH"].split(":")[0], str(build_support.LLVM))
        self.assertEqual(env["MACOSX_DEPLOYMENT_TARGET"], "10.15")
        self.assertIn("-mmacosx-version-min=10.15", env["LDFLAGS"])
        self.assertEqual(env["GOPROXY"], "off")
        self.assertEqual(env["NINJA"], str(build_support.ROOT / "tools/bin/ninja"))
        for name in (
            "GOPATH",
            "GOMODCACHE",
            "GOCACHE",
            "GOTMPDIR",
            "TMPDIR",
            "PIP_CACHE_DIR",
        ):
            self.assertTrue(Path(env[name]).relative_to(build_support.ROOT).parts)

    def test_compiler_mode_defaults_to_llvm_and_rejects_unknown_values(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(build_support.compiler_mode(), "llvm")
        for mode in ("", "clang", "Apple"):
            with (
                self.subTest(mode=mode),
                mock.patch.dict(os.environ, {"LIMA_COMPILER": mode}),
            ):
                with self.assertRaisesRegex(RuntimeError, "LIMA_COMPILER"):
                    build_support._environment({})

    def test_apple_mode_uses_discovered_compilers_and_isolated_flags(self):
        tools = {
            "ar": "/apple/bin/ar",
            "ranlib": "/apple/bin/ranlib",
            "ld": "/apple/bin/ld",
            "clang": "/apple/bin/clang",
            "clang++": "/apple/bin/clang++",
            "sdk": "/apple/sdk",
        }
        with mock.patch.dict(
            os.environ,
            {"LIMA_COMPILER": "apple", "CC": "/poison", "CXXFLAGS": "-I/poison"},
        ):
            env = build_support._environment(tools)
        self.assertEqual(env["LIMA_COMPILER"], "apple")
        self.assertEqual(env["CC"], tools["clang"])
        self.assertEqual(env["CXX"], tools["clang++"])
        self.assertEqual(env["OBJC"], tools["clang"])
        self.assertEqual(env["PATH"].split(":")[0], "/apple/bin")
        self.assertNotIn(str(build_support.LLVM), env["PATH"].split(":"))
        for name in ("CFLAGS", "CXXFLAGS", "OBJCFLAGS", "LDFLAGS"):
            self.assertIn("-mmacosx-version-min=10.15", env[name])
            self.assertIn("-isysroot /apple/sdk", env[name])
            self.assertNotIn("/poison", env[name])

    def test_xcrun_discovers_cxx_and_fingerprint_distinguishes_modes(self):
        def query(args, **kwargs):
            self.assertEqual(kwargs["timeout"], 30)
            if args[1] == "--find":
                return "/apple/bin/" + args[2]
            return "/apple/sdk" if args[1] == "--show-sdk-path" else "15.5"

        with (
            mock.patch.object(build_support, "check_host"),
            mock.patch.object(subprocess, "check_output", side_effect=query),
            mock.patch.object(Path, "is_dir", return_value=True),
            mock.patch.object(Path, "is_file", return_value=True),
            mock.patch.object(Path, "read_bytes", return_value=b"tool identity"),
        ):
            with mock.patch.dict(os.environ, {"LIMA_COMPILER": "llvm"}):
                llvm = build_support.fingerprint()
            with mock.patch.dict(os.environ, {"LIMA_COMPILER": "apple"}):
                apple = build_support.fingerprint()
        self.assertEqual(apple["tools"]["clang++"], "/apple/bin/clang++")
        self.assertIn("clang++", apple["apple_sha256"])
        self.assertNotEqual(llvm, apple)
        self.assertEqual(llvm["environment"]["LIMA_COMPILER"], "llvm")
        self.assertEqual(apple["environment"]["LIMA_COMPILER"], "apple")

    def test_qemu_configure_uses_selected_environment_compilers(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "native_compiler_test", build_support.ROOT / "build_native.py"
        )
        for compiler in (build_support.LLVM, Path("/apple/bin")):
            with self.subTest(compiler=compiler):
                env = {
                    "CC": str(compiler / "clang"),
                    "CXX": str(compiler / "clang++"),
                    "OBJC": str(compiler / "clang"),
                }
                with mock.patch.object(build_support, "environment", return_value=env):
                    native = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(native)
                with (
                    mock.patch.object(Path, "mkdir"),
                    mock.patch.object(native, "run") as run,
                ):
                    native.configure()
                args = run.call_args.args[0]
                self.assertIn("--cc=" + env["CC"], args)
                self.assertIn("--cxx=" + env["CXX"], args)
                self.assertIn("--objcc=" + env["OBJC"], args)


if __name__ == "__main__":
    unittest.main()
