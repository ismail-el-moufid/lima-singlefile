"""Isolated orchestration tests; no host tools, downloads, or project build writes.

Run: python3 -B -m unittest discover -s tests -p test_build.py -v

"""

import contextlib
import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

import bootstrap
import build as orchestration
import build_support as support
import fetch_test_image as fixture
import prepare_sources as sources

IDENTITY_FILES = (
    "build.py",
    "bootstrap.py",
    "build_support.py",
    "build_native.py",
    "link_lima.py",
    "prepare_sources.py",
    "dependencies.lock.json",
    "sources.lock.json",
    "source-overlays.json",
    "native/overrides.json",
)


class IsolatedBuildTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="test-build-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.build = self.root / "build/self-contained"
        self.source = self.build / "sources"
        self.marker = self.build / "prepared.json"
        self.stamp = self.source / sources.STAMP
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
        self.stack.enter_context(
            mock.patch.multiple(
                support,
                ROOT=self.root,
                BUILD=self.build,
                SOURCES=self.source,
                PREFIX=self.root / "prefix",
                LLVM=self.root / "tools/llvm/bin",
                PYTHON=self.root / "tools/python/bin/python",
                GO=self.root / "tools/go/bin/go",
                MESON=str(self.root / "tools/python/bin/meson"),
                NINJA=str(self.root / "tools/bin/ninja"),
            )
        )
        # All command execution must be explicitly allowed by an individual test.
        self.process = self.patch(
            subprocess, "run", side_effect=AssertionError("unexpected command")
        )
        self.patch(
            subprocess, "Popen", side_effect=AssertionError("host process forbidden")
        )
        self.patch(socket, "socket", side_effect=AssertionError("network forbidden"))
        self.download = self.patch(
            bootstrap, "download", side_effect=AssertionError("download forbidden")
        )
        self.patch(
            bootstrap, "_fetch", side_effect=AssertionError("network fetch forbidden")
        )
        self.patch(
            bootstrap, "extract", side_effect=AssertionError("extraction forbidden")
        )
        self.host = self.patch(support, "check_host")
        self.fingerprint = self.patch(
            support, "fingerprint", return_value={"sdk": "test-sdk"}
        )
        self.tools = {
            "sdk": str(self.root / "sdk"),
            "ar": str(self.root / "apple/bin/ar"),
            "ranlib": str(self.root / "apple/bin/ranlib"),
            "ld": str(self.root / "apple/bin/ld"),
            "clang": str(self.root / "apple/bin/clang"),
        }
        self.patch(support, "apple_tools", return_value=self.tools)
        self.bootstrap = self.patch(
            bootstrap, "bootstrap", side_effect=AssertionError("bootstrap forbidden")
        )
        self.fetch_image = self.patch(
            fixture, "fetch_test_image", side_effect=AssertionError("fixture forbidden")
        )

    def patch(self, target, name, **kwargs):
        return self.stack.enter_context(mock.patch.object(target, name, **kwargs))

    def write(self, relative, contents):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(contents, bytes):
            path.write_bytes(contents)
        else:
            path.write_text(contents, encoding="utf-8")
        return path

    def make_modules(self):
        self.original_modules = {
            "go.mod": b"module example.invalid/test\n",
            "go.sum": b"locked sums\n",
        }
        for name, contents in self.original_modules.items():
            self.write("build/self-contained/sources/lima/" + name, contents)


class OrchestrationFixture(IsolatedBuildTest):
    def setUp(self):
        super().setUp()
        self.events = []
        self.locked = False
        self.identity_value = {
            "files": {"recipe": "digest"},
            "host": {"sdk": "test-sdk"},
        }
        self.identity = self.patch(
            orchestration, "preparation_identity", side_effect=self.get_identity
        )
        self.prepare = self.patch(
            orchestration,
            "prepare_sources",
            side_effect=lambda download=None: self.record("sources"),
        )
        self.modules = self.patch(
            orchestration, "modules", side_effect=self.prepare_modules
        )
        self.bootstrap.side_effect = lambda: self.record("bootstrap")
        self.fetch_image.side_effect = lambda: self.record("fixture")
        self.process.side_effect = self.native_command
        self.real_lock = bootstrap._file_lock
        self.flock = self.patch(bootstrap.fcntl, "flock")
        self.lock = self.patch(bootstrap, "_file_lock", side_effect=self.build_lock)
        self.real_replace = os.replace
        self.replace = self.patch(
            bootstrap.os, "replace", side_effect=self.publish_marker
        )

    def record(self, event):
        self.assertTrue(self.locked, event + " ran outside the build lock")
        self.events.append(event)

    @contextlib.contextmanager
    def build_lock(self, path):
        self.assertEqual(path, self.build / ".build.lock")
        self.assertFalse(self.locked)
        with self.real_lock(path):
            self.locked = True
            self.events.append("lock")
            try:
                yield
            finally:
                self.events.append("unlock")
                self.locked = False

    def get_identity(self):
        self.record("identity")
        return self.identity_value

    def prepare_modules(self, offline=False):
        self.record("modules-offline" if offline else "modules-online")

    def publish_marker(self, source, destination):
        self.record("marker")
        source = Path(source)
        self.assertEqual(source.parent, self.marker.parent)
        self.assertTrue(source.name.startswith("." + self.marker.name))
        self.assertTrue(source.is_file())
        self.assertFalse(source.is_symlink())
        self.assertEqual(destination, self.marker)
        self.assertEqual(json.loads(source.read_text()), self.identity_value)
        self.real_replace(source, destination)

    def native_command(self, command, **kwargs):
        native = [sys.executable, str(self.root / "build_native.py")]
        link = [sys.executable, str(self.root / "link_lima.py")]
        if command == link:
            stage = "link"
        else:
            self.assertEqual(command[:2], native)
            self.assertEqual(len(command), 3)
            self.assertIn(command[2], ("slirp", "configure", "build"))
            stage = command[2]
        self.assertEqual(kwargs, {"cwd": self.root, "check": True})
        self.assertEqual(json.loads(self.marker.read_text()), self.identity_value)
        self.record(stage)
        return subprocess.CompletedProcess(command, 0)

    def mark_prepared(self, stamp=True):
        self.build.mkdir(parents=True, exist_ok=True)
        self.marker.write_text(json.dumps(self.identity_value) + "\n")
        if stamp:
            self.source.mkdir(parents=True, exist_ok=True)
            self.stamp.write_text("{}\n")

    def assert_lock_released(self):
        self.assertFalse(self.locked)
        self.assertEqual(self.events[-1], "unlock")
        self.flock.assert_called_once()
        handle, operation = self.flock.call_args[0]
        self.assertEqual(operation, bootstrap.fcntl.LOCK_EX)
        self.assertTrue(handle.closed)


class OrchestrationTests(OrchestrationFixture):
    def test_default_online_sequence_and_atomic_marker_before_native(self):
        self.assertEqual(orchestration.main([]), 0)
        self.assertEqual(
            self.events,
            [
                "lock",
                "bootstrap",
                "sources",
                "modules-online",
                "identity",
                "marker",
                "slirp",
                "configure",
                "build",
                "link",
                "unlock",
            ],
        )
        self.prepare.assert_called_once_with(download=None)
        self.modules.assert_called_once_with(offline=False)
        self.fetch_image.assert_not_called()
        self.replace.assert_called_once()
        self.assertEqual(list(self.build.glob(".prepared.json*")), [])
        self.assert_lock_released()

    def test_prepare_only_stops_after_publishing_marker(self):
        self.assertEqual(orchestration.main(["--prepare-only"]), 0)
        self.assertEqual(
            self.events,
            [
                "lock",
                "bootstrap",
                "sources",
                "modules-online",
                "identity",
                "marker",
                "unlock",
            ],
        )
        self.process.assert_not_called()
        self.fetch_image.assert_not_called()
        self.assert_lock_released()

    def test_optional_fixture_is_prepared_before_marker_and_native(self):
        self.assertEqual(orchestration.main(["--with-test-image"]), 0)
        self.assertEqual(
            self.events,
            [
                "lock",
                "bootstrap",
                "sources",
                "modules-online",
                "fixture",
                "identity",
                "marker",
                "slirp",
                "configure",
                "build",
                "link",
                "unlock",
            ],
        )
        self.fetch_image.assert_called_once_with()

    def test_prepare_only_can_include_fixture_without_native_build(self):
        self.assertEqual(orchestration.main(["--prepare-only", "--with-test-image"]), 0)
        self.fetch_image.assert_called_once_with()
        self.assertLess(self.events.index("fixture"), self.events.index("marker"))
        self.process.assert_not_called()

    def test_offline_checks_identity_before_reuse_and_never_rewrites_marker(self):
        self.mark_prepared()
        before = self.marker.read_bytes()
        self.assertEqual(orchestration.main(["--offline"]), 0)
        self.assertEqual(
            self.events,
            [
                "lock",
                "identity",
                "sources",
                "modules-offline",
                "slirp",
                "configure",
                "build",
                "link",
                "unlock",
            ],
        )
        self.bootstrap.assert_not_called()
        self.fetch_image.assert_not_called()
        self.download.assert_not_called()
        self.prepare.assert_called_once_with(
            download=orchestration._reject_offline_download
        )
        self.modules.assert_called_once_with(offline=True)
        self.replace.assert_not_called()
        self.assertEqual(self.marker.read_bytes(), before)
        self.assert_lock_released()

    def assert_offline_rejected(self, error, message):
        with self.assertRaisesRegex(error, message):
            orchestration.main(["--offline"])
        for function in (
            self.bootstrap,
            self.prepare,
            self.modules,
            self.fetch_image,
            self.download,
            self.process,
            self.replace,
        ):
            function.assert_not_called()
        self.assert_lock_released()

    def test_offline_missing_marker_stops_without_preparation_or_network(self):
        self.assert_offline_rejected(RuntimeError, "prepare-only")
        self.identity.assert_not_called()

    def test_offline_changed_identity_stops_without_preparation_or_network(self):
        self.mark_prepared()
        self.identity_value = {"host": "changed"}
        self.assert_offline_rejected(RuntimeError, "inputs or host changed")

    def test_offline_malformed_marker_stops_without_preparation_or_network(self):
        self.mark_prepared()
        self.marker.write_text("{not json")
        self.assert_offline_rejected(ValueError, "")
        self.identity.assert_not_called()

    def test_offline_missing_source_stamp_cannot_fall_through_to_downloader(self):
        self.mark_prepared(stamp=False)
        self.assert_offline_rejected(RuntimeError, "sources are missing")
        self.identity.assert_called_once_with()

    def test_offline_unstamped_existing_directory_is_also_rejected(self):
        self.mark_prepared(stamp=False)
        self.source.mkdir()
        self.assert_offline_rejected(RuntimeError, "sources are missing")

    def test_conflicting_cli_options_do_not_start_work(self):
        for arguments in (
            ["--offline", "--prepare-only"],
            ["--offline", "--with-test-image"],
        ):
            with (
                self.subTest(arguments=arguments),
                self.assertRaises(SystemExit) as caught,
            ):
                orchestration.main(arguments)
            self.assertEqual(caught.exception.code, 2)
        for function in (
            self.lock,
            self.bootstrap,
            self.prepare,
            self.modules,
            self.process,
        ):
            function.assert_not_called()
        self.assertFalse(self.build.exists())

    def test_unsupported_host_stops_before_lock_or_mutation(self):
        self.host.side_effect = RuntimeError("unsupported host")
        with self.assertRaisesRegex(RuntimeError, "unsupported host"):
            orchestration.main([])
        self.lock.assert_not_called()
        self.bootstrap.assert_not_called()
        self.assertFalse(self.build.exists())

    def test_lock_acquisition_failure_stops_all_stages(self):
        self.flock.side_effect = OSError("lock denied")
        with self.assertRaisesRegex(OSError, "lock denied"):
            orchestration.main([])
        self.assertEqual(self.events, [])
        self.bootstrap.assert_not_called()
        self.prepare.assert_not_called()
        self.modules.assert_not_called()
        self.process.assert_not_called()
        self.assertTrue(self.flock.call_args[0][0].closed)
        self.assertFalse(self.marker.exists())

    def assert_stage_failure(self, stage, error, arguments=None):
        record = self.record

        def fail_at(event):
            record(event)
            if event == stage:
                raise error

        self.record = fail_at
        with self.assertRaises(type(error)) as caught:
            orchestration.main(arguments or ["--with-test-image"])
        self.assertIs(caught.exception, error)
        full = [
            "bootstrap",
            "sources",
            "modules-online",
            "fixture",
            "identity",
            "marker",
            "slirp",
            "configure",
            "build",
            "link",
        ]
        self.assertEqual(
            self.events, ["lock"] + full[: full.index(stage) + 1] + ["unlock"]
        )
        self.assert_lock_released()
        if full.index(stage) <= full.index("marker"):
            self.assertFalse(self.marker.exists())
            self.process.assert_not_called()
        else:
            self.assertTrue(self.marker.is_file())

    def test_bootstrap_failure_stops_preparation_and_build(self):
        self.assert_stage_failure("bootstrap", RuntimeError("bootstrap failed"))

    def test_source_failure_stops_modules_and_build(self):
        self.assert_stage_failure("sources", sources.SourceError("source drift"))

    def test_module_failure_stops_fixture_marker_and_build(self):
        self.assert_stage_failure(
            "modules-online", subprocess.CalledProcessError(1, ["mock-go"])
        )

    def test_fixture_failure_stops_marker_and_build(self):
        self.assert_stage_failure("fixture", ValueError("fixture hash mismatch"))

    def test_identity_failure_does_not_publish_marker(self):
        self.assert_stage_failure("identity", OSError("missing identity file"))

    def test_marker_publication_failure_stops_native_build(self):
        self.assert_stage_failure("marker", OSError("rename failed"))
        self.assertEqual(list(self.build.glob(".prepared.json*")), [])

    def test_marker_publication_failure_preserves_previous_marker(self):
        self.mark_prepared(stamp=False)
        previous = self.marker.read_bytes()
        self.replace.side_effect = OSError("rename failed")
        with self.assertRaisesRegex(OSError, "rename failed"):
            orchestration.main(["--prepare-only"])
        self.assertEqual(self.marker.read_bytes(), previous)
        self.assertEqual(list(self.build.glob(".prepared.json*")), [])
        self.process.assert_not_called()
        self.assert_lock_released()

    def test_marker_serialization_failure_cleans_temporary_and_stops_build(self):
        self.patch(bootstrap.json, "dump", side_effect=OSError("write failed"))
        with self.assertRaisesRegex(OSError, "write failed"):
            orchestration.main([])
        self.assertFalse(self.marker.exists())
        self.assertEqual(list(self.build.glob(".prepared.json*")), [])
        self.replace.assert_not_called()
        self.process.assert_not_called()
        self.assert_lock_released()

    def test_slirp_failure_stops_remaining_native_stages(self):
        self.assert_stage_failure(
            "slirp", subprocess.CalledProcessError(1, ["mock-native"])
        )

    def test_configure_failure_stops_build_and_link(self):
        self.assert_stage_failure(
            "configure", subprocess.CalledProcessError(1, ["mock-native"])
        )

    def test_native_runner_timeout_failure_stops_link_and_releases_lock(self):
        # The inner runner cleans up its workers, then exits nonzero on timeout.
        self.assert_stage_failure(
            "build", subprocess.CalledProcessError(1, ["mock-native", "build"])
        )

    def test_link_failure_is_propagated(self):
        self.assert_stage_failure(
            "link", subprocess.CalledProcessError(1, ["mock-link"])
        )

    def test_interruption_releases_lock_without_publishing_marker(self):
        self.assert_stage_failure("sources", KeyboardInterrupt())

    def test_marker_temporary_symlink_must_not_overwrite_unrelated_file(self):
        # An old predictable temporary pathname must never be opened for writing.
        victim = self.write("unrelated.txt", "keep me\n")
        self.build.mkdir(parents=True, exist_ok=True)
        try:
            self.marker.with_suffix(".tmp").symlink_to(victim)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation unavailable")
        self.assertEqual(orchestration.main(["--prepare-only"]), 0)
        self.assertEqual(victim.read_text(), "keep me\n")
        self.assertTrue(self.marker.with_suffix(".tmp").is_symlink())
        self.assertFalse(self.marker.is_symlink())
        self.assertEqual(json.loads(self.marker.read_text()), self.identity_value)
        self.assertEqual(list(self.build.glob(".prepared.json*")), [])


class ModuleTests(IsolatedBuildTest):
    def setUp(self):
        super().setUp()
        self.make_modules()
        self.process.side_effect = None
        self.process.return_value = subprocess.CompletedProcess([], 0)

    def test_module_commands_use_isolated_environment_and_no_direct_fallback(self):
        for offline in (False, True):
            with self.subTest(offline=offline):
                self.process.reset_mock()
                with mock.patch.dict(
                    os.environ,
                    {
                        "GOPROXY": "https://untrusted.invalid,direct",
                        "GOSUMDB": "untrusted.invalid",
                        "GONOPROXY": "*",
                        "GOPRIVATE": "*",
                        "GOFLAGS": "-mod=mod",
                        "GOTOOLCHAIN": "auto",
                        "GOWORK": "/untrusted/go.work",
                    },
                ):
                    orchestration.modules(offline=offline)
                self.assertEqual(self.process.call_count, 2)
                for call, operation in zip(
                    self.process.call_args_list, ("download", "verify")
                ):
                    command = call[0][0]
                    options = call[1]
                    self.assertEqual(command, [str(support.GO), "mod", operation])
                    self.assertEqual(options["cwd"], self.source / "lima")
                    self.assertTrue(options["check"])
                    self.assertEqual(options["timeout"], 900)
                    self.assertEqual(options["stderr"], subprocess.STDOUT)
                    self.assertTrue(options["stdout"].closed)
                    env = options["env"]
                    self.assertEqual(
                        env["GOPROXY"], "off" if offline else "https://proxy.golang.org"
                    )
                    self.assertEqual(
                        env["GOSUMDB"], "off" if offline else "sum.golang.org"
                    )
                    self.assertEqual(env["GOTOOLCHAIN"], "local")
                    self.assertEqual(env["GOENV"], "off")
                    self.assertEqual(env["GOWORK"], "off")
                    self.assertEqual(
                        env["GOMODCACHE"], str(self.root / "cache/modules")
                    )
                    for variable in ("GOPRIVATE", "GONOPROXY", "GOFLAGS"):
                        self.assertNotIn(variable, env)
                first, second = self.process.call_args_list
                self.assertIs(first[1]["stdout"], second[1]["stdout"])
                self.assertIs(first[1]["env"], second[1]["env"])
                for name, contents in self.original_modules.items():
                    self.assertEqual(
                        (self.source / "lima" / name).read_bytes(), contents
                    )

    def test_either_module_file_drift_is_rejected_without_silently_restoring(self):
        for name in self.original_modules:
            with self.subTest(name=name):
                self.make_modules()
                changed = self.source / "lima" / name

                def mutate(*args, **kwargs):
                    changed.write_bytes(b"unreviewed changes\n")

                self.process.side_effect = mutate
                with self.assertRaisesRegex(RuntimeError, "Go changed go.mod/go.sum"):
                    orchestration.modules()
                self.assertEqual(changed.read_bytes(), b"unreviewed changes\n")

    def test_download_failure_prevents_verify(self):
        error = subprocess.CalledProcessError(7, ["mock-go", "mod", "download"])
        self.process.side_effect = error
        with self.assertRaises(subprocess.CalledProcessError) as caught:
            orchestration.modules(offline=True)
        self.assertIs(caught.exception, error)
        self.process.assert_called_once()

    def test_verify_failure_is_propagated(self):
        error = subprocess.CalledProcessError(1, ["mock-go", "mod", "verify"])
        self.process.side_effect = [subprocess.CompletedProcess([], 0), error]
        with self.assertRaises(subprocess.CalledProcessError) as caught:
            orchestration.modules()
        self.assertIs(caught.exception, error)
        self.assertEqual(self.process.call_count, 2)

    def test_timeout_prevents_verify(self):
        error = subprocess.TimeoutExpired(["mock-go"], 900)
        self.process.side_effect = error
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            orchestration.modules(offline=True)
        self.assertIs(caught.exception, error)
        self.process.assert_called_once()

    def test_drift_is_checked_even_when_go_fails(self):
        error = subprocess.CalledProcessError(1, ["mock-go"])

        def mutate_and_fail(*args, **kwargs):
            (self.source / "lima/go.sum").write_bytes(b"changed before failure\n")
            raise error

        self.process.side_effect = mutate_and_fail
        with self.assertRaisesRegex(RuntimeError, "Go changed go.mod/go.sum") as caught:
            orchestration.modules()
        self.assertIs(caught.exception.__context__, error)
        self.process.assert_called_once()

    def test_missing_module_file_stops_before_running_go(self):
        (self.source / "lima/go.sum").unlink()
        with self.assertRaises(FileNotFoundError):
            orchestration.modules()
        self.process.assert_not_called()


class PreparationIdentityTests(IsolatedBuildTest):
    def setUp(self):
        super().setUp()
        for name in IDENTITY_FILES:
            self.write(name, "fixture: " + name + "\n")

    def test_identity_hashes_all_declared_inputs_and_host(self):
        identity = orchestration.preparation_identity()
        self.assertEqual(
            identity["files"],
            {
                name: hashlib.sha256((self.root / name).read_bytes()).hexdigest()
                for name in IDENTITY_FILES
            },
        )
        self.assertEqual(identity["host"], self.fingerprint.return_value)
        self.process.assert_not_called()

    def test_each_recipe_or_lock_change_invalidates_identity(self):
        before = orchestration.preparation_identity()
        for name in IDENTITY_FILES:
            with self.subTest(name=name):
                path = self.root / name
                original = path.read_bytes()
                path.write_bytes(original + b"changed\n")
                after = orchestration.preparation_identity()
                self.assertNotEqual(before, after)
                self.assertNotEqual(before["files"][name], after["files"][name])
                path.write_bytes(original)

    def test_host_change_invalidates_identity(self):
        before = orchestration.preparation_identity()
        self.fingerprint.return_value = {"sdk": "different-sdk"}
        self.assertNotEqual(before, orchestration.preparation_identity())

    def test_missing_identity_input_fails_closed(self):
        (self.root / "sources.lock.json").unlink()
        with self.assertRaises(FileNotFoundError):
            orchestration.preparation_identity()


class SourceHelperCompatibilityTests(OrchestrationFixture):
    """Use the real helper with tiny stamped trees, never the live preparation."""

    def make_snapshot(self):
        lock = {"format": 1, "sources": {}, "copies": []}
        for name in sources.SOURCE_NAMES:
            lock["sources"][name] = {
                "url": "https://example.invalid/" + name + ".tar.gz",
                "sha256": "a" * 64,
                "filename": name + ".tar.gz",
                "archive_root": name,
                "revision": "b" * 40,
                "destination": name,
            }
            self.write(
                "build/self-contained/sources/" + name + "/tracked.txt", name + "\n"
            )
        self.make_modules()
        self.write(
            "build/self-contained/sources/lima/cmd/limactl/main.go", "package main\n"
        )
        self.write("build/self-contained/sources/qemu/scripts/tool.py", "# fixture\n")
        self.write("sources.lock.json", json.dumps(lock))
        self.write("source-overlays.json", json.dumps({"format": 1, "overlays": []}))
        inputs = {
            "sources.lock.json": sources.sha256(self.root / "sources.lock.json"),
            "source-overlays.json": sources.sha256(self.root / "source-overlays.json"),
            "prepare_sources.py": sources.sha256(Path(sources.__file__)),
        }
        self.stamp.write_text(
            json.dumps(
                {
                    "format": 1,
                    "inputs": inputs,
                    "tree": sources.snapshot(self.source),
                }
            )
        )
        self.mark_prepared(stamp=False)
        self.prepare.side_effect = self.real_prepare

    def real_prepare(self, *, download=None):
        self.record("sources")
        return sources.prepare_sources(
            root=self.root, destination=self.source, download=download
        )

    def test_real_helper_reuses_valid_snapshot_without_download_or_extract(self):
        self.make_snapshot()
        before = self.stamp.read_bytes()
        self.assertEqual(orchestration.main(["--offline"]), 0)
        self.download.assert_not_called()
        self.bootstrap.assert_not_called()
        self.modules.assert_called_once_with(offline=True)
        self.assertEqual(self.stamp.read_bytes(), before)
        self.assertFalse((self.build / ".sources.prepare.lock").exists())

    def test_generated_go_flags_and_python_caches_do_not_invalidate_snapshot(self):
        self.make_snapshot()
        for path in (
            "lima/cmd/limactl/native_link_flags.go",
            "qemu/scripts/__pycache__/tool.cpython-38.pyc",
            "qemu/scripts/tool.pyc",
            "qemu/scripts/tool.pyo",
        ):
            self.write("build/self-contained/sources/" + path, "generated\n")
        self.assertEqual(orchestration.main(["--offline"]), 0)
        self.download.assert_not_called()
        self.assertEqual(self.process.call_count, 4)

    def test_real_helper_rejects_tracked_source_drift_without_network(self):
        self.make_snapshot()
        (self.source / "qemu/tracked.txt").write_text("drift\n")
        with self.assertRaisesRegex(sources.SourceError, "source drift"):
            orchestration.main(["--offline"])
        self.modules.assert_not_called()
        self.process.assert_not_called()
        self.download.assert_not_called()
        self.assertFalse((self.build / ".sources.prepare.lock").exists())
        self.assert_lock_released()

    def test_real_helper_rejects_go_mod_and_go_sum_drift_before_modules(self):
        self.make_snapshot()
        for name, original in self.original_modules.items():
            with self.subTest(name=name):
                path = self.source / "lima" / name
                path.write_bytes(b"drift\n")
                with self.assertRaisesRegex(sources.SourceError, "source drift"):
                    orchestration.main(["--offline"])
                path.write_bytes(original)
        self.modules.assert_not_called()
        self.process.assert_not_called()
        self.download.assert_not_called()

    def test_malformed_source_stamp_does_not_trigger_redownload(self):
        self.make_snapshot()
        self.stamp.write_text("{malformed")
        with self.assertRaises(sources.SourceError):
            orchestration.main(["--offline"])
        self.download.assert_not_called()
        self.modules.assert_not_called()
        self.process.assert_not_called()

    def test_stale_source_inputs_do_not_trigger_redownload(self):
        self.make_snapshot()
        stamp = json.loads(self.stamp.read_text())
        stamp["inputs"]["sources.lock.json"] = "outdated"
        self.stamp.write_text(json.dumps(stamp))
        with self.assertRaisesRegex(sources.SourceError, "stale inputs"):
            orchestration.main(["--offline"])
        self.download.assert_not_called()
        self.modules.assert_not_called()
        self.process.assert_not_called()

    def test_existing_source_preparation_lock_is_preserved_and_stops_build(self):
        self.make_snapshot()
        lock = self.build / ".sources.prepare.lock"
        lock.write_text("owned by another preparer\n")
        with self.assertRaisesRegex(sources.SourceError, "Preparation lock exists"):
            orchestration.main(["--offline"])
        self.assertEqual(lock.read_text(), "owned by another preparer\n")
        self.download.assert_not_called()
        self.modules.assert_not_called()
        self.process.assert_not_called()
        self.assert_lock_released()

    def test_offline_snapshot_disappearance_must_not_fall_through_to_download(self):
        # Simulate removal after the stamp precheck but before the helper's lock.
        self.make_snapshot()

        def disappear_before_prepare(*, download=None):
            shutil.rmtree(self.source)
            return self.real_prepare(download=download)

        self.prepare.side_effect = disappear_before_prepare
        with self.assertRaisesRegex(
            RuntimeError, "Source download forbidden in --offline mode"
        ):
            orchestration.main(["--offline"])
        self.modules.assert_not_called()
        self.process.assert_not_called()
        self.download.assert_not_called()
        self.assertFalse((self.build / ".sources.prepare.lock").exists())
        self.assert_lock_released()


if __name__ == "__main__":
    unittest.main()
