"""Pinned native bootstrap, plus import-safe download/extract APIs for source preparation.

Run `python3 bootstrap.py --download-only` to fill the verified cache, or omit the
flag to install the toolchain and static dependencies. No QEMU/slirp sources or
builds are managed here. Existing unowned or obsolete installations are refused.
"""

import argparse
import fcntl
import hashlib
import json
import os
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

import build_support as support
from build_support import BUILD, GO, LLVM, MESON, NINJA, PREFIX, PYTHON, ROOT

DOWNLOADS = ROOT / "downloads"
# The atomic Lima/QEMU/libslirp snapshot owns support.SOURCES exclusively.
DEPENDENCY_SOURCES = BUILD / "dependency-sources"
LOCKFILE = ROOT / "dependencies.lock.json"
WHEELS = ("meson", "pycotap", "packaging", "tomli")


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _filename(name):
    if (
        not isinstance(name, str)
        or not name
        or name in {".", ".."}
        or any(c in name for c in "/\\\x00")
    ):
        raise ValueError("Expected a plain filename, got " + repr(name))
    return name


def _spec(spec):
    name = _filename(spec["filename"])
    sha = spec["sha256"]
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", sha):
        raise ValueError("Invalid SHA-256 for " + name)
    url = urlsplit(spec["url"])
    if url.scheme != "https" or not url.hostname or url.username or url.password:
        raise ValueError("Downloads require an HTTPS URL without credentials")
    if "size" in spec and (type(spec["size"]) is not int or spec["size"] <= 0):
        raise ValueError("Invalid download size for " + name)
    return name, sha.lower()


def _exists(path):
    return path.exists() or path.is_symlink()


@contextmanager
def _file_lock(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def _fetch(url, target):
    # System curl uses macOS trust, unlike some otherwise usable Python installs.
    # Disable ~/.curlrc and forbid insecure redirects as well as initial URLs.
    subprocess.run(
        [
            "/usr/bin/curl",
            "--disable",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--connect-timeout",
            "20",
            "--max-time",
            "600",
            "--retry",
            "3",
            "--retry-connrefused",
            "--retry-delay",
            "2",
            "--retry-max-time",
            "900",
            "--output",
            str(target),
            url,
        ],
        check=True,
        timeout=1000,
    )


def download(spec):
    """Return a verified cached Path for {url, sha256, filename[, size]}.

    A failed transfer/hash never publishes a partial file. Corrupt cached bytes
    remain untouched on failure and are quarantined only after a verified
    replacement is available. The operation is serialized per cache filename.
    """
    name, expected = _spec(spec)
    if DOWNLOADS.is_symlink():
        raise ValueError("Refusing a symlinked download directory")
    DOWNLOADS.mkdir(parents=True, exist_ok=True)
    target = DOWNLOADS / name
    with _file_lock(DOWNLOADS / ("." + name + ".lock")):
        if target.is_symlink() or (_exists(target) and not target.is_file()):
            raise ValueError("Refusing non-regular cache entry: " + str(target))
        if target.is_file() and digest(target) == expected:
            if "size" in spec and target.stat().st_size != spec["size"]:
                raise ValueError("Locked size disagrees with verified hash: " + name)
            return target
        fd, temporary = tempfile.mkstemp(
            prefix="." + name + ".", suffix=".part", dir=str(DOWNLOADS)
        )
        os.close(fd)
        temporary = Path(temporary)
        try:
            print("DOWNLOAD:", spec["url"], flush=True)
            _fetch(spec["url"], temporary)
            actual = digest(temporary)
            if actual != expected:
                raise ValueError(
                    "SHA-256 mismatch for {}: expected {}, got {}".format(
                        name, expected, actual
                    )
                )
            if "size" in spec and temporary.stat().st_size != spec["size"]:
                raise ValueError("Size mismatch for " + name)
            if target.exists():
                quarantine = DOWNLOADS / (name + ".corrupt-" + uuid.uuid4().hex)
                os.rename(target, quarantine)
                print("QUARANTINED:", quarantine, flush=True)
            os.replace(temporary, target)
            return target
        finally:
            if temporary.exists():
                temporary.unlink()


def _tar_parts(name):
    if not name or "\x00" in name or "\\" in name or name.startswith("/"):
        raise ValueError("Unsafe archive path: " + repr(name))
    parts = PurePosixPath(name).parts
    if not parts or ".." in parts or re.match(r"^[A-Za-z]:", parts[0]):
        raise ValueError("Unsafe archive path: " + repr(name))
    return parts


def _link_target(relative, link):
    if (
        not link
        or "\x00" in link
        or "\\" in link
        or link.startswith("/")
        or re.match(r"^[A-Za-z]:", link)
    ):
        raise ValueError("Unsafe symlink target: " + repr(link))
    target = posixpath.normpath(posixpath.join(posixpath.dirname(relative), link))
    if target == ".." or target.startswith("../"):
        raise ValueError("Symlink escapes extraction root: " + relative)
    return target


def extract(archive: Path, destination: Path):
    """Safely strip one tar root and atomically publish into an absent/empty dir.

    Validate all members first; never call tarfile.extract/extractall. Links may
    refer only inside the stripped tree, no member may traverse a link, and hard
    links must ultimately name a regular archive member. A nonempty destination
    is always an error (callers handle their own receipts/resume policy).
    """
    archive, destination = Path(archive), Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Resolve the caller-selected parent, but never follow destination itself.
    destination = destination.parent.resolve() / destination.name
    with _file_lock(destination.parent / ("." + destination.name + ".extract.lock")):
        if destination.is_symlink() or (
            _exists(destination)
            and (not destination.is_dir() or any(destination.iterdir()))
        ):
            raise FileExistsError(
                "Refusing nonempty or non-directory destination: " + str(destination)
            )
        with tarfile.open(archive, "r:*") as tar:
            members, root = {}, None
            for member in tar:
                parts = _tar_parts(member.name)
                if root is None:
                    root = parts[0]
                if parts[0] != root:
                    raise ValueError("Archive must have exactly one top-level root")
                if (
                    not (
                        member.isdir()
                        or member.isfile()
                        or member.issym()
                        or member.islnk()
                    )
                    or member.issparse()
                ):
                    raise ValueError("Unsupported archive member: " + member.name)
                relative = "/".join(parts[1:])
                if not relative:
                    if not member.isdir():
                        raise ValueError("Archive root must be a directory")
                    continue
                if relative in members:
                    raise ValueError("Duplicate archive member: " + relative)
                members[relative] = member
            if root is None:
                raise ValueError("Empty archive has no root")
            for name, member in members.items():
                for parent in PurePosixPath(name).parents:
                    other = members.get(str(parent))
                    if other is not None and not other.isdir():
                        raise ValueError(
                            "Archive member traverses a non-directory: " + name
                        )
                if member.issym():
                    _link_target(name, member.linkname)

            def hard_target(name, seen):
                if name in seen:
                    raise ValueError("Hardlink cycle: " + name)
                member = members.get(name)
                if member is None:
                    raise ValueError("Missing hardlink target: " + name)
                if member.isfile():
                    return name
                if not member.islnk():
                    raise ValueError("Hardlink target is not a regular file: " + name)
                parts = _tar_parts(member.linkname)
                if parts[0] != root or len(parts) < 2:
                    raise ValueError("Hardlink escapes archive root: " + name)
                return hard_target("/".join(parts[1:]), seen | {name})

            hardlinks = {
                n: hard_target(n, set()) for n, m in members.items() if m.islnk()
            }
            with tempfile.TemporaryDirectory(
                prefix="." + destination.name + ".extract-", dir=str(destination.parent)
            ) as temporary:
                stage = Path(temporary) / "root"
                stage.mkdir()
                for name, member in members.items():
                    path = stage / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    if member.isdir():
                        path.mkdir(exist_ok=True)
                    elif member.isfile():
                        with tar.extractfile(member) as source:
                            with path.open("xb") as output:
                                shutil.copyfileobj(source, output)
                        path.chmod(member.mode & 0o777)
                for name, target in hardlinks.items():
                    os.link(stage / target, stage / name)
                for name, member in members.items():
                    if member.issym():
                        os.symlink(member.linkname, stage / name)
                for name, member in members.items():
                    if member.issym():
                        try:
                            (stage / name).resolve().relative_to(stage.resolve())
                        except (ValueError, RuntimeError, OSError) as error:
                            raise ValueError(
                                "Unsafe or cyclic symlink: " + name
                            ) from error
                # POSIX rename replaces only an empty directory; nonempty trees
                # remain protected even if another process creates one now.
                os.rename(stage, destination)
    return destination


def _atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="." + path.name, dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _signature(path):
    if path.is_symlink():
        return {"symlink": os.readlink(path)}
    if not path.is_file():
        raise RuntimeError("Missing/non-regular bootstrap output: " + str(path))
    return {"sha256": digest(path), "mode": stat.S_IMODE(path.stat().st_mode)}


def _tree_files(root):
    return sorted(p for p in root.rglob("*") if p.is_file() or p.is_symlink())


def _managed(path):
    """Do not let local tools/build/prefix paths be redirected through symlinks."""
    relative = path.absolute().relative_to(ROOT)
    cursor = ROOT
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise RuntimeError("Refusing symlinked managed path: " + str(cursor))


def _step(name, key, workspace, expected, action):
    _filename(name)
    _managed(workspace)
    state_path = BUILD / "stamps" / (name + ".json")
    _managed(state_path)
    key = json.loads(json.dumps(key, sort_keys=True))
    if state_path.exists():
        state = json.loads(state_path.read_text())
        if state.get("key") != key:
            raise RuntimeError(
                "Obsolete bootstrap setup: {}. Move its managed workspace/outputs aside explicitly; no automatic deletion.".format(
                    state_path
                )
            )
        if state.get("status") == "complete":
            for file, signature in state["outputs"].items():
                if _signature(Path(file)) != signature:
                    raise RuntimeError("Bootstrap output changed: " + file)
            if not all(_exists(p) for p in expected):
                raise RuntimeError("Incomplete bootstrap outputs for " + name)
            print("CACHED:", name, flush=True)
            return
        if state.get("status") != "pending":
            raise RuntimeError("Invalid bootstrap state: " + str(state_path))
    else:
        if _exists(workspace) and (not workspace.is_dir() or any(workspace.iterdir())):
            raise RuntimeError(
                "Unowned nonempty bootstrap workspace: " + str(workspace)
            )
        if any(_exists(p) for p in expected):
            raise RuntimeError(
                "Unowned bootstrap output for " + name + "; refusing to overwrite"
            )
        _atomic_json(state_path, {"key": key, "status": "pending"})
    outputs = list(action())
    if not outputs or not all(_exists(p) for p in expected):
        raise RuntimeError("Bootstrap step did not produce required outputs: " + name)
    _atomic_json(
        state_path,
        {
            "key": key,
            "status": "complete",
            "outputs": {str(p): _signature(p) for p in outputs},
        },
    )


def _install_files(pairs):
    pairs = list(pairs)
    # Check every conflict before publishing anything. Identical files permit
    # recovery after interruption halfway through a previous staged install.
    for source, target in pairs:
        _managed(target.parent)
        if _exists(target) and _signature(target) != _signature(source):
            raise FileExistsError(
                "Refusing to replace prefix/tool file: " + str(target)
            )
        if source.is_symlink():
            _link_target(str(target.relative_to(ROOT)), os.readlink(source))
    for source, target in pairs:
        if _exists(target):
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            os.symlink(os.readlink(source), target)
        else:
            fd, name = tempfile.mkstemp(
                prefix=".bootstrap-install-", dir=str(target.parent)
            )
            os.close(fd)
            try:
                shutil.copy2(source, name)
                # Unlike replace(), link() cannot overwrite a concurrent file.
                os.link(name, target)
            finally:
                os.unlink(name)
    return [target for _, target in pairs]


def _publish_prefix(stage):
    if not stage.is_dir():
        raise RuntimeError("Missing staged install: " + str(stage))
    files = _tree_files(stage)
    if any(p.name.endswith(".dylib") for p in files):
        raise RuntimeError("Unexpected shared library in staged static dependency")
    return _install_files((p, PREFIX / p.relative_to(stage)) for p in files)


def _configure(command, work, marker, label):
    receipt = work / ".configure-complete.json"
    command = [str(a) for a in command]
    if receipt.exists():
        if json.loads(receipt.read_text()) != command or not (work / marker).is_file():
            raise RuntimeError("Obsolete/incomplete configure state: " + str(work))
        return
    if (work / marker).exists():
        raise RuntimeError(
            "Unconfirmed configure output; inspect before resuming: " + str(work)
        )
    support.run(command, work, label)
    if not (work / marker).is_file():
        raise RuntimeError("Configure did not generate " + marker)
    _atomic_json(receipt, command)


def _unpack(name, spec, archive, destination, recipe, expected):
    def action():
        extract(archive, destination)
        return _tree_files(destination)

    _step(
        "extract-" + name,
        {"recipe": recipe, "input": spec},
        destination,
        expected,
        action,
    )


def _native(name, source, flags, context, expected):
    work = BUILD / name

    def action():
        work.mkdir(parents=True, exist_ok=True)
        _configure(
            [source / "configure", "--prefix=" + str(PREFIX)] + flags,
            work,
            "Makefile",
            name + "-configure",
        )
        support.run(["/usr/bin/make", "-j" + support.JOBS], work, name + "-build")
        stage = work / "stage"
        support.run(
            ["/usr/bin/make", "install", "DESTDIR=" + str(stage)],
            work,
            name + "-install",
        )
        return _publish_prefix(stage / PREFIX.relative_to(PREFIX.anchor))

    _step(name, {"context": context, "flags": flags}, work, expected, action)


def _glib(source, context):
    work = BUILD / "glib"
    flags = [
        "--prefix=" + str(PREFIX),
        "--libdir=lib",
        "--buildtype=release",
        "--default-library=static",
        "--wrap-mode=nodownload",
        "-Dinternal_pcre=true",
        "-Dnls=disabled",
        "-Diconv=auto",
        "-Dgtk_doc=false",
        "-Dman=false",
        "-Dinstalled_tests=false",
        "-Dlibmount=disabled",
        "-Dselinux=disabled",
        "-Dxattr=false",
        "-Dfam=false",
        "-Ddtrace=false",
        "-Dsystemtap=false",
        "-Dsysprof=disabled",
        "-Doss_fuzz=disabled",
    ]
    names = {"libglib-2.0.a", "libgthread-2.0.a", "libintl.a"}

    def introspect(option):
        return json.loads(
            subprocess.check_output(
                [MESON, "introspect", option, str(work)],
                env=support.environment(),
                cwd=ROOT,
                text=True,
                timeout=90,
            )
        )

    def action():
        work.mkdir(parents=True, exist_ok=True)
        _configure(
            [MESON, "setup", work, source] + flags,
            work,
            "build.ninja",
            "glib-configure",
        )
        targets = introspect("--targets")
        archives = [
            Path(file)
            for target in targets
            for file in target["filename"]
            if Path(file).name in names
        ]
        if len(archives) != 3 or {p.name for p in archives} != names:
            raise RuntimeError("Unexpected GLib archive targets")
        support.run(
            [NINJA, "-C", work, "-j" + support.JOBS]
            + [p.relative_to(work) for p in archives],
            ROOT,
            "glib-build",
        )
        stage = work / "stage-prefix"
        (stage / "lib").mkdir(parents=True, exist_ok=True)
        for file in archives:
            shutil.copy2(file, stage / "lib" / file.name)
        headers, packages = 0, set()
        for src, dst in introspect("--installed").items():
            src, dst = Path(src), Path(dst)
            core_header = dst.suffix == ".h" and (
                str(dst).startswith(str(PREFIX / "include/glib-2.0/glib") + "/")
                or dst == PREFIX / "lib/glib-2.0/include/glibconfig.h"
                or dst
                in [
                    PREFIX / "include/glib-2.0/glib.h",
                    PREFIX / "include/glib-2.0/glib-unix.h",
                    PREFIX / "include/glib-2.0/gmodule.h",
                ]
            )
            package = dst.parent == PREFIX / "lib/pkgconfig" and dst.name in [
                "glib-2.0.pc",
                "gthread-2.0.pc",
            ]
            if core_header or package:
                if not src.is_file():
                    raise RuntimeError("Missing staged GLib input: " + str(src))
                target = stage / dst.relative_to(PREFIX)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, target)
                headers += int(core_header)
                if package:
                    packages.add(dst.name)
        if headers <= 50 or packages != {"glib-2.0.pc", "gthread-2.0.pc"}:
            raise RuntimeError("Incomplete minimal GLib install")
        outputs = _publish_prefix(stage)
        support.run(
            [PREFIX / "bin/pkgconf", "--static", "--libs", "glib-2.0", "gthread-2.0"],
            ROOT,
            "glib-static-link-flags",
        )
        return outputs

    _step(
        "glib",
        {"context": context, "flags": flags},
        work,
        [PREFIX / "lib" / name for name in sorted(names)],
        action,
    )


def load_lock():
    lock = json.loads(LOCKFILE.read_text())
    if lock.get("schema") != 1 or lock.get("platform") != "darwin/amd64":
        raise ValueError("Unsupported dependency lock format/platform")
    inputs = lock["inputs"]
    required = {
        "go",
        "llvm",
        "ninja",
        "pkgconf",
        "libffi",
        "zlib",
        "glib",
        "proxy-libintl",
        *WHEELS,
    }
    if set(inputs) != required:
        raise ValueError("Dependency lock has missing or unexpected inputs")
    names = [_spec(spec)[0] for spec in inputs.values()]
    if len(set(names)) != len(names):
        raise ValueError("Duplicate dependency cache filename")
    return inputs


def bootstrap(download_only=False):
    support.check_host()
    inputs = load_lock()
    archives = {name: download(spec) for name, spec in inputs.items()}
    if download_only:
        return
    _managed(BUILD)
    _managed(PREFIX)
    _managed(ROOT / "tools")
    with _file_lock(BUILD / ".bootstrap.lock"):
        recipe = {
            p.name: digest(p)
            for p in (Path(__file__).resolve(), ROOT / "build_support.py")
        }
        _unpack(
            "go",
            inputs["go"],
            archives["go"],
            GO.parent.parent,
            recipe,
            [GO, GO.parent / "gofmt"],
        )
        _unpack(
            "llvm",
            inputs["llvm"],
            archives["llvm"],
            LLVM.parent,
            recipe,
            [LLVM / "clang", LLVM / "clang++", LLVM / "llvm-ar"],
        )
        context = {"recipe": recipe, "inputs": inputs, "host": support.fingerprint()}

        def python_install():
            support.run(
                [sys.executable, "-m", "venv", PYTHON.parent.parent],
                ROOT,
                "python-venv",
            )
            support.run(
                [
                    PYTHON,
                    "-m",
                    "pip",
                    "install",
                    "--no-index",
                    "--no-deps",
                    "--no-compile",
                ]
                + [archives[name] for name in WHEELS],
                ROOT,
                "python-packages",
            )
            return _tree_files(PYTHON.parent.parent)

        _step(
            "python",
            context,
            PYTHON.parent.parent,
            [PYTHON, Path(MESON)],
            python_install,
        )
        sources = {}
        for name in ("ninja", "pkgconf", "libffi", "zlib", "glib"):
            destination = DEPENDENCY_SOURCES / (name + "-" + inputs[name]["version"])
            probe = (
                "configure.py"
                if name == "ninja"
                else "meson.build"
                if name == "glib"
                else "configure"
            )
            _unpack(
                name,
                inputs[name],
                archives[name],
                destination,
                recipe,
                [destination / probe],
            )
            sources[name] = destination
        proxy = sources["glib"] / "subprojects/proxy-libintl"
        _unpack(
            "proxy-libintl",
            inputs["proxy-libintl"],
            archives["proxy-libintl"],
            proxy,
            recipe,
            [proxy / "meson.build"],
        )

        def ninja_install():
            work = BUILD / "ninja"
            shutil.copytree(sources["ninja"], work, dirs_exist_ok=True)
            support.run(
                [
                    PYTHON,
                    work / "configure.py",
                    "--bootstrap",
                    "--verbose",
                    "--with-python=" + str(PYTHON),
                ],
                work,
                "ninja-bootstrap",
            )
            return _install_files([(work / "ninja", Path(NINJA))])

        _step("ninja", context, BUILD / "ninja", [Path(NINJA)], ninja_install)
        _native(
            "pkgconf",
            sources["pkgconf"],
            [
                "--disable-shared",
                "--enable-static",
                "--with-system-libdir=/usr/lib",
                "--with-system-includedir=/usr/include",
                "--with-pkg-config-dir=" + str(PREFIX / "lib/pkgconfig"),
            ],
            context,
            [PREFIX / "bin/pkgconf", PREFIX / "lib/libpkgconf.a"],
        )
        _native(
            "libffi",
            sources["libffi"],
            ["--disable-shared", "--enable-static", "--disable-docs"],
            context,
            [PREFIX / "lib/libffi.a"],
        )
        _native("zlib", sources["zlib"], ["--static"], context, [PREFIX / "lib/libz.a"])
        _glib(sources["glib"], context)
        if list(PREFIX.rglob("*.dylib")):
            raise RuntimeError("Unexpected shared library in dependency prefix")
        support.run([GO, "version"], ROOT, "bootstrap-go-version")
        support.run([LLVM / "clang", "--version"], ROOT, "bootstrap-clang-version")
        support.run([NINJA, "--version"], ROOT, "bootstrap-ninja-version")
        support.run([MESON, "--version"], ROOT, "bootstrap-meson-version")
        print("Native bootstrap complete:", PREFIX, flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--download-only",
        action="store_true",
        help="verify/download locked inputs without installing or building",
    )
    args = parser.parse_args(argv)
    try:
        bootstrap(download_only=args.download_only)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, "bootstrap: " + str(error) + "\n")


if __name__ == "__main__":
    main()
