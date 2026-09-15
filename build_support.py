"""Project-local Catalina build environment; importing this module does no work."""

import hashlib
import os
import platform
import re
import shlex
import signal
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BUILD = ROOT / "build/self-contained"
SOURCES = BUILD / "sources"
PREFIX = ROOT / "prefix"
LLVM = ROOT / "tools/clang+llvm-10.0.1-x86_64-apple-darwin/bin"
PYTHON = ROOT / "tools/python/bin/python"
MESON = str(ROOT / "tools/python/bin/meson")
NINJA = str(ROOT / "tools/bin/ninja")
GO = ROOT / "tools/go/bin/go"
JOBS = str(min(4, os.cpu_count() or 2))


def check_host():
    if sys.version_info < (3, 8):
        raise RuntimeError("Python >= 3.8 with venv and ensurepip is required")
    if platform.system() != "Darwin" or platform.machine().lower() not in {
        "x86_64",
        "amd64",
    }:
        raise RuntimeError("This toolchain requires an Intel (Darwin/amd64) macOS host")


def apple_tools():
    """Discover the selected SDK/tools, not a fixed Xcode installation."""
    check_host()

    def query(*args):
        return subprocess.check_output(
            ["/usr/bin/xcrun", *args], text=True, timeout=30
        ).strip()

    tools = {name: query("--find", name) for name in ("ar", "ranlib", "ld", "clang")}
    tools.update(sdk=query("--show-sdk-path"), sdk_version=query("--show-sdk-version"))
    if not Path(tools["sdk"]).is_dir() or not all(
        Path(tools[n]).is_file() for n in ("ar", "ranlib", "ld", "clang")
    ):
        raise RuntimeError(
            "xcrun did not resolve an installed macOS SDK and Apple toolchain"
        )
    return tools


def _environment(tools):
    env = os.environ.copy()
    for name in list(env):
        if name.startswith(("GO", "CGO_", "PIP_", "PYTHON", "DYLD_")) or name in {
            "CPATH",
            "C_INCLUDE_PATH",
            "CPLUS_INCLUDE_PATH",
            "OBJC_INCLUDE_PATH",
            "LIBRARY_PATH",
            "PKG_CONFIG_PATH",
            "PKG_CONFIG_SYSROOT_DIR",
            "PKG_CONFIG_SYSTEM_INCLUDE_PATH",
            "PKG_CONFIG_SYSTEM_LIBRARY_PATH",
            "CMAKE_PREFIX_PATH",
            "CONFIG_SITE",
            "MAKEFLAGS",
            "MFLAGS",
            "MAKE",
            "CC",
            "CXX",
            "OBJC",
            "AR",
            "RANLIB",
            "LD",
            "AS",
            "NM",
            "STRIP",
            "CFLAGS",
            "CXXFLAGS",
            "OBJCFLAGS",
            "CPPFLAGS",
            "LDFLAGS",
            "LIBS",
            "ARCHFLAGS",
            "CCC_OVERRIDE_OPTIONS",
            "CLANG_CONFIG_FILE_SYSTEM_DIR",
            "CLANG_CONFIG_FILE_USER_DIR",
            "SDKROOT",
            "MACOSX_DEPLOYMENT_TARGET",
        }:
            env.pop(name, None)
    sdk = shlex.quote(tools["sdk"])
    apple = str(Path(tools["ld"]).parent)
    flags = "-O2 -isysroot " + sdk + " -mmacosx-version-min=10.15"
    cache = ROOT / "cache"
    env.update(
        PATH=":".join(
            [
                str(LLVM),
                str(PYTHON.parent),
                str(ROOT / "tools/bin"),
                str(GO.parent),
                str(PREFIX / "bin"),
                apple,
                "/usr/bin",
                "/bin",
                "/usr/sbin",
                "/sbin",
            ]
        ),
        CC=str(LLVM / "clang"),
        CXX=str(LLVM / "clang++"),
        OBJC=str(LLVM / "clang"),
        AR=tools["ar"],
        RANLIB=tools["ranlib"],
        LD=tools["ld"],
        CFLAGS=flags,
        CXXFLAGS=flags,
        OBJCFLAGS=flags,
        CPPFLAGS="-I" + shlex.quote(str(PREFIX / "include")),
        LDFLAGS="-isysroot "
        + sdk
        + " -mmacosx-version-min=10.15 -B"
        + shlex.quote(apple)
        + " -L"
        + shlex.quote(str(PREFIX / "lib")),
        SDKROOT=tools["sdk"],
        MACOSX_DEPLOYMENT_TARGET="10.15",
        TMPDIR=str(ROOT / "tmp"),
        TMP=str(ROOT / "tmp"),
        TEMP=str(ROOT / "tmp"),
        XDG_CACHE_HOME=str(cache),
        PIP_CACHE_DIR=str(cache / "pip"),
        PIP_CONFIG_FILE=os.devnull,
        PIP_DISABLE_PIP_VERSION_CHECK="1",
        PYTHONNOUSERSITE="1",
        PYTHONPYCACHEPREFIX=str(cache / "python"),
        CONFIG_SITE=os.devnull,
        PKG_CONFIG=str(PREFIX / "bin/pkgconf"),
        PKG_CONFIG_LIBDIR=str(PREFIX / "lib/pkgconfig")
        + ":"
        + str(PREFIX / "share/pkgconfig"),
        NINJA=NINJA,
        GOROOT=str(GO.parent.parent),
        GOENV="off",
        GOTOOLCHAIN="local",
        GOOS="darwin",
        GOARCH="amd64",
        CGO_ENABLED="1",
        GOWORK="off",
        GOPROXY="off",
        GOSUMDB="sum.golang.org",
        GOPATH=str(cache / "gopath"),
        GOMODCACHE=str(cache / "modules"),
        GOCACHE=str(cache / "build"),
        GOTMPDIR=str(ROOT / "tmp"),
    )
    return env


def environment():
    """Return an isolated environment. Tools need not yet be installed."""
    return _environment(apple_tools())


def fingerprint():
    """Inputs which invalidate configured native builds when changed."""
    tools = apple_tools()
    env = _environment(tools)
    identities = {}
    for name in ("ar", "ranlib", "ld", "clang"):
        identities[name] = hashlib.sha256(Path(tools[name]).read_bytes()).hexdigest()
    settings = Path(tools["sdk"]) / "SDKSettings.plist"
    return {
        "tools": tools,
        "apple_sha256": identities,
        "sdk_settings_sha256": hashlib.sha256(settings.read_bytes()).hexdigest()
        if settings.is_file()
        else None,
        "python": {
            "executable": str(Path(sys.executable).resolve()),
            "version": sys.version,
        },
        "environment": {
            k: env[k]
            for k in (
                "PATH",
                "CC",
                "CXX",
                "OBJC",
                "AR",
                "RANLIB",
                "LD",
                "CFLAGS",
                "CXXFLAGS",
                "OBJCFLAGS",
                "CPPFLAGS",
                "LDFLAGS",
                "SDKROOT",
                "MACOSX_DEPLOYMENT_TARGET",
                "PKG_CONFIG",
                "PKG_CONFIG_LIBDIR",
                "NINJA",
                "GOROOT",
            )
        },
    }


def run(args, cwd, label, timeout=900):
    """Run a build command with local caches/logs; kill its process group on timeout."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", label) or label in {".", ".."}:
        raise ValueError("Invalid log label: " + str(label))
    args = [str(arg) for arg in args]
    env = environment()
    for path in (
        ROOT / "logs",
        ROOT / "tmp",
        ROOT / "cache/pip",
        ROOT / "cache/python",
        ROOT / "cache/gopath",
        ROOT / "cache/modules",
        ROOT / "cache/build",
    ):
        path.mkdir(parents=True, exist_ok=True)
    log = ROOT / "logs" / (label + ".log")
    print("RUN:", shlex.join(args), "\nLOG:", log, flush=True)
    with log.open("wb") as output:
        output.write(
            ("cwd: " + str(cwd) + "\ncommand: " + shlex.join(args) + "\n").encode()
        )
        output.flush()
        proc = subprocess.Popen(
            args,
            cwd=cwd,
            env=env,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            code = proc.wait(timeout=timeout)
        except BaseException:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
            print("Interrupted or timed out:", label, "; inspect", log, flush=True)
            raise
    if code:
        print("\n".join(log.read_text(errors="replace").splitlines()[-60:]), flush=True)
        raise subprocess.CalledProcessError(code, args)
    print("PASS:", label, flush=True)
