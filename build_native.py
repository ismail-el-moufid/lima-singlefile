import argparse
import json
import os
import shlex
import subprocess
import time
from pathlib import Path

import build_support as support

ROOT, PREFIX = support.ROOT, support.PREFIX
ENV = support.environment()
ENV.update(
    PKG_CONFIG=shlex.quote(str(PREFIX / "bin/pkgconf")) + " --static", GOSUMDB="off"
)
NINJA, MESON = support.NINJA, support.MESON


def run(args, cwd, label, timeout=900):
    args = [str(a) for a in args]
    (ROOT / "logs").mkdir(parents=True, exist_ok=True)
    (ROOT / "tmp").mkdir(parents=True, exist_ok=True)
    log = ROOT / "logs" / (label + ".log")
    print("RUN:", label, "LOG:", log, flush=True)
    with log.open("wb") as out:
        out.write(
            ("cwd: " + str(cwd) + "\ncommand: " + shlex.join(args) + "\n").encode()
        )
        out.flush()
        proc = subprocess.Popen(
            args,
            cwd=cwd,
            env=ENV,
            stdout=out,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        started = time.monotonic()
        try:
            while True:
                try:
                    code = proc.wait(timeout=20)
                    break
                except subprocess.TimeoutExpired:
                    lines = log.read_text(errors="replace").splitlines()
                    print(
                        label
                        + ": "
                        + str(int(time.monotonic() - started))
                        + "s; "
                        + (lines[-1][:220] if lines else "running"),
                        flush=True,
                    )
                    if time.monotonic() - started >= timeout:
                        raise TimeoutError(
                            label + " exceeded " + str(timeout) + " seconds"
                        )
        except BaseException:
            import signal

            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            raise
    if code:
        print(
            "\n".join(
                l[:600] for l in log.read_text(errors="replace").splitlines()[-45:]
            ),
            flush=True,
        )
        raise RuntimeError(label + " failed with status " + str(code))
    print("PASS:", label, flush=True)


def slirp():
    build = support.BUILD / "libslirp"
    source = support.SOURCES / "libslirp"
    build.mkdir(parents=True, exist_ok=True)
    if not (build / "build.ninja").exists():
        run(
            [
                MESON,
                "setup",
                build,
                source,
                "--prefix=" + str(PREFIX),
                "--libdir=lib",
                "--default-library=static",
                "--buildtype=release",
                "--wrap-mode=nodownload",
            ],
            ROOT,
            "slirp-configure",
        )
    run([NINJA, "-C", build, "-j4", "install"], ROOT, "slirp-build")
    assert (PREFIX / "lib/libslirp.a").is_file()
    assert not list(PREFIX.rglob("*.dylib")), "Unexpected shared dependency"


def configure():
    source = support.SOURCES / "qemu"
    build = support.BUILD / "qemu"
    build.mkdir(parents=True, exist_ok=True)
    flags = [
        "--prefix=" + str(PREFIX),
        "--target-list=x86_64-softmmu",
        "--cc=" + ENV["CC"],
        "--cxx=" + ENV["CXX"],
        "--objcc=" + ENV["OBJC"],
        "--python=" + str(support.PYTHON),
        "--ninja=" + NINJA,
        "--without-default-features",
        "--enable-tcg",
        "--enable-hvf",
        "--disable-vmnet",
        "--disable-pvg",
        "--disable-fdt",
        "--disable-pixman",
        "--enable-slirp",
        "--enable-virtfs",
        "--enable-tools",
        "--disable-guest-agent",
        "--disable-docs",
        "--disable-modules",
        "--disable-plugins",
        "--disable-shared-lib",
        "--disable-rust",
        "--disable-cfi",
        "--audio-drv-list=",
        "--enable-trace-backends=nop",
        "--disable-download",
    ]
    run([source / "configure"] + flags, build, "qemu-configure")


def build():
    run(
        [
            NINJA,
            "-C",
            support.BUILD / "qemu",
            "-j4",
            "qemu-system-x86_64-unsigned",
            "qemu-img",
        ],
        ROOT,
        "qemu-build",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("step", choices=["slirp", "configure", "build"])
    globals()[parser.parse_args().step]()
