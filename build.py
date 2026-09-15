#!/usr/bin/env python3
"""Download pinned inputs and build the single-file executable in this repository."""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import bootstrap
import build_support as support
from prepare_sources import prepare_sources


def modules(offline=False):
    source = support.SOURCES / "lima"
    tracked = {name: (source / name).read_bytes() for name in ("go.mod", "go.sum")}
    env = support.environment()
    env.update(
        GOPROXY="off" if offline else "https://proxy.golang.org",
        GOSUMDB="off" if offline else "sum.golang.org",
    )
    for name in ("cache/modules", "cache/gopath", "cache/build", "tmp", "logs"):
        (support.ROOT / name).mkdir(parents=True, exist_ok=True)
    log = support.ROOT / "logs/go-modules.log"
    print(
        "Go modules:",
        "offline verification" if offline else "download and verification",
        "LOG:",
        log,
        flush=True,
    )
    try:
        with log.open("wb") as stream:
            for args in (["mod", "download"], ["mod", "verify"]):
                subprocess.run(
                    [str(support.GO)] + args,
                    cwd=source,
                    env=env,
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                    check=True,
                    timeout=900,
                )
    except subprocess.CalledProcessError:
        print(log.read_text(errors="replace"), flush=True)
        raise
    finally:
        if any(
            (source / name).read_bytes() != value for name, value in tracked.items()
        ):
            raise RuntimeError(
                "Go changed go.mod/go.sum; refusing a build with unreviewed module changes: "
                + str(source)
            )


def _reject_offline_download(_spec):
    raise RuntimeError(
        "Source download forbidden in --offline mode; run an online preparation again"
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    phase = parser.add_mutually_exclusive_group()
    phase.add_argument(
        "--prepare-only",
        action="store_true",
        help="download/install all tools, sources, native dependencies and Go modules without compiling QEMU/Lima",
    )
    phase.add_argument(
        "--offline",
        action="store_true",
        help="reuse a successful preparation; never download inputs",
    )
    parser.add_argument(
        "--with-test-image",
        action="store_true",
        help="also download/verify the pinned Alpine boot-test ISO",
    )
    args = parser.parse_args(argv)
    support.check_host()
    if args.offline and args.with_test_image:
        parser.error(
            "--with-test-image is an online preparation option, not an offline build option"
        )
    support.BUILD.mkdir(parents=True, exist_ok=True)
    marker = support.BUILD / "prepared.json"
    # Serialize all mutation of the shared prefix, sources, generated flags and output.
    with bootstrap._file_lock(support.BUILD / ".build.lock"):
        if args.offline:
            if not marker.is_file():
                raise RuntimeError(
                    "Run python3 build.py --prepare-only online before using --offline"
                )
            previous = json.loads(marker.read_text())
            current = preparation_identity()
            if previous != current:
                raise RuntimeError(
                    "Preparation inputs or host changed; run an online preparation again"
                )
            # An offline request must not fall through to prepare_sources' downloader.
            if not (support.SOURCES / ".source-stamp.json").is_file():
                raise RuntimeError(
                    "Prepared sources are missing; run an online preparation again"
                )
        else:
            bootstrap.bootstrap()
        prepare_sources(download=_reject_offline_download if args.offline else None)
        modules(offline=args.offline)
        if args.with_test_image:
            from fetch_test_image import fetch_test_image

            fetch_test_image()
        if not args.offline:
            bootstrap._atomic_json(marker, preparation_identity())
        if args.prepare_only:
            print(
                "Preparation complete. Build without downloads: python3 build.py --offline",
                flush=True,
            )
            return 0
        # Native/link runners bound their own commands and clean up child groups.
        # An outer timeout would kill the wrapper before it can perform that cleanup.
        for step in ("slirp", "configure", "build"):
            subprocess.run(
                [sys.executable, str(support.ROOT / "build_native.py"), step],
                cwd=support.ROOT,
                check=True,
            )
        subprocess.run(
            [sys.executable, str(support.ROOT / "link_lima.py")],
            cwd=support.ROOT,
            check=True,
        )
    return 0


def preparation_identity():
    names = (
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
    return {
        "files": {
            name: hashlib.sha256((support.ROOT / name).read_bytes()).hexdigest()
            for name in names
        },
        "host": support.fingerprint(),
    }


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        sys.exit("build: " + str(error))
