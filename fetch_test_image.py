#!/usr/bin/env python3
"""Fetch the optional, checksum-locked Alpine image used by the boot validator.

Run python3 fetch_test_image.py from the repository root. bootstrap.download owns
atomic/cache-safe downloading into the repository downloads directory. Importing
this module performs no downloads; tests can inject a downloader and fixture lock.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
LOCKFILE = ROOT / "tests/fixtures.lock.json"
FIXTURE = "alpine-x86_64"


def load_fixture(lock_path=None):
    path = Path(lock_path) if lock_path is not None else LOCKFILE
    try:
        lock = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise ValueError("Cannot read test fixture lock %s: %s" % (path, exc)) from exc
    if not isinstance(lock, dict) or lock.get("format") != 1:
        raise ValueError("Unsupported test fixture lock format: " + str(path))
    fixtures = lock.get("fixtures")
    spec = fixtures.get(FIXTURE) if isinstance(fixtures, dict) else None
    if not isinstance(spec, dict):
        raise ValueError("Fixture lock must define " + FIXTURE)
    filename = spec.get("filename")
    if (
        not isinstance(filename, str)
        or not filename
        or filename in (".", "..")
        or any(character in filename for character in "/\\\0")
    ):
        raise ValueError("Fixture filename must be a plain basename")
    for field, length in (("sha256", 64), ("sha512", 128)):
        value = spec.get(field)
        if not isinstance(value, str) or not re.fullmatch(
            r"[0-9a-f]{%d}" % length, value
        ):
            raise ValueError("Invalid fixture " + field)
    if type(spec.get("size")) is not int or spec["size"] <= 0:
        raise ValueError("Invalid fixture size")
    value = spec.get("url")
    if not isinstance(value, str):
        raise ValueError("Invalid fixture URL")
    url = urlsplit(value)
    if url.scheme != "https" or not url.hostname or url.username or url.password:
        raise ValueError("Fixture URL must use HTTPS without credentials")
    return {
        field: spec[field] for field in ("url", "sha256", "sha512", "filename", "size")
    }


def verify_image(path, spec):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("Missing/non-regular test image: " + str(path))
    hashes = {"sha256": hashlib.sha256(), "sha512": hashlib.sha512()}
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            for digest in hashes.values():
                digest.update(chunk)
    if size != spec["size"]:
        raise ValueError(
            "Test image size mismatch: expected %d, got %d" % (spec["size"], size)
        )
    for field, digest in hashes.items():
        actual = digest.hexdigest()
        if actual != spec[field]:
            raise ValueError(
                "Test image %s mismatch: expected %s, got %s"
                % (field, spec[field], actual)
            )
    return path


def fetch_test_image(*, download=None, lock_path=None):
    spec = load_fixture(lock_path)
    if download is None:
        try:
            from bootstrap import download
        except ImportError as exc:
            raise RuntimeError(
                "Test image fetching requires bootstrap.download"
            ) from exc
    request = {field: spec[field] for field in ("url", "sha256", "filename", "size")}
    return verify_image(download(request), spec)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    try:
        path = fetch_test_image()
    except (OSError, ValueError, RuntimeError) as exc:
        parser.exit(1, "fetch_test_image: %s\n" % exc)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
