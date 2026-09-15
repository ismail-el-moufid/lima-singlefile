#!/usr/bin/env python3
"""Reconstruct locked sources without modifying the project's src trees.

Integration contract: bootstrap.download({url, sha256, filename}) -> Path and
bootstrap.extract(archive, destination) safely strip one archive root, publishing
atomically without overwriting destination. bootstrap is imported lazily; callers
can inject download/extract functions instead. No bootstrap work occurs on import.

The destination is an immutable, stamped source snapshot, except for the known
build-generated Lima native_link_flags.go and Python bytecode caches. Reuse checks
all other contents, symlinks and modes. Stale/edited destinations are never reset.
"""

import argparse
import hashlib
import importlib
import json
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
SOURCE_NAMES = ("lima", "qemu", "libslirp")
STAMP = ".source-stamp.json"
FORMAT = 1


class SourceError(RuntimeError):
    """An input or existing source snapshot cannot safely be used."""


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def relative_path(value):
    if not isinstance(value, str) or not value or "\\" in value or "\0" in value:
        raise SourceError("Invalid relative path: %r" % (value,))
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or ".." in path.parts
        or value != path.as_posix()
        or value == "."
    ):
        raise SourceError("Invalid relative path: %r" % value)
    return path


def safe_path(root, value):
    path = Path(root)
    for component in relative_path(value).parts:
        path = path / component
        if path.is_symlink():
            raise SourceError("Refusing symlink in input/output path: %s" % path)
    return path


def valid_hash(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise SourceError("Invalid SHA-256: %r" % (value,))


def generated_path(value):
    path = PurePosixPath(value)
    return (
        value == "lima/cmd/limactl/native_link_flags.go"
        or "__pycache__" in path.parts
        or path.suffix in (".pyc", ".pyo")
    )


def read_json(path):
    try:
        data = Path(path).read_bytes()
        result = json.loads(data)
    except (OSError, ValueError) as exc:
        raise SourceError("Cannot read %s: %s" % (path, exc)) from exc
    if not isinstance(result, dict) or result.get("format") != FORMAT:
        raise SourceError("Unsupported metadata format in %s" % path)
    return result, hashlib.sha256(data).hexdigest()


def load_lock(root):
    lock, digest = read_json(safe_path(root, "sources.lock.json"))
    sources = lock.get("sources")
    if not isinstance(sources, dict) or not set(SOURCE_NAMES).issubset(sources):
        raise SourceError("Source lock must include lima, qemu and libslirp")
    destinations, filenames = set(), set()
    for name, spec in sources.items():
        if len(relative_path(name).parts) != 1 or not isinstance(spec, dict):
            raise SourceError("Invalid source specification: %s" % name)
        destination = str(relative_path(spec.get("destination")))
        filename = str(relative_path(spec.get("filename")))
        archive_root = relative_path(spec.get("archive_root"))
        if len(PurePosixPath(filename).parts) != 1 or len(archive_root.parts) != 1:
            raise SourceError("Archive filename/root must be a basename: %s" % name)
        if name in SOURCE_NAMES:
            if destination != name:
                raise SourceError("Unexpected destination for %s" % name)
        elif (
            not destination.startswith("qemu/subprojects/")
            or len(PurePosixPath(destination).parts) != 3
        ):
            raise SourceError("Unexpected subproject destination: %s" % destination)
        if destination in destinations or filename in filenames:
            raise SourceError("Duplicate archive destination or filename: %s" % name)
        destinations.add(destination)
        filenames.add(filename)
        valid_hash(spec.get("sha256"))
        url = urlsplit(spec.get("url", ""))
        if url.scheme != "https" or not url.netloc or url.username or url.password:
            raise SourceError(
                "Source URL must use HTTPS without credentials: %s" % name
            )
        if not re.fullmatch(r"[0-9a-f]{40}", spec.get("revision", "")):
            raise SourceError("Source revision must be a full commit: %s" % name)
    copies = lock.get("copies", [])
    if not isinstance(copies, list):
        raise SourceError("Source lock copies must be a list")
    targets = set()
    for recipe in copies:
        if not isinstance(recipe, dict):
            raise SourceError("Invalid source copy recipe")
        source = str(relative_path(recipe.get("from")))
        target = str(relative_path(recipe.get("to")))
        if not source.startswith("qemu/subprojects/packagefiles/"):
            raise SourceError("Copy recipe must use QEMU packagefiles: %s" % source)
        if not any(
            target.startswith(d + "/")
            for d in destinations
            if d.startswith("qemu/subprojects/")
        ):
            raise SourceError(
                "Copy recipe must target a locked subproject: %s" % target
            )
        if target in targets:
            raise SourceError("Duplicate copy recipe: %s" % target)
        targets.add(target)
        valid_hash(recipe.get("sha256"))
    return lock, digest


def load_overlays(root, lock):
    manifest, digest = read_json(safe_path(root, "source-overlays.json"))
    overlays = manifest.get("overlays")
    if not isinstance(overlays, list):
        raise SourceError("Overlay manifest must contain an explicit overlays list")
    targets = set()
    subprojects = [
        s["destination"] for n, s in lock["sources"].items() if n not in SOURCE_NAMES
    ]
    for entry in overlays:
        if not isinstance(entry, dict) or entry.get("source") not in ("lima", "qemu"):
            raise SourceError("Invalid overlay source")
        source = entry["source"]
        path = str(relative_path(entry.get("path")))
        target = source + "/" + path
        if entry.get("file") != "src/" + target:
            raise SourceError(
                "Overlay must refer to its explicit src file: %s" % target
            )
        if (
            target in targets
            or generated_path(target)
            or any(target.startswith(p + "/") for p in subprojects)
        ):
            raise SourceError("Duplicate or excluded overlay: %s" % target)
        targets.add(target)
        valid_hash(entry.get("sha256"))
        preimage = entry.get("upstream_sha256")
        if "upstream_sha256" not in entry:
            raise SourceError("Missing overlay preimage declaration: %s" % target)
        if preimage is not None:
            valid_hash(preimage)
        for field in ("mode", "upstream_mode"):
            mode = entry.get(field)
            if field == "upstream_mode" and preimage is None and mode is None:
                continue
            if type(mode) is not int or not 0 <= mode <= 0o777:
                raise SourceError("Invalid %s for %s" % (field, target))
        verify_file(safe_path(root, entry["file"]), entry["sha256"], "overlay")
    return manifest, digest


def verify_file(path, expected, label):
    if not path.is_file() or path.is_symlink():
        raise SourceError("Missing/non-regular %s file: %s" % (label, path))
    actual = sha256(path)
    if actual != expected:
        raise SourceError(
            "%s hash mismatch: %s (expected %s, got %s)"
            % (label, path, expected, actual)
        )


def apply_overlays(root, stage, manifest):
    """Apply only listed, verified files to a disposable staging tree."""
    for entry in manifest["overlays"]:
        source = safe_path(root, entry["file"])
        target = safe_path(stage, entry["source"] + "/" + entry["path"])
        preimage = entry["upstream_sha256"]
        if preimage is None:
            if os.path.lexists(target):
                raise SourceError(
                    "Added overlay collides with upstream path: %s" % target
                )
        else:
            verify_file(target, preimage, "upstream preimage")
            if (
                stat.S_IMODE(target.stat().st_mode) & 0o111
                != entry["upstream_mode"] & 0o111
            ):
                raise SourceError("Upstream executable mode mismatch: %s" % target)
        # Hash the bytes actually written, not an earlier read before downloads.
        contents = source.read_bytes()
        if hashlib.sha256(contents).hexdigest() != entry["sha256"]:
            raise SourceError("overlay hash mismatch: %s" % source)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(contents)
        target.chmod(entry["mode"])


def populate_copies(stage, lock):
    for recipe in lock.get("copies", []):
        source = safe_path(stage, recipe["from"])
        target = safe_path(stage, recipe["to"])
        verify_file(source, recipe["sha256"], "Meson overlay")
        if os.path.lexists(target):
            raise SourceError(
                "Meson overlay collides with extracted source: %s" % target
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(stat.S_IMODE(source.stat().st_mode))


def snapshot(directory):
    """Content/mode inventory; never follow source-tree symlinks."""
    directory = Path(directory)
    entries = {}
    for parent, dirs, files in os.walk(directory, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(parent) / name
            relative = path.relative_to(directory).as_posix()
            if relative == STAMP or generated_path(relative):
                if name in dirs:
                    dirs.remove(name)
                continue
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                resolved = path.resolve()
                if directory not in resolved.parents:
                    raise SourceError("Source symlink escapes snapshot: %s" % path)
                entry = {"type": "symlink", "target": os.readlink(path)}
            elif stat.S_ISDIR(info.st_mode):
                entry = {"type": "directory", "mode": stat.S_IMODE(info.st_mode)}
            elif stat.S_ISREG(info.st_mode):
                entry = {
                    "type": "file",
                    "mode": stat.S_IMODE(info.st_mode),
                    "sha256": sha256(path),
                }
            else:
                raise SourceError("Unsupported source file type: %s" % path)
            entries[relative] = entry
    return entries


def verify_existing(destination, inputs):
    if destination.is_symlink() or not destination.is_dir():
        raise SourceError(
            "Existing destination is not a source directory: %s" % destination
        )
    stamp_path = safe_path(destination, STAMP)
    if not stamp_path.is_file():
        raise SourceError(
            "Existing sources have no preparation stamp; refusing overwrite: %s"
            % destination
        )
    stamp, _ = read_json(stamp_path)
    if stamp.get("inputs") != inputs:
        raise SourceError(
            "Existing sources have stale inputs; preserve them and choose a new --sources-dir: %s"
            % destination
        )
    expected = stamp.get("tree")
    if not isinstance(expected, dict):
        raise SourceError("Invalid source content stamp: %s" % stamp_path)
    actual = snapshot(destination)
    if actual != expected:
        changed = sorted(
            p for p in set(actual) | set(expected) if actual.get(p) != expected.get(p)
        )
        raise SourceError(
            "Existing source drift; refusing overwrite (%d paths): %s"
            % (len(changed), ", ".join(changed[:8]))
        )


def bootstrap_api(name):
    try:
        module = importlib.import_module("bootstrap")
        function = getattr(module, name)
    except (ImportError, AttributeError) as exc:
        raise SourceError(
            "Source preparation requires bootstrap.%s; provide bootstrap.py or inject %s"
            % (name, name)
        ) from exc
    if not callable(function):
        raise SourceError("bootstrap.%s is not callable" % name)
    return function


def download_archives(lock, download=None):
    download = download if download is not None else bootstrap_api("download")
    archives = {}
    for name, spec in sorted(lock["sources"].items()):
        request = {key: spec[key] for key in ("url", "sha256", "filename")}
        archive = Path(download(request))
        verify_file(archive, spec["sha256"], "archive")
        archives[name] = archive
    return archives


def prepare_sources(
    root=ROOT, destination=None, *, download_only=False, download=None, extract=None
):
    """Return {lima, qemu, libslirp: Path}, or all archive paths for download_only.

    A valid existing snapshot needs no bootstrap import or network access. A
    preparation lock serializes cooperating callers; stale locks require explicit
    operator inspection, never automatic deletion or a destructive retry.
    """
    root = Path(root).resolve()
    lock, lock_hash = load_lock(root)
    if download_only:
        return download_archives(lock, download)
    manifest, overlay_hash = load_overlays(root, lock)
    inputs = {
        "sources.lock.json": lock_hash,
        "source-overlays.json": overlay_hash,
        "prepare_sources.py": sha256(Path(__file__)),
    }
    destination = (
        Path(destination)
        if destination is not None
        else Path("build/self-contained/sources")
    )
    if not destination.is_absolute():
        destination = root / destination
    destination = destination.parent.resolve() / destination.name
    resolved = destination.resolve()
    if (
        resolved == root
        or resolved in root.parents
        or resolved == root / "src"
        or root / "src" in resolved.parents
    ):
        raise SourceError(
            "Source destination must not overlap the project's original sources: %s"
            % destination
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    lock_path = destination.parent / ("." + destination.name + ".prepare.lock")
    try:
        descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise SourceError(
            "Preparation lock exists; inspect before removing a stale lock: %s"
            % lock_path
        ) from exc
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(json.dumps({"pid": os.getpid()}) + "\n")
        if os.path.lexists(destination):
            verify_existing(destination, inputs)
            return {name: destination / name for name in SOURCE_NAMES}
        archives = download_archives(lock, download)
        extract = extract if extract is not None else bootstrap_api("extract")
        with tempfile.TemporaryDirectory(
            prefix="." + destination.name + ".stage-", dir=destination.parent
        ) as temporary:
            stage = Path(temporary)
            ordered = sorted(
                lock["sources"].items(),
                key=lambda item: (
                    len(PurePosixPath(item[1]["destination"]).parts),
                    item[0],
                ),
            )
            for name, spec in ordered:
                target = safe_path(stage, spec["destination"])
                # A pristine archive may represent an unpopulated subproject as
                # an empty directory. Only remove that disposable staging stub.
                if target.is_dir() and not any(target.iterdir()):
                    target.rmdir()
                if os.path.lexists(target):
                    raise SourceError(
                        "Archive destination already populated: %s" % target
                    )
                target.parent.mkdir(parents=True, exist_ok=True)
                extract(archives[name], target)
                if target.is_symlink() or not target.is_dir():
                    raise SourceError(
                        "Extractor did not create a source directory: %s" % target
                    )
            populate_copies(stage, lock)
            apply_overlays(root, stage, manifest)
            stamp = {"format": FORMAT, "inputs": inputs, "tree": snapshot(stage)}
            (stage / STAMP).write_text(
                json.dumps(stamp, sort_keys=True, indent=2) + "\n"
            )
            if os.path.lexists(destination):
                raise SourceError(
                    "Destination appeared during preparation; refusing overwrite: %s"
                    % destination
                )
            stage.rename(destination)
        return {name: destination / name for name in SOURCE_NAMES}
    finally:
        lock_path.unlink()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--download-only",
        action="store_true",
        help="cache all six locked source archives without extracting",
    )
    parser.add_argument(
        "--sources-dir",
        help="destination (default: build/self-contained/sources); existing drift is never overwritten",
    )
    args = parser.parse_args(argv)
    try:
        result = prepare_sources(
            destination=args.sources_dir, download_only=args.download_only
        )
    except (SourceError, OSError, ValueError) as exc:
        parser.exit(1, "prepare_sources: %s\n" % exc)
    print(
        json.dumps(
            {name: str(path) for name, path in result.items()}, indent=2, sort_keys=True
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
