#!/usr/bin/env python3
"""Read-only embedded-resource/archive comparison; not licensing clearance."""

import argparse
import bz2
import hashlib
import json
import sys
import tarfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent
RESOURCE_DIR = "src/qemu/util/builtin-resources/"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def verify_file(path, expected):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Missing or non-regular input: " + str(path))
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != expected:
        raise ValueError("Input checksum mismatch: " + str(path))


def resource_records(manifest, blob):
    if manifest.get("format") != 1 or not manifest.get("resources"):
        raise ValueError("Unsupported or empty resource manifest")
    names, intervals = set(), []
    for resource in manifest["resources"]:
        name = resource["name"]
        path = PurePosixPath(name)
        if (
            not name
            or name == "."
            or path.is_absolute()
            or ".." in path.parts
            or path.as_posix() != name
            or name in names
        ):
            raise ValueError("Unsafe or duplicate resource name: " + name)
        names.add(name)
        offset, size = resource["offset"], resource["size"]
        if (
            type(offset) is not int
            or type(size) is not int
            or offset < 0
            or size < 0
            or offset + size > len(blob)
        ):
            raise ValueError("Invalid resource bounds: " + name)
        if sha256(blob[offset : offset + size]) != resource["sha256"]:
            raise ValueError("Embedded resource checksum mismatch: " + name)
        intervals.append((offset, offset + size))
    intervals.sort()
    if any(left[1] > right[0] for left, right in zip(intervals, intervals[1:])):
        raise ValueError("Overlapping embedded resources")
    return sorted(manifest["resources"], key=lambda item: item["name"])


def compare_archive(manifest, blob, archive, spec):
    """Return deterministic byte evidence, rejecting altered/ambiguous inputs."""
    resources = resource_records(manifest, blob)
    verify_file(archive, spec["sha256"])
    matches, discrepancies = [], []
    with tarfile.open(archive, "r:*") as bundle:
        members = {}
        for member in bundle:
            if member.name in members:
                raise ValueError("Duplicate archive member: " + member.name)
            members[member.name] = member
        for resource in resources:
            name = resource["name"]
            # Match the notice aliases used by gen-builtin-resources.py.
            relative = {
                "firmware-COPYING": "COPYING",
                "firmware-COPYING.LIB": "COPYING.LIB",
                "firmware-notices.txt": "pc-bios/README",
            }.get(name, "pc-bios/" + name)
            base = spec["archive_root"] + "/" + relative
            candidates = [members[p] for p in (base, base + ".bz2") if p in members]
            evidence = {
                "name": name,
                "embedded_size": resource["size"],
                "embedded_sha256": resource["sha256"],
            }
            if not candidates:
                evidence["status"] = "missing_from_archive"
                discrepancies.append(evidence)
                continue
            if len(candidates) != 1 or not candidates[0].isfile():
                raise ValueError("Ambiguous or non-regular archive resource: " + name)
            member = candidates[0]
            with bundle.extractfile(member) as stream:
                data = stream.read()
            if member.name.endswith(".bz2"):
                data = bz2.decompress(data)
            checksum = sha256(data)
            if len(data) == resource["size"] and checksum == resource["sha256"]:
                matches.append(name)
            else:
                evidence.update(
                    status="differs_from_archive",
                    archive_member=member.name,
                    archive_size=len(data),
                    archive_sha256=checksum,
                )
                discrepancies.append(evidence)
    return {
        "format": 1,
        "scope": "Embedded resource byte identity against the locked QEMU archive only",
        "source_provenance_cleared": False,
        "redistribution_cleared": False,
        "archive": {
            key: spec[key] for key in ("filename", "revision", "sha256", "archive_root")
        },
        "blob_sha256": sha256(blob),
        "resource_count": len(resources),
        "matched_count": len(matches),
        "matches": matches,
        "discrepancies": discrepancies,
    }


def audit(root=ROOT, archive=None):
    spec = json.loads((root / "sources.lock.json").read_text())["sources"]["qemu"]
    overlays = json.loads((root / "source-overlays.json").read_text())["overlays"]
    inputs = {}
    for name in ("manifest.json", "builtin-data.bin"):
        relative = RESOURCE_DIR + name
        entries = [item for item in overlays if item["file"] == relative]
        if len(entries) != 1:
            raise ValueError("Expected exactly one locked resource input: " + relative)
        path = root / relative
        verify_file(path, entries[0]["sha256"])
        inputs[name] = path.read_bytes()
    report = compare_archive(
        json.loads(inputs["manifest.json"]),
        inputs["builtin-data.bin"],
        archive if archive is not None else root / "downloads" / spec["filename"],
        spec,
    )
    report["manifest_sha256"] = sha256(inputs["manifest.json"])
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--archive", type=Path, help="Existing locked QEMU archive (no download)"
    )
    args = parser.parse_args(argv)
    try:
        report = audit(archive=args.archive)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print("firmware audit: " + str(error), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 2 if report["discrepancies"] else 0


if __name__ == "__main__":
    sys.exit(main())
