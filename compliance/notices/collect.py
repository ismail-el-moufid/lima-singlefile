#!/usr/bin/env python3
"""Collect authentic notices, or verify the packaged inventory (Python >= 3.8).

No extraction to source trees, no builds, no implicit network access. Only
--fetch-historical downloads anything, using curl with TLS verification.
"""

import argparse
import base64
import hashlib
import json
import re
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
BUNDLE = Path(__file__).resolve().parent
HOST = "output/limactl"
GUEST = "src/lima/pkg/embeddedassets/lima-guestagent.Linux-x86_64"
GO_SUM = "src/lima/go.sum"
GUEST_MANIFEST = "compliance/guest-agent/manifest.json"
NOTICE_NAME = re.compile(
    r"^(?:licen[sc]es?|copying|copyright|notices?|patents|authors)"
    r"(?:[._-].*)?$|^.*[-_]licenses?\.txt$",
    re.I,
)
SOURCE_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".go", ".s", ".S", ".inc"}
MARKER = re.compile(
    rb"copyright|SPDX-License-Identifier|permission is hereby|public domain", re.I
)
EXCLUDED_PARTS = {"tests", "test", "testdata", "examples", "fuzz", "fuzzing"}
HEADER_PREFIXES = {
    "glib": ("glib/", "gmodule/", "gthread/", "gobject/"),
    "proxy-libintl": ("",),
    "libslirp": ("src/",),
    "zlib": ("",),
    "libffi": ("src/", "include/"),
    "qemu": ("util/", "include/qemu/", "fpu/", "net/", "pc-bios/optionrom/"),
    "keycodemapdb": (),
    "berkeley-softfloat-3": ("source/",),
}
SCOPE = {
    "host_module_count": 48,
    "host_module_named_notice_inventory": "complete for the explicit filename rule in the 48 verified ZIPs",
    "host_runtime": "go1.22.12",
    "guest_runtime": "go1.19.2 (official historical source archive, not host substitution)",
    "guest_module_bundle": "unchanged; see compliance/guest-agent/manifest.json",
    "native_named_notice_inventory": "complete for the explicit filename rule in the selected locked archives",
    "file_level_inventory_complete": False,
    "firmware_notice_inventory_complete": False,
    "source_delivery_complete": False,
    "relinking_materials_complete": False,
    "redistribution_cleared": False,
    "applicability": "Conservative candidate notices; archive membership is not proof that each file is linked. Header selection is partial, not a legal applicability determination.",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key: " + key)
        result[key] = value
    return result


def load_json(path):
    return json.loads(path.read_bytes(), object_pairs_hook=unique_object)


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def file_hash(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def safe_name(value):
    p = PurePosixPath(value)
    require(
        bool(value)
        and not p.is_absolute()
        and p.as_posix() == value
        and not any(x in {".", "..", ".git"} for x in p.parts)
        and not any(c in value for c in "\\\n\r\x00"),
        "Unsafe path: " + repr(value),
    )
    return value


def safe_path(base, name):
    safe_name(name)
    require(not base.is_symlink(), "Symlink base: " + str(base))
    path = base
    for part in PurePosixPath(name).parts:
        path = path / part
        require(not path.is_symlink(), "Symlink path: " + str(path))
    require(base.resolve() in path.resolve().parents, "Path escapes base: " + name)
    return path


def escape_module(value):
    return "".join("!" + c.lower() if "A" <= c <= "Z" else c for c in value)


def zip_h1(archive):
    """Go dirhash.HashZip/Hash1; do not trust the adjacent .ziphash file."""
    names = [m.filename for m in archive.infolist()]
    require(len(names) == len(set(names)), "Duplicate ZIP member")
    h = hashlib.sha256()
    for name in sorted(names):
        safe_name(name.rstrip("/"))
        mode = archive.getinfo(name).external_attr >> 16
        require(not stat.S_ISLNK(mode), "Symlink ZIP member: " + name)
        h.update((sha256(archive.read(name)) + "  " + name + "\n").encode())
    return "h1:" + base64.b64encode(h.digest()).decode()


def parse_build(text):
    lines = text.splitlines()
    require(bool(lines) and ": go" in lines[0], "Missing Go build metadata")
    result = {"go_version": lines[0].rsplit(": ", 1)[1], "modules": [], "settings": {}}
    for line in lines[1:]:
        fields = line.strip().split("\t")
        if fields[0] == "=>":
            raise ValueError("Module replacements require explicit review")
        if fields[0] == "dep":
            require(
                len(fields) == 4 and fields[3].startswith("h1:"),
                "Invalid dependency metadata",
            )
            result["modules"].append(
                dict(zip(("path", "version", "zip_h1"), fields[1:]))
            )
        elif fields[0] == "path":
            result["package"] = fields[1]
        elif fields[0] == "build":
            key, value = fields[1].split("=", 1)
            result["settings"][key] = value
    ids = [m["path"] for m in result["modules"]]
    require(len(ids) == len(set(ids)), "Duplicate module metadata")
    return result


def leading_notice(data):
    """Return an exact leading C/Go comment region; never synthesize license text."""
    pos = 3 if data.startswith(b"\xef\xbb\xbf") else 0
    end = pos
    while pos < len(data):
        while pos < len(data) and data[pos : pos + 1] in (b" ", b"\t", b"\r", b"\n"):
            pos += 1
        if data[pos : pos + 2] == b"/*":
            close = data.find(b"*/", pos + 2)
            if close < 0:
                break
            pos = close + 2
        elif data[pos : pos + 2] == b"//":
            close = data.find(b"\n", pos)
            pos = len(data) if close < 0 else close + 1
        else:
            break
        end = pos
    return (0, end) if end and MARKER.search(data[:end]) else None


def is_named_notice(relative):
    name = PurePosixPath(relative).name
    return bool(NOTICE_NAME.fullmatch(name)) and not name.lower().endswith(
        (".c", ".h", ".go", ".sh", ".py")
    )


def header_candidate(component, relative):
    path = PurePosixPath(relative)
    if (
        path.suffix not in SOURCE_SUFFIXES
        or EXCLUDED_PARTS.intersection(path.parts)
        or path.name.endswith("_test.go")
    ):
        return False
    if component.startswith("go-"):
        return relative.startswith("src/") and not relative.startswith("src/cmd/")
    if component == "zlib":
        return len(path.parts) == 1
    return relative.startswith(HEADER_PREFIXES.get(component, ()))


def add_notice(component, files, member, relative, data, kind, byte_range=None):
    name = "headers/" + relative + ".txt" if byte_range else "files/" + relative
    output = "texts/" + component["id"] + "/" + safe_name(name)
    require(output not in files, "Duplicate notice output: " + output)
    payload = data if byte_range is None else data[byte_range[0] : byte_range[1]]
    require(bool(payload), "Empty notice: " + member)
    record = {
        "path": output,
        "source_path": member,
        "kind": kind,
        "size": len(payload),
        "sha256": sha256(payload),
        "source_size": len(data),
        "source_sha256": sha256(data),
    }
    if byte_range is not None:
        record["byte_range"] = list(byte_range)
    component["notices"].append(record)
    files[output] = payload


def scan_tar(component, files, root):
    spec = component["archive"]
    path = safe_path(root, spec["path"])
    require(
        file_hash(path) == spec["sha256"], "Archive SHA-256 mismatch: " + spec["path"]
    )
    if "size" in spec:
        require(path.stat().st_size == spec["size"], "Archive size mismatch")
    prefix = component["archive_root"] + "/"
    seen = set()
    with tarfile.open(path, "r:*") as archive:
        if component["id"].startswith("go-"):
            version = (
                archive.extractfile(prefix + "VERSION").read().decode().splitlines()[0]
            )
            require(version == component["version"], "Runtime archive VERSION mismatch")
        for member in archive:
            safe_name(member.name.rstrip("/"))
            require(member.name not in seen, "Duplicate tar member: " + member.name)
            seen.add(member.name)
            require(
                member.name == prefix[:-1] or member.name.startswith(prefix),
                "Unexpected archive root",
            )
            if not member.isfile():
                continue
            relative = member.name[len(prefix) :]
            named = is_named_notice(relative)
            firmware_readme = component["id"] == "qemu" and relative == "pc-bios/README"
            header = header_candidate(component["id"], relative)
            if not (named or firmware_readme or header):
                continue
            data = archive.extractfile(member).read()
            if named or firmware_readme:
                kind = "upstream-context" if firmware_readme else "named-notice"
                add_notice(component, files, member.name, relative, data, kind)
            elif header:
                region = leading_notice(data)
                if region and component["id"].startswith("go-"):
                    # Standard Go headers merely point at LICENSE. Preserve distinct
                    # third-party/public-domain headers without thousands of copies.
                    copyrights = [
                        line
                        for line in data[: region[1]].splitlines()
                        if b"copyright" in line.lower()
                    ]
                    if copyrights and all(
                        b"the go authors" in line.lower() for line in copyrights
                    ):
                        continue
                if region:
                    add_notice(
                        component,
                        files,
                        member.name,
                        relative,
                        data,
                        "leading-source-comments",
                        region,
                    )
    component["notices"].sort(key=lambda n: n["path"])
    require(component["notices"], "No notices found: " + component["id"])


def module_component(module, root, files, sums):
    name, version, checksum = module["path"], module["version"], module["zip_h1"]
    require(
        " ".join((name, version, checksum)) in sums,
        "Module missing from go.sum: " + name,
    )
    relative = (
        "cache/modules/cache/download/"
        + escape_module(name)
        + "/@v/"
        + escape_module(version)
        + ".zip"
    )
    path = safe_path(root, relative)
    component = {
        "id": "host-modules/" + name + "@" + version,
        "kind": "host-module",
        **module,
        "archive_root": name + "@" + version,
        "archive": {
            "path": relative,
            "sha256": file_hash(path),
            "size": path.stat().st_size,
            "url": "https://proxy.golang.org/"
            + escape_module(name)
            + "/@v/"
            + escape_module(version)
            + ".zip",
        },
        "notices": [],
        "coverage": "recursive named notices; file-level attribution review incomplete",
    }
    prefix = component["archive_root"] + "/"
    with zipfile.ZipFile(path) as archive:
        require(zip_h1(archive) == checksum, "Go h1 mismatch: " + name)
        for member in sorted(archive.namelist()):
            require(member.startswith(prefix), "Unexpected module ZIP root")
            relative = member[len(prefix) :]
            if not member.endswith("/") and is_named_notice(relative):
                add_notice(
                    component,
                    files,
                    member,
                    relative,
                    archive.read(member),
                    "named-notice",
                )
    require(
        any("/" not in n["source_path"][len(prefix) :] for n in component["notices"]),
        "Missing top-level notice: " + name,
    )
    return component


def historical_spec(bundle):
    spec = load_json(bundle / "historical-go.lock.json")
    require(
        spec["version"] == "go1.19.2" and spec["archive_root"] == "go",
        "Wrong historical runtime",
    )
    record = spec["catalog"]["file_record"]
    require(
        record["kind"] == "source" and record["version"] == spec["version"],
        "Wrong historical release record",
    )
    for key in ("filename", "size", "sha256"):
        require(
            record[key] == spec[key], "Historical catalog/lock disagreement: " + key
        )
    return spec


def fetch_historical(root, bundle):
    spec = historical_spec(bundle)
    target = safe_path(bundle, "inputs/" + spec["filename"])
    if target.exists():
        require(
            file_hash(target) == spec["sha256"],
            "Existing historical archive checksum mismatch",
        )
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_suffix(target.suffix + ".part")
    require(
        not partial.exists() and not partial.is_symlink(),
        "Partial download already exists",
    )
    try:
        subprocess.run(
            [
                "curl",
                "--fail",
                "--location",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--connect-timeout",
                "20",
                "--max-time",
                "180",
                "--output",
                str(partial),
                spec["url"],
            ],
            check=True,
            timeout=190,
            cwd=root,
        )
        require(
            partial.stat().st_size == spec["size"]
            and file_hash(partial) == spec["sha256"],
            "Historical download mismatch",
        )
        partial.rename(target)
    finally:
        if partial.exists():
            partial.unlink()


def collect_plan(root=ROOT, bundle=BUNDLE, go=None):
    """Verify all acquisition inputs first; return deterministic output bytes."""
    go = go or root / "tools/go/bin/go"
    files, binaries = {}, {}
    guest_manifest = load_json(root / GUEST_MANIFEST)
    for label, binary in (("host", HOST), ("guest", GUEST)):
        path = safe_path(root, binary)
        raw = subprocess.check_output(
            [str(go), "version", "-m", binary], cwd=root, timeout=30
        )
        metadata = parse_build(raw.decode())
        evidence = "evidence/" + label + "-go-version-m.txt"
        files[evidence] = raw
        binaries[label] = {
            "path": binary,
            "size": path.stat().st_size,
            "sha256": file_hash(path),
            "build_record": evidence,
            **metadata,
        }
    require(binaries["host"]["go_version"] == "go1.22.12", "Unexpected host runtime")
    require(len(binaries["host"]["modules"]) == 48, "Expected exactly 48 host modules")
    require(
        binaries["host"]["settings"].get("GOOS") == "darwin"
        and binaries["host"]["settings"].get("GOARCH") == "amd64",
        "Unexpected host platform",
    )
    for key in ("path", "size", "sha256", "go_version"):
        require(
            binaries["guest"][key] == guest_manifest["guest_agent"][key],
            "Guest manifest mismatch: " + key,
        )
    guest_modules = [
        {key: m[key] for key in ("path", "version", "zip_h1")}
        for m in guest_manifest["modules"]
    ]
    require(
        binaries["guest"]["modules"] == guest_modules,
        "Guest dependency metadata mismatch",
    )
    sums = set((root / GO_SUM).read_text().splitlines())
    components = [
        module_component(m, root, files, sums) for m in binaries["host"]["modules"]
    ]
    locks = {
        name: load_json(root / name)
        for name in ("dependencies.lock.json", "sources.lock.json")
    }
    selections = [
        ("dependencies.lock.json", "inputs", "go", "go-host"),
        ("dependencies.lock.json", "inputs", "glib", "glib"),
        ("dependencies.lock.json", "inputs", "proxy-libintl", "proxy-libintl"),
        ("dependencies.lock.json", "inputs", "zlib", "zlib"),
        ("dependencies.lock.json", "inputs", "libffi", "libffi"),
        ("sources.lock.json", "sources", "lima", "lima"),
        ("sources.lock.json", "sources", "libslirp", "libslirp"),
        ("sources.lock.json", "sources", "qemu", "qemu"),
        ("sources.lock.json", "sources", "keycodemapdb", "keycodemapdb"),
        (
            "sources.lock.json",
            "sources",
            "berkeley-softfloat-3",
            "berkeley-softfloat-3",
        ),
    ]
    historical = historical_spec(bundle)
    historical_path = "compliance/notices/inputs/" + historical["filename"]
    for lock_path, section, key, cid in selections:
        spec = locks[lock_path][section][key]
        component = {
            "id": cid,
            "kind": "runtime" if cid == "go-host" else "native-or-main-project",
            "version": ("go" + spec["version"])
            if cid == "go-host"
            else spec.get("version", spec.get("revision")),
            "archive_root": spec["archive_root"]
            if "archive_root" in spec
            else ("go" if cid == "go-host" else key + "-" + spec["version"]),
            "lock": {"path": lock_path, "section": section, "key": key},
            "archive": {
                "path": "downloads/" + spec["filename"],
                "sha256": spec["sha256"],
                "url": spec["url"],
            },
            "coverage": "recursive named notices and selected leading source comments; partial file-level inventory",
            "notices": [],
        }
        if "size" in spec:
            component["archive"]["size"] = spec["size"]
        scan_tar(component, files, root)
        components.append(component)
    component = {
        "id": "go-guest",
        "kind": "runtime",
        "version": historical["version"],
        "archive_root": "go",
        "lock": {"path": "compliance/notices/historical-go.lock.json"},
        "archive": {
            "path": historical_path,
            **{k: historical[k] for k in ("url", "size", "sha256")},
        },
        "coverage": "historical named notices and selected leading source comments; partial file-level inventory",
        "notices": [],
    }
    scan_tar(component, files, root)
    components.append(component)
    manifest = {
        "format": 1,
        "scope": SCOPE,
        "selection": {
            "named_notice_regex": NOTICE_NAME.pattern,
            "header_prefixes": HEADER_PREFIXES,
            "header_suffixes": sorted(SOURCE_SUFFIXES),
            "excluded_header_path_parts": sorted(EXCLUDED_PARTS),
            "runtime_headers": "non-cmd src/ leading comments except standard Go-only copyright headers; excludes *_test.go and excluded path parts",
            "zlib_headers": "top-level source files only",
            "module_headers": "not collected; recursive named notices only",
            "qemu_context": "pc-bios/README included without claiming its pointers establish historical provenance",
            "header_bytes": "exact prefix from byte 0 through last contiguous leading C/Go comment; requires copyright/SPDX/permission/public-domain marker; may include adjacent descriptive comments",
        },
        "binaries": binaries,
        "components": components,
        "evidence": [
            {"path": p, "size": len(data), "sha256": sha256(data)}
            for p, data in sorted(files.items())
            if p.startswith("evidence/")
        ],
        "guest_manifest_sha256": file_hash(root / GUEST_MANIFEST),
    }
    files["manifest.json"] = json_bytes(manifest)
    return files


def publish(files, bundle=BUNDLE):
    # Do not silently overwrite manual edits or stale data, even in this owned tree.
    for name, data in files.items():
        path = safe_path(bundle, name)
        require(
            not path.exists() or path.read_bytes() == data,
            "Refusing to overwrite differing output: " + name,
        )
    for name, data in sorted(files.items()):
        path = safe_path(bundle, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_bytes(data)


def verify(root=ROOT, bundle=BUNDLE, sources=False, go=None):
    manifest = load_json(bundle / "manifest.json")
    require(
        manifest["format"] == 1 and manifest["scope"] == SCOPE,
        "Unexpected manifest scope",
    )
    require(
        manifest["guest_manifest_sha256"] == file_hash(root / GUEST_MANIFEST),
        "Guest bundle manifest changed",
    )
    historical = historical_spec(bundle)
    components = manifest["components"]
    ids = [c["id"] for c in components]
    require(len(ids) == len(set(ids)), "Duplicate component")
    modules = [c for c in components if c["kind"] == "host-module"]
    require(len(modules) == 48, "Expected 48 host modules")
    expected_native = set(HEADER_PREFIXES) | {"lima", "go-host", "go-guest"}
    require(
        set(ids) - {c["id"] for c in modules} == expected_native,
        "Incomplete component inventory",
    )
    sums = set((root / GO_SUM).read_text().splitlines())
    records = list(manifest["evidence"])
    for component in components:
        require(component["notices"], "Empty component")
        prefix = component["archive_root"] + "/"
        if component["kind"] == "host-module":
            require(
                " ".join(component[k] for k in ("path", "version", "zip_h1")) in sums,
                "go.sum mismatch",
            )
            require(
                component["archive_root"]
                == component["path"] + "@" + component["version"],
                "Wrong module root",
            )
        else:
            ref = component["lock"]
            spec = (
                historical
                if component["id"] == "go-guest"
                else load_json(safe_path(root, ref["path"]))[ref["section"]][ref["key"]]
            )
            for key in ("sha256", "url"):
                require(
                    component["archive"][key] == spec[key],
                    "Archive lock mismatch: " + component["id"],
                )
            if "size" in spec:
                require(
                    component["archive"].get("size") == spec["size"],
                    "Archive locked-size mismatch",
                )
        for notice in component["notices"]:
            safe_name(notice["source_path"])
            require(
                not notice["source_path"].endswith("/")
                and notice["source_path"].startswith(prefix),
                "Wrong source member root",
            )
            relative = notice["source_path"][len(prefix) :]
            destination = (
                "headers/" + relative + ".txt"
                if "byte_range" in notice
                else "files/" + relative
            )
            require(
                notice["path"] == "texts/" + component["id"] + "/" + destination,
                "Wrong notice output/member mapping",
            )
            if "byte_range" in notice:
                start, end = notice["byte_range"]
                require(
                    start == 0
                    and end == notice["size"]
                    and end <= notice["source_size"],
                    "Invalid header byte range",
                )
            else:
                require(
                    notice["sha256"] == notice["source_sha256"]
                    and notice["size"] == notice["source_size"],
                    "Whole-member mismatch",
                )
            records.append(notice)
    expected = set()
    for record in records:
        name = record["path"]
        require(name not in expected, "Duplicate output record: " + name)
        expected.add(name)
        path = safe_path(bundle, name)
        require(
            path.is_file()
            and path.stat().st_size == record["size"]
            and file_hash(path) == record["sha256"],
            "Packaged file mismatch: " + name,
        )
    actual = set()
    for directory in ("texts", "evidence"):
        base = safe_path(bundle, directory)
        for path in base.rglob("*"):
            require(not path.is_symlink(), "Symlink in bundle")
            if not path.is_dir():
                require(path.is_file(), "Nonregular bundle file")
                actual.add(path.relative_to(bundle).as_posix())
    require(actual == expected, "Unexpected or missing packaged files")
    for label, binary in manifest["binaries"].items():
        parsed = parse_build(safe_path(bundle, binary["build_record"]).read_text())
        for key, value in parsed.items():
            require(binary[key] == value, "Build evidence mismatch")
        if label == "host":
            require(
                parsed["modules"]
                == [{k: c[k] for k in ("path", "version", "zip_h1")} for c in modules],
                "Host module inventory mismatch",
            )
    runtimes = {c["id"]: c["version"] for c in components if c["kind"] == "runtime"}
    require(
        runtimes == {"go-host": "go1.22.12", "go-guest": "go1.19.2"},
        "Runtime versions were conflated",
    )
    if sources:
        generated = collect_plan(root, bundle, go)
        for name, data in generated.items():
            require(
                safe_path(bundle, name).read_bytes() == data,
                "Source recollection differs: " + name,
            )
        require(
            set(generated) == expected | {"manifest.json"},
            "Source recollection inventory differs",
        )
    return {
        "components": len(components),
        "host_modules": len(modules),
        "notices": sum(len(c["notices"]) for c in components),
        "source_archives_rechecked": sources,
        "file_level_inventory_complete": False,
        "redistribution_cleared": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("collect", "verify"))
    parser.add_argument(
        "--sources",
        action="store_true",
        help="verify against archives and live binary build records too",
    )
    parser.add_argument(
        "--fetch-historical",
        action="store_true",
        help="explicit HTTPS download of the pinned Go 1.19.2 source archive if absent",
    )
    parser.add_argument(
        "--go", type=Path, help="Go executable used only for go version -m"
    )
    args = parser.parse_args()
    try:
        if args.fetch_historical:
            fetch_historical(ROOT, BUNDLE)
        if args.action == "collect":
            publish(collect_plan(go=args.go))
        report = verify(sources=args.sources, go=args.go)
        if args.action == "collect":
            report["source_archives_rechecked"] = True
        print(json.dumps(report, indent=2, sort_keys=True))
    except (
        ValueError,
        OSError,
        KeyError,
        tarfile.TarError,
        zipfile.BadZipFile,
        subprocess.SubprocessError,
    ) as exc:
        print("notice verification failed: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
