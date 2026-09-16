#!/usr/bin/env python3
"""Evidence inventory, not a license decision. Python 3.8+, stdlib, offline.

Run from the project root: python3 -B compliance/linkage/audit.py
No build-module imports, subprocesses, archive extraction or git access.
"""

import argparse
import collections
import hashlib
import json
import re
import shlex
import struct
import tarfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
CODE_SUFFIXES = (".c", ".h", ".S", ".m", ".cc", ".cpp", ".inc", ".h.inc")
COMMENT = re.compile(r"/\*.*?\*/|(?://[^\n]*(?:\n|$))+", re.S)
NOTICE = re.compile(
    r"SPDX-License-Identifier|\blicen[sc]e[ds]?\b|\b[AL]?GPL\b|"
    r"redistribut|permission is hereby|public domain|Derivative works are acceptable|"
    r"SOFTWARE IS DISTRIBUTED AS IS",
    re.I,
)
FUNCTION = re.compile(
    r"(?m)^[ \t]*(?:[A-Za-z_]\w*[ \t*]+)*?([A-Za-z_]\w*)\s*"
    r"\([^;{}]*\)\s*\{"
)
INCLUDE = re.compile(r'^\s*#\s*include\s*([<"])([^>"\n]+)[>"]', re.M)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def delivery_relink_projection(delivery):
    field = (
        "local_relink_inputs"
        if "local_relink_inputs" in delivery
        else "private_relinking_evidence"
    )
    return {
        "field": field,
        "inputs": [
            {"path": item["path"], "sha256": item["sha256"]}
            for item in delivery.get(field, [])
        ],
    }


def delivery_relink_fingerprint(delivery):
    # Whole-manifest hashing would cycle through acquisition's inventory hash.
    projection = delivery_relink_projection(delivery)
    canonical = json.dumps(
        projection, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return {
        "fingerprint_scope": "source-delivery-relink-projection",
        "fingerprint_schema": "ordered-path-sha256-v1",
        "projection_sha256": sha(canonical),
    }


def grants(text):
    """Per-comment signals: no file-wide 'later' cancellation or SPDX rewriting."""
    flat = re.sub(r"\s+", " ", re.sub(r"(?m)^\s*\*\s?", "", text)).lower()
    spdx = re.findall(r"SPDX-License-Identifier:\s*([^\n*]+)", text)
    result = set()
    gpl = bool(re.search(r"\bgpl(?:v?[- ]?2)?\b|gnu general public license", flat))
    lgpl = bool(re.search(r"\blgpl\b|gnu (?:lesser|library) general public", flat))
    later = bool(
        re.search(
            r"later version|version \d(?:\.\d)? or later|or-later|gplv?2\+|gpl-v2\+",
            flat,
        )
    )
    v2 = bool(
        re.search(
            r"version\s+2(?!\d|\.\d)|\bgpl[- ]?(?:v(?:ersion)?[- ]?)?2(?:\.0)?(?!\d|\.\d)",
            flat,
        )
    )
    # A mixed LGPL/GPL comment without an explicit GPL identifier is not resolved.
    if any(re.search(r"(?<![A-Z])GPL-2\.0-only\b", s) for s in spdx):
        result.add("explicit-gpl-2.0-only")
    elif gpl and not lgpl and v2:
        if later:
            result.add("gpl-2.0-or-later-text")
        elif re.search(r"only|no later|not later", flat):
            result.add("explicit-gpl-2.0-only")
        else:
            result.add("gpl-version-2-without-later-candidate")
    elif gpl:
        result.add("gpl-version-or-scope-unresolved")
    if lgpl:
        result.add("lgpl-or-library-gpl-text")
    if re.search(r"\bbsd\b|redistribution and use in source and binary", flat):
        result.add("bsd-style-text")
    if re.search(r"\bmit\b|permission is hereby granted", flat):
        result.add("mit-style-text")
    if "public domain" in flat:
        result.add("public-domain-text")
    if "softfloat" in flat:
        result.add("softfloat-terms-or-provenance")
    if re.search(r"\bwith\s+[\w.-]+", " ".join(spdx), re.I) or re.search(
        r"special exception|linking exception|syscall.note|additional permission", flat
    ):
        result.add("exception-text-review-scope")
    if re.search(
        r"dual.licen|alternativ.{0,100}licen|licen.{0,100}alternativ|\bat your option\b.{0,80}\bbsd\b",
        flat,
    ) or any(" OR " in s for s in spdx):
        result.add("alternate-grant-text-review-scope")
    if re.search(
        r"portions of (?:this|the) (?:work|code)|some portions|some parts|some later contributions|separately licensed",
        flat,
    ) and NOTICE.search(text):
        result.add("portion-specific-text-review-scope")
    return sorted(result), [s.strip() for s in spdx]


def notices(text):
    found = []
    for match in COMMENT.finditer(text):
        snippet = match.group()
        if not NOTICE.search(snippet):
            continue
        signals, spdx = grants(snippet)
        found.append(
            {
                "start_line": text.count("\n", 0, match.start()) + 1,
                "end_line": text.count("\n", 0, match.end()) + 1,
                "snippet": snippet,
                "signals": signals,
                "spdx_expressions_verbatim": spdx,
            }
        )
    return found


def macho(data):
    """Read little-endian 64-bit Mach-O load commands/nlist, never execute it."""
    if len(data) < 32 or data[:4] != b"\xcf\xfa\xed\xfe":
        raise ValueError("Expected thin little-endian 64-bit Mach-O")
    _, cpu, subtype, kind, ncmd, cmdsize, flags, reserved = struct.unpack_from(
        "<8I", data
    )
    end = 32 + cmdsize
    if end > len(data):
        raise ValueError("Truncated Mach-O commands")
    off, symbols, dylibs, debug = 32, {}, [], []
    symbol_count = 0
    for _ in range(ncmd):
        if off + 8 > end:
            raise ValueError("Truncated load command")
        cmd, size = struct.unpack_from("<II", data, off)
        if size < 8 or off + size > end:
            raise ValueError("Invalid load command size")
        if cmd in (12, 24, 0x80000018, 0x8000001F, 0x80000023):
            if size < 24:
                raise ValueError("Truncated dylib command")
            pos = struct.unpack_from("<I", data, off + 8)[0]
            if not 24 <= pos < size:
                raise ValueError("Invalid dylib name offset")
            dylibs.append(data[off + pos : off + size].split(b"\0")[0].decode())
        if cmd == 2:
            if size < 24:
                raise ValueError("Truncated symtab command")
            st, count, ss, sz = struct.unpack_from("<4I", data, off + 8)
            if st + count * 16 > len(data) or ss + sz > len(data):
                raise ValueError("Truncated Mach-O symbol table")
            symbol_count += count
            for index in range(count):
                string, typ, section, desc, value = struct.unpack_from(
                    "<IBBHQ", data, st + index * 16
                )
                if string >= sz:
                    raise ValueError("Invalid string-table offset")
                stop = data.find(b"\0", ss + string, ss + sz)
                if stop < 0:
                    raise ValueError("Unterminated symbol")
                name = data[ss + string : stop].decode(errors="replace")
                if typ in (0x64, 0x66):
                    debug.append({"type": typ, "name": name, "index": index})
                if not typ & 0xE0 and typ & 0x0E == 0x0E:
                    symbols.setdefault(name, []).append(
                        {
                            "index": index,
                            "address": hex(value),
                            "section": section,
                            "external": bool(typ & 1),
                        }
                    )
        off += size
    if off != end:
        raise ValueError("Load command count/size mismatch")
    return {
        "cpu_type": cpu,
        "file_type": kind,
        "symbol_count": symbol_count,
        "defined_symbol_count": sum(map(len, symbols.values())),
        "dylibs": dylibs,
        "debug_map_records": debug,
    }, symbols


def object_key(value):
    """Meson flattening is many-to-one. Caller must retain ALL candidates."""
    path = PurePosixPath(value)
    if "meson-generated" in path.name:
        return None
    prefix = path.parent.parent.as_posix()
    return ("" if prefix == "." else prefix.replace("/", "_") + "_") + path.name


def source_index(paths):
    result = collections.defaultdict(list)
    for path in sorted(paths):
        if path.endswith((".c", ".S", ".m", ".cc", ".cpp")):
            result[path.replace("/", "_") + ".o"].append(path)
    return result


def ar_members(data):
    """Regular BSD/GNU ar; preserve ordinals, duplicate names and byte offsets."""
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("Expected regular ar archive (thin archives unsupported)")
    off, names, result = 8, b"", []
    while off < len(data):
        header = data[off : off + 60]
        if len(header) != 60 or header[58:] != b"`\n":
            raise ValueError("Invalid ar member header")
        size = int(header[48:58])
        if size < 0 or off + 60 + size > len(data):
            raise ValueError("Truncated ar member")
        label = header[:16].decode().strip()
        payload = data[off + 60 : off + 60 + size]
        payload_offset = off + 60
        if label.startswith("#1/"):
            count = int(label[3:])
            if count < 0 or count > size:
                raise ValueError("Invalid BSD extended name")
            label = payload[:count].rstrip(b"\0").decode()
            payload = payload[count:]
            payload_offset += count
        elif label == "//":
            names = payload
        elif label.startswith("/") and label[1:].isdigit():
            start = int(label[1:])
            stop = names.find(b"/\n", start)
            if stop < start:
                raise ValueError("Invalid GNU long name")
            label = names[start:stop].decode()
        else:
            label = label.rstrip("/")
        if label not in ("", "/", "//", "/SYM64") and not label.startswith("__.SYMDEF"):
            result.append(
                {
                    "ordinal": len(result),
                    "name": label,
                    "header_offset": off,
                    "payload_offset": payload_offset,
                    "bsd_extended_name": header[:16].startswith(b"#1/"),
                    "sha256": sha(payload),
                    "size": len(payload),
                    "data": payload,
                }
            )
        off += 60 + size + size % 2
    if off != len(data):
        raise ValueError("Missing ar alignment byte")
    return result


def archive_object_padding(payload, object_bytes, bsd_extended_name):
    if payload == object_bytes:
        return 0
    padding = (-len(object_bytes)) % 8
    if bsd_extended_name and padding and payload == object_bytes + b"\n" * padding:
        return padding
    return None


def ninja_deps(data):
    """Ninja v4 deps log: validated path checksums and last record per output."""
    if data[:16] != b"# ninjadeps\n\x04\0\0\0":
        raise ValueError("Expected Ninja dependency log version 4")
    off, paths, records = 16, [], {}
    while off < len(data):
        record_offset = off
        if off + 4 > len(data):
            raise ValueError("Truncated Ninja record size")
        raw = struct.unpack_from("<I", data, off)[0]
        size = raw & 0x7FFFFFFF
        off += 4
        if size < 4 or size % 4 or off + size > len(data):
            raise ValueError("Invalid Ninja record size")
        block = data[off : off + size]
        off += size
        if raw & 0x80000000:
            if size < 12:
                raise ValueError("Truncated Ninja dependency record")
            ident, mtime = struct.unpack_from("<Iq", block)
            ids = struct.unpack_from("<" + "I" * ((size - 12) // 4), block, 12)
            if ident >= len(paths) or any(i >= len(paths) for i in ids):
                raise ValueError("Unknown Ninja path id")
            records[paths[ident]] = {
                "mtime_ns": mtime,
                "record_offset": record_offset,
                "dependencies": [paths[i] for i in ids],
            }
        else:
            checksum = struct.unpack_from("<I", block, size - 4)[0]
            if checksum != (~len(paths) & 0xFFFFFFFF):
                raise ValueError("Ninja path checksum mismatch")
            paths.append(block[:-4].rstrip(b"\0").decode())
    return records


class Audit:
    def __init__(self, root):
        self.root = root
        self.inputs = {}
        self.files = {}
        self.texts = {}
        self.archives = {}
        self.gaps = []
        self.retained_source_cache = {}
        self.sources = self.load_json("sources.lock.json")["sources"]
        self.deps = self.load_json("dependencies.lock.json")["inputs"]
        self.overlays = self.load_json("source-overlays.json")["overlays"]
        self.overrides = self.load_json("native/overrides.json")["overrides"]
        manifest = self.load_json("output/build-manifest.json")
        self.manifest = manifest
        binary = self.read("output/limactl")
        self.binary, self.symbols = macho(binary)
        self.binary.update(
            path="output/limactl",
            sha256=sha(binary),
            matches_manifest=sha(binary) == manifest["binary_sha256"],
        )
        self.binary["source_attribution"] = (
            "No whole-file survival inference from symbols"
        )
        self.binary["manifest_input_checks"] = {
            p: self.fingerprint(p)["sha256"] == expected
            for p, expected in manifest["input_manifests"].items()
        }

    def fingerprint(self, path):
        if path not in self.inputs:
            p = self.root / path
            if path == "compliance/source-delivery/manifest.json":
                self.inputs[path] = {
                    "path": path,
                    "exists": p.is_file(),
                    **delivery_relink_fingerprint(json.loads(p.read_bytes())),
                }
            else:
                self.inputs[path] = {
                    "path": path,
                    "exists": p.is_file(),
                    "sha256": file_sha(p) if p.is_file() else None,
                }
        return self.inputs[path]

    def read(self, path):
        self.fingerprint(path)
        return (self.root / path).read_bytes()

    def load_json(self, path):
        return json.loads(self.read(path))

    def archive(self, name):
        if name not in self.archives:
            lock = self.sources.get(name, self.deps.get(name))
            path = "downloads/" + lock["filename"]
            record = dict(self.fingerprint(path), expected_sha256=lock["sha256"])
            record["matches_lock"] = record["sha256"] == lock["sha256"]
            members = {}
            if record["exists"]:
                with tarfile.open(self.root / path) as archive:
                    for member in archive:
                        if member.isfile() and (
                            member.name.endswith(CODE_SUFFIXES)
                            or re.search(
                                r"(?:COPYING|LICENSE|LICENCE|meson\.build|\.json|\.xml|\.py|\.csv)$",
                                member.name,
                                re.I,
                            )
                        ):
                            relative = member.name.split("/", 1)[-1]
                            if relative in members:
                                raise ValueError("Duplicate archive path: " + relative)
                            members[relative] = (
                                member.name,
                                archive.extractfile(member).read(),
                            )
            self.archives[name] = (record, members)
        return self.archives[name]

    def witnesses(self, text, renamed=None):
        result = []
        # Comments are blanked without shifting offsets. Not a C parser: macros,
        # conditional definitions and same-name definitions remain ambiguous.
        code = COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group()), text)
        for match in FUNCTION.finditer(code):
            name = match.group(1)
            binary_name = "_" + (renamed if name == "main" and renamed else name)
            if binary_name in self.symbols:
                result.append(
                    {
                        "name": binary_name,
                        "source_line": text.count("\n", 0, match.start(1)) + 1,
                        "nlist": self.symbols[binary_name],
                    }
                )
        return result

    def add_file(self, key, data, provenance, renamed=None):
        if key not in self.files:
            text = data.decode("utf-8", errors="replace")
            found = notices(text)
            signals = sorted({s for n in found for s in n["signals"]})
            witnesses = self.witnesses(text, renamed)
            self.files[key] = {
                "path": key,
                "sha256": sha(data),
                "size": len(data),
                "provenance": provenance,
                "memberships": [],
                "notices": found,
                "license_signals": signals,
                "gplv2_only_review_candidate": bool(
                    set(signals)
                    & {"explicit-gpl-2.0-only", "gpl-version-2-without-later-candidate"}
                ),
                "no_detected_notice": not found,
                "symbol_witness_count": len(witnesses),
                "symbol_witnesses": witnesses,
                "symbol_attribution": "lexical definition/name match; not unique origin or byte-level proof",
                "alternate_or_exception_clearance": "not determined",
            }
            self.texts[key] = text
        return self.files[key]

    def qemu_file(self, relative, renamed=None):
        key = "src/qemu/" + relative
        data = self.read(key)
        archive, members = self.archive("qemu")
        upstream = members.get(relative)
        overlay = next(
            (
                x
                for x in self.overlays
                if x["source"] == "qemu" and x["path"] == relative
            ),
            None,
        )
        expected = (
            overlay["sha256"] if overlay else sha(upstream[1]) if upstream else None
        )
        return self.add_file(
            key,
            data,
            {
                "archive": archive["path"],
                "archive_member": upstream[0] if upstream else None,
                "upstream_sha256": sha(upstream[1]) if upstream else None,
                "overlay": overlay,
                "matches_prepared_source_recipe": sha(data) == expected,
                "archive_matches_lock": archive["matches_lock"],
                "compiled_bytes_verified": False,
            },
            renamed,
        )

    def tar_file(self, component, relative):
        archive, members = self.archive(component)
        member, data = members[relative]
        key = archive["path"] + "::" + member
        return self.add_file(
            key,
            data,
            {
                "archive": archive["path"],
                "archive_member": member,
                "archive_matches_lock": archive["matches_lock"],
                "compiled_bytes_verified": False,
            },
        )

    def log(self, path):
        return self.read(path).decode(errors="replace").splitlines()

    def run(self):
        self.read("compliance/linkage/audit.py")
        self.read("link_lima.py")
        self.read("build_native.py")
        self.read("bootstrap.py")
        self.read("src/qemu/LICENSE")
        qpaths = sorted(
            p.relative_to(self.root / "src/qemu").as_posix()
            for p in (self.root / "src/qemu").rglob("*")
            if p.is_file() and p.name.endswith(CODE_SUFFIXES)
        )
        index = source_index(qpaths)
        log_path = "logs/native-core-archive.log"
        lines = self.log(log_path)
        command = shlex.split(next(l[9:] for l in lines if l.startswith("command: ")))
        raw_objects = [a for a in command if a.endswith(".o")]
        native = {}
        recompiles = []
        for path in sorted((self.root / "logs").glob("native-compile-*.log")):
            relative = path.relative_to(self.root).as_posix()
            args = shlex.split(
                next(l[9:] for l in self.log(relative) if l.startswith("command: "))
            )
            output, input_path = args[args.index("-o") + 1], args[args.index("-c") + 1]
            name = path.name[len("native-compile-") : -len(".log")]
            override = next(
                (x for x in self.overrides if x["path"].replace("/", "-") == name), None
            )
            if override:
                source = override["path"]
                record = self.add_file(
                    override["file"],
                    self.read(override["file"]),
                    {
                        "override_manifest": "native/overrides.json",
                        "upstream_path": "src/qemu/" + source,
                        "matches_override_hash": self.fingerprint(override["file"])[
                            "sha256"
                        ]
                        == override["sha256"],
                        "matches_upstream_base": self.fingerprint("src/qemu/" + source)[
                            "sha256"
                        ]
                        == override["upstream_sha256"],
                        "transformations": "link_lima.py:65-76 error text replacement and mutex diagnostic; retained transformed input is inventoried separately",
                        "compiled_bytes_verified": False,
                    },
                )
            else:
                source = input_path.split("/sources/qemu/")[-1]
                rename = (
                    "qemu_img_embedded_main"
                    if source == "qemu-img.c"
                    else "qemu_embedded_main"
                )
                record = self.qemu_file(source, rename)
            native[output] = record["path"]
            recompiles.append(
                {
                    "source": source,
                    "input": input_path,
                    "output": output,
                    "review_file": record["path"],
                    "log": relative,
                    "line": 2,
                }
            )
        objects = []
        for ordinal, raw in enumerate(raw_objects):
            relative = raw.split("/qemu/", 1)[-1]
            candidates = (
                [native[raw]]
                if raw in native
                else ["src/qemu/" + p for p in index.get(object_key(relative), [])]
            )
            status = (
                "native-compile-log"
                if raw in native
                else "unique-meson-name-inference"
                if len(candidates) == 1
                else "ambiguous"
                if candidates
                else "generated-unavailable"
                if "meson-generated" in raw
                else "unresolved"
            )
            row = {
                "ordinal": ordinal,
                "object": raw,
                "original_group": str(PurePosixPath(relative).parent),
                "evidence": {
                    "path": log_path,
                    "line": 2,
                    "argv_index": command.index(raw),
                },
                "membership": "logged-force-loaded-aggregate-input",
                "mapping": status,
                "source_candidates": candidates,
                "actual_object_bytes_available": (self.root / raw).is_file(),
            }
            objects.append(row)
            for candidate in candidates:
                record = self.files.get(candidate) or self.qemu_file(
                    candidate[len("src/qemu/") :]
                )
                record["memberships"].append(
                    {
                        "kind": row["membership"],
                        "core_ordinal": ordinal,
                        "mapping": status,
                    }
                )
        retained = self.load_json("logs/native-link-inputs.json")
        system = [
            a for a in retained["qemu-system-x86_64-unsigned"] if a.endswith(".o")
        ]
        img = [a for a in retained["qemu-img"] if a.endswith(".o")]
        # Compare after the two core substitutions and qemu-img addition.
        expected = list(system)
        for item in recompiles:
            if item["source"] in ("system/main.c", "os-posix.c"):
                matches = [
                    p
                    for p in expected
                    if PurePosixPath(p).name == PurePosixPath(item["output"]).name
                ]
                if len(matches) == 1:
                    expected[expected.index(matches[0])] = item["output"]
            elif item["source"] == "qemu-img.c":
                expected.append(item["output"])
        normalized_actual = [
            p if p in native else p.split("/qemu/", 1)[-1] for p in raw_objects
        ]
        # Actual utility members are read below; do not substitute Meson declarations.
        for item in recompiles:
            if item["source"].startswith("util/"):
                self.files[item["review_file"]]["memberships"].append(
                    {"kind": "utility-replacement-log", "path": item["log"], "line": 2}
                )
        self.log("logs/native-utility-archive.log")
        self.log("logs/lima-link.log")
        generator_leads = self.generator_leads()
        dependencies = self.native_dependencies(retained)
        retained_evidence = self.retained_linkage(objects, recompiles)
        for dependency in dependencies:
            linked = [
                a
                for a in retained_evidence["archives"]
                if PurePosixPath(a["path"]).name == dependency["library"]
            ]
            dependency["retained_link_archives"] = [a["path"] for a in linked]
            dependency["retained_member_count"] = sum(a["member_count"] for a in linked)
            dependency["status"] = (
                "retained-link-flag archive; complete member inventory, extraction inference only"
                if linked
                else "present/built, not on retained native link flags"
            )
        header_edges = self.headers(qpaths)
        review = []
        for key, record in sorted(self.files.items()):
            if record["gplv2_only_review_candidate"]:
                review.append(
                    {
                        "file": key,
                        "signals": record["license_signals"],
                        "membership_kinds": sorted(
                            {m["kind"] for m in record["memberships"]}
                        ),
                        "notice_lines": [
                            n["start_line"]
                            for n in record["notices"]
                            if set(n["signals"])
                            & {
                                "explicit-gpl-2.0-only",
                                "gpl-version-2-without-later-candidate",
                            }
                        ],
                    }
                )
        private_archives = []
        for path in self.manifest["private_archives"]:
            relative = "build/" + path.split("/build/", 1)[-1]
            item = dict(
                self.fingerprint(relative),
                recorded_sha256=self.manifest["private_archives"][path],
            )
            item["matches_manifest"] = item["sha256"] == item["recorded_sha256"]
            private_archives.append(item)
        self.gaps.extend(
            [
                "Retained archives, compilation databases, generated link flags, transformed inputs and Ninja dependency logs were read directly with Path.is_file, independent of editor visibility. Member byte equality verifies the retained objects; compilation databases name source paths but do not capture immutable compile-time source hashes.",
                "The retained generated cgo flags supersede the qemu-static-poc paths in historical native-link-inputs.json. They are not the complete Go external-link argv. Link-map search results are reported for explicit retained roots; extraction is not asserted from unevaluated map candidates.",
                "Binary and private-archive digests are compared to the stored build manifest. Its source-overlays.json digest is compared to the current file only; a mismatch can reflect later manifest edits and does not by itself prove different linked source bytes. Retained/prepared/source-recipe comparisons are reported separately.",
                "Force-load requests every core member, unlike ordinary archive extraction. It does not prove every section/function survived. -dead_strip_dylibs concerns dylibs, not code; Go's final external-link dead-strip flags are unrecorded.",
                "Mach-O defined symbols corroborate names only; lexical definitions can be macros, conditional, duplicate or from a different translation unit. No witness is not evidence of absence. Data-only and inline/header code can survive without named functions.",
                "Ordinary archive membership is verified. Unique external definitions shared with the final binary support extraction inference within the six inventoried archives, not proof against every Go/cgo/compiler/SDK input. Absence of a symbol never establishes exclusion or whole-object dead stripping.",
                "Ninja dependency records are tied to retained output mtimes and byte-matched archive members. Native recompiles removed depfile flags, and zlib lacks Ninja records; lexical include edges remain a separate conservative fallback. SDK paths are listed but their file licenses are not audited.",
                "Generated C and headers are inspected where retained, including all 17 generated core inputs. Schema/XML/generator review leads do not automatically assign output licenses; their full generation dependency/portion graph still needs review.",
                "Native dependency logs can include intermediate/test/unused objects. GLib includes PCRE and libcharset; libintl evidence points to proxy-libintl, not an assumed gettext grant. libffi is built but not thereby linked.",
                "Comment/SPDX recognition is heuristic and not exhaustive contributor/portion or legal review. Missing notices are not GPLv2-only; QEMU LICENSE:11-15 provides a separate default-policy lead, not an explicit per-file grant.",
                "Go host packages/runtime, cgo-generated wrappers, embedded guest agent and firmware remain outside this native inventory; existing compliance/guest-agent and compliance/firmware are separate audits. No redistribution clearance, permissions or replacements supplied.",
            ]
        )
        summary = {
            "core_logged_objects": len(objects),
            "manifest_object_count": self.manifest["object_count"],
            "core_mapping_counts": dict(
                sorted(collections.Counter(o["mapping"] for o in objects).items())
            ),
            "retained_archive_members": sum(
                a["member_count"] for a in retained_evidence["archives"]
            ),
            "archive_members_with_byte_matched_compiler_records": sum(
                bool(m["compiler_records"])
                for a in retained_evidence["archives"]
                for m in a["members"]
            ),
            "ordinary_members_with_unique_symbol_witness": sum(
                m["unique_external_symbol_witness_count"] > 0
                for a in retained_evidence["archives"]
                if not a["force_load"]
                for m in a["members"]
            ),
            "recorded_dependency_sets": len(retained_evidence["dependency_sets"]),
            "files_reviewed": len(self.files),
            "gplv2_only_review_candidates": len(review),
            "candidate_membership_counts": dict(
                sorted(
                    collections.Counter(
                        m for r in review for m in r["membership_kinds"]
                    ).items()
                )
            ),
            "files_with_symbol_witnesses": sum(
                bool(r["symbol_witnesses"]) for r in self.files.values()
            ),
        }
        return {
            "format": 2,
            "scope": {
                "file_level_inventory_complete": False,
                "retained_link_archive_membership_complete": True,
                "core_source_mapping_complete": all(
                    o["archive_member_bytes_verified"] for o in objects
                ),
                "ordinary_archive_extraction_complete": False,
                "contributor_inventory_complete": False,
                "redistribution_cleared": False,
                "single_file_design_unchanged": True,
            },
            "summary": summary,
            "binary": self.binary,
            "linkage": {
                "core_force_load_evidence": {
                    "path": "link_lima.py",
                    "lines": [119, 152],
                },
                "core_archive_log": log_path,
                "private_archives": private_archives,
                "historical_list_matches_core_after_replacements": expected
                == normalized_actual,
                "historical_qemu_img_only_objects": sorted(set(img) - set(system)),
                "historical_link_flags": {
                    t: [a for a in args if not a.endswith(".o")]
                    for t, args in retained.items()
                },
                "recompiles": recompiles,
                "utility_member_files": sorted(
                    {
                        p
                        for a in retained_evidence["archives"]
                        if a["path"].endswith("libqemuutil-go.a")
                        for m in a["members"]
                        for p in m["source_candidates"]
                    }
                ),
                "retained_evidence": retained_evidence,
            },
            "core_objects": objects,
            "native_dependencies": dependencies,
            "header_include_edges": header_edges,
            "generated_input_leads": generator_leads,
            "gplv2_only_review_queue": review,
            "mixed_alternate_exception_review_queue": [
                k
                for k, r in sorted(self.files.items())
                if any(
                    s in r["license_signals"]
                    for s in (
                        "alternate-grant-text-review-scope",
                        "exception-text-review-scope",
                        "portion-specific-text-review-scope",
                    )
                )
            ],
            "files": [r for _, r in sorted(self.files.items())],
            "source_archives": [r for _, (r, _) in sorted(self.archives.items())],
            "evidence_inputs": [r for _, r in sorted(self.inputs.items())],
            "gaps": self.gaps,
        }

    def native_dependencies(self, retained):
        result = []
        for component, library, log_name in (
            ("glib", "libglib-2.0.a", "logs/glib-build.log"),
            ("proxy-libintl", "libintl.a", "logs/glib-build.log"),
            ("zlib", "libz.a", "logs/zlib-build.log"),
            ("libslirp", "libslirp.a", "logs/slirp-build.log"),
            ("libffi", "libffi.a", "logs/libffi-build.log"),
        ):
            archive, members = self.archive(component)
            idx = source_index(members)
            records = []
            log_lines = self.log(log_name)
            if component in ("glib", "proxy-libintl"):
                for line, text in enumerate(log_lines, 1):
                    match = re.search(r"Compiling C object (\S+\.o)", text)
                    if not match:
                        continue
                    obj = match.group(1)
                    is_proxy = obj.startswith("subprojects/proxy-libintl/")
                    if is_proxy != (component == "proxy-libintl"):
                        continue
                    key = PurePosixPath(obj).name if is_proxy else object_key(obj)
                    records.append(
                        (
                            obj,
                            idx.get(key, []),
                            line,
                            "dependency-compile-log-not-extraction",
                        )
                    )
            elif component == "zlib":
                compiled = {}
                for text in log_lines:
                    args = shlex.split(text)
                    if "-c" in args and "-o" in args:
                        output = args[args.index("-o") + 1]
                        compiled[output] = sorted(
                            {
                                p
                                for p in members
                                if p.endswith(".c")
                                and any(a.endswith("/" + p) for a in args)
                            }
                        )
                for line, text in enumerate(log_lines, 1):
                    args = shlex.split(text)
                    if args[:3] == ["libtool", "-o", "libz.a"]:
                        for obj in args[3:]:
                            records.append(
                                (
                                    obj,
                                    compiled.get(obj, []),
                                    line,
                                    "dependency-archive-construction-log-not-extraction",
                                )
                            )
            elif component == "libslirp":
                # There are only install messages; do not turn a source list into objects.
                for relative in sorted(members):
                    if relative.startswith("src/") and relative.endswith(".c"):
                        records.append(
                            (None, [relative], None, "dependency-source-review-only")
                        )
            # libffi has a build log, but is not on the retained QEMU link line.
            for obj, candidates, line, kind in records:
                for relative in candidates:
                    record = self.tar_file(component, relative)
                    record["memberships"].append(
                        {
                            "kind": kind,
                            "component": component,
                            "object": obj,
                            "path": log_name,
                            "line": line,
                        }
                    )
                if not candidates:
                    self.gaps.append(
                        "Unmapped dependency build input: " + component + ":" + str(obj)
                    )
            license_members = [
                p
                for p in members
                if re.search(
                    r"(?:^|/)(?:COPYING|LICENSE|LICENCE)(?:\.[^/]*)?$", p, re.I
                )
            ]
            result.append(
                {
                    "component": component,
                    "library": library,
                    "historical_link_arguments": [
                        a
                        for a in retained["qemu-system-x86_64-unsigned"]
                        if a.endswith("/" + library)
                    ],
                    "build_log": log_name,
                    "source_archive": archive["path"],
                    "file_records": sorted(
                        {
                            self.tar_file(component, p)["path"]
                            for _, ps, _, _ in records
                            for p in ps
                        }
                    ),
                    "notice_members": [
                        {"member": members[p][0], "sha256": sha(members[p][1])}
                        for p in sorted(license_members)
                    ],
                    "linked_member_inventory_complete": False,
                    "status": "built-only; linkage unproven"
                    if component == "libffi"
                    else "historical-link/build evidence; final member extraction unknown",
                }
            )
        self.log("logs/glib-static-link-flags.log")
        return result

    def local_path(self, path):
        resolved = Path(path).resolve()
        try:
            return resolved.relative_to(self.root.resolve()).as_posix()
        except ValueError:
            return str(resolved)

    def retained_file(self, path):
        key = self.local_path(path)
        if key in self.retained_source_cache:
            return self.files[self.retained_source_cache[key]]
        data = self.read(key)
        digest = sha(data)
        record = None
        qbase = "build/self-contained/sources/qemu/"
        if key.startswith(qbase):
            relative = key[len(qbase) :]
            original = "src/qemu/" + relative
            if (self.root / original).is_file() and self.fingerprint(original)[
                "sha256"
            ] == digest:
                record = self.qemu_file(relative)
        component_roots = [
            (
                "proxy-libintl",
                "build/self-contained/dependency-sources/glib-"
                + self.deps["glib"]["version"]
                + "/subprojects/proxy-libintl/",
            ),
            (
                "glib",
                "build/self-contained/dependency-sources/glib-"
                + self.deps["glib"]["version"]
                + "/",
            ),
            (
                "zlib",
                "build/self-contained/dependency-sources/zlib-"
                + self.deps["zlib"]["version"]
                + "/",
            ),
            ("libslirp", "build/self-contained/sources/libslirp/"),
        ]
        for component, prefix in component_roots:
            if record is None and key.startswith(prefix):
                _, members = self.archive(component)
                relative = key[len(prefix) :]
                if relative in members and sha(members[relative][1]) == digest:
                    record = self.tar_file(component, relative)
                break
        if record is None:
            record = self.add_file(
                key,
                data,
                {
                    "kind": "retained-build-or-installed-input",
                    "compiled_bytes_verified": False,
                    "compile_time_source_hash_available": False,
                },
            )
        record["provenance"].setdefault("retained_inputs", []).append(
            {"path": key, "sha256": digest, "matches_review_bytes": True}
        )
        self.retained_source_cache[key] = record["path"]
        return record

    def retained_linkage(self, core, recompiles):
        delivery_path = "compliance/source-delivery/manifest.json"
        delivery = self.load_json(delivery_path)
        projection = delivery_relink_projection(delivery)
        selected = projection["inputs"]
        delivery_checks = []
        for item in selected:
            actual = dict(self.fingerprint(item["path"]))
            actual.update(
                recorded_sha256=item["sha256"],
                matches_recorded_sha256=actual["sha256"] == item["sha256"],
            )
            delivery_checks.append(actual)
        flag_path = "build/self-contained/sources/lima/cmd/limactl/native_link_flags.go"
        flag_lines = self.log(flag_path)
        flags = shlex.split(
            next(
                l.split("#cgo LDFLAGS:", 1)[1]
                for l in flag_lines
                if "#cgo LDFLAGS:" in l
            )
        )
        embedded_hashes = json.loads(
            next(
                l.split("// Native archive hashes:", 1)[1]
                for l in flag_lines
                if l.startswith("// Native archive hashes:")
            )
        )
        by_name = collections.defaultdict(list)
        databases, dep_logs, dep_records = [], {}, {}
        for component in ("qemu", "glib", "libslirp"):
            base = "build/self-contained/" + component
            path = base + "/compile_commands.json"
            entries = self.load_json(path)
            databases.append({"path": path, "entries": len(entries)})
            for number, entry in enumerate(entries):
                output = self.local_path(Path(entry["directory"]) / entry["output"])
                source = self.local_path(Path(entry["directory"]) / entry["file"])
                by_name[PurePosixPath(output).name].append(
                    {
                        "database": path,
                        "entry_index": number,
                        "object": output,
                        "source": source,
                    }
                )
            dep_path = base + "/.ninja_deps"
            records = ninja_deps(self.read(dep_path))
            dep_logs[dep_path] = len(records)
            for output, record in records.items():
                dep_records[self.local_path(self.root / base / output)] = (
                    base,
                    dep_path,
                    record,
                )
            self.fingerprint(base + "/build.ninja")
            self.fingerprint(base + "/.ninja_log")
        for item in recompiles:
            args = shlex.split(self.log(item["log"])[1][9:])
            source = self.local_path(args[args.index("-c") + 1])
            output = self.local_path(item["output"])
            by_name[PurePosixPath(output).name].append(
                {"log": item["log"], "line": 2, "object": output, "source": source}
            )
            item["retained_input"] = dict(self.fingerprint(source))
            self.files[item["review_file"]]["memberships"].append(
                {"kind": "native-recompile-review-base", "path": item["log"]}
            )
        zlog = "logs/zlib-build.log"
        zlines = self.log(zlog)
        cwd = zlines[0].split("cwd: ", 1)[1]
        for line, text in enumerate(zlines, 1):
            args = shlex.split(text)
            if "-c" in args and "-o" in args:
                sources = [a for a in args if a.endswith(".c")]
                if len(sources) == 1:
                    output = self.local_path(Path(cwd) / args[args.index("-o") + 1])
                    by_name[PurePosixPath(output).name].append(
                        {
                            "log": zlog,
                            "line": line,
                            "object": output,
                            "source": self.local_path(Path(cwd) / sources[0]),
                        }
                    )
        # Remove the prior log/name inference, replacing it with archive/compiler evidence.
        for record in self.files.values():
            record["memberships"] = [
                m
                for m in record["memberships"]
                if m["kind"] != "logged-force-loaded-aggregate-input"
            ]
        archives, all_definitions = [], collections.Counter()
        dep_sets, dep_set_index, dep_paths, dep_path_index = [], {}, [], {}
        dependency_memberships = collections.defaultdict(set)

        def dependencies(output):
            if output in dep_set_index:
                return dep_set_index[output]
            if output not in dep_records:
                return None
            base, log, record = dep_records[output]
            ident = len(dep_sets)
            dep_set_index[output] = ident
            path_ids = []
            for raw in record["dependencies"]:
                path = self.local_path(self.root / base / raw)
                if path not in dep_path_index:
                    dep_path_index[path] = len(dep_paths)
                    actual = self.root / path
                    entry = {
                        "path": path,
                        "exists": actual.is_file(),
                        "review_file": None,
                    }
                    if (
                        not Path(path).is_absolute()
                        and actual.is_file()
                        and actual.name.endswith(CODE_SUFFIXES)
                    ):
                        entry["review_file"] = self.retained_file(actual)["path"]
                    elif Path(path).is_absolute():
                        entry["scope"] = (
                            "external SDK/compiler/system input; license not inventoried"
                        )
                    dep_paths.append(entry)
                index = dep_path_index[path]
                path_ids.append(index)
                if dep_paths[index]["review_file"]:
                    dependency_memberships[dep_paths[index]["review_file"]].add(ident)
            dep_sets.append(
                {
                    "id": ident,
                    "object": output,
                    "log": log,
                    "record_offset": record["record_offset"],
                    "mtime_ns": record["mtime_ns"],
                    "matches_object_mtime": (self.root / output).stat().st_mtime_ns
                    == record["mtime_ns"],
                    "dependency_path_ids": path_ids,
                }
            )
            return ident

        for flag in flags:
            force = flag.startswith("-Wl,-force_load,")
            raw = flag.split(",", 2)[2] if force else flag
            if not raw.endswith(".a"):
                continue
            path = self.local_path(raw)
            data = self.read(path)
            members = ar_members(data)
            rows = []
            for member in members:
                payload = member.pop("data")
                _, symbols = macho(payload)
                external = sorted(
                    name
                    for name, entries in symbols.items()
                    if any(e["external"] for e in entries)
                )
                all_definitions.update(external)
                member["external_definitions"] = external
                member["compiler_records"] = []
                for compiler in by_name[member["name"]]:
                    if force and path.endswith("libqemu-embedded.a"):
                        ordinal = member["ordinal"]
                        if (
                            ordinal >= len(core)
                            or self.local_path(core[ordinal]["object"])
                            != compiler["object"]
                        ):
                            continue
                    check = self.fingerprint(compiler["object"])
                    object_bytes = (
                        self.read(compiler["object"]) if check["exists"] else None
                    )
                    padding = (
                        archive_object_padding(
                            payload, object_bytes, member["bsd_extended_name"]
                        )
                        if object_bytes is not None
                        else None
                    )
                    if padding is not None:
                        proof = dict(
                            compiler,
                            object_sha256=check["sha256"],
                            object_size=len(object_bytes),
                            object_bytes_verified=True,
                            archive_padding_size=padding,
                        )
                        source_check = self.fingerprint(compiler["source"])
                        proof["retained_source"] = dict(source_check)
                        proof["review_file"] = (
                            self.retained_file(self.root / compiler["source"])["path"]
                            if source_check["exists"]
                            else None
                        )
                        proof["dependency_set_id"] = dependencies(compiler["object"])
                        member["compiler_records"].append(proof)
                member["source_candidates"] = sorted(
                    {
                        c["review_file"]
                        for c in member["compiler_records"]
                        if c["review_file"]
                    }
                )
                kind = (
                    "force-loaded-archive-member"
                    if force
                    else "ordinary-archive-member"
                )
                for key in member["source_candidates"]:
                    self.files[key]["memberships"].append(
                        {
                            "kind": kind,
                            "archive": path,
                            "member_ordinal": member["ordinal"],
                            "member": member["name"],
                            "member_sha256": member["sha256"],
                        }
                    )
                if force and path.endswith("libqemu-embedded.a"):
                    row = core[member["ordinal"]]
                    row.update(
                        membership=kind,
                        mapping="archive-bytes-and-compiler-record"
                        if member["compiler_records"]
                        else "archive-member-source-unresolved",
                        source_candidates=member["source_candidates"],
                        archive=path,
                        member_sha256=member["sha256"],
                        member_name_matches_log=member["name"]
                        == PurePosixPath(row["object"]).name,
                        archive_member_bytes_verified=bool(member["compiler_records"]),
                    )
                rows.append(member)
            archives.append(
                {
                    "path": path,
                    "exists": (self.root / path).is_file(),
                    "sha256": sha(data),
                    "force_load": force,
                    "member_count": len(rows),
                    "members": rows,
                    "hash_recorded_in_generated_flags": embedded_hashes.get(raw),
                    "matches_generated_flag_hash": sha(data) == embedded_hashes[raw]
                    if raw in embedded_hashes
                    else None,
                }
            )
        for archive in archives:
            for member in archive["members"]:
                matches = [
                    name
                    for name in member["external_definitions"]
                    if name in self.symbols
                ]
                unique = [name for name in matches if all_definitions[name] == 1]
                member["binary_symbol_witnesses"] = [
                    {
                        "name": name,
                        "final_nlist": self.symbols[name],
                        "defining_member_count_in_inventoried_archives": all_definitions[
                            name
                        ],
                    }
                    for name in matches
                ]
                member["unique_external_symbol_witness_count"] = len(unique)
                member["extraction_assessment"] = (
                    "force-load-requested"
                    if archive["force_load"]
                    else "inferred-from-unique-external-definition"
                    if unique
                    else "unresolved-not-proven-absent"
                )
                member["whole_member_survival_proven"] = False
        for key, ids in sorted(dependency_memberships.items()):
            self.files[key]["memberships"].append(
                {
                    "kind": "ninja-recorded-compiler-dependency",
                    "dependency_set_ids": sorted(ids),
                }
            )
        search_roots = ["build/self-contained", "logs", "output"]
        map_candidates = []
        for root in search_roots:
            for path in sorted((self.root / root).rglob("*.map")):
                if path.is_file():
                    text = path.read_text(errors="replace")
                    map_candidates.append(
                        {
                            "path": path.relative_to(self.root).as_posix(),
                            "looks_like_ld_link_map": "# Object files:" in text
                            and "# Symbols:" in text,
                        }
                    )
        self.log("logs/stop-relink.log")
        self.fingerprint("build/self-contained/stamps/glib.json")
        return {
            "source_delivery_manifest": delivery_path,
            "source_delivery_field": projection["field"],
            "source_delivery_input_checks": delivery_checks,
            "link_flags_file": flag_path,
            "native_link_flags": flags,
            "compilation_databases": databases,
            "ninja_dependency_logs": dep_logs,
            "archives": archives,
            "dependency_sets": dep_sets,
            "dependency_paths": dep_paths,
            "final_link_map_search": {
                "roots": search_roots,
                "candidates": map_candidates,
            },
            "extraction_inference_scope": "unique external definitions among these six archives only; not complete Go/cgo/compiler/SDK provenance or dead-strip proof",
        }

    def generator_leads(self):
        groups = [
            ("QAPI", "qapi/meson.build", "qapi-schema.json", ["scripts/qapi-gen.py"]),
            (
                "block wrappers",
                "block/meson.build",
                "block-gen.c",
                ["scripts/block-coroutine-wrapper.py"],
            ),
            ("GDB XML", "meson.build", "gdbstub-xml.c", ["scripts/feature_to_c.py"]),
        ]
        result = []
        _, members = self.archive("qemu")
        for group, build, marker, generators in groups:
            build_path = "src/qemu/" + build
            lines = self.log(build_path)
            references = [
                {"path": build_path, "line": i, "snippet": line}
                for i, line in enumerate(lines, 1)
                if marker in line
            ]
            leads = list(generators)
            if group == "QAPI":
                leads += sorted(
                    p
                    for p in members
                    if (p.startswith("qapi/") and p.endswith(".json"))
                    or (p.startswith("scripts/qapi/") and p.endswith(".py"))
                )
            elif group == "GDB XML":
                leads += sorted(
                    p
                    for p in members
                    if p.startswith("gdb-xml/") and p.endswith(".xml")
                )
            evidence = []
            for relative in leads:
                path = "src/qemu/" + relative
                if not (self.root / path).is_file():
                    continue
                data = self.read(path)
                upstream = members.get(relative)
                evidence.append(
                    {
                        "path": path,
                        "sha256": sha(data),
                        "archive_member": upstream[0] if upstream else None,
                        "matches_archive_member": bool(
                            upstream and data == upstream[1]
                        ),
                        "start_line": 1,
                        "snippet": "\n".join(
                            data.decode(errors="replace").splitlines()[:40]
                        ),
                    }
                )
            result.append(
                {
                    "group": group,
                    "build_references": references,
                    "inputs": evidence,
                    "status": "generator/schema review leads, selection not evaluated; not a generated-output license assignment",
                }
            )
        return result

    def headers(self, qpaths):
        available = set(qpaths)
        queue = sorted(
            k
            for k in self.files
            if k.startswith("src/qemu/") or k.startswith("native/overrides/")
        )
        seen, edges = set(), []
        roots = (
            "",
            "include/",
            "host/include/x86_64/",
            "host/include/generic/",
            "tcg/i386/",
        )
        while queue:
            key = queue.pop()
            if key in seen:
                continue
            seen.add(key)
            relative = (
                key[len("src/qemu/") :]
                if key.startswith("src/qemu/")
                else self.files[key]["provenance"]["upstream_path"][len("src/qemu/") :]
            )
            for match in INCLUDE.finditer(self.texts[key]):
                quote, name = match.groups()
                # Retain all plausible locations, not an invented preprocessor result.
                candidates = sorted(
                    {
                        p
                        for p in [str(PurePosixPath(relative).parent / name)]
                        + [r + name for r in roots]
                        if p in available
                    }
                )
                if quote == "<" and not candidates:
                    continue
                line = self.texts[key].count("\n", 0, match.start()) + 1
                edge = {
                    "from": key,
                    "line": line,
                    "include": name,
                    "source_candidates": ["src/qemu/" + p for p in candidates],
                    "status": "lexical-conditional-unverified"
                    if candidates
                    else "unresolved-generated-or-external",
                }
                edges.append(edge)
                for candidate in candidates:
                    record = self.qemu_file(candidate)
                    membership = {
                        "kind": "lexical-header-or-include-input",
                        "from": key,
                        "line": line,
                    }
                    if membership not in record["memberships"]:
                        record["memberships"].append(membership)
                    if record["path"] not in seen:
                        queue.append(record["path"])
        return sorted(edges, key=lambda e: (e["from"], e["line"], e["include"]))


def generate(root=ROOT):
    return Audit(root).run()


def serialize(report):
    return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare without writing; incomplete evidence is not legal clearance",
    )
    args = parser.parse_args()
    report = generate()
    destination = ROOT / "compliance/linkage/inventory.json"
    content = serialize(report)
    if args.check:
        if not destination.is_file() or destination.read_text() != content:
            raise SystemExit(
                "Inventory differs; regenerate and review evidence changes"
            )
    else:
        destination.write_text(content)
    print(json.dumps(report["summary"], indent=2, sort_keys=True))
    print("Evidence INCOMPLETE; not exhaustive legal clearance.")


if __name__ == "__main__":
    main()
