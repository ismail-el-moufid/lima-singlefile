#!/usr/bin/env python3
"""Native registry/archive and deterministic-generation tests; no QEMU build.
SPDX-License-Identifier: GPL-2.0-or-later
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


class Resource(ctypes.Structure):
    _fields_ = [("name", ctypes.c_char_p),
                ("data", ctypes.POINTER(ctypes.c_uint8)),
                ("size", ctypes.c_size_t)]


def run(args, **kwargs):
    subprocess.run([str(a) for a in args], check=True, timeout=60, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--asset-dir", type=Path)
    args = parser.parse_args()
    directory = Path(__file__).resolve().parent
    root = directory.parents[1]
    manifest = json.loads((directory / "manifest.json").read_text())
    entries = manifest["resources"]
    blob = (directory / "builtin-data.bin").read_bytes()
    assert len(blob) == manifest["blob_bytes"]
    assert hashlib.sha256(blob).hexdigest() == manifest["blob_sha256"]
    assert sum(e["size"] for e in entries) == manifest["resource_bytes"]
    assert len({e["name"] for e in entries}) == len(entries)
    assert [e["name"] for e in entries] == sorted(e["name"] for e in entries)
    previous_end = 0
    keymaps = []
    for e in entries:
        assert e["offset"] % 16 == 0
        assert e["offset"] >= previous_end
        assert not any(blob[previous_end:e["offset"]])
        previous_end = e["offset"] + e["size"]
        data = blob[e["offset"]:previous_end]
        assert len(data) == e["size"] > 0
        assert hashlib.sha256(data).hexdigest() == e["sha256"], e["name"]
        if e["name"].startswith("keymaps/"):
            keymaps.append(e["name"])
            # QEMU 10 no longer supports include directives in keymaps.
            assert not any(line.startswith(b"include ") for line in data.splitlines())
    assert previous_end == len(blob)
    assert len(keymaps) == 34 and "keymaps/en-us" in keymaps
    cc, ar = shutil.which("cc"), shutil.which("ar")
    if not cc or not ar:
        raise SystemExit("Native tests require cc and ar")
    # All test outputs stay inside the resource write scope and are removed.
    with tempfile.TemporaryDirectory(prefix=".test-", dir=directory) as tmp:
        tmp = Path(tmp)
        if args.asset_dir:
            regenerated = tmp / "regenerated"
            run([sys.executable, root / "scripts/gen-builtin-resources.py",
                 "--asset-dir", args.asset_dir, "--output-dir", regenerated])
            for name in ("builtin-data.bin", "builtin-table.inc", "manifest.json"):
                assert (regenerated / name).read_bytes() == (directory / name).read_bytes(), name
        (tmp / "builtin-path.h").write_text(
            "#define QEMU_BUILTIN_DATA_FILE " +
            json.dumps(str(directory / "builtin-data.bin")) + "\n")
        registry, assembly = tmp / "registry.o", tmp / "blob.o"
        run([cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-fPIC",
             "-I", root / "include", "-c", directory / "registry.c", "-o", registry])
        run([cc, "-I", tmp, "-c", directory / "builtin-data.S", "-o", assembly])
        library = tmp / "registry.dylib"
        run([cc, "-dynamiclib" if sys.platform == "darwin" else "-shared",
             registry, assembly, "-o", library])
        lib = ctypes.CDLL(str(library))
        lib.qemu_builtin_count.restype = ctypes.c_size_t
        lib.qemu_builtin_at.argtypes = [ctypes.c_size_t]
        lib.qemu_builtin_at.restype = ctypes.POINTER(Resource)
        lib.qemu_builtin_lookup.argtypes = [ctypes.c_char_p]
        lib.qemu_builtin_lookup.restype = ctypes.POINTER(Resource)
        lib.qemu_builtin_is_uri.argtypes = [ctypes.c_char_p]
        lib.qemu_builtin_is_uri.restype = ctypes.c_bool
        assert lib.qemu_builtin_count() == len(entries)
        for index, e in enumerate(entries):
            name = e["name"].encode()
            found = lib.qemu_builtin_lookup(b"builtin:" + name)
            assert found and found.contents.name == name
            assert found.contents.size == e["size"]
            assert ctypes.addressof(found.contents) == ctypes.addressof(
                lib.qemu_builtin_lookup(name).contents)
            assert ctypes.addressof(found.contents) == ctypes.addressof(
                lib.qemu_builtin_at(index).contents)
            data = ctypes.string_at(found.contents.data, found.contents.size)
            assert data == blob[e["offset"]:e["offset"] + e["size"]], name
        assert not lib.qemu_builtin_at(len(entries))
        assert not lib.qemu_builtin_at(ctypes.c_size_t(-1).value)
        for name in (None, b"", b"builtin:", b"builtin:missing.fd",
                     b"builtin:/bios.bin", b"builtin:../bios.bin",
                     b"builtin:builtin:bios.bin", b"/missing/bios.bin",
                     b"./bios.bin", b"BUILTIN:bios.bin", b"bios.bin?x",
                     b"builtin:keymaps/../en-us", b"builtin:keymaps/missing",
                     b"/missing/keymaps/en-us", b"builtin:en-us",
                     b"builtin:edk2-aarch64-code.fd", b"builtin:edk2-riscv-code.fd"):
            assert not lib.qemu_builtin_lookup(name), name
        assert lib.qemu_builtin_is_uri(b"builtin:missing.fd")
        assert not lib.qemu_builtin_is_uri(None)
        assert not lib.qemu_builtin_is_uri(b"/tmp/builtin:bios.bin")
        # Normal archive extraction and dead stripping must retain the blob
        # reached from a registry lookup, without relying on dynamic loading.
        archive = tmp / "libbuiltin.a"
        run([ar, "rcs", archive, registry, assembly])
        probe = tmp / "probe.c"
        probe.write_text("#include <qemu/builtin.h>\n"
                         "int main(void) {\n"
                         ' const QemuBuiltinResource *r = qemu_builtin_lookup("builtin:bios.bin");\n'
                         " return !r || r->size != 131072 || r->data[0] != " +
                         str(lib.qemu_builtin_lookup(b"bios.bin").contents.data[0]) + ";\n}\n")
        executable = tmp / "probe"
        run([cc, "-I", root / "include", probe, archive,
             "-Wl,-dead_strip" if sys.platform == "darwin" else "-Wl,--gc-sections",
             "-o", executable])
        run([executable])
    print(f"PASS: {len(entries)} resources, {manifest['resource_bytes']} bytes; "
          "hashes, exact URI lookup, invalid names, shared/static native linking" +
          (", reproducible generation" if args.asset_dir else ""))


if __name__ == "__main__":
    main()
