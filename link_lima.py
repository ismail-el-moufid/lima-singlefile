import hashlib
import json
import os
import shlex
import shutil
from pathlib import Path

import build_native
import build_support as support

ROOT = Path(__file__).resolve().parent
ENV, run = build_native.ENV, build_native.run
BUILD, SOURCE = support.BUILD / "qemu", support.SOURCES / "qemu"
NATIVE = support.BUILD / "native"
GO = support.GO
AR = support.LLVM / "llvm-ar"
(NATIVE / "objects").mkdir(parents=True, exist_ok=True)
(ROOT / "output").mkdir(parents=True, exist_ok=True)
OVERRIDES = {
    item["path"]: item
    for item in json.loads((ROOT / "native/overrides.json").read_text())["overrides"]
}
import subprocess


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


names = [
    "system/main.c",
    "qemu-img.c",
    "os-posix.c",
    "util/main-loop.c",
    "util/qemu-thread-posix.c",
    "util/oslib-posix.c",
]
entries = json.loads((BUILD / "compile_commands.json").read_text())
compiled, old_outputs = {}, {}
for name in names:
    matches = [
        e
        for e in entries
        if (Path(e["directory"]) / e["file"]).resolve() == (SOURCE / name).resolve()
    ]
    assert len(matches) == 1, (name, len(matches))
    entry = matches[0]
    args = shlex.split(entry["command"])
    output = NATIVE / "objects" / Path(entry["output"]).name
    old_outputs[name] = (Path(entry["directory"]) / entry["output"]).resolve()
    if name in ["system/main.c", "qemu-img.c"]:
        input_file = SOURCE / name
    else:
        override = OVERRIDES[name]
        if digest(SOURCE / name) != override["upstream_sha256"]:
            raise RuntimeError("Override base changed: " + name)
        original = ROOT / override["file"]
        if digest(original) != override["sha256"]:
            raise RuntimeError("Native override changed: " + str(original))
        input_file = NATIVE / "objects" / ("override-" + name.replace("/", "__"))
        content = original.read_text().replace(
            "unsupported in the Go/QEMU prototype", "unsupported in embedded QEMU"
        )
        if name == "util/qemu-thread-posix.c":
            old = "    assert(mutex->initialized);\n    qemu_mutex_pre_lock(mutex, file, line);"
            new = (
                '    if (!mutex->initialized) {\n        fprintf(stderr, "Uninitialized QEMU mutex requested at %s:%d\\n", file, line);\n    }\n'
                + old
            )
            assert content.count(old) == 1
            content = content.replace(old, new)
        input_file.write_text(content)
    filtered = [args[0], "-iquote", str((SOURCE / name).parent), "-DQEMU_GO_EMBEDDED"]
    if name == "system/main.c":
        filtered += ["-Dmain=qemu_embedded_main"]
    elif name == "qemu-img.c":
        filtered += ["-Dmain=qemu_img_embedded_main"]
    i = 1
    while i < len(args):
        arg = args[i]
        if arg in ["-MD", "-MMD", "-MP"]:
            i += 1
        elif arg in ["-MF", "-MT", "-MQ"]:
            i += 2
        elif arg == "-o":
            filtered += ["-o", str(output)]
            i += 2
        elif arg == "-c":
            filtered += ["-c", str(input_file)]
            i += 2
        else:
            filtered.append(arg)
            i += 1
    run(filtered, entry["directory"], "native-compile-" + name.replace("/", "-"))
    compiled[name] = output

utility = NATIVE / "libqemuutil-go.a"
shutil.copy2(BUILD / "libqemuutil.a", utility)
replacements = [compiled[n] for n in names if n.startswith("util/")]
members = subprocess.check_output(
    [str(AR), "t", str(utility)], env=ENV, text=True
).splitlines()
assert all(members.count(p.name) == 1 for p in replacements)
run([AR, "rcs", utility] + replacements, ROOT, "native-utility-archive")
links = {}
for target in ["qemu-system-x86_64-unsigned", "qemu-img"]:
    commands = subprocess.check_output(
        [support.NINJA, "-C", str(BUILD), "-t", "commands", target], env=ENV, text=True
    )
    matches = [
        shlex.split(l) for l in commands.splitlines() if " -o " + target + " " in l
    ]
    assert len(matches) == 1
    links[target] = matches[0]
link = links["qemu-system-x86_64-unsigned"]
objects = [(BUILD / a).resolve() for a in link if a.endswith(".o")]
image_only = {
    (BUILD / a).resolve() for a in links["qemu-img"] if a.endswith(".o")
} - set(objects)
assert image_only == {old_outputs["qemu-img.c"]}, image_only
for name in ["system/main.c", "os-posix.c"]:
    assert objects.count(old_outputs[name]) == 1
    objects[objects.index(old_outputs[name])] = compiled[name]
objects.append(compiled["qemu-img.c"])
archive = NATIVE / "libqemu-embedded.a"
temporary = NATIVE / "libqemu-embedded.new.a"
if temporary.exists():
    temporary.unlink()
run([AR, "qcs", temporary] + objects, ROOT, "native-core-archive")
members = subprocess.check_output(
    [str(AR), "t", str(temporary)], env=ENV, text=True
).splitlines()
assert len(members) == len(objects)
os.replace(temporary, archive)
flags = ["-Wl,-force_load," + str(archive)]
for arg in link[link.index("libqemuutil.a") :]:
    if arg == "libqemuutil.a":
        flags.append(str(utility))
    elif arg.startswith("@"):
        assert not (BUILD / arg[1:]).read_text().strip(), (
            "Review linker response: " + arg
        )
    elif arg.endswith(".a"):
        path = Path(arg) if Path(arg).is_absolute() else BUILD / arg
        assert path.is_file()
        flags.append(str(path))
    else:
        flags.append(arg)
archive_hashes = {str(p): digest(p) for p in [archive, utility]}
generated = support.SOURCES / "lima/cmd/limactl/native_link_flags.go"
if generated.exists():
    assert generated.read_text().startswith(
        "// Code generated by link_lima.py; DO NOT EDIT."
    )
generated.write_text(
    "// Code generated by link_lima.py; DO NOT EDIT.\n// Native archive hashes: "
    + json.dumps(archive_hashes, sort_keys=True)
    + "\n//go:build darwin && amd64 && cgo\n\npackage main\n\n/*\n#cgo LDFLAGS: "
    + shlex.join(flags)
    + '\n*/\nimport "C"\n'
)
ENV.update(
    CGO_ENABLED="1",
    GOOS="darwin",
    GOARCH="amd64",
    GOTOOLCHAIN="local",
    GOENV="off",
    GOPROXY="off",
    GOPATH=str(ROOT / "cache/gopath"),
    GOMODCACHE=str(ROOT / "cache/modules"),
    GOCACHE=str(ROOT / "cache/build"),
    GOTMPDIR=str(ROOT / "tmp"),
    CGO_CFLAGS=ENV["CFLAGS"],
    CGO_CPPFLAGS=ENV["CPPFLAGS"],
    CGO_LDFLAGS=ENV["LDFLAGS"],
    CGO_LDFLAGS_ALLOW=r"-Wl,-force_load,.*",
)
run([GO.parent / "gofmt", "-w", generated], ROOT, "native-link-flags-format")
run(
    [
        GO,
        "build",
        "-mod=readonly",
        "-ldflags=-linkmode=external -X github.com/lima-vm/lima/pkg/version.Version=0.13.0-singlefile",
        "-o",
        ROOT / "output/limactl",
        "./cmd/limactl",
    ],
    support.SOURCES / "lima",
    "lima-link",
)
manifest = {
    "private_archives": archive_hashes,
    "object_count": len(objects),
    "binary": str(ROOT / "output/limactl"),
    "binary_sha256": digest(ROOT / "output/limactl"),
    "binary_size": (ROOT / "output/limactl").stat().st_size,
}
manifest["input_manifests"] = {
    name: digest(ROOT / name)
    for name in [
        "dependencies.lock.json",
        "sources.lock.json",
        "source-overlays.json",
        "native/overrides.json",
    ]
}
manifest["toolchain"] = support.fingerprint()
(ROOT / "output/build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print("BUILT:", manifest["binary"], manifest["binary_size"], "bytes", flush=True)
