# Single-file Lima (Go integration)

This source tree embeds the original Lima 0.13 Linux x86_64 guest agent and all
37 bundled YAML examples, including nested/deprecated examples. Template locations
are `template://NAME` URIs, not host filesystem paths. The interactive picker and
cidata ISO writer consume embedded bytes/readers directly, without extracting assets.
The ISO writer streams inputs into their final ISO extents and writes ISO9660/Rock
Ridge metadata in place; it does not use a diskfs temporary workspace. Its cidata
layout supports regular files, names up to 128 bytes, paths up to eight components,
and individual files smaller than 4 GiB; unsupported inputs fail explicitly.
`limactl licenses` prints the embedded Lima license and asset notes without storage
setup. Normal user-supplied YAML paths/URLs and the existing editor flow still work.

## Native link contract

Build the final executable with Go 1.19 or later, `GOOS=darwin`, `GOARCH=amd64`, and
`CGO_ENABLED=1`. The main/native agent owns `cmd/limactl/native_link_flags.go` and
must supply the CGO linker directives, native static archives and platform frameworks
needed to resolve these C entry points:

```c
int qemu_embedded_main(int argc, char **argv);
int qemu_img_embedded_main(int argc, char **argv);
```

Both symbols must coexist in one executable (native duplicate globals/entry points
must be handled in the native build). This Go change deliberately contains no guessed
archive paths or native linker flags. `go build ./cmd/limactl` and tests that link
`cmd/limactl` on darwin/amd64 with CGO require those definitions and directives.
Unsupported host/CGO builds retain a clear error stub, not a fallback to QEMU on PATH.

The startup thread is locked in `init`, and native entry asserts `pthread_main_np()`.
The CGO bridge passes a NULL-terminated, C-allocated argv array and C strings with
`argv[0]` set to `qemu-system-x86_64` or `qemu-img`. The native resource resolver
must use the builtin resource contract, not infer an installation from argv[0].
Each worker invokes C once; native `exit()` is the dedicated subprocess's lifetime.
The Go worker adds no signal.Notify handler and never constructs Cobra or resolves
Lima storage. Native code remains responsible for safely interworking with Go's
runtime signal handlers and must not fork/daemonize or use memory preallocation.

All bundled system/image commands resolve to `os.Executable()` with first argument
`--internal-qemu` or `--internal-qemu-img`, including capability probes, disk creation,
image inspection and the hostagent's VM subprocess. Those flags are intentionally
not Cobra flags and must be first. No Go worker banners are written to stdout.
Daemonization, `-mem-prealloc` and enabled memory-backend `prealloc` properties are
rejected before C entry, including bare boolean properties and dotted global
properties. Explicit `prealloc=off` and disk-image `preallocation=metadata` remain
allowed. The native guard must also enforce its own restrictions, including QMP.

For bundled UEFI, native resources must support `builtin:edk2-x86_64-code.fd` as a
read-only pflash/block filename. Default BIOS, option ROMs and other QEMU resources
must likewise resolve from the native bundle (`builtin:<filename>` contract), with
no external share directory. Legacy BIOS relies on native QEMU's default BIOS
resource resolution. This build rejects guests other than x86_64, even though the
unchanged upstream templates contain other-architecture image alternatives.

Explicit `QEMU_SYSTEM_X86_64` and `QEMU_IMG` commands remain supported, including
shell-quoted prefix arguments; system prefix arguments are passed to capability
probes too. External system QEMU keeps the original filesystem firmware lookup.
Set both overrides when a matched external system/image toolchain is desired.

## Storage and remaining runtime dependencies

The existing lazy foreground storage prompt, default `~/goinfre/lima-home`, saved
`~/goinfre/lima-config.json`, LIMA_HOME precedence, noninteractive behavior and editor
error propagation are unchanged. Persistent image and nerdctl download caches now
live under `<resolved Lima storage>/_cache`, and `prune` uses that same path. The
explicit downloader `WithCacheDir` option still works (empty disables caching).
Old platform caches are left untouched; no automatic migration occurs.

This is a single executable for Lima/QEMU/assets, not an offline VM distribution:
OS images and nerdctl archives may still be downloaded, SSH/SCP and configured
network helpers remain host dependencies, and VM/editor working files remain on disk.
Native QEMU/firmware/dependency licenses and corresponding-source obligations are
separate from the embedded Lima license and must be addressed for distribution.

## Verification handoff

Command-package builds and native integration tests are left to the main agent.
After native linking, run focused tests for `./pkg/embeddedassets`,
`./pkg/templatestore`, `./pkg/iso9660util`, `./pkg/cidata`, `./pkg/qemu/...`, `./pkg/downloader`, `./pkg/store/dirnames`,
`./pkg/editutil`, and `./cmd/limactl`, then the broader suite as appropriate.
The added tests cover asset identity, independent readers, template enumeration,
worker prefixes/JSON, capability stdout/stderr isolation, firmware choice, unsafe
flags, storage-independent worker dispatch, lazy cache/error propagation, and an
ISO round trip with the embedded agent, long/nested names, multi-sector directories,
a deliberately unusable temporary directory, and input-reader failure cleanup.

Final linked-binary smoke checks should include a relocated executable with no
share directory and no QEMU on PATH; help/version/templates/licenses; both internal
help modes with corrupt Lima settings; qemu-img JSON info/create; capability probes;
rejected unsafe flags; and an x86_64 VM UEFI boot, hostagent/QMP stop and restart.
Native thread, signal, resource and exit behavior requires those final linked checks.
