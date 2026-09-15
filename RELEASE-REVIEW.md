# Release licensing and corresponding-source review

**Reviewed: 2026-09-15. Release decision: HOLD.**

This is an engineering inventory of licensing evidence and release gaps, not legal
advice or clearance. Passing functional tests, publishing source, or providing
checksums does not by itself authorize redistribution. No additional permissions,
relicensing, or exceptions from copyright holders have been established here.

## Scope and artifact

The reviewed executable is `output/limactl`, 81,235,004 bytes, SHA-256:

```text
3a4fe1e0b19879b1e60dbb0fca8ff9be9d47f66260c115c1cd6e01a93b013218
```

It combines Lima 0.13.0, UTM QEMU `v10.0.2-utm`, statically linked native libraries,
Go runtime/modules, embedded firmware, and a separately executed Linux guest agent.
This review used source/license headers, checksum-verified archives and modules,
linker logs, binary symbols/build metadata, and upstream firmware history. It did
not rebuild firmware or establish bit-identical corresponding-source reproduction.

The publication export is a **source distribution with prebuilt inputs**, not a
binary-free archive: firmware, ROMs, and the guest agent remain required inputs.
The export also retains non-x86 firmware from the QEMU reference snapshot; its
redistribution scope is broader than the x86 executable inventory below.

## 1. Verified combined-work license conflict

| Evidence | Finding |
| --- | --- |
| [Lima LICENSE](src/lima/LICENSE) | Apache-2.0. |
| [QEMU LICENSE](src/qemu/LICENSE) | QEMU as a whole is GPL version 2; individual file grants control. Unmarked files have a version-2-or-later default, not a blanket later-version grant for every file. |
| [Virtqueue mapping](src/qemu/hw/virtio/iothread-vq-mapping.c) | Explicit `SPDX-License-Identifier: GPL-2.0-only`. |
| [HVF implementation](src/qemu/accel/hvf/hvf-accel-ops.c) | Explicit GNU GPL version 2 grant without an "or later" option; also preserves NetApp BSD notices. |
| [Socket utilities](src/qemu/util/qemu-sockets.c) | Older contributions are GPLv2-only; later-version permission for contributions after 2012-01-13 does not relicense the older code. |
| [Native linker](link_lima.py) | Builds and force-loads the QEMU aggregate archive into the Go executable. Archive logs and final symbols confirm the virtqueue-mapping and HVF implementations are linked. |

The [FSF license list](https://www.gnu.org/licenses/license-list.html#apache2) and
[Apache compatibility guidance](https://www.apache.org/licenses/GPL-compatibility.html)
describe Apache-2.0 as incompatible with GPLv2, while distinguishing GPLv3
compatibility. [GPLv2](src/qemu/COPYING) sections 2(b) and 6 impose whole-work and
no-additional-restrictions conditions. Multiple linked Go modules, not just Lima,
also use Apache-2.0.

**Do not distribute this combined executable on the assumption that source
publication, an Apache label, a GPLv3 label, or private worker command-line flags
resolve the conflict.** Disabling HVF alone does not remove all GPLv2-only code.
The legal classification of the integration and any alternative permission route
require qualified review. Possible engineering directions include genuinely
separate programs, or replacing/relicensing every relevant incompatible component;
none has been selected or implemented.

Independently licensed sources and separable patches can coexist as an aggregate,
but an integrated derivative does not automatically become exempt because it is
distributed in source form. Review the actual publication arrangement.

## 2. Native and Go notice/compliance inventory

| Component | Inspected license terms and remaining work |
| --- | --- |
| GLib 2.66.8 | LGPL-2.1-or-later. Static linking requires an applicable source/relinking compliance route, notices, and modification/reverse-engineering permissions; see LGPL section 6. |
| proxy-libintl 0.1 | GNU Library GPL version 2 or later (LGPL-2.0-or-later). Its stub implementation is still linked and has separate obligations. |
| libslirp 4.9.1 | BSD-3-Clause and MIT portions; preserve individual copyrights and binary-distribution notices. |
| zlib 1.3.1 | zlib license; retain required source notices and mark altered source. An acknowledgment is appreciated, not a mandatory advertising clause. |
| Go runtime | BSD-3-Clause license and separate `PATENTS` grant; include applicable notices. |
| Host Go modules | Apache-2.0, BSD/MIT/ISC-style terms, and MPL-2.0 among the inspected modules. Hashicorp errwrap and go-multierror have MPL-2.0 terms; their secondary-license provisions require review rather than treating MPL as an automatic incompatibility. |
| Build-only inputs | Merely appearing in a lock file does not prove linkage. Inclusion of libffi/PCRE implementations in the binary was not established by the symbol review; compiler/build-tool licenses must be assessed according to actual redistribution. |

Binary metadata identified 48 host modules and nine guest-agent modules, 52 unique
modules. Their pinned module hashes and top-level license/header evidence were
reviewed; this is not a complete file-level attribution inventory for every copied
fragment, generated table, or transitive native contribution.

Prepare an actual notice bundle, including applicable upstream NOTICE material:

- `github.com/containerd/containerd@v1.6.9/NOTICE`
- `github.com/coreos/go-semver@v0.3.0/NOTICE`
- `google.golang.org/grpc@v1.47.0/NOTICE.txt`
- `github.com/elastic/go-libaudit/v2@v2.3.2/NOTICE.txt` for the guest agent

`limactl licenses` currently exposes only the embedded Lima LICENSE and NOTES; it
is **not** the full native/module notice interface. Notices embedded somewhere in
a firmware blob are not automatically a complete, accessible notice package.

Audit modified files for Apache-2.0 section 4(b) change notices and GPLv2 section
2(a) change notices/dates. Hash manifests preserve provenance but are not an
automatic substitute for notices required on modified files.

There is no root license explicitly covering all new build/integration scripts.
The copyright holders must choose and document the scope of permissions for their
original contributions. Do not silently extend `src/lima/LICENSE` to parent files
or attempt to resolve third-party incompatibility with a new blanket license.

## 3. Firmware corresponding-source coverage

The embedded QEMU payload has **77 resources**: 39 firmware/ROM/variable-store
assets, 34 keymaps, and four notice texts. The aligned blob is 18,886,688 bytes,
SHA-256 `4f4a697785e3e70a6d514d31ae54cd246e4d9aa77a4f8918d0005c20eb90bbf6`.
Per-resource identities are in the
[firmware manifest](src/qemu/util/builtin-resources/manifest.json).

| Group | Evidence and source gap |
| --- | --- |
| SeaBIOS / SeaVGABIOS, 12 images | Embedded version strings match `a6ed6b701f0a57db0569ab98b0661c12a6ec3ff8` (1.16.3). Corresponding implementation source is absent; LGPLv3 and accompanying GPLv3 license texts need appropriate inclusion. QEMU configuration recipes alone are insufficient. |
| Legacy iPXE, 6 ROMs | Binary history identifies `7aee315f61aaf1be6d2fff26339f28a1137231a5`, not the current submodule pin. Preserve the matching GPLv2 source and historical build configuration. |
| EFI iPXE, 8 ROMs | Binary history matches `4bd064de239dab2426b31c9789a1f4d78087dc63`. Source is absent; effective licenses vary by target. Obtain target-specific license reports and the EDK2 EfiRom build-tool dependency. |
| qboot, 1 image | Binary-update history identifies `8ca302e86d685fa05b16e2b208888243da319941`. GPLv2 source is absent; matching build environment remains to be supplied. |
| EDK2 code / VARS, 6 assets | Four code images match the locked QEMU archive, but exact UTM source/patch/configuration provenance is unresolved. Two VARS assets differ from or are absent in that archive; see below. |
| QEMU option ROMs, 6 images | Implementation sources and recipes are present in `pc-bios/optionrom/` and `scripts/signrom.py`; exact compiler/binutils reproduction of prebuilts was not verified. |
| Keymaps, 34 text assets | Match the locked archive. Generator and text inputs are retained, but XKB/libxkbcommon regeneration versions are not pinned. Review data provenance separately from the generator license. |

`sources.lock.json` fetches Lima, QEMU, libslirp, keycodemapdb, SoftFloat, and
TestFloat. It **does not fetch firmware submodule sources**. The QEMU archive has
no implementation source inside `roms/seabios`, `roms/ipxe`, `roms/qboot`, or
`roms/edk2`; the local firmware submodule directories are empty. `.gitmodules`
contains URLs, not the missing source or all required revision records.

Current firmware gitlinks at the locked QEMU commit are documented by the
[upstream ROM-directory metadata](https://api.github.com/repos/utmapp/qemu/contents/roms?ref=37ba092d59aff24900dfd0d5e01d4ed68441ba07).
Fetching those pins alone still misses legacy iPXE and does not establish the UTM
EDK2 build source. Relevant binary history:

- [Legacy iPXE update](https://github.com/utmapp/qemu/commit/36d8d02dc8c45780cae74e2ba7a6135b95c16f81)
- [EFI iPXE update](https://github.com/utmapp/qemu/commit/3e570a9ae9b966362596fd649f2cbcff0b2199c9)
- [qboot update](https://github.com/utmapp/qemu/commit/2fc7eb689704687f890688507e15bbbe71275f63)
- [UTM firmware replacement](https://github.com/utmapp/qemu/commit/361d160a6894dc9b206b2699533960762763f370)

### Unresolved EDK2 provenance

- Embedded `edk2-i386-vars.fd` is 328,704 bytes, versus 335,360 bytes after
  decompressing the locked archive's version; the contents differ.
- Embedded `edk2-i386-secure-vars.fd` is 340,992 bytes and has no corresponding
  member in that archive.
- The pc-bios README names stable202302; `roms/edk2-version` names stable202408.
  Neither establishes the exact source of the UTM replacement images.
- The replacement commit's EDK2 gitlink was `edc6681206c1a8791981a2f911d2fb8b3d2f5768`;
  the current locked tree's gitlink is `4dfdca63a93497203f197ec98ba20e2327e4afe4`.
  These are **not** substituted for missing build attestations.
- The embedded EDK2 license bundle contains BSD, MIT, SoftFloat and historical
  OpenSSL/SSLeay notices; their completeness for the actual replacement builds
  requires verification. Nested source closure must follow the actual revision
  and targets, not an arbitrary current checkout.

Obtain the matching build records and sources, or deliberately replace unresolved
inputs with reviewed source-built assets and revalidate behavior. A checksum
establishes byte identity, not corresponding-source completeness.

The retained source export additionally includes unembedded/non-x86 firmware
(OpenBIOS, OpenSBI, SLOF, skiboot, U-Boot, and others). Those binary/source pairs
also need review if distributed; the x86 table above is not a clearance for them.

## 4. Guest agent and native reconstruction

The embedded Linux guest agent is 7,135,232 bytes, SHA-256:

```text
b10989ec96ac40392b4d49494577fe308de8d6e734c5024722be82cdd29c464c
```

Its Go build record identifies Go 1.19.2, Linux/amd64, `CGO_ENABLED=0`, Lima commit
`6b6073ff536ea3ae7605129489a33ed2ba11fc46`, an unmodified VCS tree, and version
`v0.13.0`. That commit matches the locked Lima archive. Nine recorded dependencies
match `go.sum`: go-libaudit, mux, logrus, cobra, pflag, native_endian, atomic,
multierr, and x/sys. No module-level incompatibility was identified within the
agent itself; required notices still apply.

The root build copies this prebuilt input; it does not rebuild it. The upstream
recipe exists, but the host toolchain pin is Go 1.22.12, not 1.19.2, and exact
reproduction was not tested. Record a supported rebuild recipe and supply the
module and Go-runtime notices; Lima's Apache text alone does not cover them all.

Native override sources and hashes are retained in `native/`. Their complete
transformation also depends on `link_lima.py` (diagnostic transformations, flags,
entry-point renaming, archive replacement, constructor retention, and CGO linking).
Keep all locks, overlays, bootstrap/preparation/build/link scripts, not just
pristine QEMU or the override files, in any applicable source-delivery package.

## 5. Release gates

| Gate | Status / next action |
| --- | --- |
| Combined-work permission compatibility | **BLOCKED:** no demonstrated compatible route for the current Apache-2.0 / GPLv2-only link. Obtain qualified advice and select a permission or architecture remedy. |
| Firmware source and provenance | **INCOMPLETE:** supply matching source closure/build details, resolve EDK2/VARS, and review all exported firmware. |
| Notices and modification notices | **INCOMPLETE:** assemble complete component notices; audit file-level change notices and original-code license scope. |
| Actual source-delivery method | **UNSELECTED:** implement the applicable GPL/LGPL source/relinking method; upstream URLs alone are not proof of fulfillment. |
| Portable firmware-authoring documentation | **FIXED:** optional commands now use `./firmware-assets`; normal builds need no external firmware directory. |
| Publication payload integrity | Hash/allowlist, source reconstruction, and targeted credential checks are engineering controls, not licensing clearance. |
| Git-staged inventory | **REQUIRED PER REVISION:** compare the exact staged candidate with the publication manifest before pushing and record the result in the local audit. An index match or private CI run does not clear the licensing release hold. |

Local publication tooling is retained outside the export under `output/`.
`audit-publication-index.py` compares exact staged paths, blob SHA-256 contents,
symlink targets, and executable modes against `source-publication-manifest.json`.
It reports pending, not passed, when no export repository exists. Required pinned
inputs must not be silently omitted because an upstream nested ignore rule
matches them. Never stage the original workspace's VM state, keys, or build caches.
