# Licensing and corresponding-source inventory

**Evidence reviewed: 2026-09-15. Release-process update: 2026-09-16. Scope: retained
local single-file executable and source materials; future CI release artifacts
are outside this evidence set.**

This document records component licensing evidence, source provenance, and known
gaps for the retained artifacts. No additional permissions, relicensing, or
exceptions from copyright holders have been established here.

## Current remediation result

The release workflow immediately publishes an experimental prerelease on a
successful `v*` tag build. The evidence below concerns the retained local artifacts:
no effective new third-party permission has been obtained, no incompatible
implementation has been replaced, and no firmware or VARS bytes have been changed.
The single-file design is unchanged.

New evidence and delivered materials:

- [Native linkage inventory](compliance/linkage/README.md): all 783 core archive
  members mapped; 1,407 members across six selected archives checked against
  retained object bytes. There are 152 GPLv2-only **review candidates**, not 152
  proved surviving contributions. Alternate/portion-specific grants and exceptions
  are preserved for review. The complete final ld map/argv and exhaustive
  contribution-level permission determination remain unavailable.
- [Additional notices](compliance/notices/README.md): 48 host modules, host Go
  1.22.12, authentic historical Go 1.19.2, and native/upstream notices, including
  NOTICE/PATENTS: 1,383 notice/context records. File-level coverage remains partial.
- [Firmware source inventory](compliance/firmware/SOURCE-INVENTORY.md): 174 retained
  pc-bios files and all 77 embedded resources; 11 history-supported exact-revision
  source archives acquired. These are source candidates with recorded evidence,
  not complete build closure or UTM EDK2 provenance.
- [Source-delivery package](compliance/source-delivery/README.md): actual pinned
  sources, runtime sources, 52 host/guest module ZIPs, and 283 pinned go.mod records.
  The 406 payload files total 155,568,363 bytes, before firmware and notices.
  Source bytes and recipes are supplied; a modified-library rebuild/relink has
  **not** been demonstrated and recipient permissions for the combination remain
  unsettled.
- [Original-contribution license](LICENSE-ORIGINAL.md): MIT, strictly scoped to
  original project material, excluding third-party code and copied evidence.
- [Publication audit](compliance/publication/README.md): the existing export's
  Git history/index was inspected read-only, together with current source/firmware
  archive contents. Findings remain recorded. It is distinct from
  the separately regenerated candidate and must not be represented as auditing
  a future public commit.

The retained executable and private archives match their build manifest, but its
`source-overlays.json` hash differs from today's manifest. This is a provenance
metadata mismatch, not proof that different source bytes were compiled. Rebuild
or reconcile the exact inputs before associating this source package with a new
binary release. Byte-identical rebuilding is useful evidence, **not a universal
license requirement**.

## Scope and artifact

Release executables are built, tested, checksummed, and published by
`.github/workflows/build.yml` from version tags, rather than supplied from the local
workspace. The inventory below describes the retained local evidence only; its
hash, linkage findings, and validation results must not be represented as an audit
of a future CI-built executable. CI release assets and their checksums are produced
from the tagged revision; this inventory describes the separately identified local
artifact below.

The reviewed executable is `output/limactl`, 81,235,004 bytes, SHA-256:

```text
3a4fe1e0b19879b1e60dbb0fca8ff9be9d47f66260c115c1cd6e01a93b013218
```

It combines Lima 0.13.0, UTM QEMU `v10.0.2-utm`, statically linked native libraries,
Go runtime/modules, embedded firmware, and a separately executed Linux guest agent.
This review used source/license headers, checksum-verified archives and modules,
linker logs, binary symbols/build metadata, and upstream firmware history. It did
not rebuild firmware or demonstrate a modified-library relink.

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
none has been implemented. For the retained single-file design, effective
permissions or complete compatible replacements remain the unresolved route;
separating programs has not been silently substituted.

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

The [guest-agent notice bundle](compliance/guest-agent/README.md) now packages
Lima's LICENSE and the original top-level notices for all nine modules recorded
in the retained Linux agent: 12 notice files in total, including go-libaudit's
NOTICE.txt and x/sys's PATENTS. Module ZIP `h1:` checksums were verified against
the agent build record and `go.sum` before copying. Its manifest records member
paths and SHA-256 identities; offline tests check inventory and retained inputs.
This is a partial notice inventory, not a complete release package. The separate
additional-notices bundle now supplies Go 1.19.2 notices, and source-delivery
supplies its authentic source archive. File-level attribution remains outstanding.

The additional-notices bundle now includes the host/native named-file notices,
including the following upstream NOTICE material. Its documented selection rule
is not a complete contribution-level attribution review:

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

[LICENSE-ORIGINAL.md](LICENSE-ORIGINAL.md) now selects MIT for original
build/audit/integration contributions with an explicit third-party exclusion.
Confirm contributor authority/ownership before release. This does not extend
Lima's license to parent files or resolve third-party incompatibility.

## 3. Firmware corresponding-source coverage

A [repeatable offline archive comparison](compliance/firmware/README.md) now
verifies the locked blob/manifest and QEMU archive, checks every embedded slice,
and records **75 archive matches and two VARS discrepancies** in
`compliance/firmware/archive-comparison.json`. Run `python3 -B audit_firmware.py`;
exit 2 reports the unresolved discrepancies, not successful provenance clearance.
An archive byte match does not supply missing implementation source or a build
attestation. No firmware bytes were changed.

The embedded QEMU payload has **77 resources**: 39 firmware/ROM/variable-store
assets, 34 keymaps, and four notice texts. The aligned blob is 18,886,688 bytes,
SHA-256 `4f4a697785e3e70a6d514d31ae54cd246e4d9aa77a4f8918d0005c20eb90bbf6`.
Per-resource identities are in the
[firmware manifest](src/qemu/util/builtin-resources/manifest.json).

| Group | Evidence and source gap |
| --- | --- |
| SeaBIOS / SeaVGABIOS, 12 images | Embedded version strings match `a6ed6b701f0a57db0569ab98b0661c12a6ec3ff8` (1.16.3). Exact-revision source archive is now supplied, including upstream license texts; complete build dependencies/configuration and accessible firmware notice coverage remain under review. QEMU configuration recipes alone are insufficient. |
| Legacy iPXE, 6 ROMs | Binary history identifies `7aee315f61aaf1be6d2fff26339f28a1137231a5`, not the current submodule pin. Preserve the matching GPLv2 source and historical build configuration. |
| EFI iPXE, 8 ROMs | Binary history matches `4bd064de239dab2426b31c9789a1f4d78087dc63`. Exact-revision source archive is now supplied; effective licenses vary by target. Obtain target-specific license reports and the EDK2 EfiRom build-tool dependency. |
| qboot, 1 image | Binary-update history identifies `8ca302e86d685fa05b16e2b208888243da319941`. Exact-revision GPLv2 source archive is now supplied; build environment/closure remains under review. |
| EDK2 code / VARS, 6 assets | Four code images match the locked QEMU archive, but exact UTM source/patch/configuration provenance is unresolved. Two VARS assets differ from or are absent in that archive; see below. |
| QEMU option ROMs, 6 images | Implementation sources and recipes are present in `pc-bios/optionrom/` and `scripts/signrom.py`; exact compiler/binutils reproduction of prebuilts was not verified. |
| Keymaps, 34 text assets | Match the locked archive. Generator and text inputs are retained, but XKB/libxkbcommon regeneration versions are not pinned. Review data provenance separately from the generator license. |

`sources.lock.json` fetches Lima, QEMU, libslirp, keycodemapdb, SoftFloat, and
TestFloat. It **does not fetch firmware submodule sources**. The QEMU archive has
no implementation source inside `roms/seabios`, `roms/ipxe`, `roms/qboot`, or
`roms/edk2`. Separately supplied archives are now frozen under
`compliance/firmware/sources/`; their acquisition lock/catalog records exact
revisions and the strength/limits of each association. They are not automatically
installed as current submodules. `.gitmodules` alone is not source delivery.

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
are now included in the retained-file/source-candidate inventory. Specific gaps
remain for OpenBIOS, U-Boot, NPCM, historical dependencies and generated NVRAM;
the x86 table above is not a clearance for them.

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
The nine modules' top-level notices are now packaged under
`compliance/guest-agent/`; historical runtime notices and source are now in the
additional-notices and source-delivery packages respectively.

Native override sources and hashes are retained in `native/`. Their complete
transformation also depends on `link_lima.py` (diagnostic transformations, flags,
entry-point renaming, archive replacement, constructor retention, and CGO linking).
Keep all locks, overlays, bootstrap/preparation/build/link scripts, not just
pristine QEMU or the override files, in any applicable source-delivery package.

## 5. Outstanding licensing and source-compliance work

| Area | Findings / remaining work |
| --- | --- |
| Combined-work permission compatibility | **UNRESOLVED:** no demonstrated compatible permission route for the current Apache-2.0 / GPLv2-only link. The single-file design is retained; qualified review and effective permissions or compatible component replacements remain necessary. |
| Firmware source and provenance | **INCOMPLETE:** supply matching source closure/build details, resolve EDK2/VARS, and review all exported firmware. |
| Notices and modification notices | **PARTIAL:** guest/host module and both runtime notice selections are packaged; native named-file/selected header notices are supplied. Full file-level/firmware attribution and dated modification notices remain incomplete. Original contributions now have an explicit MIT scope. |
| Actual source-delivery method | **PARTIAL DELIVERY:** actual pinned source bytes, overlays, build/install scripts and a manual relinking recipe are packaged. A recipient-modified-library rebuild/relink, complete closure, and applicable permissions remain unverified. |
| Portable firmware-authoring documentation | **FIXED:** optional commands now use `./firmware-assets`; normal builds need no external firmware directory. |
| Publication payload integrity | Hash/allowlist, source reconstruction, and targeted credential checks record payload integrity. |
| Git-staged inventory | For a manifest-based export, compare the exact staged candidate with its publication manifest and record the result in the local audit. |

The local exporter now includes the guest and additional notice bundles,
firmware sources/evidence, linkage inventory, actual source-delivery package,
publication audit and tests through explicit hash-verified selections. Use a new
`--name` and an empty matching output directory to preserve earlier exports.
The separate `output/source-publication-review-20260915` candidate is not the
existing Git export or a public commit. Its external manifest/audit and validation
results describe that candidate only; generating it did not modify the original
repository.

Local publication tooling is retained outside the export under `output/`.
`audit-publication-index.py` compares exact staged paths, blob SHA-256 contents,
symlink targets, and executable modes against `source-publication-manifest.json`.
It reports pending, not passed, when no export repository exists. Required pinned
inputs must not be silently omitted because an upstream nested ignore rule
matches them. Never stage the original workspace's VM state, keys, or build caches.
