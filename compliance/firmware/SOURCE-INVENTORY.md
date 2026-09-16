# Retained firmware sources and build evidence

**Status: incomplete; no firmware rebuilt, replaced, or cleared.** This review
adds to, and does not supersede, `archive-comparison.json` or the release gates.
It examines the actual local `src/qemu/pc-bios` tree, including non-x86 blobs,
not merely the embedded x86 resource manifest. It is not an audit of a newly
exported/staged publication. The root has no Git history; remote evidence is
preserved explicitly rather than presented as local history.

## Reproduce and interpret the evidence

From the project root:

```sh
python3 -B compliance/firmware/acquire.py
python3 -B compliance/firmware/inventory.py --check
python3 -B -m unittest discover -s tests -p 'test_firmware*.py'
```

The first command verifies frozen source archives and upstream responses without
network access. The second regenerates the evidence in memory, including the
original embedded-resource audit, and compares it to `retained-inventory.json`.
Exit 0 on these verification commands means **evidence consistency only**.
Running `inventory.py` without `--check` prints deterministic JSON and exits 2
because source/redistribution gates remain open; exit 1 indicates invalid inputs.
Neither program extracts or executes downloaded source or alters firmware.

- `retained-inventory.json`: every regular retained `pc-bios` file, its size and
  SHA-256, locked-archive comparison, decompressed identity for bz2 firmware,
  historical Git blob comparisons where available, all 77 embedded resources,
  the two VARS discrepancies, and recipe file hashes.
- `source-catalog.json`: group-level evidence, acquired candidate source links,
  current gitlinks **labeled candidates only**, and remaining blockers.
- `acquisition-lock.json`: exact HTTPS URLs, retrieved sizes, SHA-256, archive
  roots/full revisions, required source members and their hashes. Hashes were
  observed on initial acquisition, **not** checked against an independent signed
  upstream checksum. Tar PAX commit comments agree with the requested revisions;
  those comments are not cryptographic proof of source/binary correspondence.
- `evidence/`: raw bounded GitHub API responses. Commit file-list Git blob hashes
  are compared with retained bytes; historical update messages and same-tree
  gitlinks corroborate candidate revisions but are not build attestations.
- `sources/`: original unmodified exact-commit GitLab archives. No source trees
  were installed into QEMU's empty submodule directories.

`python3 -B compliance/firmware/acquire.py --fetch` is an **opt-in network**
command that reacquires only missing archives from their locked URLs, checks
size/hash before installing them, and refuses to replace an existing differing
file. It needs Python 3.10+ and curl; requests have 15-second connection and
90-second transfer limits, with byte caps equal to the recorded archive sizes.
It does not clone repositories or refresh changing API responses. It shares the
caller's network policy, contacts GitLab, and makes no paid API calls. Initial
requests were capped at 12 MiB per small source archive, 32 MiB for EDK2, and
2 MiB per metadata response. No toolchain or large U-Boot archive was downloaded.

Local-first inspection found only the QEMU archive and copies of its retained
blobs, not independent SeaBIOS/iPXE/qboot/EDK2 implementation sources. The
`downloads/`, `cache/`, and matching archive paths under `build/`, `tmp/`,
`output/`, and `prefix/` were checked before network acquisition.

## Acquired revisions and strength of association

| Source | Exact archive revision | Supporting evidence and limit |
| --- | --- | --- |
| SeaBIOS/SeaVGABIOS | `a6ed6b701f0a57db0569ab98b0661c12a6ec3ff8` | All 12 images carry matching 1.16.3 commit/version strings; no rebuild. |
| Legacy iPXE | `7aee315f61aaf1be6d2fff26339f28a1137231a5` | Six blobs match the 2011 refresh; same-tree pin and binary version agree. Not the current pin. |
| EFI iPXE | `4bd064de239dab2426b31c9789a1f4d78087dc63` | Eight blobs match the EFI update; historical pin/recipe preserved. |
| qboot | `8ca302e86d685fa05b16e2b208888243da319941` | Binary matches update explicitly describing rebuild from this revision. |
| EDK2 for EfiRom | `20d2e5a125e34fc8501026613a71549b2a1a3e54` | EDK2 pin at EFI iPXE update; **build-tool candidate only, not UTM firmware source**. |
| SLOF | `ee03aec2c106a699aaddd2d3dd52cbd7b7e8d544` | Matching standalone blob update changes source to this revision/tag qemu-slof-20241106. Locked pin `3a259df…` differs. |
| SeaBIOS-hppa | `1c516b481339f511d83a4afba9a48d1ac904e93e` | Both v18 images match update changing source to this revision. Locked pin `3391c58…` differs. |
| OpenSBI | `43cace6c3671e5172d0df0a8963e552bb04b7b20` | Both generic images match v1.5.1 update and source change. |
| skiboot | `785a5e3070a86e18521e62fe202b87209de30fa2` | Byte-identical 7.1-106 image update and source change. |
| Alpha palcode | `99d9b4dcf27d7fbcbadab71bdc88ef6531baf6bf` | Byte-identical update with matching source change. |
| QemuMacDrivers | `90c488d5f4a407342247b9ea869df1c2d9c8e266` | Byte-identical driver update explicitly names source and changes gitlink. |

An archive contains source files, not Git history/tags or necessarily nested
submodules. The EfiRom-era EDK2 `.gitmodules` declares OpenSSL and SoftFloat;
those implementations are not supplied by that EDK2 archive. They are not
established as EfiRom dependencies: its GNUmakefile links `Common`, whose sources
include its own EFI/Tiano compression code. Full EDK2 firmware closure is a
separate, unresolved task. Non-x86 acquired archives have not undergone complete
nested/build dependency review. License files remain inside original archives;
this is **not** a new notice bundle or a blanket license determination.

## Concrete build recipes and dependency evidence

These are documented recipes, **not executed builds**. Run experiments only in
an isolated scratch tree. QEMU `roms/Makefile` targets copy results over
`pc-bios`; do not invoke them on retained firmware without a separately approved
replacement plan. Prefix names below denote environment choices, not pinned
historical packages.

### SeaBIOS and nine VGA variants

The retained recipe uses `config.seabios-128k`, `-256k`, `-microvm` and
`config.vga-{stdvga,cirrus,vmware,qxl,isavga,virtio,bochs-display,ramfb,ati}`.
For each it copies the config, runs `oldnoconfig`, then `all` with
`KCONFIG_CONFIG`, `OUT`, `CROSS_PREFIX` and
`EXTRAVERSION=-prebuilt.qemu.org`; `bios`/`vgabios` install 12 outputs.
The source Makefile specifies GNU make, a host compiler, x86 GCC/binutils,
Python scripts, and IASL environment checks in `scripts/test-build.sh`.

All 12 images report GCC `13.2.1 20230728 (Red Hat Cross 13.2.1-1)` and
binutils `2.40-3.fc39`. Obtain those actual packages and dependencies, preserve
final generated configs, and reproduce the version
`rel-1.16.3-0-ga6ed6b701f0a-prebuilt.qemu.org` using verified buildversion inputs.
A source tar without Git tags/history may generate a different version string.

### Legacy versus EFI iPXE

Historical legacy recipe is the complete added `scripts/refresh-pxe-roms.sh`
patch in `evidence/ipxe-legacy-update.json`. In `src/config/local/general.h` it
sets `BANNER_TIMEOUT=0` and `PRODUCT_NAME` from `git describe --tags`, corroborated
by binary string `iPXE v1.0.0-591-g7aee315`. It builds these six `bin/ID.rom` targets:

| NIC | PCI ID |
| --- | --- |
| e1000 | `8086100e` |
| eepro100 | `80861209` |
| ne2k_pci | `10500940` |
| pcnet | `10222000` |
| rtl8139 | `10ec8139` |
| virtio | `1af41000` |

Do not replace that recipe with modern `CONFIG=qemu`. The EFI recipe, preserved
as base64 file content in `evidence/ipxe-efi-makefile.json`, does use
`CONFIG=qemu` and adds e1000e `808610d3` and vmxnet3 `15ad07b0`. It builds both
`bin/ID.rom` and `bin-x86_64-efi/ID.efidrv` at the EFI revision, then combines them:

```text
EfiRom -f 0xVENDOR -i 0xDEVICE -l 0x02 -b LEGACY.rom -ec X64.efidrv -o OUTPUT.rom
```

These combined ROMs are not EFI-only images; their legacy portion is not the
separately retained 2011 legacy ROM. Historical BaseTools recipe is
`make -C edk2/BaseTools PYTHON_COMMAND=python3`, with
`EXTRA_OPTFLAGS`/`EXTRA_LDFLAGS` supplied via `EDK2_BASETOOLS_*` variables.
`EfiRom/GNUmakefile` links Common; full BaseTools also builds other utilities
and a VfrLexer prerequisite. The iPXE Makefiles use GNU make, host GCC,
cross GCC/binutils and Perl. Exact compiler versions, flags, Git-derived
version inputs and BaseTools provenance still need a build record.

For the EFI revision, `src/Makefile.housekeeping` implements per-target
`bin/ID.licence` and `bin-x86_64-efi/ID.licence` (and `.licence_list`) using
linked `.tmp` objects, `nm` symbols and `src/util/licence.pl`. Generate reports
for **both halves of all eight actual targets** and preserve the linker input
lists. No reports were generated here and no target-wide license conclusion is
inferred from `COPYING`, `COPYING.GPLv2` or `COPYING.UBDL` alone.

### qboot

At the supplied revision: `meson setup build` then `ninja -C build` produces
`build/bios.bin` (64 KiB). `meson.build` specifies Meson >=0.49.0, `objcopy`,
x86 `-m32 -march=i386 -mregparm=3`, freestanding compilation, no stack protector,
no PIC, `-nostdlib`, `flat.lds`, and supported no-PIE/no-build-ID linker flags.
A GNU-compatible x86 compiler/binutils environment is required; the macOS
native build dependencies do not establish that environment. Pin the actual
Meson/Ninja/compiler versions and reproduce before claiming a build match.

## UTM EDK2 and VARS: evidence still required

Eight retained compressed members match UTM replacement commit
`361d160a6894dc9b206b2699533960762763f370`: AArch64 normal/secure code, ARM VARS,
i386 normal/secure code and VARS, x86_64 normal/secure code. Matching these bytes
proves the replacement's identity, **not the source used to create it**.

The replacement tree's EDK2 gitlink is
`edc6681206c1a8791981a2f911d2fb8b3d2f5768`; locked QEMU uses
`4dfdca63a93497203f197ec98ba20e2327e4afe4`. README says stable202302 while
`roms/edk2-version` says stable202408. None is accepted as exact UTM provenance.
The separately acquired 2019 EfiRom tool source must not be substituted.

The retained **reference** config names OvmfPkgIa32.dsc, OvmfPkgX64.dsc,
MicrovmX64.dsc, ArmVirtQemu.dsc, RiscVVirtQemu.dsc and LoongArchVirtQemu.dsc.
Common flags include HTTP/IP6/TLS/iSCSI/TPM; secure x86 sets
`SECURE_BOOT_ENABLE=TRUE`, `SMM_REQUIRE=TRUE`, `BUILD_SHELL=FALSE`.
ARM/AArch64 use the broken-shim/grub NX PCD profile. ARM code/VARS are padded
to 64 MiB, AArch64 code to 64 MiB, RISC-V code/VARS to 32 MiB, and LoongArch
code/VARS to 16 MiB. There is **no AArch64 secure build stanza**, despite that
retained asset, and no secure i386 VARS copy rule. This config is not asserted
to describe the UTM images. Other retained ARM, RISC-V, LoongArch and microvm
EDK2 files need their own build/source associations too.

Obtain from the UTM firmware producer:

1. Actual source repository and immutable revision for each target, including
   fork changes, patch series, submodule/nested source revisions and checksums.
2. DSC/FDF selections, PCDs, defines, debug/release and toolchain tags, secure-boot,
   SMM/TPM/network options, flash geometry, CODE/VARS split, pad/compress steps,
   version/date inputs and environment/container/toolchain package identities.
3. Full build and packaging logs and SHA-256 output list tying those inputs to
   each retained file, followed by reproduction and target-specific notice review.
4. Original and transformed VARS inputs: generator/provisioning tool revision,
   transformations, enrollment/default settings (PK/KEK/db/dbx where applicable),
   variable-store/authentication format, sizes/offsets and the firmware pair used.
   Review any nonpublic enrollment data before publishing it.

| Embedded VARS | Actual bytes / SHA-256 | Locked QEMU evidence |
| --- | --- | --- |
| `edk2-i386-vars.fd` | 328,704 / `a5c722949ba13c60b08c1ad3507ef751424941781f66d529f5f1feded8320ccb` | Decompressed archive is 335,360 / `be0b35d7b31ca9b66bd634c6145480debf59502692d2a99144002d4d43be4b65`; differs. |
| `edk2-i386-secure-vars.fd` | 340,992 / `8686f255ecea2a07803f4eb9c0481778d651267e20688466a2c265980db3ca85` | No archive member. |

Do not clear these by renaming, padding, trimming, copying a current template,
or accepting a gitlink. Replacement requires a deliberate approved approach,
revalidated flash layout/secure boot/boot behavior, regenerated resource
manifests/locks and fresh provenance. Nothing here modifies these assets.

## Additional retained, non-x86 scope

The catalog and generated inventory enumerate the entire tree, including assets
outside the install list (for example microvm EDK2), support sources, descriptor
JSON, keymaps and installer artwork. Important remaining distinctions:

- **OpenBIOS:** UTM PPC screamer-support build needs its actual fork/patches;
  SPARC32/SPARC64 and the two FCode display blobs need separate revision/build
  evidence. README SVN r1280 and the current gitlink are insufficient.
- **SLOF/HPPA/OpenSBI/skiboot/palcode/Mac drivers:** historical source candidates
  are supplied; actual configurations, architecture toolchains, SDKs, nested
  dependencies and builds remain unverified. Current SLOF/HPPA pins are wrong
  substitutes for the history-supported binary source candidates.
- **U-Boot e500:** blob history supports v2021.07 at
  `840658b093976390e9537724f802281c9c8439f5`, not README `2072e72`.
  The update records the GCC 10.1.0 nolibc PowerPC toolchain URL. Sources and
  larger toolchain download remain deferred; hashes and dependency closure needed.
- **U-Boot Sam460:** binary says 2010.06.05 but carries a 2018 build date.
  The latest path-history result is only a mode change and its API blob hash
  does not match this retained file; actual update/source provenance remains open.
- **NPCM7xx/8xx:** current ARM/AArch64 build recipes exist, and NPCM8xx matches
  its introduction; actual source revision/configuration for each is still needed.
- **s390-ccw:** QEMU implementation exists but builds in SLOF libc/libnet.
  Determine the historical SLOF revision for this image, not the standalone
  SLOF image's revision. Its binary records GCC 14.2.1 Red Hat 14.2.1-6.
- **VOF:** implementation exists, but historical PowerPC build not reproduced.
  `vof-nvram.bin` has a separate unresolved state-generation provenance.
- **PowerNV NVRAM:** README gives `ffspart -s 0x1000 -c 34` with input lines
  `NVRAM,0x01000,0x00020000,,,/dev/zero` and
  `VERSION,0x21000,0x00001000,,,/dev/zero`, followed by one skiboot boot.
  Exact tool revision, boot environment and initialized state remain unrecorded.
- **Four DTBs:** paired DTS sources and `dtc` command exist; dtc version and
  reproduction are unverified. QEMU option-ROM sources likewise are not proof
  of historical compiler/configuration matching. Keymap data/generator provenance
  remains distinct from the generator's own license.

This work does not change publication allowlists/exports, root audit code,
firmware bytes, resource locks, linkage policy or notice bundles. Publication
owners must deliberately include these new evidence/source files and review the
resulting source-delivery and notice obligations; this directory alone does not
select or fulfill a legal source-delivery method.
