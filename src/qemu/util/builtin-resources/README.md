# Memory-backed x86 firmware for single-file Lima

## Generate and build

These optional resource-authoring commands require the matching firmware inventory
in a `firmware-assets/` directory under this QEMU source root (or substitute your
own inventory directory). Ordinary single-file builds use the checked-in payload;
run `python3 build.py` from the project root instead.

```sh
python3 scripts/gen-builtin-resources.py --asset-dir ./firmware-assets
python3 util/builtin-resources/test.py --asset-dir ./firmware-assets
```

Generated inputs are checked into/copied with the source tree. Normal QEMU
configure/Meson/Ninja builds require no asset directory and no generator run.
After the main agent configures its build directory, `ninja -C BUILD_DIR
qemu-system-x86_64 qemu-img qemu-io` includes these resources automatically.
This change does not configure or run that full build.

`util/meson.build` adds the registry, `.incbin` assembly, and file-content adapter
to `libqemuutil.a`. `block/meson.build` adds `builtin.c` unconditionally to
`block_ss`; it is not an optional module. Normal QEMU links extract all libblock
objects, retaining `block_init(bdrv_builtin_init)`. The later Go archive must
include the objects from libblock and libqemuutil and force-load that aggregate
archive (Darwin `-Wl,-force_load,<archive>`), retaining QEMU module constructors.
The driver references the registry, which references the single immutable blob.
No asset path is consulted at runtime, and no firmware is extracted to files.
The assembly supports Darwin and ELF hosts. Windows assembly is not supported.

## Public API

`include/qemu/builtin.h` is libc-only. `qemu_builtin_lookup()` accepts an exact
resource name (a basename or `keymaps/<layout>`) or `builtin:<name>`,
returning a process-lifetime
`const QemuBuiltinResource *` (`name`, `const uint8_t *data`, `size_t size`), or
NULL. Never free or modify this storage. `qemu_builtin_is_uri()` recognizes the
prefix even for unknown names. `qemu_builtin_count()` and `qemu_builtin_at()`
enumerate the immutable table, including license notices; an out-of-range index
returns NULL. Matching is case-sensitive, with no URI decoding/path stripping.

`include/qemu/resource.h`: `qemu_resource_get_contents(filename, contents,
length, error)` has GLib `g_file_get_contents()` ownership/error/NUL-termination
semantics. URIs copy embedded bytes to caller-owned RAM; non-URIs use the original
file reader. Unknown URIs fail without trying to open a fake host filename.

## Lookup and x86 loader coverage

- `qemu_find_file(BIOS, ...)` preserves existing direct-file and data-directory
  precedence, then tries an exact built-in basename. Explicit `builtin:` URIs
  bypass all filesystem searches. Missing explicit paths are never stripped to
  a basename. Keymaps use the same precedence with the `keymaps/` namespace;
  `-k en-us` falls back to embedded data, and `-k builtin:keymaps/en-us`
  explicitly selects it without filesystem access. Missing custom paths never
  fall back to their basename. The keymap parser reads a memory buffer (also
  for external files), retaining the original bounded line-parsing behavior.
- `get_image_size()` and `load_image_size()` read URI bytes directly. This covers
  x86 BIOS sizing and SEV direct loading, PCI ROM BARs (including ROM ID patching
  in their mutable guest-memory copies), and physical-memory/image-MR loaders.
- `rom_add_file()` uses the content adapter. This covers BIOS reset registration,
  ISA VGA, option ROMs, legacy PCI fw_cfg ROM loading, vapic, Linux, multiboot,
  and PVH boot ROMs. fw_cfg filenames strip the URI prefix, preserving names
  such as `genroms/linuxboot.bin`.
- fw_cfg splash/image reads and the gzip-buffer loader use the same adapter.
- pc/q35 default `bios-256k.bin`, isapc `bios.bin`, and microvm `qboot.rom` /
  `bios-microvm.bin` were traced in the actual machine sources.
- Pflash uses the new block protocol through its existing block backend, with
  no changes to flash-device implementation or the qemu-img entry point.
- All 34 bundled keymaps are embedded unchanged. Guest kernels, initrds,
  disks, and custom firmware paths are not embedded by this patch. ELF/a.out loaders are not generalized virtual files.

## Runtime checks for the main agent

Use the built executables in an empty working directory with no installed
firmware/datadir available (and an empty directory passed to `-L`).

```sh
qemu-img info -f raw builtin:edk2-x86_64-code.fd
qemu-img info --image-opts driver=raw,file.driver=builtin,file.filename=builtin:edk2-x86_64-secure-code.fd,file.read-only=on
qemu-io -r -f raw -c 'read 0 512' -c 'read 3653120 512' builtin:edk2-x86_64-code.fd
qemu-io -f raw -c 'write 0 512' builtin:edk2-x86_64-code.fd
qemu-img info builtin:missing.fd
```

The last two commands must fail. Also test QMP `blockdev-reopen` with read-only
false (must fail), arbitrary/unaligned reads, EOF handling, and pflash:

```sh
qemu-system-x86_64 -machine q35 -accel tcg -display none -S -nodefaults -drive if=pflash,unit=0,format=raw,readonly=on,file=builtin:edk2-x86_64-code.fd
```

The supported structured pflash form is:

```sh
qemu-system-x86_64 -machine q35,pflash0=fw -accel tcg -display none -S -nodefaults -blockdev driver=builtin,node-name=fw,read-only=on,filename=builtin:edk2-x86_64-code.fd
```

Start/stop the paused VMs through QMP or a bounded harness; these commands do not
exit by themselves. Test BIOS boot with no `-bios`, explicit `-bios builtin:bios.bin`,
VGA/virtio-net/e1000e ROMs, microvm, and `-kernel` Linux/multiboot/PVH. Check that
explicit real firmware/ROM paths and `-L` overrides still win. Trace host file
opens to verify no `builtin:` paths or extracted firmware files are opened.
Also test `-k en-us`, `-k builtin:keymaps/en-us`, all other bundled layouts,
external keymap overrides, and missing `-k /missing/en-us` (must fail).
The native test covers byte identity, deterministic generation, malformed names,
and archive dead stripping, but is not a substitute for these QEMU tests.

## Important limitations and provenance

- All resources are read-only, including VARS templates. Writable opens without
  auto-read-only, writes, and writable reopen are rejected. Persistent UEFI
  variables require a separately managed writable backend; this patch creates
  neither a temporary firmware file nor a writable host VARS copy.
- The supplied `edk2-i386-vars.fd` is 328704 bytes and
  `edk2-i386-secure-vars.fd` is 340992 bytes. Neither is 4-KiB aligned; the x86
  pflash mapper rejects these as direct raw pflash backends. They are preserved
  byte-for-byte, NOT padded or silently replaced. The main agent must resolve
  VARS provisioning separately. Both supplied x86_64 JSON descriptors point to
  `edk2-i386-vars.fd`, including the secure descriptor.
- The asset directory lacks `edk2-x86_64-microvm.fd`; no filename was invented
  and no alternate bundle was substituted. Microvm's BIOS defaults are present.
- Asset bytes come only from the provided Lima/UTM share-qemu inventory. Large
  ARM, AArch64, RISC-V, LoongArch, PPC, and other non-x86 images are excluded.
- `edk2-licenses.txt` is embedded unchanged from the supplied assets. The original
  source tree's pc-bios README, COPYING, and COPYING.LIB are also embedded
  unchanged as `firmware-notices.txt`, `firmware-COPYING`, `firmware-COPYING.LIB`.
  Original QEMU option-ROM source notices remain in pc-bios/optionrom unchanged.
  Firmware bytes retain their own licenses, not the registry's GPL license.
  Firmware source submodules in this copy are empty: redistribution still needs
  matching corresponding source/additional upstream notices where required.
  The pc-bios README describes source-tree firmware provenance; do not assume
  that proves the exact UTM bundle firmware revisions. SHA-256 identities are
  recorded in manifest.json.

## Embedded inventory

77 resources; 18886417 payload bytes; 18886688 bytes including alignment.

| Filename | Bytes |
|---|---:|
| `bios-256k.bin` | 262144 |
| `bios-microvm.bin` | 131072 |
| `bios.bin` | 131072 |
| `edk2-i386-code.fd` | 3653632 |
| `edk2-i386-secure-code.fd` | 3653632 |
| `edk2-i386-secure-vars.fd` | 340992 |
| `edk2-i386-vars.fd` | 328704 |
| `edk2-licenses.txt` | 42903 |
| `edk2-x86_64-code.fd` | 3653632 |
| `edk2-x86_64-secure-code.fd` | 3653632 |
| `efi-e1000.rom` | 159232 |
| `efi-e1000e.rom` | 159232 |
| `efi-eepro100.rom` | 159232 |
| `efi-ne2k_pci.rom` | 157696 |
| `efi-pcnet.rom` | 157696 |
| `efi-rtl8139.rom` | 160768 |
| `efi-virtio.rom` | 160768 |
| `efi-vmxnet3.rom` | 156672 |
| `firmware-COPYING` | 17992 |
| `firmware-COPYING.LIB` | 26530 |
| `firmware-notices.txt` | 4847 |
| `keymaps/ar` | 28605 |
| `keymaps/bepo` | 27809 |
| `keymaps/cz` | 29209 |
| `keymaps/da` | 29230 |
| `keymaps/de` | 29183 |
| `keymaps/de-ch` | 29214 |
| `keymaps/en-gb` | 29219 |
| `keymaps/en-us` | 27086 |
| `keymaps/es` | 29203 |
| `keymaps/et` | 27291 |
| `keymaps/fi` | 28604 |
| `keymaps/fo` | 29217 |
| `keymaps/fr` | 29204 |
| `keymaps/fr-be` | 29211 |
| `keymaps/fr-ca` | 27564 |
| `keymaps/fr-ch` | 29215 |
| `keymaps/hr` | 29255 |
| `keymaps/hu` | 29207 |
| `keymaps/is` | 29254 |
| `keymaps/it` | 29312 |
| `keymaps/ja` | 27163 |
| `keymaps/lt` | 29166 |
| `keymaps/lv` | 28618 |
| `keymaps/mk` | 27685 |
| `keymaps/nl` | 29268 |
| `keymaps/no` | 29563 |
| `keymaps/pl` | 29327 |
| `keymaps/pt` | 29195 |
| `keymaps/pt-br` | 29175 |
| `keymaps/ru` | 27704 |
| `keymaps/sl` | 4632 |
| `keymaps/sv` | 3346 |
| `keymaps/th` | 27829 |
| `keymaps/tr` | 29142 |
| `kvmvapic.bin` | 9216 |
| `linuxboot.bin` | 1024 |
| `linuxboot_dma.bin` | 1536 |
| `multiboot.bin` | 1024 |
| `multiboot_dma.bin` | 1024 |
| `pvh.bin` | 1536 |
| `pxe-e1000.rom` | 67072 |
| `pxe-eepro100.rom` | 61440 |
| `pxe-ne2k_pci.rom` | 61440 |
| `pxe-pcnet.rom` | 61440 |
| `pxe-rtl8139.rom` | 61440 |
| `pxe-virtio.rom` | 60416 |
| `qboot.rom` | 65536 |
| `vgabios-ati.bin` | 39424 |
| `vgabios-bochs-display.bin` | 28672 |
| `vgabios-cirrus.bin` | 38912 |
| `vgabios-qxl.bin` | 39424 |
| `vgabios-ramfb.bin` | 28672 |
| `vgabios-stdvga.bin` | 39424 |
| `vgabios-virtio.bin` | 39424 |
| `vgabios-vmware.bin` | 39424 |
| `vgabios.bin` | 38912 |
