# Additional runtime and dependency notices

This directory supplements, and does not modify, `compliance/guest-agent/`.
It packages authentic upstream text with reproducible extraction provenance.
**It is not a corresponding-source delivery, a relinking kit, a blanket project
license, or permission/legal clearance to redistribute the combined binary.**
The release gates elsewhere in the project remain open.

## Coverage of the retained build

`manifest.json` records **1,383 notice/context records in 59 components**:

| Component | Records | Coverage and limits |
| --- | ---: | --- |
| Host Go dependencies | 79 across **48 modules** | All named notices matching the documented rule in each binary-recorded module ZIP, including nested notices. File-level attribution is not complete. |
| Host Go **1.22.12** | 41 | Locked Darwin/amd64 distribution: LICENSE, PATENTS, nested named notices and selected nonstandard leading source comments. |
| Historical guest Go **1.19.2** | 53 | Official historical source release: LICENSE, PATENTS, nested named notices and selected nonstandard leading source comments. Not substituted from the host toolchain. |
| GLib 2.66.8 | 320 | Named texts (including PCRE COPYING and AUTHORS) plus leading comments under glib/, gmodule/, gthread/, gobject/. |
| proxy-libintl 0.1 | 3 | COPYING plus original libintl.c and libintl.h leading comments. |
| libslirp, locked revision | 58 | COPYRIGHT plus selected src/ leading comments, preserving individual BSD/MIT/SPDX attributions. |
| zlib 1.3.1 | 25 | LICENSE, nested named text, and top-level source-header notices. |
| libffi 3.4.6 | 135 | Named notices and selected src/ and include/ leading comments. |
| QEMU, locked UTM revision | 233 | Named license files, pc-bios/edk2-licenses.txt, pc-bios/README context, and selected leading comments. |
| Berkeley SoftFloat, locked revision | 433 | Named texts and source/ leading comments. Conservative superset, not a linked-object inventory. |
| keycodemapdb, locked revision | 2 | Named license texts. Not proof of the historical generator/data used for embedded keymaps. |
| Lima, locked revision | 1 | Original upstream LICENSE; does not establish permissions for integration modifications. |

The unchanged guest-agent bundle already covers its nine modules' top-level
notices. Its README's statement that the historical runtime was not yet packaged
is an accurate statement of **that bundle's** scope; this separate directory now
supplies the Go 1.19.2 notice supplement. No guest module text or manifest was
rewritten. Its manifest hash is recorded here as a boundary check.

### What “complete” does and does not mean

The recursive **named-file inventory** is complete only for the explicit rule
in `collect.py` / `manifest.selection`: basenames LICENSE/LICENCE (also plural),
COPYING, COPYRIGHT, NOTICE (also plural), PATENTS, AUTHORS, with suffixes, plus
`*-license(s).txt`. Code/script extensions are excluded. This captures upstream
NOTICE and PATENTS files instead of inventing generic replacements. Examples
include containerd and coreos NOTICE, gRPC NOTICE.txt, Go/x-module PATENTS,
survey's terminal/LICENSE.txt, go-libvirt's internal/go-xdr/LICENSE, and tail's
ratelimiter/Licence. Named build-tool, test, compiler-vendor and alternate-platform
notices may be included conservatively; not every included text necessarily
applies to linked code.

**File-level coverage is partial.** A deterministic scanner preserves contiguous
leading C/Go comments containing a copyright, SPDX, permission, or public-domain
marker. It records exact byte ranges (start inclusive, end exclusive) and hashes
of both the full original member and the copied prefix. Adjacent descriptive
comments are retained verbatim. It does not parse arbitrary embedded comments,
assembler dialects, generated code attribution, or every copied fragment.
Module source headers are not scanned. Go headers are selected from `src/`,
excluding `src/cmd/`, test paths and `_test.go`, and omit standard Go-only
copyright headers already pointing at LICENSE. Named notices are still collected
throughout the Go archives, including compiler vendors and BoringSSL: inclusion
is not a claim those features were enabled.

Native header selection is intentionally bounded. QEMU covers `util/`,
`include/qemu/`, `fpu/`, `net/`, and `pc-bios/optionrom/`, **not its entire device,
architecture, or block tree**. GLib includes gnulib and PCRE headers where the
leading-comment scanner recognizes them. libffi/SoftFloat include candidates
for architectures not necessarily present in this build. Neither this scan nor
the binary's Go build record is a complete native link map. Review of actual
compiled/linked objects, modified/generated code and non-leading notices remains
necessary before treating the notices gate as closed.

### Firmware boundary

The original `pc-bios/edk2-licenses.txt`, QEMU license texts and `pc-bios/README`
are packaged from the locked retained QEMU archive; option-ROM source comments
are supplemental candidates. The README is **upstream context**, not an
independently verified source/provenance attestation. This does not establish
historical SeaBIOS, SeaVGABIOS, iPXE, qboot, EDK2/VARS, or keymap notice
completeness, supply missing firmware sources, or resolve differing firmware
bytes. Firmware source/build provenance remains owned by
`compliance/firmware/` and its audit. No firmware files or evidence were changed.

## Provenance and authentication

- `evidence/host-go-version-m.txt` is `go version -m output/limactl`.
  It identifies Go 1.22.12, Darwin/amd64 and exactly 48 dependencies.
- `evidence/guest-go-version-m.txt` is the same inspection of the retained Linux
  x86_64 guest agent. It identifies Go 1.19.2. Both binary SHA-256 values, sizes,
  module records, and build settings are retained in the manifest.
- Each host module ZIP was read directly from the retained project cache, not
  from an unpacked module directory. Go `dirhash.HashZip` / `Hash1` was recomputed:
  sort member names; SHA-256 each member's bytes; hash the concatenation of
  lowercase hex digest, two spaces, name and newline; base64 with `h1:` prefix.
  All 48 results matched **both binary build metadata and `src/lima/go.sum`**.
  Raw ZIP SHA-256, size, exact member path and proxy reacquisition URL are also
  recorded. These are content checks, not publisher signatures or build
  attestations. The collector does not trust `.ziphash` sidecars.
- Native, Lima and host Go archives were checked against their applicable entry
  in `sources.lock.json` or `dependencies.lock.json` before any notice was copied.
  The manifest records the lock reference and original archive SHA-256/URL.
- `historical-go.lock.json` pins `go1.19.2.src.tar.gz`, obtained from Go's official
  HTTPS release endpoint, SHA-256
  `2ce930d70a931de660fdaf271d70192793b1b240272645bf0275779f6704df6b`,
  **26,534,465 bytes**. The value was retrieved from the official release catalog
  on 2026-09-15, not inferred from the host runtime. The downloaded archive's
  size/hash matched, and `go/VERSION` is `go1.19.2`.
  The lock includes the selected catalog JSON object, catalog URL and original
  response hash. The selected object is not represented as verbatim HTTP bytes.
  The original response and source archive are retained locally under `inputs/`.
  This is HTTPS/checksum provenance, not a detached signature or proof that the
  historical guest executable was rebuilt from exactly that source.

Notice payloads have **no added headers or newline conversion**. In the manifest,
notice `path` is bundle-relative, `source_path` is an exact archive member name,
and archive/binary/lock paths are project-relative. Full-member records have
matching payload/member hashes; header records additionally carry `byte_range`.
Identical text in two releases is still attributed separately to each verified
archive. Empty or missing module top-level notices cause collection to fail.

## Repeatable collection and verification

From the project root (Python 3.8+ standard library):

```sh
# Offline packaged-file and metadata integrity; no Go, archives, binaries or network needed.
python3 -B compliance/notices/collect.py verify

# Also recompute all archive hashes/h1, reread both binaries using Go,
# re-extract selections in memory and compare every byte and the whole manifest.
python3 -B compliance/notices/collect.py verify --sources

# Reproduce an absent bundle's generated outputs, or check an identical existing one.
python3 -B compliance/notices/collect.py collect

# Explicitly reacquire the historical Go archive only if absent (curl, verified HTTPS).
python3 -B compliance/notices/collect.py collect --fetch-historical

# Focused tests; enables the optional full retained-archive recheck in the same test run.
ADDITIONAL_NOTICES_VERIFY_SOURCES=1 python3 -B -m unittest discover -s tests -p test_additional_notices.py -v
```

Plain `verify` needs the two root lockfiles, `src/lima/go.sum`, and the existing
guest bundle manifest, in addition to this directory. It checks payload hashes,
sizes, member/output mappings, runtime distinction, 48-module coverage, recorded
build metadata, and the exact `texts/` / `evidence/` file inventory. It **does not**
reconstruct absent archives or authenticate a self-consistently rewritten
manifest. Trust in the pinned input records and reviewed collector remains
necessary. `--sources` is the stronger check and requires all recorded archives,
the two binaries, and Go (`tools/go/bin/go` by default; override with `--go PATH`).
It neither executes the target binaries nor compiles anything.

All inputs except the historical download were already retained locally. There
is no implicit network fallback. To restore missing module/native archives,
use the project's existing acquisition workflow and recorded URLs/checksums;
this collector does not write shared caches or downloads. Historical fetching
uses `curl` with HTTPS-only redirects, TLS verification and bounded timeouts;
no insecure TLS fallback is used. The initial Python HTTPS attempt failed local
certificate verification; system curl successfully retrieved the catalog and
archive with TLS verification enabled.

Collection refuses to overwrite differing existing generated files and refuses
unsafe paths/duplicate archive members. Run in a clean copy for a changed build
rather than overwrite a reviewed manifest. Only this directory's `texts/`,
`evidence/`, `manifest.json`, and explicitly requested `inputs/` downloads are
written. Tests use disposable fixtures under this directory's `inputs/` and do
not modify the guest bundle or other project inputs.

## Required publication/export allowlist additions (not applied)

The root/export scripts and documentation were deliberately left untouched.
For `output/prepare-source-publication.py` and any release-artifact allowlist:

1. Add `compliance/notices/README.md`, `collect.py`, `historical-go.lock.json`,
   `manifest.json`, and optionally `.gitignore` (all under `compliance/notices/`).
2. Read `manifest.json`; validate safe canonical paths and size/SHA-256, then
   include every `components[].notices[].path` and `evidence[].path` with the
   `compliance/notices/` prefix. Do not glob unvalidated local files.
3. Add `tests/test_additional_notices.py` to the test allowlist.
4. **Exclude `compliance/notices/inputs/`, `__pycache__/`, and temporary files.**
   The large historical archive/catalog are local verification inputs, not part
   of the notice payload or a declared corresponding-source delivery method.
5. Wire plain `verify` / the offline tests into export integrity checks and
   regenerate/review the export before claiming that release artifacts carry
   these notices. Do not require the optional source-archive test in a
   cache-free export. Preserve the existing guest bundle allowlist unchanged.

No export or release artifact was regenerated by this task. A notice bundle
alone does not satisfy source delivery, relinking, modification-notice,
combined-work compatibility, or other unresolved redistribution obligations.
