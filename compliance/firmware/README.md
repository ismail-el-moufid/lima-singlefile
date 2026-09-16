# Embedded firmware provenance evidence

This directory records **byte provenance, not corresponding-source completeness
or redistribution clearance**. The broader release gates remain in
[`RELEASE-REVIEW.md`](../../RELEASE-REVIEW.md).

## Repeatable offline comparison

From the repository root:

```sh
python3 -B audit_firmware.py
```

The command verifies the QEMU archive against `sources.lock.json`, and the resource
manifest and blob against `source-overlays.json`. It verifies each embedded slice
before comparing it with the archive's `pc-bios/` member, decompressing `.bz2`
members where needed. It does not extract files, download inputs, compile firmware,
or modify the repository. Use `--archive PATH` for an existing copy of the same
locked archive if it is not in `downloads/`.

It prints deterministic JSON. Exit codes are **0** for all byte matches, **2** for
reported archive discrepancies, and **1** for invalid/missing inputs. Even exit 0
would not establish the firmware's implementation source, build provenance,
notice completeness, or permission to redistribute.

`archive-comparison.json` is the retained report for the locked inputs: **75 of
77 resources match** (39 firmware/ROM/VARS assets, 34 keymaps, four notice texts
in total). The two discrepancies are not waived or replaced:

| Resource | Embedded bytes | Archive bytes | Finding |
| --- | ---: | ---: | --- |
| `edk2-i386-vars.fd` | 328,704 | 335,360 after decompression | Different contents |
| `edk2-i386-secure-vars.fd` | 340,992 | Absent | Origin not established |

The report records input hashes, every matching resource name, and the differing
or missing resources' identities. Offline regression tests ensure the stored
report is tied to the current locked inputs; only rerunning the audit against the
archive rechecks the actual archive-member comparison.

## Source/build work still required

| Group | Remaining work |
| --- | --- |
| SeaBIOS / SeaVGABIOS | Historical source candidate and original license files now acquired; actual build environment and reproduction remain unverified. |
| Legacy and EFI iPXE | Both historical source candidates, historical recipes and an EfiRom-era EDK2 source candidate now acquired; actual build environment, tool attestation and target-specific license reports remain missing. |
| qboot | History-supported source candidate now acquired; exact build environment and reproduction remain unverified. |
| EDK2 / VARS | Establish actual UTM source, patches, nested dependencies and configurations; resolve both VARS origins or deliberately replace and revalidate them. |
| QEMU option ROMs | Implementation sources/recipes exist; historical prebuilt reproduction has not been verified. |
| Keymaps | Establish historical data/generator versions and applicable data notices. |

The historical revision evidence and its limits are detailed in the release
review. A current submodule pin is not substituted for an unverified historical
build. This audit covers only embedded resources, **not the additional non-x86
firmware retained in the source export**. No firmware bytes or locks were changed.

## Retained firmware/source inventory

The separate [source inventory and build notes](SOURCE-INVENTORY.md) extend the
review to **all retained `pc-bios` files, including non-x86 firmware**.
`retained-inventory.json` records byte identities and source/build gaps;
`source-catalog.json` distinguishes historical source candidates from current
gitlinks. Eleven exact-revision source archives and frozen upstream metadata are
checksummed in `acquisition-lock.json`. Acquisition is not source completeness,
a build attestation, notice completeness, or redistribution clearance.

```sh
python3 -B compliance/firmware/acquire.py
python3 -B compliance/firmware/inventory.py --check
```

These are offline consistency checks. See the build notes for opt-in bounded
reacquisition and remaining UTM/VARS evidence requirements. The original
`archive-comparison.json` and root `audit_firmware.py` are unchanged.
