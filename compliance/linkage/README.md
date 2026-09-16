# Native linkage / file-license evidence

**Incomplete rights inventory, not exhaustive legal clearance.** The single-file
build is unchanged. No permissions, replacements or legal compatibility decision
are supplied.

## Reproduce

From the project root, with Python 3.8+ and the retained build/source artifacts:

```sh
python3 -B compliance/linkage/audit.py
python3 -B compliance/linkage/audit.py --check
python3 -B -m unittest discover -s tests -p test_linkage_audit.py -v
```

The standard-library tool reads files directly with `Path.is_file()`/`read_bytes()`;
it does not rely on editor directory visibility or git ignore rules. It parses
BSD/GNU archives, Mach-O and Ninja v4 dependency logs without extraction, external
tools, network, binary execution, builds or relinking. Only `inventory.json` is
written; `--check` compares without writing. Success means reproducible evidence,
**not** redistribution clearance. Report schema: **2**.

## Corrected snapshot findings

**The earlier absence claims were wrong.** All **14** selected private inputs in
`compliance/source-delivery/manifest.json` exist and match its hashes. In this
manifest the relevant field is named `local_relink_inputs`. Compilation databases,
archives, generated native flags, transformed overrides, generated C/headers and
Ninja dependency logs are retained under ignored build/prefix paths.

The binary SHA-256 is
`3a4fe1e0b19879b1e60dbb0fca8ff9be9d47f66260c115c1cd6e01a93b013218`.
It and both private QEMU archives match `output/build-manifest.json`.

The actual retained `native_link_flags.go` selects:

| Archive | Members | Link treatment | Members with unique final-symbol witnesses |
| --- | ---: | --- | ---: |
| `build/self-contained/native/libqemu-embedded.a` | 783 | Force-load | 606 |
| `build/self-contained/native/libqemuutil-go.a` | 455 | Ordinary extraction | 222 |
| `prefix/lib/libz.a` | 15 | Ordinary extraction | 9 |
| `prefix/lib/libslirp.a` | 31 | Ordinary extraction | 30 |
| `prefix/lib/libglib-2.0.a` | 122 | Ordinary extraction | 75 |
| `prefix/lib/libintl.a` | 1 | Ordinary extraction | 1 |

- **All 1,407 members** match retained compiler-output bytes, with compilation-db
  entry or compile-log references and current source-file hashes. BSD archive
  newline padding is explicitly verified, not silently stripped: stored-payload
  hashes and original-object hashes/sizes are separate.
- **All 783 core sources are mapped**, including the **17 generated C inputs**
  previously called unresolved. Core order/names reconcile with the archive log
  and historical QEMU list after the three core substitutions/addition. The three
  utility replacements and all four transformed override inputs are inspected.
- **1,386 Ninja dependency sets** match retained object mtimes. The shared path
  table has **3,929 entries**, including **924 external SDK/compiler/system paths**
  whose licensing is not inspected. Six native recompiles and fifteen zlib objects
  lack these Ninja records. Lexical includes remain separate fallback evidence.
- **337 of 624 ordinary members** have external definitions also defined in the
  binary and unique among these six archives. This supports extraction inference,
  not proof against every other Go/cgo/compiler input. The other **287** remain
  unresolved, **not proved absent**. Data symbols are included, not just functions.
- **3,087 files** have review records; **152** are GPLv2-only review candidates.
  Membership labels overlap: **54** force-loaded source records, **4** ordinary
  member source records, **147** compiler-dependency records, and **92** lexical
  include records. Do not add these counts or interpret them as surviving legal
  contributions. Explicit `only` and version-2-without-later wording are distinct.

`libffi.a` and `libgthread-2.0.a` exist, but neither is selected by the retained
native flags. GLib includes PCRE, libcharset and other internal sources; each
selected member is inventoried. `libintl.a` maps to **proxy-libintl**, not an assumed
GNU gettext implementation.

### Manifest precision

The stored build manifest's `source-overlays.json` digest differs from the current
file. This is a **current-versus-recorded metadata mismatch**, potentially from
later manifest edits—not proof that different source bytes were linked. Source
recipe, cached archive, retained prepared input, object and binary comparisons are
reported separately. Compilation databases identify input paths; they are not
immutable source-content hashes captured at compile time.

`qapi/block-core.json` differs from upstream and matches its declared overlay. The
audit preserves that distinction while separately inspecting retained generated
outputs; it does not replace their notices with a generator's license.

## Read the report

| Field | Evidence |
| --- | --- |
| `linkage.retained_evidence.source_delivery_input_checks` | Direct presence/hash checks for all 14 selected private inputs |
| `linkage.retained_evidence.native_link_flags` | Parsed retained cgo flags, superseding historical `qemu-static-poc` paths |
| `linkage.retained_evidence.archives` | Ordered members, offsets, payload hashes, compiler-byte proofs, source paths, actual object definitions and final nlist witnesses |
| `linkage.retained_evidence.dependency_sets`, `dependency_paths` | Ninja record offsets/mtimes and shared dependency path IDs; source review records where in scope |
| `core_objects`, `linkage.recompiles` | Archive/log/compiler reconciliation, entry substitutions and transformed-input evidence |
| `files` | File/member hashes, retained-input provenance, membership edges, full detected notice snippets/line ranges, verbatim SPDX and lexical symbol witnesses |
| `gplv2_only_review_queue` | Candidate paths and supporting notice lines, without blanket license inference |
| `mixed_alternate_exception_review_queue` | Portion-specific, alternate and exception review leads, not clearance |
| `header_include_edges` | Conservative lexical includes, distinct from recorded compiler dependencies |
| `generated_input_leads` | Hashed generator/schema/XML snippets and build declarations; not automatic output-license assignments |
| `binary`, `evidence_inputs`, `source_archives`, `scope`, `gaps` | Binary/load-command observations, fingerprinted inputs, completeness boundaries |

Paths containing `::` refer to a cached source-tar member. Where retained input
bytes match that member or `src/qemu/`, the canonical review record is reused and
the actual compiler-input path/hash is attached. Modified/generated inputs retain
their own build-path records. The four override bases remain separately traceable.

## Concrete grant distinctions

- `hw/virtio/iothread-vq-mapping.c` explicitly says `GPL-2.0-only`; its force-loaded
  archive member defines `_iothread_vq_mapping_apply`, also present in the binary.
- `hw/9pfs/9p-local.c:9-10` says “GNU GPL, version 2” without later wording: a
  version-2-only **candidate**, not an explicit `-only` SPDX expression.
- `hw/net/igb_regs.h` explicitly says `GPL-2.0-only`. Its compiler-dependency evidence
  is retained; LGPL notices in consumers do not silently replace header grants.
- `util/crc-ccitt.c` is a **verified utility archive member**, not merely a Meson
  declaration. Its object definitions lack final-symbol witnesses; extraction is
  unresolved. The same applies to the mixed-notice `util/host-utils.c` member.
  `util/bitmap.c` and `util/throttle.c` have unique final-symbol witnesses.
- `fpu/softfloat.c:1-80` describes SoftFloat-2a, BSD and GPLv2-or-later **portions**,
  not a choice of one license for the entire file.
- Standard headers preserve `Linux-syscall-note` and explicit GPL/BSD `OR`
  expressions, including `virtio_pmem.h` and `vmclock-abi.h`. Their existence and
  applicability are separate questions; none is treated as general permission to
  combine GPL code with Lima.
- Proxy-libintl's `libintl.c` explicitly uses GNU **Library** GPL version 2-or-later.
  It is not GPLv2-only by inference from its library name.

## Remaining limitations

No final ld map was recognized among `.map` files directly searched under
`build/self-contained`, `logs`, and `output`; those found are export/version maps.
The retained cgo flags and successful relink log are not the complete Go external
linker argv. The binary has defined symbols and 12 dynamic-library load commands,
but no `N_SO`/`N_OSO` debug map. Force-load requests every core member; it does not
prove every section survives dead stripping. `-dead_strip_dylibs` concerns dylibs,
not code. Symbol absence never proves exclusion.

To resolve exact ordinary-member extraction and section survival, retain the final
linker argv/response files and an ld map including dead-stripped entries, tied to
the binary and compile-time source-content manifests. No design change is needed.

Notice recognition remains heuristic, not an exhaustive contributor/portion rights
review. Missing notices are unresolved; QEMU's default policy is not an explicit
per-file GPLv2-only grant. Compiler/SDK contributions, Go host/runtime/cgo code,
firmware and embedded guest-agent contents are not exhaustively covered here.
Existing firmware, guest-agent and source-delivery audits remain separate.
