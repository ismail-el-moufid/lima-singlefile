# Read-only publication audit

This audit does **not** stage, commit, initialize, clean, fetch, extract, or modify
an export. Its only generated output is this directory's `history-audit.json`.
It uses the Python standard library and does not access the network. All findings
remain recorded: exact upstream matches are evidence, never release clearance.
Only paths, types, counts, and hashes are reported, never matched file content.

## Run

From the work root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s compliance/publication/tests -p test_publication_audit.py
PYTHONDONTWRITEBYTECODE=1 python3 compliance/publication/audit.py
```

An audit returns **1 (`review-required`) even if enumeration succeeds**. Inspect
`repository.complete_object_enumeration`, `repository.scanned_blob_count`, command
exit codes, snapshot fingerprints, provenance issues, and individual coverage
findings. No zero-exit publication approval is implemented. Rerunning replaces
this directory's report, not the export.

Default scope:

* Exact local `output/source-publication` HEAD and advertised refs; all objects
  reachable from refs, HEAD and reflogs; all index stages, including index-only
  blobs; raw commit/tag content as well as every bounded blob.
* All commit-tree paths via NUL-delimited `ls-tree`; all index paths via
  NUL-delimited `ls-files`. Object bytes are read by bounded `cat-file --batch`.
  The report inventories every enumerated object and every index entry.
* Separate **current-workspace** `compliance/source-delivery/` payload bytes,
  checked against the current saved manifest, and `compliance/firmware/sources/` (integrity-checked against its observed
  acquisition lock, without elevating that lock to private-key authority).
  These are not misrepresented as files contained in the older Git snapshot.

Every Git subprocess disables optional locks, filesystem monitoring, hooks,
automatic maintenance, replacement objects, lazy fetch, prompts and network
protocols, sanitizes inherited `GIT_*` settings, and has a 60-second timeout.
No raw Git error output, log messages, author identities, remotes or diff content
are printed. HEAD, refs, reflog selectors and index listings are fingerprinted
before and after inspection. This is observational, not an atomic snapshot.
Unreachable objects, expired reflogs, unrelated repositories and the default
repository's untracked/working-tree files are outside the history scope.

## Reuse for the new candidate

The existing repository is **not** `output/source-publication-review-20260915`.
The main task owns creating that export, its Git state, root documentation and
publication decisions. Once that directory actually exists:

```sh
# Candidate bytes before Git exists; excludes .git directories, follows no links.
PYTHONDONTWRITEBYTECODE=1 python3 compliance/publication/audit.py --no-repository --candidate output/source-publication-review-20260915
# Once Git exists, separately inspect its history/index and working-tree bytes.
PYTHONDONTWRITEBYTECODE=1 python3 compliance/publication/audit.py --repository output/source-publication-review-20260915 --candidate output/source-publication-review-20260915
```

These commands replace `history-audit.json`; retain this baseline report externally
through the main task's evidence workflow if both observations are needed.
`--no-workspace-payloads` omits the separate payload scans, not provenance checks.
Importable `Scanner.scan(bytes, path, context)` provides the same bounded nested
scanner for a future exporter without executing the CLI or making writes.

## Bounded archives and provenance

ZIP/wheels, TAR, gzip, bzip2 and xz are inspected in memory, recursively, without
extracting members. Defaults: 128 MiB input/member, 512 MiB decompressed stream,
1 GiB total charged expansion per top-level item, 100,000 descendant members,
eight container layers, and 120 seconds per item. Expansion accounting is
conservative and counts both a decompressed TAR and its regular member reads.
Absolute/traversing/control-character paths, duplicate names, links, sparse and
special members, encryption, corrupt/unsupported containers, and bounds are
reported. Original source members are fingerprinted without expanding their
nested test containers during provenance collection. During the actual audit,
compressed VM test fixtures with exact locked upstream member hashes are left
unexpanded and individually recorded as such, so large known fixtures cannot
starve inspection of later source members. This exception never matches on a
filename alone. A structural finding with `sha256_subject=containing-archive`
hashes that container, not an uninspected member. Links are never resolved; safe link findings are informational coverage
notes, not evidence that their targets were inspected. Time checks are cooperative
between bounded reads, not an OS CPU/memory isolation guarantee.

A finding may be labeled `exact-locked-upstream[-test]-bytes` only on full member
SHA-256 equality with an inspected archive whose bytes match the local source or
dependency lock (including QEMU and Go distributions/source). Go module ZIPs must
also independently reproduce Go `dirhash.Hash1` against `go.sum` read from the
**SHA-256-verified original locked Lima tarball**, not the working-tree `go.sum`,
ZIP name or adjacent `.ziphash`. The report records the archive hash, member path,
and lock chain. “Test” is a path-role hint; a matching key is not assumed valid,
revoked, safe for operational use, or licensed for this combined work.

Historical Go uses the existing historical source lock; this audit does not
re-fetch or independently authenticate its catalog. Firmware acquisition pins
are observed hashes rather than independent authority and are **not** used to
classify private keys as public. Changed/local-only keys stay unresolved. Generic
credential strings and build/VM signatures may be upstream examples or test data;
all such matches remain visible, including exact upstream matches.

## Limitations and blockers

Credential patterns are intentionally heuristic and not comprehensive. No claim
is made about DER/encrypted keys, arbitrary encodings, entropy-only secrets,
obfuscated credentials, embedded filesystems, unsupported compression, submodule
repositories or remotely stored LFS content. Binary and path findings are triage,
not an assertion that every source fixture is unintended. Review all unresolved
findings and coverage limits. A source archive can contain firmware and compiled
fixtures. Exact upstream provenance is not a license grant, a corresponding-source
assessment, a runtime/rebuild result, or combined-work redistribution permission.

Tests are in-memory synthetic fixtures and mocked Git subprocesses; they never
initialize, stage or commit a real repository and need no external network.

## Baseline observation — 2026-09-15

The saved audit ran from **21:04:30 to 21:07:50 UTC** against the existing export,
not the future review candidate. Nineteen synthetic/mock tests passed before this
run. The audit's exit code was intentionally 1 (`review-required`); every Git
subprocess recorded in the final report returned 0. An earlier exploratory
`rev-list --no-object-names` command returned 129 on Apple Git 2.21.1; the final
scanner uses supported `rev-list --objects` syntax instead. A preliminary combined
metadata probe and a later verbose report-display command hit their 10-second
tool deadlines; neither is represented as a successful validation command.

| Observation | Result |
| --- | --- |
| Repository | `output/source-publication` |
| HEAD | `94e1e39e82ac854131238de11575ade6acbbbf11` |
| Refs | `refs/heads/main`, `refs/remotes/origin/main`, both at HEAD |
| Reflogs | Three entries: local main, origin/main, HEAD; all at HEAD |
| Reachable commits | 1; non-shallow repository |
| Reachable objects | 11,956: 11,143 blobs, 812 trees, 1 commit |
| Blob content inspection | 11,143 of 11,143 unique blobs |
| Index | 11,614 entries, 11,143 unique blobs, no index-only objects |
| Reflog-only objects | 0 |
| Before/after observations | HEAD, refs, reflog selectors, index listing unchanged |
| Current source-delivery bytes | 411 files, 156,077,897 bytes; all 406 manifest payload records match |
| Current firmware source bytes | 11 archives, 29,557,421 bytes; all 11 observed acquisition pins match |
| Provenance | 70 verified archive records, including 52 Go module h1 checks; no provenance issues |
| Findings | 720: 109 Git, 452 current source-delivery, 159 current firmware sources |
| Classification totals | 449 exact locked byte/container matches; 271 unresolved |
| Nested containers | 382 records: 318 bounded inspections completed, 18 exact-locked VM fixture skips, 46 incomplete |
| Future candidate | **Not audited** |

All four Git private-key-marker findings hash-match the locked QEMU archive:
`src/qemu/tests/keys/id_rsa`, `src/qemu/tests/keys/vagrant`,
`src/qemu/tests/qemu-iotests/common.tls`, and
`src/qemu/tests/unit/crypto-tls-x509-helpers.c`. The report retains their blob IDs,
full-file SHA-256 values and exact upstream member provenance, without key text.
All 37 current source-delivery private-key-marker findings also have exact locked
byte provenance. **136 firmware-source private-key-marker findings remain
unclassified**: observed firmware acquisition hashes alone were deliberately not
accepted as authoritative public-key-fixture provenance. A marker can occur in
parser/test source; these counts do not assert that every match is a live secret.

Outstanding review includes credential-shaped URLs in local Git test files
(including `tests/test_bootstrap.py` and `tests/test_test_image.py`), firmware/VM
and generated-artifact signatures, links not followed, unsupported/corrupt nested
test containers, and oversized/special archive members. Four nested Go TAR test
members advertise 16 GiB each and were not read. Eighteen compressed VM fixture
containers were not expanded after exact locked upstream hash comparison; each
exception remains a finding. There are no remaining whole-archive expansion-byte
bound failures in this final run. No finding was suppressed or turned into
redistribution clearance, and the combined-work permission blocker remains.
