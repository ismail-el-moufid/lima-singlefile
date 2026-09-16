# Guest-agent dependency notices

This is a focused notice bundle for the retained Linux x86_64 Lima guest agent,
not a license for the project or a redistribution clearance. Original notice
files keep their upstream text and apply according to their own terms.

## Provenance and contents

`manifest.json` identifies the retained binary at
`src/lima/pkg/embeddedassets/lima-guestagent.Linux-x86_64` (paths in this document
are repository-relative unless stated otherwise). Its Go build record identifies
Go 1.19.2, Linux/amd64, GOAMD64=v1, CGO_ENABLED=0, Lima v0.13.0, and unmodified
Lima revision `6b6073ff536ea3ae7605129489a33ed2ba11fc46`.

The bundle contains the original top-level LICENSE, NOTICE, and PATENTS files
present in all nine recorded module ZIPs:

| Bundle directory | Module | Version | Files |
| --- | --- | --- | --- |
| `modules/go-libaudit-v2/` | github.com/elastic/go-libaudit/v2 | v2.3.2 | LICENSE.txt, NOTICE.txt |
| `modules/mux/` | github.com/gorilla/mux | v1.8.0 | LICENSE |
| `modules/logrus/` | github.com/sirupsen/logrus | v1.9.0 | LICENSE |
| `modules/cobra/` | github.com/spf13/cobra | v1.6.1 | LICENSE.txt |
| `modules/pflag/` | github.com/spf13/pflag | v1.0.5 | LICENSE |
| `modules/native_endian/` | github.com/yalue/native_endian | v1.0.2 | LICENSE |
| `modules/atomic/` | go.uber.org/atomic | v1.7.0 | LICENSE.txt |
| `modules/multierr/` | go.uber.org/multierr | v1.7.0 | LICENSE.txt |
| `modules/x-sys/` | golang.org/x/sys | v0.0.0-20220811171246-fbc7d0a398ab | LICENSE, PATENTS |

`lima/LICENSE` is copied from `lima-0.13.0/LICENSE` in the locked Lima source
archive, not inferred from a blanket project license.

During packaging, the nine existing ZIPs under `cache/modules/cache/download/`
were read directly. Each Go `h1:` checksum was recomputed using Go dirhash.Hash1:
SHA-256 of the sorted sequence of `hex(SHA256(member contents))`, two spaces,
member name, and newline, then base64-encoded with the `h1:` prefix. The results
matched both the retained binary's Go build record and `src/lima/go.sum`.
The top-level notice inventory was checked before copying. Unpacked module
cache files were not used as extraction inputs.

The existing `downloads/lima-v0.13.0.tar.gz` was verified against
`sources.lock.json`, including its SHA-256 and PAX commit record. Notice members
were copied as raw bytes without reformatting, newline conversion, or added
headers. No archives were downloaded.

The manifest records module paths/versions and recorded Go ZIP checksums, archive
paths and SHA-256 values, each notice's archive member path, size and SHA-256,
and the guest-agent binary identity and build metadata. Notice `path` values
are relative to this directory; `source_path` values are archive member names.
Archive and binary paths are repository-relative provenance references, not
requirements for running the bundle's offline tests. Go `h1:` checksums are
content hashes, not raw ZIP-file SHA-256 values or publisher signatures.

## Offline integrity checks

From the repository root, run only this test file with:

```sh
python3 -B -m unittest discover -s tests -p test_guest_agent_notices.py -v
```

The tests use only Python's standard library, this bundle, and retained
repository inputs (`src/lima/go.sum`, `sources.lock.json`, `src/lima/LICENSE`,
and the guest-agent binary). They do not need Go, module caches, archives,
network access, or compilation. They check the exact bundle inventory, expected
nine-module coverage, archive member mappings, notice sizes/hashes, recorded
module checksums, Lima's lock identity, and the retained agent's identity.
Archive-content verification was performed during packaging; the offline tests
do not reconstruct absent ZIPs or independently establish their provenance.

## Limits and remaining work

- **Go 1.19.2 runtime notices and source are not yet packaged.** The local
  Go 1.22.12 toolchain is not substituted for that historical runtime.
- This is **not a complete file-level attribution inventory**. Nested notices,
  copied fragments, generated material, and other potentially applicable
  attributions still require review of the actual included code.
- Module and Lima implementation source archives are not included here. This
  notice bundle does not select or fulfill a complete source-delivery method.
- The binary's original release-bundle acquisition/authentication record and an
  exact source rebuild remain unestablished by this bundle. Recorded build
  metadata and checksums are evidence, not build attestations.
- Host Go modules, native dependencies, firmware, modification notices, and
  original integration-code permissions are outside this bundle's scope.
- **This is not redistribution clearance and does not close the whole notices
  gate.** The combined-work licensing conflict, firmware provenance/source gaps,
  and other release gates in `RELEASE-REVIEW.md` remain unresolved.
- The local `output/prepare-source-publication.py` export allowlist includes
  this bundle and verifies the notice hashes before copying. Existing exports
  have not been regenerated; release-artifact packaging remains pending.
