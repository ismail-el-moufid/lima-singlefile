# Contributing

This is an experimental Intel macOS integration of Lima and QEMU. Start with the
[README](README.md) for the architecture, prerequisites, and supported build
commands. Read [RELEASE-REVIEW.md](RELEASE-REVIEW.md) before changing licensing,
source-delivery, or publication materials.

## Working on the project

Use the repository root for development and Git operations. Directories under
`output/` are generated artifacts or publication exports, not the development
checkout. Do not edit an exported copy expecting the root workspace to change.

Keep changes focused and preserve unrelated local work. Before editing:

```sh
git status --short --branch
```

- Make integration changes in the retained `src/` authoring snapshots or the
  relevant root/native build files, not in `build/self-contained/sources/`.
- When changing a listed overlay, update its entry in `source-overlays.json`.
  Native runtime overrides have corresponding checksums in `native/overrides.json`.
- Keep dependency and source pins, provenance, notices, and tests consistent with
  intentional input changes. A checksum update records identity; it does not
  establish licensing permission or provenance by itself.
- Preserve upstream license headers and required modification notices. The MIT
  grant in [LICENSE-ORIGINAL.md](LICENSE-ORIGINAL.md) covers original project
  contributions only, not the combined executable or third-party material.
- Do not remove embedded firmware, ROMs, the guest agent, or retained snapshots
  merely because they look like generated binaries or duplicate source trees.

Generated builds, toolchains, caches, logs, executables, and disposable validator
state are ignored. Do not force-add them or change preparation stamps to bypass
input verification. Never include credentials, private keys, or VM state.

## Validation

Run the offline unit suite from the root:

```sh
python3 -B -m unittest discover -s tests -p 'test_*.py' -v
```

For runtime changes, build and run the relevant native, prompt, and VM validators
listed in the [validation guide](README.md#validation). VM checks require a suitable
Intel macOS host; hosted CI runs non-VM smoke checks rather than HVF boot tests.
Report the commands, host/compiler mode, results, and any skipped checks.

Use the same `LIMA_COMPILER` setting for preparation, builds, and offline reuse.
The default is pinned LLVM; CI uses `apple` for its modern SDK. Use a fresh workspace
when switching compiler modes rather than reusing incompatible build state.

If an integrity check fails, inspect the specific input and recorded evidence.
Do not weaken the test or refresh a manifest solely to turn the check green.
Historical validation reports do not certify a changed executable.

Before submitting a change, review the diff for accidental outputs and whitespace:

```sh
git diff --check
git diff --stat
```

## Releases

The workflow in [`.github/workflows/build.yml`](.github/workflows/build.yml) runs
checks for `main` pushes, pull requests, manual runs, and `v*` tag pushes. **Only a
`v*` tag push publishes a release**, after the build and verification steps succeed.

- Publication is immediate: an experimental GitHub prerelease, not a draft or the
  latest release. Do not push a version tag just to test the workflow.
- The executable and `SHA256SUMS` come from that CI run, not a local `output/limactl`.
- Existing releases are not overwritten; release creation fails if the tag already
  has a release. Investigate a failed run before attempting publication again.
- CI does not provide signing/notarization, Catalina compatibility certification,
  or VM/HVF validation.

Before tagging, review the exact revision, build inputs, and validation results.
Component licenses, notices, and source-delivery evidence are documented in
[RELEASE-REVIEW.md](RELEASE-REVIEW.md).
