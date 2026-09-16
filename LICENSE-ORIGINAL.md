# License for original project contributions

## Scope

The MIT license below is selected for the **original contributions** to this
single-file Lima project, including:

- Project-authored root Python build, preparation, linking, fetching, and audit
  scripts, and project-authored build/lock/overlay configuration.
- Original integration additions and modifications described by
  `source-overlays.json` and `native/overrides.json`, **only to the extent that
  those portions are original project contributions**.
- Project-authored tests, workflow configuration, documentation, and the Python
  tools under `compliance/` and `output/`.

Copyright remains with the respective contributors. This grant covers only
rights held by those contributors; it does not assert ownership of upstream
work or permission from other copyright holders.

## Third-party exclusions and integration boundary

This is **not a root-wide license for every file**. Upstream Lima, QEMU, native
libraries, Go/runtime/module code, firmware, copied source fragments, archives,
notice texts, and quoted upstream evidence retain their own grants and notices.
A file listed in an overlay manifest is not necessarily wholly original.
Modifying or copying third-party code does not relicense it under MIT. Applicable
upstream conditions continue to govern derivative files and their distribution.

Do not remove original copyright, NOTICE, PATENTS, or license material on the
strength of this document. The MIT grant does not supply missing GPL/LGPL
corresponding source, relinking materials, historical change notices, firmware
provenance, or permission to distribute the integrated executable.

In particular, choosing MIT for original contributions **does not resolve the
Apache-2.0 / GPLv2-only compatibility issue** described in `RELEASE-REVIEW.md`.
No additional third-party permission or exception is claimed. Contributor
ownership/authority and any historical contributions outside this grant must
be confirmed before release.

## MIT License

Copyright (c) 2026 Single-file Lima contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
