#!/usr/bin/env python3
"""Offline native linkage evidence regression tests; no build, git or downloads.

Run: python3 -B -m unittest discover -s tests -p test_linkage_audit.py -v
"""

import importlib.util
import json
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "linkage_audit", ROOT / "compliance/linkage/audit.py"
)
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


def mach_fixture(symbol_type=0x0F):
    strings = b"\0_witness\0"
    header = struct.pack("<8I", 0xFEEDFACF, 0x01000007, 3, 2, 1, 24, 0, 0)
    command = struct.pack("<6I", 2, 24, 56, 1, 72, len(strings))
    symbol = struct.pack("<IBBHQ", 1, symbol_type, 1, 0, 0x100001000)
    return header + command + symbol + strings


class LicenseSignalTests(unittest.TestCase):
    def signals(self, text):
        return set(audit.grants(text)[0])

    def test_version_two_sentence_punctuation_is_not_version_21(self):
        for grant in (
            "GNU GPL, version 2.",
            "GNU General Public License version 2, as published.",
            "GPLv2",
        ):
            with self.subTest(grant=grant):
                self.assertIn(
                    "gpl-version-2-without-later-candidate", self.signals(grant)
                )
        for grant in ("GNU Lesser General Public License version 2.1", "LGPL-2.0-only"):
            self.assertFalse(
                self.signals(grant)
                & {"explicit-gpl-2.0-only", "gpl-version-2-without-later-candidate"}
            )

    def test_later_version_not_only(self):
        for grant in (
            "GNU GPL version 2 or later",
            "GPL-2.0-or-later",
            "GNU General Public License; either version 2 of the License, or any later version.",
        ):
            self.assertIn("gpl-2.0-or-later-text", self.signals(grant))
            self.assertNotIn(
                "gpl-version-2-without-later-candidate", self.signals(grant)
            )

    def test_spdx_only_with_exception_is_preserved(self):
        expression = "GPL-2.0-only WITH Linux-syscall-note"
        signals, expressions = audit.grants(
            "/* SPDX-License-Identifier: " + expression + " */"
        )
        self.assertEqual(expressions, [expression])
        self.assertIn("explicit-gpl-2.0-only", signals)
        self.assertIn("exception-text-review-scope", signals)

    def test_alternate_expression_not_simplified(self):
        expression = "(GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause"
        signals, expressions = audit.grants(
            "/* SPDX-License-Identifier: " + expression + " */"
        )
        self.assertEqual(expressions, [expression])
        self.assertIn("alternate-grant-text-review-scope", signals)
        self.assertIn("exception-text-review-scope", signals)

    def test_separate_contribution_grants_do_not_cancel(self):
        text = "/* SPDX-License-Identifier: GPL-2.0-only */\n\n/* Other portions: GNU GPL version 2 or later. */"
        found = audit.notices(text)
        self.assertEqual(len(found), 2)
        self.assertEqual(found[1]["start_line"], 3)
        self.assertIn("explicit-gpl-2.0-only", found[0]["signals"])
        self.assertIn("gpl-2.0-or-later-text", found[1]["signals"])

    def test_absent_notice_is_not_inferred_gpl(self):
        self.assertEqual(audit.notices("int hello(void) { return 2; }\n"), [])
        self.assertEqual(audit.grants("Nothing about licensing here")[0], [])

    def test_library_gpl_and_generic_mit_portions_not_mixed(self):
        signals = self.signals(
            "GNU Library General Public License; either version 2 or any later version"
        )
        self.assertIn("lgpl-or-library-gpl-text", signals)
        self.assertNotIn("gpl-2.0-or-later-text", signals)
        self.assertNotIn(
            "portion-specific-text-review-scope",
            self.signals(
                "Permission is hereby granted to use substantial portions of the Software."
            ),
        )


class EvidenceParserTests(unittest.TestCase):
    def test_meson_flattening_collisions_are_not_discarded(self):
        index = audit.source_index(["foo/bar.c", "foo_bar.c"])
        self.assertEqual(index["foo_bar.c.o"], ["foo/bar.c", "foo_bar.c"])
        self.assertEqual(
            audit.object_key("tcg/libtcg_system.a.p/tcg-op.c.o"), "tcg_tcg-op.c.o"
        )
        self.assertIsNone(
            audit.object_key("libblock.a.p/meson-generated_.._block_block-gen.c.o")
        )

    def test_defined_symbol_evidence(self):
        result, symbols = audit.macho(mach_fixture())
        self.assertEqual(result["defined_symbol_count"], 1)
        self.assertEqual(symbols["_witness"][0]["address"], "0x100001000")
        self.assertEqual(symbols["_witness"][0]["index"], 0)
        self.assertEqual(result["debug_map_records"], [])

    def test_undefined_symbol_not_survival_evidence(self):
        result, symbols = audit.macho(mach_fixture(0x01))
        self.assertEqual(symbols, {})
        self.assertEqual(result["defined_symbol_count"], 0)

    def test_debug_map_not_ordinary_defined_symbol(self):
        result, symbols = audit.macho(mach_fixture(0x66))
        self.assertEqual(symbols, {})
        self.assertEqual(result["debug_map_records"][0]["name"], "_witness")

    def test_invalid_binary_fails_closed(self):
        for data in (b"", b"not Mach-O", mach_fixture()[:-1], mach_fixture()[:40]):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                audit.macho(data)


class RetainedParserTests(unittest.TestCase):
    @staticmethod
    def archive(entries):
        data = b"!<arch>\n"
        for name, payload in entries:
            encoded = name.encode()
            size = len(encoded) + len(payload)
            header = f"{'#1/' + str(len(encoded)):<16}{0:<12}{0:<6}{0:<6}{100644:<8}{size:<10}`\n".encode()
            data += header + encoded + payload + (b"\n" if size % 2 else b"")
        return data

    @staticmethod
    def deps(mtime=42, dependency_id=1):
        data = b"# ninjadeps\n\x04\0\0\0"
        for ident, path in enumerate((b"object.o", b"source.c")):
            payload = path + b"\0"
            payload += b"\0" * (-len(payload) % 4)
            payload += struct.pack("<I", ~ident & 0xFFFFFFFF)
            data += struct.pack("<I", len(payload)) + payload
        data += struct.pack("<IIqI", 0x80000010, 0, mtime, dependency_id)
        return data

    def test_archive_duplicates_offsets_and_hashes(self):
        data = self.archive([("same.o", b"1234"), ("same.o", b"5678")])
        members = audit.ar_members(data)
        self.assertEqual([m["name"] for m in members], ["same.o", "same.o"])
        self.assertEqual([m["ordinal"] for m in members], [0, 1])
        for member in members:
            self.assertEqual(
                data[
                    member["payload_offset"] : member["payload_offset"] + member["size"]
                ],
                member["data"],
            )
            self.assertEqual(member["sha256"], audit.sha(member["data"]))

    def test_bsd_padding_is_verified_not_blindly_stripped(self):
        self.assertEqual(audit.archive_object_padding(b"1234", b"1234", True), 0)
        self.assertEqual(
            audit.archive_object_padding(b"1234\n\n\n\n", b"1234", True), 4
        )
        for payload, original, bsd in (
            (b"1234\n\n\n\n", b"1234", False),
            (b"1234\0\0\0\0", b"1234", True),
            (b"1234\n\n\n", b"1234", True),
            (b"1234" + b"\n" * 12, b"1234", True),
        ):
            self.assertIsNone(audit.archive_object_padding(payload, original, bsd))

    def test_archive_corruption_fails_closed(self):
        for data in (b"!<thin>\n", self.archive([("one.o", b"x")])[:-2]):
            with self.assertRaises(ValueError):
                audit.ar_members(data)

    def test_ninja_dependencies_and_last_record(self):
        data = self.deps()
        self.assertEqual(
            audit.ninja_deps(data)["object.o"]["dependencies"], ["source.c"]
        )
        self.assertEqual(audit.ninja_deps(data)["object.o"]["mtime_ns"], 42)
        data += struct.pack("<IIqI", 0x80000010, 0, 43, 1)
        self.assertEqual(audit.ninja_deps(data)["object.o"]["mtime_ns"], 43)

    def test_ninja_corruption_fails_closed(self):
        bad_checksum = bytearray(self.deps())
        bad_checksum[32] ^= 1
        for data in (
            b"",
            self.deps()[:-1],
            self.deps(dependency_id=7),
            bytes(bad_checksum),
        ):
            with self.assertRaises(ValueError):
                audit.ninja_deps(data)


class SnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report_bytes = (ROOT / "compliance/linkage/inventory.json").read_bytes()
        cls.report = json.loads(cls.report_bytes)
        cls.files = {f["path"]: f for f in cls.report["files"]}
        cls.retained = cls.report["linkage"]["retained_evidence"]

    def test_report_reproduces_without_writes(self):
        # One complete regeneration in memory also verifies every current input,
        # snippet, source hash, include edge, symbol witness and report index.
        regenerated = audit.serialize(audit.generate(ROOT)).encode()
        self.assertEqual(audit.sha(regenerated), audit.sha(self.report_bytes))

    def test_incomplete_and_manifest_mismatch_are_not_hidden(self):
        self.assertEqual(self.report["format"], 2)
        scope = self.report["scope"]
        self.assertTrue(scope["retained_link_archive_membership_complete"])
        self.assertTrue(scope["core_source_mapping_complete"])
        self.assertFalse(scope["ordinary_archive_extraction_complete"])
        self.assertFalse(scope["file_level_inventory_complete"])
        self.assertFalse(scope["contributor_inventory_complete"])
        self.assertFalse(scope["redistribution_cleared"])
        self.assertTrue(scope["single_file_design_unchanged"])
        self.assertTrue(self.report["binary"]["matches_manifest"])
        self.assertFalse(
            self.report["binary"]["manifest_input_checks"]["source-overlays.json"]
        )
        self.assertGreater(len(self.report["gaps"]), 5)

    def test_every_core_object_has_traceable_membership(self):
        objects = self.report["core_objects"]
        self.assertEqual(len(objects), 783)
        self.assertEqual([o["ordinal"] for o in objects], list(range(783)))
        self.assertTrue(
            self.report["linkage"]["historical_list_matches_core_after_replacements"]
        )
        self.assertEqual(
            self.report["summary"]["core_mapping_counts"],
            {"archive-bytes-and-compiler-record": 783},
        )
        for obj in objects:
            self.assertEqual(obj["membership"], "force-loaded-archive-member")
            self.assertTrue(obj["archive_member_bytes_verified"])
            self.assertTrue(obj["member_name_matches_log"])
            self.assertTrue(obj["source_candidates"])
            self.assertEqual(obj["evidence"]["path"], "logs/native-core-archive.log")
            for path in obj["source_candidates"]:
                self.assertIn(path, self.files)
        generated = [o for o in objects if "meson-generated" in o["object"]]
        self.assertEqual(len(generated), 17)
        for obj in generated:
            self.assertTrue(all((ROOT / p).is_file() for p in obj["source_candidates"]))

    def test_six_recompiles_and_four_overrides(self):
        recompiles = self.report["linkage"]["recompiles"]
        self.assertEqual(len(recompiles), 6)
        self.assertEqual(
            {r["source"] for r in recompiles},
            {
                "system/main.c",
                "qemu-img.c",
                "os-posix.c",
                "util/main-loop.c",
                "util/qemu-thread-posix.c",
                "util/oslib-posix.c",
            },
        )
        overrides = [
            self.files[r["review_file"]]
            for r in recompiles
            if r["review_file"].startswith("native/")
        ]
        self.assertEqual(len(overrides), 4)
        for record in overrides:
            self.assertTrue(record["provenance"]["matches_override_hash"])
            self.assertTrue(record["provenance"]["matches_upstream_base"])
            self.assertFalse(record["provenance"]["compiled_bytes_verified"])

    def test_core_header_utility_and_mixed_examples_remain_distinct(self):
        core = self.files["src/qemu/hw/virtio/iothread-vq-mapping.c"]
        self.assertIn("explicit-gpl-2.0-only", core["license_signals"])
        self.assertIn(
            "_iothread_vq_mapping_apply", {w["name"] for w in core["symbol_witnesses"]}
        )
        ninep = self.files["src/qemu/hw/9pfs/9p-local.c"]
        self.assertIn("gpl-version-2-without-later-candidate", ninep["license_signals"])
        header = self.files["src/qemu/hw/net/igb_regs.h"]
        self.assertIn(
            "ninja-recorded-compiler-dependency",
            {m["kind"] for m in header["memberships"]},
        )
        self.assertNotIn(
            "ordinary-archive-member", {m["kind"] for m in header["memberships"]}
        )
        crc = self.files["src/qemu/util/crc-ccitt.c"]
        self.assertIn(
            "ordinary-archive-member", {m["kind"] for m in crc["memberships"]}
        )
        self.assertNotIn(
            "utility-build-declaration-only", {m["kind"] for m in crc["memberships"]}
        )
        self.assertIn("explicit-gpl-2.0-only", crc["license_signals"])
        self.assertFalse(
            self.files["src/qemu/fpu/softfloat.c"]["gplv2_only_review_candidate"]
        )
        self.assertIn(
            "src/qemu/fpu/softfloat.c",
            self.report["mixed_alternate_exception_review_queue"],
        )

    def test_candidate_queue_has_notice_level_support(self):
        queue = self.report["gplv2_only_review_queue"]
        self.assertEqual(len(queue), 152)
        self.assertEqual(
            {q["file"] for q in queue},
            {p for p, f in self.files.items() if f["gplv2_only_review_candidate"]},
        )
        for candidate in queue:
            self.assertTrue(candidate["notice_lines"])
            file = self.files[candidate["file"]]
            self.assertEqual(file["alternate_or_exception_clearance"], "not determined")
            for line in candidate["notice_lines"]:
                self.assertTrue(
                    any(
                        n["start_line"] == line and n["snippet"]
                        for n in file["notices"]
                    )
                )

    def test_native_deps_are_file_level_not_blanket_linked(self):
        deps = {d["component"]: d for d in self.report["native_dependencies"]}
        self.assertEqual(
            {name: len(d["file_records"]) for name, d in deps.items()},
            {
                "glib": 122,
                "proxy-libintl": 1,
                "zlib": 15,
                "libslirp": 31,
                "libffi": 0,
            },
        )
        self.assertTrue(
            all(not d["linked_member_inventory_complete"] for d in deps.values())
        )
        self.assertEqual(deps["libffi"]["historical_link_arguments"], [])
        proxy = self.files[deps["proxy-libintl"]["file_records"][0]]
        self.assertIn("lgpl-or-library-gpl-text", proxy["license_signals"])
        self.assertFalse(proxy["gplv2_only_review_candidate"])
        self.assertTrue(any("glib/pcre/" in p for p in deps["glib"]["file_records"]))
        self.assertTrue(
            any("glib/libcharset/" in p for p in deps["glib"]["file_records"])
        )
        self.assertTrue(all(a["matches_lock"] for a in self.report["source_archives"]))

    def test_ignored_private_inputs_exist_and_match_direct_hashes(self):
        checks = self.retained["source_delivery_input_checks"]
        self.assertEqual(len(checks), 14)
        for check in checks:
            self.assertTrue((ROOT / check["path"]).is_file(), check["path"])
            self.assertTrue(check["exists"])
            self.assertTrue(check["matches_recorded_sha256"])
            self.assertEqual(audit.file_sha(ROOT / check["path"]), check["sha256"])
        self.assertTrue(
            all(
                a["matches_manifest"]
                for a in self.report["linkage"]["private_archives"]
            )
        )
        self.assertNotIn(
            "qemu-static-poc", " ".join(self.retained["native_link_flags"])
        )
        self.assertTrue(
            all(
                r["retained_input"]["exists"]
                for r in self.report["linkage"]["recompiles"]
            )
        )

    def test_all_retained_members_map_and_extraction_remains_qualified(self):
        archives = self.retained["archives"]
        self.assertEqual(
            {Path(a["path"]).name: a["member_count"] for a in archives},
            {
                "libqemu-embedded.a": 783,
                "libqemuutil-go.a": 455,
                "libz.a": 15,
                "libslirp.a": 31,
                "libglib-2.0.a": 122,
                "libintl.a": 1,
            },
        )
        self.assertEqual(
            self.report["summary"][
                "archive_members_with_byte_matched_compiler_records"
            ],
            1407,
        )
        self.assertEqual(
            self.report["summary"]["ordinary_members_with_unique_symbol_witness"], 337
        )
        for archive in archives:
            self.assertTrue(archive["exists"])
            for member in archive["members"]:
                self.assertTrue(member["compiler_records"])
                self.assertTrue(member["source_candidates"])
                self.assertFalse(member["whole_member_survival_proven"])
                for proof in member["compiler_records"]:
                    self.assertTrue(proof["object_bytes_verified"])
                    self.assertEqual(
                        proof["object_size"] + proof["archive_padding_size"],
                        member["size"],
                    )
        utility = next(a for a in archives if a["path"].endswith("libqemuutil-go.a"))
        by_name = {m["name"]: m for m in utility["members"]}
        self.assertEqual(
            by_name["util_crc-ccitt.c.o"]["extraction_assessment"],
            "unresolved-not-proven-absent",
        )
        self.assertEqual(
            by_name["util_bitmap.c.o"]["extraction_assessment"],
            "inferred-from-unique-external-definition",
        )
        self.assertNotIn("util_dbus.c.o", by_name)
        self.assertNotIn("util_chardev_open.c.o", by_name)

    def test_ninja_records_have_fresh_objects_and_reviewable_dependencies(self):
        records = self.retained["dependency_sets"]
        paths = self.retained["dependency_paths"]
        self.assertEqual(len(records), 1386)
        self.assertTrue(all(r["matches_object_mtime"] for r in records))
        for record in records:
            self.assertTrue(record["dependency_path_ids"])
            self.assertTrue(
                all(0 <= i < len(paths) for i in record["dependency_path_ids"])
            )
        for path in paths:
            if path["review_file"]:
                self.assertIn(path["review_file"], self.files)
        self.assertFalse(
            any(
                m["looks_like_ld_link_map"]
                for m in self.retained["final_link_map_search"]["candidates"]
            )
        )

    def test_generated_leads_do_not_assign_output_license(self):
        groups = self.report["generated_input_leads"]
        self.assertEqual(
            {g["group"] for g in groups}, {"QAPI", "block wrappers", "GDB XML"}
        )
        for group in groups:
            self.assertTrue(group["build_references"])
            self.assertTrue(group["inputs"])
            self.assertIn("not a generated-output license assignment", group["status"])
            for source in group["inputs"]:
                data = (ROOT / source["path"]).read_bytes()
                self.assertEqual(
                    source["snippet"],
                    "\n".join(data.decode(errors="replace").splitlines()[:40]),
                )
                self.assertEqual(source["sha256"], audit.sha(data))
        differences = [
            source
            for group in groups
            for source in group["inputs"]
            if not source["matches_archive_member"]
        ]
        self.assertEqual(
            {s["path"] for s in differences}, {"src/qemu/qapi/block-core.json"}
        )
        overlays = {
            o["file"]: o
            for o in json.loads((ROOT / "source-overlays.json").read_text())["overlays"]
        }
        for source in differences:
            overlay = overlays[source["path"]]
            self.assertEqual(source["sha256"], overlay["sha256"])
            self.assertNotEqual(source["sha256"], overlay["upstream_sha256"])


if __name__ == "__main__":
    unittest.main()
