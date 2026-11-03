"""Regression coverage for provenance, strict generation and audited domains."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "extract_gt"))
sys.path.insert(0, str(ROOT / "protobuf_def"))
os.environ.setdefault("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION", "python")

import blocks_pb2
from jump_table_gt import read_certificates, refine_jump_tables, sha256_file, write_outputs


class JumpTableOutputTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.binary = Path(self.directory.name) / "binary"
        self.binary.write_bytes(b"binary hash fixture")
        self.module = blocks_pb2.module()
        self.function = self.module.fuc.add(va=0x1000)
        self.block = self.function.bb.add(va=0x1000, parent=0x1000, type=7)
        self.block.instructions.add(va=0x1000, size=2)
        self.block.child.add(va=0x1010)
        self.block.child.add(va=0x1020)

    def analyze(self, rows, **options):
        analyzer = types.SimpleNamespace(analyze_jump_tables=lambda *_: rows)
        with patch.dict(sys.modules, {"jump_table_analysis": analyzer}):
            return refine_jump_tables(str(self.binary), self.module, **options)

    def test_unresolved_table_preserves_targets_and_records_limitation(self):
        report = self.analyze([])
        self.assertEqual([c.va for c in self.block.child], [0x1010, 0x1020])
        self.assertEqual(report["unresolved_physical_tables"], 1)
        self.assertEqual(report["sites"][0]["action"], "preserved_physical_table")
        self.assertEqual(report["binary_sha256"], sha256_file(self.binary))

    def test_strict_failure_does_not_partially_modify_protobuf(self):
        another = self.function.bb.add(va=0x1040, parent=0x1000, type=6)
        another.instructions.add(va=0x1040, size=2)
        before = self.module.SerializeToString()
        with self.assertRaisesRegex(ValueError, "lack selector evidence"):
            self.analyze([{"site": 0x1040, "status": "resolved", "targets": [0x1010]}],
                         require_resolved=True)
        self.assertEqual(before, self.module.SerializeToString())

    def test_strict_mode_rejects_physical_table_without_instruction(self):
        self.block.ClearField("instructions")
        before = self.module.SerializeToString()
        with self.assertRaisesRegex(ValueError, "lack a terminating instruction"):
            self.analyze([], require_resolved=True)
        self.assertEqual(before, self.module.SerializeToString())

    def test_nonstrict_report_retains_malformed_table_without_inventing_site(self):
        self.block.ClearField("instructions")
        before = self.module.SerializeToString()
        report = self.analyze([])
        self.assertEqual(before, self.module.SerializeToString())
        self.assertEqual(report["sites"], [])
        self.assertEqual(report["unresolved_physical_tables"], 1)
        self.assertEqual(report["malformed_physical_tables"], [{
            "function": 0x1000, "block": 0x1000,
            "reason": "physical jump table has no terminating instruction",
        }])

    def test_resolved_targets_replace_children_and_promote(self):
        self.block.type = 6
        report = self.analyze([{"site": 0x1000, "status": "resolved", "targets": [0x1010, 0x1010]}])
        self.assertEqual([c.va for c in self.block.child], [0x1010])
        self.assertEqual(self.block.type, 7)
        self.assertEqual(report["sites"][0]["action"], "promoted")

    def test_empty_resolved_set_is_an_error(self):
        before = self.module.SerializeToString()
        with self.assertRaisesRegex(ValueError, "no targets"):
            self.analyze([{"site": 0x1000, "status": "resolved", "targets": []}])
        self.assertEqual(before, self.module.SerializeToString())

    def test_missing_metadata_does_not_partially_modify_protobuf(self):
        before = self.module.SerializeToString()
        with self.assertRaises(FileNotFoundError):
            self.analyze([{"site": 0x1000, "status": "resolved", "targets": [0x1010]}],
                         metadata=str(Path(self.directory.name) / "missing.metadata"))
        self.assertEqual(before, self.module.SerializeToString())

    def test_duplicate_site_with_unresolved_analysis_preserves_physical_targets(self):
        for rows in (
                [{"site": 0x1000, "status": "unresolved", "reason": "unknown predecessor"},
                 {"site": 0x1000, "status": "resolved", "targets": [0x1010]}],
                [{"site": 0x1000, "status": "resolved", "targets": [0x1010]},
                 {"site": 0x1000, "status": "unresolved", "reason": "unknown predecessor"}]):
            report = self.analyze(rows)
            self.assertEqual([c.va for c in self.block.child], [0x1010, 0x1020])
            self.assertEqual(report["unresolved_physical_tables"], 1)
            self.assertEqual(len(report["sites"][0]["evidence"]["analyses"]), 2)
            with self.assertRaisesRegex(ValueError, "lack selector evidence"):
                self.analyze(rows, require_resolved=True)

    def test_duplicate_resolved_site_unions_all_proven_domains(self):
        report = self.analyze([
            {"site": 0x1000, "status": "resolved", "targets": [0x1010]},
            {"site": 0x1000, "status": "resolved", "targets": [0x1020]},
        ])
        self.assertEqual([c.va for c in self.block.child], [0x1010, 0x1020])
        self.assertEqual(len(report["sites"][0]["evidence"]["analyses"]), 2)

    def test_artifact_write_retains_report_and_protobuf(self):
        output = str(Path(self.directory.name) / "output.pb")
        report = self.analyze([])
        write_outputs(self.module, output, report)
        self.assertEqual(Path(output).read_bytes(), self.module.SerializeToString())
        self.assertEqual(json.loads(Path(output + ".jumptables.json").read_text()), report)
        self.assertEqual(report["protobuf_sha256"],
                         hashlib.sha256(self.module.SerializeToString()).hexdigest())
        with self.assertRaisesRegex(ValueError, "must differ"):
            write_outputs(self.module, output, report, output)

    def test_failed_replacement_restores_both_old_artifacts(self):
        output = Path(self.directory.name) / "output.pb"
        sidecar = Path(str(output) + ".jumptables.json")
        output.write_bytes(b"previous protobuf")
        sidecar.write_bytes(b"previous audit")
        report = self.analyze([])
        real_replace = os.replace
        for fail_on in (1, 2):
            calls = []

            def fail_replace(source, target):
                calls.append(target)
                if len(calls) == fail_on:
                    raise OSError("injected replacement failure")
                real_replace(source, target)

            with self.subTest(fail_on=fail_on):
                with patch("jump_table_gt.os.replace", side_effect=fail_replace):
                    with self.assertRaisesRegex(OSError, "injected"):
                        write_outputs(self.module, output, report)
                self.assertEqual(output.read_bytes(), b"previous protobuf")
                self.assertEqual(sidecar.read_bytes(), b"previous audit")
                self.assertEqual({path.name for path in output.parent.iterdir()},
                                 {"binary", "output.pb", "output.pb.jumptables.json"})

    def test_failed_protobuf_replace_removes_new_sidecar(self):
        output = Path(self.directory.name) / "output.pb"
        output.write_bytes(b"previous protobuf")
        real_replace = os.replace

        def fail_output_replace(source, target):
            if target == str(output):
                raise OSError("injected protobuf failure")
            real_replace(source, target)

        with patch("jump_table_gt.os.replace", side_effect=fail_output_replace):
            with self.assertRaisesRegex(OSError, "injected"):
                write_outputs(self.module, output, self.analyze([]))
        self.assertEqual(output.read_bytes(), b"previous protobuf")
        self.assertFalse(Path(str(output) + ".jumptables.json").exists())

    def test_failed_rollback_keeps_last_backup_for_recovery(self):
        output = Path(self.directory.name) / "output.pb"
        sidecar = Path(str(output) + ".jumptables.json")
        output.write_bytes(b"previous protobuf")
        sidecar.write_bytes(b"previous audit")
        real_replace = os.replace
        calls = []

        def fail_after_first_replace(source, target):
            calls.append(target)
            if len(calls) > 1:
                raise OSError("injected replacement and rollback failure")
            real_replace(source, target)

        with patch("jump_table_gt.os.replace", side_effect=fail_after_first_replace):
            with self.assertRaisesRegex(OSError, "rollback failed"):
                write_outputs(self.module, output, self.analyze([]))
        self.assertEqual(output.read_bytes(), b"previous protobuf")
        backups = [path for path in output.parent.iterdir()
                   if path.name not in {"binary", output.name, sidecar.name}]
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), b"previous audit")


@unittest.skipUnless(shutil.which("cc") and shutil.which("nm"), "requires cc and nm")
class AuditedSelectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        directory = Path(cls.directory.name)
        assembly = directory / "table.s"
        assembly.write_text("""
.text
.global _start, dispatch, case_a, case_b, case_c, table, table_second
_start:
  lea table(%rip), %rdx
  movslq (%rdx,%rax,4), %rax
  add %rdx, %rax
dispatch:
  jmp *%rax
case_a:
  nop
  ret
case_b:
  nop
  ret
case_c:
  nop
  ret
  .space 16, 0x90
.section .rodata
table:
  .long case_a-table, case_b-table, case_a-table
table_second:
  .long case_b-table_second, case_c-table_second
.section .note.GNU-stack,"",@progbits
""")
        cls.binary = directory / "table"
        subprocess.run(["cc", "-nostdlib", "-no-pie", str(assembly), "-o", str(cls.binary)],
                       check=True, capture_output=True)
        symbols = subprocess.check_output(["nm", str(cls.binary)], text=True)
        cls.addresses = {parts[2]: int(parts[0], 16) for line in symbols.splitlines()
                         if len(parts := line.split()) == 3}
        end_assembly = directory / "end_table.s"
        end_assembly.write_text(assembly.read_text().replace(
            "dispatch:\n  jmp *%rax\n", "  jmp dispatch\n").replace(
            "  .space 16, 0x90", "dispatch:\n  jmp *%rax"))
        cls.end_binary = directory / "end_table"
        subprocess.run(["cc", "-nostdlib", "-no-pie", str(end_assembly), "-o", str(cls.end_binary)],
                       check=True, capture_output=True)
        symbols = subprocess.check_output(["nm", str(cls.end_binary)], text=True)
        cls.end_addresses = {parts[2]: int(parts[0], 16) for line in symbols.splitlines()
                             if len(parts := line.split()) == 3}

    def setUp(self):
        self.module = blocks_pb2.module()
        function = self.module.fuc.add(va=self.addresses["_start"])
        for name in ["dispatch", "case_a", "case_b", "case_c"]:
            block = function.bb.add(va=self.addresses[name], parent=function.va)
            block.instructions.add(va=block.va, size=2 if name == "dispatch" else 1)
        self.manifest = {"schema_version": 1, "binary_sha256": sha256_file(self.binary),
                         "sites": [{"site": self.addresses["dispatch"], "switch_only": True,
                                    "table_address": self.addresses["table"], "entry_size": 4,
                                    "entry_encoding": "signed_relative",
                                    "relative_base": self.addresses["table"],
                                    "selector_values": [0, 2],
                                    "evidence": "fixture source audit excludes selector 1"}]}
        self.path = Path(self.directory.name) / "certificate.json"

    def read(self):
        self.path.write_text(json.dumps(self.manifest))
        return read_certificates(str(self.path), str(self.binary), self.module)

    def test_signed_entries_decoded_from_binary_and_duplicates_collapsed(self):
        records = self.read()
        row = records[self.addresses["dispatch"]]
        self.assertEqual(row["targets"], [self.addresses["case_a"]])
        self.assertEqual(row["evidence"]["scope"], "audited_source_invariant")

    def multi_table_manifest(self):
        self.manifest["schema_version"] = 2
        certificate = self.manifest["sites"][0]
        fields = ("table_address", "entry_size", "entry_encoding", "relative_base", "selector_values")
        first = {key: certificate.pop(key) for key in fields}
        second = dict(first, table_address=self.addresses["table_second"],
                      relative_base=self.addresses["table_second"], selector_values=[0, 1])
        certificate["tables"] = [first, second]
        certificate["source_contract"] = ["Correct compilation and defined C execution"]
        return certificate

    def test_multiple_stage_tables_include_later_only_target(self):
        certificate = self.multi_table_manifest()
        row = self.read()[self.addresses["dispatch"]]
        self.assertEqual(row["targets"], [self.addresses[name] for name in ("case_a", "case_b", "case_c")])
        self.assertEqual(row["evidence"]["validation_status"], "source_validated")
        self.assertEqual(row["evidence"]["source_contract"], certificate["source_contract"])
        self.assertEqual(len(row["evidence"]["tables"]), 2)

    def test_source_contract_required_for_v2(self):
        certificate = self.multi_table_manifest()
        for contract in (None, [], "defined C", [""]):
            certificate["source_contract"] = contract
            with self.subTest(contract=contract), self.assertRaisesRegex(ValueError, "source_contract"):
                self.read()

    def test_empty_stage_tables_rejected(self):
        self.multi_table_manifest()["tables"] = []
        with self.assertRaisesRegex(ValueError, "1..64 tables"):
            self.read()

    def test_mixed_schema_table_fields_rejected(self):
        self.multi_table_manifest()["selector_values"] = [0]
        with self.assertRaisesRegex(ValueError, "inside tables"):
            self.read()

    def test_invalid_later_table_rejects_before_mutation(self):
        self.multi_table_manifest()["tables"][1]["selector_values"] = [0x100000]
        self.path.write_text(json.dumps(self.manifest))
        before = self.module.SerializeToString()
        analyzer = types.SimpleNamespace(analyze_jump_tables=lambda *_: [])
        with patch.dict(sys.modules, {"jump_table_analysis": analyzer}):
            with self.assertRaisesRegex(ValueError, "outside file-backed"):
                refine_jump_tables(self.binary, self.module, certificates=self.path)
        self.assertEqual(self.module.SerializeToString(), before)

    def test_source_override_retains_unresolved_binary_status(self):
        self.multi_table_manifest()
        self.path.write_text(json.dumps(self.manifest))
        site = self.addresses["dispatch"]
        unresolved = {"site": site, "status": "unresolved", "targets": [],
                      "reason": "fallback crosses an unknown call"}
        analyzer = types.SimpleNamespace(analyze_jump_tables=lambda *_: [unresolved])
        with patch.dict(sys.modules, {"jump_table_analysis": analyzer}):
            report = refine_jump_tables(self.binary, self.module, certificates=self.path)
        row = report["sites"][0]
        self.assertEqual(row["binary_analysis"], unresolved)
        self.assertEqual(row["status"], "resolved")
        self.assertEqual(row["evidence"]["validation_status"], "source_validated")
        self.assertEqual(self.module.fuc[0].bb[0].type, 7)

    def test_source_override_records_missing_binary_analysis(self):
        self.multi_table_manifest()
        self.path.write_text(json.dumps(self.manifest))
        analyzer = types.SimpleNamespace(analyze_jump_tables=lambda *_: [])
        with patch.dict(sys.modules, {"jump_table_analysis": analyzer}):
            report = refine_jump_tables(self.binary, self.module, certificates=self.path)
        self.assertEqual(report["sites"][0]["binary_analysis"]["status"], "unresolved")

    def test_stale_certificate_rejected(self):
        self.manifest["binary_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.read()

    def test_binary_audit_is_distinguished_from_source_invariant(self):
        self.manifest["sites"][0]["evidence_kind"] = "binary_audit"
        row = self.read()[self.addresses["dispatch"]]
        self.assertEqual(row["evidence"]["scope"], "audited_binary_domain")

    def test_non_jump_site_rejected(self):
        self.manifest["sites"][0]["site"] = self.addresses["case_a"]
        with self.assertRaisesRegex(ValueError, "not an indirect jump"):
            self.read()

    def test_out_of_segment_selector_rejected(self):
        self.manifest["sites"][0]["selector_values"] = [0x100000]
        with self.assertRaisesRegex(ValueError, "outside file-backed"):
            self.read()

    def test_source_evidence_required(self):
        self.manifest["sites"][0]["evidence"] = ""
        with self.assertRaisesRegex(ValueError, "audit reference"):
            self.read()

    def test_duplicate_certificate_rejected(self):
        self.manifest["sites"].append(dict(self.manifest["sites"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate certificate"):
            self.read()

    def test_fractional_addresses_and_selectors_rejected(self):
        for key in ("site", "table_address", "entry_size", "relative_base"):
            with self.subTest(key=key):
                original = self.manifest["sites"][0][key]
                self.manifest["sites"][0][key] = original + 0.5
                with self.assertRaisesRegex(ValueError, "must be integers"):
                    self.read()
                self.manifest["sites"][0][key] = original
        self.manifest["sites"][0]["selector_values"] = [0.5, 2]
        with self.assertRaisesRegex(ValueError, "must be integers"):
            self.read()

    def test_boolean_schema_version_rejected(self):
        self.manifest["schema_version"] = True
        with self.assertRaisesRegex(ValueError, "schema"):
            self.read()

    def test_indirect_jump_at_end_of_executable_segment(self):
        self.binary = self.end_binary
        function = self.module.fuc[0]
        function.va = self.end_addresses["_start"]
        for block, name in zip(function.bb, ["dispatch", "case_a", "case_b", "case_c"]):
            block.va = self.end_addresses[name]
            block.parent = function.va
            block.instructions[0].va = block.va
        self.manifest["binary_sha256"] = sha256_file(self.binary)
        certificate = self.manifest["sites"][0]
        certificate["site"] = self.end_addresses["dispatch"]
        certificate["table_address"] = self.end_addresses["table"]
        certificate["relative_base"] = self.end_addresses["table"]
        for size in (2, 0):
            with self.subTest(instruction_size=size):
                function.bb[0].instructions[0].size = size
                result = self.read()
                self.assertEqual(result[certificate["site"]]["targets"],
                                 [self.end_addresses["case_a"]])


if __name__ == "__main__":
    unittest.main()
