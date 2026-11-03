"""End-to-end checks for the build-bound source proof provider."""

from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest

import capstone
from capstone import x86_const as x86
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "extract_gt"))

from jump_table_proofs import apply_source_facts
from jump_table_proofs import proof_requests
from jump_table_source import analyze_source_build


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@unittest.skipUnless(shutil.which("cc"), "C compiler required")
class SourceProviderTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="jump-table-source-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def compile(self, source, name, options=("-O1", "-g", "-no-pie")):
        source_path = self.root / (name + ".c")
        binary = self.root / name
        source_path.write_text(source)
        build = subprocess.run(("cc", *options, str(source_path), "-o", str(binary)),
                               capture_output=True, text=True)
        if build.returncode:
            self.fail(build.stderr)
        return source_path, binary

    def manifest(self, binary, source, definitions=None, linked=()):
        path = self.root / "source-build.json"
        path.write_text(json.dumps({
            "schema_version": 1,
            "builds": [{
                "binary_sha256": sha256(binary),
                "source_root": str(self.root),
                "source_files": [Path(source).name],
                "definitions": definitions or {},
                "compile_commands": ["cc " + " ".join((str(source), "-o", str(binary)))],
                "linked_inputs": list(linked),
            }],
        }))
        return path

    def function(self, binary, name):
        with binary.open("rb") as stream:
            elf = ELFFile(stream)
            symbols = [symbol for symbol in elf.get_section_by_name(".symtab").iter_symbols()
                       if symbol.name == name]
        self.assertEqual(1, len(symbols))
        return int(symbols[0]["st_value"]), int(symbols[0]["st_size"])

    def indirect_sites(self, binary, start, size):
        with binary.open("rb") as stream:
            elf = ELFFile(stream)
            text = elf.get_section_by_name(".text")
            raw = text.data()
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        sites = []
        for instruction in decoder.disasm(raw, text["sh_addr"]):
            if (start <= instruction.address < start + size and instruction.mnemonic == "jmp"
                    and instruction.operands
                    and instruction.operands[0].type == x86.X86_OP_REG):
                sites.append(instruction.address)
        return sites

    def test_computed_goto_shared_source_dispatch_replays_original_bytes(self):
        source, binary = self.compile('''
            int dispatch(int stage, int value) {
                static const long long first[] = {
                    (long long)&&fallback - (long long)&&fallback,
                    (long long)&&case_zero - (long long)&&fallback,
                    (long long)&&case_one - (long long)&&fallback,
                    (long long)&&case_two - (long long)&&fallback,
                };
                static const long long second[] = {
                    (long long)&&fallback - (long long)&&fallback,
                    (long long)&&case_two - (long long)&&fallback,
                    (long long)&&case_zero - (long long)&&fallback,
                    (long long)&&case_one - (long long)&&fallback,
                };
                char *ptr;
                long long offset;
                if (stage == 0) {
                    offset = value < 0 || value > 2
                        ? (long long)&&fallback - (long long)&&fallback : first[value];
                    ptr = (char *)&&fallback + offset;
                    goto *ptr;
                }
                offset = value < 0 || value > 2
                    ? (long long)&&fallback - (long long)&&fallback : second[value];
                ptr = (char *)&&fallback + offset;
                goto *ptr;
            case_zero: return 10;
            case_one: return 21;
            case_two: return 32;
            fallback: return -1;
            }
            int main(void) { return dispatch(0, 0); }
        ''', "computed")
        start, size = self.function(binary, "dispatch")
        sites = self.indirect_sites(binary, start, size)
        self.assertEqual(1, len(sites), "fixture must optimize both source dispatches together")
        request = {"kind": "computed_goto_dispatch", "site": sites[0],
                   "function": start, "request_id": "fixture"}
        result = analyze_source_build(self.manifest(binary, source), binary, [request])
        self.assertEqual([], result["unresolved_requests"])
        self.assertEqual([sites[0]], result["proved_sites"], result["facts"])
        fact = result["facts"][0]
        self.assertEqual({"first": 1, "second": 1}, fact["table_dispatch_uses"])
        self.assertEqual("fallback", fact["fallback"]["source_label"])
        record = {"site": sites[0], "status": "unresolved", "targets": [],
                  "reason": "fixture request", "evidence": {"function": start}}
        replay = apply_source_facts([record], result["facts"], binary)
        self.assertEqual("resolved", replay[0]["status"])
        self.assertEqual("combined_binary_source", replay[0]["proof_mode"])
        self.assertEqual(sorted(fact["targets"]), replay[0]["targets"])

    def test_changed_fallback_expression_stays_unresolved(self):
        source, binary = self.compile('''
            int dispatch(int stage, int value) {
                static const long long first[] = {
                    (long long)&&fallback - (long long)&&fallback,
                    (long long)&&alternate - (long long)&&fallback,
                    (long long)&&case_zero - (long long)&&fallback,
                    (long long)&&case_one - (long long)&&fallback,
                    (long long)&&case_two - (long long)&&fallback,
                };
                static const long long second[] = {
                    (long long)&&fallback - (long long)&&fallback,
                    (long long)&&case_two - (long long)&&fallback,
                    (long long)&&case_zero - (long long)&&fallback,
                    (long long)&&case_one - (long long)&&fallback,
                };
                char *ptr;
                long long offset;
                if (stage == 0) {
                    offset = value < 0 || value > 2
                        ? (long long)&&alternate - (long long)&&fallback : first[value];
                    ptr = (char *)&&fallback + offset;
                    goto *ptr;
                }
                offset = value < 0 || value > 2
                    ? (long long)&&fallback - (long long)&&fallback : second[value];
                ptr = (char *)&&fallback + offset;
                goto *ptr;
            case_zero: return 10;
            case_one: return 21;
            case_two: return 32;
            fallback: return -1;
            alternate: return -2;
            }
            int main(void) { return dispatch(0, 0); }
        ''', "changed-fallback")
        start, size = self.function(binary, "dispatch")
        sites = self.indirect_sites(binary, start, size)
        self.assertEqual(1, len(sites))
        request = {"kind": "computed_goto_dispatch", "site": sites[0],
                   "function": start, "request_id": "fixture"}
        result = analyze_source_build(self.manifest(binary, source), binary, [request])
        fact = result["facts"][0]
        self.assertEqual("unresolved", fact["status"])
        self.assertIn("different fallback expressions", fact["reason"])
        replay = apply_source_facts([{"site": sites[0], "status": "unresolved", "targets": [],
                                      "evidence": {}}], result["facts"], binary)
        self.assertEqual("unresolved", replay[0]["status"])

    def test_writable_object_without_getter_and_rejects_mutation(self):
        source = '''
            unsigned int packed_values[] = {0x2000, 0x46000, 0x62000};
            int packed_selector(int index) {
                return (packed_values[index] >> 13) & 7;
            }
            int main(void) { return packed_selector(0); }
        '''
        source_path, binary = self.compile(source, "packed", ("-O2", "-g", "-no-pie"))
        with binary.open("rb") as stream:
            elf = ELFFile(stream)
            symbol = next(item for item in elf.get_section_by_name(".symtab").iter_symbols()
                          if item.name == "packed_values")
            table = int(symbol["st_value"])
        request = {"kind": "writable_object_invariant", "site": 0x1000,
                   "function": 0x1000, "table_address": table, "entry_size": 4,
                   "entry_count": 3, "obligations": ["index_bounds", "data_stability"],
                   "request_id": "fixture"}
        result = analyze_source_build(self.manifest(binary, source_path, linked=[binary.name]),
                                      binary, [request])
        self.assertEqual([], result["unresolved_requests"])
        self.assertEqual("proved", result["facts"][0]["status"], result["facts"][0])
        self.assertEqual([], result["facts"][0]["linked_evidence"]["getter_references"])

        mutated = source.replace("return (packed_values[index] >> 13) & 7;",
                                 "packed_values[index] = 0; return 0;")
        source_path, binary = self.compile(mutated, "packed-mutated", ("-O2", "-g", "-no-pie"))
        with binary.open("rb") as stream:
            elf = ELFFile(stream)
            symbol = next(item for item in elf.get_section_by_name(".symtab").iter_symbols()
                          if item.name == "packed_values")
            request["table_address"] = int(symbol["st_value"])
        result = analyze_source_build(self.manifest(binary, source_path, linked=[binary.name]),
                                      binary, [request])
        self.assertEqual("unresolved", result["facts"][0]["status"])
        self.assertIn("write or pointer escape", result["facts"][0]["reason"])

    def test_pointer_escape_rejects_without_a_binary_write(self):
        source, binary = self.compile('''
            unsigned int packed_values[] = {0x2000, 0x46000};
            int packed_selector(int index) {
                unsigned int *escaped = packed_values;
                return (escaped[index] >> 13) & 7;
            }
            int main(void) { return packed_selector(0); }
        ''', "packed-escape", ("-O2", "-g", "-no-pie"))
        with binary.open("rb") as stream:
            elf = ELFFile(stream)
            symbol = next(item for item in elf.get_section_by_name(".symtab").iter_symbols()
                          if item.name == "packed_values")
            request = {"kind": "writable_object_invariant", "site": 0x1000,
                       "function": 0x1000, "table_address": int(symbol["st_value"]),
                       "entry_size": 4, "entry_count": 2,
                       "obligations": ["index_bounds", "data_stability"],
                       "request_id": "fixture"}
        result = analyze_source_build(self.manifest(binary, source, linked=[binary.name]),
                                      binary, [request])
        self.assertEqual("unresolved", result["facts"][0]["status"])
        self.assertIn("write or pointer escape", result["facts"][0]["reason"])

    def test_shared_site_requests_are_deduplicated_across_analyses(self):
        obligations = [{"kind": "loop_transfer", "proved": True, "selectors": [1]},
                       {"kind": "data_stability", "proved": False}]
        proof = {"table_address": 0x2000, "entry_size": 4, "entry_count": 2,
                 "load_instruction": 0x1004, "obligations": obligations}
        rows = [{"site": 0x1000, "status": "unresolved", "targets": [],
                 "evidence": {"function": 0x1000,
                              "writable_selector_data": [dict(proof)]}}
                for _ in range(2)]
        grouped = {"site": 0x1000, "status": "unresolved", "targets": [],
                   "evidence": {"analyses": rows}}
        requests = proof_requests([grouped])
        self.assertEqual(1, len(requests))
        self.assertEqual("writable_object_invariant", requests[0]["kind"])
        self.assertEqual(["data_stability"], requests[0]["obligations"])


if __name__ == "__main__":
    unittest.main()
