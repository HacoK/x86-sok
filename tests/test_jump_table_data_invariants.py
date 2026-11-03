"""Writable initializers never substitute for a runtime selector proof."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

from elftools.elf.elffile import ELFFile

PATH = Path(__file__).resolve().parents[1] / 'extract_gt' / 'jump_table_data_invariants.py'
SPEC = importlib.util.spec_from_file_location('jump_table_data_invariants', PATH)
invariants = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(invariants)


class ShiftLoopTests(unittest.TestCase):
    def test_nonzero_guard_and_all_nibbles_are_required(self):
        result = invariants.shift_loop_domain([0x123 << 13, 0x7654 << 13], 32, 13, 4, 7)
        self.assertEqual(result['selectors'], list(range(1, 8)))
        self.assertEqual(result['status'], 'proved_arithmetic_closure')
        result = invariants.shift_loop_domain([0x10 << 13], 32, 13, 4, 7)
        self.assertIn(0, result['selectors'])
        unguarded = invariants.shift_loop_domain([1 << 13], 32, 13, 4, 7, nonzero_guard=False)
        self.assertEqual(unguarded['selectors'], [0, 1])

    def test_signed_shift_and_flag_clearing_are_included_in_closure(self):
        result = invariants.shift_loop_domain([0x1238 << 13], 32, 13, 4, 7,
                                              clear_masks=[0xfffffff7], loop_signed=True)
        self.assertIn(0, result['selectors'])
        negative = invariants.shift_loop_domain([0xffffffff], 32, 0, 4, 7, loop_signed=True)
        self.assertEqual(negative['selectors'], [7])

    def test_budget_and_malformed_summary_do_not_create_partial_proof(self):
        result = invariants.shift_loop_domain([0x1234], 32, 0, 4, 7, max_states=1)
        self.assertEqual(result['status'], 'unresolved')
        self.assertNotIn('selectors', result)
        with self.assertRaises(ValueError):
            invariants.shift_loop_domain([1], 32, 0, 0, 7)


@unittest.skipUnless(shutil.which('as') and shutil.which('ld'), 'GNU assembler/linker required')
class WritableObjectTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='packed-data-proof-')
        self.addCleanup(self.directory.cleanup)

    def build(self, code, extra_data=''):
        directory = Path(self.directory.name)
        source, obj, binary = directory / 'test.s', directory / 'test.o', directory / 'test'
        source.write_text('''
.text
.global _start
.type _start,@function
_start:
''' + code + '''
.size _start,.-_start
.data
.align 8
.global packed
.type packed,@object
packed: .long 0x246000,0xeca8000
.size packed,.-packed
other: .quad 0
''' + extra_data + '\n.section .note.GNU-stack,"",@progbits\n')
        subprocess.run(['as', '--64', '-o', str(obj), str(source)], check=True, capture_output=True)
        subprocess.run(['ld', '-o', str(binary), str(obj)], check=True, capture_output=True)
        audit = invariants.WritableTableAudit(binary)
        with binary.open('rb') as stream:
            elf = ELFFile(stream)
            symbols = {symbol.name: int(symbol['st_value'])
                       for symbol in elf.get_section_by_name('.symtab').iter_symbols()}
            section = elf.get_section_by_name('.text')
            instructions = {instruction.address: instruction for instruction in
                            audit.decoder.disasm(section.data(), section['sh_addr'])}
        return audit, symbols, SimpleNamespace(instructions=instructions)

    def test_closed_no_write_object_requires_independent_index_bound(self):
        audit, symbols, _ = self.build('and $1,%eax\nmov packed(,%rax,4),%edx\nhlt')
        result = audit.prove_object(symbols['packed'], 4, range(2))
        self.assertEqual(result['status'], 'proved', result)
        self.assertEqual(result['values'], [0x246000, 0xeca8000])
        unknown = audit.prove_object(symbols['packed'], 4)
        self.assertEqual(unknown['status'], 'unresolved')
        self.assertNotIn('values', unknown)
        wide = audit.prove_object(symbols['packed'], 4, range(65536))
        self.assertFalse(next(item for item in wide['obligations'] if item['kind'] == 'index_bounds')['proved'])

    def test_unknown_pointer_store_cannot_be_assumed_disjoint(self):
        audit, symbols, _ = self.build('movl $0,(%rdi)\nhlt')
        result = audit.prove_object(symbols['packed'], 4, range(2))
        self.assertEqual(result['status'], 'unresolved')
        stability = next(item for item in result['obligations'] if item['kind'] == 'data_stability')
        self.assertFalse(stability['proved'])
        self.assertIn('alias', stability['unknown_effects'][0]['reason'])

    def test_direct_overlap_and_proven_disjoint_store_differ(self):
        for target, expected in [('packed', 'unresolved'), ('other', 'proved')]:
            with self.subTest(target=target):
                audit, symbols, _ = self.build('movl $0,' + target + '(%rip)\nhlt')
                self.assertEqual(audit.prove_object(symbols['packed'], 4, range(2))['status'], expected)

    def test_unknown_call_and_materialized_or_stored_pointer_fail_closed(self):
        for code, extra in [('call *%rax\nhlt', ''),
                            ('lea packed(%rip),%rax\nhlt', ''),
                            ('hlt', '.quad packed')]:
            with self.subTest(code=code, extra=extra):
                audit, symbols, _ = self.build(code, extra)
                result = audit.prove_object(symbols['packed'], 4, range(2))
                self.assertEqual(result['status'], 'unresolved')
                self.assertNotIn('values', result)

    def test_mutable_address_return_is_concrete_escape_evidence(self):
        for instruction in ('mov $packed,%eax', 'lea packed(%rip),%rax'):
            with self.subTest(instruction=instruction):
                audit, symbols, _ = self.build(instruction + '\nret')
                returns = audit.pointer_returns(symbols['packed'], 8)
                self.assertEqual(len(returns), 1)
                self.assertEqual(returns[0]['function'], symbols['_start'])
                self.assertEqual(returns[0]['returned_address'], symbols['packed'])
                self.assertFalse(returns[0]['caller_reachability_proved'])
                proof = audit.prove_object(symbols['packed'], 4, range(2))
                escape = next(item for item in proof['obligations'] if item['kind'] == 'no_pointer_escape')
                self.assertFalse(escape['proved'])
                self.assertEqual(escape['pointer_returning_functions'], returns)

    def test_overwritten_or_nonreturning_address_is_not_a_pointer_return(self):
        for code in ('mov $packed,%eax\nxor %eax,%eax\nret',
                     'lea packed(%rip),%rax\nhlt'):
            with self.subTest(code=code):
                audit, symbols, _ = self.build(code)
                self.assertEqual(audit.pointer_returns(symbols['packed'], 8), [])

    def test_discovery_keeps_snapshot_nibbles_separate_from_failed_proofs(self):
        audit, symbols, function = self.build('''
movzwl (%rdi),%eax
mov packed(,%rax,4),%edx
mov %edx,%ebp
shr $13,%ebp
again:
test %ebp,%ebp
je done
mov %ebp,%eax
and $7,%eax
dispatch:
jmp *targets(,%rax,8)
next:
sar $4,%ebp
jmp again
done: hlt
''', '.section .rodata\ntargets: .quad next,next,next,next,next,next,next,next')
        rows = audit.inspect(function, symbols['dispatch'])
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row['status'], 'unresolved')
        self.assertEqual(row['index_source_bits'], 16)
        self.assertEqual(row['snapshot_closure']['status'], 'conditional_initial_bytes')
        self.assertNotIn('selectors', row)
        self.assertNotIn('targets', row)
        failed = {item['kind'] for item in row['obligations'] if not item['proved']}
        self.assertTrue({'index_bounds', 'data_stability', 'loop_transfer'} <= failed)

    def test_full_generation_preserves_eight_targets_and_strict_mode_rejects(self):
        root = PATH.parents[1]
        sys.path.insert(0, str(root / 'extract_gt'))
        sys.path.insert(0, str(root / 'protobuf_def'))
        os.environ.setdefault('PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION', 'python')
        import blocks_pb2
        from jump_table_analysis import analyze_jump_tables
        from jump_table_gt import refine_jump_tables

        cases = '\n'.join('case%d: jmp next' % index for index in range(8))
        targets = ','.join('case%d' % index for index in range(8))
        audit, symbols, decoded = self.build('''
movzwl (%rdi),%eax
mov packed(,%rax,4),%edx
mov %edx,%ebp
shr $13,%ebp
again:
test %ebp,%ebp
je done
mov %ebp,%eax
and $7,%eax
dispatch:
jmp *targets(,%rax,8)
''' + cases + '''
next:
sar $4,%ebp
jmp again
done: hlt
''', '.section .rodata\ntargets: .quad ' + targets)
        module = blocks_pb2.module()
        function = module.fuc.add(va=symbols['_start'])
        physical = [symbols['case%d' % index] for index in range(8)]
        for address, instruction in decoded.instructions.items():
            block = function.bb.add(va=address, parent=function.va, type=0)
            block.instructions.add(va=address, size=instruction.size)
            if address == symbols['dispatch']:
                block.type = 7
                for target in physical:
                    block.child.add(va=target)
        binary = Path(self.directory.name) / 'test'
        rows = analyze_jump_tables(binary, module)
        site = next(row for row in rows if row['site'] == symbols['dispatch'])
        self.assertEqual(site['status'], 'unresolved', site)
        self.assertEqual(site['local_upper_bound'], physical)
        obligations = site['evidence']['writable_selector_data'][0]['obligations']
        failed = {item['kind'] for item in obligations if not item['proved']}
        self.assertTrue({'index_bounds', 'data_stability', 'loop_transfer'} <= failed)
        loop = next(item for item in obligations if item['kind'] == 'loop_transfer')
        self.assertFalse(loop['proved'], loop)
        self.assertEqual(loop['conditional_proof']['status'], 'proved_conditional_loop')
        # This fixture splits CMP and its branch into separate metadata blocks;
        # losing transient flags may widen the conditional result, never narrow
        # the physical output without the independent data proof.
        self.assertEqual(loop['selectors'], list(range(8)))
        before = module.SerializeToString()
        report = refine_jump_tables(binary, module)
        self.assertEqual(module.SerializeToString(), before)
        self.assertEqual(report['unresolved_physical_tables'], 1)
        row = next(row for row in report['sites'] if row['site'] == symbols['dispatch'])
        self.assertEqual(row['action'], 'preserved_physical_table')
        self.assertEqual(row['previous_targets'], physical)
        with self.assertRaisesRegex(ValueError, 'lack selector evidence'):
            refine_jump_tables(binary, module, require_resolved=True)
        self.assertEqual(module.SerializeToString(), before)


if __name__ == '__main__':
    unittest.main()
