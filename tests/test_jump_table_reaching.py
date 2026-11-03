"""Instruction-level regressions for entry-reaching CFG closure proofs."""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from elftools.elf.elffile import ELFFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'extract_gt'))
import jump_table_analysis as analysis
from jump_table_reaching import recover_reaching_tables
from jump_table_dataflow import function_dataflow


ASSEMBLY = r'''
.text
.global _start
.type _start,@function
_start: ret
.size _start,.-_start

.global reused
.type reused,@function
reused:
 and $1,%edi
 lea reuse_a(%rip),%r13
reuse_first:
 movslq (%r13,%rdi,4),%rax
 add %r13,%rax
reuse_first_site: jmp *%rax
reuse_a0:
 lea reuse_b(%rip),%r13
 jmp reuse_second
reuse_a1:
 lea reuse_b(%rip),%r13
reuse_second:
 and $1,%edi
 movslq (%r13,%rdi,4),%rax
 add %r13,%rax
reuse_second_site: jmp *%rax
reuse_b0: ret
reuse_b1: ret
.size reused,.-reused

.global stable_loop
.type stable_loop,@function
stable_loop:
 lea stable_table(%rip),%r13
stable_head:
 and $1,%edi
 movslq (%r13,%rdi,4),%rax
 add %r13,%rax
stable_site: jmp *%rax
stable_a:
 test %esi,%esi
 jne stable_head
 ret
stable_b:
 xor %edi,%edi
 jmp stable_head
.size stable_loop,.-stable_loop

.global clobber_loop
.type clobber_loop,@function
clobber_loop:
 lea clobber_table(%rip),%r13
clobber_head:
 and $1,%edi
 movslq (%r13,%rdi,4),%rax
 add %r13,%rax
clobber_site: jmp *%rax
clobber_a:
 mov %rsi,%r13
 jmp clobber_head
clobber_b: ret
.size clobber_loop,.-clobber_loop

.global unknown_frontier
.type unknown_frontier,@function
unknown_frontier:
 test %esi,%esi
 jne unknown_site
 and $1,%edi
 lea unknown_table(%rip),%r13
 movslq (%r13,%rdi,4),%rax
 add %r13,%rax
known_site: jmp *%rax
unknown_a: ret
unknown_b: ret
unknown_site: jmp *%r11
.size unknown_frontier,.-unknown_frontier

.global unknown_predecessor
.type unknown_predecessor,@function
unknown_predecessor:
 test %esi,%esi
 jne unknown_join
 lea predecessor_table(%rip),%r13
unknown_join:
 and $1,%edi
 movslq (%r13,%rdi,4),%rax
 add %r13,%rax
unknown_join_site: jmp *%rax
predecessor_a: ret
predecessor_b: ret
.size unknown_predecessor,.-unknown_predecessor

.global call_clobber
.type call_clobber,@function
call_clobber:
 lea call_table(%rip),%r8
 call leaf
 and $1,%edi
 movslq (%r8,%rdi,4),%rax
 add %r8,%rax
call_site: jmp *%rax
call_a: ret
call_b: ret
.size call_clobber,.-call_clobber

.global copied_byte
.type copied_byte,@function
copied_byte:
 movzbl (%rdi),%eax
 mov %eax,%ecx
 and $15,%cl
 cmp $13,%cl
 ja copied_out
 and $15,%eax
 lea copied_table(%rip),%rbx
 movslq (%rbx,%rax,4),%rax
 add %rbx,%rax
copied_site: jmp *%rax
copied_a: ret
copied_b: ret
copied_out: ret
.size copied_byte,.-copied_byte

.type leaf,@function
leaf: ret
.size leaf,.-leaf

.section .rodata
.align 4
reuse_a: .long reuse_a0-reuse_a,reuse_a1-reuse_a
reuse_b: .long reuse_b0-reuse_b,reuse_b1-reuse_b
stable_table: .long stable_a-stable_table,stable_b-stable_table
clobber_table: .long clobber_a-clobber_table,clobber_b-clobber_table
unknown_table: .long unknown_a-unknown_table,unknown_b-unknown_table
predecessor_table: .long predecessor_a-predecessor_table,predecessor_b-predecessor_table
call_table: .long call_a-call_table,call_b-call_table
copied_table:
 .rept 7
 .long copied_a-copied_table,copied_b-copied_table
 .endr
 # Adjacent data is deliberately not a code target. The byte guard must also
 # restrict the equivalent wider selector before these words are consumed.
 .long 0x12345678,0x76543210
.section .note.GNU-stack,"",@progbits
'''


@unittest.skipUnless(shutil.which('as') and shutil.which('ld'), 'GNU assembler/linker required')
class JumpTableReachingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        directory = Path(cls.temp.name)
        source, obj, binary = directory / 'input.s', directory / 'input.o', directory / 'input'
        source.write_text(ASSEMBLY)
        subprocess.run(['as', '--64', '-o', str(obj), str(source)], check=True)
        subprocess.run(['ld', '-o', str(binary), str(obj)], check=True)
        cls.image = analysis._Image(str(binary))
        cls.functions = {}
        with binary.open('rb') as stream:
            symbols = list(ELFFile(stream).get_section_by_name('.symtab').iter_symbols())
            cls.addresses = {symbol.name: int(symbol['st_value']) for symbol in symbols}
            for symbol in symbols:
                if symbol['st_info']['type'] != 'STT_FUNC':
                    continue
                address, size = int(symbol['st_value']), int(symbol['st_size'])
                instructions = [SimpleNamespace(va=ins.address, size=ins.size)
                                for ins in cls.image.md.disasm(cls.image.read(address, size), address)]
                cls.functions[symbol.name] = SimpleNamespace(
                    va=address, type=0, bb=[SimpleNamespace(
                        va=address, instructions=instructions, child=[], type=0)])

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def function(self, name, external_entries=()):
        return analysis._Function(self.functions[name], self.image,
                                  {f.va for f in self.functions.values()}, external_entries)

    def recover(self, function, **kwargs):
        return recover_reaching_tables(function, analysis._analyze_site, analysis._State,
                                       analysis._indirect, analysis.Unresolved, **kwargs)

    def assert_targets(self, result, site, *targets):
        self.assertEqual(result['status'], 'closed', result)
        record = next(record for record in result['records']
                      if record['site'] == self.addresses[site])
        self.assertEqual(set(record['targets']), {self.addresses[name] for name in targets})
        self.assertEqual(record['evidence']['reaching_definitions']['scope'],
                         'entry_reachable_closed_cfg')

    def test_register_reused_for_distinct_dispatch_regions(self):
        result = self.recover(self.function('reused'))
        self.assert_targets(result, 'reuse_first_site', 'reuse_a0', 'reuse_a1')
        self.assert_targets(result, 'reuse_second_site', 'reuse_b0', 'reuse_b1')
        self.assertGreaterEqual(result['proof']['iterations'], 3)

    def test_missing_switch_backedges_are_added_and_revalidated(self):
        result = self.recover(self.function('stable_loop'))
        self.assert_targets(result, 'stable_site', 'stable_a', 'stable_b')
        self.assertGreaterEqual(result['proof']['iterations'], 2)

    def test_new_backedge_can_invalidate_a_provisional_table(self):
        result = self.recover(self.function('clobber_loop'))
        self.assertEqual(result['status'], 'unresolved')
        self.assertEqual(result['records'], [])
        self.assertEqual(result['unresolved_frontiers'][0]['site'], self.addresses['clobber_site'])

    def test_unknown_reachable_frontier_blocks_partial_publication(self):
        result = self.recover(self.function('unknown_frontier'))
        self.assertEqual(result['status'], 'unresolved')
        self.assertEqual(result['records'], [])
        self.assertIn(self.addresses['unknown_site'],
                      {item['site'] for item in result['unresolved_frontiers']})

    def test_unknown_incoming_state_is_not_discarded(self):
        result = self.recover(self.function('unknown_predecessor'))
        self.assertEqual(result['status'], 'unresolved')
        self.assertEqual(result['records'], [])

    def test_call_clobbers_caller_saved_table_base(self):
        result = self.recover(self.function('call_clobber'))
        self.assertEqual(result['status'], 'unresolved')
        self.assertEqual(result['records'], [])

    def test_budgets_do_not_publish_unvalidated_discoveries(self):
        for kwargs in ({'max_rounds': 1}, {'max_steps': 1}):
            with self.subTest(kwargs=kwargs):
                result = self.recover(self.function('reused'), **kwargs)
                self.assertEqual(result['status'], 'unresolved')
                self.assertEqual(result['records'], [])

    def test_provisional_edges_do_not_mutate_original_metadata(self):
        function = self.function('reused')
        before = {site: set(targets) for site, targets in function.known_edges.items()}
        self.assertEqual(self.recover(function)['status'], 'closed')
        self.assertEqual(dict(function.known_edges), before)
        self.assertEqual(self.recover(function, max_rounds=1)['status'], 'unresolved')

    def test_recorded_external_entry_rejects_the_entry_proof(self):
        function = self.function('reused', [self.addresses['reuse_second']])
        result = self.recover(function)
        self.assertEqual(result['status'], 'unresolved')
        self.assertEqual(result['records'], [])

    def test_copied_byte_guard_constrains_equivalent_wide_mask(self):
        result = self.recover(self.function('copied_byte'))
        self.assert_targets(result, 'copied_site', 'copied_a', 'copied_b')

    def test_metadata_covered_frontier_retains_failed_replay_evidence(self):
        function = self.function('unknown_frontier')
        site = self.addresses['unknown_site']
        function.known_edges[site].add(self.addresses['unknown_a'])
        function.rebuild_graph()
        result = self.recover(function)
        self.assertEqual(result['status'], 'closed', result)
        self.assertEqual(result['unresolved_frontiers'], [])
        self.assertIn(site, {item['site'] for item in result['replay_failures']})
        self.assertEqual(result['proof']['replay_failures'], result['replay_failures'])

    def test_frame_proof_retains_replayable_input_snapshots(self):
        result = self.recover(self.function('reused'), dataflow=function_dataflow)
        self.assert_targets(result, 'reuse_second_site', 'reuse_b0', 'reuse_b1')
        self.assertTrue(result['proof']['frame_inputs'])
        entry = next(item for item in result['proof']['frame_inputs']
                     if item['block'] == self.addresses['reused'])
        self.assertIn('rsp', entry['registers'])

    def test_frame_budget_reason_is_preserved(self):
        result = self.recover(self.function('reused'), dataflow=function_dataflow, max_steps=1)
        self.assertEqual(result['status'], 'unresolved')
        self.assertEqual(result['reason'], 'frame dataflow fixed point exceeded its budget')
        self.assertEqual(result['records'], [])


if __name__ == '__main__':
    unittest.main()
