"""Frame constants are proved across guards, joins, and binary-checked calls."""
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
from jump_table_dataflow import function_dataflow


ASSEMBLY = r'''
.text
.global _start
.type _start,@function
_start: ret
.size _start,.-_start

.macro begin name
.global \name
.type \name,@function
\name:
 push %rbp
 mov %rsp,%rbp
 sub $32,%rsp
.endm
.macro finish name
 leave
 ret
.size \name,.-\name
.endm

begin guard_spill
 and $2,%edi
 mov %edi,-4(%rbp)
 jne guard_spill_out
 jmp guard_spill_read
guard_spill_read:
 mov -4(%rbp),%r12d
guard_spill_observe:
 nop
guard_spill_out:
finish guard_spill

begin stable_loop
 movl $7,-4(%rbp)
stable_loop_header:
 test %edi,%edi
 jne stable_loop_header
 mov -4(%rbp),%r12d
stable_loop_observe:
finish stable_loop

begin changing_loop
 movl $7,-4(%rbp)
changing_loop_header:
 test %edi,%edi
 je changing_loop_read
 movl $9,-4(%rbp)
 jmp changing_loop_header
changing_loop_read:
 mov -4(%rbp),%r12d
changing_loop_observe:
finish changing_loop

begin overlapping_store
 movl $7,-4(%rbp)
 movb $0,-3(%rbp)
 mov -4(%rbp),%r12d
overlapping_store_observe:
finish overlapping_store

begin unknown_store
 movl $7,-4(%rbp)
 movb $0,(%rdi)
 mov -4(%rbp),%r12d
unknown_store_observe:
finish unknown_store

begin disjoint_store
 movl $7,-4(%rbp)
 movb $0,-8(%rbp)
 jmp disjoint_store_read
disjoint_store_read:
 mov -4(%rbp),%r12d
disjoint_store_observe:
finish disjoint_store

begin escaped_slot
 movl $7,-4(%rbp)
 lea -4(%rbp),%rdi
 call mutates_argument
 mov -4(%rbp),%r12d
escaped_slot_observe:
finish escaped_slot

begin escaped_neighbor
 movl $7,-4(%rbp)
 lea -16(%rbp),%rdi
 call *%rax
 mov -4(%rbp),%r12d
escaped_neighbor_observe:
finish escaped_neighbor

begin pure_call
 movl $7,-4(%rbp)
 mov $11,%r12d
 mov $13,%r10d
 call pure_leaf
pure_call_abi:
 mov -4(%rbp),%r13d
pure_call_observe:
finish pure_call

begin stack_argument
 movl $7,-8(%rsp)
 call pure_leaf
 mov -8(%rsp),%r12d
stack_argument_observe:
finish stack_argument

begin unknown_call
 movl $7,-4(%rbp)
 call *%rax
 mov -4(%rbp),%r12d
unknown_call_observe:
finish unknown_call

begin incompatible_join
 test %edi,%edi
 je incompatible_other
 movl $7,-4(%rbp)
 jmp incompatible_read
incompatible_other:
 movl $9,-4(%rbp)
incompatible_read:
 mov -4(%rbp),%r12d
incompatible_join_observe:
finish incompatible_join

begin carry_guard
 add $2,%edi
 mov %edi,-4(%rbp)
 jae carry_guard_out
 mov -4(%rbp),%r12d
carry_guard_observe:
 nop
carry_guard_out:
finish carry_guard

begin zero_shift
 cmp $0,%esi
 shl $0,%edi
 mov %edi,-4(%rbp)
 jne zero_shift_out
 mov -4(%rbp),%r12d
zero_shift_observe:
 nop
zero_shift_out:
finish zero_shift

begin dynamic_shift
 cmp $0,%esi
 shl %cl,%edi
 mov %edi,-4(%rbp)
 jne dynamic_shift_out
 mov -4(%rbp),%r12d
dynamic_shift_observe:
 nop
dynamic_shift_out:
finish dynamic_shift

begin nonzero_shift
 shl $1,%edi
 mov %edi,-4(%rbp)
 jne nonzero_shift_out
 jmp nonzero_shift_read
nonzero_shift_read:
 mov -4(%rbp),%r12d
nonzero_shift_observe:
 nop
nonzero_shift_out:
finish nonzero_shift

begin partial_pop
 movl $7,(%rsp)
 pop %r12
partial_pop_observe:
finish partial_pop

begin partial_leave
 movl $7,(%rbp)
 leave
partial_leave_observe:
 ret
.size partial_leave,.-partial_leave

begin short_leave
 .byte 0x66,0xc9
short_leave_observe:
 ret
.size short_leave,.-short_leave

begin simd_disjoint
 movl $7,-4(%rbp)
 movdqu (%rdi),%xmm1
 movups %xmm1,-32(%rbp)
 mov -4(%rbp),%r12d
simd_disjoint_observe:
finish simd_disjoint

begin simd_overlap
 movl $7,-4(%rbp)
 movups %xmm1,-16(%rbp)
 mov -4(%rbp),%r12d
simd_overlap_observe:
finish simd_overlap

begin simd_unknown_store
 movl $7,-4(%rbp)
 movups %xmm1,(%rdi)
 mov -4(%rbp),%r12d
simd_unknown_store_observe:
finish simd_unknown_store

begin register_rotate
 movl $7,-4(%rbp)
 mov $11,%eax
 ror $17,%rax
 mov -4(%rbp),%r12d
register_rotate_observe:
finish register_rotate

begin tls_read
 movl $7,-4(%rbp)
 mov %fs:0x30,%rax
 xor %fs:0x30,%rax
 mov -4(%rbp),%r12d
tls_read_observe:
finish tls_read

begin tls_store
 movl $7,-4(%rbp)
 mov %rax,%fs:0x30
 mov -4(%rbp),%r12d
tls_store_observe:
finish tls_store

begin memory_rotate
 movl $7,-4(%rbp)
 rorl $17,(%rdi)
 mov -4(%rbp),%r12d
memory_rotate_observe:
finish memory_rotate

begin segment_write
 movl $7,-4(%rbp)
 mov %ax,%ss
 mov -4(%rbp),%r12d
segment_write_observe:
finish segment_write

begin rotate_flags
 mov $11,%eax
 cmp $0,%edi
 ror $17,%rax
 je rotate_flags_read
 jmp rotate_flags_out
rotate_flags_read:
 mov %eax,%r12d
rotate_flags_observe:
 nop
rotate_flags_out:
finish rotate_flags

.global mutates_argument
.type mutates_argument,@function
mutates_argument:
 movl $99,(%rdi)
 ret
.size mutates_argument,.-mutates_argument

.global pure_leaf
.type pure_leaf,@function
pure_leaf:
 xor %eax,%eax
 ret
.size pure_leaf,.-pure_leaf
.section .note.GNU-stack,"",@progbits
'''


def shared_dispatch(name, count=80, unknown=False):
    lines = ['.text', '.global ' + name, '.type ' + name + ',@function', name + ':']
    for index in range(count - 1):
        lines += ['cmp $%d,%%esi' % index, 'je %s_prepare_%d' % (name, index)]
    lines.append('jmp %s_prepare_%d' % (name, count - 1))
    for index in range(count):
        lines.append('%s_prepare_%d:' % (name, index))
        if unknown and index == count - 1:
            lines += ['mov %rdi,%rax', 'jmp ' + name + '_site']
        else:
            lines += ['cmp $1,%rdi', 'ja ' + name + '_out',
                      'lea ' + name + '_table(%rip),%rcx',
                      'movslq (%rcx,%rdi,4),%rax', 'add %rcx,%rax',
                      'jmp ' + name + '_site']
    lines += [name + '_site: jmp *%rax', name + '_a: ret', name + '_b: ret',
              name + '_out: ret', '.size ' + name + ',.-' + name, '.section .rodata',
              name + '_table:', '.long ' + name + '_a-' + name + '_table',
              '.long ' + name + '_b-' + name + '_table']
    return '\n'.join(lines) + '\n'


ASSEMBLY += shared_dispatch('many_preparations')
ASSEMBLY += shared_dispatch('unknown_preparation', unknown=True)
ASSEMBLY += shared_dispatch('too_many_preparations', count=270)
ASSEMBLY += r'''
.text
begin frame_dispatch
 lea frame_dispatch_table(%rip),%rax
 mov %rax,-16(%rbp)
frame_dispatch_loop:
 test %esi,%esi
 jne frame_dispatch_loop
 mov -16(%rbp),%rcx
 cmp $1,%rdi
 ja frame_dispatch_out
 movslq (%rcx,%rdi,4),%rax
 add %rcx,%rax
frame_dispatch_site:
 jmp *%rax
frame_dispatch_a:
 mov $1,%eax
 jmp frame_dispatch_out
frame_dispatch_b:
 mov $2,%eax
frame_dispatch_out:
finish frame_dispatch
.section .rodata
frame_dispatch_table:
 .long frame_dispatch_a-frame_dispatch_table
 .long frame_dispatch_b-frame_dispatch_table
'''


@unittest.skipUnless(shutil.which('as') and shutil.which('ld'), 'GNU assembler/linker required')
class JumpTableDataflowTests(unittest.TestCase):
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
            elf = ELFFile(stream)
            symbols = list(elf.get_section_by_name('.symtab').iter_symbols())
            cls.addresses = {symbol.name: int(symbol['st_value']) for symbol in symbols}
            for symbol in symbols:
                if symbol['st_info']['type'] != 'STT_FUNC':
                    continue
                address, size = int(symbol['st_value']), int(symbol['st_size'])
                instructions = [SimpleNamespace(va=ins.address, size=ins.size)
                                for ins in cls.image.md.disasm(cls.image.read(address, size), address)]
                block = SimpleNamespace(va=address, instructions=instructions, child=[], type=0)
                cls.functions[symbol.name] = SimpleNamespace(va=address, bb=[block], type=0)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def function(self, name):
        return analysis._Function(self.functions[name], self.image,
                                  {function.va for function in self.functions.values()})

    def observe(self, name, label=None):
        function = self.function(name)
        result = function_dataflow(function, analysis._State)
        self.assertEqual(result.status, 'converged', result.reason)
        address = self.addresses[label or name + '_observe']
        owner = function.owner[address]
        self.assertIn(owner, result.inputs)
        state = result.initial_state(owner)
        for instruction in function.blocks[owner]:
            if instruction.address == address:
                break
            state.step(instruction)
        return state, result

    def test_masked_value_spilled_before_zero_branch_becomes_constant(self):
        state, _ = self.observe('guard_spill')
        self.assertEqual(state.regs['r12'], analysis._const(0, 64))

    def test_loop_without_writes_preserves_slot(self):
        state, _ = self.observe('stable_loop')
        self.assertEqual(state.regs['r12'], analysis._const(7, 64))

    def test_loop_backedge_write_participates_in_join(self):
        state, _ = self.observe('changing_loop')
        self.assertNotEqual(state.regs['r12'], analysis._const(7, 64))

    def test_overlapping_write_invalidates_full_slot(self):
        state, _ = self.observe('overlapping_store')
        self.assertNotEqual(state.regs['r12'], analysis._const(7, 64))

    def test_unknown_pointer_write_invalidates_slot(self):
        state, _ = self.observe('unknown_store')
        self.assertNotEqual(state.regs['r12'], analysis._const(7, 64))

    def test_disjoint_frame_write_survives_block_boundary(self):
        state, _ = self.observe('disjoint_store')
        self.assertEqual(state.regs['r12'], analysis._const(7, 64))

    def test_direct_callee_mutating_argument_pointee_invalidates_slot(self):
        state, result = self.observe('escaped_slot')
        self.assertNotEqual(state.regs['r12'], analysis._const(7, 64))
        self.assertTrue(any(item['effect'] == 'call_invalidates_frame_slots' for item in result.diagnostics))

    def test_escaped_neighbor_address_does_not_prove_disjoint_call_effects(self):
        state, _ = self.observe('escaped_neighbor')
        self.assertNotEqual(state.regs['r12'], analysis._const(7, 64))

    def test_unknown_call_invalidates_even_unescaped_slots(self):
        state, _ = self.observe('unknown_call')
        self.assertNotEqual(state.regs['r12'], analysis._const(7, 64))

    def test_binary_proved_write_free_callee_preserves_slot(self):
        state, result = self.observe('pure_call')
        self.assertEqual(state.regs['r13'], analysis._const(7, 64))
        self.assertTrue(any(item['effect'] == 'binary_proved_write_free_callee' for item in result.diagnostics))

    def test_calls_respect_caller_and_callee_saved_registers(self):
        state, _ = self.observe('pure_call', 'pure_call_abi')
        self.assertEqual(state.regs['r12'], analysis._const(11, 64))
        self.assertNotEqual(state.regs['r10'], analysis._const(13, 64))

    def test_return_address_push_invalidates_overlapping_slot(self):
        state, _ = self.observe('stack_argument')
        self.assertNotEqual(state.regs['r12'], analysis._const(7, 64))

    def test_conflicting_predecessors_do_not_keep_one_path_constant(self):
        state, _ = self.observe('incompatible_join')
        self.assertNotEqual(state.regs['r12'], analysis._const(7, 64))
        self.assertNotEqual(state.regs['r12'], analysis._const(9, 64))

    def test_arithmetic_carry_branch_is_not_a_result_comparison(self):
        state, _ = self.observe('carry_guard')
        self.assertNotEqual(state.regs['r12'], analysis._const(0, 64))

    def test_zero_shift_does_not_set_result_flags(self):
        state, _ = self.observe('zero_shift')
        self.assertNotEqual(state.regs['r12'], analysis._const(0, 64))

    def test_dynamic_shift_may_preserve_previous_flags(self):
        state, _ = self.observe('dynamic_shift')
        self.assertNotEqual(state.regs['r12'], analysis._const(0, 64))

    def test_nonzero_shift_zero_flag_refines_spilled_result(self):
        state, _ = self.observe('nonzero_shift')
        self.assertEqual(state.regs['r12'], analysis._const(0, 64))

    def test_narrow_stack_store_does_not_define_full_width_pop(self):
        state, _ = self.observe('partial_pop')
        self.assertNotEqual(state.regs['r12'], analysis._const(7, 64))

    def test_narrow_stack_store_does_not_define_full_width_leave(self):
        state, _ = self.observe('partial_leave')
        self.assertNotEqual(state.regs['rbp'], analysis._const(7, 64))

    def test_operand_size_override_leave_does_not_create_wrong_frame_offset(self):
        state, _ = self.observe('short_leave')
        self.assertEqual(state.regs['rsp'][0], 'var')
        self.assertEqual(state.regs['rbp'][0], 'var')

    def test_simd_load_and_disjoint_frame_store_preserve_slot(self):
        state, _ = self.observe('simd_disjoint')
        self.assertEqual(state.regs['r12'], analysis._const(7, 64))

    def test_simd_overlapping_store_invalidates_slot(self):
        state, _ = self.observe('simd_overlap')
        self.assertNotEqual(state.regs['r12'], analysis._const(7, 64))

    def test_simd_unknown_store_invalidates_slot(self):
        state, _ = self.observe('simd_unknown_store')
        self.assertNotEqual(state.regs['r12'], analysis._const(7, 64))

    def test_register_rotate_preserves_memory_but_kills_unknown_result(self):
        state, result = self.observe('register_rotate')
        self.assertEqual(state.regs['r12'], analysis._const(7, 64))
        self.assertEqual(state.regs['rax'][0], 'var')
        self.assertTrue(any(item['effect'] == 'read_only_instruction_preserves_frame_slots'
                            for item in result.diagnostics))

    def test_segmented_tls_reads_preserve_frame_slots(self):
        state, _ = self.observe('tls_read')
        self.assertEqual(state.regs['r12'], analysis._const(7, 64))

    def test_segmented_tls_store_still_invalidates_unknown_aliases(self):
        state, _ = self.observe('tls_store')
        self.assertNotEqual(state.regs['r12'], analysis._const(7, 64))

    def test_rotate_through_unknown_pointer_invalidates_frame_slots(self):
        state, _ = self.observe('memory_rotate')
        self.assertNotEqual(state.regs['r12'], analysis._const(7, 64))

    def test_special_register_destination_does_not_preserve_memory_facts(self):
        state, _ = self.observe('segment_write')
        self.assertNotEqual(state.regs['r12'], analysis._const(7, 64))

    def test_rotate_flags_do_not_constrain_its_result_to_zero(self):
        state, _ = self.observe('rotate_flags')
        self.assertNotEqual(state.regs['r12'], analysis._const(0, 64))

    def test_budget_exhaustion_publishes_no_facts(self):
        result = function_dataflow(self.function('changing_loop'), analysis._State, max_steps=1)
        self.assertEqual(result.status, 'unresolved')
        self.assertEqual(result.inputs, {})
        self.assertEqual(result.constants, {})

    def test_external_entry_prevents_frame_proof(self):
        function = self.function('guard_spill')
        function.external_entries = {self.addresses['guard_spill_read']}
        result = function_dataflow(function, analysis._State)
        self.assertEqual(result.status, 'unresolved')
        self.assertEqual(result.inputs, {})

    def test_many_shared_preparations_use_adaptive_suffixes(self):
        name = 'many_preparations'
        record = analysis._analyze_site(self.function(name), self.addresses[name + '_site'])
        self.assertEqual(record['evidence']['strategy'], 'adaptive_cfg_suffixes')
        self.assertEqual(set(record['targets']), {self.addresses[name + '_a'], self.addresses[name + '_b']})
        self.assertEqual(len(record['evidence']['paths']), 80)

    def test_one_unknown_preparation_prevents_a_partial_target_proof(self):
        name = 'unknown_preparation'
        with self.assertRaises(analysis.Unresolved):
            analysis._analyze_site(self.function(name), self.addresses[name + '_site'])

    def test_adaptive_path_budget_refuses_partial_results(self):
        name = 'too_many_preparations'
        with self.assertRaisesRegex(analysis.Unresolved, 'path budget'):
            analysis._analyze_site(self.function(name), self.addresses[name + '_site'])

    def test_frame_constant_recovers_dispatch_after_loop_fixed_point(self):
        from jump_table_reaching import recover_reaching_tables
        function = self.function('frame_dispatch')
        result = recover_reaching_tables(function, analysis._analyze_site, analysis._State,
                                         analysis._indirect, analysis.Unresolved,
                                         dataflow=function_dataflow)
        self.assertEqual(result['status'], 'closed', result)
        self.assertEqual(len(result['records']), 1)
        self.assertEqual(set(result['records'][0]['targets']),
                         {self.addresses['frame_dispatch_a'], self.addresses['frame_dispatch_b']})
        proof = result['records'][0]['evidence']['reaching_definitions']
        self.assertIn('frame_inputs', proof)


if __name__ == '__main__':
    unittest.main()
