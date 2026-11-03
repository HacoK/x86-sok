"""Binary-level regressions for generic selector and table recovery."""
import importlib.util
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('jump_table_analysis', ROOT / 'extract_gt/jump_table_analysis.py')
analysis = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(analysis)

ASSEMBLY = r'''
.text
.global _start
.type _start,@function
_start:
 ret
.size _start,.-_start

.global holes
.type holes,@function
holes:
 mov %edi,%edi
 cmp $2,%edi
 je holes_out
 cmp $3,%edi
 ja holes_out
holes_site:
 jmp *holes_table(,%rdi,8)
holes_0: ret
holes_1: ret
holes_2: ret
holes_3: ret
holes_out: ret
.size holes,.-holes

.global masked
.type masked,@function
masked:
 mov %rdi,%rax
 shr $2,%rax
 xor $1,%rax
 and $1,%eax
masked_site:
 jmp *masked_table(,%rax,8)
masked_0: ret
masked_1: ret
masked_2: ret
.size masked,.-masked

.global sparse
.type sparse,@function
sparse:
 mov %edi,%edi
 cmp $4,%edi
 ja sparse_out
 lea classifier(%rip),%rdx
 movzbl (%rdx,%rdi),%eax
 lea sparse_table(%rip),%rcx
 movslq (%rcx,%rax,4),%rax
 lea sparse_base(%rip),%rcx
 add %rcx,%rax
sparse_site:
 jmp *%rax
sparse_base: nop
sparse_0: ret
sparse_1: ret
sparse_2: ret
sparse_3: ret
sparse_out: ret
.size sparse,.-sparse

.global bypass
.type bypass,@function
bypass:
 mov %edi,%edi
 test %esi,%esi
 je bypass_site
 cmp $1,%edi
 ja bypass_out
bypass_site:
 jmp *bypass_table(,%rdi,8)
bypass_0: ret
bypass_1: ret
bypass_out: ret
.size bypass,.-bypass

.global signed_guard
.type signed_guard,@function
signed_guard:
 mov %edi,%edi
 cmp $0,%edi
 jl signed_out
 cmp $1,%edi
 jg signed_out
signed_site:
 jmp *signed_table(,%rdi,8)
signed_0: ret
signed_1: ret
signed_out: ret
.size signed_guard,.-signed_guard

.global zero_hole
.type zero_hole,@function
zero_hole:
 mov %edi,%edi
 test %edi,%edi
 je zero_out
 cmp $2,%edi
 ja zero_out
zero_site:
 jmp *zero_table(,%rdi,8)
zero_0: ret
zero_1: ret
zero_2: ret
zero_out: ret
.size zero_hole,.-zero_hole

.global function_pointers
.type function_pointers,@function
function_pointers:
 and $1,%edi
function_pointers_site:
 jmp *function_pointers_table(,%rdi,8)
.size function_pointers,.-function_pointers

.global partial_register
.type partial_register,@function
partial_register:
 mov %edi,%eax
 and $1,%al
partial_register_site:
 jmp *partial_table(,%rax,8)
partial_0: ret
partial_1: ret
.size partial_register,.-partial_register

.global overwritten_guard
.type overwritten_guard,@function
overwritten_guard:
 mov %edi,%edi
 cmp $1,%edi
 ja overwritten_out
 bswap %edi
overwritten_guard_site:
 jmp *overwritten_table(,%rdi,8)
overwritten_0: ret
overwritten_1: ret
overwritten_out: ret
.size overwritten_guard,.-overwritten_guard

.global preserved_base
.type preserved_base,@function
preserved_base:
 lea preserved_table(%rip),%r13
preserved_loop:
 call _start
 mov %edi,%edi
 cmp $1,%edi
 ja preserved_out
preserved_base_site:
 jmp *(%r13,%rdi,8)
preserved_0: jmp preserved_loop
preserved_1: ret
preserved_out:
 test %esi,%esi
 jne preserved_loop
 ret
.size preserved_base,.-preserved_base

.global stack_overlap
.type stack_overlap,@function
stack_overlap:
 and $1,%edi
 lea stack_table(%rip),%rax
 mov %rax,(%rsp)
 movb $0,1(%rsp)
 mov (%rsp),%rax
stack_overlap_site:
 jmp *(%rax,%rdi,8)
stack_0: ret
stack_1: ret
.size stack_overlap,.-stack_overlap

.global disconnected
.type disconnected,@function
disconnected:
 lea disconnected_table(%rip),%r13
 jmp disconnected_join
disconnected_cycle:
 mov %rsi,%r13
 test %esi,%esi
 je disconnected_cycle
disconnected_join:
 and $1,%edi
disconnected_site:
 jmp *(%r13,%rdi,8)
disconnected_0: ret
disconnected_1: ret
.size disconnected,.-disconnected

.global negative_offsets
.type negative_offsets,@function
negative_offsets:
 and $1,%edi
 lea negative_table(%rip),%rdx
 movslq (%rdx,%rdi,4),%rax
 lea negative_base(%rip),%rdx
 add %rdx,%rax
negative_offsets_site:
 jmp *%rax
negative_0: ret
negative_1: ret
negative_base: nop
 ret
.size negative_offsets,.-negative_offsets

.global byte_guard
.type byte_guard,@function
byte_guard:
 lea -32(%rdi),%ecx
 cmp $4,%cl
 ja byte_out
 movsbl %dil,%eax
 sub $32,%eax
 cltq
 lea classifier(%rip),%rdx
 movzbl (%rdx,%rax),%eax
 lea byte_table(%rip),%rdx
 movslq (%rdx,%rax,4),%rax
 lea byte_base(%rip),%rdx
 add %rdx,%rax
byte_guard_site:
 jmp *%rax
byte_base: nop
byte_0: ret
byte_1: ret
byte_2: ret
byte_3: ret
byte_out: ret
.size byte_guard,.-byte_guard

.global sign_selector
.type sign_selector,@function
sign_selector:
 mov %edi,%ecx
 shl $12,%ecx
 sar $31,%ecx
 and $3,%ecx
sign_selector_site:
 jmp *sign_table(,%rcx,8)
sign_0: ret
sign_1: ret
sign_2: ret
sign_3: ret
.size sign_selector,.-sign_selector

.global repeated_load
.type repeated_load,@function
repeated_load:
 cmpl $0,(%rdi)
 je repeated_out
 cmpl $2,(%rdi)
 ja repeated_out
 mov (%rdi),%eax
repeated_load_site:
 jmp *repeated_table(,%rax,8)
repeated_0: ret
repeated_1: ret
repeated_2: ret
repeated_out: ret
.size repeated_load,.-repeated_load

.global mutated_load
.type mutated_load,@function
mutated_load:
 cmpl $1,(%rdi)
 ja mutated_out
 movl $20,(%rdi)
 mov (%rdi),%eax
mutated_load_site:
 jmp *mutated_table(,%rax,8)
mutated_0: ret
mutated_1: ret
mutated_out: ret
.size mutated_load,.-mutated_load

.global constant_fallback
.type constant_fallback,@function
constant_fallback:
 mov %edi,%edi
 cmp $1,%edi
 ja constant_default
 mov constant_table(,%rdi,8),%rax
 jmp constant_fallback_site
constant_default:
 lea constant_2(%rip),%rax
constant_fallback_site:
 jmp *%rax
constant_0: ret
constant_1: ret
constant_2: ret
.size constant_fallback,.-constant_fallback

.global unknown_fallback
.type unknown_fallback,@function
unknown_fallback:
 mov %edi,%edi
 cmp $1,%edi
 ja unknown_default
 mov unknown_table(,%rdi,8),%rax
 jmp unknown_fallback_site
unknown_default:
 mov %rsi,%rax
unknown_fallback_site:
 jmp *%rax
unknown_0: ret
unknown_1: ret
.size unknown_fallback,.-unknown_fallback

.global converged_branch
.type converged_branch,@function
converged_branch:
 mov %edi,%edi
 cmp $1,%edi
 je converged_next
converged_next:
 cmp $2,%edi
 ja converged_out
converged_branch_site:
 jmp *converged_table(,%rdi,8)
converged_0: ret
converged_1: ret
converged_2: ret
converged_out: ret
.size converged_branch,.-converged_branch

.global hidden_bypass
.type hidden_bypass,@function
hidden_bypass:
 mov %edi,%edi
 test %esi,%esi
 jne hidden_code
 cmp $1,%edi
 ja hidden_out
 jmp hidden_bypass_site
hidden_code:
 mov $2,%edi
 jmp hidden_bypass_site
hidden_bypass_site:
 jmp *hidden_table(,%rdi,8)
hidden_0: ret
hidden_1: ret
hidden_2: ret
hidden_out: ret
.size hidden_bypass,.-hidden_bypass

.section .rodata
.align 8
holes_table: .quad holes_0,holes_1,holes_2,holes_3
masked_table: .quad masked_0,masked_1,masked_2
classifier: .byte 1,3,1,0,3
.align 4
sparse_table: .long sparse_0-sparse_base,sparse_1-sparse_base,sparse_2-sparse_base,sparse_3-sparse_base
.align 8
bypass_table: .quad bypass_0,bypass_1
signed_table: .quad signed_0,signed_1
zero_table: .quad zero_0,zero_1,zero_2
function_pointers_table: .quad holes,masked
partial_table: .quad partial_0,partial_1
overwritten_table: .quad overwritten_0,overwritten_1
preserved_table: .quad preserved_0,preserved_1
stack_table: .quad stack_0,stack_1
disconnected_table: .quad disconnected_0,disconnected_1
negative_table: .long negative_0-negative_base,negative_1-negative_base
byte_table: .long byte_0-byte_base,byte_1-byte_base,byte_2-byte_base,byte_3-byte_base
sign_table: .quad sign_0,sign_1,sign_2,sign_3
repeated_table: .quad repeated_0,repeated_1,repeated_2
mutated_table: .quad mutated_0,mutated_1
constant_table: .quad constant_0,constant_1
unknown_table: .quad unknown_0,unknown_1
converged_table: .quad converged_0,converged_1,converged_2
hidden_table: .quad hidden_0,hidden_1,hidden_2
.section .note.GNU-stack,"",@progbits
'''


@unittest.skipUnless(shutil.which('as') and shutil.which('ld'), 'GNU assembler/linker required')
class BinaryRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='jump-table-analysis-')
        root = Path(cls.directory.name)
        source, obj, binary = root / 'tables.s', root / 'tables.o', root / 'tables'
        source.write_text(ASSEMBLY)
        subprocess.run(['as', '--64', '-o', str(obj), str(source)], check=True, capture_output=True)
        subprocess.run(['ld', '-o', str(binary), str(obj)], check=True, capture_output=True)
        cls.binary = binary
        image = analysis._Image(binary)
        functions, cls.symbols = [], {}
        with binary.open('rb') as stream:
            elf = ELFFile(stream)
            for symbol in elf.get_section_by_name('.symtab').iter_symbols():
                cls.symbols[symbol.name] = int(symbol['st_value'])
                if symbol['st_info']['type'] == 'STT_FUNC' and symbol['st_size']:
                    start, size = int(symbol['st_value']), int(symbol['st_size'])
                    instructions = [SimpleNamespace(va=ins.address, size=ins.size)
                                    for ins in image.md.disasm(image.read(start, size), start)]
                    block = SimpleNamespace(va=start, instructions=instructions, child=[])
                    functions.append(SimpleNamespace(va=start, bb=[block]))
        cls.module = SimpleNamespace(fuc=functions)
        cls.records = {record['site']: record for record in analysis.analyze_jump_tables(binary, cls.module)}

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def record(self, name):
        return self.records[self.symbols[name]]

    def assert_targets(self, site, names):
        record = self.record(site)
        self.assertEqual('resolved', record['status'], record)
        self.assertEqual(sorted(self.symbols[name] for name in names), record['targets'])

    def test_equality_hole_excluded(self):
        self.assert_targets('holes_site', ['holes_0', 'holes_1', 'holes_3'])

    def test_mask_after_64_bit_operations(self):
        self.assert_targets('masked_site', ['masked_0', 'masked_1'])

    def test_sparse_selector_map_and_distinct_relative_base(self):
        self.assert_targets('sparse_site', ['sparse_0', 'sparse_1', 'sparse_3'])
        loads = self.record('sparse_site')['evidence']['paths'][0]['loads']
        self.assertEqual({1, 4}, {load['entry_size'] for load in loads})

    def test_unbounded_bypass_prevents_promotion(self):
        self.assertEqual('unresolved', self.record('bypass_site')['status'])

    def test_signed_guards_reject_negative_indexes(self):
        self.assert_targets('signed_site', ['signed_0', 'signed_1'])

    def test_zero_case_branches_before_table(self):
        self.assert_targets('zero_site', ['zero_1', 'zero_2'])

    def test_cross_function_pointer_table_is_not_switch(self):
        self.assertEqual('unresolved', self.record('function_pointers_site')['status'])

    def test_byte_write_does_not_clear_upper_register(self):
        self.assertEqual('unresolved', self.record('partial_register_site')['status'])

    def test_unsupported_write_invalidates_guard_value(self):
        self.assertEqual('unresolved', self.record('overwritten_guard_site')['status'])

    def test_callee_saved_base_survives_call_and_loop(self):
        self.assert_targets('preserved_base_site', ['preserved_0', 'preserved_1'])

    def test_overlapping_stack_store_invalidates_spilled_base(self):
        self.assertEqual('unresolved', self.record('stack_overlap_site')['status'])

    def test_closed_entry_cfg_excludes_disconnected_cycle(self):
        self.assert_targets('disconnected_site', ['disconnected_0', 'disconnected_1'])
        proof = self.record('disconnected_site')['evidence']['reaching_definitions']
        self.assertEqual('entry_reachable_closed_cfg', proof['scope'])
        self.assertNotIn(self.symbols['disconnected_cycle'], proof['reachable_blocks'])

    def test_negative_offsets_are_sign_extended(self):
        self.assert_targets('negative_offsets_site', ['negative_0', 'negative_1'])

    def test_modular_byte_guard_constrains_sign_extended_index(self):
        self.assert_targets('byte_guard_site', ['byte_0', 'byte_1', 'byte_3'])

    def test_sign_bit_shift_realizes_only_zero_and_three(self):
        self.assert_targets('sign_selector_site', ['sign_0', 'sign_3'])

    def test_repeated_memory_read_reuses_guarded_value(self):
        self.assert_targets('repeated_load_site', ['repeated_1', 'repeated_2'])

    def test_intervening_store_invalidates_read_guard(self):
        self.assertEqual('unresolved', self.record('mutated_load_site')['status'])

    def test_constant_fallback_is_included_at_shared_indirect_jump(self):
        self.assert_targets('constant_fallback_site', ['constant_0', 'constant_1', 'constant_2'])

    def test_unknown_fallback_is_never_discarded(self):
        self.assertEqual('unresolved', self.record('unknown_fallback_site')['status'])

    def test_taken_and_fallthrough_same_target_adds_no_predicate(self):
        self.assert_targets('converged_branch_site', ['converged_0', 'converged_1', 'converged_2'])

    def test_missing_local_block_cannot_hide_a_guard_bypass(self):
        original = next(function for function in self.module.fuc
                        if function.va == self.symbols['hidden_bypass'])
        omitted_start = self.symbols['hidden_code']
        site = self.symbols['hidden_bypass_site']
        instructions = [item for item in original.bb[0].instructions
                        if not omitted_start <= item.va < site]
        block = SimpleNamespace(va=original.va, instructions=instructions, child=[])
        function = SimpleNamespace(va=original.va, bb=[block])
        records = analysis.analyze_jump_tables(self.binary, SimpleNamespace(fuc=[function]))
        result = next(record for record in records if record['site'] == site)
        self.assertEqual('unresolved', result['status'])
        self.assertIn('CFG', result['reason'])

    def test_file_backed_read_does_not_cross_segment(self):
        image = analysis._Image(self.binary)
        _, end, _ = image.segments[-1]
        with self.assertRaises(analysis.Unresolved):
            image.read(end - 1, 8)


if __name__ == '__main__':
    unittest.main()
