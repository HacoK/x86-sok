"""Independent checks that unsupported control/data effects fail closed."""
import importlib.util
from pathlib import Path
import shutil
from types import SimpleNamespace
import unittest

import capstone
from elftools.elf.elffile import ELFFile


FIXTURE_PATH = Path(__file__).with_name('test_jump_table_analysis.py')
SPEC = importlib.util.spec_from_file_location('_jump_table_safety_fixture', FIXTURE_PATH)
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)
analysis = fixture.analysis

for mnemonic in ('loop', 'loope', 'loopne'):
    prefix = mnemonic + '_bypass'
    fixture.ASSEMBLY += '''
.text
.global {name}
.type {name},@function
{name}:
 {mnemonic} {name}_site
 mov %edi,%edi
 cmp $1,%edi
 ja {name}_out
{name}_site:
 jmp *{name}_table(,%rdi,8)
{name}_0: ret
{name}_1: ret
{name}_2: ret
{name}_out: ret
.size {name},.-{name}
.section .rodata
.align 8
{name}_table: .quad {name}_0,{name}_1,{name}_2
'''.format(name=prefix, mnemonic=mnemonic)

for name, instruction in (('syscall_result', 'syscall'),
                          ('sysenter_result', 'sysenter'),
                          ('int80_result', 'int $0x80')):
    fixture.ASSEMBLY += '''
.text
.global {name}
.type {name},@function
{name}:
 mov %edi,%eax
 and $1,%eax
 {instruction}
{name}_site:
 jmp *{name}_table(,%rax,8)
{name}_0: ret
{name}_1: ret
{name}_2: ret
.size {name},.-{name}
.section .rodata
.align 8
{name}_table: .quad {name}_0,{name}_1,{name}_2
'''.format(name=name, instruction=instruction)

fixture.ASSEMBLY += '''
.text
.global transaction_result
.type transaction_result,@function
transaction_result:
 mov %edi,%eax
 and $1,%eax
 xbegin transaction_result_site
 xend
transaction_result_site:
 jmp *transaction_table(,%rax,8)
transaction_0: ret
transaction_1: ret
transaction_2: ret
.size transaction_result,.-transaction_result
.section .rodata
.align 8
transaction_table: .quad transaction_0,transaction_1,transaction_2
'''

for name, restore in (
        ('prefix_return', 'pop %r13\n ret'),
        ('prefix_call', 'mov %rsi,%r13\n call _start\n ret'),
        ('prefix_tailjump', 'mov %rsi,%r13\n jmp prefix_tailjump_dispatch')):
    fixture.ASSEMBLY += '''
.text
.global {name}
.type {name},@function
{name}:
 lea {name}_table(%rip),%r13
 jmp {name}_dispatch
{name}_restore:
 {restore}
{name}_dispatch:
 and $1,%edi
{name}_site:
 jmp *(%r13,%rdi,8)
{name}_other: ret
.size {name},.-{name}
.section .rodata
.align 8
{name}_table: .quad {name}_restore,{name}_other
'''.format(name=name, restore=restore)

fixture.ASSEMBLY += '''
.text
.global foreign_target
.type foreign_target,@function
foreign_target:
 mov %edi,%edi
 cmp $1,%edi
 ja foreign_target_out
foreign_target_site:
 jmp *foreign_target_table(,%rdi,8)
foreign_target_0: ret
foreign_target_1: ret
foreign_target_2: ret
foreign_target_out: ret
.size foreign_target,.-foreign_target
.global foreign_bypass
.type foreign_bypass,@function
foreign_bypass:
 mov $2,%edi
 jmp foreign_target_site
.size foreign_bypass,.-foreign_bypass
.global ordinary_caller
.type ordinary_caller,@function
ordinary_caller:
 call foreign_target
 ret
.size ordinary_caller,.-ordinary_caller
.global foreign_caller
.type foreign_caller,@function
foreign_caller:
 call foreign_target_site
 ret
.size foreign_caller,.-foreign_caller
.global ordinary_tailcall
.type ordinary_tailcall,@function
ordinary_tailcall:
 jmp foreign_target
.size ordinary_tailcall,.-ordinary_tailcall
.section .rodata
.align 8
foreign_target_table: .quad foreign_target_0,foreign_target_1,foreign_target_2
'''


@unittest.skipUnless(shutil.which('as') and shutil.which('ld'), 'GNU assembler/linker required')
class AnalysisSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.BinaryRecoveryTests.setUpClass()
        cls.addClassCleanup(fixture.BinaryRecoveryTests.tearDownClass)
        cls.binary = fixture.BinaryRecoveryTests.binary
        cls.records = fixture.BinaryRecoveryTests.records
        cls.symbols = fixture.BinaryRecoveryTests.symbols
        cls.module = fixture.BinaryRecoveryTests.module

    def test_loop_taken_edges_cannot_bypass_selector_guard_unnoticed(self):
        for mnemonic in ('loop', 'loope', 'loopne'):
            with self.subTest(mnemonic=mnemonic):
                row = self.records[self.symbols[mnemonic + '_bypass_site']]
                # The taken loop edge allows RDI=2 (and arbitrary other values).
                # A proof using only the fallthrough CMP incorrectly emits 0,1.
                self.assertEqual(row['status'], 'unresolved', row)

    def test_system_call_result_does_not_reuse_pre_call_selector_bounds(self):
        for name in ('syscall_result', 'sysenter_result', 'int80_result'):
            with self.subTest(instruction=name):
                row = self.records[self.symbols[name + '_site']]
                self.assertEqual(row['status'], 'unresolved', row)

    def test_transaction_abort_replaces_eax_with_unknown_status(self):
        row = self.records[self.symbols['transaction_result_site']]
        self.assertEqual(row['status'], 'unresolved', row)

    def test_address_override_wraps_at_32_bits_or_is_rejected(self):
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        instruction = next(decoder.disasm(bytes.fromhex('67ff248500000000'), 0x1000))
        image = SimpleNamespace(bits=64)
        state = analysis._State(image, {'rax': 0xffffffff})
        try:
            expression = state.address(instruction, instruction.operands[0])
        except analysis.Unresolved:
            return
        values = analysis._Evaluator(image, analysis._Domains()).values(expression)
        self.assertEqual(values, {0xfffffffc})

    def test_readonly_section_in_writable_load_segment_is_not_immutable(self):
        table = self.symbols['masked_table']
        with self.binary.open('rb') as stream:
            elf = ELFFile(stream)
            self.assertEqual(elf.elfclass, 64)
            index, segment = next((index, segment) for index, segment in enumerate(elf.iter_segments())
                                  if segment['p_type'] == 'PT_LOAD'
                                  and segment['p_vaddr'] <= table < segment['p_vaddr'] + segment['p_filesz'])
            flags_offset = elf['e_phoff'] + index * elf['e_phentsize'] + 4
            new_flags = segment['p_flags'] | 2
        content = bytearray(self.binary.read_bytes())
        content[flags_offset:flags_offset + 4] = new_flags.to_bytes(4, 'little')
        writable = self.binary.with_name('writable-table-segment')
        writable.write_bytes(content)
        records = {row['site']: row for row in analysis.analyze_jump_tables(writable, self.module)}
        row = records[self.symbols['masked_site']]
        self.assertEqual(row['status'], 'unresolved', row)

    def function(self, name, handwritten=False):
        item = next(item for item in self.module.fuc if item.va == self.symbols[name])
        copied = SimpleNamespace(va=item.va, bb=item.bb, type=int(handwritten))
        return analysis._Function(copied, analysis._Image(self.binary),
                                  {item.va for item in self.module.fuc})

    def test_entry_constant_allows_restore_in_straight_return_suffix(self):
        function = self.function('prefix_return')
        self.assertEqual(function.entry_invariants().get('r13'), self.symbols['prefix_return_table'])
        row = self.records[self.symbols['prefix_return_site']]
        self.assertEqual(row['status'], 'resolved', row)

    def test_dummy_function_does_not_assume_single_entry_prefix(self):
        self.assertEqual(self.function('prefix_return', handwritten=True).entry_invariants(), {})

    def test_entry_constant_rejected_after_clobber_before_call_or_tailjump(self):
        for name in ('prefix_call', 'prefix_tailjump'):
            with self.subTest(name=name):
                self.assertNotIn('r13', self.function(name).entry_invariants())

    def test_unknown_alias_store_and_call_invalidate_guarded_memory_read(self):
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        # cmp dword ptr [rdi],1; <interference>; mov eax,[rdi]
        for interference in ('c60600', 'e800000000', 'c6470300'):
            with self.subTest(interference=interference):
                instructions = list(decoder.disasm(
                    bytes.fromhex('833f01' + interference + '8b07'), 0x1000))
                state = analysis._State(SimpleNamespace(bits=64))
                state.step(instructions[0])
                guarded_read = state.flags[0]
                for instruction in instructions[1:]:
                    state.step(instruction)
                reread = analysis._extract(state.regs['rax'], 0, 32)
                self.assertNotEqual(reread, guarded_read)

    def test_same_base_disjoint_store_preserves_guarded_memory_read(self):
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        # CMP reads bytes 0..3; this store writes byte 4 of the same object.
        instructions = list(decoder.disasm(bytes.fromhex('833f01 c6470400 8b07'), 0x1000))
        state = analysis._State(SimpleNamespace(bits=64))
        state.step(instructions[0])
        guarded_read = state.flags[0]
        for instruction in instructions[1:]:
            state.step(instruction)
        self.assertEqual(analysis._extract(state.regs['rax'], 0, 32), guarded_read)

    def test_memory_overlap_check_accounts_for_modular_address_wrap(self):
        base = ('var', 'base', 64)
        before = analysis._binary('add', base, analysis._const(-1, 64), 64)
        after = analysis._binary('add', base, analysis._const(3, 64), 64)
        self.assertFalse(analysis._disjoint(before, 4, base, 1))
        self.assertFalse(analysis._disjoint(base, 1, before, 4))
        self.assertTrue(analysis._disjoint(before, 4, after, 1))

    def module_with_edge(self, source, target, kind):
        functions = []
        for item in self.module.fuc:
            if item.va == self.symbols[source]:
                original = item.bb[0]
                if kind == 1:
                    # Give the real CALL its own metadata block, followed by RET.
                    call, rest = original.instructions[0], original.instructions[1:]
                    blocks = [SimpleNamespace(va=call.va, type=kind, instructions=[call],
                                              child=[SimpleNamespace(va=self.symbols[target])]),
                              SimpleNamespace(va=rest[0].va, type=3, instructions=rest, child=[])]
                else:
                    blocks = [SimpleNamespace(va=original.va, type=kind,
                                              instructions=original.instructions,
                                              child=[SimpleNamespace(va=self.symbols[target])])]
                functions.append(SimpleNamespace(va=item.va, bb=blocks))
            else:
                functions.append(item)
        return SimpleNamespace(fuc=functions)

    def test_foreign_jump_into_suffix_cannot_bypass_local_guard(self):
        module = self.module_with_edge('foreign_bypass', 'foreign_target_site', 5)
        records = {row['site']: row for row in analysis.analyze_jump_tables(self.binary, module)}
        row = records[self.symbols['foreign_target_site']]
        self.assertEqual(row['status'], 'unresolved', row)
        self.assertIn('external CFG edge', row['reason'])

    def test_normal_call_and_tailcall_to_function_entry_preserve_analysis(self):
        for source, kind in (('ordinary_caller', 1), ('ordinary_tailcall', 11)):
            with self.subTest(source=source):
                module = self.module_with_edge(source, 'foreign_target', kind)
                records = {row['site']: row for row in analysis.analyze_jump_tables(self.binary, module)}
                row = records[self.symbols['foreign_target_site']]
                self.assertEqual(row['status'], 'resolved', row)
                self.assertEqual(row['targets'], [self.symbols['foreign_target_0'],
                                                  self.symbols['foreign_target_1']])

    def test_foreign_call_into_suffix_cannot_bypass_local_guard(self):
        module = self.module_with_edge('foreign_caller', 'foreign_target_site', 1)
        records = {row['site']: row for row in analysis.analyze_jump_tables(self.binary, module)}
        row = records[self.symbols['foreign_target_site']]
        self.assertEqual(row['status'], 'unresolved', row)
        self.assertIn('external CFG edge', row['reason'])


if __name__ == '__main__':
    unittest.main()
