"""Binary-level checks for initialization regions and later dispatch paths."""
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
from jump_table_constants import entry_region_constants


ASSEMBLY = r'''
.text
.global _start
.type _start,@function
_start: ret
.size _start,.-_start

.global guarded
.type guarded,@function
guarded:
 test %edi,%edi
 je guarded_out
 mov $0x123400,%r13
 call leaf
guarded_loop:
 test %esi,%esi
 je guarded_loop
 jmp *%rax
guarded_case:
 nop
 jmp guarded_loop
guarded_out: ret
.size guarded,.-guarded

.global caller_base
.type caller_base,@function
caller_base:
 test %edi,%edi
 je caller_out
 call leaf
 mov $0x123400,%r8
caller_loop:
 test %esi,%esi
 je caller_loop
 jmp *%rax
caller_case: jmp caller_loop
caller_out: ret
.size caller_base,.-caller_base

.global conflicting
.type conflicting,@function
conflicting:
 test %edi,%edi
 je conflicting_other
 mov $0x123400,%r13
 jmp *%rax
conflicting_other:
 mov $0x567800,%r13
 jmp *%rax
.size conflicting,.-conflicting

.global bypass
.type bypass,@function
bypass:
 test %edi,%edi
 je bypass_site
 mov $0x123400,%r13
bypass_site: jmp *%rax
.size bypass,.-bypass

.global clobbered_case
.type clobbered_case,@function
clobbered_case:
 mov $0x123400,%r13
 jmp *%rax
clobbered_target:
 xor %r13,%r13
 jmp *%rax
.size clobbered_case,.-clobbered_case

.global caller_clobber
.type caller_clobber,@function
caller_clobber:
 mov $0x123400,%r8
 jmp *%rax
caller_clobber_target:
 call leaf
 jmp *%rax
.size caller_clobber,.-caller_clobber

.global epilogue
.type epilogue,@function
epilogue:
 push %r13
 test %edi,%edi
 je epilogue_return
 mov $0x123400,%r13
 jmp *%rax
epilogue_return:
 pop %r13
 ret
.size epilogue,.-epilogue

.global unsafe_reentry
.type unsafe_reentry,@function
unsafe_reentry:
 mov $1,%r13
unsafe_increment:
 inc %r13
 jmp *%rax
unsafe_case: jmp unsafe_increment
.size unsafe_reentry,.-unsafe_reentry

.global safe_reentry
.type safe_reentry,@function
safe_reentry:
 test %edi,%edi
 je safe_return
safe_initialize:
 call leaf
 mov $0x123400,%r8
 jmp *%rax
safe_case: jmp safe_initialize
safe_return: ret
.size safe_reentry,.-safe_reentry

.global padding
.type padding,@function
padding:
 test %edi,%edi
 je padding_out
 mov $0x123400,%r13
 .p2align 4
padding_loop:
 test %esi,%esi
 je padding_loop
 jmp *%rax
padding_out: ret
.size padding,.-padding

.global missing_write
.type missing_write,@function
missing_write:
 mov $0x123400,%r13
 inc %r13
 test %edi,%edi
 je missing_out
 jmp *%rax
missing_out: ret
.size missing_write,.-missing_write

.type leaf,@function
leaf: ret
.size leaf,.-leaf
.section .note.GNU-stack,"",@progbits
'''


@unittest.skipUnless(shutil.which('as') and shutil.which('ld'), 'GNU assembler/linker required')
class JumpTableConstantTests(unittest.TestCase):
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

    def function(self, name, extra_entries=()):
        entries = {function.va for function in self.functions.values()} | set(extra_entries)
        return analysis._Function(self.functions[name], self.image, entries)

    def infer(self, function, **kwargs):
        return entry_region_constants(function, analysis._State, analysis._const,
                                      analysis._is_branch, **kwargs)

    def test_guard_before_initialization_and_loop_preserve_callee_saved_base(self):
        self.assertEqual(self.infer(self.function('guarded')).get('r13'), 0x123400)

    def test_caller_saved_base_can_be_initialized_after_a_call(self):
        self.assertEqual(self.infer(self.function('caller_base')).get('r8'), 0x123400)

    def test_different_first_dispatch_values_are_rejected(self):
        self.assertNotIn('r13', self.infer(self.function('conflicting')))

    def test_first_dispatch_bypassing_initialization_is_rejected(self):
        self.assertNotIn('r13', self.infer(self.function('bypass')))

    def test_post_dispatch_register_write_is_rejected(self):
        self.assertNotIn('r13', self.infer(self.function('clobbered_case')))

    def test_post_dispatch_call_kills_caller_saved_constant(self):
        self.assertNotIn('r8', self.infer(self.function('caller_clobber')))

    def test_straight_return_epilogue_may_restore_register(self):
        self.assertEqual(self.infer(self.function('epilogue')).get('r13'), 0x123400)

    def test_reentry_cannot_reapply_nonconstant_initialization(self):
        self.assertNotIn('r13', self.infer(self.function('unsafe_reentry')))

    def test_reentry_before_independent_reset_is_safe(self):
        self.assertEqual(self.infer(self.function('safe_reentry')).get('r8'), 0x123400)

    def test_exhausted_fixed_point_budget_yields_no_constants(self):
        self.assertEqual(self.infer(self.function('guarded'), max_steps=1), {})

    def test_missing_local_successor_prevents_a_constant_proof(self):
        function = self.function('guarded')
        del function.blocks[self.addresses['guarded_out']]
        self.assertEqual(self.infer(function), {})

    def test_omitted_alignment_nops_are_verified_and_bridged(self):
        function = self.function('padding')
        removed = [address for address, ins in function.instructions.items()
                   if ins.mnemonic == 'nop']
        self.assertTrue(removed)
        for address in removed:
            del function.instructions[address]
        function.rebuild_graph()
        self.assertEqual(self.infer(function).get('r13'), 0x123400)

    def test_omitted_state_changing_instruction_is_not_padding(self):
        function = self.function('missing_write')
        address = next(address for address, ins in function.instructions.items()
                       if ins.mnemonic == 'inc')
        del function.instructions[address]
        function.rebuild_graph()
        self.assertEqual(self.infer(function), {})

    def test_multiple_entries_and_handwritten_functions_are_rejected(self):
        function = self.function('guarded', [self.addresses['guarded_case']])
        self.assertEqual(self.infer(function), {})
        function = self.function('guarded')
        function.handwritten = True
        self.assertEqual(self.infer(function), {})


if __name__ == '__main__':
    unittest.main()
