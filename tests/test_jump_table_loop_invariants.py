"""Machine-code loop invariants remain conditional on valid seed-load values."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'extract_gt'))
import jump_table_analysis as analysis
from jump_table_loop_invariants import prove_seeded_selector_loop


@unittest.skipUnless(shutil.which('as') and shutil.which('ld'), 'GNU assembler/linker required')
class SeededLoopTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='seeded-loop-proof-')
        self.addCleanup(self.directory.cleanup)

    def build(self, before='', guard='test %ebp,%ebp\nje done', body='',
              shift='sar $4,%ebp', register='ebp', edges=True):
        directory = Path(self.directory.name)
        source, obj, binary = directory / 'loop.s', directory / 'loop.o', directory / 'loop'
        code = '''
.text
.global _start
.type _start,@function
_start:
BEFORE
seed:
mov packed(,%rdi,4),%edx
mov %edx,%ebp
shr $13,%ebp
again:
GUARD
prepare:
mov %ebp,%eax
and $7,%eax
dispatch:
jmp *targets(,%rax,8)
case:
BODY
SHIFT
jmp again
done: ret
.size _start,.-_start
.global helper
.type helper,@function
helper: ret
.size helper,.-helper
.data
packed: .long 0x246000,0xeca8000
.section .rodata
.align 8
targets: .quad case,case,case,case,case,case,case,case
.section .note.GNU-stack,"",@progbits
'''.replace('BEFORE', before).replace('GUARD', guard).replace('BODY', body).replace('SHIFT', shift)
        if register != 'ebp':
            code = code.replace('%ebp', '%' + register)
        source.write_text(code)
        subprocess.run(['as', '--64', '-o', str(obj), str(source)], check=True, capture_output=True)
        subprocess.run(['ld', '-o', str(binary), str(obj)], check=True, capture_output=True)
        image = analysis._Image(binary)
        with binary.open('rb') as stream:
            elf = ELFFile(stream)
            symbols = {symbol.name: int(symbol['st_value']) for symbol in elf.get_section_by_name('.symtab').iter_symbols()}
            main = next(symbol for symbol in elf.get_section_by_name('.symtab').iter_symbols() if symbol.name == '_start')
            decoded = list(image.md.disasm(image.read(main['st_value'], main['st_size']), main['st_value']))
        # The metadata supplies the conservative physical-table children.
        # _Function rebuilds ordinary branch boundaries from emitted bytes.
        split = next(index for index, ins in enumerate(decoded) if ins.address == symbols['dispatch']) + 1
        blocks = [SimpleNamespace(va=decoded[0].address,
                  instructions=[SimpleNamespace(va=ins.address, size=ins.size) for ins in decoded[:split]],
                  child=[SimpleNamespace(va=symbols['case'])] if edges else []),
                  SimpleNamespace(va=decoded[split].address,
                  instructions=[SimpleNamespace(va=ins.address, size=ins.size) for ins in decoded[split:]], child=[])]
        function = analysis._Function(SimpleNamespace(va=symbols['_start'], bb=blocks), image,
                                      {symbols['_start'], symbols['helper']})
        return function, symbols

    def prove(self, function, symbols, values=(0x123 << 13, 0x7654 << 13), **kwargs):
        return prove_seeded_selector_loop(function, symbols['dispatch'], symbols['seed'], values,
                                          analysis._State, state_register='rbp', **kwargs)

    def test_full_loop_has_only_nonzero_nibble_selectors(self):
        function, symbols = self.build()
        result = self.prove(function, symbols)
        self.assertEqual(result['status'], 'proved_conditional_loop', result)
        self.assertEqual(result['selectors'], list(range(1, 8)))
        self.assertIn('seed', result['assumptions'][0])

    def test_missing_zero_guard_keeps_selector_zero(self):
        function, symbols = self.build(guard='nop')
        result = self.prove(function, symbols)
        self.assertEqual(result['selectors'], list(range(8)), result)

    def test_explicit_guard_bypass_keeps_selector_zero(self):
        function, symbols = self.build(guard='test %esi,%esi\nje prepare\ntest %ebp,%ebp\nje done')
        result = self.prove(function, symbols)
        self.assertIn(0, result['selectors'], result)

    def test_new_state_write_is_part_of_fixed_point(self):
        function, symbols = self.build(body='mov $0x80,%ebp')
        result = self.prove(function, symbols)
        self.assertIn(0, result['selectors'], result)

    def test_partial_state_write_cannot_be_ignored(self):
        function, symbols = self.build(body='mov $0x80,%bpl')
        result = self.prove(function, symbols)
        self.assertIn(0, result['selectors'], result)

    def test_unknown_state_write_prevents_exclusion_of_zero(self):
        function, symbols = self.build(body='mov %esi,%ebp')
        result = self.prove(function, symbols)
        self.assertIn(0, result['selectors'], result)

    def test_bypassing_seed_with_unknown_value_is_not_ignored(self):
        function, symbols = self.build(before='test %esi,%esi\nje again')
        self.assertIn(0, self.prove(function, symbols)['selectors'])

    def test_unknown_indirect_frontier_prevents_entry_proof(self):
        function, symbols = self.build(edges=False)
        result = self.prove(function, symbols)
        self.assertEqual(result['status'], 'unresolved', result)
        self.assertIn('successor coverage', result['reason'])

    def test_nonlocal_unknown_indirect_successor_prevents_proof(self):
        function, symbols = self.build()
        function.known_edges[symbols['dispatch']].add(0x123456)
        result = self.prove(function, symbols)
        self.assertEqual(result['status'], 'unresolved', result)

    def test_callee_saved_loop_state_survives_abi_call(self):
        function, symbols = self.build(body='call helper')
        result = self.prove(function, symbols)
        self.assertEqual(result['selectors'], list(range(1, 8)), result)

    def test_caller_saved_loop_state_is_invalidated_by_call(self):
        function, symbols = self.build(body='call helper', register='edx')
        result = prove_seeded_selector_loop(function, symbols['dispatch'], symbols['seed'],
                                            [0x123 << 13], analysis._State, state_register='rdx')
        self.assertIn(0, result['selectors'], result)

    def test_zero_or_dynamic_shift_does_not_invent_zero_flag(self):
        for shift in ('shr $0,%ebp', 'shr %cl,%ebp'):
            with self.subTest(shift=shift):
                function, symbols = self.build(guard='test %esi,%esi\n' + shift + '\nje done', shift='nop')
                result = self.prove(function, symbols, values=[0])
                self.assertEqual(result['status'], 'proved_conditional_loop', result)
                self.assertEqual(result['selectors'], [0])

    def test_budget_is_not_convergence(self):
        function, symbols = self.build()
        result = self.prove(function, symbols, max_steps=1)
        self.assertEqual(result['status'], 'unresolved')
        self.assertNotIn('selectors', result)


if __name__ == '__main__':
    unittest.main()
