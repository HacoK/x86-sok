"""Exercise table-reference taint with real x86 and ARM instructions."""
import ast
import logging
from pathlib import Path
from types import SimpleNamespace
import unittest

import capstone as cs
from capstone import arm, x86


def load_taint(architecture='x86'):
    path = Path(__file__).resolve().parents[1] / 'extract_gt' / 'BlockUtil.py'
    tree = ast.parse(path.read_text())
    names = {'invalidInst', 'regs_access', 'instReadRegsIsTaint', 'taintRegsCrossBB'}
    tree.body = [node for node in tree.body
                 if isinstance(node, ast.FunctionDef)
                 and (node.name in names or node.name.startswith('_x86')
                      or node.name in {'_isX86TaintArchitecture', '_taintX86RegsCrossBB'})]
    config = SimpleNamespace(BB_ARCH=architecture, BB_OP_REG=x86.X86_OP_REG,
                             BB_OP_MEM=x86.X86_OP_MEM)
    namespace = {'cs': cs, 'x86': x86, 'bbl': config, 'logging': logging}
    exec(compile(tree, str(path), 'exec'), namespace)
    return namespace


class JumpTableTaintTests(unittest.TestCase):
    def setUp(self):
        self.namespace = load_taint()
        self.md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        self.md.detail = True

    def instructions(self, code):
        return list(self.md.disasm(bytes.fromhex(code), 0x1000))

    def run_taint(self, code, tainted=None, first=False):
        instructions = self.instructions(code)
        before = list(instructions)
        result = self.namespace['taintRegsCrossBB'](
            instructions, set() if tainted is None else set(tainted), first)
        self.assertEqual(instructions, before)
        return result

    def test_eax_write_flows_through_rax_and_edx_aliases(self):
        # mov eax, 0x1000; movsxd rdx, eax; jmp rdx
        result = self.run_taint('b800100000 4863d0 ffe2', first=True)
        self.assertIn(x86.X86_REG_RAX, result)
        self.assertIn(x86.X86_REG_RDX, result)
        self.assertTrue(self.namespace['instReadRegsIsTaint'](
            self.instructions('ffe2')[0], result))

    def test_high_byte_and_extended_register_aliases(self):
        # movzx ecx, ah; mov r9d, r8d
        result = self.run_taint('0fb6cc 4589c1',
                                {x86.X86_REG_EAX, x86.X86_REG_R8})
        self.assertIn(x86.X86_REG_RCX, result)
        self.assertIn(x86.X86_REG_R9, result)

    def test_flags_and_ip_are_not_pointer_taint(self):
        # cmp rax, rcx; sete dl; lea rsi, [rip]
        result = self.run_taint('4839c8 0f94c2 488d3500000000', {x86.X86_REG_RAX})
        self.assertNotIn(x86.X86_REG_EFLAGS, result)
        self.assertNotIn(x86.X86_REG_RIP, result)
        self.assertNotIn(x86.X86_REG_RDX, result)
        self.assertNotIn(x86.X86_REG_RSI, result)
        self.assertEqual(self.run_taint('4839c8', first=True), set())

    def test_constant_full_write_and_zeroing_idiom_kill_taint(self):
        for code in ('b800000000', '31c0', '4829c0'):
            with self.subTest(code=code):
                self.assertNotIn(x86.X86_REG_RAX,
                                 self.run_taint(code, {x86.X86_REG_RAX}))

    def test_partial_register_write_preserves_upper_byte_dependency(self):
        self.assertIn(x86.X86_REG_RAX,
                      self.run_taint('b000', {x86.X86_REG_RAX}))

    def test_rsp_spill_survives_register_kill_and_block_boundary(self):
        # mov [rsp-8], rax; xor eax, eax
        state = self.run_taint('48894424f8 31c0', {x86.X86_REG_RAX})
        self.assertNotIn(x86.X86_REG_RAX, state)
        self.assertEqual(len(state), 8)
        # mov rcx, [rsp-8]; jmp rcx
        result = self.run_taint('488b4c24f8 ffe1', state)
        self.assertIn(x86.X86_REG_RCX, result)

    def test_rbp_spill_and_direct_memory_jump(self):
        state = self.run_taint('488945f8 31c0', {x86.X86_REG_RAX})
        # jmp qword ptr [rbp-8]
        self.assertTrue(self.namespace['instReadRegsIsTaint'](
            self.instructions('ff65f8')[0], state))
        result = self.run_taint('488b4df8', state)
        self.assertIn(x86.X86_REG_RCX, result)

    def test_stack_overwrite_removes_stale_spill(self):
        result = self.run_taint(
            '48894424f8 31c0 48c74424f800000000 488b4c24f8',
            {x86.X86_REG_RAX})
        self.assertNotIn(x86.X86_REG_RCX, result)
        self.assertFalse(any(isinstance(item, tuple) for item in result))

    def test_partial_stack_overwrite_kills_only_overlapping_bytes(self):
        state = self.run_taint(
            '48894424f8 31c0 c74424f800000000', {x86.X86_REG_RAX})
        self.assertEqual({item[2] for item in state}, {-4, -3, -2, -1})
        self.assertNotIn(x86.X86_REG_RCX, self.run_taint('8b4c24f8', state))
        self.assertIn(x86.X86_REG_RCX, self.run_taint('488b4c24f8', state))

    def test_base_change_and_unknown_store_invalidate_spills(self):
        for change in ('4883ec08', '4889fc', '488907', '488945f8'):
            with self.subTest(change=change):
                result = self.run_taint(
                    '48894424f8 31c0 ' + change + ' 488b4c24f8',
                    {x86.X86_REG_RAX})
                self.assertNotIn(x86.X86_REG_RCX, result)

    def test_lea_does_not_reload_stack_contents(self):
        state = self.run_taint('48894424f8 31c0', {x86.X86_REG_RAX})
        self.assertNotIn(x86.X86_REG_RCX, self.run_taint('488d4c24f8', state))

    def test_empty_initial_block_is_safe(self):
        self.assertEqual(self.run_taint('', first=True), set())

    def test_arm_spill_behavior_is_preserved(self):
        namespace = load_taint('ARM')
        namespace['bbl'].BB_OP_REG = arm.ARM_OP_REG
        namespace['bbl'].BB_OP_MEM = arm.ARM_OP_MEM
        md = cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_ARM)
        md.detail = True
        # ldr r0,[r1]; str r0,[sp,#4]; mov r0,#0; ldr r2,[sp,#4]
        instructions = list(md.disasm(bytes.fromhex(
            '000091e5 04008de5 0000a0e3 04209de5'), 0x1000))
        result = namespace['taintRegsCrossBB'](instructions, set(), True)
        self.assertIn(arm.ARM_REG_R2, result)
        self.assertNotIn(arm.ARM_REG_R0, result)


if __name__ == '__main__':
    unittest.main()
