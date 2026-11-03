"""Control-flow regressions for the metadata-to-indirect-jump association."""
import ast
import logging
from pathlib import Path
from types import SimpleNamespace
import unittest


class BlockTypes:
    INDIRECT_BRANCH = 1
    FALL_THROUGH = 2
    RET = 3
    DIRECT_BRANCH = 4


class DisassemblyBlock:
    def __init__(self, address, start, end, parent, fall_through):
        self.VA, self.start, self.end = address, start, end
        self.parent = parent
        self.type = parent.kind
        self.fall_through = fall_through
        self.is_call = False

    def is_direct_jump(self):
        return self.type == BlockTypes.DIRECT_BRANCH


def block(address, kind, successors=(), writes=None, consumes=None):
    instruction = SimpleNamespace(address=address, size=4, writes=writes,
                                  consumes=consumes, indirect=consumes is not None,
                                  operands=[], mnemonic="jmp")
    return SimpleNamespace(VA=address, size=4, padding=0,
                           offsetFromBase=address, hasFallThrough=False,
                           kind=kind, successors=successors,
                           instruction=instruction)


def load_association(blocks):
    source = Path(__file__).resolve().parents[1] / "extract_gt" / "extractBB.py"
    tree = ast.parse(source.read_text())
    function = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef)
                    and node.name == "findIndirectBB")
    visits = []

    def taint(instructions, state, first):
        for instruction in instructions:
            if first:
                state.add("table-base")
            if instruction.writes is not None:
                state.clear()
                state.update(instruction.writes)
        return state

    def disassemble(current, binary, elf_class):
        visits.append(current.VA)
        return [current.parent.instruction]

    namespace = {
        "logging": logging, "bb_list": {item.VA: item for item in blocks},
        "bbl": SimpleNamespace(BB_ARCH="x86"),
        "x86": SimpleNamespace(X86_OP_IMM=2),
        "jumpTable": {}, "ELF_CLASS": 64, "Blk": DisassemblyBlock,
        "BlockType": BlockTypes, "disassembleBB": disassemble,
        "getTerminator": lambda current, instructions: (instructions[-1], None),
        "getInstsBeginFromAddr": lambda address, instructions: instructions,
        "isJumpTable": lambda instruction: instruction.indirect,
        "taintRegsCrossBB": taint,
        "instReadRegsIsTaint": lambda instruction, state:
            instruction.consumes in state,
        "getSuccessorsFromDirectInst": lambda current, instruction:
            current.parent.successors,
        "getInstStr": str,
    }
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(source),
                 "exec"), namespace)
    return namespace["findIndirectBB"], visits


class JumpTableAssociationTests(unittest.TestCase):
    def test_decoded_conditional_recovers_missing_fallthrough_and_fixup(self):
        # Handwritten libc metadata marks a block ending in JA as having no
        # fallthrough. Its branch fixup may also be missing; the decoded
        # instruction supplies both successors without either metadata field.
        entry = block(0x1000, BlockTypes.DIRECT_BRANCH, successors=None)
        entry.instruction.mnemonic = "ja"
        entry.instruction.operands = [SimpleNamespace(type=2, imm=0x1020)]
        taken = block(0x1020, BlockTypes.INDIRECT_BRANCH, consumes="unrelated")
        fallthrough = block(0x1004, BlockTypes.INDIRECT_BRANCH,
                            consumes="table-base")
        associate, visits = load_association([entry, taken, fallthrough])
        self.assertFalse(entry.hasFallThrough)
        self.assertIs(associate(entry.VA, entry, b""), fallthrough)
        self.assertIn(taken.VA, visits)

    def test_unconditional_jump_does_not_gain_fallthrough(self):
        entry = block(0x1000, BlockTypes.DIRECT_BRANCH, successors=None)
        entry.instruction.operands = [SimpleNamespace(type=2, imm=0x1020)]
        taken = block(0x1020, BlockTypes.INDIRECT_BRANCH, consumes="unrelated")
        fallthrough = block(0x1004, BlockTypes.INDIRECT_BRANCH,
                            consumes="table-base")
        associate, visits = load_association([entry, taken, fallthrough])
        self.assertIsNone(associate(entry.VA, entry, b""))
        self.assertNotIn(fallthrough.VA, visits)

    def test_revisits_join_when_second_path_carries_target_register(self):
        # Both paths keep live table-related taint, but only the second reaches
        # the join with the register consumed by its indirect jump. Visiting
        # solely by address drops that second path and loses the table site.
        entry = block(0x1000, BlockTypes.DIRECT_BRANCH, (0x1010, 0x1020))
        first = block(0x1010, BlockTypes.DIRECT_BRANCH, (0x1030,),
                      writes={"table-base"})
        second = block(0x1020, BlockTypes.DIRECT_BRANCH, (0x1030,),
                       writes={"jump-target"})
        join = block(0x1030, BlockTypes.INDIRECT_BRANCH, consumes="jump-target")
        associate, visits = load_association([entry, first, second, join])
        self.assertIs(associate(entry.VA, entry, b""), join)
        self.assertEqual(visits.count(join.VA), 2)

    def test_repeated_state_on_cycle_terminates(self):
        entry = block(0x1000, BlockTypes.DIRECT_BRANCH, (0x1010,))
        cycle = block(0x1010, BlockTypes.DIRECT_BRANCH, (0x1010, 0x1020))
        unrelated = block(0x1020, BlockTypes.INDIRECT_BRANCH,
                          consumes="unrelated-register")
        associate, visits = load_association([entry, cycle, unrelated])
        self.assertIsNone(associate(entry.VA, entry, b""))
        self.assertEqual(visits.count(cycle.VA), 1)

    def test_untainted_path_does_not_create_table_association(self):
        entry = block(0x1000, BlockTypes.DIRECT_BRANCH, (0x1010,))
        killed = block(0x1010, BlockTypes.DIRECT_BRANCH, (0x1020,), writes=set())
        join = block(0x1020, BlockTypes.INDIRECT_BRANCH, consumes="table-base")
        associate, visits = load_association([entry, killed, join])
        self.assertIsNone(associate(entry.VA, entry, b""))
        self.assertNotIn(join.VA, visits)


if __name__ == "__main__":
    unittest.main()
