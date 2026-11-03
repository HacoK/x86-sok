"""Splitting metadata blocks must preserve their original function owners."""
import ast
from pathlib import Path
from types import MethodType, SimpleNamespace
import unittest


def load_block_check():
    source = Path(__file__).resolve().parents[1] / 'ccr/reorderInfo.py'
    tree = ast.parse(source.read_text())
    cls = next(node for node in tree.body
               if isinstance(node, ast.ClassDef) and node.name == 'BasicBlocks')
    method = next(node for node in cls.body
                  if isinstance(node, ast.FunctionDef) and node.name == 'block_check')
    namespace = {}
    exec(compile(ast.Module(body=[method], type_ignores=[]), str(source), 'exec'), namespace)
    return namespace['block_check']


def metadata(counts, sizes, splits):
    addresses = [0x1000 * (index + 1) for index in range(len(sizes))]
    state = SimpleNamespace(
        numBasicBlocks=len(sizes), numBBs=len(sizes), funcBBCnt=list(counts),
        BBSize=list(sizes), BBFixupCnt=[0] * len(sizes),
        BBFallThrough=[False] * len(sizes), BBOffsetFromSection=addresses[:],
        BBSec=['.text'] * len(sizes), BBPadding=[2] * len(sizes),
        BBAssembleType=[0] * len(sizes), BBVA=addresses[:], BBType=[0] * len(sizes),
        getElfParser=lambda: SimpleNamespace(getSectionVA=lambda section: 0),
        multi_jump=lambda index: (splits[index], [True] * len(splits[index])),
        count_fixup=lambda start, end, fixups: sum(pc in fixups for pc in range(start, end, 2)),
    )
    state.block_check = MethodType(load_block_check(), state)
    return state


class MetadataFunctionOwnershipTests(unittest.TestCase):
    def test_splits_in_two_functions_update_their_own_counts(self):
        state = metadata([1, 1], [10, 14],
                         [[0x1004, 0x1008], [0x2004, 0x2008, 0x200c]])
        state.block_check([0x1002, 0x1006, 0x2002, 0x2006, 0x200a], ['.text'] * 5)
        self.assertEqual(state.funcBBCnt, [2, 3])
        self.assertEqual(state.numBBs, 5)
        self.assertEqual(state.BBOffsetFromSection[:state.funcBBCnt[0]], [0x1000, 0x1004])
        self.assertEqual(state.BBOffsetFromSection[state.funcBBCnt[0]:],
                         [0x2000, 0x2004, 0x2008])
        self.assertEqual(state.BBSize, [4, 6, 4, 4, 6])
        self.assertEqual(state.BBPadding, [0, 2, 0, 0, 2])
        self.assertEqual(state.BBFallThrough, [True, False, True, True, False])
        self.assertEqual(state.BBFixupCnt, [1, 1, 1, 1, 1])

    def test_original_multiple_block_boundary_survives_an_early_split(self):
        state = metadata([2, 1], [10, 6, 10],
                         [[0x1004, 0x1008], [0x2004], [0x3004, 0x3008]])
        state.block_check([], [])
        self.assertEqual(state.funcBBCnt, [3, 2])
        self.assertEqual(state.BBOffsetFromSection[:3], [0x1000, 0x1004, 0x2000])
        self.assertEqual(state.BBOffsetFromSection[3:], [0x3000, 0x3004])

    def test_unmodified_blocks_preserve_function_counts(self):
        state = metadata([1, 1], [6, 6], [[0x1004], [0x2004]])
        state.block_check([], [])
        self.assertEqual(state.funcBBCnt, [1, 1])
        self.assertEqual(state.numBBs, 2)
        self.assertEqual(state.BBOffsetFromSection, [0x1000, 0x2000])


if __name__ == '__main__':
    unittest.main()
