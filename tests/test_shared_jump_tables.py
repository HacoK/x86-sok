"""Behavioral checks for shared handwritten table metadata.

Load the post-analysis function alone so these fixtures do not require the
legacy extractor's compiler/protobuf dependencies.
"""
import ast
import itertools
import logging
from pathlib import Path
from types import SimpleNamespace
import unittest


def load_heuristic():
    source = Path(__file__).resolve().parents[1] / "extract_gt" / "extractBB.py"
    tree = ast.parse(source.read_text())
    function = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef)
                    and node.name == "heuristicSearchingJmptbl")
    namespace = {
        "POST_ANA_JMPTBLS": 0,
        "logging": logging,
        "bbl": SimpleNamespace(BB_ARCH="x86"),
        "isInRange": lambda address, ranges: any(
            start <= address < end for start, end in ranges),
    }
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(source),
                 "exec"), namespace)
    return namespace


def fixup(address, target, entries=0, width=4, relative=True):
    return SimpleNamespace(VA=address, refTo=target, derefSz=width,
                           numJTEntries=entries, jtEntrySz=width if entries else 0,
                           isRela=relative)


def fixture(references, slots=8):
    data = [fixup(0x2000 + 4 * index, 0x1000 + index)
            for index in range(slots)]
    return SimpleNamespace(
        constructInfo=SimpleNamespace(BasicBlockLayout=[
            SimpleNamespace(VA=0x1000, size=0x100, assembleType=2)]),
        getFixupsText=lambda: references,
        getFixupsRodata=lambda: data,
    )


class SharedJumpTableTests(unittest.TestCase):
    def setUp(self):
        self.namespace = load_heuristic()
        self.run_heuristic = self.namespace["heuristicSearchingJmptbl"]

    def test_all_references_to_shared_table_are_annotated(self):
        references = [fixup(0x3000 + 4 * index, 0x2000)
                      for index in range(40)]
        self.run_heuristic(fixture(references))
        self.assertEqual([(ref.jtEntrySz, ref.numJTEntries)
                          for ref in references], [(4, 8)] * 40)
        self.assertEqual(self.namespace["POST_ANA_JMPTBLS"], 40)

    def test_adjacent_tables_and_duplicate_references_are_order_independent(self):
        # Distinct references delimit two adjacent tables, including a small
        # fragment that must not swallow later users of either complete table.
        for targets in itertools.permutations([0x2000, 0x2004, 0x2010, 0x2010]):
            references = [fixup(0x3000 + 4 * index, target)
                          for index, target in enumerate(targets)]
            self.run_heuristic(fixture(references))
            expected = {0x2000: 0, 0x2004: 3, 0x2010: 4}
            self.assertEqual([ref.numJTEntries for ref in references],
                             [expected[target] for target in targets])

    def test_compiler_annotation_survives_heuristic_split(self):
        compiler_reference = fixup(0x3000, 0x2000, entries=8, width=8)
        other_reference = fixup(0x3010, 0x2010)
        self.run_heuristic(fixture([compiler_reference, other_reference]))
        self.assertEqual((compiler_reference.jtEntrySz,
                          compiler_reference.numJTEntries), (8, 8))
        self.assertEqual(other_reference.numJTEntries, 4)
        self.assertEqual(self.namespace["POST_ANA_JMPTBLS"], 1)

    def test_relative_reference_is_normalized_only_if_accepted(self):
        accepted = fixup(0x3000, 0x2000 - 0x3000 + 2, relative=False)
        rejected = fixup(0x3010, 0x201c - 0x3010 + 2, relative=False)
        rejected_target = rejected.refTo
        self.run_heuristic(fixture([accepted, rejected]))
        self.assertEqual((accepted.refTo, accepted.numJTEntries), (0x2000, 7))
        self.assertEqual((rejected.refTo, rejected.numJTEntries),
                         (rejected_target, 0))

    def test_repeated_analysis_does_not_recount_or_rewrite_metadata(self):
        references = [fixup(0x3000, 0x2000), fixup(0x3010, 0x2000)]
        info = fixture(references)
        self.run_heuristic(info)
        self.run_heuristic(info)
        self.assertEqual(self.namespace["POST_ANA_JMPTBLS"], 2)
        self.assertEqual([ref.numJTEntries for ref in references], [8, 8])


if __name__ == "__main__":
    unittest.main()
