"""Regressions for exact site-level jump-table successor comparison.

The comparison routines do not depend on the legacy binary/protobuf loaders.
Load those routines alone so these checks also run without those dependencies.
"""

import ast
import contextlib
import io
import logging
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
COMPARATORS = (
    "compareJmpTable.py",
    "compareJmpTableX86.py",
    "compareJmpTableGt.py",
)


def load_comparison(filename):
    path = ROOT / "compare" / filename
    tree = ast.parse(path.read_text(), filename=str(path))
    tree.body = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name in ("compareSuccessors", "compareJmpTables")
    ]
    namespace = {"logging": logging, "isGhidra": False}
    exec(compile(tree, str(path), "exec"), namespace)
    return namespace


class JumpTableComparisonTests(unittest.TestCase):
    def compare(self, filename, expected, actual, ghidra=False):
        namespace = load_comparison(filename)
        namespace["isGhidra"] = ghidra
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            namespace["compareJmpTables"](expected, actual, set(expected))
        return output.getvalue()

    def test_equal_cardinality_substitution_is_wrong_for_every_tool(self):
        for filename in COMPARATORS:
            for ghidra in (False, True):
                with self.subTest(filename=filename, ghidra=ghidra):
                    with self.assertLogs(level="ERROR") as logs:
                        output = self.compare(
                            filename, {0x100: {0x200, 0x300}},
                            {0x100: {0x200, 0x400}}, ghidra,
                        )
                    self.assertIn("Wrong successors number is 1", output)
                    self.assertIn("Recall: 0.000000", output)
                    self.assertIn("Precision: 0.000000", output)
                    messages = "\n".join(logs.output)
                    self.assertIn("FalsePositive Successor #1: 0x400", messages)
                    self.assertIn("FalseNegative Successor #1: 0x300", messages)

    def test_one_extra_target_does_not_count_as_true_positive(self):
        for filename in COMPARATORS:
            for ghidra in (False, True):
                with self.subTest(filename=filename, ghidra=ghidra):
                    with self.assertLogs(level="ERROR"):
                        output = self.compare(
                            filename, {0x100: {0x200, 0x300}},
                            {0x100: {0x200, 0x300, 0x400}}, ghidra,
                        )
                    self.assertIn("Wrong successors number is 1", output)
                    self.assertIn("Precision: 0.000000", output)

    def test_equal_unique_targets_match(self):
        for filename in COMPARATORS:
            with self.subTest(filename=filename):
                output = self.compare(
                    filename, {0x100: [0x200, 0x300, 0x200]},
                    {0x100: [0x300, 0x200]},
                )
                self.assertIn("Wrong successors number is 0", output)
                self.assertIn("Recall: 1.000000", output)
                self.assertIn("Precision: 1.000000", output)

    def test_empty_results_do_not_divide_by_zero(self):
        for filename in COMPARATORS:
            with self.subTest(filename=filename):
                output = self.compare(filename, {}, {})
                self.assertIn("Wrong successors number is 0", output)
                if filename == "compareJmpTableGt.py":
                    self.assertIn("F1 Score: 0.000000", output)

    def test_missing_and_spurious_sites_keep_their_accounting(self):
        for filename in COMPARATORS:
            with self.subTest(filename=filename):
                with self.assertLogs(level="ERROR"):
                    output = self.compare(
                        filename, {0x100: {0x200, 0x300}},
                        {0x110: {0x200, 0x300}},
                    )
                self.assertIn("False negative number is 1", output)
                self.assertIn("False positive number is 1", output)
                self.assertIn("Wrong successors number is 0", output)


if __name__ == "__main__":
    unittest.main()
