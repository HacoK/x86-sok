"""Regression coverage for the Perl source-assisted stability audit."""

import sys
from collections import Counter
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'extract_gt'))

from audit_perl_source_initializers import selector_closure, source_references, without_comments


class PerlSourceAuditTests(unittest.TestCase):
    def test_selector_closure_follows_repeated_nibble_state(self):
        values = [(selector << 13) for selector in range(1, 8)]
        values.append((((1 << 4) | 2) << 13))
        self.assertEqual(selector_closure(values), [1, 2, 3, 4, 5, 6, 7])

    def test_selector_closure_rejects_only_selector_zero(self):
        with self.assertRaisesRegex(ValueError, 'do not close'):
            selector_closure([0])

    def test_comment_removal_preserves_source_line_numbers(self):
        source = 'before\n/* one\ntwo\nthree */\nafter\n'
        self.assertEqual(without_comments(source).splitlines(),
                         ['before', '', '', '', 'after'])

    def source_tree(self, root):
        source = root / 'src'
        source.mkdir()
        (source / 'opcode.h').write_text(
            'EXT U32 PL_opargs[];\nEXT U32 PL_opargs[] = {\n  0x1,\n};\n')
        (source / 'proto.h').write_text('PERL_CALLCONV U32* Perl_get_opargs(pTHX);\n')
        (source / 'util.c').write_text(
            'Perl_get_opargs(pTHX)\n{\n return PL_opargs;\n}\n')
        (source / 'op.c').write_text('if (PL_opargs[type] & OA_TARGET)\n    use(type);\n')
        return source

    def test_source_inventory_accepts_reads_and_an_uncalled_getter(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.source_tree(Path(directory))
            result = source_references(source.parent)
        self.assertTrue(result['all_pl_opargs_uses_read_only'])
        self.assertEqual(result['getter_callers'], [])
        self.assertEqual(Counter(row['kind'] for row in result['pl_opargs_uses']),
                         Counter({'definition': 2, 'getter_return': 1, 'read': 1}))

    def test_source_inventory_rejects_a_table_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.source_tree(root)
            (source / 'op.c').write_text('PL_opargs[type] = OA_TARGET;\n')
            with self.assertRaisesRegex(ValueError, 'unsupported PL_opargs use'):
                source_references(root)


if __name__ == '__main__':
    unittest.main()
