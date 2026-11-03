#!/usr/bin/env python3
"""Counterfactual memory-contract experiment for the two libc O1 dispatches.

This script never changes GT and its results are not accepted by the generator.
It asks whether the existing CFG analysis would finish under an explicitly
ASSUMED object/alias contract. It enumerates fixed and location-list DWARF
frame locations and direct RBP address materializations, but does not prove
complete pointer provenance, dynamic-allocation separation, arbitrary callback
effects, or faithful source object metadata. Those gaps remain assumptions.
A successful conditional replay therefore does not resolve either default site.
"""
import os, sys, json, hashlib
from pathlib import Path
from types import SimpleNamespace
os.environ['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] = 'python'
SOURCE_DIR = Path(__file__).resolve().parent
sys.path[:0] = [str(SOURCE_DIR), str(SOURCE_DIR.parent / 'protobuf_def')]
import blocks_pb2, jump_table_analysis as a
from jump_table_dataflow import function_dataflow
from jump_table_reaching import recover_reaching_tables
from elftools.elf.elffile import ELFFile
from elftools.dwarf.dwarf_expr import DWARFExprParser
from elftools.dwarf.locationlists import LocationParser
from capstone import x86_const as X
import capstone

def main():
    import argparse
    argparser = argparse.ArgumentParser(description=__doc__)
    argparser.add_argument('--binary', type=Path, default=Path('/mnt/nvme1/sba/x86_dataset/linux/libs/gcc_O1/libc-2.27.so'))
    argparser.add_argument('--metadata', type=Path, default=Path('/tmp/x86-sok-presemantic-current-libc-O1.pb'))
    argparser.add_argument('--output', type=Path, default=Path('/mnt/nvme1/sba/reports/x86_sok_libc_o1_conditional_frame_experiment.json'))
    argparser.add_argument('--reference-audit', type=Path, default=Path('/mnt/nvme1/sba/reports/x86_sok_libc_o1_shared_suffix_audit.json'))
    args = argparser.parse_args()
    binary = args.binary
    if hashlib.sha256(binary.read_bytes()).hexdigest() != '2fd22299b0f76a4348e7810a667266711e929a04076ca7598b8c341c919a02b7':
        raise ValueError('this diagnostic applies only to the original GCC O1 libc')
    metadata = args.metadata
    module = blocks_pb2.module()
    module.ParseFromString(metadata.read_bytes())
    image = a._Image(str(binary))
    entries = {f.va for f in module.fuc}

    def digest(path):
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    stream = binary.open('rb')
    elf = ELFFile(stream)
    dwarf = elf.get_dwarf_info()
    parser = DWARFExprParser(dwarf.structs)

    def typedie(die):
        if 'DW_AT_type' in die.attributes:
            return die.get_DIE_from_attribute('DW_AT_type')
        for key in ['DW_AT_abstract_origin', 'DW_AT_specification']:
            if key in die.attributes:
                return typedie(die.get_DIE_from_attribute(key))
        return None

    def size(die, seen=()):
        if die is None or die.offset in seen:
            return None
        at = die.attributes
        if 'DW_AT_byte_size' in at:
            return at['DW_AT_byte_size'].value
        if die.tag == 'DW_TAG_array_type':
            element = size(typedie(die), seen + (die.offset,))
            if element is None:
                return None
            for ch in die.iter_children():
                if ch.tag != 'DW_TAG_subrange_type':
                    continue
                if 'DW_AT_count' in ch.attributes:
                    element *= ch.attributes['DW_AT_count'].value
                elif 'DW_AT_upper_bound' in ch.attributes:
                    upper = ch.attributes['DW_AT_upper_bound']
                    lower = ch.attributes.get('DW_AT_lower_bound')
                    if not isinstance(upper.value, int) or (lower and (not isinstance(lower.value, int))):
                        return None
                    element *= upper.value - (lower.value if lower else 0) + 1
                else:
                    return None
            return element
        return size(typedie(die), seen + (die.offset,))

    def objects(fn):
        cu = dwarf.get_CU_at(dwarf.get_aranges().cu_offset_at_addr(fn))
        found = []

        def visit(die):
            at = die.attributes
            if die.tag in ('DW_TAG_variable', 'DW_TAG_formal_parameter') and 'DW_AT_location' in at:
                locs = LocationParser(dwarf.location_lists()).parse_from_attribute(at['DW_AT_location'], cu['version'], die=die)
                locs = [locs] if hasattr(locs, 'loc_expr') else locs
                for loc in locs:
                    if not hasattr(loc, 'loc_expr'):
                        continue
                    op = parser.parse_expr(loc.loc_expr)
                    if op and op[0].op_name in ('DW_OP_fbreg', 'DW_OP_breg6') and (len(op) == 1 or (len(op) == 2 and op[1].op_name == 'DW_OP_piece')):
                        width = size(typedie(die))
                        if width is None:
                            raise ValueError('unknown object size at' + hex(die.offset))
                        offset = op[0].args[0] + (8 if op[0].op_name == 'DW_OP_fbreg' else -8)
                        entry = {'die': die.offset, 'name': at['DW_AT_name'].value.decode() if 'DW_AT_name' in at else None, 'entry_rsp_offset': offset, 'size': width, 'location_form': at['DW_AT_location'].form, 'location_expression': list(loc.loc_expr)}
                        if entry not in found:
                            found.append(entry)
            for ch in die.iter_children():
                if ch.tag != 'DW_TAG_subprogram':
                    visit(ch)
        for die in cu.iter_DIEs():
            if die.tag == 'DW_TAG_subprogram' and die.attributes.get('DW_AT_low_pc') and (die.attributes['DW_AT_low_pc'].value == fn):
                assert die.attributes['DW_AT_frame_base'].value == [156]
                visit(die)
        return found
    results = []
    for site in [332985, 379711]:
        item = next((f for f in module.fuc if any((i.va == site for b in f.bb for i in b.instructions))))
        fn = a._Function(item, image, entries)
        obs = objects(fn.va)
        address_materializations = []
        unproved_dynamic_materializations = []
        for instruction in fn.instructions.values():
            operands = instruction.operands
            if instruction.mnemonic == 'lea' and len(operands) == 2 and (operands[1].type == X.X86_OP_MEM) and (operands[0].reg != X.X86_REG_RSP):
                mem = operands[1].mem
                if mem.base == X.X86_REG_RBP and (not mem.index):
                    address_materializations.append({'instruction': instruction.address, 'offset': mem.disp - 8})
                elif mem.base == X.X86_REG_RSP:
                    unproved_dynamic_materializations.append(instruction.address)
        escaped = [o for o in obs if any((o['entry_rsp_offset'] <= m['offset'] < o['entry_rsp_offset'] + o['size'] for m in address_materializations))]
        regions = [(o['entry_rsp_offset'], o['entry_rsp_offset'] + o['size']) for o in escaped]
        events = set()

        def offset(expr):
            base, n = a._address_parts(expr)
            if base != ('var', 'entry-frame:%x' % fn.va, 64):
                return None
            return n if n < 1 << 63 else n - (1 << 64)

        def containsframe(expr):
            return expr == ('var', 'entry-frame:%x' % fn.va, 64) or any((containsframe(x) for x in expr[1:] if isinstance(x, tuple)))

        class ConditionalState(a._State):

            def preserve(self, ins, operation):
                explicit_stores = {'mov', 'movabs', 'add', 'sub', 'and', 'or', 'xor', 'shl', 'sal', 'shr', 'sar', 'rol', 'ror', 'rcl', 'rcr', 'inc', 'dec', 'not', 'neg', 'cmpxchg', 'xchg', 'xadd', 'movdqu', 'movdqa', 'movups', 'movaps'}
                opcode = ins.mnemonic.removeprefix('lock ')
                modeled_store = opcode in explicit_stores and bool(ins.operands) and (ins.operands[0].type == X.X86_OP_MEM)
                if not (ins.group(capstone.CS_GRP_CALL) or modeled_store):
                    operation()
                    return
                before = dict(self.stack)
                writes = []
                unbounded = False
                for op_index, op in enumerate(ins.operands):
                    if op.type == X.X86_OP_MEM and (op.access & capstone.CS_AC_WRITE or (modeled_store and op_index == 0)):
                        try:
                            addr = self.address(ins, op)
                            off = offset(addr)
                            if off is not None:
                                writes.append((off, off + op.size))
                            elif containsframe(addr):
                                unbounded = True
                        except a.Unresolved:
                            pass
                if ins.group(capstone.CS_GRP_CALL):
                    rsp = self.regs.get('rsp')
                    off = offset(rsp) if rsp else None
                    if off is None:
                        unbounded = True
                    else:
                        writes.append((off - 8, off))
                operation()
                if unbounded:
                    return
                for addr, value in before.items():
                    off = offset(addr)
                    if off is None:
                        continue
                    high = off + a._bits(value) // 8
                    if any((off < end and start < high for start, end in regions + writes)):
                        continue
                    if addr not in self.stack:
                        self.stack[addr] = value
                        events.add((ins.address, off, a._bits(value)))

            def step(self, ins):
                self.preserve(ins, lambda: super(ConditionalState, self).step(ins))

            def kill(self, ins):
                self.preserve(ins, lambda: super(ConditionalState, self).kill(ins))
        for name in ['_address_parts', '_binary', '_const', '_bits', '_Evaluator', '_ALIASES', '_is_branch', '_successors', '_disjoint', '_extend', 'Unresolved', 'Infeasible']:
            globals()[name] = getattr(a, name)
        recovered = recover_reaching_tables(fn, a._analyze_site, ConditionalState, a._indirect, a.Unresolved, dataflow=function_dataflow)
        rec = next((r for r in recovered['records'] if r['site'] == site), None)
        if rec is not None:
            rec['status'] = 'conditional_only'
            rec['reason'] = 'Finite replay under an assumed memory-effects contract; not an automatic binary proof'
        result = {'default_status': 'unresolved', 'experiment_status': 'conditional_only', 'function': fn.va, 'site': site, 'objects': obs, 'assumed_escaped_objects': escaped, 'frame_address_materializations': address_materializations, 'dynamic_frame_address_materializations_not_proved_disjoint': unproved_dynamic_materializations, 'conditional_preservations': [{'instruction': x, 'offset': y, 'bits': z} for x, y, z in sorted(events)], 'status': recovered['status'], 'reason': recovered['reason'], 'record': rec, 'unresolved_frontiers': recovered.get('unresolved_frontiers', [])}
        results.append(result)
        print(hex(site), 'default=unresolved', 'conditional_closure=' + result['status'], 'conditional_targets=' + str(len(rec['targets']) if rec else None), result['unresolved_frontiers'], flush=True)
    reference = json.loads(args.reference_audit.read_text())
    assert reference['binary_sha256'] == digest(binary)
    expected = {r['site']: r['table_target_union'] for r in reference['sites']}
    for result in results:
        result['matches_independently_decoded_table_union'] = bool(result['record']) and set(result['record']['targets']) == set(expected[result['site']])
    args.output.write_text(json.dumps({'schema_version': 1, 'scope': 'counterfactual_frame_memory_contract', 'not_a_ground_truth_input': True, 'contract_proved': False, 'dwarf_location_coverage_complete': False, 'frame_escape_coverage_complete': False, 'default_status': 'unresolved', 'verifier': str(Path(__file__).resolve()), 'verifier_sha256': digest(__file__), 'generator_sources_sha256': {name: digest(SOURCE_DIR / name) for name in ['jump_table_analysis.py', 'jump_table_dataflow.py', 'jump_table_reaching.py']}, 'reference_audit': str(args.reference_audit), 'reference_audit_sha256': digest(args.reference_audit), 'binary': str(binary), 'binary_sha256': digest(binary), 'input_protobuf_sha256': digest(metadata), 'assumptions': ['Unknown call/store effects are confined to the enumerated frame objects whose addresses are materialized by direct RBP LEAs or to external objects; this is an unproved contract', 'Compiler-private spill storage is not addressable through forged pointers or out-of-object pointer arithmetic', 'DWARF object extents and CFA metadata faithfully describe this compiled function; RBP equals entryRSP-8 while these object locations are live', 'Dynamic RSP-derived allocations, omitted alias paths, callback introspection and unmodeled location expressions do not alias protected frame slots; this is NOT proved'], 'sites': results}, indent=2) + '\n')
if __name__ == '__main__':
    main()
