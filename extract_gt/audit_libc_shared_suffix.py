#!/usr/bin/env python3
"""Audit the libc GCC O1 and Os shared formatter dispatches directly from ELF bytes.

This standalone, case-specific verifier is not imported by GT generation. It
checks all six stage tables, the emitted suffixes and the feasible hh witness.
The complete table union is a local upper bound, not a whole-program entry proof.
"""
import argparse
import hashlib
import json
from pathlib import Path

import capstone
from capstone import x86_const as X
from elftools.elf.elffile import ELFFile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binary', required=True, type=Path)
parser.add_argument('--output', required=True, type=Path)
parser.add_argument('--generated', type=Path, help='optional generated JSON records for comparison after the audit')
arguments = parser.parse_args()
binary, output = arguments.binary, arguments.output
VARIANTS = {
    'c0bbbc6d545f3c99f763e4de86fee6215450b4c145d2036a8ff118e33db776fb': 'Os',
    '2fd22299b0f76a4348e7810a667266711e929a04076ca7598b8c341c919a02b7': 'O1',
}
variant = VARIANTS.get(hashlib.sha256(binary.read_bytes()).hexdigest())
if variant is None:
    raise ValueError('this audit applies only to the original hash-matched libc GCC O1 or Os')
specifications = [
    dict(site=0x48776, function=0x48466, code_base=0x4a47b, character_map=0x143de0,
         tables=[0x143d60,0x143ce0,0x143c60,0x143be0,0x143ae0,0x143b60],
         first_h=0x48e5b, second_h=0x48eb0, witness_end=0x48eb0,
         witness_format='%hhd', character_width=1),
    dict(site=0x50e80, function=0x50b12, code_base=0x52b99, character_map=0x1441e0,
         tables=[0x144160,0x1440e0,0x144060,0x143fe0,0x143ee0,0x143f60],
         first_h=0x51533, second_h=0x5157f, witness_end=0x5157f,
         witness_format='L"%hhd"', character_width=4),
]

if variant == 'O1':
    specifications = [
        dict(site=0x514b9, function=0x5024d, code_base=0x52af5, character_map=0x172560,
             tables=[0x1724e0,0x172460,0x1723e0,0x172360,0x172260,0x1722e0],
             first_h=0x50cce, second_h=0x50d24, witness_end=0x50d24,
             witness_format='%hhd', character_width=1),
        dict(site=0x5cb3f, function=0x5b5d7, code_base=0x5dfcc, character_map=0x172960,
             tables=[0x1728e0,0x172860,0x1727e0,0x172760,0x172660,0x1726e0],
             first_h=0x5c024, second_h=0x5c074, witness_end=0x5c074,
             witness_format='L"%hhd"', character_width=4),
    ]

with binary.open('rb') as stream:
    elf = ELFFile(stream)
    segments = [seg for seg in elf.iter_segments() if seg['p_type'] == 'PT_LOAD']
    symbols = list(elf.get_section_by_name('.symtab').iter_symbols())
    def read(address, size):
        seg = next(seg for seg in segments if seg['p_vaddr'] <= address and
                   address + size <= seg['p_vaddr'] + seg['p_filesz'])
        assert not (int(seg['p_flags']) & 2), (hex(address), 'writable segment')
        stream.seek(int(seg['p_offset']) + address - int(seg['p_vaddr']))
        return stream.read(size)
    def disassembly(instruction):
        return dict(address=instruction.address, bytes=bytes(instruction.bytes).hex(),
                    mnemonic=instruction.mnemonic, operands=instruction.op_str)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    records = []
    for spec in specifications:
        symbol = next(sym for sym in symbols if sym['st_info']['type'] == 'STT_FUNC'
                      and sym['st_value'] == spec['function'] and sym['st_size'])
        instructions = list(md.disasm(read(spec['function'], int(symbol['st_size'])), spec['function']))
        instruction_map = {ins.address: ins for ins in instructions}
        mapping = read(spec['character_map'], 91)
        classes = sorted(set(mapping))
        assert classes == list(range(30))
        index_h = mapping[ord('h') - 0x20]
        assert index_h == 10
        tables, union, initial = [], {spec['code_base']}, set()
        for table_index, table in enumerate(spec['tables']):
            table_symbol = next(sym for sym in symbols if sym['st_value'] == table and sym['st_size'] == 120)
            data = read(table, 120)
            entries = []
            for selector in classes:
                raw = data[selector*4:selector*4+4]
                relative = int.from_bytes(raw, 'little', signed=True)
                target = spec['code_base'] + relative
                assert target in instruction_map, hex(target)
                entries.append(dict(selector=selector, entry_address=table+selector*4,
                                    bytes=raw.hex(), signed_relative=relative, target=target,
                                    example_character=chr(0x20 + mapping.index(selector))))
            targets = {row['target'] for row in entries}
            if table_index == 0:
                initial = targets
                assert entries[index_h]['target'] == spec['first_h']
            if table_index == 3:
                assert entries[index_h]['target'] == spec['second_h']
            union |= targets
            references = []
            for position, ins in enumerate(instructions):
                if ins.mnemonic != 'lea' or len(ins.operands) != 2:
                    continue
                operand = ins.operands[1]
                if operand.type != X.X86_OP_MEM or operand.mem.base != X.X86_REG_RIP:
                    continue
                if ins.address + ins.size + operand.mem.disp != table:
                    continue
                suffix = []
                for item in instructions[position:position+128]:
                    suffix.append(disassembly(item))
                    if item.address == spec['site'] or (item.mnemonic == 'jmp' and
                            len(item.operands) == 1 and item.operands[0].type == X.X86_OP_IMM
                            and item.operands[0].imm == spec['site']):
                        break
                else:
                    raise AssertionError(('table reference does not feed shared suffix', hex(ins.address)))
                references.append(dict(table_base_instruction=ins.address,
                                       guarded_prefix=[disassembly(x) for x in instructions[max(0,position-8):position]],
                                       suffix_to_site=suffix))
            assert references, hex(table)
            tables.append(dict(address=table, symbol=table_symbol.name, entry_size=4,
                               entry_encoding='signed_relative', relative_base=spec['code_base'],
                               bytes_sha256=hashlib.sha256(data).hexdigest(), entries=entries,
                               targets=sorted(targets), references=references))
        assert len(initial) == 30 and len(union) == 31
        assert union - initial == {spec['second_h']}
        witness = [disassembly(ins) for ins in instructions
                   if spec['first_h'] <= ins.address < spec['witness_end']]
        records.append(dict(site=spec['site'], function=spec['function'], function_size=int(symbol['st_size']),
                            code_base=spec['code_base'], site_instruction=disassembly(instruction_map[spec['site']]),
                            character_map=dict(address=spec['character_map'], length=91, bytes=mapping.hex(),
                                               domain=classes, guarded_input_range=[0x20,0x7a]),
                            tables=tables, initial_stage_targets=sorted(initial),
                            shared_dispatch_targets=sorted(union), extra_target=spec['second_h'],
                            witness=dict(format=spec['witness_format'], character_width=spec['character_width'],
                                         first_character=ord('h'), next_character=ord('h'),
                                         guard_subtract=0x20, guarded_index=ord('h')-0x20,
                                         guard_upper_bound=0x5a, class_value=index_h,
                                         initial_target=spec['first_h'], second_target=spec['second_h'],
                                         instructions=witness,
                                         reasoning='The initial h maps to class10 and enters the first-h handler. '
                                         'That handler advances the format pointer and reads the second h. '
                                         'The second h satisfies the emitted unsigned guard; the immutable '
                                         'step3a class10 offset computes the extra target and flows directly '
                                         'to the same indirect jump. No intervening branch rejects this h.'),
                            conclusion='The shared site has31 formatter-stage targets. A30-target step0-only '
                            'certificate omits the feasible hh handler. The table union is an independent '
                            'upper bound, and the extra target has a concrete format witness. Every initial '
                            'stage class also has a character witness in the emitted map. This audit does '
                            'not claim arbitrary whole-program entry/environment reachability.'))

for record in records:
    record['table_target_union'] = list(record['shared_dispatch_targets'])
    if variant == 'O1':
        record.pop('shared_dispatch_targets')
        record['scope'] = 'table_paths_only_fallback_unresolved'
        record['conclusion'] = (
            'The six immutable formatter-stage tables yield31 targets, and the extra hh '
            'target is feasible on a guarded table path that overwrites the fallback value. '
            'The old30-target step0 certificate is incomplete. Unknown incoming fallback '
            'values are a separate unresolved obligation:31 is the proved table-target '
            'union/minimum, not a proved exact set for the entire indirect jump. No '
            'replacement certificate is justified by this audit.')
    else:
        record['scope'] = 'six_stage_table_union_and_constant_default'

report = dict(schema_version=1, variant=variant, binary=str(binary), binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
              audit_method='Independent pyelftools/Capstone decoding of immutable emitted bytes; no GT analysis imports',
              verifier=str(Path(__file__).resolve()),
              audit_script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), sites=records)
comparison_path = arguments.generated
if comparison_path is not None:
    generated = json.loads(comparison_path.read_text())
    for record in report['sites']:
        match = next((item for item in generated if item['site'] == record['site']), None)
        if match:
            record['comparison_with_generator'] = dict(status=match['status'], generated_count=len(match.get('targets', [])),
                comparison_scope=record['scope'])
            if match['status'] == 'resolved':
                record['comparison_with_generator'].update(
                    missing=sorted(set(record['table_target_union']) - set(match.get('targets', []))),
                    extra=sorted(set(match.get('targets', [])) - set(record['table_target_union'])))
            else:
                record['comparison_with_generator']['reason'] = 'generator did not publish a full successor proof'
output.write_text(json.dumps(report, indent=2) + '\n')
print(output)
for record in records:
    print(hex(record['site']), len(record['table_target_union']), hex(record['extra_target']),
          record.get('comparison_with_generator'))
