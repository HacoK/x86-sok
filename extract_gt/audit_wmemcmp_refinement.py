#!/usr/bin/env python3
"""Independently replay the four reported libc O1 wmemcmp refinements.

This is a case-specific audit, not an input to GT generation. It decodes the
original ELF without importing the selector analyzer. Its proof is a local
CFG upper bound; it does not establish source-level input reachability.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

import capstone
from capstone import x86_const as X
from elftools.elf.elffile import ELFFile

os.environ.setdefault('PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION', 'python')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'protobuf_def'))
import blocks_pb2


EXPECTED_SHA256 = '2fd22299b0f76a4348e7810a667266711e929a04076ca7598b8c341c919a02b7'
# (first unsigned guard, second guard, subtraction, shared suffix, jump)
CASES = [(0x14f0fc, 0x14f106, 0x14f134, 0x14f140, 0x14f154),
         (0x14f2f8, 0x14f302, 0x14f330, 0x14f33c, 0x14f350),
         (0x14f605, 0x14f60f, 0x14f63d, 0x14f649, 0x14f65d),
         (0x14f810, 0x14f81a, 0x14f848, 0x14f854, 0x14f868)]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def successors(ins):
    if ins.group(capstone.CS_GRP_RET) or ins.mnemonic in ('ud2', 'hlt'):
        return []
    if ins.group(capstone.CS_GRP_JUMP) or ins.mnemonic.startswith('loop'):
        targets = [ins.operands[0].imm] if ins.operands[0].type == X.X86_OP_IMM else []
        return targets + ([] if ins.mnemonic == 'jmp' else [ins.address + ins.size])
    return [ins.address + ins.size]


def audit(binary, metadata):
    binary_bytes = binary.read_bytes()
    digest = hashlib.sha256(binary_bytes).hexdigest()
    require(digest == EXPECTED_SHA256, 'this audit applies only to the original hash-matched libc O1')
    with binary.open('rb') as stream:
        elf = ELFFile(stream)
        segments = [(int(s['p_vaddr']), int(s['p_filesz']), int(s['p_offset']), int(s['p_flags']))
                    for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
        symbols = [s for s in elf.get_section_by_name('.symtab').iter_symbols()
                   if s.name == '__wmemcmp_sse4_1']
        require(len(symbols) == 1, 'missing or ambiguous function symbol')
        start, size = int(symbols[0]['st_value']), int(symbols[0]['st_size'])

    def read(address, count, readonly=False):
        for base, length, offset, flags in segments:
            if base <= address and address + count <= base + length:
                require(not readonly or not flags & 2, 'table is writable')
                data = binary_bytes[offset + address - base:offset + address - base + count]
                require(len(data) == count, 'truncated ELF segment')
                return data
        raise ValueError('unmapped ELF read')

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    instructions = {i.address: i for i in md.disasm(read(start, size), start)}
    require(sum(i.size for i in instructions.values()) == size, 'incomplete function decoding')
    table = 0x178ee0
    slots = [table + x for x in struct.unpack('<80i', read(table, 320, readonly=True))]
    require(all(t in instructions for t in slots), 'table target outside decoded function')
    module = blocks_pb2.module()
    module.ParseFromString(metadata.read_bytes())
    recorded = {i.va: i.size for f in module.fuc for b in f.bb for i in b.instructions}
    decoded_edges, undecoded, size_repairs = [], [], []
    for address, count in recorded.items():
        ins = next(md.disasm(read(address, count or 15), address, count=1), None)
        if ins is None and count:
            ins = next(md.disasm(read(address, 15), address, count=1), None)
            if ins is not None:
                size_repairs.append({'address': hex(address), 'recorded_size': count,
                                     'decoded_size': ins.size, 'instruction': ins.mnemonic + ' ' + ins.op_str})
        if ins is None:
            undecoded.append(hex(address))
            continue
        if ((ins.group(capstone.CS_GRP_JUMP) or ins.group(capstone.CS_GRP_CALL)
             or ins.mnemonic.startswith('loop')) and ins.operands
                and ins.operands[0].type == X.X86_OP_IMM):
            decoded_edges.append((address, ins.operands[0].imm))
    known_edges = [(b.instructions[-1].va, c.va) for f in module.fuc for b in f.bb
                   if b.instructions for c in b.child]
    results = []
    for high, low, subtract, suffix, site in CASES:
        end = instructions[site].address + instructions[site].size
        region = {a: i for a, i in instructions.items() if high <= a < end}
        for address, immediate in [(high, 64), (low, 32)]:
            ins = region[address]
            require(ins.mnemonic == 'cmp' and ins.reg_name(ins.operands[0].reg) == 'rdx'
                    and ins.operands[1].type == X.X86_OP_IMM
                    and ins.operands[1].imm == immediate, 'unsigned guard mismatch')
        upper_branch = region[high + region[high].size]
        require(upper_branch.mnemonic == 'jae' and upper_branch.operands[0].imm not in region,
                'upper guard must branch out of the suffix')
        lower_branch = region[low + region[low].size]
        require(lower_branch.mnemonic == 'jb' and lower_branch.operands[0].imm == suffix,
                'lower guard branch mismatch')
        sub = region[subtract]
        require(sub.mnemonic == 'sub' and sub.op_str == 'rdx, 0x20', 'subtraction mismatch')
        for address, ins in region.items():
            if address == subtract:
                continue
            require(X.X86_REG_RDX not in ins.regs_access()[1], 'unexpected selector write')
        # A path must enter at the first guard. Check fallthroughs in the full
        # decoded function, all recorded direct branches/calls, and child edges.
        incoming = [(a, t) for a, ins in instructions.items() for t in successors(ins)]
        incoming += decoded_edges + known_edges
        bypasses = sorted({(a, t) for a, t in incoming if high < t < end and a not in region})
        require(not bypasses, 'an incoming edge bypasses the first guard')
        # Enumerate the finite domain after the first guard. Above 63 the
        # branch exits this suffix. All other conditions are nondeterministic.
        pending = [(high + region[high].size, n) for n in range(64)]
        seen, live = set(), set()
        while pending:
            address, n = pending.pop()
            if (address, n) in seen or address not in region:
                continue
            seen.add((address, n))
            if address == site:
                live.add(n)
                continue
            ins = region[address]
            next_addresses = successors(ins)
            if address == high + region[high].size:
                next_addresses = [address + ins.size]  # n < 64
            elif address == lower_branch.address:
                next_addresses = [suffix if n < 32 else address + ins.size]
            if address == subtract:
                n -= 32
            pending.extend((target, n) for target in next_addresses)
        require(live == set(range(32)), 'unexpected local selector domain')
        tail = [region[a] for a in sorted(region) if suffix <= a <= site]
        require([i.mnemonic for i in tail] == ['add', 'add', 'lea', 'movsxd', 'add', 'jmp'],
                'table dispatch pattern mismatch')
        lea, load, add, jump = tail[2:]
        require(lea.op_str.startswith('r11, [rip + ')
                and lea.address + lea.size + lea.operands[1].mem.disp == table,
                'table base mismatch')
        require(load.op_str == 'rcx, dword ptr [r11 + rdx*4]'
                and add.op_str == 'rcx, r11' and jump.op_str == 'rcx', 'table load mismatch')
        results.append({'site': hex(site), 'first_guard': hex(high), 'second_guard': hex(low),
                        'subtract': hex(subtract), 'suffix': hex(suffix),
                        'selectors': sorted(live), 'physical_unique_targets': len(set(slots)),
                        'bounded_unique_targets': len({slots[n] for n in live}),
                        'targets': [hex(t) for t in sorted({slots[n] for n in live})],
                        'bypassing_incoming_edges': bypasses,
                        'instructions': [f'{hex(i.address)} {i.mnemonic} {i.op_str}'
                                         for i in region.values()]})
    return {'binary': str(binary), 'binary_sha256': digest, 'metadata': str(metadata),
            'metadata_sha256': hashlib.sha256(metadata.read_bytes()).hexdigest(),
            'scope': 'local CFG upper bound, assuming recorded incoming-edge coverage',
            'source_reachability_proved': False, 'table': hex(table), 'physical_slots': 80,
            'recorded_instructions_checked': len(recorded),
            'undecoded_metadata_addresses': undecoded,
            'metadata_size_repairs': size_repairs,
            'function_instructions_decoded': len(instructions), 'sites': results,
            'caveat': 'Non-multiple-of-four selectors lead to 0x14fd21. Valid C wchar_t '
                      'alignment may exclude them; this audit does not prove exact caller reachability.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('metadata', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    result = audit(args.binary, args.metadata)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'sites': len(result['sites']), 'refinements': [
        [r['site'], r['physical_unique_targets'], r['bounded_unique_targets']] for r in result['sites']]}))


if __name__ == '__main__':
    main()
