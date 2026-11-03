#!/usr/bin/env python3
"""Demonstrate why the Perl selector proof needs nonlocal input invariants.

This case-specific audit runs the original bytes in Unicorn with synthetic
function-entry objects. These are not valid source-level Perl executions and
do not refute the audited seven-target oracle. They show that unconstrained
machine-code function inputs admit selector zero before any call executes.
The script is not an input to GT generation.
"""
import argparse
import hashlib
import json
from pathlib import Path

import capstone
from capstone import x86_const as X
from elftools.elf.elffile import ELFFile
import unicorn
from unicorn import x86_const as U


DATASET = Path('/mnt/nvme1/sba/x86_dataset/linux/cpu2006')
INPUT_REPORT = Path('/mnt/nvme1/sba/reports/x86_sok_perl_data_invariants.json')


def audit(binary, expected_hash, site):
    raw = binary.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != expected_hash:
        raise ValueError('binary hash does not match the prior audit')
    with binary.open('rb') as stream:
        elf = ELFFile(stream)
        symbols = {symbol.name: (int(symbol['st_value']), int(symbol['st_size']))
                   for symbol in elf.get_section_by_name('.symtab').iter_symbols()}
        table, table_size = symbols['PL_opargs']
        entry, function_size = symbols['Perl_ck_fun']
        segments = [(int(segment['p_vaddr']), int(segment['p_memsz']), int(segment['p_filesz']),
                     int(segment['p_offset'])) for segment in elf.iter_segments()
                    if segment['p_type'] == 'PT_LOAD']

    def file_bytes(address, size):
        for start, _, file_size, offset in segments:
            if start <= address and address + size <= start + file_size:
                return raw[offset + address - start:offset + address - start + size]
        return None

    candidate = None
    for index in range(table_size // 4, 1 << 16):
        data = file_bytes(table + index * 4, 4)
        if data is None:
            continue
        value = int.from_bytes(data, 'little')
        shifted = value >> 13
        if shifted and shifted & 7 == 0:
            candidate = index, value, shifted
            break
    if candidate is None:
        raise ValueError('no file-backed local-entry witness was found')
    index, loaded_value, shifted = candidate
    machine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    page = 4096
    mapped = set()
    for start, memory_size, file_size, offset in segments:
        for address in range(start & -page, (start + memory_size + page - 1) & -page, page):
            if address not in mapped:
                machine.mem_map(address, page)
                mapped.add(address)
        machine.mem_write(start, raw[offset:offset + file_size])
    object_address, child_address = 0x600000000000, 0x600000000100
    stack_address, stack_size = 0x700000000000, 0x10000
    machine.mem_map(object_address, page)
    machine.mem_map(stack_address, stack_size)
    op = bytearray(64)
    op[0x20:0x22] = index.to_bytes(2, 'little')
    op[0x24] = 4  # OPf_KIDS, without OPf_SPECIAL.
    op[0x28:0x30] = child_address.to_bytes(8, 'little')
    child = bytearray(64)
    child[0x20:0x22] = (1).to_bytes(2, 'little')
    machine.mem_write(object_address, bytes(op))
    machine.mem_write(child_address, bytes(child))
    machine.reg_write(U.UC_X86_REG_RDI, object_address)
    machine.reg_write(U.UC_X86_REG_RSP, stack_address + stack_size - 256)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    trace, writes, reached = [], [], {}

    def instruction_hook(uc, address, size, _):
        instruction = next(decoder.disasm(bytes(uc.mem_read(address, size)), address, count=1))
        trace.append({'address': address, 'bytes': instruction.bytes.hex(),
                      'mnemonic': instruction.mnemonic, 'operands': instruction.op_str})
        if instruction.group(capstone.CS_GRP_CALL):
            raise ValueError('witness unexpectedly calls another function')
        if address != site:
            return
        operand = instruction.operands[0]
        if instruction.mnemonic != 'jmp' or operand.type != X.X86_OP_MEM or not operand.mem.index:
            raise ValueError('audited dispatch is not an indexed absolute jump')
        selector_name = instruction.reg_name(operand.mem.index)
        selector = uc.reg_read(getattr(U, 'UC_X86_REG_' + selector_name.upper()))
        address = operand.mem.disp + selector * operand.mem.scale
        if operand.mem.base:
            name = instruction.reg_name(operand.mem.base)
            address += uc.reg_read(getattr(U, 'UC_X86_REG_' + name.upper()))
        reached.update({'selector': selector, 'jump_table_entry_address': address,
                        'selected_target': int.from_bytes(uc.mem_read(address, operand.size), 'little')})
        uc.emu_stop()

    def write_hook(uc, access, address, size, value, _):
        writes.append({'address': address, 'size': size})
        if any(start <= address < start + memory_size for start, memory_size, _, _ in segments):
            raise ValueError('witness unexpectedly modifies the original ELF image')

    machine.hook_add(unicorn.UC_HOOK_CODE, instruction_hook)
    machine.hook_add(unicorn.UC_HOOK_MEM_WRITE, write_hook)
    machine.emu_start(entry, entry + function_size, count=100000)
    if reached.get('selector') != 0:
        raise ValueError('the concrete trace did not select zero')
    return {'binary': str(binary), 'binary_sha256': digest, 'entry': entry, 'site': site,
            'table_address': table, 'table_entries': table_size // 4,
            'synthetic_op_type': index, 'out_of_object_read_address': table + index * 4,
            'loaded_initial_word': loaded_value, 'shifted_state': shifted,
            'input_objects': [{'address': object_address, 'bytes': op.hex()},
                              {'address': child_address, 'bytes': child.hex()}],
            'initial_registers': {'rdi': object_address, 'rsp': stack_address + stack_size - 256},
            'memory_writes': writes, 'trace': trace, **reached,
            'scope': 'synthetic machine-code function-entry execution; not a valid source-level Perl execution',
            'calls_executed': 0, 'original_elf_bytes_modified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-report', type=Path, default=INPUT_REPORT)
    parser.add_argument('--output', type=Path, default=Path('/mnt/nvme1/sba/reports/x86_sok_perl_local_counterexamples.json'))
    args = parser.parse_args()
    prior = json.loads(args.input_report.read_text())
    records = [audit(Path(item['binary']), item['binary_sha256'], item['site']) for item in prior['binaries']]
    result = {'schema_version': 1, 'verifier': str(Path(__file__).resolve()),
              'verifier_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'unicorn_version': unicorn.__version__,
              'meaning': 'Function-local machine-code assumptions alone cannot prove the index in bounds or exclude selector zero.',
              'not_claimed': 'These synthetic objects are not shown reachable from valid program inputs and do not refute the seven-target source oracle.',
              'binaries': records}
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps([{'site': hex(row['site']), 'index': row['synthetic_op_type'],
                       'selector': row['selector'], 'target': hex(row['selected_target'])} for row in records]))


if __name__ == '__main__':
    main()
