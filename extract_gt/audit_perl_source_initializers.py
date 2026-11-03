#!/usr/bin/env python3
"""Match CPU2006 PL_opargs source initializers to the four original ELFs.

This source-assisted audit is separate from binary-only GT generation. It
checks the entire literal initializer, relevant source configuration branches,
the emitted getter, dynamic symbol visibility and loader relocations. It also
inventories writes/escapes in the matching source and scans every sized linked
function symbol for table access direction and getter references.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone
from capstone import x86_const as X
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def without_comments(text):
    text = re.sub(r'/\*.*?\*/', lambda match: '\n' * match.group(0).count('\n'),
                  text, flags=re.S)
    return re.sub(r'//[^\n]*', '', text)


def source_references(source_root):
    """Inventory source uses and reject any write or pointer escape of PL_opargs."""
    uses, getter_calls = [], []
    allowed_getter_calls = {
        ('src/embed.h', 'Perl_get_opargs(aTHX)'),
        ('src/proto.h', 'Perl_get_opargs(pTHX);'),
        ('src/util.c', 'Perl_get_opargs(pTHX)'),
    }
    paths = sorted(path for path in (source_root / 'src').rglob('*')
                   if path.is_file() and path.suffix in {'.c', '.h', '.xs', '.xsi'})
    for path in paths:
        relative = path.relative_to(source_root).as_posix()
        clean = without_comments(path.read_text(errors='replace'))
        for line_number, line in enumerate(clean.splitlines(), 1):
            if 'PL_opargs' in line:
                stripped = line.strip()
                allowed = (stripped in {'EXT U32 PL_opargs[];',
                                        'EXT U32 PL_opargs[] = {'} or
                           stripped == 'return PL_opargs;' or 'PL_opargs[' in stripped)
                if not allowed or re.search(r'\bPL_opargs\s*\[[^\]]+\]\s*(?:\+\+|--|[+*/%&|^]?=)', line):
                    raise ValueError(f'unsupported PL_opargs use at {relative}:{line_number}: {stripped}')
                uses.append({'path': str(path), 'relative_path': relative,
                             'line': line_number, 'text': stripped,
                             'kind': ('definition' if 'EXT U32 PL_opargs' in stripped else
                                      'getter_return' if stripped == 'return PL_opargs;' else 'read')})
            if line.lstrip().startswith('#define get_opargs()'):
                getter_calls.append({'path': str(path), 'relative_path': relative,
                                     'line': line_number, 'text': line.strip(),
                                     'kind': 'convenience_macro'})
                continue
            for match in re.finditer(r'\b(?:Perl_)?get_opargs\s*\(', line):
                fragment = line[match.start():].strip()
                if (relative, fragment) not in allowed_getter_calls:
                    raise ValueError(f'getter call at {relative}:{line_number}: {stripped}')
                getter_calls.append({'path': str(path), 'relative_path': relative,
                                     'line': line_number, 'text': fragment,
                                     'kind': 'definition_or_prototype'})
    if not uses or {row['kind'] for row in uses} != {'definition', 'getter_return', 'read'}:
        raise ValueError('source reference inventory is incomplete')
    if not getter_calls:
        raise ValueError('getter definition/prototype inventory is incomplete')
    return {'all_pl_opargs_uses_read_only': True, 'pl_opargs_uses': uses,
            'getter_definition_and_prototypes': getter_calls, 'getter_callers': []}


def selector_closure(values):
    selectors = set()
    for value in values:
        shifted = value >> 13
        while shifted:
            selectors.add(shifted & 7)
            shifted >>= 4
    result = sorted(selectors)
    if result != list(range(1, 8)):
        raise ValueError('PL_opargs initializers do not close to selectors 1..7')
    return result


def source_evidence(source_root):
    header = source_root / 'src/opcode.h'
    text = header.read_text()
    found = re.search(r'^EXT U32 PL_opargs\[\] = \{\s*\n(.*?)^\};', text, re.M | re.S)
    if found is None:
        raise ValueError('source initializer declaration is missing or changed')
    body = found.group(1)
    if '#' in body:
        raise ValueError('initializer contains a conditional directive requiring preprocessing')
    uncommented = re.sub(r'/\*.*?\*/', '', body, flags=re.S)
    literals = [entry.strip() for entry in uncommented.split(',') if entry.strip()]
    if len(literals) != 352 or any(not re.fullmatch(r'0x[0-9a-fA-F]+', entry) for entry in literals):
        raise ValueError('expected exactly 352 unconditional hexadecimal U32 literals')
    values = [int(entry, 16) for entry in literals]
    encoded = struct.pack('<352I', *values)
    selectors = selector_closure(values)
    start_line = text[:found.start()].count('\n') + 1
    sources = []
    for relative, start, end in [('src/opcode.h', start_line - 3, start_line + 355),
                                  ('src/config.h', 1, 5), ('src/spec_config.h', 887, 897),
                                  ('src/spec_config.h', 3506, 3511), ('src/util.c', 3329, 3334),
                                  ('src/proto.h', 145, 150), ('src/embed.h', 139, 145)]:
        path = source_root / relative
        sources.append({'path': str(path), 'sha256': sha256(path.read_bytes()),
                        'first_line': start, 'last_line': end,
                        'excerpt': '\n'.join(path.read_text().splitlines()[start - 1:end])})
    references = source_references(source_root)
    return values, encoded, {'source_root': str(source_root),
            'source_version': (source_root / 'version.txt').read_text().strip(),
            'initializer_count': len(values), 'initializer_values': values,
            'initializer_little_endian_sha256': sha256(encoded), 'sources': sources,
            'initializer_selector_values': selectors,
            'shift_loop': {'initial_shift': 13, 'state_shift': 4, 'selector_mask': 7,
                           'state_condition': 'while shifted value is nonzero'},
            'preprocessor_findings': [
                'PL_opargs has only a DOINIT declaration/definition branch; the 352 literal values contain no conditional directives or macro expressions.',
                'The supplied config.h requires SPEC_CPU and includes spec_config.h.',
                'Under SPEC_CPU, spec_config.h explicitly undefines USE_DYNAMIC_LOADING; its later configuration entry is commented out.',
                'Perl_get_opargs returns U32*, not const U32*. Its source return expression is PL_opargs.',
                'The get_opargs convenience macro maps to Perl_get_opargs under PERL_CORE; the direct Perl_get_opargs prototype remains visible.',
                'The full original compiler command lines are not embedded in these ELF files; binary visibility, dependency and getter checks independently corroborate the relevant linked behavior.'
            ], 'reference_audit': references}


def binary_evidence(binary, expected_hash, source_values, encoded):
    raw = binary.read_bytes()
    if sha256(raw) != expected_hash:
        raise ValueError('binary hash mismatch')
    with binary.open('rb') as stream:
        elf = ELFFile(stream)
        symbols = {symbol.name: symbol for symbol in elf.get_section_by_name('.symtab').iter_symbols()}
        table, getter = symbols['PL_opargs'], symbols['Perl_get_opargs']
        start, size = int(table['st_value']), int(table['st_size'])
        if size != len(encoded):
            raise ValueError('binary initializer size differs from the complete source initializer')

        def read(address, length):
            for segment in elf.iter_segments():
                if (segment['p_type'] == 'PT_LOAD' and segment['p_vaddr'] <= address
                        and address + length <= segment['p_vaddr'] + segment['p_filesz']):
                    offset = segment['p_offset'] + address - segment['p_vaddr']
                    return raw[offset:offset + length]
            raise ValueError('audit read is not file-backed')

        data = read(start, size)
        binary_values = struct.unpack('<352I', data)
        mismatches = [{'index': index, 'source': source, 'binary': actual}
                      for index, (source, actual) in enumerate(zip(source_values, binary_values))
                      if source != actual]
        if mismatches:
            raise ValueError('source initializer does not match this binary: ' + repr(mismatches[:4]))
        dynsym = elf.get_section_by_name('.dynsym')
        dynamic_symbols = list(dynsym.iter_symbols()) if dynsym is not None else []
        queried = ('PL_opargs', 'Perl_get_opargs', 'Perl_ck_fun')
        visibility = {name: [{'value': int(symbol['st_value']), 'section': symbol['st_shndx'],
                              'binding': symbol['st_info']['bind'], 'visibility': symbol['st_other']['visibility']}
                             for symbol in dynamic_symbols if symbol.name == name] for name in queried}
        loader_functions = [symbol.name for symbol in dynamic_symbols
                            if symbol.name in ('dlopen', 'dlsym', 'dlclose', 'dladdr', 'dlmopen')]
        needed = [tag.needed for tag in elf.get_section_by_name('.dynamic').iter_tags()
                  if tag.entry.d_tag == 'DT_NEEDED']
        relocations = []
        for section in elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            linked = elf.get_section(section['sh_link'])
            for relocation in section.iter_relocations():
                name = linked.get_symbol(relocation['r_info_sym']).name if relocation['r_info_sym'] else None
                target = int(relocation['r_offset'])
                if start - 7 <= target < start + size or name in queried:
                    relocations.append({'section': section.name, 'offset': target, 'symbol': name,
                                        'type': int(relocation['r_info_type'])})
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        table_references, getter_references = [], []
        function_count = instruction_count = 0
        undecoded_functions = []
        for symbol in symbols.values():
            function_start, function_size = int(symbol['st_value']), int(symbol['st_size'])
            if symbol['st_info']['type'] != 'STT_FUNC' or function_size <= 0:
                continue
            function_bytes = read(function_start, function_size)
            function_count += 1
            function_instructions = list(md.disasm(function_bytes, function_start))
            instruction_count += len(function_instructions)
            decoded_size = sum(instruction.size for instruction in function_instructions)
            if decoded_size != function_size:
                undecoded_functions.append({'name': symbol.name, 'address': function_start,
                                            'size': function_size, 'decoded_size': decoded_size})
            for instruction in function_instructions:
                for operand in instruction.operands:
                    reference = None
                    if operand.type == X.X86_OP_MEM:
                        if operand.mem.disp == start:
                            reference = 'PL_opargs'
                        elif (operand.mem.base == X.X86_REG_RIP and
                              instruction.address + instruction.size + operand.mem.disp == start):
                            reference = 'PL_opargs'
                        elif operand.mem.disp == int(getter['st_value']):
                            reference = 'Perl_get_opargs'
                    elif operand.type == X.X86_OP_IMM and operand.imm == int(getter['st_value']):
                        reference = 'Perl_get_opargs'
                    record = {'function': symbol.name, 'function_address': function_start,
                              'address': instruction.address, 'bytes': instruction.bytes.hex(),
                              'instruction': f'{instruction.mnemonic} {instruction.op_str}'}
                    if reference == 'PL_opargs':
                        record['access'] = operand.access
                        table_references.append(record)
                    elif reference == 'Perl_get_opargs':
                        getter_references.append(record)
        stored_pointer_references = []
        for candidate_section in elf.iter_sections():
            if (not candidate_section['sh_flags'] & 2 or candidate_section['sh_flags'] & 4 or
                    not candidate_section['sh_size']):
                continue
            section_bytes = candidate_section.data()
            for name, address in (('PL_opargs', start),
                                  ('Perl_get_opargs', int(getter['st_value']))):
                needle = struct.pack('<Q', address)
                offset = section_bytes.find(needle)
                while offset >= 0:
                    stored_pointer_references.append({
                        'section': candidate_section.name,
                        'offset': int(candidate_section['sh_addr']) + offset,
                        'symbol': name,
                    })
                    offset = section_bytes.find(needle, offset + 1)
        table_writes = [row for row in table_references if row['access'] & 2]
        if undecoded_functions:
            raise ValueError('function-symbol disassembly has undecoded bytes: ' +
                             repr(undecoded_functions[:3]))
        if table_writes:
            raise ValueError('linked executable contains writes through PL_opargs: ' +
                             repr(table_writes[:3]))
        if getter_references or stored_pointer_references:
            raise ValueError('linked executable exposes Perl_get_opargs')
        if any(visibility.values()) or loader_functions or relocations:
            raise ValueError('linked executable could import or export a table alias')
        getter_start, getter_size = int(getter['st_value']), int(getter['st_size'])
        getter_bytes = read(getter_start, getter_size)
        decoded = list(md.disasm(getter_bytes, getter_start))
        if (len(decoded) != 2 or sum(ins.size for ins in decoded) != getter_size
                or decoded[0].mnemonic != 'mov' or len(decoded[0].operands) != 2
                or decoded[0].operands[0].type != X.X86_OP_REG
                or decoded[0].reg_name(decoded[0].operands[0].reg) not in ('eax', 'rax')
                or decoded[0].operands[1].type != X.X86_OP_IMM
                or decoded[0].operands[1].imm != start
                or decoded[1].mnemonic != 'ret' or decoded[1].operands):
            raise ValueError('emitted getter does not match the source return of PL_opargs')
        instructions = [{'address': ins.address, 'bytes': ins.bytes.hex(), 'mnemonic': ins.mnemonic,
                         'operands': ins.op_str} for ins in decoded]
        section = elf.get_section(table['st_shndx'])
        return {'binary': str(binary), 'binary_sha256': expected_hash,
                'elf_type': elf['e_type'], 'elf_machine': elf['e_machine'],
                'table': {'address': start, 'size': size, 'entries': len(binary_values),
                          'section': section.name, 'section_writable': bool(section['sh_flags'] & 1),
                          'source_matches_all_entries': True, 'bytes_sha256': sha256(data),
                          'source_mismatches': mismatches},
                'getter': {'address': getter_start, 'size': getter_size,
                           'returns_table_address': True, 'instructions': instructions},
                'dynamic_visibility': visibility, 'dynamic_loader_function_symbols': loader_functions,
                'needed_libraries': needed, 'relevant_loader_relocations': relocations,
                'source_reachability': {
                    'elf_type_is_fixed_executable': elf['e_type'] == 'ET_EXEC',
                    'dynamic_loading_disabled_by_SPEC_source': True,
                    'dynamic_loader_imports_absent': not loader_functions,
                    'queried_symbols_not_dynamically_exported': not any(visibility.values()),
                    'relevant_dynamic_relocations_absent': not relocations,
                    'getter_references_absent': not getter_references,
                    'stored_table_or_getter_pointers_absent': not stored_pointer_references,
                    'all_observed_table_accesses_are_reads': not table_writes and bool(table_references),
                },
                'code_scan': {
                    'scope': 'every sized STT_FUNC symbol in the non-stripped executable',
                    'function_symbols': function_count, 'decoded_instructions': instruction_count,
                    'undecoded_functions': undecoded_functions,
                    'pl_opargs_references': table_references,
                    'pl_opargs_write_references': table_writes,
                    'getter_references': getter_references,
                    'stored_table_or_getter_pointers': stored_pointer_references,
                },
                'compile_command_line_section_present': elf.get_section_by_name('.GCC.command.line') is not None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=Path('/mnt/nvme1/CPU2006_source/400.perlbench'))
    parser.add_argument('--input-report', type=Path,
                        default=Path('/mnt/nvme1/sba/reports/x86_sok_perl_data_invariants.json'))
    parser.add_argument('--output', type=Path,
                        default=Path('/mnt/nvme1/sba/reports/x86_sok_perl_source_initializers.json'))
    args = parser.parse_args()
    values, encoded, source = source_evidence(args.source_root)
    prior = json.loads(args.input_report.read_text())
    binaries = [binary_evidence(Path(row['binary']), row['binary_sha256'], values, encoded)
                for row in prior['binaries']]
    result = {'schema_version': 2, 'verifier': str(Path(__file__).resolve()),
              'verifier_sha256': sha256(Path(__file__).read_bytes()), 'source': source, 'binaries': binaries,
              'ground_truth_status': 'source_validated', 'automatic_binary_status': 'unresolved',
              'source_contract': [
                  'GT covers defined C executions of CPU2006 400.perlbench version 109 under correct compilation.',
                  'An out-of-bounds PL_opargs access is undefined C behavior and is excluded from defined executions.',
                  'The closed linked program cannot mutate PL_opargs in those executions: all source uses are reads, the getter has no caller, dynamic loading is disabled, and the original executable has no write, exporter, import, getter reference or pointer escape.',
              ],
              'scope': 'The 352 source initializers, source access inventory, and linked-build mutation surface.',
              'result': 'All 352 source initializers match all four originals. The audited shift loop therefore yields selectors 1..7 under the defined-C contract.'}
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'source_entries': len(values), 'binary_matches': len(binaries),
                      'sha256': sha256(encoded), 'output': str(args.output)}))


if __name__ == '__main__':
    main()
