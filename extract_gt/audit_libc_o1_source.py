#!/usr/bin/env python3
"""Validate the two original libc O1 dispatches under an explicit source contract.

This case-specific audit is separate from automatic binary inference. It binds
the glibc-2.27 JUMP macro and all six source arrays to ELF bytes and DWARF labels,
then applies correct compilation and defined source execution. The remaining
binary-only obligation (fallback spills surviving unknown calls) stays open.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.request import urlopen

from elftools.dwarf.dwarf_expr import DWARFExprParser
from elftools.elf.elffile import ELFFile


BINARY_SHA256 = '2fd22299b0f76a4348e7810a667266711e929a04076ca7598b8c341c919a02b7'
SOURCE_SHA256 = '40b8f01eabef3546a58749bfb1615948fc93fc3375db3967d9ce4c8fbbb46b3f'
SOURCE_URL = 'https://raw.githubusercontent.com/bminor/glibc/glibc-2.27/stdio-common/vfprintf.c'
TABLE_NAMES = ('step0_jumps', 'step1_jumps', 'step2_jumps',
               'step3a_jumps', 'step3b_jumps', 'step4_jumps')
FUNCTIONS = {0x5024d: '_IO_vfprintf_internal', 0x5b5d7: '_IO_vfwprintf'}
SOURCE_CONTRACT = (
    'The original hash-matched binary correctly implements the matching '
    'glibc-2.27 source, and executions obey the source object and control-flow '
    'semantics (defined C execution, including glibc GNU C extensions). '
    'In particular calls cannot corrupt unrelated live local objects. '
    'This contract is an explicit source-validation assumption, not a '
    'memory-effect fact established by the automatic binary analyzer.')


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def compact(text):
    return re.sub(r'\s+', '', text)


def descendants(die):
    for child in die.iter_children():
        yield child
        yield from descendants(child)


def value(die, name, default=None):
    attribute = die.attributes.get(name)
    return attribute.value if attribute else default


def source_line(text, pattern):
    match = re.search(pattern, text, re.M)
    require(match is not None, 'missing source pattern: ' + pattern)
    return text.count('\n', 0, match.start()) + 1


def parse_source(text):
    clean = re.sub(r'/\*.*?\*/', '', text, flags=re.S).replace('\\\n', '')
    shared = clean.split('#ifdef SHARED', 1)[1].split('#else', 1)[0]
    required = (
        '# define JUMP_TABLE_TYPE const int',
        '# define JUMP_TABLE_BASE_LABEL do_form_unknown',
        '# define REF(Name) &&do_##Name - &&JUMP_TABLE_BASE_LABEL',
        'offset = NOT_IN_JUMP_RANGE (spec) ? REF (form_unknown) : table[CHAR_CLASS (spec)];',
        'ptr = &&JUMP_TABLE_BASE_LABEL + offset;',
        'goto *ptr;',
    )
    for statement in required:
        require(compact(statement) in compact(shared), 'unexpected SHARED macro: ' + statement)
    for statement in (
        "#define NOT_IN_JUMP_RANGE(Ch) ((Ch) < L_(' ') || (Ch) > L_('z'))",
        "#define CHAR_CLASS(Ch) (jump_table[(INT_T) (Ch) - L_(' ')])",
    ):
        require(compact(statement) in compact(clean), 'unexpected selector guard')
    table_matches = re.findall(
        r'static JUMP_TABLE_TYPE (step\w+_jumps)\[30\]\s*=\s*\{(.*?)\}', clean, re.S)
    require(len(table_matches) == 6, 'expected exactly six source stage arrays')
    tables = {}
    for name, body in table_matches:
        labels = re.findall(r'REF\s*\(\s*(\w+)\s*\)', body)
        require(len(labels) == 30, 'source stage array does not have 30 labels')
        require(not re.sub(r'REF\s*\(\s*\w+\s*\)|[\s,]', '', body),
                'unrecognized source initializer')
        tables[name] = labels
    require(set(tables) == set(TABLE_NAMES), 'unexpected source stage names')
    table_region = clean[clean.index('#define STEP0_3_TABLE'):clean.index('#define process_arg')]
    require(not re.search(r'^\s*#\s*(?:if|else|elif)', table_region, re.M),
            'source tables have unhandled compilation conditionals')
    mapping_match = re.search(r'static const uint8_t jump_table\[\]\s*=\s*\{(.*?)\}', clean, re.S)
    require(mapping_match is not None, 'missing source character map')
    mapping = bytes(int(part.strip()) for part in mapping_match.group(1).split(',') if part.strip())
    require(len(mapping) == 91 and set(mapping) == set(range(30)), 'unexpected source character classes')
    labels = set().union(*(set(entries) for entries in tables.values()))
    require(len(labels) == 31, 'unexpected source label union')
    require(labels - set(tables['step0_jumps']) == {'mod_halfhalf'}, 'unexpected extra stage label')
    require(tables['step3a_jumps'][mapping[ord('h') - 0x20]] == 'mod_halfhalf',
            'missing second-h source witness')
    require(compact('LABEL (mod_half): is_short = 1; JUMP (*++f, step3a_jumps);') in compact(clean),
            'unexpected first-h handler')
    return tables, mapping


def dwarf_bindings(elf, source):
    dwarf = elf.get_dwarf_info()
    result = {}
    declaration_line = source_line(source, r'^vfprintf \(FILE \*s,',)
    for cu in dwarf.iter_CUs():
        # Only the two formatter compilation units contain these exact entries.
        if cu.cu_offset not in (0x13c801, 0x172dd9):
            continue
        for function in cu.iter_DIEs():
            address = value(function, 'DW_AT_low_pc')
            if function.tag != 'DW_TAG_subprogram' or address not in FUNCTIONS:
                continue
            name = value(function, 'DW_AT_name').decode()
            require(name == FUNCTIONS[address], 'unexpected DWARF formatter name')
            require(value(function, 'DW_AT_decl_line') == declaration_line,
                    'source function line differs from DWARF')
            files = dwarf.line_program_for_CU(cu).header['file_entry']
            filename = files[value(function, 'DW_AT_decl_file') - 1].name.decode()
            require(filename == 'vfprintf.c', 'unexpected DWARF declaration file')
            labels, variables = {}, {}
            parser = DWARFExprParser(dwarf.structs)
            for item in descendants(function):
                item_name = value(item, 'DW_AT_name', b'').decode()
                if item.tag == 'DW_TAG_label' and value(item, 'DW_AT_low_pc') is not None:
                    require(item_name not in labels, 'duplicate local DWARF label')
                    labels[item_name] = dict(address=value(item, 'DW_AT_low_pc'), die_offset=item.offset,
                                             source_line=value(item, 'DW_AT_decl_line'))
                elif item.tag == 'DW_TAG_variable' and item_name in TABLE_NAMES:
                    expression = parser.parse_expr(value(item, 'DW_AT_location'))
                    require(len(expression) == 1 and expression[0].op_name == 'DW_OP_addr',
                            'stage table does not have a constant DWARF address')
                    require(item_name not in variables, 'duplicate source stage table')
                    variables[item_name] = dict(address=expression[0].args[0], die_offset=item.offset,
                                                source_line=value(item, 'DW_AT_decl_line'))
            require(set(variables) == set(TABLE_NAMES), 'DWARF does not bind all six tables')
            top = cu.get_top_DIE()
            result[address] = dict(
                function=name, function_die_offset=function.offset, cu_offset=cu.cu_offset,
                compilation_unit=value(top, 'DW_AT_name').decode(),
                compilation_directory=value(top, 'DW_AT_comp_dir').decode(),
                compiler=value(top, 'DW_AT_producer').decode(), declaration_file=filename,
                declaration_line=declaration_line, labels=labels, variables=variables)
    require(set(result) == set(FUNCTIONS), 'missing original formatter DWARF')
    return result


def audit(binary, source_path, verify_upstream=False):
    binary_hash = sha256(binary.read_bytes())
    source_bytes = source_path.read_bytes()
    require(binary_hash == BINARY_SHA256, 'audit requires the original hash-matched GCC O1 libc')
    require(sha256(source_bytes) == SOURCE_SHA256, 'source is not the audited upstream glibc-2.27 file')
    if verify_upstream:
        with urlopen(SOURCE_URL, timeout=30) as response:
            require(response.read() == source_bytes, 'local source differs from upstream release tag')
    source = source_bytes.decode()
    source_tables, source_map = parse_source(source)
    verifier = Path(__file__).with_name('audit_libc_shared_suffix.py')
    with tempfile.TemporaryDirectory(prefix='libc-o1-source-audit-') as directory:
        binary_audit_path = Path(directory) / 'binary-audit.json'
        subprocess.run([sys.executable, str(verifier), '--binary', str(binary),
                        '--output', str(binary_audit_path)], check=True, capture_output=True, text=True)
        binary_audit = json.loads(binary_audit_path.read_text())
    with binary.open('rb') as stream:
        bindings = dwarf_bindings(ELFFile(stream), source)
    sites = []
    for site in binary_audit['sites']:
        binding = bindings[site['function']]
        labels = binding['labels']
        require(labels['do_form_unknown']['address'] == site['code_base'], 'incorrect label-relative base')
        require(bytes.fromhex(site['character_map']['bytes']) == source_map,
                'binary character map differs from source')
        tables, targets = [], set()
        for name, emitted in zip(TABLE_NAMES, site['tables']):
            require(binding['variables'][name]['address'] == emitted['address'],
                    'DWARF source table has a different binary address')
            entries = []
            for entry, label in zip(emitted['entries'], source_tables[name]):
                dwarf_label = labels.get('do_' + label)
                require(dwarf_label is not None, 'missing address-bearing DWARF source label')
                require(entry['target'] == dwarf_label['address'],
                        'binary offset does not target the source REF label')
                entries.append(dict(entry, source_label=label, dwarf_label=dwarf_label))
                targets.add(entry['target'])
            tables.append(dict(name=name, table_address=emitted['address'], entry_size=4,
                               entry_encoding='signed_relative', relative_base=site['code_base'],
                               selector_values=list(range(30)), bytes_sha256=emitted['bytes_sha256'],
                               source_declaration_line=source_line(source, 'static JUMP_TABLE_TYPE ' + name),
                               dwarf_variable=binding['variables'][name], entries=entries,
                               references=emitted['references']))
        require(len(targets) == 31 and targets == set(site['table_target_union']), 'target-union mismatch')
        require(site['code_base'] in targets, 'fallback should already belong to the stage union')
        sites.append(dict(
            site=site['site'], function=site['function'], function_name=binding['function'],
            ground_truth_status='source_validated', automatic_binary_status='unresolved',
            source_contract=SOURCE_CONTRACT, target_count=len(targets), targets=sorted(targets),
            source_to_binary_binding={key: val for key, val in binding.items() if key not in ('labels', 'variables')},
            character_map=dict(site['character_map'], source_bytes_match=True), tables=tables,
            verified_source_entries=sum(len(table['entries']) for table in tables),
            fallback=dict(source_label='form_unknown', offset=0, target=site['code_base'],
                          algebra='REF(form_unknown) = &&do_form_unknown - &&do_form_unknown = 0',
                          dwarf_label=labels['do_form_unknown'], member_of_table_union=True,
                          proof_kind='source_semantics_under_explicit_contract'),
            hh_witness=dict(site['witness'], source_handler_line=source_line(source, r'LABEL \(mod_half\):'),
                            dwarf_extra_label=labels['do_mod_halfhalf']),
            binary_only_scope=site['scope'],
            binary_only_unresolved_obligation='Prove fallback spill preservation across unknown calls and escaped frame objects.',
            conclusion='All 180 signed table offsets match their named source labels through DWARF. '
                       'The six source stages have 31 distinct labels. Under the explicit source contract, '
                       'JUMP fallback is the same form_unknown label, so the whole shared dispatch has 31 '
                       'targets. Binary-only automatic inference remains unresolved.'))
    return dict(
        schema_version=1, audit_kind='source_semantics_with_elf_and_dwarf_binding',
        ground_truth_status='source_validated', automatic_binary_status='unresolved',
        binary=str(binary.resolve()), binary_sha256=binary_hash,
        source=dict(path=str(source_path.resolve()), sha256=sha256(source_bytes), release='glibc-2.27',
                    upstream_url=SOURCE_URL, upstream_bytes_verified_this_run=verify_upstream,
                    shared_macro_line=source_line(source, '#ifdef SHARED'),
                    character_map_line=source_line(source, r'static const uint8_t jump_table'),
                    configuration='SHARED: const int label differences; same six stage arrays for narrow and wide'),
        source_contract=SOURCE_CONTRACT,
        validation_scope=dict(all_source_table_entries_bound_to_dwarf_labels=True,
                              character_map_bytes_match=True, full_reproducible_build_performed=False,
                              source_build_identity='DWARF source file/function lines and labels, plus exact table/map binding; correct compilation is assumed',
                              automatic_binary_proof=False),
        verifier=str(Path(__file__).resolve()), audit_script_sha256=sha256(Path(__file__).read_bytes()),
        independent_binary_verifier=str(verifier.resolve()),
        independent_binary_verifier_sha256=sha256(verifier.read_bytes()), sites=sites)


def certificate(report, output):
    """Convert verified stage tables into the generator's source certificate."""
    sites = []
    for site in report['sites']:
        sites.append({
            'site': hex(site['site']),
            'switch_only': True,
            'evidence_kind': 'source_invariant',
            'source_contract': [report['source_contract'],
                                'The GT includes defined matching-source executions only; '
                                'the JUMP fallback is the same form_unknown label at offset zero.'],
            'tables': [{
                'name': table['name'],
                'table_address': hex(table['table_address']),
                'entry_size': table['entry_size'],
                'entry_encoding': table['entry_encoding'],
                'relative_base': hex(table['relative_base']),
                'selector_values': table['selector_values'],
                'bytes_sha256': table['bytes_sha256'],
            } for table in site['tables']],
            'evidence': (f'{output}: glibc-2.27 source, DWARF label binding and '
                         'all six stage tables; automatic binary analysis is unresolved'),
        })
    return {
        'schema_version': 2,
        'binary_sha256': report['binary_sha256'],
        'sites': sites,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--certificate', type=Path,
                        help='write a generator certificate derived from the audit')
    parser.add_argument('--verify-upstream', action='store_true', help='also compare source bytes with the upstream release tag')
    args = parser.parse_args()
    report = audit(args.binary, args.source, args.verify_upstream)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    if args.certificate:
        args.certificate.write_text(json.dumps(certificate(report, args.output.resolve()),
                                              indent=2) + '\n')
    print(args.output)
    for site in report['sites']:
        print(hex(site['site']), site['ground_truth_status'], site['target_count'],
              'automatic_binary=' + site['automatic_binary_status'])


if __name__ == '__main__':
    main()
