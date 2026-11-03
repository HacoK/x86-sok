#!/usr/bin/env python3
"""Validate source-certified GT outputs without treating them as binary proofs."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

from elftools.elf.elffile import ELFFile

os.environ.setdefault('PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION', 'python')
SOURCE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SOURCE_DIR.parent / 'protobuf_def'))
import blocks_pb2


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text())


def integer(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def read_module(path):
    module = blocks_pb2.module()
    module.ParseFromString(Path(path).read_bytes())
    return module


def generated_rows(module):
    rows = {}
    for function in module.fuc:
        for block in function.bb:
            if block.instructions:
                rows.setdefault(block.instructions[-1].va, {'types': set(), 'targets': set()})
                row = rows[block.instructions[-1].va]
                row['types'].add(block.type)
                row['targets'].update(child.va for child in block.child)
    return rows


def read_elf(binary, table, selector, entry_size, encoding, base):
    with Path(binary).open('rb') as source:
        elf = ELFFile(source)
        address = table + selector * entry_size
        for segment in elf.iter_segments():
            if segment['p_type'] != 'PT_LOAD':
                continue
            offset = address - segment['p_vaddr']
            if 0 <= offset and offset + entry_size <= segment['p_filesz']:
                source.seek(segment['p_offset'] + offset)
                value = int.from_bytes(source.read(entry_size), 'little',
                                       signed=encoding == 'signed_relative')
                return (base + value) & ((1 << elf.elfclass) - 1)
    raise ValueError(f'cannot read certificate table 0x{table:x}+{selector}')


def certified_targets(certificate_path, binary):
    certificate = read_json(certificate_path)
    if certificate.get('schema_version') != 2 or certificate.get('binary_sha256') != sha256_file(binary):
        raise ValueError(f'invalid or stale certificate: {certificate_path}')
    result = {}
    for row in certificate['sites']:
        contract = row.get('source_contract')
        if row.get('evidence_kind') != 'source_invariant' or not isinstance(contract, list) or not contract:
            raise ValueError(f'certificate lacks a source contract: {certificate_path}')
        targets = set()
        selectors = set()
        for table in row['tables']:
            base = integer(table.get('relative_base', 0))
            for selector in table['selector_values']:
                selectors.add(selector)
                targets.add(read_elf(binary, integer(table['table_address']), selector,
                                     integer(table['entry_size']), table['entry_encoding'], base))
        result[integer(row['site'])] = {'targets': sorted(targets), 'source_contract': contract,
                                        'selector_values': sorted(selectors)}
    return result


def perl_selector_closure(source_report):
    values = read_json(source_report)['source']['initializer_values']
    selectors = set()
    for value in values:
        shifted = value >> 13
        while shifted:
            selectors.add(shifted & 7)
            shifted >>= 4
    if selectors != set(range(1, 8)):
        raise ValueError('Perl source initializers do not close to selectors 1..7')
    return sorted(selectors)


def validate_case(binary, output, certificate, expected_targets=None, expected_selectors=None,
                  required_contracts=None):
    sidecar_path = Path(str(output) + '.jumptables.json')
    sidecar = read_json(sidecar_path)
    if sidecar.get('binary_sha256') != sha256_file(binary):
        raise ValueError(f'stale binary hash in {sidecar_path}')
    if sidecar.get('protobuf_sha256') != sha256_file(output):
        raise ValueError(f'stale protobuf hash in {sidecar_path}')
    certificate_hash = sha256_file(certificate)
    if sidecar.get('certificates_sha256') != certificate_hash:
        raise ValueError(f'certificate hash differs from {sidecar_path}')
    decoded = certified_targets(certificate, binary)
    module_rows = generated_rows(read_module(output))
    cases = []
    for site, expected in decoded.items():
        evidence_rows = [row for row in sidecar['sites'] if row['site'] == site]
        if len(evidence_rows) != 1:
            raise ValueError(f'expected one sidecar row for 0x{site:x}')
        evidence = evidence_rows[0]
        targets = expected_targets[site] if expected_targets else expected['targets']
        if expected_selectors is not None and expected['selector_values'] != expected_selectors:
            raise ValueError(f'certificate selectors differ at 0x{site:x}')
        if required_contracts is not None and not set(required_contracts) <= set(expected['source_contract']):
            raise ValueError(f'certificate source contract differs at 0x{site:x}')
        generated = module_rows.get(site)
        if generated is None or 7 not in generated['types'] or generated['targets'] != set(targets):
            raise ValueError(f'generated targets differ at 0x{site:x}')
        if evidence.get('status') != 'resolved' or set(evidence.get('targets', [])) != set(targets):
            raise ValueError(f'sidecar source result differs at 0x{site:x}')
        if evidence.get('evidence', {}).get('scope') != 'audited_source_invariant':
            raise ValueError(f'sidecar evidence scope differs at 0x{site:x}')
        if evidence.get('evidence', {}).get('validation_status') != 'source_validated':
            raise ValueError(f'sidecar source validation missing at 0x{site:x}')
        if evidence.get('binary_analysis', {}).get('status') != 'unresolved':
            raise ValueError(f'automatic status was lost at 0x{site:x}')
        if expected_targets is None and set(targets) != set(expected['targets']):
            raise ValueError(f'repeated decode differs at 0x{site:x}')
        cases.append({
            'site': site, 'target_count': len(targets), 'targets': sorted(targets),
            'ground_truth_status': 'source_validated',
            'automatic_binary_status': 'unresolved',
            'binary_unresolved_reason': evidence['binary_analysis'].get('reason'),
            'source_contract': expected['source_contract'],
        })
    return {'binary': str(Path(binary).resolve()), 'binary_sha256': sha256_file(binary),
            'output': str(Path(output).resolve()), 'output_sha256': sha256_file(output),
            'sidecar': str(sidecar_path.resolve()), 'sidecar_sha256': sha256_file(sidecar_path),
            'certificate': str(Path(certificate).resolve()), 'certificate_sha256': certificate_hash,
            'cases': cases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--libc-report', type=Path,
                        default=Path('/mnt/nvme1/sba/reports/x86_sok_libc_o1_source_validation.json'))
    parser.add_argument('--perl-report', type=Path,
                        default=Path('/mnt/nvme1/sba/reports/x86_sok_perl_source_initializers.json'))
    parser.add_argument('--output', type=Path,
                        default=Path('/mnt/nvme1/sba/reports/x86_sok_source_certified_gt_validation.json'))
    parser.add_argument('--cpu2006-root', type=Path,
                        default=Path('/mnt/nvme1/sba/x86_dataset/linux/cpu2006'))
    parser.add_argument('--work-dir', type=Path, default=Path('/tmp'))
    args = parser.parse_args()
    libc_report = read_json(args.libc_report)
    if (libc_report.get('ground_truth_status') != 'source_validated' or
            libc_report.get('automatic_binary_status') != 'unresolved'):
        raise ValueError('libc source report has the wrong status split')
    libc_binary = Path(libc_report['binary'])
    expected_libc = {row['site']: set(row['targets']) for row in libc_report['sites']}
    libc = validate_case(libc_binary, args.work_dir / 'x86-sok-source-certified-libc-O1.pb',
                         SOURCE_DIR / 'certificates/libc-gcc_O1.json', expected_libc,
                         required_contracts=[libc_report['source_contract']])
    perl_report = read_json(args.perl_report)
    if (perl_report.get('ground_truth_status') != 'source_validated' or
            perl_report.get('automatic_binary_status') != 'unresolved'):
        raise ValueError('Perl source report has the wrong status split')
    selectors = perl_selector_closure(args.perl_report)
    if selectors != list(range(1, 8)):
        raise ValueError('unexpected Perl selector closure')
    perl_cases = []
    for build in ('O1', 'O2', 'O3', 'Of'):
        root = args.cpu2006_root / f'gcc_{build}'
        binary = root / f'perlbench_base.amd64-m64-gcc81-{build}'
        perl_cases.append(validate_case(binary,
                                       args.work_dir / f'x86-sok-source-certified-perl-{build}.pb',
                                       SOURCE_DIR / f'certificates/perlbench-gcc_{build}.json',
                                       expected_selectors=selectors,
                                       required_contracts=perl_report['source_contract']))
    result = {
        'schema_version': 1,
        'verifier': str(Path(__file__).resolve()),
        'verifier_sha256': sha256_file(Path(__file__)),
        'source_evidence': {
            'libc_report': str(args.libc_report.resolve()),
            'libc_report_sha256': sha256_file(args.libc_report),
            'perl_report': str(args.perl_report.resolve()),
            'perl_report_sha256': sha256_file(args.perl_report),
        },
        'libc': libc,
        'perl': {'source_initializer_selector_values': selectors, 'builds': perl_cases},
        'summary': {
            'source_validated_sites': len(libc['cases']) + sum(len(row['cases']) for row in perl_cases),
            'automatic_binary_unresolved_sites': len(libc['cases']) +
                                                  sum(len(row['cases']) for row in perl_cases),
            'libc_targets_per_site': 31,
            'perl_targets_per_site': len(selectors),
        },
    }
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result['summary'], sort_keys=True))


if __name__ == '__main__':
    main()
