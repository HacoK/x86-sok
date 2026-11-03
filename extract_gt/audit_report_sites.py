#!/usr/bin/env python3
"""Reproduce report-site validation without conflating equality with proof.

Libc outputs come from full raw-metadata extraction. Other inputs contain the
complete reported functions plus other function entries as stubs. They are
refined without certificates. This checks every CSV row against its separately
audited protobuf; it does not claim a full-corpus re-extraction for the reduced
function fixtures. The JSON records exact sets, analysis status and artifact
hashes independently, including unresolved rows whose physical sets match.
"""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

os.environ.setdefault('PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION', 'python')
SOURCE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SOURCE_DIR.parent / 'protobuf_def'))
import blocks_pb2
from jump_table_gt import refine_jump_tables, sha256_file, write_outputs


def successor_hash(targets):
    """Match the published frozen/current CSV's sorted hexadecimal encoding."""
    payload = ','.join('0x%x' % value for value in sorted(set(targets)))
    return hashlib.sha256(payload.encode()).hexdigest()


def read_module(path):
    module = blocks_pb2.module()
    module.ParseFromString(Path(path).read_bytes())
    return module


def site_rows(module):
    result = {}
    for function in module.fuc:
        for block in function.bb:
            if not block.instructions:
                continue
            site = block.instructions[-1].va
            row = result.setdefault(site, {'types': set(), 'targets': set(), 'functions': set()})
            row['types'].add(block.type)
            row['functions'].add(function.va)
            if block.type == 7:
                row['targets'].update(child.va for child in block.child)
    return result


def binary_path(dataset_root, relative):
    parts = list(Path(relative).parts)
    parts = [part[:-6] if part.endswith('_strip') else part for part in parts]
    if parts[-1].endswith('.strip'):
        parts[-1] = parts[-1][:-6]
    return Path(dataset_root).joinpath(*parts)


def fixture_for(relative, args):
    binary = binary_path(args.dataset_root, relative)
    variant = Path(relative).parent.name.removesuffix('_strip').split('_')[-1]
    if relative.endswith('/libc-2.27.so.strip'):
        return {'binary': binary, 'output': Path(args.libc_template.format(variant=variant)),
                'input': None, 'kind': 'full_raw_metadata_extraction'}
    if relative.endswith('/libv8.so.strip') and variant in ('O3', 'Of'):
        source = Path(args.v8_raw_template.format(variant=variant))
        kind = 'raw_metadata_containing_functions_and_entry_stubs'
    else:
        source = Path(args.function_cache) / (relative.replace('/', '_') + '.pb')
        kind = 'shipped_containing_functions_and_entry_stubs'
    return {'binary': binary, 'input': source,
            'output': Path(args.work_dir) / (relative.replace('/', '_') + '.pb'), 'kind': kind}


def read_csv(path, expected_count):
    with Path(path).open(newline='') as source:
        rows = list(csv.DictReader(source))
    if expected_count is not None and len(rows) != expected_count:
        raise ValueError('expected %d report rows, found %d' % (expected_count, len(rows)))
    keys = [(row['binary'], int(row['site'], 0)) for row in rows]
    if len(set(keys)) != len(keys):
        raise ValueError('duplicate binary/site rows in report CSV')
    if len({row['id'] for row in rows}) != len(rows):
        raise ValueError('duplicate report IDs')
    return rows


def validate_sidecar(report, output, binary, allow_stale=False):
    if report.get('protobuf_sha256') != sha256_file(output):
        raise ValueError('sidecar/protobuf SHA-256 mismatch: %s' % output)
    if report.get('binary_sha256') != sha256_file(binary):
        raise ValueError('sidecar/binary SHA-256 mismatch: %s' % binary)
    sources = report.get('generator_sha256', {})
    if not {'jump_table_gt.py', 'jump_table_analysis.py'} <= sources.keys():
        raise ValueError('sidecar lacks generator source hashes: %s' % output)
    mismatches = {}
    for name, expected in sources.items():
        path = SOURCE_DIR.parent / name if name.startswith('ccr/') else SOURCE_DIR / name
        actual = sha256_file(path) if path.is_file() else None
        if actual != expected:
            mismatches[name] = {'artifact': expected, 'current': actual}
    if mismatches and not allow_stale:
        raise ValueError('stale generator sidecar for %s: %s' % (output, ', '.join(sorted(mismatches))))
    return mismatches


def certificates_used(report):
    if report.get('certificates_sha256'):
        return True
    for row in report.get('sites', []):
        if row.get('evidence', {}).get('scope', '').startswith('audited_'):
            return True
    return False


def summarize(rows):
    statuses = Counter(row['analysis_status'] for row in rows)
    return {'report_sites': len(rows), 'analysis_status_counts': dict(sorted(statuses.items())),
            'exact_target_sets': sum(row['exact_targets'] for row in rows),
            'mismatched_target_sets': sum(not row['exact_targets'] for row in rows),
            'automatic_resolved_exact': sum(row['automatic_resolved'] and row['exact_targets'] for row in rows),
            'automatic_resolved_mismatch': sum(row['automatic_resolved'] and not row['exact_targets'] for row in rows),
            'unresolved_or_unproved_exact': sum(not row['automatic_resolved'] and row['exact_targets'] for row in rows),
            'unresolved_or_unproved_mismatch': sum(not row['automatic_resolved'] and not row['exact_targets'] for row in rows),
            'rows_using_certificates': sum(row['certificates_used'] for row in rows),
            'absent_type7_rows': sum(not row['generated_jump_table'] for row in rows)}


def oracle_tables(path):
    return {site: row['targets'] for site, row in site_rows(read_module(path)).items() if 7 in row['types']}


def prepare(args, rows):
    grouped = defaultdict(list)
    for row in rows:
        grouped[row['binary']].append(row)
    plans = []
    for relative, group in sorted(grouped.items()):
        fixture = fixture_for(relative, args)
        paths = [fixture['binary']]
        if fixture['input'] is not None:
            paths.append(fixture['input'])
        else:
            paths.extend([fixture['output'], Path(str(fixture['output']) + '.jumptables.json')])
        paths.extend(Path(args.oracle_root) / row['ground_truth'] for row in group)
        missing = sorted({str(path) for path in paths if not path.is_file()})
        plans.append({'binary': relative, 'report_sites': len(group),
                      'fixture': {key: str(value) if isinstance(value, Path) else value
                                  for key, value in fixture.items()}, 'missing_inputs': missing})
    return plans


def audit(args):
    rows = read_csv(args.csv, args.expected_sites)
    plans = prepare(args, rows)
    if args.prepare_only:
        return {'prepared_report_sites': len(rows), 'binaries': plans,
                'missing_inputs': sum(len(plan['missing_inputs']) for plan in plans)}
    missing = [path for plan in plans for path in plan['missing_inputs']]
    if missing:
        raise ValueError('missing audit inputs: ' + ', '.join(missing))
    Path(args.work_dir).mkdir(parents=True, exist_ok=True)
    oracle_cache, fixtures, results = {}, [], []
    grouped = defaultdict(list)
    for row in rows:
        grouped[row['binary']].append(row)
    for relative, group in sorted(grouped.items()):
        fixture = fixture_for(relative, args)
        binary, output = fixture['binary'], fixture['output']
        sidecar = Path(str(output) + '.jumptables.json')
        input_hash = sha256_file(fixture['input']) if fixture['input'] else None
        if fixture['input'] is not None:
            reuse = args.reuse_generated and output.is_file() and sidecar.is_file()
            if reuse:
                report = json.loads(sidecar.read_text())
                reuse = report.get('audit_input_protobuf_sha256') == input_hash
                if reuse:
                    # A requested reuse never silently falls back to a stale proof.
                    validate_sidecar(report, output, binary, args.allow_stale_generator)
            if not reuse:
                module = read_module(fixture['input'])
                report = refine_jump_tables(binary, module, certificates=None)
                report['audit_input_protobuf_sha256'] = input_hash
                report['audit_input_protobuf'] = str(fixture['input'])
                report['audit_fixture_scope'] = fixture['kind']
                write_outputs(module, output, report)
        else:
            report = json.loads(sidecar.read_text())
        stale = validate_sidecar(report, output, binary, args.allow_stale_generator)
        assisted = certificates_used(report)
        generated = site_rows(read_module(output))
        evidence = {}
        for row in report.get('sites', []):
            if row['site'] in evidence:
                raise ValueError('duplicate sidecar site at 0x%x' % row['site'])
            evidence[row['site']] = row
        fixture_result = {'binary': relative, 'original_binary': str(binary),
                          'binary_sha256': sha256_file(binary), 'fixture_scope': fixture['kind'],
                          'input_protobuf': str(fixture['input']) if fixture['input'] else None,
                          'input_protobuf_sha256': input_hash, 'output_protobuf': str(output),
                          'output_protobuf_sha256': sha256_file(output), 'sidecar': str(sidecar),
                          'sidecar_sha256': sha256_file(sidecar), 'certificates_used': assisted,
                          'generator_sha256': report['generator_sha256'], 'stale_generator_sources': stale,
                          'metadata_sha256': report.get('metadata_sha256')}
        group_results = []
        for source in group:
            site = int(source['site'], 0)
            oracle_path = Path(args.oracle_root) / source['ground_truth']
            if oracle_path not in oracle_cache:
                oracle_cache[oracle_path] = (oracle_tables(oracle_path), sha256_file(oracle_path))
            expected_tables, oracle_hash = oracle_cache[oracle_path]
            if site not in expected_tables:
                raise ValueError('audited type7 site absent from oracle: %s %s' % (oracle_path, source['site']))
            expected = expected_tables[site]
            if (len(expected) != int(source['current_successor_count']) or
                    successor_hash(expected) != source['current_successor_sha256']):
                raise ValueError('oracle targets disagree with frozen/current CSV: ' + source['id'])
            actual = generated.get(site, {'types': set(), 'targets': set(), 'functions': set()})
            record = evidence.get(site, {})
            status = record.get('status', 'missing_record')
            present = 7 in actual['types']
            exact = present and actual['targets'] == expected
            if status == 'resolved' and (not present or set(record.get('targets', [])) != actual['targets']):
                raise ValueError('resolved sidecar targets disagree with protobuf: ' + source['id'])
            row = {'id': source['id'], 'binary': relative, 'site': source['site'],
                   'repair_kind': source['repair_kind'], 'generated_jump_table': present,
                   'generated_block_types': sorted(actual['types']),
                   'actual_targets': sorted(actual['targets']), 'audited_targets': sorted(expected),
                   'missing_targets': sorted(expected - actual['targets']),
                   'extra_targets': sorted(actual['targets'] - expected), 'exact_targets': exact,
                   'analysis_status': status, 'analysis_reason': record.get('reason'),
                   'analysis_action': record.get('action'),
                   'analysis_scope': record.get('evidence', {}).get('scope'),
                   'automatic_resolved': status == 'resolved' and not assisted and not stale,
                   'certificates_used': assisted, 'sidecar': str(sidecar),
                   'audited_protobuf': str(oracle_path), 'audited_protobuf_sha256': oracle_hash,
                   'audited_target_sha256': successor_hash(expected),
                   'generated_target_sha256': successor_hash(actual['targets'])}
            results.append(row)
            group_results.append(row)
        fixture_result['summary'] = summarize(group_results)
        if fixture['kind'] == 'full_raw_metadata_extraction':
            expected = oracle_cache[Path(args.oracle_root) / group[0]['ground_truth']][0]
            actual = {site: row['targets'] for site, row in generated.items() if 7 in row['types']}
            audited = {int(row['site'], 0) for row in group}
            changed = [site for site in actual.keys() & expected.keys() if actual[site] != expected[site]]
            fixture_result['full_libc_oracle_comparison'] = {
                'generated_type7_sites': len(actual), 'audited_oracle_type7_sites': len(expected),
                'missing_oracle_sites': [hex(site) for site in sorted(expected.keys() - actual.keys())],
                'additional_generated_sites': [hex(site) for site in sorted(actual.keys() - expected.keys())],
                'changed_shared_sites': [hex(site) for site in sorted(changed)],
                'changed_shared_sites_outside_report': [
                    {'site': hex(site), 'actual_targets': sorted(actual[site]),
                     'audited_targets': sorted(expected[site]),
                     'analysis_status': evidence.get(site, {}).get('status', 'missing_record'),
                     'analysis_reason': evidence.get(site, {}).get('reason')}
                    for site in sorted(set(changed) - audited)]}
        fixtures.append(fixture_result)
        print('%s: %s' % (relative, json.dumps(fixture_result['summary'], sort_keys=True)), flush=True)
    return {'schema_version': 1, 'csv': str(Path(args.csv)), 'csv_sha256': sha256_file(args.csv),
            'audit_script_sha256': sha256_file(__file__),
            'certificates_used': any(item['certificates_used'] for item in fixtures),
            'all_generator_sources_current': not any(item['stale_generator_sources'] for item in fixtures),
            'scope': __doc__.strip(), 'summary': summarize(results), 'fixtures': fixtures, 'sites': results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--csv', default='/mnt/nvme1/sba/reports/frozen_gt_repair_diff.csv')
    parser.add_argument('--dataset-root', default='/mnt/nvme1/sba/x86_dataset/linux')
    parser.add_argument('--oracle-root', default='/mnt/nvme1/sba')
    parser.add_argument('--function-cache', default='/tmp/x86-sok-report-function-cache')
    parser.add_argument('--libc-template', default='/tmp/x86-sok-current-raw-libc-{variant}.pb')
    parser.add_argument('--v8-raw-template', default='/tmp/x86-sok-v8-raw-{variant}.pb')
    parser.add_argument('--work-dir', default='/tmp/x86-sok-report-site-audit')
    parser.add_argument('--output', default='/mnt/nvme1/sba/reports/x86_sok_automatic_report_site_validation.json')
    parser.add_argument('--expected-sites', type=int, default=372)
    parser.add_argument('--prepare-only', action='store_true', help='inspect fixture paths without running the generator')
    parser.add_argument('--reuse-generated', action='store_true', help='reuse only inputs and sources verified by hashes')
    parser.add_argument('--allow-stale-generator', action='store_true', help='report stale artifacts as unproved, never automatic')
    args = parser.parse_args()
    try:
        report = audit(args)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    if args.prepare_only:
        print(json.dumps(report, indent=2))
        return
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w', dir=destination.parent, delete=False) as temporary:
        temporary.write(json.dumps(report, indent=2) + '\n')
    os.replace(temporary.name, destination)
    print(json.dumps(report['summary'], indent=2))
    print(destination)


if __name__ == '__main__':
    main()
