"""Apply site-level jump-table analysis and retain its provenance.

This module also accepts explicitly audited selector domains for invariants
that cannot be inferred from local machine code. Certificates are bound to the
entire input binary; targets are always decoded again from its table bytes.
"""

import argparse
import hashlib
import json
import os
import shutil
import tempfile


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _integer(value):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError("addresses and selectors must be integers or integer strings")
    return int(value, 0) if isinstance(value, str) else int(value)


def _site_blocks(module):
    sites = {}
    for function in module.fuc:
        for block in function.bb:
            if block.instructions:
                sites.setdefault(block.instructions[-1].va, []).append((function, block))
    return sites


def read_certificates(path, binary, module):
    """Validate an audited selector manifest and re-decode its successors.

    The manifest's evidence is a human assertion, not an automatically checked
    source proof. Requiring a binary hash and decoding live bytes prevents a
    stale address/target patch from silently becoming ground truth.
    """
    import capstone
    from capstone import x86_const as x86
    from elftools.elf.elffile import ELFFile

    with open(path) as source:
        manifest = json.load(source)
    if (not isinstance(manifest, dict) or
            type(manifest.get("schema_version")) is not int or manifest["schema_version"] not in (1, 2)):
        raise ValueError("unsupported jump-table certificate schema")
    if manifest.get("binary_sha256") != sha256_file(binary):
        raise ValueError("jump-table certificate binary SHA-256 mismatch")
    sites = _site_blocks(module)
    result = {}
    with open(binary, "rb") as source:
        elf = ELFFile(source)
        if elf.get_machine_arch() not in {"x86", "x64"}:
            raise ValueError("selector certificates require an x86 ELF binary")
        segments = [segment for segment in elf.iter_segments()
                    if segment["p_type"] == "PT_LOAD"]

        def read(address, size, table=False, instruction=False):
            for segment in segments:
                offset = address - segment["p_vaddr"]
                available = segment["p_filesz"] - offset
                if offset >= 0 and available > 0 and (size <= available or instruction):
                    if table and segment["p_flags"] & 2:
                        raise ValueError("certificate table is in writable memory")
                    if instruction and not segment["p_flags"] & 1:
                        raise ValueError("certificate instruction is outside executable memory")
                    size = min(size, available)
                    source.seek(segment["p_offset"] + offset)
                    data = source.read(size)
                    if len(data) != size:
                        raise ValueError("certificate reads truncated ELF data")
                    return data
            raise ValueError("certificate reads outside file-backed ELF segments")

        decoder = capstone.Cs(capstone.CS_ARCH_X86,
                              capstone.CS_MODE_64 if elf.elfclass == 64 else capstone.CS_MODE_32)
        decoder.detail = True
        certificates = manifest.get("sites", [])
        if not isinstance(certificates, list):
            raise ValueError("certificate sites must be a list")
        for certificate in certificates:
            if not isinstance(certificate, dict) or "site" not in certificate:
                raise ValueError("certificate is missing required site")
            site = _integer(certificate["site"])
            if site in result:
                raise ValueError("duplicate certificate site 0x%x" % site)
            if site not in sites:
                raise ValueError("certificate site 0x%x is absent from GT" % site)
            sizes = {block.instructions[-1].size for _, block in sites[site]
                     if block.instructions[-1].size}
            if len(sizes) > 1 or any(size > 15 for size in sizes):
                raise ValueError("certificate site has inconsistent instruction sizes")
            size = next(iter(sizes), 15)
            instruction = next(decoder.disasm(read(site, size, instruction=True), site, count=1), None)
            if (instruction is None or instruction.mnemonic != "jmp" or
                    not instruction.operands or instruction.operands[0].type == x86.X86_OP_IMM):
                raise ValueError("certificate site is not an indirect jump")
            if sizes and instruction.size != size:
                raise ValueError("certificate site instruction size disagrees with GT")
            evidence = certificate.get("evidence", "")
            if not isinstance(evidence, str) or not evidence.strip():
                raise ValueError("certificate requires a source/binary audit reference")
            evidence_kind = certificate.get("evidence_kind", "source_invariant")
            if evidence_kind not in ("source_invariant", "binary_audit"):
                raise ValueError("unsupported certificate evidence kind")
            if certificate.get("switch_only") is not True:
                raise ValueError("certificate must explicitly attest switch-only dispatch")
            table_fields = {"selector_values", "entry_size", "entry_encoding", "table_address"}
            if manifest["schema_version"] == 1:
                tables = [certificate]
            else:
                if table_fields.intersection(certificate) or "relative_base" in certificate:
                    raise ValueError("schema 2 table fields must appear inside tables")
                tables = certificate.get("tables")
                if not isinstance(tables, list) or not 1 <= len(tables) <= 64:
                    raise ValueError("certificate requires 1..64 tables")
            contract = certificate.get("source_contract")
            if contract is not None or (manifest["schema_version"] == 2 and
                                        evidence_kind == "source_invariant"):
                if (not isinstance(contract, list) or not contract or
                        any(not isinstance(item, str) or not item.strip() for item in contract)):
                    raise ValueError("source certificate requires an explicit source_contract")
            targets, decoded_tables = set(), []
            for specification in tables:
                if not isinstance(specification, dict) or not table_fields <= specification.keys():
                    raise ValueError("certificate is missing required table or selector fields")
                if not isinstance(specification["selector_values"], list):
                    raise ValueError("certificate selector values must be a list")
                selectors = sorted({_integer(value) for value in specification["selector_values"]})
                if not selectors or len(selectors) > 4096 or selectors[0] < 0:
                    raise ValueError("certificate requires 1..4096 nonnegative selector values")
                entry_size = _integer(specification["entry_size"])
                if entry_size not in {1, 2, 4, 8}:
                    raise ValueError("unsupported certificate table entry size")
                encoding = specification["entry_encoding"]
                if not isinstance(encoding, str) or encoding not in {"absolute", "signed_relative"}:
                    raise ValueError("unsupported certificate table encoding")
                table = _integer(specification["table_address"])
                if encoding == "signed_relative" and "relative_base" not in specification:
                    raise ValueError("relative certificate table requires a base address")
                base = _integer(specification["relative_base"]) if encoding == "signed_relative" else 0
                if not 0 <= table < 1 << elf.elfclass or not 0 <= base < 1 << elf.elfclass:
                    raise ValueError("certificate table/base is outside the ELF address space")
                table_targets = set()
                for selector in selectors:
                    value = int.from_bytes(read(table + selector * entry_size, entry_size, True),
                                           "little" if elf.little_endian else "big",
                                           signed=encoding == "signed_relative")
                    table_targets.add((base + value) & ((1 << elf.elfclass) - 1))
                targets.update(table_targets)
                decoded_tables.append({"table_address": table, "entry_size": entry_size,
                                       "entry_encoding": encoding, "relative_base": base,
                                       "selector_values": selectors,
                                       "targets": sorted(table_targets)})
            for function, _ in sites[site]:
                boundaries = {ins.va for block in function.bb for ins in block.instructions}
                if not targets <= boundaries:
                    raise ValueError("certificate targets are not local instruction boundaries")
            for target in targets:
                read(target, 1, instruction=True)
            provenance = {"scope": ("audited_source_invariant" if evidence_kind == "source_invariant"
                                     else "audited_binary_domain"), "reference": evidence}
            if manifest["schema_version"] == 1:
                provenance.update({key: value for key, value in decoded_tables[0].items()
                                   if key != "targets"})
            else:
                provenance["tables"] = decoded_tables
            if contract is not None:
                provenance["source_contract"] = contract
                if evidence_kind == "source_invariant":
                    provenance["validation_status"] = "source_validated"
            result[site] = {"site": site, "targets": sorted(targets), "status": "resolved",
                            "reason": "audited selector domain", "evidence": provenance}
    return result


def _group_analyses(analyses):
    grouped = {}
    for record in analyses:
        grouped.setdefault(record["site"], []).append(dict(record))
    records = {}
    for site, rows in grouped.items():
        if len(rows) == 1:
            records[site] = rows[0]
        elif any(record["status"] != "resolved" for record in rows):
            records[site] = {"site": site, "status": "unresolved", "targets": [],
                             "reason": "not all analyses of this shared site resolved",
                             "evidence": {"scope": "local_cfg_selector_domain", "analyses": rows}}
        else:
            if any(not record["targets"] for record in rows):
                raise ValueError("resolved jump table has no targets at 0x%x" % site)
            modes = {record.get("proof_mode", "binary_only") for record in rows}
            records[site] = {"site": site, "status": "resolved",
                             "targets": sorted({target for record in rows for target in record["targets"]}),
                             "reason": "finite table replay covers every analysis of this shared site",
                             "proof_mode": ("combined_binary_source"
                                            if "combined_binary_source" in modes else "binary_only"),
                             "evidence": {"scope": "local_cfg_selector_domain", "analyses": rows}}
    return records


def refine_jump_tables(binary, module, certificates=None, require_resolved=False,
                       metadata=None, source_manifest=None):
    """Refine/promote only fully resolved sites; preserve unresolved legacy rows.

    Return the audit sidecar. With require_resolved, reject the result before
    mutating the module if a legacy jump-table row lacks a finite selector
    domain. This is local CFG evidence, not a whole-program reachability proof.
    """
    from jump_table_analysis import analyze_jump_tables

    if certificates and source_manifest:
        raise ValueError("source build manifests and legacy selector certificates are mutually exclusive")

    malformed = [{"function": function.va, "block": block.va,
                  "reason": "physical jump table has no terminating instruction"}
                 for function in module.fuc for block in function.bb
                 if block.type == 7 and not block.instructions]
    if require_resolved and malformed:
        raise ValueError("%d physical jump-table blocks lack a terminating instruction "
                         "(first block: 0x%x)" % (len(malformed), malformed[0]["block"]))
    hashes = {"binary_sha256": sha256_file(binary)}
    source_directory = os.path.dirname(os.path.abspath(__file__))
    hashes["generator_sha256"] = {
        name: sha256_file(os.path.join(source_directory, name))
        for name in ("extractBB.py", "BlockUtil.py", "jump_table_analysis.py",
                     "jump_table_constants.py", "jump_table_reaching.py",
                     "jump_table_dataflow.py", "jump_table_data_invariants.py",
                     "jump_table_loop_invariants.py", "jump_table_proofs.py",
                     "jump_table_source.py", "jump_table_gt.py")
    }
    hashes["generator_sha256"]["ccr/reorderInfo.py"] = sha256_file(
        os.path.join(source_directory, "..", "ccr", "reorderInfo.py"))
    if metadata:
        hashes["metadata_sha256"] = sha256_file(metadata)
    if certificates:
        hashes["certificates_sha256"] = sha256_file(certificates)
    if source_manifest:
        hashes["source_manifest_sha256"] = sha256_file(source_manifest)

    records = _group_analyses(analyze_jump_tables(binary, module))
    source_report = None
    if source_manifest:
        try:
            from jump_table_proofs import proof_requests
            from jump_table_source import analyze_source_build
        except ModuleNotFoundError:
            from extract_gt.jump_table_proofs import proof_requests
            from extract_gt.jump_table_source import analyze_source_build
        requests = proof_requests(records.values())
        source_result = analyze_source_build(source_manifest, binary, requests)
        facts = source_result["facts"]
        # Repeat the affected binary analysis with source facts available. The
        # coordinator still validates and decodes every table from `binary`.
        records = _group_analyses(analyze_jump_tables(binary, module, source_facts=facts))
        manifest = source_result["manifest"]
        source_report = {
            "status": source_result["status"],
            "manifest": {key: manifest[key] for key in
                         ("manifest_path", "manifest_sha256", "binary_sha256", "source_root",
                          "file_hashes", "definitions", "compile_commands", "linked_inputs",
                          "dwarf_source_files", "contract")},
            "request_count": source_result["requests"],
            "facts": [{"site": fact.get("site"), "kind": fact.get("kind"),
                       "status": fact.get("status"), "reason": fact.get("reason"),
                       "proved_obligations": fact.get("proved_obligations", [])}
                      for fact in facts],
            "unresolved_requests": source_result["unresolved_requests"],
            "proved_sites": source_result["proved_sites"],
        }
    if certificates:
        for site, certificate in read_certificates(certificates, binary, module).items():
            certificate["binary_analysis"] = records.get(site, {
                "site": site, "status": "unresolved", "targets": [],
                "reason": "no site-level selector analysis"})
            certificate["proof_mode"] = "legacy_certificate"
            records[site] = certificate
    sites = _site_blocks(module)
    for site, blocks in sites.items():
        if any(block.type == 7 for _, block in blocks) and site not in records:
            records[site] = {"site": site, "status": "unresolved",
                             "reason": "no site-level selector analysis", "targets": []}
    unresolved = []
    changes = []
    for site, record in sorted(records.items()):
        blocks = sites.get(site, [])
        if not blocks:
            raise ValueError("analysis returned unknown site 0x%x" % site)
        old_targets = sorted({child.va for _, block in blocks for child in block.child})
        was_table = any(block.type == 7 for _, block in blocks)
        record["previous_targets"] = old_targets
        record["previously_jump_table"] = was_table
        if record["status"] != "resolved":
            record["action"] = "preserved_physical_table" if was_table else "unresolved"
            if was_table:
                unresolved.append(site)
            continue
        targets = sorted(set(record["targets"]))
        if not targets:
            raise ValueError("resolved jump table has no targets at 0x%x" % site)
        record["targets"] = targets
        record["action"] = ("promoted" if not was_table else
                            "refined" if targets != old_targets else "confirmed")
        changes.append((blocks, targets))
    if require_resolved and unresolved:
        raise ValueError("%d jump-table sites lack selector evidence (first: 0x%x); "
                         "inspect the analysis or supply audited selector certificates" %
                         (len(unresolved), unresolved[0]))
    for blocks, targets in changes:
        for _, block in blocks:
            del block.child[:]
            for target in targets:
                block.child.add().va = target
            block.type = 7
    report = {"schema_version": 1, **hashes,
              "protobuf_sha256": hashlib.sha256(module.SerializeToString()).hexdigest(),
              "analysis_scope": ("combined_binary_source_proof" if source_manifest else
                                 "local_cfg_selector_domain_with_audited_overrides" if certificates
                                 else "local_cfg_selector_domain"),
              "unresolved_physical_tables": len(unresolved) + len(malformed),
              "malformed_physical_tables": malformed,
              "sites": [records[site] for site in sorted(records)]}
    if source_report is not None:
        report["source_assistance"] = source_report
    return report


def write_outputs(module, output, report, report_path=None):
    """Stage both artifacts and roll back replacement failures.

    The protobuf hash detects mismatched pairs after interruption between the
    two renames; a filesystem cannot atomically rename two independent files.
    """
    output = os.fspath(output)
    report_path = report_path or output + ".jumptables.json"
    if os.path.realpath(output) == os.path.realpath(report_path):
        raise ValueError("protobuf and jump-table report paths must differ")
    protobuf = module.SerializeToString()
    report["protobuf_sha256"] = hashlib.sha256(protobuf).hexdigest()
    staged = []
    backups = {}
    replaced = []
    retained_backups = set()
    try:
        for path, content in ((report_path, (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()),
                              (output, protobuf)):
            directory = os.path.dirname(os.path.abspath(path))
            with tempfile.NamedTemporaryFile(dir=directory, delete=False) as target:
                staged.append((target.name, path))
                target.write(content)
            if os.path.lexists(path):
                with tempfile.NamedTemporaryFile(dir=directory, delete=False) as backup:
                    backups[path] = backup.name
                if os.path.islink(path):
                    os.unlink(backup.name)
                    os.symlink(os.readlink(path), backup.name)
                else:
                    shutil.copy2(path, backup.name)
            else:
                backups[path] = None
        try:
            for temporary, path in staged:
                os.replace(temporary, path)
                replaced.append(path)
        except OSError as replacement_error:
            rollback_errors = []
            for path in reversed(replaced):
                try:
                    if backups[path] is None:
                        os.unlink(path)
                    else:
                        os.replace(backups[path], path)
                except OSError as rollback_error:
                    if backups[path] is not None:
                        retained_backups.add(backups[path])
                    rollback_errors.append("%s (previous artifact: %s): %s" %
                                           (path, backups[path], rollback_error))
            if rollback_errors:
                raise OSError("artifact replacement failed; rollback failed: " +
                              "; ".join(rollback_errors)) from replacement_error
            raise
    finally:
        temporaries = [temporary for temporary, _ in staged] + list(backups.values())
        for temporary in temporaries:
            if (temporary is not None and temporary not in retained_backups
                    and os.path.lexists(temporary)):
                os.unlink(temporary)


def main():
    # Also usable on an existing protobuf, without re-running legacy extraction.
    import deps  # noqa: F401: makes the repository protobuf module importable
    import blocks_pb2

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-b", "--binary", required=True)
    parser.add_argument("-g", "--ground-truth", required=True)
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("--jump-table-certificates")
    parser.add_argument("--source-build-manifest")
    parser.add_argument("--jump-table-report")
    parser.add_argument("--require-resolved-jump-tables", action="store_true")
    args = parser.parse_args()
    module = blocks_pb2.module()
    with open(args.ground_truth, "rb") as source:
        module.ParseFromString(source.read())
    try:
        report = refine_jump_tables(args.binary, module, args.jump_table_certificates,
                                    args.require_resolved_jump_tables,
                                    source_manifest=args.source_build_manifest)
        write_outputs(module, args.output, report, args.jump_table_report)
    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
