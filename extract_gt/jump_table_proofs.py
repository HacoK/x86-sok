"""Coordinate binary obligations with source-supplied proof facts.

The coordinator deliberately keeps the two proof domains separate.  A source
fact can discharge a named premise, while table bytes, selector closure, the
machine loop, and final target decoding remain delegated to the binary side.
"""

from copy import deepcopy
from pathlib import Path


PROOF_MODES = {"binary_only", "combined_binary_source", "legacy_certificate"}


def _integer(value):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError("proof addresses and selectors must be integers")
    return int(value, 0) if isinstance(value, str) else int(value)


def _site(value):
    site = _integer(value)
    if site < 0:
        raise ValueError("proof site must be nonnegative")
    return site


def _writable_proofs(record):
    evidence = record.get("evidence") if isinstance(record, dict) else None
    proofs = evidence.get("writable_selector_data", []) if isinstance(evidence, dict) else []
    return [item for item in proofs if isinstance(item, dict)] if isinstance(proofs, list) else []


def _request_records(record):
    """Expand a grouped shared-site record into its contributing analyses."""
    if not isinstance(record, dict):
        return []
    rows = [record]
    evidence = record.get("evidence")
    analyses = evidence.get("analyses") if isinstance(evidence, dict) else None
    if isinstance(analyses, list):
        nested = [row for item in analyses for row in _request_records(item)]
        return nested or rows
    return rows


def proof_requests(records):
    """Return explicit unresolved facts requested by binary analysis.

    One writable object produces one request whose dependency list contains
    every failed obligation.  This makes a partial source answer fail closed
    without generating application-specific request names.
    """
    requests = []
    seen = set()
    for grouped in records:
        if not isinstance(grouped, dict) or grouped.get("status") == "resolved":
            continue
        for record in _request_records(grouped):
            site = _site(record.get("site"))
            writable = _writable_proofs(record)
            if writable:
                for proof in writable:
                    table = _integer(proof.get("table_address"))
                    missing = [item for item in proof.get("obligations", [])
                               if isinstance(item, dict) and not item.get("proved")]
                    if not missing:
                        continue
                    request_id = "0x%x:object:0x%x" % (site, table)
                    if request_id in seen:
                        continue
                    seen.add(request_id)
                    evidence = record.get("evidence") if isinstance(record.get("evidence"), dict) else {}
                    requests.append({
                        "request_id": request_id,
                        "kind": "writable_object_invariant",
                        "site": site,
                        "function": _integer(proof.get("function", evidence.get("function", 0))),
                        "table_address": table,
                        "entry_size": _integer(proof.get("entry_size", 0)),
                        "entry_count": _integer(proof.get("entry_count", 0)),
                        "load_instruction": _integer(proof.get("load_instruction", 0)),
                        "obligations": sorted({item["kind"] for item in missing}),
                        "binary_obligations": deepcopy(proof.get("obligations", [])),
                        "loop_transfer": deepcopy(next((item for item in proof.get("obligations", [])
                                                        if item.get("kind") == "loop_transfer"), None)),
                    })
                continue
            request_id = "0x%x:computed_goto_dispatch" % site
            if request_id in seen:
                continue
            seen.add(request_id)
            evidence = record.get("evidence") if isinstance(record.get("evidence"), dict) else {}
            function = evidence.get("function")
            requests.append({
                "request_id": request_id,
                "kind": "computed_goto_dispatch",
                "site": site,
                "function": _integer(function) if function is not None else None,
                "binary_reason": record.get("reason"),
                "binary_evidence": deepcopy(evidence),
            })
    return requests


def _read_tables(binary, site, tables):
    from elftools.elf.elffile import ELFFile

    if not isinstance(tables, list) or not tables:
        raise ValueError("source-assisted dispatch requires at least one table")
    rows = []
    with Path(binary).open("rb") as source:
        elf = ELFFile(source)
        if elf.get_machine_arch() not in {"x86", "x64"}:
            raise ValueError("source-assisted tables require x86 ELF")
        segments = [segment for segment in elf.iter_segments()
                    if segment["p_type"] == "PT_LOAD"]
        for specification in tables:
            if not isinstance(specification, dict):
                raise ValueError("source table specification must be an object")
            table = _integer(specification.get("table_address"))
            entry_size = _integer(specification.get("entry_size"))
            selectors = sorted({_integer(value) for value in specification.get("selector_values", [])})
            encoding = specification.get("entry_encoding")
            if entry_size not in {1, 2, 4, 8} or not selectors or selectors[0] < 0:
                raise ValueError("invalid source-assisted table shape")
            if encoding not in {"absolute", "signed_relative"}:
                raise ValueError("invalid source-assisted table encoding")
            base = _integer(specification.get("relative_base", 0))
            decoded = []
            for selector in selectors:
                address = table + selector * entry_size
                segment = next((item for item in segments
                                if item["p_vaddr"] <= address and
                                address + entry_size <= item["p_vaddr"] + item["p_filesz"]), None)
                if segment is None:
                    raise ValueError("source-assisted table reads outside the original ELF")
                source.seek(segment["p_offset"] + address - segment["p_vaddr"])
                raw = source.read(entry_size)
                if len(raw) != entry_size:
                    raise ValueError("source-assisted table read is truncated")
                value = int.from_bytes(raw, "little", signed=encoding == "signed_relative")
                target = (base + value if encoding == "signed_relative" else value)
                target &= (1 << elf.elfclass) - 1
                decoded.append({"selector": selector, "target": target,
                                "bytes": raw.hex()})
            rows.append({"table_address": table, "entry_size": entry_size,
                         "entry_encoding": encoding, "relative_base": base,
                         "selector_values": selectors, "decoded": decoded})
    return rows


def _combined_obligations(record, fact):
    requests = set(fact.get("proved_obligations", []))
    proof = _writable_proofs(record)
    if not proof:
        return []
    rows = []
    for item in proof[0].get("obligations", []):
        if not isinstance(item, dict):
            continue
        row = deepcopy(item)
        if item.get("kind") in requests:
            row["binary_proved"] = bool(item.get("proved"))
            row["source_proved"] = True
            row["status"] = "proved_by_combined_evidence"
        elif item.get("proved"):
            row["binary_proved"] = True
            row["source_proved"] = False
            row["status"] = "proved_by_binary_analysis"
        else:
            row["binary_proved"] = False
            row["source_proved"] = False
            row["status"] = "unresolved"
        rows.append(row)
    return rows


def _terminal_target_tables(record, selectors):
    """Find the immutable target tables already reached by binary replay."""
    evidence = record.get("evidence") if isinstance(record, dict) else {}
    paths = evidence.get("paths", []) if isinstance(evidence, dict) else []
    coverage = {}
    for path in paths if isinstance(paths, list) else ():
        if not isinstance(path, dict):
            continue
        for load in path.get("loads", []):
            if (not isinstance(load, dict) or load.get("instruction") != record.get("site")
                    or type(load.get("entry_size")) is not int):
                continue
            entries = [item for item in load.get("entries", []) if isinstance(item, dict)]
            if not entries:
                continue
            addresses = {item.get("address") for item in entries}
            if any(type(address) is not int for address in addresses):
                continue
            base = min(addresses)
            size = load["entry_size"]
            indexes = {(address - base) // size for address in addresses}
            if (any(address != base + index * size for address, index in zip(sorted(addresses), sorted(indexes)))
                    or any(index < 0 for index in indexes)):
                raise ValueError("binary terminal-table evidence is not contiguous")
            coverage[(base, size)] = coverage.get((base, size), set()) | set(indexes)
    if not coverage:
        raise ValueError("writable source fact has no binary terminal target table")
    rows = []
    for (table, size), available in sorted(coverage.items()):
        if not set(selectors) <= available:
            raise ValueError("binary terminal table does not cover the proved selector domain")
        rows.append({"table_address": table, "entry_size": size,
                     "entry_encoding": "absolute", "selector_values": sorted(selectors),
                     "binary_selector_coverage": sorted(available)})
    return rows


def apply_source_facts(records, facts, binary):
    """Discharge matching requests and build final records, failing closed.

    ``records`` is replaced only when every missing writable obligation has a
    source or binary proof and the binary loop proof supplies a finite selector
    set.  A computed-goto fact is accepted only after every supplied offset is
    decoded from the original ELF and its complete target union is reproduced.
    """
    if not facts:
        return records
    if not isinstance(facts, list):
        raise ValueError("source facts must be a list")
    by_site = {}
    for fact in facts:
        if not isinstance(fact, dict) or fact.get("status") not in {"proved", "unresolved"}:
            raise ValueError("source fact requires a proved or unresolved status")
        site = _site(fact.get("site"))
        if site in by_site:
            raise ValueError("duplicate source facts for 0x%x" % site)
        by_site[site] = fact
    known = {_site(item.get("site")) for item in records if isinstance(item, dict)}
    unknown = sorted(set(by_site) - known)
    if unknown:
        raise ValueError("source facts target sites absent from binary analysis: " +
                         ", ".join("0x%x" % site for site in unknown))

    result = []
    for original in records:
        if not isinstance(original, dict):
            result.append(original)
            continue
        record = deepcopy(original)
        site = _site(record.get("site"))
        fact = by_site.get(site)
        if fact is None:
            if record.get("status") == "resolved":
                record.setdefault("proof_mode", "binary_only")
            result.append(record)
            continue
        evidence = record.setdefault("evidence", {})
        requests = [row for row in fact.get("requests", []) if isinstance(row, dict)]
        evidence["proof_requests"] = deepcopy(requests)
        if fact["status"] != "proved":
            evidence["source_assistance"] = {"status": "unresolved",
                                              "reason": fact.get("reason", "source proof failed")}
            result.append(record)
            continue
        if record.get("status") == "resolved":
            raise ValueError("source fact targets an already resolved site 0x%x" % site)

        kind = fact.get("kind")
        if kind == "writable_object_invariant":
            proofs = _writable_proofs(record)
            if len(proofs) != 1 or _integer(proofs[0].get("table_address")) != _integer(fact.get("table_address")):
                raise ValueError("source fact does not match the binary writable object at 0x%x" % site)
            loop = next((item for item in proofs[0].get("obligations", [])
                         if isinstance(item, dict) and item.get("kind") == "loop_transfer"), None)
            selectors = loop.get("selectors") if isinstance(loop, dict) and loop.get("proved") else None
            if not isinstance(selectors, list) or not selectors:
                evidence["source_assistance"] = {
                    "status": "unresolved", "reason": "binary loop proof did not provide selectors"}
                result.append(record)
                continue
            target_tables = _terminal_target_tables(record, selectors)
            decoded_tables = _read_tables(binary, site, target_tables)
            targets = sorted({row["target"] for table in decoded_tables for row in table["decoded"]})
            upper = set(record.get("local_upper_bound", []))
            if not targets or (upper and not set(targets) <= upper):
                raise ValueError("source-assisted selector decode is outside the binary upper bound")
            obligations = _combined_obligations(record, fact)
            if any(row.get("status") == "unresolved" for row in obligations):
                evidence["source_assistance"] = {
                    "status": "unresolved", "reason": "combined obligations remain undischarged",
                    "obligations": obligations}
                result.append(record)
                continue
            for table in decoded_tables:
                obligations.append({
                    "kind": "binary_target_replay", "status": "proved_by_binary_analysis",
                    "table_address": table["table_address"],
                    "entry_size": table["entry_size"],
                    "selector_values": table["selector_values"],
                    "bytes_decoded_from_original_binary": True})
        elif kind == "computed_goto_dispatch":
            decoded_tables = _read_tables(binary, site, fact.get("tables"))
            targets = sorted({row["target"] for table in decoded_tables for row in table["decoded"]})
            expected = sorted({_integer(value) for value in fact.get("targets", [])})
            if not targets or targets != expected:
                raise ValueError("source-assisted target union does not match original ELF bytes at 0x%x" % site)
            fallback = fact.get("fallback")
            if not isinstance(fallback, dict) or _integer(fallback.get("target")) not in targets:
                raise ValueError("source fallback is not represented in the decoded target union")
            obligations = []
            for table in decoded_tables:
                obligations.append({
                    "kind": "source_table_binding", "status": "proved_by_combined_evidence",
                    "table_address": table["table_address"],
                    "entry_count": len(table["selector_values"]),
                    "bytes_decoded_from_original_binary": True})
            obligations.append({"kind": "source_fallback",
                                "status": "proved_by_combined_evidence",
                                "source_label": fallback.get("source_label"),
                                "target": _integer(fallback.get("target")),
                                "binary_target_revalidated": True})
        else:
            raise ValueError("unsupported source fact kind: %r" % kind)

        binary_record = {key: value for key, value in record.items()
                         if key not in ("evidence", "targets", "status", "reason", "proof_mode")}
        record.update({
            "status": "resolved",
            "targets": targets,
            "reason": "binary replay completed by validated source facts",
            "proof_mode": "combined_binary_source",
        })
        evidence.update({
            "scope": "combined_binary_source",
            "proof_status": "complete",
            "proof_mode": "combined_binary_source",
            "obligations": obligations,
            "binary_analysis_initial": binary_record,
            "source_analysis": {key: deepcopy(value) for key, value in fact.items()
                                if key not in ("site", "targets", "tables", "table")},
        })
        result.append(record)
    return result


def summarize_records(records):
    summary = {mode: 0 for mode in PROOF_MODES}
    for record in records:
        if not isinstance(record, dict) or record.get("status") != "resolved":
            continue
        mode = record.get("proof_mode", "binary_only")
        summary[mode] = summary.get(mode, 0) + 1
    return summary
