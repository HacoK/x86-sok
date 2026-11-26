#!/usr/bin/env python3
"""Audit every Corpus 1 tool discrepancy against explicit T_phys/T_feas."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_COMPARATOR = Path("/mnt/nvme1/sba/tools/compare_jump_table_results.py")
DEFAULT_LAYER_ROOT = Path("/mnt/nvme1/sba/tmp/x86-sok-corpus1-two-layer-v2")
DEFAULT_AUDIT_ROOT = REPO_ROOT / "artifact_eval" / "corpus1_two_layer_audit"


TOOLS = {
    "proofjtr": "ProofJTR",
    "idapro": "IDA Pro 9.0",
    "ghidra": "Ghidra 12",
    "angr": "angr",
    "dyninst": "Dyninst",
    "sja": "SJA",
}
METRIC_KEYS = (
    "files",
    "truth_total",
    "detected_total",
    "exact_matches",
    "false_positive",
    "false_negative",
    "wrong_successors",
    "filtered_non_jump_sites",
    "filtered_call_sites",
    "filtered_unknown_sites",
    "address_normalized_files",
    "address_normalized_sites",
)
AUDIT_FIELDS = (
    "tool",
    "binary_relpath",
    "site_va",
    "physical_category",
    "physical_truth_count",
    "physical_truth_targets_sha256",
    "detected_count",
    "detected_targets_sha256",
    "t_feas_category",
    "t_feas_truth_count",
    "t_feas_truth_targets_sha256",
    "outcome",
)


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as source:
        return json.load(source)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def write_csv(path: Path, rows: list[dict[str, Any]], fields: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=list(fields))
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def target_hash(targets: Iterable[int]) -> str:
    canonical = ",".join(f"0x{target:x}" for target in sorted(set(targets)))
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def relative_binary(result: dict[str, Any]) -> str:
    text = str(result["binary"]).replace("\\", "/")
    markers = (
        "x86_dataset_stripped_x64_ground_truth/",
        "x86-sok-corpus1-refined/",
        "x86-sok-corpus1-two-layer/T_phys/",
        "x86-sok-corpus1-two-layer/T_feas/",
        "x86-sok-corpus1-two-layer-v2/T_phys/",
        "x86-sok-corpus1-two-layer-v2/T_feas/",
        "x86-sok-corpus1-two-layer/",
        "x86-sok-corpus1-two-layer-v2/",
    )
    for marker in markers:
        if marker in text:
            return text.split(marker, 1)[1]
    raise ValueError(f"cannot derive Corpus 1 relative path: {text}")


def verify_layers(layer_root: Path) -> dict[str, Any]:
    summary = load_json(layer_root / "layer_summary.json")
    expected = {
        "files": 2026,
        "sites": 61249,
        "added_physical_sites": 347,
        "restored_physical_target_sets": 25,
    }
    for key, value in expected.items():
        if int(summary[key]) != value:
            raise RuntimeError(
                f"layer {key}={summary[key]} does not match expected {value}"
            )

    physical_hash_mismatches = 0
    feasible_hash_mismatches = 0
    sidecar_subset_violations = 0
    sidecar_site_count = 0
    sidecar_physical_edges = 0
    sidecar_feasible_edges = 0
    with (layer_root / "oracle_layer_manifest.csv").open(
        newline="", encoding="utf-8"
    ) as source:
        rows = list(csv.DictReader(source))
    for row in rows:
        physical = Path(row["physical_protobuf"])
        feasible = Path(row["feasible_protobuf"])
        if sha256_file(physical) != row["physical_sha256"]:
            physical_hash_mismatches += 1
        if sha256_file(feasible) != row["feasible_sha256"]:
            feasible_hash_mismatches += 1
        sidecar = load_json(Path(row["feasible_sidecar"]))
        sidecar_site_count += int(sidecar["physical_site_count"])
        sidecar_physical_edges += int(sidecar["physical_target_count"])
        sidecar_feasible_edges += int(sidecar["feasible_target_count"])
        for change in sidecar["changes"]:
            if not set(change["feasible_targets"]) <= set(
                change["physical_targets"]
            ):
                sidecar_subset_violations += 1
    if physical_hash_mismatches or feasible_hash_mismatches:
        raise RuntimeError(
            "layer hash mismatch: "
            f"T_phys={physical_hash_mismatches}, T_feas={feasible_hash_mismatches}"
        )
    if sidecar_subset_violations:
        raise RuntimeError(
            f"{sidecar_subset_violations} recorded T_feas rows are not subsets"
        )
    if sidecar_site_count != int(summary["sites"]):
        raise RuntimeError("sidecar site count does not match layer summary")
    if sidecar_physical_edges != int(summary["physical_target_edges"]):
        raise RuntimeError("sidecar physical edge count does not match layer summary")
    if sidecar_feasible_edges != int(summary["feasible_target_edges"]):
        raise RuntimeError("sidecar feasible edge count does not match layer summary")
    return {
        **summary,
        "manifest_rows": len(rows),
        "physical_hash_mismatches": physical_hash_mismatches,
        "feasible_hash_mismatches": feasible_hash_mismatches,
        "sidecar_subset_violations": sidecar_subset_violations,
        "verified_sidecar_sites": sidecar_site_count,
        "verified_sidecar_physical_edges": sidecar_physical_edges,
        "verified_sidecar_feasible_edges": sidecar_feasible_edges,
    }


def error_map(score: dict[str, Any]) -> dict[str, dict[int, dict[str, Any]]]:
    def result_path(value: str) -> str:
        prefix = "/home/haco/sba/"
        return "/mnt/nvme1/sba/" + value[len(prefix) :] if value.startswith(prefix) else value

    mapped: dict[str, dict[int, dict[str, Any]]] = {}
    for result in score["results"]:
        relative = relative_binary(result)
        entries = mapped.setdefault(relative, {})
        for site in result["false_positive"]:
            entries[int(site, 0)] = {
                "category": "false_positive",
                "detected_targets": set(),
                "result_path": result_path(result["result"]),
            }
        for site in result["false_negative"]:
            entries[int(site, 0)] = {
                "category": "false_negative",
                "detected_targets": set(),
                "result_path": result_path(result["result"]),
            }
        for wrong in result["wrong_successors"]:
            entries[int(wrong["site"], 0)] = {
                "category": "wrong_successors",
                "detected_targets": {
                    int(target, 0) for target in wrong["detected_targets"]
                },
                "result_path": result_path(result["result"]),
            }
    return mapped


def metric_row(display: str, gt: str, score: dict[str, Any]) -> dict[str, Any]:
    aggregate = score["aggregate"]
    row: dict[str, Any] = {"tool": display, "ground_truth": gt}
    row.update({key: int(aggregate.get(key, 0)) for key in METRIC_KEYS})
    row["precision"] = (
        row["exact_matches"] / row["detected_total"]
        if row["detected_total"]
        else 0.0
    )
    row["recall"] = (
        row["exact_matches"] / row["truth_total"]
        if row["truth_total"]
        else 0.0
    )
    return row


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--layer-root", type=Path, default=DEFAULT_LAYER_ROOT)
    parser.add_argument("--audit-root", type=Path, default=DEFAULT_AUDIT_ROOT)
    parser.add_argument("--comparator", type=Path, default=DEFAULT_COMPARATOR)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    layer_root = args.layer_root.resolve()
    audit_root = args.audit_root.resolve()
    comparator = args.comparator.resolve()
    comparator_directory = str(comparator.parent)
    if comparator_directory not in sys.path:
        sys.path.insert(0, comparator_directory)
    import compare_jump_table_results as comparator_module

    verification = verify_layers(layer_root)
    physical_scores = {
        key: load_json(audit_root / "scores" / "T_phys" / f"{key}.json")
        for key in TOOLS
    }
    feasible_scores = {
        key: load_json(audit_root / "scores" / "T_feas" / f"{key}.json")
        for key in TOOLS
    }
    for layer, scores in (
        ("T_phys", physical_scores),
        ("T_feas", feasible_scores),
    ):
        truth_totals = {int(score["aggregate"]["truth_total"]) for score in scores.values()}
        if truth_totals != {61249}:
            raise RuntimeError(f"{layer} truth totals are inconsistent: {truth_totals}")
        for key, score in scores.items():
            if int(score["aggregate"]["files"]) != 2026:
                raise RuntimeError(f"{layer}/{key} does not cover 2,026 binaries")

    metrics = []
    for key, display in TOOLS.items():
        metrics.append(metric_row(display, "T_phys", physical_scores[key]))
        metrics.append(metric_row(display, "T_feas", feasible_scores[key]))
    write_csv(
        audit_root / "tool_metrics.csv",
        metrics,
        (
            "tool",
            "ground_truth",
            *METRIC_KEYS,
            "precision",
            "recall",
        ),
    )

    physical_errors = {key: error_map(score) for key, score in physical_scores.items()}
    feasible_errors = {key: error_map(score) for key, score in feasible_scores.items()}
    all_relative = sorted(
        set().union(
            *(set(mapping) for mapping in physical_errors.values())
        )
    )
    audited_by_tool: dict[str, list[dict[str, Any]]] = {
        key: [] for key in TOOLS
    }
    detected_target_cache: dict[tuple[str, str], dict[int, set[int]]] = {}
    for relative in all_relative:
        physical_pb = (
            layer_root
            / "T_phys"
            / Path(relative).parent
            / f"gtBlock_{Path(relative).name[:-6]}.pb"
        )
        feasible_pb = (
            layer_root
            / "T_feas"
            / Path(relative).parent
            / f"gtBlock_{Path(relative).name[:-6]}.pb"
        )
        physical_truth = comparator_module.load_ground_truth_tables(physical_pb, 7)
        feasible_truth = comparator_module.load_ground_truth_tables(feasible_pb, 7)
        for key, display in TOOLS.items():
            for site, physical_error in sorted(
                physical_errors[key].get(relative, {}).items()
            ):
                physical_targets = physical_truth.get(site, set())
                feasible_targets = feasible_truth.get(site, set())
                feasible_error = feasible_errors[key].get(relative, {}).get(site)
                if feasible_error is None:
                    outcome = "resolved_by_guarded_feasibility"
                    feasible_category = "exact"
                else:
                    feasible_category = feasible_error["category"]
                    outcome = f"confirmed_{feasible_category}"
                detected = physical_error["detected_targets"]
                if physical_error["category"] == "false_positive":
                    cache_key = (key, relative)
                    if cache_key not in detected_target_cache:
                        parsed = comparator_module.parse_jump_table_output(
                            Path(physical_error["result_path"])
                        )
                        parsed = comparator_module.normalize_parsed_result_for_binary(
                            layer_root / "T_phys" / relative, parsed
                        )
                        filtered = comparator_module._filter_detected_tables(
                            layer_root / "T_phys" / relative,
                            parsed.indirect_tables,
                            site_filter="jumps-only",
                        )
                        detected_target_cache[cache_key] = filtered.tables
                    detected = detected_target_cache[cache_key].get(site, set())
                audited_by_tool[key].append(
                    {
                        "tool": display,
                        "binary_relpath": relative,
                        "site_va": f"0x{site:x}",
                        "physical_category": physical_error["category"],
                        "physical_truth_count": len(physical_targets),
                        "physical_truth_targets_sha256": target_hash(
                            physical_targets
                        ),
                        "detected_count": len(detected),
                        "detected_targets_sha256": target_hash(detected),
                        "t_feas_category": feasible_category,
                        "t_feas_truth_count": len(feasible_targets),
                        "t_feas_truth_targets_sha256": target_hash(
                            feasible_targets
                        ),
                        "outcome": outcome,
                    }
                )

    all_audited = []
    audit_summaries = {}
    for key, display in TOOLS.items():
        rows = audited_by_tool[key]
        all_audited.extend(rows)
        outcomes = Counter(row["outcome"] for row in rows)
        categories = Counter(row["physical_category"] for row in rows)
        audit_summaries[key] = {
            "tool": display,
            "physical_error_rows": len(rows),
            "physical_category_counts": dict(sorted(categories.items())),
            "outcome_counts": dict(sorted(outcomes.items())),
        }
        write_csv(
            audit_root / f"audit_{key}_{len(rows)}.csv",
            rows,
            AUDIT_FIELDS,
        )
    write_csv(
        audit_root / "all_discrepancies_audited.csv",
        all_audited,
        AUDIT_FIELDS,
    )

    summary = {
        "schema_version": 1,
        "definitions": verification["definition"],
        "correction": (
            "This report supersedes artifact_eval/corpus1_audit. The earlier "
            "audit treated the accepted repaired tree as T_phys, which mixed "
            "347 real physical-site additions with 25 feasibility-oriented "
            "successor shrinks. The corrected T_phys retains every evidenced "
            "site and restores the 25 compiler-physical target sets."
        ),
        "protocol": (
            "All tools are scored against the same two protobuf layers with "
            "the unchanged positive jump-only comparator. Every T_phys "
            "discrepancy is reclassified against the materialized T_feas "
            "target set."
        ),
        "paper_sentence": (
            "We publish two explicit oracles: T_phys contains all physically "
            "evidenced table targets, including compiler/linker-bound entries "
            "and audited computed-goto and other physical-site additions; "
            "T_feas is its independently guarded site-feasible subset."
        ),
        "layer_verification": verification,
        "metrics": metrics,
        "audits": audit_summaries,
        "scores": {
            "T_phys": str(audit_root / "scores" / "T_phys"),
            "T_feas": str(audit_root / "scores" / "T_feas"),
        },
    }
    write_json(audit_root / "summary.json", summary)

    lines = [
        "# Corpus 1: Explicit Physical and Feasible Oracles",
        "",
        summary["paper_sentence"],
        "",
        "## Definitions",
        "",
        f"- **T_phys:** {summary['definitions']['T_phys']}",
        f"- **T_feas:** {summary['definitions']['T_feas']}",
        "",
        "## Correction",
        "",
        summary["correction"],
        "",
        "## Oracle Integrity",
        "",
        f"- Physical sites: `{verification['sites']}`.",
        f"- Audited physical site additions: `{verification['added_physical_sites']}`.",
        f"- Restored compiler-physical target sets: `{verification['restored_physical_target_sets']}`.",
        f"- Guarded feasible refinements: `{verification['changed_sites']}`.",
        f"- Non-physical guarded edges clipped: `{verification['dropped_nonphysical_edges']}`.",
        f"- Layer hash mismatches: `{verification['physical_hash_mismatches'] + verification['feasible_hash_mismatches']}`.",
        f"- Recorded subset violations: `{verification['sidecar_subset_violations']}`.",
        "",
        "## Tool Metrics",
        "",
        "| Tool | GT | Truth | Detected | Exact | FP | FN | WS | Precision | Recall |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in metrics:
        lines.append(
            f"| {row['tool']} | {row['ground_truth']} | {row['truth_total']} | "
            f"{row['detected_total']} | {row['exact_matches']} | "
            f"{row['false_positive']} | {row['false_negative']} | "
            f"{row['wrong_successors']} | {row['precision']:.2%} | "
            f"{row['recall']:.2%} |"
        )
    lines.extend(
        [
            "",
            "## Discrepancy Audit",
            "",
            "| Tool | T_phys discrepancies | Resolved under T_feas | Confirmed |",
            "| --- | ---: | ---: | ---: |",
        ]
    )
    for key, display in TOOLS.items():
        audit = audit_summaries[key]
        resolved = sum(
            count
            for outcome, count in audit["outcome_counts"].items()
            if outcome.startswith("resolved_")
        )
        confirmed = sum(
            count
            for outcome, count in audit["outcome_counts"].items()
            if outcome.startswith("confirmed_")
        )
        lines.append(
            f"| {display} | {audit['physical_error_rows']} | {resolved} | "
            f"{confirmed} |"
        )
    lines.extend(
        [
            "",
            "Per-row evidence is in the `audit_<tool>_<rows>.csv` files and "
            "`all_discrepancies_audited.csv`.",
        ]
    )
    (audit_root / "summary.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "summary": str(audit_root / "summary.md"),
                "metrics": str(audit_root / "tool_metrics.csv"),
                "audits": {
                    key: row["physical_error_rows"]
                    for key, row in audit_summaries.items()
                },
            },
            indent=2,
            sort_keys=True,
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
