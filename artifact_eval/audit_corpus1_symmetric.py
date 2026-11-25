#!/usr/bin/env python3
"""Score Corpus 1 on T_phys/T_feas and audit every physical error row."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PHYSICAL_ROOT = Path(
    "/mnt/nvme1/sba/x86_dataset_stripped_x64_ground_truth"
)
DEFAULT_REFINED_ROOT = Path("/mnt/nvme1/sba/tmp/x86-sok-corpus1-refined")
DEFAULT_COMPARATOR = Path(
    "/mnt/nvme1/sba/tools/compare_jump_table_results.py"
)
DEFAULT_OUTPUT_ROOT = REPO_ROOT / "artifact_eval" / "corpus1_audit"


@dataclass(frozen=True)
class ToolSpec:
    key: str
    display: str
    results: Path
    physical_json: Path
    physical_errors: Path


TOOLS = (
    ToolSpec(
        key="proofjtr",
        display="ProofJTR",
        results=Path(
            "/mnt/nvme1/sba/reports/ndss_artifacts/"
            "artifact-final-strict/results"
        ),
        physical_json=Path(
            "/mnt/nvme1/sba/reports/ndss_artifacts/"
            "artifact-final-strict/comparison.json"
        ),
        physical_errors=Path(
            "/mnt/nvme1/sba/reports/ndss_artifacts/"
            "artifact-final-strict/error_sites.csv"
        ),
    ),
    ToolSpec(
        key="idapro",
        display="IDA Pro 9.0",
        results=Path("/mnt/nvme1/sba/experiment/idapro/jt_results"),
        physical_json=Path(
            "/mnt/nvme1/sba/reports/paper_artifacts/"
            "current_gt_baseline_compare/idapro.json"
        ),
        physical_errors=Path(
            "/mnt/nvme1/sba/experiment/idapro/jump_table_error_sites.csv"
        ),
    ),
    ToolSpec(
        key="ghidra",
        display="Ghidra 12",
        results=Path("/mnt/nvme1/sba/experiment/ghidra/jt_results"),
        physical_json=Path(
            "/mnt/nvme1/sba/reports/paper_artifacts/"
            "current_gt_baseline_compare/ghidra.json"
        ),
        physical_errors=Path(
            "/mnt/nvme1/sba/experiment/ghidra/jump_table_error_sites.csv"
        ),
    ),
    ToolSpec(
        key="angr",
        display="angr",
        results=Path("/mnt/nvme1/sba/experiment/angr/jt_results"),
        physical_json=Path(
            "/mnt/nvme1/sba/reports/paper_artifacts/"
            "current_gt_baseline_compare/angr.json"
        ),
        physical_errors=Path(
            "/mnt/nvme1/sba/experiment/angr/jump_table_error_sites.csv"
        ),
    ),
    ToolSpec(
        key="dyninst",
        display="Dyninst",
        results=Path("/mnt/nvme1/sba/experiment/dyninst/jt_results"),
        physical_json=Path(
            "/mnt/nvme1/sba/reports/paper_artifacts/"
            "current_gt_baseline_compare/dyninst.json"
        ),
        physical_errors=Path(
            "/mnt/nvme1/sba/experiment/dyninst/jump_table_error_sites.csv"
        ),
    ),
    ToolSpec(
        key="sja",
        display="SJA",
        results=Path("/mnt/nvme1/sba/experiment/sja/jt_results"),
        physical_json=Path(
            "/mnt/nvme1/sba/reports/paper_artifacts/"
            "current_gt_baseline_compare/sja.json"
        ),
        physical_errors=Path(
            "/mnt/nvme1/sba/experiment/sja/jump_table_error_sites.csv"
        ),
    ),
)
TOOL_BY_KEY = {tool.key: tool for tool in TOOLS}
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
    "detected_count",
    "physical_truth_targets_sha256",
    "detected_targets_sha256",
    "refined_in_t_feas",
    "refined_analysis_action",
    "refined_analysis_status",
    "refined_proof_mode",
    "refined_reason",
    "refined_truth_count",
    "refined_truth_targets_sha256",
    "refined_missing_count",
    "refined_extra_count",
    "truth_target_set_changed",
    "refined_outcome",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_targets(value: str | None) -> set[int]:
    if not value:
        return set()
    return {int(token, 0) for token in value.split(",") if token.strip()}


def target_hash(targets: Iterable[int]) -> str:
    canonical = ",".join(f"0x{target:x}" for target in sorted(set(targets)))
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as source:
        return json.load(source)


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def score_tool(
    tool: ToolSpec,
    comparator: Path,
    refined_root: Path,
    output_root: Path,
    force: bool,
) -> dict:
    output = output_root / "scores" / "T_feas" / f"{tool.key}.json"
    log = output_root / "logs" / f"score_T_feas_{tool.key}.log"
    if output.is_file() and not force:
        return {"tool": tool.key, "status": "reused", "elapsed_seconds": 0.0}
    output.parent.mkdir(parents=True, exist_ok=True)
    log.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp")
    command = [
        sys.executable,
        str(comparator),
        str(tool.results),
        "--dataset-root",
        str(refined_root),
        "--site-filter",
        "jumps-only",
        "--json",
    ]
    environment = os.environ.copy()
    environment["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"
    started = time.monotonic()
    with temporary.open("w", encoding="utf-8") as stdout, log.open(
        "w", encoding="utf-8"
    ) as stderr:
        stderr.write("$ " + " ".join(command) + "\n")
        stderr.flush()
        process = subprocess.run(
            command,
            cwd=REPO_ROOT,
            env=environment,
            stdout=stdout,
            stderr=stderr,
            text=True,
        )
    elapsed = time.monotonic() - started
    if process.returncode != 0:
        raise RuntimeError(
            f"T_feas scoring failed for {tool.key}; see {log}"
        )
    payload = load_json(temporary)
    if "aggregate" not in payload or "results" not in payload:
        raise RuntimeError(f"comparator output is incomplete for {tool.key}")
    temporary.replace(output)
    return {
        "tool": tool.key,
        "status": "created",
        "elapsed_seconds": elapsed,
        "path": str(output),
    }


def load_sidecar(
    refined_root: Path, binary_relpath: str
) -> tuple[Path, dict[int, dict]]:
    relative = Path(binary_relpath)
    stem = relative.name[:-6]
    sidecar = refined_root / relative.parent / f"gtBlock_{stem}.pb.jumptables.json"
    payload = load_json(sidecar)
    sites = {int(site["site"]): site for site in payload.get("sites", [])}
    return sidecar, sites


def physical_error_counts(score: dict) -> Counter:
    aggregate = score["aggregate"]
    return Counter(
        {
            "false_positive": aggregate["false_positive"],
            "false_negative": aggregate["false_negative"],
            "wrong_successors": aggregate["wrong_successors"],
        }
    )


def physical_error_set(score: dict) -> set[tuple[str, int, str]]:
    marker = "x86_dataset_stripped_x64_ground_truth/"
    errors: set[tuple[str, int, str]] = set()
    for result in score["results"]:
        binary_text = str(result["binary"]).replace("\\", "/")
        if marker not in binary_text:
            raise RuntimeError(f"cannot derive physical relpath: {binary_text}")
        binary_relpath = binary_text.split(marker, 1)[1]
        errors.update(
            (binary_relpath, int(site, 0), "false_positive")
            for site in result["false_positive"]
        )
        errors.update(
            (binary_relpath, int(site, 0), "false_negative")
            for site in result["false_negative"]
        )
        errors.update(
            (
                binary_relpath,
                int(wrong["site"], 0),
                "wrong_successors",
            )
            for wrong in result["wrong_successors"]
        )
    return errors


def is_materialized_table_site(site: dict) -> bool:
    return bool(site.get("previously_jump_table")) or site.get("action") in {
        "confirmed",
        "refined",
        "preserved_physical_table",
    }


def materialized_targets(site: dict) -> set[int]:
    targets = site.get("targets")
    if targets is None:
        targets = site.get("previous_targets", [])
    return {int(target) for target in targets}


def audit_tool(
    tool: ToolSpec,
    refined_root: Path,
    output_root: Path,
) -> tuple[list[dict], dict]:
    with tool.physical_errors.open(newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))
    score = load_json(tool.physical_json)
    expected = physical_error_counts(score)
    actual = Counter(row["category"] for row in rows)
    if expected != actual:
        raise RuntimeError(
            f"{tool.key} physical error ledger disagrees with score: "
            f"ledger={dict(actual)} score={dict(expected)}"
        )
    ledger_set = {
        (
            row["binary_relpath"],
            int(row["site_va"], 0),
            row["category"],
        )
        for row in rows
    }
    if ledger_set != physical_error_set(score):
        raise RuntimeError(
            f"{tool.key} physical error ledger rows disagree with the score"
        )

    audited: list[dict] = []
    current_binary = None
    sidecar_sites: dict[int, dict] = {}
    for row in rows:
        binary_relpath = row["binary_relpath"]
        if binary_relpath != current_binary:
            _, sidecar_sites = load_sidecar(refined_root, binary_relpath)
            current_binary = binary_relpath
        site = int(row["site_va"], 0)
        physical_truth = parse_targets(row.get("truth_targets"))
        detected = parse_targets(row.get("detected_targets"))
        analysis_site = sidecar_sites.get(site)
        refined_site = (
            analysis_site
            if analysis_site is not None and is_materialized_table_site(analysis_site)
            else None
        )
        refined_truth = (
            materialized_targets(refined_site)
            if refined_site is not None
            else None
        )
        refined_missing = (
            sorted(refined_truth - detected) if refined_truth is not None else []
        )
        refined_extra = (
            sorted(detected - refined_truth) if refined_truth is not None else []
        )
        if refined_truth is None:
            if not detected:
                outcome = "resolved_by_clean_room_refinement_site_removed"
            else:
                outcome = "confirmed_false_positive"
        elif not detected:
            outcome = "confirmed_false_negative"
        elif detected == refined_truth:
            outcome = "resolved_by_clean_room_refinement"
        else:
            outcome = "confirmed_wrong_successors"
        truth_changed = refined_truth is None or physical_truth != refined_truth
        audited.append(
            {
                "tool": tool.display,
                "binary_relpath": binary_relpath,
                "site_va": f"0x{site:x}",
                "physical_category": row["category"],
                "physical_truth_count": len(physical_truth),
                "detected_count": len(detected),
                "physical_truth_targets_sha256": target_hash(physical_truth),
                "detected_targets_sha256": target_hash(detected),
                "refined_in_t_feas": "yes" if refined_site is not None else "no",
                "refined_analysis_action": (
                    analysis_site.get("action", "") if analysis_site else ""
                ),
                "refined_analysis_status": (
                    analysis_site.get("status", "") if analysis_site else ""
                ),
                "refined_proof_mode": (
                    analysis_site.get("proof_mode", "") if analysis_site else ""
                ),
                "refined_reason": (
                    analysis_site.get("reason", "") if analysis_site else ""
                ),
                "refined_truth_count": (
                    len(refined_truth) if refined_truth is not None else 0
                ),
                "refined_truth_targets_sha256": (
                    target_hash(refined_truth)
                    if refined_truth is not None
                    else target_hash([])
                ),
                "refined_missing_count": len(refined_missing),
                "refined_extra_count": len(refined_extra),
                "truth_target_set_changed": "yes" if truth_changed else "no",
                "refined_outcome": outcome,
            }
        )
    summary = {
        "tool": tool.display,
        "physical_incorrect_rows": len(rows),
        "physical_category_counts": dict(sorted(actual.items())),
        "audit_outcome_counts": dict(
            sorted(Counter(row["refined_outcome"] for row in audited).items())
        ),
        "truth_target_set_changed_rows": sum(
            row["truth_target_set_changed"] == "yes" for row in audited
        ),
    }
    return audited, summary


def write_csv(path: Path, rows: list[dict], fieldnames: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=list(fieldnames))
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def verify_refinement(
    manifest: Path,
    refined_root: Path,
    physical_root: Path,
    comparator: Path,
) -> dict:
    comparator_directory = str(comparator.parent)
    if comparator_directory not in sys.path:
        sys.path.insert(0, comparator_directory)
    import compare_jump_table_results as comparator_module

    with manifest.open(newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))
    failures = [row for row in rows if row["status"] == "failed"]
    missing = [
        row["relative_path"]
        for row in rows
        if not Path(row["output"]).is_file() or not Path(row["report"]).is_file()
    ]
    if failures or missing:
        raise RuntimeError(
            f"refinement incomplete: failed={len(failures)} missing={len(missing)}"
        )

    generator_hashes: dict[str, str] = {}
    binary_hash_mismatches = 0
    protobuf_hash_mismatches = 0
    target_set_mismatches = 0
    action_counts: Counter = Counter()
    status_counts: Counter = Counter()
    analysis_sites = 0
    refined_type7_sites = 0
    for row in rows:
        sidecar = load_json(Path(row["report"]))
        if not generator_hashes:
            generator_hashes = sidecar["generator_sha256"]
        elif sidecar["generator_sha256"] != generator_hashes:
            raise RuntimeError("generator hashes differ between refinement sidecars")
        binary = Path(row["binary"])
        output = Path(row["output"])
        if sha256_file(binary) != sidecar["binary_sha256"]:
            binary_hash_mismatches += 1
        if sha256_file(output) != sidecar["protobuf_sha256"]:
            protobuf_hash_mismatches += 1
        sites = sidecar.get("sites", [])
        sidecar_truth = {
            int(site["site"]): materialized_targets(site)
            for site in sites
            if is_materialized_table_site(site)
        }
        protobuf_truth = comparator_module.load_ground_truth_tables(output, 7)
        if sidecar_truth != protobuf_truth:
            target_set_mismatches += 1
        analysis_sites += len(sites)
        refined_type7_sites += len(sidecar_truth)
        action_counts.update(site.get("action", "") for site in sites)
        status_counts.update(site.get("status", "") for site in sites)
    if binary_hash_mismatches or protobuf_hash_mismatches or target_set_mismatches:
        raise RuntimeError(
            "refined sidecar hash mismatch: "
            f"binaries={binary_hash_mismatches} "
            f"protobufs={protobuf_hash_mismatches} "
            f"target_sets={target_set_mismatches}"
        )

    current_generator_hashes = {
        name: sha256_file(REPO_ROOT / relative)
        for name, relative in {
            "BlockUtil.py": "extract_gt/BlockUtil.py",
            "ccr/reorderInfo.py": "ccr/reorderInfo.py",
            "extractBB.py": "extract_gt/extractBB.py",
            "jump_table_analysis.py": "extract_gt/jump_table_analysis.py",
            "jump_table_constants.py": "extract_gt/jump_table_constants.py",
            "jump_table_data_invariants.py": (
                "extract_gt/jump_table_data_invariants.py"
            ),
            "jump_table_dataflow.py": "extract_gt/jump_table_dataflow.py",
            "jump_table_gt.py": "extract_gt/jump_table_gt.py",
            "jump_table_loop_invariants.py": (
                "extract_gt/jump_table_loop_invariants.py"
            ),
            "jump_table_proofs.py": "extract_gt/jump_table_proofs.py",
            "jump_table_reaching.py": "extract_gt/jump_table_reaching.py",
            "jump_table_source.py": "extract_gt/jump_table_source.py",
        }.items()
    }
    if generator_hashes != current_generator_hashes:
        raise RuntimeError("refinement generator hashes do not match the checkout")
    return {
        "manifest": str(manifest),
        "manifest_sha256": sha256_file(manifest),
        "files": len(rows),
        "created": sum(row["status"] == "created" for row in rows),
        "reused": sum(row["status"] == "reused" for row in rows),
        "failed": len(failures),
        "missing_outputs": len(missing),
        "binary_hash_mismatches": binary_hash_mismatches,
        "protobuf_hash_mismatches": protobuf_hash_mismatches,
        "target_set_mismatches": target_set_mismatches,
        "analysis_sites": analysis_sites,
        "refined_type7_sites": refined_type7_sites,
        "site_action_counts": dict(sorted(action_counts.items())),
        "site_status_counts": dict(sorted(status_counts.items())),
        "generator_sha256": generator_hashes,
        "comparator": str(comparator),
        "comparator_sha256": sha256_file(comparator),
        "physical_root": str(physical_root),
        "refined_root": str(refined_root),
    }


def metric_row(tool: ToolSpec, gt_label: str, score: dict) -> dict:
    aggregate = score["aggregate"]
    row = {"tool": tool.display, "ground_truth": gt_label}
    row.update({key: int(aggregate.get(key, 0)) for key in METRIC_KEYS})
    detected = row["detected_total"]
    truth = row["truth_total"]
    exact = row["exact_matches"]
    row["precision"] = exact / detected if detected else 0.0
    row["recall"] = exact / truth if truth else 0.0
    return row


def validate_scores(scores: dict[str, dict[str, dict]]) -> None:
    for gt_label, tool_scores in scores.items():
        truth_totals = set()
        for tool_key, score in tool_scores.items():
            aggregate = score["aggregate"]
            if int(aggregate["files"]) != len(score["results"]):
                raise RuntimeError(
                    f"{gt_label}/{tool_key} file count disagrees with detail rows"
                )
            if int(aggregate["files"]) != 2026:
                raise RuntimeError(
                    f"{gt_label}/{tool_key} scored {aggregate['files']} files, "
                    "expected 2026"
                )
            truth_totals.add(int(aggregate["truth_total"]))
        if len(truth_totals) != 1:
            raise RuntimeError(
                f"{gt_label} truth totals differ across tools: {truth_totals}"
            )


def write_summary(
    output_root: Path,
    scores: dict[str, dict[str, dict]],
    audit_summaries: dict[str, dict],
    verification: dict,
    tools: Iterable[ToolSpec],
) -> None:
    tools = tuple(tools)
    metrics = []
    for tool in tools:
        metrics.append(metric_row(tool, "T_phys", scores["T_phys"][tool.key]))
        metrics.append(metric_row(tool, "T_feas", scores["T_feas"][tool.key]))
    write_csv(
        output_root / "tool_metrics.csv",
        metrics,
        (
            "tool",
            "ground_truth",
            *METRIC_KEYS,
            "precision",
            "recall",
        ),
    )
    report = {
        "protocol": (
            "The unchanged positive jump-only comparator scores each tool "
            "against T_phys and T_feas. Every T_phys incorrect row is then "
            "re-evaluated against the hash-bound T_feas protobuf and its "
            "extract_gt jump-table sidecar."
        ),
        "paper_sentence": (
            "Every discrepancy between any evaluated tool and x86-sok was "
            "audited under the identical protocol: the same frozen physical "
            "truth, the same hash-bound clean-room refinement, and the same "
            "extract_gt jump-table validator."
        ),
        "refinement_verification": verification,
        "metrics": metrics,
        "physical_error_audits": audit_summaries,
        "expected_row_counts": {"idapro": 200, "sja": 2507},
        "overall_passed": (
            audit_summaries.get("idapro", {}).get("physical_incorrect_rows") == 200
            and audit_summaries.get("sja", {}).get("physical_incorrect_rows")
            == 2507
        ),
    }
    write_json(output_root / "summary.json", report)

    lines = [
        "# Corpus 1 Symmetric Audit",
        "",
        report["protocol"],
        "",
        report["paper_sentence"],
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
            "## Physical Error-Row Audit",
            "",
            "| Tool | T_phys errors | Truth changed | Resolved | Confirmed |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for tool in tools:
        summary = audit_summaries[tool.key]
        outcome_counts = summary["audit_outcome_counts"]
        resolved = sum(
            count
            for outcome, count in outcome_counts.items()
            if outcome.startswith("resolved_")
        )
        confirmed = sum(
            count
            for outcome, count in outcome_counts.items()
            if outcome.startswith("confirmed_")
        )
        lines.append(
            f"| {tool.display} | {summary['physical_incorrect_rows']} | "
            f"{summary['truth_target_set_changed_rows']} | {resolved} | "
            f"{confirmed} |"
        )
    lines.extend(
        [
            "",
            "## Evidence Integrity",
            "",
            f"- Refined files verified: `{verification['files']}`.",
            f"- Analyzed indirect-jump sites: `{verification['analysis_sites']}`.",
            f"- Materialized type-7 truth sites: "
            f"`{verification['refined_type7_sites']}`.",
            f"- Binary hash mismatches: `{verification['binary_hash_mismatches']}`.",
            f"- Protobuf hash mismatches: `{verification['protobuf_hash_mismatches']}`.",
            f"- Sidecar/type-7 target-set mismatches: "
            f"`{verification['target_set_mismatches']}`.",
            f"- Comparator SHA-256: `{verification['comparator_sha256']}`.",
            f"- Refinement manifest SHA-256: `{verification['manifest_sha256']}`.",
            "",
            "The exact IDA 200-row and SJA 2,507-row ledgers are written as "
            "`audit_idapro_200.csv` and `audit_sja_2507.csv`. A combined ledger "
            "contains every physical discrepancy for all six tools.",
        ]
    )
    (output_root / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--physical-root", type=Path, default=DEFAULT_PHYSICAL_ROOT)
    parser.add_argument("--refined-root", type=Path, default=DEFAULT_REFINED_ROOT)
    parser.add_argument("--comparator", type=Path, default=DEFAULT_COMPARATOR)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument(
        "--manifest",
        type=Path,
        help="Defaults to <refined-root>/refinement_manifest.csv.",
    )
    parser.add_argument(
        "--tools",
        nargs="+",
        choices=tuple(tool.key for tool in TOOLS),
        default=[tool.key for tool in TOOLS],
    )
    parser.add_argument("--score-jobs", type=int, default=3)
    parser.add_argument("--force-score", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    physical_root = args.physical_root.resolve()
    refined_root = args.refined_root.resolve()
    comparator = args.comparator.resolve()
    output_root = args.output_root.resolve()
    manifest = (
        args.manifest.resolve()
        if args.manifest
        else refined_root / "refinement_manifest.csv"
    )
    selected = [TOOL_BY_KEY[key] for key in args.tools]
    if args.score_jobs < 1:
        raise SystemExit("--score-jobs must be positive")

    verification = verify_refinement(
        manifest, refined_root, physical_root, comparator
    )
    score_outcomes = []
    with ThreadPoolExecutor(max_workers=args.score_jobs) as executor:
        futures = {
            executor.submit(
                score_tool,
                tool,
                comparator,
                refined_root,
                output_root,
                args.force_score,
            ): tool
            for tool in selected
        }
        for future in as_completed(futures):
            outcome = future.result()
            score_outcomes.append(outcome)
            print(
                f"{outcome['tool']} T_feas score {outcome['status']} "
                f"in {outcome['elapsed_seconds']:.1f}s",
                flush=True,
            )

    scores = {"T_phys": {}, "T_feas": {}}
    all_audited = []
    audit_summaries = {}
    for tool in selected:
        scores["T_phys"][tool.key] = load_json(tool.physical_json)
        scores["T_feas"][tool.key] = load_json(
            output_root / "scores" / "T_feas" / f"{tool.key}.json"
        )
        audited, summary = audit_tool(tool, refined_root, output_root)
        audit_summaries[tool.key] = summary
        all_audited.extend(audited)
        suffix = {
            "idapro": "200",
            "sja": "2507",
        }.get(tool.key, str(len(audited)))
        write_csv(
            output_root / f"audit_{tool.key}_{suffix}.csv",
            audited,
            AUDIT_FIELDS,
        )
    validate_scores(scores)
    write_csv(
        output_root / "all_tool_discrepancy_audit.csv",
        all_audited,
        AUDIT_FIELDS,
    )
    write_summary(output_root, scores, audit_summaries, verification, selected)
    if (
        "idapro" in audit_summaries
        and audit_summaries["idapro"]["physical_incorrect_rows"] != 200
    ):
        raise RuntimeError("IDA physical error ledger is not the expected 200 rows")
    if (
        "sja" in audit_summaries
        and audit_summaries["sja"]["physical_incorrect_rows"] != 2507
    ):
        raise RuntimeError("SJA physical error ledger is not the expected 2,507 rows")
    print(
        f"symmetric audit written to {output_root}; "
        f"IDA rows={audit_summaries['idapro']['physical_incorrect_rows']} "
        f"SJA rows={audit_summaries['sja']['physical_incorrect_rows']}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
