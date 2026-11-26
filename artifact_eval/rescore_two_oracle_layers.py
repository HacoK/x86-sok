#!/usr/bin/env python3
"""Rescore only binaries affected by the corrected two-layer oracle split."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_COMPARATOR = Path("/mnt/nvme1/sba/tools/compare_jump_table_results.py")
DEFAULT_LAYER_ROOT = Path("/mnt/nvme1/sba/tmp/x86-sok-corpus1-two-layer-v2")
DEFAULT_OUTPUT_ROOT = REPO_ROOT / "artifact_eval" / "corpus1_two_layer_audit"


@dataclass(frozen=True)
class ToolSpec:
    key: str
    display: str
    results: Path
    physical_base: Path
    feasible_base: Path


TOOLS = (
    ToolSpec(
        key="proofjtr",
        display="ProofJTR",
        results=Path(
            "/mnt/nvme1/sba/reports/ndss_artifacts/"
            "artifact-final-strict/results"
        ),
        physical_base=Path(
            "/mnt/nvme1/sba/reports/ndss_artifacts/"
            "artifact-final-strict/comparison.json"
        ),
        feasible_base=Path(
            "/mnt/nvme1/JPT/x86-sok/artifact_eval/corpus1_audit/"
            "scores/T_feas/proofjtr.json"
        ),
    ),
    ToolSpec(
        key="idapro",
        display="IDA Pro 9.0",
        results=Path("/mnt/nvme1/sba/experiment/idapro/jt_results"),
        physical_base=Path(
            "/mnt/nvme1/sba/reports/paper_artifacts/"
            "current_gt_baseline_compare/idapro.json"
        ),
        feasible_base=Path(
            "/mnt/nvme1/JPT/x86-sok/artifact_eval/corpus1_audit/"
            "scores/T_feas/idapro.json"
        ),
    ),
    ToolSpec(
        key="ghidra",
        display="Ghidra 12",
        results=Path("/mnt/nvme1/sba/experiment/ghidra/jt_results"),
        physical_base=Path(
            "/mnt/nvme1/sba/reports/paper_artifacts/"
            "current_gt_baseline_compare/ghidra.json"
        ),
        feasible_base=Path(
            "/mnt/nvme1/JPT/x86-sok/artifact_eval/corpus1_audit/"
            "scores/T_feas/ghidra.json"
        ),
    ),
    ToolSpec(
        key="angr",
        display="angr",
        results=Path("/mnt/nvme1/sba/experiment/angr/jt_results"),
        physical_base=Path(
            "/mnt/nvme1/sba/reports/paper_artifacts/"
            "current_gt_baseline_compare/angr.json"
        ),
        feasible_base=Path(
            "/mnt/nvme1/JPT/x86-sok/artifact_eval/corpus1_audit/"
            "scores/T_feas/angr.json"
        ),
    ),
    ToolSpec(
        key="dyninst",
        display="Dyninst",
        results=Path("/mnt/nvme1/sba/experiment/dyninst/jt_results"),
        physical_base=Path(
            "/mnt/nvme1/sba/reports/paper_artifacts/"
            "current_gt_baseline_compare/dyninst.json"
        ),
        feasible_base=Path(
            "/mnt/nvme1/JPT/x86-sok/artifact_eval/corpus1_audit/"
            "scores/T_feas/dyninst.json"
        ),
    ),
    ToolSpec(
        key="sja",
        display="SJA",
        results=Path("/mnt/nvme1/sba/experiment/sja/jt_results"),
        physical_base=Path(
            "/mnt/nvme1/sba/reports/paper_artifacts/"
            "current_gt_baseline_compare/sja.json"
        ),
        feasible_base=Path(
            "/mnt/nvme1/JPT/x86-sok/artifact_eval/corpus1_audit/"
            "scores/T_feas/sja.json"
        ),
    ),
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


def relative_binary(result: dict[str, Any]) -> str:
    text = str(result["binary"]).replace("\\", "/")
    markers = (
        "x86_dataset_stripped_x64_ground_truth/",
        "x86-sok-corpus1-refined/",
        "x86-sok-corpus1-two-layer/",
        "x86-sok-corpus1-two-layer-v2/",
    )
    for marker in markers:
        if marker in text:
            return text.split(marker, 1)[1]
    raise ValueError(f"cannot derive Corpus 1 relative path: {text}")


def affected_layers(layer_root: Path) -> tuple[set[str], set[str]]:
    physical_changed = set()
    feasible_changed = set()
    with (layer_root / "oracle_layer_manifest.csv").open(
        newline="", encoding="utf-8"
    ) as source:
        for row in csv.DictReader(source):
            relative = row["relative_binary"]
            if int(row["restored_physical_target_sets"]):
                physical_changed.add(relative)
            if (
                int(row["restored_physical_target_sets"])
                or int(row["changed_sites"])
                or int(row["dropped_edges"])
            ):
                feasible_changed.add(relative)
    return physical_changed, feasible_changed


def score_one(payload: dict[str, str]) -> dict[str, Any]:
    comparator_directory = str(Path(payload["comparator"]).parent)
    if comparator_directory not in sys.path:
        sys.path.insert(0, comparator_directory)
    import compare_jump_table_results as comparator

    result = comparator.compare_task(
        comparator.Task(
            result=Path(payload["result"]),
            binary=Path(payload["binary"]),
            ground_truth=Path(payload["ground_truth"]),
        ),
        comparator.DEFAULT_JUMP_TABLE_BLOCK_TYPE,
        comparator.DEFAULT_SITE_FILTER,
    )
    return {
        "relative_binary": payload["relative_binary"],
        "result": comparator._result_to_dict(result),
    }


def aggregate_results(results: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "files": len(results),
        "truth_total": sum(int(row["truth_total"]) for row in results),
        "detected_total": sum(int(row["detected_total"]) for row in results),
        "exact_matches": sum(int(row["exact_matches"]) for row in results),
        "false_positive": sum(len(row["false_positive"]) for row in results),
        "false_negative": sum(len(row["false_negative"]) for row in results),
        "wrong_successors": sum(len(row["wrong_successors"]) for row in results),
        "parsed_jump_table_bases": sum(
            int(row["parsed_jump_table_bases"]) for row in results
        ),
        "parsed_witnesses": sum(int(row["parsed_witnesses"]) for row in results),
        "witnessed_sites": sum(int(row["witnessed_sites"]) for row in results),
        "complete_witnesses": sum(
            int(row["complete_witnesses"]) for row in results
        ),
        "filtered_non_jump_sites": sum(
            int(row["filtered_non_jump_sites"]) for row in results
        ),
        "filtered_call_sites": sum(
            int(row["filtered_call_sites"]) for row in results
        ),
        "filtered_unknown_sites": sum(
            int(row["filtered_unknown_sites"]) for row in results
        ),
        "address_normalized_files": sum(
            int(str(row["address_normalization_base"]), 0) != 0 for row in results
        ),
        "address_normalized_sites": sum(
            int(row["address_normalized_sites"]) for row in results
        ),
    }


def rescore_tool(
    tool: ToolSpec,
    base_path: Path,
    layer: str,
    affected: set[str],
    layer_root: Path,
    comparator: Path,
    output_root: Path,
    jobs: int,
) -> dict[str, Any]:
    base = load_json(base_path)
    if int(base["aggregate"]["files"]) != 2026:
        raise ValueError(f"{tool.key}/{layer}: base score is not full-corpus")
    result_by_relative = {
        relative_binary(row): row for row in base["results"]
    }
    missing = affected - set(result_by_relative)
    if missing:
        raise ValueError(
            f"{tool.key}/{layer}: {len(missing)} affected results are absent"
        )

    payloads = []
    for relative in sorted(affected):
        ground_truth = (
            layer_root
            / layer
            / Path(relative).parent
            / f"gtBlock_{Path(relative).name[:-6]}.pb"
        )
        payloads.append(
            {
                "relative_binary": relative,
                "result": str(tool.results / f"{relative}.result"),
                "binary": str(layer_root / layer / relative),
                "ground_truth": str(ground_truth),
                "comparator": str(comparator),
            }
        )
    with ProcessPoolExecutor(max_workers=jobs) as executor:
        futures = [executor.submit(score_one, payload) for payload in payloads]
        for future in as_completed(futures):
            scored = future.result()
            result_by_relative[scored["relative_binary"]] = scored["result"]

    results = list(result_by_relative.values())
    aggregate = aggregate_results(results)
    payload = {
        "aggregate": aggregate,
        "results": results,
        "rescore_provenance": {
            "base": str(base_path),
            "ground_truth_layer": layer,
            "rescore_count": len(affected),
            "unchanged_count": len(results) - len(affected),
            "comparator": str(comparator),
        },
    }
    output = output_root / "scores" / layer / f"{tool.key}.json"
    write_json(output, payload)
    return {
        "tool": tool.display,
        "layer": layer,
        "rescore_count": len(affected),
        "aggregate": aggregate,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--layer-root", type=Path, default=DEFAULT_LAYER_ROOT)
    parser.add_argument("--comparator", type=Path, default=DEFAULT_COMPARATOR)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--jobs", type=int, default=8)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    layer_root = args.layer_root.resolve()
    comparator = args.comparator.resolve()
    output_root = args.output_root.resolve()
    if args.jobs < 1:
        raise SystemExit("--jobs must be positive")

    physical_affected, feasible_affected = affected_layers(layer_root)
    print(
        f"affected binaries: T_phys={len(physical_affected)} "
        f"T_feas={len(feasible_affected)}",
        flush=True,
    )

    summaries = []
    for layer, affected in (
        ("T_phys", physical_affected),
        ("T_feas", feasible_affected),
    ):
        for tool in TOOLS:
            base = tool.physical_base if layer == "T_phys" else tool.feasible_base
            summary = rescore_tool(
                tool,
                base,
                layer,
                affected,
                layer_root,
                comparator,
                output_root,
                args.jobs,
            )
            summaries.append(summary)
            print(
                f"{tool.display} {layer}: rescored={summary['rescore_count']} "
                f"exact={summary['aggregate']['exact_matches']}",
                flush=True,
            )
    write_json(
        output_root / "rescore_summary.json",
        {
            "physical_affected_binaries": sorted(physical_affected),
            "feasible_affected_binaries": sorted(feasible_affected),
            "scores": summaries,
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
