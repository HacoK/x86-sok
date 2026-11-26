#!/usr/bin/env python3
"""Publish physical and guarded-feasible Corpus 1 oracle layers.

T_phys keeps the accepted physical site inventory, including audited
computed-goto and other omitted sites. For sites present in the frozen compiler
protobuf, its target set is restored to the compiler/linker physical entries.
T_feas may only remove targets from that physical set.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
EXTRACT_GT = REPO_ROOT / "extract_gt"
PROTOBUF_DEF = REPO_ROOT / "protobuf_def"
for search_path in (REPO_ROOT, EXTRACT_GT, PROTOBUF_DEF):
    if str(search_path) not in sys.path:
        sys.path.insert(0, str(search_path))

import deps  # noqa: E402,F401
import blocks_pb2  # noqa: E402


DEFAULT_STRIPPED_ROOT = Path(
    "/mnt/nvme1/sba/x86_dataset_stripped_x64_ground_truth"
)
DEFAULT_ACCEPTED_ROOT = DEFAULT_STRIPPED_ROOT
DEFAULT_UPSTREAM_ROOT = Path("/mnt/nvme1/sba/x86_dataset/linux")
DEFAULT_OPENSSL_ROOT = Path("/mnt/nvme1/sba/x86_dataset/openssl-1.1.0l_execs")
DEFAULT_GUARDED_ROOT = Path("/mnt/nvme1/sba/tmp/x86-sok-corpus1-refined")
DEFAULT_OUTPUT_ROOT = Path("/mnt/nvme1/sba/tmp/x86-sok-corpus1-two-layer-v2")


@dataclass(frozen=True)
class Task:
    relative_binary: Path
    binary: Path
    accepted_protobuf: Path
    upstream_protobuf: Path
    guarded_sidecar: Path
    physical_protobuf: Path
    physical_sidecar: Path
    feasible_protobuf: Path
    feasible_sidecar: Path
    log: Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def upstream_protobuf_for(
    relative_binary: Path, upstream_root: Path, openssl_root: Path
) -> Path:
    if relative_binary.parts[0] == "openssl-1.1.0":
        name = relative_binary.name
        prefix = "openssl_gcc_"
        if not name.startswith(prefix) or not name.endswith(".strip"):
            raise ValueError(f"unexpected OpenSSL Corpus 1 name: {relative_binary}")
        optimization = name[len(prefix) : -len(".strip")]
        return openssl_root / f"gtBlock_openssl_{optimization}.pb"

    relative_directory = relative_binary.parent
    source_directory = Path(
        *[
            part[: -len("_strip")] if part.endswith("_strip") else part
            for part in relative_directory.parts
        ]
    )
    stem = relative_binary.name[: -len(".strip")]
    return upstream_root / source_directory / f"gtBlock_{stem}.pb"


def discover_tasks(
    stripped_root: Path,
    accepted_root: Path,
    upstream_root: Path,
    openssl_root: Path,
    guarded_root: Path,
    output_root: Path,
) -> list[Task]:
    tasks = []
    missing = []
    for binary in sorted(stripped_root.rglob("*.strip")):
        relative_binary = binary.relative_to(stripped_root)
        stem = relative_binary.name[: -len(".strip")]
        accepted_protobuf = accepted_root / relative_binary.parent / f"gtBlock_{stem}.pb"
        upstream_protobuf = upstream_protobuf_for(
            relative_binary, upstream_root, openssl_root
        )
        guarded_sidecar = (
            guarded_root
            / relative_binary.parent
            / f"gtBlock_{stem}.pb.jumptables.json"
        )
        if not accepted_protobuf.is_file():
            missing.append((relative_binary, accepted_protobuf))
            continue
        if not upstream_protobuf.is_file():
            missing.append((relative_binary, upstream_protobuf))
            continue
        if not guarded_sidecar.is_file():
            missing.append((relative_binary, guarded_sidecar))
            continue
        tasks.append(
            Task(
                relative_binary=relative_binary,
                binary=binary.resolve(),
                accepted_protobuf=accepted_protobuf.resolve(),
                upstream_protobuf=upstream_protobuf.resolve(),
                guarded_sidecar=guarded_sidecar.resolve(),
                physical_protobuf=(
                    output_root / "T_phys" / relative_binary.parent / f"gtBlock_{stem}.pb"
                ),
                physical_sidecar=(
                    output_root
                    / "T_phys"
                    / relative_binary.parent
                    / f"gtBlock_{stem}.pb.oracle-layer.json"
                ),
                feasible_protobuf=(
                    output_root / "T_feas" / relative_binary.parent / f"gtBlock_{stem}.pb"
                ),
                feasible_sidecar=(
                    output_root
                    / "T_feas"
                    / relative_binary.parent
                    / f"gtBlock_{stem}.pb.oracle-layers.json"
                ),
                log=(
                    output_root
                    / "logs"
                    / relative_binary.parent
                    / f"{relative_binary.name}.log"
                ),
            )
        )
    if missing:
        preview = ", ".join(str(item[0]) for item in missing[:5])
        raise FileNotFoundError(f"missing {len(missing)} provenance inputs: {preview}")
    return tasks


def ensure_symlink(link: Path, target: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    if link.is_symlink():
        if link.resolve() != target.resolve():
            link.unlink()
            link.symlink_to(target)
    elif not link.exists():
        link.symlink_to(target)
    else:
        raise RuntimeError(f"expected symlink path: {link}")


def replace_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as output:
        output.write(data)
    temporary.replace(path)


def replace_json(path: Path, payload: dict[str, Any]) -> None:
    replace_bytes(
        path,
        (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )


def materialized_targets(site: dict[str, Any]) -> set[int] | None:
    if site.get("status") != "resolved":
        return None
    targets = site.get("targets")
    if targets is None:
        return None
    return {int(target) for target in targets}


def build_layers(task_data: dict[str, str]) -> dict[str, Any]:
    task = Task(
        relative_binary=Path(task_data["relative_binary"]),
        binary=Path(task_data["binary"]),
        accepted_protobuf=Path(task_data["accepted_protobuf"]),
        upstream_protobuf=Path(task_data["upstream_protobuf"]),
        guarded_sidecar=Path(task_data["guarded_sidecar"]),
        physical_protobuf=Path(task_data["physical_protobuf"]),
        physical_sidecar=Path(task_data["physical_sidecar"]),
        feasible_protobuf=Path(task_data["feasible_protobuf"]),
        feasible_sidecar=Path(task_data["feasible_sidecar"]),
        log=Path(task_data["log"]),
    )
    task.log.parent.mkdir(parents=True, exist_ok=True)
    with task.log.open("w", encoding="utf-8") as log:
        log.write(f"binary={task.binary}\n")
        log.write(f"accepted_protobuf={task.accepted_protobuf}\n")
        log.write(f"upstream_protobuf={task.upstream_protobuf}\n")
        log.write(f"guarded_sidecar={task.guarded_sidecar}\n")

    module = blocks_pb2.module()
    accepted_bytes = task.accepted_protobuf.read_bytes()
    module.ParseFromString(accepted_bytes)
    upstream_module = blocks_pb2.module()
    upstream_module.ParseFromString(task.upstream_protobuf.read_bytes())
    upstream_tables: dict[int, set[int]] = {}
    for function in upstream_module.fuc:
        for block in function.bb:
            if int(block.type) != 7 or not block.instructions:
                continue
            site = int(block.instructions[-1].va)
            upstream_tables.setdefault(site, set()).update(
                int(child.va) for child in block.child
            )
    guarded = json.loads(task.guarded_sidecar.read_text(encoding="utf-8"))
    guarded_sites = {
        int(site["site"]): site for site in guarded.get("sites", [])
    }

    sites: dict[int, list[Any]] = {}
    malformed = []
    for function in module.fuc:
        for block in function.bb:
            if int(block.type) != 7:
                continue
            if not block.instructions:
                malformed.append(int(block.va))
                continue
            site = int(block.instructions[-1].va)
            sites.setdefault(site, []).append(block)
    if malformed:
        raise ValueError(
            f"{task.relative_binary}: {len(malformed)} jump-table blocks "
            "have no terminating instruction"
        )

    physical_by_site: dict[int, set[int]] = {}
    physical_changes = []
    added_sites = []
    provenance_counts: Counter = Counter()
    restored_target_sets = 0
    for site, blocks in sorted(sites.items()):
        accepted_targets = {
            int(child.va) for block in blocks for child in block.child
        }
        if not accepted_targets:
            raise ValueError(
                f"{task.relative_binary}: accepted site 0x{site:x} has no targets"
            )
        compiler_targets = upstream_tables.get(site)
        if compiler_targets:
            physical_targets = set(compiler_targets)
            provenance = "compiler_linker_physical"
            if physical_targets != accepted_targets:
                restored_target_sets += 1
                physical_changes.append(
                    {
                        "site": site,
                        "action": "restored_compiler_physical_targets",
                        "accepted_target_count": len(accepted_targets),
                        "physical_target_count": len(physical_targets),
                        "accepted_targets": sorted(accepted_targets),
                        "physical_targets": sorted(physical_targets),
                    }
                )
        else:
            physical_targets = set(accepted_targets)
            provenance = "audited_existing_physical_site"
            added_sites.append(
                {
                    "site": site,
                    "target_count": len(physical_targets),
                    "targets": sorted(physical_targets),
                    "provenance": provenance,
                }
            )
        provenance_counts[provenance] += 1
        physical_by_site[site] = physical_targets
        for block in blocks:
            del block.child[:]
            for target in sorted(physical_targets):
                block.child.add().va = target
            block.type = 7

    physical_bytes = module.SerializeToString()
    replace_bytes(task.physical_protobuf, physical_bytes)
    physical_sha256 = hashlib.sha256(physical_bytes).hexdigest()
    physical_target_edges = sum(len(targets) for targets in physical_by_site.values())
    physical_sidecar = {
        "schema_version": 1,
        "analysis_scope": "physical_table_targets",
        "binary_sha256": sha256_file(task.binary),
        "accepted_source_sha256": sha256_file(task.accepted_protobuf),
        "upstream_source_sha256": sha256_file(task.upstream_protobuf),
        "protobuf_sha256": physical_sha256,
        "site_count": len(physical_by_site),
        "target_edges": physical_target_edges,
        "site_provenance_counts": dict(sorted(provenance_counts.items())),
        "restored_compiler_target_sets": restored_target_sets,
        "added_physical_sites": len(added_sites),
        "restored_sites": physical_changes,
        "added_sites": added_sites,
    }
    replace_json(task.physical_sidecar, physical_sidecar)

    changes = []
    actions: Counter = Counter()
    dropped_edges = 0
    feasible_target_edges = 0
    for site, blocks in sorted(sites.items()):
        physical_targets = physical_by_site[site]
        source_site = guarded_sites.get(site)
        guarded_targets = (
            materialized_targets(source_site) if source_site is not None else None
        )
        if guarded_targets is None:
            action = "retained_without_resolved_guard"
            feasible_targets = physical_targets
            dropped = set()
            reason = (
                source_site.get("reason", "")
                if source_site is not None
                else "no independent guarded-successor record"
            )
        else:
            accepted = guarded_targets & physical_targets
            dropped = guarded_targets - physical_targets
            dropped_edges += len(dropped)
            if accepted and accepted != physical_targets:
                action = "guarded_refinement"
                feasible_targets = accepted
            elif accepted == physical_targets:
                action = "guarded_confirmation"
                feasible_targets = physical_targets
            else:
                action = "retained_nonphysical_guard_result"
                feasible_targets = physical_targets
            reason = source_site.get("reason", "")
        actions[action] += 1
        feasible_target_edges += len(feasible_targets)
        if feasible_targets != physical_targets or dropped:
            changes.append(
                {
                    "site": site,
                    "action": action,
                    "physical_target_count": len(physical_targets),
                    "feasible_target_count": len(feasible_targets),
                    "physical_targets": sorted(physical_targets),
                    "feasible_targets": sorted(feasible_targets),
                    "dropped_nonphysical_targets": sorted(dropped),
                    "source_action": (
                        source_site.get("action", "") if source_site is not None else ""
                    ),
                    "source_status": (
                        source_site.get("status", "") if source_site is not None else ""
                    ),
                    "proof_mode": (
                        source_site.get("proof_mode", "")
                        if source_site is not None
                        else ""
                    ),
                    "reason": reason,
                }
            )
        for block in blocks:
            del block.child[:]
            for target in sorted(feasible_targets):
                block.child.add().va = target
            block.type = 7

    feasible_bytes = module.SerializeToString()
    replace_bytes(task.feasible_protobuf, feasible_bytes)
    feasible_sha256 = hashlib.sha256(feasible_bytes).hexdigest()
    binary_sha256 = sha256_file(task.binary)
    guarded_sha256 = sha256_file(task.guarded_sidecar)
    sidecar = {
        "schema_version": 1,
        "analysis_scope": "physical_table_targets_with_guarded_feasible_subset",
        "binary_sha256": binary_sha256,
        "t_phys_sha256": physical_sha256,
        "t_feas_sha256": feasible_sha256,
        "guarded_source_sha256": guarded_sha256,
        "guarded_source": str(task.guarded_sidecar),
        "physical_site_count": len(sites),
        "physical_target_count": physical_target_edges,
        "feasible_target_count": feasible_target_edges,
        "added_physical_sites": len(added_sites),
        "restored_physical_target_sets": restored_target_sets,
        "action_counts": dict(sorted(actions.items())),
        "dropped_nonphysical_edges": dropped_edges,
        "changes": changes,
    }
    replace_json(task.feasible_sidecar, sidecar)
    return {
        "relative_binary": task.relative_binary.as_posix(),
        "binary": str(task.binary),
        "accepted_protobuf": str(task.accepted_protobuf),
        "upstream_protobuf": str(task.upstream_protobuf),
        "physical_protobuf": str(task.physical_protobuf),
        "physical_sidecar": str(task.physical_sidecar),
        "feasible_protobuf": str(task.feasible_protobuf),
        "feasible_sidecar": str(task.feasible_sidecar),
        "binary_sha256": binary_sha256,
        "physical_sha256": physical_sha256,
        "feasible_sha256": feasible_sha256,
        "guarded_sha256": guarded_sha256,
        "sites": len(sites),
        "added_physical_sites": len(added_sites),
        "restored_physical_target_sets": restored_target_sets,
        "physical_target_edges": physical_target_edges,
        "feasible_target_edges": feasible_target_edges,
        "changed_sites": sum(
            change["physical_targets"] != change["feasible_targets"]
            for change in changes
        ),
        "dropped_edges": dropped_edges,
        "action_counts": dict(sorted(actions.items())),
    }


def prepare_binary_links(tasks: list[Task]) -> None:
    for task in tasks:
        ensure_symlink(
            task.physical_protobuf.parent / task.binary.name,
            task.binary,
        )
        ensure_symlink(
            task.feasible_protobuf.parent / task.binary.name,
            task.binary,
        )


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stripped-root", type=Path, default=DEFAULT_STRIPPED_ROOT)
    parser.add_argument("--accepted-root", type=Path, default=DEFAULT_ACCEPTED_ROOT)
    parser.add_argument("--upstream-root", type=Path, default=DEFAULT_UPSTREAM_ROOT)
    parser.add_argument("--openssl-root", type=Path, default=DEFAULT_OPENSSL_ROOT)
    parser.add_argument("--guarded-root", type=Path, default=DEFAULT_GUARDED_ROOT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--limit", type=int)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    stripped_root = args.stripped_root.resolve()
    accepted_root = args.accepted_root.resolve()
    upstream_root = args.upstream_root.resolve()
    openssl_root = args.openssl_root.resolve()
    guarded_root = args.guarded_root.resolve()
    output_root = args.output_root.resolve()
    if args.jobs < 1:
        raise SystemExit("--jobs must be positive")

    tasks = discover_tasks(
        stripped_root,
        accepted_root,
        upstream_root,
        openssl_root,
        guarded_root,
        output_root,
    )
    if args.limit is not None:
        tasks = tasks[: args.limit]
    prepare_binary_links(tasks)
    task_payloads = [
        {
            "relative_binary": task.relative_binary.as_posix(),
            "binary": str(task.binary),
            "accepted_protobuf": str(task.accepted_protobuf),
            "upstream_protobuf": str(task.upstream_protobuf),
            "guarded_sidecar": str(task.guarded_sidecar),
            "physical_protobuf": str(task.physical_protobuf),
            "physical_sidecar": str(task.physical_sidecar),
            "feasible_protobuf": str(task.feasible_protobuf),
            "feasible_sidecar": str(task.feasible_sidecar),
            "log": str(task.log),
        }
        for task in tasks
    ]
    results = []
    with ProcessPoolExecutor(max_workers=args.jobs) as executor:
        futures = {
            executor.submit(build_layers, payload): payload["relative_binary"]
            for payload in task_payloads
        }
        for completed, future in enumerate(as_completed(futures), 1):
            results.append(future.result())
            if completed % 50 == 0 or completed == len(futures):
                print(f"published {completed}/{len(futures)}", flush=True)

    results.sort(key=lambda row: row["relative_binary"])
    layer_fields = [
        "relative_binary",
        "binary",
        "accepted_protobuf",
        "upstream_protobuf",
        "physical_protobuf",
        "physical_sidecar",
        "feasible_protobuf",
        "feasible_sidecar",
        "binary_sha256",
        "physical_sha256",
        "feasible_sha256",
        "guarded_sha256",
        "sites",
        "added_physical_sites",
        "restored_physical_target_sets",
        "physical_target_edges",
        "feasible_target_edges",
        "changed_sites",
        "dropped_edges",
    ]
    write_csv(output_root / "oracle_layer_manifest.csv", results, layer_fields)
    total_sites = sum(row["sites"] for row in results)
    total_physical_edges = sum(row["physical_target_edges"] for row in results)
    total_feasible_edges = sum(row["feasible_target_edges"] for row in results)
    total_changed = sum(row["changed_sites"] for row in results)
    total_dropped = sum(row["dropped_edges"] for row in results)
    total_added = sum(row["added_physical_sites"] for row in results)
    total_restored = sum(row["restored_physical_target_sets"] for row in results)
    action_counts: Counter = Counter()
    for row in results:
        action_counts.update(row["action_counts"])
    summary = {
        "schema_version": 1,
        "definition": {
            "T_phys": (
                "All physically evidenced jump-table site targets: compiler/"
                "linker physical entries for compiler-marked sites, plus "
                "audited existing computed-goto and other omitted physical "
                "sites. Feasibility filtering is not applied."
            ),
            "T_feas": (
                "Guarded site-feasible successors. Each site retains its "
                "T_phys site key and every T_feas target must be a member of "
                "its T_phys target set."
            ),
        },
        "files": len(results),
        "sites": total_sites,
        "physical_target_edges": total_physical_edges,
        "feasible_target_edges": total_feasible_edges,
        "changed_sites": total_changed,
        "added_physical_sites": total_added,
        "restored_physical_target_sets": total_restored,
        "dropped_nonphysical_edges": total_dropped,
        "action_counts": dict(sorted(action_counts.items())),
        "subset_invariant": (
            "enforced by construction; guarded targets are intersected with "
            "T_phys and a site with no accepted target retains T_phys"
        ),
        "manifest": str(output_root / "oracle_layer_manifest.csv"),
    }
    replace_json(output_root / "layer_summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
