#!/usr/bin/env python3
"""Refine the frozen x86-sok protobuf corpus with the clean-room analyzer."""

from __future__ import annotations

import argparse
import csv
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Sequence, TextIO


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET_ROOT = Path(
    "/mnt/nvme1/sba/x86_dataset_stripped_x64_ground_truth"
)
DEFAULT_OUTPUT_ROOT = Path("/mnt/nvme1/sba/tmp/x86-sok-corpus1-refined")
DEFAULT_REFINER = REPO_ROOT / "extract_gt" / "jump_table_gt.py"
HEAVY_BINARY_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class Task:
    binary: Path
    ground_truth: Path
    relative_path: Path
    output: Path
    report: Path
    log: Path

    @property
    def shadow_binary(self) -> Path:
        return self.output.parent / self.binary.name


@dataclass(frozen=True)
class Outcome:
    task: Task
    status: str
    elapsed_seconds: float
    returncode: int | None = None
    detail: str = ""


def discover_tasks(
    dataset_root: Path, output_root: Path, limit: int | None
) -> list[Task]:
    tasks: list[Task] = []
    for binary in sorted(dataset_root.rglob("*.strip")):
        ground_truth = binary.parent / f"gtBlock_{binary.name[:-6]}.pb"
        if not ground_truth.is_file():
            continue
        relative_path = binary.relative_to(dataset_root)
        output = output_root / relative_path.parent / ground_truth.name
        tasks.append(
            Task(
                binary=binary.resolve(),
                ground_truth=ground_truth.resolve(),
                relative_path=relative_path,
                output=output,
                report=Path(f"{output}.jumptables.json"),
                log=output_root / "logs" / relative_path.parent / f"{binary.name}.log",
            )
        )
    if limit is not None:
        tasks = tasks[:limit]
    return tasks


def prepare_shadow_tree(task: Task) -> None:
    task.output.parent.mkdir(parents=True, exist_ok=True)
    task.log.parent.mkdir(parents=True, exist_ok=True)
    if task.shadow_binary.is_symlink():
        if task.shadow_binary.resolve() != task.binary:
            task.shadow_binary.unlink()
            task.shadow_binary.symlink_to(task.binary)
    elif not task.shadow_binary.exists():
        task.shadow_binary.symlink_to(task.binary)
    else:
        raise RuntimeError(f"shadow binary is not a symlink: {task.shadow_binary}")


def run_task(task: Task, refiner: Path, force: bool) -> Outcome:
    prepare_shadow_tree(task)
    if not force and task.output.is_file() and task.report.is_file():
        return Outcome(task=task, status="reused", elapsed_seconds=0.0)

    command = [
        sys.executable,
        str(refiner),
        "-b",
        str(task.binary),
        "-g",
        str(task.ground_truth),
        "-o",
        str(task.output),
        "--jump-table-report",
        str(task.report),
    ]
    environment = os.environ.copy()
    environment["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"
    environment.setdefault("PYTHONHASHSEED", "0")
    started = time.monotonic()
    with task.log.open("w", encoding="utf-8") as log:
        log.write("$ " + " ".join(command) + "\n")
        log.flush()
        process = subprocess.run(
            command,
            cwd=REPO_ROOT,
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )
    elapsed = time.monotonic() - started
    if process.returncode == 0 and task.output.is_file() and task.report.is_file():
        return Outcome(
            task=task,
            status="created",
            elapsed_seconds=elapsed,
            returncode=process.returncode,
        )
    return Outcome(
        task=task,
        status="failed",
        elapsed_seconds=elapsed,
        returncode=process.returncode,
        detail=f"see {task.log}",
    )


def run_pool(
    tasks: Sequence[Task],
    refiner: Path,
    jobs: int,
    force: bool,
    writer: csv.DictWriter,
    manifest_file: TextIO,
    write_lock: Lock,
) -> list[Outcome]:
    outcomes: list[Outcome] = []
    total = len(tasks)
    completed = 0
    with ThreadPoolExecutor(max_workers=jobs) as executor:
        futures = {
            executor.submit(run_task, task, refiner, force): task for task in tasks
        }
        for future in as_completed(futures):
            outcome = future.result()
            outcomes.append(outcome)
            completed += 1
            with write_lock:
                writer.writerow(
                    {
                        "relative_path": outcome.task.relative_path.as_posix(),
                        "status": outcome.status,
                        "elapsed_seconds": f"{outcome.elapsed_seconds:.6f}",
                        "returncode": outcome.returncode or "",
                        "detail": outcome.detail,
                        "binary": outcome.task.binary,
                        "ground_truth": outcome.task.ground_truth,
                        "output": outcome.task.output,
                        "report": outcome.task.report,
                        "log": outcome.task.log,
                    }
                )
                manifest_file.flush()
            if completed % 25 == 0 or completed == total:
                print(
                    f"progress {completed}/{total}; "
                    f"elapsed={sum(item.elapsed_seconds for item in outcomes):.1f}s",
                    flush=True,
                )
    return outcomes


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-root", type=Path, default=DEFAULT_DATASET_ROOT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--refiner", type=Path, default=DEFAULT_REFINER)
    parser.add_argument("--jobs", type=int, default=10)
    parser.add_argument("--heavy-jobs", type=int, default=2)
    parser.add_argument(
        "--manifest",
        type=Path,
        help="Defaults to <output-root>/refinement_manifest.csv.",
    )
    parser.add_argument("--limit", type=int)
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    dataset_root = args.dataset_root.resolve()
    output_root = args.output_root.resolve()
    refiner = args.refiner.resolve()
    manifest = (
        args.manifest.resolve()
        if args.manifest
        else output_root / "refinement_manifest.csv"
    )
    if not dataset_root.is_dir():
        raise SystemExit(f"dataset root does not exist: {dataset_root}")
    if not refiner.is_file():
        raise SystemExit(f"refiner does not exist: {refiner}")
    if args.jobs < 1 or args.heavy_jobs < 1:
        raise SystemExit("job counts must be positive")

    tasks = discover_tasks(dataset_root, output_root, args.limit)
    if not tasks:
        raise SystemExit("no matching *.strip and gtBlock_*.pb pairs found")
    normal = [task for task in tasks if task.binary.stat().st_size < HEAVY_BINARY_BYTES]
    heavy = [task for task in tasks if task.binary.stat().st_size >= HEAVY_BINARY_BYTES]
    output_root.mkdir(parents=True, exist_ok=True)
    manifest.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "relative_path",
        "status",
        "elapsed_seconds",
        "returncode",
        "detail",
        "binary",
        "ground_truth",
        "output",
        "report",
        "log",
    ]
    outcomes: list[Outcome] = []
    with manifest.open("w", newline="", encoding="utf-8") as manifest_file:
        writer = csv.DictWriter(manifest_file, fieldnames=fieldnames)
        writer.writeheader()
        write_lock = Lock()
        if normal:
            outcomes.extend(
                run_pool(
                    normal,
                    refiner,
                    args.jobs,
                    args.force,
                    writer,
                    manifest_file,
                    write_lock,
                )
            )
        if heavy:
            outcomes.extend(
                run_pool(
                    heavy,
                    refiner,
                    args.heavy_jobs,
                    args.force,
                    writer,
                    manifest_file,
                    write_lock,
                )
            )

    created = sum(item.status == "created" for item in outcomes)
    reused = sum(item.status == "reused" for item in outcomes)
    failed = [item for item in outcomes if item.status == "failed"]
    print(
        f"Corpus 1 refinement: total={len(outcomes)} created={created} "
        f"reused={reused} failed={len(failed)}",
        flush=True,
    )
    for outcome in failed:
        print(
            f"FAILED {outcome.task.relative_path} returncode={outcome.returncode} "
            f"{outcome.detail}",
            file=sys.stderr,
        )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
