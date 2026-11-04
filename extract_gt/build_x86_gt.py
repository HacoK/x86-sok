#!/usr/bin/env python3
"""Build jump-table GT outputs for every x86 ELF in the local dataset."""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
import fcntl
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time


REPOSITORY = Path(__file__).resolve().parents[1]
EXTRACTOR = REPOSITORY / "extract_gt" / "extractBB.py"
DEFAULT_DATASET = Path("/mnt/nvme1/sba/x86_dataset/linux")
DEFAULT_OUTPUT = Path("/mnt/nvme1/JPT/GT")
DEFAULT_MANIFEST = REPOSITORY / "extract_gt" / "source_builds" / "gt_six_builds.json"
X86_MACHINES = {"Advanced Micro Devices X86-64", "Intel 80386"}


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def elf_metadata(path):
    try:
        result = subprocess.run(("readelf", "-h", "-S", str(path)),
                                capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode:
        return None
    text = result.stdout
    machine = re.search(r"^\s*Machine:\s*(.+?)\s*$", text, re.M)
    elf_type = re.search(r"^\s*Type:\s*(.+?)\s*$", text, re.M)
    if not machine or machine.group(1) not in X86_MACHINES:
        return None
    if not elf_type or not elf_type.group(1).split()[0] in {"EXEC", "DYN"}:
        return None
    if not re.search(r"^\s*\[\s*\d+\]\s+\.rand\s+", text, re.M):
        return None
    return {"machine": machine.group(1), "elf_type": elf_type.group(1).split()[0]}


def discover(dataset):
    rows = []
    for path in sorted(dataset.glob("*/*/*")):
        if not path.is_file() or path.is_symlink():
            continue
        executable = path.stat().st_mode & 0o111
        shared_object = path.suffix == ".so" or ".so." in path.name
        if not (executable or shared_object):
            continue
        metadata = elf_metadata(path)
        if metadata is not None:
            rows.append({"binary": path, **metadata})
    return rows


def source_build_hashes(manifest_path):
    if not manifest_path:
        return set()
    manifest = json.loads(Path(manifest_path).read_text())
    return {row["binary_sha256"] for row in manifest.get("builds", [])
            if isinstance(row, dict) and row.get("binary_sha256")}


def append_index(index, row):
    with Path(index).open("a", encoding="utf-8") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        stream.write(json.dumps(row, sort_keys=True) + "\n")
        stream.flush()


def valid_pair(protobuf, report, binary_hash):
    if not protobuf.is_file() or not report.is_file():
        return False
    try:
        sidecar = json.loads(report.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    return (sidecar.get("binary_sha256") == binary_hash
            and sidecar.get("protobuf_sha256") == sha256(protobuf))


def run_one(job):
    binary = Path(job["binary"])
    output_root = Path(job["output"])
    relative = binary.relative_to(Path(job["dataset"]))
    destination = output_root / relative.parent
    destination.mkdir(parents=True, exist_ok=True)
    stem = binary.name
    metadata = destination / (stem + ".gt")
    protobuf = destination / (stem + ".gtBlock.pb")
    report = destination / (stem + ".gtBlock.jumptables.json")
    log_path = destination / (stem + ".gtBlock.log")
    binary_hash = sha256(binary)
    started = time.monotonic()
    common = {
        "binary": str(relative), "machine": job["machine"], "elf_type": job["elf_type"],
        "binary_sha256": binary_hash, "protobuf": str(protobuf.relative_to(output_root)),
        "report": str(report.relative_to(output_root)), "metadata": str(metadata.relative_to(output_root)),
        "source_assisted": bool(job["source_manifest"] and binary_hash in job["source_hashes"]),
    }

    if valid_pair(protobuf, report, binary_hash):
        append_index(job["index"], {**common, "status": "reused", "seconds": 0})
        return common, True

    for path in (metadata, protobuf, report, log_path):
        temporary = path.with_name(path.name + ".tmp")
        if temporary.exists():
            temporary.unlink()

    section_temp = metadata.with_name(metadata.name + ".section.tmp")
    metadata_temp = metadata.with_name(metadata.name + ".tmp")
    extract = subprocess.run(("objcopy", "--dump-section", ".rand=" + str(section_temp),
                              str(binary)), capture_output=True, text=True)
    if extract.returncode:
        section_temp.unlink(missing_ok=True)
        append_index(job["index"], {**common, "status": "metadata_error",
                                    "seconds": time.monotonic() - started,
                                    "error": extract.stderr.strip()})
        return common, False
    try:
        with section_temp.open("rb") as source:
            prefix = source.read(2)
        if prefix == b"\x1f\x8b":
            payload = gzip.decompress(section_temp.read_bytes())
        else:
            payload = section_temp.read_bytes()
        metadata_temp.write_bytes(payload)
    except (OSError, gzip.BadGzipFile) as error:
        section_temp.unlink(missing_ok=True)
        metadata_temp.unlink(missing_ok=True)
        append_index(job["index"], {**common, "status": "metadata_error",
                                    "seconds": time.monotonic() - started,
                                    "error": "invalid .rand section: " + str(error)})
        return common, False
    finally:
        section_temp.unlink(missing_ok=True)
    metadata_temp.replace(metadata)

    protobuf_temp = protobuf.with_name(protobuf.name + ".tmp")
    command = [sys.executable, str(EXTRACTOR), "-b", str(binary), "-m", str(metadata),
               "-o", str(protobuf_temp), "--jump-table-report",
               str(protobuf_temp) + ".jumptables.json"]
    if common["source_assisted"]:
        command += ["--source-build-manifest", str(job["source_manifest"])]
    environment = dict(os.environ)
    environment["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"
    with log_path.open("wb") as log:
        process = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                 cwd=REPOSITORY, env=environment)
    report_temp = Path(str(protobuf_temp) + ".jumptables.json")
    succeeded = process.returncode == 0 and valid_pair(protobuf_temp, report_temp, binary_hash)
    if succeeded:
        protobuf_temp.replace(protobuf)
        report_temp.replace(report)
    else:
        error = "extractor failed"
        if report_temp.is_file():
            try:
                sidecar = json.loads(report_temp.read_text())
                error = sidecar.get("failure_reason", error)
            except (OSError, UnicodeError, json.JSONDecodeError):
                pass
        append_index(job["index"], {**common, "status": "failed", "seconds": time.monotonic() - started,
                                    "returncode": process.returncode, "error": error,
                                    "log": str(log_path.relative_to(output_root))})
        return common, False

    try:
        sidecar = json.loads(report.read_text())
        sites = sidecar.get("sites", [])
        statistics = {
            "recorded_sites": len(sites),
            "resolved_sites": sum(row.get("status") == "resolved" for row in sites),
            "unresolved_physical_tables": sidecar.get("unresolved_physical_tables"),
            "analysis_scope": sidecar.get("analysis_scope"),
        }
    except (OSError, UnicodeError, json.JSONDecodeError):
        statistics = {}
    append_index(job["index"], {**common, "status": "built", "seconds": time.monotonic() - started,
                                **statistics})
    return common, True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--source-manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--workers", type=int, default=max(2, min(12, os.cpu_count() or 2)))
    parser.add_argument("--inventory-only", action="store_true")
    args = parser.parse_args()

    rows = discover(args.dataset)
    args.output.mkdir(parents=True, exist_ok=True)
    inventory = {"schema_version": 1, "dataset": str(args.dataset.resolve()),
                 "x86_elf_with_rand_section": len(rows),
                 "by_suite": {}}
    for row in rows:
        suite = row["binary"].relative_to(args.dataset).parts[0]
        inventory["by_suite"][suite] = inventory["by_suite"].get(suite, 0) + 1
    inventory_path = args.output / "inventory.json"
    inventory_temp = inventory_path.with_suffix(".json.tmp")
    inventory_temp.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n")
    inventory_temp.replace(inventory_path)
    print(json.dumps(inventory, sort_keys=True))
    if args.inventory_only:
        return

    source_hashes = source_build_hashes(args.source_manifest)
    jobs = [{"binary": str(row["binary"]), "machine": row["machine"], "elf_type": row["elf_type"],
             "dataset": str(args.dataset.resolve()), "output": str(args.output.resolve()),
             "source_manifest": str(args.source_manifest.resolve()) if args.source_manifest else None,
             "source_hashes": source_hashes,
             "index": str((args.output / "build-index.jsonl").resolve())}
            for row in rows]
    succeeded = 0
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(run_one, job) for job in jobs]
        for completed, future in enumerate(as_completed(futures), 1):
            _, ok = future.result()
            succeeded += ok
            if completed % 25 == 0 or completed == len(futures):
                print("completed %d/%d; successful %d" % (completed, len(futures), succeeded),
                      flush=True)

    summary = {"schema_version": 1, "dataset": str(args.dataset.resolve()),
               "output": str(args.output.resolve()), "discovered": len(rows),
               "successful": succeeded, "failed": len(rows) - succeeded,
               "workers": args.workers}
    summary_path = args.output / "summary.json"
    summary_temp = summary_path.with_suffix(".json.tmp")
    summary_temp.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    summary_temp.replace(summary_path)
    print(json.dumps(summary, sort_keys=True))
    if succeeded != len(rows):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
