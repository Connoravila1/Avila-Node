#!/usr/bin/env python3
"""Reproduce snapshot_floor measurements on Linux; no global cache dropping.

Build first:
  cargo build --release --locked -p avila-consensus \
      --example snapshot_floor --example snapshot_bench
Then:
  python3 tools/snapshot_floor.py SNAPSHOT --output target/snapshot-floor/run-1

Every command runs sequentially. Cache eviction is advisory and physical I/O
counters are recorded, so a cached run cannot silently become a cold result.
Outputs must go to a new directory. The source snapshot is never modified.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import subprocess
import time


def evict(path):
    with path.open("rb") as source:
        os.posix_fadvise(source.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)


def proc_io():
    return {
        key: int(value)
        for key, value in (
            line.split(":") for line in Path("/proc/self/io").read_text().splitlines()
        )
    }


def fields(stdout):
    values = {}
    for item in stdout.split():
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        try:
            values[key] = float(value) if "." in value else int(value)
        except ValueError:
            values[key] = value
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--skip-baseline", action="store_true")
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("repetitions must be positive")
    root = Path(__file__).resolve().parents[1]
    source = args.snapshot.resolve(strict=True)
    output = args.output.resolve()
    candidate = root / "target/release/examples/snapshot_floor"
    baseline = root / "target/release/examples/snapshot_bench"
    if not candidate.is_file() or (not args.skip_baseline and not baseline.is_file()):
        parser.error("build the release examples first")
    output.mkdir(parents=True, exist_ok=False)
    manifest = {
        "source": str(source),
        "source_bytes": source.stat().st_size,
        "source_mtime_ns": source.stat().st_mtime_ns,
        "platform": platform.platform(),
        "cpuinfo": Path("/proc/cpuinfo").read_text().split("\n\n")[0],
        "memory_before": Path("/proc/meminfo").read_text(),
        "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        "rustc": subprocess.check_output(["rustc", "--version"], cwd=root, text=True).strip(),
        "sha256": {
            str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in [candidate, root / "Cargo.lock", root / "crates/avila-consensus/examples/snapshot_floor.rs", Path(__file__).resolve()]
        },
        "cache_protocol": "POSIX_FADV_DONTNEED on each input before each run; physical reads recorded; no global cache drop",
        "measurements": [],
    }

    def record(row):
        manifest["measurements"].append(row)
        (output / "results.json").write_text(json.dumps(manifest, indent=2) + "\n")
        print(json.dumps(row), flush=True)

    def command(label, argv, inputs, env=None):
        for path in inputs:
            evict(path)
        number = len(manifest["measurements"])
        timing = output / f"{number:02d}-{label}.time.json"
        usage = '{"user_seconds":%U,"system_seconds":%S,"max_rss_kib":%M,"input_blocks":%I,"output_blocks":%O}'
        start = time.perf_counter()
        child = subprocess.run(
            ["/usr/bin/time", "-f", usage, "-o", str(timing), *map(str, argv)],
            cwd=root, env=env, capture_output=True, text=True,
        )
        row = {
            "label": label,
            "argv": list(map(str, argv)),
            "wall_seconds": time.perf_counter() - start,
            "returncode": child.returncode,
            "stdout": child.stdout,
            "stderr": child.stderr,
        }
        # GNU time adds a diagnostic on failure, followed by the JSON record.
        row.update(json.loads(timing.read_text().splitlines()[-1]))
        row["physical_read_bytes"] = row["input_blocks"] * 512
        row["physical_write_bytes"] = row["output_blocks"] * 512
        row["metrics"] = fields(child.stdout)
        record(row)
        child.check_returncode()
        return row

    if not args.skip_baseline:
        for rep in range(args.repetitions):
            evict(source)
            before = proc_io()
            usage = resource.getrusage(resource.RUSAGE_SELF)
            start = time.perf_counter()
            buf = bytearray(4 << 20)
            count = 0
            with source.open("rb", buffering=0) as f:
                while n := f.readinto(buf):
                    count += n
            after_usage = resource.getrusage(resource.RUSAGE_SELF)
            seconds = time.perf_counter() - start
            after = proc_io()
            record({
                "label": "raw-read", "rep": rep, "wall_seconds": seconds,
                "logical_bytes": count,
                "physical_read_bytes": after["read_bytes"] - before["read_bytes"],
                "user_seconds": after_usage.ru_utime - usage.ru_utime,
                "system_seconds": after_usage.ru_stime - usage.ru_stime,
            })
            command("original-index", [baseline, "runindex", source, "935000"], [source],
                    dict(os.environ, SNAP_BENCH_DIR=str(output / f"baseline-{rep}")))

    for rep in range(args.repetitions):
        # Alternate order; each run evicts the source separately.
        modes = ["serial", "pipeline"] if rep % 2 == 0 else ["pipeline", "serial"]
        for mode in modes:
            command(f"scan-{mode}", [candidate, "scan", source, mode], [source])

    index = output / "snapshot.idx"
    packed = command("pack", [candidate, "pack", source, index, "pipeline"], [source])
    trusted_root = packed["metrics"]["root"]
    manifest["locally_prepared_root"] = trusted_root
    manifest["trust_note"] = "Local experiment root only; not a consensus checkpoint or an authenticated download. Preparation is charged separately."
    queries = Path(str(index) + ".queries")
    for _ in range(args.repetitions):
        command("authenticated-open-and-queries",
                [candidate, "bench", source, index, trusted_root, queries], [source, index, queries])


if __name__ == "__main__":
    main()
