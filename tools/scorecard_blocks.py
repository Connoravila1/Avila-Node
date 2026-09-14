#!/usr/bin/env python3
"""
scorecard_blocks.py -- the G2 scorecard runner for the block-validation
workload: correctness first, then cold/warm throughput measurements of the
avila-consensus `Chainstate` replay path vs the installed reference daemon,
under an exact run manifest.

WHAT IT MEASURES
----------------
Full block validation is now a complete consensus pipeline (structural
CheckBlock + contextual checks + UTXO connect + script execution + signet
solutions). This runner measures that pipeline end-to-end:

  workload       replay a contiguous blk.dat-framed real-chain segment through
                 `Chainstate::accept_block` in order -- mainnet heights
                 0..=500 (real P2PK/P2PKH spends incl. historical high-S sigs)
                 and signet heights 0..=300 (300 real BIP325 challenge-spend
                 verifications).
  correctness    the same per-block verdict comparison as
                 tools/check_blocks_core.py's segment suites; a measurement
                 row is only reported when both sides agree on every verdict.
  avila side     wall time + peak RSS of the release-mode `check_blocks
                 replay` process; rep 0 is "cold" (first run after build),
                 later reps are "warm".
  reference      wall time of the `submitblock` batch phase plus the daemon's
                 peak RSS afterwards; each rep runs against a fresh
                 daemon/datadir so every rep is a cold reference run (a warm
                 daemon hits the known-index path and does no validation
                 work). Daemon startup is recorded separately as first-use
                 preparation, per the scorecard protocol.

The workloads are matched on *checks*, not implementation scope: the daemon
also persists blocks to disk, maintains its coins cache, and pays RPC
overhead, so it is expected to be slower per block. That asymmetry is part of
the record, not hidden.

MANIFEST
--------
The artifact JSON records: repo commit + dirty flag, rustc/cargo versions,
the reference binary's version string and sha256, fixture sha256s, CPU model,
kernel/OS, rep counts and timing method. Raw per-rep wall times are stored
verbatim -- no smoothing.

    python3 tools/scorecard_blocks.py                      # all suites
    python3 tools/scorecard_blocks.py --suites segment-signet --reps 5 --ref-reps 3
"""

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "tools"))
import check_blocks_core as adapter  # noqa: E402

EXAMPLE_BIN = os.path.join(
    REPO, "target", "release", "examples", "check_blocks"
)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_example():
    tmpdir = os.path.join(REPO, "target", "tmp")
    os.makedirs(tmpdir, exist_ok=True)
    proc = subprocess.run(
        [
            "cargo",
            "build",
            "--release",
            "--locked",
            "-p",
            "avila-consensus",
            "--example",
            "check_blocks",
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
        env={**os.environ, "TMPDIR": tmpdir},
    )
    if proc.returncode != 0:
        raise RuntimeError(f"release build failed:\n{proc.stderr[-2000:]}")
    return EXAMPLE_BIN


def rss_kb(pid):
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("VmHWM"):
                return int(line.split()[1])
    return 0


def run_avila(network, path, now):
    """One replay process; returns (wall seconds, peak RSS in KiB) via wait4."""
    pid = os.fork()
    if pid == 0:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, 1)
        os.execv(
            EXAMPLE_BIN,
            [EXAMPLE_BIN, "replay", network, path, str(now)],
        )
        os._exit(127)
    start = time.monotonic()
    _pid, status, rusage = os.wait4(pid, 0)
    elapsed = time.monotonic() - start
    if status != 0:
        raise RuntimeError(f"check_blocks replay exited with status {status}")
    return elapsed, rusage.ru_maxrss


def measure_suite(suite, workdir, now, reps, ref_reps):
    network = suite[len("segment-"):]
    file_name = adapter.SEGMENT_FIXTURES[network]
    path = os.path.join(REPO, "fixtures", file_name)
    blocks = adapter.read_blkdat(path)
    result = {
        "suite": suite,
        "network": network,
        "blocks": len(blocks),
        "fixture_sha256": sha256_file(path),
    }

    # --- correctness: identical verdicts from both sides ---
    daemon = adapter.Daemon(network, workdir)
    try:
        core_verdicts = [daemon.submit_block(b) for b in blocks]
        ours = adapter.avila_replay_verdicts(network, path, now)
        mismatches = [
            i for i, (c, o) in enumerate(zip(core_verdicts, ours)) if c != o
        ]
        result["verdict_mismatches"] = len(mismatches)
        result["correctness"] = (
            "agree" if not mismatches else {"mismatch_indexes": mismatches}
        )

        # --- reference cold runs: fresh daemon each rep ---
        result["reference"] = {"startup_seconds": [], "submit_seconds": []}
        first = True
        for rep in range(ref_reps):
            if not first:
                daemon.stop()
                boot = time.monotonic()
                daemon = adapter.Daemon(network, workdir)
                result["reference"]["startup_seconds"].append(
                    time.monotonic() - boot
                )
            first = False
            start = time.monotonic()
            for b in blocks:
                daemon.submit_block(b)
            result["reference"]["submit_seconds"].append(time.monotonic() - start)
            result["reference"].setdefault("rss_kb", rss_kb(daemon.proc.pid))
    finally:
        daemon.stop()

    # --- avila cold + warm runs ---
    times, rss = [], []
    for rep in range(reps):
        elapsed, peak = run_avila(network, path, now)
        times.append(elapsed)
        rss.append(peak)
    result["avila"] = {
        "wall_seconds": times,
        "cold_seconds": times[0],
        "warm_seconds": times[1:],
        "peak_rss_kb": max(rss),
    }
    result["measured_blocks"] = len(blocks)
    return result


def manifest():
    def cmd(*args):
        return subprocess.run(args, capture_output=True, text=True).stdout.splitlines()[0]

    bitcoind = adapter.shutil.which("bitcoind")
    cpu = "unknown"
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    cpu = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    return {
        "git_head": cmd("git", "-C", REPO, "rev-parse", "HEAD"),
        "git_dirty": bool(
            subprocess.run(
                ["git", "-C", REPO, "status", "--porcelain"],
                capture_output=True,
                text=True,
            ).stdout.strip()
        ),
        "rustc": cmd("rustc", "--version"),
        "cargo": cmd("cargo", "--version"),
        "reference_binary": {
            "path": bitcoind,
            "version": cmd("bitcoind", "--version"),
            "sha256": sha256_file(bitcoind),
        },
        "cpu": cpu,
        "os": platform.platform(),
        "timing": "time.monotonic wall time per rep; RSS via /proc VmHWM and getrusage",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--suites",
        default=",".join(f"segment-{n}" for n in adapter.SEGMENT_FIXTURES),
        help="comma-separated subset (segment-<network>)",
    )
    parser.add_argument("--reps", type=int, default=5, help="avila reps (first is cold)")
    parser.add_argument("--ref-reps", type=int, default=3, help="fresh-daemon reps")
    parser.add_argument(
        "--out",
        default=os.path.join(
            REPO, "target", "scorecard", f"blocks-{int(time.time())}.json"
        ),
    )
    parser.add_argument("--now", type=int, default=1_800_000_000)
    args = parser.parse_args()

    binary = build_example()
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    workdir = tempfile.mkdtemp(prefix="scorecard-blocks-", dir=os.path.join(REPO, "target"))

    artifact = {
        "tool": "scorecard_blocks",
        "manifest": manifest(),
        "reps": args.reps,
        "ref_reps": args.ref_reps,
        "suites": {},
    }
    for suite in args.suites.split(","):
        suite = suite.strip()
        print(f"[{suite}] measuring ...", flush=True)
        try:
            result = measure_suite(suite, workdir, args.now, args.reps, args.ref_reps)
        except Exception as err:
            artifact["suites"][suite] = {"error": str(err)}
            print(f"  error: {err}", flush=True)
            continue
        artifact["suites"][suite] = result
        av = result["avila"]
        ref = result["reference"]
        print(
            f"  correctness={result['correctness']} blocks={result['blocks']} "
            f"avila cold={av['cold_seconds']:.2f}s warm={min(av['warm_seconds'], default=0):.2f}s "
            f"rss={av['peak_rss_kb']}KiB | "
            f"ref submit={min(ref['submit_seconds'], default=0):.2f}s "
            f"rss={ref.get('rss_kb', 0)}KiB",
            flush=True,
        )

    with open(args.out, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"artifact: {args.out}")


if __name__ == "__main__":
    main()
