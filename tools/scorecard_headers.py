#!/usr/bin/env python3
"""
scorecard_headers.py -- the G1 scorecard runner for the header-validation
workload: correctness first, then cold/warm throughput measurements of
avila-consensus `HeaderTree` vs the installed reference daemon, under an exact
run manifest.

WHAT IT MEASURES
----------------
Header acceptance is the only complete consensus pipeline so far; this runner
deliberately measures just that (per the scorecard, "header validation alone is
not labeled full validation"):

  workload       replay a genesis-anchored header run through full acceptance
                 (PoW, ancestry, nBits schedule, MTP/timewarp/future-drift,
                 chainwork) -- fixtures on mainnet/testnet4/signet, and the
                 generated valid regtest chain (mutations excluded; they are
                 correctness cases, not throughput).
  correctness    the same per-header verdict comparison as
                 tools/check_headers_core.py; a measurement row is only
                 reported when both sides agree.
  avila side     wall time + peak RSS of the release-mode `check_headers`
                 example process; rep 0 is "cold" (first run after build),
                 later reps are "warm".
  reference      wall time of the `submitheader` batch phase plus the
                 daemon's peak RSS afterwards; each rep runs against a fresh
                 daemon/datadir so every rep is a cold reference run (a warm
                 daemon hits the known-index path and does no validation
                 work). Daemon startup is recorded separately as first-use
                 preparation, per the scorecard protocol.

The workloads are matched on *checks*, not implementation scope: the daemon
also persists its block index and pays RPC overhead, so it is expected to be
slower per header. That asymmetry is part of the record, not hidden.

MANIFEST
--------
The artifact JSON records: repo commit + dirty flag, rustc/cargo versions,
the reference binary's version string and sha256, fixture sha256s, CPU model,
kernel/OS, rep counts and timing method. Raw per-rep wall times are stored
verbatim -- no smoothing.

    python3 tools/scorecard_headers.py                      # all suites
    python3 tools/scorecard_headers.py --suites regtest --reps 5 --ref-reps 3
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
import check_headers_core as adapter  # noqa: E402

EXAMPLE_BIN = os.path.join(
    REPO, "target", "release", "examples", "check_headers"
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
            "check_headers",
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


def run_avila(binary, network, path, now):
    """One process run; returns (wall seconds, peak RSS in KiB) via wait4."""
    pid = os.fork()
    if pid == 0:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, 1)
        os.execv(binary, [binary, network, path, str(now)])
        os._exit(127)
    start = time.monotonic()
    _pid, status, rusage = os.wait4(pid, 0)
    elapsed = time.monotonic() - start
    if status != 0:
        raise RuntimeError(f"check_headers exited with status {status}")
    return elapsed, rusage.ru_maxrss


def measure_suite(suite, workdir, now, reps, ref_reps):
    cfg = adapter.SUITES[suite]
    result = {"suite": suite, "network": cfg["network"]}

    # --- correctness: identical verdicts from both sides ---
    daemon = adapter.Daemon(suite, workdir)
    try:
        if cfg["fixture"] is not None:
            path = os.path.join(REPO, cfg["fixture"])
            headers = [
                bytes(c) for c in adapter._chunks(open(path, "rb").read(), adapter.HEADER)
            ]
            result["fixture_sha256"] = sha256_file(path)
        else:
            headers, _names = adapter.regtest_corpus(daemon, now)
            # Only the valid prefix (up to the named mutations) is a throughput
            # workload; the mutation tail is still checked for verdict parity.
            valid_end = next(
                i for i, n in enumerate(_names) if n.startswith("mut-")
            )
            result["fixture_sha256"] = None
            path = os.path.join(workdir, f"{suite}-corpus.bin")
            with open(path, "wb") as f:
                for h in headers:
                    f.write(h)
            valid_path = os.path.join(workdir, f"{suite}-valid.bin")
            with open(valid_path, "wb") as f:
                for h in headers[:valid_end]:
                    f.write(h)

        core_verdicts = daemon.submit_headers(headers)
        ours = adapter.avila_verdicts(cfg["network"], path, now)
        mismatches = [
            i for i, (c, o) in enumerate(zip(core_verdicts, ours)) if i > 0 and c != o
        ]
        result["headers"] = len(headers)
        result["verdict_mismatches"] = len(mismatches)
        result["correctness"] = "agree" if not mismatches else {"mismatch_indexes": mismatches}

        if cfg["fixture"] is not None:
            measure_path = path
            measure_count = len(headers)
        else:
            measure_path = valid_path
            measure_count = valid_end

        # --- reference cold runs: fresh daemon each rep ---
        result["reference"] = {"startup_seconds": [], "submit_seconds": []}
        first = True
        for rep in range(ref_reps):
            if not first:
                daemon.stop()
                daemon = adapter.Daemon(suite, workdir)
            first = False
            start = time.monotonic()
            daemon.submit_headers(headers[:measure_count])
            result["reference"]["submit_seconds"].append(time.monotonic() - start)
            result["reference"].setdefault("rss_kb", rss_kb(daemon.proc.pid))
    finally:
        daemon.stop()

    # --- avila cold + warm runs ---
    times, rss = [], []
    for rep in range(reps):
        elapsed, peak = run_avila(EXAMPLE_BIN, cfg["network"], measure_path, now)
        times.append(elapsed)
        rss.append(peak)
    result["avila"] = {
        "wall_seconds": times,
        "cold_seconds": times[0],
        "warm_seconds": times[1:],
        "peak_rss_kb": max(rss),
    }
    result["measured_headers"] = measure_count
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
    parser.add_argument("--suites", default=",".join(adapter.SUITES))
    parser.add_argument("--reps", type=int, default=5, help="avila reps per suite")
    parser.add_argument(
        "--ref-reps", type=int, default=2, help="reference cold reps per suite"
    )
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    build_example()
    now = int(time.time())
    workdir = tempfile.mkdtemp(prefix="scorecard-", dir=os.path.join(REPO, "target"))

    artifact = {
        "tool": "tools/scorecard_headers.py",
        "ran_at_unix": now,
        "manifest": manifest(),
        "workload": (
            "genesis-anchored header acceptance; identical verdict tables on both "
            "sides are a precondition for reporting a timing row"
        ),
        "suites": {},
    }

    for suite in args.suites.split(","):
        suite = suite.strip()
        print(f"[{suite}] correctness + measurement ...", flush=True)
        result = measure_suite(suite, workdir, now, args.reps, args.ref_reps)
        artifact["suites"][suite] = result
        count = result["measured_headers"]
        avila = result["avila"]
        ref = result["reference"]
        print(
            f"[{suite}] {count} headers, verdicts {result['correctness']}\n"
            f"    avila cold {avila['cold_seconds']*1e3:.0f} ms, "
            f"warm {[f'{t*1e3:.0f}' for t in avila['warm_seconds']]} ms, "
            f"peak RSS {avila['peak_rss_kb']/1024:.0f} MiB\n"
            f"    reference submit "
            f"{[f'{t:.2f}' for t in ref['submit_seconds']]} s, "
            f"peak RSS {ref.get('rss_kb',0)/1024:.0f} MiB",
            flush=True,
        )

    out = args.out or os.path.join(
        REPO, "target", "scorecard", f"headers-{now}.json"
    )
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"artifact: {out}")
    bad = any(
        s.get("correctness") != "agree" for s in artifact["suites"].values()
    )
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
