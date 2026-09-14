#!/usr/bin/env python3
"""
check_blocks_core.py -- differential-check avila-consensus block-level
validation (header insertion + CheckBlock + ContextualCheckBlock) against the
installed reference daemon's `submitblock` RPC.

WHAT THIS DOES
--------------
Two suites:

  regtest-corpus — `cargo run --example check_blocks -- gen-corpus` emits one
      block per implemented rule violation plus valid controls (a height-1
      block, a height-2 child, a witness-committed block, and a duplicate
      resubmission). An isolated `bitcoind -regtest` judges each block through
      `submitblock` in manifest order; the same files run through
      `check_blocks check-many`, which shares one HeaderTree across the corpus
      the way the daemon shares its block index.

  fixtures-{mainnet,testnet4,signet} — every committed real block fixture for
      the network, in height order. The daemon connects the ones whose parents
      it has (genesis -> "duplicate", height 1 -> connected as tip) and returns
      "prev-blk-not-found" for deeper blocks whose ancestors are not committed.
      Signet block 1 is an expected divergence: the daemon verifies the real
      BIP325 block solution while `check_block` returns the explicit
      `bad-signet-blksig-unchecked` stub — the documented gap, surfaced as
      evidence rather than hidden.

VERDICT NORMALIZATION
---------------------
  submitblock result null / "inconclusive" / "duplicate"   <->  accepted
  "Block decode failed"                                    <->  rejected:decode
  "<reason>"                                               <->  rejected:<reason>

The "inconclusive" normalization matters: corpus blocks that don't extend the
tip are equal-work side-chain candidates. A side-chain block that passes
AcceptBlock is written but never receives UTXO-level validation
(ConnectBlock), so Core reports BIP22 "inconclusive" for valid-but-not-best
blocks and null only for a block that becomes the tip. Both mean "passed every
check this tool tests".

One pair is a *layer* difference, not a verdict difference: our bounded block
decoder refuses inputs over 4,000,000 serialized bytes outright
(`rejected:decode`), while Core decodes them and rejects at the contextual
weight check (`bad-blk-weight`). Since weight = 3*stripped + total, any block
over 4,000,000 bytes is necessarily overweight — the cap can never reject a
consensus-valid block, so the pair is counted as agreement with `layer_note`
set in the artifact.

REQUIREMENTS
------------
`bitcoind` on PATH (any Core lineage -- checked and recorded per run), the
pinned workspace toolchain for the example binary, and Python 3 standard
library only. Daemons launch with -connect=0 -listen=0 -dnsseed=0
-fixedseeds=0 and never see the network.

OUTPUT
------
A JSON artifact (default target/reference-runs/blocks-<unixtime>.json)
recording the reference binary version/hash, per-suite verdict counts,
layer notes, expected divergences, and any disagreements with the offending
block hex. Exit status is non-zero on any unexplained disagreement.

    python3 tools/check_blocks_core.py
    python3 tools/check_blocks_core.py --suites regtest-corpus
    python3 tools/check_blocks_core.py --out run.json --dump-verdicts
"""

import argparse
import base64
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

NETWORKS = {
    "mainnet": {"flag": [], "cookie_dir": ""},
    "testnet4": {"flag": ["-testnet4"], "cookie_dir": "testnet4"},
    "signet": {"flag": ["-signet"], "cookie_dir": "signet"},
    "regtest": {"flag": ["-regtest"], "cookie_dir": "regtest"},
}

# Block fixtures per network, in height order.
BLOCK_FIXTURES = {
    "mainnet": [
        "mainnet-block-000000.bin",
        "mainnet-block-000001.bin",
        "mainnet-block-000170.bin",
        "mainnet-block-100000.bin",
        "mainnet-block-segwit-small.bin",
        "mainnet-block-taproot-era-small.bin",
    ],
    "testnet4": ["testnet4-block-000000.bin"],
    "signet": ["signet-block-000000.bin", "signet-block-000001.bin"],
}

# Documented gaps where the two sides are known to differ today.
EXPECTED_DIVERGENCE = {
    "signet-block-000001.bin": (
        "signet BIP325 block-solution validation is unimplemented; the daemon "
        "verifies the real signature, we return the explicit "
        "bad-signet-blksig-unchecked stub"
    ),
}


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Daemon:
    """An isolated reference daemon on one network."""

    def __init__(self, network, workdir):
        cfg = NETWORKS[network]
        self.rpc_port = free_port()
        self.p2p_port = free_port()
        self.datadir = os.path.join(workdir, f"datadir-{network}")
        os.makedirs(self.datadir, exist_ok=True)
        self.proc = subprocess.Popen(
            ["bitcoind"]
            + cfg["flag"]
            + [
                f"-datadir={self.datadir}",
                "-connect=0",
                "-listen=0",
                "-dnsseed=0",
                "-fixedseeds=0",
                f"-rpcport={self.rpc_port}",
                f"-port={self.p2p_port}",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        cookie_path = os.path.join(self.datadir, cfg["cookie_dir"], ".cookie")
        deadline = time.time() + 60
        while time.time() < deadline:
            if os.path.exists(cookie_path):
                self.cookie = open(cookie_path).read().strip()
                try:
                    self.rpc("getblockchaininfo")
                    break
                except (urllib.error.URLError, ConnectionError, json.JSONDecodeError):
                    time.sleep(0.25)
            else:
                time.sleep(0.25)
                if self.proc.poll() is not None:
                    raise RuntimeError(f"bitcoind exited early for {network}")
        else:
            raise RuntimeError(f"bitcoind for {network} did not become ready")

    def rpc(self, method, *params):
        payload = [{"jsonrpc": "1.0", "id": 0, "method": method, "params": list(params)}]
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.rpc_port}",
            data=json.dumps(payload).encode(),
            headers={
                "Authorization": "Basic "
                + base64.b64encode(self.cookie.encode()).decode()
            },
        )
        try:
            with urllib.request.urlopen(req) as resp:
                body = resp.read()
        except urllib.error.HTTPError as err:
            body = err.read()
        return json.loads(body)[0]

    def submit_block(self, block_bytes):
        """Verdict token: 'accepted' for tip/side-chain acceptance, 'decode'
        for wire-level rejection, else the reject reason string."""
        item = self.rpc("submitblock", block_bytes.hex())
        if item["error"] is not None:
            # RPC-layer failure (e.g. undecodable serialization) carries the
            # reason in the error message, like submitheader.
            message = item["error"].get("message", "rpc-error")
            return "decode" if "decode" in message.lower() else message
        result = item["result"]
        if result is None or result in ("inconclusive", "duplicate"):
            return "accepted"
        return result

    def stop(self):
        try:
            self.rpc("stop")
            self.proc.wait(timeout=30)
        except Exception:
            self.proc.kill()
            self.proc.wait()


def cargo_env():
    # Some dev-dependency build scripts honor $TMPDIR; keep scratch space in the
    # workspace where quota is available.
    tmpdir = os.path.join(REPO, "target", "tmp")
    os.makedirs(tmpdir, exist_ok=True)
    return {**os.environ, "TMPDIR": tmpdir}


def avila_gen_corpus(outdir):
    """Run the corpus generator; returns the manifest list."""
    subprocess.run(
        [
            "cargo", "run", "-q", "--locked", "-p", "avila-consensus",
            "--example", "check_blocks", "--", "gen-corpus", outdir,
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
        env=cargo_env(),
    )
    with open(os.path.join(outdir, "manifest.json")) as f:
        return json.load(f)


def avila_verdicts(network, paths, now):
    """Verdict tokens for `paths` in order, from one stateful check-many run.
    Returns a list aligned with `paths` (a file may appear twice — e.g. the
    duplicate-resubmission case — so a name-keyed map would lose order)."""
    proc = subprocess.run(
        [
            "cargo", "run", "-q", "--locked", "-p", "avila-consensus",
            "--example", "check_blocks", "--", "check-many", network, str(now),
        ]
        + paths,
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
        env=cargo_env(),
    )
    lines = [l.split("\t") for l in proc.stdout.splitlines()]
    assert len(lines) == len(paths), (len(lines), len(paths), proc.stdout)
    return [
        ("accepted" if v.startswith("accepted") else v.split(":", 1)[1])
        for _name, v, _detail in lines
    ]


def compare_rows(rows):
    """Split compared rows into (mismatches, layer_notes, expected)."""
    mismatches, notes, expected = [], [], []
    for row in rows:
        core, ours = row["core"], row["avila"]
        if ours == "decode" and core in ("bad-blk-weight", "bad-blk-length"):
            notes.append({**row, "note": "decode-bound vs rule reason; same rejection"})
        elif core != ours:
            if row["name"] in EXPECTED_DIVERGENCE:
                expected.append({**row, "why": EXPECTED_DIVERGENCE[row["name"]]})
            else:
                mismatches.append(row)
    return mismatches, notes, expected


def suite_regtest_corpus(workdir, now):
    corpus_dir = os.path.join(workdir, "block-corpus")
    os.makedirs(corpus_dir, exist_ok=True)
    manifest = avila_gen_corpus(corpus_dir)
    paths = [os.path.join(corpus_dir, e["file"]) for e in manifest]
    names = [e["file"] for e in manifest]

    daemon = Daemon("regtest", workdir)
    try:
        core = [daemon.submit_block(open(p, "rb").read()) for p in paths]
    finally:
        daemon.stop()
    ours = avila_verdicts("regtest", paths, now)

    rows = []
    for n, p, c, o, e in zip(names, paths, core, ours, manifest):
        row = {
            "name": n,
            "core": c,
            "avila": o,
            "expected_by_avila": e["expected_verdict"],
        }
        if c != o:
            row["block"] = open(p, "rb").read().hex()
        rows.append(row)
    for row in rows:
        print(
            f"  {row['name']:<34} core={row['core']:<36} avila={row['avila']}",
            flush=True,
        )
    mismatches, notes, expected = compare_rows(rows)
    return {
        "blocks": len(rows),
        "compared": len(rows),
        "mismatches": mismatches,
        "layer_notes": notes,
        "expected_divergences": expected,
        "rows": rows,
    }


def suite_fixtures(network, workdir, now):
    files = BLOCK_FIXTURES[network]
    paths = [os.path.join(REPO, "fixtures", f) for f in files]

    daemon = Daemon(network, workdir)
    try:
        core = [daemon.submit_block(open(p, "rb").read()) for p in paths]
    finally:
        daemon.stop()
    ours = avila_verdicts(network, paths, now)

    rows = [
        {"name": n, "core": c, "avila": o}
        for n, c, o in zip(files, core, ours)
    ]
    for row in rows:
        print(
            f"  {row['name']:<40} core={row['core']:<36} avila={row['avila']}",
            flush=True,
        )
    mismatches, notes, expected = compare_rows(rows)
    return {
        "blocks": len(rows),
        "compared": len(rows),
        "mismatches": mismatches,
        "layer_notes": notes,
        "expected_divergences": expected,
        "rows": rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--suites",
        default="regtest-corpus,fixtures-mainnet,fixtures-testnet4,fixtures-signet",
        help="comma-separated subset",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="artifact path (default target/reference-runs/blocks-<now>.json)",
    )
    parser.add_argument(
        "--workdir",
        default=None,
        help="scratch dir for daemon datadirs (default: a temp dir under target/)",
    )
    parser.add_argument(
        "--dump-verdicts",
        action="store_true",
        help="record every verdict row in the artifact",
    )
    args = parser.parse_args()

    version = subprocess.run(
        ["bitcoind", "--version"], capture_output=True, text=True, check=True
    ).stdout.splitlines()[0]
    binary_sha = hashlib.sha256(open(shutil.which("bitcoind"), "rb").read()).hexdigest()

    now = int(time.time())
    workdir = args.workdir or tempfile.mkdtemp(
        prefix="core-adapter-", dir=os.path.join(REPO, "target")
    )
    os.makedirs(workdir, exist_ok=True)

    artifact = {
        "tool": "tools/check_blocks_core.py",
        "ran_at_unix": now,
        "reference": {
            "binary": shutil.which("bitcoind"),
            "version": version,
            "sha256": binary_sha,
            "lineage_note": (
                "Whatever `bitcoind` is installed; consensus rules under test are "
                "identical across Core and Core-derived builds."
            ),
        },
        "suites": {},
    }

    failed = False
    for suite in args.suites.split(","):
        suite = suite.strip()
        print(f"[{suite}] launching isolated reference daemon ...", flush=True)
        try:
            if suite == "regtest-corpus":
                result = suite_regtest_corpus(workdir, now)
            elif suite.startswith("fixtures-"):
                result = suite_fixtures(suite[len("fixtures-"):], workdir, now)
            else:
                raise ValueError(f"unknown suite {suite}")
        except Exception as err:
            artifact["suites"][suite] = {"error": str(err)}
            print(f"[{suite}] ERROR: {err}", flush=True)
            failed = True
            continue
        if not args.dump_verdicts:
            result = {k: v for k, v in result.items() if k != "rows"}
        artifact["suites"][suite] = result
        print(
            f"[{suite}] {result['compared']} compared, "
            f"{len(result['mismatches'])} mismatches, "
            f"{len(result['expected_divergences'])} expected divergences",
            flush=True,
        )
        failed = failed or bool(result["mismatches"])

    out = args.out or os.path.join(
        REPO, "target", "reference-runs", f"blocks-{now}.json"
    )
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"artifact: {out}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
