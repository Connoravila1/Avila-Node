#!/usr/bin/env python3
"""
check_blocks_core.py -- differential-check avila-consensus block-level
validation (header insertion + CheckBlock + ContextualCheckBlock) against the
installed reference daemon's `submitblock` RPC.

WHAT THIS DOES
--------------
Generates a regtest block corpus with `cargo run --example check_blocks --
gen-corpus` (one valid block plus one block per implemented rule violation),
launches an isolated `bitcoind -regtest`, submits each block through
`submitblock`, runs the same block through the check_blocks example's pipeline
(HeaderTree::insert -> check_block -> contextual_check_block), and compares
verdicts reason-for-reason:

  submitblock result null / "inconclusive" / "duplicate"   <->  accepted
  "Block decode failed"                                    <->  rejected:decode
  "<reason>"                                               <->  rejected:<reason>

The "inconclusive" normalization matters: every corpus block builds on genesis
at height 1, so all but the first are equal-work side-chain candidates. A
side-chain block that passes AcceptBlock is written but never receives
UTXO-level validation (ConnectBlock), so Core reports BIP22 "inconclusive" for
valid-but-not-best blocks and null only for a block that becomes the tip. Both
mean "passed every check this tool tests".

One pair is a *layer* difference, not a verdict difference: our bounded block
decoder refuses inputs over 4,000,000 serialized bytes outright
(`rejected:decode`), while Core decodes them and rejects at the contextual
weight check (`bad-blk-weight`). Since weight = 3*stripped + total, any block
over 4,000,000 bytes is necessarily overweight — the cap can never reject a
consensus-valid block, so the pair is counted as agreement with
`layer_note` set in the artifact.

REQUIREMENTS
------------
`bitcoind` on PATH (any Core lineage -- checked and recorded per run), the
pinned workspace toolchain for the example binary, and Python 3 standard
library only. The daemon is launched with -connect=0 -listen=0 -dnsseed=0
-fixedseeds=0 and never sees the network.

OUTPUT
------
A JSON artifact (default target/reference-runs/blocks-<unixtime>.json)
recording the reference binary version/hash, per-block verdicts, and any
disagreements with the offending block hex. Exit status is non-zero on any
disagreement.

    python3 tools/check_blocks_core.py
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


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Daemon:
    """An isolated regtest reference daemon."""

    def __init__(self, workdir):
        self.rpc_port = free_port()
        self.p2p_port = free_port()
        self.datadir = os.path.join(workdir, "datadir-regtest")
        os.makedirs(self.datadir, exist_ok=True)
        self.proc = subprocess.Popen(
            [
                "bitcoind",
                "-regtest",
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
        cookie_path = os.path.join(self.datadir, "regtest", ".cookie")
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
                    raise RuntimeError("bitcoind exited early")
        else:
            raise RuntimeError("bitcoind did not become ready")

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


def avila_gen_corpus(outdir):
    """Run the corpus generator; returns the manifest list."""
    tmpdir = os.path.join(REPO, "target", "tmp")
    os.makedirs(tmpdir, exist_ok=True)
    subprocess.run(
        [
            "cargo", "run", "-q", "--locked", "-p", "avila-consensus",
            "--example", "check_blocks", "--", "gen-corpus", outdir,
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "TMPDIR": tmpdir},
    )
    with open(os.path.join(outdir, "manifest.json")) as f:
        return json.load(f)


def avila_verdict(path, now):
    """One verdict token from the check_blocks pipeline."""
    tmpdir = os.path.join(REPO, "target", "tmp")
    proc = subprocess.run(
        [
            "cargo", "run", "-q", "--locked", "-p", "avila-consensus",
            "--example", "check_blocks", "--", "check", "regtest", path, str(now),
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "TMPDIR": tmpdir},
    )
    verdict, _detail = proc.stdout.strip().split("\t", 1)
    return "accepted" if verdict.startswith("accepted") else verdict.split(":", 1)[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--out",
        default=None,
        help="artifact path (default target/reference-runs/blocks-<now>.json)",
    )
    parser.add_argument(
        "--workdir",
        default=None,
        help="scratch dir for the daemon datadir (default: a temp dir under target/)",
    )
    parser.add_argument(
        "--corpus",
        default=None,
        help="reuse a previously generated corpus dir instead of regenerating",
    )
    parser.add_argument(
        "--dump-verdicts", action="store_true", help="record every verdict line"
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
    corpus_dir = args.corpus or os.path.join(workdir, "block-corpus")
    os.makedirs(corpus_dir, exist_ok=True)

    manifest = avila_gen_corpus(corpus_dir)
    print(f"corpus: {len(manifest)} blocks in {corpus_dir}", flush=True)

    daemon = Daemon(workdir)
    mismatches = []
    notes = []
    compared = 0
    rows = []
    try:
        for entry in manifest:
            name = entry["file"]
            path = os.path.join(corpus_dir, name)
            block_bytes = open(path, "rb").read()
            core = daemon.submit_block(block_bytes)
            ours = avila_verdict(path, now)
            compared += 1
            row = {"name": name, "core": core, "avila": ours}
            # Decode-bound vs. rule reason: our 4,000,000-byte input cap
            # pre-rejects what Core reports as bad-blk-weight. The rejection is
            # equivalent — any block that large is necessarily overweight —
            # only the layer differs.
            if ours == "decode" and core in ("bad-blk-weight", "bad-blk-length"):
                row["layer_note"] = "decode-bound vs rule reason; same rejection"
                notes.append(row)
            elif core != ours:
                mismatches.append({**row, "block": block_bytes.hex()})
            rows.append(row)
            print(f"  {name:<34} core={core:<36} avila={ours}", flush=True)
    finally:
        daemon.stop()

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
        "blocks": len(manifest),
        "compared": compared,
        "mismatches": mismatches,
        "layer_notes": notes,
    }
    if args.dump_verdicts:
        artifact["verdicts"] = rows

    out = args.out or os.path.join(
        REPO, "target", "reference-runs", f"blocks-{now}.json"
    )
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"{compared} compared, {len(mismatches)} mismatches")
    print(f"artifact: {out}")
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
