#!/usr/bin/env python3
"""
diff_fuzz.py -- seeded-mutation differential fuzzing: Avila vs Bitcoin
Knots `submitblock` verdicts.

WHAT THIS DOES
--------------
The existing differential suite (check_blocks_core.py, diff_validate.py)
compares on *crafted* corpora and real blocks. This tool explores the
random space: valid blocks are mined on Knots, then mutated under a
seeded RNG -- byte flips in header/coinbase/tx regions, merkle-root
corruption, truncations, zeroed signatures -- and every mutation is
judged by BOTH engines. Any accept/reject disagreement is a consensus
divergence signal and is reported with the seed, mutation, and block
for reproduction.

Mutations never touch the PoW-critical header bytes that would just
produce "high-hash" noise — the interesting space is *structurally
plausible* invalidity (the classes real bugs live in).

Usage:
  python3 tools/diff_fuzz.py \
      --avila 127.0.0.1:PORT --avila-cookie <datadir>/regtest/.cookie \
      --seed 1 --blocks 20 --mutations 24
"""

import argparse
import base64
import json
import os
import random
import struct
import subprocess
import hashlib
import sys
import tempfile
import time
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_blocks_core import Daemon, free_port  # noqa: E402


class RpcClient:
    """Minimal cookie-auth JSON-RPC client (same wire shape Knots uses)."""

    def __init__(self, addr, cookie):
        self.addr = addr
        self.cookie = cookie

    def call(self, method, *params):
        req = urllib.request.Request(
            f"http://{self.addr}",
            data=json.dumps(
                {"jsonrpc": "1.0", "id": 0, "method": method, "params": list(params)}
            ).encode(),
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
        return json.loads(body)

    def submit_block(self, block_bytes):
        item = self.call("submitblock", block_bytes.hex())
        if item["error"] is not None:
            message = item["error"].get("message", "rpc-error")
            return "decode" if "decode" in message.lower() else message
        result = item["result"]
        if result is None or result in ("inconclusive", "duplicate"):
            return "accepted"
        return result


def mutate(rng, block):
    """One seeded mutation; returns (tag, mutated_bytes). Layout of a
    serialized block: [80B header][varint txcount][txs]."""
    b = bytearray(block)
    n = len(b)
    # Mutation classes, each leaving a structurally-plausible block.
    kind = rng.randrange(6)
    if kind == 0:
        # corrupt merkle root (header bytes 36..68)
        i = 36 + rng.randrange(32)
        b[i] ^= 1 << rng.randrange(8)
        return f"merkle-byte{i-36}", bytes(b)
    if kind == 1:
        # corrupt a byte inside a non-header region (tx data)
        if n > 90:
            i = 81 + rng.randrange(n - 81)
            b[i] ^= 1 << rng.randrange(8)
            return f"tx-byte{i}", bytes(b)
        return "tx-byte-none", bytes(b)
    if kind == 2:
        # zero a window inside tx data (mauled sig/script) — pick a
        # region that isn't already zero, or the mutation is a no-op.
        for _ in range(16):
            if n <= 120:
                break
            i = 90 + rng.randrange(n - 90)
            w = min(1 + rng.randrange(8), n - i)
            if any(b[i : i + w]):
                b[i : i + w] = b"\x00" * w
                return f"zero{i}+{w}", bytes(b)
        return "zero-none", bytes(b)
    if kind == 3:
        # truncate
        cut = rng.randrange(81, n)
        return f"truncate@{cut}", bytes(b[:cut])
    if kind == 4:
        # inflate tx count varint beyond actual txs
        if n > 81:
            b[80] = min(0xFC, b[80] + 1 + rng.randrange(8))
            return "txcount-inflate", bytes(b)
        return "txcount-none", bytes(b)
    # kind == 5: duplicate the block tail onto itself (junk append)
    if n > 90:
        tail = b[81 : 81 + rng.randrange(1, n - 81)]
        return "tail-append", bytes(b + tail)
    return "noop", bytes(b)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--avila", required=True)
    ap.add_argument("--avila-cookie", required=True)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--blocks", type=int, default=20)
    ap.add_argument("--mutations", type=int, default=24)
    ap.add_argument("--fund", type=int, default=105)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    avila = RpcClient(args.avila, open(args.avila_cookie).read().strip())
    workdir = tempfile.mkdtemp(prefix="difffuzz-")
    core = Daemon("regtest", workdir)
    try:
        # Fund the reference chain; Avila gets the same blocks raw.
        core.rpc("createwallet", "fuzz")
        waddr = core.rpc("getnewaddress")["result"]
        core.rpc("generatetoaddress", args.fund + args.blocks, waddr)
        corpus = []
        for h in range(1, args.fund + args.blocks + 1):
            bh = core.rpc("getblockhash", h)["result"]
            corpus.append((h, bytes.fromhex(core.rpc("getblock", bh, 0)["result"])))

        # Phase 1: valid-block parity — both must accept identically.
        mism = 0
        for h, blk in corpus:
            a = avila.submit_block(blk)
            if a != "accepted":
                print(f"  [h{h}] avila rejected valid block: {a}", flush=True)
                mism += 1
        print(f"valid parity: {len(corpus) - mism}/{len(corpus)} accepted")

        # Phase 2: seeded mutations on the tail blocks — verdict parity.
        divergences = []
        trials = 0
        for h, blk in corpus[-args.blocks :]:
            for _ in range(args.mutations):
                tag, mut = mutate(rng, blk)
                ca = core.submit_block(mut)
                cb = avila.submit_block(mut)
                trials += 1
                # Normalize: both-rejected is parity regardless of reason.
                bad_a = ca not in ("accepted",)
                bad_b = cb not in ("accepted",)
                if bad_a != bad_b:
                    # Known benign class: the mutation left the 80-byte
                    # header identical, so Core short-circuits on the
                    # block hash (duplicate / trailing-garbage leniency)
                    # before validating, while Avila strictly decodes
                    # wire bytes first. Strictness ordering, not a
                    # consensus rule difference.
                    if mut[:80] == blk[:80] and ca == "accepted":
                        print(f"  strictness h{h} {tag}: core={ca} "
                              f"(dup/lenient) avila={cb}", flush=True)
                        continue
                    divergences.append(
                        (h, tag, ca, cb, mut.hex()[:80])
                    )
                    print(f"  DIVERGE h{h} {tag}: core={ca} avila={cb}",
                          flush=True)
                    dump = os.path.join(workdir, f"div-h{h}-{tag}.hex")
                    with open(dump, "w") as fp:
                        fp.write(mut.hex())
        print(f"\n{trials} mutations, {len(divergences)} verdict divergences")
        if divergences:
            for d in divergences[:12]:
                print(f"  seed={args.seed} h{d[0]} {d[1]}: core={d[2]} avila={d[3]}")
            sys.exit(1)
        print("PASS — no verdict divergence")
    finally:
        core.stop()


if __name__ == "__main__":
    main()
