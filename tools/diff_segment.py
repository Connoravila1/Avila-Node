#!/usr/bin/env python3
"""
diff_segment.py -- state-level differential replay of a REAL-chain
blk.dat segment through Avila and a reference daemon simultaneously.

WHAT THIS DOES
--------------
diff_validate.py exercises generated regtest traffic (wallet txs of
every standard type). This tool instead feeds a committed fixture —
real historical blocks, byte-for-byte as mined — to BOTH engines via
`submitblock`, comparing consensus state per block:

  gettxoutsetinfo: bestblock, height, txouts, transactions,
                   total_amount, hash_serialized_3

Real-chain segments carry transaction/script shapes regtest wallet
traffic never produces: pre-BIP34 coinbases, raw-pubkey P2PK outputs
and their spends (CHECKSIG without a script hash wrapper), the first
real P2PKH traffic (h170+), nonstandard early outputs. Any satoshi,
fee, maturity, or script-eval disagreement shows up as a UTXO-hash
divergence at the exact height where the connect went wrong.

Verdict parity is checked too: both daemons must accept every block
(`null`/`duplicate`/`inconclusive` = accept). The committed segments
start at genesis, so a fresh datadir can take them directly.

Note on signet: Avila does not verify the BIP325 block signature
(`bad-signet-blksig-unchecked` is a documented gap) — a signet run
still compares UTXO content, but Avila accepts where the reference
actually validates the signature. That asymmetry is intentional
coverage, reported honestly.

Usage:
  python3 tools/diff_segment.py \
      --segment fixtures/mainnet-blocks-000000-000500.dat \
      --magic f9beb4d9 \
      --core 127.0.0.1:18332 --core-cookie /tmp/knots-main/.cookie \
      --avila 127.0.0.1:28332 --avila-cookie /tmp/avila-main/main/.cookie \
      --every 1
"""

import argparse
import base64
import json
import struct
import sys
import urllib.request
import urllib.error

from diff_validate import Node, RpcError, Divergence, compare_utxo, compare


def iter_frames(path, magic):
    """blk.dat framing: 4-byte magic + 4-byte LE length + raw block."""
    data = open(path, "rb").read()
    pos, n = 0, 0
    while pos + 8 <= len(data):
        magic_b, size = struct.unpack("<4sI", data[pos : pos + 8])
        if magic_b != bytes.fromhex(magic):
            raise Divergence(f"bad magic {magic_b.hex()} at offset {pos}")
        block = data[pos + 8 : pos + 8 + size]
        if len(block) != size:
            raise Divergence(f"truncated frame at offset {pos}")
        pos += 8 + size
        n += 1
        yield n - 1, block.hex()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--segment", required=True)
    ap.add_argument("--magic", required=True, help="4-byte hex net magic")
    ap.add_argument("--core", required=True)
    ap.add_argument("--core-cookie", required=True)
    ap.add_argument("--avila", required=True)
    ap.add_argument("--avila-cookie", required=True)
    ap.add_argument("--every", type=int, default=1,
                    help="compare UTXO state every N blocks (default 1)")
    args = ap.parse_args()

    core = Node(args.core, args.core_cookie)
    avila = Node(args.avila, args.avila_cookie)

    frames = list(iter_frames(args.segment, args.magic))
    print(f"[load] {len(frames)} frames from {args.segment}")

    for i, raw in frames:
        # Verdict parity: both must accept (genesis returns duplicate).
        a_verdict = core.call("submitblock", raw)
        b_verdict = avila.call("submitblock", raw)
        for label, v in (("core", a_verdict), ("avila", b_verdict)):
            if v not in (None, "duplicate", "inconclusive"):
                raise Divergence(f"{label} rejected block #{i}: {v}")
        compare(f"verdict#{i}",
                a_verdict or "accepted", b_verdict or "accepted",
                f"frame {i}")
        if i % args.every == 0 or i == len(frames) - 1:
            compare_utxo(core, avila, f"block #{i}")
            if i % (args.every * 25) == 0:
                info = core.call("getblockchaininfo")
                print(f"  h{i}: identical — tip {info['blocks']}", flush=True)

    print(f"\nPASS — {len(frames)} real blocks, identical verdicts and "
          f"UTXO state at every compared height")


if __name__ == "__main__":
    main()
