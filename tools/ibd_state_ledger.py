#!/usr/bin/env python3
"""Exact-state anti-join measurement (candidate #42) on a bounded blk span.

Streams raw blk records and emits two sequential ledgers plus a join:

  created.bin : txid32 | vout u32 | value i64 | height u32     (48 B/entry)
  spent.bin   : txid32 | vout u32 | spend_height u32           (40 B/entry)

Then joins in memory (bounded span only — the production shape is an
external sort-merge; this measures record counts, byte volumes, and the
survivor/outflow classes):

  survivors   = created-in-span AND never-spent-in-span (UTXO tail)
  outflow     = spent-in-span whose source predates the span (cold-start
                dependency — exactly the class #41's index must serve)
  coinbase    = ledgered for completeness; maturity predicate reported.

Caveat labels: in-memory join on a bounded window, sequential-IO shape is
the point — this does not emulate full-history sort cost.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ibd_corpus_window import MAGIC, bip34_height, compact, parse_tx_io, \
    records, sha256d, stripped_txid, tx_spans


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--files", nargs="+", type=Path, required=True)
    ap.add_argument("--xor-key", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    key = args.xor_key.read_bytes() if args.xor_key else b""
    args.out.mkdir(parents=True, exist_ok=True)

    created_path = args.out / "created.bin"
    spent_path = args.out / "spent.bin"
    stats = {"blocks": 0, "txs": 0, "created": 0, "spent": 0,
             "coinbase_outputs": 0, "files": []}
    heights = []

    with created_path.open("wb") as cf, spent_path.open("wb") as sf:
        for f in args.files:
            meta = {"file": str(f), "sha256": hashlib.sha256(f.read_bytes()).hexdigest(),
                    "records": 0}
            blocks = []
            for off, rec in records(f, key):
                h = bip34_height(rec)
                if h is None:
                    continue
                blocks.append((h, rec))
                meta["records"] += 1
            blocks.sort(key=lambda x: x[0])
            for h, rec in blocks:
                stats["blocks"] += 1
                heights.append(h)
                for ti, (tstart, tlen, _s) in enumerate(tx_spans(rec)):
                    ins, outs = parse_tx_io(rec, tstart)
                    stats["txs"] += 1
                    is_cb = len(ins) == 1 and ins[0][0] == b"\x00" * 32
                    if not is_cb:
                        txid = stripped_txid(rec, tstart, tlen, _s)
                        for prevtx, vout in ins:
                            sf.write(prevtx + struct.pack("<II", vout, h))
                            stats["spent"] += 1
                    else:
                        txid = stripped_txid(rec, tstart, tlen, _s)
                    for vi, (value, _spk) in enumerate(outs):
                        cf.write(txid + struct.pack("<Iqi", vi, value, h))
                        stats["created"] += 1
                        if is_cb:
                            stats["coinbase_outputs"] += 1
            stats["files"].append(meta)

    # Join: spent-in-span sources → created lookup.
    created = {}
    cb_spent_in_span = 0
    with created_path.open("rb") as cf:
        while True:
            b = cf.read(48)
            if len(b) < 48:
                break
            txid = b[:32]
            vout, _val, _h = struct.unpack_from("<Iqi", b, 32)
            created[(txid, vout)] = _h
    spent_keys = set()
    with spent_path.open("rb") as sf:
        while True:
            b = sf.read(40)
            if len(b) < 40:
                break
            spent_keys.add((b[:32], struct.unpack_from("<I", b, 32)[0]))
    survivors = [(k, h) for k, h in created.items() if k not in spent_keys]
    outflow = len(spent_keys) - len(set(spent_keys) & set(created))
    in_span = len(spent_keys) - outflow
    result = {
        "labels": {"join": "in-memory dict over bounded span",
                   "survivors": "created-in-span, never-spent-in-span",
                   "outflow": "spent-in-span, source predates span = cold-start dependency",
                   "ledger_io": "sequential write; production shape is external sort-merge"},
        "heights": [min(heights), max(heights)] if heights else None,
        "stats": stats,
        "ledger_bytes": {"created": created_path.stat().st_size,
                         "spent": spent_path.stat().st_size},
        "join": {"created_in_span": len(created), "spent_in_span": len(spent_keys),
                 "consumed_created_in_span": in_span,
                 "survivors_at_span_end": len(survivors),
                 "outflow_to_history": outflow,
                 "survivor_share_of_created": round(len(survivors) / max(1, len(created)), 4),
                 "dedup_multiple_spend_records": len(spent_keys) - in_span - outflow},
    }
    (args.out / "ledger_result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["join"]))


if __name__ == "__main__":
    main()
