#!/usr/bin/env python3
"""Matched-subset calibration (gate 2).

Reconstructs the EXACT executed set from an AVCORP02 corpus (same rules
as corpus_replay.rs: non-coinbase txs whose every input is resolved and
no coinbase-source input violates the 100-block maturity rule), verifies
the selection digest matches the replay's `executed_set_digest`, then
counts structural sig-item attempts over only that set and compares
them with the replay's executed counters (ecdsa/schnorr verify
attempts). This is a matched-set comparison, not a density-scaled
whole-window extrapolation.

Usage: python3 tools/ibd_matched_calib.py <corpus.bin> <replay.jsonl>
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ibd_census import census_tx, der_shaped, pushes  # noqa: E402


def parse_corpus(path):
    raw = Path(path).read_bytes()
    assert raw[:8] == b"AVCORP02", "expect AVCORP02 corpus"
    o = 8
    blocks = []
    while o < len(raw):
        height = struct.unpack_from("<I", raw, o)[0]
        o += 4
        bhash = raw[o:o + 32]
        o += 32
        n_tx = struct.unpack_from("<I", raw, o)[0]
        o += 4
        txs = []
        for _ in range(n_tx):
            n = struct.unpack_from("<I", raw, o)[0]
            o += 4
            rawtx = raw[o:o + n]
            o += n
            n_in = struct.unpack_from("<I", raw, o)[0]
            o += 4
            srcs = []
            for _ in range(n_in):
                if raw[o] == 0:
                    o += 1
                    srcs.append(None)
                else:
                    o += 1
                    o += 8  # value
                    sl = struct.unpack_from("<I", raw, o)[0]
                    o += 4
                    o += sl  # scriptPubKey
                    create_h = struct.unpack_from("<I", raw, o)[0]
                    o += 4
                    is_cb = raw[o] & 1
                    o += 1
                    srcs.append((create_h, is_cb))
            txs.append((rawtx, srcs))
        blocks.append((height, bhash, txs))
    return blocks


def main():
    corpus_path, replay_path = sys.argv[1], sys.argv[2]
    runs = [json.loads(l) for l in Path(replay_path).read_text().splitlines()
            if l.strip()]
    counters = next(r for r in runs if r["type"] == "counters")
    run = next(r for r in runs if r["type"] == "run")
    want_digest = counters["executed_set_digest"]

    sel = bytearray()
    structural = {"ecdsa_der_attempts": 0, "witness_der_attempts": 0,
                  "schnorr_sized_items": 0, "executed_txs": 0,
                  "executed_inputs": 0}
    for height, bhash, txs in parse_corpus(corpus_path):
        for txidx, (rawtx, srcs) in enumerate(txs):
            n_in = len(srcs)
            if n_in == 0:
                continue
            _, rec = census_tx(rawtx, 0)
            is_cb = (n_in == 1 and len(rec["inputs"]) == 1
                     and rec["inputs"][0][2] == b"\x00" * 32 + b"\xff" * 4)
            if is_cb:
                continue
            n_missing = sum(1 for s in srcs if s is None)
            n_immature = sum(1 for s in srcs
                             if s is not None and s[1]
                             and height < s[0] + 100)
            if n_missing or n_immature:
                continue
            # executed tx — append membership record
            sel += bhash + struct.pack("<I", txidx)
            structural["executed_txs"] += 1
            structural["executed_inputs"] += n_in
            for j, (script, _seq, _prev) in enumerate(rec["inputs"]):
                for _k, v in (it for it in pushes(script) if it[0] == "push"):
                    if der_shaped(v):
                        structural["ecdsa_der_attempts"] += 1
                wit = rec["witnesses"][j] if j < len(rec["witnesses"]) else []
                for w in wit:
                    if der_shaped(w):
                        structural["witness_der_attempts"] += 1
                    elif len(w) in (64, 65):
                        structural["schnorr_sized_items"] += 1

    got_digest = hashlib.sha256(bytes(sel)).hexdigest()
    matched = got_digest == want_digest
    out = {
        "selection_digest_match": matched,
        "selection_digest_python": got_digest,
        "selection_digest_rust": want_digest,
        "executed_txs_python": structural["executed_txs"],
        "executed_txs_rust": counters["executed_txs"],
        "executed_inputs_python": structural["executed_inputs"],
        "executed_inputs_rust": counters["executed_inputs"],
        "structural_ecdsa_der_attempts": structural["ecdsa_der_attempts"],
        "structural_witness_der_attempts": structural["witness_der_attempts"],
        "structural_schnorr_sized_items": structural["schnorr_sized_items"],
        "executed_ecdsa_verify_attempts": run["ecdsa_verify_attempts"],
        "executed_schnorr_verify_attempts": run["schnorr_verify_attempts"],
    }
    if matched:
        out["ecdsa_ratio"] = round(
            structural["ecdsa_der_attempts"] / max(run["ecdsa_verify_attempts"], 1), 4)
    print(json.dumps(out, indent=1))
    if not matched:
        sys.exit(2)


if __name__ == "__main__":
    main()
