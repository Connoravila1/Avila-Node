#!/usr/bin/env python3
"""Build a corpus-resolved script-replay window from raw blk files.

Two passes over a bounded set of blkNNNNN.dat records (Avila plain framing or
Core xor encoding via --xor-key):

  pass 1 (index):   txid -> list of occurrences (height, tx_index_in_block,
                    file_idx, record_offset, tx_offset_in_record, tx_len).
                    Occurrences model BIP30-style same-txid re-creation; file
                    order is NOT assumed to be chain order (heights from BIP34
                    coinbases; records lacking a height are dropped+counted).
  pass 2 (emit):    for each tx in --window-files (blocks sorted by height):
                    each input's prevout is resolved to the *latest occurrence*
                    with (height, txidx) strictly before the spender's
                    (height, txidx) — same-block earlier-tx spends included,
                    future sources excluded. The source tx is re-read from
                    its file to extract the referenced (value, scriptPubKey).

Output corpus.bin (magic AVCORP01) embeds window txs in chain order with
per-input resolved TxOuts (or an unresolved marker) plus each block's height
and hash — enough for the replay driver to derive exact consensus script
flags via block_script_flags(). Provenance is a local blk-store scan;
the manifest labels resolution coverage and every skipped class.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

MAGIC = {"mainnet": bytes.fromhex("f9beb4d9"), "signet": bytes.fromhex("0a03cf40"),
         "testnet": bytes.fromhex("0b110907"), "regtest": bytes.fromhex("fabfb5da")}


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def compact(d, o):
    f = d[o]
    if f < 253:
        return f, o + 1
    s = {253: 2, 254: 4, 255: 8}[f]
    return int.from_bytes(d[o + 1:o + 1 + s], "little"), o + 1 + s


def bip34_height(b):
    try:
        _, o = compact(b, 80)
        o += 4
        if b[o:o + 2] == b"\x00\x01":
            o += 2
        c, o = compact(b, o)
        if c != 1:
            return None
        o += 36
        sz, o = compact(b, o)
        p = b[o]
        if not 1 <= p <= 5 or sz < 1 + p:
            return None
        h = int.from_bytes(b[o + 1:o + 1 + p], "little")
        return h if 1 <= h <= 2_000_000 else None
    except Exception:
        return None


def tx_spans(block):
    """Yield (tx_offset, tx_len, stripped_len) for each tx in a block."""
    o = 80
    n, o = compact(block, o)
    for _ in range(n):
        start = o
        segwit = block[o + 4:o + 6] == b"\x00\x01"
        vin_start = o + (6 if segwit else 4)
        ni, o = compact(block, vin_start)
        for _ in range(ni):
            o += 36
            sl, o = compact(block, o)
            o += sl + 4
        no, o = compact(block, o)
        out_start = o
        for _ in range(no):
            o += 8
            sl, o = compact(block, o)
            o += sl
        wit_start = o
        if segwit:
            for _ in range(ni):
                cnt, o = compact(block, o)
                for _ in range(cnt):
                    il, o = compact(block, o)
                    o += il
        o += 4  # locktime
        # stripped serialization = full tx minus marker/flag (2B) minus the
        # witness region (wit_start .. o-4 before locktime) for segwit txs.
        stripped = (o - start) if not segwit else (o - start) - 2 - (o - 4 - wit_start)
        yield start, o - start, stripped


def parse_tx_io(block, tstart):
    """Return (inputs[(txid,vout)], outputs[(value,spk)]) for tx at tstart."""
    o = tstart
    segwit = block[o + 4:o + 6] == b"\x00\x01"
    o += 6 if segwit else 4
    ni, o = compact(block, o)
    ins = []
    for _ in range(ni):
        prev = block[o:o + 32]
        vout = struct.unpack_from("<I", block, o + 32)[0]
        o += 36
        sl, o = compact(block, o)
        o += sl + 4
        ins.append((prev, vout))
    no, o = compact(block, o)
    outs = []
    for _ in range(no):
        value = struct.unpack_from("<q", block, o)[0]
        o += 8
        sl, o = compact(block, o)
        outs.append((value, block[o:o + sl]))
        o += sl
    return ins, outs


def stripped_txid(block, tstart, tlen, stripped_len):
    """Compute txid: sha256d over the stripped serialization."""
    tx = block[tstart:tstart + tlen]
    segwit = tx[4:6] == b"\x00\x01"
    if not segwit:
        return sha256d(tx)
    # strip marker+flag and witness section
    o = 6
    ni, o = compact(tx, o)
    for _ in range(ni):
        o += 36
        sl, o = compact(tx, o)
        o += sl + 4
    no, o = compact(tx, o)
    for _ in range(no):
        o += 8
        sl, o = compact(tx, o)
        o += sl
    wit_start = o
    stripped = tx[:4] + tx[6:wit_start] + tx[-4:]
    return sha256d(stripped)


def records(path, key):
    data = path.read_bytes()
    if key:
        b = bytearray(data)
        for i, k in enumerate(key):
            b[i::8] = b[i::8].translate(bytes(v ^ k for v in range(256)))
        data = bytes(b)
    magic = None
    for m in MAGIC.values():
        if data[:4] == m:
            magic = m
    if magic is None:
        return
    off = 0
    while off + 8 <= len(data):
        if data[off:off + 4] != magic:
            break
        n = struct.unpack_from("<I", data, off + 4)[0]
        if not 1 <= n <= 16 << 20 or off + 8 + n > len(data):
            break
        yield off + 8, data[off + 8:off + 8 + n]
        off += 8 + n


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--span-files", nargs="+", type=Path, required=True,
                    help="files indexed for prevout resolution (include window files)")
    ap.add_argument("--window-files", nargs="+", type=Path, required=True)
    ap.add_argument("--xor-key", type=Path)
    ap.add_argument("--out", type=Path, required=True, help="output directory")
    args = ap.parse_args()
    key = args.xor_key.read_bytes() if args.xor_key else b""

    span = list(args.span_files)
    manifest = {"span_files": [], "window_files": [str(f) for f in args.window_files],
                "labels": {"provenance": "local blk-store scan (corpus-resolved prevouts)",
                           "occurrence_model": "latest (height,txidx) < (spend_height,spend_idx)",
                           "ordering": "blocks sorted by BIP34 height; file order not trusted"}}
    index = {}          # txid -> [occurrence, ...]
    dropped_no_height = 0
    for fi, f in enumerate(span):
        sha = hashlib.sha256(f.read_bytes()).hexdigest()
        meta = {"file": str(f), "sha256": sha, "records": 0}
        blocks = []
        for off, rec in records(f, key):
            h = bip34_height(rec)
            if h is None:
                dropped_no_height += 1
                continue
            blocks.append((h, off, rec))
            meta["records"] += 1
        for h, off, rec in blocks:
            for ti, (tstart, tlen, _slen) in enumerate(tx_spans(rec)):
                ins, _outs = parse_tx_io(rec, tstart)
                is_cb = len(ins) == 1 and ins[0][0] == b"\x00" * 32
                txid = stripped_txid(rec, tstart, tlen, _slen)
                # (height, txidx, file_idx, record_off, tx_off, tx_len, coinbase)
                index.setdefault(txid, []).append(
                    (h, ti, fi, off, tstart, tlen, is_cb))
        manifest["span_files"].append(meta)

    # Resolve the window. Two bounded phases:
    #  (a) walk window txs, choose the occurrence for each input, collect the
    #      set of needed source-tx positions grouped by file;
    #  (b) one pass per referenced file extracting (value, scriptPubKey) for
    #      the referenced vouts — never re-reads a file per input.
    args.out.mkdir(parents=True, exist_ok=True)
    stats = {"blocks": 0, "txs": 0, "inputs": 0, "resolved": 0,
             "unresolved_no_occurrence": 0, "unresolved_future_only": 0,
             "unresolved_bad_vout": 0, "coinbase_inputs": 0,
             "duplicate_txid_occurrences": sum(1 for v in index.values() if len(v) > 1)}
    heights_seen = []
    plan = []  # [(height, blockhash, [(raw_tx, [spec_or_None_per_input]), ...])]
    need = {}  # file_idx -> {off: {tstart: set(vout)}}
    for f in args.window_files:
        win_blocks = []
        for _off, rec in records(f, key):
            h = bip34_height(rec)
            if h is None:
                stats["dropped_window_no_height"] = stats.get("dropped_window_no_height", 0) + 1
                continue
            win_blocks.append((h, rec))
        win_blocks.sort(key=lambda x: x[0])
        for h, rec in win_blocks:
            stats["blocks"] += 1
            heights_seen.append(h)
            blockhash = sha256d(rec[:80])
            header80 = rec[:80]  # version|prev|merkle|time|bits|nonce
            txs = []
            for ti, (tstart, tlen, _slen) in enumerate(tx_spans(rec)):
                ins, _outs = parse_tx_io(rec, tstart)
                raw = rec[tstart:tstart + tlen]
                is_cb = len(ins) == 1 and ins[0][0] == b"\x00" * 32
                stats["txs"] += 1
                if is_cb:
                    stats["coinbase_inputs"] += len(ins)
                specs = []
                for (prevtx, vout) in ins:
                    if is_cb:
                        specs.append(None)
                        continue
                    stats["inputs"] += 1
                    occs = index.get(prevtx, [])
                    cand = [o for o in occs if (o[0], o[1]) < (h, ti)]
                    if not cand:
                        specs.append(None)
                        stats["unresolved_no_occurrence" if not occs
                              else "unresolved_future_only"] += 1
                        continue
                    occ = max(cand)  # (h2,ti2,fi2,off2,tstart2,tlen2,is_cb)
                    # need[fi][off][tstart] = (tlen, [(prevtx, vout), ...])
                    grp = need.setdefault(occ[2], {}).setdefault(occ[3], {}) \
                        .setdefault(occ[4], [occ[5], []])
                    grp[1].append((prevtx, vout))
                    # spec carries FULL source identity + creation metadata
                    specs.append((occ[2], occ[3], occ[4], occ[5],
                                  vout, prevtx, occ[0], occ[6]))
                txs.append((raw, specs))
            plan.append((h, blockhash, header80, txs))
    # Pass 3: fetch referenced outputs, one pass per file. The source tx's
    # txid is recomputed and checked against the txid named in the spending
    # outpoint — a wrong record/offset match surfaces as an explicit identity
    # mismatch, never as silently returned data.
    resolved_map = {}  # (fi, off, tstart, vout) -> (value, spk)
    for fi, by_off in need.items():
        wanted_offs = set(by_off)
        for off, rec in records(span[fi], key):
            if off not in wanted_offs:
                continue
            for tstart, (tlen, reqs) in by_off[off].items():
                _ins, outs = parse_tx_io(rec, tstart)
                txid2 = stripped_txid(rec, tstart, tlen, 0)
                for (prevtx, vout) in reqs:
                    if txid2 != prevtx:
                        stats["txid_identity_mismatch"] = \
                            stats.get("txid_identity_mismatch", 0) + 1
                        continue
                    if vout < len(outs):
                        resolved_map[(fi, off, tstart, vout)] = outs[vout]
                    else:
                        stats["unresolved_bad_vout"] += 1
    # Emit corpus (AVCORP03: block record carries the raw 80-byte header —
    # hash/parent linkage, block time, bits and merkle root are all
    # verifiable downstream; per resolved input appends creation_height u32
    # and a source_flags byte — bit0 = coinbase source).
    outbuf = bytearray(b"AVCORP03")
    headers_manifest = []
    for (h, blockhash, header80, txs) in plan:
        headers_manifest.append({
            "height": h,
            "hash": blockhash[::-1].hex(),
            "parent": header80[4:36][::-1].hex(),
            "time": struct.unpack_from("<I", header80, 68)[0],
            "bits": struct.unpack_from("<I", header80, 72)[0],
        })
        outbuf += struct.pack("<I", h) + blockhash + header80
        outbuf += struct.pack("<I", len(txs))
        for (raw, specs) in txs:
            outbuf += struct.pack("<I", len(raw)) + raw + struct.pack("<I", len(specs))
            for spec in specs:
                if spec is None:
                    outbuf.append(0)
                    continue
                (fi2, off2, tstart2, _tlen2, vout, _prevtx, create_h, is_cb) = spec
                got = resolved_map.get((fi2, off2, tstart2, vout))
                if got is None:
                    outbuf.append(0)
                    continue
                if is_cb and h - create_h < 100:
                    stats["immature_coinbase_refs"] = \
                        stats.get("immature_coinbase_refs", 0) + 1
                value, spk = got
                outbuf.append(1)
                outbuf += struct.pack("<q", value) + struct.pack("<I", len(spk)) + spk
                outbuf += struct.pack("<I", create_h) + bytes([1 if is_cb else 0])
                stats["resolved"] += 1
    (args.out / "corpus.bin").write_bytes(bytes(outbuf))
    if stats.get("txid_identity_mismatch", 0):
        # A re-verification failure means resolved prevouts cannot be
        # trusted — the manifest is still written (diagnostics preserved)
        # but the run fails rather than shrink the sample silently.
        manifest["window"] = {"stats": stats}
        (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2))
        sys.exit(f"txid_identity_mismatch={stats['txid_identity_mismatch']}: "
                 "source re-verification failed; corpus not trustworthy")
    manifest["window"] = {"height_min": min(heights_seen) if heights_seen else None,
                          "height_max": max(heights_seen) if heights_seen else None,
                          "stats": stats,
                          "corpus_sha256": hashlib.sha256(bytes(outbuf)).hexdigest(),
                          "corpus_bytes": len(outbuf)}
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    with open(args.out / "headers.jsonl", "w") as hf:
        for row in headers_manifest:
            hf.write(json.dumps(row) + "\n")
    print(json.dumps({"blocks": stats["blocks"], "txs": stats["txs"],
                      "inputs": stats["inputs"], "resolved": stats["resolved"],
                      "heights": manifest["window"]["height_min"],
                      "to": manifest["window"]["height_max"]}))


if __name__ == "__main__":
    main()
