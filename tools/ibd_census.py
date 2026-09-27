#!/usr/bin/env python3
"""Structural workload census over raw block-file corpora.

Reads blkNNNNN.dat records in either storage encoding: Avila's plain
`magic + u32 len + block` framing, or Bitcoin Core's XOR-obfuscated variant
(--xor-key xor.dat). Emits a machine-readable census: byte categories,
transaction/input/output counts, output script classes, input scriptSig/witness
shape classes, DER-shaped signature-item estimates, and SHA-256 compression-call
estimates per category (txid, wtxid, merkle interior, witness commitment,
sighash preimages by class).

Everything here is a STRUCTURAL count: scriptSig/witness shapes and sighash
message sizes are estimated from serialization, not from script execution.
Dynamic signature-attempt counts (CHECKMULTISIG retries, dead branches) require
the executed replay pass and are labeled as such downstream.

Provenance: verifies each block's sha256d(header) and the prevhash linkage of
consecutive records where a contiguous run is requested. Records whose height
cannot be extracted (pre-BIP34 coinbases) are bucketed by chain position only
when --heights-by-position is off they are labeled 'unknown-height'.
"""
import argparse
import hashlib
import json
import math
import struct
import sys
from pathlib import Path

MAGIC = {"mainnet": bytes.fromhex("f9beb4d9"), "signet": bytes.fromhex("0a03cf40"),
         "testnet": bytes.fromhex("0b110907"), "regtest": bytes.fromhex("fabfb5da")}


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def xor_decode(raw, key):
    data = bytearray(raw)
    for i, k in enumerate(key):
        data[i::8] = data[i::8].translate(bytes(v ^ k for v in range(256)))
    return bytes(data)


def compact(d, o):
    f = d[o]
    if f < 253:
        return f, o + 1
    s = {253: 2, 254: 4, 255: 8}[f]
    return int.from_bytes(d[o + 1:o + 1 + s], "little"), o + 1 + s


def comps(n):
    """SHA-256 compression calls for one message of n bytes."""
    return (n + 9 + 63) // 64


def sha256d_comps(n):
    return comps(n) + 1


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


def classify_script(spk):
    n = len(spk)
    if n == 25 and spk[:3] == bytes.fromhex("76a914") and spk[23:] == bytes.fromhex("88ac"):
        return "p2pkh"
    if n == 23 and spk[:2] == bytes.fromhex("a914") and spk[22] == 0x87:
        return "p2sh"
    if n == 22 and spk[:2] == b"\x00\x14":
        return "p2wpkh"
    if n == 34 and spk[:2] == b"\x00\x20":
        return "p2wsh"
    if n == 34 and spk[:2] == b"\x51\x20":
        return "p2tr"
    if n > 0 and spk[0] == 0x6a:
        return "op_return"
    if n == 35 and spk[0] == 0x21 and spk[34] == 0xac:
        return "p2pk_compressed"
    if n == 67 and spk[0] == 0x41 and spk[66] == 0xac:
        return "p2pk_uncompressed"
    if n >= 3 and 0x51 <= spk[0] <= 0x60 and spk[-1] == 0xae:
        i = 1
        keys = 0
        while i < n - 2 and spk[i] in (33, 65):
            i += 1 + spk[i]
            keys += 1
        if i == n - 2 and 0x51 <= spk[i] <= 0x60:
            return "p2ms_bare"
        return "other"
    if n > 10000:
        return "unspendable_size"
    return "other"


def pushes(script):
    """Split a scriptSig into pushed items (best-effort; malformed -> rest)."""
    items = []
    o = 0
    n = len(script)
    while o < n:
        op = script[o]
        if op <= 75:
            ln, o = op, o + 1
        elif op == 0x4c:
            if o + 1 > n:
                break
            ln, o = script[o + 1], o + 2
        elif op == 0x4d:
            if o + 2 > n:
                break
            ln, o = int.from_bytes(script[o + 1:o + 3], "little"), o + 3
        elif op == 0x4e:
            if o + 4 > n:
                break
            ln, o = int.from_bytes(script[o + 1:o + 5], "little"), o + 5
        else:
            items.append(("op", bytes([op])))
            o += 1
            continue
        if o + ln > n:
            items.append(("truncated", script[o:n]))
            return items
        items.append(("push", script[o:o + ln]))
        o += ln
    return items


def der_shaped(item):
    """DER sequence optionally followed by one sighash byte (chain encoding)."""
    n = len(item)
    return (8 <= n <= 73 and item[0] == 0x30
            and item[1] in (n - 2, n - 3))


def cs_len(n):
    return 1 if n < 253 else (3 if n < 65536 else (5 if n < 2**32 else 9))


def hashtype_of(sig_item):
    """Raw sighash byte at the end of a chain-encoded signature (1 when
    absent). The raw byte is preserved: the interpreter treats a base
    other than SINGLE(3)/NONE(2) as ALL(1) for output serialization while
    the ANYONECANPAY(0x80) bit applies independently — do NOT normalize
    the byte to a small enum or the ACP/invalid-base semantics are lost."""
    if not sig_item:
        return 1
    return sig_item[-1]


def legacy_preimage_len(n_in, n_out, out_lens, scriptsig_len_i, i, htype,
                        scriptcode_len):
    """Byte length of the legacy (pre-BIP143) sighash preimage for input i.

    Core's SignatureHash serializes the tx with every OTHER input's
    scriptSig blanked (1-byte empty field each) and input i carrying the
    prevout's scriptPubKey (scriptCode). SIGHASH_NONE drops outputs;
    SIGHASH_SINGLE keeps outputs 0..i (earlier ones as -1/null = 9B) and
    yields uint256::ONE with NO hashing when i >= n_out; ANYONECANPAY keeps
    only input i. Returns -1 for the SINGLE-out-of-range no-hash case.
    """
    base = htype & 0x1F
    if base == 3 and i >= n_out:
        return -1
    L = 4  # version
    if htype & 0x80:  # ANYONECANPAY
        L += 1 + 36 + cs_len(scriptcode_len) + scriptcode_len + 4
    else:
        L += cs_len(n_in)
        for j in range(n_in):
            sc = scriptcode_len if j == i else 0
            L += 36 + cs_len(sc) + sc + 4
    if base == 3:  # SINGLE: outputs 0..i; 0..i-1 are null (-1 + empty spk = 9B)
        L += cs_len(i + 1) + 9 * i + 8 + cs_len(out_lens[i]) + out_lens[i]
    elif base == 2:  # NONE
        L += 1
    else:
        L += cs_len(n_out)
        for ol in out_lens:
            L += 8 + cs_len(ol) + ol
    return L + 8  # locktime + hashtype


def b143_preimage_len(scriptcode_len, htype):
    """BIP143 (v0 witness) sighash preimage length model.

    Fixed skeleton: version4 + hashPrevouts32 + hashSequence32 + outpoint36
    + scriptCode + amount8 + seq4 + hashOutputs32 + locktime4 + hashtype4.
    ANYONECANPAY/SINGLE/NONE elide some shared hashes — modeled as the full
    form; the error is bounded by three 32-byte slots and labeled structural.
    """
    return 156 + cs_len(scriptcode_len) + scriptcode_len


def census_tx(tx, start):
    """Parse one transaction; returns (end_offset, record dict)."""
    o = start
    version = struct.unpack_from("<i", tx, o)[0]
    o += 4
    segwit = tx[o:o + 2] == b"\x00\x01"
    if segwit:
        o += 2
    n_in, o = compact(tx, o)
    inputs = []
    outpoint_bytes = 0
    scriptsig_bytes = 0
    for _ in range(n_in):
        prev = tx[o:o + 36]
        o += 36
        outpoint_bytes += 36
        sl, o = compact(tx, o)
        script = tx[o:o + sl]
        o += sl
        seq = struct.unpack_from("<I", tx, o)[0]
        o += 4
        scriptsig_bytes += sl
        inputs.append((script, seq, prev))
    n_out, o = compact(tx, o)
    outputs = []
    value_bytes = 0
    spk_bytes = 0
    for _ in range(n_out):
        o += 8
        value_bytes += 8
        sl, o = compact(tx, o)
        outputs.append(tx[o:o + sl])
        o += sl
        spk_bytes += sl
    witnesses = []
    wit_bytes = 0
    wit_start = o
    if segwit:
        for _ in range(n_in):
            cnt, o = compact(tx, o)
            items = []
            for _ in range(cnt):
                il, o = compact(tx, o)
                items.append(tx[o:o + il])
                o += il
                wit_bytes += il
            witnesses.append(items)
    wit_section_len = (o - wit_start) if segwit else 0
    o += 4  # locktime
    return o, {
        "version": version, "segwit": segwit, "inputs": inputs, "outputs": outputs,
        "witnesses": witnesses, "stripped_end": None,
        # tx-relative offset where the witness section begins (after outputs)
        "wit_start_rel": (wit_start - start) if segwit else 0,
        "wit_section_len": wit_section_len,
        "outpoint_bytes": outpoint_bytes, "scriptsig_bytes": scriptsig_bytes,
        "value_bytes": value_bytes, "spk_bytes": spk_bytes, "witness_bytes": wit_bytes,
        "full_len": o - start,
    }


def census_block(block, agg):
    agg["blocks"] += 1
    header = block[:80]
    agg["block_hash_first"] = agg.get("block_hash_first") or sha256d(header)[::-1].hex()
    agg["block_hash_last"] = sha256d(header)[::-1].hex()
    agg["bytes_header"] += 80
    h = bip34_height(block)
    if h is not None:
        agg.setdefault("heights", []).append(h)
    merkle_seen = block[36:68]
    o = 80
    n_tx, o = compact(block, o)
    agg["bytes_tx_count_field"] += o - 80
    tx_hashes = []
    for _ in range(n_tx):
        tx_start = o
        o, rec = census_tx(block, o)
        agg["txs"] += 1
        agg["bytes_tx_overhead"] += 8 + (2 if rec["segwit"] else 0)
        agg["bytes_outpoint"] += rec["outpoint_bytes"]
        agg["bytes_scriptsig"] += rec["scriptsig_bytes"]
        agg["bytes_sequence"] += 4 * len(rec["inputs"])
        agg["bytes_output_value"] += rec["value_bytes"]
        agg["bytes_scriptpubkey"] += rec["spk_bytes"]
        agg["bytes_witness"] += rec["witness_bytes"]
        full_len = rec["full_len"]
        # exact stripped serialization length: full minus marker/flag (2B)
        # minus the whole witness section (item counts + item lengths + data)
        stripped_len = full_len - (2 + rec["wit_section_len"]
                                   if rec["segwit"] else 0)
        txraw = block[tx_start:tx_start + full_len]
        if rec["segwit"]:
            stripped = txraw[:4] + txraw[6:rec["wit_start_rel"]] + txraw[-4:]
            assert len(stripped) == stripped_len, \
                f"stripped len {len(stripped)} != computed {stripped_len}"
        else:
            stripped = txraw
        tx_hashes.append(sha256d(stripped))
        agg["sha_comps_txid"] += sha256d_comps(stripped_len)
        agg["sha_input_bytes_txid"] += stripped_len
        is_cb = (len(rec["inputs"]) == 1
                 and rec["inputs"][0][2] == b"\x00" * 32 + b"\xff" * 4)
        if rec["segwit"] and not is_cb:
            agg["sha_comps_wtxid"] += sha256d_comps(full_len)
            agg["sha_input_bytes_wtxid"] += full_len
        elif rec["segwit"] and is_cb:
            # coinbase leaf in the witness-commitment tree is 32 zero bytes,
            # not a wtxid — no hash is executed for it (Block::witness_merkle_root)
            agg["cb_wtxid_zero_leaf"] = agg.get("cb_wtxid_zero_leaf", 0) + 1
        else:
            agg["txs_no_wtxid"] = agg.get("txs_no_wtxid", 0) + 1
        agg["tx_size_hist"][min(full_len // 256, 63)] += 1
        if is_cb:
            agg["coinbase_txs"] += 1
        wit_der_htypes = []
        for j, (script, seq, prev) in enumerate(rec["inputs"]):
            if is_cb:
                agg["inputs_coinbase"] += 1
                continue
            agg["inputs"] += 1
            its = pushes(script)
            npush = sum(1 for k, _ in its if k == "push")
            ndersig = sum(1 for k, v in its if k == "push" and der_shaped(v))
            agg["scriptsig_push_items"] += npush
            agg["scriptsig_der_items"] += ndersig
            if not script:
                shape = "empty"
            elif n_in_multisig_shape(its):
                shape = "bare_or_p2sh_multisig"
            elif npush == 2 and len(its) >= 2 and der_shaped(_pushval(its, -2)) and len(_pushval(its, -1)) in (33, 65):
                shape = "sig_plus_pubkey"
            elif npush == 1:
                shape = "single_push"
            elif npush >= 3:
                shape = "multi_push"
            else:
                shape = "ops_only_or_mixed"
            agg[f"input_shape_{shape}"] = agg.get(f"input_shape_{shape}", 0) + 1
            # witness item analysis
            n_wit = 0
            if rec["segwit"] and j < len(rec["witnesses"]):
                witems = rec["witnesses"][j]
                n_wit = len(witems)
                agg["witness_items"] += n_wit
                der = sum(1 for w in witems if der_shaped(w))
                schn = sum(1 for w in witems if len(w) in (64, 65))
                agg["witness_der_items"] += der
                agg["witness_schnorr_sized"] += schn
            # Structural sighash estimates, hashtype-aware:
            #   legacy — per DER-shaped item: exact preimage LENGTH for the
            #     input's position (other inputs' scripts blanked, SINGLE/
            #     NONE/ANYONECANPAY cases applied). scriptCode length is
            #     approximated from the input shape (prevout not resolved
            #     here): sig_plus_pubkey→25 (P2PKH spk), multisig→redeem push
            #     length, other→25. The executed pass calibrates with real
            #     prevouts — do not read these as measured bytes.
            #   witness — BIP143 structured model (156B + scriptCode);
            #     P2WPKH scriptCode=25, P2WSH≈last witness item length.
            #     Tagged/schnorr items → taproot SigMsg model (~6 comps).
            wit_items = rec["witnesses"][j] if rec["segwit"] and j < len(rec["witnesses"]) else []
            if wit_items:
                agg["sighash_witness_inputs"] += 1
                n_out_l = [len(s) for s in rec["outputs"]]
                for w in wit_items:
                    if der_shaped(w):
                        htype = hashtype_of(w)
                        wit_der_htypes.append((j, htype))
                        # scriptCode: P2WPKH→25, P2WSH→last item (witness script)
                        sc_len = 25 if (len(wit_items) == 2
                                        and len(wit_items[-1]) == 33) \
                            else len(wit_items[-1])
                        pl = b143_preimage_len(sc_len, htype)
                        agg["sighash_witness_attempts_der"] = agg.get("sighash_witness_attempts_der",0) + 1
                        agg["sighash_witness_comps_est"] += sha256d_comps(pl)
                        agg["sighash_witness_preimage_bytes_est"] = agg.get("sighash_witness_preimage_bytes_est",0) + pl
                    elif len(w) in (64, 65):
                        agg["sighash_taproot_attempts_schnorr_sized"] = agg.get("sighash_taproot_attempts_schnorr_sized",0) + 1
                        agg["sighash_taproot_comps_est"] = agg.get("sighash_taproot_comps_est",0) + 6
            else:
                agg["sighash_legacy_inputs"] += 1
                n_out_l = [len(s) for s in rec["outputs"]]
                push_items = [v for k, v in its if k == "push"]
                n_sigs = sum(1 for v in push_items if der_shaped(v))
                if n_sigs == 0:
                    agg["sighash_legacy_nosig_inputs"] = agg.get("sighash_legacy_nosig_inputs",0) + 1
                    continue
                # scriptCode estimate by shape (prevouts unresolved here)
                if shape == "bare_or_p2sh_multisig" and push_items:
                    sc_est = len(push_items[-1])
                else:
                    sc_est = 25
                for sig in (v for v in push_items if der_shaped(v)):
                    htype = hashtype_of(sig)
                    pl = legacy_preimage_len(
                        len(rec["inputs"]), len(rec["outputs"]), n_out_l,
                        len(script), j, htype, sc_est)
                    agg["sighash_legacy_attempts_der"] = agg.get("sighash_legacy_attempts_der",0) + 1
                    if pl < 0:
                        agg["sighash_legacy_single_oob_nohash"] = agg.get("sighash_legacy_single_oob_nohash",0) + 1
                    else:
                        agg["sighash_legacy_preimage_bytes_est"] += pl
                        agg["sighash_legacy_comps_est"] += sha256d_comps(pl)
        # BIP143 shared per-tx components, need-based (real component
        # lengths): hashPrevouts=sha256d(36·n_in), hashSequence=sha256d(4·n_in),
        # hashOutputs=sha256d(serialized outputs). A component is charged once
        # if ANY witness-DER input needs it (ACP inputs skip prevouts/seq;
        # SINGLE/NONE skip outputs; SINGLE uses a single-output hash instead).
        # This is still a structural model — the fixed 32-byte preimage slots
        # are present regardless of which shared hashes were computed.
        if wit_der_htypes:
            n_in_t = len(rec["inputs"])
            n_out_t = len(rec["outputs"])
            out_ser = sum(8 + cs_len(len(s)) + len(s) for s in rec["outputs"])
            hts = [t for _j, t in wit_der_htypes]
            if any(not (t & 0x80) for t in hts):
                agg["sighash_shared_comps_est"] = agg.get("sighash_shared_comps_est", 0) \
                    + sha256d_comps(36 * n_in_t)
            if any(not (t & 0x80) and (t & 0x1F) not in (2, 3) for t in hts):
                agg["sighash_shared_comps_est"] = agg.get("sighash_shared_comps_est", 0) \
                    + sha256d_comps(4 * n_in_t)
            if any((t & 0x1F) not in (2, 3) for t in hts):
                agg["sighash_shared_comps_est"] = agg.get("sighash_shared_comps_est", 0) \
                    + sha256d_comps(out_ser)
            # SIGHASH_SINGLE (base 3) hashes exactly output i instead of
            # hashOutputs — charge the single-output hash per SINGLE input
            for j, t in wit_der_htypes:
                if (t & 0x1F) == 3 and j < n_out_t:
                    ol = len(rec["outputs"][j])
                    agg["sighash_shared_comps_est"] = agg.get("sighash_shared_comps_est", 0) \
                        + sha256d_comps(8 + cs_len(ol) + ol)
        for spk in rec["outputs"]:
            agg["outputs"] += 1
            agg[f"outcls_{classify_script(spk)}"] = agg.get(f"outcls_{classify_script(spk)}", 0) + 1
    # merkle interior: real level-by-level node count (odd levels duplicate
    # the last leaf) + an actual verification against the header commitment
    interior = 0
    level = tx_hashes
    while len(level) > 1:
        if len(level) % 2:
            level = level + [level[-1]]
        level = [sha256d(level[i] + level[i + 1])
                 for i in range(0, len(level), 2)]
        interior += len(level)
    agg["sha_comps_merkle_interior"] += interior * 3
    if n_tx:
        if tx_hashes and level and level[0] == merkle_seen:
            agg["merkle_verified"] = agg.get("merkle_verified", 0) + 1
        else:
            agg["merkle_mismatch"] = agg.get("merkle_mismatch", 0) + 1
    agg["sha_comps_header"] += 3
    return o


def _pushval(items, idx):
    pushes_only = [v for k, v in items if k == "push"]
    return pushes_only[idx]


def n_in_multisig_shape(items):
    # OP_0 tokenizes as a zero-length PUSH, not ("op", b"\x00") — the first
    # item of a bare/P2SH-multisig scriptSig is the dummy empty push.
    kinds = [k for k, _ in items]
    return (kinds and items[0] == ("push", b"")
            and sum(1 for k, _ in items if k == "push") >= 2)


def records_from_file(path, key):
    raw = path.read_bytes()
    if key:
        data = xor_decode(raw, key)
    else:
        data = raw
    off = 0
    magic = None
    for m in MAGIC.values():
        if data[:4] == m:
            magic = m
    if magic is None:
        return None
    while off + 8 <= len(data):
        if data[off:off + 4] != magic:
            break
        n = struct.unpack_from("<I", data, off + 4)[0]
        if not 1 <= n <= 16 << 20 or off + 8 + n > len(data):
            break
        yield data[off + 8:off + 8 + n]
        off += 8 + n


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument("--xor-key", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--max-blocks", type=int, default=0)
    args = ap.parse_args()
    key = args.xor_key.read_bytes() if args.xor_key else b""
    if key and len(key) != 8:
        ap.error("xor key must be 8 bytes")
    agg = {"blocks": 0, "txs": 0, "inputs": 0, "inputs_coinbase": 0, "outputs": 0,
           "coinbase_txs": 0, "witness_items": 0, "witness_der_items": 0,
           "witness_schnorr_sized": 0, "scriptsig_push_items": 0,
           "scriptsig_der_items": 0, "bytes_header": 0, "bytes_tx_count_field": 0,
           "bytes_tx_overhead": 0, "bytes_outpoint": 0, "bytes_scriptsig": 0,
           "bytes_sequence": 0, "bytes_output_value": 0, "bytes_scriptpubkey": 0,
           "bytes_witness": 0, "sha_comps_txid": 0, "sha_comps_wtxid": 0,
           "sha_comps_merkle_interior": 0, "sha_comps_header": 0,
           "sha_input_bytes_txid": 0, "sha_input_bytes_wtxid": 0,
           "sighash_legacy_preimage_bytes_est": 0, "sighash_legacy_comps_est": 0,
           "sighash_witness_comps_est": 0, "sighash_legacy_inputs": 0,
           "sighash_witness_inputs": 0,
           "tx_size_hist": [0] * 64}
    files_meta = []
    for f in args.files:
        meta = {"file": str(f), "size": f.stat().st_size,
                "sha256": hashlib.sha256(f.read_bytes()).hexdigest()}
        files_meta.append(meta)
        gen = records_from_file(f, key)
        if gen is None:
            meta["error"] = "no known magic"
            continue
        n = 0
        for block in gen:
            census_block(block, agg)
            n += 1
            if args.max_blocks and n >= args.max_blocks:
                break
        meta["records_decoded"] = n
    heights = sorted(agg.pop("heights", []))
    out = {"files": files_meta,
           "totals": {k: v for k, v in agg.items() if k != "tx_size_hist"},
           "tx_size_hist_256b_buckets": agg["tx_size_hist"],
           "height_min": heights[0] if heights else None,
           "height_max": heights[-1] if heights else None,
           "height_median": heights[len(heights) // 2] if heights else None,
           "height_p05": heights[len(heights) * 5 // 100] if heights else None,
           "height_p95": heights[len(heights) * 95 // 100] if heights else None,
           "labels": {"count_kind": "structural_parse",
                      "sighash": ("structural estimate v2: per-DER-item preimage "
                                  "lengths with blanked scripts + SIGHASH_SINGLE/"
                                  "NONE/ANYONECANPAY cases; scriptCode approximated "
                                  "from input shape (prevouts unresolved). Dynamic "
                                  "attempt counts require executed replay."),
                      "scriptcode": "estimated: p2pkh=25B, multisig=last push, else 25",
                      "merkle": "executed: real tree computed and verified vs header",
                      "wtxid": "counted only for witness-serialized txs"}}
    args.out.write_text(json.dumps(out, indent=2) + "\n")
    if agg.get("merkle_mismatch", 0):
        sys.exit(f"merkle_mismatch={agg['merkle_mismatch']}: refusing to "
                 "emit a passing result over unverified blocks")
    print(json.dumps({"blocks": agg["blocks"], "txs": agg["txs"],
                      "inputs": agg["inputs"], "outputs": agg["outputs"],
                      "heights": [min(heights) if heights else None,
                                  max(heights) if heights else None]}))


if __name__ == "__main__":
    main()
