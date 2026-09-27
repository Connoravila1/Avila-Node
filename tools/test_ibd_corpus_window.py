#!/usr/bin/env python3
"""Deterministic regressions for ibd_corpus_window.py resolver repairs.

Builds synthetic multi-file blk corpora exercising:
  1. cross-file (record_offset, tx_offset) collisions — same offsets in two
     files must not alias (the file-identity defect from the 72–75 audit);
  2. mature coinbase sources resolve; immature coinbase sources are flagged;
  3. missing sources are counted unresolved, never fabricated;
  4. duplicate txid occurrences resolve to the latest occurrence before the
     spend (creation-height metadata verifies which occurrence was chosen).

Run: python3 tools/test_ibd_corpus_window.py
"""
import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ibd_corpus_window as cw

MAGIC = bytes.fromhex("f9beb4d9")


def csize(n):
    if n < 253:
        return bytes([n])
    if n < 65536:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def b34push(h):
    """BIP34 height push inside a coinbase scriptSig."""
    hb = h.to_bytes((h.bit_length() + 7) // 8 or 1, "little")
    return bytes([len(hb)]) + hb


def tx(inputs, outputs, lock=b"\x00" * 4):
    b = b"\x01\x00\x00\x00" + csize(len(inputs))
    for (prev, vout, script, seq) in inputs:
        b += prev + struct.pack("<I", vout) + csize(len(script)) + script + \
            struct.pack("<I", seq)
    b += csize(len(outputs))
    for (value, spk) in outputs:
        b += struct.pack("<q", value) + csize(len(spk)) + spk
    return b + lock


def coinbase(h, outputs, tag=b""):
    script = b34push(h) + tag
    inp = (b"\x00" * 32, 0xFFFFFFFF, script, 0xFFFFFFFF)
    return tx([inp], outputs)


def block(txs):
    return b"\x00" * 80 + csize(len(txs)) + b"".join(txs)


def blkfile(*blocks):
    out = bytearray()
    for b in blocks:
        out += MAGIC + struct.pack("<I", len(b)) + b
    return bytes(out)


def txid_of(txbytes):
    return cw.sha256d(txbytes)


def run_resolver(span_files, window_files, outdir):
    import argparse as _a
    argv = ["--span-files"] + [str(f) for f in span_files] + \
           ["--window-files"] + [str(f) for f in window_files] + \
           ["--out", str(outdir)]
    old = sys.argv
    sys.argv = ["ibd_corpus_window.py"] + argv
    try:
        cw.main()
    finally:
        sys.argv = old
    import json
    return json.loads((outdir / "manifest.json").read_text())


def parse_corpus(path):
    d = Path(path).read_bytes()
    assert d[:8] == b"AVCORP02"
    o = 8
    blocks = []
    while o < len(d):
        h = struct.unpack_from("<I", d, o)[0]; o += 4
        bh = d[o:o + 32]; o += 32
        ntx = struct.unpack_from("<I", d, o)[0]; o += 4
        txs = []
        for _ in range(ntx):
            n = struct.unpack_from("<I", d, o)[0]; o += 4
            raw = d[o:o + n]; o += n
            ni = struct.unpack_from("<I", d, o)[0]; o += 4
            ins = []
            for _ in range(ni):
                r = d[o]; o += 1
                if r == 0:
                    ins.append(None)
                else:
                    val = struct.unpack_from("<q", d, o)[0]; o += 8
                    sl = struct.unpack_from("<I", d, o)[0]; o += 4
                    spk = d[o:o + sl]; o += sl
                    ch = struct.unpack_from("<I", d, o)[0]; o += 4
                    fl = d[o]; o += 1
                    ins.append((val, spk, ch, fl))
            txs.append((raw, ins))
        blocks.append((h, bh, txs))
    return blocks


def main():
    tmp = Path(tempfile.mkdtemp(prefix="cwreg-"))
    fA, fB, fW = tmp / "blkA.dat", tmp / "blkB.dat", tmp / "blkW.dat"

    cbA = coinbase(100, [(50_00000000, b"\x51")])
    cbB = coinbase(101, [(51_00000000, b"\x51")])
    cbW = coinbase(200, [(50_00000000, b"\x51")])

    # SA/SB: SAME length, SAME positions in single-record files A/B → identical
    # (record_offset, tx_offset) — different txids & output values. This is the
    # cross-file collision case.
    pA = b"\xaa" * 32
    pB = b"\xbb" * 32
    SA = tx([(pA, 0, b"\x51", 0)], [(7_000, b"\x76"), (8_000, b"\x76")])
    SB = tx([(pB, 0, b"\x51", 0)], [(9_000, b"\x76"), (8_000, b"\x76")])
    assert len(SA) == len(SB) and txid_of(SA) != txid_of(SB)

    # duplicate txid D appears in file A (h=102) and file B (h=110)
    D = tx([(b"\xcc" * 32, 0, b"\x51", 0)], [(5_000, b"\x76")])

    fA.write_bytes(blkfile(block([cbA, SA]), block([coinbase(102, [(50_00000000, b"\x51")]), D])))
    fB.write_bytes(blkfile(block([cbB, SB]), block([coinbase(110, [(50_00000000, b"\x51")]), D])))

    # Window h=200: spends SA:0, SB:0, cbA:0 (mature), cbB:0 (immature),
    # D:0 (dup → must pick h=110 occurrence), missing txid.
    spend = tx([
        (txid_of(SA), 0, b"\x51", 0),
        (txid_of(SB), 0, b"\x51", 0),
        (txid_of(cbA), 0, b"\x51", 0),
        (txid_of(cbB), 0, b"\x51", 0),
        (txid_of(D), 0, b"\x51", 0),
        (b"\x99" * 32, 0, b"\x51", 0),
    ], [(1_000, b"\x76")])
    fW.write_bytes(blkfile(block([cbW, spend])))

    man = run_resolver([fA, fB, fW], [fW], tmp / "out")
    st = man["window"]["stats"]
    blks = parse_corpus(tmp / "out" / "corpus.bin")
    ins = blks[0][2][1][1]  # second tx's inputs

    # 1. file identity: SA spend must get file A's 7000-sat output, not B's 9000.
    assert ins[0] == (7_000, b"\x76", 100, 0), f"SA prevout wrong: {ins[0]}"
    assert ins[1] == (9_000, b"\x76", 101, 0), f"SB prevout wrong: {ins[1]}"
    # 2. coinbase: cbA mature (200-100=100), cbB immature (200-101=99).
    assert ins[2] == (50_00000000, b"\x51", 100, 1), f"cbA: {ins[2]}"
    assert ins[3] == (51_00000000, b"\x51", 101, 1), f"cbB: {ins[3]}"
    assert st.get("immature_coinbase_refs", 0) == 1, st
    # 3. duplicate: D spend must carry creation_height=110 (latest occ < 200).
    assert ins[4][0] == 5_000 and ins[4][2] == 110, f"dup occurrence: {ins[4]}"
    # 4. missing source unresolved.
    assert ins[5] is None and st["unresolved_no_occurrence"] >= 1, st
    assert st.get("txid_identity_mismatch", 0) == 0, st
    print("resolver regressions: PASS", st)

    # 5. Replay-level rejection (through the actual driver): window2 spends
    #    [mature cbA:0, immature cbB:0] in ONE tx, and [missing, immature
    #    cbB:0] in another — detected consensus invalidity must exit nonzero.
    replay_bin = Path(__file__).resolve().parent.parent / \
        "target/release/examples/corpus_replay"
    fW2 = tmp / "blkW2.dat"
    spend2 = tx([(txid_of(cbA), 0, b"\x51", 0),
                 (txid_of(cbB), 0, b"\x51", 0)], [(1_000, b"\x76")])
    spend3 = tx([(b"\x99" * 32, 0, b"\x51", 0),
                 (txid_of(cbB), 0, b"\x51", 0)], [(1_000, b"\x76")])
    fW2.write_bytes(blkfile(block([cbW, spend2, spend3])))
    man2 = run_resolver([fA, fB, fW2], [fW2], tmp / "out2")
    if replay_bin.exists():
        import subprocess
        jl = tmp / "out2" / "replay.jsonl"
        r = subprocess.run(
            [str(replay_bin), str(tmp / "out2" / "corpus.bin"),
             "--workers", "1", "--jsonl", str(jl)],
            capture_output=True, text=True)
        import json as _j
        ctr = next(_j.loads(l) for l in jl.read_text().splitlines()
                   if '"type":"counters"' in l)
        assert ctr["excluded_immature_txs"] == 2, ctr
        assert ctr["immature_source_inputs"] == 2, ctr
        assert ctr["inputs_excluded_by_immaturity"] == 4, ctr
        assert r.returncode != 0, \
            "immature coinbase spend must fail the replay run"
        print("replay rejection regression: PASS",
              {"rc": r.returncode, "excluded_immature_txs": 2})
        # 6. zero-worker run must not report success
        r0 = subprocess.run([str(replay_bin), str(tmp / "out2" / "corpus.bin"),
                             "--workers", "0"], capture_output=True, text=True)
        assert r0.returncode != 0, "0-worker run must fail"
        print("worker-count regression: PASS")
    else:
        print(f"SKIP replay regressions — binary not found: {replay_bin}; "
              f"manifest for inspection: {man2['window']['stats']}")


if __name__ == "__main__":
    main()
