#!/usr/bin/env python3
"""SwiftSync write-elision hypothesis: how many coins created during a sync
window die inside it? Those are the writes+deletes an aggregate-verified
no-write path never pays. Scan signet blk files, track outpoint lifetimes."""
import hashlib, os, struct, sys, glob
from collections import defaultdict

def dsha(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()

class Rd:
    def __init__(s, b, p=0): s.b, s.p = b, p
    def u8(s):  v = s.b[s.p]; s.p += 1; return v
    def u16(s): v = struct.unpack('<H', s.b[s.p:s.p+2])[0]; s.p += 2; return v
    def u32(s): v = struct.unpack('<I', s.b[s.p:s.p+4])[0]; s.p += 4; return v
    def u64(s): v = struct.unpack('<Q', s.b[s.p:s.p+8])[0]; s.p += 8; return v
    def take(s, n): v = s.b[s.p:s.p+n]; s.p += n; return v
    def cs(s):
        c = s.u8()
        if c < 0xfd: return c
        if c == 0xfd: return s.u16()
        if c == 0xfe: return s.u32()
        return s.u64()

def parse_block(raw):
    """Yield (stripped_tx_bytes, [prevout...], n_outputs) per tx."""
    r = Rd(raw)
    r.take(80)  # header
    ntx = r.cs()
    for _ in range(ntx):
        start = r.p
        r.u32()  # version
        segwit = False
        vin_n = r.cs()
        if vin_n == 0:  # segwit marker
            r.u8()      # flag
            segwit = True
            vin_n = r.cs()
        ins = []
        for _ in range(vin_n):
            pt = r.take(32); vo = r.u32()
            sl = r.cs(); r.take(sl)
            r.u32()  # sequence
            ins.append((pt, vo))
        vout_n = r.cs()
        vout_start = r.p
        for _ in range(vout_n):
            r.u64(); sl = r.cs(); r.take(sl)
        if segwit:
            for _ in range(vin_n):
                wn = r.cs()
                for _ in range(wn):
                    wl = r.cs(); r.take(wl)
        r.u32()  # locktime
        # stripped serialization = raw minus witness — rebuild cheaply:
        # strip by re-encoding: version + ins + outs + locktime
        # simpler: capture slices
        yield raw[start:start+4], ins, vout_n, r

def txid_of(raw, r2):
    # Recompute stripped bytes: re-parse without witness
    rr = Rd(raw)
    start = rr.p
    ver = rr.take(4)
    vin_n = rr.cs()
    if vin_n == 0:
        rr.u8(); vin_n = rr.cs()
    in_start = rr.p - 1
    for _ in range(vin_n):
        rr.take(32); rr.u32(); sl = rr.cs(); rr.take(sl); rr.u32()
    # vin_n varint was consumed; rebuild: ver + vin_n + ins + outs + locktime
    # find the vin_n encoding: it was a compactsize — reslice
    # simpler approach: re-encode
    return None

def parse_tx(raw):
    """Return (txid, stripped_raw, inputs, n_outputs)."""
    r = Rd(raw)
    ver = r.take(4)
    vin_n = r.cs()
    segwit = vin_n == 0
    if segwit:
        flag = r.u8(); vin_n = r.cs()
    vin_pos = []
    parts = [ver, enc_cs(vin_n)]
    for _ in range(vin_n):
        pt = r.take(32); vo = r.u32()
        sl = r.cs(); ss = r.take(sl); seq = r.u32()
        vin_pos.append((pt, vo))
        parts.append(pt + struct.pack('<I', vo) + enc_cs(sl) + ss + struct.pack('<I', seq))
    vout_n = r.cs()
    parts.append(enc_cs(vout_n))
    for _ in range(vout_n):
        val = r.u64(); sl = r.cs(); spk = r.take(sl)
        parts.append(struct.pack('<Q', val) + enc_cs(sl) + spk)
    if segwit:
        for _ in range(vin_n):
            wn = r.cs()
            for _ in range(wn):
                wl = r.cs(); r.take(wl)
    lt = r.take(4); parts.append(lt)
    stripped = b''.join(parts)
    return dsha(stripped), vin_pos, vout_n, r.p

def enc_cs(n):
    if n < 0xfd: return bytes([n])
    if n < 0x10000: return b'\xfd' + struct.pack('<H', n)
    if n < 0x100000000: return b'\xfe' + struct.pack('<I', n)
    return b'\xff' + struct.pack('<Q', n)

created = {}          # outpoint key -> birth height
spent_in_window = 0
created_total = 0
spent_total = 0
lifetimes = []        # (spend_h - birth_h) for in-window spends
height = 0
files = sorted(glob.glob('/tmp/avila-data/signet/blk*.dat'))
for fp in files:
    blob = open(fp, 'rb').read()
    pos = 0
    while pos + 8 <= len(blob):
        magic, blen = struct.unpack('<II', blob[pos:pos+8])
        if magic != 0x40cf030a: break
        pos += 8
        raw = blob[pos:pos+blen]; pos += blen
        height += 1
        r = Rd(raw); r.take(80); ntx = r.cs()
        for _ in range(ntx):
            txstart = r.p
            # find tx end by full parse
            tid, ins, nouts, consumed = parse_tx(raw[txstart:])
            r.p = txstart + consumed
            coinbase = ins and ins[0][0] == b'\x00'*32 and ins[0][1] == 0xffffffff
            if not coinbase:
                for pt, vo in ins:
                    key = pt + struct.pack('<I', vo)
                    spent_total += 1
                    bh = created.pop(key, None)
                    if bh is not None:
                        spent_in_window += 1
                        lifetimes.append(height - bh)
            for v in range(nouts):
                created[tid + struct.pack('<I', v)] = height
                created_total += 1
        if height % 2000 == 0:
            print(f"  h={height} created={created_total} spent={spent_total} live={len(created)}", flush=True)

print(f"\nblocks parsed: {height}")
print(f"coins created: {created_total:,}")
print(f"coins spent:   {spent_total:,}")
print(f"spent within window: {spent_in_window:,} ({100*spent_in_window/max(1,created_total):.1f}% of all created)")
print(f"still live at end:   {len(created):,}")
if lifetimes:
    lifetimes.sort()
    import statistics
    print(f"lifetime blocks: median {statistics.median(lifetimes):.0f}, "
          f"p90 {lifetimes[int(.9*len(lifetimes))]}, mean {statistics.mean(lifetimes):.1f}")
    for t in (1, 10, 100, 1000):
        print(f"  die within {t:>5} blocks: {sum(1 for l in lifetimes if l <= t):,} "
              f"({100*sum(1 for l in lifetimes if l <= t)/max(1,len(lifetimes)):.1f}% of spends)")
