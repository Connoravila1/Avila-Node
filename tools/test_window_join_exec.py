#!/usr/bin/env python3
"""Executable regressions for `window_join` (the real-data join driver).

Builds AVCORP03 corpora with REAL fabricated headers (correct sha256d
hash field, linked parents, regtest pow_limit bits — ground nonces until
the self-consistent PoW target is met) and asserts the BINARY's behavior
in BOTH modes:

  ok               clean OP_TRUE boundary spend → exit 0, verified=1
  dup-boundary     same supplied coin spent twice → DupSpend, exit 1
  boundary-conflict same outpoint, conflicting specs → exit 1
  immature         coinbase source at depth < 100 → exit 1
  overspend        outputs > inputs → exit 1
  neg-output       12000 + (-3000) outputs on 10000 input — the audit's
                   counterexample: cumulative totals stay in range but
                   check_transaction rejects the negative output → exit 1
  nonfinal         height-form lock_time ahead of block height → exit 1
  excess-cb        coinbase claims subsidy+1 → exit 1
  badsig+desc      valid block, then a script failure, then a descendant —
                   asserts valid-prefix boundary (first_bad = mid block,
                   its descendant does NOT extend the prefix), exit 1
  workers 0        refused up front → exit 2
  unresolved       strict exit 1; --diagnostic exit 0, incomplete labeled

Every invalidity case asserts: exit nonzero in BOTH modes AND nothing
exported (known invalidity never publishes state).

Run:  python3 tools/test_window_join_exec.py [path/to/window_join]
"""
import hashlib, json, struct, subprocess, sys, tempfile, os

BIN = sys.argv[1] if len(sys.argv) > 1 else "target/release/examples/window_join"
PARAMS = ["--params", "regtest"]

def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def tx(inputs, outputs, lock=0):
    b = struct.pack('<I', 1) + bytes([len(inputs)])
    for (txid, vout, sig, seq) in inputs:
        b += txid + struct.pack('<I', vout) + bytes([len(sig)]) + sig + struct.pack('<I', seq)
    b += bytes([len(outputs)])
    for (val, spk) in outputs:
        b += struct.pack('<q', val) + bytes([len(spk)]) + spk
    return b + struct.pack('<I', lock)

def cb_tx(n, value=50_00000000):
    return tx([(b'\x00' * 32, 0xffffffff, bytes([2, n >> 8, n & 0xff]), 0xffffffff)],
              [(value, b'\x51')])

def spec(val, spk, ch, cb):
    return (b'\x01' + struct.pack('<q', val) + struct.pack('<I', len(spk))
            + spk + struct.pack('<I', ch) + bytes([cb]))

def merkle(txids):
    layer = txids[:]
    while len(layer) > 1:
        if len(layer) & 1:
            layer.append(layer[-1])
        layer = [sha256d(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]

REGTEST_BITS = 0x207fffff  # pow_limit — target ~2^255

def mkheader(prev_hash, merkle_root, time_=1_700_000_000):
    # grind nonce so sha256d(header) <= regtest target (top bit clear)
    fixed = (struct.pack('<i', 4) + prev_hash + merkle_root
             + struct.pack('<I', time_) + struct.pack('<I', REGTEST_BITS))
    for nonce in range(1 << 20):
        h = fixed + struct.pack('<I', nonce)
        if int.from_bytes(sha256d(h), 'little') < (0x7fffff << (8 * (0x20 - 3))):
            return h
    raise RuntimeError("no valid nonce")

class Chain:
    def __init__(self):
        self.buf = bytearray(b'AVCORP03')
        self.prev = b'\x00' * 32  # genesis-ish parent outside corpus
        self.t = 1_700_000_000

    def block(self, h, txs_with_specs):
        raws = [r for r, _ in txs_with_specs]
        mr = merkle([sha256d(r) for r in raws])
        hdr = mkheader(self.prev, mr, self.t)
        self.t += 600
        self.prev = sha256d(hdr)
        self.buf += struct.pack('<I', h) + self.prev + hdr
        self.buf += struct.pack('<I', len(txs_with_specs))
        for raw, specs in txs_with_specs:
            self.buf += struct.pack('<I', len(raw)) + raw + struct.pack('<I', len(specs))
            for s in specs:
                self.buf += s if s else b'\x00'
        return self

P2PKH = bytes.fromhex('76a914') + b'\x11' * 20 + bytes.fromhex('88ac')
OP_TRUE = b'\x51'
BOP = b'\xaa' * 32
val = 10_000

# ---- dumptxoutset (utxo\xff v2) fixture encoding ----------------------
def compress_amount(n):  # Core CompressAmount
    if n == 0:
        return 0
    e = 0
    while n % 10 == 0 and e < 9:
        n //= 10; e += 1
    if e < 9:
        d = n % 10
        n //= 10
        return 1 + (n * 9 + d - 1) * 10 + e
    return 1 + (n - 1) * 10 + 9

def varint(n):  # Core VARINT (MSB base-128, n++ on continuation)
    tmp = []
    while True:
        tmp.append((n & 0x7f) | (0x80 if tmp else 0))
        if n <= 0x7f:
            break
        n = (n >> 7) - 1
    return bytes(reversed(tmp))

def compact_size(n):
    if n < 253:
        return bytes([n])
    if n <= 0xffff:
        return b'\xfd' + struct.pack('<H', n)
    return b'\xfe' + struct.pack('<I', n)

def snap_group(txid, coins):  # coins: [(vout, code, value, script)]
    g = txid + compact_size(len(coins))
    for (vout, code, v, spk) in coins:
        g += compact_size(vout) + varint(code) + varint(compress_amount(v))
        g += varint(6 + len(spk)) + spk
    return g

def snapshot(coins_by_txid, base=b'\x00' * 32):
    groups = b''.join(snap_group(txid, coins) for txid, coins in coins_by_txid.items())
    n = sum(len(c) for c in coins_by_txid.values())
    # network magic must match the run's --params (regtest = fabfb5da);
    # base_blockhash is checked against the corpus's first-block parent
    # by the caller — fixtures pass the real value in via `base`.
    return (b'utxo\xff' + struct.pack('<H', 2) + b'\xfa\xbf\xb5\xda'
            + base + struct.pack('<Q', n) + groups)

def run(path, *extra):
    r = subprocess.run([BIN, path, '--workers', '4', '--export',
                        path + '.canonical', *PARAMS, *extra],
                       capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr

fails = []
def check(name, cond, detail=""):
    print(("PASS" if cond else "FAIL"), name, detail)
    if not cond:
        fails.append(name)

def last_json(out):
    return [json.loads(l) for l in out.strip().splitlines() if '"window_join"' in l][0]

def expect_invalid(name, corpus_fn, field_asserts):
    for diag in ([], ['--diagnostic']):
        p = corpus_fn()
        rc, out, err = run(p, *diag)
        mode = 'diag' if diag else 'strict'
        check(f'{name} [{mode}] exit 1', rc == 1, f'rc={rc}')
        if rc != 1:
            continue
        d = last_json(out)
        check(f'{name} [{mode}] not exported',
              not d['exported'] and not os.path.exists(p + '.canonical'))
        check(f'{name} [{mode}] known_invalid', d['known_invalid'])
        field_asserts(d, f'{name} [{mode}]')

with tempfile.TemporaryDirectory() as td:
    def W(name):
        return os.path.join(td, name + '.bin')

    # --- ok -------------------------------------------------------------
    def make_ok():
        c = Chain()
        s = tx([(BOP, 0, b'', 0xffffffff)], [(val - 1000, OP_TRUE)])
        c.block(140, [(cb_tx(1), [b'\x00']), (s, [spec(val, OP_TRUE, 50, 0)])])
        p = W('ok'); open(p, 'wb').write(bytes(c.buf)); return p
    p = make_ok()
    rc, out, _ = run(p)
    check('ok exit 0', rc == 0, f'rc={rc}')
    d = last_json(out)
    check('ok verified=1', d['verified_inputs'] == 1 and d['script_jobs_complete'])
    check('ok exported-not-chainstate',
          d['exported'] and not d['chainstate_complete']
          and not d['starting_state_complete'])

    # --- dup boundary -----------------------------------------------------
    def make_dup():
        c = Chain()
        s1 = tx([(BOP, 0, b'', 0xffffffff)], [(val - 1000, OP_TRUE)], lock=0)
        s2 = tx([(BOP, 0, b'', 0xffffffff)], [(val - 1000, OP_TRUE)], lock=1)
        c.block(140, [(cb_tx(1), [b'\x00']), (s1, [spec(val, OP_TRUE, 50, 0)])])
        c.block(141, [(cb_tx(2), [b'\x00']), (s2, [spec(val, OP_TRUE, 50, 0)])])
        p = W('dup'); open(p, 'wb').write(bytes(c.buf)); return p
    expect_invalid('dup-boundary', make_dup,
                   lambda d, n: check(f'{n} dup counted',
                                      d['join_dup_spends'] == 1
                                      and d['first_bad_height'] == 141))

    # --- conflicting boundary spec --------------------------------------
    def make_conf():
        c = Chain()
        s1 = tx([(BOP, 0, b'', 0xffffffff)], [(val - 1000, OP_TRUE)], lock=0)
        # same outpoint, DIFFERENT value in the two specs (one tx claims 10k,
        # another claims 9k — inconsistent supplied state)
        s2 = tx([(BOP, 0, b'', 0xfffffffe)], [(val - 2000, OP_TRUE)], lock=1)
        c.block(140, [(cb_tx(1), [b'\x00']), (s1, [spec(val, OP_TRUE, 50, 0)])])
        c.block(141, [(cb_tx(2), [b'\x00']), (s2, [spec(9000, OP_TRUE, 50, 0)])])
        p = W('conf'); open(p, 'wb').write(bytes(c.buf)); return p
    expect_invalid('boundary-conflict', make_conf,
                   lambda d, n: check(f'{n} conflict counted',
                                      d['boundary_conflicts'] >= 1))

    # --- immature coinbase ------------------------------------------------
    def make_imm():
        c = Chain()
        s = tx([(BOP, 0, b'', 0xffffffff)], [(val - 1000, OP_TRUE)])
        # source cb at h=150 spent at 200 → depth 50 < 100
        c.block(149, [(cb_tx(1), [b'\x00']), (s, [spec(val, OP_TRUE, 99, 1)])])
        p = W('imm'); open(p, 'wb').write(bytes(c.buf)); return p
    expect_invalid('immature', make_imm,
                   lambda d, n: check(f'{n} immature counted',
                                      d['immature_violations'] == 1
                                      and d['first_bad_height'] == 149))

    # --- overspend --------------------------------------------------------
    def make_over():
        c = Chain()
        s = tx([(BOP, 0, b'', 0xffffffff)], [(val + 5000, OP_TRUE)])
        c.block(140, [(cb_tx(1), [b'\x00']), (s, [spec(val, OP_TRUE, 50, 0)])])
        p = W('over'); open(p, 'wb').write(bytes(c.buf)); return p
    expect_invalid('overspend', make_over,
                   lambda d, n: check(f'{n} value violation',
                                      d['value_violations'] == 1))

    # --- negative output (the audit's counterexample) -------------------
    def make_neg():
        c = Chain()
        # 10000 input → outputs [12000, -3000]: sum 9000 < vin, fee 1000 ≥
        # 0 — cumulative checks pass; check_transaction must reject.
        s = tx([(BOP, 0, b'', 0xffffffff)], [(12_000, OP_TRUE), (-3_000, OP_TRUE)])
        c.block(140, [(cb_tx(1), [b'\x00']), (s, [spec(val, OP_TRUE, 50, 0)])])
        p = W('neg'); open(p, 'wb').write(bytes(c.buf)); return p
    expect_invalid('neg-output', make_neg,
                   lambda d, n: check(f'{n} context-free catch',
                                      d['context_free_failed'] >= 1
                                      and d['first_bad_height'] == 140))

    # --- non-final --------------------------------------------------------
    def make_nf():
        c = Chain()
        s = tx([(BOP, 0, b'', 0xfffffffe)], [(val - 1000, OP_TRUE)], lock=200)
        c.block(140, [(cb_tx(1), [b'\x00']), (s, [spec(val, OP_TRUE, 50, 0)])])
        p = W('nf'); open(p, 'wb').write(bytes(c.buf)); return p
    expect_invalid('nonfinal', make_nf,
                   lambda d, n: check(f'{n} nonfinal counted',
                                      d['nonfinal_violations'] == 1))

    # --- excess coinbase --------------------------------------------------
    def make_cb():
        c = Chain()
        s = tx([(BOP, 0, b'', 0xffffffff)], [(val - 1000, OP_TRUE)])
        # regtest subsidy at h200 = 50e8; claim subsidy+fee+1
        c.block(140, [(cb_tx(1, 50_00000000 + 1000 + 1), [b'\x00']),
                      (s, [spec(val, OP_TRUE, 50, 0)])])
        p = W('cb'); open(p, 'wb').write(bytes(c.buf)); return p
    expect_invalid('excess-cb', make_cb,
                   lambda d, n: check(f'{n} cb bound violation',
                                      d['cb_bound_violations'] == 1))

    # --- bad script mid-chain: valid prefix boundary -----------------------
    def make_badseq():
        c = Chain()
        good = tx([(BOP, 0, b'', 0xffffffff)], [(val - 1000, OP_TRUE)], lock=0)
        c.block(140, [(cb_tx(1), [b'\x00']), (good, [spec(val, OP_TRUE, 50, 0)])])
        bad = tx([(b'\xbb' * 32, 0, b'', 0xffffffff)], [(val - 1000, OP_TRUE)])
        c.block(141, [(cb_tx(2), [b'\x00']), (bad, [spec(val, P2PKH, 50, 0)])])
        ok2 = tx([(b'\xcc' * 32, 0, b'', 0xffffffff)], [(val - 1000, OP_TRUE)])
        c.block(142, [(cb_tx(3), [b'\x00']), (ok2, [spec(val, OP_TRUE, 50, 0)])])
        p = W('badseq'); open(p, 'wb').write(bytes(c.buf)); return p
    expect_invalid('badsig-prefix', make_badseq,
                   lambda d, n: check(f'{n} fails at 141, prefix before it',
                                      d['script_failure_txs'] == 1
                                      and d['first_bad_height'] == 141
                                      and d['verified_inputs'] >= 1))

    # --- workers 0 ---------------------------------------------------------
    p = make_ok()
    r = subprocess.run([BIN, p, '--workers', '0', *PARAMS],
                       capture_output=True, text=True)
    check('workers0 exit 2', r.returncode == 2, f'rc={r.returncode}')

    # --- unresolved: strict fails, diagnostic emits labeled projection ----
    def make_unres():
        c = Chain()
        s = tx([(b'\xbb' * 32, 0, b'', 0xffffffff)], [(val - 1000, OP_TRUE)])
        c.block(140, [(cb_tx(1), [b'\x00']), (s, [b'\x00'])])
        p = W('unres'); open(p, 'wb').write(bytes(c.buf)); return p
    p = make_unres()
    rc, out, _ = run(p)
    check('unresolved strict exit 1', rc == 1, f'rc={rc}')
    rc, out, _ = run(p, '--diagnostic')
    check('unresolved diagnostic exit 0', rc == 0, f'rc={rc}')
    d = last_json(out)
    check('diagnostic incomplete-labeled',
          d['exported'] and not d['resolved_inputs_complete']
          and d['excluded_txs'] == 1 and not d['chainstate_complete'])

    # --- --boundary: supplied state resolves a spec-less spend ----------
    # the unresolved corpus's missing spec is (BOP'bb',0) — supply it
    p = make_unres()
    bp = os.path.join(td, 'state.utxo')
    open(bp, 'wb').write(snapshot({b'\xbb' * 32: [(0, 100, val, OP_TRUE)]}))
    rc, out, _ = run(p, '--boundary', bp)
    d = last_json(out)
    check('boundary resolves spec-less spend',
          rc == 0 and d['starting_state_complete']
          and d['verified_inputs'] == 1 and d['join_missing_spends'] == 0,
          f'rc={rc} missing={d["join_missing_spends"]}')

    # spec says value=val but boundary holds a DIFFERENT coin → conflict
    p = make_ok()
    bp2 = os.path.join(td, 'bad.utxo')
    open(bp2, 'wb').write(snapshot({BOP: [(0, 100, val - 5, OP_TRUE)]}))
    rc, out, _ = run(p, '--boundary', bp2)
    d = last_json(out)
    check('boundary/spec mismatch → invalid',
          rc == 1 and d['boundary_conflicts'] >= 1, f'rc={rc}')

    # boundary supplied but spend's outpoint absent entirely → the coin
    # does not exist → invalid (Missing is no longer a coverage gap)
    p = make_unres()
    bp3 = os.path.join(td, 'empty.utxo')
    open(bp3, 'wb').write(snapshot({b'\xdd' * 32: [(0, 100, val, OP_TRUE)]}))
    rc, out, _ = run(p, '--boundary', bp3)
    d = last_json(out)
    check('absent-from-boundary → invalid',
          rc == 1 and d['join_missing_spends'] == 1, f'rc={rc}')

    # --- boundary INTEGRITY checks (exit 2, malformed input) --------------
    # wrong network magic (mainnet f9beb4d9 vs the run's regtest)
    p = make_unres()
    bpn = os.path.join(td, 'net.utxo')
    snap = snapshot({b'\xbb' * 32: [(0, 100, val, OP_TRUE)]})
    snap = snap[:7] + b'\xf9\xbe\xb4\xd9' + snap[11:]
    open(bpn, 'wb').write(snap)
    rc, out, err = run(p, '--boundary', bpn)
    check('wrong-network boundary → exit 2', rc == 2, f'rc={rc} err={err[-80:]}')

    # base hash not naming the window's parent → not adjacent → exit 2
    bpb = os.path.join(td, 'far.utxo')
    open(bpb, 'wb').write(snapshot({b'\xbb' * 32: [(0, 100, val, OP_TRUE)]},
                                  base=b'\x77' * 32))
    rc, out, err = run(p, '--boundary', bpb)
    check('non-adjacent base → exit 2', rc == 2, f'rc={rc}')

    # duplicate outpoint in the dump → malformed → exit 2
    bpd = os.path.join(td, 'dup.utxo')
    open(bpd, 'wb').write(
        snapshot({b'\xbb' * 32: [(0, 100, val, OP_TRUE),
                                 (0, 100, val, OP_TRUE)]}))
    rc, out, err = run(p, '--boundary', bpd)
    check('dup-outpoint boundary → exit 2', rc == 2, f'rc={rc}')

    # --- donor pins: base-hash / base-height / coin-set commitment ------
    # A NON-palindromic base hash exercises real byte-order handling.
    custom_base = bytes(range(32))          # internal (file) order
    custom_base_disp = custom_base[::-1].hex()  # display hex
    c = Chain()
    c.prev = custom_base
    s = tx([(b'\xcc' * 32, 0, b'', 0xffffffff)], [(val - 1000, OP_TRUE)])
    c.block(140, [(cb_tx(1), [b'\x00']), (s, [b'\x00'])])  # spec-less spend
    p = os.path.join(td, 'pin.corpus')
    open(p, 'wb').write(bytes(c.buf))
    donor = {b'\xcc' * 32: [(0, 100, val, OP_TRUE)]}
    bpf = os.path.join(td, 'pin.utxo')
    open(bpf, 'wb').write(snapshot(donor, base=custom_base))
    # coin-set commitment, computed the same way the verifier does:
    # sha256d over every coin's TxOutSer (txid‖vout‖code‖value‖len‖spk)
    ser = b''
    for txi, coins in donor.items():
        for (vout, code, v, spk) in coins:
            ser += txi + struct.pack('<I', vout) + struct.pack('<I', code)
            ser += struct.pack('<q', v) + compact_size(len(spk)) + spk
    commit_disp = sha256d(ser)[::-1].hex()

    rc, out, _ = run(p, '--boundary', bpf,
                     '--boundary-base-hash', custom_base_disp,
                     '--boundary-base-height', '139',
                     '--boundary-txoutset-hash', commit_disp)
    d = last_json(out)
    check('all donor pins correct → exit 0',
          rc == 0 and d['join_missing_spends'] == 0
          and d['boundary_txoutset_hash'] == commit_disp, f'rc={rc}')

    rc, _, _ = run(p, '--boundary', bpf,
                   '--boundary-base-hash', 'aa' * 32)
    check('wrong base-hash pin → exit 2', rc == 2, f'rc={rc}')
    rc, _, _ = run(p, '--boundary', bpf, '--boundary-base-hash', 'abc')
    check('short base-hash pin → exit 2 not panic', rc == 2, f'rc={rc}')
    rc, _, _ = run(p, '--boundary', bpf,
                   '--boundary-base-hash', 'zz' * 32)
    check('non-hex base-hash pin → exit 2 not panic', rc == 2, f'rc={rc}')
    rc, _, _ = run(p, '--boundary', bpf, '--boundary-base-height', '138')
    check('wrong donor-height pin → exit 2', rc == 2, f'rc={rc}')
    rc, _, _ = run(p, '--boundary', bpf,
                   '--boundary-txoutset-hash', 'aa' * 32)
    check('wrong txoutset pin → exit 2', rc == 2, f'rc={rc}')

    # manifest ties build + binary + inputs + outputs on the success path
    rm = p + '.runmanifest'
    rc, out, _ = run(p, '--boundary', bpf, '--run-manifest', rm)
    m = json.loads(open(rm).read())
    check('run manifest: build_rev + argv array + hashes',
          rc == 0 and m['build_rev'] and isinstance(m['argv'], list)
          and m['exit_code'] == 0 and m['boundary_sha256']
          and m['corpus_sha256'] and m['export_sha256'],
          f'rc={rc} rev={m.get("build_rev")}')

print()
if fails:
    print("FAILED:", fails)
    sys.exit(1)
print("all window_join executable regressions pass")
