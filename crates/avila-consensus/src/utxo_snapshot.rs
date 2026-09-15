//! Core's assumeutxo snapshot format — the file `dumptxoutset` writes and
//! `loadtxoutset` consumes (`SnapshotMetadata` + compressed `Coin` rows).
//!
//! Layout, matching `WriteUTXOSnapshot`:
//!
//! ```text
//! metadata  := magic[4] base_blockhash[32] coins_count[8]
//! group     := txid[32] CompactSize(n_outs) (CompactSize(vout) coin)*
//! coin      := VARINT(code) VARINT(amount) VARINT(script_size) script_data
//! code      := height*2 + coinbase            (NONNEGATIVE_SIGNED varint)
//! amount    := CompressAmount(value)          (NONNEGATIVE_SIGNED varint)
//! script    := CompressedScript             (VARINT size id + payload)
//! ```
//!
//! Groups iterate outpoints in `(txid, vout)` order — Core's coins-DB cursor
//! order, a plain byte sort over the serialized `COutPoint` key.

use crate::connect::{Coin, UtxoSet};
use crate::hash::BlockHash;
use crate::script::ScriptType;
use crate::transaction::{OutPoint, Script};
use std::io::Write;

/// Writes Core's `VARINT` (`VarIntMode::NONNEGATIVE_SIGNED`): base-128,
/// most-significant group first, `n = (n >> 7) - 1` between groups.
fn write_varint(out: &mut Vec<u8>, mut n: u64) {
    let mut tmp = [0u8; 10];
    let mut len = 0usize;
    loop {
        tmp[len] = (n & 0x7f) as u8;
        len += 1;
        if n <= 0x7f {
            break;
        }
        n = (n >> 7) - 1;
    }
    while len > 0 {
        len -= 1;
        out.push(tmp[len] | if len > 0 { 0x80 } else { 0 });
    }
}

/// Core's `CompressAmount` (`compressor.cpp`) — decimal digit-exponent
/// compression of the satoshi value.
fn compress_amount(mut n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut e = 0;
    while n.is_multiple_of(10) && e < 9 {
        n /= 10;
        e += 1;
    }
    if e < 9 {
        let d = n % 10;
        debug_assert!((1..=9).contains(&d));
        n /= 10;
        1 + (n * 9 + d - 1) * 10 + e
    } else {
        1 + (n - 1) * 10 + 9
    }
}

/// Core's `CompressScript`: the compact script encodings `Coin`
/// serialization uses for standard templates. Returns
/// `(size_or_id, payload)` — `size_or_id` is the VARINT-written field.
fn compress_script(script: &Script) -> (u64, Vec<u8>) {
    match script.classify() {
        ScriptType::PubKeyHash(h) => (0, h.to_vec()),
        ScriptType::ScriptHash(h) => (1, h.to_vec()),
        ScriptType::PubKey(key) if key.len() == 33 && matches!(key[0], 2 | 3) => {
            // Core writes the pubkey's own prefix byte — 2 = even Y,
            // 3 = odd Y; the payload is X only.
            (u64::from(key[0]), key[1..33].to_vec())
        }
        ScriptType::PubKey(key) if key.len() == 65 && key[0] == 4 => {
            // 4/5 — uncompressed keys keep X; Y is recomputed on decode.
            (4 + u64::from(key[64] & 1), key[1..33].to_vec())
        }
        // IDs 28/29/30 (P2WPKH/P2WSH/P2TR) are decode-only leftovers —
        // Core stopped writing them in v23, so witness scripts take
        // the default `len + 6` + raw form like everything else.
        _ => (script.len() as u64 + 6, script.as_bytes().to_vec()),
    }
}

/// `Coin`'s serialized form: `VARINT(height*2 + coinbase)` then the
/// compressed `CTxOut` (compressed amount + compressed script).
fn write_coin(out: &mut Vec<u8>, coin: &Coin) {
    write_varint(out, u64::from(coin.height) * 2 + u64::from(coin.coinbase));
    debug_assert!(coin.out.value >= 0, "UTXO coins are never negative");
    write_varint(out, compress_amount(coin.out.value.max(0) as u64));
    let (size_id, payload) = compress_script(&coin.out.script_pubkey);
    write_varint(out, size_id);
    out.extend_from_slice(&payload);
}

/// One [`OutPoint`] in Core's coins-DB cursor order — the byte-wise sort of
/// the serialized `COutPoint` key (`txid` raw internal bytes, then `vout`
/// little-endian).
pub fn outpoint_key(o: &OutPoint) -> [u8; 36] {
    let mut k = [0u8; 36];
    k[..32].copy_from_slice(o.txid.as_bytes());
    k[32..].copy_from_slice(&o.vout.to_le_bytes());
    k
}

/// `WriteUTXOSnapshot` — serializes `metadata` then the whole `coins` set,
/// grouped by txid. `out` receives the complete file body; returns the
/// number of coins written.
///
/// `coins` must yield `(OutPoint, &Coin)` in [`outpoint_key`] order — the
/// caller sorts, since `UtxoSet`'s map is unordered.
pub fn write_snapshot<W: Write>(
    mut w: W,
    message_start: [u8; 4],
    base_hash: &BlockHash,
    coins_count: u64,
    coins: &[(OutPoint, Coin)],
) -> std::io::Result<u64> {
    // File magic `utxo\xff` + u16 format version, then
    // SnapshotMetadata: network magic, base blockhash, coins count.
    w.write_all(b"utxo\xff")?;
    w.write_all(&2u16.to_le_bytes())?;
    w.write_all(&message_start)?;
    w.write_all(base_hash.as_bytes())?;
    w.write_all(&coins_count.to_le_bytes())?;

    let mut buf = Vec::with_capacity(1024);
    let mut written = 0u64;
    let mut i = 0usize;
    while i < coins.len() {
        let txid = coins[i].0.txid;
        let mut j = i;
        while j < coins.len() && coins[j].0.txid == txid {
            j += 1;
        }
        buf.clear();
        buf.extend_from_slice(txid.as_bytes());
        crate::encode::write_compact_size(&mut buf, (j - i) as u64);
        for (op, coin) in &coins[i..j] {
            crate::encode::write_compact_size(&mut buf, u64::from(op.vout));
            write_coin(&mut buf, coin);
            written += 1;
        }
        w.write_all(&buf)?;
        i = j;
    }
    Ok(written)
}

/// Collects the set in cursor order — `(txid, vout)` byte order like the
/// LevelDB scan `WriteUTXOSnapshot` drives.
#[must_use]
pub fn sorted_coins(utxo: &UtxoSet) -> Vec<(OutPoint, Coin)> {
    let mut coins: Vec<(OutPoint, Coin)> = utxo.iter().map(|(o, c)| (*o, c.clone())).collect();
    coins.sort_by_key(|(o, _)| outpoint_key(o));
    coins
}
