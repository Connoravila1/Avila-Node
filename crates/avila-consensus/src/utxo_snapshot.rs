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
pub(crate) fn write_varint(out: &mut Vec<u8>, mut n: u64) {
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
pub(crate) fn compress_amount(mut n: u64) -> u64 {
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
pub(crate) fn compress_script(script: &Script) -> (u64, Vec<u8>) {
    match script.classify() {
        ScriptType::PubKeyHash(h) => (0, h.to_vec()),
        ScriptType::ScriptHash(h) => (1, h.to_vec()),
        ScriptType::PubKey(key) if key.len() == 33 && matches!(key[0], 2 | 3) => {
            // Core writes the pubkey's own prefix byte — 2 = even Y,
            // 3 = odd Y; the payload is X only.
            (u64::from(key[0]), key[1..33].to_vec())
        }
        ScriptType::PubKey(key)
            if key.len() == 65 && key[0] == 4 && secp256k1::PublicKey::from_slice(&key).is_ok() =>
        {
            // 4/5 — uncompressed keys keep X; Y is recomputed on decode.
            // Gated on full validity (secp256k1 parse succeeds), like
            // compressor.cpp's `IsToPubKey`: `CPubKey::IsFullyValid()`
            // is checked "last since it's expensive" before taking this
            // path — an off-curve key falls through to the raw fallback
            // below instead, matching Core exactly.
            (4 + u64::from(key[64] & 1), key[1..33].to_vec())
        }
        // Witness and everything else take the default `len + 6` +
        // raw form — Core's `CompressScript` has no witness cases.
        _ => (script.len() as u64 + 6, script.as_bytes().to_vec()),
    }
}

/// `Coin`'s serialized form: `VARINT(height*2 + coinbase)` then the
/// compressed `CTxOut` (compressed amount + compressed script).
#[doc(hidden)]
pub fn write_coin(out: &mut Vec<u8>, coin: &Coin) {
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
    let mut coins: Vec<(OutPoint, Coin)> = utxo.iter();
    coins.sort_by_key(|(o, _)| outpoint_key(o));
    coins
}

// ------------------------------------------------------------------
// Reading — `loadtxoutset`'s `SnapshotMetadata` parse and the
// `PopulateAndValidateSnapshot` coin stream, with Core's exact
// failure strings at each stage.
// ------------------------------------------------------------------

/// The parsed snapshot header — `SnapshotMetadata` after
/// `Unserialize`. Field checks happen in `read_metadata` so the RPC
/// can map them to Core's `RPC_DESERIALIZATION_ERROR`.
#[derive(Debug)]
pub struct SnapshotMetadata {
    /// `m_base_blockhash` — the block the UTXO set reflects.
    pub base_blockhash: BlockHash,
    /// `m_coins_count` — declared coin count, checked against the
    /// stream while loading.
    pub coins_count: u64,
}

/// A snapshot-load failure carrying Core's error text — either an
/// `ios_base::failure` message (metadata parse) or a
/// `util::Error` string (activation/population).
#[derive(Debug)]
pub struct SnapshotError(pub String);

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SnapshotError {}

/// `SnapshotMetadata::Unserialize` — magic `utxo\xff`, version u16
/// (only `2` is supported), the network's `pchMessageStart`, then
/// `m_base_blockhash` and `m_coins_count`.
///
/// # Errors
///
/// `SnapshotError` with `Unserialize`'s exact messages: bad magic,
/// unsupported version, or a network mismatch (named when the file's
/// magic belongs to a known network, unrecognized otherwise). Every
/// failure is an `std::ios_base::failure` in Core, whose `what()`
/// carries the `: iostream error` suffix — reproduced here so the
/// RPC's `Unable to parse metadata: %s` matches verbatim.
pub fn read_metadata(
    r: &mut impl std::io::Read,
    message_start: [u8; 4],
) -> Result<SnapshotMetadata, SnapshotError> {
    read_metadata_inner(r, message_start).map_err(|e| {
        if e.0.ends_with(": iostream error") {
            e
        } else {
            SnapshotError(format!("{}: iostream error", e.0))
        }
    })
}

fn read_metadata_inner(
    r: &mut impl std::io::Read,
    message_start: [u8; 4],
) -> Result<SnapshotMetadata, SnapshotError> {
    let fail = |msg: String| Err(SnapshotError(msg));
    let mut magic = [0u8; 5];
    r.read_exact(&mut magic)
        .map_err(|e| SnapshotError(e.to_string()))?;
    if magic != *b"utxo\xff" {
        return fail(
            "Invalid UTXO set snapshot magic bytes. Please check if this is indeed a snapshot file or if you are using an outdated snapshot format."
                .to_string(),
        );
    }
    let mut version = [0u8; 2];
    r.read_exact(&mut version)
        .map_err(|e| SnapshotError(e.to_string()))?;
    let version = u16::from_le_bytes(version);
    if version != 2 {
        return fail(format!(
            "Version of snapshot {version} does not match any of the supported versions."
        ));
    }
    let mut magic4 = [0u8; 4];
    r.read_exact(&mut magic4)
        .map_err(|e| SnapshotError(e.to_string()))?;
    if magic4 != message_start {
        let file_net = crate::params::Network::all()
            .into_iter()
            .find(|n| n.params().message_start == magic4);
        let node_net = crate::params::Network::all()
            .into_iter()
            .find(|n| n.params().message_start == message_start)
            .map(|n| n.name())
            .unwrap_or("unknown");
        return match file_net {
            Some(n) => fail(format!(
                "The network of the snapshot ({}) does not match the network of this node ({}).",
                n.name(),
                node_net
            )),
            None => fail(
                "This snapshot has been created for an unrecognized network. This could be a custom signet, a new testnet or possibly caused by data corruption."
                    .to_string(),
            ),
        };
    }
    let mut hash = [0u8; 32];
    r.read_exact(&mut hash)
        .map_err(|e| SnapshotError(e.to_string()))?;
    let mut count = [0u8; 8];
    r.read_exact(&mut count)
        .map_err(|e| SnapshotError(e.to_string()))?;
    Ok(SnapshotMetadata {
        base_blockhash: BlockHash::from_bytes(hash),
        coins_count: u64::from_le_bytes(count),
    })
}

/// `VARINT`'s inverse — `ReadVarInt<I>` in `NONNEGATIVE_SIGNED` mode:
/// MSB-first base-128, `n = (n << 7) | (b & 0x7f)`, with the extra
/// `n++` Core applies per continuation byte. Bounded by `max` — the
/// destination type's maximum, exactly like Core (`n > max >> 7`
/// before folding in each byte, `n == max` before each `n++`), not by
/// `u64::MAX` unconditionally: `Coin`'s `code` and `ScriptCompression`'s
/// `nSize` are `uint32_t` on the wire, so a value only representable
/// past `u32::MAX` is exactly as invalid to Core as a truncated stream.
pub(crate) fn read_varint(r: &mut impl std::io::Read, max: u64) -> std::io::Result<u64> {
    let mut buf = [0u8; 1];
    let mut n = 0u64;
    loop {
        if n > max >> 7 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ReadVarInt(): size too large",
            ));
        }
        r.read_exact(&mut buf)?;
        n = (n << 7) | u64::from(buf[0] & 0x7f);
        if buf[0] & 0x80 != 0 {
            if n == max {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "ReadVarInt(): too-large value",
                ));
            }
            n += 1;
        } else {
            return Ok(n);
        }
    }
}

/// `DecompressAmount` — the inverse of [`compress_amount`].
pub(crate) fn decompress_amount(mut x: u64) -> u64 {
    if x == 0 {
        return 0;
    }
    // x = 1 + 10*(9*n + d - 1) + e  or  x = 10*(9*n + 1)
    x -= 1;
    let mut e = x % 10;
    x /= 10;
    // x = 9*n + d - 1 — the digit part is packed base-9, not base-10.
    let mut n = if e < 9 {
        let d = (x % 9) + 1;
        x /= 9;
        x * 10 + d
    } else {
        x + 1
    };
    while e > 0 {
        // Malicious input can drive the exponent past u64 — saturate
        // (the caller's MAX_MONEY range-check rejects it downstream).
        n = n.saturating_mul(10);
        e -= 1;
    }
    n
}

/// `DecompressScript` — rebuilds the scriptPubKey a compressed `Coin`
/// carries. `size_id` 0..=5 are the standard templates; 28/29/30 are
/// the decode-only legacy witness ids; `>= 6` reads `size_id - 6` raw
/// bytes.
pub(crate) fn decompress_script(
    r: &mut impl std::io::Read,
    size_id: u64,
) -> std::io::Result<Script> {
    let mut take = |n: usize| -> std::io::Result<Vec<u8>> {
        let mut v = vec![0u8; n];
        r.read_exact(&mut v)?;
        Ok(v)
    };
    match size_id {
        // P2PKH
        0 => {
            let h = take(20)?;
            let mut s = Vec::with_capacity(25);
            s.extend_from_slice(&[0x76, 0xa9, 0x14]);
            s.extend_from_slice(&h);
            s.extend_from_slice(&[0x88, 0xac]);
            Ok(Script::new(s))
        }
        // P2SH
        1 => {
            let h = take(20)?;
            let mut s = Vec::with_capacity(23);
            s.extend_from_slice(&[0xa9, 0x14]);
            s.extend_from_slice(&h);
            s.push(0x87);
            Ok(Script::new(s))
        }
        // P2PK compressed — payload is X; prefix byte is the id itself.
        id @ (2 | 3) => {
            let x = take(32)?;
            let mut s = Vec::with_capacity(35);
            s.push(33);
            s.push(id as u8);
            s.extend_from_slice(&x);
            s.push(0xac);
            Ok(Script::new(s))
        }
        // P2PK uncompressed — payload is X plus Y's parity; the full
        // point is recovered and serialized uncompressed. An off-curve
        // X can't be `XOnlyPublicKey::from_slice`d — Core's
        // `DecompressScript` returns `false` in that case and
        // `ScriptCompression::Unser` ignores the bool, leaving `script`
        // at its default-constructed empty value; we match that (an
        // empty script) instead of hard-erroring, so a coin nobody but
        // an adversary would create still decodes rather than poisoning
        // the whole snapshot/record read.
        id @ (4 | 5) => {
            let x = take(32)?;
            match secp256k1::XOnlyPublicKey::from_slice(&x) {
                Ok(xonly) => {
                    let parity = if id == 4 {
                        secp256k1::Parity::Even
                    } else {
                        secp256k1::Parity::Odd
                    };
                    let pubkey = secp256k1::PublicKey::from_x_only_public_key(xonly, parity)
                        .serialize_uncompressed();
                    let mut s = Vec::with_capacity(67);
                    s.push(65);
                    s.extend_from_slice(&pubkey);
                    s.push(0xac);
                    Ok(Script::new(s))
                }
                Err(_) => Ok(Script::new(Vec::new())),
            }
        }
        n => {
            let payload = take((n - 6) as usize)?;
            Ok(Script::new(payload))
        }
    }
}

/// `ReadCompactSize` over a raw stream — prefix-driven, with the
/// canonical-encoding rejections `Unserialize` performs.
fn read_compact_size_from(r: &mut impl std::io::Read) -> std::io::Result<u64> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b)?;
    let too_short = |what: &str| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("non-canonical ReadCompactSize(): {what}"),
        )
    };
    match b[0] {
        n if n < 253 => Ok(u64::from(n)),
        253 => {
            let mut v = [0u8; 2];
            r.read_exact(&mut v)?;
            let n = u64::from(u16::from_le_bytes(v));
            if n < 253 {
                Err(too_short("16-bit"))
            } else {
                Ok(n)
            }
        }
        254 => {
            let mut v = [0u8; 4];
            r.read_exact(&mut v)?;
            let n = u64::from(u32::from_le_bytes(v));
            if n < 0x1_0000 {
                Err(too_short("32-bit"))
            } else {
                Ok(n)
            }
        }
        _ => {
            let mut v = [0u8; 8];
            r.read_exact(&mut v)?;
            let n = u64::from_le_bytes(v);
            if n < 0x1_0000_0000 {
                Err(too_short("64-bit"))
            } else {
                Ok(n)
            }
        }
    }
}

/// The coin-stream half of `PopulateAndValidateSnapshot`: groups of
/// `txid || CompactSize(n_outs) || (CompactSize(vout) || coin)*`,
/// invoking `sink` per coin. Per-coin guards mirror Core's:
/// height <= base, vout < u32::MAX, `MoneyRange` on the value — each
/// failure reports the count of coins decoded so far, and a trailing
/// byte after the declared count is its own error.
///
/// # Errors
///
/// `SnapshotError` with `PopulateAndValidateSnapshot`'s messages:
/// count mismatch, bad per-coin data (with the decoded tally), a
/// truncated stream, or leftover bytes.
pub fn read_coins<R: std::io::Read>(
    r: &mut R,
    coins_count: u64,
    base_height: u32,
    mut sink: impl FnMut(OutPoint, Coin),
) -> Result<(), SnapshotError> {
    let mut coins_left = coins_count;
    let mut coins_processed = 0u64;
    let truncated = |processed: u64| {
        SnapshotError(format!(
            "Bad snapshot format or truncated snapshot after deserializing {processed} coins"
        ))
    };
    while coins_left > 0 {
        let mut txid = [0u8; 32];
        r.read_exact(&mut txid)
            .map_err(|_| truncated(coins_processed))?;
        let coins_per_txid = read_compact_size_from(r).map_err(|_| truncated(coins_processed))?;
        if coins_per_txid > coins_left {
            return Err(SnapshotError(
                "Mismatch in coins count in snapshot metadata and actual snapshot data".to_string(),
            ));
        }
        for _ in 0..coins_per_txid {
            let outpoint_vout =
                read_compact_size_from(r).map_err(|_| truncated(coins_processed))?;
            let code =
                read_varint(r, u64::from(u32::MAX)).map_err(|_| truncated(coins_processed))?;
            let amount_raw = read_varint(r, u64::MAX).map_err(|_| truncated(coins_processed))?;
            let size_id =
                read_varint(r, u64::from(u32::MAX)).map_err(|_| truncated(coins_processed))?;
            let script = decompress_script(r, size_id).map_err(|_| truncated(coins_processed))?;
            let coin = Coin {
                out: crate::transaction::TxOut {
                    value: decompress_amount(amount_raw) as i64,
                    script_pubkey: script,
                },
                height: (code >> 1) as u32,
                coinbase: code & 1 == 1,
            };
            let outpoint = OutPoint {
                txid: crate::hash::Txid::from_bytes(txid),
                vout: outpoint_vout as u32,
            };
            if coin.height > base_height || outpoint_vout >= u64::from(u32::MAX) {
                return Err(SnapshotError(format!(
                    "Bad snapshot data after deserializing {coins_processed} coins (height={} vout={} code={} size_id={} amt_raw={} txid={})",
                    coin.height,
                    outpoint_vout,
                    code,
                    size_id,
                    amount_raw,
                    crate::hash::format_display_hex(&txid),
                )));
            }
            if !(0..=crate::check::MAX_MONEY).contains(&coin.out.value) {
                return Err(SnapshotError(format!(
                    "Bad snapshot data after deserializing {coins_processed} coins - bad tx out value"
                )));
            }
            sink(outpoint, coin);
            coins_left -= 1;
            coins_processed += 1;
        }
    }
    // Core reads one more byte expecting EOF — anything left is
    // "coins left over".
    let mut extra = [0u8; 1];
    if r.read_exact(&mut extra).is_ok() {
        return Err(SnapshotError(format!(
            "Bad snapshot - coins left over after deserializing {coins_count} coins"
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// `CompressAmount`/`DecompressAmount` roundtrip — the digit part is
    /// packed base-9 (`9*n + d - 1`), which a naive base-10 decode
    /// silently corrupts (the first real `dumptxoutset` caught this:
    /// 25 BTC compressed to 229 decoded as 2.3e9).
    #[test]
    fn amount_compress_roundtrip() {
        // Core compressor.cpp vectors: (sats, compressed).
        let vectors: [(u64, u64); 6] = [
            (0, 0),
            (1, 1),
            (100_000_000, 9),     // 1 BTC — 8 trailing zeros
            (5_000_000_000, 50),  // 50 BTC — e==9 branch
            (2_500_000_000, 229), // 25 BTC — base-9 digit path
            (123_456_789, 1_111_111_101),
        ];
        for (sats, want) in &vectors {
            assert_eq!(compress_amount(*sats), *want, "compress({sats})");
            assert_eq!(decompress_amount(*want), *sats, "decompress({want})");
        }
        // Broad roundtrip — every boundary of the encoding.
        for sats in [
            1u64,
            9,
            10,
            11,
            99,
            100,
            101,
            999,
            1000,
            5_462,
            54_620,
            546_200,
            5_462_000,
            99_999_999,
            1_000_000_000,
            21_000_000_000_000_000,
        ] {
            let c = compress_amount(sats);
            assert_eq!(decompress_amount(c), sats, "roundtrip({sats}) via {c}");
        }
    }

    /// A 65-byte `0x04`-prefixed P2PK script whose X coordinate is
    /// off-curve — anyone can mine one; Bitcoin's script rules only
    /// check the push shape, not that the "pubkey" is a real curve
    /// point. Core's `IsToPubKey` refuses to compress such a script
    /// (`CPubKey::IsFullyValid()` fails) and stores it raw.
    fn invalid_uncompressed_pubkey_script() -> Script {
        let mut s = Vec::with_capacity(67);
        s.push(65);
        s.push(4);
        // 2^256 - 1 exceeds the secp256k1 field prime, so it isn't
        // even a candidate X — guaranteed off-curve regardless of Y.
        s.extend_from_slice(&[0xffu8; 64]);
        s.push(0xac);
        Script::new(s)
    }

    #[test]
    fn compress_script_rejects_off_curve_uncompressed_pubkey() {
        let script = invalid_uncompressed_pubkey_script();
        assert!(matches!(script.classify(), ScriptType::PubKey(_)));
        let (size_id, payload) = compress_script(&script);
        // Falls to the raw `len + 6` fallback, never id 4/5.
        assert_eq!(size_id, script.len() as u64 + 6);
        assert_eq!(payload, script.as_bytes());
    }

    #[test]
    fn decompress_script_id_4_5_off_curve_x_yields_empty_script() {
        // A record that *claims* id 4 over an off-curve X (a corrupt
        // record, or a hostile/foreign snapshot) must decode to an
        // empty script — Core's `DecompressScript` returns `false` and
        // `ScriptCompression::Unser` ignores it, leaving the
        // default-constructed empty `CScript` — never a hard error
        // that would abort a whole snapshot load.
        let mut r = &[0xffu8; 32][..];
        let script = decompress_script(&mut r, 4).unwrap();
        assert!(script.as_bytes().is_empty());
    }

    /// End-to-end: a coin carrying the off-curve pubkey script
    /// round-trips byte-exact through `write_snapshot`/`read_coins` —
    /// before this fix, `read_coins` aborted the whole load on this
    /// coin's unrecoverable compressed X.
    #[test]
    fn snapshot_roundtrips_off_curve_pubkey_coin() {
        let script = invalid_uncompressed_pubkey_script();
        let op = OutPoint {
            txid: crate::hash::Txid::from_bytes([7u8; 32]),
            vout: 0,
        };
        let coin = Coin {
            out: crate::transaction::TxOut {
                value: 5_000,
                script_pubkey: script.clone(),
            },
            height: 100,
            coinbase: false,
        };
        let mut buf = Vec::new();
        let message_start = [0xf9, 0xbe, 0xb4, 0xd9];
        let base = BlockHash::from_bytes([1u8; 32]);
        write_snapshot(&mut buf, message_start, &base, 1, &[(op, coin)]).unwrap();

        let mut r = &buf[..];
        let meta = read_metadata(&mut r, message_start).unwrap();
        assert_eq!(meta.coins_count, 1);
        let mut got = Vec::new();
        read_coins(&mut r, meta.coins_count, 100, |o, c| got.push((o, c))).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, op);
        assert_eq!(got[0].1.out.value, 5_000);
        assert_eq!(got[0].1.out.script_pubkey.as_bytes(), script.as_bytes());
        assert_eq!(got[0].1.height, 100);
    }

    /// Core's `ReadVarInt<uint32_t>` (used for `Coin::code` and
    /// `ScriptCompression::nSize`) must reject a value past `u32::MAX`
    /// even though the identical bytes decode fine as a `u64` (the
    /// bound amounts use).
    #[test]
    fn read_varint_bounds_by_destination_type() {
        let max = u64::from(u32::MAX);
        let mut buf = Vec::new();
        write_varint(&mut buf, max);
        assert_eq!(read_varint(&mut &buf[..], max).unwrap(), max);

        let mut buf = Vec::new();
        write_varint(&mut buf, max + 1);
        assert!(
            read_varint(&mut &buf[..], max).is_err(),
            "must reject past u32::MAX"
        );
        assert_eq!(read_varint(&mut &buf[..], u64::MAX).unwrap(), max + 1);
    }
}
