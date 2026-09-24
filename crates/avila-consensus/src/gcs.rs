//! BIP 158 compact block filters — the `basic` filter is a Golomb-coded
//! set (GCS) over SipHash-keyed scriptPubKeys: every non-OP_RETURN output
//! script in the block plus every script the block's spends lock up (from
//! the undo data). `getblockfilter` serves these and `scanblocks` runs
//! descriptor scripts through [`filter_match_any`].
//!
//! Construction matches Core's `GCSFilter`/`BlockFilter` bit-for-bit —
//! SipHash-2-4 keyed by the block hash's first 16 bytes, `FastRange64`
//! range mapping, Golomb-Rice delta coding at `P=19`, `M=784931`, and a
//! CompactSize `N` prefix on the encoded bitstream.

use crate::block::Block;
use crate::connect::BlockUndo;
use crate::encode::write_compact_size;
use crate::hash::BlockHash;

/// Golomb-Rice parameter P for basic filters (BIP 158).
const BASIC_P: u8 = 19;
/// Inverse false-positive rate for basic filters (BIP 158).
const BASIC_M: u64 = 784931;
/// OP_RETURN — outputs whose script starts with it are excluded (Core's
/// `script[0] == OP_RETURN` check, not just `IsUnspendable`).
const OP_RETURN: u8 = 0x6a;

/// One SipHash mixing round — Core's `SIPROUND`.
macro_rules! sipround {
    ($v0:expr, $v1:expr, $v2:expr, $v3:expr) => {
        $v0 = $v0.wrapping_add($v1);
        $v1 = $v1.rotate_left(13) ^ $v0;
        $v0 = $v0.rotate_left(32);
        $v2 = $v2.wrapping_add($v3);
        $v3 = $v3.rotate_left(16) ^ $v2;
        $v0 = $v0.wrapping_add($v3);
        $v3 = $v3.rotate_left(21) ^ $v0;
        $v2 = $v2.wrapping_add($v1);
        $v1 = $v1.rotate_left(17) ^ $v2;
        $v2 = $v2.rotate_left(32);
    };
}

/// SipHash-2-4 — Core's `CSipHasher` with `Finalize()`: tail bytes fold
/// in little-endian with the byte count in the top byte, then four
/// finalization rounds.
pub fn siphash24(k0: u64, k1: u64, data: &[u8]) -> u64 {
    let mut v0 = k0 ^ 0x736f_6d65_7073_6575;
    let mut v1 = k1 ^ 0x646f_7261_6e64_6f6d;
    let mut v2 = k0 ^ 0x6c79_6765_6e65_7261;
    let mut v3 = k1 ^ 0x7465_6462_7974_6573;
    let (chunks, remainder) = data.as_chunks::<8>();
    for &c in chunks {
        let m = u64::from_le_bytes(c);
        v3 ^= m;
        sipround!(v0, v1, v2, v3);
        sipround!(v0, v1, v2, v3);
        v0 ^= m;
    }
    let mut tail = u64::from(data.len() as u8) << 56;
    for (i, b) in remainder.iter().enumerate() {
        tail |= u64::from(*b) << (8 * i);
    }
    v3 ^= tail;
    sipround!(v0, v1, v2, v3);
    sipround!(v0, v1, v2, v3);
    v0 ^= tail;
    v2 ^= 0xff;
    sipround!(v0, v1, v2, v3);
    sipround!(v0, v1, v2, v3);
    sipround!(v0, v1, v2, v3);
    sipround!(v0, v1, v2, v3);
    v0 ^ v1 ^ v2 ^ v3
}

/// Core's `FastRange64` — the multiply-high map `x * n >> 64`.
fn fast_range64(x: u64, n: u64) -> u64 {
    ((u128::from(x) * u128::from(n)) >> 64) as u64
}

/// The SipHash keys a basic filter derives from its block hash — Core's
/// `block_hash.GetUint64(0/1)` (little-endian words of the hash bytes).
fn filter_keys(block_hash: &BlockHash) -> (u64, u64) {
    let b = block_hash.as_bytes();
    (
        u64::from_le_bytes(b[0..8].try_into().unwrap_or([0; 8])),
        u64::from_le_bytes(b[8..16].try_into().unwrap_or([0; 8])),
    )
}

fn hash_to_range(element: &[u8], k0: u64, k1: u64, f: u64) -> u64 {
    fast_range64(siphash24(k0, k1, element), f)
}

/// Appends `nbits` low bits of `data` MSB-first — Core's
/// `BitStreamWriter::Write`. `flush` zero-pads the last byte.
struct BitWriter {
    out: Vec<u8>,
    /// Bits used in `out`'s last byte, 0 when `out` is byte-aligned.
    used: u8,
}

impl BitWriter {
    fn write(&mut self, data: u64, nbits: u8) {
        let data = if nbits == 64 {
            data
        } else {
            data & ((1u64 << nbits) - 1)
        };
        for i in (0..nbits).rev() {
            let bit = (data >> i) & 1;
            if self.used == 0 {
                self.out.push(0);
            }
            if bit == 1 {
                let last = self.out.len() - 1;
                self.out[last] |= 0x80 >> self.used;
            }
            self.used = (self.used + 1) % 8;
        }
    }
}

/// Reads `nbits` MSB-first — Core's `BitStreamReader::Read`. Returns
/// `None` past the end of the bitstream.
struct BitReader<'a> {
    data: &'a [u8],
    /// Absolute bit position.
    pos: usize,
}

impl<'a> BitReader<'a> {
    fn read(&mut self, nbits: u8) -> Option<u64> {
        if self.pos + usize::from(nbits) > self.data.len() * 8 {
            return None;
        }
        let mut v = 0u64;
        for _ in 0..nbits {
            let bit = u64::from(self.data[self.pos / 8] >> (7 - self.pos % 8) & 1);
            v = (v << 1) | bit;
            self.pos += 1;
        }
        Some(v)
    }
}

/// Golomb-Rice encodes `x` at parameter `P`: quotient in unary (`q` 1s
/// then a 0), remainder in `P` bits — Core's `GolombRiceEncode`.
fn gr_encode(w: &mut BitWriter, p: u8, x: u64) {
    let mut q = x >> p;
    while q > 0 {
        let nbits = q.min(64) as u8;
        w.write(u64::MAX, nbits);
        q -= u64::from(nbits);
    }
    w.write(0, 1);
    w.write(x, p);
}

/// Golomb-Rice decode — Core's `GolombRiceDecode`. `None` on a
/// truncated stream.
fn gr_decode(r: &mut BitReader<'_>, p: u8) -> Option<u64> {
    let mut q = 0u64;
    while r.read(1)? == 1 {
        q += 1;
    }
    Some((q << p) + r.read(p)?)
}

/// The element set a basic filter commits — Core's
/// `BasicFilterElements`: every non-OP_RETURN, non-empty output
/// scriptPubKey in the block, plus every non-empty scriptPubKey the
/// undo data shows spent, deduplicated. Core collects into a
/// `std::set<Element>`, so a repeated scriptPubKey (very common —
/// change addresses, exchange hot wallets) contributes exactly one
/// member; counting or hashing duplicates would desync `N`, the
/// Golomb-Rice stream, and therefore the filter header from the rest
/// of the network. `BTreeSet` also reproduces `std::set`'s
/// lexicographic byte order, though only the dedup matters here since
/// [`build_basic`] re-sorts by hash anyway.
pub fn basic_elements(block: &Block, undo: &BlockUndo) -> Vec<Vec<u8>> {
    let mut elements = std::collections::BTreeSet::new();
    for tx in &block.transactions {
        for out in &tx.outputs {
            let s = out.script_pubkey.as_bytes();
            if s.first() == Some(&OP_RETURN) || s.is_empty() {
                continue;
            }
            elements.insert(s.to_vec());
        }
    }
    for tx_undo in &undo.txs {
        for coin in &tx_undo.spent {
            let s = coin.out.script_pubkey.as_bytes();
            if !s.is_empty() {
                elements.insert(s.to_vec());
            }
        }
    }
    elements.into_iter().collect()
}

/// Builds the serialized basic filter for `block` — the CompactSize `N`
/// prefix plus the Golomb-Rice bitstream (Core's `GCSFilter` constructor
/// over `BasicFilterElements`).
pub fn build_basic(block: &Block, undo: &BlockUndo) -> Vec<u8> {
    let (k0, k1) = filter_keys(&block.header.hash());
    let elements = basic_elements(block, undo);
    let f = elements.len() as u64 * BASIC_M;
    let mut hashed: Vec<u64> = elements
        .iter()
        .map(|e| hash_to_range(e, k0, k1, f))
        .collect();
    hashed.sort_unstable();
    let mut out = Vec::new();
    write_compact_size(&mut out, hashed.len() as u64);
    let mut w = BitWriter {
        out: Vec::new(),
        used: 0,
    };
    let mut last = 0u64;
    for v in hashed {
        gr_encode(&mut w, BASIC_P, v - last);
        last = v;
    }
    out.extend_from_slice(&w.out);
    out
}

/// Core's `GCSFilter::MatchAny` — sorts the query hashes and merge-walks
/// the filter's sorted values. `queries` are raw scriptPubKeys; `None`
/// on a malformed filter.
pub fn filter_match_any(
    encoded: &[u8],
    block_hash: &BlockHash,
    queries: &[Vec<u8>],
) -> Option<bool> {
    let mut dec = crate::encode::Decoder::new(encoded);
    let n = dec.read_compact_size().ok()?;
    if n > u64::from(u32::MAX) {
        return None;
    }
    let (k0, k1) = filter_keys(block_hash);
    let f = n * BASIC_M;
    let mut qhashes: Vec<u64> = queries
        .iter()
        .map(|q| hash_to_range(q, k0, k1, f))
        .collect();
    qhashes.sort_unstable();
    if qhashes.is_empty() {
        return Some(false);
    }
    let mut r = BitReader {
        data: &encoded[dec.position()..],
        pos: 0,
    };
    let mut value = 0u64;
    let mut qi = 0usize;
    for _ in 0..n {
        value = value.checked_add(gr_decode(&mut r, BASIC_P)?)?;
        while qi < qhashes.len() {
            if qhashes[qi] == value {
                return Some(true);
            }
            if qhashes[qi] > value {
                break;
            }
            qi += 1;
        }
        if qi == qhashes.len() {
            return Some(false);
        }
    }
    Some(false)
}

/// `BlockFilter::GetHash` — dSHA256 of the encoded filter.
#[must_use]
pub fn filter_hash(encoded: &[u8]) -> [u8; 32] {
    crate::hash::sha256d(encoded)
}

/// `BlockFilter::ComputeHeader` — `Hash(filter_hash || prev_header)`.
#[must_use]
pub fn compute_header(fhash: &[u8; 32], prev_header: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(fhash);
    buf.extend_from_slice(prev_header);
    crate::hash::sha256d(&buf)
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::connect::BlockUndo;
    use crate::hex;
    use crate::params::Network;

    /// BIP 158 regtest genesis: Core 29.4 `getblockfilter` reports
    /// filter 014756c0 / header 485e301e…6dc5a2b.
    #[test]
    fn regtest_genesis_filter_matches_core() {
        let block = Network::Regtest.params().genesis_block().unwrap();
        let filter = build_basic(&block, &BlockUndo::default());
        assert_eq!(hex::encode(&filter), "014756c0");
        let header = compute_header(&filter_hash(&filter), &[0; 32]);
        // `header` displays reversed like any uint256 — the same
        // convention `getblockfilter` emits.
        assert_eq!(
            crate::hash::format_display_hex(&header),
            "485e301e4509d7f0d954bf5b529f3ecef68c5191fd0e635f775c1d0266dc5a2b"
        );
    }

    /// Round-trip: a built filter matches one of its member scripts and
    /// rejects a foreign one.
    #[test]
    fn match_any_finds_member_script() {
        let block = Network::Regtest.params().genesis_block().unwrap();
        let filter = build_basic(&block, &BlockUndo::default());
        let hash = block.block_hash();
        let member = block.transactions[0].outputs[0]
            .script_pubkey
            .as_bytes()
            .to_vec();
        assert_eq!(filter_match_any(&filter, &hash, &[member]), Some(true));
        assert_eq!(filter_match_any(&filter, &hash, &[vec![0x51]]), Some(false));
    }

    /// A minimal one-transaction block paying `output_scripts`, for
    /// exercising [`basic_elements`] without a real serialized block.
    fn test_block(output_scripts: &[Vec<u8>]) -> Block {
        let outputs = output_scripts
            .iter()
            .map(|s| crate::transaction::TxOut {
                value: 1_000,
                script_pubkey: crate::transaction::Script::new(s.clone()),
            })
            .collect();
        Block {
            header: crate::header::BlockHeader {
                version: 1,
                prev_block_hash: BlockHash::from_bytes([0; 32]),
                merkle_root: crate::hash::MerkleRoot::from_bytes([0; 32]),
                time: 0,
                bits: crate::arith::CompactTarget(0x207f_ffff),
                nonce: 0,
            },
            transactions: vec![crate::transaction::Transaction {
                version: 1,
                inputs: vec![],
                outputs,
                lock_time: 0,
            }],
        }
    }

    /// Two outputs paying the identical script — Core's
    /// `BasicFilterElements` collects into a `std::set<Element>`, so a
    /// repeated scriptPubKey (very common: change addresses, exchange
    /// hot wallets) must count as exactly one member. Before the fix,
    /// `N` (the leading CompactSize) and every hash after it diverged
    /// from Core for any such block.
    #[test]
    fn basic_elements_deduplicates_repeated_scripts() {
        let mut script_a = vec![0x00, 0x14];
        script_a.extend_from_slice(&[0xaa; 20]);
        let mut script_b = vec![0x00, 0x14];
        script_b.extend_from_slice(&[0xbb; 20]);

        let dup_block = test_block(&[script_a.clone(), script_a.clone()]);
        assert_eq!(basic_elements(&dup_block, &BlockUndo::default()).len(), 1);
        // CompactSize N=1 encodes as the single byte 0x01.
        assert_eq!(build_basic(&dup_block, &BlockUndo::default())[0], 0x01);

        // Two genuinely different scripts are still both kept.
        let distinct_block = test_block(&[script_a.clone(), script_b.clone()]);
        assert_eq!(
            basic_elements(&distinct_block, &BlockUndo::default()).len(),
            2
        );

        // A duplicate split between a new output and an undo-recorded
        // spent coin is still just one element.
        let mut undo = BlockUndo::default();
        undo.txs.push(crate::connect::TxUndo {
            spent: vec![crate::connect::Coin {
                out: crate::transaction::TxOut {
                    value: 500,
                    script_pubkey: crate::transaction::Script::new(script_a.clone()),
                },
                height: 1,
                coinbase: false,
            }],
            ..Default::default()
        });
        let single_block = test_block(&[script_a.clone()]);
        assert_eq!(basic_elements(&single_block, &undo).len(), 1);
    }
}
