//! SwiftSync-style write-elision sync — measured on real chain data
//! (experiment #31 / `experiments/2026-09-24-swiftsync-write-elision.md`):
//! **67.0% of coins created during a 229k-block signet sync are spent
//! again inside the window** — writes+deletes a transient-map sync
//! never pays.
//!
//! The scheme: the [`UtxoSet`] keeps every coin in its write-back map
//! for the whole window (no flush — the honest cost is transient RAM,
//! ~682MiB at signet scale) while maintaining a 256-bit wrapping-sum
//! aggregate over [`coin_tag`]s. `created − spent == Σ live tags`
//! holds exactly — proven over 22.4M real coins — so at the checkpoint
//! the node can verify a peer-supplied [`Hints`] file: matching
//! aggregate + identical set proves the file honest; a wrong file only
//! wastes the optimization (the node writes its own live set anyway —
//! hints can never corrupt consensus state).

use crate::connect::Coin;
use crate::hash::tagged_hash;
use crate::transaction::OutPoint;

/// 256-bit wrapping-sum accumulator — the order-free multiset hash
/// maintained over created/spent coin tags. Wrapping arithmetic makes
/// subtraction the exact inverse of addition, so the running value
/// always equals Σ(live tags) regardless of order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TagAgg([u64; 4]);

impl TagAgg {
    /// Adds one coin tag.
    pub fn add(&mut self, t: &[u8; 32]) {
        for (i, w) in self.0.iter_mut().enumerate() {
            let v = u64::from_le_bytes(t[i * 8..i * 8 + 8].try_into().unwrap_or_default());
            *w = w.wrapping_add(v);
        }
    }
    /// Removes one coin tag — the exact inverse of [`Self::add`].
    pub fn sub(&mut self, t: &[u8; 32]) {
        for (i, w) in self.0.iter_mut().enumerate() {
            let v = u64::from_le_bytes(t[i * 8..i * 8 + 8].try_into().unwrap_or_default());
            *w = w.wrapping_sub(v);
        }
    }
    /// The raw 256-bit commitment, little-endian limbs.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, w) in self.0.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        out
    }
    /// Rebuilds from [`Self::to_bytes`].
    #[must_use]
    pub fn from_bytes(b: [u8; 32]) -> Self {
        let mut a = Self::default();
        for (i, w) in a.0.iter_mut().enumerate() {
            *w = u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap_or_default());
        }
        a
    }
}

/// Commitment to one created coin — binds the outpoint to the coin
/// contents (value, script, height, coinbase flag) so a hinted
/// consumer recomputes the identical tag from the coin it must
/// already fetch to validate the spend.
#[must_use]
pub fn coin_tag(op: &OutPoint, coin: &Coin) -> [u8; 32] {
    let mut b = Vec::with_capacity(49 + coin.out.script_pubkey.as_bytes().len());
    b.extend_from_slice(op.txid.as_bytes());
    b.extend_from_slice(&op.vout.to_le_bytes());
    b.extend_from_slice(&coin.out.value.to_le_bytes());
    b.extend_from_slice(&coin.height.to_le_bytes());
    b.push(u8::from(coin.coinbase));
    b.extend_from_slice(coin.out.script_pubkey.as_bytes());
    tagged_hash(b"avila/swiftsync-coin", &b)
}

/// Outcome of [`crate::connect::UtxoSet::verify_hints`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HintsVerdict {
    /// Committed aggregate matches and the survivor list is exactly
    /// the live set — the file is honest for this chain.
    Verified,
    /// The file's committed aggregate differs from ours — its
    /// producer tracked a different chain or is lying.
    AggregateMismatch,
    /// Aggregates match but the survivor list isn't our live set —
    /// malformed or adversarial content.
    SurvivorMismatch,
}

const HINTS_MAGIC: &[u8; 4] = b"AHS1";

/// A producer's claim about the UTXO set at a checkpoint: the
/// committed tag aggregate plus the sorted survivor outpoints.
/// Untrusted input — the consumer verifies aggregate + set equality
/// against its own transient map before trusting a single entry.
#[derive(Clone, Debug)]
pub struct Hints {
    /// Block height the claim describes.
    pub height: u32,
    /// The producer's `Σ live tags` commitment.
    pub aggregate: TagAgg,
    /// Surviving outpoints, sorted by `(txid, vout)`.
    pub survivors: Vec<OutPoint>,
}

impl Hints {
    /// `magic || height || aggregate || count || outpoints…`
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(44 + self.survivors.len() * 36);
        b.extend_from_slice(HINTS_MAGIC);
        b.extend_from_slice(&self.height.to_le_bytes());
        b.extend_from_slice(&self.aggregate.to_bytes());
        b.extend_from_slice(&(self.survivors.len() as u64).to_le_bytes());
        for op in &self.survivors {
            b.extend_from_slice(op.txid.as_bytes());
            b.extend_from_slice(&op.vout.to_le_bytes());
        }
        b
    }

    /// Parses an [`Self::encode`]d hints file. Errors on bad magic,
    /// truncation, or out-of-order outpoints (the sorted order is part
    /// of the format — a producer that can't sort is malformed).
    pub fn decode(b: &[u8]) -> std::io::Result<Self> {
        fn err(msg: &str) -> std::io::Error {
            std::io::Error::new(std::io::ErrorKind::InvalidData, msg.to_string())
        }
        if b.len() < 48 || &b[..4] != HINTS_MAGIC {
            return Err(err("bad hints magic"));
        }
        let height = u32::from_le_bytes(b[4..8].try_into().unwrap_or_default());
        let aggregate = TagAgg::from_bytes(b[8..40].try_into().unwrap_or_default());
        let count = u64::from_le_bytes(b[40..48].try_into().unwrap_or_default()) as usize;
        if b.len() != 48 + count * 36 {
            return Err(err("hints length mismatch"));
        }
        let mut survivors = Vec::with_capacity(count);
        let mut prev: Option<OutPoint> = None;
        for i in 0..count {
            let off = 48 + i * 36;
            let op = OutPoint {
                txid: crate::hash::Txid::from_bytes(
                    b[off..off + 32].try_into().unwrap_or_default(),
                ),
                vout: u32::from_le_bytes(b[off + 32..off + 36].try_into().unwrap_or_default()),
            };
            if prev.is_some_and(|p| (op.txid.as_bytes(), op.vout) <= (p.txid.as_bytes(), p.vout)) {
                return Err(err("survivors not strictly sorted"));
            }
            prev = Some(op);
            survivors.push(op);
        }
        Ok(Self {
            height,
            aggregate,
            survivors,
        })
    }
}
