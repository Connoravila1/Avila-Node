//! RAM-resident open-addressed coins table — the flat committed layer
//! measured in `coins_flat_bench` (~95 ns/probe single-miss vs ~3 µs
//! through the disk cascade). [`FlatCoins`] is an *exact mirror* of the
//! UTXO set's committed layers: it is populated by streaming them once
//! at enable time and updated with the same delta applied to the disk
//! backend at every flush, so a `flat` miss is an authoritative miss.
//!
//! Slot layout is fixed-width 96 bytes: 36-byte outpoint key, value,
//! height, flags, and a 40-byte inline script body — enough for every
//! standard scriptPubKey (P2PKH 25, P2WPKH/P2SH-P2WPKH 22/23,
//! P2WSH/P2TR 34/35, P2PK 35/67-spill). Longer scripts spill into a
//! pooled `Vec<u8>`; the flag bit selects. Spend tombstones are kept
//! in-slot (bit 30) so probe chains stay intact; a rebuild pass
//! compacts when tombstones pile up.

use crate::connect::Coin;
use crate::transaction::{OutPoint, Script, TxOut};

const FLAG_USED: u32 = 1 << 31;
const FLAG_TOMB: u32 = 1 << 30;
const FLAG_SPILL: u32 = 1 << 29;
const FLAG_COINBASE: u32 = 1;
const SPK_LEN_SHIFT: u32 = 2;
const SPK_LEN_MASK: u32 = 0x3f << 2; // 6 bits, inline cap 40
const INLINE_SPK: usize = 40;

#[repr(C)]
#[derive(Clone, Copy)]
struct Slot {
    key: [u8; 36],
    value: i64,
    height: u32,
    flags: u32,
    spk: [u8; INLINE_SPK],
}

#[inline]
fn key_of(op: &OutPoint) -> [u8; 36] {
    let mut k = [0u8; 36];
    k[..32].copy_from_slice(op.txid.as_bytes());
    k[32..].copy_from_slice(&op.vout.to_le_bytes());
    k
}

#[inline]
fn hash(k: &[u8; 36]) -> usize {
    let lo = u64::from_le_bytes(k[..8].try_into().unwrap_or_default());
    let v = u32::from_le_bytes(k[32..36].try_into().unwrap_or_default()) as u64;
    lo.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(v) as usize
}

/// The flat committed-coin mirror. `None` on a `UtxoSet` means the
/// lookup falls through to the disk backend exactly as before — this
/// layer is purely a cache, never the only copy of state.
#[derive(Debug)]
pub struct FlatCoins {
    slots: Vec<Slot>,
    mask: usize,
    /// Number of live (non-tombstone) entries — capacity signal.
    live: usize,
    /// Number of tombstones — rebuild trigger.
    tomb: usize,
    /// Long-script pool: spilled scriptPubKey bytes, append-only.
    pool: Vec<u8>,
}

impl Default for Slot {
    fn default() -> Self {
        Slot {
            key: [0; 36],
            value: 0,
            height: 0,
            flags: 0,
            spk: [0; INLINE_SPK],
        }
    }
}
impl std::fmt::Debug for Slot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Slot(flags={:#x})", self.flags)
    }
}

impl FlatCoins {
    /// An empty table sized for `cap` live entries at ~0.7 load.
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        let n = (((cap as f64) / 0.7) as usize).next_power_of_two().max(16);
        FlatCoins {
            slots: vec![Slot::default(); n],
            mask: n - 1,
            live: 0,
            tomb: 0,
            pool: Vec::new(),
        }
    }

    /// Estimated resident bytes for `cap` coins — the cap check.
    #[must_use]
    pub fn estimate_bytes(cap: usize) -> usize {
        (((cap as f64) / 0.7) as usize).next_power_of_two() * 96 + cap * 8
    }

    /// Live coin count — diagnostics; the authoritative `len()` stays
    /// with the UtxoSet's own accounting.
    #[must_use]
    pub fn len(&self) -> usize {
        self.live
    }

    /// `true` when the table holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    /// Inserts or overwrites `op → coin` (the commit path's `Some`
    /// entries). Never inserts a coin whose script exceeds the pool.
    pub fn insert(&mut self, op: &OutPoint, coin: &Coin) {
        let k = key_of(op);
        let mut i = hash(&k) & self.mask;
        loop {
            let f = self.slots[i].flags;
            if f & FLAG_USED == 0 {
                break;
            }
            if self.slots[i].key == k {
                // same-key overwrite or tombstone resurrection
                if f & FLAG_TOMB != 0 {
                    self.tomb -= 1;
                    self.live += 1;
                }
                self.write_slot(i, k, coin);
                return;
            }
            i = (i + 1) & self.mask;
        }
        self.live += 1;
        self.write_slot(i, k, coin);
        self.maybe_rebuild();
    }

    fn write_slot(&mut self, i: usize, key: [u8; 36], coin: &Coin) {
        let spk = coin.out.script_pubkey.as_bytes();
        let mut flags = FLAG_USED | u32::from(coin.coinbase);
        let mut body = [0u8; INLINE_SPK];
        if spk.len() <= INLINE_SPK {
            body[..spk.len()].copy_from_slice(spk);
            flags |= (spk.len() as u32) << SPK_LEN_SHIFT;
        } else {
            let off = self.pool.len() as u64;
            self.pool.extend_from_slice(spk);
            body[..8].copy_from_slice(&off.to_le_bytes());
            body[8..12].copy_from_slice(&(spk.len() as u32).to_le_bytes());
            flags |= FLAG_SPILL;
        }
        self.slots[i] = Slot {
            key,
            value: coin.out.value,
            height: coin.height,
            flags,
            spk: body,
        };
    }

    /// The coin at `op`, or `None` — tombstones and empty slots both
    /// end the probe; only a full 36-byte key compare confirms a hit.
    #[must_use]
    pub fn get(&self, op: &OutPoint) -> Option<Coin> {
        let k = key_of(op);
        let mut i = hash(&k) & self.mask;
        loop {
            let s = &self.slots[i];
            if s.flags & FLAG_USED == 0 {
                return None;
            }
            if s.flags & FLAG_TOMB == 0 && s.key == k {
                return Some(self.coin_of(s));
            }
            i = (i + 1) & self.mask;
        }
    }

    /// `true` if `op` is live in the table (Core's `HaveCoin`).
    #[must_use]
    pub fn have(&self, op: &OutPoint) -> bool {
        let k = key_of(op);
        let mut i = hash(&k) & self.mask;
        loop {
            let s = &self.slots[i];
            if s.flags & FLAG_USED == 0 {
                return false;
            }
            if s.flags & FLAG_TOMB == 0 && s.key == k {
                return true;
            }
            i = (i + 1) & self.mask;
        }
    }

    /// Marks `op` spent (the commit path's `None` entries) — a
    /// tombstone that keeps probe chains traversable.
    pub fn remove(&mut self, op: &OutPoint) {
        let k = key_of(op);
        let mut i = hash(&k) & self.mask;
        loop {
            let s = &self.slots[i];
            if s.flags & FLAG_USED == 0 {
                return; // never committed — born-key elision made it absent
            }
            if s.flags & FLAG_TOMB == 0 && s.key == k {
                self.slots[i].flags |= FLAG_TOMB;
                self.live -= 1;
                self.tomb += 1;
                return;
            }
            i = (i + 1) & self.mask;
        }
    }

    /// Applies a committed delta exactly as the backend does: `Some`
    /// inserts/overwrites, `None` tombstones.
    pub fn apply_delta(&mut self, map: &std::collections::HashMap<OutPoint, Option<Coin>>) {
        for (op, entry) in map {
            match entry {
                Some(c) => self.insert(op, c),
                None => self.remove(op),
            }
        }
    }

    fn coin_of(&self, s: &Slot) -> Coin {
        coin_in(s, &self.pool)
    }

    /// All live entries — the committed-view iterator for
    /// `UtxoSet::iter`/`iter_delta`.
    pub fn iter(&self) -> Vec<(OutPoint, Coin)> {
        let mut out = Vec::with_capacity(self.live);
        for s in &self.slots {
            if s.flags & FLAG_USED != 0 && s.flags & FLAG_TOMB == 0 {
                let mut t = [0u8; 32];
                t.copy_from_slice(&s.key[..32]);
                let op = OutPoint {
                    txid: crate::hash::Txid::from_bytes(t),
                    vout: u32::from_le_bytes(s.key[32..].try_into().unwrap_or_default()),
                };
                out.push((op, self.coin_of(s)));
            }
        }
        out
    }

    /// Keeps the table healthy: grows when occupancy (live+tombstones)
    /// passes ~0.7 — a full table would probe forever — and compacts
    /// when tombstones alone exceed a quarter of slots (chain drag).
    fn maybe_rebuild(&mut self) {
        let occupied = self.live + self.tomb;
        let grow = occupied * 10 > self.slots.len() * 7;
        let compact = !grow && self.tomb * 4 > self.slots.len();
        if !grow && !compact {
            return;
        }
        let n = if grow {
            ((self.live * 2) as f64 / 0.7) as usize
        } else {
            self.slots.len()
        }
        .next_power_of_two()
        .max(16);
        let mut fresh = FlatCoins {
            slots: vec![Slot::default(); n],
            mask: n - 1,
            live: 0,
            tomb: 0,
            pool: std::mem::take(&mut self.pool),
        };
        for i in 0..self.slots.len() {
            let s = self.slots[i];
            if s.flags & FLAG_USED != 0 && s.flags & FLAG_TOMB == 0 {
                // NB: `self.pool` was already moved into `fresh` —
                // spilled scripts must be read through it.
                let coin = coin_in(&s, &fresh.pool);
                let mut t = [0u8; 32];
                t.copy_from_slice(&s.key[..32]);
                fresh.insert(
                    &OutPoint {
                        txid: crate::hash::Txid::from_bytes(t),
                        vout: u32::from_le_bytes(s.key[32..].try_into().unwrap_or_default()),
                    },
                    &coin,
                );
            }
        }
        self.slots = fresh.slots;
        self.mask = fresh.mask;
        self.pool = fresh.pool;
        self.live = fresh.live;
        self.tomb = fresh.tomb;
    }
}

/// Reconstructs a `Coin` from a slot — pool explicit so rebuilds can
/// read through the moved pool (`self.pool` is empty mid-rebuild).
fn coin_in(s: &Slot, pool: &[u8]) -> Coin {
    let len = if s.flags & FLAG_SPILL != 0 {
        u32::from_le_bytes(s.spk[8..12].try_into().unwrap_or_default()) as usize
    } else {
        ((s.flags & SPK_LEN_MASK) >> SPK_LEN_SHIFT) as usize
    };
    let spk = if s.flags & FLAG_SPILL != 0 {
        let off = u64::from_le_bytes(s.spk[..8].try_into().unwrap_or_default()) as usize;
        pool[off..off + len].to_vec()
    } else {
        s.spk[..len].to_vec()
    };
    Coin {
        out: TxOut {
            value: s.value,
            script_pubkey: Script::new(spk),
        },
        height: s.height,
        coinbase: s.flags & FLAG_COINBASE != 0,
    }
}
