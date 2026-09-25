//! Utreexo accumulator backend — the "proof-carrying state" experiment
//! (queue #3, spike evidence in `experiments/2026-09-24-utreexo-spike.md`).
//!
//! A conventional UTXO backend answers point lookups against the whole
//! coin set (~12 GiB at 170M coins). This backend stores only the
//! accumulator: a [`Stump`] — roots + leaf count, ~864 B at mainnet
//! scale — and *cannot* answer lookups. Blocks connect via
//! [`connect_block_proven`]: the caller supplies every spent
//! `(OutPoint, Coin)` plus an accumulator [`Proof`] covering their
//! leaves. We verify membership against the pre-block accumulator,
//! connect through the unchanged [`connect_block`] on an overlay, then
//! apply adds+deletes to the stump.
//!
//! A proof proves *the supplied coin data* hashes to a committed leaf —
//! it cannot forge a coin, only omit: a spent input absent from the
//! bundle fails lookup exactly like an unknown prevout. Consensus
//! soundness never rests on the bridge; a missing/withheld proof is a
//! stall, never a bypass.
//!
//! ## Leaf scheme
//!
//! `leaf = sha256d(outpoint_key[36] || compact_coin_record)` — the
//! same derivation as the spike. This is Avila's own scheme, not the
//! BIP LeafData hash; bridge interop is a deliberate later step.
//!
//! ## Not yet
//!
//! Reorg/undo (the `UpdateData` rustreexo returns makes reverts
//! possible — not wired), proof *serving* (`MemForest`-backed bridge),
//! and p2p proof-bundle transport (queue #6).

use crate::block::Block;
use crate::coinsdb::{self, CoinFormat};
use crate::connect::{Coin, ConnectContext, ConnectError, connect_block};
use crate::transaction::OutPoint;
use crate::utxo_snapshot::outpoint_key;
use rustreexo::node_hash::BitcoinNodeHash;
use rustreexo::proof::Proof;
use rustreexo::stump::Stump;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::Path;

/// The accumulator + its persisted state. Holds no coins — only
/// `roots` and `leaves`, the whole synchronizable state.
pub struct UtxoAccumulator {
    /// Current roots+count, held for proof verification. The file copy
    /// commits after every apply so a crash cannot lose the tip.
    pub stump: Stump<BitcoinNodeHash>,
    file: std::fs::File,
}

/// Wire/persist form is trivially small: `u64 leaves | u8 n_roots |
/// n_roots * 32B roots`.
const MAGIC: &[u8; 8] = b"AVUSTMP1";

/// Leaf commitment for one coin — `sha256d(key || compact_record)`.
/// `key` (`txid||vout` big-endian) binds the commitment to the
/// outpoint so a coin's bytes can never be claimed under another.
pub fn leaf_hash(key: &[u8; 36], coin: &[u8]) -> BitcoinNodeHash {
    let mut preimage = Vec::with_capacity(36 + coin.len());
    preimage.extend_from_slice(key);
    preimage.extend_from_slice(coin);
    BitcoinNodeHash::from(crate::hash::sha256d(&preimage))
}

/// Hash of a `(OutPoint, Coin)` pair — the common case in connect,
/// where the coin is already decoded.
pub fn leaf_for(op: &OutPoint, coin: &Coin) -> BitcoinNodeHash {
    leaf_hash(
        &outpoint_key(op),
        &coinsdb::encode_coin(coin, CoinFormat::Compact),
    )
}

impl UtxoAccumulator {
    /// Opens or creates `dir/utreexo.stump`.
    ///
    /// # Errors
    /// `io::Error` on open/create or malformed contents.
    pub fn open(dir: &Path) -> io::Result<Self> {
        let path = dir.join("utreexo.stump");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        let len = file.metadata()?.len();
        let stump = if len == 0 {
            Stump::new()
        } else {
            let mut buf = vec![0u8; len as usize];
            file.read_exact_at(&mut buf, 0)?;
            if buf.len() < 17 || buf[..8] != MAGIC[..] {
                return Err(io::Error::other("utreexo.stump: bad header"));
            }
            let leaves = u64::from_le_bytes(buf[8..16].try_into().unwrap_or_default());
            let n_roots = buf[16] as usize;
            if buf.len() != 17 + n_roots * 32 {
                return Err(io::Error::other("utreexo.stump: truncated roots"));
            }
            let roots = buf[17..]
                .as_chunks::<32>()
                .0
                .iter()
                .map(|b| BitcoinNodeHash::from(*b))
                .collect();
            Stump { leaves, roots }
        };
        Ok(Self { stump, file })
    }

    /// Persists the current stump — `fsync` before returning so the
    /// on-disk state is never ahead of memory.
    fn persist(&mut self) -> io::Result<()> {
        let mut buf = Vec::with_capacity(17 + self.stump.roots.len() * 32);
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&self.stump.leaves.to_le_bytes());
        buf.push(self.stump.roots.len() as u8);
        for r in &self.stump.roots {
            buf.extend_from_slice(&r[..]);
        }
        self.file.set_len(0)?;
        self.file.write_all_at(&buf, 0)?;
        self.file.sync_data()
    }

    /// Verifies `proof` covers exactly the supplied spend set — the
    /// (outpoint, coin) pairs must all be leaves. Verification only;
    /// no mutation.
    ///
    /// # Errors
    /// `io::Error` (kind `InvalidData`) when the proof fails.
    pub fn verify_spend_set(
        &self,
        spends: &[(OutPoint, Coin)],
        proof: &Proof<BitcoinNodeHash>,
    ) -> io::Result<()> {
        let hashes: Vec<BitcoinNodeHash> = spends.iter().map(|(op, c)| leaf_for(op, c)).collect();
        self.stump
            .verify(proof, &hashes)
            .map_err(|e| io::Error::other(format!("utreexo verify: {e}")))?
            .then_some(())
            .ok_or_else(|| io::Error::other("utreexo proof rejected"))
    }

    /// Verifies the spend set then applies adds+deletes: the new roots
    /// commit to disk before returning. On proof failure nothing
    /// changes — `Stump::modify` verifies internally.
    ///
    /// # Errors
    /// `io::Error` on proof failure or persistence error.
    pub fn apply(
        &mut self,
        adds: &[(OutPoint, Coin)],
        spends: &[(OutPoint, Coin)],
        proof: &Proof<BitcoinNodeHash>,
    ) -> io::Result<()> {
        let del_hashes: Vec<BitcoinNodeHash> =
            spends.iter().map(|(op, c)| leaf_for(op, c)).collect();
        let add_hashes: Vec<BitcoinNodeHash> = adds.iter().map(|(op, c)| leaf_for(op, c)).collect();
        let (next, _update) = self
            .stump
            .modify(&add_hashes, &del_hashes, proof)
            .map_err(|e| io::Error::other(format!("utreexo modify: {e}")))?;
        self.stump = next;
        self.persist()
    }

    /// `(leaves, roots)` — the whole accountable state.
    #[must_use]
    pub fn stats(&self) -> (u64, usize) {
        (self.stump.leaves, self.stump.roots.len())
    }
}

/// A bridge node: maintains a full [`rustreexo::mem_forest::MemForest`]
/// alongside the conventional UTXO set so every connected block's
/// spend bundle can be proven *at the moment its leaves are still
/// live*. Bundles append to `proofs.dat` (`[32B block hash][varbytes
/// bundle]`); the index is shared with [`ProofReader`].
///
/// Post-hoc serving is impossible — once a leaf is deleted the forest
/// can't prove it — so the bridge only knows blocks it connected (or
/// replayed) itself. `MemForest` is `Rc`-backed (`!Send`), so the
/// bridge runs on a dedicated worker thread: chainstate sends each
/// connected `(block, undo)` over a channel — proving stays off the
/// consensus path entirely and never shares the caller's thread state.
pub struct ProofBridge {
    /// Proving forest — kept in lockstep with connected blocks the
    /// worker has applied. `None` when stale (post-restart, or a reorg
    /// un-deleted coins the forest already dropped — MemForest has no
    /// rollback, so recording pauses rather than serve wrong proofs).
    forest: Option<rustreexo::mem_forest::MemForest<BitcoinNodeHash>>,
    /// `proofs.dat` — append-only bundle log (worker-owned).
    file: std::fs::File,
    /// `hash -> (offset, rec_len)` into `file`, shared with readers.
    /// A record lands in the index only after `write_all`+`sync_data`,
    /// so readers never see a partial bundle.
    index: std::sync::Arc<
        std::sync::RwLock<std::collections::HashMap<crate::hash::BlockHash, (u64, u64)>>,
    >,
    /// Height the forest corresponds to — the last block it applied.
    tip: u32,
}

/// The serving half of the bridge — `Send`/`Sync` (a read handle plus
/// the shared index); chainstate holds this and answers peer requests
/// while the worker forest lives on its own thread.
pub struct ProofReader {
    /// Second `File` handle on `proofs.dat` — `read_exact_at` needs no
    /// cursor coordination with the appending writer.
    file: std::fs::File,
    index: std::sync::Arc<
        std::sync::RwLock<std::collections::HashMap<crate::hash::BlockHash, (u64, u64)>>,
    >,
}

/// Work items for the bridge worker thread.
pub enum BridgeMsg {
    /// A block committed to the connected chain — prove its spends,
    /// append the bundle, apply adds+dels.
    Record {
        hash: crate::hash::BlockHash,
        height: u32,
        block: Block,
        undo: crate::connect::BlockUndo,
    },
    /// The chain disconnected blocks — the forest can no longer prove
    /// (its deleted leaves were un-deleted); recording pauses.
    Stale,
}

const PROOF_MAGIC: &[u8; 8] = b"AVUPROOF";

impl ProofBridge {
    /// Opens `dir/proofs.dat` (creating it), indexes existing bundles,
    /// then spawns the bridge worker: the `Rc`-backed forest is built
    /// *inside* the thread (the type is `!Send`, so it never crosses
    /// a boundary). Returns the serving reader, the work channel, and
    /// the worker handle — dropping the sender shuts the worker down.
    ///
    /// # Errors
    /// `io::Error` on file errors or a malformed log (bad tails
    /// truncate rather than fail — same crash policy as the blk files).
    pub fn spawn(
        dir: &Path,
    ) -> io::Result<(
        ProofReader,
        std::sync::mpsc::SyncSender<BridgeMsg>,
        std::thread::JoinHandle<()>,
    )> {
        let path = dir.join("proofs.dat");
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        let mut index = std::collections::HashMap::new();
        let len = file.metadata()?.len();
        if len == 0 {
            use std::io::Write as _;
            file.write_all(PROOF_MAGIC)?;
        } else {
            let mut buf = vec![0u8; len as usize];
            file.read_exact_at(&mut buf, 0)?;
            if buf[..8] != *PROOF_MAGIC {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "proofs.dat: bad magic",
                ));
            }
            let mut off = 8usize;
            while off + 33 <= buf.len() {
                let Ok(arr) = <[u8; 32]>::try_from(&buf[off..off + 32]) else {
                    break;
                };
                let hash = crate::hash::BlockHash::from_bytes(arr);
                let mut d = crate::encode::Decoder::new(&buf[off + 32..]);
                let Ok(blen) = d.read_compact_size() else {
                    break;
                };
                let rec_len = 32 + (buf.len() - off - 32 - d.remaining()) + blen as usize;
                let end = off + rec_len;
                if end > buf.len() {
                    break; // torn tail — index only complete records
                }
                index.insert(hash, (off as u64, (rec_len - 32) as u64));
                off = end;
            }
            // Truncate any partial tail so appends start at a record
            // boundary (a torn write from a crash is unreachable bytes).
            if off as u64 != len {
                file.set_len(off as u64)?;
            }
        }
        let index = std::sync::Arc::new(std::sync::RwLock::new(index));
        let reader = ProofReader {
            file: std::fs::File::open(&path)?,
            index: std::sync::Arc::clone(&index),
        };
        let (tx, rx) = std::sync::mpsc::sync_channel(64);
        let handle = std::thread::spawn(move || {
            let bridge = Self {
                forest: Some(rustreexo::mem_forest::MemForest::new()),
                file,
                index,
                tip: u32::MAX,
            };
            bridge.run(rx);
        });
        Ok((reader, tx, handle))
    }

    /// The worker loop — owns `self`, applies `Record` messages until
    /// the channel closes (sender drop = clean shutdown).
    pub fn run(mut self, rx: std::sync::mpsc::Receiver<BridgeMsg>) {
        while let Ok(msg) = rx.recv() {
            match msg {
                BridgeMsg::Record {
                    hash,
                    height,
                    block,
                    undo,
                } => {
                    if let Err(e) = self.record(&hash, &block, &undo, height) {
                        eprintln!("bridge: record h{height}: {e}");
                    }
                }
                BridgeMsg::Stale => {
                    self.forest = None;
                }
            }
        }
    }

    /// Records a just-connected block: proves its spend set against
    /// the current forest, appends the bundle, then applies adds+dels.
    /// No-op when the forest is stale. Returns `false` when nothing
    /// was recorded.
    ///
    /// # Errors
    /// `io::Error` on disk failure; proof failure would mean the
    /// bridge's forest diverged from the real UTXO set — a bug, not
    /// data — so it returns `InvalidData`.
    pub fn record(
        &mut self,
        hash: &crate::hash::BlockHash,
        block: &Block,
        undo: &crate::connect::BlockUndo,
        height: u32,
    ) -> io::Result<bool> {
        let Some(forest) = &mut self.forest else {
            return Ok(false);
        };
        {
            let index = self
                .index
                .read()
                .map_err(|_| io::Error::other("bridge index poisoned"))?;
            if index.contains_key(hash) && self.tip == height {
                return Ok(false); // already recorded at this tip
            }
        }
        // Spends: non-coinbase inputs zipped with undo records (input
        // order — `TxUndo.spent` is built in the same order).
        let mut spends: Vec<(OutPoint, Coin)> = Vec::new();
        for (tx, tu) in block.transactions.iter().zip(&undo.txs) {
            if tx.is_coinbase() {
                continue;
            }
            for (inp, coin) in tx.inputs.iter().zip(&tu.spent) {
                spends.push((inp.previous_output, coin.clone()));
            }
        }
        let del_hashes: Vec<BitcoinNodeHash> =
            spends.iter().map(|(op, c)| leaf_for(op, c)).collect();
        // Adds: outputs not flagged unspendable and not re-spent inside
        // the same block — mirror of `connect_block_proven`'s set.
        let mut intra_spent: std::collections::HashSet<OutPoint> = std::collections::HashSet::new();
        for tx in &block.transactions {
            if tx.is_coinbase() {
                continue;
            }
            for inp in &tx.inputs {
                intra_spent.insert(inp.previous_output);
            }
        }
        let mut adds: Vec<(OutPoint, Coin)> = Vec::new();
        for tx in &block.transactions {
            let txid = tx.txid();
            let coinbase = tx.is_coinbase();
            for (vout, out) in tx.outputs.iter().enumerate() {
                if out.script_pubkey.is_unspendable() {
                    continue;
                }
                let op = OutPoint {
                    txid,
                    vout: vout as u32,
                };
                if intra_spent.contains(&op) {
                    continue;
                }
                adds.push((
                    op,
                    Coin {
                        out: out.clone(),
                        height,
                        coinbase,
                    },
                ));
            }
        }
        let add_hashes: Vec<BitcoinNodeHash> = adds.iter().map(|(op, c)| leaf_for(op, c)).collect();
        let proof = if del_hashes.is_empty() {
            Proof::default() // coinbase-only blocks spend nothing
        } else {
            forest.prove(&del_hashes).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("bridge prove divergence: {e}"),
                )
            })?
        };
        let bundle = encode_spend_bundle(&spends, &proof);
        let mut rec = Vec::with_capacity(32 + 9 + bundle.len());
        rec.extend_from_slice(hash.as_bytes());
        crate::encode::write_compact_size(&mut rec, bundle.len() as u64);
        rec.extend_from_slice(&bundle);
        use std::io::Write as _;
        let off = self.file.metadata()?.len();
        self.file.write_all(&rec)?;
        self.file.sync_data()?;
        self.index
            .write()
            .map_err(|_| io::Error::other("bridge index poisoned"))?
            .insert(*hash, (off, rec.len() as u64 - 32));
        forest
            .modify(&add_hashes, &del_hashes)
            .map_err(|e| io::Error::other(format!("bridge forest: {e}")))?;
        self.tip = height;
        Ok(true)
    }
}

impl ProofReader {
    /// The stored bundle for `hash`, if the bridge recorded one.
    ///
    /// # Errors
    /// `io::Error` on read failure; `Ok(None)` when absent.
    pub fn bundle(&self, hash: &crate::hash::BlockHash) -> io::Result<Option<Vec<u8>>> {
        let rec = {
            let index = self
                .index
                .read()
                .map_err(|_| io::Error::other("bridge index poisoned"))?;
            index.get(hash).copied()
        };
        let Some((off, rec_len)) = rec else {
            return Ok(None);
        };
        let mut buf = vec![0u8; rec_len as usize];
        self.file.read_exact_at(&mut buf, off + 32)?; // skip the hash
        // The record stores `varint len || bundle` — serve only the
        // bundle bytes (the length prefix is this file's framing).
        let mut d = crate::encode::Decoder::new(&buf);
        d.read_compact_size()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "proofs.dat: bad record"))?;
        Ok(Some(buf.split_off(buf.len() - d.remaining())))
    }
}

/// Errors the proven-connect path can produce.
#[derive(Debug)]
pub enum ProvenConnectError {
    /// Proof/spend-set verification failed.
    Proof(String),
    /// A block input had no entry in the supplied spend set.
    MissingSpend(OutPoint),
    /// Consensus connect failed after verification.
    Connect(ConnectError),
}

impl std::fmt::Display for ProvenConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Proof(e) => write!(f, "accumulator proof: {e}"),
            Self::MissingSpend(o) => write!(f, "input {o:?} absent from proof bundle"),
            Self::Connect(e) => write!(f, "connect: {e}"),
        }
    }
}

impl std::error::Error for ProvenConnectError {}

/// Connects `block` when prevouts arrive *with their accumulator
/// proof* rather than a UTXO backend — the utreexo validation shape.
///
/// `spends` must contain exactly the non-coinbase inputs' coins;
/// `proof` commits them to `acc`'s pre-state. The block then connects
/// through the normal [`connect_block`] against an overlay seeded
/// with just those coins — every consensus check (amounts, heights,
/// scripts, timelocks) runs unchanged, because the coin data the
/// proof attests is the data consensus sees.
///
/// On success `acc` has applied the block's adds and the verified
/// deletes, and `undo` is the conventional [`crate::connect::BlockUndo`].
///
/// # Errors
/// [`ProvenConnectError`] — proof failure, a missing spend-set entry,
/// or a consensus rejection. Nothing mutates on proof/connect failure;
/// `acc` only advances after `connect_block` succeeded.
pub fn connect_block_proven(
    block: &Block,
    acc: &mut UtxoAccumulator,
    spends: &[(OutPoint, Coin)],
    proof: &Proof<BitcoinNodeHash>,
    ctx: &ConnectContext<'_>,
) -> Result<crate::connect::BlockUndo, ProvenConnectError> {
    // 1. Membership: the bundle must prove every supplied coin.
    acc.verify_spend_set(spends, proof)
        .map_err(|e| ProvenConnectError::Proof(e.to_string()))?;

    // 2. Completeness: every block input must resolve from the bundle
    //    (extras in the bundle are fine — they weren't spent).
    let spend_map: std::collections::HashMap<OutPoint, Coin> = spends.iter().cloned().collect();
    for tx in block.transactions.iter().skip(1) {
        for inp in &tx.inputs {
            if !spend_map.contains_key(&inp.previous_output) {
                return Err(ProvenConnectError::MissingSpend(inp.previous_output));
            }
        }
    }

    // 3. Connect on an overlay holding only the proven coins. No
    //    backend — anything outside the bundle misses.
    let mut overlay = crate::connect::UtxoSet::new();
    for (op, c) in spends {
        overlay.insert_synthetic(*op, c.clone());
    }
    let undo = connect_block(block, &mut overlay, ctx).map_err(ProvenConnectError::Connect)?;

    // 4. The post-block overlay's *remaining* entries are outputs the
    //    block created minus anything the block re-spent; the adds for
    //    the accumulator are exactly the block's new outputs.
    let mut adds = Vec::new();
    for tx in &block.transactions {
        let txid = tx.txid();
        for (vout, out) in tx.outputs.iter().enumerate() {
            if out.value < 0 {
                continue;
            }
            let op = OutPoint {
                txid,
                vout: vout as u32,
            };
            // The overlay marks still-live new outputs; a same-block
            // re-spend lands as spent there already.
            if let Some(c) = overlay.get(&op) {
                adds.push((op, c.clone()));
            }
        }
    }
    acc.apply(&adds, spends, proof)
        .map_err(|e| ProvenConnectError::Proof(e.to_string()))?;
    Ok(undo)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::header::BlockHeader;
    use crate::params::{Network, Params};
    use crate::pow;
    use crate::script;
    use crate::transaction::{Script, Transaction, TxIn, TxOut, Witness};
    use rustreexo::mem_forest::MemForest;

    fn easy_params() -> Params {
        let mut params = Network::Regtest.params();
        params.pow_limit = crate::arith::Target(crate::arith::U256::MAX);
        params.allow_min_difficulty_blocks = false;
        params
    }

    fn txin(prev: OutPoint) -> TxIn {
        TxIn {
            previous_output: prev,
            script_sig: Script::new(Vec::new()),
            sequence: 0xffff_ffff,
            witness: Witness::default(),
        }
    }

    fn coinbase(height: u32, value: i64) -> Transaction {
        let mut script_sig = script::push_int(i64::from(height));
        script_sig.push(script::OP_1);
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::NULL,
                script_sig: Script::new(script_sig),
                sequence: 0xffff_ffff,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value,
                script_pubkey: Script::new(vec![script::OP_1]),
            }],
            lock_time: 0,
        }
    }

    fn block_on(parent: &BlockHeader, txs: Vec<Transaction>, params: &Params) -> Block {
        let mut block = Block {
            header: BlockHeader {
                version: 4,
                prev_block_hash: parent.hash(),
                merkle_root: parent.merkle_root,
                time: parent.time + 1,
                bits: parent.bits,
                nonce: 0,
            },
            transactions: txs,
        };
        let (root, _) = block.merkle_root();
        block.header.merkle_root = root;
        while pow::check_proof_of_work(&block.block_hash(), block.header.bits, params).is_err() {
            block.header.nonce += 1;
        }
        block
    }

    /// The bridge oracle: a full forest + coin map. In production this
    /// role belongs to a bridging node carrying the whole set; here it
    /// answers proofs for the accumulator under test.
    struct Bridge {
        forest: MemForest<BitcoinNodeHash>,
        coins: std::collections::HashMap<OutPoint, Coin>,
    }

    impl Bridge {
        fn new() -> Self {
            Self {
                forest: MemForest::new(),
                coins: std::collections::HashMap::new(),
            }
        }

        /// Applies a connected block to the oracle set and forest.
        fn apply_block(&mut self, block: &Block, height: u32) {
            let mut dels = Vec::new();
            for tx in block.transactions.iter().skip(1) {
                for inp in &tx.inputs {
                    let op = inp.previous_output;
                    let c = self.coins.remove(&op).expect("oracle spend");
                    dels.push(leaf_for(&op, &c));
                }
            }
            let mut adds = Vec::new();
            for tx in &block.transactions {
                let txid = tx.txid();
                for (vout, out) in tx.outputs.iter().enumerate() {
                    let op = OutPoint {
                        txid,
                        vout: vout as u32,
                    };
                    let coin = Coin {
                        out: out.clone(),
                        height,
                        coinbase: tx.is_coinbase(),
                    };
                    adds.push(leaf_for(&op, &coin));
                    self.coins.insert(op, coin);
                }
            }
            self.forest.modify(&adds, &dels).expect("oracle modify");
        }

        /// Proof + spend bundle for `block`'s non-coinbase inputs.
        fn bundle(&self, block: &Block) -> (Vec<(OutPoint, Coin)>, Proof<BitcoinNodeHash>) {
            let mut spends = Vec::new();
            let mut hashes = Vec::new();
            for tx in block.transactions.iter().skip(1) {
                for inp in &tx.inputs {
                    let op = inp.previous_output;
                    let c = self.coins.get(&op).expect("bundle coin").clone();
                    hashes.push(leaf_for(&op, &c));
                    spends.push((op, c));
                }
            }
            let proof = if hashes.is_empty() {
                Proof::default()
            } else {
                self.forest.prove(&hashes).expect("bridge prove")
            };
            (spends, proof)
        }
    }

    fn tempdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("utreexo-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A block spends proven coins end-to-end: bundle verified, block
    /// connected, accumulator advanced to the same leaf count the
    /// oracle reports. The baseline `UtxoSet` run must agree on what
    /// the connect produced.
    #[test]
    fn proven_block_connects_and_advances_accumulator() {
        let dir = tempdir("connect");
        let params = easy_params();
        let mut tree = crate::chain::HeaderTree::new(params);
        let mut tip_header = params.genesis_header;
        let mut bridge = Bridge::new();
        let mut acc = UtxoAccumulator::open(&dir).unwrap();
        // Conventional parallel run — same blocks, map-backed set.
        let mut control = crate::connect::UtxoSet::new();

        // Grow past coinbase maturity, accumulating coinbase leaves.
        let mut cb_outs = Vec::new();
        let mut height = 0u32;
        for _ in 0..=crate::connect::COINBASE_MATURITY + 1 {
            height += 1;
            let block = block_on(
                &tip_header,
                vec![coinbase(height, 50 * 100_000_000)],
                &params,
            );
            tree.insert(&block.header, u32::MAX / 2).unwrap();
            let ctx = ConnectContext {
                params: &params,
                tree: &tree,
                block_hash: block.block_hash(),
                script_checks: true,
                script_pool: None,
            };
            let (spends, proof) = bridge.bundle(&block);
            connect_block_proven(&block, &mut acc, &spends, &proof, &ctx).unwrap();
            connect_block(&block, &mut control, &ctx).unwrap();
            bridge.apply_block(&block, height);
            cb_outs.push(OutPoint {
                txid: block.transactions[0].txid(),
                vout: 0,
            });
            tip_header = block.header;
        }
        // `leaves` is the accumulator's monotone append counter —
        // every coinbase we inserted, not the live set.
        let mut total_added = crate::connect::COINBASE_MATURITY as u64 + 2;
        assert_eq!(acc.stump.leaves, total_added);

        // Now a spending block: consume the two oldest coinbases.
        height += 1;
        let spend_tx = Transaction {
            version: 1,
            inputs: vec![txin(cb_outs[0]), txin(cb_outs[1])],
            outputs: vec![TxOut {
                value: 50 * 100_000_000 - 1000,
                script_pubkey: Script::new(vec![script::OP_1]),
            }],
            lock_time: 0,
        };
        let block = block_on(
            &tip_header,
            vec![coinbase(height, 50 * 100_000_000), spend_tx],
            &params,
        );
        tree.insert(&block.header, u32::MAX / 2).unwrap();
        let ctx = ConnectContext {
            params: &params,
            tree: &tree,
            block_hash: block.block_hash(),
            script_checks: true,
            script_pool: None,
        };
        let (spends, proof) = bridge.bundle(&block);
        assert_eq!(spends.len(), 2);
        connect_block_proven(&block, &mut acc, &spends, &proof, &ctx).unwrap();
        connect_block(&block, &mut control, &ctx).unwrap();
        bridge.apply_block(&block, height);

        // Accumulator and oracle agree on live-leaf count; the control
        // path's spent outpoints are absent from the oracle.
        // +2 appended (coinbase + spend output): total inserts only
        // ever grow; the spend deletes moved leaves but `leaves` stays
        // an append watermark.
        total_added += 2;
        assert_eq!(acc.stump.leaves, total_added);
        assert!(control.get(&cb_outs[0]).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A bundle whose coin data was tampered (wrong value) fails
    /// verification before connect ever runs — the leaf hash commits
    /// to the coin bytes.
    #[test]
    fn tampered_bundle_fails_membership() {
        let dir = tempdir("tamper");
        let params = easy_params();
        let mut bridge = Bridge::new();
        let mut acc = UtxoAccumulator::open(&dir).unwrap();
        let mut tip_header = params.genesis_header;

        for h in 1..=2u32 {
            let block = block_on(&tip_header, vec![coinbase(h, 50 * 100_000_000)], &params);
            // Apply through the oracle only — builds the forest.
            let mut adds = Vec::new();
            let op = OutPoint {
                txid: block.transactions[0].txid(),
                vout: 0,
            };
            let c = Coin {
                out: block.transactions[0].outputs[0].clone(),
                height: h,
                coinbase: true,
            };
            adds.push(leaf_for(&op, &c));
            bridge.forest.modify(&adds, &[]).unwrap();
            acc.apply(&[(op, c.clone())], &[], &Proof::default())
                .unwrap();
            bridge.coins.insert(op, c);
            tip_header = block.header;
        }
        let victim = *bridge.coins.keys().next().unwrap();
        let good = bridge.coins.get(&victim).unwrap().clone();
        let mut bad = good.clone();
        bad.out.value += 1;
        // The proof exists for the REAL leaf; verifying a mutated coin
        // against it must fail — leaf hash commits to the coin bytes.
        let proof = bridge.forest.prove(&[leaf_for(&victim, &good)]).unwrap();
        assert!(
            acc.verify_spend_set(&[(victim, bad)], &proof).is_err(),
            "mutated coin must fail leaf-hash membership"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An input absent from the bundle is a clean MissingSpend before
    /// any connect work — the bridge omission shows up as a stall, not
    /// a consensus failure.
    #[test]
    fn unbundled_input_is_missing_spend() {
        let dir = tempdir("missing");
        let params = easy_params();
        let mut tree = crate::chain::HeaderTree::new(params);
        let mut tip_header = params.genesis_header;
        let mut acc = UtxoAccumulator::open(&dir).unwrap();
        let mut height = 0u32;
        for _ in 0..=crate::connect::COINBASE_MATURITY + 1 {
            height += 1;
            let block = block_on(
                &tip_header,
                vec![coinbase(height, 50 * 100_000_000)],
                &params,
            );
            tree.insert(&block.header, u32::MAX / 2).unwrap();
            let ctx = ConnectContext {
                params: &params,
                tree: &tree,
                block_hash: block.block_hash(),
                script_checks: true,
                script_pool: None,
            };
            connect_block_proven(&block, &mut acc, &[], &Proof::default(), &ctx).unwrap();
            tip_header = block.header;
        }
        // Spend a coinbase that was never bundled (the accumulator has
        // its leaf — we gave no coin for it).
        let fake = OutPoint {
            txid: crate::hash::Txid::from_bytes([7u8; 32]),
            vout: 0,
        };
        height += 1;
        let spend_tx = Transaction {
            version: 1,
            inputs: vec![txin(fake)],
            outputs: vec![TxOut {
                value: 1000,
                script_pubkey: Script::new(vec![script::OP_1]),
            }],
            lock_time: 0,
        };
        let block = block_on(
            &tip_header,
            vec![coinbase(height, 50 * 100_000_000), spend_tx],
            &params,
        );
        tree.insert(&block.header, u32::MAX / 2).unwrap();
        let ctx = ConnectContext {
            params: &params,
            tree: &tree,
            block_hash: block.block_hash(),
            script_checks: true,
            script_pool: None,
        };
        match connect_block_proven(&block, &mut acc, &[], &Proof::default(), &ctx) {
            Err(ProvenConnectError::MissingSpend(o)) => assert_eq!(o, fake),
            other => panic!("expected MissingSpend, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Persisted stump survives reopen — restart reattachment.
    #[test]
    fn stump_persists_across_reopen() {
        let dir = tempdir("persist");
        let leaves;
        {
            let mut acc = UtxoAccumulator::open(&dir).unwrap();
            let op = OutPoint {
                txid: crate::hash::Txid::from_bytes([1u8; 32]),
                vout: 0,
            };
            let c = Coin {
                out: TxOut {
                    value: 5,
                    script_pubkey: Script::new(vec![script::OP_1]),
                },
                height: 1,
                coinbase: false,
            };
            acc.apply(&[(op, c)], &[], &Proof::default()).unwrap();
            leaves = acc.stump.leaves;
        }
        let acc = UtxoAccumulator::open(&dir).unwrap();
        assert_eq!(acc.stump.leaves, leaves);
        assert_eq!(acc.stump.roots.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Wire/disk encoding of a proof bundle: `compact_size(n_spends)` then
/// per-input `txid32 | vout u32-le | compact-coin-record` in the
/// block's input order, then the rustreexo `Proof` serialization to
/// end. Decoding must consume every byte — a trailing-garbage bundle
/// is malformed, not truncated.
///
/// `encode_coin`/`decode_coin` are `pub(crate)` — this module owns the
/// bundle format so p2p carries it as opaque bytes.
pub fn encode_spend_bundle(spends: &[(OutPoint, Coin)], proof: &Proof<BitcoinNodeHash>) -> Vec<u8> {
    let mut out = Vec::new();
    crate::encode::write_compact_size(&mut out, spends.len() as u64);
    for (op, coin) in spends {
        out.extend_from_slice(op.txid.as_bytes());
        out.extend_from_slice(&op.vout.to_le_bytes());
        out.extend_from_slice(&coinsdb::encode_coin(coin, CoinFormat::Compact));
    }
    let _ = proof.serialize(&mut out);
    out
}

/// A spend bundle cannot exceed a block's possible input count —
/// 1M is ~10× the densest feasible block; above that the framing
/// itself is hostile, whatever the contents.
const MAX_BUNDLE_SPENDS: u64 = 1_000_000;

/// The decoded spend set + accumulator proof for one block.
pub type SpendBundle = (Vec<(OutPoint, Coin)>, Proof<BitcoinNodeHash>);

/// Decodes a bundle produced by [`encode_spend_bundle`]. Returns
/// `None` on any malformed or truncated input — callers treat the
/// message as garbage, never a consensus signal.
#[must_use]
pub fn decode_spend_bundle(buf: &[u8]) -> Option<SpendBundle> {
    let mut d = crate::encode::Decoder::new(buf);
    let n = d.read_compact_size().ok()?;
    if n > MAX_BUNDLE_SPENDS {
        return None;
    }
    let mut spends = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let txid_bytes: [u8; 32] = d.read_bytes(32).ok()?.try_into().ok()?;
        let vout = d.read_u32_le().ok()?;
        // A compact coin record is self-delimiting: hand the decoder
        // the remaining tail as a slice it consumes exactly.
        let rest = &buf[buf.len() - d.remaining()..];
        let mut rest = rest;
        let coin = coinsdb::decode_coin_compact(&mut rest)?;
        let used = d.remaining() - rest.len();
        let _ = d.read_bytes(used).ok()?;
        spends.push((
            OutPoint {
                txid: crate::hash::Txid::from_bytes(txid_bytes),
                vout,
            },
            coin,
        ));
    }
    // The proof runs to the end of the payload — hand rustreexo the
    // remaining slice directly.
    let consumed = buf.len() - d.remaining();
    let proof = Proof::deserialize(&buf[consumed..]).ok()?;
    Some((spends, proof))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod bundle_tests {
    use super::*;
    use crate::transaction::{Script, TxOut};

    fn coin(v: i64, h: u32) -> Coin {
        Coin {
            out: TxOut {
                value: v,
                script_pubkey: Script::new(vec![0x51]),
            },
            height: h,
            coinbase: false,
        }
    }

    fn op(i: u8) -> OutPoint {
        OutPoint {
            txid: crate::hash::Txid::from_bytes([i; 32]),
            vout: i as u32,
        }
    }

    #[test]
    fn spend_bundle_roundtrips() {
        let spends = vec![(op(1), coin(50, 100)), (op(2), coin(75, 200))];
        let proof = Proof::<BitcoinNodeHash>::default();
        let bytes = encode_spend_bundle(&spends, &proof);
        let (back_spend, back_proof) = decode_spend_bundle(&bytes).unwrap();
        assert_eq!(back_spend.len(), 2);
        assert_eq!(back_spend[0].0, spends[0].0);
        assert_eq!(back_spend[0].1.out.value, 50);
        assert_eq!(back_spend[1].1.height, 200);
        assert_eq!(back_proof.targets, proof.targets);
    }

    #[test]
    fn bundle_rejects_truncation_and_garbage() {
        let spends = vec![(op(9), coin(1, 1))];
        let bytes = encode_spend_bundle(&spends, &Proof::default());
        // Every strict prefix must fail to decode.
        for cut in 0..bytes.len() {
            assert!(decode_spend_bundle(&bytes[..cut]).is_none(), "cut {cut}");
        }
        // A hostile count header fails fast — no gigabyte alloc.
        let mut bad = Vec::new();
        crate::encode::write_compact_size(&mut bad, MAX_BUNDLE_SPENDS + 1);
        bad.extend_from_slice(&bytes[1..]);
        assert!(decode_spend_bundle(&bad).is_none());
    }
}
