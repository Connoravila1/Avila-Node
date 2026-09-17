//! Watch-only descriptor wallet — Core's `importdescriptors` model.
//!
//! The wallet tracks descriptor-owned scripts against the active
//! chain: `importdescriptors` registers a (possibly ranged) descriptor
//! and rescans from its timestamp; each block connect advances the
//! scan; a reorg rewinds it. Confirmed receipts and spends persist to
//! `watchlist.dat` in the network data dir; mempool receipts and
//! pending spends are folded in per query, like Core's
//! `AvailableCoins` over `mempool`.
//!
//! Signing keys never enter this wallet — an imported descriptor's
//! private material is expanded to scripts and then discarded; every
//! tracked coin reports `spendable: false`, `solvable: true`.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::PathBuf;

use avila_consensus::hex;

use avila_consensus::chainstate::Chainstate;
use avila_consensus::hash::{BlockHash, Txid};
use avila_consensus::transaction::OutPoint;

/// One imported descriptor — Core's `WalletDescriptor`: the
/// checksummed string plus the import-request metadata. `scripts` is
/// the expanded `[range]` script set keyed back to its derivation
/// index so `listunspent`'s `desc` field can name the exact child.
#[derive(Debug, Clone)]
pub struct TrackedDesc {
    /// Canonical descriptor text including `#checksum`.
    pub desc: String,
    /// Creation/rescan timestamp (`importdescriptors` `timestamp`;
    /// `"now"` resolves to the chain tip's time at import).
    pub timestamp: i64,
    /// `active` — Core's active-flag bookkeeping (`next_index`
    /// tracking lands with it).
    pub active: bool,
    /// `internal` — change-side descriptor (only meaningful when
    /// `active`, like Core).
    pub internal: bool,
    /// `label` — only allowed on non-ranged external descriptors.
    pub label: String,
    /// `next_index` — Core's cursor for ranged descriptors.
    pub next_index: u32,
    /// `[begin, end]` derivation range — `(0, 0)` for un-ranged.
    pub range: (u32, u32),
    /// Expanded scriptPubKeys → derivation position.
    pub scripts: HashMap<Vec<u8>, u32>,
}

/// A confirmed chain coin paying to a tracked script. Spent coins are
/// retained (with `spent_height`) so `listreceivedbyaddress` can still
/// report the receipt, matching Core's wallet which keeps spent
/// outputs in `mapWallet`.
#[derive(Debug, Clone)]
pub struct WatchedCoin {
    /// Height of the block that created it.
    pub height: u32,
    /// The creating block — rechecked on reorg rewind.
    pub block: BlockHash,
    /// Satoshis.
    pub value: i64,
    /// The scriptPubKey bytes.
    pub script: Vec<u8>,
    /// Which descriptor produced the script.
    pub desc_idx: usize,
    /// Coinbase outputs are untrusted until they mature (BIP30-style
    /// immaturity — Core's `IsImmatureCoinBase`, 100 confs).
    pub coinbase: bool,
    /// Height of the block that spent it (`None` while unspent).
    pub spent_height: Option<u32>,
    /// The spending txid, for reporting.
    pub spent_by: Option<Txid>,
}

/// The wallet — persistent across restarts via `watchlist.dat`.
pub struct WatchWallet {
    /// `watchlist.dat` path — writes are atomic (tmp + rename).
    path: PathBuf,
    /// Imported descriptors in import order.
    pub descs: Vec<TrackedDesc>,
    /// scriptPubKey bytes → `(desc index, derivation position)` — the
    /// merged lookup the block scan uses.
    pub scripts: HashMap<Vec<u8>, (usize, u32)>,
    /// Chain-owned coins keyed by outpoint — includes spent ones.
    pub coins: BTreeMap<(Txid, u32), WatchedCoin>,
    /// The block hash scanned at each height — `chain[h]` parallels
    /// `cs.chain()[h]`; divergence means reorg.
    pub chain: Vec<BlockHash>,
    /// Heights skipped because the body was unavailable (pruned or
    /// not yet stored). An unsearched interval must never masquerade
    /// as an empty balance — `getbalances` surfaces these.
    pub gaps: Vec<(u32, u32)>,
    /// Blocks below this height are asserted empty — set by the first
    /// import's timestamp (or the tip for `"now"`). Lazy `advance`
    /// marks them scanned without searching, matching Core's "don't
    /// search before the earliest descriptor timestamp". An explicit
    /// `rescanblockchain` still searches the full requested range.
    pub scan_floor: u32,
    /// Dirty flag — set by any mutation, cleared by [`Self::persist`].
    dirty: bool,
}

impl WatchWallet {
    /// Opens (or lazily creates) the wallet at `path`. Corrupt or
    /// incompatible files are treated like a missing one — the wallet
    /// is reconstructible metadata, never the only copy of anything.
    #[must_use]
    pub fn open(path: PathBuf) -> Self {
        let mut w = Self {
            path,
            descs: Vec::new(),
            scripts: HashMap::new(),
            coins: BTreeMap::new(),
            chain: Vec::new(),
            gaps: Vec::new(),
            scan_floor: 0,
            dirty: false,
        };
        if let Ok(text) = std::fs::read_to_string(&w.path) {
            let _ = w.load(&text);
        }
        w
    }

    /// Rewinds to the fork point (if any), then scans forward to the
    /// active tip. Returns `true` when the scan state changed.
    pub fn advance(&mut self, cs: &Chainstate) -> bool {
        let chain = cs.chain();
        let fork = self
            .chain
            .iter()
            .zip(chain.iter())
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| self.chain.len().min(chain.len()));
        let fork = fork as u32;
        if (fork as usize) < self.chain.len() {
            // Blocks above the fork are gone — drop coins they
            // created and un-mark coins they spent.
            self.coins.retain(|_, c| c.height < fork);
            for c in self.coins.values_mut() {
                if c.spent_height.is_some_and(|s| s >= fork) {
                    c.spent_height = None;
                    c.spent_by = None;
                }
            }
            self.gaps.retain(|(lo, _)| *lo < fork);
            self.chain.truncate(fork as usize);
            self.dirty = true;
        }
        for (h, &hash) in chain.iter().enumerate().skip(self.chain.len()) {
            if (h as u32) < self.scan_floor {
                // Below the import floor — asserted empty, not a gap.
                self.chain.push(hash);
                continue;
            }
            match cs.body(&hash) {
                Some(block) => {
                    self.scan_block(&block, h as u32, hash);
                }
                None => {
                    // Body missing (pruned) — record the gap rather
                    // than silently counting it as scanned.
                    self.gaps.push((h as u32, h as u32));
                    self.merge_gaps();
                }
            }
            self.chain.push(hash);
            self.dirty = true;
        }
        self.dirty
    }

    /// `ScanForWalletTransactions` over one connected block — record
    /// outputs paying tracked scripts, then mark spends of ours.
    fn scan_block(&mut self, block: &avila_consensus::block::Block, height: u32, hash: BlockHash) {
        for tx in &block.transactions {
            let txid = tx.txid();
            for (vout, out) in tx.outputs.iter().enumerate() {
                if let Some(&(desc_idx, _)) = self.scripts.get(out.script_pubkey.as_bytes()) {
                    self.coins.insert(
                        (txid, vout as u32),
                        WatchedCoin {
                            height,
                            block: hash,
                            value: out.value,
                            script: out.script_pubkey.as_bytes().to_vec(),
                            desc_idx,
                            coinbase: tx.is_coinbase(),
                            spent_height: None,
                            spent_by: None,
                        },
                    );
                }
            }
            if tx.is_coinbase() {
                continue;
            }
            for input in &tx.inputs {
                let op = input.previous_output;
                if let Some(coin) = self.coins.get_mut(&(op.txid, op.vout)) {
                    coin.spent_height = Some(height);
                    coin.spent_by = Some(txid);
                }
            }
        }
    }

    /// `importdescriptors` — register a descriptor's script set. The
    /// caller decides the rescan height from `timestamp` and calls
    /// [`Self::rescan_from`] when a historical scan is needed.
    ///
    /// # Errors
    /// `io` only on expansion exhaustion; descriptor validation is the
    /// caller's job (`parse_descriptors`).
    pub fn track(&mut self, desc: TrackedDesc, floor: u32) {
        let idx = self.descs.len();
        if self.descs.is_empty() || floor < self.scan_floor {
            self.scan_floor = floor;
        }
        // First descriptor to claim a script wins the `desc`/
        // `parent_descs` reporting slot (Core attributes a coin to
        // every matching descriptor; we report the canonical one).
        for (script, pos) in &desc.scripts {
            self.scripts.entry(script.clone()).or_insert((idx, *pos));
        }
        self.descs.push(desc);
        self.dirty = true;
    }

    /// Rewind the scan to `height` (exclusive of it — blocks at
    /// `height` are rescanned) then advance to the tip. Existing
    /// descriptor scripts survive the rewind, so coins found below
    /// are re-found identically.
    pub fn rescan_from(&mut self, cs: &Chainstate, height: u32) {
        self.scan_floor = 0;
        self.chain.truncate(height as usize);
        self.coins.retain(|_, c| c.height < height);
        for c in self.coins.values_mut() {
            if c.spent_height.is_some_and(|s| s >= height) {
                c.spent_height = None;
                c.spent_by = None;
            }
        }
        self.gaps.retain(|(lo, _)| *lo < height);
        self.advance(cs);
    }

    /// The first chain height whose block time is `>= timestamp`
    /// (Core's `FindWalletRescanHeight` — binary search over header
    /// times, scanning from genesis when `timestamp` predates it).
    #[must_use]
    pub fn rescan_height_for(cs: &Chainstate, timestamp: i64) -> u32 {
        let chain = cs.chain();
        let mut lo = 0usize;
        let mut hi = chain.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            let t = cs
                .tree()
                .get(&chain[mid])
                .map(|n| i64::from(n.header.time))
                .unwrap_or(i64::MAX);
            if t >= timestamp {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        lo as u32
    }

    /// Merge adjacent gap records — `(a,b] ∪ (b,c]` → `(a,c]`.
    fn merge_gaps(&mut self) {
        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(self.gaps.len());
        for &(lo, hi) in &self.gaps {
            match merged.last_mut() {
                Some((_, prev_hi)) if *prev_hi + 1 >= lo => *prev_hi = hi,
                _ => merged.push((lo, hi)),
            }
        }
        self.gaps = merged;
    }

    /// Unspent chain coins as of the last [`Self::advance`].
    pub fn unspent(&self) -> impl Iterator<Item = (OutPoint, &WatchedCoin)> {
        self.coins
            .iter()
            .filter(|(_, c)| c.spent_height.is_none())
            .map(|(&(txid, vout), c)| (OutPoint { txid, vout }, c))
    }

    /// Persists when dirty — `watchlist.dat` via tmp+rename like the
    /// other node data files.
    ///
    /// # Errors
    /// `io` on write/rename failure.
    pub fn persist(&mut self) -> io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        let text = self.dump();
        let tmp = self.path.with_extension("dat.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, &self.path)?;
        self.dirty = false;
        Ok(())
    }

    /// `backupwallet` — flush, then copy the wallet file to `dest`.
    /// A bare filename resolves against the wallet's directory like
    /// Core resolves it against `-walletdir`.
    ///
    /// # Errors
    /// `io` on persist/copy failure.
    pub fn backup_to(&mut self, dest: &std::path::Path) -> io::Result<PathBuf> {
        self.persist()?;
        // The file may not exist yet when nothing was ever written —
        // persist() only runs when dirty, so materialize it first.
        if !self.path.exists() {
            let text = self.dump();
            std::fs::write(&self.path, text)?;
        }
        let target = if dest.is_absolute() {
            dest.to_path_buf()
        } else {
            self.path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join(dest)
        };
        std::fs::copy(&self.path, &target)?;
        Ok(target)
    }

    /// `restorewallet` — load a backup file into this wallet. A bare
    /// filename resolves against the wallet's directory; malformed
    /// backups are rejected without touching live state.
    ///
    /// # Errors
    /// `io` on read/write failure; `InvalidData` when the file isn't
    /// a wallet backup.
    pub fn restore_from(&mut self, src: &std::path::Path) -> io::Result<()> {
        let target = if src.is_absolute() {
            src.to_path_buf()
        } else {
            self.path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join(src)
        };
        let text = std::fs::read_to_string(&target)?;
        // Validate into a scratch wallet first — a corrupt backup must
        // not tear down the live descriptor/coin state.
        let mut scratch = Self {
            path: self.path.clone(),
            descs: Vec::new(),
            scripts: HashMap::new(),
            coins: BTreeMap::new(),
            chain: Vec::new(),
            gaps: Vec::new(),
            scan_floor: 0,
            dirty: false,
        };
        scratch
            .load(&text)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "not a wallet backup"))?;
        let restored = Self {
            path: self.path.clone(),
            dirty: true,
            ..scratch
        };
        *self = restored;
        self.persist()
    }

    /// JSON serialization — plain fields, hex for hashes/scripts.
    fn dump(&self) -> String {
        let descs: Vec<serde_json::Value> = self
            .descs
            .iter()
            .map(|d| {
                serde_json::json!({
                    "desc": d.desc,
                    "timestamp": d.timestamp,
                    "active": d.active,
                    "internal": d.internal,
                    "label": d.label,
                    "next_index": d.next_index,
                    "range": [d.range.0, d.range.1],
                    "scripts": d
                        .scripts
                        .iter()
                        .map(|(s, p)| serde_json::json!([hex::encode(s), p]))
                        .collect::<Vec<_>>(),
                })
            })
            .collect();
        let coins: Vec<serde_json::Value> = self
            .coins
            .iter()
            .map(|((txid, vout), c)| {
                serde_json::json!({
                    "txid": txid.to_string(),
                    "vout": vout,
                    "height": c.height,
                    "block": c.block.to_string(),
                    "value": c.value,
                    "script": hex::encode(&c.script),
                    "desc": c.desc_idx,
                    "coinbase": c.coinbase,
                    "spent": c.spent_height,
                    "spent_by": c.spent_by.map(|t| t.to_string()),
                })
            })
            .collect();
        serde_json::json!({
            "version": 1,
            "descs": descs,
            "coins": coins,
            "chain": self.chain.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "gaps": self.gaps,
            "scan_floor": self.scan_floor,
        })
        .to_string()
    }

    /// Loads a `dump` document. Any malformed entry aborts the load —
    /// the caller treats that as an empty wallet (the descriptors can
    /// always be re-imported).
    fn load(&mut self, text: &str) -> Result<(), ()> {
        let v: serde_json::Value = serde_json::from_str(text).map_err(|_| ())?;
        if v["version"].as_i64() != Some(1) {
            return Err(());
        }
        let hex_bytes =
            |v: &serde_json::Value| -> Option<Vec<u8>> { hex::decode(v.as_str()?).ok() };
        let descs = v["descs"].as_array().ok_or(())?;
        for d in descs {
            let scripts: HashMap<Vec<u8>, u32> = d["scripts"]
                .as_array()
                .ok_or(())?
                .iter()
                .filter_map(|pair| {
                    let arr = pair.as_array()?;
                    Some((hex_bytes(&arr[0])?, arr[1].as_u64()? as u32))
                })
                .collect();
            let range = d["range"].as_array().ok_or(())?;
            let td = TrackedDesc {
                desc: d["desc"].as_str().ok_or(())?.to_string(),
                timestamp: d["timestamp"].as_i64().ok_or(())?,
                active: d["active"].as_bool().unwrap_or(false),
                internal: d["internal"].as_bool().unwrap_or(false),
                label: d["label"].as_str().unwrap_or_default().to_string(),
                next_index: d["next_index"].as_u64().unwrap_or(0) as u32,
                range: (
                    range[0].as_u64().unwrap_or(0) as u32,
                    range[1].as_u64().unwrap_or(0) as u32,
                ),
                scripts,
            };
            let idx = self.descs.len();
            for (s, pos) in &td.scripts {
                self.scripts.entry(s.clone()).or_insert((idx, *pos));
            }
            self.descs.push(td);
        }
        let coins = v["coins"].as_array().ok_or(())?;
        for c in coins {
            let txid: Txid = c["txid"].as_str().ok_or(())?.parse().map_err(|_| ())?;
            let vout = c["vout"].as_u64().ok_or(())? as u32;
            let block: BlockHash = c["block"].as_str().ok_or(())?.parse().map_err(|_| ())?;
            let spent_by = c["spent_by"].as_str().and_then(|s| s.parse::<Txid>().ok());
            self.coins.insert(
                (txid, vout),
                WatchedCoin {
                    height: c["height"].as_u64().ok_or(())? as u32,
                    block,
                    value: c["value"].as_i64().ok_or(())?,
                    script: hex_bytes(&c["script"]).ok_or(())?,
                    desc_idx: c["desc"].as_u64().unwrap_or(0) as usize,
                    coinbase: c["coinbase"].as_bool().unwrap_or(false),
                    spent_height: c["spent"].as_u64().map(|h| h as u32),
                    spent_by,
                },
            );
        }
        for h in v["chain"].as_array().ok_or(())? {
            self.chain
                .push(h.as_str().ok_or(())?.parse().map_err(|_| ())?);
        }
        self.scan_floor = v["scan_floor"].as_u64().unwrap_or(0) as u32;
        for g in v["gaps"].as_array().unwrap_or(&vec![]) {
            let arr = g.as_array().ok_or(())?;
            self.gaps.push((
                arr[0].as_u64().ok_or(())? as u32,
                arr[1].as_u64().ok_or(())? as u32,
            ));
        }
        Ok(())
    }
}

/// `SharedWallet` — the wallet lives behind the RPC layer's lock;
/// every wallet method runs inside a `chain_query` closure so the
/// scan and the chainstate advance atomically.
pub type SharedWallet = std::sync::Arc<std::sync::Mutex<WatchWallet>>;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use avila_consensus::block::Block;
    use avila_consensus::header::BlockHeader;
    use avila_consensus::params::Network;
    use avila_consensus::pow;
    use avila_consensus::script;
    use avila_consensus::transaction::{Script, Transaction, TxIn, TxOut, Witness};

    const REGTEST_BITS: u32 = 0x207f_ffff;
    const NOW: u32 = 1_800_000_000;
    /// The watched script — `OP_1` bare, matching the coinbases below.
    const WATCHED: &[u8] = &[script::OP_1];

    fn coinbase_tx(height: u32, subsidy: i64) -> Transaction {
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
                value: subsidy,
                script_pubkey: Script::new(WATCHED.to_vec()),
            }],
            lock_time: 0,
        }
    }

    fn block_on(
        parent: &BlockHeader,
        txs: Vec<Transaction>,
        params: &avila_consensus::params::Params,
    ) -> Block {
        let mut block = Block {
            header: BlockHeader {
                version: 4,
                prev_block_hash: parent.hash(),
                merkle_root: parent.merkle_root,
                time: parent.time + 1,
                bits: avila_consensus::arith::CompactTarget(REGTEST_BITS),
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

    fn tracked(script: &[u8]) -> TrackedDesc {
        TrackedDesc {
            desc: "raw(51)#x".into(),
            timestamp: 0,
            active: false,
            internal: false,
            label: String::new(),
            next_index: 0,
            range: (0, 0),
            scripts: HashMap::from([(script.to_vec(), 0)]),
        }
    }

    fn chain_of(n: u32) -> Chainstate {
        let params = Network::Regtest.params();
        let mut cs = Chainstate::new(&params);
        let mut parent = params.genesis_header;
        for height in 1..=n {
            let block = block_on(
                &parent,
                vec![coinbase_tx(height, 50 * 100_000_000)],
                &params,
            );
            parent = block.header;
            assert!(cs.accept_block(&block, NOW).is_ok());
        }
        cs
    }

    #[test]
    fn advance_records_and_spends() {
        // 105 blocks so the h3 coinbase is mature when h106 spends it.
        let mut cs = chain_of(105);
        let mut w = WatchWallet::open(PathBuf::from("/nonexistent/watchlist.dat"));
        w.track(tracked(WATCHED), 0);
        w.advance(&cs);
        assert_eq!(w.unspent().count(), 105);
        // Spend the height-3 coinbase in a new block — watched output
        // must drop out of `unspent`.
        let coin3_txid = cs.body(&cs.chain()[3]).unwrap().transactions[0].txid();
        let spend = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: coin3_txid,
                    vout: 0,
                },
                script_sig: Script::new(vec![]),
                sequence: 0xffff_fffe,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: Script::new(vec![0x52]),
            }],
            lock_time: 0,
        };
        let params = Network::Regtest.params();
        let parent = cs.tip_hash();
        let tip_hdr = cs.tree().get(&parent).unwrap().header;
        let b6 = block_on(
            &tip_hdr,
            vec![coinbase_tx(106, 50 * 100_000_000), spend],
            &params,
        );
        cs.accept_block(&b6, NOW).unwrap();
        w.advance(&cs);
        let unspent: Vec<_> = w.unspent().collect();
        assert_eq!(unspent.len(), 105); // all coinbases except h3's
        assert!(unspent.iter().all(|(op, _)| op.txid != coin3_txid));
        // Spent coin is retained with a spent_height for
        // `listreceivedbyaddress`.
        let spent = &w.coins[&(coin3_txid, 0)];
        assert_eq!(spent.spent_height, Some(106));
    }

    #[test]
    fn scan_floor_suppresses_pre_import_history() {
        let cs = chain_of(5);
        let mut w = WatchWallet::open(PathBuf::from("/nonexistent/watchlist.dat"));
        // "now" at tip — floor = 5: blocks 1..4 are asserted empty.
        w.track(tracked(WATCHED), 5);
        w.advance(&cs);
        assert_eq!(w.unspent().count(), 1); // only height-5's coinbase
        // Explicit rescan bypasses the floor, like Core.
        w.rescan_from(&cs, 0);
        assert_eq!(w.unspent().count(), 5);
    }

    #[test]
    fn reorg_drops_orphans_and_unspends() {
        let params = Network::Regtest.params();
        let mut cs = Chainstate::new(&params);
        let mut parent = params.genesis_header;
        for height in 1..=4u32 {
            let b = block_on(
                &parent,
                vec![coinbase_tx(height, 50 * 100_000_000)],
                &params,
            );
            parent = b.header;
            cs.accept_block(&b, NOW).unwrap();
        }
        let mut w = WatchWallet::open(PathBuf::from("/nonexistent/watchlist.dat"));
        w.track(tracked(WATCHED), 0);
        w.advance(&cs);
        assert_eq!(w.unspent().count(), 4);

        // Fork at height 2: two side blocks with different coinbases
        // (tagged scriptSig → different txids/hashes).
        let fork_hdr = cs.tree().get(&cs.chain()[1]).unwrap().header;
        let mut side_parent = fork_hdr;
        for height in 2..=5u32 {
            let mut cb = coinbase_tx(height, 50 * 100_000_000);
            let mut sig = cb.inputs[0].script_sig.as_bytes().to_vec();
            sig.push(0xaa);
            cb.inputs[0].script_sig = Script::new(sig);
            let b = block_on(&side_parent, vec![cb], &params);
            side_parent = b.header;
            cs.accept_block(&b, NOW).unwrap();
        }
        assert_eq!(cs.chain().len(), 6); // reorged to the longer fork
        w.advance(&cs);
        // The main-chain coinbases at h2-4 are gone; the side chain's
        // replacements at h2-5 (still paying WATCHED) stand.
        assert_eq!(w.unspent().count(), 5); // h1 main + h2..5 side
    }

    #[test]
    fn reorg_unspends_orphaned_spends() {
        let params = Network::Regtest.params();
        // 104 blocks so h2's coinbase is mature when block 105 spends
        // it — the fork then orphans the spend.
        let mut cs = chain_of(104);
        let h2_txid = cs.body(&cs.chain()[2]).unwrap().transactions[0].txid();
        let spend = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: h2_txid,
                    vout: 0,
                },
                script_sig: Script::new(vec![]),
                sequence: 0xffff_fffe,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: Script::new(vec![0x52]),
            }],
            lock_time: 0,
        };
        let tip_hdr = cs.tree().get(&cs.tip_hash()).unwrap().header;
        let b4 = block_on(
            &tip_hdr,
            vec![coinbase_tx(105, 50 * 100_000_000), spend],
            &params,
        );
        cs.accept_block(&b4, NOW).unwrap();
        let mut w = WatchWallet::open(PathBuf::from("/nonexistent/watchlist.dat"));
        w.track(tracked(WATCHED), 0);
        w.advance(&cs);
        assert_eq!(w.coins[&(h2_txid, 0)].spent_height, Some(105));

        // Reorg away block 105 — the spend unwinds.
        let fork_hdr = cs.tree().get(&cs.chain()[103]).unwrap().header;
        let mut side = fork_hdr;
        for height in 104..=107u32 {
            let mut cb = coinbase_tx(height, 50 * 100_000_000);
            let mut sig = cb.inputs[0].script_sig.as_bytes().to_vec();
            sig.push(0xbb);
            cb.inputs[0].script_sig = Script::new(sig);
            let b = block_on(&side, vec![cb], &params);
            side = b.header;
            cs.accept_block(&b, NOW).unwrap();
        }
        w.advance(&cs);
        assert_eq!(w.coins[&(h2_txid, 0)].spent_height, None);
        assert!(w.unspent().any(|(op, _)| op.txid == h2_txid));
    }

    #[test]
    fn persistence_round_trip() {
        let dir = std::env::temp_dir().join(format!("avila-watch-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("watchlist.dat");
        let cs = chain_of(4);
        {
            let mut w = WatchWallet::open(path.clone());
            w.track(tracked(WATCHED), 0);
            w.advance(&cs);
            w.persist().unwrap();
        }
        let mut w = WatchWallet::open(path);
        assert_eq!(w.descs.len(), 1);
        w.advance(&cs);
        assert_eq!(w.unspent().count(), 4);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
