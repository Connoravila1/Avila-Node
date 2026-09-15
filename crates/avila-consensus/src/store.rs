//! Durable block storage: Core's `blkNNNNN.dat` flat-file format.
//!
//! Each file is a stream of `magic` + `u32` little-endian length + raw block
//! frames, appended in arrival order and rotated at `MAX_FILE_SIZE` —
//! Core's `MAX_BLOCKFILE_SIZE`. Files are append-only; the in-memory index is
//! a *derived* structure rebuilt by scanning on [`BlockStore::open`], so no
//! separate index can fall out of sync with the block files — an interrupted
//! append simply leaves a partial tail frame, which `open` truncates.
//!
//! This is the block store only. The coins view and undo records remain in
//! memory until the durable-chainstate milestone; restarting therefore means
//! rescanning and re-validating the stored bodies, not re-downloading them.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::block::{Block, MAX_BLOCK_SERIALIZED_SIZE};
use crate::connect::{BlockUndo, Coin, TxUndo};
use crate::encode::{Decoder, write_compact_size, write_var_bytes};
use crate::hash::{BlockHash, Txid, sha256d};
use crate::transaction::{OutPoint, Script, TxOut};

/// Core's `MAX_BLOCKFILE_SIZE` — `BLK_FILE_CHUNK` rotations keep each file
/// under 128 MiB.
const MAX_FILE_SIZE: u64 = 0x0800_0000;

const FILE_PREFIX: &str = "blk";
const FILE_SUFFIX: &str = ".dat";
/// `magic` + `u32` length before each payload.
const FRAME_HEADER: u64 = 8;

/// A stored block's position: which file, the payload offset, and its length.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BlockPos {
    /// `blkNNNNN.dat` file number.
    pub file: u32,
    /// Byte offset of the frame's *payload* (past the 8-byte header).
    pub offset: u64,
    /// Payload length in bytes.
    pub len: u32,
}

/// An append-only `blkNNNNN.dat` store for one network.
pub struct BlockStore {
    dir: PathBuf,
    /// The network message start written before every frame — frames from
    /// another network are rejected rather than indexed.
    magic: [u8; 4],
    index: HashMap<BlockHash, BlockPos>,
    /// File number of the append tail.
    tail_no: u32,
    /// Bytes in the tail file.
    tail_len: u64,
    tail: File,
    /// Rotation threshold — `MAX_FILE_SIZE` in production; tests shrink it.
    max_file_size: u64,
    /// `blkNNNNN.dat` files ≤ this number were deleted by
    /// [`Self::prune_to_bytes`] this session — their index entries
    /// survive so `read` can report "pruned" rather than "absent".
    /// On reopen the index rebuilds from existing files only, so the
    /// flag is session-scoped by design.
    pruned_through: Option<u32>,
}

impl BlockStore {
    /// Opens (creating) the store in `dir` and rebuilds the index by scanning
    /// every `blk*.dat` file in name order. A file's first bad frame —
    /// foreign magic, oversize length, truncation, or an undecodable payload —
    /// ends its scan; a partial tail on the *last* file is truncated so the
    /// store returns to its last committed boundary.
    ///
    /// # Errors
    ///
    /// `io::Error` on directory/file failures. A mid-file corruption is
    /// reported as [`io::ErrorKind::InvalidData`] — only the tail may be
    /// partial.
    pub fn open(dir: &Path, magic: [u8; 4]) -> io::Result<Self> {
        Self::open_with_limit(dir, magic, MAX_FILE_SIZE)
    }

    fn open_with_limit(dir: &Path, magic: [u8; 4], max_file_size: u64) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let mut files: Vec<(u32, PathBuf)> = fs::read_dir(dir)?
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let name = entry.file_name().into_string().ok()?;
                let digits = name.strip_prefix(FILE_PREFIX)?.strip_suffix(FILE_SUFFIX)?;
                digits.parse::<u32>().ok().map(|n| (n, entry.path()))
            })
            .collect();
        files.sort_by_key(|(n, _)| *n);

        // Foreign-magic first frame means the directory points at another
        // network's store — refuse rather than silently truncate it.
        if let Some((_, path)) = files.first() {
            let mut file = File::open(path)?;
            let mut first_magic = [0u8; 4];
            if file.metadata()?.len() >= 4 {
                file.read_exact(&mut first_magic)?;
                if first_magic != magic {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "block store magic does not match this network",
                    ));
                }
            }
        }

        let mut index = HashMap::new();
        let mut tail_no = 0;
        let mut tail_len = 0u64;
        for (pos, (no, path)) in files.iter().enumerate() {
            let is_tail = pos + 1 == files.len();
            let len = scan_file(path, *no, magic, is_tail, &mut index)?;
            tail_no = *no;
            tail_len = len;
        }
        let tail = if files.is_empty() {
            tail_no = 0;
            tail_len = 0;
            open_tail(dir, tail_no)?
        } else {
            let meta_len = fs::metadata(file_path(dir, tail_no))?.len();
            if tail_len < meta_len {
                // Partial tail frame from an interrupted write: truncate back
                // to the last complete frame boundary.
                OpenOptions::new()
                    .write(true)
                    .open(file_path(dir, tail_no))?
                    .set_len(tail_len)?;
            }
            OpenOptions::new()
                .append(true)
                .open(file_path(dir, tail_no))?
        };

        Ok(Self {
            dir: dir.to_path_buf(),
            magic,
            index,
            tail_no,
            tail_len,
            tail,
            max_file_size,
            pruned_through: None,
        })
    }

    /// Number of indexed blocks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// `true` when no blocks are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// `true` when `hash` has a stored frame.
    #[must_use]
    pub fn contains(&self, hash: &BlockHash) -> bool {
        self.index.contains_key(hash)
    }

    /// Position of `hash`'s frame.
    #[must_use]
    pub fn position(&self, hash: &BlockHash) -> Option<BlockPos> {
        self.index.get(hash).copied()
    }

    /// Stored positions in file order — the order `append` wrote them.
    pub fn positions(&self) -> Vec<(BlockHash, BlockPos)> {
        let mut v: Vec<_> = self.index.iter().map(|(h, p)| (*h, *p)).collect();
        v.sort_by_key(|(_, p)| (p.file, p.offset));
        v
    }

    /// Reads and decodes the block at `pos`.
    ///
    /// # Errors
    ///
    /// `io::Error` on read failure; [`io::ErrorKind::InvalidData`] when the
    /// payload no longer decodes (store corruption).
    pub fn read(&self, pos: BlockPos) -> io::Result<Block> {
        if self.is_pruned(pos) {
            return Err(io::Error::new(io::ErrorKind::NotFound, "block body pruned"));
        }
        let mut file = BufReader::new(File::open(file_path(&self.dir, pos.file))?);
        file.seek(SeekFrom::Start(pos.offset))?;
        let mut payload = vec![0u8; pos.len as usize];
        file.read_exact(&mut payload)?;
        Block::decode(&payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("block decode: {e}")))
    }

    /// Appends `block` as a `magic | len | payload` frame, rotating to a new
    /// file when the frame would push the tail past `MAX_FILE_SIZE`.
    /// Idempotent per block hash — a stored block is not written twice.
    ///
    /// # Errors
    ///
    /// `io::Error` on write failure. On `Err` the tail may hold a partial
    /// frame; the next `open` truncates it.
    pub fn append(&mut self, block: &Block) -> io::Result<BlockPos> {
        let hash = block.block_hash();
        if let Some(pos) = self.index.get(&hash) {
            return Ok(*pos);
        }
        let payload = block.encode();
        let frame_len = FRAME_HEADER + payload.len() as u64;
        if self.tail_len > 0 && self.tail_len + frame_len > self.max_file_size {
            self.tail.flush()?;
            self.tail_no += 1;
            self.tail_len = 0;
            self.tail = open_tail(&self.dir, self.tail_no)?;
        }
        let pos = BlockPos {
            file: self.tail_no,
            offset: self.tail_len + FRAME_HEADER,
            len: payload.len() as u32,
        };
        self.tail.write_all(&self.magic)?;
        self.tail.write_all(&(payload.len() as u32).to_le_bytes())?;
        self.tail.write_all(&payload)?;
        self.tail_len += frame_len;
        self.index.insert(hash, pos);
        Ok(pos)
    }

    /// `true` if `pos` points into a file deleted by pruning.
    #[must_use]
    pub fn is_pruned(&self, pos: BlockPos) -> bool {
        self.pruned_through.is_some_and(|t| pos.file <= t)
    }

    /// Highest `blkNNNNN.dat` file number deleted so far this session.
    #[must_use]
    pub fn pruned_through(&self) -> Option<u32> {
        self.pruned_through
    }

    /// Deletes the oldest `blk*.dat` files while the on-disk total
    /// exceeds `keep` bytes — never the append tail. Returns the count
    /// deleted. Index entries survive in-session so `read` reports
    /// "pruned" rather than "absent"; a reopen rebuilds the index from
    /// what remains on disk.
    ///
    /// # Errors
    ///
    /// `io::Error` on listing or removal failure — a partial prune may
    /// leave some files deleted.
    pub fn prune_to_bytes(&mut self, keep: u64) -> io::Result<u32> {
        self.tail.flush()?;
        let mut files: Vec<(u32, u64)> = fs::read_dir(&self.dir)?
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let name = entry.file_name().into_string().ok()?;
                let no = name
                    .strip_prefix(FILE_PREFIX)?
                    .strip_suffix(FILE_SUFFIX)?
                    .parse::<u32>()
                    .ok()?;
                Some((no, entry.metadata().ok()?.len()))
            })
            .collect();
        files.sort_unstable();
        let mut total: u64 = files.iter().map(|(_, size)| size).sum();
        let mut deleted = 0;
        for (file, size) in files {
            if file >= self.tail_no || total <= keep {
                break;
            }
            fs::remove_file(file_path(&self.dir, file))?;
            total -= size;
            self.pruned_through = Some(file);
            deleted += 1;
        }
        Ok(deleted)
    }

    /// Flushes buffered writes to the OS. Durability beyond this (fsync) is
    /// the caller's batch boundary — the index is rebuilt by scanning, so an
    /// unflushed tail is at worst absent or partial on reopen, never corrupt.
    pub fn flush(&mut self) -> io::Result<()> {
        self.tail.flush()
    }

    /// The directory holding this store — where `state.dat` lives too.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The network magic frames carry — also `state.dat`'s magic.
    #[must_use]
    pub fn magic(&self) -> [u8; 4] {
        self.magic
    }
}

fn file_path(dir: &Path, no: u32) -> PathBuf {
    dir.join(format!("{FILE_PREFIX}{no:05}{FILE_SUFFIX}"))
}

fn open_tail(dir: &Path, no: u32) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(file_path(dir, no))
}

/// Scans one blk file frame-by-frame, indexing each decodable block by hash.
/// Returns the offset of the first bad frame (the file's committed length).
/// A stop before EOF is only legitimate on the tail file — a non-tail file
/// ended cleanly when it was rotated, so an early stop there means store
/// corruption and is reported.
fn scan_file(
    path: &Path,
    file_no: u32,
    magic: [u8; 4],
    is_tail: bool,
    index: &mut HashMap<BlockHash, BlockPos>,
) -> io::Result<u64> {
    let mut file = BufReader::new(File::open(path)?);
    let file_len = file.get_ref().metadata()?.len();
    let mut cursor = 0u64;
    while cursor + FRAME_HEADER <= file_len {
        let mut header = [0u8; 8];
        file.read_exact(&mut header)?;
        if header[..4] != magic {
            break;
        }
        let len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as u64;
        if len == 0
            || len > MAX_BLOCK_SERIALIZED_SIZE as u64
            || cursor + FRAME_HEADER + len > file_len
        {
            break; // bad or partial tail frame — committed length is `cursor`
        }
        let mut payload = vec![0u8; len as usize];
        file.read_exact(&mut payload)?;
        let block = match Block::decode(&payload) {
            Ok(block) => block,
            Err(_) => break,
        };
        index.insert(
            block.block_hash(),
            BlockPos {
                file: file_no,
                offset: cursor + FRAME_HEADER,
                len: len as u32,
            },
        );
        cursor += FRAME_HEADER + len;
    }
    if cursor < file_len && !is_tail {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{}: corrupt frame at offset {cursor} (non-tail file)",
                path.display()
            ),
        ));
    }
    Ok(cursor)
}

// ---------------------------------------------------------------------------
// Validation-state snapshot (`state.dat`)
//
// The blk files are the durable record of *arrived* bodies; the snapshot is
// the durable record of *validated* state — connected tip, chain order, undo
// records, the coins view, and the failed-block set — written at a flush
// boundary so a restart resumes without re-validating. The write is atomic:
// `state.dat.tmp` is synced then renamed over `state.dat`, so a crash
// mid-write leaves the previous snapshot (or none) and replay covers the gap.
//
// This is our own bounded format — storage is free to differ from Core's
// LevelDB/rev files as long as consensus behavior is unchanged.
// ---------------------------------------------------------------------------

const STATE_FILE: &str = "state.dat";
const STATE_TMP: &str = "state.dat.tmp";
// v2 adds `tx_meta` (per-node nTx/nChainTx) so `getchaintxstats`
// survives restarts; a v1 snapshot is rejected and replay rebuilds.
const STATE_VERSION: u32 = 2;

/// The complete validation state needed to resume without re-validation.
#[derive(Clone, PartialEq, Debug)]
pub struct StateData {
    /// The connected tip's block hash (`chain.last()`).
    pub tip: BlockHash,
    /// The connected tip's height (`chain.len() - 1`).
    pub height: u32,
    /// Every header in the block index, sorted by height so parents always
    /// precede children on reinsert — including headers indexed headers-first
    /// whose bodies never arrived.
    pub headers: Vec<crate::header::BlockHeader>,
    /// The best-header tip (`HeaderTree::tip_hash`) — stored explicitly
    /// because "earliest inserted wins" among equal-work candidates cannot be
    /// reconstructed from a height sort.
    pub best_header: BlockHash,
    /// Connected chain block hashes, genesis at index 0.
    pub chain: Vec<BlockHash>,
    /// Undo for `chain[1..]`: `undos[k]` reverses `chain[k + 1]`.
    pub undos: Vec<BlockUndo>,
    /// The coins view at `tip`.
    pub utxo: Vec<(OutPoint, Coin)>,
    /// Failed-marked block hashes (`BLOCK_FAILED_*` bookkeeping).
    pub failed: Vec<BlockHash>,
    /// `(hash, n_tx, n_chain_tx)` for nodes whose body was seen —
    /// Core's per-index `nTx`/`nChainTx`, needed to keep
    /// `getchaintxstats` honest across a snapshot resume.
    pub tx_meta: Vec<(BlockHash, u32, u64)>,
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn put_coin(out: &mut Vec<u8>, coin: &Coin) {
    out.extend_from_slice(&coin.out.value.to_le_bytes());
    write_var_bytes(out, coin.out.script_pubkey.as_bytes());
    out.extend_from_slice(&coin.height.to_le_bytes());
    out.push(u8::from(coin.coinbase));
}

fn get_coin(d: &mut Decoder) -> io::Result<Coin> {
    let value = d
        .read_i64_le()
        .map_err(|e| invalid(format!("coin value: {e}")))?;
    let spk = d
        .read_var_bytes()
        .map_err(|e| invalid(format!("coin script: {e}")))?;
    let height = d
        .read_u32_le()
        .map_err(|e| invalid(format!("coin height: {e}")))?;
    let coinbase = d
        .read_u8()
        .map_err(|e| invalid(format!("coin flag: {e}")))?;
    Ok(Coin {
        out: TxOut {
            value,
            script_pubkey: Script::new(spk),
        },
        height,
        coinbase: coinbase != 0,
    })
}

fn put_outpoint(out: &mut Vec<u8>, op: &OutPoint) {
    out.extend_from_slice(op.txid.as_bytes());
    out.extend_from_slice(&op.vout.to_le_bytes());
}

fn get_outpoint(d: &mut Decoder) -> io::Result<OutPoint> {
    let txid = d
        .read_array::<32>()
        .map_err(|e| invalid(format!("outpoint txid: {e}")))?;
    let vout = d
        .read_u32_le()
        .map_err(|e| invalid(format!("outpoint vout: {e}")))?;
    Ok(OutPoint {
        txid: Txid::from_bytes(txid),
        vout,
    })
}

fn put_undo(out: &mut Vec<u8>, undo: &BlockUndo) {
    write_compact_size(out, undo.txs.len() as u64);
    for tx in &undo.txs {
        write_compact_size(out, tx.spent.len() as u64);
        for coin in &tx.spent {
            put_coin(out, coin);
        }
        write_compact_size(out, tx.overwritten.len() as u64);
        for (op, coin) in &tx.overwritten {
            put_outpoint(out, op);
            put_coin(out, coin);
        }
    }
}

fn get_undo(d: &mut Decoder) -> io::Result<BlockUndo> {
    let tx_count = d
        .read_compact_size()
        .map_err(|e| invalid(format!("undo tx count: {e}")))?;
    let mut txs = Vec::with_capacity(d.bounded_capacity(tx_count, 2));
    for _ in 0..tx_count {
        let spent_count = d
            .read_compact_size()
            .map_err(|e| invalid(format!("undo spent count: {e}")))?;
        let mut spent = Vec::with_capacity(d.bounded_capacity(spent_count, 37));
        for _ in 0..spent_count {
            spent.push(get_coin(d)?);
        }
        let over_count = d
            .read_compact_size()
            .map_err(|e| invalid(format!("undo overwrite count: {e}")))?;
        let mut overwritten = Vec::with_capacity(d.bounded_capacity(over_count, 73));
        for _ in 0..over_count {
            let op = get_outpoint(d)?;
            let coin = get_coin(d)?;
            overwritten.push((op, coin));
        }
        txs.push(TxUndo { spent, overwritten });
    }
    Ok(BlockUndo { txs })
}

/// Atomically writes `data` as `dir/state.dat` (tmp file + rename). The
/// payload carries a sha256d checksum so truncation or bit damage is
/// detected on load rather than producing a wrong state.
///
/// # Errors
///
/// `io::Error` on any write/sync/rename failure.
pub fn write_state(dir: &Path, magic: [u8; 4], data: &StateData) -> io::Result<()> {
    let mut payload = Vec::new();
    payload.extend_from_slice(data.tip.as_bytes());
    payload.extend_from_slice(&data.height.to_le_bytes());
    write_compact_size(&mut payload, data.headers.len() as u64);
    for header in &data.headers {
        payload.extend_from_slice(&header.encode());
    }
    payload.extend_from_slice(data.best_header.as_bytes());
    write_compact_size(&mut payload, data.chain.len() as u64);
    for hash in &data.chain {
        payload.extend_from_slice(hash.as_bytes());
    }
    write_compact_size(&mut payload, data.undos.len() as u64);
    for undo in &data.undos {
        let mut buf = Vec::new();
        put_undo(&mut buf, undo);
        write_var_bytes(&mut payload, &buf);
    }
    write_compact_size(&mut payload, data.utxo.len() as u64);
    for (op, coin) in &data.utxo {
        put_outpoint(&mut payload, op);
        put_coin(&mut payload, coin);
    }
    write_compact_size(&mut payload, data.failed.len() as u64);
    for hash in &data.failed {
        payload.extend_from_slice(hash.as_bytes());
    }
    write_compact_size(&mut payload, data.tx_meta.len() as u64);
    for (hash, n_tx, n_chain_tx) in &data.tx_meta {
        payload.extend_from_slice(hash.as_bytes());
        payload.extend_from_slice(&n_tx.to_le_bytes());
        payload.extend_from_slice(&n_chain_tx.to_le_bytes());
    }

    let mut file_bytes = Vec::with_capacity(payload.len() + 44);
    file_bytes.extend_from_slice(&magic);
    file_bytes.extend_from_slice(&STATE_VERSION.to_le_bytes());
    file_bytes.extend_from_slice(&sha256d(&payload));
    file_bytes.extend_from_slice(&payload);

    let tmp = dir.join(STATE_TMP);
    {
        let mut f = File::create(&tmp)?;
        f.write_all(&file_bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, dir.join(STATE_FILE))
}

/// Reads `dir/state.dat`, verifying magic, version and checksum.
/// `Ok(None)` when no snapshot exists (a fresh store, or a crash before the
/// first snapshot — replay covers it). A leftover `state.dat.tmp` from an
/// interrupted write is removed.
///
/// # Errors
///
/// [`io::ErrorKind::InvalidData`] on a present-but-corrupt snapshot — the
/// checksum should make this corruption, never a silent wrong state.
pub fn read_state(dir: &Path, magic: [u8; 4]) -> io::Result<Option<StateData>> {
    let path = dir.join(STATE_FILE);
    if dir.join(STATE_TMP).exists() {
        // Interrupted write — the tmp never became the snapshot.
        fs::remove_file(dir.join(STATE_TMP))?;
    }
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path)?;
    if bytes.len() < 40 || bytes[..4] != magic {
        return Err(invalid("state.dat: bad magic"));
    }
    let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if version != STATE_VERSION {
        return Err(invalid(format!("state.dat: version {version}")));
    }
    let checksum: [u8; 32] = bytes[8..40]
        .try_into()
        .map_err(|_| invalid("state.dat: short checksum"))?;
    let payload = &bytes[40..];
    if sha256d(payload) != checksum {
        return Err(invalid("state.dat: checksum mismatch"));
    }

    let mut d = Decoder::new(payload);
    let tip = BlockHash::from_bytes(
        d.read_array::<32>()
            .map_err(|e| invalid(format!("tip: {e}")))?,
    );
    let height = d
        .read_u32_le()
        .map_err(|e| invalid(format!("height: {e}")))?;
    let header_count = d
        .read_compact_size()
        .map_err(|e| invalid(format!("header count: {e}")))?;
    let mut headers = Vec::with_capacity(d.bounded_capacity(header_count, 80));
    for _ in 0..header_count {
        let bytes = d
            .read_array::<80>()
            .map_err(|e| invalid(format!("header: {e}")))?;
        headers.push(
            crate::header::BlockHeader::decode(&bytes)
                .map_err(|e| invalid(format!("header decode: {e}")))?,
        );
    }
    let best_header = BlockHash::from_bytes(
        d.read_array::<32>()
            .map_err(|e| invalid(format!("best header: {e}")))?,
    );
    let chain = read_hashes(&mut d, "chain")?;
    let undo_count = d
        .read_compact_size()
        .map_err(|e| invalid(format!("undo count: {e}")))?;
    let mut undos = Vec::with_capacity(d.bounded_capacity(undo_count, 1));
    for _ in 0..undo_count {
        let buf = d
            .read_var_bytes()
            .map_err(|e| invalid(format!("undo payload: {e}")))?;
        let mut ud = Decoder::new(&buf);
        undos.push(get_undo(&mut ud)?);
        ud.finish()
            .map_err(|e| invalid(format!("undo trailing: {e}")))?;
    }
    let utxo_count = d
        .read_compact_size()
        .map_err(|e| invalid(format!("utxo count: {e}")))?;
    let mut utxo = Vec::with_capacity(d.bounded_capacity(utxo_count, 45));
    for _ in 0..utxo_count {
        let op = get_outpoint(&mut d)?;
        let coin = get_coin(&mut d)?;
        utxo.push((op, coin));
    }
    let failed = read_hashes(&mut d, "failed")?;
    let tx_meta_count = d
        .read_compact_size()
        .map_err(|e| invalid(format!("tx_meta count: {e}")))?;
    let mut tx_meta = Vec::with_capacity(d.bounded_capacity(tx_meta_count, 44));
    for _ in 0..tx_meta_count {
        let hash = BlockHash::from_bytes(
            d.read_array::<32>()
                .map_err(|e| invalid(format!("tx_meta hash: {e}")))?,
        );
        let n_tx = d
            .read_u32_le()
            .map_err(|e| invalid(format!("tx_meta n_tx: {e}")))?;
        let n_chain_tx = d
            .read_u64_le()
            .map_err(|e| invalid(format!("tx_meta n_chain_tx: {e}")))?;
        tx_meta.push((hash, n_tx, n_chain_tx));
    }
    d.finish().map_err(|e| invalid(format!("trailing: {e}")))?;
    if chain.is_empty()
        || chain.len() as u64 - 1 != undos.len() as u64
        || chain.last() != Some(&tip)
        || u64::from(height) != chain.len() as u64 - 1
    {
        return Err(invalid("state.dat: chain/undo/tip mismatch"));
    }
    Ok(Some(StateData {
        tip,
        height,
        headers,
        best_header,
        chain,
        undos,
        utxo,
        failed,
        tx_meta,
    }))
}

fn read_hashes(d: &mut Decoder, what: &str) -> io::Result<Vec<BlockHash>> {
    let count = d
        .read_compact_size()
        .map_err(|e| invalid(format!("{what} count: {e}")))?;
    let mut v = Vec::with_capacity(d.bounded_capacity(count, 32));
    for _ in 0..count {
        v.push(BlockHash::from_bytes(
            d.read_array::<32>()
                .map_err(|e| invalid(format!("{what} hash: {e}")))?,
        ));
    }
    Ok(v)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::arith::CompactTarget;
    use crate::hash::MerkleRoot;
    use crate::header::BlockHeader;
    use crate::transaction::{OutPoint, Script, Transaction, TxIn, TxOut, Witness};

    const MAGIC: [u8; 4] = [0xfa, 0xbf, 0xb5, 0xda]; // regtest pchMessageStart

    /// A distinct, decodable block per `nonce` — the store indexes by hash
    /// and never validates content.
    fn test_block(nonce: u32) -> Block {
        Block {
            header: BlockHeader {
                version: 4,
                prev_block_hash: BlockHash::from_bytes([0; 32]),
                merkle_root: MerkleRoot::from_bytes([nonce as u8; 32]),
                time: 1_700_000_000,
                bits: CompactTarget(0x207f_ffff),
                nonce,
            },
            transactions: vec![Transaction {
                version: 1,
                inputs: vec![TxIn {
                    previous_output: OutPoint::NULL,
                    script_sig: Script::new(vec![0x01, nonce as u8]),
                    sequence: u32::MAX,
                    witness: Witness::default(),
                }],
                outputs: vec![TxOut {
                    value: 0,
                    script_pubkey: Script::new(vec![0x51]),
                }],
                lock_time: 0,
            }],
        }
    }

    /// A unique store dir under the test target dir — no external tempdir dep.
    fn test_dir(name: &str) -> PathBuf {
        // canonicalize: a relative TMPDIR would otherwise land inside the
        // crate directory.
        let base = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|_| std::env::temp_dir());
        let dir = base.join(format!("avila-store-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn append_rescan_roundtrip() {
        let dir = test_dir("roundtrip");
        let mut store = BlockStore::open(&dir, MAGIC).unwrap();
        let blocks: Vec<Block> = (0..5).map(test_block).collect();
        for block in &blocks {
            store.append(block).unwrap();
        }
        // Idempotent: appending a known block does not grow the index.
        let len_before = store.len();
        store.append(&blocks[0]).unwrap();
        assert_eq!(store.len(), len_before);
        store.flush().unwrap();
        drop(store);

        let store = BlockStore::open(&dir, MAGIC).unwrap();
        assert_eq!(store.len(), 5);
        for block in &blocks {
            let pos = store.position(&block.block_hash()).unwrap();
            assert_eq!(store.read(pos).unwrap(), *block);
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn partial_tail_is_truncated_on_open() {
        let dir = test_dir("truncate");
        let mut store = BlockStore::open(&dir, MAGIC).unwrap();
        store.append(&test_block(1)).unwrap();
        let pos = store.position(&test_block(1).block_hash()).unwrap();
        let committed = pos.offset + u64::from(pos.len);
        store.flush().unwrap();
        drop(store);

        // Simulate an interrupted write: frame header + half a payload.
        let mut file = OpenOptions::new()
            .append(true)
            .open(dir.join("blk00000.dat"))
            .unwrap();
        file.write_all(&MAGIC).unwrap();
        file.write_all(&500u32.to_le_bytes()).unwrap();
        file.write_all(&[0xaa; 100]).unwrap();
        drop(file);

        let store = BlockStore::open(&dir, MAGIC).unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(
            fs::metadata(dir.join("blk00000.dat")).unwrap().len(),
            committed
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rotation_spans_files() {
        let dir = test_dir("rotate");
        // ~3 small blocks per file.
        let limit = 3 * (FRAME_HEADER + test_block(0).encode().len() as u64);
        let mut store = BlockStore::open_with_limit(&dir, MAGIC, limit).unwrap();
        let blocks: Vec<Block> = (0..8).map(test_block).collect();
        for block in &blocks {
            store.append(block).unwrap();
        }
        store.flush().unwrap();
        assert!(store.positions().iter().map(|(_, p)| p.file).max().unwrap() >= 2);
        drop(store);

        let store = BlockStore::open_with_limit(&dir, MAGIC, limit).unwrap();
        assert_eq!(store.len(), 8);
        for block in &blocks {
            let pos = store.position(&block.block_hash()).unwrap();
            assert_eq!(store.read(pos).unwrap(), *block);
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn pruning_deletes_oldest_files_and_reports_them() {
        let dir = test_dir("prune");
        let limit = 3 * (FRAME_HEADER + test_block(0).encode().len() as u64);
        let mut store = BlockStore::open_with_limit(&dir, MAGIC, limit).unwrap();
        let blocks: Vec<Block> = (0..9).map(test_block).collect();
        for block in &blocks {
            store.append(block).unwrap();
        }
        store.flush().unwrap();
        // 9 blocks / 3 per file → files 0,1,2 (+tail 3).
        let first_pos = store.position(&blocks[0].block_hash()).unwrap();
        let last_pos = store.position(&blocks[8].block_hash()).unwrap();
        let keep = fs::metadata(file_path(&dir, last_pos.file)).unwrap().len();
        let deleted = store.prune_to_bytes(keep).unwrap();
        assert!(deleted >= 1, "oldest files pruned");
        // Pruned positions still resolve but reads report NotFound.
        assert!(store.is_pruned(first_pos));
        assert!(!store.is_pruned(last_pos));
        assert_eq!(
            store.read(first_pos).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(store.read(last_pos).unwrap(), blocks[8]);
        drop(store);

        // Reopen: the index holds only what survived; reads of retained
        // bodies still work.
        let store = BlockStore::open_with_limit(&dir, MAGIC, limit).unwrap();
        assert!(store.position(&blocks[8].block_hash()).is_some());
        assert_eq!(store.len(), 9 - deleted as usize * 3);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn foreign_magic_is_refused() {
        let dir = test_dir("foreign");
        fs::create_dir_all(&dir).unwrap();
        let mut file = File::create(dir.join("blk00000.dat")).unwrap();
        file.write_all(&[0xde, 0xad, 0xbe, 0xef]).unwrap();
        file.write_all(&10u32.to_le_bytes()).unwrap();
        file.write_all(&[0; 10]).unwrap();
        drop(file);
        match BlockStore::open(&dir, MAGIC) {
            Err(err) => assert_eq!(err.kind(), io::ErrorKind::InvalidData),
            Ok(_) => panic!("foreign-magic store opened"),
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A `StateData` exercising every field — header set, connected chain,
    /// undo records, coins, and the failed set.
    fn test_state() -> StateData {
        let blocks: Vec<Block> = (0..3).map(test_block).collect();
        let headers: Vec<BlockHeader> = blocks.iter().map(|b| b.header).collect();
        let chain: Vec<BlockHash> = blocks.iter().map(Block::block_hash).collect();
        let tx_meta: Vec<(BlockHash, u32, u64)> = chain
            .iter()
            .enumerate()
            .map(|(i, h)| (*h, 1, i as u64 + 1))
            .collect();
        StateData {
            tip: *chain.last().unwrap(),
            height: 2,
            headers,
            best_header: *chain.last().unwrap(),
            chain,
            undos: vec![
                BlockUndo {
                    txs: vec![TxUndo {
                        spent: vec![Coin {
                            out: TxOut {
                                value: 5_000,
                                script_pubkey: Script::new(vec![0x51]),
                            },
                            height: 0,
                            coinbase: true,
                        }],
                        overwritten: vec![(
                            OutPoint {
                                txid: Txid::from_bytes([9; 32]),
                                vout: 3,
                            },
                            Coin {
                                out: TxOut {
                                    value: 7,
                                    script_pubkey: Script::new(vec![0x52]),
                                },
                                height: 1,
                                coinbase: false,
                            },
                        )],
                    }],
                },
                BlockUndo::default(),
            ],
            utxo: vec![
                (
                    OutPoint {
                        txid: Txid::from_bytes([1; 32]),
                        vout: 0,
                    },
                    Coin {
                        out: TxOut {
                            value: 50,
                            script_pubkey: Script::new(vec![0x51, 0x52]),
                        },
                        height: 2,
                        coinbase: false,
                    },
                ),
                (
                    OutPoint {
                        txid: Txid::from_bytes([2; 32]),
                        vout: 1,
                    },
                    Coin {
                        out: TxOut {
                            value: 100,
                            script_pubkey: Script::new(vec![]),
                        },
                        height: 1,
                        coinbase: true,
                    },
                ),
            ],
            failed: vec![BlockHash::from_bytes([0xee; 32])],
            tx_meta,
        }
    }

    fn expect_invalid(result: io::Result<Option<StateData>>) {
        match result {
            Err(err) => assert_eq!(err.kind(), io::ErrorKind::InvalidData),
            Ok(_) => panic!("invalid state.dat loaded"),
        }
    }

    #[test]
    fn state_roundtrip() {
        let dir = test_dir("state-roundtrip");
        fs::create_dir_all(&dir).unwrap();
        let state = test_state();
        write_state(&dir, MAGIC, &state).unwrap();
        assert_eq!(read_state(&dir, MAGIC).unwrap(), Some(state));
        // The tmp file is consumed by the rename — never left behind.
        assert!(!dir.join(STATE_TMP).exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn state_absent_is_none() {
        let dir = test_dir("state-absent");
        fs::create_dir_all(&dir).unwrap();
        assert_eq!(read_state(&dir, MAGIC).unwrap(), None);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn state_checksum_catches_corruption() {
        let dir = test_dir("state-corrupt");
        fs::create_dir_all(&dir).unwrap();
        write_state(&dir, MAGIC, &test_state()).unwrap();
        let path = dir.join(STATE_FILE);
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::write(&path, &bytes).unwrap();
        expect_invalid(read_state(&dir, MAGIC));
        // Truncation is caught the same way.
        fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();
        expect_invalid(read_state(&dir, MAGIC));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn state_magic_and_version_are_checked() {
        let dir = test_dir("state-guards");
        fs::create_dir_all(&dir).unwrap();
        write_state(&dir, MAGIC, &test_state()).unwrap();
        // Wrong network magic.
        expect_invalid(read_state(&dir, [0xde, 0xad, 0xbe, 0xef]));
        // An unknown version — checked before the checksum, so the digest
        // stays stale on purpose.
        let path = dir.join(STATE_FILE);
        let mut bytes = fs::read(&path).unwrap();
        bytes[4] = 0x7f;
        fs::write(&path, &bytes).unwrap();
        expect_invalid(read_state(&dir, MAGIC));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn state_tmp_leftover_is_ignored() {
        let dir = test_dir("state-tmp");
        fs::create_dir_all(&dir).unwrap();
        let state = test_state();
        write_state(&dir, MAGIC, &state).unwrap();
        // An interrupted second write leaves a partial tmp — the last
        // committed snapshot still wins.
        fs::write(dir.join(STATE_TMP), [0xde, 0xad]).unwrap();
        assert_eq!(read_state(&dir, MAGIC).unwrap(), Some(state));
        assert!(!dir.join(STATE_TMP).exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rotation_failure_surfaces_and_store_stays_openable() {
        let dir = test_dir("rotate-fail");
        // ~3 small blocks per file; blk00001.dat exists as a *directory*, so
        // the first rotation's open_tail fails mid-append.
        let limit = 3 * (FRAME_HEADER + test_block(0).encode().len() as u64);
        let mut store = BlockStore::open_with_limit(&dir, MAGIC, limit).unwrap();
        fs::create_dir(dir.join("blk00001.dat")).unwrap();
        let blocks: Vec<Block> = (0..8).map(test_block).collect();
        let mut appended = 0;
        for block in &blocks {
            match store.append(block) {
                Ok(_) => appended += 1,
                Err(_) => break,
            }
        }
        assert!(appended < 8, "rotation should have failed");
        drop(store);
        fs::remove_dir(dir.join("blk00001.dat")).unwrap();

        // Reopen: the truncated tail is dropped, committed blocks are intact,
        // and the store accepts appends again.
        let mut store = BlockStore::open_with_limit(&dir, MAGIC, limit).unwrap();
        assert_eq!(store.len(), appended);
        for block in &blocks {
            store.append(block).unwrap();
        }
        assert_eq!(store.len(), 8);
        fs::remove_dir_all(&dir).unwrap();
    }
}
