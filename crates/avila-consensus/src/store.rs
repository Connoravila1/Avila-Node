//! Durable block storage: Core's `blkNNNNN.dat` flat-file format.
//!
//! Each file is a stream of `magic` + `u32` little-endian length + raw block
//! frames, appended in arrival order and rotated at [`MAX_FILE_SIZE`] —
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
use crate::hash::BlockHash;

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
    /// Rotation threshold — [`MAX_FILE_SIZE`] in production; tests shrink it.
    max_file_size: u64,
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
        let mut file = BufReader::new(File::open(file_path(&self.dir, pos.file))?);
        file.seek(SeekFrom::Start(pos.offset))?;
        let mut payload = vec![0u8; pos.len as usize];
        file.read_exact(&mut payload)?;
        Block::decode(&payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("block decode: {e}")))
    }

    /// Appends `block` as a `magic | len | payload` frame, rotating to a new
    /// file when the frame would push the tail past [`MAX_FILE_SIZE`].
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

    /// Flushes buffered writes to the OS. Durability beyond this (fsync) is
    /// the caller's batch boundary — the index is rebuilt by scanning, so an
    /// unflushed tail is at worst absent or partial on reopen, never corrupt.
    pub fn flush(&mut self) -> io::Result<()> {
        self.tail.flush()
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
}
