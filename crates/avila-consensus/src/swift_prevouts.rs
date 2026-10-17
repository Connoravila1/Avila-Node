//! Bounded disk-backed historical prevout records for shadow SwiftSync experiments.
//!
//! The store retains every inserted output record, including coins later spent. A lookup
//! proves only that this database contains a coin record for an outpoint under its local
//! checkpoint binding; it does not prove that the outpoint was created in a valid block,
//! remains unspent, or belongs to a valid chain. This is not a consensus membership source.
//!
//! Rows use Avila's compact coin codec inside a versioned, length-framed, checksummed value.
//! Record and metadata checksums detect accidental corruption; they are unkeyed and provide
//! no authenticity. The table uses a canonical outpoint key (txid || vout with big-endian vout)
//! and redb's bounded cache. Entry, encoded-byte, batch, and per-record limits are explicit
//! and persisted where they define the database's storage ceiling.

use std::path::Path;

use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use sha2::{Digest, Sha256};

use crate::coinsdb::CoinFormat;
use crate::connect::Coin;
use crate::hash::BlockHash;
use crate::params::Network;
use crate::transaction::OutPoint;

const COINS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("swift_prevout_coins");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("swift_prevout_meta");
const META_KEY: &str = "state";
const MAGIC: &[u8; 8] = b"AVPRV001";
const VERSION: u32 = 1;
const ROW_VERSION: u8 = 1;
const ROW_DOMAIN: &[u8] = b"Avila SwiftPrevout record v1\0";
const META_DOMAIN: &[u8] = b"Avila SwiftPrevout metadata v1\0";
const ROW_PREFIX_BYTES: usize = 1 + 4;
const CHECKSUM_BYTES: usize = 32;
const META_BODY_BYTES: usize = 8 + 4 + 1 + 4 + 32 + 8 + 8 + 4 + 4 + 8 + 8;
const META_BYTES: usize = META_BODY_BYTES + CHECKSUM_BYTES;
/// Script-byte ceiling accepted by this store. Callers must exclude provably unspendable
/// outputs; this bound is about spending scripts and is not an output-creation rule.
pub const MAX_SCRIPT_BYTES: usize = 10_000;
/// Largest supported framed value size. Limits may choose a smaller value.
pub const MAX_RECORD_BYTES: usize = 20_000;
/// Redb cache upper bound for this experimental store.
pub const MAX_CACHE_BYTES: usize = 1024 * 1024 * 1024;

/// Network and checkpoint that scope one on-disk prevout index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrevoutCheckpoint {
    /// Bitcoin network identifier.
    pub network: Network,
    /// Height described by the index.
    pub height: u32,
    /// Block hash at height.
    pub hash: BlockHash,
}

/// Explicit resource limits for a disk-backed prevout index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwiftPrevoutLimits {
    /// Maximum number of distinct outpoints stored.
    pub max_entries: u64,
    /// Maximum total bytes of 36-byte key plus framed value.
    pub max_total_encoded_bytes: u64,
    /// Maximum number of distinct records accepted in one atomic batch.
    pub max_batch_entries: usize,
    /// Maximum size of one complete framed value, including checksum.
    pub max_record_bytes: usize,
    /// Maximum coin script size.
    pub max_script_bytes: usize,
    /// Redb's in-process page-cache budget.
    pub cache_bytes: usize,
}

/// A typed failure while opening or using the experimental store.
#[derive(Debug, thiserror::Error)]
pub enum SwiftPrevoutError {
    /// Filesystem operation failed.
    #[error("prevout store I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Redb operation failed. The message is diagnostic only.
    #[error("prevout store database {operation}: {message}")]
    Database {
        /// Operation that failed.
        operation: &'static str,
        /// Underlying storage-library error text.
        message: String,
    },
    /// Caller-supplied resource limits are invalid.
    #[error("invalid prevout store limits")]
    InvalidLimits,
    /// The requested path already exists; create never overwrites a database.
    #[error("prevout store path already exists")]
    AlreadyExists,
    /// The existing database is bound to a different checkpoint or storage ceiling.
    #[error("prevout store checkpoint or persisted limits do not match")]
    BindingMismatch,
    /// Required metadata is absent, malformed, or inconsistent with bounded table metadata.
    #[error("prevout store metadata is malformed or inconsistent")]
    CorruptMetadata,
    /// The output coin is invalid for this bounded storage format.
    #[error("coin value is outside MoneyRange or script exceeds the bound")]
    InvalidCoin,
    /// The output coin claims creation after the bound checkpoint.
    #[error("coin creation height is beyond the store checkpoint")]
    CoinAfterCheckpoint,
    /// A framed record exceeds the configured per-record size.
    #[error("framed coin record exceeds configured limit")]
    RecordTooLarge,
    /// One batch exceeds its configured record count.
    #[error("batch exceeds configured entry limit")]
    BatchTooLarge,
    /// The table has reached its configured distinct-outpoint count.
    #[error("store entry limit exceeded")]
    EntryLimitExceeded,
    /// The table has reached its configured encoded-byte budget.
    #[error("store encoded-byte limit exceeded")]
    EncodedBytesLimitExceeded,
    /// The same outpoint was presented with different coin data.
    #[error("duplicate outpoint has a different coin record")]
    DuplicateCoinMismatch,
    /// A stored row has invalid framing or cannot be decoded as exactly one compact coin.
    #[error("stored coin record is malformed")]
    MalformedRecord,
    /// A stored row's checksum does not match its key and body.
    #[error("stored coin record checksum mismatch")]
    ChecksumMismatch,
    /// Metadata counter arithmetic overflowed.
    #[error("prevout store counter overflow")]
    CounterOverflow,
}

#[derive(Clone, Copy)]
struct State {
    entries: u64,
    encoded_bytes: u64,
}

/// Checkpoint-bound append-only historical coin index for shadow experiments.
pub struct SwiftPrevoutStore {
    db: redb::Database,
    checkpoint: PrevoutCheckpoint,
    limits: SwiftPrevoutLimits,
    state: State,
}

impl SwiftPrevoutStore {
    /// Creates a new database without replacing an existing path.
    pub fn create(
        path: &Path,
        checkpoint: PrevoutCheckpoint,
        limits: SwiftPrevoutLimits,
    ) -> Result<Self, SwiftPrevoutError> {
        validate_limits(limits)?;
        let reservation = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    SwiftPrevoutError::AlreadyExists
                } else {
                    SwiftPrevoutError::Io(error)
                }
            })?;
        drop(reservation);

        let db = database_builder(limits)
            .create(path)
            .map_err(|error| database_error("create", error))?;
        let write = db
            .begin_write()
            .map_err(|error| database_error("begin create transaction", error))?;
        {
            let _coins = write
                .open_table(COINS)
                .map_err(|error| database_error("create coin table", error))?;
            let mut meta = write
                .open_table(META)
                .map_err(|error| database_error("create metadata table", error))?;
            meta.insert(
                META_KEY,
                encode_state(
                    checkpoint,
                    limits,
                    State {
                        entries: 0,
                        encoded_bytes: 0,
                    },
                )
                .as_slice(),
            )
            .map_err(|error| database_error("initialize metadata", error))?;
        }
        write
            .commit()
            .map_err(|error| database_error("commit initialization", error))?;
        Ok(Self {
            db,
            checkpoint,
            limits,
            state: State {
                entries: 0,
                encoded_bytes: 0,
            },
        })
    }

    /// Opens an existing database only when its binding and persisted limits match exactly.
    /// Open reads the bounded metadata row and table length; it does not scan all coin rows.
    pub fn open(
        path: &Path,
        checkpoint: PrevoutCheckpoint,
        limits: SwiftPrevoutLimits,
    ) -> Result<Self, SwiftPrevoutError> {
        validate_limits(limits)?;
        let db = database_builder(limits)
            .open(path)
            .map_err(|error| database_error("open", error))?;
        let read = db
            .begin_read()
            .map_err(|error| database_error("begin open transaction", error))?;
        let state_bytes = {
            let meta = read
                .open_table(META)
                .map_err(|_| SwiftPrevoutError::CorruptMetadata)?;
            let value = meta
                .get(META_KEY)
                .map_err(|error| database_error("read metadata", error))?
                .ok_or(SwiftPrevoutError::CorruptMetadata)?;
            if value.value().len() != META_BYTES {
                return Err(SwiftPrevoutError::CorruptMetadata);
            }
            value.value().to_vec()
        };
        let (stored_checkpoint, stored_limits, state) = decode_state(&state_bytes)?;
        if stored_checkpoint != checkpoint
            || persisted_limits(stored_limits) != persisted_limits(limits)
        {
            return Err(SwiftPrevoutError::BindingMismatch);
        }
        if state.entries > limits.max_entries
            || state.encoded_bytes > limits.max_total_encoded_bytes
        {
            return Err(SwiftPrevoutError::CorruptMetadata);
        }
        let table = read
            .open_table(COINS)
            .map_err(|_| SwiftPrevoutError::CorruptMetadata)?;
        let actual_entries = table
            .len()
            .map_err(|error| database_error("read coin table length", error))?;
        if actual_entries != state.entries {
            return Err(SwiftPrevoutError::CorruptMetadata);
        }
        drop(table);
        drop(read);
        Ok(Self {
            db,
            checkpoint,
            limits,
            state,
        })
    }

    /// The exact network/checkpoint persisted for this database.
    #[must_use]
    pub const fn checkpoint(&self) -> PrevoutCheckpoint {
        self.checkpoint
    }

    /// Number of distinct records currently stored, from bounded metadata.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.state.entries
    }

    /// True when the table has no coin records.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.state.entries == 0
    }

    /// Encoded key/value bytes currently charged against the store's total-byte cap.
    #[must_use]
    pub const fn encoded_bytes(&self) -> u64 {
        self.state.encoded_bytes
    }

    /// Reads and strictly validates one stored full coin record.
    pub fn get(&self, outpoint: &OutPoint) -> Result<Option<Coin>, SwiftPrevoutError> {
        let key = crate::utxo_snapshot::outpoint_key(outpoint);
        let read = self
            .db
            .begin_read()
            .map_err(|error| database_error("begin coin lookup", error))?;
        let table = read
            .open_table(COINS)
            .map_err(|error| database_error("open coin table for lookup", error))?;
        let value = table
            .get(&key[..])
            .map_err(|error| database_error("lookup coin", error))?;
        value
            .map(|value| decode_record(&key, value.value(), self.limits, self.checkpoint.height))
            .transpose()
    }

    /// Inserts a bounded batch atomically. Re-inserting identical coin data is idempotent;
    /// reusing an outpoint with different coin data is rejected without committing the batch.
    pub fn insert_batch(&mut self, records: &[(OutPoint, Coin)]) -> Result<(), SwiftPrevoutError> {
        if records.len() > self.limits.max_batch_entries {
            return Err(SwiftPrevoutError::BatchTooLarge);
        }
        if records.is_empty() {
            return Ok(());
        }

        // Bound and validate the batch before opening a write transaction.
        let mut encoded =
            std::collections::HashMap::<[u8; 36], (&Coin, Vec<u8>)>::with_capacity(records.len());
        for (outpoint, coin) in records {
            if coin.height > self.checkpoint.height {
                return Err(SwiftPrevoutError::CoinAfterCheckpoint);
            }
            let key = crate::utxo_snapshot::outpoint_key(outpoint);
            let value = encode_record(&key, coin, self.limits)?;
            if let Some((prior_coin, _)) = encoded.get(&key) {
                if *prior_coin != coin {
                    return Err(SwiftPrevoutError::DuplicateCoinMismatch);
                }
            } else {
                encoded.insert(key, (coin, value));
            }
        }

        let write = self
            .db
            .begin_write()
            .map_err(|error| database_error("begin insert transaction", error))?;
        let mut state = self.state;
        {
            let meta = write
                .open_table(META)
                .map_err(|error| database_error("open metadata for consistency check", error))?;
            let stored = meta
                .get(META_KEY)
                .map_err(|error| database_error("read metadata for consistency check", error))?
                .ok_or(SwiftPrevoutError::CorruptMetadata)?;
            if stored.value().len() != META_BYTES {
                return Err(SwiftPrevoutError::CorruptMetadata);
            }
            let (stored_checkpoint, stored_limits, stored_state) = decode_state(stored.value())?;
            if stored_checkpoint != self.checkpoint
                || persisted_limits(stored_limits) != persisted_limits(self.limits)
                || stored_state.entries != self.state.entries
                || stored_state.encoded_bytes != self.state.encoded_bytes
            {
                return Err(SwiftPrevoutError::CorruptMetadata);
            }
            drop(stored);
            drop(meta);
            let mut table = write
                .open_table(COINS)
                .map_err(|error| database_error("open coin table for insert", error))?;
            if table
                .len()
                .map_err(|error| database_error("read coin table length", error))?
                != state.entries
            {
                return Err(SwiftPrevoutError::CorruptMetadata);
            }
            for (key, (coin, value)) in encoded {
                if let Some(existing) = table
                    .get(&key[..])
                    .map_err(|error| database_error("check existing coin", error))?
                {
                    let stored_coin =
                        decode_record(&key, existing.value(), self.limits, self.checkpoint.height)?;
                    if stored_coin != *coin {
                        return Err(SwiftPrevoutError::DuplicateCoinMismatch);
                    }
                    continue;
                }
                let size = u64::try_from(key.len() + value.len())
                    .map_err(|_| SwiftPrevoutError::CounterOverflow)?;
                let new_count = state
                    .entries
                    .checked_add(1)
                    .ok_or(SwiftPrevoutError::CounterOverflow)?;
                let new_bytes = state
                    .encoded_bytes
                    .checked_add(size)
                    .ok_or(SwiftPrevoutError::CounterOverflow)?;
                if new_count > self.limits.max_entries {
                    return Err(SwiftPrevoutError::EntryLimitExceeded);
                }
                if new_bytes > self.limits.max_total_encoded_bytes {
                    return Err(SwiftPrevoutError::EncodedBytesLimitExceeded);
                }
                table
                    .insert(&key[..], value.as_slice())
                    .map_err(|error| database_error("insert coin", error))?;
                state = State {
                    entries: new_count,
                    encoded_bytes: new_bytes,
                };
            }
        }
        {
            let mut meta = write
                .open_table(META)
                .map_err(|error| database_error("open metadata for insert", error))?;
            meta.insert(
                META_KEY,
                encode_state(self.checkpoint, self.limits, state).as_slice(),
            )
            .map_err(|error| database_error("update metadata", error))?;
        }
        write
            .commit()
            .map_err(|error| database_error("commit insert transaction", error))?;
        self.state = state;
        Ok(())
    }
}

fn validate_limits(limits: SwiftPrevoutLimits) -> Result<(), SwiftPrevoutError> {
    if limits.max_entries == 0
        || limits.max_total_encoded_bytes == 0
        || limits.max_batch_entries == 0
        || u64::try_from(limits.max_batch_entries).map_or(true, |batch| batch > limits.max_entries)
        || limits.max_record_bytes < ROW_PREFIX_BYTES + CHECKSUM_BYTES
        || limits.max_record_bytes > MAX_RECORD_BYTES
        || limits.max_script_bytes == 0
        || limits.max_script_bytes > MAX_SCRIPT_BYTES
        || limits.cache_bytes == 0
        || limits.cache_bytes > MAX_CACHE_BYTES
    {
        return Err(SwiftPrevoutError::InvalidLimits);
    }
    Ok(())
}

fn database_builder(limits: SwiftPrevoutLimits) -> redb::Builder {
    let mut builder = redb::Database::builder();
    builder.set_cache_size(limits.cache_bytes);
    builder
}

fn database_error(operation: &'static str, error: impl std::fmt::Display) -> SwiftPrevoutError {
    SwiftPrevoutError::Database {
        operation,
        message: error.to_string(),
    }
}

fn encode_record(
    key: &[u8; 36],
    coin: &Coin,
    limits: SwiftPrevoutLimits,
) -> Result<Vec<u8>, SwiftPrevoutError> {
    if !(0..=crate::check::MAX_MONEY).contains(&coin.out.value)
        || coin.out.script_pubkey.len() > limits.max_script_bytes
    {
        return Err(SwiftPrevoutError::InvalidCoin);
    }
    let encoded_coin = crate::coinsdb::encode_coin(coin, CoinFormat::Compact);
    let record_len = ROW_PREFIX_BYTES
        .checked_add(encoded_coin.len())
        .and_then(|len| len.checked_add(CHECKSUM_BYTES))
        .ok_or(SwiftPrevoutError::CounterOverflow)?;
    if record_len > limits.max_record_bytes || encoded_coin.len() > u32::MAX as usize {
        return Err(SwiftPrevoutError::RecordTooLarge);
    }
    let mut record = Vec::with_capacity(record_len);
    record.push(ROW_VERSION);
    record.extend_from_slice(&(encoded_coin.len() as u32).to_le_bytes());
    record.extend_from_slice(&encoded_coin);
    let checksum = row_checksum(key, &record);
    record.extend_from_slice(&checksum);
    Ok(record)
}

fn decode_record(
    key: &[u8; 36],
    record: &[u8],
    limits: SwiftPrevoutLimits,
    checkpoint_height: u32,
) -> Result<Coin, SwiftPrevoutError> {
    if record.len() > limits.max_record_bytes || record.len() < ROW_PREFIX_BYTES + CHECKSUM_BYTES {
        return Err(SwiftPrevoutError::MalformedRecord);
    }
    if record[0] != ROW_VERSION {
        return Err(SwiftPrevoutError::MalformedRecord);
    }
    let encoded_len = u32::from_le_bytes(
        record[1..5]
            .try_into()
            .map_err(|_| SwiftPrevoutError::MalformedRecord)?,
    ) as usize;
    let body_end = ROW_PREFIX_BYTES
        .checked_add(encoded_len)
        .ok_or(SwiftPrevoutError::MalformedRecord)?;
    let expected_len = body_end
        .checked_add(CHECKSUM_BYTES)
        .ok_or(SwiftPrevoutError::MalformedRecord)?;
    if expected_len != record.len() {
        return Err(SwiftPrevoutError::MalformedRecord);
    }
    let expected_checksum = row_checksum(key, &record[..body_end]);
    if !constant_time_equal(&expected_checksum, &record[body_end..]) {
        return Err(SwiftPrevoutError::ChecksumMismatch);
    }
    let mut cursor = &record[ROW_PREFIX_BYTES..body_end];
    let coin = crate::coinsdb::decode_coin_compact(&mut cursor)
        .ok_or(SwiftPrevoutError::MalformedRecord)?;
    if !cursor.is_empty()
        || !(0..=crate::check::MAX_MONEY).contains(&coin.out.value)
        || coin.out.script_pubkey.len() > limits.max_script_bytes
        || coin.height > checkpoint_height
    {
        return Err(SwiftPrevoutError::MalformedRecord);
    }
    Ok(coin)
}

fn row_checksum(key: &[u8; 36], body: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(ROW_DOMAIN);
    hash.update(key);
    hash.update(body);
    hash.finalize().into()
}

fn constant_time_equal(expected: &[u8; 32], actual: &[u8]) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in expected.iter().zip(actual) {
        diff |= left ^ right;
    }
    diff == 0
}

fn encode_state(
    checkpoint: PrevoutCheckpoint,
    limits: SwiftPrevoutLimits,
    state: State,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(META_BYTES);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    bytes.push(network_byte(checkpoint.network));
    bytes.extend_from_slice(&checkpoint.height.to_le_bytes());
    bytes.extend_from_slice(checkpoint.hash.as_bytes());
    bytes.extend_from_slice(&limits.max_entries.to_le_bytes());
    bytes.extend_from_slice(&limits.max_total_encoded_bytes.to_le_bytes());
    bytes.extend_from_slice(&(limits.max_record_bytes as u32).to_le_bytes());
    bytes.extend_from_slice(&(limits.max_script_bytes as u32).to_le_bytes());
    bytes.extend_from_slice(&state.entries.to_le_bytes());
    bytes.extend_from_slice(&state.encoded_bytes.to_le_bytes());
    let checksum = metadata_checksum(&bytes);
    bytes.extend_from_slice(&checksum);
    bytes
}

fn decode_state(
    bytes: &[u8],
) -> Result<(PrevoutCheckpoint, SwiftPrevoutLimits, State), SwiftPrevoutError> {
    if bytes.len() != META_BYTES || &bytes[..8] != MAGIC {
        return Err(SwiftPrevoutError::CorruptMetadata);
    }
    let checksum = metadata_checksum(&bytes[..META_BODY_BYTES]);
    if !constant_time_equal(&checksum, &bytes[META_BODY_BYTES..]) {
        return Err(SwiftPrevoutError::CorruptMetadata);
    }
    if u32::from_le_bytes(bytes[8..12].try_into().unwrap_or_default()) != VERSION {
        return Err(SwiftPrevoutError::CorruptMetadata);
    }
    let network = network_from_byte(bytes[12]).ok_or(SwiftPrevoutError::CorruptMetadata)?;
    let checkpoint = PrevoutCheckpoint {
        network,
        height: u32::from_le_bytes(bytes[13..17].try_into().unwrap_or_default()),
        hash: BlockHash::from_bytes(bytes[17..49].try_into().unwrap_or_default()),
    };
    let limits = SwiftPrevoutLimits {
        max_entries: u64::from_le_bytes(bytes[49..57].try_into().unwrap_or_default()),
        max_total_encoded_bytes: u64::from_le_bytes(bytes[57..65].try_into().unwrap_or_default()),
        max_batch_entries: 1,
        max_record_bytes: u32::from_le_bytes(bytes[65..69].try_into().unwrap_or_default()) as usize,
        max_script_bytes: u32::from_le_bytes(bytes[69..73].try_into().unwrap_or_default()) as usize,
        cache_bytes: 1,
    };
    let state = State {
        entries: u64::from_le_bytes(bytes[73..81].try_into().unwrap_or_default()),
        encoded_bytes: u64::from_le_bytes(bytes[81..89].try_into().unwrap_or_default()),
    };
    Ok((checkpoint, limits, state))
}

fn metadata_checksum(body: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(META_DOMAIN);
    hash.update(body);
    hash.finalize().into()
}

fn persisted_limits(limits: SwiftPrevoutLimits) -> (u64, u64, usize, usize) {
    (
        limits.max_entries,
        limits.max_total_encoded_bytes,
        limits.max_record_bytes,
        limits.max_script_bytes,
    )
}

fn network_byte(network: Network) -> u8 {
    match network {
        Network::Mainnet => 0,
        Network::Testnet4 => 1,
        Network::Signet => 2,
        Network::Regtest => 3,
    }
}

fn network_from_byte(byte: u8) -> Option<Network> {
    match byte {
        0 => Some(Network::Mainnet),
        1 => Some(Network::Testnet4),
        2 => Some(Network::Signet),
        3 => Some(Network::Regtest),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::hash::Txid;
    use crate::transaction::{Script, TxOut};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir(std::path::PathBuf);

    impl TestDir {
        fn new() -> Self {
            let base = std::env::temp_dir();
            loop {
                let sequence = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
                let path = base.join(format!(
                    "avila-swift-prevout-test-{}-{sequence}",
                    std::process::id()
                ));
                match std::fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("create test directory: {error}"),
                }
            }
        }

        fn db_path(&self) -> std::path::PathBuf {
            self.0.join("prevouts.redb")
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn checkpoint() -> PrevoutCheckpoint {
        PrevoutCheckpoint {
            network: Network::Regtest,
            height: 50,
            hash: BlockHash::from_bytes([0x44; 32]),
        }
    }

    fn limits() -> SwiftPrevoutLimits {
        SwiftPrevoutLimits {
            max_entries: 16,
            max_total_encoded_bytes: 16 * 1024,
            max_batch_entries: 8,
            max_record_bytes: 12_000,
            max_script_bytes: 10_000,
            cache_bytes: 4 * 1024 * 1024,
        }
    }

    fn item(seed: u8, value: i64, script: &[u8]) -> (OutPoint, Coin) {
        (
            OutPoint {
                txid: Txid::from_bytes([seed; 32]),
                vout: u32::from(seed),
            },
            Coin {
                out: TxOut {
                    value,
                    script_pubkey: Script::new(script.to_vec()),
                },
                height: u32::from(seed),
                coinbase: seed.is_multiple_of(2),
            },
        )
    }

    #[test]
    fn creates_inserts_reopens_and_binds_checkpoint() {
        let temp = TestDir::new();
        let point = item(1, 500, &[0x51]);
        let mut store = SwiftPrevoutStore::create(&temp.db_path(), checkpoint(), limits()).unwrap();
        store.insert_batch(std::slice::from_ref(&point)).unwrap();
        assert_eq!(store.get(&point.0).unwrap(), Some(point.1.clone()));
        assert_eq!(store.len(), 1);
        let stored_bytes = store.encoded_bytes();
        assert!(matches!(
            SwiftPrevoutStore::create(&temp.db_path(), checkpoint(), limits()),
            Err(SwiftPrevoutError::AlreadyExists)
        ));
        drop(store);

        let reopened = SwiftPrevoutStore::open(&temp.db_path(), checkpoint(), limits()).unwrap();
        assert_eq!(reopened.get(&point.0).unwrap(), Some(point.1));
        assert_eq!(reopened.encoded_bytes(), stored_bytes);
        drop(reopened);

        let wrong = PrevoutCheckpoint {
            height: 51,
            ..checkpoint()
        };
        assert!(matches!(
            SwiftPrevoutStore::open(&temp.db_path(), wrong, limits()),
            Err(SwiftPrevoutError::BindingMismatch)
        ));
        let wrong_hash = PrevoutCheckpoint {
            hash: BlockHash::from_bytes([0x45; 32]),
            ..checkpoint()
        };
        assert!(matches!(
            SwiftPrevoutStore::open(&temp.db_path(), wrong_hash, limits()),
            Err(SwiftPrevoutError::BindingMismatch)
        ));
        let wrong_network = PrevoutCheckpoint {
            network: Network::Mainnet,
            ..checkpoint()
        };
        assert!(matches!(
            SwiftPrevoutStore::open(&temp.db_path(), wrong_network, limits()),
            Err(SwiftPrevoutError::BindingMismatch)
        ));
    }

    #[test]
    fn duplicate_identical_is_idempotent_and_conflicting_coin_is_rejected() {
        let temp = TestDir::new();
        let (outpoint, coin) = item(2, 700, &[0x51, 0x51]);
        let mut store = SwiftPrevoutStore::create(&temp.db_path(), checkpoint(), limits()).unwrap();
        store
            .insert_batch(&[(outpoint, coin.clone()), (outpoint, coin.clone())])
            .unwrap();
        let count = store.len();
        let mut changed = coin.clone();
        changed.out.value += 1;
        assert!(matches!(
            store.insert_batch(&[(outpoint, changed)]),
            Err(SwiftPrevoutError::DuplicateCoinMismatch)
        ));
        assert_eq!(store.len(), count);
        assert_eq!(store.get(&outpoint).unwrap(), Some(coin));
    }

    #[test]
    fn framed_records_reject_truncation_and_corruption() {
        let (outpoint, coin) = item(3, 900, &[0x00, 0x14, 7]);
        let lim = limits();
        let key = crate::utxo_snapshot::outpoint_key(&outpoint);
        let record = encode_record(&key, &coin, lim).unwrap();
        assert_eq!(
            decode_record(&key, &record, lim, checkpoint().height).unwrap(),
            coin
        );
        assert!(matches!(
            decode_record(&key, &record[..record.len() - 1], lim, checkpoint().height),
            Err(SwiftPrevoutError::MalformedRecord)
        ));
        let mut damaged = record;
        damaged[5] ^= 1;
        assert!(matches!(
            decode_record(&key, &damaged, lim, checkpoint().height),
            Err(SwiftPrevoutError::ChecksumMismatch)
        ));
        let mut future_coin = coin;
        future_coin.height = checkpoint().height + 1;
        let future_record = encode_record(&key, &future_coin, lim).unwrap();
        assert!(matches!(
            decode_record(&key, &future_record, lim, checkpoint().height),
            Err(SwiftPrevoutError::MalformedRecord)
        ));
    }

    #[test]
    fn entry_batch_and_script_bounds_are_enforced_atomically() {
        let temp = TestDir::new();
        let mut lim = limits();
        lim.max_entries = 2;
        lim.max_batch_entries = 2;
        let a = item(4, 100, &[0x51]);
        let b = item(5, 200, &[0x51]);
        let c = item(8, 300, &[0x51]);
        let mut store = SwiftPrevoutStore::create(&temp.db_path(), checkpoint(), lim).unwrap();
        store.insert_batch(std::slice::from_ref(&a)).unwrap();
        assert!(matches!(
            store.insert_batch(&[b.clone(), c.clone()]),
            Err(SwiftPrevoutError::EntryLimitExceeded)
        ));
        assert_eq!(store.len(), 1);
        assert_eq!(store.get(&a.0).unwrap(), Some(a.1.clone()));
        assert_eq!(store.get(&b.0).unwrap(), None);
        assert_eq!(store.get(&c.0).unwrap(), None);
        assert!(matches!(
            store.insert_batch(&[b.clone(), c.clone(), c.clone()]),
            Err(SwiftPrevoutError::BatchTooLarge)
        ));
        let mut oversized_script = Vec::new();
        oversized_script.resize(lim.max_script_bytes + 1, 0x51);
        assert!(matches!(
            store.insert_batch(&[(
                c.0,
                Coin {
                    out: TxOut {
                        value: c.1.out.value,
                        script_pubkey: Script::new(oversized_script),
                    },
                    ..c.1.clone()
                }
            )]),
            Err(SwiftPrevoutError::InvalidCoin)
        ));
        let mut out_of_range = c.1.clone();
        out_of_range.out.value = crate::check::MAX_MONEY + 1;
        assert!(matches!(
            store.insert_batch(&[(c.0, out_of_range)]),
            Err(SwiftPrevoutError::InvalidCoin)
        ));
        assert_eq!(store.len(), 1);
        assert_eq!(store.get(&a.0).unwrap(), Some(a.1));
    }

    #[test]
    fn total_encoded_byte_cap_and_open_metadata_are_checked() {
        let state_bytes = encode_state(
            checkpoint(),
            limits(),
            State {
                entries: 0,
                encoded_bytes: 0,
            },
        );
        assert_eq!(decode_state(&state_bytes).unwrap().2.entries, 0);
        let mut damaged_metadata = state_bytes;
        damaged_metadata[META_BODY_BYTES - 1] ^= 1;
        assert!(matches!(
            decode_state(&damaged_metadata),
            Err(SwiftPrevoutError::CorruptMetadata)
        ));

        let temp = TestDir::new();
        let a = item(6, 123, &[0x51]);
        let mut lim = limits();
        lim.max_total_encoded_bytes = 1;
        let store = SwiftPrevoutStore::create(&temp.db_path(), checkpoint(), lim).unwrap();
        drop(store);
        let mut store = SwiftPrevoutStore::open(&temp.db_path(), checkpoint(), lim).unwrap();
        assert!(matches!(
            store.insert_batch(&[a]),
            Err(SwiftPrevoutError::EncodedBytesLimitExceeded)
        ));
        assert_eq!(store.len(), 0);
        drop(store);
        let wrong_limits = SwiftPrevoutLimits {
            max_total_encoded_bytes: 2,
            ..lim
        };
        assert!(matches!(
            SwiftPrevoutStore::open(&temp.db_path(), checkpoint(), wrong_limits),
            Err(SwiftPrevoutError::BindingMismatch)
        ));
    }

    #[test]
    fn rejects_coin_created_after_checkpoint() {
        let temp = TestDir::new();
        let mut store = SwiftPrevoutStore::create(&temp.db_path(), checkpoint(), limits()).unwrap();
        let (outpoint, mut coin) = item(7, 1000, &[0x51]);
        coin.height = checkpoint().height + 1;
        assert!(matches!(
            store.insert_batch(&[(outpoint, coin)]),
            Err(SwiftPrevoutError::CoinAfterCheckpoint)
        ));
        assert!(store.is_empty());
    }
}
