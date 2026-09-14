//! Transactions: inputs, outputs, and Bitcoin's legacy and BIP144 witness serialization
//! formats.
//!
//! Decoding reproduces Bitcoin Core's `UnserializeTransaction` (`primitives/transaction.h`)
//! with `allow_witness = true` exactly, including its dummy-vin/flags byte dance and its
//! "Superfluous witness record" / "Unknown transaction optional data" error conditions.
//! Encoding reproduces `SerializeTransaction` with the same parameter: the legacy format when
//! no input carries a witness, the BIP144 extended format otherwise.

use std::fmt;

use crate::encode::{DecodeError, Decoder, compact_size_len, write_compact_size, write_var_bytes};
use crate::hash::{Txid, Wtxid, sha256d};
use crate::hex;

/// A raw, unparsed Bitcoin script (`scriptSig` or `scriptPubKey`).
///
/// This crate does not interpret script opcodes; a `Script` is simply the opaque byte string
/// carried in a transaction input or output.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct Script(Vec<u8>);

impl Script {
    /// Wraps raw script bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the script's raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the script, returning its raw bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Returns the script's length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the script is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Script {
    /// Renders the script as `Script(<hex>)` rather than the default `Vec<u8>` debug form, so
    /// script bytes read the same way they would in a hex dump or Core's own tooling.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Script({})", hex::encode(&self.0))
    }
}

/// A reference to a specific output of a specific previous transaction (Core's `COutPoint`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct OutPoint {
    /// The id of the transaction holding the referenced output.
    pub txid: Txid,
    /// The index of the referenced output within that transaction.
    pub vout: u32,
}

impl OutPoint {
    /// The null outpoint used by coinbase transactions' sole input: an all-zero txid and
    /// `vout = u32::MAX` (Core's default-constructed `COutPoint`).
    pub const NULL: OutPoint = OutPoint {
        txid: Txid::ZERO,
        vout: u32::MAX,
    };

    /// Returns `true` if this is the null outpoint (Core's `COutPoint::IsNull`).
    #[must_use]
    pub fn is_null(&self) -> bool {
        self.txid.is_zero() && self.vout == u32::MAX
    }
}

/// A transaction input's segregated witness data: a stack of byte strings (Core's
/// `CScriptWitness::stack`).
#[derive(Clone, PartialEq, Eq, Hash, Debug, Default)]
pub struct Witness(Vec<Vec<u8>>);

impl Witness {
    /// The empty witness — Core's `static const CScriptWitness emptyWitness`.
    pub const EMPTY: Self = Self(Vec::new());

    /// Wraps a witness stack.
    #[must_use]
    pub fn new(items: Vec<Vec<u8>>) -> Self {
        Self(items)
    }

    /// Returns the witness stack items.
    #[must_use]
    pub fn items(&self) -> &[Vec<u8>] {
        &self.0
    }

    /// Returns `true` if the witness stack has no items.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of items on the witness stack.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// A transaction input (Core's `CTxIn`).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct TxIn {
    /// The output this input spends.
    pub previous_output: OutPoint,
    /// The unlocking script (legacy signature data).
    pub script_sig: Script,
    /// The sequence number (BIP68 relative locktime / RBF signaling).
    pub sequence: u32,
    /// The BIP141/BIP144 segregated witness data. Not covered by the legacy (non-witness)
    /// serialization or `txid`.
    pub witness: Witness,
}

/// A transaction output (Core's `CTxOut`).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct TxOut {
    /// The output value in satoshis. Signed, like Core's `CAmount`, though a valid output's
    /// value is never negative.
    pub value: i64,
    /// The locking script.
    pub script_pubkey: Script,
}

/// A Bitcoin transaction (Core's `CTransaction`).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Transaction {
    /// The transaction version. Core's `CTransaction`/`CMutableTransaction` declare this field
    /// as `uint32_t` in `primitives/transaction.h` (Bitcoin Core v31.1) -- unlike
    /// [`crate::header::BlockHeader::version`], which genuinely is `int32_t`. This type follows
    /// Core rather than an earlier draft of this crate's specification, which had incorrectly
    /// documented this field as `i32`; a version with the high bit set must compare as a large
    /// positive value, not a negative one, to match Core's semantics in any future numeric
    /// comparison against this field.
    pub version: u32,
    /// The transaction's inputs.
    pub inputs: Vec<TxIn>,
    /// The transaction's outputs.
    pub outputs: Vec<TxOut>,
    /// The lock time (block height or Unix timestamp below/above `500_000_000`).
    pub lock_time: u32,
}

impl Transaction {
    /// The smallest possible serialized size of any transaction, in bytes: a 4-byte version, a
    /// zero-length `vin` (1 byte), a zero-length `vout` (1 byte), and a 4-byte lock time (Core's
    /// `MIN_SERIALIZABLE_TRANSACTION_WEIGHT` divided by `WITNESS_SCALE_FACTOR`,
    /// `consensus/consensus.h`).
    pub const MIN_SERIALIZED_SIZE: usize = 10;

    /// Returns `true` if any input carries a non-empty witness stack (Core's `HasWitness`).
    #[must_use]
    pub fn has_witness(&self) -> bool {
        self.inputs.iter().any(|input| !input.witness.is_empty())
    }

    /// Returns `true` if this is a coinbase transaction: exactly one input, spending the null
    /// outpoint (Core's `IsCoinBase`).
    #[must_use]
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].previous_output.is_null()
    }

    /// Appends this transaction's legacy (pre-BIP144, no witness data) serialization to `out`.
    pub fn write_without_witness(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.version.to_le_bytes());
        write_compact_size(out, self.inputs.len() as u64);
        for input in &self.inputs {
            Self::write_txin_no_witness(out, input);
        }
        write_compact_size(out, self.outputs.len() as u64);
        for output in &self.outputs {
            Self::write_txout(out, output);
        }
        out.extend_from_slice(&self.lock_time.to_le_bytes());
    }

    /// Appends this transaction's serialization to `out`, using the BIP144 extended format iff
    /// [`Transaction::has_witness`], otherwise the legacy format (Core's `SerializeTransaction`
    /// with `allow_witness = true`).
    pub fn write_with_witness(&self, out: &mut Vec<u8>) {
        if !self.has_witness() {
            self.write_without_witness(out);
            return;
        }
        out.extend_from_slice(&self.version.to_le_bytes());
        out.push(0x00); // marker
        out.push(0x01); // flags = 1 (witness present)
        write_compact_size(out, self.inputs.len() as u64);
        for input in &self.inputs {
            Self::write_txin_no_witness(out, input);
        }
        write_compact_size(out, self.outputs.len() as u64);
        for output in &self.outputs {
            Self::write_txout(out, output);
        }
        for input in &self.inputs {
            write_compact_size(out, input.witness.len() as u64);
            for item in input.witness.items() {
                write_var_bytes(out, item);
            }
        }
        out.extend_from_slice(&self.lock_time.to_le_bytes());
    }

    /// Serializes this transaction, including witness data (equivalent to
    /// [`Transaction::write_with_witness`] into a fresh buffer).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.size_with_witness());
        self.write_with_witness(&mut out);
        out
    }

    /// Computes the serialized size of the legacy (non-witness) form, without allocating.
    #[must_use]
    pub fn size_without_witness(&self) -> usize {
        let mut size = 4 + compact_size_len(self.inputs.len() as u64);
        for input in &self.inputs {
            size +=
                32 + 4 + compact_size_len(input.script_sig.len() as u64) + input.script_sig.len();
            size += 4;
        }
        size += compact_size_len(self.outputs.len() as u64);
        for output in &self.outputs {
            size += 8
                + compact_size_len(output.script_pubkey.len() as u64)
                + output.script_pubkey.len();
        }
        size + 4
    }

    /// Computes the serialized size including witness data (BIP141/BIP144 "total size"),
    /// without allocating.
    #[must_use]
    pub fn size_with_witness(&self) -> usize {
        if !self.has_witness() {
            return self.size_without_witness();
        }
        let mut size = self.size_without_witness() + 2; // marker + flags
        for input in &self.inputs {
            size += compact_size_len(input.witness.len() as u64);
            for item in input.witness.items() {
                size += compact_size_len(item.len() as u64) + item.len();
            }
        }
        size
    }

    /// Computes this transaction's weight: `3 * size_without_witness + size_with_witness`
    /// (BIP141).
    #[must_use]
    pub fn weight(&self) -> usize {
        3 * self.size_without_witness() + self.size_with_witness()
    }

    /// Computes this transaction's id: `sha256d` of its legacy (non-witness) serialization.
    #[must_use]
    pub fn txid(&self) -> Txid {
        let mut bytes = Vec::with_capacity(self.size_without_witness());
        self.write_without_witness(&mut bytes);
        Txid::from_bytes(sha256d(&bytes))
    }

    /// Computes this transaction's witness id: `sha256d` of its full (BIP144) serialization
    /// (identical to [`Transaction::txid`] when the transaction has no witness data).
    #[must_use]
    pub fn wtxid(&self) -> Wtxid {
        Wtxid::from_bytes(sha256d(&self.encode()))
    }

    /// Decodes a transaction from `decoder`, reproducing Core's `UnserializeTransaction` with
    /// `allow_witness = true` exactly.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEnd`] on truncated input,
    /// [`DecodeError::SuperfluousWitness`] if the witness flag is set but no input actually
    /// carries a non-empty witness, or [`DecodeError::UnknownTransactionFlags`] if flag bits
    /// this decoder does not understand remain set after consuming the witness flag.
    pub fn read(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let version = decoder.read_u32_le()?;
        let mut inputs = Self::read_vin(decoder)?;
        let mut flags = 0u8;
        let outputs = if inputs.is_empty() {
            // Might be an empty `vin`, or the 0x00 dummy marker of the extended format.
            flags = decoder.read_u8()?;
            if flags != 0 {
                inputs = Self::read_vin(decoder)?;
                Self::read_vout(decoder)?
            } else {
                Vec::new()
            }
        } else {
            Self::read_vout(decoder)?
        };
        if flags & 1 != 0 {
            flags ^= 1;
            for input in &mut inputs {
                input.witness = Self::read_witness(decoder)?;
            }
            if !inputs.iter().any(|input| !input.witness.is_empty()) {
                return Err(DecodeError::SuperfluousWitness);
            }
        }
        if flags != 0 {
            return Err(DecodeError::UnknownTransactionFlags(flags));
        }
        let lock_time = decoder.read_u32_le()?;
        Ok(Transaction {
            version,
            inputs,
            outputs,
            lock_time,
        })
    }

    /// Decodes a transaction from exactly `bytes`, requiring the whole input to be consumed.
    ///
    /// # Errors
    ///
    /// As [`Transaction::read`], plus [`DecodeError::TrailingBytes`] if bytes remain after a
    /// otherwise-successful decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let tx = Self::read(&mut decoder)?;
        decoder.finish()?;
        Ok(tx)
    }

    /// Appends one input's legacy fields (outpoint, `scriptSig`, sequence; no witness) to `out`.
    fn write_txin_no_witness(out: &mut Vec<u8>, input: &TxIn) {
        out.extend_from_slice(input.previous_output.txid.as_bytes());
        out.extend_from_slice(&input.previous_output.vout.to_le_bytes());
        write_var_bytes(out, input.script_sig.as_bytes());
        out.extend_from_slice(&input.sequence.to_le_bytes());
    }

    /// Appends one output's fields to `out`.
    fn write_txout(out: &mut Vec<u8>, output: &TxOut) {
        out.extend_from_slice(&output.value.to_le_bytes());
        write_var_bytes(out, output.script_pubkey.as_bytes());
    }

    /// Decodes a `vin` vector: a `CompactSize` count followed by that many [`TxIn`]s (with
    /// empty witnesses; witness data, if any, is layered on afterward by [`Transaction::read`]).
    fn read_vin(decoder: &mut Decoder<'_>) -> Result<Vec<TxIn>, DecodeError> {
        // A `TxIn` without witness data is at least 32 (txid) + 4 (vout) + 1 (empty scriptSig
        // CompactSize) + 4 (sequence) = 41 bytes on the wire, but each decoded `TxIn` also owns
        // a `script_sig` and a `witness` (each a heap-allocating `Vec`), so its true in-memory
        // size can exceed that wire minimum. Reserve by whichever is larger so the eager
        // `Vec::with_capacity` below can never allocate more bytes than the remaining input
        // could actually justify, even before a single `TxIn` is decoded.
        const MIN_TXIN_SIZE: usize = 41;
        let count = decoder.read_compact_size()?;
        let reserve = MIN_TXIN_SIZE.max(std::mem::size_of::<TxIn>());
        let mut inputs = Vec::with_capacity(decoder.bounded_capacity(count, reserve));
        for _ in 0..count {
            let txid = Txid::from_bytes(decoder.read_array::<32>()?);
            let vout = decoder.read_u32_le()?;
            let script_sig = Script::new(decoder.read_var_bytes()?);
            let sequence = decoder.read_u32_le()?;
            inputs.push(TxIn {
                previous_output: OutPoint { txid, vout },
                script_sig,
                sequence,
                witness: Witness::default(),
            });
        }
        Ok(inputs)
    }

    /// Decodes a `vout` vector: a `CompactSize` count followed by that many [`TxOut`]s.
    fn read_vout(decoder: &mut Decoder<'_>) -> Result<Vec<TxOut>, DecodeError> {
        // A `TxOut` is at least 8 (value) + 1 (empty scriptPubKey CompactSize) = 9 bytes on the
        // wire, but its `script_pubkey` is a heap-allocating `Vec`, so its true in-memory size
        // can exceed that wire minimum; reserve by whichever is larger (see `read_vin`).
        const MIN_TXOUT_SIZE: usize = 9;
        let count = decoder.read_compact_size()?;
        let reserve = MIN_TXOUT_SIZE.max(std::mem::size_of::<TxOut>());
        let mut outputs = Vec::with_capacity(decoder.bounded_capacity(count, reserve));
        for _ in 0..count {
            let value = decoder.read_i64_le()?;
            let script_pubkey = Script::new(decoder.read_var_bytes()?);
            outputs.push(TxOut {
                value,
                script_pubkey,
            });
        }
        Ok(outputs)
    }

    /// Decodes a single input's witness stack: a `CompactSize` count followed by that many
    /// length-prefixed byte strings.
    fn read_witness(decoder: &mut Decoder<'_>) -> Result<Witness, DecodeError> {
        // Each item is at least a 1-byte CompactSize (possibly declaring zero length) on the
        // wire, but each decoded item is an owned `Vec<u8>` -- 24 bytes on a 64-bit target, a
        // ~24x gap versus that 1-byte wire minimum. Reserve by whichever is larger (see
        // `read_vin`) so a declared count backed by too few bytes can never force a reservation
        // far beyond what the remaining input could contain.
        const MIN_ITEM_SIZE: usize = 1;
        let count = decoder.read_compact_size()?;
        let reserve = MIN_ITEM_SIZE.max(std::mem::size_of::<Vec<u8>>());
        let mut items = Vec::with_capacity(decoder.bounded_capacity(count, reserve));
        for _ in 0..count {
            items.push(decoder.read_var_bytes()?);
        }
        Ok(Witness::new(items))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // The genesis block's sole (coinbase) transaction, taken from the full genesis block hex
    // in the crate specification (everything after the 80-byte header and the `01` tx-count
    // byte).
    const GENESIS_COINBASE_HEX: &str = "01000000010000000000000000000000000000000000000000000000\
000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f323030392043686\
16e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73fffff\
fff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f\
6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";

    fn genesis_coinbase() -> Transaction {
        Transaction::decode(&hex::decode(GENESIS_COINBASE_HEX).unwrap()).unwrap()
    }

    // ---- Script -------------------------------------------------------------------------

    #[test]
    fn script_accessors() {
        let script = Script::new(vec![0x01, 0x02, 0x03]);
        assert_eq!(script.as_bytes(), &[0x01, 0x02, 0x03]);
        assert_eq!(script.len(), 3);
        assert!(!script.is_empty());
        assert_eq!(script.clone().into_bytes(), vec![0x01, 0x02, 0x03]);
        assert!(Script::default().is_empty());
        assert_eq!(Script::default().len(), 0);
    }

    #[test]
    fn script_debug_is_hex() {
        let script = Script::new(vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(format!("{script:?}"), "Script(deadbeef)");
    }

    // ---- OutPoint -------------------------------------------------------------------------

    #[test]
    fn outpoint_null() {
        assert!(OutPoint::NULL.is_null());
        assert_eq!(OutPoint::NULL.vout, u32::MAX);
        assert!(OutPoint::NULL.txid.is_zero());
    }

    #[test]
    fn outpoint_non_null_variants() {
        let zero_txid_nonzero_vout = OutPoint {
            txid: Txid::ZERO,
            vout: 0,
        };
        assert!(!zero_txid_nonzero_vout.is_null());
        let nonzero_txid_max_vout = OutPoint {
            txid: Txid::from_bytes([1u8; 32]),
            vout: u32::MAX,
        };
        assert!(!nonzero_txid_max_vout.is_null());
    }

    // ---- Witness -------------------------------------------------------------------------

    #[test]
    fn witness_accessors() {
        let witness = Witness::new(vec![vec![1, 2], vec![3]]);
        assert_eq!(witness.len(), 2);
        assert!(!witness.is_empty());
        assert_eq!(witness.items(), &[vec![1, 2], vec![3]]);
        assert!(Witness::default().is_empty());
        assert_eq!(Witness::default().len(), 0);
    }

    // ---- has_witness / is_coinbase ---------------------------------------------------------

    #[test]
    fn genesis_coinbase_is_coinbase_and_has_no_witness() {
        let tx = genesis_coinbase();
        assert!(tx.is_coinbase());
        assert!(!tx.has_witness());
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.version, 1);
        assert_eq!(tx.lock_time, 0);
    }

    #[test]
    fn is_coinbase_requires_exactly_one_null_input() {
        let mut tx = genesis_coinbase();
        // Two inputs, first null: not a coinbase (must be exactly one input).
        tx.inputs.push(tx.inputs[0].clone());
        assert_eq!(tx.inputs.len(), 2);
        assert!(!tx.is_coinbase());
    }

    #[test]
    fn is_coinbase_false_for_non_null_single_input() {
        let mut tx = genesis_coinbase();
        tx.inputs[0].previous_output.vout = 0;
        assert!(!tx.is_coinbase());
    }

    // ---- txid / wtxid / genesis merkle root -------------------------------------------------

    #[test]
    fn genesis_coinbase_txid_matches_genesis_merkle_root() {
        let tx = genesis_coinbase();
        assert_eq!(
            tx.txid().to_string(),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
        );
    }

    #[test]
    fn legacy_transaction_txid_equals_wtxid() {
        let tx = genesis_coinbase();
        assert!(!tx.has_witness());
        assert_eq!(tx.txid().as_bytes(), tx.wtxid().as_bytes());
    }

    // ---- weight / size ----------------------------------------------------------------------

    #[test]
    fn weight_formula_matches_definition() {
        let tx = genesis_coinbase();
        assert_eq!(
            tx.weight(),
            3 * tx.size_without_witness() + tx.size_with_witness()
        );
        // No witness: both sizes coincide, so weight = 4 * size.
        assert_eq!(tx.size_with_witness(), tx.size_without_witness());
        assert_eq!(tx.weight(), 4 * tx.size_without_witness());
    }

    #[test]
    fn size_without_witness_matches_actual_serialization_length() {
        let tx = genesis_coinbase();
        let mut out = Vec::new();
        tx.write_without_witness(&mut out);
        assert_eq!(out.len(), tx.size_without_witness());
    }

    #[test]
    fn size_with_witness_matches_encode_length() {
        let tx = genesis_coinbase();
        assert_eq!(tx.encode().len(), tx.size_with_witness());
    }

    // ---- empty-vin / flag-0 edge case --------------------------------------------------------

    #[test]
    fn empty_vin_flag_zero_decodes_to_empty_transaction() {
        // version=1, vin count=0, flags=0 (so vout is NOT read), lock_time=0.
        let mut bytes = hex::decode("0100000000").unwrap(); // version + vin count
        bytes.push(0x00); // flags
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // lock_time
        assert_eq!(bytes.len(), Transaction::MIN_SERIALIZED_SIZE);
        let tx = Transaction::decode(&bytes).unwrap();
        assert_eq!(tx.version, 1);
        assert!(tx.inputs.is_empty());
        assert!(tx.outputs.is_empty());
        assert_eq!(tx.lock_time, 0);
        // `txid` must be well-defined (not panic) even for this degenerate transaction.
        let _ = tx.txid();
        let _ = tx.wtxid();
        assert_eq!(tx.txid().as_bytes(), tx.wtxid().as_bytes());
    }

    #[test]
    fn empty_vin_flag_zero_round_trips() {
        // version(4) + vin count(1=0) + flags(1=0) + lock_time(4) = 10 bytes.
        let mut expected = Vec::new();
        expected.extend_from_slice(&1i32.to_le_bytes());
        expected.push(0x00); // vin count
        expected.push(0x00); // flags
        expected.extend_from_slice(&0u32.to_le_bytes());
        let tx = Transaction::decode(&expected).unwrap();
        // Since the decoded transaction has no witness data, `encode` must reproduce the
        // legacy serialization byte-for-byte (not re-introduce a marker/flags pair).
        assert_eq!(tx.encode(), expected);
    }

    // ---- superfluous witness / unknown flags ------------------------------------------------

    #[test]
    fn superfluous_witness_with_zero_inputs() {
        // version=1, vin=0 (dummy), flags=01 (extended), vin=0 (still empty), vout=0.
        // flags & 1 triggers a witness-stack read for each of the 0 inputs, so no witness item
        // is ever read, and the "no input has a non-empty witness" check fires immediately.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1i32.to_le_bytes());
        bytes.push(0x00); // vin count (dummy)
        bytes.push(0x01); // flags
        bytes.push(0x00); // vin count (real, still empty)
        bytes.push(0x00); // vout count
        assert_eq!(
            Transaction::decode(&bytes),
            Err(DecodeError::SuperfluousWitness)
        );
    }

    #[test]
    fn superfluous_witness_with_nonempty_vin_but_empty_witness_stacks() {
        // One input, flags=01, but the witness stack decoded for that one input is empty.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1i32.to_le_bytes());
        bytes.push(0x00); // vin count (dummy, triggers flags read)
        bytes.push(0x01); // flags
        bytes.push(0x01); // vin count (real): 1 input
        bytes.extend_from_slice(&[0xaa; 32]); // txid
        bytes.extend_from_slice(&0u32.to_le_bytes()); // vout
        bytes.push(0x00); // empty scriptSig
        bytes.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
        bytes.push(0x00); // vout count: 0 outputs
        bytes.push(0x00); // witness stack for the 1 input: 0 items
        bytes.extend_from_slice(&0u32.to_le_bytes()); // lock_time
        assert_eq!(
            Transaction::decode(&bytes),
            Err(DecodeError::SuperfluousWitness)
        );
    }

    #[test]
    fn unknown_transaction_flags_2() {
        // vin=0 (dummy), flags=02 (unknown; not the witness bit), vin=0, vout=0.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1i32.to_le_bytes());
        bytes.push(0x00);
        bytes.push(0x02); // flags
        bytes.push(0x00); // vin
        bytes.push(0x00); // vout
        assert_eq!(
            Transaction::decode(&bytes),
            Err(DecodeError::UnknownTransactionFlags(2))
        );
    }

    #[test]
    fn unknown_transaction_flags_3_with_valid_witness_reports_remaining_2() {
        // flags=03: bit 0 (witness) is consumed and satisfied by a genuine non-empty witness,
        // leaving bit 1 (value 2) unrecognized.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1i32.to_le_bytes());
        bytes.push(0x00); // vin count (dummy)
        bytes.push(0x03); // flags
        bytes.push(0x01); // vin count (real): 1 input
        bytes.extend_from_slice(&[0xbb; 32]); // txid
        bytes.extend_from_slice(&0u32.to_le_bytes()); // vout
        bytes.push(0x00); // empty scriptSig
        bytes.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
        bytes.push(0x00); // vout count: 0 outputs
        // Witness stack for the 1 input: 1 item, containing a single 0x42 byte.
        bytes.push(0x01); // 1 witness item
        bytes.push(0x01); // item length 1
        bytes.push(0x42); // item bytes
        bytes.extend_from_slice(&0u32.to_le_bytes()); // lock_time
        assert_eq!(
            Transaction::decode(&bytes),
            Err(DecodeError::UnknownTransactionFlags(2))
        );
    }

    // ---- segwit round trip -------------------------------------------------------------------

    fn build_segwit_transaction() -> Transaction {
        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_bytes([0x11; 32]),
                    vout: 1,
                },
                script_sig: Script::new(vec![]),
                sequence: 0xffff_ffff,
                witness: Witness::new(vec![vec![0xde, 0xad], vec![0x01, 0x02, 0x03]]),
            }],
            outputs: vec![TxOut {
                value: 5_000_000_000,
                script_pubkey: Script::new(vec![0x00, 0x14]),
            }],
            lock_time: 0,
        }
    }

    #[test]
    fn segwit_transaction_round_trips_and_txid_differs_from_wtxid() {
        let tx = build_segwit_transaction();
        assert!(tx.has_witness());
        let encoded = tx.encode();
        // BIP144 marker/flag bytes present.
        assert_eq!(encoded[4], 0x00);
        assert_eq!(encoded[5], 0x01);
        let decoded = Transaction::decode(&encoded).unwrap();
        assert_eq!(decoded, tx);
        assert_ne!(tx.txid().as_bytes(), tx.wtxid().as_bytes());
        assert_eq!(encoded.len(), tx.size_with_witness());

        // The legacy serialization must omit the witness entirely.
        let mut legacy = Vec::new();
        tx.write_without_witness(&mut legacy);
        assert_eq!(legacy.len(), tx.size_without_witness());
        assert!(legacy.len() < encoded.len());
    }

    #[test]
    fn weight_formula_holds_for_segwit_transaction() {
        let tx = build_segwit_transaction();
        assert_eq!(
            tx.weight(),
            3 * tx.size_without_witness() + tx.size_with_witness()
        );
        assert!(tx.size_with_witness() > tx.size_without_witness());
    }

    // ---- truncation never panics --------------------------------------------------------------

    #[test]
    fn truncation_at_every_offset_errors_without_panicking() {
        let tx = build_segwit_transaction();
        let encoded = tx.encode();
        for len in 0..encoded.len() {
            assert!(
                Transaction::decode(&encoded[..len]).is_err(),
                "prefix of length {len} unexpectedly decoded successfully"
            );
        }
        assert!(Transaction::decode(&encoded).is_ok());
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let tx = genesis_coinbase();
        let mut encoded = tx.encode();
        encoded.push(0xff);
        assert_eq!(
            Transaction::decode(&encoded),
            Err(DecodeError::TrailingBytes(1))
        );
    }

    // ---- oversized declared counts fail fast, without large allocation ------------------------

    #[test]
    fn oversized_declared_vin_count_fails_fast() {
        // A CompactSize declaring ~33 million inputs, backed by only a few real bytes: must
        // fail with `UnexpectedEnd` on the very first input, not attempt to allocate space for
        // (or iterate) tens of millions of `TxIn`s.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1i32.to_le_bytes());
        bytes.push(0xfe); // CompactSize u32 prefix
        bytes.extend_from_slice(&0x0200_0000u32.to_le_bytes()); // MAX_SIZE inputs declared
        bytes.extend_from_slice(&[0xaa, 0xbb]); // far too little payload
        let mut decoder = Decoder::new(&bytes);
        let start = std::time::Instant::now();
        let result = Transaction::read(&mut decoder);
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
        assert!(matches!(result, Err(DecodeError::UnexpectedEnd { .. })));
    }

    // ---- eager reservation bounded by true in-memory element size, not wire minimum -----------

    // These three tests exercise the real `Transaction::read_vin` / `read_vout` / `read_witness`
    // directly (not a re-derived copy of their reserve formula compared against itself). Each
    // decodes a declared element count, backed by genuine minimal-wire-size elements, chosen
    // large enough that the *correct* (`size_of`-aware) reserve leaves `Vec::with_capacity`
    // short of the final length -- forcing at least one real reallocation -- while the buggy,
    // wire-minimum-only reserve happens to land on exactly the declared count for this specific
    // input (by construction: `remaining` here is exactly `COUNT * wire_size`, so
    // `remaining / wire_size == COUNT` exactly), needing no reallocation at all. So the final
    // vector's `capacity()` is `> COUNT` after the fix and would be *exactly* `COUNT` if the
    // reserve regressed back to the wire minimum alone -- making the assertion below fail on a
    // revert, unlike a test that only recomputes the formula in isolation.
    //
    // (Verified for these exact constants against Rust's amortized-doubling `Vec` growth: with
    // `size_of::<TxIn>() == 88`, `size_of::<TxOut>() == 32`, `size_of::<Vec<u8>>() == 24`, and
    // `size_of::<Transaction>() == 56` on this target, the correct reserve's initial capacity is
    // always strictly below `COUNT` and its post-growth capacity always lands strictly above
    // `COUNT` -- never coincidentally equal to it.)

    #[test]
    fn vin_reservation_never_implies_more_bytes_than_remain() {
        // Regression test: `read_vin` used to reserve capacity using only `TxIn`'s 41-byte wire
        // minimum. A decoded `TxIn` also owns a `script_sig` and a `witness` (each a
        // heap-allocating `Vec`), so its true in-memory size exceeds that wire minimum.
        const COUNT: usize = 12_345;
        const WIRE_SIZE: usize = 41; // MIN_TXIN_SIZE.
        let element_size = std::mem::size_of::<TxIn>();
        assert!(
            element_size > WIRE_SIZE,
            "test premise violated: TxIn's in-memory size must exceed its wire minimum"
        );

        // `COUNT` all-zero, empty-scriptSig `TxIn`s: each is exactly `WIRE_SIZE` zero bytes
        // (32-byte txid + 4-byte vout + a single zero CompactSize byte for the empty scriptSig +
        // 4-byte sequence).
        let mut bytes = Vec::new();
        write_compact_size(&mut bytes, COUNT as u64);
        bytes.extend(vec![0u8; COUNT * WIRE_SIZE]);
        let mut decoder = Decoder::new(&bytes);
        let inputs = Transaction::read_vin(&mut decoder).unwrap();

        assert_eq!(inputs.len(), COUNT);
        assert!(
            inputs.capacity() > COUNT,
            "read_vin's returned capacity {} did not exceed COUNT ({COUNT}): its initial \
             reservation was not bounded by size_of::<TxIn>() (a wire-minimum-only reserve would \
             have sized the vector at exactly COUNT, needing no growth here)",
            inputs.capacity()
        );
    }

    #[test]
    fn vout_reservation_never_implies_more_bytes_than_remain() {
        // As `vin_reservation_never_implies_more_bytes_than_remain`, for `read_vout` / `TxOut`
        // (9-byte wire minimum vs. a `script_pubkey`-owning in-memory size).
        const COUNT: usize = 12_345;
        const WIRE_SIZE: usize = 9; // MIN_TXOUT_SIZE.
        let element_size = std::mem::size_of::<TxOut>();
        assert!(
            element_size > WIRE_SIZE,
            "test premise violated: TxOut's in-memory size must exceed its wire minimum"
        );

        // `COUNT` zero-value, empty-scriptPubKey `TxOut`s: each is exactly `WIRE_SIZE` zero
        // bytes (8-byte value + a single zero CompactSize byte for the empty scriptPubKey).
        let mut bytes = Vec::new();
        write_compact_size(&mut bytes, COUNT as u64);
        bytes.extend(vec![0u8; COUNT * WIRE_SIZE]);
        let mut decoder = Decoder::new(&bytes);
        let outputs = Transaction::read_vout(&mut decoder).unwrap();

        assert_eq!(outputs.len(), COUNT);
        assert!(
            outputs.capacity() > COUNT,
            "read_vout's returned capacity {} did not exceed COUNT ({COUNT}): its initial \
             reservation was not bounded by size_of::<TxOut>() (a wire-minimum-only reserve \
             would have sized the vector at exactly COUNT, needing no growth here)",
            outputs.capacity()
        );
    }

    #[test]
    fn witness_item_reservation_never_implies_more_bytes_than_remain() {
        // As above, for `read_witness`: the sharpest case named in the regression this guards
        // against, since a witness item's `Vec<u8>` costs 24 bytes on a 64-bit target versus a
        // 1-byte wire minimum -- a ~24x amplification if the reservation used the wire minimum
        // alone.
        const COUNT: usize = 12_345;
        const WIRE_SIZE: usize = 1; // MIN_ITEM_SIZE.
        let element_size = std::mem::size_of::<Vec<u8>>();
        assert!(
            element_size > WIRE_SIZE,
            "test premise violated: Vec<u8>'s in-memory size must exceed the 1-byte wire minimum"
        );

        // `COUNT` empty witness items: each is a single zero CompactSize byte (a declared
        // zero-length item).
        let mut bytes = Vec::new();
        write_compact_size(&mut bytes, COUNT as u64);
        bytes.extend(vec![0u8; COUNT * WIRE_SIZE]);
        let mut decoder = Decoder::new(&bytes);
        let witness = Transaction::read_witness(&mut decoder).unwrap();

        assert_eq!(witness.len(), COUNT);
        // `Witness`'s inner `Vec<Vec<u8>>` (field `.0`) is private to `transaction.rs`, but this
        // test module is a descendant of that module, so it can inspect the exact allocation
        // `read_witness` produced.
        assert!(
            witness.0.capacity() > COUNT,
            "read_witness's returned item-vector capacity {} did not exceed COUNT ({COUNT}): its \
             initial reservation was not bounded by size_of::<Vec<u8>>() (a wire-minimum-only \
             reserve would have sized the vector at exactly COUNT, needing no growth here)",
            witness.0.capacity()
        );
    }

    #[test]
    fn oversized_declared_vout_count_fails_fast() {
        // Mirrors `oversized_declared_vin_count_fails_fast` for `read_vout`: a `CompactSize`
        // declaring ~33 million outputs, backed by only a couple of real bytes, must fail with
        // `UnexpectedEnd` on the very first output, not attempt to allocate space for tens of
        // millions of `TxOut`s.
        let mut bytes = Vec::new();
        bytes.push(0xfe); // CompactSize u32 prefix
        bytes.extend_from_slice(&0x0200_0000u32.to_le_bytes()); // MAX_SIZE outputs declared
        bytes.extend_from_slice(&[0xaa, 0xbb]); // far too little payload
        let mut decoder = Decoder::new(&bytes);
        let start = std::time::Instant::now();
        let result = Transaction::read_vout(&mut decoder);
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
        assert!(matches!(result, Err(DecodeError::UnexpectedEnd { .. })));
    }

    #[test]
    fn oversized_declared_witness_item_count_fails_fast() {
        // Mirrors the above for `read_witness`, backed by only a couple of real bytes: must fail
        // fast with `UnexpectedEnd`, not reserve space for tens of millions of `Vec<u8>`s.
        let mut bytes = Vec::new();
        bytes.push(0xfe);
        bytes.extend_from_slice(&0x0200_0000u32.to_le_bytes());
        bytes.extend_from_slice(&[0xaa, 0xbb]);
        let mut decoder = Decoder::new(&bytes);
        let start = std::time::Instant::now();
        let result = Transaction::read_witness(&mut decoder);
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
        assert!(matches!(result, Err(DecodeError::UnexpectedEnd { .. })));
    }
}
