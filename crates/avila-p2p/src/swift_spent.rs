//! Bounded codec and request tracker for the Draft BIP455 `getbspent`/`bspent`
//! long command. This module deliberately does not advertise or schedule the
//! feature; the connection manager must negotiate BIP434 and use the literal
//! command names only where the transport assigns them a message type.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use avila_consensus::check::MAX_MONEY;
use avila_consensus::connect::Coin;
use avila_consensus::encode::{DecodeError, Decoder, write_compact_size};
use avila_consensus::hash::BlockHash;
use avila_consensus::transaction::{OutPoint, Script, TxOut};
use thiserror::Error;

/// Draft BIP434 feature pair for historical spent coins.
pub const FEATURE_NAME: &str = "blockspentcoinsv1";
/// Version zero is the only feature-data version in the referenced BIP455 draft.
pub const FEATURE_DATA_V1: &[u8] = &[0x00];
/// BIP455 request command. Do not map this to an unassigned BIP324 short id.
pub const GET_SPENT_COMMAND: &str = "getbspent";
/// BIP455 response command. Do not map this to an unassigned BIP324 short id.
pub const SPENT_COMMAND: &str = "bspent";
/// Local ceiling matching the framed P2P payload limit.
pub const MAX_SPENT_PAYLOAD_BYTES: usize = 4_000_000;
/// Local hard ceiling for one response's decoded records.
pub const MAX_SPENT_COINS: usize = 100_000;
/// Matches the full-check engine's per-coin script audit limit. A larger script
/// must use ordinary validation; it is a resource fallback, not a consensus reject.
pub const MAX_SPENT_SCRIPT_BYTES: usize = 10_000;
/// Hard ceiling for in-flight block requests maintained by one peer provider.
pub const MAX_PENDING_SPENT_REQUESTS: usize = 1_024;
/// Hard ceiling for all exact expected-input index vectors held in memory.
pub const MAX_PENDING_INPUT_INDEX_BYTES: usize = 16 * 1024 * 1024;

/// Exact Draft BIP434 version-zero feature match.
#[must_use]
pub fn supports_feature(name: &str, data: &[u8]) -> bool {
    name == FEATURE_NAME && data == FEATURE_DATA_V1
}

/// A request's exact block and optional creation-height cutoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetSpentCoins {
    /// Block whose non-coinbase inputs are being described.
    pub block_hash: BlockHash,
    /// Zero means no cutoff; otherwise only coins created below this height are sent.
    pub cutoff: u32,
}

/// A coin claim is associated with its non-coinbase block input index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpentCoin {
    /// Input index with the coinbase transaction excluded, as specified by BIP455.
    pub input_index: u32,
    /// Untrusted prior output metadata, amount, and script.
    pub coin: Coin,
}

/// A response tied to the requested block hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpentCoins {
    /// Block whose inputs these claims describe.
    pub block_hash: BlockHash,
    /// Records in strictly increasing input-index order.
    pub coins: Vec<SpentCoin>,
}

/// Per-block request plan bound to one negotiated peer and one requested
/// checkpoint. It maps BIP455 input ordinals back to exact block outpoints;
/// the returned coin bodies remain untrusted until consensus checks and the
/// full transcript audit succeed.
#[derive(Clone, Debug)]
pub struct SpentCoinsBatchPlan {
    peer_id: u64,
    block_hash: BlockHash,
    block_height: u32,
    checkpoint_height: u32,
    checkpoint_hash: BlockHash,
    input_outpoints: Vec<(u32, OutPoint)>,
}

impl SpentCoinsBatchPlan {
    /// Builds the exact BIP455 request plan from a locally parsed block.
    /// Same-block spends are reconstructed from earlier transactions and
    /// omitted from external claims. The request cutoff excludes same-height
    /// outputs at the serving peer. Unsupported block layouts should fall back
    /// to ordinary ordered validation.
    pub fn for_block(
        peer_id: u64,
        block: &avila_consensus::block::Block,
        block_height: u32,
        checkpoint_height: u32,
        checkpoint_hash: BlockHash,
    ) -> Result<Self, SpentCoinsError> {
        if block.transactions.is_empty()
            || !block.transactions[0].is_coinbase()
            || block_height == 0
            || block_height > checkpoint_height
            || checkpoint_hash == BlockHash::ZERO
        {
            return Err(SpentCoinsError::BlockLayout);
        }

        let block_hash = block.block_hash();
        let mut seen_txids = std::collections::HashSet::with_capacity(block.transactions.len());
        let mut local_outputs = std::collections::HashSet::new();
        let mut input_outpoints = Vec::new();
        let mut input_index = 0u32;
        for (tx_position, tx) in block.transactions.iter().enumerate() {
            let txid = tx.txid();
            if !seen_txids.insert(txid) {
                return Err(SpentCoinsError::BlockLayout);
            }
            if tx_position != 0 {
                for input in &tx.inputs {
                    let index = input_index;
                    input_index = input_index
                        .checked_add(1)
                        .ok_or(SpentCoinsError::ResourceLimit)?;
                    if local_outputs.remove(&input.previous_output) {
                        continue;
                    }
                    if seen_txids.contains(&input.previous_output.txid) {
                        // It names an earlier or current block transaction,
                        // but no locally spendable output remains at that
                        // outpoint. Let the ordinary validator classify this
                        // malformed/double-spend case.
                        return Err(SpentCoinsError::BlockLayout);
                    }
                    if input_outpoints.len() >= MAX_SPENT_COINS {
                        return Err(SpentCoinsError::ResourceLimit);
                    }
                    input_outpoints.push((index, input.previous_output));
                }
            }

            for (vout, output) in tx.outputs.iter().enumerate() {
                if output.value < 0 || output.script_pubkey.is_unspendable() {
                    continue;
                }
                let outpoint = OutPoint {
                    txid,
                    vout: u32::try_from(vout).map_err(|_| SpentCoinsError::ResourceLimit)?,
                };
                if !local_outputs.insert(outpoint) {
                    return Err(SpentCoinsError::BlockLayout);
                }
            }
        }

        Ok(Self {
            peer_id,
            block_hash,
            block_height,
            checkpoint_height,
            checkpoint_hash,
            input_outpoints,
        })
    }

    /// The selected provider; the caller must match `NetEvent::SpentCoins.peer`.
    #[must_use]
    pub const fn peer_id(&self) -> u64 {
        self.peer_id
    }

    /// Exact target checkpoint this request was prepared for.
    #[must_use]
    pub const fn checkpoint_binding(&self) -> (u32, BlockHash) {
        (self.checkpoint_height, self.checkpoint_hash)
    }

    /// Exact BIP455 request and response-index set for this block.
    #[must_use]
    pub fn request(&self) -> (GetSpentCoins, Vec<u32>) {
        (
            GetSpentCoins {
                block_hash: self.block_hash,
                cutoff: self.block_height,
            },
            self.input_outpoints
                .iter()
                .map(|(index, _)| *index)
                .collect(),
        )
    }

    /// Bind a response to the selected session and exact request. This only
    /// converts data into engine claims; it never validates or publishes a
    /// block or checkpoint.
    pub fn bind_response(
        &self,
        peer_id: u64,
        response: SpentCoins,
    ) -> Result<Vec<(OutPoint, avila_consensus::connect::Coin)>, SpentCoinsError> {
        if peer_id != self.peer_id {
            return Err(SpentCoinsError::WrongPeer);
        }
        if response.block_hash != self.block_hash {
            return Err(SpentCoinsError::UnrequestedBlock);
        }
        if self.block_height > self.checkpoint_height || self.checkpoint_hash == BlockHash::ZERO {
            return Err(SpentCoinsError::Checkpoint);
        }
        if response.coins.len() != self.input_outpoints.len()
            || response.coins.iter().zip(&self.input_outpoints).any(
                |(coin, (expected_index, _))| {
                    coin.input_index != *expected_index || coin.coin.height >= self.block_height
                },
            )
        {
            return Err(SpentCoinsError::InputIndices);
        }
        Ok(response
            .coins
            .into_iter()
            .zip(&self.input_outpoints)
            .map(|(claim, (_, outpoint))| (*outpoint, claim.coin))
            .collect())
    }
}

/// Codec and correlation failures. Resource bounds are separate from malformed data.
#[derive(Debug, PartialEq, Eq, Error)]
pub enum SpentCoinsError {
    /// Payload is malformed, noncanonical, or has trailing bytes.
    #[error("malformed BIP455 spent-coins payload: {0}")]
    Decode(DecodeError),
    /// A local byte, record, or script budget was exceeded; use ordinary validation.
    #[error("BIP455 response exceeds local resource budget")]
    ResourceLimit,
    /// A compressed value is outside the money range.
    #[error("BIP455 coin amount exceeds MAX_MONEY")]
    AmountRange,
    /// The serving peer returned a block other than the requested one.
    #[error("BIP455 response block hash was not requested")]
    UnrequestedBlock,
    /// The response contained a duplicate or unexpected input index.
    #[error("BIP455 response input indices do not match the request")]
    InputIndices,
    /// A cutoff response included a coin created at or after the cutoff.
    #[error("BIP455 response coin violates the requested cutoff")]
    Cutoff,
    /// A local block cannot be mapped to stable input ordinals.
    #[error("block layout is unsuitable for a spent-coin request")]
    BlockLayout,
    /// A response came from a session other than the selected provider.
    #[error("BIP455 response came from the wrong peer")]
    WrongPeer,
    /// The request is not bound to a valid checkpoint range.
    #[error("BIP455 request has an invalid checkpoint binding")]
    Checkpoint,
    /// A second request for the same block is already pending on this tracker.
    #[error("BIP455 request for this block is already pending")]
    DuplicateRequest,
    /// The tracker has no room for another in-flight request.
    #[error("BIP455 pending-request limit reached")]
    PendingLimit,
}

/// Encodes the fixed-size `getbspent` payload.
pub fn encode_request(request: GetSpentCoins) -> Vec<u8> {
    let mut out = Vec::with_capacity(36);
    out.extend_from_slice(request.block_hash.as_bytes());
    out.extend_from_slice(&request.cutoff.to_le_bytes());
    out
}

/// Decodes exactly one fixed-size `getbspent` payload.
pub fn decode_request(payload: &[u8]) -> Result<GetSpentCoins, SpentCoinsError> {
    let mut decoder = Decoder::new(payload);
    let block_hash = BlockHash::from_bytes(decoder.read_array().map_err(SpentCoinsError::Decode)?);
    let cutoff = decoder.read_u32_le().map_err(SpentCoinsError::Decode)?;
    decoder.finish().map_err(SpentCoinsError::Decode)?;
    Ok(GetSpentCoins { block_hash, cutoff })
}

/// Decodes one bounded `bspent` payload without reserving from an unchecked count.
pub fn decode_response(
    payload: &[u8],
    max_coins: usize,
    max_script_bytes: usize,
) -> Result<SpentCoins, SpentCoinsError> {
    if payload.len() > MAX_SPENT_PAYLOAD_BYTES
        || max_coins > MAX_SPENT_COINS
        || max_script_bytes > MAX_SPENT_SCRIPT_BYTES
    {
        return Err(SpentCoinsError::ResourceLimit);
    }
    let mut decoder = Decoder::new(payload);
    let block_hash = BlockHash::from_bytes(decoder.read_array().map_err(SpentCoinsError::Decode)?);
    let count = usize::try_from(
        decoder
            .read_compact_size()
            .map_err(SpentCoinsError::Decode)?,
    )
    .map_err(|_| SpentCoinsError::ResourceLimit)?;
    if count > max_coins || count > decoder.bounded_capacity(count as u64, 8) {
        return Err(SpentCoinsError::ResourceLimit);
    }
    let mut coins = Vec::with_capacity(count);
    let mut previous_index = None;
    for _ in 0..count {
        let input_index = decoder.read_u32_le().map_err(SpentCoinsError::Decode)?;
        if previous_index.is_some_and(|prior| prior >= input_index) {
            return Err(SpentCoinsError::InputIndices);
        }
        previous_index = Some(input_index);
        let code = decoder.read_u32_le().map_err(SpentCoinsError::Decode)?;
        // Amount compression is a u64 CompactSize value, not a vector length;
        // the shared Decoder applies its 32 MiB allocation ceiling and would
        // reject valid high compressed amounts.
        let amount_code = read_compact_u64(&mut decoder)?;
        let amount = decompress_amount(amount_code).ok_or(SpentCoinsError::AmountRange)?;
        if amount > MAX_MONEY as u64 {
            return Err(SpentCoinsError::AmountRange);
        }
        let script = read_reconstructable_script(&mut decoder, max_script_bytes)?;
        let coin = Coin {
            out: TxOut {
                value: amount as i64,
                script_pubkey: script,
            },
            height: code >> 1,
            coinbase: code & 1 != 0,
        };
        coins.push(SpentCoin { input_index, coin });
    }
    decoder.finish().map_err(SpentCoinsError::Decode)?;
    Ok(SpentCoins { block_hash, coins })
}

/// Encodes `bspent` records in BIP455 order, using the reconstructable-script
/// prefixes and `CompressAmount` representation. Intended for interoperability tests.
pub fn encode_response(response: &SpentCoins) -> Result<Vec<u8>, SpentCoinsError> {
    if response.coins.len() > MAX_SPENT_COINS {
        return Err(SpentCoinsError::ResourceLimit);
    }
    let mut out = Vec::with_capacity(36 + response.coins.len().saturating_mul(16));
    out.extend_from_slice(response.block_hash.as_bytes());
    write_compact_size(&mut out, response.coins.len() as u64);
    let mut prior = None;
    for spent in &response.coins {
        if prior.is_some_and(|index| index >= spent.input_index)
            || spent.coin.height > (u32::MAX >> 1)
            || !(0..=MAX_MONEY).contains(&spent.coin.out.value)
            || spent.coin.out.script_pubkey.len() > MAX_SPENT_SCRIPT_BYTES
        {
            return Err(SpentCoinsError::InputIndices);
        }
        prior = Some(spent.input_index);
        out.extend_from_slice(&spent.input_index.to_le_bytes());
        let code = spent.coin.height * 2 + u32::from(spent.coin.coinbase);
        out.extend_from_slice(&code.to_le_bytes());
        write_compact_size(&mut out, compress_amount(spent.coin.out.value as u64));
        write_reconstructable_script(&mut out, &spent.coin.out.script_pubkey)?;
        if out.len() > MAX_SPENT_PAYLOAD_BYTES {
            return Err(SpentCoinsError::ResourceLimit);
        }
    }
    Ok(out)
}

/// Per-connection request tracker. The caller supplies the exact subset of block
/// input positions expected after applying the requested creation-height cutoff.
pub struct SpentCoinsRequests {
    pending: HashMap<BlockHash, Pending>,
    max_pending: usize,
    max_coins: usize,
    max_script_bytes: usize,
    max_pending_index_bytes: usize,
    pending_index_bytes: usize,
}

struct Pending {
    cutoff: u32,
    expected_indices: Vec<u32>,
    requested_at: Instant,
}

impl SpentCoinsRequests {
    /// Creates a tracker with explicit in-flight, record, and script byte budgets.
    pub fn new(
        max_pending: usize,
        max_coins: usize,
        max_script_bytes: usize,
        max_pending_index_bytes: usize,
    ) -> Result<Self, SpentCoinsError> {
        if max_pending == 0
            || max_pending > MAX_PENDING_SPENT_REQUESTS
            || max_coins > MAX_SPENT_COINS
            || max_script_bytes > MAX_SPENT_SCRIPT_BYTES
            || !(4..=MAX_PENDING_INPUT_INDEX_BYTES).contains(&max_pending_index_bytes)
        {
            return Err(SpentCoinsError::ResourceLimit);
        }
        Ok(Self {
            pending: HashMap::with_capacity(max_pending),
            max_pending,
            max_coins,
            max_script_bytes,
            max_pending_index_bytes,
            pending_index_bytes: 0,
        })
    }

    /// Adds a unique exact request and returns its wire payload. Expected indices
    /// must already be sorted and fit the caller's configured count ceiling.
    pub fn request(
        &mut self,
        request: GetSpentCoins,
        expected_indices: &[u32],
    ) -> Result<Vec<u8>, SpentCoinsError> {
        if expected_indices.len() > self.max_coins
            || expected_indices.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(SpentCoinsError::InputIndices);
        }
        if self.pending.contains_key(&request.block_hash) {
            return Err(SpentCoinsError::DuplicateRequest);
        }
        if self.pending.len() >= self.max_pending {
            return Err(SpentCoinsError::PendingLimit);
        }
        let index_bytes = expected_indices
            .len()
            .checked_mul(std::mem::size_of::<u32>())
            .ok_or(SpentCoinsError::ResourceLimit)?;
        if self
            .pending_index_bytes
            .checked_add(index_bytes)
            .is_none_or(|bytes| bytes > self.max_pending_index_bytes)
        {
            return Err(SpentCoinsError::ResourceLimit);
        }
        self.pending.insert(
            request.block_hash,
            Pending {
                cutoff: request.cutoff,
                expected_indices: expected_indices.to_vec(),
                requested_at: Instant::now(),
            },
        );
        self.pending_index_bytes += index_bytes;
        Ok(encode_request(request))
    }

    /// Decodes and exactly matches one response. A malformed response does not
    /// consume the pending entry, allowing the caller to disconnect the peer and
    /// retry through another source without losing request state.
    pub fn accept(&self, payload: &[u8]) -> Result<SpentCoins, SpentCoinsError> {
        let response = decode_response(payload, self.max_coins, self.max_script_bytes)?;
        self.accept_decoded(&response)?;
        Ok(response)
    }

    /// Correlates an already bounded and decoded response to its exact request.
    pub fn accept_decoded(&self, response: &SpentCoins) -> Result<(), SpentCoinsError> {
        let pending = self
            .pending
            .get(&response.block_hash)
            .ok_or(SpentCoinsError::UnrequestedBlock)?;
        if response.coins.len() != pending.expected_indices.len()
            || response
                .coins
                .iter()
                .zip(&pending.expected_indices)
                .any(|(coin, expected)| coin.input_index != *expected)
        {
            return Err(SpentCoinsError::InputIndices);
        }
        if pending.cutoff != 0
            && response
                .coins
                .iter()
                .any(|coin| coin.coin.height >= pending.cutoff)
        {
            return Err(SpentCoinsError::Cutoff);
        }
        Ok(())
    }

    /// Removes a completed or abandoned request.
    pub fn remove(&mut self, block_hash: &BlockHash) -> bool {
        if let Some(pending) = self.pending.remove(block_hash) {
            self.pending_index_bytes -= pending.expected_indices.len() * std::mem::size_of::<u32>();
            true
        } else {
            false
        }
    }

    /// Removes requests that exceeded the caller's response deadline and
    /// returns their hashes so the ordinary block path can take over.
    pub fn expire_older_than(&mut self, timeout: Duration) -> Vec<BlockHash> {
        let now = Instant::now();
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, pending)| now.saturating_duration_since(pending.requested_at) > timeout)
            .map(|(hash, _)| *hash)
            .collect();
        for hash in &expired {
            self.remove(hash);
        }
        expired
    }

    /// Number of bounded requests currently in flight.
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

fn read_reconstructable_script(
    decoder: &mut Decoder<'_>,
    max_script_bytes: usize,
) -> Result<Script, SpentCoinsError> {
    let prefix = decoder
        .read_compact_size()
        .map_err(SpentCoinsError::Decode)?;
    let (script, consumed) = match prefix {
        0 => {
            let len = usize::try_from(
                decoder
                    .read_compact_size()
                    .map_err(SpentCoinsError::Decode)?,
            )
            .map_err(|_| SpentCoinsError::ResourceLimit)?;
            if len > max_script_bytes {
                return Err(SpentCoinsError::ResourceLimit);
            }
            (
                Script::new(
                    decoder
                        .read_bytes(len)
                        .map_err(SpentCoinsError::Decode)?
                        .to_vec(),
                ),
                len,
            )
        }
        1 => {
            let hash = decoder
                .read_array::<20>()
                .map_err(SpentCoinsError::Decode)?;
            let mut script = vec![0x76, 0xa9, 0x14];
            script.extend_from_slice(&hash);
            script.extend_from_slice(&[0x88, 0xac]);
            (Script::new(script), 25)
        }
        2 | 3 => {
            let x = decoder
                .read_array::<32>()
                .map_err(SpentCoinsError::Decode)?;
            let mut script = vec![33, prefix as u8];
            script.extend_from_slice(&x);
            script.push(0xac);
            (Script::new(script), 35)
        }
        4 => {
            let key = decoder
                .read_array::<64>()
                .map_err(SpentCoinsError::Decode)?;
            let mut script = vec![65, 0x04];
            script.extend_from_slice(&key);
            script.push(0xac);
            (Script::new(script), 67)
        }
        5 => {
            let hash = decoder
                .read_array::<20>()
                .map_err(SpentCoinsError::Decode)?;
            let mut script = vec![0xa9, 0x14];
            script.extend_from_slice(&hash);
            script.push(0x87);
            (Script::new(script), 23)
        }
        6 => {
            let hash = decoder
                .read_array::<32>()
                .map_err(SpentCoinsError::Decode)?;
            let mut script = vec![0x00, 0x20];
            script.extend_from_slice(&hash);
            (Script::new(script), 34)
        }
        7 => {
            let hash = decoder
                .read_array::<20>()
                .map_err(SpentCoinsError::Decode)?;
            let mut script = vec![0x00, 0x14];
            script.extend_from_slice(&hash);
            (Script::new(script), 22)
        }
        8 => {
            let key = decoder
                .read_array::<32>()
                .map_err(SpentCoinsError::Decode)?;
            let mut script = vec![0x51, 0x20];
            script.extend_from_slice(&key);
            (Script::new(script), 34)
        }
        unknown => {
            let len = usize::try_from(unknown - 9).map_err(|_| SpentCoinsError::ResourceLimit)?;
            if len > max_script_bytes {
                return Err(SpentCoinsError::ResourceLimit);
            }
            (
                Script::new(
                    decoder
                        .read_bytes(len)
                        .map_err(SpentCoinsError::Decode)?
                        .to_vec(),
                ),
                len,
            )
        }
    };
    if consumed > max_script_bytes {
        return Err(SpentCoinsError::ResourceLimit);
    }
    Ok(script)
}

fn write_reconstructable_script(out: &mut Vec<u8>, script: &Script) -> Result<(), SpentCoinsError> {
    let bytes = script.as_bytes();
    let compressed = if bytes.len() == 25
        && bytes[..3] == [0x76, 0xa9, 0x14]
        && bytes[23..] == [0x88, 0xac]
    {
        Some((1, &bytes[3..23]))
    } else if bytes.len() == 35 && bytes[0] == 33 && matches!(bytes[1], 2 | 3) && bytes[34] == 0xac
    {
        Some((u64::from(bytes[1]), &bytes[2..34]))
    } else if bytes.len() == 67 && bytes[0] == 65 && bytes[1] == 4 && bytes[66] == 0xac {
        Some((4, &bytes[2..66]))
    } else if bytes.len() == 23 && bytes[..2] == [0xa9, 0x14] && bytes[22] == 0x87 {
        Some((5, &bytes[2..22]))
    } else if bytes.len() == 34 && bytes[..2] == [0x00, 0x20] {
        Some((6, &bytes[2..]))
    } else if bytes.len() == 22 && bytes[..2] == [0x00, 0x14] {
        Some((7, &bytes[2..]))
    } else if bytes.len() == 34 && bytes[..2] == [0x51, 0x20] {
        Some((8, &bytes[2..]))
    } else {
        None
    };
    if let Some((prefix, payload)) = compressed {
        write_compact_size(out, prefix);
        out.extend_from_slice(payload);
    } else {
        if bytes.len() > MAX_SPENT_SCRIPT_BYTES {
            return Err(SpentCoinsError::ResourceLimit);
        }
        write_compact_size(out, 0);
        write_compact_size(out, bytes.len() as u64);
        out.extend_from_slice(bytes);
    }
    Ok(())
}

fn compress_amount(mut amount: u64) -> u64 {
    if amount == 0 {
        return 0;
    }
    let mut exponent = 0;
    while amount.is_multiple_of(10) && exponent < 9 {
        amount /= 10;
        exponent += 1;
    }
    if exponent < 9 {
        let digit = amount % 10;
        amount /= 10;
        1 + (amount * 9 + digit - 1) * 10 + exponent
    } else {
        1 + (amount - 1) * 10 + 9
    }
}

fn decompress_amount(mut code: u64) -> Option<u64> {
    if code == 0 {
        return Some(0);
    }
    code -= 1;
    let exponent = code % 10;
    code /= 10;
    let mut amount = if exponent < 9 {
        let digit = (code % 9) + 1;
        code /= 9;
        code.checked_mul(10)?.checked_add(digit)?
    } else {
        code.checked_add(1)?
    };
    for _ in 0..exponent {
        amount = amount.checked_mul(10)?;
    }
    Some(amount)
}

fn read_compact_u64(decoder: &mut Decoder<'_>) -> Result<u64, SpentCoinsError> {
    let prefix = decoder.read_u8().map_err(SpentCoinsError::Decode)?;
    let value = match prefix {
        0..=252 => u64::from(prefix),
        253 => {
            let value = u64::from(decoder.read_u16_le().map_err(SpentCoinsError::Decode)?);
            if value < 253 {
                return Err(SpentCoinsError::Decode(
                    DecodeError::NonCanonicalCompactSize,
                ));
            }
            value
        }
        254 => {
            let value = u64::from(decoder.read_u32_le().map_err(SpentCoinsError::Decode)?);
            if value < 0x1_0000 {
                return Err(SpentCoinsError::Decode(
                    DecodeError::NonCanonicalCompactSize,
                ));
            }
            value
        }
        255 => {
            let value = decoder.read_u64_le().map_err(SpentCoinsError::Decode)?;
            if value < 0x1_0000_0000 {
                return Err(SpentCoinsError::Decode(
                    DecodeError::NonCanonicalCompactSize,
                ));
            }
            value
        }
    };
    Ok(value)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use avila_consensus::script;
    use avila_consensus::transaction::{Transaction, TxIn, Witness};

    #[test]
    fn response_roundtrip_covers_witness_taproot_and_index_binding() {
        let hash = BlockHash::from_bytes([0x42; 32]);
        let response = SpentCoins {
            block_hash: hash,
            coins: vec![
                SpentCoin {
                    input_index: 0,
                    coin: Coin {
                        out: TxOut {
                            value: 12_345_000,
                            script_pubkey: Script::new([&[0x00, 0x14][..], &[7; 20]].concat()),
                        },
                        height: 100,
                        coinbase: false,
                    },
                },
                SpentCoin {
                    input_index: 3,
                    coin: Coin {
                        out: TxOut {
                            value: 50_000,
                            script_pubkey: Script::new([&[0x51, 0x20][..], &[9; 32]].concat()),
                        },
                        height: 42,
                        coinbase: true,
                    },
                },
            ],
        };
        let encoded = encode_response(&response).unwrap();
        assert_eq!(decode_response(&encoded, 16, 256).unwrap(), response);

        let mut requests = SpentCoinsRequests::new(4, 16, 256, 1024).unwrap();
        let request = GetSpentCoins {
            block_hash: hash,
            cutoff: 500,
        };
        assert_eq!(
            requests.request(request, &[0, 3]).unwrap(),
            encode_request(request)
        );
        assert_eq!(requests.accept(&encoded).unwrap(), response);
        assert!(requests.remove(&hash));
        assert_eq!(requests.pending_len(), 0);
    }

    #[test]
    fn batch_plan_binds_peer_checkpoint_and_excludes_earlier_block_outputs() {
        let params = avila_consensus::params::Network::Regtest.params();
        let prior = OutPoint {
            txid: avila_consensus::hash::Txid::from_bytes([0x31; 32]),
            vout: 4,
        };
        let local_spend = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: prior,
                script_sig: Script::default(),
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: Script::new(vec![script::OP_1]),
            }],
            lock_time: 0,
        };
        let local_child = Transaction {
            version: 2,
            inputs: vec![
                TxIn {
                    previous_output: OutPoint {
                        txid: local_spend.txid(),
                        vout: 0,
                    },
                    script_sig: Script::default(),
                    sequence: u32::MAX,
                    witness: Witness::default(),
                },
                TxIn {
                    previous_output: OutPoint {
                        txid: avila_consensus::hash::Txid::from_bytes([0x52; 32]),
                        vout: 1,
                    },
                    script_sig: Script::default(),
                    sequence: u32::MAX,
                    witness: Witness::default(),
                },
            ],
            outputs: vec![TxOut {
                value: 900,
                script_pubkey: Script::new(vec![script::OP_1]),
            }],
            lock_time: 0,
        };
        let block = crate::testchain::block_on_txs(
            &params.genesis_header,
            vec![
                crate::testchain::coinbase_tx(1),
                local_spend.clone(),
                local_child,
            ],
            &params,
        );
        let checkpoint = BlockHash::from_bytes([0x77; 32]);
        let plan = SpentCoinsBatchPlan::for_block(19, &block, 1, 100, checkpoint).unwrap();
        let (request, indices) = plan.request();
        assert_eq!(request.block_hash, block.block_hash());
        assert_eq!(request.cutoff, 1);
        assert_eq!(indices, vec![0, 2]);
        assert_eq!(plan.peer_id(), 19);
        assert_eq!(plan.checkpoint_binding(), (100, checkpoint));

        let response = SpentCoins {
            block_hash: block.block_hash(),
            coins: vec![
                SpentCoin {
                    input_index: 0,
                    coin: Coin {
                        out: TxOut {
                            value: 2_000,
                            script_pubkey: Script::new(vec![script::OP_1]),
                        },
                        height: 0,
                        coinbase: false,
                    },
                },
                SpentCoin {
                    input_index: 2,
                    coin: Coin {
                        out: TxOut {
                            value: 3_000,
                            script_pubkey: Script::new(vec![script::OP_1]),
                        },
                        height: 0,
                        coinbase: false,
                    },
                },
            ],
        };
        let claims = plan.bind_response(19, response.clone()).unwrap();
        assert_eq!(claims.len(), 2);
        assert_eq!(claims[0].0, prior);
        assert_eq!(claims[1].0.vout, 1);
        assert_eq!(
            plan.bind_response(20, response),
            Err(SpentCoinsError::WrongPeer)
        );
    }

    #[test]
    fn reconstructable_script_codes_roundtrip_exact_scripts() {
        let scripts = vec![
            [vec![0x76, 0xa9, 0x14], vec![1; 20], vec![0x88, 0xac]].concat(),
            [vec![33, 2], vec![2; 32], vec![0xac]].concat(),
            [vec![33, 3], vec![3; 32], vec![0xac]].concat(),
            [vec![65, 4], vec![4; 64], vec![0xac]].concat(),
            [vec![0xa9, 0x14], vec![5; 20], vec![0x87]].concat(),
            [vec![0, 0x20], vec![6; 32]].concat(),
            [vec![0, 0x14], vec![7; 20]].concat(),
            [vec![0x51, 0x20], vec![8; 32]].concat(),
            vec![0x6a, 2, 0xaa, 0xbb],
        ];
        for (index, bytes) in scripts.into_iter().enumerate() {
            let response = SpentCoins {
                block_hash: BlockHash::from_bytes([index as u8; 32]),
                coins: vec![SpentCoin {
                    input_index: 0,
                    coin: Coin {
                        out: TxOut {
                            value: 100_000_000,
                            script_pubkey: Script::new(bytes),
                        },
                        height: 123_456,
                        coinbase: true,
                    },
                }],
            };
            let encoded = encode_response(&response).unwrap();
            assert_eq!(
                decode_response(&encoded, 2, MAX_SPENT_SCRIPT_BYTES).unwrap(),
                response
            );
        }
    }

    #[test]
    fn compressed_amount_roundtrips_money_range() {
        for amount in [
            0,
            1,
            10,
            100,
            1_000,
            50_000_000,
            100_000_000,
            MAX_MONEY as u64,
        ] {
            assert_eq!(decompress_amount(compress_amount(amount)), Some(amount));
            let response = SpentCoins {
                block_hash: BlockHash::from_bytes([0x31; 32]),
                coins: vec![SpentCoin {
                    input_index: 0,
                    coin: Coin {
                        out: TxOut {
                            value: amount as i64,
                            script_pubkey: Script::new(vec![0x51]),
                        },
                        height: 1,
                        coinbase: false,
                    },
                }],
            };
            let encoded = encode_response(&response).unwrap();
            assert_eq!(decode_response(&encoded, 1, 64).unwrap(), response);
        }
    }

    #[test]
    fn rejects_unrequested_indices_cutoff_and_noncanonical_count() {
        let hash = BlockHash::from_bytes([1; 32]);
        let coin = Coin {
            out: TxOut {
                value: 1,
                script_pubkey: Script::new(vec![0x51]),
            },
            height: 9,
            coinbase: false,
        };
        let response = SpentCoins {
            block_hash: hash,
            coins: vec![SpentCoin {
                input_index: 1,
                coin,
            }],
        };
        let encoded = encode_response(&response).unwrap();
        let mut requests = SpentCoinsRequests::new(1, 4, 64, 64).unwrap();
        requests
            .request(
                GetSpentCoins {
                    block_hash: hash,
                    cutoff: 9,
                },
                &[0],
            )
            .unwrap();
        assert_eq!(
            requests.accept(&encoded),
            Err(SpentCoinsError::InputIndices)
        );
        requests.remove(&hash);
        requests
            .request(
                GetSpentCoins {
                    block_hash: hash,
                    cutoff: 9,
                },
                &[1],
            )
            .unwrap();
        assert_eq!(requests.accept(&encoded), Err(SpentCoinsError::Cutoff));

        let mut noncanonical = hash.as_bytes().to_vec();
        noncanonical.extend_from_slice(&[0xfd, 1, 0]);
        assert!(matches!(
            decode_response(&noncanonical, 4, 64),
            Err(SpentCoinsError::Decode(
                DecodeError::NonCanonicalCompactSize
            ))
        ));
    }
}
