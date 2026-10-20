//! Experimental, shadow-only audit for SwiftSync spent-coin classifications.
//!
//! This checks whether the multiset of outputs classified as spent by a checkpoint
//! matches the multiset of coins supplied for observed inputs. It does not establish
//! membership, block validity, temporal ordering, BIP30 correctness, script validity,
//! or any other consensus rule. The caller must exclude genesis and unspendable outputs.
//! It must never authorize consensus acceptance.

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::connect::Coin;
use crate::hash::BlockHash;
use crate::params::Network;
use crate::swiftsync::TagAgg;
use crate::transaction::OutPoint;

/// Maximum keyed-commitment operations accepted for one bounded checkpoint window. This
/// includes output/input records plus separately committed survivors and BIP30 overwrites.
/// Sessions cannot be merged independently.
pub const MAX_AUDIT_RECORDS: u64 = u64::MAX;
/// Maximum script length hashed in one record. This bounds work per call.
pub const MAX_AUDIT_SCRIPT_BYTES: usize = 10_000;
const HMAC_BLOCK_BYTES: usize = 64;
const COIN_DOMAIN: &[u8] = b"Avila SwiftAudit coin commitment v1\0";
const STATE_DOMAIN: &[u8] = b"Avila SwiftAudit persistent state v1\0";
const STATE_MAGIC: &[u8; 8] = b"AVSAUD01";
const STATE_VERSION: u32 = 1;

/// Whether an output was claimed to be spent by the selected checkpoint.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OutputClass {
    /// This output has a corresponding observed input at or before the checkpoint.
    SpentByCheckpoint,
    /// This output is claimed to remain unspent at the checkpoint.
    SurvivesCheckpoint,
}

/// The public outcome of the shadow audit. It contains no commitment material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditVerdict {
    /// The classified-spent and observed-input coin multisets matched.
    Match,
    /// Counts or keyed coin aggregates differed.
    Mismatch,
}

/// Bounded public counters from a completed audit session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditReport {
    /// Number of output records included.
    pub outputs: u64,
    /// Number of outputs claimed to survive the checkpoint.
    pub survivors: u64,
    /// Number of locally recognized BIP30-overwritten output incarnations.
    pub overwritten_outputs: u64,
    /// Number of observed input-coin records.
    pub input_coins: u64,
    /// Aggregate comparison result.
    pub verdict: AuditVerdict,
}

/// A bounded failure from a shadow audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuditError {
    /// OS-provided entropy could not be read.
    #[error("OS randomness unavailable for the Swift audit key")]
    RandomnessUnavailable,
    /// An output or input coin script exceeds the per-record work bound.
    #[error("Swift audit coin script exceeds the per-record bound")]
    ScriptTooLarge,
    /// The session record cap was reached.
    #[error("Swift audit record budget exhausted")]
    RecordLimitExceeded,
    /// Internal count arithmetic overflowed.
    #[error("Swift audit counter overflow")]
    CounterOverflow,
    /// A failed audit session cannot be serialized or resumed.
    #[error("failed Swift audit session")]
    FailedSession,
    /// The finish context differs from the session's checkpoint binding.
    #[error("Swift audit checkpoint binding mismatch")]
    CheckpointMismatch,
    /// The claimed survivor count exceeds the number of output records.
    #[error("Swift audit counts are inconsistent")]
    InvalidCounts,
}

/// One audit session. Its secret key and intermediate aggregates are never exposed.
///
/// Create a session with [`Self::new`], feed all parsed output records and observed input
/// coins, then compare it with [`Self::finish`]. This is an experimental shadow diagnostic
/// only and is not a consensus validation result. Dropping the session attempts to wipe its
/// owned key and aggregate storage; this is best-effort and cannot guarantee erasure of
/// compiler, CPU, or cryptographic-library copies.
pub struct SwiftAudit {
    key: [u8; 32],
    network: Network,
    checkpoint_height: u32,
    checkpoint_hash: BlockHash,
    output_tags: TagAgg,
    survivor_tags: TagAgg,
    hint_survivor_tags: TagAgg,
    overwritten_tags: TagAgg,
    input_tags: TagAgg,
    outputs: u64,
    survivors: u64,
    hint_survivors: u64,
    overwritten: u64,
    input_coins: u64,
    records: u64,
    failed: Option<AuditError>,
}

impl SwiftAudit {
    /// Starts an audit bound to a Bitcoin network and checkpoint, using a fresh OS-random key.
    pub fn new(
        network: Network,
        checkpoint_height: u32,
        checkpoint_hash: BlockHash,
    ) -> Result<Self, AuditError> {
        let mut session = Self::empty(network, checkpoint_height, checkpoint_hash);
        if getrandom::fill(&mut session.key).is_err() {
            session.key.zeroize();
            return Err(AuditError::RandomnessUnavailable);
        }
        Ok(session)
    }

    fn empty(network: Network, checkpoint_height: u32, checkpoint_hash: BlockHash) -> Self {
        Self {
            key: [0; 32],
            network,
            checkpoint_height,
            checkpoint_hash,
            output_tags: TagAgg::default(),
            survivor_tags: TagAgg::default(),
            hint_survivor_tags: TagAgg::default(),
            overwritten_tags: TagAgg::default(),
            input_tags: TagAgg::default(),
            outputs: 0,
            survivors: 0,
            hint_survivors: 0,
            overwritten: 0,
            input_coins: 0,
            records: 0,
            failed: None,
        }
    }

    /// Encodes the secret verifier state for storage in a private local database.
    /// Callers must keep this blob local, protect its containing file, and commit it
    /// atomically with the corresponding live-index block transition.
    pub(crate) fn persisted_state(&self) -> Result<Vec<u8>, AuditError> {
        if self.failed.is_some() {
            return Err(AuditError::FailedSession);
        }
        let mut out = Vec::with_capacity(321);
        out.extend_from_slice(STATE_MAGIC);
        out.extend_from_slice(&STATE_VERSION.to_le_bytes());
        out.push(network_tag(self.network));
        out.extend_from_slice(&self.checkpoint_height.to_le_bytes());
        out.extend_from_slice(self.checkpoint_hash.as_bytes());
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&self.output_tags.to_bytes());
        out.extend_from_slice(&self.survivor_tags.to_bytes());
        out.extend_from_slice(&self.hint_survivor_tags.to_bytes());
        out.extend_from_slice(&self.overwritten_tags.to_bytes());
        out.extend_from_slice(&self.input_tags.to_bytes());
        for count in [
            self.outputs,
            self.survivors,
            self.hint_survivors,
            self.overwritten,
            self.input_coins,
            self.records,
        ] {
            out.extend_from_slice(&count.to_le_bytes());
        }
        let checksum = state_checksum(&out);
        out.extend_from_slice(&checksum);
        Ok(out)
    }

    /// Restores a verifier session from private local storage after checking its
    /// framing, checksum, checkpoint, and bounded counters.
    pub(crate) fn from_persisted_state(
        bytes: &[u8],
        network: Network,
        checkpoint_height: u32,
        checkpoint_hash: BlockHash,
    ) -> Result<Self, AuditError> {
        const BODY: usize = 289;
        if bytes.len() != BODY + 32
            || &bytes[..8] != STATE_MAGIC
            || u32::from_le_bytes(bytes[8..12].try_into().unwrap_or_default()) != STATE_VERSION
            || network_from_tag(bytes[12]) != Some(network)
            || u32::from_le_bytes(bytes[13..17].try_into().unwrap_or_default()) != checkpoint_height
            || BlockHash::from_bytes(bytes[17..49].try_into().unwrap_or_default())
                != checkpoint_hash
            || !ct_eq(&state_checksum(&bytes[..BODY]), &bytes[BODY..])
        {
            return Err(AuditError::CheckpointMismatch);
        }
        let mut session = Self::empty(network, checkpoint_height, checkpoint_hash);
        session.key.copy_from_slice(&bytes[49..81]);
        session.output_tags = TagAgg::from_bytes(bytes[81..113].try_into().unwrap_or_default());
        session.survivor_tags = TagAgg::from_bytes(bytes[113..145].try_into().unwrap_or_default());
        session.hint_survivor_tags =
            TagAgg::from_bytes(bytes[145..177].try_into().unwrap_or_default());
        session.overwritten_tags =
            TagAgg::from_bytes(bytes[177..209].try_into().unwrap_or_default());
        session.input_tags = TagAgg::from_bytes(bytes[209..241].try_into().unwrap_or_default());
        session.outputs = u64::from_le_bytes(bytes[241..249].try_into().unwrap_or_default());
        session.survivors = u64::from_le_bytes(bytes[249..257].try_into().unwrap_or_default());
        session.hint_survivors = u64::from_le_bytes(bytes[257..265].try_into().unwrap_or_default());
        session.overwritten = u64::from_le_bytes(bytes[265..273].try_into().unwrap_or_default());
        session.input_coins = u64::from_le_bytes(bytes[273..281].try_into().unwrap_or_default());
        session.records = u64::from_le_bytes(bytes[281..289].try_into().unwrap_or_default());
        if session.survivors > session.outputs
            || session.hint_survivors > session.outputs
            || session.overwritten > session.outputs
            || session
                .survivors
                .checked_add(session.overwritten)
                .is_none_or(|excluded| excluded > session.outputs)
            || session.input_coins > session.records
        {
            session.key.zeroize();
            return Err(AuditError::InvalidCounts);
        }
        Ok(session)
    }

    /// Whether this in-memory audit is bound to the requested checkpoint.
    #[must_use]
    pub fn matches_checkpoint(
        &self,
        network: Network,
        checkpoint_height: u32,
        checkpoint_hash: BlockHash,
    ) -> bool {
        self.network as u8 == network as u8
            && self.checkpoint_height == checkpoint_height
            && self.checkpoint_hash == checkpoint_hash
    }

    /// Injects a deterministic key only in unit tests. The source key is public test data.
    #[cfg(test)]
    fn with_test_key(
        network: Network,
        checkpoint_height: u32,
        checkpoint_hash: BlockHash,
        key: &[u8; 32],
    ) -> Self {
        let mut session = Self::empty(network, checkpoint_height, checkpoint_hash);
        session.key.copy_from_slice(key);
        session
    }

    /// Records one parsed transaction output and its untrusted checkpoint classification.
    pub fn record_output(
        &mut self,
        outpoint: &OutPoint,
        coin: &Coin,
        class: OutputClass,
    ) -> Result<(), AuditError> {
        self.check_record(coin, false, class == OutputClass::SurvivesCheckpoint)?;
        let mut tag = coin_commitment(
            &self.key,
            self.network,
            self.checkpoint_height,
            self.checkpoint_hash,
            outpoint,
            coin,
        );
        self.output_tags.add(&tag);
        self.outputs += 1;
        if class == OutputClass::SurvivesCheckpoint {
            self.hint_survivor_tags.add(&tag);
            self.hint_survivors += 1;
            self.survivor_tags.add(&tag);
            self.survivors += 1;
        }
        tag.zeroize();
        self.records += 1;
        Ok(())
    }

    /// Records a locally parsed output and the helper's untrusted checkpoint-survivor bit.
    /// Finalization compares all such hints against the exact local live set.
    pub fn record_output_with_hint(
        &mut self,
        outpoint: &OutPoint,
        coin: &Coin,
        claims_survivor: bool,
    ) -> Result<(), AuditError> {
        self.check_record(coin, false, false)?;
        let mut tag = coin_commitment(
            &self.key,
            self.network,
            self.checkpoint_height,
            self.checkpoint_hash,
            outpoint,
            coin,
        );
        self.output_tags.add(&tag);
        self.outputs += 1;
        if claims_survivor {
            self.hint_survivor_tags.add(&tag);
            self.hint_survivors = self
                .hint_survivors
                .checked_add(1)
                .ok_or(AuditError::CounterOverflow)?;
        }
        tag.zeroize();
        self.records += 1;
        Ok(())
    }

    /// Marks one locally parsed output coin as present at the exact checkpoint.
    pub fn record_survivor(&mut self, outpoint: &OutPoint, coin: &Coin) -> Result<(), AuditError> {
        self.check_tag_metadata(coin)?;
        self.reserve_aux_record()?;
        if self.survivors >= self.outputs || self.survivors.checked_add(1).is_none() {
            self.failed = Some(AuditError::InvalidCounts);
            return Err(AuditError::InvalidCounts);
        }
        let mut tag = coin_commitment(
            &self.key,
            self.network,
            self.checkpoint_height,
            self.checkpoint_hash,
            outpoint,
            coin,
        );
        self.survivor_tags.add(&tag);
        self.survivors += 1;
        tag.zeroize();
        Ok(())
    }

    /// Excludes a locally observed output incarnation overwritten by a consensus-valid
    /// BIP30 exception. This is distinct from a transaction input spend, so it is subtracted
    /// from the output side of the checkpoint aggregate without adding an input record.
    pub fn record_overwritten_output(
        &mut self,
        outpoint: &OutPoint,
        coin: &Coin,
    ) -> Result<(), AuditError> {
        self.check_tag_metadata(coin)?;
        self.reserve_aux_record()?;
        if self.overwritten.checked_add(1).is_none() {
            self.failed = Some(AuditError::CounterOverflow);
            return Err(AuditError::CounterOverflow);
        }
        let mut tag = coin_commitment(
            &self.key,
            self.network,
            self.checkpoint_height,
            self.checkpoint_hash,
            outpoint,
            coin,
        );
        self.overwritten_tags.add(&tag);
        self.overwritten += 1;
        tag.zeroize();
        Ok(())
    }

    /// Records a coin supplied for a locally observed transaction input.
    pub fn record_input_coin(
        &mut self,
        outpoint: &OutPoint,
        coin: &Coin,
    ) -> Result<(), AuditError> {
        self.check_record(coin, true, false)?;
        let mut tag = coin_commitment(
            &self.key,
            self.network,
            self.checkpoint_height,
            self.checkpoint_hash,
            outpoint,
            coin,
        );
        self.input_tags.add(&tag);
        tag.zeroize();
        self.input_coins += 1;
        self.records += 1;
        Ok(())
    }

    /// Consumes this session and compares the supplied finish context and aggregate balance.
    pub fn finish(
        &self,
        network: Network,
        checkpoint_height: u32,
        checkpoint_hash: BlockHash,
    ) -> Result<AuditReport, AuditError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if self.network != network
            || self.checkpoint_height != checkpoint_height
            || self.checkpoint_hash != checkpoint_hash
        {
            return Err(AuditError::CheckpointMismatch);
        }
        let expected_spent = self
            .outputs
            .checked_sub(self.survivors)
            .and_then(|count| count.checked_sub(self.overwritten))
            .ok_or(AuditError::InvalidCounts)?;
        let mut expected_bytes = self.output_tags.to_bytes();
        let mut survivor_bytes = self.survivor_tags.to_bytes();
        let mut hint_survivor_bytes = self.hint_survivor_tags.to_bytes();
        let mut overwritten_bytes = self.overwritten_tags.to_bytes();
        for offset in (0..32).step_by(8) {
            let expected = u64::from_le_bytes(
                expected_bytes[offset..offset + 8]
                    .try_into()
                    .unwrap_or_default(),
            );
            let survivor = u64::from_le_bytes(
                survivor_bytes[offset..offset + 8]
                    .try_into()
                    .unwrap_or_default(),
            );
            let overwritten = u64::from_le_bytes(
                overwritten_bytes[offset..offset + 8]
                    .try_into()
                    .unwrap_or_default(),
            );
            expected_bytes[offset..offset + 8].copy_from_slice(
                &expected
                    .wrapping_sub(survivor)
                    .wrapping_sub(overwritten)
                    .to_le_bytes(),
            );
        }
        let mut input_bytes = self.input_tags.to_bytes();
        let verdict = if expected_spent == self.input_coins
            && expected_bytes == input_bytes
            && self.hint_survivors == self.survivors
            && hint_survivor_bytes == survivor_bytes
        {
            AuditVerdict::Match
        } else {
            AuditVerdict::Mismatch
        };
        // Wipe stack copies of keyed intermediate aggregates before returning counters.
        expected_bytes.zeroize();
        survivor_bytes.zeroize();
        hint_survivor_bytes.zeroize();
        overwritten_bytes.zeroize();
        input_bytes.zeroize();
        Ok(AuditReport {
            outputs: self.outputs,
            survivors: self.survivors,
            overwritten_outputs: self.overwritten,
            input_coins: self.input_coins,
            verdict,
        })
    }

    fn check_record(
        &mut self,
        coin: &Coin,
        is_input: bool,
        is_survivor: bool,
    ) -> Result<(), AuditError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if coin.out.script_pubkey.len() > MAX_AUDIT_SCRIPT_BYTES {
            self.failed = Some(AuditError::ScriptTooLarge);
            return Err(AuditError::ScriptTooLarge);
        }
        if self.records == MAX_AUDIT_RECORDS {
            self.failed = Some(AuditError::RecordLimitExceeded);
            return Err(AuditError::RecordLimitExceeded);
        }
        if self.records.checked_add(1).is_none()
            || (is_input && self.input_coins.checked_add(1).is_none())
            || (!is_input && self.outputs.checked_add(1).is_none())
            || (is_survivor && self.survivors.checked_add(1).is_none())
        {
            self.failed = Some(AuditError::CounterOverflow);
            return Err(AuditError::CounterOverflow);
        }
        Ok(())
    }

    fn check_tag_metadata(&mut self, coin: &Coin) -> Result<(), AuditError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if coin.out.script_pubkey.len() > MAX_AUDIT_SCRIPT_BYTES {
            self.failed = Some(AuditError::ScriptTooLarge);
            return Err(AuditError::ScriptTooLarge);
        }
        Ok(())
    }

    fn reserve_aux_record(&mut self) -> Result<(), AuditError> {
        if self.records == MAX_AUDIT_RECORDS {
            self.failed = Some(AuditError::RecordLimitExceeded);
            return Err(AuditError::RecordLimitExceeded);
        }
        self.records = self
            .records
            .checked_add(1)
            .ok_or(AuditError::CounterOverflow)?;
        Ok(())
    }
}

impl Drop for SwiftAudit {
    fn drop(&mut self) {
        self.key.zeroize();
        self.output_tags = TagAgg::default();
        self.survivor_tags = TagAgg::default();
        self.hint_survivor_tags = TagAgg::default();
        self.overwritten_tags = TagAgg::default();
        self.input_tags = TagAgg::default();
    }
}

fn network_tag(network: Network) -> u8 {
    match network {
        Network::Mainnet => 0,
        Network::Testnet4 => 1,
        Network::Signet => 2,
        Network::Regtest => 3,
    }
}

fn network_from_tag(tag: u8) -> Option<Network> {
    match tag {
        0 => Some(Network::Mainnet),
        1 => Some(Network::Testnet4),
        2 => Some(Network::Signet),
        3 => Some(Network::Regtest),
        _ => None,
    }
}

fn state_checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(STATE_DOMAIN);
    hash.update(bytes);
    hash.finalize().into()
}

fn ct_eq(expected: &[u8; 32], actual: &[u8]) -> bool {
    if actual.len() != 32 {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in expected.iter().zip(actual) {
        diff |= left ^ right;
    }
    diff == 0
}

/// Canonical full-coin keyed commitment, with every variable-length field framed.
fn coin_commitment(
    key: &[u8; 32],
    network: Network,
    checkpoint_height: u32,
    checkpoint_hash: BlockHash,
    outpoint: &OutPoint,
    coin: &Coin,
) -> [u8; 32] {
    let script = coin.out.script_pubkey.as_bytes();
    let mut hmac = HmacSha256::new(key);
    hmac.update(COIN_DOMAIN);
    hmac.update(&[network_tag(network)]);
    hmac.update(&checkpoint_height.to_le_bytes());
    hmac.update(checkpoint_hash.as_bytes());
    hmac.update(outpoint.txid.as_bytes());
    hmac.update(&outpoint.vout.to_le_bytes());
    hmac.update(&coin.out.value.to_le_bytes());
    hmac.update(&(script.len() as u64).to_le_bytes());
    hmac.update(script);
    hmac.update(&coin.height.to_le_bytes());
    hmac.update(&[u8::from(coin.coinbase)]);
    hmac.finalize()
}

/// Small streaming HMAC-SHA256 implementation, kept local to avoid a new dependency.
struct HmacSha256 {
    inner: Sha256,
    outer_pad: [u8; HMAC_BLOCK_BYTES],
}

impl HmacSha256 {
    fn new(key: &[u8]) -> Self {
        let mut key_block = [0u8; HMAC_BLOCK_BYTES];
        if key.len() > HMAC_BLOCK_BYTES {
            let key_hash = Sha256::digest(key);
            key_block[..32].copy_from_slice(&key_hash);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }
        let mut inner_pad = [0x36; HMAC_BLOCK_BYTES];
        let mut outer_pad = [0x5c; HMAC_BLOCK_BYTES];
        for index in 0..HMAC_BLOCK_BYTES {
            inner_pad[index] ^= key_block[index];
            outer_pad[index] ^= key_block[index];
        }
        key_block.zeroize();
        let mut inner = Sha256::new();
        inner.update(inner_pad);
        inner_pad.zeroize();
        Self { inner, outer_pad }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.inner.update(bytes);
    }

    fn finalize(mut self) -> [u8; 32] {
        let mut inner_digest: [u8; 32] = self.inner.finalize().into();
        let mut outer = Sha256::new();
        outer.update(self.outer_pad);
        outer.update(inner_digest);
        let digest = outer.finalize().into();
        inner_digest.zeroize();
        self.outer_pad.zeroize();
        digest
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::{
        AuditError, AuditVerdict, HmacSha256, MAX_AUDIT_RECORDS, OutputClass, SwiftAudit,
        coin_commitment,
    };
    use crate::connect::Coin;
    use crate::hash::{BlockHash, Txid};
    use crate::params::Network;
    use crate::transaction::{OutPoint, Script, TxOut};

    const NETWORK: Network = Network::Regtest;
    const HEIGHT: u32 = 42;
    const CHECKPOINT: BlockHash = BlockHash::ZERO;
    const KEY: [u8; 32] = [0x42; 32];

    fn outpoint(byte: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: Txid::from_bytes([byte; 32]),
            vout,
        }
    }

    fn coin(value: i64, script: &[u8], height: u32, coinbase: bool) -> Coin {
        Coin {
            out: TxOut {
                value,
                script_pubkey: Script::new(script.to_vec()),
            },
            height,
            coinbase,
        }
    }

    fn audit() -> SwiftAudit {
        SwiftAudit::with_test_key(NETWORK, HEIGHT, CHECKPOINT, &KEY)
    }

    fn report(audit: SwiftAudit) -> super::AuditReport {
        audit.finish(NETWORK, HEIGHT, CHECKPOINT).unwrap()
    }

    #[test]
    fn hmac_sha256_rfc_4231_case_1() {
        let key = [0x0b; 20];
        let mut mac = HmacSha256::new(&key);
        mac.update(b"Hi There");
        assert_eq!(
            mac.finalize(),
            [
                0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
                0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
                0x2e, 0x32, 0xcf, 0xf7,
            ]
        );
    }

    #[test]
    fn hmac_sha256_rfc_4231_case_6_long_key() {
        let key = [0xaa; 131];
        let mut mac = HmacSha256::new(&key);
        mac.update(b"Test Using Larger Than Block-Size Key - Hash Key First");
        assert_eq!(
            mac.finalize(),
            [
                0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5,
                0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f,
                0x0e, 0xe3, 0x7f, 0x54,
            ]
        );
    }

    #[test]
    fn honest_stream_is_order_independent() {
        let a = outpoint(1, 0);
        let b = outpoint(2, 1);
        let c = outpoint(3, 0);
        let ca = coin(10, &[0x51], 1, false);
        let cb = coin(20, &[0x00, 0x14, 1], 2, false);
        let cc = coin(30, &[0x51, 0x51], 3, true);
        let mut session = audit();
        session
            .record_output(&a, &ca, OutputClass::SpentByCheckpoint)
            .unwrap();
        session
            .record_output(&b, &cb, OutputClass::SurvivesCheckpoint)
            .unwrap();
        session
            .record_output(&c, &cc, OutputClass::SpentByCheckpoint)
            .unwrap();
        session.record_input_coin(&c, &cc).unwrap();
        session.record_input_coin(&a, &ca).unwrap();
        assert_eq!(report(session).verdict, AuditVerdict::Match);
    }

    #[test]
    fn altered_coin_fields_mismatch() {
        let op = outpoint(7, 9);
        let original = coin(50, &[0x51, 0x00], 123, false);
        let variants = [
            (outpoint(8, 9), original.clone()),
            (outpoint(7, 10), original.clone()),
            (op, coin(51, &[0x51, 0x00], 123, false)),
            (op, coin(50, &[0x51, 1], 123, false)),
            (op, coin(50, &[0x51], 123, false)),
            (op, coin(50, &[0x51, 0x00], 124, false)),
            (op, coin(50, &[0x51, 0x00], 123, true)),
        ];
        for (input_op, input_coin) in variants {
            let mut session = audit();
            session
                .record_output(&op, &original, OutputClass::SpentByCheckpoint)
                .unwrap();
            session.record_input_coin(&input_op, &input_coin).unwrap();
            assert_eq!(report(session).verdict, AuditVerdict::Mismatch);
        }
    }

    #[test]
    fn duplicate_missing_and_misclassified_spends_mismatch() {
        let op = outpoint(1, 0);
        let c = coin(1, &[0x51], 1, false);

        let mut duplicate = audit();
        duplicate
            .record_output(&op, &c, OutputClass::SpentByCheckpoint)
            .unwrap();
        duplicate.record_input_coin(&op, &c).unwrap();
        duplicate.record_input_coin(&op, &c).unwrap();
        assert_eq!(report(duplicate).verdict, AuditVerdict::Mismatch);

        let mut missing = audit();
        missing
            .record_output(&op, &c, OutputClass::SpentByCheckpoint)
            .unwrap();
        assert_eq!(report(missing).verdict, AuditVerdict::Mismatch);

        let mut lying_survivor = audit();
        lying_survivor
            .record_output(&op, &c, OutputClass::SurvivesCheckpoint)
            .unwrap();
        lying_survivor.record_input_coin(&op, &c).unwrap();
        assert_eq!(report(lying_survivor).verdict, AuditVerdict::Mismatch);
    }

    #[test]
    fn exact_bip30_overwrite_is_not_counted_as_an_input_spend() {
        let op = outpoint(0x2a, 0);
        let old = coin(5_000, &[0x51], 10, true);
        let new = coin(5_000, &[0x51], 20, true);
        let mut session = audit();
        // The helper survivor bit describes the final incarnation. The prior
        // BIP30 incarnation is intentionally classified as non-surviving;
        // audit it as an overwrite, not as an input spend.
        session.record_output_with_hint(&op, &old, false).unwrap();
        session.record_output_with_hint(&op, &new, true).unwrap();
        session.record_overwritten_output(&op, &old).unwrap();
        session.record_survivor(&op, &new).unwrap();
        let report = report(session);
        assert_eq!(report.verdict, AuditVerdict::Match);
        assert_eq!(report.outputs, 2);
        assert_eq!(report.overwritten_outputs, 1);
        assert_eq!(report.input_coins, 0);
    }

    #[test]
    fn helper_survivor_hints_must_match_exact_live_survivors() {
        let op = outpoint(0x33, 2);
        let c = coin(8_000, &[0x51], 19, false);
        let mut honest = audit();
        honest.record_output_with_hint(&op, &c, true).unwrap();
        honest.record_survivor(&op, &c).unwrap();
        assert_eq!(report(honest).verdict, AuditVerdict::Match);

        let mut lying = audit();
        lying.record_output_with_hint(&op, &c, false).unwrap();
        lying.record_survivor(&op, &c).unwrap();
        assert_eq!(report(lying).verdict, AuditVerdict::Mismatch);
    }

    #[test]
    fn persistent_audit_roundtrips_and_rejects_tampering() {
        let op = outpoint(0x44, 1);
        let c = coin(9_000, &[0x51, 0x51], 21, false);
        let mut session = audit();
        session.record_output_with_hint(&op, &c, true).unwrap();
        let mut encoded = session.persisted_state().unwrap();
        let mut resumed =
            SwiftAudit::from_persisted_state(&encoded, NETWORK, HEIGHT, CHECKPOINT).unwrap();
        resumed.record_survivor(&op, &c).unwrap();
        assert_eq!(report(resumed).verdict, AuditVerdict::Match);
        encoded[90] ^= 1;
        assert_eq!(
            SwiftAudit::from_persisted_state(&encoded, NETWORK, HEIGHT, CHECKPOINT).err(),
            Some(AuditError::CheckpointMismatch)
        );
    }

    #[test]
    fn wrong_finish_network_or_checkpoint_fails() {
        assert_eq!(
            audit().finish(Network::Mainnet, HEIGHT, CHECKPOINT),
            Err(AuditError::CheckpointMismatch)
        );
        assert_eq!(
            audit().finish(NETWORK, HEIGHT + 1, CHECKPOINT),
            Err(AuditError::CheckpointMismatch)
        );
        assert_eq!(
            audit().finish(NETWORK, HEIGHT, BlockHash::from_bytes([1; 32])),
            Err(AuditError::CheckpointMismatch)
        );
    }

    #[test]
    fn framing_network_checkpoint_and_key_separate_commitments() {
        let op = outpoint(1, 2);
        let c = coin(3, &[4, 5], 6, true);
        let base = coin_commitment(&KEY, NETWORK, HEIGHT, CHECKPOINT, &op, &c);
        assert_ne!(
            base,
            coin_commitment(&[0x43; 32], NETWORK, HEIGHT, CHECKPOINT, &op, &c)
        );
        assert_ne!(
            base,
            coin_commitment(&KEY, Network::Mainnet, HEIGHT, CHECKPOINT, &op, &c)
        );
        assert_ne!(
            base,
            coin_commitment(&KEY, NETWORK, HEIGHT + 1, CHECKPOINT, &op, &c)
        );
        assert_ne!(
            base,
            coin_commitment(
                &KEY,
                NETWORK,
                HEIGHT,
                BlockHash::from_bytes([9; 32]),
                &op,
                &c
            )
        );
        assert_ne!(
            coin_commitment(
                &KEY,
                NETWORK,
                HEIGHT,
                CHECKPOINT,
                &op,
                &coin(3, &[4, 5, 0], 6, true)
            ),
            coin_commitment(
                &KEY,
                NETWORK,
                HEIGHT,
                CHECKPOINT,
                &op,
                &coin(3, &[4, 5, 0, 0], 6, true)
            ),
        );
    }

    #[test]
    fn hmac_domain_separation_changes_commitment() {
        let mut audit_domain = HmacSha256::new(&KEY);
        audit_domain.update(b"Avila SwiftAudit coin commitment v1\0");
        audit_domain.update(b"same record");
        let mut other_domain = HmacSha256::new(&KEY);
        other_domain.update(b"another protocol domain\0");
        other_domain.update(b"same record");
        assert_ne!(audit_domain.finalize(), other_domain.finalize());
    }

    #[test]
    fn record_bound_is_enforced() {
        let mut session = audit();
        session.records = MAX_AUDIT_RECORDS;
        assert_eq!(
            session.record_input_coin(&outpoint(1, 0), &coin(1, &[], 1, false)),
            Err(AuditError::RecordLimitExceeded)
        );
        assert_eq!(
            session.finish(NETWORK, HEIGHT, CHECKPOINT),
            Err(AuditError::RecordLimitExceeded)
        );
    }

    #[test]
    fn count_overflow_is_a_typed_failure() {
        let mut session = audit();
        session.outputs = u64::MAX;
        assert_eq!(
            session.record_output(
                &outpoint(1, 0),
                &coin(1, &[], 1, false),
                OutputClass::SpentByCheckpoint,
            ),
            Err(AuditError::CounterOverflow)
        );
    }
}
