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

/// Maximum records accepted for one bounded checkpoint window, counting outputs and input
/// coins together. Sessions cannot be merged independently.
pub const MAX_AUDIT_RECORDS: u64 = 100_000_000;
/// Maximum script length hashed in one record. This bounds work per call.
pub const MAX_AUDIT_SCRIPT_BYTES: usize = 10_000;
const HMAC_BLOCK_BYTES: usize = 64;
const COIN_DOMAIN: &[u8] = b"Avila SwiftAudit coin commitment v1\0";

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
    /// Number of observed input-coin records.
    pub input_coins: u64,
    /// Aggregate comparison result.
    pub verdict: AuditVerdict,
}

/// A bounded failure from a shadow audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditError {
    /// OS-provided entropy could not be read.
    RandomnessUnavailable,
    /// An output or input coin script exceeds the per-record work bound.
    ScriptTooLarge,
    /// The session record cap was reached.
    RecordLimitExceeded,
    /// Internal count arithmetic overflowed.
    CounterOverflow,
    /// The finish context differs from the session's checkpoint binding.
    CheckpointMismatch,
    /// The claimed survivor count exceeds the number of output records.
    InvalidCounts,
}

/// One audit session. Its secret key and intermediate aggregates are never exposed.
///
/// Create a session with [`Self::new`], feed all parsed output records and observed input
/// coins, then consume it with [`Self::finish`]. This is an experimental shadow diagnostic
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
    input_tags: TagAgg,
    outputs: u64,
    survivors: u64,
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
            input_tags: TagAgg::default(),
            outputs: 0,
            survivors: 0,
            input_coins: 0,
            records: 0,
            failed: None,
        }
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
            self.survivor_tags.add(&tag);
            self.survivors += 1;
        }
        tag.zeroize();
        self.records += 1;
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
        self,
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
            .ok_or(AuditError::InvalidCounts)?;
        let mut expected_bytes = self.output_tags.to_bytes();
        let mut survivor_bytes = self.survivor_tags.to_bytes();
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
            expected_bytes[offset..offset + 8]
                .copy_from_slice(&expected.wrapping_sub(survivor).to_le_bytes());
        }
        let mut input_bytes = self.input_tags.to_bytes();
        let verdict = if expected_spent == self.input_coins && expected_bytes == input_bytes {
            AuditVerdict::Match
        } else {
            AuditVerdict::Mismatch
        };
        // Wipe stack copies of keyed intermediate aggregates before returning counters.
        expected_bytes.zeroize();
        survivor_bytes.zeroize();
        input_bytes.zeroize();
        Ok(AuditReport {
            outputs: self.outputs,
            survivors: self.survivors,
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
        if self.records >= MAX_AUDIT_RECORDS {
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
}

impl Drop for SwiftAudit {
    fn drop(&mut self) {
        self.key.zeroize();
        self.output_tags = TagAgg::default();
        self.survivor_tags = TagAgg::default();
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
