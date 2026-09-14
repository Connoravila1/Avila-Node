//! BIP325 signet block-solution validation — a port of Core's `signet.cpp`
//! (`CheckSignetBlockSolution`, `SignetTxs::Create`,
//! `FetchAndClearCommitmentSection`, `ComputeModifiedMerkleRoot`).
//!
//! A signet block proves authorization by carrying, inside the coinbase's
//! witness-commitment output, a *solution*: the `scriptSig` and witness stack of
//! a synthetic transaction that spends the network's static `signet_challenge`
//! script. The synthetic pair commits to the block's contents, so the solution
//! cannot be replayed onto a different block:
//!
//! * `to_spend` has one output paying `0` to the challenge script and a
//!   `scriptSig` pushing the block's serialization with the merkle root
//!   replaced by one computed over a coinbase whose signet commitment section
//!   has been removed.
//! * `to_sign` spends `to_spend:0` and carries the solution's `scriptSig` and
//!   witness stack; its validity is decided by running Core's `VerifyScript`
//!   with `P2SH | WITNESS | DERSIG | NULLDUMMY`.
//!
//! The genesis block is exempt (`block.GetHash() == consensus.hashGenesisBlock`
//! short-circuits to valid), and a coinbase without a signet commitment section
//! is allowed so that `OP_TRUE` trivial challenges keep working.

use crate::block::Block;
use crate::encode::Decoder;
use crate::interpreter::{get_op, verify_script};
use crate::merkle;
use crate::params::Params;
use crate::script::{ScriptFlags, push_slice};
use crate::sigchecker::{PrecomputedTransactionData, TransactionSignatureChecker};
use crate::transaction::{OutPoint, Script, Transaction, TxIn, TxOut, Witness};

/// `SIGNET_HEADER` (`signet.cpp`): the marker prefixing the signet commitment
/// section inside the coinbase's witness-commitment push.
const SIGNET_HEADER: [u8; 4] = [0xec, 0xc7, 0xda, 0xa2];

/// `BLOCK_SCRIPT_VERIFY_FLAGS` (`signet.cpp`): the flag set `CheckSignetBlockSolution`
/// verifies the challenge spend with.
const BLOCK_SCRIPT_VERIFY_FLAGS: ScriptFlags = ScriptFlags::P2SH
    .union(ScriptFlags::WITNESS)
    .union(ScriptFlags::DERSIG)
    .union(ScriptFlags::NULLDUMMY);

/// `FetchAndClearCommitmentSection` (`signet.cpp`): scans `witness_commitment`'s
/// pushes for the first data push longer than `header` that begins with
/// `header`; the bytes after the header are the section payload. When found, the
/// commitment script is rewritten with the header prefix retained but the
/// payload removed, and the payload is returned. Pushes that don't match, and
/// every non-push opcode, are re-encoded verbatim into the replacement.
fn fetch_and_clear_commitment_section(
    header: &[u8],
    witness_commitment: &mut Vec<u8>,
) -> Option<Vec<u8>> {
    let mut replacement = Vec::new();
    let mut found = false;
    let mut result = Vec::new();

    let mut pc = 0;
    // `GetOp(pc, opcode, pushdata)` — a failed opcode ends the scan.
    while let Some((opcode, pushdata)) = get_op(witness_commitment, &mut pc) {
        if !pushdata.is_empty() {
            if !found && pushdata.len() > header.len() && pushdata[..header.len()] == *header {
                // The push only counts if it has the header *and* some data.
                result.extend_from_slice(&pushdata[header.len()..]);
                replacement.extend_from_slice(&push_slice(&pushdata[..header.len()]));
                found = true;
            } else {
                replacement.extend_from_slice(&push_slice(pushdata));
            }
        } else {
            // `replacement << opcode` — appends the raw opcode byte (this also
            // covers `OP_0` and zero-length `OP_PUSHDATA*` encodings, which
            // Core emits as the bare opcode byte).
            replacement.push(opcode);
        }
    }

    if found {
        *witness_commitment = replacement;
        Some(result)
    } else {
        None
    }
}

/// `ComputeModifiedMerkleRoot` (`signet.cpp`): the txid merkle root of the block
/// with `modified_cb` (coinbase minus the signet commitment section) in place of
/// the real coinbase. Mutation detection is irrelevant here — Core calls the
/// `ComputeMerkleRoot` overload that discards it.
fn compute_modified_merkle_root(modified_cb: &Transaction, block: &Block) -> [u8; 32] {
    let mut leaves = Vec::with_capacity((block.transactions.len() + 1) & !1);
    leaves.push(modified_cb.txid().to_bytes());
    for tx in &block.transactions[1..] {
        leaves.push(tx.txid().to_bytes());
    }
    merkle::merkle_root(&leaves).0
}

/// The two synthetic transactions produced by `SignetTxs::Create` (`signet.cpp`).
struct SignetTxs {
    /// `m_to_spend`: pays `0` to the challenge script; its `scriptSig` pushes the
    /// block header fields with the signet-stripped merkle root.
    to_spend: Transaction,
    /// `m_to_sign`: spends `to_spend:0`; carries the solution's `scriptSig` and
    /// witness stack extracted from the coinbase.
    to_sign: Transaction,
}

/// `SignetTxs::Create` (`signet.cpp`). Returns `None` for every case Core
/// returns `std::nullopt`: no coinbase, no witness-commitment output, a
/// malformed solution payload, or trailing bytes after it.
fn signet_txs(block: &Block, challenge: &Script) -> Option<SignetTxs> {
    let mut to_spend = Transaction {
        version: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint::NULL,
            script_sig: Script::new(vec![0x00]), // CScript(OP_0)
            sequence: 0,
            witness: Witness::EMPTY,
        }],
        outputs: vec![TxOut {
            value: 0,
            script_pubkey: challenge.clone(),
        }],
        lock_time: 0,
    };
    let mut to_sign = Transaction {
        version: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint::NULL,
            script_sig: Script::new(Vec::new()),
            sequence: 0,
            witness: Witness::EMPTY,
        }],
        outputs: vec![TxOut {
            value: 0,
            script_pubkey: Script::new(vec![0x6a]), // CScript(OP_RETURN)
        }],
        lock_time: 0,
    };

    // Find and delete the signet signature from the coinbase.
    let mut modified_cb = block.transactions.first()?.clone();
    let cidx = block.witness_commitment_output()?;

    let mut commitment = modified_cb.outputs[cidx].script_pubkey.as_bytes().to_vec();
    if let Some(solution) = fetch_and_clear_commitment_section(&SIGNET_HEADER, &mut commitment) {
        modified_cb.outputs[cidx].script_pubkey = Script::new(commitment);
        // `v >> scriptSig >> witness.stack` — CompactSize-framed script, then a
        // CompactSize-counted list of CompactSize-framed stack items; trailing
        // bytes or a parse error invalidate the block.
        let mut decoder = Decoder::new(&solution);
        let script_sig = decoder.read_var_bytes().ok()?;
        let count = decoder.read_compact_size().ok()?;
        let mut stack = Vec::new();
        for _ in 0..count {
            stack.push(decoder.read_var_bytes().ok()?);
        }
        if !decoder.is_finished() {
            return None;
        }
        to_sign.inputs[0].script_sig = Script::new(script_sig);
        to_sign.inputs[0].witness = Witness::new(stack);
    }
    // No signet solution is allowed so `OP_TRUE` trivial challenges keep working.

    let signet_merkle = compute_modified_merkle_root(&modified_cb, block);

    // `block_data` serializes nVersion, hashPrevBlock, the modified merkle root
    // and nTime — notably *not* nBits/nNonce (VectorWriter << field order).
    let mut block_data = Vec::with_capacity(72);
    block_data.extend_from_slice(&block.header.version.to_le_bytes());
    block_data.extend_from_slice(block.header.prev_block_hash.as_bytes());
    block_data.extend_from_slice(&signet_merkle);
    block_data.extend_from_slice(&block.header.time.to_le_bytes());
    // `scriptSig << block_data` *appends* the data push to the OP_0 the
    // scriptSig was constructed with — it does not replace it.
    let mut script_sig = vec![0x00];
    script_sig.extend_from_slice(&push_slice(&block_data));
    to_spend.inputs[0].script_sig = Script::new(script_sig);

    to_sign.inputs[0].previous_output = OutPoint {
        txid: to_spend.txid(),
        vout: 0,
    };

    Some(SignetTxs { to_spend, to_sign })
}

/// `CheckSignetBlockSolution` (`signet.cpp`): `true` when the block's signet
/// solution satisfies the network's block challenge. The genesis block is
/// always valid; everything else must carry a valid challenge spend.
#[must_use]
pub fn check_signet_block_solution(block: &Block, params: &Params) -> bool {
    if block.block_hash() == params.genesis_header.hash() {
        // Genesis block solution is always valid.
        return true;
    }

    let challenge = Script::new(params.signet_challenge.to_vec());
    let Some(txs) = signet_txs(block, &challenge) else {
        return false;
    };

    let txdata = PrecomputedTransactionData::new(
        &txs.to_sign,
        Some(vec![txs.to_spend.outputs[0].clone()]),
        false,
    );
    let checker =
        TransactionSignatureChecker::new(&txs.to_sign, 0, txs.to_spend.outputs[0].value, &txdata);

    verify_script(
        &txs.to_sign.inputs[0].script_sig,
        &challenge,
        Some(&txs.to_sign.inputs[0].witness),
        BLOCK_SCRIPT_VERIFY_FLAGS,
        &checker,
    )
    .is_ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::block::Block;
    use crate::params::Network;

    /// The real signet genesis block: exempt from the solution check.
    #[test]
    fn genesis_block_is_always_valid() {
        let block =
            Block::decode(include_bytes!("../../../fixtures/signet-block-000000.bin")).unwrap();
        assert!(check_signet_block_solution(
            &block,
            &Network::Signet.params()
        ));
    }

    /// The real signet block at height 1 carries a genuine 1-of-2 multisig
    /// solution for the default challenge — the full path must verify it.
    #[test]
    fn signet_block_1_solution_verifies() {
        let block =
            Block::decode(include_bytes!("../../../fixtures/signet-block-000001.bin")).unwrap();
        assert!(check_signet_block_solution(
            &block,
            &Network::Signet.params()
        ));
    }

    /// Stripping the signet commitment section must produce a script whose
    /// pushes survive verbatim and whose solution payload is recovered.
    #[test]
    fn fetch_and_clear_extracts_and_rebuilds() {
        // 6a 24 aa21a9ed <32-byte hash> 24 ecc7daa2 <32-byte solution> 51
        let mut commitment = vec![0x6a, 0x24];
        commitment.extend_from_slice(&[0xaa, 0x21, 0xa9, 0xed]);
        commitment.extend_from_slice(&[0x11; 32]);
        commitment.push(0x24);
        commitment.extend_from_slice(&SIGNET_HEADER);
        commitment.extend_from_slice(&[0x22; 32]);
        commitment.push(0x51);
        let original_len = commitment.len();

        let section = fetch_and_clear_commitment_section(&SIGNET_HEADER, &mut commitment).unwrap();
        assert_eq!(section, vec![0x22; 32]);
        // The 36-byte commitment push shrank to a 4-byte push of the header.
        assert_eq!(commitment.len(), original_len - 32);
        let mut expected = vec![0x6a, 0x24];
        expected.extend_from_slice(&[0xaa, 0x21, 0xa9, 0xed]);
        expected.extend_from_slice(&[0x11; 32]);
        expected.extend_from_slice(&[0x04]);
        expected.extend_from_slice(&SIGNET_HEADER);
        expected.push(0x51);
        assert_eq!(commitment, expected);
    }

    /// A header-prefix push with no payload does not count as a section.
    #[test]
    fn header_only_push_is_not_a_section() {
        let mut commitment = vec![0x6a, 0x24];
        commitment.extend_from_slice(&[0xaa, 0x21, 0xa9, 0xed]);
        commitment.extend_from_slice(&[0x11; 32]);
        commitment.push(0x04);
        commitment.extend_from_slice(&SIGNET_HEADER);
        let original = commitment.clone();
        assert!(fetch_and_clear_commitment_section(&SIGNET_HEADER, &mut commitment).is_none());
        assert_eq!(commitment, original);
    }

    /// A block-1 copy with a corrupted solution must fail the challenge.
    #[test]
    fn corrupted_solution_fails() {
        let block =
            Block::decode(include_bytes!("../../../fixtures/signet-block-000001.bin")).unwrap();
        // Flip a byte inside the coinbase's signet solution payload.
        let mut corrupted = block.clone();
        let cidx = corrupted.witness_commitment_output().unwrap();
        let bytes = corrupted.transactions[0].outputs[cidx]
            .script_pubkey
            .as_bytes()
            .to_vec();
        // The solution section sits after the 6-byte commitment header + 32-byte
        // hash + PUSHDATA + 4-byte signet header.
        let mut patched = bytes;
        let last = patched.len() - 1;
        patched[last] ^= 0xff;
        corrupted.transactions[0].outputs[cidx].script_pubkey = Script::new(patched);
        assert!(!check_signet_block_solution(
            &corrupted,
            &Network::Signet.params()
        ));
    }
}
