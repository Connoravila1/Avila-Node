//! A consensus-invalid spend must rewind the speculative tip even when its
//! sidecar falsely claims its signature is true; the original valid branch
//! must then connect to the same complete UTXO state.
use super::*;

pub(super) fn blocks(mut raw: &[u8]) -> Result<Vec<Block>, String> {
    let mut blocks = Vec::new();
    while !raw.is_empty() {
        take(&mut raw, 4)?;
        let len = u32le(&mut raw)? as usize;
        blocks.push(Block::decode(take(&mut raw, len)?).map_err(|e| e.to_string())?);
    }
    Ok(blocks)
}

fn invalid(original: &Block) -> Block {
    let mut block = original.clone();
    // Last tx has no in-block descendants, so its modified txid cannot cause
    // an earlier missing-input rejection. Fee rises by one satoshi.
    let tx = block.transactions.last_mut().unwrap();
    assert!(!tx.is_coinbase() && tx.outputs[0].value > 0);
    tx.outputs[0].value -= 1;
    if let Some(index) = block.witness_commitment_output() {
        let commitment = block.expected_witness_commitment().unwrap();
        let mut script = block.transactions[0].outputs[index]
            .script_pubkey
            .as_bytes()
            .to_vec();
        script[6..38].copy_from_slice(&commitment);
        block.transactions[0].outputs[index].script_pubkey =
            avila_consensus::transaction::Script::new(script);
    }
    block.header.merkle_root = block.merkle_root().0;
    let params = Network::Regtest.params();
    block.header.nonce = 0;
    while avila_consensus::pow::check_proof_of_work(&block.block_hash(), block.header.bits, &params)
        .is_err()
    {
        block.header.nonce += 1;
    }
    avila_consensus::check::check_block(&block, &params).unwrap();
    block
}

/// Create the attack's untrusted frame with the new witness ID but the old
/// nonce hint. Verification still must bind the new local sighash equation.
pub(super) fn advice_for_invalid(raw: &[u8], path: &Path) -> Result<std::path::PathBuf, String> {
    let chain = blocks(raw)?;
    let original = chain.last().unwrap();
    let bad = invalid(original);
    let mut stream = std::fs::read(path).map_err(|e| e.to_string())?;
    if stream.get(..8) == Some(b"AVHINT04") {
        let mut offset = 8;
        let mut found = None;
        while offset < stream.len() {
            if stream.len() - offset < 36 {
                return Err("stream frame".into());
            }
            let size =
                u32::from_le_bytes(stream[offset + 32..offset + 36].try_into().unwrap()) as usize;
            let end = offset + 36 + size;
            if size > 1 << 20 || end > stream.len() {
                return Err("stream bound".into());
            }
            if &stream[offset..offset + 32] == original.block_hash().as_bytes() {
                found = Some((offset, end));
                break;
            }
            offset = end;
        }
        let (offset, end) = found.ok_or("missing original block advice")?;
        let valid = stream[offset..end].to_vec();
        stream[offset..offset + 32].copy_from_slice(bad.block_hash().as_bytes());
        stream.extend_from_slice(&valid);
        let output = path.with_extension("rollback-hints");
        std::fs::write(&output, stream).map_err(|e| e.to_string())?;
        return Ok(output);
    }
    let old_key = original.transactions.last().unwrap().wtxid();
    let new_key = bad.transactions.last().unwrap().wtxid();
    let mut data = std::fs::read(path).map_err(|e| e.to_string())?;
    if data.len() > 32 << 20 || data.get(..8) != Some(b"AVADVC03") {
        return Err("advice bound".into());
    }
    let mut remaining = &data[8..];
    let mut copied = None;
    while !remaining.is_empty() {
        let key = take(&mut remaining, 32)?;
        let count = u32le(&mut remaining)? as usize;
        let hints = take(&mut remaining, count)?;
        if key == old_key.as_bytes() {
            copied = Some(hints.to_vec());
        }
    }
    let hints = copied.ok_or("missing original spend advice")?;
    assert!(hints.iter().any(|h| *h < 4));
    data.extend_from_slice(new_key.as_bytes());
    data.extend_from_slice(&(hints.len() as u32).to_le_bytes());
    data.extend_from_slice(&hints);
    let output = path.with_extension("rollback-advice");
    std::fs::write(&output, data).map_err(|e| e.to_string())?;
    Ok(output)
}

pub(super) fn run(raw: &[u8]) -> Result<Outcome, String> {
    use avila_consensus::chainstate::BlockRejection;
    use avila_consensus::connect::ConnectError;
    let blocks = blocks(raw)?;
    let last = blocks.last().unwrap();
    let params = Network::Regtest.params();
    let now = 2_000_000_000;
    let mut cs = Chainstate::new(&params);
    cs.enable_speculative_connect();
    for block in &blocks[..blocks.len() - 1] {
        cs.accept_block(block, now)
            .map_err(|e| format!("prefix: {e:?}"))?;
    }
    cs.drain_scripts().map_err(|e| e.to_string())?;
    let before = cs.coin_stats(CoinStatsHashType::HashSerialized);
    let before_tip = cs.tip_hash();
    let bad = invalid(last);
    let rejected = match cs.accept_block(&bad, now) {
        Ok(_) => matches!(cs.drain_scripts(), Err(ConnectError::ScriptVerify(_))),
        Err(BlockRejection::Connect(ConnectError::ScriptVerify(_))) => true,
        Err(other) => return Err(format!("wrong rejection: {other:?}")),
    };
    let after = cs.coin_stats(CoinStatsHashType::HashSerialized);
    if !rejected
        || !cs.tree().is_failed(&bad.block_hash())
        || cs.tip_hash() != before_tip
        || after.hash_serialized != before.hash_serialized
        || after.txouts != before.txouts
    {
        return Err("failed script did not restore the exact prefix state".into());
    }
    cs.accept_block(last, now)
        .map_err(|e| format!("valid branch: {e:?}"))?;
    cs.drain_scripts().map_err(|e| e.to_string())?;
    let state = cs.coin_stats(CoinStatsHashType::HashSerialized);
    Ok(Outcome {
        blocks: blocks.len() as u64,
        transactions: blocks.iter().map(|b| b.transactions.len() as u64).sum(),
        hash: state.hash_serialized.unwrap().to_string(),
        coins: state.txouts,
    })
}
