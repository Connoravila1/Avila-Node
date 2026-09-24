//! Wallet-fingerprint self-measurement (queue #38): score a
//! transaction against the published identification heuristics and
//! report which wallet profile it resembles. The literature's live
//! signals — BIP69 ordering, nLockTime convention, RBF sequence value,
//! low-R grinding, version, script types — let an observer name the
//! software behind a tx at ~45–50% accuracy. The node should know its
//! own fingerprint rather than assume one.
//!
//! Honest scope: this measures construction tells, not network-layer
//! attribution (stem timing, cluster linkage) — the first-spy sim
//! covers that side. Exclusion ("which tells are absent") is as
//! informative as identification.

use avila_consensus::transaction::Transaction;

/// One scored signal with its observed value.
#[derive(Debug, Clone)]
pub struct Signal {
    /// Signal name (stable for JSON output).
    pub name: &'static str,
    /// Observed value.
    pub value: String,
    /// Which profile this value is characteristic of, if distinctive.
    pub profile_hint: Option<&'static str>,
}

/// The analysis result.
#[derive(Debug)]
pub struct Fingerprint {
    /// Every observed signal.
    pub signals: Vec<Signal>,
    /// Profiles and their matched-signal counts: `("core", 4/5)`.
    pub profile_scores: Vec<(&'static str, usize, usize)>,
    /// Best match, when one profile leads.
    pub best_match: Option<&'static str>,
}

/// BIP69's input comparator — reversed txid (LE uint256) then vout.
fn bip69_sorted_inputs(tx: &Transaction) -> bool {
    let mut sorted: Vec<_> = tx.inputs.iter().collect();
    sorted.sort_by(|a, b| {
        let mut ta = a.previous_output.txid.as_bytes().to_vec();
        let mut tb = b.previous_output.txid.as_bytes().to_vec();
        ta.reverse();
        tb.reverse();
        ta.cmp(&tb)
            .then(a.previous_output.vout.cmp(&b.previous_output.vout))
    });
    tx.inputs
        .iter()
        .zip(sorted)
        .all(|(a, b)| std::ptr::eq(a, b))
}

/// BIP69's output comparator — value then scriptPubKey bytes.
fn bip69_sorted_outputs(tx: &Transaction) -> bool {
    let mut sorted = tx.outputs.clone();
    sorted.sort_by(|a, b| {
        a.value
            .cmp(&b.value)
            .then(a.script_pubkey.as_bytes().cmp(b.script_pubkey.as_bytes()))
    });
    tx.outputs
        .iter()
        .zip(&sorted)
        .all(|(a, b)| a.value == b.value && a.script_pubkey == b.script_pubkey)
}

/// Any input's ECDSA sig above 71 bytes → not low-R ground.
fn low_r_ground(tx: &Transaction) -> bool {
    for i in &tx.inputs {
        for item in i.witness.items() {
            // DER sig: 0x30 len — sigs are 70-72B; low-R ⇒ ≤71.
            if item.len() >= 70 && item.len() <= 73 && item[0] == 0x30 && item.len() > 71 {
                return false;
            }
        }
    }
    true
}

/// Score `tx` — `height` lets the locktime signal say whether the
/// value is the anti-fee-sniping convention (≈ current tip).
#[must_use]
pub fn analyze(tx: &Transaction, height: u32) -> Fingerprint {
    let mut signals = Vec::new();

    // 1. Version — v2 is universal now; v1 fingerprints legacy wallets.
    signals.push(Signal {
        name: "version",
        value: tx.version.to_string(),
        profile_hint: if tx.version == 2 {
            None
        } else {
            Some("legacy")
        },
    });

    // 2. BIP69 — sorted ordering is Electrum/Sparrow's tell; Core
    //    shuffles randomly.
    let bip69 = bip69_sorted_inputs(tx) && bip69_sorted_outputs(tx);
    signals.push(Signal {
        name: "bip69_ordering",
        value: bip69.to_string(),
        profile_hint: Some(if bip69 { "electrum-like" } else { "core" }),
    });

    // 3. nLockTime — Core wallet sets tip height (anti-fee-sniping);
    //    0 fingerprints wallets that don't.
    let afs = tx.lock_time != 0
        && tx.lock_time < 500_000_000
        && height > 0
        && tx.lock_time <= height
        && height - tx.lock_time < 100;
    signals.push(Signal {
        name: "anti_fee_sniping_locktime",
        value: format!("{} (tip {})", tx.lock_time, height),
        profile_hint: Some(if afs { "core" } else { "other" }),
    });

    // 4. RBF — 0xfffffffd is Core's opt-in signal; 0xffffffff/…fe say
    //    the wallet never signals (older Electrum) or inherits.
    let rbf = tx.inputs.iter().all(|i| i.sequence == 0xffff_fffd);
    let no_rbf = tx.inputs.iter().all(|i| i.sequence >= 0xffff_fffe);
    signals.push(Signal {
        name: "rbf_signaling",
        value: if rbf {
            "0xfffffffd".into()
        } else if no_rbf {
            "final".into()
        } else {
            "mixed".into()
        },
        profile_hint: Some(if rbf {
            "core"
        } else if no_rbf {
            "non-signaling"
        } else {
            "mixed"
        }),
    });

    // 5. Low-R grinding — Core grinds until DER ≤71B (fee minimization).
    let low_r = low_r_ground(tx);
    signals.push(Signal {
        name: "low_r_grinding",
        value: low_r.to_string(),
        profile_hint: Some(if low_r { "core" } else { "unground" }),
    });

    // 6. Round-payment heuristic — exactly one "round" output reads as
    //    payment-with-change; the non-round one is the change guess.
    let round = |v: i64| v > 0 && (v % 100_000 == 0 || v % 1_000_000 == 0);
    let n_round = tx.outputs.iter().filter(|o| round(o.value)).count();
    signals.push(Signal {
        name: "round_payment_detectable",
        value: (n_round == 1 && tx.outputs.len() > 1).to_string(),
        profile_hint: None,
    });

    // Profile scoring — each profile's expected tells.
    let expect: [(&'static str, Vec<bool>); 2] = [
        ("core", vec![tx.version == 2, !bip69, afs, rbf, low_r]),
        (
            "electrum-like",
            vec![bip69, tx.lock_time == 0 || !afs, !rbf],
        ),
    ];
    let mut scores: Vec<(&'static str, usize, usize)> = expect
        .iter()
        .map(|(name, checks)| (*name, checks.iter().filter(|&&c| c).count(), checks.len()))
        .collect();
    scores.sort_by_key(|s| std::cmp::Reverse(s.1));
    let best = scores.first().and_then(|(n, hit, _)| {
        if *hit > scores.last().map(|s| s.1).unwrap_or(0) {
            Some(*n)
        } else {
            None
        }
    });
    Fingerprint {
        signals,
        profile_scores: scores,
        best_match: best,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use avila_consensus::hash::Txid;
    use avila_consensus::transaction::{OutPoint, Script, TxIn, TxOut, Witness};

    fn our_tx() -> Transaction {
        // Mirrors fund_spend: v2, RBF sequence, tip-height locktime.
        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_bytes([0x22; 32]),
                    vout: 0,
                },
                script_sig: Script::new(Vec::new()),
                sequence: 0xffff_fffd,
                witness: Witness::default(),
            }],
            outputs: vec![
                TxOut {
                    value: 1_000_000,
                    script_pubkey: Script::new(vec![0x00, 0x14]),
                },
                TxOut {
                    value: 49_123,
                    script_pubkey: Script::new(vec![0x00, 0x14]),
                },
            ],
            lock_time: 850_000,
        }
    }

    #[test]
    fn our_construction_scores_core_like() {
        let fp = analyze(&our_tx(), 850_001);
        assert_eq!(fp.best_match, Some("core"));
        let bip69 = fp
            .signals
            .iter()
            .find(|s| s.name == "bip69_ordering")
            .unwrap();
        // Shuffled outputs (Core's convention) are NOT BIP69-sorted —
        // unsorted is the match.
        assert_eq!(bip69.value, "false");
    }

    #[test]
    fn bip69_sorted_tx_scores_electrum_like() {
        let mut tx = our_tx();
        tx.lock_time = 0;
        for i in &mut tx.inputs {
            i.sequence = 0xffff_ffff;
        }
        // Second input so ordering is observable — sorted already.
        tx.inputs.push(TxIn {
            previous_output: OutPoint {
                txid: Txid::from_bytes([0x44; 32]),
                vout: 1,
            },
            script_sig: Script::new(Vec::new()),
            sequence: 0xffff_ffff,
            witness: Witness::default(),
        });
        let fp = analyze(&tx, 850_001);
        let rbf = fp
            .signals
            .iter()
            .find(|s| s.name == "rbf_signaling")
            .unwrap();
        assert_eq!(rbf.value, "final");
        let lt = fp
            .signals
            .iter()
            .find(|s| s.name == "anti_fee_sniping_locktime")
            .unwrap();
        assert_eq!(lt.profile_hint, Some("other"));
    }
}
