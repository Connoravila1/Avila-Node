//! BIP-330 (Erlay) transaction-reconciliation rounds over
//! [`crate::sketch`]: salted short-ids, the negotiation handshake and
//! the per-connection round state that drives `reqrecon` → `sketch` →
//! `reconcildiff`.
//!
//! A round needs no round-trip to learn a tx the other side already
//! has: the initiator ships a sketch sized for the expected difference;
//! the responder XORs it against its own sketch of its pool and decodes
//! the symmetric difference — short-ids each side holds that the other
//! does not. Misses come back as `reconcildiff` short-id asks and the
//! ordinary `tx`/`inv` paths carry the bodies.
//!
//! Scope note: this is the intra-Avila protocol — no live Core/Knots
//! peer speaks BIP-330 yet, so wire details follow the BIP-330 draft's
//! shape while remaining the only implementation either side will see.

use avila_consensus::gcs::siphash24;

use crate::message::{Message, SendRecon};
use crate::sketch::Sketch;

/// BIP-330 reconciliation protocol version this build negotiates.
pub const RECON_VERSION: u32 = 1;

/// A transaction's 32-bit short-id for one connection — `SipHash-2-4`
/// keyed by the negotiated salt over the txid, truncated. Salted per
/// link so short-ids are not a network-wide identifier (a tx index
/// collision on one link says nothing about others) and cannot be
/// precomputed by an attacker who does not know the salt.
#[must_use]
pub fn short_id(salt: u64, txid: &[u8; 32]) -> u32 {
    siphash24(salt, salt, txid) as u32
}

/// Role negotiation: both sides send [`SendRecon`]; the connection runs
/// rounds only when roles are compatible (one sender, one responder —
/// or both, in which case rounds alternate).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReconPeer {
    /// The peer's salt — keys short-ids it sends us.
    pub their_salt: u64,
    /// Our salt — keys short-ids we send them.
    pub our_salt: u64,
    /// Whether the peer initiates rounds.
    pub they_send: bool,
    /// Whether the peer answers requests.
    pub they_respond: bool,
}

/// What a completed decode produced for one round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundOutcome {
    /// Short-ids present only on the initiator's side — the responder
    /// asks for these (`reconcildiff`).
    pub responder_misses: Vec<u32>,
    /// Short-ids present only on the responder's side — the initiator
    /// should announce them.
    pub initiator_misses: Vec<u32>,
}

/// One side of a reconciliation round in progress.
#[derive(Debug)]
pub struct ReconRound {
    /// Short-ids the initiator sketched over — needed to attribute the
    /// decoded difference back to the correct side.
    initiator_ids: std::collections::HashSet<u32>,
}

impl ReconRound {
    /// Initiator side: build the sketch over `our_ids` and the
    /// `reqrecon` message carrying it.
    #[must_use]
    pub fn open(our_ids: &[u32], capacity: usize) -> (Self, Message) {
        let mut sketch = Sketch::new(capacity);
        for &id in our_ids {
            sketch.add(id);
        }
        (
            Self {
                initiator_ids: our_ids.iter().copied().collect(),
            },
            Message::ReqRecon(sketch.serialize()),
        )
    }

    /// Responder side: merge the initiator's sketch against `our_ids`,
    /// decode the symmetric difference, and answer with a `sketch` of
    /// our own (so the initiator can learn its misses too) plus the
    /// split outcome for the caller to act on.
    #[must_use]
    pub fn answer(&self, their_sketch_bytes: &[u8], our_ids: &[u32]) -> Option<(Message, RoundOutcome)> {
        let mut merged = Sketch::deserialize(their_sketch_bytes)?;
        let mut ours = Sketch::new(merged.capacity());
        for &id in our_ids {
            ours.add(id);
        }
        // Answer carries our raw sketch — the initiator merges it the
        // same way to find ITS misses.
        let reply = Message::Sketch(ours.serialize());
        merged.merge(&ours);
        let diff = merged.decode()?;
        let ours_set: std::collections::HashSet<u32> = our_ids.iter().copied().collect();
        let (mut responder_misses, mut initiator_misses) = (Vec::new(), Vec::new());
        for id in diff {
            if self.initiator_ids.contains(&id) {
                responder_misses.push(id);
            } else if ours_set.contains(&id) {
                initiator_misses.push(id);
            }
            // An id in neither set cannot occur — the merged sketch's
            // difference is drawn from the two input sets by definition.
        }
        Some((reply, RoundOutcome {
            responder_misses,
            initiator_misses,
        }))
    }

    /// Initiator side, closing the round: merge the responder's `sketch`
    /// reply and decode — our misses are the ids in neither the diff's
    /// already-attributed set nor our own pool.
    #[must_use]
    pub fn close(&self, reply_sketch_bytes: &[u8], our_ids: &[u32]) -> Option<Vec<u32>> {
        let mut merged = Sketch::deserialize(reply_sketch_bytes)?;
        let mut ours = Sketch::new(merged.capacity());
        for &id in our_ids {
            ours.add(id);
        }
        merged.merge(&ours);
        let diff = merged.decode()?;
        let ours_set: std::collections::HashSet<u32> = our_ids.iter().copied().collect();
        Some(diff.into_iter().filter(|id| !ours_set.contains(id)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Command;
    use crate::message::Message;

    fn cmd(name: &str) -> Command {
        Command::new(name).unwrap()
    }

    fn pool(base: u32, n: usize, extra: &[u32]) -> Vec<u32> {
        (0..n as u32)
            .map(|i| i.wrapping_mul(2654435761).wrapping_add(base))
            .chain(extra.iter().copied())
            .collect()
    }

    #[test]
    fn short_ids_are_salted() {
        let txid = [7u8; 32];
        assert_ne!(short_id(1, &txid), short_id(2, &txid));
        assert_eq!(short_id(1, &txid), short_id(1, &txid));
    }

    #[test]
    fn recon_wire_roundtrip() {
        let msg = Message::SendRecon(SendRecon {
            is_sender: true,
            is_responder: true,
            version: RECON_VERSION,
            salt: 0xfeed,
        });
        let back = Message::decode(&cmd("sendrecon"), &msg.encode()).unwrap();
        assert_eq!(msg, back);
        let rd = Message::ReconcilDiff {
            ask_parents: 0,
            short_ids: vec![1, 2, 3],
        };
        assert_eq!(
            Message::decode(&cmd("reconcildiff"), &rd.encode()).unwrap(),
            rd
        );
        let sk = Message::ReqRecon(vec![1, 2, 3, 4]);
        assert_eq!(Message::decode(&cmd("reqrecon"), &sk.encode()).unwrap(), sk);
    }

    #[test]
    fn full_recon_round_finds_both_sides_misses() {
        // Shared mempool + 3 initiator-only + 2 responder-only ids.
        let a = pool(0, 5_000, &[0xAAAA, 0xBBBB, 0xCCCC]);
        let b = pool(0, 5_000, &[0x1111, 0x2222]);

        let (round, req) = ReconRound::open(&a, 16);
        let Message::ReqRecon(their_sk) = req else {
            panic!("expected reqrecon")
        };
        let (reply, outcome) = round.answer(&their_sk, &b).expect("decode");
        // Responder learns it is missing the 3 A-only ids.
        assert_eq!(outcome.responder_misses.len(), 3);
        assert_eq!(outcome.initiator_misses.len(), 2);
        // Initiator decodes the reply for its own misses.
        let Message::Sketch(reply_sk) = reply else {
            panic!("expected sketch")
        };
        let misses = round.close(&reply_sk, &a).expect("decode");
        assert_eq!(misses.len(), 2);
        assert!(misses.contains(&0x1111));
    }

    #[test]
    fn over_capacity_round_never_misattributes() {
        // Over-capacity sketches either fail to decode OR spuriously
        // decode to "phantom" ids — elements in neither pool (a known
        // minisketch property: BIP-330 filters decoded ids against the
        // real pools and falls back to reqbisec). What must never
        // happen is a wrong *attribution*: an id claimed as one side's
        // miss that the other side does not actually hold.
        let a = pool(0, 1_000, &(0..200).map(|i| 0xFFFF0000 + i).collect::<Vec<_>>());
        let b = pool(0, 1_000, &[]);
        let a_set: std::collections::HashSet<u32> = a.iter().copied().collect();
        let b_set: std::collections::HashSet<u32> = b.iter().copied().collect();
        let (round, req) = ReconRound::open(&a, 8); // capacity too small for 200
        let Message::ReqRecon(their_sk) = req else {
            panic!("expected reqrecon")
        };
        if let Some((_reply, outcome)) = round.answer(&their_sk, &b) {
            for id in &outcome.responder_misses {
                assert!(a_set.contains(id), "responder miss {id:#x} not in A");
            }
            for id in &outcome.initiator_misses {
                assert!(b_set.contains(id), "initiator miss {id:#x} not in B");
            }
        }
    }
}
