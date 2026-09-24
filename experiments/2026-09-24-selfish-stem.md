# Selfish-stem relay + first-spy measurement

**Queue:** #18 (build), #26 (measure).
**Hypothesis:** locally-originated txs announced to one random outbound
peer, held for a randomized delay, then fluffed — cut first-spy origin
attribution without the stempool DoS that killed Dandelion (BIP156).
**Result:** adopted. Detection 68.9% → 14.4% at 15% spy density.

## The design

Dandelion's stempool relayed *other people's* unvalidated txs — free
bandwidth/CPU for attackers. Selfish-stem relays only OUR txs: fully
validated, pooled, broadcast-pool tracked, announced to one random
outbound peer, fluffed after a 2–15s delay. Zero protocol changes;
the worst case is a slightly later announce.

`stem_announce` in `PeerManager`; `sendrawtransaction` and the
broadcast-pool rebroadcast both route through it. `set_stem_relay`
toggles.

## The measurement

`tools/firstspy_sim.py` — 300-node random graph, 8 outbound links,
15% spies, 4000 runs. A spy records the sender of its earliest
observation of the tx.

| mode | P(first spy names origin) |
|---|---|
| no stem | 0.689 |
| 1-hop stem | 0.144 |

Residual ≈ spy density: a spy directly connected to V still sees V's
fluff arrive before the stem wave wraps around. The 5× reduction is
the honest number for a single hop — multi-hop stem needs peer
cooperation we can't unilaterally add.

## Honest limits

- This hides *timing-origin* from passive first-spy analysis. It does
  not help if every one of our outbound peers is a spy (eclipse).
- Recon rounds still carry the tx — the stem hop buys deniability in
  the inv-timing channel only.
- Pair with the privacy artifact (#25): packet-capture a real run.
