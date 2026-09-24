# Block-fetch frontier scan — scheduler fix + live re-measure

**Date:** 2026-09-24 · **Status:** ADOPTED — ~5x connected-block
throughput on live signet

## Hypothesis

Exp3's live sync capped at ~1.7 connected blocks/s with in-flight
stuck near the per-peer cap — suspected scheduler, not validation.

## Root cause

`fill_queues` called `cs.tree().headers_by_height()` **per peer per
tick** — a full collect + sort of every indexed header (66k+ at
signet scale), then filtered for unfetched bodies. O(peers x headers)
per tick, growing quadratically as sync progresses; the loop spent its
time sorting instead of refilling queues.

## Fix (`manager.rs`)

- `PeerManager` keeps `fetch_index: Vec<(height, hash)>` — the
  height-sorted header index, **rebuilt only when the header count
  changes** (pages arrive in ~2000-header chunks).
- One shared scan per tick: candidates above the connected frontier
  (`chain().len()` — connected heights have bodies by definition),
  filtered by `have_body` + reservation, capped by the aggregate
  budget; each peer takes a slice.
- Per-peer cap stays Core's 16 — the window, not the scan, was meant
  to be the constraint.

## Measure (same signet config, 190s bounded run)

| | before | after |
|---|---|---|
| connected blocks | 1124 / 600s | 1728 / 192s |
| throughput | ~1.7 blk/s | **~9 blk/s** |
| in-flight | 0-96 | 80-128 (saturated) |

In-flight now rides the 16/peer x ~8-peer window — the limiter is peer
serve latency, which is where it should be. Next lever if needed:
window sizing by observed block size/RTT, not bigger scans.

Not a controlled A/B (different header heights/peer sets) — but the
mechanism (O(n) sort per peer per tick) is unambiguous and the
direction is consistent.
