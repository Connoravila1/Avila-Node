# Per-peer adversarial budgets

Queue #14: the resources a single remote peer may consume, stated as a
contract with enforcement points and tests. A peer that exceeds any row
is disconnected; no row may be bypassed by message ordering or rate.

## Wire and transport

| Resource | Limit | Enforcement | Test |
|---|---|---|---|
| Frame payload | 4,000,000 B (`codec::MAX_MESSAGE_PAYLOAD`, Core's `MAX_PROTOCOL_MESSAGE_LENGTH`) | `FrameDecoder::next` rejects oversized declarations | `codec` oversized tests, `oversized_contents_length_is_rejected_at_the_correct_bound` |
| Decode buffer | header + 4 MB (`FrameDecoder::over_buffered`) | buffered bytes past the cap → drop | `adversarial_livewire_budgets_hold` |
| Send queue | 8 MiB (`SEND_BUDGET_PER_PEER`) | `Session::send` errors when `send_buf` would exceed it | `session::send_budget_is_enforced` |
| Handshake | 60 s (`HANDSHAKE_TIMEOUT`) | `check_handshake_timeout` per tick | session handshake tests |
| Garbage bytes | any non-frame input | decode error → disconnect | `adversarial_livewire_budgets_hold` |

## Sync work

| Resource | Limit | Enforcement | Test |
|---|---|---|---|
| Blocks in flight / peer | 16 (`MAX_BLOCKS_IN_TRANSIT_PER_PEER`) | `PeerSync` request window | sync queue tests |
| Blocks in flight / total | 1024 (`MAX_BLOCKS_IN_TRANSIT_TOTAL`) | global free list | manager tests |
| Stalled block | 2 s (`BLOCK_STALLING_TIMEOUT`) then re-ask another peer | `PeerSync::stalled` | sync tests |
| Headers answer | 120 s (`HEADERS_RESPONSE_TIME`) | `headers_timed_out` → disconnect | manager tests |
| Headers catch-up deadline | 15 min base + 1 ms/header | `headers_sync_deadline` → disconnect | manager tests |
| Address gossip | 0.1 addr/s, burst 1000 (token bucket) | `addr_token_bucket` | `full_set_evicts_*`, addr tests |

## Tx relay

| Resource | Limit | Enforcement | Test |
|---|---|---|---|
| Recon round state | one open round per peer | `recon_round` Option | recon tests |
| Announced-not-delivered | tracked per peer | `in_flight` accounting | manager tests |
| Stem delay | 2–15 s randomized | `stem_fluff_pass` | `selfish_stem_announces_one_hop_then_fluffs` |
| Rebroadcast cadence | ≥60 s between passes | `rebroadcast_pass` | broadcast-pool tests |

## Connection accounting

| Resource | Limit | Enforcement | Test |
|---|---|---|---|
| Total peers | `DEFAULT_MAX_PEERS` = 8 (configurable) | `has_slot`/`outbound_open` | `full_set_evicts_least_useful_inbound` |
| Pending accepts | 32 (`MAX_PENDING_ACCEPTS`) | `accept_peer` queue | manager tests |
| Inbound eviction | unprotected only, randomized pick | `evict_inbound` | eviction tests |
| Useful-peer protection | 20 min (`USEFUL_PROTECTION_WINDOW`) | eviction scoring | `full_set_evicts_*` |
| Peer churn | reconnects get fresh budgets (state per connection) | `PeerEntry` lifecycle | — |

## What's NOT bounded yet

- CPU per peer during message dispatch — measured but not enforced
  per-peer; a pathological message could cost disproportionate
  validate work before the frame budget trips it.
- ~~Recon bisection depth~~ — sketch wire size capped at 2,048
  fields; rounds are bounded by the 2-sketch half-pool close.
- ~~getcf* rate limiting~~ — 1 req/s + burst 20 token bucket;
  exhausted peers are silently unserved.

These rows are the honest gaps — closing them is queue work, not a
claim made before it exists.
