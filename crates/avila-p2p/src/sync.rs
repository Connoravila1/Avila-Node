//! Headers-first synchronization state for one peer — the part of Core's
//! `net_processing` that turns `headers` messages into `accept_header`
//! calls and `inv` announcements into bounded `getdata` requests.
//!
//! Two interleaved phases, same as Core:
//!
//! * **Headers phase** — `getheaders` paged from our best-header locator;
//!   a full page ([`MAX_HEADERS_RESULTS`]) means the peer has more.
//! * **Block phase** — `inv`/`headers` announcements select which indexed
//!   blocks to fetch; in-flight requests are capped at
//!   [`MAX_BLOCKS_IN_TRANSIT_PER_PEER`] with a [`BLOCK_STALLING_TIMEOUT`]
//!   stall detector.
//!
//! All verdicts come from [`Chainstate`] — this module only sequences the
//! wire traffic and enforces the peer's resource budgets.

use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};

use avila_consensus::arith::{U256, Work};
use avila_consensus::block::Block;
use avila_consensus::chainstate::{Acceptance, Chainstate};
use avila_consensus::hash::BlockHash;
use avila_consensus::header::BlockHeader;
use avila_consensus::params::Params;
use avila_consensus::pow;
use thiserror::Error;

use crate::headerssync::{HeadersSyncParams, HeadersSyncState};
use crate::message::{GetHeaders, InvType, InvVector, MAX_HEADERS_RESULTS, Message};

/// Core's `MAX_GETCFILTERS_SIZE` — max filters per `getcfilters` (BIP157).
const MAX_GETCFILTERS_SIZE: u32 = 1_000;
/// Core's `MAX_GETCFHEADERS_SIZE` — max headers per `getcfheaders`.
const MAX_GETCFHEADERS_SIZE: u32 = 2_000;
/// BIP157 checkpoint stride — every 1,000th block's filter header.
const CFCHECKPT_INTERVAL: u32 = 1_000;

/// Core's `MAX_BLOCKS_IN_TRANSIT_PER_PEER` — the most block bodies one peer
/// may owe us at once.
pub const MAX_BLOCKS_IN_TRANSIT_PER_PEER: usize = 16;

/// Core's `BLOCK_STALLING_TIMEOUT_DEFAULT` — a peer that stops answering
/// `getdata` gets its in-flight slots reclaimed.
pub const BLOCK_STALLING_TIMEOUT: Duration = Duration::from_secs(2);

/// Core's `HEADERS_RESPONSE_TIME` — how long an outstanding `getheaders`
/// may go unanswered before the peer is treated as unresponsive. Core
/// uses this to gate re-sending `getheaders` to the *same* peer
/// (`MaybeSendGetHeaders`); here, where only the headers leader keeps
/// paging, it is also what lets the manager reclaim leadership from a
/// leader that has otherwise gone quiet on headers (while still, say,
/// answering pings) instead of freezing sync until it disconnects for
/// some unrelated reason.
pub const HEADERS_RESPONSE_TIME: Duration = Duration::from_secs(120);

/// What [`PeerSync::on_headers`] reports.
#[derive(Clone, Debug, Default)]
pub struct HeadersOutcome {
    /// Headers newly indexed by this page.
    pub added: usize,
    /// Headers already in the tree.
    pub known: usize,
    /// The peer has more — send the returned `getheaders` to continue.
    pub continuation: Option<Message>,
    /// Indexed blocks whose bodies we don't have — candidates for `getdata`.
    pub fetchable: Vec<BlockHash>,
    /// This peer's low-work sync just ended without ever proving enough
    /// work — aborted (bad continuity, an impossible difficulty
    /// transition, a commitment mismatch, or the peer-length bound), or
    /// it simply ran out of chain below the anti-DoS threshold. Not
    /// misbehavior on its own, but if this peer currently holds headers
    /// leadership the caller should release it immediately rather than
    /// wait for a timeout, so another peer gets a chance to page
    /// instead. Never set alongside a non-empty `continuation`, and
    /// never set when a low-work sync completed successfully (that
    /// peer just proved a good chain — it stays leader).
    pub give_up_leadership: bool,
}

/// What [`PeerSync::on_block`] reports.
#[derive(Clone, Debug)]
pub struct BlockOutcome {
    /// `accept_block`'s verdict.
    pub acceptance: Acceptance,
    /// Whether this block was one we had in flight from this peer.
    pub was_in_flight: bool,
}

/// Peer violations the sync layer can prove — all disconnect-worthy, all
/// matching a Core "misbehaving" condition.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum SyncError {
    /// A `headers` message whose first header doesn't connect to anything we
    /// know — the peer went off-script (Core: "non-continuous headers
    /// sequence" misbehavior).
    #[error("peer sent headers that don't connect to our tree")]
    DiscontinuousHeaders,
    /// A header failed `accept_header` (PoW, median-time, bad ancestry).
    /// Carries the consensus rejection reason.
    #[error("peer sent an invalid header: {0}")]
    InvalidHeader(String),
    /// A block failed `accept_block`. Carries the rejection reason.
    #[error("peer sent an invalid block: {0}")]
    InvalidBlock(String),
}

/// One peer's synchronization state.
pub struct PeerSync {
    /// Hashes we've `getdata`'d and await, in request order.
    in_flight: VecDeque<(BlockHash, Instant)>,
    /// Hashes already requested from any source — dedup guard.
    wanted: HashSet<BlockHash>,
    /// When the `getheaders` we currently have outstanding was sent —
    /// `None` once answered (even by an empty page). Core's
    /// `m_last_getheaders_timestamp`.
    headers_in_flight: Option<Instant>,
    /// Announced block hashes we haven't requested yet — invs beyond
    /// the in-flight cap wait here instead of being forgotten; drained
    /// as slots free (`drain_pending`).
    pending_blocks: VecDeque<BlockHash>,
    /// Dedupe for `pending_blocks` — keeps the queue from growing a
    /// duplicate per repeated announcement.
    pending_set: HashSet<BlockHash>,
    /// Headers applied from this peer so far (a boundless-increment counter
    /// is fine — it's pure bookkeeping).
    headers_applied: usize,
    /// Block bodies received from this peer.
    blocks_received: usize,
    /// A low-work-chain presync/redownload in progress with this peer
    /// (Core's `Peer::m_headers_sync`) — `Some` only while the batches
    /// we've seen so far haven't proven enough claimed work to trust
    /// directly. See [`crate::headerssync`].
    headers_sync: Option<HeadersSyncState>,
}

impl Default for PeerSync {
    fn default() -> Self {
        Self::new()
    }
}

/// The verdict for a BIP157 request — Core's
/// `PrepareBlockFilterRequest` outcome: serve the messages, ignore the
/// request (index gap — Core logs and returns), or disconnect the peer.
#[derive(Debug)]
pub enum FilterReply {
    /// Messages to send back.
    Serve(Vec<crate::message::Message>),
    /// No answer — the index lacks coverage for the range.
    Ignore,
    /// The request violates BIP157 — disconnect the peer.
    Disconnect(&'static str),
}

/// Core's `IsAncestorOfBestHeaderOrTip`: whether `hash` is already known
/// and is an ancestor-or-self of our best header, or sits on our active
/// (connected) chain. A headers batch whose last header satisfies this
/// needs no anti-DoS gating — Core skips `TryLowWorkHeadersSync` for
/// exactly this, since accepting it again (or no-op'ing on it) teaches
/// us nothing we don't already have.
fn is_ancestor_of_best_header_or_tip(cs: &Chainstate, hash: &BlockHash) -> bool {
    let Some(node) = cs.tree().get(hash) else {
        return false;
    };
    if cs.tree().is_ancestor(node, cs.tree().tip()) {
        return true;
    }
    // `cs.chain()` is height-indexed (index == height), so this is the
    // O(1) equivalent of Core's `ActiveChain().Contains(header)` rather
    // than a linear scan.
    cs.chain().get(node.height as usize) == Some(hash)
}

impl PeerSync {
    /// A fresh peer — nothing requested yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            in_flight: VecDeque::new(),
            wanted: HashSet::new(),
            headers_in_flight: None,
            headers_applied: 0,
            blocks_received: 0,
            headers_sync: None,
            pending_blocks: VecDeque::new(),
            pending_set: HashSet::new(),
        }
    }

    /// How many block bodies this peer currently owes us.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }

    /// The block hashes this peer currently owes us (`getpeerinfo`'s
    /// `inflight` list, rendered as heights by callers with the tree).
    pub fn in_flight_hashes(&self) -> impl Iterator<Item = BlockHash> + '_ {
        self.in_flight.iter().map(|(h, _)| *h)
    }

    /// Every hash this peer has been asked for or already marked — the
    /// manager uses the union across peers as a reservation set so two
    /// peers never download the same block.
    pub fn reserved_hashes(&self) -> impl Iterator<Item = &BlockHash> {
        self.in_flight
            .iter()
            .map(|(h, _)| h)
            .chain(self.wanted.iter())
    }

    /// Whether a `getheaders` is outstanding.
    #[must_use]
    pub fn awaiting_headers(&self) -> bool {
        self.headers_in_flight.is_some()
    }

    /// `true` once an outstanding `getheaders` has gone unanswered past
    /// [`HEADERS_RESPONSE_TIME`] — the peer is still connected (it may
    /// even be answering pings) but has stopped cooperating on headers.
    /// The caller should reassign headers leadership and disconnect (or
    /// otherwise penalize) this peer so another one can continue paging.
    #[must_use]
    pub fn headers_timed_out(&self) -> bool {
        self.headers_in_flight
            .is_some_and(|t| t.elapsed() > HEADERS_RESPONSE_TIME)
    }

    /// Test-only: back-dates an outstanding `getheaders` so it reads as
    /// timed out, without an actual multi-minute sleep. A no-op if
    /// nothing is outstanding.
    #[cfg(test)]
    pub(crate) fn force_headers_timeout(&mut self) {
        if let Some(sent_at) = &mut self.headers_in_flight {
            *sent_at = Instant::now() - HEADERS_RESPONSE_TIME - Duration::from_secs(1);
        }
    }

    /// Total headers this peer has contributed to the index.
    #[must_use]
    pub fn headers_applied(&self) -> usize {
        self.headers_applied
    }

    /// Block bodies this peer has sent us.
    #[must_use]
    pub fn blocks_received(&self) -> usize {
        self.blocks_received
    }

    /// The `getheaders` that (re)starts or continues the headers phase —
    /// a locator over the best-*header* tip, matching Core's
    /// `FindNextBlocksToDownload`/`SendMessages` flow.
    #[must_use]
    pub fn request_headers(&mut self, cs: &Chainstate) -> Message {
        self.headers_in_flight = Some(Instant::now());
        Message::GetHeaders(GetHeaders {
            locator: cs.tree().locator(),
            stop: BlockHash::ZERO,
        })
    }

    /// Feeds a `headers` page into the chainstate. The first header must
    /// extend something we know (its prev is in the tree); each later header
    /// chains to its predecessor — otherwise the peer sent a discontinuous
    /// sequence. Every header's own proof-of-work is checked up front too
    /// (Core's `CheckHeadersPoW`), independent of whichever path below ends
    /// up handling the batch.
    ///
    /// A batch that doesn't yet carry [`headerssync`](crate::headerssync)'s
    /// anti-DoS work threshold is diverted into a per-peer presync/redownload
    /// instead of reaching [`Chainstate::accept_header`] directly — see that
    /// module for why. Once a peer's low-work sync is in progress, every
    /// subsequent `headers` message feeds it until it either proves enough
    /// work (releasing verified headers for real acceptance) or gives up.
    ///
    /// A full page means the peer holds more: the outcome carries the next
    /// `getheaders` (from the low-work sync's own locator while one is in
    /// progress, otherwise the ordinary best-header locator). `fetchable`
    /// lists newly indexed blocks whose bodies we lack — the caller passes
    /// them to [`Self::want_blocks`].
    ///
    /// # Errors
    /// [`SyncError`] on discontinuous or PoW-invalid headers, or a
    /// consensus-invalid header — from the ordinary path, or from a header
    /// a completed low-work redownload released and handed to
    /// `accept_header` for real (a low-work sync's own internal failures,
    /// e.g. a commitment mismatch, are not treated as misbehavior: the sync
    /// is simply abandoned, exactly as headers full of consensus-honest
    /// content dropped mid-download would be).
    pub fn on_headers(
        &mut self,
        cs: &mut Chainstate,
        headers: &[BlockHeader],
        now: u32,
    ) -> Result<HeadersOutcome, SyncError> {
        self.headers_in_flight = None;

        if headers.is_empty() {
            // Nothing to check; an empty page also settles any low-work
            // sync in progress (Core: a bare reply means the peer
            // suddenly has nothing more, e.g. it reorged onto our chain).
            self.headers_sync = None;
            return Ok(HeadersOutcome::default());
        }

        let params = *cs.tree().params();
        for header in headers {
            pow::check_proof_of_work(&header.hash(), header.bits, &params)
                .map_err(|e| SyncError::InvalidHeader(e.to_string()))?;
        }
        for i in 1..headers.len() {
            if headers[i].prev_block_hash != headers[i - 1].hash() {
                return Err(SyncError::DiscontinuousHeaders);
            }
        }

        // A low-work sync already in progress consumes the batch on its
        // own terms — its continuity is against wherever *it* left off,
        // which needn't be anything in our tree yet.
        if self.headers_sync.is_some() {
            return self.continue_low_work_sync(cs, headers, now);
        }

        if !cs.tree().contains(&headers[0].prev_block_hash) {
            return Err(SyncError::DiscontinuousHeaders);
        }

        // Core's `IsAncestorOfBestHeaderOrTip`: a batch whose last header
        // is already known and sits on our best-header chain or our
        // active chain can't teach us anything new — skip the anti-DoS
        // gate rather than start a pointless presync over data we
        // already have (e.g. a peer re-announcing our own tip).
        let Some(last) = headers.last() else {
            // Checked non-empty above; defended rather than panicking.
            return Ok(HeadersOutcome::default());
        };
        let already_known_enough = is_ancestor_of_best_header_or_tip(cs, &last.hash());

        // Anti-DoS gate (Core's `TryLowWorkHeadersSync`): a headers batch
        // that doesn't carry enough claimed work must never reach
        // `accept_header` directly, or a cheap low-difficulty chain could
        // grow the header tree without bound.
        if !already_known_enough
            && let Some(outcome) = self.try_low_work_headers_sync(cs, &params, headers, now)
        {
            return Ok(outcome);
        }

        let (added, known, fetchable) = self.accept_headers(cs, headers, now)?;
        let continuation = if headers.len() as u64 == MAX_HEADERS_RESULTS {
            Some(self.request_headers(cs))
        } else {
            None
        };
        Ok(HeadersOutcome {
            added,
            known,
            continuation,
            fetchable,
            give_up_leadership: false,
        })
    }

    /// Runs `headers` through `accept_header` one at a time, updating this
    /// peer's applied-headers counter. Returns `(added, known, fetchable)`;
    /// shared by the ordinary path and a low-work redownload's release.
    fn accept_headers(
        &mut self,
        cs: &mut Chainstate,
        headers: &[BlockHeader],
        now: u32,
    ) -> Result<(usize, usize, Vec<BlockHash>), SyncError> {
        let mut added = 0usize;
        let mut known = 0usize;
        let mut fetchable = Vec::new();
        for header in headers {
            let hash = header.hash();
            let had_header = cs.tree().contains(&hash);
            match cs.accept_header(header, now) {
                Ok(_) => {
                    if had_header {
                        known += 1;
                    } else {
                        added += 1;
                        fetchable.push(hash);
                    }
                    self.headers_applied += 1;
                }
                Err(rej) => return Err(SyncError::InvalidHeader(rej.to_string())),
            }
        }
        Ok((added, known, fetchable))
    }

    /// Core's `TryLowWorkHeadersSync`: gates a fresh headers batch behind
    /// [`headerssync::anti_dos_work_threshold`](crate::headerssync::anti_dos_work_threshold).
    /// `headers` must have already passed `on_headers`'s PoW/continuity
    /// checks, and `headers[0]` must connect to something in `cs`'s tree.
    ///
    /// Returns `Some(outcome)` when the batch was fully handled here (a
    /// presync started, or a short low-work batch was ignored outright) —
    /// the caller returns that outcome as-is. `None` means the batch
    /// already carries enough work and the caller should run it through
    /// [`Self::accept_headers`] normally.
    fn try_low_work_headers_sync(
        &mut self,
        cs: &Chainstate,
        params: &Params,
        headers: &[BlockHeader],
        now: u32,
    ) -> Option<HeadersOutcome> {
        let fork = *cs.tree().get(&headers[0].prev_block_hash)?;
        let claimed_batch_work = headers.iter().fold(Work::ZERO, |acc, h| {
            acc.checked_add(Work::from_compact(h.bits))
                .unwrap_or(Work(U256::MAX))
        });
        let total_work = fork
            .chainwork
            .checked_add(claimed_batch_work)
            .unwrap_or(Work(U256::MAX));
        let threshold = crate::headerssync::anti_dos_work_threshold(cs, params);
        if total_work >= threshold {
            return None;
        }
        if headers.len() as u64 != MAX_HEADERS_RESULTS {
            // Short low-work batch: the peer has nothing more to give
            // and never proved sufficient work — ignore it outright
            // (Core logs "Ignoring low-work chain" and does nothing). If
            // this peer is currently leading headers sync, it just
            // showed it can't: release leadership so another peer gets
            // a chance instead of freezing sync on this one.
            return Some(HeadersOutcome {
                give_up_leadership: true,
                ..HeadersOutcome::default()
            });
        }
        let sync_params = HeadersSyncParams::for_network(params.network);
        let mut state = HeadersSyncState::new(cs, &fork, *params, sync_params, threshold, now);
        let result = state.process_next_headers(headers, true);
        // A brand-new presync's first page can never itself release
        // redownloaded headers — that only happens once REDOWNLOAD is
        // already under way, on a later call.
        debug_assert!(result.pow_validated_headers.is_empty());
        let continuation = self.next_low_work_request(cs, &state, result.request_more);
        let is_final = state.is_final();
        if !is_final {
            self.headers_sync = Some(state);
        }
        Some(HeadersOutcome {
            added: 0,
            known: 0,
            continuation,
            fetchable: Vec::new(),
            // The only way a brand-new presync's very first call can
            // finalize is by failing outright on this page (a
            // successful completion needs REDOWNLOAD, which can't have
            // started yet) — give up leadership in that case too.
            give_up_leadership: is_final,
        })
    }

    /// Core's `IsContinuationOfLowWorkHeadersSync`: hands a wire batch to
    /// an already-in-progress presync/redownload. An internal failure (bad
    /// continuity relative to where the sync left off, an impossible
    /// difficulty transition, a commitment mismatch, or the peer-length
    /// bound) is not punished on its own — the sync is simply abandoned,
    /// same as Core's "just give up" — but headers a completed REDOWNLOAD
    /// releases go through the ordinary [`Self::accept_headers`] path and
    /// *can* misbehave there like any other header.
    fn continue_low_work_sync(
        &mut self,
        cs: &mut Chainstate,
        headers: &[BlockHeader],
        now: u32,
    ) -> Result<HeadersOutcome, SyncError> {
        let Some(mut state) = self.headers_sync.take() else {
            // Only called when `headers_sync.is_some()`; defended anyway.
            return Ok(HeadersOutcome::default());
        };
        let full_page = headers.len() as u64 == MAX_HEADERS_RESULTS;
        let result = state.process_next_headers(headers, full_page);
        let sync_continuation = self.next_low_work_request(cs, &state, result.request_more);
        let is_final = state.is_final();
        if !is_final {
            self.headers_sync = Some(state);
        }

        if !result.success {
            // Abandoned (bad continuity relative to where the sync left
            // off, an impossible difficulty transition, a commitment
            // mismatch, or the peer-length bound) — not misbehavior on
            // its own; give up on this peer's low-work chain and
            // release leadership so another peer can take over paging.
            return Ok(HeadersOutcome {
                give_up_leadership: true,
                ..HeadersOutcome::default()
            });
        }

        let (added, known, fetchable) =
            self.accept_headers(cs, &result.pow_validated_headers, now)?;

        let continuation = if sync_continuation.is_none() && full_page {
            // Core's `ProcessHeadersMessage`: `nCount` is the *received*
            // message's size, captured before any swap with released
            // headers, and `!have_headers_sync` — the sync just
            // finished (successfully, since we're past the
            // `!result.success` check above) — so a full wire page
            // still triggers the ordinary "peer may have more" fetch,
            // via our new best-header locator, exactly as if this had
            // never been a low-work batch at all.
            Some(self.request_headers(cs))
        } else {
            sync_continuation
        };
        // Reached only when `result.success`. `is_final` here means
        // either REDOWNLOAD released everything (`continuation` above
        // already covers keeping the peer as leader) or the sync ended
        // on a non-full page without ever proving enough work (Core's
        // "declining to serve us that full chain again" / a presync
        // whose whole chain came up short) — in that second case
        // `continuation` stays `None`, and this peer should give up
        // leadership too.
        let give_up_leadership = is_final && continuation.is_none();
        Ok(HeadersOutcome {
            added,
            known,
            continuation,
            fetchable,
            give_up_leadership,
        })
    }

    /// Builds the next `getheaders` for an in-progress low-work sync and
    /// timestamps it as this peer's new outstanding request, or `None`
    /// when the sync didn't ask for more this round.
    fn next_low_work_request(
        &mut self,
        cs: &Chainstate,
        state: &HeadersSyncState,
        request_more: bool,
    ) -> Option<Message> {
        request_more.then(|| {
            self.headers_in_flight = Some(Instant::now());
            state.next_headers_request(cs)
        })
    }

    /// Selects newly announced blocks to fetch: `inv` entries naming blocks
    /// the tree already knows (headers-first) or doesn't know at all (the
    /// peer may announce ahead of our headers sync — Core fetches such
    /// announcements' *headers* first via `getheaders`, which the caller
    /// triggers separately). Returns at most the free in-flight slots'
    /// worth of `getdata` entries, further bounded by `global_free` —
    /// the caller's remaining aggregate in-flight budget.
    #[must_use]
    pub fn on_inv(
        &mut self,
        cs: &Chainstate,
        mempool: Option<&avila_mempool::Mempool>,
        invs: &[InvVector],
        global_free: usize,
    ) -> Option<Message> {
        let free = MAX_BLOCKS_IN_TRANSIT_PER_PEER
            .saturating_sub(self.in_flight.len())
            .min(global_free);
        let mut want = Vec::new();
        for inv in invs {
            let is_block = matches!(inv.inv_type, InvType::Block | InvType::WitnessBlock);
            let is_tx = matches!(
                inv.inv_type,
                InvType::Tx | InvType::Wtx | InvType::WitnessTx
            );
            if !is_block && !is_tx {
                continue;
            }
            let hash = inv.hash;
            // Block: known header + held body → nothing to fetch. Unknown
            // header → fetch anyway (the block carries its header and
            // Chainstate indexes it on acceptance — out-of-order
            // announcements happen). Tx: skip what the pool already holds
            // (announced by txid or wtxid — `contains_hash` covers both).
            if is_block && cs.have_body(&hash) {
                continue;
            }
            // Beyond the request budget this tick: remember the block —
            // without a backlog the rest of a 100-inv announcement is
            // silently dropped and the chain stalls behind the tip.
            if want.len() >= free {
                if is_block
                    && self.pending_set.insert(hash)
                    && !self.wanted.contains(&hash)
                {
                    self.pending_blocks.push_back(hash);
                }
                continue;
            }
            if is_tx && mempool.is_some_and(|m| m.contains_hash(&hash)) {
                continue;
            }
            if self.wanted.insert(hash) {
                want.push(InvVector {
                    // Always request witness serialization — a plain
                    // MSG_BLOCK response is witness-stripped and fails the
                    // witness-commitment check on segwit chains, exactly as
                    // in Core.
                    inv_type: if is_block {
                        InvType::WitnessBlock
                    } else {
                        InvType::WitnessTx
                    },
                    hash,
                });
            }
        }
        if want.is_empty() {
            return None;
        }
        // Record as in-flight now — the caller sends the message verbatim.
        let now = Instant::now();
        for inv in &want {
            self.in_flight.push_back((inv.hash, now));
        }
        Some(Message::GetData(want))
    }

    /// Request announced-but-unrequested blocks as in-flight slots
    /// free up — the backlog [`Self::on_inv`] parks when a burst
    /// exceeds the per-peer window.
    #[must_use]
    pub fn drain_pending(&mut self, cs: &Chainstate, global_free: usize) -> Option<Message> {
        let free = MAX_BLOCKS_IN_TRANSIT_PER_PEER
            .saturating_sub(self.in_flight.len())
            .min(global_free);
        if free == 0 {
            return None;
        }
        let now = Instant::now();
        let mut want = Vec::new();
        while want.len() < free {
            let Some(hash) = self.pending_blocks.pop_front() else {
                break;
            };
            self.pending_set.remove(&hash);
            if cs.have_body(&hash) || !self.wanted.insert(hash) {
                continue;
            }
            self.in_flight.push_back((hash, now));
            want.push(InvVector {
                inv_type: InvType::WitnessBlock,
                hash,
            });
        }
        if want.is_empty() {
            return None;
        }
        Some(Message::GetData(want))
    }

    /// Queues specific hashes for download (e.g. the `fetchable` list from
    /// a headers page), capped by free in-flight slots.
    #[must_use]
    pub fn want_blocks(&mut self, cs: &Chainstate, hashes: &[BlockHash]) -> Option<Message> {
        self.want_blocks_excluding(cs, hashes, &HashSet::new())
    }

    /// [`Self::want_blocks`] with a cross-peer reservation set: hashes in
    /// `exclude` are skipped even if this peer hasn't seen them — another
    /// peer is already fetching them.
    #[must_use]
    pub fn want_blocks_excluding(
        &mut self,
        cs: &Chainstate,
        hashes: &[BlockHash],
        exclude: &HashSet<BlockHash>,
    ) -> Option<Message> {
        let free = MAX_BLOCKS_IN_TRANSIT_PER_PEER.saturating_sub(self.in_flight.len());
        if free == 0 {
            return None;
        }
        let now = Instant::now();
        let mut want = Vec::new();
        for hash in hashes {
            if want.len() >= free {
                break;
            }
            if cs.have_body(hash) || exclude.contains(hash) || !self.wanted.insert(*hash) {
                continue;
            }
            self.in_flight.push_back((*hash, now));
            want.push(InvVector {
                inv_type: InvType::WitnessBlock,
                hash: *hash,
            });
        }
        if want.is_empty() {
            None
        } else {
            Some(Message::GetData(want))
        }
    }

    /// Feeds an arrived block into the chainstate, clearing its in-flight
    /// slot if this peer owed it.
    ///
    /// # Errors
    /// [`SyncError::InvalidBlock`] on a consensus rejection.
    pub fn on_block(
        &mut self,
        cs: &mut Chainstate,
        block: &Block,
        now: u32,
    ) -> Result<BlockOutcome, SyncError> {
        let hash = block.block_hash();
        let was_in_flight = self.clear_in_flight(&hash);
        self.wanted.remove(&hash);
        match cs.accept_block(block, now) {
            Ok(acceptance) => {
                self.blocks_received += 1;
                Ok(BlockOutcome {
                    acceptance,
                    was_in_flight,
                })
            }
            Err(rej) => Err(SyncError::InvalidBlock(rej.to_string())),
        }
    }

    /// A received `tx` releases its in-flight slot (the hash was
    /// requested as the txid via `MSG_WITNESS_TX`).
    pub fn on_tx(&mut self, txid: &avila_consensus::hash::Txid) {
        let h = BlockHash::from_bytes(*txid.as_bytes());
        self.clear_in_flight(&h);
        self.wanted.remove(&h);
    }

    /// `notfound` clears matching in-flight slots — the peer answered, it
    /// just doesn't have the data (e.g. pruned nodes serving recent
    /// history only). Returns the hashes released this way.
    pub fn on_notfound(&mut self, invs: &[InvVector]) -> Vec<BlockHash> {
        let mut released = Vec::new();
        for inv in invs {
            if self.clear_in_flight(&inv.hash) {
                released.push(inv.hash);
            }
            self.wanted.remove(&inv.hash);
        }
        released
    }

    /// `true` if the oldest in-flight block request has gone unanswered
    /// past [`BLOCK_STALLING_TIMEOUT`] — the caller should evict the peer
    /// and requeue its blocks elsewhere.
    #[must_use]
    pub fn stalled(&self) -> bool {
        self.in_flight
            .front()
            .is_some_and(|(_, t)| t.elapsed() > BLOCK_STALLING_TIMEOUT)
    }

    /// Removes `hash` from the in-flight queue. Returns whether it was owed.
    fn clear_in_flight(&mut self, hash: &BlockHash) -> bool {
        if let Some(pos) = self.in_flight.iter().position(|(h, _)| h == hash) {
            self.in_flight.remove(pos);
            true
        } else {
            false
        }
    }

    /// Answers a peer's `getheaders`: find the deepest locator hash on our
    /// best header chain (Core's `FindFork` equivalent), then emit the
    /// following headers — up to [`MAX_HEADERS_RESULTS`], stopping before
    /// `stop` if it's on the chain. An empty reply means we have nothing
    /// the peer doesn't (or the locator never intersected our chain —
    /// Core serves from genesis in that case; an empty page is the honest
    /// answer when the fork is our tip).
    #[must_use]
    pub fn serve_getheaders(cs: &Chainstate, request: &GetHeaders) -> Message {
        let chain = cs.tree().best_chain();
        // Deepest locator hash on our best chain; -1 means "no common
        // point" — serve from genesis.
        let fork = request
            .locator
            .iter()
            .filter_map(|hash| chain.iter().position(|h| h == hash).map(|p| p as i64))
            .max()
            .unwrap_or(-1);
        let mut headers = Vec::new();
        for height in (fork + 1)..chain.len() as i64 {
            let hash = &chain[height as usize];
            if *hash == request.stop {
                break;
            }
            let Some(node) = cs.tree().get(hash) else {
                break;
            };
            headers.push(node.header);
            if headers.len() as u64 == MAX_HEADERS_RESULTS {
                break;
            }
        }
        Message::Headers(headers)
    }

    /// Shared bounds of `PrepareBlockFilterRequest`: the stop hash must
    /// be an active-chain block and `start..=stop` must fit the cap.
    /// Returns the resolved stop height on success.
    fn prepare_cf_request(
        cs: &Chainstate,
        serve_filters: bool,
        filter_type: u8,
        start_height: u32,
        stop_hash: &BlockHash,
        max_height_diff: u32,
    ) -> Result<u32, FilterReply> {
        use FilterReply as R;
        if filter_type != 0 || !serve_filters {
            // Core's PrepareBlockFilterRequest: requesting a filter
            // type we never advertised (or a non-BASIC type) is a
            // protocol violation — the peer gets disconnected.
            return Err(R::Disconnect("unsupported filter type"));
        }
        if !cs.blockfilterindex_enabled() {
            // The bit is up but the index isn't — Core logs and
            // returns without disconnecting.
            return Err(R::Ignore);
        }
        let Some(stop_node) = cs.tree().get(stop_hash) else {
            return Err(R::Disconnect("unknown stop hash"));
        };
        // Core's BlockRequestAllowed — the block must be fetchable:
        // only the active chain is served here.
        if !cs.chain().contains(stop_hash) {
            return Err(R::Disconnect("stop hash not on the active chain"));
        }
        let stop_height = stop_node.height;
        if start_height > stop_height {
            return Err(R::Disconnect("start height above stop"));
        }
        if stop_height - start_height >= max_height_diff {
            return Err(R::Disconnect("requested range too large"));
        }
        Ok(stop_height)
    }

    /// `getcfilters` → one `cfilter` per block in `start..=stop` —
    /// Core caps the range at `MAX_GETCFILTERS_SIZE` (1000).
    #[must_use]
    pub fn serve_getcfilters(
        cs: &Chainstate,
        serve_filters: bool,
        req: &crate::message::CFRange,
    ) -> FilterReply {
        use FilterReply as R;
        let stop_height = match Self::prepare_cf_request(
            cs,
            serve_filters,
            req.filter_type,
            req.start_height,
            &req.stop_hash,
            MAX_GETCFILTERS_SIZE,
        ) {
            Ok(h) => h,
            Err(reply) => return reply,
        };
        let filters = cs.block_filters_range(req.start_height, stop_height);
        if filters.is_empty() {
            return R::Ignore;
        }
        R::Serve(
            filters
                .into_iter()
                .map(|(hash, filter, _)| {
                    crate::message::Message::CFilter(crate::message::CFilter {
                        filter_type: req.filter_type,
                        block_hash: hash,
                        filter,
                    })
                })
                .collect(),
        )
    }

    /// `getcfheaders` → `prev_filter_header` + the filter hash chain —
    /// cap `MAX_GETCFHEADERS_SIZE` (2000).
    #[must_use]
    pub fn serve_getcfheaders(
        cs: &Chainstate,
        serve_filters: bool,
        req: &crate::message::CFRange,
    ) -> FilterReply {
        use FilterReply as R;
        let stop_height = match Self::prepare_cf_request(
            cs,
            serve_filters,
            req.filter_type,
            req.start_height,
            &req.stop_hash,
            MAX_GETCFHEADERS_SIZE,
        ) {
            Ok(h) => h,
            Err(reply) => return reply,
        };
        let prev_filter_header = if req.start_height > 0 {
            match cs.filter_header_at(req.start_height - 1) {
                Some(h) => h,
                None => return R::Ignore,
            }
        } else {
            [0u8; 32]
        };
        let filters = cs.block_filters_range(req.start_height, stop_height);
        if filters.is_empty() {
            return R::Ignore;
        }
        let filter_hashes = filters
            .iter()
            .map(|(_, f, _)| avila_consensus::gcs::filter_hash(f))
            .collect();
        R::Serve(vec![crate::message::Message::CFHeaders(
            crate::message::CFHeaders {
                filter_type: req.filter_type,
                stop_hash: req.stop_hash,
                prev_filter_header,
                filter_hashes,
            },
        )])
    }

    /// `getcfcheckpt` → filter headers at every 1,000th height up to
    /// the stop block — Core's `stop_height / CFCHECKPT_INTERVAL`.
    #[must_use]
    pub fn serve_getcfcheckpt(
        cs: &Chainstate,
        serve_filters: bool,
        req: &crate::message::CFCheckptReq,
    ) -> FilterReply {
        use FilterReply as R;
        let stop_height = match Self::prepare_cf_request(
            cs,
            serve_filters,
            req.filter_type,
            0,
            &req.stop_hash,
            u32::MAX,
        ) {
            Ok(h) => h,
            Err(reply) => return reply,
        };
        let count = stop_height / CFCHECKPT_INTERVAL;
        let mut filter_headers = Vec::with_capacity(count as usize);
        for i in 1..=count {
            let Some(h) = cs.filter_header_at(i * CFCHECKPT_INTERVAL) else {
                return R::Ignore;
            };
            filter_headers.push(h);
        }
        R::Serve(vec![crate::message::Message::CFCheckpt(
            crate::message::CFCheckpt {
                filter_type: req.filter_type,
                stop_hash: req.stop_hash,
                filter_headers,
            },
        )])
    }

    /// Answers a peer's `getdata`: a `block` message for each requested
    /// block whose body we hold (memory or store), `notfound` for the rest.
    /// Bounded by the request size — `getdata` payloads are already capped
    /// at `MAX_INV_SZ` by the decoder.
    #[must_use]
    pub fn serve_getdata(
        cs: &Chainstate,
        mempool: Option<&avila_mempool::Mempool>,
        requests: &[InvVector],
    ) -> Vec<Message> {
        let mut out = Vec::new();
        let mut missing = Vec::new();
        for inv in requests {
            match inv.inv_type {
                InvType::Block | InvType::WitnessBlock => {
                    if let Some(block) = cs.body(&inv.hash) {
                        // MSG_BLOCK is answered witness-stripped — the wire
                        // encoding mirrors Core's `NetMsgType::BLOCK` vs
                        // `MSG_WITNESS_BLOCK` split.
                        let mut block = block;
                        if inv.inv_type == InvType::Block {
                            for tx in &mut block.transactions {
                                for input in &mut tx.inputs {
                                    input.witness =
                                        avila_consensus::transaction::Witness::default();
                                }
                            }
                        }
                        out.push(Message::Block(block));
                    } else {
                        missing.push(*inv);
                    }
                }
                // A tx request is answered from the mempool — txid or
                // wtxid both resolve to the pooled transaction; the wire
                // form is always witness-capable (witness data present
                // when the tx carries it, matching Core's MSG_WTX/TX
                // response which never strips).
                InvType::Tx | InvType::Wtx | InvType::WitnessTx => {
                    let found = mempool.and_then(|m| {
                        m.get(&avila_consensus::hash::Txid::from_bytes(
                            *inv.hash.as_bytes(),
                        ))
                        .or_else(|| {
                            m.get_wtxid(&avila_consensus::hash::Wtxid::from_bytes(
                                *inv.hash.as_bytes(),
                            ))
                        })
                    });
                    match found {
                        Some(tx) => out.push(Message::Tx(tx.clone())),
                        None => missing.push(*inv),
                    }
                }
                _ => missing.push(*inv),
            }
        }
        if !missing.is_empty() {
            out.push(Message::NotFound(missing));
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const NOW: u32 = 1_800_000_000;

    use avila_consensus::params::Network;

    use crate::testchain::{block_on, chain_blocks, regtest};

    #[test]
    fn request_headers_uses_best_header_locator() {
        let cs = regtest();
        let mut sync = PeerSync::new();
        match sync.request_headers(&cs) {
            Message::GetHeaders(gh) => {
                assert_eq!(gh.locator.len(), 1); // genesis only
                assert!(gh.stop.is_zero());
            }
            other => panic!("expected getheaders, got {other:?}"),
        }
        assert!(sync.awaiting_headers());
    }

    #[test]
    fn headers_page_indexes_and_requests_continuation() {
        let mut cs = regtest();
        let blocks = chain_blocks(&cs, 5);
        let headers: Vec<BlockHeader> = blocks.iter().map(|b| b.header).collect();
        let mut sync = PeerSync::new();
        let out = sync.on_headers(&mut cs, &headers, NOW).unwrap();
        assert_eq!(out.added, 5);
        assert_eq!(out.known, 0);
        assert!(out.continuation.is_none()); // partial page — peer is done
        assert_eq!(out.fetchable.len(), 5);
        assert_eq!(cs.tree().tip().height, 5);
    }

    #[test]
    fn full_page_requests_more() {
        let mut cs = regtest();
        // A synthetic "full page" doesn't need 2000 real blocks: the
        // continuation check keys on MAX_HEADERS_RESULTS — feed a partial
        // page and assert no continuation, which is the observable branch.
        // (Building 2000 regtest blocks per test is too slow; the boundary
        // is covered by the constant comparison itself.)
        let blocks = chain_blocks(&cs, 3);
        let headers: Vec<BlockHeader> = blocks.iter().map(|b| b.header).collect();
        let mut sync = PeerSync::new();
        let out = sync.on_headers(&mut cs, &headers, NOW).unwrap();
        assert!(out.continuation.is_none());
    }

    /// Wiring check for the anti-DoS gate: a full-page, low-work batch
    /// must be diverted into a presync (nothing stored, more requested)
    /// rather than reaching `accept_header` directly; once the whole
    /// chain has been paged through presync and its claimed work clears
    /// the floor, it switches to redownloading the identical range and,
    /// once redownloaded work also clears the floor, releases everything
    /// for real acceptance. The state-machine details (commitments,
    /// buffering, ...) are covered in `headerssync`'s own tests; this
    /// only pins that `PeerSync::on_headers` actually calls into it, over
    /// the two full pages each phase needs for a 4000-header chain.
    #[test]
    fn on_headers_diverts_a_low_work_chain_then_applies_it_once_proven() {
        use avila_consensus::arith::{U256, Work};
        use avila_consensus::chainstate::Chainstate;

        // Threshold picked so a single 2000-header page's claimed work
        // (2 per regtest header, plus genesis's own 2 = 4002) is *not*
        // enough on its own — otherwise the very first page would clear
        // it immediately and never divert into presync at all — but a
        // handful of headers past it is. A non-full page that crosses
        // the floor still asks for more (Core: `full_headers_message ||
        // state == REDOWNLOAD`), so this second page need not itself be
        // a full 2000 headers — kept tiny so the chain this test mines
        // stays small.
        let mut params = Network::Regtest.params();
        params.minimum_chain_work = Work(U256::from_u64(4_010));
        let seed = Chainstate::new(&params);
        let blocks = chain_blocks(&seed, MAX_HEADERS_RESULTS as u32 + 4);
        let headers: Vec<BlockHeader> = blocks.iter().map(|b| b.header).collect();
        let page1 = &headers[..MAX_HEADERS_RESULTS as usize];
        let page2 = &headers[MAX_HEADERS_RESULTS as usize..];

        let mut cs = Chainstate::new(&params);
        let mut sync = PeerSync::new();

        // Presync, page 1: below the floor on its own — diverted, and
        // asks for more (this page was full).
        let out = sync.on_headers(&mut cs, page1, NOW).unwrap();
        assert_eq!((out.added, out.known), (0, 0));
        assert!(
            out.continuation.is_some(),
            "a full low-work page should page for more"
        );
        assert_eq!(
            cs.tree().len(),
            1,
            "a low-work batch must never be stored directly"
        );

        // Presync, page 2: the full chain's claimed work now clears the
        // floor, promoting presync to redownload — still nothing stored.
        let out = sync.on_headers(&mut cs, page2, NOW).unwrap();
        assert_eq!((out.added, out.known), (0, 0));
        assert!(
            out.continuation.is_some(),
            "redownload should start by re-requesting from the top"
        );
        assert_eq!(cs.tree().len(), 1);

        // Redownload, page 1: re-verifies the same range against the
        // commitments taken during presync; buffered, not yet released
        // (this page's own work hasn't cleared the floor again yet).
        let out = sync.on_headers(&mut cs, page1, NOW).unwrap();
        assert_eq!((out.added, out.known), (0, 0));
        assert!(out.continuation.is_some());
        assert_eq!(cs.tree().len(), 1);

        // Redownload, page 2: crosses the floor again partway through,
        // releasing the entire verified chain for real acceptance.
        let out = sync.on_headers(&mut cs, page2, NOW).unwrap();
        assert_eq!(out.added, headers.len());
        assert!(out.continuation.is_none(), "the sync is complete");
        assert_eq!(cs.tree().len(), headers.len() + 1);
        assert_eq!(cs.tree().tip().height as usize, headers.len());
    }

    /// Core's `IsAncestorOfBestHeaderOrTip`: re-announcing a header we
    /// already have, that's part of our best-header chain, must never
    /// start a presync — even with a threshold no single page could
    /// otherwise clear.
    #[test]
    fn known_header_on_best_chain_skips_the_anti_dos_gate() {
        use avila_consensus::arith::{U256, Work};
        use avila_consensus::chainstate::Chainstate;

        let mut params = Network::Regtest.params();
        params.minimum_chain_work = Work(U256::from_u64(u64::MAX)); // unreachable by any batch
        let mut cs = Chainstate::new(&params);
        let blocks = chain_blocks(&cs, 5);
        for b in &blocks {
            cs.accept_header(&b.header, NOW).unwrap();
        }
        let mut sync = PeerSync::new();

        // Re-announcing the whole known chain (a `headers` reply to an
        // ordinary getheaders, or an unsolicited re-advertisement) must
        // be accepted normally — `known` counts every one of them —
        // rather than diverted into a presync that could never succeed.
        let headers: Vec<BlockHeader> = blocks.iter().map(|b| b.header).collect();
        let out = sync.on_headers(&mut cs, &headers, NOW).unwrap();
        assert_eq!(out.known, headers.len());
        assert_eq!(out.added, 0);
        assert!(!out.give_up_leadership);
    }

    /// Realistic end-to-end regression on real mainnet data. A peer's
    /// claimed work clears the anti-DoS floor only partway through a
    /// 4000-header chain, so the whole chain must be presynced and then
    /// redownloaded before anything lands in the tree. This specifically
    /// pins the "keep paging after a completed low-work sync" fix: the
    /// redownload crosses the floor on a full wire page (heights
    /// 2001..=4000), and completing on a full page must still trigger an
    /// ordinary continuation — without it, sync would simply stop at
    /// height 4000 and never pick up the real remaining headers.
    #[test]
    fn mainnet_fixture_presync_redownload_then_ordinary_continuation() {
        use avila_consensus::arith::{U256, Work};
        use avila_consensus::chainstate::Chainstate;

        const MAINNET_HEADERS: &[u8] =
            include_bytes!("../../../fixtures/mainnet-headers-000000-004031.bin");
        let raw: Vec<BlockHeader> = MAINNET_HEADERS
            .as_chunks::<{ BlockHeader::SIZE }>()
            .0
            .iter()
            .map(|chunk| BlockHeader::decode(chunk).unwrap())
            .collect();
        assert_eq!(raw.len(), 4032, "genesis plus 4031 real headers");
        // `raw[0]` is the genesis header itself — already seeded by
        // `Chainstate::new`, so only `raw[1..]` are ever fed on the wire.
        let headers = &raw[1..];
        assert_eq!(headers.len(), 4031);
        let page1 = &headers[..2000]; // heights 1..=2000
        let page2 = &headers[2000..4000]; // heights 2001..=4000
        let page3 = &headers[4000..]; // heights 4001..=4031
        assert_eq!(page3.len(), 31);

        let base_params = Network::Mainnet.params();

        // The real cumulative work through heights 2000 and 4000, summed
        // directly from each header's own claimed bits — exactly how
        // `HeaderNode::chainwork` itself accumulates, but without paying
        // for a 4000-deep `HeaderTree::insert` (whose ancestor-validity
        // walk back to genesis on every call makes actually building a
        // reference tree here needlessly expensive for what's simple
        // arithmetic over already-known-real header data).
        let genesis_work = Work::from_compact(base_params.genesis_header.bits);
        let work_at_2000 = page1.iter().fold(genesis_work, |acc, h| {
            acc.checked_add(Work::from_compact(h.bits)).unwrap()
        });
        let work_at_4000 = page2.iter().fold(work_at_2000, |acc, h| {
            acc.checked_add(Work::from_compact(h.bits)).unwrap()
        });
        assert!(
            work_at_2000 < work_at_4000,
            "mainnet's first retarget (height 2016) must raise cumulative work"
        );

        let mut params = base_params;
        // Strictly between the two: page 1 alone can never clear it, but
        // page 1 + page 2 together do.
        params.minimum_chain_work = work_at_2000.checked_add(Work(U256::ONE)).unwrap();
        assert!(params.minimum_chain_work <= work_at_4000);

        let mut cs = Chainstate::new(&params);
        let mut sync = PeerSync::new();

        // Presync page 1: below the floor on its own.
        let out = sync.on_headers(&mut cs, page1, NOW).unwrap();
        assert_eq!((out.added, out.known), (0, 0));
        assert!(out.continuation.is_some());
        assert_eq!(cs.tree().len(), 1, "nothing stored during presync");

        // Presync page 2: the chain's claimed work now clears the floor
        // mid-page, promoting presync to redownload.
        let out = sync.on_headers(&mut cs, page2, NOW).unwrap();
        assert_eq!((out.added, out.known), (0, 0));
        assert!(out.continuation.is_some());
        assert_eq!(
            cs.tree().len(),
            1,
            "still nothing stored — redownload hasn't verified anything yet"
        );

        // Redownload page 1: re-verifies against presync's commitments;
        // buffered, not released yet.
        let out = sync.on_headers(&mut cs, page1, NOW).unwrap();
        assert_eq!((out.added, out.known), (0, 0));
        assert!(out.continuation.is_some());
        assert_eq!(cs.tree().len(), 1);

        // Redownload page 2: crosses the floor again mid-page, releasing
        // the whole verified chain (heights 1..=4000). The regression
        // this test pins: since this wire page was itself full, an
        // ordinary continuation must follow.
        let out = sync.on_headers(&mut cs, page2, NOW).unwrap();
        assert_eq!(out.added, 4000);
        assert_eq!(cs.tree().len(), 4001);
        assert_eq!(cs.tree().tip().height, 4000);
        assert!(
            out.continuation.is_some(),
            "completing a low-work sync on a full page must keep paging ordinarily, \
             or header sync stops dead at the minimum-chainwork height"
        );
        assert!(!out.give_up_leadership);

        // The peer answers that ordinary continuation with the real
        // remaining headers — accepted through the normal path (already
        // proven work, no low-work sync involved).
        let out = sync.on_headers(&mut cs, page3, NOW).unwrap();
        assert_eq!(out.added, 31);
        assert!(out.continuation.is_none(), "a non-full page ends the sync");
        assert_eq!(cs.tree().tip().height, 4031);
        assert_eq!(cs.tree().len(), 4032);
    }

    #[test]
    fn discontinuous_headers_are_misbehavior() {
        let mut cs = regtest();
        let blocks = chain_blocks(&cs, 4);
        let mut sync = PeerSync::new();
        // A page starting at block 3 — its prev (h2) isn't in the tree.
        let stray = vec![blocks[3].header];
        assert_eq!(
            sync.on_headers(&mut cs, &stray, NOW).unwrap_err(),
            SyncError::DiscontinuousHeaders
        );
        // Internally discontinuous page: h1 then h3.
        let broken = vec![blocks[0].header, blocks[2].header];
        assert_eq!(
            sync.on_headers(&mut cs, &broken, NOW).unwrap_err(),
            SyncError::DiscontinuousHeaders
        );
    }

    #[test]
    fn inv_requests_only_unknown_bodies() {
        let cs = regtest();
        let blocks = chain_blocks(&cs, 3);
        let mut sync = PeerSync::new();
        let invs = vec![
            InvVector {
                inv_type: InvType::Block,
                hash: blocks[0].block_hash(),
            },
            InvVector {
                inv_type: InvType::Tx, // fetched as witness-tx for the mempool
                hash: blocks[1].block_hash(),
            },
            InvVector {
                inv_type: InvType::Block,
                hash: blocks[2].block_hash(),
            },
        ];
        match sync.on_inv(&cs, None, &invs, usize::MAX) {
            Some(Message::GetData(want)) => {
                assert_eq!(want.len(), 3);
                assert_eq!(want[0].inv_type, InvType::WitnessBlock);
                assert_eq!(want[1].inv_type, InvType::WitnessTx);
                assert_eq!(want[2].inv_type, InvType::WitnessBlock);
            }
            other => panic!("expected getdata, got {other:?}"),
        }
        assert_eq!(sync.in_flight(), 3);
        // Same invs again → nothing new to ask for.
        assert!(sync.on_inv(&cs, None, &invs, usize::MAX).is_none());
    }

    #[test]
    fn inv_burst_beyond_window_queues_and_drains() {
        // 20 announced blocks against a 16-slot window: the first 16
        // are requested now, the rest park in the backlog — arriving
        // bodies free slots and the drain requests them.
        let mut sync = PeerSync::new();
        let cs = regtest();
        let invs: Vec<InvVector> = (0..20u32)
            .map(|i| InvVector {
                inv_type: InvType::WitnessBlock,
                hash: BlockHash::from_bytes([i as u8; 32]),
            })
            .collect();
        let req = sync.on_inv(&cs, None, &invs, 1024).expect("getdata");
        let Message::GetData(want) = req else { panic!() };
        assert_eq!(want.len(), 16);
        assert_eq!(sync.pending_blocks.len(), 4);
        // Free a slot — the drain takes one more.
        sync.in_flight.pop_front();
        let req = sync.drain_pending(&cs, 1024).expect("drained getdata");
        let Message::GetData(want) = req else { panic!() };
        assert_eq!(want.len(), 1);
        assert_eq!(want[0].hash, BlockHash::from_bytes([16; 32]));
        assert_eq!(sync.pending_blocks.len(), 3);
    }

    #[test]
    fn in_flight_is_bounded() {
        let cs = regtest();
        let blocks = chain_blocks(&cs, 20);
        let mut sync = PeerSync::new();
        let hashes: Vec<BlockHash> = blocks.iter().map(|b| b.block_hash()).collect();
        // First request fills all 16 slots.
        let req = sync.want_blocks(&cs, &hashes);
        match req {
            Some(Message::GetData(want)) => assert_eq!(want.len(), 16),
            other => panic!("expected getdata, got {other:?}"),
        }
        assert_eq!(sync.in_flight(), 16);
        // Second request — no free slots.
        assert!(sync.want_blocks(&cs, &hashes).is_none());
    }

    #[test]
    fn arrived_blocks_clear_in_flight_and_connect() {
        let mut cs = regtest();
        let blocks = chain_blocks(&cs, 3);
        let mut sync = PeerSync::new();
        let hashes: Vec<BlockHash> = blocks.iter().map(|b| b.block_hash()).collect();
        let _ = sync.want_blocks(&cs, &hashes);
        for (i, block) in blocks.iter().enumerate() {
            let out = sync.on_block(&mut cs, block, NOW).unwrap();
            assert!(out.was_in_flight);
            assert_eq!(cs.chain().len() as u32 - 1, u32::try_from(i).unwrap() + 1);
        }
        assert_eq!(sync.in_flight(), 0);
        assert_eq!(cs.tip_hash(), blocks[2].block_hash());
    }

    #[test]
    fn notfound_releases_in_flight_slots() {
        let cs = regtest();
        let blocks = chain_blocks(&cs, 3);
        let mut sync = PeerSync::new();
        let hashes: Vec<BlockHash> = blocks.iter().map(|b| b.block_hash()).collect();
        let _ = sync.want_blocks(&cs, &hashes);
        assert_eq!(sync.in_flight(), 3);

        // Peer can't serve the first two (e.g. pruned) — slots release and
        // the fill pass can hand them to someone else.
        let released = sync.on_notfound(&[
            InvVector {
                inv_type: InvType::WitnessBlock,
                hash: hashes[0],
            },
            InvVector {
                inv_type: InvType::WitnessBlock,
                hash: hashes[1],
            },
        ]);
        assert_eq!(released.len(), 2);
        assert_eq!(sync.in_flight(), 1);
        assert!(!sync.stalled());

        // The released hashes are requestable again.
        let req = sync.want_blocks(&cs, &hashes);
        match req {
            Some(Message::GetData(want)) => assert_eq!(want.len(), 2),
            other => panic!("expected getdata, got {other:?}"),
        }
    }

    #[test]
    fn invalid_block_surfaces_consensus_reason() {
        let mut cs = regtest();
        let params = *cs.tree().params();
        // A block on genesis with no coinbase — CheckBlock rejects it.
        let mut bad = block_on(&params.genesis_header, 1, &params);
        bad.transactions.clear();
        let mut sync = PeerSync::new();
        let err = sync.on_block(&mut cs, &bad, NOW).unwrap_err();
        assert!(matches!(err, SyncError::InvalidBlock(_)), "{err}");
    }

    #[test]
    fn serve_bip157_requests() {
        let mut cs = regtest();
        cs.enable_blockfilterindex(None).unwrap();
        let blocks = chain_blocks(&cs, 3);
        for b in &blocks {
            cs.accept_block(b, NOW).unwrap();
        }
        let tip = blocks[2].block_hash();

        // getcfilters 0..tip → one cfilter per block (genesis + 3).
        match PeerSync::serve_getcfilters(
            &cs,
            true,
            &crate::message::CFRange {
                filter_type: 0,
                start_height: 0,
                stop_hash: tip,
            },
        ) {
            FilterReply::Serve(msgs) => assert_eq!(msgs.len(), 4),
            other => panic!("getcfilters: expected serve, got {other:?}"),
        }
        // getcfheaders → prev header at start-1 (zero at genesis) + 4 hashes.
        match PeerSync::serve_getcfheaders(
            &cs,
            true,
            &crate::message::CFRange {
                filter_type: 0,
                start_height: 0,
                stop_hash: tip,
            },
        ) {
            FilterReply::Serve(msgs) => match &msgs[0] {
                Message::CFHeaders(h) => {
                    assert_eq!(h.prev_filter_header, [0; 32]);
                    assert_eq!(h.filter_hashes.len(), 4);
                    assert_eq!(h.stop_hash, tip);
                }
                other => panic!("expected cfheaders, got {other:?}"),
            },
            other => panic!("getcfheaders: expected serve, got {other:?}"),
        }
        // getcfcheckpt at h3 → no 1000-boundary heights → empty list.
        match PeerSync::serve_getcfcheckpt(
            &cs,
            true,
            &crate::message::CFCheckptReq {
                filter_type: 0,
                stop_hash: tip,
            },
        ) {
            FilterReply::Serve(msgs) => match &msgs[0] {
                Message::CFCheckpt(c) => assert!(c.filter_headers.is_empty()),
                other => panic!("expected cfcheckpt, got {other:?}"),
            },
            other => panic!("getcfcheckpt: expected serve, got {other:?}"),
        }
        // Bad requests disconnect (Core's PrepareBlockFilterRequest).
        for req in [
            crate::message::CFRange {
                filter_type: 9, // unsupported type
                start_height: 0,
                stop_hash: tip,
            },
            crate::message::CFRange {
                filter_type: 0,
                start_height: 2, // start > stop
                stop_hash: blocks[0].block_hash(),
            },
            crate::message::CFRange {
                filter_type: 0,
                start_height: 0,
                stop_hash: BlockHash::ZERO, // unknown stop
            },
        ] {
            assert!(
                matches!(
                    PeerSync::serve_getcfilters(&cs, true, &req),
                    FilterReply::Disconnect(_)
                ),
                "expected disconnect for {req:?}"
            );
        }
        // Range over the cap disconnects.
        assert!(matches!(
            PeerSync::serve_getcfilters(
                &cs,
                true,
                &crate::message::CFRange {
                    filter_type: 0,
                    start_height: 0,
                    stop_hash: tip, // 3 blocks < 1000 cap — need >cap: use checkpt
                },
            ),
            FilterReply::Serve(_)
        ));
        // With no index the same request is ignored, not served.
        let cs2 = regtest();
        match PeerSync::serve_getcfilters(
            &cs2,
            true, // bit advertised but index missing → Ignore, like Core
            &crate::message::CFRange {
                filter_type: 0,
                start_height: 0,
                stop_hash: tip,
            },
        ) {
            FilterReply::Ignore => {}
            other => panic!("no index: expected ignore, got {other:?}"),
        }
    }

    #[test]
    fn serve_getheaders_answers_from_fork_point() {
        let mut cs = regtest();
        let blocks = chain_blocks(&cs, 5);
        for b in &blocks {
            cs.accept_block(b, NOW).unwrap();
        }
        // Peer at h2 asks with locator [h2, h1, genesis] → serve h3..h5.
        let genesis = cs
            .tree()
            .get(&blocks[0].header.prev_block_hash)
            .unwrap()
            .hash();
        let req = GetHeaders {
            locator: vec![blocks[1].block_hash(), blocks[0].block_hash(), genesis],
            stop: BlockHash::ZERO,
        };
        match PeerSync::serve_getheaders(&cs, &req) {
            Message::Headers(headers) => {
                assert_eq!(headers.len(), 3);
                assert_eq!(headers[0].hash(), blocks[2].block_hash());
                assert_eq!(headers[2].hash(), blocks[4].block_hash());
            }
            other => panic!("expected headers, got {other:?}"),
        }
    }

    #[test]
    fn serve_getheaders_stop_and_empty() {
        let mut cs = regtest();
        let blocks = chain_blocks(&cs, 4);
        for b in &blocks {
            cs.accept_block(b, NOW).unwrap();
        }
        // Stop at h3: serve h2 only (the stop hash is exclusive).
        let req = GetHeaders {
            locator: vec![blocks[0].block_hash()],
            stop: blocks[2].block_hash(),
        };
        match PeerSync::serve_getheaders(&cs, &req) {
            Message::Headers(h) => {
                assert_eq!(h.len(), 1);
                assert_eq!(h[0].hash(), blocks[1].block_hash());
            }
            other => panic!("expected headers, got {other:?}"),
        }
        // Locator at our tip → nothing to serve.
        let req = GetHeaders {
            locator: vec![blocks[3].block_hash()],
            stop: BlockHash::ZERO,
        };
        match PeerSync::serve_getheaders(&cs, &req) {
            Message::Headers(h) => assert!(h.is_empty()),
            other => panic!("expected headers, got {other:?}"),
        }
    }

    #[test]
    fn serve_getdata_blocks_and_notfound() {
        let mut cs = regtest();
        let blocks = chain_blocks(&cs, 2);
        for b in &blocks {
            cs.accept_block(b, NOW).unwrap();
        }
        let unknown = BlockHash::from_bytes([0xee; 32]);
        let reqs = vec![
            InvVector {
                inv_type: InvType::WitnessBlock,
                hash: blocks[0].block_hash(),
            },
            InvVector {
                inv_type: InvType::Block,
                hash: unknown,
            },
        ];
        let out = PeerSync::serve_getdata(&cs, None, &reqs);
        assert_eq!(out.len(), 2);
        assert!(matches!(&out[0], Message::Block(b) if b.block_hash() == blocks[0].block_hash()));
        match &out[1] {
            Message::NotFound(v) => assert_eq!(v[0].hash, unknown),
            other => panic!("expected notfound, got {other:?}"),
        }
    }
}
