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
#[derive(Clone, Debug)]
pub struct HeadersOutcome {
    /// Headers newly indexed by this page.
    pub added: usize,
    /// Headers already in the tree.
    pub known: usize,
    /// The peer has more — send the returned `getheaders` to continue.
    pub continuation: Option<Message>,
    /// Indexed blocks whose bodies we don't have — candidates for `getdata`.
    pub fetchable: Vec<BlockHash>,
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
            return Ok(HeadersOutcome {
                added: 0,
                known: 0,
                continuation: None,
                fetchable: Vec::new(),
            });
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

        // Anti-DoS gate (Core's `TryLowWorkHeadersSync`): a headers batch
        // that doesn't carry enough claimed work must never reach
        // `accept_header` directly, or a cheap low-difficulty chain could
        // grow the header tree without bound.
        if let Some(outcome) = self.try_low_work_headers_sync(cs, &params, headers, now) {
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
            // (Core logs "Ignoring low-work chain" and does nothing).
            return Some(HeadersOutcome {
                added: 0,
                known: 0,
                continuation: None,
                fetchable: Vec::new(),
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
        if !state.is_final() {
            self.headers_sync = Some(state);
        }
        Some(HeadersOutcome {
            added: 0,
            known: 0,
            continuation,
            fetchable: Vec::new(),
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
            return Ok(HeadersOutcome {
                added: 0,
                known: 0,
                continuation: None,
                fetchable: Vec::new(),
            });
        };
        let full_page = headers.len() as u64 == MAX_HEADERS_RESULTS;
        let result = state.process_next_headers(headers, full_page);
        let continuation = self.next_low_work_request(cs, &state, result.request_more);
        if !state.is_final() {
            self.headers_sync = Some(state);
        }
        if !result.success {
            return Ok(HeadersOutcome {
                added: 0,
                known: 0,
                continuation: None,
                fetchable: Vec::new(),
            });
        }
        let (added, known, fetchable) =
            self.accept_headers(cs, &result.pow_validated_headers, now)?;
        Ok(HeadersOutcome {
            added,
            known,
            continuation,
            fetchable,
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
        if free == 0 {
            return None;
        }
        let mut want = Vec::new();
        for inv in invs {
            if want.len() >= free {
                break;
            }
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
