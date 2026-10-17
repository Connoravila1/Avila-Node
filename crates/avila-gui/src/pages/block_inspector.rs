//! State and controls for on-demand block inspection.
//!
//! Lookups go through the node's private in-process control channel. The
//! inspector never calls an HTTP endpoint or performs storage work on the UI
//! thread.

use super::block_detail;
use avila_consensus::hash::BlockHash;
use avila_node::inspect::{BlockLookup, BlockLookupResult, BlockSummary, BlockTxSummary};
use avila_node::sync::ControlMsg;
use eframe::egui::{self, Align, Layout, RichText, TextEdit, Ui};
use std::str::FromStr;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, Instant};

const PAGE_SIZE: u16 = 100;
const MAX_DISPLAYED_TXS: usize = 2_000;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Default)]
pub struct State {
    draft: String,
    lookup: Option<BlockLookup>,
    pending: Option<Receiver<BlockLookupResult>>,
    pending_since: Option<Instant>,
    scroll_requested: bool,
    was_live: bool,
    #[cfg(feature = "devtools")]
    fixture: bool,
    block: Option<BlockSummary>,
    transactions: Vec<BlockTxSummary>,
    next_offset: Option<u32>,
    message: Option<String>,
}

impl State {
    /// Forget observations across a stop/start cycle. A selection describes
    /// one chainstate snapshot and should not silently survive a new run.
    pub fn update_liveness(&mut self, live: bool) {
        if !live && self.was_live {
            self.pending = None;
            self.pending_since = None;
            self.lookup = None;
            self.block = None;
            self.transactions.clear();
            self.next_offset = None;
            self.message = Some("The node stopped; inspect again after it starts.".into());
            #[cfg(feature = "devtools")]
            {
                self.fixture = false;
            }
        } else if live
            && !self.was_live
            && self.message.as_deref() == Some("The node stopped; inspect again after it starts.")
        {
            self.message = None;
        }
        #[cfg(feature = "devtools")]
        if live && self.fixture {
            self.clear_fixture_data();
        }
        self.was_live = live;
    }

    #[cfg(feature = "devtools")]
    pub fn set_offline_genesis_fixture(&mut self) {
        let Some(block) = avila_consensus::params::Network::Mainnet
            .params()
            .genesis_block()
        else {
            self.message = Some("Mainnet genesis fixture could not be loaded.".into());
            return;
        };
        let mut transactions = Vec::with_capacity(block.transactions.len());
        for (index, tx) in block.transactions.iter().enumerate() {
            let Some(output_sats) = tx
                .outputs
                .iter()
                .try_fold(0i64, |sum, output| sum.checked_add(output.value))
            else {
                self.message = Some("Mainnet genesis output total overflowed.".into());
                return;
            };
            transactions.push(BlockTxSummary {
                index: index as u32,
                txid: tx.txid().to_string(),
                coinbase: tx.is_coinbase(),
                inputs: tx.inputs.len() as u32,
                outputs: tx.outputs.len() as u32,
                output_sats,
                size: tx.size_with_witness() as u64,
                weight: tx.weight() as u64,
                has_witness: tx.has_witness(),
            });
        }
        let summary = BlockSummary {
            hash: block.block_hash().to_string(),
            height: 0,
            previous_hash: block.header.prev_block_hash.to_string(),
            next_hash: None,
            version: block.header.version,
            bits: block.header.bits.0,
            time: block.header.time,
            nonce: block.header.nonce,
            merkle_root: block.header.merkle_root.to_string(),
            active_chain: false,
            fully_checked: false,
            snapshot_assumed: false,
            body_state: avila_node::inspect::BodyState::Available,
            tx_count: Some(block.transactions.len() as u32),
            size: Some(block.size_with_witness() as u64),
            weight: Some(block.weight() as u64),
        };
        self.lookup = None;
        self.pending = None;
        self.pending_since = None;
        self.block = Some(summary);
        self.transactions = transactions;
        self.next_offset = None;
        self.message = None;
        self.draft = "0".into();
        self.scroll_requested = true;
        self.fixture = true;
    }

    #[cfg(feature = "devtools")]
    pub fn clear_fixture(&mut self) {
        if self.fixture {
            self.clear_fixture_data();
            self.draft.clear();
        }
    }

    #[cfg(feature = "devtools")]
    fn clear_fixture_data(&mut self) {
        self.fixture = false;
        self.block = None;
        self.transactions.clear();
        self.lookup = None;
        self.next_offset = None;
        self.message = None;
    }

    fn is_fixture(&self) -> bool {
        #[cfg(feature = "devtools")]
        {
            self.fixture
        }
        #[cfg(not(feature = "devtools"))]
        {
            false
        }
    }

    /// Queue a lookup without waiting for the node thread. `tx_offset == 0`
    /// begins a new block selection; nonzero offsets append a transaction page.
    pub fn request(
        &mut self,
        sender: Option<&std::sync::mpsc::Sender<ControlMsg>>,
        lookup: BlockLookup,
        tx_offset: u32,
    ) {
        #[cfg(feature = "devtools")]
        if self.fixture {
            self.clear_fixture_data();
        }
        let Some(sender) = sender else {
            self.message =
                Some("Block inspection is available while a live node is running.".into());
            return;
        };
        if self.pending.is_some() {
            return;
        }
        if tx_offset == 0 {
            self.scroll_requested = true;
            self.lookup = Some(lookup);
            self.block = None;
            self.transactions.clear();
            self.next_offset = None;
            self.message = Some("Looking up block…".into());
        } else {
            if self.transactions.len() >= MAX_DISPLAYED_TXS {
                self.message = Some(format!(
                    "Display limit reached: at most {MAX_DISPLAYED_TXS} transaction summaries are retained."
                ));
                return;
            }
            self.message = Some("Loading transactions…".into());
        }

        let remaining = MAX_DISPLAYED_TXS.saturating_sub(self.transactions.len());
        let tx_limit = PAGE_SIZE
            .min(remaining.min(usize::from(u16::MAX)) as u16)
            .max(1);
        let (reply, receive) = std::sync::mpsc::sync_channel(1);
        match sender.send(ControlMsg::InspectBlock {
            lookup,
            tx_offset,
            tx_limit,
            reply,
        }) {
            Ok(()) => {
                self.pending = Some(receive);
                self.pending_since = Some(Instant::now());
            }
            Err(_) => {
                self.message = Some("The node stopped before it could inspect this block.".into())
            }
        }
    }

    pub fn poll(&mut self) {
        let Some(receiver) = &self.pending else {
            return;
        };
        let response = match receiver.try_recv() {
            Ok(response) => Some(response),
            Err(TryRecvError::Empty)
                if self
                    .pending_since
                    .is_some_and(|started| started.elapsed() >= REQUEST_TIMEOUT) =>
            {
                Some(BlockLookupResult::Error(
                    "The block lookup timed out; retry when the node is responsive.".into(),
                ))
            }
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => Some(BlockLookupResult::Error(
                "The node ended the inspection request without a result.".into(),
            )),
        };
        let Some(response) = response else {
            return;
        };
        self.pending = None;
        self.pending_since = None;
        match response {
            BlockLookupResult::NotFound => {
                self.block = None;
                self.transactions.clear();
                self.next_offset = None;
                self.message = Some("No stored block matched that height or hash.".into());
            }
            BlockLookupResult::Error(error) => self.message = Some(error),
            BlockLookupResult::Found {
                block,
                transactions,
                next_offset,
            } => {
                let same_block = self
                    .block
                    .as_ref()
                    .is_some_and(|current| current.hash == block.hash);
                if !same_block {
                    self.transactions.clear();
                }
                self.block = Some(block);
                for transaction in transactions {
                    if !self
                        .transactions
                        .iter()
                        .any(|known| known.index == transaction.index)
                    {
                        self.transactions.push(transaction);
                    }
                }
                self.transactions
                    .sort_by_key(|transaction| transaction.index);
                self.next_offset = next_offset;
                self.message = None;
            }
        }
    }

    /// Draw search, navigation and the selected block details.
    pub fn ui(
        &mut self,
        ui: &mut Ui,
        sender: Option<&std::sync::mpsc::Sender<ControlMsg>>,
        validated_height: u32,
        header_height: u32,
    ) {
        self.update_liveness(sender.is_some());
        self.poll();
        ui.separator();
        let heading = ui.heading("Block inspector");
        if std::mem::take(&mut self.scroll_requested) {
            heading.scroll_to_me(Some(egui::Align::TOP));
        }
        if self.is_fixture() {
            ui.colored_label(
                egui::Color32::from_rgb(198, 146, 72),
                "Offline mainnet genesis fixture — not live node data",
            );
        }
        ui.horizontal(|ui| {
            ui.label("Height or block hash");
            let edit = ui.add(
                TextEdit::singleline(&mut self.draft)
                    .desired_width(310.0)
                    .hint_text("e.g. 840000 or a 64-character hash"),
            );
            let submit_button =
                ui.add_enabled(self.pending.is_none(), egui::Button::new("Inspect"));
            let submit = submit_button.clicked()
                || (self.pending.is_none()
                    && edit.lost_focus()
                    && ui.input(|input| input.key_pressed(egui::Key::Enter)));
            if submit {
                if let Some(lookup) = parse_lookup(&self.draft) {
                    self.request(sender, lookup, 0);
                } else {
                    self.message =
                        Some("Enter a block height or a valid 64-character block hash.".into());
                }
            }
        });

        ui.horizontal(|ui| {
            let previous = self
                .block
                .as_ref()
                .filter(|block| block.height > 0)
                .and_then(|block| BlockHash::from_str(&block.previous_hash).ok());
            if ui
                .add_enabled(
                    previous.is_some() && self.pending.is_none(),
                    egui::Button::new("← Previous"),
                )
                .clicked()
                && let Some(hash) = previous
            {
                self.draft = hash.to_string();
                self.request(sender, BlockLookup::Hash(hash), 0);
            }
            let next = self
                .block
                .as_ref()
                .and_then(|block| block.next_hash.as_deref())
                .and_then(|hash| BlockHash::from_str(hash).ok());
            if ui
                .add_enabled(
                    next.is_some() && self.pending.is_none(),
                    egui::Button::new("Next →"),
                )
                .clicked()
                && let Some(hash) = next
            {
                self.draft = hash.to_string();
                self.request(sender, BlockLookup::Hash(hash), 0);
            }
            if !self.is_fixture() {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new(format!(
                            "Validated {validated_height} · Headers {header_height}"
                        ))
                        .weak(),
                    );
                });
            }
        });

        if let Some(message) = &self.message {
            ui.label(RichText::new(message).weak());
        }
        if let Some(block) = &self.block {
            block_detail::show(
                ui,
                block,
                &self.transactions,
                self.next_offset,
                self.pending.is_some(),
                self.is_fixture(),
            );
            if self.transactions.len() >= MAX_DISPLAYED_TXS && self.next_offset.is_some() {
                ui.label(RichText::new(format!(
                    "Showing the first {MAX_DISPLAYED_TXS} of {} transactions; more are available.",
                    block.tx_count.unwrap_or(MAX_DISPLAYED_TXS as u32)
                )).weak());
            } else if let Some(offset) = self.next_offset
                && ui
                    .add_enabled(
                        self.pending.is_none(),
                        egui::Button::new("Load next 100 transactions"),
                    )
                    .clicked()
                && let Some(lookup) = self.lookup
            {
                self.request(sender, lookup, offset);
            }
        }
        if self.pending.is_some() {
            ui.add(egui::Spinner::new());
        }
    }
}

fn parse_lookup(value: &str) -> Option<BlockLookup> {
    let value = value.trim();
    if let Ok(height) = value.parse::<u32>() {
        return Some(BlockLookup::Height(height));
    }
    BlockHash::from_str(value).ok().map(BlockLookup::Hash)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::{MAX_DISPLAYED_TXS, PAGE_SIZE, REQUEST_TIMEOUT, State, parse_lookup};
    use avila_consensus::hash::BlockHash;
    use avila_node::inspect::{
        BlockLookup, BlockLookupResult, BlockSummary, BlockTxSummary, BodyState,
    };
    use avila_node::sync::ControlMsg;
    use std::sync::mpsc::{TryRecvError, channel};
    use std::time::Instant;

    fn summary(tx_count: u32) -> BlockSummary {
        BlockSummary {
            hash: BlockHash::ZERO.to_string(),
            height: 7,
            previous_hash: BlockHash::ZERO.to_string(),
            next_hash: None,
            version: 1,
            bits: 0,
            time: 1,
            nonce: 0,
            merkle_root: BlockHash::ZERO.to_string(),
            active_chain: true,
            fully_checked: true,
            snapshot_assumed: false,
            body_state: BodyState::Available,
            tx_count: Some(tx_count),
            size: Some(1_000),
            weight: Some(4_000),
        }
    }

    fn transaction(index: u32) -> BlockTxSummary {
        BlockTxSummary {
            index,
            txid: BlockHash::ZERO.to_string(),
            coinbase: index == 0,
            inputs: 1,
            outputs: 1,
            output_sats: 50,
            size: 100,
            weight: 400,
            has_witness: false,
        }
    }

    #[test]
    fn lookup_input_accepts_heights_and_rejects_partial_hashes() {
        assert!(matches!(
            parse_lookup(" 840000 "),
            Some(BlockLookup::Height(840_000))
        ));
        assert!(matches!(
            parse_lookup("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),
            Some(BlockLookup::Hash(_))
        ));
        assert!(parse_lookup("000019d6689c085ae165831e934ff763ae46a6c172b3f1b60a8ce26f").is_none());
        assert!(parse_lookup("nope").is_none());
    }

    #[test]
    fn paged_results_are_retained_only_to_the_display_bound() {
        let (sender, receiver) = channel();
        let total = (MAX_DISPLAYED_TXS + usize::from(PAGE_SIZE)) as u32;
        let mut state = State::default();
        state.request(Some(&sender), BlockLookup::Height(7), 0);

        for start in (0..MAX_DISPLAYED_TXS).step_by(usize::from(PAGE_SIZE)) {
            let ControlMsg::InspectBlock {
                lookup,
                tx_offset,
                tx_limit,
                reply,
            } = receiver.try_recv().expect("each requested page is sent")
            else {
                panic!("only block inspections are sent by the state");
            };
            assert_eq!(lookup, BlockLookup::Height(7));
            assert_eq!(tx_offset as usize, start);
            assert_eq!(usize::from(tx_limit), PAGE_SIZE as usize);
            let end = start + usize::from(tx_limit);
            let transactions = (start..end)
                .map(|index| transaction(index as u32))
                .collect();
            let next_offset = (end < total as usize).then_some(end as u32);
            reply
                .send(BlockLookupResult::Found {
                    block: summary(total),
                    transactions,
                    next_offset,
                })
                .expect("UI receiver remains connected");
            state.poll();
            assert_eq!(state.transactions.len(), end);
            if let Some(offset) = state.next_offset {
                state.request(Some(&sender), BlockLookup::Height(7), offset);
            }
        }

        assert_eq!(state.transactions.len(), MAX_DISPLAYED_TXS);
        assert_eq!(state.next_offset, Some(MAX_DISPLAYED_TXS as u32));
        state.request(
            Some(&sender),
            BlockLookup::Height(7),
            MAX_DISPLAYED_TXS as u32,
        );
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
        assert!(
            state
                .message
                .as_deref()
                .is_some_and(|message| message.contains("Display limit"))
        );
    }

    #[test]
    fn pending_request_times_out_without_blocking_ui_poll() {
        let (sender, receiver) = channel();
        let mut state = State::default();
        state.request(Some(&sender), BlockLookup::Height(7), 0);
        let ControlMsg::InspectBlock { reply, .. } = receiver.try_recv().expect("request sent")
        else {
            panic!("state sends a block inspection");
        };
        state.pending_since = Some(Instant::now() - REQUEST_TIMEOUT);
        state.poll();
        assert!(state.pending.is_none());
        assert!(
            state
                .message
                .as_deref()
                .is_some_and(|message| message.contains("timed out"))
        );
        drop(reply);
    }

    #[test]
    fn stopping_discards_the_previous_chain_snapshot() {
        let (sender, receiver) = channel();
        let mut state = State::default();
        state.update_liveness(true);
        state.request(Some(&sender), BlockLookup::Height(7), 0);
        let ControlMsg::InspectBlock { reply, .. } = receiver.try_recv().expect("request sent")
        else {
            panic!("state sends a block inspection");
        };
        reply
            .send(BlockLookupResult::Found {
                block: summary(1),
                transactions: vec![transaction(0)],
                next_offset: None,
            })
            .expect("state remains connected");
        state.poll();
        assert!(state.block.is_some());
        state.update_liveness(false);
        assert!(state.block.is_none());
        assert!(state.transactions.is_empty());
        assert!(state.pending.is_none());
    }

    #[cfg(feature = "devtools")]
    #[test]
    fn offline_capture_fixture_is_measured_from_mainnet_genesis() {
        let genesis = avila_consensus::params::Network::Mainnet
            .params()
            .genesis_block()
            .expect("mainnet parameters include genesis");
        let mut state = State::default();
        state.set_offline_genesis_fixture();

        let block = state.block.as_ref().expect("fixture block is installed");
        assert_eq!(block.hash, genesis.block_hash().to_string());
        assert_eq!(block.height, 0);
        assert_eq!(block.tx_count, Some(genesis.transactions.len() as u32));
        assert_eq!(block.size, Some(genesis.size_with_witness() as u64));
        assert_eq!(block.weight, Some(genesis.weight() as u64));
        assert!(!block.active_chain && !block.fully_checked && !block.snapshot_assumed);
        assert_eq!(state.transactions.len(), genesis.transactions.len());
        assert_eq!(
            state.transactions[0].txid,
            genesis.transactions[0].txid().to_string()
        );
        assert!(state.transactions[0].coinbase);
        assert!(state.fixture);
    }
}
