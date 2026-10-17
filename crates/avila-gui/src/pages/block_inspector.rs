//! State and controls for on-demand block inspection.
//!
//! Lookups go through the node's private in-process control channel. The
//! inspector never calls an HTTP endpoint or performs storage work on the UI
//! thread.

use super::block_detail;
use avila_consensus::hash::{BlockHash, Txid};
use avila_node::inspect::{
    BlockLookup, BlockLookupResult, BlockSummary, BlockTxDetail, BlockTxDetailResult,
    BlockTxSummary,
};
use avila_node::sync::ControlMsg;
use eframe::egui::{self, Align, Layout, RichText, TextEdit, Ui};
use std::str::FromStr;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, Instant};

const PAGE_SIZE: u16 = 100;
const DETAIL_PAGE_SIZE: u16 = 100;
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
    selected_tx_index: Option<u32>,
    tx_detail: Option<BlockTxDetail>,
    tx_detail_pending: Option<Receiver<BlockTxDetailResult>>,
    tx_detail_pending_since: Option<Instant>,
    tx_detail_timed_out: bool,
    tx_detail_generation: u64,
    pending_detail_generation: Option<u64>,
    pending_detail_offsets: Option<(u32, u32)>,
    detail_input_offset: u32,
    detail_output_offset: u32,
    detail_message: Option<String>,
    detail_scroll_requested: bool,
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
            self.selected_tx_index = None;
            self.clear_transaction_detail();
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
        self.selected_tx_index = None;
        self.clear_transaction_detail();
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
        self.selected_tx_index = None;
        self.clear_transaction_detail();
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
            self.selected_tx_index = None;
            self.clear_transaction_detail();
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
                self.selected_tx_index = None;
                self.clear_transaction_detail();
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
                    self.selected_tx_index = None;
                    self.clear_transaction_detail();
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

    fn clear_transaction_detail(&mut self) {
        self.tx_detail_generation = self.tx_detail_generation.wrapping_add(1);
        self.tx_detail = None;
        self.tx_detail_pending = None;
        self.tx_detail_pending_since = None;
        self.tx_detail_timed_out = false;
        self.pending_detail_generation = None;
        self.pending_detail_offsets = None;
        self.detail_input_offset = 0;
        self.detail_output_offset = 0;
        self.detail_message = None;
        self.detail_scroll_requested = false;
    }

    fn request_transaction_detail(
        &mut self,
        sender: Option<&std::sync::mpsc::Sender<ControlMsg>>,
        tx_index: u32,
        input_offset: u32,
        output_offset: u32,
        force: bool,
    ) {
        // Control messages share the node's unbounded command channel. Keep
        // this inspector single-flight so rapid clicks cannot queue work
        // faster than the storage worker can answer it.
        if self.tx_detail_pending.is_some() {
            return;
        }
        let Some(block_hash_text) = self.block.as_ref().map(|block| block.hash.clone()) else {
            return;
        };
        let Some(txid_text) = self
            .transactions
            .iter()
            .find(|transaction| transaction.index == tx_index)
            .map(|transaction| transaction.txid.clone())
        else {
            self.detail_message = Some("That transaction is not in the loaded block page.".into());
            return;
        };
        if !force
            && self.selected_tx_index == Some(tx_index)
            && self.tx_detail.as_ref().is_some_and(|detail| {
                detail.block.hash == block_hash_text
                    && detail.tx_index == tx_index
                    && detail.txid == txid_text
            })
        {
            return;
        }
        if self.is_fixture() {
            self.clear_transaction_detail();
            self.selected_tx_index = Some(tx_index);
            self.detail_scroll_requested = true;
            self.detail_message = Some(
                "This offline fixture includes transaction summaries only; live input/output detail requires a running node.".into(),
            );
            return;
        }
        self.tx_detail_generation = self.tx_detail_generation.wrapping_add(1);
        let generation = self.tx_detail_generation;
        let detail_identity_changed = self.tx_detail.as_ref().is_some_and(|detail| {
            detail.block.hash != block_hash_text
                || detail.tx_index != tx_index
                || detail.txid != txid_text
        });
        let selection_changed = self.selected_tx_index != Some(tx_index) || detail_identity_changed;
        self.selected_tx_index = Some(tx_index);
        if selection_changed {
            // A different tx has a different page identity; discard the old
            // detail and reset its displayed offsets together.
            self.tx_detail = None;
            self.detail_input_offset = 0;
            self.detail_output_offset = 0;
        }
        self.tx_detail_pending = None;
        self.tx_detail_pending_since = None;
        self.tx_detail_timed_out = false;
        self.pending_detail_generation = None;
        self.pending_detail_offsets = None;
        if selection_changed {
            self.detail_scroll_requested = true;
        }
        self.detail_message = Some("Loading transaction details…".into());
        let Some(sender) = sender else {
            self.detail_message = Some(if self.is_fixture() {
                "This offline fixture includes transaction summaries only; live input/output detail requires a running node.".into()
            } else {
                "Transaction detail is available while a live node is running.".into()
            });
            return;
        };
        let Ok(block_hash) = BlockHash::from_str(&block_hash_text) else {
            self.detail_message = Some("The selected block hash is invalid.".into());
            return;
        };
        let Ok(txid) = Txid::from_str(&txid_text) else {
            self.detail_message = Some("The selected transaction ID is invalid.".into());
            return;
        };
        let (reply, receive) = std::sync::mpsc::sync_channel(1);
        match sender.send(ControlMsg::InspectBlockTx {
            block_hash,
            txid,
            tx_index,
            input_offset,
            input_limit: DETAIL_PAGE_SIZE,
            output_offset,
            output_limit: DETAIL_PAGE_SIZE,
            reply,
        }) {
            Ok(()) => {
                self.tx_detail_pending = Some(receive);
                self.tx_detail_pending_since = Some(Instant::now());
                self.pending_detail_generation = Some(generation);
                self.pending_detail_offsets = Some((input_offset, output_offset));
            }
            Err(_) => {
                self.detail_message =
                    Some("The node stopped before it could inspect this transaction.".into());
            }
        }
    }

    fn poll_transaction_detail(&mut self) {
        let Some(receiver) = &self.tx_detail_pending else {
            return;
        };
        let response = match receiver.try_recv() {
            Ok(response) => Some(response),
            Err(TryRecvError::Empty)
                if !self.tx_detail_timed_out
                    && self
                        .tx_detail_pending_since
                        .is_some_and(|started| started.elapsed() >= REQUEST_TIMEOUT) =>
            {
                self.tx_detail_timed_out = true;
                self.detail_message = Some(
                    "Transaction detail exceeded 30 seconds. The outstanding lookup remains single-flight until it returns or the node stops.".into(),
                );
                return;
            }
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => Some(BlockTxDetailResult::Error(
                "The node ended the transaction detail request without a result.".into(),
            )),
        };
        let Some(response) = response else {
            return;
        };
        let response_generation = self.pending_detail_generation;
        let requested_offsets = self.pending_detail_offsets.take();
        self.tx_detail_pending = None;
        self.tx_detail_pending_since = None;
        self.tx_detail_timed_out = false;
        self.pending_detail_generation = None;
        if response_generation != Some(self.tx_detail_generation) {
            return;
        }
        let expected_block_hash = self.block.as_ref().map(|block| block.hash.as_str());
        let expected_tx = self.selected_tx_index.and_then(|index| {
            self.transactions
                .iter()
                .find(|transaction| transaction.index == index)
        });
        match response {
            BlockTxDetailResult::Found { detail }
                if Some(detail.block.hash.as_str()) == expected_block_hash
                    && expected_tx.is_some_and(|tx| {
                        detail.tx_index == tx.index && detail.txid == tx.txid
                    })
                    && requested_offsets.is_some_and(|(input, output)| {
                        Self::detail_page_matches(&detail, input, output)
                    }) =>
            {
                let Some((input_offset, output_offset)) = requested_offsets else {
                    return;
                };
                self.detail_input_offset = input_offset.min(detail.input_count);
                self.detail_output_offset = output_offset.min(detail.output_count);
                self.tx_detail = Some(detail);
                self.detail_message = None;
            }
            BlockTxDetailResult::BodyUnavailable { block }
                if Some(block.hash.as_str()) == expected_block_hash =>
            {
                self.detail_message = Some(format!(
                    "Transaction body unavailable for this block ({})",
                    body_state_label(block.body_state)
                ));
            }
            BlockTxDetailResult::Found { .. } | BlockTxDetailResult::BodyUnavailable { .. } => {
                self.detail_message = Some(
                    "The transaction response did not match the selected block and transaction; retry the inspection.".into(),
                );
            }
            BlockTxDetailResult::NotFound => {
                self.detail_message =
                    Some("The selected transaction was not found at this block position.".into());
            }
            BlockTxDetailResult::Error(error) => self.detail_message = Some(error),
        }
    }

    fn detail_page_matches(detail: &BlockTxDetail, input_offset: u32, output_offset: u32) -> bool {
        let expected_input_len = detail
            .input_count
            .saturating_sub(input_offset)
            .min(u32::from(DETAIL_PAGE_SIZE)) as usize;
        let expected_output_len = detail
            .output_count
            .saturating_sub(output_offset)
            .min(u32::from(DETAIL_PAGE_SIZE)) as usize;
        let expected_input_end = input_offset.checked_add(expected_input_len as u32);
        let expected_output_end = output_offset.checked_add(expected_output_len as u32);
        detail.block.body_state == avila_node::inspect::BodyState::Available
            && detail.inputs.len() <= usize::from(DETAIL_PAGE_SIZE)
            && detail.outputs.len() <= usize::from(DETAIL_PAGE_SIZE)
            && detail.inputs.len() == expected_input_len
            && detail.outputs.len() == expected_output_len
            && detail.inputs.iter().enumerate().all(|(position, input)| {
                input_offset.checked_add(position as u32) == Some(input.index)
            })
            && detail.outputs.iter().enumerate().all(|(position, output)| {
                output_offset.checked_add(position as u32) == Some(output.index)
            })
            && expected_input_end.is_some_and(|end| {
                detail.next_input_offset == (end < detail.input_count).then_some(end)
            })
            && expected_output_end.is_some_and(|end| {
                detail.next_output_offset == (end < detail.output_count).then_some(end)
            })
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
        self.poll_transaction_detail();
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
        let offline_fixture = self.is_fixture();
        let interaction = if let Some(block) = &self.block {
            let mut view = block_detail::InspectorView {
                block,
                transactions: &self.transactions,
                next_offset: self.next_offset,
                loading: self.pending.is_some(),
                offline_fixture,
                selected_tx_index: self.selected_tx_index,
                detail: self.tx_detail.as_ref(),
                detail_status: self.detail_message.as_deref(),
                detail_loading: self.tx_detail_pending.is_some(),
                input_offset: self.detail_input_offset,
                output_offset: self.detail_output_offset,
                detail_scroll_requested: &mut self.detail_scroll_requested,
            };
            block_detail::show(ui, &mut view)
        } else {
            None
        };
        if let Some(interaction) = interaction {
            match interaction {
                block_detail::Interaction::SelectTransaction(index) => {
                    self.request_transaction_detail(sender, index, 0, 0, false);
                }
                block_detail::Interaction::InputPage(offset) => {
                    if let Some(index) = self.selected_tx_index {
                        self.request_transaction_detail(
                            sender,
                            index,
                            offset,
                            self.detail_output_offset,
                            true,
                        );
                    }
                }
                block_detail::Interaction::OutputPage(offset) => {
                    if let Some(index) = self.selected_tx_index {
                        self.request_transaction_detail(
                            sender,
                            index,
                            self.detail_input_offset,
                            offset,
                            true,
                        );
                    }
                }
            }
        }
        if let Some(block) = &self.block {
            if self.transactions.len() >= MAX_DISPLAYED_TXS && self.next_offset.is_some() {
                ui.label(
                    RichText::new(format!(
                        "Showing the first {MAX_DISPLAYED_TXS} of {} transactions; more are available.",
                        block.tx_count.unwrap_or(MAX_DISPLAYED_TXS as u32)
                    ))
                    .weak(),
                );
            } else if let Some(offset) = self.next_offset
                && ui
                    .add_enabled(
                        self.pending.is_none(),
                        egui::Button::new("Load more transactions"),
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

fn body_state_label(state: avila_node::inspect::BodyState) -> &'static str {
    match state {
        avila_node::inspect::BodyState::Available => "available",
        avila_node::inspect::BodyState::HeaderOnly => "header-only",
        avila_node::inspect::BodyState::Pruned => "pruned",
        avila_node::inspect::BodyState::Unavailable => "unavailable",
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::{MAX_DISPLAYED_TXS, PAGE_SIZE, REQUEST_TIMEOUT, State, parse_lookup};
    use avila_consensus::hash::BlockHash;
    use avila_node::inspect::{
        AmountUnknownReason, BlockIdentity, BlockLookup, BlockLookupResult, BlockSummary,
        BlockTxDetail, BlockTxDetailResult, BlockTxSummary, BodyState, TxInputDetail,
        TxOutputDetail, TxScriptSummary,
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

    fn transaction_detail(input_offset: u32, output_offset: u32) -> BlockTxDetail {
        let input_count = 101u32;
        let output_count = 1u32;
        let input_len = input_count
            .saturating_sub(input_offset)
            .min(u32::from(super::DETAIL_PAGE_SIZE));
        let output_len = output_count
            .saturating_sub(output_offset)
            .min(u32::from(super::DETAIL_PAGE_SIZE));
        let input_end = input_offset + input_len;
        let output_end = output_offset + output_len;
        BlockTxDetail {
            block: BlockIdentity {
                hash: BlockHash::ZERO.to_string(),
                height: 7,
                active_chain: true,
                fully_checked: true,
                snapshot_assumed: false,
                body_state: BodyState::Available,
            },
            tx_index: 0,
            txid: BlockHash::ZERO.to_string(),
            wtxid: BlockHash::ZERO.to_string(),
            version: 1,
            lock_time: 0,
            coinbase: false,
            input_count,
            output_count,
            input_amount_sats: None,
            input_amount_unknown_reason: Some(AmountUnknownReason::PreviousOutputsNotLookedUp),
            fee_sats: None,
            fee_unknown_reason: Some(AmountUnknownReason::PreviousOutputsNotLookedUp),
            amount_source: None,
            inputs: (input_offset..input_end)
                .map(|index| TxInputDetail {
                    index,
                    prev_txid: None,
                    prev_vout: None,
                    sequence: 0,
                    value_sats: None,
                    value_unknown_reason: Some(AmountUnknownReason::PreviousOutputsNotLookedUp),
                    script_sig: TxScriptSummary {
                        byte_len: 0,
                        hex_prefix: String::new(),
                        truncated: false,
                    },
                    witness_item_count: 0,
                    witness_items: Vec::new(),
                    witness_items_truncated: false,
                })
                .collect(),
            next_input_offset: (input_end < input_count).then_some(input_end),
            outputs: (output_offset..output_end)
                .map(|index| TxOutputDetail {
                    index,
                    value_sats: 0,
                    address: None,
                    script_pubkey: TxScriptSummary {
                        byte_len: 0,
                        hex_prefix: String::new(),
                        truncated: false,
                    },
                })
                .collect(),
            next_output_offset: (output_end < output_count).then_some(output_end),
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

    #[test]
    fn stale_transaction_detail_generation_is_discarded() {
        let mut state = State {
            block: Some(summary(1)),
            transactions: vec![transaction(0)],
            selected_tx_index: Some(0),
            tx_detail_generation: 4,
            pending_detail_generation: Some(3),
            pending_detail_offsets: Some((100, 0)),
            detail_message: Some("Loading transaction details…".into()),
            ..State::default()
        };

        let (reply, receiver) = std::sync::mpsc::sync_channel(1);
        reply
            .send(BlockTxDetailResult::Found {
                detail: BlockTxDetail {
                    block: BlockIdentity {
                        hash: BlockHash::ZERO.to_string(),
                        height: 7,
                        active_chain: true,
                        fully_checked: true,
                        snapshot_assumed: false,
                        body_state: BodyState::Available,
                    },
                    tx_index: 0,
                    txid: BlockHash::ZERO.to_string(),
                    wtxid: BlockHash::ZERO.to_string(),
                    version: 1,
                    lock_time: 0,
                    coinbase: true,
                    input_count: 1,
                    output_count: 1,
                    input_amount_sats: None,
                    input_amount_unknown_reason: Some(
                        AmountUnknownReason::CoinbaseHasNoPrevoutAmount,
                    ),
                    fee_sats: None,
                    fee_unknown_reason: Some(AmountUnknownReason::CoinbaseHasNoPrevoutAmount),
                    amount_source: None,
                    inputs: Vec::new(),
                    next_input_offset: None,
                    outputs: Vec::new(),
                    next_output_offset: None,
                },
            })
            .expect("detail receiver is live");
        state.tx_detail_pending = Some(receiver);
        state.pending_detail_generation = Some(3);

        state.poll_transaction_detail();

        assert!(state.tx_detail.is_none());
        assert_eq!(state.selected_tx_index, Some(0));
        assert!(state.detail_message.is_some());
        assert!(state.pending_detail_offsets.is_none());
    }

    #[test]
    fn transaction_detail_requests_are_single_flight() {
        let (sender, receiver) = channel();
        let mut state = State {
            block: Some(summary(2)),
            transactions: vec![transaction(0), transaction(1)],
            ..State::default()
        };

        state.request_transaction_detail(Some(&sender), 0, 0, 0, false);
        state.request_transaction_detail(Some(&sender), 1, 0, 0, false);

        let ControlMsg::InspectBlockTx { tx_index, .. } = receiver.try_recv().expect("one request")
        else {
            panic!("state sends transaction detail requests");
        };
        assert_eq!(tx_index, 0);
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
        assert_eq!(state.selected_tx_index, Some(0));
        assert!(state.tx_detail_pending.is_some());
        assert_eq!(state.pending_detail_offsets, Some((0, 0)));
    }

    #[test]
    fn timed_out_transaction_request_stays_single_flight_until_worker_returns() {
        let (sender, receiver) = channel();
        let mut state = State {
            block: Some(summary(2)),
            transactions: vec![transaction(0), transaction(1)],
            ..State::default()
        };
        state.request_transaction_detail(Some(&sender), 0, 0, 0, false);
        let ControlMsg::InspectBlockTx { reply, .. } = receiver.try_recv().expect("request sent")
        else {
            panic!("state sends transaction detail requests");
        };

        state.tx_detail_pending_since = Some(Instant::now() - REQUEST_TIMEOUT);
        state.poll_transaction_detail();
        assert!(state.tx_detail_pending.is_some());
        assert!(state.tx_detail_timed_out);
        assert!(
            state
                .detail_message
                .as_deref()
                .is_some_and(|message| message.contains("remains single-flight"))
        );

        state.request_transaction_detail(Some(&sender), 1, 0, 0, false);
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
        drop(reply);
    }

    #[test]
    fn transaction_detail_pages_require_contiguous_indexes_and_correct_next_offsets() {
        let mut detail = transaction_detail(100, 0);
        assert!(State::detail_page_matches(&detail, 100, 0));

        detail.inputs[0].index = 99;
        assert!(!State::detail_page_matches(&detail, 100, 0));
        detail.inputs[0].index = 100;
        detail.next_input_offset = Some(101);
        assert!(!State::detail_page_matches(&detail, 100, 0));
    }

    #[test]
    fn same_index_with_different_detail_pin_discards_old_page() {
        for changed_txid in [false, true] {
            let (sender, receiver) = channel();
            let mut old_detail = transaction_detail(100, 0);
            if changed_txid {
                old_detail.txid = BlockHash::from_bytes([1; 32]).to_string();
            } else {
                old_detail.block.hash = BlockHash::from_bytes([1; 32]).to_string();
            }
            let mut state = State {
                block: Some(summary(1)),
                transactions: vec![transaction(0)],
                selected_tx_index: Some(0),
                tx_detail: Some(old_detail),
                detail_input_offset: 100,
                detail_output_offset: 0,
                ..State::default()
            };

            state.request_transaction_detail(Some(&sender), 0, 0, 0, true);
            let ControlMsg::InspectBlockTx {
                input_offset,
                output_offset,
                ..
            } = receiver.try_recv().expect("new detail request sent")
            else {
                panic!("state sends transaction detail requests");
            };
            assert_eq!((input_offset, output_offset), (0, 0));
            assert_eq!(state.selected_tx_index, Some(0));
            assert!(state.tx_detail.is_none());
            assert_eq!(
                (state.detail_input_offset, state.detail_output_offset),
                (0, 0)
            );
            assert!(state.detail_scroll_requested);
            assert_eq!(state.pending_detail_offsets, Some((0, 0)));
        }
    }

    #[test]
    fn selected_transaction_keeps_displayed_page_until_requested_page_is_accepted() {
        let (sender, receiver) = channel();
        let old_detail = transaction_detail(0, 0);
        let mut state = State {
            block: Some(summary(1)),
            transactions: vec![transaction(0)],
            selected_tx_index: Some(0),
            tx_detail: Some(old_detail.clone()),
            detail_input_offset: 0,
            detail_output_offset: 0,
            ..State::default()
        };

        state.request_transaction_detail(Some(&sender), 0, 100, 0, true);
        let ControlMsg::InspectBlockTx {
            input_offset,
            output_offset,
            reply,
            ..
        } = receiver.try_recv().expect("page request sent")
        else {
            panic!("state sends transaction detail requests");
        };
        assert_eq!((input_offset, output_offset), (100, 0));
        assert_eq!(
            serde_json::to_value(state.tx_detail.as_ref()).unwrap(),
            serde_json::to_value(&old_detail).unwrap()
        );
        assert_eq!(
            (state.detail_input_offset, state.detail_output_offset),
            (0, 0)
        );
        assert_eq!(state.pending_detail_offsets, Some((100, 0)));

        reply
            .send(BlockTxDetailResult::Found {
                detail: transaction_detail(100, 0),
            })
            .expect("detail receiver remains live");
        state.poll_transaction_detail();

        assert_eq!(
            serde_json::to_value(state.tx_detail.as_ref()).unwrap(),
            serde_json::to_value(transaction_detail(100, 0)).unwrap()
        );
        assert_eq!(
            (state.detail_input_offset, state.detail_output_offset),
            (100, 0)
        );
        assert!(state.pending_detail_offsets.is_none());
        assert!(state.detail_message.is_none());
    }

    #[test]
    fn rejected_detail_pin_or_page_retains_last_detail_and_offsets() {
        for wrong_page in [true, false] {
            let (sender, receiver) = channel();
            let old_detail = transaction_detail(0, 0);
            let mut state = State {
                block: Some(summary(1)),
                transactions: vec![transaction(0)],
                selected_tx_index: Some(0),
                tx_detail: Some(old_detail.clone()),
                detail_input_offset: 0,
                detail_output_offset: 0,
                ..State::default()
            };
            state.request_transaction_detail(Some(&sender), 0, 100, 0, true);
            let ControlMsg::InspectBlockTx { reply, .. } =
                receiver.try_recv().expect("page request sent")
            else {
                panic!("state sends transaction detail requests");
            };
            let mut bad_detail = if wrong_page {
                transaction_detail(0, 0)
            } else {
                transaction_detail(100, 0)
            };
            if !wrong_page {
                bad_detail.block.hash = BlockHash::from_bytes([1; 32]).to_string();
            }
            reply
                .send(BlockTxDetailResult::Found { detail: bad_detail })
                .expect("detail receiver remains live");
            state.poll_transaction_detail();

            assert_eq!(
                serde_json::to_value(state.tx_detail.as_ref()).unwrap(),
                serde_json::to_value(&old_detail).unwrap()
            );
            assert_eq!(
                (state.detail_input_offset, state.detail_output_offset),
                (0, 0)
            );
            assert!(state.pending_detail_offsets.is_none());
            assert!(
                state
                    .detail_message
                    .as_deref()
                    .is_some_and(|message| message.contains("did not match"))
            );
        }
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
