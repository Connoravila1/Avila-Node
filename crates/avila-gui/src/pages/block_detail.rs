//! Data-driven block summary and transaction composition for the inspector.

use avila_node::inspect::{
    AmountSource, AmountUnknownReason, BlockSummary, BlockTxDetail, BlockTxSummary, BodyState,
};
use eframe::egui::{self, Align, Color32, Layout, RichText, Sense, Stroke, Ui, vec2};

const COMPACT_TRANSACTION_TABLE_WIDTH: f32 = 640.0;

pub struct InspectorView<'a> {
    pub(super) block: &'a BlockSummary,
    pub(super) transactions: &'a [BlockTxSummary],
    pub(super) next_offset: Option<u32>,
    pub(super) loading: bool,
    pub(super) offline_fixture: bool,
    pub(super) selected_tx_index: Option<u32>,
    pub(super) detail: Option<&'a BlockTxDetail>,
    pub(super) detail_status: Option<&'a str>,
    pub(super) detail_loading: bool,
    pub(super) input_offset: u32,
    pub(super) output_offset: u32,
    pub(super) detail_scroll_requested: &'a mut bool,
}

pub fn show(ui: &mut Ui, view: &mut InspectorView<'_>) -> Option<Interaction> {
    ui.add_space(10.0);
    ui.separator();
    ui.horizontal(|ui| {
        ui.heading(format!("Block {}", view.block.height));
        if view.offline_fixture {
            ui.label(RichText::new("Offline fixture").weak());
        } else {
            ui.label(RichText::new("Lookup snapshot").weak()).on_hover_text(
                "Chain membership and validation flags are as of this lookup. Reopen the block to refresh them after a reorganization.",
            );
            let status = if view.block.active_chain {
                "Active chain"
            } else {
                "Stored block"
            };
            ui.label(RichText::new(status).weak());
            if view.block.fully_checked {
                ui.label(RichText::new("Fully checked").color(Color32::from_rgb(108, 175, 139)));
            } else if view.block.snapshot_assumed {
                ui.label(
                    RichText::new("Snapshot-assumed prefix").color(Color32::from_rgb(206, 160, 90)),
                );
            } else {
                ui.label(RichText::new("Not marked fully checked").weak());
            }
        }
    });

    egui::Grid::new("block_detail_facts")
        .num_columns(2)
        .spacing([24.0, 8.0])
        .show(ui, |ui| {
            fact(ui, "Hash", &view.block.hash);
            fact(ui, "Previous block", &view.block.previous_hash);
            fact(ui, "Merkle root", &view.block.merkle_root);
            fact(ui, "Version", &view.block.version.to_string());
            fact(ui, "Timestamp", &format!("{} (Unix)", view.block.time));
            fact(ui, "Bits", &format!("0x{:08x}", view.block.bits));
            fact(ui, "Nonce", &view.block.nonce.to_string());
            fact(
                ui,
                "Transactions",
                &view
                    .block
                    .tx_count
                    .map_or_else(|| "Unavailable".into(), |n| n.to_string()),
            );
            fact(
                ui,
                "Serialized size",
                &view
                    .block
                    .size
                    .map_or_else(|| "Unavailable".into(), format_bytes),
            );
            fact(
                ui,
                "Weight",
                &view
                    .block
                    .weight
                    .map_or_else(|| "Unavailable".into(), |n| format!("{} WU", n)),
            );
        });

    match &view.block.body_state {
        BodyState::Available => {
            let map_action = composition(
                ui,
                view.block,
                view.transactions,
                view.next_offset,
                view.loading,
                view.selected_tx_index,
                !view.detail_loading,
            );
            let table_action = transaction_table(
                ui,
                view.transactions,
                view.selected_tx_index,
                !view.detail_loading,
            );
            let detail_action = transaction_detail(ui, view);
            let action = map_action.or(table_action).or(detail_action);
            if let Some(action) = action {
                return Some(action);
            }
        }
        BodyState::HeaderOnly => {
            ui.add_space(8.0);
            ui.label(
                RichText::new(
                    "Only the header is available; this node has no block body for this hash.",
                )
                .weak(),
            );
        }
        BodyState::Pruned => {
            ui.add_space(8.0);
            ui.label(RichText::new("The block body was pruned from local storage.").weak());
        }
        BodyState::Unavailable => {
            ui.add_space(8.0);
            ui.label(
                RichText::new("The block body is not currently available from local storage.")
                    .weak(),
            );
        }
    }
    if let Some(next) = view.block.next_hash.as_deref() {
        if ui.available_width() < COMPACT_TRANSACTION_TABLE_WIDTH {
            ui.label(RichText::new("Next block").weak());
            wrapped_hash_label(ui, next, 12.0);
        } else {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Next block").weak());
                wrapped_hash_label(ui, next, 12.0);
            });
        }
    }
    None
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Interaction {
    SelectTransaction(u32),
    InputPage(u32),
    OutputPage(u32),
}

fn fact(ui: &mut Ui, name: &str, value: &str) {
    ui.label(RichText::new(name).weak());
    if matches!(name, "Hash" | "Previous block" | "Merkle root") {
        wrapped_hash_label(ui, value, 12.0);
    } else {
        ui.add(
            egui::Label::new(RichText::new(value).monospace())
                .selectable(true)
                .wrap(),
        );
    }
    ui.end_row();
}

fn wrapped_hash_label(ui: &mut Ui, hash: &str, size: f32) {
    let response = ui.add(
        egui::Label::new(RichText::new(hash).monospace().size(size))
            .selectable(true)
            .wrap()
            .sense(Sense::click()),
    );
    if response.clicked() {
        ui.ctx().copy_text(hash.to_owned());
    }
    response
        .on_hover_cursor(egui::CursorIcon::Copy)
        .on_hover_text("Copy the full hash")
        .context_menu(|ui| {
            if ui.button("Copy hash").clicked() {
                ui.ctx().copy_text(hash.to_owned());
                ui.close();
            }
        });
}

fn wrapped_fact(ui: &mut Ui, name: &str, value: String) {
    ui.add(
        egui::Label::new(RichText::new(format!("{name}: {value}")))
            .selectable(true)
            .wrap(),
    );
}

fn composition(
    ui: &mut Ui,
    block: &BlockSummary,
    transactions: &[BlockTxSummary],
    next_offset: Option<u32>,
    loading: bool,
    selected_tx_index: Option<u32>,
    allow_selection: bool,
) -> Option<Interaction> {
    let total = block.tx_count.unwrap_or(0);
    ui.add_space(12.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new("Transaction weight composition").strong());
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let status = if loading {
                "Loading page…".to_owned()
            } else if let Some(next) = next_offset {
                format!(
                    "{} of {total} loaded",
                    transactions.len().min(total as usize)
                ) + &format!(" · more from {next}")
            } else {
                format!("{} transactions", transactions.len())
            };
            ui.label(RichText::new(status).weak());
        });
    });
    if transactions.is_empty() {
        ui.label(RichText::new("No transaction summaries loaded yet.").weak());
        return None;
    }
    ui.label(
        RichText::new("Transaction weight map · area follows loaded tx weight share; shade is log-scaled; framing excluded")
            .weak(),
    );
    let total_weight: u128 = transactions.iter().map(|tx| u128::from(tx.weight)).sum();
    if total_weight == 0 {
        ui.label(RichText::new("Loaded transaction weights are unavailable.").weak());
        return None;
    }
    let map_height = if ui.available_width() < 520.0 {
        136.0
    } else {
        156.0
    };
    let (map_rect, _) = ui.allocate_exact_size(
        vec2(ui.available_width().max(1.0), map_height),
        Sense::hover(),
    );
    ui.painter()
        .rect_filled(map_rect, 4.0, Color32::from_gray(36));
    let rects = treemap_rects(map_rect.shrink(2.0), transactions);
    let max_weight = transactions.iter().map(|tx| tx.weight).max().unwrap_or(1);
    let mut selected = None;
    for (tx, rect) in transactions.iter().zip(rects) {
        if rect.width() <= 0.0 || rect.height() <= 0.0 {
            continue;
        }
        let cell = rect;
        let color = weight_color(tx.weight, max_weight);
        let is_selected = selected_tx_index == Some(tx.index);
        ui.painter().rect_filled(cell, 0.0, color);
        if is_selected {
            ui.painter().rect_stroke(
                cell,
                0.0,
                Stroke::new(2.0, Color32::WHITE),
                egui::StrokeKind::Inside,
            );
        } else {
            ui.painter().rect_stroke(
                cell,
                0.0,
                Stroke::new(0.5, Color32::from_gray(30)),
                egui::StrokeKind::Inside,
            );
        }
        if cell.width() >= 22.0 && cell.height() >= 15.0 {
            ui.painter().text(
                cell.center(),
                egui::Align2::CENTER_CENTER,
                tx.index.to_string(),
                egui::FontId::monospace(10.0),
                if color.r() > 165 && color.g() > 125 {
                    Color32::from_rgb(32, 31, 29)
                } else {
                    Color32::WHITE
                },
            );
        }
        let response = ui
            .interact(
                cell,
                ui.id().with(("block_tx_map_cell", tx.index)),
                if allow_selection {
                    Sense::click()
                } else {
                    Sense::hover()
                },
            )
            .on_hover_text(format!(
                "Transaction {} · {} WU · {} of loaded transaction weight{}",
                tx.index,
                tx.weight,
                weight_share(tx.weight, total_weight),
                if tx.coinbase { " · coinbase" } else { "" }
            ));
        if response.clicked() {
            selected = Some(Interaction::SelectTransaction(tx.index));
        }
    }
    ui.add(
        egui::Label::new(
            RichText::new(
                "Area reflects share of loaded transaction WU; block header and framing are excluded.",
            )
            .weak(),
        )
        .wrap(),
    );
    if next_offset.is_some() {
        ui.add(
            egui::Label::new(RichText::new("Map covers loaded transactions only.").weak()).wrap(),
        );
    }
    selected
}

fn transaction_table(
    ui: &mut Ui,
    transactions: &[BlockTxSummary],
    selected_tx_index: Option<u32>,
    allow_selection: bool,
) -> Option<Interaction> {
    let compact = ui.available_width() < COMPACT_TRANSACTION_TABLE_WIDTH;
    ui.add_space(12.0);
    ui.label(RichText::new("Transactions").strong());
    egui::ScrollArea::vertical()
        .id_salt("block_transaction_rows")
        .max_height(300.0)
        .min_scrolled_height(120.0)
        .show(ui, |ui| {
            // Give the nested vertical area a useful viewport even when the
            // current block has only a few rows. The enclosing page also
            // scrolls vertically; without this minimum its nested area can
            // collapse to a single visible row.
            ui.set_min_height(120.0);
            let mut selected = None;
            if compact {
                for tx in transactions {
                    ui.horizontal_wrapped(|ui| {
                        let index = ui
                            .add_enabled_ui(allow_selection, |ui| {
                                ui.selectable_label(
                                    selected_tx_index == Some(tx.index),
                                    tx.index.to_string(),
                                )
                            })
                            .inner;
                        if index.clicked() {
                            index.request_focus();
                            selected = Some(Interaction::SelectTransaction(tx.index));
                        }
                        // The visible text is shortened, while the widget retains
                        // its full-hash copy action and tx selection behavior.
                        let txid = crate::widgets::hash_label(ui, &tx.txid, 13.0, Some(14));
                        if txid.clicked() && allow_selection {
                            txid.request_focus();
                            selected = Some(Interaction::SelectTransaction(tx.index));
                        }
                    });
                    ui.add(
                        egui::Label::new(
                            RichText::new(format!(
                                "{} · Inputs {} · Outputs {} · Output value {} · Weight {} WU",
                                if tx.coinbase {
                                    "coinbase"
                                } else if tx.has_witness {
                                    "witness"
                                } else {
                                    "standard"
                                },
                                tx.inputs,
                                tx.outputs,
                                format_sats(tx.output_sats),
                                tx.weight
                            ))
                            .weak(),
                        )
                        .wrap(),
                    );
                    ui.separator();
                }
            } else {
                egui::ScrollArea::horizontal()
                    .id_salt("block_transaction_columns")
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        egui::Grid::new("block_transactions")
                            .striped(true)
                            .num_columns(7)
                            .spacing([12.0, 5.0])
                            .show(ui, |ui| {
                                for header in [
                                    "Index",
                                    "Txid",
                                    "Kind",
                                    "Inputs",
                                    "Outputs",
                                    "Output value",
                                    "Weight",
                                ] {
                                    ui.label(RichText::new(header).strong().weak());
                                }
                                ui.end_row();
                                for tx in transactions {
                                    let index = ui
                                        .add_enabled_ui(allow_selection, |ui| {
                                            ui.selectable_label(
                                                selected_tx_index == Some(tx.index),
                                                tx.index.to_string(),
                                            )
                                        })
                                        .inner;
                                    if index.clicked() {
                                        index.request_focus();
                                        selected = Some(Interaction::SelectTransaction(tx.index));
                                    }
                                    // Keep the table compact at narrow window sizes;
                                    // clicking the label or its context menu still
                                    // copies the complete txid.
                                    let txid =
                                        crate::widgets::hash_label(ui, &tx.txid, 13.0, Some(14));
                                    if txid.clicked() && allow_selection {
                                        txid.request_focus();
                                        selected = Some(Interaction::SelectTransaction(tx.index));
                                    }
                                    ui.label(if tx.coinbase {
                                        "coinbase"
                                    } else if tx.has_witness {
                                        "witness"
                                    } else {
                                        "standard"
                                    });
                                    ui.label(tx.inputs.to_string());
                                    ui.label(tx.outputs.to_string());
                                    ui.label(format_sats(tx.output_sats));
                                    ui.label(format!("{} WU", tx.weight));
                                    ui.end_row();
                                }
                            });
                    });
            }
            selected
        })
        .inner
}

fn transaction_detail(ui: &mut Ui, view: &mut InspectorView<'_>) -> Option<Interaction> {
    let tx_index = view.selected_tx_index?;
    let summary = view.transactions.iter().find(|tx| tx.index == tx_index)?;
    ui.add_space(14.0);
    ui.separator();
    let heading = ui.heading(format!("Transaction {} details", tx_index));
    if std::mem::take(&mut *view.detail_scroll_requested) {
        heading.scroll_to_me(Some(egui::Align::Center));
    }
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Txid").weak());
        wrapped_hash_label(ui, &summary.txid, 12.5);
        if view.detail_loading {
            ui.add(egui::Spinner::new());
        }
    });
    ui.label(
        RichText::new(format!(
            "{} · {} WU · {} bytes · {} input(s) · {} output(s)",
            if summary.coinbase {
                "Coinbase"
            } else if summary.has_witness {
                "Witness transaction"
            } else {
                "Transaction"
            },
            summary.weight,
            summary.size,
            summary.inputs,
            summary.outputs
        ))
        .weak(),
    );

    let Some(detail) = view.detail else {
        if let Some(status) = view.detail_status {
            ui.label(RichText::new(status).weak());
        } else {
            ui.label(
                RichText::new("Choose a transaction from the map or table to load details.").weak(),
            );
        }
        return None;
    };
    if detail.block.hash != view.block.hash
        || detail.tx_index != tx_index
        || detail.txid != summary.txid
    {
        ui.colored_label(
            Color32::from_rgb(205, 144, 67),
            "Details belong to a different block or transaction; select the transaction again.",
        );
        return None;
    }

    if !detail.block.active_chain {
        ui.label(
            RichText::new("This stored block is not on the active chain in the detail response.")
                .weak(),
        );
    }
    ui.label(
        RichText::new(if detail.block.fully_checked {
            "Detail response marks this block fully checked."
        } else if detail.block.snapshot_assumed {
            "Detail response marks this block in a snapshot-assumed range."
        } else {
            "Detail response does not mark this block fully checked."
        })
        .weak(),
    );
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Witness txid").weak());
        wrapped_hash_label(ui, &detail.wtxid, 12.0);
        ui.label(
            RichText::new(format!(
                "Version {} · lock time {}",
                detail.version, detail.lock_time
            ))
            .weak(),
        );
    });
    ui.horizontal_wrapped(|ui| {
        wrapped_fact(
            ui,
            "Input amount",
            detail.input_amount_sats.map_or_else(
                || {
                    format!(
                        "unknown ({})",
                        amount_unknown(detail.input_amount_unknown_reason)
                    )
                },
                format_sats,
            ),
        );
        wrapped_fact(
            ui,
            "Fee",
            detail.fee_sats.map_or_else(
                || format!("unknown ({})", amount_unknown(detail.fee_unknown_reason)),
                format_sats,
            ),
        );
        if let Some(fee) = detail.fee_sats
            && let Some(rate) = format_fee_rate(fee, summary.weight)
        {
            wrapped_fact(ui, "Rate", rate);
        }
    });
    if detail.amount_source == Some(AmountSource::BlockUndo) {
        ui.label(
            RichText::new("Input amounts and fee recovered from matching active-chain block undo.")
                .weak(),
        );
    }

    let mut action = None;
    ui.columns(2, |columns| {
        columns[0].label(RichText::new(format!("Inputs · {} total", detail.input_count)).strong());
        if view.input_offset > 0
            && columns[0]
                .add_enabled(!view.detail_loading, egui::Button::new("← Previous inputs"))
                .clicked()
        {
            action = Some(Interaction::InputPage(
                view.input_offset.saturating_sub(100),
            ));
        }
        if let Some(next) = detail.next_input_offset
            && columns[0]
                .add_enabled(!view.detail_loading, egui::Button::new("Next inputs →"))
                .clicked()
        {
            action = Some(Interaction::InputPage(next));
        }
        columns[0].label(
            RichText::new(format!(
                "{}–{} of {}",
                view.input_offset.saturating_add(1),
                view.input_offset.saturating_add(detail.inputs.len() as u32),
                detail.input_count
            ))
            .weak(),
        );
        egui::ScrollArea::vertical()
            .id_salt(("block_tx_inputs", detail.txid.as_str()))
            .max_height(220.0)
            .min_scrolled_height(200.0)
            .show(&mut columns[0], |ui| {
                ui.set_min_height(200.0);
                if detail.inputs.is_empty() {
                    ui.label(RichText::new("No inputs on this page.").weak());
                }
                for input in &detail.inputs {
                    ui.group(|ui| {
                        ui.label(RichText::new(format!("Input {}", input.index)).strong());
                        if let (Some(txid), Some(vout)) =
                            (input.prev_txid.as_deref(), input.prev_vout)
                        {
                            ui.vertical(|ui| {
                                ui.label(RichText::new("Previous output").weak());
                                ui.horizontal_wrapped(|ui| {
                                    wrapped_hash_label(ui, txid, 11.5);
                                    ui.label(format!(":{vout}"));
                                });
                            });
                        } else {
                            ui.add(egui::Label::new("Coinbase null outpoint").wrap());
                        }
                        wrapped_fact(
                            ui,
                            "Value",
                            input.value_sats.map_or_else(
                                || {
                                    format!(
                                        "unknown ({})",
                                        amount_unknown(input.value_unknown_reason)
                                    )
                                },
                                format_sats,
                            ),
                        );
                        ui.add(
                            egui::Label::new(format!("Sequence: 0x{:08x}", input.sequence)).wrap(),
                        );
                        script_summary(ui, "scriptSig", &input.script_sig);
                        if input.witness_item_count > 0 {
                            ui.label(
                                RichText::new(format!(
                                    "Witness: {} item(s){}",
                                    input.witness_item_count,
                                    if input.witness_items_truncated {
                                        " · more omitted"
                                    } else {
                                        ""
                                    }
                                ))
                                .weak(),
                            );
                            for (item_index, item) in input.witness_items.iter().enumerate() {
                                script_summary(ui, &format!("witness[{item_index}]"), item);
                            }
                        }
                    });
                }
            });

        columns[1]
            .label(RichText::new(format!("Outputs · {} total", detail.output_count)).strong());
        if view.output_offset > 0
            && columns[1]
                .add_enabled(
                    !view.detail_loading,
                    egui::Button::new("← Previous outputs"),
                )
                .clicked()
        {
            action = Some(Interaction::OutputPage(
                view.output_offset.saturating_sub(100),
            ));
        }
        if let Some(next) = detail.next_output_offset
            && columns[1]
                .add_enabled(!view.detail_loading, egui::Button::new("Next outputs →"))
                .clicked()
        {
            action = Some(Interaction::OutputPage(next));
        }
        columns[1].label(
            RichText::new(format!(
                "{}–{} of {}",
                view.output_offset.saturating_add(1),
                view.output_offset
                    .saturating_add(detail.outputs.len() as u32),
                detail.output_count
            ))
            .weak(),
        );
        egui::ScrollArea::vertical()
            .id_salt(("block_tx_outputs", detail.txid.as_str()))
            .max_height(220.0)
            .min_scrolled_height(200.0)
            .show(&mut columns[1], |ui| {
                ui.set_min_height(200.0);
                if detail.outputs.is_empty() {
                    ui.label(RichText::new("No outputs on this page.").weak());
                }
                for output in &detail.outputs {
                    ui.group(|ui| {
                        ui.add(
                            egui::Label::new(
                                RichText::new(format!(
                                    "Output {} · {}",
                                    output.index,
                                    format_sats(output.value_sats)
                                ))
                                .strong(),
                            )
                            .wrap(),
                        );
                        if let Some(address) = output.address.as_deref() {
                            ui.label(RichText::new("Address").weak());
                            ui.add(
                                egui::Label::new(RichText::new(address).monospace())
                                    .selectable(true)
                                    .wrap(),
                            );
                        } else {
                            ui.add(
                                egui::Label::new(
                                    RichText::new("Address: no standard address").weak(),
                                )
                                .wrap(),
                            );
                        }
                        script_summary(ui, "scriptPubKey", &output.script_pubkey);
                    });
                }
            });
    });
    action
}

fn script_summary(ui: &mut Ui, label: &str, script: &avila_node::inspect::TxScriptSummary) {
    let shown = if script.truncated {
        format!("{}…", script.hex_prefix)
    } else {
        script.hex_prefix.clone()
    };
    ui.add(
        egui::Label::new(
            RichText::new(format!(
                "{label} · {} bytes{}",
                script.byte_len,
                if script.truncated {
                    " · hex prefix only"
                } else {
                    ""
                }
            ))
            .weak(),
        )
        .wrap(),
    );
    if shown.is_empty() {
        ui.label(RichText::new("(empty script)").monospace().weak());
    } else {
        ui.add(
            egui::Label::new(RichText::new(shown).monospace().size(11.0))
                .selectable(true)
                .wrap(),
        );
    }
}

fn amount_unknown(reason: Option<AmountUnknownReason>) -> &'static str {
    match reason {
        Some(AmountUnknownReason::CoinbaseHasNoPrevoutAmount) => "coinbase has no prevout amount",
        Some(AmountUnknownReason::PreviousOutputsNotLookedUp) => "previous outputs not looked up",
        Some(AmountUnknownReason::UndoUnavailable) => "matching block undo unavailable",
        Some(AmountUnknownReason::NotActiveChain) => "block is not on the active chain",
        Some(AmountUnknownReason::UndoHashMismatch) => "undo block hash did not match",
        Some(AmountUnknownReason::UndoTooLarge) => "undo exceeds the inspection size limit",
        Some(AmountUnknownReason::UndoMalformed) => "undo data is malformed",
        Some(AmountUnknownReason::InconsistentTransactionAmounts) => {
            "transaction amounts are inconsistent"
        }
        None => "not provided by node",
    }
}

fn format_fee_rate(fee_sats: i64, weight: u64) -> Option<String> {
    if fee_sats < 0 || weight == 0 {
        return None;
    }
    let vsize = weight.saturating_add(3) / 4;
    if vsize == 0 {
        return None;
    }
    let hundredths =
        (i128::from(fee_sats) * 100 + i128::from(vsize) / 2).checked_div(i128::from(vsize))?;
    let whole = hundredths / 100;
    let fraction = hundredths % 100;
    Some(format!("{whole}.{fraction:02} sat/vB · {vsize} vB"))
}

fn treemap_rects(bounds: egui::Rect, transactions: &[BlockTxSummary]) -> Vec<egui::Rect> {
    let mut rects = vec![egui::Rect::NOTHING; transactions.len()];
    let weights = transactions
        .iter()
        .map(|tx| u128::from(tx.weight))
        .collect::<Vec<_>>();
    slice_dice(&weights, &mut rects, 0, bounds, true);
    rects
}

fn slice_dice(
    weights: &[u128],
    rects: &mut [egui::Rect],
    start: usize,
    bounds: egui::Rect,
    vertical: bool,
) {
    if weights.is_empty() {
        return;
    }
    if weights.len() == 1 {
        rects[start] = bounds;
        return;
    }
    let total: u128 = weights.iter().sum();
    if total == 0 {
        return;
    }
    let mut left_total = 0_u128;
    let mut split = 1_usize;
    let mut best_difference = u128::MAX;
    let mut prefix = 0_u128;
    for boundary in 1..weights.len() {
        prefix += weights[boundary - 1];
        let difference = prefix.abs_diff(total - prefix);
        if difference < best_difference {
            best_difference = difference;
            left_total = prefix;
            split = boundary;
        }
    }
    let fraction = (left_total as f64 / total as f64).clamp(0.0, 1.0) as f32;
    let (first, second) = if vertical {
        let x = bounds.left() + bounds.width() * fraction;
        (
            egui::Rect::from_min_max(bounds.min, egui::pos2(x, bounds.bottom())),
            egui::Rect::from_min_max(egui::pos2(x, bounds.top()), bounds.max),
        )
    } else {
        let y = bounds.top() + bounds.height() * fraction;
        (
            egui::Rect::from_min_max(bounds.min, egui::pos2(bounds.right(), y)),
            egui::Rect::from_min_max(egui::pos2(bounds.left(), y), bounds.max),
        )
    };
    let pivot = split;
    slice_dice(&weights[..pivot], rects, start, first, !vertical);
    slice_dice(&weights[pivot..], rects, start + pivot, second, !vertical);
}

fn weight_color(weight: u64, maximum: u64) -> Color32 {
    let ratio = if maximum == 0 {
        0.0
    } else {
        ((weight as f64).ln_1p() / (maximum as f64).ln_1p()).clamp(0.0, 1.0) as f32
    };
    let (low, mid, high) = (
        Color32::from_rgb(67, 112, 139),
        Color32::from_rgb(118, 150, 151),
        Color32::from_rgb(224, 165, 76),
    );
    let (from, to, amount) = if ratio <= 0.5 {
        (low, mid, ratio * 2.0)
    } else {
        (mid, high, (ratio - 0.5) * 2.0)
    };
    Color32::from_rgb(
        lerp_channel(from.r(), to.r(), amount),
        lerp_channel(from.g(), to.g(), amount),
        lerp_channel(from.b(), to.b(), amount),
    )
}

fn lerp_channel(from: u8, to: u8, amount: f32) -> u8 {
    (f32::from(from) + (f32::from(to) - f32::from(from)) * amount).round() as u8
}

fn weight_share(weight: u64, total: u128) -> String {
    if total == 0 {
        "0.0%".into()
    } else {
        format!("{:.1}%", weight as f64 / total as f64 * 100.0)
    }
}

fn format_sats(sats: i64) -> String {
    let sign = if sats < 0 { "−" } else { "" };
    let abs = sats.unsigned_abs();
    format!("{sign}{}.{:08} BTC", abs / 100_000_000, abs % 100_000_000)
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1_000 {
        format!("{bytes} B")
    } else {
        format!("{:.1} kB", bytes as f64 / 1_000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{format_fee_rate, treemap_rects};
    use avila_node::inspect::BlockTxSummary;
    use eframe::egui::{pos2, vec2};

    fn tx(index: u32, weight: u64) -> BlockTxSummary {
        BlockTxSummary {
            index,
            txid: format!("tx-{index}"),
            coinbase: index == 0,
            inputs: 1,
            outputs: 1,
            output_sats: 0,
            size: 1,
            weight,
            has_witness: false,
        }
    }

    #[test]
    fn map_cell_area_tracks_measured_weight() {
        let blocks = [tx(0, 1), tx(1, 3), tx(2, 4)];
        let bounds = eframe::egui::Rect::from_min_size(pos2(0.0, 0.0), vec2(800.0, 160.0));
        let rects = treemap_rects(bounds, &blocks);
        let total_area = bounds.width() * bounds.height();
        let weights = [1.0_f32, 3.0, 4.0];
        for (rect, weight) in rects.iter().zip(weights) {
            let actual = (rect.width() * rect.height()) / total_area;
            let expected = weight / 8.0;
            assert!((actual - expected).abs() < 0.001);
        }
    }

    #[test]
    fn map_splits_when_last_transaction_dominates_weight() {
        let blocks = [tx(0, 1), tx(1, 1), tx(2, 100)];
        let bounds = eframe::egui::Rect::from_min_size(pos2(0.0, 0.0), vec2(800.0, 160.0));
        let rects = treemap_rects(bounds, &blocks);
        assert!(
            rects
                .iter()
                .all(|rect| rect.width() > 0.0 && rect.height() > 0.0)
        );
        let total_area = bounds.width() * bounds.height();
        let dominant = rects[2].width() * rects[2].height() / total_area;
        assert!((dominant - 100.0 / 102.0).abs() < 0.001);
    }

    #[test]
    fn fee_rate_uses_rounded_virtual_size_and_is_unknown_without_weight() {
        assert_eq!(
            format_fee_rate(10_000, 400).as_deref(),
            Some("100.00 sat/vB · 100 vB")
        );
        assert_eq!(format_fee_rate(1, 5).as_deref(), Some("0.50 sat/vB · 2 vB"));
        assert_eq!(format_fee_rate(1, 0), None);
        assert_eq!(format_fee_rate(-1, 400), None);
    }
}
