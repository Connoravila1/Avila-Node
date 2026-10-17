//! Data-driven block summary and transaction composition for the inspector.

use avila_node::inspect::{BlockSummary, BlockTxSummary, BodyState};
use eframe::egui::{self, Align, Color32, Layout, RichText, Sense, Stroke, Ui, vec2};

pub fn show(
    ui: &mut Ui,
    block: &BlockSummary,
    transactions: &[BlockTxSummary],
    next_offset: Option<u32>,
    loading: bool,
    offline_fixture: bool,
) {
    ui.add_space(10.0);
    ui.separator();
    ui.horizontal(|ui| {
        ui.heading(format!("Block {}", block.height));
        if offline_fixture {
            ui.label(RichText::new("Offline fixture").weak());
        } else {
            let status = if block.active_chain {
                "Active chain"
            } else {
                "Stored block"
            };
            ui.label(RichText::new(status).weak());
            if block.fully_checked {
                ui.label(RichText::new("Fully checked").color(Color32::from_rgb(108, 175, 139)));
            } else if block.snapshot_assumed {
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
            fact(ui, "Hash", &block.hash);
            fact(ui, "Previous block", &block.previous_hash);
            fact(ui, "Merkle root", &block.merkle_root);
            fact(ui, "Version", &block.version.to_string());
            fact(ui, "Timestamp", &format!("{} (Unix)", block.time));
            fact(ui, "Bits", &format!("0x{:08x}", block.bits));
            fact(ui, "Nonce", &block.nonce.to_string());
            fact(
                ui,
                "Transactions",
                &block
                    .tx_count
                    .map_or_else(|| "Unavailable".into(), |n| n.to_string()),
            );
            fact(
                ui,
                "Serialized size",
                &block
                    .size
                    .map_or_else(|| "Unavailable".into(), format_bytes),
            );
            fact(
                ui,
                "Weight",
                &block
                    .weight
                    .map_or_else(|| "Unavailable".into(), |n| format!("{} WU", n)),
            );
        });

    match &block.body_state {
        BodyState::Available => {
            composition(ui, block, transactions, next_offset, loading);
            transaction_table(ui, transactions);
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
    if let Some(next) = block.next_hash.as_deref() {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Next block").weak());
            ui.label(RichText::new(next).monospace());
        });
    }
}

fn fact(ui: &mut Ui, name: &str, value: &str) {
    ui.label(RichText::new(name).weak());
    ui.label(RichText::new(value).monospace());
    ui.end_row();
}

fn composition(
    ui: &mut Ui,
    block: &BlockSummary,
    transactions: &[BlockTxSummary],
    next_offset: Option<u32>,
    loading: bool,
) {
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
    let (rect, _) =
        ui.allocate_exact_size(vec2(ui.available_width().max(1.0), 38.0), Sense::hover());
    ui.painter().rect_filled(rect, 4.0, Color32::from_gray(36));
    let weight: u128 = transactions.iter().map(|tx| u128::from(tx.weight)).sum();
    if weight == 0 || transactions.is_empty() {
        return;
    }
    let mut x = rect.left();
    for tx in transactions {
        let fraction = (tx.weight as f64 / weight as f64) as f32;
        let width = rect.width() * fraction;
        if width <= 0.0 {
            continue;
        }
        let cell = egui::Rect::from_min_max(
            egui::pos2(x, rect.top()),
            egui::pos2((x + width).min(rect.right()), rect.bottom()),
        );
        let color = if tx.coinbase {
            Color32::from_rgb(222, 161, 75)
        } else {
            Color32::from_rgb(86, 139, 166)
        };
        ui.painter().rect_filled(cell, 1.0, color);
        if tx.index > 0 {
            ui.painter().line_segment(
                [cell.left_top(), cell.left_bottom()],
                Stroke::new(0.5, Color32::from_gray(25)),
            );
        }
        x += width;
        if x >= rect.right() {
            break;
        }
    }
    ui.horizontal(|ui| {
        ui.label(RichText::new("■ Coinbase").color(Color32::from_rgb(222, 161, 75)));
        ui.label(RichText::new("■ Other transactions").color(Color32::from_rgb(86, 139, 166)));
        if next_offset.is_some() {
            ui.label(RichText::new("Composition covers loaded transactions only.").weak());
        }
    });
}

fn transaction_table(ui: &mut Ui, transactions: &[BlockTxSummary]) {
    ui.add_space(12.0);
    ui.label(RichText::new("Transactions").strong());
    egui::ScrollArea::vertical()
        .max_height(300.0)
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
                        ui.label(tx.index.to_string());
                        ui.label(RichText::new(&tx.txid).monospace());
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
