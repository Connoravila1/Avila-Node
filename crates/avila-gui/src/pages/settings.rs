//! How the next run starts, how the interface looks, and what this build
//! of the node is.

use super::{Action, Scene};
use crate::prefs::{Prefs, ThemeChoice};
use crate::session::RunSettings;
use crate::theme::mono;
use crate::widgets::{self, Kind};
use avila_core::CapabilityState;
use avila_node::Node;
use eframe::egui::{self, RichText, TextEdit, Ui};

pub fn show(
    ui: &mut Ui,
    s: &Scene,
    run: &mut RunSettings,
    prefs: &mut Prefs,
    node: &Node,
) -> Option<Action> {
    starting(ui, s, run, node);
    ui.add_space(30.0);
    appearance(ui, s, prefs);
    ui.add_space(30.0);
    this_node(ui, s, node);
    None
}

fn grid(ui: &mut Ui, id: &str, rows: impl FnOnce(&mut Ui)) {
    egui::Grid::new(id)
        .num_columns(2)
        .spacing([28.0, 16.0])
        .min_col_width(150.0)
        .show(ui, rows);
}

fn key(ui: &mut Ui, s: &Scene, text: &str) {
    ui.label(RichText::new(text).size(14.0).color(s.pal.text));
}

fn help(ui: &mut Ui, s: &Scene, text: &str) {
    ui.label(RichText::new(text).size(12.5).color(s.pal.muted));
}

fn field(ui: &mut Ui, value: &mut String, hint: &str, width: f32) {
    ui.add(
        TextEdit::singleline(value)
            .hint_text(hint)
            .font(mono(13.0))
            .desired_width(width)
            .margin(egui::vec2(10.0, 7.0)),
    );
}

fn starting(ui: &mut Ui, s: &Scene, run: &mut RunSettings, node: &Node) {
    let note = s
        .session
        .running()
        .then_some("changes apply the next time the node starts");
    widgets::section(ui, "Starting the node", note);
    grid(ui, "run", |ui| {
        key(ui, s, "Connect to");
        ui.vertical(|ui| {
            field(ui, &mut run.connect, "DNS seeds only", 360.0);
            help(
                ui,
                s,
                "Extra peers to dial, as host:port, separated by commas.",
            );
        });
        ui.end_row();

        key(ui, s, "Proxy");
        ui.vertical(|ui| {
            field(ui, &mut run.proxy, "Connect directly", 360.0);
            help(
                ui,
                s,
                "A SOCKS5 proxy for every connection. Tor listens on 127.0.0.1:9050.",
            );
        });
        ui.end_row();

        key(ui, s, "Run");
        ui.vertical(|ui| {
            let mut bounded = run.stop_after.is_some();
            widgets::segmented(
                ui,
                &mut bounded,
                &[(false, "Until I stop it"), (true, "For a number of blocks")],
            );
            match (bounded, run.stop_after) {
                (false, _) => run.stop_after = None,
                (true, None) => run.stop_after = Some(1_000),
                (true, Some(_)) => {}
            }
            if let Some(n) = &mut run.stop_after {
                ui.horizontal(|ui| {
                    ui.add(egui::DragValue::new(n).range(1..=10_000_000).speed(10.0));
                    help(ui, s, "blocks, then stop");
                });
            }
        });
        ui.end_row();

        key(ui, s, "Chainstate");
        ui.vertical(|ui| {
            ui.checkbox(&mut run.store, "Keep it on disk, so the next start resumes");
            ui.label(
                RichText::new(node.config().network_data_dir().display().to_string())
                    .font(mono(12.0))
                    .color(s.pal.muted),
            );
        });
        ui.end_row();

        key(ui, s, "Prune");
        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                field(ui, &mut run.prune_mib, "Keep every block", 160.0);
                help(ui, s, "MiB");
            });
            help(
                ui,
                s,
                "Delete old block files to stay under this size. Needs the chainstate kept on disk.",
            );
        });
        ui.end_row();
    });
    for problem in run.problems() {
        ui.label(RichText::new(problem).size(13.0).color(s.pal.alert));
    }
}

fn appearance(ui: &mut Ui, s: &Scene, prefs: &mut Prefs) {
    widgets::section(ui, "Appearance", None);
    grid(ui, "appearance", |ui| {
        key(ui, s, "Theme");
        widgets::segmented(
            ui,
            &mut prefs.theme,
            &[
                (ThemeChoice::System, "Match the system"),
                (ThemeChoice::Light, "Light"),
                (ThemeChoice::Dark, "Dark"),
            ],
        );
        ui.end_row();
        key(ui, s, "Size");
        let mut size = prefs.size;
        let options: Vec<(u32, &str)> = Prefs::SIZES
            .iter()
            .map(|(v, label)| ((v * 100.0).round() as u32, *label))
            .collect();
        let mut pick = (size * 100.0).round() as u32;
        if widgets::segmented(ui, &mut pick, &options) {
            size = pick as f32 / 100.0;
        }
        prefs.size = size;
        ui.end_row();
    });
}

fn this_node(ui: &mut Ui, s: &Scene, node: &Node) {
    let config = node.config();
    widgets::section(ui, "This node", None);
    grid(ui, "node", |ui| {
        let rows = [
            ("Version", env!("CARGO_PKG_VERSION").to_owned()),
            ("Network", config.get().network.to_string()),
            (
                "Data directory",
                config.network_data_dir().display().to_string(),
            ),
            (
                "Configuration schema",
                config.get().schema_version.to_string(),
            ),
            (
                "Journal capacity",
                format!("{} events", config.event_capacity()),
            ),
        ];
        for (label, value) in rows {
            ui.label(RichText::new(label).size(14.0).color(s.pal.muted));
            ui.horizontal(|ui| {
                ui.add(
                    egui::Label::new(RichText::new(&value).font(mono(13.0)).color(s.pal.text))
                        .selectable(true),
                );
                if label == "Data directory" && widgets::button(ui, "Copy", Kind::Quiet).clicked() {
                    ui.ctx().copy_text(value.clone());
                }
            });
            ui.end_row();
        }
    });
    ui.add_space(24.0);
    widgets::section(
        ui,
        "What’s built",
        Some("updated only when the code and its tests exist"),
    );
    grid(ui, "capabilities", |ui| {
        for cap in avila_core::CAPABILITIES {
            ui.label(RichText::new(cap.name).size(14.0).color(s.pal.text));
            let (text, color) = match cap.state {
                CapabilityState::Implemented => ("Built", s.pal.text),
                CapabilityState::Planned => ("Planned", s.pal.faint),
            };
            ui.label(RichText::new(text).size(13.0).color(color));
            ui.end_row();
        }
    });
}
