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
    open_advanced: bool,
) -> Option<Action> {
    starting(ui, s, run, node, open_advanced);
    ui.add_space(30.0);
    privacy(ui, s, prefs);
    ui.add_space(30.0);
    appearance(ui, s, prefs);
    ui.add_space(30.0);
    this_node(ui, s, node);
    ui.add_space(30.0);
    widgets::section(ui, "Getting oriented", None);
    if widgets::button(ui, "Replay the intro", Kind::Quiet).clicked() {
        return Some(Action::ReplayTour);
    }
    help(
        ui,
        s,
        "The short slideshow shown on first open — what the node does and what the sync looks like.",
    );
    None
}

fn privacy(ui: &mut Ui, s: &Scene, prefs: &mut Prefs) {
    widgets::section(ui, "Privacy", None);
    grid(ui, "privacy", |ui| {
        key(ui, s, "Peer addresses");
        ui.vertical(|ui| {
            widgets::checkbox(
                ui,
                &mut prefs.hide_addresses,
                "Hide them everywhere (Ctrl+Shift+H)",
            );
            help(
                ui,
                s,
                "For screenshots and screen sharing. The peer graph and the activity log never show addresses; this also masks the table, the peer panel and the session fingerprints.",
            );
        });
        ui.end_row();
    });
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

fn starting(ui: &mut Ui, s: &Scene, run: &mut RunSettings, node: &Node, open_advanced: bool) {
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
            widgets::checkbox(
                ui,
                &mut run.store,
                "Keep it on disk, so the next start resumes",
            );
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
    ui.add_space(10.0);
    let mut header = egui::CollapsingHeader::new(
        RichText::new("Advanced")
            .font(crate::theme::font(crate::theme::MEDIUM, 14.0))
            .color(s.pal.text),
    )
    .id_salt("advanced")
    .open(open_advanced.then_some(true));
    if crate::theme::Skin::current() == crate::theme::Skin::Xp {
        header = header.icon(crate::xp::expander);
    }
    header.show(ui, |ui| advanced(ui, s, run));
    for problem in run.problems() {
        ui.label(RichText::new(problem).size(13.0).color(s.pal.alert));
    }
}

/// What the node supports but most people never need to touch.
fn advanced(ui: &mut Ui, s: &Scene, run: &mut RunSettings) {
    ui.add_space(6.0);
    grid(ui, "advanced-grid", |ui| {
        key(ui, s, "Incoming connections");
        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                widgets::checkbox(ui, &mut run.listen, "Accept them on port");
                field(ui, &mut run.listen_port, "8333", 80.0);
            });
            help(
                ui,
                s,
                "Lets other nodes connect to yours, so you serve the network too. They learn your IP address; behind a router, the port also needs forwarding.",
            );
        });
        ui.end_row();

        key(ui, s, "Cache");
        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                field(ui, &mut run.dbcache_mib, "450", 100.0);
                help(ui, s, "MiB");
            });
            help(
                ui,
                s,
                "Memory for the coin set. More makes the first sync faster.",
            );
        });
        ui.end_row();

        key(ui, s, "Mempool limit");
        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                field(ui, &mut run.maxmempool_mb, "300", 100.0);
                help(ui, s, "MB");
            });
            help(
                ui,
                s,
                "Unconfirmed transactions kept in memory; when it fills, the cheapest leave first.",
            );
        });
        ui.end_row();

        key(ui, s, "Indexes");
        ui.vertical(|ui| {
            widgets::checkbox(ui, &mut run.txindex, "Transaction index");
            help(ui, s, "Look up any transaction by its id, not only your own.");
            widgets::checkbox(ui, &mut run.blockfilterindex, "Block filter index (BIP 158)");
            help(
                ui,
                s,
                "Compact filters that let wallets find their transactions without revealing their addresses.",
            );
            ui.add_enabled_ui(run.blockfilterindex, |ui| {
                widgets::checkbox(
                    ui,
                    &mut run.peerblockfilters,
                    "Serve filters to peers (BIP 157)",
                );
            });
            if !run.blockfilterindex {
                run.peerblockfilters = false;
            }
        });
        ui.end_row();

        key(ui, s, "Verification");
        ui.vertical(|ui| {
            widgets::checkbox(
                ui,
                &mut run.full_verify,
                "Verify every historical signature",
            );
            help(
                ui,
                s,
                "Check all input scripts from genesis (assumevalid=0). Slower to sync; every block's receipt shows its checks ran.",
            );
        });
        ui.end_row();

        key(ui, s, "Electrum server");
        ui.vertical(|ui| {
            field(ui, &mut run.electrum, "Off", 220.0);
            help(
                ui,
                s,
                "An address with a port, like 127.0.0.1:50001, so wallets such as Sparrow can use this node.",
            );
        });
        ui.end_row();
    });
}

fn appearance(ui: &mut Ui, s: &Scene, prefs: &mut Prefs) {
    widgets::section(ui, "Appearance", None);
    grid(ui, "appearance", |ui| {
        key(ui, s, "Theme");
        widgets::segmented(
            ui,
            &mut prefs.theme,
            &[
                (ThemeChoice::Light, "Light"),
                (ThemeChoice::Dark, "Dark"),
                (ThemeChoice::System, "Match the system"),
            ],
        );
        ui.end_row();
        key(ui, s, "Toybox");
        ui.vertical(|ui| {
            widgets::segmented(ui, &mut prefs.toybox, &[(false, "Off"), (true, "On")]);
            help(
                ui,
                s,
                "A game and some silly skins, on their own page. Nothing in it touches the node.",
            );
        });
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
