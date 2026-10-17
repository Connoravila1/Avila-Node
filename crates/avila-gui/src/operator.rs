//! Standard-node actions that do not belong to the experimental toybox.

use crate::pages::{Action, Scene};
use crate::rail::Page;
use crate::widgets::{self, Kind};
use eframe::egui::{self, RichText, Ui};
use std::path::Path;

/// Fixed destinations handled by the application shell. These are not
/// arbitrary paths supplied by UI text and the shell must open them without a shell.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatorPath {
    Config,
    Data,
    Logs,
}

/// Draw the operator menu in the standard node chrome.
pub fn show(ui: &mut Ui, s: &Scene, config: Option<&Path>, _data_dir: &Path) -> Option<Action> {
    let mut action = None;
    ui.menu_button("Operator", |ui| {
        ui.set_min_width(248.0);
        widgets::section(ui, "Node folders", None);
        if ui
            .add_enabled(
                config.is_some(),
                egui::Button::new("Open configuration folder"),
            )
            .clicked()
        {
            action = Some(Action::OpenOperatorPath(OperatorPath::Config));
            ui.close();
        }
        if ui.button("Open data folder").clicked() {
            action = Some(Action::OpenOperatorPath(OperatorPath::Data));
            ui.close();
        }
        if ui.button("Open logs folder").clicked() {
            action = Some(Action::OpenOperatorPath(OperatorPath::Logs));
            ui.close();
        }
        ui.separator();
        widgets::section(ui, "Diagnostics", None);
        if widgets::button(ui, "Copy node diagnostics", Kind::Quiet).clicked() {
            ui.ctx().copy_text(diagnostics(s));
            ui.close();
        }
        ui.separator();
        ui.label(RichText::new("Go to").size(12.0).color(s.pal.muted));
        for (title, page) in [
            ("Overview", Page::Overview),
            ("Peers", Page::Peers),
            ("Network traffic", Page::Network),
            ("Activity", Page::Activity),
            ("Settings", Page::Settings),
        ] {
            if ui.button(title).clicked() {
                action = Some(Action::Open(page));
                ui.close();
            }
        }
    });
    action
}

/// Deliberately bounded, address-free, and independent of the config file.
fn diagnostics(s: &Scene) -> String {
    let mut out = String::with_capacity(512);
    out.push_str("Avila node diagnostics\n");
    out.push_str("network: ");
    out.push_str(&s.network.to_string());
    out.push_str("\nmode: ");
    out.push_str(if s.session.demo { "demo" } else { "node" });
    out.push_str("\nstatus: ");
    out.push_str(s.session.phase().label());
    if let Some(view) = &s.session.view {
        use std::fmt::Write as _;
        let _ = writeln!(out, "\nheight: {}", view.connected);
        let _ = writeln!(out, "headers: {}", view.headers);
        let _ = writeln!(out, "connected peers: {}", view.established().count());
        let _ = writeln!(out, "bytes received: {}", view.network_bytes_recv);
        let _ = write!(out, "bytes sent: {}", view.network_bytes_sent);
    } else {
        out.push_str("\nnode view: waiting for first update");
    }
    out
}
