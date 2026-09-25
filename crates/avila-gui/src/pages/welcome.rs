//! The first-run sheet — what a brand-new user sees before any sync
//! starts. Three choices that shape the run (prune target, verify-
//! everything, proxy) and an explicit Start. Once they've been here,
//! `Prefs.welcomed` is set and later launches can autostart.

use super::{Action, Scene};
use crate::session::RunSettings;
use crate::theme::{self, mono};
use crate::widgets::{self, Kind};
use eframe::egui::{Align, Layout, RichText, TextEdit, Ui, vec2};

pub fn show(ui: &mut Ui, s: &Scene, run: &mut RunSettings) -> Option<Action> {
    let pal = s.pal;
    ui.add_space(40.0);
    ui.vertical_centered(|ui| {
        ui.label(
            RichText::new("Avila Node")
                .font(theme::font(theme::TITLE, 30.0))
                .color(pal.text),
        );
        ui.add_space(10.0);
        ui.label(
            RichText::new(
                "Your own Bitcoin node. It downloads every block from the network \
                 and checks it on this machine — nobody else's server says what's true.",
            )
            .font(theme::font(theme::MEDIUM, 15.0))
            .color(pal.muted),
        );
    });
    ui.add_space(28.0);

    ui.vertical_centered(|ui| {
        ui.set_max_width(460.0);
        ui.allocate_ui_with_layout(vec2(460.0, 0.0), Layout::top_down(Align::Min), |ui| {
            note(
                ui,
                s,
                "The first sync is the long part — the whole history, \
                     about 700 GB downloaded through peers over days. \
                     Once it's done, keeping up is seconds a day.",
            );
            ui.add_space(4.0);
            note(
                ui,
                s,
                "It resumes where it stops — closing the app never \
                     loses progress.",
            );
            ui.add_space(18.0);

            widgets::label(ui, "How much chain to keep");
            row(ui, |ui| {
                field(ui, &mut run.prune_mib, "Keep everything", 110.0);
                ui.label(
                    RichText::new("MiB of recent blocks")
                        .font(theme::font(theme::MEDIUM, 13.0))
                        .color(pal.muted),
                );
            });
            note(
                ui,
                s,
                "2048 keeps the last few days — enough for reorgs and \
                     serving. Blank keeps the whole chain (~700 GB and \
                     growing). Verification is identical either way.",
            );
            ui.add_space(14.0);

            widgets::checkbox(
                ui,
                &mut run.full_verify,
                "Verify every historical signature",
            );
            note(
                ui,
                s,
                "Slower first sync. Leave it off and blocks before the \
                     built-in checkpoint get proof-of-work checks but not \
                     script checks — each block's receipt reports which \
                     ran.",
            );
            ui.add_space(14.0);

            widgets::label(ui, "Proxy (optional)");
            field(ui, &mut run.proxy, "Direct connection", 220.0);
            note(
                ui,
                s,
                "A SOCKS5 address like 127.0.0.1:9050 routes every peer \
                     connection through it — Tor users set this before the \
                     first sync, not after.",
            );
            ui.add_space(22.0);

            let bad = !run.proxy.trim().is_empty()
                && run.proxy.trim().parse::<std::net::SocketAddr>().is_err();
            if bad {
                ui.label(
                    RichText::new("The proxy needs an address with a port, like 127.0.0.1:9050.")
                        .font(theme::font(theme::MEDIUM, 13.0))
                        .color(pal.alert),
                );
                ui.add_space(8.0);
            }
            ui.add_enabled_ui(!bad, |ui| {
                widgets::button(ui, "Start syncing", Kind::Primary).clicked()
            })
            .inner
            .then_some(Action::Start)
        })
        .inner
    })
    .inner
}

fn field(ui: &mut Ui, value: &mut String, hint: &str, width: f32) {
    ui.add(
        TextEdit::singleline(value)
            .hint_text(hint)
            .font(mono(13.0))
            .desired_width(width)
            .margin(vec2(10.0, 7.0)),
    );
}

fn note(ui: &mut Ui, s: &Scene, text: &str) {
    ui.label(
        RichText::new(text)
            .font(theme::font(theme::MEDIUM, 13.0))
            .color(s.pal.muted),
    );
}

fn row(ui: &mut Ui, add: impl FnOnce(&mut Ui)) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        add(ui);
    });
}
