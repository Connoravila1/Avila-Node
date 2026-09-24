//! The chain in detail: coverage to scale, what the validation report
//! says, the snapshot and its replay, and the newest blocks.

use super::{Action, Scene, start_offer};
use crate::model::{NodeView, percent, span, thousands};
use crate::ribbon::{self, Coverage, Options};
use crate::theme::{self, font, mono};
use crate::widgets;
use eframe::egui::{self, RichText, Ui};

pub fn show(ui: &mut Ui, s: &Scene) -> Option<Action> {
    let Some(v) = &s.session.view else {
        widgets::empty(
            ui,
            "No chain yet",
            "Start the node and the chain it verifies shows up here, to scale.",
        );
        return start_offer(ui, s);
    };
    widgets::section(ui, "Coverage", Some("genesis to the best header, to scale"));
    ui.add_space(10.0);
    ribbon::show(
        ui,
        &v.trust,
        &Options {
            band: 52.0,
            halvings: true,
            pulse: s.pulse(),
        },
    );
    ribbon::legend(ui, &v.trust);
    ui.add_space(28.0);
    validation(ui, s, v);
    if v.trust.snapshot.is_some() {
        ui.add_space(28.0);
        snapshot(ui, s, v);
    }
    ui.add_space(28.0);
    recent(ui, s, v);
    None
}

fn facts(ui: &mut Ui, id: &str, rows: impl FnOnce(&mut Ui)) {
    egui::Grid::new(id)
        .num_columns(2)
        .spacing([28.0, 12.0])
        .min_col_width(170.0)
        .show(ui, rows);
}

fn key(ui: &mut Ui, s: &Scene, text: &str) {
    ui.label(RichText::new(text).size(13.5).color(s.pal.muted));
}

fn value(ui: &mut Ui, s: &Scene, main: &str, aside: Option<&str>) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(main).font(mono(13.5)).color(s.pal.text));
        if let Some(aside) = aside {
            ui.label(RichText::new(aside).size(13.5).color(s.pal.muted));
        }
    });
}

fn validation(ui: &mut Ui, s: &Scene, v: &NodeView) {
    let cov = Coverage::of(&v.trust);
    widgets::section(ui, "Validation", None);
    facts(ui, "validation", |ui| {
        key(ui, s, "Validated tip");
        value(ui, s, &thousands(v.connected.into()), None);
        ui.end_row();
        if let Some(hash) = v.tip_hash() {
            key(ui, s, "Tip block");
            widgets::hash_label(ui, hash, 13.0, None);
            ui.end_row();
        }
        key(ui, s, "Best header");
        let behind = v.behind();
        let aside = if behind == 0 {
            "· every block downloaded".to_owned()
        } else {
            format!("· {} to download", thousands(behind.into()))
        };
        value(ui, s, &thousands(v.headers.into()), Some(&aside));
        ui.end_row();
        key(ui, s, "Proven here");
        value(
            ui,
            s,
            &thousands(cov.proven_blocks().into()),
            Some(&format!(
                "blocks · {} of the known chain",
                percent(cov.proven_share())
            )),
        );
        ui.end_row();
        key(ui, s, "Verified share");
        value(
            ui,
            s,
            &percent(v.trust.verified_fraction),
            Some("of the connected chain, as getvalidationreport reports it"),
        );
        ui.end_row();
    });
}

fn snapshot(ui: &mut Ui, s: &Scene, v: &NodeView) {
    let Some(snap) = &v.trust.snapshot else {
        return;
    };
    let status = if snap.proven {
        "proven by the replay"
    } else {
        "being checked"
    };
    widgets::section(ui, "Snapshot", Some(status));
    facts(ui, "snapshot", |ui| {
        key(ui, s, "Base height");
        value(ui, s, &thousands(snap.base.into()), None);
        ui.end_row();
        key(ui, s, "Base block");
        widgets::hash_label(ui, &snap.base_hash, 13.0, None);
        ui.end_row();
        key(ui, s, "UTXO set hash");
        ui.add(egui::Label::new(
            RichText::new(&snap.expected_utxo_hash)
                .font(mono(13.0))
                .color(s.pal.text),
        ))
        .on_hover_text("The hash_serialized_3 the replayed coin set must match");
        ui.end_row();
        key(ui, s, "Background replay");
        ui.vertical(|ui| {
            let r = snap.replayed.min(snap.base);
            ribbon::replay_bar(ui, r, snap.base, 360.0);
            let share = percent(f64::from(r) / f64::from(snap.base.max(1)));
            let mut line = format!(
                "{} of {} · {share}",
                thousands(r.into()),
                thousands(snap.base.into())
            );
            if !snap.proven
                && let Some(pace) = s.session.per_min(|x| x.replayed).filter(|p| *p > 0.0)
            {
                line.push_str(&format!(
                    " · {} blocks a minute · about {} to go",
                    thousands(pace as u64),
                    span((f64::from(snap.base - r) / pace * 60.0) as u64)
                ));
            }
            ui.label(RichText::new(line).size(13.5).color(s.pal.muted));
        });
        ui.end_row();
    });
    ui.add_space(10.0);
    let explain = if snap.proven {
        "The replay rebuilt the coin set from genesis and it matched the hash above. Nothing is assumed."
    } else {
        "Blocks the replay hasn’t reached are assumed valid on the strength of the hash above. When the replay reaches the base and its coin set hashes to that value, they become proven; a mismatch would mean the snapshot was wrong."
    };
    ui.label(RichText::new(explain).size(13.5).color(s.pal.muted));
}

fn recent(ui: &mut Ui, s: &Scene, v: &NodeView) {
    widgets::section(
        ui,
        "Recent blocks",
        Some("newest first · click a hash to copy it"),
    );
    let keep = (ui.available_width() < 760.0).then_some(20);
    egui::Grid::new("recent")
        .num_columns(3)
        .spacing([28.0, 10.0])
        .show(ui, |ui| {
            for title in ["Height", "Hash", "Seen"] {
                ui.label(
                    RichText::new(title)
                        .font(font(theme::MEDIUM, 12.0))
                        .color(s.pal.muted),
                );
            }
            ui.end_row();
            for (h, hash) in v.recent.iter().rev() {
                ui.label(
                    RichText::new(thousands((*h).into()))
                        .font(font(theme::MONO_MEDIUM, 13.0))
                        .color(s.pal.text),
                );
                widgets::hash_label(ui, hash, 12.5, keep);
                let seen = match s.session.seen_ago(*h) {
                    Some(ago) if ago < 5.0 => "just now".to_owned(),
                    Some(ago) => format!("{} ago", span(ago as u64)),
                    None => "while syncing".to_owned(),
                };
                ui.label(RichText::new(seen).size(13.0).color(s.pal.muted));
                ui.end_row();
            }
        });
}
