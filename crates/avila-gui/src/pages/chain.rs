//! The chain in detail: coverage to scale, what the validation report
//! says, the snapshot and its replay, and the newest blocks.

use super::{Action, Scene, start_offer};
use crate::model::{NodeView, btc, month_year, percent, span, thousands};
use crate::ribbon::{self, Coverage, Options, Ruler, Scale};
use crate::session;
use crate::theme::{self, font, mono};
use crate::widgets;
use avila_consensus::connect::block_subsidy;
use eframe::egui::{self, Align, Layout, Rect, RichText, Sense, Ui, vec2};

pub fn show(ui: &mut Ui, s: &Scene, scale: &mut Scale) -> Option<Action> {
    let Some(v) = &s.session.view else {
        widgets::empty(
            ui,
            "No chain yet",
            "Start the node and the chain it verifies shows up here, to scale.",
        );
        return start_offer(ui, s);
    };
    ui.horizontal(|ui| {
        ui.label(
            RichText::new("Coverage")
                .font(font(theme::TITLE, 19.0))
                .color(s.pal.text),
        );
        ui.add_space(4.0);
        let note = if *scale == Scale::Work && !v.curve.is_empty() {
            "genesis to the best header, weighed by proof-of-work"
        } else {
            "genesis to the best header, to scale"
        };
        ui.label(RichText::new(note).size(13.0).color(s.pal.muted));
        if !v.curve.is_empty() {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ribbon::scale_toggle(ui, scale);
            });
        }
    });
    widgets::hairline(ui);
    ui.add_space(12.0);
    let cov = Coverage::of(&v.trust);
    ribbon::show(
        ui,
        &v.trust,
        &v.curve,
        &Options {
            band: 52.0,
            halvings: true,
            years: true,
            scale: *scale,
            pulse: s.pulse(),
        },
    );
    ribbon::legend(ui, &v.trust, &Ruler::new(cov.top, *scale, &v.curve));
    ui.add_space(28.0);
    validation(ui, s, v);
    if v.trust.snapshot.is_some() {
        ui.add_space(28.0);
        snapshot(ui, s, v);
    }
    ui.add_space(28.0);
    rhythm(ui, s, v);
    ui.add_space(28.0);
    recent(ui, s, v);
    None
}

/// Where the chain stands in its two long cycles: the 2,016-block
/// difficulty period and the 210,000-block halving era.
fn rhythm(ui: &mut Ui, s: &Scene, v: &NodeView) {
    let params = session::params(s.network);
    let tip = v.headers.max(v.connected);
    let spacing = params.pow_target_spacing.max(1);
    let interval = (params.pow_target_timespan / spacing).max(1) as u32;
    widgets::section(ui, "Rhythm", Some("difficulty periods and halvings"));
    facts(ui, "rhythm", |ui| {
        key(ui, s, "Difficulty period");
        ui.vertical(|ui| {
            let into = tip % interval;
            let left = interval - into;
            bar(ui, s, into, interval);
            let mut line = format!(
                "Block {} of {} · {} to go",
                thousands(into.into()),
                thousands(interval.into()),
                thousands(left.into())
            );
            if params.no_retargeting {
                line.push_str(" · this network never retargets");
            } else if let (Some(start), Some(head)) =
                (v.curve.period_start(interval), v.curve.tip())
                && into > 0
                && head.time > start.time
            {
                let taken = f64::from(head.time - start.time);
                let expected = f64::from(into) * spacing as f64;
                let change = (expected / taken).clamp(0.25, 4.0) - 1.0;
                let sign = if change >= 0.0 { "+" } else { "−" };
                line.push_str(&format!(
                    " · projected {sign}{:.1}% in about {}",
                    change.abs() * 100.0,
                    span((f64::from(left) * taken / f64::from(into)) as u64)
                ));
            }
            ui.label(RichText::new(line).size(13.5).color(s.pal.muted));
        });
        ui.end_row();

        key(ui, s, "Next halving");
        ui.vertical(|ui| {
            let era = params.subsidy_halving_interval.max(1);
            let next = (tip / era + 1) * era;
            let left = next - tip;
            bar(ui, s, tip % era, era);
            let now = block_subsidy(tip, &params);
            let then = block_subsidy(next, &params);
            let mut line = format!(
                "At {} · {} blocks to go",
                thousands(next.into()),
                thousands(left.into())
            );
            if let Some(head) = v.curve.tip() {
                let eta = i64::from(head.time) + i64::from(left) * spacing as i64;
                line.push_str(&format!(", around {}", month_year(eta)));
            }
            line.push_str(&format!(" · subsidy {} → {}", btc(now), btc(then)));
            ui.label(RichText::new(line).size(13.5).color(s.pal.muted));
        });
        ui.end_row();
    });
}

/// Progress through a cycle, in ink — orange stays reserved for proof.
fn bar(ui: &mut Ui, s: &Scene, done: u32, of: u32) {
    let (r, _) = ui.allocate_exact_size(vec2(360.0, 6.0), Sense::hover());
    let p = ui.painter();
    p.rect_filled(r, 3, s.pal.well);
    let f = (f64::from(done) / f64::from(of.max(1))) as f32;
    p.rect_filled(
        Rect::from_min_size(r.min, vec2(r.width() * f.clamp(0.0, 1.0), r.height())),
        3,
        s.pal.muted,
    );
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
                percent(cov.proven_share(&Ruler::new(cov.top, Scale::Blocks, &v.curve)))
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
