//! The first screen answers three questions at a glance: what has this
//! machine proven, what is it assuming, and is it alive?

use super::{Action, Scene, start_offer};
use crate::model::{NodeView, fee_rate, percent, span, thousands};
use crate::ribbon::{self, Coverage, Options};
use crate::session::{Ended, Phase};
use crate::theme::{self, body, font, mono};
use crate::widgets;
use eframe::egui::{Align, Align2, Layout, Rect, RichText, Sense, Stroke, Ui, pos2, vec2};

pub fn show(ui: &mut Ui, s: &Scene) -> Option<Action> {
    let Some(view) = &s.session.view else {
        return idle(ui, s);
    };
    hero(ui, s, view);
    ui.add_space(30.0);
    readouts(ui, s, view);
    ui.add_space(30.0);
    tape(ui, s, view);
    None
}

fn idle(ui: &mut Ui, s: &Scene) -> Option<Action> {
    match (s.session.phase(), &s.session.ended) {
        (Phase::Connecting, _) => widgets::empty(
            ui,
            "Looking for peers",
            "The node is asking DNS seeds for addresses. The chain shows up here once a peer answers.",
        ),
        (Phase::Failed, Some(Ended::Failed(e))) => widgets::empty(
            ui,
            "The node stopped with an error",
            &format!("{e}. Check the settings, then start it again."),
        ),
        _ => widgets::empty(
            ui,
            "Your node isn’t running",
            "Start it to download the chain and verify every block on this machine, from genesis to the newest.",
        ),
    }
    let action = start_offer(ui, s);
    ui.add_space(36.0);
    // The ribbon's empty ground: where the chain will fill in.
    ribbon::show(
        ui,
        &crate::model::TrustView::default(),
        &Options {
            band: 40.0,
            halvings: false,
            pulse: None,
        },
    );
    action
}

fn hero(ui: &mut Ui, s: &Scene, v: &NodeView) {
    let pal = s.pal;
    let cov = Coverage::of(&v.trust);
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 92.0), Sense::hover());
    let p = ui.painter();
    let label = font(theme::MEDIUM, 13.0);
    let figure = font(theme::DISPLAY, 62.0);
    p.text(
        rect.left_top(),
        Align2::LEFT_TOP,
        "Proven by this machine",
        label.clone(),
        pal.muted,
    );
    p.text(
        rect.left_top() + vec2(-3.0, 14.0),
        Align2::LEFT_TOP,
        percent(cov.proven_share()),
        figure.clone(),
        pal.signal_text,
    );
    p.text(
        rect.right_top(),
        Align2::RIGHT_TOP,
        "Validated tip",
        label,
        pal.muted,
    );
    p.text(
        rect.right_top() + vec2(2.0, 14.0),
        Align2::RIGHT_TOP,
        thousands(v.connected.into()),
        figure,
        pal.text,
    );
    ui.add_space(4.0);
    ribbon::show(
        ui,
        &v.trust,
        &Options {
            band: 40.0,
            halvings: false,
            pulse: s.pulse(),
        },
    );
    ribbon::legend(ui, &v.trust);
    ui.add_space(4.0);
    ui.label(RichText::new(summary(s, v)).size(14.0).color(pal.muted));
}

/// The ribbon in one plain sentence.
fn summary(s: &Scene, v: &NodeView) -> String {
    let t = &v.trust;
    if let Some(snap) = t.snapshot.as_ref().filter(|x| !x.proven) {
        let r = snap.replayed.min(snap.base);
        let left = match s.session.per_min(|x| x.replayed).filter(|p| *p > 0.0) {
            Some(pace) => format!(
                " — about {} to go",
                span((f64::from(snap.base - r) / pace * 60.0) as u64)
            ),
            None => String::new(),
        };
        return format!(
            "Blocks {}–{} came from a snapshot and are assumed valid until the background replay reaches them{left}. Every other block was verified here.",
            thousands(u64::from(r) + 1),
            thousands(snap.base.into()),
        );
    }
    if v.behind() > 0 {
        return match s.session.per_min(|x| x.connected).filter(|p| *p >= 1.0) {
            Some(pace) => format!(
                "Verifying about {} blocks a minute; {} to go, roughly {}.",
                thousands(pace as u64),
                thousands(v.behind().into()),
                span((f64::from(v.behind()) / pace * 60.0) as u64)
            ),
            None => format!(
                "{} blocks are known by their headers and waiting to be downloaded and verified.",
                thousands(v.behind().into())
            ),
        };
    }
    match &t.snapshot {
        Some(snap) => format!(
            "Every block from genesis to {} was verified on this machine. The snapshot at {} was proven by a full replay.",
            thousands(v.connected.into()),
            thousands(snap.base.into())
        ),
        None => format!(
            "Every block from genesis to {} was verified on this machine.",
            thousands(v.connected.into())
        ),
    }
}

fn readouts(ui: &mut Ui, s: &Scene, v: &NodeView) {
    widgets::hairline(ui);
    ui.add_space(16.0);
    let gap = 36.0;
    let w = ((ui.available_width() - 2.0 * gap) / 3.0).floor();
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = gap;
        column(ui, w, |ui| last_block(ui, s, v, w));
        column(ui, w, |ui| peers(ui, s, v, w));
        column(ui, w, |ui| mempool(ui, s, v, w));
    });
}

fn column(ui: &mut Ui, w: f32, add: impl FnOnce(&mut Ui)) {
    ui.allocate_ui_with_layout(vec2(w, 0.0), Layout::top_down(Align::Min), |ui| {
        ui.set_width(w);
        ui.spacing_mut().item_spacing.y = 3.0;
        add(ui);
    });
}

fn figure(ui: &mut Ui, _s: &Scene, value: &str, unit: &str) {
    widgets::figure(ui, value, unit, 38.0);
}

fn note(ui: &mut Ui, s: &Scene, text: &str) {
    ui.label(RichText::new(text).size(13.0).color(s.pal.muted));
}

fn last_block(ui: &mut Ui, s: &Scene, v: &NodeView, w: f32) {
    widgets::label(ui, "Last block");
    let pace = s.session.per_min(|x| x.connected);
    match (v.caught_up(), pace, s.session.seen_ago(v.connected)) {
        (false, Some(p), _) if p >= 1.0 => figure(ui, s, &thousands(p as u64), "blocks a minute"),
        (_, _, Some(ago)) if ago < 5.0 => figure(ui, s, "Just now", ""),
        (_, _, Some(ago)) => figure(ui, s, &span(ago as u64), "ago"),
        _ => figure(ui, s, "—", ""),
    }
    if let Some(hash) = v.tip_hash() {
        let zeros = crate::model::work_zeros(hash);
        let keep = ((w / 7.3) as usize).saturating_sub(zeros + 1).clamp(4, 24);
        ui.label(widgets::hash_job(hash, 12.0, &s.pal, Some(keep)));
    }
    note(ui, s, &format!("Block {}", thousands(v.connected.into())));
    ui.add_space(8.0);
    widgets::sparkline(
        ui,
        &s.session.series(|x| f64::from(x.connected)),
        vec2(w, 44.0),
        s.pal.signal,
    );
}

fn peers(ui: &mut Ui, s: &Scene, v: &NodeView, w: f32) {
    widgets::label(ui, "Peers");
    let est: Vec<_> = v.established().collect();
    let n = est.len();
    figure(ui, s, &n.to_string(), if n == 1 { "peer" } else { "peers" });
    let v2 = est.iter().filter(|p| p.v2).count();
    let recon = est.iter().filter(|p| p.recon).count();
    let inbound = est.iter().filter(|p| p.inbound).count();
    note(
        ui,
        s,
        &format!("{v2} encrypted · {recon} with Erlay · {inbound} inbound"),
    );
    match v.median_ping_ms() {
        Some(ms) => note(ui, s, &format!("Median ping {ms:.0} ms")),
        None => note(ui, s, "No pings measured yet"),
    }
    ui.add_space(8.0);
    widgets::sparkline(
        ui,
        &s.session.series(|x| x.peers as f64),
        vec2(w, 44.0),
        s.pal.muted,
    );
}

fn mempool(ui: &mut Ui, s: &Scene, v: &NodeView, w: f32) {
    widgets::label(ui, "Mempool");
    figure(ui, s, &thousands(v.mempool_txs as u64), "transactions");
    match v.fee_rate_sat_kvb {
        Some(f) => note(
            ui,
            s,
            &format!("{} to confirm in about 6 blocks", fee_rate(f)),
        ),
        None => note(ui, s, "No fee estimate yet"),
    }
    note(
        ui,
        s,
        &format!(
            "{} orphan{} waiting for parents",
            v.orphans,
            if v.orphans == 1 { "" } else { "s" }
        ),
    );
    ui.add_space(8.0);
    widgets::sparkline(
        ui,
        &s.session.series(|x| x.mempool as f64),
        vec2(w, 44.0),
        s.pal.muted,
    );
}

/// The newest blocks as a strip of tape, oldest fading at the left.
fn tape(ui: &mut Ui, s: &Scene, v: &NodeView) {
    let pal = s.pal;
    widgets::label(ui, "Recent blocks");
    ui.add_space(2.0);
    let w = ui.available_width();
    let n = ((w / 150.0) as usize).clamp(3, 8).min(v.recent.len());
    if n == 0 {
        return;
    }
    let (rect, _) = ui.allocate_exact_size(vec2(w, 64.0), Sense::hover());
    let p = ui.painter();
    p.rect_filled(rect, 8, pal.well);
    let cell = w / n as f32;
    let pulse = s.pulse();
    for (i, (h, hash)) in v.recent[v.recent.len() - n..].iter().enumerate() {
        let r = Rect::from_min_size(
            pos2(rect.left() + cell * i as f32, rect.top()),
            vec2(cell, rect.height()),
        );
        if i > 0 {
            p.vline(
                r.left(),
                (r.top() + 12.0)..=(r.bottom() - 12.0),
                Stroke::new(1.0, pal.hairline),
            );
        }
        let age = (n - 1 - i) as f32 / n as f32;
        let ink = pal.text.gamma_multiply(1.0 - 0.6 * age);
        p.text(
            r.left_top() + vec2(14.0, 13.0),
            Align2::LEFT_TOP,
            thousands((*h).into()),
            font(theme::MONO_MEDIUM, 13.5),
            ink,
        );
        let tail: String = hash.trim_start_matches('0').chars().take(10).collect();
        p.text(
            r.left_top() + vec2(14.0, 35.0),
            Align2::LEFT_TOP,
            format!("…{tail}"),
            mono(11.0),
            pal.muted.gamma_multiply(1.0 - 0.5 * age),
        );
        if let Some(ago) = s.session.seen_ago(*h) {
            p.text(
                r.right_top() + vec2(-12.0, 15.0),
                Align2::RIGHT_TOP,
                if ago < 5.0 {
                    "now".into()
                } else {
                    span(ago as u64)
                },
                body(11.5),
                pal.muted.gamma_multiply(1.0 - 0.5 * age),
            );
        }
        if i == n - 1
            && let Some(f) = pulse
        {
            let edge = Rect::from_min_size(r.left_top(), vec2(r.width(), 3.0));
            p.rect_filled(edge, 0, pal.signal.gamma_multiply(1.0 - f));
        }
    }
}
