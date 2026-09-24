//! The block clock: a watch face whose hands are Bitcoin's own cycles.
//! The long thin hand sweeps the ten minutes a block takes on average,
//! the middle one the two weeks of a difficulty period, the short thick
//! one the four years of a halving era. It moves as time passes and
//! snaps back when a block arrives, with the tip — proven here — at the
//! center.

use crate::model::{NodeView, month_year, span, thousands};
use crate::pages::Scene;
use crate::theme::{self, Palette, font};
use eframe::egui::{Align, Layout, Pos2, RichText, Sense, Shape, Stroke, Ui, vec2};
use std::f32::consts::{FRAC_PI_2, TAU};

const SIDE: f32 = 236.0;

/// One cycle as the clock shows it.
struct Hand {
    /// Progress through the cycle, `0..1` (the block hand may lap).
    turn: f32,
    radius: f32,
    width: f32,
    ticks: usize,
    ink: f32,
}

/// Seconds since the tip arrived: as seen this session when it was, else
/// by the tip's own timestamp.
fn since_tip(s: &Scene, v: &NodeView) -> Option<f64> {
    if s.session.tip_advanced_at.is_some()
        && let Some(ago) = s.session.seen_ago(v.connected)
    {
        return Some(ago.max(0.0));
    }
    let tip = v.curve.tip()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs_f64();
    Some((now - f64::from(tip.time)).max(0.0))
}

pub fn show(ui: &mut Ui, s: &Scene, v: &NodeView, params: &avila_consensus::params::Params) {
    let pal = s.pal;
    let tip = v.headers.max(v.connected);
    let spacing = params.pow_target_spacing.max(1) as f64;
    let interval = (params.pow_target_timespan / params.pow_target_spacing.max(1)).max(1) as u32;
    let era = params.subsidy_halving_interval.max(1);
    let elapsed = since_tip(s, v);
    let block_turn = elapsed.map_or(0.0, |e| (e / spacing) as f32);
    let hands = [
        Hand {
            turn: (tip % era) as f32 / era as f32,
            radius: 58.0,
            width: 4.0,
            ticks: 4,
            ink: 0.55,
        },
        Hand {
            turn: (tip % interval) as f32 / interval as f32,
            radius: 84.0,
            width: 2.6,
            ticks: 14,
            ink: 0.8,
        },
        Hand {
            turn: block_turn,
            radius: 110.0,
            width: 1.5,
            ticks: 10,
            ink: 1.0,
        },
    ];
    ui.horizontal_top(|ui| {
        let (rect, _) = ui.allocate_exact_size(vec2(SIDE, SIDE), Sense::hover());
        dial(ui, rect.center(), &hands, &pal, s.pulse());
        ui.add_space(28.0);
        ui.allocate_ui_with_layout(
            vec2(ui.available_width(), SIDE),
            Layout::top_down(Align::Min),
            |ui| {
                ui.spacing_mut().item_spacing.y = 3.0;
                ui.add_space(22.0);
                let (block_line, odds) = match elapsed {
                    Some(e) => (
                        format!(
                            "{} since block {}",
                            span(e as u64),
                            thousands(v.connected.into())
                        ),
                        // Blocks arrive as a Poisson process: a wait of
                        // at least `e` happens e^(−e/600) of the time.
                        Some(format!(
                            "A wait this long or longer happens for {:.0}% of blocks.",
                            100.0 * (-e / spacing).exp()
                        )),
                    ),
                    None => ("Waiting for the first block".into(), None),
                };
                row(ui, &pal, "Block · the long hand, ten minutes", &block_line);
                if let Some(odds) = odds {
                    ui.label(RichText::new(odds).size(12.5).color(pal.faint));
                }
                ui.add_space(12.0);
                let into = tip % interval;
                row(
                    ui,
                    &pal,
                    "Difficulty period · the middle hand, two weeks",
                    &format!(
                        "Block {} of {}",
                        thousands(into.into()),
                        thousands(interval.into())
                    ),
                );
                ui.add_space(12.0);
                let next = (tip / era + 1) * era;
                let mut era_line = format!(
                    "{} blocks to the halving at {}",
                    thousands((next - tip).into()),
                    thousands(next.into())
                );
                if let Some(head) = v.curve.tip() {
                    let eta = i64::from(head.time) + i64::from(next - tip) * spacing as i64;
                    era_line.push_str(&format!(", around {}", month_year(eta)));
                }
                row(
                    ui,
                    &pal,
                    "Halving era · the short hand, four years",
                    &era_line,
                );
            },
        );
    });
}

fn row(ui: &mut Ui, pal: &Palette, label: &str, value: &str) {
    ui.label(
        RichText::new(label)
            .font(font(theme::MEDIUM, 12.5))
            .color(pal.muted),
    );
    ui.label(RichText::new(value).size(14.0).color(pal.text));
}

fn dial(ui: &Ui, c: Pos2, hands: &[Hand; 3], pal: &Palette, pulse: Option<f32>) {
    let p = ui.painter();
    let at = |turn: f32, r: f32| {
        let a = turn * TAU - FRAC_PI_2;
        c + vec2(a.cos(), a.sin()) * r
    };
    // Each cycle's track: a faint ring with its ticks, and the part of
    // the cycle already gone by.
    for h in hands {
        p.circle_stroke(c, h.radius, Stroke::new(1.0, pal.hairline));
        for i in 0..h.ticks {
            let t = i as f32 / h.ticks as f32;
            let len = if i == 0 { 7.0 } else { 4.0 };
            p.line_segment(
                [at(t, h.radius - len / 2.0), at(t, h.radius + len / 2.0)],
                Stroke::new(1.0, pal.faint),
            );
        }
        let done = h.turn.clamp(0.0, 1.0);
        if done > 0.0 {
            let steps = (done * 96.0).ceil().max(2.0) as usize;
            let arc: Vec<Pos2> = (0..=steps)
                .map(|i| at(done * i as f32 / steps as f32, h.radius))
                .collect();
            p.add(Shape::line(
                arc,
                Stroke::new(3.0, pal.text.gamma_multiply(0.18 * h.ink)),
            ));
        }
    }
    // The hands, slowest first so the fastest sits on top.
    for h in hands {
        let tip = at(h.turn.rem_euclid(1.0), h.radius - 6.0);
        let back = at(h.turn.rem_euclid(1.0) + 0.5, 10.0);
        p.line_segment(
            [back, tip],
            Stroke::new(h.width, pal.text.gamma_multiply(h.ink)),
        );
    }
    // The tip at the center: orange, because it's proven here.
    if crate::julia::on() {
        crate::julia::heart(p, c, 18.0, pal.signal);
    } else {
        p.circle_filled(c, 6.0, pal.signal);
        p.circle_stroke(c, 6.0, Stroke::new(1.5, pal.canvas));
    }
    if let Some(f) = pulse {
        p.circle_stroke(
            c,
            8.0 + 110.0 * f,
            Stroke::new(2.0 * (1.0 - f) + 0.5, pal.signal.gamma_multiply(1.0 - f)),
        );
    }
}
