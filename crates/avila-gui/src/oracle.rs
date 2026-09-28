//! The hash oracle: call the last hex digit of the next block's hash,
//! then wait ~ten minutes like everyone else. Your node does the
//! resolving — no house edge, no prizes, a streak and nothing more.

use crate::model::thousands;
use crate::pages::Scene;
use crate::theme::{self, MONO_MEDIUM, Palette, font, mono};
use crate::widgets::{self, Kind as Button};
use eframe::egui::{
    Align, Align2, CursorIcon, Key, Layout, Modifiers, Painter, Pos2, Rect, RichText, Sense,
    Stroke, StrokeKind, Ui, UiBuilder, pos2, vec2,
};
use std::time::Instant;

const HEX: &[char] = &[
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];
/// How long a resolved call stays lit before settling into history.
const GLOW_SECS: f32 = 3.0;

struct Call {
    /// The digit picked (0..16) and the tip it was placed at.
    digit: u8,
    at_height: u32,
    /// Once the next block lands: the digit that came out, and when.
    resolved: Option<(u8, Instant)>,
    hit: bool,
}

#[derive(Default)]
pub struct Oracle {
    pub open: bool,
    pending: Option<Call>,
    streak: u32,
    best: u32,
    /// Latest first, capped — hits and misses.
    history: Vec<bool>,
}

impl Oracle {
    pub fn shelve(&mut self) {
        self.open = false;
    }

    #[must_use]
    pub fn animating(&self) -> bool {
        // Only while a resolution is still glowing.
        self.open
            && self
                .pending
                .as_ref()
                .and_then(|c| c.resolved)
                .is_some_and(|(_, at)| at.elapsed().as_secs_f32() < GLOW_SECS)
    }

    /// A pose for screenshots: a call on the table, history behind it.
    pub fn demo(&mut self) {
        self.open = true;
        self.pending = Some(Call {
            digit: 0xb,
            at_height: 0,
            resolved: None,
            hit: false,
        });
        self.streak = 3;
        self.best = 5;
        self.history = vec![true, true, true, false, true, false];
    }

    /// The node grew a block — settle any open call against its tail
    /// digit.
    fn resolve(&mut self, height: u32, hash: &str) {
        let Some(call) = &mut self.pending else {
            return;
        };
        if call.resolved.is_some() || height <= call.at_height {
            return;
        }
        let tail = hash
            .as_bytes()
            .last()
            .and_then(|&c| (c as char).to_digit(16))
            .unwrap_or(0) as u8;
        call.resolved = Some((tail, Instant::now()));
        call.hit = tail == call.digit;
        if call.hit {
            self.streak += 1;
            self.best = self.best.max(self.streak);
        } else {
            self.streak = 0;
        }
        self.history.insert(0, call.hit);
        self.history.truncate(14);
    }
}

/// The whole open view: the tip, the caller's row, the history.
pub fn show(ui: &mut Ui, s: &Scene, oracle: &mut Oracle) {
    let pal = s.pal;
    let escape = ui.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Escape));
    let mut leave = escape;
    ui.horizontal(|ui| {
        leave |= widgets::button(ui, "← Toybox", Button::Quiet).clicked();
        ui.add_space(12.0);
        ui.label(
            RichText::new("Hash oracle")
                .font(font(theme::TITLE, 21.0))
                .color(pal.text),
        );
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(
                RichText::new(format!("streak {} · best {}", oracle.streak, oracle.best))
                    .font(mono(13.0))
                    .color(if oracle.streak > 0 {
                        pal.signal_text
                    } else {
                        pal.muted
                    }),
            );
        });
    });
    ui.add_space(14.0);

    let tip = s
        .session
        .view
        .as_ref()
        .and_then(|v| v.recent.last())
        .map(|(h, hash)| (*h, hash.clone()));
    if let Some((h, hash)) = &tip {
        oracle.resolve(*h, hash);
    }
    // A settled call glows for a moment, then opens the table again.
    if oracle
        .pending
        .as_ref()
        .and_then(|c| c.resolved)
        .is_some_and(|(_, at)| at.elapsed().as_secs_f32() >= GLOW_SECS)
    {
        oracle.pending = None;
    }

    let (rect, _r) = ui.allocate_exact_size(vec2(ui.available_width(), 300.0), Sense::hover());
    let p = ui.painter_at(rect);
    let card = Rect::from_min_size(rect.min, vec2(rect.width(), 300.0));
    p.rect_filled(card, 14, pal.well);
    p.rect_stroke(card, 14, Stroke::new(1.0, pal.hairline), StrokeKind::Inside);

    let Some((tip_height, tip_hash)) = tip else {
        p.text(
            card.center(),
            Align2::CENTER_CENTER,
            "Your node calls the blocks — start it and this comes alive.",
            theme::body(14.0),
            pal.muted,
        );
        if leave {
            oracle.shelve();
        }
        return;
    };

    // The current tip, mono'd, its tail digit glowing — that's the digit
    // the oracle reads.
    p.text(
        card.center_top() + vec2(0.0, 28.0),
        Align2::CENTER_CENTER,
        format!("tip {} ends in", thousands(u64::from(tip_height))),
        theme::body(13.0),
        pal.muted,
    );
    let tail_digit = tip_hash
        .as_bytes()
        .last()
        .and_then(|&c| (c as char).to_digit(16))
        .unwrap_or(0) as usize;
    draw_hex_row(&p, card.center_top() + vec2(0.0, 74.0), &pal, tail_digit);

    // The caller's row: sixteen picks, or the verdict if one's pending.
    match &oracle.pending {
        Some(call) => verdict(&p, card, &pal, call),
        None => picks(ui, card, &pal, oracle, tip_height),
    }
    // History, dots lit green or dimmed red, latest on the left.
    let dots = card.center_bottom() - vec2(oracle.history.len() as f32 * 11.0 - 5.0, 34.0);
    for (i, hit) in oracle.history.iter().enumerate() {
        p.circle_filled(
            dots + vec2(i as f32 * 11.0, 0.0),
            3.4,
            if *hit {
                pal.signal
            } else {
                pal.alert.gamma_multiply(0.55)
            },
        );
    }
    if leave {
        oracle.shelve();
    }
}

/// The sixteen digits in a row; `lit` is raised in the signal color.
fn draw_hex_row(p: &Painter, at: Pos2, pal: &Palette, lit: usize) {
    let w = 30.0;
    let x0 = at.x - 8.0 * w;
    for (d, ch) in HEX.iter().enumerate() {
        let r = Rect::from_min_size(pos2(x0 + d as f32 * w, at.y - 17.0), vec2(26.0, 34.0));
        let hot = d == lit;
        if hot {
            p.rect_filled(r, 6, pal.signal);
        }
        p.text(
            r.center(),
            Align2::CENTER_CENTER,
            ch.to_string(),
            font(MONO_MEDIUM, if hot { 17.0 } else { 14.0 }),
            if hot { pal.on_signal() } else { pal.muted },
        );
    }
}

/// Sixteen cells to call — each a quiet clickable digit.
fn picks(ui: &mut Ui, card: Rect, pal: &Palette, oracle: &mut Oracle, tip_height: u32) {
    let row = Rect::from_min_size(
        pos2(card.center().x - 8.0 * 42.0, card.top() + 130.0),
        vec2(16.0 * 42.0, 54.0),
    );
    ui.scope_builder(
        UiBuilder::new()
            .max_rect(row)
            .layout(Layout::left_to_right(Align::Center)),
        |ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            for (d, ch) in HEX.iter().enumerate() {
                let (rect, resp) = ui.allocate_exact_size(vec2(36.0, 50.0), Sense::click());
                let p = ui.painter_at(rect);
                let hot = resp.hovered();
                p.rect_filled(
                    rect,
                    8,
                    if hot {
                        pal.raised
                    } else {
                        pal.canvas.gamma_multiply(0.6)
                    },
                );
                p.rect_stroke(
                    rect,
                    8,
                    Stroke::new(1.0, if hot { pal.faint } else { pal.hairline }),
                    StrokeKind::Inside,
                );
                p.text(
                    rect.center() - vec2(0.0, 4.0),
                    Align2::CENTER_CENTER,
                    ch.to_string(),
                    font(MONO_MEDIUM, 17.0),
                    if hot { pal.text } else { pal.muted },
                );
                p.text(
                    rect.center() + vec2(0.0, 12.0),
                    Align2::CENTER_CENTER,
                    if d == 0 { "one in sixteen" } else { "" },
                    theme::body(8.5),
                    pal.faint,
                );
                if resp.clicked() {
                    oracle.pending = Some(Call {
                        digit: d as u8,
                        at_height: tip_height,
                        resolved: None,
                        hit: false,
                    });
                }
                resp.on_hover_cursor(CursorIcon::PointingHand);
            }
        },
    );
}

/// A pending call: waiting on the next block, or the verdict while it
/// still glows.
fn verdict(p: &Painter, card: Rect, pal: &Palette, call: &Call) {
    let mid = card.center() + vec2(0.0, 42.0);
    match call.resolved {
        None => {
            p.text(
                mid,
                Align2::CENTER_CENTER,
                format!(
                    "called {} — waiting on the next block",
                    HEX[call.digit as usize]
                ),
                theme::body(14.0),
                pal.muted,
            );
        }
        Some((tail, at)) => {
            let glow = (1.0 - at.elapsed().as_secs_f32() / GLOW_SECS).max(0.0);
            p.text(
                mid - vec2(0.0, 26.0),
                Align2::CENTER_CENTER,
                format!(
                    "called {} — it ended in {}",
                    HEX[call.digit as usize], HEX[tail as usize]
                ),
                theme::body(14.0),
                pal.muted,
            );
            p.text(
                mid + vec2(0.0, 8.0),
                Align2::CENTER_CENTER,
                if call.hit {
                    "called it"
                } else {
                    "the chain disagrees"
                },
                font(theme::TITLE, 24.0),
                if call.hit {
                    pal.signal_text
                } else {
                    pal.alert.gamma_multiply(0.6 + 0.4 * glow)
                },
            );
        }
    }
}
