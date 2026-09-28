//! The avalanche playground: two inputs, two SHA-256 hashes as 256-cell
//! grids, every differing bit lit. Flip one input bit and roughly half
//! the output flips — the property mining runs on.

use crate::theme::{self, MONO_MEDIUM, Palette, font, mono};
use crate::widgets::{self, Kind as Button};
use eframe::egui::{
    Align, Align2, Key, Layout, Modifiers, Pos2, Rect, RichText, Sense, TextEdit, Ui, vec2,
};
use sha2::{Digest, Sha256};

const BITS: usize = 16;
const CELL: f32 = 13.0;

pub struct Avalanche {
    pub open: bool,
    a: String,
    b: String,
}

impl Default for Avalanche {
    fn default() -> Self {
        Self {
            open: false,
            a: "satoshi".into(),
            b: "satoshi ".into(),
        }
    }
}

impl Avalanche {
    pub fn shelve(&mut self) {
        self.open = false;
    }

    /// `b` becomes `a` with its lowest bit flipped — the whole point.
    fn flip_one(&mut self) {
        self.b = self.a.clone();
        match self.b.as_bytes().last() {
            Some(last) => {
                let n = self.b.len() - 1;
                self.b.replace_range(n.., &char::from(last ^ 1).to_string());
            }
            None => self.b.push(' '),
        }
    }
}

fn digest(text: &str) -> [u8; 32] {
    let h = Sha256::digest(text.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h);
    out
}

fn bit(hash: &[u8; 32], i: usize) -> bool {
    hash[i / 8] >> (7 - i % 8) & 1 != 0
}

/// How many of the 256 bits differ between `a` and `b`.
pub fn distance(a: &[u8; 32], b: &[u8; 32]) -> u32 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones())
        .sum()
}

/// The whole open view: inputs, the two grids, the count.
pub fn show(ui: &mut Ui, pal: &Palette, toy: &mut Avalanche) {
    let escape = ui.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Escape));
    let mut leave = escape;
    ui.horizontal(|ui| {
        leave |= widgets::button(ui, "← Toybox", Button::Quiet).clicked();
        ui.add_space(12.0);
        ui.label(
            RichText::new("Avalanche")
                .font(font(theme::TITLE, 21.0))
                .color(pal.text),
        );
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if widgets::button(ui, "Flip one bit", Button::Quiet).clicked() {
                toy.flip_one();
            }
        });
    });
    ui.add_space(12.0);

    ui.horizontal(|ui| {
        ui.label(RichText::new("a").font(mono(14.0)).color(pal.muted));
        ui.add(
            TextEdit::singleline(&mut toy.a)
                .font(mono(13.5))
                .desired_width(ui.available_width() / 2.0 - 40.0),
        );
        ui.add_space(16.0);
        ui.label(RichText::new("b").font(mono(14.0)).color(pal.muted));
        ui.add(
            TextEdit::singleline(&mut toy.b)
                .font(mono(13.5))
                .desired_width(ui.available_width() - 8.0),
        );
    });
    ui.add_space(14.0);

    let (ha, hb) = (digest(&toy.a), digest(&toy.b));
    let diff = distance(&ha, &hb);

    let side = vec2(BITS as f32 * CELL, BITS as f32 * CELL);
    ui.horizontal(|ui| {
        let gap = (ui.available_width() - side.x * 2.0 - 190.0).max(24.0) / 2.0;
        ui.add_space(gap);
        grid(ui, pal, &ha, None);
        ui.add_space(190.0);
        grid(ui, pal, &hb, Some(&ha));
    });

    ui.add_space(12.0);
    ui.horizontal(|ui| {
        ui.add_space(ui.available_width() / 2.0 - 230.0);
        ui.vertical(|ui| {
            ui.label(
                RichText::new(format!("{diff} of 256 bits differ — {}%", diff * 100 / 256))
                    .font(font(MONO_MEDIUM, 15.0))
                    .color(if diff == 0 { pal.muted } else { pal.signal_text }),
            );
            ui.label(
                RichText::new(if diff == 0 {
                    "Same input, same hash — every bit agrees."
                } else {
                    "One changed bit should move about 128 of them. That scrambling is all proof-of-work gets to play with."
                })
                .size(12.5)
                .color(pal.faint),
            );
        });
    });
    if leave {
        toy.shelve();
    }
}

/// One hash as a 16×16 field of bits; against `other`, lit cells turn
/// alert-colored where the hashes disagree.
fn grid(ui: &mut Ui, pal: &Palette, hash: &[u8; 32], other: Option<&[u8; 32]>) {
    let side = vec2(BITS as f32 * CELL + 12.0, BITS as f32 * CELL + 12.0);
    let (rect, _r) = ui.allocate_exact_size(side, Sense::hover());
    let p = ui.painter_at(rect);
    p.rect_filled(rect, 8, pal.well);
    for i in 0..256 {
        let (x, y) = (i % BITS, i / BITS);
        let on = bit(hash, i);
        let fill = if let Some(o) = other {
            if bit(o, i) == on {
                if on {
                    pal.faint
                } else {
                    pal.hairline.gamma_multiply(0.5)
                }
            } else if on {
                pal.alert
            } else {
                pal.alert.gamma_multiply(0.4)
            }
        } else if on {
            pal.text
        } else {
            pal.hairline.gamma_multiply(0.5)
        };
        p.rect_filled(
            Rect::from_min_size(
                rect.min + vec2(6.0 + x as f32 * CELL, 6.0 + y as f32 * CELL),
                vec2(CELL - 1.5, CELL - 1.5),
            ),
            2,
            fill,
        );
    }
    // The hash's head and tail, mono'd under the grid.
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    p.text(
        Pos2::new(rect.center().x, rect.bottom() + 14.0),
        Align2::CENTER_CENTER,
        format!("{}…{}", &hex[..12], &hex[56..]),
        mono(11.0),
        pal.muted,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_avalanche_moves_about_half_the_bits() {
        let a = digest("satoshi");
        let b = digest("satoshi ");
        let d = distance(&a, &b);
        assert_eq!(distance(&a, &a), 0);
        // Statistically near 128; a fixed pair lands wherever it lands.
        assert!((80..180).contains(&d), "{d}");
    }
}
