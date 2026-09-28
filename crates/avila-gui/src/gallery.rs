//! The block gallery: every block your node has connected hangs on the
//! wall, painted from its own hash — an identicon-style tile, symmetric
//! left to right, the hue picked by the hash's low byte. The wall turns
//! over every ten minutes or so; nothing is stored.

use crate::model::thousands;
use crate::pages::Scene;
use crate::theme::{self, Palette, font, mono};
use crate::widgets::{self, Kind as Button};
use eframe::egui::{
    Align, Align2, Color32, Key, Layout, Modifiers, Painter, Rect, RichText, Sense, Stroke,
    StrokeKind, Ui, ecolor::Hsva, pos2, vec2,
};

/// Tiles in a painting — 8 across, mirrored, 14 deep.
const TILES_X: usize = 8;
const TILES_Y: usize = 14;

#[derive(Default)]
pub struct Gallery {
    pub open: bool,
}

impl Gallery {
    pub fn shelve(&mut self) {
        self.open = false;
    }
}

/// The hash's 32 bytes, or `None` when it's not hex.
pub fn hash_bytes(hash: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    let bytes = hash.as_bytes();
    if bytes.len() < 64 {
        return None;
    }
    for (i, pair) in bytes[..64].chunks_exact(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

/// One painting: a mirrored tile field in the hash's hue, on a mat.
/// Eight source columns fold over the middle seam into fifteen.
pub fn painting(p: &Painter, rect: Rect, hash: &[u8; 32]) {
    let hue = f32::from(hash[0]) / 255.0;
    let second = f32::from(hash[1]) / 255.0;
    let paint = |s: f32, v: f32| -> Color32 {
        Hsva {
            h: hue,
            s,
            v,
            a: 1.0,
        }
        .into()
    };
    p.rect_filled(rect, 2, paint(0.16, 0.92));
    let cell = (rect.width() / (2 * TILES_X - 1) as f32).min(rect.height() / TILES_Y as f32);
    let grid = vec2(cell * (2 * TILES_X - 1) as f32, cell * TILES_Y as f32);
    let at = rect.center() - grid / 2.0;
    let lit = paint(0.78, 0.62 + 0.2 * second);
    let dim = paint(0.5, 0.78 + 0.15 * second);
    for y in 0..TILES_Y {
        for x in 0..TILES_X {
            let byte = hash[2 + (x + y * TILES_X) % 30];
            if byte >> ((x + y) % 8) & 1 == 0 {
                continue;
            }
            let accent = hash[2 + (x * 3 + y) % 30] >> (y % 8) & 1 != 0;
            let fill = if accent { lit } else { dim };
            for col in [x, 2 * TILES_X - 2 - x] {
                let r = Rect::from_min_size(
                    at + vec2(col as f32 * cell, y as f32 * cell),
                    vec2(cell - 0.5, cell - 0.5),
                );
                p.rect_filled(r, 1, fill);
            }
        }
    }
}

/// The whole open view: header, then the wall, newest first.
pub fn show(ui: &mut Ui, s: &Scene, gallery: &mut Gallery) {
    let pal = s.pal;
    let escape = ui.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Escape));
    let mut leave = escape;
    ui.horizontal(|ui| {
        leave |= widgets::button(ui, "← Toybox", Button::Quiet).clicked();
        ui.add_space(12.0);
        ui.label(
            RichText::new("Block gallery")
                .font(font(theme::TITLE, 21.0))
                .color(pal.text),
        );
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(
                RichText::new("each painting is the block's own hash")
                    .font(theme::body(12.5))
                    .color(pal.faint),
            );
        });
    });
    ui.add_space(10.0);

    let blocks: Vec<(u32, String)> = s
        .session
        .view
        .as_ref()
        .map(|v| v.recent.iter().rev().cloned().collect())
        .unwrap_or_default();
    if blocks.is_empty() {
        widgets::empty(
            ui,
            "The walls are bare",
            "Start the node and every block it connects hangs a painting here.",
        );
    } else {
        // The wall: frames across, wrapping; each is mat + painting +
        // height and the hash's tail.
        let gap = 14.0;
        let card_w = 176.0;
        let per_row = ((ui.available_width() + gap) / (card_w + gap)).max(1.0) as usize;
        for row in blocks.chunks(per_row) {
            ui.horizontal(|ui| {
                for (height, hash) in row {
                    frame(ui, &pal, *height, hash);
                    ui.add_space(gap - 4.0);
                }
            });
            ui.add_space(gap);
        }
    }
    if leave {
        gallery.shelve();
    }
}

/// One frame on the wall.
fn frame(ui: &mut Ui, pal: &Palette, height: u32, hash: &str) {
    let (rect, _r) = ui.allocate_exact_size(vec2(172.0, 216.0), Sense::hover());
    let p = ui.painter_at(rect);
    p.rect_filled(rect, 8, pal.raised);
    p.rect_stroke(rect, 8, Stroke::new(1.0, pal.hairline), StrokeKind::Inside);
    let art = Rect::from_min_max(rect.min + vec2(10.0, 10.0), rect.min + vec2(162.0, 152.0));
    match hash_bytes(hash) {
        Some(bytes) => painting(&p, art, &bytes),
        None => {
            p.rect_filled(art, 2, pal.well);
        }
    }
    p.text(
        pos2(rect.left() + 12.0, rect.top() + 164.0),
        Align2::LEFT_TOP,
        format!("Block {}", thousands(height.into())),
        font(theme::MEDIUM, 12.5),
        pal.text,
    );
    p.text(
        pos2(rect.left() + 12.0, rect.top() + 186.0),
        Align2::LEFT_TOP,
        format!("…{}", &hash[hash.len().saturating_sub(12)..]),
        mono(10.5),
        pal.muted,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_decode_to_bytes() {
        let h = format!("{:064x}", u128::MAX);
        let bytes = hash_bytes(&h);
        assert!(bytes.is_some());
        assert_eq!(bytes.map(|b| b[31]), Some(0xff));
        assert!(hash_bytes("xyz").is_none());
        assert!(hash_bytes("").is_none());
    }
}
