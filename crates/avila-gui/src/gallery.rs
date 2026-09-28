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

/// One painting: a mirrored tile field painted in the hash's own hues,
/// on a mat. Eight source columns fold over the middle seam into
/// fifteen. The hash's leading bytes are all zeroes by definition —
/// the proof-of-work target — so the palette reads the tail, where
/// the entropy lives.
pub fn painting(p: &Painter, rect: Rect, hash: &[u8; 32]) {
    let tail = &hash[16..];
    let hue = f32::from(tail[0]) / 255.0;
    let second = f32::from(tail[4]) / 255.0;
    let paint = |h: f32, s: f32, v: f32| -> Color32 { Hsva { h, s, v, a: 1.0 }.into() };
    p.rect_filled(rect, 2, paint(hue, 0.14, 0.93));
    let cell = (rect.width() / (2 * TILES_X - 1) as f32).min(rect.height() / TILES_Y as f32);
    let grid = vec2(cell * (2 * TILES_X - 1) as f32, cell * TILES_Y as f32);
    let at = rect.center() - grid / 2.0;
    let lit = paint(hue, 0.72, 0.55 + 0.25 * second);
    let dim = paint(second, 0.55, 0.7 + 0.2 * second);
    let deep = paint(hue, 0.8, 0.34);
    for y in 0..TILES_Y {
        for x in 0..TILES_X {
            let byte = tail[(x + y * TILES_X) % tail.len()];
            if byte >> ((x + y) % 8) & 1 == 0 {
                continue;
            }
            let shade = tail[(x * 5 + y * 3) % tail.len()];
            let fill = match shade % 3 {
                0 => lit,
                1 => dim,
                _ => deep,
            };
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
        // The wall: frames across, wrapping; each is a matted painting
        // with a small plaque — the height and the hash's tail.
        let gap = 16.0;
        let card_w = 208.0;
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

/// One frame on the wall: a dark frame, a light mat, the painting,
/// and a little plaque.
fn frame(ui: &mut Ui, pal: &Palette, height: u32, hash: &str) {
    let (rect, _r) = ui.allocate_exact_size(vec2(204.0, 252.0), Sense::hover());
    let p = ui.painter_at(rect);
    // Frame.
    p.rect_filled(rect, 4, pal.rail);
    p.rect_stroke(rect, 4, Stroke::new(1.0, pal.hairline), StrokeKind::Inside);
    // Mat.
    let mat = rect.shrink(10.0);
    p.rect_filled(mat, 2, pal.canvas);
    let art = mat.shrink(8.0);
    let art = Rect::from_min_max(art.min, pos2(art.right(), mat.bottom() - 44.0));
    match hash_bytes(hash) {
        Some(bytes) => painting(&p, art, &bytes),
        None => {
            p.rect_filled(art, 2, pal.well);
        }
    }
    p.rect_stroke(art, 2, Stroke::new(1.0, pal.hairline), StrokeKind::Inside);
    // Plaque.
    p.text(
        pos2(mat.left() + 6.0, art.bottom() + 10.0),
        Align2::LEFT_TOP,
        format!("Block {}", thousands(height.into())),
        font(theme::MEDIUM, 12.5),
        pal.text,
    );
    p.text(
        pos2(mat.left() + 6.0, art.bottom() + 28.0),
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
