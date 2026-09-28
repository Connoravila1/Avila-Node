//! The block gallery: every block your node has connected hangs on the
//! wall, painted from its own hash — an identicon-style tile, symmetric
//! left to right, the hue picked by the hash's low byte. The wall turns
//! over every ten minutes or so; nothing is stored.

use crate::model::thousands;
use crate::pages::Scene;
use crate::theme::{self, Palette, font, mono};
use crate::widgets::{self, Kind as Button};
use std::time::Instant;

use eframe::egui::{
    self, Align, Align2, Color32, Key, Layout, Modifiers, Painter, Rect, RichText, Sense, Stroke,
    StrokeKind, Ui, ecolor::Hsva, pos2, vec2,
};

/// Tiles in a painting — 8 across, mirrored, 14 deep.
const TILES_X: usize = 8;
const TILES_Y: usize = 14;

/// What the envious mutter, in rotation.
const MUTTERS: &[&str] = &[
    "Wish I was the favorite…",
    "All that time being mined, and I'm not even the favorite.",
    "I had a nonce too, you know.",
    "Twenty trillion hashes and this is my reward.",
    "The favorite doesn't even have better entropy.",
    "Fine. I didn't want to be the favorite anyway.",
    "My coinbase paid real fees. Just saying.",
    "One reorg and the favorite is nobody.",
];

#[derive(Default)]
pub struct Gallery {
    pub open: bool,
    /// The block height on the wall's favorite — `None` until one
    /// gets pinned.
    favorite: Option<u32>,
    /// When the favorite was crowned — the mutter clock runs off it.
    fav_at: Option<Instant>,
    /// Star-pinning mode: the cursor carries a ★ until it's placed.
    picking: bool,
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
    for (i, pair) in bytes[..64].as_chunks::<2>().0.iter().enumerate() {
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
    let was_picking = gallery.picking;
    if escape && was_picking {
        gallery.picking = false;
    }
    let mut leave = escape && !was_picking;
    ui.horizontal(|ui| {
        leave |= widgets::button(ui, "← Toybox", Button::Quiet).clicked();
        ui.add_space(12.0);
        ui.label(
            RichText::new("Block gallery")
                .font(font(theme::TITLE, 21.0))
                .color(pal.text),
        );
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if gallery.picking {
                ui.label(
                    RichText::new("pin the star on a painting — Esc to put it away")
                        .font(theme::body(12.5))
                        .color(pal.signal_text),
                );
            } else if widgets::button(
                ui,
                "Pick a favorite — make the others jealous",
                Button::Quiet,
            )
            .clicked()
            {
                gallery.picking = true;
            }
            ui.add_space(10.0);
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
        // While a favorite reigns, someone mutters about it: one
        // non-favorite per ~6s, typed out live.
        let mutter_for: Option<(u32, (&'static str, usize))> = gallery.favorite.and_then(|fav| {
            let since = gallery.fav_at?.elapsed().as_secs_f32();
            let cycle = (since / 6.0) as usize;
            let phase = since % 6.0;
            let others: Vec<u32> = blocks
                .iter()
                .map(|(h, _)| *h)
                .filter(|h| *h != fav)
                .collect();
            if phase < 4.0 && !others.is_empty() {
                let speaker = others[cycle % others.len()];
                let msg = MUTTERS[(cycle + speaker as usize) % MUTTERS.len()];
                let typed = ((phase * 26.0) as usize).min(msg.len());
                Some((speaker, (msg, typed)))
            } else {
                None
            }
        });
        let gap = 16.0;
        let card_w = 208.0;
        let per_row = ((ui.available_width() + gap) / (card_w + gap)).max(1.0) as usize;
        for row in blocks.chunks(per_row) {
            ui.horizontal(|ui| {
                for (height, hash) in row {
                    let mutter = mutter_for
                        .as_ref()
                        .filter(|(h, _)| *h == *height)
                        .map(|(_, m)| *m);
                    if frame(
                        ui,
                        &pal,
                        *height,
                        hash,
                        gallery.favorite,
                        gallery.picking,
                        mutter,
                    ) {
                        gallery.favorite = Some(*height);
                        gallery.fav_at = Some(Instant::now());
                        gallery.picking = false;
                    }
                    ui.add_space(gap - 4.0);
                }
            });
            ui.add_space(gap);
        }
        // While pinning, the cursor carries the star.
        if gallery.picking {
            ui.ctx().set_cursor_icon(egui::CursorIcon::None);
            if let Some(pos) = ui.ctx().input(|i| i.pointer.hover_pos()) {
                ui.ctx()
                    .layer_painter(egui::LayerId::new(
                        egui::Order::Foreground,
                        egui::Id::new("favorite-star"),
                    ))
                    .text(
                        pos + vec2(4.0, -4.0),
                        Align2::CENTER_CENTER,
                        "★",
                        font(theme::TITLE, 18.0),
                        Color32::from_rgb(196, 154, 58),
                    );
            }
            ui.ctx().request_repaint();
        }
        // The typewriter needs its frames.
        if mutter_for.is_some() {
            ui.ctx().request_repaint();
        }
    }
    if leave {
        gallery.shelve();
    }
}

/// One frame on the wall: a dark frame, a light mat, the painting,
/// and a little plaque. Once a favorite is crowned the rest of the
/// wall turns jealous.
fn frame(
    ui: &mut Ui,
    pal: &Palette,
    height: u32,
    hash: &str,
    favorite: Option<u32>,
    picking: bool,
    mutter: Option<(&'static str, usize)>,
) -> bool {
    let (rect, resp) = ui.allocate_exact_size(
        vec2(204.0, 252.0),
        if picking {
            Sense::click()
        } else {
            Sense::hover()
        },
    );
    let p = ui.painter_at(rect);
    let favored = favorite == Some(height);
    // Frame — gold for the favorite; glows when the star hovers.
    let gilt = Color32::from_rgb(196, 154, 58);
    p.rect_filled(rect, 4, if favored { gilt } else { pal.rail });
    if picking && resp.hovered() {
        p.rect_stroke(rect, 4, Stroke::new(2.0, gilt), StrokeKind::Inside);
    }
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
    // A jealous block mutters — a little bubble over the painting,
    // typed out a character at a time.
    if let Some((full, typed)) = mutter {
        let w = (p
            .layout_no_wrap(full.to_string(), mono(9.5), pal.text)
            .size()
            .x
            + 18.0)
            .max(60.0);
        let bub = Rect::from_min_size(
            pos2(art.center().x - w / 2.0, art.top() + 8.0),
            vec2(w, 24.0),
        );
        p.rect_filled(bub, 6, pal.canvas);
        p.rect_stroke(bub, 6, Stroke::new(1.0, pal.hairline), StrokeKind::Inside);
        // Tail pointing at the painting.
        let tail = [
            pos2(bub.center().x - 4.0, bub.bottom()),
            pos2(bub.center().x + 4.0, bub.bottom()),
            pos2(bub.center().x, bub.bottom() + 7.0),
        ];
        p.add(egui::Shape::convex_polygon(
            tail.to_vec(),
            pal.canvas,
            Stroke::new(1.0, pal.hairline),
        ));
        p.text(
            pos2(bub.left() + 9.0, bub.center().y),
            Align2::LEFT_CENTER,
            &full[..typed],
            mono(9.5),
            pal.text,
        );
    }
    // Plaque — the favorite's says so.
    p.text(
        pos2(mat.left() + 6.0, art.bottom() + 10.0),
        Align2::LEFT_TOP,
        format!("Block {}", thousands(height.into())),
        font(theme::MEDIUM, 12.5),
        pal.text,
    );
    if favored {
        p.text(
            pos2(mat.left() + 6.0, art.bottom() + 28.0),
            Align2::LEFT_TOP,
            "★ the favorite",
            mono(10.5),
            Color32::from_rgb(150, 112, 30),
        );
    } else {
        p.text(
            pos2(mat.left() + 6.0, art.bottom() + 28.0),
            Align2::LEFT_TOP,
            format!("…{}", &hash[hash.len().saturating_sub(12)..]),
            mono(10.5),
            pal.muted,
        );
    }
    resp.clicked()
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
