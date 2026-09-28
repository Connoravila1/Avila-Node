//! The toybox's Phosphor skin, drawn over the page: scanlines, a soft
//! drifting refresh band, and darkened edges — a terminal, not a window.
//! The palette and the all-mono fonts live in `theme`.

use crate::theme::Skin;
use eframe::egui::{Color32, Painter, Rect, Stroke, StrokeKind, pos2, vec2};

pub fn on() -> bool {
    Skin::current() == Skin::Phosphor
}

/// The CRT over `rect`: a hairline every few rows, a bright band that
/// drifts down like the beam refreshing, and a dark frame at the edge.
pub fn overlay(p: &Painter, rect: Rect, time: f64) {
    let clip = p.with_clip_rect(rect);
    // Scanlines, thin enough to sit under the text's anti-aliasing.
    let mut y = rect.top() + 1.0;
    while y < rect.bottom() {
        clip.hline(
            rect.x_range(),
            y,
            Stroke::new(1.0, Color32::from_black_alpha(14)),
        );
        y += 3.0;
    }
    // A slow bright band drifting down, like the beam refreshing.
    let band_h = 90.0_f32;
    let span = rect.height() + band_h * 2.0;
    let top = rect.top() - band_h + (time * 26.0) as f32 % span;
    clip.rect_filled(
        Rect::from_min_size(pos2(rect.left(), top), vec2(rect.width(), band_h)),
        0,
        Color32::from_rgb(30, 80, 45).gamma_multiply(0.10),
    );
    // The edges darken — the cheap vignette is a thick inside stroke.
    clip.rect_stroke(
        rect.shrink(16.0),
        0,
        Stroke::new(32.0, Color32::from_black_alpha(46)),
        StrokeKind::Inside,
    );
}
