//! The toybox's Julia skin: the node as if Barbie shipped it. Titles and
//! big numbers in a bubbly script (Pacifico, the one font this skin adds),
//! hearts wherever there were dots, candy stripes and a bow on the
//! ribbon, jelly buttons, lace under the headings, and glitter.

use crate::theme::{self, Palette, Skin, font};
use eframe::egui::{
    Align2, Color32, CornerRadius, CursorIcon, Mesh, Painter, Pos2, Rect, Response, Sense, Shape,
    Stroke, StrokeKind, Ui, pos2, vec2,
};
use std::f32::consts::{FRAC_PI_2, TAU};

/// Whether the Julia skin is on.
#[must_use]
pub fn on() -> bool {
    Skin::current() == Skin::Julia
}

/// Points around a heart `size` tall, centered on `c`: the classic
/// x = 16 sin³t, y = 13 cos t − 5 cos 2t − 2 cos 3t − cos 4t, which runs
/// from 12 at the lobes to −17 at the tip.
fn heart_points(c: Pos2, size: f32) -> Vec<Pos2> {
    let s = size / 29.0;
    // Small hearts don't need the detail.
    let n = if size < 10.0 { 14 } else { 28 };
    (0..n)
        .map(|i| {
            let t = TAU * i as f32 / n as f32;
            let x = 16.0 * t.sin().powi(3);
            let y =
                13.0 * t.cos() - 5.0 * (2.0 * t).cos() - 2.0 * (3.0 * t).cos() - (4.0 * t).cos();
            c + vec2(x * s, -(y + 2.5) * s)
        })
        .collect()
}

/// A filled heart. Every ray from its middle crosses the edge once, so a
/// fan from there fills it.
pub fn heart(p: &Painter, c: Pos2, size: f32, color: Color32) {
    let points = heart_points(c, size);
    let mut mesh = Mesh::default();
    mesh.colored_vertex(c, color);
    for point in &points {
        mesh.colored_vertex(*point, color);
    }
    let n = points.len() as u32;
    for i in 0..n {
        mesh.add_triangle(0, 1 + i, 1 + (i + 1) % n);
    }
    p.add(Shape::mesh(mesh));
    // A hairline around a bigger one keeps its edge smooth.
    if size >= 10.0 {
        p.add(Shape::closed_line(points, Stroke::new(0.8, color)));
    }
}

pub fn heart_outline(p: &Painter, c: Pos2, size: f32, stroke: Stroke) {
    p.add(Shape::closed_line(heart_points(c, size), stroke));
}

/// A four-pointed glint.
pub fn sparkle(p: &Painter, c: Pos2, r: f32, color: Color32) {
    let mut mesh = Mesh::default();
    mesh.colored_vertex(c, color);
    for i in 0..8 {
        let a = TAU * i as f32 / 8.0 - FRAC_PI_2;
        let reach = if i % 2 == 0 { r } else { r * 0.26 };
        mesh.colored_vertex(c + vec2(a.cos(), a.sin()) * reach, color);
    }
    for i in 0..8 {
        mesh.add_triangle(0, 1 + i, 1 + (i + 1) % 8);
    }
    p.add(Shape::mesh(mesh));
}

/// A ribbon bow `size` wide, centered on its knot.
pub fn bow(p: &Painter, c: Pos2, size: f32, color: Color32, knot: Color32) {
    let (w, h) = (size / 2.0, size * 0.3);
    let edge = Stroke::new(1.0, knot);
    for s in [-1.0, 1.0] {
        p.add(Shape::convex_polygon(
            vec![
                c + vec2(s * w * 0.1, h * 0.3),
                c + vec2(s * w * 0.5, h * 2.1),
                c + vec2(s * w * 0.28, h * 1.75),
                c + vec2(s * w * 0.02, h * 0.5),
            ],
            color,
            edge,
        ));
        p.add(Shape::convex_polygon(
            vec![
                c,
                c + vec2(s * w * 0.78, -h * 1.25),
                c + vec2(s * w, -h * 0.45),
                c + vec2(s * w * 0.92, h * 0.75),
            ],
            color,
            edge,
        ));
    }
    p.circle_filled(c, h * 0.62, knot);
}

/// Candy stripes and a sheen over a bar that's already filled.
pub fn candy(p: &Painter, rect: Rect) {
    crate::widgets::hatch(p, rect, Color32::from_white_alpha(80), 13.0, 4.5);
    let sheen = Rect::from_min_size(
        rect.min + vec2(0.0, 2.0),
        vec2(rect.width(), rect.height() * 0.3),
    );
    p.rect_filled(sheen, 0, Color32::from_white_alpha(56));
}

/// A glossy jelly pill: lighter on top, a shine across its upper half, a
/// soft shadow under it.
pub fn jelly(
    p: &Painter,
    rect: Rect,
    radius: u8,
    base: Color32,
    edge: Color32,
    hot: bool,
    down: bool,
) {
    let round = CornerRadius::same(radius);
    p.rect_filled(
        rect.translate(vec2(0.0, 2.0)),
        round,
        edge.gamma_multiply(0.22),
    );
    let top = base.lerp_to_gamma(Color32::WHITE, if hot { 0.46 } else { 0.32 });
    let bottom = if down {
        base.lerp_to_gamma(Color32::BLACK, 0.08)
    } else {
        base
    };
    crate::xp::gradient(p, rect, round, &[(0.0, top), (1.0, bottom)]);
    let shine = Rect::from_min_max(
        rect.min + vec2(5.0, 2.5),
        pos2(rect.right() - 5.0, rect.top() + rect.height() * 0.46),
    );
    p.rect_filled(
        shine,
        CornerRadius::same(radius.saturating_sub(3)),
        Color32::from_white_alpha(if down { 36 } else { 84 }),
    );
    p.rect_stroke(rect, round, Stroke::new(1.0, edge), StrokeKind::Inside);
}

/// A row of little hearts, for underlining.
pub fn lace(p: &Painter, from: f32, to: f32, y: f32, color: Color32) {
    let mut x = from + 3.0;
    while x < to - 3.0 {
        heart(p, pos2(x, y), 5.0, color);
        x += 16.0;
    }
}

/// Where the glitter sits, 0..1 across the canvas, and when it twinkles.
const GLITTER: [(f32, f32, f32); 9] = [
    (0.08, 0.12, 0.0),
    (0.31, 0.06, 1.7),
    (0.57, 0.18, 3.1),
    (0.83, 0.09, 0.9),
    (0.93, 0.41, 2.4),
    (0.66, 0.55, 4.2),
    (0.18, 0.62, 5.0),
    (0.44, 0.83, 1.2),
    (0.87, 0.86, 3.6),
];

/// The canvas: hearts and dots in a staggered grid, anchored to the
/// window, and glitter that twinkles as the page repaints.
pub fn wallpaper(p: &Painter, rect: Rect, time: f64) {
    let step = 56.0;
    let rows = (rect.height() / step).ceil() as i32 + 1;
    let cols = (rect.width() / step).ceil() as i32 + 1;
    let first = (rect.top() / step).floor() as i32;
    let left = (rect.left() / step).floor() as i32;
    for row in first..first + rows {
        for col in left..left + cols {
            let x = col as f32 * step + if row % 2 == 0 { 0.0 } else { step / 2.0 };
            let at = pos2(x, row as f32 * step);
            if !rect.contains(at) {
                continue;
            }
            if (row + col).rem_euclid(3) == 0 {
                heart(p, at, 8.0, Color32::from_white_alpha(150));
            } else {
                p.circle_filled(at, 1.6, Color32::from_rgb(247, 168, 207));
            }
        }
    }
    for (fx, fy, phase) in GLITTER {
        let twinkle = (((time as f32) * 1.9 + phase).sin() * 0.5 + 0.5).powi(2);
        if twinkle > 0.08 {
            let at = pos2(
                rect.left() + rect.width() * fx,
                rect.top() + rect.height() * fy,
            );
            sparkle(
                p,
                at,
                3.0 + 4.0 * twinkle,
                Color32::from_white_alpha((230.0 * twinkle) as u8),
            );
        }
    }
}

/// The rail: a deeper pink at the top, glitter down it, and a bow on the
/// logo.
pub fn rail(p: &Painter, rect: Rect, logo: Pos2, time: f64) {
    crate::xp::gradient(
        p,
        rect,
        0,
        &[
            (0.0, Color32::from_rgb(214, 22, 128)),
            (1.0, Color32::from_rgb(250, 120, 186)),
        ],
    );
    for (i, fy) in [0.26, 0.47, 0.63, 0.78, 0.9].into_iter().enumerate() {
        let twinkle = (((time as f32) * 1.6 + i as f32 * 1.3).sin() * 0.5 + 0.5).powi(2);
        let x = rect.left()
            + if i % 2 == 0 {
                12.0
            } else {
                rect.width() - 12.0
            };
        sparkle(
            p,
            pos2(x, rect.top() + rect.height() * fy),
            2.5 + 3.0 * twinkle,
            Color32::from_white_alpha((80.0 + 150.0 * twinkle) as u8),
        );
    }
    bow(
        p,
        logo + vec2(15.0, -17.0),
        22.0,
        Color32::WHITE,
        Color32::from_rgb(255, 170, 212),
    );
}

/// A section heading: the title in script, a heart, and lace beneath.
pub fn section(ui: &mut Ui, title: &str, note: Option<&str>) {
    let pal = Palette::of(ui.ctx());
    let width = ui.available_width();
    let galley =
        ui.painter()
            .layout_no_wrap(title.to_owned(), font(theme::TITLE, 23.0), pal.signal_text);
    let (rect, _) = ui.allocate_exact_size(vec2(width, galley.size().y + 10.0), Sense::hover());
    let p = ui.painter();
    let mid = rect.top() + galley.size().y * 0.56;
    let after = rect.left() + galley.size().x + 14.0;
    p.galley(rect.left_top(), galley, pal.signal_text);
    heart(p, pos2(after, mid), 10.0, pal.signal);
    if let Some(note) = note {
        p.text(
            pos2(after + 14.0, mid),
            Align2::LEFT_CENTER,
            note,
            theme::body(13.0),
            pal.muted,
        );
    }
    lace(
        p,
        rect.left(),
        rect.right(),
        rect.bottom() - 3.0,
        pal.hairline,
    );
    ui.add_space(6.0);
}

/// A check box that's a heart: empty until it's ticked.
pub fn checkbox(ui: &mut Ui, value: &mut bool, text: &str) -> Response {
    let pal = Palette::of(ui.ctx());
    let enabled = ui.is_enabled();
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_owned(), theme::body(14.0), pal.text);
    let (rect, mut resp) =
        ui.allocate_exact_size(vec2(26.0 + galley.size().x, 24.0), Sense::click());
    if resp.clicked() {
        *value = !*value;
        resp.mark_changed();
    }
    let p = ui.painter();
    let c = pos2(rect.left() + 9.0, rect.center().y);
    let ink = if enabled { pal.signal } else { pal.faint };
    if *value {
        heart(p, c, 17.0, ink);
        sparkle(p, c + vec2(-3.5, -3.0), 2.6, Color32::from_white_alpha(220));
    } else {
        heart(p, c, 17.0, pal.raised);
        heart_outline(
            p,
            c,
            17.0,
            Stroke::new(
                1.6,
                if resp.hovered() && enabled {
                    ink
                } else {
                    pal.faint
                },
            ),
        );
    }
    let text_at = pos2(rect.left() + 26.0, rect.center().y - galley.size().y / 2.0);
    p.galley(text_at, galley, if enabled { pal.text } else { pal.faint });
    if resp.has_focus() {
        p.rect_stroke(
            rect.expand(2.0),
            8,
            Stroke::new(1.5, pal.signal_text),
            StrokeKind::Outside,
        );
    }
    resp.on_hover_cursor(CursorIcon::PointingHand)
}
