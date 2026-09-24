//! The brand rail: the logo's orange field running down the window's
//! edge, the swirl at its head, the pages beneath, and at its foot the
//! network and whether the node is live.

use crate::theme::{self, INK, SIGNAL, font};
use eframe::egui::{
    Align2, Color32, CursorIcon, Painter, Pos2, Rect, Sense, Stroke, StrokeKind, TextureHandle, Ui,
    pos2, vec2,
};

pub const WIDTH: f32 = 80.0;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Page {
    #[default]
    Overview,
    Chain,
    Peers,
    Activity,
    Settings,
}

impl Page {
    pub const ALL: [Self; 5] = [
        Self::Overview,
        Self::Chain,
        Self::Peers,
        Self::Activity,
        Self::Settings,
    ];

    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Chain => "Chain",
            Self::Peers => "Peers",
            Self::Activity => "Activity",
            Self::Settings => "Settings",
        }
    }
}

pub fn show(
    ui: &mut Ui,
    page: &mut Page,
    swirl: Option<&TextureHandle>,
    network: &str,
    live: bool,
) {
    let rect = ui.max_rect();
    let p = ui.painter().clone();
    let cx = rect.center().x;
    if let Some(tex) = swirl {
        let mark = Rect::from_center_size(pos2(cx, rect.top() + 42.0), vec2(46.0, 46.0));
        p.image(
            tex.id(),
            mark,
            Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)),
            INK,
        );
    }
    let mut y = rect.top() + 92.0;
    for item in Page::ALL {
        let r = Rect::from_min_size(pos2(rect.left() + 9.0, y), vec2(rect.width() - 18.0, 58.0));
        y += 62.0;
        let resp = ui
            .interact(r, ui.id().with(item.label()), Sense::click())
            .on_hover_cursor(CursorIcon::PointingHand);
        if resp.clicked() {
            *page = item;
        }
        let selected = *page == item;
        let (bg, fg) = if selected {
            (INK, SIGNAL)
        } else if resp.hovered() {
            (INK.gamma_multiply(0.10), INK)
        } else {
            (Color32::TRANSPARENT, INK)
        };
        p.rect_filled(r, 12, bg);
        icon(
            &p,
            item,
            pos2(r.center().x, r.top() + 21.0),
            fg,
            if selected { INK } else { SIGNAL },
        );
        p.text(
            pos2(r.center().x, r.top() + 43.0),
            Align2::CENTER_CENTER,
            item.label(),
            font(theme::MEDIUM, 11.0),
            fg,
        );
        if resp.has_focus() {
            p.rect_stroke(
                r.expand(1.5),
                13,
                Stroke::new(1.5, INK),
                StrokeKind::Outside,
            );
        }
    }
    let foot = rect.bottom() - 22.0;
    p.text(
        pos2(cx, foot),
        Align2::CENTER_CENTER,
        network,
        font(theme::STRONG, 10.5),
        INK,
    );
    let dot = pos2(cx, foot - 17.0);
    if live {
        p.circle_filled(dot, 4.0, INK);
    } else {
        p.circle_stroke(dot, 3.5, Stroke::new(1.4, INK));
    }
}

/// Each page's glyph, drawn rather than borrowed from an icon font.
fn icon(p: &Painter, page: Page, c: Pos2, fg: Color32, bg: Color32) {
    let s = Stroke::new(1.6, fg);
    match page {
        // The ribbon in miniature.
        Page::Overview => {
            let r = Rect::from_center_size(c, vec2(24.0, 10.0));
            p.rect_stroke(r, 2, s, StrokeKind::Inside);
            let fill = Rect::from_min_max(r.min, pos2(r.left() + 14.0, r.bottom()));
            p.rect_filled(fill, 2, fg);
        }
        // Linked blocks.
        Page::Chain => {
            for i in [-1.0_f32, 0.0, 1.0] {
                let b = Rect::from_center_size(c + vec2(i * 9.0, 0.0), vec2(6.5, 6.5));
                p.rect_stroke(b, 1, s, StrokeKind::Inside);
            }
            for dx in [-4.5_f32, 4.5] {
                p.line_segment([c + vec2(dx - 1.25, 0.0), c + vec2(dx + 1.25, 0.0)], s);
            }
        }
        // A node among its peers.
        Page::Peers => {
            for o in [
                vec2(-9.0, -6.0),
                vec2(9.0, -6.0),
                vec2(-9.0, 6.0),
                vec2(9.0, 6.0),
            ] {
                p.line_segment([c, c + o], Stroke::new(1.2, fg));
                p.circle_filled(c + o, 2.4, fg);
            }
            p.circle_filled(c, 3.6, fg);
        }
        // A running log.
        Page::Activity => {
            for (dy, w) in [(-6.0, 22.0), (0.0, 14.0), (6.0, 18.0)] {
                p.line_segment(
                    [pos2(c.x - 11.0, c.y + dy), pos2(c.x - 11.0 + w, c.y + dy)],
                    s,
                );
            }
        }
        // Two sliders.
        Page::Settings => {
            for (dy, kx) in [(-4.5, -4.0), (4.5, 5.0)] {
                p.line_segment([pos2(c.x - 11.0, c.y + dy), pos2(c.x + 11.0, c.y + dy)], s);
                let k = pos2(c.x + kx, c.y + dy);
                p.circle_filled(k, 3.4, bg);
                p.circle_stroke(k, 3.4, s);
            }
        }
    }
}
