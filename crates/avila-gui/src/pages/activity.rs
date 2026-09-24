//! What happened this session, newest first: blocks, peers coming and
//! going, verification milestones, and the node's own journal.

use super::{Action, Scene, start_offer};
use crate::session::{Activity, ActivityKind};
use crate::theme::{self, body, font, mono};
use crate::widgets;
use eframe::egui::{
    Align, Align2, CursorIcon, Layout, Rect, RichText, Sense, Stroke, Ui, pos2, text::TextWrapping,
    vec2,
};

/// Rows drawn at most; the log itself keeps more.
const SHOWN: usize = 300;

pub fn show(ui: &mut Ui, s: &Scene, filter: &mut Option<ActivityKind>) -> Option<Action> {
    ui.horizontal(|ui| {
        let mut options: Vec<(Option<ActivityKind>, &str)> = vec![(None, "All")];
        options.extend(ActivityKind::ALL.iter().map(|k| (Some(*k), k.label())));
        widgets::segmented(ui, filter, &options);
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(RichText::new("Times are UTC").size(12.5).color(s.pal.faint));
        });
    });
    ui.add_space(16.0);
    let rows: Vec<&Activity> = s
        .session
        .activity
        .iter()
        .rev()
        .filter(|a| filter.is_none_or(|k| a.kind == k))
        .take(SHOWN)
        .collect();
    if rows.is_empty() {
        let body = match filter {
            None => "Start the node and what it does shows up here as it happens.",
            Some(_) => "Nothing of this kind has happened yet this session.",
        };
        widgets::empty(ui, "Nothing yet", body);
        return filter.is_none().then(|| start_offer(ui, s)).flatten();
    }
    for (i, a) in rows.into_iter().enumerate() {
        row(ui, s, a, i);
    }
    None
}

/// One entry, painted into a fixed-height row — and only when it's on
/// screen, so a long log costs nothing to scroll past.
fn row(ui: &mut Ui, s: &Scene, a: &Activity, index: usize) {
    let pal = s.pal;
    let height = if a.detail.is_some() { 56.0 } else { 38.0 };
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), height), Sense::hover());
    if !ui.is_rect_visible(rect) {
        return;
    }
    let p = ui.painter();
    let top = rect.top() + 9.0;
    p.text(
        pos2(rect.left(), top + 1.0),
        Align2::LEFT_TOP,
        &a.clock,
        mono(12.0),
        pal.faint,
    );
    // Orange means proven here, so only verification wears it.
    let kind = if a.kind == ActivityKind::Verification {
        pal.signal_text
    } else {
        pal.muted
    };
    p.text(
        pos2(rect.left() + 84.0, top + 1.0),
        Align2::LEFT_TOP,
        a.kind.label(),
        font(theme::MEDIUM, 12.5),
        kind,
    );
    let x = rect.left() + 192.0;
    let w = (rect.right() - x).max(40.0);
    let text = widgets::fit(p, a.text.clone(), body(14.0), pal.text, w);
    let elided = text.elided;
    p.galley(pos2(x, top), text, pal.text);
    if let Some(d) = &a.detail {
        let at = pos2(x, top + 23.0);
        if is_hash(d) {
            let mut job = widgets::hash_job(d, 12.0, &pal, None);
            job.wrap = TextWrapping::truncate_at_width(w);
            let galley = p.layout_job(job);
            let r = Rect::from_min_size(at, galley.size());
            p.galley(at, galley, pal.muted);
            let copy = ui
                .interact(r, ui.id().with(("hash", index)), Sense::click())
                .on_hover_cursor(CursorIcon::Copy)
                .on_hover_text("Copy the full hash");
            if copy.clicked() {
                ui.ctx().copy_text(d.clone());
            }
        } else {
            let galley = widgets::fit(p, d.clone(), mono(12.0), pal.muted, w);
            ui.painter().galley(at, galley, pal.muted);
        }
    }
    ui.painter().hline(
        rect.x_range(),
        rect.bottom() - 0.5,
        Stroke::new(1.0, pal.hairline),
    );
    if elided {
        resp.on_hover_text(&a.text);
    }
}

fn is_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
