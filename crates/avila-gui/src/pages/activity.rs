//! What happened this session, newest first: blocks, peers coming and
//! going, verification milestones, and the node's own journal.

use super::{Action, Scene, start_offer};
use crate::session::{Activity, ActivityKind};
use crate::theme::{self, font, mono};
use crate::widgets;
use eframe::egui::{Align, Layout, RichText, Ui, vec2};

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
    for a in rows {
        row(ui, s, a);
    }
    None
}

fn row(ui: &mut Ui, s: &Scene, a: &Activity) {
    let pal = s.pal;
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        fixed(ui, 84.0, |ui| {
            ui.label(RichText::new(&a.clock).font(mono(12.0)).color(pal.faint));
        });
        fixed(ui, 108.0, |ui| {
            // Orange means proven here, so only verification wears it.
            let color = if a.kind == ActivityKind::Verification {
                pal.signal_text
            } else {
                pal.muted
            };
            ui.label(
                RichText::new(a.kind.label())
                    .font(font(theme::MEDIUM, 12.5))
                    .color(color),
            );
        });
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 3.0;
            ui.label(RichText::new(&a.text).size(14.0).color(pal.text));
            if let Some(d) = &a.detail {
                if is_hash(d) {
                    let keep = (ui.available_width() < 560.0).then_some(16);
                    widgets::hash_label(ui, d, 12.0, keep);
                } else {
                    ui.label(RichText::new(d).font(mono(12.0)).color(pal.muted));
                }
            }
        });
    });
    ui.add_space(6.0);
    widgets::hairline(ui);
    ui.add_space(6.0);
}

fn fixed(ui: &mut Ui, width: f32, add: impl FnOnce(&mut Ui)) {
    ui.allocate_ui_with_layout(vec2(width, 20.0), Layout::top_down(Align::Min), |ui| {
        ui.set_width(width);
        add(ui);
    });
}

fn is_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
