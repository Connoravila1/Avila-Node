//! The first-open walkthrough — a short slideshow over the live app,
//! in the spirit of OpenBNCT's guided tours: dimmed canvas, one card,
//! Back / Next / Skip, ← → keys, Esc. `None` returned while running;
//! `Some(())` when the deck is finished or skipped.

use crate::theme::{self, Palette};
use crate::widgets::{self, Kind};
use eframe::egui::{self, Align, Color32, Id, Key, LayerId, Layout, Order, RichText, Ui, vec2};

struct Slide {
    title: &'static str,
    body: &'static str,
}

const SLIDES: &[Slide] = &[
    Slide {
        title: "This is a real node",
        body: "It connects to the bitcoin network and downloads every block, checking each one on this machine. No company's server decides what's true — the work is done here.",
    },
    Slide {
        title: "The first sync is the long part",
        body: "About 700 GB moves through your peers over days, then the node keeps up in seconds a day. It resumes where it stops — closing the window loses nothing.",
    },
    Slide {
        title: "What you'll see while it runs",
        body: "The banner up top counts headers, then blocks, with a pace and a finish estimate once one exists. The ribbon is the chain filling in — orange is what this machine proved.",
    },
    Slide {
        title: "Peers are strangers, handled carefully",
        body: "The node talks to a handful of them, encrypted when they allow it. If something looks wrong — like every route coming from one place — a warning says so plainly.",
    },
    Slide {
        title: "When it catches up",
        body: "The mempool, fee estimates, an Electrum server for your wallet, and per-block verification receipts — all served by this machine, inspectable by you.",
    },
];

/// Draw the slideshow over whatever the app just rendered. Returns
/// `true` while a slide is up (the app stays live underneath).
pub fn show(ui: &mut Ui, pal: &Palette, step: usize) -> Option<TourAction> {
    let ctx = ui.ctx().clone();
    let screen = ctx.content_rect();
    // Dim the whole app behind the card.
    let dimmer = ctx.layer_painter(LayerId::new(Order::Foreground, Id::new("tour-dim")));
    dimmer.rect_filled(screen, 0.0, Color32::from_black_alpha(170));

    let mut action = None;
    egui::Area::new(Id::new("tour-card"))
        .order(Order::Tooltip)
        .anchor(egui::Align2::CENTER_CENTER, vec2(0.0, 0.0))
        .show(&ctx, |ui| {
            egui::Frame::new()
                .fill(pal.raised)
                .stroke(egui::Stroke::new(1.0, pal.hairline))
                .corner_radius(12.0)
                .inner_margin(egui::Margin::same(24))
                .show(ui, |ui| {
                    ui.set_width(430.0);
                    let slide = &SLIDES[step];
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("FIRST RUN")
                                .font(theme::font(theme::STRONG, 11.0))
                                .color(theme::SIGNAL),
                        );
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui
                                .button(RichText::new("×").size(17.0).color(pal.muted))
                                .clicked()
                            {
                                action = Some(TourAction::Skip);
                            }
                        });
                    });
                    ui.add_space(14.0);
                    ui.label(
                        RichText::new(slide.title)
                            .font(theme::font(theme::TITLE, 22.0))
                            .color(pal.text),
                    );
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(slide.body)
                            .font(theme::font(theme::MEDIUM, 14.0))
                            .color(pal.muted),
                    );
                    ui.add_space(18.0);
                    // Progress dots.
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 6.0;
                        for i in 0..SLIDES.len() {
                            let on = i <= step;
                            let (rect, _) = ui.allocate_exact_size(
                                vec2(if i == step { 18.0 } else { 7.0 }, 7.0),
                                egui::Sense::hover(),
                            );
                            ui.painter().rect_filled(
                                rect,
                                4.0,
                                if on { pal.signal } else { pal.well },
                            );
                        }
                    });
                    ui.add_space(14.0);
                    ui.horizontal(|ui| {
                        if step > 0 && widgets::button(ui, "Back", Kind::Quiet).clicked() {
                            action = Some(TourAction::Back);
                        }
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            let last = step + 1 == SLIDES.len();
                            let label = if last { "Set it up" } else { "Next" };
                            if widgets::button(ui, label, Kind::Primary).clicked() {
                                action = Some(if last {
                                    TourAction::Skip
                                } else {
                                    TourAction::Next
                                });
                            }
                            if !last && ui.link(RichText::new("Skip").color(pal.muted)).clicked() {
                                action = Some(TourAction::Skip);
                            }
                        });
                    });
                });
        });

    // Keys: → / ← step, Esc quits the deck.
    if ctx.input(|i| i.key_pressed(Key::ArrowRight)) {
        action = Some(TourAction::Next);
    } else if ctx.input(|i| i.key_pressed(Key::ArrowLeft)) && step > 0 {
        action = Some(TourAction::Back);
    } else if ctx.input(|i| i.key_pressed(Key::Escape)) {
        action = Some(TourAction::Skip);
    }
    action
}

pub enum TourAction {
    Back,
    Next,
    Skip,
}

#[must_use]
pub fn slide_count() -> usize {
    SLIDES.len()
}
