//! The screens. Each draws from the shared [`Scene`] and hands back an
//! [`Action`] for the app to carry out once the frame is drawn.

pub mod activity;
pub mod chain;
pub mod overview;
pub mod peers;
pub mod settings;
pub mod tour;
pub mod welcome;

use crate::session::Session;
use crate::theme::Palette;
use crate::widgets::{self, Kind};
use eframe::egui::{TextureHandle, Ui};

/// How long the new-block pulse runs, seconds.
const PULSE_SECS: f64 = 1.6;

pub struct Scene<'a> {
    pub pal: Palette,
    pub session: &'a Session,
    pub network: avila_core::Network,
    /// The logo's swirl, for marks that stand for this node.
    pub swirl: Option<&'a TextureHandle>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Start,
    Stop,
    Open(crate::rail::Page),
    /// Re-run the first-open slideshow.
    ReplayTour,
}

impl Scene<'_> {
    /// Progress `0..1` of the new-block pulse, while one is running.
    #[must_use]
    pub fn pulse(&self) -> Option<f32> {
        let at = self.session.tip_advanced_at?;
        let f = (self.session.now() - at) / PULSE_SECS;
        (0.0..1.0).contains(&f).then_some(f as f32)
    }
}

/// The start button empty states offer, when the node isn't running.
pub fn start_offer(ui: &mut Ui, s: &Scene) -> Option<Action> {
    let running = s.session.running();
    (!running && widgets::button(ui, "Start node", Kind::Primary).clicked())
        .then_some(Action::Start)
}
