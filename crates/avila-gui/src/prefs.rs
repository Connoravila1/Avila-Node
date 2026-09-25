//! What the interface remembers between launches: appearance only.

use crate::ribbon::Scale;
use crate::theme::{self, Skin};
use clap::ValueEnum;
use eframe::egui;
use serde::{Deserialize, Serialize};

const KEY: &str = "appearance.v2";
/// Where the first release kept it — when following the system was the
/// default rather than light.
const KEY_V1: &str = "appearance";

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ThemeChoice {
    #[default]
    Light,
    Dark,
    /// Follow the operating system.
    System,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Prefs {
    pub theme: ThemeChoice,
    /// Interface scale, one of [`Prefs::SIZES`].
    pub size: f32,
    /// How the Trust Ribbon measures the chain.
    #[serde(default)]
    pub scale: Scale,
    /// Mask peer addresses everywhere, for screenshots and screen shares.
    #[serde(default)]
    pub hide_addresses: bool,
    /// Draw the Rhythm section as a clock instead of bars.
    #[serde(default)]
    pub rhythm_clock: bool,
    /// Show the Toybox page (games and skins).
    #[serde(default)]
    pub toybox: bool,
    /// A toybox skin; only worn while the toybox is on.
    #[serde(default)]
    pub skin: Skin,
    /// SOCKS5 proxy `host:port` from the last run's settings —
    /// private operation stays chosen across restarts rather than
    /// silently reverting to direct connections.
    #[serde(default)]
    pub proxy: String,
    /// The first-run sheet was shown — returning launches may
    /// autostart; a brand-new user sees the walkthrough instead.
    #[serde(default)]
    pub welcomed: bool,
    /// Shitcoin Defense's best score.
    #[serde(default)]
    pub game_best: u32,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            theme: ThemeChoice::Light,
            size: 1.0,
            scale: Scale::Blocks,
            hide_addresses: false,
            rhythm_clock: false,
            toybox: false,
            skin: Skin::Standard,
            proxy: String::new(),
            welcomed: false,
            game_best: 0,
        }
    }
}

impl Prefs {
    pub const SIZES: [(f32, &'static str); 4] =
        [(0.9, "90%"), (1.0, "100%"), (1.15, "115%"), (1.3, "130%")];

    #[must_use]
    pub fn load(storage: Option<&dyn eframe::Storage>) -> Self {
        let Some(storage) = storage else {
            return Self::default();
        };
        if let Some(prefs) = eframe::get_value::<Self>(storage, KEY) {
            return prefs.normalized();
        }
        // Carried over from the first release, where "match the system"
        // was saved for anyone who never chose; light is the default now.
        eframe::get_value::<Self>(storage, KEY_V1)
            .map(|old| Self {
                theme: match old.theme {
                    ThemeChoice::System => ThemeChoice::Light,
                    chosen => chosen,
                },
                ..old.normalized()
            })
            .unwrap_or_default()
    }

    pub fn save(&self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, KEY, &self.normalized());
    }

    pub fn apply(&self, ctx: &egui::Context) {
        ctx.set_theme(match self.theme {
            ThemeChoice::System => egui::ThemePreference::System,
            ThemeChoice::Light => egui::ThemePreference::Light,
            ThemeChoice::Dark => egui::ThemePreference::Dark,
        });
        ctx.set_zoom_factor(self.size);
        theme::set_skin(
            ctx,
            if self.toybox {
                self.skin
            } else {
                Skin::Standard
            },
        );
    }

    /// Snaps a stored size to the nearest offered one.
    fn normalized(&self) -> Self {
        let size = Self::SIZES
            .iter()
            .map(|(s, _)| *s)
            .min_by(|a, b| (a - self.size).abs().total_cmp(&(b - self.size).abs()))
            .unwrap_or(1.0);
        Self {
            size,
            ..self.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct Storage(HashMap<String, String>);

    impl eframe::Storage for Storage {
        fn get_string(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }

        fn set_string(&mut self, key: &str, value: String) {
            self.0.insert(key.into(), value);
        }

        fn remove_string(&mut self, key: &str) {
            self.0.remove(key);
        }

        fn flush(&mut self) {}
    }

    #[test]
    fn prefs_round_trip_and_snap_sizes() {
        let mut storage = Storage::default();
        let prefs = Prefs {
            theme: ThemeChoice::Dark,
            size: 1.12,
            scale: Scale::Work,
            hide_addresses: true,
            rhythm_clock: true,
            toybox: true,
            skin: Skin::Julia,
            game_best: 42,
            proxy: "127.0.0.1:9050".into(),
            welcomed: true,
        };
        prefs.save(&mut storage);
        assert_eq!(
            Prefs::load(Some(&storage)),
            Prefs {
                theme: ThemeChoice::Dark,
                size: 1.15,
                scale: Scale::Work,
                hide_addresses: true,
                rhythm_clock: true,
                toybox: true,
                skin: Skin::Julia,
                game_best: 42,
                proxy: "127.0.0.1:9050".into(),
                welcomed: true,
            }
        );
        assert_eq!(storage.0.len(), 1);
        assert_eq!(Prefs::load(None), Prefs::default());
        storage.0.insert(KEY.into(), "not ron".into());
        assert_eq!(Prefs::load(Some(&storage)), Prefs::default());
    }

    #[test]
    fn first_release_prefs_carry_over_with_light_as_the_default() {
        let mut storage = Storage::default();
        assert_eq!(Prefs::load(Some(&storage)).theme, ThemeChoice::Light);
        // Saved by the first release, before the ribbon had a scale: the
        // untouched default ("system") becomes light; a real choice stays.
        storage
            .0
            .insert(KEY_V1.into(), "(theme:system,size:1.15)".into());
        let carried = Prefs::load(Some(&storage));
        assert_eq!(carried.theme, ThemeChoice::Light);
        assert_eq!(carried.size, 1.15);
        assert_eq!(carried.scale, Scale::Blocks);
        storage
            .0
            .insert(KEY_V1.into(), "(theme:dark,size:1.0)".into());
        assert_eq!(Prefs::load(Some(&storage)).theme, ThemeChoice::Dark);
        // Once saved under the new key, an explicit "system" sticks.
        Prefs {
            theme: ThemeChoice::System,
            ..Prefs::default()
        }
        .save(&mut storage);
        assert_eq!(Prefs::load(Some(&storage)).theme, ThemeChoice::System);
    }
}
