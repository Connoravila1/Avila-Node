//! What the interface remembers between launches: appearance only.

use clap::ValueEnum;
use eframe::egui;
use serde::{Deserialize, Serialize};

const KEY: &str = "appearance";

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ThemeChoice {
    /// Follow the operating system.
    #[default]
    System,
    Light,
    Dark,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub struct Prefs {
    pub theme: ThemeChoice,
    /// Interface scale, one of [`Prefs::SIZES`].
    pub size: f32,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            theme: ThemeChoice::System,
            size: 1.0,
        }
    }
}

impl Prefs {
    pub const SIZES: [(f32, &'static str); 4] =
        [(0.9, "90%"), (1.0, "100%"), (1.15, "115%"), (1.3, "130%")];

    #[must_use]
    pub fn load(storage: Option<&dyn eframe::Storage>) -> Self {
        storage
            .and_then(|s| eframe::get_value::<Self>(s, KEY))
            .map(Self::normalized)
            .unwrap_or_default()
    }

    pub fn save(self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, KEY, &self.normalized());
    }

    pub fn apply(self, ctx: &egui::Context) {
        ctx.set_theme(match self.theme {
            ThemeChoice::System => egui::ThemePreference::System,
            ThemeChoice::Light => egui::ThemePreference::Light,
            ThemeChoice::Dark => egui::ThemePreference::Dark,
        });
        ctx.set_zoom_factor(self.size);
    }

    /// Snaps a stored size to the nearest offered one.
    fn normalized(self) -> Self {
        let size = Self::SIZES
            .iter()
            .map(|(s, _)| *s)
            .min_by(|a, b| (a - self.size).abs().total_cmp(&(b - self.size).abs()))
            .unwrap_or(1.0);
        Self { size, ..self }
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
        };
        prefs.save(&mut storage);
        assert_eq!(
            Prefs::load(Some(&storage)),
            Prefs {
                theme: ThemeChoice::Dark,
                size: 1.15
            }
        );
        assert_eq!(storage.0.len(), 1);
        assert_eq!(Prefs::load(None), Prefs::default());
        storage.0.insert(KEY.into(), "not json".into());
        assert_eq!(Prefs::load(Some(&storage)), Prefs::default());
    }
}
