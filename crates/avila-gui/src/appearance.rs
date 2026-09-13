use clap::ValueEnum;
use eframe::egui::{self, Color32};
use serde::{Deserialize, Serialize};

const STORAGE_KEY: &str = "avila_appearance_v1";

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum AppearanceMode {
    Light,
    #[default]
    Dark,
    Black,
}

impl AppearanceMode {
    pub const ALL: [Self; 3] = [Self::Light, Self::Dark, Self::Black];

    pub fn label(self) -> &'static str {
        match self {
            Self::Light => "Light",
            Self::Dark => "Dark",
            Self::Black => "Black",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Light => "Light surfaces with dark text.",
            Self::Dark => "Charcoal surfaces with light text.",
            Self::Black => "Pure black backgrounds with light text.",
        }
    }

    fn base_theme(self) -> egui::Theme {
        match self {
            Self::Light => egui::Theme::Light,
            Self::Dark | Self::Black => egui::Theme::Dark,
        }
    }

    fn visuals(self) -> egui::Visuals {
        let mut visuals = match self {
            Self::Light => egui::Visuals::light(),
            Self::Dark | Self::Black => egui::Visuals::dark(),
        };
        visuals.selection.bg_fill = Color32::from_rgb(135, 74, 6);
        visuals.selection.stroke = egui::Stroke::new(1.0, Color32::WHITE);
        visuals.hyperlink_color = self.accent();
        if self == Self::Black {
            visuals.panel_fill = Color32::BLACK;
            visuals.window_fill = Color32::BLACK;
            visuals.extreme_bg_color = Color32::BLACK;
            visuals.faint_bg_color = Color32::from_gray(8);
            visuals.widgets.noninteractive.bg_fill = Color32::BLACK;
            visuals.widgets.noninteractive.weak_bg_fill = Color32::BLACK;
        }
        visuals
    }

    pub fn accent(self) -> Color32 {
        match self {
            Self::Light => Color32::from_rgb(145, 74, 0),
            Self::Dark | Self::Black => Color32::from_rgb(247, 147, 26),
        }
    }
}

/// Only presentation preferences belong in this record. Never include node data.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppearanceConfig {
    pub theme: AppearanceMode,
    pub scale: f32,
}

impl Default for AppearanceConfig {
    fn default() -> Self {
        Self {
            theme: AppearanceMode::Dark,
            scale: 1.0,
        }
    }
}

impl AppearanceConfig {
    pub fn load(storage: Option<&dyn eframe::Storage>) -> Self {
        storage
            .and_then(|storage| eframe::get_value::<Self>(storage, STORAGE_KEY))
            .map(Self::normalized)
            .unwrap_or_default()
    }

    fn normalized(mut self) -> Self {
        self.scale = if self.scale.is_finite() {
            self.scale.clamp(0.75, 2.0)
        } else {
            1.0
        };
        self
    }

    pub fn apply(self, ctx: &egui::Context) {
        ctx.set_visuals_of(self.theme.base_theme(), self.theme.visuals());
        ctx.set_theme(match self.theme {
            AppearanceMode::Light => egui::ThemePreference::Light,
            AppearanceMode::Dark | AppearanceMode::Black => egui::ThemePreference::Dark,
        });
        ctx.set_zoom_factor(self.normalized().scale);
        ctx.request_repaint();
    }

    pub fn save(self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, STORAGE_KEY, &self.normalized());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct Storage(BTreeMap<String, String>);

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
    fn appearance_survives_restart_without_saving_node_or_search_state() {
        for theme in AppearanceMode::ALL {
            let mut storage = Storage::default();
            let settings = AppearanceConfig { theme, scale: 1.5 };
            settings.save(&mut storage);
            assert_eq!(AppearanceConfig::load(Some(&storage)), settings);
            assert_eq!(storage.0.len(), 1);
            assert!(storage.0.contains_key(STORAGE_KEY));
        }
    }

    #[test]
    fn invalid_preferences_cannot_make_the_interface_unusable() {
        let mut storage = Storage::default();
        storage
            .0
            .insert(STORAGE_KEY.into(), "corrupt preferences".into());
        assert_eq!(
            AppearanceConfig::load(Some(&storage)),
            AppearanceConfig::default()
        );
        for (scale, expected) in [
            (f32::NAN, 1.0),
            (f32::INFINITY, 1.0),
            (0.0, 0.75),
            (8.0, 2.0),
        ] {
            eframe::set_value(
                &mut storage,
                STORAGE_KEY,
                &AppearanceConfig {
                    scale,
                    ..Default::default()
                },
            );
            assert_eq!(AppearanceConfig::load(Some(&storage)).scale, expected);
        }
    }
}
