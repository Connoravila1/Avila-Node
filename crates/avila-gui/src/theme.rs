//! The interface's design tokens — one palette per appearance, one type
//! system, and the egui style both are installed into.
//!
//! Orange carries meaning here, not decoration: it is the color of what
//! this machine has itself verified (and of the brand rail, which is the
//! logo's own field). Everything else is ink on ash.

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Stroke, TextStyle,
    Theme, Visuals,
};
use std::sync::Arc;

/// The logo's orange field, sampled from `assets/avila-node-logo.png`.
pub const SIGNAL: Color32 = Color32::from_rgb(247, 139, 19);
/// The logo's ink — what sits on the orange rail.
pub const INK: Color32 = Color32::from_rgb(22, 20, 15);

/// Named font families (see [`install_fonts`]).
pub const DISPLAY: &str = "display";
pub const TITLE: &str = "title";
pub const MEDIUM: &str = "medium";
pub const STRONG: &str = "strong";
pub const MONO_MEDIUM: &str = "mono-medium";

/// Every surface and text color, resolved for one appearance.
#[derive(Clone, Copy, Debug)]
pub struct Palette {
    pub dark: bool,
    /// The app background.
    pub canvas: Color32,
    /// Lifted surfaces: fields, popups, menus.
    pub raised: Color32,
    /// Recessed wells: tables, sparklines, the ribbon's track.
    pub well: Color32,
    /// Separators.
    pub hairline: Color32,
    pub text: Color32,
    pub muted: Color32,
    pub faint: Color32,
    /// Proven — the brand orange as a fill.
    pub signal: Color32,
    /// Orange that reads as text on this canvas.
    pub signal_text: Color32,
    pub alert: Color32,
}

impl Palette {
    pub const LIGHT: Self = Self {
        dark: false,
        canvas: Color32::from_rgb(236, 237, 239),
        raised: Color32::from_rgb(247, 248, 249),
        well: Color32::from_rgb(225, 227, 230),
        hairline: Color32::from_rgb(205, 208, 213),
        text: Color32::from_rgb(23, 24, 27),
        muted: Color32::from_rgb(92, 98, 108),
        faint: Color32::from_rgb(158, 163, 171),
        signal: SIGNAL,
        signal_text: Color32::from_rgb(168, 83, 0),
        alert: Color32::from_rgb(180, 35, 24),
    };

    pub const DARK: Self = Self {
        dark: true,
        canvas: Color32::from_rgb(19, 20, 22),
        raised: Color32::from_rgb(29, 31, 34),
        well: Color32::from_rgb(26, 28, 31),
        hairline: Color32::from_rgb(44, 47, 52),
        text: Color32::from_rgb(236, 233, 228),
        muted: Color32::from_rgb(146, 152, 162),
        faint: Color32::from_rgb(90, 95, 103),
        signal: SIGNAL,
        signal_text: Color32::from_rgb(249, 160, 63),
        alert: Color32::from_rgb(255, 107, 94),
    };

    /// The palette for whatever appearance `ctx` is currently showing.
    #[must_use]
    pub fn of(ctx: &egui::Context) -> Self {
        if ctx.global_style().visuals.dark_mode {
            Self::DARK
        } else {
            Self::LIGHT
        }
    }

    /// `signal` at a fraction of full strength — assumed state, soft
    /// highlights.
    #[must_use]
    pub fn signal_alpha(&self, alpha: f32) -> Color32 {
        self.signal.gamma_multiply(alpha)
    }
}

/// A font of one of the named families.
#[must_use]
pub fn font(family: &str, size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(family.into()))
}

#[must_use]
pub fn body(size: f32) -> FontId {
    FontId::proportional(size)
}

#[must_use]
pub fn mono(size: f32) -> FontId {
    FontId::monospace(size)
}

/// Jost (display, titles — the wordmark's geometry), Instrument Sans
/// (interface text) and IBM Plex Mono (hashes, heights, bytes). egui's
/// bundled fonts stay behind each as fallback for symbols.
pub fn install_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    let faces: [(&str, &'static [u8]); 7] = [
        (
            "jost-light",
            include_bytes!("../assets/fonts/Jost-Light.ttf"),
        ),
        (
            "jost-regular",
            include_bytes!("../assets/fonts/Jost-Regular.ttf"),
        ),
        (
            "instrument-regular",
            include_bytes!("../assets/fonts/InstrumentSans-Regular.ttf"),
        ),
        (
            "instrument-medium",
            include_bytes!("../assets/fonts/InstrumentSans-Medium.ttf"),
        ),
        (
            "instrument-semibold",
            include_bytes!("../assets/fonts/InstrumentSans-SemiBold.ttf"),
        ),
        (
            "plex-mono",
            include_bytes!("../assets/fonts/IBMPlexMono-Regular.ttf"),
        ),
        (
            "plex-mono-medium",
            include_bytes!("../assets/fonts/IBMPlexMono-Medium.ttf"),
        ),
    ];
    for (name, bytes) in faces {
        fonts
            .font_data
            .insert(name.to_owned(), Arc::new(FontData::from_static(bytes)));
    }
    let proportional_fallback = fonts
        .families
        .get(&FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    let mono_fallback = fonts
        .families
        .get(&FontFamily::Monospace)
        .cloned()
        .unwrap_or_default();
    let chain = |first: &str, rest: &[String]| {
        let mut v = vec![first.to_owned()];
        v.extend(rest.iter().cloned());
        v
    };
    fonts.families.insert(
        FontFamily::Proportional,
        chain("instrument-regular", &proportional_fallback),
    );
    fonts
        .families
        .insert(FontFamily::Monospace, chain("plex-mono", &mono_fallback));
    for (family, face) in [
        (DISPLAY, "jost-light"),
        (TITLE, "jost-regular"),
        (MEDIUM, "instrument-medium"),
        (STRONG, "instrument-semibold"),
    ] {
        fonts.families.insert(
            FontFamily::Name(family.into()),
            chain(face, &proportional_fallback),
        );
    }
    fonts.families.insert(
        FontFamily::Name(MONO_MEDIUM.into()),
        chain("plex-mono-medium", &mono_fallback),
    );
    ctx.set_fonts(fonts);
}

/// Installs both appearances into egui's own visuals, so native widgets
/// (fields, menus, tooltips, scroll bars) follow the palette too.
pub fn install_style(ctx: &egui::Context) {
    for (theme, pal) in [(Theme::Light, Palette::LIGHT), (Theme::Dark, Palette::DARK)] {
        ctx.set_visuals_of(theme, visuals(&pal));
        ctx.style_mut_of(theme, |style| {
            use TextStyle as T;
            style.text_styles = [
                (T::Small, body(11.5)),
                (T::Body, body(14.0)),
                (T::Button, font(MEDIUM, 13.5)),
                (T::Monospace, mono(13.0)),
                (T::Heading, font(TITLE, 22.0)),
            ]
            .into();
            let s = &mut style.spacing;
            s.item_spacing = egui::vec2(10.0, 8.0);
            s.button_padding = egui::vec2(12.0, 6.0);
            s.interact_size = egui::vec2(40.0, 30.0);
            s.window_margin = egui::Margin::same(14);
            s.menu_margin = egui::Margin::same(8);
            s.scroll = egui::style::ScrollStyle::floating();
        });
    }
}

fn visuals(pal: &Palette) -> Visuals {
    let mut v = if pal.dark {
        Visuals::dark()
    } else {
        Visuals::light()
    };
    v.panel_fill = pal.canvas;
    v.window_fill = pal.raised;
    v.window_stroke = Stroke::new(1.0, pal.hairline);
    v.extreme_bg_color = pal.raised;
    v.faint_bg_color = pal.well;
    v.code_bg_color = pal.well;
    v.override_text_color = Some(pal.text);
    v.hyperlink_color = pal.signal_text;
    v.warn_fg_color = pal.signal_text;
    v.error_fg_color = pal.alert;
    v.selection.bg_fill = pal.signal_alpha(if pal.dark { 0.38 } else { 0.30 });
    v.selection.stroke = Stroke::new(1.0, pal.text);
    v.window_corner_radius = CornerRadius::same(10);
    v.menu_corner_radius = CornerRadius::same(8);

    let hover = if pal.dark {
        Color32::from_rgb(38, 41, 45)
    } else {
        Color32::from_rgb(214, 217, 221)
    };
    let w = &mut v.widgets;
    for (state, fill, stroke) in [
        (
            &mut w.noninteractive,
            pal.canvas,
            Stroke::new(1.0, pal.hairline),
        ),
        (&mut w.inactive, pal.well, Stroke::NONE),
        (&mut w.hovered, hover, Stroke::new(1.0, pal.faint)),
        (&mut w.active, pal.hairline, Stroke::new(1.0, pal.muted)),
        (&mut w.open, hover, Stroke::new(1.0, pal.faint)),
    ] {
        state.bg_fill = fill;
        state.weak_bg_fill = fill;
        state.bg_stroke = stroke;
        state.fg_stroke = Stroke::new(1.0, pal.text);
        state.corner_radius = CornerRadius::same(6);
        state.expansion = 0.0;
    }
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, pal.text);
    v
}
