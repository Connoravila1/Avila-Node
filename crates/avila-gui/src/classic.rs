//! The '11 chrome — the way the first client dressed a window: a menu
//! bar nobody reads, a toolbar of raised page tabs, content in the
//! sunken middle, and a status bar along the bottom counting blocks
//! and connections. The rail and the modern status line step aside.

use crate::pages::Action;
use crate::prefs::Prefs;
use crate::rail::{self, Page};
use crate::theme::{self, Palette, font, mono};
use eframe::egui::{
    self, Align, Align2, Color32, CursorIcon, Layout, Painter, Rect, RichText, Sense, Stroke, Ui,
    UiBuilder, pos2, vec2,
};

/// The two raised lines: a menu bar and the page toolbar.
pub const CHROME_H: f32 = 76.0;
/// The status bar's height at the window's foot.
pub const STATUSBAR_H: f32 = 26.0;

/// What the chrome can ask of the app.
pub enum Pick {
    /// Switch the page — the toolbar did it.
    Open(Page),
    /// The File menu's way home.
    Modern,
}

/// A qt-style bevel: raised edges light above and dark below, sunken
/// ones the reverse. Fudged in two strokes, like 2011 did it.
fn bevel(p: &Painter, r: Rect, sunken: bool) {
    let (light, dark) = if sunken {
        (
            Color32::from_rgb(150, 144, 126),
            Color32::from_rgb(252, 251, 246),
        )
    } else {
        (
            Color32::from_rgb(252, 251, 246),
            Color32::from_rgb(150, 144, 126),
        )
    };
    let ls = Stroke::new(1.0, light);
    let ds = Stroke::new(1.0, dark);
    p.hline(r.x_range(), r.top(), ls);
    p.vline(r.left(), r.y_range(), ls);
    p.hline(r.x_range(), r.bottom(), ds);
    p.vline(r.right(), r.y_range(), ds);
}

/// The menu bar — File, Settings, Help, in 2011's own grey.
fn menubar(ui: &mut Ui, prefs: &mut Prefs) -> Option<Pick> {
    let mut pick = None;
    ui.horizontal(|ui| {
        ui.add_space(6.0);
        ui.menu_button("File", |ui| {
            if ui.button("Back to the modern look").clicked() {
                pick = Some(Pick::Modern);
                ui.close();
            }
        });
        ui.menu_button("Settings", |ui| {
            if ui.button("Preferences…").clicked() {
                pick = Some(Pick::Open(Page::Settings));
                ui.close();
            }
            let mut toybox = prefs.toybox;
            if ui
                .selectable_label(toybox, "Toybox")
                .on_hover_text("The games shelf — on when this is ticked")
                .clicked()
            {
                toybox = !toybox;
                prefs.toybox = toybox;
            }
        });
        ui.menu_button("Help", |ui| {
            ui.add_enabled(
                false,
                egui::Button::new("The wallet that started it — 2011"),
            );
        });
        ui.add_space(6.0);
        // The coin mark qt's toolbar carried.
        let (r, _) = ui.allocate_exact_size(vec2(18.0, 18.0), Sense::hover());
        ui.painter()
            .circle_filled(r.center(), 8.0, Color32::from_rgb(228, 186, 74));
        ui.painter().circle_stroke(
            r.center(),
            8.0,
            Stroke::new(1.0, Color32::from_rgb(150, 118, 34)),
        );
        ui.painter().text(
            r.center(),
            Align2::CENTER_CENTER,
            "₿",
            font(theme::MEDIUM, 10.0),
            Color32::from_rgb(96, 72, 16),
        );
        ui.label(
            RichText::new("Bitcoin")
                .font(font(theme::MEDIUM, 12.0))
                .color(Palette::CLASSIC.text),
        );
    });
    pick
}

/// One raised toolbar tab — icon and label, sunken while it's the
/// page you're on.
fn tab(ui: &mut Ui, item: Page, current: Page) -> Option<Pick> {
    let pal = Palette::CLASSIC;
    let (r, resp) = ui.allocate_exact_size(vec2(96.0, 40.0), Sense::click());
    let on = current == item;
    let p = ui.painter_at(r);
    p.rect_filled(r, 0, if on { pal.well } else { pal.canvas });
    if on {
        bevel(&p, r, true);
    } else {
        bevel(&p, r, false);
        if resp.hovered() {
            p.rect_filled(r, 0, Color32::from_white_alpha(18));
        }
    }
    let fg = pal.text;
    rail::icon(&p, item, pos2(r.left() + 20.0, r.center().y), fg, pal.well);
    p.text(
        pos2(r.left() + 38.0, r.center().y),
        Align2::LEFT_CENTER,
        item.label(),
        font(if on { theme::STRONG } else { theme::MEDIUM }, 12.0),
        fg,
    );
    resp.on_hover_cursor(CursorIcon::PointingHand)
        .clicked()
        .then_some(Pick::Open(item))
}

/// The toolbar row of tabs across the top — the first client's
/// navigation.
fn toolbar(ui: &mut Ui, page: &mut Page, toybox: bool) -> Option<Pick> {
    let mut pick = None;
    ui.horizontal(|ui| {
        ui.add_space(4.0);
        for item in Page::ALL {
            if let Some(p) = tab(ui, item, *page) {
                pick = Some(p);
            }
            ui.add_space(2.0);
        }
        if toybox && let Some(p) = tab(ui, Page::Toybox, *page) {
            pick = Some(p);
        }
    });
    pick
}

/// Menu bar and toolbar, one after the other inside the top panel.
pub fn chrome(ui: &mut Ui, page: &mut Page, prefs: &mut Prefs) -> Option<Pick> {
    let rect = ui.max_rect();
    let p = ui.painter().clone();
    // Menu bar strip.
    let menus = Rect::from_min_size(rect.min, vec2(rect.width(), 26.0));
    p.rect_filled(menus, 0, Palette::CLASSIC.well);
    p.hline(
        menus.x_range(),
        menus.bottom(),
        Stroke::new(1.0, Palette::CLASSIC.hairline),
    );
    let mut ui_m = ui.new_child(
        UiBuilder::new()
            .max_rect(menus.shrink2(vec2(4.0, 2.0)))
            .layout(Layout::left_to_right(Align::Center)),
    );
    let mut pick = menubar(&mut ui_m, prefs);
    // Toolbar strip.
    let tools = Rect::from_min_max(menus.left_bottom(), rect.right_bottom());
    p.rect_filled(tools, 0, Palette::CLASSIC.well.gamma_multiply(1.02));
    let mut ui_t = ui.new_child(
        UiBuilder::new()
            .max_rect(tools.shrink2(vec2(4.0, 5.0)))
            .layout(Layout::left_to_right(Align::Center)),
    );
    pick = toolbar(&mut ui_t, page, prefs.toybox).or(pick);
    pick
}

/// A sunken status field — qt's statusBar() widgets in miniature.
fn field(p: &Painter, ui: &mut Ui, w: f32, text: &str, hint: Option<Color32>) -> Rect {
    let (r, _) = ui.allocate_exact_size(vec2(w, STATUSBAR_H - 6.0), Sense::hover());
    p.rect_filled(r, 0, Color32::from_rgb(248, 246, 240));
    bevel(p, r, true);
    p.text(
        r.left_center() + vec2(7.0, 0.0),
        Align2::LEFT_CENTER,
        text,
        mono(11.0),
        hint.unwrap_or(Palette::CLASSIC.text),
    );
    r
}

/// The status bar: phase and counts in sunken fields, like
/// `statusBar()` drew them.
pub fn statusbar(ui: &mut Ui, phase: &str, context: &str, running: bool) -> Option<Action> {
    let rect = ui.max_rect();
    let p = ui.painter().clone();
    p.rect_filled(rect, 0, Palette::CLASSIC.well);
    p.hline(
        rect.x_range(),
        rect.top(),
        Stroke::new(1.0, Palette::CLASSIC.hairline),
    );
    let mut action = None;
    let mut row = ui.new_child(
        UiBuilder::new()
            .max_rect(rect.shrink2(vec2(5.0, 2.0)))
            .layout(Layout::left_to_right(Align::Center)),
    );
    let dot_color = if running {
        Color32::from_rgb(78, 140, 60)
    } else {
        Palette::CLASSIC.faint
    };
    let (d, _) = row.allocate_exact_size(vec2(14.0, 14.0), Sense::hover());
    p.circle_filled(d.center(), 5.0, dot_color);
    p.circle_stroke(d.center(), 5.0, Stroke::new(1.0, Palette::CLASSIC.hairline));
    row.add_space(4.0);
    field(&p, &mut row, 96.0, phase, None);
    row.add_space(3.0);
    // The context line takes what's left, then controls on the right.
    let left_w = row.available_width() - 96.0;
    field(&p, &mut row, left_w.max(80.0), context, None);
    row.add_space(3.0);
    let (b, resp) = row.allocate_exact_size(vec2(90.0, STATUSBAR_H - 6.0), Sense::click());
    p.rect_filled(b, 0, Palette::CLASSIC.raised);
    bevel(&p, b, false);
    p.text(
        b.center(),
        Align2::CENTER_CENTER,
        if running { "Stop node" } else { "Start node" },
        font(theme::MEDIUM, 11.5),
        Palette::CLASSIC.text,
    );
    if resp.on_hover_cursor(CursorIcon::PointingHand).clicked() {
        action = Some(if running { Action::Stop } else { Action::Start });
    }
    action
}
