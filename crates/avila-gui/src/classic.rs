//! Bitcoin 0.1's wxWidgets window, with its original masked bitmaps.
//! Geometry follows trottier/original-bitcoin's uibase.cpp and ui.cpp.
//! Avila's pages and node actions live in one additional menu.

use crate::model::{span, thousands};
use crate::pages::{Action, Scene};
use crate::prefs::Prefs;
use crate::rail::Page;
use crate::theme;
use eframe::egui::{
    self, Align, Align2, Color32, ColorImage, CornerRadius, FontId, Id, Layout, Mesh, Painter,
    Rect, Response, ScrollArea, Sense, Shape, Stroke, StrokeKind, TextureHandle, TextureOptions,
    Ui, UiBuilder, ViewportCommand, pos2, vec2,
};

pub const CHROME_H: f32 = 82.0;
pub const STATUSBAR_H: f32 = 23.0;
const FRAME: f32 = 3.0;
const TITLE_H: f32 = 27.0;
const MENU_H: f32 = 21.0;
const TOOL_H: f32 = 30.0;
const FACE: Color32 = Color32::from_rgb(224, 223, 227);
const MENU: Color32 = Color32::from_rgb(239, 238, 242);
const LIGHT: Color32 = Color32::WHITE;
const SHADOW: Color32 = Color32::from_rgb(157, 157, 161);
const DARK: Color32 = Color32::from_rgb(113, 111, 128);
const EDGE: Color32 = Color32::from_rgb(127, 157, 185);
const SELECT: Color32 = Color32::from_rgb(49, 106, 197);
const TEXT: Color32 = Color32::BLACK;
const UV: Rect = Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0));

pub enum Pick {
    Open(Page),
    Modern,
    Node(Action),
}

fn font() -> FontId {
    theme::font(theme::CLASSIC_UI, 11.0)
}

pub fn window_icon() -> Option<std::sync::Arc<egui::IconData>> {
    eframe::icon_data::from_png_bytes(include_bytes!("../assets/original-bitcoin/bitcoin48.png"))
        .ok()
        .map(std::sync::Arc::new)
}

/// A real rendered window in miniature, using the same bitmap loader.
pub fn preview(p: &Painter, r: Rect) {
    let texture = image(
        p.ctx(),
        "bitcoin-client-preview",
        include_bytes!("../assets/original-bitcoin/client-preview.png"),
    );
    let aspect = texture.size()[0] as f32 / texture.size()[1] as f32;
    let h = (r.width() / aspect).min(r.height());
    p.rect_filled(r, 8, FACE);
    p.image(
        texture.id(),
        Rect::from_center_size(r.center(), vec2(h * aspect, h)),
        UV,
        LIGHT,
    );
}

fn line(p: &Painter, r: Rect, top: Color32, bottom: Color32) {
    let r = r.shrink(0.5);
    p.line_segment([r.left_bottom(), r.left_top()], Stroke::new(1.0, top));
    p.line_segment([r.left_top(), r.right_top()], Stroke::new(1.0, top));
    p.line_segment([r.right_top(), r.right_bottom()], Stroke::new(1.0, bottom));
    p.line_segment(
        [r.right_bottom(), r.left_bottom()],
        Stroke::new(1.0, bottom),
    );
}

fn bevel(p: &Painter, r: Rect, sunken: bool) {
    if sunken {
        line(p, r, SHADOW, LIGHT);
        line(p, r.shrink(1.0), DARK, FACE);
    } else {
        line(p, r, LIGHT, DARK);
        line(p, r.shrink(1.0), FACE, SHADOW);
    }
}

/// Native control surfaces, following XP's Silver window theme.
fn shade(p: &Painter, r: Rect, top: Color32, bottom: Color32) {
    let mut mesh = Mesh::default();
    mesh.colored_vertex(r.left_top(), top);
    mesh.colored_vertex(r.right_top(), top);
    mesh.colored_vertex(r.right_bottom(), bottom);
    mesh.colored_vertex(r.left_bottom(), bottom);
    mesh.add_triangle(0, 1, 2);
    mesh.add_triangle(0, 2, 3);
    p.add(Shape::mesh(mesh));
}

fn image(ctx: &egui::Context, name: &'static str, bytes: &'static [u8]) -> TextureHandle {
    let id = Id::new(("bitcoin-0.1-image", name));
    if let Some(texture) = ctx.data_mut(|d| d.get_temp::<TextureHandle>(id)) {
        return texture;
    }
    let icon = eframe::icon_data::from_png_bytes(bytes).unwrap_or(egui::IconData {
        rgba: vec![0; 4],
        width: 1,
        height: 1,
    });
    let texture = ctx.load_texture(
        name,
        ColorImage::from_rgba_unmultiplied([icon.width as usize, icon.height as usize], &icon.rgba),
        TextureOptions::NEAREST,
    );
    ctx.data_mut(|d| d.insert_temp(id, texture.clone()));
    texture
}

fn titlebar(ui: &mut Ui, r: Rect, page: Page, demo: bool) {
    let p = ui.painter().clone();
    let upper = Rect::from_min_max(r.min, pos2(r.right(), r.top() + 8.0));
    shade(
        &p,
        upper,
        Color32::from_rgb(174, 173, 194),
        Color32::from_rgb(215, 215, 226),
    );
    shade(
        &p,
        Rect::from_min_max(upper.left_bottom(), r.max),
        Color32::from_rgb(215, 215, 226),
        LIGHT,
    );
    p.hline(r.x_range(), r.bottom() - 1.5, Stroke::new(1.0, DARK));
    let icon = image(
        ui.ctx(),
        "bitcoin16",
        include_bytes!("../assets/original-bitcoin/bitcoin16.png"),
    );
    p.image(
        icon.id(),
        Rect::from_min_size(r.min + vec2(5.0, 5.0), vec2(16.0, 16.0)),
        UV,
        LIGHT,
    );
    let title = if page == Page::Overview {
        "Bitcoin".to_owned()
    } else {
        format!("Bitcoin - {}", page.label())
    };
    let title = if demo {
        format!("{title} (simulated)")
    } else {
        title
    };
    p.text(
        r.left_center() + vec2(25.0, -1.0),
        Align2::LEFT_CENTER,
        title,
        theme::font(theme::CAPTION, 13.0),
        TEXT,
    );
    let drag = Rect::from_min_max(r.min, pos2(r.right() - 77.0, r.bottom()));
    let resp = ui.interact(drag, ui.id().with("bitcoin-title"), Sense::click_and_drag());
    let maximized = ui.input(|i| i.viewport().maximized.unwrap_or(false));
    if resp.double_clicked() {
        ui.ctx()
            .send_viewport_cmd(ViewportCommand::Maximized(!maximized));
    } else if resp.drag_started() {
        ui.ctx().send_viewport_cmd(ViewportCommand::StartDrag);
    }
    for (i, help) in ["Minimize", "Maximize / restore", "Close"]
        .into_iter()
        .enumerate()
    {
        let b = Rect::from_min_size(
            pos2(r.right() - 74.0 + i as f32 * 24.0, r.top() + 3.0),
            vec2(22.0, 21.0),
        );
        let response = ui
            .interact(b, ui.id().with(("bitcoin-caption", i)), Sense::click())
            .on_hover_text(help);
        response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, help));
        let close = i == 2;
        let (top, bottom) = if close {
            (
                Color32::from_rgb(238, 173, 153),
                Color32::from_rgb(185, 45, 35),
            )
        } else {
            (
                Color32::from_rgb(247, 247, 252),
                Color32::from_rgb(155, 153, 177),
            )
        };
        shade(&p, b, top, bottom);
        if response.is_pointer_button_down_on() {
            p.rect_filled(b, 2, Color32::from_black_alpha(30));
        } else if response.hovered() {
            p.rect_filled(b, 2, Color32::from_white_alpha(40));
        }
        p.rect_stroke(b, 2, Stroke::new(1.0, DARK), StrokeKind::Inside);
        p.rect_stroke(
            b.shrink(1.0),
            1,
            Stroke::new(1.0, LIGHT),
            StrokeKind::Inside,
        );
        let c = b.center();
        let ink = if close {
            LIGHT
        } else {
            Color32::from_rgb(59, 58, 75)
        };
        match i {
            0 => {
                p.line_segment(
                    [c + vec2(-5.0, 4.0), c + vec2(2.0, 4.0)],
                    Stroke::new(2.0, ink),
                );
            }
            1 => {
                if maximized {
                    let back = Rect::from_center_size(c + vec2(2.0, -2.0), vec2(9.0, 8.0));
                    p.rect_stroke(back, 0, Stroke::new(1.0, ink), StrokeKind::Inside);
                    p.hline(back.x_range(), back.top() + 1.0, Stroke::new(2.0, ink));
                    let front = back.translate(vec2(-3.0, 3.0));
                    p.rect_filled(front, 0, bottom);
                    p.rect_stroke(front, 0, Stroke::new(1.0, ink), StrokeKind::Inside);
                    p.hline(front.x_range(), front.top() + 1.0, Stroke::new(2.0, ink));
                } else {
                    let box_r = Rect::from_center_size(c, vec2(11.0, 10.0));
                    p.rect_stroke(box_r, 0, Stroke::new(1.0, ink), StrokeKind::Inside);
                    p.hline(box_r.x_range(), box_r.top() + 1.0, Stroke::new(2.0, ink));
                }
            }
            _ => {
                p.line_segment(
                    [c + vec2(-4.0, -4.0), c + vec2(4.0, 4.0)],
                    Stroke::new(2.0, ink),
                );
                p.line_segment(
                    [c + vec2(4.0, -4.0), c + vec2(-4.0, 4.0)],
                    Stroke::new(2.0, ink),
                );
            }
        }
        if response.clicked() {
            ui.ctx().send_viewport_cmd(match i {
                0 => ViewportCommand::Minimized(true),
                1 => ViewportCommand::Maximized(!maximized),
                _ => ViewportCommand::Close,
            });
        }
    }
}

fn menubar(
    ui: &mut Ui,
    page: Page,
    prefs: &mut Prefs,
    running: bool,
    tip: Option<&str>,
) -> Option<Pick> {
    let mut pick = None;
    ui.spacing_mut().item_spacing.x = 0.0;
    ui.spacing_mut().button_padding = vec2(6.0, 2.0);
    ui.spacing_mut().interact_size = vec2(0.0, 19.0);
    ui.horizontal(|ui| {
        ui.menu_button("File", |ui| {
            if ui.button("Exit").clicked() { ui.ctx().send_viewport_cmd(ViewportCommand::Close); }
        });
        ui.menu_button("Options", |ui| {
            ui.add_enabled(false, egui::Button::new("Generate Coins"))
                .on_disabled_hover_text("The original client's CPU miner. Avila validates Bitcoin; it has no wallet miner.");
            if ui.button("Options...").clicked() { pick = Some(Pick::Open(Page::Settings)); ui.close(); }
        });
        ui.menu_button("Help", |ui| {
            if ui.button("About...").clicked() {
                ui.ctx().data_mut(|d| d.insert_temp(Id::new("bitcoin-0.1-about"), true));
                ui.close();
            }
        });
        // The original toolbar remains two tools. Our additions fit in
        // a menu instead of displacing the original's main controls.
        ui.menu_button("Node", |ui| {
            if ui.button(if running { "Stop node" } else { "Start node" }).clicked() {
                pick = Some(Pick::Node(if running { Action::Stop } else { Action::Start }));
                ui.close();
            }
            if ui.add_enabled(tip.is_some(), egui::Button::new("Copy chain tip")).clicked() {
                if let Some(tip) = tip { ui.ctx().copy_text(tip.to_owned()); }
                ui.close();
            }
            ui.separator();
            for item in Page::ALL.into_iter().chain(prefs.toybox.then_some(Page::Toybox)) {
                if ui.selectable_label(page == item, item.label()).clicked() {
                    pick = Some(Pick::Open(item)); ui.close();
                }
            }
            ui.separator();
            ui.checkbox(&mut prefs.toybox, "Toybox");
            ui.checkbox(&mut prefs.hide_addresses, "Hide addresses");
            if ui.button("Back to the modern look").clicked() { pick = Some(Pick::Modern); ui.close(); }
        });
    });
    pick
}

fn tool(ui: &mut Ui, name: &'static str, bytes: &'static [u8], label: &str, width: f32) {
    let (r, resp) = ui.allocate_exact_size(vec2(width, 26.0), Sense::hover());
    let texture = image(ui.ctx(), name, bytes);
    let p = ui.painter();
    p.image(
        texture.id(),
        Rect::from_min_size(r.min + vec2(2.0, 3.0), vec2(20.0, 20.0)),
        UV,
        LIGHT,
    );
    p.text(
        r.left_center() + vec2(27.0, 0.0),
        Align2::LEFT_CENTER,
        label,
        font(),
        TEXT,
    );
    resp.on_hover_text(
        "This is the original Bitcoin wallet control. Avila Node does not hold or send coins.",
    );
}

pub fn chrome(
    ui: &mut Ui,
    page: Page,
    prefs: &mut Prefs,
    running: bool,
    demo: bool,
    tip: Option<&str>,
) -> Option<Pick> {
    let r = ui.max_rect();
    let p = ui.painter().clone();
    p.rect_filled(r, 0, FACE);
    bevel(&p, r, false);
    let title = Rect::from_min_size(
        r.min + vec2(FRAME, FRAME),
        vec2(r.width() - 2.0 * FRAME, TITLE_H),
    );
    titlebar(ui, title, page, demo);
    let menus = Rect::from_min_size(title.left_bottom(), vec2(title.width(), MENU_H));
    p.rect_filled(menus, 0, MENU);
    p.hline(
        menus.x_range(),
        menus.bottom() - 1.5,
        Stroke::new(1.0, SHADOW),
    );
    p.hline(
        menus.x_range(),
        menus.bottom() - 0.5,
        Stroke::new(1.0, LIGHT),
    );
    let mut menu_ui = ui.new_child(
        UiBuilder::new()
            .max_rect(menus.shrink2(vec2(2.0, 0.0)))
            .layout(Layout::left_to_right(Align::Center)),
    );
    menu_ui.visuals_mut().widgets.inactive.bg_stroke = Stroke::NONE;
    let pick = menubar(&mut menu_ui, page, prefs, running, tip);
    let tools = Rect::from_min_size(menus.left_bottom(), vec2(menus.width(), TOOL_H));
    let mut tool_ui = ui.new_child(
        UiBuilder::new()
            .max_rect(tools.shrink2(vec2(2.0, 1.0)))
            .layout(Layout::left_to_right(Align::Center)),
    );
    tool_ui.spacing_mut().item_spacing.x = 1.0;
    tool(
        &mut tool_ui,
        "send20",
        include_bytes!("../assets/original-bitcoin/send20.png"),
        "Send Coins",
        102.0,
    );
    tool(
        &mut tool_ui,
        "addressbook20",
        include_bytes!("../assets/original-bitcoin/addressbook20.png"),
        "Address Book",
        119.0,
    );

    let id = Id::new("bitcoin-0.1-about");
    let mut about = ui
        .ctx()
        .data_mut(|d| d.get_temp::<bool>(id))
        .unwrap_or(false);
    egui::Window::new("About Bitcoin").open(&mut about).collapsible(false).resizable(false).show(ui.ctx(), |ui| {
        ui.label("Original Bitcoin client appearance");
        ui.label("Bitcoin version 0.1.0 Alpha, 2009 Satoshi Nakamoto");
        ui.separator();
        ui.label("This window runs Avila Node. Its validation and node services are unchanged by the skin.");
        ui.hyperlink_to("Original Bitcoin source", "https://github.com/trottier/original-bitcoin");
    });
    ui.ctx().data_mut(|d| d.insert_temp(id, about));
    pick
}

/// Three fields, using the original 81px and 286px right fields.
/// The first carries Avila's phase; the miner's field stays empty.
pub fn statusbar(ui: &mut Ui, phase: &str, stats: Option<(u32, usize, usize)>, demo: bool) {
    let r = ui.max_rect();
    let p = ui.painter();
    p.rect_filled(r, 0, MENU);
    line(p, r, SHADOW, DARK);
    let right = r.right() - FRAME - 14.0;
    let counts = Rect::from_min_max(
        pos2((right - 286.0).max(r.left() + FRAME), r.top() + 2.0),
        pos2(right, r.bottom() - FRAME),
    );
    let generate = Rect::from_min_max(
        pos2((counts.left() - 81.0).max(r.left() + FRAME), counts.top()),
        counts.left_bottom(),
    );
    let status = Rect::from_min_max(pos2(r.left() + FRAME, counts.top()), generate.left_bottom());
    for field in [status, generate, counts] {
        line(p, field, SHADOW, LIGHT);
    }
    p.with_clip_rect(status.shrink(2.0)).text(
        status.left_center() + vec2(5.0, 0.0),
        Align2::LEFT_CENTER,
        if demo {
            format!("Simulated data - {phase}")
        } else {
            phase.to_owned()
        },
        font(),
        TEXT,
    );
    let summary = stats
        .map(|(blocks, peers, txs)| {
            format!("{peers} connections     {blocks} blocks     {txs} transactions")
        })
        .unwrap_or_else(|| "- connections     - blocks     - transactions".to_owned());
    p.with_clip_rect(counts.shrink(2.0)).text(
        counts.right_center() - vec2(5.0, 0.0),
        Align2::RIGHT_CENTER,
        summary,
        font(),
        TEXT,
    );
    for i in 0..3 {
        let d = i as f32 * 4.0;
        p.line_segment(
            [
                pos2(r.right() - 4.0 - d, r.bottom() - 4.0),
                pos2(r.right() - 4.0, r.bottom() - 4.0 - d),
            ],
            Stroke::new(1.0, SHADOW),
        );
    }
}

/// The notebook frame surrounds the list alone, never the whole page.
pub fn content_frame(p: &Painter, r: Rect) {
    p.rect_filled(r, 0, FACE);
    p.vline(r.left() + 0.5, r.y_range(), Stroke::new(1.0, DARK));
    p.vline(r.right() - 0.5, r.y_range(), Stroke::new(1.0, DARK));
}

/// Keep the original window resizable after replacing the OS decorations.
pub fn resize_frame(ui: &mut Ui) {
    use egui::viewport::ResizeDirection as D;
    if ui.input(|i| i.viewport().maximized.unwrap_or(false)) {
        return;
    }
    let r = ui.ctx().content_rect();
    let g = 5.0;
    let handles = [
        (
            Rect::from_min_size(r.min, vec2(g, g)),
            D::NorthWest,
            egui::CursorIcon::ResizeNwSe,
        ),
        (
            Rect::from_min_size(r.right_top() - vec2(g, 0.0), vec2(g, g)),
            D::NorthEast,
            egui::CursorIcon::ResizeNeSw,
        ),
        (
            Rect::from_min_size(r.left_bottom() - vec2(0.0, g), vec2(g, g)),
            D::SouthWest,
            egui::CursorIcon::ResizeNeSw,
        ),
        (
            Rect::from_min_size(r.max - vec2(g, g), vec2(g, g)),
            D::SouthEast,
            egui::CursorIcon::ResizeNwSe,
        ),
        (
            Rect::from_min_max(r.min + vec2(g, 0.0), r.right_top() + vec2(-g, FRAME)),
            D::North,
            egui::CursorIcon::ResizeVertical,
        ),
        (
            Rect::from_min_max(r.left_bottom() + vec2(g, -FRAME), r.max - vec2(g, 0.0)),
            D::South,
            egui::CursorIcon::ResizeVertical,
        ),
        (
            Rect::from_min_max(r.min + vec2(0.0, g), r.left_bottom() + vec2(FRAME, -g)),
            D::West,
            egui::CursorIcon::ResizeHorizontal,
        ),
        (
            Rect::from_min_max(r.right_top() + vec2(-FRAME, g), r.max - vec2(0.0, g)),
            D::East,
            egui::CursorIcon::ResizeHorizontal,
        ),
    ];
    for (i, (rect, direction, cursor)) in handles.into_iter().enumerate() {
        let response = ui
            .interact(rect, Id::new(("bitcoin-resize", i)), Sense::drag())
            .on_hover_cursor(cursor);
        if response.drag_started() {
            ui.ctx()
                .send_viewport_cmd(ViewportCommand::BeginResize(direction));
        }
    }
}

fn button(ui: &mut Ui, r: Rect, id: &str, label: &str, enabled: bool) -> Response {
    let response = ui.interact(
        r,
        ui.id().with(id),
        if enabled {
            Sense::click()
        } else {
            Sense::hover()
        },
    );
    let p = ui.painter();
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, enabled, label));
    p.rect_filled(r, 2, MENU);
    p.rect_stroke(
        r,
        2,
        Stroke::new(
            1.0,
            if response.hovered() && enabled {
                SELECT
            } else {
                SHADOW
            },
        ),
        StrokeKind::Inside,
    );
    line(p, r.shrink(1.0), LIGHT, FACE);
    p.text(
        r.center()
            + if response.is_pointer_button_down_on() {
                vec2(1.0, 1.0)
            } else {
                vec2(0.0, 0.0)
            },
        Align2::CENTER_CENTER,
        label,
        font(),
        if enabled { TEXT } else { SHADOW },
    );
    response
}

/// The original wallet surface is read-only. The additional Recent
/// Blocks tab keeps the existing tip-copy and block-list functionality.
pub fn overview(ui: &mut Ui, s: &Scene) {
    let r = ui.available_rect_before_wrap();
    let p = ui.painter().clone();
    let view = s.session.view.as_ref();
    let tip = view
        .and_then(|v| v.recent.last())
        .map(|(_, hash)| hash.as_str());
    let tab_id = ui.id().with("bitcoin-notebook");
    let mut blocks = ui
        .ctx()
        .data_mut(|d| d.get_temp::<bool>(tab_id))
        .unwrap_or(false);
    let row_y = r.top() + 2.0;
    p.text(
        pos2(r.left() + 10.0, row_y + 12.0),
        Align2::LEFT_CENTER,
        if blocks {
            "Chain tip:"
        } else {
            "Your Bitcoin Address:"
        },
        font(),
        TEXT,
    );
    let field = Rect::from_min_size(pos2(r.left() + 124.0, row_y + 2.0), vec2(250.0, 21.0));
    p.rect_filled(field, 0, MENU);
    bevel(&p, field, true);
    if blocks {
        p.with_clip_rect(field.shrink(3.0)).text(
            field.left_center() + vec2(4.0, 0.0),
            Align2::LEFT_CENTER,
            tip.unwrap_or(""),
            font(),
            TEXT,
        );
    }
    let wallet_note = "The original client's wallet controls. Avila Node has no wallet; use Recent Blocks for node data.";
    ui.interact(field, ui.id().with("original-address"), Sense::hover())
        .on_hover_text(if blocks {
            "The validated Bitcoin chain tip."
        } else {
            wallet_note
        });
    let copy = button(
        ui,
        Rect::from_min_size(pos2(field.right() + 5.0, row_y), vec2(103.0, 24.0)),
        "copy-tip",
        "Copy to Clipboard",
        blocks && tip.is_some(),
    );
    if copy.clicked()
        && let Some(tip) = tip
    {
        ui.ctx().copy_text(tip.to_owned());
    }
    if !blocks {
        copy.on_hover_text(wallet_note);
    }
    button(
        ui,
        Rect::from_min_size(pos2(field.right() + 113.0, row_y), vec2(75.0, 24.0)),
        "change-tip",
        "Change...",
        false,
    )
    .on_hover_text(if blocks {
        "The validated chain selects the tip; it cannot be changed here."
    } else {
        wallet_note
    });
    let summary_y = row_y + 40.0;
    p.text(
        pos2(r.left() + 10.0, summary_y),
        Align2::LEFT_CENTER,
        if blocks { "Blocks:" } else { "Balance:" },
        font(),
        TEXT,
    );
    let balance = Rect::from_center_size(pos2(r.left() + 121.0, summary_y), vec2(120.0, 15.0));
    p.rect_filled(balance, 0, Color32::from_rgb(240, 240, 240));
    let value = if blocks {
        view.map(|v| thousands(u64::from(v.connected)))
            .unwrap_or_default()
    } else {
        String::new()
    };
    p.text(
        balance.right_center() - vec2(7.0, 0.0),
        Align2::RIGHT_CENTER,
        value,
        font(),
        TEXT,
    );
    if !blocks {
        ui.interact(balance, ui.id().with("original-balance"), Sense::hover())
            .on_hover_text(wallet_note);
    }

    let notebook = Rect::from_min_max(
        pos2(r.left() + FRAME, row_y + 59.0),
        pos2(r.right() - FRAME, r.bottom()),
    );
    let tab_h = 23.0;
    let body = Rect::from_min_max(notebook.min + vec2(0.0, tab_h - 1.0), notebook.max);
    p.rect_filled(body, 0, MENU);
    bevel(&p, body, false);
    let mut x = notebook.left();
    for (is_blocks, label, width) in [
        (false, "All Transactions", 110.0),
        (true, "Recent Blocks", 99.0),
    ] {
        let on = blocks == is_blocks;
        let tab = Rect::from_min_size(
            pos2(x, notebook.top() + if on { 0.0 } else { 2.0 }),
            vec2(width, tab_h - if on { 0.0 } else { 2.0 }),
        );
        let response = ui.interact(tab, tab_id.with(is_blocks), Sense::click());
        response.widget_info(|| {
            egui::WidgetInfo::selected(egui::WidgetType::SelectableLabel, true, on, label)
        });
        if response.clicked() {
            blocks = is_blocks;
        }
        p.rect_filled(
            tab,
            CornerRadius {
                nw: 3,
                ne: 3,
                sw: 0,
                se: 0,
            },
            if on { MENU } else { FACE },
        );
        p.rect_stroke(tab, 2, Stroke::new(1.0, SHADOW), StrokeKind::Inside);
        if on {
            p.hline(
                tab.left() + 2.0..=tab.right() - 2.0,
                tab.top() + 1.5,
                Stroke::new(3.0, Color32::from_rgb(255, 194, 73)),
            );
            p.hline(
                tab.left() + 1.0..=tab.right() - 1.0,
                tab.bottom() - 0.5,
                Stroke::new(2.0, MENU),
            );
        }
        p.text(
            tab.center() + vec2(0.0, 1.0),
            Align2::CENTER_CENTER,
            label,
            font(),
            TEXT,
        );
        x += width;
    }
    ui.ctx().data_mut(|d| d.insert_temp(tab_id, blocks));

    let list = Rect::from_min_max(body.min + vec2(5.0, 6.0), body.max - vec2(5.0, 5.0));
    p.rect_filled(list, 0, LIGHT);
    p.rect_stroke(list, 0, Stroke::new(1.0, EDGE), StrokeKind::Inside);
    let head = Rect::from_min_size(list.min + vec2(2.0, 2.0), vec2(list.width() - 4.0, 20.0));
    shade(&p, head, LIGHT, FACE);
    p.hline(
        head.x_range(),
        head.bottom() - 0.5,
        Stroke::new(1.0, SHADOW),
    );
    let columns: &[(f32, f32, &str, bool)] = if blocks {
        &[
            (0.0, 90.0, "Status", false),
            (90.0, 90.0, "Block", false),
            (180.0, 105.0, "Received", false),
            (285.0, head.width() - 285.0, "Hash", false),
        ]
    } else {
        // ui.cpp: Status 90; date string length * 6 + 8; Description
        // 409 - date width; Debit and Credit 79 each.
        &[
            (0.0, 90.0, "Status", false),
            (90.0, 104.0, "Date", false),
            (194.0, 305.0, "Description", false),
            (499.0, 79.0, "Debit", true),
            (578.0, 79.0, "Credit", true),
        ]
    };
    for &(x, width, label, right) in columns {
        p.text(
            pos2(
                head.left() + x + if right { width - 6.0 } else { 6.0 },
                head.center().y,
            ),
            if right {
                Align2::RIGHT_CENTER
            } else {
                Align2::LEFT_CENTER
            },
            label,
            font(),
            TEXT,
        );
        if x + width < head.width() {
            p.vline(
                head.left() + x + width - 0.5,
                head.top() + 3.0..=head.bottom() - 3.0,
                Stroke::new(1.0, SHADOW),
            );
            p.vline(
                head.left() + x + width + 0.5,
                head.top() + 3.0..=head.bottom() - 3.0,
                Stroke::new(1.0, LIGHT),
            );
        }
    }
    if blocks {
        let rows = Rect::from_min_max(head.left_bottom(), list.max - vec2(2.0, 2.0));
        let mut list_ui = ui.new_child(
            UiBuilder::new()
                .id_salt("bitcoin-block-list")
                .max_rect(rows)
                .layout(Layout::top_down(Align::Min)),
        );
        list_ui.set_clip_rect(rows);
        list_ui.spacing_mut().item_spacing.y = 0.0;
        list_ui.spacing_mut().scroll = egui::style::ScrollStyle {
            bar_width: 16.0,
            floating: false,
            ..egui::style::ScrollStyle::solid()
        };
        ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(&mut list_ui, |ui| {
                let Some(view) = view else {
                    return;
                };
                let selected_id = ui.id().with("selected-block");
                let mut selected = ui.ctx().data_mut(|d| d.get_temp::<u32>(selected_id));
                for (height, hash) in view.recent.iter().rev() {
                    let (row, response) =
                        ui.allocate_exact_size(vec2(ui.available_width(), 17.0), Sense::click());
                    if response.clicked() {
                        selected = Some(*height);
                    }
                    let on = selected == Some(*height);
                    let rp = ui.painter_at(row);
                    if on {
                        rp.rect_filled(row, 0, SELECT);
                    }
                    let ink = if on { LIGHT } else { TEXT };
                    let ago = s
                        .session
                        .seen_ago(*height)
                        .map(|age| {
                            if age < 5.0 {
                                "just now".to_owned()
                            } else {
                                span(age as u64)
                            }
                        })
                        .unwrap_or_else(|| "earlier".to_owned());
                    for (x, text) in [
                        (6.0, "Connected".to_owned()),
                        (96.0, thousands(u64::from(*height))),
                        (186.0, ago),
                        (291.0, hash.clone()),
                    ] {
                        rp.text(
                            pos2(row.left() + x, row.center().y),
                            Align2::LEFT_CENTER,
                            text,
                            font(),
                            ink,
                        );
                    }
                    response.on_hover_text(hash);
                }
                if let Some(height) = selected {
                    ui.ctx().data_mut(|d| d.insert_temp(selected_id, height));
                }
            });
    }
    ui.allocate_rect(r, Sense::hover());
}
