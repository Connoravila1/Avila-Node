//! The toybox's Windows XP skin, all the way down: a Luna window that
//! really moves, minimizes and closes, with menus, a toolbar, an address
//! bar, a task pane and a status bar; a taskbar with a green start
//! button, a Start menu and a tray clock; and the dialogs that go with
//! them. Everything is drawn in code, and no Microsoft artwork is copied:
//! the start button wears the node's own swirl and the hills are our own.
//! XP's fonts are borrowed from the system when it has them (see
//! `theme::install_fonts`), so the skin adds nothing to the download.

use crate::model::Eclipse;
use crate::rail::{self, Page};
use crate::theme::{self, CAPTION, MEDIUM, START, STRONG, font};
use eframe::egui::{
    self, Align, Align2, Color32, Context, CornerRadius, CursorIcon, FontId, Id, Key, Layout, Mesh,
    Order, Painter, Pos2, Rect, ResizeDirection, Response, ScrollArea, Sense, Shape, Stroke,
    StrokeKind, TextureHandle, Ui, UiBuilder, Vec2, ViewportCommand, pos2, vec2,
};
use egui::scroll_area::ScrollBarVisibility;

pub const TASKBAR: f32 = 30.0;
const TITLE: f32 = 30.0;
const MENU: f32 = 22.0;
const TOOLBAR: f32 = 38.0;
const ADDRESS: f32 = 28.0;
const INFO: f32 = 24.0;
const STATUS: f32 = 23.0;
const PANE: f32 = 206.0;
const SCROLL: f32 = 17.0;
/// The blue frame around a restored window.
const FRAME: f32 = 4.0;

const fn rgb(r: u8, g: u8, b: u8) -> Color32 {
    Color32::from_rgb(r, g, b)
}

type Stops = [(f32, Color32)];

const TITLE_STOPS: [(f32, Color32); 6] = [
    (0.0, rgb(0, 88, 238)),
    (0.07, rgb(61, 149, 255)),
    (0.2, rgb(12, 101, 240)),
    (0.55, rgb(0, 84, 227)),
    (0.88, rgb(3, 90, 238)),
    (1.0, rgb(0, 63, 196)),
];
/// The title bar while another window has the focus.
const TITLE_IDLE: [(f32, Color32); 4] = [
    (0.0, rgb(151, 177, 233)),
    (0.1, rgb(166, 192, 240)),
    (0.5, rgb(128, 155, 226)),
    (1.0, rgb(112, 136, 212)),
];
const TASKBAR_STOPS: [(f32, Color32); 5] = [
    (0.0, rgb(58, 128, 243)),
    (0.08, rgb(92, 154, 250)),
    (0.2, rgb(36, 94, 219)),
    (0.8, rgb(33, 87, 214)),
    (1.0, rgb(24, 64, 178)),
];
const START_STOPS: [(f32, Color32); 5] = [
    (0.0, rgb(56, 146, 52)),
    (0.1, rgb(123, 199, 111)),
    (0.3, rgb(61, 160, 55)),
    (0.8, rgb(52, 143, 49)),
    (1.0, rgb(33, 102, 31)),
];
const START_DOWN: [(f32, Color32); 3] = [
    (0.0, rgb(33, 102, 31)),
    (0.5, rgb(46, 128, 43)),
    (1.0, rgb(56, 146, 52)),
];
const TRAY_STOPS: [(f32, Color32); 4] = [
    (0.0, rgb(12, 137, 230)),
    (0.1, rgb(28, 163, 245)),
    (0.5, rgb(16, 136, 234)),
    (1.0, rgb(12, 112, 214)),
];
const TASK_STOPS: [(f32, Color32); 3] = [
    (0.0, rgb(88, 151, 249)),
    (0.5, rgb(60, 129, 243)),
    (1.0, rgb(47, 110, 230)),
];
const TASK_DOWN: [(f32, Color32); 3] = [
    (0.0, rgb(21, 60, 152)),
    (0.5, rgb(29, 78, 178)),
    (1.0, rgb(35, 92, 200)),
];
const BUTTON_STOPS: [(f32, Color32); 3] = [
    (0.0, rgb(255, 255, 255)),
    (0.6, rgb(240, 239, 233)),
    (1.0, rgb(214, 208, 197)),
];
const PRESSED_STOPS: [(f32, Color32); 2] = [(0.0, rgb(221, 218, 206)), (1.0, rgb(240, 239, 233))];
const DROP_STOPS: [(f32, Color32); 2] = [(0.0, rgb(197, 214, 252)), (1.0, rgb(160, 186, 245))];
const PANE_STOPS: [(f32, Color32); 2] = [(0.0, rgb(123, 162, 231)), (1.0, rgb(99, 117, 214))];

/// The chrome's beige.
pub const BEIGE: Color32 = rgb(236, 233, 216);
/// XP's selection blue.
pub const SELECTION: Color32 = rgb(49, 106, 197);
const EDGE: Color32 = rgb(0, 60, 116);
const FIELD_EDGE: Color32 = rgb(127, 157, 185);
const HOVER_GLOW: Color32 = rgb(248, 179, 48);
const DEFAULT_GLOW: Color32 = rgb(105, 145, 225);
const LINK: Color32 = rgb(33, 93, 198);
const LINK_HOT: Color32 = rgb(66, 142, 255);
const ETCH_DARK: Color32 = rgb(197, 194, 178);
const GREEN: Color32 = rgb(33, 161, 33);
const DISABLED: Color32 = rgb(161, 161, 146);

/// What the chrome asks the app to do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Pick {
    Open(Page),
    Back,
    Forward,
    ToggleHide,
    /// Leave the skin.
    LogOff,
    StartNode,
    StopNode,
    RestartNode,
}

/// A dialog over the desktop.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Dialog {
    #[default]
    None,
    About,
    TurnOff,
}

/// State the skin keeps between frames.
#[derive(Default)]
pub struct Xp {
    pub start_open: bool,
    /// The window shrunk to show the desktop.
    pub restored: bool,
    pub dialog: Dialog,
    /// The menu dropped down from the menu bar.
    menu_open: Option<usize>,
    /// The task pane's boxes, folded shut.
    folded: [bool; 3],
    address_open: bool,
    /// Where the page scroll should jump next frame (the scroll bar).
    scroll_to: Option<f32>,
    /// The warnings a balloon was closed for; a new set shows again.
    dismissed: Vec<Eclipse>,
    /// Local offset from UTC in seconds, asked of `date` once.
    offset: Option<Option<i64>>,
}

/// What the chrome shows of the node, gathered by the app each frame.
pub struct Chrome {
    pub title: String,
    pub page: Page,
    pub pages: Vec<Page>,
    pub swirl: Option<TextureHandle>,
    pub running: bool,
    /// Stopping: start and stop wait.
    pub busy: bool,
    pub hide: bool,
    pub back: bool,
    pub forward: bool,
    pub signs: Vec<Eclipse>,
    pub peers: Option<usize>,
    pub demo: bool,
    /// The address bar's path.
    pub path: String,
    /// The Details box: a bold first line, then plain ones.
    pub details: Vec<String>,
    /// The status bar's panels.
    pub panels: Vec<String>,
    /// Whether the window has the focus (the title bar pales without).
    pub focused: bool,
}

// ---------------------------------------------------------------------
// Painting helpers
// ---------------------------------------------------------------------

fn at(stops: &Stops, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    for pair in stops.windows(2) {
        let ((a, ca), (b, cb)) = (pair[0], pair[1]);
        if t <= b {
            let f = if b > a { (t - a) / (b - a) } else { 1.0 };
            return ca.lerp_to_gamma(cb, f);
        }
    }
    stops.last().map_or(Color32::TRANSPARENT, |s| s.1)
}

/// A rounded rectangle filled with a vertical gradient through `stops`.
/// Built from horizontal strips, one at every stop and down each curve,
/// so a many-stop gradient keeps every stop.
#[inline]
pub fn gradient(p: &Painter, rect: Rect, radius: impl Into<CornerRadius>, stops: &Stops) {
    shade(p, rect, radius.into(), stops);
}

fn shade(p: &Painter, rect: Rect, radius: CornerRadius, stops: &Stops) {
    let (w, h) = (rect.width(), rect.height());
    if w <= 0.0 || h <= 0.0 {
        return;
    }
    let cap = (w.min(h) / 2.0).max(0.0);
    let [nw, ne, sw, se] =
        [radius.nw, radius.ne, radius.sw, radius.se].map(|r| f32::from(r).min(cap));
    let mut ys: Vec<f32> = stops.iter().map(|(t, _)| rect.top() + t * h).collect();
    for i in 0..=6 {
        let f = i as f32 / 6.0;
        ys.extend([rect.top() + nw.max(ne) * f, rect.bottom() - sw.max(se) * f]);
    }
    ys.extend([rect.top(), rect.bottom()]);
    ys.retain(|y| (rect.top()..=rect.bottom()).contains(y));
    ys.sort_by(f32::total_cmp);
    ys.dedup_by(|a, b| (*a - *b).abs() < 0.05);
    let inset = |y: f32, top: f32, bottom: f32| {
        let up = rect.top() + top - y;
        let down = y - (rect.bottom() - bottom);
        let (r, d) = if up > 0.0 { (top, up) } else { (bottom, down) };
        if r > 0.0 && d > 0.0 {
            r - (r * r - d * d).max(0.0).sqrt()
        } else {
            0.0
        }
    };
    let mut mesh = Mesh::default();
    for (i, y) in ys.iter().enumerate() {
        let c = at(stops, (y - rect.top()) / h);
        mesh.colored_vertex(pos2(rect.left() + inset(*y, nw, sw), *y), c);
        mesh.colored_vertex(pos2(rect.right() - inset(*y, ne, se), *y), c);
        if i > 0 {
            let k = (i * 2) as u32;
            mesh.add_triangle(k - 2, k - 1, k);
            mesh.add_triangle(k - 1, k, k + 1);
        }
    }
    p.add(Shape::mesh(mesh));
}

/// A plain rectangle shading from `left` to `right`.
fn across(p: &Painter, rect: Rect, left: Color32, right: Color32) {
    let mut mesh = Mesh::default();
    mesh.colored_vertex(rect.left_top(), left);
    mesh.colored_vertex(rect.right_top(), right);
    mesh.colored_vertex(rect.right_bottom(), right);
    mesh.colored_vertex(rect.left_bottom(), left);
    mesh.add_triangle(0, 1, 2);
    mesh.add_triangle(0, 2, 3);
    p.add(Shape::mesh(mesh));
}

/// Text with a soft one-pixel shadow, the way XP writes on blue and green.
fn shadowed(p: &Painter, pos: Pos2, anchor: Align2, text: &str, font_id: FontId, color: Color32) {
    p.text(
        pos + vec2(1.0, 1.0),
        anchor,
        text,
        font_id.clone(),
        Color32::from_black_alpha(120),
    );
    p.text(pos, anchor, text, font_id, color);
}

fn ui_font(size: f32) -> FontId {
    theme::body(size)
}

/// The etched double line XP puts between bands of chrome.
fn etch_h(p: &Painter, x: egui::Rangef, y: f32) {
    p.hline(x, y, Stroke::new(1.0, ETCH_DARK));
    p.hline(x, y + 1.0, Stroke::new(1.0, Color32::WHITE));
}

fn etch_v(p: &Painter, x: f32, y: egui::Rangef) {
    p.vline(x, y, Stroke::new(1.0, ETCH_DARK));
    p.vline(x + 1.0, y, Stroke::new(1.0, Color32::WHITE));
}

/// A toolbar band's gripper: a column of little raised dots.
fn gripper(p: &Painter, x: f32, y: egui::Rangef) {
    let mut at_y = y.min + 4.0;
    while at_y < y.max - 4.0 {
        p.rect_filled(
            Rect::from_min_size(pos2(x + 1.0, at_y + 1.0), vec2(2.0, 2.0)),
            0,
            Color32::WHITE,
        );
        p.rect_filled(
            Rect::from_min_size(pos2(x, at_y), vec2(2.0, 2.0)),
            0,
            rgb(193, 190, 177),
        );
        at_y += 4.0;
    }
}

fn dotted(p: &Painter, rect: Rect) {
    let pts = [
        rect.left_top(),
        rect.right_top(),
        rect.right_bottom(),
        rect.left_bottom(),
        rect.left_top(),
    ];
    p.extend(Shape::dashed_line(
        &pts,
        Stroke::new(1.0, rgb(40, 40, 40)),
        1.0,
        1.0,
    ));
}

/// Every popup the skin opens goes through here, so egui's area code is
/// compiled once, not once per popup: a copy per call site cost tens of
/// kilobytes of download.
fn popup(
    ctx: &Context,
    id: &str,
    pos: Pos2,
    order: Order,
    content: &mut dyn FnMut(&mut Ui),
) -> Rect {
    egui::Area::new(Id::new(id))
        .order(order)
        .fixed_pos(pos)
        .show(ctx, |ui| content(ui))
        .response
        .rect
}

/// The node's swirl on an orange disc: our stand-in for the flag.
fn swirl_disc(p: &Painter, c: Pos2, r: f32, swirl: Option<&TextureHandle>) {
    p.circle_filled(c, r, theme::SIGNAL);
    if let Some(tex) = swirl {
        p.image(
            tex.id(),
            Rect::from_center_size(c, Vec2::splat(r * 1.5)),
            Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)),
            theme::INK,
        );
    }
}

// ---------------------------------------------------------------------
// Icons
// ---------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Glyph {
    Back,
    Forward,
    Go,
    Stop,
    Warn,
    Eye,
    Page(Page),
}

fn glyph(p: &Painter, g: Glyph, c: Pos2, size: f32, enabled: bool) {
    let r = size / 2.0;
    match g {
        Glyph::Back | Glyph::Forward => {
            let (hi, lo) = if enabled {
                (rgb(118, 214, 104), rgb(26, 138, 26))
            } else {
                (rgb(214, 214, 206), rgb(160, 160, 150))
            };
            p.circle_filled(c, r, lo);
            p.circle_filled(
                c + vec2(-r * 0.15, -r * 0.2),
                r * 0.72,
                hi.lerp_to_gamma(lo, 0.35),
            );
            p.circle_stroke(c, r, Stroke::new(1.0, lo.gamma_multiply(0.8)));
            let s = if matches!(g, Glyph::Back) { -1.0 } else { 1.0 };
            let ink = Stroke::new(r * 0.26, Color32::WHITE);
            p.line_segment(
                [c + vec2(-s * r * 0.45, 0.0), c + vec2(s * r * 0.5, 0.0)],
                ink,
            );
            p.line_segment(
                [
                    c + vec2(s * r * 0.5, 0.0),
                    c + vec2(s * r * 0.05, -r * 0.45),
                ],
                ink,
            );
            p.line_segment(
                [c + vec2(s * r * 0.5, 0.0), c + vec2(s * r * 0.05, r * 0.45)],
                ink,
            );
        }
        Glyph::Go => {
            let lo = if enabled { rgb(26, 138, 26) } else { DISABLED };
            p.circle_filled(c, r, lo);
            p.circle_filled(
                c + vec2(-r * 0.15, -r * 0.2),
                r * 0.7,
                if enabled {
                    rgb(88, 190, 80)
                } else {
                    rgb(200, 200, 190)
                },
            );
            p.add(Shape::convex_polygon(
                vec![
                    c + vec2(-r * 0.3, -r * 0.5),
                    c + vec2(r * 0.55, 0.0),
                    c + vec2(-r * 0.3, r * 0.5),
                ],
                Color32::WHITE,
                Stroke::NONE,
            ));
        }
        Glyph::Stop => {
            let sq = Rect::from_center_size(c, Vec2::splat(size * 0.9));
            let stops: &Stops = if enabled {
                &[(0.0, rgb(244, 124, 100)), (1.0, rgb(188, 38, 18))]
            } else {
                &[(0.0, rgb(220, 220, 212)), (1.0, rgb(170, 170, 160))]
            };
            gradient(p, sq, 3, stops);
            p.rect_filled(
                Rect::from_center_size(c, Vec2::splat(size * 0.36)),
                1,
                Color32::WHITE,
            );
        }
        Glyph::Warn => {
            p.add(Shape::convex_polygon(
                vec![
                    c + vec2(0.0, -r),
                    c + vec2(r, r * 0.85),
                    c + vec2(-r, r * 0.85),
                ],
                rgb(250, 206, 40),
                Stroke::new(1.0, rgb(160, 110, 0)),
            ));
            p.text(
                c + vec2(0.0, r * 0.2),
                Align2::CENTER_CENTER,
                "!",
                font(STRONG, size * 0.62),
                Color32::BLACK,
            );
        }
        Glyph::Eye => {
            let pts: Vec<Pos2> = (0..16)
                .map(|i| {
                    let a = std::f32::consts::TAU * i as f32 / 16.0;
                    c + vec2(a.cos() * r, a.sin() * r * 0.55)
                })
                .collect();
            p.add(Shape::closed_line(pts, Stroke::new(1.3, LINK)));
            p.circle_filled(c, r * 0.36, LINK);
        }
        Glyph::Page(page) => {
            rail::icon(p, page, c, LINK, Color32::WHITE);
        }
    }
}

// ---------------------------------------------------------------------
// The desktop
// ---------------------------------------------------------------------

/// Sky over a green hill, and a few clouds.
pub fn wallpaper(p: &Painter, rect: Rect) {
    gradient(
        p,
        rect,
        0,
        &[
            (0.0, rgb(40, 110, 212)),
            (0.5, rgb(104, 163, 234)),
            (1.0, rgb(170, 206, 244)),
        ],
    );
    // Wisps of cloud: flat ellipses, piled up a little.
    for (cx, cy, w) in [
        (0.18, 0.16, 0.2),
        (0.62, 0.1, 0.26),
        (0.84, 0.3, 0.12),
        (0.38, 0.32, 0.1),
    ] {
        let c = pos2(
            rect.left() + rect.width() * cx,
            rect.top() + rect.height() * cy,
        );
        let r = rect.width() * w * 0.5;
        for (dx, dy, s) in [
            (-0.45, 0.05, 0.6),
            (0.0, -0.04, 0.8),
            (0.4, 0.06, 0.55),
            (0.1, 0.1, 1.0),
        ] {
            p.add(Shape::ellipse_filled(
                c + vec2(dx * r, dy * r),
                vec2(r * s, r * s * 0.22),
                Color32::from_white_alpha(46),
            ));
        }
    }
    // The hill: a long curve, lit from the upper left.
    let mut mesh = Mesh::default();
    let steps = 64;
    for i in 0..=steps {
        let t = i as f32 / steps as f32;
        let x = rect.left() + rect.width() * t;
        let crest = rect.top() + rect.height() * (0.5 + 0.55 * (t - 0.38).powi(2) - 0.05 * t);
        let lit = rgb(132, 202, 72).lerp_to_gamma(rgb(78, 152, 40), t);
        mesh.colored_vertex(pos2(x, crest), lit);
        mesh.colored_vertex(pos2(x, rect.bottom()), rgb(36, 106, 26));
        if i > 0 {
            let k = (i * 2) as u32;
            mesh.add_triangle(k - 2, k - 1, k);
            mesh.add_triangle(k - 1, k, k + 1);
        }
    }
    p.add(Shape::mesh(mesh));
}

/// Where a restored window sits on the desktop.
fn restored(desk: Rect) -> Rect {
    let min = vec2(620.0, 380.0);
    let want = Rect::from_min_max(
        desk.min + vec2(desk.width() * 0.05, desk.height() * 0.05),
        desk.max - vec2(desk.width() * 0.09, desk.height() * 0.07),
    );
    if want.width() < min.x || want.height() < min.y {
        desk.shrink(10.0)
    } else {
        want
    }
}

/// The whole desktop: the window (menus, toolbar, address bar, task pane,
/// the page that `page` draws, status bar), the taskbar, and whatever is
/// open over them. `scroll_to` moves the page (for captures).
pub fn desktop(
    ui: &mut Ui,
    state: &mut Xp,
    c: &Chrome,
    scroll_to: Option<f32>,
    page: impl FnOnce(&mut Ui),
) -> Option<Pick> {
    let ctx = ui.ctx().clone();
    let screen = ui.max_rect();
    let mut pick = None;
    let bar = Rect::from_min_max(pos2(screen.left(), screen.bottom() - TASKBAR), screen.max);
    let desk = Rect::from_min_max(screen.min, pos2(screen.right(), bar.top()));
    let win = if state.restored {
        wallpaper(ui.painter(), desk);
        restored(desk)
    } else {
        desk
    };
    let w = window(ui, win, &c.title, c.swirl.as_ref(), c.focused, state);
    if w.title.drag_started() {
        ctx.send_viewport_cmd(ViewportCommand::StartDrag);
    }
    if w.title.double_clicked() {
        state.restored = !state.restored;
    }
    let client = w.client;
    let p = ui.painter().clone();

    // Menus, then the toolbar, then the address bar.
    let menu_r = Rect::from_min_size(client.min, vec2(client.width(), MENU));
    let tool_r = Rect::from_min_size(menu_r.left_bottom(), vec2(client.width(), TOOLBAR));
    let addr_r = Rect::from_min_size(tool_r.left_bottom(), vec2(client.width(), ADDRESS));
    let mut top = addr_r.bottom() + 2.0;
    etch_h(&p, client.x_range(), menu_r.bottom() - 1.0);
    etch_h(&p, client.x_range(), tool_r.bottom() - 1.0);
    etch_h(&p, client.x_range(), addr_r.bottom());
    pick = pick.or(menus(ui, menu_r, state, c));
    pick = pick.or(toolbar(ui, tool_r, c));
    pick = pick.or(address_bar(ui, addr_r, state, c));
    // SP2's information bar, for the simulator.
    if c.demo {
        let info = Rect::from_min_size(pos2(client.left(), top), vec2(client.width(), INFO));
        info_bar(ui, info);
        top = info.bottom();
    }
    let status_r = Rect::from_min_max(pos2(client.left(), client.bottom() - STATUS), client.max);
    let body = Rect::from_min_max(
        pos2(client.left(), top),
        pos2(client.right(), status_r.top()),
    );

    // The task pane, when there's room for it beside the page.
    let pane_w = if body.width() >= 800.0 { PANE } else { 0.0 };
    if pane_w > 0.0 {
        let pane = Rect::from_min_size(body.min, vec2(pane_w, body.height()));
        pick = pick.or(task_pane(ui, pane, state, c));
    }

    // The page, on white, with XP's scroll bar.
    let view = Rect::from_min_max(
        pos2(body.left() + pane_w, body.top()),
        pos2(body.right() - SCROLL, body.bottom()),
    );
    p.rect_filled(
        Rect::from_min_max(view.min, pos2(body.right(), body.bottom())),
        0,
        Color32::WHITE,
    );
    let mut child = ui.new_child(
        UiBuilder::new()
            .max_rect(view)
            .layout(Layout::top_down(Align::Min)),
    );
    child.set_clip_rect(view);
    let mut area = ScrollArea::vertical()
        .id_salt("xp-page")
        .auto_shrink([false, false])
        .scroll_bar_visibility(ScrollBarVisibility::AlwaysHidden);
    if let Some(y) = scroll_to.or(state.scroll_to.take()) {
        area = area.vertical_scroll_offset(y);
    }
    let out = area.show(&mut child, page);
    let strip = Rect::from_min_max(
        pos2(view.right(), body.top()),
        pos2(body.right(), body.bottom()),
    );
    state.scroll_to = scrollbar(
        ui,
        strip,
        out.state.offset.y,
        out.content_size.y,
        out.inner_rect.height(),
    );
    status_bar(&p, status_r, &c.panels);

    pick = pick.or(taskbar(ui, bar, state, c));
    pick = pick.or(start_menu(&ctx, bar.left_top(), state, c));
    let warn_icon = pos2(bar.right() - 118.0 + 36.0, bar.center().y);
    pick = pick.or(balloon(&ctx, warn_icon, state, &c.signs));
    pick = pick.or(dialogs(&ctx, desk, state, c));
    if ctx.input(|i| i.key_pressed(Key::Escape)) {
        state.start_open = false;
        state.address_open = false;
        state.menu_open = None;
        state.dialog = Dialog::None;
    }
    if !ctx.input(|i| i.viewport().maximized.unwrap_or(false)) {
        resize_edges(ui, screen);
    }
    pick
}

// ---------------------------------------------------------------------
// The window
// ---------------------------------------------------------------------

struct Window {
    client: Rect,
    title: Response,
}

/// The Luna frame and title bar, with caption buttons that act: minimize
/// the real window, maximize or restore this one, close the app.
fn window(
    ui: &mut Ui,
    rect: Rect,
    title: &str,
    swirl: Option<&TextureHandle>,
    focused: bool,
    state: &mut Xp,
) -> Window {
    let maximized = !state.restored;
    let radius = if maximized { 0 } else { 8 };
    let top = CornerRadius {
        nw: radius,
        ne: radius,
        sw: 0,
        se: 0,
    };
    let bar = Rect::from_min_size(rect.min, vec2(rect.width(), TITLE));
    let p = ui.painter().clone();
    if !maximized {
        p.rect_filled(
            rect.translate(vec2(4.0, 4.0)),
            top,
            Color32::from_black_alpha(50),
        );
        p.rect_filled(rect, top, rgb(0, 72, 211));
        p.rect_stroke(
            rect,
            top,
            Stroke::new(1.0, rgb(0, 40, 150)),
            StrokeKind::Inside,
        );
    }
    gradient(
        &p,
        bar,
        top,
        if focused { &TITLE_STOPS } else { &TITLE_IDLE },
    );
    swirl_disc(&p, pos2(bar.left() + 17.0, bar.center().y), 8.5, swirl);
    let caption = pos2(bar.left() + 32.0, bar.center().y);
    if focused {
        shadowed(
            &p,
            caption,
            Align2::LEFT_CENTER,
            title,
            font(CAPTION, 13.5),
            Color32::WHITE,
        );
    } else {
        p.text(
            caption,
            Align2::LEFT_CENTER,
            title,
            font(CAPTION, 13.5),
            rgb(216, 228, 248),
        );
    }
    // The title bar drags the window; the buttons claim their own spots
    // after it, so they win the clicks.
    let title_resp = ui.interact(bar, Id::new("xp-title"), Sense::click_and_drag());
    let size = vec2(21.0, 21.0);
    let close = Rect::from_min_size(
        pos2(bar.right() - 5.0 - size.x, bar.center().y - size.y / 2.0),
        size,
    );
    let max = close.translate(vec2(-(size.x + 2.0), 0.0));
    let min = max.translate(vec2(-(size.x + 2.0), 0.0));
    for (r, which) in [(min, 0), (max, 1), (close, 2)] {
        let resp = ui.interact(r, Id::new(("xp-caption", which)), Sense::click());
        let red = which == 2;
        let down = resp.is_pointer_button_down_on();
        let stops: &Stops = match (red, down) {
            (true, false) => &[
                (0.0, rgb(234, 128, 100)),
                (0.45, rgb(222, 80, 48)),
                (1.0, rgb(196, 54, 26)),
            ],
            (true, true) => &[(0.0, rgb(180, 50, 24)), (1.0, rgb(214, 90, 60))],
            (false, false) => &[
                (0.0, rgb(98, 158, 255)),
                (0.45, rgb(46, 116, 246)),
                (1.0, rgb(28, 92, 228)),
            ],
            (false, true) => &[(0.0, rgb(20, 70, 190)), (1.0, rgb(50, 110, 230))],
        };
        gradient(&p, r, 3, stops);
        if resp.hovered() && !down {
            p.rect_filled(r, 3, Color32::from_white_alpha(46));
        }
        if !focused {
            p.rect_filled(r, 3, Color32::from_white_alpha(80));
        }
        p.rect_stroke(r, 3, Stroke::new(1.0, Color32::WHITE), StrokeKind::Inside);
        let c = r.center();
        let ink = Stroke::new(2.0, Color32::WHITE);
        match which {
            0 => {
                p.line_segment(
                    [c + vec2(-4.5, 4.0), c + vec2(1.5, 4.0)],
                    Stroke::new(2.6, Color32::WHITE),
                );
            }
            1 if maximized => {
                let back = Rect::from_min_size(c + vec2(-2.0, -5.5), vec2(7.5, 6.5));
                let front = Rect::from_min_size(c + vec2(-5.5, -1.5), vec2(7.5, 6.5));
                p.rect_stroke(
                    back,
                    0,
                    Stroke::new(1.2, Color32::WHITE),
                    StrokeKind::Inside,
                );
                p.hline(
                    back.x_range(),
                    back.top() + 1.0,
                    Stroke::new(2.0, Color32::WHITE),
                );
                p.rect_filled(front, 0, rgb(46, 116, 246));
                p.rect_stroke(
                    front,
                    0,
                    Stroke::new(1.2, Color32::WHITE),
                    StrokeKind::Inside,
                );
                p.hline(
                    front.x_range(),
                    front.top() + 1.0,
                    Stroke::new(2.0, Color32::WHITE),
                );
            }
            1 => {
                let frame = Rect::from_center_size(c, vec2(10.0, 9.5));
                p.rect_stroke(
                    frame,
                    0,
                    Stroke::new(1.2, Color32::WHITE),
                    StrokeKind::Inside,
                );
                p.hline(
                    frame.x_range(),
                    frame.top() + 1.2,
                    Stroke::new(2.4, Color32::WHITE),
                );
            }
            _ => {
                p.line_segment([c + vec2(-4.0, -4.0), c + vec2(4.0, 4.0)], ink);
                p.line_segment([c + vec2(4.0, -4.0), c + vec2(-4.0, 4.0)], ink);
            }
        }
        if resp.clicked() {
            match which {
                0 => ui.ctx().send_viewport_cmd(ViewportCommand::Minimized(true)),
                1 => state.restored = !state.restored,
                _ => ui.ctx().send_viewport_cmd(ViewportCommand::Close),
            }
        }
    }
    let inset = if maximized { 0.0 } else { FRAME };
    let client = Rect::from_min_max(
        pos2(rect.left() + inset, bar.bottom()),
        pos2(rect.right() - inset, rect.bottom() - inset),
    );
    p.rect_filled(client, 0, BEIGE);
    Window {
        client,
        title: title_resp,
    }
}

// ---------------------------------------------------------------------
// Menus
// ---------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Mark {
    None,
    Check(bool),
    Dot(bool),
}

/// A menu row: blue with white text under the pointer, a check or a dot
/// in the gutter, the shortcut at the right.
fn item(ui: &mut Ui, label: &str, keys: &str, mark: Mark) -> bool {
    let (r, resp) = ui.allocate_exact_size(vec2(272.0, 22.0), Sense::click());
    let hot = resp.hovered();
    let p = ui.painter();
    if hot {
        p.rect_filled(r, 0, SELECTION);
    }
    let ink = if hot { Color32::WHITE } else { Color32::BLACK };
    let gutter = pos2(r.left() + 12.0, r.center().y);
    match mark {
        Mark::Check(true) => {
            p.add(Shape::line(
                vec![
                    gutter + vec2(-3.5, 0.0),
                    gutter + vec2(-1.0, 3.0),
                    gutter + vec2(4.0, -3.5),
                ],
                Stroke::new(1.8, ink),
            ));
        }
        Mark::Dot(true) => {
            p.circle_filled(gutter, 3.0, ink);
        }
        _ => {}
    }
    p.text(
        pos2(r.left() + 26.0, r.center().y),
        Align2::LEFT_CENTER,
        label,
        ui_font(12.5),
        ink,
    );
    if !keys.is_empty() {
        p.text(
            pos2(r.right() - 12.0, r.center().y),
            Align2::RIGHT_CENTER,
            keys,
            ui_font(12.5),
            ink,
        );
    }
    resp.clicked()
}

fn menu_rule(ui: &mut Ui) {
    let (r, _) = ui.allocate_exact_size(vec2(272.0, 7.0), Sense::hover());
    ui.painter().hline(
        (r.left() + 2.0)..=(r.right() - 2.0),
        r.center().y,
        Stroke::new(1.0, rgb(172, 168, 153)),
    );
}

const MENU_TITLES: [&str; 4] = ["File", "View", "Tools", "Help"];

/// What a menu entry does.
#[derive(Clone, Copy)]
enum Act {
    Pick(Pick),
    Quit,
    About,
}

type Entry = Option<(String, String, Mark, Act)>;

/// One menu's entries: label, shortcut, mark and action; `None` is a rule.
fn entries(menu: usize, c: &Chrome) -> Vec<Entry> {
    let e = |label: &str, keys: &str, mark: Mark, act: Act| {
        Some((label.to_owned(), keys.to_owned(), mark, act))
    };
    match menu {
        0 => vec![
            if c.running {
                e("Stop node", "", Mark::None, Act::Pick(Pick::StopNode))
            } else {
                e("Start node", "", Mark::None, Act::Pick(Pick::StartNode))
            },
            None,
            e("Log Off", "", Mark::None, Act::Pick(Pick::LogOff)),
            e("Close", "Alt+F4", Mark::None, Act::Quit),
        ],
        1 => {
            let mut v: Vec<Entry> = c
                .pages
                .iter()
                .map(|page| {
                    let keys = Page::ALL
                        .iter()
                        .position(|p| p == page)
                        .map_or(String::new(), |i| format!("Ctrl+{}", i + 1));
                    Some((
                        page.label().to_owned(),
                        keys,
                        Mark::Dot(*page == c.page),
                        Act::Pick(Pick::Open(*page)),
                    ))
                })
                .collect();
            v.push(None);
            v.push(e(
                "Hide peer addresses",
                "Ctrl+Shift+H",
                Mark::Check(c.hide),
                Act::Pick(Pick::ToggleHide),
            ));
            v
        }
        2 => vec![
            e(
                "Shitcoin Defense",
                "",
                Mark::None,
                Act::Pick(Pick::Open(Page::Toybox)),
            ),
            None,
            e(
                "Options…",
                "",
                Mark::None,
                Act::Pick(Pick::Open(Page::Settings)),
            ),
        ],
        _ => vec![e("About Avila Node", "", Mark::None, Act::About)],
    }
}

/// The menu bar, drawn by hand: titles light up blue, a click opens one,
/// and while one is open the pointer slides between them.
fn menus(ui: &mut Ui, rect: Rect, state: &mut Xp, c: &Chrome) -> Option<Pick> {
    let p = ui.painter().clone();
    let mut x = rect.left() + 4.0;
    let mut anchor = None;
    for (i, title) in MENU_TITLES.iter().enumerate() {
        let galley = p.layout_no_wrap((*title).to_owned(), ui_font(12.5), Color32::PLACEHOLDER);
        let r = Rect::from_min_size(
            pos2(x, rect.top() + 1.0),
            vec2(galley.size().x + 16.0, rect.height() - 3.0),
        );
        x = r.right();
        let resp = ui.interact(r, Id::new(("xp-menu-title", i)), Sense::click());
        if resp.clicked() {
            state.menu_open = if state.menu_open == Some(i) {
                None
            } else {
                Some(i)
            };
        } else if resp.hovered() && state.menu_open.is_some() {
            state.menu_open = Some(i);
        }
        let lit = state.menu_open == Some(i) || resp.hovered();
        if lit {
            p.rect_filled(r, 0, SELECTION);
        }
        p.galley(
            r.center() - galley.size() / 2.0,
            galley,
            if lit { Color32::WHITE } else { Color32::BLACK },
        );
        if state.menu_open == Some(i) {
            anchor = Some(r.left_bottom());
        }
    }
    // Where XP waves its flag, the node shows its swirl.
    let badge = Rect::from_min_max(
        pos2(rect.right() - 40.0, rect.top()),
        pos2(rect.right(), rect.bottom() + TOOLBAR - 2.0),
    );
    p.rect_filled(badge, 0, Color32::WHITE);
    p.vline(badge.left(), badge.y_range(), Stroke::new(1.0, ETCH_DARK));
    swirl_disc(&p, badge.center(), 12.0, c.swirl.as_ref());

    let (Some(menu), Some(at)) = (state.menu_open, anchor) else {
        return None;
    };
    let list = entries(menu, c);
    let mut chosen = None;
    let area = popup(ui.ctx(), "xp-menu", at, Order::Foreground, &mut |ui| {
        let under = ui.painter().add(Shape::Noop);
        ui.spacing_mut().item_spacing = Vec2::ZERO;
        ui.add_space(2.0);
        for entry in &list {
            match entry {
                Some((label, keys, mark, act)) => {
                    if item(ui, label, keys, *mark) {
                        chosen = Some(*act);
                    }
                }
                None => menu_rule(ui),
            }
        }
        ui.add_space(2.0);
        let r = ui.min_rect().expand2(vec2(2.0, 0.0));
        ui.painter().set(
            under,
            Shape::Vec(vec![
                Shape::rect_filled(
                    r.translate(vec2(3.0, 3.0)),
                    0,
                    Color32::from_black_alpha(50),
                ),
                Shape::rect_filled(r, 0, Color32::WHITE),
                Shape::rect_stroke(
                    r,
                    0,
                    Stroke::new(1.0, rgb(172, 168, 153)),
                    StrokeKind::Inside,
                ),
            ]),
        );
    });
    let clicked_away = ui.ctx().input(|i| {
        i.pointer.any_click()
            && i.pointer
                .interact_pos()
                .is_some_and(|pos| !area.contains(pos) && !rect.contains(pos))
    });
    if chosen.is_some() || clicked_away {
        state.menu_open = None;
    }
    match chosen? {
        Act::Pick(pick) => Some(pick),
        Act::Quit => {
            ui.ctx().send_viewport_cmd(ViewportCommand::Close);
            None
        }
        Act::About => {
            state.dialog = Dialog::About;
            None
        }
    }
}

// ---------------------------------------------------------------------
// Toolbar, address bar, information bar
// ---------------------------------------------------------------------

fn tool(ui: &mut Ui, label: &str, g: Glyph, enabled: bool) -> bool {
    let galley = (!label.is_empty()).then(|| {
        ui.painter()
            .layout_no_wrap(label.to_owned(), ui_font(12.5), Color32::BLACK)
    });
    let w = 36.0 + galley.as_ref().map_or(0.0, |g| g.size().x + 4.0);
    let (r, resp) = ui.allocate_exact_size(vec2(w, 32.0), Sense::click());
    let hot = enabled && resp.hovered();
    let down = hot && resp.is_pointer_button_down_on();
    let p = ui.painter();
    if hot {
        gradient(p, r, 3, if down { &PRESSED_STOPS } else { &BUTTON_STOPS });
        p.rect_stroke(
            r,
            3,
            Stroke::new(1.0, rgb(206, 206, 195)),
            StrokeKind::Inside,
        );
    }
    let shift = if down { vec2(1.0, 1.0) } else { Vec2::ZERO };
    glyph(
        p,
        g,
        pos2(r.left() + 18.0, r.center().y) + shift,
        24.0,
        enabled,
    );
    if let Some(galley) = galley {
        p.galley(
            pos2(r.left() + 34.0, r.center().y - galley.size().y / 2.0) + shift,
            galley,
            if enabled { Color32::BLACK } else { DISABLED },
        );
    }
    let resp = if enabled {
        resp.on_hover_cursor(CursorIcon::PointingHand)
    } else {
        resp
    };
    enabled && resp.clicked()
}

fn tool_rule(ui: &mut Ui) {
    let (r, _) = ui.allocate_exact_size(vec2(8.0, 28.0), Sense::hover());
    etch_v(ui.painter(), r.center().x, r.y_range());
}

fn toolbar(ui: &mut Ui, rect: Rect, c: &Chrome) -> Option<Pick> {
    let mut pick = None;
    gripper(ui.painter(), rect.left() + 3.0, rect.y_range());
    let mut row = ui.new_child(
        UiBuilder::new()
            .max_rect(Rect::from_min_max(
                pos2(rect.left() + 10.0, rect.top()),
                pos2(rect.right() - 44.0, rect.bottom()),
            ))
            .layout(Layout::left_to_right(Align::Center)),
    );
    row.spacing_mut().item_spacing.x = 2.0;
    if tool(&mut row, "Back", Glyph::Back, c.back) {
        pick = Some(Pick::Back);
    }
    if tool(&mut row, "", Glyph::Forward, c.forward) {
        pick = Some(Pick::Forward);
    }
    tool_rule(&mut row);
    if c.running {
        if tool(&mut row, "Stop node", Glyph::Stop, !c.busy) {
            pick = Some(Pick::StopNode);
        }
    } else if tool(&mut row, "Start node", Glyph::Go, !c.busy) {
        pick = Some(Pick::StartNode);
    }
    tool_rule(&mut row);
    if tool(&mut row, "Peers", Glyph::Page(Page::Peers), true) {
        pick = Some(Pick::Open(Page::Peers));
    }
    if !c.signs.is_empty() && tool(&mut row, "Possible eclipse", Glyph::Warn, true) {
        pick = Some(Pick::Open(Page::Peers));
    }
    pick
}

fn address_bar(ui: &mut Ui, rect: Rect, state: &mut Xp, c: &Chrome) -> Option<Pick> {
    let mut pick = None;
    let p = ui.painter().clone();
    gripper(&p, rect.left() + 3.0, rect.y_range());
    p.text(
        pos2(rect.left() + 12.0, rect.center().y),
        Align2::LEFT_CENTER,
        "Address",
        ui_font(12.5),
        rgb(90, 90, 80),
    );
    let go = Rect::from_min_max(
        pos2(rect.right() - 52.0, rect.top() + 3.0),
        pos2(rect.right() - 6.0, rect.bottom() - 3.0),
    );
    let field = Rect::from_min_max(
        pos2(rect.left() + 70.0, rect.top() + 3.0),
        pos2(go.left() - 6.0, rect.bottom() - 3.0),
    );
    p.rect_filled(field, 0, Color32::WHITE);
    p.rect_stroke(field, 0, Stroke::new(1.0, FIELD_EDGE), StrokeKind::Inside);
    rail::icon(
        &p,
        c.page,
        pos2(field.left() + 14.0, field.center().y),
        LINK,
        Color32::WHITE,
    );
    p.text(
        pos2(field.left() + 30.0, field.center().y),
        Align2::LEFT_CENTER,
        &c.path,
        ui_font(12.5),
        Color32::BLACK,
    );
    let drop = Rect::from_min_max(
        pos2(field.right() - 18.0, field.top() + 1.0),
        pos2(field.right() - 1.0, field.bottom() - 1.0),
    );
    let field_resp = ui
        .interact(field, Id::new("xp-address"), Sense::click())
        .on_hover_cursor(CursorIcon::PointingHand);
    gradient(&p, drop, 2, &DROP_STOPS);
    if field_resp.hovered() {
        p.rect_filled(drop, 2, Color32::from_white_alpha(50));
    }
    p.rect_stroke(
        drop,
        2,
        Stroke::new(1.0, Color32::WHITE),
        StrokeKind::Inside,
    );
    chevron(&p, drop.center(), 3.5, false, rgb(77, 97, 133));
    if field_resp.clicked() {
        state.address_open = !state.address_open;
    }
    // Go: a green arrow and the word.
    let go_resp = ui
        .interact(go, Id::new("xp-go"), Sense::click())
        .on_hover_cursor(CursorIcon::PointingHand);
    if go_resp.hovered() {
        gradient(&p, go, 3, &BUTTON_STOPS);
        p.rect_stroke(
            go,
            3,
            Stroke::new(1.0, rgb(206, 206, 195)),
            StrokeKind::Inside,
        );
    }
    let arrow = pos2(go.left() + 11.0, go.center().y);
    gradient(
        &p,
        Rect::from_center_size(arrow, vec2(15.0, 15.0)),
        3,
        &[(0.0, rgb(110, 205, 96)), (1.0, rgb(30, 140, 30))],
    );
    p.add(Shape::convex_polygon(
        vec![
            arrow + vec2(-3.0, -4.5),
            arrow + vec2(4.0, 0.0),
            arrow + vec2(-3.0, 4.5),
        ],
        Color32::WHITE,
        Stroke::NONE,
    ));
    p.text(
        pos2(go.left() + 22.0, go.center().y),
        Align2::LEFT_CENTER,
        "Go",
        ui_font(12.5),
        Color32::BLACK,
    );
    if go_resp.clicked() {
        state.address_open = false;
        pick = Some(Pick::Open(c.page));
    }
    // The drop-down list of places.
    if state.address_open {
        let list = Rect::from_min_size(
            field.left_bottom() + vec2(0.0, 1.0),
            vec2(field.width(), 20.0 * c.pages.len() as f32 + 4.0),
        );
        popup(
            ui.ctx(),
            "xp-address-list",
            list.min,
            Order::Foreground,
            &mut |ui| {
                let (r, _) = ui.allocate_exact_size(list.size(), Sense::hover());
                let p = ui.painter();
                p.rect_filled(r, 0, Color32::WHITE);
                p.rect_stroke(r, 0, Stroke::new(1.0, Color32::BLACK), StrokeKind::Inside);
                for (i, page) in c.pages.iter().enumerate() {
                    let row = Rect::from_min_size(
                        r.min + vec2(2.0, 2.0 + 20.0 * i as f32),
                        vec2(r.width() - 4.0, 20.0),
                    );
                    let resp = ui.interact(row, Id::new(("xp-place", i)), Sense::click());
                    let hot = resp.hovered();
                    if hot {
                        p.rect_filled(row, 0, SELECTION);
                    }
                    let ink = if hot { Color32::WHITE } else { Color32::BLACK };
                    rail::icon(
                        p,
                        *page,
                        pos2(row.left() + 14.0, row.center().y),
                        if hot { Color32::WHITE } else { LINK },
                        if hot { SELECTION } else { Color32::WHITE },
                    );
                    p.text(
                        pos2(row.left() + 32.0, row.center().y),
                        Align2::LEFT_CENTER,
                        page.label(),
                        ui_font(12.5),
                        ink,
                    );
                    if resp.clicked() {
                        pick = Some(Pick::Open(*page));
                    }
                }
            },
        );
        let clicked_away = ui.ctx().input(|i| {
            i.pointer.any_click()
                && i.pointer
                    .interact_pos()
                    .is_some_and(|pos| !list.contains(pos) && !field.contains(pos))
        });
        if pick.is_some() || clicked_away {
            state.address_open = false;
        }
    }
    pick
}

/// SP2's yellow information bar, saying the data is simulated.
fn info_bar(ui: &Ui, rect: Rect) {
    let p = ui.painter();
    p.rect_filled(rect, 0, rgb(255, 255, 225));
    p.hline(
        rect.x_range(),
        rect.bottom() - 0.5,
        Stroke::new(1.0, rgb(172, 168, 153)),
    );
    let icon = pos2(rect.left() + 16.0, rect.center().y);
    p.circle_filled(icon, 7.0, SELECTION);
    p.text(
        icon,
        Align2::CENTER_CENTER,
        "i",
        font(STRONG, 11.0),
        Color32::WHITE,
    );
    let galley = crate::widgets::fit(
        p,
        "This window shows simulated data, started with --demo. Nothing on screen comes from the network."
            .to_owned(),
        ui_font(12.0),
        Color32::BLACK,
        rect.width() - 40.0,
    );
    p.galley(
        pos2(rect.left() + 30.0, rect.center().y - galley.size().y / 2.0),
        galley,
        Color32::BLACK,
    );
}

// ---------------------------------------------------------------------
// The task pane
// ---------------------------------------------------------------------

/// A pair of strokes making a chevron, pointing up or down.
fn chevron(p: &Painter, c: Pos2, s: f32, up: bool, color: Color32) {
    let d = if up { -1.0 } else { 1.0 };
    let stroke = Stroke::new(1.5, color);
    p.line_segment(
        [c + vec2(-s, -d * s * 0.5), c + vec2(0.0, d * s * 0.5)],
        stroke,
    );
    p.line_segment(
        [c + vec2(0.0, d * s * 0.5), c + vec2(s, -d * s * 0.5)],
        stroke,
    );
}

/// The round fold button at a task box's right (and on Settings'
/// Advanced header): chevrons up while open, down while folded.
fn fold_button(p: &Painter, c: Pos2, open: bool, hot: bool) {
    p.circle_filled(c, 8.5, Color32::WHITE);
    p.circle_stroke(
        c,
        8.5,
        Stroke::new(1.0, if hot { LINK_HOT } else { rgb(170, 188, 228) }),
    );
    let color = if hot { LINK_HOT } else { LINK };
    chevron(p, c + vec2(0.0, -2.2), 3.0, open, color);
    chevron(p, c + vec2(0.0, 2.2), 3.0, open, color);
}

/// A task box's header; a click folds the box. Returns the body's top.
fn task_box_header(ui: &Ui, r: Rect, title: &str, folded: &mut bool, id: usize) -> f32 {
    let resp = ui
        .interact(r, Id::new(("xp-taskbox", id)), Sense::click())
        .on_hover_cursor(CursorIcon::PointingHand);
    if resp.clicked() {
        *folded = !*folded;
    }
    let p = ui.painter();
    let left_top = CornerRadius {
        nw: 4,
        ne: 0,
        sw: 0,
        se: 0,
    };
    p.rect_filled(
        r,
        CornerRadius {
            nw: 4,
            ne: 4,
            sw: 0,
            se: 0,
        },
        rgb(198, 211, 247),
    );
    p.rect_filled(
        Rect::from_min_size(r.min, vec2(10.0, r.height())),
        left_top,
        Color32::WHITE,
    );
    across(
        p,
        Rect::from_min_max(
            pos2(r.left() + 8.0, r.top()),
            pos2(r.right() - 4.0, r.bottom()),
        ),
        Color32::WHITE,
        rgb(198, 211, 247),
    );
    let hot = resp.hovered();
    p.text(
        pos2(r.left() + 12.0, r.center().y),
        Align2::LEFT_CENTER,
        title,
        font(STRONG, 12.0),
        if hot { LINK_HOT } else { LINK },
    );
    fold_button(p, pos2(r.right() - 14.0, r.center().y), !*folded, hot);
    r.bottom()
}

/// A task link: an icon, and blue text that underlines under the pointer.
fn task_link(ui: &Ui, pos: Pos2, width: f32, label: &str, g: Glyph, id: &str) -> bool {
    let r = Rect::from_min_size(pos, vec2(width, 20.0));
    let resp = ui
        .interact(r, Id::new(("xp-link", id)), Sense::click())
        .on_hover_cursor(CursorIcon::PointingHand);
    let p = ui.painter();
    glyph(p, g, pos2(r.left() + 9.0, r.center().y), 15.0, true);
    let color = if resp.hovered() { LINK_HOT } else { LINK };
    let text = p.text(
        pos2(r.left() + 24.0, r.center().y),
        Align2::LEFT_CENTER,
        label,
        ui_font(12.0),
        color,
    );
    if resp.hovered() {
        p.hline(text.x_range(), text.bottom() - 1.0, Stroke::new(1.0, color));
    }
    resp.clicked()
}

fn task_pane(ui: &mut Ui, rect: Rect, state: &mut Xp, c: &Chrome) -> Option<Pick> {
    let mut pick = None;
    gradient(ui.painter(), rect, 0, &PANE_STOPS);
    let clip = ui.painter().with_clip_rect(rect);
    let (left, width) = (rect.left() + 12.0, rect.width() - 24.0);
    let mut y = rect.top() + 12.0;
    let body = |p: &Painter, top: f32, h: f32| {
        let r = Rect::from_min_size(pos2(left, top), vec2(width, h));
        p.rect_filled(r, 0, rgb(214, 223, 247));
        p.rect_stroke(r, 0, Stroke::new(1.0, Color32::WHITE), StrokeKind::Inside);
    };
    // Node tasks.
    let head = Rect::from_min_size(pos2(left, y), vec2(width, 25.0));
    y = task_box_header(ui, head, "Node Tasks", &mut state.folded[0], 0);
    if !state.folded[0] {
        let h = 3.0 * 20.0 + 16.0;
        body(&clip, y, h);
        let mut row = y + 8.0;
        let (label, g, choice) = if c.running {
            ("Stop the node", Glyph::Stop, Pick::StopNode)
        } else {
            ("Start the node", Glyph::Go, Pick::StartNode)
        };
        if task_link(ui, pos2(left + 8.0, row), width - 16.0, label, g, "run") && !c.busy {
            pick = Some(choice);
        }
        row += 20.0;
        let hide = if c.hide {
            "Show peer addresses"
        } else {
            "Hide peer addresses"
        };
        if task_link(
            ui,
            pos2(left + 8.0, row),
            width - 16.0,
            hide,
            Glyph::Eye,
            "hide",
        ) {
            pick = Some(Pick::ToggleHide);
        }
        row += 20.0;
        if task_link(
            ui,
            pos2(left + 8.0, row),
            width - 16.0,
            "Play Shitcoin Defense",
            Glyph::Page(Page::Toybox),
            "game",
        ) {
            pick = Some(Pick::Open(Page::Toybox));
        }
        y += h;
    }
    y += 12.0;
    // Other places: every page but this one.
    let head = Rect::from_min_size(pos2(left, y), vec2(width, 25.0));
    y = task_box_header(ui, head, "Other Places", &mut state.folded[1], 1);
    if !state.folded[1] {
        let others: Vec<Page> = c.pages.iter().copied().filter(|p| *p != c.page).collect();
        let h = others.len() as f32 * 20.0 + 16.0;
        body(&clip, y, h);
        for (i, page) in others.iter().enumerate() {
            let at = pos2(left + 8.0, y + 8.0 + 20.0 * i as f32);
            if task_link(
                ui,
                at,
                width - 16.0,
                page.label(),
                Glyph::Page(*page),
                page.label(),
            ) {
                pick = Some(Pick::Open(*page));
            }
        }
        y += h;
    }
    y += 12.0;
    // Details, the way XP describes a drive.
    let head = Rect::from_min_size(pos2(left, y), vec2(width, 25.0));
    y = task_box_header(ui, head, "Details", &mut state.folded[2], 2);
    if !state.folded[2] {
        let h = c.details.len() as f32 * 17.0 + 16.0;
        body(&clip, y, h);
        for (i, line) in c.details.iter().enumerate() {
            let galley = crate::widgets::fit(
                &clip,
                line.clone(),
                if i == 0 {
                    font(STRONG, 12.0)
                } else {
                    ui_font(12.0)
                },
                Color32::BLACK,
                width - 20.0,
            );
            clip.galley(
                pos2(left + 10.0, y + 8.0 + 17.0 * i as f32),
                galley,
                Color32::BLACK,
            );
        }
    }
    pick
}

// ---------------------------------------------------------------------
// The scroll bar and the status bar
// ---------------------------------------------------------------------

/// XP's scroll bar for the page: pale blue arrows and a thumb with a
/// grip. Returns where the page should scroll to, when it's used.
fn scrollbar(ui: &Ui, strip: Rect, offset: f32, content: f32, view: f32) -> Option<f32> {
    let p = ui.painter();
    across(p, strip, rgb(238, 237, 229), rgb(253, 253, 250));
    let can = content > view + 1.0;
    let range = (content - view).max(0.0);
    let side = strip.width();
    let up = Rect::from_min_size(strip.min, vec2(side, side));
    let down = Rect::from_min_size(pos2(strip.left(), strip.bottom() - side), vec2(side, side));
    let track = Rect::from_min_max(up.left_bottom(), down.right_top());
    let piece = |r: Rect, hot: bool| {
        let r = r.shrink(0.5);
        let stops: &Stops = if !can {
            &[(0.0, rgb(244, 243, 238)), (1.0, rgb(232, 231, 222))]
        } else if hot {
            &[(0.0, rgb(226, 236, 255)), (1.0, rgb(196, 214, 253))]
        } else {
            &[(0.0, rgb(213, 225, 253)), (1.0, rgb(183, 202, 246))]
        };
        gradient(p, r, 3, stops);
        p.rect_stroke(
            r,
            3,
            Stroke::new(
                1.0,
                if can {
                    rgb(166, 188, 238)
                } else {
                    rgb(210, 208, 198)
                },
            ),
            StrokeKind::Inside,
        );
    };
    let ink = if can { rgb(77, 97, 133) } else { DISABLED };
    let mut to = None;
    for (r, sign, id) in [(up, -1.0, "up"), (down, 1.0, "down")] {
        let resp = ui.interact(r, Id::new(("xp-scroll", id)), Sense::click());
        piece(r, resp.hovered());
        let tip = r.center() + vec2(0.0, sign * 2.0);
        let stroke = Stroke::new(2.0, ink);
        p.line_segment([tip + vec2(-3.5, -sign * 3.5), tip], stroke);
        p.line_segment([tip, tip + vec2(3.5, -sign * 3.5)], stroke);
        if can && resp.clicked() {
            to = Some((offset + sign * 48.0).clamp(0.0, range));
        }
    }
    if !can {
        return None;
    }
    let thumb_h = (track.height() * view / content).clamp(18.0, track.height());
    let travel = (track.height() - thumb_h).max(1.0);
    let thumb = Rect::from_min_size(
        pos2(
            track.left(),
            track.top() + travel * (offset / range.max(1.0)),
        ),
        vec2(track.width(), thumb_h),
    );
    let track_resp = ui.interact(track, Id::new("xp-scroll-track"), Sense::click());
    if track_resp.clicked()
        && let Some(pos) = track_resp.interact_pointer_pos()
        && !thumb.contains(pos)
    {
        let dir = if pos.y < thumb.top() { -1.0 } else { 1.0 };
        to = Some((offset + dir * view * 0.9).clamp(0.0, range));
    }
    let thumb_resp = ui.interact(thumb, Id::new("xp-scroll-thumb"), Sense::drag());
    piece(thumb, thumb_resp.hovered() || thumb_resp.dragged());
    for dy in [-3.0, -1.0, 1.0, 3.0] {
        let y = thumb.center().y + dy;
        p.hline(
            (thumb.center().x - 3.5)..=(thumb.center().x + 3.5),
            y,
            Stroke::new(1.0, Color32::WHITE),
        );
        p.hline(
            (thumb.center().x - 3.0)..=(thumb.center().x + 4.0),
            y + 0.8,
            Stroke::new(0.8, rgb(140, 164, 222)),
        );
    }
    if thumb_resp.dragged() {
        let dy = thumb_resp.drag_delta().y;
        to = Some((offset + dy * range / travel).clamp(0.0, range));
    }
    to
}

/// The status bar along the window's bottom: sunken panels, and the
/// resize grip in the corner.
fn status_bar(p: &Painter, rect: Rect, panels: &[String]) {
    p.rect_filled(rect, 0, BEIGE);
    etch_h(p, rect.x_range(), rect.top());
    let mut x = rect.left() + 3.0;
    let end = rect.right() - 18.0;
    for (i, text) in panels.iter().enumerate() {
        let galley = p.layout_no_wrap(text.clone(), ui_font(12.0), Color32::BLACK);
        let last = i + 1 == panels.len();
        let w = if last {
            end - x
        } else {
            galley.size().x + 24.0
        };
        if w < 30.0 {
            break;
        }
        let panel = Rect::from_min_size(pos2(x, rect.top() + 3.0), vec2(w, rect.height() - 5.0));
        let shade = Stroke::new(1.0, rgb(172, 168, 153));
        p.hline(panel.x_range(), panel.top(), shade);
        p.vline(panel.left(), panel.y_range(), shade);
        p.hline(
            panel.x_range(),
            panel.bottom(),
            Stroke::new(1.0, Color32::WHITE),
        );
        p.vline(
            panel.right(),
            panel.y_range(),
            Stroke::new(1.0, Color32::WHITE),
        );
        let clip = p.with_clip_rect(panel.shrink(1.0));
        clip.galley(
            pos2(panel.left() + 7.0, panel.center().y - galley.size().y / 2.0),
            galley,
            Color32::BLACK,
        );
        x += w + 2.0;
    }
    // The grip: dots stepping down into the corner.
    let corner = rect.right_bottom() - vec2(3.0, 3.0);
    for (i, j) in [(0, 0), (1, 0), (2, 0), (0, 1), (1, 1), (0, 2)] {
        let at = corner - vec2(4.0 * i as f32, 4.0 * j as f32);
        p.rect_filled(
            Rect::from_min_size(at - vec2(2.0, 2.0), vec2(2.0, 2.0)),
            0,
            Color32::WHITE,
        );
        p.rect_filled(
            Rect::from_min_size(at - vec2(3.0, 3.0), vec2(2.0, 2.0)),
            0,
            rgb(184, 180, 162),
        );
    }
}

// ---------------------------------------------------------------------
// The taskbar
// ---------------------------------------------------------------------

impl Xp {
    /// Local time as the tray shows it, e.g. `3:45 PM`.
    fn clock(&mut self) -> String {
        let offset = *self.offset.get_or_insert_with(|| {
            if cfg!(test) {
                return None;
            }
            // `date +%z` gives `-0400`: a local zone without a timezone
            // database.
            let out = std::process::Command::new("date")
                .arg("+%z")
                .output()
                .ok()?;
            let z = String::from_utf8(out.stdout).ok()?;
            let z = z.trim();
            let sign = if z.starts_with('-') { -1 } else { 1 };
            let digits = z.trim_start_matches(['+', '-']);
            let h = digits.get(..2)?.parse::<i64>().ok()?;
            let m = digits.get(2..4)?.parse::<i64>().ok()?;
            Some(sign * (h * 3600 + m * 60))
        });
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64)
            + offset.unwrap_or(0);
        twelve_hour(now)
    }
}

fn twelve_hour(secs: i64) -> String {
    let secs = secs.rem_euclid(86_400);
    let (h, m) = (secs / 3600, secs % 3600 / 60);
    let (h12, half) = match h {
        0 => (12, "AM"),
        1..=11 => (h, "AM"),
        12 => (12, "PM"),
        _ => (h - 12, "PM"),
    };
    format!("{h12}:{m:02} {half}")
}

/// The taskbar: start button, a button per page, and the tray.
fn taskbar(ui: &mut Ui, rect: Rect, state: &mut Xp, c: &Chrome) -> Option<Pick> {
    let mut pick = None;
    let p = ui.painter().clone();
    gradient(&p, rect, 0, &TASKBAR_STOPS);

    // Start.
    let start = Rect::from_min_size(rect.min, vec2(100.0, rect.height()));
    let start_resp = ui
        .interact(start, Id::new("xp-start"), Sense::click())
        .on_hover_cursor(CursorIcon::PointingHand);
    let shape = CornerRadius {
        nw: 0,
        sw: 0,
        ne: 12,
        se: 12,
    };
    gradient(
        &p,
        start,
        shape,
        if state.start_open {
            &START_DOWN
        } else {
            &START_STOPS
        },
    );
    if start_resp.hovered() && !state.start_open {
        p.rect_filled(start, shape, Color32::from_white_alpha(26));
    }
    p.rect_stroke(
        start.shrink2(vec2(0.0, 0.5)),
        shape,
        Stroke::new(1.0, rgb(28, 88, 26)),
        StrokeKind::Inside,
    );
    let logo = pos2(start.left() + 20.0, start.center().y);
    p.circle_stroke(logo, 10.5, Stroke::new(1.0, Color32::from_white_alpha(170)));
    swirl_disc(&p, logo, 10.0, c.swirl.as_ref());
    shadowed(
        &p,
        pos2(start.left() + 35.0, start.center().y - 1.0),
        Align2::LEFT_CENTER,
        "start",
        font(START, 19.0),
        Color32::WHITE,
    );
    if start_resp.clicked() {
        state.start_open = !state.start_open;
    }

    // The tray, from the right.
    let tray = Rect::from_min_max(pos2(rect.right() - 118.0, rect.top()), rect.max);
    gradient(&p, tray, 0, &TRAY_STOPS);
    p.vline(
        tray.left(),
        tray.y_range(),
        Stroke::new(1.0, rgb(16, 66, 175)),
    );
    p.vline(
        tray.left() + 1.0,
        tray.y_range(),
        Stroke::new(1.0, rgb(96, 186, 250)),
    );
    shadowed(
        &p,
        pos2(tray.right() - 12.0, tray.center().y),
        Align2::RIGHT_CENTER,
        &state.clock(),
        ui_font(12.0),
        Color32::WHITE,
    );
    // Network: two little screens, lit while there are peers.
    let net = pos2(tray.left() + 16.0, tray.center().y);
    let lit = c.peers.is_some_and(|n| n > 0);
    for (dx, dy) in [(-3.0, -2.5), (3.0, 2.0)] {
        let screen = Rect::from_center_size(net + vec2(dx, dy), vec2(9.0, 7.0));
        p.rect_filled(
            screen,
            1,
            if lit {
                rgb(170, 225, 255)
            } else {
                rgb(120, 140, 170)
            },
        );
        p.rect_stroke(
            screen,
            1,
            Stroke::new(1.0, rgb(10, 40, 110)),
            StrokeKind::Inside,
        );
    }
    ui.interact(
        Rect::from_center_size(net, vec2(18.0, 18.0)),
        Id::new("xp-net"),
        Sense::hover(),
    )
    .on_hover_text(match c.peers {
        Some(n) => format!("Avila Node: {n} peer{}", if n == 1 { "" } else { "s" }),
        None => "Avila Node: not running".to_owned(),
    });
    if !c.signs.is_empty() {
        let shield = pos2(tray.left() + 36.0, tray.center().y);
        glyph(&p, Glyph::Warn, shield, 15.0, true);
        let resp = ui
            .interact(
                Rect::from_center_size(shield, vec2(18.0, 18.0)),
                Id::new("xp-warn"),
                Sense::click(),
            )
            .on_hover_cursor(CursorIcon::PointingHand);
        if resp.clicked() {
            state.dismissed.clear();
        }
    }

    // One button per page, like open windows.
    let left = start.right() + 8.0;
    let room = (tray.left() - 6.0 - left).max(0.0);
    let each = (room / c.pages.len().max(1) as f32).min(160.0);
    for (i, page) in c.pages.iter().enumerate() {
        let r = Rect::from_min_size(
            pos2(left + each * i as f32, rect.top() + 3.0),
            vec2(each - 3.0, rect.height() - 5.0),
        );
        if r.width() < 24.0 {
            break;
        }
        let resp = ui
            .interact(r, Id::new(("xp-task", i)), Sense::click())
            .on_hover_cursor(CursorIcon::PointingHand);
        let active = *page == c.page;
        gradient(&p, r, 3, if active { &TASK_DOWN } else { &TASK_STOPS });
        if resp.hovered() && !active {
            p.rect_filled(r, 3, Color32::from_white_alpha(30));
        }
        p.rect_stroke(
            r,
            3,
            Stroke::new(
                1.0,
                if active {
                    rgb(16, 46, 124)
                } else {
                    rgb(36, 84, 196)
                },
            ),
            StrokeKind::Inside,
        );
        rail::icon(
            &p,
            *page,
            pos2(r.left() + 16.0, r.center().y),
            Color32::WHITE,
            if active {
                rgb(29, 78, 178)
            } else {
                rgb(60, 129, 243)
            },
        );
        let label = crate::widgets::fit(
            &p,
            page.label().to_owned(),
            ui_font(12.0),
            Color32::WHITE,
            r.width() - 38.0,
        );
        p.galley(
            pos2(r.left() + 32.0, r.center().y - label.size().y / 2.0),
            label,
            Color32::WHITE,
        );
        if resp.clicked() {
            pick = Some(Pick::Open(*page));
        }
    }
    pick
}

// ---------------------------------------------------------------------
// The Start menu
// ---------------------------------------------------------------------

/// What each page is for, under its name in the Start menu.
fn blurb(page: Page) -> &'static str {
    match page {
        Page::Overview => "Your node at a glance",
        Page::Chain => "Blocks and what was proven",
        Page::Peers => "Who you're connected to",
        Page::Activity => "What just happened",
        Page::Toybox => "The game and the skins",
        Page::Settings => "How the node starts",
    }
}

/// The Start menu over the taskbar. A click anywhere else closes it.
fn start_menu(ctx: &Context, bottom_left: Pos2, state: &mut Xp, c: &Chrome) -> Option<Pick> {
    if !state.start_open {
        return None;
    }
    let rows = c.pages.len() as f32;
    let size = vec2(400.0, 62.0 + 16.0 + rows * 44.0 + 48.0);
    let origin = bottom_left - vec2(0.0, size.y);
    let menu = Rect::from_min_size(origin, size);
    let mut pick = None;
    popup(ctx, "xp-start-menu", origin, Order::Foreground, &mut |ui| {
        let (rect, _) = ui.allocate_exact_size(size, Sense::click());
        let p = ui.painter().clone();
        let top = CornerRadius {
            nw: 7,
            ne: 7,
            sw: 0,
            se: 0,
        };
        p.rect_filled(
            rect.translate(vec2(3.0, 0.0)),
            top,
            Color32::from_black_alpha(60),
        );
        p.rect_filled(rect, top, rgb(0, 72, 211));
        // Header: who's here.
        let head = Rect::from_min_size(rect.min, vec2(size.x, 62.0));
        gradient(
            &p,
            head,
            top,
            &[
                (0.0, rgb(24, 104, 222)),
                (0.12, rgb(66, 146, 238)),
                (0.5, rgb(38, 118, 226)),
                (1.0, rgb(18, 84, 204)),
            ],
        );
        p.hline(
            head.x_range(),
            head.bottom() - 1.0,
            Stroke::new(2.0, rgb(240, 160, 70)),
        );
        let tile = Rect::from_min_size(head.min + vec2(8.0, 8.0), vec2(46.0, 46.0));
        p.rect_filled(tile, 4, theme::SIGNAL);
        p.rect_stroke(
            tile,
            4,
            Stroke::new(2.0, Color32::WHITE),
            StrokeKind::Inside,
        );
        if let Some(tex) = &c.swirl {
            p.image(
                tex.id(),
                tile.shrink(7.0),
                Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)),
                theme::INK,
            );
        }
        let who = std::env::var("USER")
            .ok()
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| "Node operator".into());
        shadowed(
            &p,
            pos2(tile.right() + 10.0, head.center().y),
            Align2::LEFT_CENTER,
            &who,
            font(CAPTION, 16.0),
            Color32::WHITE,
        );
        // Body: the pages on white, shortcuts on pale blue.
        let body = Rect::from_min_max(
            pos2(rect.left() + 2.0, head.bottom()),
            pos2(rect.right() - 2.0, rect.bottom() - 46.0),
        );
        let split = body.left() + body.width() * 0.55;
        p.rect_filled(
            Rect::from_min_max(body.min, pos2(split, body.bottom())),
            0,
            Color32::WHITE,
        );
        p.rect_filled(
            Rect::from_min_max(pos2(split, body.top()), body.max),
            0,
            rgb(211, 229, 250),
        );
        p.vline(split, body.y_range(), Stroke::new(1.0, rgb(149, 189, 237)));
        for (i, page) in c.pages.iter().enumerate() {
            let r = Rect::from_min_size(
                pos2(body.left() + 4.0, body.top() + 8.0 + 44.0 * i as f32),
                vec2(split - body.left() - 8.0, 42.0),
            );
            if pinned(ui, &p, r, *page) {
                pick = Some(Pick::Open(*page));
            }
        }
        let right = split + 4.0;
        let w = body.right() - right - 4.0;
        let mut y = body.top() + 8.0;
        for (label, choice) in [
            ("My Node", Some(Pick::Open(Page::Overview))),
            ("My Peers", Some(Pick::Open(Page::Peers))),
            ("My Activity", Some(Pick::Open(Page::Activity))),
            ("Control Panel", Some(Pick::Open(Page::Settings))),
            ("Help and Support", None),
            (
                if c.hide {
                    "Show Addresses"
                } else {
                    "Hide Addresses"
                },
                Some(Pick::ToggleHide),
            ),
        ] {
            let r = Rect::from_min_size(pos2(right, y), vec2(w, 30.0));
            y += 32.0;
            if shortcut(ui, &p, r, label) {
                match choice {
                    Some(choice) => pick = Some(choice),
                    None => state.dialog = Dialog::About,
                }
            }
        }
        // Footer: log off (leave the skin), turn off (the dialog).
        let foot = Rect::from_min_max(pos2(rect.left(), body.bottom()), rect.max);
        gradient(
            &p,
            foot,
            0,
            &[
                (0.0, rgb(58, 136, 234)),
                (0.5, rgb(32, 106, 218)),
                (1.0, rgb(16, 84, 200)),
            ],
        );
        let off = Rect::from_min_size(
            pos2(foot.right() - 164.0, foot.top() + 8.0),
            vec2(156.0, 30.0),
        );
        let log = Rect::from_min_size(pos2(off.left() - 98.0, foot.top() + 8.0), vec2(92.0, 30.0));
        for (r, label, color, id) in [
            (log, "Log Off", rgb(236, 176, 30), 0),
            (off, "Turn Off Computer", rgb(222, 72, 40), 1),
        ] {
            let resp = ui
                .interact(r, Id::new(("xp-foot", id)), Sense::click())
                .on_hover_cursor(CursorIcon::PointingHand);
            if resp.hovered() {
                p.rect_filled(r, 3, Color32::from_white_alpha(40));
            }
            let icon =
                Rect::from_center_size(pos2(r.left() + 14.0, r.center().y), vec2(22.0, 22.0));
            gradient(
                &p,
                icon,
                4,
                &[
                    (0.0, color.lerp_to_gamma(Color32::WHITE, 0.35)),
                    (1.0, color),
                ],
            );
            p.rect_stroke(
                icon,
                4,
                Stroke::new(1.0, Color32::WHITE),
                StrokeKind::Inside,
            );
            let dot = icon.center();
            if id == 0 {
                // A key: a ring, a shaft, two teeth.
                let s = Stroke::new(1.8, Color32::WHITE);
                p.circle_stroke(dot + vec2(-4.0, 0.0), 3.2, s);
                p.line_segment([dot + vec2(-0.8, 0.0), dot + vec2(7.0, 0.0)], s);
                p.line_segment([dot + vec2(4.0, 0.0), dot + vec2(4.0, 3.5)], s);
                p.line_segment([dot + vec2(6.5, 0.0), dot + vec2(6.5, 3.0)], s);
            } else {
                power(&p, dot, 5.5, Color32::WHITE);
            }
            shadowed(
                &p,
                pos2(r.left() + 30.0, r.center().y),
                Align2::LEFT_CENTER,
                label,
                ui_font(12.5),
                Color32::WHITE,
            );
            if resp.clicked() {
                if id == 0 {
                    pick = Some(Pick::LogOff);
                } else {
                    state.dialog = Dialog::TurnOff;
                }
            }
        }
    });
    let button = Rect::from_min_size(bottom_left, vec2(100.0, TASKBAR));
    let clicked_away = ctx.input(|i| {
        i.pointer.any_click()
            && i.pointer
                .interact_pos()
                .is_some_and(|pos| !menu.contains(pos) && !button.contains(pos))
    });
    if pick.is_some() || clicked_away || state.dialog != Dialog::None {
        state.start_open = false;
    }
    pick
}

/// The power symbol: a broken ring and a stroke through its gap.
fn power(p: &Painter, c: Pos2, r: f32, color: Color32) {
    use std::f32::consts::{FRAC_PI_2, TAU};
    let arc: Vec<Pos2> = (0..=20)
        .map(|i| {
            let a = -FRAC_PI_2 + 0.7 + (TAU - 1.4) * i as f32 / 20.0;
            c + vec2(a.cos(), a.sin()) * r
        })
        .collect();
    p.add(Shape::line(arc, Stroke::new(1.8, color)));
    p.vline(c.x, (c.y - r - 1.0)..=(c.y - 0.5), Stroke::new(1.8, color));
}

/// A pinned program: a big icon, its name in bold, a line about it.
fn pinned(ui: &Ui, p: &Painter, r: Rect, page: Page) -> bool {
    let resp = ui
        .interact(r, Id::new(("xp-pinned", page.label())), Sense::click())
        .on_hover_cursor(CursorIcon::PointingHand);
    let hot = resp.hovered();
    if hot {
        p.rect_filled(r, 0, SELECTION);
    }
    let icon = Rect::from_center_size(pos2(r.left() + 20.0, r.center().y), vec2(32.0, 32.0));
    gradient(
        p,
        icon,
        5,
        &[(0.0, rgb(250, 252, 255)), (1.0, rgb(206, 222, 250))],
    );
    p.rect_stroke(
        icon,
        5,
        Stroke::new(1.0, rgb(150, 178, 230)),
        StrokeKind::Inside,
    );
    rail::icon(p, page, icon.center(), SELECTION, rgb(228, 238, 252));
    let (name, note) = if hot {
        (Color32::WHITE, Color32::from_white_alpha(210))
    } else {
        (Color32::BLACK, rgb(110, 110, 110))
    };
    let label = if page == Page::Toybox {
        "Shitcoin Defense"
    } else {
        page.label()
    };
    p.text(
        pos2(r.left() + 44.0, r.center().y - 8.0),
        Align2::LEFT_CENTER,
        label,
        font(STRONG, 12.5),
        name,
    );
    p.text(
        pos2(r.left() + 44.0, r.center().y + 8.0),
        Align2::LEFT_CENTER,
        blurb(page),
        ui_font(11.5),
        note,
    );
    resp.clicked()
}

/// A right-column Start menu entry: a folder and a bold blue label.
fn shortcut(ui: &Ui, p: &Painter, r: Rect, label: &str) -> bool {
    let resp = ui
        .interact(r, Id::new(("xp-shortcut", label)), Sense::click())
        .on_hover_cursor(CursorIcon::PointingHand);
    let hot = resp.hovered();
    if hot {
        p.rect_filled(r, 0, SELECTION);
    }
    let f = Rect::from_center_size(pos2(r.left() + 16.0, r.center().y + 1.0), vec2(18.0, 13.0));
    p.rect_filled(
        Rect::from_min_size(f.min - vec2(0.0, 3.0), vec2(8.0, 4.0)),
        1,
        rgb(228, 186, 64),
    );
    gradient(
        p,
        f,
        1,
        &[(0.0, rgb(255, 228, 130)), (1.0, rgb(240, 196, 70))],
    );
    p.rect_stroke(
        f,
        1,
        Stroke::new(1.0, rgb(186, 138, 26)),
        StrokeKind::Inside,
    );
    p.text(
        pos2(r.left() + 32.0, r.center().y),
        Align2::LEFT_CENTER,
        label,
        font(STRONG, 12.5),
        if hot { Color32::WHITE } else { rgb(0, 40, 120) },
    );
    resp.clicked()
}

// ---------------------------------------------------------------------
// The tray balloon and the dialogs
// ---------------------------------------------------------------------

/// XP's yellow tray balloon, for the eclipse warnings. Closing it keeps
/// it closed until the set of warnings changes.
fn balloon(ctx: &Context, tray_icon: Pos2, state: &mut Xp, signs: &[Eclipse]) -> Option<Pick> {
    if signs.is_empty() || state.dismissed == signs || state.start_open {
        return None;
    }
    let size = vec2(330.0, 96.0);
    let origin = tray_icon - vec2(size.x - 34.0, size.y + 16.0);
    let mut pick = None;
    popup(ctx, "xp-balloon", origin, Order::Foreground, &mut |ui| {
        let (rect, resp) = ui.allocate_exact_size(size + vec2(0.0, 14.0), Sense::click());
        let body = Rect::from_min_size(rect.min, size);
        let p = ui.painter();
        p.rect_filled(
            body.translate(vec2(2.0, 2.0)),
            8,
            Color32::from_black_alpha(50),
        );
        p.rect_filled(body, 8, rgb(255, 255, 225));
        p.rect_stroke(
            body,
            8,
            Stroke::new(1.0, Color32::BLACK),
            StrokeKind::Inside,
        );
        let tip = pos2(body.right() - 34.0, body.bottom() + 13.0);
        let (a, b) = (
            pos2(tip.x - 18.0, body.bottom() - 1.0),
            pos2(tip.x, body.bottom() - 1.0),
        );
        p.add(Shape::convex_polygon(
            vec![a, b, tip],
            rgb(255, 255, 225),
            Stroke::NONE,
        ));
        p.line_segment([a + vec2(0.0, 0.5), tip], Stroke::new(1.0, Color32::BLACK));
        p.line_segment([b + vec2(0.0, 0.5), tip], Stroke::new(1.0, Color32::BLACK));
        glyph(
            p,
            Glyph::Warn,
            body.left_top() + vec2(18.0, 20.0),
            16.0,
            true,
        );
        p.text(
            body.left_top() + vec2(34.0, 12.0),
            Align2::LEFT_TOP,
            "Your node might be eclipsed",
            font(STRONG, 12.5),
            Color32::BLACK,
        );
        let close = Rect::from_min_size(
            pos2(body.right() - 22.0, body.top() + 8.0),
            vec2(14.0, 14.0),
        );
        p.rect_stroke(
            close,
            2,
            Stroke::new(1.0, rgb(130, 130, 130)),
            StrokeKind::Inside,
        );
        let x = Stroke::new(1.3, Color32::BLACK);
        p.line_segment(
            [
                close.left_top() + vec2(3.5, 3.5),
                close.right_bottom() - vec2(3.5, 3.5),
            ],
            x,
        );
        p.line_segment(
            [
                close.right_top() + vec2(-3.5, 3.5),
                close.left_bottom() + vec2(3.5, -3.5),
            ],
            x,
        );
        let text = signs.first().map_or("", |e| e.title());
        let galley = p.layout(
            format!("{text}. Click here to see your peers."),
            ui_font(12.0),
            Color32::BLACK,
            size.x - 48.0,
        );
        p.galley(body.left_top() + vec2(34.0, 34.0), galley, Color32::BLACK);
        if resp.clicked() {
            let on_close = resp
                .interact_pointer_pos()
                .is_some_and(|pos| close.expand(3.0).contains(pos));
            state.dismissed = signs.to_vec();
            if !on_close {
                pick = Some(Pick::Open(Page::Peers));
            }
        }
    });
    pick
}

/// A small XP window for a dialog. Returns the client rect and whether
/// its close button was clicked.
fn dialog_window(ui: &Ui, rect: Rect, title: &str) -> (Rect, bool) {
    let p = ui.painter();
    let top = CornerRadius {
        nw: 8,
        ne: 8,
        sw: 0,
        se: 0,
    };
    p.rect_filled(
        rect.translate(vec2(4.0, 4.0)),
        top,
        Color32::from_black_alpha(60),
    );
    p.rect_filled(rect, top, rgb(0, 72, 211));
    let bar = Rect::from_min_size(rect.min, vec2(rect.width(), TITLE));
    gradient(p, bar, top, &TITLE_STOPS);
    shadowed(
        p,
        pos2(bar.left() + 10.0, bar.center().y),
        Align2::LEFT_CENTER,
        title,
        font(CAPTION, 13.5),
        Color32::WHITE,
    );
    let close = Rect::from_min_size(
        pos2(bar.right() - 26.0, bar.center().y - 10.5),
        vec2(21.0, 21.0),
    );
    let resp = ui.interact(close, Id::new(("xp-dialog-close", title)), Sense::click());
    gradient(
        p,
        close,
        3,
        &[
            (0.0, rgb(234, 128, 100)),
            (0.45, rgb(222, 80, 48)),
            (1.0, rgb(196, 54, 26)),
        ],
    );
    if resp.hovered() {
        p.rect_filled(close, 3, Color32::from_white_alpha(46));
    }
    p.rect_stroke(
        close,
        3,
        Stroke::new(1.0, Color32::WHITE),
        StrokeKind::Inside,
    );
    let c = close.center();
    let ink = Stroke::new(2.0, Color32::WHITE);
    p.line_segment([c + vec2(-4.0, -4.0), c + vec2(4.0, 4.0)], ink);
    p.line_segment([c + vec2(4.0, -4.0), c + vec2(-4.0, 4.0)], ink);
    let client = Rect::from_min_max(
        pos2(rect.left() + FRAME, bar.bottom()),
        rect.max - vec2(FRAME, FRAME),
    );
    p.rect_filled(client, 0, BEIGE);
    (client, resp.clicked())
}

/// A push button painted at `rect` (for dialogs, outside any layout).
fn dialog_button(ui: &Ui, rect: Rect, label: &str, primary: bool) -> bool {
    let resp = ui.interact(rect, Id::new(("xp-dialog-button", label)), Sense::click());
    let down = resp.is_pointer_button_down_on();
    button(ui.painter(), rect, primary, resp.hovered(), down);
    ui.painter().text(
        rect.center() + if down { vec2(1.0, 1.0) } else { Vec2::ZERO },
        Align2::CENTER_CENTER,
        label,
        ui_font(12.5),
        Color32::BLACK,
    );
    resp.clicked()
}

fn dialogs(ctx: &Context, desk: Rect, state: &mut Xp, c: &Chrome) -> Option<Pick> {
    let mut pick = None;
    match state.dialog {
        Dialog::None => {}
        Dialog::About => {
            let size = vec2(440.0, 212.0);
            let rect = Rect::from_center_size(desk.center(), size);
            popup(ctx, "xp-about", rect.min, Order::Foreground, &mut |ui| {
                let (rect, _) = ui.allocate_exact_size(size, Sense::click());
                let (client, closed) = dialog_window(ui, rect, "About Avila Node");
                let p = ui.painter();
                swirl_disc(
                    p,
                    client.left_top() + vec2(44.0, 48.0),
                    24.0,
                    c.swirl.as_ref(),
                );
                let x = client.left() + 84.0;
                p.text(
                    pos2(x, client.top() + 22.0),
                    Align2::LEFT_TOP,
                    "Avila Node",
                    font(CAPTION, 18.0),
                    Color32::BLACK,
                );
                let lines = [
                    format!("Version {}", env!("CARGO_PKG_VERSION")),
                    "A Bitcoin full node that checks every block itself.".to_owned(),
                    "Bitcoin only.".to_owned(),
                ];
                let mut y = client.top() + 52.0;
                for line in lines {
                    let galley = p.layout(
                        line,
                        ui_font(12.0),
                        Color32::BLACK,
                        client.right() - x - 16.0,
                    );
                    let h = galley.size().y;
                    p.galley(pos2(x, y), galley, Color32::BLACK);
                    y += h + 3.0;
                }
                let ok = Rect::from_min_size(
                    pos2(client.right() - 90.0, client.bottom() - 36.0),
                    vec2(75.0, 23.0),
                );
                if dialog_button(ui, ok, "OK", true) || closed {
                    state.dialog = Dialog::None;
                }
            });
        }
        Dialog::TurnOff => {
            // The screen fades to gray behind the question, as XP's did.
            let screen = ctx.content_rect();
            popup(ctx, "xp-fade", screen.min, Order::Foreground, &mut |ui| {
                let resp = ui.allocate_rect(screen, Sense::click());
                ui.painter()
                    .rect_filled(screen, 0, Color32::from_black_alpha(110));
                if resp.clicked() {
                    state.dialog = Dialog::None;
                }
            });
            let size = vec2(312.0, 200.0);
            let rect = Rect::from_center_size(desk.center(), size);
            popup(ctx, "xp-turn-off", rect.min, Order::Tooltip, &mut |ui| {
                let (rect, _) = ui.allocate_exact_size(size, Sense::click());
                pick = turn_off(ui, rect, state, c);
            });
        }
    }
    pick
}

/// XP's "Turn off computer": stand by (minimize), turn off (stop the
/// node), restart (stop it and start it again).
fn turn_off(ui: &Ui, rect: Rect, state: &mut Xp, c: &Chrome) -> Option<Pick> {
    let mut pick = None;
    let p = ui.painter();
    let head = Rect::from_min_size(rect.min, vec2(rect.width(), 44.0));
    let foot = Rect::from_min_max(pos2(rect.left(), rect.bottom() - 42.0), rect.max);
    let mid = Rect::from_min_max(head.left_bottom(), foot.right_top());
    p.rect_filled(head, 0, rgb(0, 48, 150));
    p.rect_filled(foot, 0, rgb(0, 48, 150));
    gradient(
        p,
        mid,
        0,
        &[(0.0, rgb(108, 140, 228)), (1.0, rgb(78, 108, 212))],
    );
    p.hline(
        mid.x_range(),
        mid.top(),
        Stroke::new(2.0, rgb(240, 160, 70)),
    );
    p.text(
        pos2(head.left() + 14.0, head.center().y),
        Align2::LEFT_CENTER,
        "Turn off computer",
        font(CAPTION, 17.0),
        Color32::WHITE,
    );
    swirl_disc(
        p,
        pos2(head.right() - 24.0, head.center().y),
        13.0,
        c.swirl.as_ref(),
    );
    let choices = [
        ("Stand By", rgb(236, 176, 30)),
        ("Turn Off", rgb(214, 56, 32)),
        ("Restart", rgb(46, 150, 46)),
    ];
    for (i, (label, color)) in choices.into_iter().enumerate() {
        let cx = mid.left() + mid.width() * (0.2 + 0.3 * i as f32);
        let icon = Rect::from_center_size(pos2(cx, mid.center().y - 10.0), vec2(34.0, 34.0));
        // Turning off needs a running node.
        let usable = i != 1 || c.running;
        let resp = ui.interact(icon, Id::new(("xp-off", i)), Sense::click());
        let tone = if usable { color } else { rgb(150, 150, 150) };
        gradient(
            p,
            icon,
            6,
            &[(0.0, tone.lerp_to_gamma(Color32::WHITE, 0.45)), (1.0, tone)],
        );
        if resp.hovered() && usable {
            p.rect_filled(icon, 6, Color32::from_white_alpha(50));
        }
        p.rect_stroke(
            icon,
            6,
            Stroke::new(1.5, Color32::WHITE),
            StrokeKind::Inside,
        );
        let ic = icon.center();
        match i {
            0 => {
                // A crescent moon.
                p.circle_filled(ic, 8.0, Color32::WHITE);
                p.circle_filled(ic + vec2(4.0, -3.0), 7.0, tone);
            }
            1 => power(p, ic, 8.0, Color32::WHITE),
            _ => {
                let arc: Vec<Pos2> = (0..=16)
                    .map(|k| {
                        let a = -1.2 + 4.6 * k as f32 / 16.0;
                        ic + vec2(a.cos(), a.sin()) * 8.0
                    })
                    .collect();
                let end = arc[0];
                p.add(Shape::line(arc, Stroke::new(2.2, Color32::WHITE)));
                p.add(Shape::convex_polygon(
                    vec![
                        end + vec2(-5.0, -3.0),
                        end + vec2(4.0, -5.0),
                        end + vec2(1.0, 4.0),
                    ],
                    Color32::WHITE,
                    Stroke::NONE,
                ));
            }
        }
        p.text(
            pos2(cx, icon.bottom() + 12.0),
            Align2::CENTER_CENTER,
            label,
            ui_font(12.0),
            if usable {
                Color32::WHITE
            } else {
                rgb(200, 205, 225)
            },
        );
        if resp.clicked() && usable {
            state.dialog = Dialog::None;
            match i {
                0 => ui.ctx().send_viewport_cmd(ViewportCommand::Minimized(true)),
                1 => pick = Some(Pick::StopNode),
                _ => pick = Some(Pick::RestartNode),
            }
        }
    }
    let cancel = Rect::from_min_size(
        pos2(foot.right() - 88.0, foot.center().y - 11.5),
        vec2(75.0, 23.0),
    );
    if dialog_button(ui, cancel, "Cancel", false) {
        state.dialog = Dialog::None;
    }
    pick
}

// ---------------------------------------------------------------------
// Resizing without the system's frame
// ---------------------------------------------------------------------

/// With the native frame off, the window's edges still resize it.
fn resize_edges(ui: &Ui, rect: Rect) {
    let e = 5.0;
    let (l, r, t, b) = (rect.left(), rect.right(), rect.top(), rect.bottom());
    let zones = [
        (
            Rect::from_min_max(pos2(l, t), pos2(l + e, t + e)),
            ResizeDirection::NorthWest,
            CursorIcon::ResizeNorthWest,
        ),
        (
            Rect::from_min_max(pos2(r - e, t), pos2(r, t + e)),
            ResizeDirection::NorthEast,
            CursorIcon::ResizeNorthEast,
        ),
        (
            Rect::from_min_max(pos2(l, b - e), pos2(l + e, b)),
            ResizeDirection::SouthWest,
            CursorIcon::ResizeSouthWest,
        ),
        (
            Rect::from_min_max(pos2(r - e, b - e), pos2(r, b)),
            ResizeDirection::SouthEast,
            CursorIcon::ResizeSouthEast,
        ),
        (
            Rect::from_min_max(pos2(l + e, t), pos2(r - e, t + 3.0)),
            ResizeDirection::North,
            CursorIcon::ResizeVertical,
        ),
        (
            Rect::from_min_max(pos2(l + e, b - 3.0), pos2(r - e, b)),
            ResizeDirection::South,
            CursorIcon::ResizeVertical,
        ),
        (
            Rect::from_min_max(pos2(l, t + e), pos2(l + 3.0, b - e)),
            ResizeDirection::West,
            CursorIcon::ResizeHorizontal,
        ),
        (
            Rect::from_min_max(pos2(r - 3.0, t + e), pos2(r, b - e)),
            ResizeDirection::East,
            CursorIcon::ResizeHorizontal,
        ),
    ];
    for (i, (zone, dir, cursor)) in zones.into_iter().enumerate() {
        let resp = ui
            .interact(zone, Id::new(("xp-resize", i)), Sense::drag())
            .on_hover_cursor(cursor);
        if resp.drag_started() {
            ui.ctx()
                .send_viewport_cmd(ViewportCommand::BeginResize(dir));
        }
    }
}

// ---------------------------------------------------------------------
// The pages' widgets in XP's clothes (`widgets` calls these)
// ---------------------------------------------------------------------

/// A push button's face: pale gradient, dark blue edge, an orange glow
/// under the pointer and a blue one on the default button.
pub fn button(p: &Painter, rect: Rect, primary: bool, hot: bool, down: bool) {
    gradient(
        p,
        rect,
        3,
        if down { &PRESSED_STOPS } else { &BUTTON_STOPS },
    );
    p.rect_stroke(rect, 3, Stroke::new(1.0, EDGE), StrokeKind::Inside);
    let glow = if hot && !down {
        Some(HOVER_GLOW)
    } else if primary && !down {
        Some(DEFAULT_GLOW)
    } else {
        None
    };
    if let Some(glow) = glow {
        p.rect_stroke(
            rect.shrink(1.0),
            2,
            Stroke::new(2.0, glow.gamma_multiply(0.8)),
            StrokeKind::Inside,
        );
    }
}

/// [`button`] as a widget: XP's 75-pixel minimum, black text, and a
/// dotted focus rectangle.
pub fn push_button(ui: &mut Ui, text: &str, primary: bool) -> Response {
    let enabled = ui.is_enabled();
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_owned(), font(MEDIUM, 13.0), Color32::BLACK);
    let size = vec2((galley.size().x + 26.0).max(75.0), 27.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    if ui.is_rect_visible(rect) {
        let p = ui.painter();
        let down = resp.is_pointer_button_down_on();
        if enabled {
            button(p, rect, primary, resp.hovered(), down);
        } else {
            p.rect_filled(rect, 3, rgb(245, 244, 234));
            p.rect_stroke(
                rect,
                3,
                Stroke::new(1.0, rgb(201, 199, 186)),
                StrokeKind::Inside,
            );
        }
        let shift = if down { vec2(1.0, 1.0) } else { Vec2::ZERO };
        p.galley(
            rect.center() - galley.size() / 2.0 + shift,
            galley,
            if enabled { Color32::BLACK } else { DISABLED },
        );
        if resp.has_focus() {
            dotted(p, rect.shrink(4.0));
        }
    }
    resp.on_hover_cursor(CursorIcon::PointingHand)
}

/// A radio button's circle: white with a soft inner shade, a green dot
/// when chosen, an orange ring under the pointer.
fn radio_face(p: &Painter, c: Pos2, on: bool, hot: bool, enabled: bool) {
    let r = 6.5;
    p.circle_filled(
        c,
        r,
        if enabled {
            rgb(226, 226, 220)
        } else {
            rgb(240, 239, 230)
        },
    );
    p.circle_filled(c + vec2(0.8, 0.8), r - 1.6, Color32::WHITE);
    if hot && enabled {
        p.circle_stroke(c, r - 1.8, Stroke::new(1.6, HOVER_GLOW));
    }
    p.circle_stroke(
        c,
        r,
        Stroke::new(
            1.0,
            if enabled {
                rgb(28, 81, 128)
            } else {
                rgb(202, 200, 187)
            },
        ),
    );
    if on {
        p.circle_filled(c, 3.2, if enabled { GREEN } else { DISABLED });
        p.circle_filled(c + vec2(-0.9, -0.9), 1.3, Color32::from_white_alpha(120));
    }
}

/// A row of radio buttons: XP's way of choosing one of a few.
#[inline]
pub fn radios<T: Copy + PartialEq>(ui: &mut Ui, value: &mut T, options: &[(T, &str)]) -> bool {
    let labels: Vec<&str> = options.iter().map(|(_, label)| *label).collect();
    let current = options.iter().position(|(option, _)| option == value);
    match radio_row(ui, current, &labels) {
        Some(i) => {
            *value = options[i].0;
            true
        }
        None => false,
    }
}

/// [`radios`] without the type: placed by hand, left to right, even
/// inside a right-to-left row. Returns the option newly chosen.
fn radio_row(ui: &mut Ui, current: Option<usize>, labels: &[&str]) -> Option<usize> {
    let mut chosen = None;
    let enabled = ui.is_enabled();
    let galleys: Vec<_> = labels
        .iter()
        .map(|label| {
            ui.painter()
                .layout_no_wrap((*label).to_owned(), ui_font(13.0), Color32::PLACEHOLDER)
        })
        .collect();
    let gap = 16.0;
    let total = galleys.iter().map(|g| 19.0 + g.size().x).sum::<f32>()
        + gap * labels.len().saturating_sub(1) as f32;
    let base = ui.next_auto_id();
    let (row, _) = ui.allocate_exact_size(vec2(total, 22.0), Sense::hover());
    let mut x = row.left();
    for (i, galley) in galleys.into_iter().enumerate() {
        let rect = Rect::from_min_size(
            pos2(x, row.top()),
            vec2(19.0 + galley.size().x, row.height()),
        );
        x = rect.right() + gap;
        let resp = ui
            .interact(rect, base.with(i), Sense::click())
            .on_hover_cursor(CursorIcon::PointingHand);
        let on = current == Some(i);
        if resp.clicked() && !on {
            chosen = Some(i);
        }
        let p = ui.painter();
        radio_face(
            p,
            pos2(rect.left() + 7.0, rect.center().y),
            on,
            resp.hovered(),
            enabled,
        );
        let text_at = pos2(rect.left() + 19.0, rect.center().y - galley.size().y / 2.0);
        let text_rect = Rect::from_min_size(text_at, galley.size());
        p.galley(
            text_at,
            galley,
            if enabled { Color32::BLACK } else { DISABLED },
        );
        if resp.has_focus() {
            dotted(p, text_rect.expand(1.0));
        }
    }
    chosen
}

/// A check box: a white square, a navy edge, a green tick.
pub fn checkbox(ui: &mut Ui, value: &mut bool, text: &str) -> Response {
    let enabled = ui.is_enabled();
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_owned(), ui_font(13.0), Color32::BLACK);
    let (rect, mut resp) =
        ui.allocate_exact_size(vec2(19.0 + galley.size().x, 22.0), Sense::click());
    if resp.clicked() {
        *value = !*value;
        resp.mark_changed();
    }
    let p = ui.painter();
    let square = Rect::from_center_size(pos2(rect.left() + 7.0, rect.center().y), vec2(13.0, 13.0));
    if enabled {
        gradient(
            p,
            square,
            0,
            &[
                (0.0, rgb(220, 220, 215)),
                (0.5, rgb(246, 246, 244)),
                (1.0, Color32::WHITE),
            ],
        );
    } else {
        p.rect_filled(square, 0, rgb(245, 244, 234));
    }
    if resp.hovered() && enabled {
        p.rect_stroke(
            square.shrink(1.0),
            0,
            Stroke::new(1.6, HOVER_GLOW),
            StrokeKind::Inside,
        );
    }
    p.rect_stroke(
        square,
        0,
        Stroke::new(
            1.0,
            if enabled {
                rgb(28, 81, 128)
            } else {
                rgb(202, 200, 187)
            },
        ),
        StrokeKind::Inside,
    );
    if *value {
        let c = square.center();
        p.add(Shape::line(
            vec![
                c + vec2(-3.5, -0.5),
                c + vec2(-1.0, 2.5),
                c + vec2(3.5, -2.5),
            ],
            Stroke::new(2.0, if enabled { GREEN } else { DISABLED }),
        ));
    }
    let text_at = pos2(rect.left() + 19.0, rect.center().y - galley.size().y / 2.0);
    let text_rect = Rect::from_min_size(text_at, galley.size());
    p.galley(
        text_at,
        galley,
        if enabled { Color32::BLACK } else { DISABLED },
    );
    if resp.has_focus() {
        dotted(p, text_rect.expand(1.0));
    }
    resp.on_hover_cursor(CursorIcon::PointingHand)
}

/// A collapsing header's icon: the task pane's round fold button.
pub fn expander(ui: &mut Ui, openness: f32, response: &Response) {
    fold_button(
        ui.painter(),
        response.rect.center(),
        openness > 0.5,
        response.hovered(),
    );
}

/// A section title the way XP groups a folder: bold blue words over a
/// rule that fades out to the right.
pub fn group_header(ui: &mut Ui, title: &str, note: Option<&str>) {
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(vec2(width, 26.0), Sense::hover());
    let p = ui.painter();
    let text = p.text(
        pos2(rect.left(), rect.center().y - 1.0),
        Align2::LEFT_CENTER,
        title,
        font(CAPTION, 15.0),
        rgb(22, 64, 168),
    );
    if let Some(note) = note {
        p.text(
            pos2(text.right() + 10.0, rect.center().y),
            Align2::LEFT_CENTER,
            note,
            ui_font(12.0),
            rgb(90, 100, 130),
        );
    }
    let rule = Rect::from_min_size(
        pos2(rect.left(), rect.bottom() - 1.0),
        vec2(width.min(640.0), 1.0),
    );
    across(p, rule, rgb(64, 118, 214), Color32::WHITE);
    ui.add_space(8.0);
}

/// A list view's column header strip.
pub fn list_header(p: &Painter, rect: Rect) {
    gradient(
        p,
        rect,
        0,
        &[
            (0.0, Color32::WHITE),
            (0.8, rgb(242, 241, 234)),
            (1.0, rgb(235, 234, 219)),
        ],
    );
    p.hline(
        rect.x_range(),
        rect.bottom() - 1.5,
        Stroke::new(1.0, rgb(214, 210, 194)),
    );
    p.hline(
        rect.x_range(),
        rect.bottom() - 0.5,
        Stroke::new(1.0, rgb(203, 199, 184)),
    );
}

/// One column of it: an etched divider, and the orange underline XP
/// shows under the header the pointer is on.
pub fn list_column(p: &Painter, rect: Rect, sorted: bool, hot: bool) {
    if sorted {
        p.rect_filled(
            rect.shrink2(vec2(0.0, 1.0)),
            0,
            Color32::from_black_alpha(6),
        );
    }
    let x = rect.right() - 1.0;
    let y = (rect.top() + 4.0)..=(rect.bottom() - 5.0);
    p.vline(x, y.clone(), Stroke::new(1.0, rgb(199, 197, 178)));
    p.vline(x + 1.0, y, Stroke::new(1.0, Color32::WHITE));
    if hot {
        p.rect_filled(
            Rect::from_min_max(
                pos2(rect.left(), rect.bottom() - 3.0),
                pos2(rect.right() - 1.0, rect.bottom()),
            ),
            0,
            rgb(249, 177, 25),
        );
    }
}

/// A list view's row: pale blue when chosen, a whisper under the pointer.
pub fn list_row(p: &Painter, rect: Rect, selected: bool, hot: bool) {
    if selected {
        p.rect_filled(rect, 0, rgb(193, 210, 238));
        p.rect_stroke(rect, 0, Stroke::new(1.0, SELECTION), StrokeKind::Inside);
    } else if hot {
        p.rect_filled(rect, 0, rgb(238, 243, 251));
    }
    p.hline(
        rect.x_range(),
        rect.bottom() - 0.5,
        Stroke::new(1.0, rgb(240, 239, 232)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tray_clock_reads_like_xp() {
        assert_eq!(twelve_hour(0), "12:00 AM");
        assert_eq!(twelve_hour(9 * 3600 + 5 * 60), "9:05 AM");
        assert_eq!(twelve_hour(12 * 3600 + 30 * 60), "12:30 PM");
        assert_eq!(twelve_hour(23 * 3600 + 59 * 60), "11:59 PM");
        assert_eq!(twelve_hour(-60), "11:59 PM");
    }

    #[test]
    fn gradients_keep_every_stop() {
        let stops = [
            (0.0, Color32::BLACK),
            (0.5, Color32::WHITE),
            (1.0, Color32::BLACK),
        ];
        assert_eq!(at(&stops, 0.5), Color32::WHITE);
        assert_eq!(at(&stops, 0.0), Color32::BLACK);
        assert_eq!(at(&stops, 1.0), Color32::BLACK);
    }
}
