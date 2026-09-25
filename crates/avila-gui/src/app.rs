//! The window: the brand rail, the status line, and the current page.

use crate::bench::Bench;
use crate::capture::Capture;
use crate::constellation::Constellation;
use crate::pages::peers::PeerSort;
use crate::pages::{self, Action, Scene};
use crate::prefs::{Prefs, ThemeChoice};
use crate::rail::{self, Page};
use crate::ribbon::View;
use crate::session::{ActivityKind, Phase, RunSettings, Session};
use crate::theme::{self, Palette, Skin, font};
use crate::toybox;
use crate::widgets::{self, Kind, hatch};
use crate::{brand, model, xp};
use avila_node::Node;
use avila_node::events::NodeEvent;
use eframe::egui::{
    self, Align, Frame, Key, Layout, Margin, RichText, ScrollArea, Sense, Stroke, TextureHandle,
    Ui, vec2,
};
use std::time::Duration;

pub struct App {
    node: Node,
    session: Session,
    page: Page,
    run: RunSettings,
    prefs: Prefs,
    filter: Option<ActivityKind>,
    swirl: Option<TextureHandle>,
    capture: Option<Capture>,
    bench: Option<Bench>,
    autostart: bool,
    /// The peer whose panel is open on the Peers page.
    selected_peer: Option<u64>,
    sky: Constellation,
    peer_sort: PeerSort,
    /// The Chain page's zoom into the ribbon.
    ribbon_view: View,
    game: toybox::Game,
    /// The preferences last put in force; any change re-applies them.
    applied: Prefs,
    /// The Windows XP skin's desktop.
    xp: xp::Xp,
    /// Pages visited, and pages gone back from, for XP's Back and
    /// Forward; `seen` is the page as of the last frame.
    history: Vec<Page>,
    ahead: Vec<Page>,
    seen: Page,
    /// Start the node again once it has stopped.
    restart: bool,
    /// Whether the system draws the window's frame (not under XP, which
    /// draws its own); `None` until first asked.
    decorated: Option<bool>,
    /// Save preferences on exit (not for captures or one-run skins).
    keep_prefs: bool,
    /// The first-open slideshow — `Some(step)` while it runs.
    tour: Option<usize>,
    /// SIGINT/SIGTERM request — closing through eframe runs on_exit,
    /// which drains the sync worker so state.dat actually writes.
    close: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl App {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        node: Node,
        demo: bool,
        theme_override: Option<ThemeChoice>,
        close: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        let ctx = &cc.egui_ctx;
        theme::install_fonts(ctx, Skin::Standard);
        theme::install_style(ctx);
        let mut prefs = Prefs::load(cc.storage);
        if let Some(choice) = theme_override {
            prefs.theme = choice;
        }
        // `AVILA_GUI_SKIN=xp` (or `julia`) wears a toybox skin for this
        // run only, for development.
        let skin = std::env::var("AVILA_GUI_SKIN")
            .ok()
            .map(|s| match s.as_str() {
                "xp" => Skin::Xp,
                "julia" => Skin::Julia,
                _ => Skin::Standard,
            });
        if let Some(skin) = skin {
            prefs.toybox = true;
            prefs.skin = skin;
        }
        let capture = Capture::from_env();
        let keep_prefs = capture.is_none() && skin.is_none();
        prefs.apply(ctx);
        let network = node.config().get().network;
        let mut run = RunSettings::new(network);
        // The proxy choice persists — privacy stays binding across
        // restarts instead of silently reverting to direct dials.
        run.proxy = prefs.proxy.clone();
        // The config file's prune_mb (Core's -prune in bitcoin.conf)
        // seeds the settings field — an IBD on a small disk must be
        // pruned from block one, not after the settings page opens.
        if let Some(mb) = node.config().get().prune_mb {
            run.prune_mib = mb.to_string();
        }
        let applied = prefs.clone();
        let mut session = Session::new(demo);
        // The node's own journal opens the activity log.
        for record in node.events().entries() {
            session.log(
                ActivityKind::Node,
                journal_text(record.event).into(),
                None,
                0.0,
            );
        }
        // Networks with DNS seeds (or an explicit peer list) start right
        // away, as a node should; tests never touch the network.
        // First launch shows the welcome sheet instead of syncing
        // silently — a new user picks prune/verify/proxy and presses
        // Start. Returning launches autostart as before.
        let autostart = !cfg!(test)
            && (demo
                || (prefs.welcomed
                    && (network != avila_core::Network::Regtest
                        || !run.connect.trim().is_empty())));
        let show_tour = !demo && !prefs.welcomed;
        Self {
            node,
            session,
            // `AVILA_GUI_PAGE=peers` opens on that page (for development).
            page: std::env::var("AVILA_GUI_PAGE")
                .ok()
                .and_then(|want| {
                    Page::ALL
                        .into_iter()
                        .find(|p| p.label().eq_ignore_ascii_case(&want))
                })
                .unwrap_or_default(),
            run,
            prefs,
            filter: None,
            swirl: brand::swirl_texture(ctx),
            capture,
            keep_prefs,
            tour: show_tour.then_some(0),
            close,
            bench: Bench::from_env(),
            autostart,
            selected_peer: None,
            sky: Constellation::default(),
            peer_sort: PeerSort::default(),
            ribbon_view: View::default(),
            game: toybox::Game::default(),
            applied,
            xp: xp::Xp::default(),
            history: Vec::new(),
            ahead: Vec::new(),
            seen: Page::default(),
            restart: false,
            decorated: None,
        }
    }

    fn network(&self) -> avila_core::Network {
        self.node.config().get().network
    }

    /// The network on screen: the simulator always plays mainnet.
    fn shown_network(&self) -> avila_core::Network {
        if self.session.demo {
            avila_core::Network::Mainnet
        } else {
            self.network()
        }
    }

    fn start(&mut self) {
        let data_dir = self.node.config().network_data_dir();
        self.session.start(self.network(), data_dir, &self.run);
    }

    /// The current page inside its margins; either layout wraps it.
    fn page_body(
        &mut self,
        ui: &mut Ui,
        pal: Palette,
        network: avila_core::Network,
        open_advanced: bool,
        margin: Margin,
    ) -> Option<Action> {
        let mut action = None;
        Frame::new().inner_margin(margin).show(ui, |ui| {
            let scene = Scene {
                pal,
                session: &self.session,
                network,
                swirl: self.swirl.as_ref(),
            };
            action = if !self.prefs.welcomed && !self.session.demo && self.tour.is_none() {
                pages::welcome::show(ui, &scene, &mut self.run)
            } else {
                match self.page {
                    Page::Overview => pages::overview::show(ui, &scene, &mut self.prefs.scale),
                    Page::Chain => pages::chain::show(
                        ui,
                        &scene,
                        &mut self.prefs.scale,
                        &mut self.ribbon_view,
                        &mut self.prefs.rhythm_clock,
                    ),
                    Page::Peers => pages::peers::show(
                        ui,
                        &scene,
                        &mut self.selected_peer,
                        &mut self.sky,
                        &mut self.peer_sort,
                        self.prefs.hide_addresses,
                    ),
                    Page::Activity => pages::activity::show(
                        ui,
                        &scene,
                        &mut self.filter,
                        self.prefs.hide_addresses,
                    ),
                    Page::Toybox => {
                        toybox::show(ui, &scene, &mut self.game, &mut self.prefs);
                        None
                    }
                    Page::Settings => pages::settings::show(
                        ui,
                        &scene,
                        &mut self.run,
                        &mut self.prefs,
                        &self.node,
                        open_advanced,
                    ),
                }
            };
        });
        // The first-run slideshow rides on top of whatever the page
        // just drew — the app stays live behind the dim.
        if let Some(step) = self.tour {
            match pages::tour::show(ui, &pal, step) {
                Some(pages::tour::TourAction::Next) => {
                    self.tour = Some((step + 1).min(pages::tour::slide_count() - 1));
                }
                Some(pages::tour::TourAction::Back) => {
                    self.tour = Some(step.saturating_sub(1));
                }
                Some(pages::tour::TourAction::Skip) => self.tour = None,
                None => {}
            }
        }
        action
    }

    /// The pages on offer: the toybox joins while it's on.
    fn pages(&self) -> Vec<Page> {
        let mut pages = Page::ALL.to_vec();
        if self.prefs.toybox {
            pages.insert(pages.len() - 1, Page::Toybox);
        }
        pages
    }

    /// What the XP skin's chrome shows of the node this frame.
    fn xp_chrome(&self, ctx: &egui::Context, phase: Phase) -> xp::Chrome {
        let network = network_name(self.shown_network());
        let view = self.session.view.as_ref();
        let peers = view.map(|v| v.established().count());
        let mut details = vec![
            "Avila Node".to_owned(),
            format!("{network}, {}", phase.label().to_lowercase()),
        ];
        let mut panels = vec![phase.label().to_owned()];
        if let Some(v) = view {
            let n = peers.unwrap_or(0);
            let lines = [
                format!("Block {}", model::thousands(v.connected.into())),
                format!("{n} peer{}", if n == 1 { "" } else { "s" }),
                format!("Up {}", model::span(v.uptime_secs)),
            ];
            details.extend(lines.iter().cloned());
            panels.extend(lines);
        }
        panels.push(network.to_owned());
        xp::Chrome {
            title: format!("{} - Avila Node", self.page.label()),
            page: self.page,
            pages: self.pages(),
            swirl: self.swirl.clone(),
            running: self.session.running(),
            busy: phase == Phase::Stopping,
            hide: self.prefs.hide_addresses,
            back: !self.history.is_empty(),
            forward: !self.ahead.is_empty(),
            signs: view.map(|v| v.eclipse.clone()).unwrap_or_default(),
            peers: peers.filter(|_| self.session.running()),
            demo: self.session.demo,
            path: format!("Avila Node\\{network}\\{}", self.page.label()),
            details,
            panels,
            // Captures keep the active look, whatever has the focus.
            focused: self.capture.is_some() || ctx.input(|i| i.viewport().focused.unwrap_or(true)),
        }
    }

    fn go_back(&mut self) {
        if let Some(page) = self.history.pop() {
            self.ahead.push(self.page);
            self.page = page;
            self.seen = page;
        }
    }

    fn go_forward(&mut self) {
        if let Some(page) = self.ahead.pop() {
            self.history.push(self.page);
            self.page = page;
            self.seen = page;
        }
    }

    fn shortcuts(&mut self, ctx: &egui::Context) {
        let keys = [Key::Num1, Key::Num2, Key::Num3, Key::Num4, Key::Num5];
        ctx.input(|i| {
            if i.modifiers.command {
                for (key, page) in keys.iter().zip(Page::ALL) {
                    if i.key_pressed(*key) {
                        self.page = page;
                    }
                }
                if i.modifiers.shift && i.key_pressed(Key::H) {
                    self.prefs.hide_addresses = !self.prefs.hide_addresses;
                }
            }
        });
    }

    /// Block, peers, network, uptime: one line under every page.
    fn context_line(&self) -> String {
        let network = network_name(self.shown_network());
        match &self.session.view {
            Some(v) => {
                let peers = v.established().count();
                format!(
                    "Block {} · {} peer{} · {network} · up {}",
                    model::thousands(v.connected.into()),
                    peers,
                    if peers == 1 { "" } else { "s" },
                    model::span(v.uptime_secs)
                )
            }
            None => network.to_owned(),
        }
    }

    fn status_line(&self, ui: &mut Ui, pal: Palette, phase: Phase) -> Option<Action> {
        let mut action = None;
        // Controls claim their space first; the status text takes the rest
        // and elides when the window is narrow.
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if phase == Phase::Stopping {
                ui.label(
                    RichText::new("Saving the chainstate…")
                        .size(13.5)
                        .color(pal.muted),
                );
            } else if self.session.running() {
                if widgets::button(ui, "Stop node", Kind::Quiet).clicked() {
                    action = Some(Action::Stop);
                }
            } else if widgets::button(ui, "Start node", Kind::Primary).clicked() {
                action = Some(Action::Start);
            }
            if self.session.demo {
                ui.add_space(6.0);
                demo_badge(ui, pal);
            }
            if self
                .session
                .view
                .as_ref()
                .is_some_and(|v| !v.eclipse.is_empty())
            {
                ui.add_space(6.0);
                let warn = ui
                    .add(
                        egui::Button::new(
                            RichText::new("Possible eclipse")
                                .font(font(theme::MEDIUM, 12.5))
                                .color(pal.alert),
                        )
                        .fill(pal.alert.gamma_multiply(0.08))
                        .stroke(Stroke::new(1.0, pal.alert.gamma_multiply(0.6))),
                    )
                    .on_hover_text("The node sees signs its peers may be controlled by one attacker. Open Peers for details.");
                if warn.clicked() {
                    action = Some(Action::Open(Page::Peers));
                }
            }
            ui.add_space(16.0);
            ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                let (r, _) = ui.allocate_exact_size(vec2(18.0, 18.0), Sense::hover());
                let (c, p) = (r.center(), ui.painter());
                match phase {
                    Phase::CaughtUp | Phase::Syncing if pal.hearts => {
                        crate::julia::heart(p, c, 16.0, pal.signal);
                    }
                    Phase::CaughtUp | Phase::Syncing => {
                        p.circle_filled(c, 9.0, pal.signal_alpha(0.22));
                        p.circle_filled(c, 5.0, pal.signal);
                    }
                    Phase::Connecting => {
                        p.circle_stroke(c, 5.0, Stroke::new(1.6, pal.text));
                    }
                    Phase::Stopping => {
                        p.circle_stroke(c, 5.0, Stroke::new(1.6, pal.muted));
                    }
                    Phase::Failed => {
                        p.circle_filled(c, 5.0, pal.alert);
                    }
                    Phase::Idle | Phase::Stopped => {
                        p.circle_filled(c, 5.0, pal.faint);
                    }
                }
                ui.label(
                    RichText::new(phase.label())
                        .font(font(theme::TITLE, 20.0))
                        .color(pal.text),
                );
                ui.add_space(6.0);
                ui.add(
                    egui::Label::new(
                        RichText::new(self.context_line())
                            .size(13.5)
                            .color(pal.muted),
                    )
                    .truncate(),
                );
            });
        });
        action
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut Ui, frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        // A SIGINT/SIGTERM lands as a window close, so on_exit's
        // stop-and-drain runs the same as clicking ×.
        if self.close.load(std::sync::atomic::Ordering::Relaxed) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        if std::mem::take(&mut self.autostart) {
            self.start();
        }
        self.session.poll();
        if self.restart && !self.session.running() && self.session.phase() != Phase::Stopping {
            self.restart = false;
            self.start();
        }
        if let Some(page) = self
            .bench
            .as_mut()
            .and_then(|b| b.drive(&ctx, frame.info().cpu_usage))
        {
            self.page = page;
        }
        let mut pose_scroll = None;
        let mut open_advanced = false;
        if let Some(pose) = self.capture.as_mut().and_then(|c| c.drive(&ctx)) {
            pose_scroll = Some(pose.scroll);
            open_advanced = pose.advanced;
            self.prefs.hide_addresses = pose.hide;
            self.prefs.rhythm_clock = pose.clock;
            if let Some((lo, hi)) = pose.zoom {
                self.ribbon_view = View { lo, hi };
            }
            if pose.eclipse
                && let Some(v) = self.session.view.as_mut()
            {
                v.eclipse = vec![crate::model::Eclipse::DiversityCollapse];
            }
            self.prefs.toybox |= pose.page == Page::Toybox || pose.skin != Skin::Standard;
            self.prefs.skin = pose.skin;
            self.xp.start_open = pose.desk == crate::capture::Desk::StartMenu;
            self.xp.restored = pose.desk == crate::capture::Desk::Restored;
            self.xp.dialog = match pose.desk {
                crate::capture::Desk::TurnOff => xp::Dialog::TurnOff,
                crate::capture::Desk::About => xp::Dialog::About,
                _ => xp::Dialog::None,
            };
            if pose.play {
                if !self.game.animating() {
                    self.game.demo();
                }
            } else if pose.over {
                if !self.game.over() {
                    self.game.demo_over();
                }
            } else {
                self.game.shelve();
            }
            self.page = pose.page;
            self.prefs.scale = pose.scale;
            if pose.select_peer && self.selected_peer.is_none() {
                self.selected_peer = self
                    .session
                    .view
                    .as_ref()
                    .and_then(|v| v.established().find(|p| p.session_id.is_some()))
                    .map(|p| p.id);
            }
        }
        self.shortcuts(&ctx);
        let pal = Palette::of(&ctx);
        let phase = self.session.phase();
        let network = self.shown_network();
        let mut action = None;

        if Skin::current() == Skin::Xp {
            let chrome = self.xp_chrome(&ctx, phase);
            let mut desk = std::mem::take(&mut self.xp);
            let mut pick = None;
            let mut page_action = None;
            egui::CentralPanel::default()
                .frame(Frame::NONE)
                .show(ui, |ui| {
                    pick = xp::desktop(ui, &mut desk, &chrome, pose_scroll, |ui| {
                        page_action = self.page_body(
                            ui,
                            pal,
                            network,
                            open_advanced,
                            Margin {
                                left: 26,
                                right: 22,
                                top: 18,
                                bottom: 30,
                            },
                        );
                    });
                });
            self.xp = desk;
            action = page_action;
            match pick {
                Some(xp::Pick::Open(page)) => action = Some(Action::Open(page)),
                Some(xp::Pick::Back) => self.go_back(),
                Some(xp::Pick::Forward) => self.go_forward(),
                Some(xp::Pick::ToggleHide) => {
                    self.prefs.hide_addresses = !self.prefs.hide_addresses;
                }
                Some(xp::Pick::LogOff) => self.prefs.skin = Skin::Standard,
                Some(xp::Pick::StartNode) => action = Some(Action::Start),
                Some(xp::Pick::StopNode) => action = Some(Action::Stop),
                Some(xp::Pick::RestartNode) if self.session.running() => {
                    self.restart = true;
                    action = Some(Action::Stop);
                }
                Some(xp::Pick::RestartNode) => action = Some(Action::Start),
                None => {}
            }
        } else {
            egui::Panel::left("rail")
                .exact_size(rail::WIDTH)
                .resizable(false)
                .show_separator_line(false)
                .frame(Frame::new().fill(pal.rail))
                .show(ui, |ui| {
                    rail::show(
                        ui,
                        &mut self.page,
                        self.swirl.as_ref(),
                        network_name(network),
                        phase.live(),
                        self.prefs.toybox,
                    );
                });
            egui::Panel::top("status")
                .exact_size(68.0)
                .resizable(false)
                .show_separator_line(false)
                .frame(Frame::new().fill(pal.canvas).inner_margin(Margin {
                    left: 30,
                    right: 30,
                    top: 0,
                    bottom: 0,
                }))
                .show(ui, |ui| {
                    action = self.status_line(ui, pal, phase);
                });
            egui::CentralPanel::default()
                .frame(Frame::new().fill(pal.canvas))
                .show(ui, |ui| {
                    let top = ui.max_rect();
                    if crate::julia::on() {
                        crate::julia::wallpaper(ui.painter(), top, ui.input(|i| i.time));
                    }
                    ui.painter().hline(
                        top.x_range(),
                        top.top() + 0.5,
                        Stroke::new(1.0, pal.hairline),
                    );
                    let mut scroll = ScrollArea::vertical().auto_shrink([false, false]);
                    if let Some(y) = pose_scroll {
                        scroll = scroll.vertical_scroll_offset(y);
                    }
                    scroll.show(ui, |ui| {
                        let page_action = self.page_body(
                            ui,
                            pal,
                            network,
                            open_advanced,
                            Margin {
                                left: 32,
                                right: 32,
                                top: 26,
                                bottom: 40,
                            },
                        );
                        if page_action.is_some() {
                            action = page_action;
                        }
                    });
                });
        }

        match action {
            Some(Action::Start) => {
                self.prefs.welcomed = true;
                self.start();
            }
            Some(Action::Stop) => self.session.stop(),
            Some(Action::Open(page)) => self.page = page,
            Some(Action::ReplayTour) => self.tour = Some(0),
            None => {}
        }
        // Preferences changed anywhere (Settings, the toybox, a shortcut)
        // are put in force here, once.
        if self.prefs != self.applied {
            self.prefs.apply(&ctx);
            self.applied = self.prefs.clone();
        }
        if self.page == Page::Toybox && !self.prefs.toybox {
            self.page = Page::Settings;
        }
        if self.page != self.seen {
            self.history.push(self.seen);
            if self.history.len() > 32 {
                self.history.remove(0);
            }
            self.ahead.clear();
            self.seen = self.page;
        }
        // XP draws its own title bar, so the system's goes while it's on.
        let framed = Skin::current() != Skin::Xp;
        if self.decorated != Some(framed) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Decorations(framed));
            self.decorated = Some(framed);
        }
        // Smooth frames only while the new-block pulse runs; otherwise
        // just often enough for "seconds ago" to tick over.
        // Only the pages that draw the new-block pulse animate for it.
        let shows_pulse = matches!(self.page, Page::Overview | Page::Chain | Page::Peers);
        let pulsing = shows_pulse
            && Scene {
                pal,
                session: &self.session,
                network,
                swirl: None,
            }
            .pulse()
            .is_some();
        let settling = (self.page == Page::Peers && self.sky.animating())
            || (self.page == Page::Toybox && self.game.animating());
        let benching = self.bench.as_ref().is_some_and(Bench::forcing);
        if self.capture.is_some() || pulsing || settling || benching {
            ctx.request_repaint();
        } else if self.session.running() {
            ctx.request_repaint_after(Duration::from_millis(250));
        } else {
            ctx.request_repaint_after(Duration::from_secs(1));
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if !self.session.running() {
            return;
        }
        // Window-close kills the process — without this the sync
        // worker dies mid-run and every header learned this session
        // is lost. Stop + drain until the worker's exit-path flush
        // reports back, bounded so a wedged worker can't hold the
        // window open.
        self.session.stop();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while self.session.running() && std::time::Instant::now() < deadline {
            self.session.poll();
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        // A capture run poses the app, and a skin from the environment is
        // for one run; neither may overwrite real choices.
        if self.keep_prefs {
            self.prefs.proxy = self.run.proxy.trim().to_string();
            self.prefs.save(storage);
        }
    }

    fn raw_input_hook(&mut self, _ctx: &egui::Context, raw_input: &mut egui::RawInput) {
        if let Some(capture) = &mut self.capture {
            capture.feed(raw_input);
        }
    }

    fn persist_egui_memory(&self) -> bool {
        false
    }

    fn clear_color(&self, visuals: &egui::Visuals) -> [f32; 4] {
        visuals.panel_fill.to_normalized_gamma_f32()
    }
}

/// Says, wherever it shows, that nothing on screen is real.
fn demo_badge(ui: &mut Ui, pal: Palette) {
    let galley = ui.painter().layout_no_wrap(
        "Simulated data".to_owned(),
        font(theme::MEDIUM, 12.5),
        pal.text,
    );
    let (r, resp) = ui.allocate_exact_size(galley.size() + vec2(22.0, 12.0), Sense::hover());
    let p = ui.painter();
    p.rect_filled(r, 6, pal.well);
    hatch(p, r, pal.hairline, 5.0, 1.2);
    p.rect_stroke(r, 6, Stroke::new(1.0, pal.faint), egui::StrokeKind::Inside);
    p.galley(r.center() - galley.size() / 2.0, galley, pal.text);
    resp.on_hover_text("Started with --demo. Nothing on screen comes from the network.");
}

fn network_name(network: avila_core::Network) -> &'static str {
    match network {
        avila_core::Network::Mainnet => "Mainnet",
        avila_core::Network::Testnet4 => "Testnet4",
        avila_core::Network::Signet => "Signet",
        avila_core::Network::Regtest => "Regtest",
    }
}

fn journal_text(event: NodeEvent) -> &'static str {
    match event {
        NodeEvent::ConfigurationLoaded => "Loaded the configuration; it passed validation.",
        NodeEvent::StartupBlocked => {
            "Refused to start the persistent services; they aren’t wired up yet."
        }
    }
}
