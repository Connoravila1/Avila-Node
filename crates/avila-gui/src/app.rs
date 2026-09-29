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
use crate::{brand, classic, model, phosphor, xp};
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
    /// The Config page's live-edit state — drafts, pending, overrides.
    config_page: pages::config::ConfigPage,
    /// The TOML this node was loaded from — the Config page offers it
    /// up for the knobs that only a restart can apply.
    config_file: Option<std::path::PathBuf>,
    /// Last-seen mtimes of the config file and its runtime overlay —
    /// the watch that powers the "changes detected" banner.
    config_mtime: (Option<std::time::SystemTime>, Option<std::time::SystemTime>),
    /// Knob paths whose on-disk value differs from what the node has
    /// loaded (`Some(vec![])` = the file changed but can't be read).
    config_dirty: Option<Vec<String>>,
    /// The file-watch's last stat — polling every frame is rude.
    config_checked: std::time::Instant,
    /// The toybox's shelf: every game, the hash-fed toys, the confetti.
    toys: toybox::Toys,
    /// The toy a capture posed, so it isn't re-posed every frame.
    toy_posed: u8,
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
    /// Restore the user's window size after the original client's compact frame.
    classic_restore_size: Option<egui::Vec2>,
    /// Save preferences on exit (not for captures or one-run skins).
    keep_prefs: bool,
    /// The first-open slideshow — `Some(step)` while it runs.
    tour: Option<usize>,
    /// The node event stream's tail — events.ndjson feeds the
    /// activity log instead of the in-process journal, so the log
    /// shows the same truth `--follow` sees (hooks, extrapool, risks).
    events_tail: Option<avila_node::events::EventTail>,
    /// SIGINT/SIGTERM request — closing through eframe runs on_exit,
    /// which drains the sync worker so state.dat actually writes.
    close: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl App {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        node: Node,
        demo: bool,
        fast_ibd: bool,
        theme_override: Option<ThemeChoice>,
        close: std::sync::Arc<std::sync::atomic::AtomicBool>,
        // The TOML the node was loaded from — restart knobs open it.
        config_file: Option<std::path::PathBuf>,
    ) -> Self {
        let ctx = &cc.egui_ctx;
        // A signal lands whenever it lands — the window may be idle and
        // not repainting, so a watcher thread turns it into a viewport
        // close (which itself wakes the event loop) rather than a flag
        // only polled from ui().
        {
            let wake_ctx = ctx.clone();
            let flag = close.clone();
            std::thread::spawn(move || {
                use std::sync::atomic::Ordering::Relaxed;
                while !flag.load(Relaxed) {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                wake_ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            });
        }
        theme::install_fonts(ctx, Skin::Standard);
        theme::install_style(ctx);
        let mut prefs = Prefs::load(cc.storage);
        if let Some(choice) = theme_override {
            prefs.theme = choice;
        }
        // `AVILA_GUI_SKIN=xp` (or `julia`, `tip`, `phosphor`, `classic`)
        // wears a toybox skin for this run only, for development.
        let skin = std::env::var("AVILA_GUI_SKIN")
            .ok()
            .map(|s| match s.as_str() {
                "xp" => Skin::Xp,
                "julia" => Skin::Julia,
                "tip" => Skin::Tip,
                "phosphor" => Skin::Phosphor,
                "classic" => Skin::Classic,
                _ => Skin::Standard,
            });
        if let Some(skin) = skin {
            prefs.toybox = true;
            prefs.skin = skin;
        }
        let capture = Capture::from_env();
        let keep_prefs = capture.is_none() && skin.is_none();
        prefs.apply(ctx);
        if prefs.skin == Skin::Classic {
            ctx.send_viewport_cmd(egui::ViewportCommand::Icon(classic::window_icon()));
            ctx.send_viewport_cmd(egui::ViewportCommand::MinInnerSize(vec2(705.0, 331.0)));
            if capture.is_none() {
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(vec2(705.0, 484.0)));
            }
        }
        let network = node.config().get().network;
        let mut run = RunSettings::new(network);
        // The proxy choice persists — privacy stays binding across
        // restarts instead of silently reverting to direct dials.
        run.proxy = prefs.proxy.clone();
        // The config file's storage.prune_mb (Core's -prune in
        // bitcoin.conf) seeds the settings field — an IBD on a small
        // disk must be pruned from block one, not after the settings
        // page opens.
        if let Some(mb) = node.config().get().storage.prune_mb {
            run.prune_mib = mb.to_string();
        }
        // `net.connect` in the config seeds the same field — running
        // the GUI against a file should connect to its peers, not the
        // hardcoded regtest default.
        let connect = node
            .config()
            .get()
            .net
            .connect
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        if !connect.is_empty() {
            run.connect = connect;
        }
        // `--fast-ibd` overrides the welcome/settings default for this
        // launch — the running node's choice, not a persisted pref.
        if fast_ibd {
            run.fast_ibd = true;
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
        // From here the live log is the event stream — opened before
        // the run starts so run_started/risks/spawn failures land.
        let events_tail = Some(avila_node::events::EventTail::follow(
            node.config()
                .network_data_dir()
                .join(avila_node::events::EVENTS_FILENAME),
        ));
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
        let mut s = Self {
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
            config_page: pages::config::ConfigPage::default(),
            toys: toybox::Toys::default(),
            toy_posed: 0,
            applied,
            xp: xp::Xp::default(),
            history: Vec::new(),
            ahead: Vec::new(),
            seen: Page::default(),
            restart: false,
            events_tail,
            decorated: None,
            classic_restore_size: None,
            config_mtime: (
                config_file
                    .as_ref()
                    .and_then(|f| std::fs::metadata(f).ok())
                    .and_then(|m| m.modified().ok()),
                config_file
                    .as_ref()
                    .map(|f| avila_node::config::overlay_path(f))
                    .and_then(|f| std::fs::metadata(f).ok())
                    .and_then(|m| m.modified().ok()),
            ),
            config_dirty: None,
            config_checked: std::time::Instant::now(),
            config_file,
        };
        // The compositor may never send a frame callback while the
        // window is occluded — a node must sync anyway, so the worker
        // starts here, not on the first repaint.
        if autostart {
            s.autostart = false;
            s.start();
        }
        s
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
        // Re-read the file so edits made between runs actually land —
        // the Config page's "restart to apply" banner depends on it.
        if let Some(file) = &self.config_file {
            match avila_node::config::load_config(Some(file)) {
                Ok(v) => {
                    self.node.replace_config(v);
                    self.config_dirty = None;
                }
                Err(_) => {
                    self.session.log(
                        ActivityKind::Node,
                        "The config file doesn't parse — keeping the loaded configuration.".into(),
                        None,
                        self.session.now(),
                    );
                }
            }
        }
        let data_dir = self.node.config().network_data_dir();
        self.session.start(
            self.network(),
            data_dir,
            &self.run,
            self.node.config().get(),
        );
    }

    /// Watch the config file and its runtime overlay; when either
    /// moves, reload and diff the merged knobs against what the node
    /// has loaded. Live edits that already applied (or are in flight)
    /// with the same value don't count — the file isn't diverged, it's
    /// just ahead of the loaded snapshot.
    fn poll_config_file(&mut self) {
        let Some(file) = &self.config_file else {
            return;
        };
        if self.config_checked.elapsed() < std::time::Duration::from_millis(700) {
            return;
        }
        self.config_checked = std::time::Instant::now();
        let overlay = avila_node::config::overlay_path(file);
        let mtime = (
            std::fs::metadata(file).ok().and_then(|m| m.modified().ok()),
            std::fs::metadata(&overlay)
                .ok()
                .and_then(|m| m.modified().ok()),
        );
        if mtime == self.config_mtime {
            return;
        }
        self.config_mtime = mtime;
        match avila_node::config::load_config(Some(file)) {
            Ok(v) => {
                use std::collections::HashMap;
                let base: HashMap<String, serde_json::Value> =
                    avila_node::config::describe_config(self.node.config().get())
                        .iter()
                        .map(|k| (k.path.to_string(), k.value.clone()))
                        .collect();
                let diffs: Vec<String> = avila_node::config::describe_config(v.get())
                    .iter()
                    .filter(|k| base.get(k.path) != Some(&k.value))
                    .filter(|k| !self.config_page.already_live(k.path, &k.value))
                    .map(|k| k.path.to_string())
                    .collect();
                self.config_dirty = (!diffs.is_empty()).then_some(diffs);
            }
            Err(_) => self.config_dirty = Some(vec![]),
        }
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
                    Page::Overview if Skin::current() == Skin::Classic => {
                        classic::overview(ui, &scene);
                        None
                    }
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
                    Page::Config => pages::config::show(
                        ui,
                        &scene,
                        &mut self.config_page,
                        &self.node,
                        &mut self.prefs,
                        self.session.control_sender(),
                        self.config_file.as_deref(),
                        self.config_dirty.as_deref(),
                    ),
                    Page::Toybox => {
                        toybox::show(ui, &scene, &mut self.toys, &mut self.prefs);
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
                use avila_node::sync::Phase as NPhase;
                // Startup phases report what the node is actually doing —
                // counters like "Block 133,875 · 0 peers" would lie while
                // the node is still replaying its backlog.
                match v.phase {
                    NPhase::Opening => format!("Opening the block store · {network}"),
                    NPhase::RestoringHeaders { done, total } => format!(
                        "Restoring headers — {} of {} · {network}",
                        model::thousands(done),
                        model::thousands(total)
                    ),
                    NPhase::VerifyingChain { done, total } => format!(
                        "Verifying the saved chain — {} of {} · {network}",
                        model::thousands(done),
                        model::thousands(total)
                    ),
                    NPhase::ReconcilingBackend => {
                        format!("Reconciling the coins database · {network}")
                    }
                    NPhase::ReplayingBodies { done, total, tip } => format!(
                        "Replaying saved blocks — {} of {}, at height {} · {network}",
                        model::thousands(done),
                        model::thousands(total),
                        model::thousands(tip.into())
                    ),
                    _ => {
                        let peers = v.established().count();
                        format!(
                            "Block {} · {} peer{} · {network} · up {}",
                            model::thousands(v.connected.into()),
                            peers,
                            if peers == 1 { "" } else { "s" },
                            model::span(v.uptime_secs)
                        )
                    }
                }
            }
            None => {
                if self.session.running() {
                    format!("Starting up · {network}")
                } else {
                    network.to_owned()
                }
            }
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
            // The tip skin wears its block — name it.
            if Skin::current() == Skin::Tip
                && let Some((h, hash)) = self
                    .session
                    .view
                    .as_ref()
                    .and_then(|v| v.recent.last())
            {
                ui.add_space(6.0);
                let tail = &hash[hash.len().saturating_sub(8)..];
                ui.label(
                    RichText::new(format!("dressed by {h} · …{tail}"))
                        .font(font(theme::MONO_MEDIUM, 11.5))
                        .color(pal.signal_text),
                );
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
                    Phase::Connecting | Phase::Starting => {
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
        self.poll_config_file();
        // The Tip skin's seed is the tip's hash — a new block repaints
        // the whole node in the hash's hue.
        let seed = tip_hash_seed(&self.session);
        if seed != theme::tip_seed() {
            theme::set_tip_seed(seed);
            if Skin::current() == Skin::Tip {
                theme::set_skin(&ctx, Skin::Tip);
            }
        }
        // Stream events into the activity log — bounded per frame so
        // a busy tick can't stall the render.
        if let Some(tail) = &mut self.events_tail {
            for ev in tail.read_new(128) {
                self.config_page.note(&ev);
                if let Some(text) = stream_text(&ev) {
                    self.session.log(ActivityKind::Node, text, None, 0.0);
                }
            }
        }
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
            self.prefs.toybox |=
                pose.page == Page::Toybox || pose.skin != Skin::Standard || pose.toy > 0;
            if pose.pointer.is_empty() || pose.first {
                self.prefs.skin = pose.skin;
            }
            if pose.toy > 0 && self.toy_posed != pose.toy {
                self.toys.pose(pose.toy);
            }
            self.toy_posed = pose.toy;
            self.xp.start_open = pose.desk == crate::capture::Desk::StartMenu;
            self.xp.restored = pose.desk == crate::capture::Desk::Restored;
            self.xp.dialog = match pose.desk {
                crate::capture::Desk::TurnOff => xp::Dialog::TurnOff,
                crate::capture::Desk::About => xp::Dialog::About,
                _ => xp::Dialog::None,
            };
            if pose.play {
                if !self.toys.game.animating() {
                    self.toys.game.demo();
                }
            } else if pose.over {
                if !self.toys.game.over() {
                    self.toys.game.demo_over();
                }
            } else {
                self.toys.game.shelve();
            }
            if pose.pointer.is_empty() || pose.first {
                self.page = pose.page;
            }
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
            if Skin::current() == Skin::Classic {
                // Bitcoin 0.1's title, two wallet tools, and menus.
                egui::Panel::top("bitcoin-0.1-chrome")
                    .exact_size(classic::CHROME_H)
                    .resizable(false)
                    .frame(Frame::new().fill(pal.well))
                    .show(ui, |ui| {
                        match classic::chrome(
                            ui,
                            self.page,
                            &mut self.prefs,
                            self.session.running(),
                            self.session.demo,
                            self.session
                                .view
                                .as_ref()
                                .and_then(|v| v.recent.last())
                                .map(|(_, hash)| hash.as_str()),
                        ) {
                            Some(classic::Pick::Open(p)) => self.page = p,
                            Some(classic::Pick::Modern) => self.prefs.skin = Skin::Standard,
                            Some(classic::Pick::Node(a)) => action = Some(a),
                            None => {}
                        }
                    });
                egui::Panel::bottom("bitcoin-0.1-status")
                    .exact_size(classic::STATUSBAR_H)
                    .resizable(false)
                    .frame(Frame::new().fill(pal.well))
                    .show(ui, |ui| {
                        let stats = self.session.view.as_ref().map(|v| {
                            (
                                v.connected,
                                if self.session.running() {
                                    v.established().count()
                                } else {
                                    0
                                },
                                v.mempool_txs,
                            )
                        });
                        classic::statusbar(ui, phase.label(), stats, self.session.demo);
                    });
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
                            self.config_dirty.is_some(),
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
            }
            egui::CentralPanel::default()
                .frame(Frame::new().fill(pal.canvas))
                .show(ui, |ui| {
                    let top = ui.max_rect();
                    if Skin::current() == Skin::Classic {
                        classic::content_frame(ui.painter(), top);
                        // The original notebook expands with the window.
                        // A page-wide scroll area gives it an unbounded
                        // height and leaves the list stranded mid-window.
                        if self.page == Page::Overview {
                            let page_action =
                                self.page_body(ui, pal, network, open_advanced, Margin::ZERO);
                            if page_action.is_some() {
                                action = page_action;
                            }
                            return;
                        }
                    }
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
                            if Skin::current() == Skin::Classic {
                                Margin::same(12)
                            } else {
                                Margin {
                                    left: 32,
                                    right: 32,
                                    top: 26,
                                    bottom: 40,
                                }
                            },
                        );
                        if page_action.is_some() {
                            action = page_action;
                        }
                    });
                    if phosphor::on() {
                        phosphor::overlay(ui.painter(), top, ui.input(|i| i.time));
                    }
                });
        }

        if Skin::current() == Skin::Classic {
            classic::resize_frame(ui);
        }
        match action {
            Some(Action::Start) => {
                self.prefs.welcomed = true;
                self.start();
            }
            Some(Action::Stop) => self.session.stop(),
            Some(Action::Restart) => {
                if self.session.running() {
                    self.session.stop();
                    self.restart = true;
                } else {
                    self.start();
                }
            }
            Some(Action::Open(page)) => self.page = page,
            Some(Action::ReplayTour) => self.tour = Some(0),
            None => {}
        }
        // Preferences changed anywhere (Settings, the toybox, a shortcut)
        // are put in force here, once.
        if self.prefs != self.applied {
            if self.prefs.skin != self.applied.skin {
                if self.capture.is_none() {
                    if self.prefs.skin == Skin::Classic {
                        self.classic_restore_size = Some(ctx.viewport_rect().size());
                        ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(vec2(705.0, 484.0)));
                        self.page = Page::Overview;
                    } else if self.applied.skin == Skin::Classic
                        && let Some(size) = self.classic_restore_size.take()
                    {
                        ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(size));
                    }
                }
                let icon = if self.prefs.skin == Skin::Classic {
                    classic::window_icon()
                } else {
                    eframe::icon_data::from_png_bytes(brand::LOGO_PNG)
                        .ok()
                        .map(std::sync::Arc::new)
                };
                ctx.send_viewport_cmd(egui::ViewportCommand::Icon(icon));
                ctx.send_viewport_cmd(egui::ViewportCommand::MinInnerSize(
                    if self.prefs.skin == Skin::Classic {
                        vec2(705.0, 331.0)
                    } else {
                        vec2(760.0, 480.0)
                    },
                ));
            }
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
        // XP and Bitcoin 0.1 draw their own period window chrome.
        let framed = !matches!(Skin::current(), Skin::Xp | Skin::Classic);
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
            || (self.page == Page::Toybox && self.toys.animating());
        let benching = self.bench.as_ref().is_some_and(Bench::forcing);
        if self.capture.is_some() || pulsing || settling || benching || phosphor::on() {
            ctx.request_repaint();
        } else if self.session.running() {
            ctx.request_repaint_after(Duration::from_millis(250));
        } else {
            ctx.request_repaint_after(Duration::from_secs(1));
        }
        if let Some(capture) = &mut self.capture {
            capture.observe(
                &ctx,
                self.page,
                Skin::current(),
                self.session.phase().label(),
                self.session.running(),
                self.session
                    .view
                    .as_ref()
                    .and_then(|v| v.recent.last())
                    .map(|(_, hash)| hash.as_str()),
            );
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

/// The Tip skin's seed: the newest block hash's low 64 bits.
fn tip_hash_seed(session: &Session) -> u64 {
    session
        .view
        .as_ref()
        .and_then(|v| v.recent.last())
        .and_then(|(_, h)| u64::from_str_radix(&h[h.len().saturating_sub(16)..], 16).ok())
        .unwrap_or(0xF7_8B)
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

/// One line of activity-log text per stream event — `None` for the
/// kinds a GUI reader doesn't care about (a `jq` consumer still sees
/// them; the log keeps its signal-to-noise).
fn stream_text(ev: &serde_json::Value) -> Option<String> {
    let kind = ev.get("kind")?.as_str()?;
    let num = |key: &str| ev.get(key).and_then(|v| v.as_u64()).unwrap_or(0);
    let txt = |key: &str| {
        ev.get(key)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    Some(match kind {
        "run_started" => "The node is running.".into(),
        "run_stopped" => "The node stopped.".into(),
        "peer_connected" => format!(
            "Peer {} connected{}.",
            num("peer"),
            txt("user_agent")
                .split('/')
                .nth(1)
                .map(|ua| format!(" ({ua})"))
                .unwrap_or_default()
        ),
        "peer_disconnected" => format!("Peer {} disconnected: {}.", num("peer"), txt("reason")),
        "tip_advanced" => format!("Tip is height {}.", num("height")),
        "compact_received" => format!(
            "Peer {} sent a compact block ({} short ids).",
            num("peer"),
            num("short_ids")
        ),
        "compact_hit" => format!(
            "Compact block {} rebuilt from the pool — peer {}.",
            txt("block").chars().take(16).collect::<String>(),
            num("peer")
        ),
        "compact_patch_request" => format!(
            "Compact block {} missing {} txs — asked peer {} for the patch.",
            txt("block").chars().take(16).collect::<String>(),
            num("missing"),
            num("peer")
        ),
        "compact_fallback" => format!(
            "Compact block {} fell back to a full download — peer {}.",
            txt("block").chars().take(16).collect::<String>(),
            num("peer")
        ),
        "config_risk" => format!("Configuration risk — {}: {}", txt("path"), txt("message")),
        "config_changed" => format!(
            "Knob {} set to {} — live until restart.",
            txt("path"),
            txt("value")
        ),
        "config_rejected" => format!("Knob {} refused: {}.", txt("path"), txt("reason")),
        "hook_spawn_failed" => format!(
            "Hook {} failed to start ({}) — answering its timeout default.",
            txt("point"),
            txt("program")
        ),
        "hook_verdict" => format!(
            "{} {}: {} → {}.",
            txt("point"),
            txt("helper").rsplit('/').next().unwrap_or_default(),
            txt("verdict"),
            txt("admit")
        ),
        "hook_events_dropped" => format!(
            "{} hook verdicts were dropped — the event channel saturated.",
            num("total")
        ),
        "shadow_divergence" => format!(
            "Shadow profile '{}' diverges: {} ({} total).",
            txt("profile"),
            txt("reason"),
            num("total")
        ),
        "extrapool_stored" => format!(
            "Observed a filtered transaction ({}) — {} held.",
            txt("reason"),
            num("total")
        ),
        "extrapool_evicted" | "extrapool_expired" => {
            format!(
                "Extrapool {} — {} total.",
                kind.trim_start_matches("extrapool_"),
                num("total")
            )
        }
        "extrapool_promoted" => {
            format!("Promoted an observed transaction ({} total).", num("total"))
        }
        "extrapool_relayed" => {
            format!("Relayed an observed transaction ({} scope).", txt("scope"))
        }
        "extrapool_promotion_pass" => format!(
            "Tip-triggered promotion: {}/{} entries re-admitted.",
            num("promoted"),
            num("attempted")
        ),
        "eclipse_suspected" => "Eclipse indicators — advisory only, cross-checking routes.".into(),
        "proxy_unreachable" => "The configured proxy is unreachable.".into(),
        "v2_downgraded" => format!("Peer at {} downgraded to plaintext transport.", txt("addr")),
        "cpu_throttled" => format!("Peer {} is being CPU-throttled.", num("peer")),
        _ => return None,
    })
}
