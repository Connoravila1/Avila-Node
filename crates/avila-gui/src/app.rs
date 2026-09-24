//! The window: the brand rail, the status line, and the current page.

use crate::capture::Capture;
use crate::constellation::Constellation;
use crate::pages::{self, Action, Scene};
use crate::prefs::{Prefs, ThemeChoice};
use crate::rail::{self, Page};
use crate::session::{ActivityKind, Phase, RunSettings, Session};
use crate::theme::{self, Palette, SIGNAL, font};
use crate::widgets::{self, Kind, hatch};
use crate::{brand, model};
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
    autostart: bool,
    /// The peer whose panel is open on the Peers page.
    selected_peer: Option<u64>,
    sky: Constellation,
}

impl App {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        node: Node,
        demo: bool,
        theme_override: Option<ThemeChoice>,
    ) -> Self {
        let ctx = &cc.egui_ctx;
        theme::install_fonts(ctx);
        theme::install_style(ctx);
        let mut prefs = Prefs::load(cc.storage);
        if let Some(choice) = theme_override {
            prefs.theme = choice;
        }
        prefs.apply(ctx);
        let network = node.config().get().network;
        let run = RunSettings::new(network);
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
        let autostart = !cfg!(test)
            && (demo || network != avila_core::Network::Regtest || !run.connect.trim().is_empty());
        Self {
            node,
            session,
            page: Page::Overview,
            run,
            prefs,
            filter: None,
            swirl: brand::swirl_texture(ctx),
            capture: Capture::from_env(),
            autostart,
            selected_peer: None,
            sky: Constellation::default(),
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

    fn shortcuts(&mut self, ctx: &egui::Context) {
        let keys = [Key::Num1, Key::Num2, Key::Num3, Key::Num4, Key::Num5];
        ctx.input(|i| {
            if i.modifiers.command {
                for (key, page) in keys.iter().zip(Page::ALL) {
                    if i.key_pressed(*key) {
                        self.page = page;
                    }
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
            ui.add_space(16.0);
            ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                let (r, _) = ui.allocate_exact_size(vec2(18.0, 18.0), Sense::hover());
                let (c, p) = (r.center(), ui.painter());
                match phase {
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
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if std::mem::take(&mut self.autostart) {
            self.start();
        }
        self.session.poll();
        let mut pose_scroll = None;
        if let Some(pose) = self.capture.as_mut().and_then(|c| c.drive(&ctx)) {
            pose_scroll = Some(pose.scroll);
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

        egui::Panel::left("rail")
            .exact_size(rail::WIDTH)
            .resizable(false)
            .show_separator_line(false)
            .frame(Frame::new().fill(SIGNAL))
            .show(ui, |ui| {
                rail::show(
                    ui,
                    &mut self.page,
                    self.swirl.as_ref(),
                    network_name(network),
                    phase.live(),
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
                    Frame::new()
                        .inner_margin(Margin {
                            left: 32,
                            right: 32,
                            top: 26,
                            bottom: 40,
                        })
                        .show(ui, |ui| {
                            let scene = Scene {
                                pal,
                                session: &self.session,
                                network,
                                swirl: self.swirl.as_ref(),
                            };
                            let page_action = match self.page {
                                Page::Overview => {
                                    pages::overview::show(ui, &scene, &mut self.prefs.scale)
                                }
                                Page::Chain => {
                                    pages::chain::show(ui, &scene, &mut self.prefs.scale)
                                }
                                Page::Peers => pages::peers::show(
                                    ui,
                                    &scene,
                                    &mut self.selected_peer,
                                    &mut self.sky,
                                ),
                                Page::Activity => {
                                    pages::activity::show(ui, &scene, &mut self.filter)
                                }
                                Page::Settings => {
                                    let before = self.prefs;
                                    let a = pages::settings::show(
                                        ui,
                                        &scene,
                                        &mut self.run,
                                        &mut self.prefs,
                                        &self.node,
                                    );
                                    if self.prefs != before {
                                        self.prefs.apply(ui.ctx());
                                    }
                                    a
                                }
                            };
                            if page_action.is_some() {
                                action = page_action;
                            }
                        });
                });
            });

        match action {
            Some(Action::Start) => self.start(),
            Some(Action::Stop) => self.session.stop(),
            None => {}
        }
        // Smooth frames only while the new-block pulse runs; otherwise
        // just often enough for "seconds ago" to tick over.
        let pulsing = Scene {
            pal,
            session: &self.session,
            network,
            swirl: None,
        }
        .pulse()
        .is_some();
        let settling = self.page == Page::Peers && self.sky.animating();
        if self.capture.is_some() || pulsing || settling {
            ctx.request_repaint();
        } else if self.session.running() {
            ctx.request_repaint_after(Duration::from_millis(250));
        } else {
            ctx.request_repaint_after(Duration::from_secs(1));
        }
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        // A capture run poses the app; it mustn't overwrite real choices.
        if self.capture.is_none() {
            self.prefs.save(storage);
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
