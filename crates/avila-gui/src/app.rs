use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{Receiver, channel};
use std::thread;
use std::time::Duration;

use crate::appearance::{AppearanceConfig, AppearanceMode};
use avila_core::CapabilityState;
use avila_node::Node;
use avila_node::events::{EventRecord, NodeEvent};
use avila_node::sync::{SyncConfig, SyncProgress, SyncReport};
use eframe::egui::{self, Align, Color32, Layout, RichText, Stroke, vec2};
use egui_extras::{Column, TableBuilder};

#[cfg(test)]
mod tests;

// ---------------------------------------------------------------------------
// Design tokens — the node's data is the design. Graphite surfaces, hairline
// rules, monospace for anything measured, and one accent reserved for live
// data: the moving chain tip.
// ---------------------------------------------------------------------------

const ACCENT: Color32 = Color32::from_rgb(0xF7, 0x93, 0x1A); // live/active
const OK: Color32 = Color32::from_rgb(0x43, 0xC0, 0x8E); // verified/connected
const WARN: Color32 = Color32::from_rgb(0xD9, 0x6C, 0x4A); // stalls/errors
const MUTED: Color32 = Color32::from_rgb(0x8C, 0x92, 0x9B);
const HAIRLINE: Color32 = Color32::from_rgb(0x2A, 0x2E, 0x36);
const CELL_BG: Color32 = Color32::from_rgb(0x1D, 0x20, 0x26);

fn mono(text: impl Into<String>) -> RichText {
    RichText::new(text).family(egui::FontFamily::Monospace)
}

fn muted(text: impl Into<String>) -> RichText {
    mono(text).color(MUTED)
}

/// Short form of a 32-byte hash's display hex: `3504…2e1b`.
fn short_hash(display: &str) -> String {
    if display.len() > 12 {
        format!("{}…{}", &display[..6], &display[display.len() - 5..])
    } else {
        display.to_string()
    }
}

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Page {
    #[default]
    Chain,
    Sync,
    Events,
    Capabilities,
    Configuration,
}

impl Page {
    const ALL: [Self; 5] = [
        Self::Chain,
        Self::Sync,
        Self::Events,
        Self::Capabilities,
        Self::Configuration,
    ];

    fn title(self) -> &'static str {
        match self {
            Self::Chain => "Chain",
            Self::Sync => "Sync",
            Self::Events => "Events",
            Self::Capabilities => "Capabilities",
            Self::Configuration => "Configuration",
        }
    }
}

// ---------------------------------------------------------------------------
// Sync worker — avila_node::sync::run on a thread, progress over a channel.
// ---------------------------------------------------------------------------

enum SyncMsg {
    Progress(Box<SyncProgress>),
    Done(Result<SyncReport, String>),
}

struct SyncUi {
    rx: Option<Receiver<SyncMsg>>,
    cancel: Option<Arc<AtomicBool>>,
    running: bool,
    latest: Option<SyncProgress>,
    report: Option<Result<SyncReport, String>>,
    target_input: String,
    connect_input: String,
    proxy_input: String,
    prune_input: String,
    store: bool,
}

impl Default for SyncUi {
    fn default() -> Self {
        Self {
            rx: None,
            cancel: None,
            running: false,
            latest: None,
            report: None,
            target_input: "100".into(),
            connect_input: String::new(),
            proxy_input: String::new(),
            prune_input: String::new(),
            store: true,
        }
    }
}

/// The one-glance verdict the interface exists to answer.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Verdict {
    Idle,
    Connecting,
    Syncing,
    AtTarget,
    Stopped,
    Failed,
}

impl Verdict {
    fn label(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Connecting => "connecting",
            Self::Syncing => "syncing",
            Self::AtTarget => "at target",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }

    fn color(self) -> Color32 {
        match self {
            Self::Idle | Self::Connecting => MUTED,
            Self::Syncing => ACCENT,
            Self::AtTarget => OK,
            Self::Stopped | Self::Failed => WARN,
        }
    }
}

impl SyncUi {
    fn verdict(&self) -> Verdict {
        if self.running {
            match &self.latest {
                Some(p) if p.peers > 0 => Verdict::Syncing,
                _ => Verdict::Connecting,
            }
        } else {
            match &self.report {
                Some(Ok(r)) if r.target_reached => Verdict::AtTarget,
                Some(Ok(_)) => Verdict::Stopped,
                Some(Err(_)) => Verdict::Failed,
                None => Verdict::Idle,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

pub struct AvilaApp {
    node: Node,
    page: Page,
    logo: egui::TextureHandle,
    sync: SyncUi,
    auto_started: bool,
    event_query: String,
    newest_first: bool,
    selected_event: Option<EventRecord>,
    focus_search: bool,
    implemented_only: bool,
    show_appearance: bool,
    show_help: bool,
    appearance: AppearanceConfig,
    #[cfg(debug_assertions)]
    show_egui_tools: bool,
}

impl AvilaApp {
    pub fn new(
        ctx: &egui::Context,
        node: Node,
        logo: egui::ColorImage,
        appearance: AppearanceConfig,
    ) -> Self {
        appearance.apply(ctx);
        ctx.all_styles_mut(|style| {
            style.spacing.item_spacing = vec2(10.0, 8.0);
            style.spacing.button_padding = vec2(14.0, 6.0);
            style.visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, HAIRLINE);
            style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, HAIRLINE);
            style.visuals.panel_fill = Color32::from_rgb(0x14, 0x16, 0x1B);
        });
        let mut sync = SyncUi::default();
        // Regtest has no DNS seeds — prefill Core's default port.
        if node.config().get().network == avila_core::Network::Regtest {
            sync.connect_input = "127.0.0.1:18444".into();
        }
        Self {
            node,
            page: Page::default(),
            logo: ctx.load_texture("avila-node-logo", logo, egui::TextureOptions::LINEAR),
            sync,
            auto_started: false,
            event_query: String::new(),
            newest_first: true,
            selected_event: None,
            focus_search: false,
            implemented_only: false,
            show_appearance: false,
            show_help: false,
            appearance,
            #[cfg(debug_assertions)]
            show_egui_tools: false,
        }
    }

    fn shortcuts(&mut self, ctx: &egui::Context) {
        ctx.input_mut(|input| {
            for (key, page) in [
                egui::Key::Num1,
                egui::Key::Num2,
                egui::Key::Num3,
                egui::Key::Num4,
                egui::Key::Num5,
            ]
            .into_iter()
            .zip(Page::ALL)
            {
                if input.consume_key(egui::Modifiers::COMMAND, key) {
                    self.page = page;
                }
            }
            if input.consume_key(egui::Modifiers::COMMAND, egui::Key::F) {
                self.page = Page::Events;
                self.focus_search = true;
            }
            if input.consume_key(egui::Modifiers::NONE, egui::Key::F1) {
                self.show_help = !self.show_help;
            }
        });
    }

    /// Drain the sync worker's channel into UI state.
    fn poll_sync(&mut self, ctx: &egui::Context) {
        if let Some(rx) = &self.sync.rx {
            let mut done = None;
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    SyncMsg::Progress(p) => self.sync.latest = Some(*p),
                    SyncMsg::Done(r) => done = Some(r),
                }
            }
            if let Some(report) = done {
                self.sync.report = Some(report);
                self.sync.running = false;
                self.sync.rx = None;
                self.sync.cancel = None;
            }
        }
        if self.sync.running {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }

    pub fn render(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        self.appearance.scale = ctx.zoom_factor();
        // A node starts itself — but never in headless tests, where a
        // worker would touch the test's working directory.
        #[cfg(not(test))]
        if !self.auto_started {
            self.auto_started = true;
            let has_seeds = !matches!(
                self.node.config().get().network,
                avila_core::Network::Regtest
            );
            if has_seeds || !self.sync.connect_input.trim().is_empty() {
                self.start_sync();
            }
        }
        #[cfg(test)]
        {
            self.auto_started = true;
        }
        self.poll_sync(&ctx);
        self.shortcuts(&ctx);
        self.header(ui);
        egui::Panel::bottom("status").show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(muted(format!(
                    "{} · {}",
                    self.node.config().get().network,
                    self.node.config().network_data_dir().display()
                )));
                ui.separator();
                ui.label(muted(format!(
                    "{} events retained",
                    self.node.events().entries().count()
                )));
            });
        });
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::both()
                .auto_shrink([false, false])
                .id_salt("page")
                .show(ui, |ui| {
                    ui.add_space(14.0);
                    match self.page {
                        Page::Chain => self.chain(ui),
                        Page::Sync => self.sync_page(ui),
                        Page::Events => self.events(ui),
                        Page::Capabilities => self.capabilities(ui),
                        Page::Configuration => self.configuration(ui),
                    }
                });
        });
        self.windows(&ctx);
    }

    /// The instrument band: wordmark, page tabs, live chain readout.
    fn header(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("header").show(ui, |ui| {
            ui.painter().hline(
                ui.max_rect().x_range(),
                ui.max_rect().bottom(),
                Stroke::new(1.0, HAIRLINE),
            );
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.add(egui::Image::new(&self.logo).fit_to_exact_size(vec2(22.0, 22.0)));
                ui.label(RichText::new("AVILA").strong().size(15.0));
                ui.label(muted("NODE"));
                ui.add_space(20.0);
                for page in Page::ALL {
                    let active = self.page == page;
                    let text = if active {
                        RichText::new(page.title()).color(ACCENT).strong()
                    } else {
                        RichText::new(page.title()).color(MUTED)
                    };
                    let response = ui.add(egui::Button::new(text).frame_when_inactive(false));
                    if active {
                        ui.painter().hline(
                            response.rect.x_range(),
                            response.rect.bottom() + 2.0,
                            Stroke::new(2.0, ACCENT),
                        );
                    }
                    if response.clicked() {
                        self.page = page;
                    }
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui
                        .add(egui::Button::new(muted("⚙")).frame_when_inactive(false))
                        .on_hover_text("Appearance")
                        .clicked()
                    {
                        self.show_appearance = true;
                    }
                    if ui
                        .add(egui::Button::new(muted("?")).frame_when_inactive(false))
                        .on_hover_text("About and shortcuts")
                        .clicked()
                    {
                        self.show_help = true;
                    }
                });
            });
            // The ticker row — the live chain readout, always visible.
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                let verdict = self.sync.verdict();
                let (dot_rect, _) = ui.allocate_exact_size(
                    vec2(10.0, ui.spacing().interact_size.y.min(14.0)),
                    egui::Sense::hover(),
                );
                ui.painter()
                    .circle_filled(dot_rect.center(), 4.0, verdict.color());
                ui.label(mono(verdict.label()).color(verdict.color()))
                    .on_hover_text("Local verdict — what this node has itself observed");
                ui.label(muted("·"));
                if let Some(p) = &self.sync.latest {
                    ui.label(
                        mono(format!("h {}", p.connected_height)).color(if self.sync.running {
                            ACCENT
                        } else {
                            MUTED
                        }),
                    );
                    ui.label(muted("·"));
                    let tip = p
                        .recent
                        .last()
                        .map(|(_, h)| format!("tip {}", short_hash(&h.to_string())))
                        .unwrap_or_else(|| "no tip".into());
                    ui.label(mono(tip));
                    ui.label(muted("·"));
                    ui.label(muted(format!("peers {}", p.peers)));
                    if p.mempool.0 > 0 || p.mempool.1 > 0 {
                        ui.label(muted("·"));
                        ui.label(muted(format!("pool {}", p.mempool.0)));
                        if p.mempool.1 > 0 {
                            ui.label(muted(format!("+{} orphans", p.mempool.1)));
                        }
                    }
                    if let Some(rate) = p.mempool.2 {
                        ui.label(muted("·"));
                        ui.label(muted(format!("~{} sat/kvB (6 blk)", rate)));
                    }
                } else {
                    ui.label(muted("no chain data"));
                }
            });
            ui.add_space(6.0);
        });
    }

    // -- Chain page --------------------------------------------------------

    fn chain(&mut self, ui: &mut egui::Ui) {
        match (&self.sync.latest, &self.sync.report) {
            (Some(p), _) => {
                ui.label(muted("CONNECTED HEIGHT"));
                ui.label(mono(p.connected_height.to_string()).size(52.0).strong());
                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    if let Some((h, hash)) = p.recent.last() {
                        ui.label(muted("tip"));
                        ui.label(mono(format!("{h} {}", short_hash(&hash.to_string()))));
                    }
                    ui.label(muted(format!("· best header {}", p.header_height)));
                    ui.label(muted(format!("· {} peers", p.peers)));
                    ui.label(muted(format!("· {} in flight", p.in_flight)));
                });
                if let Some(Ok(r)) = &self.sync.report {
                    ui.add_space(10.0);
                    ui.label(muted(format!(
                        "last run: {} connected · {} peers · {:.1}s{}",
                        r.connected_height,
                        r.established_total,
                        r.elapsed.as_secs_f64(),
                        if r.target_reached {
                            ""
                        } else {
                            " · stopped early"
                        },
                    )));
                }
            }
            _ => {
                ui.label(muted("NO CHAIN DATA"));
                ui.add_space(6.0);
                ui.label(RichText::new("This process has no validated chain yet.").size(20.0));
                ui.label(muted(
                    "Run a sync to download and verify blocks from live peers.",
                ));
                ui.add_space(10.0);
                if ui
                    .add(egui::Button::new(RichText::new("Open Sync").color(ACCENT)))
                    .clicked()
                {
                    self.page = Page::Sync;
                }
            }
        }
        ui.add_space(16.0);
        ui.separator();
        ui.add_space(10.0);
        // Recent events summary — the last few journal entries inline.
        ui.label(muted("RECENT EVENTS"));
        let recent: Vec<EventRecord> = self
            .node
            .events()
            .entries()
            .rev()
            .take(4)
            .copied()
            .collect();
        if recent.is_empty() {
            ui.label(muted("none"));
        }
        for record in recent {
            ui.horizontal(|ui| {
                ui.label(muted(format!("#{}", record.sequence)));
                ui.label(mono(event_title(record.event)));
            });
        }
    }

    // -- Sync page ---------------------------------------------------------

    fn sync_page(&mut self, ui: &mut egui::Ui) {
        // Controls.
        ui.horizontal_wrapped(|ui| {
            ui.label(muted("target"));
            ui.add(
                egui::TextEdit::singleline(&mut self.sync.target_input)
                    .desired_width(60.0)
                    .font(egui::FontId::monospace(12.0)),
            );
            ui.label(muted("connect"));
            ui.add(
                egui::TextEdit::singleline(&mut self.sync.connect_input)
                    .hint_text("addr:port")
                    .desired_width(150.0)
                    .font(egui::FontId::monospace(12.0)),
            );
            ui.label(muted("proxy"));
            ui.add(
                egui::TextEdit::singleline(&mut self.sync.proxy_input)
                    .hint_text("socks5 addr:port")
                    .desired_width(130.0)
                    .font(egui::FontId::monospace(12.0)),
            );
            ui.label(muted("prune MiB"));
            ui.add(
                egui::TextEdit::singleline(&mut self.sync.prune_input)
                    .hint_text("archive")
                    .desired_width(60.0)
                    .font(egui::FontId::monospace(12.0)),
            );
            ui.checkbox(&mut self.sync.store, "store");
            if self.sync.running {
                if ui
                    .add(egui::Button::new(RichText::new("Stop").color(WARN)))
                    .clicked()
                    && let Some(c) = &self.sync.cancel
                {
                    c.store(true, std::sync::atomic::Ordering::Relaxed);
                }
            } else if ui
                .add(egui::Button::new(RichText::new("Start sync").color(ACCENT)))
                .clicked()
            {
                self.start_sync();
            }
        });
        if let Some(Err(e)) = &self.sync.report {
            ui.add_space(6.0);
            ui.label(RichText::new(format!("sync failed: {e}")).color(WARN));
        }
        ui.add_space(14.0);

        // The block tape — the chain as the interface.
        self.block_tape(ui);
        ui.add_space(14.0);

        if let Some(p) = &self.sync.latest {
            // Hero metric: connected height.
            ui.horizontal(|ui| {
                ui.label(mono(p.connected_height.to_string()).size(52.0).strong());
                ui.vertical(|ui| {
                    ui.add_space(18.0);
                    ui.label(muted("blocks connected"));
                    if let Some((_, hash)) = p.recent.last() {
                        ui.label(mono(short_hash(&hash.to_string())));
                    }
                });
            });
            ui.add_space(12.0);

            // Two thin progress rails: headers vs connected, against target.
            let target: f32 = self.sync.target_input.parse().unwrap_or(100.0_f32).max(1.0);
            for (label, value, color) in [
                ("headers", p.header_height as f32 / target, MUTED),
                ("connected", p.connected_height as f32 / target, ACCENT),
            ] {
                ui.horizontal(|ui| {
                    ui.label(muted(format!("{label:>9}")));
                    let bar = egui::ProgressBar::new(value.clamp(0.0, 1.0))
                        .fill(color)
                        .desired_height(6.0)
                        .desired_width(ui.available_width() - 20.0)
                        .text("");
                    ui.add(bar);
                });
            }
            ui.add_space(10.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(muted(format!("{} peers", p.peers)));
                ui.label(muted(format!("{} in flight", p.in_flight)));
                ui.label(muted(format!("{} established", p.established_total)));
                ui.label(muted(format!("{} drops", p.disconnects)));
            });
            if !p.peer_details.is_empty() {
                ui.add_space(12.0);
                self.peer_table(ui, &p.peer_details);
            }
        } else if self.sync.running {
            ui.label(muted("connecting…"));
            ui.label(muted(
                "No peers yet. On regtest there are no DNS seeds — enter a connect address above.",
            ));
        } else {
            ui.label(muted("No sync run yet. Set a target height and start."));
        }
    }

    /// Every peer as an untrusted input: what it *claims* (its asserted
    /// height) vs. what it has *served* (headers/blocks we verified).
    fn peer_table(&self, ui: &mut egui::Ui, peers: &[avila_p2p::manager::PeerSnapshot]) {
        ui.label(muted("PEERS — claims vs. served"));
        ui.add_space(4.0);
        TableBuilder::new(ui)
            .id_salt("peers")
            .striped(true)
            .column(Column::remainder().at_least(150.0)) // address
            .column(Column::initial(30.0)) // dir
            .column(Column::initial(120.0).clip(true)) // agent
            .column(Column::initial(55.0)) // claims
            .column(Column::initial(50.0)) // hdrs
            .column(Column::initial(45.0)) // blks
            .column(Column::initial(45.0)) // in-flight
            .column(Column::initial(45.0)) // idle
            .header(20.0, |mut header| {
                for label in [
                    "peer", "dir", "agent", "claims", "hdrs", "blks", "in-flt", "idle",
                ] {
                    header.col(|ui| {
                        ui.label(muted(label));
                    });
                }
            })
            .body(|body| {
                body.rows(22.0, peers.len(), |mut row| {
                    let p = &peers[row.index()];
                    row.col(|ui| {
                        let addr = p
                            .remote
                            .map(|a| a.to_string())
                            .unwrap_or_else(|| format!("#{}", p.id));
                        ui.label(mono(addr));
                    });
                    row.col(|ui| {
                        ui.label(muted(if p.inbound { "in" } else { "out" }));
                    });
                    row.col(|ui| {
                        let agent = p.user_agent.as_deref().unwrap_or("—");
                        let agent = agent.trim_start_matches('/').trim_end_matches('/');
                        ui.label(muted(agent));
                    });
                    row.col(|ui| {
                        // What the peer claims — never presented as verified.
                        let claim = p
                            .start_height
                            .map(|h| h.to_string())
                            .unwrap_or_else(|| "?".into());
                        ui.label(muted(claim));
                    });
                    row.col(|ui| {
                        ui.label(mono(p.headers_received.to_string()));
                    });
                    row.col(|ui| {
                        ui.label(mono(p.blocks_received.to_string()));
                    });
                    row.col(|ui| {
                        let n = p.in_flight;
                        ui.label(mono(n.to_string()).color(if n > 0 { ACCENT } else { MUTED }));
                    });
                    row.col(|ui| {
                        let idle = if p.idle_secs > 3600 {
                            format!("{}h", p.idle_secs / 3600)
                        } else if p.idle_secs > 60 {
                            format!("{}m", p.idle_secs / 60)
                        } else {
                            format!("{}s", p.idle_secs)
                        };
                        ui.label(muted(idle).color(if p.idle_secs > 300 { WARN } else { MUTED }));
                    });
                });
            });
    }

    /// A horizontal strip of the most recent connected blocks — the
    /// signature element. The tip cell carries the accent.
    fn block_tape(&self, ui: &mut egui::Ui) {
        const CELL: egui::Vec2 = vec2(92.0, 46.0);
        const GAP: f32 = 6.0;
        let cells: Vec<(u32, String)> = self
            .sync
            .latest
            .as_ref()
            .map(|p| {
                p.recent
                    .iter()
                    .map(|(h, hash)| (*h, short_hash(&hash.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        let count = cells.len().max(1);
        let width = count as f32 * (CELL.x + GAP);
        let (rect, _) = ui.allocate_exact_size(
            vec2(ui.available_width().max(width), CELL.y + 22.0),
            egui::Sense::hover(),
        );
        let painter = ui.painter_at(rect);
        if cells.is_empty() {
            // An empty tape: a single muted placeholder cell.
            let cell = egui::Rect::from_min_size(rect.min + vec2(0.0, 18.0), CELL);
            painter.rect(
                cell,
                2.0,
                CELL_BG,
                Stroke::new(1.0, HAIRLINE),
                egui::StrokeKind::Inside,
            );
            painter.text(
                cell.center(),
                egui::Align2::CENTER_CENTER,
                "no blocks",
                egui::FontId::monospace(11.0),
                MUTED,
            );
            return;
        }
        painter.text(
            rect.min + vec2(0.0, 6.0),
            egui::Align2::LEFT_CENTER,
            "RECENT BLOCKS",
            egui::FontId::monospace(10.0),
            MUTED,
        );
        for (i, (height, hash)) in cells.iter().enumerate() {
            let is_tip = i + 1 == cells.len();
            let origin = rect.min + vec2(i as f32 * (CELL.x + GAP), 18.0);
            let cell = egui::Rect::from_min_size(origin, CELL);
            let (border, text_color) = if is_tip {
                (Stroke::new(1.5, ACCENT), ACCENT)
            } else {
                (Stroke::new(1.0, HAIRLINE), MUTED)
            };
            painter.rect(cell, 2.0, CELL_BG, border, egui::StrokeKind::Inside);
            painter.text(
                cell.min + vec2(8.0, 12.0),
                egui::Align2::LEFT_CENTER,
                height.to_string(),
                egui::FontId::monospace(12.0),
                if is_tip { text_color } else { Color32::WHITE },
            );
            painter.text(
                cell.min + vec2(8.0, 30.0),
                egui::Align2::LEFT_CENTER,
                hash,
                egui::FontId::monospace(10.0),
                text_color,
            );
        }
    }

    fn start_sync(&mut self) {
        use avila_consensus::params::Network as ConsensusNet;
        let consensus_net = match self.node.config().get().network {
            avila_core::Network::Mainnet => ConsensusNet::Mainnet,
            avila_core::Network::Testnet4 => ConsensusNet::Testnet4,
            avila_core::Network::Signet => ConsensusNet::Signet,
            avila_core::Network::Regtest => ConsensusNet::Regtest,
        };
        let params = consensus_net.params();
        let cancel = Arc::new(AtomicBool::new(false));
        let cfg = SyncConfig {
            connect: self
                .sync
                .connect_input
                .split(',')
                .filter_map(|s| s.trim().parse::<SocketAddr>().ok())
                .collect(),
            target_height: self.sync.target_input.parse().unwrap_or(100),
            max_peers: 8,
            timeout: Duration::from_secs(3600),
            proxy: self.sync.proxy_input.trim().parse().ok(),
            data_dir: self
                .sync
                .store
                .then(|| self.node.config().network_data_dir()),
            cancel: Some(cancel.clone()),
            status: None,
            queries: None,
            waiters: None,
            txindex: false,
            blockfilterindex: false,
            v2transport: true,
            prune_bytes: self
                .sync
                .prune_input
                .trim()
                .parse::<u64>()
                .ok()
                .map(|m| m * 1024 * 1024),
        };
        let (tx, rx) = channel();
        thread::spawn(move || {
            let report = avila_node::sync::run(&params, &cfg, |p| {
                let _ = tx.send(SyncMsg::Progress(Box::new(p.clone())));
            });
            let _ = tx.send(SyncMsg::Done(report.map_err(|e| e.to_string())));
        });
        self.sync.cancel = Some(cancel);
        self.sync.rx = Some(rx);
        self.sync.running = true;
        self.sync.report = None;
    }

    // -- Events page -------------------------------------------------------

    fn events(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label(muted("search"));
            let search = ui.add(
                egui::TextEdit::singleline(&mut self.event_query)
                    .hint_text("sequence, event or explanation…")
                    .desired_width(240.0),
            );
            if self.focus_search {
                search.request_focus();
                self.focus_search = false;
            }
            if ui.button("Clear").clicked() {
                self.event_query.clear();
            }
            ui.checkbox(&mut self.newest_first, "Newest first");
        });
        let records: Vec<_> = self.node.events().entries().copied().collect();
        let capacity = self.node.config().event_capacity().get();
        ui.add(
            egui::ProgressBar::new(records.len() as f32 / capacity as f32)
                .fill(MUTED)
                .desired_height(4.0)
                .text(muted(format!("{} / {capacity} events", records.len()))),
        )
        .on_hover_text(
            "Oldest events are evicted at capacity. Memory occupancy, not sync progress.",
        );
        let records = filtered_events(&records, &self.event_query, self.newest_first);
        ui.add_space(8.0);
        if records.is_empty() {
            ui.label(muted("No events match this search."));
            return;
        }
        let table_height = (ui.clip_rect().bottom() - ui.cursor().top()).max(96.0);
        TableBuilder::new(ui)
            .id_salt("events")
            .striped(true)
            .resizable(true)
            .min_scrolled_height(96.0)
            .max_scroll_height(table_height)
            .column(Column::initial(90.0).at_least(65.0))
            .column(Column::remainder().at_least(160.0))
            .header(24.0, |mut header| {
                header.col(|ui| {
                    ui.label(muted("SEQ"));
                });
                header.col(|ui| {
                    ui.label(muted("EVENT"));
                });
            })
            .body(|body| {
                body.rows(30.0, records.len(), |mut row| {
                    let record = records[row.index()];
                    row.col(|ui| {
                        ui.label(muted(format!("#{}", record.sequence)));
                    });
                    row.col(|ui| {
                        let response = ui
                            .selectable_label(
                                self.selected_event == Some(record),
                                mono(event_title(record.event)),
                            )
                            .on_hover_text(event_description(record.event));
                        if response.clicked() {
                            self.selected_event = Some(record);
                        }
                        response.context_menu(|ui| {
                            if ui.button("Copy event").clicked() {
                                ui.ctx().copy_text(event_text(record));
                                ui.close();
                            }
                        });
                    });
                });
            });
    }

    // -- Capabilities page --------------------------------------------------

    fn capabilities(&mut self, ui: &mut egui::Ui) {
        ui.label(muted("Implementation status of this build."));
        ui.checkbox(&mut self.implemented_only, "Show implemented only");
        ui.add_space(8.0);
        let capabilities: Vec<_> = self
            .node
            .snapshot()
            .capabilities
            .iter()
            .filter(|capability| {
                !self.implemented_only || capability.state == CapabilityState::Implemented
            })
            .collect();
        TableBuilder::new(ui)
            .id_salt("capabilities")
            .striped(true)
            .resizable(true)
            .column(Column::initial(115.0).at_least(90.0))
            .column(Column::remainder().at_least(140.0))
            .header(24.0, |mut header| {
                header.col(|ui| {
                    ui.label(muted("STATUS"));
                });
                header.col(|ui| {
                    ui.label(muted("CAPABILITY"));
                });
            })
            .body(|body| {
                body.rows(34.0, capabilities.len(), |mut row| {
                    let capability = capabilities[row.index()];
                    row.col(|ui| {
                        ui.label(match capability.state {
                            CapabilityState::Implemented => RichText::new("Implemented").color(OK),
                            CapabilityState::Planned => RichText::new("Planned").color(MUTED),
                        });
                    });
                    row.col(|ui| {
                        ui.label(capability.name);
                    });
                });
            });
    }

    // -- Configuration page -------------------------------------------------

    fn configuration(&self, ui: &mut egui::Ui) {
        let config = self.node.config();
        ui.label(muted("Loaded settings for this process."));
        ui.add_space(8.0);
        egui::Grid::new("configuration")
            .spacing([20.0, 12.0])
            .show(ui, |ui| {
                for (label, value) in [
                    ("Network", config.get().network.to_string()),
                    ("Schema version", config.get().schema_version.to_string()),
                    ("Event capacity", config.event_capacity().to_string()),
                    (
                        "Network data directory",
                        config.network_data_dir().display().to_string(),
                    ),
                ] {
                    ui.label(muted(label));
                    ui.add(egui::Label::new(mono(&value)).selectable(true));
                    if ui
                        .small_button("Copy")
                        .on_hover_text(format!("Copy {label}"))
                        .clicked()
                    {
                        ui.ctx().copy_text(value);
                    }
                    ui.end_row();
                }
            });
        ui.add_space(16.0);
        ui.collapsing("Configuration file and data paths", |ui| {
            ui.label("Pass --config <path> when launching the CLI or desktop. Relative data paths are resolved against that file's directory. Without a file, data/ is relative to the working directory.");
            ui.label("Each network has its own subdirectory; the chainstate (blk*.dat + state.dat) and peers.dat live under it.");
        });
    }

    // -- Windows ------------------------------------------------------------

    fn windows(&mut self, ctx: &egui::Context) {
        if let Some(record) = self.selected_event {
            let mut open = true;
            egui::Window::new("Event details")
                .open(&mut open)
                .resizable(true)
                .default_width(400.0)
                .vscroll(true)
                .show(ctx, |ui| {
                    ui.label(muted(format!("Sequence #{}", record.sequence)));
                    ui.heading(event_title(record.event));
                    ui.label(event_description(record.event));
                    ui.small("Source: this process's in-memory diagnostic history.");
                    if ui.button("Copy event").clicked() {
                        ctx.copy_text(event_text(record));
                    }
                });
            if !open {
                self.selected_event = None;
            }
        }
        let previous_appearance = self.appearance;
        egui::Window::new("Appearance")
            .open(&mut self.show_appearance)
            .default_width(380.0)
            .vscroll(true)
            .show(ctx, |ui| {
                ui.heading("Color theme");
                ui.horizontal_wrapped(|ui| {
                    for theme in AppearanceMode::ALL {
                        ui.radio_value(&mut self.appearance.theme, theme, theme.label())
                            .on_hover_text(theme.description());
                    }
                });
                ui.label(self.appearance.theme.description());
                ui.add_space(8.0);
                ui.add(
                    egui::Slider::new(&mut self.appearance.scale, 0.75..=2.0)
                        .text("Interface scale"),
                );
                if ui.button("Reset scale").clicked() {
                    self.appearance.scale = 1.0;
                }
                ui.small("Your theme and scale are remembered on this device.");
            });
        if self.appearance != previous_appearance {
            self.appearance.apply(ctx);
        }
        egui::Window::new("About Avila Node").open(&mut self.show_help)
            .default_width(430.0).vscroll(true).show(ctx, |ui| {
                ui.heading("Avila Node");
                ui.label("An open-source Bitcoin full node by Connor Avila.");
                ui.label("Rust · egui · MIT license");
                ui.separator();
                ui.label("Ctrl/Cmd + 1–5: switch pages");
                ui.label("Ctrl/Cmd + F: search local events");
                ui.label("F1: toggle this window");
                ui.label("Tab / Shift + Tab: move keyboard focus");
                ui.label("Enter / Space: activate a focused control");
                ui.separator();
                ui.label("Consensus validation, persistent chainstate, peer sync, and the mempool are implemented. Wallet, RPC, and services are not.");
            });
        #[cfg(debug_assertions)]
        egui::Window::new("egui development tools")
            .open(&mut self.show_egui_tools)
            .default_width(540.0)
            .vscroll(true)
            .show(ctx, |ui| {
                ui.collapsing("Style and settings", |ui| ctx.settings_ui(ui));
                ui.collapsing("Inspection", |ui| ctx.inspection_ui(ui));
                ui.collapsing("Memory", |ui| ctx.memory_ui(ui));
            });
    }
}

impl eframe::App for AvilaApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.render(ui);
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        self.appearance.save(storage);
    }

    fn persist_egui_memory(&self) -> bool {
        false
    }

    fn clear_color(&self, visuals: &egui::Visuals) -> [f32; 4] {
        visuals.panel_fill.to_normalized_gamma_f32()
    }
}

fn event_title(event: NodeEvent) -> &'static str {
    match event {
        NodeEvent::ConfigurationLoaded => "Configuration loaded",
        NodeEvent::StartupBlocked => "Startup blocked",
    }
}

fn event_description(event: NodeEvent) -> &'static str {
    match event {
        NodeEvent::ConfigurationLoaded => {
            "The configuration passed validation. No Bitcoin services were started."
        }
        NodeEvent::StartupBlocked => {
            "Startup was refused because the persistent node services are not wired yet."
        }
    }
}

fn event_text(record: EventRecord) -> String {
    format!(
        "#{} · {}\n{}",
        record.sequence,
        event_title(record.event),
        event_description(record.event)
    )
}

fn filtered_events(records: &[EventRecord], query: &str, newest_first: bool) -> Vec<EventRecord> {
    let query = query.trim().to_lowercase();
    let mut result: Vec<_> = records
        .iter()
        .copied()
        .filter(|record| {
            if query.is_empty() {
                return true;
            }
            record.sequence.to_string().contains(&query)
                || event_title(record.event).to_lowercase().contains(&query)
                || event_description(record.event)
                    .to_lowercase()
                    .contains(&query)
        })
        .collect();
    if newest_first {
        result.reverse();
    }
    result
}
