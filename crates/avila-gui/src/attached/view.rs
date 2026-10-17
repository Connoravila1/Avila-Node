//! Read-only desktop view attached to an already-running Avila RPC server.
//!
//! It deliberately consumes only observations supplied by the worker: absent
//! fields stay unknown, failed refreshes leave the previous sample visible with
//! its age, and closing this view does not stop the node.

use crate::attached::worker::{ConsoleRequest, Snapshot, Worker};
use crate::brand;
use crate::pages::block_inspector;
use crate::prefs::{Prefs, ThemeChoice};
use crate::theme::{self, Palette};
use avila_node::Node;
use eframe::egui::{
    self, Align, Color32, Frame, Layout, RichText, ScrollArea, Sense, Stroke, TextEdit, Ui, pos2,
    vec2,
};
use serde_json::Value;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::{Arc, atomic::AtomicBool};
use std::time::{Duration, Instant};

const MAX_TRAFFIC_SAMPLES: usize = 120;
const MAX_CONSOLE_INPUT: usize = 8 * 1024;
const MAX_CONSOLE_OUTPUT: usize = 64 * 1024;
const CONSOLE_TIMEOUT: Duration = Duration::from_secs(30);
const ATTACHED_SCALE_KEY: &str = "attached.ui_scale.v1";
const ATTACHED_BLACK_KEY: &str = "attached.black_theme.v1";
const ATTACHED_SCALES: [(f32, &str); 8] = [
    (0.75, "75%"),
    (0.9, "90%"),
    (1.0, "100%"),
    (1.15, "115%"),
    (1.3, "130%"),
    (1.5, "150%"),
    (1.75, "175%"),
    (2.0, "200%"),
];

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Page {
    #[default]
    Overview,
    Blocks,
    Peers,
    Traffic,
    Console,
}

impl Page {
    const ALL: [Self; 5] = [
        Self::Overview,
        Self::Blocks,
        Self::Peers,
        Self::Traffic,
        Self::Console,
    ];

    fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Blocks => "Blocks",
            Self::Peers => "Peers",
            Self::Traffic => "Traffic",
            Self::Console => "RPC console",
        }
    }
}

struct TrafficSample {
    at: Instant,
    recv: u64,
    sent: u64,
}

struct ConsolePending {
    receiver: Receiver<Result<Value, String>>,
    started: Instant,
}

/// A GUI window observing an existing loopback RPC daemon. `node` supplies
/// configured network/data-directory identity only; it is never started here.
pub struct AttachedApp {
    worker: Worker,
    network: String,
    rpc_addr: SocketAddr,
    data_dir: PathBuf,
    page: Page,
    snapshot: Option<Snapshot>,
    last_error: Option<String>,
    updates_disconnected: bool,
    inspector: block_inspector::State,
    traffic: VecDeque<TrafficSample>,
    console_method: String,
    console_params: String,
    console_pending: Option<ConsolePending>,
    console_result: Option<Result<Value, String>>,
    console_message: Option<String>,
    swirl: Option<eframe::egui::TextureHandle>,
    prefs: Prefs,
    config_file: Option<PathBuf>,
    ui_scale: f32,
    black_theme: bool,
    about_open: bool,
}

impl AttachedApp {
    /// Construct a read-only window against an existing loopback RPC server.
    /// The worker validates loopback access and performs cookie reads/RPC off-thread.
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        node: Node,
        config_file: Option<PathBuf>,
        addr: SocketAddr,
        theme_override: Option<ThemeChoice>,
        close: Arc<AtomicBool>,
    ) -> Self {
        {
            let wake_ctx = cc.egui_ctx.clone();
            std::thread::spawn(move || {
                use std::sync::atomic::Ordering::Relaxed;
                while !close.load(Relaxed) {
                    std::thread::sleep(Duration::from_millis(100));
                }
                wake_ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            });
        }
        theme::install_fonts(&cc.egui_ctx, theme::Skin::Standard);
        theme::install_style(&cc.egui_ctx);
        let mut prefs = Prefs::load(cc.storage);
        if let Some(theme) = theme_override {
            prefs.theme = theme;
        }
        let ui_scale = cc
            .storage
            .and_then(|storage| eframe::get_value::<f32>(storage, ATTACHED_SCALE_KEY))
            .filter(|scale| ATTACHED_SCALES.iter().any(|(value, _)| *value == *scale))
            .unwrap_or(prefs.size);
        let black_theme = if theme_override.is_some() {
            false
        } else {
            cc.storage
                .and_then(|storage| eframe::get_value::<bool>(storage, ATTACHED_BLACK_KEY))
                .unwrap_or(false)
        };
        let mut appearance = prefs.clone();
        appearance.toybox = false;
        appearance.apply(&cc.egui_ctx);
        cc.egui_ctx.set_zoom_factor(ui_scale);
        if black_theme {
            apply_black_visuals(&cc.egui_ctx);
        }
        let network = node.config().get().network.to_string();
        let data_dir = node.config().network_data_dir();
        let worker = Worker::start(addr, data_dir, cc.egui_ctx.clone());
        Self {
            worker,
            network,
            rpc_addr: addr,
            data_dir: node.config().network_data_dir(),
            page: Page::Overview,
            snapshot: None,
            last_error: None,
            updates_disconnected: false,
            inspector: block_inspector::State::default(),
            traffic: VecDeque::with_capacity(MAX_TRAFFIC_SAMPLES),
            console_method: "getblockchaininfo".into(),
            console_params: "[]".into(),
            console_pending: None,
            console_result: None,
            console_message: None,
            swirl: brand::swirl_texture(&cc.egui_ctx),
            prefs,
            config_file,
            ui_scale,
            black_theme,
            about_open: false,
        }
    }

    fn poll(&mut self) {
        loop {
            match self.worker.updates.try_recv() {
                Ok(Ok(snapshot)) => {
                    self.observe_traffic(&snapshot);
                    self.snapshot = Some(snapshot);
                    self.last_error = None;
                    self.updates_disconnected = false;
                }
                Ok(Err(error)) => self.last_error = Some(error),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.updates_disconnected = true;
                    break;
                }
            }
        }
        self.poll_console();
    }

    fn observe_traffic(&mut self, snapshot: &Snapshot) {
        let Some(network) = snapshot.net.as_ref() else {
            return;
        };
        let (Some(recv), Some(sent)) = (
            network.get("totalbytesrecv").and_then(Value::as_u64),
            network.get("totalbytessent").and_then(Value::as_u64),
        ) else {
            return;
        };
        if self
            .traffic
            .back()
            .is_some_and(|last| last.at >= snapshot.observed_at)
        {
            return;
        }
        self.traffic.push_back(TrafficSample {
            at: snapshot.observed_at,
            recv,
            sent,
        });
        while self.traffic.len() > MAX_TRAFFIC_SAMPLES {
            self.traffic.pop_front();
        }
    }

    fn poll_console(&mut self) {
        let Some(pending) = &self.console_pending else {
            return;
        };
        let outcome = match pending.receiver.try_recv() {
            Ok(value) => Some(value),
            Err(TryRecvError::Empty) if pending.started.elapsed() >= CONSOLE_TIMEOUT => Some(Err(
                "RPC request timed out; check the daemon connection.".into(),
            )),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => Some(Err(
                "RPC worker ended the request without a response.".into(),
            )),
        };
        if let Some(outcome) = outcome {
            self.console_pending = None;
            self.console_result = Some(outcome);
        }
    }

    fn show_header(&mut self, ui: &mut Ui, pal: Palette) {
        ui.horizontal_wrapped(|ui| {
            if let Some(swirl) = &self.swirl {
                ui.add(
                    egui::Image::new(swirl)
                        .fit_to_exact_size(vec2(32.0, 32.0))
                        .tint(pal.text),
                );
            }
            ui.vertical(|ui| {
                ui.heading("Avila Node");
                ui.add(
                    egui::Label::new(
                        RichText::new(format!("Attached · {} · {}", self.network, self.rpc_addr))
                            .size(12.0)
                            .color(pal.muted),
                    )
                    .wrap(),
                );
            });
            ui.add_space(8.0);
            ui.menu_button("Node", |ui| {
                if ui.button("Copy attached-node diagnostics").clicked() {
                    ui.ctx().copy_text(self.diagnostics());
                    ui.close();
                }
                if ui
                    .add_enabled(
                        self.config_file.is_some(),
                        egui::Button::new("Open config folder"),
                    )
                    .clicked()
                {
                    if let Some(path) = self
                        .config_file
                        .as_deref()
                        .and_then(std::path::Path::parent)
                    {
                        open_folder(path);
                    }
                    ui.close();
                }
                if ui.button("Open data folder").clicked() {
                    open_folder(&self.data_dir);
                    ui.close();
                }
                ui.separator();
                if ui.button("Close monitor").clicked() {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                    ui.close();
                }
            });
            ui.menu_button("View", |ui| {
                ui.label(RichText::new("Theme").weak());
                let mut appearance_changed = false;
                if ui
                    .selectable_label(
                        self.prefs.theme == ThemeChoice::Light && !self.black_theme,
                        "Light",
                    )
                    .clicked()
                {
                    self.black_theme = false;
                    self.prefs.theme = ThemeChoice::Light;
                    appearance_changed = true;
                }
                if ui
                    .selectable_label(
                        self.prefs.theme == ThemeChoice::Dark && !self.black_theme,
                        "Dark",
                    )
                    .clicked()
                {
                    self.black_theme = false;
                    self.prefs.theme = ThemeChoice::Dark;
                    appearance_changed = true;
                }
                if ui
                    .selectable_label(self.prefs.theme == ThemeChoice::System, "System")
                    .clicked()
                {
                    self.black_theme = false;
                    self.prefs.theme = ThemeChoice::System;
                    appearance_changed = true;
                }
                if ui.selectable_label(self.black_theme, "Black").clicked() {
                    self.black_theme = true;
                    self.prefs.theme = ThemeChoice::Dark;
                    appearance_changed = true;
                }
                ui.separator();
                ui.label(RichText::new("Interface scale").weak());
                for (scale, label) in ATTACHED_SCALES {
                    if ui
                        .selectable_value(&mut self.ui_scale, scale, label)
                        .clicked()
                    {
                        ui.ctx().set_zoom_factor(scale);
                    }
                }
                ui.separator();
                ui.checkbox(&mut self.prefs.hide_addresses, "Hide peer addresses");
                if appearance_changed {
                    theme::install_style(ui.ctx());
                    let mut appearance = self.prefs.clone();
                    appearance.toybox = false;
                    appearance.apply(ui.ctx());
                    ui.ctx().set_zoom_factor(self.ui_scale);
                    if self.black_theme {
                        apply_black_visuals(ui.ctx());
                    }
                }
            });
            ui.menu_button("Help", |ui| {
                if ui.button("About Avila Node").clicked() {
                    self.about_open = true;
                    ui.close();
                }
            });
            ui.add_space(8.0);
            let (label, color) = self.connection_label(pal);
            ui.add(egui::Label::new(RichText::new(label).color(color)).wrap());
        });
        ui.add_space(7.0);
        ui.horizontal_wrapped(|ui| {
            for page in Page::ALL {
                let selected = self.page == page;
                let button = egui::Button::new(page.title()).selected(selected);
                if ui.add(button).clicked() {
                    self.page = page;
                }
            }
        });
        ui.add_space(8.0);
        ui.painter().hline(
            ui.min_rect().x_range(),
            ui.cursor().top(),
            Stroke::new(1.0, pal.hairline),
        );
    }

    fn connection_label(&self, pal: Palette) -> (String, Color32) {
        match (&self.snapshot, &self.last_error) {
            (None, Some(error)) if self.updates_disconnected => {
                (format!("RPC disconnected · {error}"), pal.alert)
            }
            (None, Some(error)) => (format!("RPC unavailable · {error}"), pal.alert),
            (None, None) => ("Connecting to RPC".into(), pal.muted),
            (Some(snapshot), _) if self.updates_disconnected => (
                format!(
                    "Disconnected · last sample {} ago",
                    age(snapshot.observed_at)
                ),
                pal.alert,
            ),
            (Some(snapshot), Some(_)) => (
                format!("Stale · last sample {} ago", age(snapshot.observed_at)),
                pal.alert,
            ),
            (Some(snapshot), None) if snapshot.observed_at.elapsed() > Duration::from_secs(5) => (
                format!("Stale · last sample {} ago", age(snapshot.observed_at)),
                pal.alert,
            ),
            (Some(snapshot), None) => (
                format!("Connected · sampled {} ago", age(snapshot.observed_at)),
                pal.signal_text,
            ),
        }
    }

    fn diagnostics(&self) -> String {
        let mut out = format!(
            "Avila Node attached diagnostics\nnetwork: {}\nrpc endpoint: {}\n",
            self.network, self.rpc_addr
        );
        match (&self.snapshot, &self.last_error) {
            (Some(snapshot), None) => {
                out.push_str(&format!(
                    "sample age: {}\nconnected height: {}\nheader height: {}\ninitial download estimate: {}\n",
                    age(snapshot.observed_at),
                    number(snapshot.chain.get("blocks")),
                    number(snapshot.chain.get("headers")),
                    boolean(snapshot.chain.get("initialblockdownload")),
                ));
            }
            (Some(snapshot), Some(error)) => {
                out.push_str(&format!(
                    "status: stale\nsample age: {}\nlatest error: {}\n",
                    age(snapshot.observed_at),
                    error
                ));
            }
            (None, Some(error)) => out.push_str(&format!("status: unavailable\nerror: {error}\n")),
            (None, None) => out.push_str("status: connecting\n"),
        }
        if let Some(snapshot) = &self.snapshot {
            out.push_str(&format!(
                "historical script policy: {}\n",
                historical_script_policy(&snapshot.validation)
            ));
            if snapshot.chain.get("blocks").and_then(Value::as_u64) == Some(0)
                || snapshot.chain.get("headers").and_then(Value::as_u64) == Some(0)
            {
                out.push_str("bootstrap: connected or header height is zero; do not read the height ratio as completion\n");
            }
        }
        out
    }

    fn page(&mut self, ui: &mut Ui, pal: Palette) {
        ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| match self.page {
                Page::Overview => self.overview(ui, pal),
                Page::Blocks => self.blocks(ui),
                Page::Peers => self.peers(ui, pal),
                Page::Traffic => self.traffic_page(ui, pal),
                Page::Console => self.console(ui, pal),
            });
    }

    fn overview(&self, ui: &mut Ui, pal: Palette) {
        section(ui, "Chain and validation", pal);
        let Some(snapshot) = &self.snapshot else {
            unavailable(ui, "No successful status sample is available yet.", pal);
            return;
        };
        let connected_height = snapshot.chain.get("blocks").and_then(Value::as_u64);
        let header_height = snapshot.chain.get("headers").and_then(Value::as_u64);
        if connected_height == Some(0) || header_height == Some(0) {
            ui.colored_label(
                pal.alert,
                "Bootstrap state: connected or header height is zero. Height ratios do not indicate completion.",
            );
        }
        fact(
            ui,
            "Connected height",
            number(snapshot.chain.get("blocks")),
            pal,
        );
        fact(
            ui,
            "Best header height",
            number(snapshot.chain.get("headers")),
            pal,
        );
        fact(
            ui,
            "Best block hash",
            string(snapshot.chain.get("bestblockhash")),
            pal,
        );
        fact(
            ui,
            "Initial download estimate",
            boolean(snapshot.chain.get("initialblockdownload")),
            pal,
        );
        fact(
            ui,
            "Connected/header ratio",
            height_ratio(snapshot.chain.get("blocks"), snapshot.chain.get("headers")),
            pal,
        );
        ui.label(
            RichText::new("A 100% height ratio means only that the reported heights match; it is not an ETA, a measure of validation work, or a catch-up guarantee.")
                .small()
                .color(pal.muted),
        );
        fact(
            ui,
            "Historical script policy",
            historical_script_policy(&snapshot.validation),
            pal,
        );
        fact(
            ui,
            "Validation coverage",
            snapshot
                .validation
                .get("coverage")
                .and_then(|v| v.get("state"))
                .and_then(Value::as_str)
                .unwrap_or("Unknown")
                .to_owned(),
            pal,
        );
        fact(
            ui,
            "Coverage explanation",
            snapshot
                .validation
                .get("coverage")
                .and_then(|v| v.get("plain"))
                .and_then(Value::as_str)
                .unwrap_or("Not reported by the daemon")
                .to_owned(),
            pal,
        );
        if let Some(ranges) = snapshot
            .validation
            .get("coverage")
            .and_then(|v| v.get("verified_ranges"))
        {
            fact(ui, "Verified ranges", compact_json(ranges), pal);
        }
        if let Some(assumed) = snapshot
            .validation
            .get("coverage")
            .and_then(|v| v.get("snapshot_assumed"))
        {
            fact(
                ui,
                "Snapshot assumed",
                if assumed.is_null() {
                    "None".into()
                } else {
                    compact_json(assumed)
                },
                pal,
            );
        }
        ui.add_space(16.0);
        section(ui, "Network sample", pal);
        fact(
            ui,
            "Connections",
            snapshot
                .network
                .as_ref()
                .map(|net| number(net.get("connections")))
                .unwrap_or_else(|| "Unavailable in this sample".into()),
            pal,
        );
        fact(
            ui,
            "Network active",
            snapshot
                .network
                .as_ref()
                .map(|net| boolean(net.get("networkactive")))
                .unwrap_or_else(|| "Unavailable in this sample".into()),
            pal,
        );
        ui.label(
            RichText::new(format!("Sample time: {} ago", age(snapshot.observed_at)))
                .small()
                .color(pal.muted),
        );
        ui.label(
            RichText::new(
                "RPC calls are sampled sequentially; values may differ slightly in time.",
            )
            .small()
            .color(pal.muted),
        );
    }

    fn blocks(&mut self, ui: &mut Ui) {
        let heights = self.snapshot.as_ref().map(|snapshot| {
            let connected = snapshot
                .validation
                .get("connected_height")
                .and_then(Value::as_u64)
                .or_else(|| snapshot.chain.get("blocks").and_then(Value::as_u64))
                .and_then(|v| u32::try_from(v).ok());
            let headers = snapshot
                .validation
                .get("header_height")
                .and_then(Value::as_u64)
                .or_else(|| snapshot.chain.get("headers").and_then(Value::as_u64))
                .and_then(|v| u32::try_from(v).ok());
            (connected, headers)
        });
        let Some((Some(connected), Some(headers))) = heights else {
            ui.heading("Block inspector");
            unavailable(
                ui,
                "The daemon has not reported both connected and header heights; block inspection is paused until those values are available.",
                Palette::of(ui.ctx()),
            );
            return;
        };
        self.inspector
            .ui(ui, Some(&self.worker.control), connected, headers);
    }

    fn peers(&self, ui: &mut Ui, pal: Palette) {
        section(ui, "Connected peers", pal);
        let Some(snapshot) = &self.snapshot else {
            unavailable(ui, "No successful peer sample is available.", pal);
            return;
        };
        let Some(peers) = snapshot.peers.as_ref().and_then(Value::as_array) else {
            unavailable(
                ui,
                "Peer information was unavailable in the latest sample.",
                pal,
            );
            return;
        };
        if peers.is_empty() {
            ui.label("The daemon reported no peers in this sample.");
            return;
        }
        ui.label(
            RichText::new(format!(
                "{} peers · sampled {} ago",
                peers.len(),
                age(snapshot.observed_at)
            ))
            .weak(),
        );
        ui.add_space(6.0);
        egui::Grid::new("attached_peer_rows")
            .striped(true)
            .num_columns(5)
            .spacing([14.0, 6.0])
            .show(ui, |ui| {
                for heading in ["ID", "Address", "Direction", "Agent", "Height"] {
                    ui.label(RichText::new(heading).strong());
                }
                ui.end_row();
                for peer in peers.iter().take(500) {
                    ui.label(number(peer.get("id")));
                    ui.label(if self.prefs.hide_addresses {
                        "Hidden".to_owned()
                    } else {
                        string(peer.get("addr"))
                    });
                    ui.label(
                        peer.get("inbound")
                            .and_then(Value::as_bool)
                            .map(|inbound| if inbound { "Inbound" } else { "Outbound" })
                            .unwrap_or("Unknown"),
                    );
                    ui.label(string(peer.get("subver")));
                    ui.label(number(peer.get("synced_blocks")));
                    ui.end_row();
                }
            });
        if peers.len() > 500 {
            ui.label(
                RichText::new(format!("Showing the first 500 of {} peers.", peers.len())).weak(),
            );
        }
    }

    fn traffic_page(&self, ui: &mut Ui, pal: Palette) {
        section(ui, "Network traffic", pal);
        let Some(snapshot) = &self.snapshot else {
            unavailable(ui, "No successful network sample is available.", pal);
            return;
        };
        if let Some(network) = &snapshot.net {
            fact(
                ui,
                "Total received",
                network
                    .get("totalbytesrecv")
                    .and_then(Value::as_u64)
                    .map(format_bytes)
                    .unwrap_or_else(|| "Unknown".into()),
                pal,
            );
            fact(
                ui,
                "Total sent",
                network
                    .get("totalbytessent")
                    .and_then(Value::as_u64)
                    .map(format_bytes)
                    .unwrap_or_else(|| "Unknown".into()),
                pal,
            );
        } else {
            unavailable(
                ui,
                "Traffic counters were unavailable in the latest sample.",
                pal,
            );
        }
        let counter_age = self
            .traffic
            .back()
            .map(|sample| format!("Counters sampled {} ago", age(sample.at)))
            .unwrap_or_else(|| "No valid traffic-counter sample yet.".into());
        ui.label(RichText::new(counter_age).small().color(pal.muted));
        ui.add_space(14.0);
        draw_traffic(ui, &self.traffic, pal);
    }

    fn console(&mut self, ui: &mut Ui, pal: Palette) {
        section(ui, "Read-only RPC console", pal);
        ui.label(
            RichText::new("Requests are sent to the attached daemon through its read-only method allowlist. One request can be pending at a time.")
                .color(pal.muted),
        );
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label("Method");
            ui.add(
                TextEdit::singleline(&mut self.console_method)
                    .desired_width(280.0)
                    .hint_text("e.g. getblockchaininfo"),
            );
        });
        ui.label("Parameters (JSON array)");
        ui.label(RichText::new("Input is limited to 8 KiB; the daemon worker enforces its read-only method allowlist.").small().color(pal.muted));
        ui.add(
            TextEdit::multiline(&mut self.console_params)
                .desired_width(ui.available_width())
                .desired_rows(3)
                .lock_focus(true),
        );
        truncate_utf8(&mut self.console_method, 128);
        truncate_utf8(&mut self.console_params, MAX_CONSOLE_INPUT);
        let pending = self.console_pending.is_some();
        if ui
            .add_enabled(!pending, egui::Button::new("Run read-only request"))
            .clicked()
        {
            self.run_console_request();
        }
        if pending {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Waiting for the node response…");
            });
        }
        if let Some(message) = &self.console_message {
            ui.colored_label(pal.alert, message);
        }
        if let Some(result) = &self.console_result {
            ui.add_space(10.0);
            match result {
                Ok(value) => {
                    let display_value = if self.prefs.hide_addresses {
                        let mut redacted = value.clone();
                        redact_peer_addresses(&mut redacted);
                        redacted
                    } else {
                        value.clone()
                    };
                    let mut text = serde_json::to_string_pretty(&display_value)
                        .unwrap_or_else(|_| "Response could not be formatted as JSON.".into());
                    truncate_utf8(&mut text, MAX_CONSOLE_OUTPUT);
                    ui.label(RichText::new("Response").strong());
                    ScrollArea::vertical().max_height(360.0).show(ui, |ui| {
                        ui.add(
                            TextEdit::multiline(&mut text)
                                .font(egui::TextStyle::Monospace)
                                .desired_width(ui.available_width())
                                .desired_rows(12)
                                .interactive(false),
                        );
                    });
                }
                Err(error) => {
                    ui.colored_label(pal.alert, error);
                }
            }
        }
    }

    fn run_console_request(&mut self) {
        self.console_message = None;
        self.console_result = None;
        if self.console_method.is_empty()
            || !self
                .console_method
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            self.console_message = Some("Enter a valid RPC method name.".into());
            return;
        }
        if self.console_params.len() > MAX_CONSOLE_INPUT {
            self.console_message = Some("Parameters exceed the 8 KiB input limit.".into());
            return;
        }
        let params: Vec<Value> = match serde_json::from_str(&self.console_params) {
            Ok(params) => params,
            Err(error) => {
                self.console_message = Some(format!("Parameters must be a JSON array: {error}"));
                return;
            }
        };
        let (reply, receiver) = std::sync::mpsc::sync_channel(1);
        let request = ConsoleRequest {
            method: self.console_method.clone(),
            params,
            reply,
        };
        match self.worker.console.try_send(request) {
            Ok(()) => {
                self.console_pending = Some(ConsolePending {
                    receiver,
                    started: Instant::now(),
                });
            }
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                self.console_message =
                    Some("The RPC worker is busy; retry after the current request.".into());
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                self.console_message =
                    Some("The RPC console is disconnected from its worker.".into());
            }
        }
    }
}

impl eframe::App for AttachedApp {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        self.poll();
        // Keep the displayed sample age current, while allowing the worker's
        // own repaint notification to wake the window immediately on updates.
        let ctx = ui.ctx().clone();
        ctx.request_repaint_after(Duration::from_secs(1));
        let pal = if self.black_theme {
            black_palette(Palette::of(&ctx))
        } else {
            Palette::of(&ctx)
        };
        egui::Panel::top("attached_top")
            .frame(
                Frame::new()
                    .fill(pal.canvas)
                    .inner_margin(egui::Margin::symmetric(18, 12)),
            )
            .show(ui, |ui| self.show_header(ui, pal));
        egui::CentralPanel::default()
            .frame(
                Frame::new()
                    .fill(pal.canvas)
                    .inner_margin(egui::Margin::same(18)),
            )
            .show(ui, |ui| self.page(ui, pal));
        if self.about_open {
            egui::Window::new("About Avila Node")
                .open(&mut self.about_open)
                .resizable(false)
                .show(ui.ctx(), |ui| {
                    ui.heading(format!("Avila Node {}", env!("CARGO_PKG_VERSION")));
                    ui.label("Attached read-only monitor");
                    ui.label(format!("Network: {}", self.network));
                    ui.label("Closing this monitor leaves the daemon running.");
                });
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // Dropping the observation worker closes this window's client only;
        // the independently-running daemon remains untouched.
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        self.prefs.save(storage);
        eframe::set_value(storage, ATTACHED_SCALE_KEY, &self.ui_scale);
        eframe::set_value(storage, ATTACHED_BLACK_KEY, &self.black_theme);
    }
}

fn apply_black_visuals(ctx: &egui::Context) {
    ctx.style_mut_of(egui::Theme::Dark, |style| {
        style.visuals.dark_mode = true;
        style.visuals.panel_fill = Color32::BLACK;
        style.visuals.window_fill = Color32::BLACK;
        style.visuals.extreme_bg_color = Color32::from_gray(4);
        style.visuals.faint_bg_color = Color32::from_gray(18);
        style.visuals.code_bg_color = Color32::from_gray(12);
        style.visuals.widgets.inactive.bg_fill = Color32::from_gray(22);
        style.visuals.widgets.hovered.bg_fill = Color32::from_gray(38);
        style.visuals.widgets.active.bg_fill = Color32::from_gray(52);
        style.visuals.widgets.open.bg_fill = Color32::from_gray(30);
    });
}

fn black_palette(mut palette: Palette) -> Palette {
    palette.canvas = Color32::BLACK;
    palette.raised = Color32::from_gray(10);
    palette.well = Color32::from_gray(5);
    palette.hairline = Color32::from_gray(42);
    palette.text = Color32::from_gray(238);
    palette.muted = Color32::from_gray(160);
    palette.faint = Color32::from_gray(100);
    palette.primary = Color32::from_gray(238);
    palette.on_primary = Color32::BLACK;
    palette
}

fn redact_peer_addresses(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, child) in object.iter_mut() {
                if matches!(key.as_str(), "addr" | "addrlocal" | "addrbind") {
                    *child = Value::String("Hidden".into());
                } else {
                    redact_peer_addresses(child);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_peer_addresses(item);
            }
        }
        _ => {}
    }
}

fn section(ui: &mut Ui, title: &str, pal: Palette) {
    ui.heading(RichText::new(title).color(pal.text));
    ui.painter().hline(
        ui.min_rect().x_range(),
        ui.cursor().top(),
        Stroke::new(1.0, pal.hairline),
    );
    ui.add_space(8.0);
}

fn fact(ui: &mut Ui, name: &str, value: String, pal: Palette) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(name).color(pal.muted));
        ui.add_space(10.0);
        ui.label(RichText::new(value).color(pal.text));
    });
}

fn unavailable(ui: &mut Ui, message: &str, pal: Palette) {
    ui.label(RichText::new(message).color(pal.muted));
}

fn number(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_u64)
        .map(|value| value.to_string())
        .unwrap_or_else(|| "Unknown".into())
}

fn string(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "Unknown".into())
}

fn boolean(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_bool)
        .map(|value| if value { "Yes" } else { "No" }.to_owned())
        .unwrap_or_else(|| "Unknown".into())
}

fn height_ratio(connected: Option<&Value>, headers: Option<&Value>) -> String {
    let (Some(connected), Some(headers)) = (
        connected.and_then(Value::as_u64),
        headers.and_then(Value::as_u64),
    ) else {
        return "Unknown".into();
    };
    if headers == 0 || connected > headers {
        return "Unknown".into();
    }
    format!("{:.2}%", connected as f64 / headers as f64 * 100.0)
}

fn historical_script_policy(validation: &Value) -> String {
    let policy = validation.get("validation_policy");
    match policy.and_then(|value| value.get("historical_scripts_required")) {
        Some(Value::Bool(true)) => "All historical scripts required".into(),
        Some(Value::Bool(false)) => match policy
            .and_then(|value| value.get("assume_valid_checkpoint"))
            .and_then(Value::as_str)
            .filter(|checkpoint| {
                checkpoint.len() == 64 && checkpoint.bytes().all(|byte| byte.is_ascii_hexdigit())
            }) {
            Some(checkpoint) => format!("AssumeValid checkpoint configured: {checkpoint}"),
            None => "AssumeValid configured; checkpoint is unknown".into(),
        },
        _ => "Unknown (daemon did not report validation policy)".into(),
    }
}

fn compact_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "Unknown".into())
}

fn age(at: Instant) -> String {
    let elapsed = at.elapsed();
    if elapsed < Duration::from_secs(60) {
        format!("{}s", elapsed.as_secs())
    } else {
        format!("{}m {}s", elapsed.as_secs() / 60, elapsed.as_secs() % 60)
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut amount = bytes as f64;
    let mut unit = 0;
    while amount >= 1024.0 && unit + 1 < UNITS.len() {
        amount /= 1024.0;
        unit += 1;
    }
    format!("{amount:.1} {}", UNITS[unit])
}

fn open_folder(path: &std::path::Path) {
    if !path.is_dir() {
        return;
    }
    #[cfg(target_os = "windows")]
    let program = "explorer";
    #[cfg(target_os = "macos")]
    let program = "open";
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let program = "xdg-open";
    if let Ok(mut child) = std::process::Command::new(program)
        .arg(path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
}

fn truncate_utf8(value: &mut String, max_bytes: usize) {
    if value.len() <= max_bytes {
        return;
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
}

fn draw_traffic(ui: &mut Ui, samples: &VecDeque<TrafficSample>, pal: Palette) {
    let (rect, _) =
        ui.allocate_exact_size(vec2(ui.available_width().max(1.0), 210.0), Sense::hover());
    ui.painter().rect_filled(rect, 6.0, pal.well);
    let ordered: Vec<&TrafficSample> = samples.iter().collect();
    let rates: Vec<(f64, f64)> = ordered
        .windows(2)
        .filter_map(|pair| {
            let elapsed = pair[1].at.duration_since(pair[0].at).as_secs_f64();
            if elapsed <= 0.0 || elapsed > 5.0 {
                return None;
            }
            Some((
                pair[1].recv.checked_sub(pair[0].recv)? as f64 / elapsed,
                pair[1].sent.checked_sub(pair[0].sent)? as f64 / elapsed,
            ))
        })
        .collect();
    if rates.is_empty() {
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            "Collecting valid traffic intervals",
            egui::FontId::proportional(13.0),
            pal.muted,
        );
        ui.label("Rates are omitted across counter resets, missing counters, or sample gaps over five seconds.");
        return;
    }
    let max = rates
        .iter()
        .flat_map(|(recv, sent)| [*recv, *sent])
        .fold(0.0_f64, f64::max)
        .max(1.0);
    let to_point = |index: usize, value: f64| {
        let x = rect.left()
            + rect.width() * index as f32 / (rates.len().saturating_sub(1).max(1) as f32);
        let y = rect.bottom() - rect.height() * (value / max) as f32;
        pos2(x, y)
    };
    for (i, pair) in rates.windows(2).enumerate() {
        ui.painter().line_segment(
            [to_point(i, pair[0].0), to_point(i + 1, pair[1].0)],
            Stroke::new(2.0, pal.signal),
        );
        ui.painter().line_segment(
            [to_point(i, pair[0].1), to_point(i + 1, pair[1].1)],
            Stroke::new(2.0, pal.text),
        );
    }
    if rates.len() == 1 {
        ui.painter()
            .circle_filled(to_point(0, rates[0].0), 3.0, pal.signal);
        ui.painter()
            .circle_filled(to_point(0, rates[0].1), 3.0, pal.text);
    }
    ui.horizontal(|ui| {
        ui.colored_label(pal.signal, "Received");
        ui.colored_label(pal.text, "Sent");
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(format!("Peak {:.1} KiB/s", max / 1024.0));
        });
    });
    if let Some((recv, sent)) = rates.last() {
        ui.label(
            RichText::new(format!(
                "Latest valid interval: received {:.1} KiB/s · sent {:.1} KiB/s",
                recv / 1024.0,
                sent / 1024.0
            ))
            .small()
            .color(pal.muted),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{apply_black_visuals, historical_script_policy, redact_peer_addresses};
    use crate::theme::{self, Palette};
    use eframe::egui::{self, Color32};
    use serde_json::json;

    #[test]
    fn script_policy_requires_explicit_true_and_labels_assumevalid_checkpoint() {
        let checkpoint = format!("{:064x}", 1);
        assert_eq!(
            historical_script_policy(&json!({
                "validation_policy": {
                    "historical_scripts_required": true,
                    "assume_valid_checkpoint": null
                }
            })),
            "All historical scripts required"
        );
        assert_eq!(
            historical_script_policy(&json!({
                "validation_policy": {
                    "historical_scripts_required": false,
                    "assume_valid_checkpoint": checkpoint.clone()
                }
            })),
            format!("AssumeValid checkpoint configured: {checkpoint}")
        );
        assert_eq!(
            historical_script_policy(&json!({
                "validation_policy": {
                    "historical_scripts_required": false,
                    "assume_valid_checkpoint": null
                }
            })),
            "AssumeValid configured; checkpoint is unknown"
        );
        assert_eq!(
            historical_script_policy(&json!({"coverage":{"state":"full_validation"}})),
            "Unknown (daemon did not report validation policy)"
        );
    }

    #[test]
    fn hide_peer_addresses_redacts_nested_rpc_peer_fields() {
        let mut peers = json!([
            { "addr": "198.51.100.4:8333", "addrlocal": "192.0.2.1:8333", "subver": "/node/" },
            { "addr": "[2001:db8::1]:8333", "addrbind": "0.0.0.0:8333" }
        ]);

        redact_peer_addresses(&mut peers);

        assert_eq!(peers[0]["addr"], "Hidden");
        assert_eq!(peers[0]["addrlocal"], "Hidden");
        assert_eq!(peers[0]["subver"], "/node/");
        assert_eq!(peers[1]["addr"], "Hidden");
        assert_eq!(peers[1]["addrbind"], "Hidden");
    }

    #[test]
    fn standard_style_install_resets_black_theme_visuals() {
        let ctx = egui::Context::default();
        theme::install_style(&ctx);
        apply_black_visuals(&ctx);
        let dark = ctx.style_of(egui::Theme::Dark);
        assert_eq!(dark.visuals.panel_fill, Color32::BLACK);
        assert_eq!(dark.visuals.window_fill, Color32::BLACK);

        theme::install_style(&ctx);
        let dark = ctx.style_of(egui::Theme::Dark);
        assert_eq!(dark.visuals.panel_fill, Palette::DARK.canvas);
        assert_eq!(dark.visuals.window_fill, Palette::DARK.raised);
    }
}
