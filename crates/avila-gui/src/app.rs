use crate::appearance::{AppearanceConfig, AppearanceMode};
use avila_core::CapabilityState;
use avila_node::Node;
use avila_node::events::{EventRecord, NodeEvent};
use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Page {
    #[default]
    Overview,
    Capabilities,
    Configuration,
    Events,
}

impl Page {
    const ALL: [Self; 4] = [
        Self::Overview,
        Self::Capabilities,
        Self::Configuration,
        Self::Events,
    ];

    fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Capabilities => "Capabilities",
            Self::Configuration => "Configuration",
            Self::Events => "Events",
        }
    }
}

pub struct AvilaApp {
    node: Node,
    page: Page,
    logo: egui::TextureHandle,
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
            style.spacing.item_spacing = egui::vec2(10.0, 8.0);
        });
        Self {
            node,
            page: Page::default(),
            logo: ctx.load_texture("avila-node-logo", logo, egui::TextureOptions::LINEAR),
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

    pub fn render(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        self.appearance.scale = ctx.zoom_factor();
        self.shortcuts(&ctx);
        egui::Panel::top("menu").show(ui, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                ui.menu_button("View", |ui| {
                    for page in Page::ALL {
                        if ui
                            .selectable_value(&mut self.page, page, page.title())
                            .clicked()
                        {
                            ui.close();
                        }
                    }
                    ui.separator();
                    if ui.button("Appearance…").clicked() {
                        self.show_appearance = true;
                        ui.close();
                    }
                });
                ui.menu_button("Help", |ui| {
                    if ui.button("About and keyboard shortcuts").clicked() {
                        self.show_help = true;
                        ui.close();
                    }
                    #[cfg(debug_assertions)]
                    if ui.button("egui development tools").clicked() {
                        self.show_egui_tools = true;
                        ui.close();
                    }
                });
            });
        });
        egui::Panel::bottom("status").show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.strong("Local inspection");
                ui.separator();
                ui.label(format!("{} selected", self.node.config().get().network));
                ui.separator();
                ui.label("No active Bitcoin connection");
            });
        });
        // High zoom moves navigation above the content to preserve reading space.
        if ui.available_width() >= 650.0 {
            egui::Panel::left("navigation")
                .resizable(true)
                .default_size(190.0)
                .size_range(150.0..=260.0)
                .show(ui, |ui| {
                    egui::ScrollArea::vertical().show(ui, |ui| self.navigation(ui));
                });
        } else {
            egui::Panel::top("compact_navigation").show(ui, |ui| {
                egui::ComboBox::from_id_salt("page")
                    .selected_text(self.page.title())
                    .show_ui(ui, |ui| {
                        for page in Page::ALL {
                            ui.selectable_value(&mut self.page, page, page.title());
                        }
                    });
            });
        }
        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading(self.page.title());
            ui.add_space(8.0);
            match self.page {
                Page::Events => {
                    egui::ScrollArea::vertical()
                        .id_salt("event_page")
                        .show(ui, |ui| self.events(ui));
                }
                Page::Capabilities => self.capabilities(ui),
                Page::Overview | Page::Configuration => {
                    egui::ScrollArea::both()
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            if self.page == Page::Overview {
                                self.overview(ui);
                            } else {
                                self.configuration(ui);
                            }
                        });
                }
            }
        });
        self.windows(&ctx);
    }

    fn navigation(&mut self, ui: &mut egui::Ui) {
        ui.add_space(12.0);
        ui.add(egui::Image::new(&self.logo).fit_to_exact_size(egui::vec2(80.0, 80.0)))
            .on_hover_text("Avila Node · Connor Avila");
        ui.heading("Avila Node");
        ui.label(RichText::new("Independent by design").small());
        ui.add_space(16.0);
        for page in Page::ALL {
            ui.selectable_value(&mut self.page, page, page.title());
        }
        ui.add_space(24.0);
        ui.separator();
        ui.label(RichText::new("Development foundation").color(self.appearance.theme.accent()));
        ui.small("Open source · MIT");
        ui.small(format!("Build {}", env!("CARGO_PKG_VERSION")));
    }

    fn overview(&self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.strong("Verification has not started");
            ui.label("This build can inspect configuration and local events. Bitcoin validation, storage and networking are still being implemented.");
        });
        ui.add_space(16.0);
        let snapshot = self.node.snapshot();
        egui::Grid::new("verification")
            .spacing([24.0, 12.0])
            .show(ui, |ui| {
                for (label, value) in [
                    ("Selected network", snapshot.network.to_string()),
                    ("Verified chain tip", "Unavailable".into()),
                    ("Historical validation", "Not started".into()),
                    ("Connected peers", "Unavailable".into()),
                ] {
                    ui.label(label);
                    ui.label(value);
                    ui.end_row();
                }
            });
        ui.add_space(20.0);
        ui.collapsing("What will a complete Avila Node do?", |ui| {
            ui.label("Independently validate and synchronize Bitcoin, recover durable chainstate, relay transactions, serve wallets, enforce privacy choices, and explain its decisions.");
            ui.label("The roadmap targets a complete node someone could choose as their primary node.");
        });
        ui.collapsing("How to interpret these measurements", |ui| {
            ui.label("Unavailable means this process has no measurement. Selecting a network does not connect to it. An active chain tip, complete historical validation and a wallet's scan coverage will be tracked independently.");
        });
    }

    fn capabilities(&mut self, ui: &mut egui::Ui) {
        ui.label("Implementation status of this build.");
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
            .header(26.0, |mut header| {
                header.col(|ui| {
                    ui.strong("Status");
                });
                header.col(|ui| {
                    ui.strong("Capability");
                });
            })
            .body(|body| {
                body.rows(40.0, capabilities.len(), |mut row| {
                    let capability = capabilities[row.index()];
                    row.col(|ui| {
                        ui.label(match capability.state {
                            CapabilityState::Implemented => "Implemented",
                            CapabilityState::Planned => "Planned",
                        });
                    });
                    row.col(|ui| {
                        ui.label(capability.name);
                    });
                });
            });
    }

    fn configuration(&self, ui: &mut egui::Ui) {
        let config = self.node.config();
        ui.label("Loaded settings for this process.");
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
                    ui.label(label);
                    ui.add(egui::Label::new(RichText::new(&value).monospace()).selectable(true));
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
            ui.label("Each network has its own subdirectory. This build does not create data directories or listening sockets.");
        });
    }

    fn events(&mut self, ui: &mut egui::Ui) {
        ui.label("Bounded diagnostic history for this process.");
        ui.horizontal_wrapped(|ui| {
            ui.label("Search");
            let search = ui.add(
                egui::TextEdit::singleline(&mut self.event_query)
                    .hint_text("Sequence, event or explanation…")
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
                .text(format!("{} / {capacity} events retained", records.len())),
        )
        .on_hover_text(
            "Oldest events are evicted at capacity. This is memory occupancy, not sync progress.",
        );
        let records = filtered_events(&records, &self.event_query, self.newest_first);
        ui.add_space(8.0);
        if records.is_empty() {
            ui.label("No events match this search.");
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
            .header(26.0, |mut header| {
                header.col(|ui| {
                    ui.strong("Sequence");
                });
                header.col(|ui| {
                    ui.strong("Event · select for details");
                });
            })
            .body(|body| {
                body.rows(32.0, records.len(), |mut row| {
                    let record = records[row.index()];
                    row.col(|ui| {
                        ui.monospace(format!("#{}", record.sequence));
                    });
                    row.col(|ui| {
                        let response = ui
                            .selectable_label(
                                self.selected_event == Some(record),
                                event_title(record.event),
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

    fn windows(&mut self, ctx: &egui::Context) {
        if let Some(record) = self.selected_event {
            let mut open = true;
            egui::Window::new("Event details")
                .open(&mut open)
                .resizable(true)
                .default_width(400.0)
                .vscroll(true)
                .show(ctx, |ui| {
                    ui.monospace(format!("Sequence #{}", record.sequence));
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
                ui.label("Ctrl/Cmd + 1–4: switch pages");
                ui.label("Ctrl/Cmd + F: search local events");
                ui.label("F1: toggle this window");
                ui.label("Tab / Shift + Tab: move keyboard focus");
                ui.label("Enter / Space: activate a focused control");
                ui.separator();
                ui.label("The current build is the application foundation. No chain has been downloaded or validated.");
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
            "Startup was refused because consensus validation, persistent chainstate and peer networking are not implemented."
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
        .filter(|record| event_text(*record).to_lowercase().contains(&query))
        .collect();
    if newest_first {
        result.reverse();
    }
    result
}
