use std::error::Error;
use std::path::PathBuf;

use avila_node::Node;
use avila_node::config::load_config;
use clap::Parser;
use eframe::egui;

#[derive(Debug, Parser)]
#[command(version, about = "Avila Node desktop interface")]
struct Args {
    /// Explicit TOML configuration; the GUI never invents a running node.
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Page {
    #[default]
    Overview,
    Capabilities,
    Configuration,
    Events,
}

struct AvilaApp {
    node: Node,
    page: Page,
}

impl AvilaApp {
    fn render(&mut self, ui: &mut egui::Ui) {
        ui.add_space(12.0);
        ui.heading("Avila Node");
        ui.label("A complete Bitcoin node, built to explore better implementations.");
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.page, Page::Overview, "Overview");
            ui.selectable_value(&mut self.page, Page::Capabilities, "Capabilities");
            ui.selectable_value(&mut self.page, Page::Configuration, "Configuration");
            ui.selectable_value(&mut self.page, Page::Events, "Events");
        });
        ui.separator();
        ui.label("Development scaffold | Local inspection | No active Bitcoin connection");
        ui.add_space(12.0);
        egui::ScrollArea::vertical().show(ui, |ui| match self.page {
            Page::Overview => {
                let snapshot = self.node.snapshot();
                ui.heading("Verification status");
                ui.label("No chain has been downloaded or validated by this build.");
                ui.add_space(12.0);
                egui::Grid::new("overview").spacing([32.0, 10.0]).show(ui, |ui| {
                    ui.label("Selected network");
                    ui.monospace(snapshot.network.to_string());
                    ui.end_row();
                    ui.label("Verified chain tip");
                    ui.label("Unavailable");
                    ui.end_row();
                    ui.label("Connected peers");
                    ui.label("Not measured — networking is not implemented");
                    ui.end_row();
                    ui.label("Build");
                    ui.monospace(snapshot.version);
                    ui.end_row();
                });
                ui.add_space(20.0);
                ui.heading("What comes next");
                ui.label("Consensus primitives and historical fixtures, followed by real synchronization, validation, durable storage, and wallet connectivity.");
                ui.label("The roadmap targets a node usable as a primary node, not a permanent demonstration.");
            }
            Page::Capabilities => {
                ui.heading("Implemented versus planned");
                ui.label("These are implementation states, not security certifications.");
                ui.add_space(12.0);
                egui::Grid::new("capabilities").spacing([24.0, 10.0]).show(ui, |ui| {
                    for capability in self.node.snapshot().capabilities {
                        ui.monospace(format!("{:?}", capability.state));
                        ui.label(capability.name);
                        ui.end_row();
                    }
                });
            }
            Page::Configuration => {
                let config = self.node.config();
                ui.heading("Loaded configuration");
                ui.label("Read-only inspection; no settings are silently applied to a daemon.");
                ui.add_space(12.0);
                ui.label(format!("Network: {}", config.get().network));
                ui.label(format!("Data directory: {}", config.network_data_dir().display()));
                ui.label(format!("Event capacity: {}", config.event_capacity()));
                ui.label("No data directories or listening sockets are created by this build.");
            }
            Page::Events => {
                ui.heading("Local event history");
                ui.label("Bounded, in-memory diagnostics for this process; not a durable chainstate journal.");
                ui.add_space(12.0);
                for record in self.node.events().entries().rev() {
                    ui.monospace(format!("#{:04}  {:?}", record.sequence, record.event));
                }
            }
        });
    }
}

impl eframe::App for AvilaApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| self.render(ui));
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let node = Node::new(load_config(args.config.as_deref())?)?;
    let app = AvilaApp {
        node,
        page: Page::default(),
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1080.0, 720.0])
            .with_min_inner_size([760.0, 480.0]),
        ..Default::default()
    };
    eframe::run_native("Avila Node", options, Box::new(move |_cc| Ok(Box::new(app))))?;
    Ok(())
}
