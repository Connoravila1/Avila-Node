mod app;
mod bench;
mod brand;
mod capture;
mod clock;
mod constellation;
mod demo;
mod fingerprint;
mod julia;
mod model;
mod pages;
mod prefs;
mod rail;
mod ribbon;
mod session;
mod theme;
mod toybox;
mod widgets;
mod xp;

use std::error::Error;
use std::path::PathBuf;

use avila_node::Node;
use avila_node::config::load_config;
use clap::Parser;
use eframe::egui;

#[derive(Debug, Parser)]
#[command(version, about = "Avila Node desktop interface")]
struct Args {
    /// Explicit TOML configuration file; otherwise use development defaults.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Start with a specific appearance instead of the saved preference.
    #[arg(long, value_enum)]
    theme: Option<prefs::ThemeChoice>,
    /// Preview the interface with a simulated node. Nothing touches the
    /// network, and every screen says the data is simulated.
    #[arg(long)]
    demo: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let node = Node::new(load_config(args.config.as_deref())?)?;
    let icon = eframe::icon_data::from_png_bytes(brand::LOGO_PNG)?;
    let title = if args.demo {
        "Avila Node — simulated"
    } else {
        "Avila Node"
    };
    let options = eframe::NativeOptions {
        persist_window: false,
        viewport: egui::ViewportBuilder::default()
            .with_title(title)
            .with_app_id("avila-node")
            .with_icon(icon)
            .with_inner_size([1120.0, 760.0])
            .with_min_inner_size([760.0, 480.0]),
        ..Default::default()
    };
    let (demo, theme) = (args.demo, args.theme);
    eframe::run_native(
        "Avila Node",
        options,
        Box::new(move |cc| Ok(Box::new(app::App::new(cc, node, demo, theme)))),
    )?;
    Ok(())
}
