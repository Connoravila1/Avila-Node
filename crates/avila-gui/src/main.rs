mod app;
mod appearance;

use std::error::Error;
use std::path::PathBuf;

use avila_node::Node;
use avila_node::config::load_config;
use clap::Parser;
use eframe::egui;

const LOGO: &[u8] = include_bytes!("../../../assets/avila-node-logo.png");

#[derive(Debug, Parser)]
#[command(version, about = "Avila Node desktop interface")]
struct Args {
    /// Explicit TOML configuration file; otherwise use development defaults.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Start with a specific appearance instead of the saved preference.
    #[arg(long, value_enum)]
    theme: Option<appearance::AppearanceMode>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let node = Node::new(load_config(args.config.as_deref())?)?;
    let icon = eframe::icon_data::from_png_bytes(LOGO)?;
    let logo = egui::ColorImage::from_rgba_unmultiplied(
        [icon.width as usize, icon.height as usize],
        &icon.rgba,
    );
    let options = eframe::NativeOptions {
        persist_window: false,
        viewport: egui::ViewportBuilder::default()
            .with_icon(icon)
            .with_inner_size([1120.0, 760.0])
            .with_min_inner_size([760.0, 480.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Avila Node",
        options,
        Box::new(move |cc| {
            let mut appearance = appearance::AppearanceConfig::load(cc.storage);
            if let Some(theme) = args.theme {
                appearance.theme = theme;
            }
            Ok(Box::new(app::AvilaApp::new(
                &cc.egui_ctx,
                node,
                logo,
                appearance,
            )))
        }),
    )?;
    Ok(())
}
