mod app;
#[cfg(feature = "devtools")]
mod bench;
/// Audit slop: without `devtools` the bench harness compiles to a
/// stub — same API, no code.
#[cfg(not(feature = "devtools"))]
#[allow(dead_code)]
mod bench {
    use crate::rail::Page;
    use eframe::egui::Context;
    pub struct Bench;
    impl Bench {
        pub fn from_env() -> Option<Self> {
            None
        }
        pub fn forcing(&self) -> bool {
            false
        }
        pub fn drive(&mut self, _ctx: &Context, _cpu_secs: Option<f32>) -> Option<Page> {
            None
        }
    }
}
mod brand;
#[cfg(feature = "devtools")]
mod capture;
/// Audit slop: without `devtools` the screenshot harness compiles to
/// a stub — `Pose`/`Desk` types remain for `app.rs`'s field refs.
#[cfg(not(feature = "devtools"))]
#[allow(dead_code)]
mod capture {
    use crate::rail::Page;
    use crate::ribbon::Scale;
    use crate::theme::Skin;
    use eframe::egui::{Context, RawInput};
    #[derive(Default, Clone, Copy, PartialEq, Eq)]
    pub enum Desk {
        #[default]
        Window,
        StartMenu,
        Restored,
        TurnOff,
        About,
    }
    pub type Step = (f32, f32, bool);
    #[derive(Clone, Copy)]
    pub struct Pose {
        pub page: Page,
        pub scale: Scale,
        pub select_peer: bool,
        pub scroll: f32,
        pub hide: bool,
        pub clock: bool,
        pub zoom: Option<(f64, f64)>,
        pub eclipse: bool,
        pub advanced: bool,
        pub skin: Skin,
        pub play: bool,
        pub over: bool,
        pub desk: Desk,
        pub pointer: &'static [Step],
    }
    pub struct Capture;
    impl Capture {
        pub fn from_env() -> Option<Self> {
            None
        }
        pub fn feed(&mut self, _raw: &mut RawInput) {}
        pub fn drive(&mut self, _ctx: &Context) -> Option<Pose> {
            None
        }
    }
}
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
