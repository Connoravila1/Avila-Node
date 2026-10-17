mod app;
mod attached;
mod avalanche;
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
mod builder;
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
        pub toy: u8,
        pub desk: Desk,
        pub pointer: &'static [Step],
        pub first: bool,
        pub block_fixture: bool,
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
        pub fn observe(
            &mut self,
            _ctx: &Context,
            _page: Page,
            _skin: Skin,
            _phase: &str,
            _running: bool,
            _tip: Option<&str>,
        ) {
        }
    }
}
mod classic;
mod clock;
mod constellation;
mod demo;
mod fingerprint;
mod gallery;
mod julia;
mod model;
mod operator;
mod oracle;
mod pages;
mod phosphor;
mod prefs;
mod rail;
mod ribbon;
mod session;
mod snake;
mod sweep;
mod theme;
mod toybox;
mod widgets;
mod xp;

use std::error::Error;
use std::net::SocketAddr;
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
    /// Experimental fast IBD: keep the committed coin set in a RAM-resident
    /// flat table from first start. Verification is identical; the trade is
    /// ~17 GiB RAM at mainnet tip and a less-tested code path.
    #[arg(long)]
    fast_ibd: bool,
    /// Verify historical scripts instead of using the assume-valid checkpoint.
    /// This can make initial sync substantially slower; the default is unchanged.
    #[arg(long)]
    full_verify: bool,
    /// Observe an already-running local daemon instead of starting a node.
    /// The daemon must expose cookie-authenticated loopback RPC.
    #[arg(long)]
    attach: bool,
    /// Loopback RPC endpoint for --attach; defaults to services.rpc.bind,
    /// then 127.0.0.1:18443. Needed when the daemon was started with --rpc.
    #[arg(long, value_name = "IP:PORT", requires = "attach")]
    rpc_addr: Option<SocketAddr>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    if args.attach && args.demo {
        return Err("--attach cannot be combined with --demo".into());
    }
    if args.attach && (args.fast_ibd || args.full_verify) {
        return Err(
            "--fast-ibd and --full-verify only configure a GUI-owned node; they cannot change an attached daemon".into(),
        );
    }
    if !args.attach && args.rpc_addr.is_some() {
        return Err("--rpc-addr requires --attach".into());
    }
    // SIGINT/SIGTERM ask the window to close — eframe then runs the
    // app's on_exit, which stops the sync worker and lets its exit
    // flush write state.dat. A bare kill would otherwise discard
    // every header learned this session.
    let close = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        if let Err(e) = signal_hook::flag::register(sig, close.clone()) {
            eprintln!("warning: signal handler for {sig} not installed: {e}");
        }
    }
    // Keep the file's path: the Config page opens it for the
    // restart-only knobs it can't edit live.
    let config_file = args
        .config
        .clone()
        .and_then(|p| p.canonicalize().ok().or(Some(p)));
    let node = Node::new(load_config(args.config.as_deref())?)?;
    let rpc_addr = args
        .rpc_addr
        .or(node.config().get().services.rpc.bind)
        .unwrap_or("127.0.0.1:18443".parse()?);
    if args.attach && !rpc_addr.ip().is_loopback() {
        return Err("--attach accepts loopback RPC addresses only".into());
    }
    let icon = eframe::icon_data::from_png_bytes(brand::LOGO_PNG)?;
    let title = if args.attach {
        "Avila Node — attached"
    } else if args.demo {
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
    let (attach, demo, theme) = (args.attach, args.demo, args.theme);
    let start_options = app::StartOptions {
        fast_ibd: args.fast_ibd,
        full_verify: args.full_verify,
    };
    let close_flag = close;
    eframe::run_native(
        "Avila Node",
        options,
        Box::new(move |cc| {
            let app: Box<dyn eframe::App> = if attach {
                Box::new(attached::AttachedApp::new(
                    cc,
                    node,
                    config_file,
                    rpc_addr,
                    theme,
                    close_flag,
                ))
            } else {
                Box::new(app::App::new(
                    cc,
                    node,
                    demo,
                    start_options,
                    theme,
                    close_flag,
                    config_file,
                ))
            };
            Ok(app)
        }),
    )?;
    Ok(())
}
