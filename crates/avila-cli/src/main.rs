use std::error::Error;
use std::path::PathBuf;
use std::process::ExitCode;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use avila_node::Node;
use avila_node::config::load_config;
use avila_node::sync::{SyncConfig, run as run_sync};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "avila-node",
    version,
    about = "Avila Node — a Bitcoin full node in development"
)]
struct Args {
    /// Explicit TOML configuration file; otherwise use development defaults.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate configuration without starting services or creating data.
    CheckConfig,
    /// Inspect this build and configuration, NOT a running daemon.
    Inspect {
        #[arg(long)]
        json: bool,
    },
    /// Start the node (currently fails until required subsystems exist).
    Run,
    /// Sync headers and blocks from live peers (headers-first, full
    /// consensus validation). Bounded by target height and timeout.
    Sync {
        /// Stop after connecting this many blocks (relative to genesis).
        #[arg(long, default_value_t = 100)]
        blocks: u32,
        /// Peer-set bound.
        #[arg(long, default_value_t = 8)]
        max_peers: usize,
        /// Wall-clock bound in seconds.
        #[arg(long, default_value_t = 120)]
        timeout_secs: u64,
        /// Explicit peer addr:port (repeatable); DNS seeds are also used.
        #[arg(long)]
        connect: Vec<SocketAddr>,
    },
}

fn execute(args: Args) -> Result<(), Box<dyn Error>> {
    let config = load_config(args.config.as_deref())?;
    match args.command {
        Command::CheckConfig => {
            println!("Configuration valid: {}", config.get().network);
            println!(
                "Network data directory: {}",
                config.network_data_dir().display()
            );
        }
        Command::Inspect { json } => {
            let node = Node::new(config)?;
            let snapshot = node.snapshot();
            if json {
                println!("{}", serde_json::to_string_pretty(&snapshot)?);
            } else {
                println!("Avila Node {} | {}", snapshot.version, snapshot.network);
                println!("Local inspection only — no running daemon is queried.");
                println!("Validation: not implemented; no verified chain tip.");
                println!("Data directory: {}", snapshot.data_dir.display());
                for capability in snapshot.capabilities {
                    println!("{:?}: {}", capability.state, capability.name);
                }
            }
        }
        Command::Run => Node::new(config)?.start()?,
        Command::Sync {
            blocks,
            max_peers,
            timeout_secs,
            connect,
        } => {
            use avila_consensus::params::Network as ConsensusNet;
            let network = config.get().network;
            let consensus_net = match network {
                avila_core::Network::Mainnet => ConsensusNet::Mainnet,
                avila_core::Network::Testnet4 => ConsensusNet::Testnet4,
                avila_core::Network::Signet => ConsensusNet::Signet,
                avila_core::Network::Regtest => ConsensusNet::Regtest,
            };
            let params = consensus_net.params();
            let cfg = SyncConfig {
                connect,
                target_height: blocks,
                max_peers,
                timeout: Duration::from_secs(timeout_secs),
            };
            println!("Syncing {network} (target height {blocks}, {max_peers} peers max)...");
            let mut last = (u32::MAX, u32::MAX);
            let mut last_print = Instant::now() - Duration::from_secs(2);
            let report = run_sync(&params, &cfg, |p| {
                let cur = (p.header_height, p.connected_height);
                if cur != last && last_print.elapsed() >= Duration::from_secs(1) {
                    println!(
                        "  headers {} | connected {} | peers {} | in-flight {} | established {} | drops {}",
                        p.header_height,
                        p.connected_height,
                        p.peers,
                        p.in_flight,
                        p.established_total,
                        p.disconnects,
                    );
                    last = cur;
                    last_print = Instant::now();
                }
            })?;
            println!(
                "Done: connected {} blocks (headers {}), tip {}, {} peers established, {:.1}s{}",
                report.connected_height,
                report.header_height,
                report.tip.as_deref().unwrap_or("none"),
                report.established_total,
                report.elapsed.as_secs_f64(),
                if report.target_reached {
                    ""
                } else {
                    " — timeout before target"
                },
            );
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match execute(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("avila-node: {error}");
            ExitCode::FAILURE
        }
    }
}
