use std::error::Error;
use std::path::PathBuf;
use std::process::ExitCode;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use avila_node::Node;
use avila_node::config::load_config;
use avila_node::sync::{SyncConfig, SyncProgress, run as run_sync};
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
    /// Run the node: sync to tip, then keep serving and relaying until killed.
    Run {
        /// Explicit peer addr:port (repeatable); DNS seeds are also used.
        #[arg(long)]
        connect: Vec<SocketAddr>,
        /// Route all outbound connections through this SOCKS5 proxy.
        #[arg(long)]
        proxy: Option<SocketAddr>,
        /// Bind the read-only JSON-RPC query surface to this address
        /// (e.g. 127.0.0.1:18443).
        #[arg(long)]
        rpc: Option<SocketAddr>,
    },
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
        /// Route all outbound connections through this SOCKS5 proxy.
        #[arg(long)]
        proxy: Option<SocketAddr>,
        /// Persist the chainstate under the configured data directory,
        /// resuming where the last run stopped. Enabled by default;
        /// pass --no-store for an in-memory run.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        store: bool,
        /// Prune blk files to ~this many MiB after syncing (needs --store).
        #[arg(long)]
        prune_mb: Option<u64>,
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
        Command::Run {
            connect,
            proxy,
            rpc,
        } => {
            // A real daemon: unbounded headers-first sync — sync to the
            // tip, then keep serving, relaying, and announcing until
            // killed. The store resumes from the last snapshot.
            use avila_consensus::params::Network as ConsensusNet;
            let consensus_net = match config.get().network {
                avila_core::Network::Mainnet => ConsensusNet::Mainnet,
                avila_core::Network::Testnet4 => ConsensusNet::Testnet4,
                avila_core::Network::Signet => ConsensusNet::Signet,
                avila_core::Network::Regtest => ConsensusNet::Regtest,
            };
            let params = consensus_net.params();
            let status: avila_node::rpc::SharedStatus =
                std::sync::Arc::new(std::sync::RwLock::new(SyncProgress {
                    peers: 0,
                    connected_height: 0,
                    header_height: 0,
                    in_flight: 0,
                    established_total: 0,
                    disconnects: 0,
                    recent: Vec::new(),
                    peer_details: Vec::new(),
                    mempool: (0, 0, None),
                    elapsed_secs: 0,
                }));
            let (query_tx, query_rx) = std::sync::mpsc::channel();
            let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            if let Some(addr) = rpc {
                let _server = avila_node::rpc::serve(
                    addr,
                    status.clone(),
                    Some(query_tx),
                    Some(cancel.clone()),
                )
                .map_err(|e| format!("rpc bind {addr}: {e}"))?;
                println!("RPC listening on http://{addr} (read-only)");
                std::mem::forget(_server);
            }
            let cfg = SyncConfig {
                connect,
                target_height: u32::MAX,
                max_peers: 8,
                timeout: Duration::from_secs(u64::MAX),
                proxy,
                data_dir: Some(config.network_data_dir()),
                cancel: Some(cancel),
                prune_bytes: None,
                status: Some(status),
                queries: Some(std::sync::Arc::new(std::sync::Mutex::new(query_rx))),
            };
            println!(
                "Running {} — syncing to tip, then serving (Ctrl+C to stop)...",
                config.get().network
            );
            let mut last_print = Instant::now();
            let _ = run_sync(&params, &cfg, |p| {
                if last_print.elapsed() >= Duration::from_secs(5) {
                    last_print = Instant::now();
                    println!(
                        "  h {} | headers {} | peers {} | pool {}+{}orph",
                        p.connected_height, p.header_height, p.peers, p.mempool.0, p.mempool.1,
                    );
                }
            })?;
        }
        Command::Sync {
            blocks,
            max_peers,
            timeout_secs,
            connect,
            proxy,
            store,
            prune_mb,
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
                proxy,
                data_dir: store.then(|| config.network_data_dir()),
                cancel: None,
                prune_bytes: prune_mb.map(|m| m * 1024 * 1024),
                status: None,
                queries: None,
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
