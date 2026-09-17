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
        /// Maintain a txid index (Core's -txindex) so getrawtransaction
        /// finds transactions without a named block.
        #[arg(long)]
        txindex: bool,
        /// Maintain the BIP 158 basic block filter index (Core's
        /// -blockfilterindex) so getblockfilter/scanblocks serve.
        #[arg(long)]
        blockfilterindex: bool,
        /// Serve BIP157 compact filters to peers (Core's
        /// -peerblockfilters; requires --blockfilterindex).
        #[arg(long)]
        peerblockfilters: bool,
        /// Mempool size cap in MB (Core's -maxmempool, default 300).
        #[arg(long)]
        maxmempool: Option<u64>,
        /// Attempt BIP324 v2 transport on outbound peers (Core's
        /// -v2transport, default on). Pass --v2transport=false to
        /// force cleartext.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        v2transport: bool,
        /// Accept inbound peer connections on this address (Core's
        /// -listen=<addr>). Inbound peers auto-negotiate v1 or BIP324
        /// and join under the manager's slot/eviction rules.
        #[arg(long)]
        listen: Option<SocketAddr>,
        /// Bind the Electrum-protocol server to this address
        /// (e.g. 127.0.0.1:50001) and maintain the scripthash index.
        #[arg(long)]
        electrum: Option<SocketAddr>,
        /// Authenticated RPC user (Core's -rpcuser); pairs with
        /// --rpcpassword. Adds a Basic-auth credential alongside the
        /// cookie.
        #[arg(long)]
        rpcuser: Option<String>,
        /// Password for --rpcuser (Core's -rpcpassword).
        #[arg(long)]
        rpcpassword: Option<String>,
        /// Restrict an RPC user to the listed methods (Core's
        /// -rpcwhitelist=user:m1,m2; repeatable per user).
        #[arg(long)]
        rpcwhitelist: Vec<String>,
        /// Whether users without a whitelist entry may call any method
        /// (Core's -rpcwhitelistdefault, default 1). Pass
        /// --rpcwhitelistdefault=0 to deny all unlisted methods.
        /// Accepts 0/1/true/false like Core's bool parser.
        #[arg(long)]
        rpcwhitelistdefault: Option<String>,
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
        /// Maintain a txid index (Core's -txindex) for txid lookups.
        #[arg(long)]
        txindex: bool,
        /// Maintain the BIP 158 basic block filter index (Core's
        /// -blockfilterindex) so getblockfilter/scanblocks serve.
        #[arg(long)]
        blockfilterindex: bool,
        /// Serve BIP157 compact filters to peers (Core's
        /// -peerblockfilters; requires --blockfilterindex).
        #[arg(long)]
        peerblockfilters: bool,
        /// Mempool size cap in MB (Core's -maxmempool, default 300).
        #[arg(long)]
        maxmempool: Option<u64>,
        /// Attempt BIP324 v2 transport on outbound peers (Core's
        /// -v2transport, default on).
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        v2transport: bool,
    },
    /// Call a JSON-RPC method on a running daemon — the bitcoin-cli
    /// analog. Positional params are parsed as raw JSON values, falling
    /// back to strings (e.g. `rpc getblockhash 100`,
    /// `rpc getblockheader 0000…ab`).
    Rpc {
        /// The method name (see `rpc help`).
        method: String,
        /// Positional params, each parsed as JSON then as a string.
        params: Vec<String>,
        /// The daemon's RPC endpoint.
        #[arg(long, default_value = "127.0.0.1:18443")]
        rpc_addr: SocketAddr,
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
            txindex,
            blockfilterindex,
            peerblockfilters,
            maxmempool,
            v2transport,
            listen,
            electrum,
            rpcuser,
            rpcpassword,
            rpcwhitelist,
            rpcwhitelistdefault,
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
            // SIGTERM/SIGINT take the same path as `stop`: the loop
            // exits cleanly and the shutdown block persists the chain,
            // peers.dat, mempool.dat, and banlist. Without this every
            // kill silently dropped the address book.
            for sig in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
                if let Err(e) = signal_hook::flag::register(sig, cancel.clone()) {
                    eprintln!("warning: signal handler for {sig} not installed: {e}");
                }
            }
            let data_dir = config.network_data_dir();
            // The waitforblock* registry — RPC handlers park predicates,
            // the sync loop fires them on tick and on shutdown. The
            // scantxoutset slot is pure RPC state (no sync-loop input).
            let waiters = std::sync::Arc::new(avila_node::rpc::BlockWaiters::new());
            let scan = std::sync::Arc::new(avila_node::rpc::TxoutScan::new());
            // The watch-only wallet is an RPC-side service — the
            // descriptor store loads lazily; `watchlist.dat` appears
            // on first import.
            let wallet = std::sync::Arc::new(std::sync::Mutex::new(
                avila_node::watch::WatchWallet::open(data_dir.join("watchlist.dat")),
            ));
            if let Some(addr) = rpc {
                // Cookie auth, regenerated per run exactly like Core's
                // .cookie — the file lives in the network data dir with
                // owner-only permissions.
                let token = avila_node::rpc::write_cookie(&data_dir)
                    .map_err(|e| format!("cookie {}: {e}", data_dir.display()))?;
                // Cookie is always accepted; --rpcuser adds named
                // creds, --rpcwhitelist scopes their methods (Core's
                // g_rpc_whitelist).
                let mut auth = avila_node::rpc::RpcAuth::cookie(&token);
                if let Some(u) = &rpcuser {
                    let Some(p) = &rpcpassword else {
                        return Err("--rpcuser requires --rpcpassword".to_string().into());
                    };
                    auth.add_user(u, p);
                }
                for wl in &rpcwhitelist {
                    let Some((u, methods)) = wl.split_once(':') else {
                        return Err(format!(
                            "invalid --rpcwhitelist {wl:?} — expected user:method1,method2"
                        )
                        .into());
                    };
                    auth.whitelist(u, methods);
                }
                let wl_default = match rpcwhitelistdefault.as_deref() {
                    None | Some("1") | Some("true") => true,
                    Some("0") | Some("false") => false,
                    Some(other) => {
                        return Err(format!(
                            "invalid --rpcwhitelistdefault {other:?} — expected 0 or 1"
                        )
                        .into());
                    }
                };
                auth.set_whitelist_default(wl_default);
                let _server = avila_node::rpc::serve(
                    addr,
                    status.clone(),
                    Some(query_tx.clone()),
                    Some(waiters.clone()),
                    Some(scan.clone()),
                    Some(wallet),
                    Some(cancel.clone()),
                    Some(auth),
                )
                .map_err(|e| format!("rpc bind {addr}: {e}"))?;
                println!(
                    "RPC listening on http://{addr} (cookie auth: {}/.cookie)",
                    data_dir.display()
                );
                std::mem::forget(_server);
            }
            if let Some(addr) = electrum {
                // The Electrum-protocol service — the scripthash index
                // it serves is enabled in the sync config below.
                let _server = avila_node::electrum::serve(
                    addr,
                    query_tx.clone(),
                    waiters.clone(),
                    status.clone(),
                    cancel.clone(),
                )
                .map_err(|e| format!("electrum bind {addr}: {e}"))?;
                println!("Electrum listening on {addr}");
                std::mem::forget(_server);
            }
            let cfg = SyncConfig {
                connect,
                target_height: u32::MAX,
                max_peers: 8,
                timeout: Duration::from_secs(u64::MAX),
                proxy,
                data_dir: Some(data_dir.clone()),
                cancel: Some(cancel),
                prune_bytes: None,
                txindex,
                blockfilterindex,
                peerblockfilters,
                maxmempool_bytes: maxmempool.map(|m| (m * 1024 * 1024) as usize),
                v2transport,
                listen,
                electrum,
                status: Some(status),
                queries: Some(std::sync::Arc::new(std::sync::Mutex::new(query_rx))),
                waiters: Some(waiters),
            };
            println!(
                "Running {} — syncing to tip, then serving (Ctrl+C to stop)...",
                config.get().network
            );
            let mut last_print = Instant::now();
            let result = run_sync(&params, &cfg, |p| {
                if last_print.elapsed() >= Duration::from_secs(5) {
                    last_print = Instant::now();
                    println!(
                        "  h {} | headers {} | peers {} | pool {}+{}orph",
                        p.connected_height, p.header_height, p.peers, p.mempool.0, p.mempool.1,
                    );
                }
            });
            // The cookie is per-session — remove it on the way out,
            // matching Core's shutdown.
            if rpc.is_some() {
                let _ = std::fs::remove_file(data_dir.join(avila_node::rpc::COOKIE_FILE));
            }
            result?;
        }
        Command::Sync {
            blocks,
            max_peers,
            timeout_secs,
            connect,
            proxy,
            store,
            prune_mb,
            txindex,
            blockfilterindex,
            peerblockfilters,
            maxmempool,
            v2transport,
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
                txindex,
                blockfilterindex,
                peerblockfilters,
                maxmempool_bytes: maxmempool.map(|m| (m * 1024 * 1024) as usize),
                v2transport,
                listen: None,
                electrum: None,
                status: None,
                queries: None,
                waiters: None,
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
        Command::Rpc {
            method,
            params,
            rpc_addr,
        } => {
            // Params arrive as CLI strings; each parses as JSON first
            // (`100` → number, `true` → bool, `"x"`/`[…]`/`{…}` →
            // their JSON forms) and falls back to a bare string.
            let params: Vec<serde_json::Value> = params
                .iter()
                .map(|p| serde_json::from_str(p).unwrap_or(serde_json::Value::String(p.clone())))
                .collect();
            let token = avila_node::rpc::read_cookie(&config.network_data_dir()).map_err(|e| {
                format!(
                    "reading {}: {e} — is a `run --rpc` daemon up?",
                    config
                        .network_data_dir()
                        .join(avila_node::rpc::COOKIE_FILE)
                        .display()
                )
            })?;
            let request = serde_json::json!({
                "jsonrpc": "1.0",
                "id": "avila-cli",
                "method": method,
                "params": params,
            });
            let response = avila_node::rpc::call(
                rpc_addr,
                Some(&avila_node::rpc::cookie_auth_header(&token)),
                &request,
            )?;
            if let Some(error) = response.get("error").filter(|e| !e.is_null()) {
                println!("{}", serde_json::to_string_pretty(error)?);
                return Err(format!("rpc {method} failed").into());
            }
            match response.get("result") {
                Some(result) => match result {
                    serde_json::Value::String(s) => println!("{s}"),
                    other => println!("{}", serde_json::to_string_pretty(other)?),
                },
                None => println!("null"),
            }
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
