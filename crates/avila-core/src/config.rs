use std::fmt;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_EVENT_CAPACITY: usize = 4096;

/// Structural ceiling for `policy.datacarrier_size` — avila-mempool's
/// `MAX_STANDARD_TX_WEIGHT`. A larger OP_RETURN budget can never bind
/// against any standard transaction, so bigger values are typos, not
/// policy.
const MAX_DATACARRIER_SIZE: usize = 400_000;

/// A network selection, not a claim that its protocol is implemented.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Mainnet,
    Testnet4,
    Signet,
    #[default]
    Regtest,
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Mainnet => "mainnet",
            Self::Testnet4 => "testnet4",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
        })
    }
}

/// User-supplied configuration. Validate before constructing a coordinator.
/// Sections are the operator-policy namespaces of
/// `docs/DECISION_REGISTRY.md` — local judgment only; consensus rules
/// never appear as fields here.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NodeConfig {
    pub schema_version: u32,
    pub network: Network,
    pub data_dir: PathBuf,
    pub diag: DiagConfig,
    pub storage: StorageConfig,
    pub net: NetConfig,
    pub peers: PeersConfig,
    pub privacy: PrivacyConfig,
    pub mempool: MempoolConfig,
    pub policy: PolicyConfig,
    /// Observation pool for consensus-valid policy rejects.
    pub extrapool: ExtrapoolConfig,
    pub relay: RelayConfig,
    pub hooks: HooksConfig,
    pub filters: FiltersConfig,
    pub indexes: IndexesConfig,
    pub sync: SyncKnobs,
    pub services: ServicesConfig,
    /// Block-template construction policy (`mining.*`).
    pub mining: MiningConfig,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            schema_version: 1,
            network: Network::Regtest,
            data_dir: PathBuf::from("data"),
            diag: DiagConfig::default(),
            storage: StorageConfig::default(),
            net: NetConfig::default(),
            peers: PeersConfig::default(),
            privacy: PrivacyConfig::default(),
            mempool: MempoolConfig::default(),
            policy: PolicyConfig::default(),
            extrapool: ExtrapoolConfig::default(),
            relay: RelayConfig::default(),
            hooks: HooksConfig::default(),
            filters: FiltersConfig::default(),
            indexes: IndexesConfig::default(),
            sync: SyncKnobs::default(),
            services: ServicesConfig::default(),
            mining: MiningConfig::default(),
        }
    }
}

/// `diag.*` — local diagnostics; never affects consensus, policy, or peers.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DiagConfig {
    /// Bounded process-local event journal capacity.
    pub event_capacity: usize,
}

impl Default for DiagConfig {
    fn default() -> Self {
        Self {
            event_capacity: 256,
        }
    }
}

/// `storage.*` — what the node keeps on disk.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    /// Prune blk files to this many MiB (Core's `-prune`).
    /// `None` keeps every block — archival.
    pub prune_mb: Option<u64>,
    /// Coins-view write-back cache budget in MiB (Core's `-dbcache`).
    /// `None` = the internal 450 MiB default.
    pub dbcache_mb: Option<usize>,
}

/// `net.*` — connectivity and transport selection.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetConfig {
    /// Attempt BIP324 v2 transport on outbound dials (Core's
    /// `-v2transport`, default on since v26).
    pub v2transport: bool,
    /// Fixed outbound peers `["addr:port", …]` (Core's `-connect`) —
    /// naming any peer suppresses DNS seeding entirely.
    pub connect: Vec<SocketAddr>,
    /// Inbound peer listener (Core's `-listen=<addr>`).
    /// `None` = outbound-only.
    pub listen: Option<SocketAddr>,
    /// prefix→ASN map for outbound-dial bucketing (Core's `-asmap`);
    /// text rows `a.b.c.d/plen asn`. Relative paths resolve against
    /// the configuration file's directory.
    pub asmap: Option<PathBuf>,
    /// DNS seeding (Core's `-dnsseed`). Suppressed regardless when
    /// `connect` names peers or a proxy is set — local DNS lookups
    /// would leak through the resolver in both cases.
    pub dns_seeds: bool,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            v2transport: true,
            connect: Vec::new(),
            listen: None,
            asmap: None,
            dns_seeds: true,
        }
    }
}

/// `peers.*` — peer-set shape and admission.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PeersConfig {
    /// Total peer slots, inbound + outbound (Core's `-maxconnections`).
    pub max_connections: usize,
    /// Default ban duration in seconds for `setban` and discouragement
    /// escalation (Core's `-bantime`; 24h).
    pub ban_time: i64,
}

impl Default for PeersConfig {
    fn default() -> Self {
        Self {
            max_connections: avila_p2p_defaults::MAX_PEERS,
            ban_time: 86_400,
        }
    }
}

/// `privacy.*` — traffic routing and shaping.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrivacyConfig {
    /// Route all outbound connections through this SOCKS5 proxy
    /// (Core's `-proxy`). Also suppresses DNS seeding.
    pub proxy: Option<SocketAddr>,
    /// Pad every v2 link's outgoing writes to this byte multiple with
    /// decoy packets — flat wire write-size histogram. 0 = off (Core's
    /// behavior).
    pub cell_bytes: usize,
}

/// `mempool.*` — pool economics.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct MempoolConfig {
    /// Serialized-byte cap on the pool, in MiB (Core's `-maxmempool`,
    /// default 300).
    pub max_mb: u64,
    /// Fee floor for admission and relay, sat/kvB (Core's
    /// `-minrelaytxfee`; the codebase default is the 0.1 sat/vB
    /// post-29.x floor, 100 sat/kvB).
    pub min_relay_fee_sat_per_kvb: i64,
    /// Entries older than this many seconds are evicted (Core's
    /// `-mempoolexpiry`, 336h).
    pub expiry_secs: u32,
    /// Private submissions: `sendrawtransaction`/wallet-origin txs get
    /// stem-only relay (never fluffed to all peers) and are hidden
    /// from `getrawmempool` and `getmempoolentry`. They still pass
    /// full consensus and policy validation — only propagation and
    /// listing change.
    pub private: bool,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_mb: 300,
            min_relay_fee_sat_per_kvb: 100,
            expiry_secs: 336 * 60 * 60,
            private: false,
        }
    }
}

/// `policy.*` — relay/standardness policy. All of it is local
/// preference: it can tighten what this node relays but never widens
/// consensus acceptance.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    /// Gate transactions through the standardness rules (negated
    /// Core `-acceptnonstdtxn`; default on).
    pub require_standard: bool,
    /// Relay `OP_RETURN` (nulldata) outputs at all (Core's
    /// `-datacarrier`, default on). `false` rejects them regardless of
    /// `datacarrier_size`.
    pub datacarrier: bool,
    /// Total `OP_RETURN` bytes standard per transaction (Core's
    /// `-datacarriersize`; default is `MAX_OP_RETURN_RELAY` =
    /// `MAX_STANDARD_TX_WEIGHT / 4` = 100_000).
    pub datacarrier_size: usize,
    /// Relay bare (unwrapped) multisig outputs (Core's
    /// `-permitbaremultisig`, default on).
    pub permit_bare_multisig: bool,
    /// Fee rate used for the dust threshold, sat/kvB (Core's
    /// `-dustrelayfee`, default 3000).
    pub dust_relay_fee_sat_per_kvb: i64,
    /// Counterfactual relay policies scored against every admitted
    /// transaction — the shadow observatory (never gates; counters +
    /// `shadow_divergence` events). Built-in names: "strict", "core",
    /// "permissive". Empty disables.
    pub shadow: Vec<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            require_standard: true,
            datacarrier: true,
            datacarrier_size: 100_000,
            permit_bare_multisig: true,
            dust_relay_fee_sat_per_kvb: 3_000,
            shadow: vec!["strict".to_string()],
        }
    }
}

impl PolicyConfig {
    /// The `Option<usize>` the mempool takes: `None` mirrors
    /// `-datacarrier=0` (no nulldata outputs at all).
    pub fn datacarrier_bytes(&self) -> Option<usize> {
        self.datacarrier.then_some(self.datacarrier_size)
    }
}

/// `relay.*` — what crosses peer links, per direction.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RelayConfig {
    pub tx: TxRelayConfig,
}

/// `relay.tx.*` — transaction announcement and serving.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TxRelayConfig {
    /// Route locally-originated transactions through a single stem hop
    /// before flooding (selfish-stem origin privacy; default on).
    pub stem: bool,
    /// Compartment matrix — "src->dst" pairs never announced across:
    /// src ∈ {inbound, outbound, local, extrapool}, dst ∈ {inbound,
    /// outbound}. E.g. "inbound->inbound" keeps inbound-sourced
    /// transactions off inbound links.
    pub deny_pairs: Vec<String>,
}

impl Default for TxRelayConfig {
    fn default() -> Self {
        Self {
            stem: true,
            deny_pairs: Vec::new(),
        }
    }
}

/// `[extrapool]` — the observation pool for consensus-valid policy
/// rejects: bounded, inspectable, never announced. `observe = false`
/// drops rejected txs the way Core does.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExtrapoolConfig {
    /// Record policy rejects for inspection (`getextrapoolinfo`,
    /// `extrapoolpromote`, `extrapool_*` events).
    pub observe: bool,
    /// Entry bound — FIFO eviction past it.
    pub max_entries: usize,
    /// Serialized-bytes bound — FIFO eviction past it.
    pub max_bytes: usize,
    /// Entry lifetime; `0` keeps entries until evicted or promoted.
    pub expiry_secs: u32,
    /// Propagation: "never" (default — Core's behavior), "outbound"
    /// (announce observed txs on outbound links only), or "all".
    /// The compartment matrix and `tx.announce` still gate each hop.
    pub relay: String,
    /// Automatic re-admission triggers: "tip" retries every entry on
    /// each new checked tip (a connected block changes the fee/UTXO
    /// landscape). Empty = manual `extrapoolpromote` only.
    pub promote_on: Vec<String>,
    /// Per-reject-class entry caps: `[extrapool.caps] fee = 4000`
    /// bounds that class's share of the pool (per-class FIFO past the
    /// cap). Classes: nonstandard, fee, hook, rbf, package, finality,
    /// capacity, weight, sigops, truc, other.
    pub caps: std::collections::BTreeMap<String, usize>,
}

impl Default for ExtrapoolConfig {
    fn default() -> Self {
        Self {
            observe: true,
            max_entries: 10_000,
            max_bytes: 50_000_000,
            expiry_secs: 86_400,
            relay: "never".to_string(),
            promote_on: Vec::new(),
            caps: std::collections::BTreeMap::new(),
        }
    }
}

/// `hooks.*` — external verdict programs (docs/DECISION_REGISTRY.md).
/// A helper is a long-lived subprocess consulted at a decision point:
/// one JSON line of facts on stdin, `{"verdict": ...}` on stdout.
/// Helpers can only narrow acceptance — they never authorize what
/// built-in checks refused.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HooksConfig {
    /// Inbound peer admission — one `[[hooks.peer_accept]]` table per
    /// helper, consulted in order under conjunction (any reject drops).
    pub peer_accept: Vec<HookSpecConfig>,
    /// Transaction admission — one `[[hooks.tx_admit]]` table per
    /// helper. Consulted on every submitted tx before the built-in
    /// checks; this is a hot path — keep helpers fast (admission
    /// throughput is bounded by helper latency).
    pub tx_admit: Vec<HookSpecConfig>,
    /// Transaction announcement — one `[[hooks.tx_announce]]` table per
    /// helper. Consulted per (tx, target link) before each `inv` hop;
    /// `reject` withholds that link. Facts include provenance
    /// (source compartment + supplying peer) and the target's
    /// address/direction/user-agent. The hottest path — announce
    /// throughput is bounded by helper latency × peer count.
    pub tx_announce: Vec<HookSpecConfig>,
    /// Extrapool store — one `[[hooks.extrapool_admit]]` table per
    /// helper. Consulted before a policy reject is recorded;
    /// `reject` drops the observation (the tx is still rejected).
    pub extrapool_admit: Vec<HookSpecConfig>,
    /// Extrapool promotion — one `[[hooks.extrapool_promote]]` table
    /// per helper. Consulted before a `promote_on` trigger or manual
    /// `extrapoolpromote` re-runs admission; `reject` leaves the entry
    /// in the pool.
    pub extrapool_promote: Vec<HookSpecConfig>,
    /// Transaction serving — one `[[hooks.tx_serve]]` table per
    /// helper. Consulted per tx item in a peer's `getdata`; `reject`
    /// answers that item `notfound`, indistinguishable from never
    /// holding it. Facts: txid, wtxid, peer id/address/direction/
    /// user-agent. One consult per tx per getdata batch.
    pub tx_serve: Vec<HookSpecConfig>,
}

/// One `[[hooks.<point>]]` entry. `program` is the only required key.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HookSpecConfig {
    /// Helper executable; relative paths resolve against the config
    /// file's directory.
    pub program: PathBuf,
    pub args: Vec<String>,
    /// Longest a verdict may take before the helper counts as dead —
    /// bounds how long a decision point can stall. 1..=10_000.
    pub timeout_ms: u64,
    /// Verdict when the helper cannot answer (timeout, crash, garbage).
    /// Fail-closed for admission points.
    pub on_timeout: OnDefault,
    /// What a `defer` answer means at this point.
    pub on_defer: OnDefault,
    /// Respawns over the node's lifetime; exhausted → `on_timeout`
    /// forever.
    pub max_restarts: u32,
}

impl Default for HookSpecConfig {
    fn default() -> Self {
        Self {
            program: PathBuf::new(),
            args: Vec::new(),
            timeout_ms: 500,
            on_timeout: OnDefault::Reject,
            on_defer: OnDefault::Reject,
            max_restarts: 3,
        }
    }
}

/// What an unreachable/indecisive helper means at a decision point —
/// helpers narrow only, so a default is "admit" or "drop", never
/// `defer`.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OnDefault {
    /// Behave as if the helper accepted — fail-open.
    Accept,
    /// Behave as if the helper rejected — fail-closed. The default.
    #[default]
    Reject,
}

/// `filters.*` — BIP158 compact block filters.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FiltersConfig {
    /// Maintain the basic filter index (Core's `-blockfilterindex`).
    pub build: bool,
    /// Serve BIP157 requests to peers (Core's `-peerblockfilters`,
    /// default off; requires `build`, enforced at startup).
    pub serve: bool,
}

/// `indexes.*` — optional lookup indexes beside the chainstate.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct IndexesConfig {
    /// txid→block index so `getrawtransaction` works without a named
    /// block (Core's `-txindex`).
    pub txindex: bool,
}

/// `sync.*` — block-download scheduling and acceleration experiments.
/// These are performance policy, not correctness.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SyncKnobs {
    /// Total blocks requested but not yet received, across all peers.
    pub max_in_transit: usize,
    /// Utreexo shadow consumer — validate through a ~1 KiB accumulator
    /// alongside the conventional path. Advice, never authority.
    pub utreexo: bool,
    /// Maintain a proving forest and serve `utxproof` spend bundles to
    /// peers that ask.
    pub utreexo_bridge: bool,
}

impl Default for SyncKnobs {
    fn default() -> Self {
        Self {
            max_in_transit: 1024,
            utreexo: false,
            utreexo_bridge: false,
        }
    }
}

/// `mining.*` — block-template construction policy. Consensus
/// validity is never configurable; these knobs only choose *which*
/// candidate set a template draws from.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct MiningConfig {
    /// When true, `build_template` auditions extrapool (observed,
    /// policy-rejected) entries for the block's leftover budget after
    /// the mempool's packages — "mine what you won't relay". Each
    /// candidate is revalidated with consensus rules only; at most
    /// 512 entries are auditioned per template. Default off.
    pub include_extrapool: bool,
}

/// `services.*` — local query interfaces.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServicesConfig {
    pub rpc: RpcServiceConfig,
    pub electrum: ElectrumServiceConfig,
    pub sv2: Sv2ServiceConfig,
}

/// `services.rpc.*` — the JSON-RPC surface (Core's server options).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RpcServiceConfig {
    /// Bind address (Core's `-rpcbind`/`-rpcport` as one `addr:port`).
    /// `None` = RPC off; cookie auth still applies when set.
    pub bind: Option<SocketAddr>,
    /// Named Basic-auth credential (Core's `-rpcuser`); requires
    /// `password`.
    pub user: Option<String>,
    /// Password for `user` (Core's `-rpcpassword`).
    pub password: Option<String>,
    /// Per-user method scopes, `"user:m1,m2"` entries (Core's
    /// `-rpcwhitelist=`).
    pub whitelist: Vec<String>,
    /// Whether users without a whitelist entry may call any method
    /// (Core's `-rpcwhitelistdefault`, default on).
    pub whitelist_default: bool,
}

impl Default for RpcServiceConfig {
    fn default() -> Self {
        Self {
            bind: None,
            user: None,
            password: None,
            whitelist: Vec::new(),
            whitelist_default: true,
        }
    }
}

/// `services.electrum.*` — the Electrum-protocol server.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ElectrumServiceConfig {
    /// Bind address; also maintains the scripthash index it serves
    /// from (`scindex.dat`).
    pub listen: Option<SocketAddr>,
}

/// `services.sv2.*` — the Stratum V2 Template Provider.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Sv2ServiceConfig {
    /// Bind address (plaintext framing — loopback solo mining only).
    pub listen: Option<SocketAddr>,
}

mod avila_p2p_defaults {
    /// avila-p2p's `DEFAULT_MAX_PEERS`, duplicated to keep avila-core
    /// free of a p2p dependency for one constant.
    pub const MAX_PEERS: usize = 8;
}

impl NodeConfig {
    pub fn validate(self) -> Result<ValidatedConfig, ConfigError> {
        if self.schema_version != 1 {
            return Err(ConfigError::SchemaVersion(self.schema_version));
        }
        if self.data_dir.as_os_str().is_empty() {
            return Err(ConfigError::EmptyDataDirectory);
        }
        if !(1..=MAX_EVENT_CAPACITY).contains(&self.diag.event_capacity) {
            return Err(ConfigError::EventCapacity(self.diag.event_capacity));
        }
        if self.peers.max_connections == 0 {
            return Err(ConfigError::MaxConnections);
        }
        if self.peers.ban_time < 0 {
            return Err(ConfigError::NegativeFee("peers.ban_time"));
        }
        if self.mempool.max_mb == 0 {
            return Err(ConfigError::MaxMempoolBytes);
        }
        if self.mempool.min_relay_fee_sat_per_kvb < 0 {
            return Err(ConfigError::NegativeFee(
                "mempool.min_relay_fee_sat_per_kvb",
            ));
        }
        if self.policy.dust_relay_fee_sat_per_kvb < 0 {
            return Err(ConfigError::NegativeFee(
                "policy.dust_relay_fee_sat_per_kvb",
            ));
        }
        if self.policy.datacarrier_size > MAX_DATACARRIER_SIZE {
            return Err(ConfigError::DatacarrierSize(self.policy.datacarrier_size));
        }
        // Bounds of zero with observation on would make every store
        // evict itself — the knobs only make sense non-zero.
        if self.extrapool.observe
            && (self.extrapool.max_entries == 0 || self.extrapool.max_bytes == 0)
        {
            return Err(ConfigError::ExtrapoolBounds);
        }
        if self.sync.max_in_transit == 0 {
            return Err(ConfigError::MaxInTransit);
        }
        if self.services.rpc.user.is_some() && self.services.rpc.password.is_none() {
            return Err(ConfigError::RpcUserWithoutPassword);
        }
        for entry in &self.services.rpc.whitelist {
            if !entry.contains(':') {
                return Err(ConfigError::RpcWhitelistEntry(entry.clone()));
            }
        }
        for (point, hooks) in [
            ("peer_accept", &self.hooks.peer_accept),
            ("tx_admit", &self.hooks.tx_admit),
            ("tx_announce", &self.hooks.tx_announce),
            ("extrapool_admit", &self.hooks.extrapool_admit),
            ("extrapool_promote", &self.hooks.extrapool_promote),
            ("tx_serve", &self.hooks.tx_serve),
        ] {
            for hook in hooks {
                if hook.program.as_os_str().is_empty() {
                    return Err(ConfigError::HookProgram(point));
                }
                if !(1..=10_000).contains(&hook.timeout_ms) {
                    return Err(ConfigError::HookTimeout(point));
                }
            }
        }
        // relay.tx.deny_pairs — "src->dst" over the compartment names.
        const COMPARTMENTS: [&str; 4] = ["inbound", "outbound", "local", "extrapool"];
        for pair in &self.relay.tx.deny_pairs {
            let Some((src, dst)) = pair.split_once("->") else {
                return Err(ConfigError::DenyPair(pair.clone()));
            };
            if !COMPARTMENTS.contains(&src.trim()) || !["inbound", "outbound"].contains(&dst.trim())
            {
                return Err(ConfigError::DenyPair(pair.clone()));
            }
        }
        if !["never", "outbound", "all"].contains(&self.extrapool.relay.as_str()) {
            return Err(ConfigError::ExtrapoolRelay(self.extrapool.relay.clone()));
        }
        for trigger in &self.extrapool.promote_on {
            if trigger != "tip" {
                return Err(ConfigError::PromoteTrigger(trigger.clone()));
            }
        }
        const CAP_CLASSES: [&str; 11] = [
            "nonstandard",
            "fee",
            "hook",
            "rbf",
            "package",
            "finality",
            "capacity",
            "weight",
            "sigops",
            "truc",
            "other",
        ];
        for class in self.extrapool.caps.keys() {
            if !CAP_CLASSES.contains(&class.as_str()) {
                return Err(ConfigError::ExtrapoolCapClass(class.clone()));
            }
        }
        let capacity = NonZeroUsize::new(self.diag.event_capacity)
            .ok_or(ConfigError::EventCapacity(self.diag.event_capacity))?;
        Ok(ValidatedConfig {
            config: self,
            capacity,
        })
    }
}

/// Its fields are private and it cannot be deserialized around validation.
#[derive(Clone, Debug)]
pub struct ValidatedConfig {
    config: NodeConfig,
    capacity: NonZeroUsize,
}

impl ValidatedConfig {
    pub fn get(&self) -> &NodeConfig {
        &self.config
    }

    pub fn event_capacity(&self) -> NonZeroUsize {
        self.capacity
    }

    /// Separates data for different networks; does not create the directory.
    pub fn network_data_dir(&self) -> PathBuf {
        self.config.data_dir.join(self.config.network.to_string())
    }

    /// Resolve relative paths — `data_dir`, `net.asmap` — against the
    /// configuration file's directory, not the current working directory.
    pub fn resolve_relative_to(mut self, base: &Path) -> Self {
        if self.config.data_dir.is_relative() {
            self.config.data_dir = base.join(&self.config.data_dir);
        }
        if let Some(asmap) = &mut self.config.net.asmap
            && asmap.is_relative()
        {
            *asmap = base.join(&*asmap);
        }
        for hook in self
            .config
            .hooks
            .peer_accept
            .iter_mut()
            .chain(self.config.hooks.tx_admit.iter_mut())
            .chain(self.config.hooks.tx_announce.iter_mut())
            .chain(self.config.hooks.extrapool_admit.iter_mut())
            .chain(self.config.hooks.extrapool_promote.iter_mut())
        {
            if !hook.program.as_os_str().is_empty() && hook.program.is_relative() {
                hook.program = base.join(&hook.program);
            }
        }
        self
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("unsupported configuration schema version {0}; expected 1")]
    SchemaVersion(u32),
    #[error("data_dir must not be empty")]
    EmptyDataDirectory,
    #[error("diag.event_capacity {0} is outside the supported range 1..=4096")]
    EventCapacity(usize),
    #[error("peers.max_connections must be at least 1")]
    MaxConnections,
    #[error("mempool.max_mb must be at least 1")]
    MaxMempoolBytes,
    /// `extrapool.observe` with a zero bound — the pool can't hold
    /// anything it observes.
    #[error("extrapool.observe requires nonzero extrapool.max_entries and extrapool.max_bytes")]
    ExtrapoolBounds,
    #[error("{0} must not be negative")]
    NegativeFee(&'static str),
    #[error(
        "policy.datacarrier_size {0} exceeds MAX_STANDARD_TX_WEIGHT (400000) — no standard transaction could carry it"
    )]
    DatacarrierSize(usize),
    #[error("sync.max_in_transit must be at least 1")]
    MaxInTransit,
    #[error("services.rpc.user requires services.rpc.password")]
    RpcUserWithoutPassword,
    #[error("services.rpc.whitelist entry {0:?} must be \"user:method1,method2\"")]
    RpcWhitelistEntry(String),
    #[error("hooks.{0} entry has no program — the executable is required")]
    HookProgram(&'static str),
    #[error("hooks.{0}.timeout_ms must be 1..=10000 — a hook must never stall a decision point")]
    HookTimeout(&'static str),
    #[error(
        "relay.tx.deny_pairs entry {0:?} — expected \"src->dst\", src ∈ inbound|outbound|local|extrapool, dst ∈ inbound|outbound"
    )]
    DenyPair(String),
    #[error("extrapool.relay {0:?} — expected \"never\", \"outbound\", or \"all\"")]
    ExtrapoolRelay(String),
    #[error("extrapool.promote_on entry {0:?} — expected \"tip\"")]
    PromoteTrigger(String),
    #[error(
        "extrapool.caps class {0:?} — expected nonstandard|fee|hook|rbf|package|finality|capacity|weight|sigops|truc|other"
    )]
    ExtrapoolCapClass(String),
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid_and_network_specific() {
        let config = NodeConfig::default().validate().unwrap();
        assert_eq!(config.network_data_dir(), PathBuf::from("data/regtest"));
        assert_eq!(config.event_capacity().get(), 256);
    }

    #[test]
    fn policy_defaults_match_the_core_port() {
        let c = NodeConfig::default();
        assert!(c.policy.require_standard);
        assert_eq!(c.policy.datacarrier_bytes(), Some(100_000));
        assert!(c.policy.permit_bare_multisig);
        assert_eq!(c.policy.dust_relay_fee_sat_per_kvb, 3_000);
        assert_eq!(c.mempool.min_relay_fee_sat_per_kvb, 100);
        assert_eq!(c.mempool.max_mb, 300);
        assert_eq!(c.mempool.expiry_secs, 336 * 60 * 60);
        assert_eq!(c.peers.max_connections, 8);
        assert_eq!(c.sync.max_in_transit, 1024);
        assert!(c.net.v2transport && c.net.dns_seeds && c.relay.tx.stem);
    }

    #[test]
    fn rejects_invalid_capacities() {
        for event_capacity in [0, MAX_EVENT_CAPACITY + 1, usize::MAX] {
            let config = NodeConfig {
                diag: DiagConfig { event_capacity },
                ..NodeConfig::default()
            };
            assert!(matches!(
                config.validate(),
                Err(ConfigError::EventCapacity(_))
            ));
        }
    }

    #[test]
    fn accepts_capacity_boundaries() {
        for event_capacity in [1, MAX_EVENT_CAPACITY] {
            assert!(
                NodeConfig {
                    diag: DiagConfig { event_capacity },
                    ..NodeConfig::default()
                }
                .validate()
                .is_ok()
            );
        }
    }

    #[test]
    fn rejects_unknown_schema() {
        let config = NodeConfig {
            schema_version: 2,
            ..NodeConfig::default()
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::SchemaVersion(2))
        ));
    }

    #[test]
    fn rejects_empty_directory_before_resolution() {
        let config = NodeConfig {
            data_dir: PathBuf::new(),
            ..NodeConfig::default()
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::EmptyDataDirectory)
        ));
    }

    #[test]
    fn resolves_directory_against_configuration_location() {
        let config = NodeConfig::default()
            .validate()
            .unwrap()
            .resolve_relative_to(Path::new("configuration"));
        assert_eq!(config.get().data_dir, PathBuf::from("configuration/data"));
    }

    #[test]
    fn resolves_asmap_against_configuration_location() {
        let mut config = NodeConfig::default();
        config.net.asmap = Some(PathBuf::from("maps/asmap.txt"));
        let config = config
            .validate()
            .unwrap()
            .resolve_relative_to(Path::new("configuration"));
        assert_eq!(
            config.get().net.asmap.as_deref(),
            Some(Path::new("configuration/maps/asmap.txt"))
        );
    }

    #[test]
    fn rejects_structural_nonsense_not_policy_choice() {
        let mut config = NodeConfig::default();
        config.peers.max_connections = 0;
        assert!(matches!(
            config.clone().validate(),
            Err(ConfigError::MaxConnections)
        ));
        config = NodeConfig::default();
        config.policy.datacarrier_size = MAX_DATACARRIER_SIZE + 1;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::DatacarrierSize(_))
        ));
        // But every policy-sane value passes — validation is not
        // policy police: a zero relay fee and a 42-byte datacarrier
        // budget (the strict posture) are operator choices.
        let mut config = NodeConfig::default();
        config.mempool.min_relay_fee_sat_per_kvb = 0;
        config.policy.datacarrier_size = 42;
        config.policy.datacarrier = true;
        config.policy.permit_bare_multisig = false;
        config.validate().unwrap();
    }

    #[test]
    fn rpc_user_requires_password() {
        let mut config = NodeConfig::default();
        config.services.rpc.user = Some("alice".into());
        assert!(matches!(
            config.clone().validate(),
            Err(ConfigError::RpcUserWithoutPassword)
        ));
        config.services.rpc.password = Some("pw".into());
        config.validate().unwrap();
    }

    #[test]
    fn whitelist_entries_need_user_colon_methods() {
        let mut config = NodeConfig::default();
        config.services.rpc.whitelist = vec!["alice:getbalance".into()];
        config.clone().validate().unwrap();
        config.services.rpc.whitelist = vec!["alice".into()];
        assert!(matches!(
            config.validate(),
            Err(ConfigError::RpcWhitelistEntry(_))
        ));
    }

    #[test]
    fn datacarrier_disable_is_none() {
        let mut config = NodeConfig::default();
        config.policy.datacarrier = false;
        assert_eq!(config.policy.datacarrier_bytes(), None);
    }
}
