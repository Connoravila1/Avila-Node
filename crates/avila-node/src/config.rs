use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use avila_core::{ConfigError, NodeConfig, ValidatedConfig};
use thiserror::Error;

pub const MAX_CONFIG_BYTES: usize = 64 * 1024;

/// No implicit config discovery, environment expansion, or file creation.
pub fn load_config(path: Option<&Path>) -> Result<ValidatedConfig, LoadConfigError> {
    let Some(path) = path else {
        return Ok(NodeConfig::default().validate()?);
    };
    let file = File::open(path).map_err(|source| LoadConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mut contents = String::new();
    file.take((MAX_CONFIG_BYTES + 1) as u64)
        .read_to_string(&mut contents)
        .map_err(|source| LoadConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    let config = parse_config(&contents)?;
    Ok(config.resolve_relative_to(path.parent().unwrap_or_else(|| Path::new("."))))
}

/// Pure parsing entry point, also used for tests and future fuzzing.
pub fn parse_config(contents: &str) -> Result<ValidatedConfig, LoadConfigError> {
    if contents.len() > MAX_CONFIG_BYTES {
        return Err(LoadConfigError::TooLarge);
    }
    let config: NodeConfig = toml::from_str(contents)?;
    let config = config.validate()?;
    // `policy.shadow` names resolve to mempool-crate presets —
    // validation lives here (not in avila-core) because that's where
    // the preset table is defined.
    let mut seen = std::collections::BTreeSet::new();
    for name in &config.get().policy.shadow {
        if avila_mempool::policy::shadow_preset(name).is_none() {
            return Err(LoadConfigError::UnknownShadow(name.clone()));
        }
        if !seen.insert(name) {
            return Err(LoadConfigError::DuplicateShadow(name.clone()));
        }
    }
    Ok(config)
}

#[derive(Debug, Error)]
pub enum LoadConfigError {
    #[error("could not read configuration {path}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("configuration exceeds the 64 KiB limit")]
    TooLarge,
    #[error("invalid TOML configuration: {0}")]
    Parse(#[from] toml::de::Error),
    #[error(transparent)]
    Invalid(#[from] ConfigError),
    #[error("policy.shadow profile {0:?} is unknown — builtins: strict, core, permissive")]
    UnknownShadow(String),
    #[error("policy.shadow lists {0:?} twice")]
    DuplicateShadow(String),
}

/// One line of `config describe`: dotted knob path, its one-line doc,
/// and the effective vs. default values.
#[derive(Clone, Debug)]
pub struct KnobDescription {
    pub path: &'static str,
    pub doc: &'static str,
    pub value: serde_json::Value,
    pub default: serde_json::Value,
}

/// Every documented knob, in display order. A test asserts this covers
/// exactly the serializable fields of [`NodeConfig`], so a renamed or
/// added field fails the suite until documented — the table is the
/// schema, not a copy of it.
const KNOB_DOCS: &[(&str, &str)] = &[
    ("schema_version", "configuration format version — must be 1"),
    (
        "network",
        "Bitcoin network: mainnet | testnet4 | signet | regtest",
    ),
    (
        "data_dir",
        "chainstate and index root; relative paths resolve against the config file",
    ),
    (
        "diag.event_capacity",
        "process-local event journal capacity (1..=4096)",
    ),
    (
        "storage.prune_mb",
        "prune blk files to this many MiB (Core's -prune; empty = archival)",
    ),
    (
        "storage.dbcache_mb",
        "coins-view write-back cache budget, MiB (Core's -dbcache)",
    ),
    (
        "net.v2transport",
        "BIP324 encrypted transport on outbound dials (-v2transport)",
    ),
    (
        "net.connect",
        "fixed outbound peers addr:port (-connect; suppresses DNS seeding)",
    ),
    (
        "net.listen",
        "inbound peer listener (-listen=<addr>; empty = outbound-only)",
    ),
    (
        "net.asmap",
        "prefix-to-ASN map for outbound-dial bucketing (-asmap; relative to config file)",
    ),
    (
        "net.dns_seeds",
        "DNS seeding (-dnsseed); also suppressed by connect/proxy",
    ),
    (
        "peers.max_connections",
        "total peer slots, inbound + outbound (-maxconnections)",
    ),
    (
        "peers.ban_time",
        "default setban duration in seconds (Core's -bantime)",
    ),
    (
        "privacy.proxy",
        "SOCKS5 proxy for all outbound connections (-proxy)",
    ),
    (
        "privacy.cell_bytes",
        "pad v2 writes to this byte multiple with decoy packets; 0 = off",
    ),
    (
        "mempool.max_mb",
        "mempool serialized-byte cap in MiB (-maxmempool)",
    ),
    (
        "mempool.min_relay_fee_sat_per_kvb",
        "admission and relay fee floor, sat/kvB (-minrelaytxfee)",
    ),
    (
        "mempool.expiry_secs",
        "evict entries older than this many seconds (-mempoolexpiry)",
    ),
    (
        "policy.require_standard",
        "apply standardness policy to admission (-acceptnonstdtxn negated)",
    ),
    (
        "policy.datacarrier",
        "relay OP_RETURN outputs at all (-datacarrier)",
    ),
    (
        "policy.datacarrier_size",
        "OP_RETURN bytes standard per transaction (-datacarriersize; dead while datacarrier = false)",
    ),
    (
        "policy.permit_bare_multisig",
        "relay unwrapped multisig outputs (-permitbaremultisig)",
    ),
    (
        "policy.dust_relay_fee_sat_per_kvb",
        "dust-threshold fee rate, sat/kvB (-dustrelayfee)",
    ),
    (
        "policy.shadow",
        "counterfactual policies scored on live admissions (strict, core, permissive)",
    ),
    (
        "relay.tx.stem",
        "route locally-originated transactions through one stem hop before flooding",
    ),
    (
        "extrapool.observe",
        "record consensus-valid policy rejects into the bounded extrapool",
    ),
    (
        "extrapool.max_entries",
        "extrapool entry cap — FIFO evict past it",
    ),
    (
        "extrapool.max_bytes",
        "extrapool serialized-bytes cap — FIFO evict past it",
    ),
    (
        "extrapool.expiry_secs",
        "extrapool entry lifetime; 0 keeps entries until evicted/promoted",
    ),
    (
        "hooks.peer_accept",
        "inbound-admission verdict helpers ([[hooks.peer_accept]]: program, args, timeout_ms, on_timeout, on_defer, max_restarts)",
    ),
    (
        "hooks.tx_admit",
        "tx-admission verdict helpers ([[hooks.tx_admit]] — consulted per tx, before built-in checks; narrowing only)",
    ),
    (
        "filters.build",
        "maintain the BIP158 basic filter index (-blockfilterindex)",
    ),
    (
        "filters.serve",
        "answer BIP157 requests from peers (-peerblockfilters; needs filters.build)",
    ),
    (
        "indexes.txindex",
        "txid-to-block index for getrawtransaction (-txindex)",
    ),
    (
        "sync.max_in_transit",
        "total blocks-in-flight budget across all peers",
    ),
    (
        "sync.utreexo",
        "utreexo shadow-accumulator validation alongside the UTXO path",
    ),
    (
        "sync.utreexo_bridge",
        "maintain a proving forest and serve utxproof spend bundles",
    ),
    (
        "services.rpc.bind",
        "JSON-RPC bind addr:port (empty = off; cookie auth when bound)",
    ),
    (
        "services.rpc.user",
        "named RPC credential (-rpcuser; requires services.rpc.password)",
    ),
    (
        "services.rpc.password",
        "password for services.rpc.user (-rpcpassword; redacted from describe)",
    ),
    (
        "services.rpc.whitelist",
        "per-user method scopes 'user:m1,m2' (-rpcwhitelist)",
    ),
    (
        "services.rpc.whitelist_default",
        "users without a whitelist entry may call any method (-rpcwhitelistdefault)",
    ),
    (
        "services.electrum.listen",
        "Electrum-protocol bind; also maintains the scripthash index",
    ),
    (
        "services.sv2.listen",
        "Stratum V2 Template Provider bind; loopback only until Noise lands",
    ),
    (
        "mempool.private",
        "stem-only relay + hidden from getrawmempool/getmempoolentry for local submissions",
    ),
    (
        "relay.tx.deny_pairs",
        "compartment matrix: 'src->dst' pairs never announced across (src: inbound|outbound|local|extrapool; dst: inbound|outbound)",
    ),
    (
        "extrapool.relay",
        "propagate observed txs — never|outbound|all (tx.announce gates each hop)",
    ),
    (
        "extrapool.promote_on",
        "auto re-admission triggers — 'tip' retries all entries per connected block",
    ),
    (
        "extrapool.caps",
        "per-reject-class entry caps — oldest of a class evicts past its bound",
    ),
    (
        "hooks.tx_announce",
        "verdict helpers consulted per (tx, link) — reject withholds that announce",
    ),
    (
        "hooks.extrapool_admit",
        "verdict helpers gating extrapool observation records",
    ),
    (
        "hooks.extrapool_promote",
        "verdict helpers gating extrapool re-admission",
    ),
];

/// Serialize each knob out of the loaded config next to its default —
/// `config describe`'s answer to "what is this node set to".
pub fn describe_config(config: &NodeConfig) -> Vec<KnobDescription> {
    // to_value on plain data structs cannot fail; the coverage test
    // would catch it if it ever did.
    let current = serde_json::to_value(config).unwrap_or_default();
    let defaults = serde_json::to_value(NodeConfig::default()).unwrap_or_default();
    KNOB_DOCS
        .iter()
        .map(|(path, doc)| {
            let pointer = format!("/{}", path.replace('.', "/"));
            let mut value = current.pointer(&pointer).cloned().unwrap_or_default();
            // Credentials never echo to a terminal or a piped log.
            if *path == "services.rpc.password" && !value.is_null() {
                value = serde_json::json!("[set]");
            }
            KnobDescription {
                path,
                doc,
                value,
                default: defaults.pointer(&pointer).cloned().unwrap_or_default(),
            }
        })
        .collect()
}

/// How loud a lint finding is — `Fail` mirrors a condition `run`/`sync`
/// would refuse at startup.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum LintLevel {
    Note,
    Warn,
    Fail,
}

/// One lint finding on the resolved (validated) config.
#[derive(Clone, Debug)]
pub struct LintFinding {
    pub level: LintLevel,
    pub path: &'static str,
    pub message: String,
}

/// Heuristic audit — valid config can still be self-defeating. These
/// are warnings and notes, not validation; the knobs they touch are
/// legal, just suspicious in combination.
pub fn lint_config(c: &NodeConfig) -> Vec<LintFinding> {
    let mut out = Vec::new();
    let mut push = |level: LintLevel, path: &'static str, message: String| {
        out.push(LintFinding {
            level,
            path,
            message,
        })
    };

    if c.filters.serve && !c.filters.build {
        push(
            LintLevel::Fail,
            "filters.serve",
            "requires filters.build — startup refuses -peerblockfilters without the index".into(),
        );
    }
    if let Some(mb) = c.storage.prune_mb
        && mb < 550
    {
        push(
            LintLevel::Warn,
            "storage.prune_mb",
            format!("{mb} MiB is under Core's 550 MiB minimum for pruned operation"),
        );
    }
    if c.services.rpc.user.is_some() && c.services.rpc.bind.is_none() {
        push(
            LintLevel::Warn,
            "services.rpc.user",
            "credential configured but services.rpc.bind is unset — RPC is off".into(),
        );
    }
    if c.services.rpc.password.is_some() && c.services.rpc.user.is_none() {
        push(
            LintLevel::Warn,
            "services.rpc.password",
            "password without user is ignored".into(),
        );
    }
    if c.mempool.max_mb < 5 {
        push(
            LintLevel::Warn,
            "mempool.max_mb",
            format!(
                "{} MiB is a tiny pool — most inbound transactions will fail fee checks",
                c.mempool.max_mb
            ),
        );
    }
    if !c.policy.datacarrier && c.policy.datacarrier_size != 100_000 {
        push(
            LintLevel::Warn,
            "policy.datacarrier_size",
            "dead knob while policy.datacarrier = false".into(),
        );
    }
    if !c.net.connect.is_empty() {
        push(
            LintLevel::Note,
            "net.connect",
            "fixed peers suppress DNS seeding (Core's -connect is exclusive)".into(),
        );
    }
    if c.privacy.proxy.is_some() && c.net.dns_seeds {
        push(
            LintLevel::Note,
            "privacy.proxy",
            "proxy suppresses DNS seeding regardless — a local lookup would leak the resolver"
                .into(),
        );
    }
    if !c.net.dns_seeds && c.net.connect.is_empty() {
        push(
            LintLevel::Note,
            "net.dns_seeds",
            "seeding off with no fixed peers — the address book must come from peers.dat".into(),
        );
    }
    for (path, addr) in [
        ("services.electrum.listen", c.services.electrum.listen),
        ("services.sv2.listen", c.services.sv2.listen),
    ] {
        if let Some(a) = addr
            && !a.ip().is_loopback()
        {
            push(
                LintLevel::Warn,
                path,
                format!("{a} is not loopback — an unauthenticated plaintext service"),
            );
        }
    }
    out
}

/// One entry in the startup risk report — a knob making the node
/// behave dramatically unlike stock relay policy. Unlike `lint_config`
/// findings (suspicious combinations), these are deliberate
/// postures an operator should consciously accept *once*; `run`
/// re-warns only when a finding it hasn't seen before appears.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RiskFinding {
    pub path: &'static str,
    pub message: String,
}

/// The dramatic-change tripwires — evaluated on the loaded config.
/// Each returns `(path, human explanation)`; the set is hashed into
/// the datadir's `risk_ack` so acknowledgment survives restarts and a
/// *new* risk still surfaces.
pub fn risk_review(c: &NodeConfig) -> Vec<RiskFinding> {
    let mut out = Vec::new();
    let mut push = |path: &'static str, message: String| out.push(RiskFinding { path, message });

    if !c.policy.require_standard {
        push(
            "policy.require_standard",
            "relays consensus-valid-but-nonstandard transactions — departs from every stock node"
                .into(),
        );
    }
    if c.mempool.min_relay_fee_sat_per_kvb == 0 {
        push(
            "mempool.min_relay_fee_sat_per_kvb",
            "zero fee floor — zero-cost transactions relay freely; bounds are the only brake"
                .into(),
        );
    }
    if !c.relay.tx.stem {
        push(
            "relay.tx.stem",
            "locally-originated transactions flood immediately — first-hop peers learn the origin"
                .into(),
        );
    }
    for (point, specs) in [
        ("peer_accept", &c.hooks.peer_accept),
        ("tx_admit", &c.hooks.tx_admit),
        ("tx_announce", &c.hooks.tx_announce),
        ("extrapool_admit", &c.hooks.extrapool_admit),
        ("extrapool_promote", &c.hooks.extrapool_promote),
    ] {
        for (i, s) in specs.iter().enumerate() {
            if matches!(s.on_timeout, avila_core::OnDefault::Accept)
                || matches!(s.on_defer, avila_core::OnDefault::Accept)
            {
                push(
                    "hooks",
                    format!(
                        "{point}[{i}] is fail-open — a dead or wedged helper admits by default"
                    ),
                );
            }
        }
    }
    if c.extrapool.observe && c.extrapool.max_bytes > 256_000_000 {
        push(
            "extrapool.max_bytes",
            format!(
                "{} MiB of rejected-transaction retention — held in memory for observation",
                c.extrapool.max_bytes / 1_048_576
            ),
        );
    }
    if c.peers.ban_time == 0 {
        push(
            "peers.ban_time",
            "zero default ban duration — `setban` entries expire instantly".into(),
        );
    }
    out.sort();
    out
}

/// Findings in `risks` not yet acknowledged — the ack file stores the
/// literal `path: message` lines so `cat` shows exactly what was
/// signed off. Set semantics: only *new* findings warn.
pub fn unacknowledged<'a>(
    risks: &'a [RiskFinding],
    acked: &std::collections::HashSet<String>,
) -> Vec<&'a RiskFinding> {
    risks
        .iter()
        .filter(|r| !acked.contains(&format!("{}: {}", r.path, r.message)))
        .collect()
}

/// The on-disk acknowledgment set — one `path: message` line each.
pub fn acknowledge_risks(dir: &std::path::Path, risks: &[RiskFinding]) -> std::io::Result<()> {
    let lines: Vec<String> = risks
        .iter()
        .map(|r| format!("{}: {}", r.path, r.message))
        .collect();
    std::fs::write(dir.join("risk_ack"), lines.join("\n") + "\n")
}

/// Read the acknowledgment set (`risks` file semantics).
#[must_use]
pub fn risk_ack_set(dir: &std::path::Path) -> std::collections::HashSet<String> {
    std::fs::read_to_string(dir.join("risk_ack"))
        .map(|s| s.lines().map(str::to_string).collect())
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use avila_core::Network;

    #[test]
    fn checked_in_configuration_parses() {
        let config = parse_config(include_str!("../../../config/default.toml")).unwrap();
        assert_eq!(config.get().network, Network::Regtest);
        let config = parse_config(include_str!("../../../config/mainnet.toml")).unwrap();
        assert_eq!(config.get().network, Network::Mainnet);
        assert_eq!(config.get().storage.prune_mb, Some(2048));
    }

    #[test]
    fn namespaced_sections_parse() {
        let config = parse_config(
            r#"
            network = "regtest"
            [net]
            listen = "127.0.0.1:18333"
            dns_seeds = false
            [mempool]
            max_mb = 64
            [policy]
            datacarrier_size = 42
            permit_bare_multisig = false
            [relay.tx]
            stem = false
            "#,
        )
        .unwrap();
        let c = config.get();
        assert_eq!(c.net.listen, Some("127.0.0.1:18333".parse().unwrap()));
        assert!(!c.net.dns_seeds);
        assert_eq!(c.mempool.max_mb, 64);
        assert_eq!(c.policy.datacarrier_bytes(), Some(42));
        assert!(!c.policy.permit_bare_multisig);
        assert!(!c.relay.tx.stem);
    }

    #[test]
    fn rejects_unknown_keys_inside_sections() {
        assert!(parse_config("[mempool]\nmax_bytez = 1\n").is_err());
        assert!(parse_config("[policy]\ndatacarier = false\n").is_err());
    }

    #[test]
    fn rejects_unknown_keys_instead_of_ignoring_typos() {
        assert!(parse_config("event_capcity = 12").is_err());
    }

    #[test]
    fn rejects_unknown_network() {
        assert!(parse_config("network = 'not-bitcoin'").is_err());
    }

    #[test]
    fn rejects_oversized_input() {
        assert!(matches!(
            parse_config(&" ".repeat(MAX_CONFIG_BYTES + 1)),
            Err(LoadConfigError::TooLarge)
        ));
    }

    #[test]
    fn shadow_profile_names_validate_at_load() {
        assert!(matches!(
            parse_config("[policy]\nshadow = ['strict', 'bogus']"),
            Err(LoadConfigError::UnknownShadow(n)) if n == "bogus"
        ));
        assert!(matches!(
            parse_config("[policy]\nshadow = ['strict', 'strict']"),
            Err(LoadConfigError::DuplicateShadow(n)) if n == "strict"
        ));
        assert!(parse_config("[policy]\nshadow = ['core', 'strict', 'permissive']").is_ok());
        assert!(parse_config("[policy]\nshadow = []").is_ok());
        assert_eq!(
            parse_config("").unwrap().get().policy.shadow,
            vec!["strict".to_string()]
        );
    }

    #[test]
    fn network_selection_is_explicit() {
        for name in ["mainnet", "testnet4", "signet", "regtest"] {
            let config = parse_config(&format!("network = '{name}'")).unwrap();
            assert_eq!(config.get().network.to_string(), name);
        }
    }

    #[test]
    fn malformed_configuration_has_no_default_fallback() {
        assert!(parse_config("network = [").is_err());
    }

    #[test]
    fn docs_cover_every_knob() {
        // If this fails, a NodeConfig field was added or renamed
        // without updating KNOB_DOCS — describe would silently drop it.
        fn leaves(v: &serde_json::Value, prefix: &str, out: &mut Vec<String>) {
            match v {
                serde_json::Value::Object(map) if !map.is_empty() => {
                    for (k, sub) in map {
                        let p = if prefix.is_empty() {
                            k.clone()
                        } else {
                            format!("{prefix}.{k}")
                        };
                        leaves(sub, &p, out);
                    }
                }
                // An empty map/array is still a knob (e.g.
                // extrapool.caps = {}) — it just has no leaves yet.
                _ => out.push(prefix.to_string()),
            }
        }
        let root = serde_json::to_value(NodeConfig::default()).unwrap();
        let mut paths = Vec::new();
        leaves(&root, "", &mut paths);
        paths.sort();
        let mut docs: Vec<&str> = KNOB_DOCS.iter().map(|(p, _)| *p).collect();
        docs.sort();
        assert_eq!(paths, docs);
    }

    #[test]
    fn describe_reports_effective_and_default() {
        let config = parse_config("network = 'regtest'\n[mempool]\nmax_mb = 64\n").unwrap();
        let knobs = describe_config(config.get());
        let knob = knobs.iter().find(|k| k.path == "mempool.max_mb").unwrap();
        assert_eq!(knob.value, serde_json::json!(64));
        assert_eq!(knob.default, serde_json::json!(300));
        let untouched = knobs.iter().find(|k| k.path == "relay.tx.stem").unwrap();
        assert_eq!(untouched.value, untouched.default);
    }

    #[test]
    fn describe_redacts_rpc_password() {
        let config =
            parse_config("network = 'regtest'\n[services.rpc]\nuser = 'a'\npassword = 'secret'\n")
                .unwrap();
        let knobs = describe_config(config.get());
        let pw = knobs
            .iter()
            .find(|k| k.path == "services.rpc.password")
            .unwrap();
        assert_eq!(pw.value, serde_json::json!("[set]"));
    }

    #[test]
    fn lint_flags_serve_without_build_as_fatal() {
        let config = parse_config("network = 'regtest'\n[filters]\nserve = true\n").unwrap();
        let findings = lint_config(config.get());
        assert!(
            findings
                .iter()
                .any(|f| f.level == LintLevel::Fail && f.path == "filters.serve")
        );
    }

    #[test]
    fn lint_passes_a_clean_default() {
        assert!(lint_config(&NodeConfig::default()).is_empty());
    }

    #[test]
    fn lint_notes_dead_and_footgun_knobs() {
        let config = parse_config(
            r#"
            network = 'regtest'
            [storage]
            prune_mb = 100
            [policy]
            datacarrier = false
            datacarrier_size = 42
            [services.sv2]
            listen = "0.0.0.0:55001"
            "#,
        )
        .unwrap();
        let findings = lint_config(config.get());
        let warned: Vec<&str> = findings.iter().map(|f| f.path).collect();
        assert!(warned.contains(&"storage.prune_mb"));
        assert!(warned.contains(&"policy.datacarrier_size"));
        assert!(warned.contains(&"services.sv2.listen"));
        assert!(!findings.iter().any(|f| f.level == LintLevel::Fail));
    }

    #[test]
    fn peer_accept_hook_table_parses_with_defaults() {
        let config = parse_config(
            r#"
            network = 'regtest'
            [[hooks.peer_accept]]
            program = "/usr/local/sbin/accept-peer"
            args = ["--strict"]
            "#,
        )
        .unwrap();
        let hook = &config.get().hooks.peer_accept[0];
        assert_eq!(hook.program.to_str(), Some("/usr/local/sbin/accept-peer"));
        assert_eq!(hook.args, vec!["--strict"]);
        assert_eq!(hook.timeout_ms, 500);
        assert_eq!(hook.on_timeout, avila_core::OnDefault::Reject);
        assert_eq!(hook.max_restarts, 3);
    }

    #[test]
    fn hook_without_program_is_an_error() {
        assert!(parse_config("network = 'regtest'\n[[hooks.peer_accept]]\n").is_err());
        assert!(parse_config("network = 'regtest'\n[[hooks.tx_admit]]\n").is_err());
    }

    #[test]
    fn extrapool_section_parses_and_validates() {
        let config = parse_config(
            r#"
            network = 'regtest'
            [extrapool]
            observe = true
            max_entries = 500
            max_bytes = 1000000
            expiry_secs = 0
            "#,
        )
        .unwrap();
        let x = &config.get().extrapool;
        assert!(x.observe);
        assert_eq!(x.max_entries, 500);
        assert_eq!(x.expiry_secs, 0);

        // observe=true with a zero bound can't hold anything — reject.
        assert!(parse_config("network = 'regtest'\n[extrapool]\nmax_entries = 0\n").is_err());
        // observe=false with zero bounds is fine — nothing to hold.
        assert!(
            parse_config("network = 'regtest'\n[extrapool]\nobserve = false\nmax_entries = 0\n")
                .is_ok()
        );

        // relay / promote_on / caps accept only their vocabularies.
        let cfg = parse_config(
            r#"
            network = 'regtest'
            [extrapool]
            relay = "outbound"
            promote_on = ["tip"]
            caps = { fee = 500, hook = 100 }
            "#,
        )
        .unwrap();
        let x = &cfg.get().extrapool;
        assert_eq!(x.relay, "outbound");
        assert_eq!(x.promote_on, ["tip"]);
        assert_eq!(x.caps["fee"], 500);
        for bad in [
            r#"[extrapool]
relay = "sideways""#,
            r#"[extrapool]
promote_on = ["moon"]"#,
            r#"[extrapool]
caps = { bogus = 1 }"#,
            r#"[relay.tx]
deny_pairs = ["sideways->outbound"]"#,
            r#"[relay.tx]
deny_pairs = ["inbound"]"#,
            r#"[relay.tx]
deny_pairs = ["local->local"]"#,
        ] {
            assert!(
                parse_config(&format!("network = 'regtest'\n{bad}\n")).is_err(),
                "{bad} must fail validation"
            );
        }
    }

    /// The risk review flags dramatic postures once — the ack file
    /// keeps the literal line set, so only new findings resurface.
    #[test]
    fn risk_review_warns_once_until_the_set_changes() {
        // Stock config is quiet.
        let clean = parse_config("network = 'regtest'").unwrap();
        assert!(risk_review(clean.get()).is_empty());

        let risky = parse_config(
            r#"
            network = 'regtest'
            [policy]
            require_standard = false
            [[hooks.tx_admit]]
            program = "/bin/cat"
            on_timeout = "accept"
            "#,
        )
        .unwrap();
        let risks = risk_review(risky.get());
        assert_eq!(risks.len(), 2);
        assert!(risks.iter().any(|r| r.path == "policy.require_standard"));
        assert!(risks.iter().any(|r| r.message.contains("fail-open")));

        // Unacknowledged → all fresh; after acknowledge → silent.
        let dir = std::env::temp_dir().join(format!("avila-risk-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let empty = std::collections::HashSet::new();
        assert_eq!(unacknowledged(&risks, &empty).len(), 2);
        acknowledge_risks(&dir, &risks).unwrap();
        let acked = risk_ack_set(&dir);
        assert!(unacknowledged(&risks, &acked).is_empty());

        // A new risk added later re-warns alone.
        let mut extra = risks.clone();
        extra.push(RiskFinding {
            path: "peers.ban_time",
            message: "zero".into(),
        });
        extra.sort();
        assert_eq!(unacknowledged(&extra, &acked).len(), 1);
    }

    #[test]
    fn hook_timeout_is_bounded() {
        let toml = r#"
            network = 'regtest'
            [[hooks.peer_accept]]
            program = "/bin/cat"
            timeout_ms = 0
        "#;
        assert!(parse_config(toml).is_err());
    }
}
