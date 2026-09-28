//! Shared contracts, not a Bitcoin consensus implementation.
//!
//! This crate performs no filesystem, socket, clock, or GUI operations.

mod config;
mod status;

pub use config::{
    ConfigError, DiagConfig, ElectrumServiceConfig, ExtrapoolConfig, FiltersConfig, HookSpecConfig,
    HooksConfig, IndexesConfig, MAX_EVENT_CAPACITY, MempoolConfig, NetConfig, Network, NodeConfig,
    OnDefault, PeersConfig, PolicyConfig, PrivacyConfig, RelayConfig, RpcServiceConfig,
    ServicesConfig, StorageConfig, Sv2ServiceConfig, SyncKnobs, TxRelayConfig, ValidatedConfig,
};
pub use status::{CAPABILITIES, Capability, CapabilityState, Lifecycle, NodeSnapshot};
