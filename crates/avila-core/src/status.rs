use std::path::PathBuf;

use serde::Serialize;

use crate::Network;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Implemented,
    Planned,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Capability {
    pub name: &'static str,
    pub state: CapabilityState,
}

/// Update only when implementation and its acceptance tests actually exist.
pub const CAPABILITIES: &[Capability] = &[
    Capability {
        name: "Configuration validation",
        state: CapabilityState::Implemented,
    },
    Capability {
        name: "Local capability inspection",
        state: CapabilityState::Implemented,
    },
    Capability {
        name: "Bounded in-memory event journal",
        state: CapabilityState::Implemented,
    },
    Capability {
        name: "Bitcoin consensus validation",
        state: CapabilityState::Planned,
    },
    Capability {
        name: "Persistent chainstate and reorganization",
        state: CapabilityState::Planned,
    },
    Capability {
        name: "Peer networking and initial block download",
        state: CapabilityState::Planned,
    },
    Capability {
        name: "Mempool and transaction relay",
        state: CapabilityState::Planned,
    },
    Capability {
        name: "Wallet backends and authenticated RPC",
        state: CapabilityState::Planned,
    },
    Capability {
        name: "Enforced network privacy profiles",
        state: CapabilityState::Planned,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    Configured,
    StartupBlocked,
}

/// An observation of this process, never a report from a remote running daemon.
/// Unknown measurements are null, not fabricated zeroes or a fake genesis tip.
#[derive(Clone, Debug, Serialize)]
pub struct NodeSnapshot {
    pub scope: &'static str,
    pub version: &'static str,
    pub network: Network,
    pub data_dir: PathBuf,
    pub lifecycle: Lifecycle,
    pub validated_tip_height: Option<u64>,
    pub historical_validation_complete: bool,
    pub connected_peers: Option<usize>,
    pub capabilities: &'static [Capability],
}
