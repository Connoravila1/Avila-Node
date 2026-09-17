//! Coordinator shared by the headless executable and egui application.
//!
//! Full-node startup currently fails explicitly: persistent services are not
//! wired yet. There is no mock validator or success-returning placeholder.
//! Live peer sync is available through [`sync::run`].

pub mod config;
pub mod electrum;
pub mod events;
pub mod rpc;
pub mod sv2;
pub mod sync;
pub mod time;
pub mod watch;

use avila_core::{CAPABILITIES, Lifecycle, NodeSnapshot, ValidatedConfig};
use thiserror::Error;

use events::{EventJournal, JournalError, NodeEvent};

#[derive(Debug)]
pub struct Node {
    config: ValidatedConfig,
    lifecycle: Lifecycle,
    events: EventJournal,
}

impl Node {
    pub fn new(config: ValidatedConfig) -> Result<Self, NodeError> {
        let mut events = EventJournal::new(config.event_capacity());
        events.push(NodeEvent::ConfigurationLoaded)?;
        Ok(Self {
            config,
            lifecycle: Lifecycle::Configured,
            events,
        })
    }

    pub fn config(&self) -> &ValidatedConfig {
        &self.config
    }

    pub fn events(&self) -> &EventJournal {
        &self.events
    }

    pub fn snapshot(&self) -> NodeSnapshot {
        NodeSnapshot {
            scope: "local_inspection",
            version: env!("CARGO_PKG_VERSION"),
            network: self.config.get().network,
            data_dir: self.config.network_data_dir(),
            lifecycle: self.lifecycle,
            validated_tip_height: None,
            historical_validation_complete: false,
            connected_peers: None,
            capabilities: CAPABILITIES,
        }
    }

    /// Replace this gate only as real implementations pass the roadmap gates.
    /// It cannot be bypassed by choosing another network or adding a flag.
    pub fn start(&mut self) -> Result<(), NodeError> {
        self.lifecycle = Lifecycle::StartupBlocked;
        self.events.push(NodeEvent::StartupBlocked)?;
        Err(NodeError::MissingSubsystems)
    }
}

#[derive(Debug, Error)]
pub enum NodeError {
    #[error(
        "node startup is not implemented: consensus validation, persistent chainstate, and peer networking are still required; see ROADMAP.md"
    )]
    MissingSubsystems,
    #[error(transparent)]
    Journal(#[from] JournalError),
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use avila_core::{Network, NodeConfig};

    #[test]
    fn inspection_does_not_claim_to_have_verified_a_chain() {
        let node = Node::new(NodeConfig::default().validate().unwrap()).unwrap();
        let snapshot = node.snapshot();
        assert_eq!(snapshot.scope, "local_inspection");
        assert_eq!(snapshot.validated_tip_height, None);
        assert_eq!(snapshot.connected_peers, None);
        assert!(!snapshot.historical_validation_complete);
    }

    #[test]
    fn all_networks_refuse_unimplemented_startup() {
        for network in [
            Network::Mainnet,
            Network::Testnet4,
            Network::Signet,
            Network::Regtest,
        ] {
            let config = NodeConfig {
                network,
                ..NodeConfig::default()
            };
            let mut node = Node::new(config.validate().unwrap()).unwrap();
            assert!(matches!(node.start(), Err(NodeError::MissingSubsystems)));
            assert_eq!(node.snapshot().lifecycle, Lifecycle::StartupBlocked);
            assert_eq!(node.events().entries().count(), 2);
        }
    }
}
