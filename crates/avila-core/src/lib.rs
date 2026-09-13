//! Shared contracts, not a Bitcoin consensus implementation.
//!
//! This crate performs no filesystem, socket, clock, or GUI operations.

mod config;
mod status;

pub use config::{ConfigError, MAX_EVENT_CAPACITY, Network, NodeConfig, ValidatedConfig};
pub use status::{CAPABILITIES, Capability, CapabilityState, Lifecycle, NodeSnapshot};
