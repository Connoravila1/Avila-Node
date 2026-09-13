use std::fmt;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_EVENT_CAPACITY: usize = 4096;

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
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NodeConfig {
    pub schema_version: u32,
    pub network: Network,
    pub data_dir: PathBuf,
    pub event_capacity: usize,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            schema_version: 1,
            network: Network::Regtest,
            data_dir: PathBuf::from("data"),
            event_capacity: 256,
        }
    }
}

impl NodeConfig {
    pub fn validate(self) -> Result<ValidatedConfig, ConfigError> {
        if self.schema_version != 1 {
            return Err(ConfigError::SchemaVersion(self.schema_version));
        }
        if self.data_dir.as_os_str().is_empty() {
            return Err(ConfigError::EmptyDataDirectory);
        }
        if !(1..=MAX_EVENT_CAPACITY).contains(&self.event_capacity) {
            return Err(ConfigError::EventCapacity(self.event_capacity));
        }
        let capacity = NonZeroUsize::new(self.event_capacity)
            .ok_or(ConfigError::EventCapacity(self.event_capacity))?;
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

    /// Resolve a relative base directory after validating the original value.
    pub fn resolve_relative_to(mut self, base: &Path) -> Self {
        if self.config.data_dir.is_relative() {
            self.config.data_dir = base.join(&self.config.data_dir);
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
    #[error("event_capacity {0} is outside the supported range 1..=4096")]
    EventCapacity(usize),
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
    fn rejects_invalid_capacities() {
        for event_capacity in [0, MAX_EVENT_CAPACITY + 1, usize::MAX] {
            let config = NodeConfig {
                event_capacity,
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
                    event_capacity,
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
}
