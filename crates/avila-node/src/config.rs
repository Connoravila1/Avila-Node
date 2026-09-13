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
    Ok(config.validate()?)
}

#[derive(Debug, Error)]
pub enum LoadConfigError {
    #[error("could not read configuration {path}: {source}")]
    Read {
        path: PathBuf,
        source: io::Error,
    },
    #[error("configuration exceeds the 64 KiB limit")]
    TooLarge,
    #[error("invalid TOML configuration: {0}")]
    Parse(#[from] toml::de::Error),
    #[error(transparent)]
    Invalid(#[from] ConfigError),
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
}
