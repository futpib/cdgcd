use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub allow_process_name: Vec<String>,

    #[serde(default)]
    pub allow_executable_path: Vec<String>,

    #[serde(default = "default_coredump_directory")]
    pub coredump_directory: PathBuf,

    #[serde(default = "default_idle_interval", deserialize_with = "deserialize_duration")]
    pub idle_interval: Duration,

    #[serde(default = "default_minimum_age", deserialize_with = "deserialize_duration")]
    pub minimum_age: Duration,

    #[serde(default)]
    pub dry_run: bool,
}

fn default_coredump_directory() -> PathBuf {
    PathBuf::from("/var/lib/systemd/coredump")
}

fn default_idle_interval() -> Duration {
    Duration::from_secs(5 * 60)
}

fn default_minimum_age() -> Duration {
    Duration::from_secs(30)
}

fn deserialize_duration<'de, D: serde::Deserializer<'de>>(de: D) -> Result<Duration, D::Error> {
    let s = String::deserialize(de)?;
    humantime::parse_duration(&s).map_err(serde::de::Error::custom)
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let s = std::fs::read_to_string(path).map_err(|e| ConfigError::Io(path.to_path_buf(), e))?;
        Self::parse(&s).map_err(|e| ConfigError::Toml(path.to_path_buf(), e))
    }

    pub fn parse(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io(PathBuf, std::io::Error),
    Toml(PathBuf, toml::de::Error),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(p, e) => write!(f, "read {}: {}", p.display(), e),
            ConfigError::Toml(p, e) => write!(f, "parse {}: {}", p.display(), e),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_config() {
        let cfg = Config::parse(
            r#"
allow_process_name = ["myapp", "worker"]
allow_executable_path = ["/opt/foo/*"]
idle_interval = "1m"
minimum_age = "10s"
dry_run = true
"#,
        )
        .unwrap();
        assert_eq!(
            cfg.allow_process_name,
            vec!["myapp".to_string(), "worker".to_string()]
        );
        assert_eq!(cfg.allow_executable_path, vec!["/opt/foo/*".to_string()]);
        assert_eq!(cfg.idle_interval, Duration::from_secs(60));
        assert_eq!(cfg.minimum_age, Duration::from_secs(10));
        assert!(cfg.dry_run);
    }

    #[test]
    fn applies_defaults_when_empty() {
        let cfg = Config::parse("").unwrap();
        assert!(cfg.allow_process_name.is_empty());
        assert!(cfg.allow_executable_path.is_empty());
        assert_eq!(
            cfg.coredump_directory,
            PathBuf::from("/var/lib/systemd/coredump")
        );
        assert_eq!(cfg.idle_interval, Duration::from_secs(300));
        assert_eq!(cfg.minimum_age, Duration::from_secs(30));
        assert!(!cfg.dry_run);
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(Config::parse("nonsense_field = 1").is_err());
    }
}
