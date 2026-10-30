//! User preferences, stored as TOML. Missing or malformed config is never fatal: every field has a
//! sensible default, because a broken config file must not stop somebody from fixing their firewall.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// dark, light, 16color or mono.
    pub theme: String,
    /// Show the confirmation dialog before applying a change.
    pub confirm_before_apply: bool,
    /// Read per-rule packet counters (needs root).
    pub show_counters: bool,
    /// How often counters are refreshed.
    pub counters_refresh_secs: u64,
    /// auto, file or journal.
    pub log_source: String,
    /// Seconds to wait for confirmation before automatically reverting a risky change. 0 disables.
    pub reconcile_seconds: u64,
    /// Force ASCII box drawing.
    pub ascii_fallback: bool,
    /// Start in read-only mode even when root.
    pub readonly: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            theme: "dark".into(),
            confirm_before_apply: true,
            show_counters: true,
            counters_refresh_secs: 5,
            log_source: "auto".into(),
            reconcile_seconds: 60,
            ascii_fallback: false,
            readonly: false,
        }
    }
}

impl Config {
    pub fn default_path() -> Option<PathBuf> {
        directories::ProjectDirs::from("", "", "ufw-manager-tui")
            .map(|dirs| dirs.config_dir().join("config.toml"))
    }

    /// Loads the config, falling back to defaults for anything unreadable.
    pub fn load(explicit: Option<&Path>) -> Self {
        let path = match explicit {
            Some(path) => Some(path.to_path_buf()),
            None => Self::default_path(),
        };
        let Some(path) = path else {
            return Self::default();
        };
        let Ok(text) = std::fs::read_to_string(path) else {
            return Self::default();
        };
        toml::from_str(&text).unwrap_or_default()
    }

    pub fn save(&self, explicit: Option<&Path>) -> std::io::Result<()> {
        let path = match explicit {
            Some(path) => Some(path.to_path_buf()),
            None => Self::default_path(),
        };
        let Some(path) = path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = toml::to_string_pretty(self).unwrap_or_default();
        std::fs::write(path, text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_what_the_docs_promise() {
        let config = Config::default();
        assert_eq!(config.theme, "dark");
        assert!(config.confirm_before_apply);
        assert_eq!(config.reconcile_seconds, 60);
    }

    #[test]
    fn a_missing_file_yields_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::load(Some(&dir.path().join("nope.toml")));
        assert_eq!(config.theme, "dark");
    }

    #[test]
    fn a_corrupt_file_yields_defaults_instead_of_failing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "this is not toml {{{").unwrap();
        assert_eq!(Config::load(Some(&path)).theme, "dark");
    }

    #[test]
    fn partial_files_keep_defaults_for_missing_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "theme = \"mono\"\n").unwrap();
        let config = Config::load(Some(&path));
        assert_eq!(config.theme, "mono");
        assert_eq!(config.reconcile_seconds, 60);
    }

    #[test]
    fn round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("config.toml");
        let config = Config {
            theme: "light".into(),
            reconcile_seconds: 15,
            ..Default::default()
        };
        config.save(Some(&path)).unwrap();
        let loaded = Config::load(Some(&path));
        assert_eq!(loaded.theme, "light");
        assert_eq!(loaded.reconcile_seconds, 15);
    }
}
