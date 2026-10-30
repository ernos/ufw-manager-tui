//! User preferences, stored as TOML. Missing or malformed config is never fatal: every field has a
//! sensible default, because a broken config file must not stop somebody from fixing their firewall.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
/**
 * User preferences persisted as TOML.
 *
 * Every field has a default so a missing or malformed file never prevents the
 * application from starting. Unknown keys are rejected by serde, and absent
 * keys fall back to [`Config::default`].
 *
 * # Fields
 *
 * * `theme` (`String`) - `dark`, `light`, `16color` or `mono`.
 * * `confirm_before_apply` (`bool`) - Show the confirmation dialog before applying a change.
 * * `show_counters` (`bool`) - Read per-rule packet counters (needs root).
 * * `counters_refresh_secs` (`u64`) - How often counters are refreshed.
 * * `log_source` (`String`) - `auto`, `file` or `journal`.
 * * `reconcile_seconds` (`u64`) - Seconds to wait for confirmation before automatically reverting a risky change; `0` disables the watchdog.
 * * `ascii_fallback` (`bool`) - Force ASCII box drawing.
 * * `readonly` (`bool`) - Start in read-only mode even when root.
 */
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
    /**
     * Implements `Default::default` for [`Config`], producing the built-in
     * preferences used when no config file exists or it cannot be parsed.
     *
     * # Arguments
     *
     * This method takes no arguments.
     *
     * # Returns
     *
     * `Config` - A configuration with the dark theme, confirmations enabled,
     * counters shown every 5 seconds, the `auto` log source, a 60 second
     * reconcile window, and neither ASCII fallback nor read-only mode forced.
     */
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
    /**
     * Computes the default location of `config.toml` inside the platform's
     * per-user configuration directory.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `Option<PathBuf>` - The path `<config_dir>/ufw-manager-tui/config.toml`,
     * or `None` when the platform configuration directory cannot be determined.
     */
    pub fn default_path() -> Option<PathBuf> {
        directories::ProjectDirs::from("", "", "ufw-manager-tui")
            .map(|dirs| dirs.config_dir().join("config.toml"))
    }

    /**
     * Loads the config, falling back to defaults for anything unreadable.
     *
     * # Arguments
     *
     * * `explicit` (`Option<&Path>`) - An explicit config file path, typically
     *   from `--config`. When `None`, [`Config::default_path`] is used.
     *
     * # Returns
     *
     * `Config` - The parsed configuration. A missing path, an unreadable file,
     * or invalid TOML all yield [`Config::default`] instead of an error.
     *
     * # Notes
     *
     * Read and parse errors are deliberately ignored so a broken config file
     * never prevents the user from fixing their firewall.
     */
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

    /**
     * Writes the configuration to disk as pretty-printed TOML, creating parent
     * directories as needed.
     *
     * # Arguments
     *
     * * `self` (`&Config`) - The configuration being persisted; it is only read.
     * * `explicit` (`Option<&Path>`) - An explicit destination path. When
     *   `None`, [`Config::default_path`] is used.
     *
     * # Returns
     *
     * `std::io::Result<()>` - `Ok(())` once the file is written, or when no
     * destination path could be determined (nothing is written in that case).
     * Errors from creating directories or writing the file are propagated.
     *
     * # Notes
     *
     * A serialization failure is not reported; an empty string is written
     * instead, which later loads as defaults.
     */
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
    /**
     * Verifies that [`Config::default`] returns the documented defaults.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts on the default values.
     */
    fn defaults_are_what_the_docs_promise() {
        let config = Config::default();
        assert_eq!(config.theme, "dark");
        assert!(config.confirm_before_apply);
        assert_eq!(config.reconcile_seconds, 60);
    }

    #[test]
    /**
     * Verifies that loading a path that does not exist yields defaults.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts on the loaded theme.
     */
    fn a_missing_file_yields_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::load(Some(&dir.path().join("nope.toml")));
        assert_eq!(config.theme, "dark");
    }

    #[test]
    /**
     * Verifies that invalid TOML falls back to defaults instead of failing.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts on the loaded theme.
     */
    fn a_corrupt_file_yields_defaults_instead_of_failing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "this is not toml {{{").unwrap();
        assert_eq!(Config::load(Some(&path)).theme, "dark");
    }

    #[test]
    /**
     * Verifies that keys absent from a partial config file keep their defaults.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts on the loaded values.
     */
    fn partial_files_keep_defaults_for_missing_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "theme = \"mono\"\n").unwrap();
        let config = Config::load(Some(&path));
        assert_eq!(config.theme, "mono");
        assert_eq!(config.reconcile_seconds, 60);
    }

    #[test]
    /**
     * Verifies that a config saved to a nested path loads back unchanged.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts on the reloaded values.
     */
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
