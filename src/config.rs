//! User preferences, stored as TOML. Missing or malformed config is never fatal: every field has a
//! sensible default, because a broken config file must not stop somebody from fixing their firewall.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::core::rule::{Action, Direction, LogMode, Protocol, RuleDraft};

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
 * * `defaults` (`RuleDefaults`) - Defaults applied to newly created rules.
 * * `skip_wizard` (`bool`) - Start new rules on the advanced step instead of the guided wizard.
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
    /// Defaults applied to newly created rules.
    pub defaults: RuleDefaults,
    /// Start new rules on the advanced step instead of the guided wizard.
    pub skip_wizard: bool,
}

/**
 * Defaults applied to newly created rules.
 *
 * Values are stored as the same strings `ufw` uses so the TOML file stays
 * human-readable: `allow`, `deny`, `reject` or `limit` for the action; `in` or
 * `out` for the direction; `any`, `tcp`, `udp`, ... for the protocol; `off`,
 * `log` or `log-all` for logging. Addresses and the interface are free text,
 * with an empty value meaning "any".
 *
 * # Fields
 *
 * * `action` (`String`) - Default action for new rules.
 * * `direction` (`String`) - Default direction for new rules.
 * * `interface` (`String`) - Default incoming interface; empty means any.
 * * `protocol` (`String`) - Default protocol for new rules.
 * * `from_addr` (`String`) - Default source address or network; empty means any.
 * * `to_addr` (`String`) - Default destination address or network; empty means any.
 * * `logging` (`String`) - Default logging mode for new rules.
 */
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuleDefaults {
    /// Default action for new rules.
    pub action: String,
    /// Default direction for new rules.
    pub direction: String,
    /// Default incoming interface; empty means any.
    pub interface: String,
    /// Default protocol for new rules.
    pub protocol: String,
    /// Default source address or network; empty means any.
    pub from_addr: String,
    /// Default destination address or network; empty means any.
    pub to_addr: String,
    /// Default logging mode for new rules.
    pub logging: String,
}

impl Default for RuleDefaults {
    /**
     * Implements `Default` for [`RuleDefaults`], producing the same permissive
     * inbound allow rule the wizard used before settings existed.
     *
     * # Arguments
     *
     * This method takes no arguments.
     *
     * # Returns
     *
     * `RuleDefaults` - Allow inbound, any interface, any protocol, any address,
     * no logging.
     */
    fn default() -> Self {
        Self {
            action: "allow".into(),
            direction: "in".into(),
            interface: String::new(),
            protocol: "any".into(),
            from_addr: String::new(),
            to_addr: String::new(),
            logging: "off".into(),
        }
    }
}

impl RuleDefaults {
    /**
     * Converts the defaults into a [`RuleDraft`] the wizard can start from.
     *
     * Unknown or malformed values fall back to the safe defaults rather than
     * failing, so a hand-edited config file can never break rule creation.
     *
     * # Arguments
     *
     * * `self` (`&RuleDefaults`) - The defaults being converted; it is only read.
     *
     * # Returns
     *
     * `RuleDraft` - A draft carrying the configured defaults, with any
     * unrecognized value replaced by the built-in default.
     */
    pub fn to_draft(&self) -> RuleDraft {
        RuleDraft {
            action: Action::from_label(&self.action).unwrap_or(Action::Allow),
            direction: Direction::from_label(&self.direction).unwrap_or(Direction::In),
            interface_in: empty_to_none(&self.interface),
            protocol: self.protocol.parse().unwrap_or(Protocol::Any),
            from_addr: empty_to_none(&self.from_addr),
            from_port: Default::default(),
            to_addr: empty_to_none(&self.to_addr),
            to_port: Default::default(),
            log: match self.logging.as_str() {
                "log" => LogMode::Log,
                "log-all" => LogMode::LogAll,
                _ => LogMode::None,
            },
            comment: None,
        }
    }
}

/**
 * Turns an empty or whitespace-only string into `None`.
 *
 * # Arguments
 *
 * * `value` (`&str`) - The text to normalize.
 *
 * # Returns
 *
 * `Option<String>` - `None` when the value is empty or whitespace, otherwise
 * the trimmed value.
 */
fn empty_to_none(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
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
     * reconcile window, neither ASCII fallback nor read-only mode forced, the
     * built-in rule defaults, and the guided wizard enabled.
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
            defaults: RuleDefaults::default(),
            skip_wizard: false,
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

    #[test]
    /**
     * Verifies that the rule defaults and skip-wizard flag survive a save/load round trip.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts on the reloaded values.
     */
    fn rule_defaults_round_trip_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let config = Config {
            skip_wizard: true,
            defaults: RuleDefaults {
                action: "limit".into(),
                direction: "out".into(),
                interface: "wg0".into(),
                protocol: "tcp".into(),
                from_addr: "192.168.1.0/24".into(),
                to_addr: "10.0.0.0/8".into(),
                logging: "log-all".into(),
            },
            ..Default::default()
        };
        config.save(Some(&path)).unwrap();
        let loaded = Config::load(Some(&path));
        assert!(loaded.skip_wizard);
        assert_eq!(loaded.defaults.action, "limit");
        assert_eq!(loaded.defaults.direction, "out");
        assert_eq!(loaded.defaults.interface, "wg0");
        assert_eq!(loaded.defaults.protocol, "tcp");
        assert_eq!(loaded.defaults.from_addr, "192.168.1.0/24");
        assert_eq!(loaded.defaults.to_addr, "10.0.0.0/8");
        assert_eq!(loaded.defaults.logging, "log-all");
    }

    #[test]
    /**
     * Verifies that an old config file without the new keys keeps its defaults.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts on the loaded values.
     */
    fn old_config_files_keep_the_new_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "theme = \"mono\"\n").unwrap();
        let config = Config::load(Some(&path));
        assert_eq!(config.theme, "mono");
        assert!(!config.skip_wizard);
        assert_eq!(config.defaults.action, "allow");
        assert_eq!(config.defaults.logging, "off");
    }

    #[test]
    /**
     * Verifies that the defaults convert into the expected draft.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts on the draft fields.
     */
    fn defaults_convert_to_a_draft() {
        let defaults = RuleDefaults {
            action: "deny".into(),
            direction: "out".into(),
            interface: "eth0".into(),
            protocol: "udp".into(),
            from_addr: "10.0.0.0/8".into(),
            to_addr: String::new(),
            logging: "log".into(),
        };
        let draft = defaults.to_draft();
        assert_eq!(draft.action, crate::core::rule::Action::Deny);
        assert_eq!(draft.direction, crate::core::rule::Direction::Out);
        assert_eq!(draft.interface_in.as_deref(), Some("eth0"));
        assert_eq!(draft.protocol, crate::core::rule::Protocol::Udp);
        assert_eq!(draft.from_addr.as_deref(), Some("10.0.0.0/8"));
        assert_eq!(draft.to_addr, None);
        assert_eq!(draft.log, crate::core::rule::LogMode::Log);
    }

    #[test]
    /**
     * Verifies that unknown values in a hand-edited config fall back to safe defaults.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts on the draft fields.
     */
    fn unknown_default_values_fall_back_to_safe_defaults() {
        let defaults = RuleDefaults {
            action: "explode".into(),
            direction: "sideways".into(),
            interface: "  ".into(),
            protocol: "quantum".into(),
            from_addr: "  ".into(),
            to_addr: "203.0.113.9".into(),
            logging: "loud".into(),
        };
        let draft = defaults.to_draft();
        assert_eq!(draft.action, crate::core::rule::Action::Allow);
        assert_eq!(draft.direction, crate::core::rule::Direction::In);
        assert_eq!(draft.interface_in, None);
        assert_eq!(draft.protocol, crate::core::rule::Protocol::Any);
        assert_eq!(draft.from_addr, None);
        assert_eq!(draft.to_addr.as_deref(), Some("203.0.113.9"));
        assert_eq!(draft.log, crate::core::rule::LogMode::None);
    }
}
