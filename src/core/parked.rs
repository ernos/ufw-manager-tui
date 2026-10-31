//! Rules that have been commented out.
//!
//! `ufw` has no per-rule enable/disable: a rule is either in the ruleset or it is not. Commenting a
//! rule out therefore deletes it from `ufw` and keeps the whole rule — including the position it
//! occupied — in this store, so it can be put back with one keypress instead of being retyped.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::core::rule::{Action, Direction, Endpoint, LogMode, Protocol, Rule, RuleDraft};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/**
 * One rule that has been commented out.
 *
 * The rule is no longer in `ufw`'s ruleset, so it is stored in full: without these fields there
 * would be nothing left to put back. `position` is the rule number the rule had when it was
 * commented out, which is where it returns to when it is enabled again.
 *
 * # Fields
 *
 * * `position` (`u32`) - The `ufw` rule number the rule occupied when it was commented out.
 * * `action` (`Action`) - What would happen to matching traffic.
 * * `direction` (`Direction`) - Which way the traffic flows.
 * * `interface_in` (`Option<String>`) - The incoming interface, when the rule named one.
 * * `interface_out` (`Option<String>`) - The outgoing interface, when the rule named one.
 * * `protocol` (`Protocol`) - The protocol the rule applies to.
 * * `from` (`Endpoint`) - The source side of the rule.
 * * `to` (`Endpoint`) - The destination side of the rule.
 * * `log` (`LogMode`) - How much of the rule's traffic is logged.
 * * `comment` (`Option<String>`) - The user's note for the rule.
 */
pub struct ParkedRule {
    /// The `ufw` rule number the rule occupied when it was commented out.
    pub position: u32,
    pub action: Action,
    pub direction: Direction,
    pub interface_in: Option<String>,
    pub interface_out: Option<String>,
    pub protocol: Protocol,
    pub from: Endpoint,
    pub to: Endpoint,
    pub log: LogMode,
    pub comment: Option<String>,
}

impl ParkedRule {
    /**
     * Puts a live rule into storage, remembering the position it is giving up.
     *
     * # Arguments
     *
     * * `rule` (`&Rule`) - The rule that is about to be deleted from `ufw`.
     *
     * # Returns
     *
     * A `ParkedRule` holding every field needed to recreate the rule verbatim.
     */
    pub fn from_rule(rule: &Rule) -> Self {
        Self {
            position: rule.number,
            action: rule.action,
            direction: rule.direction,
            interface_in: rule.interface_in.clone(),
            interface_out: rule.interface_out.clone(),
            protocol: rule.protocol,
            from: rule.from.clone(),
            to: rule.to.clone(),
            log: rule.log,
            comment: rule.comment.clone(),
        }
    }

    /**
     * Converts the stored rule back into the draft the command builder works with.
     *
     * # Arguments
     *
     * * `&self` - The stored rule being converted.
     *
     * # Returns
     *
     * A `RuleDraft` carrying the rule's editable fields.
     */
    pub fn to_draft(&self) -> RuleDraft {
        RuleDraft {
            action: self.action,
            direction: self.direction,
            interface_in: self.interface_in.clone(),
            interface_out: self.interface_out.clone(),
            protocol: self.protocol,
            from_addr: self.from.addr.clone(),
            from_port: self.from.port.clone(),
            to_addr: self.to.addr.clone(),
            to_port: self.to.port.clone(),
            log: self.log,
            comment: self.comment.clone(),
        }
    }

    /**
     * Rebuilds the rule the way it would look once it is enabled again.
     *
     * The rule keeps its original number, so risk assessment, the explanations and the command
     * preview all describe the rule the user is looking at.
     *
     * # Arguments
     *
     * * `&self` - The stored rule being rebuilt.
     *
     * # Returns
     *
     * A `Rule` numbered with the stored position.
     */
    pub fn to_rule(&self) -> Rule {
        self.to_draft().to_rule(self.position)
    }

    /**
     * Builds the identity string used to match the stored rule against live rules.
     *
     * # Arguments
     *
     * * `&self` - The stored rule being described.
     *
     * # Returns
     *
     * A `String` identical to [`Rule::signature`] for the same rule.
     */
    pub fn signature(&self) -> String {
        self.to_rule().signature()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
/**
 * The on-disk JSON shape of the store.
 *
 * Kept separate from [`ParkedRules`] so the persisted format can stay stable while the in-memory
 * type evolves.
 *
 * # Fields
 *
 * * `entries` (`Vec<ParkedRule>`) - The commented-out rules, in the order they were commented out.
 */
struct ParkedFile {
    #[serde(default)]
    entries: Vec<ParkedRule>,
}

#[derive(Debug, Clone, Default)]
/**
 * The commented-out rules, in the order they were commented out.
 *
 * # Fields
 *
 * * `entries` (`Vec<ParkedRule>`) - The stored rules, oldest first.
 */
pub struct ParkedRules {
    entries: Vec<ParkedRule>,
}

impl ParkedRules {
    /**
     * Creates an empty store.
     *
     * # Arguments
     *
     * This method takes no arguments.
     *
     * # Returns
     *
     * A `ParkedRules` with no entries.
     */
    pub fn new() -> Self {
        Self::default()
    }

    /**
     * Returns the stored rules in the order they were commented out.
     *
     * # Arguments
     *
     * * `&self` - The store being read.
     *
     * # Returns
     *
     * A `&[ParkedRule]` slice borrowing the entries, oldest first.
     */
    pub fn entries(&self) -> &[ParkedRule] {
        &self.entries
    }

    /**
     * Returns the stored rule at an index.
     *
     * # Arguments
     *
     * * `&self` - The store being read.
     * * `index` (`usize`) - The zero-based index into the stored entries.
     *
     * # Returns
     *
     * An `Option<&ParkedRule>` containing the entry, or `None` when the index is out of range.
     */
    pub fn get(&self, index: usize) -> Option<&ParkedRule> {
        self.entries.get(index)
    }

    /**
     * Returns how many rules are commented out.
     *
     * # Arguments
     *
     * * `&self` - The store being read.
     *
     * # Returns
     *
     * A `usize` containing the number of stored rules.
     */
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /**
     * Returns whether nothing is commented out.
     *
     * # Arguments
     *
     * * `&self` - The store being read.
     *
     * # Returns
     *
     * `true` when the store holds no entries; otherwise, `false`.
     */
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /**
     * Stores a rule that has just been commented out.
     *
     * # Arguments
     *
     * * `&mut self` - The store being appended to.
     * * `rule` (`ParkedRule`) - The rule to remember.
     *
     * # Returns
     *
     * This method returns no value.
     */
    pub fn push(&mut self, rule: ParkedRule) {
        self.entries.push(rule);
    }

    /**
     * Forgets the stored rule matching a signature, keeping the list in order.
     *
     * Used when a commented-out rule has been put back into the ruleset, so the store never lists
     * a rule that `ufw` is enforcing again.
     *
     * # Arguments
     *
     * * `&mut self` - The store being mutated.
     * * `signature` (`&str`) - The [`Rule::signature`] of the rule that came back.
     *
     * # Returns
     *
     * `true` when an entry was removed; `false` when nothing matched.
     */
    pub fn forget_signature(&mut self, signature: &str) -> bool {
        match self
            .entries
            .iter()
            .position(|entry| entry.signature() == signature)
        {
            Some(index) => {
                self.entries.remove(index);
                true
            }
            None => false,
        }
    }

    /**
     * Removes the stored rule at an index.
     *
     * # Arguments
     *
     * * `&mut self` - The store being mutated.
     * * `index` (`usize`) - The zero-based index of the entry to drop.
     *
     * # Returns
     *
     * An `Option<ParkedRule>` containing the removed entry, or `None` when the index is out of
     * range.
     */
    pub fn remove_at(&mut self, index: usize) -> Option<ParkedRule> {
        if index < self.entries.len() {
            Some(self.entries.remove(index))
        } else {
            None
        }
    }

    /**
     * Serializes the store to pretty-printed JSON.
     *
     * # Arguments
     *
     * * `&self` - The store being serialized.
     *
     * # Returns
     *
     * A `String` containing the JSON document. Serialization cannot fail for this data, but if it
     * ever did the result would be `"{}"`.
     */
    pub fn to_json(&self) -> String {
        let file = ParkedFile {
            entries: self.entries.clone(),
        };
        serde_json::to_string_pretty(&file).unwrap_or_else(|_| "{}".to_string())
    }

    /**
     * Parses the store from JSON, falling back to an empty store.
     *
     * # Arguments
     *
     * * `text` (`&str`) - The JSON document to parse.
     *
     * # Returns
     *
     * A `ParkedRules` containing the parsed entries, or an empty store when the text is not valid
     * store JSON.
     */
    pub fn from_json(text: &str) -> Self {
        match serde_json::from_str::<ParkedFile>(text) {
            Ok(file) => Self {
                entries: file.entries,
            },
            Err(_) => Self::default(),
        }
    }

    /**
     * Writes the store to disk as JSON, creating parent directories.
     *
     * # Arguments
     *
     * * `&self` - The store being persisted.
     * * `path` (`&Path`) - The file to write.
     *
     * # Returns
     *
     * A `std::io::Result<()>` that is `Ok(())` on success and carries the I/O error when a
     * directory or the file cannot be written.
     */
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, self.to_json())
    }

    /**
     * Loads the store from disk, falling back to an empty store.
     *
     * # Arguments
     *
     * * `path` (`&Path`) - The file to read.
     *
     * # Returns
     *
     * A `ParkedRules` parsed from the file, or an empty store when the file is missing, unreadable
     * or corrupt.
     */
    pub fn load(path: &Path) -> Self {
        match fs::read_to_string(path) {
            Ok(text) => Self::from_json(&text),
            Err(_) => Self::default(),
        }
    }
}

/**
 * Returns the default on-disk location of the commented-out rules.
 *
 * The path is derived from the platform state directory (falling back to the data directory) for
 * the `ufw-manager-tui` project, next to the undo journal.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * An `Option<PathBuf>` containing the `disabled-rules.json` path, or `None` when the platform
 * directories cannot be determined.
 */
pub fn default_path() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "ufw-manager-tui").map(|dirs| {
        dirs.state_dir()
            .unwrap_or_else(|| dirs.data_dir())
            .join("disabled-rules.json")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::rule::PortSpec;

    /**
     * Builds a live rule for the tests to comment out.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * A rule allowing `22/tcp` from `192.168.1.0/24`, numbered 3.
     */
    fn ssh_rule() -> Rule {
        Rule {
            number: 3,
            action: Action::Allow,
            direction: Direction::In,
            interface_in: Some("eno1".into()),
            interface_out: None,
            protocol: Protocol::Tcp,
            from: Endpoint::from_addr("192.168.1.0/24"),
            to: Endpoint::port(22),
            log: LogMode::Log,
            comment: Some("Home network".into()),
            v6: false,
            route: false,
        }
    }

    #[test]
    /**
     * Checks that a commented-out rule rebuilds byte for byte, position included.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test on any lost field.
     */
    fn parking_a_rule_keeps_every_field_and_its_position() {
        let rule = ssh_rule();
        let parked = ParkedRule::from_rule(&rule);
        assert_eq!(parked.position, 3);
        assert_eq!(parked.signature(), rule.signature());
        assert_eq!(parked.to_rule().number, 3);
        assert_eq!(parked.to_rule().interface_in.as_deref(), Some("eno1"));
        assert_eq!(parked.to_rule().log, LogMode::Log);
        assert_eq!(parked.to_rule().comment.as_deref(), Some("Home network"));
        assert_eq!(parked.to_rule().to.port, PortSpec::single(22));
    }

    #[test]
    /**
     * Checks that the store survives a round trip through JSON.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test on a lost or corrupted entry.
     */
    fn the_store_round_trips_through_json() {
        let mut store = ParkedRules::new();
        store.push(ParkedRule::from_rule(&ssh_rule()));
        let restored = ParkedRules::from_json(&store.to_json());
        assert_eq!(restored.len(), 1);
        assert_eq!(restored.entries()[0], store.entries()[0]);
        assert!(ParkedRules::from_json("not json").is_empty());
    }

    #[test]
    /**
     * Checks that a rule that came back is forgotten and others are left alone.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test on a wrong match.
     */
    fn forgetting_removes_only_the_matching_entry() {
        let mut store = ParkedRules::new();
        let mut web = ParkedRule::from_rule(&ssh_rule());
        web.to.port = PortSpec::single(443);
        store.push(ParkedRule::from_rule(&ssh_rule()));
        store.push(web);
        assert!(store.forget_signature(&ssh_rule().signature()));
        assert_eq!(store.len(), 1);
        assert_eq!(store.entries()[0].to.port, PortSpec::single(443));
        assert!(!store.forget_signature(&ssh_rule().signature()));
    }

    #[test]
    /**
     * Checks that the store is written to disk and read back unchanged.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test when the round trip
     * loses an entry.
     */
    fn the_store_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disabled-rules.json");
        let mut store = ParkedRules::new();
        store.push(ParkedRule::from_rule(&ssh_rule()));
        store.save(&path).unwrap();

        let reloaded = ParkedRules::load(&path);
        assert_eq!(reloaded.len(), 1);
        assert_eq!(reloaded.entries()[0].position, 3);
        assert!(ParkedRules::load(&dir.path().join("missing.json")).is_empty());
    }
}
