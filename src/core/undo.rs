//! The undo journal.
//!
//! Every applied change records its forward steps and their inverse. Undo replays the inverse
//! through the same validate → confirm pipeline, and nothing ever rewrites `/etc/ufw/user.rules`
//! directly — that is what corrupts rule sets.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::core::command::Change;
use crate::core::util;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/**
 * One applied change, with the steps needed to replay or revert it.
 *
 * # Fields
 *
 * * `id` (`u64`) - The journal-assigned identifier, increasing over time.
 * * `at` (`String`) - UTC `HH:MM:SS` of when the change was applied.
 * * `description` (`String`) - The human-readable summary of the change.
 * * `forward` (`Vec<Vec<String>>`) - The commands that applied the change.
 * * `inverse` (`Vec<Vec<String>>`) - The commands that revert it.
 */
pub struct UndoEntry {
    pub id: u64,
    /// UTC `HH:MM:SS` of when the change was applied.
    pub at: String,
    pub description: String,
    pub forward: Vec<Vec<String>>,
    pub inverse: Vec<Vec<String>>,
}

impl UndoEntry {
    /**
     * Returns whether this journal entry can be reverted.
     *
     * An entry is undoable only when it recorded at least one inverse step;
     * entries such as a firewall reset have nothing to replay.
     *
     * # Arguments
     *
     * * `&self` - The entry being inspected.
     *
     * # Returns
     *
     * `true` when the entry has a non-empty inverse step list; otherwise,
     * `false`.
     */
    pub fn can_undo(&self) -> bool {
        !self.inverse.is_empty()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
/**
 * The on-disk JSON shape of a journal.
 *
 * Kept separate from [`Journal`] so the persisted format can stay stable while
 * the in-memory type evolves.
 *
 * # Fields
 *
 * * `entries` (`Vec<UndoEntry>`) - The recorded entries, oldest first.
 * * `next_id` (`u64`) - The last id handed out, used to continue numbering.
 */
struct JournalFile {
    #[serde(default)]
    entries: Vec<UndoEntry>,
    #[serde(default)]
    next_id: u64,
}

#[derive(Debug, Clone, Default)]
/**
 * The in-memory undo journal.
 *
 * Entries are stored newest last, so popping the vector is exactly what undo
 * needs.
 *
 * # Fields
 *
 * * `entries` (`Vec<UndoEntry>`) - The recorded entries, oldest first.
 * * `next_id` (`u64`) - The last id handed out, used to continue numbering.
 */
pub struct Journal {
    entries: Vec<UndoEntry>,
    next_id: u64,
}

impl Journal {
    /**
     * Creates an empty journal.
     *
     * # Arguments
     *
     * This method takes no arguments.
     *
     * # Returns
     *
     * A `Journal` with no entries and a next id of zero.
     */
    pub fn new() -> Self {
        Self::default()
    }

    /**
     * Appends a new entry for an applied change and returns its id.
     *
     * The entry captures the change description, its forward steps and its
     * inverse steps, and is stamped with the current UTC time. The journal's
     * id counter is incremented, so ids are unique and increasing.
     *
     * # Arguments
     *
     * * `&mut self` - The journal being appended to.
     * * `change` (`&Change`) - The applied change to record.
     *
     * # Returns
     *
     * A `u64` containing the id assigned to the new entry.
     */
    pub fn record(&mut self, change: &Change) -> u64 {
        self.next_id += 1;
        let entry = UndoEntry {
            id: self.next_id,
            at: util::utc_hms(),
            description: change.description.clone(),
            forward: change.steps.clone(),
            inverse: change.inverse.clone(),
        };
        self.entries.push(entry);
        self.next_id
    }

    /**
     * Returns all journal entries in application order.
     *
     * # Arguments
     *
     * * `&self` - The journal being read.
     *
     * # Returns
     *
     * A `&[UndoEntry]` slice borrowing the entries, oldest first.
     */
    pub fn entries(&self) -> &[UndoEntry] {
        &self.entries
    }

    /**
     * Returns how many entries the journal holds.
     *
     * # Arguments
     *
     * * `&self` - The journal being read.
     *
     * # Returns
     *
     * A `usize` containing the number of recorded entries.
     */
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /**
     * Returns whether the journal holds no entries.
     *
     * # Arguments
     *
     * * `&self` - The journal being read.
     *
     * # Returns
     *
     * `true` when there is nothing to undo; otherwise, `false`.
     */
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /**
     * Returns the newest entry without removing it.
     *
     * # Arguments
     *
     * * `&self` - The journal being read.
     *
     * # Returns
     *
     * An `Option<&UndoEntry>` containing the most recently recorded entry, or
     * `None` when the journal is empty.
     */
    pub fn last(&self) -> Option<&UndoEntry> {
        self.entries.last()
    }

    /**
     * Removes and returns the newest entry, which is the one undo applies.
     *
     * # Arguments
     *
     * * `&mut self` - The journal being mutated; the newest entry is popped.
     *
     * # Returns
     *
     * An `Option<UndoEntry>` containing the removed entry, or `None` when the
     * journal is empty.
     */
    pub fn take_last(&mut self) -> Option<UndoEntry> {
        self.entries.pop()
    }

    /**
     * Returns up to `limit` entries, newest first, for display.
     *
     * # Arguments
     *
     * * `&self` - The journal being read.
     * * `limit` (`usize`) - The maximum number of entries to return.
     *
     * # Returns
     *
     * A `Vec<&UndoEntry>` of borrowed entries in reverse chronological order.
     */
    pub fn recent(&self, limit: usize) -> Vec<&UndoEntry> {
        self.entries.iter().rev().take(limit).collect()
    }

    /**
     * Serializes the journal to pretty-printed JSON.
     *
     * # Arguments
     *
     * * `&self` - The journal being serialized.
     *
     * # Returns
     *
     * A `String` containing the JSON document. Serialization cannot fail for
     * this data, but if it ever did the result would be `"{}"`.
     */
    pub fn to_json(&self) -> String {
        let file = JournalFile {
            entries: self.entries.clone(),
            next_id: self.next_id,
        };
        serde_json::to_string_pretty(&file).unwrap_or_else(|_| "{}".to_string())
    }

    /**
     * Parses a journal from JSON, falling back to an empty journal.
     *
     * The next id is raised to at least the highest entry id so that ids keep
     * increasing after a reload.
     *
     * # Arguments
     *
     * * `text` (`&str`) - The JSON document to parse.
     *
     * # Returns
     *
     * A `Journal` containing the parsed entries, or an empty `Journal` when
     * the text is not valid journal JSON.
     */
    pub fn from_json(text: &str) -> Self {
        match serde_json::from_str::<JournalFile>(text) {
            Ok(file) => {
                let next_id = file
                    .next_id
                    .max(file.entries.iter().map(|e| e.id).max().unwrap_or(0));
                Self {
                    entries: file.entries,
                    next_id,
                }
            }
            Err(_) => Self::default(),
        }
    }

    /**
     * Writes the journal to disk as JSON, creating parent directories.
     *
     * # Arguments
     *
     * * `&self` - The journal being persisted.
     * * `path` (`&Path`) - The file to write.
     *
     * # Returns
     *
     * A `std::io::Result<()>` that is `Ok(())` on success and carries the I/O
     * error when a directory or the file cannot be written.
     */
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, self.to_json())
    }

    /**
     * Loads a journal from disk, falling back to an empty journal.
     *
     * # Arguments
     *
     * * `path` (`&Path`) - The file to read.
     *
     * # Returns
     *
     * A `Journal` parsed from the file, or an empty `Journal` when the file is
     * missing, unreadable or corrupt.
     */
    pub fn load(path: &Path) -> Self {
        match fs::read_to_string(path) {
            Ok(text) => Self::from_json(&text),
            Err(_) => Self::default(),
        }
    }
}

/**
 * Returns the default on-disk location of the journal.
 *
 * The path is derived from the platform state directory (falling back to the
 * data directory) for the `ufw-manager-tui` project.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * An `Option<PathBuf>` containing the `journal.json` path, or `None` when the
 * platform directories cannot be determined.
 */
pub fn default_path() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "ufw-manager-tui").map(|dirs| {
        dirs.state_dir()
            .unwrap_or_else(|| dirs.data_dir())
            .join("journal.json")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /**
     * Builds a sample change with a forward and an inverse step.
     *
     * # Arguments
     *
     * * `description` (`&str`) - The description to attach to the change.
     *
     * # Returns
     *
     * A `Change` that allows `22/tcp` and whose inverse deletes that rule.
     */
    fn change(description: &str) -> Change {
        Change {
            description: description.to_string(),
            steps: vec![vec!["allow".into(), "22/tcp".into()]],
            inverse: vec![vec!["delete".into(), "allow".into(), "22/tcp".into()]],
        }
    }

    #[test]
    /**
     * Verifies that entries are recorded in order and popped newest first.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn records_and_pops_in_order() {
        let mut journal = Journal::new();
        journal.record(&change("first"));
        journal.record(&change("second"));
        assert_eq!(journal.len(), 2);
        assert_eq!(journal.last().unwrap().description, "second");
        assert_eq!(journal.take_last().unwrap().description, "second");
        assert_eq!(journal.take_last().unwrap().description, "first");
        assert!(journal.take_last().is_none());
    }

    #[test]
    /**
     * Verifies that `recent` returns entries newest first.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn recent_is_newest_first() {
        let mut journal = Journal::new();
        journal.record(&change("a"));
        journal.record(&change("b"));
        let recent: Vec<&str> = journal
            .recent(2)
            .iter()
            .map(|e| e.description.as_str())
            .collect();
        assert_eq!(recent, vec!["b", "a"]);
    }

    #[test]
    /**
     * Verifies that a journal survives serialization and parsing unchanged.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn survives_a_json_round_trip() {
        let mut journal = Journal::new();
        journal.record(&change("only"));
        let restored = Journal::from_json(&journal.to_json());
        assert_eq!(restored.len(), 1);
        assert_eq!(restored.entries()[0].forward, journal.entries()[0].forward);
        assert_eq!(restored.entries()[0].inverse, journal.entries()[0].inverse);
    }

    #[test]
    /**
     * Verifies that invalid JSON yields an empty journal instead of an error.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn a_corrupt_journal_file_starts_empty_instead_of_failing() {
        assert!(Journal::from_json("not json").is_empty());
    }

    #[test]
    /**
     * Verifies that new ids continue after the highest id in a reloaded file.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn ids_continue_after_a_reload() {
        let mut journal = Journal::new();
        journal.record(&change("a"));
        journal.record(&change("b"));
        let mut restored = Journal::from_json(&journal.to_json());
        assert_eq!(restored.record(&change("c")), 3);
    }

    #[test]
    /**
     * Verifies that a journal round-trips through the filesystem.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn saves_and_loads_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("journal.json");
        let mut journal = Journal::new();
        journal.record(&change("persisted"));
        journal.save(&path).unwrap();
        let loaded = Journal::load(&path);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.entries()[0].description, "persisted");
    }

    #[test]
    /**
     * Verifies that a missing journal file loads as an empty journal.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn a_missing_file_loads_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Journal::load(&dir.path().join("nope.json")).is_empty());
    }

    #[test]
    /**
     * Verifies that an entry with no inverse steps reports itself as not undoable.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn entries_without_an_inverse_cannot_be_undone() {
        let entry = UndoEntry {
            id: 1,
            at: "00:00:00".into(),
            description: "reset".into(),
            forward: vec![vec!["reset".into()]],
            inverse: Vec::new(),
        };
        assert!(!entry.can_undo());
    }
}
