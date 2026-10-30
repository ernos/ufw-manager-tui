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
pub struct UndoEntry {
    pub id: u64,
    /// UTC `HH:MM:SS` of when the change was applied.
    pub at: String,
    pub description: String,
    pub forward: Vec<Vec<String>>,
    pub inverse: Vec<Vec<String>>,
}

impl UndoEntry {
    pub fn can_undo(&self) -> bool {
        !self.inverse.is_empty()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct JournalFile {
    #[serde(default)]
    entries: Vec<UndoEntry>,
    #[serde(default)]
    next_id: u64,
}

/// Newest entry last, so `pop` is undo.
#[derive(Debug, Clone, Default)]
pub struct Journal {
    entries: Vec<UndoEntry>,
    next_id: u64,
}

impl Journal {
    pub fn new() -> Self {
        Self::default()
    }

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

    pub fn entries(&self) -> &[UndoEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn last(&self) -> Option<&UndoEntry> {
        self.entries.last()
    }

    /// Removes and returns the newest entry, which is the one undo applies.
    pub fn take_last(&mut self) -> Option<UndoEntry> {
        self.entries.pop()
    }

    /// Newest first, for display.
    pub fn recent(&self, limit: usize) -> Vec<&UndoEntry> {
        self.entries.iter().rev().take(limit).collect()
    }

    pub fn to_json(&self) -> String {
        let file = JournalFile {
            entries: self.entries.clone(),
            next_id: self.next_id,
        };
        serde_json::to_string_pretty(&file).unwrap_or_else(|_| "{}".to_string())
    }

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

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, self.to_json())
    }

    pub fn load(path: &Path) -> Self {
        match fs::read_to_string(path) {
            Ok(text) => Self::from_json(&text),
            Err(_) => Self::default(),
        }
    }
}

/// Where the journal lives when it is persisted.
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

    fn change(description: &str) -> Change {
        Change {
            description: description.to_string(),
            steps: vec![vec!["allow".into(), "22/tcp".into()]],
            inverse: vec![vec!["delete".into(), "allow".into(), "22/tcp".into()]],
        }
    }

    #[test]
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
    fn survives_a_json_round_trip() {
        let mut journal = Journal::new();
        journal.record(&change("only"));
        let restored = Journal::from_json(&journal.to_json());
        assert_eq!(restored.len(), 1);
        assert_eq!(restored.entries()[0].forward, journal.entries()[0].forward);
        assert_eq!(restored.entries()[0].inverse, journal.entries()[0].inverse);
    }

    #[test]
    fn a_corrupt_journal_file_starts_empty_instead_of_failing() {
        assert!(Journal::from_json("not json").is_empty());
    }

    #[test]
    fn ids_continue_after_a_reload() {
        let mut journal = Journal::new();
        journal.record(&change("a"));
        journal.record(&change("b"));
        let mut restored = Journal::from_json(&journal.to_json());
        assert_eq!(restored.record(&change("c")), 3);
    }

    #[test]
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
    fn a_missing_file_loads_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Journal::load(&dir.path().join("nope.json")).is_empty());
    }

    #[test]
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
