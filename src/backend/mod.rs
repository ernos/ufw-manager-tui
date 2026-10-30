//! Everything that touches the operating system.
//!
//! The [`Backend`] trait exists so the whole application can be driven by a fake firewall: tests
//! use it, and `--demo` uses it so the UI can be shown, screenshotted and exercised without root
//! and without risk.

use std::path::PathBuf;

use crate::core::firewall::FirewallState;
use crate::core::lockout::Session;
use crate::core::parse::{AppProfile, Listening};
use crate::core::presets::LanInfo;

pub mod counters;
pub mod logs;
pub mod mock;
pub mod probe;
pub mod ufw;

pub use counters::HitCounters;
pub use logs::BlockRow;

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("ufw needs root: {0}")]
    NotRoot(String),
    #[error("ufw is not installed or not on the PATH")]
    NotFound,
    #[error("ufw did not respond within {seconds} seconds")]
    Timeout { seconds: u64 },
    #[error("`{command}` failed: {stderr}")]
    Failed { command: String, stderr: String },
    #[error("could not understand ufw's output: {0}")]
    Parse(String),
    #[error("{0}")]
    Io(String),
}

impl From<std::io::Error> for BackendError {
    fn from(error: std::io::Error) -> Self {
        BackendError::Io(error.to_string())
    }
}

/// The result of running one command, kept in full so errors can be shown verbatim.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CmdOutput {
    pub argv: Vec<String>,
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

impl CmdOutput {
    pub fn command(&self) -> String {
        crate::core::command::render_command(&self.argv)
    }

    /// ufw's own words, which are usually clearer than anything we could invent.
    pub fn message(&self) -> String {
        let text = if self.stderr.trim().is_empty() {
            &self.stdout
        } else {
            &self.stderr
        };
        text.trim().to_string()
    }
}

pub trait Backend: Send + Sync {
    /// Short human description, e.g. "ufw 0.36.2" or "demo mode".
    fn label(&self) -> String;

    fn is_root(&self) -> bool;

    /// Whether writes are possible. False in read-only and demo modes.
    fn can_write(&self) -> bool;

    fn read_state(&self) -> Result<FirewallState, BackendError>;

    fn app_profiles(&self) -> Result<Vec<AppProfile>, BackendError>;

    fn listening(&self) -> Result<Vec<Listening>, BackendError>;

    /// Per-rule packet counters. `rules` is required because counters are aligned by position.
    fn counters(&self, rules: &[crate::core::rule::Rule]) -> Result<HitCounters, BackendError>;

    /// Runs `ufw <args>` for real.
    fn run(&self, args: &[String]) -> Result<CmdOutput, BackendError>;

    /// Runs `ufw --dry-run <args>`: ufw validates without changing anything.
    fn dry_run(&self, args: &[String]) -> Result<CmdOutput, BackendError>;

    fn ssh_port(&self) -> u16;

    fn ssh_session(&self) -> Session;

    fn lan(&self) -> Option<LanInfo>;

    fn interfaces(&self) -> Vec<String>;

    /// Escape hatch for environments where `sudo` prompts must never appear.
    fn may_escalate(&self) -> bool {
        false
    }

    /// Best-effort privilege escalation. Returns true when writes are now possible.
    fn escalate(&self) -> bool {
        false
    }

    fn log_path(&self) -> Option<PathBuf> {
        None
    }
}

/// Shared implementation of the `--dry-run` prefix so every backend behaves the same way.
pub(crate) fn with_dry_run(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len() + 1);
    out.push("--dry-run".to_string());
    out.extend(args.iter().cloned());
    out
}

/// Detects "you are not root" from ufw's own message rather than guessing from the exit code.
pub(crate) fn looks_like_not_root(stderr: &str) -> bool {
    stderr.to_ascii_lowercase().contains("you need to be root")
}

/// Detects "ufw is not installed" from a spawn failure.
pub(crate) fn looks_like_missing(stderr: &str) -> bool {
    stderr.contains("No such file or directory") || stderr.contains("not found")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dry_run_prefix_goes_first() {
        let args = vec!["allow".to_string(), "22/tcp".to_string()];
        assert_eq!(with_dry_run(&args), vec!["--dry-run", "allow", "22/tcp"]);
    }

    #[test]
    fn recognises_ufws_root_complaint() {
        assert!(looks_like_not_root(
            "ERROR: You need to be root to run this script"
        ));
        assert!(!looks_like_not_root("ERROR: Bad port"));
    }
}
