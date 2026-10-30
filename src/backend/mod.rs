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

/**
 * Everything that can go wrong while talking to the firewall.
 *
 * Variants carry ufw's own wording where possible, so the UI can show the real
 * message instead of a paraphrase.
 *
 * # Variants
 *
 * * `NotRoot` - ufw refused because the process is not root; carries its message.
 * * `NotFound` - ufw is not installed or not on the `PATH`.
 * * `Timeout` - ufw did not respond within the given number of seconds.
 * * `Failed` - A command exited non-zero; carries the command and its stderr.
 * * `Parse` - ufw's output could not be understood.
 * * `Io` - Any other I/O failure, as text.
 */
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
    /**
     * Converts an I/O error into a [`BackendError::Io`].
     *
     * # Arguments
     *
     * * `error` (`std::io::Error`) - The I/O error being converted.
     *
     * # Returns
     *
     * `BackendError` - The `Io` variant carrying the error's display text.
     */
    fn from(error: std::io::Error) -> Self {
        BackendError::Io(error.to_string())
    }
}

/**
 * The result of running one command, kept in full so errors can be shown
 * verbatim.
 *
 * Both streams are retained rather than collapsed into a message, because the
 * UI shows ufw's own wording and the exact command that produced it.
 *
 * # Fields
 *
 * * `argv` (`Vec<String>`) - The argument vector that was run, without the
 *   program name.
 * * `success` (`bool`) - Whether the command exited successfully.
 * * `stdout` (`String`) - Captured standard output.
 * * `stderr` (`String`) - Captured standard error.
 */
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CmdOutput {
    pub argv: Vec<String>,
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

impl CmdOutput {
    /**
     * Renders the recorded argument vector as a copy-pasteable shell command.
     *
     * # Arguments
     *
     * * `self` (`&CmdOutput`) - The captured output being read; it is not
     *   modified.
     *
     * # Returns
     *
     * `String` - The command line, quoted by
     * [`crate::core::command::render_command`].
     */
    pub fn command(&self) -> String {
        crate::core::command::render_command(&self.argv)
    }

    /**
     * ufw's own words, which are usually clearer than anything we could invent.
     *
     * Prefers stderr when it has content and falls back to stdout, trimmed of
     * surrounding whitespace.
     *
     * # Arguments
     *
     * * `self` (`&CmdOutput`) - The captured output being read; it is not
     *   modified.
     *
     * # Returns
     *
     * `String` - The trimmed stderr, or the trimmed stdout when stderr is empty.
     */
    pub fn message(&self) -> String {
        let text = if self.stderr.trim().is_empty() {
            &self.stdout
        } else {
            &self.stderr
        };
        text.trim().to_string()
    }
}

/**
 * The contract every firewall backend implements.
 *
 * The real implementation shells out to `ufw`; the mock one keeps everything in
 * memory. All methods are required except [`Backend::may_escalate`],
 * [`Backend::escalate`] and [`Backend::log_path`], which have safe defaults for
 * backends that cannot escalate or read a log file.
 */
pub trait Backend: Send + Sync {
    /**
     * Short human description, e.g. "ufw 0.36.2" or "demo mode".
     *
     * # Arguments
     *
     * * `self` (`&Self`) - The backend being queried; it is not modified.
     *
     * # Returns
     *
     * `String` - A one-line label shown in the UI header.
     */
    fn label(&self) -> String;

    /**
     * Reports whether the process is running with root privileges.
     *
     * # Arguments
     *
     * * `self` (`&Self`) - The backend being queried; it is not modified.
     *
     * # Returns
     *
     * `bool` - `true` when ufw commands can be run without escalation.
     */
    fn is_root(&self) -> bool;

    /**
     * Whether writes are possible. False in read-only and demo modes.
     *
     * # Arguments
     *
     * * `self` (`&Self`) - The backend being queried; it is not modified.
     *
     * # Returns
     *
     * `bool` - `true` when the backend may change the firewall.
     */
    fn can_write(&self) -> bool;

    /**
     * Reads the current firewall state.
     *
     * # Arguments
     *
     * * `self` (`&Self`) - The backend being read; it is not modified.
     *
     * # Returns
     *
     * `Result<FirewallState, BackendError>` - The parsed rules and header, or an
     * error when the state cannot be read.
     */
    fn read_state(&self) -> Result<FirewallState, BackendError>;

    /**
     * Lists the application profiles ufw knows about.
     *
     * # Arguments
     *
     * * `self` (`&Self`) - The backend being read; it is not modified.
     *
     * # Returns
     *
     * `Result<Vec<AppProfile>, BackendError>` - The available profiles, or an
     * error when they cannot be read.
     */
    fn app_profiles(&self) -> Result<Vec<AppProfile>, BackendError>;

    /**
     * Lists the sockets currently listening on this machine.
     *
     * # Arguments
     *
     * * `self` (`&Self`) - The backend being read; it is not modified.
     *
     * # Returns
     *
     * `Result<Vec<Listening>, BackendError>` - The listening sockets, or an error
     * when they cannot be read.
     */
    fn listening(&self) -> Result<Vec<Listening>, BackendError>;

    /**
     * Per-rule packet counters. `rules` is required because counters are aligned
     * by position.
     *
     * # Arguments
     *
     * * `self` (`&Self`) - The backend being queried; it is not modified.
     * * `rules` (`&[crate::core::rule::Rule]`) - The rules to align counters
     *   against, in ufw order.
     *
     * # Returns
     *
     * `Result<HitCounters, BackendError>` - The counters, possibly marked
     * unreliable, or an error when they cannot be read at all.
     */
    fn counters(&self, rules: &[crate::core::rule::Rule]) -> Result<HitCounters, BackendError>;

    /**
     * Runs `ufw <args>` for real.
     *
     * # Arguments
     *
     * * `self` (`&Self`) - The backend being invoked; it is not modified.
     * * `args` (`&[String]`) - Arguments passed to ufw.
     *
     * # Returns
     *
     * `Result<CmdOutput, BackendError>` - The captured output, or an error when
     * the command could not be run.
     */
    fn run(&self, args: &[String]) -> Result<CmdOutput, BackendError>;

    /**
     * Runs `ufw --dry-run <args>`: ufw validates without changing anything.
     *
     * # Arguments
     *
     * * `self` (`&Self`) - The backend being invoked; it is not modified.
     * * `args` (`&[String]`) - Arguments passed to ufw after the flag.
     *
     * # Returns
     *
     * `Result<CmdOutput, BackendError>` - The captured output, or an error when
     * the command could not be run.
     */
    fn dry_run(&self, args: &[String]) -> Result<CmdOutput, BackendError>;

    /**
     * Returns the SSH port detected for this machine.
     *
     * # Arguments
     *
     * * `self` (`&Self`) - The backend being queried; it is not modified.
     *
     * # Returns
     *
     * `u16` - The port sshd is expected to listen on.
     */
    fn ssh_port(&self) -> u16;

    /**
     * Returns the SSH session the UI is running inside, if any.
     *
     * # Arguments
     *
     * * `self` (`&Self`) - The backend being queried; it is not modified.
     *
     * # Returns
     *
     * `Session` - The detected session, or a local session when not over SSH.
     */
    fn ssh_session(&self) -> Session;

    /**
     * Returns the local network detected for this machine.
     *
     * # Arguments
     *
     * * `self` (`&Self`) - The backend being queried; it is not modified.
     *
     * # Returns
     *
     * `Option<LanInfo>` - The interface and subnet, or `None` when detection
     * failed.
     */
    fn lan(&self) -> Option<LanInfo>;

    /**
     * Lists the network interface names available for rule editing.
     *
     * # Arguments
     *
     * * `self` (`&Self`) - The backend being queried; it is not modified.
     *
     * # Returns
     *
     * `Vec<String>` - Interface names, excluding loopback.
     */
    fn interfaces(&self) -> Vec<String>;

    /**
     * Escape hatch for environments where `sudo` prompts must never appear.
     *
     * # Arguments
     *
     * * `self` (`&Self`) - The backend being queried; it is not modified.
     *
     * # Returns
     *
     * `bool` - `true` when the backend may ask for privileges.
     *
     * # Notes
     *
     * This is a trait default implementation returning `false`; backends that
     * can escalate override it.
     */
    fn may_escalate(&self) -> bool {
        false
    }

    /**
     * Best-effort privilege escalation. Returns true when writes are now possible.
     *
     * # Arguments
     *
     * * `self` (`&Self`) - The backend being asked to escalate; implementations
     *   may record that privileges were obtained.
     *
     * # Returns
     *
     * `bool` - `true` when writes are now possible, `false` when escalation was
     * declined or failed.
     *
     * # Notes
     *
     * This is a trait default implementation returning `false`; backends that
     * can escalate override it.
     */
    fn escalate(&self) -> bool {
        false
    }

    /**
     * Returns the ufw log file to tail, when one is readable.
     *
     * # Arguments
     *
     * * `self` (`&Self`) - The backend being queried; it is not modified.
     *
     * # Returns
     *
     * `Option<PathBuf>` - The log path, or `None` to fall back to the journal.
     *
     * # Notes
     *
     * This is a trait default implementation returning `None`; backends that can
     * read a log file override it.
     */
    fn log_path(&self) -> Option<PathBuf> {
        None
    }
}

/**
 * Shared implementation of the `--dry-run` prefix so every backend behaves the
 * same way.
 *
 * # Arguments
 *
 * * `args` (`&[String]`) - The ufw arguments to prefix.
 *
 * # Returns
 *
 * `Vec<String>` - A new vector with `--dry-run` first, followed by `args` in
 * order.
 */
pub(crate) fn with_dry_run(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len() + 1);
    out.push("--dry-run".to_string());
    out.extend(args.iter().cloned());
    out
}

/**
 * Detects "you are not root" from ufw's own message rather than guessing from
 * the exit code.
 *
 * # Arguments
 *
 * * `stderr` (`&str`) - The captured stderr from a failed ufw invocation.
 *
 * # Returns
 *
 * `bool` - `true` when the text contains ufw's "you need to be root" complaint,
 * compared case-insensitively.
 */
pub(crate) fn looks_like_not_root(stderr: &str) -> bool {
    stderr.to_ascii_lowercase().contains("you need to be root")
}

/**
 * Detects "ufw is not installed" from a spawn failure.
 *
 * # Arguments
 *
 * * `stderr` (`&str`) - The captured stderr from a failed ufw invocation.
 *
 * # Returns
 *
 * `bool` - `true` when the text contains "No such file or directory" or "not
 * found".
 */
pub(crate) fn looks_like_missing(stderr: &str) -> bool {
    stderr.contains("No such file or directory") || stderr.contains("not found")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /**
     * Verifies that [`with_dry_run`] puts the flag before the original arguments.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
    fn dry_run_prefix_goes_first() {
        let args = vec!["allow".to_string(), "22/tcp".to_string()];
        assert_eq!(with_dry_run(&args), vec!["--dry-run", "allow", "22/tcp"]);
    }

    #[test]
    /**
     * Verifies that ufw's root complaint is recognised and other errors are not.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
    fn recognises_ufws_root_complaint() {
        assert!(looks_like_not_root(
            "ERROR: You need to be root to run this script"
        ));
        assert!(!looks_like_not_root("ERROR: Bad port"));
    }
}
