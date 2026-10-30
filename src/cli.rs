//! Command line interface.

use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Clone, Parser)]
#[command(
    name = "ufw-manager-tui",
    version,
    about = "A friendly terminal UI for ufw that will not lock you out",
    long_about = "Manage ufw firewall rules from a full-screen terminal interface.\n\n\
                  Every change is shown as the exact `ufw` command first, validated with\n\
                  `ufw --dry-run`, and recorded so it can be undone. \n\n\
                  Running without root starts in read-only mode; press X to escalate.\n\n\
                  Run `ufw-manager-tui --demo` to explore the interface with a fake firewall."
)]
pub struct Cli {
    /// Run against a fake firewall. Nothing on the system is read or changed.
    #[arg(long)]
    pub demo: bool,

    /// Look but do not touch: never run a command that changes the firewall.
    #[arg(long)]
    pub readonly: bool,

    /// Never invoke sudo to escalate privileges.
    #[arg(long = "no-escalate")]
    pub no_escalate: bool,

    /// Skip the confirmation dialog for each change (the dry run still happens).
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// Use text risk badges instead of colours.
    #[arg(long = "no-color")]
    pub no_color: bool,

    /// Force ASCII box drawing.
    #[arg(long)]
    pub ascii: bool,

    /// Theme: dark, light, 16color or mono.
    #[arg(long)]
    pub theme: Option<String>,

    /// Path to config.toml (defaults to the XDG config directory).
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Write a debug trace to this file.
    #[arg(long = "debug-log")]
    pub debug_log: Option<PathBuf>,

    /// Print the parsed firewall state as JSON and exit. Useful for bug reports.
    #[arg(long = "dump-state")]
    pub dump_state: bool,

    /// Override the ufw executable (used by the test suite).
    #[arg(long, hide = true)]
    pub ufw: Option<String>,

    /// Internal: undo everything in the `--nonce` state file after N seconds unless it is cancelled.
    #[arg(long = "internal-revert-after", hide = true)]
    pub internal_revert_after: Option<u64>,

    /// Internal: watchdog state file, written by the UI before a risky change.
    #[arg(long, hide = true)]
    pub nonce: Option<PathBuf>,
}

impl Cli {
    /// True when the process should act as the detached revert watchdog instead of a UI.
    pub fn is_watchdog(&self) -> bool {
        self.internal_revert_after.is_some() && self.nonce.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_interactive() {
        let cli = Cli::parse_from(["ufw-manager-tui"]);
        assert!(!cli.demo);
        assert!(!cli.readonly);
        assert!(!cli.is_watchdog());
    }

    #[test]
    fn demo_and_readonly_combine() {
        let cli = Cli::parse_from(["ufw-manager-tui", "--demo", "--readonly", "--no-color", "-y"]);
        assert!(cli.demo && cli.readonly && cli.no_color && cli.yes);
    }

    #[test]
    fn the_watchdog_mode_is_only_entered_with_both_arguments() {
        let cli = Cli::parse_from(["ufw-manager-tui", "--internal-revert-after", "60"]);
        assert!(!cli.is_watchdog());
        let cli = Cli::parse_from([
            "ufw-manager-tui",
            "--internal-revert-after",
            "60",
            "--nonce",
            "/tmp/x",
        ]);
        assert!(cli.is_watchdog());
    }
}
