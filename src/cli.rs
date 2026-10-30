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
/**
 * Parsed command-line options for the application.
 *
 * Built by `clap` from the process arguments. The flags select the backend
 * (demo or real `ufw`), the theme and colour behaviour, read-only and
 * confirmation policy, and the internal watchdog mode used by the detached
 * revert helper.
 *
 * # Fields
 *
 * * `demo` (`bool`) - Run against a fake firewall; nothing on the system is read or changed.
 * * `readonly` (`bool`) - Look but do not touch: never run a command that changes the firewall.
 * * `no_escalate` (`bool`) - Never invoke sudo to escalate privileges.
 * * `yes` (`bool`) - Skip the confirmation dialog for each change; the dry run still happens.
 * * `no_color` (`bool`) - Use text risk badges instead of colours.
 * * `ascii` (`bool`) - Force ASCII box drawing.
 * * `theme` (`Option<String>`) - Theme override: `dark`, `light`, `16color` or `mono`.
 * * `config` (`Option<PathBuf>`) - Explicit configuration file path; defaults to the XDG config directory.
 * * `debug_log` (`Option<PathBuf>`) - File to write a debug trace to.
 * * `dump_state` (`bool`) - Print the parsed firewall state as JSON and exit.
 * * `ufw` (`Option<String>`) - Override the `ufw` executable, used by tests.
 * * `internal_revert_after` (`Option<u64>`) - Internal watchdog delay in seconds; set only by the detached helper.
 * * `nonce` (`Option<PathBuf>`) - Internal watchdog state file path; set only by the detached helper.
 */
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
    /**
     * True when the process should act as the detached revert watchdog instead
     * of a UI.
     *
     * # Arguments
     *
     * * `self` (`&Cli`) - The parsed command line being inspected. Both
     *   `internal_revert_after` and `nonce` must be present for watchdog mode.
     *
     * # Returns
     *
     * `bool` - `true` when both `--internal-revert-after` and `--nonce` were
     * supplied, meaning the caller should run the revert helper instead of the
     * terminal UI.
     */
    pub fn is_watchdog(&self) -> bool {
        self.internal_revert_after.is_some() && self.nonce.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /**
     * Verifies that parsing no arguments yields interactive mode: no demo, no
     * read-only flag, and no watchdog mode.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts on the parsed flags.
     */
    fn defaults_are_interactive() {
        let cli = Cli::parse_from(["ufw-manager-tui"]);
        assert!(!cli.demo);
        assert!(!cli.readonly);
        assert!(!cli.is_watchdog());
    }

    #[test]
    /**
     * Verifies that `--demo`, `--readonly`, `--no-color` and `-y` can be
     * combined and all set their respective flags.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts on the parsed flags.
     */
    fn demo_and_readonly_combine() {
        let cli = Cli::parse_from([
            "ufw-manager-tui",
            "--demo",
            "--readonly",
            "--no-color",
            "-y",
        ]);
        assert!(cli.demo && cli.readonly && cli.no_color && cli.yes);
    }

    #[test]
    /**
     * Verifies that watchdog mode requires both `--internal-revert-after` and
     * `--nonce`.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts on
     * [`Cli::is_watchdog`] for both argument combinations.
     */
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
