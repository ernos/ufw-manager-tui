//! The reconcile watchdog.
//!
//! The one thing a terminal firewall tool can do that `ufw` itself cannot: if a risky change cuts
//! the connection the user is typing on, undo it automatically.
//!
//! Before applying a change that the lockout guard flagged (turning the firewall on, changing the
//! default policy), the UI spawns a detached copy of itself. That copy sleeps, then applies the
//! inverse commands — unless the UI wrote the cancel marker first, which it does the moment the
//! user confirms they are still connected.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
/**
 * Serialized payload the detached helper reads from the watchdog state file.
 *
 * # Fields
 *
 * * `inverse` (`Vec<Vec<String>>`) - Commands that restore the previous
 *   firewall configuration, each as an argument vector.
 * * `description` (`String`) - Human description of what is being guarded,
 *   shown in the countdown banner.
 */
pub struct WatchdogState {
    /// Commands that restore the previous firewall configuration.
    pub inverse: Vec<Vec<String>>,
    /// Human description of what is being guarded, shown in the countdown banner.
    pub description: String,
}

/**
 * Handle for a running reconcile watchdog.
 *
 * Returned by [`spawn`] and held by the UI while a risky change is pending. It
 * tracks the deadline for the countdown banner and owns the paths used to
 * cancel or clean up the guard.
 *
 * # Fields
 *
 * * `state_path` (`PathBuf`) - The state file the helper reads.
 * * `cancel_path` (`PathBuf`) - The marker file whose presence cancels the
 *   revert.
 * * `description` (`String`) - Human description of the guarded change.
 * * `expires_at` (`std::time::Instant`) - When the helper will revert unless
 *   cancelled.
 * * `seconds` (`u64`) - The configured delay in seconds.
 */
pub struct Watchdog {
    state_path: PathBuf,
    cancel_path: PathBuf,
    pub description: String,
    pub expires_at: std::time::Instant,
    pub seconds: u64,
}

impl Watchdog {
    /**
     * Reports how long the guard still has to run before the inverse commands
     * are applied.
     *
     * # Arguments
     *
     * * `self` (`&Watchdog`) - The active guard being read; its `expires_at`
     *   deadline is compared against the current instant.
     *
     * # Returns
     *
     * `u64` - Whole seconds left until expiry, saturating at `0` once the
     * deadline has passed.
     */
    pub fn remaining(&self) -> u64 {
        self.expires_at
            .saturating_duration_since(std::time::Instant::now())
            .as_secs()
    }

    /**
     * Creates the cancel marker; the detached helper will exit without touching
     * anything.
     *
     * # Arguments
     *
     * * `self` (`&Watchdog`) - The active guard; its `cancel_path` is the file
     *   that is written.
     *
     * # Returns
     *
     * `std::io::Result<()>` - `Ok(())` once the marker file contains
     * `confirmed`, or the I/O error from writing it.
     *
     * # Notes
     *
     * The helper polls for this file every 250 ms, so cancellation takes effect
     * almost immediately.
     */
    pub fn confirm(&self) -> std::io::Result<()> {
        std::fs::write(&self.cancel_path, b"confirmed")
    }

    /**
     * Exposes the path of the cancel marker file.
     *
     * # Arguments
     *
     * * `self` (`&Watchdog`) - The active guard whose `cancel_path` field is
     *   returned.
     *
     * # Returns
     *
     * `&Path` - A borrowed path to the marker file the helper watches for.
     */
    pub fn cancel_path(&self) -> &Path {
        &self.cancel_path
    }

    /**
     * Removes the state file, used when the change is accepted normally.
     *
     * # Arguments
     *
     * * `self` (`&Watchdog`) - The guard being retired; its `state_path` and
     *   `cancel_path` files are deleted.
     *
     * # Returns
     *
     * `()` - This function returns no value.
     *
     * # Notes
     *
     * Removal errors are ignored: the files may already be gone, and cleanup is
     * best effort.
     */
    pub fn cleanup(&self) {
        let _ = std::fs::remove_file(&self.state_path);
        let _ = std::fs::remove_file(&self.cancel_path);
    }
}

/**
 * Derives the cancel marker path that sits next to a watchdog state file.
 *
 * # Arguments
 *
 * * `state_path` (`&Path`) - The path of the watchdog state file, for example
 *   `watchdog.json`.
 *
 * # Returns
 *
 * `PathBuf` - The same path with `.cancel` appended to the file name, such as
 * `watchdog.json.cancel`. A path without a file name yields `.cancel`.
 */
pub fn cancel_path_for(state_path: &Path) -> PathBuf {
    let mut path = state_path.to_path_buf();
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    path.set_file_name(format!("{name}.cancel"));
    path
}

/**
 * Spawns the detached helper.
 *
 * # Arguments
 *
 * * `inverse` (`Vec<Vec<String>>`) - The commands that restore the previous
 *   firewall configuration, each as an argument vector.
 * * `description` (`String`) - Human description of the guarded change, shown
 *   in the countdown banner and stored in the state file.
 * * `seconds` (`u64`) - How long to wait before reverting.
 *
 * # Returns
 *
 * `Option<Watchdog>` - A handle for the running guard, or `None` when it could
 * not be started (zero seconds, no inverse commands, or an I/O or spawn
 * failure). The caller then applies the change unguarded and says so in the
 * status line.
 *
 * # Notes
 *
 * The state file lives in the platform state directory, falling back to the
 * data directory and then the system temp directory. The child process is
 * started with `--internal-revert-after` and `--nonce` and has its standard
 * streams redirected to null so it survives the parent's terminal.
 */
pub fn spawn(inverse: Vec<Vec<String>>, description: String, seconds: u64) -> Option<Watchdog> {
    if seconds == 0 || inverse.is_empty() {
        return None;
    }
    let dir = directories::ProjectDirs::from("", "", "ufw-manager-tui")
        .map(|dirs| {
            dirs.state_dir()
                .unwrap_or_else(|| dirs.data_dir())
                .to_path_buf()
        })
        .unwrap_or_else(std::env::temp_dir);
    std::fs::create_dir_all(&dir).ok()?;

    let state_path = dir.join("watchdog.json");
    let cancel_path = cancel_path_for(&state_path);
    let _ = std::fs::remove_file(&cancel_path);

    let state = WatchdogState {
        inverse,
        description: description.clone(),
    };
    std::fs::write(&state_path, serde_json::to_vec_pretty(&state).ok()?).ok()?;

    let exe = std::env::current_exe().ok()?;
    let child = Command::new(exe)
        .arg("--internal-revert-after")
        .arg(seconds.to_string())
        .arg("--nonce")
        .arg(&state_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    match child {
        Ok(_) => Some(Watchdog {
            state_path,
            cancel_path,
            description,
            expires_at: std::time::Instant::now() + Duration::from_secs(seconds),
            seconds,
        }),
        Err(_) => {
            let _ = std::fs::remove_file(&state_path);
            None
        }
    }
}

/**
 * Entry point for the detached helper: waits for the deadline while polling for
 * the cancel marker, then runs the inverse commands.
 *
 * # Arguments
 *
 * * `state_path` (`&Path`) - The watchdog state file written by [`spawn`].
 * * `seconds` (`u64`) - How long to wait before reverting.
 * * `program` (`&str`) - The executable used to run each inverse command, for
 *   example `ufw`.
 *
 * # Returns
 *
 * `i32` - The process exit code: `1` when the state file is missing or cannot
 * be parsed, `0` when the run was cancelled or the inverse commands were
 * attempted.
 *
 * # Notes
 *
 * Polling sleeps for 250 ms between checks, so this call blocks for up to
 * `seconds`. Failed inverse commands are reported on stderr but do not stop the
 * remaining ones, because reverting half the change beats reverting none. The
 * state and cancel files are removed on every successful path.
 */
pub fn run_revert_helper(state_path: &Path, seconds: u64, program: &str) -> i32 {
    let Ok(text) = std::fs::read_to_string(state_path) else {
        return 1;
    };
    let Ok(state) = serde_json::from_str::<WatchdogState>(&text) else {
        return 1;
    };
    let cancel = cancel_path_for(state_path);

    let deadline = std::time::Instant::now() + Duration::from_secs(seconds);
    while std::time::Instant::now() < deadline {
        if cancel.exists() {
            let _ = std::fs::remove_file(state_path);
            let _ = std::fs::remove_file(cancel);
            return 0;
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    if cancel.exists() {
        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(cancel);
        return 0;
    }

    for argv in &state.inverse {
        let status = Command::new(program)
            .args(argv)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .status();
        if !status.map(|s| s.success()).unwrap_or(false) {
            // Keep going: reverting half the change is better than reverting none of it.
            eprintln!("ufw-manager-tui watchdog: `{argv:?}` failed");
        }
    }

    let _ = std::fs::remove_file(state_path);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /**
     * Verifies that the cancel marker path is the state path with `.cancel`
     * appended.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts on
     * [`cancel_path_for`].
     */
    fn cancel_path_sits_next_to_the_state_file() {
        let path = Path::new("/tmp/ufw-manager-tui/watchdog.json");
        assert_eq!(
            cancel_path_for(path),
            PathBuf::from("/tmp/ufw-manager-tui/watchdog.json.cancel")
        );
    }

    #[test]
    /**
     * Verifies that the helper exits with code `1` when its state file is
     * missing.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts on the exit code.
     */
    fn the_helper_gives_up_when_its_state_file_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let code = run_revert_helper(&dir.path().join("nope.json"), 0, "true");
        assert_eq!(code, 1);
    }

    #[test]
    /**
     * Verifies that a pre-written cancel marker makes the helper exit without
     * running any inverse command.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts on the exit code and
     * that the marker file was never created.
     */
    fn the_helper_exits_without_running_commands_when_cancelled() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("watchdog.json");
        let marker = dir.path().join("ran");
        let state = WatchdogState {
            inverse: vec![vec![
                "sh".into(),
                "-c".into(),
                format!("touch {}", marker.display()),
            ]],
            description: "test".into(),
        };
        std::fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
        // Pre-write the cancel marker.
        std::fs::write(cancel_path_for(&state_path), b"confirmed").unwrap();

        let code = run_revert_helper(&state_path, 5, "sh");
        assert_eq!(code, 0);
        assert!(!marker.exists(), "the command must not run after a cancel");
    }

    #[test]
    /**
     * Verifies that the helper runs the inverse commands once the delay has
     * elapsed and then removes the state file.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts on the exit code, the
     * marker file, and the state file cleanup.
     */
    fn the_helper_runs_the_inverse_commands_after_the_delay() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("watchdog.json");
        let marker = dir.path().join("ran");
        let state = WatchdogState {
            inverse: vec![vec!["-c".into(), format!("touch {}", marker.display())]],
            description: "test".into(),
        };
        std::fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();

        let code = run_revert_helper(&state_path, 0, "sh");
        assert_eq!(code, 0);
        assert!(marker.exists(), "the inverse command should have run");
        assert!(!state_path.exists(), "the state file should be cleaned up");
    }

    #[test]
    /**
     * Verifies that [`spawn`] refuses a zero-second delay and an empty inverse
     * command list.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts that both calls return
     * `None`.
     */
    fn a_zero_second_watchdog_is_not_spawned() {
        assert!(spawn(vec![vec!["disable".into()]], "test".into(), 0).is_none());
        assert!(spawn(Vec::new(), "test".into(), 60).is_none());
    }
}
