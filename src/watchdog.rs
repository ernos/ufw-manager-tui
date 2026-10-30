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
pub struct WatchdogState {
    /// Commands that restore the previous firewall configuration.
    pub inverse: Vec<Vec<String>>,
    /// Human description of what is being guarded, shown in the countdown banner.
    pub description: String,
}

pub struct Watchdog {
    state_path: PathBuf,
    cancel_path: PathBuf,
    pub description: String,
    pub expires_at: std::time::Instant,
    pub seconds: u64,
}

impl Watchdog {
    pub fn remaining(&self) -> u64 {
        self.expires_at
            .saturating_duration_since(std::time::Instant::now())
            .as_secs()
    }

    /// Creates the cancel marker; the detached helper will exit without touching anything.
    pub fn confirm(&self) -> std::io::Result<()> {
        std::fs::write(&self.cancel_path, b"confirmed")
    }

    pub fn cancel_path(&self) -> &Path {
        &self.cancel_path
    }

    /// Removes the state file, used when the change is accepted normally.
    pub fn cleanup(&self) {
        let _ = std::fs::remove_file(&self.state_path);
        let _ = std::fs::remove_file(&self.cancel_path);
    }
}

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

/// Spawns the detached helper. Returns `None` when it could not be started; the caller then
/// applies the change unguarded and says so in the status line.
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

/// Entry point for the detached helper.
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
    fn cancel_path_sits_next_to_the_state_file() {
        let path = Path::new("/tmp/ufw-manager-tui/watchdog.json");
        assert_eq!(
            cancel_path_for(path),
            PathBuf::from("/tmp/ufw-manager-tui/watchdog.json.cancel")
        );
    }

    #[test]
    fn the_helper_gives_up_when_its_state_file_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let code = run_revert_helper(&dir.path().join("nope.json"), 0, "true");
        assert_eq!(code, 1);
    }

    #[test]
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
    fn a_zero_second_watchdog_is_not_spawned() {
        assert!(spawn(vec![vec!["disable".into()]], "test".into(), 0).is_none());
        assert!(spawn(Vec::new(), "test".into(), 60).is_none());
    }
}
