//! The real backend: shells out to `ufw` and reads a few world-readable system files.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::backend::{
    looks_like_missing, looks_like_not_root, probe, with_dry_run, Backend, BackendError, CmdOutput,
    HitCounters,
};
use crate::core::firewall::FirewallState;
use crate::core::lockout::Session;
use crate::core::parse::{self, AppProfile, Listening};
use crate::core::presets::LanInfo;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct UfwCli {
    program: String,
    timeout: Duration,
    is_root: bool,
    readonly: bool,
    no_escalate: bool,
    ssh_port: u16,
    session: Session,
    lan: Option<LanInfo>,
    interfaces: Vec<String>,
    profiles: Vec<AppProfile>,
    escalated: AtomicBool,
}

impl UfwCli {
    /// Builds the backend, probing the machine once for the facts the UI needs everywhere
    /// (root-ness, LAN, interfaces, SSH port).
    pub fn new(readonly: bool, no_escalate: bool) -> Self {
        let program = std::env::var("UFW_MANAGER_UFW").unwrap_or_else(|_| "ufw".to_string());
        let is_root = current_uid_is_zero();
        let listening = read_listening();
        let ssh_port = probe::ssh_port_from_sshd_config(
            &std::fs::read_to_string("/etc/ssh/sshd_config").unwrap_or_default(),
        )
        .or_else(|| probe::ssh_port_from_listening(&listening))
        .unwrap_or(22);
        let lan = probe::detect_lan(
            &probe::run("ip", &["route", "show", "default"]),
            &probe::run("ip", &["-o", "-4", "addr", "show", "scope", "global"]),
        );
        let interfaces = probe::parse_interfaces(&probe::run("ip", &["-o", "link", "show"]));
        let profiles = read_profiles(Path::new("/etc/ufw/applications.d"));

        Self {
            program,
            timeout: DEFAULT_TIMEOUT,
            is_root,
            readonly,
            no_escalate,
            ssh_port,
            session: probe::current_session(),
            lan,
            interfaces,
            profiles,
            escalated: AtomicBool::new(false),
        }
    }

    /// Test and diagnostic constructor: talk to `program` instead of `ufw` and skip the root check.
    /// Used by the integration tests, which drive a fake `ufw` script.
    #[doc(hidden)]
    pub fn for_testing(program: impl Into<String>) -> Self {
        let mut cli = Self::new(false, true);
        cli.program = program.into();
        cli.is_root = true;
        cli
    }

    fn privileged(&self) -> bool {
        self.is_root || self.escalated.load(Ordering::Relaxed)
    }

    fn invoke(&self, args: &[String]) -> Result<CmdOutput, BackendError> {
        let mut command = Command::new(&self.program);
        // ufw's output is translated; every parser here is written for the C locale.
        command
            .args(args)
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let output = run_with_timeout(command, self.timeout)?;
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();

        if !output.status.success() {
            if looks_like_not_root(&stderr) {
                return Err(BackendError::NotRoot(stderr.trim().to_string()));
            }
            if looks_like_missing(&stderr) {
                return Err(BackendError::NotFound);
            }
        }

        Ok(CmdOutput {
            argv: args.to_vec(),
            success: output.status.success(),
            stdout,
            stderr,
        })
    }
}

fn current_uid_is_zero() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|out| {
            String::from_utf8_lossy(&out.stdout)
                .trim()
                .parse::<u32>()
                .ok()
        })
        .map(|uid| uid == 0)
        .unwrap_or(false)
}

/// Runs a child process with a hard timeout, draining its pipes on separate threads so a large
/// output cannot deadlock against the wait loop.
fn run_with_timeout(
    mut command: Command,
    timeout: Duration,
) -> Result<std::process::Output, BackendError> {
    let mut child = command.spawn().map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            BackendError::NotFound
        } else {
            BackendError::Io(error.to_string())
        }
    })?;

    let stdout = child.stdout.take().map(|mut pipe| {
        std::thread::spawn(move || {
            let mut buffer = Vec::new();
            let _ = pipe.read_to_end(&mut buffer);
            buffer
        })
    });
    let stderr = child.stderr.take().map(|mut pipe| {
        std::thread::spawn(move || {
            let mut buffer = Vec::new();
            let _ = pipe.read_to_end(&mut buffer);
            buffer
        })
    });

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => return Err(BackendError::Io(error.to_string())),
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            if let Some(handle) = stdout {
                let _ = handle.join();
            }
            if let Some(handle) = stderr {
                let _ = handle.join();
            }
            return Err(BackendError::Timeout {
                seconds: timeout.as_secs(),
            });
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    Ok(std::process::Output {
        status,
        stdout: stdout
            .map(|h| h.join().unwrap_or_default())
            .unwrap_or_default(),
        stderr: stderr
            .map(|h| h.join().unwrap_or_default())
            .unwrap_or_default(),
    })
}

fn read_profiles(dir: &Path) -> Vec<AppProfile> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            // applications.d may contain sub-directories of profiles.
            out.extend(read_profiles(&path));
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        out.extend(parse::parse_profile_ini(&text));
    }
    out
}

fn read_listening() -> Vec<Listening> {
    // Without root `ss` still lists sockets, it just cannot name the process.
    let output = probe::run("ss", &["-tulpnH"]);
    parse::parse_ss(&output)
}

impl Backend for UfwCli {
    fn label(&self) -> String {
        let version = Command::new(&self.program)
            .arg("--version")
            .env("LC_ALL", "C")
            .output()
            .ok()
            .map(|out| {
                String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string()
            })
            .unwrap_or_else(|| "ufw".to_string());
        if version.trim().is_empty() {
            "ufw".to_string()
        } else {
            version.trim().to_string()
        }
    }

    fn is_root(&self) -> bool {
        self.is_root
    }

    fn can_write(&self) -> bool {
        !self.readonly && self.privileged()
    }

    fn read_state(&self) -> Result<FirewallState, BackendError> {
        if !self.privileged() {
            return Err(BackendError::NotRoot(
                "run `sudo ufw-manager-tui` to see and edit rules".to_string(),
            ));
        }
        let numbered = self.invoke(&["status".into(), "numbered".into()])?;
        if !numbered.success {
            return Err(BackendError::Failed {
                command: numbered.command(),
                stderr: numbered.message(),
            });
        }
        let verbose = self.invoke(&["status".into(), "verbose".into()])?;
        if !verbose.success {
            return Err(BackendError::Failed {
                command: verbose.command(),
                stderr: verbose.message(),
            });
        }
        let rules = parse::parse_status_numbered(&numbered.stdout);
        let header = parse::parse_status_verbose(&verbose.stdout);
        Ok(parse::combine_rules_and_header(rules, header))
    }

    fn app_profiles(&self) -> Result<Vec<AppProfile>, BackendError> {
        Ok(self.profiles.clone())
    }

    fn listening(&self) -> Result<Vec<Listening>, BackendError> {
        Ok(read_listening())
    }

    fn counters(&self, rules: &[crate::core::rule::Rule]) -> Result<HitCounters, BackendError> {
        let output = Command::new("nft")
            .args(["-j", "list", "ruleset"])
            .env("LC_ALL", "C")
            .output()
            .map_err(|error| BackendError::Io(error.to_string()))?;
        if !output.status.success() {
            return Ok(HitCounters::unavailable(
                "hit counters need root (`nft list ruleset`)",
            ));
        }
        Ok(crate::backend::counters::collect(
            &String::from_utf8_lossy(&output.stdout),
            rules,
        ))
    }

    fn run(&self, args: &[String]) -> Result<CmdOutput, BackendError> {
        self.invoke(args)
    }

    fn dry_run(&self, args: &[String]) -> Result<CmdOutput, BackendError> {
        self.invoke(&with_dry_run(args))
    }

    fn ssh_port(&self) -> u16 {
        self.ssh_port
    }

    fn ssh_session(&self) -> Session {
        self.session.clone()
    }

    fn lan(&self) -> Option<LanInfo> {
        self.lan.clone()
    }

    fn interfaces(&self) -> Vec<String> {
        self.interfaces.clone()
    }

    fn may_escalate(&self) -> bool {
        !self.no_escalate && !self.is_root && !self.readonly
    }

    fn escalate(&self) -> bool {
        if self.escalated.load(Ordering::Relaxed) {
            return true;
        }
        // `sudo -v` needs the real terminal, so the caller must have left raw mode already.
        let status = Command::new("sudo")
            .arg("-v")
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status();
        if status.map(|s| s.success()).unwrap_or(false) {
            self.escalated.store(true, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    fn log_path(&self) -> Option<PathBuf> {
        let path = PathBuf::from("/var/log/ufw.log");
        if std::fs::File::open(&path).is_ok() {
            Some(path)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_program_reports_not_found() {
        let mut command = Command::new("definitely-not-a-real-binary-xyz");
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let error = run_with_timeout(command, Duration::from_secs(1)).unwrap_err();
        assert!(matches!(error, BackendError::NotFound));
    }

    #[test]
    fn a_slow_program_is_killed_at_the_timeout() {
        let mut command = Command::new("sleep");
        command
            .arg("5")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let error = run_with_timeout(command, Duration::from_millis(120)).unwrap_err();
        assert!(matches!(error, BackendError::Timeout { .. }));
    }

    #[test]
    fn a_fast_program_returns_its_output() {
        let mut command = Command::new("echo");
        command
            .arg("hello")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = run_with_timeout(command, Duration::from_secs(2)).unwrap();
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "hello");
    }

    #[test]
    fn profiles_are_read_from_a_directory_tree() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ssh.profile"), "[OpenSSH]\nports=22/tcp\n").unwrap();
        let nested = dir.path().join("nginx");
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(
            nested.join("nginx.profile"),
            "[Nginx Full]\nports=80,443/tcp\n",
        )
        .unwrap();

        let profiles = read_profiles(dir.path());
        assert_eq!(profiles.len(), 2);
        assert!(profiles.iter().any(|p| p.name == "OpenSSH"));
        assert!(profiles.iter().any(|p| p.name == "Nginx Full"));
    }

    #[test]
    fn a_missing_profiles_directory_is_not_an_error() {
        assert!(read_profiles(Path::new("/definitely/not/here")).is_empty());
    }
}
