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

/**
 * The real backend: shells out to `ufw` and reads a few world-readable system
 * files.
 *
 * The machine is probed once at construction for the facts the UI needs
 * everywhere (root-ness, LAN, interfaces, SSH port, profiles), so rendering a
 * frame never spawns a process.
 *
 * # Fields
 *
 * * `program` (`String`) - The ufw executable, overridable with `UFW_MANAGER_UFW`.
 * * `timeout` (`Duration`) - Hard limit for each ufw invocation.
 * * `is_root` (`bool`) - Whether the process started as root.
 * * `readonly` (`bool`) - Whether writes are forbidden by the command line.
 * * `no_escalate` (`bool`) - Whether `sudo` prompting is forbidden.
 * * `ssh_port` (`u16`) - The detected SSH port.
 * * `session` (`Session`) - The SSH session the UI runs inside, if any.
 * * `lan` (`Option<LanInfo>`) - The detected local network.
 * * `interfaces` (`Vec<String>`) - The detected interface names.
 * * `profiles` (`Vec<AppProfile>`) - The application profiles read at startup.
 * * `escalated` (`AtomicBool`) - Set once `sudo -v` has succeeded.
 */
pub struct UfwCli {
    program: String,
    sudo_program: String,
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
    /**
     * Builds the backend, probing the machine once for the facts the UI needs
     * everywhere (root-ness, LAN, interfaces, SSH port).
     *
     * The ufw program comes from `UFW_MANAGER_UFW` when set, otherwise `ufw`.
     * Profiles are read from `/etc/ufw/applications.d`.
     *
     * # Arguments
     *
     * * `readonly` (`bool`) - When `true`, writes are refused even as root.
     * * `no_escalate` (`bool`) - When `true`, `sudo` prompting is never offered.
     *
     * # Returns
     *
     * `UfwCli` - A backend holding the probed facts and the default timeout.
     *
     * # Notes
     *
     * Spawns several subprocesses (`id`, `ss`, `ip`) and reads system files.
     */
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
            sudo_program: "sudo".to_string(),
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

    /**
     * Test and diagnostic constructor: talk to `program` instead of `ufw` and
     * skip the root check.
     *
     * Used by the integration tests, which drive a fake `ufw` script.
     *
     * # Arguments
     *
     * * `program` (`impl Into<String>`) - The executable to invoke instead of
     *   `ufw`.
     *
     * # Returns
     *
     * `UfwCli` - A backend that always reports root and never escalates.
     *
     * # Notes
     *
     * Still probes the machine through [`UfwCli::new`], so it spawns the same
     * subprocesses.
     */
    #[doc(hidden)]
    pub fn for_testing(program: impl Into<String>) -> Self {
        let mut cli = Self::new(false, true);
        cli.program = program.into();
        cli.is_root = true;
        cli
    }

    /**
     * Test constructor for the escalation path: a non-root backend that can
     * escalate, with both `ufw` and `sudo` replaced by scripts.
     *
     * # Arguments
     *
     * * `program` (`impl Into<String>`) - The executable to invoke instead of
     *   `ufw`.
     * * `sudo_program` (`impl Into<String>`) - The executable to invoke instead
     *   of `sudo`.
     *
     * # Returns
     *
     * `UfwCli` - A backend that reports non-root, may escalate, and routes both
     * `sudo -v` and `sudo ufw ...` through the given scripts.
     */
    #[doc(hidden)]
    pub fn for_testing_escalatable(
        program: impl Into<String>,
        sudo_program: impl Into<String>,
    ) -> Self {
        let mut cli = Self::new(false, false);
        cli.program = program.into();
        cli.sudo_program = sudo_program.into();
        cli.is_root = false;
        cli
    }

    /**
     * Reports whether commands will run with root privileges.
     *
     * # Arguments
     *
     * * `self` (`&UfwCli`) - The backend being queried; it is not modified.
     *
     * # Returns
     *
     * `bool` - `true` when the process is root or `sudo -v` already succeeded.
     */
    fn privileged(&self) -> bool {
        self.is_root || self.escalated.load(Ordering::Relaxed)
    }

    /**
     * Runs the configured ufw program with a timeout and the C locale.
     *
     * A non-zero exit is still returned as `Ok` so callers can show ufw's own
     * message; only spawn failures, timeouts and the two recognised ufw
     * complaints become errors.
     *
     * # Arguments
     *
     * * `self` (`&UfwCli`) - The backend supplying the program name and timeout;
     *   it is not modified.
     * * `args` (`&[String]`) - Arguments passed to ufw.
     *
     * # Returns
     *
     * `Result<CmdOutput, BackendError>` - The captured output, or `NotRoot`,
     * `NotFound`, `Timeout` or `Io` when the command could not be run.
     *
     * # Notes
     *
     * Spawns a subprocess and blocks for up to the configured timeout.
     */
    fn invoke(&self, args: &[String]) -> Result<CmdOutput, BackendError> {
        // Once `sudo -v` has succeeded, ufw must be run through sudo too: `sudo -v`
        // only validates the cached credentials, it does not make later commands run
        // as root. Without this, every write after pressing X fails with
        // "You need to be root" and the rules stay hidden.
        let mut command = Command::new(if self.privileged() && !self.is_root {
            &self.sudo_program
        } else {
            &self.program
        });
        // ufw's output is translated; every parser here is written for the C locale.
        command
            .args(if self.privileged() && !self.is_root {
                // `sudo -- ufw ...`; sudo keeps the cached credentials from `sudo -v`,
                // so no password prompt appears. The `--` guard keeps ufw from being
                // parsed as a sudo option.
                let mut prefixed = vec!["--".to_string(), self.program.clone()];
                prefixed.extend(args.iter().cloned());
                prefixed
            } else {
                args.to_vec()
            })
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

/**
 * Checks whether the effective user id is 0 by running `id -u`.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `bool` - `true` only when `id -u` succeeds and prints `0`; any failure is
 * treated as "not root".
 *
 * # Notes
 *
 * Spawns a subprocess; errors are swallowed deliberately.
 */
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

/**
 * Runs a child process with a hard timeout, draining its pipes on separate
 * threads so a large output cannot deadlock against the wait loop.
 *
 * # Arguments
 *
 * * `command` (`Command`) - The fully configured command to spawn; its stdout and stderr must be piped.
 * * `timeout` (`Duration`) - How long to wait before killing the child.
 *
 * # Returns
 *
 * `Result<std::process::Output, BackendError>` - The exit status and captured
 * output, `NotFound` when the program is missing, `Timeout` when it had to be
 * killed, or `Io` for other spawn/wait failures.
 *
 * # Notes
 *
 * Spawns a subprocess and two reader threads; the wait loop polls every 20 ms.
 */
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

/**
 * Recursively reads ufw application profiles from a directory tree.
 *
 * Files are parsed with [`crate::core::parse::parse_profile_ini`]; sub-directories
 * are visited in sorted order so the resulting list is stable.
 *
 * # Arguments
 *
 * * `dir` (`&Path`) - Directory to scan, normally `/etc/ufw/applications.d`.
 *
 * # Returns
 *
 * `Vec<AppProfile>` - Every profile found, or an empty vector when the directory
 * cannot be read.
 */
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

/**
 * Lists listening sockets by running `ss -tulpnH`.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `Vec<Listening>` - The parsed sockets, or an empty vector when `ss` is missing
 * or produces nothing.
 *
 * # Notes
 *
 * Spawns a subprocess. Without root `ss` still lists sockets but cannot name the
 * owning process.
 */
fn read_listening() -> Vec<Listening> {
    // Without root `ss` still lists sockets, it just cannot name the process.
    let output = probe::run("ss", &["-tulpnH"]);
    parse::parse_ss(&output)
}

impl Backend for UfwCli {
    /**
     * Implements [`Backend::label`] by asking ufw for its version string.
     *
     * # Arguments
     *
     * * `self` (`&UfwCli`) - The backend supplying the program name; it is not
     *   modified.
     *
     * # Returns
     *
     * `String` - The first line of `ufw --version`, or `ufw` when the command
     * fails or prints nothing.
     *
     * # Notes
     *
     * Spawns a subprocess on every call; failures fall back to a constant.
     */
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

    /**
     * Implements [`Backend::is_root`] from the value probed at construction.
     *
     * # Arguments
     *
     * * `self` (`&UfwCli`) - The backend being queried; it is not modified.
     *
     * # Returns
     *
     * `bool` - The cached result of the `id -u` check.
     */
    fn is_root(&self) -> bool {
        self.is_root
    }

    /**
     * Implements [`Backend::can_write`] from the read-only flag and privileges.
     *
     * # Arguments
     *
     * * `self` (`&UfwCli`) - The backend being queried; it is not modified.
     *
     * # Returns
     *
     * `bool` - `true` when not read-only and either root or already escalated.
     */
    fn can_write(&self) -> bool {
        !self.readonly && self.privileged()
    }

    /**
     * Implements [`Backend::read_state`] by running `ufw status numbered` and
     * `ufw status verbose` and combining the two parses.
     *
     * # Arguments
     *
     * * `self` (`&UfwCli`) - The backend being read; it is not modified.
     *
     * # Returns
     *
     * `Result<FirewallState, BackendError>` - The parsed rules and header, or
     * `NotRoot` when unprivileged and `Failed` when either command fails.
     *
     * # Notes
     *
     * Spawns two subprocesses.
     */
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

    /**
     * Implements [`Backend::app_profiles`] from the profiles read at startup.
     *
     * # Arguments
     *
     * * `self` (`&UfwCli`) - The backend being read; it is not modified.
     *
     * # Returns
     *
     * `Result<Vec<AppProfile>, BackendError>` - Always `Ok` with a clone of the
     * cached profiles.
     */
    fn app_profiles(&self) -> Result<Vec<AppProfile>, BackendError> {
        Ok(self.profiles.clone())
    }

    /**
     * Implements [`Backend::listening`] by re-running `ss` on each call.
     *
     * # Arguments
     *
     * * `self` (`&UfwCli`) - The backend being read; it is not modified.
     *
     * # Returns
     *
     * `Result<Vec<Listening>, BackendError>` - Always `Ok`; a failed `ss` yields
     * an empty list.
     *
     * # Notes
     *
     * Spawns a subprocess.
     */
    fn listening(&self) -> Result<Vec<Listening>, BackendError> {
        Ok(read_listening())
    }

    /**
     * Implements [`Backend::counters`] by reading `nft -j list ruleset`.
     *
     * # Arguments
     *
     * * `self` (`&UfwCli`) - The backend being queried; it is not modified.
     * * `rules` (`&[crate::core::rule::Rule]`) - The rules to align counters
     *   against, in ufw order.
     *
     * # Returns
     *
     * `Result<HitCounters, BackendError>` - The aligned counters, an unavailable
     * set when `nft` needs root, or `Io` when `nft` cannot be spawned.
     *
     * # Notes
     *
     * Spawns a subprocess.
     */
    fn counters(&self, rules: &[crate::core::rule::Rule]) -> Result<HitCounters, BackendError> {
        // `nft list ruleset` needs root too, so once escalated it must go through
        // sudo just like ufw does.
        let mut command = Command::new(if self.privileged() && !self.is_root {
            &self.sudo_program
        } else {
            "nft"
        });
        if self.privileged() && !self.is_root {
            command.args(["--", "nft", "-j", "list", "ruleset"]);
        } else {
            command.args(["-j", "list", "ruleset"]);
        }
        let output = command
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

    /**
     * Implements [`Backend::run`] by invoking ufw for real.
     *
     * # Arguments
     *
     * * `self` (`&UfwCli`) - The backend supplying the program and timeout; it is
     *   not modified.
     * * `args` (`&[String]`) - Arguments passed to ufw.
     *
     * # Returns
     *
     * `Result<CmdOutput, BackendError>` - The captured output, or the error from
     * the private `invoke` helper.
     *
     * # Notes
     *
     * Spawns a subprocess and blocks until it exits or times out.
     */
    fn run(&self, args: &[String]) -> Result<CmdOutput, BackendError> {
        self.invoke(args)
    }

    /**
     * Implements [`Backend::dry_run`] by prefixing `--dry-run` and invoking ufw.
     *
     * # Arguments
     *
     * * `self` (`&UfwCli`) - The backend supplying the program and timeout; it is
     *   not modified.
     * * `args` (`&[String]`) - Arguments passed to ufw after the flag.
     *
     * # Returns
     *
     * `Result<CmdOutput, BackendError>` - The captured output, or the error from
     * the private `invoke` helper.
     *
     * # Notes
     *
     * Spawns a subprocess; ufw validates the command without changing anything.
     */
    fn dry_run(&self, args: &[String]) -> Result<CmdOutput, BackendError> {
        self.invoke(&with_dry_run(args))
    }

    /**
     * Implements [`Backend::ssh_port`] from the value probed at construction.
     *
     * # Arguments
     *
     * * `self` (`&UfwCli`) - The backend being queried; it is not modified.
     *
     * # Returns
     *
     * `u16` - The cached SSH port.
     */
    fn ssh_port(&self) -> u16 {
        self.ssh_port
    }

    /**
     * Implements [`Backend::ssh_session`] from the value probed at construction.
     *
     * # Arguments
     *
     * * `self` (`&UfwCli`) - The backend being queried; it is not modified.
     *
     * # Returns
     *
     * `Session` - A clone of the cached session.
     */
    fn ssh_session(&self) -> Session {
        self.session.clone()
    }

    /**
     * Implements [`Backend::lan`] from the value probed at construction.
     *
     * # Arguments
     *
     * * `self` (`&UfwCli`) - The backend being queried; it is not modified.
     *
     * # Returns
     *
     * `Option<LanInfo>` - A clone of the cached LAN, or `None` when detection
     * failed.
     */
    fn lan(&self) -> Option<LanInfo> {
        self.lan.clone()
    }

    /**
     * Implements [`Backend::interfaces`] from the value probed at construction.
     *
     * # Arguments
     *
     * * `self` (`&UfwCli`) - The backend being queried; it is not modified.
     *
     * # Returns
     *
     * `Vec<String>` - A clone of the cached interface names.
     */
    fn interfaces(&self) -> Vec<String> {
        self.interfaces.clone()
    }

    /**
     * Implements [`Backend::may_escalate`] from the startup flags.
     *
     * # Arguments
     *
     * * `self` (`&UfwCli`) - The backend being queried; it is not modified.
     *
     * # Returns
     *
     * `bool` - `true` only when escalation was not disabled, the process is not
     * root and the backend is not read-only.
     */
    fn may_escalate(&self) -> bool {
        !self.no_escalate && !self.is_root && !self.readonly
    }

    /**
     * Implements [`Backend::escalate`] by running `sudo -v` once.
     *
     * # Arguments
     *
     * * `self` (`&UfwCli`) - The backend being mutated; the escalated flag is set
     *   on success.
     *
     * # Returns
     *
     * `bool` - `true` when privileges are now available, `false` when the user
     * declined or `sudo` failed.
     *
     * # Notes
     *
     * Spawns `sudo -v` with inherited stdio, so it needs the real terminal and
     * the caller must have left raw mode.
     */
    fn escalate(&self) -> bool {
        if self.escalated.load(Ordering::Relaxed) {
            return true;
        }
        // `sudo -v` needs the real terminal, so the caller must have left raw mode already.
        let status = Command::new(&self.sudo_program)
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

    /**
     * Implements [`Backend::log_path`] by testing whether `/var/log/ufw.log` is
     * readable.
     *
     * # Arguments
     *
     * * `self` (`&UfwCli`) - The backend being queried; it is not modified.
     *
     * # Returns
     *
     * `Option<PathBuf>` - The log path when it can be opened, otherwise `None` so
     * the monitor falls back to the journal.
     */
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
    /**
     * Verifies that a missing program maps to [`BackendError::NotFound`].
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
    fn a_missing_program_reports_not_found() {
        let mut command = Command::new("definitely-not-a-real-binary-xyz");
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let error = run_with_timeout(command, Duration::from_secs(1)).unwrap_err();
        assert!(matches!(error, BackendError::NotFound));
    }

    #[test]
    /**
     * Verifies that a slow child is killed and reported as a timeout.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
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
    /**
     * Verifies that a fast child's stdout is captured intact.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
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
    /**
     * Verifies that profiles are read from nested directories.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
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
    /**
     * Verifies that a missing profiles directory yields an empty list.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
    fn a_missing_profiles_directory_is_not_an_error() {
        assert!(read_profiles(Path::new("/definitely/not/here")).is_empty());
    }
}
