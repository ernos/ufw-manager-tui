//! A fake firewall.
//!
//! Used by the integration tests and by `--demo`, so the entire UI can be explored, screenshotted
//! and exercised without root and without any chance of changing the real machine.

use std::sync::Mutex;

use crate::backend::{Backend, BackendError, CmdOutput, HitCounters};
use crate::core::firewall::FirewallState;
use crate::core::lockout::Session;
use crate::core::parse::{self, AppProfile, Listening};
use crate::core::presets::LanInfo;
use crate::core::rule::{
    Action, Direction, Endpoint, LogMode, PortSpec, Protocol, Rule, RuleDraft,
};

/// A realistic rule set: an installer-default SSH rule open to the world, a web server, a LAN-only
/// app rule, a deny, an IPv6 twin and a WireGuard forward rule.
const DEMO_STATUS: &str = "\
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere                   # SSH (installer default)
[ 2] 80,443/tcp                 ALLOW IN    Anywhere                   # web server
[ 3] OpenSSH                    ALLOW IN    192.168.1.0/24            # home network only
[ 4] 3306/tcp                   DENY IN     Anywhere                   # keep mysql private
[ 5] 53/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 6] Anywhere on wg0            ALLOW FWD   Anywhere                   # wireguard
";

const DEMO_PROFILES: &[(&str, &str, &str, &str)] = &[
    (
        "OpenSSH",
        "Secure Shell Server",
        "OpenSSH is a free version of the SSH protocol suite of network connectivity tools.",
        "22/tcp",
    ),
    (
        "Nginx Full",
        "Nginx Full",
        "Web server: both plain HTTP and HTTPS.",
        "80,443/tcp",
    ),
    (
        "Apache",
        "Apache",
        "Apache web server on ports 80 and 443.",
        "80,443/tcp",
    ),
    (
        "Samba",
        "Samba file sharing",
        "Windows-compatible file sharing.",
        "137,138/udp|139,445/tcp",
    ),
    (
        "CUPS",
        "Print server",
        "Common UNIX Printing System.",
        "631/tcp",
    ),
    (
        "PostgreSQL",
        "PostgreSQL database",
        "Database server.",
        "5432/tcp",
    ),
];

/**
 * The mutable state behind a [`MockBackend`].
 *
 * # Fields
 *
 * * `state` (`FirewallState`) - The simulated firewall rules and header.
 * * `history` (`Vec<Vec<String>>`) - Every command the app asked the fake
 *   firewall to run, in order.
 * * `profiles` (`Vec<AppProfile>`) - The demo application profiles.
 * * `listening` (`Vec<Listening>`) - The demo listening sockets.
 */
struct MockState {
    state: FirewallState,
    history: Vec<Vec<String>>,
    profiles: Vec<AppProfile>,
    listening: Vec<Listening>,
}

/**
 * A fake firewall used by the integration tests and by `--demo`.
 *
 * It implements [`Backend`] entirely in memory: commands are recorded and
 * applied to a small, honest subset of ufw semantics, so the whole UI can be
 * explored without root and without any chance of changing the real machine.
 *
 * # Fields
 *
 * * `inner` (`Mutex<MockState>`) - The simulated state, guarded so the backend
 *   can be shared across threads.
 */
pub struct MockBackend {
    inner: Mutex<MockState>,
}

impl Default for MockBackend {
    /**
     * Creates the default mock backend, identical to [`MockBackend::new`].
     *
     * # Arguments
     *
     * This method takes no arguments.
     *
     * # Returns
     *
     * `MockBackend` - A backend seeded with the demo rule set.
     */
    fn default() -> Self {
        Self::new()
    }
}

impl MockBackend {
    /**
     * Builds a mock backend seeded with the demo rule set, profiles and sockets.
     *
     * The demo status text is parsed with the real parser, so the mock exercises
     * the same code paths as a live machine.
     *
     * # Arguments
     *
     * This method takes no arguments.
     *
     * # Returns
     *
     * `MockBackend` - A backend holding the demo state behind a mutex.
     */
    pub fn new() -> Self {
        let state = parse::parse_status(DEMO_STATUS);
        let profiles = DEMO_PROFILES
            .iter()
            .map(|(name, title, description, ports)| AppProfile {
                name: (*name).to_string(),
                title: (*title).to_string(),
                description: (*description).to_string(),
                ports_raw: (*ports).to_string(),
            })
            .collect();
        let listening = vec![
            Listening {
                proto: "tcp".into(),
                addr: "0.0.0.0".into(),
                port: 22,
                process: Some("sshd".into()),
            },
            Listening {
                proto: "tcp".into(),
                addr: "0.0.0.0".into(),
                port: 443,
                process: Some("nginx".into()),
            },
            Listening {
                proto: "tcp".into(),
                addr: "0.0.0.0".into(),
                port: 80,
                process: Some("nginx".into()),
            },
            Listening {
                proto: "tcp".into(),
                addr: "127.0.0.1".into(),
                port: 631,
                process: Some("cupsd".into()),
            },
            Listening {
                proto: "tcp".into(),
                addr: "0.0.0.0".into(),
                port: 3306,
                process: Some("mysqld".into()),
            },
        ];
        Self {
            inner: Mutex::new(MockState {
                state,
                history: Vec::new(),
                profiles,
                listening,
            }),
        }
    }

    /**
     * The commands the app asked the "firewall" to run, in order.
     *
     * Asserted on by the tests, which check the exact argument vectors the UI
     * produced.
     *
     * # Arguments
     *
     * * `self` (`&MockBackend`) - The backend whose history is read; it is not
     *   modified.
     *
     * # Returns
     *
     * `Vec<Vec<String>>` - A clone of the recorded argument vectors, or an empty
     * vector when the mutex is poisoned.
     */
    pub fn history(&self) -> Vec<Vec<String>> {
        self.inner
            .lock()
            .map(|inner| inner.history.clone())
            .unwrap_or_default()
    }
}

impl Backend for MockBackend {
    /**
     * Implements [`Backend::label`] with a fixed demo-mode description.
     *
     * # Arguments
     *
     * * `self` (`&MockBackend`) - The backend being queried; it is not modified.
     *
     * # Returns
     *
     * `String` - The constant text `demo mode (nothing is applied)`.
     */
    fn label(&self) -> String {
        "demo mode (nothing is applied)".to_string()
    }

    /**
     * Implements [`Backend::is_root`], always reporting root.
     *
     * # Arguments
     *
     * * `self` (`&MockBackend`) - The backend being queried; it is not modified.
     *
     * # Returns
     *
     * `bool` - Always `true`, so the demo UI is fully usable.
     */
    fn is_root(&self) -> bool {
        true
    }

    /**
     * Implements [`Backend::can_write`], always allowing writes.
     *
     * # Arguments
     *
     * * `self` (`&MockBackend`) - The backend being queried; it is not modified.
     *
     * # Returns
     *
     * `bool` - Always `true`; nothing is applied to the real machine.
     */
    fn can_write(&self) -> bool {
        true
    }

    /**
     * Implements [`Backend::read_state`] by cloning the in-memory state.
     *
     * # Arguments
     *
     * * `self` (`&MockBackend`) - The backend being read; its mutex is locked but
     *   the state is not modified.
     *
     * # Returns
     *
     * `Result<FirewallState, BackendError>` - A clone of the current mock state,
     * or an `Io` error when the mutex is poisoned.
     */
    fn read_state(&self) -> Result<FirewallState, BackendError> {
        self.inner
            .lock()
            .map(|inner| inner.state.clone())
            .map_err(|_| BackendError::Io("mock state poisoned".into()))
    }

    /**
     * Implements [`Backend::app_profiles`] with the built-in demo profiles.
     *
     * # Arguments
     *
     * * `self` (`&MockBackend`) - The backend being read; it is not modified.
     *
     * # Returns
     *
     * `Result<Vec<AppProfile>, BackendError>` - A clone of the demo profiles, or
     * an empty vector if the mutex is poisoned.
     */
    fn app_profiles(&self) -> Result<Vec<AppProfile>, BackendError> {
        Ok(self
            .inner
            .lock()
            .map(|inner| inner.profiles.clone())
            .unwrap_or_default())
    }

    /**
     * Implements [`Backend::listening`] with the built-in demo sockets.
     *
     * # Arguments
     *
     * * `self` (`&MockBackend`) - The backend being read; it is not modified.
     *
     * # Returns
     *
     * `Result<Vec<Listening>, BackendError>` - A clone of the demo sockets, or an
     * empty vector if the mutex is poisoned.
     */
    fn listening(&self) -> Result<Vec<Listening>, BackendError> {
        Ok(self
            .inner
            .lock()
            .map(|inner| inner.listening.clone())
            .unwrap_or_default())
    }

    /**
     * Implements [`Backend::counters`] with deterministic fake numbers.
     *
     * Rules with an explicit port list get 1234 hits and every other rule gets
     * 42, so the counters column can be exercised in demos.
     *
     * # Arguments
     *
     * * `self` (`&MockBackend`) - The backend being queried; it is not modified.
     * * `rules` (`&[Rule]`) - The rules to invent counters for; IPv6 and route
     *   rules are skipped.
     *
     * # Returns
     *
     * `Result<HitCounters, BackendError>` - Always `Ok` with `reliable` set and a
     * `demo counters` note.
     */
    fn counters(&self, rules: &[Rule]) -> Result<HitCounters, BackendError> {
        // Deterministic, obviously fake numbers so the column can be exercised in demos.
        let mut per_rule = std::collections::BTreeMap::new();
        for rule in rules.iter().filter(|r| !r.v6 && !r.is_route()) {
            let hits = match rule.to.port {
                PortSpec::Ports(_) => 1_234,
                _ => 42,
            };
            per_rule.insert(rule.number, hits);
        }
        Ok(HitCounters {
            per_rule,
            chain_totals: vec![("ufw-user-input".into(), 1_318)],
            reliable: true,
            note: "demo counters".into(),
        })
    }

    /**
     * Implements [`Backend::run`] by recording the command and applying it to
     * the in-memory state.
     *
     * # Arguments
     *
     * * `self` (`&MockBackend`) - The backend being mutated; its history and
     *   state are updated.
     * * `args` (`&[String]`) - The ufw argument vector to simulate.
     *
     * # Returns
     *
     * `Result<CmdOutput, BackendError>` - A successful output describing the
     * simulated command, or an `Io` error when the mutex is poisoned.
     */
    fn run(&self, args: &[String]) -> Result<CmdOutput, BackendError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| BackendError::Io("mock state poisoned".into()))?;
        inner.history.push(args.to_vec());
        apply(&mut inner.state, args);
        Ok(CmdOutput {
            argv: args.to_vec(),
            success: true,
            stdout: format!("demo: {}", crate::core::command::render_command(args)),
            stderr: String::new(),
        })
    }

    /**
     * Implements [`Backend::dry_run`] without touching the mock state.
     *
     * # Arguments
     *
     * * `self` (`&MockBackend`) - The backend being queried; it is not modified.
     * * `args` (`&[String]`) - The ufw argument vector to describe.
     *
     * # Returns
     *
     * `Result<CmdOutput, BackendError>` - Always `Ok`, with the `--dry-run`
     * prefix added to the echoed argv.
     */
    fn dry_run(&self, args: &[String]) -> Result<CmdOutput, BackendError> {
        Ok(CmdOutput {
            argv: crate::backend::with_dry_run(args),
            success: true,
            stdout: format!(
                "demo dry run: {}",
                crate::core::command::render_command(args)
            ),
            stderr: String::new(),
        })
    }

    /**
     * Implements [`Backend::ssh_port`] with the fixed demo port 22.
     *
     * # Arguments
     *
     * * `self` (`&MockBackend`) - The backend being queried; it is not modified.
     *
     * # Returns
     *
     * `u16` - Always `22`.
     */
    fn ssh_port(&self) -> u16 {
        22
    }

    /**
     * Implements [`Backend::ssh_session`] with a local session.
     *
     * # Arguments
     *
     * * `self` (`&MockBackend`) - The backend being queried; it is not modified.
     *
     * # Returns
     *
     * `Session` - Always [`Session::local`], since the demo is not over SSH.
     */
    fn ssh_session(&self) -> Session {
        Session::local()
    }

    /**
     * Implements [`Backend::lan`] with a fixed demo network.
     *
     * # Arguments
     *
     * * `self` (`&MockBackend`) - The backend being queried; it is not modified.
     *
     * # Returns
     *
     * `Option<LanInfo>` - `eno1` on `192.168.1.0/24`, or `None` if that literal
     * fails to parse.
     */
    fn lan(&self) -> Option<LanInfo> {
        Some(LanInfo {
            iface: "eno1".into(),
            net: "192.168.1.0/24".parse().ok()?,
        })
    }

    /**
     * Implements [`Backend::interfaces`] with a fixed demo interface list.
     *
     * # Arguments
     *
     * * `self` (`&MockBackend`) - The backend being queried; it is not modified.
     *
     * # Returns
     *
     * `Vec<String>` - `eno1`, `wlp7s0` and `wg0`.
     */
    fn interfaces(&self) -> Vec<String> {
        vec!["eno1".into(), "wlp7s0".into(), "wg0".into()]
    }
}

/**
 * Applies a small, honest subset of ufw semantics so the demo is interactive
 * rather than a mock-up.
 *
 * Handles delete, insert, enable/disable, default policy, logging level and the
 * allow/deny/reject/limit verbs; anything else is ignored.
 *
 * # Arguments
 *
 * * `state` (`&mut FirewallState`) - The simulated state, mutated in place.
 * * `args` (`&[String]`) - The ufw argument vector to interpret.
 *
 * # Returns
 *
 * `()` - This function returns no value. Unrecognised commands are silently
 * ignored.
 */
fn apply(state: &mut FirewallState, args: &[String]) {
    match args.first().map(String::as_str) {
        Some("--force") if args.get(1).map(String::as_str) == Some("delete") => {
            if let Some(number) = args.get(2).and_then(|n| n.parse::<u32>().ok()) {
                state.rules.retain(|rule| rule.number != number);
                renumber(state);
            }
        }
        Some("delete") => {
            if let Some(rule) = rule_from_args(args, 0) {
                if let Some(index) = state
                    .rules
                    .iter()
                    .position(|r| r.signature() == rule.signature())
                {
                    state.rules.remove(index);
                    renumber(state);
                }
            }
        }
        Some("insert") => {
            let position = args.get(1).and_then(|n| n.parse::<u32>().ok()).unwrap_or(1);
            if let Some(rule) = rule_from_args(args, position) {
                let index = state
                    .rules
                    .iter()
                    .position(|r| r.number >= position)
                    .unwrap_or(state.rules.len());
                state.rules.insert(index, rule);
                renumber(state);
            }
        }
        Some("--force") => {
            // `ufw --force enable` skips ufw's own prompt; the effect is the same.
            if args.get(1).map(String::as_str) == Some("enable") {
                state.enabled = true;
            }
        }
        Some("enable") => state.enabled = true,
        Some("disable") => state.enabled = false,
        Some("default") => {
            if let (Some(policy), Some(direction)) = (args.get(1), args.get(2)) {
                if let Some(policy) = crate::core::firewall::Policy::from_word(policy) {
                    if direction == "incoming" {
                        state.default_incoming = policy;
                    } else if direction == "outgoing" {
                        state.default_outgoing = policy;
                    }
                }
            }
        }
        Some("logging") => {
            if let Some(level) = args
                .get(1)
                .and_then(|l| crate::core::firewall::LogLevel::from_word(l))
            {
                state.log_level = level;
            }
        }
        Some("allow" | "deny" | "reject" | "limit") => {
            let number = state.next_number();
            if let Some(rule) = rule_from_args(args, number) {
                state.rules.push(rule);
            }
        }
        _ => {}
    }
}

/**
 * Rewrites rule numbers so they run 1..=n in list order.
 *
 * # Arguments
 *
 * * `state` (`&mut FirewallState`) - The state whose rules are renumbered in
 *   place.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 */
fn renumber(state: &mut FirewallState) {
    for (index, rule) in state.rules.iter_mut().enumerate() {
        rule.number = index as u32 + 1;
    }
}

/**
 * Best-effort reconstruction of a rule from a `ufw` argument vector, good enough
 * for a demo.
 *
 * Understands both the long form (`allow in on eno1 proto tcp from ... port 22`)
 * and the simple form (`allow 22/tcp`, `allow OpenSSH`). Unparseable tokens are
 * skipped rather than rejected.
 *
 * # Arguments
 *
 * * `args` (`&[String]`) - The ufw argument vector to interpret.
 * * `number` (`u32`) - The rule number to assign to the reconstructed rule.
 *
 * # Returns
 *
 * `Option<Rule>` - The reconstructed rule, or `None` when no action verb is
 * present.
 */
pub fn rule_from_args(args: &[String], number: u32) -> Option<Rule> {
    let action_index = args
        .iter()
        .position(|arg| matches!(arg.as_str(), "allow" | "deny" | "reject" | "limit"))?;
    let action = match args[action_index].as_str() {
        "allow" => Action::Allow,
        "deny" => Action::Deny,
        "reject" => Action::Reject,
        _ => Action::Limit,
    };
    let rest = &args[action_index + 1..];

    let direction = if rest.first().map(String::as_str) == Some("out") {
        Direction::Out
    } else {
        Direction::In
    };

    let mut draft = RuleDraft {
        action,
        direction,
        ..Default::default()
    };

    let mut index = 0;
    while index < rest.len() {
        match rest[index].as_str() {
            "in" | "out" => index += 1,
            "on" => {
                if let Some(iface) = rest.get(index + 1) {
                    draft.interface_in = Some(iface.clone());
                }
                index += 2;
            }
            "proto" => {
                if let Some(proto) = rest.get(index + 1) {
                    draft.protocol = proto.parse().unwrap_or(Protocol::Any);
                }
                index += 2;
            }
            "from" => {
                if let Some(addr) = rest.get(index + 1) {
                    if addr != "any" {
                        draft.from_addr = Some(addr.clone());
                    }
                }
                index += 2;
            }
            "to" => {
                if let Some(addr) = rest.get(index + 1) {
                    if addr != "any" {
                        draft.to_addr = Some(addr.clone());
                    }
                }
                index += 2;
            }
            "port" => {
                if let Some(port) = rest.get(index + 1) {
                    if let Ok(spec) = port.parse::<PortSpec>() {
                        draft.to_port = spec;
                    }
                }
                index += 2;
            }
            "app" => {
                if let Some(name) = rest.get(index + 1) {
                    draft.to_port = PortSpec::App(name.clone());
                }
                index += 2;
            }
            "comment" => {
                draft.comment = rest.get(index + 1).cloned();
                index += 2;
            }
            "log" | "log-all" => {
                draft.log = LogMode::Log;
                index += 1;
            }
            other => {
                // Simple syntax: `allow 22/tcp` or `allow OpenSSH`.
                if let Some((base, proto)) = other.split_once('/') {
                    if let Ok(port) = base.parse::<u16>() {
                        draft.protocol =
                            Protocol::from_status_token(proto).unwrap_or(Protocol::Any);
                        draft.to_port = PortSpec::single(port);
                    }
                } else if let Ok(port) = other.parse::<u16>() {
                    draft.to_port = PortSpec::single(port);
                } else if !other.is_empty() {
                    draft.to_port = PortSpec::App(other.to_string());
                }
                index += 1;
            }
        }
    }

    let mut rule = draft.to_rule(number);
    rule.from = Endpoint {
        addr: draft.from_addr.clone(),
        port: PortSpec::Any,
    };
    Some(rule)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /**
     * Verifies that the demo status text parses into six rules with no leftovers.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
    fn the_demo_state_parses_cleanly() {
        let state = parse::parse_status(DEMO_STATUS);
        assert!(state.enabled);
        assert_eq!(state.rules.len(), 6);
        assert!(state.unparsed.is_empty());
        assert_eq!(state.rules[5].direction, Direction::Forward);
    }

    #[test]
    /**
     * Verifies that the mock backend reads state and allows writes without root.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
    fn the_demo_backend_reads_without_root() {
        let backend = MockBackend::new();
        let state = backend.read_state().unwrap();
        assert_eq!(state.rules.len(), 6);
        assert!(backend.can_write());
    }

    #[test]
    /**
     * Verifies that [`Backend::run`] appends the command to the history.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
    fn run_records_commands() {
        let backend = MockBackend::new();
        backend.run(&["allow".into(), "22/tcp".into()]).unwrap();
        assert_eq!(backend.history().len(), 1);
    }

    #[test]
    /**
     * Verifies that an `allow` command appends a rule with the next number.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
    fn adding_a_rule_appends_it() {
        let backend = MockBackend::new();
        backend.run(&["allow".into(), "8080/tcp".into()]).unwrap();
        let state = backend.read_state().unwrap();
        assert_eq!(state.rules.len(), 7);
        assert_eq!(state.rules[6].number, 7);
        assert_eq!(state.rules[6].to.port, PortSpec::single(8080));
    }

    #[test]
    /**
     * Verifies that deleting by number removes the rule and renumbers the rest.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
    fn deleting_by_number_removes_and_renumbers() {
        let backend = MockBackend::new();
        backend
            .run(&["--force".into(), "delete".into(), "1".into()])
            .unwrap();
        let state = backend.read_state().unwrap();
        assert_eq!(state.rules.len(), 5);
        assert_eq!(state.rules[0].number, 1);
        assert_eq!(
            state.rules[0].to.port,
            PortSpec::Ports(vec![
                crate::core::rule::PortRange::single(80),
                crate::core::rule::PortRange::single(443)
            ])
        );
    }

    #[test]
    /**
     * Verifies that enable, disable and default-policy commands are reflected in
     * the mock state.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
    fn enabling_and_policy_changes_are_reflected() {
        let backend = MockBackend::new();
        backend.run(&["disable".into()]).unwrap();
        assert!(!backend.read_state().unwrap().enabled);
        backend.run(&["--force".into(), "enable".into()]).unwrap();
        assert!(backend.read_state().unwrap().enabled);
        backend
            .run(&["default".into(), "reject".into(), "incoming".into()])
            .unwrap();
        assert_eq!(
            backend.read_state().unwrap().default_incoming,
            crate::core::firewall::Policy::Reject
        );
    }

    #[test]
    /**
     * Verifies that a full rule argument vector is reconstructed into a rule.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
    fn rule_arguments_are_understood() {
        let rule = rule_from_args(
            &[
                "allow".into(),
                "in".into(),
                "on".into(),
                "eno1".into(),
                "proto".into(),
                "tcp".into(),
                "from".into(),
                "192.168.1.0/24".into(),
                "to".into(),
                "any".into(),
                "port".into(),
                "22".into(),
                "comment".into(),
                "SSH from LAN".into(),
            ],
            3,
        )
        .unwrap();
        assert_eq!(rule.number, 3);
        assert_eq!(rule.interface_in.as_deref(), Some("eno1"));
        assert_eq!(rule.protocol, Protocol::Tcp);
        assert_eq!(rule.from.addr.as_deref(), Some("192.168.1.0/24"));
        assert_eq!(rule.to.port, PortSpec::single(22));
        assert_eq!(rule.comment.as_deref(), Some("SSH from LAN"));
    }

    #[test]
    /**
     * Verifies that a bare application name becomes an application port spec.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `()` - This function returns no value; it asserts and panics on failure.
     */
    fn app_rules_are_understood() {
        let rule = rule_from_args(&["allow".into(), "OpenSSH".into()], 1).unwrap();
        assert_eq!(rule.to.port, PortSpec::App("OpenSSH".into()));
    }
}
