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

struct MockState {
    state: FirewallState,
    history: Vec<Vec<String>>,
    profiles: Vec<AppProfile>,
    listening: Vec<Listening>,
}

pub struct MockBackend {
    inner: Mutex<MockState>,
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MockBackend {
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

    /// The commands the app asked the "firewall" to run, in order. Asserted on by the tests.
    pub fn history(&self) -> Vec<Vec<String>> {
        self.inner
            .lock()
            .map(|inner| inner.history.clone())
            .unwrap_or_default()
    }
}

impl Backend for MockBackend {
    fn label(&self) -> String {
        "demo mode (nothing is applied)".to_string()
    }

    fn is_root(&self) -> bool {
        true
    }

    fn can_write(&self) -> bool {
        true
    }

    fn read_state(&self) -> Result<FirewallState, BackendError> {
        self.inner
            .lock()
            .map(|inner| inner.state.clone())
            .map_err(|_| BackendError::Io("mock state poisoned".into()))
    }

    fn app_profiles(&self) -> Result<Vec<AppProfile>, BackendError> {
        Ok(self
            .inner
            .lock()
            .map(|inner| inner.profiles.clone())
            .unwrap_or_default())
    }

    fn listening(&self) -> Result<Vec<Listening>, BackendError> {
        Ok(self
            .inner
            .lock()
            .map(|inner| inner.listening.clone())
            .unwrap_or_default())
    }

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

    fn ssh_port(&self) -> u16 {
        22
    }

    fn ssh_session(&self) -> Session {
        Session::local()
    }

    fn lan(&self) -> Option<LanInfo> {
        Some(LanInfo {
            iface: "eno1".into(),
            net: "192.168.1.0/24".parse().ok()?,
        })
    }

    fn interfaces(&self) -> Vec<String> {
        vec!["eno1".into(), "wlp7s0".into(), "wg0".into()]
    }
}

/// Applies a small, honest subset of ufw semantics so the demo is interactive rather than a mock-up.
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

fn renumber(state: &mut FirewallState) {
    for (index, rule) in state.rules.iter_mut().enumerate() {
        rule.number = index as u32 + 1;
    }
}

/// Best-effort reconstruction of a rule from a `ufw` argument vector, good enough for a demo.
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
    fn the_demo_state_parses_cleanly() {
        let state = parse::parse_status(DEMO_STATUS);
        assert!(state.enabled);
        assert_eq!(state.rules.len(), 6);
        assert!(state.unparsed.is_empty());
        assert_eq!(state.rules[5].direction, Direction::Forward);
    }

    #[test]
    fn the_demo_backend_reads_without_root() {
        let backend = MockBackend::new();
        let state = backend.read_state().unwrap();
        assert_eq!(state.rules.len(), 6);
        assert!(backend.can_write());
    }

    #[test]
    fn run_records_commands() {
        let backend = MockBackend::new();
        backend.run(&["allow".into(), "22/tcp".into()]).unwrap();
        assert_eq!(backend.history().len(), 1);
    }

    #[test]
    fn adding_a_rule_appends_it() {
        let backend = MockBackend::new();
        backend.run(&["allow".into(), "8080/tcp".into()]).unwrap();
        let state = backend.read_state().unwrap();
        assert_eq!(state.rules.len(), 7);
        assert_eq!(state.rules[6].number, 7);
        assert_eq!(state.rules[6].to.port, PortSpec::single(8080));
    }

    #[test]
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
    fn app_rules_are_understood() {
        let rule = rule_from_args(&["allow".into(), "OpenSSH".into()], 1).unwrap();
        assert_eq!(rule.to.port, PortSpec::App("OpenSSH".into()));
    }
}
