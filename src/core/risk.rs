//! Risk assessment.
//!
//! The point is not to score rules for their own sake: it is to answer "is this machine exposed?"
//! and "what should I do about it?" for somebody who has no basis for forming an opinion.

use std::fmt;

use ipnet::IpNet;

use crate::core::firewall::{FirewallState, Policy};
use crate::core::parse::{AppProfile, Listening};
use crate::core::rule::{Action, Direction, PortSpec, Rule};

/// Ports that give an attacker remote control of, or data from, the machine.
pub const SENSITIVE_PORTS: [u16; 20] = [
    21, 22, 23, 25, 111, 135, 139, 445, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 5986, 6379,
    9200, 27017,
];

pub fn is_sensitive_port(port: u16) -> bool {
    SENSITIVE_PORTS.contains(&port)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn label(self) -> &'static str {
        match self {
            RiskLevel::Info => "info",
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }

    /// Text fallback so risk is never conveyed by colour alone (`NO_COLOR`, monochrome terminals).
    pub fn ascii_badge(self) -> &'static str {
        match self {
            RiskLevel::Info => "[i]",
            RiskLevel::Low => "[ok]",
            RiskLevel::Medium => "[~]",
            RiskLevel::High => "[!]",
            RiskLevel::Critical => "[!!]",
        }
    }

    pub fn upgrade(self) -> Self {
        match self {
            RiskLevel::Info => RiskLevel::Low,
            RiskLevel::Low => RiskLevel::Medium,
            RiskLevel::Medium => RiskLevel::High,
            RiskLevel::High | RiskLevel::Critical => RiskLevel::Critical,
        }
    }

    pub fn downgrade(self) -> Self {
        match self {
            RiskLevel::Critical => RiskLevel::High,
            RiskLevel::High => RiskLevel::Medium,
            RiskLevel::Medium => RiskLevel::Low,
            RiskLevel::Low | RiskLevel::Info => RiskLevel::Info,
        }
    }

    /// Sort key for "worst first".
    pub fn severity(self) -> u8 {
        match self {
            RiskLevel::Info => 0,
            RiskLevel::Low => 1,
            RiskLevel::Medium => 2,
            RiskLevel::High => 3,
            RiskLevel::Critical => 4,
        }
    }
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    pub level: RiskLevel,
    pub reasons: Vec<String>,
}

impl Assessment {
    fn new(level: RiskLevel, reason: impl Into<String>) -> Self {
        Self {
            level,
            reasons: vec![reason.into()],
        }
    }

    pub fn summary(&self) -> String {
        self.reasons.join("; ")
    }
}

fn is_private(net: &IpNet) -> bool {
    match net {
        IpNet::V4(v4) => v4.addr().is_private() || v4.addr().is_link_local(),
        IpNet::V6(v6) => {
            let first = v6.addr().segments()[0];
            (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
    }
}

fn is_single_host(net: &IpNet) -> bool {
    net.prefix_len() == net.max_prefix_len()
}

/// The most sensitive port a rule opens, resolving application profiles when given.
fn sensitive_ports_of(rule: &Rule, profiles: &[AppProfile]) -> Vec<u16> {
    let ports: Vec<u16> = match &rule.to.port {
        PortSpec::Any => SENSITIVE_PORTS.to_vec(),
        PortSpec::Ports(list) => list
            .iter()
            .flat_map(|range| {
                if range.end.saturating_sub(range.start) <= 64 {
                    (range.start..=range.end).collect::<Vec<_>>()
                } else {
                    vec![range.start, range.end]
                }
            })
            .collect(),
        PortSpec::App(name) => profiles
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case(name))
            .map(|p| p.ports())
            .unwrap_or_default(),
    };
    ports
        .into_iter()
        .filter(|p| is_sensitive_port(*p))
        .collect()
}

pub fn assess_rule(rule: &Rule, profiles: &[AppProfile]) -> Assessment {
    if !rule.action.permits() {
        return Assessment::new(RiskLevel::Info, "this rule blocks traffic");
    }
    if rule.direction == Direction::Out {
        return Assessment::new(
            RiskLevel::Info,
            "outgoing rule: it limits what leaves this machine",
        );
    }
    if rule.is_route() {
        return Assessment::new(
            RiskLevel::Medium,
            "forwarding rule: it is not covered by the incoming default policy",
        );
    }

    let sensitive = sensitive_ports_of(rule, profiles);
    let source = match &rule.from.net() {
        None => None,
        Some(net) if is_private(net) => Some("private"),
        Some(net) if is_single_host(net) => Some("host"),
        Some(_) => Some("public"),
    };

    let mut assessment = match source {
        None => {
            if sensitive.is_empty() {
                Assessment::new(RiskLevel::High, "reachable from the entire internet")
            } else {
                let ports = sensitive
                    .iter()
                    .take(3)
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                Assessment::new(
                    RiskLevel::Critical,
                    format!("reachable from the entire internet on remote-access port {ports}"),
                )
            }
        }
        Some("private") => {
            let mut a = Assessment::new(RiskLevel::Low, "limited to a private network");
            a.reasons
                .push("anyone already on that network can connect".to_string());
            a
        }
        Some("host") => Assessment::new(RiskLevel::Low, "limited to one specific address"),
        _ => {
            if sensitive.is_empty() {
                Assessment::new(RiskLevel::Medium, "reachable from a public network")
            } else {
                Assessment::new(
                    RiskLevel::High,
                    "reachable from a public network on a remote-access port",
                )
            }
        }
    };

    if rule.action == Action::Limit {
        assessment.level = assessment.level.downgrade();
        assessment
            .reasons
            .push("rate limited, which slows down password guessing".to_string());
    }

    if rule.v6 {
        assessment
            .reasons
            .push("IPv6 variant of a rule".to_string());
    }

    assessment
}

/// A concrete thing the user could fix, with enough context for the UI to offer it as one keypress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suggestion {
    pub level: RiskLevel,
    pub text: String,
    pub fix: Option<Fix>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fix {
    TurnOnFirewall,
    FixDefaultIncoming,
    RestrictSshToLan,
    RateLimitSsh,
}

/// Whole-firewall advice, worst first.
pub fn assess_state(
    state: &FirewallState,
    listening: &[Listening],
    ssh_port: Option<u16>,
    profiles: &[AppProfile],
) -> Vec<Suggestion> {
    let mut out = Vec::new();

    if !state.rules_readable {
        return out;
    }

    if !state.enabled {
        out.push(Suggestion {
            level: RiskLevel::Critical,
            text: "Your firewall is turned off, so nothing is filtered at all.".into(),
            fix: Some(Fix::TurnOnFirewall),
        });
    }

    if state.default_incoming == Policy::Allow {
        out.push(Suggestion {
            level: RiskLevel::Critical,
            text: "The default policy lets incoming connections in, so any service you start is exposed until you add a rule.".into(),
            fix: Some(Fix::FixDefaultIncoming),
        });
    }

    if let Some(port) = ssh_port {
        let open_to_world = state.incoming_rules().any(|rule| {
            rule.action.permits()
                && rule.from.addr.is_none()
                && rule.interface_in.is_none()
                && (rule.to.port.contains(port) || rule.to.port.is_any())
        });
        if open_to_world {
            out.push(Suggestion {
                level: RiskLevel::High,
                text: format!(
                    "SSH (port {port}) is open to the entire internet. Restrict it to your local network, or rate-limit it to slow down password guessing."
                ),
                fix: Some(Fix::RestrictSshToLan),
            });
        }
    }

    // A listening service that nothing mentions is only a problem when the default policy would
    // let it through anyway.
    if state.default_incoming == Policy::Allow {
        let mut unmentioned: Vec<String> = Vec::new();
        for socket in listening {
            if socket.is_loopback() {
                continue;
            }
            let mentioned = state.incoming_rules().any(|rule| {
                rule.action.permits()
                    && (rule.to.port.contains(socket.port) || rule.to.port.is_any())
            });
            if !mentioned {
                let name = socket
                    .process
                    .clone()
                    .unwrap_or_else(|| format!("port {}", socket.port));
                unmentioned.push(format!("{name} ({}/{})", socket.port, socket.proto));
            }
        }
        if !unmentioned.is_empty() {
            out.push(Suggestion {
                level: RiskLevel::Medium,
                text: format!(
                    "{} service(s) are listening and your default policy lets them through: {}",
                    unmentioned.len(),
                    unmentioned.join(", ")
                ),
                fix: Some(Fix::FixDefaultIncoming),
            });
        }
    }

    if state.log_level == crate::core::firewall::LogLevel::Off {
        out.push(Suggestion {
            level: RiskLevel::Low,
            text: "Logging is off, so blocked connection attempts are not recorded anywhere."
                .into(),
            fix: None,
        });
    }

    let mut critical = 0;
    let mut open = 0;
    for rule in state.incoming_rules() {
        match assess_rule(rule, profiles).level {
            RiskLevel::Critical => critical += 1,
            RiskLevel::High => open += 1,
            _ => {}
        }
    }
    if critical > 0 {
        out.push(Suggestion {
            level: RiskLevel::Critical,
            text: format!("{critical} rule(s) expose a remote-access port to the whole internet."),
            fix: None,
        });
    } else if open > 0 {
        out.push(Suggestion {
            level: RiskLevel::High,
            text: format!("{open} rule(s) are open to the whole internet."),
            fix: None,
        });
    }

    out.sort_by_key(|suggestion| std::cmp::Reverse(suggestion.level.severity()));
    out
}

/// Rules that are unreachable because an earlier rule already matches their traffic.
///
/// This is the single most common `ufw` mistake: a broad rule above a specific one means the
/// specific rule never runs. Returned as `(shadowed_rule, shadowing_rule)` pairs.
pub fn find_shadowed(rules: &[Rule], profiles: &[AppProfile]) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    let incoming: Vec<&Rule> = rules
        .iter()
        .filter(|r| r.direction == Direction::In && !r.is_route())
        .collect();
    for (i, later) in incoming.iter().enumerate() {
        if !later.action.permits() {
            continue;
        }
        for earlier in incoming.iter().take(i) {
            if !earlier.action.permits() {
                continue;
            }
            if covers(earlier, later, profiles) {
                out.push((later.number, earlier.number));
                break;
            }
        }
    }
    out
}

/// The concrete port ranges a specification stands for, or `None` when it means "any port".
/// Application profiles are resolved, which is what makes "allow 22/tcp" correctly shadow
/// "allow OpenSSH".
fn port_ranges(
    spec: &PortSpec,
    profiles: &[AppProfile],
) -> Option<Vec<crate::core::rule::PortRange>> {
    match spec {
        PortSpec::Any => None,
        PortSpec::Ports(list) => Some(list.clone()),
        PortSpec::App(name) => {
            let profile = profiles
                .iter()
                .find(|p| p.name.eq_ignore_ascii_case(name))?;
            let mut out = Vec::new();
            for port in profile.ports() {
                out.push(crate::core::rule::PortRange::single(port));
            }
            if out.is_empty() {
                None
            } else {
                Some(out)
            }
        }
    }
}

/// What a rule actually exposes: the concrete ports and protocols, or `None` for "anything".
fn exposure(
    rule: &Rule,
    profiles: &[AppProfile],
) -> (
    Option<Vec<crate::core::rule::PortRange>>,
    Option<Vec<crate::core::rule::Protocol>>,
) {
    let ports = port_ranges(&rule.to.port, profiles);
    let protocols = if rule.protocol != crate::core::rule::Protocol::Any {
        Some(vec![rule.protocol])
    } else {
        match &rule.to.port {
            PortSpec::App(name) => profiles
                .iter()
                .find(|p| p.name.eq_ignore_ascii_case(name))
                .map(|p| p.protocols())
                .filter(|list| !list.is_empty()),
            _ => None,
        }
    };
    (ports, protocols)
}

/// True when `broad` matches everything `narrow` would match, and at least as much more.
fn covers(broad: &Rule, narrow: &Rule, profiles: &[AppProfile]) -> bool {
    if broad.signature() == narrow.signature() {
        // Identical rules: the second is redundant rather than shadowed.
        return false;
    }
    let addr_covers = match (&broad.from.net(), &narrow.from.net()) {
        (None, _) => true,
        (Some(b), Some(n)) => b.contains(&n.network()) && b.prefix_len() <= n.prefix_len(),
        (Some(_), None) => false,
    };
    let (broad_ports, broad_protocols) = exposure(broad, profiles);
    let (narrow_ports, narrow_protocols) = exposure(narrow, profiles);

    let port_covers = match (broad_ports, narrow_ports) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(broad_ranges), Some(narrow_ranges)) => narrow_ranges.iter().all(|nr| {
            broad_ranges
                .iter()
                .any(|br| br.start <= nr.start && br.end >= nr.end)
        }),
    };
    let proto_covers = match (broad_protocols, narrow_protocols) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(broad_list), Some(narrow_list)) => narrow_list.iter().all(|p| broad_list.contains(p)),
    };
    let iface_covers = broad.interface_in.is_none() || broad.interface_in == narrow.interface_in;
    addr_covers && port_covers && proto_covers && iface_covers
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::firewall::LogLevel;
    use crate::core::rule::{Endpoint, LogMode, PortRange, Protocol};

    fn rule(number: u32, action: Action, ports: PortSpec, from: Option<&str>) -> Rule {
        Rule {
            number,
            action,
            direction: Direction::In,
            interface_in: None,
            interface_out: None,
            protocol: Protocol::Tcp,
            from: Endpoint {
                addr: from.map(str::to_string),
                port: PortSpec::Any,
            },
            to: Endpoint {
                addr: None,
                port: ports,
            },
            log: LogMode::None,
            comment: None,
            v6: false,
            route: false,
        }
    }

    #[test]
    fn open_ssh_is_critical() {
        let a = assess_rule(&rule(1, Action::Allow, PortSpec::single(22), None), &[]);
        assert_eq!(a.level, RiskLevel::Critical);
    }

    #[test]
    fn open_high_port_is_only_high() {
        let a = assess_rule(&rule(1, Action::Allow, PortSpec::single(8080), None), &[]);
        assert_eq!(a.level, RiskLevel::High);
    }

    #[test]
    fn private_source_is_low() {
        let a = assess_rule(
            &rule(
                1,
                Action::Allow,
                PortSpec::single(22),
                Some("192.168.1.0/24"),
            ),
            &[],
        );
        assert_eq!(a.level, RiskLevel::Low);
    }

    #[test]
    fn single_host_source_is_low() {
        let a = assess_rule(
            &rule(1, Action::Allow, PortSpec::single(22), Some("203.0.113.7")),
            &[],
        );
        assert_eq!(a.level, RiskLevel::Low);
    }

    #[test]
    fn public_network_source_is_medium() {
        let a = assess_rule(
            &rule(
                1,
                Action::Allow,
                PortSpec::single(8443),
                Some("203.0.113.0/24"),
            ),
            &[],
        );
        assert_eq!(a.level, RiskLevel::Medium);
    }

    #[test]
    fn deny_rules_are_informational() {
        let a = assess_rule(&rule(1, Action::Deny, PortSpec::single(22), None), &[]);
        assert_eq!(a.level, RiskLevel::Info);
    }

    #[test]
    fn rate_limiting_downgrades_one_step() {
        let a = assess_rule(&rule(1, Action::Limit, PortSpec::single(22), None), &[]);
        assert_eq!(a.level, RiskLevel::High);
        assert!(a.reasons.iter().any(|r| r.contains("rate limited")));
    }

    #[test]
    fn app_profiles_resolve_to_sensitive_ports() {
        let profile = AppProfile {
            name: "OpenSSH".into(),
            title: String::new(),
            description: String::new(),
            ports_raw: "22/tcp".into(),
        };
        let a = assess_rule(
            &rule(1, Action::Allow, PortSpec::App("OpenSSH".into()), None),
            std::slice::from_ref(&profile),
        );
        assert_eq!(a.level, RiskLevel::Critical);
    }

    #[test]
    fn unreadable_state_produces_no_advice() {
        let state = FirewallState {
            rules_readable: false,
            ..Default::default()
        };
        assert!(assess_state(&state, &[], None, &[]).is_empty());
    }

    #[test]
    fn disabled_firewall_is_the_first_suggestion() {
        let state = FirewallState {
            rules_readable: true,
            enabled: false,
            ..Default::default()
        };
        let suggestions = assess_state(&state, &[], None, &[]);
        assert_eq!(suggestions[0].fix, Some(Fix::TurnOnFirewall));
        assert_eq!(suggestions[0].level, RiskLevel::Critical);
    }

    #[test]
    fn an_open_ssh_rule_produces_a_restrict_suggestion() {
        let state = FirewallState {
            rules_readable: true,
            enabled: true,
            default_incoming: Policy::Deny,
            rules: vec![rule(1, Action::Allow, PortSpec::single(22), None)],
            ..Default::default()
        };
        let suggestions = assess_state(&state, &[], Some(22), &[]);
        assert!(suggestions
            .iter()
            .any(|s| s.fix == Some(Fix::RestrictSshToLan)));
    }

    #[test]
    fn lan_only_ssh_produces_no_restrict_suggestion() {
        let state = FirewallState {
            rules_readable: true,
            enabled: true,
            default_incoming: Policy::Deny,
            rules: vec![rule(
                1,
                Action::Allow,
                PortSpec::single(22),
                Some("192.168.1.0/24"),
            )],
            ..Default::default()
        };
        let suggestions = assess_state(&state, &[], Some(22), &[]);
        assert!(!suggestions
            .iter()
            .any(|s| s.fix == Some(Fix::RestrictSshToLan)));
    }

    #[test]
    fn logging_off_is_mentioned() {
        let state = FirewallState {
            rules_readable: true,
            enabled: true,
            default_incoming: Policy::Deny,
            log_level: LogLevel::Off,
            ..Default::default()
        };
        let suggestions = assess_state(&state, &[], None, &[]);
        assert!(suggestions
            .iter()
            .any(|s| s.text.contains("Logging is off")));
    }

    #[test]
    fn detects_a_broad_rule_shadowing_a_narrow_one() {
        let rules = vec![
            rule(1, Action::Allow, PortSpec::single(22), None),
            rule(
                2,
                Action::Allow,
                PortSpec::single(22),
                Some("192.168.1.0/24"),
            ),
        ];
        assert_eq!(find_shadowed(&rules, &[]), vec![(2, 1)]);
    }

    #[test]
    fn does_not_flag_the_opposite_order() {
        let rules = vec![
            rule(
                1,
                Action::Allow,
                PortSpec::single(22),
                Some("192.168.1.0/24"),
            ),
            rule(2, Action::Allow, PortSpec::single(22), None),
        ];
        assert!(find_shadowed(&rules, &[]).is_empty());
    }

    #[test]
    fn does_not_flag_unrelated_rules() {
        let rules = vec![
            rule(1, Action::Allow, PortSpec::single(22), None),
            rule(2, Action::Allow, PortSpec::single(443), None),
        ];
        assert!(find_shadowed(&rules, &[]).is_empty());
    }

    #[test]
    fn does_not_flag_identical_rules_as_shadowing() {
        let rules = vec![
            rule(1, Action::Allow, PortSpec::single(22), None),
            rule(2, Action::Allow, PortSpec::single(22), None),
        ];
        assert!(find_shadowed(&rules, &[]).is_empty());
    }

    #[test]
    fn detects_a_port_range_shadowing_a_single_port() {
        let rules = vec![
            rule(
                1,
                Action::Allow,
                PortSpec::Ports(vec![PortRange::new(1, 1024).unwrap()]),
                None,
            ),
            rule(2, Action::Allow, PortSpec::single(22), None),
        ];
        assert_eq!(find_shadowed(&rules, &[]), vec![(2, 1)]);
    }
}
