//! Whole-firewall state: everything `ufw status` tells us.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::core::rule::Rule;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Policy {
    Allow,
    #[default]
    Deny,
    Reject,
}

impl Policy {
    pub fn ufw(self) -> &'static str {
        match self {
            Policy::Allow => "allow",
            Policy::Deny => "deny",
            Policy::Reject => "reject",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Policy::Allow => "ALLOW",
            Policy::Deny => "DENY",
            Policy::Reject => "REJECT",
        }
    }

    pub fn from_word(word: &str) -> Option<Self> {
        match word.trim().to_ascii_lowercase().as_str() {
            "allow" | "accept" => Some(Policy::Allow),
            "deny" | "drop" => Some(Policy::Deny),
            "reject" => Some(Policy::Reject),
            _ => None,
        }
    }

    pub fn permits(self) -> bool {
        self == Policy::Allow
    }
}

impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// The routed policy can also be switched off entirely, which `status` prints as `disabled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RoutedPolicy {
    Allow,
    Deny,
    Reject,
    #[default]
    Disabled,
}

impl RoutedPolicy {
    pub fn label(self) -> &'static str {
        match self {
            RoutedPolicy::Allow => "ALLOW",
            RoutedPolicy::Deny => "DENY",
            RoutedPolicy::Reject => "REJECT",
            RoutedPolicy::Disabled => "DISABLED",
        }
    }

    pub fn from_word(word: &str) -> Option<Self> {
        match word.trim().to_ascii_lowercase().as_str() {
            "allow" | "accept" => Some(RoutedPolicy::Allow),
            "deny" | "drop" => Some(RoutedPolicy::Deny),
            "reject" => Some(RoutedPolicy::Reject),
            "disabled" => Some(RoutedPolicy::Disabled),
            _ => None,
        }
    }
}

impl fmt::Display for RoutedPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum LogLevel {
    Off,
    #[default]
    Low,
    Medium,
    High,
    Full,
}

impl LogLevel {
    pub const ALL: [LogLevel; 5] = [
        LogLevel::Off,
        LogLevel::Low,
        LogLevel::Medium,
        LogLevel::High,
        LogLevel::Full,
    ];

    pub fn ufw(self) -> &'static str {
        match self {
            LogLevel::Off => "off",
            LogLevel::Low => "low",
            LogLevel::Medium => "medium",
            LogLevel::High => "high",
            LogLevel::Full => "full",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            LogLevel::Off => "off",
            LogLevel::Low => "low",
            LogLevel::Medium => "medium",
            LogLevel::High => "high",
            LogLevel::Full => "full",
        }
    }

    pub fn from_word(word: &str) -> Option<Self> {
        match word.trim().to_ascii_lowercase().as_str() {
            "off" => Some(LogLevel::Off),
            "low" | "on" => Some(LogLevel::Low),
            "medium" => Some(LogLevel::Medium),
            "high" => Some(LogLevel::High),
            "full" => Some(LogLevel::Full),
            _ => None,
        }
    }

    /// Levels above `medium` generate enough log volume to fill a disk; the UI warns about it.
    pub fn is_noisy(self) -> bool {
        matches!(self, LogLevel::High | LogLevel::Full)
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Everything the app knows about the firewall right now.
#[derive(Debug, Clone, Default)]
pub struct FirewallState {
    pub enabled: bool,
    pub log_level: LogLevel,
    pub default_incoming: Policy,
    pub default_outgoing: Policy,
    pub default_routed: RoutedPolicy,
    pub new_profiles: String,
    pub rules: Vec<Rule>,
    /// Rows we could not parse. They keep their number so deletion stays safe, and they are shown
    /// raw rather than silently dropped.
    pub unparsed: Vec<String>,
    /// `false` when running without root, where `ufw` refuses to print rules at all.
    pub rules_readable: bool,
}

impl FirewallState {
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn rule(&self, number: u32) -> Option<&Rule> {
        self.rules.iter().find(|r| r.number == number)
    }

    pub fn index_of(&self, number: u32) -> Option<usize> {
        self.rules.iter().position(|r| r.number == number)
    }

    /// The next rule number `ufw` would assign.
    pub fn next_number(&self) -> u32 {
        self.rules.iter().map(|r| r.number).max().unwrap_or(0) + 1
    }

    /// Rules ufw evaluates for incoming traffic, in order. Route rules are evaluated by a separate
    /// chain and never decide the fate of a packet addressed to this host.
    pub fn incoming_rules(&self) -> impl Iterator<Item = &Rule> {
        self.rules
            .iter()
            .filter(|r| r.direction == crate::core::rule::Direction::In && !r.is_route())
    }

    /// The rule that would let a packet from `client` in on `port`, if any.
    pub fn permitting_rule(&self, port: u16, client: Option<std::net::IpAddr>) -> Option<&Rule> {
        self.incoming_rules().find(|rule| {
            if !rule.action.permits() {
                return false;
            }
            if rule.interface_out.is_some() {
                return false;
            }
            let port_matches = rule.to.port.contains(port) || rule.to.port.is_any();
            if !port_matches {
                return false;
            }
            match (&rule.from.net(), client) {
                (None, _) => true,
                (Some(net), Some(ip)) => net.contains(&ip),
                (Some(_), None) => true,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::rule::{Action, Direction, Endpoint, PortSpec, Protocol, Rule};

    fn rule(number: u32, action: Action, port: PortSpec, from: Option<&str>) -> Rule {
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
            to: Endpoint { addr: None, port },
            log: crate::core::rule::LogMode::None,
            comment: None,
            v6: false,
            route: false,
        }
    }

    #[test]
    fn permitting_rule_respects_source_network() {
        let state = FirewallState {
            rules: vec![
                rule(
                    1,
                    Action::Allow,
                    PortSpec::single(22),
                    Some("192.168.1.0/24"),
                ),
                rule(2, Action::Allow, PortSpec::single(443), None),
            ],
            ..Default::default()
        };
        let lan: std::net::IpAddr = "192.168.1.50".parse().unwrap();
        let wan: std::net::IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(
            state.permitting_rule(22, Some(lan)).map(|r| r.number),
            Some(1)
        );
        assert_eq!(state.permitting_rule(22, Some(wan)).map(|r| r.number), None);
        assert_eq!(
            state.permitting_rule(443, Some(wan)).map(|r| r.number),
            Some(2)
        );
    }

    #[test]
    fn denying_rules_never_permit() {
        let state = FirewallState {
            rules: vec![rule(1, Action::Deny, PortSpec::single(22), None)],
            ..Default::default()
        };
        let lan: std::net::IpAddr = "192.168.1.50".parse().unwrap();
        assert!(state.permitting_rule(22, Some(lan)).is_none());
    }

    #[test]
    fn next_number_follows_the_highest_existing() {
        let state = FirewallState {
            rules: vec![
                rule(1, Action::Allow, PortSpec::Any, None),
                rule(7, Action::Allow, PortSpec::Any, None),
            ],
            ..Default::default()
        };
        assert_eq!(state.next_number(), 8);
    }
}
