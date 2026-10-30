//! Whole-firewall state: everything `ufw status` tells us.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::core::rule::Rule;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
/**
 * The default policy `ufw` applies to traffic that matches no rule.
 *
 * The variants mirror the three words `ufw` accepts for `default allow|deny|reject`.
 *
 * # Variants
 *
 * * `Allow` - Traffic is accepted.
 * * `Deny` - Traffic is silently dropped; this is the default.
 * * `Reject` - Traffic is refused with an ICMP or TCP reset response.
 */
pub enum Policy {
    Allow,
    #[default]
    Deny,
    Reject,
}

impl Policy {
    /**
     * Returns the `ufw` keyword for this policy.
     *
     * # Arguments
     *
     * * `self` (`Policy`) - The policy being converted.
     *
     * # Returns
     *
     * A `&'static str` holding `"allow"`, `"deny"` or `"reject"`.
     */
    pub fn ufw(self) -> &'static str {
        match self {
            Policy::Allow => "allow",
            Policy::Deny => "deny",
            Policy::Reject => "reject",
        }
    }

    /**
     * Returns the upper-case label shown in the UI.
     *
     * # Arguments
     *
     * * `self` (`Policy`) - The policy being labelled.
     *
     * # Returns
     *
     * A `&'static str` holding `"ALLOW"`, `"DENY"` or `"REJECT"`.
     */
    pub fn label(self) -> &'static str {
        match self {
            Policy::Allow => "ALLOW",
            Policy::Deny => "DENY",
            Policy::Reject => "REJECT",
        }
    }

    /**
     * Parses a policy from a status word.
     *
     * # Arguments
     *
     * * `word` (`&str`) - The word to parse; matching is case-insensitive and surrounding
     *   whitespace is ignored.
     *
     * # Returns
     *
     * `Option<Self>` - The matching policy, or `None` when the word is not recognized.
     *
     * # Notes
     *
     * `accept` is treated as `allow` and `drop` as `deny`, matching `ufw`'s own vocabulary.
     */
    pub fn from_word(word: &str) -> Option<Self> {
        match word.trim().to_ascii_lowercase().as_str() {
            "allow" | "accept" => Some(Policy::Allow),
            "deny" | "drop" => Some(Policy::Deny),
            "reject" => Some(Policy::Reject),
            _ => None,
        }
    }

    /**
     * Returns whether this policy allows traffic.
     *
     * # Arguments
     *
     * * `self` (`Policy`) - The policy being tested.
     *
     * # Returns
     *
     * `true` only for [`Policy::Allow`]; otherwise, `false`.
     */
    pub fn permits(self) -> bool {
        self == Policy::Allow
    }
}

impl fmt::Display for Policy {
    /**
     * Implements `std::fmt::Display` for [`Policy`] by writing its label.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The policy being formatted.
     * * `f` (`&mut fmt::Formatter<'_>`) - The formatter to write into.
     *
     * # Returns
     *
     * `fmt::Result` - `Ok(())` when the label was written, or the formatter's error.
     */
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
/**
 * The default policy for forwarded traffic.
 *
 * The routed policy can also be switched off entirely, which `status` prints as
 * `disabled`.
 *
 * # Variants
 *
 * * `Allow` - Forwarded traffic is accepted.
 * * `Deny` - Forwarded traffic is silently dropped.
 * * `Reject` - Forwarded traffic is refused with an ICMP or TCP reset response.
 * * `Disabled` - Routing rules are not applied at all; this is the default.
 */
pub enum RoutedPolicy {
    Allow,
    Deny,
    Reject,
    #[default]
    Disabled,
}

impl RoutedPolicy {
    /**
     * Returns the upper-case label shown in the UI.
     *
     * # Arguments
     *
     * * `self` (`RoutedPolicy`) - The routed policy being labelled.
     *
     * # Returns
     *
     * A `&'static str` holding `"ALLOW"`, `"DENY"`, `"REJECT"` or `"DISABLED"`.
     */
    pub fn label(self) -> &'static str {
        match self {
            RoutedPolicy::Allow => "ALLOW",
            RoutedPolicy::Deny => "DENY",
            RoutedPolicy::Reject => "REJECT",
            RoutedPolicy::Disabled => "DISABLED",
        }
    }

    /**
     * Parses a routed policy from a status word.
     *
     * # Arguments
     *
     * * `word` (`&str`) - The word to parse; matching is case-insensitive and surrounding
     *   whitespace is ignored.
     *
     * # Returns
     *
     * `Option<Self>` - The matching routed policy, or `None` when the word is not
     * recognized.
     *
     * # Notes
     *
     * `accept` is treated as `allow` and `drop` as `deny`; `disabled` is also accepted.
     */
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
    /**
     * Implements `std::fmt::Display` for [`RoutedPolicy`] by writing its label.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The routed policy being formatted.
     * * `f` (`&mut fmt::Formatter<'_>`) - The formatter to write into.
     *
     * # Returns
     *
     * `fmt::Result` - `Ok(())` when the label was written, or the formatter's error.
     */
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
/**
 * How much detail `ufw` writes to the kernel log.
 *
 * The variants are ordered from quietest to noisiest, so they can be compared and
 * sorted directly.
 *
 * # Variants
 *
 * * `Off` - Nothing is logged.
 * * `Low` - Only blocked packets that match a logging rule; this is the default.
 * * `Medium` - Also logs invalid packets and new connections.
 * * `High` - Logs all packets, including rate-limited ones.
 * * `Full` - Logs everything without rate limiting.
 */
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

    /**
     * Returns the `ufw` keyword for this logging level.
     *
     * # Arguments
     *
     * * `self` (`LogLevel`) - The logging level being converted.
     *
     * # Returns
     *
     * A `&'static str` holding `"off"`, `"low"`, `"medium"`, `"high"` or `"full"`.
     */
    pub fn ufw(self) -> &'static str {
        match self {
            LogLevel::Off => "off",
            LogLevel::Low => "low",
            LogLevel::Medium => "medium",
            LogLevel::High => "high",
            LogLevel::Full => "full",
        }
    }

    /**
     * Returns the label shown in the UI.
     *
     * # Arguments
     *
     * * `self` (`LogLevel`) - The logging level being labelled.
     *
     * # Returns
     *
     * A `&'static str` holding the lower-case level name.
     */
    pub fn label(self) -> &'static str {
        match self {
            LogLevel::Off => "off",
            LogLevel::Low => "low",
            LogLevel::Medium => "medium",
            LogLevel::High => "high",
            LogLevel::Full => "full",
        }
    }

    /**
     * Parses a logging level from a status word.
     *
     * # Arguments
     *
     * * `word` (`&str`) - The word to parse; matching is case-insensitive and surrounding
     *   whitespace is ignored.
     *
     * # Returns
     *
     * `Option<Self>` - The matching level, or `None` when the word is not recognized.
     *
     * # Notes
     *
     * `on` is treated as `low`, which is how older `ufw` versions print the level.
     */
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

    /**
     * Returns whether this level generates enough log volume to fill a disk.
     *
     * Levels above `medium` are considered noisy, and the UI warns about them.
     *
     * # Arguments
     *
     * * `self` (`LogLevel`) - The logging level being tested.
     *
     * # Returns
     *
     * `true` for [`LogLevel::High`] and [`LogLevel::Full`]; otherwise, `false`.
     */
    pub fn is_noisy(self) -> bool {
        matches!(self, LogLevel::High | LogLevel::Full)
    }
}

impl fmt::Display for LogLevel {
    /**
     * Implements `std::fmt::Display` for [`LogLevel`] by writing its label.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The logging level being formatted.
     * * `f` (`&mut fmt::Formatter<'_>`) - The formatter to write into.
     *
     * # Returns
     *
     * `fmt::Result` - `Ok(())` when the label was written, or the formatter's error.
     */
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Default)]
/**
 * Everything the app knows about the firewall right now.
 *
 * # Fields
 *
 * * `enabled` (`bool`) - Whether the firewall is active.
 * * `log_level` (`LogLevel`) - The configured logging level.
 * * `default_incoming` (`Policy`) - The default policy for incoming traffic.
 * * `default_outgoing` (`Policy`) - The default policy for outgoing traffic.
 * * `default_routed` (`RoutedPolicy`) - The default policy for forwarded traffic.
 * * `new_profiles` (`String`) - The `New profiles:` setting, usually `skip` or `ask`.
 * * `rules` (`Vec<Rule>`) - The parsed rules, in the order `ufw` evaluates them.
 * * `unparsed` (`Vec<String>`) - Rows we could not parse. They keep their number so deletion stays safe, and they are shown raw rather than silently dropped.
 * * `rules_readable` (`bool`) - `false` when running without root, where `ufw` refuses to print rules at all.
 */
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
    /**
     * Returns the number of parsed rules.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The firewall state being read.
     *
     * # Returns
     *
     * A `usize` holding the length of the rule list.
     */
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /**
     * Looks up a rule by its number.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The firewall state being read.
     * * `number` (`u32`) - The rule number to find.
     *
     * # Returns
     *
     * `Option<&Rule>` - A reference to the first rule with that number, or `None` when no
     * rule matches.
     */
    pub fn rule(&self, number: u32) -> Option<&Rule> {
        self.rules.iter().find(|r| r.number == number)
    }

    /**
     * Returns the position of a rule in the rule list.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The firewall state being read.
     * * `number` (`u32`) - The rule number to locate.
     *
     * # Returns
     *
     * `Option<usize>` - The zero-based index of the first matching rule, or `None` when no
     * rule matches.
     */
    pub fn index_of(&self, number: u32) -> Option<usize> {
        self.rules.iter().position(|r| r.number == number)
    }

    /**
     * Returns the next rule number `ufw` would assign.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The firewall state being read.
     *
     * # Returns
     *
     * A `u32` one greater than the highest existing rule number, or `1` when there are
     * no rules.
     */
    pub fn next_number(&self) -> u32 {
        self.rules.iter().map(|r| r.number).max().unwrap_or(0) + 1
    }

    /**
     * Returns the rules ufw evaluates for incoming traffic, in order.
     *
     * Route rules are evaluated by a separate chain and never decide the fate of a
     * packet addressed to this host, so they are excluded.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The firewall state being read.
     *
     * # Returns
     *
     * An `impl Iterator<Item = &Rule>` yielding the inbound, non-route rules in list
     * order.
     */
    pub fn incoming_rules(&self) -> impl Iterator<Item = &Rule> {
        self.rules
            .iter()
            .filter(|r| r.direction == crate::core::rule::Direction::In && !r.is_route())
    }

    /**
     * Returns the rule that would let a packet from `client` in on `port`, if any.
     *
     * Only inbound, non-route rules that permit traffic are considered. A rule with no
     * source address matches any client; a rule with a source network matches only when
     * the client address falls inside it.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The firewall state being searched.
     * * `port` (`u16`) - The destination port the packet is addressed to.
     * * `client` (`Option<std::net::IpAddr>`) - The source address, or `None` when it is
     *   unknown.
     *
     * # Returns
     *
     * `Option<&Rule>` - The first matching rule in evaluation order, or `None` when no
     * rule would permit the packet.
     */
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

    /**
     * Builds an inbound TCP rule for use in firewall tests.
     *
     * # Arguments
     *
     * * `number` (`u32`) - The rule number to assign.
     * * `action` (`Action`) - The action to assign to the rule.
     * * `port` (`PortSpec`) - The destination port selection.
     * * `from` (`Option<&str>`) - An optional source address.
     *
     * # Returns
     *
     * A `Rule` configured as an inbound TCP rule with the provided values.
     */
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
    /**
     * Verifies that a permitting rule respects the source network.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
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
    /**
     * Verifies that deny rules never count as permitting.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn denying_rules_never_permit() {
        let state = FirewallState {
            rules: vec![rule(1, Action::Deny, PortSpec::single(22), None)],
            ..Default::default()
        };
        let lan: std::net::IpAddr = "192.168.1.50".parse().unwrap();
        assert!(state.permitting_rule(22, Some(lan)).is_none());
    }

    #[test]
    /**
     * Verifies that the next rule number follows the highest existing number.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
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
