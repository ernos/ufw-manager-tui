//! Risk assessment.
//!
//! The point is not to score rules for their own sake: it is to answer "is this machine exposed?"
//! and "what should I do about it?" for somebody who has no basis for forming an opinion.

use std::fmt;

use ipnet::IpNet;

use crate::core::firewall::{FirewallState, Policy};
use crate::core::parse::{AppProfile, Listening};
use crate::core::rule::{Action, Direction, PortSpec, Rule};

/**
 * Ports that give an attacker remote control of, or data from, the machine.
 *
 * The list covers common remote-access, file-sharing, database and
 * administration services; a rule exposing one of these to the internet is
 * treated as critical.
 */
pub const SENSITIVE_PORTS: [u16; 20] = [
    21, 22, 23, 25, 111, 135, 139, 445, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 5986, 6379,
    9200, 27017,
];

/**
 * Returns whether a port is one that grants remote control or data access.
 *
 * # Arguments
 *
 * * `port` (`u16`) - The port to classify.
 *
 * # Returns
 *
 * `true` when the port appears in [`SENSITIVE_PORTS`]; otherwise, `false`.
 */
pub fn is_sensitive_port(port: u16) -> bool {
    SENSITIVE_PORTS.contains(&port)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
/**
 * How dangerous a rule or firewall state is.
 *
 * The levels are ordered from least to most severe, so they can be compared
 * and sorted directly. They drive the colour and badge shown next to a rule
 * and the ordering of whole-firewall advice.
 *
 * # Variants
 *
 * * `Info` - Nothing to worry about; the rule blocks traffic or is outbound.
 * * `Low` - Exposure is limited to a private network or a single host.
 * * `Medium` - Exposure reaches a public network, or the rule forwards traffic.
 * * `High` - A port is reachable from the entire internet.
 * * `Critical` - A remote-access port is reachable from the entire internet.
 */
pub enum RiskLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    /**
     * Returns the lowercase name of the risk level.
     *
     * # Arguments
     *
     * * `self` (`RiskLevel`) - The level being rendered; it is read, not
     *   mutated.
     *
     * # Returns
     *
     * A `&'static str` containing `info`, `low`, `medium`, `high` or
     * `critical`.
     */
    pub fn label(self) -> &'static str {
        match self {
            RiskLevel::Info => "info",
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }

    /**
     * Returns a short ASCII badge for the risk level.
     *
     * This is a text fallback so risk is never conveyed by colour alone, which
     * matters for `NO_COLOR` and monochrome terminals.
     *
     * # Arguments
     *
     * * `self` (`RiskLevel`) - The level being rendered; it is read, not
     *   mutated.
     *
     * # Returns
     *
     * A `&'static str` containing `[i]`, `[ok]`, `[~]`, `[!]` or `[!!]`.
     */
    pub fn ascii_badge(self) -> &'static str {
        match self {
            RiskLevel::Info => "[i]",
            RiskLevel::Low => "[ok]",
            RiskLevel::Medium => "[~]",
            RiskLevel::High => "[!]",
            RiskLevel::Critical => "[!!]",
        }
    }

    /**
     * Returns the next more severe risk level.
     *
     * `Critical` is already the maximum, so it stays `Critical`.
     *
     * # Arguments
     *
     * * `self` (`RiskLevel`) - The level being raised; it is read, not mutated.
     *
     * # Returns
     *
     * The `RiskLevel` one step more severe than `self`.
     */
    pub fn upgrade(self) -> Self {
        match self {
            RiskLevel::Info => RiskLevel::Low,
            RiskLevel::Low => RiskLevel::Medium,
            RiskLevel::Medium => RiskLevel::High,
            RiskLevel::High | RiskLevel::Critical => RiskLevel::Critical,
        }
    }

    /**
     * Returns the next less severe risk level.
     *
     * `Info` is already the minimum, so it stays `Info`.
     *
     * # Arguments
     *
     * * `self` (`RiskLevel`) - The level being lowered; it is read, not
     *   mutated.
     *
     * # Returns
     *
     * The `RiskLevel` one step less severe than `self`.
     */
    pub fn downgrade(self) -> Self {
        match self {
            RiskLevel::Critical => RiskLevel::High,
            RiskLevel::High => RiskLevel::Medium,
            RiskLevel::Medium => RiskLevel::Low,
            RiskLevel::Low | RiskLevel::Info => RiskLevel::Info,
        }
    }

    /**
     * Returns a numeric sort key for "worst first" ordering.
     *
     * # Arguments
     *
     * * `self` (`RiskLevel`) - The level being ranked; it is read, not mutated.
     *
     * # Returns
     *
     * A `u8` from `0` for `Info` up to `4` for `Critical`.
     */
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
    /**
     * Implements `Display` by writing the lowercase level name.
     *
     * # Arguments
     *
     * * `&self` - The level being formatted; it is read, not mutated.
     * * `f` (`&mut fmt::Formatter<'_>`) - The formatter to write into.
     *
     * # Returns
     *
     * A `fmt::Result` that is `Ok(())` when the write succeeds, or the
     * formatter's error when it does not.
     */
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/**
 * The risk verdict for a single rule, with the reasoning behind it.
 *
 * The reasons are shown to the user so the level is never an unexplained
 * number.
 *
 * # Fields
 *
 * * `level` (`RiskLevel`) - The assessed severity.
 * * `reasons` (`Vec<String>`) - Plain-English reasons for the level, in the
 *   order they were discovered.
 */
pub struct Assessment {
    pub level: RiskLevel,
    pub reasons: Vec<String>,
}

impl Assessment {
    /**
     * Builds an assessment with a single reason.
     *
     * # Arguments
     *
     * * `level` (`RiskLevel`) - The assessed risk level.
     * * `reason` (`impl Into<String>`) - The first reason explaining the level.
     *
     * # Returns
     *
     * An `Assessment` holding the level and one reason.
     */
    fn new(level: RiskLevel, reason: impl Into<String>) -> Self {
        Self {
            level,
            reasons: vec![reason.into()],
        }
    }

    /**
     * Joins all reasons into one sentence fragment.
     *
     * # Arguments
     *
     * * `&self` - The assessment being read.
     *
     * # Returns
     *
     * A `String` with the reasons separated by `; `.
     */
    pub fn summary(&self) -> String {
        self.reasons.join("; ")
    }
}

/**
 * Returns whether a network is private or link-local.
 *
 * For IPv4 this recognizes the RFC 1918 ranges and `169.254.0.0/16`; for IPv6
 * it recognizes unique-local `fc00::/7` and link-local `fe80::/10`.
 *
 * # Arguments
 *
 * * `net` (`&IpNet`) - The network to classify.
 *
 * # Returns
 *
 * `true` when the network is private or link-local; otherwise, `false`.
 */
fn is_private(net: &IpNet) -> bool {
    match net {
        IpNet::V4(v4) => v4.addr().is_private() || v4.addr().is_link_local(),
        IpNet::V6(v6) => {
            let first = v6.addr().segments()[0];
            (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
    }
}

/**
 * Returns whether a network contains exactly one address.
 *
 * # Arguments
 *
 * * `net` (`&IpNet`) - The network to check.
 *
 * # Returns
 *
 * `true` when the prefix length covers a single address; otherwise, `false`.
 */
fn is_single_host(net: &IpNet) -> bool {
    net.prefix_len() == net.max_prefix_len()
}

/**
 * Returns the sensitive ports a rule opens.
 *
 * Application profiles are resolved through the supplied profile list. Ranges
 * of up to 65 ports are expanded; wider ranges contribute only their bounds.
 *
 * # Arguments
 *
 * * `rule` (`&Rule`) - The rule whose destination ports are inspected.
 * * `profiles` (`&[AppProfile]`) - Application profiles used to resolve
 *   profile-based rules.
 *
 * # Returns
 *
 * A `Vec<u16>` of the sensitive ports the rule exposes, possibly empty.
 */
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

/**
 * Assesses how much exposure a single rule creates.
 *
 * Blocking rules and outgoing rules are informational. Forwarding rules are
 * medium risk because the incoming default policy does not cover them. For
 * permitting incoming rules the level depends on the source: the whole
 * internet is high, or critical when a remote-access port is exposed; a
 * private network or single host is low; a public network is medium, or high
 * with a remote-access port. Rate limiting lowers the level by one step, and
 * IPv6 variants add a note.
 *
 * # Arguments
 *
 * * `rule` (`&Rule`) - The rule to assess.
 * * `profiles` (`&[AppProfile]`) - Application profiles used to resolve
 *   profile-based rules.
 *
 * # Returns
 *
 * An `Assessment` containing the risk level and the reasons for it.
 */
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

#[derive(Debug, Clone, PartialEq, Eq)]
/**
 * A concrete thing the user could fix.
 *
 * Each suggestion carries enough context for the UI to offer it as a single
 * keypress, and an optional [`Fix`] describing the action to take.
 *
 * # Fields
 *
 * * `level` (`RiskLevel`) - How urgent the suggestion is.
 * * `text` (`String`) - The plain-English advice shown to the user.
 * * `fix` (`Option<Fix>`) - The one-keypress remedy, when one exists.
 */
pub struct Suggestion {
    pub level: RiskLevel,
    pub text: String,
    pub fix: Option<Fix>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/**
 * A one-keypress remedy for a [`Suggestion`].
 *
 * # Variants
 *
 * * `TurnOnFirewall` - Enable the firewall.
 * * `FixDefaultIncoming` - Change the default incoming policy to deny.
 * * `RestrictSshToLan` - Narrow an SSH rule to the local network.
 * * `RateLimitSsh` - Replace an SSH allow rule with a rate-limited one.
 */
pub enum Fix {
    TurnOnFirewall,
    FixDefaultIncoming,
    RestrictSshToLan,
    RateLimitSsh,
}

/**
 * Produces whole-firewall advice, worst first.
 *
 * The suggestions cover a disabled firewall, a permissive incoming default,
 * SSH open to the internet, unmentioned listening services, logging being off,
 * and rules that expose remote-access ports. Nothing is returned when the rule
 * set could not be read.
 *
 * # Arguments
 *
 * * `state` (`&FirewallState`) - The firewall state to assess.
 * * `listening` (`&[Listening]`) - The listening sockets found on the machine.
 * * `ssh_port` (`Option<u16>`) - The SSH port to check, when known.
 * * `profiles` (`&[AppProfile]`) - Application profiles used to resolve
 *   profile-based rules.
 *
 * # Returns
 *
 * A `Vec<Suggestion>` sorted from most to least severe.
 */
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

/**
 * Finds rules that are unreachable because an earlier rule already matches
 * their traffic.
 *
 * This is the single most common `ufw` mistake: a broad rule above a specific
 * one means the specific rule never runs. Only permitting incoming,
 * non-forwarding rules are considered.
 *
 * # Arguments
 *
 * * `rules` (`&[Rule]`) - The rule set to inspect, in evaluation order.
 * * `profiles` (`&[AppProfile]`) - Application profiles used to resolve
 *   profile-based rules.
 *
 * # Returns
 *
 * A `Vec<(u32, u32)>` of `(shadowed_rule, shadowing_rule)` number pairs.
 */
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

/**
 * Returns the concrete port ranges a specification stands for.
 *
 * Application profiles are resolved, which is what makes "allow 22/tcp"
 * correctly shadow "allow OpenSSH".
 *
 * # Arguments
 *
 * * `spec` (`&PortSpec`) - The port selection to expand.
 * * `profiles` (`&[AppProfile]`) - Application profiles used to resolve
 *   profile-based selections.
 *
 * # Returns
 *
 * An `Option<Vec<PortRange>>` containing the ranges, or `None` when the
 * specification means "any port" or names an unknown profile.
 */
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

/**
 * Returns what a rule actually exposes: its concrete ports and protocols.
 *
 * A `None` in either position means "anything", which is what makes a broad
 * rule cover a narrow one.
 *
 * # Arguments
 *
 * * `rule` (`&Rule`) - The rule to inspect.
 * * `profiles` (`&[AppProfile]`) - Application profiles used to resolve
 *   profile-based rules.
 *
 * # Returns
 *
 * A tuple of `Option<Vec<PortRange>>` and `Option<Vec<Protocol>>` describing
 * the exposed ports and protocols.
 */
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

/**
 * Returns whether `broad` matches everything `narrow` would match.
 *
 * The address, ports, protocol and interface of `broad` must each cover the
 * corresponding part of `narrow`. Identical rules are not considered covering,
 * because the second is redundant rather than shadowed.
 *
 * # Arguments
 *
 * * `broad` (`&Rule`) - The earlier, potentially broader rule.
 * * `narrow` (`&Rule`) - The later rule that may be shadowed.
 * * `profiles` (`&[AppProfile]`) - Application profiles used to resolve
 *   profile-based rules.
 *
 * # Returns
 *
 * `true` when `broad` covers `narrow`; otherwise, `false`.
 */
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

    /**
     * Builds an inbound TCP rule for use in risk tests.
     *
     * # Arguments
     *
     * * `number` (`u32`) - The rule number to assign.
     * * `action` (`Action`) - The action the rule applies.
     * * `ports` (`PortSpec`) - The destination port selection.
     * * `from` (`Option<&str>`) - An optional source address.
     *
     * # Returns
     *
     * A `Rule` configured as an inbound TCP rule with the given fields.
     */
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
    /**
     * Verifies that SSH open to the internet is rated critical.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn open_ssh_is_critical() {
        let a = assess_rule(&rule(1, Action::Allow, PortSpec::single(22), None), &[]);
        assert_eq!(a.level, RiskLevel::Critical);
    }

    #[test]
    /**
     * Verifies that a non-sensitive open port is only high risk.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn open_high_port_is_only_high() {
        let a = assess_rule(&rule(1, Action::Allow, PortSpec::single(8080), None), &[]);
        assert_eq!(a.level, RiskLevel::High);
    }

    #[test]
    /**
     * Verifies that a private-network source lowers the risk.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
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
    /**
     * Verifies that a single-host source lowers the risk.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn single_host_source_is_low() {
        let a = assess_rule(
            &rule(1, Action::Allow, PortSpec::single(22), Some("203.0.113.7")),
            &[],
        );
        assert_eq!(a.level, RiskLevel::Low);
    }

    #[test]
    /**
     * Verifies that a public network source is medium risk.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
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
    /**
     * Verifies that blocking rules are informational.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn deny_rules_are_informational() {
        let a = assess_rule(&rule(1, Action::Deny, PortSpec::single(22), None), &[]);
        assert_eq!(a.level, RiskLevel::Info);
    }

    #[test]
    /**
     * Verifies that rate limiting lowers the level by one step.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn rate_limiting_downgrades_one_step() {
        let a = assess_rule(&rule(1, Action::Limit, PortSpec::single(22), None), &[]);
        assert_eq!(a.level, RiskLevel::High);
        assert!(a.reasons.iter().any(|r| r.contains("rate limited")));
    }

    #[test]
    /**
     * Verifies that application profiles resolve to their sensitive ports.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
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
    /**
     * Verifies that an unreadable rule set produces no advice.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn unreadable_state_produces_no_advice() {
        let state = FirewallState {
            rules_readable: false,
            ..Default::default()
        };
        assert!(assess_state(&state, &[], None, &[]).is_empty());
    }

    #[test]
    /**
     * Verifies that a disabled firewall is the most severe suggestion.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
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
    /**
     * Verifies that SSH open to the world suggests restricting it.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
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
    /**
     * Verifies that LAN-only SSH does not suggest restricting it.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
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
    /**
     * Verifies that disabled logging is reported.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
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
    /**
     * Verifies that a broad rule shadowing a narrow one is detected.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
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
    /**
     * Verifies that the reverse rule order is not flagged.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
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
    /**
     * Verifies that unrelated rules are not flagged.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn does_not_flag_unrelated_rules() {
        let rules = vec![
            rule(1, Action::Allow, PortSpec::single(22), None),
            rule(2, Action::Allow, PortSpec::single(443), None),
        ];
        assert!(find_shadowed(&rules, &[]).is_empty());
    }

    #[test]
    /**
     * Verifies that identical rules are not treated as shadowing.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn does_not_flag_identical_rules_as_shadowing() {
        let rules = vec![
            rule(1, Action::Allow, PortSpec::single(22), None),
            rule(2, Action::Allow, PortSpec::single(22), None),
        ];
        assert!(find_shadowed(&rules, &[]).is_empty());
    }

    #[test]
    /**
     * Verifies that a port range shadowing a single port is detected.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
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
