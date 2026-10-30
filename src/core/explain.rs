//! Turns rules into plain English.
//!
//! This is the feature that lets someone who has never read `man ufw` understand what they are
//! about to change. Sentences are generated from templates rather than free text so the tone stays
//! consistent, and they are snapshot tested.

use ipnet::IpNet;

use crate::core::rule::{
    parse_net, Action, Direction, Endpoint, PortSpec, Protocol, Rule, RuleDraft,
};

/**
 * Returns the familiar service name for a well-known port.
 *
 * This is used to make generated descriptions easier to scan, for example
 * rendering port 22 as "22 (SSH)".
 *
 * # Arguments
 *
 * * `port` (`u16`) - The port number to look up.
 *
 * # Returns
 *
 * An `Option<&'static str>` containing the service name, or `None` when the
 * port has no name in this table.
 */
pub fn service_name(port: u16) -> Option<&'static str> {
    Some(match port {
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        67 | 68 => "DHCP",
        80 => "HTTP",
        110 => "POP3",
        123 => "NTP",
        137..=139 => "NetBIOS",
        143 => "IMAP",
        161 => "SNMP",
        389 => "LDAP",
        443 => "HTTPS",
        445 => "SMB",
        465 => "SMTPS",
        514 => "syslog",
        587 => "submission",
        631 => "CUPS",
        993 => "IMAPS",
        995 => "POP3S",
        1433 => "SQL Server",
        1521 => "Oracle",
        2049 => "NFS",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5900 => "VNC",
        6379 => "Redis",
        8080 => "HTTP alt",
        9200 => "Elasticsearch",
        11211 => "memcached",
        27017 => "MongoDB",
        _ => return None,
    })
}

/**
 * Returns whether a network is private or link-local.
 *
 * For IPv4, this recognizes the RFC 1918 private ranges and `169.254.0.0/16`.
 * For IPv6, this recognizes unique-local `fc00::/7` and link-local
 * `fe80::/10`.
 *
 * # Arguments
 *
 * * `net` (`&IpNet`) - The network to classify.
 *
 * # Returns
 *
 * `true` if the network is private or link-local; otherwise, `false`.
 */
fn is_private(net: &IpNet) -> bool {
    match net {
        IpNet::V4(v4) => v4.addr().is_private() || v4.addr().is_link_local(),
        IpNet::V6(v6) => {
            let first = v6.addr().segments()[0];
            // fc00::/7 unique-local and fe80::/10 link-local.
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
 * `true` when the prefix length covers exactly one address; otherwise,
 * `false`.
 */
fn is_single_host(net: &IpNet) -> bool {
    net.prefix_len() == net.max_prefix_len()
}

/**
 * Describes who can connect from a rule's source endpoint.
 *
 * Networks recognized as private or link-local are described as a local
 * network; a single-address network is described as one computer. An optional
 * interface is appended to the description.
 *
 * # Arguments
 *
 * * `endpoint` (`&Endpoint`) - The source endpoint to describe. An absent
 *   address means any source.
 * * `iface` (`Option<&str>`) - An optional incoming interface name. `None`
 *   omits interface information.
 *
 * # Returns
 *
 * A `String` containing a plain-English description of the source and, when
 * provided, its interface.
 */
pub fn describe_source(endpoint: &Endpoint, iface: Option<&str>) -> String {
    let mut out = match &endpoint.addr {
        None => "anyone on the internet".to_string(),
        Some(addr) => match parse_net(addr) {
            Some(net) if is_private(&net) => {
                format!("computers on your local network ({addr})")
            }
            Some(net) if is_single_host(&net) => format!("the single computer at {addr}"),
            _ => format!("any computer in {addr}"),
        },
    };
    if let Some(iface) = iface {
        out.push_str(&format!(" arriving on {iface}"));
    }
    out
}

/**
 * Describes the destination endpoint and its optional outgoing interface.
 *
 * An endpoint without an address is described as "the internet".
 *
 * # Arguments
 *
 * * `endpoint` (`&Endpoint`) - The destination endpoint to describe. An absent
 *   address is rendered as "the internet".
 * * `iface` (`Option<&str>`) - An optional outgoing interface name. `None`
 *   omits interface information.
 *
 * # Returns
 *
 * A `String` describing the destination and, when provided, its interface.
 */
fn describe_destination(endpoint: &Endpoint, iface: Option<&str>) -> String {
    let mut out = match &endpoint.addr {
        None => "the internet".to_string(),
        Some(addr) => addr.clone(),
    };
    if let Some(iface) = iface {
        out.push_str(&format!(" on {iface}"));
    }
    out
}

/**
 * Describes a port selection and protocol in plain English.
 *
 * Well-known single ports include their service names, ranges use "to", and
 * application profiles are identified as applications. The protocol is
 * omitted when it is `Protocol::Any`.
 *
 * # Arguments
 *
 * * `port` (`&PortSpec`) - The selected ports, application profile, or
 *   any-port selection.
 * * `protocol` (`Protocol`) - The transport protocol to include in the
 *   description.
 *
 * # Returns
 *
 * A `String` containing a human-readable description of the selection.
 */
pub fn describe_port(port: &PortSpec, protocol: Protocol) -> String {
    let proto = if protocol == Protocol::Any {
        String::new()
    } else {
        format!("{} ", protocol.label().to_uppercase())
    };
    match port {
        PortSpec::Any => "any port".to_string(),
        PortSpec::App(name) => format!("the {name} application"),
        PortSpec::Ports(list) => {
            let rendered: Vec<String> = list
                .iter()
                .map(|range| {
                    if range.is_single() {
                        match service_name(range.start) {
                            Some(service) => format!("{} ({service})", range.start),
                            None => range.start.to_string(),
                        }
                    } else {
                        format!("{} to {}", range.start, range.end)
                    }
                })
                .collect();
            let noun = if rendered.len() == 1 && list[0].is_single() {
                "port"
            } else {
                "ports"
            };
            format!("{proto}{noun} {}", join_and(&rendered))
        }
    }
}

/**
 * Joins items using commas and "and" before the final item.
 *
 * Empty and single-item slices are returned without additional punctuation.
 *
 * # Arguments
 *
 * * `items` (`&[String]`) - The strings to join, in display order.
 *
 * # Returns
 *
 * A `String` containing the joined items.
 */
fn join_and(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [a, b] => format!("{a} and {b}"),
        _ => {
            let (last, rest) = items.split_last().expect("non-empty");
            format!("{} and {last}", rest.join(", "))
        }
    }
}

/**
 * Returns the user-facing lead verb for a firewall action.
 *
 * # Arguments
 *
 * * `action` (`Action`) - The firewall action to render.
 *
 * # Returns
 *
 * A static string containing the lead verb: "Allow", "Block", or "Refuse".
 */
fn action_lead(action: Action) -> &'static str {
    match action {
        Action::Allow => "Allow",
        Action::Deny => "Block",
        Action::Reject => "Refuse",
        Action::Limit => "Allow",
    }
}

/**
 * Produces a plain-English sentence describing a draft rule.
 *
 * The draft is converted to a rule before its explanation is generated.
 *
 * # Arguments
 *
 * * `draft` (`&RuleDraft`) - The rule draft to describe.
 *
 * # Returns
 *
 * A `String` containing a sentence explaining the rule's effect.
 */
pub fn explain_draft(draft: &RuleDraft) -> String {
    let rule = draft.to_rule(0);
    explain_rule(&rule)
}

/**
 * Produces a plain-English sentence describing a firewall rule.
 *
 * The description accounts for the rule's action, direction, endpoints,
 * protocol, rate limiting, and non-empty comment.
 *
 * # Arguments
 *
 * * `rule` (`&Rule`) - The rule to describe.
 *
 * # Returns
 *
 * A `String` containing a sentence explaining the rule's effect.
 */
pub fn explain_rule(rule: &Rule) -> String {
    let lead = action_lead(rule.action);
    let source = describe_source(&rule.from, rule.interface_in.as_deref());
    let destination = describe_destination(&rule.to, rule.interface_out.as_deref());
    let port = describe_port(&rule.to.port, rule.protocol);

    let mut sentence = match rule.direction {
        Direction::In => {
            let verb = match rule.action {
                Action::Deny => "from connecting to",
                Action::Reject => "from connecting to",
                _ => "to connect to",
            };
            if rule.to.port.is_any() {
                format!("{lead} {source} {verb} this machine on any port")
            } else {
                format!("{lead} {source} {verb} {port} on this machine")
            }
        }
        Direction::Out => {
            if rule.to.port.is_any() {
                format!("{lead} traffic from this machine to {destination}")
            } else {
                format!("{lead} traffic from this machine to {destination} on {port}")
            }
        }
        Direction::Forward => {
            format!("{lead} traffic from {source} through this machine to {destination} on {port}")
        }
    };

    if rule.action == Action::Limit {
        sentence.push_str(", but rate-limit repeat attempts");
    }
    if let Some(comment) = &rule.comment {
        if !comment.trim().is_empty() {
            sentence.push_str(&format!(" — “{comment}”"));
        }
    }
    sentence.push('.');
    sentence
}

/**
 * Produces a compact rule summary suitable for a table row.
 *
 * # Arguments
 *
 * * `rule` (`&Rule`) - The rule to summarize.
 *
 * # Returns
 *
 * A `String` containing its action, port or destination, protocol, and source
 * address.
 */
pub fn short_summary(rule: &Rule) -> String {
    let port = match &rule.to.port {
        PortSpec::Any => {
            if let Some(addr) = &rule.to.addr {
                addr.clone()
            } else {
                "all ports".to_string()
            }
        }
        PortSpec::App(name) => name.clone(),
        PortSpec::Ports(list) => list
            .iter()
            .map(|r| r.to_string())
            .collect::<Vec<_>>()
            .join(","),
    };
    let proto = if rule.protocol == Protocol::Any {
        String::new()
    } else {
        format!("/{}", rule.protocol.label())
    };
    let from = rule
        .from
        .addr
        .clone()
        .unwrap_or_else(|| "anywhere".to_string());
    format!("{} {port}{proto} from {from}", rule.action.ufw())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::rule::{Endpoint, PortRange, Rule};

    /**
     * Builds an inbound TCP rule for use in explanation tests.
     *
     * # Arguments
     *
     * * `action` (`Action`) - The action to assign to the rule.
     * * `port` (`PortSpec`) - The destination port selection.
     * * `from` (`Option<&str>`) - An optional source address.
     *
     * # Returns
     *
     * A `Rule` configured as an inbound TCP rule with the provided action,
     * destination port selection, and optional source address.
     */
    fn rule(action: Action, port: PortSpec, from: Option<&str>) -> Rule {
        Rule {
            number: 1,
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
    /** Verifies that well-known ports have service names and unknown ones do not. */
    fn names_well_known_ports() {
        assert_eq!(service_name(22), Some("SSH"));
        assert_eq!(service_name(443), Some("HTTPS"));
        assert_eq!(service_name(54321), None);
    }

    #[test]
    /** Verifies the explanation generated for an unrestricted inbound SSH rule. */
    fn describes_an_open_ssh_rule() {
        assert_eq!(
            explain_rule(&rule(Action::Allow, PortSpec::single(22), None)),
            "Allow anyone on the internet to connect to TCP port 22 (SSH) on this machine."
        );
    }

    #[test]
    /** Verifies that a private source network is described as a local network. */
    fn describes_a_lan_only_rule() {
        assert_eq!(
            explain_rule(&rule(Action::Allow, PortSpec::single(22), Some("192.168.1.0/24"))),
            "Allow computers on your local network (192.168.1.0/24) to connect to TCP port 22 (SSH) on this machine."
        );
    }

    #[test]
    /** Verifies that a single-address source is described as one computer. */
    fn describes_a_single_host_source() {
        assert_eq!(
            explain_rule(&rule(Action::Allow, PortSpec::single(443), Some("203.0.113.7"))),
            "Allow the single computer at 203.0.113.7 to connect to TCP port 443 (HTTPS) on this machine."
        );
    }

    #[test]
    /** Verifies that a deny action is described using "Block". */
    fn describes_a_deny_rule_as_blocking() {
        assert_eq!(
            explain_rule(&rule(Action::Deny, PortSpec::single(23), None)),
            "Block anyone on the internet from connecting to TCP port 23 (Telnet) on this machine."
        );
    }

    #[test]
    /** Verifies that limit actions mention rate-limiting repeat attempts. */
    fn describes_rate_limiting() {
        assert_eq!(
            explain_rule(&rule(Action::Limit, PortSpec::single(22), None)),
            "Allow anyone on the internet to connect to TCP port 22 (SSH) on this machine, but rate-limit repeat attempts."
        );
    }

    #[test]
    /** Verifies formatting for lists of ports and port ranges. */
    fn describes_port_lists_and_ranges() {
        assert_eq!(
            describe_port(
                &PortSpec::Ports(vec![PortRange::single(80), PortRange::single(443)]),
                Protocol::Tcp
            ),
            "TCP ports 80 (HTTP) and 443 (HTTPS)"
        );
        assert_eq!(
            describe_port(
                &PortSpec::Ports(vec![PortRange::new(8000, 8100).unwrap()]),
                Protocol::Tcp
            ),
            "TCP ports 8000 to 8100"
        );
    }

    #[test]
    /** Verifies that application profiles are described by their profile name. */
    fn describes_application_profiles() {
        assert_eq!(
            describe_port(&PortSpec::App("OpenSSH".into()), Protocol::Any),
            "the OpenSSH application"
        );
    }

    #[test]
    /** Verifies that a non-empty rule comment is appended in quotation marks. */
    fn appends_the_note_in_quotes() {
        let mut r = rule(Action::Allow, PortSpec::single(22), None);
        r.comment = Some("Home SSH".into());
        assert!(explain_rule(&r).ends_with("— “Home SSH”."));
    }

    #[test]
    /** Verifies the description of an outbound UDP rule. */
    fn describes_outbound_rules() {
        let mut r = rule(Action::Allow, PortSpec::single(53), None);
        r.direction = Direction::Out;
        r.protocol = Protocol::Udp;
        assert_eq!(
            explain_rule(&r),
            "Allow traffic from this machine to the internet on UDP port 53 (DNS)."
        );
    }
}
