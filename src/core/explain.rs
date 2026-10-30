//! Turns rules into plain English.
//!
//! This is the feature that lets someone who has never read `man ufw` understand what they are
//! about to change. Sentences are generated from templates rather than free text so the tone stays
//! consistent, and they are snapshot tested.

use ipnet::IpNet;

use crate::core::rule::{
    parse_net, Action, Direction, Endpoint, PortSpec, Protocol, Rule, RuleDraft,
};

/// Well-known port names, so "TCP port 22" can also read as "SSH".
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

fn is_single_host(net: &IpNet) -> bool {
    net.prefix_len() == net.max_prefix_len()
}

/// "anyone on the internet", "computers on your local network (192.168.1.0/24)", ...
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

/// "TCP port 22 (SSH)", "TCP ports 80 and 443", "the OpenSSH application", "any port".
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

fn action_lead(action: Action) -> &'static str {
    match action {
        Action::Allow => "Allow",
        Action::Deny => "Block",
        Action::Reject => "Refuse",
        Action::Limit => "Allow",
    }
}

/// One sentence describing a draft rule.
pub fn explain_draft(draft: &RuleDraft) -> String {
    let rule = draft.to_rule(0);
    explain_rule(&rule)
}

/// One sentence describing a rule.
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

/// A short verb phrase for table rows, e.g. "allow TCP 22 from anywhere".
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
    fn names_well_known_ports() {
        assert_eq!(service_name(22), Some("SSH"));
        assert_eq!(service_name(443), Some("HTTPS"));
        assert_eq!(service_name(54321), None);
    }

    #[test]
    fn describes_an_open_ssh_rule() {
        assert_eq!(
            explain_rule(&rule(Action::Allow, PortSpec::single(22), None)),
            "Allow anyone on the internet to connect to TCP port 22 (SSH) on this machine."
        );
    }

    #[test]
    fn describes_a_lan_only_rule() {
        assert_eq!(
            explain_rule(&rule(Action::Allow, PortSpec::single(22), Some("192.168.1.0/24"))),
            "Allow computers on your local network (192.168.1.0/24) to connect to TCP port 22 (SSH) on this machine."
        );
    }

    #[test]
    fn describes_a_single_host_source() {
        assert_eq!(
            explain_rule(&rule(Action::Allow, PortSpec::single(443), Some("203.0.113.7"))),
            "Allow the single computer at 203.0.113.7 to connect to TCP port 443 (HTTPS) on this machine."
        );
    }

    #[test]
    fn describes_a_deny_rule_as_blocking() {
        assert_eq!(
            explain_rule(&rule(Action::Deny, PortSpec::single(23), None)),
            "Block anyone on the internet from connecting to TCP port 23 (Telnet) on this machine."
        );
    }

    #[test]
    fn describes_rate_limiting() {
        assert_eq!(
            explain_rule(&rule(Action::Limit, PortSpec::single(22), None)),
            "Allow anyone on the internet to connect to TCP port 22 (SSH) on this machine, but rate-limit repeat attempts."
        );
    }

    #[test]
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
    fn describes_application_profiles() {
        assert_eq!(
            describe_port(&PortSpec::App("OpenSSH".into()), Protocol::Any),
            "the OpenSSH application"
        );
    }

    #[test]
    fn appends_the_note_in_quotes() {
        let mut r = rule(Action::Allow, PortSpec::single(22), None);
        r.comment = Some("Home SSH".into());
        assert!(explain_rule(&r).ends_with("— “Home SSH”."));
    }

    #[test]
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
