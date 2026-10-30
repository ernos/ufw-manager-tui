//! The rule model.
//!
//! A [`Rule`] is the parsed form of one `ufw status numbered` row. A [`RuleDraft`] is the
//! editable form used by the wizard, the raw form, the command builder and the simulator.

use std::fmt;
use std::str::FromStr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Anything in ufw that decides the fate of a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Action {
    Allow,
    Deny,
    Reject,
    Limit,
}

impl Action {
    pub const ALL: [Action; 4] = [Action::Allow, Action::Deny, Action::Reject, Action::Limit];

    /// The word `ufw` expects on the command line.
    pub fn ufw(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Deny => "deny",
            Action::Reject => "reject",
            Action::Limit => "limit",
        }
    }

    /// The word `ufw status` prints.
    pub fn label(self) -> &'static str {
        match self {
            Action::Allow => "ALLOW",
            Action::Deny => "DENY",
            Action::Reject => "REJECT",
            Action::Limit => "LIMIT",
        }
    }

    /// How the action reads in a sentence.
    pub fn verb(self) -> &'static str {
        match self {
            Action::Allow => "Allow",
            Action::Deny => "Block",
            Action::Reject => "Refuse",
            Action::Limit => "Allow (rate limited)",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label.to_ascii_uppercase().as_str() {
            "ALLOW" => Some(Action::Allow),
            "DENY" => Some(Action::Deny),
            "REJECT" => Some(Action::Reject),
            "LIMIT" => Some(Action::Limit),
            _ => None,
        }
    }

    /// Deny, reject and limit do not let traffic through unconditionally.
    pub fn permits(self) -> bool {
        matches!(self, Action::Allow | Action::Limit)
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.ufw())
    }
}

impl FromStr for Action {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Action::from_label(s).ok_or_else(|| format!("unknown action '{s}'"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Direction {
    In,
    Out,
    Forward,
}

impl Direction {
    pub const ALL: [Direction; 3] = [Direction::In, Direction::Out, Direction::Forward];

    pub fn ufw(self) -> Option<&'static str> {
        match self {
            Direction::In => Some("in"),
            Direction::Out => Some("out"),
            Direction::Forward => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Direction::In => "IN",
            Direction::Out => "OUT",
            Direction::Forward => "FWD",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label.to_ascii_uppercase().as_str() {
            "IN" => Some(Direction::In),
            "OUT" => Some(Direction::Out),
            "FWD" => Some(Direction::Forward),
            _ => None,
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Any,
    Tcp,
    Udp,
    Sctp,
    Esp,
    Ah,
    Gre,
    Igmp,
    Icmp,
    Icmpv6,
}

impl Protocol {
    pub const COMMON: [Protocol; 3] = [Protocol::Tcp, Protocol::Udp, Protocol::Any];

    pub fn ufw(self) -> Option<&'static str> {
        match self {
            Protocol::Any => None,
            Protocol::Tcp => Some("tcp"),
            Protocol::Udp => Some("udp"),
            Protocol::Sctp => Some("sctp"),
            Protocol::Esp => Some("esp"),
            Protocol::Ah => Some("ah"),
            Protocol::Gre => Some("gre"),
            Protocol::Igmp => Some("igmp"),
            Protocol::Icmp => Some("icmp"),
            Protocol::Icmpv6 => Some("ipv6-icmp"),
        }
    }

    pub fn label(self) -> &'static str {
        self.ufw().unwrap_or("any")
    }

    /// Protocol names that may appear as a `/<proto>` suffix in `ufw status` output.
    pub fn from_status_token(token: &str) -> Option<Self> {
        match token.to_ascii_lowercase().as_str() {
            "tcp" => Some(Protocol::Tcp),
            "udp" => Some(Protocol::Udp),
            "sctp" => Some(Protocol::Sctp),
            "esp" => Some(Protocol::Esp),
            "ah" => Some(Protocol::Ah),
            "gre" => Some(Protocol::Gre),
            "igmp" => Some(Protocol::Igmp),
            "icmp" => Some(Protocol::Icmp),
            "ipv6-icmp" | "icmpv6" => Some(Protocol::Icmpv6),
            _ => None,
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl FromStr for Protocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("any") {
            return Ok(Protocol::Any);
        }
        Protocol::from_status_token(s).ok_or_else(|| format!("unknown protocol '{s}'"))
    }
}

/// A single port or an inclusive port range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    pub fn new(start: u16, end: u16) -> Result<Self, String> {
        if start == 0 || end == 0 {
            return Err("ports must be between 1 and 65535".into());
        }
        if start > end {
            return Err(format!("port range start {start} is above its end {end}"));
        }
        Ok(Self { start, end })
    }

    pub fn is_single(&self) -> bool {
        self.start == self.end
    }

    pub fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_single() {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}:{}", self.start, self.end)
        }
    }
}

impl FromStr for PortRange {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once(':') {
            Some((a, b)) => {
                let start = a
                    .trim()
                    .parse::<u16>()
                    .map_err(|_| format!("bad port '{a}'"))?;
                let end = b
                    .trim()
                    .parse::<u16>()
                    .map_err(|_| format!("bad port '{b}'"))?;
                PortRange::new(start, end)
            }
            None => {
                let port = s
                    .trim()
                    .parse::<u16>()
                    .map_err(|_| format!("bad port '{s}'"))?;
                PortRange::new(port, port)
            }
        }
    }
}

/// What a rule points at: nothing in particular, a set of ports, or an application profile.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum PortSpec {
    #[default]
    Any,
    Ports(Vec<PortRange>),
    App(String),
}

impl PortSpec {
    pub fn single(port: u16) -> Self {
        PortSpec::Ports(vec![PortRange::single(port)])
    }

    pub fn is_any(&self) -> bool {
        matches!(self, PortSpec::Any)
    }

    /// True when the spec covers exactly one port, which is the only case `ufw` accepts in its
    /// simple syntax without an explicit protocol.
    pub fn single_port(&self) -> Option<u16> {
        match self {
            PortSpec::Ports(list) if list.len() == 1 && list[0].is_single() => Some(list[0].start),
            _ => None,
        }
    }

    pub fn contains(&self, port: u16) -> bool {
        match self {
            PortSpec::Any => true,
            PortSpec::Ports(list) => list.iter().any(|r| r.contains(port)),
            // An application profile only matches through its expansion; the caller resolves it.
            PortSpec::App(_) => false,
        }
    }

    pub fn is_range_or_list(&self) -> bool {
        match self {
            PortSpec::Ports(list) => list.len() > 1 || list.iter().any(|r| !r.is_single()),
            _ => false,
        }
    }

    /// The lowest port the spec mentions, used to build a representative test packet.
    pub fn first_port(&self) -> Option<u16> {
        match self {
            PortSpec::Any => None,
            PortSpec::App(_) => None,
            PortSpec::Ports(list) => list.iter().map(|r| r.start).min(),
        }
    }
}

impl fmt::Display for PortSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortSpec::Any => f.write_str("any"),
            PortSpec::App(name) => f.write_str(name),
            PortSpec::Ports(list) => {
                let joined = list
                    .iter()
                    .map(|r| r.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                f.write_str(&joined)
            }
        }
    }
}

impl FromStr for PortSpec {
    type Err = String;

    /// Parses `any`, `22`, `22:80`, `80,443`, `8000:8100,9000` and bare service or app names.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() || s.eq_ignore_ascii_case("any") {
            return Ok(PortSpec::Any);
        }
        if s.chars()
            .all(|c| c.is_ascii_digit() || c == ':' || c == ',')
        {
            let mut out = Vec::new();
            for part in s.split(',') {
                out.push(part.parse::<PortRange>()?);
            }
            return Ok(PortSpec::Ports(out));
        }
        Ok(PortSpec::App(s.to_string()))
    }
}

/// One side of a rule: an optional address plus a port specification.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    /// `None` means "any address".
    pub addr: Option<String>,
    pub port: PortSpec,
}

impl Endpoint {
    pub fn any() -> Self {
        Self {
            addr: None,
            port: PortSpec::Any,
        }
    }

    pub fn port(port: u16) -> Self {
        Self {
            addr: None,
            port: PortSpec::single(port),
        }
    }

    pub fn from_addr(addr: impl Into<String>) -> Self {
        Self {
            addr: Some(addr.into()),
            port: PortSpec::Any,
        }
    }

    pub fn is_any(&self) -> bool {
        self.addr.is_none() && self.port.is_any()
    }

    /// The address as a network, when it parses as one.
    pub fn net(&self) -> Option<IpNet> {
        parse_net(self.addr.as_deref()?)
    }

    /// `Anywhere`, `Anywhere on eth0` or the address, for display.
    pub fn addr_label(&self, iface: Option<&str>) -> String {
        let mut out = match &self.addr {
            Some(addr) => addr.clone(),
            None => "Anywhere".to_string(),
        };
        if let Some(iface) = iface {
            out.push_str(" on ");
            out.push_str(iface);
        }
        out
    }
}

/// Parses `1.2.3.4`, `1.2.3.0/24` or `2001:db8::/32` into a network.
pub fn parse_net(value: &str) -> Option<IpNet> {
    let value = value.trim();
    if let Ok(net) = value.parse::<IpNet>() {
        return Some(net);
    }
    value.parse::<std::net::IpAddr>().ok().map(IpNet::from)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LogMode {
    None,
    Log,
    LogAll,
}

impl LogMode {
    pub fn ufw(self) -> Option<&'static str> {
        match self {
            LogMode::None => None,
            LogMode::Log => Some("log"),
            LogMode::LogAll => Some("log-all"),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            LogMode::None => "off",
            LogMode::Log => "log",
            LogMode::LogAll => "log-all",
        }
    }
}

/// One row of `ufw status numbered`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// `ufw`'s own rule number, i.e. the `N` in `ufw delete N`. `0` marks a rule that does not
    /// exist yet (a pending draft shown in the simulator).
    pub number: u32,
    pub action: Action,
    pub direction: Direction,
    pub interface_in: Option<String>,
    pub interface_out: Option<String>,
    pub protocol: Protocol,
    pub from: Endpoint,
    pub to: Endpoint,
    pub log: LogMode,
    pub comment: Option<String>,
    pub v6: bool,
    /// Forward rules are shown but not editable in v1.
    pub route: bool,
}

impl Rule {
    pub fn is_pending(&self) -> bool {
        self.number == 0
    }

    pub fn is_route(&self) -> bool {
        self.route || self.direction == Direction::Forward
    }

    /// The port a rule is about, preferring the destination for incoming rules.
    pub fn primary_port(&self) -> PortSpec {
        match self.direction {
            Direction::Out => self.to.port.clone(),
            _ => self.to.port.clone(),
        }
    }

    pub fn comment_text(&self) -> &str {
        self.comment.as_deref().unwrap_or("")
    }

    /// A stable identity for a rule, used to check that a rule number still refers to the rule we
    /// think it does after a refresh.
    pub fn signature(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.action.ufw(),
            self.direction.label(),
            self.interface_in.as_deref().unwrap_or(""),
            self.interface_out.as_deref().unwrap_or(""),
            self.protocol.label(),
            self.from.addr.clone().unwrap_or_default(),
            self.from.port,
            self.to.addr.clone().unwrap_or_default(),
            self.to.port,
        )
    }

    /// Converts back into an editable draft. Lossy only for route rules, which are read-only.
    pub fn to_draft(&self) -> RuleDraft {
        RuleDraft {
            action: self.action,
            direction: self.direction,
            interface_in: self.interface_in.clone(),
            protocol: self.protocol,
            from_addr: self.from.addr.clone(),
            from_port: self.from.port.clone(),
            to_addr: self.to.addr.clone(),
            to_port: self.to.port.clone(),
            log: self.log,
            comment: self.comment.clone(),
        }
    }
}

/// The editable form of a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleDraft {
    pub action: Action,
    pub direction: Direction,
    pub interface_in: Option<String>,
    pub protocol: Protocol,
    pub from_addr: Option<String>,
    pub from_port: PortSpec,
    pub to_addr: Option<String>,
    pub to_port: PortSpec,
    pub log: LogMode,
    pub comment: Option<String>,
}

impl Default for RuleDraft {
    fn default() -> Self {
        Self {
            action: Action::Allow,
            direction: Direction::In,
            interface_in: None,
            protocol: Protocol::Any,
            from_addr: None,
            from_port: PortSpec::Any,
            to_addr: None,
            to_port: PortSpec::Any,
            log: LogMode::None,
            comment: None,
        }
    }
}

impl RuleDraft {
    pub fn allow_port(protocol: Protocol, port: u16) -> Self {
        Self {
            protocol,
            to_port: PortSpec::single(port),
            ..Default::default()
        }
    }

    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        let text = comment.into();
        self.comment = if text.is_empty() { None } else { Some(text) };
        self
    }

    pub fn from_anywhere(mut self, addr: impl Into<String>) -> Self {
        self.from_addr = Some(addr.into());
        self
    }

    pub fn on_interface(mut self, iface: impl Into<String>) -> Self {
        self.interface_in = Some(iface.into());
        self
    }

    /// Catches the mistakes a newcomer is most likely to make before `ufw` sees them, so the error
    /// can be phrased in plain English.
    pub fn validate(&self) -> Result<(), String> {
        if self.direction == Direction::Forward {
            return Err("forward rules are not supported yet — they are shown read-only".into());
        }
        if let Some(addr) = &self.from_addr {
            if parse_net(addr).is_none() {
                return Err(format!(
                    "'{addr}' is not an address or network. Try something like 192.168.1.0/24 or 203.0.113.7"
                ));
            }
        }
        if let Some(addr) = &self.to_addr {
            if parse_net(addr).is_none() {
                return Err(format!("'{addr}' is not an address or network"));
            }
        }
        let uses_profile =
            matches!(self.to_port, PortSpec::App(_)) || matches!(self.from_port, PortSpec::App(_));
        if uses_profile && self.protocol != Protocol::Any {
            return Err(
                "application profiles already know their protocol, so do not also choose one"
                    .into(),
            );
        }
        let needs_proto = self.to_port.is_range_or_list() || self.from_port.is_range_or_list();
        if needs_proto && self.protocol == Protocol::Any {
            return Err("a port range or list needs a protocol (TCP or UDP). Pick one.".into());
        }
        if self.to_port.is_any()
            && self.from_port.is_any()
            && self.to_addr.is_none()
            && self.from_addr.is_none()
            && self.interface_in.is_none()
        {
            return Err(
                "this rule would match all traffic; choose a port, address or interface".into(),
            );
        }
        Ok(())
    }

    pub fn to_rule(&self, number: u32) -> Rule {
        Rule {
            number,
            action: self.action,
            direction: self.direction,
            interface_in: self.interface_in.clone(),
            interface_out: None,
            protocol: self.protocol,
            from: Endpoint {
                addr: self.from_addr.clone(),
                port: self.from_port.clone(),
            },
            to: Endpoint {
                addr: self.to_addr.clone(),
                port: self.to_port.clone(),
            },
            log: self.log,
            comment: self.comment.clone(),
            v6: false,
            route: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_range_rejects_inverted_bounds() {
        assert!(PortRange::new(90, 80).is_err());
        assert!(PortRange::new(0, 80).is_err());
        assert!(PortRange::new(80, 80).is_ok());
    }

    #[test]
    fn port_spec_parses_common_forms() {
        assert_eq!("any".parse::<PortSpec>().unwrap(), PortSpec::Any);
        assert_eq!("22".parse::<PortSpec>().unwrap(), PortSpec::single(22));
        assert_eq!(
            "8000:8100".parse::<PortSpec>().unwrap(),
            PortSpec::Ports(vec![PortRange::new(8000, 8100).unwrap()])
        );
        assert_eq!(
            "80,443".parse::<PortSpec>().unwrap(),
            PortSpec::Ports(vec![PortRange::single(80), PortRange::single(443)])
        );
        assert_eq!(
            "OpenSSH".parse::<PortSpec>().unwrap(),
            PortSpec::App("OpenSSH".into())
        );
    }

    #[test]
    fn port_spec_display_round_trips() {
        for text in ["22", "8000:8100", "80,443"] {
            let spec: PortSpec = text.parse().unwrap();
            assert_eq!(spec.to_string(), text);
        }
    }

    #[test]
    fn single_port_requires_one_single_range() {
        assert_eq!(PortSpec::single(22).single_port(), Some(22));
        assert_eq!("80,443".parse::<PortSpec>().unwrap().single_port(), None);
        assert_eq!("8000:8100".parse::<PortSpec>().unwrap().single_port(), None);
    }

    #[test]
    fn validate_rejects_ambiguous_drafts() {
        let all = RuleDraft::default();
        assert!(all.validate().unwrap_err().contains("all traffic"));

        let ranged = RuleDraft {
            to_port: "8000:8100".parse().unwrap(),
            ..Default::default()
        };
        assert!(ranged.validate().unwrap_err().contains("needs a protocol"));

        let app_with_proto = RuleDraft {
            to_port: PortSpec::App("OpenSSH".into()),
            protocol: Protocol::Tcp,
            ..Default::default()
        };
        assert!(app_with_proto
            .validate()
            .unwrap_err()
            .contains("already know their protocol"));

        let bad_addr = RuleDraft {
            from_addr: Some("not-an-ip".into()),
            ..Default::default()
        };
        assert!(bad_addr.validate().unwrap_err().contains("not an address"));
    }

    #[test]
    fn validate_accepts_a_typical_lan_ssh_rule() {
        let draft = RuleDraft::allow_port(Protocol::Tcp, 22)
            .from_anywhere("192.168.1.0/24")
            .on_interface("eno1")
            .with_comment("SSH from LAN");
        assert!(draft.validate().is_ok(), "{:?}", draft.validate());
    }

    #[test]
    fn net_parses_addresses_and_networks() {
        assert!(parse_net("192.168.1.0/24").is_some());
        assert!(parse_net("203.0.113.7").is_some());
        assert!(parse_net("2001:db8::/32").is_some());
        assert!(parse_net("OpenSSH").is_none());
    }

    #[test]
    fn actions_round_trip_through_labels() {
        for action in Action::ALL {
            assert_eq!(Action::from_label(action.label()), Some(action));
        }
        assert_eq!(Action::from_label("nope"), None);
    }
}
