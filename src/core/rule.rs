//! The rule model.
//!
//! A [`Rule`] is the parsed form of one `ufw status numbered` row. A [`RuleDraft`] is the
//! editable form used by the wizard, the raw form, the command builder and the simulator.

use std::fmt;
use std::str::FromStr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
/**
 * Anything in ufw that decides the fate of a packet.
 *
 * # Variants
 *
 * * `Allow` - Let the traffic through.
 * * `Deny` - Drop the traffic silently.
 * * `Reject` - Drop the traffic and tell the sender.
 * * `Limit` - Allow the traffic but rate-limit new connections.
 */
pub enum Action {
    Allow,
    Deny,
    Reject,
    Limit,
}

impl Action {
    pub const ALL: [Action; 4] = [Action::Allow, Action::Deny, Action::Reject, Action::Limit];

    /**
     * Returns the word `ufw` expects on the command line.
     *
     * # Arguments
     *
     * * `self` (`Action`) - The action being rendered; it is read, not mutated.
     *
     * # Returns
     *
     * A `&'static str` containing the lowercase command word: `allow`, `deny`,
     * `reject` or `limit`.
     */
    pub fn ufw(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Deny => "deny",
            Action::Reject => "reject",
            Action::Limit => "limit",
        }
    }

    /**
     * Returns the word `ufw status` prints for this action.
     *
     * # Arguments
     *
     * * `self` (`Action`) - The action being rendered; it is read, not mutated.
     *
     * # Returns
     *
     * A `&'static str` containing the uppercase status label: `ALLOW`, `DENY`,
     * `REJECT` or `LIMIT`.
     */
    pub fn label(self) -> &'static str {
        match self {
            Action::Allow => "ALLOW",
            Action::Deny => "DENY",
            Action::Reject => "REJECT",
            Action::Limit => "LIMIT",
        }
    }

    /**
     * Returns how the action reads in a sentence.
     *
     * # Arguments
     *
     * * `self` (`Action`) - The action being rendered; it is read, not mutated.
     *
     * # Returns
     *
     * A `&'static str` containing the sentence verb: `Allow`, `Block`,
     * `Refuse` or `Allow (rate limited)`.
     */
    pub fn verb(self) -> &'static str {
        match self {
            Action::Allow => "Allow",
            Action::Deny => "Block",
            Action::Reject => "Refuse",
            Action::Limit => "Allow (rate limited)",
        }
    }

    /**
     * Parses an action from a `ufw status` label.
     *
     * Matching is case-insensitive.
     *
     * # Arguments
     *
     * * `label` (`&str`) - The status label to parse, such as `ALLOW`.
     *
     * # Returns
     *
     * An `Option<Action>` containing the matching action, or `None` when the
     * label is not a known action.
     */
    pub fn from_label(label: &str) -> Option<Self> {
        match label.to_ascii_uppercase().as_str() {
            "ALLOW" => Some(Action::Allow),
            "DENY" => Some(Action::Deny),
            "REJECT" => Some(Action::Reject),
            "LIMIT" => Some(Action::Limit),
            _ => None,
        }
    }

    /**
     * Returns whether the action lets traffic through.
     *
     * Deny and reject never permit traffic; limit permits it but rate-limits
     * it, so it counts as permitting.
     *
     * # Arguments
     *
     * * `self` (`Action`) - The action being classified; it is read, not
     *   mutated.
     *
     * # Returns
     *
     * `true` for `Allow` and `Limit`; otherwise, `false`.
     */
    pub fn permits(self) -> bool {
        matches!(self, Action::Allow | Action::Limit)
    }
}

impl fmt::Display for Action {
    /**
     * Implements `Display` by writing the `ufw` command word.
     *
     * # Arguments
     *
     * * `&self` - The action being formatted; it is read, not mutated.
     * * `f` (`&mut fmt::Formatter<'_>`) - The formatter to write into.
     *
     * # Returns
     *
     * A `fmt::Result` that is `Ok(())` when the write succeeds, or the
     * formatter's error when it does not.
     */
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.ufw())
    }
}

impl FromStr for Action {
    /**
     * The error type for action parsing: a plain-English message.
     */
    type Err = String;

    /**
     * Implements `FromStr` by parsing an action label.
     *
     * # Arguments
     *
     * * `s` (`&str`) - The text to parse, matched case-insensitively.
     *
     * # Returns
     *
     * A `Result<Action, String>` containing the parsed action, or an error
     * message naming the unknown action.
     */
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Action::from_label(s).ok_or_else(|| format!("unknown action '{s}'"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
/**
 * Which way traffic flows relative to this machine.
 *
 * # Variants
 *
 * * `In` - Traffic arriving at this machine.
 * * `Out` - Traffic leaving this machine.
 * * `Forward` - Traffic routed through this machine; shown read-only.
 */
pub enum Direction {
    In,
    Out,
    Forward,
}

impl Direction {
    pub const ALL: [Direction; 3] = [Direction::In, Direction::Out, Direction::Forward];

    /**
     * Returns the direction word `ufw` accepts on the command line.
     *
     * # Arguments
     *
     * * `self` (`Direction`) - The direction being rendered; it is read, not
     *   mutated.
     *
     * # Returns
     *
     * An `Option<&'static str>` containing `in` or `out`, or `None` for
     * forwarding, which has no simple command-line word.
     */
    pub fn ufw(self) -> Option<&'static str> {
        match self {
            Direction::In => Some("in"),
            Direction::Out => Some("out"),
            Direction::Forward => None,
        }
    }

    /**
     * Returns the short uppercase label used in tables.
     *
     * # Arguments
     *
     * * `self` (`Direction`) - The direction being rendered; it is read, not
     *   mutated.
     *
     * # Returns
     *
     * A `&'static str` containing `IN`, `OUT` or `FWD`.
     */
    pub fn label(self) -> &'static str {
        match self {
            Direction::In => "IN",
            Direction::Out => "OUT",
            Direction::Forward => "FWD",
        }
    }

    /**
     * Parses a direction from its short label.
     *
     * Matching is case-insensitive.
     *
     * # Arguments
     *
     * * `label` (`&str`) - The label to parse, such as `IN` or `FWD`.
     *
     * # Returns
     *
     * An `Option<Direction>` containing the matching direction, or `None` when
     * the label is not recognized.
     */
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
    /**
     * Implements `Display` by writing the short direction label.
     *
     * # Arguments
     *
     * * `&self` - The direction being formatted; it is read, not mutated.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
/**
 * The transport or network protocol a rule applies to.
 *
 * `Any` means the rule does not restrict the protocol.
 *
 * # Variants
 *
 * * `Any` - No protocol restriction.
 * * `Tcp` - Transmission Control Protocol.
 * * `Udp` - User Datagram Protocol.
 * * `Sctp` - Stream Control Transmission Protocol.
 * * `Esp` - IPsec Encapsulating Security Payload.
 * * `Ah` - IPsec Authentication Header.
 * * `Gre` - Generic Routing Encapsulation.
 * * `Igmp` - Internet Group Management Protocol.
 * * `Icmp` - IPv4 ICMP.
 * * `Icmpv6` - IPv6 ICMP, written `ipv6-icmp` by `ufw`.
 */
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

    /**
     * Returns the protocol token `ufw` accepts on the command line.
     *
     * # Arguments
     *
     * * `self` (`Protocol`) - The protocol being rendered; it is read, not
     *   mutated.
     *
     * # Returns
     *
     * An `Option<&'static str>` containing the lowercase protocol name, or
     * `None` for `Protocol::Any`, which needs no suffix.
     */
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

    /**
     * Returns the protocol name for display, using `any` as a fallback.
     *
     * # Arguments
     *
     * * `self` (`Protocol`) - The protocol being rendered; it is read, not
     *   mutated.
     *
     * # Returns
     *
     * A `&'static str` containing the lowercase protocol name, or `any` for
     * `Protocol::Any`.
     */
    pub fn label(self) -> &'static str {
        self.ufw().unwrap_or("any")
    }

    /**
     * Parses a protocol from a `/<proto>` suffix in `ufw status` output.
     *
     * Matching is case-insensitive, and `icmpv6` is accepted as an alias for
     * `ipv6-icmp`.
     *
     * # Arguments
     *
     * * `token` (`&str`) - The protocol token to parse.
     *
     * # Returns
     *
     * An `Option<Protocol>` containing the matching protocol, or `None` when
     * the token is not a known protocol.
     */
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
    /**
     * Implements `Display` by writing the protocol label.
     *
     * # Arguments
     *
     * * `&self` - The protocol being formatted; it is read, not mutated.
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

impl FromStr for Protocol {
    /**
     * The error type for protocol parsing: a plain-English message.
     */
    type Err = String;

    /**
     * Implements `FromStr` by parsing a protocol name.
     *
     * The literal `any` is accepted in any case and maps to `Protocol::Any`.
     *
     * # Arguments
     *
     * * `s` (`&str`) - The protocol name to parse.
     *
     * # Returns
     *
     * A `Result<Protocol, String>` containing the parsed protocol, or an error
     * message naming the unknown protocol.
     */
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("any") {
            return Ok(Protocol::Any);
        }
        Protocol::from_status_token(s).ok_or_else(|| format!("unknown protocol '{s}'"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
/**
 * A single port or an inclusive port range.
 *
 * # Fields
 *
 * * `start` (`u16`) - The first port in the range.
 * * `end` (`u16`) - The last port in the range; equal to `start` for a single port.
 */
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    /**
     * Builds a range that covers exactly one port.
     *
     * # Arguments
     *
     * * `port` (`u16`) - The port to use as both bounds.
     *
     * # Returns
     *
     * A `PortRange` whose start and end are both `port`.
     */
    pub fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    /**
     * Builds a validated inclusive port range.
     *
     * # Arguments
     *
     * * `start` (`u16`) - The first port in the range.
     * * `end` (`u16`) - The last port in the range.
     *
     * # Returns
     *
     * A `Result<PortRange, String>` containing the range, or a plain-English
     * error when a bound is zero or `start` is above `end`.
     */
    pub fn new(start: u16, end: u16) -> Result<Self, String> {
        if start == 0 || end == 0 {
            return Err("ports must be between 1 and 65535".into());
        }
        if start > end {
            return Err(format!("port range start {start} is above its end {end}"));
        }
        Ok(Self { start, end })
    }

    /**
     * Returns whether the range covers exactly one port.
     *
     * # Arguments
     *
     * * `&self` - The range being inspected.
     *
     * # Returns
     *
     * `true` when `start` equals `end`; otherwise, `false`.
     */
    pub fn is_single(&self) -> bool {
        self.start == self.end
    }

    /**
     * Returns whether a port falls inside the range, bounds included.
     *
     * # Arguments
     *
     * * `&self` - The range being tested.
     * * `port` (`u16`) - The port to look for.
     *
     * # Returns
     *
     * `true` when `port` is between `start` and `end` inclusive; otherwise,
     * `false`.
     */
    pub fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

impl fmt::Display for PortRange {
    /**
     * Implements `Display` as `22` for a single port or `22:80` for a range.
     *
     * # Arguments
     *
     * * `&self` - The range being formatted; it is read, not mutated.
     * * `f` (`&mut fmt::Formatter<'_>`) - The formatter to write into.
     *
     * # Returns
     *
     * A `fmt::Result` that is `Ok(())` when the write succeeds, or the
     * formatter's error when it does not.
     */
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_single() {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}:{}", self.start, self.end)
        }
    }
}

impl FromStr for PortRange {
    /**
     * The error type for port range parsing: a plain-English message.
     */
    type Err = String;

    /**
     * Implements `FromStr` by parsing `22` or `22:80`.
     *
     * Surrounding whitespace on each part is trimmed before parsing.
     *
     * # Arguments
     *
     * * `s` (`&str`) - The text to parse.
     *
     * # Returns
     *
     * A `Result<PortRange, String>` containing the parsed range, or an error
     * message naming the bad port or the invalid bounds.
     */
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

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
/**
 * What a rule points at: nothing in particular, a set of ports, or an
 * application profile.
 *
 * # Variants
 *
 * * `Any` - Any port; the default.
 * * `Ports(Vec<PortRange>)` - An explicit list of ports and ranges.
 * * `App(String)` - The name of a ufw application profile, such as `OpenSSH`.
 */
pub enum PortSpec {
    #[default]
    Any,
    Ports(Vec<PortRange>),
    App(String),
}

impl PortSpec {
    /**
     * Builds a spec covering exactly one port.
     *
     * # Arguments
     *
     * * `port` (`u16`) - The port to cover.
     *
     * # Returns
     *
     * A `PortSpec::Ports` holding a single one-port range.
     */
    pub fn single(port: u16) -> Self {
        PortSpec::Ports(vec![PortRange::single(port)])
    }

    /**
     * Returns whether the spec means "any port".
     *
     * # Arguments
     *
     * * `&self` - The spec being inspected.
     *
     * # Returns
     *
     * `true` for `PortSpec::Any`; otherwise, `false`.
     */
    pub fn is_any(&self) -> bool {
        matches!(self, PortSpec::Any)
    }

    /**
     * Returns the single port the spec covers, when it covers exactly one.
     *
     * This is the only case `ufw` accepts in its simple syntax without an
     * explicit protocol.
     *
     * # Arguments
     *
     * * `&self` - The spec being inspected.
     *
     * # Returns
     *
     * An `Option<u16>` containing the port when the spec is one single-port
     * range; otherwise, `None`.
     */
    pub fn single_port(&self) -> Option<u16> {
        match self {
            PortSpec::Ports(list) if list.len() == 1 && list[0].is_single() => Some(list[0].start),
            _ => None,
        }
    }

    /**
     * Returns whether the spec covers a port.
     *
     * `PortSpec::Any` covers every port. Application profiles are not resolved
     * here, so they never report a match.
     *
     * # Arguments
     *
     * * `&self` - The spec being tested.
     * * `port` (`u16`) - The port to look for.
     *
     * # Returns
     *
     * `true` when the spec covers `port`; otherwise, `false`.
     */
    pub fn contains(&self, port: u16) -> bool {
        match self {
            PortSpec::Any => true,
            PortSpec::Ports(list) => list.iter().any(|r| r.contains(port)),
            // An application profile only matches through its expansion; the caller resolves it.
            PortSpec::App(_) => false,
        }
    }

    /**
     * Returns whether the spec needs an explicit protocol.
     *
     * A list of several ports, or any range spanning more than one port, is
     * ambiguous without a protocol.
     *
     * # Arguments
     *
     * * `&self` - The spec being inspected.
     *
     * # Returns
     *
     * `true` when the spec holds multiple ranges or a multi-port range;
     * otherwise, `false`.
     */
    pub fn is_range_or_list(&self) -> bool {
        match self {
            PortSpec::Ports(list) => list.len() > 1 || list.iter().any(|r| !r.is_single()),
            _ => false,
        }
    }

    /**
     * Returns the lowest port the spec mentions.
     *
     * This is used to build a representative test packet for the simulator.
     *
     * # Arguments
     *
     * * `&self` - The spec being inspected.
     *
     * # Returns
     *
     * An `Option<u16>` containing the smallest range start, or `None` for
     * `Any` and application profiles.
     */
    pub fn first_port(&self) -> Option<u16> {
        match self {
            PortSpec::Any => None,
            PortSpec::App(_) => None,
            PortSpec::Ports(list) => list.iter().map(|r| r.start).min(),
        }
    }
}

impl fmt::Display for PortSpec {
    /**
     * Implements `Display` as `any`, the profile name, or a comma-joined list.
     *
     * # Arguments
     *
     * * `&self` - The spec being formatted; it is read, not mutated.
     * * `f` (`&mut fmt::Formatter<'_>`) - The formatter to write into.
     *
     * # Returns
     *
     * A `fmt::Result` that is `Ok(())` when the write succeeds, or the
     * formatter's error when it does not.
     */
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
    /**
     * The error type for port specification parsing: a plain-English message.
     */
    type Err = String;

    /**
     * Implements `FromStr` for the port syntax used throughout the app.
     *
     * Parses `any`, `22`, `22:80`, `80,443`, `8000:8100,9000` and bare service
     * or application names. Anything that is not purely digits, colons and
     * commas is treated as an application profile name.
     *
     * # Arguments
     *
     * * `s` (`&str`) - The text to parse; surrounding whitespace is trimmed.
     *
     * # Returns
     *
     * A `Result<PortSpec, String>` containing the parsed spec, or an error
     * message from the failing port range.
     */
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

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
/**
 * One side of a rule: an optional address plus a port specification.
 *
 * # Fields
 *
 * * `addr` (`Option<String>`) - The address or network; `None` means "any address".
 * * `port` (`PortSpec`) - The port selection for this side.
 */
pub struct Endpoint {
    /// `None` means "any address".
    pub addr: Option<String>,
    pub port: PortSpec,
}

impl Endpoint {
    /**
     * Builds an endpoint that matches any address and any port.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * An `Endpoint` with no address and `PortSpec::Any`.
     */
    pub fn any() -> Self {
        Self {
            addr: None,
            port: PortSpec::Any,
        }
    }

    /**
     * Builds an endpoint with no address that matches one port.
     *
     * # Arguments
     *
     * * `port` (`u16`) - The port the endpoint covers.
     *
     * # Returns
     *
     * An `Endpoint` with no address and a single-port spec.
     */
    pub fn port(port: u16) -> Self {
        Self {
            addr: None,
            port: PortSpec::single(port),
        }
    }

    /**
     * Builds an endpoint for an address that matches any port.
     *
     * # Arguments
     *
     * * `addr` (`impl Into<String>`) - The address or network to store.
     *
     * # Returns
     *
     * An `Endpoint` holding the address and `PortSpec::Any`.
     */
    pub fn from_addr(addr: impl Into<String>) -> Self {
        Self {
            addr: Some(addr.into()),
            port: PortSpec::Any,
        }
    }

    /**
     * Returns whether the endpoint matches everything.
     *
     * # Arguments
     *
     * * `&self` - The endpoint being inspected.
     *
     * # Returns
     *
     * `true` when there is no address and the port spec is `Any`; otherwise,
     * `false`.
     */
    pub fn is_any(&self) -> bool {
        self.addr.is_none() && self.port.is_any()
    }

    /**
     * Returns the endpoint address parsed as a network.
     *
     * # Arguments
     *
     * * `&self` - The endpoint being read.
     *
     * # Returns
     *
     * An `Option<IpNet>` containing the parsed network, or `None` when there is
     * no address or it does not parse.
     */
    pub fn net(&self) -> Option<IpNet> {
        parse_net(self.addr.as_deref()?)
    }

    /**
     * Renders the address for display, optionally with an interface.
     *
     * # Arguments
     *
     * * `&self` - The endpoint being rendered.
     * * `iface` (`Option<&str>`) - An optional interface name to append.
     *
     * # Returns
     *
     * A `String` containing `Anywhere`, the address, and ` on <iface>` when an
     * interface is given.
     */
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

/**
 * Parses an address or CIDR network into an `IpNet`.
 *
 * A bare address is widened to a single-host network. Surrounding whitespace
 * is trimmed first.
 *
 * # Arguments
 *
 * * `value` (`&str`) - The text to parse, such as `1.2.3.4`, `1.2.3.0/24` or `2001:db8::/32`.
 *
 * # Returns
 *
 * An `Option<IpNet>` containing the network, or `None` when the text is
 * neither a network nor an address.
 */
pub fn parse_net(value: &str) -> Option<IpNet> {
    let value = value.trim();
    if let Ok(net) = value.parse::<IpNet>() {
        return Some(net);
    }
    value.parse::<std::net::IpAddr>().ok().map(IpNet::from)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
/**
 * How much of a rule's traffic `ufw` logs.
 *
 * # Variants
 *
 * * `None` - Logging is off for this rule.
 * * `Log` - Log only new connections.
 * * `LogAll` - Log every matching packet.
 */
pub enum LogMode {
    None,
    Log,
    LogAll,
}

impl LogMode {
    /**
     * Returns the logging token `ufw` accepts on the command line.
     *
     * # Arguments
     *
     * * `self` (`LogMode`) - The mode being rendered; it is read, not mutated.
     *
     * # Returns
     *
     * An `Option<&'static str>` containing `log` or `log-all`, or `None` when
     * logging is off.
     */
    pub fn ufw(self) -> Option<&'static str> {
        match self {
            LogMode::None => None,
            LogMode::Log => Some("log"),
            LogMode::LogAll => Some("log-all"),
        }
    }

    /**
     * Returns the short label used in tables.
     *
     * # Arguments
     *
     * * `self` (`LogMode`) - The mode being rendered; it is read, not mutated.
     *
     * # Returns
     *
     * A `&'static str` containing `off`, `log` or `log-all`.
     */
    pub fn label(self) -> &'static str {
        match self {
            LogMode::None => "off",
            LogMode::Log => "log",
            LogMode::LogAll => "log-all",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/**
 * One row of `ufw status numbered`.
 *
 * # Fields
 *
 * * `number` (`u32`) - `ufw`'s own rule number, i.e. the `N` in `ufw delete N`. `0` marks a rule that does not exist yet (a pending draft shown in the simulator).
 * * `action` (`Action`) - What happens to matching traffic.
 * * `direction` (`Direction`) - Which way the traffic flows.
 * * `interface_in` (`Option<String>`) - The incoming interface, when limited.
 * * `interface_out` (`Option<String>`) - The outgoing interface, when limited.
 * * `protocol` (`Protocol`) - The protocol the rule applies to.
 * * `from` (`Endpoint`) - The source side of the rule.
 * * `to` (`Endpoint`) - The destination side of the rule.
 * * `log` (`LogMode`) - How much of the rule's traffic is logged.
 * * `comment` (`Option<String>`) - The user's note for the rule.
 * * `v6` (`bool`) - Whether this is the IPv6 variant of the rule.
 * * `route` (`bool`) - Whether this is a forwarding rule; shown but not editable in v1.
 */
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
    /**
     * Returns whether the rule is a draft that does not exist in `ufw` yet.
     *
     * # Arguments
     *
     * * `&self` - The rule being inspected.
     *
     * # Returns
     *
     * `true` when the rule number is `0`; otherwise, `false`.
     */
    pub fn is_pending(&self) -> bool {
        self.number == 0
    }

    /**
     * Returns whether the rule forwards traffic rather than filtering it.
     *
     * # Arguments
     *
     * * `&self` - The rule being inspected.
     *
     * # Returns
     *
     * `true` when the route flag is set or the direction is `Forward`;
     * otherwise, `false`.
     */
    pub fn is_route(&self) -> bool {
        self.route || self.direction == Direction::Forward
    }

    /**
     * Returns the port specification the rule is about.
     *
     * Both directions currently resolve to the destination port, which is the
     * port shown in the rule table.
     *
     * # Arguments
     *
     * * `&self` - The rule being read.
     *
     * # Returns
     *
     * A cloned `PortSpec` taken from the destination endpoint.
     */
    pub fn primary_port(&self) -> PortSpec {
        match self.direction {
            Direction::Out => self.to.port.clone(),
            _ => self.to.port.clone(),
        }
    }

    /**
     * Returns the rule comment, or an empty string when there is none.
     *
     * # Arguments
     *
     * * `&self` - The rule being read.
     *
     * # Returns
     *
     * A `&str` borrowing the comment text, or `""` when the comment is absent.
     */
    pub fn comment_text(&self) -> &str {
        self.comment.as_deref().unwrap_or("")
    }

    /**
     * Builds a stable identity string for the rule.
     *
     * The signature is used to check that a rule number still refers to the
     * same rule after a refresh. It joins the action, direction, interfaces,
     * protocol, addresses and ports with `|`.
     *
     * # Arguments
     *
     * * `&self` - The rule being described.
     *
     * # Returns
     *
     * A `String` containing the pipe-separated signature.
     */
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

    /**
     * Converts the rule back into an editable draft.
     *
     * The conversion is lossy only for route rules, which are read-only and
     * therefore never round-trip through the wizard.
     *
     * # Arguments
     *
     * * `&self` - The rule being converted.
     *
     * # Returns
     *
     * A `RuleDraft` carrying the rule's editable fields.
     */
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

#[derive(Debug, Clone, PartialEq, Eq)]
/**
 * The editable form of a rule.
 *
 * The wizard, the raw editor, the command builder and the simulator all work
 * on drafts, which are validated before being turned into a [`Rule`].
 *
 * # Fields
 *
 * * `action` (`Action`) - What happens to matching traffic.
 * * `direction` (`Direction`) - Which way the traffic flows.
 * * `interface_in` (`Option<String>`) - The incoming interface, when limited.
 * * `protocol` (`Protocol`) - The protocol the rule applies to.
 * * `from_addr` (`Option<String>`) - The source address or network.
 * * `from_port` (`PortSpec`) - The source port selection.
 * * `to_addr` (`Option<String>`) - The destination address or network.
 * * `to_port` (`PortSpec`) - The destination port selection.
 * * `log` (`LogMode`) - How much of the rule's traffic is logged.
 * * `comment` (`Option<String>`) - The user's note for the rule.
 */
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
    /**
     * Implements `Default` as a permissive inbound allow rule.
     *
     * The draft allows inbound traffic with no interface, any protocol, any
     * address and any port, and no logging or comment.
     *
     * # Arguments
     *
     * This method takes no arguments.
     *
     * # Returns
     *
     * A `RuleDraft` containing the default field values.
     */
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
    /**
     * Builds an inbound allow draft for one port and protocol.
     *
     * # Arguments
     *
     * * `protocol` (`Protocol`) - The transport protocol to allow.
     * * `port` (`u16`) - The destination port to allow.
     *
     * # Returns
     *
     * A `RuleDraft` based on the defaults with the protocol and destination
     * port set.
     */
    pub fn allow_port(protocol: Protocol, port: u16) -> Self {
        Self {
            protocol,
            to_port: PortSpec::single(port),
            ..Default::default()
        }
    }

    /**
     * Sets the comment, treating an empty string as no comment.
     *
     * # Arguments
     *
     * * `mut self` (`RuleDraft`) - The draft being modified; it is consumed and
     *   returned.
     * * `comment` (`impl Into<String>`) - The comment text to store.
     *
     * # Returns
     *
     * The updated `RuleDraft`, for chaining.
     */
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        let text = comment.into();
        self.comment = if text.is_empty() { None } else { Some(text) };
        self
    }

    /**
     * Sets the source address of the draft.
     *
     * # Arguments
     *
     * * `mut self` (`RuleDraft`) - The draft being modified; it is consumed and
     *   returned.
     * * `addr` (`impl Into<String>`) - The source address or network to store.
     *
     * # Returns
     *
     * The updated `RuleDraft`, for chaining.
     */
    pub fn from_anywhere(mut self, addr: impl Into<String>) -> Self {
        self.from_addr = Some(addr.into());
        self
    }

    /**
     * Sets the incoming interface of the draft.
     *
     * # Arguments
     *
     * * `mut self` (`RuleDraft`) - The draft being modified; it is consumed and
     *   returned.
     * * `iface` (`impl Into<String>`) - The interface name to store.
     *
     * # Returns
     *
     * The updated `RuleDraft`, for chaining.
     */
    pub fn on_interface(mut self, iface: impl Into<String>) -> Self {
        self.interface_in = Some(iface.into());
        self
    }

    /**
     * Checks the draft for mistakes before `ufw` ever sees it.
     *
     * This catches the errors a newcomer is most likely to make so they can be
     * phrased in plain English: forwarding rules, unparsable addresses, an
     * application profile combined with an explicit protocol, a port range or
     * list without a protocol, and a rule that would match all traffic.
     *
     * # Arguments
     *
     * * `&self` - The draft being validated.
     *
     * # Returns
     *
     * A `Result<(), String>` that is `Ok(())` when the draft is valid, or an
     * error message describing the first problem found.
     */
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

    /**
     * Converts the draft into a concrete rule with the given number.
     *
     * The resulting rule is never marked as IPv6 or as a route, and has no
     * outgoing interface.
     *
     * # Arguments
     *
     * * `&self` - The draft being converted.
     * * `number` (`u32`) - The rule number to assign; `0` marks a pending rule.
     *
     * # Returns
     *
     * A `Rule` built from the draft's fields.
     */
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
    /**
     * Verifies that inverted or zero port bounds are rejected.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn port_range_rejects_inverted_bounds() {
        assert!(PortRange::new(90, 80).is_err());
        assert!(PortRange::new(0, 80).is_err());
        assert!(PortRange::new(80, 80).is_ok());
    }

    #[test]
    /**
     * Verifies that the common port specification forms parse correctly.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
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
    /**
     * Verifies that parsing and displaying a port spec round-trips.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn port_spec_display_round_trips() {
        for text in ["22", "8000:8100", "80,443"] {
            let spec: PortSpec = text.parse().unwrap();
            assert_eq!(spec.to_string(), text);
        }
    }

    #[test]
    /**
     * Verifies that only a single one-port range yields a single port.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn single_port_requires_one_single_range() {
        assert_eq!(PortSpec::single(22).single_port(), Some(22));
        assert_eq!("80,443".parse::<PortSpec>().unwrap().single_port(), None);
        assert_eq!("8000:8100".parse::<PortSpec>().unwrap().single_port(), None);
    }

    #[test]
    /**
     * Verifies that ambiguous or malformed drafts are rejected with clear errors.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
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
    /**
     * Verifies that a typical LAN-restricted SSH rule validates.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn validate_accepts_a_typical_lan_ssh_rule() {
        let draft = RuleDraft::allow_port(Protocol::Tcp, 22)
            .from_anywhere("192.168.1.0/24")
            .on_interface("eno1")
            .with_comment("SSH from LAN");
        assert!(draft.validate().is_ok(), "{:?}", draft.validate());
    }

    #[test]
    /**
     * Verifies that addresses and CIDR networks parse while names do not.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn net_parses_addresses_and_networks() {
        assert!(parse_net("192.168.1.0/24").is_some());
        assert!(parse_net("203.0.113.7").is_some());
        assert!(parse_net("2001:db8::/32").is_some());
        assert!(parse_net("OpenSSH").is_none());
    }

    #[test]
    /**
     * Verifies that actions round-trip through their status labels.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn actions_round_trip_through_labels() {
        for action in Action::ALL {
            assert_eq!(Action::from_label(action.label()), Some(action));
        }
        assert_eq!(Action::from_label("nope"), None);
    }
}
