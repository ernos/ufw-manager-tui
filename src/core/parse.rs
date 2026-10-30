//! Parsers for everything we read off the system.
//!
//! The formats are derived from `ufw` 0.36.2 itself
//! (`/usr/lib/python3/dist-packages/ufw/backend_iptables.py::get_status`), not from guessing at
//! sample output:
//!
//! ```text
//! tmp_str += "%-26s %-12s%-26s%s%s\n" % (location['dst'], action + " " + direction,
//!                                        location['src'], attrib_str, comment_str)
//! ```
//!
//! Python's `%-26s` **pads but never truncates**, and `attrib_str` (`" (log)"`) is glued straight
//! onto the `From` column without a separating space when that column is already 26 characters
//! wide. Fixed byte columns therefore cannot work. Instead we:
//!
//! 1. split off the trailing ` # comment`,
//! 2. strip a trailing parenthesised attribute group (`(log)`, `(out)`, `(log-all, out)`),
//! 3. locate the action word (`ALLOW`/`DENY`/`REJECT`/`LIMIT`) as a whitespace-delimited token —
//!    addresses and port specs can never contain one, so this is unambiguous,
//! 4. treat everything before it as the `To` column and everything after it (plus the optional
//!    direction token) as the `From` column.
//!
//! This survives every column-shifting case.

use std::net::IpAddr;

use crate::core::firewall::{FirewallState, LogLevel, Policy, RoutedPolicy};
use crate::core::rule::{
    parse_net, Action, Direction, Endpoint, LogMode, PortSpec, Protocol, Rule,
};

#[derive(Debug, Clone, Default)]
/**
 * The result of parsing `ufw status numbered`.
 *
 * # Fields
 *
 * * `active` (`bool`) - Whether the status line reported the firewall as active.
 * * `rules` (`Vec<Rule>`) - The rules that were parsed successfully.
 * * `unparsed` (`Vec<String>`) - Rows that could not be parsed, kept verbatim so they are still shown and can still be deleted by number.
 */
pub struct ParsedRules {
    pub active: bool,
    pub rules: Vec<Rule>,
    pub unparsed: Vec<String>,
}

#[derive(Debug, Clone)]
/**
 * The header values from `ufw status verbose`.
 *
 * # Fields
 *
 * * `active` (`bool`) - Whether the firewall is active.
 * * `log_level` (`LogLevel`) - The configured logging level.
 * * `default_incoming` (`Policy`) - The default policy for incoming traffic.
 * * `default_outgoing` (`Policy`) - The default policy for outgoing traffic.
 * * `default_routed` (`RoutedPolicy`) - The default policy for forwarded traffic.
 * * `new_profiles` (`String`) - The `New profiles:` setting, usually `skip` or `ask`.
 */
pub struct ParsedHeader {
    pub active: bool,
    pub log_level: LogLevel,
    pub default_incoming: Policy,
    pub default_outgoing: Policy,
    pub default_routed: RoutedPolicy,
    pub new_profiles: String,
}

impl Default for ParsedHeader {
    /**
     * Implements `Default` for [`ParsedHeader`], returning the values `ufw` uses before any
     * status output is parsed.
     *
     * # Arguments
     *
     * This method takes no arguments.
     *
     * # Returns
     *
     * A `ParsedHeader` with the firewall inactive, low logging, deny incoming, allow
     * outgoing, routed policy disabled, and new profiles set to `skip`.
     */
    fn default() -> Self {
        Self {
            active: false,
            log_level: LogLevel::Low,
            default_incoming: Policy::Deny,
            default_outgoing: Policy::Allow,
            default_routed: RoutedPolicy::Disabled,
            new_profiles: "skip".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/**
 * A profile from `/etc/ufw/applications.d`, i.e. what `ufw app info NAME` describes.
 *
 * # Fields
 *
 * * `name` (`String`) - The section name, which is the profile name `ufw` accepts.
 * * `title` (`String`) - The human-readable title from the `title` key.
 * * `description` (`String`) - The description from the `description` key.
 * * `ports_raw` (`String`) - The unparsed `ports` value, such as `80,443/tcp`.
 */
pub struct AppProfile {
    pub name: String,
    pub title: String,
    pub description: String,
    pub ports_raw: String,
}

impl AppProfile {
    /**
     * Returns the protocols an application profile opens, used by the risk engine.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The profile whose `ports_raw` value is read.
     *
     * # Returns
     *
     * A `Vec<Protocol>` holding one entry per recognized `<port>/<proto>` part, in the
     * order they appear. Unrecognized protocol words are skipped.
     */
    pub fn protocols(&self) -> Vec<Protocol> {
        self.ports_raw
            .split(['|', ','])
            .filter_map(|part| part.split_once('/').map(|(_, proto)| proto))
            .filter_map(Protocol::from_status_token)
            .collect()
    }

    /**
     * Returns the distinct ports an application profile opens.
     *
     * Ranges of up to 33 ports are expanded; longer ranges contribute only their start
     * port, because a profile that opens `1:65535` is not useful to enumerate.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The profile whose `ports_raw` value is read.
     *
     * # Returns
     *
     * A sorted, de-duplicated `Vec<u16>` of the ports the profile opens.
     */
    pub fn ports(&self) -> Vec<u16> {
        let mut out = Vec::new();
        for part in self.ports_raw.split(['|', ',']) {
            let digits = part.split('/').next().unwrap_or("").trim();
            if let Ok(range) = digits.parse::<crate::core::rule::PortRange>() {
                // Only expand short ranges; a profile that opens 1:65535 is not useful to enumerate.
                if range.end.saturating_sub(range.start) <= 32 {
                    out.extend(range.start..=range.end);
                } else {
                    out.push(range.start);
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/**
 * One socket from `ss -tulpn`, or from `ufw show listening`.
 *
 * # Fields
 *
 * * `proto` (`String`) - The lower-case protocol, such as `tcp` or `udp`.
 * * `addr` (`String`) - The local address the socket is bound to.
 * * `port` (`u16`) - The local port the socket is bound to.
 * * `process` (`Option<String>`) - The owning process name, when `ss` reported one.
 */
pub struct Listening {
    pub proto: String,
    pub addr: String,
    pub port: u16,
    pub process: Option<String>,
}

impl Listening {
    /**
     * Returns whether the listening address is a loopback address.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The listening socket being inspected.
     *
     * # Returns
     *
     * `true` for addresses starting with `127.` and for `::1`; otherwise, `false`.
     */
    pub fn is_loopback(&self) -> bool {
        self.addr.starts_with("127.") || self.addr == "::1"
    }

    /**
     * Returns whether the listening address accepts traffic on every interface.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The listening socket being inspected.
     *
     * # Returns
     *
     * `true` for `0.0.0.0`, `::` and `*`; otherwise, `false`.
     */
    pub fn is_wildcard(&self) -> bool {
        self.addr == "0.0.0.0" || self.addr == "::" || self.addr == "*"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/**
 * One `[UFW BLOCK]` kernel log entry.
 *
 * # Fields
 *
 * * `iface` (`String`) - The incoming interface from `IN=`, or `?` when absent.
 * * `src` (`IpAddr`) - The source address from `SRC=`.
 * * `dst` (`IpAddr`) - The destination address from `DST=`.
 * * `proto` (`String`) - The lower-case protocol from `PROTO=`, or `?` when absent.
 * * `spt` (`u16`) - The source port from `SPT=`, or `0` when absent.
 * * `dpt` (`u16`) - The destination port from `DPT=`, or `0` when absent.
 */
pub struct BlockEvent {
    pub iface: String,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: String,
    pub spt: u16,
    pub dpt: u16,
}

#[derive(Debug, Clone, Copy, Default)]
/**
 * The bits of `/etc/ufw/ufw.conf` a non-root user is allowed to read.
 *
 * # Fields
 *
 * * `enabled` (`Option<bool>`) - The `ENABLED` value, or `None` when the key was absent.
 * * `log_level` (`Option<LogLevel>`) - The `LOGLEVEL` value, or `None` when the key was absent or unrecognized.
 */
pub struct UfwConf {
    pub enabled: Option<bool>,
    pub log_level: Option<LogLevel>,
}

// ---------------------------------------------------------------------------------------------
// status numbered
// ---------------------------------------------------------------------------------------------

/**
 * Parses `ufw status numbered` output into rules.
 *
 * Rows that cannot be parsed are kept verbatim in `unparsed` so they are still shown
 * and can still be deleted by number.
 *
 * # Arguments
 *
 * * `text` (`&str`) - The complete output of `ufw status numbered`.
 *
 * # Returns
 *
 * A `ParsedRules` holding the active flag, the parsed rules, and the raw rows that
 * could not be parsed. An inactive status returns the default, empty value.
 */
pub fn parse_status_numbered(text: &str) -> ParsedRules {
    let mut out = ParsedRules::default();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.eq_ignore_ascii_case("Status: inactive") {
            return ParsedRules::default();
        }
        if trimmed.eq_ignore_ascii_case("Status: active") {
            out.active = true;
            continue;
        }
        let Some((number, body)) = split_rule_number(line) else {
            continue;
        };
        match parse_rule_row(number, body) {
            Ok(rule) => out.rules.push(rule),
            Err(_) => out.unparsed.push(line.trim_end().to_string()),
        }
    }
    out
}

/**
 * Extracts `[ 12] ` from the start of a rule row.
 *
 * # Arguments
 *
 * * `line` (`&str`) - One line of `ufw status numbered` output.
 *
 * # Returns
 *
 * `Option<(u32, &str)>` - The rule number and the remaining row text with leading
 * whitespace removed, or `None` when the line does not start with a bracketed number.
 */
fn split_rule_number(line: &str) -> Option<(u32, &str)> {
    let open = line.find('[')?;
    if !line[..open].trim().is_empty() {
        return None;
    }
    let close = line[open..].find(']')? + open;
    let digits = line[open + 1..close].trim();
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let number = digits.parse::<u32>().ok()?;
    Some((number, line[close + 1..].trim_start()))
}

/**
 * Splits `body` (a row with the number removed) into a [`Rule`].
 *
 * The trailing comment and attribute group are stripped first, then the action word is
 * used as the anchor that separates the `To` column from the `From` column.
 *
 * # Arguments
 *
 * * `number` (`u32`) - The rule number taken from the row prefix.
 * * `body` (`&str`) - The row text with the number removed.
 *
 * # Returns
 *
 * `Result<Rule, String>` - The parsed rule, or a message describing why the row could
 * not be parsed (for example `no action word`).
 */
fn parse_rule_row(number: u32, body: &str) -> Result<Rule, String> {
    let body = body.trim_end();

    // 1. Trailing comment. ufw writes `" # %s"`, so the first occurrence is the separator.
    let (body, comment) = match body.find(" # ") {
        Some(idx) => (
            body[..idx].trim_end(),
            Some(body[idx + 3..].trim().to_string()),
        ),
        None => (body, None),
    };

    // 2. Trailing attribute group: " (log)", " (log-all)", " (out)" or " (log, out)".
    let (body, log) = strip_attributes(body);

    // 3. The action word is the anchor. It cannot appear inside an address or a port spec.
    let tokens = tokenize(body);
    let mut anchor = None;
    for (index, (start, _end, word)) in tokens.iter().enumerate() {
        if let Some(action) = Action::from_label(word) {
            anchor = Some((index, *start, action));
            break;
        }
    }
    let (index, action_start, action) = anchor.ok_or("no action word")?;

    // 4. Optional direction token right after the action.
    let mut direction = Direction::In;
    let mut last_index = index;
    if let Some((_start, _end, word)) = tokens.get(index + 1) {
        if let Some(parsed) = Direction::from_label(word) {
            direction = parsed;
            last_index = index + 1;
        }
    }

    let to_text = body[..action_start].trim();
    let from_start = tokens
        .get(last_index + 1)
        .map(|(start, ..)| *start)
        .unwrap_or(body.len());
    let from_text = body[from_start..].trim();

    let to = parse_column(to_text)?;
    let from = parse_column(from_text)?;

    let is_route = direction == Direction::Forward;
    let (interface_in, interface_out) = if is_route {
        (from.iface.clone(), to.iface.clone())
    } else {
        (to.iface.clone(), from.iface.clone())
    };

    // The protocol can be printed on either side (`22/tcp`, or `Anywhere/tcp` when the port is
    // unconstrained). Prefer the destination side, which is the one that carries the service.
    let protocol = to.protocol.or(from.protocol).unwrap_or(Protocol::Any);

    Ok(Rule {
        number,
        action,
        direction,
        interface_in,
        interface_out,
        protocol,
        from: Endpoint {
            addr: from.addr,
            port: from.port,
        },
        to: Endpoint {
            addr: to.addr,
            port: to.port,
        },
        log,
        comment,
        v6: to.v6 || from.v6,
        route: is_route,
    })
}

/**
 * Splits a trailing parenthesised attribute group off a rule row.
 *
 * # Arguments
 *
 * * `body` (`&str`) - The rule row with the number and comment already removed.
 *
 * # Returns
 *
 * A tuple of the remaining text and the `LogMode` implied by the attributes. When the
 * trailing group is not a known attribute list, the text is returned unchanged with
 * `LogMode::None`.
 */
fn strip_attributes(body: &str) -> (&str, LogMode) {
    let trimmed = body.trim_end();
    if !trimmed.ends_with(')') {
        return (body, LogMode::None);
    }
    let Some(open) = trimmed.rfind('(') else {
        return (body, LogMode::None);
    };
    let inner = &trimmed[open + 1..trimmed.len() - 1];
    let words: Vec<&str> = inner.split(',').map(str::trim).collect();
    if words.is_empty()
        || !words
            .iter()
            .all(|w| matches!(*w, "log" | "log-all" | "out" | "in" | "log-level"))
    {
        return (body, LogMode::None);
    }
    let log = if words.contains(&"log-all") {
        LogMode::LogAll
    } else if words.contains(&"log") {
        LogMode::Log
    } else {
        LogMode::None
    };
    (trimmed[..open].trim_end(), log)
}

/**
 * Splits text into whitespace-delimited tokens with their byte offsets.
 *
 * # Arguments
 *
 * * `text` (`&str`) - The text to tokenize.
 *
 * # Returns
 *
 * A `Vec<(usize, usize, &str)>` of `(start, end, token)` triples, where the offsets
 * index into `text`.
 */
fn tokenize(text: &str) -> Vec<(usize, usize, &str)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < text.len() {
        while i < text.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let start = i;
        while i < text.len() && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if start < i {
            out.push((start, i, &text[start..i]));
        }
    }
    out
}

#[derive(Debug, Default)]
/**
 * One `To` or `From` cell of a `ufw status` row, before it is turned into an
 * [`Endpoint`].
 *
 * # Fields
 *
 * * `addr` (`Option<String>`) - The address or network, or `None` for `Anywhere`.
 * * `port` (`PortSpec`) - The port selection printed in this cell.
 * * `protocol` (`Option<Protocol>`) - The protocol suffix, when the cell carried one.
 * * `iface` (`Option<String>`) - The interface from an `on <iface>` clause.
 * * `v6` (`bool`) - Whether the cell carried the `(v6)` marker.
 */
struct Column {
    addr: Option<String>,
    port: PortSpec,
    protocol: Option<Protocol>,
    iface: Option<String>,
    v6: bool,
}

impl Column {
    /**
     * Returns a column that matches any address and any port.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * A `Column` with no address, no protocol, no interface and `PortSpec::Any`.
     */
    fn any() -> Self {
        Self {
            port: PortSpec::Any,
            ..Default::default()
        }
    }
}

/**
 * Parses one `To` or `From` cell.
 *
 * A trailing `(v6)` marker and a trailing `on <iface>` clause are removed before the
 * address and port are parsed.
 *
 * # Arguments
 *
 * * `text` (`&str`) - The cell text, already trimmed of the action word and comment.
 *
 * # Returns
 *
 * `Result<Column, String>` - The parsed column, or an error when the port
 * specification cannot be parsed.
 */
fn parse_column(text: &str) -> Result<Column, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(Column::any());
    }

    // `(v6)` can appear on either side, and always at the end.
    let (text, v6) = match text.strip_suffix("(v6)") {
        Some(rest) => (rest.trim_end(), true),
        None => (text, false),
    };

    // `on <iface>` also sits at the end.
    let (text, iface) = split_interface(text);

    let mut column = parse_endpoint(text)?;
    column.iface = iface;
    column.v6 = v6;
    Ok(column)
}

/**
 * Splits a trailing `on <iface>` clause off a column.
 *
 * The search runs from the right so a hostname containing `on` is not mangled.
 *
 * # Arguments
 *
 * * `text` (`&str`) - The column text to split.
 *
 * # Returns
 *
 * A tuple of the remaining text and the interface name, or `None` when no plausible
 * interface clause is present.
 */
fn split_interface(text: &str) -> (&str, Option<String>) {
    // Search from the right so a hostname containing "on" is not mangled.
    let mut search_from = text.len();
    while let Some(idx) = text[..search_from].rfind(" on ") {
        let candidate = text[idx + 4..].trim();
        let plausible = !candidate.is_empty()
            && !candidate.contains(char::is_whitespace)
            && !candidate.contains('/')
            && !candidate.contains('(')
            && !candidate.contains(')');
        if plausible {
            return (text[..idx].trim_end(), Some(candidate.to_string()));
        }
        search_from = idx;
        if search_from == 0 {
            break;
        }
    }
    (text, None)
}

/**
 * Parses the address and port part of a column, without `(v6)` or `on <iface>`.
 *
 * # Arguments
 *
 * * `text` (`&str`) - The column text to parse.
 *
 * # Returns
 *
 * `Result<Column, String>` - The parsed column, or an error when the port specification
 * cannot be parsed.
 */
fn parse_endpoint(text: &str) -> Result<Column, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(Column::any());
    }

    let tokens: Vec<&str> = text.split_whitespace().collect();
    if tokens.len() > 1 {
        // `<address> <portspec>` — the only two-token shape ufw prints.
        if let Some((port, protocol)) = port_token(tokens[tokens.len() - 1]) {
            let addr = tokens[..tokens.len() - 1].join(" ");
            let addr = if addr.eq_ignore_ascii_case("Anywhere") {
                None
            } else {
                Some(addr)
            };
            return Ok(Column {
                addr,
                port,
                protocol,
                ..Default::default()
            });
        }
    }

    single_token(text)
}

/**
 * Parses a column that consists of a single token.
 *
 * # Arguments
 *
 * * `text` (`&str`) - The token to interpret.
 *
 * # Returns
 *
 * `Result<Column, String>` - The parsed column. Unrecognized text is treated as an
 * application profile name; an invalid numeric port specification is an error.
 */
fn single_token(text: &str) -> Result<Column, String> {
    if text.eq_ignore_ascii_case("Anywhere") || text.eq_ignore_ascii_case("any") {
        return Ok(Column::any());
    }

    // A complete address or network, e.g. `192.168.1.0/24` or `2001:db8::/32`.
    if parse_net(text).is_some() {
        return Ok(Column {
            addr: Some(text.to_string()),
            port: PortSpec::Any,
            ..Default::default()
        });
    }

    // A `<something>/<proto>` suffix. `ufw` prints this when the port is unconstrained but the
    // protocol is not (`Anywhere/tcp`, `10.0.0.0/8/udp`).
    if let Some((prefix, suffix)) = text.rsplit_once('/') {
        if let Some(protocol) = Protocol::from_status_token(suffix) {
            let mut inner = single_token(prefix)?;
            inner.protocol = Some(protocol);
            return Ok(inner);
        }
    }

    // A bare numeric port spec: `22`, `22:80`, `80,443`.
    if text
        .chars()
        .all(|c| c.is_ascii_digit() || c == ':' || c == ',')
    {
        let port: PortSpec = text.parse()?;
        return Ok(Column {
            port,
            ..Default::default()
        });
    }

    // `(OpenSSH)` in verbose output.
    if let Some(name) = text.strip_prefix('(').and_then(|t| t.strip_suffix(')')) {
        return Ok(Column {
            port: PortSpec::App(name.to_string()),
            ..Default::default()
        });
    }

    // Anything else is an application profile name.
    Ok(Column {
        port: PortSpec::App(text.to_string()),
        ..Default::default()
    })
}

/**
 * Parses a `<port>[/<proto>]` token.
 *
 * # Arguments
 *
 * * `token` (`&str`) - The token to parse.
 *
 * # Returns
 *
 * `Option<(PortSpec, Option<Protocol>)>` - The port specification and optional
 * protocol, or `None` when the token is not a port specification.
 */
fn port_token(token: &str) -> Option<(PortSpec, Option<Protocol>)> {
    let (base, protocol) = match token.rsplit_once('/') {
        Some((base, suffix)) => (base, Some(Protocol::from_status_token(suffix)?)),
        None => (token, None),
    };
    if base.is_empty()
        || !base
            .chars()
            .all(|c| c.is_ascii_digit() || c == ':' || c == ',')
    {
        return None;
    }
    let port = base.parse::<PortSpec>().ok()?;
    Some((port, protocol))
}

// ---------------------------------------------------------------------------------------------
// status verbose
// ---------------------------------------------------------------------------------------------

/**
 * Parses the header lines of `ufw status verbose`.
 *
 * # Arguments
 *
 * * `text` (`&str`) - The complete output of `ufw status verbose`.
 *
 * # Returns
 *
 * A `ParsedHeader` with the active flag, logging level, default policies and
 * new-profile setting. Lines that are not recognized are ignored.
 */
pub fn parse_status_verbose(text: &str) -> ParsedHeader {
    let mut header = ParsedHeader::default();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Status:") {
            header.active = rest.trim().eq_ignore_ascii_case("active");
        } else if let Some(rest) = line.strip_prefix("Logging:") {
            let rest = rest.trim();
            if rest.eq_ignore_ascii_case("off") {
                header.log_level = LogLevel::Off;
                continue;
            }
            let level = rest
                .split_once('(')
                .map(|(_, inner)| inner.trim_end_matches(')'))
                .unwrap_or(rest);
            if let Some(level) = LogLevel::from_word(level) {
                header.log_level = level;
            }
        } else if let Some(rest) = line.strip_prefix("Default:") {
            parse_defaults(rest, &mut header);
        } else if let Some(rest) = line.strip_prefix("New profiles:") {
            header.new_profiles = rest.trim().to_string();
        }
    }
    header
}

/**
 * Applies the `Default:` line of verbose output to a header.
 *
 * # Arguments
 *
 * * `rest` (`&str`) - The text after `Default:`, for example `deny (incoming), allow (outgoing)`.
 * * `header` (`&mut ParsedHeader`) - The header being filled in; it is mutated in place.
 *
 * # Returns
 *
 * This function returns no value. Unrecognized directions and words are ignored.
 */
fn parse_defaults(rest: &str, header: &mut ParsedHeader) {
    for part in rest.split(',') {
        let part = part.trim();
        let Some((word, tail)) = part.split_once('(') else {
            continue;
        };
        let direction = tail.trim_end_matches(')').trim().to_ascii_lowercase();
        match direction.as_str() {
            "incoming" => {
                if let Some(policy) = Policy::from_word(word) {
                    header.default_incoming = policy;
                }
            }
            "outgoing" => {
                if let Some(policy) = Policy::from_word(word) {
                    header.default_outgoing = policy;
                }
            }
            "routed" => {
                if let Some(policy) = RoutedPolicy::from_word(word) {
                    header.default_routed = policy;
                }
            }
            _ => {}
        }
    }
}

/**
 * Merges the numbered rule list with the verbose header into the state the UI works
 * with.
 *
 * # Arguments
 *
 * * `rules` (`ParsedRules`) - The parsed rule list, consumed by value.
 * * `header` (`ParsedHeader`) - The parsed verbose header, consumed by value.
 *
 * # Returns
 *
 * A `FirewallState` whose `enabled` flag is true when either input reported the
 * firewall as active, and whose `rules_readable` flag is always true.
 */
pub fn combine_rules_and_header(rules: ParsedRules, header: ParsedHeader) -> FirewallState {
    FirewallState {
        enabled: rules.active || header.active,
        log_level: header.log_level,
        default_incoming: header.default_incoming,
        default_outgoing: header.default_outgoing,
        default_routed: header.default_routed,
        new_profiles: header.new_profiles,
        unparsed: rules.unparsed,
        rules: rules.rules,
        rules_readable: true,
    }
}

/**
 * Parses the output of `ufw status` into the state the UI works with.
 *
 * # Arguments
 *
 * * `text` (`&str`) - The output of `ufw status`, numbered or verbose.
 *
 * # Returns
 *
 * A `FirewallState` combining the numbered rule list with the verbose header.
 */
pub fn parse_status(text: &str) -> FirewallState {
    let rules = parse_status_numbered(text);
    let header = parse_status_verbose(text);
    combine_rules_and_header(rules, header)
}

// ---------------------------------------------------------------------------------------------
// application profiles
// ---------------------------------------------------------------------------------------------

/**
 * Parses one `.ufw.profile` or `applications.d` INI file, which may hold several
 * profiles.
 *
 * Comment lines and lines outside a `[section]` are ignored, as are keys other than
 * `title`, `description` and `ports`.
 *
 * # Arguments
 *
 * * `text` (`&str`) - The contents of the profile file.
 *
 * # Returns
 *
 * A `Vec<AppProfile>` with one entry per section, in file order. Sections with an empty
 * name are dropped.
 */
pub fn parse_profile_ini(text: &str) -> Vec<AppProfile> {
    let mut out: Vec<AppProfile> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            out.push(AppProfile {
                name: name.trim().to_string(),
                title: String::new(),
                description: String::new(),
                ports_raw: String::new(),
            });
            continue;
        }
        let Some(current) = out.last_mut() else {
            continue;
        };
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().to_string();
        match key.trim().to_ascii_lowercase().as_str() {
            "title" => current.title = value,
            "description" => current.description = value,
            "ports" => current.ports_raw = value,
            _ => {}
        }
    }
    out.retain(|p| !p.name.is_empty());
    out
}

// ---------------------------------------------------------------------------------------------
// /etc/ufw/ufw.conf (readable without root)
// ---------------------------------------------------------------------------------------------

/**
 * Parses `/etc/ufw/ufw.conf`, which a non-root user is allowed to read.
 *
 * # Arguments
 *
 * * `text` (`&str`) - The contents of the configuration file.
 *
 * # Returns
 *
 * A `UfwConf` with the `ENABLED` and `LOGLEVEL` values that were present. Comments and
 * unrecognized keys are ignored.
 */
pub fn parse_ufw_conf(text: &str) -> UfwConf {
    let mut conf = UfwConf::default();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim().to_ascii_uppercase().as_str() {
            "ENABLED" => conf.enabled = Some(value.trim().eq_ignore_ascii_case("yes")),
            "LOGLEVEL" => conf.log_level = LogLevel::from_word(value),
            _ => {}
        }
    }
    conf
}

// ---------------------------------------------------------------------------------------------
// ss -tulpn
// ---------------------------------------------------------------------------------------------

/**
 * Parses `ss -tulpnH` output.
 *
 * ```text
 * tcp   LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1234,fd=3))
 * ```
 *
 * # Arguments
 *
 * * `text` (`&str`) - The complete output of `ss -tulpnH`.
 *
 * # Returns
 *
 * A `Vec<Listening>` with one entry per socket that has at least five columns and a
 * parseable local address. Lines that do not fit that shape are skipped.
 */
pub fn parse_ss(text: &str) -> Vec<Listening> {
    let mut out = Vec::new();
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 5 {
            continue;
        }
        let Some((addr, port)) = split_host_port(cols[4]) else {
            continue;
        };
        let process = cols
            .iter()
            .find_map(|col| col.split("((\"").nth(1))
            .and_then(|rest| rest.split('"').next())
            .map(str::to_string);
        out.push(Listening {
            proto: cols[0].to_ascii_lowercase(),
            addr,
            port,
            process,
        });
    }
    out
}

/**
 * Splits an `address:port` value from `ss` output.
 *
 * # Arguments
 *
 * * `value` (`&str`) - The address and port, optionally with the address in brackets.
 *
 * # Returns
 *
 * `Option<(String, u16)>` - The address without brackets and the port, or `None` when
 * the value has no colon or the port is not a valid `u16`.
 */
fn split_host_port(value: &str) -> Option<(String, u16)> {
    let (host, port) = value.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    Some((host.to_string(), port))
}

// ---------------------------------------------------------------------------------------------
// kernel log: [UFW BLOCK]
// ---------------------------------------------------------------------------------------------

/**
 * Parses one kernel log line into a block event.
 *
 * # Arguments
 *
 * * `line` (`&str`) - One kernel log line, expected to contain `[UFW BLOCK]`.
 *
 * # Returns
 *
 * `Option<BlockEvent>` - The parsed event, or `None` when the line is not a ufw block
 * or its `SRC=` or `DST=` field is missing or not a valid address. Missing `SPT=`,
 * `DPT=`, `PROTO=` and `IN=` fields fall back to `0`, `?` and `?` respectively.
 */
pub fn parse_ufw_log_line(line: &str) -> Option<BlockEvent> {
    if !line.contains("[UFW BLOCK]") {
        return None;
    }
    let field = |name: &str| -> Option<&str> {
        let start = line.find(name)?;
        let rest = &line[start + name.len()..];
        rest.split_whitespace().next()
    };
    let src = field("SRC=")?.parse::<IpAddr>().ok()?;
    let dst = field("DST=").and_then(|d| d.parse::<IpAddr>().ok())?;
    let dpt = field("DPT=")
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(0);
    let spt = field("SPT=")
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(0);
    let proto = field("PROTO=").unwrap_or("?").to_ascii_lowercase();
    let iface = field("IN=").unwrap_or("?").to_string();
    Some(BlockEvent {
        iface,
        src,
        dst,
        proto,
        spt,
        dpt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::rule::PortRange;

    const ACTIVE: &str = "\
Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere                   # SSH
[ 2] 80,443/tcp                 ALLOW IN    Anywhere
[ 3] Anywhere on eth0           ALLOW IN    192.168.0.0/16
[ 4] 10.0.0.0/8                 ALLOW OUT   Anywhere on eth1
[ 5] Anywhere on eth1           ALLOW FWD   192.168.0.0/16 on eth0
[ 6] 2222/tcp                   LIMIT IN    Anywhere                   # SSH port
[ 7] OpenSSH                    ALLOW IN    10.0.0.0/8
[ 8] 53/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 9] 22/tcp                     DENY IN     Anywhere (log)
";

    #[test]
    /**
     * Verifies that a realistic numbered listing is parsed into rules.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn parses_a_realistic_numbered_listing() {
        let parsed = parse_status_numbered(ACTIVE);
        assert!(parsed.active);
        assert!(parsed.unparsed.is_empty(), "{:?}", parsed.unparsed);
        assert_eq!(parsed.rules.len(), 9);

        let ssh = &parsed.rules[0];
        assert_eq!(ssh.number, 1);
        assert_eq!(ssh.action, Action::Allow);
        assert_eq!(ssh.direction, Direction::In);
        assert_eq!(ssh.protocol, Protocol::Tcp);
        assert_eq!(ssh.to.port, PortSpec::single(22));
        assert_eq!(ssh.from.addr, None);
        assert_eq!(ssh.comment.as_deref(), Some("SSH"));
        assert!(!ssh.v6);
    }

    #[test]
    /**
     * Verifies that a comma-separated port list is parsed.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn parses_a_port_list() {
        let rule = &parse_status_numbered(ACTIVE).rules[1];
        assert_eq!(
            rule.to.port,
            PortSpec::Ports(vec![PortRange::single(80), PortRange::single(443)])
        );
    }

    #[test]
    /**
     * Verifies that interfaces are attached to the correct side of a rule.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn parses_interfaces_on_the_correct_side() {
        let rules = parse_status_numbered(ACTIVE).rules;
        // Incoming rule: the destination interface is the one traffic arrives on.
        assert_eq!(rules[2].interface_in.as_deref(), Some("eth0"));
        assert_eq!(rules[2].from.addr.as_deref(), Some("192.168.0.0/16"));

        // Outgoing rule: the "on" sits in the From column.
        assert_eq!(rules[3].direction, Direction::Out);
        assert_eq!(rules[3].interface_out.as_deref(), Some("eth1"));
        assert_eq!(rules[3].to.addr.as_deref(), Some("10.0.0.0/8"));
    }

    #[test]
    /**
     * Verifies that forwarded rules are parsed as route rules.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn parses_route_rules() {
        let rule = &parse_status_numbered(ACTIVE).rules[4];
        assert_eq!(rule.direction, Direction::Forward);
        assert!(rule.is_route());
        // For route rules the interfaces are reported from the packet's point of view.
        assert_eq!(rule.interface_in.as_deref(), Some("eth0"));
        assert_eq!(rule.interface_out.as_deref(), Some("eth1"));
    }

    #[test]
    /**
     * Verifies that limit actions and comments containing spaces are parsed.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn parses_limit_and_comments_with_spaces() {
        let rule = &parse_status_numbered(ACTIVE).rules[5];
        assert_eq!(rule.action, Action::Limit);
        assert_eq!(rule.to.port, PortSpec::single(2222));
        assert_eq!(rule.comment.as_deref(), Some("SSH port"));
    }

    #[test]
    /**
     * Verifies that application profile names are parsed as ports.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn parses_application_profiles() {
        let rule = &parse_status_numbered(ACTIVE).rules[6];
        assert_eq!(rule.to.port, PortSpec::App("OpenSSH".into()));
        assert_eq!(rule.from.addr.as_deref(), Some("10.0.0.0/8"));
    }

    #[test]
    /**
     * Verifies that the `(v6)` marker is detected.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn parses_ipv6_markers() {
        let rule = &parse_status_numbered(ACTIVE).rules[7];
        assert!(rule.v6);
        assert_eq!(rule.to.port, PortSpec::single(53));
        assert_eq!(rule.protocol, Protocol::Tcp);
    }

    #[test]
    /**
     * Verifies that the `(log)` attribute is parsed and does not leak into the From column.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn parses_the_log_attribute() {
        let rule = &parse_status_numbered(ACTIVE).rules[8];
        assert_eq!(rule.log, LogMode::Log);
        assert_eq!(rule.action, Action::Deny);
        // The `(log)` attribute must not leak into the From column.
        assert_eq!(rule.from.addr, None);
        assert_eq!(rule.to.port, PortSpec::single(22));
    }

    #[test]
    /**
     * Verifies that an inactive status yields no rules.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn handles_inactive_firewalls() {
        let parsed = parse_status_numbered("Status: inactive\n");
        assert!(!parsed.active);
        assert!(parsed.rules.is_empty());
    }

    #[test]
    /**
     * Verifies that an active status with no rules yields an empty list.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn handles_empty_rule_lists() {
        let text = "Status: active\n\n     To                         Action      From\n     --                         ------      ----\n";
        let parsed = parse_status_numbered(text);
        assert!(parsed.active);
        assert!(parsed.rules.is_empty());
    }

    #[test]
    /**
     * Verifies that a long To column without a padding gap is still parsed.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn survives_a_long_to_column_that_removes_the_padding_gap() {
        // Python's `%-26s` pads but never truncates: a 26+ character To column leaves a single
        // space before the action, which is exactly what breaks byte-offset parsers.
        let text = "\
Status: active

     To                                  Action      From
     --                                  ------      ----
[ 1] 2001:db8:1234:5678::/64 22/tcp      ALLOW IN    Anywhere
";
        let parsed = parse_status_numbered(text);
        assert_eq!(parsed.rules.len(), 1, "{:?}", parsed.unparsed);
        let rule = &parsed.rules[0];
        assert_eq!(rule.to.addr.as_deref(), Some("2001:db8:1234:5678::/64"));
        assert_eq!(rule.to.port, PortSpec::single(22));
        assert_eq!(rule.from.addr, None);
    }

    #[test]
    /**
     * Verifies that unparseable rows are kept in `unparsed`.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn keeps_unparseable_rows_instead_of_dropping_them() {
        // No recognisable action word, so the row cannot be understood.
        let text = "Status: active\n\n[ 1] this row makes no sense\n";
        let parsed = parse_status_numbered(text);
        assert_eq!(parsed.unparsed.len(), 1);
        assert_eq!(parsed.rules.len(), 0);
    }

    #[test]
    /**
     * Verifies that a protocol without a port is parsed.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn parses_a_protocol_without_a_port() {
        let text = "Status: active\n\n[ 1] Anywhere/tcp ALLOW IN Anywhere\n";
        let rule = &parse_status_numbered(text).rules[0];
        assert_eq!(rule.protocol, Protocol::Tcp);
        assert!(rule.to.port.is_any());
    }

    #[test]
    /**
     * Verifies that two-digit rule numbers are parsed.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn parses_two_digit_rule_numbers() {
        let text = "Status: active\n\n[10] 22/tcp ALLOW IN Anywhere\n";
        assert_eq!(parse_status_numbered(text).rules[0].number, 10);
    }

    #[test]
    /**
     * Verifies that the verbose header is parsed.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn parses_the_verbose_header() {
        let text = "\
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip
";
        let header = parse_status_verbose(text);
        assert!(header.active);
        assert_eq!(header.log_level, LogLevel::Low);
        assert_eq!(header.default_incoming, Policy::Deny);
        assert_eq!(header.default_outgoing, Policy::Allow);
        assert_eq!(header.default_routed, RoutedPolicy::Disabled);
        assert_eq!(header.new_profiles, "skip");
    }

    #[test]
    /**
     * Verifies that a full log level and logging off are parsed.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn parses_a_full_log_level_and_logging_off() {
        let header = parse_status_verbose("Status: active\nLogging: on (medium)\n");
        assert_eq!(header.log_level, LogLevel::Medium);
        let header = parse_status_verbose("Status: active\nLogging: off\n");
        assert_eq!(header.log_level, LogLevel::Off);
    }

    #[test]
    /**
     * Verifies that a risky default policy is parsed.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn parses_a_risky_default_policy() {
        let header = parse_status_verbose(
            "Status: active\nDefault: allow (incoming), allow (outgoing), deny (routed)\n",
        );
        assert_eq!(header.default_incoming, Policy::Allow);
        assert_eq!(header.default_routed, RoutedPolicy::Deny);
    }

    #[test]
    /**
     * Verifies that application profile files are parsed.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn parses_application_profile_files() {
        let text = "\
[OpenSSH]
title=Secure Shell Server, OpenSSH Server
description=OpenSSH is a free version of the SSH protocol
ports=22/tcp
";
        let profiles = parse_profile_ini(text);
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "OpenSSH");
        assert_eq!(profiles[0].title, "Secure Shell Server, OpenSSH Server");
        assert_eq!(profiles[0].ports_raw, "22/tcp");
        assert_eq!(profiles[0].ports(), vec![22]);
        assert_eq!(profiles[0].protocols(), vec![Protocol::Tcp]);
    }

    #[test]
    /**
     * Verifies that multi-port profiles are parsed.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn parses_multi_port_profiles() {
        let text = "[Nginx Full]\nports=80,443/tcp\n";
        let profiles = parse_profile_ini(text);
        assert_eq!(profiles[0].name, "Nginx Full");
        assert_eq!(profiles[0].ports(), vec![80, 443]);
    }

    #[test]
    /**
     * Verifies that several profiles in one file are parsed.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn parses_several_profiles_from_one_file() {
        let text = "[A]\nports=1/tcp\n[B]\nports=2/udp\n";
        let profiles = parse_profile_ini(text);
        assert_eq!(profiles.len(), 2);
        assert_eq!(profiles[1].name, "B");
    }

    #[test]
    /**
     * Verifies that `ufw.conf` is parsed without root.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn parses_ufw_conf_without_root() {
        let text = "# /etc/ufw/ufw.conf\n#\n\nENABLED=no\n\nLOGLEVEL=low\n";
        let conf = parse_ufw_conf(text);
        assert_eq!(conf.enabled, Some(false));
        assert_eq!(conf.log_level, Some(LogLevel::Low));
    }

    #[test]
    /**
     * Verifies that `ss` listening sockets are parsed.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn parses_ss_listening_sockets() {
        let text = "\
tcp   LISTEN 0      4096         0.0.0.0:22        0.0.0.0:*    users:((\"sshd\",pid=1234,fd=3))
udp   UNCONN 0      0            127.0.0.1:631     0.0.0.0:*
";
        let listening = parse_ss(text);
        assert_eq!(listening.len(), 2);
        assert_eq!(listening[0].port, 22);
        assert_eq!(listening[0].process.as_deref(), Some("sshd"));
        assert!(listening[0].is_wildcard());
        assert!(listening[1].is_loopback());
        assert_eq!(listening[1].process, None);
    }

    #[test]
    /**
     * Verifies that a `[UFW BLOCK]` log line is parsed.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn parses_a_ufw_block_log_line() {
        let line = "Oct 30 08:23:50 mainnet kernel: [12345.678901] [UFW BLOCK] IN=eno1 OUT= MAC=00:11:22:33:44:55 SRC=45.155.205.233 DST=192.168.1.19 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=54321 DF PROTO=TCP SPT=51000 DPT=22 WINDOW=65535 RES=0x00 SYN URGP=0";
        let event = parse_ufw_log_line(line).expect("should parse");
        assert_eq!(event.src.to_string(), "45.155.205.233");
        assert_eq!(event.dst.to_string(), "192.168.1.19");
        assert_eq!(event.dpt, 22);
        assert_eq!(event.spt, 51000);
        assert_eq!(event.proto, "tcp");
        assert_eq!(event.iface, "eno1");
    }

    #[test]
    /**
     * Verifies that lines without `[UFW BLOCK]` are ignored.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn ignores_lines_that_are_not_ufw_blocks() {
        assert!(parse_ufw_log_line("Oct 30 08:23:50 host apparmor=\"DENIED\"").is_none());
        assert!(parse_ufw_log_line("").is_none());
    }
}
