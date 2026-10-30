//! A deterministic packet simulator.
//!
//! It answers "would this traffic be allowed?" without touching the live firewall, and it explains
//! *why* by showing every step it considered. It also runs against a **pending** rule set, so a
//! change can be tested before it is applied.
//!
//! The modelled order mirrors ufw's real chain layout: `before.rules` (built-ins), then
//! `user.rules` in rule-number order, then the default policy.

use std::net::IpAddr;

use crate::core::firewall::{FirewallState, Policy};
use crate::core::parse::AppProfile;
use crate::core::rule::{Action, Direction, PortSpec, Protocol, Rule, RuleDraft};

#[derive(Debug, Clone, PartialEq, Eq)]
/**
 * A packet to evaluate.
 *
 * `direction` is relative to this machine.
 *
 * # Fields
 *
 * * `direction` (`Direction`) - Which way the traffic flows.
 * * `iface` (`Option<String>`) - The interface the packet arrives on, if known.
 * * `protocol` (`Protocol`) - The packet's protocol.
 * * `src` (`IpAddr`) - The source address.
 * * `src_port` (`u16`) - The source port.
 * * `dst` (`IpAddr`) - The destination address.
 * * `dst_port` (`u16`) - The destination port.
 * * `established` (`bool`) - Whether the packet belongs to an established
 *   connection.
 * * `loopback` (`bool`) - Whether the packet is loopback traffic.
 */
pub struct Packet {
    pub direction: Direction,
    pub iface: Option<String>,
    pub protocol: Protocol,
    pub src: IpAddr,
    pub src_port: u16,
    pub dst: IpAddr,
    pub dst_port: u16,
    pub established: bool,
    pub loopback: bool,
}

impl Default for Packet {
    /**
     * Implements `Default` as a plausible inbound SSH packet.
     *
     * The packet arrives on no particular interface over TCP from
     * `192.168.1.50:51000` to `192.168.1.19:22`, and is neither established nor
     * loopback.
     *
     * # Arguments
     *
     * This method takes no arguments.
     *
     * # Returns
     *
     * A `Packet` containing the default field values.
     */
    fn default() -> Self {
        Self {
            direction: Direction::In,
            iface: None,
            protocol: Protocol::Tcp,
            src: "192.168.1.50".parse().expect("valid literal"),
            src_port: 51_000,
            dst: "192.168.1.19".parse().expect("valid literal"),
            dst_port: 22,
            established: false,
            loopback: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/**
 * What produced a step in a simulation trace.
 *
 * # Variants
 *
 * * `Builtin(&'static str)` - One of ufw's built-in rules, carrying its label;
 *   these never appear in `ufw status`.
 * * `Rule(u32)` - A user rule, carrying its rule number (`0` for a pending
 *   draft).
 * * `Default` - The default policy that decided the packet.
 */
pub enum StepOwner {
    /// One of ufw's built-in rules, which the user never sees in `ufw status`.
    Builtin(&'static str),
    Rule(u32),
    Default,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/**
 * One evaluated step in a simulation trace.
 *
 * # Fields
 *
 * * `owner` (`StepOwner`) - What produced the step.
 * * `label` (`String`) - The human-readable description of the step.
 * * `action` (`Action`) - The action the step would apply.
 * * `matched` (`bool`) - Whether the step matched the packet.
 * * `shadowed` (`bool`) - True for rules that would have matched but were
 *   never reached.
 */
pub struct TraceStep {
    pub owner: StepOwner,
    pub label: String,
    pub action: Action,
    pub matched: bool,
    /// True for rules that would have matched but were never reached.
    pub shadowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/**
 * The full result of simulating one packet.
 *
 * # Fields
 *
 * * `steps` (`Vec<TraceStep>`) - Every step considered, in evaluation order.
 * * `verdict` (`Action`) - The action that decides the packet's fate.
 * * `winning_rule` (`Option<u32>`) - The number of the deciding rule, if any.
 * * `decided_by_default` (`bool`) - Whether the default policy decided it.
 * * `shadowed` (`Vec<(u32, u32)>`) - `(shadowed, shadowing)` rule pairs found.
 * * `explanation` (`String`) - A one-sentence summary of the outcome.
 * * `notes` (`Vec<String>`) - Extra advice, such as shadowing warnings.
 */
pub struct Trace {
    pub steps: Vec<TraceStep>,
    pub verdict: Action,
    pub winning_rule: Option<u32>,
    pub decided_by_default: bool,
    pub shadowed: Vec<(u32, u32)>,
    pub explanation: String,
    pub notes: Vec<String>,
}

impl Trace {
    /**
     * Returns whether the simulated packet would be let through.
     *
     * # Arguments
     *
     * * `&self` - The trace being inspected.
     *
     * # Returns
     *
     * `true` when the verdict permits traffic; otherwise, `false`.
     */
    pub fn allowed(&self) -> bool {
        self.verdict.permits()
    }
}

/**
 * Runs the simulation against the live rule set.
 *
 * This is a convenience wrapper around [`simulate_with_pending`] with no
 * pending drafts.
 *
 * # Arguments
 *
 * * `state` (`&FirewallState`) - The firewall state whose rules are evaluated.
 * * `profiles` (`&[AppProfile]`) - Application profiles used to resolve
 *   profile-based rules.
 * * `packet` (`&Packet`) - The traffic to evaluate.
 *
 * # Returns
 *
 * A `Trace` describing every step considered and the final verdict.
 */
pub fn simulate(state: &FirewallState, profiles: &[AppProfile], packet: &Packet) -> Trace {
    simulate_with_pending(state, profiles, &[], packet)
}

/**
 * Runs the simulation against the live rule set plus rules not yet applied.
 *
 * Built-in rules are evaluated first, then the live and pending rules in
 * order, and finally the default policy. Shadowed rules are detected and
 * reported in the trace notes.
 *
 * # Arguments
 *
 * * `state` (`&FirewallState`) - The firewall state whose rules are evaluated.
 * * `profiles` (`&[AppProfile]`) - Application profiles used to resolve
 *   profile-based rules.
 * * `pending` (`&[RuleDraft]`) - Draft rules to evaluate as if they were
 *   applied, numbered `0`.
 * * `packet` (`&Packet`) - The traffic to evaluate.
 *
 * # Returns
 *
 * A `Trace` containing the evaluated steps, the verdict, the winning rule (if
 * any), and an explanation.
 */
pub fn simulate_with_pending(
    state: &FirewallState,
    profiles: &[AppProfile],
    pending: &[RuleDraft],
    packet: &Packet,
) -> Trace {
    let mut steps = Vec::new();

    for builtin in builtin_steps(packet) {
        let matched = builtin.matches(packet);
        steps.push(TraceStep {
            owner: StepOwner::Builtin(builtin.label),
            label: builtin.label.to_string(),
            action: builtin.action,
            matched,
            shadowed: false,
        });
        if matched {
            return finish(steps, builtin.action, None, false, packet);
        }
    }

    let mut candidates: Vec<Rule> = state
        .rules
        .iter()
        .filter(|r| r.direction == packet.direction && !r.is_route())
        .cloned()
        .collect();
    for draft in pending {
        candidates.push(draft.to_rule(0));
    }

    let mut winner: Option<usize> = None;
    for (index, rule) in candidates.iter().enumerate() {
        let matched = matches_rule(rule, profiles, packet);
        let label = rule_label(rule);
        steps.push(TraceStep {
            owner: StepOwner::Rule(rule.number),
            label,
            action: rule.action,
            matched,
            shadowed: false,
        });
        if matched && winner.is_none() {
            winner = Some(index);
        }
    }

    if let Some(index) = winner {
        let winning = &candidates[index];
        let mut trace = finish(steps, winning.action, Some(winning.number), false, packet);

        // A rule is "shadowed" when an earlier rule matches everything it would match, so it can
        // never fire. That is a property of the rule set, not of this packet, so it is computed
        // over all candidates — but only reported when it explains this packet's path.
        let shadowed = crate::core::risk::find_shadowed(&candidates, profiles);
        if !shadowed.is_empty() {
            for step in trace.steps.iter_mut() {
                if let StepOwner::Rule(number) = &step.owner {
                    if shadowed.iter().any(|(later, _)| later == number) {
                        step.shadowed = true;
                    }
                }
            }
            let list = shadowed
                .iter()
                .map(|(later, by)| format!("#{later} is shadowed by #{by}"))
                .collect::<Vec<_>>()
                .join(", ");
            trace.notes.push(format!(
                "{list}. A rule that is completely covered by one above it never runs; move the more specific rule up if you meant it to win."
            ));
            trace.shadowed = shadowed;
        }
        return trace;
    }

    let policy = match packet.direction {
        Direction::Out => state.default_outgoing,
        _ => state.default_incoming,
    };
    let action = match policy {
        Policy::Allow => Action::Allow,
        Policy::Deny => Action::Deny,
        Policy::Reject => Action::Reject,
    };
    steps.push(TraceStep {
        owner: StepOwner::Default,
        label: format!("default {} policy", direction_word(packet.direction)),
        action,
        matched: true,
        shadowed: false,
    });
    finish(steps, action, None, true, packet)
}

/**
 * Assembles the final trace once a verdict is known.
 *
 * The explanation is built from the traffic description, the outcome and the
 * step that decided it.
 *
 * # Arguments
 *
 * * `steps` (`Vec<TraceStep>`) - The steps evaluated so far, in order.
 * * `verdict` (`Action`) - The action that decides the packet's fate.
 * * `winning_rule` (`Option<u32>`) - The number of the deciding rule, if any.
 * * `by_default` (`bool`) - Whether the default policy decided the outcome.
 * * `packet` (`&Packet`) - The packet being simulated, used for the wording.
 *
 * # Returns
 *
 * A `Trace` with the steps, verdict, explanation and empty notes.
 */
fn finish(
    steps: Vec<TraceStep>,
    verdict: Action,
    winning_rule: Option<u32>,
    by_default: bool,
    packet: &Packet,
) -> Trace {
    let traffic = describe_traffic(packet);
    let outcome = match verdict {
        Action::Allow => "ALLOWED",
        Action::Deny => "BLOCKED (silently dropped)",
        Action::Reject => "REFUSED (the sender is told)",
        Action::Limit => "ALLOWED (rate limited)",
    };
    let winner_step = steps.iter().find(|s| s.matched);
    let because = match winner_step.map(|s| (&s.owner, s.label.as_str())) {
        Some((StepOwner::Default, _)) => {
            "by the default policy, because no rule matched".to_string()
        }
        Some((StepOwner::Builtin(name), _)) => format!("by ufw's built-in rule: {name}"),
        _ => match winning_rule {
            Some(number) if number > 0 => format!("by rule #{number}"),
            _ => "by the pending rule you are drafting".to_string(),
        },
    };
    Trace {
        steps,
        verdict,
        winning_rule,
        decided_by_default: by_default,
        shadowed: Vec::new(),
        explanation: format!("{traffic} would be {outcome} {because}."),
        notes: Vec::new(),
    }
}

/**
 * Returns the adjective used for a direction in prose.
 *
 * # Arguments
 *
 * * `direction` (`Direction`) - The direction to describe.
 *
 * # Returns
 *
 * A `&'static str` containing `incoming`, `outgoing` or `forwarding`.
 */
fn direction_word(direction: Direction) -> &'static str {
    match direction {
        Direction::In => "incoming",
        Direction::Out => "outgoing",
        Direction::Forward => "forwarding",
    }
}

/**
 * Describes a packet in one plain-English clause.
 *
 * The wording depends on the direction: incoming traffic names the source
 * address and both ports, outgoing traffic names the destination, and
 * forwarded traffic is described generically.
 *
 * # Arguments
 *
 * * `packet` (`&Packet`) - The packet to describe.
 *
 * # Returns
 *
 * A `String` containing the traffic description.
 */
fn describe_traffic(packet: &Packet) -> String {
    match packet.direction {
        Direction::In => format!(
            "A computer at {} connecting from port {} to port {} ({}) on this machine",
            packet.src,
            packet.src_port,
            packet.dst_port,
            packet.protocol.label()
        ),
        Direction::Out => format!(
            "Traffic from this machine from port {} to {} port {} ({})",
            packet.src_port,
            packet.dst,
            packet.dst_port,
            packet.protocol.label()
        ),
        Direction::Forward => "Forwarded traffic".to_string(),
    }
}

/**
 * Builds the one-line label shown for a rule in the trace.
 *
 * The label combines the action, the described port selection, the source
 * address (or `from anywhere`) and the incoming interface when present.
 *
 * # Arguments
 *
 * * `rule` (`&Rule`) - The rule to label.
 *
 * # Returns
 *
 * A `String` containing the human-readable rule label.
 */
fn rule_label(rule: &Rule) -> String {
    let mut out = format!(
        "{} {}",
        rule.action.label(),
        crate::core::explain::describe_port(&rule.to.port, rule.protocol)
    );
    if let Some(addr) = &rule.from.addr {
        out.push_str(&format!(" from {addr}"));
    } else {
        out.push_str(" from anywhere");
    }
    if let Some(iface) = &rule.interface_in {
        out.push_str(&format!(" on {iface}"));
    }
    out
}

/**
 * A built-in ufw rule that is evaluated before the user's rules.
 *
 * The predicate is kept as a function pointer so the rule list stays
 * declarative.
 *
 * # Fields
 *
 * * `label` (`&'static str`) - The description shown in the trace.
 * * `action` (`Action`) - The action applied when the rule matches.
 * * `matches` (`fn(&Packet) -> bool`) - The predicate deciding a match.
 */
struct Builtin {
    label: &'static str,
    action: Action,
    /// Predicate, kept as a fn pointer so the list stays declarative.
    matches: fn(&Packet) -> bool,
}

impl Builtin {
    /**
     * Evaluates the built-in rule's predicate against a packet.
     *
     * # Arguments
     *
     * * `&self` - The built-in rule being evaluated.
     * * `packet` (`&Packet`) - The packet to test.
     *
     * # Returns
     *
     * `true` when the built-in rule matches the packet; otherwise, `false`.
     */
    fn matches(&self, packet: &Packet) -> bool {
        (self.matches)(packet)
    }
}

/**
 * Returns the built-in rules that apply to a packet's direction.
 *
 * Loopback, established connections, ICMP echo, DHCP replies and mDNS are
 * always considered. For traffic that is not incoming, only the loopback
 * built-in is kept, because the others only apply to traffic arriving at this
 * host.
 *
 * # Arguments
 *
 * * `packet` (`&Packet`) - The packet whose direction selects the rule set.
 *
 * # Returns
 *
 * A `Vec<Builtin>` of the applicable built-in rules, in evaluation order.
 */
fn builtin_steps(packet: &Packet) -> Vec<Builtin> {
    let mut out = vec![
        Builtin {
            label: "loopback traffic is always allowed",
            action: Action::Allow,
            matches: |p| p.loopback,
        },
        Builtin {
            label: "part of an already-established connection",
            action: Action::Allow,
            matches: |p| p.established,
        },
        Builtin {
            label: "ICMP echo request (ping)",
            action: Action::Allow,
            matches: |p| p.protocol == Protocol::Icmp && p.dst_port == 8,
        },
        Builtin {
            label: "DHCP reply",
            action: Action::Allow,
            matches: |p| p.protocol == Protocol::Udp && p.src_port == 67 && p.dst_port == 68,
        },
        Builtin {
            label: "mDNS service discovery",
            action: Action::Allow,
            matches: |p| p.protocol == Protocol::Udp && p.dst_port == 5353,
        },
    ];
    // Built-ins only apply to traffic arriving at this host.
    if packet.direction != Direction::In {
        out.retain(|b| b.label == "loopback traffic is always allowed");
    }
    out
}

/**
 * Returns whether a rule matches a packet.
 *
 * This is pure and is the single definition of matching used everywhere. A
 * rule matches when the direction agrees, the interface agrees (when both
 * sides specify one), both addresses fall inside the rule's networks, the
 * protocol agrees, and both ports match.
 *
 * # Arguments
 *
 * * `rule` (`&Rule`) - The rule to test.
 * * `profiles` (`&[AppProfile]`) - Application profiles used to resolve
 *   profile-based ports.
 * * `packet` (`&Packet`) - The packet to test.
 *
 * # Returns
 *
 * `true` when the rule matches the packet; otherwise, `false`.
 */
pub fn matches_rule(rule: &Rule, profiles: &[AppProfile], packet: &Packet) -> bool {
    if rule.direction != packet.direction {
        return false;
    }
    if let (Some(rule_iface), Some(packet_iface)) = (&rule.interface_in, &packet.iface) {
        if rule_iface != packet_iface {
            return false;
        }
    }
    if let Some(net) = rule.from.net() {
        if !net.contains(&packet.src) {
            return false;
        }
    }
    if let Some(net) = rule.to.net() {
        if !net.contains(&packet.dst) {
            return false;
        }
    }
    if rule.protocol != Protocol::Any && rule.protocol != packet.protocol {
        return false;
    }
    if !port_matches(&rule.from.port, profiles, packet.src_port, &rule.protocol) {
        return false;
    }
    port_matches(&rule.to.port, profiles, packet.dst_port, &rule.protocol)
}

/**
 * Returns whether a port specification matches a port and protocol.
 *
 * Application profiles are resolved through the supplied profile list; an
 * unknown profile never matches, because inventing a match would be worse than
 * missing one.
 *
 * # Arguments
 *
 * * `spec` (`&PortSpec`) - The port selection to test.
 * * `profiles` (`&[AppProfile]`) - Application profiles used to resolve
 *   profile-based selections.
 * * `port` (`u16`) - The port to test.
 * * `protocol` (`&Protocol`) - The protocol to test against the profile.
 *
 * # Returns
 *
 * `true` when the specification covers the port and protocol; otherwise,
 * `false`.
 */
fn port_matches(spec: &PortSpec, profiles: &[AppProfile], port: u16, protocol: &Protocol) -> bool {
    match spec {
        PortSpec::Any => true,
        PortSpec::Ports(_) => spec.contains(port),
        PortSpec::App(name) => match profiles.iter().find(|p| p.name.eq_ignore_ascii_case(name)) {
            Some(profile) => {
                let port_hit = profile.ports().contains(&port);
                if !port_hit {
                    return false;
                }
                match protocol {
                    Protocol::Any => true,
                    proto => profile.protocols().iter().any(|p| p == proto),
                }
            }
            // Unknown profile: do not invent a match.
            None => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::rule::{Endpoint, LogMode, PortRange};

    /**
     * Builds an inbound TCP rule for use in simulation tests.
     *
     * # Arguments
     *
     * * `number` (`u32`) - The rule number to assign.
     * * `action` (`Action`) - The action the rule applies.
     * * `action_dir` (`Direction`) - The direction the rule applies to.
     * * `ports` (`PortSpec`) - The destination port selection.
     * * `from` (`Option<&str>`) - An optional source address.
     *
     * # Returns
     *
     * A `Rule` configured with the given fields and no interface, logging or
     * comment.
     */
    fn rule(
        number: u32,
        action: Action,
        action_dir: Direction,
        ports: PortSpec,
        from: Option<&str>,
    ) -> Rule {
        Rule {
            number,
            action,
            direction: action_dir,
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

    /**
     * Builds an enabled, readable firewall state around a rule list.
     *
     * # Arguments
     *
     * * `rules` (`Vec<Rule>`) - The rules to place in the state.
     *
     * # Returns
     *
     * A `FirewallState` with the given rules and default policies.
     */
    fn state(rules: Vec<Rule>) -> FirewallState {
        FirewallState {
            enabled: true,
            rules_readable: true,
            rules,
            ..Default::default()
        }
    }

    /**
     * Builds an inbound TCP packet aimed at this machine's SSH port.
     *
     * # Arguments
     *
     * * `ip` (`&str`) - The source address to parse.
     * * `port` (`u16`) - The destination port to target.
     *
     * # Returns
     *
     * A `Packet` arriving from `ip:51000` at `192.168.1.19:port`.
     */
    fn ssh_from(ip: &str, port: u16) -> Packet {
        Packet {
            direction: Direction::In,
            iface: None,
            protocol: Protocol::Tcp,
            src: ip.parse().unwrap(),
            src_port: 51_000,
            dst: "192.168.1.19".parse().unwrap(),
            dst_port: port,
            established: false,
            loopback: false,
        }
    }

    #[test]
    /**
     * Verifies that a matching allow rule decides the packet.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn an_allowing_rule_wins() {
        let trace = simulate(
            &state(vec![rule(
                1,
                Action::Allow,
                Direction::In,
                PortSpec::single(22),
                None,
            )]),
            &[],
            &ssh_from("203.0.113.9", 22),
        );
        assert!(trace.allowed());
        assert_eq!(trace.winning_rule, Some(1));
        assert!(trace.explanation.contains("rule #1"));
    }

    #[test]
    /**
     * Verifies that the default policy decides when no rule matches.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn the_default_policy_decides_when_nothing_matches() {
        let mut st = state(vec![]);
        st.default_incoming = Policy::Deny;
        let trace = simulate(&st, &[], &ssh_from("203.0.113.9", 22));
        assert!(!trace.allowed());
        assert!(trace.decided_by_default);
        assert!(trace.explanation.contains("default policy"));
    }

    #[test]
    /**
     * Verifies that a LAN-restricted rule does not admit internet traffic.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn a_lan_restricted_rule_does_not_let_the_internet_in() {
        let st = state(vec![rule(
            1,
            Action::Allow,
            Direction::In,
            PortSpec::single(22),
            Some("192.168.1.0/24"),
        )]);
        assert!(simulate(&st, &[], &ssh_from("203.0.113.9", 22)).decided_by_default);
        assert!(simulate(&st, &[], &ssh_from("192.168.1.50", 22)).allowed());
    }

    #[test]
    /**
     * Verifies that the earliest matching rule wins.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn the_first_matching_rule_wins() {
        let st = state(vec![
            rule(1, Action::Deny, Direction::In, PortSpec::single(22), None),
            rule(2, Action::Allow, Direction::In, PortSpec::single(22), None),
        ]);
        let trace = simulate(&st, &[], &ssh_from("203.0.113.9", 22));
        assert_eq!(trace.winning_rule, Some(1));
        assert!(!trace.allowed());
    }

    #[test]
    /**
     * Verifies that loopback traffic is allowed by a built-in rule.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn loopback_is_allowed_before_any_rule() {
        let mut packet = ssh_from("127.0.0.1", 22);
        packet.loopback = true;
        let trace = simulate(
            &state(vec![rule(
                1,
                Action::Deny,
                Direction::In,
                PortSpec::single(22),
                None,
            )]),
            &[],
            &packet,
        );
        assert!(trace.allowed());
        assert!(trace.explanation.contains("built-in"));
    }

    #[test]
    /**
     * Verifies that established connections are allowed by a built-in rule.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn established_connections_are_allowed() {
        let mut packet = ssh_from("203.0.113.9", 22);
        packet.established = true;
        let trace = simulate(
            &state(vec![rule(
                1,
                Action::Deny,
                Direction::In,
                PortSpec::single(22),
                None,
            )]),
            &[],
            &packet,
        );
        assert!(trace.allowed());
    }

    #[test]
    /**
     * Verifies that ICMP echo requests are allowed by a built-in rule.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn ping_is_allowed_by_a_builtin_rule() {
        let mut packet = ssh_from("203.0.113.9", 22);
        packet.protocol = Protocol::Icmp;
        packet.dst_port = 8;
        let trace = simulate(&state(vec![]), &[], &packet);
        assert!(trace.allowed());
        assert!(trace.explanation.contains("ping"));
    }

    #[test]
    /**
     * Verifies that a broad rule shadowing a specific one is reported.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn detects_a_broad_rule_shadowing_a_specific_one() {
        let st = state(vec![
            rule(1, Action::Allow, Direction::In, PortSpec::single(22), None),
            rule(
                2,
                Action::Allow,
                Direction::In,
                PortSpec::single(22),
                Some("192.168.1.0/24"),
            ),
        ]);
        let trace = simulate(&st, &[], &ssh_from("192.168.1.50", 22));
        assert_eq!(trace.winning_rule, Some(1));
        assert_eq!(trace.shadowed, vec![(2, 1)]);
        assert!(trace.notes.iter().any(|n| n.contains("shadowed")));
        assert!(trace.steps.iter().any(|s| s.shadowed));
    }

    #[test]
    /**
     * Verifies that a specific rule above a broad one is not flagged.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn a_specific_rule_above_a_broad_one_is_not_shadowed() {
        let st = state(vec![
            rule(
                1,
                Action::Deny,
                Direction::In,
                PortSpec::single(22),
                Some("203.0.113.0/24"),
            ),
            rule(2, Action::Allow, Direction::In, PortSpec::single(22), None),
        ]);
        let trace = simulate(&st, &[], &ssh_from("203.0.113.9", 22));
        assert_eq!(trace.winning_rule, Some(1));
        assert!(trace.shadowed.is_empty());
        assert!(!trace.allowed());
    }

    #[test]
    /**
     * Verifies that pending drafts participate in the simulation.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn pending_rules_participate_without_a_number() {
        let mut st = state(vec![]);
        st.default_incoming = Policy::Deny;
        let draft = RuleDraft::allow_port(Protocol::Tcp, 22);
        let trace = simulate_with_pending(&st, &[], &[draft], &ssh_from("203.0.113.9", 22));
        assert!(trace.allowed());
        assert!(trace.explanation.contains("pending rule"));
    }

    #[test]
    /**
     * Verifies that interface restrictions are honoured.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn interfaces_are_respected() {
        let mut r = rule(1, Action::Allow, Direction::In, PortSpec::single(22), None);
        r.interface_in = Some("eno1".into());
        let st = state(vec![r]);
        let mut packet = ssh_from("203.0.113.9", 22);
        packet.iface = Some("wlan0".into());
        assert!(simulate(&st, &[], &packet).decided_by_default);
        packet.iface = Some("eno1".into());
        assert!(simulate(&st, &[], &packet).allowed());
    }

    #[test]
    /**
     * Verifies that protocol restrictions are honoured.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn protocols_are_respected() {
        let st = state(vec![rule(
            1,
            Action::Allow,
            Direction::In,
            PortSpec::single(53),
            None,
        )]);
        let mut packet = ssh_from("203.0.113.9", 53);
        packet.protocol = Protocol::Udp;
        assert!(simulate(&st, &[], &packet).decided_by_default);
        packet.protocol = Protocol::Tcp;
        assert!(simulate(&st, &[], &packet).allowed());
    }

    #[test]
    /**
     * Verifies that port ranges match every port they span.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn port_ranges_match_their_span() {
        let st = state(vec![rule(
            1,
            Action::Allow,
            Direction::In,
            PortSpec::Ports(vec![PortRange::new(8000, 8100).unwrap()]),
            None,
        )]);
        assert!(simulate(&st, &[], &ssh_from("203.0.113.9", 8050)).allowed());
        assert!(simulate(&st, &[], &ssh_from("203.0.113.9", 8101)).decided_by_default);
    }

    #[test]
    /**
     * Verifies that application profiles resolve through their ports.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn application_profiles_resolve_through_their_ports() {
        let profile = AppProfile {
            name: "OpenSSH".into(),
            title: String::new(),
            description: String::new(),
            ports_raw: "22/tcp".into(),
        };
        let st = state(vec![rule(
            1,
            Action::Allow,
            Direction::In,
            PortSpec::App("OpenSSH".into()),
            None,
        )]);
        assert!(simulate(
            &st,
            std::slice::from_ref(&profile),
            &ssh_from("203.0.113.9", 22)
        )
        .allowed());
        // Without the profile we refuse to guess.
        assert!(simulate(&st, &[], &ssh_from("203.0.113.9", 22)).decided_by_default);
    }

    #[test]
    /**
     * Verifies that outgoing traffic uses the outgoing default policy.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn outgoing_traffic_uses_the_outgoing_default() {
        let mut st = state(vec![]);
        st.default_outgoing = Policy::Allow;
        let mut packet = ssh_from("192.168.1.19", 22);
        packet.direction = Direction::Out;
        packet.src = "192.168.1.19".parse().unwrap();
        packet.dst = "203.0.113.9".parse().unwrap();
        assert!(simulate(&st, &[], &packet).allowed());
    }

    #[test]
    /**
     * Verifies that reject and deny produce different explanations.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it asserts the expected behavior.
     */
    fn reject_reads_differently_from_deny() {
        let st = state(vec![rule(
            1,
            Action::Reject,
            Direction::In,
            PortSpec::single(22),
            None,
        )]);
        let trace = simulate(&st, &[], &ssh_from("203.0.113.9", 22));
        assert!(!trace.allowed());
        assert!(trace.explanation.contains("REFUSED"));
    }
}
