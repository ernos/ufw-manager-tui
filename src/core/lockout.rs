//! Lockout protection.
//!
//! `ufw enable`, `ufw reset` and changing the default policy all flush the firewall's chains,
//! which drops existing connections — including the SSH session the user is typing in. This module
//! decides, before anything runs, whether the pending change can cost the user their access.

use std::net::IpAddr;

use crate::core::firewall::FirewallState;
use crate::core::rule::{Rule, RuleDraft};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/**
 * Who is driving, and from where.
 *
 * The lockout guard uses this to decide whether a change could cut the connection the
 * user is typing in.
 *
 * # Fields
 *
 * * `via_ssh` (`bool`) - Whether the session arrived over SSH.
 * * `client` (`Option<IpAddr>`) - The address the session comes from, when known.
 * * `server` (`Option<IpAddr>`) - The address the session is connected to, when known.
 * * `port` (`Option<u16>`) - The server port the session is connected to, when known.
 */
pub struct Session {
    pub via_ssh: bool,
    pub client: Option<IpAddr>,
    pub server: Option<IpAddr>,
    pub port: Option<u16>,
}

impl Session {
    /**
     * Parses `SSH_CONNECTION`, whose format is
     * `client_ip client_port server_ip server_port`.
     *
     * # Arguments
     *
     * * `value` (`&str`) - The raw environment variable value.
     *
     * # Returns
     *
     * `Option<Self>` - A session with `via_ssh` set and the parsed client, server and
     * port, or `None` when fewer than four fields are present. Fields that fail to parse
     * are left as `None` rather than failing the whole session.
     */
    pub fn from_ssh_connection(value: &str) -> Option<Self> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 4 {
            return None;
        }
        Some(Self {
            via_ssh: true,
            client: parts[0].parse().ok(),
            server: parts[2].parse().ok(),
            port: parts[3].parse().ok(),
        })
    }

    /**
     * Returns a session that represents a local, non-SSH login.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * A `Session` with `via_ssh` false and no client, server or port information.
     */
    pub fn local() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/**
 * The kind of change the user is about to apply.
 *
 * The guard only inspects the kinds that can cut an existing connection; the rest are
 * allowed without further checks.
 *
 * # Variants
 *
 * * `AddRule` - A new rule is added.
 * * `DeleteRule` - An existing rule is deleted.
 * * `EditRule` - An existing rule is replaced.
 * * `MoveRule` - A rule is reordered.
 * * `Enable` - The firewall is turned on.
 * * `Disable` - The firewall is turned off.
 * * `SetDefaultIncoming` - The default incoming policy changes.
 * * `SetLogging` - The logging level changes.
 * * `Reset` - The firewall is reset to its defaults.
 */
pub enum ChangeKind {
    AddRule,
    DeleteRule,
    EditRule,
    MoveRule,
    Enable,
    Disable,
    SetDefaultIncoming,
    SetLogging,
    Reset,
}

#[derive(Debug, Clone)]
/**
 * A change that has been prepared but not yet applied, together with the context the
 * lockout guard needs to judge it.
 *
 * # Fields
 *
 * * `kind` (`ChangeKind`) - Which operation is about to run.
 * * `description` (`String`) - The plain-English description shown to the user.
 * * `rule` (`Option<Rule>`) - The existing rule being deleted, edited or moved.
 * * `draft` (`Option<RuleDraft>`) - The rule being added or the replacement being edited in.
 * * `forced` (`bool`) - `true` when the user has explicitly opted into dangerous operations.
 */
pub struct PendingChange {
    pub kind: ChangeKind,
    pub description: String,
    /// The existing rule being deleted, edited or moved.
    pub rule: Option<Rule>,
    /// The rule being added or the replacement being edited in.
    pub draft: Option<RuleDraft>,
    /// `true` when the user has explicitly opted into dangerous operations.
    pub forced: bool,
}

impl PendingChange {
    /**
     * Creates a pending change with no rule or draft attached.
     *
     * # Arguments
     *
     * * `kind` (`ChangeKind`) - The kind of change being described.
     * * `description` (`impl Into<String>`) - The plain-English description shown to the
     *   user.
     *
     * # Returns
     *
     * A `PendingChange` with `rule` and `draft` unset and `forced` false.
     */
    pub fn new(kind: ChangeKind, description: impl Into<String>) -> Self {
        Self {
            kind,
            description: description.into(),
            rule: None,
            draft: None,
            forced: false,
        }
    }

    /**
     * Attaches the existing rule involved in the change.
     *
     * # Arguments
     *
     * * `self` (`Self`) - The pending change being built; it is consumed and returned.
     * * `rule` (`Rule`) - The rule being deleted, edited or moved.
     *
     * # Returns
     *
     * The same `PendingChange` with `rule` set.
     */
    pub fn with_rule(mut self, rule: Rule) -> Self {
        self.rule = Some(rule);
        self
    }

    /**
     * Attaches the replacement draft involved in the change.
     *
     * # Arguments
     *
     * * `self` (`Self`) - The pending change being built; it is consumed and returned.
     * * `draft` (`RuleDraft`) - The rule being added or the replacement being edited in.
     *
     * # Returns
     *
     * The same `PendingChange` with `draft` set.
     */
    pub fn with_draft(mut self, draft: RuleDraft) -> Self {
        self.draft = Some(draft);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/**
 * The lockout guard's decision about a pending change.
 *
 * # Variants
 *
 * * `Allow` - The change is safe to run.
 * * `Warn(String)` - Proceed, but the user must read the message first.
 * * `Block(String)` - Refuse the change; the message explains what to do instead.
 */
pub enum GuardVerdict {
    Allow,
    /// Proceed, but the user must read a warning first.
    Warn(String),
    /// Refuse. The message must explain what to do instead.
    Block(String),
}

impl GuardVerdict {
    /**
     * Returns whether the verdict allows the change to proceed.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The verdict being inspected.
     *
     * # Returns
     *
     * `true` for [`GuardVerdict::Allow`] and [`GuardVerdict::Warn`]; `false` for
     * [`GuardVerdict::Block`].
     */
    pub fn permits(&self) -> bool {
        !matches!(self, GuardVerdict::Block(_))
    }

    /**
     * Returns the warning or block message, if any.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The verdict being inspected.
     *
     * # Returns
     *
     * `Option<&str>` - The message for `Warn` and `Block`, or `None` for `Allow`.
     */
    pub fn message(&self) -> Option<&str> {
        match self {
            GuardVerdict::Allow => None,
            GuardVerdict::Warn(m) | GuardVerdict::Block(m) => Some(m),
        }
    }
}

/**
 * Decides whether a pending change can cost the user their access.
 *
 * Only reset, enable, default-policy changes, and deleting or editing the rule that
 * carries the current SSH session are examined; everything else is allowed.
 *
 * # Arguments
 *
 * * `session` (`&Session`) - Who is driving and from where.
 * * `pending` (`&PendingChange`) - The change about to run.
 * * `state` (`&FirewallState`) - The current firewall state, used to look for a rule that keeps the session alive.
 *
 * # Returns
 *
 * A `GuardVerdict`: `Allow` to proceed, `Warn` to proceed after a warning, or `Block`
 * with an explanation of what to do instead.
 */
pub fn check(session: &Session, pending: &PendingChange, state: &FirewallState) -> GuardVerdict {
    // Everything outside the four dangerous operations is safe by construction.
    match pending.kind {
        ChangeKind::AddRule | ChangeKind::SetLogging | ChangeKind::MoveRule => GuardVerdict::Allow,
        ChangeKind::Disable => GuardVerdict::Allow,
        ChangeKind::Reset => {
            if pending.forced {
                GuardVerdict::Allow
            } else {
                GuardVerdict::Block(
                    "Resetting deletes every rule and turns the firewall off. It cannot be undone, and if you are connected over SSH you will probably not be able to reconnect. Do it from the console instead."
                        .into(),
                )
            }
        }
        ChangeKind::Enable => {
            if !session.via_ssh {
                return GuardVerdict::Allow;
            }
            let port = session.port.unwrap_or(22);
            match state.permitting_rule(port, session.client) {
                Some(rule) => GuardVerdict::Warn(format!(
                    "Turning the firewall on reloads every chain, which can briefly drop your SSH connection. Rule #{} already allows SSH on port {port}, so you should be able to reconnect.",
                    rule.number
                )),
                None => GuardVerdict::Block(format!(
                    "Turning the firewall on right now would cut your SSH session on port {port}: no rule allows it, so you would not be able to reconnect. Add an SSH rule first."
                )),
            }
        }
        ChangeKind::SetDefaultIncoming => GuardVerdict::Warn(
            "Changing the default policy reloads the firewall and drops existing connections, including yours. Your SSH rule (if any) keeps you able to reconnect."
                .into(),
        ),
        ChangeKind::DeleteRule => {
            let Some(rule) = &pending.rule else {
                return GuardVerdict::Allow;
            };
            if permits_session(session, rule) {
                return GuardVerdict::Block(format!(
                    "Rule #{} is the one keeping your SSH session open. Deleting it would lock you out. Restrict it to your local network instead of removing it.",
                    rule.number
                ));
            }
            GuardVerdict::Allow
        }
        ChangeKind::EditRule => {
            let Some(rule) = &pending.rule else {
                return GuardVerdict::Allow;
            };
            if !permits_session(session, rule) {
                return GuardVerdict::Allow;
            }
            match &pending.draft {
                Some(draft) if draft_still_permits(session, draft) => GuardVerdict::Allow,
                _ => GuardVerdict::Block(format!(
                    "Rule #{} is the one keeping your SSH session open, and this change would stop it matching you. If you need to narrow it, keep your own address inside the new range.",
                    rule.number
                )),
            }
        }
    }
}

/**
 * Returns whether a rule keeps the current SSH session open.
 *
 * # Arguments
 *
 * * `session` (`&Session`) - The session to test.
 * * `rule` (`&Rule`) - The rule to test against the session's port and client address.
 *
 * # Returns
 *
 * `true` when the session is over SSH, the rule permits traffic, and the rule matches
 * the session's port and client address; otherwise, `false`.
 */
fn permits_session(session: &Session, rule: &Rule) -> bool {
    if !session.via_ssh || !rule.action.permits() {
        return false;
    }
    let port = session.port.unwrap_or(22);
    let port_matches = rule.to.port.contains(port) || rule.to.port.is_any();
    if !port_matches {
        return false;
    }
    match (&rule.from.net(), session.client) {
        (None, _) => true,
        (Some(net), Some(client)) => net.contains(&client),
        (Some(_), None) => true,
    }
}

/**
 * Returns whether a draft rule would still keep the current SSH session open.
 *
 * # Arguments
 *
 * * `session` (`&Session`) - The session to test.
 * * `draft` (`&RuleDraft`) - The replacement rule being edited in.
 *
 * # Returns
 *
 * `true` when the draft, converted to a rule, still permits the session; otherwise,
 * `false`.
 */
fn draft_still_permits(session: &Session, draft: &RuleDraft) -> bool {
    let rule = draft.to_rule(0);
    permits_session(session, &rule)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::rule::{Action, Direction, Endpoint, LogMode, PortSpec, Protocol};

    /**
     * Builds an inbound TCP rule for use in lockout tests.
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
            log: LogMode::None,
            comment: None,
            v6: false,
            route: false,
        }
    }

    /**
     * Builds a session parsed from a typical `SSH_CONNECTION` value.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * A `Session` for client `192.168.1.50` connecting to port 22 on `192.168.1.19`.
     *
     * # Panics
     *
     * Panics if the hard-coded value fails to parse, which would indicate a broken test.
     */
    fn ssh_session() -> Session {
        Session::from_ssh_connection("192.168.1.50 51234 192.168.1.19 22").unwrap()
    }

    #[test]
    /**
     * Verifies that `SSH_CONNECTION` is parsed into a session.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn parses_ssh_connection() {
        let session = ssh_session();
        assert!(session.via_ssh);
        assert_eq!(session.client.unwrap().to_string(), "192.168.1.50");
        assert_eq!(session.server.unwrap().to_string(), "192.168.1.19");
        assert_eq!(session.port, Some(22));
    }

    #[test]
    /**
     * Verifies that short or malformed `SSH_CONNECTION` values are rejected.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn rejects_short_or_malformed_values() {
        assert!(Session::from_ssh_connection("").is_none());
        assert!(Session::from_ssh_connection("1.2.3.4 22").is_none());
    }

    #[test]
    /**
     * Verifies that a local session is never blocked.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn a_local_session_is_never_blocked() {
        let state = FirewallState::default();
        let pending = PendingChange::new(ChangeKind::Enable, "enable");
        assert_eq!(
            check(&Session::local(), &pending, &state),
            GuardVerdict::Allow
        );
    }

    #[test]
    /**
     * Verifies that enabling over SSH without an SSH rule is blocked.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn enabling_over_ssh_without_an_ssh_rule_is_blocked() {
        let state = FirewallState::default();
        let pending = PendingChange::new(ChangeKind::Enable, "enable");
        let verdict = check(&ssh_session(), &pending, &state);
        assert!(!verdict.permits());
        assert!(
            verdict.message().unwrap().contains("lock")
                || verdict.message().unwrap().contains("cut")
        );
    }

    #[test]
    /**
     * Verifies that enabling over SSH with an SSH rule only warns.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn enabling_over_ssh_with_an_ssh_rule_warns() {
        let state = FirewallState {
            rules: vec![rule(1, Action::Allow, PortSpec::single(22), None)],
            ..Default::default()
        };
        let pending = PendingChange::new(ChangeKind::Enable, "enable");
        let verdict = check(&ssh_session(), &pending, &state);
        assert!(matches!(verdict, GuardVerdict::Warn(_)));
        assert!(verdict.permits());
    }

    #[test]
    /**
     * Verifies that deleting the rule that permits the session is blocked.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn deleting_the_rule_that_permits_the_session_is_blocked() {
        let ssh_rule = rule(1, Action::Allow, PortSpec::single(22), None);
        let pending = PendingChange::new(ChangeKind::DeleteRule, "delete").with_rule(ssh_rule);
        let verdict = check(&ssh_session(), &pending, &FirewallState::default());
        assert!(!verdict.permits());
        assert!(verdict.message().unwrap().contains("#1"));
    }

    #[test]
    /**
     * Verifies that deleting an unrelated rule is allowed.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn deleting_an_unrelated_rule_is_allowed() {
        let other = rule(2, Action::Allow, PortSpec::single(443), None);
        let pending = PendingChange::new(ChangeKind::DeleteRule, "delete").with_rule(other);
        assert_eq!(
            check(&ssh_session(), &pending, &FirewallState::default()),
            GuardVerdict::Allow
        );
    }

    #[test]
    /**
     * Verifies that narrowing the SSH rule to a range that excludes the client is blocked.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn editing_the_ssh_rule_to_a_lan_range_that_excludes_us_is_blocked() {
        let ssh_rule = rule(1, Action::Allow, PortSpec::single(22), None);
        let draft = RuleDraft::allow_port(Protocol::Tcp, 22).from_anywhere("10.0.0.0/8");
        let pending = PendingChange::new(ChangeKind::EditRule, "edit")
            .with_rule(ssh_rule)
            .with_draft(draft);
        let verdict = check(&ssh_session(), &pending, &FirewallState::default());
        assert!(!verdict.permits());
    }

    #[test]
    /**
     * Verifies that narrowing the SSH rule to the client's own network is allowed.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn narrowing_the_ssh_rule_to_our_own_network_is_allowed() {
        let ssh_rule = rule(1, Action::Allow, PortSpec::single(22), None);
        let draft = RuleDraft::allow_port(Protocol::Tcp, 22).from_anywhere("192.168.1.0/24");
        let pending = PendingChange::new(ChangeKind::EditRule, "edit")
            .with_rule(ssh_rule)
            .with_draft(draft);
        assert_eq!(
            check(&ssh_session(), &pending, &FirewallState::default()),
            GuardVerdict::Allow
        );
    }

    #[test]
    /**
     * Verifies that changing the default policy warns over SSH.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn changing_the_default_policy_warns_over_ssh() {
        let pending = PendingChange::new(ChangeKind::SetDefaultIncoming, "default deny");
        let verdict = check(&ssh_session(), &pending, &FirewallState::default());
        assert!(matches!(verdict, GuardVerdict::Warn(_)));
    }

    #[test]
    /**
     * Verifies that a reset is blocked unless it is forced.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn reset_is_blocked_unless_forced() {
        let mut pending = PendingChange::new(ChangeKind::Reset, "reset");
        assert!(!check(&ssh_session(), &pending, &FirewallState::default()).permits());
        pending.forced = true;
        assert!(check(&ssh_session(), &pending, &FirewallState::default()).permits());
    }

    #[test]
    /**
     * Verifies that adding a rule, logging, moving and disabling are always allowed.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn adding_a_rule_and_logging_are_always_allowed() {
        for kind in [
            ChangeKind::AddRule,
            ChangeKind::SetLogging,
            ChangeKind::MoveRule,
            ChangeKind::Disable,
        ] {
            let pending = PendingChange::new(kind, "x");
            assert_eq!(
                check(&ssh_session(), &pending, &FirewallState::default()),
                GuardVerdict::Allow
            );
        }
    }

    #[test]
    /**
     * Verifies that a rule for a different port does not protect the session.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn a_rule_for_a_different_port_does_not_protect_the_session() {
        let other = rule(3, Action::Allow, PortSpec::single(2222), None);
        let pending = PendingChange::new(ChangeKind::DeleteRule, "delete").with_rule(other);
        assert_eq!(
            check(&ssh_session(), &pending, &FirewallState::default()),
            GuardVerdict::Allow
        );
    }
}
