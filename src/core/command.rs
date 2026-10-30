//! Builds `ufw` argument vectors.
//!
//! This is the only place in the program that knows `ufw` syntax. Arguments are produced as
//! `Vec<String>` and passed straight to `Command::args`, never joined into a shell string, so no
//! quoting or injection problem can arise.
//!
//! The grammar followed is the one in `man ufw`:
//!
//! ```text
//! ufw [--dry-run] [rule] [delete] [insert NUM] [prepend]
//!     allow|deny|reject|limit [in|out [on INTERFACE]] [log|log-all] [proto PROTOCOL]
//!     [from ADDRESS [port PORT | app APPNAME]] [to ADDRESS [port PORT | app APPNAME]]
//!     [comment COMMENT]
//! ```

use std::fmt;

use crate::core::firewall::{LogLevel, Policy};
use crate::core::rule::{Direction, LogMode, PortSpec, Rule, RuleDraft};

/// A single logical edit, which may need several `ufw` invocations.
///
/// `steps` is applied in order; `inverse` restores the previous state by running in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// One line of plain English, e.g. "Allow TCP port 22 from 192.168.1.0/24".
    pub description: String,
    pub steps: Vec<Vec<String>>,
    pub inverse: Vec<Vec<String>>,
}

impl Change {
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Renders the commands the way the confirmation dialog shows them.
    pub fn preview(&self) -> String {
        self.steps
            .iter()
            .map(|s| render_command(s))
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn inverse_preview(&self) -> String {
        self.inverse
            .iter()
            .map(|s| render_command(s))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.preview())
    }
}

/// Renders an argument vector as a copy-pasteable command, quoting only what needs it.
pub fn render_command(args: &[String]) -> String {
    let mut out = String::from("ufw");
    for arg in args {
        out.push(' ');
        if arg.is_empty() || arg.contains(char::is_whitespace) || arg.contains('\'') {
            out.push('\'');
            out.push_str(&arg.replace('\'', r"'\''"));
            out.push('\'');
        } else {
            out.push_str(arg);
        }
    }
    out
}

/// Builds the rule arguments, without the leading `ufw`.
pub fn rule_args(draft: &RuleDraft, include_comment: bool) -> Result<Vec<String>, String> {
    draft.validate()?;
    let mut args = vec![draft.action.ufw().to_string()];

    match simple_target(draft) {
        Some(target) => args.push(target),
        None => {
            if let Some(direction) = draft.direction.ufw() {
                args.push(direction.to_string());
            }
            if let Some(iface) = &draft.interface_in {
                args.push("on".to_string());
                args.push(iface.clone());
            }
            if let Some(log) = draft.log.ufw() {
                args.push(log.to_string());
            }
            if let Some(proto) = draft.protocol.ufw() {
                args.push("proto".to_string());
                args.push(proto.to_string());
            }
            push_endpoints(&mut args, draft);
        }
    }

    if include_comment {
        if let Some(comment) = &draft.comment {
            if !comment.trim().is_empty() {
                args.push("comment".to_string());
                args.push(comment.clone());
            }
        }
    }
    Ok(args)
}

/// The short `ufw allow 22/tcp` form, used whenever the rule is plain enough for it. It is what
/// users see in every tutorial, so preferring it keeps the preview recognisable.
fn simple_target(draft: &RuleDraft) -> Option<String> {
    if draft.direction != Direction::In
        || draft.interface_in.is_some()
        || draft.log != LogMode::None
        || draft.from_addr.is_some()
        || !draft.from_port.is_any()
        || draft.to_addr.is_some()
    {
        return None;
    }
    match &draft.to_port {
        PortSpec::App(name) => Some(name.clone()),
        PortSpec::Ports(list) if list.len() == 1 && list[0].is_single() => {
            let mut target = list[0].start.to_string();
            if let Some(proto) = draft.protocol.ufw() {
                target.push('/');
                target.push_str(proto);
            }
            Some(target)
        }
        _ => None,
    }
}

fn push_endpoints(args: &mut Vec<String>, draft: &RuleDraft) {
    let from_empty = draft.from_addr.is_none() && draft.from_port.is_any();
    let to_empty = draft.to_addr.is_none() && draft.to_port.is_any();
    if from_empty && to_empty {
        return;
    }
    // The documented grammar always puts `from` before `to`, and both halves are emitted once
    // either is present, so the command reads exactly like the man page example.
    push_endpoint(args, "from", draft.from_addr.as_deref(), &draft.from_port);
    push_endpoint(args, "to", draft.to_addr.as_deref(), &draft.to_port);
}

fn push_endpoint(args: &mut Vec<String>, keyword: &str, addr: Option<&str>, port: &PortSpec) {
    args.push(keyword.to_string());
    args.push(addr.unwrap_or("any").to_string());
    match port {
        PortSpec::Any => {}
        PortSpec::App(name) => {
            args.push("app".to_string());
            args.push(name.clone());
        }
        PortSpec::Ports(_) => {
            args.push("port".to_string());
            args.push(port.to_string());
        }
    }
}

pub fn change_add(draft: &RuleDraft) -> Result<Change, String> {
    let args = rule_args(draft, true)?;
    Ok(Change {
        description: format!("Add rule: {}", crate::core::explain::explain_draft(draft)),
        steps: vec![args.clone()],
        // Deleting by specification survives renumbering, so it is the safer inverse.
        inverse: vec![[vec!["delete".to_string()], rule_args(draft, false)?].concat()],
    })
}

pub fn change_delete(rule: &Rule) -> Result<Change, String> {
    let draft = rule.to_draft();
    Ok(Change {
        description: format!(
            "Delete rule #{}: {}",
            rule.number,
            crate::core::explain::explain_rule(rule)
        ),
        steps: vec![delete_by_number(rule.number)],
        inverse: vec![insert_rule(&draft, rule.number)?],
    })
}

pub fn change_edit(old: &Rule, new: &RuleDraft) -> Result<Change, String> {
    let old_draft = old.to_draft();
    let number = old.number;
    Ok(Change {
        description: format!(
            "Edit rule #{number}: {}",
            crate::core::explain::explain_draft(new)
        ),
        steps: vec![delete_by_number(number), insert_rule(new, number)?],
        inverse: vec![delete_by_number(number), insert_rule(&old_draft, number)?],
    })
}

pub fn change_move(rule: &Rule, target_position: u32) -> Result<Change, String> {
    let draft = rule.to_draft();
    Ok(Change {
        description: format!("Move rule #{} to position {target_position}", rule.number),
        steps: vec![
            delete_by_number(rule.number),
            insert_rule(&draft, target_position)?,
        ],
        inverse: vec![
            delete_by_number(target_position),
            insert_rule(&draft, rule.number)?,
        ],
    })
}

pub fn change_comment(rule: &Rule, note: Option<&str>) -> Result<Change, String> {
    let mut updated = rule.to_draft();
    updated.comment = note.map(str::to_string).filter(|n| !n.trim().is_empty());
    change_edit(rule, &updated)
}

pub fn change_policy(direction: &str, policy: Policy, previous: Policy) -> Change {
    Change {
        description: format!("Set the default {direction} policy to {}", policy.ufw()),
        steps: vec![vec![
            "default".into(),
            policy.ufw().into(),
            direction.into(),
        ]],
        inverse: vec![vec![
            "default".into(),
            previous.ufw().into(),
            direction.into(),
        ]],
    }
}

pub fn change_logging(level: LogLevel, previous: LogLevel) -> Change {
    Change {
        description: format!("Set logging to {}", level.ufw()),
        steps: vec![vec!["logging".into(), level.ufw().into()]],
        inverse: vec![vec!["logging".into(), previous.ufw().into()]],
    }
}

pub fn change_enabled(enable: bool) -> Change {
    // `--force` suppresses ufw's own interactive prompt; our confirmation dialog replaces it.
    if enable {
        Change {
            description: "Turn the firewall on".into(),
            steps: vec![vec!["--force".into(), "enable".into()]],
            inverse: vec![vec!["disable".into()]],
        }
    } else {
        Change {
            description: "Turn the firewall off".into(),
            steps: vec![vec!["disable".into()]],
            inverse: vec![vec!["--force".into(), "enable".into()]],
        }
    }
}

pub fn change_reset() -> Change {
    Change {
        description: "Reset the firewall to ufw's installation defaults".into(),
        steps: vec![vec!["--force".into(), "reset".into()]],
        // A reset is not reversible: ufw discards the rule set before we can read it back.
        inverse: Vec::new(),
    }
}

pub fn delete_by_number(number: u32) -> Vec<String> {
    vec![
        "--force".to_string(),
        "delete".to_string(),
        number.to_string(),
    ]
}

pub fn insert_rule(draft: &RuleDraft, position: u32) -> Result<Vec<String>, String> {
    let position = position.max(1);
    let mut args = vec!["insert".to_string(), position.to_string()];
    args.extend(rule_args(draft, true)?);
    Ok(args)
}

/// Convenience for the few places that only need to know whether an action writes.
pub fn is_destructive(change: &Change) -> bool {
    change.inverse.is_empty()
        || change.steps.iter().any(|args| {
            args.iter()
                .any(|a| a == "delete" || a == "reset" || a == "disable")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::rule::{Action, Endpoint, PortRange, Protocol};

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn plain_port_rule_uses_the_familiar_short_form() {
        let draft = RuleDraft::allow_port(Protocol::Tcp, 22);
        assert_eq!(rule_args(&draft, true).unwrap(), argv(&["allow", "22/tcp"]));
    }

    #[test]
    fn plain_port_rule_without_protocol() {
        let draft = RuleDraft {
            to_port: PortSpec::single(22),
            ..Default::default()
        };
        assert_eq!(rule_args(&draft, true).unwrap(), argv(&["allow", "22"]));
    }

    #[test]
    fn application_profile_uses_the_short_form() {
        let draft = RuleDraft {
            to_port: PortSpec::App("OpenSSH".into()),
            ..Default::default()
        };
        assert_eq!(
            rule_args(&draft, true).unwrap(),
            argv(&["allow", "OpenSSH"])
        );
    }

    #[test]
    fn restricted_rule_uses_the_documented_full_form() {
        let draft = RuleDraft::allow_port(Protocol::Tcp, 22)
            .from_anywhere("192.168.1.0/24")
            .on_interface("eno1")
            .with_comment("SSH from LAN");
        let args = rule_args(&draft, true).unwrap();
        assert_eq!(
            args,
            argv(&[
                "allow",
                "in",
                "on",
                "eno1",
                "proto",
                "tcp",
                "from",
                "192.168.1.0/24",
                "to",
                "any",
                "port",
                "22",
                "comment",
                "SSH from LAN",
            ])
        );
    }

    #[test]
    fn full_form_always_emits_from_before_to() {
        let draft = RuleDraft {
            to_port: PortSpec::single(8080),
            protocol: Protocol::Udp,
            ..Default::default()
        }
        .on_interface("eth0");
        let args = rule_args(&draft, true).unwrap();
        let from_pos = args.iter().position(|a| a == "from").unwrap();
        let to_pos = args.iter().position(|a| a == "to").unwrap();
        assert!(from_pos < to_pos, "{args:?}");
        assert_eq!(args[from_pos + 1], "any");
    }

    #[test]
    fn range_requires_and_emits_a_protocol() {
        let draft = RuleDraft {
            to_port: "8000:8100".parse().unwrap(),
            protocol: Protocol::Tcp,
            ..Default::default()
        };
        let args = rule_args(&draft, true).unwrap();
        assert!(args.contains(&"proto".to_string()));
        assert!(args.contains(&"8000:8100".to_string()));
    }

    #[test]
    fn comments_are_omitted_when_deleting() {
        let draft = RuleDraft::allow_port(Protocol::Tcp, 22).with_comment("SSH");
        let with = rule_args(&draft, true).unwrap();
        let without = rule_args(&draft, false).unwrap();
        assert!(with.contains(&"comment".to_string()));
        assert!(!without.contains(&"comment".to_string()));
        assert_eq!(without, argv(&["allow", "22/tcp"]));
    }

    #[test]
    fn outbound_rules_use_full_syntax() {
        let draft = RuleDraft {
            direction: Direction::Out,
            protocol: Protocol::Tcp,
            to_port: PortSpec::single(25),
            ..Default::default()
        };
        let args = rule_args(&draft, true).unwrap();
        assert_eq!(args[1], "out");
    }

    #[test]
    fn add_change_has_a_specification_based_inverse() {
        let draft = RuleDraft::allow_port(Protocol::Tcp, 22);
        let change = change_add(&draft).unwrap();
        assert_eq!(change.steps, vec![argv(&["allow", "22/tcp"])]);
        assert_eq!(change.inverse, vec![argv(&["delete", "allow", "22/tcp"])]);
    }

    #[test]
    fn delete_change_reinserts_at_the_original_position() {
        let rule = Rule {
            number: 4,
            action: Action::Allow,
            direction: Direction::In,
            interface_in: None,
            interface_out: None,
            protocol: Protocol::Tcp,
            from: Endpoint::any(),
            to: Endpoint::port(22),
            log: LogMode::None,
            comment: Some("SSH".into()),
            v6: false,
            route: false,
        };
        let change = change_delete(&rule).unwrap();
        assert_eq!(change.steps, vec![argv(&["--force", "delete", "4"])]);
        assert_eq!(change.inverse[0][0], "insert");
        assert_eq!(change.inverse[0][1], "4");
        assert!(change.inverse[0].contains(&"SSH".to_string()));
    }

    #[test]
    fn edit_replaces_in_place_and_can_be_reversed() {
        let rule = Rule {
            number: 2,
            action: Action::Allow,
            direction: Direction::In,
            interface_in: None,
            interface_out: None,
            protocol: Protocol::Tcp,
            from: Endpoint::any(),
            to: Endpoint::port(22),
            log: LogMode::None,
            comment: None,
            v6: false,
            route: false,
        };
        let new = RuleDraft::allow_port(Protocol::Tcp, 2222);
        let change = change_edit(&rule, &new).unwrap();
        assert_eq!(change.steps.len(), 2);
        assert_eq!(change.steps[0], argv(&["--force", "delete", "2"]));
        assert!(change.steps[1].contains(&"2222/tcp".to_string()));
        assert_eq!(change.inverse.len(), 2);
        assert!(change.inverse[1].contains(&"22/tcp".to_string()));
    }

    #[test]
    fn policy_and_logging_changes_have_simple_inverses() {
        let change = change_policy("incoming", Policy::Deny, Policy::Allow);
        assert_eq!(change.steps, vec![argv(&["default", "deny", "incoming"])]);
        assert_eq!(
            change.inverse,
            vec![argv(&["default", "allow", "incoming"])]
        );

        let change = change_logging(LogLevel::Medium, LogLevel::Low);
        assert_eq!(change.steps, vec![argv(&["logging", "medium"])]);
        assert_eq!(change.inverse, vec![argv(&["logging", "low"])]);
    }

    #[test]
    fn enable_and_disable_are_each_others_inverse() {
        assert_eq!(change_enabled(true).inverse, vec![argv(&["disable"])]);
        assert_eq!(
            change_enabled(false).inverse,
            vec![argv(&["--force", "enable"])]
        );
    }

    #[test]
    fn reset_is_destructive() {
        assert!(is_destructive(&change_reset()));
        assert!(is_destructive(
            &change_delete(&Rule {
                number: 1,
                action: Action::Allow,
                direction: Direction::In,
                interface_in: None,
                interface_out: None,
                protocol: Protocol::Tcp,
                from: Endpoint::any(),
                to: Endpoint::port(22),
                log: LogMode::None,
                comment: None,
                v6: false,
                route: false,
            })
            .unwrap()
        ));
        assert!(!is_destructive(
            &change_add(&RuleDraft::allow_port(Protocol::Tcp, 22)).unwrap()
        ));
    }

    #[test]
    fn move_reorders_and_can_be_reversed() {
        let rule = Rule {
            number: 5,
            action: Action::Allow,
            direction: Direction::In,
            interface_in: None,
            interface_out: None,
            protocol: Protocol::Tcp,
            from: Endpoint::any(),
            to: Endpoint::port(22),
            log: LogMode::None,
            comment: None,
            v6: false,
            route: false,
        };
        let change = change_move(&rule, 1).unwrap();
        assert_eq!(change.steps[0], argv(&["--force", "delete", "5"]));
        assert_eq!(change.steps[1][0], "insert");
        assert_eq!(change.steps[1][1], "1");
        assert_eq!(change.inverse[0], argv(&["--force", "delete", "1"]));
    }

    #[test]
    fn preview_quotes_only_arguments_that_need_it() {
        let args = argv(&["allow", "in", "comment", "SSH from LAN"]);
        assert_eq!(render_command(&args), "ufw allow in comment 'SSH from LAN'");
    }

    #[test]
    fn preview_escapes_embedded_quotes() {
        let args = argv(&["comment", "it's mine"]);
        assert_eq!(render_command(&args), r"ufw comment 'it'\''s mine'");
    }

    #[test]
    fn port_lists_render_comma_separated() {
        let draft = RuleDraft {
            protocol: Protocol::Tcp,
            to_port: PortSpec::Ports(vec![PortRange::single(80), PortRange::single(443)]),
            ..Default::default()
        };
        let args = rule_args(&draft, true).unwrap();
        assert!(args.contains(&"80,443".to_string()), "{args:?}");
    }
}
