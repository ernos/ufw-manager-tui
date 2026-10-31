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

#[derive(Debug, Clone, PartialEq, Eq)]
/**
 * A single logical edit, which may need several `ufw` invocations.
 *
 * `steps` is applied in order; `inverse` restores the previous state by running in
 * order.
 *
 * # Fields
 *
 * * `description` (`String`) - One line of plain English, e.g. "Allow TCP port 22 from 192.168.1.0/24".
 * * `steps` (`Vec<Vec<String>>`) - The argument vectors to run, in order, to apply the change.
 * * `inverse` (`Vec<Vec<String>>`) - The argument vectors to run, in order, to undo the change. Empty when the change cannot be undone.
 */
pub struct Change {
    /// One line of plain English, e.g. "Allow TCP port 22 from 192.168.1.0/24".
    pub description: String,
    pub steps: Vec<Vec<String>>,
    pub inverse: Vec<Vec<String>>,
}

impl Change {
    /**
     * Returns whether this change has no steps to run.
     *
     * A change with no steps is a no-op and is never offered for confirmation.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The change being inspected.
     *
     * # Returns
     *
     * `true` when `steps` is empty; otherwise, `false`.
     */
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /**
     * Renders the commands the way the confirmation dialog shows them.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The change whose forward steps are rendered.
     *
     * # Returns
     *
     * A `String` with one rendered `ufw` command per line, joined by newlines. A change
     * with no steps produces an empty string.
     */
    pub fn preview(&self) -> String {
        self.steps
            .iter()
            .map(|s| render_command(s))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /**
     * Renders the inverse commands, one per line, the way the undo preview shows them.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The change whose inverse steps are rendered.
     *
     * # Returns
     *
     * A `String` with one rendered `ufw` command per line, joined by newlines. An empty
     * `inverse` produces an empty string.
     */
    pub fn inverse_preview(&self) -> String {
        self.inverse
            .iter()
            .map(|s| render_command(s))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl fmt::Display for Change {
    /**
     * Implements `std::fmt::Display` for [`Change`] by writing the forward preview.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The change being formatted.
     * * `f` (`&mut fmt::Formatter<'_>`) - The formatter to write into.
     *
     * # Returns
     *
     * `fmt::Result` - `Ok(())` when the text was written, or the formatter's error.
     */
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.preview())
    }
}

/**
 * Renders an argument vector as a copy-pasteable command, quoting only what needs it.
 *
 * The leading `ufw` is added here, so `args` must not contain it. Arguments that are
 * empty, contain whitespace, or contain a single quote are wrapped in single quotes,
 * with embedded quotes escaped as `'\''`.
 *
 * # Arguments
 *
 * * `args` (`&[String]`) - The argument vector to render, without the leading `ufw`.
 *
 * # Returns
 *
 * A `String` holding the complete command line, starting with `ufw`.
 */
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

/**
 * Builds the rule arguments, without the leading `ufw`.
 *
 * The short `allow 22/tcp` form is preferred whenever the rule is plain enough for it;
 * otherwise the full documented grammar is emitted, with `from` always before `to`.
 * Forwarding rules are prefixed with `route` and carry up to two interface clauses.
 *
 * # Arguments
 *
 * * `draft` (`&RuleDraft`) - The rule to render; it is validated before use.
 * * `include_comment` (`bool`) - Whether a non-empty comment is appended as a `comment <text>` clause.
 *
 * # Returns
 *
 * `Result<Vec<String>, String>` - The argument vector on success, or the validation
 * error returned by [`RuleDraft::validate`].
 */
pub fn rule_args(draft: &RuleDraft, include_comment: bool) -> Result<Vec<String>, String> {
    draft.validate()?;
    let mut args = Vec::new();
    if draft.direction == Direction::Forward {
        args.push("route".to_string());
    }
    args.push(draft.action.ufw().to_string());

    match simple_target(draft) {
        Some(target) => args.push(target),
        None => {
            if draft.direction == Direction::Forward {
                push_route_interfaces(&mut args, draft);
            } else {
                if let Some(direction) = draft.direction.ufw() {
                    args.push(direction.to_string());
                }
                if let Some(iface) = rule_interface(draft) {
                    args.push("on".to_string());
                    args.push(iface.to_string());
                }
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

/**
 * Returns the interface a filter rule is limited to, if any.
 *
 * `ufw` accepts exactly one `in on`/`out on` clause on a rule that is not a route rule,
 * and the keyword follows the direction: incoming rules name the interface they arrive
 * on, outgoing rules name the one they leave through. Both draft fields are consulted so
 * a rule read back from `ufw status` keeps its interface after conversion, wherever the
 * parser stored it.
 *
 * # Arguments
 *
 * * `draft` (`&RuleDraft`) - The rule whose interface is wanted.
 *
 * # Returns
 *
 * `Option<&str>` - The interface name, or `None` when the rule is not limited to one.
 */
fn rule_interface(draft: &RuleDraft) -> Option<&str> {
    match draft.direction {
        Direction::Out => draft
            .interface_out
            .as_deref()
            .or(draft.interface_in.as_deref()),
        _ => draft
            .interface_in
            .as_deref()
            .or(draft.interface_out.as_deref()),
    }
}

/**
 * Appends the `in on` and `out on` clauses of a forwarding rule.
 *
 * `in` is always emitted before `out`: `ufw` parses the first interface clause as the
 * rule's own direction and the second as the opposite one, and `route allow out on eth1
 * in on eth0` therefore reads back as an outgoing rule. The clauses also have to sit
 * immediately after the action, because `ufw` answers `Invalid interface clause` to
 * `route allow log in on eth0`.
 *
 * # Arguments
 *
 * * `args` (`&mut Vec<String>`) - The argument vector being built; it is mutated in place.
 * * `draft` (`&RuleDraft`) - The rule draft whose interfaces are rendered.
 *
 * # Returns
 *
 * This function returns no value; the clauses are appended to `args`.
 */
fn push_route_interfaces(args: &mut Vec<String>, draft: &RuleDraft) {
    if let Some(iface) = &draft.interface_in {
        args.push("in".to_string());
        args.push("on".to_string());
        args.push(iface.clone());
    }
    if let Some(iface) = &draft.interface_out {
        args.push("out".to_string());
        args.push("on".to_string());
        args.push(iface.clone());
    }
}

/**
 * Returns the short `ufw allow 22/tcp` form, used whenever the rule is plain enough for
 * it.
 *
 * It is what users see in every tutorial, so preferring it keeps the preview
 * recognisable. Only inbound rules with no interface, no logging, no source constraint
 * and a single port or application profile qualify.
 *
 * # Arguments
 *
 * * `draft` (`&RuleDraft`) - The rule to test for the short form.
 *
 * # Returns
 *
 * `Option<String>` - The short target, such as `22/tcp` or `OpenSSH`, or `None` when
 * the rule needs the full syntax.
 */
fn simple_target(draft: &RuleDraft) -> Option<String> {
    if draft.direction != Direction::In
        || draft.interface_in.is_some()
        || draft.interface_out.is_some()
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

/**
 * Appends the `from` and `to` halves of a rule to `args`.
 *
 * Both halves are emitted once either side is constrained, so the output matches the
 * documented `ufw` grammar. Nothing is appended when both sides are unconstrained.
 *
 * # Arguments
 *
 * * `args` (`&mut Vec<String>`) - The argument vector being built; it is mutated in place.
 * * `draft` (`&RuleDraft`) - The rule draft whose endpoints are rendered.
 *
 * # Returns
 *
 * This function returns no value; the clauses are appended to `args`.
 */
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

/**
 * Appends one `from` or `to` clause, including its address and optional port or app.
 *
 * # Arguments
 *
 * * `args` (`&mut Vec<String>`) - The argument vector being built; it is mutated in place.
 * * `keyword` (`&str`) - The clause keyword, either `"from"` or `"to"`.
 * * `addr` (`Option<&str>`) - The address to emit; `None` is rendered as `any`.
 * * `port` (`&PortSpec`) - The port selection for this side of the rule.
 *
 * # Returns
 *
 * This function returns no value; the clause is appended to `args`.
 */
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

/**
 * Builds the change that adds a rule.
 *
 * The inverse deletes the rule by specification rather than by number, so it still works
 * after `ufw` renumbers the list. A forwarding rule is deleted with `ufw route delete
 * <rule>`; `ufw delete route …` is not valid syntax.
 *
 * # Arguments
 *
 * * `draft` (`&RuleDraft`) - The rule to add.
 *
 * # Returns
 *
 * `Result<Change, String>` - The change on success, or the validation error from
 * [`rule_args`].
 */
pub fn change_add(draft: &RuleDraft) -> Result<Change, String> {
    let args = rule_args(draft, true)?;
    // Deleting by specification survives renumbering, so it is the safer inverse.
    let undo = command_with_verb(draft, &["delete".to_string()], rule_args(draft, false)?);
    Ok(Change {
        description: format!("Add rule: {}", crate::core::explain::explain_draft(draft)),
        steps: vec![args],
        inverse: vec![undo],
    })
}

/**
 * Returns how many rules `ufw` lists once the delete step of a change has run.
 *
 * # Arguments
 *
 * * `existing` (`usize`) - The number of rules listed before the change starts.
 *
 * # Returns
 *
 * `usize` - One less than `existing`, saturating at zero.
 */
fn remaining_after_delete(existing: usize) -> usize {
    existing.saturating_sub(1)
}

/**
 * Builds the change that deletes an existing rule.
 *
 * The inverse re-inserts the rule at its original position.
 *
 * # Arguments
 *
 * * `rule` (`&Rule`) - The rule to delete.
 * * `existing` (`usize`) - The number of rules currently listed, including this one.
 *
 * # Returns
 *
 * `Result<Change, String>` - The change on success, or an error when the rule cannot be
 * rebuilt as an insert command.
 */
pub fn change_delete(rule: &Rule, existing: usize) -> Result<Change, String> {
    let draft = rule.to_draft();
    Ok(Change {
        description: format!(
            "Delete rule #{}: {}",
            rule.number,
            crate::core::explain::explain_rule(rule)
        ),
        steps: vec![delete_by_number(rule.number)],
        inverse: vec![insert_rule(
            &draft,
            rule.number,
            remaining_after_delete(existing),
        )?],
    })
}

/**
 * Builds the change that replaces a rule in place.
 *
 * The rule is deleted by number and the replacement inserted at the same position; the
 * inverse restores the original rule the same way.
 *
 * # Arguments
 *
 * * `old` (`&Rule`) - The rule currently in the firewall.
 * * `new` (`&RuleDraft`) - The replacement rule.
 * * `existing` (`usize`) - The number of rules currently listed, including `old`.
 *
 * # Returns
 *
 * `Result<Change, String>` - The change on success, or an error when either insert
 * command cannot be built.
 */
pub fn change_edit(old: &Rule, new: &RuleDraft, existing: usize) -> Result<Change, String> {
    let old_draft = old.to_draft();
    let number = old.number;
    let after_delete = remaining_after_delete(existing);
    Ok(Change {
        description: format!(
            "Edit rule #{number}: {}",
            crate::core::explain::explain_draft(new)
        ),
        steps: vec![
            delete_by_number(number),
            insert_rule(new, number, after_delete)?,
        ],
        inverse: vec![
            delete_by_number(number),
            insert_rule(&old_draft, number, after_delete)?,
        ],
    })
}

/**
 * Builds the change that copies an existing rule to the slot right after it.
 *
 * # Arguments
 *
 * * `rule` (`&Rule`) - The rule to copy.
 * * `existing` (`usize`) - The number of rules currently listed.
 *
 * # Returns
 *
 * * `Result<Change, String>` - The change on success, or an error when the insert command cannot be built.
 */
pub fn change_duplicate(rule: &Rule, existing: usize) -> Result<Change, String> {
    let draft = rule.to_draft();
    let copy = rule.number + 1;

    Ok(Change {
        description: format!("Duplicate rule #{} below it", rule.number),
        steps: vec![insert_rule(&draft, copy, existing)?],
        // Deleting by specification survives renumbering, so it is the safer inverse.
        inverse: vec![delete_by_number(copy)],
    })
}

/**
 * Builds the change that moves a rule to another position.
 *
 * # Arguments
 *
 * * `rule` (`&Rule`) - The rule to move.
 * * `target_position` (`u32`) - The 1-based position the rule should end up at.
 * * `existing` (`usize`) - The number of rules currently listed, including `rule`.
 *
 * # Returns
 *
 * `Result<Change, String>` - The change on success, or an error when the insert command
 * cannot be built.
 */
pub fn change_move(rule: &Rule, target_position: u32, existing: usize) -> Result<Change, String> {
    let draft = rule.to_draft();
    let after_delete = remaining_after_delete(existing);
    Ok(Change {
        description: format!("Move rule #{} to position {target_position}", rule.number),
        steps: vec![
            delete_by_number(rule.number),
            insert_rule(&draft, target_position, after_delete)?,
        ],
        inverse: vec![
            delete_by_number(target_position),
            insert_rule(&draft, rule.number, after_delete)?,
        ],
    })
}

/**
 * Builds the change that sets or clears a rule's comment.
 *
 * A note that is empty or only whitespace clears the comment.
 *
 * # Arguments
 *
 * * `rule` (`&Rule`) - The rule whose comment is changed.
 * * `note` (`Option<&str>`) - The new comment, or `None` to remove it.
 * * `existing` (`usize`) - The number of rules currently listed, including `rule`.
 *
 * # Returns
 *
 * `Result<Change, String>` - The edit change produced by [`change_edit`].
 */
pub fn change_comment(rule: &Rule, note: Option<&str>, existing: usize) -> Result<Change, String> {
    let mut updated = rule.to_draft();
    updated.comment = note.map(str::to_string).filter(|n| !n.trim().is_empty());
    change_edit(rule, &updated, existing)
}

/**
 * Builds the change that sets a default policy for one direction.
 *
 * # Arguments
 *
 * * `direction` (`&str`) - The policy direction word, for example `"incoming"`.
 * * `policy` (`Policy`) - The policy to apply.
 * * `previous` (`Policy`) - The policy to restore in the inverse.
 *
 * # Returns
 *
 * A `Change` with a single `default` step and the matching inverse.
 */
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

/**
 * Builds the change that sets the logging level.
 *
 * # Arguments
 *
 * * `level` (`LogLevel`) - The logging level to apply.
 * * `previous` (`LogLevel`) - The level to restore in the inverse.
 *
 * # Returns
 *
 * A `Change` with a single `logging` step and the matching inverse.
 */
pub fn change_logging(level: LogLevel, previous: LogLevel) -> Change {
    Change {
        description: format!("Set logging to {}", level.ufw()),
        steps: vec![vec!["logging".into(), level.ufw().into()]],
        inverse: vec![vec!["logging".into(), previous.ufw().into()]],
    }
}

/**
 * Builds the change that turns the firewall on or off.
 *
 * `--force` is used so `ufw` does not prompt; the confirmation dialog replaces that
 * prompt.
 *
 * # Arguments
 *
 * * `enable` (`bool`) - `true` to enable the firewall, `false` to disable it.
 *
 * # Returns
 *
 * A `Change` whose inverse performs the opposite operation.
 */
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

/**
 * Builds the change that resets the firewall to ufw's installation defaults.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * A `Change` with a single `--force reset` step. Its `inverse` is empty because a reset
 * cannot be undone.
 */
pub fn change_reset() -> Change {
    Change {
        description: "Reset the firewall to ufw's installation defaults".into(),
        steps: vec![vec!["--force".into(), "reset".into()]],
        // A reset is not reversible: ufw discards the rule set before we can read it back.
        inverse: Vec::new(),
    }
}

/**
 * Builds the argument vector that deletes a rule by its number.
 *
 * The number is the one `ufw status numbered` prints, which covers filter and route
 * rules in a single list. `ufw` has no `route delete NUM`: its parser rejects it with
 * `'route delete NUM' unsupported. Use 'delete NUM' instead`, so this plain form is used
 * for every rule kind.
 *
 * # Arguments
 *
 * * `number` (`u32`) - The rule number to delete.
 *
 * # Returns
 *
 * A `Vec<String>` containing `--force delete <number>`.
 */
pub fn delete_by_number(number: u32) -> Vec<String> {
    vec![
        "--force".to_string(),
        "delete".to_string(),
        number.to_string(),
    ]
}

/**
 * Prefixes a rule's arguments with an `ufw` verb, keeping `route` in front of it.
 *
 * [`rule_args`] returns a complete rule, starting with `route` when the draft forwards
 * traffic. `ufw` wants that keyword before the verb (`route insert NUM …`, `route delete
 * …`), so the prefix is lifted off, the verb is spliced in, and the prefix is put back.
 * `ufw` refuses the alternatives: `delete route …` is a syntax error and `route delete
 * NUM` is rejected outright in favour of plain `delete NUM`.
 *
 * # Arguments
 *
 * * `draft` (`&RuleDraft`) - The rule the arguments belong to; only its direction matters.
 * * `verb` (`&[String]`) - The words that go between the prefix and the rule, such as
 *   `insert 3` or `delete`.
 * * `args` (`Vec<String>`) - The complete rule arguments returned by [`rule_args`].
 *
 * # Returns
 *
 * A `Vec<String>` holding the prefixed command.
 */
fn command_with_verb(draft: &RuleDraft, verb: &[String], args: Vec<String>) -> Vec<String> {
    let mut body = args;
    let mut out = Vec::with_capacity(body.len() + verb.len() + 1);
    if draft.direction == Direction::Forward {
        out.push("route".to_string());
        body.remove(0);
    }
    out.extend(verb.iter().cloned());
    out.extend(body);
    out
}

/**
 * Builds the argument vector that places a rule at a given position.
 *
 * `ufw insert NUM` is only accepted when `NUM` is one of the positions the list
 * already has; `ufw` answers `Invalid position 'NUM'` for anything past the end.
 * A position at or beyond the end is therefore emitted as a plain append, which
 * is exactly where that position points. This is what keeps editing, moving and
 * undoing the last rule working, and in particular the one-rule case, where the
 * delete leaves the list empty and even `insert 1` is rejected.
 *
 * A forwarding rule needs `ufw route insert NUM <rule>`, which
 * [`command_with_verb`] produces.
 *
 * # Arguments
 *
 * * `draft` (`&RuleDraft`) - The rule to insert.
 * * `position` (`u32`) - The 1-based position; values below 1 are clamped to 1.
 * * `existing` (`usize`) - How many rules the list holds when this command runs.
 *
 * # Returns
 *
 * `Result<Vec<String>, String>` - The `insert <position> ...` arguments, the bare rule
 * arguments when the rule is appended, or the validation error from [`rule_args`].
 */
pub fn insert_rule(
    draft: &RuleDraft,
    position: u32,
    existing: usize,
) -> Result<Vec<String>, String> {
    let position = position.max(1);
    let args = rule_args(draft, true)?;
    if position as usize > existing {
        return Ok(args);
    }
    let verb = ["insert".to_string(), position.to_string()];
    Ok(command_with_verb(draft, &verb, args))
}

/**
 * Convenience for the few places that only need to know whether an action writes.
 *
 * A change is treated as destructive when it has no inverse, or when any of its steps
 * contains `delete`, `reset` or `disable`.
 *
 * # Arguments
 *
 * * `change` (`&Change`) - The change to classify.
 *
 * # Returns
 *
 * `true` when the change cannot be undone or removes access; otherwise, `false`.
 */
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

    /**
     * Converts a slice of string literals into an owned argument vector for assertions.
     *
     * # Arguments
     *
     * * `args` (`&[&str]`) - The arguments to copy.
     *
     * # Returns
     *
     * A `Vec<String>` holding the same arguments.
     */
    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    /**
     * Verifies that a plain TCP port rule uses the short `allow 22/tcp` form.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn plain_port_rule_uses_the_familiar_short_form() {
        let draft = RuleDraft::allow_port(Protocol::Tcp, 22);
        assert_eq!(rule_args(&draft, true).unwrap(), argv(&["allow", "22/tcp"]));
    }

    #[test]
    /**
     * Verifies that a port rule without a protocol renders as a bare port.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn plain_port_rule_without_protocol() {
        let draft = RuleDraft {
            to_port: PortSpec::single(22),
            ..Default::default()
        };
        assert_eq!(rule_args(&draft, true).unwrap(), argv(&["allow", "22"]));
    }

    #[test]
    /**
     * Verifies that an application profile rule uses the short form.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
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
    /**
     * Verifies that a restricted rule uses the full documented syntax.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
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
    /**
     * Verifies that the full form always emits `from` before `to`.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
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
    /**
     * Verifies that a port range emits its protocol.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
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
    /**
     * Verifies that comments are omitted when `include_comment` is false.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn comments_are_omitted_when_deleting() {
        let draft = RuleDraft::allow_port(Protocol::Tcp, 22).with_comment("SSH");
        let with = rule_args(&draft, true).unwrap();
        let without = rule_args(&draft, false).unwrap();
        assert!(with.contains(&"comment".to_string()));
        assert!(!without.contains(&"comment".to_string()));
        assert_eq!(without, argv(&["allow", "22/tcp"]));
    }

    #[test]
    /**
     * Verifies that outbound rules use the full syntax with `out`.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
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
    /**
     * Verifies that an outgoing rule keeps the interface it leaves through.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn outbound_rules_name_their_interface_after_out() {
        let draft = RuleDraft {
            direction: Direction::Out,
            interface_out: Some("eth1".into()),
            to_addr: Some("10.0.0.0/8".into()),
            ..Default::default()
        };
        assert_eq!(
            rule_args(&draft, true).unwrap(),
            argv(&[
                "allow",
                "out",
                "on",
                "eth1",
                "from",
                "any",
                "to",
                "10.0.0.0/8"
            ])
        );
    }

    #[test]
    /**
     * Verifies the minimal forwarding rule: `ufw route allow in on … out on …`.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn forward_rules_are_prefixed_with_route() {
        let draft = RuleDraft {
            direction: Direction::Forward,
            interface_in: Some("eth0".into()),
            interface_out: Some("eth1".into()),
            ..Default::default()
        };
        assert_eq!(
            rule_args(&draft, true).unwrap(),
            argv(&["route", "allow", "in", "on", "eth0", "out", "on", "eth1"])
        );
    }

    #[test]
    /**
     * Verifies that a forwarding rule renders every optional clause in the order
     * `ufw` accepts.
     *
     * The interface clauses must come first: `ufw` answers `Invalid interface
     * clause` to `route allow log in on eth0`.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn forward_rules_render_the_full_form() {
        let draft = RuleDraft {
            action: Action::Deny,
            direction: Direction::Forward,
            interface_in: Some("eth0".into()),
            interface_out: Some("eth1".into()),
            protocol: Protocol::Tcp,
            from_addr: Some("192.168.1.0/24".into()),
            to_addr: Some("10.0.0.0/8".into()),
            to_port: PortSpec::single(443),
            log: LogMode::LogAll,
            comment: Some("VPN to LAN".into()),
            ..Default::default()
        };
        assert_eq!(
            rule_args(&draft, true).unwrap(),
            argv(&[
                "route",
                "deny",
                "in",
                "on",
                "eth0",
                "out",
                "on",
                "eth1",
                "log-all",
                "proto",
                "tcp",
                "from",
                "192.168.1.0/24",
                "to",
                "10.0.0.0/8",
                "port",
                "443",
                "comment",
                "VPN to LAN",
            ])
        );
    }

    #[test]
    /**
     * Verifies that inserting a forwarding rule keeps a single `route` prefix.
     *
     * `ufw route insert NUM <rule>` is the only accepted spelling; `ufw insert
     * NUM route …` is not.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn inserting_a_forward_rule_uses_route_insert() {
        let draft = RuleDraft {
            direction: Direction::Forward,
            interface_in: Some("eth0".into()),
            interface_out: Some("eth1".into()),
            ..Default::default()
        };
        assert_eq!(
            insert_rule(&draft, 3, 5).unwrap(),
            argv(&["route", "insert", "3", "allow", "in", "on", "eth0", "out", "on", "eth1"])
        );
        // Past the end of the list an insert is a plain append, route prefix included.
        assert_eq!(
            insert_rule(&draft, 9, 5).unwrap(),
            rule_args(&draft, true).unwrap()
        );
    }

    #[test]
    /**
     * Verifies that editing a forwarding rule deletes it by number and re-adds it
     * as a route rule at the same position.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn editing_a_forward_rule_replaces_it_with_a_route_insert() {
        let old = Rule {
            number: 3,
            action: Action::Allow,
            direction: Direction::Forward,
            interface_in: Some("eth0".into()),
            interface_out: Some("eth1".into()),
            protocol: Protocol::Any,
            from: Endpoint::any(),
            to: Endpoint::any(),
            log: LogMode::None,
            comment: None,
            v6: false,
            route: true,
        };
        let mut updated = old.to_draft();
        updated.action = Action::Deny;
        let change = change_edit(&old, &updated, 5).unwrap();
        assert_eq!(change.steps[0], argv(&["--force", "delete", "3"]));
        assert_eq!(
            change.steps[1],
            argv(&["route", "insert", "3", "deny", "in", "on", "eth0", "out", "on", "eth1"])
        );
        assert_eq!(change.inverse[1][3], "allow");
    }

    #[test]
    /**
     * Verifies that undoing a forwarded rule uses `ufw route delete <rule>`.
     *
     * `ufw delete route …` is a syntax error, so the inverse has to keep the prefix in
     * front of the verb.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn undoing_a_forward_rule_uses_route_delete() {
        let draft = RuleDraft {
            direction: Direction::Forward,
            interface_in: Some("eth0".into()),
            interface_out: Some("eth1".into()),
            ..Default::default()
        };
        let change = change_add(&draft).unwrap();
        assert_eq!(
            change.inverse,
            vec![argv(&[
                "route", "delete", "allow", "in", "on", "eth0", "out", "on", "eth1"
            ])]
        );
    }

    #[test]
    /**
     * Verifies that an add change has a specification-based inverse.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn add_change_has_a_specification_based_inverse() {
        let draft = RuleDraft::allow_port(Protocol::Tcp, 22);
        let change = change_add(&draft).unwrap();
        assert_eq!(change.steps, vec![argv(&["allow", "22/tcp"])]);
        assert_eq!(change.inverse, vec![argv(&["delete", "allow", "22/tcp"])]);
    }

    #[test]
    /**
     * Verifies that a delete change re-inserts the rule at its original position.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
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
        let change = change_delete(&rule, 8).unwrap();
        assert_eq!(change.steps, vec![argv(&["--force", "delete", "4"])]);
        assert_eq!(change.inverse[0][0], "insert");
        assert_eq!(change.inverse[0][1], "4");
        assert!(change.inverse[0].contains(&"SSH".to_string()));
    }

    #[test]
    /**
     * Verifies that undoing the delete of the only rule appends instead of
     * asking for position 1, which `ufw` rejects on an empty list.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn undoing_the_delete_of_the_only_rule_appends() {
        let rule = Rule {
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
        };
        let change = change_delete(&rule, 1).unwrap();
        assert_eq!(change.inverse[0], argv(&["allow", "22/tcp"]));
    }

    #[test]
    /**
     * Verifies that an edit deletes and re-inserts in place and can be reversed.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
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
        let change = change_edit(&rule, &new, 4).unwrap();
        assert_eq!(change.steps.len(), 2);
        assert_eq!(change.steps[0], argv(&["--force", "delete", "2"]));
        assert_eq!(change.steps[1][0], "insert");
        assert_eq!(change.steps[1][1], "2");
        assert!(change.steps[1].contains(&"2222/tcp".to_string()));
        assert_eq!(change.inverse.len(), 2);
        assert!(change.inverse[1].contains(&"22/tcp".to_string()));
    }

    #[test]
    /**
     * Verifies that editing the only rule appends, because the delete leaves an
     * empty list where `insert 1` is an invalid position.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn editing_the_only_rule_appends_instead_of_inserting() {
        let rule = Rule {
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
        };
        let new = RuleDraft::allow_port(Protocol::Tcp, 2222);
        let change = change_edit(&rule, &new, 1).unwrap();
        assert_eq!(change.steps[1], argv(&["allow", "2222/tcp"]));
        assert_eq!(change.inverse[1], argv(&["allow", "22/tcp"]));
    }

    #[test]
    /**
     * Verifies that editing the last of several rules appends, since no position
     * past the shortened list exists.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn editing_the_last_rule_appends() {
        let rule = Rule {
            number: 3,
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
        let change = change_edit(&rule, &new, 3).unwrap();
        assert_eq!(change.steps[1], argv(&["allow", "2222/tcp"]));
        assert_eq!(change.inverse[1], argv(&["allow", "22/tcp"]));
    }

    #[test]
    /**
     * Verifies the steps and inverses of the policy and logging changes.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
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
    /**
     * Verifies that enabling and disabling are each other's inverse.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn enable_and_disable_are_each_others_inverse() {
        assert_eq!(change_enabled(true).inverse, vec![argv(&["disable"])]);
        assert_eq!(
            change_enabled(false).inverse,
            vec![argv(&["--force", "enable"])]
        );
    }

    #[test]
    /**
     * Verifies that a reset and a delete are destructive while an add is not.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn reset_is_destructive() {
        assert!(is_destructive(&change_reset()));
        assert!(is_destructive(
            &change_delete(
                &Rule {
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
                },
                1
            )
            .unwrap()
        ));
        assert!(!is_destructive(
            &change_add(&RuleDraft::allow_port(Protocol::Tcp, 22)).unwrap()
        ));
    }

    #[test]
    /**
     * Verifies that a move deletes and re-inserts and can be reversed.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
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
        let change = change_move(&rule, 1, 8).unwrap();
        assert_eq!(change.steps[0], argv(&["--force", "delete", "5"]));
        assert_eq!(change.steps[1][0], "insert");
        assert_eq!(change.steps[1][1], "1");
        assert_eq!(change.inverse[0], argv(&["--force", "delete", "1"]));
    }

    #[test]
    /**
     * Verifies that moving a rule to the end appends, because `ufw` rejects a
     * position one past the shortened list.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn moving_a_rule_to_the_end_appends() {
        let rule = Rule {
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
        };
        let change = change_move(&rule, 2, 2).unwrap();
        assert_eq!(change.steps[0], argv(&["--force", "delete", "1"]));
        assert_eq!(change.steps[1], argv(&["allow", "22/tcp"]));
    }

    #[test]
    /**
     * Verifies that only arguments containing whitespace are quoted in a preview.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn preview_quotes_only_arguments_that_need_it() {
        let args = argv(&["allow", "in", "comment", "SSH from LAN"]);
        assert_eq!(render_command(&args), "ufw allow in comment 'SSH from LAN'");
    }

    #[test]
    /**
     * Verifies that embedded single quotes are escaped in a preview.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
    fn preview_escapes_embedded_quotes() {
        let args = argv(&["comment", "it's mine"]);
        assert_eq!(render_command(&args), r"ufw comment 'it'\''s mine'");
    }

    #[test]
    /**
     * Verifies that a port list renders as a comma-separated argument.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value.
     */
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
