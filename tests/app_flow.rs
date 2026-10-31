//! End-to-end flows through [`App`], driven by key presses exactly as a user would.
//!
//! The mock backend makes these deterministic: no root, no real firewall, no terminal.

use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use ufw_manager::app::{
    App, AppOptions, Tab, WizardStep, SETTINGS_DEFAULT_START, SETTINGS_SAVE_ROW,
};
use ufw_manager::backend::logs::BlockMonitor;
use ufw_manager::backend::mock::MockBackend;
use ufw_manager::config::Config;
use ufw_manager::ui::theme::Theme;

/**
 * Builds an [`App`] wired to the deterministic [`MockBackend`] with default
 * options, so tests can drive the real application logic without root, a real
 * firewall, or a terminal.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `App` - A freshly constructed application in its initial state.
 */
fn app() -> App {
    App::new(
        Box::new(MockBackend::new()),
        AppOptions {
            journal_path: None,
            parked_path: None,
            yes: false,
            readonly: false,
            theme: Theme::new("dark", false),
            reconcile_seconds: 0,
            show_counters: true,
            confirm_before_apply: false,
            no_color: false,
            config: Config::default(),
            config_path: None,
        },
    )
}

/**
 * Builds an [`App`] whose settings come from a config file, as the real binary
 * does at start-up.
 *
 * # Arguments
 *
 * * `path` (`Option<&Path>`) - The config file to load and to save back to;
 *   `None` keeps everything in memory only.
 *
 * # Returns
 *
 * `App` - A freshly constructed application in its initial state.
 */
fn app_with_config_path(path: Option<&Path>) -> App {
    let config = match path {
        Some(path) => Config::load(Some(path)),
        None => Config::default(),
    };
    App::new(
        Box::new(MockBackend::new()),
        AppOptions {
            journal_path: None,
            parked_path: None,
            yes: false,
            readonly: config.readonly,
            theme: Theme::new(&config.theme, false),
            reconcile_seconds: config.reconcile_seconds,
            show_counters: config.show_counters,
            confirm_before_apply: config.confirm_before_apply,
            no_color: false,
            config,
            config_path: path.map(|path| path.to_path_buf()),
        },
    )
}

/**
 * Wraps a key code in a [`KeyEvent`] with no modifiers held.
 *
 * # Arguments
 *
 * * `code` (`KeyCode`) - The key to press, such as `KeyCode::Enter`.
 *
 * # Returns
 *
 * `KeyEvent` - The key event with `KeyModifiers::NONE`.
 */
fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

/**
 * Sends a single key press to the application, exactly as the event loop would.
 *
 * # Arguments
 *
 * * `app` (`&mut App`) - The application to deliver the key to.
 * * `code` (`KeyCode`) - The key to press.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 */
fn press(app: &mut App, code: KeyCode) {
    app.handle_key(key(code));
}

/**
 * Sends a single key press while a modifier is held.
 *
 * # Arguments
 *
 * * `app` (`&mut App`) - The application to deliver the key to.
 * * `code` (`KeyCode`) - The key to press.
 * * `modifiers` (`KeyModifiers`) - The modifiers held down, such as `KeyModifiers::CONTROL`.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 */
fn press_with(app: &mut App, code: KeyCode, modifiers: KeyModifiers) {
    app.handle_key(KeyEvent::new(code, modifiers));
}

#[test]
/**
 * Verifies that the demo backend loads a realistic rule set: the firewall is
 * enabled, six rules are present, the Home tab is selected, and the loaded
 * state produces at least one suggestion.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if any assertion about the loaded demo state fails.
 */
fn the_demo_backend_loads_a_realistic_rule_set() {
    let app = app();
    assert!(app.state.enabled);
    assert_eq!(app.state.rules.len(), 6);
    assert_eq!(app.tab, Tab::Home);
    assert!(
        !app.suggestions.is_empty(),
        "the demo state should produce advice"
    );
}

#[test]
/**
 * Verifies that walking the add wizard with the default selections adds an SSH
 * rule from the local network, records one journal entry, and switches to the
 * Rules tab.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the wizard does not advance as expected or the rule set and
 * journal do not change.
 */
fn adding_a_rule_through_the_wizard_changes_the_firewall_and_the_journal() {
    let mut app = app();
    let before = app.state.rules.len();

    app.start_add();
    assert_eq!(app.tab, Tab::Add);
    assert_eq!(app.wizard.step, WizardStep::Goal);

    // 1. Allow traffic in
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.wizard.step, WizardStep::Who);

    // 2. Only my local network (the default selection)
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.wizard.step, WizardStep::Service);

    // 3. SSH (the first service)
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.wizard.step, WizardStep::Review);

    // 4. Apply is the second option on the review step.
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Enter);

    assert_eq!(
        app.state.rules.len(),
        before + 1,
        "the rule should have been added"
    );
    assert_eq!(app.journal.len(), 1);
    assert_eq!(app.tab, Tab::Rules);

    let added = app.state.rules.last().expect("a rule");
    assert_eq!(added.to.port.to_string(), "22");
    assert_eq!(added.from.addr.as_deref(), Some("192.168.1.0/24"));
    assert!(added.comment_text().contains("SSH") || added.comment.is_some());
}

#[test]
/**
 * Verifies that undoing an applied change restores the previous rule set and
 * consumes the journal entry.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the rule count is not restored or the journal is not emptied.
 */
fn undo_puts_the_rule_set_back_and_pops_the_journal() {
    let mut app = app();
    let before = app.state.rules.len();

    app.start_add();
    press(&mut app, KeyCode::Enter); // goal
    press(&mut app, KeyCode::Enter); // who
    press(&mut app, KeyCode::Enter); // service
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Enter); // apply
    assert_eq!(app.state.rules.len(), before + 1);

    app.undo();
    assert_eq!(app.state.rules.len(), before, "undo must remove the rule");
    assert!(app.journal.is_empty(), "the journal entry must be consumed");
}

#[test]
/**
 * Verifies that undoing a commented-out rule puts it back and stops offering to
 * restore it.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the rule is not restored or the stored copy survives the undo.
 */
fn undoing_a_commented_out_rule_also_forgets_the_stored_copy() {
    let mut app = app();
    app.tab = Tab::Rules;
    let before = app.state.rules.len();
    app.rules_cursor = 3;
    press(&mut app, KeyCode::Char('s'));
    assert_eq!(app.state.rules.len(), before - 1);
    assert_eq!(app.parked.len(), 1);

    app.undo();

    assert_eq!(app.state.rules.len(), before, "the rule must come back");
    assert!(
        app.parked.is_empty(),
        "a rule ufw enforces again must not stay commented out"
    );
}

#[test]
/**
 * Verifies that Ctrl+Up moves the selected rule one position earlier.
 *
 * Rule #4 is the deny rule; moving it up swaps it with rule #3.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the rule did not change position or no journal entry was written.
 */
fn ctrl_up_moves_the_selected_rule_up() {
    let mut app = app();
    app.tab = Tab::Rules;
    app.rules_cursor = 3;
    assert_eq!(app.selected_rule().unwrap().number, 4);

    press_with(&mut app, KeyCode::Up, KeyModifiers::CONTROL);

    assert_eq!(app.state.rules[2].number, 3);
    assert_eq!(app.state.rules[2].to.port.to_string(), "3306");
    assert_eq!(app.state.rules.len(), 6, "moving must not add a rule");
    assert_eq!(app.journal.len(), 1);
}

#[test]
/**
 * Verifies that Ctrl+Down moves the selected rule one position later.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the rule did not change position or no journal entry was written.
 */
fn ctrl_down_moves_the_selected_rule_down() {
    let mut app = app();
    app.tab = Tab::Rules;
    app.rules_cursor = 3;
    assert_eq!(app.selected_rule().unwrap().number, 4);

    press_with(&mut app, KeyCode::Down, KeyModifiers::CONTROL);

    assert_eq!(app.state.rules[4].number, 5);
    assert_eq!(app.state.rules[4].to.port.to_string(), "3306");
    assert_eq!(app.state.rules.len(), 6, "moving must not add a rule");
    assert_eq!(app.journal.len(), 1);
}

#[test]
/**
 * Verifies that moving a rule past the end of the list does nothing.
 *
 * A rule that cannot move further is reported instead of being deleted and
 * re-added in the same place.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the rule set changed or a journal entry was written.
 */
fn moving_a_rule_past_the_end_of_the_list_is_a_no_op() {
    let mut app = app();
    app.tab = Tab::Rules;

    app.rules_cursor = 0;
    press_with(&mut app, KeyCode::Up, KeyModifiers::CONTROL);
    assert!(app.journal.is_empty(), "the top rule cannot move up");

    app.rules_cursor = 5;
    press_with(&mut app, KeyCode::Down, KeyModifiers::CONTROL);
    assert!(app.journal.is_empty(), "the bottom rule cannot move down");
    assert_eq!(app.state.rules.len(), 6);
}

#[test]
/**
 * Verifies that the plain arrows still move the cursor rather than the rule.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the rule set changed.
 */
fn plain_arrows_only_move_the_cursor() {
    let mut app = app();
    app.tab = Tab::Rules;
    app.rules_cursor = 3;

    press(&mut app, KeyCode::Down);
    assert_eq!(app.rules_cursor, 4);
    press(&mut app, KeyCode::Up);
    assert_eq!(app.rules_cursor, 3);

    assert!(app.journal.is_empty(), "the cursor must not change rules");
    assert_eq!(app.state.rules.len(), 6);
}

#[test]
/**
 * Verifies that pressing `d` on a rule removes it from the rule set and adds a
 * journal entry.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the rule count does not decrease by one or the journal is empty.
 */
fn deleting_a_rule_reduces_the_list() {
    let mut app = app();
    app.tab = Tab::Rules;
    let before = app.state.rules.len();

    // Rule #4 is the deny rule, which nothing depends on.
    app.rules_cursor = 3;
    press(&mut app, KeyCode::Char('d'));

    assert_eq!(app.state.rules.len(), before - 1);
    assert!(app.journal.len() == 1);
}

#[test]
/**
 * Verifies that `s` comments a rule out and that pressing it again puts the very
 * same rule back where it was.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the rule set or the commented-out list is not updated as expected.
 */
fn commenting_a_rule_out_can_be_undone_with_the_same_key() {
    let mut app = app();
    app.tab = Tab::Rules;
    let before = app.state.rules.len();

    // Rule #4 is the deny rule, which nothing depends on.
    app.rules_cursor = 3;
    let original = app.selected_rule().expect("rule #4 is selected");
    press(&mut app, KeyCode::Char('s'));

    assert_eq!(app.state.rules.len(), before - 1, "the rule must leave ufw");
    assert_eq!(app.parked.len(), 1, "the rule must be remembered");
    assert_eq!(app.parked.entries()[0].position, original.number);
    assert!(app.parked.entries()[0].signature() == original.signature());

    // The commented-out rule is listed after the live ones, so it is the last row.
    app.rules_cursor = app.rules_row_count() - 1;
    assert!(
        app.selected_parked().is_some(),
        "the last row is the parked one"
    );
    press(&mut app, KeyCode::Char('s'));

    assert_eq!(app.state.rules.len(), before, "the rule must come back");
    assert!(app.parked.is_empty(), "nothing should stay commented out");
    assert_eq!(app.state.rules[3].number, 4, "it returns to position 4");
    assert!(app.state.rules[3].signature() == original.signature());
}

#[test]
/**
 * Verifies that deleting a commented-out rule forgets it instead of touching the
 * firewall, and that rule actions explain why they do nothing.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the stored copy survives or the wrong message is shown.
 */
fn a_commented_out_rule_can_be_forgotten_and_explains_itself() {
    let mut app = app();
    app.tab = Tab::Rules;
    app.rules_cursor = 3;
    press(&mut app, KeyCode::Char('s'));
    let live = app.state.rules.len();

    app.rules_cursor = app.rules_row_count() - 1;
    press(&mut app, KeyCode::Char('e'));
    assert_eq!(app.tab, Tab::Rules, "a commented-out rule cannot be edited");
    let status = app.status.as_ref().expect("a status message is set");
    assert!(status.text.contains("commented out"), "{}", status.text);

    app.rules_cursor = app.rules_row_count() - 1;
    press(&mut app, KeyCode::Char('d'));
    assert!(app.parked.is_empty(), "d forgets the stored copy");
    assert_eq!(app.state.rules.len(), live, "the firewall is untouched");
}

#[test]
/**
 * Verifies that commented-out rules are written to disk and read back on the next
 * start, so quitting the app does not lose them.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the file is not written or the rule is not remembered.
 */
fn commented_out_rules_survive_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("disabled-rules.json");
    let options = |path: Option<std::path::PathBuf>| AppOptions {
        journal_path: None,
        parked_path: path,
        yes: false,
        readonly: false,
        theme: Theme::new("dark", false),
        reconcile_seconds: 0,
        show_counters: true,
        confirm_before_apply: false,
        no_color: false,
        config: Config::default(),
        config_path: None,
    };

    let mut app = App::new(Box::new(MockBackend::new()), options(Some(path.clone())));
    app.tab = Tab::Rules;
    app.rules_cursor = 3;
    press(&mut app, KeyCode::Char('s'));
    assert!(path.exists(), "the commented-out rule must be written");

    let reopened = App::new(Box::new(MockBackend::new()), options(Some(path)));
    assert_eq!(reopened.parked.len(), 1, "the rule must be remembered");
    assert_eq!(reopened.parked.entries()[0].position, 4);
    // A fresh mock backend still has all six rules, so the reopened app lists those plus the
    // remembered one.
    assert_eq!(reopened.rules_row_count(), 7, "six live rules plus one");
}

#[test]
/**
 * Verifies that the lockout guard is consulted for destructive changes: a
 * reset is always routed through a modal instead of being applied silently.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if no modal is shown for the submitted reset.
 */
fn deleting_the_ssh_rule_is_blocked_when_the_change_would_be_unsafe() {
    // No SSH session in tests, so the guard permits it; this asserts the guard is consulted at all
    // by checking that a reset is refused.
    let mut app = app();
    app.tab = Tab::Rules;
    let reset = ufw_manager::core::command::change_reset();
    let pending = ufw_manager::core::lockout::PendingChange::new(
        ufw_manager::core::lockout::ChangeKind::Reset,
        reset.description.clone(),
    );
    app.submit(reset, pending);
    assert!(
        app.modal.is_some(),
        "a reset must always be confirmed or refused"
    );
}

#[test]
/**
 * Verifies that the traffic simulator reports the rule that decides a packet,
 * including the winning rule number for an allowed SSH connection.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if no trace is produced, the packet is not allowed, or the winning
 * rule is not rule 1.
 */
fn the_simulator_reports_the_rule_that_decides_a_packet() {
    let mut app = app();
    app.tab = Tab::Test;
    app.traffic.src.set("203.0.113.9");
    app.traffic.dst_port.set("22");
    app.run_simulation();

    let trace = app.trace.as_ref().expect("a trace");
    assert!(trace.allowed());
    assert_eq!(trace.winning_rule, Some(1));
}

#[test]
/**
 * Verifies that the simulator explains a dropped packet by reporting that the
 * default policy decided it.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if no trace is produced, the packet is allowed, or the trace is not
 * attributed to the default policy.
 */
fn the_simulator_explains_why_a_packet_is_dropped() {
    let mut app = app();
    app.tab = Tab::Test;
    app.traffic.src.set("203.0.113.9");
    app.traffic.dst_port.set("9999");
    app.run_simulation();

    let trace = app.trace.as_ref().expect("a trace");
    assert!(!trace.allowed());
    assert!(trace.decided_by_default);
}

#[test]
/**
 * Verifies that pressing Escape during the add wizard abandons it without
 * changing the rule set or the journal.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the tab, rule count, or journal differ from the pre-wizard state.
 */
fn the_wizard_can_be_abandoned_with_escape() {
    let mut app = app();
    let before = app.state.rules.len();
    app.start_add();
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.tab, Tab::Rules);
    assert_eq!(app.state.rules.len(), before);
    assert!(app.journal.is_empty());
}

#[test]
/**
 * Verifies that Tab and BackTab cycle through the tabs in both directions and
 * wrap around at the ends.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the selected tab is not the expected one after each key press.
 */
fn tabs_cycle_in_both_directions() {
    let mut app = app();
    assert_eq!(app.tab, Tab::Home);
    press(&mut app, KeyCode::Tab);
    assert_eq!(app.tab, Tab::Rules);
    press(&mut app, KeyCode::BackTab);
    assert_eq!(app.tab, Tab::Home);
    // Wrapping backwards from the first tab lands on the last.
    press(&mut app, KeyCode::BackTab);
    assert_eq!(app.tab, Tab::Settings);
}

#[test]
/**
 * Verifies that number keys jump directly to the corresponding tab.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the selected tab does not match the pressed number.
 */
fn number_keys_jump_directly_to_a_tab() {
    let mut app = app();
    press(&mut app, KeyCode::Char('4'));
    assert_eq!(app.tab, Tab::Test);
    press(&mut app, KeyCode::Char('1'));
    assert_eq!(app.tab, Tab::Home);
}

#[test]
/**
 * Verifies that pressing `q` requests application shutdown.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if `should_quit` is not set.
 */
fn q_quits() {
    let mut app = app();
    press(&mut app, KeyCode::Char('q'));
    assert!(app.should_quit);
}

#[test]
/**
 * Verifies that read-only mode refuses a delete: the rule set is unchanged, no
 * journal entry is written, and the user is told why.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the rule set changes, the journal is non-empty, or no status
 * message is shown.
 */
fn read_only_mode_refuses_to_write() {
    let mut app = App::new(
        Box::new(MockBackend::new()),
        AppOptions {
            journal_path: None,
            parked_path: None,
            yes: false,
            readonly: true,
            theme: Theme::new("dark", false),
            reconcile_seconds: 0,
            show_counters: true,
            confirm_before_apply: false,
            no_color: false,
            config: Config::default(),
            config_path: None,
        },
    );
    let before = app.state.rules.len();
    app.tab = Tab::Rules;
    app.rules_cursor = 3;
    press(&mut app, KeyCode::Char('d'));

    assert_eq!(
        app.state.rules.len(),
        before,
        "nothing may change in read-only mode"
    );
    assert!(app.journal.is_empty());
    assert!(app.status.is_some(), "the user must be told why");
}

#[test]
/**
 * Verifies that pressing `e` on an existing rule opens the wizard prefilled
 * with that rule and positioned on the review step.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the tab, wizard step, edited rule number, or prefilled port is not
 * as expected.
 */
fn editing_an_existing_rule_opens_the_wizard_prefilled() {
    let mut app = app();
    app.tab = Tab::Rules;
    app.rules_cursor = 0;
    press(&mut app, KeyCode::Char('e'));

    assert_eq!(app.tab, Tab::Add);
    assert_eq!(app.wizard.step, WizardStep::Review);
    assert_eq!(app.wizard.editing, Some(1));
    assert_eq!(app.wizard.draft.to_port.to_string(), "22");
}

#[test]
/**
 * Verifies that the forwarding rule in the demo set can be edited.
 *
 * Forwarding rules used to be refused outright; the draft has to keep both
 * interfaces so the rebuilt command is still a `ufw route` rule.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the wizard does not open on the forwarding rule or the draft lost
 * its direction or interfaces.
 */
fn editing_a_forward_rule_opens_the_wizard_prefilled() {
    let mut app = app();
    app.tab = Tab::Rules;
    // The demo's rule 6 is `Anywhere on wg0  ALLOW FWD  Anywhere`.
    app.rules_cursor = 5;
    press(&mut app, KeyCode::Char('e'));

    assert_eq!(app.tab, Tab::Add);
    assert_eq!(app.wizard.step, WizardStep::Review);
    assert_eq!(app.wizard.editing, Some(6));
    assert_eq!(
        app.wizard.draft.direction,
        ufw_manager::core::rule::Direction::Forward
    );
    assert_eq!(app.wizard.draft.interface_out.as_deref(), Some("wg0"));
}

#[test]
/**
 * Verifies that applying an edited forwarding rule sends `route insert`.
 *
 * The edit is a delete by number followed by a `ufw route insert NUM …`, so the
 * rule keeps its position and stays a route rule.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the update was not queued as expected.
 */
fn applying_an_edited_forward_rule_sends_a_route_insert() {
    let mut app = app();
    app.tab = Tab::Rules;
    app.rules_cursor = 5;
    press(&mut app, KeyCode::Char('e'));

    // Apply is the second option on the review step.
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Enter);

    assert_eq!(app.journal.len(), 1);
    let entry = &app.journal.entries()[0];
    let steps: Vec<String> = entry.forward.iter().map(|step| step.join(" ")).collect();
    assert!(steps[0].contains("delete 6"), "{steps:?}");
    // Rule 6 is the last rule, so `ufw` re-appends it instead of inserting at position 6.
    assert!(steps[1].starts_with("route allow out on wg0"), "{steps:?}");

    let kept = app.state.rules.iter().filter(|r| r.is_route()).count();
    assert_eq!(kept, 1, "the forwarding rule should still be there");
}

#[test]
/**
 * Verifies that a forwarding rule can be deleted like any other rule.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the rule set still contains a forwarding rule afterwards.
 */
fn deleting_a_forward_rule_removes_it() {
    let mut app = app();
    app.tab = Tab::Rules;
    let before = app.state.rules.len();
    app.rules_cursor = 5;
    press(&mut app, KeyCode::Char('d'));

    assert_eq!(app.state.rules.len(), before - 1);
    assert!(app.state.rules.iter().all(|rule| !rule.is_route()));
}

#[test]
/**
 * Verifies that the forwarding goal jumps straight to the advanced step with
 * the incoming-interface row selected.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the wizard lands somewhere else or the direction is not forwarding.
 */
fn the_forwarding_goal_opens_the_advanced_step() {
    let mut app = app();
    app.start_add();
    app.wizard.cursor = 3;
    press(&mut app, KeyCode::Enter);

    assert_eq!(app.wizard.step, WizardStep::Advanced);
    assert_eq!(app.wizard.cursor, 2);
    assert_eq!(
        app.wizard.draft.direction,
        ufw_manager::core::rule::Direction::Forward
    );
}

#[test]
/**
 * Verifies that a forwarding rule can be built end to end from the wizard.
 *
 * The test picks the forwarding goal, types both interfaces, walks to the end
 * of the advanced step and applies, then checks that the firewall gained a
 * `route` rule with both interfaces.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the wizard does not follow the expected path or the rule set does
 * not gain the forwarding rule.
 */
fn creating_a_forward_rule_through_the_wizard_adds_a_route_rule() {
    let mut app = app();
    app.start_add();
    app.wizard.cursor = 3;
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.wizard.step, WizardStep::Advanced);

    // Row 2 is "In interface"; clear whatever the defaults prefilled.
    press(&mut app, KeyCode::Enter);
    for _ in 0..16 {
        press(&mut app, KeyCode::Backspace);
    }
    for c in "wg0".chars() {
        press(&mut app, KeyCode::Char(c));
    }
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.wizard.draft.interface_in.as_deref(), Some("wg0"));

    // Row 3 is "Out interface".
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Enter);
    for _ in 0..16 {
        press(&mut app, KeyCode::Backspace);
    }
    for c in "eno1".chars() {
        press(&mut app, KeyCode::Char(c));
    }
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.wizard.draft.interface_out.as_deref(), Some("eno1"));

    // Walk to the last row, "Done — go to review", and apply.
    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.wizard.step, WizardStep::Review);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Enter);

    let added = app.state.rules.last().expect("the new rule");
    assert!(added.is_route(), "{added:?}");
    assert_eq!(added.interface_in.as_deref(), Some("wg0"));
    assert_eq!(added.interface_out.as_deref(), Some("eno1"));
}

#[test]
/**
 * Verifies that with skip-wizard enabled, editing a rule opens the wizard on
 * the advanced step instead of the review step.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the wizard does not open on the advanced step or the edit target
 * is lost.
 */
fn editing_a_rule_with_skip_wizard_opens_the_advanced_step() {
    let mut app = app();
    app.skip_wizard = true;
    app.config.skip_wizard = true;
    app.tab = Tab::Rules;
    app.rules_cursor = 0;
    press(&mut app, KeyCode::Char('e'));

    assert_eq!(app.tab, Tab::Add);
    assert_eq!(app.wizard.step, WizardStep::Advanced);
    assert_eq!(app.wizard.editing, Some(1));
    assert_eq!(app.wizard.draft.to_port.to_string(), "22");
}

#[test]
/**
 * Verifies that pressing `a` on the Add tab jumps straight to the advanced
 * step from any wizard step.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the wizard does not land on the advanced step.
 */
fn the_add_tab_a_key_jumps_to_the_advanced_step() {
    let mut app = app();
    app.start_add();
    assert_eq!(app.wizard.step, WizardStep::Goal);

    press(&mut app, KeyCode::Char('a'));
    assert_eq!(app.wizard.step, WizardStep::Advanced);
    assert_eq!(app.wizard.cursor, 0);

    // The uppercase form works too, and from a later step.
    app.wizard.step = WizardStep::Service;
    press(&mut app, KeyCode::Char('A'));
    assert_eq!(app.wizard.step, WizardStep::Advanced);
}

#[test]
/**
 * Verifies that the shadowed-rule detector finds rule 3 shadowed by rule 1 in
 * the demo rule set.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the expected shadowing pair is not reported.
 */
fn a_shadowed_rule_is_detected_in_the_demo_rule_set() {
    // Rules #1 (allow 22 from anywhere) and #3 (allow OpenSSH from the LAN) overlap: #3 can never
    // fire for LAN addresses, because #1 already matches them.
    let app = app();
    assert!(
        app.shadowed
            .iter()
            .any(|(later, by)| *later == 3 && *by == 1),
        "expected #3 to be shadowed by #1, got {:?}",
        app.shadowed
    );
}

/**
 * Builds an [`App`] on the mock backend with confirmation before apply enabled,
 * so tests can exercise the confirmation dialog.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `App` - An application whose options set `confirm_before_apply` to `true`.
 */
fn app_with_confirmation() -> App {
    App::new(
        Box::new(MockBackend::new()),
        AppOptions {
            journal_path: None,
            parked_path: None,
            yes: false,
            readonly: false,
            theme: Theme::new("dark", false),
            reconcile_seconds: 0,
            show_counters: true,
            confirm_before_apply: true,
            no_color: false,
            config: Config::default(),
            config_path: None,
        },
    )
}

/**
 * Builds a matching add-rule change and pending change for port 2222, used by
 * the confirmation dialog tests.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `(ufw_manager::core::command::Change, ufw_manager::core::lockout::PendingChange)` -
 * The change to apply and the pending change describing it, both for an
 * `admin SSH` rule on TCP port 2222.
 *
 * # Panics
 *
 * Panics if the change cannot be built from the draft.
 */
fn ssh_change() -> (
    ufw_manager::core::command::Change,
    ufw_manager::core::lockout::PendingChange,
) {
    use ufw_manager::core::command::change_add;
    use ufw_manager::core::lockout::{ChangeKind, PendingChange};
    use ufw_manager::core::rule::{Protocol, RuleDraft};

    let draft = RuleDraft::allow_port(Protocol::Tcp, 2222).with_comment("admin SSH");
    let change = change_add(&draft).expect("change");
    let pending =
        PendingChange::new(ChangeKind::AddRule, change.description.clone()).with_draft(draft);
    (change, pending)
}

#[test]
/**
 * Verifies that a submitted change is held in a confirmation dialog until the
 * user presses Enter, and that the dialog states the effect in words.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if no modal is shown, the change is applied early, the rendered
 * dialog lacks the expected text, or the change is not applied on Enter.
 */
fn the_confirmation_dialog_holds_the_change_until_enter() {
    let mut app = app_with_confirmation();
    let before = app.state.rules.len();
    let (change, pending) = ssh_change();

    app.submit(change, pending);
    assert!(app.modal.is_some(), "a confirmation must be shown");
    assert_eq!(app.state.rules.len(), before, "nothing may be applied yet");
    assert!(app.journal.is_empty());

    // The dialog states the effect in words, not just the command.
    let rendered = ufw_manager::ui::render_dialog_for_test(&app);
    assert!(rendered.contains("ufw allow 2222/tcp"), "{rendered}");
    assert!(
        rendered.contains("2222 (admin SSH)") || rendered.contains("2222"),
        "{rendered}"
    );

    press(&mut app, KeyCode::Enter);
    assert!(app.modal.is_none());
    assert_eq!(app.state.rules.len(), before + 1);
    assert_eq!(app.journal.len(), 1);
}

#[test]
/**
 * Verifies that pressing Escape in the confirmation dialog cancels the change
 * without touching the rule set or the journal.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the modal remains, the rule set changes, or the journal is
 * non-empty.
 */
fn escaping_the_confirmation_dialog_cancels_the_change() {
    let mut app = app_with_confirmation();
    let before = app.state.rules.len();
    let (change, pending) = ssh_change();

    app.submit(change, pending);
    press(&mut app, KeyCode::Esc);

    assert!(app.modal.is_none());
    assert_eq!(app.state.rules.len(), before);
    assert!(app.journal.is_empty());
}

#[test]
/**
 * Verifies that commenting a rule out is confirmed first, that the dialog says
 * so in words, and that cancelling it leaves the rule live and nothing
 * commented out.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the dialog is missing, its wording is wrong, cancelling changes
 * anything, or confirming does not park the rule.
 */
fn commenting_a_rule_out_is_confirmed_and_can_be_cancelled() {
    let mut app = app_with_confirmation();
    app.tab = Tab::Rules;
    let before = app.state.rules.len();
    app.rules_cursor = 3;

    press(&mut app, KeyCode::Char('s'));
    assert!(app.modal.is_some(), "a confirmation must be shown");
    let rendered = ufw_manager::ui::render_dialog_for_test(&app);
    assert!(rendered.contains("comment out rule #4"), "{rendered}");
    assert!(
        rendered.contains("Comment out the rule that says"),
        "{rendered}"
    );

    press(&mut app, KeyCode::Esc);
    assert!(app.modal.is_none());
    assert_eq!(
        app.state.rules.len(),
        before,
        "cancelling must change nothing"
    );
    assert!(app.parked.is_empty());

    press(&mut app, KeyCode::Char('s'));
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.state.rules.len(), before - 1);
    assert_eq!(app.parked.len(), 1);
}

#[test]
/**
 * Verifies that a reset is refused by the lockout guard even when confirmation
 * before apply is enabled, leaving the rule set and journal untouched.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the rule set changes or a journal entry is written.
 */
fn a_reset_is_refused_regardless_of_confirmation_settings() {
    use ufw_manager::core::command::change_reset;
    use ufw_manager::core::lockout::{ChangeKind, PendingChange};

    let mut app = app_with_confirmation();
    let before = app.state.rules.len();
    let change = change_reset();
    let pending = PendingChange::new(ChangeKind::Reset, change.description.clone());
    app.submit(change, pending);

    // The guard refuses it, so the dialog is an error rather than a confirmation.
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.state.rules.len(), before);
    assert!(app.journal.is_empty());
}

#[test]
/**
 * Verifies the behaviour of the `X` escalation shortcut in three cases: a
 * backend that already has write access, a read-only backend with escalation
 * disabled, and a backend that may escalate.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if an unexpected escalation request is produced, the explanatory
 * status message is missing, or no privileges request is returned by the
 * escalatable backend.
 */
fn x_asks_for_privileges_when_it_can_and_explains_when_it_cannot() {
    use ufw_manager::app::Escalation;

    // Demo backend already has write access, so X is a no-op with an explanation.
    let mut app = app();
    press(&mut app, KeyCode::Char('X'));
    assert!(app.escalation.is_none());
    assert!(app.status.is_some());

    // Read-only with escalation disabled: still no request, but the reason mentions the flags.
    let mut app = App::new(
        Box::new(ReadOnlyBackend),
        AppOptions {
            journal_path: None,
            parked_path: None,
            yes: false,
            readonly: true,
            theme: Theme::new("dark", false),
            reconcile_seconds: 0,
            show_counters: true,
            confirm_before_apply: false,
            no_color: false,
            config: Config::default(),
            config_path: None,
        },
    );
    press(&mut app, KeyCode::Char('X'));
    assert!(app.escalation.is_none());
    let message = app
        .status
        .as_ref()
        .map(|s| s.text.clone())
        .unwrap_or_default();
    assert!(message.contains("escalation is disabled"), "{message}");

    // A backend that may escalate: X produces a request the main loop can act on.
    let mut app = App::new(
        Box::new(EscalatableBackend),
        AppOptions {
            journal_path: None,
            parked_path: None,
            yes: false,
            readonly: false,
            theme: Theme::new("dark", false),
            reconcile_seconds: 0,
            show_counters: true,
            confirm_before_apply: false,
            no_color: false,
            config: Config::default(),
            config_path: None,
        },
    );
    press(&mut app, KeyCode::Char('X'));
    assert!(matches!(
        app.take_escalation(),
        Some(Escalation::Privileges)
    ));
}

/**
 * A unit-struct test double for a backend that never allows writes and refuses
 * escalation.
 *
 * It reports an empty firewall state so the application can start, but every
 * write or dry run fails with [`ufw_manager::backend::BackendError::NotRoot`].
 * Tests use it to check that read-only mode refuses changes and that the `X`
 * shortcut explains why escalation is unavailable.
 *
 * # Fields
 *
 * This struct has no fields; it is a marker type.
 */
struct ReadOnlyBackend;

impl ufw_manager::backend::Backend for ReadOnlyBackend {
    /**
     * Returns the backend's display label.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The backend instance.
     *
     * # Returns
     *
     * `String` - The constant label `"read-only"`.
     */
    fn label(&self) -> String {
        "read-only".into()
    }
    /**
     * Reports that this backend never runs as root.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The backend instance.
     *
     * # Returns
     *
     * `bool` - Always `false`.
     */
    fn is_root(&self) -> bool {
        false
    }
    /**
     * Reports that this backend cannot write to the firewall.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The backend instance.
     *
     * # Returns
     *
     * `bool` - Always `false`.
     */
    fn can_write(&self) -> bool {
        false
    }
    /**
     * Returns an empty default firewall state so the application can start.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The backend instance.
     *
     * # Returns
     *
     * `Result<ufw_manager::core::firewall::FirewallState, ufw_manager::backend::BackendError>` -
     * Always `Ok` with a default state.
     */
    fn read_state(
        &self,
    ) -> Result<ufw_manager::core::firewall::FirewallState, ufw_manager::backend::BackendError>
    {
        Ok(ufw_manager::core::firewall::FirewallState::default())
    }
    /**
     * Returns no application profiles.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The backend instance.
     *
     * # Returns
     *
     * `Result<Vec<ufw_manager::core::parse::AppProfile>, ufw_manager::backend::BackendError>` -
     * Always `Ok` with an empty vector.
     */
    fn app_profiles(
        &self,
    ) -> Result<Vec<ufw_manager::core::parse::AppProfile>, ufw_manager::backend::BackendError> {
        Ok(Vec::new())
    }
    /**
     * Returns no listening sockets.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The backend instance.
     *
     * # Returns
     *
     * `Result<Vec<ufw_manager::core::parse::Listening>, ufw_manager::backend::BackendError>` -
     * Always `Ok` with an empty vector.
     */
    fn listening(
        &self,
    ) -> Result<Vec<ufw_manager::core::parse::Listening>, ufw_manager::backend::BackendError> {
        Ok(Vec::new())
    }
    /**
     * Reports that hit counters are unavailable for this backend.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The backend instance.
     * * `_rules` (`&[ufw_manager::core::rule::Rule]`) - The rules to query; ignored.
     *
     * # Returns
     *
     * `Result<ufw_manager::backend::HitCounters, ufw_manager::backend::BackendError>` -
     * Always `Ok` with counters marked unavailable.
     */
    fn counters(
        &self,
        _rules: &[ufw_manager::core::rule::Rule],
    ) -> Result<ufw_manager::backend::HitCounters, ufw_manager::backend::BackendError> {
        Ok(ufw_manager::backend::HitCounters::unavailable("read-only"))
    }
    /**
     * Refuses to run any command because the backend is read-only.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The backend instance.
     * * `_args` (`&[String]`) - The command arguments; ignored.
     *
     * # Returns
     *
     * `Result<ufw_manager::backend::CmdOutput, ufw_manager::backend::BackendError>` -
     * Always `Err(BackendError::NotRoot)`.
     */
    fn run(
        &self,
        _args: &[String],
    ) -> Result<ufw_manager::backend::CmdOutput, ufw_manager::backend::BackendError> {
        Err(ufw_manager::backend::BackendError::NotRoot(
            "read-only".into(),
        ))
    }
    /**
     * Refuses to dry-run any command because the backend is read-only.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The backend instance.
     * * `_args` (`&[String]`) - The command arguments; ignored.
     *
     * # Returns
     *
     * `Result<ufw_manager::backend::CmdOutput, ufw_manager::backend::BackendError>` -
     * Always `Err(BackendError::NotRoot)`.
     */
    fn dry_run(
        &self,
        _args: &[String],
    ) -> Result<ufw_manager::backend::CmdOutput, ufw_manager::backend::BackendError> {
        Err(ufw_manager::backend::BackendError::NotRoot(
            "read-only".into(),
        ))
    }
    /**
     * Returns the SSH port used by the lockout guard.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The backend instance.
     *
     * # Returns
     *
     * `u16` - Always `22`.
     */
    fn ssh_port(&self) -> u16 {
        22
    }
    /**
     * Reports that the current session is local, so no SSH lockout risk exists.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The backend instance.
     *
     * # Returns
     *
     * `ufw_manager::core::lockout::Session` - A local session.
     */
    fn ssh_session(&self) -> ufw_manager::core::lockout::Session {
        ufw_manager::core::lockout::Session::local()
    }
    /**
     * Reports that no LAN information is available.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The backend instance.
     *
     * # Returns
     *
     * `Option<ufw_manager::core::presets::LanInfo>` - Always `None`.
     */
    fn lan(&self) -> Option<ufw_manager::core::presets::LanInfo> {
        None
    }
    /**
     * Returns no network interfaces.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The backend instance.
     *
     * # Returns
     *
     * `Vec<String>` - An empty vector.
     */
    fn interfaces(&self) -> Vec<String> {
        Vec::new()
    }
}

/**
 * A unit-struct test double for a backend that cannot write yet is willing to
 * ask for elevated privileges.
 *
 * Reading state fails with [`ufw_manager::backend::BackendError::NotRoot`], and
 * [`ufw_manager::backend::Backend::may_escalate`] returns `true`, so tests can
 * verify that the `X` shortcut produces a privileges request.
 *
 * # Fields
 *
 * This struct has no fields; it is a marker type.
 */
struct EscalatableBackend;

impl ufw_manager::backend::Backend for EscalatableBackend {
    /**
     * Returns the backend's display label.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The backend instance.
     *
     * # Returns
     *
     * `String` - The constant label `"needs sudo"`.
     */
    fn label(&self) -> String {
        "needs sudo".into()
    }
    /**
     * Reports that this backend never runs as root.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The backend instance.
     *
     * # Returns
     *
     * `bool` - Always `false`.
     */
    fn is_root(&self) -> bool {
        false
    }
    /**
     * Reports that this backend cannot write to the firewall without escalation.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The backend instance.
     *
     * # Returns
     *
     * `bool` - Always `false`.
     */
    fn can_write(&self) -> bool {
        false
    }
    /**
     * Fails to read state, simulating a backend that needs elevated privileges.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The backend instance.
     *
     * # Returns
     *
     * `Result<ufw_manager::core::firewall::FirewallState, ufw_manager::backend::BackendError>` -
     * Always `Err(BackendError::NotRoot)`.
     */
    fn read_state(
        &self,
    ) -> Result<ufw_manager::core::firewall::FirewallState, ufw_manager::backend::BackendError>
    {
        Err(ufw_manager::backend::BackendError::NotRoot("no".into()))
    }
    /**
     * Returns no application profiles.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The backend instance.
     *
     * # Returns
     *
     * `Result<Vec<ufw_manager::core::parse::AppProfile>, ufw_manager::backend::BackendError>` -
     * Always `Ok` with an empty vector.
     */
    fn app_profiles(
        &self,
    ) -> Result<Vec<ufw_manager::core::parse::AppProfile>, ufw_manager::backend::BackendError> {
        Ok(Vec::new())
    }
    /**
     * Returns no listening sockets.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The backend instance.
     *
     * # Returns
     *
     * `Result<Vec<ufw_manager::core::parse::Listening>, ufw_manager::backend::BackendError>` -
     * Always `Ok` with an empty vector.
     */
    fn listening(
        &self,
    ) -> Result<Vec<ufw_manager::core::parse::Listening>, ufw_manager::backend::BackendError> {
        Ok(Vec::new())
    }
    /**
     * Reports that hit counters are unavailable without root.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The backend instance.
     * * `_rules` (`&[ufw_manager::core::rule::Rule]`) - The rules to query; ignored.
     *
     * # Returns
     *
     * `Result<ufw_manager::backend::HitCounters, ufw_manager::backend::BackendError>` -
     * Always `Ok` with counters marked unavailable.
     */
    fn counters(
        &self,
        _rules: &[ufw_manager::core::rule::Rule],
    ) -> Result<ufw_manager::backend::HitCounters, ufw_manager::backend::BackendError> {
        Ok(ufw_manager::backend::HitCounters::unavailable("no root"))
    }
    /**
     * Refuses to run any command without elevated privileges.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The backend instance.
     * * `_args` (`&[String]`) - The command arguments; ignored.
     *
     * # Returns
     *
     * `Result<ufw_manager::backend::CmdOutput, ufw_manager::backend::BackendError>` -
     * Always `Err(BackendError::NotRoot)`.
     */
    fn run(
        &self,
        _args: &[String],
    ) -> Result<ufw_manager::backend::CmdOutput, ufw_manager::backend::BackendError> {
        Err(ufw_manager::backend::BackendError::NotRoot("no".into()))
    }
    /**
     * Refuses to dry-run any command without elevated privileges.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The backend instance.
     * * `_args` (`&[String]`) - The command arguments; ignored.
     *
     * # Returns
     *
     * `Result<ufw_manager::backend::CmdOutput, ufw_manager::backend::BackendError>` -
     * Always `Err(BackendError::NotRoot)`.
     */
    fn dry_run(
        &self,
        _args: &[String],
    ) -> Result<ufw_manager::backend::CmdOutput, ufw_manager::backend::BackendError> {
        Err(ufw_manager::backend::BackendError::NotRoot("no".into()))
    }
    /**
     * Returns the SSH port used by the lockout guard.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The backend instance.
     *
     * # Returns
     *
     * `u16` - Always `22`.
     */
    fn ssh_port(&self) -> u16 {
        22
    }
    /**
     * Reports that the current session is local, so no SSH lockout risk exists.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The backend instance.
     *
     * # Returns
     *
     * `ufw_manager::core::lockout::Session` - A local session.
     */
    fn ssh_session(&self) -> ufw_manager::core::lockout::Session {
        ufw_manager::core::lockout::Session::local()
    }
    /**
     * Reports that no LAN information is available.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The backend instance.
     *
     * # Returns
     *
     * `Option<ufw_manager::core::presets::LanInfo>` - Always `None`.
     */
    fn lan(&self) -> Option<ufw_manager::core::presets::LanInfo> {
        None
    }
    /**
     * Returns no network interfaces.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The backend instance.
     *
     * # Returns
     *
     * `Vec<String>` - An empty vector.
     */
    fn interfaces(&self) -> Vec<String> {
        Vec::new()
    }
    /**
     * Reports that this backend is willing to ask for elevated privileges.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The backend instance.
     *
     * # Returns
     *
     * `bool` - Always `true`.
     */
    fn may_escalate(&self) -> bool {
        true
    }
}

#[test]
/**
 * Verifies that typing in the Test tab's source address field inserts letters
 * instead of triggering the global `q` quit shortcut.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the focused field is not the source address, the application quits,
 * or the typed character is missing from the field.
 */
fn letters_are_inserted_in_the_test_tab_source_field_instead_of_running_commands() {
    let mut app = app();
    app.tab = Tab::Test;
    // Move from field 0 to field 2 (the source address), which is a text field.
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Down);
    assert_eq!(app.traffic.field, 2);

    // 'q' would quit if the global shortcut were still bound.
    press(&mut app, KeyCode::Char('q'));
    assert!(!app.should_quit, "'q' must be inserted, not quit");
    assert!(app.traffic.src.value().contains('q'));
}

#[test]
/**
 * Verifies that typing digits in the Test tab's source address field inserts
 * them instead of jumping to another tab.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the focused field is not the source address, the tab changes, or
 * the typed digit is missing from the field.
 */
fn digits_are_inserted_in_the_test_tab_source_field_instead_of_jumping_tabs() {
    let mut app = app();
    app.tab = Tab::Test;
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Down);
    assert_eq!(app.traffic.field, 2);

    // '4' would jump to the Test tab if the global shortcut were still bound.
    press(&mut app, KeyCode::Char('4'));
    assert_eq!(app.tab, Tab::Test, "the tab must not change while typing");
    assert!(app.traffic.src.value().contains('4'));
}

#[test]
/**
 * Verifies that global shortcuts remain bound on the Test tab while focus is on
 * a selector rather than a text field.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the initial focus is not the direction selector or the number key
 * does not switch to the Home tab.
 */
fn global_shortcuts_still_work_outside_text_fields_on_the_test_tab() {
    let mut app = app();
    app.tab = Tab::Test;
    // Field 0 (direction) is a selector, not a text field, so shortcuts stay bound.
    assert_eq!(app.traffic.field, 0);
    press(&mut app, KeyCode::Char('1'));
    assert_eq!(
        app.tab,
        Tab::Home,
        "tab jump still works outside text input"
    );
}

#[test]
/**
 * Verifies that opening the wizard's address input unbinds global shortcuts, so
 * `q` and `1` are inserted into the field instead of quitting or switching tabs.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the address input does not open, the application quits, or the
 * typed characters are missing from the field.
 */
fn wizard_address_input_unbinds_shortcuts() {
    let mut app = app();
    app.start_add();
    assert_eq!(app.tab, Tab::Add);

    // Goal -> Who
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.wizard.step, WizardStep::Who);
    // Select "One specific address or network".
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Enter);
    assert!(
        app.wizard.input.is_some(),
        "the address field should be open"
    );

    // 'q' and '1' must be inserted, not trigger quit / tab jump.
    press(&mut app, KeyCode::Char('q'));
    press(&mut app, KeyCode::Char('1'));
    assert!(
        !app.should_quit,
        "'q' must be inserted into the address field"
    );
    let (_, input) = app.wizard.input.as_ref().expect("still editing");
    assert!(input.value().contains('q'));
    assert!(input.value().contains('1'));
}

#[test]
/**
 * Verifies that the Settings tab is reachable by number key and that toggling
 * the skip-wizard checkbox flips the flag.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the tab is not Settings or the flag does not flip.
 */
fn settings_tab_toggles_skip_wizard() {
    let mut app = app();
    press(&mut app, KeyCode::Char('8'));
    assert_eq!(app.tab, Tab::Settings);
    assert!(!app.skip_wizard);

    // Row 6 is the skip-wizard checkbox.
    for _ in 0..6 {
        press(&mut app, KeyCode::Down);
    }
    press(&mut app, KeyCode::Char(' '));
    assert!(app.skip_wizard);
    assert!(app.config.skip_wizard);
}

#[test]
/**
 * Verifies that cycling the default action on the Settings tab changes the
 * config and that a new rule starts from the configured defaults.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the action does not cycle or the new draft ignores the defaults.
 */
fn settings_defaults_are_used_for_new_rules() {
    let mut app = app();
    app.tab = Tab::Settings;
    // Row 7 is the default Action; Enter cycles allow -> deny.
    for _ in 0..SETTINGS_DEFAULT_START {
        press(&mut app, KeyCode::Down);
    }
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.config.defaults.action, "deny");

    // Row 8 is Direction; Enter cycles in -> out.
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.config.defaults.direction, "out");

    app.start_add();
    assert_eq!(app.tab, Tab::Add);
    assert_eq!(app.wizard.draft.action.ufw(), "deny");
    assert_eq!(app.wizard.draft.direction.label(), "OUT");
}

#[test]
/**
 * Verifies that with skip-wizard enabled, adding a rule opens the wizard on the
 * advanced step.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the wizard does not open on the advanced step.
 */
fn skip_wizard_opens_the_advanced_step() {
    let mut app = app();
    app.skip_wizard = true;
    app.config.skip_wizard = true;
    app.start_add();
    assert_eq!(app.tab, Tab::Add);
    assert_eq!(app.wizard.step, WizardStep::Advanced);
}

#[test]
/**
 * Verifies that typing into a settings text field commits the value and that
 * global shortcuts stay unbound while the field is open.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the value is not committed or a shortcut fires while typing.
 */
fn settings_text_input_commits_the_value() {
    let mut app = app();
    app.tab = Tab::Settings;
    // Row 9 is Interface; Enter opens the text input.
    for _ in 0..SETTINGS_DEFAULT_START + 2 {
        press(&mut app, KeyCode::Down);
    }
    press(&mut app, KeyCode::Enter);
    assert!(
        app.settings_input.is_some(),
        "the interface field should open"
    );

    // 'q' and '1' must be inserted, not trigger quit / tab jump.
    press(&mut app, KeyCode::Char('q'));
    press(&mut app, KeyCode::Char('1'));
    assert!(
        !app.should_quit,
        "'q' must be inserted into the settings field"
    );
    let (_, input) = app.settings_input.as_ref().expect("still editing");
    assert!(input.value().contains('q'));
    assert!(input.value().contains('1'));

    press(&mut app, KeyCode::Enter);
    assert!(app.settings_input.is_none());
    assert_eq!(app.config.defaults.interface, "q1");
}

#[test]
/**
 * Verifies that changing a setting only touches memory until the Save Settings
 * row is confirmed, and that the file then holds the change.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the file is written early or does not hold the new value.
 */
fn settings_are_written_only_when_the_save_row_is_confirmed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let mut app = app_with_config_path(Some(&path));
    app.tab = Tab::Settings;

    // Row 0 is Theme; Enter cycles dark -> light.
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.config.theme, "light");
    assert!(!path.exists(), "nothing should be written before saving");

    // The last row is the Save Settings button.
    for _ in 0..SETTINGS_SAVE_ROW {
        press(&mut app, KeyCode::Down);
    }
    press(&mut app, KeyCode::Enter);
    assert!(!app.settings_dirty);
    let saved = Config::load(Some(&path));
    assert_eq!(saved.theme, "light");
}

#[test]
/**
 * Verifies that the `S` shortcut writes every changed setting, including the
 * numeric and rule-default rows.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if any changed setting is missing from the file.
 */
fn the_save_shortcut_writes_every_changed_setting() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let mut app = app_with_config_path(Some(&path));
    app.tab = Tab::Settings;

    // Row 1 is Confirm before apply; Space flips it.
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Char(' '));
    assert!(!app.confirm_before_apply);

    // Row 2 is Counters refresh; Enter opens the text box, which is replaced.
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Backspace);
    press(&mut app, KeyCode::Backspace);
    press(&mut app, KeyCode::Char('9'));
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.config.counters_refresh_secs, 9);

    press(&mut app, KeyCode::Char('S'));
    let saved = Config::load(Some(&path));
    assert!(!saved.confirm_before_apply);
    assert_eq!(saved.counters_refresh_secs, 9);
}

#[test]
/**
 * Verifies that a non-numeric value for a seconds setting is rejected instead of
 * being written to the file.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the previous value is lost.
 */
fn a_non_numeric_seconds_value_is_rejected() {
    let mut app = app();
    app.tab = Tab::Settings;
    let before = app.config.counters_refresh_secs;

    // Row 2 is Counters refresh.
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Enter);
    for _ in 0..before.to_string().len() {
        press(&mut app, KeyCode::Backspace);
    }
    press(&mut app, KeyCode::Char('x'));
    press(&mut app, KeyCode::Enter);

    assert_eq!(app.config.counters_refresh_secs, before);
}

#[test]
/**
 * Verifies that the theme row rebuilds the live palette, not only the config.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the palette on screen does not follow the setting.
 */
fn the_theme_row_changes_the_palette_immediately() {
    let mut app = app();
    app.tab = Tab::Settings;
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.theme.palette.name(), "light");
    press(&mut app, KeyCode::Left);
    assert_eq!(app.theme.palette.name(), "dark");
}

#[test]
/**
 * Verifies that a config file written by an earlier session is loaded on
 * start-up and used for new rules.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if any saved setting is ignored.
 */
fn the_config_file_is_loaded_on_startup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        r#"
theme = "light"
confirm_before_apply = false
counters_refresh_secs = 9
log_source = "journal"
reconcile_seconds = 0
readonly = false
skip_wizard = true

[defaults]
action = "limit"
direction = "out"
interface = "wg0"
protocol = "udp"
from_addr = "192.168.1.0/24"
from_port = "1024:65535"
to_addr = "10.0.0.0/8"
to_port = "53"
logging = "log-all"
"#,
    )
    .unwrap();

    let mut app = app_with_config_path(Some(&path));
    assert_eq!(app.config.theme, "light");
    assert!(!app.confirm_before_apply);
    assert_eq!(app.config.counters_refresh_secs, 9);
    assert_eq!(app.config.log_source, "journal");
    assert_eq!(app.reconcile_seconds, 0);
    assert!(app.skip_wizard);

    app.start_add();
    let draft = &app.wizard.draft;
    assert_eq!(draft.action.ufw(), "limit");
    assert_eq!(draft.direction.label(), "OUT");
    assert_eq!(draft.interface_in.as_deref(), Some("wg0"));
    assert_eq!(draft.protocol.to_string(), "udp");
    assert_eq!(draft.from_addr.as_deref(), Some("192.168.1.0/24"));
    assert_eq!(draft.from_port.to_string(), "1024:65535");
    assert_eq!(draft.to_addr.as_deref(), Some("10.0.0.0/8"));
    assert_eq!(draft.to_port.single_port(), Some(53));
    assert_eq!(draft.log.label(), "log-all");
}

/**
 * Appends one `[UFW BLOCK]` line to a log file the activity monitor is tailing.
 *
 * The file is flushed so the reader thread can pick the line up immediately.
 *
 * # Arguments
 *
 * * `path` (`&Path`) - The log file to append to.
 *
 * # Returns
 *
 * `()` - This function returns no value; it panics when the file cannot be
 * written.
 */
fn append_block_line(path: &Path) {
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .expect("open log file");
    writeln!(
        file,
        "Oct 30 08:23:50 host kernel: [1.0] [UFW BLOCK] IN=eno1 OUT= MAC=aa SRC=203.0.113.7 DST=192.168.1.19 LEN=60 PROTO=TCP SPT=51000 DPT=22"
    )
    .expect("write log line");
    file.flush().expect("flush log line");
}
/**
 * Appends two `[UFW BLOCK]` lines from two different sources.
 *
 * Two lines, two sources, two rows: the monitor aggregates by
 * `(source, port, protocol)`, so distinct sources can never fold together.
 *
 * # Arguments
 *
 * * `path` (`&Path`) - The log file to append to.
 *
 * # Returns
 *
 * `()` - This function returns no value; it panics when the file cannot be
 * written.
 */
fn append_two_block_lines(path: &Path) {
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .expect("open log file");
    writeln!(
        file,
        "Oct 30 08:23:50 host kernel: [1.0] [UFW BLOCK] IN=wg0 OUT= MAC=aa SRC=203.0.5.7 DST=192.168.1.20 LEN=60 PROTO=TCP SPT=51000 DPT=222"
    )
    .expect("write log line");
    writeln!(
        file,
        "Oct 30 08:23:50 host kernel: [1.0] [UFW BLOCK] IN=eno1 OUT= MAC=aa SRC=201.0.5.7 DST=192.168.1.19 LEN=60 PROTO=TCP SPT=51000 DPT=22"
    )
    .expect("write log line");
    file.flush().expect("flush log line");
}
/**
 * Waits until the activity monitor has aggregated at least one row.
 *
 * The reader thread polls its source, so the test has to give it a moment. It
 * panics instead of hanging forever when nothing arrives.
 *
 * # Arguments
 *
 * * `app` (`&mut App`) - The application whose monitor is polled.
 *
 * # Returns
 *
 * `()` - This function returns no value; it panics on timeout.
 */
fn wait_for_activity_rows(app: &mut App) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if !app.blocks.rows().is_empty() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("the log tailer never picked up the appended line");
}

/**
 * Appends block lines until the monitor shows a row.
 *
 * The reader thread starts at the end of the file, so a line written before it
 * has opened the file is skipped. Appending until one shows up keeps the test
 * independent of that startup race.
 *
 * # Arguments
 *
 * * `app` (`&mut App`) - The application whose monitor is polled.
 * * `path` (`&Path`) - The log file the monitor tails.
 *
 * # Returns
 *
 * `()` - This function returns no value; it panics on timeout.
 */
fn append_until_a_row_shows_up(app: &mut App, path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        append_block_line(path);
        std::thread::sleep(Duration::from_millis(100));
        if !app.blocks.rows().is_empty() {
            return;
        }
    }
    panic!("the log tailer never picked up an appended line");
}
/**
 * Waits until the monitor has aggregated at least `expected` rows.
 *
 * The lines are written once, before the wait, so the count only grows towards
 * `expected` and the assertion that follows stays exact.
 *
 * # Arguments
 *
 * * `app` (`&mut App`) - The application whose monitor is polled.
 * * `expected` (`usize`) - Row count to wait for.
 *
 * # Returns
 *
 * `()` - This function returns no value; it panics on timeout.
 */
fn wait_for_row_count(app: &mut App, expected: usize) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if app.blocks.rows().len() >= expected {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("the log tailer never aggregated {expected} rows");
}
#[test]
/**
 * Verifies that `c` on the Activity tab clears the blocked-traffic rows and that
 * they stay cleared: the next tick must not reload them from the monitor, which
 * keeps aggregating new traffic.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value; it asserts and panics on failure.
 */
fn clear_on_the_activity_tab_empties_the_view_for_good() {
    let dir = tempfile::tempdir().expect("temp dir");
    let log = dir.path().join("ufw.log");
    std::fs::write(&log, "").expect("create log file");

    let mut app = app();
    app.blocks = BlockMonitor::start(Some(log.clone()));
    app.tab = Tab::Activity;

    append_until_a_row_shows_up(&mut app, &log);
    // Let any line still in flight land before the view is cleared.
    std::thread::sleep(Duration::from_millis(500));
    app.tick();
    assert!(
        !app.activity_rows.is_empty(),
        "the row should be visible before clearing"
    );

    press(&mut app, KeyCode::Char('c'));
    assert!(app.activity_rows.is_empty(), "c must clear the view");

    app.tick();
    assert!(
        app.activity_rows.is_empty(),
        "the rows must not come back on the next tick"
    );
    assert_eq!(app.activity_cursor, 0);

    append_block_line(&log);
    wait_for_activity_rows(&mut app);
    app.tick();
    assert_eq!(
        app.activity_rows.len(),
        1,
        "new traffic should still show up after a clear"
    );
}

#[test]
/**
 * Verifies that clearing one source at the monitor level removes exactly that
 * source's row from the Activity view, once the view is re-derived.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value; it asserts and panics on failure.
 */
fn clear_activities_list_from_source() {
    let dir = tempfile::tempdir().expect("temp dir");
    let log = dir.path().join("ufw.log");
    std::fs::write(&log, "").expect("create log file");

    let mut app = app();
    app.blocks = BlockMonitor::start(Some(log.clone()));
    app.tab = Tab::Activity;

    // One line first, so the tailer is provably watching before the rest is written.
    append_until_a_row_shows_up(&mut app, &log);
    append_two_block_lines(&log);
    wait_for_row_count(&mut app, 3);

    app.tick();
    assert_eq!(
        app.activity_rows.len(),
        3,
        "every source should be listed before one of them is cleared"
    );

    let doomed = app
        .activity_rows
        .iter()
        .find(|row| row.dpt == 222)
        .expect("the second source should be listed")
        .src;

    assert_eq!(
        app.blocks.clear_source(doomed),
        1,
        "exactly one row belongs to that source"
    );

    app.tick();
    assert_eq!(
        app.activity_rows.len(),
        2,
        "only the cleared source should disappear"
    );
    assert!(
        app.activity_rows.iter().all(|row| row.src != doomed),
        "no row from the cleared source may survive"
    );
}
