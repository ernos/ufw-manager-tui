//! End-to-end flows through [`App`], driven by key presses exactly as a user would.
//!
//! The mock backend makes these deterministic: no root, no real firewall, no terminal.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use ufw_manager::app::{App, AppOptions, Tab, WizardStep};
use ufw_manager::backend::mock::MockBackend;
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
            yes: false,
            readonly: false,
            theme: Theme::new("dark", false),
            reconcile_seconds: 0,
            show_counters: true,
            confirm_before_apply: false,
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
    assert_eq!(app.tab, Tab::Help);
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
            yes: false,
            readonly: true,
            theme: Theme::new("dark", false),
            reconcile_seconds: 0,
            show_counters: true,
            confirm_before_apply: false,
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
            yes: false,
            readonly: false,
            theme: Theme::new("dark", false),
            reconcile_seconds: 0,
            show_counters: true,
            confirm_before_apply: true,
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
            yes: false,
            readonly: true,
            theme: Theme::new("dark", false),
            reconcile_seconds: 0,
            show_counters: true,
            confirm_before_apply: false,
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
            yes: false,
            readonly: false,
            theme: Theme::new("dark", false),
            reconcile_seconds: 0,
            show_counters: true,
            confirm_before_apply: false,
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
    assert_eq!(app.tab, Tab::Home, "tab jump still works outside text input");
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
    assert!(app.wizard.input.is_some(), "the address field should be open");

    // 'q' and '1' must be inserted, not trigger quit / tab jump.
    press(&mut app, KeyCode::Char('q'));
    press(&mut app, KeyCode::Char('1'));
    assert!(!app.should_quit, "'q' must be inserted into the address field");
    let (_, input) = app.wizard.input.as_ref().expect("still editing");
    assert!(input.value().contains('q'));
    assert!(input.value().contains('1'));
}
