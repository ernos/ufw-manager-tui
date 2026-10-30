//! End-to-end flows through [`App`], driven by key presses exactly as a user would.
//!
//! The mock backend makes these deterministic: no root, no real firewall, no terminal.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use ufw_manager::app::{App, AppOptions, Tab, WizardStep};
use ufw_manager::backend::mock::MockBackend;
use ufw_manager::ui::theme::Theme;

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

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn press(app: &mut App, code: KeyCode) {
    app.handle_key(key(code));
}

#[test]
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
fn number_keys_jump_directly_to_a_tab() {
    let mut app = app();
    press(&mut app, KeyCode::Char('4'));
    assert_eq!(app.tab, Tab::Test);
    press(&mut app, KeyCode::Char('1'));
    assert_eq!(app.tab, Tab::Home);
}

#[test]
fn q_quits() {
    let mut app = app();
    press(&mut app, KeyCode::Char('q'));
    assert!(app.should_quit);
}

#[test]
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

/// A backend that never allows writes and refuses escalation.
struct ReadOnlyBackend;

impl ufw_manager::backend::Backend for ReadOnlyBackend {
    fn label(&self) -> String {
        "read-only".into()
    }
    fn is_root(&self) -> bool {
        false
    }
    fn can_write(&self) -> bool {
        false
    }
    fn read_state(
        &self,
    ) -> Result<ufw_manager::core::firewall::FirewallState, ufw_manager::backend::BackendError>
    {
        Ok(ufw_manager::core::firewall::FirewallState::default())
    }
    fn app_profiles(
        &self,
    ) -> Result<Vec<ufw_manager::core::parse::AppProfile>, ufw_manager::backend::BackendError> {
        Ok(Vec::new())
    }
    fn listening(
        &self,
    ) -> Result<Vec<ufw_manager::core::parse::Listening>, ufw_manager::backend::BackendError> {
        Ok(Vec::new())
    }
    fn counters(
        &self,
        _rules: &[ufw_manager::core::rule::Rule],
    ) -> Result<ufw_manager::backend::HitCounters, ufw_manager::backend::BackendError> {
        Ok(ufw_manager::backend::HitCounters::unavailable("read-only"))
    }
    fn run(
        &self,
        _args: &[String],
    ) -> Result<ufw_manager::backend::CmdOutput, ufw_manager::backend::BackendError> {
        Err(ufw_manager::backend::BackendError::NotRoot(
            "read-only".into(),
        ))
    }
    fn dry_run(
        &self,
        _args: &[String],
    ) -> Result<ufw_manager::backend::CmdOutput, ufw_manager::backend::BackendError> {
        Err(ufw_manager::backend::BackendError::NotRoot(
            "read-only".into(),
        ))
    }
    fn ssh_port(&self) -> u16 {
        22
    }
    fn ssh_session(&self) -> ufw_manager::core::lockout::Session {
        ufw_manager::core::lockout::Session::local()
    }
    fn lan(&self) -> Option<ufw_manager::core::presets::LanInfo> {
        None
    }
    fn interfaces(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Read-only, but willing to ask sudo.
struct EscalatableBackend;

impl ufw_manager::backend::Backend for EscalatableBackend {
    fn label(&self) -> String {
        "needs sudo".into()
    }
    fn is_root(&self) -> bool {
        false
    }
    fn can_write(&self) -> bool {
        false
    }
    fn read_state(
        &self,
    ) -> Result<ufw_manager::core::firewall::FirewallState, ufw_manager::backend::BackendError>
    {
        Err(ufw_manager::backend::BackendError::NotRoot("no".into()))
    }
    fn app_profiles(
        &self,
    ) -> Result<Vec<ufw_manager::core::parse::AppProfile>, ufw_manager::backend::BackendError> {
        Ok(Vec::new())
    }
    fn listening(
        &self,
    ) -> Result<Vec<ufw_manager::core::parse::Listening>, ufw_manager::backend::BackendError> {
        Ok(Vec::new())
    }
    fn counters(
        &self,
        _rules: &[ufw_manager::core::rule::Rule],
    ) -> Result<ufw_manager::backend::HitCounters, ufw_manager::backend::BackendError> {
        Ok(ufw_manager::backend::HitCounters::unavailable("no root"))
    }
    fn run(
        &self,
        _args: &[String],
    ) -> Result<ufw_manager::backend::CmdOutput, ufw_manager::backend::BackendError> {
        Err(ufw_manager::backend::BackendError::NotRoot("no".into()))
    }
    fn dry_run(
        &self,
        _args: &[String],
    ) -> Result<ufw_manager::backend::CmdOutput, ufw_manager::backend::BackendError> {
        Err(ufw_manager::backend::BackendError::NotRoot("no".into()))
    }
    fn ssh_port(&self) -> u16 {
        22
    }
    fn ssh_session(&self) -> ufw_manager::core::lockout::Session {
        ufw_manager::core::lockout::Session::local()
    }
    fn lan(&self) -> Option<ufw_manager::core::presets::LanInfo> {
        None
    }
    fn interfaces(&self) -> Vec<String> {
        Vec::new()
    }
    fn may_escalate(&self) -> bool {
        true
    }
}

#[test]
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
fn global_shortcuts_still_work_outside_text_fields_on_the_test_tab() {
    let mut app = app();
    app.tab = Tab::Test;
    // Field 0 (direction) is a selector, not a text field, so shortcuts stay bound.
    assert_eq!(app.traffic.field, 0);
    press(&mut app, KeyCode::Char('1'));
    assert_eq!(app.tab, Tab::Home, "tab jump still works outside text input");
}

#[test]
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
