//! The guided wizard that lives in the Add tab.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, InputField, WizardStep};
use crate::core::command;
use crate::core::explain;
use crate::core::risk::RiskLevel;

/**
 * Draws the Add tab's guided wizard.
 *
 * Lays out the breadcrumb, the current prompt, the list of options and the
 * preview of the rule being built as four stacked regions. When a text field is
 * open, the input dialog is drawn on top of the whole area.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the widgets are rendered into.
 * * `area` (`Rect`) - The screen region reserved for the Add tab.
 * * `app` (`&App`) - The application state supplying the wizard state, the draft, the profiles and the theme.
 *
 * # Returns
 *
 * This function returns no value.
 */
pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(4),
        Constraint::Length(7),
    ])
    .split(area);

    draw_breadcrumb(frame, rows[0], app);

    let cursor_marker = "▸";
    let prompt = format!(" {cursor_marker} {}", app.wizard_prompt());
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            prompt,
            app.theme.text_style().add_modifier(Modifier::BOLD),
        ))),
        rows[1],
    );

    draw_options(frame, rows[2], app);
    draw_preview(frame, rows[3], app);

    if let Some((field, input)) = &app.wizard.input {
        draw_input(frame, area, app, *field, input);
    }
}

/**
 * Draws the wizard breadcrumb.
 *
 * Shows the four numbered steps separated by chevrons, highlighting the current
 * one. An `advanced` marker is appended when the advanced step is active, and an
 * `editing rule #N` note when an existing rule is being edited.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the breadcrumb is rendered into.
 * * `area` (`Rect`) - The single-row region reserved for the breadcrumb.
 * * `app` (`&App`) - The application state supplying the wizard step, the rule being edited and the theme.
 *
 * # Returns
 *
 * This function returns no value.
 */
fn draw_breadcrumb(frame: &mut Frame, area: Rect, app: &App) {
    let steps = [
        (WizardStep::Goal, "1 Goal"),
        (WizardStep::Who, "2 Who"),
        (WizardStep::Service, "3 Service"),
        (WizardStep::Review, "4 Review"),
    ];
    let mut spans = Vec::new();
    for (step, label) in steps {
        let style = if step == app.wizard.step {
            app.theme.selected()
        } else {
            app.theme.dimmed()
        };
        spans.push(Span::styled(format!(" {label} "), style));
        spans.push(Span::styled("›", app.theme.border_style()));
    }
    if app.wizard.step == WizardStep::Advanced {
        spans.push(Span::styled(" advanced ", app.theme.selected()));
    }
    if let Some(number) = app.wizard.editing {
        spans.push(Span::styled(
            format!("   editing rule #{number}"),
            app.theme.risk_style(RiskLevel::Medium),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/**
 * Draws the selectable options for the current wizard step.
 *
 * Each option is shown with a selection marker and its label, plus a hint when
 * one exists; the selected option is highlighted. Any validation error from the
 * wizard is appended in the critical risk style.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the options are rendered into.
 * * `area` (`Rect`) - The region reserved for the option list.
 * * `app` (`&App`) - The application state supplying the wizard step, the options, the selection, the error and the theme.
 *
 * # Returns
 *
 * This function returns no value.
 */
fn draw_options(frame: &mut Frame, area: Rect, app: &App) {
    let block = app.theme.titled(" options ");
    let options = app.wizard_options();
    let mut lines = Vec::new();
    for (index, (label, hint)) in options.iter().enumerate() {
        let selected = index == app.wizard.cursor;
        let style = if selected {
            app.theme.selected()
        } else {
            app.theme.text_style()
        };
        let hint_style = if selected {
            app.theme.selected()
        } else {
            app.theme.dimmed()
        };
        let marker = if selected { "▸" } else { " " };
        lines.push(Line::from(vec![
            Span::styled(format!(" {marker} {label}"), style),
            Span::styled(
                if hint.is_empty() {
                    String::new()
                } else {
                    format!("   {hint}")
                },
                hint_style,
            ),
        ]));
    }
    if let Some(error) = &app.wizard.error {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            format!(" ! {error}"),
            app.theme.risk_style(RiskLevel::Critical),
        )));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

/**
 * Draws the preview of the rule being built.
 *
 * Shows the plain-English explanation of the draft, the `ufw` command that would
 * create it (or why it is not valid yet), the risk badge and summary and, when a
 * simulation has been run, its explanation. On the goal step a short
 * introduction is drawn instead.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the preview is rendered into.
 * * `area` (`Rect`) - The region reserved for the preview.
 * * `app` (`&App`) - The application state supplying the wizard step, the draft, the trace, the profiles and the theme.
 *
 * # Returns
 *
 * This function returns no value.
 */
fn draw_preview(frame: &mut Frame, area: Rect, app: &App) {
    let block = app.theme.titled(" what this will do ");

    if app.wizard.step == WizardStep::Goal {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "  Pick a goal and the rule will be built for you, one step at a time.",
                app.theme.dimmed(),
            )))
            .block(block),
            area,
        );
        return;
    }

    let draft = &app.wizard.draft;
    let mut lines = vec![Line::from(Span::styled(
        format!("  {}", explain::explain_draft(draft)),
        app.theme.text_style(),
    ))];

    match command::rule_args(draft, true) {
        Ok(args) => lines.push(Line::from(Span::styled(
            format!("  {}", command::render_command(&args)),
            app.theme.title(),
        ))),
        Err(error) => lines.push(Line::from(Span::styled(
            format!("  not valid yet: {error}"),
            app.theme.risk_style(RiskLevel::Medium),
        ))),
    }

    let assessment = crate::core::risk::assess_rule(&draft.to_rule(0), &app.profiles);
    lines.push(Line::from(vec![
        Span::styled("  ", app.theme.dimmed()),
        Span::styled(
            app.theme.badge(assessment.level),
            app.theme.risk_style(assessment.level),
        ),
        Span::styled(
            format!(" {}", assessment.summary()),
            app.theme.risk_style(assessment.level),
        ),
    ]));

    if let Some(trace) = &app.wizard.trace {
        lines.push(Line::from(Span::styled(
            format!("  simulation: {}", trace.explanation),
            if trace.allowed() {
                app.theme.risk_style(RiskLevel::Low)
            } else {
                app.theme.risk_style(RiskLevel::High)
            },
        )));
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

/**
 * Returns the prompt shown above a text input for the given field.
 *
 * The label includes an example of the expected format so the user knows what
 * to type.
 *
 * # Arguments
 *
 * * `field` (`InputField`) - The field being edited.
 *
 * # Returns
 *
 * A `&'static str` describing the field and its expected format.
 */
fn field_label(field: InputField) -> &'static str {
    match field {
        InputField::Address => "address or network (e.g. 192.168.1.0/24, 203.0.113.7)",
        InputField::Port => "port (e.g. 22, 8000:8100, 80,443, or an app profile name)",
        InputField::Interface => "interface (e.g. eno1, wlan0, wg0 — empty for any)",
        InputField::Note => "note for this rule",
        InputField::FromAddress => "from address (empty for any)",
        InputField::FromPort => "from port (empty for any)",
        InputField::AdvancedComment => "note for this rule",
    }
}

/**
 * Draws the centred text-input dialog.
 *
 * The dialog is cleared first so the wizard behind it does not show through. It
 * shows the field's label, the value split around a highlighted block cursor,
 * and the accept and cancel key hints.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the dialog is rendered into.
 * * `area` (`Rect`) - The full screen area the dialog is centred within.
 * * `app` (`&App`) - The application state supplying the theme.
 * * `field` (`InputField`) - The field being edited, used for the label.
 * * `input` (`&crate::ui::widgets::TextInput`) - The text being edited.
 *
 * # Returns
 *
 * This function returns no value.
 */
fn draw_input(
    frame: &mut Frame,
    area: Rect,
    app: &App,
    field: InputField,
    input: &crate::ui::widgets::TextInput,
) {
    let rect = crate::ui::widgets::centered_rect(area, 70, 7);
    frame.render_widget(Clear, rect);
    let block = app.theme.titled(" type a value ");
    let (before, at, after) = input.parts();
    let lines = vec![
        Line::from(Span::styled(
            format!("  {}", field_label(field)),
            app.theme.dimmed(),
        )),
        Line::default(),
        Line::from(vec![
            Span::styled("  ", app.theme.text_style()),
            Span::styled(before, app.theme.text_style()),
            Span::styled(at.to_string(), app.theme.selected()),
            Span::styled(after, app.theme.text_style()),
        ]),
        Line::default(),
        Line::from(Span::styled(
            "  ENTER accept    ESC cancel",
            app.theme.dimmed(),
        )),
    ];
    frame.render_widget(Paragraph::new(lines).block(block), rect);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::Tab;
    use crate::ui::render_to_string as render;
    use crate::ui::tests::demo_app;

    #[test]
    /**
     * Checks that starting the wizard switches to the Add tab on the goal step.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test on a wrong tab or step.
     */
    fn the_wizard_opens_on_the_goal_step() {
        let mut app = demo_app();
        app.start_add();
        assert_eq!(app.tab, Tab::Add);
        assert_eq!(app.wizard.step, WizardStep::Goal);
        let output = render(&app, 120, 40);
        assert!(output.contains("What would you like to do"));
    }

    #[test]
    /**
     * Checks that a new draft is prefilled with the local network address.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test on a different value.
     */
    fn the_default_draft_was_prefilled_with_the_local_network() {
        let mut app = demo_app();
        app.start_add();
        assert_eq!(
            app.wizard.draft.from_addr.as_deref(),
            Some("192.168.1.0/24")
        );
    }

    #[test]
    /**
     * Checks that every wizard step renders without panicking.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; a panic fails the test.
     */
    fn every_step_renders() {
        let mut app = demo_app();
        app.start_add();
        for step in [
            WizardStep::Goal,
            WizardStep::Who,
            WizardStep::Service,
            WizardStep::Review,
            WizardStep::Advanced,
        ] {
            app.wizard.step = step;
            let _ = render(&app, 120, 40);
        }
    }

    #[test]
    /**
     * Checks that the text-input dialog renders and shows the typed value.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test when the value is not
     * drawn.
     */
    fn an_open_text_input_renders_without_panicking() {
        let mut app = demo_app();
        app.start_add();
        app.wizard.input = Some((
            InputField::Address,
            crate::ui::widgets::TextInput::new("10.0.0.0/8"),
        ));
        let output = render(&app, 120, 40);
        assert!(output.contains("10.0.0.0/8"));
    }
}
