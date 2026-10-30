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
    fn the_wizard_opens_on_the_goal_step() {
        let mut app = demo_app();
        app.start_add();
        assert_eq!(app.tab, Tab::Add);
        assert_eq!(app.wizard.step, WizardStep::Goal);
        let output = render(&app, 120, 40);
        assert!(output.contains("What would you like to do"));
    }

    #[test]
    fn the_default_draft_was_prefilled_with_the_local_network() {
        let mut app = demo_app();
        app.start_add();
        assert_eq!(
            app.wizard.draft.from_addr.as_deref(),
            Some("192.168.1.0/24")
        );
    }

    #[test]
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
