//! The traffic simulator screen.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, TRAFFIC_PROTOCOLS};
use crate::core::risk::RiskLevel;
use crate::core::simulate::StepOwner;

/**
 * Draws the Test tab: the pretend-traffic form, the verdict and the decision
 * trace.
 *
 * The area is split into a seven-row form, a three-row verdict and a flexible
 * trace region.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the widgets are rendered into.
 * * `area` (`Rect`) - The screen region reserved for the Test tab.
 * * `app` (`&App`) - The application state supplying the traffic form, the last
 *   trace and the theme.
 *
 * # Returns
 *
 * This function returns no value.
 */
pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let rows = Layout::vertical([
        Constraint::Length(7),
        Constraint::Length(3),
        Constraint::Min(4),
    ])
    .split(area);
    draw_form(frame, rows[0], app);
    draw_verdict(frame, rows[1], app);
    draw_trace(frame, rows[2], app);
}

/**
 * Returns the style for one form field.
 *
 * The field currently being edited uses the selected style; every other field
 * uses the normal text style.
 *
 * # Arguments
 *
 * * `app` (`&App`) - The application state holding the traffic form and theme.
 * * `index` (`usize`) - The zero-based index of the field to style.
 *
 * # Returns
 *
 * The `ratatui::style::Style` to draw the field with.
 */
fn field_style(app: &App, index: usize) -> ratatui::style::Style {
    if app.traffic.field == index {
        app.theme.selected()
    } else {
        app.theme.text_style()
    }
}

/**
 * Builds the display span for one text-input field.
 *
 * When the field is being edited the value is split around the cursor so the
 * character under it can be drawn as a block cursor; otherwise the plain value
 * is shown. Either way the span carries the field's style.
 *
 * # Arguments
 *
 * * `app` (`&App`) - The application state holding the traffic form and theme.
 * * `index` (`usize`) - The zero-based index of the field in the form.
 * * `input` (`&crate::ui::widgets::TextInput`) - The text input to display.
 *
 * # Returns
 *
 * A `Span<'static>` containing the styled field text.
 */
fn input_span(app: &App, index: usize, input: &crate::ui::widgets::TextInput) -> Span<'static> {
    let style = field_style(app, index);
    if app.traffic.field == index {
        let (before, at, after) = input.parts();
        Span::styled(format!("{before}{at}{after}"), style)
    } else {
        Span::styled(input.value().to_string(), style)
    }
}

/**
 * Draws the pretend-traffic form.
 *
 * Shows the direction and protocol selectors, the interface the packet would
 * travel over, the source and destination address and port inputs, and a line
 * of key hints. The field currently being edited is highlighted.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the form is rendered into.
 * * `area` (`Rect`) - The region reserved for the form.
 * * `app` (`&App`) - The application state supplying the traffic form, the LAN
 *   interface and the theme.
 *
 * # Returns
 *
 * This function returns no value.
 */
fn draw_form(frame: &mut Frame, area: Rect, app: &App) {
    let block = app.theme.titled(" pretend traffic ");

    let direction = if app.traffic.direction == 0 {
        "Incoming"
    } else {
        "Outgoing"
    };
    let protocol = TRAFFIC_PROTOCOLS
        .get(app.traffic.protocol)
        .map(|p| p.label().to_uppercase())
        .unwrap_or_else(|| "TCP".into());

    let lines = vec![
        Line::from(vec![
            Span::styled("  Direction  ", app.theme.dimmed()),
            Span::styled(format!("◀ {direction} ▶"), field_style(app, 0)),
            Span::styled("      Protocol  ", app.theme.dimmed()),
            Span::styled(format!("◀ {protocol} ▶"), field_style(app, 1)),
            Span::styled(
                format!(
                    "      via {}",
                    app.lan
                        .as_ref()
                        .map(|l| l.iface.clone())
                        .unwrap_or_else(|| "any interface".into())
                ),
                app.theme.dimmed(),
            ),
        ]),
        Line::default(),
        Line::from(vec![
            Span::styled("  From  ", app.theme.dimmed()),
            input_span(app, 2, &app.traffic.src),
            Span::styled(" : ", app.theme.dimmed()),
            input_span(app, 3, &app.traffic.src_port),
            Span::styled("        To  ", app.theme.dimmed()),
            input_span(app, 4, &app.traffic.dst),
            Span::styled(" : ", app.theme.dimmed()),
            input_span(app, 5, &app.traffic.dst_port),
        ]),
        Line::default(),
        Line::from(Span::styled(
            "  TAB next field   ENTER simulate   ◀ ▶ change direction or protocol",
            app.theme.dimmed(),
        )),
    ];
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/**
 * Draws the simulation verdict.
 *
 * Shows `ALLOWED` or `BLOCKED` in the matching risk style followed by the
 * trace's explanation. When no simulation has been run yet, a prompt explaining
 * that nothing is transmitted is drawn instead.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the verdict is rendered into.
 * * `area` (`Rect`) - The region reserved for the verdict.
 * * `app` (`&App`) - The application state supplying the last trace and theme.
 *
 * # Returns
 *
 * This function returns no value.
 */
fn draw_verdict(frame: &mut Frame, area: Rect, app: &App) {
    let block = app.theme.titled(" result ");

    let Some(trace) = &app.trace else {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "  Press ENTER to send a pretend packet. Nothing is transmitted.",
                app.theme.dimmed(),
            )))
            .block(block),
            area,
        );
        return;
    };

    let verdict = if trace.allowed() {
        "ALLOWED"
    } else {
        "BLOCKED"
    };
    let level = if trace.allowed() {
        RiskLevel::Low
    } else {
        RiskLevel::Critical
    };
    let lines = vec![Line::from(vec![
        Span::styled(
            format!("  {verdict}  "),
            app.theme.risk_style(level).add_modifier(Modifier::BOLD),
        ),
        Span::styled(trace.explanation.clone(), app.theme.text_style()),
    ])];
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

/**
 * Draws the ordered trace of how the packet was evaluated.
 *
 * Each step shows its position, its owner (built-in, pending draft, rule number
 * or default policy), the action, an ellipsized label and a `MATCHED` marker;
 * evaluation stops at the first match. Steps that did not match are dropped once
 * the pane is full. Any notes from the trace are appended as wrapped paragraphs.
 * A short explanation is drawn when no trace exists yet.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the trace is rendered into.
 * * `area` (`Rect`) - The region reserved for the trace.
 * * `app` (`&App`) - The application state supplying the last trace and theme.
 *
 * # Returns
 *
 * This function returns no value.
 */
fn draw_trace(frame: &mut Frame, area: Rect, app: &App) {
    let block = app.theme.titled(" how the decision was made, in order ");

    let Some(trace) = &app.trace else {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "  The trace shows every rule that was considered.",
                app.theme.dimmed(),
            )))
            .block(block),
            area,
        );
        return;
    };

    let mut lines = Vec::new();
    for (index, step) in trace.steps.iter().enumerate() {
        if lines.len() as u16 > area.height.saturating_sub(3) && !step.matched {
            continue;
        }
        let source = match step.owner {
            StepOwner::Builtin(_) => "built-in".to_string(),
            // Rule number 0 means "not applied yet", i.e. the draft being tested.
            StepOwner::Rule(0) => "pending".to_string(),
            StepOwner::Rule(number) => format!("#{number}"),
            StepOwner::Default => "default".to_string(),
        };
        let marker = if step.matched { "MATCHED" } else { "       " };
        let style = if step.shadowed {
            app.theme.risk_style(RiskLevel::Medium)
        } else if step.matched {
            app.theme.risk_style(if step.action.permits() {
                RiskLevel::Low
            } else {
                RiskLevel::High
            })
        } else {
            app.theme.dimmed()
        };
        lines.push(Line::from(Span::styled(
            format!(
                "  {:>2}  {:<8} {:<8} {:<44} {marker}",
                index + 1,
                source,
                step.action.label(),
                crate::core::util::ellipsize(&step.label, 44)
            ),
            style,
        )));
        if step.matched {
            lines.push(Line::from(Span::styled(
                "      ↑ evaluation stops here",
                app.theme.dimmed(),
            )));
            break;
        }
    }

    for note in &trace.notes {
        lines.push(Line::default());
        for chunk in crate::ui::wrap_text(note, area.width.saturating_sub(4) as usize) {
            lines.push(Line::from(Span::styled(
                format!("  {chunk}"),
                app.theme.risk_style(RiskLevel::Medium),
            )));
        }
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

#[cfg(test)]
mod tests {
    use crate::app::Tab;
    use crate::ui::render_to_string as render;
    use crate::ui::tests::demo_app;

    #[test]
    /**
     * Checks that a packet matching an allow rule is reported as allowed.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test when the verdict is
     * missing.
     */
    fn the_simulator_explains_an_allowed_packet() {
        let mut app = demo_app();
        app.tab = Tab::Test;
        app.traffic.dst_port.set("22");
        app.traffic.src.set("203.0.113.9");
        app.run_simulation();
        let output = render(&app, 140, 40);
        assert!(output.contains("ALLOWED"), "{output}");
    }

    #[test]
    /**
     * Checks that a packet matching no allow rule is reported as blocked.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test when the verdict is
     * missing.
     */
    fn the_simulator_explains_a_blocked_packet() {
        let mut app = demo_app();
        app.tab = Tab::Test;
        app.traffic.dst_port.set("9999");
        app.traffic.src.set("203.0.113.9");
        app.run_simulation();
        let output = render(&app, 140, 40);
        assert!(output.contains("BLOCKED"), "{output}");
    }

    #[test]
    /**
     * Checks that an unparseable source address produces an error instead of a
     * panic.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test when parsing succeeds.
     */
    fn an_invalid_address_is_reported_rather_than_panicking() {
        let mut app = demo_app();
        app.tab = Tab::Test;
        app.traffic.src.set("not an ip");
        assert!(app.build_packet().is_err());
    }
}
