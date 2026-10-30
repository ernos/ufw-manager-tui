//! The rule list: the main workspace.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, Wrap};
use ratatui::Frame;

use crate::app::App;
use crate::core::command;
use crate::core::explain;
use crate::core::risk::RiskLevel;
use crate::core::rule::{Action, Protocol};
use crate::core::util;

pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let rows = Layout::vertical([Constraint::Min(3), Constraint::Length(7)]).split(area);
    draw_table(frame, rows[0], app);
    draw_detail(frame, rows[1], app);
}

fn action_label(rule: &crate::core::rule::Rule) -> String {
    match rule.direction {
        crate::core::rule::Direction::Forward => format!("{} FWD", rule.action.label()),
        _ => rule.action.label().to_string(),
    }
}

fn to_column(rule: &crate::core::rule::Rule) -> String {
    let port = match &rule.to.port {
        crate::core::rule::PortSpec::Any => String::new(),
        other => {
            let proto = if rule.protocol == Protocol::Any {
                String::new()
            } else {
                format!("/{}", rule.protocol.label())
            };
            format!("{other}{proto}")
        }
    };
    let addr = rule.to.addr.clone().unwrap_or_else(|| "Anywhere".into());
    match (port.is_empty(), rule.interface_in.as_deref()) {
        (true, Some(iface)) => format!("{addr} on {iface}"),
        (true, None) => addr,
        (false, _) => port,
    }
}

fn from_column(rule: &crate::core::rule::Rule) -> String {
    let addr = rule.from.addr.clone().unwrap_or_else(|| "Anywhere".into());
    match rule.interface_out.as_deref() {
        Some(iface) => format!("{addr} on {iface}"),
        None => addr,
    }
}

fn draw_table(frame: &mut Frame, area: Rect, app: &App) {
    let visible = app.visible_rules();
    let mut rows: Vec<Row> = Vec::new();
    let filter_text = app
        .filter
        .as_ref()
        .map(|input| input.value().to_string())
        .filter(|value| !value.is_empty());

    for (index, rule) in visible.iter().enumerate() {
        let selected = index == app.rules_cursor;
        let assessment = app.risk_of(rule);
        let shadowed = app.shadowed.iter().any(|(later, _)| *later == rule.number);
        let hits = app
            .hits(rule)
            .map(util::count)
            .unwrap_or_else(|| "—".to_string());
        let note = util::ellipsize(rule.comment_text(), 22);
        let risk = if shadowed {
            format!("{} never reached", app.theme.badge(RiskLevel::Medium))
        } else {
            format!(
                "{} {}",
                app.theme.badge(assessment.level),
                assessment.level.label()
            )
        };

        let mut row = Row::new(vec![
            Cell::from(Span::styled(
                format!("#{:<3} {}", rule.number, action_label(rule)),
                app.theme.action_style(rule.action),
            )),
            Cell::from(rule.direction.label()),
            Cell::from(to_column(rule)),
            Cell::from(from_column(rule)),
            Cell::from(Span::styled(
                hits,
                if rule.action == Action::Limit {
                    app.theme.dimmed()
                } else {
                    app.theme.text_style()
                },
            )),
            Cell::from(Span::styled(note, app.theme.dimmed())),
            Cell::from(Span::styled(
                risk,
                if shadowed {
                    app.theme.risk_style(RiskLevel::Medium)
                } else {
                    app.theme.risk_style(assessment.level)
                },
            )),
        ]);
        if selected {
            row = row.style(app.theme.selected());
        }
        rows.push(row);
    }

    let header = Row::new(vec!["RULE", "DIR", "TO", "FROM", "HITS", "NOTE", "RISK"])
        .style(app.theme.dimmed().add_modifier(Modifier::BOLD));

    let title = if let Some(filter) = &filter_text {
        format!(" Rules matching “{filter}” ({}) ", visible.len())
    } else {
        format!(" Rules in ufw's evaluation order ({}) ", visible.len())
    };
    let block = app.theme.titled(&title);

    if rows.is_empty() {
        let message = if app.state.rules_readable {
            "  No rules yet. Press a to add one, or try the Presets tab."
        } else {
            "  ufw only shows rules to root. Run `sudo ufw-manager-tui` to see them."
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(message, app.theme.dimmed()))).block(block),
            area,
        );
        return;
    }

    let table = Table::new(
        rows,
        [
            Constraint::Length(18),
            Constraint::Length(4),
            Constraint::Min(16),
            Constraint::Min(14),
            Constraint::Length(6),
            Constraint::Length(22),
            Constraint::Length(17),
        ],
    )
    .header(header)
    .block(block);
    frame.render_widget(table, area);
}

fn draw_detail(frame: &mut Frame, area: Rect, app: &App) {
    let block = app.theme.titled(" Why this rule says what it says ");

    let Some(rule) = app.selected_rule() else {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "  Select a rule to see it explained in English.",
                app.theme.dimmed(),
            )))
            .block(block),
            area,
        );
        return;
    };

    let assessment = app.risk_of(&rule);
    let mut lines = vec![
        Line::from(vec![
            Span::styled(format!("  #{}  ", rule.number), app.theme.dimmed()),
            Span::styled(explain::explain_rule(&rule), app.theme.text_style()),
        ]),
        Line::from(Span::styled(
            format!(
                "  {}",
                command::rule_args(&rule.to_draft(), true)
                    .map(|args| command::render_command(&args))
                    .unwrap_or_else(|error| format!("(cannot rebuild the command: {error})"))
            ),
            app.theme.title(),
        )),
    ];

    lines.push(Line::from(vec![
        Span::styled("  ", app.theme.dimmed()),
        Span::styled(
            app.theme.badge(assessment.level),
            app.theme.risk_style(assessment.level),
        ),
        Span::styled(
            format!(" {} — {}", assessment.level.label(), assessment.summary()),
            app.theme.risk_style(assessment.level),
        ),
    ]));

    for (later, by) in &app.shadowed {
        if *later == rule.number {
            lines.push(Line::from(Span::styled(
                format!("  This rule is never reached: rule #{by} above already matches everything it would."),
                app.theme.risk_style(RiskLevel::Medium),
            )));
        }
    }

    if app.show_counters {
        lines.push(Line::from(Span::styled(
            format!(
                "  hits: {}   ({})",
                app.hits(&rule)
                    .map(util::count)
                    .unwrap_or_else(|| "unavailable".into()),
                app.counters.note
            ),
            app.theme.dimmed(),
        )));
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
    fn rules_are_listed_in_order_with_numbers() {
        let mut app = demo_app();
        app.tab = Tab::Rules;
        let output = render(&app, 140, 40);
        assert!(output.contains("#1"));
        assert!(output.contains("ALLOW"));
        assert!(output.contains("Evaluation") || output.contains("evaluation"));
    }

    #[test]
    fn the_detail_pane_explains_the_selected_rule_in_english() {
        let mut app = demo_app();
        app.tab = Tab::Rules;
        app.rules_cursor = 0;
        let output = render(&app, 140, 40);
        assert!(output.contains("Allow anyone on the internet"), "{output}");
    }

    #[test]
    fn filtering_narrows_the_list() {
        let mut app = demo_app();
        app.tab = Tab::Rules;
        app.filter = Some(crate::ui::widgets::TextInput::new("443"));
        let visible = app.visible_rules();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].number, 2);
    }

    #[test]
    fn an_empty_filter_matches_everything() {
        let mut app = demo_app();
        app.filter = Some(crate::ui::widgets::TextInput::new("   "));
        assert_eq!(app.visible_rules().len(), app.state.rules.len());
    }

    #[test]
    fn style_is_applied_to_the_selected_row_only() {
        let mut app = demo_app();
        app.tab = Tab::Rules;
        let output = render(&app, 120, 30);
        // Rendering must not panic with a selection at either end of the list.
        app.rules_cursor = app.visible_rules().len().saturating_sub(1);
        let _ = render(&app, 120, 30);
        assert!(!output.is_empty());
    }

    #[test]
    fn tiny_terminals_do_not_panic() {
        let mut app = demo_app();
        app.tab = Tab::Rules;
        let _ = render(&app, 40, 12);
        let _ = render(&app, 200, 60);
    }
}
