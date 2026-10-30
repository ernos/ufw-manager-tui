//! Home: is the firewall on, how exposed is this machine, and what should I fix?

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table};
use ratatui::Frame;

use crate::app::App;
use crate::core::firewall::LogLevel;
use crate::core::risk::{assess_rule, RiskLevel};

pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    if area.height < 20 {
        let rows = Layout::vertical([Constraint::Length(9), Constraint::Min(3)]).split(area);
        draw_summary(frame, rows[0], app);
        draw_suggestions(frame, rows[1], app);
        return;
    }
    let rows = Layout::vertical([
        Constraint::Length(9),
        Constraint::Min(5),
        Constraint::Min(5),
    ])
    .split(area);
    draw_summary(frame, rows[0], app);
    draw_suggestions(frame, rows[1], app);
    draw_services(frame, rows[2], app);
}

fn kv<'a>(label: &'a str, value: String, style: Style) -> Line<'a> {
    Line::from(vec![
        Span::styled(
            format!("  {label:<18}"),
            Style::new().fg(ratatui::style::Color::Reset),
        ),
        Span::styled(value, style),
    ])
}

fn draw_summary(frame: &mut Frame, area: Rect, app: &App) {
    let mut lines = Vec::new();

    if app.state.rules_readable {
        let (dot, text, colour) = if app.state.enabled {
            ("●", "ON", app.theme.ok)
        } else {
            ("●", "OFF — nothing is being filtered", app.theme.danger)
        };
        lines.push(Line::from(vec![
            Span::styled(
                "  FIREWALL          ",
                Style::new().fg(ratatui::style::Color::Reset),
            ),
            Span::styled(dot, Style::new().fg(colour)),
            Span::styled(
                format!(" {text}"),
                Style::new().fg(colour).add_modifier(Modifier::BOLD),
            ),
        ]));
    } else {
        lines.push(Line::from(Span::styled(
            "  FIREWALL          unknown — rules are hidden without root",
            app.theme.dimmed(),
        )));
    }

    let policy_style = |permits: bool| {
        if permits {
            app.theme.risk_style(RiskLevel::Critical)
        } else {
            app.theme.text_style()
        }
    };
    lines.push(kv(
        "Default incoming",
        app.state.default_incoming.label().to_string(),
        policy_style(app.state.default_incoming.permits()),
    ));
    lines.push(kv(
        "Default outgoing",
        app.state.default_outgoing.label().to_string(),
        app.theme.text_style(),
    ));
    lines.push(kv(
        "Routed",
        app.state.default_routed.label().to_string(),
        app.theme.dimmed(),
    ));

    let log_style = if app.state.log_level == LogLevel::Off {
        app.theme.risk_style(RiskLevel::Medium)
    } else {
        app.theme.text_style()
    };
    lines.push(kv(
        "Logging",
        app.state.log_level.label().to_string(),
        log_style,
    ));

    let open = app
        .state
        .incoming_rules()
        .filter(|rule| assess_rule(rule, &app.profiles).level >= RiskLevel::High)
        .count();
    lines.push(kv(
        "Rules",
        format!(
            "{} total, {} open to the internet",
            app.state.rule_count(),
            open
        ),
        if open > 0 {
            app.theme.risk_style(RiskLevel::High)
        } else {
            app.theme.text_style()
        },
    ));

    let ssh_reach = match app.state.permitting_rule(app.ssh_port, None) {
        Some(rule) => {
            let assessment = assess_rule(rule, &app.profiles);
            (
                format!(
                    "reachable from {}",
                    rule.from.addr.clone().unwrap_or_else(|| "Anywhere".into())
                ),
                assessment.level,
            )
        }
        None if app.state.enabled => ("not reachable".to_string(), RiskLevel::Info),
        None => ("reachable (firewall off)".to_string(), RiskLevel::Critical),
    };
    lines.push(Line::from(vec![
        Span::styled(
            format!("  SSH (port {})       ", app.ssh_port),
            Style::new().fg(ratatui::style::Color::Reset),
        ),
        Span::styled(
            format!("{} {}", app.theme.badge(ssh_reach.1), ssh_reach.0),
            app.theme.risk_style(ssh_reach.1),
        ),
    ]));

    if !app.counters.note.is_empty() && app.show_counters {
        lines.push(Line::from(Span::styled(
            format!("  counters: {}", app.counters.note),
            app.theme.dimmed(),
        )));
    }

    frame.render_widget(Paragraph::new(lines), area);
}

fn draw_suggestions(frame: &mut Frame, area: Rect, app: &App) {
    let block = app.theme.titled(" What to fix ");
    let inner_width = area.width.saturating_sub(4) as usize;

    if app.suggestions.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "  Nothing obvious to fix. Your firewall looks reasonable.",
                app.theme.dimmed(),
            )))
            .block(block),
            area,
        );
        return;
    }

    let mut lines = Vec::new();
    for (index, suggestion) in app.suggestions.iter().enumerate() {
        let selected = index == app.home_cursor;
        let base = if selected {
            app.theme.selected()
        } else {
            app.theme.risk_style(suggestion.level)
        };
        let prefix = format!(" {} ", app.theme.badge(suggestion.level));
        let fix = if suggestion.fix.is_some() {
            "  [FIX]"
        } else {
            ""
        };
        let text = format!("{prefix}{}{fix}", suggestion.text);
        for (line_index, chunk) in crate::ui::wrap_text(&text, inner_width)
            .into_iter()
            .enumerate()
        {
            let content = if line_index == 0 {
                chunk
            } else {
                format!("    {chunk}")
            };
            lines.push(Line::from(Span::styled(content, base)));
        }
    }
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_services(frame: &mut Frame, area: Rect, app: &App) {
    let mut rows: Vec<Row> = Vec::new();

    for socket in app.listening.iter().filter(|socket| !socket.is_loopback()) {
        let reachable = if socket.is_wildcard() {
            match app.state.permitting_rule(socket.port, None) {
                Some(rule) => {
                    let assessment = assess_rule(rule, &app.profiles);
                    (
                        rule.from.addr.clone().unwrap_or_else(|| "Anywhere".into()),
                        assessment.level,
                        format!("#{}", rule.number),
                    )
                }
                None => {
                    if app.state.default_incoming.permits() {
                        ("Anywhere".into(), RiskLevel::High, "no rule".to_string())
                    } else {
                        (
                            "nowhere".into(),
                            RiskLevel::Info,
                            "default denies".to_string(),
                        )
                    }
                }
            }
        } else {
            ("this address".into(), RiskLevel::Low, String::new())
        };

        rows.push(Row::new(vec![
            Cell::from(socket.port.to_string()),
            Cell::from(socket.proto.clone()),
            Cell::from(socket.process.clone().unwrap_or_else(|| "?".into())),
            Cell::from(reachable.0),
            Cell::from(reachable.2),
            Cell::from(Span::styled(
                format!("{} {}", app.theme.badge(reachable.1), reachable.1.label()),
                app.theme.risk_style(reachable.1),
            )),
        ]));
    }

    let header = Row::new(vec![
        "PORT",
        "PROTO",
        "SERVICE",
        "REACHABLE FROM",
        "RULE",
        "RISK",
    ])
    .style(app.theme.dimmed().add_modifier(Modifier::BOLD));

    let block = app.theme.titled(" Services & exposure ");

    if rows.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "  Nothing is listening on a network address.",
                app.theme.dimmed(),
            )))
            .block(block),
            area,
        );
        return;
    }

    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(12),
            Constraint::Min(16),
            Constraint::Length(10),
            Constraint::Length(16),
        ],
    )
    .header(header)
    .block(block);
    frame.render_widget(table, area);
}

#[cfg(test)]
mod tests {
    use crate::app::Tab;
    use crate::ui::render_to_string as render;
    use crate::ui::tests::demo_app;

    #[test]
    fn home_renders_the_firewall_state() {
        let mut app = demo_app();
        app.tab = Tab::Home;
        let output = render(&app, 120, 40);
        assert!(output.contains("FIREWALL"));
        assert!(output.contains("What to fix"));
    }

    #[test]
    fn the_demo_ruleset_produces_actionable_advice() {
        let app = demo_app();
        assert!(!app.suggestions.is_empty());
        assert!(
            app.suggestions.iter().any(|s| s.text.contains("SSH")),
            "expected an SSH suggestion, got {:?}",
            app.suggestions
                .iter()
                .map(|s| s.text.clone())
                .collect::<Vec<_>>()
        );
    }
}
