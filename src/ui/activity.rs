//! Activity: live blocked traffic, plus what this session changed.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table};
use ratatui::Frame;

use crate::app::App;
use crate::core::risk::RiskLevel;
use crate::core::util;

pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let rows = Layout::vertical([Constraint::Min(5), Constraint::Length(8)]).split(area);
    draw_blocks(frame, rows[0], app);
    draw_journal(frame, rows[1], app);
}

fn draw_blocks(frame: &mut Frame, area: Rect, app: &App) {
    let title = format!(
        " blocked traffic — {} ({}) ",
        app.blocks.source(),
        if app.paused { "paused" } else { "live" }
    );
    let block = app.theme.titled(&title);

    let mut rows = Vec::new();
    for (index, row) in app.activity_rows.iter().enumerate() {
        let selected = index == app.activity_cursor;
        let mut line = Row::new(vec![
            Cell::from(util::count(row.count)),
            Cell::from(util::ago(row.age().as_secs())),
            Cell::from(row.src.to_string()),
            Cell::from(row.dpt.to_string()),
            Cell::from(row.proto.clone()),
            Cell::from(row.iface.clone()),
            Cell::from(Span::styled(
                format!(
                    "{} {}",
                    app.theme.badge(RiskLevel::High),
                    verdict_hint(row.dpt)
                ),
                app.theme.risk_style(RiskLevel::High),
            )),
        ]);
        if selected {
            line = line.style(app.theme.selected());
        }
        rows.push(line);
    }

    if rows.is_empty() {
        let message = if app.state.log_level == crate::core::firewall::LogLevel::Off {
            "  Nothing here: ufw logging is off. Press L on the Home tab to turn it on."
        } else {
            "  Nothing blocked recently. That is usually good news."
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(message, app.theme.dimmed()))).block(block),
            area,
        );
        return;
    }

    let header = Row::new(vec![
        "COUNT", "LAST", "SOURCE", "PORT", "PROTO", "IFACE", "WHAT",
    ])
    .style(app.theme.dimmed().add_modifier(Modifier::BOLD));
    let table = Table::new(
        rows,
        [
            Constraint::Length(7),
            Constraint::Length(9),
            Constraint::Min(16),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(8),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .block(block);
    frame.render_widget(table, area);
}

fn verdict_hint(port: u16) -> String {
    match port {
        22 | 2222 => "SSH probing".to_string(),
        23 => "Telnet scanning".to_string(),
        445 | 139 => "SMB scanning".to_string(),
        3306 => "database probing".to_string(),
        3389 => "remote desktop probing".to_string(),
        80 | 8080 | 443 | 8443 => "web scanning".to_string(),
        _ => "connection attempt".to_string(),
    }
}

fn draw_journal(frame: &mut Frame, area: Rect, app: &App) {
    let block = app.theme.titled(&format!(
        " what this session changed ({}) — u to undo ",
        app.journal.len()
    ));

    if app.journal.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "  No changes yet. Everything you apply is listed here and can be undone.",
                app.theme.dimmed(),
            )))
            .block(block),
            area,
        );
        return;
    }

    let mut lines = Vec::new();
    for entry in app.journal.recent(area.height.saturating_sub(2) as usize) {
        let undoable = if entry.can_undo() {
            ""
        } else {
            "  (cannot be undone)"
        };
        lines.push(Line::from(vec![
            Span::styled(format!("  {} ", entry.at), app.theme.dimmed()),
            Span::styled(entry.description.clone(), app.theme.text_style()),
            Span::styled(undoable.to_string(), Style::new().fg(app.theme.danger)),
        ]));
    }
    frame.render_widget(Paragraph::new(lines).block(block), area);
}
