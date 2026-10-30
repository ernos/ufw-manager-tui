//! Activity: live blocked traffic, plus what this session changed.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table};
use ratatui::Frame;

use crate::app::App;
use crate::core::risk::RiskLevel;
use crate::core::util;

/**
 * Draws the Activity tab: the blocked-traffic table on top and the journal of
 * this session's changes underneath.
 *
 * The area is split vertically into a flexible table region and a fixed
 * eight-row journal region, and both are rendered into the frame's buffer.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the widgets are rendered into.
 * * `area` (`Rect`) - The screen region reserved for the Activity tab.
 * * `app` (`&App`) - The application state supplying the blocked rows, the
 *   journal, the theme and the current selection.
 *
 * # Returns
 *
 * This function returns no value.
 */
pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let rows = Layout::vertical([Constraint::Min(5), Constraint::Length(8)]).split(area);
    draw_blocks(frame, rows[0], app);
    draw_journal(frame, rows[1], app);
}

/**
 * Draws the table of recently blocked traffic.
 *
 * The panel title reports the log source and whether capture is live or
 * paused. Each row shows the hit count, age, source, port, protocol,
 * interface and a short verdict hint, and the selected row is highlighted.
 * When there are no rows an explanatory paragraph is drawn instead, which
 * mentions that ufw logging is off when that is the reason.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the table is rendered into.
 * * `area` (`Rect`) - The region reserved for the blocked-traffic table.
 * * `app` (`&App`) - The application state supplying the rows, the cursor, the
 *   theme and the current log level.
 *
 * # Returns
 *
 * This function returns no value.
 */
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

/**
 * Returns a short, human-readable guess at what a blocked connection was
 * trying to do, based on its destination port.
 *
 * # Arguments
 *
 * * `port` (`u16`) - The destination port of the blocked connection.
 *
 * # Returns
 *
 * A `String` such as `"SSH probing"` or `"web scanning"`; ports that are not
 * recognized fall back to `"connection attempt"`.
 */
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

/**
 * Draws the journal of changes made during this session.
 *
 * The panel title shows how many entries exist and reminds the user that `u`
 * undoes them. Entries are listed newest first, limited to the rows that fit
 * in `area`, and entries that cannot be undone are annotated in the danger
 * colour. An explanatory paragraph is drawn when the journal is empty.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the journal is rendered into.
 * * `area` (`Rect`) - The region reserved for the journal.
 * * `app` (`&App`) - The application state supplying the journal and the theme.
 *
 * # Returns
 *
 * This function returns no value.
 */
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
