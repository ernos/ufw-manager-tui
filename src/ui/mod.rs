//! Rendering. Layout only — every decision has already been made in [`crate::app`].

pub mod activity;
pub mod help;
pub mod home;
pub mod keys;
pub mod presets;
pub mod rules;
pub mod test;
pub mod theme;
pub mod widgets;
pub mod wizard;

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, MessageLevel, Modal, StatusLevel, Tab};

/**
 * Draws the whole application into the frame.
 *
 * Lays out the header, tab bar, tab description, the active tab's body, the
 * optional read-only and watchdog banners, the status line and the footer as
 * stacked one-row regions, then dispatches the body to the module for the
 * current tab. Finally the modal dialog, if any, is drawn on top of everything
 * else. Terminals smaller than 40x12 get an explanation instead of the UI.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame everything is rendered into.
 * * `app` (`&App`) - The application state supplying the tab, theme, status, banners, watchdog and modal.
 *
 * # Returns
 *
 * This function returns no value.
 */
pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    if area.width < 40 || area.height < 12 {
        draw_too_small(frame, area, app);
        return;
    }

    let show_readonly = app.readonly || !app.state.rules_readable;
    let mut constraints = vec![
        Constraint::Length(1), // header
        Constraint::Length(1), // tabs
        Constraint::Length(1), // tab description
        Constraint::Min(3),    // body
    ];
    if show_readonly {
        constraints.push(Constraint::Length(1));
    }
    if app.watchdog.is_some() {
        constraints.push(Constraint::Length(1));
    }
    constraints.push(Constraint::Length(1)); // status
    constraints.push(Constraint::Length(1)); // footer

    let chunks = Layout::vertical(constraints).split(area);
    let mut index = 0;

    draw_header(frame, chunks[index], app);
    index += 1;
    draw_tabs(frame, chunks[index], app);
    index += 1;
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!("  {}", app.tab.description()),
            app.theme
                .dimmed()
                .add_modifier(ratatui::style::Modifier::ITALIC),
        ))),
        chunks[index],
    );
    index += 1;

    let body = chunks[index];
    index += 1;
    match app.tab {
        Tab::Home => home::draw(frame, body, app),
        Tab::Rules => rules::draw(frame, body, app),
        Tab::Add => wizard::draw(frame, body, app),
        Tab::Test => test::draw(frame, body, app),
        Tab::Activity => activity::draw(frame, body, app),
        Tab::Presets => presets::draw(frame, body, app),
        Tab::Help => help::draw(frame, body, app),
    }

    if show_readonly {
        draw_readonly_banner(frame, chunks[index], app);
        index += 1;
    }
    if app.watchdog.is_some() {
        draw_watchdog(frame, chunks[index], app);
        index += 1;
    }

    draw_status(frame, chunks[index], app);
    index += 1;
    draw_footer(frame, chunks[index], app);

    if let Some(modal) = &app.modal {
        draw_modal(frame, area, app, modal);
    }
}

/**
 * Draws the one-line header.
 *
 * The left side shows the program name and its version; the right side shows
 * the hostname, whether the backend is running as root or as a normal user, and
 * the backend label. The two halves are laid out horizontally in `area`.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the header is rendered into.
 * * `area` (`Rect`) - The single-row region reserved for the header.
 * * `app` (`&App`) - The application state supplying the hostname, the backend and the theme.
 *
 * # Returns
 *
 * This function returns no value.
 */
fn draw_header(frame: &mut Frame, area: Rect, app: &App) {
    let left = Line::from(vec![
        Span::styled(" ufw-manager-tui", app.theme.title()),
        Span::styled(
            format!(" v{}", env!("CARGO_PKG_VERSION")),
            app.theme.dimmed(),
        ),
    ]);
    let privilege = if app.backend.is_root() {
        "root"
    } else {
        "user"
    };
    let right_text = format!(
        "{} · {} · {} ",
        app.hostname,
        privilege,
        app.backend.label()
    );
    let right_width = right_text.chars().count().min(u16::MAX as usize) as u16;
    let [left_area, right_area] =
        Layout::horizontal([Constraint::Min(10), Constraint::Length(right_width)]).areas(area);
    frame.render_widget(Paragraph::new(left), left_area);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(right_text, app.theme.dimmed()))),
        right_area,
    );
}

/**
 * Draws the tab bar.
 *
 * Every tab in [`Tab::ALL`] is rendered as its title surrounded by spaces and
 * separated by a vertical bar. The active tab uses the selected style and the
 * others the dimmed style.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the tab bar is rendered into.
 * * `area` (`Rect`) - The single-row region reserved for the tab bar.
 * * `app` (`&App`) - The application state supplying the active tab and theme.
 *
 * # Returns
 *
 * This function returns no value.
 */
fn draw_tabs(frame: &mut Frame, area: Rect, app: &App) {
    let mut spans = Vec::new();
    for tab in Tab::ALL {
        let selected = tab == app.tab;
        let style = if selected {
            app.theme.selected()
        } else {
            app.theme.dimmed()
        };
        spans.push(Span::styled(format!(" {} ", tab.title()), style));
        spans.push(Span::styled("│", app.theme.border_style()));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/**
 * Draws the read-only or hidden-rules banner.
 *
 * The text depends on why the app cannot change anything: an explicit
 * read-only run tells the user to rerun with sudo or press `X` to escalate,
 * while unreadable rules explain that ufw only shows rules to root.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the banner is rendered into.
 * * `area` (`Rect`) - The single-row region reserved for the banner.
 * * `app` (`&App`) - The application state supplying the read-only flag and the theme.
 *
 * # Returns
 *
 * This function returns no value.
 */
fn draw_readonly_banner(frame: &mut Frame, area: Rect, app: &App) {
    let text = if app.readonly {
        " READ-ONLY  rerun with sudo (or press X to escalate) to change anything"
    } else {
        " RULES HIDDEN  ufw only shows rules to root — run `sudo ufw-manager-tui`"
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            text,
            app.theme
                .dimmed()
                .add_modifier(ratatui::style::Modifier::BOLD),
        ))),
        area,
    );
}

/**
 * Draws the auto-revert countdown banner.
 *
 * Shows how many seconds remain before the pending change is undone, the
 * description of that change, and the reminder that pressing `Y` keeps it. The
 * text is drawn in the high-risk style so it cannot be missed.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the banner is rendered into.
 * * `area` (`Rect`) - The single-row region reserved for the banner.
 * * `app` (`&App`) - The application state supplying the watchdog, its remaining time and the theme.
 *
 * # Returns
 *
 * This function returns no value.
 */
fn draw_watchdog(frame: &mut Frame, area: Rect, app: &App) {
    let remaining = app.watchdog_remaining().unwrap_or(0);
    let description = app
        .watchdog
        .as_ref()
        .map(|w| w.description.clone())
        .unwrap_or_default();
    let text = format!(
        " AUTO-REVERT in {remaining}s unless you press Y — “{description}” will be undone if you lose your connection"
    );
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            text,
            app.theme
                .risk_style(crate::core::risk::RiskLevel::High)
                .add_modifier(ratatui::style::Modifier::BOLD),
        ))),
        area,
    );
}

/**
 * Draws the status line.
 *
 * A marker and the status text are drawn in a colour matching the level
 * (information, success, warning or error). The text is ellipsized to the
 * available width. When there is no status, a blank line is drawn so the
 * layout does not shift.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the status line is rendered into.
 * * `area` (`Rect`) - The single-row region reserved for the status line.
 * * `app` (`&App`) - The application state supplying the status and the theme.
 *
 * # Returns
 *
 * This function returns no value.
 */
fn draw_status(frame: &mut Frame, area: Rect, app: &App) {
    let Some(status) = &app.status else {
        frame.render_widget(Paragraph::new(Line::default()), area);
        return;
    };
    let style = match status.level {
        StatusLevel::Info => app.theme.text_style(),
        StatusLevel::Good => ratatui::style::Style::new().fg(app.theme.ok),
        StatusLevel::Warn => ratatui::style::Style::new().fg(app.theme.warn),
        StatusLevel::Error => ratatui::style::Style::new().fg(app.theme.danger),
    };
    let marker = match status.level {
        StatusLevel::Info => "•",
        StatusLevel::Good => "✓",
        StatusLevel::Warn => "!",
        StatusLevel::Error => "✗",
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!(
                " {marker} {}",
                crate::core::util::ellipsize(&status.text, area.width.saturating_sub(3) as usize)
            ),
            style,
        ))),
        area,
    );
}

/**
 * Draws the footer hint bar.
 *
 * Hints for the active tab come from [`keys::hints`] and are added left to
 * right until the next one would not fit in `area`, so the least important
 * hints are dropped first. A `q quit` hint is appended when there is spare
 * width.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the footer is rendered into.
 * * `area` (`Rect`) - The single-row region reserved for the footer.
 * * `app` (`&App`) - The application state supplying the active tab and theme.
 *
 * # Returns
 *
 * This function returns no value.
 */
fn draw_footer(frame: &mut Frame, area: Rect, app: &App) {
    let hints = keys::hints(app.tab);
    let mut spans = Vec::new();
    let mut used = 0u16;
    for hint in hints {
        let piece = format!("{:>0} {}   ", hint.keys, hint.label);
        let width = piece.chars().count() as u16;
        if used + width + 6 > area.width {
            break;
        }
        used += width;
        spans.push(Span::styled(hint.keys.to_string(), app.theme.title()));
        spans.push(Span::styled(
            format!(" {}   ", hint.label),
            app.theme.dimmed(),
        ));
    }
    if area.width > used + 8 {
        spans.push(Span::styled("q quit", app.theme.dimmed()));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/**
 * Draws the modal dialog layer on top of the rest of the UI.
 *
 * A [`Modal::Message`] is drawn as a centred, cleared box whose border colour
 * reflects the message level, with the body word-wrapped. A
 * [`Modal::Confirm`] is drawn as a taller centred box showing the guard
 * warning, the commands that will run, the plain-English meaning, the dry-run
 * validation result, optionally the captured `ufw --dry-run` output, and the
 * key legend.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the dialog is rendered into.
 * * `area` (`Rect`) - The full screen area the dialog is centred within.
 * * `app` (`&App`) - The application state supplying the theme.
 * * `modal` (`&Modal`) - The modal to draw.
 *
 * # Returns
 *
 * This function returns no value.
 */
fn draw_modal(frame: &mut Frame, area: Rect, app: &App, modal: &Modal) {
    match modal {
        Modal::Message(message) => {
            let height = (message.body.len() as u16 + 8).min(area.height);
            let rect = widgets::centered_rect(area, 78, height);
            frame.render_widget(Clear, rect);
            let (title, style) = match message.level {
                MessageLevel::Info => (" Information ", app.theme.title()),
                MessageLevel::Warning => {
                    (" Warning ", ratatui::style::Style::new().fg(app.theme.warn))
                }
                MessageLevel::Error => (
                    " Problem ",
                    ratatui::style::Style::new().fg(app.theme.danger),
                ),
            };
            let block = app
                .theme
                .block()
                .border_style(style)
                .title(Span::styled(title.to_string(), style));
            let body: Vec<Line> = message
                .body
                .iter()
                .flat_map(|line| wrap_text(line, rect.width.saturating_sub(4) as usize))
                .map(Line::from)
                .collect();
            frame.render_widget(
                Paragraph::new(body).block(block).wrap(Wrap { trim: false }),
                rect,
            );
        }
        Modal::Confirm(confirm) => {
            let mut lines: Vec<Line> = Vec::new();

            if let Some(warning) = confirm.guard.message() {
                lines.push(Line::from(Span::styled(
                    warning.to_string(),
                    app.theme.risk_style(crate::core::risk::RiskLevel::High),
                )));
                lines.push(Line::default());
            }

            lines.push(Line::from(Span::styled(
                "Will run:",
                app.theme
                    .text_style()
                    .add_modifier(ratatui::style::Modifier::BOLD),
            )));
            for command in confirm.change.preview().lines() {
                lines.push(Line::from(Span::styled(
                    format!("  {command}"),
                    app.theme.title(),
                )));
            }
            lines.push(Line::default());
            lines.push(Line::from(vec![
                Span::styled("This means: ", app.theme.dimmed()),
                Span::styled(confirm.meaning.clone(), app.theme.text_style()),
            ]));
            lines.push(Line::default());

            lines.push(Line::from(Span::styled(
                format!(
                    "ufw's own validation: passed for all {} command(s) (ufw --dry-run)",
                    confirm.change.steps.len()
                ),
                ratatui::style::Style::new().fg(app.theme.ok),
            )));

            if confirm.show_dry {
                if let Some(output) = &confirm.dry {
                    lines.push(Line::default());
                    for line in output.stdout.lines().take(12) {
                        lines.push(Line::from(Span::styled(
                            format!("  {line}"),
                            app.theme.dimmed(),
                        )));
                    }
                }
            }

            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "[ENTER] Apply    [ESC] Cancel    [D] dry-run output",
                app.theme.dimmed(),
            )));

            // Wrapped lines take more rows than they have entries, so leave generous headroom and
            // let the dialog fill the available height if the terminal is short.
            let height = (lines.len() as u16 + 6).min(area.height);
            let rect = widgets::centered_rect(area, 86, height);
            frame.render_widget(Clear, rect);
            let title = crate::core::util::ellipsize(
                &modal_title(&confirm.pending),
                rect.width.saturating_sub(6) as usize,
            );
            let block = app
                .theme
                .block()
                .border_style(app.theme.risk_style(crate::core::risk::RiskLevel::Medium))
                .title(Span::styled(format!(" {title} "), app.theme.title()));
            frame.render_widget(
                Paragraph::new(lines)
                    .block(block)
                    .wrap(Wrap { trim: false }),
                rect,
            );
        }
    }
}

/**
 * Builds a short, scannable heading for the confirmation dialog.
 *
 * The full sentence is already in the "This means" line, so the title only has
 * to say *what kind* of change this is. Rule numbers are included when the
 * pending change refers to an existing rule.
 *
 * # Arguments
 *
 * * `pending` (`&crate::core::lockout::PendingChange`) - The change awaiting confirmation.
 *
 * # Returns
 *
 * A `String` such as `"Confirm: delete rule #3"` or
 * `"Confirm: turn the firewall on"`.
 */
fn modal_title(pending: &crate::core::lockout::PendingChange) -> String {
    use crate::core::lockout::ChangeKind;

    let rule = pending.rule.as_ref().map(|rule| rule.number);
    match pending.kind {
        ChangeKind::AddRule => "Confirm: add this rule".to_string(),
        ChangeKind::DeleteRule => match rule {
            Some(number) => format!("Confirm: delete rule #{number}"),
            None => "Confirm: delete this rule".to_string(),
        },
        ChangeKind::EditRule => match rule {
            Some(number) => format!("Confirm: change rule #{number}"),
            None => "Confirm: change this rule".to_string(),
        },
        ChangeKind::MoveRule => "Confirm: reorder the rules".to_string(),
        ChangeKind::Enable => "Confirm: turn the firewall on".to_string(),
        ChangeKind::Disable => "Confirm: turn the firewall off".to_string(),
        ChangeKind::SetDefaultIncoming => "Confirm: change the default policy".to_string(),
        ChangeKind::SetLogging => "Confirm: change logging".to_string(),
        ChangeKind::Reset => "Confirm: reset the firewall".to_string(),
    }
}

/**
 * Splits a long line on word boundaries so dialog text never runs off the edge.
 *
 * Text that already fits, or a zero width, is returned as a single line. A word
 * longer than `width` is kept intact on its own line rather than being broken.
 * An empty input yields one empty string so callers always get at least one
 * line.
 *
 * # Arguments
 *
 * * `text` (`&str`) - The line to wrap.
 * * `width` (`usize`) - The maximum number of characters per output line.
 *
 * # Returns
 *
 * A `Vec<String>` of wrapped lines, never empty.
 */
pub fn wrap_text(text: &str, width: usize) -> Vec<String> {
    if width == 0 || text.chars().count() <= width {
        return vec![text.to_string()];
    }
    let mut out = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.chars().count() + 1 + word.chars().count() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            out.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

/**
 * Draws the explanation shown when the terminal is below the minimum size.
 *
 * The message names the program, states that the terminal is too small, reports
 * the required and actual dimensions, and tells the user to resize or press `q`
 * to quit.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the message is rendered into.
 * * `area` (`Rect`) - The full screen area, whose size is reported.
 * * `app` (`&App`) - The application state supplying the theme.
 *
 * # Returns
 *
 * This function returns no value.
 */
fn draw_too_small(frame: &mut Frame, area: Rect, app: &App) {
    let lines = vec![
        Line::from(Span::styled("ufw-manager-tui", app.theme.title())),
        Line::default(),
        Line::from("The terminal is too small."),
        Line::from(format!(
            "Need at least 40x12, have {}x{}.",
            area.width, area.height
        )),
        Line::default(),
        Line::from("Resize the window, or press q to quit."),
    ];
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
}

/**
 * Renders just the dialog layer into an off-screen buffer and returns it as
 * text.
 *
 * Used by the integration tests to assert what the confirmation dialog actually
 * says. The buffer is 110x34 and each row is terminated with a newline.
 *
 * # Arguments
 *
 * * `app` (`&App`) - The application state whose modal should be rendered.
 *
 * # Returns
 *
 * A `String` containing the rendered dialog, one line per terminal row.
 *
 * # Panics
 *
 * Panics if the test terminal cannot be created or the draw call fails.
 */
#[doc(hidden)]
pub fn render_dialog_for_test(app: &App) -> String {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    let mut terminal = Terminal::new(TestBackend::new(110, 34)).expect("terminal");
    terminal
        .draw(|frame| {
            let area = frame.area();
            if let Some(modal) = &app.modal {
                draw_modal(frame, area, app, modal);
            }
        })
        .expect("draw must succeed");
    let buffer = terminal.backend().buffer();
    let content = buffer.content();
    let mut out = String::new();
    for y in 0..buffer.area.height {
        for x in 0..buffer.area.width {
            if let Some(cell) = content.get((y * buffer.area.width + x) as usize) {
                out.push_str(cell.symbol());
            }
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
/**
 * Renders the whole UI into an off-screen buffer of the given size and returns
 * it as text.
 *
 * Used by the unit tests in the `ui` modules to assert on what a tab actually
 * draws. Each row of the buffer is terminated with a newline.
 *
 * # Arguments
 *
 * * `app` (`&App`) - The application state to render.
 * * `width` (`u16`) - The width of the test terminal in columns.
 * * `height` (`u16`) - The height of the test terminal in rows.
 *
 * # Returns
 *
 * A `String` containing the rendered screen, one line per terminal row.
 *
 * # Panics
 *
 * Panics if the test terminal cannot be created or the draw call fails.
 */
pub(crate) fn render_to_string(app: &App, width: u16, height: u16) -> String {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal");
    terminal
        .draw(|frame| draw(frame, app))
        .expect("draw must succeed");
    let buffer = terminal.backend().buffer();
    let content = buffer.content();
    let mut out = String::new();
    for y in 0..buffer.area.height {
        for x in 0..buffer.area.width {
            if let Some(cell) = content.get((y * buffer.area.width + x) as usize) {
                out.push_str(cell.symbol());
            }
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /**
     * Builds an [`App`] backed by the mock backend for use in tests.
     *
     * The app uses the dark theme, has counters enabled and confirmation
     * disabled, and writes no journal, so tests can render any tab without
     * touching the real firewall.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * An `App` populated from the mock backend's demo state.
     */
    pub(crate) fn demo_app() -> App {
        use crate::backend::mock::MockBackend;
        use crate::ui::theme::Theme;

        App::new(
            Box::new(MockBackend::new()),
            crate::app::AppOptions {
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

    #[test]
    /**
     * Checks that wrapping breaks on word boundaries and produces several lines.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test when a line overflows or
     * no break occurs.
     */
    fn wrapping_breaks_on_words() {
        let lines = wrap_text("the quick brown fox jumps over the lazy dog", 12);
        assert!(lines
            .iter()
            .all(|line| line.chars().count() <= 12 || !line.contains(' ')));
        assert!(lines.len() > 1);
    }

    #[test]
    /**
     * Checks that ASCII mode draws ASCII corners and no Unicode ones.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test on the wrong characters.
     */
    fn ascii_mode_renders_ascii_borders() {
        use crate::ui::theme::Theme;

        let mut app = tests::demo_app();
        app.tab = Tab::Rules;
        app.theme = Theme::new("dark", false).with_ascii(true);
        let output = render_to_string(&app, 100, 30);
        assert!(output.contains('+'), "expected ASCII corners");
        assert!(!output.contains('┌'), "expected no Unicode corners");
    }

    #[test]
    /**
     * Checks that every tab renders when ufw hides the rules from a non-root
     * user, and that the read-only banner explains the mode.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test on empty output or a
     * missing banner.
     */
    fn every_tab_renders_when_the_rules_are_hidden() {
        // The non-root case: ufw refuses to print rules, so the app must still be usable and say so.
        let mut app = tests::demo_app();
        app.state = crate::core::firewall::FirewallState {
            rules_readable: false,
            enabled: false,
            ..Default::default()
        };
        app.readonly = true;
        for tab in Tab::ALL {
            app.tab = tab;
            let output = render_to_string(&app, 110, 32);
            assert!(!output.is_empty(), "{tab:?} produced nothing");
        }
        let output = render_to_string(&app, 110, 32);
        assert!(
            output.contains("READ-ONLY"),
            "the banner must explain the mode"
        );
    }

    #[test]
    /**
     * Checks that a terminal below the minimum size shows the explanation.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test when the message is
     * missing.
     */
    fn a_terminal_below_the_minimum_size_shows_an_explanation() {
        let mut app = tests::demo_app();
        app.tab = Tab::Rules;
        let output = render_to_string(&app, 30, 8);
        assert!(output.contains("too small"), "{output}");
    }

    #[test]
    /**
     * Checks that text shorter than the width is returned unchanged.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test on a different result.
     */
    fn short_text_is_left_alone() {
        assert_eq!(wrap_text("short", 20), vec!["short".to_string()]);
    }

    #[test]
    /**
     * Checks that an empty string wraps to a single empty line.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test on a different result.
     */
    fn empty_lines_survive_wrapping() {
        assert_eq!(wrap_text("", 20), vec![String::new()]);
    }
}
