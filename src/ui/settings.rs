//! The Settings tab: general preferences, the defaults for new rules, and the button that writes
//! both to `config.toml`.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{
    settings_row_is_checkbox, App, SettingsField, SETTINGS_DEFAULT_ROWS, SETTINGS_DEFAULT_START,
    SETTINGS_GENERAL_ROWS, SETTINGS_SAVE_ROW,
};

/// Labels of the "General Settings" rows, in display order.
const GENERAL_LABELS: [&str; SETTINGS_GENERAL_ROWS] = [
    "Theme",
    "Confirm before apply",
    "Counters refresh (seconds)",
    "Log source",
    "Reconcile (seconds)",
    "Read-only",
    "Skip wizard (new rules start on Advanced)",
];

/// Labels of the "Rule defaults" rows, in display order.
const DEFAULT_LABELS: [&str; SETTINGS_DEFAULT_ROWS] = [
    "Action",
    "Direction",
    "Interface",
    "Protocol",
    "From address",
    "From port",
    "To address",
    "To port",
    "Logging",
];

/// Width reserved for a row label before its value starts.
const LABEL_WIDTH: usize = 40;

/**
 * Draws the Settings tab: the two lists of settings and the save button.
 *
 * The area is split into a flexible list region and a fixed two-row footer.
 * When a text field is open, the input dialog is drawn on top of the whole
 * area.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the widgets are rendered into.
 * * `area` (`Rect`) - The screen region reserved for the Settings tab.
 * * `app` (`&App`) - The application state supplying the config, the cursor and the theme.
 *
 * # Returns
 *
 * This function returns no value.
 */
pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let rows = Layout::vertical([Constraint::Min(5), Constraint::Length(2)]).split(area);
    draw_list(frame, rows[0], app);
    draw_footer(frame, rows[1], app);

    if let Some((field, input)) = &app.settings_input {
        draw_input(frame, area, app, *field, input);
    }
}

/**
 * Returns the display value of one settings row.
 *
 * Empty addresses, ports and interfaces are shown as `any`, and a watchdog
 * delay of zero is shown as disabled, so every row reads as a value rather
 * than a blank.
 *
 * # Arguments
 *
 * * `app` (`&App`) - The application state holding the config.
 * * `index` (`usize`) - The zero-based row index.
 *
 * # Returns
 *
 * A `String` with the value to display for that row.
 */
fn row_value(app: &App, index: usize) -> String {
    let defaults = &app.config.defaults;
    match index {
        0 => app.config.theme.clone(),
        2 => app.config.counters_refresh_secs.to_string(),
        3 => app.config.log_source.clone(),
        4 => match app.config.reconcile_seconds {
            0 => "0 (disabled)".into(),
            seconds => seconds.to_string(),
        },
        7 => defaults.action.clone(),
        8 => defaults.direction.clone(),
        9 => or_any(&defaults.interface),
        10 => defaults.protocol.clone(),
        11 => or_any(&defaults.from_addr),
        12 => or_any(&defaults.from_port),
        13 => or_any(&defaults.to_addr),
        14 => or_any(&defaults.to_port),
        15 => defaults.logging.clone(),
        _ => String::new(),
    }
}

/**
 * Shows an empty setting as `any`, which is what it means to ufw.
 *
 * # Arguments
 *
 * * `value` (`&str`) - The configured value.
 *
 * # Returns
 *
 * `String` - The value, or `any` when it is empty.
 */
fn or_any(value: &str) -> String {
    if value.is_empty() {
        "any".into()
    } else {
        value.to_string()
    }
}

/**
 * Draws the scrollable list of settings rows.
 *
 * Rows are grouped under the "General Settings" and "Rule defaults" headings,
 * followed by the save button. Each row shows a selection marker, its label and
 * its current value; the on/off rows are drawn as checkboxes. The list scrolls
 * so the selected row stays visible on short terminals.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the list is rendered into.
 * * `area` (`Rect`) - The region reserved for the settings list.
 * * `app` (`&App`) - The application state supplying the config, the cursor and the theme.
 *
 * # Returns
 *
 * This function returns no value.
 */
fn draw_list(frame: &mut Frame, area: Rect, app: &App) {
    let block = app.theme.titled(" settings ");
    let mut lines = Vec::new();
    let mut selected_line = 0usize;

    lines.push(heading(app, "General Settings:"));
    for (index, label) in GENERAL_LABELS.iter().enumerate() {
        if index == app.settings_cursor {
            selected_line = lines.len();
        }
        lines.push(settings_line(
            app,
            index == app.settings_cursor,
            index,
            label,
        ));
    }

    lines.push(Line::default());
    lines.push(heading(app, "Rule defaults:"));
    for (offset, label) in DEFAULT_LABELS.iter().enumerate() {
        let index = SETTINGS_DEFAULT_START + offset;
        if index == app.settings_cursor {
            selected_line = lines.len();
        }
        lines.push(settings_line(
            app,
            index == app.settings_cursor,
            index,
            label,
        ));
    }

    lines.push(Line::default());
    if app.settings_cursor == SETTINGS_SAVE_ROW {
        selected_line = lines.len();
    }
    lines.push(save_line(app));

    let visible = area.height.saturating_sub(2) as usize;
    let offset = scroll_offset(selected_line, lines.len(), visible);
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((offset, 0)),
        area,
    );
}

/**
 * Draws one selectable settings row.
 *
 * Toggle rows show a checkbox in place of a value; the rest show the current
 * value in the dimmed style so the labels stay the brightest thing on screen.
 *
 * # Arguments
 *
 * * `app` (`&App`) - The application state holding the config.
 * * `selected` (`bool`) - Whether this row is under the cursor.
 * * `index` (`usize`) - The zero-based row index.
 * * `label` (`&str`) - The row label.
 *
 * # Returns
 *
 * `Line` - The styled row, ready to render.
 */
fn settings_line(app: &App, selected: bool, index: usize, label: &str) -> Line<'static> {
    let style = if selected {
        app.theme.selected()
    } else {
        app.theme.text_style()
    };
    let marker = if selected { "▸ " } else { "  " };
    let checkbox = if settings_row_is_checkbox(index) {
        if checkbox_is_on(app, index) {
            "[x]"
        } else {
            "[ ]"
        }
    } else {
        "   "
    };
    let value = if settings_row_is_checkbox(index) {
        String::new()
    } else {
        row_value(app, index)
    };
    Line::from(vec![
        Span::styled(format!(" {marker}{checkbox} {label:<LABEL_WIDTH$}"), style),
        Span::styled(
            value,
            if selected {
                app.theme.selected()
            } else {
                app.theme.dimmed()
            },
        ),
    ])
}

/**
 * Reports whether the on/off setting at a row is currently on.
 *
 * # Arguments
 *
 * * `app` (`&App`) - The application state holding the flags.
 * * `index` (`usize`) - The zero-based row index of a checkbox row.
 *
 * # Returns
 *
 * `bool` - `true` when the setting is enabled.
 */
fn checkbox_is_on(app: &App, index: usize) -> bool {
    match index {
        1 => app.confirm_before_apply,
        5 => app.readonly,
        6 => app.skip_wizard,
        _ => false,
    }
}

/**
 * Draws the section heading that separates the two groups of settings.
 *
 * # Arguments
 *
 * * `app` (`&App`) - The application state supplying the theme.
 * * `title` (`&str`) - The heading text.
 *
 * # Returns
 *
 * `Line` - The styled heading, ready to render.
 */
fn heading(app: &App, title: &str) -> Line<'static> {
    Line::from(Span::styled(format!("  {title}"), app.theme.title()))
}

/**
 * Draws the save row, which writes every setting to `config.toml`.
 *
 * The button says where the file will be written, because "saved" means
 * different things depending on whether `--config` was used.
 *
 * # Arguments
 *
 * * `app` (`&App`) - The application state holding the destination path.
 *
 * # Returns
 *
 * `Line` - The styled save row, ready to render.
 */
fn save_line(app: &App) -> Line<'static> {
    let selected = app.settings_cursor == SETTINGS_SAVE_ROW;
    let button_style = if selected {
        app.theme.selected()
    } else {
        app.theme.action_style(crate::core::rule::Action::Allow)
    };
    let destination = match &app.config_path {
        Some(path) => format!("save settings to {}", path.display()),
        None => "save settings (no config path in this session)".to_string(),
    };
    Line::from(vec![
        Span::styled(
            format!(
                " {}{}",
                if selected { "▸ " } else { "  " },
                "[ Save Settings ]"
            ),
            button_style,
        ),
        Span::styled(format!("   {destination}"), app.theme.dimmed()),
    ])
}

/**
 * Finds the first line to show so the selected row stays inside the window.
 *
 * # Arguments
 *
 * * `selected` (`usize`) - The line index of the selected row.
 * * `total` (`usize`) - The number of lines in the list.
 * * `visible` (`usize`) - How many lines fit in the list region.
 *
 * # Returns
 *
 * `u16` - The scroll offset, in lines.
 */
fn scroll_offset(selected: usize, total: usize, visible: usize) -> u16 {
    if visible == 0 || total <= visible {
        return 0;
    }
    let lowest = selected + 1 - visible.min(selected + 1);
    lowest.min(total - visible) as u16
}

/**
 * Draws the two-row footer under the settings list.
 *
 * The first row says whether the file on disk still matches what is on screen;
 * the second shows the key hints.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the footer is rendered into.
 * * `area` (`Rect`) - The region reserved for the footer.
 * * `app` (`&App`) - The application state supplying the theme and the dirty flag.
 *
 * # Returns
 *
 * This function returns no value.
 */
fn draw_footer(frame: &mut Frame, area: Rect, app: &App) {
    let state = if app.settings_dirty {
        Line::from(Span::styled(
            "  ● Unsaved changes — nothing is written until you save.",
            Style::default().fg(app.theme.warn),
        ))
    } else {
        Line::from(Span::styled(
            "  Settings on screen match the saved file.",
            app.theme.dimmed(),
        ))
    };
    let lines = vec![
        state,
        Line::from(Span::styled(
            "  ENTER / ← → change    SPACE toggle    S save settings",
            app.theme.dimmed(),
        )),
    ];
    frame.render_widget(Paragraph::new(lines), area);
}

/**
 * Returns the prompt shown above a text input for the given field.
 *
 * # Arguments
 *
 * * `field` (`SettingsField`) - The field being edited.
 *
 * # Returns
 *
 * A `&'static str` describing what to type.
 */
fn field_label(field: SettingsField) -> &'static str {
    match field {
        SettingsField::CountersRefreshSecs => {
            "seconds between counter refreshes (e.g. 5, must be at least 1)"
        }
        SettingsField::ReconcileSeconds => {
            "seconds before a risky change is reverted (0 disables the watchdog)"
        }
        SettingsField::Interface => "default interface (e.g. eno1, wlan0, wg0 — empty for any)",
        SettingsField::FromAddress => "default from address (empty for any)",
        SettingsField::FromPort => {
            "default from port, range or list (e.g. 1024:65535 — empty for any)"
        }
        SettingsField::ToAddress => "default to address (empty for any)",
        SettingsField::ToPort => "default to port, range or list (e.g. 80,443 — empty for any)",
    }
}

/**
 * Draws the centred text-input dialog for a settings field.
 *
 * The dialog is cleared first so the settings list behind it does not show
 * through. It shows the field's label, the value split around a highlighted
 * block cursor, and the accept and cancel key hints.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the dialog is rendered into.
 * * `area` (`Rect`) - The full screen area the dialog is centred within.
 * * `app` (`&App`) - The application state supplying the theme.
 * * `field` (`SettingsField`) - The field being edited, used for the label.
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
    field: SettingsField,
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
     * Checks that the Settings tab renders both sections, every row and the save button.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test on a missing row.
     */
    fn the_settings_tab_renders_all_rows() {
        let mut app = demo_app();
        app.tab = Tab::Settings;
        let output = render(&app, 120, 45);
        assert!(output.contains("General Settings"));
        assert!(output.contains("Theme"));
        assert!(output.contains("Confirm before apply"));
        assert!(output.contains("Counters refresh"));
        assert!(output.contains("Log source"));
        assert!(output.contains("Reconcile"));
        assert!(output.contains("Read-only"));
        assert!(output.contains("Skip wizard"));
        assert!(output.contains("Rule defaults"));
        assert!(output.contains("Action"));
        assert!(output.contains("Direction"));
        assert!(output.contains("Interface"));
        assert!(output.contains("Protocol"));
        assert!(output.contains("From address"));
        assert!(output.contains("From port"));
        assert!(output.contains("To address"));
        assert!(output.contains("To port"));
        assert!(output.contains("Logging"));
        assert!(output.contains("[ Save Settings ]"));
        assert!(output.contains("[ ]"));
    }

    #[test]
    /**
     * Checks that the save row names the file the settings are written to.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test when the path is hidden.
     */
    fn the_save_row_shows_the_config_path() {
        let mut app = demo_app();
        app.tab = Tab::Settings;
        app.config_path = Some(std::path::PathBuf::from("/tmp/ufw/config.toml"));
        let output = render(&app, 120, 45);
        assert!(output.contains("/tmp/ufw/config.toml"));
    }

    #[test]
    /**
     * Checks that the skip-wizard checkbox reflects the config flag.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test on a wrong checkbox.
     */
    fn the_checkbox_reflects_the_config_flag() {
        let mut app = demo_app();
        app.tab = Tab::Settings;
        app.skip_wizard = true;
        app.config.skip_wizard = true;
        let output = render(&app, 120, 45);
        assert!(output.contains("[x]"));
    }

    #[test]
    /**
     * Checks that an open settings text input renders without panicking.
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
    fn an_open_settings_input_renders_without_panicking() {
        let mut app = demo_app();
        app.tab = Tab::Settings;
        app.settings_input = Some((
            SettingsField::FromAddress,
            crate::ui::widgets::TextInput::new("10.0.0.0/8"),
        ));
        let output = render(&app, 120, 40);
        assert!(output.contains("10.0.0.0/8"));
    }
}
