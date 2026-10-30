//! The Settings tab: defaults for new rules and the skip-wizard checkbox.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, SettingsField, SETTINGS_ROW_COUNT};

/**
 * Draws the Settings tab: the list of rule defaults, the skip-wizard checkbox
 * and a hint line.
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
 * Toggle rows show the current value; text rows show the value or `any` when
 * empty; the last row is the skip-wizard checkbox.
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
        0 => defaults.action.clone(),
        1 => defaults.direction.clone(),
        2 => {
            if defaults.interface.is_empty() {
                "any".into()
            } else {
                defaults.interface.clone()
            }
        }
        3 => defaults.protocol.clone(),
        4 => {
            if defaults.from_addr.is_empty() {
                "any".into()
            } else {
                defaults.from_addr.clone()
            }
        }
        5 => {
            if defaults.to_addr.is_empty() {
                "any".into()
            } else {
                defaults.to_addr.clone()
            }
        }
        6 => defaults.logging.clone(),
        _ => {
            if app.skip_wizard {
                "on".into()
            } else {
                "off".into()
            }
        }
    }
}

/**
 * Draws the scrollable list of settings rows.
 *
 * Each row shows a selection marker, its label and its current value; the
 * selected row is highlighted. The skip-wizard row is drawn as a checkbox.
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
    let block = app.theme.titled(" defaults for new rules ");
    let labels = [
        "Action",
        "Direction",
        "Interface",
        "Protocol",
        "From address",
        "To address",
        "Logging",
        "Skip wizard (start new rules on Advanced)",
    ];

    let mut lines = Vec::new();
    for (index, label) in labels.iter().enumerate() {
        let selected = index == app.settings_cursor;
        let style = if selected {
            app.theme.selected()
        } else {
            app.theme.text_style()
        };
        let marker = if selected { "▸" } else { " " };
        let value = row_value(app, index);
        let value_style = if selected {
            app.theme.selected()
        } else {
            app.theme.dimmed()
        };
        let checkbox = if index == SETTINGS_ROW_COUNT - 1 {
            if app.skip_wizard {
                "[x]"
            } else {
                "[ ]"
            }
        } else {
            ""
        };
        lines.push(Line::from(vec![
            Span::styled(format!(" {marker} {:<38}", label), style),
            Span::styled(
                if checkbox.is_empty() {
                    String::new()
                } else {
                    format!(" {checkbox}")
                },
                style,
            ),
            Span::styled(
                if checkbox.is_empty() {
                    value
                } else {
                    String::new()
                },
                value_style,
            ),
        ]));
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

/**
 * Draws the two-row footer under the settings list.
 *
 * The first row explains that changes are saved immediately; the second shows
 * the key hints.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the footer is rendered into.
 * * `area` (`Rect`) - The region reserved for the footer.
 * * `app` (`&App`) - The application state supplying the theme.
 *
 * # Returns
 *
 * This function returns no value.
 */
fn draw_footer(frame: &mut Frame, area: Rect, app: &App) {
    let lines = vec![
        Line::from(Span::styled(
            "  Changes are saved to config.toml immediately.",
            app.theme.dimmed(),
        )),
        Line::from(Span::styled(
            "  ENTER / ← → change    SPACE toggle checkbox    ESC cancel",
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
        SettingsField::Interface => "default interface (e.g. eno1, wlan0, wg0 — empty for any)",
        SettingsField::FromAddress => "default from address (empty for any)",
        SettingsField::ToAddress => "default to address (empty for any)",
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
     * Checks that the Settings tab renders every row and the checkbox.
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
        let output = render(&app, 120, 40);
        assert!(output.contains("Action"));
        assert!(output.contains("Direction"));
        assert!(output.contains("Interface"));
        assert!(output.contains("Protocol"));
        assert!(output.contains("From address"));
        assert!(output.contains("To address"));
        assert!(output.contains("Logging"));
        assert!(output.contains("Skip wizard"));
        assert!(output.contains("[ ]"));
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
        let output = render(&app, 120, 40);
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
