//! One-key recipes.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use crate::app::App;
use crate::core::risk::RiskLevel;

/**
 * Draws the Presets tab: the list of one-key recipes and the footer explaining
 * what the selected recipe will do.
 *
 * The area is split into a flexible list region and a fixed four-row footer.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the widgets are rendered into.
 * * `area` (`Rect`) - The screen region reserved for the Presets tab.
 * * `app` (`&App`) - The application state supplying the presets, the cursor and the theme.
 *
 * # Returns
 *
 * This function returns no value.
 */
pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let rows = Layout::vertical([Constraint::Min(5), Constraint::Length(4)]).split(area);
    draw_list(frame, rows[0], app);
    draw_footer(frame, rows[1], app);
}

/**
 * Draws the scrollable list of recipe cards.
 *
 * Each card shows a selection marker, its title and a risk badge, followed by
 * either the description of what it does or, when the recipe cannot run here,
 * the reason it is unavailable. The selected card is highlighted and its detail
 * text is word-wrapped to the panel width.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the list is rendered into.
 * * `area` (`Rect`) - The region reserved for the recipe list.
 * * `app` (`&App`) - The application state supplying the presets, the cursor and the theme.
 *
 * # Returns
 *
 * This function returns no value.
 */
fn draw_list(frame: &mut Frame, area: Rect, app: &App) {
    let block = app.theme.titled(" recipes ");
    let width = area.width.saturating_sub(6) as usize;

    let mut lines = Vec::new();
    for (index, card) in app.presets.iter().enumerate() {
        let selected = index == app.preset_cursor;
        let marker = if selected { "▸" } else { " " };
        let badge = app.theme.badge(card.level);
        let title_style = if selected {
            app.theme.selected()
        } else if card.blocked.is_some() {
            app.theme.dimmed()
        } else {
            app.theme.text_style().add_modifier(Modifier::BOLD)
        };

        lines.push(Line::from(vec![
            Span::styled(format!(" {marker} "), title_style),
            Span::styled(card.title.clone(), title_style),
            Span::styled(
                format!("   {badge} {}", card.level.label()),
                app.theme.risk_style(card.level),
            ),
        ]));

        let detail = match &card.blocked {
            Some(reason) => format!("      unavailable: {reason}"),
            None => format!("      {}", card.what),
        };
        let detail_style = if selected {
            app.theme.selected()
        } else {
            app.theme.dimmed()
        };
        for chunk in crate::ui::wrap_text(&detail, width) {
            lines.push(Line::from(Span::styled(chunk, detail_style)));
        }
        lines.push(Line::default());
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

/**
 * Draws the footer describing the selected recipe.
 *
 * For the selected card the footer lists the `ufw` commands that would run, or
 * says there is nothing to do, or shows why the recipe cannot run. It always
 * ends with a reminder that ENTER applies the recipe through the usual dry-run
 * and confirmation. When no recipe is selected a short explanation is drawn.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the footer is rendered into.
 * * `area` (`Rect`) - The region reserved for the footer.
 * * `app` (`&App`) - The application state supplying the presets, the cursor, the preset context and the theme.
 *
 * # Returns
 *
 * This function returns no value.
 */
fn draw_footer(frame: &mut Frame, area: Rect, app: &App) {
    let selected = app.presets.get(app.preset_cursor);
    let lines = match selected {
        None => vec![Line::from(Span::styled(
            "  No recipes apply to this machine right now.",
            app.theme.dimmed(),
        ))],
        Some(card) => {
            let context = app.preset_context();
            let mut lines = Vec::new();
            match card.preset.changes(&context) {
                Ok(changes) if changes.is_empty() => lines.push(Line::from(Span::styled(
                    "  Nothing to do for this recipe.",
                    app.theme.dimmed(),
                ))),
                Ok(changes) => {
                    for change in changes {
                        lines.push(Line::from(Span::styled(
                            format!(
                                "  will run: ufw {}",
                                change.preview().trim_start_matches("ufw ")
                            ),
                            app.theme.title(),
                        )));
                    }
                }
                Err(error) => lines.push(Line::from(Span::styled(
                    format!("  cannot run: {error}"),
                    app.theme.risk_style(RiskLevel::Medium),
                ))),
            }
            lines.push(Line::from(Span::styled(
                "  ENTER applies it, with the usual dry-run and confirmation.",
                app.theme.dimmed(),
            )));
            lines
        }
    };
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

#[cfg(test)]
mod tests {
    use crate::app::Tab;
    use crate::ui::render_to_string as render;
    use crate::ui::tests::demo_app;

    #[test]
    /**
     * Checks that the Presets tab lists the recipes, including the SSH one.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test on missing text.
     */
    fn recipes_are_listed() {
        let mut app = demo_app();
        app.tab = Tab::Presets;
        let output = render(&app, 120, 45);
        assert!(output.contains("recipes"), "{output}");
        assert!(output.contains("SSH"));
    }

    #[test]
    /**
     * Checks that the footer previews the command for the selected recipe.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test when no preview appears.
     */
    fn the_footer_shows_the_command_before_anything_runs() {
        let mut app = demo_app();
        app.tab = Tab::Presets;
        // Index 0 is "turn the firewall on", which is unavailable in the demo state.
        app.preset_cursor = 1;
        let output = render(&app, 140, 45);
        assert!(output.contains("will run"), "{output}");
    }

    #[test]
    /**
     * Checks that an unavailable recipe explains why it cannot run.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test when no explanation is
     * rendered.
     */
    fn an_unavailable_recipe_explains_why() {
        let mut app = demo_app();
        app.tab = Tab::Presets;
        app.preset_cursor = 0;
        let output = render(&app, 140, 45);
        assert!(
            output.contains("unavailable") || output.contains("Nothing to do"),
            "{output}"
        );
    }
}
