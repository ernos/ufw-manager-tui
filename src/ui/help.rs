//! Keys and the glossary.

use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use crate::app::App;

/**
 * Draws the Help tab: the key reference and the plain-English glossary.
 *
 * Lines come from [`App::help_text`]. Lines that look like headings (they end
 * in `:` or match a known section title) are drawn in the bold title style and
 * the rest in the normal text style. The paragraph is word-wrapped and
 * scrolled vertically by `app.help_scroll`.
 *
 * # Arguments
 *
 * * `frame` (`&mut Frame`) - The terminal frame the help text is rendered into.
 * * `area` (`Rect`) - The region reserved for the Help tab.
 * * `app` (`&App`) - The application state supplying the help text, the theme and the scroll offset.
 *
 * # Returns
 *
 * This function returns no value.
 */
pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let block = app.theme.titled(" keys and jargon ");

    let lines: Vec<Line> = app
        .help_text()
        .into_iter()
        .map(|text| {
            let is_heading = text.ends_with(':')
                || matches!(
                    text.as_str(),
                    "Everywhere" | "Rules" | "In a dialog" | "Settings" | "Plain-English glossary"
                );
            if is_heading {
                Line::from(Span::styled(
                    text,
                    app.theme.title().add_modifier(Modifier::BOLD),
                ))
            } else {
                Line::from(Span::styled(text, app.theme.text_style()))
            }
        })
        .collect();

    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((app.help_scroll, 0));
    frame.render_widget(paragraph, area);
}

#[cfg(test)]
mod tests {
    use crate::app::Tab;
    use crate::ui::render_to_string as render;
    use crate::ui::tests::demo_app;

    #[test]
    /**
     * Checks that the Help tab renders both the key reference and the glossary.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test on a missing section.
     */
    fn help_documents_the_keys_and_the_jargon() {
        let mut app = demo_app();
        app.tab = Tab::Help;
        let output = render(&app, 130, 50);
        assert!(output.contains("Everywhere"));
        assert!(output.contains("Plain-English glossary"));
    }

    #[test]
    /**
     * Checks that the help text mentions each of the core glossary terms.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test when a term is missing.
     */
    fn every_glossary_term_appears_in_the_help_text() {
        let app = demo_app();
        let text = app.help_text().join("\n");
        for term in ["port", "ALLOW / DENY", "rule order", "default policy"] {
            assert!(text.contains(term), "missing {term}");
        }
    }

    #[test]
    /**
     * Checks that an absurd scroll offset renders without panicking.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; a panic fails the test.
     */
    fn scrolling_past_the_end_does_not_panic() {
        let mut app = demo_app();
        app.tab = Tab::Help;
        app.help_scroll = u16::MAX;
        let _ = render(&app, 100, 30);
    }
}
