//! Keys and the glossary.

use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use crate::app::App;

pub fn draw(frame: &mut Frame, area: Rect, app: &App) {
    let block = app.theme.titled(" keys and jargon ");

    let lines: Vec<Line> = app
        .help_text()
        .into_iter()
        .map(|text| {
            let is_heading = text.ends_with(':')
                || matches!(
                    text.as_str(),
                    "Everywhere" | "Rules" | "In a dialog" | "Plain-English glossary"
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
    fn help_documents_the_keys_and_the_jargon() {
        let mut app = demo_app();
        app.tab = Tab::Help;
        let output = render(&app, 130, 50);
        assert!(output.contains("Everywhere"));
        assert!(output.contains("Plain-English glossary"));
    }

    #[test]
    fn every_glossary_term_appears_in_the_help_text() {
        let app = demo_app();
        let text = app.help_text().join("\n");
        for term in ["port", "ALLOW / DENY", "rule order", "default policy"] {
            assert!(text.contains(term), "missing {term}");
        }
    }

    #[test]
    fn scrolling_past_the_end_does_not_panic() {
        let mut app = demo_app();
        app.tab = Tab::Help;
        app.help_scroll = u16::MAX;
        let _ = render(&app, 100, 30);
    }
}
