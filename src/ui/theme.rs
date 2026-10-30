//! Colour palettes.
//!
//! Colour is only ever used to carry meaning (risk, verb, state), and every meaning is also
//! available as text so `NO_COLOR`, `TERM=dumb` and colour-blind users lose nothing.

use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::border;
use ratatui::widgets::{Block, BorderType};

use crate::core::risk::RiskLevel;
use crate::core::rule::Action;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Palette {
    Dark,
    Light,
    Sixteen,
    Mono,
}

impl Palette {
    pub fn from_name(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "light" => Palette::Light,
            "16color" | "16" | "ansi" => Palette::Sixteen,
            "mono" | "none" | "nocolor" => Palette::Mono,
            _ => Palette::Dark,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Palette::Dark => "dark",
            Palette::Light => "light",
            Palette::Sixteen => "16color",
            Palette::Mono => "mono",
        }
    }
}

/// Box drawing that survives terminals which mangle Unicode.
pub const ASCII_BORDERS: border::Set = border::Set {
    top_left: "+",
    top_right: "+",
    bottom_left: "+",
    bottom_right: "+",
    vertical_left: "|",
    vertical_right: "|",
    horizontal_top: "-",
    horizontal_bottom: "-",
};

#[derive(Debug, Clone)]
pub struct Theme {
    pub palette: Palette,
    /// Draw panels with `+ - |` instead of Unicode box drawing.
    pub ascii: bool,
    pub allow: Color,
    pub deny: Color,
    pub reject: Color,
    pub limit: Color,
    pub accent: Color,
    pub text: Color,
    pub dim: Color,
    pub border: Color,
    pub ok: Color,
    pub warn: Color,
    pub danger: Color,
    pub info: Color,
    pub selected_fg: Color,
    pub selected_bg: Color,
}

impl Theme {
    pub fn new(name: &str, force_mono: bool) -> Self {
        let palette = if force_mono {
            Palette::Mono
        } else {
            Palette::from_name(name)
        };
        match palette {
            Palette::Mono => Self::monochrome(),
            Palette::Light => Self::light(),
            Palette::Sixteen => Self::sixteen(),
            Palette::Dark => Self::dark(),
        }
    }

    fn dark() -> Self {
        Self {
            palette: Palette::Dark,
            ascii: false,
            allow: Color::Rgb(0x5f, 0xd7, 0x87),
            deny: Color::Rgb(0xff, 0x6b, 0x6b),
            reject: Color::Rgb(0xff, 0xa9, 0x4d),
            limit: Color::Rgb(0xff, 0xd9, 0x3d),
            accent: Color::Rgb(0x7a, 0xb8, 0xff),
            text: Color::Rgb(0xd8, 0xde, 0xe9),
            dim: Color::Rgb(0x6b, 0x72, 0x80),
            border: Color::Rgb(0x3b, 0x42, 0x52),
            ok: Color::Rgb(0x5f, 0xd7, 0x87),
            warn: Color::Rgb(0xff, 0xd9, 0x3d),
            danger: Color::Rgb(0xff, 0x6b, 0x6b),
            info: Color::Rgb(0x7a, 0xb8, 0xff),
            selected_fg: Color::Rgb(0x0b, 0x0e, 0x14),
            selected_bg: Color::Rgb(0x7a, 0xb8, 0xff),
        }
    }

    fn light() -> Self {
        Self {
            palette: Palette::Light,
            ascii: false,
            allow: Color::Rgb(0x0f, 0x7b, 0x3f),
            deny: Color::Rgb(0xb3, 0x1d, 0x1d),
            reject: Color::Rgb(0xa3, 0x51, 0x00),
            limit: Color::Rgb(0x7a, 0x5c, 0x00),
            accent: Color::Rgb(0x1a, 0x4e, 0xa8),
            text: Color::Rgb(0x1a, 0x1d, 0x22),
            dim: Color::Rgb(0x6b, 0x72, 0x80),
            border: Color::Rgb(0xb9, 0xc0, 0xcc),
            ok: Color::Rgb(0x0f, 0x7b, 0x3f),
            warn: Color::Rgb(0x7a, 0x5c, 0x00),
            danger: Color::Rgb(0xb3, 0x1d, 0x1d),
            info: Color::Rgb(0x1a, 0x4e, 0xa8),
            selected_fg: Color::Rgb(0xff, 0xff, 0xff),
            selected_bg: Color::Rgb(0x1a, 0x4e, 0xa8),
        }
    }

    fn sixteen() -> Self {
        Self {
            palette: Palette::Sixteen,
            ascii: false,
            allow: Color::Green,
            deny: Color::Red,
            reject: Color::Yellow,
            limit: Color::Yellow,
            accent: Color::Cyan,
            text: Color::Reset,
            dim: Color::DarkGray,
            border: Color::DarkGray,
            ok: Color::Green,
            warn: Color::Yellow,
            danger: Color::Red,
            info: Color::Cyan,
            selected_fg: Color::Black,
            selected_bg: Color::Cyan,
        }
    }

    fn monochrome() -> Self {
        Self {
            palette: Palette::Mono,
            ascii: false,
            allow: Color::Reset,
            deny: Color::Reset,
            reject: Color::Reset,
            limit: Color::Reset,
            accent: Color::Reset,
            text: Color::Reset,
            dim: Color::Reset,
            border: Color::Reset,
            ok: Color::Reset,
            warn: Color::Reset,
            danger: Color::Reset,
            info: Color::Reset,
            selected_fg: Color::Reset,
            selected_bg: Color::Reset,
        }
    }

    pub fn is_mono(&self) -> bool {
        self.palette == Palette::Mono
    }

    /// Switches the theme to ASCII box drawing.
    pub fn with_ascii(mut self, ascii: bool) -> Self {
        self.ascii = ascii;
        self
    }

    /// A bordered panel in this theme's border style and character set.
    pub fn block(&self) -> Block<'static> {
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(self.border_style());
        if self.ascii {
            Block::bordered()
                .border_type(BorderType::Plain)
                .border_style(self.border_style())
                .border_set(ASCII_BORDERS)
        } else {
            block
        }
    }

    /// A bordered panel with a title in the theme's accent style.
    pub fn titled(&self, title: &str) -> Block<'static> {
        self.block()
            .title(ratatui::text::Span::styled(title.to_string(), self.title()))
    }

    pub fn action_color(&self, action: Action) -> Color {
        match action {
            Action::Allow => self.allow,
            Action::Deny => self.deny,
            Action::Reject => self.reject,
            Action::Limit => self.limit,
        }
    }

    pub fn risk_color(&self, level: RiskLevel) -> Color {
        match level {
            RiskLevel::Critical | RiskLevel::High => self.danger,
            RiskLevel::Medium => self.reject,
            RiskLevel::Low => self.ok,
            RiskLevel::Info => self.dim,
        }
    }

    pub fn risk_style(&self, level: RiskLevel) -> Style {
        let style = Style::new().fg(self.risk_color(level));
        if level == RiskLevel::Critical || self.is_mono() {
            style.add_modifier(Modifier::BOLD)
        } else {
            style
        }
    }

    pub fn action_style(&self, action: Action) -> Style {
        Style::new()
            .fg(self.action_color(action))
            .add_modifier(Modifier::BOLD)
    }

    pub fn title(&self) -> Style {
        Style::new().fg(self.accent).add_modifier(Modifier::BOLD)
    }

    pub fn dimmed(&self) -> Style {
        Style::new().fg(self.dim)
    }

    pub fn text_style(&self) -> Style {
        Style::new().fg(self.text)
    }

    pub fn selected(&self) -> Style {
        if self.is_mono() {
            Style::new().add_modifier(Modifier::REVERSED)
        } else {
            Style::new()
                .fg(self.selected_fg)
                .bg(self.selected_bg)
                .add_modifier(Modifier::BOLD)
        }
    }

    pub fn border_style(&self) -> Style {
        Style::new().fg(self.border)
    }

    /// The risk badge: a colour emoji-ish marker in colour mode, ASCII text in mono mode.
    pub fn badge(&self, level: RiskLevel) -> String {
        if self.is_mono() {
            level.ascii_badge().to_string()
        } else {
            match level {
                RiskLevel::Critical => "✖".to_string(),
                RiskLevel::High => "▲".to_string(),
                RiskLevel::Medium => "◆".to_string(),
                RiskLevel::Low => "✓".to_string(),
                RiskLevel::Info => "·".to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn palettes_can_be_selected_by_name() {
        assert_eq!(Palette::from_name("light"), Palette::Light);
        assert_eq!(Palette::from_name("MONO"), Palette::Mono);
        assert_eq!(Palette::from_name("16color"), Palette::Sixteen);
        assert_eq!(Palette::from_name("nonsense"), Palette::Dark);
    }

    #[test]
    fn monochrome_has_no_colours_at_all() {
        let theme = Theme::new("dark", true);
        assert_eq!(theme.allow, Color::Reset);
        assert_eq!(theme.danger, Color::Reset);
        assert!(theme.is_mono());
    }

    #[test]
    fn mono_mode_uses_reverse_video_for_selection() {
        let theme = Theme::new("mono", false);
        assert_eq!(theme.selected().add_modifier, Modifier::REVERSED);
    }

    #[test]
    fn risk_levels_map_to_distinct_colours() {
        let theme = Theme::new("dark", false);
        assert_eq!(theme.risk_color(RiskLevel::Critical), theme.danger);
        assert_eq!(theme.risk_color(RiskLevel::Low), theme.ok);
        assert_eq!(theme.risk_color(RiskLevel::Info), theme.dim);
    }

    #[test]
    fn ascii_mode_replaces_the_box_drawing() {
        let theme = Theme::new("dark", false).with_ascii(true);
        assert!(theme.ascii);
        assert_eq!(ASCII_BORDERS.top_left, "+");
        assert_eq!(ASCII_BORDERS.horizontal_top, "-");
        assert_eq!(ASCII_BORDERS.vertical_left, "|");
    }

    #[test]
    fn badges_are_text_in_mono_mode() {
        let theme = Theme::new("mono", false);
        assert_eq!(theme.badge(RiskLevel::Critical), "[!!]");
        assert_eq!(theme.badge(RiskLevel::Low), "[ok]");
    }
}
