//! Colour palettes.
//!
//! Colour is only ever used to carry meaning (risk, verb, state), and every meaning is also
//! available as text so `NO_COLOR`, `TERM=dumb` and colour-blind users lose nothing.

use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::border;
use ratatui::widgets::{Block, BorderType};

use crate::core::risk::RiskLevel;
use crate::core::rule::Action;

/**
 * The colour palette a [`Theme`] is built from.
 *
 * The palette decides which concrete colours are used for actions, risk levels
 * and chrome, and whether colour is used at all.
 *
 * # Variants
 *
 * * `Dark` - True-colour palette tuned for dark terminal backgrounds.
 * * `Light` - True-colour palette tuned for light terminal backgrounds.
 * * `Sixteen` - The sixteen ANSI colours, for terminals without true colour.
 * * `Mono` - No colour at all; meaning is carried by text and reverse video.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Palette {
    Dark,
    Light,
    Sixteen,
    Mono,
}

impl Palette {
    /**
     * Resolves a palette from its command-line or configuration name.
     *
     * Matching is case-insensitive and ignores surrounding whitespace.
     * `"light"` selects [`Palette::Light`]; `"16color"`, `"16"` and `"ansi"`
     * select [`Palette::Sixteen`]; `"mono"`, `"none"` and `"nocolor"` select
     * [`Palette::Mono`]. Anything else falls back to [`Palette::Dark`].
     *
     * # Arguments
     *
     * * `name` (`&str`) - The palette name to resolve.
     *
     * # Returns
     *
     * The matching `Palette`.
     */
    pub fn from_name(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "light" => Palette::Light,
            "16color" | "16" | "ansi" => Palette::Sixteen,
            "mono" | "none" | "nocolor" => Palette::Mono,
            _ => Palette::Dark,
        }
    }

    /**
     * Returns the canonical name of this palette.
     *
     * The name round-trips through [`Palette::from_name`] and is suitable for
     * display or for writing back to the configuration file.
     *
     * # Arguments
     *
     * * `self` (`Palette`) - The palette being read; it is `Copy`, so the
     *   receiver is taken by value.
     *
     * # Returns
     *
     * A `&'static str` of `"dark"`, `"light"`, `"16color"` or `"mono"`.
     */
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

/**
 * The resolved colours and styles used by every renderer.
 *
 * A theme is built once at start-up from the palette name and the `NO_COLOR`
 * setting, then shared by reference. Colour is only used to carry meaning, and
 * every meaning is also available as text, so monochrome users lose nothing.
 *
 * # Fields
 *
 * * `palette` (`Palette`) - The palette this theme was built from.
 * * `ascii` (`bool`) - Draw panels with `+ - |` instead of Unicode box drawing.
 * * `allow` (`Color`) - Colour for ALLOW actions.
 * * `deny` (`Color`) - Colour for DENY actions.
 * * `reject` (`Color`) - Colour for REJECT actions and medium risk.
 * * `limit` (`Color`) - Colour for LIMIT actions.
 * * `accent` (`Color`) - Colour for titles and commands.
 * * `text` (`Color`) - Default body text colour.
 * * `dim` (`Color`) - Colour for secondary text.
 * * `border` (`Color`) - Colour for panel borders.
 * * `ok` (`Color`) - Colour for success states and low risk.
 * * `warn` (`Color`) - Colour for warnings.
 * * `danger` (`Color`) - Colour for errors and high or critical risk.
 * * `info` (`Color`) - Colour for informational text.
 * * `selected_fg` (`Color`) - Foreground of the selected row.
 * * `selected_bg` (`Color`) - Background of the selected row.
 */
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
    /**
     * Builds a theme from a palette name, optionally forcing monochrome.
     *
     * When `force_mono` is set the palette is [`Palette::Mono`] regardless of
     * `name`, which is how `NO_COLOR` and `--no-color` are honoured.
     *
     * # Arguments
     *
     * * `name` (`&str`) - The palette name, resolved with
     *   [`Palette::from_name`].
     * * `force_mono` (`bool`) - Whether to ignore `name` and use no colour.
     *
     * # Returns
     *
     * A `Theme` populated with the colours of the chosen palette.
     */
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

    /**
     * Builds the true-colour palette for dark terminal backgrounds.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * A `Theme` using the dark RGB palette with Unicode borders.
     */
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

    /**
     * Builds the true-colour palette for light terminal backgrounds.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * A `Theme` using darker RGB colours that stay legible on white.
     */
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

    /**
     * Builds the palette restricted to the sixteen ANSI colours.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * A `Theme` using named ANSI colours, for terminals without true colour.
     */
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

    /**
     * Builds the colourless palette.
     *
     * Every colour is [`Color::Reset`], so meaning is carried only by text,
     * badges and reverse video.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * A `Theme` whose palette is [`Palette::Mono`].
     */
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

    /**
     * Reports whether this theme uses no colour.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The theme being read.
     *
     * # Returns
     *
     * `true` when the palette is [`Palette::Mono`]; otherwise, `false`.
     */
    pub fn is_mono(&self) -> bool {
        self.palette == Palette::Mono
    }

    /**
     * Switches the theme to ASCII box drawing.
     *
     * Consumes and returns the theme so it can be chained onto
     * [`Theme::new`].
     *
     * # Arguments
     *
     * * `self` (`Theme`) - The theme being modified; it is taken by value and
     *   returned.
     * * `ascii` (`bool`) - Whether panels should use `+ - |` instead of Unicode
     *   box drawing.
     *
     * # Returns
     *
     * The same `Theme` with its `ascii` flag set.
     */
    pub fn with_ascii(mut self, ascii: bool) -> Self {
        self.ascii = ascii;
        self
    }

    /**
     * Returns a bordered panel in this theme's border style and character set.
     *
     * Rounded Unicode borders are used normally; when the theme is in ASCII
     * mode, plain borders drawn with [`ASCII_BORDERS`] are used instead.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The theme being read.
     *
     * # Returns
     *
     * A `Block<'static>` with no title, ready to be given to a widget.
     */
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

    /**
     * Returns a bordered panel with a title in the theme's accent style.
     *
     * The border comes from [`Theme::block`], so it follows the theme's ASCII
     * setting.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The theme being read.
     * * `title` (`&str`) - The title text drawn in the panel's top border.
     *
     * # Returns
     *
     * A `Block<'static>` carrying the styled title.
     */
    pub fn titled(&self, title: &str) -> Block<'static> {
        self.block()
            .title(ratatui::text::Span::styled(title.to_string(), self.title()))
    }

    /**
     * Returns the colour that represents a rule action.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The theme being read.
     * * `action` (`Action`) - The action to colour.
     *
     * # Returns
     *
     * The `Color` for ALLOW, DENY, REJECT or LIMIT.
     */
    pub fn action_color(&self, action: Action) -> Color {
        match action {
            Action::Allow => self.allow,
            Action::Deny => self.deny,
            Action::Reject => self.reject,
            Action::Limit => self.limit,
        }
    }

    /**
     * Returns the colour that represents a risk level.
     *
     * Critical and high risk share the danger colour, medium uses the reject
     * colour, low uses the success colour and informational text is dimmed.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The theme being read.
     * * `level` (`RiskLevel`) - The risk level to colour.
     *
     * # Returns
     *
     * The `Color` for the given level.
     */
    pub fn risk_color(&self, level: RiskLevel) -> Color {
        match level {
            RiskLevel::Critical | RiskLevel::High => self.danger,
            RiskLevel::Medium => self.reject,
            RiskLevel::Low => self.ok,
            RiskLevel::Info => self.dim,
        }
    }

    /**
     * Returns the style used to draw text about a risk level.
     *
     * The style uses [`Theme::risk_color`] and is additionally bold for
     * critical risk and in monochrome mode, where colour alone cannot convey
     * severity.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The theme being read.
     * * `level` (`RiskLevel`) - The risk level to style.
     *
     * # Returns
     *
     * The `Style` for the given level.
     */
    pub fn risk_style(&self, level: RiskLevel) -> Style {
        let style = Style::new().fg(self.risk_color(level));
        if level == RiskLevel::Critical || self.is_mono() {
            style.add_modifier(Modifier::BOLD)
        } else {
            style
        }
    }

    /**
     * Returns the bold style used to draw a rule action.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The theme being read.
     * * `action` (`Action`) - The action to style.
     *
     * # Returns
     *
     * A bold `Style` in the action's colour.
     */
    pub fn action_style(&self, action: Action) -> Style {
        Style::new()
            .fg(self.action_color(action))
            .add_modifier(Modifier::BOLD)
    }

    /**
     * Returns the bold accent style used for titles and commands.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The theme being read.
     *
     * # Returns
     *
     * A bold `Style` in the accent colour.
     */
    pub fn title(&self) -> Style {
        Style::new().fg(self.accent).add_modifier(Modifier::BOLD)
    }

    /**
     * Returns the style used for secondary, de-emphasized text.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The theme being read.
     *
     * # Returns
     *
     * A `Style` in the dim colour.
     */
    pub fn dimmed(&self) -> Style {
        Style::new().fg(self.dim)
    }

    /**
     * Returns the style used for ordinary body text.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The theme being read.
     *
     * # Returns
     *
     * A `Style` in the text colour.
     */
    pub fn text_style(&self) -> Style {
        Style::new().fg(self.text)
    }

    /**
     * Returns the style used to highlight the selected row or option.
     *
     * In monochrome mode this is reverse video; otherwise it is the selected
     * foreground on the selected background, in bold.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The theme being read.
     *
     * # Returns
     *
     * The `Style` for a selected item.
     */
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

    /**
     * Returns the style used for panel borders and separators.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The theme being read.
     *
     * # Returns
     *
     * A `Style` in the border colour.
     */
    pub fn border_style(&self) -> Style {
        Style::new().fg(self.border)
    }

    /**
     * Returns the risk badge for a level.
     *
     * In colour mode this is a single glyph (`✖`, `▲`, `◆`, `✓` or `·`); in
     * monochrome mode it falls back to the level's ASCII text badge such as
     * `[!!]` or `[ok]`, so the meaning survives without colour.
     *
     * # Arguments
     *
     * * `self` (`&self`) - The theme being read.
     * * `level` (`RiskLevel`) - The risk level to render as a badge.
     *
     * # Returns
     *
     * A `String` containing the badge text.
     */
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
    /**
     * Checks that palette names resolve case-insensitively and that unknown
     * names fall back to the dark palette.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test on a wrong palette.
     */
    fn palettes_can_be_selected_by_name() {
        assert_eq!(Palette::from_name("light"), Palette::Light);
        assert_eq!(Palette::from_name("MONO"), Palette::Mono);
        assert_eq!(Palette::from_name("16color"), Palette::Sixteen);
        assert_eq!(Palette::from_name("nonsense"), Palette::Dark);
    }

    #[test]
    /**
     * Checks that forcing monochrome resets every colour.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test when a colour remains.
     */
    fn monochrome_has_no_colours_at_all() {
        let theme = Theme::new("dark", true);
        assert_eq!(theme.allow, Color::Reset);
        assert_eq!(theme.danger, Color::Reset);
        assert!(theme.is_mono());
    }

    #[test]
    /**
     * Checks that monochrome selection uses reverse video.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test on a different modifier.
     */
    fn mono_mode_uses_reverse_video_for_selection() {
        let theme = Theme::new("mono", false);
        assert_eq!(theme.selected().add_modifier, Modifier::REVERSED);
    }

    #[test]
    /**
     * Checks that risk levels map to the expected theme colours.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test on a wrong mapping.
     */
    fn risk_levels_map_to_distinct_colours() {
        let theme = Theme::new("dark", false);
        assert_eq!(theme.risk_color(RiskLevel::Critical), theme.danger);
        assert_eq!(theme.risk_color(RiskLevel::Low), theme.ok);
        assert_eq!(theme.risk_color(RiskLevel::Info), theme.dim);
    }

    #[test]
    /**
     * Checks that ASCII mode sets the flag and uses ASCII border characters.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test on a wrong border set.
     */
    fn ascii_mode_replaces_the_box_drawing() {
        let theme = Theme::new("dark", false).with_ascii(true);
        assert!(theme.ascii);
        assert_eq!(ASCII_BORDERS.top_left, "+");
        assert_eq!(ASCII_BORDERS.horizontal_top, "-");
        assert_eq!(ASCII_BORDERS.vertical_left, "|");
    }

    #[test]
    /**
     * Checks that risk badges fall back to ASCII text in monochrome mode.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test on a wrong badge.
     */
    fn badges_are_text_in_mono_mode() {
        let theme = Theme::new("mono", false);
        assert_eq!(theme.badge(RiskLevel::Critical), "[!!]");
        assert_eq!(theme.badge(RiskLevel::Low), "[ok]");
    }
}
