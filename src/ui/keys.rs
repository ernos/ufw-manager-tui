//! Key bindings, as data.
//!
//! The footer hints and the Help screen are both generated from these tables, so they cannot drift
//! apart from the keys that are actually handled.

use crate::app::Tab;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hint {
    pub keys: &'static str,
    pub label: &'static str,
}

const fn hint(keys: &'static str, label: &'static str) -> Hint {
    Hint { keys, label }
}

/// Context-sensitive hints, most important first. The footer drops from the end when it runs out
/// of width, so the first entries must be the ones a beginner needs most.
const HOME_HINTS: &[Hint] = &[
    hint("↑↓", "select"),
    hint("ENTER", "fix"),
    hint("SPACE", "firewall on/off"),
    hint("l", "log level"),
    hint("u", "undo"),
    hint("?", "help"),
];

const RULES_HINTS: &[Hint] = &[
    hint("↑↓", "select"),
    hint("ENTER", "details"),
    hint("a", "add"),
    hint("e", "edit"),
    hint("d", "delete"),
    hint("t", "test"),
    hint("x", "move"),
    hint("/", "filter"),
    hint("u", "undo"),
    hint("?", "help"),
];

const ADD_HINTS: &[Hint] = &[
    hint("↑↓", "choose"),
    hint("ENTER", "next"),
    hint("ESC", "back"),
    hint("?", "help"),
];

const TEST_HINTS: &[Hint] = &[
    hint("TAB", "next field"),
    hint("ENTER", "simulate"),
    hint("→", "direction"),
    hint("?", "help"),
];

const ACTIVITY_HINTS: &[Hint] = &[
    hint("↑↓", "select"),
    hint("SPACE", "pause"),
    hint("B", "block source"),
    hint("c", "clear"),
    hint("?", "help"),
];

const PRESET_HINTS: &[Hint] = &[
    hint("↑↓", "select"),
    hint("ENTER", "apply"),
    hint("?", "help"),
];

const HELP_HINTS: &[Hint] = &[
    hint("↑↓", "scroll"),
    hint("ESC", "close"),
    hint("?", "close"),
];

/// Context-sensitive hints, most important first. The footer drops from the end when it runs out
/// of width, so the first entries must be the ones a beginner needs most.
pub fn hints(tab: Tab) -> &'static [Hint] {
    match tab {
        Tab::Home => HOME_HINTS,
        Tab::Rules => RULES_HINTS,
        Tab::Add => ADD_HINTS,
        Tab::Test => TEST_HINTS,
        Tab::Activity => ACTIVITY_HINTS,
        Tab::Presets => PRESET_HINTS,
        Tab::Help => HELP_HINTS,
    }
}

pub struct HelpSection {
    pub title: &'static str,
    pub entries: &'static [(&'static str, &'static str)],
}

pub const GLOBAL: HelpSection = HelpSection {
    title: "Everywhere",
    entries: &[
        ("TAB / SHIFT+TAB", "Next / previous tab"),
        ("1 … 7", "Jump straight to a tab"),
        ("↑ ↓  or  k j", "Move the selection"),
        ("← →  or  h l", "Move between panes"),
        ("ENTER", "Do the obvious thing with the selection"),
        ("ESC", "Cancel, go back, or close a dialog"),
        ("r", "Re-read the firewall"),
        ("X", "Ask sudo for privileges (read-only mode only)"),
        ("u", "Undo the last change"),
        ("?", "This help"),
        ("q", "Quit"),
        ("type", "While typing a value (e.g. an address) the letter and digit shortcuts are unbound"),
    ],
};

pub const RULES: HelpSection = HelpSection {
    title: "Rules",
    entries: &[
        ("a", "Add a rule (guided)"),
        ("e / ENTER", "Edit the selected rule"),
        ("d", "Delete the selected rule"),
        ("y", "Duplicate the selected rule"),
        ("x", "Move the selected rule up, down or to the top"),
        ("t", "Test traffic against this rule"),
        ("/", "Filter the list"),
        ("n", "Edit the note on the selected rule"),
    ],
};

pub const DIALOGS: HelpSection = HelpSection {
    title: "In a dialog",
    entries: &[
        ("ENTER", "Apply"),
        ("ESC", "Cancel"),
        ("D", "Show the output of `ufw --dry-run`"),
        ("Y", "Confirm you are still connected (watchdog)"),
    ],
};

pub const GLOSSARY: HelpSection = HelpSection {
    title: "Plain-English glossary",
    entries: &[
        ("port", "A numbered door into a computer. SSH uses 22, a web server uses 80 and 443."),
        ("ALLOW / DENY", "Let traffic through, or silently drop it."),
        ("REJECT", "Drop it, but tell the sender it was refused."),
        ("LIMIT", "Allow it, but block an address that tries repeatedly. Good for SSH."),
        ("IN / OUT", "IN means somebody connecting to this machine. OUT means this machine connecting out."),
        ("Anywhere", "Any address at all, including the whole internet."),
        ("192.168.0.0/24", "A network range: every address that starts with those three numbers."),
        ("interface", "A network card or tunnel, such as eno1, wlan0 or wg0."),
        ("rule order", "Rules are checked top to bottom and the first match wins, so specific rules go above general ones."),
        ("default policy", "What happens to traffic no rule mentioned. Should be DENY for incoming."),
        ("application profile", "A saved bundle of ports shipped by a package, e.g. 'OpenSSH' means 22/tcp."),
    ],
};

pub fn help_sections() -> [HelpSection; 4] {
    [GLOBAL, RULES, DIALOGS, GLOSSARY]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tab_has_hints_and_they_are_short_enough_for_80_columns() {
        for tab in Tab::ALL {
            let hints = hints(tab);
            assert!(!hints.is_empty(), "{tab:?} has no hints");
            // Count characters, not bytes: the arrow glyphs are multi-byte but one column wide.
            let measure = |h: &Hint| h.keys.chars().count() + h.label.chars().count() + 4;
            let width: usize = hints.iter().map(measure).sum();
            // At 80 columns the footer may drop entries, but six of them should fit.
            let first_six: usize = hints.iter().take(6).map(measure).sum();
            assert!(
                first_six <= 80 && width <= 120,
                "{tab:?} footer hints are too wide"
            );
        }
    }

    #[test]
    fn help_always_documents_how_to_quit() {
        assert!(GLOBAL.entries.iter().any(|(keys, _)| *keys == "q"));
    }

    #[test]
    fn the_glossary_explains_the_words_people_actually_get_stuck_on() {
        let terms: Vec<&str> = GLOSSARY.entries.iter().map(|(term, _)| *term).collect();
        for expected in ["port", "IN / OUT", "rule order", "default policy"] {
            assert!(terms.contains(&expected), "missing {expected}");
        }
    }
}
