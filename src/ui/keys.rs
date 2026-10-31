//! Key bindings, as data.
//!
//! The footer hints and the Help screen are both generated from these tables, so they cannot drift
//! apart from the keys that are actually handled.

use crate::app::Tab;

/**
 * One footer hint: a key or key combination and the short label describing it.
 *
 * The footer bar and the Help screen are both generated from these values, so
 * the documentation cannot drift away from the keys that are actually handled.
 *
 * # Fields
 *
 * * `keys` (`&'static str`) - The key or combination as it should be shown, for example `"ENTER"` or `"↑↓"`.
 * * `label` (`&'static str`) - The short verb phrase describing the action.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hint {
    pub keys: &'static str,
    pub label: &'static str,
}

/**
 * Builds a [`Hint`] in a `const` context so the hint tables can be declared as
 * constants without runtime initialisation.
 *
 * # Arguments
 *
 * * `keys` (`&'static str`) - The key or key combination shown in the footer.
 * * `label` (`&'static str`) - The short description of what the key does.
 *
 * # Returns
 *
 * A `Hint` holding the two borrowed strings.
 */
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
    hint("a", "advanced edit"),
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

const SETTINGS_HINTS: &[Hint] = &[
    hint("↑↓", "select"),
    hint("ENTER", "change"),
    hint("SPACE", "skip wizard"),
    hint("?", "help"),
];

/**
 * Returns the footer hints for a tab, most important first.
 *
 * The footer drops entries from the end when it runs out of width, so the first
 * entries must be the ones a beginner needs most.
 *
 * # Arguments
 *
 * * `tab` (`Tab`) - The tab whose hints should be returned.
 *
 * # Returns
 *
 * A `&'static [Hint]` borrowing the static hint table for that tab.
 */
pub fn hints(tab: Tab) -> &'static [Hint] {
    match tab {
        Tab::Home => HOME_HINTS,
        Tab::Rules => RULES_HINTS,
        Tab::Add => ADD_HINTS,
        Tab::Test => TEST_HINTS,
        Tab::Activity => ACTIVITY_HINTS,
        Tab::Presets => PRESET_HINTS,
        Tab::Help => HELP_HINTS,
        Tab::Settings => SETTINGS_HINTS,
    }
}

/**
 * One titled block of the Help screen.
 *
 * A section groups related key bindings or glossary terms under a heading that
 * the Help renderer draws in the bold title style.
 *
 * # Fields
 *
 * * `title` (`&'static str`) - The heading shown above the entries.
 * * `entries` (`&'static [(&'static str, &'static str)]`) - Pairs of key or term and its explanation, in display order.
 */
pub struct HelpSection {
    pub title: &'static str,
    pub entries: &'static [(&'static str, &'static str)],
}

pub const GLOBAL: HelpSection = HelpSection {
    title: "Everywhere",
    entries: &[
        ("TAB / SHIFT+TAB", "Next / previous tab"),
        ("1 … 8", "Jump straight to a tab"),
        ("↑ ↓  or  k j", "Move the selection"),
        ("← →  or  h l", "Move between panes"),
        ("ENTER", "Do the obvious thing with the selection"),
        ("ESC", "Cancel, go back, or close a dialog"),
        ("r", "Re-read the firewall"),
        ("X", "Ask sudo for privileges (read-only mode only)"),
        ("u", "Undo the last change"),
        ("?", "This help"),
        ("q", "Quit"),
        (
            "type",
            "While typing a value (e.g. an address) the letter and digit shortcuts are unbound",
        ),
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

pub const ADD: HelpSection = HelpSection {
    title: "Add tab",
    entries: &[
        ("a / A", "Jump straight to the advanced step"),
        ("ENTER", "Confirm the current step"),
        ("ESC", "Go back one step"),
        (
            "Direction",
            "The advanced step cycles in → out → forward; a forwarding rule then names both interfaces",
        ),
    ],
};

pub const SETTINGS: HelpSection = HelpSection {
    title: "Settings",
    entries: &[
        ("↑↓", "Select a setting"),
        ("ENTER / ← →", "Change the selected setting"),
        ("SPACE", "Toggle the skip-wizard checkbox"),
        ("type", "Interface and address fields open a text box"),
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

/**
 * Returns the help screen's sections in display order.
 *
 * The array is a copy of the six static [`HelpSection`] constants, so the
 * caller can iterate over them without knowing their names.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * A `[HelpSection; 6]` containing the global keys, the Rules keys, the dialog
 * keys, the Add tab keys, the Settings keys and the glossary, in that order.
 */
pub fn help_sections() -> [HelpSection; 6] {
    [GLOBAL, RULES, DIALOGS, ADD, SETTINGS, GLOSSARY]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /**
     * Checks that every tab has hints and that they fit the footer widths.
     *
     * The first six hints must fit in 80 columns and the whole set in 120.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test when hints are missing
     * or too wide.
     */
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
    /**
     * Checks that the global help section documents the quit key.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test when `q` is absent.
     */
    fn help_always_documents_how_to_quit() {
        assert!(GLOBAL.entries.iter().any(|(keys, _)| *keys == "q"));
    }

    #[test]
    /**
     * Checks that the glossary covers the terms users most often misunderstand.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * This function returns no value; it fails the test when a term is missing.
     */
    fn the_glossary_explains_the_words_people_actually_get_stuck_on() {
        let terms: Vec<&str> = GLOSSARY.entries.iter().map(|(term, _)| *term).collect();
        for expected in ["port", "IN / OUT", "rule order", "default policy"] {
            assert!(terms.contains(&expected), "missing {expected}");
        }
    }
}
