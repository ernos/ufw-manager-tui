

# CHANGELOG

## Version 0.1.7

- On the Activities Page `c`did not clear the list of events.`c` now empties the log monitor as well, so the rows no longer reappear on the next tick; new traffic still shows up again.

## Version 0.1.5

- Fixed bug where editing a rule would delete the edited rule instead.

## Version 0.1.4

- Editing a rule (`e` on the Rules tab) now opens the wizard on the Advanced step when the "Skip wizard" setting is enabled, matching how adding a rule behaves.
- Added an `a` "advanced edit" shortcut on the Add tab: it jumps straight to the Advanced step from any wizard step.

## Version 0.1.3

- Added a Settings tab (digit `8`) with configurable defaults for new rules: Action, Direction, Interface, Protocol, From address, To address and Logging. Changes are saved to `config.toml` immediately.
- Added a "Skip wizard" checkbox on the Settings tab: when enabled, adding a rule opens the wizard directly on the Advanced step.

## Version 0.1.1

- Fixed bug where global shortcuts (`1`-`7` tab jumps, `q`/`r`/`u`/`?` commands) were still active while typing text, so bound keys could not be entered literally. Letter (`a-z`) and digit (`1-9`) shortcuts are now temporarily unbound whenever the app expects a string, such as an address, port, or filter in the Test tab or the wizard.

## Version 0.1.0

 Initial release version
