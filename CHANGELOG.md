

# CHANGELOG

## Unreleased

- Forwarding (`FWD`) rules can now be created, edited and deleted. `RuleDraft` carries an outgoing interface, the command builder emits `ufw route …` (and `ufw route insert NUM …` when a rule is edited, moved or restored), and validation accepts forwarding rules instead of rejecting them. `ufw route delete NUM` is not valid, so deletion keeps using plain `ufw delete NUM`.
- The wizard gained a "Forward traffic through this machine" goal, an "Out interface" row, and a direction that cycles in → out → forward. Presets offer "Forward traffic from <tunnel> to my own network" for detected `wg*`/`tun*`/`tap*`/`tailscale*` interfaces.
- The wizard warns when a forwarding rule is drafted while `ufw` reports `disabled (routed)`, because the rule does nothing until `net/ipv4/ip_forward=1`.
- The simulator models forwarded packets: both interfaces are matched, the routed default policy decides the fallback, and switched-off kernel forwarding is reported instead of being guessed at.
- Fixed the advanced step's "To address" row, which edited the source address instead of the destination.
- Fixed editing an outgoing rule dropping its interface, which silently widened the rule.
- The Rules tab now shows forwarding rules' interfaces on the same side as `ufw status`.

## Version 0.1.8

- Fixed the bug which incorrectly deleted rules if it was the only one in the list. It incorrectly used `ufw insert 1` which generated an error due to bad code

## Version 0.1.7

- Editing, moving or undoing a rule no longer fails with `ERROR: Invalid position '1'` when that rule sits at the end of the list. `ufw` rejects `insert N` unless position `N` already exists, and the delete step of an edit leaves one position fewer, so the re-add is now emitted as a plain append when the rule belongs at (or past) the end. Editing the only rule in the list — which previously failed outright — now works.
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
