# Testing

## Automated

```sh
cargo test                                  # unit + integration, no root, no terminal required
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

What the suite covers:

| Area | Where | What is checked |
|---|---|---|
| `ufw status` parsing | `src/core/parse.rs` | inactive, empty, comments, `(log)`, application profiles, IPv6, interfaces, `FWD`, and a 26+ character `To` column that removes the padding gap that breaks byte-offset parsers |
| Command building | `src/core/command.rs` | exact argument vectors, the short `allow 22/tcp` form, `from` before `to`, deleting without the comment, inverse of every change, and the `ufw route …` / `ufw route insert NUM …` / `ufw route delete …` forms used for forwarding rules |
| Plain English | `src/core/explain.rs` | sentence shape for allow / deny / limit / outbound / apps / ranges / notes |
| Risk | `src/core/risk.rs` | boundaries between critical, high, medium, low, info; profile resolution; shadow detection |
| Simulation | `src/core/simulate.rs` | built-in rules first, first match wins, default policy, interfaces, protocols, ranges, apps, pending drafts, shadowing, forwarded packets and the routed default policy |
| Lockout guard | `src/core/lockout.rs` | one case per row of the safety table, plus "not over SSH" |
| Presets | `src/core/presets.rs` | each recipe's commands, preconditions, and blocked reasons, including the tunnel-forwarding recipe |
| Undo | `src/core/undo.rs` | ordering, JSON round trip, corrupt file handling, ids after reload |
| Watchdog | `src/watchdog.rs` | cancel marker wins, inverse runs after the delay, missing state file |
| Widgets | `src/ui/*` | every tab renders at 40×12, 120×40 and larger without panicking; key flows via `tests/app_flow.rs` |
| Fake `ufw` | `tests/backend_ufw.rs` | the real backend against a shell script: argument vectors, dry run, delete by number, ufw's own error text, not-root detection, missing binary |

The fake-`ufw` tests are the reason the write path is testable at all: `UfwCli::for_testing(path)` points
the backend at a script that replays captured output and records what it was asked to run.

## Manual (needs a VM with ufw and an SSH session)

Run these in a disposable virtual machine, not on anything you care about.

1. **Read-only mode.** As a normal user: `ufw-manager-tui`. Expect the "RULES HIDDEN" banner, correct
   firewall on/off and log level from `/etc/ufw/ufw.conf`, and `X` prompting for sudo.
2. **Enable safely.** Over SSH, with a rule already allowing port 22: `sudo ufw-manager-tui`, Home tab, `Space`.
   Expect a warning, a confirmation dialog, the watchdog banner, and the firewall to be on afterwards.
   Press `Y`, then check `ufw status` from another shell.
3. **Enable without an SSH rule.** Remove the SSH rule, then try `Space`. Expect a *blocked* dialog
   explaining that you would lose the session.
4. **Watchdog.** Allow 22, then enable the firewall and let the countdown expire without pressing `Y`.
   The watchdog should run `ufw disable` and you should stay connected.
5. **Shadowing.** Add `allow 22/tcp` from anywhere, then `allow 22/tcp` from `192.168.1.0/24`. On the Rules
   tab the second rule should be marked "never reached"; Test tab should show it in the trace.
6. **Undo.** Make three changes, press `u` three times. `ufw status numbered` should match where you started.
7. **Counters.** Add a `limit` rule, reload, and confirm that the HITS column shows `—` rather than an
   invented number for the rules whose alignment failed.
8. **Logs.** With logging on, attempt a connection to a closed port from another host. The Activity tab
   should show it aggregated, and `B` should offer to block the source.
9. **Terminal hygiene.** Quit with `q`; the terminal must be usable. Then `kill -TERM` the process and check
   again. As a last resort `reset` recovers a terminal left in raw mode by `kill -9`.
10. **No colour.** `NO_COLOR=1 ufw-manager-tui --demo` and `--theme mono`: risk must still be readable as
    `[!!] [!] [~] [ok]`.

## Snapshot-style review

The UI is deterministic under the mock backend, so a rendered screen can be compared as text:

```sh
cargo test --lib ui:: -- --nocapture
```

To eyeball a screen while developing, `ufw-manager-tui --demo` plus `--theme mono` is the fastest way to check
that nothing depends on colour.
