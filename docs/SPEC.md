# ufw-manager-tui — Product Specification

> A friendly terminal UI that lets someone who has never heard of `iptables` harden their Linux firewall
> safely — without memorising `ufw` syntax, and without locking themselves out.

**Status:** v0.1 implemented · **Target platform:** Linux (Ubuntu/Debian family, `ufw` 0.36+) · **Language:** Rust

> This document is the design record. Everything in §1–§17 is implemented and covered by tests, except
> where a section says otherwise. The differences between the design here and the shipped code are listed
> in [§20](#20-implementation-notes), and the manual verification checklist lives in
> [TESTING.md](TESTING.md).

---

## 1. Problem

A new Linux user is told "you should enable your firewall". They read the `ufw` docs, see:

```
ufw deny proto tcp to any port 80
ufw allow from 192.168.0.0/16 to any port 22 proto tcp
ufw limit 2222/tcp comment 'SSH port'
```

They do not know what `proto`, `to any port`, `LIMIT`, or `192.168.0.0/16` mean. They do not know whether
`ALLOW IN` or `ALLOW OUT` is the one that lets them SSH in. They are one wrong command away from losing
remote access to their own machine, and they have no way to check whether a rule does what they think it does
before it takes effect.

Existing tools do not solve this:

| Tool | Why it does not help a newcomer |
|---|---|
| `ufw` CLI | Correct but syntax-first; no preview, no explanation, no rollback |
| `gufw` | GTK desktop app — useless over SSH, which is exactly when firewalls matter |
| `iptables` / `nft` | Wrong abstraction level entirely |
| Monitoring dashboards | Report what happened; do not help you decide what to do |

## 2. Product definition

**ufw-manager-tui** is a terminal application that runs on top of `ufw`. It presents the firewall as a small
number of plain-English concepts, makes every change previewable and reversible, and lets the user *test*
a rule against simulated traffic before it touches the live firewall.

**One-sentence pitch:** *The firewall tool you can safely give to someone who has never used a firewall.*

### Target user

Primary: a competent computer user who is new to Linux and new to network security. They can use a terminal
and edit files, they know roughly what a port is, but they do not know `ufw` syntax or netfilter semantics.

Secondary: the experienced admin who wants a fast, safe, auditable way to manage `ufw` over SSH without
typing commands blind.

### Jobs to be done

1. *"Tell me whether my firewall is actually protecting me right now."*
2. *"Let me allow SSH back in so I can keep working — from my network only, not the whole internet."*
3. *"I run a web server. Open exactly what it needs and nothing else."*
4. *"Something is being blocked / let through and I do not know why."*
5. *"I want to check this change is safe **before** I apply it."*
6. *"I broke it. Undo."*

### Non-goals

- Raw `iptables` / `nftables` rule editing (wrong abstraction for the audience).
- NAT, port forwarding, VPN, routing configuration.
- Docker/container-managed rules (they bypass `ufw`; we detect and *warn* about them instead).
- Multi-host fleet management, remote agents, or a daemon/HTTP API.
- Desktop GUI or a web UI.
- Replacing `ufw`. **`ufw` remains the single source of truth**; we are a front end.

## 3. Design principles

1. **Explain, then act.** Every rule is shown as a plain-English sentence next to its `ufw` command. Every
   mutation is shown as the exact command that will run, and requires one confirmation.
2. **Preview beats confirmation.** `ufw --dry-run` runs first for every write so `ufw`'s own validation
   catches bad rules before anything changes.
3. **Reversible by default.** Every applied change pushes its inverse onto an undo stack.
4. **Never lock the user out.** A lockout guard blocks or warns on changes that could sever the current SSH
   session, and a detached watchdog can auto-revert a risky change if the connection dies.
5. **Arrow keys are enough.** Any task is completable with ↑ ↓ ← → Enter Esc. Letter shortcuts exist as
   accelerators and are always visible in the footer. `?` is always help.
6. **Degrade, never crash.** Unparseable `ufw` output is displayed raw with a bug hint, not panicked on. No
   colour, no Unicode, or an 80×24 terminal must still be usable.
7. **No silent surprises.** If we add anything to a rule the user did not explicitly choose (a comment tag,
   an interface), we say so in the preview.

## 4. Architecture

```
┌───────────────────────────────────────────────────────────────┐
│ TUI (ratatui + crossterm)                                     │
│   AppState  →  View (tab/screen)  →  Widgets                  │
│        ↑                             ↓                        │
│   Action / Event  ←──── key events / worker results            │
└───────────────────────────┬───────────────────────────────────┘
                            │
┌───────────────────────────▼───────────────────────────────────┐
│ Core (pure, no I/O — 100% unit testable)                      │
│   FirewallState · Rule · RuleDraft · StatusParsers            │
│   CommandBuilder · RiskClassifier · Explainer                 │
│   Simulator · UndoJournal · LockoutGuard                      │
└───────────────────────────┬───────────────────────────────────┘
                            │
┌───────────────────────────▼───────────────────────────────────┐
│ Backend trait                                                 │
│   UfwCli      (real: shells out to `ufw`, `ss`, `nft`)        │
│   MockBackend (tests + `--demo`)                              │
└───────────────────────────────────────────────────────────────┘
```

- **`backend` trait** keeps all process spawning in one place, so the whole app can be driven by a fake
  firewall in tests and demos.
- **`core`** holds only pure logic. Parsers and the simulator are tested against real captured `ufw` output.
- **Render loop** is single-threaded and calls the backend synchronously. `ufw status` takes tens of
  milliseconds, every invocation is bounded by a 10-second timeout with the child killed on expiry, and
  writes are validated with `--dry-run` first, so a spinner would add complexity without removing a
  stall. The one genuinely unbounded job — tailing the block log — runs on its own background thread and
  publishes aggregated rows through a `Mutex`, which the render loop polls.
- **`CommandBuilder`** is the only place that ever constructs a `ufw` argument vector. It emits `Vec<String>`
  (never a shell string) so no quoting or injection bugs are possible.

### Crate layout

```
ufw-manager-tui/
├── Cargo.toml
├── README.md
├── docs/
│   ├── SPEC.md              # this document
│   └── GLOSSARY.md          # in-app help content, also shipped as a file
└── src/
    ├── main.rs              # arg parsing, terminal guard, run loop
    ├── app.rs               # AppState, Action dispatch, event loop
    ├── cli.rs               # clap definitions (--demo, --readonly, --no-color, ...)
    ├── config.rs            # config.toml load/save
    ├── core/
    │   ├── mod.rs
    │   ├── rule.rs          # Rule, RuleDraft, Action, Direction, Proto, PortSpec
    │   ├── firewall.rs      # FirewallState, DefaultPolicies, LogLevel
    │   ├── parse.rs         # status/info/app/profile/ss parsers
    │   ├── command.rs       # RuleDraft -> Vec<String>, inverse commands
    │   ├── explain.rs       # rule/command -> plain English
    │   ├── risk.rs          # RiskLevel + reasons
    │   ├── simulate.rs      # packet simulator + built-in chain model
    │   ├── presets.rs       # recipe library
    │   ├── undo.rs          # UndoJournal
    │   └── lockout.rs       # LockoutGuard
    ├── backend/
    │   ├── mod.rs           # trait Backend
    │   ├── ufw.rs           # UfwCli implementation
    │   ├── probe.rs         # ss/sshd_config/ip route introspection
    │   ├── counters.rs      # nft JSON / iptables counters
    │   ├── logs.rs          # ufw.log / journalctl tail + aggregation
    │   └── mock.rs          # MockBackend with scriptable scenarios
    └── ui/
        ├── mod.rs           # layout, header, tab bar, footer, status bar
        ├── theme.rs         # colour palettes + 16-colour and mono fallbacks
        ├── keys.rs          # keymap table (data-driven, drives footer + help)
        ├── home.rs
        ├── rules.rs
        ├── wizard.rs        # add/edit wizard (modal)
        ├── test.rs          # simulator screen
        ├── activity.rs      # log tail + change journal
        ├── help.rs
        └── widgets/         # modal, table, badge, text input, confirm, toast
```

### Dependencies

| Crate | Purpose |
|---|---|
| `ratatui` 0.30 | TUI widgets and layout |
| `crossterm` 0.29 | Terminal control, raw mode, events |
| `clap` 4 (derive) | CLI flags |
| `serde` + `serde_json` | `nft -j` parsing, undo journal, mock scenarios |
| `toml` | `config.toml` |
| `ipnet` | CIDR parsing and containment for the risk classifier and simulator |
| `thiserror` | Typed errors for the core |
| `anyhow` | Top-level context |
| `directories` | XDG config/state paths |
| `crossbeam-channel` | Worker → UI channel (or `std::sync::mpsc`) |
| `unicode-width` | Correct column widths for the rules table |
| *dev:* `insta`, `tempfile` | Snapshot parser tests, temp dirs |

No async runtime. Threads are simpler here and there is no meaningful concurrency.

## 5. Information architecture

Eight top-level tabs. `Tab`/`Shift+Tab` cycles, `1`–`8` jumps directly. The tab bar is always visible with
the active tab highlighted; a one-line description of the current tab sits under it.

| # | Tab | Purpose |
|---|---|---|
| 1 | **Home** | Is my firewall on? How exposed am I? What should I fix first? |
| 2 | **Rules** | The rule list. The main workspace. |
| 3 | **Add** | Guided wizard: pick a goal, get a correct rule. |
| 4 | **Test** | Simulate traffic against the current or pending ruleset. |
| 5 | **Activity** | What is being blocked right now, and what did I just change? |
| 6 | **Presets** | Curated hardening recipes, one screen, one key. |
| 7 | **Help** | Keymap + glossary (`port`, `CIDR`, `ALLOW IN`, `LIMIT`, ...). |
| 8 | **Settings** | Defaults for new rules, and whether the wizard is skipped. |

Modals overlay any tab: **Add/Edit wizard**, **Confirm command**, **Delete confirm**, **Lockout warning**,
**Error**, **Undo confirm**, **Watchdog countdown**.

## 6. Screen specifications

### 6.1 Home

```
╭─ ufw-manager-tui ───────────────────────────────────── root@mainnet ── 15:42 ─╮
│ ▏Home │ Rules │ Add │ Test │ Activity │ Presets │ Help                    │
╰───────────────────────────────────────────────────────────────────────────╯

  FIREWALL            ● OFF        ← red, loud: this is the headline
  Default incoming    ALLOW        ⚠ risky
  Default outgoing    ALLOW
  Logging             low
  Rules               12           ▁▁ 4 open to the internet
  SSH reachable from  Anywhere     🔴

  ⚠ SUGGESTED FIXES                                          [F] Fix
  ┌───────────────────────────────────────────────────────────────────────┐
  │ 🔴 Your firewall is turned off. Everything is unprotected.            │
  │ 🟠 SSH (port 22) is open to the entire internet. Restrict it to your   │
  │    local network (192.168.1.0/24) or turn on rate limiting.            │
  │ 🟡 2 services are listening that no rule mentions: 3306 (mysqld).     │
  └───────────────────────────────────────────────────────────────────────┘

  SERVICES & EXPOSURE            from ufw show listening + ss
  PORT    PROTO  SERVICE   REACHABLE FROM   RULE
  22      tcp    sshd      Anywhere          #3  🔴
  443     tcp    nginx     Anywhere          #5  🟠
  3306    tcp    mysqld    Anywhere          (none) 🟡 blocked by default policy
  631     tcp    cupsd     localhost only    —   ✓ not reachable

  SPACE toggle firewall · F fix selected suggestion · R refresh
```

Content sources: `ufw status verbose` (status, policies, log level), `ufw status numbered` (rules),
`ufw show listening` + `ss -tulpn` (services), `ip route` (own LAN).

The **suggested fixes** list is the product's opinion, computed by the risk engine (§8). Each entry maps to
either a preset (§11) or a direct action. This is the screen that turns "I don't know what to do" into a
single keypress.

### 6.2 Rules

```
   ACT  DIR   TO                        FROM                   HITS  NOTE          RISK
 ▸ [ 1] ALLOW IN   22/tcp                Anywhere               1.2k  SSH            🔴 open to internet
   [ 2] LIMIT IN   22/tcp                192.168.1.0/24          —    Home network   🟢
   [ 3] ALLOW IN   OpenSSH               10.0.0.0/8              44    Office VPN     🟡
   [ 4] ALLOW OUT  53/udp (DNS)          Anywhere               8.9k                 ℹ
   [ 5] DENY  IN   3306/tcp              Anywhere               0                    ℹ
   [ 6] ALLOW FWD  Anywhere on wg0       Anywhere               12    WireGuard      🟡 route rule (read-only)

  #1  Allow anyone on the internet to connect to TCP port 22 (SSH) on this machine.
      ufw allow 22/tcp

  ↑↓ move   ←→ pane   ENTER details   e edit   a add   d delete   y duplicate
  / filter   x move up/down   t test this rule   r refresh   u undo
```

- Row numbers are **ufw's own rule numbers**, so they match `ufw status numbered` and the reference docs.
- `HITS` column comes from nft counters (§9.3); `—` when unavailable (non-root, `limit` rules, or counters
  disabled).
- The **detail pane** under the table shows the selected rule as a sentence, its exact `ufw` command, and its
  risk reasons. This is what teaches the user the syntax without a tutorial.
- Rules are always displayed in **evaluation order** and the header says so — the single most important
  concept in firewall configuration.
- Route (`FWD`) rules are shown but edit is disabled; deleting requires the lockout guard's extra warning.
- `/` opens an incremental filter (match action, port, address, app name, note).
- `x` opens a small reorder modal (`u`=up, `d`=down, `p`=move to top) implemented with `ufw insert N`, with
  an explicit note that reordering changes which rule wins.

### 6.3 Add — guided wizard

The wizard occupies the whole **Add tab** rather than a modal. A modal was the original plan, but the
review screen has to show the sentence, the command, the risk assessment and, optionally, a full simulation
trace — which needs more room than a dialog on an 80×24 terminal. `Esc` goes back one step; `Esc` on step 1
returns to the Rules tab. Starting the wizard from Rules (`a`) or from a rule (`e`, `y`, `n`) switches to
the Add tab with the draft prefilled.

**Step 1 — What do you want to do?**

```
  What would you like to do?
  ▸ Allow traffic in        Let something connect to this computer
    Block traffic           Stop something from connecting
    Limit connections       Allow it, but slow down repeat attempts (good for SSH)
```

**Step 2 — Who should it apply to?**

```
  Who should be able to reach it?
  ▸ Only my local network      192.168.1.0/24  (detected)
    One specific address       e.g. 203.0.113.7
    Anywhere on the internet   ⚠ anyone can try
    Advanced ›                 choose interface, direction, network mask
```

**Step 3 — What service?**

```
  Which service?
  ▸ SSH (remote login)            port 22/tcp        found: sshd listening
    Web server (HTTP/HTTPS)       80, 443/tcp
    File sharing (Samba)          137-139, 445
    Database                      3306/tcp
    App profile…                  browse ufw's profiles (OpenSSH, Nginx Full, …)
    Custom port…                  1234 or 8000:8100 or 80,443
```

**Step 4 — Review** (the important screen)

```
  ┌─ REVIEW ─────────────────────────────────────────────────────────────┐
  │                                                                      │
  │  Allow computers on your local network (192.168.1.0/24) to connect   │
  │  to this machine on TCP port 22 (SSH).                                │
  │                                                                      │
  │  Will run:                                                           │
  │    ufw allow in on eno1 from 192.168.1.0/24 to any port 22 proto tcp  │
  │        comment 'SSH from LAN'                                         │
  │                                                                      │
  │  Risk: 🟢 restricted to your local network    Order: added last (#7)  │
  │                                                                      │
  │  [T] Test this rule first   [ENTER] Apply   [ESC] Back   [A] Advanced │
  └──────────────────────────────────────────────────────────────────────┘
```

`T` runs the simulator (§9.1) against the **pending** ruleset — current rules plus the draft — and shows the
trace inline. This is the feature that removes the fear of applying a change.

`A` opens the raw form (action, direction, interface, protocol, port spec, from addr, to addr, log, comment)
with all fields pre-filled from the wizard. Escape hatch, not the primary path.

When the **Skip wizard** setting (§6.8) is enabled, `a` on the Rules tab opens the wizard directly on the
Advanced step, pre-filled from the configured defaults, so an experienced user goes straight to the raw form
and the review screen.

### 6.4 Test

```
  SIMULATE TRAFFIC                                  [ quick: SSH from LAN ▾ ]
  Direction [Incoming▾]  Interface [eno1▾]  Protocol [TCP▾]
  From  192.168.1.50  :  51000        To  192.168.1.19  :  22
                                                    [ ENTER ] Simulate

  RESULT:  ✅ ALLOWED
  ┌───────────────────────────────────────────────────────────────────────┐
  │ 1  built-in   accept  loopback interface             not matched       │
  │ 2  built-in   accept  already-established connection  not matched      │
  │ 3  built-in   drop    invalid packet                  not matched       │
  │ 4  rule #1    ALLOW   22/tcp from Anywhere            MATCHED ← stop    │
  │ …  rules #2-#6 are never evaluated for this traffic                    │
  └───────────────────────────────────────────────────────────────────────┘
  A computer at 192.168.1.50 connecting to port 22 from port 51000 would be
  ALLOWED by rule #1. Rule #2 (limit, LAN only) never gets a chance to run —
  #1 is above it and less restrictive.  [ x ] Move #2 above #1
```

The "x" action at the bottom is the fix for the single most common real-world `ufw` mistake (general rule
shadowing a specific one). Detecting shadowing is a headline feature.

The simulator evaluates the draft or live ruleset and models ufw's implicit `before.rules` behaviour
(loopback, established/related, INVALID drop, ICMP echo, DHCP, mDNS) as explicit visible steps so the user
learns the model.

### 6.5 Activity

Two panes.

**Live blocks** — `ufw.log` (or `journalctl -k`) tailed in the background, parsed and **aggregated** so a
port scan does not scroll the screen:

```
  LAST 5 MINUTES                                ▏paused  [SPACE]  [c] clear
  COUNT  LAST SEEN   SRC            DPT   PROTO  IFACE   WHAT
   412   2s ago      45.155.205.233 22    TCP    eno1    SSH brute-force attempt  🔴
    17   1m ago      192.168.1.7    3306  TCP    eno1    blocked db access
     3   4m ago      91.240.118.11  8080  TCP    eno1    web scan
                                                                 [B] Block 45.155.205.233
```

`B` creates `ufw deny from <ip>` (through the normal preview → confirm → dry-run flow). Watching real
blocked traffic is the fastest way to make a newcomer care about the firewall.

**Change journal** — everything *this app* did this session, newest first, with the inverse command and a
one-key undo. Persisted to `~/.local/state/ufw-manager-tui/journal.json` so it survives a restart.

### 6.6 Presets

One screen, arrow-selectable, each card = a single correct action with a plain-English explanation, the
command it runs, and its risk level. Enter runs it through the normal preview → dry-run → confirm → apply →
journal pipeline.

1. **Turn the firewall on (safe default)** — allow outgoing, deny incoming, keep SSH if it is currently open.
2. **Lock out the internet, keep myself in** — restrict SSH to the detected LAN.
3. **Rate-limit SSH** — `ufw limit 22/tcp`, mitigates brute force.
4. **I run a web server** — allow 80/443 from anywhere.
5. **Block an IP address** — prompts for the address.
6. **Allow a desktop app** — browse app profiles.
7. **Minimal laptop on public Wi-Fi** — deny all incoming, allow outgoing.
8. **Undo everything, back to ufw defaults** — `ufw reset`, behind the strongest warning in the app.
9. **Allow my VPN subnet** — allow in on `wg0`.
10. **Allow a game/voice server** — custom port with UDP, prompted.

Each preset declares its preconditions and is hidden or annotated when not applicable (e.g. #9 when no
`wg0` interface exists).

### 6.7 Help

- **Keymap** — generated from the same data structure that drives the footer, so it cannot drift.
- **Glossary** — `port`, `TCP vs UDP`, `ALLOW IN vs ALLOW OUT`, `DENY vs REJECT`, `LIMIT`,
  `192.168.0.0/24`, `Anywhere`, `interface`, `rule order`, `default policy`, `application profile`.
- **What ufw-manager-tui does not do** — explicit, so users know when to look elsewhere.

### 6.8 Settings

The Settings tab (digit `8`) configures the defaults applied to **new** rules and whether the guided
wizard is skipped. Every change is written to `config.toml` immediately.

```
  ┌─ DEFAULTS FOR NEW RULES ─────────────────────────────────────────────┐
  │  ▸ Action            allow                                            │
  │    Direction         in                                               │
  │    Interface         any                                              │
  │    Protocol          any                                              │
  │    From address      any                                              │
  │    To address        any                                              │
  │    Logging           off                                              │
  │    [ ] Skip wizard (start new rules on Advanced)                      │
  └───────────────────────────────────────────────────────────────────────┘
  Changes are saved to config.toml immediately.
  ENTER / ← → change    SPACE toggle checkbox    ESC cancel
```

- **Toggle rows** (Action, Direction, Protocol, Logging) cycle to the next value on `ENTER`, `←` or `→`.
- **Text rows** (Interface, From address, To address) open a text input on `ENTER`; empty or `any` input
  means "any".
- **Skip wizard** (`SPACE`) makes `a` on the Rules tab open the wizard directly on the Advanced step,
  pre-filled from these defaults.
- Editing or duplicating an existing rule always uses that rule's own values, never these defaults.

## 7. Rule model

A `Rule` is the parsed form of one `ufw status numbered` row. A `RuleDraft` is the editable form used by the
wizard, the raw form, and the simulator.

```rust
struct Rule {
    number: u32,                 // ufw's own number ([ 1] == 1)
    action: Action,              // Allow | Deny | Reject | Limit
    direction: Direction,        // In | Out | Forward
    interface_in: Option<String>,
    interface_out: Option<String>,
    protocol: Protocol,          // Tcp | Udp | Any | Esp | Ah | Gre | Igmp
    from: Endpoint,              // addr: Option<IpNet> + port: PortSpec + app: Option<String>
    to: Endpoint,
    log: LogMode,                // None | Log | LogAll
    comment: Option<String>,     // ufw 0.36 native comment
    v6: bool,
    route: bool,                 // FWD rule -> read-only in v1
}

enum PortSpec {
    Any,
    Single(u16),
    Range(u16, u16),
    List(Vec<PortEntry>, Protocol),
    Service(String),             // resolved via /etc/services
    App(String),                 // ufw application profile name
}
```

### Notes: native ufw comments, not a sidecar file

The brief asked for per-rule notes in a sidecar file. **ufw 0.36 supports native rule comments** and prints
them in `ufw status`:

```
ufw limit 2222/tcp comment 'SSH port'
[ 1] 2222/tcp   LIMIT IN   Anywhere    # SSH port
```

Notes therefore become `ufw ... comment '<text>'`. This is strictly better than a sidecar:

- no desync when rules change outside the app, or when ufw renumbers
- survives `ufw reset` → restore, rule export, and every other ufw tool
- visible to `ufw status` with no ufw-manager-tui installed
- no extra state file to corrupt

Constraint: comments cannot be updated in place by `insert`/`prepend`; editing a rule's note is done as
delete + re-add at the same position. Create comments are tagged with a zero-width marker prefix so the app
can tell its own notes from manually written ones. If a future ufw drops comments, fall back to a sidecar —
the `NoteStore` trait exists for that.

## 8. Risk engine

Pure function `risk(rule, state) -> (RiskLevel, Vec<Reason>)`. Reasons are user-facing strings, not codes.

| Level | Badge | Meaning |
|---|---|---|
| Critical | 🔴 | Unprotected or directly exploitable |
| High | 🟠 | Reachable from the entire internet |
| Medium | 🟡 | Reachable from a large network, or a rule whose effect is unclear |
| Low | 🟢 | Restricted to a specific host or the local network |
| Info | ℹ | Deny/reject rules and outbound rules |

Signals:

- Firewall disabled, or default incoming `allow` → **Critical** at the *state* level (Home headline).
- `allow` + `from Anywhere` + port in the *sensitive set* (22, 23, 21, 25, 111, 135, 139, 445, 1433, 1521,
  2049, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 9200, 11211, 27017) → **Critical**.
- `allow` + `from Anywhere` on any other port → **High**.
- `allow` + source inside RFC1918/link-local → **Low** if `/24` or narrower, **Medium** if broader.
- `allow` + single host source → **Low**.
- `allow` + `out` → **Info**, with a note that outbound rules are about data leaving the machine.
- `deny`/`reject` → **Info**.
- **Shadowing**: a broader `allow` earlier in the list makes a later, narrower rule unreachable for the
  traffic it targets → **Medium** on both rules, "this rule is never reached for <traffic>".
- **Exposure gap**: a listening socket is reachable and no rule mentions it → **Medium** suggestion.

`Explain` turns a rule into one sentence and a `Reason` into one short clause. Both are pure and snapshot
tested so the tone stays consistent.

## 9. Testing firewall behaviour

Three independent mechanisms, each honest about its confidence.

### 9.1 Static packet simulator

Fully deterministic, no privileges, works offline, and runs against a **pending** ruleset.

Inputs: direction, interface, protocol, source address + port, destination address + port, and optionally
TCP flags, connection state, IPv4/IPv6.

Evaluation order mirrors ufw's real `before.rules` → `user.rules` → `after.rules` chain:

1. loopback → accept
2. invalid packet → drop
3. already-established/related → accept (stateful)
4. ICMP echo / required ICMPv6 / DHCP / mDNS / UPnP → accept
5. user rules 1..n in order, first match wins
6. default policy for the direction

Each step is rendered with `not matched` / `MATCHED`, and evaluation stops at the first match. The output
explicitly names rules that were skipped **because a broader rule above them matched first**.

The UI labels this "simulated, simplified" with a link to the modelled built-ins. Model inaccuracies are
treated as bugs; there is a golden-file test per built-in step.

### 9.2 Live block log

Tail `/var/log/ufw.log` if readable, else `journalctl -k -f`. Parse `[UFW BLOCK]` / `[UFW AUDIT]` lines into
`{ timestamp, iface, src, dst, proto, spt, dpt, len }`, aggregate on `(src, proto, dpt)` over a rolling
window, and present counts + last-seen. Clearly labelled as **what actually happened**, not a prediction.

### 9.3 Per-rule hit counters

`ufw` writes via iptables-nft on modern Ubuntu, so counters are read from `nft -j list ruleset` (JSON, no
text parsing) with `iptables -L <chain> -v -n` as a fallback for legacy backends.

Chain of interest: `ufw-user-input`, `ufw-user-output`. Rules are matched to ufw rule numbers **by position**
inside the chain, which is how ufw appends them.

Honest limitations, surfaced in the UI:
- Requires root.
- `LIMIT` rules expand into several iptables rules, so their counters are shown as a combined "rate-limited"
  figure, or `—` if the mapping is ambiguous. They are never silently misattributed.
- Counters reset on `ufw reload`, `enable`, and default-policy changes; the header says "hits since last
  reload".
- If chain position and rule count disagree, the whole column is shown as `—` rather than risk misleading
  numbers. **Wrong numbers are worse than no numbers.**

## 10. Safety model

### 10.1 Command preview and validation (every write)

```
┌─ CONFIRM ────────────────────────────────────────────────────────────┐
│ Will run:                                                            │
│   ufw allow in on eno1 from 192.168.1.0/24 to any port 22 proto tcp   │
│       comment 'SSH from LAN'                                         │
│                                                                      │
│ This means: allow computers on your local network to connect using   │
│ SSH.                                                                 │
│                                                                      │
│ ufw's own validation: ✓ passed  (ufw --dry-run)                       │
│                                                                      │
│  [ENTER] Apply    [ESC] Cancel    [D] Show dry-run output            │
└──────────────────────────────────────────────────────────────────────┘
```

- The command is always shown as `argv`, never a shell string.
- `ufw --dry-run <args>` runs first; a failure aborts with ufw's stderr displayed verbatim.
- `--yes` / `-y` skips confirmation for scripted use; it does not skip the dry run.

### 10.2 Lockout guard

Runs before any write. Detects the current session (`SSH_CONNECTION`, `SSH_TTY`) and the rule that permits
it (a matching `allow`/`limit` on the SSH port). It then classifies the pending change:

| Situation | Behaviour |
|---|---|
| Change cannot affect the current session | Proceed |
| Deleting/weakening the rule that permits the current session | **Block** with a modal offering "restrict to my LAN instead" |
| `ufw enable` while an SSH session is open | **Warn** + offer to add the SSH allow rule first |
| Changing default policy (flushes chains, drops connections) | **Warn** + reconcile timer (§10.3) |
| `ufw reset`, or anything matching `*` | **Hard block** unless `--force` |
| Not over SSH | Downgrade to an informational note |

The guard's checks are pure functions over the parsed state plus the pending command, so they are unit
tested case by case.

### 10.3 Reconcile watchdog (P2)

For changes that can sever a remote session, ufw-manager-tui spawns a **detached** helper before applying:

```
ufw-manager-tui --internal-revert-after 60 --journal <path> --nonce <id>
```

The UI shows a countdown banner. Pressing `y` writes the nonce file, which cancels the revert. If the user
gets disconnected and cannot confirm, the helper applies the inverse commands from the journal after 60s and
the machine becomes reachable again. Every other ufw tool makes you do this by hand; it is the strongest
safety argument for this app.

### 10.4 Undo

Each applied action records `{description, forward: Vec<String>, inverse: Vec<String>, rule_number_hint,
timestamp}`. Undo runs the inverse through the same preview → dry-run → confirm pipeline(abbreviated to a
single confirm). Rules are never restored by rewriting `user.rules` — that is what corrupts rulesets.

### 10.5 Backups

Before the first write of a session, copy `/etc/ufw/user.rules`, `user6.rules`, and `ufw.conf` to
`/var/backups/ufw-manager-tui/<timestamp>/` (root-only, 0600). Offer `R` to restore from the newest backup in the
Help/diagnostics screen. This exists purely as an emergency exit if the app itself misbehaves.

## 11. Privilege model

`ufw` requires root. Modes:

| Mode | How it is entered | Capabilities |
|---|---|---|
| **Read-only** | default when `geteuid() != 0` | Home status from `/etc/ufw/ufw.conf` (world-readable), app profiles from `/etc/ufw/applications.d`, live log tail (if group `adm`), help. Banner: "Not running as root — rules are hidden. Run `sudo ufw-manager-tui`." |
| **Full** | launched under `sudo`/`doas` | Everything |
| **Escalate** | `X` in read-only mode, or automatically on the first write | Leave raw mode, run `sudo -v` on the real terminal, re-enter raw mode, reload state |

Notes:
- `/etc/ufw/user.rules` is `root:root 0640`, so rule *reading* genuinely needs root; the read-only mode is
  honest about that rather than pretending.
- `--readonly` forces read-only even as root (useful for auditing).
- The app never writes to `/etc/ufw/*` directly; only `ufw` does.
- Escalation is done by leaving raw mode, invoking `sudo -v` with the inherited TTY, and restoring the
  terminal afterwards. If it fails, the action is cancelled with a toast, never half-applied.
  `sudo -v` only validates the credential cache, so once escalated every `ufw` (and `nft`) invocation is
  run through `sudo` to actually use those credentials; the app never re-executes itself.
- `--no-escalate` disables it for environments where sudo prompts are forbidden.

## 12. Keybindings

Data-driven table in `ui/keys.rs`; the footer and the Help screen are both generated from it, so they cannot
drift. `↑↓←→` + `Enter` + `Esc` alone complete every task.

### Global

| Key | Action |
|---|---|
| `Tab` / `Shift+Tab` | Next / previous tab |
| `1`–`7` | Jump to tab |
| `↑` `↓` / `k` `j` | Move selection |
| `←` `→` / `h` `l` | Move focus between panes |
| `Enter` | Primary action on the selection |
| `Esc` | Cancel / go back / close modal |
| `r` | Refresh from ufw |
| `u` | Undo last change |
| `?` | Help |
| `q` | Quit (`Q` from a modal; never quits mid-write) |

### Rules tab

| Key | Action |
|---|---|
| `a` | Add (jump to wizard) |
| `e` / `Enter` | Edit selected rule |
| `d` | Delete selected rule |
| `y` | Duplicate selected rule |
| `x` | Reorder (move up/down/to top) |
| `t` | Test traffic against this rule |
| `/` | Filter |
| `Space` | Enter the detail pane |

### Footer

Always present, context sensitive, showing at most six hints plus `?`:

```
 ↑↓ select   ENTER edit   a add   d delete   t test   ? help
```

The footer is the primary discoverability mechanism in a terminal app; it is never blank and never
truncated — hints drop off in priority order to fit the terminal width.

## 13. Visual design

- **Layout:** header (app name, host, clock, privilege badge), tab bar, one-line tab description, body,
  footer hints, and a transient **status line** for toasts/errors (never a modal for something recoverable).
- **Colour** communicates meaning, never decoration:
  - risk: red / orange / yellow / green / dim
  - verbs: allow = green, deny = red, reject = orange, limit = yellow
  - state: enabled = green dot, disabled = red dot, unknown = yellow
  - chrome: dim borders, bold selection bar with reversed colours
- **Themes:** `dark` (default), `light`, `16color` (auto-detected from `COLORTERM`/`TERM`), and `mono`
  (respects `NO_COLOR`; risk is then shown with text badges `[!!]` `[!]` `[~]` `[ok]`).
- **Glyphs:** box drawing with an ASCII fallback set (`+-|`) when `LANG` is not UTF-8 or the terminal is
  `dumb`.
- **Minimum size:** warns below 80×24 and renders a scaled-down layout rather than garbage.
- **Accessibility:** no information conveyed by colour alone (badges and words always present); respects
  `NO_COLOR`, `TERM=dumb`; every action reachable by arrows; no timed modals except the watchdog countdown,
  which can be dismissed.
- **Never** use a spinner that blocks input; background work is indicated in the status line with age.

## 14. Backend contract

All ufw invocations set `LC_ALL=C` and `LANG=C` (ufw output is localised and we parse it), and run with a
timeout (default 10s) with the child killed on expiry.

| Purpose | Command | Parse |
|---|---|---|
| State + rules | `ufw status numbered` | §14.1 |
| Policies + log level | `ufw status verbose` | §14.2 |
| App profiles | read `/etc/ufw/applications.d/*` INI, fallback `ufw app list`, `ufw app info NAME` | title/description/ports |
| Listening services | `ss -tulpnH` | port/proto/addr/process |
| Counters | `nft -j list ruleset`, fallback `iptables -L ufw-user-input -v -n` | §9.3 |
| Blocks | tail `/var/log/ufw.log`, fallback `journalctl -k -f` | §9.2 |
| LAN detection | `ip -o -4 addr show scope global`, `ip route show default` | CIDR + iface |
| SSH port | `SSH_CONNECTION`, `sshd_config` `Port`, `ss -tlnp` | port |
| Validate | `ufw --dry-run <args>` | exit code + stderr |
| Apply | `ufw <args>` | exit code + stderr |

### 14.1 `ufw status numbered` format (verified against ufw 0.36.2 source)

```
Status: active
                     ← blank line
     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere                   # SSH
[ 2] Anywhere on eth0           ALLOW      192.168.0.0/16
[ 3] OpenSSH                    ALLOW IN    10.0.0.0/8
[ 4] 53/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 5] Anywhere on wg0            ALLOW FWD   Anywhere
```

Parsing rules, derived from `backend_iptables.py::get_status`:

- Rule rows are prefixed with `[%2d] ` (one space, right-aligned to width 2, then `]` and a space).
- Columns are `%-26s %-12s%-26s` — **padded but never truncated**, so a long `To` shifts later columns right.
  Parse by splitting on runs of 2+ spaces, scanning left to right, never by fixed byte offsets.
- `Action` is `<ACTION>[ <DIR>]` where `ACTION ∈ {ALLOW, DENY, REJECT, LIMIT}` and `DIR ∈ {IN, OUT, FWD}`.
  `DIR` is omitted only for non-numbered, non-verbose listings, so in `status numbered` it is always present
  or is `FWD`.
- A trailing ` # comment` may follow the `From` column. Split on the **first** ` # `.
- An optional ` (log)` or ` (log-all)` attribute may appear after the `From` column, before the comment.
- `To`/`From` may be `Anywhere`, `Anywhere on <iface>`, `Anywhere (v6)`, `<addr>`, `<port>`, `<port>/<proto>`,
  `<addr> on <iface>`, `<addr> <port>`, or an application profile name when the rule uses `app`.
- `Status: inactive` (single line, exact) when ufw is not loaded — no header, no rows.
- Row numbering is ufw's internal order: **all IPv4 rules first, then all IPv6 rules**, regardless of
  direction. `ufw delete N` uses this same numbering, so our numbers are directly deletable.
- App rules with the same `(action, app, src, dst, direction)` tuple are collapsed into one row by ufw, so we
  show what ufw shows and never invent rows.

Because this is a text format, the parser:

- returns `Vec<Rule>` plus a `Vec<UnparsedRow>` for rows it could not understand;
- never fails a whole refresh because of one bad row (bad rows are shown raw with a `?` badge and are
  read-only, which keeps numbering intact);
- has a golden-file test suite with fixtures for: inactive, empty, comments, `(log)`, apps, IPv6, interfaces,
  route rules, long addresses that shift columns, and manual edits made outside the app.

### 14.2 `ufw status verbose` header

```
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip
```

Parsed fields: `enabled`, `log_level ∈ {off, low, medium, high, full}`, `default_incoming`,
`default_outgoing`, `default_routed ∈ {allow, deny, reject, disabled}`, `new_profiles`.

### 14.3 Failure behaviour

| Failure | UI |
|---|---|
| `ufw` not installed | Full-screen message with per-distro install command; `Q` quits |
| Not root | Read-only mode banner (§11) |
| Command exits non-zero | Error modal with our command, then ufw's stderr verbatim, then a suggested fix |
| Output unparseable | Rules tab shows the raw output in a scrollable pane + "this looks like a bug" note |
| `ufw` hangs | Killed at timeout; error modal "ufw did not respond within 10s" |
| Concurrent change by another admin | Detected by comparing rule counts/ids after apply; forces refresh + toast |

## 15. Configuration and state

`~/.config/ufw-manager-tui/config.toml`:

```toml
theme = "dark"                # dark | light | 16color | mono
confirm_before_apply = true
show_counters = true
counters_refresh_secs = 5
log_source = "auto"           # auto | ufw.log | journal
reconcile_seconds = 60        # watchdog delay, 0 disables
default_confirm_within = true
ascii_fallback = false
keymap = "default"
```

`~/.local/state/ufw-manager-tui/journal.json` — undo stack + change history (session and cross-session).
`/var/backups/ufw-manager-tui/<ts>/` — emergency config copies (root only).
`--config <path>` overrides for testing. `--demo` runs against `MockBackend` with a realistic sample ruleset
so the app can be shown off, and screenshotted in CI, without root or risk.

## 16. Non-functional requirements

- **Startup** to first paint < 150 ms with a cached state; full `ufw` refresh < 500 ms on a 100-rule set.
- **No unbounded I/O on the UI thread.** `ufw` invocations are synchronously bounded by a 10s timeout;
  log tailing and blocking reads run on worker threads.
- **Memory** < 30 MB steady state.
- **Key latency** < 16 ms per frame; renders are incremental, not full-rebuild-per-key.
- **Terminal hygiene**: raw mode and alternate screen are restored on normal exit, on `Err`, on panic (panic
  hook), and on `SIGINT`/`SIGTERM`/`SIGHUP`. A crashed ufw-manager-tui must never leave the user in a broken
  terminal.
- **No telemetry, no network access, no writes outside the paths above.**
- **Logging:** `--debug-log <path>` writes a structured trace for bug reports; off by default; never logs
  anything sensitive beyond what `ufw status` already shows.

## 17. Testing strategy

1. **Parser golden tests** (`insta`) over captured real `ufw` output, covering every branch in §14.1.
2. **Command builder round-trip tests**: `RuleDraft → argv → (parse back) → RuleDraft` is idempotent for a
   generated corpus of drafts, including ranges, lists, apps, interfaces, notes with quotes and spaces.
3. **Simulator table tests**: a matrix of rulesets × packets with expected verdicts and expected winning rule
   number, including shadowing, `limit`, apps, interfaces, and both IP families.
4. **Lockout guard tests**: one case per row of the §10.2 table, plus "not over SSH".
5. **Risk classifier tests**: boundary cases (single host vs `/32`, `/24` vs `/16`, sensitive vs not).
6. **Mock-backend integration tests**: a fake `ufw` shell script on `PATH` (selected via
   `UFW_MANAGER_UFW` env override) that records argv and can be scripted to fail, hang, or emit odd output.
   This exercises the full add/edit/delete/undo pipeline with no root.
7. **Widget snapshot tests**: `ratatui` `TestBackend` + `insta` snapshots for each screen at 80×24, 120×40,
   and 40×15 (degraded), in dark/16color/mono.
8. **Manual VM checklist** (`docs/TESTING.md`): enable firewall over SSH, apply a lockout-triggering change and
   verify the watchdog reverts, verify counters after reload, verify read-only mode as a non-root user.
9. **CI**: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, `cargo deny` for licences.

## 18. Delivery plan

| Milestone | Deliverable |
|---|---|
| **M0 — Shell** | Crate, CLI, terminal guard, event loop, tab framework, help + footer from the keymap, `--demo` mock |
| **M1 — Read** | Full `ufw` read path, parsers + golden tests, Rules table, Home with status/policies |
| **M2 — Write** | CommandBuilder, dry-run preview, confirm modal, add wizard (4 steps), raw form, edit, delete, duplicate, reorder, notes, enable/disable, policies, log level |
| **M3 — Safety** | Lockout guard, undo journal + persistence, emergency backups, reconcile watchdog |
| **M4 — Test** | Simulator with built-in chain model and shadowing detection, counters, live log tail with aggregation, exposure cross-check |
| **M5 — Presets** | Recipe library, risk engine + badges everywhere, suggested fixes on Home |
| **M6 — Polish** | Themes, ASCII/mono fallbacks, small-terminal layout, docs (README, GLOSSARY, TESTING), packaging |

M1 and M2 are the minimum viable product: *see the rules, change them safely.* M3 is what makes it safe to
ship. M4 is what makes it better than `ufw`. M5 is what makes it usable by the actual target user.

## 19. Open questions (v0.1 answers in brackets)

1. **Route (FWD) rules** — read-only in v1. [Shipped read-only: shown, deletable only through the guard, not editable.] Should they be fully editable, or is hiding them from newcomers
   the better default?
2. **Reorder UI** — `x` moves the selected rule one position up (or to the top). [Shipped as a single keypress rather than a modal, because `ufw insert N` makes anything more elaborate pointless for one-rule moves.] Was: is `x` + `u`/`d` enough, or does `ufw`'s `insert N` deserve a drag-style list with visible
   positions?
3. **`ufw reset`** — [Shipped as the last Presets entry, always blocked by the lockout guard unless forced, and not undoable.] Was: expose it at all, or leave it to the CLI since it is unrecoverable in-app?
4. **Docker detection** — the DOCKER-USER chain bypasses ufw. Warn only, or offer to manage `DOCKER-USER`
   rules?
5. **Non-English UI** — `ufw`'s own output is parsed with `LC_ALL=C`; should our *own* strings be translatable
   (fluent/rust-i18n) in v1 or later?
6. **Escalation via `sudo -v`** — [Shipped on by default, disable with `--no-escalate`.] Was: convenient, but some users will prefer the app to refuse rather than prompt.
   Default on or off?

## 20. Implementation notes

Where the shipped code differs from the design above, and why.

| Design | Shipped | Reason |
|---|---|---|
| Add wizard as a modal | Add wizard as a full tab | The review step needs room for a sentence, a command, a risk assessment and a simulation trace; a dialog on 80×24 cannot hold that |
| Per-rule notes in a sidecar file | Native `ufw ... comment '…'` | `ufw` 0.36 supports comments and prints them in `status`; a sidecar desyncs on every external edit and renumber. A `NoteStore`-style fallback was not needed |
| Counters refreshed by a worker | Refreshed on read, after each write, and on `r` | A `nft -j` call is a local netlink query; polling it added thread plumbing for no user-visible benefit |
| Footer hints and Help from one keymap table | Same | Kept as designed — `src/ui/keys.rs` drives both |
| `--demo` mock backend | Same | Also used by the integration tests, so the demo state is test-covered |

Deliberate omissions from the design:

- **Signal handling** uses `signal-hook` to set a flag rather than a full signal-safe restore, so a
  `SIGKILL` can still leave the terminal in raw mode. `reset` recovers.
- **`ufw show listening`** is not used; `ss -tulpnH` gives the same information with cleaner output.
- **`ufw show raw` / iptables text parsing** is not used for counters; the nft JSON is parsed instead.

Known gaps worth naming:

- Route (`FWD`) rules can be seen and deleted but not created or edited.
- The simulator models ufw's built-in chains by hand; it is a model, and the UI says so.
- The `y` (duplicate) action copies a rule into the wizard rather than cloning it outright, so the user
  confirms the change like any other.
