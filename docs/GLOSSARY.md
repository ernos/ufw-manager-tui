# Plain-English glossary

This is the same text the in-app Help tab shows. It exists as a file so it can be read, reviewed and
corrected on its own.

## port

A numbered door into a computer. A service listens on a port and other machines connect to it.

| Port | Usually |
|---|---|
| 22 | SSH — remote terminal login |
| 80 | HTTP — web pages |
| 443 | HTTPS — encrypted web pages |
| 25, 587 | Sending mail |
| 53 | DNS — turning names into addresses |
| 445 | Windows file sharing |
| 3306 | MySQL / MariaDB |
| 3389 | Windows remote desktop |
| 5432 | PostgreSQL |
| 5900 | VNC — remote screen |

A firewall rule almost always ends up being about a port.

## ALLOW, DENY, REJECT, LIMIT

- **ALLOW** lets the traffic through.
- **DENY** silently drops it. The sender gets no reply and eventually gives up. This is the default for
  incoming traffic, because it tells an attacker nothing.
- **REJECT** drops it but replies "not allowed", so the sender fails immediately. Friendlier on a network
  you control, but it confirms that something is there.
- **LIMIT** is ALLOW with a speed limit: after six connections in thirty seconds from the same address,
  further attempts are blocked. For SSH this slows down password guessing at almost no cost.

## IN and OUT

Relative to *this* machine.

- `ALLOW IN 22/tcp` — someone else may connect **to** this machine on port 22.
- `ALLOW OUT 53/udp` — **this** machine may send DNS queries out.

Almost every rule a beginner needs is an `IN` rule. The default outgoing policy is normally `allow`, so
`OUT` rules only matter when you are tightening egress.

## Anywhere

Any address at all, which in practice means the whole internet. `ALLOW IN 22/tcp from Anywhere` means
anybody on the planet may try to log in.

## 192.168.0.0/24

A range of addresses. The `/24` says how many of the leading bits are fixed: `/24` fixes the first three
numbers, so `192.168.0.0/24` covers `192.168.0.1` through `192.168.0.254`.

The ranges that mean "a private network" — the addresses your home router hands out — are:

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`

`/32` (or a plain address with no slash) means one single machine.

## interface

A network card or tunnel: `eno1` (wired), `wlan0` (Wi-Fi), `wg0` (WireGuard VPN). A rule can be limited to
one interface, which is useful for "arriving over the VPN only".

## rule order

This is the single most important thing to understand. `ufw` checks rules **top to bottom and the first
one that matches wins**. Rules below a match are never consulted for that traffic.

That means a broad rule above a narrow one silently disables the narrow one:

```
1  ALLOW IN  22/tcp  from Anywhere        ← matches everything, wins
2  ALLOW IN  22/tcp  from 192.168.1.0/24  ← never reached
```

Put the specific rule **above** the general one. ufw-manager-tui detects this case and says so.

## default policy

What happens to traffic that no rule mentioned. The default for incoming should be `DENY`: anything you
start later stays unreachable until you add a rule for it.

Changing the default policy reloads the firewall and drops existing connections, including SSH sessions.
ufw-manager-tui warns before it does that.

## application profile

A bundle of ports shipped by a package, so you do not have to remember the numbers. `ufw allow OpenSSH`
means `22/tcp`. See them with `ufw app list` — ufw-manager-tui lists them in the Add wizard.

## log level

How much `ufw` writes to the kernel log. `low` records blocked packets, which is what the Activity tab
shows. `high` and `full` record nearly everything and can fill a disk quickly.

## established connection

Traffic belonging to a connection that was already allowed. `ufw` is stateful: once it lets a connection
in, the replies are allowed automatically. You do not need a rule for the return traffic.

## loopback

`127.0.0.1` / `::1`, traffic from the machine to itself. Always allowed, and never a security problem.

## lockout

What happens when a firewall change stops you reconnecting: you turn the firewall on without an SSH rule,
or delete the rule that was letting you in. ufw-manager-tui blocks the changes it can predict and automatically
reverts the ones it cannot.
