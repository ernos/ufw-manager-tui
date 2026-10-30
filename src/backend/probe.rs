//! Pure parsers for the network facts we need: which network this machine is on, which interfaces
//! exist, and which port sshd listens on.

use std::process::Command;

use crate::core::lockout::Session;
use crate::core::parse::Listening;
use crate::core::presets::LanInfo;

/// Picks the local network from `ip route show default` plus `ip -o -4 addr show scope global`.
///
/// The default route tells us which interface actually carries traffic to the outside world, which
/// is the one a newcomer means by "my network". Docker bridges and VPN tunnels are deliberately not
/// chosen for the SSH restriction presets.
pub fn detect_lan(default_route: &str, addrs: &str) -> Option<LanInfo> {
    let iface = default_route
        .lines()
        .find_map(|line| {
            let mut words = line.split_whitespace();
            while let Some(word) = words.next() {
                if word == "dev" {
                    return words.next().map(str::to_string);
                }
            }
            None
        })
        .or_else(|| {
            addrs
                .lines()
                .filter_map(interface_of)
                .find(|name| !is_virtual_interface(name))
        })?;

    let net = addrs.lines().find_map(|line| {
        let (line_iface, cidr) = interface_and_cidr(line)?;
        if line_iface == iface {
            cidr.parse::<ipnet::IpNet>().ok()
        } else {
            None
        }
    })?;

    Some(LanInfo { iface, net })
}

/// Bridges and tunnels are not "my network" from a newcomer's point of view.
fn is_virtual_interface(name: &str) -> bool {
    name == "lo"
        || name.starts_with("docker")
        || name.starts_with("lxc")
        || name.starts_with("veth")
        || name.starts_with("br-")
        || name.starts_with("virbr")
        || name.starts_with("tun")
        || name.starts_with("tap")
        || name.starts_with("wg")
}

/// `2: eno1    inet 192.168.1.19/24 brd ...` → (`eno1`, `192.168.1.19/24`)
fn interface_and_cidr(line: &str) -> Option<(String, String)> {
    let mut words = line.split_whitespace();
    let _index = words.next()?;
    let iface = words.next()?.trim_end_matches(':').to_string();
    let mut inet = false;
    for word in words {
        if word == "inet" {
            inet = true;
            continue;
        }
        if inet {
            return Some((iface, word.to_string()));
        }
    }
    None
}

fn interface_of(line: &str) -> Option<String> {
    interface_and_cidr(line).map(|(iface, _)| iface)
}

/// Interface names, excluding loopback.
pub fn parse_interfaces(link_output: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in link_output.lines() {
        // `ip -o link show` lines look like `2: eno1: <BROADCAST,...> mtu 1500 ...`
        let Some((_, rest)) = line.split_once(' ') else {
            continue;
        };
        let Some(name) = rest.split(':').next() else {
            continue;
        };
        let name = name.trim();
        let name = name.split('@').next().unwrap_or(name);
        if name.is_empty() || name == "lo" || name.contains(' ') {
            continue;
        }
        out.push(name.to_string());
    }
    out.sort();
    out.dedup();
    out
}

/// The `Port` directive from `sshd_config`, if it is set and uncommented.
pub fn ssh_port_from_sshd_config(text: &str) -> Option<u16> {
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let mut words = line.split_whitespace();
        if words.next().map(str::to_ascii_lowercase).as_deref() != Some("port") {
            continue;
        }
        if let Some(port) = words.next().and_then(|p| p.parse::<u16>().ok()) {
            return Some(port);
        }
    }
    None
}

/// Finds the port sshd is actually listening on from `ss -tlnp` output.
pub fn ssh_port_from_listening(listening: &[Listening]) -> Option<u16> {
    listening
        .iter()
        .find(|socket| socket.process.as_deref() == Some("sshd") && socket.proto == "tcp")
        .map(|socket| socket.port)
}

pub fn run(command: &str, args: &[&str]) -> String {
    Command::new(command)
        .args(args)
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).to_string())
        .unwrap_or_default()
}

/// Reads the current session from the environment.
pub fn current_session() -> Session {
    match std::env::var("SSH_CONNECTION") {
        Ok(value) => Session::from_ssh_connection(&value).unwrap_or_else(Session::local),
        Err(_) => Session::local(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTE: &str = "default via 192.168.1.1 dev eno1 proto dhcp src 192.168.1.19 metric 100\n";
    const ADDRS: &str = "\
2: eno1    inet 192.168.1.19/24 brd 192.168.1.255 scope global dynamic eno1\\       valid_lft 8000sec preferred_lft 8000sec
3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\\       valid_lft forever preferred_lft forever
";

    #[test]
    fn picks_the_default_route_interface() {
        let lan = detect_lan(ROUTE, ADDRS).expect("should detect");
        assert_eq!(lan.iface, "eno1");
        assert_eq!(lan.net.to_string(), "192.168.1.19/24");
    }

    #[test]
    fn does_not_pick_a_docker_bridge() {
        let lan = detect_lan("", ADDRS).expect("should detect");
        assert_eq!(lan.iface, "eno1");
        assert_ne!(lan.iface, "docker0");
    }

    #[test]
    fn only_virtual_interfaces_detects_nothing() {
        let only_docker =
            "3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\n";
        assert!(detect_lan("", only_docker).is_none());
    }

    #[test]
    fn returns_none_when_there_is_nothing_to_go_on() {
        assert!(detect_lan("", "").is_none());
    }

    #[test]
    fn parses_interface_names() {
        let output = "\
1: lo: <LOOPBACK,UP> mtu 65536
2: eno1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
3: wg0-mullvad: <POINTOPOINT,NOARP,UP> mtu 1420
4: veth8a077cf@if2: <BROADCAST,MULTICAST,UP> mtu 1500
";
        let interfaces = parse_interfaces(output);
        assert!(interfaces.contains(&"eno1".to_string()));
        assert!(interfaces.contains(&"wg0-mullvad".to_string()));
        assert!(interfaces.contains(&"veth8a077cf".to_string()));
        assert!(!interfaces.contains(&"lo".to_string()));
    }

    #[test]
    fn reads_an_explicit_ssh_port() {
        assert_eq!(ssh_port_from_sshd_config("Port 2222\n"), Some(2222));
        assert_eq!(ssh_port_from_sshd_config("#Port 2222\n"), None);
        assert_eq!(ssh_port_from_sshd_config(""), None);
    }

    #[test]
    fn ignores_other_directives_named_port() {
        assert_eq!(ssh_port_from_sshd_config("ListenAddress 0.0.0.0\n"), None);
    }

    #[test]
    fn finds_the_sshd_listening_port() {
        let sockets = vec![
            Listening {
                proto: "tcp".into(),
                addr: "0.0.0.0".into(),
                port: 80,
                process: Some("nginx".into()),
            },
            Listening {
                proto: "tcp".into(),
                addr: "0.0.0.0".into(),
                port: 2222,
                process: Some("sshd".into()),
            },
        ];
        assert_eq!(ssh_port_from_listening(&sockets), Some(2222));
    }
}
