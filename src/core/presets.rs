//! The recipe library.
//!
//! Each preset is a named goal with a fixed, correct implementation. They exist so the user never
//! has to translate an intention ("I run a web server") into firewall syntax themselves.

use ipnet::IpNet;

use crate::core::command::{change_add, change_enabled, change_policy, change_reset, Change};
use crate::core::firewall::Policy;
use crate::core::risk::RiskLevel;
use crate::core::rule::{Action, PortSpec, Protocol, RuleDraft};

/// Details about this machine's local network, used to offer "my network only" options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanInfo {
    pub iface: String,
    pub net: IpNet,
}

impl LanInfo {
    pub fn cidr(&self) -> String {
        self.net.to_string()
    }
}

/// Everything a preset needs to decide whether it applies and how to build itself.
#[derive(Debug, Clone)]
pub struct PresetContext {
    pub lan: Option<LanInfo>,
    pub ssh_port: u16,
    pub interfaces: Vec<String>,
    pub firewall_enabled: bool,
    pub default_incoming: Policy,
    /// False when a rule already lets SSH in from anywhere.
    pub ssh_already_open: bool,
}

impl Default for PresetContext {
    fn default() -> Self {
        Self {
            lan: None,
            ssh_port: 22,
            interfaces: Vec::new(),
            firewall_enabled: false,
            default_incoming: Policy::Deny,
            ssh_already_open: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Preset {
    TurnOnSafely,
    RestrictSshToLan,
    RateLimitSsh,
    WebServer,
    BlockAddress(String),
    Minimal,
    AllowInterface(String),
    CustomService { port: u16, protocol: Protocol },
    ResetToDefaults,
}

/// A preset as the UI shows it.
#[derive(Debug, Clone)]
pub struct PresetCard {
    pub preset: Preset,
    pub title: String,
    pub what: String,
    pub level: RiskLevel,
    /// `None` when the preset cannot run here, with the reason.
    pub blocked: Option<String>,
}

impl Preset {
    pub fn title(&self) -> String {
        match self {
            Preset::TurnOnSafely => "Turn the firewall on, safely".into(),
            Preset::RestrictSshToLan => "Only let my own network reach SSH".into(),
            Preset::RateLimitSsh => "Slow down SSH password guessing".into(),
            Preset::WebServer => "I run a web server".into(),
            Preset::BlockAddress(_) => "Block a specific address".into(),
            Preset::Minimal => "Minimal exposure (laptop on public Wi-Fi)".into(),
            Preset::AllowInterface(iface) => format!("Let traffic in on {iface}"),
            Preset::CustomService { port, protocol } => {
                format!("Open {protocol} port {port}")
            }
            Preset::ResetToDefaults => "Reset everything to ufw's defaults".into(),
        }
    }

    fn what(&self) -> String {
        match self {
            Preset::TurnOnSafely => {
                "Allows outgoing traffic, blocks incoming traffic, and keeps SSH open first so you do not lose your connection.".into()
            }
            Preset::RestrictSshToLan => {
                "Replaces the open SSH rule with one that only accepts connections from your local network.".into()
            }
            Preset::RateLimitSsh => {
                "Allows SSH but blocks an address that tries more than six connections in thirty seconds.".into()
            }
            Preset::WebServer => "Allows TCP ports 80 and 443 from anywhere.".into(),
            Preset::BlockAddress(_) => "Silently drops all traffic from that address.".into(),
            Preset::Minimal => {
                "Blocks everything incoming and allows everything outgoing. Good on networks you do not trust.".into()
            }
            Preset::AllowInterface(_) => {
                "Allows all traffic arriving on that interface, for example a VPN tunnel.".into()
            }
            Preset::CustomService { .. } => "Allows that port from anywhere.".into(),
            Preset::ResetToDefaults => {
                "Turns the firewall off and deletes every rule. This cannot be undone.".into()
            }
        }
    }

    fn level(&self) -> RiskLevel {
        match self {
            Preset::ResetToDefaults => RiskLevel::Critical,
            Preset::Minimal | Preset::TurnOnSafely => RiskLevel::Low,
            Preset::RestrictSshToLan => RiskLevel::Low,
            Preset::RateLimitSsh => RiskLevel::Low,
            Preset::AllowInterface(_) => RiskLevel::Medium,
            Preset::WebServer | Preset::CustomService { .. } => RiskLevel::High,
            Preset::BlockAddress(_) => RiskLevel::Info,
        }
    }

    pub fn changes(&self, ctx: &PresetContext) -> Result<Vec<Change>, String> {
        match self {
            Preset::TurnOnSafely => {
                let mut changes = Vec::new();
                if !ctx.ssh_already_open {
                    let draft = match &ctx.lan {
                        Some(lan) => RuleDraft::allow_port(Protocol::Tcp, ctx.ssh_port)
                            .from_anywhere(lan.cidr())
                            .on_interface(lan.iface.clone())
                            .with_comment("ufw-manager-tui: keep SSH reachable"),
                        None => RuleDraft::allow_port(Protocol::Tcp, ctx.ssh_port)
                            .with_comment("ufw-manager-tui: keep SSH reachable"),
                    };
                    changes.push(change_add(&draft)?);
                }
                if !ctx.firewall_enabled {
                    changes.push(change_enabled(true));
                }
                Ok(changes)
            }
            Preset::RestrictSshToLan => {
                let lan = ctx.lan.as_ref().ok_or(
                    "Could not work out which network you are on. Pick 'One specific address' instead.",
                )?;
                let draft = RuleDraft::allow_port(Protocol::Tcp, ctx.ssh_port)
                    .from_anywhere(lan.cidr())
                    .on_interface(lan.iface.clone())
                    .with_comment("ufw-manager-tui: SSH from local network");
                Ok(vec![change_add(&draft)?])
            }
            Preset::RateLimitSsh => {
                let mut draft = RuleDraft::allow_port(Protocol::Tcp, ctx.ssh_port)
                    .with_comment("ufw-manager-tui: SSH rate limited");
                draft.action = Action::Limit;
                Ok(vec![change_add(&draft)?])
            }
            Preset::WebServer => {
                let mut http =
                    RuleDraft::allow_port(Protocol::Tcp, 80).with_comment("ufw-manager-tui: web");
                http.action = Action::Allow;
                let mut https =
                    RuleDraft::allow_port(Protocol::Tcp, 443).with_comment("ufw-manager-tui: web");
                https.action = Action::Allow;
                Ok(vec![change_add(&http)?, change_add(&https)?])
            }
            Preset::BlockAddress(addr) => {
                let draft = RuleDraft {
                    action: Action::Deny,
                    from_addr: Some(addr.clone()),
                    to_port: PortSpec::Any,
                    comment: Some("ufw-manager-tui: blocked".into()),
                    ..Default::default()
                };
                Ok(vec![change_add(&draft)?])
            }
            Preset::Minimal => {
                let mut changes = Vec::new();
                if ctx.default_incoming != Policy::Deny {
                    changes.push(change_policy(
                        "incoming",
                        Policy::Deny,
                        ctx.default_incoming,
                    ));
                }
                if !ctx.firewall_enabled {
                    changes.push(change_enabled(true));
                }
                Ok(changes)
            }
            Preset::AllowInterface(iface) => {
                let draft = RuleDraft {
                    interface_in: Some(iface.clone()),
                    comment: Some(format!("ufw-manager-tui: traffic on {iface}")),
                    ..Default::default()
                };
                Ok(vec![change_add(&draft)?])
            }
            Preset::CustomService { port, protocol } => {
                let draft = RuleDraft::allow_port(*protocol, *port)
                    .with_comment(format!("ufw-manager-tui: {protocol} {port}"));
                Ok(vec![change_add(&draft)?])
            }
            Preset::ResetToDefaults => Ok(vec![change_reset()]),
        }
    }

    /// Builds the card, including whether it can run in this environment.
    pub fn card(&self, ctx: &PresetContext) -> PresetCard {
        let blocked = match self {
            Preset::RestrictSshToLan if ctx.lan.is_none() => {
                Some("Needs a local network address, and none was detected.".to_string())
            }
            Preset::TurnOnSafely if ctx.firewall_enabled && ctx.ssh_already_open => {
                Some("The firewall is already on and SSH is already allowed.".to_string())
            }
            _ => match self.changes(ctx) {
                Ok(changes) if changes.is_empty() => Some("Nothing to do.".to_string()),
                Ok(_) => None,
                Err(error) => Some(error),
            },
        };
        PresetCard {
            preset: self.clone(),
            title: self.title(),
            what: self.what(),
            level: self.level(),
            blocked,
        }
    }
}

/// The default library, minus the ones that need an argument from the user.
pub fn library(ctx: &PresetContext) -> Vec<PresetCard> {
    let mut presets = vec![
        Preset::TurnOnSafely,
        Preset::RestrictSshToLan,
        Preset::RateLimitSsh,
        Preset::WebServer,
        Preset::Minimal,
    ];
    for iface in &ctx.interfaces {
        // Tunnel interfaces are the ones people actually want to open up.
        if iface.starts_with("wg")
            || iface.starts_with("tun")
            || iface.starts_with("tap")
            || iface.starts_with("tailscale")
        {
            presets.push(Preset::AllowInterface(iface.clone()));
        }
    }
    presets.push(Preset::ResetToDefaults);
    presets.iter().map(|p| p.card(ctx)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with_lan() -> PresetContext {
        PresetContext {
            lan: Some(LanInfo {
                iface: "eno1".into(),
                net: "192.168.1.0/24".parse().unwrap(),
            }),
            ssh_port: 22,
            interfaces: vec!["eno1".into(), "wg0".into()],
            firewall_enabled: true,
            default_incoming: Policy::Deny,
            ssh_already_open: true,
        }
    }

    #[test]
    fn turning_on_safely_adds_ssh_before_enabling() {
        let ctx = PresetContext {
            firewall_enabled: false,
            ssh_already_open: false,
            ..ctx_with_lan()
        };
        let changes = Preset::TurnOnSafely.changes(&ctx).unwrap();
        assert_eq!(changes.len(), 2);
        assert!(changes[0].steps[0].contains(&"allow".to_string()));
        assert!(changes[1].steps[0].contains(&"enable".to_string()));
    }

    #[test]
    fn turning_on_safely_skips_work_already_done() {
        let ctx = ctx_with_lan();
        assert!(Preset::TurnOnSafely.changes(&ctx).unwrap().is_empty());
    }

    #[test]
    fn restricting_ssh_uses_the_detected_network() {
        let changes = Preset::RestrictSshToLan.changes(&ctx_with_lan()).unwrap();
        let args = &changes[0].steps[0];
        assert!(args.contains(&"192.168.1.0/24".to_string()));
        assert!(args.contains(&"eno1".to_string()));
    }

    #[test]
    fn restricting_ssh_without_a_detected_network_fails_helpfully() {
        let ctx = PresetContext {
            lan: None,
            ..ctx_with_lan()
        };
        let error = Preset::RestrictSshToLan.changes(&ctx).unwrap_err();
        assert!(error.contains("which network"));
    }

    #[test]
    fn rate_limiting_ssh_uses_the_limit_action() {
        let changes = Preset::RateLimitSsh.changes(&ctx_with_lan()).unwrap();
        assert_eq!(changes[0].steps[0][0], "limit");
    }

    #[test]
    fn the_web_server_preset_opens_both_ports() {
        let changes = Preset::WebServer.changes(&ctx_with_lan()).unwrap();
        assert_eq!(changes.len(), 2);
        assert!(changes[0].steps[0].contains(&"80/tcp".to_string()));
        assert!(changes[1].steps[0].contains(&"443/tcp".to_string()));
    }

    #[test]
    fn blocking_an_address_denies_from_it() {
        let changes = Preset::BlockAddress("203.0.113.7".into())
            .changes(&ctx_with_lan())
            .unwrap();
        let args = &changes[0].steps[0];
        assert_eq!(args[0], "deny");
        assert!(args.contains(&"203.0.113.7".to_string()));
    }

    #[test]
    fn minimal_only_changes_what_differs() {
        let ctx = PresetContext {
            firewall_enabled: true,
            default_incoming: Policy::Allow,
            ..ctx_with_lan()
        };
        let changes = Preset::Minimal.changes(&ctx).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].steps[0], vec!["default", "deny", "incoming"]);
    }

    #[test]
    fn interface_presets_are_only_offered_for_tunnels() {
        let cards = library(&ctx_with_lan());
        assert!(cards
            .iter()
            .any(|c| matches!(&c.preset, Preset::AllowInterface(i) if i == "wg0")));
        assert!(!cards
            .iter()
            .any(|c| matches!(&c.preset, Preset::AllowInterface(i) if i == "eno1")));
    }

    #[test]
    fn blocked_reasons_are_reported_for_the_ui() {
        let ctx = PresetContext {
            lan: None,
            ..ctx_with_lan()
        };
        let card = Preset::RestrictSshToLan.card(&ctx);
        assert!(card.blocked.is_some());
    }

    #[test]
    fn reset_is_marked_critical() {
        assert_eq!(Preset::ResetToDefaults.level(), RiskLevel::Critical);
        assert!(Preset::ResetToDefaults.changes(&ctx_with_lan()).unwrap()[0]
            .inverse
            .is_empty());
    }

    #[test]
    fn custom_service_respects_the_protocol() {
        let preset = Preset::CustomService {
            port: 25565,
            protocol: Protocol::Udp,
        };
        let changes = preset.changes(&ctx_with_lan()).unwrap();
        assert!(changes[0].steps[0].contains(&"25565/udp".to_string()));
    }
}
