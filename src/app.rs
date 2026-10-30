//! Application state and key handling.
//!
//! Everything here is synchronous: `ufw status` takes a few tens of milliseconds, and each write is
//! validated with `--dry-run` first, so a modal spinner would add more complexity than it removes.

use std::collections::VecDeque;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::backend::logs::BlockMonitor;
use crate::backend::{Backend, BackendError, BlockRow, CmdOutput, HitCounters};
use crate::core::command::{self, Change};
use crate::core::explain;
use crate::core::firewall::{FirewallState, LogLevel, Policy};
use crate::core::lockout::{self, ChangeKind, GuardVerdict, PendingChange, Session};
use crate::core::parse::{parse_ufw_conf, AppProfile, Listening};
use crate::core::presets::{self, LanInfo, PresetCard, PresetContext};
use crate::core::risk::{self, Fix, Suggestion};
use crate::core::rule::{Action, Direction, PortSpec, Protocol, Rule, RuleDraft};
use crate::core::simulate::{self, Packet, Trace};
use crate::core::undo::Journal;
use crate::ui::theme::Theme;
use crate::ui::widgets::TextInput;
use crate::watchdog::{self, Watchdog};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Home,
    Rules,
    Add,
    Test,
    Activity,
    Presets,
    Help,
}

impl Tab {
    pub const ALL: [Tab; 7] = [
        Tab::Home,
        Tab::Rules,
        Tab::Add,
        Tab::Test,
        Tab::Activity,
        Tab::Presets,
        Tab::Help,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Home => "Home",
            Tab::Rules => "Rules",
            Tab::Add => "Add",
            Tab::Test => "Test",
            Tab::Activity => "Activity",
            Tab::Presets => "Presets",
            Tab::Help => "Help",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Tab::Home => "Is the firewall on, and how exposed is this machine?",
            Tab::Rules => "Every rule, in the order ufw checks them. The first match wins.",
            Tab::Add => "Pick a goal and the correct rule is built for you.",
            Tab::Test => "Send a pretend packet and see which rule decides its fate.",
            Tab::Activity => "What is being blocked right now, and what this session changed.",
            Tab::Presets => "One-key recipes for the jobs people actually have.",
            Tab::Help => "Keys, and what the jargon means.",
        }
    }

    pub fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }

    pub fn from_digit(digit: char) -> Option<Tab> {
        let index = digit.to_digit(10)?;
        if index == 0 {
            return None;
        }
        Tab::ALL.get(index as usize - 1).copied()
    }

    pub fn next(self, delta: isize) -> Tab {
        let len = Tab::ALL.len() as isize;
        let index = ((self.index() as isize + delta) % len + len) % len;
        Tab::ALL[index as usize]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusLevel {
    Info,
    Good,
    Warn,
    Error,
}

#[derive(Debug, Clone)]
pub struct StatusMessage {
    pub level: StatusLevel,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardStep {
    Goal,
    Who,
    Service,
    Review,
    Advanced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputField {
    Address,
    Port,
    Interface,
    Note,
    FromAddress,
    FromPort,
    AdvancedComment,
}

pub struct Wizard {
    pub step: WizardStep,
    pub draft: RuleDraft,
    pub cursor: usize,
    pub input: Option<(InputField, TextInput)>,
    pub error: Option<String>,
    /// `Some` when the wizard is editing an existing rule rather than adding one.
    pub editing: Option<u32>,
    pub trace: Option<Trace>,
}

impl Default for Wizard {
    fn default() -> Self {
        Self {
            step: WizardStep::Goal,
            draft: RuleDraft::default(),
            cursor: 0,
            input: None,
            error: None,
            editing: None,
            trace: None,
        }
    }
}

impl Wizard {
    fn reset(&mut self) {
        *self = Self::default();
    }
}

pub struct TrafficForm {
    pub field: usize,
    pub direction: usize,
    pub protocol: usize,
    pub src: TextInput,
    pub src_port: TextInput,
    pub dst: TextInput,
    pub dst_port: TextInput,
}

impl Default for TrafficForm {
    fn default() -> Self {
        let mut dst = TextInput::default();
        dst.set("192.168.1.19");
        let mut dst_port = TextInput::default();
        dst_port.set("22");
        let mut src = TextInput::default();
        src.set("203.0.113.9");
        let mut src_port = TextInput::default();
        src_port.set("51000");
        Self {
            field: 0,
            direction: 0,
            protocol: 0,
            src,
            src_port,
            dst,
            dst_port,
        }
    }
}

pub struct ConfirmModal {
    pub change: Change,
    pub pending: PendingChange,
    /// The last successful `ufw --dry-run` output, shown when the user asks for it.
    pub dry: Option<CmdOutput>,
    pub guard: GuardVerdict,
    pub meaning: String,
    pub show_dry: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageLevel {
    Info,
    Warning,
    Error,
}

pub struct MessageModal {
    pub title: String,
    pub body: Vec<String>,
    pub level: MessageLevel,
}

pub enum Modal {
    Confirm(Box<ConfirmModal>),
    Message(Box<MessageModal>),
}

/// A request to leave the terminal briefly and ask `sudo` for privileges.
pub enum Escalation {
    /// Retry a change that could not be written.
    Write(Box<(Change, PendingChange)>),
    /// Just gain privileges so the rules become visible.
    Privileges,
}

pub struct AppOptions {
    /// Where the undo journal lives. `None` keeps it in memory only, which is what tests want.
    pub journal_path: Option<std::path::PathBuf>,
    pub yes: bool,
    pub readonly: bool,
    pub theme: Theme,
    pub reconcile_seconds: u64,
    pub show_counters: bool,
    pub confirm_before_apply: bool,
}

pub struct App {
    pub backend: Box<dyn Backend>,
    pub theme: Theme,
    pub tab: Tab,

    pub state: FirewallState,
    pub profiles: Vec<AppProfile>,
    pub listening: Vec<Listening>,
    pub counters: HitCounters,
    pub blocks: BlockMonitor,

    pub journal: Journal,
    pub journal_path: Option<std::path::PathBuf>,
    pub suggestions: Vec<Suggestion>,
    pub shadowed: Vec<(u32, u32)>,
    pub lan: Option<LanInfo>,
    pub session: Session,
    pub ssh_port: u16,
    pub hostname: String,

    pub rules_cursor: usize,
    pub home_cursor: usize,
    pub preset_cursor: usize,
    pub activity_cursor: usize,
    pub help_scroll: u16,

    pub filter: Option<TextInput>,
    pub filter_open: bool,

    pub wizard: Wizard,
    pub traffic: TrafficForm,
    pub trace: Option<Trace>,
    pub presets: Vec<PresetCard>,

    pub modal: Option<Modal>,
    pub queue: VecDeque<Change>,

    pub status: Option<StatusMessage>,
    pub readonly: bool,
    pub yes: bool,
    pub confirm_before_apply: bool,
    pub show_counters: bool,
    pub reconcile_seconds: u64,
    pub should_quit: bool,

    pub escalation: Option<Escalation>,
    pub watchdog: Option<Watchdog>,
    pub paused: bool,
    pub activity_rows: Vec<BlockRow>,
}

/// Services offered on the wizard's third step. Application profiles are appended to this list.
pub struct ServiceChoice {
    pub label: &'static str,
    pub hint: &'static str,
    pub ports: &'static [u16],
    pub protocol: Protocol,
}

pub const SERVICES: [ServiceChoice; 5] = [
    ServiceChoice {
        label: "SSH (remote login)",
        hint: "22/tcp",
        ports: &[22],
        protocol: Protocol::Tcp,
    },
    ServiceChoice {
        label: "Web server (HTTP/HTTPS)",
        hint: "80, 443/tcp",
        ports: &[80, 443],
        protocol: Protocol::Tcp,
    },
    ServiceChoice {
        label: "File sharing (SMB)",
        hint: "445/tcp",
        ports: &[445],
        protocol: Protocol::Tcp,
    },
    ServiceChoice {
        label: "Database",
        hint: "3306/tcp",
        ports: &[3306],
        protocol: Protocol::Tcp,
    },
    ServiceChoice {
        label: "Mail server (SMTP)",
        hint: "25, 587/tcp",
        ports: &[25, 587],
        protocol: Protocol::Tcp,
    },
];

pub const TRAFFIC_PROTOCOLS: [Protocol; 4] =
    [Protocol::Tcp, Protocol::Udp, Protocol::Icmp, Protocol::Any];

impl App {
    pub fn new(backend: Box<dyn Backend>, options: AppOptions) -> Self {
        let hostname = std::fs::read_to_string("/etc/hostname")
            .map(|text| text.trim().to_string())
            .ok()
            .filter(|text| !text.is_empty())
            .unwrap_or_else(|| "localhost".to_string());
        let journal = options
            .journal_path
            .as_deref()
            .map(Journal::load)
            .unwrap_or_default();

        let mut app = Self {
            backend,
            theme: options.theme,
            tab: Tab::Home,
            state: FirewallState::default(),
            profiles: Vec::new(),
            listening: Vec::new(),
            counters: HitCounters::unavailable("not read yet"),
            blocks: BlockMonitor::start(None),
            journal,
            journal_path: options.journal_path.clone(),
            suggestions: Vec::new(),
            shadowed: Vec::new(),
            lan: None,
            session: Session::local(),
            ssh_port: 22,
            hostname,
            rules_cursor: 0,
            home_cursor: 0,
            preset_cursor: 0,
            activity_cursor: 0,
            help_scroll: 0,
            filter: None,
            filter_open: false,
            wizard: Wizard::default(),
            traffic: TrafficForm::default(),
            trace: None,
            presets: Vec::new(),
            modal: None,
            queue: VecDeque::new(),
            status: None,
            readonly: options.readonly,
            yes: options.yes,
            confirm_before_apply: options.confirm_before_apply,
            show_counters: options.show_counters,
            reconcile_seconds: options.reconcile_seconds,
            should_quit: false,
            escalation: None,
            watchdog: None,
            paused: false,
            activity_rows: Vec::new(),
        };
        app.bootstrap();
        app
    }

    /// First read. Failures are reported, never fatal: a user with a broken ufw still needs to see
    /// why it is broken.
    pub fn bootstrap(&mut self) {
        self.lan = self.backend.lan();
        self.session = self.backend.ssh_session();
        self.ssh_port = self.backend.ssh_port();
        self.blocks = BlockMonitor::start(self.backend.log_path());
        self.profiles = self.backend.app_profiles().unwrap_or_default();
        self.listening = self.backend.listening().unwrap_or_default();
        self.refresh();
    }

    pub fn refresh(&mut self) {
        match self.backend.read_state() {
            Ok(state) => {
                self.state = state;
                self.readonly = self.readonly || !self.backend.can_write();
                let counters = self.backend.counters(&self.state.rules);
                self.counters =
                    counters.unwrap_or_else(|error| HitCounters::unavailable(error.to_string()));
            }
            Err(error) => {
                self.state = read_unprivileged_state();
                self.counters = HitCounters::unavailable("rules are hidden without root");
                self.set_status(StatusLevel::Warn, friendly_error(&error));
            }
        }
        self.reanalyse();
        self.clamp_cursors();
    }

    fn reanalyse(&mut self) {
        let context = self.preset_context();
        self.suggestions = risk::assess_state(
            &self.state,
            &self.listening,
            Some(self.ssh_port),
            &self.profiles,
        );
        self.shadowed = risk::find_shadowed(&self.state.rules, &self.profiles);
        self.presets = presets::library(&context);
    }

    pub fn preset_context(&self) -> PresetContext {
        PresetContext {
            lan: self.lan.clone(),
            ssh_port: self.ssh_port,
            interfaces: self.backend.interfaces(),
            firewall_enabled: self.state.enabled,
            default_incoming: self.state.default_incoming,
            ssh_already_open: self.state.permitting_rule(self.ssh_port, None).is_some(),
        }
    }

    fn clamp_cursors(&mut self) {
        let rules = self.visible_rules().len();
        if rules == 0 {
            self.rules_cursor = 0;
        } else if self.rules_cursor >= rules {
            self.rules_cursor = rules - 1;
        }
        if !self.suggestions.is_empty() && self.home_cursor >= self.suggestions.len() {
            self.home_cursor = self.suggestions.len() - 1;
        }
        if !self.presets.is_empty() && self.preset_cursor >= self.presets.len() {
            self.preset_cursor = self.presets.len() - 1;
        }
    }

    pub fn set_status(&mut self, level: StatusLevel, text: impl Into<String>) {
        self.status = Some(StatusMessage {
            level,
            text: text.into(),
        });
    }

    pub fn visible_rules(&self) -> Vec<&Rule> {
        let needle = self
            .filter
            .as_ref()
            .map(|input| input.value().trim().to_ascii_lowercase())
            .unwrap_or_default();
        self.state
            .rules
            .iter()
            .filter(|rule| {
                if needle.is_empty() {
                    return true;
                }
                let haystack = format!(
                    "{} {} {} {} {}",
                    rule.number,
                    rule.action.label(),
                    explain::short_summary(rule),
                    rule.comment_text(),
                    rule.to.port
                )
                .to_ascii_lowercase();
                haystack.contains(&needle)
            })
            .collect()
    }

    pub fn selected_rule(&self) -> Option<Rule> {
        self.visible_rules()
            .get(self.rules_cursor)
            .map(|rule| (*rule).clone())
    }

    pub fn risk_of(&self, rule: &Rule) -> risk::Assessment {
        risk::assess_rule(rule, &self.profiles)
    }

    pub fn hits(&self, rule: &Rule) -> Option<u64> {
        if !self.show_counters {
            return None;
        }
        self.counters.get(rule.number)
    }

    // ---------------------------------------------------------------------------------------
    // key handling
    // ---------------------------------------------------------------------------------------

    pub fn handle_key(&mut self, key: KeyEvent) {
        if self.modal.is_some() {
            self.handle_modal_key(key);
            return;
        }
        if self.filter_open {
            self.handle_filter_key(key);
            return;
        }
        if self.watchdog.is_some() {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.confirm_watchdog();
                    return;
                }
                _ => {}
            }
        }
        // While editing a text field, the letter and digit shortcuts are unbound so the user can
        // type literally (for example an IP address) without triggering a tab jump or a command.
        // The watchdog override above still wins because it is a safety mechanism.
        if self.in_text_input() {
            self.dispatch_tab_key(key);
            return;
        }

        match key.code {
            KeyCode::Char('q') => {
                self.should_quit = true;
                return;
            }
            KeyCode::Char('Q') => {
                self.should_quit = true;
                return;
            }
            KeyCode::Char('?') => {
                self.tab = if self.tab == Tab::Help {
                    Tab::Home
                } else {
                    Tab::Help
                };
                return;
            }
            KeyCode::Char('X') => {
                self.request_privileges();
                return;
            }
            KeyCode::Tab => {
                self.tab = self.tab.next(1);
                self.on_tab_entered();
                return;
            }
            KeyCode::BackTab => {
                self.tab = self.tab.next(-1);
                self.on_tab_entered();
                return;
            }
            KeyCode::Char(c) if Tab::from_digit(c).is_some() => {
                self.tab = Tab::from_digit(c).expect("checked");
                self.on_tab_entered();
                return;
            }
            KeyCode::Char('r') if !key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.refresh();
                self.set_status(StatusLevel::Info, "re-read from ufw");
                return;
            }
            KeyCode::Char('u') => {
                self.undo();
                return;
            }
            _ => {}
        }

        self.dispatch_tab_key(key);
    }

    /// Routes a key to the handler for the active tab.
    fn dispatch_tab_key(&mut self, key: KeyEvent) {
        match self.tab {
            Tab::Home => self.handle_home_key(key),
            Tab::Rules => self.handle_rules_key(key),
            Tab::Add => self.handle_wizard_key(key),
            Tab::Test => self.handle_traffic_key(key),
            Tab::Activity => self.handle_activity_key(key),
            Tab::Presets => self.handle_presets_key(key),
            Tab::Help => self.handle_help_key(key),
        }
    }

    /// True while the user is expected to type free text (an address, port, filter, note, …).
    /// In that state the letter and digit shortcuts are unbound so a keypress is inserted literally.
    fn in_text_input(&self) -> bool {
        if self.wizard.input.is_some() {
            return true;
        }
        if self.tab == Tab::Test && self.traffic.field >= 2 {
            return true;
        }
        false
    }

    fn on_tab_entered(&mut self) {
        if self.tab == Tab::Activity {
            self.activity_rows = self.blocks.rows();
        }
    }

    fn move_cursor(cursor: &mut usize, key: KeyCode, len: usize) {
        if len == 0 {
            *cursor = 0;
            return;
        }
        match key {
            KeyCode::Up | KeyCode::Char('k') => {
                *cursor = if *cursor == 0 { len - 1 } else { *cursor - 1 };
            }
            KeyCode::Down | KeyCode::Char('j') => {
                *cursor = (*cursor + 1) % len;
            }
            KeyCode::Home => *cursor = 0,
            KeyCode::End => *cursor = len - 1,
            _ => {}
        }
    }

    fn handle_help_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.help_scroll = self.help_scroll.saturating_sub(1)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.help_scroll = self.help_scroll.saturating_add(1)
            }
            KeyCode::Esc => self.tab = Tab::Home,
            _ => {}
        }
    }

    // ---------------------------------------------------------------------------------------
    // Home
    // ---------------------------------------------------------------------------------------

    fn handle_home_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up
            | KeyCode::Down
            | KeyCode::Char('k')
            | KeyCode::Char('j')
            | KeyCode::Home
            | KeyCode::End => {
                Self::move_cursor(&mut self.home_cursor, key.code, self.suggestions.len())
            }
            KeyCode::Char(' ') => self.toggle_firewall(),
            KeyCode::Enter | KeyCode::Char('f') => self.apply_suggestion(),
            KeyCode::Char('l') => self.cycle_log_level(),
            _ => {}
        }
    }

    pub fn toggle_firewall(&mut self) {
        let change = command::change_enabled(!self.state.enabled);
        let kind = if self.state.enabled {
            ChangeKind::Disable
        } else {
            ChangeKind::Enable
        };
        let pending = PendingChange::new(kind, change.description.clone());
        self.submit(change, pending);
    }

    pub fn cycle_log_level(&mut self) {
        let next = match self.state.log_level {
            LogLevel::Off => LogLevel::Low,
            LogLevel::Low => LogLevel::Medium,
            LogLevel::Medium => LogLevel::High,
            LogLevel::High => LogLevel::Full,
            LogLevel::Full => LogLevel::Off,
        };
        if next.is_noisy() {
            self.set_status(
                StatusLevel::Warn,
                format!("logging at '{}' writes a lot to disk", next.ufw()),
            );
        }
        let change = command::change_logging(next, self.state.log_level);
        let pending = PendingChange::new(ChangeKind::SetLogging, change.description.clone());
        self.submit(change, pending);
    }

    fn apply_suggestion(&mut self) {
        let Some(suggestion) = self.suggestions.get(self.home_cursor).cloned() else {
            return;
        };
        match suggestion.fix {
            Some(Fix::TurnOnFirewall) => self.toggle_firewall(),
            Some(Fix::FixDefaultIncoming) => {
                let change =
                    command::change_policy("incoming", Policy::Deny, self.state.default_incoming);
                let pending =
                    PendingChange::new(ChangeKind::SetDefaultIncoming, change.description.clone());
                self.submit(change, pending);
            }
            Some(Fix::RestrictSshToLan) => {
                let preset = presets::Preset::RestrictSshToLan;
                self.enqueue_preset(&preset);
            }
            Some(Fix::RateLimitSsh) => {
                let preset = presets::Preset::RateLimitSsh;
                self.enqueue_preset(&preset);
            }
            None => self.set_status(StatusLevel::Info, "this one has no automatic fix"),
        }
    }

    // ---------------------------------------------------------------------------------------
    // Rules
    // ---------------------------------------------------------------------------------------

    fn handle_rules_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up
            | KeyCode::Down
            | KeyCode::Char('k')
            | KeyCode::Char('j')
            | KeyCode::Home
            | KeyCode::End => {
                let len = self.visible_rules().len();
                Self::move_cursor(&mut self.rules_cursor, key.code, len);
            }
            KeyCode::Char('a') => {
                self.start_add();
            }
            KeyCode::Char('e') | KeyCode::Enter => self.start_edit(),
            KeyCode::Char('d') => self.delete_selected(),
            KeyCode::Char('y') => self.duplicate_selected(),
            KeyCode::Char('x') => self.move_selected(),
            KeyCode::Char('t') => self.test_selected(),
            KeyCode::Char('/') => {
                self.filter = Some(TextInput::new(
                    self.filter
                        .as_ref()
                        .map(|f| f.value().to_string())
                        .unwrap_or_default(),
                ));
                self.filter_open = true;
            }
            KeyCode::Char('n') => self.edit_note(),
            KeyCode::Char(' ') => self.show_rule_details(),
            _ => {}
        }
    }

    fn handle_filter_key(&mut self, key: KeyEvent) {
        let Some(input) = self.filter.as_mut() else {
            self.filter_open = false;
            return;
        };
        match key.code {
            KeyCode::Esc => {
                self.filter = None;
                self.filter_open = false;
                self.rules_cursor = 0;
            }
            KeyCode::Enter => {
                self.filter_open = false;
                self.rules_cursor = 0;
            }
            KeyCode::Backspace => input.backspace(),
            KeyCode::Delete => input.delete(),
            KeyCode::Left => input.left(),
            KeyCode::Right => input.right(),
            KeyCode::Home => input.home(),
            KeyCode::End => input.end(),
            KeyCode::Char(c) if !c.is_control() => input.insert(c),
            _ => {}
        }
    }

    pub fn start_add(&mut self) {
        self.wizard.reset();
        if let Some(lan) = &self.lan {
            self.wizard.draft.from_addr = Some(lan.cidr());
            self.wizard.draft.interface_in = Some(lan.iface.clone());
        }
        self.wizard.draft.action = Action::Allow;
        self.tab = Tab::Add;
    }

    pub fn start_edit(&mut self) {
        let Some(rule) = self.selected_rule() else {
            return;
        };
        if rule.is_route() {
            self.set_status(
                StatusLevel::Warn,
                "forward rules are read-only in this version",
            );
            return;
        }
        self.wizard = Wizard {
            step: WizardStep::Review,
            draft: rule.to_draft(),
            cursor: 0,
            input: None,
            error: None,
            editing: Some(rule.number),
            trace: None,
        };
        self.tab = Tab::Add;
    }

    fn delete_selected(&mut self) {
        let Some(rule) = self.selected_rule() else {
            return;
        };
        let change = match command::change_delete(&rule) {
            Ok(change) => change,
            Err(error) => {
                self.set_status(StatusLevel::Error, error);
                return;
            }
        };
        let pending =
            PendingChange::new(ChangeKind::DeleteRule, change.description.clone()).with_rule(rule);
        self.submit(change, pending);
    }

    fn duplicate_selected(&mut self) {
        let Some(rule) = self.selected_rule() else {
            return;
        };
        let draft = rule.to_draft();
        self.wizard = Wizard {
            step: WizardStep::Review,
            draft,
            cursor: 0,
            input: None,
            error: None,
            editing: None,
            trace: None,
        };
        self.tab = Tab::Add;
        self.set_status(StatusLevel::Info, "copied — adjust it, then apply");
    }

    fn move_selected(&mut self) {
        let Some(rule) = self.selected_rule() else {
            return;
        };
        let count = self.state.rules.len() as u32;
        let target = if rule.number > 1 {
            rule.number - 1
        } else {
            count.min(2)
        };
        if target == rule.number {
            self.set_status(StatusLevel::Info, "already at the top");
            return;
        }
        match command::change_move(&rule, target) {
            Ok(change) => {
                let pending = PendingChange::new(ChangeKind::MoveRule, change.description.clone());
                self.submit(change, pending);
                self.rules_cursor = (target.max(1) - 1) as usize;
            }
            Err(error) => self.set_status(StatusLevel::Error, error),
        }
    }

    fn edit_note(&mut self) {
        let Some(rule) = self.selected_rule() else {
            return;
        };
        let mut input = TextInput::new(rule.comment.clone().unwrap_or_default());
        input.end();
        self.wizard = Wizard {
            step: WizardStep::Review,
            draft: rule.to_draft(),
            cursor: 0,
            input: Some((InputField::Note, input)),
            error: None,
            editing: Some(rule.number),
            trace: None,
        };
        self.tab = Tab::Add;
    }

    fn test_selected(&mut self) {
        let Some(rule) = self.selected_rule() else {
            return;
        };
        let packet = packet_for_rule(&rule, self.ssh_port);
        self.traffic.src.set(packet.src.to_string());
        self.traffic.src_port.set(packet.src_port.to_string());
        self.traffic.dst.set(packet.dst.to_string());
        self.traffic.dst_port.set(packet.dst_port.to_string());
        self.traffic.protocol = TRAFFIC_PROTOCOLS
            .iter()
            .position(|p| *p == packet.protocol)
            .unwrap_or(0);
        self.traffic.direction = if packet.direction == Direction::Out {
            1
        } else {
            0
        };
        self.trace = Some(simulate::simulate(&self.state, &self.profiles, &packet));
        self.tab = Tab::Test;
    }

    fn show_rule_details(&mut self) {
        let Some(rule) = self.selected_rule() else {
            return;
        };
        let assessment = self.risk_of(&rule);
        self.modal = Some(Modal::Message(Box::new(MessageModal {
            title: format!("Rule #{}", rule.number),
            body: vec![
                explain::explain_rule(&rule),
                String::new(),
                format!(
                    "Command: ufw {}",
                    command::rule_args(&rule.to_draft(), true)
                        .map(|a| command::render_command(&a)
                            .trim_start_matches("ufw ")
                            .to_string())
                        .unwrap_or_default()
                ),
                format!(
                    "Risk: {} — {}",
                    assessment.level.label(),
                    assessment.summary()
                ),
                format!("Note: {}", rule.comment_text()),
            ],
            level: MessageLevel::Info,
        })));
    }

    // ---------------------------------------------------------------------------------------
    // Add / wizard
    // ---------------------------------------------------------------------------------------

    pub fn wizard_options(&self) -> Vec<(String, String)> {
        match self.wizard.step {
            WizardStep::Goal => vec![
                (
                    "Allow traffic in".into(),
                    "Let something connect to this computer".into(),
                ),
                (
                    "Block traffic".into(),
                    "Stop something from connecting".into(),
                ),
                (
                    "Limit connections".into(),
                    "Allow it, but slow down repeat attempts".into(),
                ),
            ],
            WizardStep::Who => {
                let lan_label = match &self.lan {
                    Some(lan) => format!("Only my local network ({})", lan.cidr()),
                    None => "Only my local network (not detected)".into(),
                };
                vec![
                    (lan_label, "recommended".into()),
                    (
                        "One specific address or network".into(),
                        "you type it in".into(),
                    ),
                    ("Anywhere on the internet".into(), "anyone can try".into()),
                    (
                        "Advanced: interface, direction, logging, note".into(),
                        "".into(),
                    ),
                ]
            }
            WizardStep::Service => {
                let mut out: Vec<(String, String)> = SERVICES
                    .iter()
                    .map(|service| (service.label.to_string(), service.hint.to_string()))
                    .collect();
                for profile in &self.profiles {
                    out.push((
                        profile.name.clone(),
                        format!("app profile: {}", profile.ports_raw),
                    ));
                }
                out.push((
                    "Custom port…".into(),
                    "for example 8080 or 8000:8100".into(),
                ));
                out
            }
            WizardStep::Review => vec![
                ("Test this rule against traffic first".into(), "T".into()),
                ("Apply".into(), "ENTER".into()),
                ("Go back".into(), "ESC".into()),
            ],
            WizardStep::Advanced => {
                let draft = &self.wizard.draft;
                let fields = vec![
                    ("Action", draft.action.ufw().to_string()),
                    ("Direction", draft.direction.label().to_string()),
                    (
                        "Interface",
                        draft.interface_in.clone().unwrap_or_else(|| "any".into()),
                    ),
                    ("Protocol", draft.protocol.label().to_string()),
                    (
                        "From address",
                        draft.from_addr.clone().unwrap_or_else(|| "any".into()),
                    ),
                    ("From port", draft.from_port.to_string()),
                    (
                        "To address",
                        draft.to_addr.clone().unwrap_or_else(|| "any".into()),
                    ),
                    ("To port", draft.to_port.to_string()),
                    ("Logging", draft.log.label().to_string()),
                    ("Note", draft.comment.clone().unwrap_or_default()),
                    ("Done — go to review", String::new()),
                ];
                fields
                    .into_iter()
                    .map(|(label, value)| (label.to_string(), value))
                    .collect()
            }
        }
    }

    pub fn wizard_prompt(&self) -> &'static str {
        match self.wizard.step {
            WizardStep::Goal => "What would you like to do?",
            WizardStep::Who => "Who should it apply to?",
            WizardStep::Service => "Which service?",
            WizardStep::Review => "Review before applying",
            WizardStep::Advanced => "Advanced options",
        }
    }

    fn handle_wizard_key(&mut self, key: KeyEvent) {
        if self.wizard.input.is_some() {
            enum Outcome {
                Keep,
                Cancel,
                Submit(InputField, String),
            }
            let mut outcome = Outcome::Keep;
            if let Some((field, input)) = self.wizard.input.as_mut() {
                match key.code {
                    KeyCode::Esc => outcome = Outcome::Cancel,
                    KeyCode::Enter => {
                        outcome = Outcome::Submit(*field, input.value().trim().to_string())
                    }
                    KeyCode::Backspace => input.backspace(),
                    KeyCode::Delete => input.delete(),
                    KeyCode::Left => input.left(),
                    KeyCode::Right => input.right(),
                    KeyCode::Home => input.home(),
                    KeyCode::End => input.end(),
                    KeyCode::Char(c) if !c.is_control() => input.insert(c),
                    _ => {}
                }
            }
            match outcome {
                Outcome::Keep => {}
                Outcome::Cancel => self.wizard.input = None,
                Outcome::Submit(field, value) => {
                    self.wizard.input = None;
                    self.commit_input(field, value);
                }
            }
            return;
        }

        let options = self.wizard_options().len();
        match key.code {
            KeyCode::Up
            | KeyCode::Down
            | KeyCode::Char('k')
            | KeyCode::Char('j')
            | KeyCode::Home
            | KeyCode::End => {
                let cursor = self.wizard.cursor;
                let len = options;
                let mut updated = cursor;
                Self::move_cursor(&mut updated, key.code, len);
                self.wizard.cursor = updated;
            }
            KeyCode::Esc => self.wizard_back(),
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => self.wizard_confirm(),
            KeyCode::Char('A') => self.wizard.step = WizardStep::Advanced,
            _ => {}
        }
    }

    fn wizard_back(&mut self) {
        self.wizard.error = None;
        self.wizard.trace = None;
        self.wizard.step = match self.wizard.step {
            WizardStep::Goal => {
                self.tab = Tab::Rules;
                WizardStep::Goal
            }
            WizardStep::Who => WizardStep::Goal,
            WizardStep::Service => WizardStep::Who,
            WizardStep::Review => WizardStep::Service,
            WizardStep::Advanced => WizardStep::Who,
        };
        self.wizard.cursor = 0;
    }

    fn wizard_confirm(&mut self) {
        self.wizard.error = None;
        match self.wizard.step {
            WizardStep::Goal => {
                self.wizard.draft.action = match self.wizard.cursor {
                    1 => Action::Deny,
                    2 => Action::Limit,
                    _ => Action::Allow,
                };
                self.wizard.step = WizardStep::Who;
                self.wizard.cursor = 0;
            }
            WizardStep::Who => match self.wizard.cursor {
                0 => {
                    match &self.lan {
                        Some(lan) => {
                            self.wizard.draft.from_addr = Some(lan.cidr());
                            self.wizard.draft.interface_in = Some(lan.iface.clone());
                        }
                        None => {
                            self.wizard.error = Some(
                                "No local network was detected. Use a specific address.".into(),
                            );
                            return;
                        }
                    }
                    self.wizard.step = WizardStep::Service;
                    self.wizard.cursor = 0;
                }
                1 => {
                    let prefill = self.wizard.draft.from_addr.clone().unwrap_or_default();
                    self.wizard.input = Some((InputField::Address, TextInput::new(prefill)));
                }
                2 => {
                    self.wizard.draft.from_addr = None;
                    self.wizard.draft.interface_in = None;
                    self.wizard.step = WizardStep::Service;
                    self.wizard.cursor = 0;
                }
                _ => {
                    self.wizard.step = WizardStep::Advanced;
                    self.wizard.cursor = 0;
                }
            },
            WizardStep::Service => {
                let outcome = self.wizard_service_choice();
                if outcome {
                    if self.wizard.draft.comment.is_none() {
                        self.wizard.draft.comment =
                            Some(explain::short_summary(&self.wizard.draft.to_rule(0)));
                    }
                    self.wizard.step = WizardStep::Review;
                    self.wizard.cursor = 0;
                }
            }
            WizardStep::Review => match self.wizard.cursor {
                0 => self.test_wizard_draft(),
                1 => self.apply_wizard(),
                _ => self.wizard_back(),
            },
            WizardStep::Advanced => self.advanced_confirm(),
        }
    }

    /// Handles the service step. Returns true when the draft is ready to review.
    fn wizard_service_choice(&mut self) -> bool {
        {
            {
                let service_count = SERVICES.len();
                let profile_count = self.profiles.len();
                if self.wizard.cursor < service_count {
                    let service = &SERVICES[self.wizard.cursor];
                    let ports = service.ports;
                    self.wizard.draft.protocol = service.protocol;
                    self.wizard.draft.to_port = if ports.len() == 1 {
                        PortSpec::single(ports[0])
                    } else {
                        PortSpec::Ports(
                            ports
                                .iter()
                                .filter_map(|p| crate::core::rule::PortRange::new(*p, *p).ok())
                                .collect(),
                        )
                    };
                    return true;
                }
                if self.wizard.cursor < service_count + profile_count {
                    let profile = &self.profiles[self.wizard.cursor - service_count];
                    self.wizard.draft.to_port = PortSpec::App(profile.name.clone());
                    self.wizard.draft.protocol = Protocol::Any;
                    return true;
                }
                let prefill = self.wizard.draft.to_port.to_string();
                let prefill = if prefill == "any" {
                    String::new()
                } else {
                    prefill
                };
                self.wizard.input = Some((InputField::Port, TextInput::new(prefill)));
                false
            }
        }
    }

    fn commit_input(&mut self, field: InputField, value: String) {
        match field {
            InputField::Address => {
                if value.is_empty() {
                    self.wizard.error = Some("enter an address or network".into());
                    return;
                }
                self.wizard.draft.from_addr = Some(value);
                self.wizard.draft.interface_in = None;
                self.wizard.step = WizardStep::Service;
                self.wizard.cursor = 0;
            }
            InputField::FromAddress => {
                self.wizard.draft.from_addr = if value.is_empty() || value == "any" {
                    None
                } else {
                    Some(value)
                };
            }
            InputField::Port => match value.parse::<PortSpec>() {
                Ok(spec) => {
                    self.wizard.draft.to_port = spec;
                    if self.wizard.draft.protocol == Protocol::Any
                        && self.wizard.draft.to_port.is_range_or_list()
                    {
                        self.wizard.draft.protocol = Protocol::Tcp;
                    }
                    self.wizard.step = WizardStep::Review;
                    self.wizard.cursor = 0;
                }
                Err(error) => self.wizard.error = Some(error),
            },
            InputField::FromPort => match value.parse::<PortSpec>() {
                Ok(spec) => self.wizard.draft.from_port = spec,
                Err(error) => self.wizard.error = Some(error),
            },
            InputField::Interface => {
                self.wizard.draft.interface_in = if value.is_empty() || value == "any" {
                    None
                } else {
                    Some(value)
                };
            }
            InputField::Note | InputField::AdvancedComment => {
                self.wizard.draft.comment = if value.is_empty() { None } else { Some(value) };
            }
        }
    }

    fn advanced_confirm(&mut self) {
        let cursor = self.wizard.cursor;
        let mut open: Option<(InputField, TextInput)> = None;
        let mut done = false;
        {
            let draft = &mut self.wizard.draft;
            match cursor {
                0 => {
                    let index = Action::ALL
                        .iter()
                        .position(|a| *a == draft.action)
                        .unwrap_or(0);
                    draft.action = Action::ALL[(index + 1) % Action::ALL.len()];
                }
                1 => {
                    draft.direction = if draft.direction == Direction::In {
                        Direction::Out
                    } else {
                        Direction::In
                    };
                }
                2 => {
                    open = Some((
                        InputField::Interface,
                        TextInput::new(draft.interface_in.clone().unwrap_or_default()),
                    ));
                }
                3 => {
                    let index = Protocol::COMMON
                        .iter()
                        .position(|p| *p == draft.protocol)
                        .unwrap_or(0);
                    draft.protocol = Protocol::COMMON[(index + 1) % Protocol::COMMON.len()];
                }
                4 => {
                    open = Some((
                        InputField::FromAddress,
                        TextInput::new(draft.from_addr.clone().unwrap_or_default()),
                    ));
                }
                5 => {
                    let prefill = if draft.from_port.is_any() {
                        String::new()
                    } else {
                        draft.from_port.to_string()
                    };
                    open = Some((InputField::FromPort, TextInput::new(prefill)));
                }
                6 => {
                    open = Some((
                        InputField::FromAddress,
                        TextInput::new(draft.to_addr.clone().unwrap_or_default()),
                    ));
                }
                7 => {
                    let prefill = draft.to_port.to_string();
                    let prefill = if prefill == "any" {
                        String::new()
                    } else {
                        prefill
                    };
                    open = Some((InputField::Port, TextInput::new(prefill)));
                }
                8 => {
                    draft.log = match draft.log {
                        crate::core::rule::LogMode::None => crate::core::rule::LogMode::Log,
                        crate::core::rule::LogMode::Log => crate::core::rule::LogMode::LogAll,
                        crate::core::rule::LogMode::LogAll => crate::core::rule::LogMode::None,
                    };
                }
                9 => {
                    open = Some((
                        InputField::AdvancedComment,
                        TextInput::new(draft.comment.clone().unwrap_or_default()),
                    ));
                }
                _ => done = true,
            }
        }
        if let Some(input) = open {
            self.wizard.input = Some(input);
        }
        if done {
            self.wizard.step = WizardStep::Review;
            self.wizard.cursor = 0;
        }
    }

    fn test_wizard_draft(&mut self) {
        let packet = packet_for_draft(&self.wizard.draft, self.ssh_port);
        let trace = simulate::simulate_with_pending(
            &self.state,
            &self.profiles,
            std::slice::from_ref(&self.wizard.draft),
            &packet,
        );
        self.wizard.trace = Some(trace);
    }

    fn apply_wizard(&mut self) {
        let draft = self.wizard.draft.clone();
        if let Err(error) = draft.validate() {
            self.wizard.error = Some(error);
            return;
        }
        match self.wizard.editing {
            Some(number) => {
                let Some(rule) = self.state.rule(number).cloned() else {
                    self.wizard.error = Some("that rule no longer exists".into());
                    return;
                };
                let change = match command::change_edit(&rule, &draft) {
                    Ok(change) => change,
                    Err(error) => {
                        self.wizard.error = Some(error);
                        return;
                    }
                };
                let pending = PendingChange::new(ChangeKind::EditRule, change.description.clone())
                    .with_rule(rule)
                    .with_draft(draft);
                self.wizard.reset();
                self.tab = Tab::Rules;
                self.submit(change, pending);
            }
            None => {
                let change = match command::change_add(&draft) {
                    Ok(change) => change,
                    Err(error) => {
                        self.wizard.error = Some(error);
                        return;
                    }
                };
                let pending = PendingChange::new(ChangeKind::AddRule, change.description.clone())
                    .with_draft(draft);
                self.wizard.reset();
                self.tab = Tab::Rules;
                self.submit(change, pending);
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Test tab
    // ---------------------------------------------------------------------------------------

    fn handle_traffic_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Tab | KeyCode::Down => self.traffic.field = (self.traffic.field + 1) % 6,
            KeyCode::BackTab | KeyCode::Up => {
                self.traffic.field = (self.traffic.field + 5) % 6;
            }
            KeyCode::Enter => self.run_simulation(),
            KeyCode::Left | KeyCode::Right => match self.traffic.field {
                0 => {
                    self.traffic.direction = if key.code == KeyCode::Left { 0 } else { 1 };
                }
                1 => {
                    let delta = if key.code == KeyCode::Left { 3 } else { 1 };
                    self.traffic.protocol =
                        (self.traffic.protocol + delta) % TRAFFIC_PROTOCOLS.len();
                }
                _ => {}
            },
            KeyCode::Backspace => self.traffic_input().backspace(),
            KeyCode::Delete => self.traffic_input().delete(),
            KeyCode::Char(c) if !c.is_control() => self.traffic_input().insert(c),
            _ => {}
        }
    }

    fn traffic_input(&mut self) -> &mut TextInput {
        match self.traffic.field {
            2 => &mut self.traffic.src,
            3 => &mut self.traffic.src_port,
            4 => &mut self.traffic.dst,
            _ => &mut self.traffic.dst_port,
        }
    }

    pub fn build_packet(&self) -> Result<Packet, String> {
        let src: std::net::IpAddr = self
            .traffic
            .src
            .value()
            .trim()
            .parse()
            .map_err(|_| format!("'{}' is not an IP address", self.traffic.src.value()))?;
        let dst: std::net::IpAddr = self
            .traffic
            .dst
            .value()
            .trim()
            .parse()
            .map_err(|_| format!("'{}' is not an IP address", self.traffic.dst.value()))?;
        let src_port: u16 = self
            .traffic
            .src_port
            .value()
            .trim()
            .parse()
            .map_err(|_| "source port must be a number".to_string())?;
        let dst_port: u16 = self
            .traffic
            .dst_port
            .value()
            .trim()
            .parse()
            .map_err(|_| "destination port must be a number".to_string())?;
        let direction = if self.traffic.direction == 1 {
            Direction::Out
        } else {
            Direction::In
        };
        let protocol = TRAFFIC_PROTOCOLS
            .get(self.traffic.protocol)
            .copied()
            .unwrap_or(Protocol::Tcp);
        Ok(Packet {
            direction,
            iface: self.lan.as_ref().map(|lan| lan.iface.clone()),
            protocol,
            src,
            src_port,
            dst,
            dst_port,
            established: false,
            loopback: src.is_loopback() && dst.is_loopback(),
        })
    }

    pub fn run_simulation(&mut self) {
        match self.build_packet() {
            Ok(packet) => {
                self.trace = Some(simulate::simulate(&self.state, &self.profiles, &packet));
                self.set_status(StatusLevel::Info, "simulated — nothing was changed");
            }
            Err(error) => self.set_status(StatusLevel::Error, error),
        }
    }

    // ---------------------------------------------------------------------------------------
    // Activity
    // ---------------------------------------------------------------------------------------

    fn handle_activity_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Down | KeyCode::Char('k') | KeyCode::Char('j') => {
                let len = self.activity_rows.len();
                Self::move_cursor(&mut self.activity_cursor, key.code, len);
            }
            KeyCode::Char(' ') => {
                self.paused = !self.paused;
                self.set_status(
                    StatusLevel::Info,
                    if self.paused {
                        "paused"
                    } else {
                        "watching again"
                    },
                );
            }
            KeyCode::Char('B') => self.block_selected_source(),
            KeyCode::Char('c') => {
                self.activity_rows.clear();
                self.set_status(StatusLevel::Info, "cleared the view");
            }
            _ => {}
        }
    }

    fn block_selected_source(&mut self) {
        let Some(row) = self.activity_rows.get(self.activity_cursor).cloned() else {
            return;
        };
        let draft = RuleDraft {
            action: Action::Deny,
            from_addr: Some(row.src.to_string()),
            comment: Some("ufw-manager-tui: blocked from activity".into()),
            ..Default::default()
        };
        match command::change_add(&draft) {
            Ok(change) => {
                let pending = PendingChange::new(ChangeKind::AddRule, change.description.clone())
                    .with_draft(draft);
                self.submit(change, pending);
            }
            Err(error) => self.set_status(StatusLevel::Error, error),
        }
    }

    // ---------------------------------------------------------------------------------------
    // Presets
    // ---------------------------------------------------------------------------------------

    fn handle_presets_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Down | KeyCode::Char('k') | KeyCode::Char('j') => {
                Self::move_cursor(&mut self.preset_cursor, key.code, self.presets.len())
            }
            KeyCode::Enter => {
                let Some(card) = self.presets.get(self.preset_cursor).cloned() else {
                    return;
                };
                if let Some(reason) = card.blocked {
                    self.set_status(StatusLevel::Warn, reason);
                    return;
                }
                self.enqueue_preset(&card.preset);
            }
            _ => {}
        }
    }

    fn enqueue_preset(&mut self, preset: &presets::Preset) {
        let context = self.preset_context();
        match preset.changes(&context) {
            Ok(changes) if changes.is_empty() => {
                self.set_status(StatusLevel::Info, "nothing to do for that one")
            }
            Ok(changes) => {
                for change in changes {
                    self.queue.push_back(change);
                }
                self.next_in_queue();
            }
            Err(error) => self.set_status(StatusLevel::Error, error),
        }
    }

    fn next_in_queue(&mut self) {
        let Some(change) = self.queue.pop_front() else {
            return;
        };
        let kind = if change.description.contains("Reset") {
            ChangeKind::Reset
        } else {
            classify(&change)
        };
        let pending = PendingChange::new(kind, change.description.clone());
        self.submit(change, pending);
    }

    // ---------------------------------------------------------------------------------------
    // Writes
    // ---------------------------------------------------------------------------------------

    /// The single choke point for every change: guard, dry-run, confirm, apply, journal.
    pub fn submit(&mut self, change: Change, pending: PendingChange) {
        if self.readonly {
            self.set_status(
                StatusLevel::Warn,
                "read-only mode: rerun with sudo, or press X to escalate",
            );
            return;
        }
        if !self.backend.can_write() {
            if self.backend.may_escalate() {
                self.escalation = Some(Escalation::Write(Box::new((change, pending))));
                return;
            }
            self.set_status(StatusLevel::Warn, "this backend cannot change the firewall");
            return;
        }

        let guard = lockout::check(&self.session, &pending, &self.state);
        if let GuardVerdict::Block(reason) = &guard {
            self.modal = Some(Modal::Message(Box::new(MessageModal {
                title: "This would lock you out".into(),
                body: vec![reason.clone()],
                level: MessageLevel::Error,
            })));
            return;
        }

        if !self.confirm_before_apply || self.yes {
            self.apply(&change);
            return;
        }

        // Every step is validated, not just the first: a delete-then-insert edit can be rejected by
        // the second command even when the first is fine.
        let mut dry: Result<Option<CmdOutput>, String> = Ok(None);
        for step in &change.steps {
            match self.backend.dry_run(step) {
                Ok(output) if output.success => dry = Ok(Some(output)),
                Ok(output) => {
                    dry = Err(output.message());
                    break;
                }
                Err(error) => {
                    dry = Err(friendly_error(&error));
                    break;
                }
            }
        }
        if let Err(message) = &dry {
            self.modal = Some(Modal::Message(Box::new(MessageModal {
                title: "ufw rejected this change".into(),
                body: vec![
                    message.clone(),
                    String::new(),
                    "Nothing was changed.".into(),
                ],
                level: MessageLevel::Error,
            })));
            return;
        }

        let meaning = meaning_of(&change, &pending);
        self.modal = Some(Modal::Confirm(Box::new(ConfirmModal {
            change,
            pending,
            dry: dry.ok().flatten(),
            guard,
            meaning,
            show_dry: false,
        })));
    }

    fn apply(&mut self, change: &Change) {
        let mut failures = Vec::new();
        for step in &change.steps {
            match self.backend.run(step) {
                Ok(output) if output.success => {}
                Ok(output) => failures.push(format!(
                    "{}\n{}",
                    output.command(),
                    output.message().if_empty("(ufw said nothing)")
                )),
                Err(error) => failures.push(friendly_error(&error)),
            }
        }

        if !failures.is_empty() {
            self.modal = Some(Modal::Message(Box::new(MessageModal {
                title: "ufw reported an error".into(),
                body: failures,
                level: MessageLevel::Error,
            })));
            self.refresh();
            return;
        }

        self.journal.record(change);
        if let Some(path) = &self.journal_path {
            let _ = self.journal.save(path);
        }
        self.refresh();
        self.set_status(StatusLevel::Good, format!("done: {}", change.description));

        if needs_watchdog(change) && self.session.via_ssh && !change.inverse.is_empty() {
            self.watchdog = watchdog::spawn(
                change.inverse.clone(),
                change.description.clone(),
                self.reconcile_seconds,
            );
            if self.watchdog.is_none() {
                self.set_status(
                    StatusLevel::Warn,
                    "applied, but the automatic revert helper could not start",
                );
            }
        }

        if !self.queue.is_empty() {
            self.next_in_queue();
        }
    }

    pub fn confirm_watchdog(&mut self) {
        if let Some(watchdog) = self.watchdog.take() {
            let _ = watchdog.confirm();
            watchdog.cleanup();
            self.set_status(StatusLevel::Good, "kept — you are still connected");
        }
    }

    pub fn undo(&mut self) {
        let Some(entry) = self.journal.last().cloned() else {
            self.set_status(StatusLevel::Info, "nothing to undo");
            return;
        };
        if entry.inverse.is_empty() {
            self.set_status(StatusLevel::Warn, "that change cannot be undone");
            return;
        }
        if self.readonly || !self.backend.can_write() {
            self.set_status(StatusLevel::Warn, "read-only mode: cannot undo");
            return;
        }

        let change = Change {
            description: format!("Undo: {}", entry.description),
            steps: entry.inverse.clone(),
            inverse: entry.forward.clone(),
        };
        let mut failures = Vec::new();
        for step in &change.steps {
            if let Err(error) = self.backend.run(step) {
                failures.push(friendly_error(&error));
            }
        }
        if failures.is_empty() {
            self.journal.take_last();
            if let Some(path) = &self.journal_path {
                let _ = self.journal.save(path);
            }
            self.refresh();
            self.set_status(StatusLevel::Good, format!("undone: {}", entry.description));
        } else {
            self.modal = Some(Modal::Message(Box::new(MessageModal {
                title: "Undo failed".into(),
                body: failures,
                level: MessageLevel::Error,
            })));
        }
    }

    // ---------------------------------------------------------------------------------------
    // Modals
    // ---------------------------------------------------------------------------------------

    fn handle_modal_key(&mut self, key: KeyEvent) {
        let Some(modal) = self.modal.take() else {
            return;
        };
        match modal {
            Modal::Message(message) => match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {}
                _ => self.modal = Some(Modal::Message(message)),
            },
            Modal::Confirm(mut confirm) => match key.code {
                KeyCode::Enter | KeyCode::Char('y') => {
                    let change = confirm.change.clone();
                    self.apply(&change);
                }
                KeyCode::Char('d') | KeyCode::Char('D') => {
                    confirm.show_dry = !confirm.show_dry;
                    self.modal = Some(Modal::Confirm(confirm));
                }
                KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('q') => {
                    self.queue.clear();
                    self.set_status(StatusLevel::Info, "cancelled");
                }
                _ => self.modal = Some(Modal::Confirm(confirm)),
            },
        }
    }

    pub fn take_escalation(&mut self) -> Option<Escalation> {
        self.escalation.take()
    }

    /// Called after the terminal has been restored and `sudo -v` has run.
    pub fn after_escalation(
        &mut self,
        granted: bool,
        pending: Option<Box<(Change, PendingChange)>>,
    ) {
        if !granted {
            let message = match pending {
                Some(_) => "sudo was refused; nothing was changed",
                None => "sudo was refused; still read-only",
            };
            self.set_status(StatusLevel::Error, message);
            return;
        }
        self.readonly = false;
        self.refresh();
        match pending {
            Some(boxed) => {
                let (change, pending) = *boxed;
                self.submit(change, pending);
            }
            None => self.set_status(
                StatusLevel::Good,
                "privileges granted — rules are visible now",
            ),
        }
    }

    /// `X`: ask sudo for privileges so the rules can be read and written.
    fn request_privileges(&mut self) {
        if self.backend.can_write() {
            self.set_status(StatusLevel::Info, "already running as root");
        } else if self.backend.may_escalate() {
            self.escalation = Some(Escalation::Privileges);
        } else {
            self.set_status(
                StatusLevel::Warn,
                "escalation is disabled; restart with sudo (or drop --readonly / --no-escalate)",
            );
        }
    }

    pub fn tick(&mut self) {
        if !self.paused {
            self.activity_rows = self.blocks.rows();
        }
        if let Some(watchdog) = &self.watchdog {
            if watchdog.remaining() == 0 {
                self.watchdog = None;
            }
        }
    }

    pub fn watchdog_remaining(&self) -> Option<u64> {
        self.watchdog.as_ref().map(|w| w.remaining())
    }

    pub fn help_text(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for section in crate::ui::keys::help_sections() {
            lines.push(section.title.to_string());
            for (keys, label) in section.entries {
                lines.push(format!("  {:<18} {}", keys, label));
            }
            lines.push(String::new());
        }
        lines
    }
}

fn classify(change: &Change) -> ChangeKind {
    let first = change
        .steps
        .first()
        .map(|s| s.join(" "))
        .unwrap_or_default();
    if first.contains("default") {
        ChangeKind::SetDefaultIncoming
    } else if first.contains("logging") {
        ChangeKind::SetLogging
    } else if first.contains("enable") {
        ChangeKind::Enable
    } else if first.contains("disable") {
        ChangeKind::Disable
    } else if first.contains("reset") {
        ChangeKind::Reset
    } else if change.description.starts_with("Delete") {
        ChangeKind::DeleteRule
    } else {
        ChangeKind::AddRule
    }
}

fn needs_watchdog(change: &Change) -> bool {
    let text = change
        .steps
        .iter()
        .map(|s| s.join(" "))
        .collect::<Vec<_>>()
        .join(";");
    text.contains("enable") || text.contains("default") || text.contains("reset")
}

/// The human sentence shown in the confirmation dialog. Prefer a rule explanation when the change is
/// about a specific rule; otherwise the description already reads like a sentence.
fn meaning_of(change: &Change, pending: &PendingChange) -> String {
    if let Some(draft) = &pending.draft {
        return explain::explain_draft(draft);
    }
    if let Some(rule) = &pending.rule {
        let verb = if change
            .steps
            .iter()
            .any(|step| step.iter().any(|arg| arg == "delete"))
        {
            "Remove the rule that says:"
        } else {
            "This rule says:"
        };
        return format!("{verb} {}", explain::explain_rule(rule));
    }
    change.description.trim_end_matches('.').to_string()
}

fn friendly_error(error: &BackendError) -> String {
    match error {
        BackendError::NotFound => {
            "ufw is not installed. On Ubuntu or Debian: sudo apt install ufw".to_string()
        }
        other => other.to_string(),
    }
}

/// Used when we cannot read rules (no root): the world-readable `ufw.conf` still tells us whether
/// the firewall is on and how it logs.
fn read_unprivileged_state() -> FirewallState {
    let conf = std::fs::read_to_string("/etc/ufw/ufw.conf")
        .map(|text| parse_ufw_conf(&text))
        .unwrap_or_default();
    FirewallState {
        enabled: conf.enabled.unwrap_or(false),
        log_level: conf.log_level.unwrap_or(LogLevel::Low),
        rules_readable: false,
        ..Default::default()
    }
}

fn packet_for_draft(draft: &RuleDraft, ssh_port: u16) -> Packet {
    let dst_port = draft
        .to_port
        .single_port()
        .or_else(|| draft.to_port.first_port())
        .unwrap_or(ssh_port);
    let src = draft
        .from_addr
        .as_deref()
        .and_then(crate::core::rule::parse_net)
        .map(|net| net.network())
        .map(bump)
        .unwrap_or_else(|| "203.0.113.9".parse().expect("valid literal"));
    Packet {
        direction: draft.direction,
        iface: draft.interface_in.clone(),
        protocol: if draft.protocol == Protocol::Any {
            Protocol::Tcp
        } else {
            draft.protocol
        },
        src,
        src_port: 51_000,
        dst: "192.168.1.19".parse().expect("valid literal"),
        dst_port,
        established: false,
        loopback: false,
    }
}

/// A sample address that sits inside `ip`'s subnet, so "does my LAN rule actually cover me?" is
/// answerable.
fn bump(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let mut octets = v4.octets();
            octets[3] = octets[3].wrapping_add(1).max(1);
            std::net::IpAddr::V4(octets.into())
        }
        other => other,
    }
}

fn packet_for_rule(rule: &Rule, ssh_port: u16) -> Packet {
    let dst_port = rule
        .to
        .port
        .single_port()
        .or_else(|| rule.to.port.first_port())
        .unwrap_or(ssh_port);
    let src = rule
        .from
        .addr
        .as_deref()
        .and_then(crate::core::rule::parse_net)
        .map(|net| bump(net.network()))
        .unwrap_or_else(|| "203.0.113.9".parse().expect("valid literal"));
    Packet {
        direction: rule.direction,
        iface: rule.interface_in.clone(),
        protocol: if rule.protocol == Protocol::Any {
            Protocol::Tcp
        } else {
            rule.protocol
        },
        src,
        src_port: 51_000,
        dst: "192.168.1.19".parse().expect("valid literal"),
        dst_port,
        established: false,
        loopback: false,
    }
}

trait IfEmpty {
    fn if_empty(self, fallback: &str) -> String;
}

impl IfEmpty for String {
    fn if_empty(self, fallback: &str) -> String {
        if self.trim().is_empty() {
            fallback.to_string()
        } else {
            self
        }
    }
}
