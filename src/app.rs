//! Application state and key handling.
//!
//! Everything here is synchronous: `ufw status` takes a few tens of milliseconds, and each write is
//! validated with `--dry-run` first, so a modal spinner would add more complexity than it removes.

use std::collections::VecDeque;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::backend::logs::BlockMonitor;
use crate::backend::{Backend, BackendError, BlockRow, CmdOutput, HitCounters};
use crate::config::Config;
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
/**
 * The top-level screens of the application.
 *
 * Each variant is one tab in the tab bar; the order of the variants matches
 * the order of [`Tab::ALL`] and therefore the digit shortcuts.
 *
 * # Variants
 *
 * * `Home` - Firewall status and prioritized suggestions.
 * * `Rules` - The rule list, in the order ufw evaluates it.
 * * `Add` - The guided rule wizard.
 * * `Test` - Packet simulation against the current rules.
 * * `Activity` - Live blocked traffic and session changes.
 * * `Presets` - One-key recipes for common jobs.
 * * `Help` - Key bindings and jargon.
 */
pub enum Tab {
    Home,
    Rules,
    Add,
    Test,
    Activity,
    Presets,
    Help,
    Settings,
}

impl Tab {
    pub const ALL: [Tab; 8] = [
        Tab::Home,
        Tab::Rules,
        Tab::Add,
        Tab::Test,
        Tab::Activity,
        Tab::Presets,
        Tab::Help,
        Tab::Settings,
    ];

    /**
     * Returns the display title of this tab.
     *
     * The title is the short label shown in the tab bar.
     *
     * # Arguments
     *
     * * `self` (`Tab`) - The tab whose title is wanted; the value is copied.
     *
     * # Returns
     *
     * `&'static str` - The static, human-readable tab name.
     */
    pub fn title(self) -> &'static str {
        match self {
            Tab::Home => "Home",
            Tab::Rules => "Rules",
            Tab::Add => "Add",
            Tab::Test => "Test",
            Tab::Activity => "Activity",
            Tab::Presets => "Presets",
            Tab::Help => "Help",
            Tab::Settings => "Settings",
        }
    }

    /**
     * Returns the one-line explanation of what this tab is for.
     *
     * The text is shown under the tab bar so a first-time user knows what the
     * screen answers.
     *
     * # Arguments
     *
     * * `self` (`Tab`) - The tab whose description is wanted; the value is copied.
     *
     * # Returns
     *
     * `&'static str` - The static description sentence for the tab.
     */
    pub fn description(self) -> &'static str {
        match self {
            Tab::Home => "Is the firewall on, and how exposed is this machine?",
            Tab::Rules => "Every rule, in the order ufw checks them. The first match wins.",
            Tab::Add => "Pick a goal and the correct rule is built for you.",
            Tab::Test => "Send a pretend packet and see which rule decides its fate.",
            Tab::Activity => "What is being blocked right now, and what this session changed.",
            Tab::Presets => "One-key recipes for the jobs people actually have.",
            Tab::Help => "Keys, and what the jargon means.",
            Tab::Settings => "Defaults for new rules, and how the wizard behaves.",
        }
    }

    /**
     * Returns the position of this tab in [`Tab::ALL`].
     *
     * # Arguments
     *
     * * `self` (`Tab`) - The tab to locate; the value is copied.
     *
     * # Returns
     *
     * `usize` - The zero-based index of the tab, or `0` if it is somehow absent from [`Tab::ALL`].
     */
    pub fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }

    /**
     * Maps a typed digit to the tab it selects.
     *
     * Digits `1` through `8` select the tabs in [`Tab::ALL`] order; `0` and any
     * non-digit character select nothing.
     *
     * # Arguments
     *
     * * `digit` (`char`) - The character the user typed.
     *
     * # Returns
     * `Option<Tab>` - The matching tab, or `None` when the character is not a digit or is out of range.
     */
    pub fn from_digit(digit: char) -> Option<Tab> {
        let index = digit.to_digit(10)?;
        if index == 0 {
            return None;
        }
        Tab::ALL.get(index as usize - 1).copied()
    }

    /**
     * Returns the tab `delta` positions away, wrapping around both ends.
     *
     * # Arguments
     *
     * * `self` (`Tab`) - The tab to move from; the value is copied.
     * * `delta` (`isize`) - The signed number of tabs to move; negative values
     *   move backwards.
     *
     * # Returns
     *
     * `Tab` - The tab at the wrapped position.
     */
    pub fn next(self, delta: isize) -> Tab {
        let len = Tab::ALL.len() as isize;
        let index = ((self.index() as isize + delta) % len + len) % len;
        Tab::ALL[index as usize]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/**
 * Severity of a status line message.
 *
 * The level only affects presentation; it does not change control flow.
 *
 * # Variants
 *
 * * `Info` - Neutral information.
 * * `Good` - A change succeeded.
 * * `Warn` - Something needs attention but is not fatal.
 * * `Error` - An operation failed.
 */
pub enum StatusLevel {
    Info,
    Good,
    Warn,
    Error,
}

#[derive(Debug, Clone)]
/**
 * A transient message shown in the status line.
 *
 * # Fields
 *
 * * `level` (`StatusLevel`) - The severity used to colour the message.
 * * `text` (`String`) - The message body.
 */
pub struct StatusMessage {
    pub level: StatusLevel,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/**
 * The steps of the guided rule wizard.
 *
 * The wizard advances through these in order, with `Advanced` reachable as a
 * side branch from the `Who` step.
 *
 * # Variants
 *
 * * `Goal` - Choose allow, block, or limit.
 * * `Who` - Choose the source scope.
 * * `Service` - Choose the service or port.
 * * `Review` - Test or apply the draft.
 * * `Advanced` - Edit individual draft fields.
 */
pub enum WizardStep {
    Goal,
    Who,
    Service,
    Review,
    Advanced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/**
 * Identifies which wizard draft field an open text input edits.
 *
 * # Variants
 *
 * * `Address` - The source address typed on the `Who` step.
 * * `Port` - The destination port or port list.
 * * `Interface` - The incoming interface name.
 * * `Note` - The rule comment edited from the Rules tab.
 * * `FromAddress` - The source address on the advanced step.
 * * `FromPort` - The source port on the advanced step.
 * * `AdvancedComment` - The comment edited on the advanced step.
 */
pub enum InputField {
    Address,
    Port,
    Interface,
    Note,
    FromAddress,
    FromPort,
    AdvancedComment,
}

/**
 * Identifies which settings row an open text input edits.
 *
 * # Variants
 *
 * * `Interface` - The default incoming interface.
 * * `FromAddress` - The default source address or network.
 * * `ToAddress` - The default destination address or network.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsField {
    Interface,
    FromAddress,
    ToAddress,
}

/// Number of rows on the Settings tab: the seven rule defaults plus the skip-wizard checkbox.
pub const SETTINGS_ROW_COUNT: usize = 8;

/**
 * State of the guided rule wizard.
 *
 * The wizard holds the draft being built, the option cursor, an optional open
 * text input, the last validation error, the rule being edited (if any), and
 * the last simulation trace.
 *
 * # Fields
 *
 * * `step` (`WizardStep`) - The step currently displayed.
 * * `draft` (`RuleDraft`) - The rule being assembled.
 * * `cursor` (`usize`) - The selected option on the current step.
 * * `input` (`Option<(InputField, TextInput)>`) - The open text field, if any.
 * * `error` (`Option<String>`) - The last validation error to display.
 * * `editing` (`Option<u32>`) - The rule number being edited, or `None` when adding.
 * * `trace` (`Option<Trace>`) - The result of testing the draft, if tested.
 */
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
    /**
     * Implements [`Default`] for [`Wizard`].
     *
     * Produces a wizard sitting on the first step with an empty draft, no open
     * input, no error, no edit target, and no trace.
     *
     * # Arguments
     *
     * This method takes no arguments.
     *
     * # Returns
     *
     * `Self` - A fresh [`Wizard`] in its initial state.
     */
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
    /**
     * Resets the wizard back to its default state.
     *
     * The whole struct is overwritten with [`Wizard::default`], discarding the
     * draft, any open input, errors, the edit target, and the last trace.
     *
     * # Arguments
     *
     * * `&mut self` - The wizard state being reset.
     *
     * # Returns
     *
     * This method returns no value.
     */
    fn reset(&mut self) {
        *self = Self::default();
    }
}

/**
 * The Test tab's packet form.
 *
 * Holds the field cursor, the selected direction and protocol indexes, and the
 * four text inputs that describe the packet.
 *
 * # Fields
 *
 * * `field` (`usize`) - The focused field, from 0 to 5.
 * * `direction` (`usize`) - `0` for incoming, `1` for outgoing.
 * * `protocol` (`usize`) - Index into [`TRAFFIC_PROTOCOLS`].
 * * `src` (`TextInput`) - Source address.
 * * `src_port` (`TextInput`) - Source port.
 * * `dst` (`TextInput`) - Destination address.
 * * `dst_port` (`TextInput`) - Destination port.
 */
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
    /**
     * Implements [`Default`] for [`TrafficForm`].
     *
     * Pre-fills the form with a sample packet (an external source talking to
     * `192.168.1.19:22`) so the Test tab is immediately usable.
     *
     * # Arguments
     *
     * This method takes no arguments.
     *
     * # Returns
     *
     * `Self` - A [`TrafficForm`] with sample addresses and ports filled in.
     */
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

/**
 * The confirmation dialog shown before a change is applied.
 *
 * # Fields
 *
 * * `change` (`Change`) - The change that will run if confirmed.
 * * `pending` (`PendingChange`) - The lockout-check metadata for the change.
 * * `dry` (`Option<CmdOutput>`) - The last successful `ufw --dry-run` output.
 * * `guard` (`GuardVerdict`) - The lockout check result.
 * * `meaning` (`String`) - The plain-English sentence describing the change.
 * * `show_dry` (`bool`) - Whether the dry-run output is currently expanded.
 */
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
/**
 * Severity of a modal message.
 *
 * # Variants
 *
 * * `Info` - Informational content.
 * * `Warning` - Something the user should notice.
 * * `Error` - A failure that needs attention.
 */
pub enum MessageLevel {
    Info,
    Warning,
    Error,
}

/**
 * A modal that shows a title and a block of text.
 *
 * # Fields
 *
 * * `title` (`String`) - The heading shown at the top of the modal.
 * * `body` (`Vec<String>`) - The body lines, rendered one per row.
 * * `level` (`MessageLevel`) - The severity used to style the modal.
 */
pub struct MessageModal {
    pub title: String,
    pub body: Vec<String>,
    pub level: MessageLevel,
}

/**
 * The modal currently covering the screen, if any.
 *
 * # Variants
 *
 * * `Confirm` - A confirmation dialog for a pending change.
 * * `Message` - A read-only message dialog.
 */
pub enum Modal {
    Confirm(Box<ConfirmModal>),
    Message(Box<MessageModal>),
}

/**
 * A request to leave the terminal briefly and ask `sudo` for privileges.
 *
 * The event loop takes the request with [`App::take_escalation`], restores the
 * terminal, runs `sudo -v`, and reports the outcome through
 * [`App::after_escalation`].
 *
 * # Variants
 *
 * * `Write(Box<(Change, PendingChange)>)` - Retry a change that could not be written once privileges are granted.
 * * `Privileges` - Just gain privileges so the rules become visible.
 */
pub enum Escalation {
    /// Retry a change that could not be written.
    Write(Box<(Change, PendingChange)>),
    /// Just gain privileges so the rules become visible.
    Privileges,
}

/**
 * Startup options passed to [`App::new`].
 *
 * # Fields
 *
 * * `journal_path` (`Option<std::path::PathBuf>`) - Where the undo journal is stored; `None` keeps it in memory only.
 * * `yes` (`bool`) - Skip the confirmation dialog.
 * * `readonly` (`bool`) - Refuse all writes.
 * * `theme` (`Theme`) - The colour theme to use.
 * * `reconcile_seconds` (`u64`) - How long the watchdog waits before reverting.
 * * `show_counters` (`bool`) - Whether rule hit counters are displayed.
 * * `confirm_before_apply` (`bool`) - Whether changes need confirmation.
 * * `config` (`Config`) - The user preferences, edited on the Settings tab.
 * * `config_path` (`Option<std::path::PathBuf>`) - Where the config is saved; `None` disables persistence.
 */
pub struct AppOptions {
    /// Where the undo journal lives. `None` keeps it in memory only, which is what tests want.
    pub journal_path: Option<std::path::PathBuf>,
    pub yes: bool,
    pub readonly: bool,
    pub theme: Theme,
    pub reconcile_seconds: u64,
    pub show_counters: bool,
    pub confirm_before_apply: bool,
    pub config: Config,
    pub config_path: Option<std::path::PathBuf>,
}

/**
 * The whole application state.
 *
 * Holds the backend, the current firewall snapshot, derived analysis, all
 * cursors and form state, the pending modal and change queue, and the flags
 * that control writes.
 *
 * # Fields
 *
 * * `backend` (`Box<dyn Backend>`) - The backend used for reads and writes.
 * * `theme` (`Theme`) - The active colour theme.
 * * `tab` (`Tab`) - The active tab.
 * * `state` (`FirewallState`) - The last read firewall snapshot.
 * * `profiles` (`Vec<AppProfile>`) - Application profiles reported by ufw.
 * * `listening` (`Vec<Listening>`) - Listening sockets found on the host.
 * * `counters` (`HitCounters`) - Per-rule hit counters.
 * * `blocks` (`BlockMonitor`) - The live blocked-traffic monitor.
 * * `journal` (`Journal`) - The undo journal.
 * * `journal_path` (`Option<std::path::PathBuf>`) - Where the journal is saved.
 * * `suggestions` (`Vec<Suggestion>`) - Prioritized recommendations.
 * * `shadowed` (`Vec<(u32, u32)>`) - Rule pairs where one shadows another.
 * * `lan` (`Option<LanInfo>`) - The detected local network, if any.
 * * `session` (`Session`) - The current login session.
 * * `ssh_port` (`u16`) - The SSH port in use.
 * * `hostname` (`String`) - The host name shown in the UI.
 * * `rules_cursor` (`usize`) - Selected row on the Rules tab.
 * * `home_cursor` (`usize`) - Selected suggestion on the Home tab.
 * * `preset_cursor` (`usize`) - Selected preset on the Presets tab.
 * * `activity_cursor` (`usize`) - Selected row on the Activity tab.
 * * `help_scroll` (`u16`) - Scroll offset on the Help tab.
 * * `settings_cursor` (`usize`) - Selected row on the Settings tab.
 * * `filter` (`Option<TextInput>`) - The rules filter text, if set.
 * * `filter_open` (`bool`) - Whether the filter is being edited.
 * * `wizard` (`Wizard`) - The Add tab wizard state.
 * * `traffic` (`TrafficForm`) - The Test tab form state.
 * * `trace` (`Option<Trace>`) - The last simulation result.
 * * `presets` (`Vec<PresetCard>`) - The preset cards for the current context.
 * * `modal` (`Option<Modal>`) - The modal covering the screen, if any.
 * * `queue` (`VecDeque<Change>`) - Changes waiting to be submitted.
 * * `status` (`Option<StatusMessage>`) - The current status line message.
 * * `config` (`Config`) - The user preferences, edited on the Settings tab.
 * * `config_path` (`Option<std::path::PathBuf>`) - Where the config is saved.
 * * `settings_input` (`Option<(SettingsField, TextInput)>`) - The open settings text field, if any.
 * * `readonly` (`bool`) - Whether writes are refused.
 * * `yes` (`bool`) - Whether confirmation is skipped.
 * * `confirm_before_apply` (`bool`) - Whether changes need confirmation.
 * * `show_counters` (`bool`) - Whether hit counters are displayed.
 * * `reconcile_seconds` (`u64`) - Watchdog delay before reverting.
 * * `skip_wizard` (`bool`) - Whether new rules start on the advanced step.
 * * `should_quit` (`bool`) - Set when the user asked to exit.
 * * `escalation` (`Option<Escalation>`) - A pending request to run `sudo`.
 * * `watchdog` (`Option<Watchdog>`) - The running revert watchdog, if any.
 * * `paused` (`bool`) - Whether live activity updates are paused.
 * * `activity_rows` (`Vec<BlockRow>`) - The rows shown on the Activity tab.
 */
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
    pub settings_cursor: usize,

    pub filter: Option<TextInput>,
    pub filter_open: bool,

    pub wizard: Wizard,
    pub traffic: TrafficForm,
    pub trace: Option<Trace>,
    pub presets: Vec<PresetCard>,

    pub modal: Option<Modal>,
    pub queue: VecDeque<Change>,

    pub status: Option<StatusMessage>,
    pub config: Config,
    pub config_path: Option<std::path::PathBuf>,
    pub settings_input: Option<(SettingsField, TextInput)>,
    pub readonly: bool,
    pub yes: bool,
    pub confirm_before_apply: bool,
    pub show_counters: bool,
    pub reconcile_seconds: u64,
    pub skip_wizard: bool,
    pub should_quit: bool,

    pub escalation: Option<Escalation>,
    pub watchdog: Option<Watchdog>,
    pub paused: bool,
    pub activity_rows: Vec<BlockRow>,
}

/**
 * A service offered on the wizard's third step.
 *
 * The built-in entries live in [`SERVICES`]; application profiles are appended
 * to that list at runtime.
 *
 * # Fields
 *
 * * `label` (`&'static str`) - The name shown in the option list.
 * * `hint` (`&'static str`) - The short port hint shown beside the label.
 * * `ports` (`&'static [u16]`) - The ports the service opens.
 * * `protocol` (`Protocol`) - The protocol the service uses.
 */
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
    /**
     * Builds the application state and performs the first read of the firewall.
     *
     * The hostname is read from `/etc/hostname` (falling back to `localhost`), the
     * undo journal is loaded from `options.journal_path` when one is configured,
     * and every field is initialized to an empty or default value before
     * [`App::bootstrap`] is called.
     *
     * # Arguments
     *
     * * `backend` (`Box<dyn Backend>`) - The backend used for all reads and
     *   writes; it is moved into the returned app.
     * * `options` (`AppOptions`) - Startup options such as the journal path,
     *   read-only mode, theme, and confirmation behaviour.
     *
     * # Returns
     *
     * `Self` - The fully initialized [`App`], already bootstrapped.
     *
     * # Notes
     *
     * Failures while reading `/etc/hostname` or the journal are ignored and fall
     * back to defaults.
     */
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
            settings_cursor: 0,
            filter: None,
            filter_open: false,
            wizard: Wizard::default(),
            traffic: TrafficForm::default(),
            trace: None,
            presets: Vec::new(),
            modal: None,
            queue: VecDeque::new(),
            status: None,
            config: options.config,
            config_path: options.config_path,
            settings_input: None,
            readonly: options.readonly,
            yes: options.yes,
            confirm_before_apply: options.confirm_before_apply,
            show_counters: options.show_counters,
            reconcile_seconds: options.reconcile_seconds,
            skip_wizard: false,
            should_quit: false,
            escalation: None,
            watchdog: None,
            paused: false,
            activity_rows: Vec::new(),
        };
        app.skip_wizard = app.config.skip_wizard;
        app.bootstrap();
        app
    }

    /**
     * Performs the first read of the firewall and its surroundings.
     *
     * The LAN, SSH session, SSH port, block monitor, application profiles, and
     * listening sockets are loaded, then [`App::refresh`] reads the rules.
     * Failures are reported, never fatal: a user with a broken ufw still needs
     * to see why it is broken.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being initialized and mutated.
     *
     * # Returns
     *
     * This method returns no value.
     *
     * # Notes
     *
     * Profile and listening-socket read errors are swallowed and replaced with
     * empty lists.
     */
    pub fn bootstrap(&mut self) {
        self.lan = self.backend.lan();
        self.session = self.backend.ssh_session();
        self.ssh_port = self.backend.ssh_port();
        self.blocks = BlockMonitor::start(self.backend.log_path());
        self.profiles = self.backend.app_profiles().unwrap_or_default();
        self.listening = self.backend.listening().unwrap_or_default();
        self.refresh();
    }

    /**
     * Re-reads firewall state from the backend and recomputes derived data.
     *
     * On success the rules, read-only flag, and hit counters are replaced. On
     * failure the state falls back to what can be read without root and a warning
     * status is set. Either way the analysis and cursor clamping run afterwards.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being refreshed.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Recomputes suggestions, shadowed rules, and the preset library.
     *
     * This is a pure in-memory recomputation; it does not touch the backend.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being reanalysed.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Builds the context used to evaluate presets.
     *
     * The context captures the detected LAN, SSH port, interfaces, firewall
     * enabled flag, default incoming policy, and whether SSH is already permitted.
     *
     * # Arguments
     *
     * * `&self` - The application state being read.
     *
     * # Returns
     *
     * `PresetContext` - A snapshot of the values presets need to decide what they
     * would change.
     */
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

    /**
     * Keeps the list cursors inside the bounds of their lists.
     *
     * A cursor pointing past the end is moved to the last item, and a cursor for
     * an empty list is reset to zero.
     *
     * # Arguments
     *
     * * `&mut self` - The application state whose cursors are clamped.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Replaces the status line message.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     * * `level` (`StatusLevel`) - The severity used to colour the message.
     * * `text` (`impl Into<String>`) - The message text; anything convertible into
     *   a `String` is accepted.
     *
     * # Returns
     *
     * This method returns no value.
     */
    pub fn set_status(&mut self, level: StatusLevel, text: impl Into<String>) {
        self.status = Some(StatusMessage {
            level,
            text: text.into(),
        });
    }

    /**
     * Returns the rules that match the current filter.
     *
     * When no filter is set every rule is returned. Otherwise the rule number,
     * action, short summary, comment, and destination port are matched
     * case-insensitively against the filter text.
     *
     * # Arguments
     *
     * * `&self` - The application state being read.
     *
     * # Returns
     *
     * `Vec<&Rule>` - Borrowed references to the matching rules, in ufw order.
     */
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

    /**
     * Returns a copy of the rule under the rules cursor.
     *
     * # Arguments
     *
     * * `&self` - The application state being read.
     *
     * # Returns
     *
     * `Option<Rule>` - A clone of the selected rule, or `None` when the filtered
     * list is empty or the cursor is out of range.
     */
    pub fn selected_rule(&self) -> Option<Rule> {
        self.visible_rules()
            .get(self.rules_cursor)
            .map(|rule| (*rule).clone())
    }

    /**
     * Assesses how risky a rule is.
     *
     * # Arguments
     *
     * * `&self` - The application state being read; its application profiles are
     *   used for the assessment.
     * * `rule` (`&Rule`) - The rule to assess.
     *
     * # Returns
     *
     * `risk::Assessment` - The risk level and summary for the rule.
     */
    pub fn risk_of(&self, rule: &Rule) -> risk::Assessment {
        risk::assess_rule(rule, &self.profiles)
    }

    /**
     * Returns the recorded hit count for a rule.
     *
     * Counters are only reported when `show_counters` is enabled.
     *
     * # Arguments
     *
     * * `&self` - The application state being read.
     * * `rule` (`&Rule`) - The rule whose counter is wanted.
     *
     * # Returns
     *
     * `Option<u64>` - The number of packets matched, or `None` when counters are
     * hidden or unavailable for that rule.
     */
    pub fn hits(&self, rule: &Rule) -> Option<u64> {
        if !self.show_counters {
            return None;
        }
        self.counters.get(rule.number)
    }

    // ---------------------------------------------------------------------------------------
    // key handling
    // ---------------------------------------------------------------------------------------

    /**
     * Handles a key press, routing it to the right handler.
     *
     * Modals, the open filter, the watchdog prompt, and text inputs take
     * precedence over the global shortcuts. Global keys quit, toggle help, request
     * privileges, switch tabs, refresh, and undo; everything else is forwarded to
     * the active tab.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     * * `key` (`KeyEvent`) - The key event to interpret.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Routes a key to the handler for the active tab.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated; its `tab` field
     *   selects the handler.
     * * `key` (`KeyEvent`) - The key event to forward.
     *
     * # Returns
     *
     * This method returns no value.
     */
    fn dispatch_tab_key(&mut self, key: KeyEvent) {
        match self.tab {
            Tab::Home => self.handle_home_key(key),
            Tab::Rules => self.handle_rules_key(key),
            Tab::Add => self.handle_wizard_key(key),
            Tab::Test => self.handle_traffic_key(key),
            Tab::Activity => self.handle_activity_key(key),
            Tab::Presets => self.handle_presets_key(key),
            Tab::Help => self.handle_help_key(key),
            Tab::Settings => self.handle_settings_key(key),
        }
    }

    /**
     * Reports whether the user is expected to type free text.
     *
     * This is true while a wizard text field is open, or while the Test tab has
     * one of its text fields focused. In that state the letter and digit
     * shortcuts are unbound so a keypress is inserted literally.
     *
     * # Arguments
     *
     * * `&self` - The application state being read.
     *
     * # Returns
     *
     * `bool` - `true` when keystrokes should be treated as text input;
     * otherwise, `false`.
     */
    fn in_text_input(&self) -> bool {
        if self.wizard.input.is_some() {
            return true;
        }
        if self.settings_input.is_some() {
            return true;
        }
        if self.tab == Tab::Test && self.traffic.field >= 2 {
            return true;
        }
        false
    }

    /**
     * Refreshes per-tab data when a tab becomes active.
     *
     * Currently this reloads the activity rows when the Activity tab is entered.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
    fn on_tab_entered(&mut self) {
        if self.tab == Tab::Activity {
            self.activity_rows = self.blocks.rows();
        }
    }

    /**
     * Moves a list cursor in response to a navigation key.
     *
     * Up and `k` wrap to the end, down and `j` wrap to the start, Home jumps to the
     * first item, and End jumps to the last. Other keys leave the cursor alone.
     *
     * # Arguments
     *
     * * `cursor` (`&mut usize`) - The cursor to move.
     * * `key` (`KeyCode`) - The key code that was pressed.
     * * `len` (`usize`) - The number of items in the list.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Handles keys on the Help tab.
     *
     * Up and `k` scroll up, down and `j` scroll down, and Escape returns to the
     * Home tab.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     * * `key` (`KeyEvent`) - The key event to interpret.
     *
     * # Returns
     *
     * This method returns no value.
     */
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
    // Settings
    // ---------------------------------------------------------------------------------------

    /**
     * Handles keys on the Settings tab.
     *
     * When a text field is open, characters are inserted and Enter submits the
     * value while Escape cancels. Otherwise navigation keys move the row cursor,
     * Enter or the arrow keys cycle toggle rows (action, direction, protocol,
     * logging) or open a text input for the text rows (interface, from address,
     * to address), and Space flips the skip-wizard checkbox. Every committed
     * change is saved to the config file immediately.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     * * `key` (`KeyEvent`) - The key event to interpret.
     *
     * # Returns
     *
     * This method returns no value.
     */
    fn handle_settings_key(&mut self, key: KeyEvent) {
        if self.settings_input.is_some() {
            /**
             * The result of handling one key press in an open settings text field.
             *
             * This is a local helper enum used only inside the settings key handler.
             *
             * # Variants
             *
             * * `Keep` - Leave the input open and unchanged.
             * * `Cancel` - Close the input without saving.
             * * `Submit` - Close the input and commit the typed value.
             */
            enum Outcome {
                Keep,
                Cancel,
                Submit(SettingsField, String),
            }
            let mut outcome = Outcome::Keep;
            if let Some((field, input)) = self.settings_input.as_mut() {
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
                Outcome::Cancel => self.settings_input = None,
                Outcome::Submit(field, value) => {
                    self.settings_input = None;
                    self.commit_settings_text(field, value);
                }
            }
            return;
        }

        match key.code {
            KeyCode::Up
            | KeyCode::Down
            | KeyCode::Char('k')
            | KeyCode::Char('j')
            | KeyCode::Home
            | KeyCode::End => {
                Self::move_cursor(&mut self.settings_cursor, key.code, SETTINGS_ROW_COUNT)
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => self.settings_confirm(),
            KeyCode::Left | KeyCode::Char('h') => self.settings_confirm(),
            KeyCode::Char(' ') => self.toggle_skip_wizard(),
            _ => {}
        }
    }

    /**
     * Confirms the selected settings row.
     *
     * Toggle rows cycle to the next value; text rows open a text input
     * pre-filled with the current value; the skip-wizard row flips the checkbox.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
    fn settings_confirm(&mut self) {
        match self.settings_cursor {
            0 => {
                let next = match self.config.defaults.action.as_str() {
                    "allow" => "deny",
                    "deny" => "reject",
                    "reject" => "limit",
                    _ => "allow",
                };
                self.config.defaults.action = next.into();
                self.save_settings("default action");
            }
            1 => {
                self.config.defaults.direction = if self.config.defaults.direction == "out" {
                    "in".into()
                } else {
                    "out".into()
                };
                self.save_settings("default direction");
            }
            2 => {
                self.settings_input = Some((
                    SettingsField::Interface,
                    TextInput::new(self.config.defaults.interface.clone()),
                ));
            }
            3 => {
                let next = match self.config.defaults.protocol.as_str() {
                    "tcp" => "udp",
                    "udp" => "any",
                    _ => "tcp",
                };
                self.config.defaults.protocol = next.into();
                self.save_settings("default protocol");
            }
            4 => {
                self.settings_input = Some((
                    SettingsField::FromAddress,
                    TextInput::new(self.config.defaults.from_addr.clone()),
                ));
            }
            5 => {
                self.settings_input = Some((
                    SettingsField::ToAddress,
                    TextInput::new(self.config.defaults.to_addr.clone()),
                ));
            }
            6 => {
                let next = match self.config.defaults.logging.as_str() {
                    "off" => "log",
                    "log" => "log-all",
                    _ => "off",
                };
                self.config.defaults.logging = next.into();
                self.save_settings("default logging");
            }
            _ => self.toggle_skip_wizard(),
        }
    }

    /**
     * Stores a value typed into a settings text field.
     *
     * The field decides where the value goes; empty or `any` input clears the
     * value so the rule falls back to "any".
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     * * `field` (`SettingsField`) - Which default the value belongs to.
     * * `value` (`String`) - The trimmed text the user submitted.
     *
     * # Returns
     *
     * This method returns no value.
     */
    fn commit_settings_text(&mut self, field: SettingsField, value: String) {
        let stored = if value.is_empty() || value == "any" {
            String::new()
        } else {
            value
        };
        match field {
            SettingsField::Interface => {
                self.config.defaults.interface = stored;
                self.save_settings("default interface");
            }
            SettingsField::FromAddress => {
                self.config.defaults.from_addr = stored;
                self.save_settings("default from address");
            }
            SettingsField::ToAddress => {
                self.config.defaults.to_addr = stored;
                self.save_settings("default to address");
            }
        }
    }

    /**
     * Flips the skip-wizard checkbox and saves the config.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
    fn toggle_skip_wizard(&mut self) {
        self.skip_wizard = !self.skip_wizard;
        self.config.skip_wizard = self.skip_wizard;
        self.save_settings("skip-wizard");
    }

    /**
     * Persists the config file and reports the outcome on the status line.
     *
     * A missing destination path is not an error (tests run without one); a
     * write failure sets an error status instead.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     * * `what` (`&str`) - A short description of what changed, for the status line.
     *
     * # Returns
     *
     * This method returns no value.
     */
    fn save_settings(&mut self, what: &str) {
        match &self.config_path {
            Some(path) => match self.config.save(Some(path)) {
                Ok(()) => self.set_status(StatusLevel::Good, format!("saved {what}")),
                Err(error) => self.set_status(
                    StatusLevel::Error,
                    format!("could not save {what}: {error}"),
                ),
            },
            None => self.set_status(StatusLevel::Info, format!("{what} set (not persisted)")),
        }
    }

    // ---------------------------------------------------------------------------------------
    // Home
    // ---------------------------------------------------------------------------------------

    /**
     * Handles keys on the Home tab.
     *
     * Navigation keys move the suggestion cursor, Space toggles the firewall,
     * Enter or `f` applies the selected suggestion, and `l` cycles the log level.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     * * `key` (`KeyEvent`) - The key event to interpret.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Queues a change that turns the firewall on or off.
     *
     * The change is the inverse of the current state and is submitted through the
     * normal confirmation path.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Queues a change that advances the ufw log level.
     *
     * The level cycles Off → Low → Medium → High → Full → Off. A warning status is
     * set first when the new level is noisy.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Applies the suggestion under the Home cursor.
     *
     * Suggestions with an automatic fix queue the matching change (turning the
     * firewall on, fixing the default incoming policy, or enqueueing an SSH
     * preset); suggestions without a fix only set an informational status.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Handles keys on the Rules tab.
     *
     * Navigation keys move the rules cursor; `a` adds, `e`/Enter edits, `d`
     * deletes, `y` duplicates, `x` moves, `t` tests, `/` opens the filter, `n`
     * edits the note, and Space shows rule details.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     * * `key` (`KeyEvent`) - The key event to interpret.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Handles keys while the rules filter is open.
     *
     * Printable characters are inserted, editing keys move within the text, Enter
     * closes the filter but keeps it applied, and Escape clears the filter and
     * resets the cursor.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     * * `key` (`KeyEvent`) - The key event to interpret.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Opens the wizard to add a new rule.
     *
     * The wizard is reset, pre-filled with the detected LAN as source and incoming
     * interface when one is known, and the action defaults to allow. The Add tab
     * becomes active.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
    pub fn start_add(&mut self) {
        self.wizard.reset();
        let mut draft = self.config.defaults.to_draft();
        // When the configured defaults leave the source or interface open, fall back to the
        // detected LAN so the recommended path still pre-fills a sensible source.
        if draft.from_addr.is_none() && draft.interface_in.is_none() {
            if let Some(lan) = &self.lan {
                draft.from_addr = Some(lan.cidr());
                draft.interface_in = Some(lan.iface.clone());
            }
        }
        self.wizard.draft = draft;
        if self.skip_wizard {
            self.wizard.step = WizardStep::Advanced;
        }
        self.tab = Tab::Add;
    }

    /**
     * Opens the wizard to edit the selected rule.
     *
     * The wizard starts on the review step with the rule converted to a draft and
     * the rule number remembered as the edit target; when the skip-wizard
     * setting is enabled it starts on the advanced step instead. Forward (route)
     * rules are refused with a warning because they are read-only in this
     * version.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
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
            step: if self.skip_wizard {
                WizardStep::Advanced
            } else {
                WizardStep::Review
            },
            draft: rule.to_draft(),
            cursor: 0,
            input: None,
            error: None,
            editing: Some(rule.number),
            trace: None,
        };
        self.tab = Tab::Add;
    }

    /**
     * Queues a change that deletes the selected rule.
     *
     * A rule that cannot be turned into a delete command sets an error status
     * instead.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Opens the wizard pre-filled with a copy of the selected rule.
     *
     * The copy is treated as a new rule (no edit target) so applying it adds a
     * second rule. The Add tab becomes active and an informational status is set.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Queues a change that moves the selected rule one position up.
     *
     * A rule already at the top sets an informational status instead. On success
     * the rules cursor follows the rule to its new position.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Opens the wizard with the selected rule's note in an editable text field.
     *
     * The wizard starts on the review step with the note input focused and the
     * cursor placed at the end of the existing text.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Loads the selected rule into the Test tab and simulates it.
     *
     * A sample packet is derived from the rule, the traffic form is filled in with
     * it, and the resulting trace is stored so the Test tab opens with an answer
     * already on screen.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Opens a message modal describing the selected rule.
     *
     * The body contains the plain-English explanation, the equivalent `ufw`
     * command, the risk assessment, and the note.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Returns the selectable options for the wizard's current step.
     *
     * Each entry is a label paired with a short hint. The service step lists the
     * built-in services, then application profiles, then a custom-port option; the
     * advanced step lists the editable fields with their current values.
     *
     * # Arguments
     *
     * * `&self` - The application state being read; the wizard step and draft
     *   determine the result.
     *
     * # Returns
     *
     * `Vec<(String, String)>` - The option labels and their hints, in display
     * order.
     */
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

    /**
     * Returns the question shown above the wizard options.
     *
     * # Arguments
     *
     * * `&self` - The application state being read; the wizard step selects the
     *   question.
     *
     * # Returns
     *
     * `&'static str` - The prompt for the current wizard step.
     */
    pub fn wizard_prompt(&self) -> &'static str {
        match self.wizard.step {
            WizardStep::Goal => "What would you like to do?",
            WizardStep::Who => "Who should it apply to?",
            WizardStep::Service => "Which service?",
            WizardStep::Review => "Review before applying",
            WizardStep::Advanced => "Advanced options",
        }
    }

    /**
     * Handles keys on the Add tab's wizard.
     *
     * When a text field is open, characters are inserted and Enter submits the
     * value while Escape cancels. Otherwise navigation keys move the option
     * cursor, Escape goes back a step, Enter/Right/`l` confirms the step, and
     * `a`/`A` jumps to the advanced step.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     * * `key` (`KeyEvent`) - The key event to interpret.
     *
     * # Returns
     *
     * This method returns no value.
     */
    fn handle_wizard_key(&mut self, key: KeyEvent) {
        if self.wizard.input.is_some() {
            /**
             * The result of handling one key press in an open wizard text field.
             *
             * This is a local helper enum used only inside the wizard key handler.
             *
             * # Variants
             *
             * * `Keep` - Leave the input open and unchanged.
             * * `Cancel` - Close the input without saving.
             * * `Submit` - Close the input and commit the typed value.
             */
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
            KeyCode::Char('a') | KeyCode::Char('A') => {
                self.wizard.step = WizardStep::Advanced;
                self.wizard.cursor = 0;
            }
            _ => {}
        }
    }

    /**
     * Moves the wizard back one step.
     *
     * Any error and trace are cleared and the cursor is reset. Going back from the
     * first step returns to the Rules tab.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Confirms the current wizard step and advances.
     *
     * The goal step records the chosen action, the who step records the source or
     * opens an address input, the service step records the chosen service, the
     * review step tests or applies the draft, and the advanced step edits one
     * field.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Handles the wizard's service step.
     *
     * Selecting a built-in service or an application profile fills in the
     * draft's destination port and protocol. Selecting the custom-port row
     * opens a port input instead.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated; the wizard cursor
     *   selects the option.
     *
     * # Returns
     *
     * `bool` - `true` when the draft is ready to review, or `false` when a
     * custom port still has to be typed.
     */
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

    /**
     * Stores a value typed into a wizard text field.
     *
     * The field decides where the value goes: addresses and interfaces are
     * normalized (empty or `any` clears them), ports are parsed and may switch the
     * protocol to TCP, and notes become the rule comment. Invalid input sets the
     * wizard error instead of advancing.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     * * `field` (`InputField`) - Which draft field the value belongs to.
     * * `value` (`String`) - The trimmed text the user submitted.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Handles the advanced step by editing the field under the cursor.
     *
     * Toggles cycle the action, direction, protocol, and logging values; the other
     * rows open a text input pre-filled with the current value. The final row
     * returns to the review step.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Simulates the wizard draft against a sample packet.
     *
     * The resulting trace is stored on the wizard so the review step can show
     * which rule would decide the packet's fate.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Validates the wizard draft and queues it as an add or an edit.
     *
     * Validation and command-building errors are shown in the wizard instead of
     * being submitted. On success the wizard is reset, the Rules tab becomes
     * active, and the change goes through the normal confirmation path.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
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
                let change: Change = match command::change_edit(&rule, &draft) {
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

    /**
     * Handles keys on the Test tab's traffic form.
     *
     * Tab/Down and BackTab/Up move between the six fields, Left/Right change the
     * direction or protocol, Enter runs the simulation, and editing keys modify
     * the focused text field.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     * * `key` (`KeyEvent`) - The key event to interpret.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Returns the text input for the currently focused traffic field.
     *
     * Fields 2 and 3 are the source address and port; every other field maps to
     * the destination address or port.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated; the returned reference
     *   borrows from it.
     *
     * # Returns
     *
     * `&mut TextInput` - A mutable reference to the focused text field.
     */
    fn traffic_input(&mut self) -> &mut TextInput {
        match self.traffic.field {
            2 => &mut self.traffic.src,
            3 => &mut self.traffic.src_port,
            4 => &mut self.traffic.dst,
            _ => &mut self.traffic.dst_port,
        }
    }

    /**
     * Builds a packet from the Test tab's form values.
     *
     * Addresses and ports are parsed and the direction and protocol are mapped to
     * their enum values. The interface comes from the detected LAN and the packet
     * is marked loopback when both addresses are loopback.
     *
     * # Arguments
     *
     * * `&self` - The application state being read.
     *
     * # Returns
     *
     * `Result<Packet, String>` - The packet to simulate, or a user-facing message
     * describing the first invalid field.
     */
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

    /**
     * Simulates the packet described by the Test tab.
     *
     * On success the trace is stored and an informational status is set; on
     * failure the parse error is shown as an error status. Nothing is written to
     * the firewall.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Handles keys on the Activity tab.
     *
     * Navigation keys move the row cursor, Space pauses or resumes live updates,
     * `B` blocks the selected source, and `c` clears the visible rows by emptying
     * the block monitor, so the view stays clear until new traffic arrives.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     * * `key` (`KeyEvent`) - The key event to interpret.
     *
     * # Returns
     *
     * This method returns no value.
     */
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
                // The rows are reloaded from the monitor on every tick, so the monitor has to
                // forget them too; otherwise the next tick would put them straight back.
                self.blocks.clear();
                self.activity_rows.clear();
                self.activity_cursor = 0;
                self.set_status(StatusLevel::Info, "cleared the view");
            }
            _ => {}
        }
    }

    /**
     * Queues a deny rule for the source address of the selected activity row.
     *
     * The generated rule carries a comment marking it as created from the activity
     * view. A rule that cannot be built sets an error status.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Handles keys on the Presets tab.
     *
     * Navigation keys move the preset cursor and Enter enqueues the selected
     * preset, or shows the reason it is blocked.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     * * `key` (`KeyEvent`) - The key event to interpret.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Expands a preset into changes and starts working through them.
     *
     * The preset is evaluated against the current context. An empty result sets an
     * informational status, a failure sets an error status, and otherwise the
     * changes are appended to the queue and the first one is submitted.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     * * `preset` (`&presets::Preset`) - The preset to expand.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Submits the next queued change, if any.
     *
     * The change kind is inferred from its description and steps, and the change
     * goes through the normal confirmation path.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * The single choke point for every change: guard, dry-run, confirm, apply, journal.
     *
     * Read-only and non-writable backends are refused (or turned into an
     * escalation request). A change that would lock the user out opens an error
     * modal. Otherwise the change is either applied immediately or, when
     * confirmation is enabled, dry-run step by step and shown in a confirm
     * modal.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     * * `change` (`Change`) - The change to validate and submit; it is moved
     *   into the confirm modal when confirmation is required.
     * * `pending` (`PendingChange`) - The lockout-check metadata for the change.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Runs every step of a change against the backend and records the result.
     *
     * Failures are collected and shown in an error modal, after which the state is
     * refreshed. On success the change is journalled (and saved when a path is
     * configured), the state is refreshed, and a success status is set. When the
     * change could lock out an SSH session, a watchdog is spawned to revert it, and
     * the next queued change is submitted.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     * * `change` (`&Change`) - The change whose steps are executed.
     *
     * # Returns
     *
     * This method returns no value.
     *
     * # Notes
     *
     * Journal save errors are ignored, and the watchdog is only spawned when the
     * session is over SSH and the change has an inverse.
     */
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

    /**
     * Confirms the pending watchdog so the applied change is kept.
     *
     * The watchdog is taken out of the state, confirmed, and cleaned up, and a
     * success status is set. Does nothing when no watchdog is pending.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     *
     * # Notes
     *
     * Errors from confirming the watchdog are ignored.
     */
    pub fn confirm_watchdog(&mut self) {
        if let Some(watchdog) = self.watchdog.take() {
            let _ = watchdog.confirm();
            watchdog.cleanup();
            self.set_status(StatusLevel::Good, "kept — you are still connected");
        }
    }

    /**
     * Reverts the most recent journal entry.
     *
     * The inverse steps are run directly against the backend. On success the entry
     * is removed from the journal, the journal is saved when a path is configured,
     * and the state is refreshed; on failure the errors are shown in a modal.
     * Nothing happens when the journal is empty, the entry has no inverse, or the
     * app is read-only.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     *
     * # Notes
     *
     * Journal save errors are ignored.
     */
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

    /**
     * Handles keys while a modal is open.
     *
     * A message modal closes on Escape, Enter, or `q`. A confirm modal applies the
     * change on Enter or `y`, toggles the dry-run output on `d`, and cancels (also
     * clearing the queue) on Escape, `n`, or `q`.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     * * `key` (`KeyEvent`) - The key event to interpret.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Takes the pending escalation request, if any.
     *
     * The caller is expected to restore the terminal, run `sudo`, and report the
     * outcome through [`App::after_escalation`].
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated; the request is removed.
     *
     * # Returns
     *
     * `Option<Escalation>` - The pending request, or `None` when nothing is
     * waiting.
     */
    pub fn take_escalation(&mut self) -> Option<Escalation> {
        self.escalation.take()
    }

    /**
     * Called after the terminal has been restored and `sudo -v` has run.
     *
     * A refusal sets an error status and changes nothing. On success the app
     * leaves read-only mode, refreshes, and either retries the change that was
     * waiting or reports that rules are now visible.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     * * `granted` (`bool`) - Whether `sudo` granted privileges.
     * * `pending` (`Option<Box<(Change, PendingChange)>>`) - The change to retry,
     *   or `None` when privileges were only requested to read the rules.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Handles the `X` key: asks sudo for privileges so the rules can be read and written.
     *
     * Already-root, escalatable, and escalation-disabled backends each get their
     * own status message; an escalatable backend records a pending
     * [`Escalation::Privileges`] request.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Advances time-based state on each UI tick.
     *
     * Unless paused, the activity rows are reloaded from the block monitor. A
     * watchdog whose countdown has reached zero is dropped.
     *
     * # Arguments
     *
     * * `&mut self` - The application state being mutated.
     *
     * # Returns
     *
     * This method returns no value.
     */
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

    /**
     * Returns the seconds left before the watchdog reverts the change.
     *
     * # Arguments
     *
     * * `&self` - The application state being read.
     *
     * # Returns
     *
     * `Option<u64>` - The remaining seconds, or `None` when no watchdog is
     * running.
     */
    pub fn watchdog_remaining(&self) -> Option<u64> {
        self.watchdog.as_ref().map(|w| w.remaining())
    }

    /**
     * Builds the lines shown on the Help tab.
     *
     * Each key section contributes a title, its formatted key/label rows, and a
     * blank separator line.
     *
     * # Arguments
     *
     * * `&self` - The application state being read.
     *
     * # Returns
     *
     * `Vec<String>` - The help text, one entry per rendered line.
     */
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

/**
 * Infers the change kind from a change's first step and description.
 *
 * The first step's joined arguments are matched against known keywords, with
 * the description used to recognize deletes; anything unrecognized is treated
 * as an add.
 *
 * # Arguments
 *
 * * `change` (`&Change`) - The change to classify.
 *
 * # Returns
 *
 * `ChangeKind` - The kind used for lockout checks and journaling.
 */
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

/**
 * Reports whether a change needs the automatic revert watchdog.
 *
 * Enabling the firewall, changing the default policy, and resetting all need a
 * watchdog because they can cut off the current SSH session.
 *
 * # Arguments
 *
 * * `change` (`&Change`) - The change to inspect.
 *
 * # Returns
 *
 * `true` when any step mentions `enable`, `default`, or `reset`; otherwise,
 * `false`.
 */
fn needs_watchdog(change: &Change) -> bool {
    let text = change
        .steps
        .iter()
        .map(|s| s.join(" "))
        .collect::<Vec<_>>()
        .join(";");
    text.contains("enable") || text.contains("default") || text.contains("reset")
}

/**
 * The human sentence shown in the confirmation dialog.
 *
 * Prefer a rule explanation when the change is about a specific rule;
 * otherwise the description already reads like a sentence.
 *
 * # Arguments
 *
 * * `change` (`&Change`) - The change being confirmed; its steps decide the verb used for rule changes.
 * * `pending` (`&PendingChange`) - The metadata that may carry a draft or a rule to explain.
 *
 * # Returns
 *
 * `String` - The sentence to display in the confirm modal.
 */
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

/**
 * Turns a backend error into a user-facing sentence.
 *
 * A missing `ufw` binary gets an install hint; every other error is rendered
 * with its own display text.
 *
 * # Arguments
 *
 * * `error` (`&BackendError`) - The error to translate.
 *
 * # Returns
 *
 * `String` - The message to show in the status line or a modal.
 */
fn friendly_error(error: &BackendError) -> String {
    match error {
        BackendError::NotFound => {
            "ufw is not installed. On Ubuntu or Debian: sudo apt install ufw".to_string()
        }
        other => other.to_string(),
    }
}

/**
 * Builds a best-effort firewall state when rules cannot be read.
 *
 * Used when we cannot read rules (no root): the world-readable `ufw.conf` still
 * tells us whether the firewall is on and how it logs.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `FirewallState` - A state with the enabled flag and log level from
 * `ufw.conf`, `rules_readable` set to `false`, and every other field at its
 * default.
 *
 * # Notes
 *
 * A missing or unreadable `ufw.conf` is ignored and yields the defaults.
 */
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

/**
 * Builds a sample packet that a rule draft would match.
 *
 * The destination port comes from the draft (falling back to the SSH port) and
 * the source is an address just inside the draft's source network, so the
 * simulation answers whether the rule covers a realistic peer.
 *
 * # Arguments
 *
 * * `draft` (`&RuleDraft`) - The draft rule to build a packet for.
 * * `ssh_port` (`u16`) - The port to use when the draft has no single port.
 *
 * # Returns
 *
 * `Packet` - A packet shaped to exercise the draft.
 *
 * # Panics
 *
 * Panics if the hard-coded fallback address literals fail to parse, which
 * cannot happen for the constants used here.
 */
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

/**
 * Returns a sample address that sits inside `ip`'s subnet.
 *
 * This makes "does my LAN rule actually cover me?" answerable. IPv4 addresses
 * get their last octet incremented (wrapping, and never below 1); other
 * addresses are returned unchanged.
 *
 * # Arguments
 *
 * * `ip` (`std::net::IpAddr`) - The network address to nudge.
 *
 * # Returns
 *
 * `std::net::IpAddr` - An address inside the same subnet as `ip`.
 */
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

/**
 * Builds a sample packet that an existing rule would match.
 *
 * The destination port comes from the rule (falling back to the SSH port) and
 * the source is an address just inside the rule's source network.
 *
 * # Arguments
 *
 * * `rule` (`&Rule`) - The rule to build a packet for.
 * * `ssh_port` (`u16`) - The port to use when the rule has no single port.
 *
 * # Returns
 *
 * `Packet` - A packet shaped to exercise the rule.
 *
 * # Panics
 *
 * Panics if the hard-coded fallback address literals fail to parse, which
 * cannot happen for the constants used here.
 */
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

/**
 * Contract for replacing blank text with a fallback.
 *
 * Implemented for `String`; the trait has one required method, `if_empty`,
 * with no provided methods.
 */
trait IfEmpty {
    /**
     * Declares the fallback helper used to replace blank command output.
     *
     * # Arguments
     *
     * * `self` (`String`) - The text to check; it is consumed.
     * * `fallback` (`&str`) - The text to use when `self` is blank.
     *
     * # Returns
     *
     * `String` - Either the original text or the fallback.
     */
    fn if_empty(self, fallback: &str) -> String;
}

impl IfEmpty for String {
    /**
     * Implements [`IfEmpty`] for `String`.
     *
     * Returns the fallback when the text is empty or only whitespace.
     *
     * # Arguments
     *
     * * `self` (`String`) - The text to check; it is consumed.
     * * `fallback` (`&str`) - The text to use when `self` is blank.
     *
     * # Returns
     *
     * `String` - The original text when it has content, otherwise the fallback.
     */
    fn if_empty(self, fallback: &str) -> String {
        if self.trim().is_empty() {
            fallback.to_string()
        } else {
            self
        }
    }
}
