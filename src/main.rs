//! Entry point: argument handling, the terminal guard, and the event loop.

use std::io::stdout;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use crossterm::event::{self, Event, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use ufw_manager::app::{App, AppOptions, Escalation};
use ufw_manager::backend::mock::MockBackend;
use ufw_manager::backend::ufw::UfwCli;
use ufw_manager::backend::Backend;
use ufw_manager::cli::Cli;
use ufw_manager::config::Config;
use ufw_manager::ui;
use ufw_manager::ui::theme::Theme;

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.is_watchdog() {
        let state_path = cli.nonce.as_ref().expect("checked by is_watchdog");
        let program = std::env::var("UFW_MANAGER_UFW").unwrap_or_else(|_| "ufw".to_string());
        let seconds = cli.internal_revert_after.unwrap_or(60);
        let code = ufw_manager::watchdog::run_revert_helper(state_path, seconds, &program);
        std::process::exit(code);
    }

    if let Some(path) = &cli.ufw {
        std::env::set_var("UFW_MANAGER_UFW", path);
    }

    let config = Config::load(cli.config.as_deref());
    let theme = Theme::new(cli.theme.as_deref().unwrap_or(&config.theme), cli.no_color)
        .with_ascii(cli.ascii || config.ascii_fallback);

    let backend: Box<dyn Backend> = if cli.demo {
        Box::new(MockBackend::new())
    } else {
        Box::new(UfwCli::new(
            cli.readonly || config.readonly,
            cli.no_escalate,
        ))
    };

    if cli.dump_state {
        dump_state(backend.as_ref())?;
        return Ok(());
    }

    let app = App::new(
        backend,
        AppOptions {
            journal_path: ufw_manager::core::undo::default_path(),
            yes: cli.yes,
            readonly: cli.readonly || config.readonly,
            theme,
            reconcile_seconds: config.reconcile_seconds,
            show_counters: config.show_counters,
            confirm_before_apply: config.confirm_before_apply,
        },
    );

    run(app)
}

/// Restores the terminal on drop, so an early return cannot leave the user without a cursor or echo.
struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> Result<Self> {
        enable_raw_mode().context("could not switch the terminal to raw mode")?;
        execute!(stdout(), EnterAlternateScreen).context("could not open the alternate screen")?;
        install_panic_hook();
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(stdout(), LeaveAlternateScreen);
}

fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        previous(info);
    }));
}

fn run(mut app: App) -> Result<()> {
    let quit = Arc::new(AtomicBool::new(false));
    install_signal_handlers(Arc::clone(&quit));

    let guard = TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend).context("could not create the terminal")?;

    let result = (|| -> Result<()> {
        loop {
            terminal.draw(|frame| ui::draw(frame, &app))?;

            if app.should_quit || quit.load(Ordering::Relaxed) {
                break;
            }

            if let Some(request) = app.take_escalation() {
                // `sudo -v` needs the real terminal, so raw mode has to be released first. If the
                // guard cannot be rebuilt we fall through to the normal shutdown path.
                restore_terminal();
                let granted = app.backend.escalate();
                let _ = TerminalGuard::enter();
                terminal.clear()?;
                let pending = match request {
                    Escalation::Write(pending) => Some(pending),
                    Escalation::Privileges => None,
                };
                app.after_escalation(granted, pending);
                continue;
            }

            if event::poll(Duration::from_millis(200))? {
                match event::read()? {
                    Event::Key(key) if key.kind != KeyEventKind::Release => app.handle_key(key),
                    _ => {}
                }
            }
            app.tick();
        }
        Ok(())
    })();

    drop(guard);
    result
}

/// Best-effort signal handling: `SIGINT`, `SIGTERM` and `SIGHUP` set a flag that the loop checks, so
/// the terminal is restored through the normal path instead of being left in raw mode.
fn install_signal_handlers(flag: Arc<AtomicBool>) {
    for signal in signal_hook::consts::TERM_SIGNALS {
        let flag = Arc::clone(&flag);
        let _ = signal_hook::flag::register(*signal, Arc::clone(&flag));
    }
}

fn dump_state(backend: &dyn Backend) -> Result<()> {
    let state = backend.read_state()?;
    println!("backend: {}", backend.label());
    println!("enabled: {}", state.enabled);
    println!("logging: {}", state.log_level.ufw());
    println!(
        "defaults: {} (in), {} (out), {} (routed)",
        state.default_incoming, state.default_outgoing, state.default_routed
    );
    println!("rules: {}", state.rules.len());
    for rule in &state.rules {
        println!(
            "  #{:<3} {:<6} {:<3} {:<28} {:<24} {}",
            rule.number,
            rule.action.label(),
            rule.direction.label(),
            rule.to.port.to_string(),
            rule.from.addr.clone().unwrap_or_else(|| "Anywhere".into()),
            ufw_manager::core::explain::short_summary(rule)
        );
    }
    if !state.unparsed.is_empty() {
        println!("unparsed rows: {}", state.unparsed.len());
        for row in &state.unparsed {
            println!("  {row}");
        }
    }
    Ok(())
}
