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

/**
 * Starts the application: parses command-line arguments, handles the internal
 * watchdog mode, loads configuration and theme, selects the backend, and either
 * dumps firewall state or runs the interactive terminal UI.
 *
 * # Arguments
 *
 * This function takes no arguments. It reads the process arguments via
 * [`Cli::parse`] and environment variables such as `UFW_MANAGER_UFW`.
 *
 * # Returns
 *
 * `anyhow::Result<()>` - `Ok(())` when the requested operation completes
 * successfully. Errors are returned when the backend cannot read state, the
 * terminal cannot be initialized, or the event loop fails.
 *
 * # Panics
 *
 * Panics if watchdog mode is selected without a nonce path. This invariant is
 * guaranteed by [`Cli::is_watchdog`], which requires both fields to be present.
 */
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
            config,
            config_path: cli.config.clone(),
        },
    );

    run(app)
}

/**
 * Restores the terminal on drop, so an early return cannot leave the user
 * without a cursor or echo.
 *
 * The guard is created by [`TerminalGuard::enter`] and held for the lifetime of
 * the interactive session. It has no fields; its only purpose is to run the
 * restoration logic in its [`Drop`] implementation.
 */
struct TerminalGuard;

impl TerminalGuard {
    /**
     * Switches the terminal into raw mode and the alternate screen, then installs
     * a panic hook so the terminal is restored even on a panic.
     *
     * # Arguments
     *
     * This function takes no arguments.
     *
     * # Returns
     *
     * `anyhow::Result<TerminalGuard>` - A guard whose `Drop` implementation
     * restores the terminal. Returns an error if raw mode or the alternate
     * screen cannot be enabled.
     */
    fn enter() -> Result<Self> {
        enable_raw_mode().context("could not switch the terminal to raw mode")?;
        execute!(stdout(), EnterAlternateScreen).context("could not open the alternate screen")?;
        install_panic_hook();
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    /**
     * Restores the terminal when the guard goes out of scope, including during
     * early returns and unwinding.
     *
     * # Arguments
     *
     * * `self` - `&mut TerminalGuard` - The guard being dropped. Its fields are
     *   not inspected; dropping it is the signal to restore the terminal.
     *
     * # Returns
     *
     * `()` - This function returns no value. Restoration errors are ignored so
     * dropping cannot panic.
     */
    fn drop(&mut self) {
        restore_terminal();
    }
}

/**
 * Best-effort restoration of the terminal: disables raw mode and leaves the
 * alternate screen. Errors are intentionally ignored because this runs during
 * shutdown and panic handling, where there is no useful recovery path.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 */
fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(stdout(), LeaveAlternateScreen);
}

/**
 * Replaces the process panic hook with one that restores the terminal before
 * delegating to the previously installed hook. This prevents a panic from
 * leaving the terminal in raw mode or on the alternate screen.
 *
 * # Arguments
 *
 * This function takes no arguments. It captures the existing hook internally.
 *
 * # Returns
 *
 * `()` - This function returns no value. The hook is installed globally for the
 * remainder of the process.
 */
fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        previous(info);
    }));
}

/**
 * Runs the interactive event loop: draws the UI, handles terminal input and
 * signals, services privilege-escalation requests, and ticks application state
 * until the user quits or a termination signal is received.
 *
 * # Arguments
 *
 * * `app` - `App` - The initialized application state. It is taken by value and mutated in place while the loop runs.
 *
 * # Returns
 *
 * `anyhow::Result<()>` - `Ok(())` after a clean shutdown. Returns an error if
 * terminal setup, drawing, event polling, or terminal clearing fails.
 *
 * # Terminal behavior
 *
 * A [`TerminalGuard`] is created for the duration of the loop. Before asking
 * `sudo` for privileges, the terminal is restored so the password prompt can use
 * the real terminal, then the guard is re-entered and the screen is cleared.
 */
fn run(mut app: App) -> Result<()> {
    let quit = Arc::new(AtomicBool::new(false));
    install_signal_handlers(Arc::clone(&quit));

    let mut guard = TerminalGuard::enter()?;
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
                guard = TerminalGuard::enter()?;
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

/**
 * Registers best-effort handlers for the standard termination signals so the
 * event loop can exit through its normal shutdown path and restore the terminal.
 *
 * # Arguments
 *
 * * `flag` - `Arc<AtomicBool>` - Shared quit flag. Each registered signal sets this flag to `true`; the event loop polls it and breaks on the next iteration. The `Arc` is cloned for each signal registration.
 *
 * # Returns
 *
 * `()` - This function returns no value. Registration failures are ignored
 * because signal handling is a best-effort enhancement rather than a
 * requirement for the UI to function.
 */
fn install_signal_handlers(flag: Arc<AtomicBool>) {
    for signal in signal_hook::consts::TERM_SIGNALS {
        let flag = Arc::clone(&flag);
        let _ = signal_hook::flag::register(*signal, Arc::clone(&flag));
    }
}

/**
 * Prints a human-readable snapshot of the firewall state to standard output,
 * including the backend label, enabled/logging flags, default policies, rule
 * count and summaries, and any rows that could not be parsed.
 *
 * # Arguments
 *
 * * `backend` - `&dyn Backend` - The backend used to read the current firewall state and its display label. The reference is not retained.
 *
 * # Returns
 *
 * `anyhow::Result<()>` - `Ok(())` after the snapshot is printed. Returns an
 * error if [`Backend::read_state`] fails.
 */
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
