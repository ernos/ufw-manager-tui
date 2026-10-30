//! End-to-end tests for the real backend, driven by a fake `ufw` script.
//!
//! This is how the write path is tested without root and without risking anybody's firewall: the
//! backend spawns a shell script that replays captured `ufw` output and records the arguments it
//! was given.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use ufw_manager::backend::ufw::UfwCli;
use ufw_manager::backend::{Backend, BackendError};
use ufw_manager::core::command;
use ufw_manager::core::rule::{Protocol, RuleDraft};

const NUMBERED: &str = "\
Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere                   # SSH
[ 2] 80,443/tcp                 ALLOW IN    Anywhere
[ 3] 3306/tcp                   DENY IN     Anywhere                   # keep mysql private
";

const VERBOSE: &str = "\
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip
";

/**
 * Writes an executable shell script into `dir` and returns its path.
 *
 * # Arguments
 *
 * * `dir` (`&Path`) - The directory in which to create the script.
 * * `body` (`&str`) - The script contents, including the shebang line.
 *
 * # Returns
 *
 * `std::path::PathBuf` - The path of the created script, named `ufw`.
 *
 * # Panics
 *
 * Panics if the script cannot be written, inspected, or made executable.
 */
fn write_script(dir: &Path, body: &str) -> std::path::PathBuf {
    let path = dir.join("ufw");
    std::fs::write(&path, body).expect("write script");
    let mut permissions = std::fs::metadata(&path).expect("stat").permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&path, permissions).expect("chmod");
    path
}

/**
 * Creates a fake `ufw` script that replays captured `status` output and records
 * every invocation in a log file.
 *
 * # Arguments
 *
 * * `dir` (`&Path`) - The directory in which to create the fixtures.
 *
 * # Returns
 *
 * `(std::path::PathBuf, std::path::PathBuf)` - The path of the fake `ufw`
 * script and the path of the call log it appends to.
 *
 * # Panics
 *
 * Panics if the fixture files cannot be written.
 */
fn fake_ufw(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let numbered = dir.join("numbered.txt");
    let verbose = dir.join("verbose.txt");
    let log = dir.join("calls.log");
    std::fs::write(&numbered, NUMBERED).expect("write numbered");
    std::fs::write(&verbose, VERBOSE).expect("write verbose");
    std::fs::write(&log, "").expect("write log");

    let script = format!(
        r#"#!/bin/sh
echo "$@" >> "{log}"
case "$1" in
  --version) echo "ufw 0.36.2"; exit 0 ;;
  status)
    case "$2" in
      numbered) cat "{numbered}" ;;
      verbose) cat "{verbose}" ;;
    esac
    exit 0 ;;
  --dry-run)
    echo "Skipping adding existing rule"
    exit 0 ;;
esac
exit 0
"#,
        log = log.display(),
        numbered = numbered.display(),
        verbose = verbose.display()
    );
    (write_script(dir, &script), log)
}

#[test]
/**
 * Verifies that the backend parses a rule set through the fake `ufw`: the
 * firewall is enabled, three rules are read, nothing is left unparsed, and the
 * first rule's port, comment, and default incoming policy are correct.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if reading state fails or any assertion about the parsed state fails.
 */
fn reads_a_rule_set_through_the_fake_ufw() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (script, _log) = fake_ufw(dir.path());
    let backend = UfwCli::for_testing(script.to_string_lossy().to_string());

    let state = backend.read_state().expect("state must parse");
    assert!(state.enabled);
    assert_eq!(state.rules.len(), 3);
    assert!(state.unparsed.is_empty());
    assert_eq!(
        state.rules[0].to.port,
        ufw_manager::core::rule::PortSpec::single(22)
    );
    assert_eq!(state.rules[0].comment.as_deref(), Some("SSH"));
    assert_eq!(
        state.default_incoming,
        ufw_manager::core::firewall::Policy::Deny
    );
}

#[test]
/**
 * Verifies that adding a rule sends exactly the expected `ufw` arguments,
 * including interface, source network, port, and comment.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if a step cannot be run or the recorded calls lack the expected
 * argument string.
 */
fn adding_a_rule_sends_exactly_the_expected_arguments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (script, log) = fake_ufw(dir.path());
    let backend = UfwCli::for_testing(script.to_string_lossy().to_string());

    let draft = RuleDraft::allow_port(Protocol::Tcp, 22)
        .from_anywhere("192.168.1.0/24")
        .on_interface("eno1")
        .with_comment("SSH from LAN");
    let change = command::change_add(&draft).expect("change");
    for step in &change.steps {
        backend.run(step).expect("ufw must accept the rule");
    }

    let calls = std::fs::read_to_string(&log).expect("read log");
    assert!(
        calls.contains(
            "allow in on eno1 proto tcp from 192.168.1.0/24 to any port 22 comment SSH from LAN"
        ),
        "unexpected calls: {calls}"
    );
}

#[test]
/**
 * Verifies that a write is validated with a `--dry-run` invocation first, and
 * that the dry run reports success.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the dry run fails or the recorded calls do not start with
 * `--dry-run allow 22/tcp`.
 */
fn every_write_is_validated_with_a_dry_run_first() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (script, log) = fake_ufw(dir.path());
    let backend = UfwCli::for_testing(script.to_string_lossy().to_string());

    let args = vec!["allow".to_string(), "22/tcp".to_string()];
    let output = backend.dry_run(&args).expect("dry run");
    assert!(output.success);
    let calls = std::fs::read_to_string(&log).expect("read log");
    assert!(
        calls.starts_with("--dry-run allow 22/tcp"),
        "unexpected calls: {calls}"
    );
}

#[test]
/**
 * Verifies that deleting a rule uses its rule number together with `--force`,
 * so `ufw` never prompts for confirmation.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if reading state or running a step fails, or the recorded calls lack
 * `--force delete 3`.
 */
fn deleting_a_rule_uses_the_number_and_never_prompts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (script, log) = fake_ufw(dir.path());
    let backend = UfwCli::for_testing(script.to_string_lossy().to_string());

    let state = backend.read_state().expect("state");
    let change = command::change_delete(&state.rules[2]).expect("change");
    for step in &change.steps {
        backend.run(step).expect("delete must succeed");
    }

    let calls = std::fs::read_to_string(&log).expect("read log");
    assert!(
        calls.contains("--force delete 3"),
        "unexpected calls: {calls}"
    );
}

#[test]
/**
 * Verifies that a rejected command is reported as an unsuccessful output that
 * preserves `ufw`'s own error text and the reconstructed command line, rather
 * than surfacing as an I/O failure.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if the command does not run, is reported as successful, or the message
 * and command text are not as expected.
 */
fn a_failed_command_keeps_ufws_own_words_for_the_error_dialog() {
    let dir = tempfile::tempdir().expect("tempdir");
    let script = write_script(
        dir.path(),
        "#!/bin/sh\necho 'ERROR: Bad port' 1>&2\nexit 1\n",
    );
    let backend = UfwCli::for_testing(script.to_string_lossy().to_string());

    // A rejected rule is not an I/O failure: the caller needs ufw's message verbatim so it can be
    // shown instead of a generic error.
    let output = backend
        .run(&["allow".to_string(), "not-a-port".to_string()])
        .expect("the command ran");
    assert!(!output.success);
    assert!(output.message().contains("Bad port"));
    assert_eq!(output.command(), "ufw allow not-a-port");
}

#[test]
/**
 * Verifies that `ufw`'s complaint about missing root privileges is mapped to
 * [`BackendError::NotRoot`].
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if reading state unexpectedly succeeds or returns a different error
 * variant.
 */
fn ufws_root_complaint_is_recognised() {
    let dir = tempfile::tempdir().expect("tempdir");
    let script = write_script(
        dir.path(),
        "#!/bin/sh\necho 'ERROR: You need to be root to run this script' 1>&2\nexit 1\n",
    );
    let backend = UfwCli::for_testing(script.to_string_lossy().to_string());

    let error = backend.read_state().expect_err("must fail");
    assert!(matches!(error, BackendError::NotRoot(_)), "{error:?}");
}

#[test]
/**
 * Verifies that a missing `ufw` binary is reported as
 * [`BackendError::NotFound`].
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if reading state unexpectedly succeeds or returns a different error
 * variant.
 */
fn a_missing_ufw_binary_is_reported_clearly() {
    let backend = UfwCli::for_testing("/definitely/not/a/binary");
    let error = backend.read_state().expect_err("must fail");
    assert!(matches!(error, BackendError::NotFound), "{error:?}");
}

#[test]
/**
 * Verifies that after a successful `sudo -v` escalation, ufw commands are run
 * through sudo so the cached credentials are actually used.
 *
 * `sudo -v` only validates the credential cache; it does not make later
 * commands run as root. The backend must therefore prefix every ufw invocation
 * with sudo once escalated, otherwise writes fail with "You need to be root"
 * and the rules stay hidden.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if escalation fails, reading state fails, or the recorded calls do not
 * show the sudo prefix.
 */
fn escalated_commands_run_through_sudo() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (script, log) = fake_ufw(dir.path());
    // The sudo script must live in its own directory: `write_script` always
    // names its output `ufw`, which would overwrite the fake ufw script above.
    let sudo_dir = tempfile::tempdir().expect("tempdir");
    let sudo_log = sudo_dir.path().join("sudo.log");
    std::fs::write(&sudo_log, "").expect("write sudo log");
    let sudo_script = write_script(
        sudo_dir.path(),
        &format!(
            "#!/bin/sh\necho \"$@\" >> \"{sudo_log}\"\ncase \"$1\" in\n  -v) exit 0 ;;\n  --) shift; shift; exec \"{script}\" \"$@\" ;;\nesac\nexit 0\n",
            sudo_log = sudo_log.display(),
            script = script.display()
        ),
    );

    let backend = UfwCli::for_testing_escalatable(
        script.to_string_lossy().to_string(),
        sudo_script.to_string_lossy().to_string(),
    );
    assert!(backend.may_escalate());
    assert!(backend.escalate(), "sudo -v must succeed");

    let state = backend
        .read_state()
        .expect("state must parse after escalation");
    assert_eq!(state.rules.len(), 3);

    let calls = std::fs::read_to_string(&log).expect("read ufw log");
    assert!(
        calls.contains("status numbered"),
        "ufw must be invoked after escalation: {calls}"
    );
    let sudo_calls = std::fs::read_to_string(&sudo_log).expect("read sudo log");
    assert!(
        sudo_calls.contains(&format!("-- {} status numbered", script.display())),
        "ufw must run through sudo after escalation: {sudo_calls}"
    );
}

#[test]
/**
 * Verifies that an inactive firewall with no rules is read as a disabled state
 * with an empty rule list.
 *
 * # Arguments
 *
 * This function takes no arguments.
 *
 * # Returns
 *
 * `()` - This function returns no value.
 *
 * # Panics
 *
 * Panics if reading state fails, the state is reported as enabled, or rules are
 * present.
 */
fn an_empty_rule_set_reads_as_no_rules() {
    let dir = tempfile::tempdir().expect("tempdir");
    let numbered = dir.path().join("numbered.txt");
    let verbose = dir.path().join("verbose.txt");
    std::fs::write(&numbered, "Status: inactive\n").expect("write");
    std::fs::write(&verbose, "Status: inactive\n").expect("write");
    let script = write_script(
        dir.path(),
        &format!(
            "#!/bin/sh\ncase \"$1\" in\n  status) case \"$2\" in numbered) cat {} ;; verbose) cat {} ;; esac ;;\nesac\nexit 0\n",
            numbered.display(),
            verbose.display()
        ),
    );
    let backend = UfwCli::for_testing(script.to_string_lossy().to_string());

    let state = backend.read_state().expect("state");
    assert!(!state.enabled);
    assert!(state.rules.is_empty());
}
