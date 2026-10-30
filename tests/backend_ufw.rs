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

fn write_script(dir: &Path, body: &str) -> std::path::PathBuf {
    let path = dir.join("ufw");
    std::fs::write(&path, body).expect("write script");
    let mut permissions = std::fs::metadata(&path).expect("stat").permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&path, permissions).expect("chmod");
    path
}

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
fn a_missing_ufw_binary_is_reported_clearly() {
    let backend = UfwCli::for_testing("/definitely/not/a/binary");
    let error = backend.read_state().expect_err("must fail");
    assert!(matches!(error, BackendError::NotFound), "{error:?}");
}

#[test]
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
