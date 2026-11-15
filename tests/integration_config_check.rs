#![forbid(unsafe_code)]

//! `prefixd --check-config` runs startup's configuration validation without a
//! database or speaker. These tests run the real binary: there is no
//! PostgreSQL and no `DATABASE_URL`, so a successful run also proves the check
//! connects to nothing.

use std::path::Path;
use std::process::{Command, Output};

/// A configuration with one error in each of three sections and one unknown
/// key. Every required section is present, so parsing succeeds.
const INVALID: &str = "\
pop: iad1
mode: dry-run
http:
  listen: \"127.0.0.1:8080\"
  auth:
    mode: none
bgp:
  local_asn: 65010
  router_id: 192.0.2.1
guardrails:
  max_port: 3
quotas:
  max_active_prefix_per_customer: 0
timers: {}
observability:
  log_level: info
blackhole:
  lease_seconds: 2
amplification:
  reflector_ports:
    - {port: 53, name: dns}
    - {port: 53, name: dns-again}
storage:
  connection_string: postgres://prefixd:secret@192.0.2.99:5432/prefixd
";

/// A configuration that loads and passes every cross-check, with one unknown
/// key and no database, so startup reaches its warning and database gate.
const STARTUP: &str = "\
pop: iad1
mode: dry-run
http:
  listen: \"127.0.0.1:8080\"
  auth:
    mode: none
bgp:
  local_asn: 65010
  router_id: 192.0.2.1
guardrails:
  require_ttl: true
  max_port: 3
quotas:
  max_active_per_customer: 20
timers: {}
observability:
  log_format: pretty
  log_level: info
storage:
  connection_string: \"\"
";

fn write_directory(directory: &Path, prefixd: &str) {
    std::fs::write(directory.join("prefixd.yaml"), prefixd).unwrap();
    std::fs::write(
        directory.join("inventory.yaml"),
        include_str!("../configs/inventory.yaml"),
    )
    .unwrap();
    std::fs::write(
        directory.join("playbooks.yaml"),
        include_str!("../configs/playbooks.yaml"),
    )
    .unwrap();
    std::fs::write(
        directory.join("correlation.yaml"),
        include_str!("../configs/correlation.yaml"),
    )
    .unwrap();
}

fn check(directory: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_prefixd"))
        .arg("--check-config")
        .arg("--config")
        .arg(directory)
        .env_remove("DATABASE_URL")
        .output()
        .unwrap()
}

fn stderr_lines(output: &Output) -> Vec<String> {
    String::from_utf8(output.stderr.clone())
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect()
}

/// Startup warns about an unknown key with its full path and keeps going: it
/// reaches the database gate, so the key did not stop the load.
#[test]
fn startup_warns_about_an_unknown_key_instead_of_refusing() {
    let directory = tempfile::tempdir().unwrap();
    write_directory(directory.path(), STARTUP);
    let output = Command::new(env!("CARGO_BIN_EXE_prefixd"))
        .arg("--config")
        .arg(directory.path())
        .env_remove("DATABASE_URL")
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let stderr = String::from_utf8(output.stderr.clone()).unwrap();
    assert!(!output.status.success());
    // tracing writes its layers to stdout; the warning is logged, not printed
    // by `--check-config`.
    assert!(
        stdout.contains(
            "prefixd.yaml: unknown key `guardrails.max_port`; ignored in this release, refused in \
             the next"
        ),
        "{stdout}"
    );
    assert!(
        stderr.contains("set DATABASE_URL or storage.connection_string"),
        "{stderr}"
    );
    assert!(!stderr.contains("failed to load"), "{stderr}");
}

/// The shipped configuration is accepted, the check names what it validated
/// and what it cannot check without a speaker, and nothing is printed as an
/// error.
#[test]
fn check_accepts_the_shipped_configuration_and_names_skipped_checks() {
    let directory = tempfile::tempdir().unwrap();
    write_directory(directory.path(), include_str!("../configs/prefixd.yaml"));
    let output = check(directory.path());
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let stderr = String::from_utf8(output.stderr.clone()).unwrap();
    assert!(output.status.success(), "{stderr}");
    assert!(stdout.contains("configuration OK"), "{stdout}");
    for file in [
        "prefixd.yaml",
        "correlation.yaml",
        "inventory.yaml",
        "playbooks.yaml",
    ] {
        assert!(stdout.contains(file), "{stdout}");
    }
    assert!(stdout.contains("skipped: playbook checks"), "{stdout}");
    assert!(stderr.is_empty(), "{stderr}");
}

/// An unknown key is reported and the check still succeeds: this release warns,
/// the next refuses.
#[test]
fn check_warns_about_an_unknown_key_and_exits_zero() {
    let directory = tempfile::tempdir().unwrap();
    let document = include_str!("../configs/prefixd.yaml")
        .replace("require_ttl: true", "require_ttl: true\n  max_port: 3");
    write_directory(directory.path(), &document);
    let output = check(directory.path());
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    assert!(output.status.success(), "{stdout}");
    assert_eq!(
        stderr_lines(&output),
        vec![
            "prefixd.yaml: unknown key `guardrails.max_port`; ignored in this release, refused in \
             the next"
                .to_string()
        ]
    );
    assert!(stdout.contains("1 unknown key(s) ignored"), "{stdout}");
}

/// Every error is printed, one per line, each naming its file, and the exit
/// code is 1. The messages are the ones the documentation lists.
#[test]
fn check_reports_every_error_one_per_line() {
    let directory = tempfile::tempdir().unwrap();
    write_directory(directory.path(), INVALID);
    let output = check(directory.path());
    let prefix = format!(
        "failed to load {}",
        directory.path().join("prefixd.yaml").display()
    );
    assert_eq!(output.status.code(), Some(1));
    let lines = stderr_lines(&output);
    assert_eq!(lines.len(), 4, "{lines:?}");
    for reason in [
        "quotas.max_active_prefix_per_customer must be nonzero",
        "configuration error: blackhole.lease_seconds must be 5..=3600, got 2",
        "configuration error: amplification.reflector_ports: port 53 is listed twice",
    ] {
        let expected = format!("{prefix}: {reason}");
        assert!(lines.contains(&expected), "{lines:?}");
    }
    assert!(
        lines.contains(
            &"prefixd.yaml: unknown key `guardrails.max_port`; ignored in this release, refused in \
              the next"
                .to_string()
        ),
        "{lines:?}"
    );
    assert!(String::from_utf8_lossy(&output.stdout).is_empty());
}

/// A `chanel:` typo in an alert destination is reported under its own file and
/// destination index; the URL beside it is never echoed.
#[test]
fn check_reports_alerting_destination_typos_without_values() {
    const CANARY: &str = "hunter2-canary";
    let directory = tempfile::tempdir().unwrap();
    write_directory(directory.path(), include_str!("../configs/prefixd.yaml"));
    std::fs::write(
        directory.path().join("alerting.yaml"),
        format!(
            "destinations:\n  - type: generic\n    url: http://example.invalid/hook?token={CANARY}\n    chanel: ops\n"
        ),
    )
    .unwrap();
    let output = check(directory.path());
    let lines = stderr_lines(&output);
    assert_eq!(output.status.code(), Some(1), "{lines:?}");
    assert!(
        lines.contains(
            &"alerting.yaml: unknown key `destinations[0].chanel`; ignored in this release, \
              refused in the next"
                .to_string()
        ),
        "{lines:?}"
    );
    for line in &lines {
        assert!(!line.contains(CANARY), "{line}");
    }
}

/// Startup's database gate runs without connecting: a configuration that names
/// no database is refused, and `DATABASE_URL` satisfies it.
#[test]
fn check_requires_a_database_url_like_startup() {
    let directory = tempfile::tempdir().unwrap();
    write_directory(
        directory.path(),
        &include_str!("../configs/prefixd.yaml").replace(
            "connection_string: \"postgres://user:password@localhost:5432/prefixd\"",
            "connection_string: \"\"",
        ),
    );
    let output = check(directory.path());
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr_lines(&output)
            .contains(&"set DATABASE_URL or storage.connection_string".to_string()),
        "{:?}",
        stderr_lines(&output)
    );
    let output = Command::new(env!("CARGO_BIN_EXE_prefixd"))
        .arg("--check-config")
        .arg("--config")
        .arg(directory.path())
        .env(
            "DATABASE_URL",
            "postgres://prefixd:secret@192.0.2.99:5432/prefixd",
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A missing directory reports one error per required file instead of stopping
/// at the first.
#[test]
fn check_reports_a_missing_directory_file_by_file() {
    let directory = tempfile::tempdir().unwrap();
    let output = check(&directory.path().join("absent"));
    assert_eq!(output.status.code(), Some(1));
    let lines = stderr_lines(&output);
    assert_eq!(lines.len(), 3, "{lines:?}");
    for file in ["prefixd.yaml", "inventory.yaml", "playbooks.yaml"] {
        assert!(
            lines
                .iter()
                .any(|line| line.contains("failed to load ") && line.contains(file)),
            "{file}: {lines:?}"
        );
    }
}

/// A `prefixd.yaml` whose inline alerting names an unset variable, as left by
/// an operator who now configures alerting in `alerting.yaml`.
fn stale_inline_alerting() -> String {
    let mut document = include_str!("../configs/prefixd.yaml").to_string();
    document.push_str(
        "alerting:\n  destinations:\n    - type: pagerduty\n      routing_key_env: \
         PREFIXD_TEST_3325_CHECK_UNSET\n",
    );
    document
}

/// A standalone `alerting.yaml` replaces the inline block, so a stale inline
/// `*_env` is not checked and the configuration passes.
#[test]
fn check_ignores_stale_inline_alerting_when_alerting_yaml_replaces_it() {
    assert!(
        std::env::var("PREFIXD_TEST_3325_CHECK_UNSET").is_err(),
        "the test variable must be unset"
    );
    let directory = tempfile::tempdir().unwrap();
    write_directory(directory.path(), &stale_inline_alerting());
    std::fs::write(
        directory.path().join("alerting.yaml"),
        "destinations:\n  - type: generic\n    url: https://example.com/hook\n",
    )
    .unwrap();
    let output = check(directory.path());
    let stderr = String::from_utf8(output.stderr.clone()).unwrap();
    assert!(output.status.success(), "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
}

/// Without `alerting.yaml`, the inline block is the configuration in effect
/// and the same stale variable is refused.
#[test]
fn check_refuses_stale_inline_alerting_when_it_is_in_effect() {
    assert!(
        std::env::var("PREFIXD_TEST_3325_CHECK_UNSET").is_err(),
        "the test variable must be unset"
    );
    let directory = tempfile::tempdir().unwrap();
    write_directory(directory.path(), &stale_inline_alerting());
    let output = check(directory.path());
    let lines = stderr_lines(&output);
    assert_eq!(output.status.code(), Some(1), "{lines:?}");
    assert!(
        lines.iter().any(|line| line.contains(
            "alerting: destination[0] (pagerduty): routing_key_env names environment variable \
             'PREFIXD_TEST_3325_CHECK_UNSET', which is not set or empty"
        )),
        "{lines:?}"
    );
}
