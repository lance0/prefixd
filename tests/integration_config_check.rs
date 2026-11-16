#![forbid(unsafe_code)]

//! `prefixd --check` runs startup's configuration validation without a
//! database or speaker. These tests run the real binary: there is no
//! PostgreSQL and no `DATABASE_URL`, so a successful run also proves the check
//! connects to nothing.

use std::path::Path;
use std::process::{Command, Output};

/// The shipped configuration this build can run: rustbgpd, or GoBGP when the
/// rustbgpd backend is compiled out.
const SHIPPED: &str = if cfg!(feature = "bgp-rustbgpd") {
    include_str!("../configs/prefixd.yaml")
} else {
    include_str!("../configs/prefixd-gobgp.yaml")
};

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
  backend: mock
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
  backend: mock
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
        .arg("--check")
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
    // as `--check` prints it.
    // The warning is structured: the file and key are fields, so log
    // pipelines can match them.
    assert!(
        stdout.contains("unknown configuration key ignored; the next release refuses it"),
        "{stdout}"
    );
    assert!(stdout.contains("guardrails.max_port"), "{stdout}");
    assert!(
        stdout.contains(&directory.path().join("prefixd.yaml").display().to_string()),
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
    write_directory(directory.path(), SHIPPED);
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
    let document = SHIPPED.replace("require_ttl: true", "require_ttl: true\n  max_port: 3");
    write_directory(directory.path(), &document);
    let output = check(directory.path());
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    assert!(output.status.success(), "{stdout}");
    assert_eq!(
        stderr_lines(&output),
        vec![format!(
            "{}: unknown key `guardrails.max_port`; ignored in this release, refused in the next",
            directory.path().join("prefixd.yaml").display()
        )]
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
        lines.contains(&format!(
            "{}: unknown key `guardrails.max_port`; ignored in this release, refused in the next",
            directory.path().join("prefixd.yaml").display()
        )),
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
    write_directory(directory.path(), SHIPPED);
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
        lines.contains(&format!(
            "{}: unknown key `destinations[0].chanel`; ignored in this release, refused in the next",
            directory.path().join("alerting.yaml").display()
        )),
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
        &SHIPPED.replace(
            "connection_string: \"postgres://user:password@localhost:5432/prefixd\"",
            "connection_string: \"\"",
        ),
    );
    let output = check(directory.path());
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr_lines(&output).contains(&format!(
            "{}: set DATABASE_URL or storage.connection_string",
            directory.path().join("prefixd.yaml").display()
        )),
        "{:?}",
        stderr_lines(&output)
    );
    let output = Command::new(env!("CARGO_BIN_EXE_prefixd"))
        .arg("--check")
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

/// The parity base: valid, with a mock speaker and a database URL that is
/// never dialed by the check.
const BASE: &str = "\
pop: iad1
mode: dry-run
http:
  listen: \"127.0.0.1:8080\"
  auth: {mode: none}
bgp:
  backend: mock
  local_asn: 65010
  router_id: 192.0.2.1
guardrails: {require_ttl: true}
quotas: {max_active_per_customer: 20}
timers: {}
observability: {log_format: pretty, log_level: info}
storage:
  connection_string: \"postgres://prefixd@127.0.0.1:1/prefixd\"
";

/// Never echoed by either path.
const CANARY: &str = "hunter2-canary";

fn variant(replacements: &[(&str, &str)]) -> String {
    let mut document = BASE.to_string();
    for (from, to) in replacements {
        assert!(document.contains(from), "{from}");
        document = document.replace(from, to);
    }
    document
}

fn run(directory: &Path, check: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_prefixd"));
    if check {
        command.arg("--check");
    }
    command
        .arg("--config")
        .arg(directory)
        .env_remove("DATABASE_URL")
        .env_remove("PREFIXD_PARITY_UNSET")
        .env("PREFIXD_PARITY_TOKEN", "parity-token")
        .output()
        .unwrap()
}

/// Every configuration startup refuses before it contacts PostgreSQL or the
/// speaker also fails the check, with the same reason. Each fixture changes
/// one thing in a base the check accepts (the negative control), and both
/// paths are the real binary.
#[test]
fn check_refuses_what_startup_refuses_before_any_connection() {
    let mock = "  backend: mock\n";
    let gobgp_userinfo =
        format!("  backend: gobgp\n  gobgp_grpc: \"operator:{CANARY}@127.0.0.1:50051\"\n");
    let database = format!("\"postgres://prefixd:{CANARY}@127.0.0.1:notaport/prefixd\"");
    let blackhole_playbook = "playbooks:\n  - name: bh\n    match: {vector: udp_flood}\n    \
                              steps:\n      - action: blackhole\n        ttl_seconds: 60\n";
    let mut cases: Vec<(&str, String, Option<&str>, &str)> = vec![
        (
            "playbook settings",
            BASE.to_string(),
            Some(blackhole_playbook),
            "has a blackhole step, but blackhole.enabled is false",
        ),
        (
            "removed bearer mode",
            variant(&[(
                "auth: {mode: none}",
                "auth: {mode: bearer, bearer_token_env: PREFIXD_PARITY_UNSET}",
            )]),
            None,
            "`http.auth.mode: bearer` was removed in 0.28.0",
        ),
        (
            "speaker endpoint userinfo",
            variant(&[(mock, &gobgp_userinfo)]),
            None,
            "invalid speaker endpoint",
        ),
        (
            "empty GoBGP endpoint",
            variant(&[(mock, "  backend: gobgp\n  gobgp_grpc: \"\"\n")]),
            None,
            "bgp.gobgp_grpc is required",
        ),
        (
            "malformed database URL",
            variant(&[("\"postgres://prefixd@127.0.0.1:1/prefixd\"", &database)]),
            None,
            "is not a valid PostgreSQL URL",
        ),
        (
            "unreadable HTTP TLS files",
            variant(&[(
                "  auth: {mode: none}\n",
                "  auth: {mode: none}\n  tls: {cert_path: /nonexistent/cert.pem, key_path: \
                 /nonexistent/key.pem}\n",
            )]),
            None,
            "cannot read http.tls.cert_path /nonexistent/cert.pem",
        ),
    ];
    if cfg!(feature = "bgp-rustbgpd") {
        let rustbgpd =
            |section: &str| variant(&[(mock, &format!("  backend: rustbgpd\n{section}"))]);
        cases.extend([
            (
                "missing rustbgpd section",
                rustbgpd(""),
                None,
                "bgp.rustbgpd is required",
            ),
            (
                "plaintext rustbgpd off loopback",
                rustbgpd(
                    "  rustbgpd: {endpoint: \"http://192.0.2.1:50051\", bearer_token_env: \
                     PREFIXD_PARITY_TOKEN}\n",
                ),
                None,
                "plaintext rustbgpd requires a literal loopback address",
            ),
            (
                "unset rustbgpd token variable",
                rustbgpd(
                    "  rustbgpd: {endpoint: \"http://127.0.0.1:50051\", bearer_token_env: \
                     PREFIXD_PARITY_UNSET}\n",
                ),
                None,
                "rustbgpd bearer token environment variable is missing",
            ),
            (
                "TLS options on a Unix socket",
                rustbgpd(
                    "  rustbgpd: {endpoint: \"unix:///run/rustbgpd/grpc.sock\", ca_cert_path: \
                     /nonexistent/ca.pem}\n",
                ),
                None,
                "TLS options are not valid for rustbgpd Unix sockets",
            ),
            (
                "client certificate without key",
                rustbgpd(
                    "  rustbgpd: {endpoint: \"https://192.0.2.1:50051\", client_cert_path: \
                     /nonexistent/client.pem}\n",
                ),
                None,
                "rustbgpd client certificate and key must be configured together",
            ),
            (
                "unreadable rustbgpd TLS file",
                rustbgpd(
                    "  rustbgpd: {endpoint: \"https://192.0.2.1:50051\", bearer_token_env: \
                     PREFIXD_PARITY_TOKEN, ca_cert_path: /nonexistent/ca.pem}\n",
                ),
                None,
                "cannot read rustbgpd TLS credential file",
            ),
        ]);
    }

    // Negative control: the base passes, so each refusal below is the change's.
    let directory = tempfile::tempdir().unwrap();
    write_directory(directory.path(), BASE);
    let output = run(directory.path(), true);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    for (name, prefixd, playbooks, reason) in cases {
        let directory = tempfile::tempdir().unwrap();
        write_directory(directory.path(), &prefixd);
        if let Some(playbooks) = playbooks {
            std::fs::write(directory.path().join("playbooks.yaml"), playbooks).unwrap();
        }
        let startup = run(directory.path(), false);
        let startup_stderr = String::from_utf8_lossy(&startup.stderr);
        assert!(!startup.status.success(), "{name}: startup accepted it");
        assert!(startup_stderr.contains(reason), "{name}: {startup_stderr}");
        let check = run(directory.path(), true);
        let lines = stderr_lines(&check);
        assert_eq!(check.status.code(), Some(1), "{name}: {lines:?}");
        assert!(
            lines.iter().any(|line| line.contains(reason)),
            "{name}: {lines:?}"
        );
        for output in [
            &startup.stdout,
            &startup.stderr,
            &check.stdout,
            &check.stderr,
        ] {
            assert!(
                !String::from_utf8_lossy(output).contains(CANARY),
                "{name}: echoed a secret"
            );
        }
    }
}
