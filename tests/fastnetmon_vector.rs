//! Regression tests for scripts/prefixd-fastnetmon.sh: attack-vector inference and ban retry.
//!
//! The script maps FastNetMon's stdin details to a prefixd vector. Idle protocol
//! lines ("outgoing udp traffic: 0 mbps") must not select a vector: they were
//! previously matched first and mislabelled SYN floods as udp_flood.
//!
//! The script is driven with a stub `curl` that records the payload it would
//! have POSTed, so no network or prefixd instance is required.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/prefixd-fastnetmon.sh");

/// Run a `ban` invocation with `details` on stdin, returning the vector in the
/// payload handed to curl.
fn detected_vector(details: &str) -> String {
    let dir = tempfile::tempdir().expect("tempdir");
    let bin_dir = dir.path().join("bin");
    fs::create_dir(&bin_dir).expect("mkdir bin");
    let args_log = dir.path().join("curl-args");

    // Emits a body plus the trailing status line `curl -w "%{http_code}"` prints,
    // so the script sees a successful ingest.
    let stub = format!(
        "#!/bin/bash\nprintf '%s\\0' \"$@\" >> '{}'\ncat > /dev/null\nprintf '{{\"status\":\"accepted\"}}\\n201'\nexit 0\n",
        args_log.display()
    );
    let curl_path = bin_dir.join("curl");
    fs::write(&curl_path, stub).expect("write curl stub");
    fs::set_permissions(&curl_path, fs::Permissions::from_mode(0o755)).expect("chmod curl stub");

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let mut child = Command::new("bash")
        .arg(SCRIPT)
        .args(["198.51.100.7", "incoming", "250000", "ban"])
        .env("PATH", path)
        .env("PREFIXD_API", "http://127.0.0.1:1")
        .env("PREFIXD_OPERATOR", "test_operator")
        .env("PREFIXD_LOG", dir.path().join("script.log"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn script");

    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().expect("stdin");
        stdin.write_all(details.as_bytes()).expect("write stdin");
    }

    let output = child.wait_with_output().expect("script output");
    assert!(
        output.status.success(),
        "script exited with {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let logged = fs::read_to_string(&args_log).expect("curl was never called");
    let payload = logged
        .split('\0')
        .find(|arg| arg.contains("\"vector\""))
        .expect("payload with vector not passed to curl");
    let json: serde_json::Value = serde_json::from_str(payload).expect("payload is valid JSON");

    json["vector"]
        .as_str()
        .expect("vector is a string")
        .to_string()
}

#[test]
fn syn_flood_wins_over_idle_udp_line() {
    let details = "Incoming traffic: 152.4 mbps\n\
                   Outgoing traffic: 0 mbps\n\
                   Incoming udp traffic: 0.0 mbps\n\
                   Outgoing udp traffic: 0 mbps\n\
                   Incoming pps: 380000\n\
                   Attack type: syn_flood";
    assert_eq!(detected_vector(details), "syn_flood");
}

#[test]
fn udp_flood_from_nonzero_udp_line() {
    let details = "Incoming traffic: 0 mbps\n\
                   Outgoing udp traffic: 900 mbps\n\
                   Incoming tcp syn: 0 mbps";
    assert_eq!(detected_vector(details), "udp_flood");
}

#[test]
fn ack_flood_not_confused_by_packets_word() {
    let details = "Incoming traffic: 420 mbps\n\
                   Incoming pps: 900000 packets per second\n\
                   Attack type: tcp_ack";
    assert_eq!(detected_vector(details), "ack_flood");
}

#[test]
fn all_zero_metrics_yield_unknown() {
    let details = "Incoming traffic: 0 mbps\n\
                   Outgoing traffic: 0 mbps\n\
                   Incoming udp traffic: 0 mbps\n\
                   Incoming tcp syn: 0 mbps";
    assert_eq!(detected_vector(details), "unknown");
}

#[test]
fn udp_flood_wins_over_idle_syn_packet_rate() {
    let details = "Incoming tcp syn pps: 0 packets per second\n\
                   Incoming udp traffic: 900 mbps";
    assert_eq!(detected_vector(details), "udp_flood");
}

#[test]
fn all_zero_syn_packet_rates_yield_unknown() {
    for rate in ["0", "0.0", "00.00"] {
        let details = format!("Incoming tcp syn pps: {rate} packets per second");
        assert_eq!(detected_vector(&details), "unknown", "rate: {rate}");
    }
}

#[test]
fn underscore_attack_type_does_not_match_ack() {
    assert_eq!(detected_vector("Attack_type: udp_flood"), "udp_flood");
}

#[test]
fn nonzero_packet_rates_keep_protocol_signal() {
    for rate in ["10", "0.1", "100.0"] {
        let details = format!("Incoming tcp syn pps: {rate} packets per second");
        assert_eq!(detected_vector(&details), "syn_flood", "rate: {rate}");
    }
}

#[test]
fn protocol_tokens_do_not_match_inside_words() {
    for details in [
        "asyn_flood",
        "attack_type: idle",
        "aicmp_flood",
        "audp_flood",
    ] {
        assert_eq!(detected_vector(details), "unknown", "details: {details}");
    }
}

/// Run a `ban` against a curl stub that answers each attempt from `outcomes`
/// (`refused` = connection error, otherwise an HTTP status). Returns whether the
/// script succeeded and the event IDs it posted, one per attempt.
fn ban_attempts(outcomes: &[&str]) -> (bool, Vec<String>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let bin_dir = dir.path().join("bin");
    fs::create_dir(&bin_dir).expect("mkdir bin");
    let outcomes_file = dir.path().join("outcomes");
    fs::write(&outcomes_file, outcomes.join("\n") + "\n").expect("write outcomes");
    let calls = dir.path().join("calls");
    let stub = format!(
        r#"#!/bin/bash
for arg in "$@"; do
    case "$arg" in *'"event_id"'*) printf '%s\n' "$(tr -d '\n' <<< "$arg")" >> '{calls}' ;; esac
done
n=$(wc -l < '{calls}')
outcome=$(sed -n "${{n}}p" '{outcomes}')
if [[ "$outcome" == refused ]]; then printf '\n000'; exit 7; fi
printf '{{"status":"x"}}\n%s' "$outcome"
"#,
        calls = calls.display(),
        outcomes = outcomes_file.display()
    );
    let curl_path = bin_dir.join("curl");
    fs::write(&curl_path, stub).expect("write curl stub");
    fs::set_permissions(&curl_path, fs::Permissions::from_mode(0o755)).expect("chmod curl stub");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let status = Command::new("bash")
        .arg(SCRIPT)
        .args(["198.51.100.7", "incoming", "250000", "ban"])
        .env("PATH", path)
        .env("PREFIXD_API", "http://127.0.0.1:1")
        .env("PREFIXD_OPERATOR", "test_operator")
        .env("PREFIXD_LOG", dir.path().join("script.log"))
        .env("BAN_POST_DELAY_SECONDS", "0")
        .stdin(Stdio::null())
        .status()
        .expect("run script");
    let event_ids = fs::read_to_string(&calls)
        .expect("curl was never called")
        .lines()
        .map(|payload| {
            let json: serde_json::Value = serde_json::from_str(payload).expect("payload JSON");
            json["event_id"].as_str().expect("event_id").to_string()
        })
        .collect();
    (status.success(), event_ids)
}

#[test]
fn ban_retries_connection_errors_and_503_with_the_same_event_id() {
    let (ok, ids) = ban_attempts(&["refused", "503", "202"]);
    assert!(ok);
    assert_eq!(ids.len(), 3);
    assert!(
        ids.iter().all(|id| id == &ids[0]),
        "retries reuse the event ID"
    );
}

#[test]
fn ban_gives_up_after_the_configured_attempts() {
    let (ok, ids) = ban_attempts(&["503", "503", "503", "202"]);
    assert!(!ok);
    assert_eq!(ids.len(), 3);
}

#[test]
fn ban_does_not_retry_client_errors() {
    for status in ["400", "401", "409", "422"] {
        let (ok, ids) = ban_attempts(&[status, "202"]);
        assert!(!ok, "{status}");
        assert_eq!(ids.len(), 1, "{status} was retried");
    }
}
