//! Regression tests for attack-vector inference in scripts/prefixd-fastnetmon.sh.
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
