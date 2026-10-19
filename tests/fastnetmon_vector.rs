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
    ban_payload(details, &[])["vector"]
        .as_str()
        .expect("vector is a string")
        .to_string()
}

/// Run a `ban` invocation with `details` on stdin and extra environment,
/// returning the JSON payload handed to curl.
fn ban_payload(details: &str, envs: &[(&str, &str)]) -> serde_json::Value {
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
        .envs(envs.iter().copied())
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
    serde_json::from_str(payload).expect("payload is valid JSON")
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

/// FastNetMon Community notify-script stdin, as FastNetMon v1.2.9 writes it:
/// `get_attack_description`, then "Attack traffic dump" with one
/// `print_simple_packet` line per sample (fast_library.cpp), then "Flow dump"
/// (`call_blackhole_actions_per_host`, fastnetmon_logic.cpp).
fn community_fixture(name: &str) -> String {
    let path = format!(
        "{}/tests/fixtures/fastnetmon/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

/// The vector and `top_src_ports` the script sends for `details`.
fn amplification(details: &str, envs: &[(&str, &str)]) -> (String, Option<Vec<u64>>) {
    let payload = ban_payload(details, envs);
    let ports = payload.get("top_src_ports").map(|ports| {
        ports
            .as_array()
            .expect("top_src_ports is an array")
            .iter()
            .map(|port| port.as_u64().expect("port is a number"))
            .collect()
    });
    (payload["vector"].as_str().unwrap().to_string(), ports)
}

#[test]
fn ntp_and_memcached_dump_reports_reflector_ports_by_share() {
    // 123 carries 9 of 20 sampled UDP packets and 11211 carries 6; DNS (1 of
    // 20) and the random ports stay below the default 0.2 share.
    let (vector, ports) = amplification(&community_fixture("community-ntp-memcached.txt"), &[]);
    assert_eq!(vector, "udp_amplification");
    assert_eq!(ports, Some(vec![123, 11211]));
}

#[test]
fn share_threshold_is_configurable() {
    let details = community_fixture("community-ntp-memcached.txt");
    let (vector, ports) = amplification(&details, &[("PREFIXD_SRC_PORT_MIN_SHARE", "0.4")]);
    assert_eq!(vector, "udp_amplification");
    assert_eq!(ports, Some(vec![123]));
    let (vector, ports) = amplification(&details, &[("PREFIXD_SRC_PORT_MIN_SHARE", "0.05")]);
    assert_eq!(vector, "udp_amplification");
    assert_eq!(ports.unwrap()[..3], [123, 11211, 53]);
}

#[test]
fn random_source_port_flood_stays_udp_flood() {
    let (vector, ports) = amplification(&community_fixture("community-random-ports.txt"), &[]);
    assert_eq!(vector, "udp_flood");
    assert_eq!(ports, None);
}

#[test]
fn zero_udp_dump_is_never_amplification() {
    let (vector, ports) = amplification(&community_fixture("community-syn-flood.txt"), &[]);
    assert_eq!(vector, "syn_flood");
    assert_eq!(ports, None);
}

#[test]
fn mixed_dump_counts_only_udp_samples() {
    // Ten TCP samples from port 443 do not count; NTP is 6 of 8 UDP packets.
    let (vector, ports) = amplification(&community_fixture("community-mixed.txt"), &[]);
    assert_eq!(vector, "udp_amplification");
    assert_eq!(ports, Some(vec![123]));
}

#[test]
fn ipv6_dump_reads_the_port_after_the_last_colon() {
    let (vector, ports) = amplification(&community_fixture("community-ipv6.txt"), &[]);
    assert_eq!(vector, "udp_amplification");
    assert_eq!(ports, Some(vec![11211]));
}

#[test]
fn malformed_or_missing_dump_falls_back_to_udp_flood() {
    let header = "Attack type: udp_flood\nIncoming udp pps: 900000 packets per second\n";
    for dump in [
        // No dump section at all.
        String::new(),
        // An empty dump.
        "\n\nAttack traffic dump\n\n\n\nFlow dump\n\n".to_string(),
        // Lines that do not parse: no port, a port out of range, a bad count.
        "\n\nAttack traffic dump\n\n\
         2026-10-19 14:02:00.000000 198.51.100.1 > 203.0.113.10:4000 protocol: udp frag: 0  packets: 1 size: 486 bytes\n\
         2026-10-19 14:02:00.000000 198.51.100.1:70000 > 203.0.113.10:4000 protocol: udp frag: 0  packets: 1 size: 486 bytes\n\
         2026-10-19 14:02:00.000000 198.51.100.1:123 > 203.0.113.10:4000 protocol: udp frag: 0  packets: many size: 486 bytes\n\
         garbage\n\nFlow dump\n"
            .to_string(),
        // Sampled packets outside the dump section are ignored.
        "2026-10-19 14:02:00.000000 198.51.100.1:123 > 203.0.113.10:4000 protocol: udp frag: 0  packets: 1 size: 486 bytes\n".to_string(),
    ] {
        let (vector, ports) = amplification(&format!("{header}{dump}"), &[]);
        assert_eq!(vector, "udp_flood", "dump: {dump:?}");
        assert_eq!(ports, None, "dump: {dump:?}");
    }
    let details = community_fixture("community-ntp-memcached.txt");
    for share in ["abc", "0", "1.5", "-0.2"] {
        let (vector, ports) = amplification(&details, &[("PREFIXD_SRC_PORT_MIN_SHARE", share)]);
        assert_eq!(vector, "udp_flood", "share: {share:?}");
        assert_eq!(ports, None, "share: {share:?}");
    }
}

#[test]
fn reported_ports_are_capped_at_64() {
    let mut details = String::from("Attack type: udp_flood\n\n\nAttack traffic dump\n\n");
    for port in 1000..1100 {
        details.push_str(&format!(
            "2026-10-19 14:02:00.000000 198.51.100.1:{port} > 203.0.113.10:4000 protocol: udp frag: 0  packets: 1 size: 486 bytes ttl: 54 sample ratio: 1  \n"
        ));
    }
    let (vector, ports) = amplification(&details, &[("PREFIXD_SRC_PORT_MIN_SHARE", "0.001")]);
    assert_eq!(vector, "udp_amplification");
    let ports = ports.unwrap();
    assert_eq!(ports.len(), 64);
    assert_eq!(ports[..2], [1000, 1001], "ties rank by port");
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
