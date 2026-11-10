//! Regression tests for scripts/prefixd-fastnetmon.sh: vectors, confidence and ban retry.
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
    ban_payload_with_jq(details, envs, true)
}

/// Link every command the ban path (and its curl stub) needs into `bin_dir`,
/// optionally including jq. A restricted PATH makes the no-jq fallback real:
/// a failing jq stub would still be found by `command -v`.
fn link_commands(bin_dir: &std::path::Path, with_jq: bool) {
    let mut commands = vec![
        "bash", "cat", "cut", "date", "tr", "grep", "awk", "sort", "head", "tail", "sed", "sleep",
        "wc",
    ];
    if with_jq {
        commands.push("jq");
    }
    for command in commands {
        let output = Command::new("bash")
            .args(["-c", "command -v \"$1\"", "--", command])
            .output()
            .expect("locate command");
        assert!(
            output.status.success(),
            "missing test prerequisite: {command}"
        );
        let target = String::from_utf8(output.stdout).expect("command path");
        std::os::unix::fs::symlink(target.trim(), bin_dir.join(command)).expect("link command");
    }
    // Preserve the script's UUID fallbacks on hosts without Linux /proc.
    for command in ["uuidgen", "python3"] {
        let output = Command::new("bash")
            .args(["-c", "command -v \"$1\"", "--", command])
            .output()
            .expect("locate optional command");
        if output.status.success() {
            let target = String::from_utf8(output.stdout).expect("command path");
            std::os::unix::fs::symlink(target.trim(), bin_dir.join(command)).expect("link command");
        }
    }
}

fn ban_payload_with_jq(details: &str, envs: &[(&str, &str)], with_jq: bool) -> serde_json::Value {
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

    link_commands(&bin_dir, with_jq);

    let mut child = Command::new("bash")
        .arg(SCRIPT)
        .args(["198.51.100.7", "incoming", "250000", "ban"])
        .env("PATH", &bin_dir)
        .env("PREFIXD_API", "http://127.0.0.1:1")
        .env("PREFIXD_OPERATOR", "test_operator")
        .env("PREFIXD_LOG", dir.path().join("script.log"))
        .env("PREFIXD_DEFAULTS_FILE", dir.path().join("no-defaults"))
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

#[tokio::test]
async fn ban_confidence_creates_a_mitigation_with_shipped_correlation() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use prefixd::AppState;
    use prefixd::bgp::MockAnnouncer;
    use prefixd::config::{
        AuthMode, BgpMode, Customer, Inventory, OperationMode, Playbooks, PolicyProfile, Settings,
    };
    use prefixd::correlation::CorrelationConfig;
    use prefixd::db::{MockRepository, RepositoryTrait};
    use std::sync::Arc;
    use tower::ServiceExt;

    let configs = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("configs");
    for with_jq in [true, false] {
        let payload = ban_payload_with_jq("Attack protocol: udp", &[], with_jq);
        assert_eq!(payload["confidence"], serde_json::json!(0.9));
        assert_eq!(payload["source"], "fastnetmon");
        assert_eq!(payload["action"], "ban");

        for with_confidence in [true, false] {
            let mut event = payload.clone();
            if !with_confidence {
                // Preserve the generic API contract: missing confidence is
                // not implicitly trusted just because source is fastnetmon.
                event.as_object_mut().unwrap().remove("confidence");
            }
            let mut settings = Settings::load(configs.join("prefixd.yaml")).unwrap();
            settings.mode = OperationMode::DryRun;
            settings.bgp.mode = BgpMode::Mock;
            settings.http.auth.mode = AuthMode::None;
            settings.correlation =
                CorrelationConfig::load(configs.join("correlation.yaml")).unwrap();
            assert!(settings.correlation.enabled);
            assert_eq!(settings.correlation.min_sources, 1);
            assert_eq!(settings.correlation.confidence_threshold, 0.5);
            let inventory = Inventory::new(vec![Customer {
                customer_id: "test".into(),
                name: "Test customer".into(),
                prefixes: vec!["198.51.100.0/24".into()],
                policy_profile: PolicyProfile::Normal,
                services: vec![],
            }]);
            let repo = Arc::new(MockRepository::new());
            let state = AppState::new(
                settings,
                inventory,
                Playbooks::load(configs.join("playbooks.yaml")).unwrap(),
                repo.clone(),
                Arc::new(MockAnnouncer::new()),
                ".".into(),
            )
            .unwrap();
            let response = prefixd::api::create_test_router(state)
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/events")
                        .header("content-type", "application/json")
                        .body(Body::from(event.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::ACCEPTED);
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(body["mitigation_id"].is_string(), with_confidence, "{body}");
            assert_eq!(
                repo.count_active_global().await.unwrap(),
                u32::from(with_confidence)
            );
        }
    }
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
fn udp_attack_protocol_wins_over_background_syn_and_ack() {
    // Nonzero SYN counters and two TCP psh,ack samples, but FastNetMon reports
    // "Attack protocol: udp". The token heuristic alone said syn_flood.
    let (vector, ports) = amplification(&community_fixture("community-ntp-tcp-noise.txt"), &[]);
    assert_eq!(vector, "udp_amplification");
    assert_eq!(ports, Some(vec![123, 11211]));
}

#[test]
fn attack_protocol_line_selects_the_vector() {
    for (details, expected) in [
        // A genuine SYN flood still reads its flags.
        (
            "Attack protocol: tcp\nIncoming syn tcp pps: 900000 packets per second",
            "syn_flood",
        ),
        (
            "Attack protocol: tcp\nx:1 > y:2 protocol: tcp flags: psh,ack frag: 0",
            "ack_flood",
        ),
        (
            "Attack protocol: tcp\nIncoming tcp pps: 900000 packets per second",
            "unknown",
        ),
        (
            "Attack protocol: icmp\nIncoming syn tcp pps: 50 packets per second",
            "icmp_flood",
        ),
        (
            "Attack protocol: udp\nIncoming syn tcp pps: 50 packets per second",
            "udp_flood",
        ),
        // An unusable line falls back to the token heuristic.
        (
            "Attack protocol: unknown\nIncoming syn tcp pps: 50 packets per second",
            "syn_flood",
        ),
        (
            "Attack protocol:\nIncoming udp traffic: 900 mbps",
            "udp_flood",
        ),
    ] {
        assert_eq!(detected_vector(details), expected, "details: {details:?}");
    }
    let (vector, _) = amplification(&community_fixture("community-syn-flood.txt"), &[]);
    assert_eq!(vector, "syn_flood");
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

struct BanRun {
    ok: bool,
    event_ids: Vec<String>,
    log: String,
}

/// Run a `ban` against a curl stub that answers each attempt from `outcomes`.
/// Each entry is `refused`, an HTTP status (`503`), or `status|body` so a test
/// can return a prefixd event response. PATH is isolated to the stub directory.
fn ban_run(outcomes: &[&str], with_jq: bool, envs: &[(&str, &str)]) -> BanRun {
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
code=${{outcome%%|*}}
body=${{outcome#*|}}
if [[ "$body" == "$outcome" ]]; then body='{{"status":"x"}}'; fi
printf '%s\n%s' "$body" "$code"
"#,
        calls = calls.display(),
        outcomes = outcomes_file.display()
    );
    let curl_path = bin_dir.join("curl");
    fs::write(&curl_path, stub).expect("write curl stub");
    fs::set_permissions(&curl_path, fs::Permissions::from_mode(0o755)).expect("chmod curl stub");
    link_commands(&bin_dir, with_jq);
    let log_path = dir.path().join("script.log");
    let status = Command::new("bash")
        .arg(SCRIPT)
        .args(["198.51.100.7", "incoming", "250000", "ban"])
        .env("PATH", &bin_dir)
        .env("PREFIXD_API", "http://127.0.0.1:1")
        .env("PREFIXD_OPERATOR", "test_operator")
        .env("PREFIXD_LOG", &log_path)
        .env("BAN_POST_DELAY_SECONDS", "0")
        .env("PREFIXD_DEFAULTS_FILE", dir.path().join("no-defaults"))
        .envs(envs.iter().copied())
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
    BanRun {
        ok: status.success(),
        event_ids,
        log: fs::read_to_string(log_path).unwrap_or_default(),
    }
}

fn ban_attempts(outcomes: &[&str]) -> (bool, Vec<String>) {
    let run = ban_run(outcomes, true, &[]);
    (run.ok, run.event_ids)
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

#[test]
fn ban_logs_no_mitigation_for_a_202_without_an_id() {
    for with_jq in [true, false] {
        for status in ["accepted", "accepted_no_mitigation", "accepted_no_playbook"] {
            let body = serde_json::json!({
                "status": status,
                "mitigation_id": serde_json::Value::Null,
                "mitigation_ids": [],
            })
            .to_string();
            let outcome = format!("202|{body}");
            let run = ban_run(&[outcome.as_str()], with_jq, &[]);
            assert!(run.ok, "jq={with_jq} {status}: {}", run.log);
            assert!(
                run.log.contains("NO_MITIGATION"),
                "jq={with_jq} {status}: {}",
                run.log
            );
            assert!(
                run.log.contains(&format!("status={status}")),
                "jq={with_jq} {status}: {}",
                run.log
            );
        }
    }
}

#[test]
fn ban_logs_success_only_when_a_mitigation_was_created_or_extended() {
    let id = "6f5e6f5e-0000-4000-8000-000000000001";
    for with_jq in [true, false] {
        for status in ["accepted", "extended"] {
            let body = serde_json::json!({
                "status": status,
                "mitigation_id": id,
                "mitigation_ids": [id],
            })
            .to_string();
            let outcome = format!("202|{body}");
            let run = ban_run(&[outcome.as_str()], with_jq, &[]);
            assert!(run.ok, "jq={with_jq} {status}: {}", run.log);
            assert!(
                run.log.contains("SUCCESS"),
                "jq={with_jq} {status}: {}",
                run.log
            );
            assert!(
                !run.log.contains("NO_MITIGATION"),
                "jq={with_jq} {status}: {}",
                run.log
            );
        }
    }
}

#[test]
fn ban_reads_the_defaults_file_when_present() {
    let dir = tempfile::tempdir().expect("tempdir");
    let defaults = dir.path().join("prefixd-defaults");
    fs::write(&defaults, "PREFIXD_OPERATOR=from_file\n").expect("write defaults");
    let body = serde_json::json!({
        "status": "accepted",
        "mitigation_id": "6f5e6f5e-0000-4000-8000-000000000001",
        "mitigation_ids": ["6f5e6f5e-0000-4000-8000-000000000001"],
    })
    .to_string();
    let outcome = format!("202|{body}");
    let run = ban_run(
        &[outcome.as_str()],
        true,
        &[
            ("PREFIXD_DEFAULTS_FILE", defaults.to_str().expect("path")),
            ("PREFIXD_OPERATOR", ""),
        ],
    );
    assert!(run.ok, "{}", run.log);
    assert!(run.log.contains("SUCCESS"), "{}", run.log);
}

#[test]
fn ban_requires_curl() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bin_dir = dir.path().join("bin");
    fs::create_dir(&bin_dir).expect("mkdir bin");
    for command in ["bash", "date"] {
        let output = Command::new("bash")
            .args(["-c", "command -v \"$1\"", "--", command])
            .output()
            .expect("locate command");
        assert!(output.status.success(), "missing {command}");
        let target = String::from_utf8(output.stdout).expect("command path");
        std::os::unix::fs::symlink(target.trim(), bin_dir.join(command)).expect("link command");
    }
    let log_path = dir.path().join("script.log");
    let status = Command::new("bash")
        .arg(SCRIPT)
        .args(["198.51.100.7", "incoming", "250000", "ban"])
        .env("PATH", &bin_dir)
        .env("PREFIXD_LOG", &log_path)
        .env("PREFIXD_DEFAULTS_FILE", dir.path().join("no-defaults"))
        .stdin(Stdio::null())
        .status()
        .expect("run script");
    assert!(!status.success(), "a host without curl must fail");
    let log = fs::read_to_string(&log_path).expect("script log");
    assert!(log.contains("ERROR: curl is required"), "{log}");
}

#[test]
fn unban_retries_a_transport_failure_before_withdrawing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bin_dir = dir.path().join("bin");
    fs::create_dir(&bin_dir).expect("mkdir bin");
    let calls = dir.path().join("calls");
    let withdraw_calls = dir.path().join("withdraw-calls");
    let stub = format!(
        r#"#!/bin/bash
mode=lookup
for arg in "$@"; do
    case "$arg" in
        *"/withdraw"*) mode=withdraw ;;
        *"/v1/mitigations"*) mode=lookup ;;
    esac
done
if [[ "$mode" == "withdraw" ]]; then
    n=$(wc -l < '{withdraw_calls}' 2>/dev/null || printf 0)
    printf 'withdraw\n' >> '{withdraw_calls}'
    if [[ "$n" -eq 0 ]]; then
        exit 7
    fi
    printf '{{"status":"withdrawn"}}\n200'
    exit 0
fi
n=$(wc -l < '{calls}' 2>/dev/null || printf 0)
printf '%s\n' "$mode" >> '{calls}'
if [[ "$n" -eq 0 ]]; then
    exit 7
fi
printf '{{"mitigations":[{{"mitigation_id":"6f5e6f5e-0000-4000-8000-000000000001"}}]}}\n200'
"#,
        calls = calls.display(),
        withdraw_calls = withdraw_calls.display()
    );
    let curl_path = bin_dir.join("curl");
    fs::write(&curl_path, stub).expect("write curl stub");
    fs::set_permissions(&curl_path, fs::Permissions::from_mode(0o755)).expect("chmod curl stub");
    link_commands(&bin_dir, true);
    let log_path = dir.path().join("script.log");
    let status = Command::new("bash")
        .arg(SCRIPT)
        .args(["198.51.100.7", "incoming", "0", "unban"])
        .env("PATH", &bin_dir)
        .env("PREFIXD_API", "http://127.0.0.1:1")
        .env("PREFIXD_OPERATOR", "test_operator")
        .env("PREFIXD_LOG", &log_path)
        .env("PREFIXD_DEFAULTS_FILE", dir.path().join("no-defaults"))
        .env("UNBAN_QUERY_RETRIES", "3")
        .env("UNBAN_QUERY_DELAY_SECONDS", "0")
        .env("WITHDRAW_DELAY_SECONDS", "0")
        .stdin(Stdio::null())
        .status()
        .expect("run script");
    assert!(status.success(), "{}", fs::read_to_string(&log_path).unwrap_or_default());
    let log = fs::read_to_string(&log_path).expect("script log");
    assert!(log.contains("Unban lookup transport failure"), "{log}");
    assert!(log.contains("Withdrawal for"), "{log}");
    assert!(log.contains("SUCCESS: Withdrew mitigation"), "{log}");
}
