//! Regression tests for scripts/prefixd-fastnetmon.sh: vectors, confidence,
//! delivery, unban by victim and token handling.
//!
//! The script maps FastNetMon's stdin details to a prefixd vector. Idle protocol
//! lines ("outgoing udp traffic: 0 mbps") must not select a vector: they were
//! previously matched first and mislabelled SYN floods as udp_flood.
//!
//! The script is driven with a stub `curl` that records each call's argv and
//! the config it reads on stdin, so no network or prefixd instance is
//! required. PATH holds only the commands the script may use; `jq` and
//! `python3` are stubs that record any call, which must never happen.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/prefixd-fastnetmon.sh");
const MITIGATION_ID: &str = "6f5e6f5e-0000-4000-8000-000000000001";
/// A recognizable token: the seeded secret every argv check looks for.
const TOKEN: &str = "prefixd_SEEDEDsecretSEEDEDsecretSEEDEDsecret12345";

/// One curl invocation: its arguments and the config it read on stdin.
struct Call {
    args: Vec<String>,
    config: String,
}

impl Call {
    /// The JSON body passed with `--data-binary`.
    fn payload(&self) -> serde_json::Value {
        let at = self
            .args
            .iter()
            .position(|arg| arg == "--data-binary")
            .expect("--data-binary");
        serde_json::from_str(&self.args[at + 1]).expect("payload is valid JSON")
    }

    fn flag(&self, name: &str) -> Option<&str> {
        let at = self.args.iter().position(|arg| arg == name)?;
        self.args.get(at + 1).map(String::as_str)
    }
}

struct Run {
    ok: bool,
    calls: Vec<Call>,
    log: String,
    /// Anything the jq and python3 stubs recorded.
    forbidden: String,
}

/// Link every command the script and the curl stub need into `bin_dir`, and
/// stub `jq` and `python3` so a call to either is recorded instead of run.
fn link_commands(bin_dir: &Path, forbidden: &Path) {
    for command in [
        "bash", "cat", "cut", "date", "tr", "grep", "awk", "sort", "head", "tail", "sed", "sleep",
        "wc", "od", "ls", "mkdir",
    ] {
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
    for command in ["jq", "python3"] {
        let stub = format!(
            "#!/bin/bash\nprintf '%s\\n' '{command}' >> '{}'\nexit 1\n",
            forbidden.display()
        );
        let path = bin_dir.join(command);
        fs::write(&path, stub).expect("write stub");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod stub");
    }
}

/// Run the script for `action` on `ip` with `input` on stdin, against a curl stub that
/// answers each call from `outcomes`: `refused`, an HTTP status (`503`), or
/// `status|body`. Calls past the end get the last outcome.
fn run_script(
    action: &str,
    ip: &str,
    input: &str,
    outcomes: &[&str],
    envs: &[(&str, &str)],
) -> Run {
    let dir = tempfile::tempdir().expect("tempdir");
    let bin_dir = dir.path().join("bin");
    fs::create_dir(&bin_dir).expect("mkdir bin");
    let calls = dir.path().join("calls");
    fs::create_dir(&calls).expect("mkdir calls");
    let outcomes_file = dir.path().join("outcomes");
    fs::write(&outcomes_file, outcomes.join("\n") + "\n").expect("write outcomes");
    let forbidden = dir.path().join("forbidden");
    let stub = format!(
        r#"#!/bin/bash
n=$(ls '{calls}' | wc -l)
mkdir '{calls}'/"$n"
printf '%s\0' "$@" > '{calls}'/"$n"/args
cat > '{calls}'/"$n"/config
total=$(wc -l < '{outcomes}')
line=$((n + 1))
if [[ "$line" -gt "$total" ]]; then line=$total; fi
outcome=$(sed -n "${{line}}p" '{outcomes}')
if [[ "$outcome" == refused ]]; then printf '\n000'; exit 7; fi
code=${{outcome%%|*}}
body=${{outcome#*|}}
if [[ "$body" == "$outcome" ]]; then body='{{"status":"x"}}'; fi
# EVENTID in a scripted body stands for the event_id this call sent.
eid=$(printf '%s\n' "$@" | grep -o '"event_id":"[^"]*"' | head -n 1 | cut -d'"' -f4)
body=${{body//EVENTID/$eid}}
printf '%s\n%s' "$body" "$code"
"#,
        calls = calls.display(),
        outcomes = outcomes_file.display()
    );
    let curl_path = bin_dir.join("curl");
    fs::write(&curl_path, stub).expect("write curl stub");
    fs::set_permissions(&curl_path, fs::Permissions::from_mode(0o755)).expect("chmod curl stub");
    link_commands(&bin_dir, &forbidden);

    let log_path = dir.path().join("script.log");
    let mut child = Command::new("bash")
        .arg(SCRIPT)
        .args([ip, "incoming", "250000", action])
        .env_clear()
        .env("PATH", &bin_dir)
        .env("PREFIXD_API", "http://127.0.0.1:1")
        .env("PREFIXD_TOKEN", TOKEN)
        .env("PREFIXD_LOG", &log_path)
        .env("EVENT_POST_DELAY_SECONDS", "0")
        .env("PREFIXD_DEFAULTS_FILE", dir.path().join("no-defaults"))
        .envs(envs.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn script");
    {
        use std::io::Write;
        // An unban never reads stdin, so a write may meet a closed pipe.
        let _ = child
            .stdin
            .take()
            .expect("stdin")
            .write_all(input.as_bytes());
    }
    let output = child.wait_with_output().expect("script output");
    let mut recorded: Vec<_> = fs::read_dir(&calls)
        .expect("calls")
        .map(|entry| entry.unwrap().path())
        .collect();
    recorded.sort_by_key(|path| {
        path.file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .parse::<u32>()
            .unwrap()
    });
    let calls = recorded
        .iter()
        .map(|path| Call {
            args: fs::read_to_string(path.join("args"))
                .unwrap()
                .split('\0')
                .filter(|arg| !arg.is_empty())
                .map(String::from)
                .collect(),
            config: fs::read_to_string(path.join("config")).unwrap(),
        })
        .collect();
    Run {
        ok: output.status.success(),
        calls,
        log: fs::read_to_string(log_path).unwrap_or_default(),
        forbidden: fs::read_to_string(forbidden).unwrap_or_default(),
    }
}

/// The payload of a successful `ban` with `details` on stdin.
fn ban_payload(details: &str, envs: &[(&str, &str)]) -> serde_json::Value {
    let run = run_script(
        "ban",
        "198.51.100.7",
        details,
        &[&format!(
            r#"202|{{"status":"accepted","mitigation_id":"{MITIGATION_ID}"}}"#
        )],
        envs,
    );
    assert!(run.ok, "script failed: {}", run.log);
    assert!(run.forbidden.is_empty(), "the script ran {}", run.forbidden);
    run.calls[0].payload()
}

/// Run a `ban` with `details` on stdin, returning the vector it sends.
fn detected_vector(details: &str) -> String {
    ban_payload(details, &[])["vector"]
        .as_str()
        .expect("vector is a string")
        .to_string()
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
    {
        let payload = ban_payload("Attack protocol: udp", &[]);
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

fn created(status: &str) -> String {
    format!(
        r#"202|{{"status":"{status}","mitigation_id":"{MITIGATION_ID}","mitigation_ids":["{MITIGATION_ID}"]}}"#
    )
}

fn ban_attempts(outcomes: &[&str]) -> (bool, Vec<String>) {
    let run = run_script("ban", "198.51.100.7", "", outcomes, &[]);
    let ids = run
        .calls
        .iter()
        .map(|call| call.payload()["event_id"].as_str().unwrap().to_string())
        .collect();
    (run.ok, ids)
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
    for status in ["400", "401", "403", "409", "422"] {
        let (ok, ids) = ban_attempts(&[status, "202"]);
        assert!(!ok, "{status}");
        assert_eq!(ids.len(), 1, "{status} was retried");
    }
}

#[test]
fn ban_logs_no_mitigation_for_a_202_without_an_id() {
    for status in ["accepted", "accepted_no_mitigation", "accepted_no_playbook"] {
        let body = serde_json::json!({
            "status": status,
            "mitigation_id": serde_json::Value::Null,
            "mitigation_ids": [],
        })
        .to_string();
        let outcome = format!("202|{body}");
        let run = run_script("ban", "198.51.100.7", "", &[outcome.as_str()], &[]);
        assert!(run.ok, "{status}: {}", run.log);
        assert!(run.log.contains("NO_MITIGATION"), "{status}: {}", run.log);
        assert!(
            run.log.contains(&format!("status={status}")),
            "{status}: {}",
            run.log
        );
    }
}

#[test]
fn ban_logs_success_only_when_a_mitigation_was_created_or_extended() {
    for status in ["accepted", "extended"] {
        let run = run_script("ban", "198.51.100.7", "", &[&created(status)], &[]);
        assert!(run.ok, "{status}: {}", run.log);
        assert!(run.log.contains("SUCCESS"), "{status}: {}", run.log);
        assert!(!run.log.contains("NO_MITIGATION"), "{status}: {}", run.log);
    }
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

/// An unban is an event too: it names the victim from `$1`, reads no stdin,
/// and pairs with nothing, since prefixd withdraws what the bound source
/// created for that victim. It retries the same event on a transport failure
/// or 503 and treats `no_active_mitigation` as definitive.
#[test]
fn unban_posts_an_unban_event_for_the_victim() {
    let run = run_script(
        "unban",
        "2001:0db8:0113::0010",
        "",
        &["refused", &created("withdrawn")],
        &[],
    );
    assert!(run.ok, "{}", run.log);
    assert_eq!(run.calls.len(), 2, "{}", run.log);
    let payload = run.calls[1].payload();
    assert_eq!(payload["action"], "unban");
    assert_eq!(payload["source"], "fastnetmon");
    assert_eq!(payload["victim_ip"], "2001:0db8:0113::0010");
    assert_eq!(payload["vector"], "unknown");
    assert_eq!(payload["raw_details"]["direction"], "incoming");
    assert_eq!(
        run.calls[0].payload()["event_id"],
        payload["event_id"],
        "a retry resends the same event"
    );
    assert!(run.log.contains("Sending unban for 2001:0db8:0113::0010 "));
    assert!(
        run.log.contains("SUCCESS (202, status=withdrawn)"),
        "{}",
        run.log
    );

    let nothing =
        r#"202|{"status":"no_active_mitigation","mitigation_id":null,"mitigation_ids":[]}"#;
    let run = run_script("unban", "203.0.113.10", "", &[nothing], &[]);
    assert!(run.ok, "{}", run.log);
    assert_eq!(run.calls.len(), 1);
    assert!(
        run.log
            .contains("NO_MITIGATION (202, status=no_active_mitigation)"),
        "{}",
        run.log
    );
    for status in ["403", "422"] {
        let run = run_script("unban", "203.0.113.10", "", &[status, "202"], &[]);
        assert!(!run.ok, "{status}");
        assert_eq!(run.calls.len(), 1, "{status} was retried");
    }
}

/// The victim always comes from `$1`. A manual IPv6 ban's stdin says
/// `IP: 0.0.0.0`; nothing from stdin may replace the address.
#[test]
fn the_victim_comes_from_the_argument_never_stdin() {
    let details = "IP: 0.0.0.0\nAttack type: unknown\nAttack protocol: unknown\n";
    let run = run_script(
        "ban",
        "2001:0db8:0113::0010",
        details,
        &[&created("accepted")],
        &[],
    );
    assert!(run.ok, "{}", run.log);
    let payload = run.calls[0].payload();
    assert_eq!(payload["victim_ip"], "2001:0db8:0113::0010");
    assert_eq!(payload["raw_details"]["raw"], details.trim_end());
    for bad in ["203.0.113.10\"}", "203.0.113.10 x", "$(id)"] {
        let run = run_script("ban", bad, "", &["202"], &[]);
        assert!(!run.ok, "{bad}");
        assert!(run.calls.is_empty(), "{bad} reached curl");
    }
}

/// The token reaches curl only through the config on its stdin, never its
/// argv (where `ps` and `/proc/*/cmdline` show it) or the log, on every
/// attempt of a ban and an unban. Each attempt is bounded. Negative control:
/// passing the header with `-H` puts the seeded token in argv, which fails.
#[test]
fn the_token_never_reaches_argv_and_every_attempt_is_bounded() {
    for action in ["ban", "unban"] {
        let run = run_script(
            action,
            "203.0.113.10",
            "",
            &["refused", "503", &created("accepted")],
            &[
                ("EVENT_CONNECT_TIMEOUT_SECONDS", "4"),
                ("EVENT_MAX_TIME_SECONDS", "9"),
            ],
        );
        assert!(run.ok, "{action}: {}", run.log);
        assert_eq!(run.calls.len(), 3, "{action}");
        for call in &run.calls {
            assert!(
                call.args.iter().all(|arg| !arg.contains(TOKEN)),
                "{action}: the token reached argv: {:?}",
                call.args
            );
            assert_eq!(
                call.config,
                format!("header = \"Authorization: Bearer {TOKEN}\"\n"),
                "{action}"
            );
            assert!(call.args.iter().any(|arg| arg == "-K"), "{action}");
            assert_eq!(call.flag("--connect-timeout"), Some("4"), "{action}");
            assert_eq!(call.flag("--max-time"), Some("9"), "{action}");
        }
        assert!(
            !run.log.contains(TOKEN),
            "{action}: the token reached the log"
        );
        assert!(run.forbidden.is_empty(), "{action} ran {}", run.forbidden);
    }
}

/// `PREFIXD_TOKEN_FILE` wins over `PREFIXD_TOKEN`, from the environment or
/// `/etc/default/prefixd`. A malformed or unreadable token stops the script
/// before any request, without logging the value.
#[test]
fn the_token_file_wins_and_a_bad_token_sends_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_token = "prefixd_FROMFILEfromfileFROMFILE";
    let token_file = dir.path().join("token");
    fs::write(&token_file, format!("{file_token}\n")).expect("write token");
    let defaults = dir.path().join("defaults");
    fs::write(
        &defaults,
        format!("PREFIXD_TOKEN_FILE={}\n", token_file.display()),
    )
    .expect("write defaults");
    let run = run_script(
        "ban",
        "203.0.113.10",
        "",
        &[&created("accepted")],
        &[("PREFIXD_DEFAULTS_FILE", defaults.to_str().unwrap())],
    );
    assert!(run.ok, "{}", run.log);
    assert_eq!(
        run.calls[0].config,
        format!("header = \"Authorization: Bearer {file_token}\"\n")
    );

    let malformed = "prefixd_bad\"\nurl = \"http://elsewhere";
    for (name, envs) in [
        ("malformed", vec![("PREFIXD_TOKEN", malformed)]),
        (
            "unreadable",
            vec![("PREFIXD_TOKEN_FILE", "/nonexistent/token")],
        ),
    ] {
        let run = run_script("ban", "203.0.113.10", "", &["202"], &envs);
        assert!(!run.ok, "{name}");
        assert!(run.calls.is_empty(), "{name} sent a request");
        assert!(run.log.contains("ERROR: "), "{name}: {}", run.log);
        assert!(!run.log.contains("elsewhere"), "{name}: {}", run.log);
    }

    // No token at all stops the script before FastNetMon's one call is
    // spent on a 401, unless the controller is explicitly in auth mode none,
    // which sends no header.
    let run = run_script(
        "ban",
        "203.0.113.10",
        "",
        &["202"],
        &[("PREFIXD_TOKEN", "")],
    );
    assert!(!run.ok);
    assert!(run.calls.is_empty(), "sent a request without a token");
    assert!(run.log.contains("ERROR: no token"), "{}", run.log);
    let run = run_script(
        "ban",
        "203.0.113.10",
        "",
        &[&created("accepted")],
        &[("PREFIXD_TOKEN", ""), ("PREFIXD_AUTH_MODE", "none")],
    );
    assert!(run.ok, "{}", run.log);
    assert_eq!(run.calls[0].config, "");
}

/// A retried ban whose earlier attempt reached prefixd meets its own event ID
/// as a 409: it was delivered, so the script exits 0. A 409 on the first
/// attempt, or for another event ID, stays an error.
#[test]
fn a_retried_ban_that_meets_its_own_event_id_was_delivered() {
    let own = r#"409|{"error":"duplicate event from fastnetmon: EVENTID"}"#;
    let run = run_script("ban", "203.0.113.10", "", &["refused", own], &[]);
    assert!(run.ok, "{}", run.log);
    assert_eq!(run.calls.len(), 2);
    assert!(
        run.log
            .contains("NO_MITIGATION (409, status=delivered_by_earlier_attempt)"),
        "{}",
        run.log
    );
    let run = run_script("ban", "203.0.113.10", "", &[own], &[]);
    assert!(!run.ok, "a first-attempt 409 is not a retry");
    let other = r#"409|{"error":"duplicate event from fastnetmon: someone-else"}"#;
    let run = run_script("ban", "203.0.113.10", "", &["503", other], &[]);
    assert!(!run.ok, "another event's 409 is not this ban");
}

/// The script's ban and unban payloads pair on a controller: the unban, sent
/// with FastNetMon's zero-padded spelling, withdraws what the ban created.
#[tokio::test]
async fn script_ban_and_unban_pair_on_the_controller() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use prefixd::AppState;
    use prefixd::bgp::MockAnnouncer;
    use prefixd::config::{Customer, Inventory, OperationMode, Playbooks, PolicyProfile, Settings};
    use prefixd::db::{MockRepository, RepositoryTrait};
    use std::sync::Arc;
    use tower::ServiceExt;

    let configs = Path::new(env!("CARGO_MANIFEST_DIR")).join("configs");
    let mut settings = Settings::load(configs.join("prefixd.yaml")).unwrap();
    settings.mode = OperationMode::DryRun;
    settings.bgp.mode = prefixd::config::BgpMode::Mock;
    settings.http.auth.mode = prefixd::config::AuthMode::Credentials;
    let repo = Arc::new(MockRepository::new());
    let token = repo.mint_token_for_test(
        "fnm",
        prefixd::domain::TokenScope::Ingest,
        Some("fastnetmon"),
    );
    let state = AppState::new(
        settings,
        Inventory::new(vec![Customer {
            customer_id: "test".into(),
            name: "Test customer".into(),
            prefixes: vec!["2001:db8::/32".into()],
            policy_profile: PolicyProfile::Normal,
            services: vec![],
        }]),
        Playbooks::load(configs.join("playbooks.yaml")).unwrap(),
        repo.clone(),
        Arc::new(MockAnnouncer::new()),
        ".".into(),
    )
    .unwrap();
    let app = prefixd::api::create_test_router(state);
    let victim = "2001:0db8:0113::0010";
    let post = |payload: serde_json::Value| {
        let app = app.clone();
        let token = token.clone();
        async move {
            let response = app
                .oneshot(
                    Request::post("/v1/events")
                        .header("content-type", "application/json")
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::from(payload.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap();
            (
                status,
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            )
        }
    };
    let ban = run_script("ban", victim, "Attack protocol: udp", &["202"], &[]);
    let (status, banned) = post(ban.calls[0].payload()).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{banned}");
    assert!(banned["mitigation_id"].is_string(), "{banned}");
    let unban = run_script("unban", victim, "", &["202"], &[]);
    let (status, withdrawn) = post(unban.calls[0].payload()).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{withdrawn}");
    assert_eq!(withdrawn["status"], "withdrawn", "{withdrawn}");
    assert_eq!(
        withdrawn["mitigation_ids"],
        serde_json::json!([banned["mitigation_id"]])
    );
    assert_eq!(repo.count_active_global().await.unwrap(), 0);
}

/// curl reads a zero timeout as no limit, so a zero connect or total timeout
/// is refused before any request; a zero retry delay is fine.
#[test]
fn a_zero_timeout_is_refused_but_a_zero_delay_is_not() {
    for setting in ["EVENT_CONNECT_TIMEOUT_SECONDS", "EVENT_MAX_TIME_SECONDS"] {
        let run = run_script("ban", "203.0.113.10", "", &["202"], &[(setting, "0")]);
        assert!(!run.ok, "{setting}");
        assert!(run.calls.is_empty(), "{setting} sent a request");
        assert!(
            run.log
                .contains(&format!("ERROR: {setting} must be at least 1")),
            "{}",
            run.log
        );
    }
    let run = run_script(
        "ban",
        "203.0.113.10",
        "",
        &["503", &created("accepted")],
        &[("EVENT_POST_DELAY_SECONDS", "0")],
    );
    assert!(run.ok, "{}", run.log);
    assert_eq!(run.calls.len(), 2);
}

/// The script has no default endpoint: without `PREFIXD_API` it stops before
/// any request and says what to set, rather than posting to a guessed one.
#[test]
fn a_missing_endpoint_sends_nothing() {
    let run = run_script("ban", "203.0.113.10", "", &["202"], &[("PREFIXD_API", "")]);
    assert!(!run.ok);
    assert!(run.calls.is_empty(), "sent a request without an endpoint");
    assert!(
        run.log.contains("ERROR: PREFIXD_API is not set"),
        "{}",
        run.log
    );
}
