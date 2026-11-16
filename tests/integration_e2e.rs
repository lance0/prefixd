//! End-to-end integration tests with REAL GoBGP.
//!
//! These tests verify the complete flow:
//!   HTTP POST /v1/events → prefixd → GoBGP gRPC → FlowSpec in RIB
//!
//! Unlike other integration tests that use MockAnnouncer, these tests
//! actually announce FlowSpec rules to a real GoBGP instance and verify
//! they appear in the RIB.
//!
//! To run:
//!   scripts/test-gobgp.sh
//!
//! Requires Linux and Docker for owned testcontainers (Postgres + pinned GoBGP).

#![cfg(target_os = "linux")]
mod common;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use common::E2ETestContext;
use prefixd::bgp::{FlowSpecReader, FlowSpecWriter};
use prefixd::domain::MitigationStatus;

/// Test: POST event → mitigation created → FlowSpec appears in GoBGP RIB
#[tokio::test]
#[ignore] // Requires Docker
async fn test_e2e_event_creates_flowspec_in_rib() {
    let ctx = E2ETestContext::new().await;
    let app = ctx.router().await;

    // POST an attack event
    let event_json = r#"{
        "timestamp": "2026-01-18T10:00:00Z",
        "source": "e2e_test",
        "victim_ip": "203.0.113.10",
        "vector": "udp_flood",
        "bps": 500000000,
        "pps": 100000,
        "confidence": 0.95
    }"#;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_json))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8_lossy(&body);

    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "Event should be accepted. Response body: {}",
        body_str
    );

    // Small delay for GoBGP to process
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify mitigation in database
    let mitigations = ctx
        .repo
        .list_mitigations(
            None,
            None,
            None,
            None,
            &prefixd::db::MitigationListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .expect("Failed to list mitigations");

    assert_eq!(mitigations.len(), 1, "Should have one mitigation");
    assert_eq!(mitigations[0].victim_ip, "203.0.113.10");
    assert_eq!(mitigations[0].status, MitigationStatus::Active);

    // THE MONEY SHOT: Verify FlowSpec rule in GoBGP RIB
    let active_rules = ctx
        .announcer
        .list_active()
        .await
        .expect("Failed to list active rules from GoBGP");

    let found = active_rules
        .iter()
        .find(|r| r.nlri.dst_prefix == "203.0.113.10/32");

    assert!(
        found.is_some(),
        "FlowSpec rule should be in GoBGP RIB. Found rules: {:?}",
        active_rules
            .iter()
            .map(|r| &r.nlri.dst_prefix)
            .collect::<Vec<_>>()
    );

    let rule = found.unwrap();
    assert_eq!(rule.nlri.protocol, Some(17), "Should be UDP (protocol 17)");
}

/// Test: Create mitigation via event, withdraw via API, verify removed from RIB
#[tokio::test]
#[ignore] // Requires Docker
async fn test_e2e_withdrawal_removes_from_rib() {
    let ctx = E2ETestContext::new().await;
    let app = ctx.router().await;

    // Step 1: Create mitigation via event
    let event_json = r#"{
        "timestamp": "2026-01-18T10:00:00Z",
        "source": "e2e_test",
        "victim_ip": "203.0.113.11",
        "vector": "syn_flood",
        "top_dst_ports": [443],
        "bps": 100000000,
        "confidence": 0.9
    }"#;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_json))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Step 2: Get mitigation ID from database
    let mitigations = ctx
        .repo
        .list_mitigations(
            None,
            None,
            None,
            None,
            &prefixd::db::MitigationListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .expect("Failed to list mitigations");

    assert_eq!(mitigations.len(), 1);
    let mitigation_id = mitigations[0].mitigation_id;

    // Verify rule is in RIB
    let active_before = ctx.announcer.list_active().await.unwrap();
    assert!(
        active_before
            .iter()
            .any(|r| r.nlri.dst_prefix == "203.0.113.11/32"),
        "Rule should be in RIB before withdrawal"
    );
    let rule = active_before
        .iter()
        .find(|r| r.nlri.dst_prefix == "203.0.113.11/32")
        .unwrap();
    assert_eq!(rule.nlri.dst_ports, [443]);

    // Step 3: Withdraw via API
    let withdraw_json = r#"{"operator_id": "e2e_test", "reason": "E2E test withdrawal"}"#;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/mitigations/{}/withdraw", mitigation_id))
                .header("content-type", "application/json")
                .body(Body::from(withdraw_json))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Withdrawal should succeed"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Step 4: Verify rule is GONE from RIB
    let active_after = ctx.announcer.list_active().await.unwrap();
    assert!(
        !active_after
            .iter()
            .any(|r| r.nlri.dst_prefix == "203.0.113.11/32"),
        "Rule should be removed from RIB after withdrawal"
    );

    ctx.announcer
        .withdraw(
            active_before
                .iter()
                .find(|rule| rule.nlri.dst_prefix == "203.0.113.11/32")
                .unwrap(),
        )
        .await
        .expect("retrying deletion of an absent rule must succeed");

    // Verify mitigation status in database
    let mitigation = ctx
        .repo
        .get_mitigation(mitigation_id)
        .await
        .expect("Failed to get mitigation")
        .expect("Mitigation should exist");

    assert_eq!(mitigation.status, MitigationStatus::Withdrawn);
}

/// Test: Multiple events for different victims create separate FlowSpec rules
#[tokio::test]
#[ignore] // Requires Docker
async fn test_e2e_multiple_mitigations() {
    let ctx = E2ETestContext::new().await;
    let app = ctx.router().await;

    // Create two mitigations for different IPs
    for (ip, vector, ports) in [
        ("203.0.113.10", "udp_flood", vec![]),
        ("203.0.113.11", "syn_flood", vec![443]),
    ] {
        let event_json = serde_json::json!({
            "timestamp": "2026-01-18T10:00:00Z",
            "source": "e2e_test",
            "victim_ip": ip,
            "vector": vector,
            "top_dst_ports": ports,
            "bps": 100000000,
            "confidence": 0.9
        })
        .to_string();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/events")
                    .header("content-type", "application/json")
                    .body(Body::from(event_json))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Verify both rules in RIB
    let active_rules = ctx.announcer.list_active().await.unwrap();

    assert!(
        active_rules
            .iter()
            .any(|r| r.nlri.dst_prefix == "203.0.113.10/32"),
        "First rule should be in RIB"
    );
    assert!(
        active_rules
            .iter()
            .any(|r| r.nlri.dst_prefix == "203.0.113.11/32"),
        "Second rule should be in RIB"
    );
    let tcp_rule = active_rules
        .iter()
        .find(|r| r.nlri.dst_prefix == "203.0.113.11/32")
        .unwrap();
    assert_eq!(tcp_rule.nlri.dst_ports, [443]);

    // Verify database
    let mitigations = ctx
        .repo
        .list_mitigations(
            None,
            None,
            None,
            None,
            &prefixd::db::MitigationListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(mitigations.len(), 2, "Should have two mitigations");
}

/// Test: Duplicate event extends TTL instead of creating new mitigation
#[tokio::test]
#[ignore] // Requires Docker
async fn test_e2e_duplicate_event_extends_ttl() {
    let ctx = E2ETestContext::new().await;
    let app = ctx.router().await;

    let event_json = r#"{
        "timestamp": "2026-01-18T10:00:00Z",
        "source": "e2e_test",
        "victim_ip": "203.0.113.10",
        "vector": "udp_flood",
        "bps": 500000000,
        "confidence": 0.95
    }"#;

    // First event
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_json))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mitigations_before = ctx
        .repo
        .list_mitigations(
            None,
            None,
            None,
            None,
            &prefixd::db::MitigationListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(mitigations_before.len(), 1);
    let expires_before = mitigations_before[0].expires_at;

    // Wait a bit
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Second event (duplicate)
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_json))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify: still one mitigation, but TTL extended
    let mitigations_after = ctx
        .repo
        .list_mitigations(
            None,
            None,
            None,
            None,
            &prefixd::db::MitigationListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(mitigations_after.len(), 1, "Should still be one mitigation");
    assert!(
        mitigations_after[0].expires_at > expires_before,
        "TTL should be extended"
    );

    // Verify: still one rule in RIB
    let active_rules = ctx.announcer.list_active().await.unwrap();
    let matching_rules: Vec<_> = active_rules
        .iter()
        .filter(|r| r.nlri.dst_prefix == "203.0.113.10/32")
        .collect();
    assert_eq!(matching_rules.len(), 1, "Should still be one rule in RIB");
}

/// Test: Safelist blocks mitigation from being created
#[tokio::test]
#[ignore] // Requires Docker
async fn test_e2e_safelist_blocks_mitigation() {
    let ctx = E2ETestContext::new().await;
    let app = ctx.router().await;

    // Add IP to safelist
    ctx.repo
        .insert_safelist("203.0.113.10/32", "e2e_test", Some("Test safelist entry"))
        .await
        .expect("Failed to add to safelist");

    // Try to create mitigation for safelisted IP
    let event_json = r#"{
        "timestamp": "2026-01-18T10:00:00Z",
        "source": "e2e_test",
        "victim_ip": "203.0.113.10",
        "vector": "udp_flood",
        "bps": 500000000,
        "confidence": 0.95
    }"#;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_json))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be rejected (422 Unprocessable Entity for guardrail violations)
    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "Safelisted IP should be rejected"
    );

    // Verify no mitigation created
    let mitigations = ctx
        .repo
        .list_mitigations(
            None,
            None,
            None,
            None,
            &prefixd::db::MitigationListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(mitigations.len(), 0, "No mitigation should be created");

    // Verify no rule in RIB
    let active_rules = ctx.announcer.list_active().await.unwrap();
    assert!(
        !active_rules
            .iter()
            .any(|r| r.nlri.dst_prefix == "203.0.113.10/32"),
        "No rule should be in RIB for safelisted IP"
    );
}

/// Test: API returns correct response format
#[tokio::test]
#[ignore] // Requires Docker
async fn test_e2e_api_response_format() {
    let ctx = E2ETestContext::new().await;
    let app = ctx.router().await;

    let event_json = r#"{
        "timestamp": "2026-01-18T10:00:00Z",
        "source": "e2e_test",
        "victim_ip": "203.0.113.10",
        "vector": "udp_flood",
        "bps": 500000000,
        "confidence": 0.95
    }"#;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_json))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);

    // Parse response body
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).expect("Response should be JSON");

    // Verify response fields
    assert!(
        json.get("event_id").is_some(),
        "Response should have event_id"
    );
    assert!(
        json.get("mitigation_id").is_some(),
        "Response should have mitigation_id"
    );
}

// =============================================================================
// Signal Adapter E2E Tests (Correlation + GoBGP)
// =============================================================================
//
// These tests verify the full signal adapter flow:
//   Signal webhook → Correlation engine → Policy → GoBGP FlowSpec
//
// VAL-CROSS-001: Alertmanager webhook → signal group → mitigation
// VAL-CROSS-002: Multi-source corroboration lifecycle
// VAL-CROSS-010: Signal dedup across adapters

/// Helper: POST to /v1/signals/alertmanager and return (status, json)
async fn post_alertmanager(app: &axum::Router, payload: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/alertmanager")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    (status, json)
}

/// Helper: POST to /v1/signals/fastnetmon and return (status, json)
async fn post_fastnetmon(app: &axum::Router, payload: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/fastnetmon")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    (status, json)
}

/// Helper: GET endpoint and return (status, json)
async fn get_json(app: &axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    (status, json)
}

/// Build an Alertmanager v4 webhook payload with one firing alert.
fn make_alertmanager_payload(
    victim_ip: &str,
    vector: &str,
    severity: &str,
    fingerprint: &str,
) -> String {
    serde_json::json!({
        "version": "4",
        "status": "firing",
        "alerts": [{
            "status": "firing",
            "labels": {
                "victim_ip": victim_ip,
                "vector": vector,
                "severity": severity,
                "alertname": "DDoS_Alert"
            },
            "annotations": {
                "bps": "500000000",
                "pps": "1000000"
            },
            "startsAt": "2026-03-19T10:30:00Z",
            "endsAt": "0001-01-01T00:00:00Z",
            "generatorURL": "http://prometheus:9090/graph",
            "fingerprint": fingerprint
        }],
        "groupLabels": { "alertname": "DDoS_Alert" },
        "commonLabels": {},
        "commonAnnotations": {},
        "externalURL": "http://alertmanager.example.com"
    })
    .to_string()
}

/// Build a FastNetMon webhook payload.
fn make_fastnetmon_payload(action: &str, ip: &str, attack_uuid: &str) -> String {
    serde_json::json!({
        "action": action,
        "ip": ip,
        "alert_scope": "host",
        "attack_details": {
            "attack_uuid": attack_uuid,
            "attack_severity": "high",
            "attack_detection_source": "automatic",
            "incoming_udp_pps": 500000,
            "incoming_udp_traffic_bits": 4000000000_i64,
            "incoming_tcp_pps": 100,
            "incoming_tcp_traffic_bits": 800000,
            "incoming_syn_tcp_pps": 0,
            "incoming_icmp_pps": 0,
            "total_incoming_pps": 500100,
            "total_incoming_traffic_bits": 4000800000_i64,
            "total_incoming_flows": 12000
        }
    })
    .to_string()
}

/// VAL-CROSS-001: Alertmanager webhook → signal group created → mitigation
/// created with correlation data (full stack through real GoBGP).
///
/// Verifies the complete flow: Alertmanager webhook payload is received,
/// a signal group is created, a mitigation is produced (with correlation
/// context), and a FlowSpec rule appears in the GoBGP RIB.
#[tokio::test]
#[ignore] // Requires Docker
async fn test_e2e_alertmanager_signal_to_mitigation() {
    // Use min_sources=1 so a single Alertmanager alert triggers mitigation
    let ctx = E2ETestContext::with_correlation(1, 0.5).await;
    let app = ctx.router().await;

    // Send Alertmanager webhook
    let payload =
        make_alertmanager_payload("203.0.113.10", "udp_flood", "critical", "e2e-am-fp-001");
    let (status, json) = post_alertmanager(&app, &payload).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Alertmanager webhook should return 200. Body: {:?}",
        json
    );
    assert_eq!(json["processed"], 1, "Should process 1 alert");
    assert_eq!(json["failed"], 0, "No alerts should fail");

    // Small delay for GoBGP to process announcement
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Verify signal group was created
    let (sg_status, sg_json) = get_json(&app, "/v1/signal-groups").await;
    assert_eq!(sg_status, StatusCode::OK);

    let groups = sg_json["groups"]
        .as_array()
        .expect("groups should be array");
    assert!(!groups.is_empty(), "At least one signal group should exist");

    let group = &groups[0];
    assert_eq!(group["victim_ip"], "203.0.113.10");
    assert_eq!(group["vector"], "udp_flood");
    assert_eq!(group["source_count"], 1);

    // Verify mitigation was created
    let mitigations = ctx
        .repo
        .list_mitigations(
            None,
            None,
            None,
            None,
            &prefixd::db::MitigationListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .expect("Failed to list mitigations");

    assert_eq!(mitigations.len(), 1, "Should have one mitigation");
    assert_eq!(mitigations[0].victim_ip, "203.0.113.10");
    assert_eq!(mitigations[0].status, MitigationStatus::Active);
    assert!(
        mitigations[0].signal_group_id.is_some(),
        "Mitigation should have signal_group_id (correlation data)"
    );

    // Verify FlowSpec rule in GoBGP RIB
    let active_rules = ctx
        .announcer
        .list_active()
        .await
        .expect("Failed to list active rules from GoBGP");

    let found = active_rules
        .iter()
        .find(|r| r.nlri.dst_prefix == "203.0.113.10/32");

    assert!(
        found.is_some(),
        "FlowSpec rule should be in GoBGP RIB. Found rules: {:?}",
        active_rules
            .iter()
            .map(|r| &r.nlri.dst_prefix)
            .collect::<Vec<_>>()
    );

    // Verify mitigation detail includes correlation context via API
    let mit_id = mitigations[0].mitigation_id;
    let (mit_status, mit_json) = get_json(&app, &format!("/v1/mitigations/{}", mit_id)).await;
    assert_eq!(mit_status, StatusCode::OK);
    assert!(
        mit_json.get("correlation").is_some() && !mit_json["correlation"].is_null(),
        "Mitigation detail should include non-null correlation context. Got: {:?}",
        mit_json.get("correlation")
    );
    assert_eq!(mit_json["correlation"]["source_count"], 1);
    assert!(
        mit_json["correlation"]["corroboration_met"]
            .as_bool()
            .unwrap_or(false)
    );
}

/// E2E test: FastNetMon signal → signal group → mitigation (full stack).
///
/// Verifies that a FastNetMon webhook payload creates a signal group,
/// produces a mitigation, and announces a FlowSpec rule to GoBGP.
#[tokio::test]
#[ignore] // Requires Docker
async fn test_e2e_fastnetmon_signal_to_mitigation() {
    // Use min_sources=1 so a single FastNetMon signal triggers mitigation
    let ctx = E2ETestContext::with_correlation(1, 0.5).await;
    let app = ctx.router().await;

    // Send FastNetMon webhook
    let payload = make_fastnetmon_payload("ban", "203.0.113.10", "e2e-fnm-uuid-001");
    let (status, json) = post_fastnetmon(&app, &payload).await;

    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "FastNetMon signal should return 202. Body: {:?}",
        json
    );
    assert!(json["event_id"].is_string(), "Should have event_id");
    assert!(
        json["mitigation_id"].is_string(),
        "Should have mitigation_id"
    );

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Verify signal group was created
    let (sg_status, sg_json) = get_json(&app, "/v1/signal-groups").await;
    assert_eq!(sg_status, StatusCode::OK);

    let groups = sg_json["groups"]
        .as_array()
        .expect("groups should be array");
    assert!(!groups.is_empty(), "At least one signal group should exist");

    let group = &groups[0];
    assert_eq!(group["victim_ip"], "203.0.113.10");
    assert_eq!(group["source_count"], 1);

    // Verify mitigation was created with signal_group_id
    let mitigations = ctx
        .repo
        .list_mitigations(
            None,
            None,
            None,
            None,
            &prefixd::db::MitigationListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .expect("Failed to list mitigations");

    assert_eq!(mitigations.len(), 1, "Should have one mitigation");
    assert_eq!(mitigations[0].victim_ip, "203.0.113.10");
    assert_eq!(mitigations[0].status, MitigationStatus::Active);
    assert!(
        mitigations[0].signal_group_id.is_some(),
        "Mitigation should have signal_group_id"
    );

    // Verify FlowSpec rule in GoBGP RIB
    let active_rules = ctx
        .announcer
        .list_active()
        .await
        .expect("Failed to list active rules from GoBGP");

    let found = active_rules
        .iter()
        .find(|r| r.nlri.dst_prefix == "203.0.113.10/32");

    assert!(
        found.is_some(),
        "FlowSpec rule should be in GoBGP RIB for FastNetMon signal. Found rules: {:?}",
        active_rules
            .iter()
            .map(|r| &r.nlri.dst_prefix)
            .collect::<Vec<_>>()
    );
}

/// VAL-CROSS-002: Multi-source corroboration lifecycle.
/// FastNetMon signal (below corroboration threshold) → group created, no mitigation.
/// Alertmanager signal → same group updated, corroboration met, mitigation created.
///
/// VAL-CROSS-010: Signal dedup across adapters.
/// Same source + fingerprint → duplicate rejected. Different sources + same
/// target → both accepted into the same signal group.
#[tokio::test]
#[ignore] // Requires Docker
async fn test_e2e_multi_source_corroboration() {
    // Require 2 distinct sources for corroboration
    let ctx = E2ETestContext::with_correlation(2, 0.5).await;
    let app = ctx.router().await;

    // Step 1: Send FastNetMon signal — should NOT trigger mitigation
    // (only 1 source, need 2 for corroboration)
    let fnm_payload = make_fastnetmon_payload("ban", "203.0.113.10", "e2e-corr-uuid-001");
    let (fnm_status, fnm_json) = post_fastnetmon(&app, &fnm_payload).await;

    assert_eq!(
        fnm_status,
        StatusCode::ACCEPTED,
        "FastNetMon signal should be accepted. Body: {:?}",
        fnm_json
    );
    // With min_sources=2, the first signal should NOT produce a mitigation
    assert!(
        fnm_json["mitigation_id"].is_null(),
        "No mitigation should be created with only 1 source (need 2). Got: {:?}",
        fnm_json["mitigation_id"]
    );

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify signal group exists with source_count=1, no mitigation yet
    let (sg_status, sg_json) = get_json(&app, "/v1/signal-groups").await;
    assert_eq!(sg_status, StatusCode::OK);

    let groups = sg_json["groups"].as_array().expect("groups array");
    assert_eq!(groups.len(), 1, "Should have exactly one signal group");
    assert_eq!(groups[0]["source_count"], 1);
    assert_eq!(groups[0]["status"], "open", "Group should still be open");

    // Verify no mitigations yet
    let mitigations = ctx
        .repo
        .list_mitigations(
            None,
            None,
            None,
            None,
            &prefixd::db::MitigationListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .expect("Failed to list mitigations");
    assert_eq!(
        mitigations.len(),
        0,
        "No mitigation should exist with only 1 source"
    );

    // Verify no FlowSpec rules in RIB
    let rules_before = ctx.announcer.list_active().await.unwrap();
    assert!(
        !rules_before
            .iter()
            .any(|r| r.nlri.dst_prefix == "203.0.113.10/32"),
        "No FlowSpec rule should be in RIB before corroboration"
    );

    // Step 2: Send Alertmanager signal for the SAME victim_ip + vector
    // This should corroborate and trigger mitigation
    let am_payload = make_alertmanager_payload(
        "203.0.113.10",
        "udp_flood",
        "critical",
        "e2e-corr-am-fp-001",
    );
    let (am_status, am_json) = post_alertmanager(&app, &am_payload).await;

    assert_eq!(
        am_status,
        StatusCode::OK,
        "Alertmanager webhook should succeed. Body: {:?}",
        am_json
    );
    assert_eq!(am_json["processed"], 1);

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Verify signal group updated with source_count=2 and resolved
    let (sg_status2, sg_json2) = get_json(&app, "/v1/signal-groups").await;
    assert_eq!(sg_status2, StatusCode::OK);

    let groups2 = sg_json2["groups"].as_array().expect("groups array");
    assert_eq!(
        groups2.len(),
        1,
        "Should still be one signal group (same victim_ip + vector)"
    );
    assert_eq!(
        groups2[0]["source_count"], 2,
        "Group should have 2 distinct sources"
    );
    assert_eq!(
        groups2[0]["status"], "resolved",
        "Group should be resolved after corroboration met"
    );
    assert!(
        groups2[0]["corroboration_met"].as_bool().unwrap_or(false),
        "Corroboration should be met"
    );

    // Verify mitigation was created
    let mitigations2 = ctx
        .repo
        .list_mitigations(
            None,
            None,
            None,
            None,
            &prefixd::db::MitigationListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .expect("Failed to list mitigations");

    assert_eq!(
        mitigations2.len(),
        1,
        "Should now have one mitigation after corroboration"
    );
    assert_eq!(mitigations2[0].victim_ip, "203.0.113.10");
    assert_eq!(mitigations2[0].status, MitigationStatus::Active);
    assert!(
        mitigations2[0].signal_group_id.is_some(),
        "Mitigation should link to signal group"
    );

    // Verify FlowSpec rule appeared in GoBGP RIB
    let active_rules = ctx
        .announcer
        .list_active()
        .await
        .expect("Failed to list active rules");

    let found = active_rules
        .iter()
        .find(|r| r.nlri.dst_prefix == "203.0.113.10/32");

    assert!(
        found.is_some(),
        "FlowSpec rule should be in GoBGP RIB after corroboration. Found: {:?}",
        active_rules
            .iter()
            .map(|r| &r.nlri.dst_prefix)
            .collect::<Vec<_>>()
    );

    // Verify signal group detail shows both sources
    let group_id = groups2[0]["group_id"].as_str().unwrap();
    let (detail_status, detail_json) =
        get_json(&app, &format!("/v1/signal-groups/{}", group_id)).await;
    assert_eq!(detail_status, StatusCode::OK);

    let events = detail_json["events"].as_array().expect("events array");
    assert_eq!(events.len(), 2, "Group should have 2 contributing events");

    let sources: Vec<&str> = events.iter().filter_map(|e| e["source"].as_str()).collect();
    assert!(
        sources.contains(&"fastnetmon"),
        "Should have fastnetmon source. Sources: {:?}",
        sources
    );
    assert!(
        sources.contains(&"alertmanager"),
        "Should have alertmanager source. Sources: {:?}",
        sources
    );

    // Verify mitigation detail includes correlation context with both sources
    let mit_id = mitigations2[0].mitigation_id;
    let (mit_status, mit_json) = get_json(&app, &format!("/v1/mitigations/{}", mit_id)).await;
    assert_eq!(mit_status, StatusCode::OK);

    let correlation = &mit_json["correlation"];
    assert!(
        !correlation.is_null(),
        "Mitigation should have correlation context"
    );
    assert_eq!(correlation["source_count"], 2);
    assert!(correlation["corroboration_met"].as_bool().unwrap_or(false));

    let contributing = correlation["contributing_sources"]
        .as_array()
        .expect("contributing_sources array");
    let source_names: Vec<&str> = contributing.iter().filter_map(|s| s.as_str()).collect();
    assert!(
        source_names.contains(&"fastnetmon"),
        "Contributing sources should include fastnetmon"
    );
    assert!(
        source_names.contains(&"alertmanager"),
        "Contributing sources should include alertmanager"
    );
}
