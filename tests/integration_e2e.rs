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
//!   cargo test --test integration_e2e -- --ignored
//!
//! Requires Docker for testcontainers (Postgres + GoBGP).

mod common;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use common::E2ETestContext;
use prefixd::bgp::FlowSpecAnnouncer;
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
        .list_mitigations(None, None, 100, 0)
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
        .list_mitigations(None, None, 100, 0)
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

    // Step 3: Withdraw via API
    let withdraw_json = r#"{"operator_id": "e2e_test", "reason": "E2E test withdrawal"}"#;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&format!("/v1/mitigations/{}/withdraw", mitigation_id))
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
    for (ip, vector) in [("203.0.113.10", "udp_flood"), ("203.0.113.11", "syn_flood")] {
        let event_json = format!(
            r#"{{
                "timestamp": "2026-01-18T10:00:00Z",
                "source": "e2e_test",
                "victim_ip": "{}",
                "vector": "{}",
                "bps": 100000000,
                "confidence": 0.9
            }}"#,
            ip, vector
        );

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

    // Verify database
    let mitigations = ctx.repo.list_mitigations(None, None, 100, 0).await.unwrap();
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

    let mitigations_before = ctx.repo.list_mitigations(None, None, 100, 0).await.unwrap();
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
    let mitigations_after = ctx.repo.list_mitigations(None, None, 100, 0).await.unwrap();
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
    let mitigations = ctx.repo.list_mitigations(None, None, 100, 0).await.unwrap();
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
