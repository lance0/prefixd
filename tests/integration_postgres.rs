mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use common::TestContext;
use prefixd::domain::MitigationStatus;

#[tokio::test]
async fn test_full_event_to_mitigation_flow() {
    let ctx = TestContext::new().await;
    let app = ctx.router();

    // Ingest an event for a known IP
    let event_json = r#"{
        "timestamp": "2026-01-17T10:00:00Z",
        "source": "integration_test",
        "victim_ip": "203.0.113.10",
        "vector": "udp_flood",
        "bps": 500000000,
        "pps": 100000,
        "top_dst_ports": [53, 123],
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

    // Verify mitigation was created in the database
    let mitigations = ctx
        .repo
        .list_mitigations(None, None, 100, 0)
        .await
        .expect("Failed to list mitigations");

    assert_eq!(mitigations.len(), 1);
    assert_eq!(mitigations[0].victim_ip, "203.0.113.10");
    assert_eq!(mitigations[0].status, MitigationStatus::Active);
}

#[tokio::test]
async fn test_mitigation_withdrawal() {
    let ctx = TestContext::new().await;
    let app = ctx.router();

    // First, create a mitigation via event
    let event_json = r#"{
        "timestamp": "2026-01-17T10:00:00Z",
        "source": "integration_test",
        "victim_ip": "203.0.113.10",
        "vector": "syn_flood",
        "bps": 100000000,
        "pps": 50000,
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

    // Get the mitigation ID from the database
    let mitigations = ctx
        .repo
        .list_mitigations(None, None, 100, 0)
        .await
        .expect("Failed to list mitigations");

    assert_eq!(mitigations.len(), 1);
    let mitigation_id = mitigations[0].mitigation_id;

    // Withdraw the mitigation
    let withdraw_json = r#"{
        "operator_id": "test_operator",
        "reason": "Integration test withdrawal"
    }"#;

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

    assert_eq!(response.status(), StatusCode::OK);

    // Verify mitigation status changed
    let mitigation = ctx
        .repo
        .get_mitigation(mitigation_id)
        .await
        .expect("Failed to get mitigation")
        .expect("Mitigation not found");

    assert_eq!(mitigation.status, MitigationStatus::Withdrawn);
}

#[tokio::test]
async fn test_pagination() {
    let ctx = TestContext::new().await;
    let app = ctx.router();

    // Create multiple mitigations by sending events for different IPs
    for i in 10..20 {
        let event_json = format!(
            r#"{{
                "timestamp": "2026-01-17T10:00:00Z",
                "source": "integration_test",
                "victim_ip": "203.0.113.{}",
                "vector": "udp_flood",
                "bps": 100000000,
                "pps": 50000,
                "top_dst_ports": [53],
                "confidence": 0.9
            }}"#,
            i
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

    // Test pagination - get first page
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations?limit=5&offset=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["count"], 5);

    // Test pagination - get second page
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations?limit=5&offset=5")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["count"], 5);
}

#[tokio::test]
async fn test_safelist_blocks_mitigation() {
    let ctx = TestContext::new().await;
    let app = ctx.router();

    // Add an IP to safelist
    ctx.repo
        .insert_safelist("203.0.113.10/32", "test", Some("Integration test"))
        .await
        .expect("Failed to add safelist entry");

    // Try to create mitigation for safelisted IP
    let event_json = r#"{
        "timestamp": "2026-01-17T10:00:00Z",
        "source": "integration_test",
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

    // Should be rejected due to safelist (422 Unprocessable Entity for guardrail violations)
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Verify no mitigation was created
    let mitigations = ctx
        .repo
        .list_mitigations(None, None, 100, 0)
        .await
        .expect("Failed to list mitigations");

    assert_eq!(mitigations.len(), 0);
}

#[tokio::test]
async fn test_duplicate_event_extends_ttl() {
    let ctx = TestContext::new().await;
    let app = ctx.router();

    let event_json = r#"{
        "timestamp": "2026-01-17T10:00:00Z",
        "source": "integration_test",
        "victim_ip": "203.0.113.10",
        "vector": "udp_flood",
        "bps": 500000000,
        "pps": 100000,
        "top_dst_ports": [53],
        "confidence": 0.95
    }"#;

    // First event creates mitigation
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
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let first_mitigation_id = json["mitigation_id"].as_str().unwrap();

    // Get original expiry time
    let mitigations = ctx
        .repo
        .list_mitigations(None, None, 100, 0)
        .await
        .expect("Failed to list mitigations");
    let original_expires_at = mitigations[0].expires_at;

    // Small delay to ensure time difference
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Second event should extend TTL
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
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Same mitigation should be returned
    assert_eq!(json["mitigation_id"].as_str().unwrap(), first_mitigation_id);
    assert_eq!(json["status"], "extended");

    // Verify TTL was extended
    let mitigations = ctx
        .repo
        .list_mitigations(None, None, 100, 0)
        .await
        .expect("Failed to list mitigations");

    assert_eq!(mitigations.len(), 1);
    assert!(mitigations[0].expires_at > original_expires_at);
}

#[tokio::test]
async fn test_migration_applies_cleanly() {
    // This test verifies that migrations apply cleanly to a fresh database
    // The TestContext::new() already runs migrations, so if we get here without panic, it worked
    let _ctx = TestContext::new().await;
    
    // Additional verification: ensure all expected tables exist
    // (implicit - we can query mitigations, safelist, etc.)
}
