mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use common::TestContext;
use prefixd::domain::MitigationStatus;

#[tokio::test]
async fn test_full_event_to_mitigation_flow() {
    let ctx = TestContext::new().await;
    let app = ctx.router().await;

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
    let app = ctx.router().await;

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
    let app = ctx.router().await;

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
    let app = ctx.router().await;

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
    let app = ctx.router().await;

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

#[tokio::test]
async fn test_ttl_expiry() {
    use chrono::{Duration, Utc};
    use prefixd::bgp::{FlowSpecAnnouncer, MockAnnouncer};
    use prefixd::domain::{
        ActionParams, ActionType, AttackVector, FlowSpecAction, FlowSpecNlri, FlowSpecRule,
        MatchCriteria, Mitigation, MitigationStatus,
    };
    use prefixd::scheduler::ReconciliationLoop;
    use std::sync::Arc;
    use uuid::Uuid;

    let ctx = TestContext::new().await;

    // Create a shared MockAnnouncer so we can check withdrawals
    let announcer = Arc::new(MockAnnouncer::new());

    // Pre-announce a rule so we can verify it gets withdrawn
    let rule = FlowSpecRule::new(
        FlowSpecNlri {
            dst_prefix: "203.0.113.99/32".to_string(),
            protocol: Some(17),
            dst_ports: vec![53],
        },
        FlowSpecAction::police(10_000_000),
    );
    announcer.announce(&rule).await.expect("Failed to announce");
    assert_eq!(announcer.announced_count().await, 1, "Should have 1 announced rule");

    // Create a mitigation with expires_at in the past (already expired)
    let now = Utc::now();
    let expired_at = now - Duration::seconds(60); // 1 minute ago

    let mitigation = Mitigation {
        mitigation_id: Uuid::new_v4(),
        scope_hash: "test_expiry_hash".to_string(),
        pop: "test-pop".to_string(),
        customer_id: Some("cust_test".to_string()),
        service_id: None,
        victim_ip: "203.0.113.99".to_string(),
        vector: AttackVector::UdpFlood,
        match_criteria: MatchCriteria {
            dst_prefix: "203.0.113.99/32".to_string(),
            protocol: Some(17),
            dst_ports: vec![53],
        },
        action_type: ActionType::Police,
        action_params: ActionParams {
            rate_bps: Some(10_000_000),
        },
        status: MitigationStatus::Active, // Active but expired
        created_at: now - Duration::seconds(120),
        updated_at: now - Duration::seconds(60),
        expires_at: expired_at, // Already expired
        withdrawn_at: None,
        triggering_event_id: Uuid::new_v4(),
        last_event_id: Uuid::new_v4(),
        escalated_from_id: None,
        reason: "TTL expiry test".to_string(),
        rejection_reason: None,
    };

    // Insert the expired mitigation
    ctx.repo
        .insert_mitigation(&mitigation)
        .await
        .expect("Failed to insert mitigation");

    // Create reconciliation loop and run it (dry_run=false to test withdrawals)
    let reconciler = ReconciliationLoop::new(
        ctx.repo.clone(),
        announcer.clone(),
        30, // interval doesn't matter, we call reconcile() directly
        false, // NOT dry-run, so withdrawals happen
    );

    // Run reconciliation
    reconciler.reconcile().await.expect("Reconciliation failed");

    // Verify status changed
    let updated = ctx
        .repo
        .get_mitigation(mitigation.mitigation_id)
        .await
        .expect("Failed to get mitigation")
        .expect("Mitigation should exist");

    assert_eq!(updated.status, MitigationStatus::Expired);
    assert!(updated.withdrawn_at.is_some());

    // Verify BGP withdrawal happened
    assert_eq!(
        announcer.announced_count().await,
        0,
        "Rule should be withdrawn from announcer"
    );

    // Verify it no longer shows in find_expired (since it's now Expired, not Active)
    let expired_after = ctx
        .repo
        .find_expired_mitigations()
        .await
        .expect("Failed to find expired mitigations");

    assert_eq!(expired_after.len(), 0, "Should find 0 expired mitigations after expiry");
}

#[tokio::test]
async fn test_config_hot_reload() {
    use common::write_yaml;

    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");

    // Write initial inventory with 1 customer
    let initial_inventory = r#"
customers:
  - customer_id: cust_initial
    name: Initial Customer
    prefixes:
      - 10.0.0.0/24
    policy_profile: normal
    services: []
"#;
    write_yaml(temp_dir.path(), "inventory.yaml", initial_inventory);

    // Write initial playbooks with 1 playbook
    let initial_playbooks = r#"
playbooks:
  - name: udp_flood
    match:
      vector: udp_flood
      require_top_ports: false
    steps:
      - action: police
        rate_bps: 10000000
        ttl_seconds: 60
"#;
    write_yaml(temp_dir.path(), "playbooks.yaml", initial_playbooks);

    // Create context with our config dir
    let ctx = TestContext::with_config_dir(temp_dir.path()).await;

    // Verify initial state
    {
        let inv = ctx.state.inventory.read().await;
        assert_eq!(inv.customers.len(), 1);
        assert_eq!(inv.customers[0].customer_id, "cust_initial");
    }
    {
        let pb = ctx.state.playbooks.read().await;
        assert_eq!(pb.playbooks.len(), 1);
        assert_eq!(pb.playbooks[0].name, "udp_flood");
    }

    // Update inventory with 2 customers
    let updated_inventory = r#"
customers:
  - customer_id: cust_initial
    name: Initial Customer
    prefixes:
      - 10.0.0.0/24
    policy_profile: normal
    services: []
  - customer_id: cust_added
    name: Added Customer
    prefixes:
      - 10.1.0.0/24
    policy_profile: strict
    services: []
"#;
    write_yaml(temp_dir.path(), "inventory.yaml", updated_inventory);

    // Update playbooks with 2 playbooks
    let updated_playbooks = r#"
playbooks:
  - name: udp_flood
    match:
      vector: udp_flood
      require_top_ports: false
    steps:
      - action: police
        rate_bps: 10000000
        ttl_seconds: 60
  - name: syn_flood
    match:
      vector: syn_flood
      require_top_ports: false
    steps:
      - action: discard
        ttl_seconds: 120
"#;
    write_yaml(temp_dir.path(), "playbooks.yaml", updated_playbooks);

    // Call reload endpoint
    let app = ctx.router().await;
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/config/reload")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Parse response to verify what was reloaded
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let reload_resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let reloaded = reload_resp["reloaded"].as_array().unwrap();
    assert!(reloaded.iter().any(|v| v == "inventory"));
    assert!(reloaded.iter().any(|v| v == "playbooks"));

    // Verify new config is loaded
    {
        let inv = ctx.state.inventory.read().await;
        assert_eq!(inv.customers.len(), 2, "Should have 2 customers after reload");
        assert!(inv.customers.iter().any(|c| c.customer_id == "cust_added"));
    }
    {
        let pb = ctx.state.playbooks.read().await;
        assert_eq!(pb.playbooks.len(), 2, "Should have 2 playbooks after reload");
        assert!(pb.playbooks.iter().any(|p| p.name == "syn_flood"));
    }
}
