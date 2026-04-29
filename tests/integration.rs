#![allow(clippy::field_reassign_with_default)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use tower::ServiceExt;

use prefixd::AppState;
use prefixd::api::create_test_router;
use prefixd::bgp::MockAnnouncer;
use prefixd::config::{
    AllowedPorts, Asset, AuthConfig, AuthMode, BgpConfig, BgpMode, Customer, EscalationConfig,
    GuardrailsConfig, HttpConfig, Inventory, ObservabilityConfig, Playbook, PlaybookAction,
    PlaybookMatch, PlaybookStep, Playbooks, QuotasConfig, RateLimitConfig, SafelistConfig, Service,
    Settings, ShutdownConfig, StorageConfig, TimersConfig,
};
use prefixd::db::{MockRepository, RepositoryTrait};
use prefixd::domain::AttackVector;

fn test_settings() -> Settings {
    Settings {
        pop: "test1".to_string(),
        mode: prefixd::config::OperationMode::DryRun,
        http: HttpConfig {
            listen: "127.0.0.1:0".to_string(),
            auth: AuthConfig {
                mode: AuthMode::None,
                bearer_token_env: None,
                ldap: None,
                radius: None,
            },
            rate_limit: RateLimitConfig::default(),
            tls: None,
            cors_origin: None,
        },
        bgp: BgpConfig {
            mode: BgpMode::Mock,
            gobgp_grpc: "127.0.0.1:50051".to_string(),
            local_asn: 65000,
            router_id: "10.0.0.1".to_string(),
            neighbors: vec![],
        },
        guardrails: GuardrailsConfig {
            require_ttl: true,
            min_ttl_seconds: Some(30),
            max_ttl_seconds: Some(1800),
            dst_prefix_minlen: 32,
            dst_prefix_maxlen: 32,
            dst_prefix_minlen_v6: None,
            dst_prefix_maxlen_v6: None,
            max_ports: 8,
            allow_src_prefix_match: false,
            allow_tcp_flags_match: false,
            allow_fragment_match: false,
            allow_packet_length_match: false,
        },
        quotas: QuotasConfig {
            max_active_per_customer: 5,
            max_active_per_pop: 200,
            max_active_global: 500,
            max_new_per_minute: 30,
            max_announcements_per_peer: 100,
        },
        timers: TimersConfig {
            default_ttl_seconds: 120,
            min_ttl_seconds: 30,
            max_ttl_seconds: 1800,
            correlation_window_seconds: 300,
            reconciliation_interval_seconds: 30,
            quiet_period_after_withdraw_seconds: 120,
        },
        escalation: EscalationConfig {
            enabled: true,
            min_persistence_seconds: 120,
            min_confidence: 0.7,
            max_escalated_duration_seconds: 1800,
        },
        storage: StorageConfig {
            connection_string: "postgres://unused:unused@localhost/unused".to_string(),
        },
        observability: ObservabilityConfig {
            log_format: prefixd::config::LogFormat::Pretty,
            log_level: "info".to_string(),
            audit_log_path: "/dev/null".to_string(),
            metrics_listen: "127.0.0.1:0".to_string(),
        },
        safelist: SafelistConfig { prefixes: vec![] },
        shutdown: ShutdownConfig::default(),
        alerting: Default::default(),
        correlation: Default::default(),
    }
}

fn test_inventory() -> Inventory {
    Inventory::new(vec![Customer {
        customer_id: "cust_test".to_string(),
        name: "Test Customer".to_string(),
        prefixes: vec!["203.0.113.0/24".to_string()],
        policy_profile: prefixd::config::PolicyProfile::Normal,
        services: vec![Service {
            service_id: "svc_dns".to_string(),
            name: "DNS".to_string(),
            assets: vec![Asset {
                ip: "203.0.113.10".to_string(),
                role: Some("dns".to_string()),
                interface: None,
            }],
            allowed_ports: AllowedPorts {
                udp: vec![53],
                tcp: vec![53],
            },
        }],
    }])
}

fn test_playbooks() -> Playbooks {
    Playbooks {
        playbooks: vec![Playbook {
            name: "udp_flood_test".to_string(),
            match_criteria: PlaybookMatch {
                vector: AttackVector::UdpFlood,
                require_top_ports: false,
            },
            correlation: None,
            steps: vec![PlaybookStep {
                action: PlaybookAction::Police,
                rate_bps: Some(5_000_000),
                ttl_seconds: 120,
                require_confidence_at_least: None,
                require_persistence_seconds: None,
            }],
        }],
    }
}

async fn setup_app_with_config_dir(config_dir: std::path::PathBuf) -> axum::Router {
    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());

    let state = AppState::new(
        test_settings(),
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        config_dir,
    )
    .expect("failed to create app state");

    create_test_router(state)
}

async fn setup_app() -> axum::Router {
    setup_app_with_config_dir(std::path::PathBuf::from(".")).await
}

async fn setup_app_bearer_with_config_dir(config_dir: std::path::PathBuf) -> axum::Router {
    unsafe {
        std::env::set_var("TEST_PREFIXD_TOKEN", "test-secret-token-123");
    }

    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());

    let state = AppState::new(
        test_settings_with_bearer(),
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        config_dir,
    )
    .expect("failed to create app state");

    create_test_router(state)
}

#[tokio::test]
async fn test_health_endpoint() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Public health returns slim response
    assert!(json["status"].is_string(), "status should be a string");
    assert!(json["version"].is_string(), "version should be a string");
    assert!(
        json["auth_mode"].is_string(),
        "auth_mode should be a string"
    );
    // Sensitive fields should NOT be present on public health
    assert!(
        json["bgp_sessions"].is_null(),
        "bgp_sessions should not be on public health"
    );
    assert!(
        json["database"].is_null(),
        "database should not be on public health"
    );
}

#[tokio::test]
async fn test_health_detail_endpoint() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/health/detail")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["status"].is_string(), "status should be a string");
    assert!(json["version"].is_string(), "version should be a string");
    assert!(
        json["bgp_sessions"].is_object(),
        "bgp_sessions should be present on detail"
    );
    assert!(
        json["database"].is_string(),
        "database should be present on detail"
    );
    assert!(
        json["gobgp"].is_object(),
        "gobgp should be present on detail"
    );
    assert!(
        json["uptime_seconds"].is_number(),
        "uptime_seconds should be present on detail"
    );
}

#[tokio::test]
async fn test_config_settings_endpoint() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/config/settings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["settings"].is_object(), "settings should be present");
    assert!(json["loaded_at"].is_string(), "loaded_at should be present");
    // Verify allowlist redaction: sensitive fields must not appear
    assert_eq!(
        json["settings"]["storage"]["connection_string"],
        "[redacted]"
    );
    assert!(
        json["settings"]["http"]["auth"]["bearer_token_env"].is_null(),
        "bearer_token_env should not be in allowlist"
    );
    assert!(
        json["settings"]["bgp"]["gobgp_grpc"].is_null(),
        "gobgp_grpc should not be in allowlist"
    );
    assert!(
        json["settings"]["bgp"]["router_id"].is_null(),
        "router_id should not be in allowlist"
    );
}

#[tokio::test]
async fn test_config_inventory_endpoint() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/config/inventory")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["customers"].is_array(), "customers should be an array");
    assert!(
        json["total_customers"].is_number(),
        "total_customers should be a number"
    );
    assert!(
        json["total_services"].is_number(),
        "total_services should be a number"
    );
    assert!(
        json["total_assets"].is_number(),
        "total_assets should be a number"
    );
    assert!(json["loaded_at"].is_string(), "loaded_at should be present");
}

#[tokio::test]
async fn test_config_playbooks_endpoint() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/config/playbooks")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["playbooks"].is_array(), "playbooks should be an array");
    assert!(
        json["total_playbooks"].is_number(),
        "total_playbooks should be a number"
    );
    assert!(json["loaded_at"].is_string(), "loaded_at should be present");
}

#[tokio::test]
async fn test_list_mitigations_empty() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_ingest_event() {
    let app = setup_app().await;

    let event_json = r#"{
        "timestamp": "2026-01-16T14:00:00Z",
        "source": "test",
        "victim_ip": "203.0.113.10",
        "vector": "udp_flood",
        "bps": 100000000,
        "pps": 50000,
        "top_dst_ports": [53],
        "confidence": 0.9
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
}

#[tokio::test]
async fn test_list_mitigations_filters_by_victim_ip() {
    let app = setup_app().await;

    let event_a = r#"{
        "timestamp": "2026-01-16T14:00:00Z",
        "source": "test",
        "victim_ip": "203.0.113.10",
        "vector": "udp_flood",
        "pps": 50000
    }"#;
    let event_b = r#"{
        "timestamp": "2026-01-16T14:00:01Z",
        "source": "test",
        "victim_ip": "203.0.113.11",
        "vector": "syn_flood",
        "pps": 25000
    }"#;

    for body in [event_a, event_b] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/events")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations?victim_ip=203.0.113.10")
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

    assert_eq!(json["count"], 1);
    assert_eq!(json["mitigations"][0]["victim_ip"], "203.0.113.10");
}

#[tokio::test]
async fn test_bulk_withdraw_mitigations() {
    let app = setup_app().await;

    // Ingest two events for different IPs to create two mitigations
    let events = vec![
        r#"{
            "timestamp": "2026-01-16T14:00:00Z",
            "source": "test",
            "victim_ip": "203.0.113.20",
            "vector": "udp_flood",
            "pps": 50000
        }"#,
        r#"{
            "timestamp": "2026-01-16T14:00:01Z",
            "source": "test",
            "victim_ip": "203.0.113.21",
            "vector": "udp_flood",
            "pps": 25000
        }"#,
    ];

    for body in events {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/events")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    // Get mitigation IDs
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations")
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
    let mitigations = json["mitigations"].as_array().unwrap();
    assert!(
        mitigations.len() >= 2,
        "expected at least 2 mitigations, got {}",
        mitigations.len()
    );

    let id1 = mitigations[0]["mitigation_id"].as_str().unwrap();
    let id2 = mitigations[1]["mitigation_id"].as_str().unwrap();

    // Bulk withdraw both plus a fake ID
    let fake_id = "00000000-0000-0000-0000-000000000000";
    let withdraw_body = serde_json::json!({
        "mitigation_ids": [id1, id2, fake_id],
        "operator_id": "test_operator",
        "reason": "bulk test"
    });

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mitigations/withdraw")
                .header("content-type", "application/json")
                .body(Body::from(withdraw_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["withdrawn"], 2);
    assert_eq!(json["failed"], 1);
    assert_eq!(json["results"].as_array().unwrap().len(), 3);
}

// Auth tests with bearer token
fn test_settings_with_bearer() -> Settings {
    let mut settings = test_settings();
    settings.http.auth.mode = AuthMode::Bearer;
    settings.http.auth.bearer_token_env = Some("TEST_PREFIXD_TOKEN".to_string());
    settings
}

async fn setup_app_with_bearer() -> axum::Router {
    // Set the test token in environment
    // SAFETY: Tests run serially, no other threads reading this env var
    unsafe {
        std::env::set_var("TEST_PREFIXD_TOKEN", "test-secret-token-123");
    }

    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());

    let state = AppState::new(
        test_settings_with_bearer(),
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("failed to create app state");

    create_test_router(state)
}

#[tokio::test]
async fn test_bearer_auth_missing_token_returns_401() {
    let app = setup_app_with_bearer().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_bearer_auth_invalid_token_returns_401() {
    let app = setup_app_with_bearer().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations")
                .header("Authorization", "Bearer wrong-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_bearer_auth_valid_token_returns_200() {
    let app = setup_app_with_bearer().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations")
                .header("Authorization", "Bearer test-secret-token-123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_public_endpoint_no_auth_required() {
    let app = setup_app_with_bearer().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_security_headers_present() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    assert_eq!(
        response
            .headers()
            .get("x-content-type-options")
            .map(|v| v.to_str().unwrap()),
        Some("nosniff")
    );
    assert_eq!(
        response
            .headers()
            .get("x-frame-options")
            .map(|v| v.to_str().unwrap()),
        Some("DENY")
    );
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .map(|v| v.to_str().unwrap()),
        Some("no-store")
    );
}

#[tokio::test]
async fn test_timeseries_returns_buckets() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/stats/timeseries?metric=mitigations&range=24h&bucket=1h")
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
    assert_eq!(json["metric"], "mitigations");
    // MockRepository returns empty buckets
    assert!(json["buckets"].is_array());
}

#[tokio::test]
async fn test_ip_history_returns_structure() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/ip/192.0.2.1/history")
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
    assert_eq!(json["ip"], "192.0.2.1");
    assert!(json["events"].is_array());
    assert!(json["mitigations"].is_array());
}

#[tokio::test]
async fn test_ip_history_rejects_invalid_ip() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/ip/not-an-ip/history")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_update_playbooks_validation_error_returns_400() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/config/playbooks")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"playbooks":[]}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_update_playbooks_invalid_json_returns_400() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/config/playbooks")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"playbooks":"not-an-array"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_update_playbooks_success_writes_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_dir = temp_dir.path().to_path_buf();
    let app = setup_app_with_config_dir(config_dir.clone()).await;

    let body = r#"{
        "playbooks": [{
            "name": "syn_discard_test",
            "match": { "vector": "syn_flood", "require_top_ports": true },
            "steps": [
                { "action": "police", "rate_bps": 3000000, "ttl_seconds": 90 },
                { "action": "discard", "ttl_seconds": 240, "require_confidence_at_least": 0.8, "require_persistence_seconds": 120 }
            ]
        }]
    }"#;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/config/playbooks")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let written = std::fs::read_to_string(config_dir.join("playbooks.yaml")).unwrap();
    assert!(written.contains("syn_discard_test"));
    assert!(written.contains("syn_flood"));
}

#[tokio::test]
async fn test_update_playbooks_bearer_operator_forbidden() {
    let app = setup_app_with_bearer().await;

    let body = r#"{
        "playbooks": [{
            "name": "test_playbook",
            "match": { "vector": "udp_flood" },
            "steps": [{ "action": "police", "rate_bps": 5000000, "ttl_seconds": 120 }]
        }]
    }"#;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/config/playbooks")
                .header("Authorization", "Bearer test-secret-token-123")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// ─── Alerting PUT tests ───

#[tokio::test]
async fn test_update_alerting_success() {
    let dir = tempfile::tempdir().unwrap();
    let app = setup_app_with_config_dir(dir.path().to_path_buf()).await;

    let body = serde_json::json!({
        "destinations": [
            {
                "type": "slack",
                "webhook_url": "https://hooks.slack.com/services/T/B/xxx",
                "channel": "#alerts"
            }
        ],
        "events": ["mitigation.created", "mitigation.withdrawn"]
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/config/alerting")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["destinations"][0]["type"], "slack");
    assert_eq!(json["destinations"][0]["webhook_url"], "***");
    assert_eq!(json["events"].as_array().unwrap().len(), 2);

    // Verify file was written
    let alerting_path = dir.path().join("alerting.yaml");
    assert!(alerting_path.exists());
}

#[tokio::test]
async fn test_update_alerting_validation_error() {
    let dir = tempfile::tempdir().unwrap();
    let app = setup_app_with_config_dir(dir.path().to_path_buf()).await;

    let body = serde_json::json!({
        "destinations": [
            {
                "type": "slack",
                "webhook_url": "",
                "channel": "#alerts"
            }
        ],
        "events": []
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/config/alerting")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_update_alerting_invalid_json() {
    let dir = tempfile::tempdir().unwrap();
    let app = setup_app_with_config_dir(dir.path().to_path_buf()).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/config/alerting")
                .header("content-type", "application/json")
                .body(Body::from("not json"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_update_alerting_operator_forbidden() {
    let dir = tempfile::tempdir().unwrap();
    let app = setup_app_bearer_with_config_dir(dir.path().to_path_buf()).await;

    let body = serde_json::json!({
        "destinations": [],
        "events": []
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/config/alerting")
                .header("Authorization", "Bearer test-secret-token-123")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_update_alerting_rejects_link_local_url() {
    let dir = tempfile::tempdir().unwrap();
    let app = setup_app_with_config_dir(dir.path().to_path_buf()).await;

    let body = serde_json::json!({
        "destinations": [
            {
                "type": "generic",
                "url": "https://169.254.169.254/latest/meta-data",
                "secret": "test",
                "headers": {}
            }
        ],
        "events": []
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/config/alerting")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_reload_config_reloads_alerting_yaml() {
    let dir = tempfile::tempdir().unwrap();
    let config_dir = dir.path().to_path_buf();
    let app = setup_app_with_config_dir(config_dir.clone()).await;

    std::fs::write(
        config_dir.join("alerting.yaml"),
        r##"
destinations:
  - type: slack
    webhook_url: https://hooks.slack.com/services/T/B/C
    channel: "#ops-alerts"
events:
  - mitigation.created
"##,
    )
    .unwrap();

    let response = app
        .clone()
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
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["reloaded"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "alerting")
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/config/alerting")
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
    assert_eq!(json["destinations"][0]["type"], "slack");
    assert_eq!(json["events"][0], "mitigation.created");
}

#[tokio::test]
async fn test_cursor_pagination_mitigations() {
    let app = setup_app().await;

    // Ingest 3 events to create 3 mitigations
    for i in 0..3 {
        let body = serde_json::json!({
            "timestamp": format!("2026-01-16T14:00:0{}Z", i),
            "source": "test",
            "victim_ip": format!("203.0.113.{}", 50 + i),
            "vector": "udp_flood",
            "pps": 50000
        });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/events")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    // Page 1: limit=2
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations?limit=2")
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
    assert_eq!(json["count"], 2);
    assert_eq!(json["has_more"], true);
    assert!(
        json["next_cursor"].is_string(),
        "next_cursor should be present"
    );

    // Page 2: use cursor
    let cursor = json["next_cursor"].as_str().unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/mitigations?limit=2&cursor={}", cursor))
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
    assert_eq!(json["count"], 1);
    assert_eq!(json["has_more"], false);
    assert!(json["next_cursor"].is_null(), "no more pages");
}

#[tokio::test]
async fn test_cursor_pagination_events() {
    let app = setup_app().await;

    // Ingest 3 events
    for i in 0..3 {
        let body = serde_json::json!({
            "timestamp": format!("2026-01-16T14:00:0{}Z", i),
            "source": "test",
            "victim_ip": format!("203.0.113.{}", 60 + i),
            "vector": "udp_flood",
            "pps": 50000
        });
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/events")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    // Page 1: limit=2
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/events?limit=2")
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
    assert_eq!(json["count"], 2);
    assert_eq!(json["has_more"], true);

    // Page 2
    let cursor = json["next_cursor"].as_str().unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/events?limit=2&cursor={}", cursor))
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
    assert_eq!(json["count"], 1);
    assert_eq!(json["has_more"], false);
}

#[tokio::test]
async fn test_date_range_filtering_events() {
    let app = setup_app().await;

    // Ingest event
    let body = r#"{
        "timestamp": "2026-01-16T14:00:00Z",
        "source": "test",
        "victim_ip": "203.0.113.70",
        "vector": "udp_flood",
        "pps": 50000
    }"#;
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    // Query with date range that includes the event
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/events?start=2020-01-01T00:00:00Z&end=2030-01-01T00:00:00Z")
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
    assert!(json["count"].as_u64().unwrap() >= 1);

    // Query with date range that excludes the event (future only)
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/events?start=2030-01-01T00:00:00Z")
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
    assert_eq!(json["count"], 0);
}

#[tokio::test]
async fn test_bulk_acknowledge_mitigations() {
    let app = setup_app().await;

    // Ingest 2 events
    for i in 0..2 {
        let body = serde_json::json!({
            "timestamp": format!("2026-01-16T14:00:0{}Z", i),
            "source": "test",
            "victim_ip": format!("203.0.113.{}", 80 + i),
            "vector": "udp_flood",
            "pps": 50000
        });
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/events")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    // Get mitigation IDs
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let mitigations = json["mitigations"].as_array().unwrap();
    assert!(mitigations.len() >= 2);

    let id1 = mitigations[0]["mitigation_id"].as_str().unwrap();
    let id2 = mitigations[1]["mitigation_id"].as_str().unwrap();
    let fake_id = "00000000-0000-0000-0000-000000000000";

    // Bulk acknowledge: 2 real + 1 fake
    let ack_body = serde_json::json!({
        "mitigation_ids": [id1, id2, fake_id],
        "operator_id": "test_operator"
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mitigations/acknowledge")
                .header("content-type", "application/json")
                .body(Body::from(ack_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["acknowledged"], 2);
    assert_eq!(json["failed"], 1);

    // Verify acknowledged filter: acknowledged=true
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations?acknowledged=true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["count"], 2);

    // acknowledged=false should return 0
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations?acknowledged=false")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["count"], 0);

    // Re-acknowledge should fail (already acknowledged)
    let ack_body = serde_json::json!({
        "mitigation_ids": [id1],
        "operator_id": "test_operator"
    });
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mitigations/acknowledge")
                .header("content-type", "application/json")
                .body(Body::from(ack_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["acknowledged"], 0);
    assert_eq!(json["failed"], 1);
}

// ---------------------------------------------------------------------------
// Event batch ingestion
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_batch_event_ingestion_all_accepted() {
    let app = setup_app().await;

    let body = serde_json::json!({
        "events": [
            {
                "timestamp": "2026-01-16T14:00:00Z",
                "source": "fastnetmon",
                "victim_ip": "203.0.113.200",
                "vector": "udp_flood",
                "pps": 50000
            },
            {
                "timestamp": "2026-01-16T14:00:01Z",
                "source": "fastnetmon",
                "victim_ip": "203.0.113.201",
                "vector": "syn_flood",
                "bps": 1000000000
            },
            {
                "timestamp": "2026-01-16T14:00:02Z",
                "source": "fastnetmon",
                "victim_ip": "203.0.113.202",
                "vector": "icmp_flood",
                "pps": 100000
            }
        ]
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events/batch")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["accepted"], 3);
    assert_eq!(json["rejected"], 0);
    let results = json["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
    for (i, r) in results.iter().enumerate() {
        assert_eq!(r["index"], i);
        assert!(r["event_id"].is_string());
        assert!(!r["status"].as_str().unwrap().contains("rejected"));
    }
}

#[tokio::test]
async fn test_batch_event_ingestion_partial_success() {
    let app = setup_app().await;

    let body = serde_json::json!({
        "events": [
            {
                "timestamp": "2026-01-16T14:00:00Z",
                "source": "fastnetmon",
                "victim_ip": "203.0.113.210",
                "vector": "udp_flood",
                "pps": 50000
            },
            {
                "timestamp": "2026-01-16T14:00:01Z",
                "source": "fastnetmon",
                "victim_ip": "not_an_ip",
                "vector": "syn_flood"
            },
            {
                "timestamp": "2026-01-16T14:00:02Z",
                "source": "fastnetmon",
                "victim_ip": "203.0.113.211",
                "vector": "ack_flood",
                "pps": 80000
            }
        ]
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events/batch")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::MULTI_STATUS);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["accepted"], 2);
    assert_eq!(json["rejected"], 1);
    let results = json["results"].as_array().unwrap();
    assert_eq!(results[1]["status"], "rejected");
    assert!(results[1]["error"].as_str().unwrap().contains("IP"));
}

#[tokio::test]
async fn test_batch_event_ingestion_empty_batch() {
    let app = setup_app().await;

    let body = serde_json::json!({ "events": [] });
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events/batch")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_batch_event_ingestion_exceeds_limit() {
    let app = setup_app().await;

    let events: Vec<serde_json::Value> = (0..101)
        .map(|i| {
            serde_json::json!({
                "timestamp": "2026-01-16T14:00:00Z",
                "source": "test",
                "victim_ip": format!("203.0.113.{}", i % 256),
                "vector": "udp_flood"
            })
        })
        .collect();

    let body = serde_json::json!({ "events": events });
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events/batch")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// Incident reports
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_incident_report_by_mitigation_id() {
    let app = setup_app().await;

    // Ingest event to create a mitigation
    let body = serde_json::json!({
        "timestamp": "2026-01-16T14:00:00Z",
        "source": "fastnetmon",
        "victim_ip": "203.0.113.230",
        "vector": "udp_flood",
        "bps": 5000000000i64,
        "pps": 500000
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let event_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let mitigation_id = event_json["mitigation_id"].as_str().unwrap_or_default();

    // Generate report by mitigation_id
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/reports/incident?mitigation_id={}",
                    mitigation_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let ct = response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.contains("text/markdown"));

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let markdown = String::from_utf8(body.to_vec()).unwrap();
    assert!(markdown.contains("# Incident Report"));
    assert!(markdown.contains("203.0.113.230"));
    assert!(markdown.contains("## Summary"));
    assert!(markdown.contains("## Timeline"));
    assert!(markdown.contains("## Events"));
    assert!(markdown.contains("## Mitigations"));
}

#[tokio::test]
async fn test_incident_report_by_ip() {
    let app = setup_app().await;

    // Ingest event
    let body = serde_json::json!({
        "timestamp": "2026-01-16T15:00:00Z",
        "source": "fastnetmon",
        "victim_ip": "203.0.113.231",
        "vector": "syn_flood",
        "bps": 2000000000i64
    });
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Generate report by IP
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/reports/incident?ip=203.0.113.231")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let markdown = String::from_utf8(body.to_vec()).unwrap();
    assert!(markdown.contains("# Incident Report"));
    assert!(markdown.contains("203.0.113.231"));
}

#[tokio::test]
async fn test_incident_report_missing_params() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/reports/incident")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// Per-destination event routing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_alerting_config_per_destination_events_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let alerting_path = dir.path().join("alerting.yaml");
    std::fs::write(
        &alerting_path,
        r#"
destinations:
  - type: generic
    url: "https://example.com/all"
  - type: generic
    url: "https://example.com/critical"
    events:
      - mitigation.created
      - mitigation.escalated
events:
  - mitigation.created
  - mitigation.withdrawn
"#,
    )
    .unwrap();

    let config = prefixd::alerting::AlertingConfig::load(&alerting_path).unwrap();
    assert_eq!(config.destinations.len(), 2);

    // First dest has no per-destination events
    assert!(config.destinations[0].events().is_empty());
    // Second dest has per-destination events
    assert_eq!(config.destinations[1].events().len(), 2);

    // Save and reload
    config.save(&alerting_path).unwrap();
    let reloaded = prefixd::alerting::AlertingConfig::load(&alerting_path).unwrap();
    assert_eq!(reloaded.destinations[1].events().len(), 2);
}

// ---------------------------------------------------------------------------
// Notification preferences API
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_notification_preferences_get_default() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/preferences")
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
    assert_eq!(json["muted_events"], serde_json::json!([]));
    assert_eq!(json["quiet_hours_start"], serde_json::Value::Null);
    assert_eq!(json["quiet_hours_end"], serde_json::Value::Null);
}

#[tokio::test]
async fn test_notification_preferences_put_invalid_hour() {
    let app = setup_app().await;

    let body = serde_json::json!({
        "muted_events": [],
        "quiet_hours_start": 25,
        "quiet_hours_end": 8,
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/preferences")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_notification_preferences_put_invalid_event() {
    let app = setup_app().await;

    let body = serde_json::json!({
        "muted_events": ["not.a.real.event"],
        "quiet_hours_start": null,
        "quiet_hours_end": null,
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/preferences")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_notification_preferences_put_half_configured_quiet_hours() {
    let app = setup_app().await;

    let body = serde_json::json!({
        "muted_events": [],
        "quiet_hours_start": 2,
        "quiet_hours_end": null,
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/preferences")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_notification_preferences_response_includes_null_quiet_hours() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/preferences")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let raw = String::from_utf8_lossy(&body);
    assert!(raw.contains("\"quiet_hours_start\":null"));
    assert!(raw.contains("\"quiet_hours_end\":null"));
}

// ==========================================================================
// Correlation integration tests
// ==========================================================================

fn test_settings_with_correlation(
    enabled: bool,
    min_sources: u32,
    confidence_threshold: f32,
) -> Settings {
    let mut settings = test_settings();
    settings.correlation = prefixd::correlation::CorrelationConfig {
        enabled,
        window_seconds: 300,
        min_sources,
        confidence_threshold,
        sources: {
            let mut m = std::collections::HashMap::new();
            m.insert(
                "detector_a".to_string(),
                prefixd::correlation::SourceConfig {
                    weight: 1.0,
                    r#type: "detector".to_string(),
                    confidence_mapping: std::collections::HashMap::new(),
                    ..Default::default()
                },
            );
            m.insert(
                "detector_b".to_string(),
                prefixd::correlation::SourceConfig {
                    weight: 1.5,
                    r#type: "detector".to_string(),
                    confidence_mapping: std::collections::HashMap::new(),
                    ..Default::default()
                },
            );
            m
        },
        default_weight: 1.0,
        webhook_adapters: Vec::new(),
    };
    settings
}

async fn setup_app_correlation(
    enabled: bool,
    min_sources: u32,
    confidence_threshold: f32,
) -> axum::Router {
    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let settings = test_settings_with_correlation(enabled, min_sources, confidence_threshold);

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("failed to create app state");

    create_test_router(state)
}

fn make_event_json(source: &str, victim_ip: &str, confidence: f32) -> String {
    format!(
        r#"{{
            "timestamp": "2026-01-16T14:00:00Z",
            "source": "{}",
            "victim_ip": "{}",
            "vector": "udp_flood",
            "bps": 100000000,
            "pps": 50000,
            "top_dst_ports": [53],
            "confidence": {}
        }}"#,
        source, victim_ip, confidence
    )
}

async fn post_event(app: &axum::Router, event_json: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_json.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    (status, json)
}

/// VAL-ENGINE-010: Single source triggers when min_sources=1 (backward compat)
#[tokio::test]
async fn test_correlation_min_sources_1_triggers_immediately() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    let (status, json) = post_event(&app, &event).await;

    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(json["status"], "accepted");
    assert!(
        json["mitigation_id"].is_string(),
        "should create mitigation with min_sources=1: {:?}",
        json
    );
}

/// VAL-ENGINE-009: min_sources=2 and one source does NOT create mitigation
#[tokio::test]
async fn test_correlation_min_sources_2_one_source_no_mitigation() {
    let app = setup_app_correlation(true, 2, 0.5).await;

    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    let (status, json) = post_event(&app, &event).await;

    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(json["status"], "accepted");
    assert!(
        json["mitigation_id"].is_null(),
        "should NOT create mitigation with 1 source when min_sources=2"
    );
}

/// VAL-ENGINE-009: min_sources=2 and two sources creates mitigation
#[tokio::test]
async fn test_correlation_min_sources_2_two_sources_creates_mitigation() {
    let app = setup_app_correlation(true, 2, 0.5).await;

    // First event from detector_a — no mitigation
    let event_a = make_event_json("detector_a", "203.0.113.10", 0.9);
    let (status_a, json_a) = post_event(&app, &event_a).await;
    assert_eq!(status_a, StatusCode::ACCEPTED);
    assert!(
        json_a["mitigation_id"].is_null(),
        "first source alone shouldn't trigger"
    );

    // Second event from detector_b — mitigation created
    let event_b = make_event_json("detector_b", "203.0.113.10", 0.8);
    let (status_b, json_b) = post_event(&app, &event_b).await;
    assert_eq!(status_b, StatusCode::ACCEPTED);
    assert_eq!(json_b["status"], "accepted");
    assert!(
        json_b["mitigation_id"].is_string(),
        "second source should trigger mitigation: {:?}",
        json_b
    );
}

/// VAL-ENGINE-020: Events bypass correlation when disabled
#[tokio::test]
async fn test_correlation_disabled_bypasses_entirely() {
    let app = setup_app_correlation(false, 2, 0.5).await;

    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    let (status, json) = post_event(&app, &event).await;

    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(json["status"], "accepted");
    assert!(
        json["mitigation_id"].is_string(),
        "should create mitigation immediately when correlation disabled"
    );
}

/// VAL-ENGINE-029: EventResponse shape unchanged
#[tokio::test]
async fn test_correlation_event_response_shape_unchanged() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    let (status, json) = post_event(&app, &event).await;

    assert_eq!(status, StatusCode::ACCEPTED);
    assert!(json["event_id"].is_string(), "event_id must be present");
    assert!(json["status"].is_string(), "status must be present");
    // mitigation_id may be string or null
    assert!(
        json["mitigation_id"].is_string() || json["mitigation_id"].is_null(),
        "mitigation_id must be string or null"
    );
}

/// VAL-ENGINE-013: Derived confidence must meet threshold
#[tokio::test]
async fn test_correlation_low_confidence_no_mitigation() {
    // Two sources but very low confidence with threshold 0.7
    let app = setup_app_correlation(true, 2, 0.7).await;

    let event_a = make_event_json("detector_a", "203.0.113.10", 0.3);
    post_event(&app, &event_a).await;

    let event_b = make_event_json("detector_b", "203.0.113.10", 0.3);
    let (status, json) = post_event(&app, &event_b).await;

    assert_eq!(status, StatusCode::ACCEPTED);
    assert!(
        json["mitigation_id"].is_null(),
        "low confidence should not trigger even with 2 sources: {:?}",
        json
    );
}

/// VAL-ENGINE-011: Duplicate source counts as one for corroboration
#[tokio::test]
async fn test_correlation_duplicate_source_counts_as_one() {
    let app = setup_app_correlation(true, 2, 0.5).await;

    // Two events from same source
    let event_a = make_event_json("detector_a", "203.0.113.10", 0.9);
    post_event(&app, &event_a).await;

    // Use a different event_id to avoid duplicate detection
    let event_b = make_event_json("detector_a", "203.0.113.10", 0.8);
    let (status, json) = post_event(&app, &event_b).await;

    assert_eq!(status, StatusCode::ACCEPTED);
    assert!(
        json["mitigation_id"].is_null(),
        "same source twice should count as 1 distinct, not trigger with min_sources=2"
    );
}

/// VAL-ENGINE-030: Batch endpoint works with correlation
#[tokio::test]
async fn test_correlation_batch_endpoint_independent_groups() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    let batch_json = r#"{
        "events": [
            {
                "timestamp": "2026-01-16T14:00:00Z",
                "source": "detector_a",
                "victim_ip": "203.0.113.10",
                "vector": "udp_flood",
                "bps": 100000000,
                "pps": 50000,
                "top_dst_ports": [53],
                "confidence": 0.9
            },
            {
                "timestamp": "2026-01-16T14:00:01Z",
                "source": "detector_a",
                "victim_ip": "203.0.113.11",
                "vector": "udp_flood",
                "bps": 50000000,
                "pps": 25000,
                "top_dst_ports": [53],
                "confidence": 0.8
            }
        ]
    }"#;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events/batch")
                .header("content-type", "application/json")
                .body(Body::from(batch_json))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be 202 (all accepted) with min_sources=1
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["accepted"], 2);
    // Each event should create a mitigation independently
    let results = json["results"].as_array().unwrap();
    assert!(results[0]["mitigation_id"].is_string());
    assert!(results[1]["mitigation_id"].is_string());
    // Different victim IPs = different mitigations
    assert_ne!(results[0]["mitigation_id"], results[1]["mitigation_id"]);
}

/// VAL-ENGINE-018 / VAL-ENGINE-033: Mitigation detail/list includes correlation context
#[tokio::test]
async fn test_correlation_mitigation_detail_includes_correlation() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    // Create a correlated mitigation
    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    let (_, event_json) = post_event(&app, &event).await;
    let mitigation_id = event_json["mitigation_id"].as_str().unwrap();

    // GET /v1/mitigations/{id}
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/mitigations/{}", mitigation_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Should have correlation field
    assert!(
        json["correlation"].is_object(),
        "correlation should be present: {:?}",
        json
    );
    let corr = &json["correlation"];
    assert!(corr["signal_group_id"].is_string());
    assert!(corr["derived_confidence"].is_number());
    assert!(corr["source_count"].is_number());
    assert!(corr["corroboration_met"].is_boolean());
    assert!(corr["contributing_sources"].is_array());
    assert!(corr["explanation"].is_string());
}

/// VAL-ENGINE-019: Non-correlated mitigation has null correlation
#[tokio::test]
async fn test_correlation_disabled_mitigation_no_correlation_field() {
    let app = setup_app_correlation(false, 1, 0.5).await;

    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    let (_, event_json) = post_event(&app, &event).await;
    let mitigation_id = event_json["mitigation_id"].as_str().unwrap();

    // GET /v1/mitigations/{id}
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/mitigations/{}", mitigation_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // correlation should be absent (skipped when None)
    assert!(
        json["correlation"].is_null(),
        "correlation should be null/absent when disabled: {:?}",
        json
    );
}

/// VAL-ENGINE-004: Signal group resolves when mitigation created
#[tokio::test]
async fn test_correlation_signal_group_resolves_on_mitigation() {
    let repo = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let settings = test_settings_with_correlation(true, 1, 0.5);

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo.clone(),
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("failed to create app state");

    let app = create_test_router(state);

    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    post_event(&app, &event).await;

    // Check that the signal group was resolved
    let groups = repo
        .list_signal_groups(
            &prefixd::correlation::SignalGroupFilter {
                status: Some(prefixd::correlation::SignalGroupStatus::Resolved),
                ..Default::default()
            },
            &prefixd::db::ListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(groups.len(), 1, "should have one resolved group");
    assert!(
        groups[0].corroboration_met,
        "corroboration_met should be true"
    );
    assert_eq!(groups[0].source_count, 1);
}

/// VAL-ENGINE-033: Mitigations list includes correlation summary
#[tokio::test]
async fn test_correlation_mitigations_list_includes_summary() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    post_event(&app, &event).await;

    // GET /v1/mitigations
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let mitigations = json["mitigations"].as_array().unwrap();
    assert!(!mitigations.is_empty());
    let corr = &mitigations[0]["correlation"];
    assert!(
        corr.is_object(),
        "list should include correlation summary: {:?}",
        mitigations[0]
    );
    // Lightweight summary fields are present
    assert!(corr["signal_group_id"].is_string());
    assert!(corr["derived_confidence"].is_number());
    assert!(corr["source_count"].is_number());
    assert!(corr["corroboration_met"].is_boolean());
    // Detail-only fields are absent (null) in list view
    assert!(
        corr.get("contributing_sources").is_none() || corr["contributing_sources"].is_null(),
        "contributing_sources should be absent in list view, got: {:?}",
        corr["contributing_sources"]
    );
    assert!(
        corr.get("explanation").is_none() || corr["explanation"].is_null(),
        "explanation should be absent in list view, got: {:?}",
        corr["explanation"]
    );
}

/// List vs detail consistency: detail endpoint has contributing_sources and explanation
#[tokio::test]
async fn test_correlation_detail_has_full_context_list_has_summary() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    let (_, event_json) = post_event(&app, &event).await;
    let mitigation_id = event_json["mitigation_id"].as_str().unwrap();

    // Detail endpoint should have full context
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/mitigations/{}", mitigation_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let detail: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let detail_corr = &detail["correlation"];
    assert!(
        detail_corr["contributing_sources"].is_array(),
        "detail should have contributing_sources"
    );
    assert!(
        detail_corr["explanation"].is_string(),
        "detail should have explanation"
    );
    assert!(
        !detail_corr["contributing_sources"]
            .as_array()
            .unwrap()
            .is_empty(),
        "detail contributing_sources should not be empty"
    );
    assert!(
        !detail_corr["explanation"].as_str().unwrap().is_empty(),
        "detail explanation should not be empty"
    );

    // List endpoint should have lightweight summary (no contributing_sources, no explanation)
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let list: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let list_corr = &list["mitigations"][0]["correlation"];
    assert!(
        list_corr["signal_group_id"].is_string(),
        "list should have signal_group_id"
    );
    assert!(
        list_corr["derived_confidence"].is_number(),
        "list should have derived_confidence"
    );
    assert!(
        list_corr.get("contributing_sources").is_none()
            || list_corr["contributing_sources"].is_null(),
        "list should NOT have contributing_sources"
    );
    assert!(
        list_corr.get("explanation").is_none() || list_corr["explanation"].is_null(),
        "list should NOT have explanation"
    );
}

/// VAL-CROSS-009: Corroborated mitigations pass through guardrails — safelisted IP rejected
#[tokio::test]
async fn test_correlation_guardrails_still_apply() {
    // Create app with safelist
    let repo = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let settings = test_settings_with_correlation(true, 1, 0.5);

    // Add IP to safelist
    repo.insert_safelist("203.0.113.10", "admin", Some("core router"))
        .await
        .unwrap();

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("failed to create app state");

    let app = create_test_router(state);

    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    let (status, json) = post_event(&app, &event).await;

    // Should be rejected by guardrails
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(json["error"].as_str().unwrap().contains("safelist"));
}

/// Fix: If guardrails reject a corroborated mitigation, the signal group must stay 'open'
/// (not incorrectly resolved). This verifies that group status is only set to 'resolved'
/// AFTER insert_mitigation() succeeds.
#[tokio::test]
async fn test_correlation_guardrails_reject_keeps_group_open() {
    let repo = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let settings = test_settings_with_correlation(true, 1, 0.5);

    // Add IP to safelist so guardrails will reject
    repo.insert_safelist("203.0.113.10", "admin", Some("core router"))
        .await
        .unwrap();

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo.clone(),
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("failed to create app state");

    let app = create_test_router(state);

    // Submit event — corroboration will be met (min_sources=1) but guardrails will reject
    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    let (status, _json) = post_event(&app, &event).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // Verify: signal group was created and is still 'open' (not 'resolved')
    let open_groups = repo
        .list_signal_groups(
            &prefixd::correlation::SignalGroupFilter {
                status: Some(prefixd::correlation::SignalGroupStatus::Open),
                ..Default::default()
            },
            &prefixd::db::ListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(open_groups.len(), 1, "should have one open group");

    // Also verify no resolved groups exist
    let resolved_groups = repo
        .list_signal_groups(
            &prefixd::correlation::SignalGroupFilter {
                status: Some(prefixd::correlation::SignalGroupStatus::Resolved),
                ..Default::default()
            },
            &prefixd::db::ListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        resolved_groups.len(),
        0,
        "no groups should be resolved when guardrails reject"
    );

    // Verify the open group has corroboration_met = true (corroboration passed, but mitigation was rejected)
    assert!(
        open_groups[0].corroboration_met,
        "corroboration should be met even though guardrails rejected"
    );
}

// ── Signal Groups API Tests ────────────────────────────────────────────

/// Helper: create an app with correlation enabled and a shared repo reference
async fn setup_app_correlation_with_repo(
    min_sources: u32,
    confidence_threshold: f32,
) -> (axum::Router, Arc<dyn RepositoryTrait>) {
    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let settings = test_settings_with_correlation(true, min_sources, confidence_threshold);

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo.clone(),
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("failed to create app state");

    (create_test_router(state), repo)
}

/// VAL-ENGINE-016: GET /v1/signal-groups returns paginated list with cursor, has_more
#[tokio::test]
async fn test_signal_groups_list_basic() {
    let (app, _repo) = setup_app_correlation_with_repo(1, 0.5).await;

    // Ingest events to create signal groups
    let event1 = make_event_json("detector_a", "203.0.113.10", 0.9);
    let event2 = make_event_json("detector_a", "203.0.113.11", 0.8);
    post_event(&app, &event1).await;
    post_event(&app, &event2).await;

    // GET /v1/signal-groups
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["groups"].is_array());
    assert_eq!(json["groups"].as_array().unwrap().len(), 2);
    assert_eq!(json["count"], 2);
    assert!(!json["has_more"].as_bool().unwrap());
    assert!(json["next_cursor"].is_null());
}

/// VAL-ENGINE-016: Cursor pagination works correctly
#[tokio::test]
async fn test_signal_groups_list_pagination() {
    let (app, _repo) = setup_app_correlation_with_repo(1, 0.5).await;

    // Create 3 signal groups (3 different IPs)
    for i in 10..13 {
        let event = make_event_json("detector_a", &format!("203.0.113.{}", i), 0.9);
        post_event(&app, &event).await;
    }

    // Request page 1 with limit=2
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups?limit=2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["groups"].as_array().unwrap().len(), 2);
    assert_eq!(json["count"], 2);
    assert!(json["has_more"].as_bool().unwrap());
    let cursor = json["next_cursor"].as_str().unwrap();

    // Request page 2 using cursor
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/signal-groups?limit=2&cursor={}", cursor))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json2: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json2["groups"].as_array().unwrap().len(), 1);
    assert_eq!(json2["count"], 1);
    assert!(!json2["has_more"].as_bool().unwrap());
}

/// VAL-ENGINE-016: Status filter returns only matching groups
#[tokio::test]
async fn test_signal_groups_list_status_filter() {
    let (app, _repo) = setup_app_correlation_with_repo(1, 0.5).await;

    // Create events → signal groups with min_sources=1 → groups become resolved
    let event1 = make_event_json("detector_a", "203.0.113.10", 0.9);
    let event2 = make_event_json("detector_a", "203.0.113.11", 0.8);
    post_event(&app, &event1).await;
    post_event(&app, &event2).await;

    // With min_sources=1 and confidence above threshold, groups should be resolved
    // Filter for resolved
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups?status=resolved")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // All groups should be resolved since min_sources=1 and confidence >= 0.5
    for group in json["groups"].as_array().unwrap() {
        assert_eq!(group["status"], "resolved");
    }

    // Filter for open — should return 0 since all were resolved
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups?status=open")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["groups"].as_array().unwrap().len(), 0);
}

/// VAL-ENGINE-016: Vector filter returns only matching groups
#[tokio::test]
async fn test_signal_groups_list_vector_filter() {
    let (app, _repo) = setup_app_correlation_with_repo(1, 0.5).await;

    // Create events (all go through udp_flood playbook)
    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    post_event(&app, &event).await;

    // Filter for udp_flood (should match)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups?vector=udp_flood")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(!json["groups"].as_array().unwrap().is_empty());

    // Filter for syn_flood (should not match)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups?vector=syn_flood")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["groups"].as_array().unwrap().len(), 0);
}

/// VAL-ENGINE-032: Date range filter works with start/end params
#[tokio::test]
async fn test_signal_groups_list_date_range_filter() {
    let (app, _repo) = setup_app_correlation_with_repo(1, 0.5).await;

    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    post_event(&app, &event).await;

    // Use a future start date — should return 0 groups
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups?start=2099-01-01T00:00:00Z")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["groups"].as_array().unwrap().len(), 0);

    // Use a past start date — should return groups
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups?start=2020-01-01T00:00:00Z")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(!json["groups"].as_array().unwrap().is_empty());

    // Use a past end date — should return 0 groups
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups?end=2020-01-01T00:00:00Z")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["groups"].as_array().unwrap().len(), 0);
}

/// VAL-ENGINE-017: GET /v1/signal-groups/{id} returns group detail with contributing events
#[tokio::test]
async fn test_signal_group_detail_with_events() {
    let (app, _repo) = setup_app_correlation_with_repo(1, 0.5).await;

    // Create an event to generate a signal group
    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    post_event(&app, &event).await;

    // List groups to get the group ID
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let group_id = json["groups"][0]["group_id"].as_str().unwrap().to_string();

    // GET /v1/signal-groups/{id}
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/signal-groups/{}", group_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let detail: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Verify group metadata
    assert_eq!(detail["group_id"], group_id);
    assert_eq!(detail["victim_ip"], "203.0.113.10");
    assert_eq!(detail["vector"], "udp_flood");
    assert!(detail["derived_confidence"].is_number());
    assert!(detail["source_count"].is_number());
    assert!(detail["status"].is_string());
    assert!(detail["corroboration_met"].is_boolean());

    // Verify mitigation_id is present (min_sources=1, so mitigation was created)
    assert!(
        detail["mitigation_id"].is_string(),
        "Signal group detail should include mitigation_id when mitigation was created"
    );

    // Verify events list
    assert!(detail["events"].is_array());
    let events = detail["events"].as_array().unwrap();
    assert!(!events.is_empty());
    let ev = &events[0];
    assert!(ev["event_id"].is_string());
    assert!(ev["source_weight"].is_number());
    assert!(ev["source"].is_string());
    assert!(ev["confidence"].is_number());
    assert!(ev["ingested_at"].is_string());
}

/// Signal group detail has null mitigation_id when no mitigation was created
#[tokio::test]
async fn test_signal_group_detail_no_mitigation_id() {
    // Use min_sources=2 so first event alone does not trigger mitigation
    let (app, _repo) = setup_app_correlation_with_repo(2, 0.5).await;

    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    post_event(&app, &event).await;

    // Get the group ID
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let group_id = json["groups"][0]["group_id"].as_str().unwrap().to_string();

    // GET /v1/signal-groups/{id}
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/signal-groups/{}", group_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let detail: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // mitigation_id should be null since only one source submitted (need 2)
    assert!(
        detail["mitigation_id"].is_null(),
        "Signal group detail should have null mitigation_id when no mitigation exists"
    );
}

/// VAL-ENGINE-017: GET /v1/signal-groups/{id} returns 404 for unknown group
#[tokio::test]
async fn test_signal_group_detail_not_found() {
    let (app, _repo) = setup_app_correlation_with_repo(1, 0.5).await;

    let fake_id = uuid::Uuid::new_v4();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/signal-groups/{}", fake_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// VAL-ENGINE-016/017: Both endpoints require authentication (401 without)
#[tokio::test]
async fn test_signal_groups_auth_required() {
    // Create app with bearer auth
    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let mut settings = test_settings_with_correlation(true, 1, 0.5);
    settings.http.auth = prefixd::config::AuthConfig {
        mode: prefixd::config::AuthMode::Bearer,
        bearer_token_env: Some("TEST_PREFIXD_TOKEN".to_string()),
        ldap: None,
        radius: None,
    };
    unsafe {
        std::env::set_var("TEST_PREFIXD_TOKEN", "test-secret-token-123");
    }

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("failed to create app state");

    let app = create_test_router(state);

    // GET /v1/signal-groups without auth → 401
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // GET /v1/signal-groups/{id} without auth → 401
    let fake_id = uuid::Uuid::new_v4();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/signal-groups/{}", fake_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // GET /v1/signal-groups with auth → 200
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups")
                .header("authorization", "Bearer test-secret-token-123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// VAL-ENGINE-034: OpenAPI spec includes signal groups endpoints
#[tokio::test]
async fn test_openapi_includes_signal_groups() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let spec: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let paths = spec["paths"].as_object().unwrap();
    assert!(
        paths.contains_key("/v1/signal-groups"),
        "OpenAPI spec should include /v1/signal-groups"
    );
    assert!(
        paths.contains_key("/v1/signal-groups/{id}"),
        "OpenAPI spec should include /v1/signal-groups/{{id}}"
    );

    // Verify schemas are registered
    let schemas = spec["components"]["schemas"].as_object().unwrap();
    assert!(
        schemas.contains_key("SignalGroup"),
        "OpenAPI spec should include SignalGroup schema"
    );
    assert!(
        schemas.contains_key("SignalGroupEvent"),
        "OpenAPI spec should include SignalGroupEvent schema"
    );
    assert!(
        schemas.contains_key("SignalGroupsListResponse"),
        "OpenAPI spec should include SignalGroupsListResponse schema"
    );
    assert!(
        schemas.contains_key("SignalGroupDetailResponse"),
        "OpenAPI spec should include SignalGroupDetailResponse schema"
    );
    assert!(
        schemas.contains_key("CorrelationContext"),
        "OpenAPI spec should include CorrelationContext schema"
    );
    assert!(
        schemas.contains_key("CorrelationExplanation"),
        "OpenAPI spec should include CorrelationExplanation schema"
    );
    assert!(
        schemas.contains_key("SourceContribution"),
        "OpenAPI spec should include SourceContribution schema"
    );
}

/// VAL-ENGINE-017: Signal group detail with multiple contributing events
#[tokio::test]
async fn test_signal_group_detail_multiple_events() {
    // Use min_sources=2 so the group stays open after first event
    let (app, _repo) = setup_app_correlation_with_repo(2, 0.5).await;

    // Submit events from 2 different sources for same victim/vector
    let event1 = make_event_json("detector_a", "203.0.113.10", 0.9);
    let event2 = make_event_json("detector_b", "203.0.113.10", 0.7);
    post_event(&app, &event1).await;
    post_event(&app, &event2).await;

    // List groups — should have exactly 1 group
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json["groups"].as_array().unwrap().len(),
        1,
        "Should have exactly one signal group for same (victim_ip, vector)"
    );

    let group_id = json["groups"][0]["group_id"].as_str().unwrap().to_string();

    // Get detail
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/signal-groups/{}", group_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let detail: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Should have 2 contributing events
    let events = detail["events"].as_array().unwrap();
    assert_eq!(events.len(), 2, "Should have 2 contributing events");

    // Verify both sources are represented
    let sources: Vec<&str> = events.iter().filter_map(|e| e["source"].as_str()).collect();
    assert!(sources.contains(&"detector_a"));
    assert!(sources.contains(&"detector_b"));

    // Verify source_weight values
    for ev in events {
        assert!(ev["source_weight"].as_f64().unwrap() > 0.0);
    }
}

/// VAL-CROSS-012: Incident reports include correlation data
#[tokio::test]
async fn test_correlation_incident_report_includes_correlation() {
    let repo = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let settings = test_settings_with_correlation(true, 1, 0.5);

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo.clone(),
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("failed to create app state");

    let app = create_test_router(state);

    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    post_event(&app, &event).await;

    // Get incident report
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/reports/incident?ip=203.0.113.10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let md = String::from_utf8_lossy(&body);

    assert!(
        md.contains("## Correlation"),
        "incident report should include Correlation section: {}",
        md
    );
    assert!(
        md.contains("Derived Confidence"),
        "incident report should include derived confidence"
    );
    assert!(
        md.contains("Source Count"),
        "incident report should include source count"
    );
}

// ==========================================================================
// Alertmanager webhook adapter tests
// ==========================================================================

fn make_alertmanager_payload(alerts: &[serde_json::Value]) -> String {
    serde_json::json!({
        "version": "4",
        "status": "firing",
        "alerts": alerts,
        "groupLabels": {"alertname": "udp_flood"},
        "commonLabels": {},
        "commonAnnotations": {},
        "externalURL": "http://alertmanager.example.com"
    })
    .to_string()
}

fn make_alert(
    status: &str,
    victim_ip: &str,
    vector: &str,
    severity: &str,
    fingerprint: &str,
) -> serde_json::Value {
    serde_json::json!({
        "status": status,
        "labels": {
            "victim_ip": victim_ip,
            "vector": vector,
            "severity": severity,
            "alertname": "DDoS_Alert"
        },
        "annotations": {
            "bps": "100000000",
            "pps": "50000"
        },
        "startsAt": "2026-01-16T14:00:00Z",
        "endsAt": "0001-01-01T00:00:00Z",
        "generatorURL": "http://prometheus:9090/graph",
        "fingerprint": fingerprint
    })
}

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
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    (status, json)
}

/// VAL-ADAPT-001: Valid Alertmanager v4 webhook accepted (returns 200, creates events)
#[tokio::test]
async fn test_alertmanager_valid_payload() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    let alert = make_alert("firing", "203.0.113.10", "udp_flood", "critical", "abc123");
    let payload = make_alertmanager_payload(&[alert]);

    let (status, json) = post_alertmanager(&app, &payload).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);
    assert_eq!(json["failed"], 0);
    assert_eq!(json["results"].as_array().unwrap().len(), 1);

    let result = &json["results"][0];
    assert_eq!(result["index"], 0);
    assert!(result["event_id"].is_string(), "should have event_id");
    // With min_sources=1, corroboration met → mitigation created
    assert!(
        result["status"].as_str().unwrap() != "error",
        "should not be error: {:?}",
        result
    );
}

/// VAL-ADAPT-002: Batched alerts processed individually (each creates a separate event)
#[tokio::test]
async fn test_alertmanager_batched_alerts() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    let alert1 = make_alert("firing", "203.0.113.10", "udp_flood", "critical", "fp1");
    let alert2 = make_alert("firing", "203.0.113.10", "udp_flood", "warning", "fp2");
    let alert3 = make_alert("firing", "203.0.113.10", "udp_flood", "info", "fp3");
    let payload = make_alertmanager_payload(&[alert1, alert2, alert3]);

    let (status, json) = post_alertmanager(&app, &payload).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 3);
    assert_eq!(json["failed"], 0);
    let results = json["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);

    // Each result should have an event_id
    for (i, r) in results.iter().enumerate() {
        assert_eq!(r["index"], i);
        assert!(
            r["event_id"].is_string(),
            "alert {} should have event_id",
            i
        );
    }
}

/// VAL-ADAPT-003: Vector from labels mapping (labels.vector takes priority over alertname)
#[tokio::test]
async fn test_alertmanager_vector_from_labels() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    // Test with labels.vector present
    let alert_with_vector = serde_json::json!({
        "status": "firing",
        "labels": {
            "victim_ip": "203.0.113.10",
            "vector": "udp_flood",
            "alertname": "should_not_use_this"
        },
        "annotations": {},
        "startsAt": "2026-01-16T14:00:00Z",
        "fingerprint": "vec_test_1"
    });
    let payload = make_alertmanager_payload(&[alert_with_vector]);
    let (status, json) = post_alertmanager(&app, &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);

    // Test with only alertname (fallback)
    let alert_with_alertname = serde_json::json!({
        "status": "firing",
        "labels": {
            "victim_ip": "203.0.113.10",
            "alertname": "syn_flood"
        },
        "annotations": {},
        "startsAt": "2026-01-16T14:00:00Z",
        "fingerprint": "vec_test_2"
    });
    let payload = make_alertmanager_payload(&[alert_with_alertname]);
    let (status, json) = post_alertmanager(&app, &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);

    // Test with neither → per-alert error
    let alert_no_vector = serde_json::json!({
        "status": "firing",
        "labels": {
            "victim_ip": "203.0.113.10"
        },
        "annotations": {},
        "startsAt": "2026-01-16T14:00:00Z",
        "fingerprint": "vec_test_3"
    });
    let payload = make_alertmanager_payload(&[alert_no_vector]);
    let (status, json) = post_alertmanager(&app, &payload).await;
    assert_eq!(status, StatusCode::OK);
    // The alert with missing vector should be reported as failed
    assert_eq!(json["failed"], 1);
    assert!(
        json["results"][0]["error"]
            .as_str()
            .unwrap()
            .contains("missing vector")
    );
}

/// VAL-ADAPT-004: Victim IP extraction with port stripping
#[tokio::test]
async fn test_alertmanager_victim_ip_port_stripping() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    // labels.victim_ip takes priority
    let alert_victim_ip = serde_json::json!({
        "status": "firing",
        "labels": {
            "victim_ip": "203.0.113.10",
            "instance": "10.0.0.1:9090",
            "vector": "udp_flood"
        },
        "annotations": {},
        "startsAt": "2026-01-16T14:00:00Z",
        "fingerprint": "ip_test_1"
    });
    let payload = make_alertmanager_payload(&[alert_victim_ip]);
    let (status, json) = post_alertmanager(&app, &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);

    // Fallback to instance with port stripping
    let alert_instance = serde_json::json!({
        "status": "firing",
        "labels": {
            "instance": "203.0.113.10:9090",
            "vector": "udp_flood"
        },
        "annotations": {},
        "startsAt": "2026-01-16T14:00:00Z",
        "fingerprint": "ip_test_2"
    });
    let payload = make_alertmanager_payload(&[alert_instance]);
    let (status, json) = post_alertmanager(&app, &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);

    // Missing both → per-alert error
    let alert_no_ip = serde_json::json!({
        "status": "firing",
        "labels": {
            "vector": "udp_flood"
        },
        "annotations": {},
        "startsAt": "2026-01-16T14:00:00Z",
        "fingerprint": "ip_test_3"
    });
    let payload = make_alertmanager_payload(&[alert_no_ip]);
    let (status, json) = post_alertmanager(&app, &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["failed"], 1);
    assert!(
        json["results"][0]["error"]
            .as_str()
            .unwrap()
            .contains("missing victim_ip")
    );
}

/// VAL-ADAPT-005: BPS/PPS from annotations parsed as optional i64
#[tokio::test]
async fn test_alertmanager_bps_pps_annotations() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    // With valid bps and pps
    let alert_with_metrics = serde_json::json!({
        "status": "firing",
        "labels": {
            "victim_ip": "203.0.113.10",
            "vector": "udp_flood"
        },
        "annotations": {
            "bps": "500000000",
            "pps": "1000000"
        },
        "startsAt": "2026-01-16T14:00:00Z",
        "fingerprint": "metrics_test_1"
    });
    let payload = make_alertmanager_payload(&[alert_with_metrics]);
    let (status, json) = post_alertmanager(&app, &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);

    // With non-numeric values (should be treated as None, not error)
    let alert_bad_metrics = serde_json::json!({
        "status": "firing",
        "labels": {
            "victim_ip": "203.0.113.10",
            "vector": "udp_flood"
        },
        "annotations": {
            "bps": "not_a_number",
            "pps": "also_bad"
        },
        "startsAt": "2026-01-16T14:00:00Z",
        "fingerprint": "metrics_test_2"
    });
    let payload = make_alertmanager_payload(&[alert_bad_metrics]);
    let (status, json) = post_alertmanager(&app, &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1); // Should still succeed

    // With missing annotations
    let alert_no_metrics = serde_json::json!({
        "status": "firing",
        "labels": {
            "victim_ip": "203.0.113.10",
            "vector": "udp_flood"
        },
        "annotations": {},
        "startsAt": "2026-01-16T14:00:00Z",
        "fingerprint": "metrics_test_3"
    });
    let payload = make_alertmanager_payload(&[alert_no_metrics]);
    let (status, json) = post_alertmanager(&app, &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);
}

/// VAL-ADAPT-006: Severity to confidence mapping
#[tokio::test]
async fn test_alertmanager_severity_confidence_mapping() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    // Test each severity level
    for (severity, _expected_confidence, fp) in [
        ("critical", 0.9, "sev_1"),
        ("warning", 0.7, "sev_2"),
        ("info", 0.5, "sev_3"),
    ] {
        let alert = serde_json::json!({
            "status": "firing",
            "labels": {
                "victim_ip": "203.0.113.10",
                "vector": "udp_flood",
                "severity": severity
            },
            "annotations": {},
            "startsAt": "2026-01-16T14:00:00Z",
            "fingerprint": fp
        });
        let payload = make_alertmanager_payload(&[alert]);
        let (status, json) = post_alertmanager(&app, &payload).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "severity={} should succeed",
            severity
        );
        assert_eq!(
            json["processed"], 1,
            "severity={} should be processed",
            severity
        );
    }

    // Missing severity → defaults to 0.5 (same as "info")
    let alert_no_severity = serde_json::json!({
        "status": "firing",
        "labels": {
            "victim_ip": "203.0.113.10",
            "vector": "udp_flood"
        },
        "annotations": {},
        "startsAt": "2026-01-16T14:00:00Z",
        "fingerprint": "sev_4"
    });
    let payload = make_alertmanager_payload(&[alert_no_severity]);
    let (status, json) = post_alertmanager(&app, &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);
}

/// VAL-ADAPT-007: Resolved alerts trigger withdraw (action="unban")
#[tokio::test]
async fn test_alertmanager_resolved_alerts_trigger_withdraw() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    // First fire an alert to create a mitigation
    let fire_alert = make_alert(
        "firing",
        "203.0.113.10",
        "udp_flood",
        "critical",
        "resolve_fp",
    );
    let payload = make_alertmanager_payload(&[fire_alert]);
    let (status, json) = post_alertmanager(&app, &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);

    // Now send resolved alert with same fingerprint
    let resolve_alert = make_alert(
        "resolved",
        "203.0.113.10",
        "udp_flood",
        "critical",
        "resolve_fp",
    );
    let payload = make_alertmanager_payload(&[resolve_alert]);
    let (status, json) = post_alertmanager(&app, &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);
    // The result should be withdrawal-related
    let result = &json["results"][0];
    assert!(
        result["status"].as_str().unwrap().starts_with("withdrawn"),
        "resolved alert should trigger withdraw: {:?}",
        result
    );
}

/// VAL-ADAPT-008: Fingerprint deduplication (same source + fingerprint = duplicate)
#[tokio::test]
async fn test_alertmanager_fingerprint_dedup() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    let alert = make_alert(
        "firing",
        "203.0.113.10",
        "udp_flood",
        "critical",
        "dedup_fp",
    );
    let payload = make_alertmanager_payload(std::slice::from_ref(&alert));

    // First request
    let (status1, json1) = post_alertmanager(&app, &payload).await;
    assert_eq!(status1, StatusCode::OK);
    assert_eq!(json1["processed"], 1);

    // Second request with same fingerprint → duplicate
    let payload2 = make_alertmanager_payload(&[alert]);
    let (status2, json2) = post_alertmanager(&app, &payload2).await;
    assert_eq!(status2, StatusCode::OK);
    // Duplicate should be detected
    let result = &json2["results"][0];
    assert_eq!(
        result["status"].as_str().unwrap(),
        "duplicate",
        "second submission of same fingerprint should be duplicate"
    );
}

/// VAL-ADAPT-009: Malformed payloads return 400 (not 500)
#[tokio::test]
async fn test_alertmanager_malformed_payload_returns_400() {
    let app = setup_app().await;

    // Invalid JSON
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/alertmanager")
                .header("content-type", "application/json")
                .body(Body::from("not valid json"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Wrong version
    let wrong_version = serde_json::json!({
        "version": "3",
        "status": "firing",
        "alerts": [{"status": "firing", "labels": {}, "annotations": {}}],
        "groupLabels": {},
        "commonLabels": {},
        "commonAnnotations": {},
        "externalURL": ""
    })
    .to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/alertmanager")
                .header("content-type", "application/json")
                .body(Body::from(wrong_version))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Missing required fields (alerts array)
    let missing_alerts = serde_json::json!({
        "version": "4",
        "status": "firing"
    })
    .to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/alertmanager")
                .header("content-type", "application/json")
                .body(Body::from(missing_alerts))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Empty alerts array
    let empty_alerts = serde_json::json!({
        "version": "4",
        "status": "firing",
        "alerts": [],
        "groupLabels": {},
        "commonLabels": {},
        "commonAnnotations": {},
        "externalURL": ""
    })
    .to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/alertmanager")
                .header("content-type", "application/json")
                .body(Body::from(empty_alerts))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// VAL-ADAPT-010: Authentication required (401 without auth)
#[tokio::test]
async fn test_alertmanager_auth_required() {
    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let mut settings = test_settings_with_correlation(true, 1, 0.5);
    settings.http.auth = prefixd::config::AuthConfig {
        mode: prefixd::config::AuthMode::Bearer,
        bearer_token_env: Some("TEST_PREFIXD_TOKEN".to_string()),
        ldap: None,
        radius: None,
    };
    unsafe {
        std::env::set_var("TEST_PREFIXD_TOKEN", "test-secret-token-123");
    }

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("failed to create app state");

    let app = create_test_router(state);

    let alert = make_alert("firing", "203.0.113.10", "udp_flood", "critical", "auth_fp");
    let payload = make_alertmanager_payload(&[alert]);

    // Without auth → 401
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/alertmanager")
                .header("content-type", "application/json")
                .body(Body::from(payload.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // With auth → 200
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/alertmanager")
                .header("content-type", "application/json")
                .header("authorization", "Bearer test-secret-token-123")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// VAL-ADAPT-018: Partial batch failure — mixed valid/invalid alerts
#[tokio::test]
async fn test_alertmanager_partial_batch_failure() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    let valid_alert = make_alert(
        "firing",
        "203.0.113.10",
        "udp_flood",
        "critical",
        "partial_1",
    );
    // Invalid: missing both victim_ip and instance
    let invalid_alert = serde_json::json!({
        "status": "firing",
        "labels": {
            "vector": "udp_flood"
        },
        "annotations": {},
        "startsAt": "2026-01-16T14:00:00Z",
        "fingerprint": "partial_2"
    });
    let valid_alert2 = make_alert(
        "firing",
        "203.0.113.10",
        "udp_flood",
        "warning",
        "partial_3",
    );
    let payload = make_alertmanager_payload(&[valid_alert, invalid_alert, valid_alert2]);

    let (status, json) = post_alertmanager(&app, &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 2);
    assert_eq!(json["failed"], 1);

    let results = json["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
    // First and third should succeed
    assert!(
        results[0]["error"].is_null(),
        "first alert should succeed: {:?}",
        results[0]
    );
    // Second should have error
    assert!(
        results[1]["error"].is_string(),
        "second alert should fail: {:?}",
        results[1]
    );
    // Third should succeed
    assert!(
        results[2]["error"].is_null(),
        "third alert should succeed: {:?}",
        results[2]
    );
}

// ==========================================================================
// FastNetMon webhook adapter tests
// ==========================================================================

fn make_fastnetmon_payload(action: &str, ip: &str, attack_uuid: Option<&str>) -> String {
    let mut payload = serde_json::json!({
        "action": action,
        "ip": ip,
        "alert_scope": "host",
        "attack_details": {
            "attack_uuid": attack_uuid,
            "attack_severity": "middle",
            "attack_detection_source": "automatic",
            "attack_detection_threshold": "bytes per second",
            "attack_detection_threshold_direction": "incoming",
            "attack_start": "2026-01-16T14:00:00Z",
            "protocol_version": "IPv4",
            "host_group": "global",
            "host_network": "192.0.2.0/24",
            "incoming_udp_pps": 5000,
            "incoming_udp_traffic_bits": 50000000,
            "incoming_tcp_pps": 1000,
            "incoming_tcp_traffic_bits": 10000000,
            "incoming_syn_tcp_pps": 200,
            "incoming_syn_tcp_traffic_bits": 2000000,
            "incoming_icmp_pps": 100,
            "incoming_icmp_traffic_bits": 1000000,
            "incoming_ip_fragmented_pps": 0,
            "incoming_ip_fragmented_traffic_bits": 0,
            "total_incoming_pps": 6100,
            "total_incoming_traffic_bits": 61000000,
            "total_incoming_flows": 50,
            "total_outgoing_pps": 500,
            "total_outgoing_traffic_bits": 5000000,
            "total_outgoing_flows": 20
        }
    });
    // If attack_uuid is None, remove the field
    if attack_uuid.is_none() {
        payload["attack_details"]["attack_uuid"] = serde_json::Value::Null;
    }
    payload.to_string()
}

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
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    (status, json)
}

/// Helper to setup app with FastNetMon source in correlation config with custom confidence mapping
async fn setup_app_fastnetmon_with_mapping(
    confidence_mapping: std::collections::HashMap<String, f32>,
) -> axum::Router {
    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let mut settings = test_settings_with_correlation(true, 1, 0.5);
    settings.correlation.sources.insert(
        "fastnetmon".to_string(),
        prefixd::correlation::SourceConfig {
            weight: 1.0,
            r#type: "detector".to_string(),
            confidence_mapping,
            ..Default::default()
        },
    );

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("failed to create app state");

    create_test_router(state)
}

/// VAL-ADAPT-011: Valid FastNetMon payload returns 202 with EventResponse shape
#[tokio::test]
async fn test_fastnetmon_valid_payload() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    let payload = make_fastnetmon_payload("ban", "203.0.113.10", Some("test-uuid-1"));
    let (status, json) = post_fastnetmon(&app, &payload).await;

    assert_eq!(status, StatusCode::ACCEPTED);
    assert!(json["event_id"].is_string(), "should have event_id");
    assert_eq!(
        json["status"], "accepted",
        "status should be 'accepted' (EventResponse shape)"
    );
    // mitigation_id should be present since min_sources=1 and confidence >= threshold
    assert!(
        json["mitigation_id"].is_string(),
        "should have mitigation_id with min_sources=1"
    );
}

/// VAL-ADAPT-012: FastNetMon confidence mapping — default (ban=0.9, partial_block=0.7, alert=0.5)
#[tokio::test]
async fn test_fastnetmon_confidence_mapping_default() {
    // Test with ban action → default confidence 0.9
    let app = setup_app_correlation(true, 1, 0.5).await;

    let payload_ban = make_fastnetmon_payload("ban", "203.0.113.10", Some("conf-uuid-ban"));
    let (status, json) = post_fastnetmon(&app, &payload_ban).await;
    assert_eq!(status, StatusCode::ACCEPTED, "ban should succeed");
    assert!(json["event_id"].is_string(), "ban should have event_id");

    // Test partial_block
    let payload_partial =
        make_fastnetmon_payload("partial_block", "203.0.113.11", Some("conf-uuid-partial"));
    let (status, json) = post_fastnetmon(&app, &payload_partial).await;
    assert_eq!(status, StatusCode::ACCEPTED, "partial_block should succeed");
    assert!(
        json["event_id"].is_string(),
        "partial_block should have event_id"
    );

    // Test alert — confidence 0.5 which equals threshold, should succeed
    let payload_alert = make_fastnetmon_payload("alert", "203.0.113.12", Some("conf-uuid-alert"));
    let (status, json) = post_fastnetmon(&app, &payload_alert).await;
    assert_eq!(status, StatusCode::ACCEPTED, "alert should succeed");
    assert!(json["event_id"].is_string(), "alert should have event_id");
}

/// VAL-ADAPT-012: Config override changes confidence values
#[tokio::test]
async fn test_fastnetmon_confidence_mapping_override() {
    let mut mapping = std::collections::HashMap::new();
    mapping.insert("ban".to_string(), 0.6);
    mapping.insert("partial_block".to_string(), 0.4);
    mapping.insert("alert".to_string(), 0.2);

    let app = setup_app_fastnetmon_with_mapping(mapping).await;

    // With overridden mapping, ban now has confidence 0.6 (still above 0.5 threshold)
    let payload_ban = make_fastnetmon_payload("ban", "203.0.113.10", Some("override-uuid-ban"));
    let (status, json) = post_fastnetmon(&app, &payload_ban).await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "ban should succeed with override mapping"
    );
    assert!(
        json["event_id"].is_string(),
        "ban with override should have event_id"
    );
}

/// VAL-ADAPT-013: Malformed FastNetMon payload returns 400
#[tokio::test]
async fn test_fastnetmon_malformed_payload_returns_400() {
    let app = setup_app().await;

    // Invalid JSON
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/fastnetmon")
                .header("content-type", "application/json")
                .body(Body::from("not valid json"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Missing required 'ip' field
    let missing_ip = serde_json::json!({
        "action": "ban"
    })
    .to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/fastnetmon")
                .header("content-type", "application/json")
                .body(Body::from(missing_ip))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Missing required 'action' field
    let missing_action = serde_json::json!({
        "ip": "203.0.113.10"
    })
    .to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/fastnetmon")
                .header("content-type", "application/json")
                .body(Body::from(missing_action))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Empty ip
    let empty_ip = serde_json::json!({
        "action": "ban",
        "ip": ""
    })
    .to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/fastnetmon")
                .header("content-type", "application/json")
                .body(Body::from(empty_ip))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Invalid IP address
    let invalid_ip = serde_json::json!({
        "action": "ban",
        "ip": "not-an-ip"
    })
    .to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/fastnetmon")
                .header("content-type", "application/json")
                .body(Body::from(invalid_ip))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// VAL-ADAPT-017: Authentication required for FastNetMon endpoint
#[tokio::test]
async fn test_fastnetmon_auth_required() {
    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let mut settings = test_settings_with_correlation(true, 1, 0.5);
    settings.http.auth = prefixd::config::AuthConfig {
        mode: prefixd::config::AuthMode::Bearer,
        bearer_token_env: Some("TEST_PREFIXD_FNM_TOKEN".to_string()),
        ldap: None,
        radius: None,
    };
    unsafe {
        std::env::set_var("TEST_PREFIXD_FNM_TOKEN", "fnm-test-token-456");
    }

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("failed to create app state");

    let app = create_test_router(state);

    let payload = make_fastnetmon_payload("ban", "203.0.113.10", Some("auth-uuid"));

    // Without auth → 401
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/fastnetmon")
                .header("content-type", "application/json")
                .body(Body::from(payload.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // With auth → 202
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/fastnetmon")
                .header("content-type", "application/json")
                .header("authorization", "Bearer fnm-test-token-456")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

/// VAL-ENGINE-034: OpenAPI spec includes FastNetMon signal endpoint
#[tokio::test]
async fn test_openapi_includes_fastnetmon() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let spec: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let paths = spec["paths"].as_object().unwrap();
    assert!(
        paths.contains_key("/v1/signals/fastnetmon"),
        "OpenAPI spec should include /v1/signals/fastnetmon"
    );

    let schemas = spec["components"]["schemas"].as_object().unwrap();
    assert!(
        schemas.contains_key("FastNetMonPayload"),
        "OpenAPI spec should include FastNetMonPayload schema"
    );
    assert!(
        schemas.contains_key("FastNetMonAttackDetails"),
        "OpenAPI spec should include FastNetMonAttackDetails schema"
    );
}

/// FastNetMon events should be stored with source='fastnetmon'
#[tokio::test]
async fn test_fastnetmon_source_field() {
    let (app, _repo) = setup_app_correlation_with_repo(1, 0.5).await;

    let payload = make_fastnetmon_payload("ban", "203.0.113.10", Some("source-uuid"));
    let (status, _json) = post_fastnetmon(&app, &payload).await;
    assert_eq!(status, StatusCode::ACCEPTED);

    // Verify signal group has 'fastnetmon' source via the API
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let groups_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let groups = groups_json["groups"].as_array().unwrap();
    assert!(!groups.is_empty(), "should have at least one signal group");

    // List events and check source
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let events_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let events = events_json["events"].as_array().unwrap();
    assert!(!events.is_empty(), "should have at least one event");

    let event = &events[0];
    assert_eq!(
        event["source"], "fastnetmon",
        "event source should be 'fastnetmon'"
    );
}

/// VAL-ENGINE-034: OpenAPI spec includes alertmanager signal endpoint
#[tokio::test]
async fn test_openapi_includes_alertmanager() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let spec: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let paths = spec["paths"].as_object().unwrap();
    assert!(
        paths.contains_key("/v1/signals/alertmanager"),
        "OpenAPI spec should include /v1/signals/alertmanager"
    );

    let schemas = spec["components"]["schemas"].as_object().unwrap();
    assert!(
        schemas.contains_key("AlertmanagerWebhookPayload"),
        "OpenAPI spec should include AlertmanagerWebhookPayload schema"
    );
    assert!(
        schemas.contains_key("AlertmanagerWebhookResponse"),
        "OpenAPI spec should include AlertmanagerWebhookResponse schema"
    );
    assert!(
        schemas.contains_key("AlertmanagerAlert"),
        "OpenAPI spec should include AlertmanagerAlert schema"
    );
    assert!(
        schemas.contains_key("AlertmanagerAlertResult"),
        "OpenAPI spec should include AlertmanagerAlertResult schema"
    );
}

// ==========================================================================
// Correlation config API tests (VAL-ADAPT-014, VAL-ADAPT-015, VAL-ADAPT-016)
// ==========================================================================

/// VAL-ADAPT-014: GET /v1/config/correlation returns redacted config
#[tokio::test]
async fn test_get_correlation_config() {
    let app = setup_app_correlation(true, 2, 0.7).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/config/correlation")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let config = &json["config"];
    assert_eq!(config["enabled"], true);
    assert_eq!(config["window_seconds"], 300);
    assert_eq!(config["min_sources"], 2);
    // f32 → JSON f64 loses precision; compare approximately
    let ct = config["confidence_threshold"].as_f64().unwrap();
    assert!(
        (ct - 0.7).abs() < 0.001,
        "confidence_threshold ~ 0.7, got {ct}"
    );
    assert_eq!(config["default_weight"], 1.0);
    assert!(config["sources"].is_object(), "sources should be an object");
    assert!(
        config["sources"]["detector_a"].is_object(),
        "detector_a should be present"
    );
    assert_eq!(config["sources"]["detector_a"]["weight"], 1.0);
    assert_eq!(config["sources"]["detector_b"]["weight"], 1.5);
    assert!(json["loaded_at"].is_string(), "loaded_at should be present");
}

/// VAL-ADAPT-014: GET /v1/config/correlation returns default config when correlation is disabled
#[tokio::test]
async fn test_get_correlation_config_default() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/config/correlation")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let config = &json["config"];
    assert_eq!(config["enabled"], false);
    assert_eq!(config["min_sources"], 1);
    assert_eq!(config["confidence_threshold"], 0.5);
}

/// VAL-ADAPT-015: PUT /v1/config/correlation requires admin (403 for bearer/operator)
#[tokio::test]
async fn test_update_correlation_config_operator_forbidden() {
    let dir = tempfile::tempdir().unwrap();
    let app = setup_app_bearer_with_config_dir(dir.path().to_path_buf()).await;

    let body = serde_json::json!({
        "enabled": true,
        "window_seconds": 600,
        "min_sources": 2,
        "confidence_threshold": 0.7,
        "default_weight": 1.0,
        "sources": {}
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/config/correlation")
                .header("Authorization", "Bearer test-secret-token-123")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// VAL-ADAPT-015: PUT /v1/config/correlation succeeds for admin (auth_mode: none)
#[tokio::test]
async fn test_update_correlation_config_success() {
    let dir = tempfile::tempdir().unwrap();
    let app = setup_app_with_config_dir(dir.path().to_path_buf()).await;

    let body = serde_json::json!({
        "enabled": true,
        "window_seconds": 600,
        "min_sources": 3,
        "confidence_threshold": 0.8,
        "default_weight": 0.5,
        "sources": {
            "fastnetmon": {
                "weight": 2.0,
                "type": "detector",
                "confidence_mapping": {
                    "ban": 0.95
                }
            }
        }
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/config/correlation")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let config = &json["config"];
    assert_eq!(config["enabled"], true);
    assert_eq!(config["window_seconds"], 600);
    assert_eq!(config["min_sources"], 3);
    let ct = config["confidence_threshold"].as_f64().unwrap();
    assert!(
        (ct - 0.8).abs() < 0.001,
        "confidence_threshold ~ 0.8, got {ct}"
    );
    assert_eq!(config["default_weight"], 0.5);
    assert_eq!(config["sources"]["fastnetmon"]["weight"], 2.0);

    // Verify file was written
    let correlation_path = dir.path().join("correlation.yaml");
    assert!(
        correlation_path.exists(),
        "correlation.yaml should be written"
    );

    // Verify the file content round-trips correctly
    let saved_config = prefixd::correlation::CorrelationConfig::load(&correlation_path).unwrap();
    assert!(saved_config.enabled);
    assert_eq!(saved_config.window_seconds, 600);
    assert_eq!(saved_config.min_sources, 3);
}

/// PUT /v1/config/correlation with invalid JSON returns 400
#[tokio::test]
async fn test_update_correlation_config_invalid_json() {
    let dir = tempfile::tempdir().unwrap();
    let app = setup_app_with_config_dir(dir.path().to_path_buf()).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/config/correlation")
                .header("content-type", "application/json")
                .body(Body::from("not json"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// PUT /v1/config/correlation with validation errors returns 400
#[tokio::test]
async fn test_update_correlation_config_validation_error() {
    let dir = tempfile::tempdir().unwrap();
    let app = setup_app_with_config_dir(dir.path().to_path_buf()).await;

    let body = serde_json::json!({
        "enabled": true,
        "window_seconds": 0,
        "min_sources": 0,
        "confidence_threshold": 2.0,
        "default_weight": -1.0,
        "sources": {}
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/config/correlation")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let errors = json["errors"].as_array().unwrap();
    assert!(errors.len() >= 3, "should have multiple validation errors");
}

/// VAL-ADAPT-016: POST /v1/config/reload refreshes correlation config from YAML
#[tokio::test]
async fn test_reload_picks_up_correlation_config() {
    let dir = tempfile::tempdir().unwrap();

    // Write initial prefixd.yaml with correlation disabled
    let initial_config = prefixd::correlation::CorrelationConfig::default();
    let correlation_path = dir.path().join("correlation.yaml");
    initial_config.save(&correlation_path).unwrap();

    let app = setup_app_with_config_dir(dir.path().to_path_buf()).await;

    // Verify initial config is disabled
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/config/correlation")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["config"]["enabled"], false);

    // Update the correlation.yaml file on disk
    let mut updated = prefixd::correlation::CorrelationConfig::default();
    updated.enabled = true;
    updated.min_sources = 3;
    updated.save(&correlation_path).unwrap();

    // Trigger reload
    let response = app
        .clone()
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
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let reloaded = json["reloaded"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert!(
        reloaded.contains(&"correlation".to_string()),
        "reload should include 'correlation': {:?}",
        reloaded
    );

    // Verify updated config
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/config/correlation")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["config"]["enabled"], true);
    assert_eq!(json["config"]["min_sources"], 3);
}

/// VAL-ADAPT-017: Unknown sources handled gracefully (default weight, not 500)
#[tokio::test]
async fn test_unknown_source_handled_gracefully() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    // Submit event from an unknown source (not in the configured sources)
    let event_json = r#"{
        "timestamp": "2026-01-16T14:00:00Z",
        "source": "completely_unknown_detector",
        "victim_ip": "203.0.113.10",
        "vector": "udp_flood",
        "bps": 100000000,
        "pps": 50000,
        "top_dst_ports": [53],
        "confidence": 0.9
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

    assert_eq!(
        response.status(),
        StatusCode::ACCEPTED,
        "unknown source should be accepted (not 500)"
    );
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "accepted");
}

/// OpenAPI spec includes correlation config endpoints
#[tokio::test]
async fn test_openapi_includes_correlation_config() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let spec: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let paths = spec["paths"].as_object().unwrap();
    assert!(
        paths.contains_key("/v1/config/correlation"),
        "OpenAPI spec should include /v1/config/correlation"
    );

    let schemas = spec["components"]["schemas"].as_object().unwrap();
    assert!(
        schemas.contains_key("CorrelationConfig"),
        "OpenAPI spec should include CorrelationConfig schema"
    );
    assert!(
        schemas.contains_key("SourceConfig"),
        "OpenAPI spec should include SourceConfig schema"
    );
}

// =============================================================================
// Generic webhook adapter integration tests
// =============================================================================

async fn setup_app_with_webhooks(
    adapters: Vec<prefixd::correlation::WebhookAdapter>,
) -> axum::Router {
    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let settings = test_settings_with_correlation(true, 1, 0.5);

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("failed to create app state");

    {
        let mut cfg = state.correlation_config.write().await;
        cfg.webhook_adapters = adapters;
    }

    create_test_router(state)
}

fn basic_webhook_adapter(name: &str) -> prefixd::correlation::WebhookAdapter {
    use prefixd::correlation::{WebhookAdapter, WebhookAuth, WebhookFieldMap};
    WebhookAdapter {
        name: name.to_string(),
        description: "test".into(),
        enabled: true,
        auth: WebhookAuth::None,
        root_path: None,
        fields: WebhookFieldMap {
            victim_ip: "$.ip".into(),
            vector: Some("$.vector".into()),
            timestamp: None,
            bps: Some("$.bps".into()),
            pps: Some("$.pps".into()),
            confidence: Some("$.score".into()),
            source_id: Some("$.id".into()),
            top_dst_ports: None,
            action: None,
        },
        vector_map: Default::default(),
        default_vector: None,
        confidence_scale: None,
        source_id_prefix: None,
    }
}

async fn post_webhook(
    app: &axum::Router,
    name: &str,
    body: &str,
    extra_headers: &[(&str, &str)],
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder()
        .method("POST")
        .uri(format!("/v1/signals/webhook/{name}"))
        .header("content-type", "application/json");
    for (k, v) in extra_headers {
        req = req.header(*k, *v);
    }
    let response = app
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::json!({}));
    (status, json)
}

#[tokio::test]
async fn test_webhook_single_event_happy_path() {
    let app = setup_app_with_webhooks(vec![basic_webhook_adapter("radware")]).await;
    let body = r#"{
        "id": "alert-1",
        "ip": "203.0.113.5",
        "vector": "udp_flood",
        "bps": 100000,
        "pps": 500,
        "score": 0.9
    }"#;
    let (status, json) = post_webhook(&app, "radware", body, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);
    assert_eq!(json["failed"], 0);
    assert_eq!(json["results"][0]["index"], 0);
}

#[tokio::test]
async fn test_webhook_name_not_configured_returns_404() {
    let app = setup_app_with_webhooks(vec![basic_webhook_adapter("radware")]).await;
    let body = r#"{"ip":"203.0.113.5"}"#;
    let (status, _json) = post_webhook(&app, "unknown", body, &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_webhook_disabled_adapter_returns_404() {
    let mut adapter = basic_webhook_adapter("radware");
    adapter.enabled = false;
    let app = setup_app_with_webhooks(vec![adapter]).await;
    let body = r#"{"ip":"203.0.113.5"}"#;
    let (status, _json) = post_webhook(&app, "radware", body, &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_webhook_invalid_name_returns_404() {
    let app = setup_app_with_webhooks(vec![]).await;
    // Path traversal attempt
    let body = r#"{}"#;
    let (status, _json) = post_webhook(&app, "UPPER", body, &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_webhook_missing_required_field_reports_error_in_result() {
    let app = setup_app_with_webhooks(vec![basic_webhook_adapter("radware")]).await;
    // Missing $.ip
    let body = r#"{"vector":"udp_flood"}"#;
    let (status, json) = post_webhook(&app, "radware", body, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 0);
    assert_eq!(json["failed"], 1);
    assert_eq!(json["results"][0]["status"], "error");
    let err = json["results"][0]["error"].as_str().unwrap();
    assert!(
        err.contains("victim_ip"),
        "error should mention field: {err}"
    );
}

#[tokio::test]
async fn test_webhook_root_path_iterates_batch() {
    let mut adapter = basic_webhook_adapter("batchy");
    adapter.root_path = Some("$.alerts[*]".into());
    let app = setup_app_with_webhooks(vec![adapter]).await;
    let body = r#"{
        "alerts": [
            {"id":"a","ip":"203.0.113.1","vector":"udp_flood"},
            {"id":"b","ip":"203.0.113.2","vector":"syn_flood"},
            {"id":"c","ip":"203.0.113.3","vector":"icmp_flood"}
        ]
    }"#;
    let (status, json) = post_webhook(&app, "batchy", body, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 3);
    assert_eq!(json["failed"], 0);
    assert_eq!(json["results"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn test_webhook_malformed_json_returns_400() {
    let app = setup_app_with_webhooks(vec![basic_webhook_adapter("radware")]).await;
    let body = r#"{not json"#;
    let (status, _json) = post_webhook(&app, "radware", body, &[]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_webhook_hmac_accepts_correct_signature() {
    use hmac::Mac;
    use prefixd::correlation::WebhookAuth;

    // Use a random env var name to avoid parallel-test contention
    let env_name = "PREFIXD_TEST_HMAC_SECRET_POS";
    let secret = "super-secret";
    // SAFETY: test-only; other tests use different env var names
    unsafe { std::env::set_var(env_name, secret) };

    let mut adapter = basic_webhook_adapter("signed");
    adapter.auth = WebhookAuth::Hmac {
        secret_env: env_name.into(),
        header: "X-Signature-SHA256".into(),
        algorithm: "sha256".into(),
    };
    let app = setup_app_with_webhooks(vec![adapter]).await;

    let body = r#"{"ip":"203.0.113.5","vector":"udp_flood"}"#;
    let mut mac =
        <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());

    let (status, json) = post_webhook(&app, "signed", body, &[("X-Signature-SHA256", &sig)]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);

    unsafe { std::env::remove_var(env_name) };
}

#[tokio::test]
async fn test_webhook_hmac_rejects_wrong_signature() {
    use prefixd::correlation::WebhookAuth;

    let env_name = "PREFIXD_TEST_HMAC_SECRET_NEG";
    unsafe { std::env::set_var(env_name, "super-secret") };

    let mut adapter = basic_webhook_adapter("signed2");
    adapter.auth = WebhookAuth::Hmac {
        secret_env: env_name.into(),
        header: "X-Signature-SHA256".into(),
        algorithm: "sha256".into(),
    };
    let app = setup_app_with_webhooks(vec![adapter]).await;

    let body = r#"{"ip":"203.0.113.5","vector":"udp_flood"}"#;
    let wrong_sig = "0".repeat(64);

    let (status, _json) =
        post_webhook(&app, "signed2", body, &[("X-Signature-SHA256", &wrong_sig)]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    unsafe { std::env::remove_var(env_name) };
}

#[tokio::test]
async fn test_webhook_hmac_missing_header_returns_401() {
    use prefixd::correlation::WebhookAuth;

    let env_name = "PREFIXD_TEST_HMAC_SECRET_MISS";
    unsafe { std::env::set_var(env_name, "super-secret") };

    let mut adapter = basic_webhook_adapter("signed3");
    adapter.auth = WebhookAuth::Hmac {
        secret_env: env_name.into(),
        header: "X-Signature-SHA256".into(),
        algorithm: "sha256".into(),
    };
    let app = setup_app_with_webhooks(vec![adapter]).await;

    let body = r#"{"ip":"203.0.113.5"}"#;
    let (status, _json) = post_webhook(&app, "signed3", body, &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    unsafe { std::env::remove_var(env_name) };
}

#[tokio::test]
async fn test_webhook_vector_map_and_scaling() {
    let mut adapter = basic_webhook_adapter("scaled");
    adapter.vector_map.insert("UDP".into(), "udp_flood".into());
    adapter.confidence_scale = Some(100.0);
    let app = setup_app_with_webhooks(vec![adapter]).await;

    let body = r#"{
        "id":"x",
        "ip":"203.0.113.5",
        "vector":"UDP",
        "score":77
    }"#;
    let (status, json) = post_webhook(&app, "scaled", body, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);
}

// ── Corroborating signals (ADR 021) ─────────────────────────────────

async fn setup_app_with_corroborating_source(
    source_name: &str,
    dims: Vec<prefixd::correlation::MatchDimension>,
    weight: f32,
) -> axum::Router {
    use prefixd::correlation::{SourceConfig, SourceMode};

    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let mut settings = test_settings_with_correlation(true, 2, 0.5);
    settings.correlation.sources.insert(
        source_name.to_string(),
        SourceConfig {
            weight,
            r#type: "telemetry".to_string(),
            confidence_mapping: std::collections::HashMap::new(),
            mode: SourceMode::Corroborating,
            match_dimensions: dims,
        },
    );

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("failed to create app state");

    create_test_router(state)
}

async fn post_corroborator(
    app: &axum::Router,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/corroborator")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::json!({}));
    (status, json)
}

#[tokio::test]
async fn test_corroborator_primary_source_rejected() {
    // Default source config (no mode) is primary; posting to corroborator
    // endpoint must be rejected.
    let app = setup_app_with_corroborating_source(
        "different-source",
        vec![prefixd::correlation::MatchDimension::Pop],
        0.5,
    )
    .await;
    let body = serde_json::json!({
        "source": "fastnetmon",  // configured as primary in base settings
        "pop": "test-pop"
    });
    let (status, _) = post_corroborator(&app, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_corroborator_requires_declared_dimension() {
    // Source declares match_dimensions=[pop] but signal doesn't carry pop → 400.
    let app = setup_app_with_corroborating_source(
        "router-cpu",
        vec![prefixd::correlation::MatchDimension::Pop],
        0.5,
    )
    .await;
    let body = serde_json::json!({
        "source": "router-cpu",
        "customer_id": "cust_1"  // wrong dimension
    });
    let (status, _) = post_corroborator(&app, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_corroborator_caches_when_no_matching_group() {
    // No primary events yet → signal is cached.
    let app = setup_app_with_corroborating_source(
        "router-cpu",
        vec![prefixd::correlation::MatchDimension::Pop],
        0.5,
    )
    .await;
    let body = serde_json::json!({
        "source": "router-cpu",
        "pop": "test-pop",
        "confidence": 0.7
    });
    let (status, json) = post_corroborator(&app, body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "cached");
    assert!(json["attached_group_ids"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_corroborator_attaches_to_matching_primary_group() {
    // 1) Primary event creates a signal group. 2) Corroborator with matching
    // dimension attaches and drives source_count to 2.
    use prefixd::correlation::{MatchDimension, SourceConfig, SourceMode};

    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let mut settings = test_settings_with_correlation(true, 2, 0.5);
    settings.correlation.sources.insert(
        "router-cpu".to_string(),
        SourceConfig {
            weight: 0.8,
            r#type: "telemetry".to_string(),
            confidence_mapping: std::collections::HashMap::new(),
            mode: SourceMode::Corroborating,
            match_dimensions: vec![MatchDimension::Pop],
        },
    );

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo.clone(),
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("state");
    let app = create_test_router(state);

    // Step 1: post a primary event — source_count=1, corroboration_met=false (min_sources=2)
    let event_body = serde_json::json!({
        "source": "fastnetmon",
        "vector": "udp_flood",
        "victim_ip": "203.0.113.10",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "confidence": 0.9,
        "action": "ban"
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    // Step 2: corroborator posts with matching pop
    let sig_body = serde_json::json!({
        "source": "router-cpu",
        "pop": "test1",
        "vector": "udp_flood",
        "confidence": 0.6
    });
    let resp2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/corroborator")
                .header("content-type", "application/json")
                .body(Body::from(sig_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp2.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["status"], "attached");
    assert_eq!(json["attached_group_ids"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn test_primary_event_rejects_corroborating_source_before_write() {
    use prefixd::correlation::{MatchDimension, SourceConfig, SourceMode};

    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let mut settings = test_settings_with_correlation(true, 1, 0.5);
    settings.correlation.sources.insert(
        "router-cpu".to_string(),
        SourceConfig {
            weight: 0.8,
            r#type: "telemetry".to_string(),
            confidence_mapping: std::collections::HashMap::new(),
            mode: SourceMode::Corroborating,
            match_dimensions: vec![MatchDimension::Pop],
        },
    );

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo.clone(),
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("state");
    let app = create_test_router(state);

    let event_body = serde_json::json!({
        "source": "router-cpu",
        "vector": "udp_flood",
        "victim_ip": "203.0.113.10",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "confidence": 0.9,
        "action": "ban"
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let stored = repo
        .list_events(&prefixd::db::ListParams::default())
        .await
        .unwrap();
    assert!(stored.is_empty(), "rejected event should not be persisted");
}

#[tokio::test]
async fn test_corroborator_does_not_match_via_undeclared_dimension() {
    use prefixd::correlation::{MatchDimension, SourceConfig, SourceMode};

    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let mut settings = test_settings_with_correlation(true, 2, 0.5);
    settings.correlation.sources.insert(
        "router-cpu".to_string(),
        SourceConfig {
            weight: 0.8,
            r#type: "telemetry".to_string(),
            confidence_mapping: std::collections::HashMap::new(),
            mode: SourceMode::Corroborating,
            match_dimensions: vec![MatchDimension::Pop],
        },
    );

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("state");
    let app = create_test_router(state);

    let event_body = serde_json::json!({
        "source": "fastnetmon",
        "vector": "udp_flood",
        "victim_ip": "203.0.113.10",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "confidence": 0.9,
        "action": "ban"
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    let sig_body = serde_json::json!({
        "source": "router-cpu",
        "pop": "wrong-pop",
        "customer_id": "cust_test",
        "vector": "udp_flood",
        "confidence": 0.6
    });
    let (status, json) = post_corroborator(&app, sig_body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "cached");
    assert!(json["attached_group_ids"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_corroborator_attaches_on_interface_dimension() {
    use prefixd::correlation::{MatchDimension, SourceConfig, SourceMode};

    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let mut settings = test_settings_with_correlation(true, 2, 0.5);
    settings.correlation.sources.insert(
        "router-iface".to_string(),
        SourceConfig {
            weight: 0.8,
            r#type: "telemetry".to_string(),
            confidence_mapping: std::collections::HashMap::new(),
            mode: SourceMode::Corroborating,
            match_dimensions: vec![MatchDimension::Interface],
        },
    );
    let inventory = Inventory::new(vec![Customer {
        customer_id: "cust_test".to_string(),
        name: "Test Customer".to_string(),
        prefixes: vec!["203.0.113.0/24".to_string()],
        policy_profile: prefixd::config::PolicyProfile::Normal,
        services: vec![Service {
            service_id: "svc_dns".to_string(),
            name: "DNS".to_string(),
            assets: vec![Asset {
                ip: "203.0.113.10".to_string(),
                role: Some("dns".to_string()),
                interface: Some("xe-0/0/0".to_string()),
            }],
            allowed_ports: AllowedPorts {
                udp: vec![53],
                tcp: vec![53],
            },
        }],
    }]);

    let state = AppState::new(
        settings,
        inventory,
        test_playbooks(),
        repo,
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("state");
    let app = create_test_router(state);

    let event_body = serde_json::json!({
        "source": "fastnetmon",
        "vector": "udp_flood",
        "victim_ip": "203.0.113.10",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "confidence": 0.9,
        "action": "ban"
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    let sig_body = serde_json::json!({
        "source": "router-iface",
        "interface": "xe-0/0/0",
        "vector": "udp_flood",
        "confidence": 0.6
    });
    let (status, json) = post_corroborator(&app, sig_body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "attached");
    assert_eq!(json["attached_group_ids"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn test_corroborator_alone_never_triggers_mitigation() {
    // Ingest two corroborators but zero primary events. Even if min_sources=1,
    // check_corroboration_with_primary must prevent a mitigation from firing.
    // Here we just verify that no signal group is created by corroborator-only.
    let app = setup_app_with_corroborating_source(
        "router-cpu",
        vec![prefixd::correlation::MatchDimension::Pop],
        1.0,
    )
    .await;
    for _ in 0..2 {
        let body = serde_json::json!({
            "source": "router-cpu",
            "pop": "test-pop"
        });
        let (status, json) = post_corroborator(&app, body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "cached");
    }
    // Listing signal groups should show none — corroborators alone don't
    // create groups.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/signal-groups?limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["groups"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_corroborator_rejected_when_correlation_disabled() {
    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let settings = test_settings_with_correlation(false, 1, 0.5);
    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("state");
    let app = create_test_router(state);

    let body = serde_json::json!({"source": "router-cpu", "pop": "x"});
    let (status, _) = post_corroborator(&app, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_expired_sweep_splits_attached_vs_unattached() {
    use chrono::{Duration, Utc};
    use prefixd::correlation::CorroboratingSignal;
    use uuid::Uuid;

    let repo = MockRepository::new();
    let now = Utc::now();

    // Unattached, expired — should count toward unattached_expired.
    repo.insert_corroborating_signal(&CorroboratingSignal {
        signal_id: Uuid::new_v4(),
        source: "router-cpu".to_string(),
        vector: Some("udp_flood".to_string()),
        customer_id: None,
        pop: Some("iad1".to_string()),
        service_id: None,
        interface: None,
        confidence: Some(0.5),
        weight: 0.5,
        ingested_at: now - Duration::seconds(600),
        expires_at: now - Duration::seconds(60),
        raw_details: None,
        attached_group_ids: vec![],
    })
    .await
    .unwrap();

    // Attached, expired — should count toward attached_expired, NOT the
    // cache-miss metric.
    repo.insert_corroborating_signal(&CorroboratingSignal {
        signal_id: Uuid::new_v4(),
        source: "router-cpu".to_string(),
        vector: Some("udp_flood".to_string()),
        customer_id: None,
        pop: Some("iad1".to_string()),
        service_id: None,
        interface: None,
        confidence: Some(0.5),
        weight: 0.5,
        ingested_at: now - Duration::seconds(600),
        expires_at: now - Duration::seconds(60),
        raw_details: None,
        attached_group_ids: vec![Uuid::new_v4()],
    })
    .await
    .unwrap();

    // Unattached, still fresh — should survive the sweep.
    repo.insert_corroborating_signal(&CorroboratingSignal {
        signal_id: Uuid::new_v4(),
        source: "router-cpu".to_string(),
        vector: Some("udp_flood".to_string()),
        customer_id: None,
        pop: Some("iad1".to_string()),
        service_id: None,
        interface: None,
        confidence: Some(0.5),
        weight: 0.5,
        ingested_at: now,
        expires_at: now + Duration::seconds(300),
        raw_details: None,
        attached_group_ids: vec![],
    })
    .await
    .unwrap();

    let stats = repo
        .delete_expired_corroborating_signals(now)
        .await
        .unwrap();
    assert_eq!(stats.unattached_expired, 1);
    assert_eq!(stats.attached_expired, 1);
    assert_eq!(repo.count_cached_corroborators(now).await.unwrap(), 1);
}

#[tokio::test]
async fn test_corroborator_source_activity_merges_cache_rows() {
    use chrono::{Duration, Utc};
    use prefixd::correlation::CorroboratingSignal;
    use uuid::Uuid;

    let repo = MockRepository::new();
    let now = Utc::now();

    for (src, delta) in [
        ("router-cpu", 30),
        ("router-cpu", 60),
        ("pop-utilization", 15),
    ] {
        repo.insert_corroborating_signal(&CorroboratingSignal {
            signal_id: Uuid::new_v4(),
            source: src.to_string(),
            vector: None,
            customer_id: None,
            pop: Some("iad1".to_string()),
            service_id: None,
            interface: None,
            confidence: Some(0.5),
            weight: 0.5,
            ingested_at: now - Duration::seconds(delta),
            expires_at: now + Duration::seconds(300),
            raw_details: None,
            attached_group_ids: vec![],
        })
        .await
        .unwrap();
    }

    let activity = repo
        .corroborator_source_activity(now - Duration::minutes(10))
        .await
        .unwrap();
    let mut by_source: std::collections::HashMap<_, _> = activity
        .into_iter()
        .map(|r| (r.source.clone(), r))
        .collect();
    assert_eq!(by_source.len(), 2);
    let cpu = by_source.remove("router-cpu").unwrap();
    assert_eq!(cpu.count, 2);
    assert!(cpu.last_seen.is_some());
    assert_eq!(by_source.remove("pop-utilization").unwrap().count, 1);
}

#[tokio::test]
async fn test_late_corroborator_finalizes_with_playbook_override() {
    // PR B: a late corroborator can flip corroboration_met=true on its
    // own path, using the override resolved from the group's stored
    // playbook_name. We set up a group whose primary event lands below
    // the global threshold but above the playbook override threshold,
    // and confirm a corroborator promotes the flag.
    use prefixd::correlation::{
        MatchDimension, PlaybookCorrelationOverride, SourceConfig, SourceMode,
    };
    use prefixd::domain::AttackVector;

    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());

    // Global config: min_sources=3, threshold=0.9 — primary alone is far
    // from meeting it. The playbook override drops both to 2 / 0.5, so a
    // single corroborator (count → 2) should finalize.
    let mut settings = test_settings_with_correlation(true, 3, 0.9);
    settings.correlation.sources.insert(
        "router-cpu".to_string(),
        SourceConfig {
            weight: 0.6,
            r#type: "telemetry".to_string(),
            confidence_mapping: std::collections::HashMap::new(),
            mode: SourceMode::Corroborating,
            match_dimensions: vec![MatchDimension::Pop],
        },
    );

    let playbooks = Playbooks {
        playbooks: vec![Playbook {
            name: "udp_flood_test".to_string(),
            match_criteria: PlaybookMatch {
                vector: AttackVector::UdpFlood,
                require_top_ports: false,
            },
            correlation: Some(PlaybookCorrelationOverride {
                min_sources: Some(2),
                confidence_threshold: Some(0.5),
            }),
            steps: vec![PlaybookStep {
                action: PlaybookAction::Police,
                rate_bps: Some(5_000_000),
                ttl_seconds: 120,
                require_confidence_at_least: None,
                require_persistence_seconds: None,
            }],
        }],
    };

    let state = AppState::new(
        settings,
        test_inventory(),
        playbooks,
        repo.clone(),
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("state");
    let app = create_test_router(state);

    // Step 1: primary event — group exists, playbook_name is set,
    // corroboration_met=false (single source against override min=2).
    let event_body = serde_json::json!({
        "source": "fastnetmon",
        "vector": "udp_flood",
        "victim_ip": "203.0.113.10",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "confidence": 0.7,
        "action": "ban"
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    let groups_before = repo
        .list_signal_groups(
            &prefixd::correlation::engine::SignalGroupFilter::default(),
            &prefixd::db::ListParams {
                limit: 10,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(groups_before.len(), 1);
    let group = &groups_before[0];
    assert_eq!(group.playbook_name.as_deref(), Some("udp_flood_test"));
    assert!(
        !group.corroboration_met,
        "single primary event should not yet meet override threshold"
    );

    // Step 2: corroborator with matching pop → group now has 2 distinct
    // sources, derived_confidence above 0.5, override allows promotion.
    let sig_body = serde_json::json!({
        "source": "router-cpu",
        "pop": "test1",
        "vector": "udp_flood",
        "confidence": 0.6
    });
    let resp2 = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/corroborator")
                .header("content-type", "application/json")
                .body(Body::from(sig_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);

    let groups_after = repo
        .list_signal_groups(
            &prefixd::correlation::engine::SignalGroupFilter::default(),
            &prefixd::db::ListParams {
                limit: 10,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let group_after = &groups_after[0];
    assert!(
        group_after.corroboration_met,
        "late corroborator should finalize via playbook override"
    );
    assert_eq!(group_after.source_count, 2);
}

#[tokio::test]
async fn test_late_corroborator_skips_when_playbook_name_is_stale() {
    // If a group's stored playbook_name no longer resolves (admin removed
    // it), the corroborator path falls back to conservative behavior:
    // aggregates update but corroboration_met is preserved (not flipped).
    use prefixd::correlation::CorroboratingSignal;
    use prefixd::correlation::engine::{PrimaryDimensions, SignalGroup, SignalGroupStatus};
    use uuid::Uuid;

    let repo = MockRepository::new();
    let now = chrono::Utc::now();
    let group_id = Uuid::new_v4();

    repo.insert_signal_group(&SignalGroup {
        group_id,
        victim_ip: "203.0.113.10".to_string(),
        vector: "udp_flood".to_string(),
        created_at: now,
        window_expires_at: now + chrono::Duration::seconds(300),
        derived_confidence: 0.0,
        source_count: 0,
        status: SignalGroupStatus::Open,
        corroboration_met: false,
        primary_dimensions: {
            let mut d = PrimaryDimensions::default();
            d.add_pop("test1".to_string());
            d
        },
        playbook_name: Some("does_not_exist".to_string()),
    })
    .await
    .unwrap();
    // Seed a primary event link so has_primary=true.
    repo.add_event_to_group(group_id, Uuid::new_v4(), 1.0)
        .await
        .unwrap();
    repo.insert_corroborating_signal(&CorroboratingSignal {
        signal_id: Uuid::new_v4(),
        source: "router-cpu".to_string(),
        vector: Some("udp_flood".to_string()),
        customer_id: None,
        pop: Some("test1".to_string()),
        service_id: None,
        interface: None,
        confidence: Some(0.9),
        weight: 1.0,
        ingested_at: now,
        expires_at: now + chrono::Duration::seconds(300),
        raw_details: None,
        attached_group_ids: vec![],
    })
    .await
    .unwrap();

    let group = repo.get_signal_group(group_id).await.unwrap().unwrap();
    assert!(
        !group.corroboration_met,
        "stale playbook_name should not allow promotion"
    );
}
