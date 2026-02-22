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
