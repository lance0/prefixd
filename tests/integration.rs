use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use tower::ServiceExt;

use prefixd::api::create_router;
use prefixd::bgp::MockAnnouncer;
use prefixd::config::{
    AllowedPorts, Asset, AuthConfig, AuthMode, BgpConfig, BgpMode, Customer, EscalationConfig,
    GuardrailsConfig, HttpConfig, Inventory, ObservabilityConfig, Playbook, PlaybookAction,
    PlaybookMatch, PlaybookStep, Playbooks, QuotasConfig, RateLimitConfig, SafelistConfig,
    Service, Settings, ShutdownConfig, StorageConfig, StorageDriver, TimersConfig,
};
use prefixd::db;
use prefixd::domain::AttackVector;
use prefixd::AppState;

fn test_settings() -> Settings {
    Settings {
        pop: "test1".to_string(),
        mode: prefixd::config::OperationMode::DryRun,
        http: HttpConfig {
            listen: "127.0.0.1:0".to_string(),
            auth: AuthConfig {
                mode: AuthMode::None,
                bearer_token_env: None,
            },
            rate_limit: RateLimitConfig::default(),
            tls: None,
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
            driver: StorageDriver::Sqlite,
            path: ":memory:".to_string(),
        },
        observability: ObservabilityConfig {
            log_format: prefixd::config::LogFormat::Pretty,
            log_level: "info".to_string(),
            audit_log_path: "/dev/null".to_string(),
            metrics_listen: "127.0.0.1:0".to_string(),
        },
        safelist: SafelistConfig { prefixes: vec![] },
        shutdown: ShutdownConfig::default(),
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

async fn setup_app() -> axum::Router {
    let pool = db::init_memory_pool().await.unwrap();
    let repo = db::Repository::from_sqlite(pool);
    let announcer = Arc::new(MockAnnouncer::new());

    let state = AppState::new(
        test_settings(),
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        std::path::PathBuf::from("."),
    );

    create_router(state)
}

#[tokio::test]
async fn test_health_endpoint() {
    let app = setup_app().await;

    let response = app
        .oneshot(Request::builder().uri("/v1/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
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

    let pool = db::init_memory_pool().await.unwrap();
    let repo = db::Repository::from_sqlite(pool);
    let announcer = Arc::new(MockAnnouncer::new());

    let state = AppState::new(
        test_settings_with_bearer(),
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        std::path::PathBuf::from("."),
    );

    create_router(state)
}

#[tokio::test]
async fn test_bearer_auth_missing_token_returns_401() {
    let app = setup_app_with_bearer().await;

    // Request without Authorization header
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

    // Request with wrong token
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

    // Request with correct token
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

    // Health endpoint should work without auth even when bearer is configured
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

    // Check security headers
    assert_eq!(
        response.headers().get("x-content-type-options").map(|v| v.to_str().unwrap()),
        Some("nosniff")
    );
    assert_eq!(
        response.headers().get("x-frame-options").map(|v| v.to_str().unwrap()),
        Some("DENY")
    );
    assert_eq!(
        response.headers().get("cache-control").map(|v| v.to_str().unwrap()),
        Some("no-store")
    );
}
