use std::sync::Arc;
use testcontainers::{runners::AsyncRunner, ContainerAsync, ImageExt};
use testcontainers_modules::postgres::Postgres;

use prefixd::bgp::MockAnnouncer;
use prefixd::config::{
    AllowedPorts, Asset, AuthConfig, AuthMode, BgpConfig, BgpMode, Customer, EscalationConfig,
    GuardrailsConfig, HttpConfig, Inventory, ObservabilityConfig, Playbook, PlaybookAction,
    PlaybookMatch, PlaybookStep, Playbooks, QuotasConfig, RateLimitConfig, SafelistConfig,
    Service, Settings, ShutdownConfig, StorageConfig, TimersConfig,
};
use prefixd::db::{init_postgres_pool, Repository, RepositoryTrait};
use prefixd::domain::AttackVector;
use prefixd::AppState;

pub struct TestContext {
    pub state: Arc<AppState>,
    pub repo: Arc<dyn RepositoryTrait>,
    _container: ContainerAsync<Postgres>,
}

impl TestContext {
    pub async fn new() -> Self {
        let container = Postgres::default()
            .with_tag("16-alpine")
            .start()
            .await
            .expect("Failed to start Postgres container");

        let host = container.get_host().await.expect("Failed to get host");
        let port = container
            .get_host_port_ipv4(5432)
            .await
            .expect("Failed to get port");

        let connection_string = format!(
            "postgres://postgres:postgres@{}:{}/postgres",
            host, port
        );

        let pool = init_postgres_pool(&connection_string)
            .await
            .expect("Failed to init pool");

        let repo: Arc<dyn RepositoryTrait> = Arc::new(Repository::new(pool));
        let announcer = Arc::new(MockAnnouncer::new());

        let mut settings = test_settings();
        settings.storage.connection_string = connection_string;

        let state = AppState::new(
            settings,
            test_inventory(),
            test_playbooks(),
            repo.clone(),
            announcer,
            std::path::PathBuf::from("."),
        );

        Self {
            state,
            repo,
            _container: container,
        }
    }

    pub fn router(&self) -> axum::Router {
        prefixd::api::create_router(self.state.clone())
    }
}

pub fn test_settings() -> Settings {
    Settings {
        pop: "test-pop".to_string(),
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
            max_active_per_customer: 100,
            max_active_per_pop: 500,
            max_active_global: 1000,
            max_new_per_minute: 60,
            max_announcements_per_peer: 200,
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
            connection_string: String::new(), // Will be set by TestContext
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

pub fn test_inventory() -> Inventory {
    Inventory::new(vec![Customer {
        customer_id: "cust_integration".to_string(),
        name: "Integration Test Customer".to_string(),
        prefixes: vec!["203.0.113.0/24".to_string()],
        policy_profile: prefixd::config::PolicyProfile::Normal,
        services: vec![Service {
            service_id: "svc_web".to_string(),
            name: "Web Server".to_string(),
            assets: vec![
                Asset {
                    ip: "203.0.113.10".to_string(),
                    role: Some("web".to_string()),
                },
                Asset {
                    ip: "203.0.113.11".to_string(),
                    role: Some("web".to_string()),
                },
            ],
            allowed_ports: AllowedPorts {
                udp: vec![],
                tcp: vec![80, 443],
            },
        }],
    }])
}

pub fn test_playbooks() -> Playbooks {
    Playbooks {
        playbooks: vec![
            Playbook {
                name: "udp_flood".to_string(),
                match_criteria: PlaybookMatch {
                    vector: AttackVector::UdpFlood,
                    require_top_ports: false,
                },
                steps: vec![PlaybookStep {
                    action: PlaybookAction::Police,
                    rate_bps: Some(10_000_000),
                    ttl_seconds: 120,
                    require_confidence_at_least: None,
                    require_persistence_seconds: None,
                }],
            },
            Playbook {
                name: "syn_flood".to_string(),
                match_criteria: PlaybookMatch {
                    vector: AttackVector::SynFlood,
                    require_top_ports: false,
                },
                steps: vec![PlaybookStep {
                    action: PlaybookAction::Discard,
                    rate_bps: None,
                    ttl_seconds: 60,
                    require_confidence_at_least: None,
                    require_persistence_seconds: None,
                }],
            },
        ],
    }
}
