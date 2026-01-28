use std::path::Path;
use std::sync::Arc;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};
use testcontainers_modules::postgres::Postgres;

use prefixd::AppState;
use prefixd::auth::create_auth_layer;
use prefixd::bgp::{FlowSpecAnnouncer, GoBgpAnnouncer, MockAnnouncer};
use prefixd::config::{
    AllowedPorts, Asset, AuthConfig, AuthMode, BgpConfig, BgpMode, Customer, EscalationConfig,
    GuardrailsConfig, HttpConfig, Inventory, ObservabilityConfig, OperationMode, Playbook,
    PlaybookAction, PlaybookMatch, PlaybookStep, Playbooks, QuotasConfig, RateLimitConfig,
    SafelistConfig, Service, Settings, ShutdownConfig, StorageConfig, TimersConfig,
};
use prefixd::db::{Repository, RepositoryTrait, init_postgres_pool};
use prefixd::domain::AttackVector;
use sqlx::PgPool;

pub struct TestContext {
    pub state: Arc<AppState>,
    pub repo: Arc<dyn RepositoryTrait>,
    pub pool: PgPool,
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

        let connection_string = format!("postgres://postgres:postgres@{}:{}/postgres", host, port);

        let pool = init_postgres_pool(&connection_string)
            .await
            .expect("Failed to init pool");

        let repo: Arc<dyn RepositoryTrait> = Arc::new(Repository::new(pool.clone()));
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
        )
        .expect("failed to create app state");

        Self {
            state,
            repo,
            pool,
            _container: container,
        }
    }

    pub async fn router(&self) -> axum::Router {
        let auth_layer = create_auth_layer(self.pool.clone(), self.repo.clone(), false).await;
        prefixd::api::create_router(self.state.clone(), auth_layer)
    }

    /// Create a test context with a custom config directory for hot-reload testing
    pub async fn with_config_dir(config_dir: &Path) -> Self {
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

        let connection_string = format!("postgres://postgres:postgres@{}:{}/postgres", host, port);

        let pool = init_postgres_pool(&connection_string)
            .await
            .expect("Failed to init pool");

        let repo: Arc<dyn RepositoryTrait> = Arc::new(Repository::new(pool.clone()));
        let announcer = Arc::new(MockAnnouncer::new());

        let mut settings = test_settings();
        settings.storage.connection_string = connection_string;

        // Load inventory/playbooks from config_dir if they exist
        let inventory = config_dir
            .join("inventory.yaml")
            .exists()
            .then(|| Inventory::load(config_dir.join("inventory.yaml")).ok())
            .flatten()
            .unwrap_or_else(test_inventory);

        let playbooks = config_dir
            .join("playbooks.yaml")
            .exists()
            .then(|| Playbooks::load(config_dir.join("playbooks.yaml")).ok())
            .flatten()
            .unwrap_or_else(test_playbooks);

        let state = AppState::new(
            settings,
            inventory,
            playbooks,
            repo.clone(),
            announcer,
            config_dir.to_path_buf(),
        )
        .expect("failed to create app state");

        Self {
            state,
            repo,
            pool,
            _container: container,
        }
    }
}

/// Write a YAML string to a file in the given directory
pub fn write_yaml(dir: &Path, filename: &str, content: &str) {
    std::fs::write(dir.join(filename), content).expect("Failed to write YAML file");
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
                ldap: None,
                radius: None,
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

// =============================================================================
// E2E Test Context - Uses REAL GoBGP (not mock)
// =============================================================================

/// End-to-end test context with real Postgres AND real GoBGP containers.
/// This tests the full flow: HTTP API → prefixd → GoBGP gRPC → FlowSpec RIB
pub struct E2ETestContext {
    pub state: Arc<AppState>,
    pub repo: Arc<dyn RepositoryTrait>,
    pub announcer: Arc<GoBgpAnnouncer>,
    pub pool: PgPool,
    pub gobgp_endpoint: String,
    _postgres: ContainerAsync<Postgres>,
    _gobgp: ContainerAsync<GenericImage>,
}

impl E2ETestContext {
    /// Create a new E2E test context with real Postgres and GoBGP containers.
    pub async fn new() -> Self {
        // Start Postgres container
        let postgres = Postgres::default()
            .with_tag("16-alpine")
            .start()
            .await
            .expect("Failed to start Postgres container");

        let pg_host = postgres
            .get_host()
            .await
            .expect("Failed to get Postgres host");
        let pg_port = postgres
            .get_host_port_ipv4(5432)
            .await
            .expect("Failed to get Postgres port");

        let connection_string = format!(
            "postgres://postgres:postgres@{}:{}/postgres",
            pg_host, pg_port
        );

        // Start GoBGP container
        // The jauderho/gobgp image is minimal - we need to configure GoBGP via gRPC after start
        let gobgp = GenericImage::new("jauderho/gobgp", "latest")
            .with_exposed_port(50051.tcp())
            .with_exposed_port(179.tcp())
            .with_wait_for(WaitFor::seconds(3))
            .with_cmd(["/usr/local/bin/gobgpd", "-p", "--api-hosts=0.0.0.0:50051"])
            .start()
            .await
            .expect("Failed to start GoBGP container");

        // Additional wait for gRPC server to be ready
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let gobgp_host = gobgp.get_host().await.expect("Failed to get GoBGP host");
        let gobgp_port = gobgp
            .get_host_port_ipv4(50051)
            .await
            .expect("Failed to get GoBGP port");

        let gobgp_endpoint = format!("{}:{}", gobgp_host, gobgp_port);

        // Initialize Postgres
        let pool = init_postgres_pool(&connection_string)
            .await
            .expect("Failed to init pool");

        let repo: Arc<dyn RepositoryTrait> = Arc::new(Repository::new(pool.clone()));

        // Configure GoBGP via gRPC StartBgp
        configure_gobgp(&gobgp_endpoint).await;

        // Create REAL GoBGP announcer
        let mut announcer = GoBgpAnnouncer::new(gobgp_endpoint.clone());
        announcer
            .connect()
            .await
            .expect("Failed to connect to GoBGP");
        let announcer = Arc::new(announcer);

        // Settings configured for ENFORCED mode (not dry-run)
        let mut settings = test_settings();
        settings.storage.connection_string = connection_string;
        settings.mode = OperationMode::Enforced; // Actually announce!
        settings.bgp.mode = BgpMode::Sidecar;
        settings.bgp.gobgp_grpc = gobgp_endpoint.clone();

        let state = AppState::new(
            settings,
            test_inventory(),
            test_playbooks(),
            repo.clone(),
            announcer.clone(),
            std::path::PathBuf::from("."),
        )
        .expect("Failed to create app state");

        Self {
            state,
            repo,
            announcer,
            pool,
            gobgp_endpoint,
            _postgres: postgres,
            _gobgp: gobgp,
        }
    }

    pub async fn router(&self) -> axum::Router {
        let auth_layer = create_auth_layer(self.pool.clone(), self.repo.clone(), false).await;
        prefixd::api::create_router(self.state.clone(), auth_layer)
    }
}

/// Configure GoBGP via gRPC StartBgp call
async fn configure_gobgp(endpoint: &str) {
    use prefixd::bgp::apipb::{Global, StartBgpRequest, go_bgp_service_client::GoBgpServiceClient};
    use tonic::transport::Channel;

    let channel = Channel::from_shared(format!("http://{}", endpoint))
        .expect("Invalid endpoint")
        .connect()
        .await
        .expect("Failed to connect to GoBGP gRPC");

    let mut client = GoBgpServiceClient::new(channel);

    let request = StartBgpRequest {
        global: Some(Global {
            asn: 65010,
            router_id: "10.10.0.10".to_string(),
            listen_port: -1, // Disable BGP listener (we only need gRPC)
            listen_addresses: vec![],
            families: vec![],
            use_multiple_paths: false,
            route_selection_options: None,
            default_route_distance: None,
            confederation: None,
            graceful_restart: None,
            bind_to_device: String::new(),
        }),
    };

    client
        .start_bgp(request)
        .await
        .expect("Failed to start GoBGP");
}
