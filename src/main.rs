#![forbid(unsafe_code)]
#![deny(clippy::allow_attributes_without_reason)]

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;

use prefixd::AppState;
use prefixd::api::create_router;
use prefixd::auth::create_auth_layer;
use prefixd::bgp::speaker_factory;
use prefixd::config::{AppConfig, AuthMode};
use prefixd::db;
use prefixd::fence;
use prefixd::observability::init_tracing;
use prefixd::scheduler::ReconciliationLoop;
use sqlx::postgres::PgConnectOptions;
use std::str::FromStr;

#[derive(Parser)]
#[command(
    name = "prefixd",
    version,
    about = "BGP FlowSpec routing policy daemon"
)]
struct Cli {
    /// Path to config directory
    #[arg(short, long, default_value = "/etc/prefixd")]
    config: PathBuf,

    /// Override listen address
    #[arg(long)]
    listen: Option<String>,

    /// Adopt legacy state on its original speaker target, audit and exit without connecting
    #[arg(long)]
    adopt_legacy_speaker: bool,

    /// Retire unexpired dry-run mitigations locally, audit and exit without connecting
    #[arg(long, conflicts_with = "adopt_legacy_speaker")]
    retire_dry_run_intent: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cli = Cli::parse();

    // Load config
    let mut config = AppConfig::load(&cli.config)?;

    // Init logging
    init_tracing(
        config.settings.observability.log_format,
        &config.settings.observability.log_level,
    );
    for deprecation in &config.deprecations {
        tracing::warn!(
            key = deprecation.key,
            rejected_in = prefixd::config::DEPRECATED_CONFIG_REJECTED_IN,
            "deprecated configuration: {}",
            deprecation.message
        );
    }

    tracing::info!(
        pop = %config.settings.pop,
        mode = ?config.settings.mode,
        "starting prefixd"
    );

    // Init database
    // DATABASE_URL env var takes precedence over config file
    let connection_string = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| config.settings.storage.connection_string.clone());
    tracing::info!("initializing PostgreSQL database");

    let pool = db::init_postgres_pool(&connection_string).await?;
    let repo: Arc<dyn db::RepositoryTrait> = Arc::new(db::Repository::new(pool.clone()));

    // Bind before even connecting: configuration changes must not redirect old intent.
    let target = prefixd::domain::SpeakerTarget::from_config(&config.settings.bgp)?;
    let binding = repo
        .register_speaker_target(&config.settings.pop, &target, cli.adopt_legacy_speaker)
        .await?;
    if cli.adopt_legacy_speaker {
        tracing::info!("speaker ownership adoption complete; no speaker connection attempted");
        return Ok(());
    }
    // Rows from before origin tracking take this startup's mode; upgrade without changing mode.
    let tagged = repo
        .tag_unknown_origin(&config.settings.pop, config.settings.mode)
        .await?;
    if tagged > 0 {
        tracing::warn!(
            tagged,
            origin_mode = config.settings.mode.as_str(),
            "tagged live mitigations of unknown origin with the startup mode"
        );
    }
    if cli.retire_dry_run_intent {
        let retired = prefixd::domain::retire_dry_run_intent(
            repo.as_ref(),
            &config.settings.pop,
            Some(&binding),
        )
        .await?;
        tracing::info!(
            retired,
            "dry-run intent retired locally; no speaker connection attempted"
        );
        return Ok(());
    }
    if config.settings.mode == prefixd::config::OperationMode::Enforced {
        prefixd::domain::check_enforced_startup(repo.as_ref(), &config.settings.pop).await?;
    }
    // Fence before any speaker connection: without the lock, run in standby (ADR 027).
    let fence_options = PgConnectOptions::from_str(&connection_string)?;
    let owner = binding.owner();
    let fence_key = fence::fence_lock_key(&owner);
    let held = fence::try_acquire(&fence_options, fence_key).await?;
    if held.is_none() {
        tracing::warn!(owner = %owner, "another controller holds this POP's fence; starting in standby");
    } else {
        tracing::info!(owner = %owner, "controller fence acquired");
    }
    let controller_fence = Arc::new(fence::ControllerFence::new(held.is_some()));
    tokio::spawn(fence::maintain(
        controller_fence.clone(),
        fence_options,
        fence_key,
        held,
        fence::POLL_INTERVAL,
        fence::CHECK_INTERVAL,
    ));
    let announcer: Arc<dyn prefixd::bgp::FlowSpecAnnouncer> =
        Arc::new(fence::FencedAnnouncer::new(
            speaker_factory(&config.settings.bgp).await?,
            controller_fence.clone(),
        ));

    // Init safelist from config
    for prefix in &config.settings.safelist.prefixes {
        repo.insert_safelist(prefix, "config", Some("from prefixd.yaml"))
            .await?;
    }
    prefixd::guardrails::check_blackhole_startup(
        &config.settings.blackhole,
        announcer.as_ref(),
        repo.as_ref(),
    )
    .await?;

    // Load alerting config from alerting.yaml if present, falling back to prefixd.yaml
    let alerting_path = cli.config.join("alerting.yaml");
    if alerting_path.exists() {
        let alerting_config = prefixd::alerting::AlertingConfig::load(&alerting_path)?;
        config.settings.alerting = alerting_config;
        tracing::info!("loaded alerting.yaml");
    }

    // Build app state
    let state = AppState::with_pool(
        config.settings.clone(),
        config.inventory,
        config.playbooks,
        repo.clone(),
        announcer.clone(),
        cli.config.clone(),
        Some(pool.clone()),
    )?
    .with_speaker_binding(binding)?
    .with_fence(controller_fence)?;

    // Create auth layer for session-based auth
    // Secure cookies require HTTPS - check if TLS is configured
    let secure_cookies = config.settings.http.tls.is_some();
    let auth_layer = create_auth_layer(
        pool,
        repo.clone(),
        config.settings.http.auth.mode,
        secure_cookies,
    )
    .await;

    // Start reconciliation loop
    let reconciler = ReconciliationLoop::new(
        repo,
        announcer,
        config.settings.timers.reconciliation_interval_seconds,
        state.is_dry_run(),
    )
    .with_ws_broadcast(state.ws_broadcast.clone())
    .with_alerting(state.alerting.clone())
    .with_app_state(state.clone());

    let shutdown_rx = state.subscribe_shutdown();
    tokio::spawn(async move {
        reconciler.run(shutdown_rx).await;
    });

    // Start HTTP server
    let listen = cli
        .listen
        .unwrap_or_else(|| config.settings.http.listen.clone());

    let router = create_router(state.clone(), auth_layer);

    // Check if TLS is configured
    if let Some(tls_config) = &config.settings.http.tls {
        start_tls_server(
            &listen,
            router,
            tls_config,
            config.settings.http.auth.mode == AuthMode::Mtls,
            state,
        )
        .await?;
    } else {
        start_plain_server(&listen, router, state).await?;
    }

    Ok(())
}

async fn start_plain_server(
    listen: &str,
    router: axum::Router,
    state: Arc<AppState>,
) -> anyhow::Result<()> {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(listen).await?;
    tracing::info!(listen = %listen, tls = false, "HTTP server starting");

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal(state))
        .await?;

    Ok(())
}

async fn start_tls_server(
    listen: &str,
    router: axum::Router,
    tls_config: &prefixd::config::TlsConfig,
    require_client_cert: bool,
    state: Arc<AppState>,
) -> anyhow::Result<()> {
    use axum_server::tls_rustls::RustlsConfig;
    use rustls::RootCertStore;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::server::WebPkiClientVerifier;

    let rustls_config = if require_client_cert {
        let ca_path = tls_config
            .ca_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("mTLS requires ca_path to be set"))?;

        let mut root_store = RootCertStore::empty();
        for cert in CertificateDer::pem_file_iter(ca_path)? {
            root_store.add(cert?)?;
        }

        let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build client verifier: {}", e))?;

        let certs: Vec<_> =
            CertificateDer::pem_file_iter(&tls_config.cert_path)?.collect::<Result<Vec<_>, _>>()?;

        let key = PrivateKeyDer::from_pem_file(&tls_config.key_path).map_err(|e| {
            anyhow::anyhow!(
                "failed to read private key from {}: {}",
                tls_config.key_path,
                e
            )
        })?;

        let config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(certs, key)?;

        RustlsConfig::from_config(Arc::new(config))
    } else {
        RustlsConfig::from_pem_file(&tls_config.cert_path, &tls_config.key_path).await?
    };

    tracing::info!(
        listen = %listen,
        tls = true,
        mtls = require_client_cert,
        "HTTPS server starting"
    );

    let addr: std::net::SocketAddr = listen.parse()?;

    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();

    tokio::spawn(async move {
        shutdown_signal(state).await;
        shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
    });

    axum_server::bind_rustls(addr, rustls_config)
        .handle(handle)
        .serve(router.into_make_service())
        .await?;

    Ok(())
}

async fn shutdown_signal(state: Arc<AppState>) {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    let drain_timeout = state.settings.shutdown.drain_timeout_seconds;
    let active = state.repo.count_active_global().await.unwrap_or(0);

    tracing::info!(
        drain_timeout_seconds = drain_timeout,
        active_mitigations = active,
        "shutdown signal received, beginning graceful shutdown"
    );

    state.trigger_shutdown();

    if drain_timeout > 0 {
        tracing::info!(seconds = drain_timeout, "waiting for drain period");
        tokio::time::sleep(std::time::Duration::from_secs(drain_timeout as u64)).await;
    }

    let final_active = state.repo.count_active_global().await.unwrap_or(0);
    tracing::info!(
        active_mitigations = final_active,
        "graceful shutdown complete"
    );
}
