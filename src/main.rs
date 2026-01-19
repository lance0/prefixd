use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;

use prefixd::AppState;
use prefixd::api::create_router;
use prefixd::auth::create_auth_layer;
use prefixd::bgp::{GoBgpAnnouncer, MockAnnouncer};
use prefixd::config::{AppConfig, AuthMode, BgpMode};
use prefixd::db;
use prefixd::observability::init_tracing;
use prefixd::scheduler::ReconciliationLoop;

#[derive(Parser)]
#[command(name = "prefixd", about = "BGP FlowSpec routing policy daemon")]
struct Cli {
    /// Path to config directory
    #[arg(short, long, default_value = "/etc/prefixd")]
    config: PathBuf,

    /// Override listen address
    #[arg(long)]
    listen: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Load config
    let config = AppConfig::load(&cli.config)?;

    // Init logging
    init_tracing(
        config.settings.observability.log_format,
        &config.settings.observability.log_level,
    );

    tracing::info!(
        pop = %config.settings.pop,
        mode = ?config.settings.mode,
        "starting prefixd"
    );

    // Init database
    let storage = &config.settings.storage;
    tracing::info!("initializing PostgreSQL database");

    let pool = db::init_postgres_pool(&storage.connection_string).await?;
    let repo: Arc<dyn db::RepositoryTrait> = Arc::new(db::Repository::new(pool.clone()));

    // Init safelist from config
    for prefix in &config.settings.safelist.prefixes {
        repo.insert_safelist(prefix, "config", Some("from prefixd.yaml"))
            .await?;
    }

    // Init BGP announcer
    let announcer: Arc<dyn prefixd::bgp::FlowSpecAnnouncer> = match config.settings.bgp.mode {
        BgpMode::Mock => {
            tracing::info!("using mock BGP announcer");
            Arc::new(MockAnnouncer::new())
        }
        BgpMode::Sidecar => {
            tracing::info!(endpoint = %config.settings.bgp.gobgp_grpc, "using GoBGP sidecar");
            let gobgp = GoBgpAnnouncer::new(config.settings.bgp.gobgp_grpc.clone());
            Arc::new(gobgp)
        }
    };

    // Build app state
    let state = AppState::new(
        config.settings.clone(),
        config.inventory,
        config.playbooks,
        repo.clone(),
        announcer.clone(),
        cli.config.clone(),
    )?;

    // Create auth layer for session-based auth
    // Secure cookies require HTTPS - check if TLS is configured
    let secure_cookies = config.settings.http.tls.is_some();
    let auth_layer = create_auth_layer(pool, repo.clone(), secure_cookies).await;

    // Start reconciliation loop
    let reconciler = ReconciliationLoop::new(
        repo,
        announcer,
        config.settings.timers.reconciliation_interval_seconds,
        state.is_dry_run(),
    )
    .with_ws_broadcast(state.ws_broadcast.clone());

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
    use rustls::server::WebPkiClientVerifier;
    use std::fs::File;
    use std::io::BufReader;

    let rustls_config = if require_client_cert {
        let ca_path = tls_config
            .ca_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("mTLS requires ca_path to be set"))?;

        let ca_file = File::open(ca_path)?;
        let mut ca_reader = BufReader::new(ca_file);
        let ca_certs: Vec<_> =
            rustls_pemfile::certs(&mut ca_reader).collect::<Result<Vec<_>, _>>()?;

        let mut root_store = RootCertStore::empty();
        for cert in ca_certs {
            root_store.add(cert)?;
        }

        let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build client verifier: {}", e))?;

        let cert_file = File::open(&tls_config.cert_path)?;
        let mut cert_reader = BufReader::new(cert_file);
        let certs: Vec<_> =
            rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

        let key_file = File::open(&tls_config.key_path)?;
        let mut key_reader = BufReader::new(key_file);
        let key = rustls_pemfile::private_key(&mut key_reader)?
            .ok_or_else(|| anyhow::anyhow!("no private key found in {}", tls_config.key_path))?;

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
        preserve_announcements = state.settings.shutdown.preserve_announcements,
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
