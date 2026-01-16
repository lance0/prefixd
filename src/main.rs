use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio::net::TcpListener;

use prefixd::api::create_router;
use prefixd::bgp::{GoBgpAnnouncer, MockAnnouncer};
use prefixd::config::{AppConfig, BgpMode, StorageDriver};
use prefixd::db;
use prefixd::observability::init_tracing;
use prefixd::scheduler::ReconciliationLoop;
use prefixd::AppState;

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
    tracing::info!(driver = ?storage.driver, "initializing database");

    if storage.driver == StorageDriver::Sqlite {
        let db_path = PathBuf::from(&storage.path);
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let pool = db::init_pool_from_config(storage.driver, &storage.path).await?;
    let repo = db::Repository::new(pool);

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
    );

    // Start reconciliation loop
    let reconciler = ReconciliationLoop::new(
        repo,
        announcer,
        config.settings.timers.reconciliation_interval_seconds,
        state.is_dry_run(),
    );

    let shutdown_rx = state.subscribe_shutdown();
    tokio::spawn(async move {
        reconciler.run(shutdown_rx).await;
    });

    // Start HTTP server
    let listen = cli
        .listen
        .unwrap_or_else(|| config.settings.http.listen.clone());

    let router = create_router(state.clone());
    let listener = TcpListener::bind(&listen).await?;

    tracing::info!(listen = %listen, "HTTP server starting");

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal(state))
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

    // Mark as shutting down (new events will get 503)
    state.trigger_shutdown();

    // Give in-flight requests time to complete
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
