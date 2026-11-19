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
use sqlx::Connection;
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

    /// Validate configuration and exit without connecting to PostgreSQL or the speaker
    #[arg(
        long,
        conflicts_with_all = ["adopt_legacy_speaker", "retire_dry_run_intent"]
    )]
    check: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cli = Cli::parse();

    if cli.check {
        let check = prefixd::config::AppConfig::check(&cli.config);
        for key in &check.unknown_keys {
            eprintln!("{key}");
        }
        for warning in &check.warnings {
            eprintln!("{warning}");
        }
        if std::env::var_os(prefixd::config::REMOVED_TOKEN_ENV).is_some() {
            eprintln!(
                "{} is set but no longer read: the shared bearer token was removed; remove it from the controller's environment and use API tokens",
                prefixd::config::REMOVED_TOKEN_ENV
            );
        }
        if check.is_ok() {
            println!("{}", check.summary());
            for skipped in prefixd::config::CHECK_SKIPPED {
                println!("skipped: {skipped}");
            }
            return Ok(());
        }
        // One error per line, already naming its file, in startup's redacted text.
        for error in &check.errors {
            eprintln!("{error}");
        }
        std::process::exit(1);
    }

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
    tracing::info!(alerting_source = config.alerting_source, "loaded alerting");
    // This release ignores unknown keys after naming them; the next refuses
    // them, so a typo such as `guardrails.max_port` is not silent meanwhile.
    for unknown in &config.unknown_keys {
        tracing::warn!(
            file = %unknown.file,
            key = %unknown.key,
            "unknown configuration key ignored; the next release refuses it"
        );
    }
    prefixd::config::warn_removed_token_env();
    prefixd::observability::init_metrics(&config.settings.pop);
    // Refuse what `--check` refuses before opening the database, so a bad edit
    // fails fast instead of after a speaker connection. Maintenance commands
    // neither serve nor connect to the speaker, so they skip it.
    if !cli.adopt_legacy_speaker && !cli.retire_dry_run_intent {
        let errors = config.preflight_errors(&cli.config);
        anyhow::ensure!(errors.is_empty(), "{}", errors.join("\n"));
    }

    // Init database
    // DATABASE_URL env var takes precedence over config file
    let connection_string = config.settings.storage.database_url()?;
    tracing::info!("initializing PostgreSQL database");

    let pool = db::init_postgres_pool(&connection_string).await?;
    let repo: Arc<dyn db::RepositoryTrait> = Arc::new(db::Repository::new(pool.clone()));

    let fence_options = PgConnectOptions::from_str(&connection_string)?;
    // Bind before even connecting: configuration changes must not redirect old intent.
    let target = prefixd::domain::SpeakerTarget::from_config(&config.settings.bgp)?;
    // Adoption writes during registration, so it takes the fence first. A target
    // that was never registered has no owner a controller could be holding.
    let mut maintenance_fence = None;
    if cli.adopt_legacy_speaker
        && let Some(target_id) = repo.registered_speaker_target_id(&target).await?
    {
        let owner = prefixd::domain::controller_owner(&config.settings.pop, target_id);
        maintenance_fence = Some(fence::acquire_for_maintenance(&fence_options, &owner).await?);
    }
    let binding = repo
        .register_speaker_target(&config.settings.pop, &target, cli.adopt_legacy_speaker)
        .await?;
    if cli.adopt_legacy_speaker {
        if let Some(session) = maintenance_fence {
            let _ = session.close().await;
        }
        tracing::info!("speaker ownership adoption complete; no speaker connection attempted");
        return Ok(());
    }
    if cli.retire_dry_run_intent {
        maintenance_fence =
            Some(fence::acquire_for_maintenance(&fence_options, &binding.owner()).await?);
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
        if let Some(session) = maintenance_fence {
            let _ = session.close().await;
        }
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

    prefixd::bgp::check_vpn_startup(
        &config.settings.bgp,
        &config.settings.pop,
        announcer.as_ref(),
        repo.as_ref(),
    )
    .await?;

    // Init safelist from config
    for prefix in &config.settings.safelist.prefixes {
        repo.insert_safelist(prefix, "config", Some("from prefixd.yaml"))
            .await?;
    }
    // Rules the guardrails or the selected speaker would refuse fail startup,
    // in dry-run and enforced modes alike (ADR 028), as do blackhole steps the
    // settings or the lease gate refuse (ADR 027).
    let playbook_errors = config
        .playbooks
        .check_settings(&config.settings, announcer.capabilities());
    if !playbook_errors.is_empty() {
        anyhow::bail!("playbooks.yaml: {}", playbook_errors.join("; "));
    }
    config.playbooks.log_warnings(&config.settings.guardrails);
    // The lease probe is the capability check and recovers a live generation
    // after a restart (ADR 027); it is asked only when the lease is configured.
    let blackhole = &config.settings.blackhole;
    let leased_flowspec = config
        .settings
        .bgp
        .rustbgpd
        .as_ref()
        .is_some_and(|rustbgpd| rustbgpd.leased_flowspec);
    let lease = if (blackhole.enabled && blackhole.leased) || leased_flowspec {
        let keeper = prefixd::domain::LeaseKeeper::new(owner.clone(), blackhole.lease_seconds)
            .with_reconcile_interval(config.settings.timers.reconciliation_interval_seconds)
            .with_fence(controller_fence.clone());
        // RenewLease is a speaker mutation, so dry-run never renews: leased
        // routes left by an enforced run lapse within one lease.
        let keeper = Arc::new(
            if config.settings.mode == prefixd::config::OperationMode::Enforced {
                keeper
            } else {
                keeper.without_renewal()
            },
        );
        if let Some(leases) = announcer.injection_leases() {
            match keeper.recover(leases).await {
                Ok(true) => tracing::info!(owner = %owner, generation = ?keeper.generation(),
                    "speaker provides the injection lease"),
                Ok(false) => tracing::warn!("speaker does not implement the injection lease"),
                Err(error) => tracing::warn!(error = %error, "injection lease probe failed"),
            }
        }
        Some(keeper)
    } else {
        None
    };
    prefixd::guardrails::check_blackhole_startup(blackhole, announcer.as_ref(), repo.as_ref())
        .await?;
    prefixd::guardrails::check_lease_startup(
        &config.settings,
        announcer.as_ref(),
        repo.as_ref(),
        &owner,
    )
    .await?;
    if let Some(keeper) = &lease
        && config.settings.mode == prefixd::config::OperationMode::Enforced
    {
        tokio::spawn(prefixd::domain::run_lease_renewals(
            keeper.clone(),
            announcer.clone(),
        ));
    }
    let blackhole_lease = announcer.capabilities().blackhole_lease;
    prefixd::observability::metrics::update_speaker_metrics(announcer.as_ref());
    let detector_unleased =
        prefixd::guardrails::detector_unleased(&config.settings, blackhole_lease);
    prefixd::observability::metrics::BLACKHOLE_DETECTOR_UNLEASED
        .set(f64::from(u8::from(detector_unleased)));
    if detector_unleased {
        tracing::warn!(
            detector_sources = ?config.settings.blackhole.detector_sources,
            "enforced detector blackholes run without the rustbgpd injection lease; \
             if prefixd stops while the speaker runs, they stay announced until prefixd returns or an operator withdraws them"
        );
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
    let state = match lease {
        Some(lease) => state.with_lease(lease)?,
        None => state,
    };

    // Recover durable diversion obligations before accepting manual mutations.
    prefixd::scrubber::ScrubberController::check_startup(&state).await?;
    if state.settings.scrubber.enabled {
        tokio::spawn(prefixd::scrubber::ScrubberController::run(state.clone()));
    }

    // Create auth layer for session-based auth
    let secure_cookies = config.settings.http.secure_cookies();
    tracing::info!(secure_cookies, "session cookies");
    let auth_layer = create_auth_layer(
        pool,
        repo.clone(),
        config.settings.http.auth.clone(),
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

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
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

    let rustls_config =
        RustlsConfig::from_config(Arc::new(tls_config.server_config(require_client_cert)?));

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
        .serve(router.into_make_service_with_connect_info::<std::net::SocketAddr>())
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

    // Drain first: readiness fails and ingest refuses before anything else runs.
    // The fence stays held until the process exits.
    state.trigger_shutdown();

    let drain_timeout = state.settings.shutdown.drain_timeout_seconds;
    let active = state.repo.count_active_global().await.unwrap_or(0);

    tracing::info!(
        drain_timeout_seconds = drain_timeout,
        active_mitigations = active,
        "shutdown signal received, beginning graceful shutdown"
    );

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
