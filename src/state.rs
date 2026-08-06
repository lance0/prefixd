use chrono::{DateTime, Utc};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tokio::sync::{RwLock, broadcast};

use crate::alerting::AlertingService;
use crate::bgp::FlowSpecAnnouncer;
use crate::config::{AuthMode, Inventory, Playbooks, Settings};
use crate::correlation::CorrelationConfig;
use crate::db::RepositoryTrait;
use crate::error::{PrefixdError, Result};
use crate::ws::WsMessage;
use sqlx::PgPool;

/// Shared application state
pub struct AppState {
    pub settings: Settings,
    pub inventory: RwLock<Inventory>,
    pub playbooks: RwLock<Playbooks>,
    pub repo: Arc<dyn RepositoryTrait>,
    pub announcer: Arc<dyn FlowSpecAnnouncer>,
    pub shutdown_tx: broadcast::Sender<()>,
    /// WebSocket broadcast channel for real-time updates
    pub ws_broadcast: broadcast::Sender<WsMessage>,
    /// Cached bearer token (loaded at startup to avoid per-request env lookups)
    pub bearer_token: Option<String>,
    /// Server start time for uptime calculation
    pub start_time: Instant,
    /// Timestamp when inventory was last loaded/reloaded
    pub inventory_loaded_at: RwLock<DateTime<Utc>>,
    /// Timestamp when playbooks were last loaded/reloaded
    pub playbooks_loaded_at: RwLock<DateTime<Utc>>,
    /// Alerting service for webhook notifications (RwLock for hot-swap on config update)
    pub alerting: Arc<RwLock<Arc<AlertingService>>>,
    /// Timestamp when alerting config was last loaded
    pub alerting_loaded_at: RwLock<DateTime<Utc>>,
    /// Correlation engine configuration (RwLock for hot-reload)
    pub correlation_config: RwLock<CorrelationConfig>,
    /// Timestamp when correlation config was last loaded
    pub correlation_loaded_at: RwLock<DateTime<Utc>>,
    /// PostgreSQL pool for metrics (None in tests with MockRepository)
    pub db_pool: Option<PgPool>,
    /// Serializes mitigation creation to prevent TOCTOU race between
    /// find_active_by_scope and insert_mitigation in handle_ban.
    pub mitigation_lock: tokio::sync::Mutex<()>,
    /// Directory containing config files (for hot-reload)
    pub config_dir: PathBuf,
    shutting_down: AtomicBool,
}

impl AppState {
    pub fn new(
        settings: Settings,
        inventory: Inventory,
        playbooks: Playbooks,
        repo: Arc<dyn RepositoryTrait>,
        announcer: Arc<dyn FlowSpecAnnouncer>,
        config_dir: PathBuf,
    ) -> Result<Arc<Self>> {
        Self::with_pool(
            settings, inventory, playbooks, repo, announcer, config_dir, None,
        )
    }

    pub fn with_pool(
        settings: Settings,
        inventory: Inventory,
        playbooks: Playbooks,
        repo: Arc<dyn RepositoryTrait>,
        announcer: Arc<dyn FlowSpecAnnouncer>,
        config_dir: PathBuf,
        db_pool: Option<PgPool>,
    ) -> Result<Arc<Self>> {
        let (shutdown_tx, _) = broadcast::channel(1);
        let ws_broadcast = crate::ws::create_broadcast();
        let alerting = AlertingService::new(settings.alerting.clone());

        // Load bearer token at startup (avoids per-request env lookups)
        let bearer_token = if matches!(settings.http.auth.mode, AuthMode::Bearer) {
            let env_var = settings
                .http
                .auth
                .bearer_token_env
                .as_deref()
                .unwrap_or("PREFIXD_API_TOKEN");

            match std::env::var(env_var) {
                Ok(token) if !token.is_empty() => {
                    tracing::info!(env_var = %env_var, "loaded bearer token from environment");
                    Some(token)
                }
                _ => {
                    return Err(PrefixdError::Config(format!(
                        "auth.mode=bearer but {} is not set or empty",
                        env_var
                    )));
                }
            }
        } else {
            None
        };

        let correlation_config = settings.correlation.clone();

        Ok(Arc::new(Self {
            settings,
            inventory: RwLock::new(inventory),
            playbooks: RwLock::new(playbooks),
            repo,
            announcer,
            shutdown_tx,
            ws_broadcast,
            bearer_token,
            alerting: Arc::new(RwLock::new(alerting)),
            alerting_loaded_at: RwLock::new(Utc::now()),
            correlation_config: RwLock::new(correlation_config),
            correlation_loaded_at: RwLock::new(Utc::now()),
            start_time: Instant::now(),
            inventory_loaded_at: RwLock::new(Utc::now()),
            playbooks_loaded_at: RwLock::new(Utc::now()),
            mitigation_lock: tokio::sync::Mutex::new(()),
            db_pool,
            config_dir,
            shutting_down: AtomicBool::new(false),
        }))
    }

    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    pub fn trigger_shutdown(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
        let _ = self.shutdown_tx.send(());
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }

    pub fn is_dry_run(&self) -> bool {
        matches!(self.settings.mode, crate::config::OperationMode::DryRun)
    }

    pub fn playbooks_path(&self) -> PathBuf {
        self.config_dir.join("playbooks.yaml")
    }

    pub fn alerting_path(&self) -> PathBuf {
        self.config_dir.join("alerting.yaml")
    }

    pub fn correlation_path(&self) -> PathBuf {
        self.config_dir.join("correlation.yaml")
    }

    /// Reload inventory and playbooks from config files
    pub async fn reload_config(&self) -> Result<Vec<String>> {
        let mut reloaded = Vec::new();

        // Reload inventory
        let inventory_path = self.config_dir.join("inventory.yaml");
        if inventory_path.exists() {
            let new_inventory = Inventory::load(&inventory_path)
                .map_err(|e| PrefixdError::Config(format!("inventory: {}", e)))?;
            *self.inventory.write().await = new_inventory;
            *self.inventory_loaded_at.write().await = Utc::now();
            reloaded.push("inventory".to_string());
            tracing::info!("reloaded inventory.yaml");
        }

        // Reload playbooks
        let playbooks_path = self.config_dir.join("playbooks.yaml");
        if playbooks_path.exists() {
            let mut playbooks_guard = self.playbooks.write().await;
            let new_playbooks = Playbooks::load(&playbooks_path)
                .map_err(|e| PrefixdError::Config(format!("playbooks: {}", e)))?;
            *playbooks_guard = new_playbooks;
            drop(playbooks_guard);
            *self.playbooks_loaded_at.write().await = Utc::now();
            reloaded.push("playbooks".to_string());
            tracing::info!("reloaded playbooks.yaml");
        }

        // Reload correlation config: prefer standalone correlation.yaml, fall back to prefixd.yaml
        let correlation_path = self.correlation_path();
        if correlation_path.exists() {
            let new_config = crate::correlation::CorrelationConfig::load(&correlation_path)
                .map_err(|e| PrefixdError::Config(format!("correlation.yaml: {}", e)))?;
            *self.correlation_config.write().await = new_config;
            *self.correlation_loaded_at.write().await = Utc::now();
            reloaded.push("correlation".to_string());
            tracing::info!("reloaded correlation config from correlation.yaml");
        } else {
            let prefixd_yaml_path = self.config_dir.join("prefixd.yaml");
            if prefixd_yaml_path.exists() {
                let new_settings = Settings::load(&prefixd_yaml_path)
                    .map_err(|e| PrefixdError::Config(format!("prefixd.yaml: {}", e)))?;
                *self.correlation_config.write().await = new_settings.correlation;
                *self.correlation_loaded_at.write().await = Utc::now();
                reloaded.push("correlation".to_string());
                tracing::info!("reloaded correlation config from prefixd.yaml");
            }
        }

        // Reload alerting (from alerting.yaml if present)
        let alerting_path = self.alerting_path();
        if alerting_path.exists() {
            let mut alerting_guard = self.alerting.write().await;
            let new_config = crate::alerting::AlertingConfig::load(&alerting_path)
                .map_err(|e| PrefixdError::Config(format!("alerting: {}", e)))?;
            let new_service = AlertingService::new(new_config);
            *alerting_guard = new_service;
            drop(alerting_guard);
            *self.alerting_loaded_at.write().await = Utc::now();
            reloaded.push("alerting".to_string());
            tracing::info!("reloaded alerting.yaml");
        }

        Ok(reloaded)
    }
}
