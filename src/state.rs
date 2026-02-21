use chrono::{DateTime, Utc};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tokio::sync::{RwLock, broadcast};

use crate::alerting::AlertingService;
use crate::bgp::FlowSpecAnnouncer;
use crate::config::{AuthMode, Inventory, Playbooks, Settings};
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
    /// Alerting service for webhook notifications
    pub alerting: Arc<AlertingService>,
    /// PostgreSQL pool for metrics (None in tests with MockRepository)
    pub db_pool: Option<PgPool>,
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

        Ok(Arc::new(Self {
            settings,
            inventory: RwLock::new(inventory),
            playbooks: RwLock::new(playbooks),
            repo,
            announcer,
            shutdown_tx,
            ws_broadcast,
            bearer_token,
            alerting,
            start_time: Instant::now(),
            inventory_loaded_at: RwLock::new(Utc::now()),
            playbooks_loaded_at: RwLock::new(Utc::now()),
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
            let new_playbooks = Playbooks::load(&playbooks_path)
                .map_err(|e| PrefixdError::Config(format!("playbooks: {}", e)))?;
            *self.playbooks.write().await = new_playbooks;
            *self.playbooks_loaded_at.write().await = Utc::now();
            reloaded.push("playbooks".to_string());
            tracing::info!("reloaded playbooks.yaml");
        }

        Ok(reloaded)
    }
}
