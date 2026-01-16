use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

use crate::bgp::FlowSpecAnnouncer;
use crate::config::{Inventory, Playbooks, Settings};
use crate::db::Repository;
use crate::error::{PrefixdError, Result};

/// Shared application state
pub struct AppState {
    pub settings: Settings,
    pub inventory: RwLock<Inventory>,
    pub playbooks: RwLock<Playbooks>,
    pub repo: Repository,
    pub announcer: Arc<dyn FlowSpecAnnouncer>,
    pub shutdown_tx: broadcast::Sender<()>,
    config_dir: PathBuf,
    shutting_down: AtomicBool,
}

impl AppState {
    pub fn new(
        settings: Settings,
        inventory: Inventory,
        playbooks: Playbooks,
        repo: Repository,
        announcer: Arc<dyn FlowSpecAnnouncer>,
        config_dir: PathBuf,
    ) -> Arc<Self> {
        let (shutdown_tx, _) = broadcast::channel(1);

        Arc::new(Self {
            settings,
            inventory: RwLock::new(inventory),
            playbooks: RwLock::new(playbooks),
            repo,
            announcer,
            shutdown_tx,
            config_dir,
            shutting_down: AtomicBool::new(false),
        })
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
            reloaded.push("inventory".to_string());
            tracing::info!("reloaded inventory.yaml");
        }

        // Reload playbooks
        let playbooks_path = self.config_dir.join("playbooks.yaml");
        if playbooks_path.exists() {
            let new_playbooks = Playbooks::load(&playbooks_path)
                .map_err(|e| PrefixdError::Config(format!("playbooks: {}", e)))?;
            *self.playbooks.write().await = new_playbooks;
            reloaded.push("playbooks".to_string());
            tracing::info!("reloaded playbooks.yaml");
        }

        Ok(reloaded)
    }
}
