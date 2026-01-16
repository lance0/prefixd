use std::sync::Arc;
use tokio::sync::broadcast;

use crate::bgp::FlowSpecAnnouncer;
use crate::config::{Inventory, Playbooks, Settings};
use crate::db::Repository;

/// Shared application state
pub struct AppState {
    pub settings: Settings,
    pub inventory: Inventory,
    pub playbooks: Playbooks,
    pub repo: Repository,
    pub announcer: Arc<dyn FlowSpecAnnouncer>,
    pub shutdown_tx: broadcast::Sender<()>,
}

impl AppState {
    pub fn new(
        settings: Settings,
        inventory: Inventory,
        playbooks: Playbooks,
        repo: Repository,
        announcer: Arc<dyn FlowSpecAnnouncer>,
    ) -> Arc<Self> {
        let (shutdown_tx, _) = broadcast::channel(1);

        Arc::new(Self {
            settings,
            inventory,
            playbooks,
            repo,
            announcer,
            shutdown_tx,
        })
    }

    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    pub fn trigger_shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    pub fn is_dry_run(&self) -> bool {
        matches!(self.settings.mode, crate::config::OperationMode::DryRun)
    }
}
