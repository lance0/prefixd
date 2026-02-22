use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;

use crate::alerting::AlertingService;
use crate::bgp::FlowSpecAnnouncer;
use crate::db::RepositoryTrait;
use crate::domain::{FlowSpecAction, FlowSpecNlri, FlowSpecRule, MitigationStatus};
use crate::ws::WsMessage;
use tokio::sync::RwLock;

pub struct ReconciliationLoop {
    repo: Arc<dyn RepositoryTrait>,
    announcer: Arc<dyn FlowSpecAnnouncer>,
    interval: Duration,
    dry_run: bool,
    ws_broadcast: Option<broadcast::Sender<WsMessage>>,
    alerting: Option<Arc<RwLock<Arc<AlertingService>>>>,
}

impl ReconciliationLoop {
    pub fn new(
        repo: Arc<dyn RepositoryTrait>,
        announcer: Arc<dyn FlowSpecAnnouncer>,
        interval_seconds: u32,
        dry_run: bool,
    ) -> Self {
        Self {
            repo,
            announcer,
            interval: Duration::from_secs(interval_seconds as u64),
            dry_run,
            ws_broadcast: None,
            alerting: None,
        }
    }

    /// Set the WebSocket broadcast sender for real-time notifications
    pub fn with_ws_broadcast(mut self, sender: broadcast::Sender<WsMessage>) -> Self {
        self.ws_broadcast = Some(sender);
        self
    }

    pub fn with_alerting(mut self, alerting: Arc<RwLock<Arc<AlertingService>>>) -> Self {
        self.alerting = Some(alerting);
        self
    }

    pub async fn run(&self, mut shutdown: broadcast::Receiver<()>) {
        tracing::info!(
            interval_secs = self.interval.as_secs(),
            dry_run = self.dry_run,
            "starting reconciliation loop"
        );

        // Initial reconciliation
        if let Err(e) = self.reconcile().await {
            tracing::error!(error = %e, "initial reconciliation failed");
        }

        let mut interval = tokio::time::interval(self.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = self.reconcile().await {
                        tracing::error!(error = %e, "reconciliation failed");
                    }
                }
                _ = shutdown.recv() => {
                    tracing::info!("reconciliation loop shutting down");
                    break;
                }
            }
        }
    }

    /// Run one reconciliation cycle (for testing)
    pub async fn reconcile(&self) -> anyhow::Result<()> {
        // 1. Expire mitigations past TTL
        self.expire_mitigations().await?;

        // 2. Sync desired vs actual state
        self.sync_announcements().await?;

        Ok(())
    }

    async fn expire_mitigations(&self) -> anyhow::Result<()> {
        let expired = self.repo.find_expired_mitigations().await?;

        for mut mitigation in expired {
            tracing::info!(
                mitigation_id = %mitigation.mitigation_id,
                victim_ip = %mitigation.victim_ip,
                "expiring mitigation"
            );

            // Withdraw BGP announcement
            if !self.dry_run {
                let rule = self.build_flowspec_rule(&mitigation);
                if let Err(e) = self.announcer.withdraw(&rule).await {
                    tracing::warn!(
                        mitigation_id = %mitigation.mitigation_id,
                        error = %e,
                        "failed to withdraw expired mitigation"
                    );
                }
            }

            // Update status
            mitigation.expire();
            self.repo.update_mitigation(&mitigation).await?;

            // Broadcast expiry via WebSocket
            if let Some(ref tx) = self.ws_broadcast {
                let _ = tx.send(WsMessage::MitigationExpired {
                    mitigation_id: mitigation.mitigation_id.to_string(),
                });
            }

            if let Some(ref alerting_lock) = self.alerting {
                let alerting = alerting_lock.read().await.clone();
                alerting.notify(crate::alerting::Alert::mitigation_expired(&mitigation));
            }
        }

        Ok(())
    }

    async fn sync_announcements(&self) -> anyhow::Result<()> {
        // Page through all active mitigations (no cap)
        let mut active = Vec::new();
        let page_size: u32 = 500;
        let mut offset: u32 = 0;
        loop {
            let page = self
                .repo
                .list_mitigations(
                    Some(&[MitigationStatus::Active, MitigationStatus::Escalated]),
                    None,
                    page_size,
                    offset,
                )
                .await?;
            let done = (page.len() as u32) < page_size;
            active.extend(page);
            if done {
                break;
            }
            offset += page_size;
        }

        crate::observability::metrics::RECONCILIATION_ACTIVE_COUNT
            .with_label_values(&["local"])
            .set(active.len() as f64);

        // Get actual state from BGP
        let announced = self.announcer.list_active().await?;
        let announced_hashes: std::collections::HashSet<_> =
            announced.iter().map(|r| r.nlri_hash()).collect();

        // Re-announce missing rules
        for mitigation in &active {
            let rule = self.build_flowspec_rule(mitigation);
            let hash = rule.nlri_hash();

            if !announced_hashes.contains(&hash) {
                tracing::warn!(
                    mitigation_id = %mitigation.mitigation_id,
                    nlri_hash = %hash,
                    "re-announcing missing rule"
                );

                if !self.dry_run {
                    if let Err(e) = self.announcer.announce(&rule).await {
                        tracing::error!(
                            mitigation_id = %mitigation.mitigation_id,
                            error = %e,
                            "failed to re-announce"
                        );
                    }
                }
            }
        }

        // Alert on unknown routes (routes in BGP not tracked by us)
        let desired_hashes: std::collections::HashSet<_> = active
            .iter()
            .map(|m| self.build_flowspec_rule(m).nlri_hash())
            .collect();

        for rule in &announced {
            if !desired_hashes.contains(&rule.nlri_hash()) {
                tracing::warn!(
                    nlri_hash = %rule.nlri_hash(),
                    dst_prefix = %rule.nlri.dst_prefix,
                    "unknown route in BGP RIB"
                );
            }
        }

        Ok(())
    }

    fn build_flowspec_rule(&self, m: &crate::domain::Mitigation) -> FlowSpecRule {
        let nlri = FlowSpecNlri::from(&m.match_criteria);
        let action = FlowSpecAction::from((m.action_type, &m.action_params));
        FlowSpecRule::new(nlri, action)
    }
}
