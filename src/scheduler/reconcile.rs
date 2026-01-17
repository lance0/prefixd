use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;

use crate::bgp::FlowSpecAnnouncer;
use crate::db::RepositoryTrait;
use crate::domain::{FlowSpecAction, FlowSpecNlri, FlowSpecRule, MitigationStatus};

pub struct ReconciliationLoop {
    repo: Arc<dyn RepositoryTrait>,
    announcer: Arc<dyn FlowSpecAnnouncer>,
    interval: Duration,
    dry_run: bool,
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
        }
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
        }

        Ok(())
    }

    async fn sync_announcements(&self) -> anyhow::Result<()> {
        // Get desired state: active mitigations
        let active = self
            .repo
            .list_mitigations(
                Some(&[MitigationStatus::Active, MitigationStatus::Escalated]),
                None,
                1000,
                0,
            )
            .await?;

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
