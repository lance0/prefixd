use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;

use crate::alerting::AlertingService;
use crate::bgp::FlowSpecAnnouncer;
use crate::correlation::{CorrelationEngine, SignalGroupStatus};
use crate::db::RepositoryTrait;
use crate::domain::{
    FlowSpecAction, FlowSpecNlri, FlowSpecRule, MitigationStatus, execute_withdrawal,
    ownership_key, request_withdrawal,
};
use crate::state::AppState;
use crate::ws::WsMessage;
use tokio::sync::RwLock;

fn wire_action(rule: &FlowSpecRule) -> crate::error::Result<u32> {
    let [action] = rule.actions.as_slice() else {
        return Err(crate::error::PrefixdError::BgpAnnouncementFailed(
            "exactly one traffic rate action is required".into(),
        ));
    };
    action
        .traffic_rate_bytes_per_second()
        .map(f32::to_bits)
        .map_err(|error| crate::error::PrefixdError::BgpAnnouncementFailed(error.to_string()))
}

fn pending_ownership_keys(
    requests: &[crate::domain::WithdrawalRequest],
) -> anyhow::Result<std::collections::HashSet<String>> {
    requests
        .iter()
        .map(|request| {
            let rule: FlowSpecRule = serde_json::from_str(&request.rule_json)?;
            anyhow::ensure!(
                rule.nlri_hash() == request.nlri_hash,
                "withdrawal rule identity does not match persisted intent"
            );
            Ok(ownership_key(&rule))
        })
        .collect()
}

pub struct ReconciliationLoop {
    repo: Arc<dyn RepositoryTrait>,
    announcer: Arc<dyn FlowSpecAnnouncer>,
    interval: Duration,
    dry_run: bool,
    ws_broadcast: Option<broadcast::Sender<WsMessage>>,
    alerting: Option<Arc<RwLock<Arc<AlertingService>>>>,
    /// Shared application state — used by the ADR 022 confidence-decay
    /// refresh path to read the current correlation config + playbooks
    /// on each tick (so hot-reloads propagate without restart). Optional
    /// so test harnesses can construct the loop standalone.
    state: Option<Arc<AppState>>,
    /// Explicit repository proof for standalone fixtures; real speakers cannot be unbound.
    speaker_binding: Option<crate::domain::VerifiedSpeakerBinding>,
    /// Set of source labels we last set on
    /// `CORROBORATOR_CACHE_SIZE`. Used to zero-out gauges when a
    /// source's cache drains to empty between ticks (Prometheus would
    /// otherwise keep the last non-zero value forever).
    last_cache_sources: tokio::sync::Mutex<std::collections::HashSet<String>>,
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
            state: None,
            speaker_binding: None,
            last_cache_sources: tokio::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// Wire the shared `AppState` for paths that need live access to the
    /// correlation config or playbooks (currently: ADR 022 confidence
    /// decay refresh). Without this, decay refresh is a no-op and
    /// `derived_confidence` is only updated on event ingest.
    pub fn with_app_state(mut self, state: Arc<AppState>) -> Self {
        self.state = Some(state);
        self
    }

    pub fn with_speaker_binding(mut self, binding: crate::domain::VerifiedSpeakerBinding) -> Self {
        self.speaker_binding = Some(binding);
        self
    }

    fn verified_speaker_binding(
        &self,
    ) -> crate::error::Result<Option<&crate::domain::VerifiedSpeakerBinding>> {
        if let Some(state) = &self.state {
            if !Arc::ptr_eq(&self.announcer, &state.announcer)
                || !Arc::ptr_eq(&self.repo, &state.repo)
            {
                return Err(crate::domain::binding_mismatch());
            }
            return state.verified_speaker_binding();
        }
        match &self.speaker_binding {
            Some(binding) => {
                binding.validate_backend(self.announcer.backend())?;
                Ok(Some(binding))
            }
            None if self.announcer.backend() == "mock" => Ok(None),
            None => Err(crate::domain::binding_mismatch()),
        }
    }

    fn owning_pop(&self) -> Option<&str> {
        self.state
            .as_ref()
            .map(|state| state.settings.pop.as_str())
            .or_else(|| {
                self.speaker_binding
                    .as_ref()
                    .map(crate::domain::VerifiedSpeakerBinding::pop)
            })
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
        match self.reconcile().await {
            Ok(()) => {
                crate::observability::metrics::RECONCILIATION_RUNS
                    .with_label_values(&["success"])
                    .inc();
            }
            Err(e) => {
                crate::observability::metrics::RECONCILIATION_RUNS
                    .with_label_values(&["error"])
                    .inc();
                tracing::error!(error = %e, "initial reconciliation failed");
            }
        }

        let mut interval =
            tokio::time::interval_at(tokio::time::Instant::now() + self.interval, self.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match self.reconcile().await {
                        Ok(()) => {
                            crate::observability::metrics::RECONCILIATION_RUNS
                                .with_label_values(&["success"])
                                .inc();
                        }
                        Err(e) => {
                            crate::observability::metrics::RECONCILIATION_RUNS
                                .with_label_values(&["error"])
                                .inc();
                            tracing::error!(error = %e, "reconciliation failed");
                        }
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
        self.verified_speaker_binding()?;
        let mut failure = None;
        // Each stage is independent; a speaker failure must not stop expiry or health updates.
        for (stage, result) in [
            ("withdrawals", self.expire_mitigations().await),
            ("signal groups", self.expire_signal_groups().await),
            ("corroborator cache", self.sweep_corroborator_cache().await),
            ("confidence", self.refresh_decayed_confidence().await),
            ("announcements", self.sync_announcements().await),
        ] {
            if let Err(error) = result {
                tracing::warn!(stage, error = %error, "reconciliation stage failed");
                failure = Some(error);
            }
        }
        self.update_bgp_session_metrics().await;
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    async fn expire_mitigations(&self) -> anyhow::Result<()> {
        let binding = self.verified_speaker_binding()?;
        let pop = self.owning_pop();
        let pending = self.repo.pending_withdrawals(pop).await?;
        let mut candidates: Vec<_> = pending
            .into_iter()
            .map(|request| (request.mitigation_id, Some(request)))
            .collect();
        let mut failure = None;
        match self.repo.expired_mitigation_inventory(pop).await {
            Ok(expired) => {
                for mitigation in expired {
                    if pop.is_none_or(|pop| mitigation.pop == pop)
                        && !candidates
                            .iter()
                            .any(|(id, _)| *id == mitigation.mitigation_id)
                    {
                        candidates.push((mitigation.mitigation_id, None));
                    }
                }
            }
            Err(error) => failure = Some(error.into()),
        }
        for (id, request) in candidates {
            let _guard = match &self.state {
                Some(state) => Some(state.mitigation_lock.lock().await),
                None => None,
            };
            let current = match self.repo.get_mitigation(id).await {
                Ok(Some(mitigation))
                    if mitigation.is_active() && pop.is_none_or(|pop| mitigation.pop == pop) =>
                {
                    mitigation
                }
                Ok(_) => continue,
                Err(error) => {
                    failure = Some(error.into());
                    continue;
                }
            };
            let request = match request {
                Some(request) => request,
                None if current.expires_at > chrono::Utc::now() => continue,
                None => match request_withdrawal(
                    self.repo.as_ref(),
                    &current,
                    true,
                    "system",
                    "scheduler",
                    "TTL expired".into(),
                    !self.dry_run,
                    binding,
                )
                .await
                {
                    Ok(request) => request,
                    Err(error) => {
                        failure = Some(error.into());
                        continue;
                    }
                },
            };
            let mitigation = match execute_withdrawal(
                self.repo.as_ref(),
                self.announcer.as_ref(),
                self.dry_run,
                &request,
                binding,
            )
            .await
            {
                Ok(mitigation) => mitigation,
                Err(error) => {
                    tracing::warn!(mitigation_id = %request.mitigation_id, error = %error, "withdrawal remains pending");
                    failure = Some(error.into());
                    continue;
                }
            };
            let message = if request.is_expiry() {
                crate::observability::metrics::MITIGATIONS_EXPIRED
                    .with_label_values(&[&mitigation.action_type.to_string(), &mitigation.pop])
                    .inc();
                WsMessage::MitigationExpired {
                    mitigation_id: mitigation.mitigation_id.to_string(),
                }
            } else {
                crate::observability::metrics::MITIGATIONS_WITHDRAWN
                    .with_label_values(&[
                        mitigation.action_type.to_string().as_str(),
                        mitigation.pop.as_str(),
                        if request.actor_type == "detector" {
                            "detector_unban"
                        } else {
                            "operator"
                        },
                    ])
                    .inc();
                WsMessage::MitigationWithdrawn {
                    mitigation_id: mitigation.mitigation_id.to_string(),
                }
            };
            if let Some(tx) = &self.ws_broadcast {
                let _ = tx.send(message);
            }
            if let Some(alerting) = &self.alerting {
                let alert = if request.is_expiry() {
                    crate::alerting::Alert::mitigation_expired(&mitigation)
                } else {
                    crate::alerting::Alert::mitigation_withdrawn(&mitigation)
                };
                alerting.read().await.notify(alert);
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    async fn expire_signal_groups(&self) -> anyhow::Result<()> {
        let expired = self.repo.find_expired_signal_groups().await?;

        for mut group in expired {
            tracing::info!(
                group_id = %group.group_id,
                victim_ip = %group.victim_ip,
                vector = %group.vector,
                source_count = group.source_count,
                "expiring signal group (corroboration timeout)"
            );

            group.status = SignalGroupStatus::Expired;
            self.repo.update_signal_group(&group).await?;

            // Increment timeout metric
            crate::observability::metrics::CORROBORATION_TIMEOUT_TOTAL
                .with_label_values(&[&group.vector])
                .inc();

            // Record source count for expired group
            crate::observability::metrics::SIGNAL_GROUP_SOURCES
                .with_label_values(&[&group.vector])
                .observe(group.source_count as f64);
        }

        Ok(())
    }

    async fn sweep_corroborator_cache(&self) -> anyhow::Result<()> {
        // Clean expired rows from the corroborating_signals cache. The
        // repository splits the delete into unattached (per-source) vs
        // attached: only true cache misses (ingested, never matched any
        // group, timed out) charge `CORROBORATOR_EXPIRED_TOTAL{source}`.
        // Attached rows are GC'd silently — their audit trail already
        // lives on signal_group_events.
        //
        // After the sweep we also refresh `CORROBORATOR_CACHE_SIZE{source}`
        // so operators can alert on caches growing without bound.
        let now = chrono::Utc::now();
        let stats = self.repo.delete_expired_corroborating_signals(now).await?;
        let unattached_total = stats.unattached_total();
        let total = unattached_total + stats.attached_expired;
        if total > 0 {
            tracing::info!(
                unattached_expired = unattached_total,
                attached_expired = stats.attached_expired,
                "swept expired corroborating signals from cache"
            );
            for (source, count) in &stats.unattached_expired {
                crate::observability::metrics::CORROBORATOR_EXPIRED_TOTAL
                    .with_label_values(&[source.as_str()])
                    .inc_by(*count as f64);
            }
        }

        // Refresh the cache_size gauge: zero out previous values for
        // sources that no longer have rows, then set per-source counts.
        let by_source = self.repo.count_cached_corroborators_by_source(now).await?;
        let live_sources: std::collections::HashSet<String> =
            by_source.iter().map(|(s, _)| s.clone()).collect();
        let mut last = self.last_cache_sources.lock().await;
        for stale in last.difference(&live_sources) {
            crate::observability::metrics::CORROBORATOR_CACHE_SIZE
                .with_label_values(&[stale.as_str()])
                .set(0.0);
        }
        for (source, count) in &by_source {
            crate::observability::metrics::CORROBORATOR_CACHE_SIZE
                .with_label_values(&[source.as_str()])
                .set(*count as f64);
        }
        *last = live_sources;
        Ok(())
    }

    /// ADR 022: re-compute and persist `derived_confidence` on every open
    /// signal group using the configured exponential half-life. Skipped
    /// when correlation config / playbooks aren't wired (e.g. in tests)
    /// or when decay is disabled (`half_life_seconds == 0`).
    ///
    /// Enforces one-shot `corroboration_met` semantics: a group whose
    /// flag is already true is never flipped back to false by decay,
    /// even if its decayed confidence drops below threshold. Decay only
    /// affects the stored value.
    async fn refresh_decayed_confidence(&self) -> anyhow::Result<()> {
        let Some(state) = self.state.as_ref() else {
            return Ok(());
        };

        let cfg = state.correlation_config.read().await.clone();
        if cfg.confidence_decay_half_life_seconds == 0 {
            return Ok(());
        }

        let groups = self.repo.list_open_signal_groups().await?;
        if groups.is_empty() {
            crate::observability::metrics::SIGNAL_GROUP_DECAY_REFRESHES_TOTAL.inc();
            return Ok(());
        }

        let playbooks = state.playbooks.read().await.clone();
        let now = chrono::Utc::now();

        for group in groups {
            let events = self.repo.list_signal_group_events(group.group_id).await?;
            if events.is_empty() {
                continue;
            }

            let resolved_playbook = group
                .playbook_name
                .as_deref()
                .and_then(|name| playbooks.playbooks.iter().find(|p| p.name == name));
            let override_ = resolved_playbook.and_then(|p| p.correlation.as_ref());
            let half_life = cfg.effective_decay_half_life(override_);
            if half_life == 0 {
                continue;
            }

            let triples: Vec<crate::correlation::ConfidenceTriple> = events
                .iter()
                .map(|e| (e.confidence, e.source_weight, e.ingested_at))
                .collect();
            let new_derived =
                CorrelationEngine::compute_derived_confidence_decayed(&triples, now, half_life);

            // Skip rewrite when nothing meaningful changed (avoids
            // churning the row + WAL on idle groups).
            if (new_derived - group.derived_confidence).abs() < 0.0005 {
                continue;
            }

            let mut updated = group;
            updated.derived_confidence = new_derived;
            // corroboration_met is sticky once true (ADR 022); the field
            // is left as-is. source_count is unaffected by decay.
            self.repo.update_signal_group(&updated).await?;
        }

        crate::observability::metrics::SIGNAL_GROUP_DECAY_REFRESHES_TOTAL.inc();
        Ok(())
    }

    async fn sync_announcements(&self) -> anyhow::Result<()> {
        use std::collections::{HashMap, HashSet};

        self.verified_speaker_binding()?;
        // An unreadable withdrawal ledger cannot safely authorize a repair.
        let pop = self.owning_pop();
        let pending = self.repo.pending_withdrawals(pop).await?;
        let pending_keys = pending_ownership_keys(&pending)?;
        let mut active = self.repo.active_mitigation_inventory(pop).await?;
        active.retain(|mitigation| {
            mitigation.is_active() && pop.is_none_or(|pop| mitigation.pop == pop)
        });
        // Pending and expired siblings still make ownership ambiguous.
        let mut owner_counts = HashMap::<String, usize>::new();
        for mitigation in &active {
            *owner_counts
                .entry(ownership_key(&self.build_flowspec_rule(mitigation)))
                .or_default() += 1;
        }
        active.retain(|mitigation| {
            matches!(
                mitigation.status,
                MitigationStatus::Active | MitigationStatus::Escalated
            ) && pop.is_none_or(|pop| mitigation.pop == pop)
        });

        crate::observability::metrics::RECONCILIATION_ACTIVE_COUNT
            .with_label_values(&["local"])
            .set(active.len() as f64);

        {
            use std::collections::HashMap;
            let mut counts: HashMap<(String, String), f64> = HashMap::new();
            for m in &active {
                *counts
                    .entry((m.action_type.to_string(), m.pop.clone()))
                    .or_default() += 1.0;
            }
            crate::observability::metrics::MITIGATIONS_ACTIVE.reset();
            for ((action_type, pop), count) in &counts {
                crate::observability::metrics::MITIGATIONS_ACTIVE
                    .with_label_values(&[action_type, pop])
                    .set(*count);
            }
        }

        let now = chrono::Utc::now();
        // Simulations are never desired speaker state, even after a mode switch.
        active.retain(|mitigation| {
            !mitigation.is_dry_run_origin()
                && mitigation.expires_at > now
                && !pending_keys.contains(&ownership_key(&self.build_flowspec_rule(mitigation)))
        });

        let Some(reader) = self.announcer.reader() else {
            tracing::debug!(
                backend = self.announcer.backend(),
                "rule observation unsupported; repair skipped"
            );
            return Ok(());
        };
        let announced = reader.list_active().await?;
        let mut announced_actions = HashMap::new();
        // Complete validation precedes every repair, including unknown local rows.
        for rule in &announced {
            let action = wire_action(rule)?;
            anyhow::ensure!(
                announced_actions
                    .insert(rule.nlri_hash(), (rule, action))
                    .is_none(),
                "speaker inventory has multiple local rules for one NLRI"
            );
        }

        // Upsert only uniquely owned missing or differing-action intent.
        let mut repair_error = None;
        for candidate in &active {
            let candidate_rule = self.build_flowspec_rule(candidate);
            let key = ownership_key(&candidate_rule);
            let nlri_hash = candidate_rule.nlri_hash();
            if owner_counts[&key] != 1 {
                tracing::warn!(mitigation_id = %candidate.mitigation_id,
                    "announcement repair blocked by multiple active owners");
                repair_error = Some(crate::error::PrefixdError::Conflict(
                    "FlowSpec rule has multiple active owners".into(),
                ));
                continue;
            }
            let action = match wire_action(&candidate_rule) {
                Ok(action) => action,
                Err(error) => {
                    repair_error = Some(error);
                    continue;
                }
            };
            if let Some((observed, observed_action)) = announced_actions.get(&nlri_hash) {
                match self
                    .announcer
                    .matches_nlri(&candidate_rule.nlri, &observed.nlri)
                {
                    Ok(true) => {}
                    Ok(false) => {
                        repair_error = Some(crate::error::PrefixdError::Conflict(
                            "observed FlowSpec match differs from the saved backend match".into(),
                        ));
                        continue;
                    }
                    Err(error) => {
                        repair_error = Some(error);
                        continue;
                    }
                }
                if observed_action == &action {
                    continue;
                }
            }
            let _guard = match &self.state {
                Some(state) => Some(state.mitigation_lock.lock().await),
                None => None,
            };
            let mitigation = match self.repo.get_mitigation(candidate.mitigation_id).await {
                Ok(Some(mitigation))
                    if mitigation.mitigation_id == candidate.mitigation_id
                        && mitigation.pop == candidate.pop
                        && matches!(
                            mitigation.status,
                            MitigationStatus::Active | MitigationStatus::Escalated
                        )
                        && mitigation.expires_at > chrono::Utc::now()
                        && pop.is_none_or(|pop| mitigation.pop == pop) =>
                {
                    mitigation
                }
                Ok(_) => continue,
                Err(error) => {
                    repair_error = Some(error);
                    continue;
                }
            };
            let rule = self.build_flowspec_rule(&mitigation);
            if rule.nlri_hash() != nlri_hash {
                continue;
            }
            match self
                .announcer
                .matches_nlri(&candidate_rule.nlri, &rule.nlri)
            {
                Ok(true) => {}
                Ok(false) => continue,
                Err(error) => {
                    repair_error = Some(error);
                    continue;
                }
            }
            let current_pending = self.repo.pending_withdrawals(pop).await?;
            if pending_ownership_keys(&current_pending)?.contains(&key)
                || current_pending
                    .iter()
                    .any(|request| request.mitigation_id == mitigation.mitigation_id)
            {
                continue;
            }
            let action = match wire_action(&rule) {
                Ok(action) => action,
                Err(error) => {
                    repair_error = Some(error);
                    continue;
                }
            };
            self.verified_speaker_binding()?;
            if mitigation.expires_at <= chrono::Utc::now() {
                continue;
            }
            if announced_actions.get(&nlri_hash).map(|(_, action)| action) != Some(&action) {
                tracing::warn!(
                    mitigation_id = %mitigation.mitigation_id,
                    nlri_hash = %rule.nlri_hash(),
                    reason = if announced_actions.contains_key(&nlri_hash) { "action_drift" } else { "missing" },
                    "repairing local announcement"
                );

                if !self.dry_run {
                    let start = std::time::Instant::now();
                    if let Err(e) = self.announcer.announce(&rule).await {
                        crate::observability::metrics::RECONCILIATION_REPAIRS
                            .with_label_values(&["error"])
                            .inc();
                        tracing::error!(
                            mitigation_id = %mitigation.mitigation_id,
                            error = %e,
                            "failed to re-announce"
                        );
                        repair_error = Some(e);
                    } else {
                        crate::observability::metrics::RECONCILIATION_REPAIRS
                            .with_label_values(&["success"])
                            .inc();
                        crate::observability::metrics::ANNOUNCEMENTS_TOTAL
                            .with_label_values(&["announced"])
                            .inc();
                        crate::observability::metrics::ANNOUNCEMENTS_LATENCY
                            .observe(start.elapsed().as_secs_f64());
                    }
                }
            }
        }

        // Alert on unknown routes (routes in BGP not tracked by us)
        let desired_hashes: HashSet<_> = active
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

        match repair_error {
            Some(error) => Err(error.into()),
            None => Ok(()),
        }
    }

    async fn update_bgp_session_metrics(&self) {
        let Some(observer) = self.announcer.peer_observer() else {
            return;
        };
        match observer.session_status().await {
            Ok(peers) => {
                for peer in &peers {
                    let value = if peer.state.is_established() {
                        1.0
                    } else {
                        0.0
                    };
                    crate::observability::metrics::BGP_SESSION_UP
                        .with_label_values(&[&peer.name])
                        .set(value);
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to fetch BGP session status for metrics");
            }
        }
    }

    fn build_flowspec_rule(&self, m: &crate::domain::Mitigation) -> FlowSpecRule {
        let nlri = FlowSpecNlri::from(&m.match_criteria);
        let action = FlowSpecAction::from((m.action_type, &m.action_params));
        FlowSpecRule::new(nlri, action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bgp::{FlowSpecReader, FlowSpecWriter, MockAnnouncer, PeerObserver, PeerStatus},
        db::MockRepository,
        domain::{
            ActionParams, ActionType, AttackVector, MatchCriteria, Mitigation, MitigationIntent,
        },
        error::{PrefixdError, Result},
    };
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

    // Reconciliation resets process-global Prometheus gauges.
    static RECONCILIATION_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct FailingWithdrawal {
        inner: MockAnnouncer,
        mode: AtomicUsize,
        announcements: AtomicUsize,
        inventories: AtomicUsize,
    }

    impl FlowSpecAnnouncer for FailingWithdrawal {
        fn backend(&self) -> &'static str {
            "mock"
        }
        fn reader(&self) -> Option<&dyn FlowSpecReader> {
            Some(self)
        }
        fn peer_observer(&self) -> Option<&dyn PeerObserver> {
            Some(self)
        }
    }

    #[async_trait::async_trait]
    impl FlowSpecWriter for FailingWithdrawal {
        async fn announce(&self, rule: &FlowSpecRule) -> Result<()> {
            self.announcements.fetch_add(1, SeqCst);
            if self.mode.load(SeqCst) == 3 && rule.nlri.dst_prefix == "192.0.2.1/32" {
                return Err(PrefixdError::BgpAnnouncementFailed(
                    "temporary repair failure".into(),
                ));
            }
            self.inner.announce(rule).await?;
            if self.mode.load(SeqCst) == 6 && rule.nlri.dst_prefix == "192.0.2.1/32" {
                return Err(PrefixdError::BgpAnnouncementFailed(
                    "accepted repair with lost acknowledgement".into(),
                ));
            }
            Ok(())
        }
        async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()> {
            let mode = self.mode.load(SeqCst);
            if rule.nlri.dst_prefix == "192.0.2.1/32" && mode != 0 {
                if mode == 2 {
                    self.inner.withdraw(rule).await?;
                }
                return Err(PrefixdError::BgpWithdrawalFailed(
                    "temporary failure".into(),
                ));
            }
            self.inner.withdraw(rule).await
        }
    }
    #[async_trait::async_trait]
    impl FlowSpecReader for FailingWithdrawal {
        async fn list_active(&self) -> Result<Vec<FlowSpecRule>> {
            self.inventories.fetch_add(1, SeqCst);
            if self.mode.load(SeqCst) == 4 {
                return Err(PrefixdError::BgpAnnouncementFailed(
                    "inventory unavailable".into(),
                ));
            }
            let mut rules = self.inner.list_active().await?;
            match self.mode.load(SeqCst) {
                7 => rules.push(rules[0].clone()),
                8..=10 => {
                    let mut unsupported = rules[0].clone();
                    unsupported.nlri.dst_prefix = "192.0.2.254/32".into();
                    unsupported.actions = match self.mode.load(SeqCst) {
                        8 => vec![],
                        9 => vec![FlowSpecAction::police(16_777_217)],
                        _ => vec![FlowSpecAction::discard(), FlowSpecAction::police(8)],
                    };
                    rules.push(unsupported);
                }
                _ => {}
            }
            Ok(rules)
        }
    }
    #[async_trait::async_trait]
    impl PeerObserver for FailingWithdrawal {
        async fn session_status(&self) -> Result<Vec<PeerStatus>> {
            if self.mode.load(SeqCst) == 5 {
                return Err(PrefixdError::BgpAnnouncementFailed(
                    "peers unavailable".into(),
                ));
            }
            self.inner.session_status().await
        }
    }

    fn expired_mitigation(ip: &str) -> Mitigation {
        let mut mitigation = Mitigation::from_intent(
            MitigationIntent {
                event_id: uuid::Uuid::new_v4(),
                customer_id: None,
                service_id: None,
                pop: "test".into(),
                match_criteria: MatchCriteria {
                    dst_prefix: format!("{ip}/32"),
                    protocol: Some(17),
                    dst_ports: vec![53],
                },
                action_type: ActionType::Discard,
                action_params: ActionParams { rate_bps: None },
                ttl_seconds: 30,
                reason: "test".into(),
            },
            ip.into(),
            AttackVector::UdpFlood,
        );
        mitigation.activate();
        mitigation.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
        mitigation
    }

    // Deliberately implements no observation traits: writing alone is sufficient.
    #[derive(Default)]
    struct WriteOnly {
        announcements: AtomicUsize,
        withdrawals: AtomicUsize,
    }

    impl FlowSpecAnnouncer for WriteOnly {
        fn backend(&self) -> &'static str {
            "mock"
        }
    }

    #[async_trait::async_trait]
    impl FlowSpecWriter for WriteOnly {
        async fn announce(&self, _: &FlowSpecRule) -> Result<()> {
            self.announcements.fetch_add(1, SeqCst);
            Ok(())
        }
        async fn withdraw(&self, _: &FlowSpecRule) -> Result<()> {
            self.withdrawals.fetch_add(1, SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn write_only_speaker_skips_repairs_but_finishes_cleanup_and_updates_counts() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(WriteOnly::default());
        let selected: &dyn FlowSpecAnnouncer = speaker.as_ref();
        assert!(!selected.capabilities().rule_reader);
        assert!(!selected.capabilities().peer_observer);
        let expired = expired_mitigation("192.0.2.1");
        let mut active = expired_mitigation("192.0.2.2");
        active.expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);
        let mut pending = expired_mitigation("192.0.2.3");
        pending.expires_at = active.expires_at;
        for mitigation in [&expired, &active, &pending] {
            repo.insert_mitigation(mitigation).await.unwrap();
        }
        request_withdrawal(
            repo.as_ref(),
            &pending,
            false,
            "operator",
            "test",
            "cleanup".into(),
            true,
            None,
        )
        .await
        .unwrap();
        let peer =
            crate::observability::metrics::BGP_SESSION_UP.with_label_values(&["write-only-peer"]);
        peer.set(1.0);
        let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false);
        for _ in 0..2 {
            reconciler.reconcile().await.unwrap();
        }
        assert_eq!(speaker.announcements.load(SeqCst), 0);
        assert_eq!(speaker.withdrawals.load(SeqCst), 2);
        assert_eq!(
            repo.get_mitigation(expired.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            MitigationStatus::Expired
        );
        assert_eq!(
            repo.get_mitigation(pending.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            MitigationStatus::Withdrawn
        );
        assert!(repo.pending_withdrawals(None).await.unwrap().is_empty());
        assert_eq!(
            crate::observability::metrics::MITIGATIONS_ACTIVE
                .with_label_values(&["discard", "test"])
                .get(),
            1.0
        );
        assert_eq!(
            crate::observability::metrics::RECONCILIATION_ACTIVE_COUNT
                .with_label_values(&["local"])
                .get(),
            1.0
        );
        assert_eq!(peer.get(), 1.0);
    }

    #[tokio::test]
    async fn supported_reader_failure_is_an_error_without_repairs_and_cleanup_continues() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(FailingWithdrawal {
            inner: MockAnnouncer::new(),
            mode: AtomicUsize::new(4),
            announcements: AtomicUsize::new(0),
            inventories: AtomicUsize::new(0),
        });
        let expired = expired_mitigation("192.0.2.2");
        let mut active = expired_mitigation("192.0.2.3");
        active.expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);
        for mitigation in [&expired, &active] {
            repo.insert_mitigation(mitigation).await.unwrap();
        }
        let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false);
        assert!(reconciler.reconcile().await.is_err());
        assert_eq!(
            repo.get_mitigation(expired.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            MitigationStatus::Expired
        );
        assert_eq!(speaker.announcements.load(SeqCst), 0);
        let errors =
            crate::observability::metrics::RECONCILIATION_RUNS.with_label_values(&["error"]);
        let before = errors.get();
        let (shutdown, rx) = broadcast::channel(1);
        shutdown.send(()).unwrap();
        reconciler.run(rx).await;
        assert_eq!(errors.get(), before + 1.0);
        assert_eq!(speaker.inventories.load(SeqCst), 2);
        assert_eq!(speaker.announcements.load(SeqCst), 0);
    }

    #[tokio::test]
    async fn supported_peer_failure_preserves_last_successful_metric() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let speaker = Arc::new(FailingWithdrawal {
            inner: MockAnnouncer::with_peers(vec![PeerStatus {
                name: "failed-peer-observation".into(),
                address: "192.0.2.254".into(),
                state: crate::bgp::SessionState::Established,
            }]),
            mode: AtomicUsize::new(0),
            announcements: AtomicUsize::new(0),
            inventories: AtomicUsize::new(0),
        });
        let reconciler =
            ReconciliationLoop::new(Arc::new(MockRepository::new()), speaker.clone(), 30, false);
        reconciler.update_bgp_session_metrics().await;
        speaker.mode.store(5, SeqCst);
        reconciler.update_bgp_session_metrics().await;
        assert_eq!(
            crate::observability::metrics::BGP_SESSION_UP
                .with_label_values(&["failed-peer-observation"])
                .get(),
            1.0
        );
    }

    #[tokio::test]
    async fn pending_creation_is_excluded_from_gauges_and_fresh_repair_checks() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        struct PendingDuringInventory {
            repo: Arc<MockRepository>,
            id: uuid::Uuid,
            inner: MockAnnouncer,
        }
        impl FlowSpecAnnouncer for PendingDuringInventory {
            fn backend(&self) -> &'static str {
                "mock"
            }
            fn reader(&self) -> Option<&dyn FlowSpecReader> {
                Some(self)
            }
            fn peer_observer(&self) -> Option<&dyn PeerObserver> {
                Some(self)
            }
        }

        #[async_trait::async_trait]
        impl FlowSpecWriter for PendingDuringInventory {
            async fn announce(&self, rule: &FlowSpecRule) -> Result<()> {
                self.inner.announce(rule).await
            }
            async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()> {
                self.inner.withdraw(rule).await
            }
        }
        #[async_trait::async_trait]
        impl FlowSpecReader for PendingDuringInventory {
            async fn list_active(&self) -> Result<Vec<FlowSpecRule>> {
                let mut mitigation = self.repo.get_mitigation(self.id).await?.unwrap();
                mitigation.status = MitigationStatus::Pending;
                self.repo.update_mitigation(&mitigation).await?;
                self.inner.list_active().await
            }
        }
        #[async_trait::async_trait]
        impl PeerObserver for PendingDuringInventory {
            async fn session_status(&self) -> Result<Vec<PeerStatus>> {
                self.inner.session_status().await
            }
        }
        let repo = Arc::new(MockRepository::new());
        let mut active = expired_mitigation("192.0.2.1");
        active.expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);
        let mut pending = expired_mitigation("192.0.2.2");
        pending.expires_at = active.expires_at;
        pending.status = MitigationStatus::Pending;
        let mut escalated = expired_mitigation("192.0.2.3");
        escalated.expires_at = active.expires_at;
        escalated.status = MitigationStatus::Escalated;
        for mitigation in [&active, &pending, &escalated] {
            repo.insert_mitigation(mitigation).await.unwrap();
        }
        let speaker = Arc::new(PendingDuringInventory {
            repo: repo.clone(),
            id: active.mitigation_id,
            inner: MockAnnouncer::new(),
        });
        let reconciler = ReconciliationLoop::new(repo, speaker.clone(), 30, false);
        reconciler.sync_announcements().await.unwrap();
        assert_eq!(
            crate::observability::metrics::MITIGATIONS_ACTIVE
                .with_label_values(&["discard", "test"])
                .get(),
            2.0
        );
        assert_eq!(
            speaker
                .inner
                .list_active()
                .await
                .unwrap()
                .iter()
                .map(|rule| rule.nlri_hash())
                .collect::<Vec<_>>(),
            vec![reconciler.build_flowspec_rule(&escalated).nlri_hash()]
        );
        reconciler.sync_announcements().await.unwrap();
        assert_eq!(
            crate::observability::metrics::MITIGATIONS_ACTIVE
                .with_label_values(&["discard", "test"])
                .get(),
            1.0
        );
    }

    #[tokio::test]
    async fn converged_inventory_skips_lifecycle_reads_but_repairs_recheck() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(MockAnnouncer::new());
        let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false);
        for suffix in 1..=10 {
            let mut mitigation = expired_mitigation(&format!("192.0.2.{suffix}"));
            mitigation.expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);
            repo.insert_mitigation(&mitigation).await.unwrap();
            speaker
                .announce(&reconciler.build_flowspec_rule(&mitigation))
                .await
                .unwrap();
        }
        reconciler.sync_announcements().await.unwrap();
        assert_eq!(repo.lifecycle_read_counts(), (0, 1));
        let missing = speaker.list_active().await.unwrap().pop().unwrap();
        speaker.withdraw(&missing).await.unwrap();
        reconciler.sync_announcements().await.unwrap();
        assert_eq!(repo.lifecycle_read_counts(), (1, 3));
        assert_eq!(speaker.list_active().await.unwrap().len(), 10);
    }

    #[tokio::test]
    async fn legacy_canonical_owners_expire_after_the_last_live_owner() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(MockAnnouncer::new());
        let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false);
        let first = expired_mitigation("192.0.2.10");
        let mut second = first.clone();
        second.mitigation_id = uuid::Uuid::new_v4();
        second.scope_hash = "legacy noncanonical hash".into();
        second.expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);
        for mitigation in [&first, &second] {
            repo.insert_mitigation(mitigation).await.unwrap();
        }
        speaker
            .announce(&reconciler.build_flowspec_rule(&first))
            .await
            .unwrap();
        assert!(reconciler.reconcile().await.is_err());
        assert_eq!(speaker.list_active().await.unwrap().len(), 1);
        assert!(
            repo.get_mitigation(first.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .is_active()
        );
        second.expires_at = first.expires_at;
        repo.update_mitigation(&second).await.unwrap();
        reconciler.reconcile().await.unwrap();
        for mitigation in [&first, &second] {
            assert_eq!(
                repo.get_mitigation(mitigation.mitigation_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .status,
                MitigationStatus::Expired
            );
        }
        assert!(speaker.list_active().await.unwrap().is_empty());
        assert!(repo.pending_withdrawals(None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn expiry_retries_failed_withdrawals_without_false_events_or_reannouncement() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        // Cover rejection before removal and an ambiguous reply after removal.
        for failure_mode in [1, 2] {
            let repo = Arc::new(MockRepository::new());
            let speaker = Arc::new(FailingWithdrawal {
                inner: MockAnnouncer::new(),
                mode: AtomicUsize::new(failure_mode),
                announcements: AtomicUsize::new(0),
                inventories: AtomicUsize::new(0),
            });
            let first = expired_mitigation("192.0.2.1");
            let second = expired_mitigation("192.0.2.2");
            let mut unrelated = expired_mitigation("192.0.2.3");
            unrelated.expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);
            repo.insert_mitigation(&unrelated).await.unwrap();
            let mut group = CorrelationEngine::create_group("192.0.2.8", "udp_flood", 60);
            group.window_expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
            repo.insert_signal_group(&group).await.unwrap();
            let now = chrono::Utc::now();
            repo.insert_corroborating_signal(&crate::correlation::CorroboratingSignal {
                signal_id: uuid::Uuid::new_v4(),
                source: "expired-test".into(),
                vector: None,
                customer_id: None,
                pop: Some("test".into()),
                service_id: None,
                interface: None,
                confidence: Some(0.5),
                weight: 1.0,
                ingested_at: now - chrono::Duration::minutes(2),
                expires_at: now - chrono::Duration::seconds(1),
                raw_details: None,
                attached_group_ids: vec![],
            })
            .await
            .unwrap();
            let (tx, mut rx) = broadcast::channel(8);
            let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false)
                .with_ws_broadcast(tx);
            for mitigation in [&first, &second] {
                repo.insert_mitigation(mitigation).await.unwrap();
                speaker
                    .inner
                    .announce(&reconciler.build_flowspec_rule(mitigation))
                    .await
                    .unwrap();
            }
            assert!(reconciler.reconcile().await.is_err());
            assert_eq!(
                repo.get_mitigation(first.mitigation_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .status,
                MitigationStatus::Active
            );
            assert_eq!(
                repo.get_mitigation(second.mitigation_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .status,
                MitigationStatus::Expired
            );
            assert!(
                matches!(rx.try_recv().unwrap(), WsMessage::MitigationExpired { mitigation_id } if mitigation_id == second.mitigation_id.to_string())
            );
            assert!(rx.try_recv().is_err());
            assert_eq!(
                repo.get_signal_group(group.group_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .status,
                SignalGroupStatus::Expired
            );
            assert_eq!(
                repo.delete_expired_corroborating_signals(now)
                    .await
                    .unwrap()
                    .unattached_total(),
                0
            );
            assert_eq!(
                crate::observability::metrics::MITIGATIONS_ACTIVE
                    .with_label_values(&["discard", "test"])
                    .get(),
                2.0
            );
            assert_eq!(speaker.announcements.load(SeqCst), 1);
            assert_eq!(
                speaker.inner.announced_count().await,
                1 + usize::from(failure_mode == 1)
            );

            speaker.mode.store(0, SeqCst);
            reconciler.reconcile().await.unwrap();
            assert_eq!(
                repo.get_mitigation(first.mitigation_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .status,
                MitigationStatus::Expired
            );
            assert_eq!(speaker.list_active().await.unwrap().len(), 1);
            assert!(
                matches!(rx.try_recv().unwrap(), WsMessage::MitigationExpired { mitigation_id } if mitigation_id == first.mitigation_id.to_string())
            );
            assert!(rx.try_recv().is_err());
            assert_eq!(speaker.announcements.load(SeqCst), 1);
        }
    }
    #[tokio::test]
    async fn failed_repair_returns_error_but_other_repairs_progress() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(FailingWithdrawal {
            inner: MockAnnouncer::with_peers(vec![PeerStatus {
                name: "failed-repair-peer".into(),
                address: "192.0.2.254".into(),
                state: crate::bgp::SessionState::Idle,
            }]),
            mode: AtomicUsize::new(3),
            announcements: AtomicUsize::new(0),
            inventories: AtomicUsize::new(0),
        });
        let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false);
        // The mock lists newest first: force the failing repair before the healthy one.
        for ip in ["192.0.2.2", "192.0.2.1"] {
            let mut mitigation = expired_mitigation(ip);
            mitigation.expires_at = chrono::Utc::now() + chrono::Duration::seconds(300);
            repo.insert_mitigation(&mitigation).await.unwrap();
        }
        let metrics = &crate::observability::metrics::RECONCILIATION_REPAIRS;
        let failures = metrics.with_label_values(&["error"]).get();
        let successes = metrics.with_label_values(&["success"]).get();
        let peer_up = crate::observability::metrics::BGP_SESSION_UP
            .with_label_values(&["failed-repair-peer"]);
        peer_up.set(1.0);
        assert!(reconciler.reconcile().await.is_err());
        assert_eq!(peer_up.get(), 0.0);
        assert_eq!(speaker.announcements.load(SeqCst), 2);
        let actual = speaker.list_active().await.unwrap();
        assert_eq!(actual.len(), 1);
        assert_eq!(actual[0].nlri.dst_prefix, "192.0.2.2/32");
        assert_eq!(metrics.with_label_values(&["error"]).get(), failures + 1.0);
        assert_eq!(
            metrics.with_label_values(&["success"]).get(),
            successes + 1.0
        );
        speaker.mode.store(0, SeqCst);
        reconciler.reconcile().await.unwrap();
        assert_eq!(speaker.list_active().await.unwrap().len(), 2);
        assert_eq!(speaker.announcements.load(SeqCst), 3);
    }

    fn action_mitigation(prefix: &str, action: FlowSpecAction) -> Mitigation {
        let mut mitigation = expired_mitigation(prefix.split('/').next().unwrap());
        mitigation.match_criteria.dst_prefix = prefix.into();
        mitigation.scope_hash = mitigation.match_criteria.compute_scope_hash();
        mitigation.action_type = action.action_type;
        mitigation.action_params.rate_bps = action.rate_bps;
        mitigation.expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);
        mitigation
    }

    fn action_speaker(mode: usize) -> Arc<FailingWithdrawal> {
        Arc::new(FailingWithdrawal {
            inner: MockAnnouncer::new(),
            mode: AtomicUsize::new(mode),
            announcements: AtomicUsize::new(0),
            inventories: AtomicUsize::new(0),
        })
    }

    fn action_state(
        repo: Arc<MockRepository>,
        speaker: Arc<dyn FlowSpecAnnouncer>,
    ) -> Arc<AppState> {
        let mut settings: crate::config::Settings =
            crate::config::parse_yaml(include_str!("../../configs/prefixd.yaml")).unwrap();
        settings.pop = "test".into();
        settings.bgp.mode = crate::config::BgpMode::Mock;
        settings.http.auth.mode = crate::config::AuthMode::None;
        settings.mode = crate::config::OperationMode::Enforced;
        AppState::new(
            settings,
            crate::config::Inventory::new(vec![]),
            crate::config::Playbooks { playbooks: vec![] },
            repo,
            speaker,
            ".".into(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn action_drift_repairs_both_families_once_and_preserves_unknown_rules() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        for (wanted, observed) in [
            (FlowSpecAction::discard(), FlowSpecAction::police(7)),
            (FlowSpecAction::police(1), FlowSpecAction::discard()),
            (FlowSpecAction::police(9), FlowSpecAction::police(8)),
            (
                FlowSpecAction::police(16_777_218),
                FlowSpecAction::police(16_777_216),
            ),
        ] {
            let repo = Arc::new(MockRepository::new());
            let speaker = action_speaker(0);
            let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false);
            let mut expected = Vec::new();
            for prefix in ["192.0.2.1/32", "2001:0DB8:0:0:0:0:0:1/128"] {
                let mut mitigation = action_mitigation(prefix, wanted.clone());
                mitigation.match_criteria.dst_ports = vec![53, 443];
                repo.insert_mitigation(&mitigation).await.unwrap();
                let rule = reconciler.build_flowspec_rule(&mitigation);
                let mut drifted = rule.clone();
                if prefix.contains(':') {
                    drifted.nlri.dst_prefix = "2001:db8::1/128".into();
                }
                drifted.actions = vec![observed.clone()];
                speaker.inner.announce(&drifted).await.unwrap();
                let mut unknown = rule.clone();
                unknown.nlri.dst_ports = vec![54];
                unknown.actions = vec![FlowSpecAction::police(7)];
                speaker.inner.announce(&unknown).await.unwrap();
                expected.extend([rule, unknown]);
            }
            let success = crate::observability::metrics::RECONCILIATION_REPAIRS
                .with_label_values(&["success"]);
            let announced = crate::observability::metrics::ANNOUNCEMENTS_TOTAL
                .with_label_values(&["announced"]);
            let before = (success.get(), announced.get());
            reconciler.sync_announcements().await.unwrap();
            assert_eq!(speaker.announcements.load(SeqCst), 2);
            assert_eq!(
                (success.get(), announced.get()),
                (before.0 + 2.0, before.1 + 2.0)
            );
            assert_eq!(repo.lifecycle_read_counts(), (2, 3));
            for _ in 0..2 {
                reconciler.sync_announcements().await.unwrap();
                let actual = speaker.inner.list_active().await.unwrap();
                assert_eq!(actual.len(), expected.len());
                for rule in &expected {
                    let found = actual
                        .iter()
                        .find(|row| row.nlri_hash() == rule.nlri_hash())
                        .unwrap();
                    assert_eq!(wire_action(found).unwrap(), wire_action(rule).unwrap());
                }
            }
            assert_eq!(repo.lifecycle_read_counts(), (2, 5));
            assert_eq!(speaker.announcements.load(SeqCst), 2);
            assert_eq!(
                (success.get(), announced.get()),
                (before.0 + 2.0, before.1 + 2.0)
            );
        }
    }

    #[tokio::test]
    async fn observed_port_order_alias_fails_before_convergence_or_repair() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        for observed_action in [FlowSpecAction::discard(), FlowSpecAction::police(7)] {
            let repo = Arc::new(MockRepository::new());
            let speaker = action_speaker(0);
            let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false);
            let mut expected = Vec::new();
            for prefix in ["192.0.2.1/32", "2001:db8::1/128"] {
                let mut owner = action_mitigation(prefix, FlowSpecAction::discard());
                owner.match_criteria.dst_ports = vec![443, 53];
                repo.insert_mitigation(&owner).await.unwrap();
                let mut alias = reconciler.build_flowspec_rule(&owner);
                alias.nlri.dst_ports.reverse();
                alias.actions = vec![observed_action.clone()];
                speaker.inner.announce(&alias).await.unwrap();
                expected.push(alias);
            }
            let successes = crate::observability::metrics::RECONCILIATION_REPAIRS
                .with_label_values(&["success"]);
            let errors =
                crate::observability::metrics::RECONCILIATION_REPAIRS.with_label_values(&["error"]);
            let announcements = crate::observability::metrics::ANNOUNCEMENTS_TOTAL
                .with_label_values(&["announced"]);
            let before = (successes.get(), errors.get(), announcements.get());
            for _ in 0..2 {
                assert!(reconciler.sync_announcements().await.is_err());
                assert_eq!(speaker.announcements.load(SeqCst), 0);
                let actual = speaker.inner.list_active().await.unwrap();
                assert_eq!(actual.len(), expected.len());
                for rule in &expected {
                    let found = actual
                        .iter()
                        .find(|row| row.nlri_hash() == rule.nlri_hash())
                        .unwrap();
                    assert_eq!(found.nlri.dst_ports, rule.nlri.dst_ports);
                    assert_eq!(wire_action(found).unwrap(), wire_action(rule).unwrap());
                }
                assert_eq!((successes.get(), errors.get(), announcements.get()), before);
            }
        }
    }

    #[tokio::test]
    async fn distinct_duplicate_term_nlri_does_not_hide_missing_intent_or_block_quiet_polls() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        for (wanted_ports, unknown_ports) in [(vec![53], vec![53, 53]), (vec![53, 53], vec![53])] {
            for unknown_action in [FlowSpecAction::discard(), FlowSpecAction::police(7)] {
                let repo = Arc::new(MockRepository::new());
                let speaker = action_speaker(0);
                let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false);
                let mut expected = Vec::new();
                for prefix in ["192.0.2.1/32", "2001:db8::1/128"] {
                    let mut owner = action_mitigation(prefix, FlowSpecAction::discard());
                    owner.match_criteria.dst_ports = wanted_ports.clone();
                    repo.insert_mitigation(&owner).await.unwrap();
                    let desired = reconciler.build_flowspec_rule(&owner);
                    let mut unknown = desired.clone();
                    unknown.nlri.dst_ports = unknown_ports.clone();
                    unknown.actions = vec![unknown_action.clone()];
                    assert_eq!(ownership_key(&desired), ownership_key(&unknown));
                    assert_ne!(desired.nlri_hash(), unknown.nlri_hash());
                    speaker.inner.announce(&unknown).await.unwrap();
                    expected.extend([desired, unknown]);
                }
                for _ in 0..3 {
                    reconciler.sync_announcements().await.unwrap();
                    assert_eq!(speaker.announcements.load(SeqCst), 2);
                    let actual = speaker.inner.list_active().await.unwrap();
                    assert_eq!(actual.len(), expected.len());
                    for rule in &expected {
                        let found = actual
                            .iter()
                            .find(|row| row.nlri_hash() == rule.nlri_hash())
                            .unwrap();
                        assert_eq!(wire_action(found).unwrap(), wire_action(rule).unwrap());
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn ambiguous_or_invalid_desired_key_leaves_independent_repairs_available() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        for sibling in ["active", "pending", "expired", "invalid"] {
            let repo = Arc::new(MockRepository::new());
            let speaker = action_speaker(0);
            let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false);
            let mut blocked = action_mitigation("2001:db8::1/128", FlowSpecAction::discard());
            if sibling == "invalid" {
                blocked.action_type = ActionType::Police;
                blocked.action_params.rate_bps = Some(0);
            } else {
                let mut other = blocked.clone();
                other.mitigation_id = uuid::Uuid::new_v4();
                other.match_criteria.dst_prefix = "2001:0DB8:0:0:0:0:0:1/128".into();
                other.match_criteria.dst_ports = vec![53, 53];
                other.scope_hash = "legacy duplicate owner".into();
                if sibling == "pending" {
                    other.status = MitigationStatus::Pending;
                }
                if sibling == "expired" {
                    other.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
                }
                repo.insert_mitigation(&other).await.unwrap();
            }
            repo.insert_mitigation(&blocked).await.unwrap();
            let healthy = action_mitigation("192.0.2.2/32", FlowSpecAction::police(9));
            repo.insert_mitigation(&healthy).await.unwrap();
            let mut observed = reconciler.build_flowspec_rule(&blocked);
            observed.actions = vec![FlowSpecAction::police(7)];
            speaker.inner.announce(&observed).await.unwrap();
            assert!(reconciler.sync_announcements().await.is_err(), "{sibling}");
            assert_eq!(speaker.announcements.load(SeqCst), 1, "{sibling}");
            let actual = speaker.inner.list_active().await.unwrap();
            assert_eq!(actual.len(), 2);
            let unchanged = actual
                .iter()
                .find(|row| ownership_key(row) == ownership_key(&observed))
                .unwrap();
            assert_eq!(
                wire_action(unchanged).unwrap(),
                wire_action(&observed).unwrap()
            );
        }
    }

    #[tokio::test]
    async fn action_drift_uses_only_its_pop_and_dry_run_sends_no_rpc() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = action_speaker(0);
        let local = action_mitigation("192.0.2.1/32", FlowSpecAction::police(9));
        let mut foreign = local.clone();
        foreign.mitigation_id = uuid::Uuid::new_v4();
        foreign.pop = "another-target".into();
        foreign.action_params.rate_bps = Some(0);
        for owner in [&local, &foreign] {
            repo.insert_mitigation(owner).await.unwrap();
        }
        let state = action_state(repo.clone(), speaker.clone());
        let mut observed = crate::domain::mitigation_rule(&local);
        observed.actions = vec![FlowSpecAction::discard()];
        speaker.inner.announce(&observed).await.unwrap();
        let success =
            crate::observability::metrics::RECONCILIATION_REPAIRS.with_label_values(&["success"]);
        let before = success.get();
        ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, true)
            .with_app_state(state.clone())
            .sync_announcements()
            .await
            .unwrap();
        assert_eq!(speaker.announcements.load(SeqCst), 0);
        assert_eq!(success.get(), before);
        ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false)
            .with_app_state(state)
            .sync_announcements()
            .await
            .unwrap();
        assert_eq!(speaker.announcements.load(SeqCst), 1);
        assert_eq!(
            wire_action(&speaker.inner.list_active().await.unwrap()[0]).unwrap(),
            wire_action(&crate::domain::mitigation_rule(&local)).unwrap()
        );
        assert_eq!(
            repo.get_mitigation(foreign.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .action_params
                .rate_bps,
            Some(0)
        );
    }

    #[tokio::test]
    async fn entire_observed_action_inventory_is_validated_before_any_repair() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        for mode in [4, 7, 8, 9, 10] {
            let repo = Arc::new(MockRepository::new());
            let speaker = action_speaker(mode);
            let owner = action_mitigation("192.0.2.1/32", FlowSpecAction::discard());
            repo.insert_mitigation(&owner).await.unwrap();
            let mut drifted = crate::domain::mitigation_rule(&owner);
            drifted.actions = vec![FlowSpecAction::police(7)];
            speaker.inner.announce(&drifted).await.unwrap();
            let reconciler = ReconciliationLoop::new(repo, speaker.clone(), 30, false);
            let repairs = &crate::observability::metrics::RECONCILIATION_REPAIRS;
            let before = (
                repairs.with_label_values(&["success"]).get(),
                repairs.with_label_values(&["error"]).get(),
            );
            assert!(
                reconciler.sync_announcements().await.is_err(),
                "mode={mode}"
            );
            assert_eq!(speaker.announcements.load(SeqCst), 0, "mode={mode}");
            assert_eq!(
                (
                    repairs.with_label_values(&["success"]).get(),
                    repairs.with_label_values(&["error"]).get()
                ),
                before
            );
        }
    }

    #[tokio::test]
    async fn pending_cleanup_blocks_drift_even_with_a_historical_invalid_action() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        for malformed in [false, true] {
            let repo = Arc::new(MockRepository::new());
            let speaker = action_speaker(0);
            let owner = action_mitigation("192.0.2.1/32", FlowSpecAction::discard());
            repo.insert_mitigation(&owner).await.unwrap();
            let mut historical = owner.clone();
            historical.action_type = ActionType::Police;
            historical.action_params.rate_bps = Some(0);
            let mut pending = crate::domain::WithdrawalRequest::new(
                &historical,
                false,
                "operator",
                "test",
                "cleanup".into(),
                true,
            )
            .unwrap();
            if malformed {
                pending.rule_json = "{".into();
            }
            repo.begin_withdrawal(&pending).await.unwrap();
            let mut observed = crate::domain::mitigation_rule(&owner);
            observed.actions = vec![FlowSpecAction::police(7)];
            speaker.inner.announce(&observed).await.unwrap();
            let reconciler = ReconciliationLoop::new(repo, speaker.clone(), 30, false);
            assert_eq!(reconciler.sync_announcements().await.is_err(), malformed);
            assert_eq!(speaker.announcements.load(SeqCst), 0);
            assert_eq!(
                speaker.inner.list_active().await.unwrap()[0].actions[0].rate_bps,
                Some(7)
            );
        }
    }

    #[tokio::test]
    async fn failed_and_uncertain_action_repairs_retry_only_when_still_drifted() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        for mode in [3, 6] {
            let repo = Arc::new(MockRepository::new());
            let speaker = action_speaker(mode);
            for prefix in ["192.0.2.2/32", "192.0.2.1/32"] {
                let owner = action_mitigation(prefix, FlowSpecAction::police(9));
                repo.insert_mitigation(&owner).await.unwrap();
                let mut drifted = crate::domain::mitigation_rule(&owner);
                drifted.actions = vec![FlowSpecAction::discard()];
                speaker.inner.announce(&drifted).await.unwrap();
            }
            let reconciler = ReconciliationLoop::new(repo, speaker.clone(), 30, false);
            let metrics = &crate::observability::metrics::RECONCILIATION_REPAIRS;
            let before = (
                metrics.with_label_values(&["success"]).get(),
                metrics.with_label_values(&["error"]).get(),
            );
            assert!(reconciler.sync_announcements().await.is_err());
            assert_eq!(speaker.announcements.load(SeqCst), 2);
            assert_eq!(
                metrics.with_label_values(&["success"]).get(),
                before.0 + 1.0
            );
            assert_eq!(metrics.with_label_values(&["error"]).get(), before.1 + 1.0);
            speaker.mode.store(0, SeqCst);
            reconciler.sync_announcements().await.unwrap();
            reconciler.sync_announcements().await.unwrap();
            assert_eq!(
                speaker.announcements.load(SeqCst),
                if mode == 3 { 3 } else { 2 }
            );
            for rule in speaker.inner.list_active().await.unwrap() {
                assert_eq!(rule.actions[0].rate_bps, Some(9));
            }
        }
    }

    struct PausedActionInventory {
        inner: Arc<FailingWithdrawal>,
        observed: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }
    impl FlowSpecAnnouncer for PausedActionInventory {
        fn backend(&self) -> &'static str {
            "mock"
        }
        fn reader(&self) -> Option<&dyn FlowSpecReader> {
            Some(self)
        }
    }
    #[async_trait::async_trait]
    impl FlowSpecWriter for PausedActionInventory {
        async fn announce(&self, rule: &FlowSpecRule) -> Result<()> {
            self.inner.announce(rule).await
        }
        async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()> {
            self.inner.withdraw(rule).await
        }
    }
    #[async_trait::async_trait]
    impl FlowSpecReader for PausedActionInventory {
        async fn list_active(&self) -> Result<Vec<FlowSpecRule>> {
            let snapshot = self.inner.list_active().await?;
            self.observed.notify_one();
            self.release.notified().await;
            Ok(snapshot)
        }
    }

    #[tokio::test]
    async fn action_repair_rechecks_lifecycle_and_uses_the_current_payload() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        for change in [
            "withdrawn",
            "pending",
            "expired",
            "foreign",
            "key",
            "duplicate_term",
            "port_order",
            "replacement",
            "action",
            "converged",
            "invalid",
            "cleanup",
        ] {
            let repo = Arc::new(MockRepository::new());
            let inner = action_speaker(0);
            let speaker = Arc::new(PausedActionInventory {
                inner: inner.clone(),
                observed: Default::default(),
                release: Default::default(),
            });
            let mut owner = action_mitigation("192.0.2.1/32", FlowSpecAction::discard());
            owner.match_criteria.dst_ports = vec![443, 53];
            repo.insert_mitigation(&owner).await.unwrap();
            let mut observed = crate::domain::mitigation_rule(&owner);
            observed.actions = vec![FlowSpecAction::police(1)];
            inner.inner.announce(&observed).await.unwrap();
            let state = action_state(repo.clone(), speaker.clone());
            let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false)
                .with_app_state(state.clone());
            let mut repair = Box::pin(reconciler.sync_announcements());
            assert!(futures_util::poll!(&mut repair).is_pending());
            tokio::time::timeout(Duration::from_secs(5), speaker.observed.notified())
                .await
                .unwrap();
            let guard = state.mitigation_lock.lock().await;
            match change {
                "withdrawn" | "replacement" => {
                    owner.status = MitigationStatus::Withdrawn;
                    inner.inner.withdraw(&observed).await.unwrap();
                }
                "pending" => owner.status = MitigationStatus::Pending,
                "expired" => owner.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1),
                "foreign" => owner.pop = "another-target".into(),
                "key" => owner.match_criteria.dst_prefix = "192.0.2.3/32".into(),
                "duplicate_term" => owner.match_criteria.dst_ports.push(53),
                "port_order" => owner.match_criteria.dst_ports.reverse(),
                "action" | "converged" | "invalid" => {
                    owner.action_type = ActionType::Police;
                    owner.action_params.rate_bps = Some(match change {
                        "action" => 9,
                        "converged" => 1,
                        _ => 0,
                    });
                }
                "cleanup" => {
                    request_withdrawal(
                        repo.as_ref(),
                        &owner,
                        false,
                        "operator",
                        "test",
                        "test".into(),
                        true,
                        None,
                    )
                    .await
                    .unwrap();
                }
                _ => unreachable!(),
            }
            repo.update_mitigation(&owner).await.unwrap();
            if change == "replacement" {
                let replacement = action_mitigation("192.0.2.1/32", FlowSpecAction::police(7));
                repo.insert_mitigation(&replacement).await.unwrap();
                inner
                    .inner
                    .announce(&crate::domain::mitigation_rule(&replacement))
                    .await
                    .unwrap();
            }
            speaker.release.notify_one();
            // Explicit polling reaches the held lifecycle lock without scheduler timing.
            assert!(
                futures_util::poll!(&mut repair).is_pending(),
                "repair must wait for lifecycle lock: {change}"
            );
            assert_eq!(
                inner.announcements.load(SeqCst),
                0,
                "repair must wait for lifecycle lock: {change}"
            );
            drop(guard);
            let result = tokio::time::timeout(Duration::from_secs(5), repair)
                .await
                .unwrap();
            assert_eq!(result.is_err(), change == "invalid", "{change}");
            assert_eq!(
                inner.announcements.load(SeqCst),
                usize::from(change == "action"),
                "{change}"
            );
            if change == "action" || change == "replacement" {
                assert_eq!(
                    inner.inner.list_active().await.unwrap()[0].actions[0].rate_bps,
                    Some(if change == "action" { 9 } else { 7 })
                );
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn startup_runs_once_then_waits_for_the_interval() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let speaker = Arc::new(FailingWithdrawal {
            inner: MockAnnouncer::new(),
            mode: AtomicUsize::new(0),
            announcements: AtomicUsize::new(0),
            inventories: AtomicUsize::new(0),
        });
        let reconciler =
            ReconciliationLoop::new(Arc::new(MockRepository::new()), speaker.clone(), 30, false);
        let (shutdown, rx) = broadcast::channel(1);
        let task = tokio::spawn(async move { reconciler.run(rx).await });
        tokio::task::yield_now().await;
        assert_eq!(speaker.inventories.load(SeqCst), 1);
        tokio::time::advance(Duration::from_secs(29)).await;
        tokio::task::yield_now().await;
        assert_eq!(speaker.inventories.load(SeqCst), 1);
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(speaker.inventories.load(SeqCst), 2);
        shutdown.send(()).unwrap();
        task.await.unwrap();
    }
}
