use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;

use crate::alerting::AlertingService;
use crate::bgp::FlowSpecAnnouncer;
use crate::correlation::{CorrelationEngine, SignalGroupStatus};
use crate::db::RepositoryTrait;
use crate::domain::{
    ActionType, FlowSpecRule, MitigationRoute, MitigationStatus, execute_withdrawal, ownership_key,
    request_withdrawal,
};
use crate::state::AppState;
use crate::ws::WsMessage;
use tokio::sync::RwLock;

/// Time allowed for all blackhole export reads in one reconciliation pass.
const EXPORT_OBSERVATION_BUDGET: Duration = Duration::from_secs(10);

/// Audit reason for a local blackhole route withdrawn because its row is already terminal.
pub const ORPHANED_AFTER_DOWNTIME: &str = "orphaned after controller downtime";

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

/// Keys blocked by pending deletions of either kind; unreadable intent fails the caller.
fn pending_ownership_keys(
    requests: &[crate::domain::WithdrawalRequest],
) -> crate::error::Result<std::collections::HashSet<String>> {
    requests
        .iter()
        .map(crate::domain::WithdrawalRequest::ownership_key)
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
    /// The controller's injection lease (ADR 027); leased adds and full re-adds use it.
    lease: Option<Arc<crate::domain::LeaseKeeper>>,
    /// Set of source labels we last set on
    /// `CORROBORATOR_CACHE_SIZE`. Used to zero-out gauges when a
    /// source's cache drains to empty between ticks (Prometheus would
    /// otherwise keep the last non-zero value forever).
    last_cache_sources: tokio::sync::Mutex<std::collections::HashSet<String>>,
    /// Rotate export reads so the fixed pass budget cannot always cut off the same rows.
    export_cursor: std::sync::atomic::AtomicUsize,
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
            lease: None,
            last_cache_sources: tokio::sync::Mutex::new(std::collections::HashSet::new()),
            export_cursor: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Standalone fixtures; with application state, its lease is used.
    pub fn with_lease(mut self, lease: Arc<crate::domain::LeaseKeeper>) -> Self {
        self.lease = Some(lease);
        self
    }

    fn lease(&self) -> Option<&crate::domain::LeaseKeeper> {
        self.lease
            .as_deref()
            .or_else(|| self.state.as_ref().and_then(|state| state.lease.as_deref()))
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
        let mut fence = self.state.as_ref().map(|state| state.fence.subscribe());
        loop {
            // Standby runs nothing; on taking the fence, reconcile at once.
            if let Some(fence) = fence.as_mut() {
                tokio::select! {
                    closed = async { fence.wait_for(|active| *active).await.is_err() } => {
                        if closed {
                            return;
                        }
                    }
                    _ = shutdown.recv() => {
                        tracing::info!("reconciliation loop shutting down");
                        return;
                    }
                }
            }
            self.record_run().await;
            let mut interval = tokio::time::interval_at(
                tokio::time::Instant::now() + self.interval,
                self.interval,
            );
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = interval.tick() => self.record_run().await,
                    // A lost lease is re-added at once, not on the next poll.
                    _ = async {
                        match self.lease() {
                            Some(lease) => lease.readd_requested().await,
                            None => std::future::pending().await,
                        }
                    } => self.record_run().await,
                    // A fence change restarts the cycle: standby waits, a regained fence reconciles at once.
                    _ = async {
                        match fence.as_mut() {
                            Some(fence) => {
                                let _ = fence.changed().await;
                            }
                            None => std::future::pending().await,
                        }
                    } => break,
                    _ = shutdown.recv() => {
                        tracing::info!("reconciliation loop shutting down");
                        return;
                    }
                }
            }
        }
    }

    async fn record_run(&self) {
        let status = match self.reconcile().await {
            Ok(()) => "success",
            Err(e) => {
                tracing::error!(error = %e, "reconciliation failed");
                "error"
            }
        };
        crate::observability::metrics::RECONCILIATION_RUNS
            .with_label_values(&[status])
            .inc();
    }

    /// Run one reconciliation cycle (for testing)
    pub async fn reconcile(&self) -> anyhow::Result<()> {
        // The scheduler entry point: a standby controller expires, repairs and withdraws nothing.
        if let Some(state) = &self.state {
            state.fence.ensure_active()?;
        }
        let export_epoch = self
            .state
            .as_ref()
            .and_then(|state| state.fence.with_observation_epoch(|epoch| epoch));
        self.verified_speaker_binding()?;
        let mut failure = None;
        // One requested full leased re-add covers both route kinds; taken
        // before the reads, so a loss signalled meanwhile is not dropped.
        let lease = self.lease();
        let readd = lease.is_some_and(crate::domain::LeaseKeeper::take_readd);
        let (mut flowspec_readd_failed, mut blackhole_readd_failed) = (readd, readd);
        let mut blackhole_readd = readd;
        let mut blackholes = None;
        // Each stage is independent; a speaker failure must not stop expiry or health updates.
        for (stage, result) in [
            ("withdrawals", self.expire_mitigations().await),
            ("signal groups", self.expire_signal_groups().await),
            ("corroborator cache", self.sweep_corroborator_cache().await),
            ("confidence", self.refresh_decayed_confidence().await),
            (
                "announcements",
                self.sync_announcements_with(readd, &mut flowspec_readd_failed)
                    .await,
            ),
            (
                "blackholes",
                self.sync_blackholes_with(
                    &mut blackhole_readd,
                    &mut blackhole_readd_failed,
                    &mut blackholes,
                )
                .await,
            ),
        ] {
            if let Err(error) = result {
                tracing::warn!(stage, error = %error, "reconciliation stage failed");
                failure = Some(error);
            }
        }
        // A partial re-add stays pending, so the next pass re-adds everything again.
        if (flowspec_readd_failed || blackhole_readd_failed)
            && let Some(lease) = lease
        {
            lease.retry_readd();
        }
        let sessions = match self.announcer.peer_observer() {
            Some(observer) => Some(observer.session_status().await),
            None => None,
        };
        self.update_bgp_session_metrics(sessions.as_ref());
        self.observe_blackhole_exports(blackholes, sessions.as_ref(), export_epoch)
            .await;
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

    #[cfg(test)]
    async fn sync_announcements(&self) -> anyhow::Result<()> {
        self.sync_announcements_with(false, &mut false).await
    }

    /// FlowSpec desired set against the local rule view. `readd` re-adds every
    /// leased rule even when present; `readd_failed` reports whether it completed.
    async fn sync_announcements_with(
        &self,
        readd: bool,
        readd_failed: &mut bool,
    ) -> anyhow::Result<()> {
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
                .entry(MitigationRoute::of(mitigation).ownership_key())
                .or_default() += 1;
        }
        active.retain(|mitigation| {
            matches!(
                mitigation.status,
                MitigationStatus::Active | MitigationStatus::Escalated
            ) && pop.is_none_or(|pop| mitigation.pop == pop)
        });

        {
            use std::collections::HashMap;
            let mut counts: HashMap<(String, String), f64> = HashMap::new();
            // A scoped loop always reports its POP, including zero; an
            // unscoped loop reports each mitigation POP it saw.
            let mut by_pop: HashMap<&str, f64> = pop.map(|pop| (pop, 0.0)).into_iter().collect();
            for m in &active {
                *counts
                    .entry((m.action_type.to_string(), m.pop.clone()))
                    .or_default() += 1.0;
                *by_pop.entry(m.pop.as_str()).or_default() += 1.0;
            }
            crate::observability::metrics::RECONCILIATION_ACTIVE_COUNT.reset();
            for (pop, count) in &by_pop {
                crate::observability::metrics::RECONCILIATION_ACTIVE_COUNT
                    .with_label_values(&[pop])
                    .set(*count);
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
        // Blackholes reconcile in their own stage against their own read.
        active.retain(|mitigation| {
            mitigation.action_type != ActionType::Blackhole
                && !mitigation.is_dry_run_origin()
                && mitigation.expires_at > now
                && !pending_keys.contains(&MitigationRoute::of(mitigation).ownership_key())
        });

        let Some(reader) = self.announcer.reader() else {
            tracing::debug!(
                backend = self.announcer.backend(),
                "rule observation unsupported; repair skipped"
            );
            *readd_failed = false;
            return Ok(());
        };
        let announced = reader.list_active().await?;
        // Our live rule while no generation is held is renewed by nothing, such
        // as an add whose reply was lost: re-add to learn the generation.
        let readd = readd
            || self.lease().is_some_and(|lease| {
                lease.generation().is_none()
                    && announced.iter().any(|rule| rule.owner == lease.owner())
            });
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
        let mut forced_failure = false;
        for candidate in &active {
            // A non-FlowSpec row fails its own repair; other rows still repair.
            let candidate_rule = match self.build_flowspec_rule(candidate) {
                Ok(rule) => rule,
                Err(error) => {
                    repair_error = Some(error);
                    continue;
                }
            };
            let key = ownership_key(&candidate_rule);
            let nlri_hash = candidate_rule.nlri_hash();
            let destination_prefix = candidate_rule
                .nlri
                .dst_prefix
                .parse::<ipnet::IpNet>()
                .ok()
                .filter(|prefix| prefix.prefix_len() < prefix.max_prefix_len());
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
            // A full leased re-add treats every leased rule as missing.
            let forced = readd && !candidate_rule.owner.is_empty();
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
                // Another owner's rule, or an unowned one where ours is leased, is never touched.
                if observed.owner != candidate_rule.owner {
                    repair_error =
                        Some(crate::error::PrefixdError::InjectionOwnerMismatch(format!(
                            "FlowSpec rule for {} is held by injection owner {:?}",
                            candidate_rule.nlri.dst_prefix, observed.owner
                        )));
                    continue;
                }
                if !forced && observed_action == &action && destination_prefix.is_none() {
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
            let rule = match self.build_flowspec_rule(&mitigation) {
                Ok(rule) => rule,
                Err(error) => {
                    repair_error = Some(error);
                    continue;
                }
            };
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
            // Hosts keep their existing admission policy. Non-host rules need
            // fresh whole-prefix ownership and overlap safety, even when the
            // speaker already has the desired action. The lifecycle mutex
            // serializes safelist insertion and inventory replacement.
            if let Some(destination) = destination_prefix {
                let safelisted = match self.repo.is_safelisted(&destination.to_string()).await {
                    Ok(safelisted) => safelisted,
                    Err(error) => {
                        repair_error = Some(error);
                        continue;
                    }
                };
                let ownership_lost = if safelisted {
                    false
                } else if let Some(state) = &self.state {
                    // Invalid inventory is not a definite loss of ownership:
                    // keep the rule and report the repair error.
                    let owner = match state.inventory.read().await.lookup_prefix(&destination) {
                        Ok(owner) => owner,
                        Err(error) => {
                            repair_error = Some(error);
                            continue;
                        }
                    };
                    owner.is_none_or(|owner| {
                        mitigation.customer_id.as_deref() != Some(owner.customer_id.as_str())
                    })
                } else {
                    repair_error = Some(crate::error::PrefixdError::Conflict(
                        "destination prefix repair requires current customer inventory".into(),
                    ));
                    continue;
                };
                if safelisted || ownership_lost {
                    if self.dry_run {
                        continue;
                    }
                    let binding = self.verified_speaker_binding()?;
                    let withdrawal = if safelisted {
                        crate::domain::withdraw_safelisted(
                            self.repo.as_ref(),
                            self.announcer.as_ref(),
                            false,
                            &mitigation,
                            binding,
                        )
                        .await
                    } else {
                        match request_withdrawal(
                            self.repo.as_ref(),
                            &mitigation,
                            false,
                            "system",
                            "inventory-recheck",
                            "destination prefix ownership changed after admission".into(),
                            true,
                            binding,
                        )
                        .await
                        {
                            Ok(request) => {
                                execute_withdrawal(
                                    self.repo.as_ref(),
                                    self.announcer.as_ref(),
                                    false,
                                    &request,
                                    binding,
                                )
                                .await
                            }
                            Err(error) => Err(error),
                        }
                    };
                    match withdrawal {
                        Ok(withdrawn) => self.notify_withdrawn(&withdrawn).await,
                        Err(error) => {
                            tracing::error!(mitigation_id = %mitigation.mitigation_id, error = %error,
                                "failed to withdraw destination prefix after safety recheck");
                            repair_error = Some(error);
                        }
                    }
                    continue;
                }
            }
            if forced
                || announced_actions.get(&nlri_hash).map(|(_, action)| action) != Some(&action)
            {
                let reason = if forced {
                    "lease re-add"
                } else if announced_actions.contains_key(&nlri_hash) {
                    "action_drift"
                } else {
                    "missing"
                };
                if forced {
                    tracing::info!(mitigation_id = %mitigation.mitigation_id,
                        nlri_hash = %rule.nlri_hash(), reason, "re-adding leased FlowSpec rule");
                } else {
                    tracing::warn!(mitigation_id = %mitigation.mitigation_id,
                        nlri_hash = %rule.nlri_hash(), reason, "repairing local announcement");
                }

                if !self.dry_run {
                    let start = std::time::Instant::now();
                    let announced = match self.announcer.match_support().require(&rule.nlri) {
                        Ok(()) => {
                            crate::domain::announce_flowspec(
                                self.announcer.as_ref(),
                                &rule,
                                self.lease(),
                            )
                            .await
                        }
                        Err(error) => Err(error),
                    };
                    if let Err(e) = announced {
                        forced_failure |= forced;
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
                        let backend =
                            crate::observability::metrics::backend_label(self.announcer.backend());
                        crate::observability::metrics::RECONCILIATION_REPAIRS
                            .with_label_values(&["success"])
                            .inc();
                        crate::observability::metrics::ANNOUNCEMENTS_TOTAL
                            .with_label_values(&[backend, "announced"])
                            .inc();
                        crate::observability::metrics::ANNOUNCEMENTS_LATENCY
                            .with_label_values(&[backend])
                            .observe(start.elapsed().as_secs_f64());
                    }
                }
            }
        }

        *readd_failed = forced_failure;
        // Alert on unknown routes (routes in BGP not tracked by us), including
        // another injection owner's rule at a desired key.
        let desired_hashes: HashSet<_> = active
            .iter()
            .filter_map(|m| self.build_flowspec_rule(m).ok())
            .map(|rule| (rule.nlri_hash(), rule.owner))
            .collect();

        let mut unknown = 0.0;
        for rule in &announced {
            if !desired_hashes.contains(&(rule.nlri_hash(), rule.owner.clone())) {
                unknown += 1.0;
                tracing::warn!(
                    nlri_hash = %rule.nlri_hash(),
                    dst_prefix = %rule.nlri.dst_prefix,
                    "unknown route in BGP RIB"
                );
            }
        }
        crate::observability::metrics::UNKNOWN_LOCAL_ROUTES
            .with_label_values(&["flowspec"])
            .set(unknown);

        match repair_error {
            Some(error) => Err(error.into()),
            None => Ok(()),
        }
    }

    /// Blackhole desired set against retained local intent (ADR 027 §5). It is a
    /// separate stage, so a failed blackhole read never stops FlowSpec repair or
    /// the reverse. Unknown and unrecognized routes are reported, never touched.
    /// `readd` re-adds every leased route even when present; `readd_failed`
    /// reports whether it completed.
    /// `observe` receives the active enforced blackholes once they are known.
    async fn sync_blackholes_with(
        &self,
        readd: &mut bool,
        readd_failed: &mut bool,
        observe: &mut Option<Vec<(uuid::Uuid, ipnet::IpNet)>>,
    ) -> anyhow::Result<()> {
        use std::collections::{HashMap, HashSet};

        let binding = self.verified_speaker_binding()?;
        let pop = self.owning_pop();
        let pending = self.repo.pending_withdrawals(pop).await?;
        let pending_keys = pending_ownership_keys(&pending)?;
        // The ledger: every enforced-origin row of this POP and pending blackhole deletions.
        let mut owned: HashSet<String> = pending
            .iter()
            .filter(|request| request.rule_kind == ActionType::Blackhole.as_str())
            .map(|request| request.nlri_hash.clone())
            .collect();
        let mut owner_counts = HashMap::<String, usize>::new();
        let mut desired = Vec::new();
        let now = chrono::Utc::now();
        for mitigation in self.repo.active_mitigation_inventory(pop).await? {
            if mitigation.action_type != ActionType::Blackhole
                || mitigation.is_dry_run_origin()
                || pop.is_some_and(|pop| mitigation.pop != pop)
            {
                continue;
            }
            let key = MitigationRoute::of(&mitigation).ownership_key();
            owned.insert(key.clone());
            *owner_counts.entry(key.clone()).or_default() += 1;
            if matches!(
                mitigation.status,
                MitigationStatus::Active | MitigationStatus::Escalated
            ) && mitigation.expires_at > now
                && !pending_keys.contains(&key)
            {
                desired.push((key, mitigation));
            }
        }
        // A row without a usable frozen route fails its own repair below.
        *observe = Some(
            desired
                .iter()
                .filter_map(|(_, mitigation)| {
                    crate::domain::blackhole_rule(mitigation)
                        .ok()
                        .map(|rule| (mitigation.mitigation_id, rule.prefix))
                })
                .collect(),
        );
        let enabled = self
            .state
            .as_ref()
            .is_some_and(|state| state.settings.blackhole.enabled);
        let Some(speaker) = self.announcer.blackhole() else {
            anyhow::ensure!(
                desired.is_empty(),
                "blackhole intent needs a blackhole-capable speaker"
            );
            // Nothing leased to re-add, so no re-add stays pending.
            *readd_failed = false;
            return Ok(());
        };
        if owned.is_empty() && !enabled {
            *readd_failed = false;
            return Ok(());
        }
        let lease = self.lease();
        // A failed or partial read is an error: no repair and no unknown-route verdicts.
        let inventory = speaker.list_blackholes().await?;
        let our_owner = lease.map_or("", crate::domain::LeaseKeeper::owner);
        // Our row with no time left is lost intent: re-add everything leased.
        if !our_owner.is_empty()
            && inventory
                .expired
                .iter()
                .any(|route| route.owner() == our_owner)
        {
            tracing::warn!(
                owner = our_owner,
                "speaker reports an expired injection lease; re-adding all active leased intent"
            );
            *readd = true;
        }
        // Our live row while no generation is held is renewed by nothing, such
        // as an add whose reply was lost: re-add to learn the generation.
        if lease.is_some_and(|lease| lease.generation().is_none())
            && inventory
                .routes
                .iter()
                .any(|route| route.owner() == our_owner)
        {
            *readd = true;
        }
        let identity =
            |prefix: &ipnet::IpNet| crate::domain::blackhole_identity(&prefix.to_string());
        let mut repair_error = None;
        let mut forced_failure = false;
        let mut unknown = 0.0;
        for route in &inventory.routes {
            // Another owner's row is reported, never modified, even at a key we hold.
            let ours = route.owner().is_empty() || route.owner() == our_owner;
            if ours && owned.contains(&identity(&route.prefix())) {
                continue;
            }
            if !ours {
                unknown += 1.0;
                tracing::warn!(prefix = %route.prefix(), owner = route.owner(),
                    "blackhole route of another injection owner; left untouched");
                continue;
            }
            match self.withdraw_orphan(speaker, route, pop).await {
                Ok(true) => continue,
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(prefix = %route.prefix(), error = %error, "orphaned blackhole route not withdrawn");
                    repair_error = Some(error);
                }
            }
            unknown += 1.0;
            tracing::warn!(prefix = %route.prefix(), "unknown blackhole route in local RIB; left untouched");
        }
        for row in &inventory.unrecognized {
            unknown += 1.0;
            tracing::warn!(prefix = %row.prefix, reason = row.reason,
                "unrecognized local unicast route; left untouched");
        }
        crate::observability::metrics::UNKNOWN_LOCAL_ROUTES
            .with_label_values(&["blackhole"])
            .set(unknown);

        for (key, candidate) in &desired {
            // A row without a usable frozen route fails its own repair; others continue.
            let (rule, wanted) = match crate::domain::blackhole_rule(candidate)
                .and_then(|rule| Ok((rule.route()?, rule)))
            {
                Ok((route, rule)) => (rule, route),
                Err(error) => {
                    repair_error = Some(error);
                    continue;
                }
            };
            if owner_counts[key] != 1 {
                repair_error = Some(crate::error::PrefixdError::Conflict(
                    "blackhole route has multiple active owners".into(),
                ));
                continue;
            }
            // An unrecognized row may hold the same key; it is never overwritten.
            if inventory
                .unrecognized
                .iter()
                .any(|row| row.prefix == rule.prefix)
            {
                repair_error = Some(crate::error::PrefixdError::Conflict(format!(
                    "unrecognized local route at desired blackhole {}",
                    rule.prefix
                )));
                continue;
            }
            // A present route is withdrawn once its victim is safelisted, for
            // entries seeded from configuration or written to the database
            // directly. A failed lookup takes no action. A full leased re-add
            // treats every leased route as missing.
            let forced = *readd && !rule.owner.is_empty();
            let present = !forced && inventory.routes.contains(&wanted);
            if present {
                match self
                    .repo
                    .is_safelisted(&rule.prefix.addr().to_string())
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(error) => {
                        repair_error = Some(error);
                        continue;
                    }
                }
            }
            let _guard = match &self.state {
                Some(state) => Some(state.mitigation_lock.lock().await),
                None => None,
            };
            let mitigation = match self.repo.get_mitigation(candidate.mitigation_id).await {
                Ok(Some(mitigation))
                    if mitigation.pop == candidate.pop
                        && matches!(
                            mitigation.status,
                            MitigationStatus::Active | MitigationStatus::Escalated
                        )
                        && mitigation.expires_at > chrono::Utc::now()
                        && !mitigation.is_dry_run_origin()
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
            // The frozen route, never the current configuration.
            if crate::domain::blackhole_rule(&mitigation).ok().as_ref() != Some(&rule) {
                continue;
            }
            let current_pending = self.repo.pending_withdrawals(pop).await?;
            if pending_ownership_keys(&current_pending)?.contains(key)
                || current_pending
                    .iter()
                    .any(|request| request.mitigation_id == mitigation.mitigation_id)
            {
                continue;
            }
            self.verified_speaker_binding()?;
            if present {
                if self.dry_run {
                    continue;
                }
                match crate::domain::withdraw_safelisted(
                    self.repo.as_ref(),
                    self.announcer.as_ref(),
                    false,
                    &mitigation,
                    binding,
                )
                .await
                {
                    Ok(withdrawn) => self.notify_withdrawn(&withdrawn).await,
                    Err(error) => {
                        tracing::error!(mitigation_id = %mitigation.mitigation_id, error = %error,
                            "failed to withdraw safelisted blackhole route");
                        repair_error = Some(error);
                    }
                }
                continue;
            }
            let reason = if forced {
                "lease re-add"
            } else if inventory
                .routes
                .iter()
                .any(|route| route.prefix() == rule.prefix)
            {
                "drift"
            } else {
                "missing"
            };
            if forced {
                tracing::info!(mitigation_id = %mitigation.mitigation_id, prefix = %rule.prefix,
                    reason, "re-adding leased blackhole route");
            } else {
                tracing::warn!(mitigation_id = %mitigation.mitigation_id, prefix = %rule.prefix,
                    reason, "repairing local blackhole route");
            }
            if self.dry_run {
                continue;
            }
            match crate::domain::announce_blackhole(
                self.repo.as_ref(),
                self.announcer.as_ref(),
                &mitigation,
                binding,
                lease,
            )
            .await
            {
                Ok(crate::domain::BlackholeAnnouncement::Announced(outcome)) => {
                    crate::observability::metrics::RECONCILIATION_REPAIRS
                        .with_label_values(&["success"])
                        .inc();
                    // As at admission (ADR 027 §5): an unleased replace overwrote
                    // a different local route at the prefix. Leased adds refuse
                    // another owner's route, so their replace is our own.
                    if rule.owner.is_empty() && outcome == crate::bgp::AddOutcome::Replaced {
                        crate::observability::metrics::BLACKHOLE_REPLACED
                            .with_label_values(&[&mitigation.pop])
                            .inc();
                        tracing::error!(mitigation_id = %mitigation.mitigation_id, prefix = %rule.prefix,
                            "blackhole repair replaced a different local route at the prefix");
                    }
                }
                Ok(crate::domain::BlackholeAnnouncement::Withdrawn(withdrawn)) => {
                    self.notify_withdrawn(&withdrawn).await
                }
                Err(error) => {
                    crate::observability::metrics::RECONCILIATION_REPAIRS
                        .with_label_values(&["error"])
                        .inc();
                    tracing::error!(mitigation_id = %mitigation.mitigation_id, error = %error,
                        "failed to repair blackhole route");
                    // An ownership refusal will not clear by re-adding everything
                    // again: report it each pass without re-triggering the re-add.
                    forced_failure |= forced
                        && !matches!(error, crate::error::PrefixdError::InjectionOwnerMismatch(_));
                    repair_error = Some(error);
                }
            }
        }
        // A partial re-add stays pending, so the next pass re-adds everything again.
        *readd_failed = forced_failure;
        match repair_error {
            Some(error) => Err(error.into()),
            None => Ok(()),
        }
    }

    async fn notify_withdrawn(&self, withdrawn: &crate::domain::Mitigation) {
        if let Some(tx) = &self.ws_broadcast {
            let _ = tx.send(WsMessage::MitigationWithdrawn {
                mitigation_id: withdrawn.mitigation_id.to_string(),
            });
        }
        if let Some(alerting) = &self.alerting {
            alerting
                .read()
                .await
                .notify(crate::alerting::Alert::mitigation_withdrawn(withdrawn));
        }
    }

    /// Withdraws a local route that prefixd left behind (ADR 027): it exactly
    /// matches the frozen, unleased route of a terminal, enforced-origin
    /// blackhole row of this POP, and no live row or pending withdrawal holds its
    /// key. For example, an enforced blackhole withdrawn locally while the
    /// controller ran in dry-run. Overdue live rows are not orphans:
    /// `expire_mitigations` withdraws them through the immutable path first.
    /// Returns false, sending nothing, for every other route.
    async fn withdraw_orphan(
        &self,
        speaker: &dyn crate::bgp::BlackholeSpeaker,
        route: &crate::bgp::BlackholeRoute,
        pop: Option<&str>,
    ) -> crate::error::Result<bool> {
        if self.dry_run {
            return Ok(false);
        }
        let _guard = match &self.state {
            Some(state) => Some(state.mitigation_lock.lock().await),
            None => None,
        };
        // Fresh ledger checks under the lifecycle mutex.
        let key = crate::domain::blackhole_identity(&route.prefix().to_string());
        let pending = self.repo.pending_withdrawals(pop).await?;
        if pending_ownership_keys(&pending)?.contains(&key)
            || self
                .repo
                .active_mitigation_inventory(pop)
                .await?
                .iter()
                .any(|live| MitigationRoute::of(live).ownership_key() == key)
        {
            return Ok(false);
        }
        // ponytail: the newest 100 rows for the victim; an older match is only reported.
        let history = self
            .repo
            .list_mitigations_by_ip(&route.prefix().addr().to_string(), 100)
            .await?;
        let Some(row) = history.into_iter().find(|row| {
            row.action_type == ActionType::Blackhole
                && matches!(
                    row.status,
                    MitigationStatus::Withdrawn | MitigationStatus::Expired
                )
                && !row.is_dry_run_origin()
                && pop.is_none_or(|pop| row.pop == pop)
                // The frozen route includes the recorded owner.
                && crate::domain::blackhole_rule(row)
                    .is_ok_and(|rule| rule.route().is_ok_and(|frozen| frozen == *route))
        }) else {
            return Ok(false);
        };
        self.verified_speaker_binding()?;
        speaker
            .withdraw_blackhole(&route.prefix(), route.owner())
            .await?;
        tracing::warn!(mitigation_id = %row.mitigation_id, prefix = %route.prefix(),
            "withdrew blackhole route orphaned after controller downtime");
        self.repo
            .insert_audit(&crate::observability::AuditEntry::new(
                crate::observability::ActorType::System,
                Some("reconciler".into()),
                "withdraw",
                Some("mitigation"),
                Some(row.mitigation_id.to_string()),
                serde_json::json!({
                    "reason": ORPHANED_AFTER_DOWNTIME,
                    "prefix": route.prefix().to_string(),
                    "next_hop": route.next_hop().to_string(),
                }),
            ))
            .await?;
        Ok(true)
    }

    fn update_bgp_session_metrics(
        &self,
        sessions: Option<&crate::error::Result<Vec<crate::bgp::PeerStatus>>>,
    ) {
        use crate::observability::metrics::BGP_SESSION_UP;
        use prometheus::core::Collector;

        let Some(sessions) = sessions else {
            return;
        };
        match sessions {
            Ok(peers) => {
                let backend =
                    crate::observability::metrics::backend_label(self.announcer.backend());
                let observed: std::collections::HashSet<_> =
                    peers.iter().map(|peer| peer.name.as_str()).collect();
                for peer in peers {
                    let value = if peer.state.is_established() {
                        1.0
                    } else {
                        0.0
                    };
                    BGP_SESSION_UP
                        .with_label_values(&[backend, &peer.name])
                        .set(value);
                }
                // Keep retained children registered throughout concurrent scrapes.
                for family in BGP_SESSION_UP.collect() {
                    for metric in family.get_metric() {
                        let labels = metric.get_label();
                        if labels
                            .iter()
                            .any(|label| label.name() == "backend" && label.value() == backend)
                            && let Some(peer) = labels.iter().find(|label| label.name() == "peer")
                            && !observed.contains(peer.value())
                            && let Err(error) =
                                BGP_SESSION_UP.remove_label_values(&[backend, peer.value()])
                        {
                            tracing::warn!(error = %error, backend, peer = peer.value(),
                                "failed to retire BGP session metric");
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to fetch BGP session status for metrics");
            }
        }
    }

    /// Read-only export evidence for the active enforced blackholes: one
    /// paginated read each per pass, sequentially, joined with this pass's peer
    /// read. An unknown blackhole set keeps the last snapshot and metrics.
    async fn observe_blackhole_exports(
        &self,
        blackholes: Option<Vec<(uuid::Uuid, ipnet::IpNet)>>,
        sessions: Option<&crate::error::Result<Vec<crate::bgp::PeerStatus>>>,
        epoch: Option<u64>,
    ) {
        use crate::domain::{BlackholeExportEvidence, UNEXPORTED_REASONS};
        use crate::observability::metrics::{
            BLACKHOLE_EXPORT_PEERS, BLACKHOLE_EXPORT_READ_ERRORS, BLACKHOLE_UNEXPORTED,
        };
        let (Some(state), Some(observer), Some(mut blackholes), Some(epoch)) = (
            &self.state,
            self.announcer.export_observer(),
            blackholes,
            epoch,
        ) else {
            return;
        };
        if !state
            .fence
            .with_observation_epoch(|current| current == Some(epoch))
        {
            return;
        }
        // Repository order is unspecified. Start where the last stored pass
        // stopped; the head then moves to the first read the budget cut off,
        // so N blackholes at K reads per budget are all read within ceil(N/K)
        // passes.
        blackholes.sort_unstable_by_key(|(id, _)| *id);
        let candidates = blackholes.len();
        if candidates > 0 {
            let start = self
                .export_cursor
                .load(std::sync::atomic::Ordering::Relaxed)
                % candidates;
            blackholes.rotate_left(start);
        }
        let sessions = match sessions {
            Some(Ok(peers)) => Some(peers.as_slice()),
            _ => None,
        };
        let now = chrono::Utc::now();
        // ponytail: one fixed budget per pass, so a stalled speaker cannot hold
        // up expiry; reads it cuts off report an error. Make it a setting if
        // large blackhole tables need longer.
        let deadline = tokio::time::Instant::now() + EXPORT_OBSERVATION_BUDGET;
        let mut routes = std::collections::HashMap::new();
        let mut cut_off = None;
        for (index, (id, prefix)) in blackholes.into_iter().enumerate() {
            let read = tokio::time::timeout_at(deadline, observer.blackhole_exports(&prefix))
                .await
                .unwrap_or_else(|_| {
                    cut_off.get_or_insert(index);
                    Err(crate::error::PrefixdError::Internal(
                        "export observation budget for this pass exhausted".into(),
                    ))
                });
            let mut evidence = BlackholeExportEvidence::from_read(&read, sessions, now);
            if let Some(error) = &evidence.error {
                tracing::warn!(%prefix, error, "blackhole export read failed; export unknown");
                // Keep the last complete read's warning, so a transient read
                // error does not clear degraded health or the unexported alert.
                evidence.warning = state
                    .export_evidence
                    .get(id, Some(epoch))
                    .and_then(|previous| previous.warning);
            }
            if let Some(warning) = &evidence.warning {
                tracing::warn!(%prefix, reason = warning.reason,
                    "active blackhole is committed to no Established peer");
            }
            routes.insert(id, (prefix.to_string(), evidence));
        }
        state.fence.with_observation_epoch(|current| {
            if current != Some(epoch) {
                return;
            }
            state.export_evidence.replace(now, epoch, routes);
            if candidates > 0 {
                // At least one place, so a read longer than the budget cannot
                // pin the head.
                let attempted = cut_off.unwrap_or(candidates).max(1);
                self.export_cursor
                    .fetch_add(attempted, std::sync::atomic::Ordering::Relaxed);
            }
            let summary = state.export_evidence.current_summary(current);
            for disposition in crate::bgp::ExportDisposition::ALL {
                BLACKHOLE_EXPORT_PEERS
                    .with_label_values(&[disposition.as_str()])
                    .set(summary.counts.get(disposition) as f64);
            }
            for reason in UNEXPORTED_REASONS {
                let count = summary
                    .unexported
                    .iter()
                    .filter(|route| route.warning.reason == reason)
                    .count();
                BLACKHOLE_UNEXPORTED
                    .with_label_values(&[reason])
                    .set(count as f64);
            }
            BLACKHOLE_EXPORT_READ_ERRORS.set(summary.errors as f64);
        });
    }

    fn build_flowspec_rule(
        &self,
        m: &crate::domain::Mitigation,
    ) -> crate::error::Result<FlowSpecRule> {
        crate::domain::mitigation_rule(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bgp::{
            BlackholeSpeaker, ExportObserver, FaultyBlackholes, FlowSpecReader, FlowSpecWriter,
            MockAnnouncer, PeerObserver, PeerStatus,
        },
        db::MockRepository,
        domain::{
            ActionParams, ActionType, AttackVector, FlowSpecAction, MatchCriteria, Mitigation,
            MitigationIntent,
        },
        error::{PrefixdError, Result},
    };
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

    // Reconciliation resets process-global Prometheus gauges.
    use crate::observability::metrics::METRICS_TEST_LOCK as RECONCILIATION_TEST_LOCK;

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
        fn match_support(&self) -> crate::bgp::FlowSpecMatchSupport {
            self.inner.match_support()
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
            if (rule.nlri.dst_prefix == "192.0.2.1/32" && mode != 0) || matches!(mode, 11 | 12) {
                if matches!(mode, 2 | 12) {
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
                    ..Default::default()
                },
                action_type: ActionType::Discard,
                action_params: ActionParams::default(),
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
        let peer = crate::observability::metrics::BGP_SESSION_UP
            .with_label_values(&["mock", "write-only-peer"]);
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
                .with_label_values(&["test"])
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
        let observe = || speaker.session_status();
        reconciler.update_bgp_session_metrics(Some(&observe().await));
        speaker.mode.store(5, SeqCst);
        let failed = observe().await;
        assert!(failed.is_err());
        reconciler.update_bgp_session_metrics(Some(&failed));
        assert_eq!(
            crate::observability::metrics::BGP_SESSION_UP
                .with_label_values(&["mock", "failed-peer-observation"])
                .get(),
            1.0
        );
    }

    #[tokio::test]
    async fn successful_complete_peer_inventory_preserves_retained_and_retires_omitted_series() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        use crate::observability::metrics::{BGP_SESSION_UP, gather_metrics};
        let reconciler = ReconciliationLoop::new(
            Arc::new(MockRepository::new()),
            Arc::new(MockAnnouncer::new()),
            30,
            false,
        );
        BGP_SESSION_UP.reset();
        let peer = |name: &str, state| PeerStatus {
            name: name.into(),
            address: "192.0.2.1".into(),
            state,
        };
        let samples = || {
            let mut samples = gather_metrics()
                .lines()
                .filter(|line| line.starts_with("prefixd_bgp_session_up{"))
                .map(str::to_owned)
                .collect::<Vec<_>>();
            samples.sort();
            samples
        };
        reconciler.update_bgp_session_metrics(Some(&Ok(vec![
            peer("retired-peer", crate::bgp::SessionState::Established),
            peer("retained-peer", crate::bgp::SessionState::Established),
        ])));
        assert_eq!(samples().len(), 2);
        let retained = BGP_SESSION_UP.with_label_values(&["mock", "retained-peer"]);
        BGP_SESSION_UP
            .with_label_values(&["gobgp", "other-backend-peer"])
            .set(1.0);
        reconciler.update_bgp_session_metrics(Some(&Ok(vec![peer(
            "retained-peer",
            crate::bgp::SessionState::Idle,
        )])));
        assert_eq!(retained.get(), 0.0, "retained child must stay registered");
        let other_backend =
            r#"prefixd_bgp_session_up{backend="gobgp",peer="other-backend-peer"} 1"#.to_owned();
        let expected = vec![
            other_backend.clone(),
            r#"prefixd_bgp_session_up{backend="mock",peer="retained-peer"} 0"#.to_owned(),
        ];
        assert_eq!(samples(), expected);
        // Failed, including partial-stream, and unsupported observations retain the snapshot.
        reconciler.update_bgp_session_metrics(Some(&Err(PrefixdError::Internal(
            "partial peer stream".into(),
        ))));
        reconciler.update_bgp_session_metrics(None);
        assert_eq!(samples(), expected);
        reconciler.update_bgp_session_metrics(Some(&Ok(vec![])));
        assert_eq!(samples(), vec![other_backend]);
        BGP_SESSION_UP
            .remove_label_values(&["gobgp", "other-backend-peer"])
            .unwrap();
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
            vec![
                reconciler
                    .build_flowspec_rule(&escalated)
                    .unwrap()
                    .nlri_hash()
            ]
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
    async fn repair_refuses_unencodable_components_before_any_rpc() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let mut mitigation = expired_mitigation("192.0.2.30");
        mitigation.expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);
        mitigation.match_criteria.dst_ports.clear();
        mitigation.match_criteria.src_ports = vec![123];
        mitigation.scope_hash = mitigation.match_criteria.compute_scope_hash();
        // The control speaker encodes source ports; the other has not opted in.
        for supported in [false, true] {
            let repo = Arc::new(MockRepository::new());
            repo.insert_mitigation(&mitigation).await.unwrap();
            let speaker = Arc::new(if supported {
                MockAnnouncer::new()
            } else {
                MockAnnouncer::without_match_support()
            });
            let reconciler = ReconciliationLoop::new(repo, speaker.clone(), 30, false);
            let result = reconciler.sync_announcements().await;
            assert_eq!(result.is_ok(), supported, "{result:?}");
            assert_eq!(speaker.announced_count().await, usize::from(supported));
        }
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
                .announce(&reconciler.build_flowspec_rule(&mitigation).unwrap())
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
            .announce(&reconciler.build_flowspec_rule(&first).unwrap())
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
                    .announce(&reconciler.build_flowspec_rule(mitigation).unwrap())
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
            .with_label_values(&["mock", "failed-repair-peer"]);
        peer_up.set(1.0);
        assert!(reconciler.reconcile().await.is_err());
        assert_eq!(
            crate::observability::metrics::BGP_SESSION_UP
                .with_label_values(&["mock", "failed-repair-peer"])
                .get(),
            0.0
        );
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

    async fn destination_prefix_state(
        repo: Arc<MockRepository>,
        speaker: Arc<dyn FlowSpecAnnouncer>,
        prefixes: &[&str],
    ) -> Arc<AppState> {
        // Keep default /32 and /128 admission bounds: the unaffected CIDR in
        // repair tests proves saved intent survives tighter startup bounds.
        let state = action_state(repo, speaker);
        *state.inventory.write().await =
            crate::config::Inventory::new(vec![crate::config::Customer {
                customer_id: "prefix-owner".into(),
                name: "Prefix owner".into(),
                prefixes: prefixes.iter().map(|prefix| (*prefix).into()).collect(),
                policy_profile: crate::config::PolicyProfile::Normal,
                services: vec![],
            }]);
        state
    }

    fn destination_prefix_mitigation(prefix: &str) -> Mitigation {
        let mut mitigation = action_mitigation(prefix, FlowSpecAction::discard());
        mitigation.victim_ip = prefix.into();
        mitigation.customer_id = Some("prefix-owner".into());
        mitigation
    }

    #[tokio::test]
    async fn destination_prefix_repair_rechecks_safety_after_observation() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        for (destination, protected, unaffected) in [
            ("203.0.112.0/22", "203.0.113.10/32", "203.0.116.0/22"),
            ("2001:db8::/64", "2001:db8::abcd/128", "2001:db8:0:1::/64"),
        ] {
            for present in [false, true] {
                for change in ["safelist", "ownership", "lookup_failure"] {
                    let repo = Arc::new(MockRepository::new());
                    let inner = action_speaker(0);
                    let speaker = Arc::new(PausedActionInventory {
                        inner: inner.clone(),
                        observed: Default::default(),
                        release: Default::default(),
                    });
                    let affected = destination_prefix_mitigation(destination);
                    let control = destination_prefix_mitigation(unaffected);
                    for mitigation in [&affected, &control] {
                        repo.insert_mitigation(mitigation).await.unwrap();
                    }
                    if present {
                        inner
                            .inner
                            .announce(&crate::domain::mitigation_rule(&affected).unwrap())
                            .await
                            .unwrap();
                    }
                    let mut unknown = crate::domain::mitigation_rule(&affected).unwrap();
                    unknown.nlri.dst_ports = vec![123];
                    inner.inner.announce(&unknown).await.unwrap();
                    let state = destination_prefix_state(
                        repo.clone(),
                        speaker.clone(),
                        &[destination, unaffected],
                    )
                    .await;
                    let reconciler =
                        ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false)
                            .with_app_state(state.clone());
                    let mut pass = Box::pin(reconciler.sync_announcements());
                    assert!(futures_util::poll!(&mut pass).is_pending());
                    speaker.observed.notified().await;
                    let guard = state.mitigation_lock.lock().await;
                    match change {
                        "safelist" => repo.insert_safelist(protected, "test", None).await.unwrap(),
                        "ownership" => {
                            let mut inventory = state.inventory.write().await;
                            inventory.customers[0].prefixes = vec![unaffected.into()];
                        }
                        _ => repo.fail_safelist.store(true, SeqCst),
                    }
                    speaker.release.notify_one();
                    drop(guard);
                    let result = pass.await;
                    if change == "lookup_failure" {
                        assert!(result.is_err());
                        assert_eq!(status(&repo, &affected).await, MitigationStatus::Active);
                        assert_eq!(inner.announcements.load(SeqCst), 0);
                        assert!(repo.pending_withdrawals(None).await.unwrap().is_empty());
                    } else {
                        result.unwrap();
                        assert_eq!(status(&repo, &affected).await, MitigationStatus::Withdrawn);
                        assert_eq!(status(&repo, &control).await, MitigationStatus::Active);
                        assert_eq!(inner.announcements.load(SeqCst), 1);
                    }
                    let retained = inner.inner.list_active().await.unwrap();
                    assert!(
                        retained
                            .iter()
                            .any(|rule| rule.nlri_hash() == unknown.nlri_hash())
                    );
                    if change != "lookup_failure" {
                        assert!(retained.iter().all(|rule| {
                            rule.nlri_hash()
                                != crate::domain::mitigation_rule(&affected)
                                    .unwrap()
                                    .nlri_hash()
                        }));
                        assert_eq!(retained.len(), 2, "the unknown rule and control remain");
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn invalid_unrelated_inventory_keeps_destination_prefix() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = action_speaker(0);
        let affected = destination_prefix_mitigation("203.0.112.0/22");
        repo.insert_mitigation(&affected).await.unwrap();
        let rule = crate::domain::mitigation_rule(&affected).unwrap();
        speaker.inner.announce(&rule).await.unwrap();
        let state =
            destination_prefix_state(repo.clone(), speaker.clone(), &["203.0.112.0/22"]).await;
        state
            .inventory
            .write()
            .await
            .customers
            .push(crate::config::Customer {
                customer_id: "unrelated".into(),
                name: "Unrelated".into(),
                prefixes: vec!["198.51.100.0/33".into()],
                policy_profile: crate::config::PolicyProfile::Normal,
                services: vec![],
            });
        let reconciler =
            ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false).with_app_state(state);
        let error = reconciler.sync_announcements().await.unwrap_err();
        assert!(error.to_string().contains("198.51.100.0/33"), "{error}");
        assert_eq!(status(&repo, &affected).await, MitigationStatus::Active);
        assert!(repo.pending_withdrawals(None).await.unwrap().is_empty());
        let retained = speaker.inner.list_active().await.unwrap();
        assert!(retained.iter().any(|r| r.nlri_hash() == rule.nlri_hash()));
    }

    #[tokio::test]
    async fn destination_prefix_safety_withdrawal_retries_immutable_intent() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        for failure in [11, 12] {
            let repo = Arc::new(MockRepository::new());
            let speaker = action_speaker(failure);
            let mut affected = destination_prefix_mitigation("203.0.112.0/22");
            affected.match_criteria.src_prefix = Some("198.51.100.0/24".into());
            affected.scope_hash = affected.match_criteria.compute_scope_hash();
            repo.insert_mitigation(&affected).await.unwrap();
            let rule = crate::domain::mitigation_rule(&affected).unwrap();
            speaker.inner.announce(&rule).await.unwrap();
            let state =
                destination_prefix_state(repo.clone(), speaker.clone(), &["203.0.112.0/22"]).await;
            let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false)
                .with_app_state(state);
            repo.insert_safelist("203.0.113.10", "test", None)
                .await
                .unwrap();
            assert!(reconciler.sync_announcements().await.is_err());
            let pending = repo.pending_withdrawals(None).await.unwrap();
            let [request] = pending.as_slice() else {
                panic!("one pending withdrawal")
            };
            assert_eq!(request.rule_kind, "flowspec");
            assert_eq!(request.reason, crate::domain::SAFELISTED_AFTER_ADMISSION);
            assert_eq!(
                serde_json::to_value(request.flowspec_rule().unwrap()).unwrap(),
                serde_json::to_value(&rule).unwrap()
            );
            // Removing the protection cannot turn pending deletion into an add.
            repo.remove_safelist("203.0.113.10").await.unwrap();
            reconciler.sync_announcements().await.unwrap();
            assert_eq!(speaker.announcements.load(SeqCst), 0);
            assert!(reconciler.expire_mitigations().await.is_err());
            let retained = repo.pending_withdrawals(None).await.unwrap();
            assert_eq!(retained[0].operation_id, request.operation_id);
            assert_eq!(retained[0].rule_json, request.rule_json);
            assert_eq!(retained[0].actor, "safelist-recheck");
            speaker.mode.store(0, SeqCst);
            reconciler.expire_mitigations().await.unwrap();
            reconciler.sync_announcements().await.unwrap();
            assert_eq!(status(&repo, &affected).await, MitigationStatus::Withdrawn);
            assert!(speaker.inner.list_active().await.unwrap().is_empty());
            assert_eq!(speaker.announcements.load(SeqCst), 0);
        }
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
                let rule = reconciler.build_flowspec_rule(&mitigation).unwrap();
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
                .with_label_values(&["mock", "announced"]);
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
                let mut alias = reconciler.build_flowspec_rule(&owner).unwrap();
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
                .with_label_values(&["mock", "announced"]);
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
    async fn source_prefix_delete_failure_preserves_frozen_intent_and_siblings() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        for failure in [1, 2] {
            let repo = Arc::new(MockRepository::new());
            let speaker = action_speaker(failure);
            let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false);
            let mut owner = action_mitigation("192.0.2.1/32", FlowSpecAction::discard());
            owner.match_criteria.src_prefix = Some("198.51.100.0/24".into());
            owner.scope_hash = owner.match_criteria.compute_scope_hash();
            let mut sibling = owner.clone();
            sibling.mitigation_id = uuid::Uuid::new_v4();
            sibling.match_criteria.src_prefix = Some("198.51.100.0/25".into());
            sibling.scope_hash = sibling.match_criteria.compute_scope_hash();
            for mitigation in [&owner, &sibling] {
                repo.insert_mitigation(mitigation).await.unwrap();
                speaker
                    .inner
                    .announce(&crate::domain::mitigation_rule(mitigation).unwrap())
                    .await
                    .unwrap();
            }
            let request = request_withdrawal(
                repo.as_ref(),
                &owner,
                false,
                "operator",
                "alice",
                "source attack ended".into(),
                true,
                None,
            )
            .await
            .unwrap();
            assert!(
                execute_withdrawal(repo.as_ref(), speaker.as_ref(), false, &request, None)
                    .await
                    .is_err()
            );
            for _ in 0..2 {
                assert!(reconciler.reconcile().await.is_err());
                assert_eq!(speaker.announcements.load(SeqCst), 0);
                let pending = repo.pending_withdrawals(None).await.unwrap();
                assert_eq!(pending.len(), 1);
                let retained = &pending[0];
                assert_eq!(
                    (
                        retained.operation_id,
                        retained.actor.as_str(),
                        retained.reason.as_str(),
                        retained.rule_json.as_str()
                    ),
                    (
                        request.operation_id,
                        "alice",
                        "source attack ended",
                        request.rule_json.as_str()
                    )
                );
                assert_eq!(
                    retained.flowspec_rule().unwrap().nlri.src_prefix,
                    owner.match_criteria.src_prefix
                );
                let actual = speaker.inner.list_active().await.unwrap();
                assert_eq!(actual.len(), if failure == 1 { 2 } else { 1 });
                assert!(actual.iter().any(|rule| {
                    rule.nlri_hash()
                        == crate::domain::mitigation_rule(&sibling)
                            .unwrap()
                            .nlri_hash()
                }));
            }
            speaker.mode.store(0, SeqCst);
            execute_withdrawal(repo.as_ref(), speaker.as_ref(), false, &request, None)
                .await
                .unwrap();
            assert!(repo.pending_withdrawals(None).await.unwrap().is_empty());
            assert_eq!(speaker.inner.list_active().await.unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn source_prefix_siblings_do_not_hide_missing_rules_or_get_deleted() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = action_speaker(0);
        let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false);
        let mut expected = Vec::new();
        for (destination, source, sibling) in [
            ("192.0.2.1/32", "198.51.100.0/24", "198.51.100.0/25"),
            ("2001:db8::1/128", "2001:db8:1::/48", "2001:db8:1::/64"),
        ] {
            let mut owner = action_mitigation(destination, FlowSpecAction::discard());
            owner.match_criteria.src_prefix = Some(source.into());
            owner.scope_hash = owner.match_criteria.compute_scope_hash();
            repo.insert_mitigation(&owner).await.unwrap();
            let desired = reconciler.build_flowspec_rule(&owner).unwrap();
            for source in [None, Some(sibling)] {
                let mut unknown = desired.clone();
                unknown.nlri.src_prefix = source.map(str::to_owned);
                unknown.actions = vec![FlowSpecAction::police(7)];
                speaker.inner.announce(&unknown).await.unwrap();
                expected.push(unknown);
            }
            expected.push(desired);
        }
        for _ in 0..3 {
            reconciler.sync_announcements().await.unwrap();
            assert_eq!(speaker.announcements.load(SeqCst), 2);
            let actual = speaker.inner.list_active().await.unwrap();
            assert_eq!(actual.len(), expected.len());
            for rule in &expected {
                let found = actual
                    .iter()
                    .find(|found| found.nlri_hash() == rule.nlri_hash())
                    .unwrap();
                assert_eq!(wire_action(found).unwrap(), wire_action(rule).unwrap());
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
                    let desired = reconciler.build_flowspec_rule(&owner).unwrap();
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
            let mut observed = reconciler.build_flowspec_rule(&blocked).unwrap();
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
        let mut observed = crate::domain::mitigation_rule(&local).unwrap();
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
        let active_count = |pop: &str| {
            crate::observability::metrics::RECONCILIATION_ACTIVE_COUNT
                .with_label_values(&[pop])
                .get()
        };
        assert_eq!(active_count(&state.settings.pop), 1.0);
        assert_eq!(active_count("another-target"), 0.0);
        assert_eq!(active_count("local"), 0.0);
        ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false)
            .with_app_state(state)
            .sync_announcements()
            .await
            .unwrap();
        assert_eq!(speaker.announcements.load(SeqCst), 1);
        assert_eq!(
            wire_action(&speaker.inner.list_active().await.unwrap()[0]).unwrap(),
            wire_action(&crate::domain::mitigation_rule(&local).unwrap()).unwrap()
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
            let mut drifted = crate::domain::mitigation_rule(&owner).unwrap();
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
            let mut observed = crate::domain::mitigation_rule(&owner).unwrap();
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
                let mut drifted = crate::domain::mitigation_rule(&owner).unwrap();
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
            let mut observed = crate::domain::mitigation_rule(&owner).unwrap();
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
                    .announce(&crate::domain::mitigation_rule(&replacement).unwrap())
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

    #[tokio::test(start_paused = true)]
    async fn standby_loop_runs_nothing_and_a_regained_fence_reconciles_at_once() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(FailingWithdrawal {
            inner: MockAnnouncer::new(),
            mode: AtomicUsize::new(0),
            announcements: AtomicUsize::new(0),
            inventories: AtomicUsize::new(0),
        });
        let fence = Arc::new(crate::fence::ControllerFence::new(false));
        let state = action_state(repo.clone(), speaker.clone())
            .with_fence(fence.clone())
            .unwrap();
        let reconciler =
            ReconciliationLoop::new(repo, speaker.clone(), 30, false).with_app_state(state);
        let (shutdown, rx) = broadcast::channel(1);
        let task = tokio::spawn(async move { reconciler.run(rx).await });
        let settle = || async {
            for _ in 0..20 {
                tokio::task::yield_now().await;
            }
        };
        let runs = || speaker.inventories.load(SeqCst);
        tokio::time::advance(Duration::from_secs(90)).await;
        settle().await;
        assert_eq!(runs(), 0, "standby reconciled");
        fence.set(true);
        settle().await;
        assert_eq!(runs(), 1, "acquiring the fence reconciles at once");
        tokio::time::advance(Duration::from_secs(30)).await;
        settle().await;
        assert_eq!(runs(), 2);
        fence.set(false);
        settle().await;
        tokio::time::advance(Duration::from_secs(90)).await;
        settle().await;
        assert_eq!(runs(), 2, "lost fence stops the schedule");
        fence.set(true);
        settle().await;
        assert_eq!(runs(), 3, "a regained fence reconciles at once");
        shutdown.send(()).unwrap();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn blackhole_rows_without_a_frozen_route_fail_closed_without_rpc() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(FailingWithdrawal {
            inner: MockAnnouncer::new(),
            mode: AtomicUsize::new(0),
            announcements: AtomicUsize::new(0),
            inventories: AtomicUsize::new(0),
        });
        let blackhole = |ip| {
            let mut mitigation = expired_mitigation(ip);
            mitigation.action_type = ActionType::Blackhole;
            mitigation.match_criteria.protocol = None;
            mitigation.match_criteria.dst_ports.clear();
            mitigation.scope_hash = mitigation
                .match_criteria
                .scope_hash_for(ActionType::Blackhole);
            mitigation
        };
        let expired = blackhole("192.0.2.1");
        let mut live = blackhole("192.0.2.2");
        live.expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);
        let mut flowspec = expired_mitigation("192.0.2.3");
        flowspec.expires_at = live.expires_at;
        for mitigation in [&expired, &live, &flowspec] {
            repo.insert_mitigation(mitigation).await.unwrap();
        }
        let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false);
        // Rows without a frozen route fail their own expiry and repair; FlowSpec still repairs.
        assert!(reconciler.reconcile().await.is_err());
        assert_eq!(speaker.announcements.load(SeqCst), 1);
        let announced = speaker.inner.list_active().await.unwrap();
        assert_eq!(announced.len(), 1);
        assert_eq!(announced[0].nlri.dst_prefix, "192.0.2.3/32");
        assert!(
            repo.get_mitigation(expired.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .is_active()
        );
        assert!(repo.pending_withdrawals(None).await.unwrap().is_empty());
        assert!(reconciler.build_flowspec_rule(&live).is_err());
        let coerced = FlowSpecRule::new(
            crate::domain::FlowSpecNlri::from(&live.match_criteria),
            FlowSpecAction {
                action_type: ActionType::Blackhole,
                rate_bps: None,
            },
        );
        assert!(wire_action(&coerced).is_err());

        // Unreadable pending intent (a FlowSpec rule labelled blackhole) blocks repair before any RPC.
        let mut request = crate::domain::WithdrawalRequest::new(
            &flowspec,
            false,
            "operator",
            "test",
            "test".into(),
            true,
        )
        .unwrap();
        request.rule_kind = "blackhole".into();
        repo.begin_withdrawal(&request).await.unwrap();
        speaker.inner.withdraw(&announced[0]).await.unwrap();
        assert!(reconciler.reconcile().await.is_err());
        assert_eq!(speaker.announcements.load(SeqCst), 1);
        assert_eq!(speaker.inner.announced_count().await, 0);
        assert!(
            repo.get_mitigation(flowspec.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .is_active()
        );
    }

    fn blackhole_config(next_hop: &str, community: &str) -> crate::config::BlackholeConfig {
        crate::config::BlackholeConfig {
            enabled: true,
            next_hop_ipv4: Some(next_hop.parse().unwrap()),
            next_hop_ipv6: Some("2001:db8:ffff::66".parse().unwrap()),
            communities: vec![community.into()],
            ..Default::default()
        }
    }

    /// Enforced, live blackhole intent frozen with next hop 192.0.2.66 and 64512:1.
    fn blackhole_row(ip: &str) -> Mitigation {
        let address: std::net::IpAddr = ip.parse().unwrap();
        let prefix = ipnet::IpNet::from(address);
        let rule = crate::domain::BlackholeRule::from_config(
            &blackhole_config("192.0.2.66", "64512:1"),
            prefix,
        )
        .unwrap();
        let mut mitigation = Mitigation::from_intent(
            MitigationIntent {
                event_id: uuid::Uuid::new_v4(),
                customer_id: None,
                service_id: None,
                pop: "test".into(),
                match_criteria: MatchCriteria {
                    dst_prefix: prefix.to_string(),
                    ..Default::default()
                },
                action_type: ActionType::Blackhole,
                action_params: ActionParams {
                    blackhole: Some(rule),
                    ..Default::default()
                },
                ttl_seconds: 600,
                reason: "test".into(),
            },
            ip.into(),
            AttackVector::Unknown,
        );
        mitigation.activate();
        mitigation.origin_mode = Some(crate::config::OperationMode::Enforced);
        mitigation
    }

    fn frozen(mitigation: &Mitigation) -> crate::bgp::BlackholeRoute {
        crate::domain::blackhole_rule(mitigation)
            .unwrap()
            .route()
            .unwrap()
    }

    /// A POP-scoped loop whose current configuration is `config`.
    fn blackhole_reconciler(
        repo: Arc<MockRepository>,
        speaker: Arc<dyn FlowSpecAnnouncer>,
        config: crate::config::BlackholeConfig,
        dry_run: bool,
    ) -> ReconciliationLoop {
        let mut settings: crate::config::Settings =
            crate::config::parse_yaml(include_str!("../../configs/prefixd.yaml")).unwrap();
        settings.pop = "test".into();
        settings.bgp.mode = crate::config::BgpMode::Mock;
        settings.http.auth.mode = crate::config::AuthMode::None;
        settings.mode = crate::config::OperationMode::Enforced;
        settings.blackhole = config;
        let state = AppState::new(
            settings,
            crate::config::Inventory::new(vec![]),
            crate::config::Playbooks { playbooks: vec![] },
            repo.clone(),
            speaker.clone(),
            ".".into(),
        )
        .unwrap();
        ReconciliationLoop::new(repo, speaker, 30, dry_run).with_app_state(state)
    }

    fn live_config() -> crate::config::BlackholeConfig {
        blackhole_config("192.0.2.66", "64512:1")
    }

    async fn status(repo: &MockRepository, mitigation: &Mitigation) -> MitigationStatus {
        repo.get_mitigation(mitigation.mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .status
    }

    #[tokio::test]
    async fn blackhole_ambiguous_delete_stays_pending_and_is_never_reannounced() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        // Rejection before removal, and removal with a lost reply.
        for fault in [1, 2] {
            let repo = Arc::new(MockRepository::new());
            let speaker = Arc::new(FaultyBlackholes::default());
            let reconciler =
                blackhole_reconciler(repo.clone(), speaker.clone(), live_config(), false);
            let withdrawn = blackhole_row("192.0.2.1");
            let mut expired = blackhole_row("192.0.2.2");
            expired.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
            for mitigation in [&withdrawn, &expired] {
                repo.insert_mitigation(mitigation).await.unwrap();
                speaker
                    .inner
                    .announce_blackhole(&frozen(mitigation))
                    .await
                    .unwrap();
            }
            speaker.withdraw_fault.store(fault, SeqCst);
            let request = request_withdrawal(
                repo.as_ref(),
                &withdrawn,
                false,
                "operator",
                "alice",
                "attack over".into(),
                true,
                None,
            )
            .await
            .unwrap();
            assert_eq!(request.rule_kind, "blackhole");
            assert!(
                execute_withdrawal(repo.as_ref(), speaker.as_ref(), false, &request, None)
                    .await
                    .is_err()
            );
            for _ in 0..2 {
                // Operator retry and TTL expiry both fail; the missing route is never re-added.
                assert!(reconciler.reconcile().await.is_err(), "fault={fault}");
                assert_eq!(speaker.adds.load(SeqCst), 0, "fault={fault}");
                for mitigation in [&withdrawn, &expired] {
                    assert!(status(&repo, mitigation).await.is_active());
                }
                let pending = repo.pending_withdrawals(None).await.unwrap();
                assert_eq!(pending.len(), 2);
                let kept = pending
                    .iter()
                    .find(|pending| pending.mitigation_id == withdrawn.mitigation_id)
                    .unwrap();
                assert_eq!(
                    (
                        kept.operation_id,
                        kept.actor.as_str(),
                        kept.reason.as_str(),
                        kept.rule_kind.as_str(),
                        kept.rule_json.as_str()
                    ),
                    (
                        request.operation_id,
                        "alice",
                        "attack over",
                        "blackhole",
                        request.rule_json.as_str()
                    )
                );
            }
            assert_eq!(speaker.routes().await.len(), if fault == 1 { 2 } else { 0 });
            speaker.withdraw_fault.store(0, SeqCst);
            reconciler.reconcile().await.unwrap();
            assert_eq!(status(&repo, &withdrawn).await, MitigationStatus::Withdrawn);
            assert_eq!(status(&repo, &expired).await, MitigationStatus::Expired);
            assert!(repo.pending_withdrawals(None).await.unwrap().is_empty());
            assert!(speaker.routes().await.is_empty());
            assert_eq!(speaker.adds.load(SeqCst), 0);
        }
    }

    struct SlowExportSpeaker {
        enabled: std::sync::atomic::AtomicBool,
        read_time: Duration,
        completed: std::sync::Mutex<Vec<ipnet::IpNet>>,
    }

    impl FlowSpecAnnouncer for SlowExportSpeaker {
        fn backend(&self) -> &'static str {
            "mock"
        }

        fn export_observer(&self) -> Option<&dyn crate::bgp::ExportObserver> {
            self.enabled.load(SeqCst).then_some(self)
        }
    }

    #[async_trait::async_trait]
    impl FlowSpecWriter for SlowExportSpeaker {
        async fn announce(&self, _: &FlowSpecRule) -> Result<()> {
            panic!("export observation must not announce")
        }

        async fn withdraw(&self, _: &FlowSpecRule) -> Result<()> {
            panic!("export observation must not withdraw")
        }
    }

    #[async_trait::async_trait]
    impl crate::bgp::ExportObserver for SlowExportSpeaker {
        async fn blackhole_exports(
            &self,
            prefix: &ipnet::IpNet,
        ) -> Result<Option<Vec<crate::bgp::PeerExport>>> {
            tokio::time::sleep(self.read_time).await;
            // Record only completed reads: timeout may poll a future once even
            // when the pass deadline has already elapsed.
            self.completed.lock().unwrap().push(*prefix);
            Ok(Some(vec![crate::bgp::PeerExport {
                peer_address: "192.0.2.10".into(),
                disposition: crate::bgp::ExportDisposition::Committed,
                reason: String::new(),
                explain_code: String::new(),
                detail: String::new(),
                advertised_path_id: 0,
            }]))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn blackhole_export_reads_rotate_under_the_pass_budget() {
        use crate::domain::ExportObservation;
        use crate::observability::metrics::{
            BLACKHOLE_EXPORT_PEERS, BLACKHOLE_EXPORT_READ_ERRORS, BLACKHOLE_UNEXPORTED,
        };
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let speaker = Arc::new(SlowExportSpeaker {
            enabled: std::sync::atomic::AtomicBool::new(true),
            read_time: Duration::from_secs(6),
            completed: std::sync::Mutex::new(vec![]),
        });
        let reconciler = blackhole_reconciler(
            Arc::new(MockRepository::new()),
            speaker.clone(),
            live_config(),
            false,
        );
        let store = &reconciler.state.as_ref().unwrap().export_evidence;
        let candidates: Vec<_> = [
            "192.0.2.1/32",
            "192.0.2.2/32",
            "2001:db8::1/128",
            "2001:db8::2/128",
        ]
        .into_iter()
        .enumerate()
        .map(|(index, prefix)| {
            (
                uuid::Uuid::from_u128(index as u128 + 1),
                prefix.parse::<ipnet::IpNet>().unwrap(),
            )
        })
        .collect();

        // Only the first six-second read fits in each ten-second pass. Four
        // candidates also catch a cursor that advances past the timed-out read.
        for (pass, candidate) in candidates.iter().enumerate() {
            let mut unordered = candidates.clone();
            unordered.rotate_left((pass + 2) % candidates.len());
            if pass % 2 == 0 {
                unordered.reverse();
            }
            let started = tokio::time::Instant::now();
            reconciler
                .observe_blackhole_exports(Some(unordered), None, Some(0))
                .await;
            assert!(started.elapsed() >= EXPORT_OBSERVATION_BUDGET);
            // Tokio timers round wakeups to millisecond boundaries.
            assert!(started.elapsed() <= EXPORT_OBSERVATION_BUDGET + Duration::from_millis(1));
            let observed: Vec<_> = candidates
                .iter()
                .filter(|(id, _)| {
                    store.get(*id, Some(0)).unwrap().status == ExportObservation::Observed
                })
                .copied()
                .collect();
            assert_eq!(observed, vec![*candidate], "pass {pass}");
            let summary = store.summary(Some(0));
            assert_eq!((summary.blackholes, summary.errors), (4, 3));
            assert_eq!(summary.counts.committed, 1);
        }
        let expected: Vec<_> = candidates.iter().map(|(_, prefix)| *prefix).collect();
        assert_eq!(*speaker.completed.lock().unwrap(), expected);

        // Unknown inventory and unsupported observation retain the complete
        // snapshot and cursor; an authoritative empty inventory clears it.
        let previous = store.summary(Some(0));
        let previous_rows: Vec<_> = candidates
            .iter()
            .map(|(id, _)| store.get(*id, Some(0)))
            .collect();
        reconciler
            .observe_blackhole_exports(None, None, Some(0))
            .await;
        assert_eq!(reconciler.export_cursor.load(SeqCst), candidates.len());
        speaker.enabled.store(false, SeqCst);
        reconciler
            .observe_blackhole_exports(Some(candidates.clone()), None, Some(0))
            .await;
        assert_eq!(reconciler.export_cursor.load(SeqCst), candidates.len());
        reconciler
            .observe_blackhole_exports(Some(vec![]), None, Some(0))
            .await;
        assert_eq!(reconciler.export_cursor.load(SeqCst), candidates.len());
        assert_eq!(store.summary(Some(0)), previous);
        assert_eq!(
            candidates
                .iter()
                .map(|(id, _)| store.get(*id, Some(0)))
                .collect::<Vec<_>>(),
            previous_rows
        );
        assert_eq!(BLACKHOLE_EXPORT_READ_ERRORS.get(), 3.0);
        assert_eq!(
            BLACKHOLE_EXPORT_PEERS
                .with_label_values(&["committed"])
                .get(),
            1.0
        );
        speaker.enabled.store(true, SeqCst);
        reconciler
            .observe_blackhole_exports(Some(vec![]), None, Some(0))
            .await;
        assert_eq!(store.summary(Some(0)).blackholes, 0);
        assert_eq!(reconciler.export_cursor.load(SeqCst), candidates.len());
        assert!(
            candidates
                .iter()
                .all(|(id, _)| store.get(*id, Some(0)).is_none())
        );
        assert_eq!(BLACKHOLE_EXPORT_READ_ERRORS.get(), 0.0);
        for disposition in crate::bgp::ExportDisposition::ALL {
            assert_eq!(
                BLACKHOLE_EXPORT_PEERS
                    .with_label_values(&[disposition.as_str()])
                    .get(),
                0.0
            );
        }
        for reason in crate::domain::UNEXPORTED_REASONS {
            assert_eq!(BLACKHOLE_UNEXPORTED.with_label_values(&[reason]).get(), 0.0);
        }
        assert_eq!(*speaker.completed.lock().unwrap(), expected);
        reconciler
            .observe_blackhole_exports(Some(candidates.clone()), None, Some(0))
            .await;
        assert_eq!(
            speaker.completed.lock().unwrap().last(),
            Some(&candidates[0].1)
        );
        assert_eq!(speaker.completed.lock().unwrap().len(), 5);
    }

    /// With K reads per budget, the head moves K places per pass, so every
    /// one of N blackholes is read within ceil(N/K) passes.
    #[tokio::test(start_paused = true)]
    async fn blackhole_export_rotation_advances_by_the_reads_in_each_pass() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        // Two four-second reads fit in each ten-second pass; the third is cut off.
        let speaker = Arc::new(SlowExportSpeaker {
            enabled: std::sync::atomic::AtomicBool::new(true),
            read_time: Duration::from_secs(4),
            completed: std::sync::Mutex::new(vec![]),
        });
        let reconciler = blackhole_reconciler(
            Arc::new(MockRepository::new()),
            speaker.clone(),
            live_config(),
            false,
        );
        let candidates: Vec<_> = (1..=5u8)
            .map(|host| {
                (
                    uuid::Uuid::from_u128(host.into()),
                    format!("192.0.2.{host}/32")
                        .parse::<ipnet::IpNet>()
                        .unwrap(),
                )
            })
            .collect();
        for _ in 0..candidates.len().div_ceil(2) {
            reconciler
                .observe_blackhole_exports(Some(candidates.clone()), None, Some(0))
                .await;
        }
        let mut read = speaker.completed.lock().unwrap().clone();
        assert_eq!(read.len(), 6);
        read.sort();
        read.dedup();
        assert_eq!(
            read,
            candidates
                .iter()
                .map(|(_, prefix)| *prefix)
                .collect::<Vec<_>>(),
            "every blackhole is read within ceil(N/K) passes"
        );
        assert_eq!(reconciler.export_cursor.load(SeqCst), 6);
    }

    /// After loss and regain, a failed refresh keeps the previous owner's rows
    /// in health as historical, but the export gauges never count them as
    /// current: no committed peers and no unexported alert from old evidence.
    #[tokio::test]
    async fn historical_export_evidence_is_not_published_as_current_metrics() {
        use crate::bgp::{ExportDisposition, PeerExport};
        use crate::observability::metrics::{
            BLACKHOLE_EXPORT_PEERS, BLACKHOLE_EXPORT_READ_ERRORS, BLACKHOLE_UNEXPORTED,
        };
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let speaker = Arc::new(MockAnnouncer::new());
        let reconciler = blackhole_reconciler(
            Arc::new(MockRepository::new()),
            speaker.clone(),
            live_config(),
            false,
        );
        let state = reconciler.state.clone().unwrap();
        let export = |disposition, reason: &str| {
            Ok(vec![PeerExport {
                peer_address: "192.0.2.10".into(),
                disposition,
                reason: reason.into(),
                explain_code: String::new(),
                detail: String::new(),
                advertised_path_id: 0,
            }])
        };
        let committed = (uuid::Uuid::from_u128(1), "192.0.2.1/32".parse().unwrap());
        let withheld = (uuid::Uuid::from_u128(2), "192.0.2.2/32".parse().unwrap());
        let candidates = vec![committed, withheld];
        let gauges = || {
            (
                ExportDisposition::ALL.map(|disposition| {
                    BLACKHOLE_EXPORT_PEERS
                        .with_label_values(&[disposition.as_str()])
                        .get()
                }),
                crate::domain::UNEXPORTED_REASONS
                    .iter()
                    .map(|reason| BLACKHOLE_UNEXPORTED.with_label_values(&[reason]).get())
                    .sum::<f64>(),
                BLACKHOLE_EXPORT_READ_ERRORS.get(),
            )
        };
        speaker.set_exports(committed.1, export(ExportDisposition::Committed, ""));
        speaker.set_exports(
            withheld.1,
            export(ExportDisposition::Withheld, "export_policy"),
        );
        reconciler
            .observe_blackhole_exports(Some(candidates.clone()), None, Some(0))
            .await;
        assert_eq!(gauges(), ([1.0, 1.0, 0.0], 1.0, 0.0));

        state.fence.set(false);
        state.fence.set(true);
        for (_, prefix) in &candidates {
            speaker.set_exports(*prefix, Err("speaker unavailable".into()));
        }
        reconciler
            .observe_blackhole_exports(Some(candidates.clone()), None, Some(1))
            .await;
        let summary = state
            .fence
            .with_observation_epoch(|epoch| state.export_evidence.summary(epoch));
        assert!(summary.historical);
        assert_eq!(summary.counts.committed, 1, "health keeps historical rows");
        assert_eq!(summary.unexported.len(), 1);
        assert_eq!(
            gauges(),
            ([0.0, 0.0, 0.0], 0.0, 2.0),
            "historical rows are read errors, not current export"
        );

        // A fresh complete read is current again.
        speaker.set_exports(
            withheld.1,
            export(ExportDisposition::Withheld, "export_policy"),
        );
        reconciler
            .observe_blackhole_exports(Some(candidates.clone()), None, Some(1))
            .await;
        assert_eq!(gauges(), ([0.0, 1.0, 0.0], 1.0, 1.0));
    }

    struct PausedExportPrerequisite {
        inner: MockAnnouncer,
        inventory: bool,
        paused: std::sync::atomic::AtomicBool,
        started: tokio::sync::Notify,
        proceed: tokio::sync::Notify,
        export_reads: AtomicUsize,
    }

    impl FlowSpecAnnouncer for PausedExportPrerequisite {
        fn backend(&self) -> &'static str {
            "mock"
        }
        fn blackhole(&self) -> Option<&dyn BlackholeSpeaker> {
            Some(self)
        }
        fn peer_observer(&self) -> Option<&dyn PeerObserver> {
            Some(self)
        }
        fn export_observer(&self) -> Option<&dyn ExportObserver> {
            Some(self)
        }
    }

    #[async_trait::async_trait]
    impl FlowSpecWriter for PausedExportPrerequisite {
        async fn announce(&self, _: &FlowSpecRule) -> Result<()> {
            panic!("the seeded route needs no mutation")
        }
        async fn withdraw(&self, _: &FlowSpecRule) -> Result<()> {
            panic!("the seeded route needs no mutation")
        }
    }

    #[async_trait::async_trait]
    impl BlackholeSpeaker for PausedExportPrerequisite {
        async fn announce_blackhole(
            &self,
            _: &crate::bgp::BlackholeRoute,
        ) -> Result<crate::bgp::AddOutcome> {
            panic!("the seeded route needs no mutation")
        }
        async fn announce_leased_blackhole(
            &self,
            _: &crate::bgp::BlackholeRoute,
            _: u32,
        ) -> Result<(crate::bgp::LeaseGeneration, crate::bgp::AddOutcome)> {
            panic!("the seeded route needs no mutation")
        }
        async fn withdraw_blackhole(&self, _: &ipnet::IpNet, _: &str) -> Result<()> {
            panic!("the seeded route needs no mutation")
        }
        async fn list_blackholes(&self) -> Result<crate::bgp::BlackholeInventory> {
            let snapshot = self.inner.list_blackholes().await?;
            if self.inventory && self.paused.load(SeqCst) {
                self.started.notify_one();
                self.proceed.notified().await;
            }
            Ok(snapshot)
        }
    }

    #[async_trait::async_trait]
    impl PeerObserver for PausedExportPrerequisite {
        async fn session_status(&self) -> Result<Vec<PeerStatus>> {
            let mut snapshot = self.inner.session_status().await?;
            if !self.inventory && self.paused.load(SeqCst) {
                snapshot[0].state = crate::bgp::SessionState::Active;
                self.started.notify_one();
                self.proceed.notified().await;
            }
            Ok(snapshot)
        }
    }

    #[async_trait::async_trait]
    impl ExportObserver for PausedExportPrerequisite {
        async fn blackhole_exports(
            &self,
            prefix: &ipnet::IpNet,
        ) -> Result<Option<Vec<crate::bgp::PeerExport>>> {
            self.export_reads.fetch_add(1, SeqCst);
            self.inner.blackhole_exports(prefix).await
        }
    }

    #[tokio::test(start_paused = true)]
    async fn export_prerequisites_crossing_fence_loss_keep_the_previous_snapshot() {
        use crate::domain::{BlackholeExportEvidence, ExportObservation};
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        for inventory in [false, true] {
            let repo = Arc::new(MockRepository::new());
            let peer = PeerStatus {
                name: "192.0.2.10".into(),
                address: "192.0.2.10".into(),
                state: crate::bgp::SessionState::Established,
            };
            let speaker = Arc::new(PausedExportPrerequisite {
                inner: MockAnnouncer::with_peers(vec![peer.clone()]),
                inventory,
                paused: std::sync::atomic::AtomicBool::new(true),
                started: tokio::sync::Notify::new(),
                proceed: tokio::sync::Notify::new(),
                export_reads: AtomicUsize::new(0),
            });
            let mitigation = blackhole_row("192.0.2.1");
            repo.insert_mitigation(&mitigation).await.unwrap();
            let route = frozen(&mitigation);
            speaker.inner.announce_blackhole(&route).await.unwrap();
            let reconciler = Arc::new(blackhole_reconciler(
                repo,
                speaker.clone(),
                live_config(),
                false,
            ));
            let state = reconciler.state.clone().unwrap();
            let old_time = chrono::DateTime::from_timestamp(0, 0).unwrap();
            let original = BlackholeExportEvidence::from_read(
                &speaker.inner.blackhole_exports(&route.prefix()).await,
                Some(&[peer]),
                old_time,
            );
            state.export_evidence.replace(
                old_time,
                0,
                [(
                    mitigation.mitigation_id,
                    (route.prefix().to_string(), original.clone()),
                )]
                .into(),
            );
            let pass = tokio::spawn({
                let reconciler = reconciler.clone();
                async move { reconciler.reconcile().await }
            });
            speaker.started.notified().await;
            state.fence.set(false);
            state.fence.set(true);
            speaker.paused.store(false, SeqCst);
            speaker.proceed.notify_one();
            pass.await.unwrap().unwrap();

            let retained = state.fence.with_observation_epoch(|epoch| {
                state
                    .export_evidence
                    .get(mitigation.mitigation_id, epoch)
                    .unwrap()
            });
            assert!(retained.historical, "inventory={inventory}");
            assert_eq!(retained.observed_at, Some(old_time));
            assert_eq!(retained.peers, original.peers);
            assert_eq!(
                retained.not_established_peers,
                original.not_established_peers
            );
            assert_eq!(
                speaker.export_reads.load(SeqCst),
                0,
                "stale prerequisites start no export read"
            );
            assert_eq!(reconciler.export_cursor.load(SeqCst), 0);

            reconciler.reconcile().await.unwrap();
            let current = state.fence.with_observation_epoch(|epoch| {
                state
                    .export_evidence
                    .get(mitigation.mitigation_id, epoch)
                    .unwrap()
            });
            assert!(!current.historical);
            assert_eq!(current.status, ExportObservation::Observed);
            assert_ne!(current.observed_at, Some(old_time));
            assert_eq!(current.counts.committed, 1);
            assert_eq!(current.not_established_peers, Some(vec![]));
            assert_eq!(speaker.export_reads.load(SeqCst), 1);
        }
    }

    struct PausedExportRead {
        started: tokio::sync::Notify,
        proceed: tokio::sync::Notify,
    }

    impl FlowSpecAnnouncer for PausedExportRead {
        fn backend(&self) -> &'static str {
            "mock"
        }

        fn export_observer(&self) -> Option<&dyn crate::bgp::ExportObserver> {
            Some(self)
        }
    }

    #[async_trait::async_trait]
    impl FlowSpecWriter for PausedExportRead {
        async fn announce(&self, _: &FlowSpecRule) -> Result<()> {
            panic!("export observation must not announce")
        }

        async fn withdraw(&self, _: &FlowSpecRule) -> Result<()> {
            panic!("export observation must not withdraw")
        }
    }

    #[async_trait::async_trait]
    impl crate::bgp::ExportObserver for PausedExportRead {
        async fn blackhole_exports(
            &self,
            _: &ipnet::IpNet,
        ) -> Result<Option<Vec<crate::bgp::PeerExport>>> {
            self.started.notify_one();
            self.proceed.notified().await;
            Ok(Some(vec![crate::bgp::PeerExport {
                peer_address: "192.0.2.10".into(),
                disposition: crate::bgp::ExportDisposition::Committed,
                reason: String::new(),
                explain_code: String::new(),
                detail: String::new(),
                advertised_path_id: 0,
            }]))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn export_read_crossing_fence_loss_cannot_publish_current_evidence() {
        use crate::domain::{BlackholeExportEvidence, ExportObservation};
        use crate::observability::metrics::BLACKHOLE_EXPORT_PEERS;
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        for regain_in_flight in [false, true] {
            let speaker = Arc::new(PausedExportRead {
                started: tokio::sync::Notify::new(),
                proceed: tokio::sync::Notify::new(),
            });
            let reconciler = Arc::new(blackhole_reconciler(
                Arc::new(MockRepository::new()),
                speaker.clone(),
                live_config(),
                false,
            ));
            let state = reconciler.state.clone().unwrap();
            let id = uuid::Uuid::new_v4();
            let prefix: ipnet::IpNet = "192.0.2.1/32".parse().unwrap();
            let old_time = chrono::DateTime::from_timestamp(0, 0).unwrap();
            let old = BlackholeExportEvidence::from_read(&Ok(Some(vec![])), None, old_time);
            state
                .export_evidence
                .replace(old_time, 0, [(id, (prefix.to_string(), old))].into());
            BLACKHOLE_EXPORT_PEERS
                .with_label_values(&["committed"])
                .set(12.0);
            let pass = tokio::spawn({
                let reconciler = reconciler.clone();
                async move {
                    reconciler
                        .observe_blackhole_exports(Some(vec![(id, prefix)]), None, Some(0))
                        .await
                }
            });
            speaker.started.notified().await;
            state.fence.set(false);
            if regain_in_flight {
                state.fence.set(true);
            }
            speaker.proceed.notify_one();
            pass.await.unwrap();
            let retained = state
                .fence
                .with_observation_epoch(|epoch| state.export_evidence.get(id, epoch).unwrap());
            assert!(retained.historical, "regain_in_flight={regain_in_flight}");
            assert_eq!(
                retained.observed_at,
                Some(old_time),
                "crossing pass was discarded"
            );
            assert_eq!(retained.counts.committed, 0);
            assert_eq!(
                BLACKHOLE_EXPORT_PEERS
                    .with_label_values(&["committed"])
                    .get(),
                12.0
            );

            state.fence.set(true);
            speaker.proceed.notify_one();
            reconciler
                .observe_blackhole_exports(Some(vec![(id, prefix)]), None, Some(1))
                .await;
            let current = state
                .fence
                .with_observation_epoch(|epoch| state.export_evidence.get(id, epoch).unwrap());
            assert!(!current.historical);
            assert_eq!(current.status, ExportObservation::Observed);
            assert_eq!(current.counts.committed, 1);
        }
    }

    /// A stalled export read spends the pass's budget and no more: expiry has
    /// run, the lifecycle mutex is free during the stall, the pass returns,
    /// and every unread blackhole is an error (unknown export), keeping its
    /// last complete read's warning, never empty or committed.
    #[tokio::test(start_paused = true)]
    async fn stalled_export_read_is_cut_off_by_the_budget() {
        use crate::bgp::{ExportDisposition, PeerExport};
        use crate::domain::ExportObservation;
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(FaultyBlackholes::default());
        let reconciler = Arc::new(blackhole_reconciler(
            repo.clone(),
            speaker.clone(),
            live_config(),
            false,
        ));
        let rows = [blackhole_row("192.0.2.1"), blackhole_row("192.0.2.2")];
        for mitigation in &rows {
            repo.insert_mitigation(mitigation).await.unwrap();
        }
        let export = |disposition, reason: &str| {
            Ok(vec![PeerExport {
                peer_address: "192.0.2.10".into(),
                disposition,
                reason: reason.into(),
                explain_code: String::new(),
                detail: String::new(),
                advertised_path_id: 0,
            }])
        };
        speaker.inner.set_exports(
            frozen(&rows[0]).prefix(),
            export(ExportDisposition::Withheld, "export_policy"),
        );
        speaker.inner.set_exports(
            frozen(&rows[1]).prefix(),
            export(ExportDisposition::Committed, ""),
        );
        reconciler.reconcile().await.unwrap();
        let state = reconciler.state.clone().unwrap();
        assert_eq!(state.export_evidence.summary(Some(0)).unexported.len(), 1);

        let expired = expired_mitigation("192.0.2.9");
        repo.insert_mitigation(&expired).await.unwrap();
        speaker.inner.stall_exports.store(true, SeqCst);
        let pass = tokio::spawn({
            let reconciler = reconciler.clone();
            async move { reconciler.reconcile().await }
        });
        tokio::time::sleep(EXPORT_OBSERVATION_BUDGET / 2).await;
        assert!(!pass.is_finished(), "the read is stalled");
        assert!(
            state.mitigation_lock.try_lock().is_ok(),
            "no lifecycle lock is held while reading"
        );
        assert_eq!(status(&repo, &expired).await, MitigationStatus::Expired);
        let started = tokio::time::Instant::now();
        tokio::time::timeout(EXPORT_OBSERVATION_BUDGET * 6, pass)
            .await
            .expect("the budget ends a stalled read")
            .unwrap()
            .unwrap();
        assert!(started.elapsed() <= EXPORT_OBSERVATION_BUDGET);

        let evidence = |mitigation: &Mitigation| {
            state
                .export_evidence
                .get(mitigation.mitigation_id, Some(0))
                .unwrap()
        };
        for row in &rows {
            let evidence = evidence(row);
            assert_eq!(evidence.status, ExportObservation::Error);
            assert!(evidence.peers.is_empty());
            assert_eq!(evidence.counts.committed, 0);
        }
        assert_eq!(evidence(&rows[0]).warning.unwrap().reason, "export_policy");
        assert_eq!(evidence(&rows[1]).warning, None);
        let summary = state.export_evidence.summary(Some(0));
        assert_eq!((summary.blackholes, summary.errors), (2, 2));
        assert_eq!(
            summary.unexported.len(),
            1,
            "a stall does not clear degraded"
        );
    }

    /// One export read per active enforced blackhole per pass, never a write;
    /// bounded metrics by disposition and reason; a read error is unknown,
    /// not an empty export; dry-run blackholes are not read.
    #[tokio::test]
    async fn blackhole_export_observation_is_read_only_bounded_and_per_pass() {
        use crate::bgp::{ExportDisposition, PeerExport};
        use crate::domain::ExportObservation;
        use crate::observability::metrics::{
            BLACKHOLE_EXPORT_PEERS, BLACKHOLE_EXPORT_READ_ERRORS, BLACKHOLE_UNEXPORTED,
        };
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(FaultyBlackholes::default());
        let reconciler = blackhole_reconciler(repo.clone(), speaker.clone(), live_config(), false);
        let rows = [
            blackhole_row("192.0.2.1"),
            blackhole_row("192.0.2.2"),
            blackhole_row("192.0.2.3"),
        ];
        let mut simulated = blackhole_row("192.0.2.4");
        simulated.origin_mode = Some(crate::config::OperationMode::DryRun);
        for mitigation in rows.iter().chain([&simulated]) {
            repo.insert_mitigation(mitigation).await.unwrap();
        }
        let export = |disposition, reason: &str| PeerExport {
            peer_address: "192.0.2.10".into(),
            disposition,
            reason: reason.into(),
            explain_code: String::new(),
            detail: String::new(),
            advertised_path_id: 0,
        };
        let prefix = |mitigation: &Mitigation| frozen(mitigation).prefix();
        speaker.inner.set_exports(
            prefix(&rows[0]),
            Ok(vec![export(ExportDisposition::Committed, "")]),
        );
        speaker.inner.set_exports(
            prefix(&rows[1]),
            Ok(vec![export(ExportDisposition::Withheld, "export_policy")]),
        );
        speaker
            .inner
            .set_exports(prefix(&rows[2]), Err("speaker unavailable".into()));
        let label = |reason| BLACKHOLE_UNEXPORTED.with_label_values(&[reason]).get();

        reconciler.reconcile().await.unwrap();
        let adds = speaker.adds.load(SeqCst);
        assert_eq!(adds, 3, "repairs, not observation, add the missing routes");
        let store = &reconciler.state.as_ref().unwrap().export_evidence;
        let evidence =
            |mitigation: &Mitigation| store.get(mitigation.mitigation_id, Some(0)).unwrap();
        assert_eq!(evidence(&rows[0]).counts.committed, 1);
        assert_eq!(evidence(&rows[0]).warning, None);
        assert_eq!(evidence(&rows[1]).warning.unwrap().reason, "export_policy");
        assert_eq!(evidence(&rows[2]).status, ExportObservation::Error);
        assert!(evidence(&rows[2]).peers.is_empty());
        assert_eq!(evidence(&rows[2]).warning, None);
        // No peer observer on this speaker: the session join is unknown, not none.
        assert_eq!(evidence(&rows[0]).not_established_peers, None);
        assert!(
            store.get(simulated.mitigation_id, Some(0)).is_none(),
            "dry-run origin"
        );
        assert_eq!(store.summary(Some(0)).blackholes, 3);
        assert_eq!(label("export_policy"), 1.0);
        assert_eq!(label("no_established_peer"), 0.0);
        assert_eq!(BLACKHOLE_EXPORT_READ_ERRORS.get(), 1.0);
        for (disposition, expected) in [("committed", 1.0), ("withheld", 1.0), ("pending", 0.0)] {
            assert_eq!(
                BLACKHOLE_EXPORT_PEERS
                    .with_label_values(&[disposition])
                    .get(),
                expected
            );
        }

        // The next pass replaces the snapshot and resets the reason series.
        speaker.inner.set_exports(
            prefix(&rows[1]),
            Ok(vec![export(ExportDisposition::Committed, "")]),
        );
        reconciler.reconcile().await.unwrap();
        assert_eq!(label("export_policy"), 0.0);
        assert_eq!(speaker.adds.load(SeqCst), adds, "observation never writes");
        assert_eq!(speaker.deletes.load(SeqCst), 0);
    }

    #[tokio::test]
    async fn blackhole_failed_read_repairs_nothing_and_families_stay_independent() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(FaultyBlackholes::default());
        let reconciler = blackhole_reconciler(repo.clone(), speaker.clone(), live_config(), false);
        let missing = blackhole_row("192.0.2.1");
        let mut expired = blackhole_row("192.0.2.2");
        expired.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
        let flowspec = action_mitigation("192.0.2.3/32", FlowSpecAction::discard());
        for mitigation in [&missing, &expired, &flowspec] {
            repo.insert_mitigation(mitigation).await.unwrap();
        }
        speaker
            .inner
            .announce_blackhole(&frozen(&expired))
            .await
            .unwrap();
        speaker
            .unrecognized
            .lock()
            .unwrap()
            .push(crate::bgp::UnrecognizedRoute {
                prefix: "198.51.100.1/32".parse().unwrap(),
                reason: "nonzero path_id",
            });
        let unknown =
            crate::observability::metrics::UNKNOWN_LOCAL_ROUTES.with_label_values(&["blackhole"]);
        unknown.set(7.0);
        speaker.fail_reads.store(true, SeqCst);
        assert!(reconciler.reconcile().await.is_err());
        // No repair and no unknown-route verdict from a failed read.
        assert_eq!(speaker.adds.load(SeqCst), 0);
        assert_eq!(unknown.get(), 7.0);
        // FlowSpec repair and blackhole expiry cleanup continue.
        assert_eq!(speaker.inner.announced_count().await, 1);
        assert_eq!(status(&repo, &expired).await, MitigationStatus::Expired);
        assert!(speaker.routes().await.is_empty());

        // The reverse: a failed FlowSpec read leaves blackhole repair running.
        speaker.fail_reads.store(false, SeqCst);
        speaker.fail_flowspec_reads.store(true, SeqCst);
        speaker
            .inner
            .withdraw(&crate::domain::mitigation_rule(&flowspec).unwrap())
            .await
            .unwrap();
        assert!(reconciler.reconcile().await.is_err());
        assert_eq!(speaker.adds.load(SeqCst), 1);
        assert_eq!(speaker.routes().await, [frozen(&missing)]);
        assert_eq!(speaker.inner.announced_count().await, 0);
        assert_eq!(unknown.get(), 1.0);
    }

    #[tokio::test]
    async fn blackhole_unknown_unrecognized_and_foreign_pop_routes_are_untouched() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(FaultyBlackholes::default());
        let reconciler = blackhole_reconciler(repo.clone(), speaker.clone(), live_config(), false);
        let desired = blackhole_row("192.0.2.1");
        // An unrecognized row holds this desired key, so it is reported, not overwritten.
        let blocked = blackhole_row("192.0.2.2");
        let foreign = |ip| {
            let mut mitigation = blackhole_row(ip);
            mitigation.pop = "another-target".into();
            mitigation
        };
        let foreign_missing = foreign("192.0.2.3");
        let foreign_present = foreign("192.0.2.4");
        let mut foreign_expired = foreign("192.0.2.5");
        foreign_expired.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
        for mitigation in [
            &desired,
            &blocked,
            &foreign_missing,
            &foreign_present,
            &foreign_expired,
        ] {
            repo.insert_mitigation(mitigation).await.unwrap();
        }
        let unknown_route = crate::bgp::BlackholeRoute::new(
            "198.51.100.1/32".parse().unwrap(),
            "192.0.2.99".parse().unwrap(),
            vec![],
            vec![],
        )
        .unwrap();
        for route in [
            frozen(&foreign_present),
            frozen(&foreign_expired),
            unknown_route.clone(),
        ] {
            speaker.inner.announce_blackhole(&route).await.unwrap();
        }
        let unrecognized = [
            crate::bgp::UnrecognizedRoute {
                prefix: "192.0.2.2/32".parse().unwrap(),
                reason: "unexpected path attributes",
            },
            crate::bgp::UnrecognizedRoute {
                prefix: "198.51.100.2/32".parse().unwrap(),
                reason: "nonzero path_id",
            },
        ];
        *speaker.unrecognized.lock().unwrap() = unrecognized.to_vec();
        for _ in 0..2 {
            assert!(reconciler.reconcile().await.is_err());
            assert_eq!(speaker.adds.load(SeqCst), 1);
            assert_eq!(speaker.deletes.load(SeqCst), 0);
            let routes = speaker.routes().await;
            assert_eq!(routes.len(), 4);
            for route in [
                frozen(&desired),
                frozen(&foreign_present),
                frozen(&foreign_expired),
                unknown_route.clone(),
            ] {
                assert!(routes.contains(&route));
            }
            assert_eq!(*speaker.unrecognized.lock().unwrap(), unrecognized);
            assert!(status(&repo, &foreign_expired).await.is_active());
            // Other POPs' routes and the unknown route, plus both unrecognized rows.
            assert_eq!(
                crate::observability::metrics::UNKNOWN_LOCAL_ROUTES
                    .with_label_values(&["blackhole"])
                    .get(),
                5.0
            );
        }
    }

    /// A live row that expired while the controller was down is withdrawn through
    /// the immutable path on the first reconcile of a fresh loop.
    #[tokio::test]
    async fn overdue_blackhole_is_withdrawn_on_the_first_reconcile_after_a_restart() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(FaultyBlackholes::default());
        let mut overdue = blackhole_row("192.0.2.1");
        overdue.expires_at = chrono::Utc::now() - chrono::Duration::hours(2);
        repo.insert_mitigation(&overdue).await.unwrap();
        speaker
            .inner
            .announce_blackhole(&frozen(&overdue))
            .await
            .unwrap();
        // A fresh loop, as after a restart.
        blackhole_reconciler(repo.clone(), speaker.clone(), live_config(), false)
            .reconcile()
            .await
            .unwrap();
        assert_eq!(status(&repo, &overdue).await, MitigationStatus::Expired);
        assert!(speaker.routes().await.is_empty());
        assert_eq!(speaker.deletes.load(SeqCst), 1);
        assert_eq!(speaker.adds.load(SeqCst), 0);
    }

    /// Only a route that exactly matches a terminal, enforced-origin row of this
    /// POP, with no live owner, is withdrawn; everything else is only reported.
    #[tokio::test]
    async fn terminal_row_orphan_is_withdrawn_and_other_routes_are_only_reported() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(FaultyBlackholes::default());
        let terminal = |ip, status| {
            let mut mitigation = blackhole_row(ip);
            mitigation.status = status;
            mitigation
        };
        // Withdrawn locally while the controller ran in dry-run; the route stayed.
        let orphan = terminal("192.0.2.1", MitigationStatus::Withdrawn);
        // The present route differs from the frozen one (another next hop).
        let drifted = terminal("192.0.2.2", MitigationStatus::Expired);
        // A simulation was never sent, so it cannot own a route.
        let mut simulated = terminal("192.0.2.3", MitigationStatus::Expired);
        simulated.origin_mode = Some(crate::config::OperationMode::DryRun);
        // Another POP's terminal row is not this controller's.
        let mut foreign = terminal("192.0.2.4", MitigationStatus::Withdrawn);
        foreign.pop = "another-target".into();
        // A live owner of the same route keeps it.
        let replaced = terminal("192.0.2.5", MitigationStatus::Withdrawn);
        let live = blackhole_row("192.0.2.5");
        for mitigation in [&orphan, &drifted, &simulated, &foreign, &replaced, &live] {
            repo.insert_mitigation(mitigation).await.unwrap();
        }
        let other_next_hop = crate::bgp::BlackholeRoute::new(
            "192.0.2.2/32".parse().unwrap(),
            "192.0.2.99".parse().unwrap(),
            frozen(&drifted).communities().to_vec(),
            vec![],
        )
        .unwrap();
        let no_ledger_row = crate::bgp::BlackholeRoute::new(
            "198.51.100.1/32".parse().unwrap(),
            "192.0.2.66".parse().unwrap(),
            vec![],
            vec![],
        )
        .unwrap();
        for route in [
            frozen(&orphan),
            other_next_hop.clone(),
            frozen(&simulated),
            frozen(&foreign),
            frozen(&live),
            no_ledger_row.clone(),
        ] {
            speaker.inner.announce_blackhole(&route).await.unwrap();
        }
        let all = speaker.routes().await;
        let unknown =
            crate::observability::metrics::UNKNOWN_LOCAL_ROUTES.with_label_values(&["blackhole"]);

        // A failed read does nothing.
        speaker.fail_reads.store(true, SeqCst);
        let reconciler = blackhole_reconciler(repo.clone(), speaker.clone(), live_config(), false);
        assert!(reconciler.reconcile().await.is_err());
        speaker.fail_reads.store(false, SeqCst);
        // Dry-run reports and sends nothing.
        blackhole_reconciler(repo.clone(), speaker.clone(), live_config(), true)
            .reconcile()
            .await
            .unwrap();
        assert_eq!(speaker.deletes.load(SeqCst), 0);
        assert_eq!(speaker.routes().await, all);
        assert_eq!(unknown.get(), 5.0);

        reconciler.reconcile().await.unwrap();
        assert_eq!(speaker.deletes.load(SeqCst), 1);
        let remaining = speaker.routes().await;
        assert!(!remaining.contains(&frozen(&orphan)));
        assert_eq!(remaining.len(), all.len() - 1);
        assert_eq!(unknown.get(), 4.0);
        assert_eq!(speaker.adds.load(SeqCst), 0);
        // The row stays terminal; the deletion is audited with its reason.
        assert_eq!(status(&repo, &orphan).await, MitigationStatus::Withdrawn);
        let audit = repo
            .list_audit(&crate::db::ListParams {
                limit: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        let orphan_id = orphan.mitigation_id.to_string();
        assert!(audit.iter().any(|entry| entry.action == "withdraw"
            && entry.target_id.as_deref() == Some(orphan_id.as_str())
            && entry.details["reason"] == ORPHANED_AFTER_DOWNTIME));
        // Converged: a second pass sends nothing more.
        reconciler.reconcile().await.unwrap();
        assert_eq!(speaker.deletes.load(SeqCst), 1);
    }

    #[tokio::test]
    async fn safelisted_blackhole_is_withdrawn_rather_than_repaired() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(FaultyBlackholes::default());
        let (tx, mut rx) = broadcast::channel(8);
        let reconciler = blackhole_reconciler(repo.clone(), speaker.clone(), live_config(), false)
            .with_ws_broadcast(tx);
        let victim = blackhole_row("192.0.2.1");
        // Negative control: an unsafelisted victim in the same pass is repaired.
        let other = blackhole_row("192.0.2.9");
        for mitigation in [&victim, &other] {
            repo.insert_mitigation(mitigation).await.unwrap();
        }
        repo.insert_safelist("192.0.2.0/30", "admin", None)
            .await
            .unwrap();
        for _ in 0..2 {
            reconciler.reconcile().await.unwrap();
            assert_eq!(speaker.adds.load(SeqCst), 1);
            assert_eq!(speaker.routes().await, [frozen(&other)]);
        }
        assert_eq!(status(&repo, &victim).await, MitigationStatus::Withdrawn);
        assert!(repo.pending_withdrawals(None).await.unwrap().is_empty());
        assert!(matches!(
            rx.try_recv().unwrap(),
            WsMessage::MitigationWithdrawn { mitigation_id } if mitigation_id == victim.mitigation_id.to_string()
        ));
        let audit = repo
            .list_audit(&crate::db::ListParams {
                limit: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        let entry = audit
            .iter()
            .find(|entry| entry.target_id.as_deref() == Some(&victim.mitigation_id.to_string()))
            .unwrap();
        assert_eq!(entry.action, "withdraw");
        assert!(matches!(
            entry.actor_type,
            crate::observability::ActorType::System
        ));
        assert_eq!(
            entry.details["reason"],
            crate::domain::SAFELISTED_AFTER_ADMISSION
        );
    }

    #[tokio::test]
    async fn blackhole_safelist_lookup_failure_sends_nothing() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(FaultyBlackholes::default());
        let reconciler = blackhole_reconciler(repo.clone(), speaker.clone(), live_config(), false);
        let missing = blackhole_row("192.0.2.1");
        repo.insert_mitigation(&missing).await.unwrap();
        let errors =
            crate::observability::metrics::RECONCILIATION_REPAIRS.with_label_values(&["error"]);
        let before = errors.get();
        repo.fail_safelist.store(true, SeqCst);
        assert!(reconciler.reconcile().await.is_err());
        assert_eq!(speaker.adds.load(SeqCst), 0);
        assert!(speaker.routes().await.is_empty());
        assert!(status(&repo, &missing).await.is_active());
        assert!(repo.pending_withdrawals(None).await.unwrap().is_empty());
        assert_eq!(errors.get(), before + 1.0);
        // Negative control: once the lookup works, the same row is repaired.
        repo.fail_safelist.store(false, SeqCst);
        reconciler.reconcile().await.unwrap();
        assert_eq!(speaker.routes().await, [frozen(&missing)]);
    }

    #[tokio::test]
    async fn present_blackhole_safelisted_in_the_database_converges_to_withdrawn() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(FaultyBlackholes::default());
        let reconciler = blackhole_reconciler(repo.clone(), speaker.clone(), live_config(), false);
        let covered = blackhole_row("192.0.2.1");
        let outside = blackhole_row("192.0.2.9");
        for mitigation in [&covered, &outside] {
            repo.insert_mitigation(mitigation).await.unwrap();
            speaker
                .inner
                .announce_blackhole(&frozen(mitigation))
                .await
                .unwrap();
        }
        // Written straight to the database, as config seeding does; no API call.
        repo.insert_safelist("192.0.2.0/30", "config", None)
            .await
            .unwrap();
        // A failed safelist lookup takes no action.
        repo.fail_safelist.store(true, SeqCst);
        assert!(reconciler.reconcile().await.is_err());
        assert_eq!(speaker.deletes.load(SeqCst), 0);
        assert!(status(&repo, &covered).await.is_active());
        assert!(repo.pending_withdrawals(None).await.unwrap().is_empty());
        // Dry-run reports and sends nothing.
        repo.fail_safelist.store(false, SeqCst);
        blackhole_reconciler(repo.clone(), speaker.clone(), live_config(), true)
            .reconcile()
            .await
            .unwrap();
        assert_eq!(speaker.deletes.load(SeqCst), 0);
        assert!(status(&repo, &covered).await.is_active());
        // The next enforced pass withdraws only the covered route, once.
        for _ in 0..2 {
            reconciler.reconcile().await.unwrap();
            assert_eq!(speaker.deletes.load(SeqCst), 1);
            assert_eq!(speaker.adds.load(SeqCst), 0);
            assert_eq!(speaker.routes().await, [frozen(&outside)]);
        }
        assert_eq!(status(&repo, &covered).await, MitigationStatus::Withdrawn);
        assert!(status(&repo, &outside).await.is_active());
        let audit = repo
            .list_audit(&crate::db::ListParams {
                limit: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        let entry = audit
            .iter()
            .find(|entry| entry.target_id.as_deref() == Some(&covered.mitigation_id.to_string()))
            .unwrap();
        assert_eq!(
            entry.details["reason"],
            crate::domain::SAFELISTED_AFTER_ADMISSION
        );
    }

    #[tokio::test]
    async fn blackhole_repair_and_withdrawal_use_the_frozen_route_after_config_change() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(FaultyBlackholes::default());
        // The configuration changed after both rows were admitted.
        let changed = blackhole_config("192.0.2.77", "64512:2");
        let missing = blackhole_row("192.0.2.1");
        let drifted = blackhole_row("192.0.2.2");
        for mitigation in [&missing, &drifted] {
            repo.insert_mitigation(mitigation).await.unwrap();
        }
        let current =
            crate::domain::BlackholeRule::from_config(&changed, "192.0.2.2/32".parse().unwrap())
                .unwrap()
                .route()
                .unwrap();
        speaker.inner.announce_blackhole(&current).await.unwrap();
        // Dry-run reports and sends nothing.
        blackhole_reconciler(repo.clone(), speaker.clone(), changed.clone(), true)
            .reconcile()
            .await
            .unwrap();
        assert_eq!(speaker.adds.load(SeqCst), 0);
        let reconciler = blackhole_reconciler(repo.clone(), speaker.clone(), changed, false);
        for _ in 0..2 {
            reconciler.reconcile().await.unwrap();
            assert_eq!(speaker.adds.load(SeqCst), 2);
            let routes = speaker.routes().await;
            assert_eq!(routes.len(), 2);
            for mitigation in [&missing, &drifted] {
                assert!(routes.contains(&frozen(mitigation)));
                assert_eq!(frozen(mitigation).next_hop().to_string(), "192.0.2.66");
            }
        }
        let request = request_withdrawal(
            repo.as_ref(),
            &missing,
            false,
            "operator",
            "alice",
            "test".into(),
            true,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<crate::domain::BlackholeRule>(&request.rule_json).unwrap(),
            crate::domain::blackhole_rule(&missing).unwrap()
        );
    }

    #[tokio::test]
    async fn pending_blackhole_withdrawal_does_not_block_flowspec_admission_or_repair() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(FaultyBlackholes::default());
        let blackhole = blackhole_row("192.0.2.1");
        repo.insert_mitigation(&blackhole).await.unwrap();
        speaker
            .inner
            .announce_blackhole(&frozen(&blackhole))
            .await
            .unwrap();
        speaker.withdraw_fault.store(1, SeqCst);
        let request = request_withdrawal(
            repo.as_ref(),
            &blackhole,
            false,
            "operator",
            "alice",
            "test".into(),
            true,
            None,
        )
        .await
        .unwrap();
        assert!(
            execute_withdrawal(repo.as_ref(), speaker.as_ref(), false, &request, None)
                .await
                .is_err()
        );
        // A FlowSpec rule on the same host is a separate, unblocked identity.
        let flowspec = action_mitigation("192.0.2.1/32", FlowSpecAction::discard());
        repo.insert_mitigation(&flowspec).await.unwrap();
        let owner = |mitigation: &Mitigation| {
            let route = MitigationRoute::of(mitigation);
            let scope = mitigation.scope_hash.clone();
            let repo = repo.clone();
            async move {
                crate::domain::find_mitigation_owner(repo.as_ref(), "test", &route, &scope).await
            }
        };
        assert_eq!(
            owner(&flowspec)
                .await
                .unwrap()
                .map(|found| found.mitigation_id),
            Some(flowspec.mitigation_id)
        );
        let candidate = action_mitigation("192.0.2.7/32", FlowSpecAction::discard());
        assert!(owner(&candidate).await.unwrap().is_none());
        // The blackhole itself still reports its pending withdrawal.
        assert!(matches!(
            owner(&blackhole).await,
            Err(PrefixdError::Conflict(_))
        ));
        let reconciler = blackhole_reconciler(repo.clone(), speaker.clone(), live_config(), false);
        reconciler.sync_announcements().await.unwrap();
        assert_eq!(speaker.inner.announced_count().await, 1);
        assert_eq!(speaker.adds.load(SeqCst), 0);
    }

    const LEASE_OWNER: &str = "prefixd.test.0123456789abcdef";

    /// Live leased blackhole intent recorded under `LEASE_OWNER`.
    fn leased_row(ip: &str) -> Mitigation {
        let mut mitigation = blackhole_row(ip);
        mitigation.action_params.blackhole.as_mut().unwrap().owner = LEASE_OWNER.into();
        mitigation
    }

    fn leased_reconciler(
        repo: Arc<MockRepository>,
        speaker: Arc<FaultyBlackholes>,
        lease: Arc<crate::domain::LeaseKeeper>,
    ) -> ReconciliationLoop {
        let config = crate::config::BlackholeConfig {
            leased: true,
            ..live_config()
        };
        blackhole_reconciler(repo, speaker, config, false).with_lease(lease)
    }

    /// As at admission, only an unleased repair add that replaced a different
    /// local route counts, once, on the configured POP.
    #[tokio::test]
    async fn replacement_counter_counts_unleased_replaced_repairs() {
        use crate::bgp::AddOutcome;
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let counter =
            crate::observability::metrics::BLACKHOLE_REPLACED.with_label_values(&["test"]);
        for (name, leased, outcome) in [
            ("unleased created", false, Some(AddOutcome::Created)),
            ("unleased unchanged", false, Some(AddOutcome::Unchanged)),
            ("unleased replaced", false, Some(AddOutcome::Replaced)),
            ("leased created", true, Some(AddOutcome::Created)),
            ("leased unchanged", true, Some(AddOutcome::Unchanged)),
            ("leased replaced", true, Some(AddOutcome::Replaced)),
            ("unleased error", false, None),
            ("leased error", true, None),
        ] {
            let before = counter.get();
            let repo = Arc::new(MockRepository::new());
            let speaker = Arc::new(FaultyBlackholes::default());
            let lease = Arc::new(crate::domain::LeaseKeeper::new(LEASE_OWNER.into(), 60));
            let (reconciler, row) = if leased {
                let reconciler = leased_reconciler(repo.clone(), speaker.clone(), lease);
                (reconciler, leased_row("192.0.2.1"))
            } else {
                let reconciler =
                    blackhole_reconciler(repo.clone(), speaker.clone(), live_config(), false);
                (reconciler, blackhole_row("192.0.2.1"))
            };
            repo.insert_mitigation(&row).await.unwrap();
            // The repair read finds nothing; this route lands just before the add.
            if matches!(outcome, Some(AddOutcome::Unchanged | AddOutcome::Replaced)) {
                let mut raced = row.clone();
                if outcome == Some(AddOutcome::Replaced) {
                    raced.action_params.blackhole.as_mut().unwrap().next_hop =
                        "192.0.2.99".parse().unwrap();
                }
                *speaker.before_add.lock().unwrap() = Some(frozen(&raced));
            }
            speaker.fail_adds.store(outcome.is_none(), SeqCst);
            assert_eq!(
                reconciler.reconcile().await.is_ok(),
                outcome.is_some(),
                "{name}"
            );
            let increment = if !leased && outcome == Some(AddOutcome::Replaced) {
                1.0
            } else {
                0.0
            };
            assert_eq!(counter.get(), before + increment, "{name}");
            // The speaker reported the case's outcome.
            let audited: Vec<String> = repo
                .list_audit(&crate::db::ListParams {
                    limit: 1000,
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_iter()
                .filter(|entry| entry.action == "announce")
                .map(|entry| entry.details["outcome"].as_str().unwrap().into())
                .collect();
            let expected_audit: &[&str] = match outcome {
                Some(AddOutcome::Created) => &["created"],
                Some(AddOutcome::Replaced) => &["replaced"],
                _ => &[],
            };
            assert_eq!(audited, expected_audit, "{name}");
            let expected_routes = if outcome.is_some() {
                vec![frozen(&row)]
            } else {
                vec![]
            };
            assert_eq!(speaker.routes().await, expected_routes, "{name}");
            assert_eq!(speaker.adds.load(SeqCst), usize::from(!leased), "{name}");
            assert_eq!(
                speaker.leased_adds.load(SeqCst),
                usize::from(leased),
                "{name}"
            );
        }
    }

    /// A refused renewal wakes the reconciler at once for a full leased re-add,
    /// which adopts the new generation. Unleased rows keep `AddPath`; leased
    /// rows never use it.
    #[tokio::test]
    async fn refused_renewal_triggers_an_immediate_full_leased_readd() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(FaultyBlackholes::default());
        let lease = Arc::new(crate::domain::LeaseKeeper::new(LEASE_OWNER.into(), 60));
        let reconciler = leased_reconciler(repo.clone(), speaker.clone(), lease.clone());
        let leased = [leased_row("192.0.2.1"), leased_row("192.0.2.2")];
        let unleased = blackhole_row("192.0.2.3");
        for mitigation in leased.iter().chain([&unleased]) {
            repo.insert_mitigation(mitigation).await.unwrap();
        }
        let counts = || (speaker.adds.load(SeqCst), speaker.leased_adds.load(SeqCst));
        // Startup re-adds the leased intent and adopts the generation.
        reconciler.reconcile().await.unwrap();
        assert_eq!(counts(), (1, 2));
        let first = lease.generation().unwrap();
        let routes = speaker.routes().await;
        for mitigation in leased.iter().chain([&unleased]) {
            assert!(routes.contains(&frozen(mitigation)));
        }
        // Converged: nothing is re-added.
        reconciler.reconcile().await.unwrap();
        assert_eq!(counts(), (1, 2));

        // The daemon restarted: the renewal is refused and a re-add requested now.
        speaker.inner.restart().await;
        lease.renew_once(speaker.as_ref()).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), lease.readd_requested())
                .await
                .is_ok(),
            "a refused renewal must wake the reconciler, not wait for its poll"
        );
        reconciler.reconcile().await.unwrap();
        assert_eq!(counts(), (2, 4));
        let second = lease.generation().unwrap();
        assert_ne!(second.incarnation, first.incarnation);
        assert!(!lease.take_readd(), "the re-add completed");
        assert_eq!(speaker.routes().await.len(), 3);

        // Deletes pass the owner each route was added under.
        for mitigation in [&leased[0], &unleased] {
            let request = request_withdrawal(
                repo.as_ref(),
                mitigation,
                false,
                "operator",
                "alice",
                "attack over".into(),
                true,
                None,
            )
            .await
            .unwrap();
            execute_withdrawal(repo.as_ref(), speaker.as_ref(), false, &request, None)
                .await
                .unwrap();
        }
        assert_eq!(*speaker.delete_owners.lock().unwrap(), [LEASE_OWNER, ""]);
    }

    /// A leased add returning another generation means earlier state may be
    /// gone: the next pass re-adds every leased route, present ones included.
    #[tokio::test]
    async fn a_changed_generation_re_adds_present_leased_routes_too() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(FaultyBlackholes::default());
        let lease = Arc::new(crate::domain::LeaseKeeper::new(LEASE_OWNER.into(), 60));
        let reconciler = leased_reconciler(repo.clone(), speaker.clone(), lease.clone());
        let [first, second] = [leased_row("192.0.2.1"), leased_row("192.0.2.2")];
        for mitigation in [&first, &second] {
            repo.insert_mitigation(mitigation).await.unwrap();
        }
        reconciler.reconcile().await.unwrap();
        assert_eq!(speaker.leased_adds.load(SeqCst), 2);
        // The lease lapsed and another add started a new generation; one route is back.
        speaker.inner.expire_lease(LEASE_OWNER).await;
        speaker
            .inner
            .announce_leased_blackhole(&frozen(&second), 60)
            .await
            .unwrap();
        reconciler.reconcile().await.unwrap();
        // Only the missing route was repaired; its new generation requested a full re-add.
        assert_eq!(speaker.leased_adds.load(SeqCst), 3);
        assert!(lease.take_readd());
        lease.request_readd();
        reconciler.reconcile().await.unwrap();
        assert_eq!(speaker.leased_adds.load(SeqCst), 5);
        assert!(!lease.take_readd());
        assert_eq!(speaker.adds.load(SeqCst), 0);
    }

    /// A row of ours with no lease time left forces the full re-add; another
    /// owner's rows and unowned rows are reported and never modified.
    #[tokio::test]
    async fn expired_rows_force_a_readd_and_foreign_rows_stay_untouched() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(FaultyBlackholes::default());
        let lease = Arc::new(crate::domain::LeaseKeeper::new(LEASE_OWNER.into(), 60));
        let reconciler = leased_reconciler(repo.clone(), speaker.clone(), lease.clone());
        let desired = leased_row("192.0.2.1");
        repo.insert_mitigation(&desired).await.unwrap();
        let foreign = crate::bgp::BlackholeRoute::new(
            "192.0.2.9/32".parse().unwrap(),
            "192.0.2.66".parse().unwrap(),
            vec![(64512 << 16) | 1],
            vec![],
        )
        .unwrap();
        speaker
            .inner
            .announce_leased_blackhole(&foreign.clone().with_owner("other.owner"), 60)
            .await
            .unwrap();
        let unowned = crate::bgp::BlackholeRoute::new(
            "192.0.2.10/32".parse().unwrap(),
            "192.0.2.66".parse().unwrap(),
            vec![],
            vec![],
        )
        .unwrap();
        speaker.inner.announce_blackhole(&unowned).await.unwrap();
        reconciler.reconcile().await.unwrap();
        assert_eq!(speaker.leased_adds.load(SeqCst), 1);
        reconciler.reconcile().await.unwrap();
        assert_eq!(speaker.leased_adds.load(SeqCst), 1);
        // The speaker reports our row expired, withdrawal pending.
        *speaker.expired.lock().unwrap() = vec![frozen(&desired)];
        reconciler.reconcile().await.unwrap();
        assert_eq!(speaker.leased_adds.load(SeqCst), 2);
        speaker.expired.lock().unwrap().clear();
        assert_eq!(speaker.deletes.load(SeqCst), 0);
        let routes = speaker.routes().await;
        assert!(routes.contains(&foreign.with_owner("other.owner")));
        assert!(routes.contains(&unowned));
        assert_eq!(
            crate::observability::metrics::UNKNOWN_LOCAL_ROUTES
                .with_label_values(&["blackhole"])
                .get(),
            2.0
        );
    }

    /// Without the controller's lease, a leased row is never repaired, and never unleased.
    #[tokio::test]
    async fn leased_intent_without_the_lease_fails_closed() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(FaultyBlackholes::default());
        let reconciler = blackhole_reconciler(repo.clone(), speaker.clone(), live_config(), false);
        repo.insert_mitigation(&leased_row("192.0.2.1"))
            .await
            .unwrap();
        assert!(reconciler.reconcile().await.is_err());
        assert_eq!(speaker.adds.load(SeqCst), 0);
        assert_eq!(speaker.leased_adds.load(SeqCst), 0);
    }

    /// Live leased FlowSpec intent recorded under `LEASE_OWNER`.
    fn leased_rule_row(prefix: &str) -> Mitigation {
        let mut mitigation = action_mitigation(prefix, FlowSpecAction::discard());
        mitigation.action_params.injection_owner = LEASE_OWNER.into();
        mitigation
    }

    /// Leased FlowSpec shares the controller's lease with blackholes: one
    /// generation, and a refused renewal re-adds both kinds at once, never
    /// through `AddFlowSpec`.
    #[tokio::test]
    async fn leased_flowspec_shares_the_lease_and_is_re_added_after_a_refused_renewal() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(FaultyBlackholes::default());
        let lease = Arc::new(crate::domain::LeaseKeeper::new(LEASE_OWNER.into(), 60));
        let reconciler = leased_reconciler(repo.clone(), speaker.clone(), lease.clone());
        let rule_row = leased_rule_row("192.0.2.10/32");
        let unleased_rule = action_mitigation("192.0.2.11/32", FlowSpecAction::discard());
        let blackhole = leased_row("192.0.2.1");
        for mitigation in [&rule_row, &unleased_rule, &blackhole] {
            repo.insert_mitigation(mitigation).await.unwrap();
        }
        let counts = || {
            (
                speaker.flowspec_adds.load(SeqCst),
                speaker.leased_flowspec_adds.load(SeqCst),
                speaker.leased_adds.load(SeqCst),
            )
        };
        reconciler.reconcile().await.unwrap();
        assert_eq!(counts(), (1, 1, 1));
        let generation = lease.generation().unwrap();
        assert!(!lease.take_readd(), "both kinds joined one generation");
        let rules = speaker.inner.list_active().await.unwrap();
        let owner = |prefix: &str| {
            rules
                .iter()
                .find(|rule| rule.nlri.dst_prefix == prefix)
                .map(|rule| rule.owner.clone())
        };
        assert_eq!(owner("192.0.2.10/32").as_deref(), Some(LEASE_OWNER));
        assert_eq!(owner("192.0.2.11/32").as_deref(), Some(""));
        reconciler.reconcile().await.unwrap();
        assert_eq!(counts(), (1, 1, 1), "converged");

        speaker.inner.restart().await;
        lease.renew_once(speaker.as_ref()).await;
        reconciler.reconcile().await.unwrap();
        assert_eq!(counts(), (2, 2, 2));
        assert_ne!(lease.generation().unwrap(), generation);
        assert!(!lease.take_readd());

        // Deletes pass the recorded owner.
        for mitigation in [&rule_row, &unleased_rule] {
            let request = request_withdrawal(
                repo.as_ref(),
                mitigation,
                false,
                "operator",
                "alice",
                "attack over".into(),
                true,
                None,
            )
            .await
            .unwrap();
            assert_eq!(
                request.flowspec_rule().unwrap().owner,
                mitigation.action_params.injection_owner
            );
            execute_withdrawal(repo.as_ref(), speaker.as_ref(), false, &request, None)
                .await
                .unwrap();
        }
        assert_eq!(
            *speaker.flowspec_delete_owners.lock().unwrap(),
            [LEASE_OWNER, ""]
        );
    }

    /// A requested full re-add sends every leased rule again, present ones
    /// included; unleased rules are left alone.
    #[tokio::test]
    async fn a_full_readd_re_adds_present_leased_flowspec_rules() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(FaultyBlackholes::default());
        let lease = Arc::new(crate::domain::LeaseKeeper::new(LEASE_OWNER.into(), 60));
        let reconciler = leased_reconciler(repo.clone(), speaker.clone(), lease.clone());
        for mitigation in [
            leased_rule_row("192.0.2.10/32"),
            leased_rule_row("192.0.2.12/32"),
            action_mitigation("192.0.2.11/32", FlowSpecAction::discard()),
        ] {
            repo.insert_mitigation(&mitigation).await.unwrap();
        }
        reconciler.reconcile().await.unwrap();
        assert_eq!(speaker.leased_flowspec_adds.load(SeqCst), 2);
        lease.request_readd();
        reconciler.reconcile().await.unwrap();
        assert_eq!(speaker.leased_flowspec_adds.load(SeqCst), 4);
        assert_eq!(speaker.flowspec_adds.load(SeqCst), 1);
        assert!(!lease.take_readd());

        // Leased FlowSpec without blackholes: the idle blackhole stage must not
        // keep the completed re-add pending.
        let reconciler =
            blackhole_reconciler(repo.clone(), speaker.clone(), Default::default(), false)
                .with_lease(lease.clone());
        lease.request_readd();
        reconciler.reconcile().await.unwrap();
        assert_eq!(speaker.leased_flowspec_adds.load(SeqCst), 6);
        assert!(!lease.take_readd(), "a completed re-add is not retried");
    }

    /// Another owner's rule at a desired key, and a desired leased rule held
    /// unowned, are reported and never touched or overwritten.
    #[tokio::test]
    async fn foreign_and_unowned_flowspec_rules_at_desired_keys_stay_untouched() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(FaultyBlackholes::default());
        let lease = Arc::new(crate::domain::LeaseKeeper::new(LEASE_OWNER.into(), 60));
        let reconciler = leased_reconciler(repo.clone(), speaker.clone(), lease.clone());
        lease.take_readd();
        let foreign_key = leased_rule_row("192.0.2.10/32");
        let unowned_key = leased_rule_row("192.0.2.12/32");
        for mitigation in [&foreign_key, &unowned_key] {
            repo.insert_mitigation(mitigation).await.unwrap();
        }
        let foreign = crate::domain::mitigation_rule(&foreign_key)
            .unwrap()
            .with_owner("other.owner");
        speaker.inner.announce_leased(&foreign, 60).await.unwrap();
        let unowned = crate::domain::mitigation_rule(&unowned_key)
            .unwrap()
            .with_owner("");
        speaker.inner.announce(&unowned).await.unwrap();
        assert!(reconciler.reconcile().await.is_err());
        assert_eq!(speaker.leased_flowspec_adds.load(SeqCst), 0);
        assert_eq!(speaker.flowspec_adds.load(SeqCst), 0);
        let rules = speaker.inner.list_active().await.unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().any(|rule| rule.owner == "other.owner"));
        assert_eq!(
            crate::observability::metrics::UNKNOWN_LOCAL_ROUTES
                .with_label_values(&["flowspec"])
                .get(),
            2.0
        );
    }

    /// A leased add whose reply was lost but which the daemon committed leaves
    /// a desired route under our owner while no generation is held, so nothing
    /// renews it. Reconciliation re-adds it to learn the generation instead of
    /// letting the speaker expire it one lease later.
    #[tokio::test]
    async fn a_present_leased_route_without_a_held_generation_is_re_added() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(FaultyBlackholes::default());
        let lease = Arc::new(crate::domain::LeaseKeeper::new(LEASE_OWNER.into(), 60));
        let reconciler = leased_reconciler(repo.clone(), speaker.clone(), lease.clone());
        // The startup re-add with nothing leased yet.
        reconciler.reconcile().await.unwrap();
        assert!(!lease.take_readd());
        let desired = leased_row("192.0.2.1");
        repo.insert_mitigation(&desired).await.unwrap();
        speaker
            .inner
            .announce_leased_blackhole(&frozen(&desired), 60)
            .await
            .unwrap();
        assert_eq!(lease.generation(), None);
        reconciler.reconcile().await.unwrap();
        assert!(
            lease.generation().is_some(),
            "a desired leased route that nothing renews"
        );
        assert_eq!(speaker.leased_adds.load(SeqCst), 1);
        reconciler.reconcile().await.unwrap();
        assert_eq!(speaker.leased_adds.load(SeqCst), 1, "converged");
        assert_eq!(speaker.adds.load(SeqCst), 0);
    }
    /// The FlowSpec side of a lost add reply: a desired rule under our owner
    /// while no generation is held is renewed by nothing, with no leased
    /// blackhole to notice it. Reconciliation re-adds it to learn the generation.
    #[tokio::test]
    async fn a_present_leased_flowspec_rule_without_a_held_generation_is_re_added() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(FaultyBlackholes::default());
        let lease = Arc::new(crate::domain::LeaseKeeper::new(LEASE_OWNER.into(), 60));
        // Leased FlowSpec without blackholes.
        let reconciler =
            blackhole_reconciler(repo.clone(), speaker.clone(), Default::default(), false)
                .with_lease(lease.clone());
        reconciler.reconcile().await.unwrap();
        assert!(!lease.take_readd());
        let desired = leased_rule_row("192.0.2.10/32");
        repo.insert_mitigation(&desired).await.unwrap();
        speaker
            .inner
            .announce_leased(&crate::domain::mitigation_rule(&desired).unwrap(), 60)
            .await
            .unwrap();
        assert_eq!(lease.generation(), None);
        reconciler.reconcile().await.unwrap();
        assert!(
            lease.generation().is_some(),
            "a desired leased rule that nothing renews"
        );
        assert_eq!(speaker.leased_flowspec_adds.load(SeqCst), 1);
        reconciler.reconcile().await.unwrap();
        assert_eq!(speaker.leased_flowspec_adds.load(SeqCst), 1, "converged");
        assert_eq!(speaker.flowspec_adds.load(SeqCst), 0);
    }

    /// A leased row whose key another owner, or no owner, holds keeps failing
    /// with an ownership refusal. It stays reported each pass but does not
    /// re-trigger the full re-add every interval.
    #[tokio::test]
    async fn an_ownership_refusal_does_not_keep_the_full_readd_pending() {
        let _metrics_guard = RECONCILIATION_TEST_LOCK.lock().await;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(FaultyBlackholes::default());
        let lease = Arc::new(crate::domain::LeaseKeeper::new(LEASE_OWNER.into(), 60));
        let reconciler = leased_reconciler(repo.clone(), speaker.clone(), lease.clone());
        let held = leased_row("192.0.2.1");
        let fine = leased_row("192.0.2.2");
        for mitigation in [&held, &fine] {
            repo.insert_mitigation(mitigation).await.unwrap();
        }
        let unowned = frozen(&held).with_owner("");
        speaker.inner.announce_blackhole(&unowned).await.unwrap();
        // The startup re-add: one refused, one added.
        assert!(reconciler.reconcile().await.is_err());
        assert_eq!(speaker.leased_adds.load(SeqCst), 2);
        assert!(
            !lease.take_readd(),
            "a refusal must not keep the re-add pending"
        );
        // Still reported on later passes, and the unowned route is untouched.
        assert!(reconciler.reconcile().await.is_err());
        assert_eq!(speaker.routes().await.len(), 2);
        assert!(speaker.routes().await.contains(&unowned));
        assert_eq!(speaker.deletes.load(SeqCst), 0);
    }
}
