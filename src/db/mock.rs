use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

use super::{
    GlobalStats, ListParams, MitigationListParams, NotificationPreferences, PopInfo, PopStats,
    RepositoryTrait, SafelistEntry, TimeseriesBucket,
};
use crate::correlation::engine::{
    CorroboratingSignal, EventDimensions, SignalGroup, SignalGroupEvent, SignalGroupFilter,
    SignalGroupStatus,
};
use crate::domain::{
    AttackEvent, Mitigation, MitigationStatus, Operator, OperatorRole, WithdrawalRequest,
};
use crate::error::Result;
use crate::observability::AuditEntry;

#[derive(Default)]
struct MockSpeakerBindings {
    targets: Vec<(Uuid, crate::domain::SpeakerTarget)>,
    pops: HashMap<String, Uuid>,
}

pub struct MockRepository {
    speaker_bindings: Mutex<MockSpeakerBindings>,
    events: Mutex<Vec<AttackEvent>>,
    #[cfg(test)]
    mitigation_reads: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    pending_reads: std::sync::atomic::AtomicUsize,
    /// Every safelist lookup fails, as an unavailable database does.
    #[cfg(test)]
    pub fail_safelist: std::sync::atomic::AtomicBool,
    /// Every FlowSpec quota/rate snapshot read fails.
    #[cfg(test)]
    pub fail_quota_reads: std::sync::atomic::AtomicBool,
    /// The creation-rate snapshot fails independently of active quota reads.
    #[cfg(test)]
    pub fail_creation_rate_reads: std::sync::atomic::AtomicBool,
    /// Every active-mitigation inventory read fails.
    #[cfg(test)]
    pub fail_active_reads: std::sync::atomic::AtomicBool,
    /// Simulate transactional audit failure before committing an expiry change.
    #[cfg(test)]
    pub fail_extension_audit: std::sync::atomic::AtomicBool,
    mitigations: Mutex<Vec<Mitigation>>,
    withdrawals: Mutex<Vec<WithdrawalRequest>>,
    safelist: Mutex<Vec<SafelistEntry>>,
    audit: Mutex<Vec<AuditEntry>>,
    operators: Mutex<Vec<Operator>>,
    notification_prefs: Mutex<HashMap<Uuid, NotificationPreferences>>,
    signal_groups: Mutex<Vec<SignalGroup>>,
    signal_group_events: Mutex<Vec<MockGroupEventLink>>,
    corroborating_signals: Mutex<Vec<CorroboratingSignal>>,
}

/// Mock-only junction-table row:
/// (group_id, event_id, source_weight, is_corroborating,
///  denorm_source, denorm_confidence, denorm_ingested_at).
type MockGroupEventLink = (
    Uuid,
    Uuid,
    f32,
    bool,
    Option<String>,
    Option<f32>,
    Option<chrono::DateTime<chrono::Utc>>,
);

impl MockRepository {
    #[cfg(test)]
    pub fn lifecycle_read_counts(&self) -> (usize, usize) {
        use std::sync::atomic::Ordering::Relaxed;
        (
            self.mitigation_reads.load(Relaxed),
            self.pending_reads.load(Relaxed),
        )
    }

    pub fn new() -> Self {
        Self {
            speaker_bindings: Mutex::new(MockSpeakerBindings::default()),
            events: Mutex::new(Vec::new()),
            #[cfg(test)]
            mitigation_reads: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            pending_reads: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            fail_safelist: Default::default(),
            #[cfg(test)]
            fail_quota_reads: Default::default(),
            #[cfg(test)]
            fail_creation_rate_reads: Default::default(),
            #[cfg(test)]
            fail_active_reads: Default::default(),
            #[cfg(test)]
            fail_extension_audit: Default::default(),
            mitigations: Mutex::new(Vec::new()),
            withdrawals: Mutex::new(Vec::new()),
            safelist: Mutex::new(Vec::new()),
            audit: Mutex::new(Vec::new()),
            operators: Mutex::new(Vec::new()),
            notification_prefs: Mutex::new(HashMap::new()),
            signal_groups: Mutex::new(Vec::new()),
            signal_group_events: Mutex::new(Vec::new()),
            corroborating_signals: Mutex::new(Vec::new()),
        }
    }
}

impl Default for MockRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RepositoryTrait for MockRepository {
    fn for_bounded_reads(
        self: std::sync::Arc<Self>,
        _deadline: tokio::time::Instant,
    ) -> Result<std::sync::Arc<dyn RepositoryTrait>> {
        // These synchronous in-memory reads leave no server work or pooled
        // connection behind when the enclosing preparation future is cancelled.
        Ok(self)
    }

    async fn register_speaker_target(
        &self,
        pop: &str,
        target: &crate::domain::SpeakerTarget,
        adopt_legacy: bool,
    ) -> Result<crate::domain::VerifiedSpeakerBinding> {
        use crate::domain::{VerifiedSpeakerBinding, binding_mismatch};
        if pop.is_empty() {
            return Err(crate::error::PrefixdError::Config(
                "speaker POP must not be empty".into(),
            ));
        }
        let mut bindings = self.speaker_bindings.lock().unwrap();
        let mitigations = self.mitigations.lock().unwrap();
        let mut withdrawals = self.withdrawals.lock().unwrap();
        let known = bindings
            .targets
            .iter()
            .find(|(_, known)| known == target)
            .map(|(id, _)| *id);
        let target_id = known.unwrap_or_else(Uuid::new_v4);
        let assigned = bindings.pops.get(pop).copied();
        if assigned.is_some_and(|id| id != target_id)
            || bindings
                .pops
                .iter()
                .any(|(owner, id)| *id == target_id && owner != pop)
            || withdrawals.iter().any(|request| {
                request.pop == pop
                    && request.completed_at.is_none()
                    && request.target_id.is_some_and(|id| id != target_id)
            })
        {
            return Err(binding_mismatch());
        }
        let legacy =
            mitigations.iter().any(|m| m.pop == pop) || withdrawals.iter().any(|r| r.pop == pop);
        let unbound = withdrawals
            .iter()
            .any(|r| r.pop == pop && r.target_id.is_none());
        if !adopt_legacy && ((assigned.is_none() && legacy) || unbound) {
            return Err(crate::error::PrefixdError::Conflict(
                "legacy speaker state requires explicit original-target adoption with --adopt-legacy-speaker".into()));
        }
        if known.is_none() {
            bindings.targets.push((target_id, target.clone()));
        }
        bindings.pops.insert(pop.into(), target_id);
        let mut attached = 0;
        if adopt_legacy {
            for request in withdrawals
                .iter_mut()
                .filter(|r| r.pop == pop && r.target_id.is_none())
            {
                request.target_id = Some(target_id);
                attached += 1;
            }
            if (assigned.is_none() && legacy) || attached > 0 {
                self.audit.lock().unwrap().push(AuditEntry::new(
                    crate::observability::ActorType::System,
                    Some("adopt-legacy-speaker".into()),
                    "adopt_speaker_target",
                    Some("speaker_target"),
                    Some(target_id.to_string()),
                    serde_json::json!({"pop": pop, "attached_withdrawals": attached}),
                ));
            }
        }
        Ok(VerifiedSpeakerBinding::new(
            pop.into(),
            target_id,
            target.clone(),
        ))
    }

    async fn registered_speaker_target_id(
        &self,
        target: &crate::domain::SpeakerTarget,
    ) -> Result<Option<Uuid>> {
        let bindings = self.speaker_bindings.lock().unwrap();
        Ok(bindings
            .targets
            .iter()
            .find(|(_, known)| known == target)
            .map(|(id, _)| *id))
    }

    async fn tag_unknown_origin(
        &self,
        pop: &str,
        mode: crate::config::OperationMode,
    ) -> Result<u64> {
        let mut tagged = 0;
        for m in self
            .mitigations
            .lock()
            .unwrap()
            .iter_mut()
            .filter(|m| m.pop == pop && m.origin_mode.is_none() && m.is_active())
        {
            m.origin_mode = Some(mode);
            tagged += 1;
        }
        if tagged > 0 {
            self.audit
                .lock()
                .unwrap()
                .push(super::repository::unknown_origin_audit(pop, mode, tagged));
        }
        Ok(tagged)
    }

    async fn insert_event(&self, event: &AttackEvent) -> Result<()> {
        self.events.lock().unwrap().push(event.clone());
        Ok(())
    }

    async fn find_ban_event_by_external_id(
        &self,
        source: &str,
        external_id: &str,
    ) -> Result<Option<AttackEvent>> {
        let events = self.events.lock().unwrap();
        // Find the most recent ban event with matching source and external_id
        Ok(events
            .iter()
            .rev() // Most recent first
            .find(|e| {
                e.source == source
                    && e.external_event_id.as_deref() == Some(external_id)
                    && e.action == "ban"
            })
            .cloned())
    }

    async fn list_events_filtered(
        &self,
        filters: &super::EventListParams,
    ) -> Result<Vec<AttackEvent>> {
        let params = &filters.pagination;
        let query = filters.query.as_ref().map(|q| q.to_lowercase());
        let events = self.events.lock().unwrap();
        let mut matching: Vec<_> = events
            .iter()
            .filter(|e| {
                params
                    .cursor
                    .is_none_or(|c| (e.ingested_at, e.event_id) < (c.timestamp, c.id))
            })
            .filter(|e| params.start.is_none_or(|s| e.ingested_at >= s))
            .filter(|e| params.end.is_none_or(|end| e.ingested_at < end))
            .filter(|e| {
                filters
                    .source
                    .as_ref()
                    .is_none_or(|source| &e.source == source)
            })
            .filter(|e| {
                filters
                    .vector
                    .as_ref()
                    .is_none_or(|vector| &e.vector == vector)
            })
            .filter(|e| {
                query.as_ref().is_none_or(|q| {
                    [&e.victim_ip, &e.event_id.to_string()]
                        .iter()
                        .any(|value| value.to_lowercase().contains(q))
                })
            })
            .collect();
        matching.sort_unstable_by_key(|e| std::cmp::Reverse((e.ingested_at, e.event_id)));
        Ok(matching
            .into_iter()
            .take(params.limit as usize)
            .cloned()
            .collect())
    }

    async fn insert_audit(&self, entry: &AuditEntry) -> Result<()> {
        self.audit.lock().unwrap().push(entry.clone());
        Ok(())
    }

    async fn list_audit(&self, params: &ListParams) -> Result<Vec<AuditEntry>> {
        let audit = self.audit.lock().unwrap();
        let mut matching: Vec<_> = audit
            .iter()
            .filter(|e| {
                params
                    .cursor
                    .is_none_or(|c| (e.timestamp, e.audit_id) < (c.timestamp, c.id))
            })
            .filter(|e| params.start.is_none_or(|s| e.timestamp >= s))
            .filter(|e| params.end.is_none_or(|end| e.timestamp < end))
            .collect();
        matching.sort_unstable_by_key(|e| std::cmp::Reverse((e.timestamp, e.audit_id)));
        Ok(matching
            .into_iter()
            .take(params.limit as usize)
            .cloned()
            .collect())
    }

    async fn active_mitigations_for_pop(&self, pop: &str) -> Result<Vec<Mitigation>> {
        self.active_mitigation_inventory(Some(pop)).await
    }

    async fn active_mitigation_inventory(&self, pop: Option<&str>) -> Result<Vec<Mitigation>> {
        #[cfg(test)]
        if self
            .fail_active_reads
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(crate::error::PrefixdError::Internal(
                "mitigation inventory unavailable".into(),
            ));
        }
        Ok(self
            .mitigations
            .lock()
            .unwrap()
            .iter()
            .rev()
            .filter(|m| pop.is_none_or(|pop| m.pop == pop) && m.is_active())
            .cloned()
            .collect())
    }

    async fn begin_withdrawal(&self, request: &WithdrawalRequest) -> Result<WithdrawalRequest> {
        let bindings = self.speaker_bindings.lock().unwrap();
        if bindings.pops.get(&request.pop).copied() != request.target_id {
            return Err(crate::domain::binding_mismatch());
        }
        let mitigations = self.mitigations.lock().unwrap();
        let mut withdrawals = self.withdrawals.lock().unwrap();
        if let Some(existing) = withdrawals
            .iter()
            .find(|r| r.mitigation_id == request.mitigation_id)
        {
            return if existing.completed_at.is_none()
                && existing.pop == request.pop
                && existing.target_id == request.target_id
            {
                Ok(existing.clone())
            } else {
                Err(crate::error::PrefixdError::Conflict(
                    "withdrawal already completed".into(),
                ))
            };
        }
        if !mitigations.iter().any(|m| {
            m.mitigation_id == request.mitigation_id
                && m.is_active()
                && m.updated_at == request.mitigation_updated_at
                && m.pop == request.pop
        }) {
            return Err(crate::error::PrefixdError::Conflict(
                "mitigation changed before withdrawal was persisted".into(),
            ));
        }
        withdrawals.push(request.clone());
        Ok(request.clone())
    }

    async fn pending_withdrawals(&self, pop: Option<&str>) -> Result<Vec<WithdrawalRequest>> {
        #[cfg(test)]
        self.pending_reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(self
            .withdrawals
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.completed_at.is_none() && pop.is_none_or(|p| p == r.pop))
            .cloned()
            .collect())
    }

    async fn finish_withdrawal(&self, request: &WithdrawalRequest) -> Result<Option<Mitigation>> {
        let mut mitigations = self.mitigations.lock().unwrap();
        let mut withdrawals = self.withdrawals.lock().unwrap();
        let Some(pending) = withdrawals.iter_mut().find(|r| {
            r.operation_id == request.operation_id
                && r.mitigation_id == request.mitigation_id
                && r.pop == request.pop
                && r.target_id == request.target_id
                && r.completed_at.is_none()
        }) else {
            return Ok(None);
        };
        let Some(mitigation) = mitigations.iter_mut().find(|m| {
            m.mitigation_id == pending.mitigation_id
                && m.updated_at == pending.mitigation_updated_at
                && m.pop == pending.pop
                && m.is_active()
        }) else {
            return Ok(None);
        };
        if pending.is_expiry() {
            mitigation.expire();
        } else {
            mitigation.withdraw(Some(pending.reason.clone()));
        }
        self.audit.lock().unwrap().push(pending.audit_entry());
        pending.completed_at = Some(Utc::now());
        Ok(Some(mitigation.clone()))
    }

    async fn insert_mitigation(&self, m: &Mitigation) -> Result<()> {
        self.mitigations.lock().unwrap().push(m.clone());
        Ok(())
    }

    async fn check_new_mitigation_rate(&self, pop: &str, max: u32) -> Result<()> {
        #[cfg(test)]
        if self
            .fail_quota_reads
            .load(std::sync::atomic::Ordering::SeqCst)
            || self
                .fail_creation_rate_reads
                .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(crate::error::PrefixdError::Internal(
                "sensitive storage diagnostic".into(),
            ));
        }

        let since = Utc::now() - super::repository::NEW_MITIGATION_WINDOW;
        let count = self
            .mitigations
            .lock()
            .unwrap()
            .iter()
            .filter(|existing| existing.pop == pop && existing.created_at > since)
            .count();
        super::repository::check_new_mitigation_rate(u32::try_from(count).unwrap_or(u32::MAX), max)
    }

    async fn admit_mitigation(
        &self,
        m: &Mitigation,
        quotas: &crate::config::QuotasConfig,
        blackhole: &crate::config::BlackholeConfig,
        actor: &crate::observability::CreationActor,
    ) -> Result<()> {
        let mut mitigations = self.mitigations.lock().unwrap();
        if m.action_type != crate::domain::ActionType::Blackhole {
            if let Some(customer_id) = &m.customer_id {
                let count = mitigations
                    .iter()
                    .filter(|existing| {
                        existing.is_active()
                            && existing.action_type != crate::domain::ActionType::Blackhole
                            && existing.customer_id.as_ref() == Some(customer_id)
                    })
                    .count();
                super::repository::check_active_quota(
                    "customer",
                    u32::try_from(count).unwrap_or(u32::MAX),
                    quotas.max_active_per_customer,
                )?;
            }
            let count = mitigations
                .iter()
                .filter(|existing| {
                    existing.is_active()
                        && existing.action_type != crate::domain::ActionType::Blackhole
                        && existing.pop == m.pop
                })
                .count();
            super::repository::check_active_quota(
                "pop",
                u32::try_from(count).unwrap_or(u32::MAX),
                quotas.max_active_per_pop,
            )?;
            let count = mitigations
                .iter()
                .filter(|existing| {
                    existing.is_active()
                        && existing.action_type != crate::domain::ActionType::Blackhole
                })
                .count();
            super::repository::check_active_quota(
                "global",
                u32::try_from(count).unwrap_or(u32::MAX),
                quotas.max_active_global,
            )?;
        }
        if m.action_type == crate::domain::ActionType::Blackhole {
            let blackholes = || {
                mitigations.iter().filter(|existing| {
                    existing.is_active()
                        && existing.action_type == crate::domain::ActionType::Blackhole
                })
            };
            for (quota_type, count, max) in [
                (
                    "blackhole_pop",
                    blackholes()
                        .filter(|existing| existing.pop == m.pop)
                        .count(),
                    blackhole.max_active_per_pop,
                ),
                (
                    "blackhole_global",
                    blackholes().count(),
                    blackhole.max_active_global,
                ),
            ] {
                super::repository::check_active_quota(
                    quota_type,
                    u32::try_from(count).unwrap_or(u32::MAX),
                    max,
                )?;
            }
        }
        let since = Utc::now() - super::repository::NEW_MITIGATION_WINDOW;
        let count = mitigations
            .iter()
            .filter(|existing| existing.pop == m.pop && existing.created_at > since)
            .count();
        super::repository::check_new_mitigation_rate(
            u32::try_from(count).unwrap_or(u32::MAX),
            quotas.max_new_per_minute,
        )?;
        mitigations.push(m.clone());
        self.audit
            .lock()
            .unwrap()
            .push(AuditEntry::mitigation_created(m, actor));
        Ok(())
    }

    async fn extend_flowspec_lifetime(
        &self,
        request: &crate::domain::LifetimeExtension,
        fence: &crate::fence::ControllerFence,
    ) -> Result<crate::domain::LifetimeExtensionOutcome> {
        use crate::domain::LifetimeExtensionOutcome;
        use crate::error::PrefixdError;

        let bindings = self.speaker_bindings.lock().unwrap();
        let mut mitigations = self.mitigations.lock().unwrap();
        let withdrawals = self.withdrawals.lock().unwrap();
        let safelist = self.safelist.lock().unwrap();
        let mut audit = self.audit.lock().unwrap();
        if bindings.pops.get(&request.expected.pop).copied() != request.target_id {
            return Err(crate::domain::binding_mismatch());
        }
        let current = mitigations
            .iter_mut()
            .find(|m| m.mitigation_id == request.expected.mitigation_id)
            .ok_or(PrefixdError::MitigationNotFound(
                request.expected.mitigation_id,
            ))?;
        let now = Utc::now();
        request.validate_current(current, now)?;
        if withdrawals.iter().any(|withdrawal| {
            withdrawal.mitigation_id == current.mitigation_id && withdrawal.completed_at.is_none()
        }) {
            return Err(PrefixdError::Conflict(
                "mitigation has a pending withdrawal".into(),
            ));
        }
        let destination =
            crate::domain::parse_flowspec_destination(&current.match_criteria.dst_prefix)
                .map_err(|error| PrefixdError::InvalidRequest(error.to_string()))?;
        for protected in safelist.iter() {
            let prefix = protected
                .prefix
                .parse::<ipnet::IpNet>()
                .or_else(|_| {
                    protected
                        .prefix
                        .parse::<std::net::IpAddr>()
                        .map(ipnet::IpNet::from)
                })
                .map_err(|_| PrefixdError::Internal("invalid stored safelist prefix".into()))?;
            if prefix.contains(&destination) || destination.contains(&prefix) {
                return Err(crate::domain::extension_safelisted(
                    &destination.to_string(),
                ));
            }
        }
        let previous_expires_at = current.expires_at;
        let proposed = now
            .checked_add_signed(chrono::Duration::seconds(request.ttl_seconds.into()))
            .ok_or_else(|| {
                PrefixdError::InvalidRequest("lifetime horizon is out of range".into())
            })?;
        let extended = proposed > current.expires_at;
        if extended {
            crate::guardrails::validate_total_lifetime(
                proposed - current.created_at,
                request.max_lifetime_seconds,
            )?;
        }
        request.ensure_fence(fence)?;
        #[cfg(test)]
        if extended
            && self
                .fail_extension_audit
                .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Err(PrefixdError::Internal("extension audit unavailable".into()));
        }
        if extended {
            let mut updated = current.clone();
            updated.expires_at = proposed;
            updated.updated_at = now;
            audit.push(request.audit(&updated));
            *current = updated;
        }
        Ok(LifetimeExtensionOutcome {
            mitigation: current.clone(),
            previous_expires_at,
            extended,
        })
    }

    async fn update_mitigation(&self, m: &Mitigation) -> Result<()> {
        let mut mitigations = self.mitigations.lock().unwrap();
        if let Some(existing) = mitigations
            .iter_mut()
            .find(|x| x.mitigation_id == m.mitigation_id)
        {
            // Like PostgreSQL, updates never rewrite the admitting mode.
            let origin_mode = existing.origin_mode;
            *existing = m.clone();
            existing.origin_mode = origin_mode;
        }
        Ok(())
    }

    async fn get_mitigation(&self, id: Uuid) -> Result<Option<Mitigation>> {
        #[cfg(test)]
        self.mitigation_reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mitigations = self.mitigations.lock().unwrap();
        Ok(mitigations.iter().find(|m| m.mitigation_id == id).cloned())
    }

    async fn find_active_by_scope(
        &self,
        scope_hash: &str,
        pop: &str,
    ) -> Result<Option<Mitigation>> {
        let mitigations = self.mitigations.lock().unwrap();
        Ok(mitigations
            .iter()
            .find(|m| {
                m.scope_hash == scope_hash
                    && m.pop == pop
                    && matches!(
                        m.status,
                        MitigationStatus::Pending
                            | MitigationStatus::Active
                            | MitigationStatus::Escalated
                    )
            })
            .cloned())
    }

    async fn list_active_by_triggering_event(&self, event_id: Uuid) -> Result<Vec<Mitigation>> {
        let mitigations = self.mitigations.lock().unwrap();
        Ok(mitigations
            .iter()
            .filter(|m| {
                m.triggering_event_id == event_id
                    && matches!(
                        m.status,
                        MitigationStatus::Pending
                            | MitigationStatus::Active
                            | MitigationStatus::Escalated
                    )
            })
            .cloned()
            .collect())
    }

    async fn list_mitigations(
        &self,
        status_filter: Option<&[MitigationStatus]>,
        customer_id: Option<&str>,
        victim_ip: Option<&str>,
        acknowledged: Option<bool>,
        params: &MitigationListParams,
    ) -> Result<Vec<Mitigation>> {
        let mitigations = self.mitigations.lock().unwrap();
        let mut matching: Vec<_> = mitigations
            .iter()
            .filter(|m| {
                let status_ok = status_filter
                    .map(|statuses| statuses.contains(&m.status))
                    .unwrap_or(true);
                let customer_ok = customer_id
                    .map(|cid| m.customer_id.as_deref() == Some(cid))
                    .unwrap_or(true);
                let ip_ok = victim_ip.map(|ip| m.victim_ip == ip).unwrap_or(true);
                let ack_ok = acknowledged.is_none_or(|ack| {
                    if ack {
                        m.acknowledged_at.is_some()
                    } else {
                        m.acknowledged_at.is_none()
                    }
                });
                let pop_ok = params.pop.as_deref().is_none_or(|pop| m.pop == pop);
                let query_ok = params.query.as_deref().is_none_or(|query| {
                    let query = query.to_lowercase();
                    m.victim_ip.to_lowercase().contains(&query)
                        || m.vector.as_str().to_lowercase().contains(&query)
                        || m.customer_id
                            .as_deref()
                            .is_some_and(|customer| customer.to_lowercase().contains(&query))
                        || m.mitigation_id.to_string().contains(&query)
                });
                let cursor_ok = params.cursor.is_none_or(|cursor| {
                    (m.created_at, m.mitigation_id) < (cursor.created_at, cursor.mitigation_id)
                });
                let start_ok = params.start.is_none_or(|s| m.created_at >= s);
                let end_ok = params.end.is_none_or(|e| m.created_at < e);
                status_ok
                    && customer_ok
                    && ip_ok
                    && ack_ok
                    && pop_ok
                    && query_ok
                    && cursor_ok
                    && start_ok
                    && end_ok
            })
            .collect();
        matching.sort_unstable_by_key(|m| std::cmp::Reverse((m.created_at, m.mitigation_id)));
        Ok(matching
            .into_iter()
            .take(params.limit as usize)
            .cloned()
            .collect())
    }

    async fn acknowledge_mitigations(&self, ids: &[Uuid], operator_id: &str) -> Result<Vec<Uuid>> {
        let mut mitigations = self.mitigations.lock().unwrap();
        let now = Utc::now();
        let mut acknowledged = Vec::new();
        for m in mitigations.iter_mut() {
            if ids.contains(&m.mitigation_id)
                && m.acknowledged_at.is_none()
                && !matches!(m.status, MitigationStatus::Rejected)
            {
                m.acknowledged_at = Some(now);
                m.acknowledged_by = Some(operator_id.to_string());
                acknowledged.push(m.mitigation_id);
            }
        }
        Ok(acknowledged)
    }

    async fn count_active_by_customer(&self, customer_id: &str) -> Result<u32> {
        let mitigations = self.mitigations.lock().unwrap();
        Ok(mitigations
            .iter()
            .filter(|m| {
                m.customer_id.as_deref() == Some(customer_id)
                    && matches!(
                        m.status,
                        MitigationStatus::Pending
                            | MitigationStatus::Active
                            | MitigationStatus::Escalated
                    )
            })
            .count() as u32)
    }

    async fn count_active_by_pop(&self, pop: &str) -> Result<u32> {
        let mitigations = self.mitigations.lock().unwrap();
        Ok(mitigations
            .iter()
            .filter(|m| {
                m.pop == pop
                    && matches!(
                        m.status,
                        MitigationStatus::Pending
                            | MitigationStatus::Active
                            | MitigationStatus::Escalated
                    )
            })
            .count() as u32)
    }

    async fn count_active_global(&self) -> Result<u32> {
        let mitigations = self.mitigations.lock().unwrap();
        Ok(mitigations
            .iter()
            .filter(|m| {
                matches!(
                    m.status,
                    MitigationStatus::Pending
                        | MitigationStatus::Active
                        | MitigationStatus::Escalated
                )
            })
            .count() as u32)
    }

    async fn count_active_flowspec_by_customer(&self, customer_id: &str) -> Result<u32> {
        #[cfg(test)]
        if self
            .fail_quota_reads
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(crate::error::PrefixdError::Internal(
                "sensitive storage diagnostic".into(),
            ));
        }

        let mitigations = self.mitigations.lock().unwrap();
        Ok(mitigations
            .iter()
            .filter(|m| {
                m.action_type != crate::domain::ActionType::Blackhole
                    && m.customer_id.as_deref() == Some(customer_id)
                    && matches!(
                        m.status,
                        MitigationStatus::Pending
                            | MitigationStatus::Active
                            | MitigationStatus::Escalated
                    )
            })
            .count() as u32)
    }

    async fn count_active_flowspec_by_pop(&self, pop: &str) -> Result<u32> {
        #[cfg(test)]
        if self
            .fail_quota_reads
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(crate::error::PrefixdError::Internal(
                "sensitive storage diagnostic".into(),
            ));
        }

        let mitigations = self.mitigations.lock().unwrap();
        Ok(mitigations
            .iter()
            .filter(|m| {
                m.action_type != crate::domain::ActionType::Blackhole
                    && m.pop == pop
                    && matches!(
                        m.status,
                        MitigationStatus::Pending
                            | MitigationStatus::Active
                            | MitigationStatus::Escalated
                    )
            })
            .count() as u32)
    }

    async fn count_active_flowspec_global(&self) -> Result<u32> {
        #[cfg(test)]
        if self
            .fail_quota_reads
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(crate::error::PrefixdError::Internal(
                "sensitive storage diagnostic".into(),
            ));
        }

        let mitigations = self.mitigations.lock().unwrap();
        Ok(mitigations
            .iter()
            .filter(|m| {
                m.action_type != crate::domain::ActionType::Blackhole
                    && matches!(
                        m.status,
                        MitigationStatus::Pending
                            | MitigationStatus::Active
                            | MitigationStatus::Escalated
                    )
            })
            .count() as u32)
    }

    async fn find_expired_mitigations(&self) -> Result<Vec<Mitigation>> {
        self.expired_mitigation_inventory(None).await
    }

    async fn expired_mitigation_inventory(&self, pop: Option<&str>) -> Result<Vec<Mitigation>> {
        let now = Utc::now();
        let mitigations = self.mitigations.lock().unwrap();
        Ok(mitigations
            .iter()
            .filter(|m| {
                matches!(
                    m.status,
                    MitigationStatus::Active | MitigationStatus::Escalated
                ) && m.expires_at < now
                    && pop.is_none_or(|pop| m.pop == pop)
            })
            .cloned()
            .collect())
    }

    async fn insert_safelist(
        &self,
        prefix: &str,
        added_by: &str,
        reason: Option<&str>,
    ) -> Result<()> {
        let mut safelist = self.safelist.lock().unwrap();
        safelist.retain(|e| e.prefix != prefix);
        safelist.push(SafelistEntry {
            prefix: prefix.to_string(),
            added_at: Utc::now(),
            added_by: added_by.to_string(),
            reason: reason.map(String::from),
            expires_at: None,
        });
        Ok(())
    }

    async fn remove_safelist(&self, prefix: &str) -> Result<bool> {
        let mut safelist = self.safelist.lock().unwrap();
        let len_before = safelist.len();
        safelist.retain(|e| e.prefix != prefix);
        Ok(safelist.len() < len_before)
    }

    async fn list_safelist(&self) -> Result<Vec<SafelistEntry>> {
        Ok(self.safelist.lock().unwrap().clone())
    }

    async fn is_safelisted(&self, target: &str) -> Result<bool> {
        use ipnet::IpNet;
        use std::net::IpAddr;
        use std::str::FromStr;

        #[cfg(test)]
        if self.fail_safelist.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(crate::error::PrefixdError::Internal(
                "safelist unavailable".into(),
            ));
        }

        let parse = |text: &str| -> Result<IpNet> {
            text.parse::<IpNet>()
                .or_else(|_| IpAddr::from_str(text).map(IpNet::from))
                .map(|prefix| prefix.trunc())
                .map_err(|_| {
                    crate::error::PrefixdError::InvalidRequest(
                        "invalid safelist address or prefix".into(),
                    )
                })
        };
        let candidate = parse(target)?;
        let entries = self.safelist.lock().unwrap();
        for entry in entries.iter() {
            let protected = parse(&entry.prefix)?;
            if candidate.contains(&protected) || protected.contains(&candidate) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn list_pops(&self) -> Result<Vec<PopInfo>> {
        let mitigations = self.mitigations.lock().unwrap();
        let mut pop_map = std::collections::HashMap::new();

        for m in mitigations.iter() {
            let entry = pop_map.entry(m.pop.clone()).or_insert((0u32, 0u32));
            entry.1 += 1;
            if matches!(m.status, MitigationStatus::Active) {
                entry.0 += 1;
            }
        }

        Ok(pop_map
            .into_iter()
            .map(|(pop, (active, total))| PopInfo {
                pop,
                active_mitigations: active,
                total_mitigations: total,
            })
            .collect())
    }

    async fn get_stats(&self) -> Result<GlobalStats> {
        let mitigations = self.mitigations.lock().unwrap();
        let events = self.events.lock().unwrap();

        let total_active = mitigations
            .iter()
            .filter(|m| matches!(m.status, MitigationStatus::Active))
            .count() as u32;

        let mut pop_map = std::collections::HashMap::new();
        for m in mitigations.iter() {
            let entry = pop_map.entry(m.pop.clone()).or_insert((0u32, 0u32));
            entry.1 += 1;
            if matches!(m.status, MitigationStatus::Active) {
                entry.0 += 1;
            }
        }

        let pops = pop_map
            .into_iter()
            .map(|(pop, (active, total))| PopStats { pop, active, total })
            .collect();

        Ok(GlobalStats {
            total_active,
            total_mitigations: mitigations.len() as u32,
            total_events: events.len() as u32,
            pops,
        })
    }

    // Timeseries (mock returns empty)
    async fn timeseries_mitigations(
        &self,
        _range_hours: u32,
        _bucket_minutes: u32,
    ) -> Result<Vec<TimeseriesBucket>> {
        Ok(vec![])
    }

    async fn timeseries_events(
        &self,
        _range_hours: u32,
        _bucket_minutes: u32,
    ) -> Result<Vec<TimeseriesBucket>> {
        Ok(vec![])
    }

    // IP history
    async fn list_events_by_ip(&self, ip: &str, limit: u32) -> Result<Vec<AttackEvent>> {
        let events = self.events.lock().unwrap();
        Ok(events
            .iter()
            .filter(|e| e.victim_ip == ip)
            .take(limit as usize)
            .cloned()
            .collect())
    }

    async fn list_mitigations_by_ip(&self, ip: &str, limit: u32) -> Result<Vec<Mitigation>> {
        let mitigations = self.mitigations.lock().unwrap();
        Ok(mitigations
            .iter()
            .filter(|m| m.victim_ip == ip)
            .take(limit as usize)
            .cloned()
            .collect())
    }

    // Operator methods
    async fn get_operator_by_username(&self, username: &str) -> Result<Option<Operator>> {
        let operators = self.operators.lock().unwrap();
        Ok(operators.iter().find(|o| o.username == username).cloned())
    }

    async fn get_operator_by_id(&self, id: Uuid) -> Result<Option<Operator>> {
        let operators = self.operators.lock().unwrap();
        Ok(operators.iter().find(|o| o.operator_id == id).cloned())
    }

    async fn create_operator(
        &self,
        username: &str,
        password_hash: &str,
        role: OperatorRole,
        created_by: Option<&str>,
    ) -> Result<Operator> {
        let op = Operator {
            operator_id: Uuid::new_v4(),
            username: username.to_string(),
            password_hash: password_hash.to_string(),
            role,
            created_at: Utc::now(),
            created_by: created_by.map(String::from),
            last_login_at: None,
        };
        self.operators.lock().unwrap().push(op.clone());
        Ok(op)
    }

    async fn update_operator_last_login(&self, id: Uuid) -> Result<()> {
        let mut operators = self.operators.lock().unwrap();
        if let Some(op) = operators.iter_mut().find(|o| o.operator_id == id) {
            op.last_login_at = Some(Utc::now());
        }
        Ok(())
    }

    async fn update_operator_password(&self, id: Uuid, password_hash: &str) -> Result<()> {
        let mut operators = self.operators.lock().unwrap();
        if let Some(op) = operators.iter_mut().find(|o| o.operator_id == id) {
            op.password_hash = password_hash.to_string();
        }
        Ok(())
    }

    async fn delete_operator(&self, id: Uuid) -> Result<bool> {
        let mut operators = self.operators.lock().unwrap();
        let len_before = operators.len();
        operators.retain(|o| o.operator_id != id);
        Ok(operators.len() < len_before)
    }

    async fn list_operators(&self) -> Result<Vec<Operator>> {
        Ok(self.operators.lock().unwrap().clone())
    }

    async fn get_notification_preferences(
        &self,
        operator_id: Uuid,
    ) -> Result<Option<NotificationPreferences>> {
        Ok(self
            .notification_prefs
            .lock()
            .unwrap()
            .get(&operator_id)
            .cloned())
    }

    async fn upsert_notification_preferences(
        &self,
        operator_id: Uuid,
        prefs: &NotificationPreferences,
    ) -> Result<()> {
        self.notification_prefs
            .lock()
            .unwrap()
            .insert(operator_id, prefs.clone());
        Ok(())
    }

    // ── Signal groups ──────────────────────────────────────────────────

    async fn insert_signal_group(&self, group: &SignalGroup) -> Result<SignalGroup> {
        let mut groups = self.signal_groups.lock().unwrap();
        // Check for existing open group (simulates ON CONFLICT behavior)
        if let Some(existing) = groups.iter().find(|g| {
            g.victim_ip == group.victim_ip
                && g.vector == group.vector
                && g.status == SignalGroupStatus::Open
                && g.window_expires_at > Utc::now()
        }) {
            return Ok(existing.clone());
        }
        groups.push(group.clone());
        Ok(group.clone())
    }

    async fn update_signal_group(&self, group: &SignalGroup) -> Result<()> {
        let mut groups = self.signal_groups.lock().unwrap();
        if let Some(existing) = groups.iter_mut().find(|g| g.group_id == group.group_id) {
            *existing = group.clone();
        }
        Ok(())
    }

    async fn get_signal_group(&self, group_id: Uuid) -> Result<Option<SignalGroup>> {
        let groups = self.signal_groups.lock().unwrap();
        Ok(groups.iter().find(|g| g.group_id == group_id).cloned())
    }

    async fn find_open_group(&self, victim_ip: &str, vector: &str) -> Result<Option<SignalGroup>> {
        let groups = self.signal_groups.lock().unwrap();
        Ok(groups
            .iter()
            .find(|g| {
                g.victim_ip == victim_ip
                    && g.vector == vector
                    && g.status == SignalGroupStatus::Open
                    && g.window_expires_at > Utc::now()
            })
            .cloned())
    }

    async fn add_event_to_group(
        &self,
        group_id: Uuid,
        event_id: Uuid,
        source_weight: f32,
    ) -> Result<bool> {
        let mut links = self.signal_group_events.lock().unwrap();
        if links
            .iter()
            .any(|(gid, eid, _, _, _, _, _)| *gid == group_id && *eid == event_id)
        {
            return Ok(false);
        }
        links.push((group_id, event_id, source_weight, false, None, None, None));
        Ok(true)
    }

    async fn list_signal_group_events(&self, group_id: Uuid) -> Result<Vec<SignalGroupEvent>> {
        let links = self.signal_group_events.lock().unwrap();
        let events = self.events.lock().unwrap();

        Ok(links
            .iter()
            .filter(|(gid, _, _, _, _, _, _)| *gid == group_id)
            .map(
                |(gid, eid, weight, is_corroborating, dsource, dconf, dts)| {
                    let event = events.iter().find(|e| e.event_id == *eid);
                    SignalGroupEvent {
                        group_id: *gid,
                        event_id: *eid,
                        source_weight: *weight,
                        is_corroborating: *is_corroborating,
                        source: event.map(|e| e.source.clone()).or_else(|| dsource.clone()),
                        confidence: event.and_then(|e| e.confidence).or(*dconf),
                        ingested_at: event.map(|e| e.ingested_at).or(*dts),
                    }
                },
            )
            .collect())
    }

    async fn list_signal_groups(
        &self,
        filter: &SignalGroupFilter,
        params: &ListParams,
    ) -> Result<Vec<SignalGroup>> {
        let groups = self.signal_groups.lock().unwrap();
        let mut matching: Vec<_> = groups
            .iter()
            .filter(|g| filter.status.is_none_or(|s| g.status == s))
            .filter(|g| filter.vector.as_ref().is_none_or(|v| &g.vector == v))
            .filter(|g| filter.start.is_none_or(|s| g.created_at >= s))
            .filter(|g| filter.end.is_none_or(|e| g.created_at < e))
            .filter(|g| {
                params
                    .cursor
                    .is_none_or(|c| (g.created_at, g.group_id) < (c.timestamp, c.id))
            })
            .collect();
        matching.sort_unstable_by_key(|g| std::cmp::Reverse((g.created_at, g.group_id)));
        Ok(matching
            .into_iter()
            .take(params.limit as usize)
            .cloned()
            .collect())
    }

    async fn count_open_groups(&self) -> Result<u32> {
        let groups = self.signal_groups.lock().unwrap();
        Ok(groups
            .iter()
            .filter(|g| g.status == SignalGroupStatus::Open)
            .count() as u32)
    }

    async fn find_expired_signal_groups(&self) -> Result<Vec<SignalGroup>> {
        let now = Utc::now();
        let groups = self.signal_groups.lock().unwrap();
        Ok(groups
            .iter()
            .filter(|g| g.status == SignalGroupStatus::Open && g.window_expires_at <= now)
            .cloned()
            .collect())
    }

    async fn list_open_signal_groups(&self) -> Result<Vec<SignalGroup>> {
        let groups = self.signal_groups.lock().unwrap();
        Ok(groups
            .iter()
            .filter(|g| g.status == SignalGroupStatus::Open)
            .cloned()
            .collect())
    }

    async fn find_open_groups_by_dimensions(
        &self,
        vector: &Option<String>,
        dims: &EventDimensions,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<SignalGroup>> {
        let groups = self.signal_groups.lock().unwrap();
        Ok(groups
            .iter()
            .filter(|g| g.status == SignalGroupStatus::Open && g.window_expires_at > now)
            .filter(|g| vector.as_ref().is_none_or(|v| &g.vector == v))
            .filter(|g| g.primary_dimensions.matches_probe(dims))
            .cloned()
            .collect())
    }

    async fn find_mitigation_id_by_signal_group(
        &self,
        signal_group_id: Uuid,
    ) -> Result<Option<Uuid>> {
        let mitigations = self.mitigations.lock().unwrap();
        Ok(mitigations
            .iter()
            .find(|m| m.signal_group_id == Some(signal_group_id))
            .map(|m| m.mitigation_id))
    }

    // Corroborating signals (ADR 021)

    async fn add_corroborator_event_to_group(
        &self,
        group_id: Uuid,
        signal: &CorroboratingSignal,
    ) -> Result<bool> {
        let mut links = self.signal_group_events.lock().unwrap();
        if links
            .iter()
            .any(|(gid, eid, _, _, _, _, _)| *gid == group_id && *eid == signal.signal_id)
        {
            return Ok(false);
        }
        links.push((
            group_id,
            signal.signal_id,
            signal.weight,
            true,
            Some(signal.source.clone()),
            signal.confidence,
            Some(signal.ingested_at),
        ));
        Ok(true)
    }

    async fn group_has_primary_event(&self, group_id: Uuid) -> Result<bool> {
        let links = self.signal_group_events.lock().unwrap();
        Ok(links
            .iter()
            .any(|(gid, _, _, is_corr, _, _, _)| *gid == group_id && !*is_corr))
    }

    async fn insert_corroborating_signal(&self, signal: &CorroboratingSignal) -> Result<()> {
        self.corroborating_signals
            .lock()
            .unwrap()
            .push(signal.clone());
        Ok(())
    }

    async fn find_matching_corroborators(
        &self,
        vector: &str,
        dims: &EventDimensions,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<CorroboratingSignal>> {
        let cache = self.corroborating_signals.lock().unwrap();
        Ok(cache
            .iter()
            .filter(|s| s.expires_at > now)
            .filter(|s| s.vector.as_deref().is_none_or(|v| v == vector))
            .filter(|s| {
                s.customer_id
                    .as_ref()
                    .is_some_and(|c| dims.customer_ids.contains(c))
                    || s.pop.as_ref().is_some_and(|p| dims.pops.contains(p))
                    || s.service_id
                        .as_ref()
                        .is_some_and(|sid| dims.service_ids.contains(sid))
                    || s.interface
                        .as_ref()
                        .is_some_and(|i| dims.interfaces.contains(i))
            })
            .cloned()
            .collect())
    }

    async fn mark_corroborator_attached(&self, signal_id: Uuid, group_id: Uuid) -> Result<()> {
        let mut cache = self.corroborating_signals.lock().unwrap();
        if let Some(s) = cache.iter_mut().find(|s| s.signal_id == signal_id)
            && !s.attached_group_ids.contains(&group_id)
        {
            s.attached_group_ids.push(group_id);
        }
        Ok(())
    }

    async fn delete_expired_corroborating_signals(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<crate::db::traits::CorroboratorSweepStats> {
        let mut cache = self.corroborating_signals.lock().unwrap();
        let mut unattached: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();
        let mut attached = 0u64;
        cache.retain(|s| {
            if s.expires_at > now {
                return true;
            }
            if s.attached_group_ids.is_empty() {
                *unattached.entry(s.source.clone()).or_insert(0) += 1;
            } else {
                attached += 1;
            }
            false
        });
        Ok(crate::db::traits::CorroboratorSweepStats {
            unattached_expired: unattached,
            attached_expired: attached,
        })
    }

    async fn count_cached_corroborators(&self, now: chrono::DateTime<chrono::Utc>) -> Result<u64> {
        let cache = self.corroborating_signals.lock().unwrap();
        Ok(cache
            .iter()
            .filter(|s| s.expires_at > now && s.attached_group_ids.is_empty())
            .count() as u64)
    }

    async fn list_cached_corroborators(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        limit: i64,
        source: Option<&str>,
    ) -> Result<Vec<CorroboratingSignal>> {
        let cache = self.corroborating_signals.lock().unwrap();
        Ok(cache
            .iter()
            .filter(|s| s.expires_at > now && s.attached_group_ids.is_empty())
            .filter(|s| source.is_none_or(|src| s.source == src))
            .take(limit.max(0) as usize)
            .cloned()
            .collect())
    }

    async fn count_cached_corroborators_by_source(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<(String, u64)>> {
        use std::collections::HashMap;
        let cache = self.corroborating_signals.lock().unwrap();
        let mut counts: HashMap<String, u64> = HashMap::new();
        for s in cache.iter() {
            if s.expires_at > now && s.attached_group_ids.is_empty() {
                *counts.entry(s.source.clone()).or_insert(0) += 1;
            }
        }
        Ok(counts.into_iter().collect())
    }

    async fn corroborator_source_activity(
        &self,
        since: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<crate::db::traits::CorroboratorSourceActivity>> {
        use std::collections::HashMap;
        let cache = self.corroborating_signals.lock().unwrap();
        let mut agg: HashMap<String, (Option<chrono::DateTime<chrono::Utc>>, u64)> = HashMap::new();
        for s in cache.iter() {
            if s.ingested_at < since {
                continue;
            }
            let entry = agg.entry(s.source.clone()).or_insert((None, 0));
            entry.1 += 1;
            if entry.0.is_none_or(|t| t < s.ingested_at) {
                entry.0 = Some(s.ingested_at);
            }
        }
        Ok(agg
            .into_iter()
            .map(
                |(source, (last_seen, count))| crate::db::traits::CorroboratorSourceActivity {
                    source,
                    last_seen,
                    count,
                },
            )
            .collect())
    }
}
