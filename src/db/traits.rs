use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::correlation::engine::{SignalGroup, SignalGroupEvent, SignalGroupFilter};
use crate::domain::{
    AttackEvent, Mitigation, MitigationStatus, Operator, OperatorRole, WithdrawalRequest,
};
use crate::error::Result;
use crate::observability::AuditEntry;

use super::{GlobalStats, PopInfo, SafelistEntry, TimeseriesBucket};

/// Return value for `delete_expired_corroborating_signals`.
///
/// `unattached_expired` is per-source counts of signals the scheduler
/// should increment `CORROBORATOR_EXPIRED_TOTAL{source}` by: signals
/// that were cached because no primary group matched at ingest and
/// then timed out without ever attaching. `attached_expired` rows are
/// the audit copies retained for late fan-out; their deletion is
/// bookkeeping, not a cache miss, so we don't attribute them by
/// source.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CorroboratorSweepStats {
    pub unattached_expired: std::collections::HashMap<String, u64>,
    pub attached_expired: u64,
}

impl CorroboratorSweepStats {
    pub fn unattached_total(&self) -> u64 {
        self.unattached_expired.values().sum()
    }
}

/// Per-source activity summary for the Signals dashboard, covering both
/// primary-event sources (via the `events` table) and corroborator-only
/// sources (via `corroborating_signals` + `signal_group_events`).
#[derive(Debug, Clone, Default)]
pub struct CorroboratorSourceActivity {
    pub source: String,
    pub last_seen: Option<DateTime<Utc>>,
    pub count: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NotificationPreferences {
    #[serde(default)]
    pub muted_events: Vec<String>,
    #[serde(default)]
    pub quiet_hours_start: Option<i16>,
    #[serde(default)]
    pub quiet_hours_end: Option<i16>,
}

/// Stable continuation position for events, audit entries and signal groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListCursor {
    pub timestamp: DateTime<Utc>,
    pub id: Uuid,
}

/// Tuple pagination parameters for events, audit entries and signal groups.
#[derive(Debug, Clone, Default)]
pub struct ListParams {
    pub limit: u32,
    pub cursor: Option<ListCursor>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
}

/// Stable continuation position for public mitigation listings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MitigationCursor {
    pub created_at: DateTime<Utc>,
    pub mitigation_id: Uuid,
}

/// Mitigation pagination uses a unique tiebreaker; other list endpoints retain their parameters.
#[derive(Debug, Clone, Default)]
pub struct MitigationListParams {
    /// None lists every POP; Some matches the stored identifier exactly.
    pub pop: Option<String>,
    pub limit: u32,
    pub cursor: Option<MitigationCursor>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
}

#[async_trait]
pub trait RepositoryTrait: Send + Sync {
    /// Bound read-only preparation's mitigation lookup, ownership inventory,
    /// pending-withdrawal, safelist and FlowSpec quota/rate reads by an absolute
    /// deadline. The implementation must bound server work and discard cancelled or
    /// session-modified connections. Other reads and all mutations are outside
    /// this contract; persistence must use the original repository. Unsupported
    /// repositories fail closed; explicitly cancellation-safe mocks may reuse self.
    fn for_bounded_reads(
        self: Arc<Self>,
        _deadline: tokio::time::Instant,
    ) -> Result<Arc<dyn RepositoryTrait>> {
        Err(crate::error::PrefixdError::Config(
            "bounded preparation reads are unsupported by this repository".into(),
        ))
    }

    /// Serialize startup registration/adoption; never rebind an existing POP or target.
    /// Trusted implementations must persist/validate ownership and commit before
    /// issuing a binding. Legacy implementations remain source-compatible but
    /// explicitly fail closed until they implement this contract.
    async fn register_speaker_target(
        &self,
        _pop: &str,
        _target: &crate::domain::SpeakerTarget,
        _adopt_legacy: bool,
    ) -> Result<crate::domain::VerifiedSpeakerBinding> {
        Err(crate::error::PrefixdError::Config(
            "speaker target registration is unsupported by this repository".into(),
        ))
    }

    /// Read-only lookup of an already registered target's ID, so one-shot
    /// maintenance can take the controller fence before registration writes.
    async fn registered_speaker_target_id(
        &self,
        _target: &crate::domain::SpeakerTarget,
    ) -> Result<Option<uuid::Uuid>> {
        Err(crate::error::PrefixdError::Config(
            "speaker target lookup is unsupported by this repository".into(),
        ))
    }

    /// Record `mode` as the origin of this POP's live rows that predate origin
    /// tracking, with one system audit entry. Never changes `updated_at`, so
    /// pending withdrawals keep matching. Returns the number of rows tagged.
    async fn tag_unknown_origin(
        &self,
        _pop: &str,
        _mode: crate::config::OperationMode,
    ) -> Result<u64> {
        Err(crate::error::PrefixdError::Config(
            "mitigation origin tracking is unsupported by this repository".into(),
        ))
    }

    // Events
    async fn insert_event(&self, event: &AttackEvent) -> Result<()>;
    /// Find the most recent ban event by external_event_id.
    /// Used for duplicate detection (ban) and correlation (unban).
    /// external_event_id should be unique per ban occurrence. This method returns
    /// only ban events, ordered by most recent first.
    async fn find_ban_event_by_external_id(
        &self,
        source: &str,
        external_id: &str,
    ) -> Result<Option<AttackEvent>>;
    async fn list_events(&self, params: &ListParams) -> Result<Vec<AttackEvent>>;

    // Audit Log
    async fn insert_audit(&self, entry: &AuditEntry) -> Result<()>;
    async fn list_audit(&self, params: &ListParams) -> Result<Vec<AuditEntry>>;

    // Mitigations
    /// Raw persistence for fixtures/imports; bypasses quota admission and audit.
    /// Production creation must use `admit_mitigation`.
    async fn insert_mitigation(&self, m: &Mitigation) -> Result<()>;
    /// Atomically check FlowSpec customer/POP/global quotas or blackhole
    /// POP/global quotas, then the POP's shared
    /// `max_new_per_minute` rate, and persist new intent with its `create` audit entry.
    async fn admit_mitigation(
        &self,
        m: &Mitigation,
        quotas: &crate::config::QuotasConfig,
        blackhole: &crate::config::BlackholeConfig,
        actor: &crate::observability::CreationActor,
    ) -> Result<()>;
    async fn update_mitigation(&self, m: &Mitigation) -> Result<()>;
    /// Atomically extend an unchanged live FlowSpec row and its authenticated
    /// audit. Implementations must recheck time, binding and pending withdrawal
    /// after waiting for their mutation lock. An unchanged horizon writes nothing.
    async fn extend_flowspec_lifetime(
        &self,
        _request: &crate::domain::LifetimeExtension,
        _fence: &crate::fence::ControllerFence,
    ) -> Result<crate::domain::LifetimeExtensionOutcome> {
        Err(crate::error::PrefixdError::Internal(
            "atomic lifetime extension is unsupported by this repository".into(),
        ))
    }
    async fn get_mitigation(&self, id: Uuid) -> Result<Option<Mitigation>>;
    async fn find_active_by_scope(&self, scope_hash: &str, pop: &str)
    -> Result<Option<Mitigation>>;
    /// Live mitigations an event created, oldest first; one event can create several.
    async fn list_active_by_triggering_event(&self, event_id: Uuid) -> Result<Vec<Mitigation>>;
    async fn list_mitigations(
        &self,
        status_filter: Option<&[MitigationStatus]>,
        customer_id: Option<&str>,
        victim_ip: Option<&str>,
        acknowledged: Option<bool>,
        params: &MitigationListParams,
    ) -> Result<Vec<Mitigation>>;
    async fn acknowledge_mitigations(&self, ids: &[Uuid], operator_id: &str) -> Result<Vec<Uuid>>;
    async fn count_active_by_customer(&self, customer_id: &str) -> Result<u32>;
    async fn count_active_by_pop(&self, pop: &str) -> Result<u32>;
    async fn count_active_global(&self) -> Result<u32>;
    /// Active FlowSpec rows only, for preflight; admission rechecks under its lock.
    async fn count_active_flowspec_by_customer(&self, customer_id: &str) -> Result<u32>;
    async fn count_active_flowspec_by_pop(&self, pop: &str) -> Result<u32>;
    async fn count_active_flowspec_global(&self) -> Result<u32>;
    /// Read-only snapshot using admission's 60-second POP window and all row kinds/statuses.
    /// This reserves no capacity; `admit_mitigation` rechecks under its transaction lock.
    async fn check_new_mitigation_rate(&self, pop: &str, max: u32) -> Result<()>;
    async fn find_expired_mitigations(&self) -> Result<Vec<Mitigation>>;
    /// Strict complete expiry inventory; `None` requests all POPs for standalone reconciliation.
    /// Legacy enumeration cannot promise strict decoding or SQL-level POP isolation.
    async fn expired_mitigation_inventory(&self, _pop: Option<&str>) -> Result<Vec<Mitigation>> {
        Err(crate::error::PrefixdError::Internal(
            "strict expiry inventory is unsupported by this repository".into(),
        ))
    }
    /// Complete owner inventory, including pending rows, without a timestamp cursor.
    async fn active_mitigations_for_pop(&self, pop: &str) -> Result<Vec<Mitigation>>;
    /// Strict complete owner inventory; `None` requests all POPs for standalone reconciliation.
    /// Existing implementers retain scoped reads; override this method to support all POPs.
    /// The default rejects an unsupported all-POP request instead of returning partial state.
    async fn active_mitigation_inventory(&self, pop: Option<&str>) -> Result<Vec<Mitigation>> {
        match pop {
            Some(pop) => self.active_mitigations_for_pop(pop).await,
            None => Err(crate::error::PrefixdError::Internal(
                "all-POP mitigation inventory is unsupported by this repository".into(),
            )),
        }
    }

    async fn begin_withdrawal(&self, request: &WithdrawalRequest) -> Result<WithdrawalRequest>;
    async fn pending_withdrawals(&self, pop: Option<&str>) -> Result<Vec<WithdrawalRequest>>;
    /// Atomically complete this exact operation and its unchanged mitigation revision.
    async fn finish_withdrawal(&self, request: &WithdrawalRequest) -> Result<Option<Mitigation>>;

    // Safelist
    async fn insert_safelist(
        &self,
        prefix: &str,
        added_by: &str,
        reason: Option<&str>,
    ) -> Result<()>;
    async fn remove_safelist(&self, prefix: &str) -> Result<bool>;
    async fn list_safelist(&self) -> Result<Vec<SafelistEntry>>;
    /// Whether an IP or destination prefix overlaps any protected prefix.
    /// Broader candidates also protect entries contained inside them.
    async fn is_safelisted(&self, target: &str) -> Result<bool>;

    // Multi-POP coordination
    async fn list_pops(&self) -> Result<Vec<PopInfo>>;
    async fn get_stats(&self) -> Result<GlobalStats>;

    // Timeseries
    async fn timeseries_mitigations(
        &self,
        range_hours: u32,
        bucket_minutes: u32,
    ) -> Result<Vec<TimeseriesBucket>>;
    async fn timeseries_events(
        &self,
        range_hours: u32,
        bucket_minutes: u32,
    ) -> Result<Vec<TimeseriesBucket>>;

    // IP history
    async fn list_events_by_ip(&self, ip: &str, limit: u32) -> Result<Vec<AttackEvent>>;
    async fn list_mitigations_by_ip(&self, ip: &str, limit: u32) -> Result<Vec<Mitigation>>;

    // Operators
    async fn get_operator_by_username(&self, username: &str) -> Result<Option<Operator>>;
    async fn get_operator_by_id(&self, id: Uuid) -> Result<Option<Operator>>;
    async fn create_operator(
        &self,
        username: &str,
        password_hash: &str,
        role: OperatorRole,
        created_by: Option<&str>,
    ) -> Result<Operator>;
    async fn update_operator_last_login(&self, id: Uuid) -> Result<()>;
    async fn update_operator_password(&self, id: Uuid, password_hash: &str) -> Result<()>;
    async fn delete_operator(&self, id: Uuid) -> Result<bool>;
    async fn list_operators(&self) -> Result<Vec<Operator>>;

    // Notification preferences
    async fn get_notification_preferences(
        &self,
        operator_id: Uuid,
    ) -> Result<Option<NotificationPreferences>>;
    async fn upsert_notification_preferences(
        &self,
        operator_id: Uuid,
        prefs: &NotificationPreferences,
    ) -> Result<()>;

    // Signal groups (correlation engine)
    /// Insert a new signal group. Uses ON CONFLICT for concurrent safety:
    /// if a matching open group already exists, returns the existing group.
    async fn insert_signal_group(&self, group: &SignalGroup) -> Result<SignalGroup>;
    /// Update a signal group (derived_confidence, source_count, status, corroboration_met).
    async fn update_signal_group(&self, group: &SignalGroup) -> Result<()>;
    /// Get a signal group by ID.
    async fn get_signal_group(&self, group_id: Uuid) -> Result<Option<SignalGroup>>;
    /// Find an open signal group matching (victim_ip, vector) whose window hasn't expired.
    async fn find_open_group(&self, victim_ip: &str, vector: &str) -> Result<Option<SignalGroup>>;
    /// Find all open signal groups whose aggregated event dimensions match
    /// any of the populated dimensions in `dims` and (if `vector` is `Some`)
    /// whose vector matches. Used by the corroborator ingest handler.
    async fn find_open_groups_by_dimensions(
        &self,
        vector: &Option<String>,
        dims: &crate::correlation::EventDimensions,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<SignalGroup>>;
    /// Add an event to a signal group (junction table). Returns false if already linked.
    async fn add_event_to_group(
        &self,
        group_id: Uuid,
        event_id: Uuid,
        source_weight: f32,
    ) -> Result<bool>;
    /// List events belonging to a signal group, with denormalized source/confidence/ingested_at.
    async fn list_signal_group_events(&self, group_id: Uuid) -> Result<Vec<SignalGroupEvent>>;
    /// List signal groups with optional filters and cursor pagination.
    async fn list_signal_groups(
        &self,
        filter: &SignalGroupFilter,
        params: &ListParams,
    ) -> Result<Vec<SignalGroup>>;
    /// Count currently open signal groups.
    async fn count_open_groups(&self) -> Result<u32>;
    /// Find open signal groups whose window has expired (for expiry sweep).
    async fn find_expired_signal_groups(&self) -> Result<Vec<SignalGroup>>;
    /// List currently open signal groups (status = 'open'). Used by the
    /// reconcile loop's confidence-decay refresh path. No pagination —
    /// callers should expect O(open_groups) results which in practice is
    /// bounded by the corroboration window size.
    async fn list_open_signal_groups(&self) -> Result<Vec<SignalGroup>>;
    /// Find the mitigation ID linked to a specific signal group (if any).
    async fn find_mitigation_id_by_signal_group(
        &self,
        signal_group_id: Uuid,
    ) -> Result<Option<Uuid>>;

    // Corroborating signals (ADR 021)

    /// Attach a corroborating signal to a signal group. Uses `event_id =
    /// signal.signal_id` in the junction table and denormalizes source /
    /// confidence so `list_signal_group_events` can render the row without
    /// touching `corroborating_signals`.
    async fn add_corroborator_event_to_group(
        &self,
        group_id: Uuid,
        signal: &crate::correlation::CorroboratingSignal,
    ) -> Result<bool>;
    /// Returns true if the group has at least one `is_corroborating=false`
    /// event (a primary event). Used to enforce the ADR 021 invariant that
    /// groups of only corroborators cannot trigger mitigations.
    async fn group_has_primary_event(&self, group_id: Uuid) -> Result<bool>;
    /// Insert a corroborating signal into the floating cache (used when the
    /// signal arrives before any matching primary signal group exists).
    async fn insert_corroborating_signal(
        &self,
        signal: &crate::correlation::CorroboratingSignal,
    ) -> Result<()>;
    /// Find cached corroborating signals whose dimensions match the given
    /// event dimensions and haven't expired. Used to drain the cache when
    /// a primary event arrives.
    async fn find_matching_corroborators(
        &self,
        vector: &str,
        dims: &crate::correlation::EventDimensions,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<crate::correlation::CorroboratingSignal>>;
    /// Record that a cached corroborating signal has been attached to a
    /// signal group. Appends `group_id` to the signal's `attached_group_ids`.
    async fn mark_corroborator_attached(&self, signal_id: Uuid, group_id: Uuid) -> Result<()>;
    /// Delete corroborating signals whose `expires_at` is in the past.
    /// Returns `CorroboratorSweepStats` so the scheduler can attribute
    /// `CORROBORATOR_EXPIRED_TOTAL` to signals that expired *without* ever
    /// attaching, while still GCing attached rows from the cache.
    async fn delete_expired_corroborating_signals(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<CorroboratorSweepStats>;
    /// Count currently-cached (unattached, unexpired) corroborating signals.
    /// For operator dashboards / metrics.
    async fn count_cached_corroborators(&self, now: chrono::DateTime<chrono::Utc>) -> Result<u64>;
    /// List currently-cached corroborating signals for admin UI /
    /// debugging. When `source` is `Some`, results are filtered to
    /// only that source.
    async fn list_cached_corroborators(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        limit: i64,
        source: Option<&str>,
    ) -> Result<Vec<crate::correlation::CorroboratingSignal>>;
    /// Aggregate corroborator activity per source since `since`, across
    /// both the live cache (`corroborating_signals`) and attached rows
    /// (`signal_group_events WHERE is_corroborating`). Used by the
    /// Signals dashboard to reflect `mode: corroborating` source health
    /// that otherwise never shows up in the primary `/v1/events` stream.
    async fn corroborator_source_activity(
        &self,
        since: DateTime<Utc>,
    ) -> Result<Vec<CorroboratorSourceActivity>>;
    /// Per-source counts of currently-cached unattached, unexpired
    /// corroborating signals. Used by the reconcile loop to set the
    /// `prefixd_corroborator_cache_size{source}` gauge on each tick so
    /// operators can alert on caches that grow without bound (e.g.
    /// when a source posts but no matching primary event ever lands).
    async fn count_cached_corroborators_by_source(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<(String, u64)>>;
}
