use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::correlation::engine::{SignalGroup, SignalGroupEvent, SignalGroupFilter};
use crate::domain::{AttackEvent, Mitigation, MitigationStatus, Operator, OperatorRole};
use crate::error::Result;
use crate::observability::AuditEntry;

use super::{GlobalStats, PopInfo, SafelistEntry, TimeseriesBucket};

/// Return value for `delete_expired_corroborating_signals`.
///
/// `unattached_expired` is the count of signals the scheduler should
/// increment `CORROBORATOR_EXPIRED_TOTAL` by: signals that were cached
/// because no primary group matched at ingest and then timed out without
/// ever attaching. `attached_expired` rows are the audit copies retained
/// for late fan-out; their deletion is bookkeeping, not a cache miss.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CorroboratorSweepStats {
    pub unattached_expired: u64,
    pub attached_expired: u64,
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

/// Query parameters shared by all list endpoints (cursor pagination + date range)
#[derive(Debug, Clone, Default)]
pub struct ListParams {
    pub limit: u32,
    pub cursor: Option<DateTime<Utc>>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
}

#[async_trait]
pub trait RepositoryTrait: Send + Sync {
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
    async fn insert_mitigation(&self, m: &Mitigation) -> Result<()>;
    async fn update_mitigation(&self, m: &Mitigation) -> Result<()>;
    async fn get_mitigation(&self, id: Uuid) -> Result<Option<Mitigation>>;
    async fn find_active_by_scope(&self, scope_hash: &str, pop: &str)
    -> Result<Option<Mitigation>>;
    async fn find_active_by_victim(&self, victim_ip: &str) -> Result<Vec<Mitigation>>;
    async fn find_active_by_triggering_event(&self, event_id: Uuid) -> Result<Option<Mitigation>>;
    async fn list_mitigations(
        &self,
        status_filter: Option<&[MitigationStatus]>,
        customer_id: Option<&str>,
        victim_ip: Option<&str>,
        acknowledged: Option<bool>,
        params: &ListParams,
    ) -> Result<Vec<Mitigation>>;
    async fn acknowledge_mitigations(&self, ids: &[Uuid], operator_id: &str) -> Result<Vec<Uuid>>;
    async fn count_active_by_customer(&self, customer_id: &str) -> Result<u32>;
    async fn count_active_by_pop(&self, pop: &str) -> Result<u32>;
    async fn count_active_global(&self) -> Result<u32>;
    async fn find_expired_mitigations(&self) -> Result<Vec<Mitigation>>;

    // Safelist
    async fn insert_safelist(
        &self,
        prefix: &str,
        added_by: &str,
        reason: Option<&str>,
    ) -> Result<()>;
    async fn remove_safelist(&self, prefix: &str) -> Result<bool>;
    async fn list_safelist(&self) -> Result<Vec<SafelistEntry>>;
    async fn is_safelisted(&self, ip: &str) -> Result<bool>;

    // Multi-POP coordination
    async fn list_pops(&self) -> Result<Vec<PopInfo>>;
    async fn get_stats(&self) -> Result<GlobalStats>;
    async fn list_mitigations_all_pops(
        &self,
        status_filter: Option<&[MitigationStatus]>,
        customer_id: Option<&str>,
        victim_ip: Option<&str>,
        acknowledged: Option<bool>,
        params: &ListParams,
    ) -> Result<Vec<Mitigation>>;

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
    /// List currently-cached corroborating signals for admin UI / debugging.
    async fn list_cached_corroborators(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        limit: i64,
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
}
