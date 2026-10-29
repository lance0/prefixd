use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgConnection, PgPool};
use std::time::Duration;
use uuid::Uuid;

use super::{ListParams, MitigationListParams, NotificationPreferences, RepositoryTrait};
use crate::config::{BlackholeConfig, QuotasConfig};
use crate::correlation::engine::{
    CorroboratingSignal, EventDimensions, SignalGroup, SignalGroupEvent, SignalGroupFilter,
};
use crate::domain::{
    ActionType, AttackEvent, Mitigation, MitigationRow, MitigationStatus, Operator, OperatorRole,
    WithdrawalRequest,
};
use crate::error::{GuardrailError, PrefixdError, Result};
use crate::observability::{ActorType, AuditEntry, CreationActor, metrics::ROW_PARSE_ERRORS};

pub(super) fn check_active_quota(quota_type: &str, current: u32, max: u32) -> Result<()> {
    if current >= max {
        return Err(PrefixdError::GuardrailViolation(
            GuardrailError::QuotaExceeded {
                quota_type: quota_type.into(),
                current,
                max,
            },
        ));
    }
    Ok(())
}

/// Window for `max_new_per_minute`: rows created at the POP, whatever their status now.
pub(super) const NEW_MITIGATION_WINDOW: chrono::TimeDelta = chrono::TimeDelta::seconds(60);

pub(super) fn check_new_mitigation_rate(current: u32, max: u32) -> Result<()> {
    if current >= max {
        return Err(PrefixdError::GuardrailViolation(
            GuardrailError::NewMitigationRateExceeded { current, max },
        ));
    }
    Ok(())
}

#[derive(Debug, FromRow)]
struct AuditRow {
    audit_id: Uuid,
    #[sqlx(try_from = "crate::db::CheckedTimestamp")]
    timestamp: DateTime<Utc>,
    schema_version: i32,
    actor_type: String,
    actor_id: Option<String>,
    action: String,
    target_type: Option<String>,
    target_id: Option<String>,
    details_json: String,
}

impl AuditEntry {
    fn from_row(row: AuditRow) -> Result<Self> {
        let actor_type = match row.actor_type.as_str() {
            "operator" => ActorType::Operator,
            "detector" => ActorType::Detector,
            "system" => ActorType::System,
            _ => {
                return Err(PrefixdError::Internal(
                    "invalid stored audit actor type".into(),
                ));
            }
        };
        Ok(Self {
            audit_id: row.audit_id,
            timestamp: row.timestamp,
            schema_version: u32::try_from(row.schema_version).map_err(|_| {
                PrefixdError::Internal("invalid stored audit schema version".into())
            })?,
            actor_type,
            actor_id: row.actor_id,
            action: row.action,
            target_type: row.target_type,
            target_id: row.target_id,
            details: serde_json::from_str(&row.details_json)?,
        })
    }
}

/// Startup assumption, not observed history: the operator upgraded without changing mode.
pub(crate) fn unknown_origin_audit(
    pop: &str,
    mode: crate::config::OperationMode,
    tagged: u64,
) -> AuditEntry {
    AuditEntry::new(
        ActorType::System,
        Some("startup".into()),
        "tag_origin_mode",
        Some("pop"),
        Some(pop.into()),
        serde_json::json!({"origin_mode": mode.as_str(), "tagged_mitigations": tagged}),
    )
}

/// An ordinary pooled connection, or a bounded read's read-only transaction.
enum ReadConnection {
    Pooled(sqlx::pool::PoolConnection<sqlx::Postgres>),
    ReadOnly(sqlx::Transaction<'static, sqlx::Postgres>),
}

impl std::ops::Deref for ReadConnection {
    type Target = PgConnection;
    fn deref(&self) -> &PgConnection {
        match self {
            Self::Pooled(connection) => connection,
            Self::ReadOnly(transaction) => transaction,
        }
    }
}

impl std::ops::DerefMut for ReadConnection {
    fn deref_mut(&mut self) -> &mut PgConnection {
        match self {
            Self::Pooled(connection) => connection,
            Self::ReadOnly(transaction) => transaction,
        }
    }
}

#[derive(Clone)]
pub struct Repository {
    pool: PgPool,
    read_deadline: Option<tokio::time::Instant>,
}

impl Repository {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            read_deadline: None,
        }
    }

    /// A bounded-read view runs each read in its own `BEGIN READ ONLY`
    /// transaction with a transaction-local `statement_timeout`. Dropping it
    /// rolls back, ending the setting, and returns the connection to the pool.
    async fn bounded_read_connection(&self) -> Result<ReadConnection> {
        let Some(deadline) = self.read_deadline else {
            return Ok(ReadConnection::Pooled(self.pool.acquire().await?));
        };
        // SQLx records a transaction only after BEGIN's reply; cancelling that
        // await would return an open transaction to the pool. The detached task
        // always finishes BEGIN, so a dropped result rolls back normally.
        let pool = self.pool.clone();
        let begin = tokio::spawn(async move { pool.begin_with("BEGIN READ ONLY").await });
        let mut transaction = tokio::time::timeout_at(deadline, begin)
            .await
            .map_err(|_| sqlx::Error::PoolTimedOut)?
            .map_err(|_| sqlx::Error::PoolTimedOut)??;
        // The server deadline ends before the request deadline, so a cancelled
        // statement has finished by the time the pool's release ping waits on it.
        let remaining = deadline
            .saturating_duration_since(tokio::time::Instant::now())
            .checked_sub(Duration::from_millis(500))
            .ok_or(sqlx::Error::PoolTimedOut)?;
        let milliseconds = i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX);
        if milliseconds == 0 {
            return Err(sqlx::Error::PoolTimedOut.into());
        }
        // pg_settings stores this GUC in milliseconds. Preserve a stricter
        // server limit; zero means disabled and must never be our new limit.
        let _: String = sqlx::query_scalar(
            r#"SELECT pg_catalog.set_config(
                'statement_timeout',
                LEAST($1::int, COALESCE(NULLIF(setting::int, 0), $1::int))::text,
                true
            ) FROM pg_catalog.pg_settings WHERE name = 'statement_timeout'"#,
        )
        .bind(milliseconds)
        .fetch_one(&mut *transaction)
        .await?;
        Ok(ReadConnection::ReadOnly(transaction))
    }

    async fn insert_mitigation_on(connection: &mut PgConnection, m: &Mitigation) -> Result<()> {
        let match_json = serde_json::to_string(&m.match_criteria)?;
        let action_params_json = serde_json::to_string(&m.action_params)?;

        sqlx::query(
            r#"
            INSERT INTO mitigations (
                mitigation_id, scope_hash, pop, customer_id, service_id, victim_ip, vector,
                match_json, action_type, action_params_json, status,
                created_at, updated_at, expires_at, withdrawn_at,
                triggering_event_id, last_event_id, escalated_from_id, reason, rejection_reason,
                signal_group_id, origin_mode
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)
            "#,
        )
        .bind(m.mitigation_id)
        .bind(&m.scope_hash)
        .bind(&m.pop)
        .bind(&m.customer_id)
        .bind(&m.service_id)
        .bind(&m.victim_ip)
        .bind(m.vector.as_str())
        .bind(&match_json)
        .bind(m.action_type.as_str())
        .bind(&action_params_json)
        .bind(m.status.as_str())
        .bind(m.created_at)
        .bind(m.updated_at)
        .bind(m.expires_at)
        .bind(m.withdrawn_at)
        .bind(m.triggering_event_id)
        .bind(m.last_event_id)
        .bind(m.escalated_from_id)
        .bind(&m.reason)
        .bind(&m.rejection_reason)
        .bind(m.signal_group_id)
        .bind(m.origin_mode.map(crate::config::OperationMode::as_str))
        .execute(connection)
        .await?;
        Ok(())
    }

    async fn insert_audit_on(connection: &mut PgConnection, entry: &AuditEntry) -> Result<()> {
        let details_json = serde_json::to_string(&entry.details)?;
        sqlx::query(
            r#"
            INSERT INTO audit_log (audit_id, timestamp, schema_version, actor_type, actor_id, action, target_type, target_id, details_json)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(entry.audit_id)
        .bind(entry.timestamp)
        .bind(entry.schema_version as i32)
        .bind(format!("{:?}", entry.actor_type).to_lowercase())
        .bind(&entry.actor_id)
        .bind(&entry.action)
        .bind(&entry.target_type)
        .bind(&entry.target_id)
        .bind(&details_json)
        .execute(connection)
        .await?;
        Ok(())
    }

    /// Runs under the admission lock. Uses this controller's clock, which also stamped
    /// `created_at` on every row at its POP (one controller per POP).
    async fn check_new_mitigation_rate_on(
        connection: &mut PgConnection,
        pop: &str,
        max: u32,
    ) -> Result<()> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mitigations WHERE pop = $1 AND created_at > $2",
        )
        .bind(pop)
        .bind(Utc::now() - NEW_MITIGATION_WINDOW)
        .fetch_one(connection)
        .await?;
        check_new_mitigation_rate(u32::try_from(count).unwrap_or(u32::MAX), max)
    }
}

#[async_trait]
impl RepositoryTrait for Repository {
    fn for_bounded_reads(
        self: std::sync::Arc<Self>,
        deadline: tokio::time::Instant,
    ) -> Result<std::sync::Arc<dyn RepositoryTrait>> {
        Ok(std::sync::Arc::new(Self {
            pool: self.pool.clone(),
            read_deadline: Some(deadline),
        }))
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
        let mut tx = self.pool.begin().await?;
        // Also serializes the absent-row case and competing POPs for one target.
        // This is startup ownership registration, not an interprocess runtime lease.
        sqlx::query("LOCK TABLE speaker_pop_bindings IN SHARE ROW EXCLUSIVE MODE")
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO speaker_targets (target_id, backend, endpoint, routing_namespace) VALUES ($1, $2, $3, $4) ON CONFLICT (backend, endpoint, routing_namespace) DO NOTHING")
            .bind(Uuid::new_v4()).bind(target.backend).bind(&target.endpoint).bind(target.namespace)
            .execute(&mut *tx).await?;
        let target_id: Uuid = sqlx::query_scalar("SELECT target_id FROM speaker_targets WHERE backend = $1 AND endpoint = $2 AND routing_namespace = $3")
            .bind(target.backend).bind(&target.endpoint).bind(target.namespace)
            .fetch_one(&mut *tx).await?;
        let assigned: Option<Uuid> =
            sqlx::query_scalar("SELECT target_id FROM speaker_pop_bindings WHERE pop = $1")
                .bind(pop)
                .fetch_optional(&mut *tx)
                .await?;
        let foreign: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM speaker_pop_bindings WHERE target_id = $1 AND pop <> $2)",
        )
        .bind(target_id)
        .bind(pop)
        .fetch_one(&mut *tx)
        .await?;
        if assigned.is_some_and(|assigned| assigned != target_id) || foreign {
            return Err(binding_mismatch());
        }
        let legacy: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM mitigations WHERE pop = $1) OR EXISTS (SELECT 1 FROM withdrawal_requests WHERE pop = $1) OR EXISTS (SELECT 1 FROM flowspec_announcements WHERE pop = $1)")
            .bind(pop).fetch_one(&mut *tx).await?;
        let unbound_requests: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM withdrawal_requests WHERE pop = $1 AND target_id IS NULL)")
            .bind(pop).fetch_one(&mut *tx).await?;
        let mismatched_requests: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM withdrawal_requests WHERE pop = $1 AND completed_at IS NULL AND target_id IS NOT NULL AND target_id <> $2)")
            .bind(pop).bind(target_id).fetch_one(&mut *tx).await?;
        if mismatched_requests {
            return Err(binding_mismatch());
        }
        if !adopt_legacy && ((assigned.is_none() && legacy) || unbound_requests) {
            return Err(crate::error::PrefixdError::Conflict(
                "legacy speaker state requires explicit original-target adoption with --adopt-legacy-speaker".into(),
            ));
        }
        if assigned.is_none() {
            sqlx::query("INSERT INTO speaker_pop_bindings (pop, target_id) VALUES ($1, $2)")
                .bind(pop)
                .bind(target_id)
                .execute(&mut *tx)
                .await?;
        }
        let attached = if adopt_legacy {
            sqlx::query("UPDATE withdrawal_requests SET target_id = $2 WHERE pop = $1 AND target_id IS NULL")
                .bind(pop).bind(target_id).execute(&mut *tx).await?.rows_affected()
        } else {
            0
        };
        if adopt_legacy && ((assigned.is_none() && legacy) || attached > 0) {
            let entry = AuditEntry::new(
                ActorType::System,
                Some("adopt-legacy-speaker".into()),
                "adopt_speaker_target",
                Some("speaker_target"),
                Some(target_id.to_string()),
                serde_json::json!({"pop": pop, "attached_withdrawals": attached}),
            );
            sqlx::query("INSERT INTO audit_log (audit_id, timestamp, actor_type, actor_id, action, target_type, target_id, details_json) VALUES ($1, $2, 'system', $3, $4, $5, $6, $7)")
                .bind(entry.audit_id).bind(entry.timestamp).bind(entry.actor_id).bind(entry.action)
                .bind(entry.target_type).bind(entry.target_id).bind(serde_json::to_string(&entry.details)?)
                .execute(&mut *tx).await?;
        }
        tx.commit().await?;
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
        Ok(sqlx::query_scalar("SELECT target_id FROM speaker_targets WHERE backend = $1 AND endpoint = $2 AND routing_namespace = $3")
            .bind(target.backend).bind(&target.endpoint).bind(target.namespace)
            .fetch_optional(&self.pool).await?)
    }

    async fn tag_unknown_origin(
        &self,
        pop: &str,
        mode: crate::config::OperationMode,
    ) -> Result<u64> {
        let mut tx = self.pool.begin().await?;
        let tagged = sqlx::query("UPDATE mitigations SET origin_mode = $2 WHERE pop = $1 AND origin_mode IS NULL AND status IN ('pending', 'active', 'escalated')")
            .bind(pop).bind(mode.as_str()).execute(&mut *tx).await?.rows_affected();
        if tagged > 0 {
            let entry = unknown_origin_audit(pop, mode, tagged);
            sqlx::query("INSERT INTO audit_log (audit_id, timestamp, actor_type, actor_id, action, target_type, target_id, details_json) VALUES ($1, $2, 'system', $3, $4, $5, $6, $7)")
                .bind(entry.audit_id).bind(entry.timestamp).bind(entry.actor_id).bind(entry.action)
                .bind(entry.target_type).bind(entry.target_id).bind(serde_json::to_string(&entry.details)?)
                .execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(tagged)
    }

    async fn insert_event(&self, event: &AttackEvent) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO events (
                event_id, external_event_id, source, event_timestamp, ingested_at,
                victim_ip, vector, protocol, bps, pps, top_dst_ports_json, top_src_ports_json, confidence,
                action, raw_details
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            "#,
        )
        .bind(event.event_id)
        .bind(&event.external_event_id)
        .bind(&event.source)
        .bind(event.event_timestamp)
        .bind(event.ingested_at)
        .bind(&event.victim_ip)
        .bind(&event.vector)
        .bind(event.protocol)
        .bind(event.bps)
        .bind(event.pps)
        .bind(&event.top_dst_ports_json)
        .bind(&event.top_src_ports_json)
        .bind(event.confidence)
        .bind(&event.action)
        .bind(&event.raw_details)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn find_ban_event_by_external_id(
        &self,
        source: &str,
        external_id: &str,
    ) -> Result<Option<AttackEvent>> {
        let event = sqlx::query_as::<_, AttackEvent>(
            r#"
            SELECT event_id, external_event_id, source, event_timestamp, ingested_at,
                   victim_ip, vector, protocol, bps, pps, top_dst_ports_json, top_src_ports_json, confidence,
                   action, raw_details
            FROM events 
            WHERE source = $1 AND external_event_id = $2 AND action = 'ban'
            ORDER BY ingested_at DESC
            LIMIT 1
            "#,
        )
        .bind(source)
        .bind(external_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(event)
    }

    async fn list_events_filtered(
        &self,
        filters: &super::EventListParams,
    ) -> Result<Vec<AttackEvent>> {
        let params = &filters.pagination;
        let events = sqlx::query_as::<_, AttackEvent>(
            r#"
            SELECT event_id, external_event_id, source, event_timestamp, ingested_at,
                   victim_ip, vector, protocol, bps, pps, top_dst_ports_json, top_src_ports_json, confidence,
                   action, raw_details
            FROM events
            WHERE ($2::timestamptz IS NULL OR (ingested_at, event_id) < ($2, $5))
              AND ($3::timestamptz IS NULL OR ingested_at >= $3)
              AND ($4::timestamptz IS NULL OR ingested_at < $4)
              AND ($6::text IS NULL OR source = $6)
              AND ($7::text IS NULL OR vector = $7)
              AND ($8::text IS NULL OR strpos(lower(victim_ip), lower($8)) > 0
                   OR strpos(event_id::text, lower($8)) > 0)
            ORDER BY ingested_at DESC, event_id DESC LIMIT $1
            "#,
        )
        .bind(params.limit as i64)
        .bind(params.cursor.map(|c| c.timestamp))
        .bind(params.start)
        .bind(params.end)
        .bind(params.cursor.map(|c| c.id))
        .bind(filters.source.as_deref())
        .bind(filters.vector.as_deref())
        .bind(filters.query.as_deref())
        .fetch_all(&self.pool)
        .await?;
        Ok(events)
    }

    async fn insert_audit(&self, entry: &AuditEntry) -> Result<()> {
        Self::insert_audit_on(&mut *self.pool.acquire().await?, entry).await
    }

    async fn list_audit(&self, params: &ListParams) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query_as::<_, AuditRow>(
            r#"
            SELECT audit_id, timestamp, schema_version, actor_type, actor_id, action, target_type, target_id, details_json
            FROM audit_log
            WHERE ($2::timestamptz IS NULL OR (timestamp, audit_id) < ($2, $5))
              AND ($3::timestamptz IS NULL OR timestamp >= $3)
              AND ($4::timestamptz IS NULL OR timestamp < $4)
            ORDER BY timestamp DESC, audit_id DESC LIMIT $1
            "#,
        )
        .bind(params.limit as i64)
        .bind(params.cursor.map(|c| c.timestamp))
        .bind(params.start)
        .bind(params.end)
        .bind(params.cursor.map(|c| c.id))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(AuditEntry::from_row).collect()
    }

    async fn active_mitigations_for_pop(&self, pop: &str) -> Result<Vec<Mitigation>> {
        self.active_mitigation_inventory(Some(pop)).await
    }

    async fn active_mitigation_inventory(&self, pop: Option<&str>) -> Result<Vec<Mitigation>> {
        let mut connection = self.bounded_read_connection().await?;
        let rows = sqlx::query_as::<_, MitigationRow>(
            "SELECT * FROM mitigations WHERE ($1::text IS NULL OR pop = $1) AND status IN ('pending', 'active', 'escalated')",
        )
        .bind(pop)
        .fetch_all(&mut *connection)
        .await?;
        rows.into_iter().map(Mitigation::from_row).collect()
    }

    async fn begin_withdrawal(&self, request: &WithdrawalRequest) -> Result<WithdrawalRequest> {
        sqlx::query(
            r#"INSERT INTO withdrawal_requests (
                operation_id, mitigation_id, pop, nlri_hash, rule_json, mitigation_updated_at,
                terminal_status, actor_type, actor, reason, requested_at, speaker_delete_required, target_id,
                rule_kind
            ) SELECT $1, mitigation_id, pop, $4, $5, updated_at, $7, $8, $9, $10, $11, $12, $13, $14
              FROM mitigations WHERE mitigation_id = $2 AND pop = $3 AND updated_at = $6
                AND status IN ('pending', 'active', 'escalated')
                AND (($13::uuid IS NULL AND NOT EXISTS (SELECT 1 FROM speaker_pop_bindings WHERE pop = $3))
                  OR EXISTS (SELECT 1 FROM speaker_pop_bindings WHERE pop = $3 AND target_id = $13))
              ON CONFLICT (mitigation_id) DO NOTHING"#,
        )
        .bind(request.operation_id)
        .bind(request.mitigation_id)
        .bind(&request.pop)
        .bind(&request.nlri_hash)
        .bind(&request.rule_json)
        .bind(request.mitigation_updated_at)
        .bind(&request.terminal_status)
        .bind(&request.actor_type)
        .bind(&request.actor)
        .bind(&request.reason)
        .bind(request.requested_at)
        .bind(request.speaker_delete_required)
        .bind(request.target_id)
        .bind(&request.rule_kind)
        .execute(&self.pool)
        .await?;
        sqlx::query_as::<_, WithdrawalRequest>(
            "SELECT * FROM withdrawal_requests WHERE mitigation_id = $1 AND completed_at IS NULL AND pop = $2 AND target_id IS NOT DISTINCT FROM $3",
        )
        .bind(request.mitigation_id)
        .bind(&request.pop)
        .bind(request.target_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| {
            crate::error::PrefixdError::Conflict(
                "mitigation changed before withdrawal was persisted".into(),
            )
        })
    }

    async fn pending_withdrawals(&self, pop: Option<&str>) -> Result<Vec<WithdrawalRequest>> {
        let mut connection = self.bounded_read_connection().await?;
        Ok(sqlx::query_as::<_, WithdrawalRequest>(
            "SELECT * FROM withdrawal_requests WHERE completed_at IS NULL AND ($1::text IS NULL OR pop = $1) ORDER BY requested_at, operation_id",
        )
        .bind(pop)
        .fetch_all(&mut *connection)
        .await?)
    }

    async fn finish_withdrawal(&self, request: &WithdrawalRequest) -> Result<Option<Mitigation>> {
        let mut transaction = self.pool.begin().await?;
        let pending = sqlx::query_as::<_, WithdrawalRequest>(
            "SELECT * FROM withdrawal_requests WHERE operation_id = $1 AND mitigation_id = $2 AND completed_at IS NULL AND pop = $3 AND target_id IS NOT DISTINCT FROM $4 FOR UPDATE",
        )
        .bind(request.operation_id)
        .bind(request.mitigation_id)
        .bind(&request.pop)
        .bind(request.target_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(pending) = pending else {
            return Ok(None);
        };
        let now = Utc::now();
        let row = sqlx::query_as::<_, MitigationRow>(
            r#"UPDATE mitigations SET status = $3, withdrawn_at = $4, updated_at = $4,
                reason = CASE WHEN $3 = 'expired' THEN reason ELSE $5 END
               WHERE mitigation_id = $1 AND updated_at = $2 AND pop = $6
                 AND status IN ('pending', 'active', 'escalated') RETURNING *"#,
        )
        .bind(pending.mitigation_id)
        .bind(pending.mitigation_updated_at)
        .bind(&pending.terminal_status)
        .bind(now)
        .bind(&pending.reason)
        .bind(&pending.pop)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(row) = row else { return Ok(None) };
        let mitigation = Mitigation::from_row(row)?;
        sqlx::query("UPDATE withdrawal_requests SET completed_at = $2 WHERE operation_id = $1")
            .bind(pending.operation_id)
            .bind(now)
            .execute(&mut *transaction)
            .await?;
        let entry = pending.audit_entry();
        sqlx::query("INSERT INTO audit_log (audit_id, timestamp, actor_type, actor_id, action, target_type, target_id, details_json) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)")
            .bind(entry.audit_id)
            .bind(entry.timestamp)
            .bind(&pending.actor_type)
            .bind(&entry.actor_id)
            .bind(&entry.action)
            .bind(&entry.target_type)
            .bind(&entry.target_id)
            .bind(serde_json::to_string(&entry.details)?)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(Some(mitigation))
    }

    async fn insert_mitigation(&self, m: &Mitigation) -> Result<()> {
        Self::insert_mitigation_on(&mut *self.pool.acquire().await?, m).await
    }

    async fn check_new_mitigation_rate(&self, pop: &str, max: u32) -> Result<()> {
        Self::check_new_mitigation_rate_on(&mut *self.bounded_read_connection().await?, pop, max)
            .await
    }

    async fn admit_mitigation(
        &self,
        m: &Mitigation,
        quotas: &QuotasConfig,
        blackhole: &BlackholeConfig,
        actor: &CreationActor,
    ) -> Result<()> {
        // Bound pool acquisition, lock wait, quota checks and insert. The server bounds also
        // limit residual work while SQLx drives rollback after cancellation. COMMIT stays
        // outside the deadline: once sent, cancelling it cannot prove the row was not kept.
        let tx = tokio::time::timeout(Duration::from_secs(5), async {
            // Explicit isolation is required: a session default of REPEATABLE READ could
            // otherwise keep the snapshot taken before waiting for the admission lock.
            let mut tx = self.pool.begin_with("BEGIN ISOLATION LEVEL READ COMMITTED").await?;
            sqlx::query("SET LOCAL lock_timeout = '5s'").execute(&mut *tx).await?;
            sqlx::query("SET LOCAL statement_timeout = '5s'").execute(&mut *tx).await?;
            // Fixed two-key namespace: prefixd / quota admission. This serializes only
            // new admissions; lifecycle updates and withdrawals do not take this lock.
            sqlx::query("SELECT pg_advisory_xact_lock(1886545528, 1903522164)")
                .execute(&mut *tx).await?;
            if m.action_type != ActionType::Blackhole {
                if let Some(customer_id) = &m.customer_id {
                    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mitigations WHERE action_type != 'blackhole' AND customer_id = $1 AND status IN ('pending', 'active', 'escalated')")
                        .bind(customer_id).fetch_one(&mut *tx).await?;
                    check_active_quota("customer", u32::try_from(count).unwrap_or(u32::MAX), quotas.max_active_per_customer)?;
                }
                let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mitigations WHERE action_type != 'blackhole' AND pop = $1 AND status IN ('pending', 'active', 'escalated')")
                    .bind(&m.pop).fetch_one(&mut *tx).await?;
                check_active_quota("pop", u32::try_from(count).unwrap_or(u32::MAX), quotas.max_active_per_pop)?;
                let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mitigations WHERE action_type != 'blackhole' AND status IN ('pending', 'active', 'escalated')")
                    .fetch_one(&mut *tx).await?;
                check_active_quota("global", u32::try_from(count).unwrap_or(u32::MAX), quotas.max_active_global)?;
            }
            if m.action_type == ActionType::Blackhole {
                let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mitigations WHERE action_type = 'blackhole' AND pop = $1 AND status IN ('pending', 'active', 'escalated')")
                    .bind(&m.pop).fetch_one(&mut *tx).await?;
                check_active_quota("blackhole_pop", u32::try_from(count).unwrap_or(u32::MAX), blackhole.max_active_per_pop)?;
                let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mitigations WHERE action_type = 'blackhole' AND status IN ('pending', 'active', 'escalated')")
                    .fetch_one(&mut *tx).await?;
                check_active_quota("blackhole_global", u32::try_from(count).unwrap_or(u32::MAX), blackhole.max_active_global)?;
            }
            Self::check_new_mitigation_rate_on(&mut tx, &m.pop, quotas.max_new_per_minute).await?;
            // Same transaction as the row: never an entry without a row, or a row without one.
            Self::insert_audit_on(&mut tx, &AuditEntry::mitigation_created(m, actor)).await?;
            Self::insert_mitigation_on(&mut tx, m).await?;
            Ok::<_, PrefixdError>(tx)
        }).await.map_err(|_| PrefixdError::Internal("mitigation admission timed out".into()))??;
        tx.commit().await?;
        Ok(())
    }

    async fn update_mitigation(&self, m: &Mitigation) -> Result<()> {
        let match_json = serde_json::to_string(&m.match_criteria)?;
        let action_params_json = serde_json::to_string(&m.action_params)?;

        sqlx::query(
            r#"
            UPDATE mitigations SET
                scope_hash = $2, status = $3, updated_at = $4, expires_at = $5,
                withdrawn_at = $6, last_event_id = $7, match_json = $8,
                action_type = $9, action_params_json = $10, reason = $11, rejection_reason = $12
            WHERE mitigation_id = $1
            "#,
        )
        .bind(m.mitigation_id)
        .bind(&m.scope_hash)
        .bind(m.status.as_str())
        .bind(m.updated_at)
        .bind(m.expires_at)
        .bind(m.withdrawn_at)
        .bind(m.last_event_id)
        .bind(&match_json)
        .bind(m.action_type.as_str())
        .bind(&action_params_json)
        .bind(&m.reason)
        .bind(&m.rejection_reason)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn extend_flowspec_lifetime(
        &self,
        request: &crate::domain::LifetimeExtension,
        fence: &crate::fence::ControllerFence,
    ) -> Result<crate::domain::LifetimeExtensionOutcome> {
        use crate::domain::LifetimeExtensionOutcome;

        // Bound preparation, but never cancel an in-flight COMMIT.
        let (tx, outcome) = tokio::time::timeout(Duration::from_secs(5), async {
            let mut tx = self.pool.begin_with("BEGIN ISOLATION LEVEL READ COMMITTED").await?;
            sqlx::query("SET LOCAL statement_timeout = '4s'")
                .execute(&mut *tx).await?;
            sqlx::query("SET LOCAL lock_timeout = '3s'")
                .execute(&mut *tx).await?;
            // Protect both a registered row and the absent-row mock case from
            // registration/transfer while this bounded update is in progress.
            sqlx::query("LOCK TABLE speaker_pop_bindings IN SHARE MODE")
                .execute(&mut *tx).await?;
            let target: Option<Uuid> = sqlx::query_scalar(
                "SELECT target_id FROM speaker_pop_bindings WHERE pop = $1",
            ).bind(&request.expected.pop).fetch_optional(&mut *tx).await?;
            if target != request.target_id {
                return Err(crate::domain::binding_mismatch());
            }
            let row = sqlx::query_as::<_, MitigationRow>(
                "SELECT * FROM mitigations WHERE mitigation_id = $1 FOR UPDATE",
            ).bind(request.expected.mitigation_id).fetch_optional(&mut *tx).await?
                .ok_or(PrefixdError::MitigationNotFound(request.expected.mitigation_id))?;
            let current = Mitigation::from_row(row)?;
            // now() is the transaction-start clock and would revive a rule that
            // expired while SELECT FOR UPDATE waited. Read the clock afterwards.
            let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
                .fetch_one(&mut *tx).await?;
            request.validate_current(&current, now)?;
            let (withdrawing, safelisted): (bool, bool) = sqlx::query_as(
                "SELECT EXISTS (SELECT 1 FROM withdrawal_requests WHERE mitigation_id = $1 AND completed_at IS NULL), EXISTS (SELECT 1 FROM safelist WHERE $2::inet && prefix::inet)",
            ).bind(current.mitigation_id).bind(&current.match_criteria.dst_prefix)
                .fetch_one(&mut *tx).await?;
            if withdrawing {
                return Err(PrefixdError::Conflict(
                    "mitigation has a pending withdrawal".into(),
                ));
            }
            // Same 422 refusal as preparation for a safelist that landed meanwhile.
            if safelisted {
                return Err(crate::domain::extension_safelisted(&current.match_criteria.dst_prefix));
            }
            request.ensure_fence(fence)?;
            // Decide from the exact sample used for the write. A backward wall-
            // clock step between reads must never shorten the existing horizon.
            let row = sqlx::query_as::<_, MitigationRow>(
                r#"WITH timing AS MATERIALIZED (SELECT clock_timestamp() AS checked_at)
                UPDATE mitigations m SET
                    expires_at = timing.checked_at + make_interval(secs => $4::double precision),
                    updated_at = timing.checked_at
                FROM timing
                WHERE mitigation_id = $1 AND updated_at = $2 AND expires_at = $3
                  AND pop = $5 AND status IN ('active', 'escalated')
                  AND action_type IN ('discard', 'police') AND origin_mode = 'enforced'
                  AND withdrawn_at IS NULL AND expires_at > timing.checked_at
                  AND expires_at < timing.checked_at + make_interval(secs => $4::double precision)
                  AND NOT EXISTS (SELECT 1 FROM withdrawal_requests WHERE mitigation_id = $1 AND completed_at IS NULL)
                  AND NOT EXISTS (SELECT 1 FROM safelist WHERE $6::inet && prefix::inet)
                RETURNING m.*"#,
            ).bind(current.mitigation_id).bind(current.updated_at).bind(current.expires_at)
                .bind(f64::from(request.ttl_seconds)).bind(&current.pop)
                .bind(&current.match_criteria.dst_prefix)
                .fetch_optional(&mut *tx).await?;
            let extended = row.is_some();
            let updated = if let Some(row) = row {
                let updated = Mitigation::from_row(row)?;
                crate::guardrails::validate_total_lifetime(
                    updated.expires_at - updated.created_at,
                    request.max_lifetime_seconds,
                )?;
                Self::insert_audit_on(&mut tx, &request.audit(&updated)).await?;
                updated
            } else {
                current
            };
            // Audit insertion may itself await. Refuse and roll back if the
            // original live authorization elapsed or deletion/safety changed.
            let (eligible, safelisted): (bool, bool) = sqlx::query_as(
                "SELECT $1::timestamptz > clock_timestamp() AND NOT EXISTS (SELECT 1 FROM withdrawal_requests WHERE mitigation_id = $2 AND completed_at IS NULL), EXISTS (SELECT 1 FROM safelist WHERE $3::inet && prefix::inet)",
            ).bind(request.expected.expires_at).bind(updated.mitigation_id)
                .bind(&updated.match_criteria.dst_prefix).fetch_one(&mut *tx).await?;
            if !eligible {
                return Err(PrefixdError::Conflict(
                    "mitigation expired or began withdrawal during lifetime update".into(),
                ));
            }
            if safelisted {
                return Err(crate::domain::extension_safelisted(&updated.match_criteria.dst_prefix));
            }
            request.ensure_fence(fence)?;
            let outcome = LifetimeExtensionOutcome {
                previous_expires_at: request.expected.expires_at,
                mitigation: updated,
                extended,
            };
            Ok::<_, PrefixdError>((tx, outcome))
        }).await.map_err(|_| PrefixdError::Internal(
            "lifetime update timed out; refresh mitigation and audit before retrying".into(),
        ))??;
        tx.commit().await?;
        Ok(outcome)
    }

    async fn get_mitigation(&self, id: Uuid) -> Result<Option<Mitigation>> {
        let mut connection = self.bounded_read_connection().await?;
        let row = sqlx::query_as::<_, MitigationRow>(
            r#"
            SELECT mitigation_id, scope_hash, pop, customer_id, service_id, victim_ip, vector,
                   match_json, action_type, action_params_json, status,
                   created_at, updated_at, expires_at, withdrawn_at,
                   triggering_event_id, last_event_id, escalated_from_id, reason, rejection_reason,
                   acknowledged_at, acknowledged_by, signal_group_id, origin_mode
            FROM mitigations WHERE mitigation_id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&mut *connection)
        .await?;
        match row {
            Some(r) => Ok(Some(Mitigation::from_row(r)?)),
            None => Ok(None),
        }
    }

    async fn find_active_by_scope(
        &self,
        scope_hash: &str,
        pop: &str,
    ) -> Result<Option<Mitigation>> {
        let row = sqlx::query_as::<_, MitigationRow>(
            r#"
            SELECT mitigation_id, scope_hash, pop, customer_id, service_id, victim_ip, vector,
                   match_json, action_type, action_params_json, status,
                   created_at, updated_at, expires_at, withdrawn_at,
                   triggering_event_id, last_event_id, escalated_from_id, reason, rejection_reason,
                   acknowledged_at, acknowledged_by, signal_group_id, origin_mode
            FROM mitigations
            WHERE scope_hash = $1 AND pop = $2 AND status IN ('pending', 'active', 'escalated')
            "#,
        )
        .bind(scope_hash)
        .bind(pop)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(r) => Ok(Some(Mitigation::from_row(r)?)),
            None => Ok(None),
        }
    }

    async fn list_active_by_triggering_event(&self, event_id: Uuid) -> Result<Vec<Mitigation>> {
        let rows = sqlx::query_as::<_, MitigationRow>(
            r#"
            SELECT mitigation_id, scope_hash, pop, customer_id, service_id, victim_ip, vector,
                   match_json, action_type, action_params_json, status,
                   created_at, updated_at, expires_at, withdrawn_at,
                   triggering_event_id, last_event_id, escalated_from_id, reason, rejection_reason,
                   acknowledged_at, acknowledged_by, signal_group_id, origin_mode
            FROM mitigations
            WHERE triggering_event_id = $1 AND status IN ('pending', 'active', 'escalated')
            ORDER BY created_at, mitigation_id
            "#,
        )
        .bind(event_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(Mitigation::from_row).collect()
    }

    async fn list_mitigations(
        &self,
        status_filter: Option<&[MitigationStatus]>,
        customer_id: Option<&str>,
        victim_ip: Option<&str>,
        acknowledged: Option<bool>,
        params: &MitigationListParams,
    ) -> Result<Vec<Mitigation>> {
        let status_strings: Option<Vec<String>> =
            status_filter.map(|statuses| statuses.iter().map(|s| s.as_str().to_string()).collect());

        let rows = sqlx::query_as::<_, MitigationRow>(
            r#"
            SELECT mitigation_id, scope_hash, pop, customer_id, service_id, victim_ip, vector,
                   match_json, action_type, action_params_json, status,
                   created_at, updated_at, expires_at, withdrawn_at,
                   triggering_event_id, last_event_id, escalated_from_id, reason, rejection_reason,
                   acknowledged_at, acknowledged_by, signal_group_id, origin_mode
            FROM mitigations
            WHERE ($1::text[] IS NULL OR status = ANY($1))
              AND ($2::text IS NULL OR customer_id = $2)
              AND ($3::text IS NULL OR victim_ip = $3)
              AND ($10::text IS NULL OR pop = $10)
              AND ($11::text IS NULL OR strpos(lower(victim_ip), lower($11)) > 0
                   OR strpos(lower(vector), lower($11)) > 0
                   OR strpos(lower(customer_id), lower($11)) > 0
                   OR strpos(mitigation_id::text, lower($11)) > 0)
              AND ($4::timestamptz IS NULL OR (created_at, mitigation_id) < ($4, $9::uuid))
              AND ($5::timestamptz IS NULL OR created_at >= $5)
              AND ($6::timestamptz IS NULL OR created_at < $6)
              AND ($7::bool IS NULL OR ($7 = true AND acknowledged_at IS NOT NULL) OR ($7 = false AND acknowledged_at IS NULL))
            ORDER BY created_at DESC, mitigation_id DESC
            LIMIT $8
            "#,
        )
        .bind(status_strings.as_deref())  // $1
        .bind(customer_id)                 // $2
        .bind(victim_ip)                   // $3
        .bind(params.cursor.map(|cursor| cursor.created_at)) // $4
        .bind(params.start)                // $5
        .bind(params.end)                  // $6
        .bind(acknowledged)                // $7
        .bind(params.limit as i64)         // $8
        .bind(params.cursor.map(|cursor| cursor.mitigation_id)) // $9
        .bind(params.pop.as_deref())       // $10
        .bind(params.query.as_deref())     // $11
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                Mitigation::from_row(row).inspect_err(|error| {
                    ROW_PARSE_ERRORS.with_label_values(&["mitigations"]).inc();
                    tracing::error!(%error, "rejecting corrupted mitigation page");
                })
            })
            .collect()
    }

    async fn acknowledge_mitigations(&self, ids: &[Uuid], operator_id: &str) -> Result<Vec<Uuid>> {
        let now = Utc::now();
        let rows: Vec<(Uuid,)> = sqlx::query_as(
            r#"
            UPDATE mitigations
            SET acknowledged_at = $1, acknowledged_by = $2
            WHERE mitigation_id = ANY($3)
              AND acknowledged_at IS NULL
              AND status != 'rejected'
            RETURNING mitigation_id
            "#,
        )
        .bind(now)
        .bind(operator_id)
        .bind(ids)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    async fn count_active_by_customer(&self, customer_id: &str) -> Result<u32> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM mitigations WHERE customer_id = $1 AND status IN ('pending', 'active', 'escalated')",
        )
        .bind(customer_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0 as u32)
    }

    async fn count_active_by_pop(&self, pop: &str) -> Result<u32> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM mitigations WHERE pop = $1 AND status IN ('pending', 'active', 'escalated')",
        )
        .bind(pop)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0 as u32)
    }

    async fn count_active_global(&self) -> Result<u32> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM mitigations WHERE status IN ('pending', 'active', 'escalated')",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0 as u32)
    }

    async fn count_active_flowspec_by_customer(&self, customer_id: &str) -> Result<u32> {
        let mut connection = self.bounded_read_connection().await?;
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM mitigations WHERE action_type != 'blackhole' AND customer_id = $1 AND status IN ('pending', 'active', 'escalated')",
        )
        .bind(customer_id)
        .fetch_one(&mut *connection)
        .await?;
        Ok(row.0 as u32)
    }

    async fn count_active_flowspec_by_pop(&self, pop: &str) -> Result<u32> {
        let mut connection = self.bounded_read_connection().await?;
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM mitigations WHERE action_type != 'blackhole' AND pop = $1 AND status IN ('pending', 'active', 'escalated')",
        )
        .bind(pop)
        .fetch_one(&mut *connection)
        .await?;
        Ok(row.0 as u32)
    }

    async fn count_active_flowspec_global(&self) -> Result<u32> {
        let mut connection = self.bounded_read_connection().await?;
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM mitigations WHERE action_type != 'blackhole' AND status IN ('pending', 'active', 'escalated')",
        )
        .fetch_one(&mut *connection)
        .await?;
        Ok(row.0 as u32)
    }

    async fn find_expired_mitigations(&self) -> Result<Vec<Mitigation>> {
        self.expired_mitigation_inventory(None).await
    }

    async fn expired_mitigation_inventory(&self, pop: Option<&str>) -> Result<Vec<Mitigation>> {
        let now = Utc::now();
        let rows = sqlx::query_as::<_, MitigationRow>(
            r#"
            SELECT mitigation_id, scope_hash, pop, customer_id, service_id, victim_ip, vector,
                   match_json, action_type, action_params_json, status,
                   created_at, updated_at, expires_at, withdrawn_at,
                   triggering_event_id, last_event_id, escalated_from_id, reason, rejection_reason,
                   acknowledged_at, acknowledged_by, signal_group_id, origin_mode
            FROM mitigations
            WHERE status IN ('active', 'escalated') AND expires_at < $1
              AND ($2::text IS NULL OR pop = $2)
            "#,
        )
        .bind(now)
        .bind(pop)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(Mitigation::from_row).collect()
    }

    async fn insert_safelist(
        &self,
        prefix: &str,
        added_by: &str,
        reason: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO safelist (prefix, added_at, added_by, reason)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (prefix) DO UPDATE SET added_at = $2, added_by = $3, reason = $4
            "#,
        )
        .bind(prefix)
        .bind(Utc::now())
        .bind(added_by)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn remove_safelist(&self, prefix: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM safelist WHERE prefix = $1")
            .bind(prefix)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_safelist(&self) -> Result<Vec<SafelistEntry>> {
        let rows = sqlx::query_as::<_, SafelistEntry>(
            "SELECT prefix, added_at, added_by, reason, expires_at FROM safelist",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    async fn is_safelisted(&self, target: &str) -> Result<bool> {
        let mut connection = self.bounded_read_connection().await?;
        // Overlap is symmetric: a broad candidate must not cover a protected
        // host or subnet. Bare addresses retain their /32 or /128 semantics.
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM safelist
            WHERE $1::inet && prefix::inet
            "#,
        )
        .bind(target)
        .fetch_one(&mut *connection)
        .await?;

        Ok(row.0 > 0)
    }

    async fn list_pops(&self) -> Result<Vec<PopInfo>> {
        let rows = sqlx::query_as::<_, (String, i64, i64)>(
            r#"
            SELECT pop,
                   SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END)::bigint as active,
                   COUNT(*)::bigint as total
            FROM mitigations
            GROUP BY pop
            ORDER BY pop
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(pop, active, total)| PopInfo {
                pop,
                active_mitigations: active as u32,
                total_mitigations: total as u32,
            })
            .collect())
    }

    async fn get_stats(&self) -> Result<GlobalStats> {
        let (total_active, total_mitigations): (i64, i64) = sqlx::query_as(
            r#"
            SELECT
                COALESCE(SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END), 0)::bigint,
                COUNT(*)::bigint
            FROM mitigations
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        let total_events: (i64,) = sqlx::query_as("SELECT COUNT(*)::bigint FROM events")
            .fetch_one(&self.pool)
            .await?;

        let pop_rows = sqlx::query_as::<_, (String, i64, i64)>(
            r#"
            SELECT pop,
                   SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END)::bigint as active,
                   COUNT(*)::bigint as total
            FROM mitigations
            GROUP BY pop
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let pops = pop_rows
            .into_iter()
            .map(|(pop, active, total)| PopStats {
                pop,
                active: active as u32,
                total: total as u32,
            })
            .collect();

        Ok(GlobalStats {
            total_active: total_active as u32,
            total_mitigations: total_mitigations as u32,
            total_events: total_events.0 as u32,
            pops,
        })
    }

    // Timeseries
    async fn timeseries_mitigations(
        &self,
        range_hours: u32,
        bucket_minutes: u32,
    ) -> Result<Vec<TimeseriesBucket>> {
        let range_interval = format!("{} hours", range_hours);
        let bucket_interval = format!("{} minutes", bucket_minutes);
        let rows = sqlx::query_as::<_, TimeseriesBucket>(
            r#"
            SELECT gs AS bucket, COALESCE(c.count, 0) AS count
            FROM generate_series(
                date_bin($2::interval, NOW() - $1::interval, '1970-01-01 00:00:00+00'::timestamptz),
                date_bin($2::interval, NOW(), '1970-01-01 00:00:00+00'::timestamptz),
                $2::interval
            ) gs
            LEFT JOIN (
                SELECT date_bin($2::interval, created_at, '1970-01-01 00:00:00+00'::timestamptz) AS bucket, COUNT(*)::bigint AS count
                FROM mitigations
                WHERE created_at >= NOW() - $1::interval
                GROUP BY 1
            ) c ON c.bucket = gs
            ORDER BY gs
            "#,
        )
        .bind(&range_interval)
        .bind(&bucket_interval)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    async fn timeseries_events(
        &self,
        range_hours: u32,
        bucket_minutes: u32,
    ) -> Result<Vec<TimeseriesBucket>> {
        let range_interval = format!("{} hours", range_hours);
        let bucket_interval = format!("{} minutes", bucket_minutes);
        let rows = sqlx::query_as::<_, TimeseriesBucket>(
            r#"
            SELECT gs AS bucket, COALESCE(c.count, 0) AS count
            FROM generate_series(
                date_bin($2::interval, NOW() - $1::interval, '1970-01-01 00:00:00+00'::timestamptz),
                date_bin($2::interval, NOW(), '1970-01-01 00:00:00+00'::timestamptz),
                $2::interval
            ) gs
            LEFT JOIN (
                SELECT date_bin($2::interval, ingested_at, '1970-01-01 00:00:00+00'::timestamptz) AS bucket, COUNT(*)::bigint AS count
                FROM events
                WHERE ingested_at >= NOW() - $1::interval
                GROUP BY 1
            ) c ON c.bucket = gs
            ORDER BY gs
            "#,
        )
        .bind(&range_interval)
        .bind(&bucket_interval)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    // IP history
    async fn list_events_by_ip(&self, ip: &str, limit: u32) -> Result<Vec<AttackEvent>> {
        let events = sqlx::query_as::<_, AttackEvent>(
            r#"
            SELECT event_id, external_event_id, source, event_timestamp, ingested_at,
                   victim_ip, vector, protocol, bps, pps, top_dst_ports_json, top_src_ports_json, confidence,
                   action, raw_details
            FROM events WHERE victim_ip = $1 ORDER BY ingested_at DESC LIMIT $2
            "#,
        )
        .bind(ip)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;
        Ok(events)
    }

    async fn list_mitigations_by_ip(&self, ip: &str, limit: u32) -> Result<Vec<Mitigation>> {
        let rows = sqlx::query_as::<_, MitigationRow>(
            r#"
            SELECT mitigation_id, scope_hash, pop, customer_id, service_id, victim_ip, vector,
                   match_json, action_type, action_params_json, status,
                   created_at, updated_at, expires_at, withdrawn_at,
                   triggering_event_id, last_event_id, escalated_from_id, reason, rejection_reason,
                   acknowledged_at, acknowledged_by, signal_group_id, origin_mode
            FROM mitigations WHERE victim_ip = $1 ORDER BY created_at DESC LIMIT $2
            "#,
        )
        .bind(ip)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                Mitigation::from_row(row).map_err(|e| {
                    ROW_PARSE_ERRORS.with_label_values(&["mitigations"]).inc();
                    tracing::error!(error = %e, "failed to parse mitigation history row");
                    e
                })
            })
            .collect()
    }

    // Operator methods
    async fn get_operator_by_username(&self, username: &str) -> Result<Option<Operator>> {
        let row = sqlx::query_as::<_, OperatorRow>(
            r#"
            SELECT operator_id, username, password_hash, role, created_at, created_by, last_login_at
            FROM operators WHERE username = $1
            "#,
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    async fn get_operator_by_id(&self, id: Uuid) -> Result<Option<Operator>> {
        let row = sqlx::query_as::<_, OperatorRow>(
            r#"
            SELECT operator_id, username, password_hash, role, created_at, created_by, last_login_at
            FROM operators WHERE operator_id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    async fn create_operator(
        &self,
        username: &str,
        password_hash: &str,
        role: OperatorRole,
        created_by: Option<&str>,
    ) -> Result<Operator> {
        let row = sqlx::query_as::<_, OperatorRow>(
            r#"
            INSERT INTO operators (username, password_hash, role, created_by)
            VALUES ($1, $2, $3, $4)
            RETURNING operator_id, username, password_hash, role, created_at, created_by, last_login_at
            "#,
        )
        .bind(username)
        .bind(password_hash)
        .bind(role.to_string())
        .bind(created_by)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.into())
    }

    async fn update_operator_last_login(&self, id: Uuid) -> Result<()> {
        sqlx::query("UPDATE operators SET last_login_at = NOW() WHERE operator_id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn update_operator_password(&self, id: Uuid, password_hash: &str) -> Result<()> {
        sqlx::query("UPDATE operators SET password_hash = $1 WHERE operator_id = $2")
            .bind(password_hash)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_operator(&self, id: Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM operators WHERE operator_id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_operators(&self) -> Result<Vec<Operator>> {
        let rows = sqlx::query_as::<_, OperatorRow>(
            r#"
            SELECT operator_id, username, password_hash, role, created_at, created_by, last_login_at
            FROM operators ORDER BY created_at ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn get_notification_preferences(
        &self,
        operator_id: Uuid,
    ) -> Result<Option<NotificationPreferences>> {
        let row = sqlx::query_as::<_, NotifPrefRow>(
            "SELECT muted_events, quiet_hours_start, quiet_hours_end FROM notification_preferences WHERE operator_id = $1",
        )
        .bind(operator_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| NotificationPreferences {
            muted_events: r.muted_events,
            quiet_hours_start: r.quiet_hours_start,
            quiet_hours_end: r.quiet_hours_end,
        }))
    }

    async fn upsert_notification_preferences(
        &self,
        operator_id: Uuid,
        prefs: &NotificationPreferences,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO notification_preferences (operator_id, muted_events, quiet_hours_start, quiet_hours_end, updated_at)
            VALUES ($1, $2, $3, $4, NOW())
            ON CONFLICT (operator_id) DO UPDATE SET
                muted_events = EXCLUDED.muted_events,
                quiet_hours_start = EXCLUDED.quiet_hours_start,
                quiet_hours_end = EXCLUDED.quiet_hours_end,
                updated_at = NOW()
            "#,
        )
        .bind(operator_id)
        .bind(&prefs.muted_events)
        .bind(prefs.quiet_hours_start)
        .bind(prefs.quiet_hours_end)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ── Signal groups ──────────────────────────────────────────────────

    async fn insert_signal_group(&self, group: &SignalGroup) -> Result<SignalGroup> {
        // Use INSERT ... ON CONFLICT to handle concurrent races.
        // If another request already created a group for (victim_ip, vector, status='open'),
        // we return the existing one. The unique constraint is checked via a CTE that
        // tries to find an existing open group first.
        //
        // Under true concurrency, two requests may both execute the CTE simultaneously,
        // both find no existing group, and both try to INSERT. The partial unique index
        // (idx_signal_groups_open_unique) will cause one to fail with a unique violation.
        // When that happens, we retry with a simple SELECT to find the group that won the race.
        let result = sqlx::query_as::<_, SignalGroupRow>(
            r#"
            WITH existing AS (
                SELECT group_id, victim_ip, vector, created_at, window_expires_at,
                       derived_confidence, source_count, status, corroboration_met,
                       primary_dimensions, playbook_name
                FROM signal_groups
                WHERE victim_ip = $2 AND vector = $3 AND status = 'open'
                  AND window_expires_at > NOW()
                LIMIT 1
            ), inserted AS (
                INSERT INTO signal_groups (group_id, victim_ip, vector, created_at, window_expires_at,
                    derived_confidence, source_count, status, corroboration_met, primary_dimensions,
                    playbook_name)
                SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
                WHERE NOT EXISTS (SELECT 1 FROM existing)
                RETURNING group_id, victim_ip, vector, created_at, window_expires_at,
                    derived_confidence, source_count, status, corroboration_met, primary_dimensions,
                    playbook_name
            )
            SELECT * FROM existing
            UNION ALL
            SELECT * FROM inserted
            LIMIT 1
            "#,
        )
        .bind(group.group_id)
        .bind(&group.victim_ip)
        .bind(&group.vector)
        .bind(group.created_at)
        .bind(group.window_expires_at)
        .bind(group.derived_confidence)
        .bind(group.source_count)
        .bind(group.status.as_str())
        .bind(group.corroboration_met)
        .bind(serde_json::to_value(&group.primary_dimensions).unwrap_or(serde_json::json!({})))
        .bind(group.playbook_name.as_deref())
        .fetch_one(&self.pool)
        .await;

        match result {
            Ok(row) => row.try_into(),
            Err(sqlx::Error::Database(ref db_err)) if db_err.code().as_deref() == Some("23505") => {
                // Unique constraint violation — another concurrent request won the race.
                // Retry by fetching the existing open group.
                tracing::debug!(
                    victim_ip = %group.victim_ip,
                    vector = %group.vector,
                    "concurrent signal group insert conflict, retrying SELECT"
                );
                let row = sqlx::query_as::<_, SignalGroupRow>(
                    r#"
                    SELECT group_id, victim_ip, vector, created_at, window_expires_at,
                           derived_confidence, source_count, status, corroboration_met,
                           primary_dimensions, playbook_name
                    FROM signal_groups
                    WHERE victim_ip = $1 AND vector = $2 AND status = 'open'
                      AND window_expires_at > NOW()
                    LIMIT 1
                    "#,
                )
                .bind(&group.victim_ip)
                .bind(&group.vector)
                .fetch_one(&self.pool)
                .await?;
                row.try_into()
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn update_signal_group(&self, group: &SignalGroup) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE signal_groups SET
                derived_confidence = $2,
                source_count = $3,
                status = $4,
                corroboration_met = $5,
                primary_dimensions = $6,
                playbook_name = COALESCE($7, playbook_name)
            WHERE group_id = $1
            "#,
        )
        .bind(group.group_id)
        .bind(group.derived_confidence)
        .bind(group.source_count)
        .bind(group.status.as_str())
        .bind(group.corroboration_met)
        .bind(serde_json::to_value(&group.primary_dimensions).unwrap_or(serde_json::json!({})))
        .bind(group.playbook_name.as_deref())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_signal_group(&self, group_id: Uuid) -> Result<Option<SignalGroup>> {
        let row = sqlx::query_as::<_, SignalGroupRow>(
            r#"
            SELECT group_id, victim_ip, vector, created_at, window_expires_at,
                   derived_confidence, source_count, status, corroboration_met,
                   primary_dimensions, playbook_name
            FROM signal_groups WHERE group_id = $1
            "#,
        )
        .bind(group_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(TryInto::try_into).transpose()
    }

    async fn find_open_group(&self, victim_ip: &str, vector: &str) -> Result<Option<SignalGroup>> {
        let row = sqlx::query_as::<_, SignalGroupRow>(
            r#"
            SELECT group_id, victim_ip, vector, created_at, window_expires_at,
                   derived_confidence, source_count, status, corroboration_met,
                   primary_dimensions, playbook_name
            FROM signal_groups
            WHERE victim_ip = $1 AND vector = $2 AND status = 'open'
              AND window_expires_at > NOW()
            LIMIT 1
            "#,
        )
        .bind(victim_ip)
        .bind(vector)
        .fetch_optional(&self.pool)
        .await?;
        row.map(TryInto::try_into).transpose()
    }

    async fn add_event_to_group(
        &self,
        group_id: Uuid,
        event_id: Uuid,
        source_weight: f32,
    ) -> Result<bool> {
        let result = sqlx::query(
            r#"
            INSERT INTO signal_group_events (group_id, event_id, source_weight, is_corroborating)
            VALUES ($1, $2, $3, false)
            ON CONFLICT (group_id, event_id) DO NOTHING
            "#,
        )
        .bind(group_id)
        .bind(event_id)
        .bind(source_weight)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_signal_group_events(&self, group_id: Uuid) -> Result<Vec<SignalGroupEvent>> {
        // For primary rows, source/confidence/ingested_at come from the events table.
        // For corroborator rows (is_corroborating=true), event_id is the corroborator's
        // signal_id and the denormalized columns on signal_group_events provide the data.
        let rows = sqlx::query_as::<_, SignalGroupEventRow>(
            r#"
            SELECT sge.group_id, sge.event_id, sge.source_weight, sge.is_corroborating,
                   CASE
                       WHEN sge.is_corroborating THEN sge.corroborator_source
                       ELSE e.source
                   END AS source,
                   CASE
                       WHEN sge.is_corroborating THEN sge.corroborator_confidence
                       ELSE e.confidence
                   END AS confidence,
                   CASE
                       WHEN sge.is_corroborating THEN sge.corroborator_ingested_at
                       ELSE e.ingested_at
                   END AS ingested_at
            FROM signal_group_events sge
            LEFT JOIN events e ON e.event_id = sge.event_id
            WHERE sge.group_id = $1
            ORDER BY
                CASE
                    WHEN sge.is_corroborating THEN sge.corroborator_ingested_at
                    ELSE e.ingested_at
                END ASC NULLS LAST
            "#,
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn list_signal_groups(
        &self,
        filter: &SignalGroupFilter,
        params: &ListParams,
    ) -> Result<Vec<SignalGroup>> {
        let status_str = filter.status.map(|s| s.as_str().to_string());
        let rows = sqlx::query_as::<_, SignalGroupRow>(
            r#"
            SELECT group_id, victim_ip, vector, created_at, window_expires_at,
                   derived_confidence, source_count, status, corroboration_met,
                   primary_dimensions, playbook_name
            FROM signal_groups
            WHERE ($1::text IS NULL OR status = $1)
              AND ($2::text IS NULL OR vector = $2)
              AND ($3::timestamptz IS NULL OR created_at >= $3)
              AND ($4::timestamptz IS NULL OR created_at < $4)
              AND ($5::timestamptz IS NULL OR (created_at, group_id) < ($5, $7))
            ORDER BY created_at DESC, group_id DESC
            LIMIT $6
            "#,
        )
        .bind(status_str.as_deref()) // $1
        .bind(filter.vector.as_deref()) // $2
        .bind(filter.start) // $3
        .bind(filter.end) // $4
        .bind(params.cursor.map(|c| c.timestamp)) // $5
        .bind(params.limit as i64) // $6
        .bind(params.cursor.map(|c| c.id)) // $7
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn count_open_groups(&self) -> Result<u32> {
        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM signal_groups WHERE status = 'open'")
                .fetch_one(&self.pool)
                .await?;
        Ok(row.0 as u32)
    }

    async fn find_expired_signal_groups(&self) -> Result<Vec<SignalGroup>> {
        let rows: Vec<SignalGroupRow> = sqlx::query_as(
            r#"
            SELECT group_id, victim_ip, vector, created_at, window_expires_at,
                   derived_confidence, source_count, status, corroboration_met,
                   primary_dimensions, playbook_name
            FROM signal_groups
            WHERE status = 'open' AND window_expires_at <= NOW()
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn list_open_signal_groups(&self) -> Result<Vec<SignalGroup>> {
        let rows: Vec<SignalGroupRow> = sqlx::query_as(
            r#"
            SELECT group_id, victim_ip, vector, created_at, window_expires_at,
                   derived_confidence, source_count, status, corroboration_met,
                   primary_dimensions, playbook_name
            FROM signal_groups
            WHERE status = 'open'
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn find_open_groups_by_dimensions(
        &self,
        vector: &Option<String>,
        dims: &EventDimensions,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<SignalGroup>> {
        let customers: Vec<String> = dims.customer_ids.iter().cloned().collect();
        let pops: Vec<String> = dims.pops.iter().cloned().collect();
        let services: Vec<String> = dims.service_ids.iter().cloned().collect();
        let interfaces: Vec<String> = dims.interfaces.iter().cloned().collect();

        // Use ?| (JSONB has-any-keys) is not safe for arbitrary values. We
        // fetch candidates via simple filter (vector + status + window) and
        // do the dimension overlap in Rust. Signal groups are a bounded set
        // (usually <100 open at a time), so this is fine.
        let rows: Vec<SignalGroupRow> = sqlx::query_as(
            r#"
            SELECT group_id, victim_ip, vector, created_at, window_expires_at,
                   derived_confidence, source_count, status, corroboration_met,
                   primary_dimensions, playbook_name
            FROM signal_groups
            WHERE status = 'open'
              AND window_expires_at > $1
              AND ($2::text IS NULL OR vector = $2)
            "#,
        )
        .bind(now)
        .bind(vector.as_deref())
        .fetch_all(&self.pool)
        .await?;

        let probe = EventDimensions {
            customer_ids: customers.iter().cloned().collect(),
            pops: pops.iter().cloned().collect(),
            service_ids: services.iter().cloned().collect(),
            interfaces: interfaces.iter().cloned().collect(),
        };

        // Corrupt SQL-selected candidates fail before dimension matching; never invent dimensions.
        let groups: Vec<SignalGroup> = rows
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<_>>()?;
        Ok(groups
            .into_iter()
            .filter(|g| g.primary_dimensions.matches_probe(&probe))
            .collect())
    }

    async fn find_mitigation_id_by_signal_group(
        &self,
        signal_group_id: Uuid,
    ) -> Result<Option<Uuid>> {
        let row: Option<(Uuid,)> = sqlx::query_as(
            "SELECT mitigation_id FROM mitigations WHERE signal_group_id = $1 LIMIT 1",
        )
        .bind(signal_group_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.0))
    }

    // Corroborating signals (ADR 021)

    async fn add_corroborator_event_to_group(
        &self,
        group_id: Uuid,
        signal: &CorroboratingSignal,
    ) -> Result<bool> {
        let result = sqlx::query(
            r#"
            INSERT INTO signal_group_events (
                group_id, event_id, source_weight, is_corroborating,
                corroborator_signal_id, corroborator_source, corroborator_confidence,
                corroborator_ingested_at
            )
            VALUES ($1, $2, $3, true, $2, $4, $5, $6)
            ON CONFLICT (group_id, event_id) DO NOTHING
            "#,
        )
        .bind(group_id)
        .bind(signal.signal_id)
        .bind(signal.weight)
        .bind(&signal.source)
        .bind(signal.confidence)
        .bind(signal.ingested_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn group_has_primary_event(&self, group_id: Uuid) -> Result<bool> {
        let row: (bool,) = sqlx::query_as(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM signal_group_events
                WHERE group_id = $1 AND is_corroborating = false
            )
            "#,
        )
        .bind(group_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0)
    }

    async fn insert_corroborating_signal(&self, signal: &CorroboratingSignal) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO corroborating_signals (
                signal_id, source, vector, customer_id, pop, service_id, interface,
                confidence, weight, ingested_at, expires_at, raw_details, attached_group_ids
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            "#,
        )
        .bind(signal.signal_id)
        .bind(&signal.source)
        .bind(signal.vector.as_deref())
        .bind(signal.customer_id.as_deref())
        .bind(signal.pop.as_deref())
        .bind(signal.service_id.as_deref())
        .bind(signal.interface.as_deref())
        .bind(signal.confidence)
        .bind(signal.weight)
        .bind(signal.ingested_at)
        .bind(signal.expires_at)
        .bind(signal.raw_details.clone())
        .bind(&signal.attached_group_ids)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn find_matching_corroborators(
        &self,
        vector: &str,
        dims: &EventDimensions,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<CorroboratingSignal>> {
        // Pull all unexpired, unattached-to-this-group candidates matching the
        // vector filter (or with no vector filter), then apply the dimension
        // OR-match in Rust to keep the SQL predicate tractable.
        let customers: Vec<String> = dims.customer_ids.iter().cloned().collect();
        let pops: Vec<String> = dims.pops.iter().cloned().collect();
        let services: Vec<String> = dims.service_ids.iter().cloned().collect();
        let interfaces: Vec<String> = dims.interfaces.iter().cloned().collect();

        let rows: Vec<CorroboratingSignalRow> = sqlx::query_as(
            r#"
            SELECT signal_id, source, vector, customer_id, pop, service_id, interface,
                   confidence, weight, ingested_at, expires_at, raw_details, attached_group_ids
            FROM corroborating_signals
            WHERE expires_at > $1
              AND (vector IS NULL OR vector = $2)
              AND (
                   (customer_id IS NOT NULL AND customer_id = ANY($3))
                OR (pop IS NOT NULL AND pop = ANY($4))
                OR (service_id IS NOT NULL AND service_id = ANY($5))
                OR (interface IS NOT NULL AND interface = ANY($6))
              )
            "#,
        )
        .bind(now)
        .bind(vector)
        .bind(&customers)
        .bind(&pops)
        .bind(&services)
        .bind(&interfaces)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn mark_corroborator_attached(&self, signal_id: Uuid, group_id: Uuid) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE corroborating_signals
            SET attached_group_ids =
                CASE WHEN $2 = ANY(attached_group_ids) THEN attached_group_ids
                     ELSE array_append(attached_group_ids, $2) END
            WHERE signal_id = $1
            "#,
        )
        .bind(signal_id)
        .bind(group_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delete_expired_corroborating_signals(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<crate::db::traits::CorroboratorSweepStats> {
        // Two statements: one DELETE-RETURNING grouped by source for
        // per-source attribution on the expired metric; another for
        // attached rows (no source attribution — they aren't cache misses).
        let unattached_rows: Vec<(String, i64)> = sqlx::query_as(
            r#"
            WITH deleted AS (
                DELETE FROM corroborating_signals
                WHERE expires_at <= $1
                  AND cardinality(attached_group_ids) = 0
                RETURNING source
            )
            SELECT source, COUNT(*)::BIGINT AS n FROM deleted GROUP BY source
            "#,
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await?;
        let attached: (i64,) = sqlx::query_as(
            r#"
            WITH deleted AS (
                DELETE FROM corroborating_signals
                WHERE expires_at <= $1
                  AND cardinality(attached_group_ids) > 0
                RETURNING signal_id
            )
            SELECT COUNT(*) FROM deleted
            "#,
        )
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        let unattached_expired = unattached_rows
            .into_iter()
            .map(|(source, n)| (source, n.max(0) as u64))
            .collect();
        Ok(crate::db::traits::CorroboratorSweepStats {
            unattached_expired,
            attached_expired: attached.0.max(0) as u64,
        })
    }

    async fn count_cached_corroborators(&self, now: chrono::DateTime<chrono::Utc>) -> Result<u64> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM corroborating_signals WHERE expires_at > $1 AND cardinality(attached_group_ids) = 0",
        )
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0.max(0) as u64)
    }

    async fn list_cached_corroborators(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        limit: i64,
        source: Option<&str>,
    ) -> Result<Vec<CorroboratingSignal>> {
        let rows: Vec<CorroboratingSignalRow> = sqlx::query_as(
            r#"
            SELECT signal_id, source, vector, customer_id, pop, service_id, interface,
                   confidence, weight, ingested_at, expires_at, raw_details, attached_group_ids
            FROM corroborating_signals
            WHERE expires_at > $1
              AND cardinality(attached_group_ids) = 0
              AND ($3::text IS NULL OR source = $3)
            ORDER BY ingested_at DESC
            LIMIT $2
            "#,
        )
        .bind(now)
        .bind(limit.max(0))
        .bind(source)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn count_cached_corroborators_by_source(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<(String, u64)>> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            r#"
            SELECT source, COUNT(*)::BIGINT AS n
            FROM corroborating_signals
            WHERE expires_at > $1
              AND cardinality(attached_group_ids) = 0
            GROUP BY source
            "#,
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(source, n)| (source, n.max(0) as u64))
            .collect())
    }

    async fn corroborator_source_activity(
        &self,
        since: DateTime<Utc>,
    ) -> Result<Vec<crate::db::traits::CorroboratorSourceActivity>> {
        // Union the live cache (`corroborating_signals`) with attached
        // corroborator rows on signal groups (`signal_group_events WHERE
        // is_corroborating`). A signal that both attached *and* remains in
        // the cache for late fan-out is counted once per table; the
        // dashboard treats this as "activity volume" rather than "distinct
        // signals", which is accurate enough for a health indicator.
        let rows: Vec<(String, crate::db::CheckedTimestamp, i64)> = sqlx::query_as(
            r#"
            SELECT source,
                   MAX(ingested_at) AS last_seen,
                   COUNT(*)         AS n
            FROM (
                SELECT source, ingested_at
                FROM corroborating_signals
                WHERE ingested_at >= $1
                UNION ALL
                SELECT corroborator_source        AS source,
                       corroborator_ingested_at  AS ingested_at
                FROM signal_group_events
                WHERE is_corroborating = true
                  AND corroborator_source IS NOT NULL
                  AND corroborator_ingested_at IS NOT NULL
                  AND corroborator_ingested_at >= $1
            ) AS combined
            GROUP BY source
            "#,
        )
        .bind(since)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(source, last_seen, n)| crate::db::traits::CorroboratorSourceActivity {
                    source,
                    last_seen: last_seen.into(),
                    count: n.max(0) as u64,
                },
            )
            .collect())
    }
}

#[derive(Debug, FromRow)]
struct CorroboratingSignalRow {
    signal_id: Uuid,
    source: String,
    vector: Option<String>,
    customer_id: Option<String>,
    pop: Option<String>,
    service_id: Option<String>,
    interface: Option<String>,
    confidence: Option<f32>,
    weight: f32,
    #[sqlx(try_from = "crate::db::CheckedTimestamp")]
    ingested_at: DateTime<Utc>,
    #[sqlx(try_from = "crate::db::CheckedTimestamp")]
    expires_at: DateTime<Utc>,
    raw_details: Option<serde_json::Value>,
    attached_group_ids: Vec<Uuid>,
}

impl From<CorroboratingSignalRow> for CorroboratingSignal {
    fn from(row: CorroboratingSignalRow) -> Self {
        Self {
            signal_id: row.signal_id,
            source: row.source,
            vector: row.vector,
            customer_id: row.customer_id,
            pop: row.pop,
            service_id: row.service_id,
            interface: row.interface,
            confidence: row.confidence,
            weight: row.weight,
            ingested_at: row.ingested_at,
            expires_at: row.expires_at,
            raw_details: row.raw_details,
            attached_group_ids: row.attached_group_ids,
        }
    }
}

// ── Signal group row types ─────────────────────────────────────────────

#[derive(Debug, FromRow)]
struct SignalGroupRow {
    group_id: Uuid,
    victim_ip: String,
    vector: String,
    #[sqlx(try_from = "crate::db::CheckedTimestamp")]
    created_at: DateTime<Utc>,
    #[sqlx(try_from = "crate::db::CheckedTimestamp")]
    window_expires_at: DateTime<Utc>,
    derived_confidence: f32,
    source_count: i32,
    status: String,
    corroboration_met: bool,
    primary_dimensions: serde_json::Value,
    playbook_name: Option<String>,
}

impl TryFrom<SignalGroupRow> for SignalGroup {
    type Error = PrefixdError;

    fn try_from(row: SignalGroupRow) -> Result<Self> {
        Ok(Self {
            group_id: row.group_id,
            victim_ip: row.victim_ip,
            vector: row.vector,
            created_at: row.created_at,
            window_expires_at: row.window_expires_at,
            derived_confidence: row.derived_confidence,
            source_count: row.source_count,
            status: row
                .status
                .parse()
                .map_err(|_| PrefixdError::Internal("invalid stored signal-group status".into()))?,
            corroboration_met: row.corroboration_met,
            primary_dimensions: serde_json::from_value(row.primary_dimensions)?,
            playbook_name: row.playbook_name,
        })
    }
}

#[derive(Debug, FromRow)]
struct SignalGroupEventRow {
    group_id: Uuid,
    event_id: Uuid,
    source_weight: f32,
    is_corroborating: bool,
    source: Option<String>,
    confidence: Option<f32>,
    #[sqlx(try_from = "crate::db::CheckedTimestamp")]
    ingested_at: Option<DateTime<Utc>>,
}

impl From<SignalGroupEventRow> for SignalGroupEvent {
    fn from(row: SignalGroupEventRow) -> Self {
        Self {
            group_id: row.group_id,
            event_id: row.event_id,
            source_weight: row.source_weight,
            is_corroborating: row.is_corroborating,
            source: row.source,
            confidence: row.confidence,
            ingested_at: row.ingested_at,
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct NotifPrefRow {
    muted_events: Vec<String>,
    quiet_hours_start: Option<i16>,
    quiet_hours_end: Option<i16>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct SafelistEntry {
    pub prefix: String,
    #[sqlx(try_from = "crate::db::CheckedTimestamp")]
    pub added_at: chrono::DateTime<Utc>,
    pub added_by: String,
    pub reason: Option<String>,
    #[sqlx(try_from = "crate::db::CheckedTimestamp")]
    pub expires_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct PopInfo {
    pub pop: String,
    pub active_mitigations: u32,
    pub total_mitigations: u32,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct GlobalStats {
    pub total_active: u32,
    pub total_mitigations: u32,
    pub total_events: u32,
    pub pops: Vec<PopStats>,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct PopStats {
    pub pop: String,
    pub active: u32,
    pub total: u32,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct TimeseriesBucket {
    #[sqlx(try_from = "crate::db::CheckedTimestamp")]
    pub bucket: DateTime<Utc>,
    pub count: i64,
}

#[derive(Debug, FromRow)]
struct OperatorRow {
    operator_id: Uuid,
    username: String,
    password_hash: String,
    role: String,
    #[sqlx(try_from = "crate::db::CheckedTimestamp")]
    created_at: DateTime<Utc>,
    created_by: Option<String>,
    #[sqlx(try_from = "crate::db::CheckedTimestamp")]
    last_login_at: Option<DateTime<Utc>>,
}

impl From<OperatorRow> for Operator {
    fn from(row: OperatorRow) -> Self {
        let role = row.role.parse().unwrap_or(OperatorRole::Operator);
        Self {
            operator_id: row.operator_id,
            username: row.username,
            password_hash: row.password_hash,
            role,
            created_at: row.created_at,
            created_by: row.created_by,
            last_login_at: row.last_login_at,
        }
    }
}

#[cfg(all(test, feature = "test-utils"))]
mod checked_timestamp_rows {
    use super::*;
    use chrono::{TimeZone, Timelike};
    use testcontainers::{ImageExt, runners::AsyncRunner};
    use testcontainers_modules::postgres::Postgres;

    // Exercise actual FromRow implementations, including rows private to this module.
    #[tokio::test]
    async fn every_owned_timestamp_row_checks_binary_values_and_preserves_valid_dates() {
        let container = Postgres::default()
            .with_tag("16-alpine")
            .with_startup_timeout(std::time::Duration::from_secs(60))
            .with_host_config_modifier(|config| {
                config.cpuset_cpus = std::env::var("PREFIXD_TEST_CPUSET").ok();
            })
            .start()
            .await
            .unwrap();
        let host = container.get_host().await.unwrap();
        let port = container.get_host_port_ipv4(5432).await.unwrap();
        let pool = PgPool::connect(&format!(
            "postgres://postgres:postgres@{host}:{port}/postgres"
        ))
        .await
        .unwrap();
        let valid = [
            "1969-12-31T23:59:59.123456Z"
                .parse::<DateTime<Utc>>()
                .unwrap(),
            Utc.with_ymd_and_hms(-4000, 1, 1, 0, 0, 0).single().unwrap(),
            DateTime::<Utc>::MAX_UTC
                .with_nanosecond(999_999_000)
                .unwrap(),
        ];
        macro_rules! check_row {
            ($row:ty, $base:expr, [$($required:ident),*], [$($optional:ident),*]) => {{
                let fields = [$(stringify!($required),)* $(stringify!($optional),)*];
                let query = format!("SELECT {}{}", $base,
                    fields.iter().map(|field| format!(", $1::timestamptz AS {field}")).collect::<String>());
                for expected in valid {
                    let row = sqlx::query_as::<_, $row>(&query).bind(expected).fetch_one(&pool).await.unwrap();
                    $(assert_eq!(row.$required, expected);)*
                    $(assert_eq!(row.$optional, Some(expected));)*
                }
                let required_fields: &[&str] = &[$(stringify!($required),)*];
                let optional_fields: &[&str] = &[$(stringify!($optional),)*];
                let null_query = format!("SELECT {}{}{}", $base,
                    required_fields.iter().map(|field| format!(", TIMESTAMPTZ '2000-01-01' AS {field}")).collect::<String>(),
                    optional_fields.iter().map(|field| format!(", NULL::timestamptz AS {field}")).collect::<String>());
                let row = sqlx::query_as::<_, $row>(&null_query).fetch_one(&pool).await.unwrap();
                $(assert!(row.$optional.is_none());)*
                let _ = row;
                for target in fields {
                    let query = format!("SELECT {}{}", $base,
                        fields.iter().map(|field| if *field == target {
                            format!(", $1::text::timestamptz AS {field}")
                        } else { format!(", TIMESTAMPTZ '2000-01-01' AS {field}") }).collect::<String>());
                    for bad in ["infinity", "-infinity", "280000-01-01 00:00:00+00"] {
                        let result = sqlx::query_as::<_, $row>(&query).bind(bad).fetch_one(&pool).await;
                        assert!(matches!(result, Err(sqlx::Error::ColumnDecode { .. })),
                            "{}.{target} accepted {bad}: {result:?}", stringify!($row));
                    }
                }
            }};
        }
        check_row!(
            AttackEvent,
            "gen_random_uuid() AS event_id, NULL::text AS external_event_id, 'test'::text AS source, '203.0.113.1'::text AS victim_ip, 'udp_flood'::text AS vector, 17::integer AS protocol, NULL::bigint AS bps, NULL::bigint AS pps, '[]'::text AS top_dst_ports_json, NULL::text AS top_src_ports_json, NULL::real AS confidence, 'ban'::text AS action, NULL::jsonb AS raw_details",
            [event_timestamp, ingested_at],
            []
        );
        check_row!(
            MitigationRow,
            "gen_random_uuid() AS mitigation_id, 'scope'::text AS scope_hash, 'test'::text AS pop, NULL::text AS customer_id, NULL::text AS service_id, '203.0.113.1'::text AS victim_ip, 'udp_flood'::text AS vector, '{}'::text AS match_json, 'discard'::text AS action_type, NULL::text AS action_params_json, 'active'::text AS status, gen_random_uuid() AS triggering_event_id, gen_random_uuid() AS last_event_id, NULL::uuid AS escalated_from_id, NULL::text AS reason, NULL::text AS rejection_reason, NULL::text AS acknowledged_by, NULL::uuid AS signal_group_id, NULL::text AS origin_mode",
            [created_at, updated_at, expires_at],
            [withdrawn_at, acknowledged_at]
        );
        check_row!(
            WithdrawalRequest,
            "gen_random_uuid() AS operation_id, gen_random_uuid() AS mitigation_id, 'test'::text AS pop, 'hash'::text AS nlri_hash, 'flowspec'::text AS rule_kind, '{}'::text AS rule_json, 'withdrawn'::text AS terminal_status, true AS speaker_delete_required, 'system'::text AS actor_type, 'test'::text AS actor, 'test'::text AS reason, NULL::uuid AS target_id",
            [mitigation_updated_at, requested_at],
            [completed_at]
        );
        check_row!(
            AuditRow,
            "gen_random_uuid() AS audit_id, 1::integer AS schema_version, 'system'::text AS actor_type, NULL::text AS actor_id, 'test'::text AS action, NULL::text AS target_type, NULL::text AS target_id, '{}'::text AS details_json",
            [timestamp],
            []
        );
        check_row!(
            CorroboratingSignalRow,
            "gen_random_uuid() AS signal_id, 'test'::text AS source, NULL::text AS vector, NULL::text AS customer_id, NULL::text AS pop, NULL::text AS service_id, NULL::text AS interface, NULL::real AS confidence, 1::real AS weight, NULL::jsonb AS raw_details, '{}'::uuid[] AS attached_group_ids",
            [ingested_at, expires_at],
            []
        );
        check_row!(
            SignalGroupRow,
            "gen_random_uuid() AS group_id, '203.0.113.1'::text AS victim_ip, 'udp_flood'::text AS vector, 0.5::real AS derived_confidence, 1::integer AS source_count, 'open'::text AS status, false AS corroboration_met, '{}'::jsonb AS primary_dimensions, NULL::text AS playbook_name",
            [created_at, window_expires_at],
            []
        );
        check_row!(
            SignalGroupEventRow,
            "gen_random_uuid() AS group_id, gen_random_uuid() AS event_id, 1::real AS source_weight, true AS is_corroborating, 'test'::text AS source, NULL::real AS confidence",
            [],
            [ingested_at]
        );
        check_row!(
            SafelistEntry,
            "'203.0.113.1/32'::text AS prefix, 'test'::text AS added_by, NULL::text AS reason",
            [added_at],
            [expires_at]
        );
        check_row!(TimeseriesBucket, "0::bigint AS count", [bucket], []);
        check_row!(
            OperatorRow,
            "gen_random_uuid() AS operator_id, 'test'::text AS username, 'hash'::text AS password_hash, 'admin'::text AS role, NULL::text AS created_by",
            [created_at],
            [last_login_at]
        );
        // The MAX tuple is a separate Decode surface from the derived rows.
        let tuple: (String, crate::db::CheckedTimestamp, i64) = sqlx::query_as(
            "SELECT 'source'::text, MAX(ts), 1::bigint FROM (VALUES ($1::timestamptz)) AS input(ts)")
            .bind(valid[0]).fetch_one(&pool).await.unwrap();
        assert_eq!(Option::<DateTime<Utc>>::from(tuple.1), Some(valid[0]));
        let tuple: (String, crate::db::CheckedTimestamp, i64) = sqlx::query_as(
            "SELECT 'source'::text, MAX(ts), 0::bigint FROM (VALUES (NULL::timestamptz)) AS input(ts)")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(Option::<DateTime<Utc>>::from(tuple.1), None);
        let row = sqlx::raw_sql("SELECT TIMESTAMPTZ '1969-12-31 23:59:59.123456+00' AS ts")
            .fetch_one(&pool)
            .await
            .unwrap();
        let checked: crate::db::CheckedTimestamp = sqlx::Row::try_get(&row, "ts").unwrap();
        assert_eq!(DateTime::<Utc>::try_from(checked).unwrap(), valid[0]);
        for bad in ["infinity", "-infinity", "280000-01-01 00:00:00+00"] {
            let row = sqlx::raw_sql(&format!("SELECT TIMESTAMPTZ '{bad}' AS ts"))
                .fetch_one(&pool)
                .await
                .unwrap();
            let result: std::result::Result<crate::db::CheckedTimestamp, _> =
                sqlx::Row::try_get(&row, "ts");
            assert!(matches!(result, Err(sqlx::Error::ColumnDecode { .. })));
        }
        for bad in ["infinity", "-infinity", "280000-01-01 00:00:00+00"] {
            let result = sqlx::query_as::<_, (String, crate::db::CheckedTimestamp, i64)>(
                "SELECT 'source'::text, MAX(ts), 1::bigint FROM (VALUES ($1::text::timestamptz)) AS input(ts)")
                .bind(bad).fetch_one(&pool).await;
            assert!(matches!(result, Err(sqlx::Error::ColumnDecode { .. })));
        }
        pool.close().await;
        container.rm().await.unwrap();
    }
}
