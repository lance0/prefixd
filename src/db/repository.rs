use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use super::{ListParams, NotificationPreferences, RepositoryTrait};
use crate::correlation::engine::{
    CorroboratingSignal, EventDimensions, SignalGroup, SignalGroupEvent, SignalGroupFilter,
    SignalGroupStatus,
};
use crate::domain::{
    AttackEvent, Mitigation, MitigationRow, MitigationStatus, Operator, OperatorRole,
};
use crate::error::Result;
use crate::observability::{ActorType, AuditEntry, metrics::ROW_PARSE_ERRORS};

#[derive(Debug, FromRow)]
struct AuditRow {
    audit_id: Uuid,
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
    fn from_row(row: AuditRow) -> Self {
        let actor_type = match row.actor_type.as_str() {
            "operator" => ActorType::Operator,
            "detector" => ActorType::Detector,
            _ => ActorType::System,
        };
        Self {
            audit_id: row.audit_id,
            timestamp: row.timestamp,
            schema_version: row.schema_version as u32,
            actor_type,
            actor_id: row.actor_id,
            action: row.action,
            target_type: row.target_type,
            target_id: row.target_id,
            details: serde_json::from_str(&row.details_json).unwrap_or(serde_json::json!({})),
        }
    }
}

#[derive(Clone)]
pub struct Repository {
    pool: PgPool,
}

impl Repository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RepositoryTrait for Repository {
    async fn insert_event(&self, event: &AttackEvent) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO events (
                event_id, external_event_id, source, event_timestamp, ingested_at,
                victim_ip, vector, protocol, bps, pps, top_dst_ports_json, confidence,
                action, raw_details
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
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
                   victim_ip, vector, protocol, bps, pps, top_dst_ports_json, confidence,
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

    async fn list_events(&self, params: &ListParams) -> Result<Vec<AttackEvent>> {
        let events = sqlx::query_as::<_, AttackEvent>(
            r#"
            SELECT event_id, external_event_id, source, event_timestamp, ingested_at,
                   victim_ip, vector, protocol, bps, pps, top_dst_ports_json, confidence,
                   action, raw_details
            FROM events
            WHERE ($2::timestamptz IS NULL OR ingested_at < $2)
              AND ($3::timestamptz IS NULL OR ingested_at >= $3)
              AND ($4::timestamptz IS NULL OR ingested_at < $4)
            ORDER BY ingested_at DESC LIMIT $1
            "#,
        )
        .bind(params.limit as i64)
        .bind(params.cursor)
        .bind(params.start)
        .bind(params.end)
        .fetch_all(&self.pool)
        .await?;
        Ok(events)
    }

    async fn insert_audit(&self, entry: &AuditEntry) -> Result<()> {
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
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_audit(&self, params: &ListParams) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query_as::<_, AuditRow>(
            r#"
            SELECT audit_id, timestamp, schema_version, actor_type, actor_id, action, target_type, target_id, details_json
            FROM audit_log
            WHERE ($2::timestamptz IS NULL OR timestamp < $2)
              AND ($3::timestamptz IS NULL OR timestamp >= $3)
              AND ($4::timestamptz IS NULL OR timestamp < $4)
            ORDER BY timestamp DESC LIMIT $1
            "#,
        )
        .bind(params.limit as i64)
        .bind(params.cursor)
        .bind(params.start)
        .bind(params.end)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(AuditEntry::from_row).collect())
    }

    async fn insert_mitigation(&self, m: &Mitigation) -> Result<()> {
        let match_json = serde_json::to_string(&m.match_criteria)?;
        let action_params_json = serde_json::to_string(&m.action_params)?;

        sqlx::query(
            r#"
            INSERT INTO mitigations (
                mitigation_id, scope_hash, pop, customer_id, service_id, victim_ip, vector,
                match_json, action_type, action_params_json, status,
                created_at, updated_at, expires_at, withdrawn_at,
                triggering_event_id, last_event_id, escalated_from_id, reason, rejection_reason,
                signal_group_id
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
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
        .execute(&self.pool)
        .await?;
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

    async fn get_mitigation(&self, id: Uuid) -> Result<Option<Mitigation>> {
        let row = sqlx::query_as::<_, MitigationRow>(
            r#"
            SELECT mitigation_id, scope_hash, pop, customer_id, service_id, victim_ip, vector,
                   match_json, action_type, action_params_json, status,
                   created_at, updated_at, expires_at, withdrawn_at,
                   triggering_event_id, last_event_id, escalated_from_id, reason, rejection_reason,
                   acknowledged_at, acknowledged_by, signal_group_id
            FROM mitigations WHERE mitigation_id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
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
                   acknowledged_at, acknowledged_by, signal_group_id
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

    async fn find_active_by_victim(&self, victim_ip: &str) -> Result<Vec<Mitigation>> {
        let rows = sqlx::query_as::<_, MitigationRow>(
            r#"
            SELECT mitigation_id, scope_hash, pop, customer_id, service_id, victim_ip, vector,
                   match_json, action_type, action_params_json, status,
                   created_at, updated_at, expires_at, withdrawn_at,
                   triggering_event_id, last_event_id, escalated_from_id, reason, rejection_reason,
                   acknowledged_at, acknowledged_by, signal_group_id
            FROM mitigations
            WHERE victim_ip = $1 AND status IN ('pending', 'active', 'escalated')
            "#,
        )
        .bind(victim_ip)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .filter_map(|row| match Mitigation::from_row(row) {
                Ok(m) => Some(m),
                Err(e) => {
                    ROW_PARSE_ERRORS.with_label_values(&["mitigations"]).inc();
                    tracing::error!(error = %e, "skipping corrupted mitigation row");
                    None
                }
            })
            .collect())
    }

    async fn find_active_by_triggering_event(&self, event_id: Uuid) -> Result<Option<Mitigation>> {
        let row = sqlx::query_as::<_, MitigationRow>(
            r#"
            SELECT mitigation_id, scope_hash, pop, customer_id, service_id, victim_ip, vector,
                   match_json, action_type, action_params_json, status,
                   created_at, updated_at, expires_at, withdrawn_at,
                   triggering_event_id, last_event_id, escalated_from_id, reason, rejection_reason,
                   acknowledged_at, acknowledged_by, signal_group_id
            FROM mitigations
            WHERE triggering_event_id = $1 AND status IN ('pending', 'active', 'escalated')
            "#,
        )
        .bind(event_id)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(r) => Ok(Some(Mitigation::from_row(r)?)),
            None => Ok(None),
        }
    }

    async fn list_mitigations(
        &self,
        status_filter: Option<&[MitigationStatus]>,
        customer_id: Option<&str>,
        victim_ip: Option<&str>,
        acknowledged: Option<bool>,
        params: &ListParams,
    ) -> Result<Vec<Mitigation>> {
        let status_strings: Option<Vec<String>> =
            status_filter.map(|statuses| statuses.iter().map(|s| s.as_str().to_string()).collect());

        let rows = sqlx::query_as::<_, MitigationRow>(
            r#"
            SELECT mitigation_id, scope_hash, pop, customer_id, service_id, victim_ip, vector,
                   match_json, action_type, action_params_json, status,
                   created_at, updated_at, expires_at, withdrawn_at,
                   triggering_event_id, last_event_id, escalated_from_id, reason, rejection_reason,
                   acknowledged_at, acknowledged_by, signal_group_id
            FROM mitigations
            WHERE ($1::text[] IS NULL OR status = ANY($1))
              AND ($2::text IS NULL OR customer_id = $2)
              AND ($3::text IS NULL OR victim_ip = $3)
              AND ($4::timestamptz IS NULL OR created_at < $4)
              AND ($5::timestamptz IS NULL OR created_at >= $5)
              AND ($6::timestamptz IS NULL OR created_at < $6)
              AND ($7::bool IS NULL OR ($7 = true AND acknowledged_at IS NOT NULL) OR ($7 = false AND acknowledged_at IS NULL))
            ORDER BY created_at DESC
            LIMIT $8
            "#,
        )
        .bind(status_strings.as_deref())  // $1
        .bind(customer_id)                 // $2
        .bind(victim_ip)                   // $3
        .bind(params.cursor)               // $4
        .bind(params.start)                // $5
        .bind(params.end)                  // $6
        .bind(acknowledged)                // $7
        .bind(params.limit as i64)         // $8
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .filter_map(|row| match Mitigation::from_row(row) {
                Ok(m) => Some(m),
                Err(e) => {
                    ROW_PARSE_ERRORS.with_label_values(&["mitigations"]).inc();
                    tracing::error!(error = %e, "skipping corrupted mitigation row");
                    None
                }
            })
            .collect())
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

    async fn find_expired_mitigations(&self) -> Result<Vec<Mitigation>> {
        let now = Utc::now();
        let rows = sqlx::query_as::<_, MitigationRow>(
            r#"
            SELECT mitigation_id, scope_hash, pop, customer_id, service_id, victim_ip, vector,
                   match_json, action_type, action_params_json, status,
                   created_at, updated_at, expires_at, withdrawn_at,
                   triggering_event_id, last_event_id, escalated_from_id, reason, rejection_reason,
                   acknowledged_at, acknowledged_by, signal_group_id
            FROM mitigations
            WHERE status IN ('active', 'escalated') AND expires_at < $1
            "#,
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .filter_map(|row| match Mitigation::from_row(row) {
                Ok(m) => Some(m),
                Err(e) => {
                    ROW_PARSE_ERRORS.with_label_values(&["mitigations"]).inc();
                    tracing::error!(error = %e, "skipping corrupted mitigation row");
                    None
                }
            })
            .collect())
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

    async fn is_safelisted(&self, ip: &str) -> Result<bool> {
        // Use PostgreSQL inet operators for efficient CIDR matching
        // This avoids loading all entries and leverages database indexes
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM safelist
            WHERE $1::inet <<= prefix::inet
               OR prefix = $1
            "#,
        )
        .bind(ip)
        .fetch_one(&self.pool)
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

    async fn list_mitigations_all_pops(
        &self,
        status_filter: Option<&[MitigationStatus]>,
        customer_id: Option<&str>,
        victim_ip: Option<&str>,
        acknowledged: Option<bool>,
        params: &ListParams,
    ) -> Result<Vec<Mitigation>> {
        let status_strings: Option<Vec<String>> =
            status_filter.map(|statuses| statuses.iter().map(|s| s.as_str().to_string()).collect());

        let rows = sqlx::query_as::<_, MitigationRow>(
            r#"
            SELECT mitigation_id, scope_hash, pop, customer_id, service_id, victim_ip, vector,
                   match_json, action_type, action_params_json, status,
                   created_at, updated_at, expires_at, withdrawn_at,
                   triggering_event_id, last_event_id, escalated_from_id, reason, rejection_reason,
                   acknowledged_at, acknowledged_by, signal_group_id
            FROM mitigations
            WHERE ($1::text[] IS NULL OR status = ANY($1))
              AND ($2::text IS NULL OR customer_id = $2)
              AND ($3::text IS NULL OR victim_ip = $3)
              AND ($4::timestamptz IS NULL OR created_at < $4)
              AND ($5::timestamptz IS NULL OR created_at >= $5)
              AND ($6::timestamptz IS NULL OR created_at < $6)
              AND ($7::bool IS NULL OR ($7 = true AND acknowledged_at IS NOT NULL) OR ($7 = false AND acknowledged_at IS NULL))
            ORDER BY created_at DESC
            LIMIT $8
            "#,
        )
        .bind(status_strings.as_deref())  // $1
        .bind(customer_id)                 // $2
        .bind(victim_ip)                   // $3
        .bind(params.cursor)               // $4
        .bind(params.start)                // $5
        .bind(params.end)                  // $6
        .bind(acknowledged)                // $7
        .bind(params.limit as i64)         // $8
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .filter_map(|row| match Mitigation::from_row(row) {
                Ok(m) => Some(m),
                Err(e) => {
                    ROW_PARSE_ERRORS.with_label_values(&["mitigations"]).inc();
                    tracing::error!(error = %e, "skipping corrupted mitigation row");
                    None
                }
            })
            .collect())
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
                   victim_ip, vector, protocol, bps, pps, top_dst_ports_json, confidence,
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
                   acknowledged_at, acknowledged_by, signal_group_id
            FROM mitigations WHERE victim_ip = $1 ORDER BY created_at DESC LIMIT $2
            "#,
        )
        .bind(ip)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .filter_map(|row| match Mitigation::from_row(row) {
                Ok(m) => Some(m),
                Err(e) => {
                    ROW_PARSE_ERRORS.with_label_values(&["mitigations"]).inc();
                    tracing::error!(error = %e, "skipping corrupted mitigation row");
                    None
                }
            })
            .collect())
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
                       primary_dimensions
                FROM signal_groups
                WHERE victim_ip = $2 AND vector = $3 AND status = 'open'
                  AND window_expires_at > NOW()
                LIMIT 1
            ), inserted AS (
                INSERT INTO signal_groups (group_id, victim_ip, vector, created_at, window_expires_at,
                    derived_confidence, source_count, status, corroboration_met, primary_dimensions)
                SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
                WHERE NOT EXISTS (SELECT 1 FROM existing)
                RETURNING group_id, victim_ip, vector, created_at, window_expires_at,
                    derived_confidence, source_count, status, corroboration_met, primary_dimensions
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
        .fetch_one(&self.pool)
        .await;

        match result {
            Ok(row) => Ok(row.into()),
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
                           primary_dimensions
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
                Ok(row.into())
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
                primary_dimensions = $6
            WHERE group_id = $1
            "#,
        )
        .bind(group.group_id)
        .bind(group.derived_confidence)
        .bind(group.source_count)
        .bind(group.status.as_str())
        .bind(group.corroboration_met)
        .bind(serde_json::to_value(&group.primary_dimensions).unwrap_or(serde_json::json!({})))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_signal_group(&self, group_id: Uuid) -> Result<Option<SignalGroup>> {
        let row = sqlx::query_as::<_, SignalGroupRow>(
            r#"
            SELECT group_id, victim_ip, vector, created_at, window_expires_at,
                   derived_confidence, source_count, status, corroboration_met,
                   primary_dimensions
            FROM signal_groups WHERE group_id = $1
            "#,
        )
        .bind(group_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    async fn find_open_group(&self, victim_ip: &str, vector: &str) -> Result<Option<SignalGroup>> {
        let row = sqlx::query_as::<_, SignalGroupRow>(
            r#"
            SELECT group_id, victim_ip, vector, created_at, window_expires_at,
                   derived_confidence, source_count, status, corroboration_met,
                   primary_dimensions
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
        Ok(row.map(Into::into))
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
                   primary_dimensions
            FROM signal_groups
            WHERE ($1::text IS NULL OR status = $1)
              AND ($2::text IS NULL OR vector = $2)
              AND ($3::timestamptz IS NULL OR created_at >= $3)
              AND ($4::timestamptz IS NULL OR created_at < $4)
              AND ($5::timestamptz IS NULL OR created_at < $5)
            ORDER BY created_at DESC
            LIMIT $6
            "#,
        )
        .bind(status_str.as_deref()) // $1
        .bind(filter.vector.as_deref()) // $2
        .bind(filter.start) // $3
        .bind(filter.end) // $4
        .bind(params.cursor) // $5
        .bind(params.limit as i64) // $6
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
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
                   primary_dimensions
            FROM signal_groups
            WHERE status = 'open' AND window_expires_at <= NOW()
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
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
                   primary_dimensions
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

        Ok(rows
            .into_iter()
            .map(SignalGroup::from)
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
        // Two statements so the scheduler can attribute the expired metric
        // to truly-unattached signals (cache misses) while still cleaning
        // attached audit rows. Both run inside the same request round-trip
        // order but we don't need a transaction: the counters are
        // monotonic and the delete predicate is narrow.
        let unattached: (i64,) = sqlx::query_as(
            r#"
            WITH deleted AS (
                DELETE FROM corroborating_signals
                WHERE expires_at <= $1
                  AND cardinality(attached_group_ids) = 0
                RETURNING signal_id
            )
            SELECT COUNT(*) FROM deleted
            "#,
        )
        .bind(now)
        .fetch_one(&self.pool)
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
        Ok(crate::db::traits::CorroboratorSweepStats {
            unattached_expired: unattached.0.max(0) as u64,
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
    ) -> Result<Vec<CorroboratingSignal>> {
        let rows: Vec<CorroboratingSignalRow> = sqlx::query_as(
            r#"
            SELECT signal_id, source, vector, customer_id, pop, service_id, interface,
                   confidence, weight, ingested_at, expires_at, raw_details, attached_group_ids
            FROM corroborating_signals
            WHERE expires_at > $1
              AND cardinality(attached_group_ids) = 0
            ORDER BY ingested_at DESC
            LIMIT $2
            "#,
        )
        .bind(now)
        .bind(limit.max(0))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
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
        let rows: Vec<(String, Option<DateTime<Utc>>, i64)> = sqlx::query_as(
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
                    last_seen,
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
    ingested_at: DateTime<Utc>,
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
    created_at: DateTime<Utc>,
    window_expires_at: DateTime<Utc>,
    derived_confidence: f32,
    source_count: i32,
    status: String,
    corroboration_met: bool,
    primary_dimensions: serde_json::Value,
}

impl From<SignalGroupRow> for SignalGroup {
    fn from(row: SignalGroupRow) -> Self {
        Self {
            group_id: row.group_id,
            victim_ip: row.victim_ip,
            vector: row.vector,
            created_at: row.created_at,
            window_expires_at: row.window_expires_at,
            derived_confidence: row.derived_confidence,
            source_count: row.source_count,
            status: row.status.parse().unwrap_or(SignalGroupStatus::Open),
            corroboration_met: row.corroboration_met,
            primary_dimensions: serde_json::from_value(row.primary_dimensions).unwrap_or_default(),
        }
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
    pub added_at: chrono::DateTime<Utc>,
    pub added_by: String,
    pub reason: Option<String>,
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
    pub bucket: DateTime<Utc>,
    pub count: i64,
}

#[derive(Debug, FromRow)]
struct OperatorRow {
    operator_id: Uuid,
    username: String,
    password_hash: String,
    role: String,
    created_at: DateTime<Utc>,
    created_by: Option<String>,
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
