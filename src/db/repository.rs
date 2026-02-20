use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use super::RepositoryTrait;
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

    async fn list_events(&self, limit: u32, offset: u32) -> Result<Vec<AttackEvent>> {
        let events = sqlx::query_as::<_, AttackEvent>(
            r#"
            SELECT event_id, external_event_id, source, event_timestamp, ingested_at,
                   victim_ip, vector, protocol, bps, pps, top_dst_ports_json, confidence,
                   action, raw_details
            FROM events ORDER BY ingested_at DESC LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit as i64)
        .bind(offset as i64)
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

    async fn list_audit(&self, limit: u32, offset: u32) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query_as::<_, AuditRow>(
            r#"
            SELECT audit_id, timestamp, schema_version, actor_type, actor_id, action, target_type, target_id, details_json
            FROM audit_log ORDER BY timestamp DESC LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit as i64)
        .bind(offset as i64)
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
                triggering_event_id, last_event_id, escalated_from_id, reason, rejection_reason
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
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
                   triggering_event_id, last_event_id, escalated_from_id, reason, rejection_reason
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
                   triggering_event_id, last_event_id, escalated_from_id, reason, rejection_reason
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
                   triggering_event_id, last_event_id, escalated_from_id, reason, rejection_reason
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
                   triggering_event_id, last_event_id, escalated_from_id, reason, rejection_reason
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
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Mitigation>> {
        // Convert status filter to string array for parameterized query
        let status_strings: Option<Vec<String>> =
            status_filter.map(|statuses| statuses.iter().map(|s| s.as_str().to_string()).collect());

        let rows = sqlx::query_as::<_, MitigationRow>(
            r#"
            SELECT mitigation_id, scope_hash, pop, customer_id, service_id, victim_ip, vector,
                   match_json, action_type, action_params_json, status,
                   created_at, updated_at, expires_at, withdrawn_at,
                   triggering_event_id, last_event_id, escalated_from_id, reason, rejection_reason
            FROM mitigations
            WHERE ($1::text[] IS NULL OR status = ANY($1))
              AND ($2::text IS NULL OR customer_id = $2)
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(status_strings.as_deref())
        .bind(customer_id)
        .bind(limit as i64)
        .bind(offset as i64)
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
                   triggering_event_id, last_event_id, escalated_from_id, reason, rejection_reason
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
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Mitigation>> {
        // Convert status filter to string array for parameterized query
        let status_strings: Option<Vec<String>> =
            status_filter.map(|statuses| statuses.iter().map(|s| s.as_str().to_string()).collect());

        let rows = sqlx::query_as::<_, MitigationRow>(
            r#"
            SELECT mitigation_id, scope_hash, pop, customer_id, service_id, victim_ip, vector,
                   match_json, action_type, action_params_json, status,
                   created_at, updated_at, expires_at, withdrawn_at,
                   triggering_event_id, last_event_id, escalated_from_id, reason, rejection_reason
            FROM mitigations
            WHERE ($1::text[] IS NULL OR status = ANY($1))
              AND ($2::text IS NULL OR customer_id = $2)
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(status_strings.as_deref())
        .bind(customer_id)
        .bind(limit as i64)
        .bind(offset as i64)
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
    async fn timeseries_mitigations(&self, range_hours: u32, bucket_minutes: u32) -> Result<Vec<TimeseriesBucket>> {
        let range_interval = format!("{} hours", range_hours);
        let bucket_interval = format!("{} minutes", bucket_minutes);
        let rows = sqlx::query_as::<_, TimeseriesBucket>(
            r#"
            SELECT gs AS bucket, COALESCE(c.count, 0) AS count
            FROM generate_series(
                date_trunc('hour', NOW() - $1::interval),
                NOW(),
                $2::interval
            ) gs
            LEFT JOIN (
                SELECT date_trunc('hour', created_at) AS bucket, COUNT(*)::bigint AS count
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

    async fn timeseries_events(&self, range_hours: u32, bucket_minutes: u32) -> Result<Vec<TimeseriesBucket>> {
        let range_interval = format!("{} hours", range_hours);
        let bucket_interval = format!("{} minutes", bucket_minutes);
        let rows = sqlx::query_as::<_, TimeseriesBucket>(
            r#"
            SELECT gs AS bucket, COALESCE(c.count, 0) AS count
            FROM generate_series(
                date_trunc('hour', NOW() - $1::interval),
                NOW(),
                $2::interval
            ) gs
            LEFT JOIN (
                SELECT date_trunc('hour', ingested_at) AS bucket, COUNT(*)::bigint AS count
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
                   triggering_event_id, last_event_id, escalated_from_id, reason, rejection_reason
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
