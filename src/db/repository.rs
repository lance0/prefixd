use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::domain::{AttackEvent, Mitigation, MitigationRow, MitigationStatus};
use crate::error::Result;

#[derive(Clone)]
pub struct Repository {
    pool: SqlitePool,
}

impl Repository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    // Events

    pub async fn insert_event(&self, event: &AttackEvent) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO events (
                event_id, external_event_id, source, event_timestamp, ingested_at,
                victim_ip, vector, protocol, bps, pps, top_dst_ports_json, confidence
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
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
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn find_event_by_external_id(
        &self,
        source: &str,
        external_id: &str,
    ) -> Result<Option<AttackEvent>> {
        let event = sqlx::query_as::<_, AttackEvent>(
            r#"
            SELECT event_id, external_event_id, source, event_timestamp, ingested_at,
                   victim_ip, vector, protocol, bps, pps, top_dst_ports_json, confidence
            FROM events WHERE source = $1 AND external_event_id = $2
            "#,
        )
        .bind(source)
        .bind(external_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(event)
    }

    // Mitigations

    pub async fn insert_mitigation(&self, m: &Mitigation) -> Result<()> {
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

    pub async fn update_mitigation(&self, m: &Mitigation) -> Result<()> {
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

    pub async fn get_mitigation(&self, id: Uuid) -> Result<Option<Mitigation>> {
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

        Ok(row.map(Mitigation::from_row))
    }

    pub async fn find_active_by_scope(&self, scope_hash: &str, pop: &str) -> Result<Option<Mitigation>> {
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

        Ok(row.map(Mitigation::from_row))
    }

    pub async fn find_active_by_victim(&self, victim_ip: &str) -> Result<Vec<Mitigation>> {
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

        Ok(rows.into_iter().map(Mitigation::from_row).collect())
    }

    pub async fn list_mitigations(
        &self,
        status_filter: Option<&[MitigationStatus]>,
        customer_id: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Mitigation>> {
        let mut query = String::from(
            r#"
            SELECT mitigation_id, scope_hash, pop, customer_id, service_id, victim_ip, vector,
                   match_json, action_type, action_params_json, status,
                   created_at, updated_at, expires_at, withdrawn_at,
                   triggering_event_id, last_event_id, escalated_from_id, reason, rejection_reason
            FROM mitigations WHERE 1=1
            "#,
        );

        if let Some(statuses) = status_filter {
            let placeholders: Vec<_> = statuses.iter().map(|s| format!("'{}'", s.as_str())).collect();
            query.push_str(&format!(" AND status IN ({})", placeholders.join(",")));
        }

        if let Some(cid) = customer_id {
            query.push_str(&format!(" AND customer_id = '{}'", cid));
        }

        query.push_str(&format!(" ORDER BY created_at DESC LIMIT {} OFFSET {}", limit, offset));

        let rows = sqlx::query_as::<_, MitigationRow>(&query)
            .fetch_all(&self.pool)
            .await?;

        Ok(rows.into_iter().map(Mitigation::from_row).collect())
    }

    pub async fn count_active_by_customer(&self, customer_id: &str) -> Result<u32> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM mitigations WHERE customer_id = $1 AND status IN ('pending', 'active', 'escalated')",
        )
        .bind(customer_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row.0 as u32)
    }

    pub async fn count_active_by_pop(&self, pop: &str) -> Result<u32> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM mitigations WHERE pop = $1 AND status IN ('pending', 'active', 'escalated')",
        )
        .bind(pop)
        .fetch_one(&self.pool)
        .await?;

        Ok(row.0 as u32)
    }

    pub async fn count_active_global(&self) -> Result<u32> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM mitigations WHERE status IN ('pending', 'active', 'escalated')",
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(row.0 as u32)
    }

    pub async fn find_expired_mitigations(&self) -> Result<Vec<Mitigation>> {
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

        Ok(rows.into_iter().map(Mitigation::from_row).collect())
    }

    // Safelist

    pub async fn insert_safelist(&self, prefix: &str, added_by: &str, reason: Option<&str>) -> Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO safelist (prefix, added_at, added_by, reason) VALUES ($1, $2, $3, $4)",
        )
        .bind(prefix)
        .bind(Utc::now())
        .bind(added_by)
        .bind(reason)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn remove_safelist(&self, prefix: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM safelist WHERE prefix = $1")
            .bind(prefix)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn list_safelist(&self) -> Result<Vec<SafelistEntry>> {
        let rows = sqlx::query_as::<_, SafelistEntry>(
            "SELECT prefix, added_at, added_by, reason, expires_at FROM safelist",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    pub async fn is_safelisted(&self, ip: &str) -> Result<bool> {
        use ipnet::Ipv4Net;
        use std::net::Ipv4Addr;
        use std::str::FromStr;

        let entries = self.list_safelist().await?;
        let ip_addr = match Ipv4Addr::from_str(ip) {
            Ok(addr) => addr,
            Err(_) => return Ok(false),
        };

        for entry in entries {
            if let Ok(prefix) = Ipv4Net::from_str(&entry.prefix) {
                if prefix.contains(&ip_addr) {
                    return Ok(true);
                }
            } else if entry.prefix == ip {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

use serde::Serialize;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct SafelistEntry {
    pub prefix: String,
    pub added_at: chrono::DateTime<Utc>,
    pub added_by: String,
    pub reason: Option<String>,
    pub expires_at: Option<chrono::DateTime<Utc>>,
}
