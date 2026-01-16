use chrono::Utc;
use sqlx::{PgPool, SqlitePool};
use uuid::Uuid;

use super::DbPool;
use crate::domain::{AttackEvent, Mitigation, MitigationRow, MitigationStatus};
use crate::error::Result;

#[derive(Clone)]
pub struct Repository {
    pool: DbPool,
}

impl Repository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub fn from_sqlite(pool: SqlitePool) -> Self {
        Self { pool: DbPool::Sqlite(pool) }
    }

    pub fn from_postgres(pool: PgPool) -> Self {
        Self { pool: DbPool::Postgres(pool) }
    }

    // Events

    pub async fn insert_event(&self, event: &AttackEvent) -> Result<()> {
        match &self.pool {
            DbPool::Sqlite(pool) => insert_event_sqlite(pool, event).await,
            DbPool::Postgres(pool) => insert_event_postgres(pool, event).await,
        }
    }

    pub async fn find_event_by_external_id(
        &self,
        source: &str,
        external_id: &str,
    ) -> Result<Option<AttackEvent>> {
        match &self.pool {
            DbPool::Sqlite(pool) => find_event_by_external_id_sqlite(pool, source, external_id).await,
            DbPool::Postgres(pool) => find_event_by_external_id_postgres(pool, source, external_id).await,
        }
    }

    // Mitigations

    pub async fn insert_mitigation(&self, m: &Mitigation) -> Result<()> {
        match &self.pool {
            DbPool::Sqlite(pool) => insert_mitigation_sqlite(pool, m).await,
            DbPool::Postgres(pool) => insert_mitigation_postgres(pool, m).await,
        }
    }

    pub async fn update_mitigation(&self, m: &Mitigation) -> Result<()> {
        match &self.pool {
            DbPool::Sqlite(pool) => update_mitigation_sqlite(pool, m).await,
            DbPool::Postgres(pool) => update_mitigation_postgres(pool, m).await,
        }
    }

    pub async fn get_mitigation(&self, id: Uuid) -> Result<Option<Mitigation>> {
        match &self.pool {
            DbPool::Sqlite(pool) => get_mitigation_sqlite(pool, id).await,
            DbPool::Postgres(pool) => get_mitigation_postgres(pool, id).await,
        }
    }

    pub async fn find_active_by_scope(&self, scope_hash: &str, pop: &str) -> Result<Option<Mitigation>> {
        match &self.pool {
            DbPool::Sqlite(pool) => find_active_by_scope_sqlite(pool, scope_hash, pop).await,
            DbPool::Postgres(pool) => find_active_by_scope_postgres(pool, scope_hash, pop).await,
        }
    }

    pub async fn find_active_by_victim(&self, victim_ip: &str) -> Result<Vec<Mitigation>> {
        match &self.pool {
            DbPool::Sqlite(pool) => find_active_by_victim_sqlite(pool, victim_ip).await,
            DbPool::Postgres(pool) => find_active_by_victim_postgres(pool, victim_ip).await,
        }
    }

    pub async fn list_mitigations(
        &self,
        status_filter: Option<&[MitigationStatus]>,
        customer_id: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Mitigation>> {
        match &self.pool {
            DbPool::Sqlite(pool) => {
                list_mitigations_sqlite(pool, status_filter, customer_id, limit, offset).await
            }
            DbPool::Postgres(pool) => {
                list_mitigations_postgres(pool, status_filter, customer_id, limit, offset).await
            }
        }
    }

    pub async fn count_active_by_customer(&self, customer_id: &str) -> Result<u32> {
        match &self.pool {
            DbPool::Sqlite(pool) => count_active_by_customer_sqlite(pool, customer_id).await,
            DbPool::Postgres(pool) => count_active_by_customer_postgres(pool, customer_id).await,
        }
    }

    pub async fn count_active_by_pop(&self, pop: &str) -> Result<u32> {
        match &self.pool {
            DbPool::Sqlite(pool) => count_active_by_pop_sqlite(pool, pop).await,
            DbPool::Postgres(pool) => count_active_by_pop_postgres(pool, pop).await,
        }
    }

    pub async fn count_active_global(&self) -> Result<u32> {
        match &self.pool {
            DbPool::Sqlite(pool) => count_active_global_sqlite(pool).await,
            DbPool::Postgres(pool) => count_active_global_postgres(pool).await,
        }
    }

    pub async fn find_expired_mitigations(&self) -> Result<Vec<Mitigation>> {
        match &self.pool {
            DbPool::Sqlite(pool) => find_expired_mitigations_sqlite(pool).await,
            DbPool::Postgres(pool) => find_expired_mitigations_postgres(pool).await,
        }
    }

    // Safelist

    pub async fn insert_safelist(&self, prefix: &str, added_by: &str, reason: Option<&str>) -> Result<()> {
        match &self.pool {
            DbPool::Sqlite(pool) => insert_safelist_sqlite(pool, prefix, added_by, reason).await,
            DbPool::Postgres(pool) => insert_safelist_postgres(pool, prefix, added_by, reason).await,
        }
    }

    pub async fn remove_safelist(&self, prefix: &str) -> Result<bool> {
        match &self.pool {
            DbPool::Sqlite(pool) => remove_safelist_sqlite(pool, prefix).await,
            DbPool::Postgres(pool) => remove_safelist_postgres(pool, prefix).await,
        }
    }

    pub async fn list_safelist(&self) -> Result<Vec<SafelistEntry>> {
        match &self.pool {
            DbPool::Sqlite(pool) => list_safelist_sqlite(pool).await,
            DbPool::Postgres(pool) => list_safelist_postgres(pool).await,
        }
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

    // Multi-POP coordination

    /// List all distinct POPs that have mitigations
    pub async fn list_pops(&self) -> Result<Vec<PopInfo>> {
        match &self.pool {
            DbPool::Sqlite(pool) => list_pops_sqlite(pool).await,
            DbPool::Postgres(pool) => list_pops_postgres(pool).await,
        }
    }

    /// Get aggregate stats across all POPs
    pub async fn get_stats(&self) -> Result<GlobalStats> {
        match &self.pool {
            DbPool::Sqlite(pool) => get_stats_sqlite(pool).await,
            DbPool::Postgres(pool) => get_stats_postgres(pool).await,
        }
    }

    /// List mitigations across all POPs (no POP filter)
    pub async fn list_mitigations_all_pops(
        &self,
        status_filter: Option<&[MitigationStatus]>,
        customer_id: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Mitigation>> {
        match &self.pool {
            DbPool::Sqlite(pool) => {
                list_mitigations_all_pops_sqlite(pool, status_filter, customer_id, limit, offset).await
            }
            DbPool::Postgres(pool) => {
                list_mitigations_all_pops_postgres(pool, status_filter, customer_id, limit, offset).await
            }
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct PopInfo {
    /// POP identifier
    pub pop: String,
    /// Number of active mitigations in this POP
    pub active_mitigations: u32,
    /// Total mitigations (all statuses) in this POP
    pub total_mitigations: u32,
}

#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct GlobalStats {
    /// Total active mitigations across all POPs
    pub total_active: u32,
    /// Total mitigations across all POPs
    pub total_mitigations: u32,
    /// Total events ingested
    pub total_events: u32,
    /// Per-POP breakdown
    pub pops: Vec<PopStats>,
}

#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct PopStats {
    /// POP identifier
    pub pop: String,
    /// Active mitigations
    pub active: u32,
    /// Total mitigations
    pub total: u32,
}

// ============================================================================
// SQLite implementations
// ============================================================================

async fn insert_event_sqlite(pool: &SqlitePool, event: &AttackEvent) -> Result<()> {
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
    .execute(pool)
    .await?;
    Ok(())
}

async fn find_event_by_external_id_sqlite(
    pool: &SqlitePool,
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
    .fetch_optional(pool)
    .await?;
    Ok(event)
}

async fn insert_mitigation_sqlite(pool: &SqlitePool, m: &Mitigation) -> Result<()> {
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
    .execute(pool)
    .await?;
    Ok(())
}

async fn update_mitigation_sqlite(pool: &SqlitePool, m: &Mitigation) -> Result<()> {
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
    .execute(pool)
    .await?;
    Ok(())
}

async fn get_mitigation_sqlite(pool: &SqlitePool, id: Uuid) -> Result<Option<Mitigation>> {
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
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Mitigation::from_row))
}

async fn find_active_by_scope_sqlite(
    pool: &SqlitePool,
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
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Mitigation::from_row))
}

async fn find_active_by_victim_sqlite(pool: &SqlitePool, victim_ip: &str) -> Result<Vec<Mitigation>> {
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
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Mitigation::from_row).collect())
}

async fn list_mitigations_sqlite(
    pool: &SqlitePool,
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
        .fetch_all(pool)
        .await?;

    Ok(rows.into_iter().map(Mitigation::from_row).collect())
}

async fn count_active_by_customer_sqlite(pool: &SqlitePool, customer_id: &str) -> Result<u32> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM mitigations WHERE customer_id = $1 AND status IN ('pending', 'active', 'escalated')",
    )
    .bind(customer_id)
    .fetch_one(pool)
    .await?;
    Ok(row.0 as u32)
}

async fn count_active_by_pop_sqlite(pool: &SqlitePool, pop: &str) -> Result<u32> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM mitigations WHERE pop = $1 AND status IN ('pending', 'active', 'escalated')",
    )
    .bind(pop)
    .fetch_one(pool)
    .await?;
    Ok(row.0 as u32)
}

async fn count_active_global_sqlite(pool: &SqlitePool) -> Result<u32> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM mitigations WHERE status IN ('pending', 'active', 'escalated')",
    )
    .fetch_one(pool)
    .await?;
    Ok(row.0 as u32)
}

async fn find_expired_mitigations_sqlite(pool: &SqlitePool) -> Result<Vec<Mitigation>> {
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
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Mitigation::from_row).collect())
}

async fn insert_safelist_sqlite(
    pool: &SqlitePool,
    prefix: &str,
    added_by: &str,
    reason: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "INSERT OR REPLACE INTO safelist (prefix, added_at, added_by, reason) VALUES ($1, $2, $3, $4)",
    )
    .bind(prefix)
    .bind(Utc::now())
    .bind(added_by)
    .bind(reason)
    .execute(pool)
    .await?;
    Ok(())
}

async fn remove_safelist_sqlite(pool: &SqlitePool, prefix: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM safelist WHERE prefix = $1")
        .bind(prefix)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

async fn list_safelist_sqlite(pool: &SqlitePool) -> Result<Vec<SafelistEntry>> {
    let rows = sqlx::query_as::<_, SafelistEntry>(
        "SELECT prefix, added_at, added_by, reason, expires_at FROM safelist",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

async fn list_pops_sqlite(pool: &SqlitePool) -> Result<Vec<PopInfo>> {
    let rows = sqlx::query_as::<_, (String, i64, i64)>(
        r#"
        SELECT pop,
               SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active,
               COUNT(*) as total
        FROM mitigations
        GROUP BY pop
        ORDER BY pop
        "#,
    )
    .fetch_all(pool)
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

async fn get_stats_sqlite(pool: &SqlitePool) -> Result<GlobalStats> {
    let (total_active, total_mitigations): (i64, i64) = sqlx::query_as(
        r#"
        SELECT
            SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END),
            COUNT(*)
        FROM mitigations
        "#,
    )
    .fetch_one(pool)
    .await?;

    let total_events: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM events")
        .fetch_one(pool)
        .await?;

    let pop_rows = sqlx::query_as::<_, (String, i64, i64)>(
        r#"
        SELECT pop,
               SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active,
               COUNT(*) as total
        FROM mitigations
        GROUP BY pop
        "#,
    )
    .fetch_all(pool)
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

async fn list_mitigations_all_pops_sqlite(
    pool: &SqlitePool,
    status_filter: Option<&[MitigationStatus]>,
    customer_id: Option<&str>,
    limit: u32,
    offset: u32,
) -> Result<Vec<Mitigation>> {
    let mut query = String::from(
        r#"
        SELECT mitigation_id, scope_hash, customer_id, service_id, victim_ip,
               status, action, dst_prefix, protocol, dst_ports_json,
               announced_at, expires_at, withdrawn_at, withdraw_reason, pop, escalation_level
        FROM mitigations WHERE 1=1
        "#,
    );

    if status_filter.is_some() {
        query.push_str(" AND status IN (SELECT value FROM json_each($1))");
    }
    if customer_id.is_some() {
        query.push_str(" AND customer_id = $2");
    }
    query.push_str(" ORDER BY announced_at DESC LIMIT $3 OFFSET $4");

    let status_json = status_filter.map(|s| {
        serde_json::to_string(&s.iter().map(|st| st.as_str()).collect::<Vec<_>>()).unwrap()
    });

    let rows = sqlx::query_as::<_, MitigationRow>(&query)
        .bind(&status_json)
        .bind(customer_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

    Ok(rows.into_iter().map(Mitigation::from_row).collect())
}

// ============================================================================
// PostgreSQL implementations
// ============================================================================

async fn insert_event_postgres(pool: &PgPool, event: &AttackEvent) -> Result<()> {
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
    .bind(event.protocol.map(|p| p as i32))
    .bind(event.bps.map(|b| b as i64))
    .bind(event.pps.map(|p| p as i64))
    .bind(&event.top_dst_ports_json)
    .bind(event.confidence)
    .execute(pool)
    .await?;
    Ok(())
}

async fn find_event_by_external_id_postgres(
    pool: &PgPool,
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
    .fetch_optional(pool)
    .await?;
    Ok(event)
}

async fn insert_mitigation_postgres(pool: &PgPool, m: &Mitigation) -> Result<()> {
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
    .execute(pool)
    .await?;
    Ok(())
}

async fn update_mitigation_postgres(pool: &PgPool, m: &Mitigation) -> Result<()> {
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
    .execute(pool)
    .await?;
    Ok(())
}

async fn get_mitigation_postgres(pool: &PgPool, id: Uuid) -> Result<Option<Mitigation>> {
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
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Mitigation::from_row))
}

async fn find_active_by_scope_postgres(
    pool: &PgPool,
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
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Mitigation::from_row))
}

async fn find_active_by_victim_postgres(pool: &PgPool, victim_ip: &str) -> Result<Vec<Mitigation>> {
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
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Mitigation::from_row).collect())
}

async fn list_mitigations_postgres(
    pool: &PgPool,
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
        .fetch_all(pool)
        .await?;

    Ok(rows.into_iter().map(Mitigation::from_row).collect())
}

async fn count_active_by_customer_postgres(pool: &PgPool, customer_id: &str) -> Result<u32> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM mitigations WHERE customer_id = $1 AND status IN ('pending', 'active', 'escalated')",
    )
    .bind(customer_id)
    .fetch_one(pool)
    .await?;
    Ok(row.0 as u32)
}

async fn count_active_by_pop_postgres(pool: &PgPool, pop: &str) -> Result<u32> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM mitigations WHERE pop = $1 AND status IN ('pending', 'active', 'escalated')",
    )
    .bind(pop)
    .fetch_one(pool)
    .await?;
    Ok(row.0 as u32)
}

async fn count_active_global_postgres(pool: &PgPool) -> Result<u32> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM mitigations WHERE status IN ('pending', 'active', 'escalated')",
    )
    .fetch_one(pool)
    .await?;
    Ok(row.0 as u32)
}

async fn find_expired_mitigations_postgres(pool: &PgPool) -> Result<Vec<Mitigation>> {
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
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Mitigation::from_row).collect())
}

async fn insert_safelist_postgres(
    pool: &PgPool,
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
    .execute(pool)
    .await?;
    Ok(())
}

async fn remove_safelist_postgres(pool: &PgPool, prefix: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM safelist WHERE prefix = $1")
        .bind(prefix)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

async fn list_safelist_postgres(pool: &PgPool) -> Result<Vec<SafelistEntry>> {
    let rows = sqlx::query_as::<_, SafelistEntry>(
        "SELECT prefix, added_at, added_by, reason, expires_at FROM safelist",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

async fn list_pops_postgres(pool: &PgPool) -> Result<Vec<PopInfo>> {
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
    .fetch_all(pool)
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

async fn get_stats_postgres(pool: &PgPool) -> Result<GlobalStats> {
    let (total_active, total_mitigations): (i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COALESCE(SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END), 0)::bigint,
            COUNT(*)::bigint
        FROM mitigations
        "#,
    )
    .fetch_one(pool)
    .await?;

    let total_events: (i64,) = sqlx::query_as("SELECT COUNT(*)::bigint FROM events")
        .fetch_one(pool)
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
    .fetch_all(pool)
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

async fn list_mitigations_all_pops_postgres(
    pool: &PgPool,
    status_filter: Option<&[MitigationStatus]>,
    customer_id: Option<&str>,
    limit: u32,
    offset: u32,
) -> Result<Vec<Mitigation>> {
    let status_strings: Option<Vec<String>> =
        status_filter.map(|s| s.iter().map(|st| st.as_str().to_string()).collect());

    let rows = sqlx::query_as::<_, MitigationRow>(
        r#"
        SELECT mitigation_id, scope_hash, customer_id, service_id, victim_ip,
               status, action, dst_prefix, protocol, dst_ports_json,
               announced_at, expires_at, withdrawn_at, withdraw_reason, pop, escalation_level
        FROM mitigations
        WHERE ($1::text[] IS NULL OR status = ANY($1))
          AND ($2::text IS NULL OR customer_id = $2)
        ORDER BY announced_at DESC
        LIMIT $3 OFFSET $4
        "#,
    )
    .bind(&status_strings)
    .bind(customer_id)
    .bind(limit as i64)
    .bind(offset as i64)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(Mitigation::from_row).collect())
}

// ============================================================================
// Types
// ============================================================================

use serde::Serialize;

#[derive(Debug, Clone, Serialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct SafelistEntry {
    /// IP prefix in CIDR notation
    pub prefix: String,
    /// When the entry was added
    pub added_at: chrono::DateTime<Utc>,
    /// Who added the entry
    pub added_by: String,
    /// Reason for safelisting
    pub reason: Option<String>,
    /// Optional expiration time
    pub expires_at: Option<chrono::DateTime<Utc>>,
}
