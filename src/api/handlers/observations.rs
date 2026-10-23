use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header, header::AUTHORIZATION},
    response::IntoResponse,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;
use crate::api::auth::{require_auth, require_role};
use crate::auth::AuthSession;
use crate::db::ListParams;
use crate::error::PrefixdError;

use super::{
    AppError, CursorQuery, ErrorResponse, MitigationResponse, clamp_limit, decode_list_cursor,
    encode_list_cursor, parse_date_range, validate_ip,
};

#[derive(Serialize, ToSchema)]
pub struct AuditListResponse {
    /// List of audit entries in this page
    entries: Vec<crate::observability::AuditEntry>,
    /// Number of entries returned in this page
    count: usize,
    /// Cursor for the next page (null if no more pages)
    next_cursor: Option<String>,
    /// Whether there are more pages
    has_more: bool,
}

/// List audit log entries
#[utoipa::path(
    get,
    path = "/v1/audit",
    tag = "audit",
    params(
        ("limit" = Option<u32>, Query, description = "Max results (default 100)"),
        ("cursor" = Option<String>, Query, description = "Opaque a1 continuation from next_cursor (max 128 bytes); superseded timestamp-only cursors are rejected"),
        ("start" = Option<String>, Query, description = "Inclusive RFC3339 start; empty or malformed supplied values are invalid"),
        ("end" = Option<String>, Query, description = "Exclusive RFC3339 end; empty or malformed supplied values are invalid"),
    ),
    responses(
        (status = 200, description = "List of audit log entries", body = AuditListResponse),
        (status = 400, description = "Invalid date filter or invalid/superseded audit cursor", body = ErrorResponse)
    )
)]
pub async fn list_audit(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Query(query): Query<CursorQuery>,
) -> Result<axum::response::Response, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    use crate::domain::OperatorRole;
    let _operator = require_role(&state, &auth_session, auth_header, OperatorRole::Operator)?;

    let limit = clamp_limit(query.limit.unwrap_or(100));
    let cursor = match query.cursor.as_deref() {
        None => None,
        Some(value) => match decode_list_cursor(value, "a1.") {
            Some(cursor) => Some(cursor),
            None => return Ok(AppError(PrefixdError::InvalidRequest(
                "invalid audit cursor; use next_cursor from a fresh audit listing (a1, at most 128 bytes)".into(),
            )).into_response()),
        },
    };
    let (start, end) = match parse_date_range(query.start.as_deref(), query.end.as_deref()) {
        Ok(bounds) => bounds,
        Err(error) => return Ok(AppError(error).into_response()),
    };
    let params = ListParams {
        limit: limit + 1,
        cursor,
        start,
        end,
    };

    let mut entries = state
        .repo
        .list_audit(&params)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let has_more = entries.len() > limit as usize;
    if has_more {
        entries.truncate(limit as usize);
    }
    let next_cursor = if has_more {
        entries
            .last()
            .map(|e| encode_list_cursor(e.timestamp, e.audit_id, "a1."))
    } else {
        None
    };
    let count = entries.len();
    Ok(Json(AuditListResponse {
        entries,
        count,
        next_cursor,
        has_more,
    })
    .into_response())
}

pub async fn metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    crate::observability::metrics::update_speaker_metrics(state.announcer.as_ref());
    if let Some(pool) = &state.db_pool {
        crate::observability::metrics::update_db_pool_metrics(pool);
    }
    crate::observability::gather_metrics()
}

// Multi-POP coordination

/// Get aggregate stats across all POPs
#[utoipa::path(
    get,
    path = "/v1/stats",
    tag = "multi-pop",
    responses(
        (status = 200, description = "Global statistics", body = crate::db::repository::GlobalStats)
    )
)]
pub async fn get_stats(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

    let stats = state
        .repo
        .get_stats()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(stats))
}

/// List all known POPs
#[utoipa::path(
    get,
    path = "/v1/pops",
    tag = "multi-pop",
    responses(
        (status = 200, description = "List of POPs", body = Vec<crate::db::repository::PopInfo>)
    )
)]
pub async fn list_pops(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

    let mut pops = state
        .repo
        .list_pops()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let current_pop = &state.settings.pop;
    if !pops.iter().any(|p| p.pop == *current_pop) {
        pops.push(crate::db::PopInfo {
            pop: current_pop.clone(),
            active_mitigations: 0,
            total_mitigations: 0,
        });
        pops.sort_by(|a, b| a.pop.cmp(&b.pop));
    }

    Ok(Json(pops))
}

// === Timeseries ===

#[derive(Deserialize)]
pub struct TimeseriesQuery {
    metric: Option<String>,
    range: Option<String>,
    bucket: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct TimeseriesResponse {
    pub metric: String,
    pub buckets: Vec<crate::db::TimeseriesBucket>,
}

fn parse_duration_hours(s: &str) -> Option<u32> {
    let s = s.trim();
    if let Some(h) = s.strip_suffix('h') {
        h.parse().ok()
    } else if let Some(d) = s.strip_suffix('d') {
        d.parse::<u32>().ok().map(|d| d.saturating_mul(24))
    } else {
        s.parse().ok()
    }
}

fn parse_duration_minutes(s: &str) -> Option<u32> {
    let s = s.trim();
    if let Some(m) = s.strip_suffix('m') {
        m.parse().ok()
    } else if let Some(h) = s.strip_suffix('h') {
        h.parse::<u32>().ok().map(|h| h.saturating_mul(60))
    } else {
        s.parse().ok()
    }
}

#[utoipa::path(
    get,
    path = "/v1/stats/timeseries",
    tag = "stats",
    params(
        ("metric" = Option<String>, Query, description = "Metric: mitigations or events (default: mitigations)"),
        ("range" = Option<String>, Query, description = "Time range, e.g. 24h, 7d (default: 24h)"),
        ("bucket" = Option<String>, Query, description = "Bucket size, e.g. 1h, 30m (default: 1h)"),
    ),
    responses(
        (status = 200, description = "Timeseries data", body = TimeseriesResponse)
    )
)]
pub async fn get_timeseries(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Query(query): Query<TimeseriesQuery>,
) -> Result<Json<TimeseriesResponse>, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

    let metric = query.metric.as_deref().unwrap_or("mitigations");
    let range_hours = query
        .range
        .as_deref()
        .and_then(parse_duration_hours)
        .unwrap_or(24)
        .min(168); // cap at 7 days
    let bucket_minutes = query
        .bucket
        .as_deref()
        .and_then(parse_duration_minutes)
        .unwrap_or(60)
        .max(5); // minimum 5 minute buckets

    let buckets = match metric {
        "events" => {
            state
                .repo
                .timeseries_events(range_hours, bucket_minutes)
                .await
        }
        _ => {
            state
                .repo
                .timeseries_mitigations(range_hours, bucket_minutes)
                .await
        }
    }
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(TimeseriesResponse {
        metric: metric.to_string(),
        buckets,
    }))
}

// === IP History ===

#[derive(Serialize, ToSchema)]
pub struct IpHistoryResponse {
    pub ip: String,
    pub customer: Option<serde_json::Value>,
    pub service: Option<serde_json::Value>,
    pub events: Vec<serde_json::Value>,
    pub mitigations: Vec<MitigationResponse>,
}

#[utoipa::path(
    get,
    path = "/v1/ip/{ip}/history",
    tag = "ip-history",
    params(
        ("ip" = String, Path, description = "IP address to look up"),
        ("limit" = Option<u32>, Query, description = "Max results per type (default 100)"),
    ),
    responses(
        (status = 200, description = "IP history", body = IpHistoryResponse)
    )
)]
pub async fn get_ip_history(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Path(ip): Path<String>,
    Query(query): Query<CursorQuery>,
) -> Result<Json<IpHistoryResponse>, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

    if ip.parse::<IpAddr>().is_err() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let limit = query.limit.unwrap_or(100).min(1000);

    let (events, mitigations) = tokio::try_join!(
        state.repo.list_events_by_ip(&ip, limit),
        state.repo.list_mitigations_by_ip(&ip, limit),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Inventory lookup for customer/service context
    let inventory = state.inventory.read().await;
    let mut customer_json = None;
    let mut service_json = None;
    'customer_search: for customer in &inventory.customers {
        for service in &customer.services {
            if service
                .assets
                .iter()
                .any(|asset| asset.ip.as_str() == ip.as_str())
            {
                customer_json = Some(serde_json::json!({
                    "customer_id": customer.customer_id,
                    "name": customer.name,
                    "policy_profile": format!("{:?}", customer.policy_profile).to_lowercase(),
                }));
                service_json = Some(serde_json::json!({
                    "service_id": service.service_id,
                    "name": service.name,
                }));
                break 'customer_search;
            }
        }
    }
    drop(inventory);

    let events_json: Vec<serde_json::Value> = events
        .iter()
        .map(|e| {
            serde_json::json!({
                "event_id": e.event_id,
                "source": e.source,
                "event_timestamp": e.event_timestamp,
                "ingested_at": e.ingested_at,
                "vector": e.vector,
                "bps": e.bps,
                "pps": e.pps,
                "confidence": e.confidence,
            })
        })
        .collect();

    let mitigation_responses: Vec<MitigationResponse> =
        mitigations.iter().map(MitigationResponse::from).collect();

    Ok(Json(IpHistoryResponse {
        ip,
        customer: customer_json,
        service: service_json,
        events: events_json,
        mitigations: mitigation_responses,
    }))
}

// --- Incident Report ---

#[derive(Deserialize)]
pub struct IncidentReportQuery {
    mitigation_id: Option<Uuid>,
    ip: Option<String>,
}

/// Generate a markdown incident report for a given IP or mitigation
#[utoipa::path(
    get,
    path = "/v1/reports/incident",
    tag = "reports",
    params(
        ("mitigation_id" = Option<String>, Query, description = "Mitigation ID; report uses its exact stored destination, including CIDRs"),
        ("ip" = Option<String>, Query, description = "Bare host IP address to generate report for; CIDRs require mitigation_id"),
    ),
    responses(
        (status = 200, description = "Markdown incident report", content_type = "text/markdown"),
        (status = 400, description = "Bad request — must provide exactly one of mitigation_id or ip"),
        (status = 401, description = "Not authenticated"),
        (status = 404, description = "Mitigation not found")
    )
)]
pub async fn generate_incident_report(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Query(query): Query<IncidentReportQuery>,
) -> impl IntoResponse {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    if let Err(status) = require_auth(&state, &auth_session, auth_header) {
        return (status, HeaderMap::new(), String::new()).into_response();
    }

    // Require exactly one of mitigation_id or ip
    let (ip, saved_owner) = match (query.mitigation_id, &query.ip) {
        (Some(mid), None) => {
            let mitigation = match state.repo.get_mitigation(mid).await {
                Ok(Some(m)) => m,
                Ok(None) => return StatusCode::NOT_FOUND.into_response(),
                Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            };
            (
                mitigation.victim_ip,
                Some((mitigation.customer_id, mitigation.service_id)),
            )
        }
        (None, Some(ip_str)) => {
            if validate_ip(ip_str).is_err() {
                return StatusCode::BAD_REQUEST.into_response();
            }
            (ip_str.clone(), None)
        }
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };

    let is_cidr = ip.contains('/');
    if (is_cidr && ip.parse::<ipnet::IpNet>().is_err()) || (!is_cidr && validate_ip(&ip).is_err()) {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // CIDRs select exact stored targets. Detector events remain host-only; do not
    // substitute the network address or imply an aggregate of addresses inside it.
    let (events, mitigations) = if is_cidr {
        match state.repo.list_mitigations_by_ip(&ip, 100).await {
            Ok(mitigations) => (Vec::new(), mitigations),
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    } else {
        match tokio::try_join!(
            state.repo.list_events_by_ip(&ip, 1000),
            state.repo.list_mitigations_by_ip(&ip, 100),
        ) {
            Ok(data) => data,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    };

    // Determine earliest timestamp across all events/mitigations for audit range
    let earliest: Option<DateTime<Utc>> = {
        let event_min = events.iter().map(|e| e.event_timestamp).min();
        let mit_min = mitigations.iter().map(|m| m.created_at).min();
        match (event_min, mit_min) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    };

    // Fetch audit entries
    let audit_params = crate::db::ListParams {
        limit: 1000,
        cursor: None,
        start: earliest,
        end: None,
    };
    let all_audit = match state.repo.list_audit(&audit_params).await {
        Ok(entries) => entries,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    // Build set of relevant IDs (mitigation IDs + event IDs) for filtering audit
    let relevant_ids: std::collections::HashSet<String> = {
        let mut ids = std::collections::HashSet::new();
        for m in &mitigations {
            ids.insert(m.mitigation_id.to_string());
        }
        for e in &events {
            ids.insert(e.event_id.to_string());
        }
        ids
    };

    let audit_entries: Vec<&crate::observability::AuditEntry> = all_audit
        .iter()
        .filter(|a| {
            a.target_id
                .as_ref()
                .is_some_and(|tid| relevant_ids.contains(tid))
        })
        .collect();

    // A CIDR's recorded owner is authoritative; its first address is not a
    // service lookup key. Host reports retain their exact-asset context.
    let inventory = state.inventory.read().await;
    let mut customer_name: Option<String> = None;
    let mut customer_id: Option<String> = None;
    let mut service_name: Option<String> = None;
    let mut service_id: Option<String> = None;
    if is_cidr {
        if let Some((saved_customer, saved_service)) = saved_owner {
            customer_id = saved_customer;
            service_id = saved_service;
            if let Some(customer) = inventory
                .customers
                .iter()
                .find(|c| Some(c.customer_id.as_str()) == customer_id.as_deref())
            {
                customer_name = Some(customer.name.clone());
                service_name = customer
                    .services
                    .iter()
                    .find(|service| Some(service.service_id.as_str()) == service_id.as_deref())
                    .map(|service| service.name.clone());
            }
        }
    } else {
        'customer_search: for customer in &inventory.customers {
            for service in &customer.services {
                if service.assets.iter().any(|asset| asset.ip == ip) {
                    customer_name = Some(customer.name.clone());
                    customer_id = Some(customer.customer_id.clone());
                    service_name = Some(service.name.clone());
                    service_id = Some(service.service_id.clone());
                    break 'customer_search;
                }
            }
        }
    }
    drop(inventory);

    // Compute derived fields
    let peak_bps: Option<i64> = events.iter().filter_map(|e| e.bps).max();
    let peak_pps: Option<i64> = events.iter().filter_map(|e| e.pps).max();

    let now = Utc::now();

    // Build timeline entries
    struct TimelineEntry {
        timestamp: DateTime<Utc>,
        kind: String,
        description: String,
    }

    let mut timeline: Vec<TimelineEntry> = Vec::new();

    for e in &events {
        timeline.push(TimelineEntry {
            timestamp: e.event_timestamp,
            kind: "Event".to_string(),
            description: format!(
                "Attack event `{}` — {} from source `{}`{}{}",
                e.event_id,
                e.vector,
                e.source,
                e.bps
                    .map(|b| format!(", {}", format_bps(b)))
                    .unwrap_or_default(),
                e.pps
                    .map(|p| format!(", {}", format_pps(p)))
                    .unwrap_or_default(),
            ),
        });
    }

    for m in &mitigations {
        timeline.push(TimelineEntry {
            timestamp: m.created_at,
            kind: "Mitigation".to_string(),
            description: format!(
                "Mitigation `{}` created — {} {} on `{}`",
                m.mitigation_id, m.action_type, m.vector, m.match_criteria.dst_prefix,
            ),
        });
        if let Some(withdrawn_at) = m.withdrawn_at {
            timeline.push(TimelineEntry {
                timestamp: withdrawn_at,
                kind: "Mitigation".to_string(),
                description: format!(
                    "Mitigation `{}` {} — {}",
                    m.mitigation_id, m.status, m.reason,
                ),
            });
        }
    }

    for a in &audit_entries {
        timeline.push(TimelineEntry {
            timestamp: a.timestamp,
            kind: "Audit".to_string(),
            description: format!(
                "`{}` by {}{}",
                a.action,
                a.actor_id.as_deref().unwrap_or("system"),
                a.target_id
                    .as_ref()
                    .map(|tid| format!(" on `{}`", tid))
                    .unwrap_or_default(),
            ),
        });
    }

    timeline.sort_by_key(|t| t.timestamp);

    // Build markdown
    let mut md = String::with_capacity(4096);

    md.push_str(&format!("# Incident Report — {}\n\n", ip));

    md.push_str(&format!("- **Generated**: {}\n", now.to_rfc3339()));
    if is_cidr {
        md.push_str("- **Scope**: exact destination CIDR. Individual host events and mitigations within this range are not aggregated.\n");
    }
    md.push_str("- **Evidence**: saved mitigation intent; router enforcement is unobserved.\n");
    if let Some(ref cid) = customer_id {
        md.push_str(&format!(
            "- **Customer**: {} (`{}`)\n",
            customer_name.as_deref().unwrap_or(cid),
            cid
        ));
    }
    if let Some(ref sid) = service_id {
        md.push_str(&format!(
            "- **Service**: {} (`{}`)\n",
            service_name.as_deref().unwrap_or(sid),
            sid
        ));
    }
    md.push('\n');

    // Summary table
    md.push_str("## Summary\n\n");
    md.push_str("| Metric | Value |\n");
    md.push_str("|--------|-------|\n");
    md.push_str(&format!("| Total Events | {} |\n", events.len()));
    md.push_str(&format!("| Total Mitigations | {} |\n", mitigations.len()));
    md.push_str(&format!(
        "| Active Mitigations | {} |\n",
        mitigations.iter().filter(|m| m.is_active()).count()
    ));
    if let Some(bps) = peak_bps {
        md.push_str(&format!("| Peak Traffic | {} |\n", format_bps(bps)));
    }
    if let Some(pps) = peak_pps {
        md.push_str(&format!("| Peak PPS | {} |\n", format_pps(pps)));
    }
    md.push('\n');

    // Timeline
    if !timeline.is_empty() {
        md.push_str("## Timeline\n\n");
        md.push_str("| Timestamp | Type | Description |\n");
        md.push_str("|-----------|------|-------------|\n");
        for entry in &timeline {
            md.push_str(&format!(
                "| {} | {} | {} |\n",
                entry.timestamp.to_rfc3339(),
                entry.kind,
                entry.description,
            ));
        }
        md.push('\n');
    }

    // Events table
    if !events.is_empty() {
        md.push_str("## Events\n\n");
        md.push_str("| Event ID | Timestamp | Source | Vector | BPS | PPS |\n");
        md.push_str("|----------|-----------|--------|--------|-----|-----|\n");
        for e in &events {
            md.push_str(&format!(
                "| `{}` | {} | {} | {} | {} | {} |\n",
                e.event_id,
                e.event_timestamp.to_rfc3339(),
                e.source,
                e.vector,
                e.bps.map(format_bps).unwrap_or_else(|| "—".to_string()),
                e.pps.map(format_pps).unwrap_or_else(|| "—".to_string()),
            ));
        }
        md.push('\n');
    }

    // Mitigations table
    if !mitigations.is_empty() {
        md.push_str("## Mitigations\n\n");
        md.push_str("| Mitigation ID | Status | Action | Vector | Prefix | Match | Expires (UTC) | Duration |\n");
        md.push_str("|---------------|--------|--------|--------|--------|-------|---------------|----------|\n");
        for m in &mitigations {
            let end_time = m.withdrawn_at.unwrap_or(m.expires_at).min(now);
            let duration_secs = (end_time - m.created_at).num_seconds().max(0);
            md.push_str(&format!(
                "| `{}` | {} | {} | {} | `{}` | {} | {} | {} |\n",
                m.mitigation_id,
                m.status,
                if m.action_type == crate::domain::ActionType::Police {
                    format!(
                        "police {} bps",
                        m.action_params.rate_bps.unwrap_or_default()
                    )
                } else {
                    m.action_type.to_string()
                },
                m.vector,
                m.match_criteria.dst_prefix,
                report_match(&m.match_criteria),
                m.expires_at.to_rfc3339(),
                format_duration(duration_secs),
            ));
        }
        md.push('\n');
    }

    // Correlation section (for correlated mitigations)
    let correlated: Vec<_> = mitigations
        .iter()
        .filter(|m| m.signal_group_id.is_some())
        .collect();
    if !correlated.is_empty() {
        md.push_str("## Correlation\n\n");
        for m in &correlated {
            if let Some(group_id) = m.signal_group_id {
                md.push_str(&format!(
                    "### Mitigation `{}` — Signal Group `{}`\n\n",
                    m.mitigation_id, group_id
                ));
                if let Ok(Some(group)) = state.repo.get_signal_group(group_id).await {
                    md.push_str(&format!(
                        "- **Derived Confidence**: {:.2}\n",
                        group.derived_confidence
                    ));
                    md.push_str(&format!("- **Source Count**: {}\n", group.source_count));
                    md.push_str(&format!(
                        "- **Corroboration Met**: {}\n",
                        if group.corroboration_met { "Yes" } else { "No" }
                    ));
                    md.push_str(&format!("- **Status**: {}\n", group.status));

                    if let Ok(group_events) = state.repo.list_signal_group_events(group_id).await {
                        if !group_events.is_empty() {
                            md.push_str("\n| Source | Confidence | Weight |\n");
                            md.push_str("|--------|------------|--------|\n");
                            for ge in &group_events {
                                md.push_str(&format!(
                                    "| {} | {:.2} | {:.1} |\n",
                                    ge.source.as_deref().unwrap_or("unknown"),
                                    ge.confidence.unwrap_or(0.0),
                                    ge.source_weight,
                                ));
                            }
                        }
                    }
                    md.push('\n');
                }
            }
        }
    }

    // Audit trail
    if !audit_entries.is_empty() {
        md.push_str("## Audit Trail\n\n");
        md.push_str("| Timestamp | Action | Actor | Target |\n");
        md.push_str("|-----------|--------|-------|--------|\n");
        for a in &audit_entries {
            md.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                a.timestamp.to_rfc3339(),
                a.action,
                a.actor_id.as_deref().unwrap_or("system"),
                a.target_id.as_deref().unwrap_or("—"),
            ));
        }
        md.push('\n');
    }

    let mut response_headers = HeaderMap::new();
    response_headers.insert(header::CONTENT_TYPE, "text/markdown".parse().unwrap());
    response_headers.insert(
        header::CONTENT_DISPOSITION,
        "attachment; filename=\"incident-report.md\""
            .parse()
            .unwrap(),
    );

    (StatusCode::OK, response_headers, md).into_response()
}

fn report_match(criteria: &crate::domain::MatchCriteria) -> String {
    let protocol = match criteria.protocol {
        Some(1) => "ICMP".into(),
        Some(6) => "TCP".into(),
        Some(17) => "UDP".into(),
        Some(58) => "ICMPv6".into(),
        Some(number) => format!("protocol {number}"),
        None => "any protocol".into(),
    };
    let mut parts = vec![protocol];
    if let Some(source) = &criteria.src_prefix {
        parts.push(format!("from `{source}`"));
    }
    for (label, ports) in [
        ("dst ports", &criteria.dst_ports),
        ("src ports", &criteria.src_ports),
    ] {
        if !ports.is_empty() {
            parts.push(format!(
                "{label} {}",
                ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    if criteria.fragment.is_some() {
        parts.push("non-first fragments".into());
    }
    if let Some(length) = &criteria.packet_length {
        parts.push(format!("length {}–{} B", length.min, length.max));
    }
    parts.join("; ")
}

fn format_bps(bps: i64) -> String {
    let abs = bps.unsigned_abs();
    if abs >= 1_000_000_000 {
        format!("{:.1} Gbps", bps as f64 / 1_000_000_000.0)
    } else if abs >= 1_000_000 {
        format!("{:.1} Mbps", bps as f64 / 1_000_000.0)
    } else {
        format!("{} Kbps", bps / 1_000)
    }
}

fn format_pps(pps: i64) -> String {
    let abs = pps.unsigned_abs();
    if abs >= 1_000_000 {
        format!("{:.1}M pps", pps as f64 / 1_000_000.0)
    } else if abs >= 1_000 {
        format!("{}K pps", pps / 1_000)
    } else {
        format!("{} pps", pps)
    }
}

fn format_duration(seconds: i64) -> String {
    if seconds <= 0 {
        return "0m".to_string();
    }
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let minutes = (seconds % 3600) / 60;

    if days > 0 {
        format!("{}d {}h", days, hours)
    } else if hours > 0 {
        format!("{}h {}m", hours, minutes)
    } else {
        format!("{}m", minutes)
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_duration_hours, parse_duration_minutes};
    use crate::db::PopInfo;

    #[test]
    fn test_parse_duration_hours_saturates_conversion() {
        for (input, expected) in [
            ("24", Some(24)),
            ("24h", Some(24)),
            ("7d", Some(168)),
            (" 2d ", Some(48)),
            ("0d", Some(0)),
            ("178956970d", Some(4_294_967_280)),
            ("178956971d", Some(u32::MAX)),
            ("536870912d", Some(u32::MAX)),
            ("4294967295d", Some(u32::MAX)),
            ("4294967295h", Some(u32::MAX)),
            ("4294967295", Some(u32::MAX)),
            ("4294967296d", None),
            ("4294967296h", None),
            ("4294967296", None),
            ("", None),
            ("invalid", None),
            ("1m", None),
            ("1H", None),
            ("-1d", None),
            ("1 d", None),
        ] {
            assert_eq!(parse_duration_hours(input), expected, "{input:?}");
        }
    }

    #[test]
    fn test_parse_duration_minutes_saturates_conversion() {
        for (input, expected) in [
            ("60", Some(60)),
            ("5m", Some(5)),
            ("2h", Some(120)),
            (" 2h ", Some(120)),
            ("0h", Some(0)),
            ("71582788h", Some(4_294_967_280)),
            ("71582789h", Some(u32::MAX)),
            ("1073741824h", Some(u32::MAX)),
            ("4294967295h", Some(u32::MAX)),
            ("4294967295m", Some(u32::MAX)),
            ("4294967295", Some(u32::MAX)),
            ("4294967296h", None),
            ("4294967296m", None),
            ("4294967296", None),
            ("", None),
            ("invalid", None),
            ("1d", None),
            ("1M", None),
            ("-1h", None),
            ("1 h", None),
        ] {
            assert_eq!(parse_duration_minutes(input), expected, "{input:?}");
        }
    }

    #[test]
    fn test_list_pops_includes_current_pop_when_missing() {
        let mut pops = vec![
            PopInfo {
                pop: "fra1".to_string(),
                active_mitigations: 2,
                total_mitigations: 50,
            },
            PopInfo {
                pop: "ord1".to_string(),
                active_mitigations: 1,
                total_mitigations: 30,
            },
        ];
        let current_pop = "iad1";

        if !pops.iter().any(|p| p.pop == *current_pop) {
            pops.push(PopInfo {
                pop: current_pop.to_string(),
                active_mitigations: 0,
                total_mitigations: 0,
            });
            pops.sort_by(|a, b| a.pop.cmp(&b.pop));
        }

        assert_eq!(pops.len(), 3);
        assert_eq!(pops[0].pop, "fra1");
        assert_eq!(pops[1].pop, "iad1");
        assert_eq!(pops[2].pop, "ord1");
        assert_eq!(pops[1].active_mitigations, 0);
        assert_eq!(pops[1].total_mitigations, 0);
    }

    #[test]
    fn test_list_pops_does_not_duplicate_existing_pop() {
        let mut pops = vec![
            PopInfo {
                pop: "iad1".to_string(),
                active_mitigations: 5,
                total_mitigations: 100,
            },
            PopInfo {
                pop: "ord1".to_string(),
                active_mitigations: 1,
                total_mitigations: 30,
            },
        ];
        let current_pop = "iad1";

        if !pops.iter().any(|p| p.pop == *current_pop) {
            pops.push(PopInfo {
                pop: current_pop.to_string(),
                active_mitigations: 0,
                total_mitigations: 0,
            });
            pops.sort_by(|a, b| a.pop.cmp(&b.pop));
        }

        assert_eq!(pops.len(), 2);
        assert_eq!(pops[0].pop, "iad1");
        assert_eq!(pops[0].active_mitigations, 5);
    }

    #[test]
    fn test_list_pops_inserts_into_empty_list() {
        let mut pops: Vec<PopInfo> = vec![];
        let current_pop = "iad1";

        if !pops.iter().any(|p| p.pop == *current_pop) {
            pops.push(PopInfo {
                pop: current_pop.to_string(),
                active_mitigations: 0,
                total_mitigations: 0,
            });
            pops.sort_by(|a, b| a.pop.cmp(&b.pop));
        }

        assert_eq!(pops.len(), 1);
        assert_eq!(pops[0].pop, "iad1");
    }
}
