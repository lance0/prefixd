use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::IntoResponse,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;
use crate::api::auth::{require_auth, require_role};
use crate::auth::AuthSession;
use crate::db::ListParams;
use crate::domain::{AttackEventInput, AttackVector, validate_confidence};
use crate::error::PrefixdError;

use super::{
    AnnouncementOutcome, AppError, ErrorResponse, EventResponse, clamp_limit, decode_list_cursor,
    default_limit, encode_list_cursor, handle_ban, handle_unban, parse_date_range,
};

// ── Signal Groups API ──────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct SignalGroupsListResponse {
    /// List of signal groups in this page
    groups: Vec<crate::correlation::SignalGroup>,
    /// Number of groups returned in this page
    count: usize,
    /// Cursor for the next page (null if no more pages)
    next_cursor: Option<String>,
    /// Whether there are more pages
    has_more: bool,
}

#[derive(Serialize, ToSchema)]
pub struct SignalGroupDetailResponse {
    /// Signal group metadata
    #[serde(flatten)]
    group: crate::correlation::SignalGroup,
    /// Contributing events with source, confidence, source_weight, ingested_at
    events: Vec<crate::correlation::SignalGroupEvent>,
    /// Linked mitigation ID (present when a mitigation was created from this signal group)
    mitigation_id: Option<Uuid>,
}

#[derive(Deserialize)]
pub struct ListSignalGroupsQuery {
    /// Filter by status (open, resolved, expired)
    status: Option<String>,
    /// Filter by attack vector
    vector: Option<String>,
    /// Number of results per page (default 100, max 1000)
    #[serde(default = "default_limit")]
    limit: u32,
    /// Cursor for pagination (from previous response)
    cursor: Option<String>,
    /// Start of date range (ISO 8601, inclusive)
    start: Option<String>,
    /// End of date range (ISO 8601, exclusive)
    end: Option<String>,
}

/// List signal groups with optional filters and cursor pagination
#[utoipa::path(
    get,
    path = "/v1/signal-groups",
    tag = "signal-groups",
    params(
        ("status" = Option<String>, Query, description = "Exact status: open, resolved or expired; empty or unknown values are invalid"),
        ("vector" = Option<String>, Query, description = "Filter by attack vector"),
        ("limit" = Option<u32>, Query, description = "Max results (default 100, max 1000)"),
        ("cursor" = Option<String>, Query, description = "Opaque s1 continuation from next_cursor (max 128 bytes); superseded timestamp-only cursors are rejected"),
        ("start" = Option<String>, Query, description = "Inclusive RFC3339 start; empty or malformed supplied values are invalid"),
        ("end" = Option<String>, Query, description = "Exclusive RFC3339 end; empty or malformed supplied values are invalid"),
    ),
    responses(
        (status = 200, description = "List of signal groups", body = SignalGroupsListResponse),
        (status = 400, description = "Invalid date/status filter or invalid/superseded signal-group cursor", body = ErrorResponse),
        (status = 401, description = "Authentication required"),
    )
)]
pub async fn list_signal_groups(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Query(query): Query<ListSignalGroupsQuery>,
) -> Result<axum::response::Response, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

    let status_filter = match query.status.as_deref().map(str::parse).transpose() {
        Ok(status) => status,
        Err(_) => {
            return Ok(AppError(PrefixdError::InvalidRequest(
                "invalid status filter; expected open, resolved or expired".into(),
            ))
            .into_response());
        }
    };

    let limit = clamp_limit(query.limit);
    let cursor = match query.cursor.as_deref() {
        None => None,
        Some(value) => match decode_list_cursor(value, "s1.") {
            Some(cursor) => Some(cursor),
            None => return Ok(AppError(PrefixdError::InvalidRequest(
                "invalid signal-group cursor; use next_cursor from a fresh signal-group listing (s1, at most 128 bytes)".into(),
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

    let filter = crate::correlation::SignalGroupFilter {
        status: status_filter,
        vector: query.vector,
        start: params.start,
        end: params.end,
    };

    let mut groups = state
        .repo
        .list_signal_groups(&filter, &params)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let has_more = groups.len() > limit as usize;
    if has_more {
        groups.truncate(limit as usize);
    }
    let next_cursor = if has_more {
        groups
            .last()
            .map(|g| encode_list_cursor(g.created_at, g.group_id, "s1."))
    } else {
        None
    };
    let count = groups.len();

    Ok(Json(SignalGroupsListResponse {
        groups,
        count,
        next_cursor,
        has_more,
    })
    .into_response())
}

/// Get a specific signal group by ID with contributing events
#[utoipa::path(
    get,
    path = "/v1/signal-groups/{id}",
    tag = "signal-groups",
    params(
        ("id" = Uuid, Path, description = "Signal group ID")
    ),
    responses(
        (status = 200, description = "Signal group detail with contributing events", body = SignalGroupDetailResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Signal group not found"),
    )
)]
pub async fn get_signal_group(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<SignalGroupDetailResponse>, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

    let group = state
        .repo
        .get_signal_group(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let events = state
        .repo
        .list_signal_group_events(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mitigation_id = state
        .repo
        .find_mitigation_id_by_signal_group(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(SignalGroupDetailResponse {
        group,
        events,
        mitigation_id,
    }))
}

// ==========================================================================
// Alertmanager webhook adapter
// ==========================================================================

/// Alertmanager v4 webhook payload.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AlertmanagerWebhookPayload {
    /// Payload version (expected "4")
    pub version: String,
    /// Group status (firing, resolved)
    #[serde(default)]
    pub status: String,
    /// List of alerts in this notification
    pub alerts: Vec<AlertmanagerAlert>,
    /// Labels shared by all alerts in the group
    #[serde(default)]
    pub group_labels: HashMap<String, String>,
    /// Labels common to all alerts in the group
    #[serde(default)]
    pub common_labels: HashMap<String, String>,
    /// Annotations common to all alerts in the group
    #[serde(default)]
    pub common_annotations: HashMap<String, String>,
    /// External Alertmanager URL
    #[serde(default)]
    pub external_url: String,
}

/// A single alert from the Alertmanager webhook.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AlertmanagerAlert {
    /// Alert status: "firing" or "resolved"
    pub status: String,
    /// Alert labels
    #[serde(default)]
    pub labels: HashMap<String, String>,
    /// Alert annotations
    #[serde(default)]
    pub annotations: HashMap<String, String>,
    /// Start time of the alert
    #[serde(default)]
    pub starts_at: Option<String>,
    /// End time of the alert (present when resolved)
    #[serde(default)]
    pub ends_at: Option<String>,
    /// URL for the alert in the generator
    #[serde(default)]
    pub generator_url: Option<String>,
    /// Unique fingerprint for the alert (used for dedup)
    #[serde(default)]
    pub fingerprint: Option<String>,
}

/// Per-alert result in the Alertmanager webhook response.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AlertmanagerAlertResult {
    /// Present only when this creation request committed intent without a successful speaker reply.
    /// Omission is not evidence of enforcement; this outcome is not persisted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub announcement_outcome: Option<AnnouncementOutcome>,
    /// Index in the alerts array
    pub index: usize,
    /// Processing status (processed, duplicate, withdrawn, error)
    pub status: String,
    /// Event ID created for this alert (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<Uuid>,
    /// Mitigation ID affected (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitigation_id: Option<Uuid>,
    /// Error message (if processing failed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Response for the Alertmanager webhook endpoint.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AlertmanagerWebhookResponse {
    /// Number of alerts successfully processed
    pub processed: u32,
    /// Number of alerts that failed processing
    pub failed: u32,
    /// Per-alert results
    pub results: Vec<AlertmanagerAlertResult>,
}

/// Map Alertmanager severity label to confidence score.
fn alertmanager_severity_to_confidence(severity: Option<&str>) -> f32 {
    match severity {
        Some("critical") => 0.9,
        Some("warning") => 0.7,
        Some("info") => 0.5,
        _ => 0.5,
    }
}

/// Extract victim IP from alert labels, stripping port if present.
/// Checks `victim_ip` first, then `instance` (with port stripping).
fn extract_victim_ip(labels: &HashMap<String, String>) -> Option<String> {
    if let Some(ip) = labels.get("victim_ip") {
        if !ip.is_empty() {
            return Some(ip.clone());
        }
    }
    if let Some(instance) = labels.get("instance") {
        if !instance.is_empty() {
            // Strip port suffix (e.g., "10.0.0.1:9090" → "10.0.0.1")
            let stripped = if instance.starts_with('[') {
                // IPv6 with brackets: [::1]:9090
                instance
                    .find("]:")
                    .map(|i| &instance[1..i])
                    .unwrap_or(instance)
            } else if instance.contains(':') && instance.matches(':').count() == 1 {
                // IPv4 with port: 10.0.0.1:9090
                instance.split(':').next().unwrap_or(instance)
            } else {
                // No port (IPv6 without brackets or plain IP)
                instance
            };
            return Some(stripped.to_string());
        }
    }
    None
}

/// Extract attack vector from alert labels.
/// Checks `vector` first, then `alertname`.
fn extract_vector(labels: &HashMap<String, String>) -> Option<String> {
    if let Some(v) = labels.get("vector") {
        if !v.is_empty() {
            return Some(v.clone());
        }
    }
    if let Some(name) = labels.get("alertname") {
        if !name.is_empty() {
            return Some(name.clone());
        }
    }
    None
}

/// Parse comma-separated ports such as `"123, 11211"`. Any empty or invalid
/// entry rejects the whole list, so a malformed annotation never becomes empty.
fn parse_port_list(raw: &str) -> Option<Vec<u16>> {
    raw.split(',')
        .map(|port| port.trim().parse::<u16>().ok())
        .collect()
}

/// Parse an optional i64 from annotations.
fn parse_optional_i64(annotations: &HashMap<String, String>, key: &str) -> Option<i64> {
    annotations.get(key).and_then(|v| v.parse::<i64>().ok())
}

/// Ingest alerts from Alertmanager v4 webhook
#[utoipa::path(
    post,
    path = "/v1/signals/alertmanager",
    tag = "signals",
    request_body = AlertmanagerWebhookPayload,
    responses(
        (status = 200, description = "Alerts processed", body = AlertmanagerWebhookResponse),
        (status = 400, description = "Malformed payload"),
        (status = 401, description = "Authentication required"),
    )
)]
pub async fn ingest_alertmanager(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    ingest_alertmanager_inner(state, auth_session, headers, body).await
}

async fn ingest_alertmanager_inner(
    state: Arc<AppState>,
    auth_session: AuthSession,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<AlertmanagerWebhookResponse>), AppError> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    if let Err(_status) = require_auth(&state, &auth_session, auth_header) {
        return Err(AppError(PrefixdError::Unauthorized(
            "authentication required".into(),
        )));
    }

    // Parse body as JSON — return 400 for malformed payloads
    let payload: AlertmanagerWebhookPayload = serde_json::from_slice(&body).map_err(|e| {
        AppError(PrefixdError::InvalidRequest(format!(
            "malformed Alertmanager payload: {}",
            e
        )))
    })?;

    // Validate version
    if payload.version != "4" {
        return Err(AppError(PrefixdError::InvalidRequest(format!(
            "unsupported Alertmanager webhook version: '{}', expected '4'",
            payload.version
        ))));
    }

    // Validate alerts array is not empty
    if payload.alerts.is_empty() {
        return Err(AppError(PrefixdError::InvalidRequest(
            "alerts array is empty".into(),
        )));
    }

    let mut results = Vec::with_capacity(payload.alerts.len());
    let mut processed = 0u32;
    let mut failed = 0u32;

    for (index, alert) in payload.alerts.into_iter().enumerate() {
        match process_alertmanager_alert(&state, &alert, index).await {
            Ok(result) => {
                processed += 1;
                results.push(result);
            }
            Err(result) => {
                failed += 1;
                results.push(result);
            }
        }
    }

    tracing::info!(target: "prefixd::api::handlers",
        processed = processed,
        failed = failed,
        total = results.len(),
        "alertmanager webhook processed"
    );

    Ok((
        StatusCode::OK,
        Json(AlertmanagerWebhookResponse {
            processed,
            failed,
            results,
        }),
    ))
}

/// Process a single Alertmanager alert, returning Ok for success or Err for
/// failure — both carry the per-alert result.
async fn process_alertmanager_alert(
    state: &Arc<AppState>,
    alert: &AlertmanagerAlert,
    index: usize,
) -> Result<AlertmanagerAlertResult, AlertmanagerAlertResult> {
    // Extract vector
    let vector_str = match extract_vector(&alert.labels) {
        Some(v) => v,
        None => {
            return Err(AlertmanagerAlertResult {
                announcement_outcome: None,
                index,
                status: "error".to_string(),
                event_id: None,
                mitigation_id: None,
                error: Some(
                    "missing vector: neither labels.vector nor labels.alertname present".into(),
                ),
            });
        }
    };

    // Parse vector
    let vector: AttackVector = vector_str.parse().unwrap_or(AttackVector::Unknown);

    // Extract victim IP
    let victim_ip = match extract_victim_ip(&alert.labels) {
        Some(ip) => ip,
        None => {
            return Err(AlertmanagerAlertResult {
                announcement_outcome: None,
                index,
                status: "error".to_string(),
                event_id: None,
                mitigation_id: None,
                error: Some(
                    "missing victim_ip: neither labels.victim_ip nor labels.instance present"
                        .into(),
                ),
            });
        }
    };

    // Validate IP
    if victim_ip.parse::<IpAddr>().is_err() {
        return Err(AlertmanagerAlertResult {
            announcement_outcome: None,
            index,
            status: "error".to_string(),
            event_id: None,
            mitigation_id: None,
            error: Some(format!("invalid IP address: '{}'", victim_ip)),
        });
    }

    // Extract optional fields
    let bps = parse_optional_i64(&alert.annotations, "bps");
    let pps = parse_optional_i64(&alert.annotations, "pps");
    let confidence =
        alertmanager_severity_to_confidence(alert.labels.get("severity").map(|s| s.as_str()));

    // Determine action from alert status
    let action = if alert.status == "resolved" {
        "unban".to_string()
    } else {
        "ban".to_string()
    };

    // Source ports matter only for a ban; a bad annotation never blocks an unban.
    let top_src_ports = match alert.annotations.get("top_src_ports") {
        Some(raw) if action == "ban" => match parse_port_list(raw) {
            Some(ports) => Some(ports),
            None => {
                return Err(AlertmanagerAlertResult {
                    announcement_outcome: None,
                    index,
                    status: "error".to_string(),
                    event_id: None,
                    mitigation_id: None,
                    error: Some(format!(
                        "invalid annotations.top_src_ports: '{raw}' (expected comma-separated ports)"
                    )),
                });
            }
        },
        _ => None,
    };

    // Use fingerprint as external_event_id for dedup
    let external_event_id = alert.fingerprint.clone();

    // Parse timestamp
    let timestamp = alert
        .starts_at
        .as_deref()
        .and_then(|s| s.parse::<DateTime<Utc>>().ok())
        .unwrap_or_else(Utc::now);

    let input = AttackEventInput {
        event_id: external_event_id,
        timestamp,
        source: "alertmanager".to_string(),
        victim_ip,
        vector,
        bps,
        pps,
        top_dst_ports: None,
        top_src_ports,
        confidence: Some(confidence),
        action,
        raw_details: None,
    };

    // Delegate to the existing event ingestion pipeline
    match input.action.as_str() {
        "unban" => match handle_unban(state.clone(), input).await {
            Ok((_status, Json(resp))) => Ok(AlertmanagerAlertResult {
                announcement_outcome: resp.announcement_outcome,
                index,
                status: "withdrawn".to_string(),
                event_id: Some(resp.event_id),
                mitigation_id: resp.mitigation_id,
                error: None,
            }),
            Err(AppError(e)) => Ok(AlertmanagerAlertResult {
                announcement_outcome: None,
                index,
                status: "withdrawn_noop".to_string(),
                event_id: None,
                mitigation_id: None,
                error: Some(e.to_string()),
            }),
        },
        _ => match handle_ban(state.clone(), input).await {
            Ok((_status, Json(resp))) => Ok(AlertmanagerAlertResult {
                announcement_outcome: resp.announcement_outcome,
                index,
                status: resp.status,
                event_id: Some(resp.event_id),
                mitigation_id: resp.mitigation_id,
                error: None,
            }),
            Err(AppError(PrefixdError::DuplicateEvent { .. })) => Ok(AlertmanagerAlertResult {
                announcement_outcome: None,
                index,
                status: "duplicate".to_string(),
                event_id: None,
                mitigation_id: None,
                error: None,
            }),
            Err(AppError(e)) => Err(AlertmanagerAlertResult {
                announcement_outcome: None,
                index,
                status: "error".to_string(),
                event_id: None,
                mitigation_id: None,
                error: Some(e.to_string()),
            }),
        },
    }
}

// ==========================================================================
// FastNetMon signal adapter
// ==========================================================================

/// FastNetMon webhook payload (JSON notify format).
///
/// Accepts FastNetMon's native notify format with IP, attack details,
/// direction, and bandwidth metrics. The `action` field determines the
/// confidence mapping (ban=0.9, partial_block=0.7, alert=0.5 by default,
/// overridable in correlation config).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FastNetMonPayload {
    /// Action type: "ban", "unban", "partial_block", or "alert"
    pub action: String,
    /// Victim IP address under attack
    pub ip: String,
    /// Scope of the alert: "host" or "total"
    #[serde(default)]
    pub alert_scope: Option<String>,
    /// Attack details with traffic metrics and classification
    #[serde(default)]
    pub attack_details: Option<FastNetMonAttackDetails>,
    /// Sampled packets, one object each with `protocol`, `source_port` and
    /// `packets` (FastNetMon's `serialize_simple_packet_to_json`). UDP samples
    /// select reflector source ports; entries that do not parse are ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_dump_detailed: Option<serde_json::Value>,
}

/// Attack details from FastNetMon.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FastNetMonAttackDetails {
    /// UUID of the attack (used as external_event_id for dedup)
    #[serde(default)]
    pub attack_uuid: Option<String>,
    /// Attack severity: "low", "middle", "high"
    #[serde(default)]
    pub attack_severity: Option<String>,
    /// Detection source: "automatic", "manual", etc.
    #[serde(default)]
    pub attack_detection_source: Option<String>,
    /// Detection threshold type: "bytes per second", "packets per second", etc.
    #[serde(default)]
    pub attack_detection_threshold: Option<String>,
    /// Detection direction: "incoming", "outgoing"
    #[serde(default)]
    pub attack_detection_threshold_direction: Option<String>,
    /// Attack start timestamp
    #[serde(default)]
    pub attack_start: Option<String>,
    /// Protocol version: "IPv4" or "IPv6"
    #[serde(default)]
    pub protocol_version: Option<String>,
    /// Host group
    #[serde(default)]
    pub host_group: Option<String>,
    /// Host network
    #[serde(default)]
    pub host_network: Option<String>,

    // Per-protocol incoming traffic metrics
    #[serde(default)]
    pub incoming_udp_pps: Option<i64>,
    #[serde(default)]
    pub incoming_udp_traffic_bits: Option<i64>,
    #[serde(default)]
    pub incoming_tcp_pps: Option<i64>,
    #[serde(default)]
    pub incoming_tcp_traffic_bits: Option<i64>,
    #[serde(default)]
    pub incoming_syn_tcp_pps: Option<i64>,
    #[serde(default)]
    pub incoming_syn_tcp_traffic_bits: Option<i64>,
    #[serde(default)]
    pub incoming_icmp_pps: Option<i64>,
    #[serde(default)]
    pub incoming_icmp_traffic_bits: Option<i64>,
    #[serde(default)]
    pub incoming_ip_fragmented_pps: Option<i64>,
    #[serde(default)]
    pub incoming_ip_fragmented_traffic_bits: Option<i64>,

    // Totals
    #[serde(default)]
    pub total_incoming_pps: Option<i64>,
    #[serde(default)]
    pub total_incoming_traffic_bits: Option<i64>,
    #[serde(default)]
    pub total_incoming_flows: Option<i64>,
    #[serde(default)]
    pub total_outgoing_pps: Option<i64>,
    #[serde(default)]
    pub total_outgoing_traffic_bits: Option<i64>,
    #[serde(default)]
    pub total_outgoing_flows: Option<i64>,
}

/// Classify attack vector from FastNetMon attack details.
///
/// Examines per-protocol traffic breakdown to determine the dominant vector.
/// Falls back to "unknown" if no clear dominant protocol is found.
fn classify_fastnetmon_vector(details: &FastNetMonAttackDetails) -> AttackVector {
    let udp_pps = details.incoming_udp_pps.unwrap_or(0);
    let tcp_pps = details.incoming_tcp_pps.unwrap_or(0);
    let syn_pps = details.incoming_syn_tcp_pps.unwrap_or(0);
    let icmp_pps = details.incoming_icmp_pps.unwrap_or(0);

    // Check for SYN flood: SYN PPS is dominant fraction of TCP
    if syn_pps > 0
        && (tcp_pps == 0 || i128::from(syn_pps) * 100 / i128::from(tcp_pps.max(1)) > 60)
        && syn_pps > udp_pps
    {
        return AttackVector::SynFlood;
    }

    // Pick the dominant protocol by PPS
    let max_pps = udp_pps.max(tcp_pps).max(icmp_pps);
    if max_pps == 0 {
        return AttackVector::Unknown;
    }

    if udp_pps == max_pps {
        AttackVector::UdpFlood
    } else if icmp_pps == max_pps {
        AttackVector::IcmpFlood
    } else {
        // TCP flood (non-SYN dominant)
        AttackVector::AckFlood
    }
}

/// Classify a FastNetMon payload, upgrading a UDP flood to `udp_amplification`
/// when sampled packets show reflector source ports (ADR 028).
///
/// Only a UDP-dominant attack is upgraded. Each library port whose share of
/// sampled UDP packets (weighted by `packets`) is at least `min_src_port_share`
/// is kept, ranked by share. With no dump, no UDP sample or no qualifying port,
/// the counter classification stands and no ports are reported.
fn classify_fastnetmon(
    payload: &FastNetMonPayload,
    amplification: &crate::config::AmplificationConfig,
) -> (AttackVector, Option<Vec<u16>>) {
    let vector = payload
        .attack_details
        .as_ref()
        .map(classify_fastnetmon_vector)
        .unwrap_or(AttackVector::Unknown);
    if vector != AttackVector::UdpFlood {
        return (vector, None);
    }
    let mut packets_by_port: HashMap<u16, u128> = HashMap::new();
    let mut total: u128 = 0;
    let samples = payload
        .packet_dump_detailed
        .as_ref()
        .and_then(serde_json::Value::as_array);
    for sample in samples.into_iter().flatten() {
        let field = |name| sample.get(name).and_then(serde_json::Value::as_u64);
        if sample.get("protocol").and_then(serde_json::Value::as_str) != Some("udp") {
            continue;
        }
        let (Some(port), Some(packets)) = (
            field("source_port").and_then(|port| u16::try_from(port).ok()),
            field("packets"),
        ) else {
            continue;
        };
        *packets_by_port.entry(port).or_default() += u128::from(packets);
        total += u128::from(packets);
    }
    let library = amplification.library_ports();
    let mut ports: Vec<(u16, u128)> = packets_by_port
        .into_iter()
        .filter(|(port, packets)| {
            library.contains(port)
                && *packets as f64 >= amplification.min_src_port_share * total as f64
        })
        .collect();
    if total == 0 || ports.is_empty() {
        return (vector, None);
    }
    ports.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    (
        AttackVector::UdpAmplification,
        Some(
            ports
                .into_iter()
                .take(crate::domain::MAX_TOP_SRC_PORTS)
                .map(|(port, _)| port)
                .collect(),
        ),
    )
}

/// Ingest a signal from FastNetMon
#[utoipa::path(
    post,
    path = "/v1/signals/fastnetmon",
    tag = "signals",
    request_body = FastNetMonPayload,
    responses(
        (status = 202, description = "Event accepted", body = EventResponse),
        (status = 400, description = "Malformed payload"),
        (status = 401, description = "Authentication required"),
    )
)]
pub async fn ingest_fastnetmon(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    ingest_fastnetmon_inner(state, auth_session, headers, body).await
}

async fn ingest_fastnetmon_inner(
    state: Arc<AppState>,
    auth_session: AuthSession,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<EventResponse>), AppError> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    if let Err(_status) = require_auth(&state, &auth_session, auth_header) {
        return Err(AppError(PrefixdError::Unauthorized(
            "authentication required".into(),
        )));
    }

    // Parse body as JSON — return 400 for malformed payloads
    let payload: FastNetMonPayload = serde_json::from_slice(&body).map_err(|e| {
        AppError(PrefixdError::InvalidRequest(format!(
            "malformed FastNetMon payload: {}",
            e
        )))
    })?;

    // Validate required fields
    if payload.ip.is_empty() {
        return Err(AppError(PrefixdError::InvalidRequest(
            "missing required field: ip".into(),
        )));
    }

    // Validate IP address
    if payload.ip.parse::<IpAddr>().is_err() {
        return Err(AppError(PrefixdError::InvalidRequest(format!(
            "invalid IP address: '{}'",
            payload.ip
        ))));
    }

    if payload.action.is_empty() {
        return Err(AppError(PrefixdError::InvalidRequest(
            "missing required field: action".into(),
        )));
    }

    let (vector, top_src_ports) = classify_fastnetmon(&payload, &state.settings.amplification);

    // Compute confidence from action type via configurable mapping
    let correlation_config = state.correlation_config.read().await;
    let confidence = correlation_config.source_action_confidence("fastnetmon", &payload.action);
    drop(correlation_config);

    // Extract traffic metrics from attack details
    let (bps, pps) = payload
        .attack_details
        .as_ref()
        .map(|d| (d.total_incoming_traffic_bits, d.total_incoming_pps))
        .unwrap_or((None, None));

    // Use attack_uuid as external_event_id for dedup
    let external_event_id = payload
        .attack_details
        .as_ref()
        .and_then(|d| d.attack_uuid.clone());

    // Parse timestamp from attack_start, or use now
    let timestamp = payload
        .attack_details
        .as_ref()
        .and_then(|d| d.attack_start.as_deref())
        .and_then(|s| s.parse::<DateTime<Utc>>().ok())
        .unwrap_or_else(Utc::now);

    // Determine action for the event pipeline
    let action = match payload.action.as_str() {
        "unban" => "unban".to_string(),
        _ => "ban".to_string(), // ban, partial_block, alert all map to ban action in the pipeline
    };

    // Store raw payload as raw_details for forensics
    let raw_details = serde_json::to_value(&payload).ok();

    let input = AttackEventInput {
        event_id: external_event_id,
        timestamp,
        source: "fastnetmon".to_string(),
        victim_ip: payload.ip,
        vector,
        bps,
        pps,
        top_dst_ports: None,
        top_src_ports,
        confidence: Some(confidence),
        action,
        raw_details,
    };

    // Delegate to the existing event ingestion pipeline
    match input.action.as_str() {
        "unban" => match handle_unban(state.clone(), input).await {
            Ok(resp) => Ok(resp),
            Err(e) => Err(e),
        },
        _ => match handle_ban(state.clone(), input).await {
            Ok(resp) => Ok(resp),
            Err(e) => Err(e),
        },
    }
}

// ==========================================================================
// Generic webhook adapter
// ==========================================================================

/// Per-event result for the generic webhook endpoint.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct WebhookEventResult {
    /// Present only when this creation request committed intent without a successful speaker reply.
    /// Omission is not evidence of enforcement; this outcome is not persisted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub announcement_outcome: Option<AnnouncementOutcome>,
    /// Position in the payload (0 for single-event adapters, 0..N for root_path).
    pub index: usize,
    /// Processing status (processed, duplicate, withdrawn, withdrawn_noop, error).
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitigation_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Response for the generic webhook endpoint.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct WebhookResponse {
    pub processed: u32,
    pub failed: u32,
    pub results: Vec<WebhookEventResult>,
}

/// Ingest signals from a generic configured webhook adapter
#[utoipa::path(
    post,
    path = "/v1/signals/webhook/{name}",
    tag = "signals",
    params(("name" = String, Path, description = "Adapter name as configured in correlation.yaml")),
    request_body(content = serde_json::Value, description = "Arbitrary JSON payload mapped via the adapter's JSONPath fields"),
    responses(
        (status = 200, description = "Events processed", body = WebhookResponse),
        (status = 400, description = "Malformed payload or no mappable events"),
        (status = 401, description = "HMAC/bearer verification failed"),
        (status = 404, description = "Adapter not configured or disabled"),
    )
)]
pub async fn ingest_webhook(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    ingest_webhook_inner(state, auth_session, name, headers, body).await
}

async fn ingest_webhook_inner(
    state: Arc<AppState>,
    auth_session: AuthSession,
    name: String,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<WebhookResponse>), AppError> {
    if !crate::correlation::is_valid_name(&name) {
        return Err(AppError(PrefixdError::NotFound(format!(
            "webhook adapter '{name}' not found"
        ))));
    }

    // Resolve adapter config
    let (adapter, compiled) = {
        let cfg = state.correlation_config.read().await;
        let adapter = cfg
            .webhook_adapters
            .iter()
            .find(|a| a.name == name && a.enabled)
            .cloned()
            .ok_or_else(|| {
                AppError(PrefixdError::NotFound(format!(
                    "webhook adapter '{name}' not found"
                )))
            })?;
        drop(cfg);
        let compiled = crate::correlation::CompiledAdapter::compile(&adapter).map_err(|e| {
            AppError(PrefixdError::Internal(format!(
                "adapter '{name}' has invalid JSONPath: {e}"
            )))
        })?;
        (adapter, compiled)
    };

    // Auth check per adapter
    match &adapter.auth {
        crate::correlation::WebhookAuth::Hmac {
            secret_env,
            header,
            algorithm,
        } => {
            if algorithm != "sha256" {
                return Err(AppError(PrefixdError::Internal(format!(
                    "adapter '{name}' uses unsupported HMAC algorithm '{algorithm}'"
                ))));
            }
            let Ok(secret) = std::env::var(secret_env) else {
                return Err(AppError(PrefixdError::Internal(format!(
                    "adapter '{name}' HMAC secret env var '{secret_env}' not set"
                ))));
            };
            let sig = headers
                .get(header.as_str())
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    AppError(PrefixdError::Unauthorized(format!(
                        "missing HMAC signature header '{header}'"
                    )))
                })?;
            if !crate::correlation::verify_hmac_sha256(secret.as_bytes(), &body, sig) {
                return Err(AppError(PrefixdError::Unauthorized(
                    "HMAC signature verification failed".into(),
                )));
            }
        }
        crate::correlation::WebhookAuth::Bearer => {
            let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
            if require_auth(&state, &auth_session, auth_header).is_err() {
                return Err(AppError(PrefixdError::Unauthorized(
                    "authentication required".into(),
                )));
            }
        }
        crate::correlation::WebhookAuth::None => {
            // No-auth is caller's responsibility; logged once at startup.
        }
    }

    // Parse body
    let payload: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
        AppError(PrefixdError::InvalidRequest(format!(
            "malformed JSON payload: {e}"
        )))
    })?;

    let mapped = crate::correlation::map_payload(&adapter, &compiled, &payload);
    if mapped.is_empty() {
        return Err(AppError(PrefixdError::InvalidRequest(
            "no events extracted from payload".into(),
        )));
    }

    let mut results = Vec::with_capacity(mapped.len());
    let mut processed = 0u32;
    let mut failed = 0u32;

    for (index, mapped_event) in mapped.into_iter().enumerate() {
        match mapped_event {
            Err(e) => {
                failed += 1;
                results.push(WebhookEventResult {
                    announcement_outcome: None,
                    index,
                    status: "error".into(),
                    event_id: None,
                    mitigation_id: None,
                    error: Some(e.to_string()),
                });
            }
            Ok(input) => match input.action.as_str() {
                "unban" => match handle_unban(state.clone(), input).await {
                    Ok((_status, Json(resp))) => {
                        processed += 1;
                        results.push(WebhookEventResult {
                            announcement_outcome: resp.announcement_outcome,
                            index,
                            status: "withdrawn".into(),
                            event_id: Some(resp.event_id),
                            mitigation_id: resp.mitigation_id,
                            error: None,
                        });
                    }
                    Err(AppError(e)) => {
                        processed += 1;
                        results.push(WebhookEventResult {
                            announcement_outcome: None,
                            index,
                            status: "withdrawn_noop".into(),
                            event_id: None,
                            mitigation_id: None,
                            error: Some(e.to_string()),
                        });
                    }
                },
                _ => match handle_ban(state.clone(), input).await {
                    Ok((_status, Json(resp))) => {
                        processed += 1;
                        results.push(WebhookEventResult {
                            announcement_outcome: resp.announcement_outcome,
                            index,
                            status: resp.status,
                            event_id: Some(resp.event_id),
                            mitigation_id: resp.mitigation_id,
                            error: None,
                        });
                    }
                    Err(AppError(PrefixdError::DuplicateEvent { .. })) => {
                        processed += 1;
                        results.push(WebhookEventResult {
                            announcement_outcome: None,
                            index,
                            status: "duplicate".into(),
                            event_id: None,
                            mitigation_id: None,
                            error: None,
                        });
                    }
                    Err(AppError(e)) => {
                        failed += 1;
                        results.push(WebhookEventResult {
                            announcement_outcome: None,
                            index,
                            status: "error".into(),
                            event_id: None,
                            mitigation_id: None,
                            error: Some(e.to_string()),
                        });
                    }
                },
            },
        }
    }

    tracing::info!(target: "prefixd::api::handlers",
        adapter = %adapter.name,
        processed = processed,
        failed = failed,
        total = results.len(),
        "webhook payload processed"
    );

    Ok((
        StatusCode::OK,
        Json(WebhookResponse {
            processed,
            failed,
            results,
        }),
    ))
}

// ── Corroborating signals (ADR 021) ────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct CorroboratorInput {
    pub source: String,
    #[serde(default)]
    pub vector: Option<String>,
    #[serde(default)]
    pub customer_id: Option<String>,
    #[serde(default)]
    pub pop: Option<String>,
    #[serde(default)]
    pub service_id: Option<String>,
    #[serde(default)]
    pub interface: Option<String>,
    /// Optional finite confidence in the inclusive range 0..=1.
    #[serde(default)]
    #[schema(minimum = 0, maximum = 1)]
    pub confidence: Option<f32>,
    #[serde(default)]
    pub raw_details: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CorroboratorResponse {
    pub signal_id: Uuid,
    /// One of "attached" (one or more groups matched) or "cached"
    /// (no matching group; held in the corroborator cache until a
    /// matching primary event arrives or TTL expires). Use this
    /// instead of the v0.16.0 `cached` boolean field, which is
    /// removed in v0.17.0.
    pub status: String,
    pub attached_group_ids: Vec<Uuid>,
}

/// Ingest a corroborating signal.
///
/// Corroborating signals come from sources configured as `mode: corroborating`
/// in `correlation.yaml`. They don't carry a `victim_ip` — they match open
/// signal groups using lighter dimensions (customer_id, pop, service_id,
/// interface) declared in the source's `match_dimensions`.
///
/// If one or more open signal groups match, the signal is attached to each
/// and strengthens their derived confidence. Otherwise the signal is cached
/// with a TTL equal to `correlation.window_seconds` and will be drained when
/// a matching primary event arrives, or expired via the cache sweep.
#[utoipa::path(
    post,
    path = "/v1/signals/corroborator",
    tag = "signals",
    request_body = CorroboratorInput,
    responses(
        (status = 200, description = "Signal ingested", body = CorroboratorResponse),
        (status = 400, description = "Invalid source mode, dimensions or confidence"),
        (status = 401, description = "Authentication required"),
    )
)]
pub async fn ingest_corroborator(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Json(input): Json<CorroboratorInput>,
) -> impl IntoResponse {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    if let Err(_status) = require_auth(&state, &auth_session, auth_header) {
        return Err(AppError(PrefixdError::Unauthorized(
            "authentication required".into(),
        )));
    }
    ingest_corroborator_inner(state, input).await
}

async fn ingest_corroborator_inner(
    state: Arc<AppState>,
    input: CorroboratorInput,
) -> Result<impl IntoResponse, AppError> {
    validate_confidence(input.confidence).map_err(AppError)?;
    use crate::correlation::{CorrelationEngine, CorroboratingSignal, EventDimensions, SourceMode};

    let correlation_config = state.correlation_config.read().await.clone();

    if !correlation_config.enabled {
        return Err(AppError(PrefixdError::InvalidRequest(
            "correlation engine is disabled".to_string(),
        )));
    }

    if correlation_config.source_mode(&input.source) != SourceMode::Corroborating {
        return Err(AppError(PrefixdError::InvalidRequest(format!(
            "source '{}' is not configured as mode=corroborating; \
             post primary events to /v1/events instead.",
            input.source
        ))));
    }

    // Enforce that at least one declared match_dimension is populated on the
    // signal. This prevents a corroborating source from attaching to any
    // random open group by accident.
    let declared = correlation_config.match_dimensions(&input.source);
    let supplied_any = declared.iter().any(|dim| match dim {
        crate::correlation::MatchDimension::CustomerId => input.customer_id.is_some(),
        crate::correlation::MatchDimension::Pop => input.pop.is_some(),
        crate::correlation::MatchDimension::ServiceId => input.service_id.is_some(),
        crate::correlation::MatchDimension::Interface => input.interface.is_some(),
    });
    if !supplied_any {
        return Err(AppError(PrefixdError::InvalidRequest(format!(
            "source '{}' requires at least one of its declared match_dimensions \
             ({}) to be populated on each signal",
            input.source,
            declared
                .iter()
                .map(|d| d.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        ))));
    }

    let now = Utc::now();
    let expires_at = now + chrono::Duration::seconds(correlation_config.window_seconds as i64);
    let weight = correlation_config.source_weight(&input.source);

    let mut signal = CorroboratingSignal {
        signal_id: Uuid::new_v4(),
        source: input.source.clone(),
        vector: input.vector.clone(),
        customer_id: input.customer_id.clone(),
        pop: input.pop.clone(),
        service_id: input.service_id.clone(),
        interface: input.interface.clone(),
        confidence: input.confidence,
        weight,
        ingested_at: now,
        expires_at,
        raw_details: input.raw_details.clone(),
        attached_group_ids: vec![],
    };

    crate::observability::metrics::CORROBORATOR_INGESTED_TOTAL
        .with_label_values(&[&signal.source])
        .inc();

    // Build a dimension probe representing THIS signal. We search for any
    // open signal group that has a primary event sharing at least one of
    // these dimension values.
    let mut probe = EventDimensions::default();
    if declared.contains(&crate::correlation::MatchDimension::CustomerId)
        && let Some(v) = &signal.customer_id
    {
        probe.add_customer(v);
    }
    if declared.contains(&crate::correlation::MatchDimension::Pop)
        && let Some(v) = &signal.pop
    {
        probe.add_pop(v);
    }
    if declared.contains(&crate::correlation::MatchDimension::ServiceId)
        && let Some(v) = &signal.service_id
    {
        probe.add_service(v);
    }
    if declared.contains(&crate::correlation::MatchDimension::Interface)
        && let Some(v) = &signal.interface
    {
        probe.add_interface(v);
    }

    let matching_groups = state
        .repo
        .find_open_groups_by_dimensions(&signal.vector, &probe, now)
        .await
        .map_err(AppError)?
        .into_iter()
        .filter(|group| {
            CorrelationEngine::corroborator_matches_declared(
                &signal,
                &group.vector,
                &group.primary_dimensions.to_event_dimensions(),
                declared,
            )
        })
        .collect::<Vec<_>>();

    let mut attached_group_ids = Vec::new();
    for group in &matching_groups {
        let attached = state
            .repo
            .add_corroborator_event_to_group(group.group_id, &signal)
            .await
            .map_err(AppError)?;
        if attached {
            attached_group_ids.push(group.group_id);
            crate::observability::metrics::CORROBORATOR_ATTACHED_TOTAL
                .with_label_values(&[&signal.source])
                .inc();
            // Recompute group aggregates to include this corroborator.
            recompute_group_aggregates(&state, group.group_id).await?;
        }
    }

    // Always cache the signal too, so late-arriving primary events within
    // the window can also attach to it. The cache table tracks attached_group_ids.
    signal.attached_group_ids = attached_group_ids.clone();
    state
        .repo
        .insert_corroborating_signal(&signal)
        .await
        .map_err(AppError)?;

    tracing::info!(target: "prefixd::api::handlers",
        signal_id = %signal.signal_id,
        source = %signal.source,
        attached_groups = attached_group_ids.len(),
        "corroborating signal ingested"
    );

    Ok((
        StatusCode::OK,
        Json(CorroboratorResponse {
            signal_id: signal.signal_id,
            status: if attached_group_ids.is_empty() {
                "cached".to_string()
            } else {
                "attached".to_string()
            },
            attached_group_ids,
        }),
    ))
}

/// Per-source activity shape returned by
/// `GET /v1/signals/corroborator/activity`. Powers the Signals dashboard
/// cards for `mode: corroborating` sources, which never appear in the
/// primary `/v1/events` stream.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct CorroboratorActivityResponse {
    pub since: chrono::DateTime<chrono::Utc>,
    pub sources: Vec<CorroboratorActivityEntry>,
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct CorroboratorActivityEntry {
    pub source: String,
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,
    pub count: u64,
}

#[derive(Debug, serde::Deserialize)]
pub struct CorroboratorActivityQuery {
    /// Optional minutes-back window; defaults to 60 minutes.
    #[serde(default)]
    pub minutes: Option<u32>,
}

/// Aggregate corroborator activity per source across the live cache and
/// attached signal-group rows. Used by the frontend to show a `last_seen`
/// / `count` for sources configured as `mode: corroborating`, since those
/// sources don't produce primary events.
#[utoipa::path(
    get,
    path = "/v1/signals/corroborator/activity",
    tag = "signals",
    params(("minutes" = Option<u32>, Query, description = "Lookback window in minutes (default 60)")),
    responses(
        (status = 200, description = "Per-source corroborator activity", body = CorroboratorActivityResponse),
        (status = 401, description = "Authentication required"),
    )
)]
pub async fn get_corroborator_activity(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<CorroboratorActivityQuery>,
) -> impl IntoResponse {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    if let Err(_status) = require_auth(&state, &auth_session, auth_header) {
        return Err(AppError(PrefixdError::Unauthorized(
            "authentication required".into(),
        )));
    }
    let minutes = query.minutes.unwrap_or(60).clamp(1, 24 * 60);
    let since = chrono::Utc::now() - chrono::Duration::minutes(minutes as i64);
    let rows = state
        .repo
        .corroborator_source_activity(since)
        .await
        .map_err(AppError)?;
    Ok(Json(CorroboratorActivityResponse {
        since,
        sources: rows
            .into_iter()
            .map(|r| CorroboratorActivityEntry {
                source: r.source,
                last_seen: r.last_seen,
                count: r.count,
            })
            .collect(),
    }))
}

/// Cached-corroborators listing endpoint (PR B). Admin-only. Lists
/// signals currently in the corroborator cache that are unattached and
/// unexpired — i.e. waiting for a matching primary event to drain.
/// Useful for L1 ops to spot a source that's posting heavily but never
/// landing on a real incident.
#[derive(Debug, serde::Deserialize)]
pub struct CachedCorroboratorsQuery {
    /// Page size; clamped to [1, 1000].
    #[serde(default)]
    pub limit: Option<u32>,
    /// Filter by signal source. Optional.
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct CachedCorroboratorsResponse {
    pub now: chrono::DateTime<chrono::Utc>,
    pub total: u64,
    pub by_source: Vec<CachedCorroboratorBySource>,
    pub signals: Vec<crate::correlation::CorroboratingSignal>,
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct CachedCorroboratorBySource {
    pub source: String,
    pub count: u64,
}

#[utoipa::path(
    get,
    path = "/v1/signals/corroborator/cache",
    tag = "signals",
    params(
        ("limit"  = Option<u32>,    Query, description = "Page size, default 100, max 1000"),
        ("source" = Option<String>, Query, description = "Filter by signal source"),
    ),
    responses(
        (status = 200, description = "Cached corroborator listing", body = CachedCorroboratorsResponse),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin role required"),
    )
)]
pub async fn list_cached_corroborators_handler(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<CachedCorroboratorsQuery>,
) -> Result<Json<CachedCorroboratorsResponse>, StatusCode> {
    use crate::domain::OperatorRole;
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_role(&state, &auth_session, auth_header, OperatorRole::Admin)?;

    let limit = query.limit.unwrap_or(100).clamp(1, 1000) as i64;
    let now = chrono::Utc::now();
    let signals = state
        .repo
        .list_cached_corroborators(now, limit, query.source.as_deref())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // When ?source= is provided, scope total + by_source to that
    // source as well so the response is internally consistent
    // (otherwise clients see a `total` that doesn't match the rows
    // they were just handed).
    let by_source_rows = state
        .repo
        .count_cached_corroborators_by_source(now)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let by_source_rows: Vec<(String, u64)> = match query.source.as_deref() {
        Some(filter) => by_source_rows
            .into_iter()
            .filter(|(s, _)| s == filter)
            .collect(),
        None => by_source_rows,
    };
    let total = by_source_rows.iter().map(|(_, n)| *n).sum();
    let by_source = by_source_rows
        .into_iter()
        .map(|(source, count)| CachedCorroboratorBySource { source, count })
        .collect();
    Ok(Json(CachedCorroboratorsResponse {
        now,
        total,
        by_source,
        signals,
    }))
}

/// Recompute a signal group's derived_confidence, source_count and
/// corroboration_met flag from its events (including corroborators).
///
/// PR B: this path now re-resolves the playbook-specific correlation
/// override using the stored `playbook_name` on the group, and is
/// allowed to flip `corroboration_met` from false→true even when the
/// triggering ingest was a corroborator. We deliberately do NOT
/// actuate a mitigation from here — the next primary-path event will
/// pick up the flipped flag and trigger normally. This keeps mitigation
/// actuation single-sourced through `handle_ban`.
async fn recompute_group_aggregates(state: &Arc<AppState>, group_id: Uuid) -> Result<(), AppError> {
    use crate::correlation::CorrelationEngine;

    let group = match state
        .repo
        .get_signal_group(group_id)
        .await
        .map_err(AppError)?
    {
        Some(g) => g,
        None => return Ok(()),
    };

    let events = state
        .repo
        .list_signal_group_events(group_id)
        .await
        .map_err(AppError)?;

    let sources: Vec<String> = events.iter().filter_map(|e| e.source.clone()).collect();
    let count = CorrelationEngine::count_distinct_sources(&sources);

    let has_primary = events.iter().any(|e| !e.is_corroborating);

    // Resolve the playbook override using the group's stored playbook_name.
    // If the group was created before PR B (playbook_name is NULL) or the
    // playbook has since been removed, fall back to the conservative
    // pre-PR-B behavior: aggregates update, but we don't flip
    // corroboration_met → true on the corroborator path.
    let was_met = group.corroboration_met;
    let mut newly_met = false;
    let correlation_config = state.correlation_config.read().await.clone();
    let playbooks = state.playbooks.read().await.clone();
    let resolved_playbook = group
        .playbook_name
        .as_deref()
        .and_then(|name| playbooks.playbooks.iter().find(|p| p.name == name));
    let playbook_override_for_decay = resolved_playbook.and_then(|p| p.correlation.as_ref());
    let half_life = correlation_config.effective_decay_half_life(playbook_override_for_decay);
    let triples: Vec<crate::correlation::ConfidenceTriple> = events
        .iter()
        .map(|e| (e.confidence, e.source_weight, e.ingested_at))
        .collect();
    let derived = CorrelationEngine::compute_derived_confidence_decayed(
        &triples,
        chrono::Utc::now(),
        half_life,
    );

    let new_met = if has_primary {
        let override_ = playbook_override_for_decay;
        match (resolved_playbook, group.playbook_name.as_deref()) {
            (Some(_), _) => {
                let met = CorrelationEngine::check_corroboration_with_primary(
                    count,
                    derived,
                    has_primary,
                    &correlation_config,
                    override_,
                );
                if met && !was_met {
                    newly_met = true;
                }
                // ADR 022 one-shot semantics: corroboration_met is sticky
                // once true. Decay can lower derived_confidence below the
                // threshold but must not undo a mitigation decision that
                // already triggered.
                met || was_met
            }
            (None, Some(missing)) => {
                tracing::debug!(target: "prefixd::api::handlers",
                    group_id = %group_id,
                    playbook = %missing,
                    "stored playbook_name no longer resolves; keeping previous corroboration_met"
                );
                was_met
            }
            (None, None) => {
                // Pre-PR-B group with no resolved playbook yet — preserve
                // previous behavior.
                was_met
            }
        }
    } else {
        // No primary event yet → invariant: corroboration cannot be met
        // unless it was already true (sticky).
        was_met
    };

    if newly_met {
        tracing::info!(target: "prefixd::api::handlers",
            group_id = %group_id,
            derived_confidence = derived,
            source_count = count,
            playbook = ?group.playbook_name,
            "signal group reached corroboration threshold via corroborator path; awaiting next primary event to actuate mitigation"
        );
    }

    let mut updated = group;
    updated.derived_confidence = derived;
    updated.source_count = count;
    updated.corroboration_met = new_met;
    state
        .repo
        .update_signal_group(&updated)
        .await
        .map_err(AppError)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        FastNetMonAttackDetails, FastNetMonPayload, classify_fastnetmon,
        classify_fastnetmon_vector, parse_port_list,
    };
    use crate::config::AmplificationConfig;
    use crate::domain::AttackVector;
    use chrono::Utc;
    use serde_json::json;

    /// FastNetMon native JSON in the v1.2.9 shape: `packet_dump_detailed`
    /// entries carry `serialize_simple_packet_to_json`'s fields. 123 has 9 of 20
    /// sampled UDP packets, 11211 has 6 and 53 has 1.
    const NATIVE_FIXTURE: &str =
        include_str!("../../../tests/fixtures/fastnetmon/native-ntp-memcached.json");

    fn native(edit: impl FnOnce(&mut serde_json::Value)) -> FastNetMonPayload {
        let mut payload: serde_json::Value = serde_json::from_str(NATIVE_FIXTURE).unwrap();
        edit(&mut payload);
        serde_json::from_value(payload).unwrap()
    }

    fn classify(payload: &FastNetMonPayload) -> (AttackVector, Option<Vec<u16>>) {
        classify_fastnetmon(payload, &AmplificationConfig::default())
    }

    #[test]
    fn native_dump_classifies_amplification_with_ranked_library_ports() {
        assert_eq!(
            classify(&native(|_| {})),
            (AttackVector::UdpAmplification, Some(vec![123, 11211]))
        );
    }

    #[test]
    fn native_dump_below_share_stays_udp_flood() {
        // A random-source-port flood: 53 is a library port, but at 1 of 21
        // sampled packets it is below 0.2.
        let payload = native(|p| {
            let dump = p["packet_dump_detailed"].as_array_mut().unwrap();
            dump.retain(|sample| sample["source_port"] != 123 && sample["source_port"] != 11211);
            for port in 0..16u16 {
                let mut sample = dump[0].clone();
                sample["source_port"] = json!(20000 + port);
                dump.push(sample);
            }
        });
        assert_eq!(classify(&payload), (AttackVector::UdpFlood, None));
        // A higher threshold drops 11211 (0.3) and keeps 123 (0.45).
        let amplification = AmplificationConfig {
            min_src_port_share: 0.4,
            ..Default::default()
        };
        assert_eq!(
            classify_fastnetmon(&native(|_| {}), &amplification),
            (AttackVector::UdpAmplification, Some(vec![123]))
        );
    }

    #[test]
    fn native_ports_outside_the_library_do_not_count() {
        let amplification = AmplificationConfig {
            reflector_ports: Some(vec![crate::config::ReflectorPort {
                port: 11211,
                name: "memcached".into(),
            }]),
            ..Default::default()
        };
        assert_eq!(
            classify_fastnetmon(&native(|_| {}), &amplification),
            (AttackVector::UdpAmplification, Some(vec![11211]))
        );
        let disabled = AmplificationConfig {
            reflector_ports: Some(vec![]),
            ..Default::default()
        };
        assert_eq!(
            classify_fastnetmon(&native(|_| {}), &disabled),
            (AttackVector::UdpFlood, None)
        );
    }

    #[test]
    fn native_tcp_and_icmp_are_never_amplification() {
        for (counter, expected) in [
            ("incoming_syn_tcp_pps", AttackVector::SynFlood),
            ("incoming_tcp_pps", AttackVector::AckFlood),
            ("incoming_icmp_pps", AttackVector::IcmpFlood),
        ] {
            // The dump still shows UDP reflection, but the counters say otherwise.
            let payload = native(|p| {
                p["attack_details"]["incoming_udp_pps"] = json!(1000);
                p["attack_details"][counter] = json!(9_000_000);
            });
            assert_eq!(classify(&payload), (expected, None), "{counter}");
        }
        // TCP samples from a library port are not UDP samples.
        let payload = native(|p| {
            for sample in p["packet_dump_detailed"].as_array_mut().unwrap() {
                sample["protocol"] = json!("tcp");
            }
        });
        assert_eq!(classify(&payload), (AttackVector::UdpFlood, None));
    }

    #[test]
    fn native_malformed_or_empty_dump_falls_back() {
        for dump in [
            json!(null),
            json!([]),
            json!("not an array"),
            json!({"protocol": "udp", "source_port": 123, "packets": 1}),
            json!([
                {"protocol": "udp", "source_port": 70000, "packets": 5},
                {"protocol": "udp", "source_port": "123", "packets": 5},
                {"protocol": "udp", "source_port": 123, "packets": -1},
                {"protocol": "udp", "source_port": 123},
                {"protocol": "icmp", "packets": 9},
                "garbage"
            ]),
            json!([{"protocol": "udp", "source_port": 123, "packets": 0}]),
        ] {
            let payload = native(|p| p["packet_dump_detailed"] = dump.clone());
            assert_eq!(classify(&payload), (AttackVector::UdpFlood, None), "{dump}");
        }
        let payload = native(|p| {
            p.as_object_mut().unwrap().remove("packet_dump_detailed");
        });
        assert_eq!(classify(&payload), (AttackVector::UdpFlood, None));
        let payload = native(|p| {
            p.as_object_mut().unwrap().remove("attack_details");
        });
        assert_eq!(classify(&payload), (AttackVector::Unknown, None));
    }

    #[test]
    fn alertmanager_port_lists_parse_or_reject_whole() {
        assert_eq!(parse_port_list("123"), Some(vec![123]));
        assert_eq!(
            parse_port_list(" 123, 11211 ,53"),
            Some(vec![123, 11211, 53])
        );
        for raw in ["", " ", "123,", "123,,53", "ntp", "70000", "-1", "123;53"] {
            assert_eq!(parse_port_list(raw), None, "{raw:?}");
        }
    }

    #[tokio::test]
    async fn confidence_typed_nonfinite_inputs_are_rejected_at_shared_ingestion_boundaries() {
        use crate::bgp::MockAnnouncer;
        use crate::config::{BgpMode, Inventory, Playbooks, Settings};
        use crate::correlation::{MatchDimension, SourceConfig, SourceMode};
        use crate::db::{ListParams, MockRepository, RepositoryTrait};
        use crate::domain::AttackEventInput;
        use std::sync::Arc;

        let mut settings: Settings =
            crate::config::parse_yaml(include_str!("../../../configs/prefixd.yaml")).unwrap();
        settings.bgp.mode = BgpMode::Mock;
        settings.http.auth.mode = crate::config::AuthMode::None;
        settings.correlation.enabled = true;
        settings.correlation.sources.insert(
            "typed-corrob".into(),
            SourceConfig {
                mode: SourceMode::Corroborating,
                match_dimensions: vec![MatchDimension::Pop],
                ..Default::default()
            },
        );
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(MockAnnouncer::new());
        let state = crate::AppState::new(
            settings,
            Inventory::new(vec![]),
            Playbooks { playbooks: vec![] },
            repo.clone(),
            speaker.clone(),
            ".".into(),
        )
        .unwrap();
        for confidence in [
            f32::NAN,
            f32::INFINITY,
            f32::NEG_INFINITY,
            -f32::EPSILON,
            1.0 + f32::EPSILON,
        ] {
            let mut input: AttackEventInput = serde_json::from_value(serde_json::json!({
                "timestamp": Utc::now(), "source": "typed-primary",
                "victim_ip": "203.0.113.10", "vector": "udp_flood",
            }))
            .unwrap();
            input.confidence = Some(confidence);
            for result in [
                super::handle_ban(state.clone(), input.clone()).await,
                super::handle_unban(state.clone(), input).await,
            ] {
                let error = match result {
                    Err(error) => error,
                    Ok(_) => panic!("invalid typed confidence accepted"),
                };
                assert_eq!(error.0.status_code(), axum::http::StatusCode::BAD_REQUEST);
                assert!(error.0.to_string().contains("confidence must be finite"));
            }
            let input = super::CorroboratorInput {
                source: "typed-corrob".into(),
                vector: None,
                customer_id: None,
                pop: Some("typed-pop".into()),
                service_id: None,
                interface: None,
                confidence: Some(confidence),
                raw_details: None,
            };
            let error = match super::ingest_corroborator_inner(state.clone(), input).await {
                Err(error) => error,
                Ok(_) => panic!("invalid typed corroborator confidence accepted"),
            };
            assert_eq!(error.0.status_code(), axum::http::StatusCode::BAD_REQUEST);
            assert!(error.0.to_string().contains("confidence must be finite"));
        }
        assert!(
            repo.list_events(&ListParams {
                limit: 100,
                ..Default::default()
            })
            .await
            .unwrap()
            .is_empty()
        );
        assert!(repo.list_open_signal_groups().await.unwrap().is_empty());
        assert_eq!(
            repo.count_cached_corroborators(Utc::now()).await.unwrap(),
            0
        );
        assert_eq!(repo.count_active_global().await.unwrap(), 0);
        assert_eq!(speaker.announced_count().await, 0);
    }

    #[test]
    fn test_fastnetmon_syn_percentage_boundaries() {
        use AttackVector::{AckFlood, IcmpFlood, SynFlood, UdpFlood, Unknown};

        let max = i64::MAX;
        let scale = max / 100;
        for (name, tcp_pps, syn_pps, udp_pps, icmp_pps, expected) in [
            ("maximum", max, max, 0, 0, SynFlood),
            ("near maximum", max, max - 1, 0, 0, SynFlood),
            (
                "large below threshold",
                scale * 100,
                scale * 59,
                0,
                0,
                AckFlood,
            ),
            (
                "large exact threshold",
                scale * 100,
                scale * 60,
                0,
                0,
                AckFlood,
            ),
            (
                "large above threshold",
                scale * 100,
                scale * 61,
                0,
                0,
                SynFlood,
            ),
            ("below threshold", 100, 59, 0, 0, AckFlood),
            ("exact threshold", 100, 60, 0, 0, AckFlood),
            ("above threshold", 100, 61, 0, 0, SynFlood),
            ("fractional percent truncates", 1000, 609, 0, 0, AckFlood),
            (
                "integer percent exceeds threshold",
                1000,
                610,
                0,
                0,
                SynFlood,
            ),
            ("zero TCP", 0, 1, 0, 0, SynFlood),
            ("zero TCP with maximum SYN", 0, max, 0, 0, SynFlood),
            ("all zero", 0, 0, 0, 0, Unknown),
            ("negative TCP clamps denominator", -1, 1, 0, 0, SynFlood),
            ("negative SYN", 100, -1, 0, 0, AckFlood),
            ("minimum SYN", max, i64::MIN, 0, 0, AckFlood),
            (
                "negative counters retain protocol tie",
                -1,
                -1,
                -1,
                -2,
                UdpFlood,
            ),
            ("ordinary SYN", 1000, 700, 100, 0, SynFlood),
            ("UDP dominates SYN", 100, 90, 1000, 0, UdpFlood),
            ("ordinary TCP", 1000, 200, 100, 0, AckFlood),
            ("ordinary ICMP", 100, 0, 0, 1000, IcmpFlood),
        ] {
            let details: FastNetMonAttackDetails = serde_json::from_value(serde_json::json!({
                "incoming_tcp_pps": tcp_pps,
                "incoming_syn_tcp_pps": syn_pps,
                "incoming_udp_pps": udp_pps,
                "incoming_icmp_pps": icmp_pps,
            }))
            .unwrap();
            assert_eq!(classify_fastnetmon_vector(&details), expected, "{name}");
        }
    }
}
