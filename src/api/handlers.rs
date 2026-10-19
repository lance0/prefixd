mod accounts;
pub use accounts::{
    __path_change_password, __path_create_operator, __path_delete_operator, __path_get_me,
    __path_get_notification_preferences, __path_list_operators, __path_login, __path_logout,
    __path_update_notification_preferences, ChangePasswordRequest, CreateOperatorRequest,
    LoginRequest, LoginResponse, OperatorInfo, OperatorListResponse, change_password,
    create_operator, delete_operator, get_me, get_notification_preferences, list_operators, login,
    logout, update_notification_preferences,
};

mod configuration;
pub use configuration::{
    __path_get_alerting_config, __path_get_config_inventory, __path_get_config_playbooks,
    __path_get_config_settings, __path_get_correlation_config, __path_test_alerting,
    __path_update_alerting_config, __path_update_correlation_config, __path_update_playbooks,
    ConfigInventoryResponse, ConfigPlaybooksResponse, ConfigSettingsResponse, ReloadResponse,
    UpdatePlaybooksRequest, get_alerting_config, get_config_inventory, get_config_playbooks,
    get_config_settings, get_correlation_config, reload_config, test_alerting,
    update_alerting_config, update_correlation_config, update_playbooks,
};

mod observations;
pub use observations::{
    __path_generate_incident_report, __path_get_ip_history, __path_get_stats,
    __path_get_timeseries, __path_list_audit, __path_list_pops, AuditListResponse,
    IncidentReportQuery, IpHistoryResponse, TimeseriesQuery, TimeseriesResponse,
    generate_incident_report, get_ip_history, get_stats, get_timeseries, list_audit, list_pops,
    metrics,
};

mod safelist;
pub use safelist::{
    __path_add_safelist, __path_remove_safelist, AddSafelistRequest, add_safelist, list_safelist,
    remove_safelist,
};

mod signals;
pub use signals::{
    __path_get_corroborator_activity, __path_get_signal_group, __path_ingest_alertmanager,
    __path_ingest_corroborator, __path_ingest_fastnetmon, __path_ingest_webhook,
    __path_list_cached_corroborators_handler, __path_list_signal_groups, AlertmanagerAlert,
    AlertmanagerAlertResult, AlertmanagerWebhookPayload, AlertmanagerWebhookResponse,
    CachedCorroboratorBySource, CachedCorroboratorsQuery, CachedCorroboratorsResponse,
    CorroboratorActivityEntry, CorroboratorActivityQuery, CorroboratorActivityResponse,
    CorroboratorInput, CorroboratorResponse, FastNetMonAttackDetails, FastNetMonPayload,
    ListSignalGroupsQuery, SignalGroupDetailResponse, SignalGroupsListResponse, WebhookEventResult,
    WebhookResponse, get_corroborator_activity, get_signal_group, ingest_alertmanager,
    ingest_corroborator, ingest_fastnetmon, ingest_webhook, list_cached_corroborators_handler,
    list_signal_groups,
};

mod health;
pub use health::{
    __path_health, __path_health_detail, __path_ready, ComponentHealth, DaemonHealthObservation,
    HealthResponse, PublicHealthResponse, ReadinessResponse, ReadinessStatus, SpeakerHealth,
    health, health_detail, ready,
};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::IntoResponse,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;
use crate::db::{ListCursor, ListParams, MitigationCursor, MitigationListParams};
use crate::domain::{
    ActionParams, ActionType, AttackEvent, AttackEventInput, FlowSpecAction, MatchCriteria,
    Mitigation, MitigationIntent, MitigationRoute, MitigationStatus, execute_withdrawal,
    find_mitigation_owner, mitigation_rule, request_withdrawal, validate_confidence,
};
use crate::error::{GuardrailError, PrefixdError};
use crate::guardrails::Guardrails;
use crate::observability::CreationActor;
use crate::policy::PolicyEngine;

use super::auth::{require_auth, require_role};
use crate::auth::AuthSession;

fn encode_list_cursor(timestamp: DateTime<Utc>, id: Uuid, prefix: &str) -> String {
    let position = format!("{}\n{}", timestamp.to_rfc3339(), id);
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(position.as_bytes()))
}

fn decode_list_cursor(value: &str, prefix: &str) -> Option<ListCursor> {
    if value.len() > 128 || !value.is_ascii() {
        return None;
    }
    let encoded = value.strip_prefix(prefix)?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    let decoded = std::str::from_utf8(&bytes).ok()?;
    let (timestamp, id) = decoded.split_once('\n')?;
    Some(ListCursor {
        timestamp: DateTime::parse_from_rfc3339(timestamp)
            .ok()?
            .with_timezone(&Utc),
        id: id.parse().ok()?,
    })
}

const MAX_MITIGATION_CURSOR_LEN: usize = 128;
const MITIGATION_CURSOR_PREFIX: &str = "m1.";

fn encode_mitigation_cursor(mitigation: &Mitigation) -> String {
    let position = format!(
        "{}\n{}",
        mitigation.created_at.to_rfc3339(),
        mitigation.mitigation_id
    );
    format!(
        "{MITIGATION_CURSOR_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(position.as_bytes())
    )
}

fn decode_mitigation_cursor(value: &str) -> Option<MitigationCursor> {
    if value.len() > MAX_MITIGATION_CURSOR_LEN || !value.is_ascii() {
        return None;
    }
    let encoded = value.strip_prefix(MITIGATION_CURSOR_PREFIX)?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    let decoded = std::str::from_utf8(&bytes).ok()?;
    let (created_at, mitigation_id) = decoded.split_once('\n')?;
    Some(MitigationCursor {
        created_at: DateTime::parse_from_rfc3339(created_at)
            .ok()?
            .with_timezone(&Utc),
        mitigation_id: mitigation_id.parse().ok()?,
    })
}

// Response types

/// Outcome of this creation request, not persisted speaker or router status.
#[derive(Clone, Copy, Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AnnouncementOutcome {
    /// Desired intent committed, but this request did not receive a successful speaker reply.
    Unconfirmed,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct EventResponse {
    /// Present only when this creation request committed intent without a successful speaker reply.
    /// Omission is not evidence of enforcement; this outcome is not persisted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub announcement_outcome: Option<AnnouncementOutcome>,
    /// Unique identifier for this event
    pub event_id: Uuid,
    /// External event ID from the detector
    pub external_event_id: Option<String>,
    /// Processing status
    pub status: String,
    /// ID of the created mitigation, if any
    pub mitigation_id: Option<Uuid>,
}

/// Correlation context attached to a mitigation that was created via the
/// correlation engine's corroboration logic.
///
/// The list endpoint provides a lightweight summary with only the core fields
/// (signal_group_id, derived_confidence, source_count, corroboration_met).
/// The detail endpoint populates the full context including contributing_sources
/// and explanation.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CorrelationContext {
    /// Signal group ID that triggered this mitigation
    pub signal_group_id: Uuid,
    /// Derived confidence (weighted average of contributing events)
    pub derived_confidence: f32,
    /// Number of distinct detection sources
    pub source_count: i32,
    /// Whether corroboration threshold was met
    pub corroboration_met: bool,
    /// List of contributing detection sources (populated on detail endpoint only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contributing_sources: Option<Vec<String>>,
    /// Human-readable explanation of the correlation decision (populated on detail endpoint only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct MitigationResponse {
    /// Present only when this creation request committed intent without a successful speaker reply.
    /// Omission is not evidence of enforcement; this outcome is not persisted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub announcement_outcome: Option<AnnouncementOutcome>,
    /// Unique mitigation identifier
    pub mitigation_id: Uuid,
    /// Current status (pending, active, withdrawn, expired)
    pub status: String,
    /// Customer ID from inventory
    pub customer_id: Option<String>,
    /// Service ID from inventory
    pub service_id: Option<String>,
    /// POP where mitigation is active
    pub pop: String,
    /// Victim IP address being protected
    pub victim_ip: String,
    /// Attack vector type
    pub vector: String,
    /// Action type (discard, police)
    pub action_type: String,
    /// Rate limit in bps (for police action)
    pub rate_bps: Option<u64>,
    /// Destination prefix (CIDR)
    pub dst_prefix: String,
    /// IP protocol number (6=TCP, 17=UDP, 1=ICMP)
    pub protocol: Option<u8>,
    /// Destination ports
    pub dst_ports: Vec<u16>,
    /// When the mitigation was created
    pub created_at: String,
    /// When the mitigation was last updated
    pub updated_at: String,
    /// When the mitigation expires
    pub expires_at: String,
    /// When the mitigation was withdrawn (if applicable)
    pub withdrawn_at: Option<String>,
    /// ID of the event that triggered this mitigation
    pub triggering_event_id: Uuid,
    /// Most recent event associated with this mitigation
    pub last_event_id: Uuid,
    /// Scope hash for deduplication
    pub scope_hash: String,
    /// Reason for the mitigation
    pub reason: String,
    /// When the mitigation was acknowledged by an operator
    pub acknowledged_at: Option<String>,
    /// Operator who acknowledged the mitigation
    pub acknowledged_by: Option<String>,
    /// Operation mode that admitted this mitigation: `dry-run` or `enforced`.
    /// `null` when the row predates origin tracking; never infer enforcement from it.
    #[schema(example = "dry-run")]
    pub origin_mode: Option<String>,
    /// Correlation context (present when mitigation was created via
    /// corroboration from the signal correlation engine)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation: Option<CorrelationContext>,
}

impl From<&Mitigation> for MitigationResponse {
    fn from(m: &Mitigation) -> Self {
        Self {
            announcement_outcome: None,
            mitigation_id: m.mitigation_id,
            status: m.status.to_string(),
            customer_id: m.customer_id.clone(),
            service_id: m.service_id.clone(),
            pop: m.pop.clone(),
            victim_ip: m.victim_ip.clone(),
            vector: m.vector.to_string(),
            action_type: m.action_type.to_string(),
            rate_bps: m.action_params.rate_bps,
            dst_prefix: m.match_criteria.dst_prefix.clone(),
            protocol: m.match_criteria.protocol,
            dst_ports: m.match_criteria.dst_ports.clone(),
            created_at: m.created_at.to_rfc3339(),
            updated_at: m.updated_at.to_rfc3339(),
            expires_at: m.expires_at.to_rfc3339(),
            withdrawn_at: m.withdrawn_at.map(|t| t.to_rfc3339()),
            triggering_event_id: m.triggering_event_id,
            last_event_id: m.last_event_id,
            scope_hash: m.scope_hash.clone(),
            reason: m.reason.clone(),
            acknowledged_at: m.acknowledged_at.map(|t| t.to_rfc3339()),
            acknowledged_by: m.acknowledged_by.clone(),
            origin_mode: m.origin_mode.map(|mode| mode.as_str().to_owned()),
            // Correlation context is populated asynchronously by handlers
            // that have access to the signal group data. The basic From impl
            // sets it to None — callers enrich it when needed.
            correlation: None,
        }
    }
}

/// Maximum page size for list endpoints
const MAX_PAGE_LIMIT: u32 = 1000;

#[derive(Serialize, ToSchema)]
pub struct MitigationsListResponse {
    /// List of mitigations in this page
    mitigations: Vec<MitigationResponse>,
    /// Number of mitigations returned in this page
    count: usize,
    /// Cursor for the next page (null if no more pages)
    next_cursor: Option<String>,
    /// Whether there are more pages
    has_more: bool,
}

#[derive(Serialize, ToSchema)]
pub struct EventsListResponse {
    /// List of events in this page
    events: Vec<AttackEvent>,
    /// Number of events returned in this page
    count: usize,
    /// Cursor for the next page (null if no more pages)
    next_cursor: Option<String>,
    /// Whether there are more pages
    has_more: bool,
}

#[derive(Serialize, ToSchema)]
pub struct ErrorResponse {
    /// Error message
    error: String,
    /// Retry after seconds (for rate limiting)
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_seconds: Option<u32>,
}

// Request types

#[derive(Deserialize)]
pub struct CursorQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    start: Option<String>,
    end: Option<String>,
}

#[derive(Deserialize)]
pub struct ListMitigationsQuery {
    status: Option<String>,
    customer_id: Option<String>,
    /// Filter by victim IP address
    victim_ip: Option<String>,
    /// Exact POP filter; omission and literal "all" list every POP.
    pop: Option<String>,
    /// Filter by acknowledged status (true/false)
    acknowledged: Option<bool>,
    #[serde(default = "default_limit")]
    limit: u32,
    cursor: Option<String>,
    start: Option<String>,
    end: Option<String>,
}

fn default_limit() -> u32 {
    100
}

type DateRange = (Option<DateTime<Utc>>, Option<DateTime<Utc>>);

fn parse_date_range(start: Option<&str>, end: Option<&str>) -> crate::error::Result<DateRange> {
    let parse = |value: Option<&str>, name: &str| {
        value
            .map(|value| {
                value.parse::<DateTime<Utc>>().map_err(|_| {
                    PrefixdError::InvalidRequest(format!(
                        "invalid {name} filter; expected an RFC3339 timestamp"
                    ))
                })
            })
            .transpose()
    };
    Ok((parse(start, "start")?, parse(end, "end")?))
}

fn clamp_limit(limit: u32) -> u32 {
    limit.min(MAX_PAGE_LIMIT)
}

const MAX_STRING_LEN: usize = 1024;
const MAX_USERNAME_LEN: usize = 64;
fn validate_string_len(value: &str, field: &str, max: usize) -> Result<(), PrefixdError> {
    if value.len() > max {
        Err(PrefixdError::InvalidRequest(format!(
            "{} exceeds maximum length of {} bytes",
            field, max
        )))
    } else {
        Ok(())
    }
}

fn validate_ip(ip: &str) -> Result<IpAddr, PrefixdError> {
    ip.parse::<IpAddr>()
        .map_err(|_| PrefixdError::InvalidRequest(format!("invalid IP address: '{}'", ip)))
}

#[derive(Deserialize, ToSchema)]
pub struct CreateMitigationRequest {
    #[serde(default)]
    #[allow(
        dead_code,
        reason = "Caller-supplied actor is ignored; request authentication determines the actor"
    )]
    operator_id: String,
    reason: String,
    victim_ip: String,
    /// IP protocol: udp, tcp, icmp (IPv4 protocol 1), icmpv6 (IPv6 protocol 58), or any.
    /// An empty string also selects any protocol. ICMP selectors must match the victim's address family.
    #[schema(example = "icmpv6")]
    protocol: String,
    #[serde(default)]
    dst_ports: Vec<u16>,
    action: String,
    /// Positive bit rate exactly representable as an f32 bytes/second traffic rate for police.
    /// Must be omitted or null for discard.
    #[serde(default)]
    rate_bps: Option<u64>,
    ttl_seconds: u32,
    /// Optional ceiling for this creation's expiry; later detector extensions are separate.
    #[serde(default)]
    expires_at_cap: Option<DateTime<Utc>>,
}
#[derive(Deserialize)]
pub struct WithdrawRequest {
    #[serde(default)]
    #[allow(
        dead_code,
        reason = "Caller-supplied actor is ignored; request authentication determines the actor"
    )]
    operator_id: String,
    reason: String,
}
// Handlers

/// Ingest an attack event from a detector
#[utoipa::path(
    post,
    path = "/v1/events",
    tag = "events",
    request_body = AttackEventInput,
    responses(
        (status = 202, description = "Event accepted", body = EventResponse),
        (status = 400, description = "Invalid input, including non-finite or out-of-range confidence"),
        (status = 409, description = "Duplicate event"),
        (status = 422, description = "Guardrail rejection"),
    )
)]
pub async fn ingest_event(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Json(input): Json<AttackEventInput>,
) -> impl IntoResponse {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    if let Err(_status) = require_auth(&state, &auth_session, auth_header) {
        return Err(AppError(PrefixdError::Unauthorized(
            "authentication required".into(),
        )));
    }

    // Validate input
    validate_ip(&input.victim_ip).map_err(AppError)?;
    validate_string_len(&input.source, "source", MAX_STRING_LEN).map_err(AppError)?;
    validate_string_len(&input.victim_ip, "victim_ip", 45).map_err(AppError)?;
    if let Some(ref eid) = input.event_id {
        validate_string_len(eid, "event_id", MAX_STRING_LEN).map_err(AppError)?;
    }

    // Reject before branching so a corroborating source cannot use unban here either (ADR 021).
    reject_corroborating_source(&state, &input).await?;

    // Branch on action type
    match input.action.as_str() {
        "unban" => handle_unban(state, input).await,
        "ban" => handle_ban(state, input).await,
        unknown => {
            tracing::warn!(action = %unknown, "unknown action type");
            Err(AppError(PrefixdError::InvalidRequest(format!(
                "unknown action: '{}', expected 'ban' or 'unban'",
                unknown
            ))))
        }
    }
}

/// Caller holds the lifecycle mutex; commit desired state before any speaker mutation.
async fn persist_new_mitigation(
    state: &AppState,
    mitigation: &mut Mitigation,
    actor: &CreationActor,
) -> crate::error::Result<Option<AnnouncementOutcome>> {
    // Fail closed before persistence: only a FlowSpec rule can be announced here.
    let rule = mitigation_rule(mitigation)?;
    mitigation.activate();
    mitigation.origin_mode = Some(state.settings.mode);
    state
        .repo
        .admit_mitigation(
            mitigation,
            &state.settings.quotas,
            &state.settings.blackhole,
            actor,
        )
        .await
        .inspect_err(|error| {
            let reason = match error {
                PrefixdError::GuardrailViolation(GuardrailError::QuotaExceeded { .. }) => {
                    "QuotaExceeded"
                }
                PrefixdError::GuardrailViolation(GuardrailError::NewMitigationRateExceeded {
                    ..
                }) => "NewMitigationRateExceeded",
                _ => return,
            };
            crate::observability::metrics::GUARDRAIL_REJECTIONS
                .with_label_values(&[reason])
                .inc();
            tracing::warn!(error = %error, pop = %mitigation.pop, reason,
                "admission rejected new mitigation");
        })?;
    if state.is_dry_run() {
        return Ok(None);
    }
    let start = std::time::Instant::now();
    if mitigation.expires_at <= Utc::now() {
        tracing::warn!(mitigation_id = %mitigation.mitigation_id,
            "mitigation expired during persistence; announcement skipped");
        return Ok(Some(AnnouncementOutcome::Unconfirmed));
    }
    if let Err(error) = state.announcer.announce(&rule).await {
        tracing::warn!(mitigation_id = %mitigation.mitigation_id, error = %error,
            "mitigation intent retained after unconfirmed BGP announcement");
        return Ok(Some(AnnouncementOutcome::Unconfirmed));
    }
    crate::observability::metrics::ANNOUNCEMENTS_TOTAL
        .with_label_values(&["announced"])
        .inc();
    crate::observability::metrics::ANNOUNCEMENTS_LATENCY.observe(start.elapsed().as_secs_f64());
    Ok(None)
}

async fn withdraw_and_notify(
    state: &AppState,
    mitigation: &Mitigation,
    actor_type: &str,
    actor: &str,
    reason: String,
) -> crate::error::Result<Mitigation> {
    let binding = state.verified_speaker_binding()?;
    if mitigation.pop != state.settings.pop {
        return Err(PrefixdError::Conflict(
            "mitigation belongs to another POP".into(),
        ));
    }
    let request = request_withdrawal(
        state.repo.as_ref(),
        mitigation,
        false,
        actor_type,
        actor,
        reason,
        !state.is_dry_run(),
        binding,
    )
    .await?;
    let mitigation = execute_withdrawal(
        state.repo.as_ref(),
        state.announcer.as_ref(),
        state.is_dry_run(),
        &request,
        binding,
    )
    .await?;
    let (message, alert) = if request.is_expiry() {
        crate::observability::metrics::MITIGATIONS_EXPIRED
            .with_label_values(&[&mitigation.action_type.to_string(), &mitigation.pop])
            .inc();
        (
            crate::ws::WsMessage::MitigationExpired {
                mitigation_id: mitigation.mitigation_id.to_string(),
            },
            crate::alerting::Alert::mitigation_expired(&mitigation),
        )
    } else {
        crate::observability::metrics::MITIGATIONS_WITHDRAWN
            .with_label_values(&[
                mitigation.action_type.to_string().as_str(),
                mitigation.pop.as_str(),
                if request.actor_type == "detector" {
                    "detector_unban"
                } else {
                    "operator"
                },
            ])
            .inc();
        (
            crate::ws::WsMessage::MitigationWithdrawn {
                mitigation_id: mitigation.mitigation_id.to_string(),
            },
            crate::alerting::Alert::mitigation_withdrawn(&mitigation),
        )
    };
    let _ = state.ws_broadcast.send(message);
    state.alerting.read().await.notify(alert);
    Ok(mitigation)
}

/// Handle unban action - withdraw mitigation by external_event_id
async fn handle_unban(
    state: Arc<AppState>,
    input: AttackEventInput,
) -> Result<(StatusCode, Json<EventResponse>), AppError> {
    validate_confidence(input.confidence).map_err(AppError)?;
    let ext_id = match &input.event_id {
        Some(id) => id.clone(),
        None => {
            // No external ID, can't find the original event
            tracing::warn!(source = %input.source, "unban without event_id, ignoring");
            return Ok((
                StatusCode::ACCEPTED,
                Json(EventResponse {
                    announcement_outcome: None,
                    event_id: Uuid::new_v4(),
                    external_event_id: None,
                    status: "ignored_no_event_id".to_string(),
                    mitigation_id: None,
                }),
            ));
        }
    };

    let _mitigation_guard = state.mitigation_lock.lock().await;
    state.verified_speaker_binding().map_err(AppError)?;

    // Find original ban event
    let original_event = match state
        .repo
        .find_ban_event_by_external_id(&input.source, &ext_id)
        .await
    {
        Ok(Some(e)) => e,
        Ok(None) => {
            tracing::debug!(source = %input.source, external_id = %ext_id, "unban for unknown event");
            return Ok((
                StatusCode::ACCEPTED,
                Json(EventResponse {
                    announcement_outcome: None,
                    event_id: Uuid::new_v4(),
                    external_event_id: Some(ext_id),
                    status: "not_found".to_string(),
                    mitigation_id: None,
                }),
            ));
        }
        Err(e) => return Err(AppError(e)),
    };

    // Find active mitigation for this event
    let mitigation = match state
        .repo
        .find_active_by_triggering_event(original_event.event_id)
        .await
    {
        Ok(Some(m)) => m,
        Ok(None) => {
            tracing::debug!(event_id = %original_event.event_id, "no active mitigation for event");
            return Ok((
                StatusCode::ACCEPTED,
                Json(EventResponse {
                    announcement_outcome: None,
                    event_id: original_event.event_id,
                    external_event_id: Some(ext_id),
                    status: "no_active_mitigation".to_string(),
                    mitigation_id: None,
                }),
            ));
        }
        Err(e) => return Err(AppError(e)),
    };

    // Store the unban event
    let source = input.source.clone();
    let unban_event = AttackEvent::from_input(input);
    if let Err(e) = state.repo.insert_event(&unban_event).await {
        tracing::warn!(error = %e, "failed to insert unban event");
    }

    let mitigation = withdraw_and_notify(
        &state,
        &mitigation,
        "detector",
        &source,
        format!("Detector unban: {}", source),
    )
    .await
    .map_err(AppError)?;

    tracing::info!(
        mitigation_id = %mitigation.mitigation_id,
        victim_ip = %mitigation.victim_ip,
        "withdrew mitigation via detector unban"
    );

    Ok((
        StatusCode::ACCEPTED,
        Json(EventResponse {
            announcement_outcome: None,
            event_id: unban_event.event_id,
            external_event_id: unban_event.external_event_id,
            status: "withdrawn".to_string(),
            mitigation_id: Some(mitigation.mitigation_id),
        }),
    ))
}

/// A `mode: corroborating` source must never create a mitigation by itself (ADR 021).
async fn reject_corroborating_source(
    state: &AppState,
    input: &AttackEventInput,
) -> Result<(), AppError> {
    if state
        .correlation_config
        .read()
        .await
        .source_mode(&input.source)
        != crate::correlation::SourceMode::Corroborating
    {
        return Ok(());
    }
    tracing::warn!(
        source = %input.source,
        action = %input.action,
        "rejected /v1/events from corroborating-only source"
    );
    Err(AppError(PrefixdError::InvalidRequest(format!(
        "source '{}' is configured as mode=corroborating and cannot post to /v1/events. Use POST /v1/signals/corroborator instead.",
        input.source
    ))))
}

/// Handle ban action - create or extend mitigation
async fn handle_ban(
    state: Arc<AppState>,
    input: AttackEventInput,
) -> Result<(StatusCode, Json<EventResponse>), AppError> {
    // Every ban path (single, batch, signal adapters) routes through here.
    reject_corroborating_source(&state, &input).await?;
    validate_confidence(input.confidence).map_err(AppError)?;
    // shortcut: one controller per speaker; use a leader fence before supporting active-active controllers.
    let _mitigation_guard = state.mitigation_lock.lock().await;
    state.verified_speaker_binding().map_err(AppError)?;
    // Check for duplicate ban event (only bans are checked, not unbans)
    if let Some(ref ext_id) = input.event_id {
        if let Ok(Some(_)) = state
            .repo
            .find_ban_event_by_external_id(&input.source, ext_id)
            .await
        {
            crate::observability::metrics::EVENTS_REJECTED
                .with_label_values(&[input.source.as_str(), "duplicate"])
                .inc();
            return Err(AppError(PrefixdError::DuplicateEvent {
                detector_source: input.source.clone(),
                external_id: ext_id.clone(),
            }));
        }
    }

    // Create internal event
    let event = AttackEvent::from_input(input);

    let inventory = state.inventory.read().await;
    let context = inventory.lookup_ip(&event.victim_ip);
    let is_owned = context.is_some() || inventory.is_owned(&event.victim_ip);
    drop(inventory);
    let playbooks = state.playbooks.read().await.clone();
    let policy = PolicyEngine::new(
        playbooks.clone(),
        state.settings.pop.clone(),
        state.settings.timers.default_ttl_seconds,
    );
    let candidate_intent = match policy.evaluate(&event, context.as_ref()) {
        Err(
            error @ PrefixdError::GuardrailViolation(
                GuardrailError::NoAllowedPorts | GuardrailError::InvalidAction(_),
            ),
        ) => {
            crate::observability::metrics::EVENTS_REJECTED
                .with_label_values(&[event.source.as_str(), "guardrail"])
                .inc();
            let reason = if matches!(
                &error,
                PrefixdError::GuardrailViolation(GuardrailError::NoAllowedPorts)
            ) {
                "NoAllowedPorts"
            } else {
                "InvalidAction"
            };
            crate::observability::metrics::GUARDRAIL_REJECTIONS
                .with_label_values(&[reason])
                .inc();
            tracing::warn!(error = %error, "policy rejected mitigation");
            return Err(AppError(error));
        }
        result => result,
    };
    let mut existing_owner = None;
    // Reject before storing the detector ID so the same event remains retryable.
    if let Ok(intent) = &candidate_intent {
        existing_owner = find_mitigation_owner(
            state.repo.as_ref(),
            &state.settings.pop,
            &MitigationRoute::new(
                intent.action_type,
                &intent.match_criteria,
                &intent.action_params,
            ),
            &intent.match_criteria.scope_hash_for(intent.action_type),
        )
        .await
        .map_err(AppError)?;
        if let Some(owner) = &existing_owner {
            // Extending a simulation in enforced mode would leave the attack unmitigated.
            if owner.is_dry_run_origin() && !state.is_dry_run() {
                return Err(AppError(PrefixdError::Conflict(format!(
                    "FlowSpec rule is owned by a dry-run simulation; retire it with {}",
                    crate::domain::RETIRE_DRY_RUN_FLAG
                ))));
            }
            (FlowSpecAction {
                action_type: owner.action_type,
                rate_bps: owner.action_params.rate_bps,
            })
            .traffic_rate_bytes_per_second()
            .map_err(|error| {
                AppError(PrefixdError::GuardrailViolation(
                    GuardrailError::InvalidAction(error),
                ))
            })?;
        }
    }

    // Store event
    state.repo.insert_event(&event).await.map_err(AppError)?;

    crate::observability::metrics::EVENTS_INGESTED
        .with_label_values(&[&event.source, &event.attack_vector().to_string()])
        .inc();

    // Check if shutting down
    if state.is_shutting_down() {
        return Err(AppError(PrefixdError::ShuttingDown));
    }

    if !is_owned {
        tracing::warn!(victim_ip = %event.victim_ip, "event for unowned IP, skipping mitigation");
        return Ok((
            StatusCode::ACCEPTED,
            Json(EventResponse {
                announcement_outcome: None,
                event_id: event.event_id,
                external_event_id: event.external_event_id.clone(),
                status: "accepted_no_mitigation".to_string(),
                mitigation_id: None,
            }),
        ));
    }

    // ── Correlation step ───────────────────────────────────────────────
    // If correlation.enabled, find/create a signal group and add the event.
    // Check corroboration — if threshold not met, return 'accepted' without
    // creating a mitigation. If threshold met, proceed to policy evaluation.
    let correlation_config = state.correlation_config.read().await.clone();

    // Find the matching playbook's correlation override
    let vector = event.attack_vector();
    let event_ports = event.top_dst_ports();
    let has_ports = !event_ports.is_empty();
    let matching_playbook = playbooks.find_playbook(vector, has_ports);
    let playbook_override = matching_playbook.and_then(|p| p.correlation.as_ref());

    let mut signal_group_id: Option<Uuid> = None;
    let mut correlation_context: Option<CorrelationContext> = None;

    if correlation_config.enabled {
        use crate::correlation::CorrelationEngine;

        let vector_str = event.vector.clone();

        // Build primary dimensions from settings + inventory context
        let mut new_group = CorrelationEngine::create_group(
            &event.victim_ip,
            &vector_str,
            correlation_config.window_seconds,
        );
        new_group
            .primary_dimensions
            .add_pop(state.settings.pop.clone());
        if let Some(ctx) = context.as_ref() {
            new_group
                .primary_dimensions
                .add_customer(ctx.customer_id.clone());
            if let Some(sid) = ctx.service_id.as_ref() {
                new_group.primary_dimensions.add_service(sid.clone());
            }
            if let Some(interface) = ctx.interface.as_ref() {
                new_group
                    .primary_dimensions
                    .add_interface(interface.clone());
            }
        }
        // Remember the resolved playbook on the group so the corroborator
        // path (PR B) can re-resolve the override at recompute time.
        new_group.playbook_name = matching_playbook.map(|p| p.name.clone());
        let group = state
            .repo
            .insert_signal_group(&new_group)
            .await
            .map_err(AppError)?;

        // If we joined an existing group, union its stored dimensions with
        // this event's so that future corroborators can match on any primary
        // event's dimensions, not just the first one's.
        let mut group = group;
        let mut dims_changed = false;
        if let Some(ctx) = context.as_ref() {
            let before = group.primary_dimensions.clone();
            group
                .primary_dimensions
                .add_customer(ctx.customer_id.clone());
            if let Some(sid) = ctx.service_id.as_ref() {
                group.primary_dimensions.add_service(sid.clone());
            }
            if let Some(interface) = ctx.interface.as_ref() {
                group.primary_dimensions.add_interface(interface.clone());
            }
            group.primary_dimensions.add_pop(state.settings.pop.clone());
            dims_changed = before != group.primary_dimensions;
        }
        // Backfill playbook_name on existing groups created before PR B (or
        // before any primary event resolved a playbook). COALESCE in
        // update_signal_group keeps an existing non-NULL value stable.
        let playbook_changed = group.playbook_name.is_none() && matching_playbook.is_some();
        if playbook_changed {
            group.playbook_name = matching_playbook.map(|p| p.name.clone());
        }
        if dims_changed || playbook_changed {
            state
                .repo
                .update_signal_group(&group)
                .await
                .map_err(AppError)?;
        }

        let is_new_group = group.group_id == new_group.group_id;
        if is_new_group {
            crate::observability::metrics::SIGNAL_GROUPS_TOTAL
                .with_label_values(&["open", &vector_str])
                .inc();
        }

        // Add event to the group
        let source_weight = correlation_config.source_weight(&event.source);
        let _ = state
            .repo
            .add_event_to_group(group.group_id, event.event_id, source_weight)
            .await
            .map_err(AppError)?;

        // Drain any cached corroborating signals whose dimensions match this
        // event's dimensions and vector. Attach them to the group and record
        // the back-reference on the signal (so cache sweep won't double-apply).
        let event_dims = {
            let mut d = crate::correlation::EventDimensions::default();
            d.add_pop(&state.settings.pop);
            if let Some(ctx) = context.as_ref() {
                d.add_customer(ctx.customer_id.clone());
                if let Some(sid) = ctx.service_id.as_ref() {
                    d.add_service(sid.clone());
                }
                if let Some(interface) = ctx.interface.as_ref() {
                    d.add_interface(interface.clone());
                }
            }
            d
        };
        if !event_dims.is_empty() {
            let matches = state
                .repo
                .find_matching_corroborators(&vector_str, &event_dims, Utc::now())
                .await
                .map_err(AppError)?;
            for sig in &matches {
                let declared = correlation_config.match_dimensions(&sig.source);
                if !CorrelationEngine::corroborator_matches_declared(
                    sig,
                    &group.vector,
                    &event_dims,
                    declared,
                ) {
                    continue;
                }
                if sig.attached_group_ids.contains(&group.group_id) {
                    continue;
                }
                let attached = state
                    .repo
                    .add_corroborator_event_to_group(group.group_id, sig)
                    .await
                    .map_err(AppError)?;
                if attached {
                    state
                        .repo
                        .mark_corroborator_attached(sig.signal_id, group.group_id)
                        .await
                        .map_err(AppError)?;
                    crate::observability::metrics::CORROBORATOR_ATTACHED_TOTAL
                        .with_label_values(&[&sig.source])
                        .inc();
                }
            }
        }

        // Recompute derived confidence from all events in group
        let group_events = state
            .repo
            .list_signal_group_events(group.group_id)
            .await
            .map_err(AppError)?;

        let confidence_triples: Vec<crate::correlation::ConfidenceTriple> = group_events
            .iter()
            .map(|ge| (ge.confidence, ge.source_weight, ge.ingested_at))
            .collect();
        let half_life = correlation_config.effective_decay_half_life(playbook_override);
        let derived_confidence = CorrelationEngine::compute_derived_confidence_decayed(
            &confidence_triples,
            chrono::Utc::now(),
            half_life,
        );

        let source_names: Vec<String> = group_events
            .iter()
            .filter_map(|ge| ge.source.clone())
            .collect();
        let source_count = CorrelationEngine::count_distinct_sources(&source_names);

        let corroboration_met = CorrelationEngine::check_corroboration(
            source_count,
            derived_confidence,
            &correlation_config,
            playbook_override,
        );

        // Update group in DB
        let mut updated_group = group.clone();
        updated_group.derived_confidence = derived_confidence;
        updated_group.source_count = source_count;
        updated_group.corroboration_met = corroboration_met;
        state
            .repo
            .update_signal_group(&updated_group)
            .await
            .map_err(AppError)?;

        // Record correlation metrics
        crate::observability::metrics::CORRELATION_CONFIDENCE
            .with_label_values(&[&vector_str])
            .observe(derived_confidence as f64);

        if !corroboration_met {
            // Signal recorded but corroboration not met — no mitigation
            tracing::info!(
                group_id = %group.group_id,
                source_count = source_count,
                derived_confidence = derived_confidence,
                "signal recorded, corroboration not met — no mitigation"
            );
            return Ok((
                StatusCode::ACCEPTED,
                Json(EventResponse {
                    announcement_outcome: None,
                    event_id: event.event_id,
                    external_event_id: event.external_event_id.clone(),
                    status: "accepted".to_string(),
                    mitigation_id: None,
                }),
            ));
        }

        // Corroboration met — proceed to create mitigation
        crate::observability::metrics::CORROBORATION_MET_TOTAL
            .with_label_values(&[&vector_str])
            .inc();
        crate::observability::metrics::SIGNAL_GROUP_SOURCES
            .with_label_values(&[&vector_str])
            .observe(source_count as f64);

        signal_group_id = Some(group.group_id);

        // Build contributing sources list
        let unique_sources: Vec<String> = {
            let mut seen = std::collections::HashSet::new();
            source_names
                .into_iter()
                .filter(|s| seen.insert(s.clone()))
                .collect()
        };

        // Build explanation
        let contributions: Vec<crate::correlation::SourceContribution> = group_events
            .iter()
            .map(|ge| {
                let conf = ge.confidence.unwrap_or(0.0);
                crate::correlation::SourceContribution {
                    source: ge.source.clone().unwrap_or_default(),
                    confidence: conf,
                    weight: ge.source_weight,
                    weighted_confidence: conf * ge.source_weight,
                }
            })
            .collect();

        let explanation = CorrelationEngine::compute_explanation(
            &updated_group,
            contributions,
            &correlation_config,
            playbook_override,
        );

        correlation_context = Some(CorrelationContext {
            signal_group_id: group.group_id,
            derived_confidence,
            source_count,
            corroboration_met: true,
            contributing_sources: Some(unique_sources),
            explanation: Some(explanation.explanation),
        });

        tracing::info!(
            group_id = %group.group_id,
            source_count = source_count,
            derived_confidence = derived_confidence,
            "corroboration met, creating mitigation"
        );
    }

    // ── Policy evaluation ──────────────────────────────────────────────

    let intent = match candidate_intent {
        Ok(i) => i,
        Err(e) => {
            tracing::warn!(error = %e, "policy evaluation failed");
            return Ok((
                StatusCode::ACCEPTED,
                Json(EventResponse {
                    announcement_outcome: None,
                    event_id: event.event_id,
                    external_event_id: event.external_event_id.clone(),
                    status: "accepted_no_playbook".to_string(),
                    mitigation_id: None,
                }),
            ));
        }
    };

    if let Some(mut existing) = existing_owner {
        // Extend TTL
        existing.extend_ttl(intent.ttl_seconds, event.event_id);
        state
            .repo
            .update_mitigation(&existing)
            .await
            .map_err(AppError)?;

        // Broadcast mitigation update via WebSocket
        let _ = state
            .ws_broadcast
            .send(crate::ws::WsMessage::MitigationUpdated {
                mitigation: MitigationResponse::from(&existing),
            });

        tracing::info!(
            mitigation_id = %existing.mitigation_id,
            "extended existing mitigation TTL"
        );

        return Ok((
            StatusCode::ACCEPTED,
            Json(EventResponse {
                announcement_outcome: None,
                event_id: event.event_id,
                external_event_id: event.external_event_id.clone(),
                status: "extended".to_string(),
                mitigation_id: Some(existing.mitigation_id),
            }),
        ));
    }

    let guardrails = Guardrails::with_timers(
        state.settings.guardrails.clone(),
        state.settings.quotas.clone(),
        &state.settings.timers,
    );

    let is_safelisted = state
        .repo
        .is_safelisted(&event.victim_ip)
        .await
        .map_err(AppError)?;

    if let Err(e) = guardrails
        .validate(&intent, state.repo.as_ref(), is_safelisted)
        .await
    {
        crate::observability::metrics::EVENTS_REJECTED
            .with_label_values(&[event.source.as_str(), "guardrail"])
            .inc();
        let reason = match &e {
            PrefixdError::GuardrailViolation(g) => format!("{:?}", g)
                .split_whitespace()
                .next()
                .unwrap_or("unknown")
                .to_string(),
            _ => "unknown".to_string(),
        };
        crate::observability::metrics::GUARDRAIL_REJECTIONS
            .with_label_values(&[&reason])
            .inc();
        tracing::warn!(error = %e, "guardrail rejected mitigation");
        return Err(AppError(e));
    }

    // Create mitigation
    let mut mitigation =
        Mitigation::from_intent(intent, event.victim_ip.clone(), event.attack_vector());
    mitigation.signal_group_id = signal_group_id;

    let actor = CreationActor::Detector(event.source.clone());
    let announcement_outcome = persist_new_mitigation(&state, &mut mitigation, &actor)
        .await
        .inspect_err(|error| {
            if matches!(
                error,
                PrefixdError::GuardrailViolation(
                    GuardrailError::QuotaExceeded { .. }
                        | GuardrailError::NewMitigationRateExceeded { .. }
                )
            ) {
                crate::observability::metrics::EVENTS_REJECTED
                    .with_label_values(&[event.source.as_str(), "guardrail"])
                    .inc();
            }
        })
        .map_err(AppError)?;

    crate::observability::metrics::MITIGATIONS_CREATED
        .with_label_values(&[&mitigation.action_type.to_string(), &state.settings.pop])
        .inc();

    if let Some(group_id) = signal_group_id {
        if let Ok(Some(mut group)) = state.repo.get_signal_group(group_id).await {
            group.status = crate::correlation::SignalGroupStatus::Resolved;
            if let Err(e) = state.repo.update_signal_group(&group).await {
                tracing::warn!(error = %e, group_id = %group.group_id, "failed to mark signal group resolved");
            }
        }
    }

    // Build response with optional correlation context
    let mut mit_response = MitigationResponse::from(&mitigation);
    mit_response.correlation = correlation_context;

    // Broadcast new mitigation via WebSocket
    let _ = state
        .ws_broadcast
        .send(crate::ws::WsMessage::MitigationCreated {
            mitigation: mit_response.clone(),
        });

    state
        .alerting
        .read()
        .await
        .notify(crate::alerting::Alert::mitigation_created(&mitigation));

    tracing::info!(
        mitigation_id = %mitigation.mitigation_id,
        victim_ip = %mitigation.victim_ip,
        action = %mitigation.action_type,
        signal_group_id = ?mitigation.signal_group_id,
        "created mitigation"
    );

    Ok((
        StatusCode::ACCEPTED,
        Json(EventResponse {
            announcement_outcome,
            event_id: event.event_id,
            external_event_id: event.external_event_id.clone(),
            status: "accepted".to_string(),
            mitigation_id: Some(mitigation.mitigation_id),
        }),
    ))
}

/// List events
#[utoipa::path(
    get,
    path = "/v1/events",
    tag = "events",
    params(
        ("limit" = Option<u32>, Query, description = "Max results (default 100, max 1000)"),
        ("cursor" = Option<String>, Query, description = "Opaque e1 continuation from next_cursor (max 128 bytes); superseded timestamp-only cursors are rejected"),
        ("start" = Option<String>, Query, description = "Inclusive RFC3339 start; empty or malformed supplied values are invalid"),
        ("end" = Option<String>, Query, description = "Exclusive RFC3339 end; empty or malformed supplied values are invalid"),
    ),
    responses(
        (status = 200, description = "List of events", body = EventsListResponse),
        (status = 400, description = "Invalid date filter or invalid/superseded event cursor", body = ErrorResponse)
    )
)]
pub async fn list_events(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Query(query): Query<CursorQuery>,
) -> Result<axum::response::Response, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

    let limit = clamp_limit(query.limit.unwrap_or(100));
    let cursor = match query.cursor.as_deref() {
        None => None,
        Some(value) => match decode_list_cursor(value, "e1.") {
            Some(cursor) => Some(cursor),
            None => return Ok(AppError(PrefixdError::InvalidRequest(
                "invalid event cursor; use next_cursor from a fresh event listing (e1, at most 128 bytes)".into(),
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

    let mut events = state
        .repo
        .list_events(&params)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let has_more = events.len() > limit as usize;
    if has_more {
        events.truncate(limit as usize);
    }
    let next_cursor = if has_more {
        events
            .last()
            .map(|e| encode_list_cursor(e.ingested_at, e.event_id, "e1."))
    } else {
        None
    };
    let count = events.len();
    Ok(Json(EventsListResponse {
        events,
        count,
        next_cursor,
        has_more,
    })
    .into_response())
}

/// List mitigations with optional filters
#[utoipa::path(
    get,
    path = "/v1/mitigations",
    tag = "mitigations",
    params(
        ("status" = Option<String>, Query, description = "Comma-separated exact statuses: pending, active, expired, withdrawn, rejected (legacy escalated is still accepted but never produced); every token must be valid and nonempty"),
        ("customer_id" = Option<String>, Query, description = "Filter by customer ID"),
        ("victim_ip" = Option<String>, Query, description = "Filter by victim IP address"),
        ("pop" = Option<String>, Query, description = "Exact case-sensitive POP; omitted or literal 'all' lists every POP. Empty/NUL identifiers are invalid."),
        ("acknowledged" = Option<bool>, Query, description = "Filter by acknowledged status"),
        ("limit" = Option<u32>, Query, description = "Max results (default 100)"),
        ("cursor" = Option<String>, Query, description = "Opaque m1 continuation from next_cursor (max 128 bytes); superseded timestamp-only cursors are rejected"),
        ("start" = Option<String>, Query, description = "Inclusive RFC3339 start; empty or malformed supplied values are invalid"),
        ("end" = Option<String>, Query, description = "Exclusive RFC3339 end; empty or malformed supplied values are invalid"),
    ),
    responses(
        (status = 200, description = "List of mitigations", body = MitigationsListResponse),
        (status = 400, description = "Invalid date/status/POP filter or invalid/superseded mitigation cursor", body = ErrorResponse)
    )
)]
pub async fn list_mitigations(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Query(query): Query<ListMitigationsQuery>,
) -> Result<axum::response::Response, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

    let status_filter = match query
        .status
        .as_deref()
        .map(|value| {
            value
                .split(',')
                .map(str::parse)
                .collect::<std::result::Result<Vec<MitigationStatus>, _>>()
        })
        .transpose()
    {
        Ok(status) => status,
        Err(_) => return Ok(AppError(PrefixdError::InvalidRequest(
            "invalid status filter; expected comma-separated pending, active, escalated, expired, withdrawn or rejected".into(),
        )).into_response()),
    };

    let limit = clamp_limit(query.limit);
    let cursor = match query.cursor.as_deref() {
        None => None,
        Some(value) => match decode_mitigation_cursor(value) {
            Some(cursor) => Some(cursor),
            None => return Ok(AppError(PrefixdError::InvalidRequest(
                "invalid mitigation cursor; use next_cursor from a fresh mitigation listing (m1, at most 128 bytes)".into(),
            )).into_response()),
        },
    };
    let pop = match query.pop.as_deref() {
        None | Some("all") => None,
        Some(value) if value.is_empty() || value.contains('\0') => {
            return Ok(AppError(PrefixdError::InvalidRequest(
                "invalid POP filter; use a nonempty identifier without NUL, or omit pop to list every POP".into(),
            )).into_response());
        }
        Some(value) => Some(value.to_owned()),
    };
    let (start, end) = match parse_date_range(query.start.as_deref(), query.end.as_deref()) {
        Ok(bounds) => bounds,
        Err(error) => return Ok(AppError(error).into_response()),
    };
    let params = MitigationListParams {
        pop,
        limit: limit + 1,
        cursor,
        start,
        end,
    };

    let mut mitigations = state
        .repo
        .list_mitigations(
            status_filter.as_deref(),
            query.customer_id.as_deref(),
            query.victim_ip.as_deref(),
            query.acknowledged,
            &params,
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let has_more = mitigations.len() > limit as usize;
    if has_more {
        mitigations.truncate(limit as usize);
    }
    let next_cursor = if has_more {
        mitigations.last().map(encode_mitigation_cursor)
    } else {
        None
    };
    let count = mitigations.len();

    // Collect signal group IDs and fetch group data for correlation summaries
    let group_ids: Vec<Uuid> = mitigations
        .iter()
        .filter_map(|m| m.signal_group_id)
        .collect();

    let mut group_map = std::collections::HashMap::new();
    for gid in &group_ids {
        if let Ok(Some(g)) = state.repo.get_signal_group(*gid).await {
            group_map.insert(g.group_id, g);
        }
    }

    let responses: Vec<_> = mitigations
        .iter()
        .map(|m| {
            let mut resp = MitigationResponse::from(m);
            // Add lightweight correlation summary for correlated mitigations
            if let Some(group_id) = m.signal_group_id {
                if let Some(group) = group_map.get(&group_id) {
                    resp.correlation = Some(CorrelationContext {
                        signal_group_id: group_id,
                        derived_confidence: group.derived_confidence,
                        source_count: group.source_count,
                        corroboration_met: group.corroboration_met,
                        contributing_sources: None,
                        explanation: None,
                    });
                }
            }
            resp
        })
        .collect();

    Ok(Json(MitigationsListResponse {
        mitigations: responses,
        count,
        next_cursor,
        has_more,
    })
    .into_response())
}

/// Get a specific mitigation by ID
#[utoipa::path(
    get,
    path = "/v1/mitigations/{id}",
    tag = "mitigations",
    params(
        ("id" = Uuid, Path, description = "Mitigation ID")
    ),
    responses(
        (status = 200, description = "Mitigation details", body = MitigationResponse),
        (status = 404, description = "Mitigation not found"),
    )
)]
pub async fn get_mitigation(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<MitigationResponse>, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

    let mitigation = state
        .repo
        .get_mitigation(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let mut response = MitigationResponse::from(&mitigation);

    // Enrich with correlation context if signal_group_id is set
    if let Some(group_id) = mitigation.signal_group_id {
        if let Ok(Some(group)) = state.repo.get_signal_group(group_id).await {
            if let Ok(events) = state.repo.list_signal_group_events(group_id).await {
                let correlation_config = state.correlation_config.read().await.clone();
                let playbooks = state.playbooks.read().await.clone();
                let playbook_override = playbooks
                    .find_playbook(
                        mitigation.vector,
                        !mitigation.match_criteria.dst_ports.is_empty(),
                    )
                    .and_then(|p| p.correlation.as_ref());

                let contributions: Vec<crate::correlation::SourceContribution> = events
                    .iter()
                    .map(|ge| {
                        let conf = ge.confidence.unwrap_or(0.0);
                        crate::correlation::SourceContribution {
                            source: ge.source.clone().unwrap_or_default(),
                            confidence: conf,
                            weight: ge.source_weight,
                            weighted_confidence: conf * ge.source_weight,
                        }
                    })
                    .collect();

                let unique_sources: Vec<String> = {
                    let mut seen = std::collections::HashSet::new();
                    events
                        .iter()
                        .filter_map(|ge| ge.source.clone())
                        .filter(|s| seen.insert(s.clone()))
                        .collect()
                };

                let explanation = crate::correlation::CorrelationEngine::compute_explanation(
                    &group,
                    contributions,
                    &correlation_config,
                    playbook_override,
                );

                response.correlation = Some(CorrelationContext {
                    signal_group_id: group.group_id,
                    derived_confidence: group.derived_confidence,
                    source_count: group.source_count,
                    corroboration_met: group.corroboration_met,
                    contributing_sources: Some(unique_sources),
                    explanation: Some(explanation.explanation),
                });
            }
        }
    }

    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/v1/mitigations",
    tag = "mitigations",
    request_body = CreateMitigationRequest,
    responses(
        (status = 201, description = "Mitigation intent created", body = MitigationResponse),
        (status = 202, description = "Intent created; announcement unconfirmed for this request", body = MitigationResponse),
        (status = 400, description = "Invalid input, including an unsupported action/rate or protocol/address-family mismatch"),
        (status = 409, description = "Conflicting owner or pending withdrawal"),
        (status = 422, description = "Guardrail rejection"),
    )
)]
pub async fn create_mitigation(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Json(req): Json<CreateMitigationRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    // Check auth first
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    use crate::domain::OperatorRole;
    let operator = require_role(&state, &auth_session, auth_header, OperatorRole::Operator)?;
    let operator_id = operator.username.clone();
    let _mitigation_guard = state.mitigation_lock.lock().await;
    if let Err(error) = state.verified_speaker_binding() {
        return Ok(AppError(error).into_response());
    }

    // Validate input
    let victim_ip = match validate_ip(&req.victim_ip) {
        Ok(ip) => ip,
        Err(error) => return Ok(AppError(error).into_response()),
    };
    if let Err(e) = validate_string_len(&req.reason, "reason", MAX_STRING_LEN) {
        return Ok(AppError(e).into_response());
    }
    if let Err(e) = validate_string_len(&operator_id, "operator_id", MAX_USERNAME_LEN) {
        return Ok(AppError(e).into_response());
    }

    // Validate protocol - reject unknown values instead of silently converting to None
    let protocol = match req.protocol.as_str() {
        "udp" => Some(17u8),
        "tcp" => Some(6u8),
        "icmp" if victim_ip.is_ipv4() => Some(1u8),
        "icmpv6" if victim_ip.is_ipv6() => Some(58u8),
        "icmp" | "icmpv6" => {
            return Ok(AppError(PrefixdError::InvalidRequest(format!(
                "protocol '{}' does not match victim IP address family",
                req.protocol
            )))
            .into_response());
        }
        "any" | "" => None,
        _ => {
            return Ok(AppError(PrefixdError::InvalidRequest(format!(
                "invalid protocol '{}', expected: udp, tcp, icmp, icmpv6, any",
                req.protocol
            )))
            .into_response());
        }
    };

    // Validate action type
    let action_type = match req.action.as_str() {
        "police" => ActionType::Police,
        "discard" => ActionType::Discard,
        _ => {
            return Ok(AppError(PrefixdError::InvalidRequest(format!(
                "invalid action '{}', expected: discard, police",
                req.action
            )))
            .into_response());
        }
    };

    if let Err(error) = (FlowSpecAction {
        action_type,
        rate_bps: req.rate_bps,
    })
    .traffic_rate_bytes_per_second()
    {
        return Ok(AppError(PrefixdError::InvalidRequest(error.to_string())).into_response());
    }

    let inventory = state.inventory.read().await;
    let customer_id = inventory.lookup_ip(&req.victim_ip).map(|c| c.customer_id);
    drop(inventory);
    let prefix_len = if victim_ip.is_ipv6() { 128 } else { 32 };
    let intent = MitigationIntent {
        event_id: Uuid::new_v4(),
        customer_id,
        service_id: None,
        pop: state.settings.pop.clone(),
        match_criteria: MatchCriteria {
            dst_prefix: format!("{}/{}", req.victim_ip, prefix_len),
            protocol,
            dst_ports: req.dst_ports,
            ..Default::default()
        },
        action_type,
        action_params: ActionParams {
            rate_bps: req.rate_bps,
        },
        ttl_seconds: req.ttl_seconds,
        reason: req.reason,
    };

    match find_mitigation_owner(
        state.repo.as_ref(),
        &state.settings.pop,
        &MitigationRoute::new(
            intent.action_type,
            &intent.match_criteria,
            &intent.action_params,
        ),
        &intent.match_criteria.scope_hash_for(intent.action_type),
    )
    .await
    {
        Ok(Some(_)) => {
            return Ok(AppError(PrefixdError::Conflict(
                "FlowSpec rule already has an active owner".into(),
            ))
            .into_response());
        }
        Ok(None) => {}
        Err(error) => return Ok(AppError(error).into_response()),
    }

    // Validate
    let guardrails = Guardrails::with_timers(
        state.settings.guardrails.clone(),
        state.settings.quotas.clone(),
        &state.settings.timers,
    );
    let is_safelisted = match state.repo.is_safelisted(&req.victim_ip).await {
        Ok(v) => v,
        Err(e) => return Ok(AppError(e).into_response()),
    };
    if let Err(e) = guardrails
        .validate(&intent, state.repo.as_ref(), is_safelisted)
        .await
    {
        let reason = match &e {
            PrefixdError::GuardrailViolation(g) => format!("{:?}", g)
                .split_whitespace()
                .next()
                .unwrap_or("unknown")
                .to_string(),
            _ => "unknown".to_string(),
        };
        crate::observability::metrics::GUARDRAIL_REJECTIONS
            .with_label_values(&[&reason])
            .inc();
        return Ok(AppError(e).into_response());
    }

    // Create and announce
    let mut mitigation =
        Mitigation::from_intent(intent, req.victim_ip, crate::domain::AttackVector::Unknown);
    if let Some(cap) = req.expires_at_cap {
        mitigation.expires_at = mitigation.expires_at.min(cap);
        if let Err(error) =
            guardrails.validate_remaining_ttl(mitigation.expires_at - mitigation.created_at)
        {
            crate::observability::metrics::GUARDRAIL_REJECTIONS
                .with_label_values(&["TtlOutOfBounds"])
                .inc();
            return Ok(AppError(error).into_response());
        }
    }

    let actor = CreationActor::Operator(operator_id);
    let announcement_outcome = match persist_new_mitigation(&state, &mut mitigation, &actor).await {
        Ok(outcome) => outcome,
        Err(error) => return Ok(AppError(error).into_response()),
    };

    crate::observability::metrics::MITIGATIONS_CREATED
        .with_label_values(&[&mitigation.action_type.to_string(), &state.settings.pop])
        .inc();

    let mut response = MitigationResponse::from(&mitigation);
    response.announcement_outcome = announcement_outcome;
    let status = if announcement_outcome.is_some() {
        StatusCode::ACCEPTED
    } else {
        StatusCode::CREATED
    };
    Ok((status, Json(response)).into_response())
}

pub async fn withdraw_mitigation(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<WithdrawRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    // Check auth
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    use crate::domain::OperatorRole;
    let operator = require_role(&state, &auth_session, auth_header, OperatorRole::Operator)?;
    let operator_id = operator.username;
    state
        .verified_speaker_binding()
        .map_err(|error| error.status_code())?;

    if validate_string_len(&operator_id, "operator_id", MAX_USERNAME_LEN).is_err() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if validate_string_len(&req.reason, "reason", MAX_STRING_LEN).is_err() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let _mitigation_guard = state.mitigation_lock.lock().await;
    let mitigation = state
        .repo
        .get_mitigation(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if !mitigation.is_active() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mitigation = withdraw_and_notify(
        &state,
        &mitigation,
        "operator",
        &operator_id,
        format!("{}: {}", operator_id, req.reason),
    )
    .await
    .map_err(|error| error.status_code())?;

    tracing::info!(
        mitigation_id = %mitigation.mitigation_id,
        operator = %operator_id,
        "mitigation withdrawn"
    );

    Ok(Json(MitigationResponse::from(&mitigation)))
}

const MAX_BULK_WITHDRAW: usize = 100;

#[derive(Deserialize, ToSchema)]
pub struct BulkWithdrawRequest {
    mitigation_ids: Vec<Uuid>,
    #[serde(default)]
    #[allow(
        dead_code,
        reason = "Caller-supplied actor is ignored; request authentication determines the actor"
    )]
    operator_id: String,
    reason: String,
}

#[derive(Serialize, ToSchema)]
pub struct BulkWithdrawResult {
    mitigation_id: Uuid,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct BulkWithdrawResponse {
    withdrawn: u32,
    failed: u32,
    results: Vec<BulkWithdrawResult>,
}

#[utoipa::path(
    post,
    path = "/v1/mitigations/withdraw",
    tag = "mitigations",
    request_body = BulkWithdrawRequest,
    responses(
        (status = 200, description = "Bulk withdraw results", body = BulkWithdrawResponse)
    )
)]
pub async fn bulk_withdraw_mitigations(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Json(req): Json<BulkWithdrawRequest>,
) -> Result<Json<BulkWithdrawResponse>, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    use crate::domain::OperatorRole;
    let operator = require_role(&state, &auth_session, auth_header, OperatorRole::Operator)?;
    let operator_id = operator.username;
    state
        .verified_speaker_binding()
        .map_err(|error| error.status_code())?;

    if req.mitigation_ids.is_empty() || req.mitigation_ids.len() > MAX_BULK_WITHDRAW {
        return Err(StatusCode::BAD_REQUEST);
    }
    if validate_string_len(&operator_id, "operator_id", MAX_USERNAME_LEN).is_err() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if validate_string_len(&req.reason, "reason", MAX_STRING_LEN).is_err() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut results = Vec::with_capacity(req.mitigation_ids.len());
    let mut withdrawn = 0u32;
    let mut failed = 0u32;

    for id in &req.mitigation_ids {
        let _mitigation_guard = state.mitigation_lock.lock().await;
        let mitigation = match state.repo.get_mitigation(*id).await {
            Ok(Some(m)) => m,
            Ok(None) => {
                failed += 1;
                results.push(BulkWithdrawResult {
                    mitigation_id: *id,
                    status: "error".to_string(),
                    error: Some("not found".to_string()),
                });
                continue;
            }
            Err(e) => {
                tracing::error!(error = %e, mitigation_id = %id, "bulk_withdraw: get_mitigation failed");
                failed += 1;
                results.push(BulkWithdrawResult {
                    mitigation_id: *id,
                    status: "error".to_string(),
                    error: Some("internal error".to_string()),
                });
                continue;
            }
        };

        if !mitigation.is_active() {
            failed += 1;
            results.push(BulkWithdrawResult {
                mitigation_id: *id,
                status: "error".to_string(),
                error: Some("not active".to_string()),
            });
            continue;
        }

        if let Err(error) = withdraw_and_notify(
            &state,
            &mitigation,
            "operator",
            &operator_id,
            format!("{}: {}", operator_id, req.reason),
        )
        .await
        {
            tracing::error!(error = %error, mitigation_id = %id, "bulk withdrawal failed");
            failed += 1;
            results.push(BulkWithdrawResult {
                mitigation_id: *id,
                status: "error".into(),
                error: Some(match error {
                    PrefixdError::Conflict(message) => message,
                    PrefixdError::BgpWithdrawalFailed(_) => "speaker withdrawal failed".into(),
                    _ => "withdrawal failed".into(),
                }),
            });
            continue;
        }

        withdrawn += 1;
        results.push(BulkWithdrawResult {
            mitigation_id: *id,
            status: "withdrawn".to_string(),
            error: None,
        });
    }

    tracing::info!(
        operator = %operator_id,
        withdrawn = withdrawn,
        failed = failed,
        total = req.mitigation_ids.len(),
        "bulk withdraw completed"
    );

    Ok(Json(BulkWithdrawResponse {
        withdrawn,
        failed,
        results,
    }))
}

const MAX_BULK_ACKNOWLEDGE: usize = 100;

#[derive(Deserialize, ToSchema)]
pub struct BulkAcknowledgeRequest {
    mitigation_ids: Vec<Uuid>,
    #[serde(default)]
    #[allow(
        dead_code,
        reason = "Caller-supplied actor is ignored; request authentication determines the actor"
    )]
    operator_id: String,
}

#[derive(Serialize, ToSchema)]
pub struct BulkAcknowledgeResult {
    mitigation_id: Uuid,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct BulkAcknowledgeResponse {
    acknowledged: u32,
    failed: u32,
    results: Vec<BulkAcknowledgeResult>,
}

/// Bulk acknowledge mitigations
#[utoipa::path(
    post,
    path = "/v1/mitigations/acknowledge",
    tag = "mitigations",
    request_body = BulkAcknowledgeRequest,
    responses(
        (status = 200, description = "Bulk acknowledge results", body = BulkAcknowledgeResponse)
    )
)]
pub async fn bulk_acknowledge_mitigations(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Json(req): Json<BulkAcknowledgeRequest>,
) -> Result<Json<BulkAcknowledgeResponse>, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    use crate::domain::OperatorRole;
    let operator = require_role(&state, &auth_session, auth_header, OperatorRole::Operator)?;
    let operator_id = operator.username;

    if req.mitigation_ids.is_empty() || req.mitigation_ids.len() > MAX_BULK_ACKNOWLEDGE {
        return Err(StatusCode::BAD_REQUEST);
    }
    if validate_string_len(&operator_id, "operator_id", MAX_USERNAME_LEN).is_err() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let acked_ids = state
        .repo
        .acknowledge_mitigations(&req.mitigation_ids, &operator_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "bulk_acknowledge failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let mut results = Vec::with_capacity(req.mitigation_ids.len());
    let mut acknowledged = 0u32;
    for id in &req.mitigation_ids {
        if acked_ids.contains(id) {
            acknowledged += 1;
            results.push(BulkAcknowledgeResult {
                mitigation_id: *id,
                status: "acknowledged".to_string(),
                error: None,
            });
        } else {
            results.push(BulkAcknowledgeResult {
                mitigation_id: *id,
                status: "error".to_string(),
                error: Some("not found, already acknowledged, or rejected".to_string()),
            });
        }
    }

    let failed = req.mitigation_ids.len() as u32 - acknowledged;

    tracing::info!(
        operator = %operator_id,
        acknowledged = acknowledged,
        failed = failed,
        total = req.mitigation_ids.len(),
        "bulk acknowledge completed"
    );

    Ok(Json(BulkAcknowledgeResponse {
        acknowledged,
        failed,
        results,
    }))
}

const MAX_BATCH_EVENTS: usize = 100;

#[derive(Deserialize, ToSchema)]
pub struct BatchEventRequest {
    events: Vec<AttackEventInput>,
}

#[derive(Serialize, ToSchema)]
pub struct BatchEventResult {
    /// Present only when this creation request committed intent without a successful speaker reply.
    /// Omission is not evidence of enforcement; this outcome is not persisted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub announcement_outcome: Option<AnnouncementOutcome>,
    index: usize,
    event_id: Uuid,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mitigation_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct BatchEventResponse {
    accepted: u32,
    rejected: u32,
    results: Vec<BatchEventResult>,
}

#[utoipa::path(
    post,
    path = "/v1/events/batch",
    tag = "events",
    request_body = BatchEventRequest,
    responses(
        (status = 207, description = "Batch results (partial success)", body = BatchEventResponse),
        (status = 202, description = "All events accepted", body = BatchEventResponse),
        (status = 400, description = "Empty batch or exceeds limit"),
    )
)]
pub async fn ingest_events_batch(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Json(req): Json<BatchEventRequest>,
) -> impl IntoResponse {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    if let Err(_status) = require_auth(&state, &auth_session, auth_header) {
        return Err(AppError(PrefixdError::Unauthorized(
            "authentication required".into(),
        )));
    }

    if req.events.is_empty() || req.events.len() > MAX_BATCH_EVENTS {
        return Err(AppError(PrefixdError::InvalidRequest(format!(
            "batch must contain 1-{} events, got {}",
            MAX_BATCH_EVENTS,
            req.events.len()
        ))));
    }

    let mut results = Vec::with_capacity(req.events.len());
    let mut accepted = 0u32;
    let mut rejected = 0u32;

    for (index, input) in req.events.into_iter().enumerate() {
        // Validate input
        let validation_err = validate_ip(&input.victim_ip)
            .and_then(|_| validate_string_len(&input.source, "source", MAX_STRING_LEN))
            .and_then(|_| validate_string_len(&input.victim_ip, "victim_ip", 45))
            .and_then(|_| {
                if let Some(ref eid) = input.event_id {
                    validate_string_len(eid, "event_id", MAX_STRING_LEN)
                } else {
                    Ok(())
                }
            })
            .err();

        if let Some(err) = validation_err {
            rejected += 1;
            results.push(BatchEventResult {
                announcement_outcome: None,
                index,
                event_id: Uuid::nil(),
                status: "rejected".to_string(),
                mitigation_id: None,
                error: Some(err.to_string()),
            });
            continue;
        }

        let action = input.action.clone();
        let result = match action.as_str() {
            "unban" => handle_unban(state.clone(), input).await,
            "ban" => handle_ban(state.clone(), input).await,
            unknown => Err(AppError(PrefixdError::InvalidRequest(format!(
                "unknown action: '{}', expected 'ban' or 'unban'",
                unknown
            )))),
        };

        match result {
            Ok((_status, Json(resp))) => {
                accepted += 1;
                results.push(BatchEventResult {
                    announcement_outcome: resp.announcement_outcome,
                    index,
                    event_id: resp.event_id,
                    status: resp.status,
                    mitigation_id: resp.mitigation_id,
                    error: None,
                });
            }
            Err(AppError(err)) => {
                rejected += 1;
                results.push(BatchEventResult {
                    announcement_outcome: None,
                    index,
                    event_id: Uuid::nil(),
                    status: "rejected".to_string(),
                    mitigation_id: None,
                    error: Some(err.to_string()),
                });
            }
        }
    }

    tracing::info!(
        accepted = accepted,
        rejected = rejected,
        total = results.len(),
        "batch event ingestion completed"
    );

    let status = if rejected > 0 {
        StatusCode::MULTI_STATUS
    } else {
        StatusCode::ACCEPTED
    };

    Ok((
        status,
        Json(BatchEventResponse {
            accepted,
            rejected,
            results,
        }),
    ))
}

/// A standby controller (ADR 027) refuses every state-changing API request with
/// `503`; reads stay available. `api_routes` applies this to its routes.
pub async fn require_active_controller(
    State(state): State<Arc<AppState>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if !request.method().is_safe() && !state.fence.is_active() {
        return AppError(PrefixdError::Standby).into_response();
    }
    next.run(request).await
}

// Error handling

struct AppError(PrefixdError);

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let status = self.0.status_code();
        let body = Json(ErrorResponse {
            error: self.0.to_string(),
            retry_after_seconds: match &self.0 {
                PrefixdError::RateLimited {
                    retry_after_seconds,
                } => Some(*retry_after_seconds),
                _ => None,
            },
        });
        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_list_cursor, encode_list_cursor};
    use crate::db::ListCursor;
    use chrono::{DateTime, Utc};
    use uuid::Uuid;

    #[test]
    fn test_cursor_encoding_known_value() {
        let timestamp = "2026-10-18T00:00:00+00:00"
            .parse::<DateTime<Utc>>()
            .unwrap();
        let id = Uuid::from_u128(1);
        let encoded =
            "MjAyNi0xMC0xOFQwMDowMDowMCswMDowMAowMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDE";
        for prefix in ["e1.", "a1.", "s1."] {
            let cursor = format!("{prefix}{encoded}");
            assert_eq!(encode_list_cursor(timestamp, id, prefix), cursor);
            assert_eq!(
                decode_list_cursor(&cursor, prefix),
                Some(ListCursor { timestamp, id })
            );
        }
    }

    #[test]
    fn test_cursor_decode_rejects_invalid_input() {
        let encoded =
            "MjAyNi0xMC0xOFQwMDowMDowMCswMDowMAowMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDE";
        for prefix in ["e1.", "a1.", "s1."] {
            for value in [
                format!("{encoded}="),                         // Padding is not accepted.
                format!("{}F", &encoded[..encoded.len() - 1]), // Nonzero unused trailing bits.
                format!("{encoded}\n"),
                "*".into(),
                "a".into(),
                "_w".into(), // Decodes to invalid UTF-8.
                "bm90LWEtdGltZXN0YW1w".into(),
                "MjAyNi0xMC0xOFQwMDowMDowMCswMDowMA".into(), // Superseded timestamp-only position.
                String::new(),
            ] {
                let cursor = format!("{prefix}{value}");
                assert_eq!(
                    decode_list_cursor(&cursor, prefix),
                    None,
                    "accepted cursor {cursor:?}"
                );
            }
        }
    }
}
