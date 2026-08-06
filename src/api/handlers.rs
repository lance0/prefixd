use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header, header::AUTHORIZATION},
    response::IntoResponse,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;
use crate::db::{ListParams, NotificationPreferences};
use crate::domain::{
    ActionParams, ActionType, AttackEvent, AttackEventInput, AttackVector, FlowSpecAction,
    FlowSpecNlri, FlowSpecRule, MatchCriteria, Mitigation, MitigationIntent, MitigationStatus,
};
use crate::error::PrefixdError;
use crate::guardrails::Guardrails;
use crate::policy::PolicyEngine;

use super::auth::{require_auth, require_role};
use crate::auth::AuthSession;

fn encode_cursor(ts: &DateTime<Utc>) -> String {
    URL_SAFE_NO_PAD.encode(ts.to_rfc3339().as_bytes())
}

fn decode_cursor(cursor: &str) -> Option<DateTime<Utc>> {
    let bytes = URL_SAFE_NO_PAD.decode(cursor).ok()?;
    let s = std::str::from_utf8(&bytes).ok()?;
    s.parse::<DateTime<Utc>>().ok()
}

// Response types

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct EventResponse {
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
    /// Correlation context (present when mitigation was created via
    /// corroboration from the signal correlation engine)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation: Option<CorrelationContext>,
}

impl From<&Mitigation> for MitigationResponse {
    fn from(m: &Mitigation) -> Self {
        Self {
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

#[derive(Serialize, ToSchema)]
pub struct PublicHealthResponse {
    /// Health status (healthy, degraded)
    status: String,
    /// Daemon version
    version: String,
    /// Authentication mode (none, bearer, credentials, mtls)
    auth_mode: String,
}

#[derive(Serialize, ToSchema)]
pub struct HealthResponse {
    /// Health status (healthy, degraded)
    status: String,
    /// Daemon version
    version: String,
    /// POP identifier
    pop: String,
    /// Seconds since daemon started
    uptime_seconds: u64,
    /// BGP session states by peer name
    bgp_sessions: std::collections::HashMap<String, String>,
    /// Number of active mitigations
    active_mitigations: u32,
    /// Database connectivity status
    database: String,
    /// GoBGP connectivity status
    gobgp: ComponentHealth,
    /// Authentication mode (none, bearer, credentials, mtls)
    auth_mode: String,
}

#[derive(Serialize, ToSchema)]
pub struct ComponentHealth {
    /// Component status (connected, error)
    status: String,
    /// Error message if status is error
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
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
    /// Filter by POP. Use "all" to see mitigations from all POPs.
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

fn parse_datetime(s: &str) -> Option<DateTime<Utc>> {
    s.parse::<DateTime<Utc>>().ok()
}

fn clamp_limit(limit: u32) -> u32 {
    limit.min(MAX_PAGE_LIMIT)
}

const LOGIN_MAX_ATTEMPTS: u32 = 5;
const LOGIN_WINDOW_SECS: u64 = 60;
const LOGIN_MAX_TRACKED_USERS: usize = 10_000;

static LOGIN_ATTEMPTS: std::sync::LazyLock<Mutex<HashMap<String, (u32, Instant)>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

fn prune_login_attempts_locked(attempts: &mut HashMap<String, (u32, Instant)>) {
    attempts.retain(|_, (_, started)| started.elapsed().as_secs() < LOGIN_WINDOW_SECS);

    if attempts.len() > LOGIN_MAX_TRACKED_USERS {
        let mut by_age: Vec<_> = attempts
            .iter()
            .map(|(key, (_, started))| (key.clone(), *started))
            .collect();
        by_age.sort_by_key(|(_, started)| *started);

        let overflow = attempts.len() - LOGIN_MAX_TRACKED_USERS;
        for (key, _) in by_age.into_iter().take(overflow) {
            attempts.remove(&key);
        }
    }
}

async fn check_and_record_login_attempt(key: &str) -> Result<(), StatusCode> {
    let mut attempts = LOGIN_ATTEMPTS.lock().await;
    prune_login_attempts_locked(&mut attempts);

    let now = Instant::now();
    let entry = attempts.entry(key.to_string()).or_insert((0, now));

    if entry.1.elapsed().as_secs() >= LOGIN_WINDOW_SECS {
        *entry = (1, Instant::now());
        return Ok(());
    }

    if entry.0 >= LOGIN_MAX_ATTEMPTS {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    entry.0 += 1;
    Ok(())
}

async fn clear_login_attempts(key: &str) {
    let mut attempts = LOGIN_ATTEMPTS.lock().await;
    attempts.remove(key);
}

fn is_valid_username(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

const MAX_STRING_LEN: usize = 1024;
const MAX_USERNAME_LEN: usize = 64;
const MAX_PASSWORD_LEN: usize = 256;

fn validate_string_len(value: &str, field: &str, max: usize) -> Result<(), PrefixdError> {
    if value.len() > max {
        Err(PrefixdError::InvalidRequest(format!(
            "{} exceeds maximum length of {} characters",
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

fn validate_cidr(prefix: &str) -> Result<(), PrefixdError> {
    if prefix.contains('/') {
        prefix
            .parse::<ipnet::IpNet>()
            .map_err(|_| PrefixdError::InvalidRequest(format!("invalid prefix: '{}'", prefix)))?;
    } else {
        prefix
            .parse::<IpAddr>()
            .map_err(|_| PrefixdError::InvalidRequest(format!("invalid prefix: '{}'", prefix)))?;
    }
    Ok(())
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct CreateMitigationRequest {
    #[serde(default)]
    operator_id: String,
    reason: String,
    victim_ip: String,
    protocol: String,
    #[serde(default)]
    dst_ports: Vec<u16>,
    action: String,
    #[serde(default)]
    rate_bps: Option<u64>,
    ttl_seconds: u32,
}
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct WithdrawRequest {
    #[serde(default)]
    operator_id: String,
    reason: String,
}
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct AddSafelistRequest {
    #[serde(default)]
    operator_id: String,
    prefix: String,
    #[serde(default)]
    reason: Option<String>,
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

    let correlation_config = state.correlation_config.read().await.clone();
    if correlation_config.source_mode(&input.source)
        == crate::correlation::SourceMode::Corroborating
    {
        tracing::warn!(
            source = %input.source,
            action = %input.action,
            "rejected /v1/events from corroborating-only source"
        );
        return Err(AppError(PrefixdError::InvalidRequest(format!(
            "source '{}' is configured as mode=corroborating and cannot post to /v1/events. Use POST /v1/signals/corroborator instead.",
            input.source
        ))));
    }

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

/// Handle unban action - withdraw mitigation by external_event_id
async fn handle_unban(
    state: Arc<AppState>,
    input: AttackEventInput,
) -> Result<(StatusCode, Json<EventResponse>), AppError> {
    let ext_id = match &input.event_id {
        Some(id) => id.clone(),
        None => {
            // No external ID, can't find the original event
            tracing::warn!(source = %input.source, "unban without event_id, ignoring");
            return Ok((
                StatusCode::ACCEPTED,
                Json(EventResponse {
                    event_id: Uuid::new_v4(),
                    external_event_id: None,
                    status: "ignored_no_event_id".to_string(),
                    mitigation_id: None,
                }),
            ));
        }
    };

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
    let mut mitigation = match state
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

    // Withdraw from BGP (if not dry-run)
    if !state.is_dry_run() {
        let nlri = FlowSpecNlri::from(&mitigation.match_criteria);
        let action = FlowSpecAction::from((mitigation.action_type, &mitigation.action_params));
        let rule = FlowSpecRule::new(nlri, action);

        let start = std::time::Instant::now();
        if let Err(e) = state.announcer.withdraw(&rule).await {
            tracing::error!(error = %e, "BGP withdrawal failed");
            // Continue anyway - mark as withdrawn in DB
        } else {
            crate::observability::metrics::ANNOUNCEMENTS_TOTAL
                .with_label_values(&["withdrawn"])
                .inc();
            crate::observability::metrics::ANNOUNCEMENTS_LATENCY
                .observe(start.elapsed().as_secs_f64());
        }
    }

    // Update mitigation status
    let action_type_str = mitigation.action_type.to_string();
    mitigation.withdraw(Some(format!("Detector unban: {}", source)));
    state
        .repo
        .update_mitigation(&mitigation)
        .await
        .map_err(AppError)?;

    crate::observability::metrics::MITIGATIONS_WITHDRAWN
        .with_label_values(&[
            action_type_str.as_str(),
            mitigation.pop.as_str(),
            "detector_unban",
        ])
        .inc();

    // Broadcast withdrawal via WebSocket
    let _ = state
        .ws_broadcast
        .send(crate::ws::WsMessage::MitigationWithdrawn {
            mitigation_id: mitigation.mitigation_id.to_string(),
        });

    state
        .alerting
        .read()
        .await
        .notify(crate::alerting::Alert::mitigation_withdrawn(&mitigation));

    tracing::info!(
        mitigation_id = %mitigation.mitigation_id,
        victim_ip = %mitigation.victim_ip,
        "withdrew mitigation via detector unban"
    );

    Ok((
        StatusCode::ACCEPTED,
        Json(EventResponse {
            event_id: unban_event.event_id,
            external_event_id: unban_event.external_event_id,
            status: "withdrawn".to_string(),
            mitigation_id: Some(mitigation.mitigation_id),
        }),
    ))
}

/// Handle ban action - create or extend mitigation
async fn handle_ban(
    state: Arc<AppState>,
    input: AttackEventInput,
) -> Result<(StatusCode, Json<EventResponse>), AppError> {
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

    // Store event
    state.repo.insert_event(&event).await.map_err(AppError)?;

    crate::observability::metrics::EVENTS_INGESTED
        .with_label_values(&[&event.source, &event.attack_vector().to_string()])
        .inc();

    // Check if shutting down
    if state.is_shutting_down() {
        return Err(AppError(PrefixdError::ShuttingDown));
    }

    // Lookup IP context
    let inventory = state.inventory.read().await;
    let context = inventory.lookup_ip(&event.victim_ip);

    if context.is_none() && !inventory.is_owned(&event.victim_ip) {
        tracing::warn!(victim_ip = %event.victim_ip, "event for unowned IP, skipping mitigation");
        return Ok((
            StatusCode::ACCEPTED,
            Json(EventResponse {
                event_id: event.event_id,
                external_event_id: event.external_event_id.clone(),
                status: "accepted_no_mitigation".to_string(),
                mitigation_id: None,
            }),
        ));
    }

    drop(inventory); // Release read lock before policy evaluation

    // ── Correlation step ───────────────────────────────────────────────
    // If correlation.enabled, find/create a signal group and add the event.
    // Check corroboration — if threshold not met, return 'accepted' without
    // creating a mitigation. If threshold met, proceed to policy evaluation.
    let correlation_config = state.correlation_config.read().await.clone();

    // Resolve the matching playbook early so we can get per-playbook overrides
    let playbooks = state.playbooks.read().await.clone();
    let policy = PolicyEngine::new(
        playbooks.clone(),
        state.settings.pop.clone(),
        state.settings.timers.default_ttl_seconds,
    );

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

    let intent = match policy.evaluate(&event, context.as_ref()) {
        Ok(i) => i,
        Err(e) => {
            tracing::warn!(error = %e, "policy evaluation failed");
            return Ok((
                StatusCode::ACCEPTED,
                Json(EventResponse {
                    event_id: event.event_id,
                    external_event_id: event.external_event_id.clone(),
                    status: "accepted_no_playbook".to_string(),
                    mitigation_id: None,
                }),
            ));
        }
    };

    // Serialize mitigation creation to prevent TOCTOU race between
    // find_active_by_scope and insert_mitigation.
    let _mitigation_guard = state.mitigation_lock.lock().await;

    // Check for existing mitigation with same scope
    let scope_hash = intent.match_criteria.compute_scope_hash();
    if let Ok(Some(mut existing)) = state
        .repo
        .find_active_by_scope(&scope_hash, &state.settings.pop)
        .await
    {
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

    // Announce FlowSpec (if not dry-run)
    if !state.is_dry_run() {
        let nlri = FlowSpecNlri::from(&mitigation.match_criteria);
        let action = FlowSpecAction::from((mitigation.action_type, &mitigation.action_params));
        let rule = FlowSpecRule::new(nlri, action);

        let start = std::time::Instant::now();
        if let Err(e) = state.announcer.announce(&rule).await {
            tracing::error!(error = %e, "BGP announcement failed");
            mitigation.reject(e.to_string());
            state
                .repo
                .insert_mitigation(&mitigation)
                .await
                .map_err(AppError)?;
            return Err(AppError(e));
        }
        crate::observability::metrics::ANNOUNCEMENTS_TOTAL
            .with_label_values(&["announced"])
            .inc();
        crate::observability::metrics::ANNOUNCEMENTS_LATENCY.observe(start.elapsed().as_secs_f64());
    }

    mitigation.activate();
    state
        .repo
        .insert_mitigation(&mitigation)
        .await
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
        ("cursor" = Option<String>, Query, description = "Cursor for pagination (from previous response)"),
        ("start" = Option<String>, Query, description = "Start of date range (ISO 8601, inclusive)"),
        ("end" = Option<String>, Query, description = "End of date range (ISO 8601, exclusive)"),
    ),
    responses(
        (status = 200, description = "List of events", body = EventsListResponse)
    )
)]
pub async fn list_events(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Query(query): Query<CursorQuery>,
) -> Result<Json<EventsListResponse>, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

    let limit = clamp_limit(query.limit.unwrap_or(100));
    let cursor = query.cursor.as_deref().and_then(decode_cursor);
    let params = ListParams {
        limit: limit + 1,
        cursor,
        start: query.start.as_deref().and_then(parse_datetime),
        end: query.end.as_deref().and_then(parse_datetime),
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
        events.last().map(|e| encode_cursor(&e.ingested_at))
    } else {
        None
    };
    let count = events.len();
    Ok(Json(EventsListResponse {
        events,
        count,
        next_cursor,
        has_more,
    }))
}

/// List audit log entries
#[utoipa::path(
    get,
    path = "/v1/audit",
    tag = "audit",
    params(
        ("limit" = Option<u32>, Query, description = "Max results (default 100)"),
        ("cursor" = Option<String>, Query, description = "Cursor for pagination (from previous response)"),
        ("start" = Option<String>, Query, description = "Start of date range (ISO 8601, inclusive)"),
        ("end" = Option<String>, Query, description = "End of date range (ISO 8601, exclusive)"),
    ),
    responses(
        (status = 200, description = "List of audit log entries", body = AuditListResponse)
    )
)]
pub async fn list_audit(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Query(query): Query<CursorQuery>,
) -> Result<Json<AuditListResponse>, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    use crate::domain::OperatorRole;
    let _operator = require_role(&state, &auth_session, auth_header, OperatorRole::Operator)?;

    let limit = clamp_limit(query.limit.unwrap_or(100));
    let cursor = query.cursor.as_deref().and_then(decode_cursor);
    let params = ListParams {
        limit: limit + 1,
        cursor,
        start: query.start.as_deref().and_then(parse_datetime),
        end: query.end.as_deref().and_then(parse_datetime),
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
        entries.last().map(|e| encode_cursor(&e.timestamp))
    } else {
        None
    };
    let count = entries.len();
    Ok(Json(AuditListResponse {
        entries,
        count,
        next_cursor,
        has_more,
    }))
}

/// List mitigations with optional filters
#[utoipa::path(
    get,
    path = "/v1/mitigations",
    tag = "mitigations",
    params(
        ("status" = Option<String>, Query, description = "Filter by status (comma-separated)"),
        ("customer_id" = Option<String>, Query, description = "Filter by customer ID"),
        ("victim_ip" = Option<String>, Query, description = "Filter by victim IP address"),
        ("pop" = Option<String>, Query, description = "Filter by POP, use 'all' for cross-POP"),
        ("acknowledged" = Option<bool>, Query, description = "Filter by acknowledged status"),
        ("limit" = Option<u32>, Query, description = "Max results (default 100)"),
        ("cursor" = Option<String>, Query, description = "Cursor for pagination (from previous response)"),
        ("start" = Option<String>, Query, description = "Start of date range (ISO 8601, inclusive)"),
        ("end" = Option<String>, Query, description = "End of date range (ISO 8601, exclusive)"),
    ),
    responses(
        (status = 200, description = "List of mitigations", body = MitigationsListResponse)
    )
)]
pub async fn list_mitigations(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Query(query): Query<ListMitigationsQuery>,
) -> Result<Json<MitigationsListResponse>, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

    let status_filter: Option<Vec<MitigationStatus>> = query
        .status
        .as_ref()
        .map(|s| s.split(',').filter_map(|st| st.parse().ok()).collect());

    let limit = clamp_limit(query.limit);
    let cursor = query.cursor.as_deref().and_then(decode_cursor);
    let params = ListParams {
        limit: limit + 1,
        cursor,
        start: query.start.as_deref().and_then(parse_datetime),
        end: query.end.as_deref().and_then(parse_datetime),
    };

    let mut mitigations = if query.pop.as_deref() == Some("all") {
        state
            .repo
            .list_mitigations_all_pops(
                status_filter.as_deref(),
                query.customer_id.as_deref(),
                query.victim_ip.as_deref(),
                query.acknowledged,
                &params,
            )
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    } else {
        state
            .repo
            .list_mitigations(
                status_filter.as_deref(),
                query.customer_id.as_deref(),
                query.victim_ip.as_deref(),
                query.acknowledged,
                &params,
            )
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    };

    let has_more = mitigations.len() > limit as usize;
    if has_more {
        mitigations.truncate(limit as usize);
    }
    let next_cursor = if has_more {
        mitigations.last().map(|m| encode_cursor(&m.created_at))
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
    }))
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

    // Validate input
    if let Err(e) = validate_ip(&req.victim_ip) {
        return Ok(AppError(e).into_response());
    }
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
        "icmp" => Some(1u8),
        "any" | "" => None,
        _ => {
            return Ok(AppError(PrefixdError::InvalidRequest(format!(
                "invalid protocol '{}', expected: udp, tcp, icmp, any",
                req.protocol
            )))
            .into_response());
        }
    };

    // Validate action type
    let action_type = match req.action.as_str() {
        "police" => {
            // Police action requires rate_bps
            if req.rate_bps.is_none() {
                return Ok(AppError(PrefixdError::InvalidRequest(
                    "action 'police' requires rate_bps".to_string(),
                ))
                .into_response());
            }
            ActionType::Police
        }
        "discard" => ActionType::Discard,
        _ => {
            return Ok(AppError(PrefixdError::InvalidRequest(format!(
                "invalid action '{}', expected: discard, police",
                req.action
            )))
            .into_response());
        }
    };

    let inventory = state.inventory.read().await;
    let customer_id = inventory.lookup_ip(&req.victim_ip).map(|c| c.customer_id);
    drop(inventory);
    let prefix_len = if req.victim_ip.contains(':') { 128 } else { 32 };
    let intent = MitigationIntent {
        event_id: Uuid::new_v4(),
        customer_id,
        service_id: None,
        pop: state.settings.pop.clone(),
        match_criteria: MatchCriteria {
            dst_prefix: format!("{}/{}", req.victim_ip, prefix_len),
            protocol,
            dst_ports: req.dst_ports,
        },
        action_type,
        action_params: ActionParams {
            rate_bps: req.rate_bps,
        },
        ttl_seconds: req.ttl_seconds,
        reason: req.reason,
    };

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

    if !state.is_dry_run() {
        let nlri = FlowSpecNlri::from(&mitigation.match_criteria);
        let action = FlowSpecAction::from((mitigation.action_type, &mitigation.action_params));
        let rule = FlowSpecRule::new(nlri, action);
        let start = std::time::Instant::now();
        if let Err(e) = state.announcer.announce(&rule).await {
            return Ok(AppError(e).into_response());
        }
        crate::observability::metrics::ANNOUNCEMENTS_TOTAL
            .with_label_values(&["announced"])
            .inc();
        crate::observability::metrics::ANNOUNCEMENTS_LATENCY.observe(start.elapsed().as_secs_f64());
    }

    mitigation.activate();
    if let Err(e) = state.repo.insert_mitigation(&mitigation).await {
        return Ok(AppError(e).into_response());
    }

    crate::observability::metrics::MITIGATIONS_CREATED
        .with_label_values(&[&mitigation.action_type.to_string(), &state.settings.pop])
        .inc();

    Ok((
        StatusCode::CREATED,
        Json(MitigationResponse::from(&mitigation)),
    )
        .into_response())
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

    if validate_string_len(&operator_id, "operator_id", MAX_USERNAME_LEN).is_err() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if validate_string_len(&req.reason, "reason", MAX_STRING_LEN).is_err() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut mitigation = state
        .repo
        .get_mitigation(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if !mitigation.is_active() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Withdraw BGP
    if !state.is_dry_run() {
        let nlri = FlowSpecNlri::from(&mitigation.match_criteria);
        let action = FlowSpecAction::from((mitigation.action_type, &mitigation.action_params));
        let rule = FlowSpecRule::new(nlri, action);
        let start = std::time::Instant::now();
        state
            .announcer
            .withdraw(&rule)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        crate::observability::metrics::ANNOUNCEMENTS_TOTAL
            .with_label_values(&["withdrawn"])
            .inc();
        crate::observability::metrics::ANNOUNCEMENTS_LATENCY.observe(start.elapsed().as_secs_f64());
    }

    let action_type_str = mitigation.action_type.to_string();
    mitigation.withdraw(Some(format!("{}: {}", operator_id, req.reason)));
    state
        .repo
        .update_mitigation(&mitigation)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    crate::observability::metrics::MITIGATIONS_WITHDRAWN
        .with_label_values(&[
            action_type_str.as_str(),
            mitigation.pop.as_str(),
            "operator",
        ])
        .inc();

    // Broadcast withdrawal via WebSocket
    let _ = state
        .ws_broadcast
        .send(crate::ws::WsMessage::MitigationWithdrawn {
            mitigation_id: mitigation.mitigation_id.to_string(),
        });

    state
        .alerting
        .read()
        .await
        .notify(crate::alerting::Alert::mitigation_withdrawn(&mitigation));

    tracing::info!(
        mitigation_id = %mitigation.mitigation_id,
        operator = %operator_id,
        "mitigation withdrawn"
    );

    Ok(Json(MitigationResponse::from(&mitigation)))
}

const MAX_BULK_WITHDRAW: usize = 100;

#[derive(Deserialize, ToSchema)]
#[allow(dead_code)]
pub struct BulkWithdrawRequest {
    mitigation_ids: Vec<Uuid>,
    #[serde(default)]
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
        let mut mitigation = match state.repo.get_mitigation(*id).await {
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
            Err(_) => {
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

        if !state.is_dry_run() {
            let nlri = FlowSpecNlri::from(&mitigation.match_criteria);
            let action = FlowSpecAction::from((mitigation.action_type, &mitigation.action_params));
            let rule = FlowSpecRule::new(nlri, action);
            let start = std::time::Instant::now();
            if let Err(e) = state.announcer.withdraw(&rule).await {
                tracing::error!(error = %e, mitigation_id = %id, "BGP withdrawal failed in bulk withdraw");
            } else {
                crate::observability::metrics::ANNOUNCEMENTS_TOTAL
                    .with_label_values(&["withdrawn"])
                    .inc();
                crate::observability::metrics::ANNOUNCEMENTS_LATENCY
                    .observe(start.elapsed().as_secs_f64());
            }
        }

        mitigation.withdraw(Some(format!("{}: {}", operator_id, req.reason)));
        if let Err(e) = state.repo.update_mitigation(&mitigation).await {
            tracing::error!(error = %e, mitigation_id = %id, "DB update failed in bulk withdraw");
            failed += 1;
            results.push(BulkWithdrawResult {
                mitigation_id: *id,
                status: "error".to_string(),
                error: Some("db update failed".to_string()),
            });
            continue;
        }

        let _ = state
            .ws_broadcast
            .send(crate::ws::WsMessage::MitigationWithdrawn {
                mitigation_id: mitigation.mitigation_id.to_string(),
            });

        state
            .alerting
            .read()
            .await
            .notify(crate::alerting::Alert::mitigation_withdrawn(&mitigation));

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
#[allow(dead_code)]
pub struct BulkAcknowledgeRequest {
    mitigation_ids: Vec<Uuid>,
    #[serde(default)]
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
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut results = Vec::with_capacity(req.mitigation_ids.len());
    for id in &req.mitigation_ids {
        if acked_ids.contains(id) {
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

    let acknowledged = acked_ids.len() as u32;
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

pub async fn list_safelist(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

    let entries = state
        .repo
        .list_safelist()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(entries))
}

pub async fn add_safelist(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Json(req): Json<AddSafelistRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    use crate::domain::OperatorRole;
    let operator = require_role(&state, &auth_session, auth_header, OperatorRole::Admin)?;
    let operator_id = operator.username;

    validate_cidr(&req.prefix).map_err(|_| StatusCode::BAD_REQUEST)?;
    validate_string_len(&operator_id, "operator_id", MAX_USERNAME_LEN)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if let Some(ref reason) = req.reason {
        validate_string_len(reason, "reason", MAX_STRING_LEN)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
    }

    state
        .repo
        .insert_safelist(&req.prefix, &operator_id, req.reason.as_deref())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tracing::info!(prefix = %req.prefix, operator = %operator_id, "safelist entry added");
    Ok(StatusCode::CREATED)
}

pub async fn remove_safelist(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Path(prefix): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    use crate::domain::OperatorRole;
    let _operator = require_role(&state, &auth_session, auth_header, OperatorRole::Admin)?;

    let removed = state
        .repo
        .remove_safelist(&prefix)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if removed {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

/// Health check endpoint
fn resolve_auth_mode(state: &AppState) -> String {
    serde_json::to_value(state.settings.http.auth.mode)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| "unknown".to_string())
}

async fn check_health_status(
    state: &AppState,
) -> (
    String,
    std::collections::HashMap<String, String>,
    u32,
    String,
    ComponentHealth,
) {
    let (sessions, gobgp_health) = match state.announcer.session_status().await {
        Ok(s) => (
            s,
            ComponentHealth {
                status: "connected".to_string(),
                error: None,
            },
        ),
        Err(e) => (
            vec![],
            ComponentHealth {
                status: "error".to_string(),
                error: Some(e.to_string()),
            },
        ),
    };

    let (active, db_status, db_error) = match state.repo.count_active_global().await {
        Ok(count) => (count, "connected".to_string(), false),
        Err(e) => {
            tracing::warn!(error = %e, "database health check failed");
            (0, format!("error: {}", e), true)
        }
    };

    let bgp_map: std::collections::HashMap<_, _> = sessions
        .into_iter()
        .map(|s| (s.name, s.state.to_string()))
        .collect();

    let status = if db_error || gobgp_health.status == "error" {
        "degraded"
    } else {
        "healthy"
    };

    (status.to_string(), bgp_map, active, db_status, gobgp_health)
}

/// Public health endpoint: minimal info safe for unauthenticated access
#[utoipa::path(
    get,
    path = "/v1/health",
    tag = "health",
    responses(
        (status = 200, description = "Service is healthy", body = PublicHealthResponse)
    )
)]
pub async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Lightweight liveness check: no DB or GoBGP calls.
    // Use /v1/health/detail for full operational status.
    Json(PublicHealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        auth_mode: resolve_auth_mode(&state),
    })
}

/// Authenticated health detail: full operational status
#[utoipa::path(
    get,
    path = "/v1/health/detail",
    tag = "health",
    responses(
        (status = 200, description = "Detailed health status", body = HealthResponse)
    )
)]
pub async fn health_detail(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

    let (status, bgp_map, active, db_status, gobgp_health) = check_health_status(&state).await;

    Ok(Json(HealthResponse {
        status,
        version: env!("CARGO_PKG_VERSION").to_string(),
        pop: state.settings.pop.clone(),
        uptime_seconds: state.start_time.elapsed().as_secs(),
        bgp_sessions: bgp_map,
        active_mitigations: active,
        database: db_status,
        gobgp: gobgp_health,
        auth_mode: resolve_auth_mode(&state),
    }))
}

pub async fn metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if let Some(pool) = &state.db_pool {
        crate::observability::metrics::update_db_pool_metrics(pool);
    }
    crate::observability::gather_metrics()
}

#[derive(Serialize, ToSchema)]
pub struct ReloadResponse {
    /// List of reloaded config files
    reloaded: Vec<String>,
    /// Reload timestamp
    timestamp: String,
}

pub async fn reload_config(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    use crate::domain::OperatorRole;
    let _operator = require_role(&state, &auth_session, auth_header, OperatorRole::Admin)?;

    match state.reload_config().await {
        Ok(reloaded) => {
            crate::observability::CONFIG_RELOADS
                .with_label_values(&["success"])
                .inc();
            Ok(Json(ReloadResponse {
                reloaded,
                timestamp: chrono::Utc::now().to_rfc3339(),
            }))
        }
        Err(_) => {
            crate::observability::CONFIG_RELOADS
                .with_label_values(&["error"])
                .inc();
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
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

// Authentication handlers

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LoginResponse {
    pub operator_id: Uuid,
    pub username: String,
    pub role: String,
}

/// Login with username and password
#[utoipa::path(
    post,
    path = "/v1/auth/login",
    tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = LoginResponse),
        (status = 401, description = "Invalid credentials")
    )
)]
pub async fn login(
    mut auth_session: crate::auth::AuthSession,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    use crate::auth::Credentials;

    // Validate input lengths and username format
    if req.username.len() > MAX_USERNAME_LEN
        || !is_valid_username(&req.username)
        || req.password.is_empty()
        || req.password.len() > MAX_PASSWORD_LEN
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Per-username brute-force throttle
    check_and_record_login_attempt(&req.username).await?;

    let username = req.username.clone();

    let creds = Credentials {
        username: req.username,
        password: req.password,
    };

    let operator = match auth_session.authenticate(creds).await {
        Ok(Some(op)) => op,
        Ok(None) => return Err(StatusCode::UNAUTHORIZED),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    auth_session
        .login(&operator)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    clear_login_attempts(&username).await;

    Ok(Json(LoginResponse {
        operator_id: operator.operator_id,
        username: operator.username,
        role: operator.role.to_string(),
    }))
}

/// Logout current session
#[utoipa::path(
    post,
    path = "/v1/auth/logout",
    tag = "auth",
    responses(
        (status = 200, description = "Logout successful")
    )
)]
pub async fn logout(mut auth_session: crate::auth::AuthSession) -> StatusCode {
    if let Err(e) = auth_session.logout().await {
        tracing::warn!(error = %e, "logout failed");
    }
    StatusCode::OK
}

/// Get current authenticated operator
#[utoipa::path(
    get,
    path = "/v1/auth/me",
    tag = "auth",
    responses(
        (status = 200, description = "Current operator", body = LoginResponse),
        (status = 401, description = "Not authenticated")
    )
)]
pub async fn get_me(
    auth_session: crate::auth::AuthSession,
) -> Result<Json<LoginResponse>, StatusCode> {
    let operator = auth_session.user.ok_or(StatusCode::UNAUTHORIZED)?;
    Ok(Json(LoginResponse {
        operator_id: operator.operator_id,
        username: operator.username,
        role: operator.role.to_string(),
    }))
}

// Operator management handlers (admin only)

#[derive(Debug, Serialize, ToSchema)]
pub struct OperatorListResponse {
    pub operators: Vec<OperatorInfo>,
    pub count: usize,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OperatorInfo {
    pub operator_id: Uuid,
    pub username: String,
    pub role: String,
    pub created_at: String,
    pub created_by: Option<String>,
    pub last_login_at: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateOperatorRequest {
    pub username: String,
    pub password: String,
    pub role: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
    /// Current password — required for self-change, optional for admin reset
    #[serde(default)]
    pub current_password: String,
    pub new_password: String,
}

/// List all operators (admin only)
#[utoipa::path(
    get,
    path = "/v1/operators",
    tag = "operators",
    responses(
        (status = 200, description = "List of operators", body = OperatorListResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions")
    )
)]
pub async fn list_operators(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    auth_session: crate::auth::AuthSession,
) -> Result<Json<OperatorListResponse>, StatusCode> {
    use super::auth::require_role;
    use crate::domain::OperatorRole;

    let auth_header = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok());

    require_role(&state, &auth_session, auth_header, OperatorRole::Admin)?;

    let operators = state
        .repo
        .list_operators()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let infos: Vec<OperatorInfo> = operators
        .into_iter()
        .map(|op| OperatorInfo {
            operator_id: op.operator_id,
            username: op.username,
            role: op.role.to_string(),
            created_at: op.created_at.to_rfc3339(),
            created_by: op.created_by,
            last_login_at: op.last_login_at.map(|t| t.to_rfc3339()),
        })
        .collect();

    Ok(Json(OperatorListResponse {
        count: infos.len(),
        operators: infos,
    }))
}

/// Create a new operator (admin only)
#[utoipa::path(
    post,
    path = "/v1/operators",
    tag = "operators",
    request_body = CreateOperatorRequest,
    responses(
        (status = 201, description = "Operator created", body = OperatorInfo),
        (status = 400, description = "Invalid input"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions"),
        (status = 409, description = "Username already exists")
    )
)]
pub async fn create_operator(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    auth_session: crate::auth::AuthSession,
    Json(req): Json<CreateOperatorRequest>,
) -> Result<(StatusCode, Json<OperatorInfo>), StatusCode> {
    use super::auth::require_role;
    use crate::domain::OperatorRole;
    use argon2::{
        Argon2, PasswordHasher,
        password_hash::{SaltString, rand_core::OsRng},
    };

    let auth_header = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok());

    let admin = require_role(&state, &auth_session, auth_header, OperatorRole::Admin)?;

    // Validate role
    let role: OperatorRole = req.role.parse().map_err(|_| StatusCode::BAD_REQUEST)?;

    // Validate username
    if req.username.len() > MAX_USERNAME_LEN || !is_valid_username(&req.username) {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate password length
    if req.password.len() < 8 || req.password.len() > MAX_PASSWORD_LEN {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check if username exists
    if state
        .repo
        .get_operator_by_username(&req.username)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .is_some()
    {
        return Err(StatusCode::CONFLICT);
    }

    // Hash password
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(req.password.as_bytes(), &salt)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .to_string();

    let operator = state
        .repo
        .create_operator(&req.username, &password_hash, role, Some(&admin.username))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tracing::info!(
        username = %operator.username,
        role = %operator.role,
        created_by = %admin.username,
        "operator created"
    );

    Ok((
        StatusCode::CREATED,
        Json(OperatorInfo {
            operator_id: operator.operator_id,
            username: operator.username,
            role: operator.role.to_string(),
            created_at: operator.created_at.to_rfc3339(),
            created_by: operator.created_by,
            last_login_at: None,
        }),
    ))
}

/// Delete an operator (admin only)
#[utoipa::path(
    delete,
    path = "/v1/operators/{id}",
    tag = "operators",
    params(
        ("id" = Uuid, Path, description = "Operator ID")
    ),
    responses(
        (status = 204, description = "Operator deleted"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Operator not found")
    )
)]
pub async fn delete_operator(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    auth_session: crate::auth::AuthSession,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    use super::auth::require_role;
    use crate::domain::OperatorRole;

    let auth_header = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok());

    let admin = require_role(&state, &auth_session, auth_header, OperatorRole::Admin)?;

    // Prevent self-deletion
    if admin.operator_id == id {
        tracing::warn!(operator_id = %id, "cannot delete self");
        return Err(StatusCode::BAD_REQUEST);
    }

    let deleted = state
        .repo
        .delete_operator(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if deleted {
        tracing::info!(operator_id = %id, deleted_by = %admin.username, "operator deleted");
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

/// Change operator password (admin or self)
#[utoipa::path(
    put,
    path = "/v1/operators/{id}/password",
    tag = "operators",
    params(
        ("id" = Uuid, Path, description = "Operator ID")
    ),
    request_body = ChangePasswordRequest,
    responses(
        (status = 204, description = "Password changed"),
        (status = 400, description = "Invalid password"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Operator not found")
    )
)]
pub async fn change_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    auth_session: crate::auth::AuthSession,
    Path(id): Path<Uuid>,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<StatusCode, StatusCode> {
    use super::auth::require_role;
    use crate::domain::OperatorRole;
    use argon2::{
        Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
        password_hash::{SaltString, rand_core::OsRng},
    };

    let auth_header = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok());

    // Allow self or admin to change password
    let caller = require_role(&state, &auth_session, auth_header, OperatorRole::Viewer)?;

    let is_self = caller.operator_id == id;
    let is_admin = caller.role == OperatorRole::Admin;

    if !is_self && !is_admin {
        return Err(StatusCode::FORBIDDEN);
    }

    // Validate password length
    if req.new_password.len() < 8 || req.new_password.len() > MAX_PASSWORD_LEN {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check operator exists
    let target = state
        .repo
        .get_operator_by_id(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Verify current password (required for self-change, skipped for admin reset of other users)
    if is_self {
        let parsed_hash = match PasswordHash::new(&target.password_hash) {
            Ok(h) => h,
            Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        };
        if Argon2::default()
            .verify_password(req.current_password.as_bytes(), &parsed_hash)
            .is_err()
        {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    // Hash new password
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(req.new_password.as_bytes(), &salt)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .to_string();

    state
        .repo
        .update_operator_password(id, &password_hash)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tracing::info!(
        operator_id = %id,
        username = %target.username,
        changed_by = %caller.username,
        "password changed"
    );

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use crate::db::PopInfo;

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

    #[test]
    fn test_validate_cidr_accepts_valid_values() {
        assert!(super::validate_cidr("203.0.113.0/24").is_ok());
        assert!(super::validate_cidr("2001:db8::/64").is_ok());
        assert!(super::validate_cidr("203.0.113.10").is_ok());
    }

    #[test]
    fn test_validate_cidr_rejects_invalid_masks() {
        assert!(super::validate_cidr("203.0.113.0/33").is_err());
        assert!(super::validate_cidr("2001:db8::/129").is_err());
        assert!(super::validate_cidr("203.0.113.0/not-a-mask").is_err());
    }

    #[test]
    fn test_is_valid_username() {
        assert!(super::is_valid_username("alice_1"));
        assert!(super::is_valid_username("ops-admin"));
        assert!(!super::is_valid_username(""));
        assert!(!super::is_valid_username("bad space"));
        assert!(!super::is_valid_username("no/slash"));
    }

    #[tokio::test]
    async fn test_login_throttle_blocks_after_limit() {
        let user = "throttle_test_user";
        super::clear_login_attempts(user).await;

        for _ in 0..super::LOGIN_MAX_ATTEMPTS {
            assert!(super::check_and_record_login_attempt(user).await.is_ok());
        }

        let blocked = super::check_and_record_login_attempt(user).await;
        assert_eq!(blocked, Err(axum::http::StatusCode::TOO_MANY_REQUESTS));

        super::clear_login_attempts(user).await;
    }
}

// Config read-only endpoints

#[derive(Serialize)]
pub struct ConfigSettingsResponse {
    settings: serde_json::Value,
    loaded_at: String,
}

#[utoipa::path(
    get,
    path = "/v1/config/settings",
    tag = "config",
    responses(
        (status = 200, description = "Running config (allowlist-redacted)")
    )
)]
pub async fn get_config_settings(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

    let s = &state.settings;

    // Allowlist: only expose operationally useful, non-sensitive fields.
    // New fields must be explicitly added here to avoid accidental leaks.
    let settings = serde_json::json!({
        "pop": s.pop,
        "mode": s.mode,
        "http": {
            "listen": s.http.listen,
            "auth": { "mode": s.http.auth.mode },
            "rate_limit": s.http.rate_limit,
            "cors_origin": s.http.cors_origin,
        },
        "bgp": {
            "mode": s.bgp.mode,
            "local_asn": s.bgp.local_asn,
            "neighbors": s.bgp.neighbors.iter().map(|n| serde_json::json!({
                "name": n.name,
                "address": n.address,
                "peer_asn": n.peer_asn,
                "afi_safi": n.afi_safi,
            })).collect::<Vec<_>>(),
        },
        "guardrails": s.guardrails,
        "quotas": s.quotas,
        "timers": s.timers,
        "escalation": s.escalation,
        "storage": { "connection_string": "[redacted]" },
        "observability": {
            "log_format": s.observability.log_format,
            "log_level": s.observability.log_level,
            "metrics_listen": s.observability.metrics_listen,
        },
        "safelist": { "count": s.safelist.prefixes.len() },
        "shutdown": s.shutdown,
    });

    // Settings are immutable after startup; compute startup wall-clock time
    let started_at = chrono::Utc::now()
        - chrono::Duration::from_std(state.start_time.elapsed()).unwrap_or_default();

    Ok(Json(ConfigSettingsResponse {
        settings,
        loaded_at: started_at.to_rfc3339(),
    }))
}

#[derive(Serialize)]
pub struct ConfigInventoryResponse {
    customers: Vec<crate::config::Customer>,
    total_customers: usize,
    total_services: usize,
    total_assets: usize,
    loaded_at: String,
}

#[utoipa::path(
    get,
    path = "/v1/config/inventory",
    tag = "config",
    responses(
        (status = 200, description = "Customer/service/IP inventory")
    )
)]
pub async fn get_config_inventory(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

    let inventory = state.inventory.read().await;
    let customers = inventory.customers.clone();
    let total_customers = customers.len();
    let total_services: usize = customers.iter().map(|c| c.services.len()).sum();
    let total_assets: usize = customers
        .iter()
        .flat_map(|c| &c.services)
        .map(|s| s.assets.len())
        .sum();
    drop(inventory);

    let loaded_at = state.inventory_loaded_at.read().await.to_rfc3339();

    Ok(Json(ConfigInventoryResponse {
        total_customers,
        total_services,
        total_assets,
        customers,
        loaded_at,
    }))
}

#[derive(Serialize)]
pub struct ConfigPlaybooksResponse {
    playbooks: Vec<crate::config::Playbook>,
    total_playbooks: usize,
    loaded_at: String,
}

#[utoipa::path(
    get,
    path = "/v1/config/playbooks",
    tag = "config",
    responses(
        (status = 200, description = "Playbook definitions")
    )
)]
pub async fn get_config_playbooks(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

    let playbooks_guard = state.playbooks.read().await;
    let playbooks = playbooks_guard.playbooks.clone();
    let total_playbooks = playbooks.len();
    drop(playbooks_guard);

    let loaded_at = state.playbooks_loaded_at.read().await.to_rfc3339();

    Ok(Json(ConfigPlaybooksResponse {
        total_playbooks,
        playbooks,
        loaded_at,
    }))
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct UpdatePlaybooksRequest {
    playbooks: Vec<crate::config::Playbook>,
}

#[utoipa::path(
    put,
    path = "/v1/config/playbooks",
    tag = "config",
    request_body = UpdatePlaybooksRequest,
    responses(
        (status = 200, description = "Updated playbook definitions"),
        (status = 400, description = "Validation failed"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions")
    )
)]
pub async fn update_playbooks(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    body: Result<Json<UpdatePlaybooksRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<impl IntoResponse, StatusCode> {
    use super::auth::require_role;
    use crate::config::Playbooks;
    use crate::domain::OperatorRole;
    use crate::observability::{ActorType, AuditEntry};

    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    let operator = require_role(&state, &auth_session, auth_header, OperatorRole::Admin)?;

    let Json(body) = match body {
        Ok(payload) => payload,
        Err(rejection) => {
            tracing::warn!(error = %rejection, "invalid playbook update payload");
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    let new_playbooks = Playbooks {
        playbooks: body.playbooks,
    };

    // Validate
    let errors = new_playbooks.validate();
    if !errors.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "errors": errors })),
        )
            .into_response());
    }

    // Serialize concurrent updates and keep in-memory state consistent with disk updates.
    let mut playbooks_guard = state.playbooks.write().await;
    let old_count = playbooks_guard.playbooks.len();
    let playbooks_path = state.playbooks_path();
    new_playbooks.save(&playbooks_path).map_err(|e| {
        tracing::error!(error = %e, "failed to save playbooks");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    *playbooks_guard = new_playbooks.clone();
    drop(playbooks_guard);
    *state.playbooks_loaded_at.write().await = chrono::Utc::now();

    // Audit log
    let audit = AuditEntry::new(
        ActorType::Operator,
        Some(operator.username.clone()),
        "update_playbooks",
        Some("config"),
        None,
        serde_json::json!({
            "previous_count": old_count,
            "new_count": new_playbooks.playbooks.len(),
        }),
    );
    if let Err(e) = state.repo.insert_audit(&audit).await {
        tracing::warn!(error = %e, "failed to insert audit entry for playbook update");
    }

    tracing::info!(
        operator = %operator.username,
        count = new_playbooks.playbooks.len(),
        "playbooks updated via API"
    );

    let loaded_at = state.playbooks_loaded_at.read().await.to_rfc3339();
    Ok(Json(ConfigPlaybooksResponse {
        total_playbooks: new_playbooks.playbooks.len(),
        playbooks: new_playbooks.playbooks,
        loaded_at,
    })
    .into_response())
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
        d.parse::<u32>().ok().map(|d| d * 24)
    } else {
        s.parse().ok()
    }
}

fn parse_duration_minutes(s: &str) -> Option<u32> {
    let s = s.trim();
    if let Some(m) = s.strip_suffix('m') {
        m.parse().ok()
    } else if let Some(h) = s.strip_suffix('h') {
        h.parse::<u32>().ok().map(|h| h * 60)
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

/// Get alerting configuration (redacted secrets)
#[utoipa::path(
    get,
    path = "/v1/config/alerting",
    tag = "config",
    responses(
        (status = 200, description = "Alerting configuration with redacted secrets"),
        (status = 401, description = "Not authenticated")
    )
)]
pub async fn get_alerting_config(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

    let alerting = state.alerting.read().await;
    let config = alerting.config();
    let destinations: Vec<serde_json::Value> =
        config.destinations.iter().map(|d| d.redacted()).collect();

    Ok(Json(serde_json::json!({
        "destinations": destinations,
        "events": config.events,
    })))
}

/// Update alerting configuration
#[utoipa::path(
    put,
    path = "/v1/config/alerting",
    tag = "config",
    request_body = crate::alerting::AlertingConfig,
    responses(
        (status = 200, description = "Updated alerting configuration"),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions")
    )
)]
pub async fn update_alerting_config(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    body: Result<Json<crate::alerting::AlertingConfig>, axum::extract::rejection::JsonRejection>,
) -> Result<impl IntoResponse, StatusCode> {
    use super::auth::require_role;
    use crate::domain::OperatorRole;
    use crate::observability::{ActorType, AuditEntry};

    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    let operator = require_role(&state, &auth_session, auth_header, OperatorRole::Admin)?;

    let Json(mut new_config) = match body {
        Ok(payload) => payload,
        Err(rejection) => {
            tracing::warn!(error = %rejection, "invalid alerting config payload");
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    // Serialize concurrent updates and merge from the current in-memory config.
    let mut alerting_guard = state.alerting.write().await;
    let current_config = alerting_guard.config().clone();
    let merge_errors = new_config.merge_secrets(&current_config);
    if !merge_errors.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "errors": merge_errors })),
        )
            .into_response());
    }

    // Validate after secret merge
    let errors = new_config.validate();
    if !errors.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "errors": errors })),
        )
            .into_response());
    }

    // Atomic save to alerting.yaml
    let alerting_path = state.alerting_path();
    new_config.save(&alerting_path).map_err(|e| {
        tracing::error!(error = %e, "failed to save alerting config");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Rebuild service and hot-swap
    let old_count = current_config.destinations.len();
    let new_service = crate::alerting::AlertingService::new(new_config.clone());
    *alerting_guard = new_service;
    drop(alerting_guard);
    *state.alerting_loaded_at.write().await = chrono::Utc::now();

    // Audit log
    let audit = AuditEntry::new(
        ActorType::Operator,
        Some(operator.username.clone()),
        "update_alerting",
        Some("config"),
        None,
        serde_json::json!({
            "previous_destinations": old_count,
            "new_destinations": new_config.destinations.len(),
        }),
    );
    if let Err(e) = state.repo.insert_audit(&audit).await {
        tracing::warn!(error = %e, "failed to insert audit entry for alerting update");
    }

    // Return redacted config
    let destinations: Vec<serde_json::Value> = new_config
        .destinations
        .iter()
        .map(|d| d.redacted())
        .collect();

    Ok(Json(serde_json::json!({
        "destinations": destinations,
        "events": new_config.events,
    }))
    .into_response())
}

/// Send a test alert to all configured destinations
#[utoipa::path(
    post,
    path = "/v1/config/alerting/test",
    tag = "config",
    responses(
        (status = 200, description = "Per-destination alert test results"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions")
    )
)]
pub async fn test_alerting(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    use super::auth::require_role;
    use crate::domain::OperatorRole;

    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_role(&state, &auth_session, auth_header, OperatorRole::Admin)?;

    let alert = crate::alerting::Alert::test_alert();
    let alerting = state.alerting.read().await.clone();
    let results = alerting.dispatch(&alert).await;

    let outcomes: Vec<serde_json::Value> = results
        .into_iter()
        .map(|(dest, result)| {
            serde_json::json!({
                "destination": dest,
                "status": if result.is_ok() { "ok" } else { "error" },
                "error": result.err(),
            })
        })
        .collect();

    Ok(Json(serde_json::json!({ "results": outcomes })))
}

// ---------------------------------------------------------------------------
// Correlation configuration
// ---------------------------------------------------------------------------

/// Get correlation configuration (allowlist-redacted, ADR 014)
#[utoipa::path(
    get,
    path = "/v1/config/correlation",
    tag = "config",
    responses(
        (status = 200, description = "Correlation configuration with redacted secrets"),
        (status = 401, description = "Not authenticated")
    )
)]
pub async fn get_correlation_config(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

    let config = state.correlation_config.read().await;
    let loaded_at = state.correlation_loaded_at.read().await;

    Ok(Json(serde_json::json!({
        "config": config.redacted(),
        "loaded_at": loaded_at.to_rfc3339(),
    })))
}

/// Update correlation configuration (admin only)
#[utoipa::path(
    put,
    path = "/v1/config/correlation",
    tag = "config",
    request_body = crate::correlation::CorrelationConfig,
    responses(
        (status = 200, description = "Updated correlation configuration"),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions")
    )
)]
pub async fn update_correlation_config(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    body: Result<
        Json<crate::correlation::CorrelationConfig>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<impl IntoResponse, StatusCode> {
    use crate::domain::OperatorRole;
    use crate::observability::{ActorType, AuditEntry};

    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    let operator = require_role(&state, &auth_session, auth_header, OperatorRole::Admin)?;

    let Json(new_config) = match body {
        Ok(payload) => payload,
        Err(rejection) => {
            tracing::warn!(error = %rejection, "invalid correlation config payload");
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    // Validate config
    let errors = new_config.validate();
    if !errors.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "errors": errors })),
        )
            .into_response());
    }

    // Atomic save to correlation.yaml
    let correlation_path = state.correlation_path();
    new_config.save(&correlation_path).map_err(|e| {
        tracing::error!(error = %e, "failed to save correlation config");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Hot-swap in-memory config
    let previous_enabled = {
        let current = state.correlation_config.read().await;
        current.enabled
    };
    *state.correlation_config.write().await = new_config.clone();
    *state.correlation_loaded_at.write().await = chrono::Utc::now();

    // Audit log
    let audit = AuditEntry::new(
        ActorType::Operator,
        Some(operator.username.clone()),
        "update_correlation",
        Some("config"),
        None,
        serde_json::json!({
            "previous_enabled": previous_enabled,
            "new_enabled": new_config.enabled,
            "sources": new_config.sources.len(),
        }),
    );
    if let Err(e) = state.repo.insert_audit(&audit).await {
        tracing::warn!(error = %e, "failed to insert audit entry for correlation update");
    }

    // Return redacted config
    Ok(Json(serde_json::json!({
        "config": new_config.redacted(),
        "loaded_at": chrono::Utc::now().to_rfc3339(),
    }))
    .into_response())
}

// ---------------------------------------------------------------------------
// Notification preferences
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/v1/preferences",
    responses(
        (status = 200, description = "Notification preferences", body = NotificationPreferences),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "preferences"
)]
pub async fn get_notification_preferences(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
) -> Result<Json<NotificationPreferences>, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    let operator = require_role(
        &state,
        &auth_session,
        auth_header,
        crate::domain::OperatorRole::Viewer,
    )?;

    let prefs = state
        .repo
        .get_notification_preferences(operator.operator_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .unwrap_or_default();

    Ok(Json(prefs))
}

#[utoipa::path(
    put,
    path = "/v1/preferences",
    request_body = NotificationPreferences,
    responses(
        (status = 200, description = "Preferences updated"),
        (status = 400, description = "Invalid preferences"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "preferences"
)]
pub async fn update_notification_preferences(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Json(prefs): Json<NotificationPreferences>,
) -> Result<StatusCode, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    let operator = require_role(
        &state,
        &auth_session,
        auth_header,
        crate::domain::OperatorRole::Viewer,
    )?;

    match (prefs.quiet_hours_start, prefs.quiet_hours_end) {
        (Some(_), None) | (None, Some(_)) => return Err(StatusCode::BAD_REQUEST),
        _ => {}
    }
    if let Some(start) = prefs.quiet_hours_start {
        if !(0..=23).contains(&start) {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    if let Some(end) = prefs.quiet_hours_end {
        if !(0..=23).contains(&end) {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    for evt in &prefs.muted_events {
        if !crate::alerting::AlertEventType::ALL_STRINGS.contains(&evt.as_str()) {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    state
        .repo
        .upsert_notification_preferences(operator.operator_id, &prefs)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::OK)
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
        ("mitigation_id" = Option<String>, Query, description = "Mitigation ID to generate report for"),
        ("ip" = Option<String>, Query, description = "IP address to generate report for"),
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
    let ip = match (query.mitigation_id, &query.ip) {
        (Some(mid), None) => {
            let mitigation = match state.repo.get_mitigation(mid).await {
                Ok(Some(m)) => m,
                Ok(None) => return StatusCode::NOT_FOUND.into_response(),
                Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            };
            mitigation.victim_ip
        }
        (None, Some(ip_str)) => ip_str.clone(),
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };

    if validate_ip(&ip).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Fetch events and mitigations in parallel
    let (events, mitigations) = match tokio::try_join!(
        state.repo.list_events_by_ip(&ip, 1000),
        state.repo.list_mitigations_by_ip(&ip, 100),
    ) {
        Ok(data) => data,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
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

    // Inventory lookup for customer/service context
    let inventory = state.inventory.read().await;
    let mut customer_name: Option<String> = None;
    let mut customer_id: Option<String> = None;
    let mut service_name: Option<String> = None;
    let mut service_id: Option<String> = None;
    'customer_search: for customer in &inventory.customers {
        for service in &customer.services {
            if service
                .assets
                .iter()
                .any(|asset| asset.ip.as_str() == ip.as_str())
            {
                customer_name = Some(customer.name.clone());
                customer_id = Some(customer.customer_id.clone());
                service_name = Some(service.name.clone());
                service_id = Some(service.service_id.clone());
                break 'customer_search;
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
        md.push_str("| Mitigation ID | Status | Action | Vector | Prefix | Duration |\n");
        md.push_str("|---------------|--------|--------|--------|--------|----------|\n");
        for m in &mitigations {
            let end_time = m.withdrawn_at.unwrap_or(m.expires_at).min(now);
            let duration_secs = (end_time - m.created_at).num_seconds().max(0);
            md.push_str(&format!(
                "| `{}` | {} | {} | {} | `{}` | {} |\n",
                m.mitigation_id,
                m.status,
                m.action_type,
                m.vector,
                m.match_criteria.dst_prefix,
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
        ("status" = Option<String>, Query, description = "Filter by status (open, resolved, expired)"),
        ("vector" = Option<String>, Query, description = "Filter by attack vector"),
        ("limit" = Option<u32>, Query, description = "Max results (default 100, max 1000)"),
        ("cursor" = Option<String>, Query, description = "Cursor for pagination (from previous response)"),
        ("start" = Option<String>, Query, description = "Start of date range (ISO 8601, inclusive)"),
        ("end" = Option<String>, Query, description = "End of date range (ISO 8601, exclusive)"),
    ),
    responses(
        (status = 200, description = "List of signal groups", body = SignalGroupsListResponse),
        (status = 401, description = "Authentication required"),
    )
)]
pub async fn list_signal_groups(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Query(query): Query<ListSignalGroupsQuery>,
) -> Result<Json<SignalGroupsListResponse>, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

    let status_filter = query.status.as_deref().and_then(|s| s.parse().ok());

    let limit = clamp_limit(query.limit);
    let cursor = query.cursor.as_deref().and_then(decode_cursor);
    let params = ListParams {
        limit: limit + 1,
        cursor,
        start: query.start.as_deref().and_then(parse_datetime),
        end: query.end.as_deref().and_then(parse_datetime),
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
        groups.last().map(|g| encode_cursor(&g.created_at))
    } else {
        None
    };
    let count = groups.len();

    Ok(Json(SignalGroupsListResponse {
        groups,
        count,
        next_cursor,
        has_more,
    }))
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

    tracing::info!(
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
        confidence: Some(confidence),
        action,
        raw_details: None,
    };

    // Delegate to the existing event ingestion pipeline
    match input.action.as_str() {
        "unban" => match handle_unban(state.clone(), input).await {
            Ok((_status, Json(resp))) => Ok(AlertmanagerAlertResult {
                index,
                status: "withdrawn".to_string(),
                event_id: Some(resp.event_id),
                mitigation_id: resp.mitigation_id,
                error: None,
            }),
            Err(AppError(e)) => Ok(AlertmanagerAlertResult {
                index,
                status: "withdrawn_noop".to_string(),
                event_id: None,
                mitigation_id: None,
                error: Some(e.to_string()),
            }),
        },
        _ => match handle_ban(state.clone(), input).await {
            Ok((_status, Json(resp))) => Ok(AlertmanagerAlertResult {
                index,
                status: resp.status,
                event_id: Some(resp.event_id),
                mitigation_id: resp.mitigation_id,
                error: None,
            }),
            Err(AppError(PrefixdError::DuplicateEvent { .. })) => Ok(AlertmanagerAlertResult {
                index,
                status: "duplicate".to_string(),
                event_id: None,
                mitigation_id: None,
                error: None,
            }),
            Err(AppError(e)) => Err(AlertmanagerAlertResult {
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
    if syn_pps > 0 && (tcp_pps == 0 || syn_pps * 100 / tcp_pps.max(1) > 60) && syn_pps > udp_pps {
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

    // Classify attack vector from details
    let vector = payload
        .attack_details
        .as_ref()
        .map(classify_fastnetmon_vector)
        .unwrap_or(AttackVector::Unknown);

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

// ==========================================================================
// Generic webhook adapter
// ==========================================================================

/// Per-event result for the generic webhook endpoint.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct WebhookEventResult {
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

    tracing::info!(
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
    #[serde(default)]
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
        (status = 400, description = "Invalid source mode or missing dimensions"),
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

    tracing::info!(
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
                tracing::debug!(
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
        tracing::info!(
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
