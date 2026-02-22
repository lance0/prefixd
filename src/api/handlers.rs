use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;
use crate::domain::{
    ActionParams, ActionType, AttackEvent, AttackEventInput, FlowSpecAction, FlowSpecNlri,
    FlowSpecRule, MatchCriteria, Mitigation, MitigationIntent, MitigationStatus,
};
use crate::error::PrefixdError;
use crate::guardrails::Guardrails;
use crate::policy::PolicyEngine;

use super::auth::require_auth;
use crate::auth::AuthSession;

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
}

#[derive(Serialize, ToSchema)]
pub struct EventsListResponse {
    /// List of events in this page
    events: Vec<AttackEvent>,
    /// Number of events returned in this page
    count: usize,
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
pub struct ListEventsQuery {
    limit: Option<u32>,
    offset: Option<u32>,
}

#[derive(Deserialize)]
pub struct ListMitigationsQuery {
    status: Option<String>,
    customer_id: Option<String>,
    /// Filter by victim IP address
    victim_ip: Option<String>,
    /// Filter by POP. Use "all" to see mitigations from all POPs.
    pop: Option<String>,
    #[serde(default = "default_limit")]
    limit: u32,
    #[serde(default)]
    offset: u32,
}

fn default_limit() -> u32 {
    100
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
pub struct CreateMitigationRequest {
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
pub struct WithdrawRequest {
    operator_id: String,
    reason: String,
}

#[derive(Deserialize)]
pub struct AddSafelistRequest {
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
    let _ = state.repo.insert_event(&unban_event).await;

    // Withdraw from BGP (if not dry-run)
    if !state.is_dry_run() {
        let nlri = FlowSpecNlri::from(&mitigation.match_criteria);
        let action = FlowSpecAction::from((mitigation.action_type, &mitigation.action_params));
        let rule = FlowSpecRule::new(nlri, action);

        if let Err(e) = state.announcer.withdraw(&rule).await {
            tracing::error!(error = %e, "BGP withdrawal failed");
            // Continue anyway - mark as withdrawn in DB
        }
    }

    // Update mitigation status
    mitigation.withdraw(Some(format!("Detector unban: {}", source)));
    state
        .repo
        .update_mitigation(&mitigation)
        .await
        .map_err(AppError)?;

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

    // Build policy engine and evaluate
    let playbooks = state.playbooks.read().await.clone();
    let policy = PolicyEngine::new(
        playbooks,
        state.settings.pop.clone(),
        state.settings.timers.default_ttl_seconds,
    );

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

    // Validate guardrails
    let guardrails = Guardrails::with_timers(
        state.settings.guardrails.clone(),
        state.settings.quotas.clone(),
        &state.settings.timers,
    );

    let is_safelisted = state
        .repo
        .is_safelisted(&event.victim_ip)
        .await
        .unwrap_or(false);

    if let Err(e) = guardrails
        .validate(&intent, state.repo.as_ref(), is_safelisted)
        .await
    {
        tracing::warn!(error = %e, "guardrail rejected mitigation");
        return Err(AppError(e));
    }

    // Create mitigation
    let mut mitigation =
        Mitigation::from_intent(intent, event.victim_ip.clone(), event.attack_vector());

    // Announce FlowSpec (if not dry-run)
    if !state.is_dry_run() {
        let nlri = FlowSpecNlri::from(&mitigation.match_criteria);
        let action = FlowSpecAction::from((mitigation.action_type, &mitigation.action_params));
        let rule = FlowSpecRule::new(nlri, action);

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
    }

    mitigation.activate();
    state
        .repo
        .insert_mitigation(&mitigation)
        .await
        .map_err(AppError)?;

    // Broadcast new mitigation via WebSocket
    let _ = state
        .ws_broadcast
        .send(crate::ws::WsMessage::MitigationCreated {
            mitigation: MitigationResponse::from(&mitigation),
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
        ("offset" = Option<u32>, Query, description = "Offset for pagination"),
    ),
    responses(
        (status = 200, description = "List of events", body = EventsListResponse)
    )
)]
pub async fn list_events(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Query(query): Query<ListEventsQuery>,
) -> Result<Json<EventsListResponse>, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

    let limit = clamp_limit(query.limit.unwrap_or(100));
    let offset = query.offset.unwrap_or(0);

    let events = state
        .repo
        .list_events(limit, offset)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let count = events.len();
    Ok(Json(EventsListResponse { events, count }))
}

/// List audit log entries
#[utoipa::path(
    get,
    path = "/v1/audit",
    tag = "audit",
    params(
        ("limit" = Option<u32>, Query, description = "Max results (default 100)"),
        ("offset" = Option<u32>, Query, description = "Offset for pagination"),
    ),
    responses(
        (status = 200, description = "List of audit log entries")
    )
)]
pub async fn list_audit(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Query(query): Query<ListEventsQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

    let limit = clamp_limit(query.limit.unwrap_or(100));
    let offset = query.offset.unwrap_or(0);

    let entries = state
        .repo
        .list_audit(limit, offset)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(entries))
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
        ("limit" = Option<u32>, Query, description = "Max results (default 100)"),
        ("offset" = Option<u32>, Query, description = "Offset for pagination"),
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
    // Check auth (bearer token)
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

    let status_filter: Option<Vec<MitigationStatus>> = query
        .status
        .as_ref()
        .map(|s| s.split(',').filter_map(|st| st.parse().ok()).collect());

    let limit = clamp_limit(query.limit);

    // If pop=all, list mitigations from all POPs
    let mitigations = if query.pop.as_deref() == Some("all") {
        state
            .repo
            .list_mitigations_all_pops(
                status_filter.as_deref(),
                query.customer_id.as_deref(),
                query.victim_ip.as_deref(),
                limit,
                query.offset,
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
                limit,
                query.offset,
            )
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    };

    let count = mitigations.len();
    let responses: Vec<_> = mitigations.iter().map(MitigationResponse::from).collect();

    Ok(Json(MitigationsListResponse {
        mitigations: responses,
        count,
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

    Ok(Json(MitigationResponse::from(&mitigation)))
}

pub async fn create_mitigation(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Json(req): Json<CreateMitigationRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    // Check auth first
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

    // Validate input
    if let Err(e) = validate_ip(&req.victim_ip) {
        return Ok(AppError(e).into_response());
    }
    if let Err(e) = validate_string_len(&req.reason, "reason", MAX_STRING_LEN) {
        return Ok(AppError(e).into_response());
    }
    if let Err(e) = validate_string_len(&req.operator_id, "operator_id", MAX_USERNAME_LEN) {
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

    let intent = MitigationIntent {
        event_id: Uuid::new_v4(),
        customer_id,
        service_id: None,
        pop: state.settings.pop.clone(),
        match_criteria: MatchCriteria {
            dst_prefix: format!("{}/32", req.victim_ip),
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
    let is_safelisted = state
        .repo
        .is_safelisted(&req.victim_ip)
        .await
        .unwrap_or(false);
    if let Err(e) = guardrails
        .validate(&intent, state.repo.as_ref(), is_safelisted)
        .await
    {
        return Ok(AppError(e).into_response());
    }

    // Create and announce
    let mut mitigation =
        Mitigation::from_intent(intent, req.victim_ip, crate::domain::AttackVector::Unknown);

    if !state.is_dry_run() {
        let nlri = FlowSpecNlri::from(&mitigation.match_criteria);
        let action = FlowSpecAction::from((mitigation.action_type, &mitigation.action_params));
        let rule = FlowSpecRule::new(nlri, action);
        if let Err(e) = state.announcer.announce(&rule).await {
            return Ok(AppError(e).into_response());
        }
    }

    mitigation.activate();
    if let Err(e) = state.repo.insert_mitigation(&mitigation).await {
        return Ok(AppError(e).into_response());
    }

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
    require_auth(&state, &auth_session, auth_header)?;

    if req.operator_id.is_empty()
        || validate_string_len(&req.operator_id, "operator_id", MAX_USERNAME_LEN).is_err()
    {
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
        state
            .announcer
            .withdraw(&rule)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    mitigation.withdraw(Some(format!("{}: {}", req.operator_id, req.reason)));
    state
        .repo
        .update_mitigation(&mitigation)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

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
        operator = %req.operator_id,
        "mitigation withdrawn"
    );

    Ok(Json(MitigationResponse::from(&mitigation)))
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
    require_auth(&state, &auth_session, auth_header)?;

    validate_cidr(&req.prefix).map_err(|_| StatusCode::BAD_REQUEST)?;
    validate_string_len(&req.operator_id, "operator_id", MAX_USERNAME_LEN)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if let Some(ref reason) = req.reason {
        validate_string_len(reason, "reason", MAX_STRING_LEN)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
    }

    state
        .repo
        .insert_safelist(&req.prefix, &req.operator_id, req.reason.as_deref())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tracing::info!(prefix = %req.prefix, operator = %req.operator_id, "safelist entry added");
    Ok(StatusCode::CREATED)
}

pub async fn remove_safelist(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Path(prefix): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

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
    require_auth(&state, &auth_session, auth_header)?;

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
        Argon2, PasswordHasher,
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
    Query(query): Query<ListEventsQuery>,
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
