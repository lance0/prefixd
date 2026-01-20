use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
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

#[derive(Deserialize)]
pub struct CreateMitigationRequest {
    #[allow(dead_code)]
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
    Json(input): Json<AttackEventInput>,
) -> impl IntoResponse {
    // Check for duplicate
    if let Some(ref ext_id) = input.event_id {
        if let Ok(Some(_)) = state
            .repo
            .find_event_by_external_id(&input.source, ext_id)
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

    let limit = query.limit.unwrap_or(100);
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
#[utoipa::path(
    get,
    path = "/v1/health",
    tag = "health",
    responses(
        (status = 200, description = "Service is healthy", body = HealthResponse)
    )
)]
pub async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Check GoBGP connectivity
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

    // Check database connectivity
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

    // Determine overall status
    let status = if db_error || gobgp_health.status == "error" {
        "degraded"
    } else {
        "healthy"
    };

    Json(HealthResponse {
        status: status.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        pop: state.settings.pop.clone(),
        uptime_seconds: state.start_time.elapsed().as_secs(),
        bgp_sessions: bgp_map,
        active_mitigations: active,
        database: db_status,
        gobgp: gobgp_health,
    })
}

pub async fn metrics() -> impl IntoResponse {
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

    let pops = state
        .repo
        .list_pops()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
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

    let creds = Credentials {
        username: req.username,
        password: req.password,
    };

    let operator = auth_session
        .authenticate(creds)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    auth_session
        .login(&operator)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

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
