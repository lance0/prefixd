use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::domain::{
    ActionParams, ActionType, AttackEvent, AttackEventInput, FlowSpecAction, FlowSpecNlri,
    FlowSpecRule, MatchCriteria, Mitigation, MitigationIntent, MitigationStatus,
};
use crate::error::PrefixdError;
use crate::guardrails::Guardrails;
use crate::policy::PolicyEngine;
use crate::AppState;

// Response types

#[derive(Serialize, ToSchema)]
pub struct EventResponse {
    /// Unique identifier for this event
    event_id: Uuid,
    /// External event ID from the detector
    external_event_id: Option<String>,
    /// Processing status
    status: String,
    /// ID of the created mitigation, if any
    mitigation_id: Option<Uuid>,
}

#[derive(Serialize, ToSchema)]
pub struct MitigationResponse {
    /// Unique mitigation identifier
    mitigation_id: Uuid,
    /// Current status (pending, active, withdrawn, expired)
    status: String,
    /// Customer ID from inventory
    customer_id: Option<String>,
    /// Victim IP address being protected
    victim_ip: String,
    /// Attack vector type
    vector: String,
    /// Action type (discard, police)
    action_type: String,
    /// Rate limit in bps (for police action)
    rate_bps: Option<u64>,
    /// When the mitigation was created
    created_at: String,
    /// When the mitigation expires
    expires_at: String,
    /// Scope hash for deduplication
    scope_hash: String,
}

impl From<&Mitigation> for MitigationResponse {
    fn from(m: &Mitigation) -> Self {
        Self {
            mitigation_id: m.mitigation_id,
            status: m.status.to_string(),
            customer_id: m.customer_id.clone(),
            victim_ip: m.victim_ip.clone(),
            vector: m.vector.to_string(),
            action_type: m.action_type.to_string(),
            rate_bps: m.action_params.rate_bps,
            created_at: m.created_at.to_rfc3339(),
            expires_at: m.expires_at.to_rfc3339(),
            scope_hash: m.scope_hash.clone(),
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
    /// BGP session states by peer name
    bgp_sessions: std::collections::HashMap<String, String>,
    /// Number of active mitigations
    active_mitigations: u32,
    /// Database connectivity status
    database: String,
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
        if let Ok(Some(_)) = state.repo.find_event_by_external_id(&input.source, ext_id).await {
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
        state.repo.update_mitigation(&existing).await.map_err(AppError)?;

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
    let guardrails = Guardrails::new(
        state.settings.guardrails.clone(),
        state.settings.quotas.clone(),
    );

    let is_safelisted = state.repo.is_safelisted(&event.victim_ip).await.unwrap_or(false);

    if let Err(e) = guardrails.validate(&intent, state.repo.as_ref(), is_safelisted).await {
        tracing::warn!(error = %e, "guardrail rejected mitigation");
        return Err(AppError(e));
    }

    // Create mitigation
    let mut mitigation = Mitigation::from_intent(intent, event.victim_ip.clone(), event.attack_vector());

    // Announce FlowSpec (if not dry-run)
    if !state.is_dry_run() {
        let nlri = FlowSpecNlri::from(&mitigation.match_criteria);
        let action = FlowSpecAction::from((mitigation.action_type, &mitigation.action_params));
        let rule = FlowSpecRule::new(nlri, action);

        if let Err(e) = state.announcer.announce(&rule).await {
            tracing::error!(error = %e, "BGP announcement failed");
            mitigation.reject(e.to_string());
            state.repo.insert_mitigation(&mitigation).await.map_err(AppError)?;
            return Err(AppError(e));
        }
    }

    mitigation.activate();
    state.repo.insert_mitigation(&mitigation).await.map_err(AppError)?;

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
    Query(query): Query<ListEventsQuery>,
) -> impl IntoResponse {
    let limit = clamp_limit(query.limit.unwrap_or(100));
    let offset = query.offset.unwrap_or(0);

    let events = state
        .repo
        .list_events(limit, offset)
        .await
        .map_err(AppError)?;

    let count = events.len();
    Ok::<_, AppError>(Json(EventsListResponse { events, count }))
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
    Query(query): Query<ListEventsQuery>,
) -> impl IntoResponse {
    let limit = query.limit.unwrap_or(100);
    let offset = query.offset.unwrap_or(0);

    let entries = state
        .repo
        .list_audit(limit, offset)
        .await
        .map_err(AppError)?;

    Ok::<_, AppError>(Json(entries))
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
    Query(query): Query<ListMitigationsQuery>,
) -> impl IntoResponse {
    let status_filter: Option<Vec<MitigationStatus>> = query.status.as_ref().map(|s| {
        s.split(',')
            .filter_map(|st| st.parse().ok())
            .collect()
    });

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
            .map_err(AppError)?
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
            .map_err(AppError)?
    };

    let count = mitigations.len();
    let responses: Vec<_> = mitigations.iter().map(MitigationResponse::from).collect();

    Ok::<_, AppError>(Json(MitigationsListResponse {
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
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let mitigation = state
        .repo
        .get_mitigation(id)
        .await
        .map_err(AppError)?
        .ok_or_else(|| AppError(PrefixdError::MitigationNotFound(id)))?;

    Ok::<_, AppError>(Json(MitigationResponse::from(&mitigation)))
}

pub async fn create_mitigation(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateMitigationRequest>,
) -> impl IntoResponse {
    // Validate protocol - reject unknown values instead of silently converting to None
    let protocol = match req.protocol.as_str() {
        "udp" => Some(17u8),
        "tcp" => Some(6u8),
        "icmp" => Some(1u8),
        "any" | "" => None,
        _ => return Err(AppError(PrefixdError::InvalidRequest(
            format!("invalid protocol '{}', expected: udp, tcp, icmp, any", req.protocol)
        ))),
    };

    // Validate action type
    let action_type = match req.action.as_str() {
        "police" => {
            // Police action requires rate_bps
            if req.rate_bps.is_none() {
                return Err(AppError(PrefixdError::InvalidRequest(
                    "action 'police' requires rate_bps".to_string()
                )));
            }
            ActionType::Police
        }
        "discard" => ActionType::Discard,
        _ => return Err(AppError(PrefixdError::InvalidRequest(
            format!("invalid action '{}', expected: discard, police", req.action)
        ))),
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
        action_params: ActionParams { rate_bps: req.rate_bps },
        ttl_seconds: req.ttl_seconds,
        reason: req.reason,
    };

    // Validate
    let guardrails = Guardrails::new(
        state.settings.guardrails.clone(),
        state.settings.quotas.clone(),
    );
    let is_safelisted = state.repo.is_safelisted(&req.victim_ip).await.unwrap_or(false);
    guardrails.validate(&intent, state.repo.as_ref(), is_safelisted).await.map_err(AppError)?;

    // Create and announce
    let mut mitigation = Mitigation::from_intent(
        intent,
        req.victim_ip,
        crate::domain::AttackVector::Unknown,
    );

    if !state.is_dry_run() {
        let nlri = FlowSpecNlri::from(&mitigation.match_criteria);
        let action = FlowSpecAction::from((mitigation.action_type, &mitigation.action_params));
        let rule = FlowSpecRule::new(nlri, action);
        state.announcer.announce(&rule).await.map_err(AppError)?;
    }

    mitigation.activate();
    state.repo.insert_mitigation(&mitigation).await.map_err(AppError)?;

    Ok::<_, AppError>((StatusCode::CREATED, Json(MitigationResponse::from(&mitigation))))
}

pub async fn withdraw_mitigation(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(req): Json<WithdrawRequest>,
) -> impl IntoResponse {
    let mut mitigation = state
        .repo
        .get_mitigation(id)
        .await
        .map_err(AppError)?
        .ok_or_else(|| AppError(PrefixdError::MitigationNotFound(id)))?;

    if !mitigation.is_active() {
        return Err(AppError(PrefixdError::InvalidRequest(
            "mitigation not active".to_string(),
        )));
    }

    // Withdraw BGP
    if !state.is_dry_run() {
        let nlri = FlowSpecNlri::from(&mitigation.match_criteria);
        let action = FlowSpecAction::from((mitigation.action_type, &mitigation.action_params));
        let rule = FlowSpecRule::new(nlri, action);
        state.announcer.withdraw(&rule).await.map_err(AppError)?;
    }

    mitigation.withdraw(Some(format!("{}: {}", req.operator_id, req.reason)));
    state.repo.update_mitigation(&mitigation).await.map_err(AppError)?;

    tracing::info!(
        mitigation_id = %mitigation.mitigation_id,
        operator = %req.operator_id,
        "mitigation withdrawn"
    );

    Ok::<_, AppError>(Json(MitigationResponse::from(&mitigation)))
}

pub async fn list_safelist(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let entries = state.repo.list_safelist().await.map_err(AppError)?;
    Ok::<_, AppError>(Json(entries))
}

pub async fn add_safelist(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddSafelistRequest>,
) -> impl IntoResponse {
    state
        .repo
        .insert_safelist(&req.prefix, &req.operator_id, req.reason.as_deref())
        .await
        .map_err(AppError)?;

    tracing::info!(prefix = %req.prefix, operator = %req.operator_id, "safelist entry added");
    Ok::<_, AppError>(StatusCode::CREATED)
}

pub async fn remove_safelist(
    State(state): State<Arc<AppState>>,
    Path(prefix): Path<String>,
) -> impl IntoResponse {
    let removed = state.repo.remove_safelist(&prefix).await.map_err(AppError)?;
    if removed {
        Ok::<_, AppError>(StatusCode::NO_CONTENT)
    } else {
        Err(AppError(PrefixdError::NotFound(format!("safelist entry: {}", prefix))))
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
    let sessions = state.announcer.session_status().await.unwrap_or_default();

    // Check database connectivity
    let (active, db_status) = match state.repo.count_active_global().await {
        Ok(count) => (count, "connected".to_string()),
        Err(e) => (0, format!("error: {}", e)),
    };

    let bgp_map: std::collections::HashMap<_, _> = sessions
        .into_iter()
        .map(|s| (s.name, s.state.to_string()))
        .collect();

    let status = if db_status.starts_with("error") {
        "degraded"
    } else {
        "healthy"
    };

    Json(HealthResponse {
        status: status.to_string(),
        bgp_sessions: bgp_map,
        active_mitigations: active,
        database: db_status,
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

pub async fn reload_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.reload_config().await {
        Ok(reloaded) => {
            crate::observability::CONFIG_RELOADS
                .with_label_values(&["success"])
                .inc();
            Ok::<_, AppError>(Json(ReloadResponse {
                reloaded,
                timestamp: chrono::Utc::now().to_rfc3339(),
            }))
        }
        Err(e) => {
            crate::observability::CONFIG_RELOADS
                .with_label_values(&["error"])
                .inc();
            Err(AppError(e))
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
pub async fn get_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let stats = state.repo.get_stats().await.map_err(AppError)?;
    Ok::<_, AppError>(Json(stats))
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
pub async fn list_pops(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let pops = state.repo.list_pops().await.map_err(AppError)?;
    Ok::<_, AppError>(Json(pops))
}

// Error handling

struct AppError(PrefixdError);

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let status = self.0.status_code();
        let body = Json(ErrorResponse {
            error: self.0.to_string(),
            retry_after_seconds: match &self.0 {
                PrefixdError::RateLimited { retry_after_seconds } => Some(*retry_after_seconds),
                _ => None,
            },
        });
        (status, body).into_response()
    }
}
