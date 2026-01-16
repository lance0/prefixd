use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
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

#[derive(Serialize)]
pub struct EventResponse {
    event_id: Uuid,
    external_event_id: Option<String>,
    status: String,
    mitigation_id: Option<Uuid>,
}

#[derive(Serialize)]
pub struct MitigationResponse {
    mitigation_id: Uuid,
    status: String,
    customer_id: Option<String>,
    victim_ip: String,
    vector: String,
    action_type: String,
    rate_bps: Option<u64>,
    created_at: String,
    expires_at: String,
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

#[derive(Serialize)]
pub struct MitigationsListResponse {
    mitigations: Vec<MitigationResponse>,
    total: usize,
}

#[derive(Serialize)]
pub struct HealthResponse {
    status: String,
    bgp_sessions: std::collections::HashMap<String, String>,
    active_mitigations: u32,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_seconds: Option<u32>,
}

// Request types

#[derive(Deserialize)]
pub struct ListMitigationsQuery {
    status: Option<String>,
    customer_id: Option<String>,
    #[serde(default = "default_limit")]
    limit: u32,
    #[serde(default)]
    offset: u32,
}

fn default_limit() -> u32 {
    100
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

    // Lookup IP context
    let context = state.inventory.lookup_ip(&event.victim_ip);

    if context.is_none() && !state.inventory.is_owned(&event.victim_ip) {
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

    // Build policy engine and evaluate
    let policy = PolicyEngine::new(
        state.playbooks.clone(),
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

    if let Err(e) = guardrails.validate(&intent, &state.repo, is_safelisted).await {
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

pub async fn list_mitigations(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListMitigationsQuery>,
) -> impl IntoResponse {
    let status_filter: Option<Vec<MitigationStatus>> = query.status.as_ref().map(|s| {
        s.split(',')
            .filter_map(|st| st.parse().ok())
            .collect()
    });

    let mitigations = state
        .repo
        .list_mitigations(
            status_filter.as_deref(),
            query.customer_id.as_deref(),
            query.limit,
            query.offset,
        )
        .await
        .map_err(AppError)?;

    let total = mitigations.len();
    let responses: Vec<_> = mitigations.iter().map(MitigationResponse::from).collect();

    Ok::<_, AppError>(Json(MitigationsListResponse {
        mitigations: responses,
        total,
    }))
}

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
    let protocol = match req.protocol.as_str() {
        "udp" => Some(17u8),
        "tcp" => Some(6u8),
        "icmp" => Some(1u8),
        _ => None,
    };

    let action_type = match req.action.as_str() {
        "police" => ActionType::Police,
        "discard" => ActionType::Discard,
        _ => return Err(AppError(PrefixdError::InvalidRequest("invalid action".to_string()))),
    };

    let intent = MitigationIntent {
        event_id: Uuid::new_v4(),
        customer_id: state.inventory.lookup_ip(&req.victim_ip).map(|c| c.customer_id),
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
    guardrails.validate(&intent, &state.repo, is_safelisted).await.map_err(AppError)?;

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

pub async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let sessions = state.announcer.session_status().await.unwrap_or_default();
    let active = state.repo.count_active_global().await.unwrap_or(0);

    let bgp_map: std::collections::HashMap<_, _> = sessions
        .into_iter()
        .map(|s| (s.name, s.state.to_string()))
        .collect();

    Json(HealthResponse {
        status: "healthy".to_string(),
        bgp_sessions: bgp_map,
        active_mitigations: active,
    })
}

pub async fn metrics() -> impl IntoResponse {
    crate::observability::gather_metrics()
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
