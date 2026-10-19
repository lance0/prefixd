use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

use crate::AppState;
use crate::api::auth::{require_auth, require_role};
use crate::auth::AuthSession;

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
        Err(e) => {
            tracing::error!(target: "prefixd::api::handlers", error = %e, "reload_config failed");
            crate::observability::CONFIG_RELOADS
                .with_label_values(&["error"])
                .inc();
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
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
        "amplification": {
            "min_src_port_share": s.amplification.min_src_port_share,
            "reflector_ports": s.amplification.reflector_ports.clone().unwrap_or_else(|| {
                crate::config::DEFAULT_REFLECTOR_PORTS
                    .iter()
                    .map(|&(port, name)| crate::config::ReflectorPort { port, name: name.into() })
                    .collect()
            }),
            "reflector_ports_default": s.amplification.reflector_ports.is_none(),
        },
        "quotas": s.quotas,
        "timers": s.timers,
        "storage": { "connection_string": "[redacted]" },
        "observability": {
            "log_format": s.observability.log_format,
            "log_level": s.observability.log_level,
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
    use crate::api::auth::require_role;
    use crate::config::Playbooks;
    use crate::domain::OperatorRole;
    use crate::observability::{ActorType, AuditEntry};

    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    let operator = require_role(&state, &auth_session, auth_header, OperatorRole::Admin)?;

    let Json(body) = match body {
        Ok(payload) => payload,
        Err(rejection) => {
            tracing::warn!(target: "prefixd::api::handlers", error = %rejection, "invalid playbook update payload");
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    let new_playbooks = Playbooks {
        playbooks: body.playbooks,
    };

    // Validate, including the rule opt-ins and speaker capability (ADR 028) and
    // the blackhole enablement, TTL cap and lease gate (ADR 027).
    let mut errors = new_playbooks.validate();
    errors.extend(new_playbooks.check_settings(&state.settings, state.announcer.capabilities()));
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
        tracing::error!(target: "prefixd::api::handlers", error = %e, "failed to save playbooks");
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
        tracing::warn!(target: "prefixd::api::handlers", error = %e, "failed to insert audit entry for playbook update");
    }

    tracing::info!(target: "prefixd::api::handlers",
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
    use crate::api::auth::require_role;
    use crate::domain::OperatorRole;
    use crate::observability::{ActorType, AuditEntry};

    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    let operator = require_role(&state, &auth_session, auth_header, OperatorRole::Admin)?;

    let Json(mut new_config) = match body {
        Ok(payload) => payload,
        Err(rejection) => {
            tracing::warn!(target: "prefixd::api::handlers", error = %rejection, "invalid alerting config payload");
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
        tracing::error!(target: "prefixd::api::handlers", error = %e, "failed to save alerting config");
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
        tracing::warn!(target: "prefixd::api::handlers", error = %e, "failed to insert audit entry for alerting update");
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
    use crate::api::auth::require_role;
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
            tracing::warn!(target: "prefixd::api::handlers", error = %rejection, "invalid correlation config payload");
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
        tracing::error!(target: "prefixd::api::handlers", error = %e, "failed to save correlation config");
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
        tracing::warn!(target: "prefixd::api::handlers", error = %e, "failed to insert audit entry for correlation update");
    }

    // Return redacted config
    Ok(Json(serde_json::json!({
        "config": new_config.redacted(),
        "loaded_at": chrono::Utc::now().to_rfc3339(),
    }))
    .into_response())
}
