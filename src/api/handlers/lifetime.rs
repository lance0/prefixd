use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::IntoResponse,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;
use crate::api::auth::require_role;
use crate::auth::AuthSession;
use crate::domain::OperatorRole;
use crate::error::PrefixdError;

use super::{AppError, MAX_USERNAME_LEN, MitigationResponse, validate_string_len};

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ExtendMitigationRequest {
    /// Requested remaining lifetime at the update, bounded by current TTL policy.
    #[schema(minimum = 1, example = 600)]
    pub ttl_seconds: u32,
    /// Nonblank operator explanation, at most 1,024 UTF-8 bytes.
    pub reason: String,
}

#[derive(Serialize, ToSchema)]
pub struct ExtendMitigationResponse {
    /// False means the existing horizon was already at least as late; nothing was written.
    pub extended: bool,
    pub previous_expires_at: DateTime<Utc>,
    /// Saved desired intent; extending it does not establish router enforcement.
    pub mitigation: MitigationResponse,
}

#[utoipa::path(
    post,
    path = "/v1/mitigations/{id}/extend",
    tag = "mitigations",
    params(("id" = Uuid, Path, description = "Existing ordinary FlowSpec mitigation")),
    request_body = ExtendMitigationRequest,
    responses(
        (status = 200, description = "Saved lifetime extended, or explicit unchanged horizon", body = ExtendMitigationResponse),
        (status = 400, description = "Blank or overlong reason, or invalid request"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Operator role required"),
        (status = 404, description = "Mitigation not found"),
        (status = 409, description = "Not live ordinary enforced FlowSpec, ownership changed, or withdrawal pending"),
        (status = 422, description = "Current TTL, prefix, match or safelist policy refuses longer exposure"),
        (status = 500, description = "Update outcome unavailable; refresh mitigation and audit before retrying"),
        (status = 503, description = "Controller is in standby")
    )
)]
pub async fn extend_mitigation(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<ExtendMitigationRequest>,
) -> Result<axum::response::Response, StatusCode> {
    let actor = require_role(
        &state,
        &auth_session,
        headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
        OperatorRole::Operator,
    )?;
    if let Err(error) = validate_string_len(&actor.username, "operator_id", MAX_USERNAME_LEN) {
        return Ok(AppError(error).into_response());
    }
    let result = crate::domain::extend_flowspec_lifetime(
        &state,
        id,
        request.ttl_seconds,
        actor.username,
        request.reason,
    )
    .await;
    match result {
        Ok(outcome) => {
            let mitigation = MitigationResponse::from(&outcome.mitigation);
            if outcome.extended {
                let _ = state
                    .ws_broadcast
                    .send(crate::ws::WsMessage::MitigationUpdated {
                        mitigation: mitigation.clone(),
                    });
            }
            Ok(Json(ExtendMitigationResponse {
                extended: outcome.extended,
                previous_expires_at: outcome.previous_expires_at,
                mitigation,
            })
            .into_response())
        }
        Err(error) => {
            let error = match error {
                PrefixdError::Database(_) | PrefixdError::Internal(_) => {
                    tracing::error!(mitigation_id = %id, error = %error, "lifetime update outcome unavailable");
                    PrefixdError::Internal(
                        "lifetime update outcome unavailable; refresh mitigation and audit before retrying".into(),
                    )
                }
                error => error,
            };
            Ok(AppError(error).into_response())
        }
    }
}
