use super::*;
use crate::api::handlers::ErrorResponse;
use crate::{
    AppState,
    auth::AuthSession,
    domain::OperatorRole,
    error::{PrefixdError, Result},
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateDiversion {
    pub profile: String,
    pub scope: crate::domain::FlowSpecNlri,
    pub ttl_seconds: u32,
    pub reason: String,
    pub confirmation: Option<String>,
}
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct VpnDiversionRequest {
    pub scope: String,
    pub diversion: CreateDiversion,
}

impl VpnDiversionRequest {
    fn into_diversion(mut self, state: &AppState) -> Result<CreateDiversion> {
        let scope = state
            .settings
            .bgp
            .resolve_scope(&self.scope)
            .map_err(|error| PrefixdError::InvalidRequest(error.to_string()))?
            .ok_or_else(|| {
                PrefixdError::InvalidRequest("VPN diversion requires a named VPN scope".into())
            })?;
        let profile = state
            .settings
            .scrubber
            .profiles
            .iter()
            .find(|profile| profile.id == self.diversion.profile)
            .ok_or_else(|| PrefixdError::NotFound("unknown scrubber profile".into()))?;
        if profile.scope != self.scope
            || self
                .diversion
                .scope
                .scope
                .as_ref()
                .is_some_and(|identity| identity != &scope.identity)
        {
            return Err(PrefixdError::InvalidRequest(
                "VPN diversion scope must match its configured profile".into(),
            ));
        }
        self.diversion.scope.scope = Some(scope.identity);
        Ok(self.diversion)
    }
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ArmProfile {
    pub revision: String,
}
#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct WithdrawDiversion {
    /// Recorded with the first withdrawal request; 1 to 1,024 UTF-8 bytes of
    /// text. Omitted, the controller records `operator withdrawal by <user>`.
    #[serde(default)]
    pub reason: Option<String>,
}
#[derive(Serialize, utoipa::ToSchema)]
pub struct ScrubberProfiles {
    pub enabled: bool,
    pub profiles: std::collections::HashMap<String, ProfileState>,
    pub configuration: Vec<ConfiguredProfile>,
}
#[derive(Serialize, utoipa::ToSchema)]
pub struct ConfiguredProfile {
    pub scope: String,
    pub id: String,
    pub revision: String,
    #[schema(value_type = Option<String>, example = "192.0.2.99")]
    pub ipv4_target: Option<std::net::IpAddr>,
    #[schema(value_type = Option<String>, example = "2001:db8::99")]
    pub ipv6_target: Option<std::net::IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_route_target: Option<String>,
    /// Absent when the profile has no return leg.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_leg: Option<ReturnLeg>,
}
#[derive(Serialize, utoipa::ToSchema)]
pub struct DiversionPreview {
    pub candidate: Diversion,
    pub confirmation: String,
    pub readiness: Option<ProfileState>,
    pub evidence: &'static str,
}

fn admin(
    state: &AppState,
    session: &AuthSession,
    headers: &HeaderMap,
) -> std::result::Result<String, StatusCode> {
    crate::api::auth::require_role(
        state,
        session,
        headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok()),
        OperatorRole::Admin,
    )
    .map(|user| user.username)
}
fn reader(
    state: &AppState,
    session: &AuthSession,
    headers: &HeaderMap,
) -> std::result::Result<(), StatusCode> {
    crate::api::require_auth(
        state,
        session,
        headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok()),
    )
}
/// Run a mutation to completion even if the client disconnects, so an
/// ambiguous speaker outcome is always recorded and latched.
async fn detached<T, F>(state: &Arc<AppState>, work: impl FnOnce(Arc<AppState>) -> F) -> Result<T>
where
    T: Send + 'static,
    F: Future<Output = Result<T>> + Send + 'static,
{
    tokio::spawn(work(state.clone()))
        .await
        .unwrap_or_else(|_| Err(PrefixdError::Internal("scrubber task failed".into())))
}
fn response<T: Serialize>(result: Result<T>, status: StatusCode) -> Response {
    match result {
        Ok(value) => (status, Json(value)).into_response(),
        Err(error) => {
            let code = error.status_code();
            let text = if code.is_server_error() {
                "scrubber operation could not be confirmed".into()
            } else {
                error.to_string()
            };
            (code, Json(serde_json::json!({"error":text}))).into_response()
        }
    }
}

#[utoipa::path(get,path="/v1/scrubbers",tag="scrubbers",responses(
    (status=200,body=ScrubberProfiles,description="Configured profile targets, readiness and arm state"),
    (status=401,description="Authentication required"),
))]
pub async fn profiles(
    State(state): State<Arc<AppState>>,
    session: AuthSession,
    headers: HeaderMap,
) -> std::result::Result<Response, StatusCode> {
    reader(&state, &session, &headers)?;
    let body = ScrubberProfiles {
        enabled: state.settings.scrubber.enabled,
        profiles: state.scrubber.profiles().await,
        configuration: state
            .settings
            .scrubber
            .profiles
            .iter()
            .map(|profile| ConfiguredProfile {
                scope: profile.scope.clone(),
                id: profile.id.clone(),
                revision: profile.revision.clone(),
                ipv4_target: profile.ipv4_target,
                ipv6_target: profile.ipv6_target,
                redirect_route_target: profile.redirect_route_target.clone(),
                return_leg: profile.return_leg.clone(),
            })
            .collect(),
    };
    Ok(Json(body).into_response())
}
#[utoipa::path(post,path="/v1/scrubbers/{profile}/arm",tag="scrubbers",request_body=ArmProfile,params(("profile"=String,Path)),responses(
    (status=200,description="Explicitly re-armed after fresh readiness and completed withdrawal"),
    (status=401,description="Authentication required"),
    (status=403,description="Administrator role required"),
    (status=404,body=ErrorResponse,description="Unknown scrubber profile"),
    (status=409,body=ErrorResponse,description="Scrubbers disabled, revision changed, profile already armed, stale readiness, outstanding withdrawal or retained guarded intent"),
    (status=422,description="Malformed request body"),
    (status=503,body=ErrorResponse,description="Controller in standby"),
    (status=500,body=ErrorResponse,description="Readiness or speaker outcome could not be confirmed"),
))]
pub async fn arm(
    State(state): State<Arc<AppState>>,
    session: AuthSession,
    headers: HeaderMap,
    Path(profile): Path<String>,
    Json(req): Json<ArmProfile>,
) -> std::result::Result<Response, StatusCode> {
    let actor = admin(&state, &session, &headers)?;
    Ok(response(
        state
            .scrubber
            .arm(&state, &profile, &req.revision, &actor)
            .await,
        StatusCode::OK,
    ))
}
#[utoipa::path(post,path="/v1/diversions/preview",tag="scrubbers",request_body=CreateDiversion,responses(
    (status=200,body=DiversionPreview,description="Controller checks only; no persistence. A VPN scope performs one read-only family capability probe"),
    (status=400,body=ErrorResponse,description="Invalid host, match, lifetime or reason, or no unambiguous inventory owner"),
    (status=401,description="Authentication required"),
    (status=403,description="Administrator role required"),
    (status=404,body=ErrorResponse,description="Unknown scrubber profile"),
    (status=409,body=ErrorResponse,description="Scrubber diversion disabled"),
    (status=422,body=ErrorResponse,description="Guardrail rejection, or a malformed body including an arbitrary target or owner"),
    (status=503,body=ErrorResponse,description="Controller in standby"),
))]
pub async fn preview(
    State(state): State<Arc<AppState>>,
    session: AuthSession,
    headers: HeaderMap,
    Json(req): Json<CreateDiversion>,
) -> std::result::Result<Response, StatusCode> {
    let actor = admin(&state, &session, &headers)?;
    let result=async {
        let candidate=state.scrubber.prepare(&state,&req,&actor).await?;
        let confirmation=ScrubberController::confirmation(&candidate)?;
        let readiness=state.scrubber.profiles().await.remove(&candidate.profile.id);
        Ok(DiversionPreview { candidate,confirmation,readiness,evidence:"Preview only; no rule reserved or speaker mutation sent. Withdrawal returns traffic to ordinary routing." })
    }.await;
    Ok(response(result, StatusCode::OK))
}
#[utoipa::path(post,path="/v1/diversions",tag="scrubbers",request_body=CreateDiversion,responses(
    (status=202,body=Diversion,description="Durable manual intent; local read-back is separate from router forwarding. An unconfirmed mutation returns the latched, withdrawing row."),
    (status=400,body=ErrorResponse,description="Invalid host, match, lifetime or reason, or a confirmation that does not match preview"),
    (status=401,description="Authentication required"),
    (status=403,description="Administrator role required"),
    (status=404,body=ErrorResponse,description="Unknown scrubber profile"),
    (status=409,body=ErrorResponse,description="Scrubbers disabled, profile not ready and armed, or the victim has live or pending mitigation intent"),
    (status=422,body=ErrorResponse,description="Guardrail or quota rejection, or a malformed body"),
    (status=503,body=ErrorResponse,description="Controller in standby"),
    (status=500,body=ErrorResponse,description="Durable admission could not be confirmed; every profile is latched"),
))]
pub async fn create(
    State(state): State<Arc<AppState>>,
    session: AuthSession,
    headers: HeaderMap,
    Json(req): Json<CreateDiversion>,
) -> std::result::Result<Response, StatusCode> {
    let actor = admin(&state, &session, &headers)?;
    let result = detached(&state, move |state| async move {
        state.scrubber.create(&state, &req, &actor).await
    })
    .await;
    Ok(response(result, StatusCode::ACCEPTED))
}
#[utoipa::path(post,path="/v1/vpn/diversions/preview",tag="scrubbers",request_body=VpnDiversionRequest,responses(
    (status=200,body=DiversionPreview,description="Named VPN profile and exact scoped rule acknowledged; no speaker mutation"),
    (status=400,body=ErrorResponse,description="Global, unknown or mismatched VPN scope"),
    (status=401,description="Authentication required"),
    (status=403,description="Administrator role required"),
    (status=404,body=ErrorResponse,description="Unknown scrubber profile"),
    (status=409,body=ErrorResponse,description="Scrubber diversion disabled"),
    (status=422,description="Malformed scoped request or guardrail refusal"),
    (status=503,body=ErrorResponse,description="Capability or controller unavailable"),
))]
pub async fn preview_vpn(
    State(state): State<Arc<AppState>>,
    session: AuthSession,
    headers: HeaderMap,
    Json(req): Json<VpnDiversionRequest>,
) -> std::result::Result<Response, StatusCode> {
    admin(&state, &session, &headers)?;
    let req = match req.into_diversion(&state) {
        Ok(req) => req,
        Err(error) => return Ok(response::<()>(Err(error), StatusCode::BAD_REQUEST)),
    };
    preview(State(state), session, headers, Json(req)).await
}

#[utoipa::path(post,path="/v1/vpn/diversions",tag="scrubbers",request_body=VpnDiversionRequest,responses(
    (status=202,body=Diversion,description="Immutable scoped guarded intent; remote installation remains unqualified"),
    (status=400,body=ErrorResponse,description="Global, unknown or mismatched VPN scope, or confirmation mismatch"),
    (status=401,description="Authentication required"),
    (status=403,description="Administrator role required"),
    (status=404,body=ErrorResponse,description="Unknown scrubber profile"),
    (status=409,body=ErrorResponse,description="Readiness, scope ownership or live intent conflict"),
    (status=422,description="Malformed scoped request or guardrail refusal"),
    (status=503,body=ErrorResponse,description="Capability or controller unavailable"),
))]
pub async fn create_vpn(
    State(state): State<Arc<AppState>>,
    session: AuthSession,
    headers: HeaderMap,
    Json(req): Json<VpnDiversionRequest>,
) -> std::result::Result<Response, StatusCode> {
    admin(&state, &session, &headers)?;
    let req = match req.into_diversion(&state) {
        Ok(req) => req,
        Err(error) => return Ok(response::<()>(Err(error), StatusCode::BAD_REQUEST)),
    };
    create(State(state), session, headers, Json(req)).await
}

#[utoipa::path(get,path="/v1/diversions",tag="scrubbers",responses(
    (status=200,body=Vec<Diversion>,description="All outstanding local intents, including pending withdrawals"),
    (status=401,description="Authentication required"),
    (status=500,body=ErrorResponse,description="Durable intent unavailable"),
))]
pub async fn list(
    State(state): State<Arc<AppState>>,
    session: AuthSession,
    headers: HeaderMap,
) -> std::result::Result<Response, StatusCode> {
    reader(&state, &session, &headers)?;
    Ok(response(
        state.repo.list_diversions(&state.settings.pop).await,
        StatusCode::OK,
    ))
}
#[utoipa::path(get,path="/v1/diversions/{id}",tag="scrubbers",params(("id"=Uuid,Path)),responses(
    (status=200,body=Diversion,description="Immutable diversion snapshot and local lifecycle state"),
    (status=401,description="Authentication required"),
    (status=404,body=ErrorResponse,description="Unknown diversion in this POP"),
))]
pub async fn get(
    State(state): State<Arc<AppState>>,
    session: AuthSession,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> std::result::Result<Response, StatusCode> {
    reader(&state, &session, &headers)?;
    let result = async {
        state
            .repo
            .get_diversion(id)
            .await?
            .filter(|row| row.pop == state.settings.pop)
            .ok_or_else(|| PrefixdError::NotFound("unknown diversion".into()))
    }
    .await;
    Ok(response(result, StatusCode::OK))
}
#[utoipa::path(post,path="/v1/diversions/{id}/withdraw",tag="scrubbers",params(("id"=Uuid,Path)),request_body(content=WithdrawDiversion,description="Optional; omit the body or send {}"),responses(
    (status=202,body=Diversion,description="Withdrawal retained until authorization expiry, final fenced delete and complete local absence"),
    (status=400,body=ErrorResponse,description="Empty or oversized reason"),
    (status=401,description="Authentication required"),
    (status=403,description="Administrator role required"),
    (status=404,body=ErrorResponse,description="Unknown diversion"),
    (status=409,body=ErrorResponse,description="Diversion belongs to another POP"),
    (status=422,description="Malformed request body"),
    (status=503,body=ErrorResponse,description="Controller in standby"),
    (status=500,body=ErrorResponse,description="Durable withdrawal could not be confirmed"),
))]
pub async fn withdraw(
    State(state): State<Arc<AppState>>,
    session: AuthSession,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    body: Option<Json<WithdrawDiversion>>,
) -> std::result::Result<Response, StatusCode> {
    let actor = admin(&state, &session, &headers)?;
    let reason = body.and_then(|Json(body)| body.reason);
    let result = detached(&state, move |state| async move {
        state.scrubber.withdraw(&state, id, &actor, reason).await
    })
    .await;
    Ok(response(result, StatusCode::ACCEPTED))
}
