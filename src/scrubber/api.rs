use super::*;
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
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ArmProfile {
    pub revision: String,
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

#[utoipa::path(get,path="/v1/scrubbers",tag="scrubbers",responses((status=200,description="Configured profile readiness and arm state")))]
pub async fn profiles(State(state): State<Arc<AppState>>) -> Response {
    Json(serde_json::json!({"enabled":state.settings.scrubber.enabled,"profiles":state.scrubber.profiles().await,"configuration":state.settings.scrubber.profiles.iter().map(|profile|serde_json::json!({"id":profile.id,"revision":profile.revision,"ipv4_target":profile.ipv4_target,"ipv6_target":profile.ipv6_target})).collect::<Vec<_>>()})).into_response()
}
#[utoipa::path(post,path="/v1/scrubbers/{profile}/arm",tag="scrubbers",request_body=ArmProfile,params(("profile"=String,Path)),responses((status=200,description="Explicitly re-armed after fresh readiness and completed withdrawal")))]
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
#[utoipa::path(post,path="/v1/diversions/preview",tag="scrubbers",request_body=CreateDiversion,responses((status=200,body=DiversionPreview,description="Controller checks only; no persistence or speaker RPC")))]
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
#[utoipa::path(post,path="/v1/diversions",tag="scrubbers",request_body=CreateDiversion,responses((status=202,body=Diversion,description="Durable manual intent; local read-back is separate from router forwarding")))]
pub async fn create(
    State(state): State<Arc<AppState>>,
    session: AuthSession,
    headers: HeaderMap,
    Json(req): Json<CreateDiversion>,
) -> std::result::Result<Response, StatusCode> {
    let actor = admin(&state, &session, &headers)?;
    Ok(response(
        state.scrubber.create(&state, &req, &actor).await,
        StatusCode::ACCEPTED,
    ))
}
#[utoipa::path(get,path="/v1/diversions",tag="scrubbers",responses((status=200,body=Vec<Diversion>,description="All outstanding local intents, including pending withdrawals")))]
pub async fn list(State(state): State<Arc<AppState>>) -> Response {
    response(
        state.repo.list_diversions(&state.settings.pop).await,
        StatusCode::OK,
    )
}
#[utoipa::path(get,path="/v1/diversions/{id}",tag="scrubbers",params(("id"=Uuid,Path)),responses((status=200,body=Diversion,description="Immutable diversion snapshot and local lifecycle state")))]
pub async fn get(State(state): State<Arc<AppState>>, Path(id): Path<Uuid>) -> Response {
    let result = async {
        state
            .repo
            .get_diversion(id)
            .await?
            .filter(|row| row.pop == state.settings.pop)
            .ok_or_else(|| PrefixdError::InvalidRequest("unknown diversion".into()))
    }
    .await;
    response(result, StatusCode::OK)
}
#[utoipa::path(post,path="/v1/diversions/{id}/withdraw",tag="scrubbers",params(("id"=Uuid,Path)),responses((status=202,body=Diversion,description="Withdrawal retained until authorization expiry, final fenced delete and complete local absence")))]
pub async fn withdraw(
    State(state): State<Arc<AppState>>,
    session: AuthSession,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> std::result::Result<Response, StatusCode> {
    let actor = admin(&state, &session, &headers)?;
    Ok(response(
        state.scrubber.withdraw(&state, id, &actor).await,
        StatusCode::ACCEPTED,
    ))
}
