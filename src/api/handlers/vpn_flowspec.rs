//! VPN-specific routes keep old controllers from ignoring a scope selector.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::sync::Arc;
use utoipa::ToSchema;

use super::{CreateMitigationRequest, FlowSpecAdmissionPreview, MitigationResponse};
use crate::{AppState, auth::AuthSession};

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct VpnMitigationRequest {
    pub scope: String,
    pub rule: CreateMitigationRequest,
}

impl VpnMitigationRequest {
    fn into_request(self) -> CreateMitigationRequest {
        let mut rule = self.rule;
        rule.vpn_scope = Some(self.scope);
        rule
    }
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceOnlyVpnRequest {
    pub scope: String,
    pub src_prefix: String,
    pub protocol: String,
    pub action: String,
    pub rate_bps: Option<u64>,
    pub ttl_seconds: u32,
    pub reason: String,
    #[serde(default)]
    pub confirm_destination_any: bool,
}

impl SourceOnlyVpnRequest {
    fn into_request(self) -> CreateMitigationRequest {
        CreateMitigationRequest {
            vpn_scope: Some(self.scope),
            scope: None,
            vrf: None,
            rd: None,
            route_targets: None,
            afi_safi: None,
            default_scope: None,
            source_only: true,
            source_only_confirmed: self.confirm_destination_any,
            operator_id: String::new(),
            reason: self.reason,
            victim_ip: String::new(),
            protocol: Some(self.protocol),
            dst_ports: Vec::new(),
            src_prefix: Some(self.src_prefix),
            src_ports: Vec::new(),
            fragment: None,
            packet_length: None,
            action: self.action,
            confirm_victim_ip: None,
            rate_bps: self.rate_bps,
            dscp: None,
            ttl_seconds: self.ttl_seconds,
            expires_at_cap: None,
        }
    }
}

#[utoipa::path(post, path = "/v1/vpn/mitigations", tag = "mitigations", request_body = VpnMitigationRequest,
    responses((status=201, description="Scoped intent created; local RPC acceptance is not router enforcement",body=MitigationResponse),
    (status=202,description="Scoped intent retained after an unconfirmed RPC"),(status=400,description="Invalid or unknown VPN scope"),
    (status=401,description="Authentication required"),(status=403,description="Operator role required"),(status=409,description="Conflicting intent"),
    (status=422,description="Guardrail or scope refusal"),(status=503,description="Speaker capability could not be established")))]
pub async fn create_vpn_mitigation(
    State(state): State<Arc<AppState>>,
    auth: AuthSession,
    headers: HeaderMap,
    Json(request): Json<VpnMitigationRequest>,
) -> Result<Response, StatusCode> {
    super::create_mitigation(State(state), auth, headers, Json(request.into_request()))
        .await
        .map(IntoResponse::into_response)
}

#[utoipa::path(post, path = "/v1/vpn/mitigations/preview", tag = "mitigations", request_body = VpnMitigationRequest,
    responses((status=200,description="Read-only scoped admission and family capability snapshot",body=FlowSpecAdmissionPreview),
    (status=400,description="Invalid VPN input"),(status=401,description="Authentication required"),(status=403,description="Operator role required"),
    (status=409,description="Conflicting intent"),(status=422,description="Guardrail refusal"),(status=503,description="Safety reads unavailable")))]
pub async fn preview_vpn_mitigation(
    State(state): State<Arc<AppState>>,
    auth: AuthSession,
    headers: HeaderMap,
    Json(request): Json<VpnMitigationRequest>,
) -> Result<Response, StatusCode> {
    super::preview_manual_flowspec(State(state), auth, headers, Json(request.into_request())).await
}

#[utoipa::path(post, path = "/v1/vpn/source-rules", tag = "mitigations", request_body = SourceOnlyVpnRequest,
    responses((status=201,description="Source-only VPN intent created",body=MitigationResponse),(status=202,description="Intent retained after an unconfirmed RPC"),
    (status=400,description="Source-only scope, source prefix, TTL, confirmation or action refused"),(status=401,description="Authentication required"),(status=403,description="Administrator role required"),
    (status=409,description="Conflicting intent"),(status=422,description="Safelist or quota refusal"),(status=503,description="Capability unavailable")))]
pub async fn create_source_only_vpn(
    State(state): State<Arc<AppState>>,
    auth: AuthSession,
    headers: HeaderMap,
    Json(request): Json<SourceOnlyVpnRequest>,
) -> Result<Response, StatusCode> {
    super::create_mitigation(State(state), auth, headers, Json(request.into_request()))
        .await
        .map(IntoResponse::into_response)
}

#[utoipa::path(post, path = "/v1/vpn/source-rules/preview", tag = "mitigations", request_body = SourceOnlyVpnRequest,
    responses((status=200,description="Read-only source-only preview; destination is any in the named VRF",body=FlowSpecAdmissionPreview),
    (status=400,description="Invalid source-only input"),(status=401,description="Authentication required"),(status=403,description="Operator role required"),
    (status=409,description="Conflicting intent"),(status=422,description="Safelist or quota refusal"),(status=503,description="Safety reads unavailable")))]
pub async fn preview_source_only_vpn(
    State(state): State<Arc<AppState>>,
    auth: AuthSession,
    headers: HeaderMap,
    Json(request): Json<SourceOnlyVpnRequest>,
) -> Result<Response, StatusCode> {
    super::preview_manual_flowspec(State(state), auth, headers, Json(request.into_request())).await
}
