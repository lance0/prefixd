mod accounts;
pub use accounts::{
    __path_change_password, __path_create_operator, __path_delete_operator, __path_get_me,
    __path_get_notification_preferences, __path_list_operators, __path_login, __path_logout,
    __path_update_notification_preferences, ChangePasswordRequest, CreateOperatorRequest,
    LoginRequest, LoginResponse, OperatorInfo, OperatorListResponse, change_password,
    create_operator, delete_operator, get_me, get_notification_preferences, list_operators, login,
    logout, update_notification_preferences,
};

mod configuration;
pub use configuration::{
    __path_get_alerting_config, __path_get_config_inventory, __path_get_config_playbooks,
    __path_get_config_settings, __path_get_correlation_config, __path_test_alerting,
    __path_update_alerting_config, __path_update_correlation_config, __path_update_playbooks,
    ConfigInventoryResponse, ConfigPlaybooksResponse, ConfigSettingsResponse, ReloadResponse,
    UpdatePlaybooksRequest, get_alerting_config, get_config_inventory, get_config_playbooks,
    get_config_settings, get_correlation_config, reload_config, test_alerting,
    update_alerting_config, update_correlation_config, update_playbooks,
};

mod observations;
pub use observations::{
    __path_generate_incident_report, __path_get_ip_history, __path_get_stats,
    __path_get_timeseries, __path_list_audit, __path_list_pops, AuditListResponse,
    IncidentReportQuery, IpHistoryResponse, TimeseriesQuery, TimeseriesResponse,
    generate_incident_report, get_ip_history, get_stats, get_timeseries, list_audit, list_pops,
    metrics,
};

mod safelist;
pub use safelist::{
    __path_add_safelist, __path_remove_safelist, AddSafelistRequest, AddSafelistResponse,
    add_safelist, list_safelist, remove_safelist,
};

mod signals;
pub use signals::{
    __path_get_corroborator_activity, __path_get_signal_group, __path_ingest_alertmanager,
    __path_ingest_corroborator, __path_ingest_fastnetmon, __path_ingest_webhook,
    __path_list_cached_corroborators_handler, __path_list_signal_groups, AlertmanagerAlert,
    AlertmanagerAlertResult, AlertmanagerWebhookPayload, AlertmanagerWebhookResponse,
    CachedCorroboratorBySource, CachedCorroboratorsQuery, CachedCorroboratorsResponse,
    CorroboratorActivityEntry, CorroboratorActivityQuery, CorroboratorActivityResponse,
    CorroboratorInput, CorroboratorResponse, FastNetMonAttackDetails, FastNetMonPayload,
    ListSignalGroupsQuery, SignalGroupDetailResponse, SignalGroupsListResponse, WebhookEventResult,
    WebhookResponse, get_corroborator_activity, get_signal_group, ingest_alertmanager,
    ingest_corroborator, ingest_fastnetmon, ingest_webhook, list_cached_corroborators_handler,
    list_signal_groups,
};

mod health;
pub use health::{
    __path_health, __path_health_detail, __path_ready, ComponentHealth, DaemonHealthObservation,
    HealthResponse, PublicHealthResponse, ReadinessResponse, ReadinessStatus, SpeakerHealth,
    health, health_detail, ready,
};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::IntoResponse,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;
use crate::db::{ListCursor, ListParams, MitigationCursor, MitigationListParams};
use crate::domain::{
    ActionParams, ActionType, AttackEvent, AttackEventInput, FlowSpecAction, FragmentMatch,
    MatchCriteria, Mitigation, MitigationIntent, MitigationRoute, MitigationStatus,
    PacketLengthRange, execute_withdrawal, find_mitigation_owner, mitigation_rule,
    request_withdrawal, validate_confidence, validate_top_src_ports,
};
use crate::error::{GuardrailError, PrefixdError};
use crate::guardrails::Guardrails;
use crate::observability::CreationActor;
use crate::policy::PolicyEngine;

use super::auth::{require_auth, require_role};
use crate::auth::AuthSession;

fn encode_list_cursor(timestamp: DateTime<Utc>, id: Uuid, prefix: &str) -> String {
    let position = format!("{}\n{}", timestamp.to_rfc3339(), id);
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(position.as_bytes()))
}

fn decode_list_cursor(value: &str, prefix: &str) -> Option<ListCursor> {
    if value.len() > 128 || !value.is_ascii() {
        return None;
    }
    let encoded = value.strip_prefix(prefix)?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    let decoded = std::str::from_utf8(&bytes).ok()?;
    let (timestamp, id) = decoded.split_once('\n')?;
    Some(ListCursor {
        timestamp: DateTime::parse_from_rfc3339(timestamp)
            .ok()?
            .with_timezone(&Utc),
        id: id.parse().ok()?,
    })
}

const MAX_MITIGATION_CURSOR_LEN: usize = 128;
const MITIGATION_CURSOR_PREFIX: &str = "m1.";

fn encode_mitigation_cursor(mitigation: &Mitigation) -> String {
    let position = format!(
        "{}\n{}",
        mitigation.created_at.to_rfc3339(),
        mitigation.mitigation_id
    );
    format!(
        "{MITIGATION_CURSOR_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(position.as_bytes())
    )
}

fn decode_mitigation_cursor(value: &str) -> Option<MitigationCursor> {
    if value.len() > MAX_MITIGATION_CURSOR_LEN || !value.is_ascii() {
        return None;
    }
    let encoded = value.strip_prefix(MITIGATION_CURSOR_PREFIX)?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    let decoded = std::str::from_utf8(&bytes).ok()?;
    let (created_at, mitigation_id) = decoded.split_once('\n')?;
    Some(MitigationCursor {
        created_at: DateTime::parse_from_rfc3339(created_at)
            .ok()?
            .with_timezone(&Utc),
        mitigation_id: mitigation_id.parse().ok()?,
    })
}

// Response types

/// Outcome of this creation request, not persisted speaker or router status.
#[derive(Clone, Copy, Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AnnouncementOutcome {
    /// Desired intent committed, but this request did not receive a successful speaker reply.
    Unconfirmed,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct EventResponse {
    /// Present only when this creation request committed intent without a successful speaker reply.
    /// Omission is not evidence of enforcement; this outcome is not persisted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub announcement_outcome: Option<AnnouncementOutcome>,
    /// Unique identifier for this event
    pub event_id: Uuid,
    /// External event ID from the detector
    pub external_event_id: Option<String>,
    /// Processing status
    pub status: String,
    /// The first mitigation this request created, extended or withdrew, if any.
    pub mitigation_id: Option<Uuid>,
    /// Every mitigation this request created, extended or withdrew, in playbook
    /// rule order; the first equals `mitigation_id` (ADR 028).
    pub mitigation_ids: Vec<Uuid>,
    /// Outcome of each rule policy produced for a ban, in playbook order.
    /// Omitted when no rule was evaluated.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<EventRuleOutcome>,
}

impl EventResponse {
    fn new(
        event_id: Uuid,
        external_event_id: Option<String>,
        status: &str,
        mitigation_id: Option<Uuid>,
    ) -> Self {
        Self {
            announcement_outcome: None,
            event_id,
            external_event_id,
            status: status.to_string(),
            mitigation_id,
            mitigation_ids: mitigation_id.into_iter().collect(),
            rules: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuleOutcome {
    Created,
    Extended,
    Rejected,
}

/// What one rule of an event's response became. Rules are admitted one by one.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct EventRuleOutcome {
    pub outcome: RuleOutcome,
    /// The created or extended mitigation; absent when rejected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitigation_id: Option<Uuid>,
    /// Why the rule was rejected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Present only when this rule's intent was committed without a successful speaker reply.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub announcement_outcome: Option<AnnouncementOutcome>,
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
    /// Present only when this creation request committed intent without a successful speaker reply.
    /// Omission is not evidence of enforcement; this outcome is not persisted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub announcement_outcome: Option<AnnouncementOutcome>,
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
    /// Action type (discard, police, blackhole)
    pub action_type: String,
    /// Rate limit in bps (for police action)
    pub rate_bps: Option<u64>,
    /// Destination prefix (CIDR)
    pub dst_prefix: String,
    /// IP protocol number (6=TCP, 17=UDP, 1=ICMP)
    pub protocol: Option<u8>,
    /// Destination ports
    pub dst_ports: Vec<u16>,
    /// UDP source ports (ADR 028), sorted and deduplicated; empty when not matched
    #[schema(example = json!([123, 389]))]
    pub src_ports: Vec<u16>,
    /// `non_first` when the rule matches non-first IP fragments; otherwise null
    pub fragment: Option<FragmentMatch>,
    /// Inclusive total IP packet length range; otherwise null
    pub packet_length: Option<PacketLengthRange>,
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
    /// Operation mode that admitted this mitigation: `dry-run` or `enforced`.
    /// `null` when the row predates origin tracking; never infer enforcement from it.
    #[schema(example = "dry-run")]
    pub origin_mode: Option<String>,
    /// Correlation context (present when mitigation was created via
    /// corroboration from the signal correlation engine)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation: Option<CorrelationContext>,
    /// The route a blackhole was admitted with; absent for FlowSpec. A blackhole
    /// drops all traffic to the victim. This is the saved intent, not router state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blackhole: Option<BlackholeRouteResponse>,
}

/// Next hop and communities frozen into a blackhole at admission (ADR 027).
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct BlackholeRouteResponse {
    /// Discard next hop, in the victim's address family.
    #[schema(example = "192.0.2.66")]
    pub next_hop: String,
    /// Standard communities as `ASN:value`, always including BLACKHOLE `65535:666`.
    #[schema(example = json!(["65535:666"]))]
    pub communities: Vec<String>,
    /// Large communities as `global:local1:local2`.
    pub large_communities: Vec<String>,
}

impl From<&crate::domain::BlackholeRule> for BlackholeRouteResponse {
    fn from(rule: &crate::domain::BlackholeRule) -> Self {
        Self {
            next_hop: rule.next_hop.to_string(),
            communities: rule
                .communities
                .iter()
                .map(|community| format!("{}:{}", community >> 16, community & 0xFFFF))
                .collect(),
            large_communities: rule
                .large_communities
                .iter()
                .map(|[global, first, second]| format!("{global}:{first}:{second}"))
                .collect(),
        }
    }
}

impl From<&Mitigation> for MitigationResponse {
    fn from(m: &Mitigation) -> Self {
        Self {
            announcement_outcome: None,
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
            src_ports: crate::domain::canonical_ports(&m.match_criteria.src_ports),
            fragment: m.match_criteria.fragment,
            packet_length: m.match_criteria.packet_length,
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
            origin_mode: m.origin_mode.map(|mode| mode.as_str().to_owned()),
            // Correlation context is populated asynchronously by handlers
            // that have access to the signal group data. The basic From impl
            // sets it to None — callers enrich it when needed.
            correlation: None,
            blackhole: m.action_params.blackhole.as_ref().map(Into::into),
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
    /// Exact POP filter; omission and literal "all" list every POP.
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

type DateRange = (Option<DateTime<Utc>>, Option<DateTime<Utc>>);

fn parse_date_range(start: Option<&str>, end: Option<&str>) -> crate::error::Result<DateRange> {
    let parse = |value: Option<&str>, name: &str| {
        value
            .map(|value| {
                value.parse::<DateTime<Utc>>().map_err(|_| {
                    PrefixdError::InvalidRequest(format!(
                        "invalid {name} filter; expected an RFC3339 timestamp"
                    ))
                })
            })
            .transpose()
    };
    Ok((parse(start, "start")?, parse(end, "end")?))
}

fn clamp_limit(limit: u32) -> u32 {
    limit.min(MAX_PAGE_LIMIT)
}

const MAX_STRING_LEN: usize = 1024;
const MAX_USERNAME_LEN: usize = 64;
fn validate_string_len(value: &str, field: &str, max: usize) -> Result<(), PrefixdError> {
    if value.len() > max {
        Err(PrefixdError::InvalidRequest(format!(
            "{} exceeds maximum length of {} bytes",
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

#[derive(Deserialize, ToSchema)]
pub struct CreateMitigationRequest {
    #[serde(default)]
    #[allow(
        dead_code,
        reason = "Caller-supplied actor is ignored; request authentication determines the actor"
    )]
    operator_id: String,
    reason: String,
    victim_ip: String,
    /// IP protocol: udp, tcp, icmp (IPv4 protocol 1), icmpv6 (IPv6 protocol 58), or any.
    /// An empty string also selects any protocol. ICMP selectors must match the victim's address family.
    /// Required for discard and police; omit for blackhole.
    #[schema(example = "icmpv6")]
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    dst_ports: Vec<u16>,
    /// UDP source ports (ADR 028), stored sorted and deduplicated; empty means absent.
    /// Needs protocol `udp`, never shares a rule with `fragment`, and is capped by
    /// `guardrails.max_ports` separately from `dst_ports`. Discard and police only.
    #[schema(example = json!([123, 389]))]
    #[serde(default)]
    src_ports: Vec<u16>,
    /// `non_first` matches non-first IP fragments (IsF). Needs protocol `udp`, no
    /// `src_ports`, and `guardrails.allow_fragment_match`. Discard and police only.
    #[serde(default)]
    fragment: Option<FragmentMatch>,
    /// Inclusive total IP packet length. Needs `src_ports`, a `min` above the IP plus
    /// UDP header (28 for IPv4, 48 for IPv6), `min <= max`, and
    /// `guardrails.allow_packet_length_match`. Discard and police only.
    #[serde(default)]
    packet_length: Option<PacketLengthRange>,
    /// discard, police, or blackhole. A blackhole drops all traffic to the victim
    /// and requires the Admin role, a nonempty reason and `confirm_victim_ip`.
    action: String,
    /// Blackhole only: must exactly equal `victim_ip`, or the request returns 400.
    #[serde(default)]
    confirm_victim_ip: Option<String>,
    /// Positive bit rate exactly representable as an f32 bytes/second traffic rate for police.
    /// Must be omitted or null for discard.
    #[serde(default)]
    rate_bps: Option<u64>,
    ttl_seconds: u32,
    /// Optional ceiling for this creation's expiry; later detector extensions are separate.
    #[serde(default)]
    expires_at_cap: Option<DateTime<Utc>>,
}
#[derive(Deserialize)]
pub struct WithdrawRequest {
    #[serde(default)]
    #[allow(
        dead_code,
        reason = "Caller-supplied actor is ignored; request authentication determines the actor"
    )]
    operator_id: String,
    reason: String,
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
        (status = 400, description = "Invalid input, including non-finite or out-of-range confidence"),
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

    // Reject before branching so a corroborating source cannot use unban here either (ADR 021).
    reject_corroborating_source(&state, &input).await?;

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

/// Caller holds the lifecycle mutex; commit desired state before any speaker mutation.
async fn persist_new_mitigation(
    state: &AppState,
    mitigation: &mut Mitigation,
    actor: &CreationActor,
) -> crate::error::Result<Option<AnnouncementOutcome>> {
    // Fail closed before persistence: only a FlowSpec rule can be announced here,
    // and only with components the selected speaker encodes, in dry-run too.
    let rule = mitigation_rule(mitigation)?;
    state.announcer.match_support().require(&rule.nlri)?;
    mitigation.activate();
    mitigation.origin_mode = Some(state.settings.mode);
    state
        .repo
        .admit_mitigation(
            mitigation,
            &state.settings.quotas,
            &state.settings.blackhole,
            actor,
        )
        .await
        .inspect_err(|error| {
            let reason = match error {
                PrefixdError::GuardrailViolation(GuardrailError::QuotaExceeded { .. }) => {
                    "QuotaExceeded"
                }
                PrefixdError::GuardrailViolation(GuardrailError::NewMitigationRateExceeded {
                    ..
                }) => "NewMitigationRateExceeded",
                _ => return,
            };
            crate::observability::metrics::GUARDRAIL_REJECTIONS
                .with_label_values(&[reason])
                .inc();
            tracing::warn!(error = %error, pop = %mitigation.pop, reason,
                "admission rejected new mitigation");
        })?;
    if state.is_dry_run() {
        return Ok(None);
    }
    let start = std::time::Instant::now();
    if mitigation.expires_at <= Utc::now() {
        tracing::warn!(mitigation_id = %mitigation.mitigation_id,
            "mitigation expired during persistence; announcement skipped");
        return Ok(Some(AnnouncementOutcome::Unconfirmed));
    }
    if let Err(error) = state.announcer.announce(&rule).await {
        tracing::warn!(mitigation_id = %mitigation.mitigation_id, error = %error,
            "mitigation intent retained after unconfirmed BGP announcement");
        return Ok(Some(AnnouncementOutcome::Unconfirmed));
    }
    crate::observability::metrics::ANNOUNCEMENTS_TOTAL
        .with_label_values(&["announced"])
        .inc();
    crate::observability::metrics::ANNOUNCEMENTS_LATENCY.observe(start.elapsed().as_secs_f64());
    Ok(None)
}

async fn withdraw_and_notify(
    state: &AppState,
    mitigation: &Mitigation,
    actor_type: &str,
    actor: &str,
    reason: String,
) -> crate::error::Result<Mitigation> {
    let binding = state.verified_speaker_binding()?;
    if mitigation.pop != state.settings.pop {
        return Err(PrefixdError::Conflict(
            "mitigation belongs to another POP".into(),
        ));
    }
    let request = request_withdrawal(
        state.repo.as_ref(),
        mitigation,
        false,
        actor_type,
        actor,
        reason,
        !state.is_dry_run(),
        binding,
    )
    .await?;
    let mitigation = execute_withdrawal(
        state.repo.as_ref(),
        state.announcer.as_ref(),
        state.is_dry_run(),
        &request,
        binding,
    )
    .await?;
    let (message, alert) = if request.is_expiry() {
        crate::observability::metrics::MITIGATIONS_EXPIRED
            .with_label_values(&[&mitigation.action_type.to_string(), &mitigation.pop])
            .inc();
        (
            crate::ws::WsMessage::MitigationExpired {
                mitigation_id: mitigation.mitigation_id.to_string(),
            },
            crate::alerting::Alert::mitigation_expired(&mitigation),
        )
    } else {
        crate::observability::metrics::MITIGATIONS_WITHDRAWN
            .with_label_values(&[
                mitigation.action_type.to_string().as_str(),
                mitigation.pop.as_str(),
                if request.actor_type == "detector" {
                    "detector_unban"
                } else {
                    "operator"
                },
            ])
            .inc();
        (
            crate::ws::WsMessage::MitigationWithdrawn {
                mitigation_id: mitigation.mitigation_id.to_string(),
            },
            crate::alerting::Alert::mitigation_withdrawn(&mitigation),
        )
    };
    let _ = state.ws_broadcast.send(message);
    state.alerting.read().await.notify(alert);
    Ok(mitigation)
}

/// Handle unban action - withdraw mitigation by external_event_id
async fn handle_unban(
    state: Arc<AppState>,
    input: AttackEventInput,
) -> Result<(StatusCode, Json<EventResponse>), AppError> {
    validate_confidence(input.confidence).map_err(AppError)?;
    validate_top_src_ports(input.top_src_ports.as_deref()).map_err(AppError)?;
    let ext_id = match &input.event_id {
        Some(id) => id.clone(),
        None => {
            // No external ID, can't find the original event
            tracing::warn!(source = %input.source, "unban without event_id, ignoring");
            return Ok((
                StatusCode::ACCEPTED,
                Json(EventResponse::new(
                    Uuid::new_v4(),
                    None,
                    "ignored_no_event_id",
                    None,
                )),
            ));
        }
    };

    let _mitigation_guard = state.mitigation_lock.lock().await;
    state.verified_speaker_binding().map_err(AppError)?;

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
                Json(EventResponse::new(
                    Uuid::new_v4(),
                    Some(ext_id),
                    "not_found",
                    None,
                )),
            ));
        }
        Err(e) => return Err(AppError(e)),
    };

    // Every live rule the ban created: one event can create several (ADR 028).
    let mitigations = match state
        .repo
        .list_active_by_triggering_event(original_event.event_id)
        .await
    {
        Ok(found) if !found.is_empty() => found,
        Ok(_) => {
            tracing::debug!(event_id = %original_event.event_id, "no active mitigation for event");
            return Ok((
                StatusCode::ACCEPTED,
                Json(EventResponse::new(
                    original_event.event_id,
                    Some(ext_id),
                    "no_active_mitigation",
                    None,
                )),
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

    let mut withdrawn = Vec::with_capacity(mitigations.len());
    for mitigation in &mitigations {
        let mitigation = withdraw_and_notify(
            &state,
            mitigation,
            "detector",
            &source,
            format!("Detector unban: {}", source),
        )
        .await
        .map_err(AppError)?;
        tracing::info!(
            mitigation_id = %mitigation.mitigation_id,
            victim_ip = %mitigation.victim_ip,
            "withdrew mitigation via detector unban"
        );
        withdrawn.push(mitigation.mitigation_id);
    }

    let mut response = EventResponse::new(
        unban_event.event_id,
        unban_event.external_event_id,
        "withdrawn",
        withdrawn.first().copied(),
    );
    response.mitigation_ids = withdrawn;
    Ok((StatusCode::ACCEPTED, Json(response)))
}

/// A `mode: corroborating` source must never create a mitigation by itself (ADR 021).
async fn reject_corroborating_source(
    state: &AppState,
    input: &AttackEventInput,
) -> Result<(), AppError> {
    if state
        .correlation_config
        .read()
        .await
        .source_mode(&input.source)
        != crate::correlation::SourceMode::Corroborating
    {
        return Ok(());
    }
    tracing::warn!(
        source = %input.source,
        action = %input.action,
        "rejected /v1/events from corroborating-only source"
    );
    Err(AppError(PrefixdError::InvalidRequest(format!(
        "source '{}' is configured as mode=corroborating and cannot post to /v1/events. Use POST /v1/signals/corroborator instead.",
        input.source
    ))))
}

/// Handle ban action - create or extend mitigation
async fn handle_ban(
    state: Arc<AppState>,
    input: AttackEventInput,
) -> Result<(StatusCode, Json<EventResponse>), AppError> {
    // Every ban path (single, batch, signal adapters) routes through here.
    reject_corroborating_source(&state, &input).await?;
    validate_confidence(input.confidence).map_err(AppError)?;
    validate_top_src_ports(input.top_src_ports.as_deref()).map_err(AppError)?;
    // shortcut: one controller per speaker; use a leader fence before supporting active-active controllers.
    let _mitigation_guard = state.mitigation_lock.lock().await;
    state.verified_speaker_binding().map_err(AppError)?;
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

    let inventory = state.inventory.read().await;
    let context = inventory.lookup_ip(&event.victim_ip);
    let is_owned = context.is_some() || inventory.is_owned(&event.victim_ip);
    drop(inventory);
    let playbooks = state.playbooks.read().await.clone();
    let policy = PolicyEngine::new(
        playbooks.clone(),
        state.settings.pop.clone(),
        state.settings.timers.default_ttl_seconds,
    )
    .with_amplification(
        state.settings.amplification.library_ports(),
        state.settings.guardrails.max_ports,
    );
    let decision = match policy.evaluate(&event, context.as_ref()) {
        Err(
            error @ PrefixdError::GuardrailViolation(
                GuardrailError::NoAllowedPorts | GuardrailError::InvalidAction(_),
            ),
        ) => {
            crate::observability::metrics::EVENTS_REJECTED
                .with_label_values(&[event.source.as_str(), "guardrail"])
                .inc();
            let reason = if matches!(
                &error,
                PrefixdError::GuardrailViolation(GuardrailError::NoAllowedPorts)
            ) {
                "NoAllowedPorts"
            } else {
                "InvalidAction"
            };
            crate::observability::metrics::GUARDRAIL_REJECTIONS
                .with_label_values(&[reason])
                .inc();
            tracing::warn!(error = %error, "policy rejected mitigation");
            return Err(AppError(error));
        }
        result => result,
    };
    // Only allowlisted detectors reach a blackhole, whether it creates or extends (ADR 027).
    if let Ok(decision) = &decision
        && decision
            .intents
            .iter()
            .any(|intent| intent.action_type == ActionType::Blackhole)
        && let Err(error) =
            crate::guardrails::check_detector_source(&state.settings.blackhole, &event.source)
    {
        crate::observability::metrics::EVENTS_REJECTED
            .with_label_values(&[event.source.as_str(), "guardrail"])
            .inc();
        crate::observability::metrics::GUARDRAIL_REJECTIONS
            .with_label_values(&["BlackholeSourceNotAllowed"])
            .inc();
        tracing::warn!(error = %error, "blackhole playbook refused for this source");
        return Err(AppError(error));
    }
    // Owners are checked per rule. When every rule is refused here, nothing is
    // stored, so the same detector event remains retryable.
    let mut owners = Vec::new();
    if let Ok(decision) = &decision {
        for intent in &decision.intents {
            owners.push(rule_owner(&state, intent).await);
        }
        if !owners.is_empty() && owners.iter().all(Result::is_err) {
            if let Err(error) = owners.swap_remove(0) {
                return Err(AppError(error));
            }
        }
    }

    // Store event
    state.repo.insert_event(&event).await.map_err(AppError)?;

    crate::observability::metrics::EVENTS_INGESTED
        .with_label_values(&[&event.source, &event.attack_vector().to_string()])
        .inc();

    // Check if shutting down
    if state.is_shutting_down() {
        return Err(AppError(PrefixdError::ShuttingDown));
    }

    if !is_owned {
        tracing::warn!(victim_ip = %event.victim_ip, "event for unowned IP, skipping mitigation");
        return Ok((
            StatusCode::ACCEPTED,
            Json(EventResponse::new(
                event.event_id,
                event.external_event_id.clone(),
                "accepted_no_mitigation",
                None,
            )),
        ));
    }

    // ── Correlation step ───────────────────────────────────────────────
    // If correlation.enabled, find/create a signal group and add the event.
    // Check corroboration — if threshold not met, return 'accepted' without
    // creating a mitigation. If threshold met, proceed to policy evaluation.
    let correlation_config = state.correlation_config.read().await.clone();

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
                Json(EventResponse::new(
                    event.event_id,
                    event.external_event_id.clone(),
                    "accepted",
                    None,
                )),
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

    let decision = match decision {
        Ok(decision) => decision,
        Err(e) => {
            tracing::warn!(error = %e, "policy evaluation failed");
            return Ok((
                StatusCode::ACCEPTED,
                Json(EventResponse::new(
                    event.event_id,
                    event.external_event_id.clone(),
                    "accepted_no_playbook",
                    None,
                )),
            ));
        }
    };

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
    let actor = CreationActor::Detector(event.source.clone());

    // Each rule is admitted on its own, in playbook order (ADR 028): every
    // admitted rule is narrower than the all-UDP alternative and stands alone.
    let mut rules = Vec::with_capacity(decision.intents.len());
    let mut first_error = None;
    let mut created_any = false;
    for (intent, owner) in decision.intents.into_iter().zip(owners) {
        let admitted = async {
            if let Some(mut existing) = owner? {
                // A blackhole extension is capped at now + max_ttl_seconds.
                if existing.action_type == ActionType::Blackhole {
                    crate::guardrails::extend_blackhole(
                        &state.settings.blackhole,
                        &mut existing,
                        intent.ttl_seconds,
                        event.event_id,
                    )?;
                } else {
                    existing.extend_ttl(intent.ttl_seconds, event.event_id);
                }
                state.repo.update_mitigation(&existing).await?;
                let _ = state
                    .ws_broadcast
                    .send(crate::ws::WsMessage::MitigationUpdated {
                        mitigation: MitigationResponse::from(&existing),
                    });
                tracing::info!(
                    mitigation_id = %existing.mitigation_id,
                    "extended existing mitigation TTL"
                );
                return Ok(EventRuleOutcome {
                    outcome: RuleOutcome::Extended,
                    mitigation_id: Some(existing.mitigation_id),
                    reason: None,
                    announcement_outcome: None,
                });
            }

            let (mitigation, announcement_outcome) = if intent.action_type == ActionType::Blackhole
            {
                admit_detector_blackhole(&state, intent, &event, decision.vector, signal_group_id)
                    .await?
            } else {
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
                    tracing::warn!(error = %e, "guardrail rejected mitigation");
                    return Err(e);
                }

                let mut mitigation =
                    Mitigation::from_intent(intent, event.victim_ip.clone(), decision.vector);
                mitigation.signal_group_id = signal_group_id;
                let announcement_outcome =
                    persist_new_mitigation(&state, &mut mitigation, &actor).await?;
                (mitigation, announcement_outcome)
            };

            crate::observability::metrics::MITIGATIONS_CREATED
                .with_label_values(&[&mitigation.action_type.to_string(), &state.settings.pop])
                .inc();

            // Build response with optional correlation context
            let mut mit_response = MitigationResponse::from(&mitigation);
            mit_response.correlation = correlation_context.clone();
            let _ = state
                .ws_broadcast
                .send(crate::ws::WsMessage::MitigationCreated {
                    mitigation: mit_response,
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
            Ok(EventRuleOutcome {
                outcome: RuleOutcome::Created,
                mitigation_id: Some(mitigation.mitigation_id),
                reason: None,
                announcement_outcome,
            })
        }
        .await;
        match admitted {
            Ok(outcome) => {
                created_any |= matches!(outcome.outcome, RuleOutcome::Created);
                rules.push(outcome);
            }
            Err(error) => {
                rules.push(EventRuleOutcome {
                    outcome: RuleOutcome::Rejected,
                    mitigation_id: None,
                    reason: Some(error.to_string()),
                    announcement_outcome: None,
                });
                first_error.get_or_insert(error);
            }
        }
    }

    let mitigation_ids: Vec<Uuid> = rules.iter().filter_map(|rule| rule.mitigation_id).collect();
    if mitigation_ids.is_empty() {
        // No rule was created or extended: the first rule's error, as before.
        let error = first_error
            .unwrap_or_else(|| PrefixdError::Internal("policy produced no rules".into()));
        if matches!(error, PrefixdError::GuardrailViolation(_)) {
            crate::observability::metrics::EVENTS_REJECTED
                .with_label_values(&[event.source.as_str(), "guardrail"])
                .inc();
        }
        return Err(AppError(error));
    }

    if let (true, Some(group_id)) = (created_any, signal_group_id) {
        if let Ok(Some(mut group)) = state.repo.get_signal_group(group_id).await {
            group.status = crate::correlation::SignalGroupStatus::Resolved;
            if let Err(e) = state.repo.update_signal_group(&group).await {
                tracing::warn!(error = %e, group_id = %group.group_id, "failed to mark signal group resolved");
            }
        }
    }

    Ok((
        StatusCode::ACCEPTED,
        Json(EventResponse {
            announcement_outcome: rules.iter().find_map(|rule| rule.announcement_outcome),
            event_id: event.event_id,
            external_event_id: event.external_event_id.clone(),
            status: if created_any { "accepted" } else { "extended" }.to_string(),
            mitigation_id: mitigation_ids.first().copied(),
            mitigation_ids,
            rules,
        }),
    ))
}

/// The live mitigation a rule would extend, or why this rule cannot proceed.
async fn rule_owner(
    state: &AppState,
    intent: &MitigationIntent,
) -> crate::error::Result<Option<Mitigation>> {
    let owner = find_mitigation_owner(
        state.repo.as_ref(),
        &state.settings.pop,
        &MitigationRoute::new(
            intent.action_type,
            &intent.match_criteria,
            &intent.action_params,
        ),
        &intent.match_criteria.scope_hash_for(intent.action_type),
    )
    .await?;
    if let Some(owner) = &owner {
        // Extending a simulation in enforced mode would leave the attack unmitigated.
        if owner.is_dry_run_origin() && !state.is_dry_run() {
            return Err(PrefixdError::Conflict(format!(
                "FlowSpec rule is owned by a dry-run simulation; retire it with {}",
                crate::domain::RETIRE_DRY_RUN_FLAG
            )));
        }
        if owner.action_type != ActionType::Blackhole {
            (FlowSpecAction {
                action_type: owner.action_type,
                rate_bps: owner.action_params.rate_bps,
            })
            .traffic_rate_bytes_per_second()
            .map_err(|error| {
                PrefixdError::GuardrailViolation(GuardrailError::InvalidAction(error))
            })?;
        }
    }
    Ok(owner)
}

/// List events
#[utoipa::path(
    get,
    path = "/v1/events",
    tag = "events",
    params(
        ("limit" = Option<u32>, Query, description = "Max results (default 100, max 1000)"),
        ("cursor" = Option<String>, Query, description = "Opaque e1 continuation from next_cursor (max 128 bytes); superseded timestamp-only cursors are rejected"),
        ("start" = Option<String>, Query, description = "Inclusive RFC3339 start; empty or malformed supplied values are invalid"),
        ("end" = Option<String>, Query, description = "Exclusive RFC3339 end; empty or malformed supplied values are invalid"),
    ),
    responses(
        (status = 200, description = "List of events", body = EventsListResponse),
        (status = 400, description = "Invalid date filter or invalid/superseded event cursor", body = ErrorResponse)
    )
)]
pub async fn list_events(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Query(query): Query<CursorQuery>,
) -> Result<axum::response::Response, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

    let limit = clamp_limit(query.limit.unwrap_or(100));
    let cursor = match query.cursor.as_deref() {
        None => None,
        Some(value) => match decode_list_cursor(value, "e1.") {
            Some(cursor) => Some(cursor),
            None => return Ok(AppError(PrefixdError::InvalidRequest(
                "invalid event cursor; use next_cursor from a fresh event listing (e1, at most 128 bytes)".into(),
            )).into_response()),
        },
    };
    let (start, end) = match parse_date_range(query.start.as_deref(), query.end.as_deref()) {
        Ok(bounds) => bounds,
        Err(error) => return Ok(AppError(error).into_response()),
    };
    let params = ListParams {
        limit: limit + 1,
        cursor,
        start,
        end,
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
        events
            .last()
            .map(|e| encode_list_cursor(e.ingested_at, e.event_id, "e1."))
    } else {
        None
    };
    let count = events.len();
    Ok(Json(EventsListResponse {
        events,
        count,
        next_cursor,
        has_more,
    })
    .into_response())
}

/// List mitigations with optional filters
#[utoipa::path(
    get,
    path = "/v1/mitigations",
    tag = "mitigations",
    params(
        ("status" = Option<String>, Query, description = "Comma-separated exact statuses: pending, active, expired, withdrawn, rejected (legacy escalated is still accepted but never produced); every token must be valid and nonempty"),
        ("customer_id" = Option<String>, Query, description = "Filter by customer ID"),
        ("victim_ip" = Option<String>, Query, description = "Filter by victim IP address"),
        ("pop" = Option<String>, Query, description = "Exact case-sensitive POP; omitted or literal 'all' lists every POP. Empty/NUL identifiers are invalid."),
        ("acknowledged" = Option<bool>, Query, description = "Filter by acknowledged status"),
        ("limit" = Option<u32>, Query, description = "Max results (default 100)"),
        ("cursor" = Option<String>, Query, description = "Opaque m1 continuation from next_cursor (max 128 bytes); superseded timestamp-only cursors are rejected"),
        ("start" = Option<String>, Query, description = "Inclusive RFC3339 start; empty or malformed supplied values are invalid"),
        ("end" = Option<String>, Query, description = "Exclusive RFC3339 end; empty or malformed supplied values are invalid"),
    ),
    responses(
        (status = 200, description = "List of mitigations", body = MitigationsListResponse),
        (status = 400, description = "Invalid date/status/POP filter or invalid/superseded mitigation cursor", body = ErrorResponse)
    )
)]
pub async fn list_mitigations(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Query(query): Query<ListMitigationsQuery>,
) -> Result<axum::response::Response, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

    let status_filter = match query
        .status
        .as_deref()
        .map(|value| {
            value
                .split(',')
                .map(str::parse)
                .collect::<std::result::Result<Vec<MitigationStatus>, _>>()
        })
        .transpose()
    {
        Ok(status) => status,
        Err(_) => return Ok(AppError(PrefixdError::InvalidRequest(
            "invalid status filter; expected comma-separated pending, active, escalated, expired, withdrawn or rejected".into(),
        )).into_response()),
    };

    let limit = clamp_limit(query.limit);
    let cursor = match query.cursor.as_deref() {
        None => None,
        Some(value) => match decode_mitigation_cursor(value) {
            Some(cursor) => Some(cursor),
            None => return Ok(AppError(PrefixdError::InvalidRequest(
                "invalid mitigation cursor; use next_cursor from a fresh mitigation listing (m1, at most 128 bytes)".into(),
            )).into_response()),
        },
    };
    let pop = match query.pop.as_deref() {
        None | Some("all") => None,
        Some(value) if value.is_empty() || value.contains('\0') => {
            return Ok(AppError(PrefixdError::InvalidRequest(
                "invalid POP filter; use a nonempty identifier without NUL, or omit pop to list every POP".into(),
            )).into_response());
        }
        Some(value) => Some(value.to_owned()),
    };
    let (start, end) = match parse_date_range(query.start.as_deref(), query.end.as_deref()) {
        Ok(bounds) => bounds,
        Err(error) => return Ok(AppError(error).into_response()),
    };
    let params = MitigationListParams {
        pop,
        limit: limit + 1,
        cursor,
        start,
        end,
    };

    let mut mitigations = state
        .repo
        .list_mitigations(
            status_filter.as_deref(),
            query.customer_id.as_deref(),
            query.victim_ip.as_deref(),
            query.acknowledged,
            &params,
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let has_more = mitigations.len() > limit as usize;
    if has_more {
        mitigations.truncate(limit as usize);
    }
    let next_cursor = if has_more {
        mitigations.last().map(encode_mitigation_cursor)
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
    })
    .into_response())
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

#[utoipa::path(
    post,
    path = "/v1/mitigations",
    tag = "mitigations",
    request_body = CreateMitigationRequest,
    responses(
        (status = 201, description = "Mitigation intent created", body = MitigationResponse),
        (status = 202, description = "Intent created; announcement unconfirmed for this request", body = MitigationResponse),
        (status = 400, description = "Invalid input, including an unsupported action/rate, protocol/address-family mismatch, a match component the selected speaker cannot encode, or a blackhole whose confirm_victim_ip differs from victim_ip or that carries match fields"),
        (status = 403, description = "A blackhole requires the Admin role; bearer tokens map to Operator"),
        (status = 409, description = "Conflicting owner, pending withdrawal, or an untracked local blackhole route at the prefix"),
        (status = 422, description = "Guardrail rejection, including ADR 028 match invariants, the fragment and packet-length opt-ins, max_ports per port list, disabled blackholes and blackhole victim, TTL and quota checks"),
    )
)]
pub async fn create_mitigation(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Json(req): Json<CreateMitigationRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    // Only a blackhole may omit protocol. A discard or police request without it
    // keeps the 422 it got when the field was required by the body schema, before
    // authentication.
    if req.action != "blackhole" && req.protocol.is_none() {
        return Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            "Failed to deserialize the JSON body into the target type: missing field `protocol`",
        )
            .into_response());
    }
    // Check auth first
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    use crate::domain::OperatorRole;
    // A blackhole drops all traffic to the victim, so it needs Admin (ADR 027);
    // bearer tokens map to Operator and get 403 before anything is read or saved.
    let required = if req.action == "blackhole" {
        OperatorRole::Admin
    } else {
        OperatorRole::Operator
    };
    let operator = require_role(&state, &auth_session, auth_header, required)?;
    let operator_id = operator.username.clone();
    if req.action == "blackhole" {
        return Ok(create_blackhole(&state, operator_id, req).await);
    }
    let _mitigation_guard = state.mitigation_lock.lock().await;
    if let Err(error) = state.verified_speaker_binding() {
        return Ok(AppError(error).into_response());
    }

    // Validate input
    let victim_ip = match validate_ip(&req.victim_ip) {
        Ok(ip) => ip,
        Err(error) => return Ok(AppError(error).into_response()),
    };
    if let Err(e) = validate_string_len(&req.reason, "reason", MAX_STRING_LEN) {
        return Ok(AppError(e).into_response());
    }
    if let Err(e) = validate_string_len(&operator_id, "operator_id", MAX_USERNAME_LEN) {
        return Ok(AppError(e).into_response());
    }

    // Validate protocol - reject unknown values instead of silently converting to None
    let protocol = req.protocol.as_deref().unwrap_or_default();
    let protocol = match protocol {
        "udp" => Some(17u8),
        "tcp" => Some(6u8),
        "icmp" if victim_ip.is_ipv4() => Some(1u8),
        "icmpv6" if victim_ip.is_ipv6() => Some(58u8),
        "icmp" | "icmpv6" => {
            return Ok(AppError(PrefixdError::InvalidRequest(format!(
                "protocol '{protocol}' does not match victim IP address family"
            )))
            .into_response());
        }
        "any" | "" => None,
        _ => {
            return Ok(AppError(PrefixdError::InvalidRequest(format!(
                "invalid protocol '{protocol}', expected: udp, tcp, icmp, icmpv6, any"
            )))
            .into_response());
        }
    };

    // Validate action type
    let action_type = match req.action.as_str() {
        "police" => ActionType::Police,
        "discard" => ActionType::Discard,
        _ => {
            return Ok(AppError(PrefixdError::InvalidRequest(format!(
                "invalid action '{}', expected: discard, police, blackhole",
                req.action
            )))
            .into_response());
        }
    };

    if let Err(error) = (FlowSpecAction {
        action_type,
        rate_bps: req.rate_bps,
    })
    .traffic_rate_bytes_per_second()
    {
        return Ok(AppError(PrefixdError::InvalidRequest(error.to_string())).into_response());
    }

    let inventory = state.inventory.read().await;
    let customer_id = inventory.lookup_ip(&req.victim_ip).map(|c| c.customer_id);
    drop(inventory);
    let prefix_len = if victim_ip.is_ipv6() { 128 } else { 32 };
    let intent = MitigationIntent {
        event_id: Uuid::new_v4(),
        customer_id,
        service_id: None,
        pop: state.settings.pop.clone(),
        match_criteria: MatchCriteria {
            dst_prefix: format!("{}/{}", req.victim_ip, prefix_len),
            protocol,
            dst_ports: req.dst_ports,
            src_ports: crate::domain::canonical_ports(&req.src_ports),
            fragment: req.fragment,
            packet_length: req.packet_length,
        },
        action_type,
        action_params: ActionParams {
            rate_bps: req.rate_bps,
            ..Default::default()
        },
        ttl_seconds: req.ttl_seconds,
        reason: req.reason,
    };

    match find_mitigation_owner(
        state.repo.as_ref(),
        &state.settings.pop,
        &MitigationRoute::new(
            intent.action_type,
            &intent.match_criteria,
            &intent.action_params,
        ),
        &intent.match_criteria.scope_hash_for(intent.action_type),
    )
    .await
    {
        Ok(Some(_)) => {
            return Ok(AppError(PrefixdError::Conflict(
                "FlowSpec rule already has an active owner".into(),
            ))
            .into_response());
        }
        Ok(None) => {}
        Err(error) => return Ok(AppError(error).into_response()),
    }

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
    if let Some(cap) = req.expires_at_cap {
        mitigation.expires_at = mitigation.expires_at.min(cap);
        if let Err(error) =
            guardrails.validate_remaining_ttl(mitigation.expires_at - mitigation.created_at)
        {
            crate::observability::metrics::GUARDRAIL_REJECTIONS
                .with_label_values(&["TtlOutOfBounds"])
                .inc();
            return Ok(AppError(error).into_response());
        }
    }

    let actor = CreationActor::Operator(operator_id);
    let announcement_outcome = match persist_new_mitigation(&state, &mut mitigation, &actor).await {
        Ok(outcome) => outcome,
        Err(error) => return Ok(AppError(error).into_response()),
    };

    crate::observability::metrics::MITIGATIONS_CREATED
        .with_label_values(&[&mitigation.action_type.to_string(), &state.settings.pop])
        .inc();

    let mut response = MitigationResponse::from(&mitigation);
    response.announcement_outcome = announcement_outcome;
    let status = if announcement_outcome.is_some() {
        StatusCode::ACCEPTED
    } else {
        StatusCode::CREATED
    };
    Ok((status, Json(response)).into_response())
}

/// A detector blackhole through the shared admission (ADR 027). The caller holds
/// the lifecycle mutex and has checked the source allowlist.
async fn admit_detector_blackhole(
    state: &AppState,
    intent: MitigationIntent,
    event: &AttackEvent,
    vector: crate::domain::AttackVector,
    signal_group_id: Option<Uuid>,
) -> crate::error::Result<(Mitigation, Option<AnnouncementOutcome>)> {
    let binding = state.verified_speaker_binding()?;
    // A snapshot, so a configuration reload never waits behind the speaker add.
    let inventory = state.inventory.read().await.clone();
    let admission = crate::guardrails::admit_blackhole(
        state.repo.as_ref(),
        &state.settings,
        &inventory,
        intent,
        vector,
        signal_group_id,
        &CreationActor::Detector(event.source.clone()),
        state.announcer.as_ref(),
        binding,
    )
    .await
    .inspect_err(|error| {
        if let PrefixdError::GuardrailViolation(violation) = error {
            crate::observability::metrics::GUARDRAIL_REJECTIONS
                .with_label_values(&[blackhole_rejection_reason(violation)])
                .inc();
            tracing::warn!(error = %error, "guardrail rejected detector blackhole");
        }
    })?;
    let outcome = admission
        .unconfirmed
        .then_some(AnnouncementOutcome::Unconfirmed);
    Ok((admission.mitigation, outcome))
}

/// Admin-only manual blackhole (ADR 027). The caller has checked the role; the
/// confirmation and request shape are checked before the lifecycle mutex, and
/// `admit_blackhole` does the rest under it.
async fn create_blackhole(
    state: &AppState,
    operator_id: String,
    req: CreateMitigationRequest,
) -> axum::response::Response {
    let victim_ip = match validate_ip(&req.victim_ip) {
        Ok(ip) => ip,
        Err(error) => return AppError(error).into_response(),
    };
    let invalid = if req.confirm_victim_ip.as_deref() != Some(req.victim_ip.as_str()) {
        Some("confirm_victim_ip must exactly equal victim_ip")
    } else if req.reason.trim().is_empty() {
        Some("a blackhole requires a reason")
    } else if !matches!(req.protocol.as_deref(), None | Some("" | "any"))
        || !req.dst_ports.is_empty()
        || !req.src_ports.is_empty()
        || req.fragment.is_some()
        || req.packet_length.is_some()
        || req.rate_bps.is_some()
        || req.expires_at_cap.is_some()
    {
        Some(
            "a blackhole takes no protocol, dst_ports, src_ports, fragment, packet_length, rate_bps or expires_at_cap",
        )
    } else {
        None
    };
    if let Some(message) = invalid {
        return AppError(PrefixdError::InvalidRequest(message.into())).into_response();
    }
    if let Err(error) = validate_string_len(&req.reason, "reason", MAX_STRING_LEN)
        .and_then(|()| validate_string_len(&operator_id, "operator_id", MAX_USERNAME_LEN))
    {
        return AppError(error).into_response();
    }

    let _mitigation_guard = state.mitigation_lock.lock().await;
    let binding = match state.verified_speaker_binding() {
        Ok(binding) => binding,
        Err(error) => return AppError(error).into_response(),
    };
    let intent = MitigationIntent {
        event_id: Uuid::new_v4(),
        customer_id: None,
        service_id: None,
        pop: state.settings.pop.clone(),
        match_criteria: MatchCriteria {
            dst_prefix: ipnet::IpNet::from(victim_ip).to_string(),
            ..Default::default()
        },
        action_type: ActionType::Blackhole,
        action_params: ActionParams::default(),
        ttl_seconds: req.ttl_seconds,
        reason: req.reason,
    };
    // A snapshot, so a configuration reload never waits behind the speaker add.
    let inventory = state.inventory.read().await.clone();
    let admission = match crate::guardrails::admit_blackhole(
        state.repo.as_ref(),
        &state.settings,
        &inventory,
        intent,
        crate::domain::AttackVector::Unknown,
        None,
        &CreationActor::Operator(operator_id),
        state.announcer.as_ref(),
        binding,
    )
    .await
    {
        Ok(admission) => admission,
        Err(error) => {
            if let PrefixdError::GuardrailViolation(violation) = &error {
                crate::observability::metrics::GUARDRAIL_REJECTIONS
                    .with_label_values(&[blackhole_rejection_reason(violation)])
                    .inc();
            }
            return AppError(error).into_response();
        }
    };

    let mitigation = admission.mitigation;
    crate::observability::metrics::MITIGATIONS_CREATED
        .with_label_values(&[&mitigation.action_type.to_string(), &state.settings.pop])
        .inc();
    let mut response = MitigationResponse::from(&mitigation);
    let _ = state
        .ws_broadcast
        .send(crate::ws::WsMessage::MitigationCreated {
            mitigation: response.clone(),
        });
    tracing::info!(mitigation_id = %mitigation.mitigation_id, victim_ip = %mitigation.victim_ip,
        unconfirmed = admission.unconfirmed, "created manual blackhole");
    let status = if admission.unconfirmed {
        response.announcement_outcome = Some(AnnouncementOutcome::Unconfirmed);
        StatusCode::ACCEPTED
    } else {
        StatusCode::CREATED
    };
    (status, Json(response)).into_response()
}

/// `prefixd_guardrail_rejections_total` reason for a refused blackhole.
fn blackhole_rejection_reason(violation: &GuardrailError) -> &'static str {
    match violation {
        GuardrailError::QuotaExceeded { .. } => "BlackholeQuotaExceeded",
        GuardrailError::NotOwned { .. } => "BlackholeNotOwned",
        GuardrailError::Safelisted { .. } => "BlackholeSafelisted",
        GuardrailError::InvalidBlackhole { .. } => "InvalidBlackhole",
        GuardrailError::BlackholeDisabled => "BlackholeDisabled",
        GuardrailError::BlackholeSourceNotAllowed { .. } => "BlackholeSourceNotAllowed",
        GuardrailError::TtlRequired => "TtlRequired",
        GuardrailError::TtlOutOfBounds { .. } => "TtlOutOfBounds",
        GuardrailError::NewMitigationRateExceeded { .. } => "NewMitigationRateExceeded",
        _ => "unknown",
    }
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
    state
        .verified_speaker_binding()
        .map_err(|error| error.status_code())?;

    if validate_string_len(&operator_id, "operator_id", MAX_USERNAME_LEN).is_err() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if validate_string_len(&req.reason, "reason", MAX_STRING_LEN).is_err() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let _mitigation_guard = state.mitigation_lock.lock().await;
    let mitigation = state
        .repo
        .get_mitigation(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if !mitigation.is_active() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mitigation = withdraw_and_notify(
        &state,
        &mitigation,
        "operator",
        &operator_id,
        format!("{}: {}", operator_id, req.reason),
    )
    .await
    .map_err(|error| error.status_code())?;

    tracing::info!(
        mitigation_id = %mitigation.mitigation_id,
        operator = %operator_id,
        "mitigation withdrawn"
    );

    Ok(Json(MitigationResponse::from(&mitigation)))
}

const MAX_BULK_WITHDRAW: usize = 100;

#[derive(Deserialize, ToSchema)]
pub struct BulkWithdrawRequest {
    mitigation_ids: Vec<Uuid>,
    #[serde(default)]
    #[allow(
        dead_code,
        reason = "Caller-supplied actor is ignored; request authentication determines the actor"
    )]
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
    state
        .verified_speaker_binding()
        .map_err(|error| error.status_code())?;

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
        let _mitigation_guard = state.mitigation_lock.lock().await;
        let mitigation = match state.repo.get_mitigation(*id).await {
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
            Err(e) => {
                tracing::error!(error = %e, mitigation_id = %id, "bulk_withdraw: get_mitigation failed");
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

        if let Err(error) = withdraw_and_notify(
            &state,
            &mitigation,
            "operator",
            &operator_id,
            format!("{}: {}", operator_id, req.reason),
        )
        .await
        {
            tracing::error!(error = %error, mitigation_id = %id, "bulk withdrawal failed");
            failed += 1;
            results.push(BulkWithdrawResult {
                mitigation_id: *id,
                status: "error".into(),
                error: Some(match error {
                    PrefixdError::Conflict(message) => message,
                    PrefixdError::BgpWithdrawalFailed(_) => "speaker withdrawal failed".into(),
                    _ => "withdrawal failed".into(),
                }),
            });
            continue;
        }

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
pub struct BulkAcknowledgeRequest {
    mitigation_ids: Vec<Uuid>,
    #[serde(default)]
    #[allow(
        dead_code,
        reason = "Caller-supplied actor is ignored; request authentication determines the actor"
    )]
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
        .map_err(|e| {
            tracing::error!(error = %e, "bulk_acknowledge failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let mut results = Vec::with_capacity(req.mitigation_ids.len());
    let mut acknowledged = 0u32;
    for id in &req.mitigation_ids {
        if acked_ids.contains(id) {
            acknowledged += 1;
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
    /// Present only when this creation request committed intent without a successful speaker reply.
    /// Omission is not evidence of enforcement; this outcome is not persisted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub announcement_outcome: Option<AnnouncementOutcome>,
    index: usize,
    event_id: Uuid,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mitigation_id: Option<Uuid>,
    /// Every mitigation the event created, extended or withdrew; see `EventResponse`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    mitigation_ids: Vec<Uuid>,
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
                announcement_outcome: None,
                index,
                event_id: Uuid::nil(),
                status: "rejected".to_string(),
                mitigation_id: None,
                mitigation_ids: Vec::new(),
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
                    announcement_outcome: resp.announcement_outcome,
                    index,
                    event_id: resp.event_id,
                    status: resp.status,
                    mitigation_id: resp.mitigation_id,
                    mitigation_ids: resp.mitigation_ids,
                    error: None,
                });
            }
            Err(AppError(err)) => {
                rejected += 1;
                results.push(BatchEventResult {
                    announcement_outcome: None,
                    index,
                    event_id: Uuid::nil(),
                    status: "rejected".to_string(),
                    mitigation_id: None,
                    mitigation_ids: Vec::new(),
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

/// A standby controller (ADR 027) refuses every state-changing API request with
/// `503`; reads stay available. `api_routes` applies this to its routes.
pub async fn require_active_controller(
    State(state): State<Arc<AppState>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if !request.method().is_safe() && !state.fence.is_active() {
        return AppError(PrefixdError::Standby).into_response();
    }
    next.run(request).await
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

#[cfg(test)]
mod tests {
    use super::{
        AppState, Arc, CreationActor, decode_list_cursor, encode_list_cursor,
        persist_new_mitigation,
    };
    use crate::db::ListCursor;
    use chrono::{DateTime, Utc};
    use uuid::Uuid;

    #[test]
    fn test_cursor_encoding_known_value() {
        let timestamp = "2026-10-18T00:00:00+00:00"
            .parse::<DateTime<Utc>>()
            .unwrap();
        let id = Uuid::from_u128(1);
        let encoded =
            "MjAyNi0xMC0xOFQwMDowMDowMCswMDowMAowMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDE";
        for prefix in ["e1.", "a1.", "s1."] {
            let cursor = format!("{prefix}{encoded}");
            assert_eq!(encode_list_cursor(timestamp, id, prefix), cursor);
            assert_eq!(
                decode_list_cursor(&cursor, prefix),
                Some(ListCursor { timestamp, id })
            );
        }
    }

    #[tokio::test]
    async fn admission_refuses_unencodable_components_in_both_modes_before_any_rpc() {
        // Enforced persistence moves process-global announcement series.
        let _metrics = crate::observability::metrics::METRICS_TEST_LOCK
            .lock()
            .await;
        use crate::bgp::MockAnnouncer;
        use crate::config::{BgpMode, Inventory, OperationMode, Playbooks, Settings};
        use crate::db::{MockRepository, RepositoryTrait};
        use crate::domain::{
            ActionParams, ActionType, AttackVector, MatchCriteria, Mitigation, MitigationIntent,
        };
        for mode in [OperationMode::DryRun, OperationMode::Enforced] {
            // The control speaker encodes source ports; the other has not opted in.
            for supported in [false, true] {
                let mut settings: Settings =
                    crate::config::parse_yaml(include_str!("../../configs/prefixd.yaml")).unwrap();
                settings.bgp.mode = BgpMode::Mock;
                settings.mode = mode;
                let repo = Arc::new(MockRepository::new());
                let speaker = Arc::new(if supported {
                    MockAnnouncer::new()
                } else {
                    MockAnnouncer::without_match_support()
                });
                let state = AppState::new(
                    settings,
                    Inventory::new(vec![]),
                    Playbooks { playbooks: vec![] },
                    repo.clone(),
                    speaker.clone(),
                    ".".into(),
                )
                .unwrap();
                let mut mitigation = Mitigation::from_intent(
                    MitigationIntent {
                        event_id: Uuid::new_v4(),
                        customer_id: None,
                        service_id: None,
                        pop: state.settings.pop.clone(),
                        match_criteria: MatchCriteria {
                            dst_prefix: "192.0.2.1/32".into(),
                            protocol: Some(17),
                            src_ports: vec![123],
                            ..Default::default()
                        },
                        action_type: ActionType::Discard,
                        action_params: ActionParams::default(),
                        ttl_seconds: 60,
                        reason: "test".into(),
                    },
                    "192.0.2.1".into(),
                    AttackVector::UdpFlood,
                );
                let result = persist_new_mitigation(
                    &state,
                    &mut mitigation,
                    &CreationActor::Detector("test".into()),
                )
                .await;
                let persisted = repo.get_mitigation(mitigation.mitigation_id).await.unwrap();
                if supported {
                    assert!(result.unwrap().is_none(), "{mode:?}");
                    assert!(persisted.is_some());
                } else {
                    assert!(
                        result
                            .unwrap_err()
                            .to_string()
                            .contains("cannot encode the source port match"),
                        "{mode:?}"
                    );
                    assert!(persisted.is_none());
                }
                let announced = supported && mode == OperationMode::Enforced;
                assert_eq!(speaker.announced_count().await, usize::from(announced));
            }
        }
    }

    #[tokio::test]
    async fn match_opt_ins_refuse_alike_in_both_modes_and_dry_run_persists_without_rpc() {
        // Enforced persistence moves process-global announcement series.
        let _metrics = crate::observability::metrics::METRICS_TEST_LOCK
            .lock()
            .await;
        use crate::bgp::MockAnnouncer;
        use crate::config::{BgpMode, Inventory, OperationMode, Playbooks, Settings};
        use crate::db::{MockRepository, RepositoryTrait};
        use crate::domain::{
            ActionParams, ActionType, AttackVector, FragmentMatch, MatchCriteria, Mitigation,
            MitigationIntent,
        };
        use crate::guardrails::Guardrails;
        let mut refusals = Vec::new();
        for mode in [OperationMode::DryRun, OperationMode::Enforced] {
            for allowed in [false, true] {
                let mut settings: Settings =
                    crate::config::parse_yaml(include_str!("../../configs/prefixd.yaml")).unwrap();
                settings.bgp.mode = BgpMode::Mock;
                settings.mode = mode;
                settings.guardrails.allow_fragment_match = allowed;
                let repo = Arc::new(MockRepository::new());
                let speaker = Arc::new(MockAnnouncer::new());
                let state = AppState::new(
                    settings,
                    Inventory::new(vec![]),
                    Playbooks { playbooks: vec![] },
                    repo.clone(),
                    speaker.clone(),
                    ".".into(),
                )
                .unwrap();
                let intent = MitigationIntent {
                    event_id: Uuid::new_v4(),
                    customer_id: None,
                    service_id: None,
                    pop: state.settings.pop.clone(),
                    match_criteria: MatchCriteria {
                        dst_prefix: "192.0.2.1/32".into(),
                        protocol: Some(17),
                        fragment: Some(FragmentMatch::NonFirst),
                        ..Default::default()
                    },
                    action_type: ActionType::Police,
                    action_params: ActionParams {
                        rate_bps: Some(1_000_000),
                        ..Default::default()
                    },
                    ttl_seconds: 60,
                    reason: "test".into(),
                };
                // The same sequence both creation handlers run.
                let guardrails = Guardrails::with_timers(
                    state.settings.guardrails.clone(),
                    state.settings.quotas.clone(),
                    &state.settings.timers,
                );
                let checked = guardrails.validate(&intent, repo.as_ref(), false).await;
                let mut mitigation =
                    Mitigation::from_intent(intent, "192.0.2.1".into(), AttackVector::UdpFlood);
                if allowed {
                    checked.unwrap();
                    let outcome = persist_new_mitigation(
                        &state,
                        &mut mitigation,
                        &CreationActor::Detector("test".into()),
                    )
                    .await
                    .unwrap();
                    assert!(outcome.is_none(), "{mode:?}");
                    let persisted = repo
                        .get_mitigation(mitigation.mitigation_id)
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(persisted.origin_mode, Some(mode));
                    assert_eq!(
                        persisted.match_criteria.fragment,
                        Some(FragmentMatch::NonFirst)
                    );
                } else {
                    refusals.push(checked.unwrap_err().to_string());
                    assert!(
                        repo.get_mitigation(mitigation.mitigation_id)
                            .await
                            .unwrap()
                            .is_none()
                    );
                }
                let announced = allowed && mode == OperationMode::Enforced;
                assert_eq!(speaker.announced_count().await, usize::from(announced));
            }
        }
        // One refusal per mode, identical in both.
        assert_eq!(refusals.len(), 2);
        assert_eq!(refusals[0], refusals[1]);
        assert!(refusals[0].contains("guardrails.allow_fragment_match=false"));
    }

    #[test]
    fn test_cursor_decode_rejects_invalid_input() {
        let encoded =
            "MjAyNi0xMC0xOFQwMDowMDowMCswMDowMAowMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDE";
        for prefix in ["e1.", "a1.", "s1."] {
            for value in [
                format!("{encoded}="),                         // Padding is not accepted.
                format!("{}F", &encoded[..encoded.len() - 1]), // Nonzero unused trailing bits.
                format!("{encoded}\n"),
                "*".into(),
                "a".into(),
                "_w".into(), // Decodes to invalid UTF-8.
                "bm90LWEtdGltZXN0YW1w".into(),
                "MjAyNi0xMC0xOFQwMDowMDowMCswMDowMA".into(), // Superseded timestamp-only position.
                String::new(),
            ] {
                let cursor = format!("{prefix}{value}");
                assert_eq!(
                    decode_list_cursor(&cursor, prefix),
                    None,
                    "accepted cursor {cursor:?}"
                );
            }
        }
    }

    /// Manual blackholes through the router (ADR 027 slice 6).
    mod blackhole {
        use super::{AppState, Arc};
        use crate::bgp::{FaultyBlackholes, FlowSpecAnnouncer};
        use crate::config::{AuthMode, BgpMode, Customer, Inventory, OperationMode, Playbooks};
        use crate::db::{ListParams, MockRepository, RepositoryTrait};
        use crate::domain::OperatorRole;
        use crate::observability::metrics::{GUARDRAIL_REJECTIONS, METRICS_TEST_LOCK};
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use serde_json::{Value, json};
        use std::sync::atomic::Ordering::SeqCst;
        use tower::ServiceExt;

        fn state(
            mode: OperationMode,
            repo: Arc<MockRepository>,
            speaker: Arc<dyn FlowSpecAnnouncer>,
            auth: AuthMode,
        ) -> Arc<AppState> {
            let mut settings: crate::config::Settings =
                crate::config::parse_yaml(include_str!("../../configs/prefixd.yaml")).unwrap();
            settings.bgp.mode = BgpMode::Mock;
            settings.mode = mode;
            settings.http.auth.mode = AuthMode::None;
            settings.blackhole.enabled = true;
            settings.blackhole.next_hop_ipv4 = Some("192.0.2.66".parse().unwrap());
            settings.blackhole.next_hop_ipv6 = Some("2001:db8:ffff::66".parse().unwrap());
            let inventory = Inventory::new(vec![Customer {
                customer_id: "customer-a".into(),
                name: "Customer A".into(),
                prefixes: vec!["203.0.113.0/24".into()],
                policy_profile: crate::config::PolicyProfile::Normal,
                services: vec![],
            }]);
            let mut state = AppState::new(
                settings,
                inventory,
                Playbooks { playbooks: vec![] },
                repo,
                speaker,
                ".".into(),
            )
            .unwrap();
            let cached = Arc::get_mut(&mut state).unwrap();
            cached.settings.http.auth.mode = auth;
            cached.bearer_token = Some("operator-bearer-token".into());
            state
        }

        fn create(victim: &str, confirm: Option<&str>) -> Value {
            json!({"reason": "attack on victim", "victim_ip": victim,
                "confirm_victim_ip": confirm, "action": "blackhole", "ttl_seconds": 600})
        }

        async fn send(
            app: &axum::Router,
            path: &str,
            auth: Option<(&str, &str)>,
            body: Value,
        ) -> (StatusCode, Value) {
            let mut request = Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json");
            if let Some((name, value)) = auth {
                request = request.header(name, value);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::from(body.to_string())).unwrap())
                .await
                .unwrap();
            let status = response.status();
            let cookie = response
                .headers()
                .get(axum::http::header::SET_COOKIE)
                .map(|value| {
                    value
                        .to_str()
                        .unwrap()
                        .split(';')
                        .next()
                        .unwrap()
                        .to_owned()
                });
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap();
            let mut json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            if let Some(cookie) = cookie {
                json["cookie"] = cookie.into();
            }
            (status, json)
        }

        async fn login(
            app: &axum::Router,
            repo: &MockRepository,
            name: &str,
            role: OperatorRole,
        ) -> String {
            use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
            let salt = SaltString::encode_b64(b"blackhole-api-test").unwrap();
            let hash = Argon2::default()
                .hash_password(b"blackhole-password", &salt)
                .unwrap()
                .to_string();
            repo.create_operator(name, &hash, role, None).await.unwrap();
            let (status, body) = send(
                app,
                "/v1/auth/login",
                None,
                json!({"username": name, "password": "blackhole-password"}),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            body["cookie"].as_str().unwrap().to_owned()
        }

        async fn audit_len(repo: &MockRepository) -> usize {
            repo.list_audit(&ListParams {
                limit: 100,
                ..Default::default()
            })
            .await
            .unwrap()
            .len()
        }

        /// Operator sessions and bearer tokens get 403, a confirmation mismatch gets
        /// 400, and neither saves a row or audit entry; Admin then succeeds in dry-run
        /// and the response and WebSocket carry the frozen route.
        #[tokio::test]
        async fn manual_blackhole_needs_admin_and_exact_confirmation() {
            let repo = Arc::new(MockRepository::new());
            let speaker = Arc::new(FaultyBlackholes::default());
            let state = state(
                OperationMode::DryRun,
                repo.clone(),
                speaker.clone(),
                AuthMode::Bearer,
            );
            let mut feed = state.ws_broadcast.subscribe();
            let app = crate::api::create_test_router(state);
            let admin = login(&app, &repo, "bh-admin", OperatorRole::Admin).await;
            let operator = login(&app, &repo, "bh-operator", OperatorRole::Operator).await;
            let before = audit_len(&repo).await;
            let victim = "203.0.113.10";
            let bearer = ("authorization", "Bearer operator-bearer-token");
            for (auth, body, expected) in [
                (bearer, create(victim, Some(victim)), StatusCode::FORBIDDEN),
                (
                    ("cookie", operator.as_str()),
                    create(victim, Some(victim)),
                    StatusCode::FORBIDDEN,
                ),
                (
                    ("cookie", admin.as_str()),
                    create(victim, Some("203.0.113.11")),
                    StatusCode::BAD_REQUEST,
                ),
                (
                    ("cookie", admin.as_str()),
                    create(victim, Some(" 203.0.113.10")),
                    StatusCode::BAD_REQUEST,
                ),
                (
                    ("cookie", admin.as_str()),
                    create(victim, None),
                    StatusCode::BAD_REQUEST,
                ),
            ] {
                let (status, response) = send(&app, "/v1/mitigations", Some(auth), body).await;
                assert_eq!(status, expected, "{auth:?}: {response}");
                assert_eq!(repo.count_active_global().await.unwrap(), 0);
                assert_eq!(audit_len(&repo).await, before);
            }
            let (status, response) = send(
                &app,
                "/v1/mitigations",
                Some(("cookie", &admin)),
                create(victim, Some(victim)),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED, "{response}");
            assert_eq!(response["action_type"], "blackhole");
            assert_eq!(response["origin_mode"], "dry-run");
            assert_eq!(response["dst_prefix"], "203.0.113.10/32");
            assert_eq!(
                response["blackhole"],
                json!({"next_hop": "192.0.2.66", "communities": ["65535:666"], "large_communities": []})
            );
            assert_eq!(repo.count_active_global().await.unwrap(), 1);
            assert_eq!(audit_len(&repo).await, before + 1);
            // Dry-run sends nothing to the speaker.
            assert_eq!(speaker.adds.load(SeqCst), 0);
            assert!(speaker.routes().await.is_empty());
            let message = serde_json::to_value(feed.try_recv().unwrap()).unwrap();
            assert_eq!(message["type"], "mitigation_created");
            assert_eq!(message["mitigation"]["blackhole"], response["blackhole"]);
            // The bearer token keeps Operator access to FlowSpec creation.
            let (status, _) = send(
                &app,
                "/v1/mitigations",
                Some(bearer),
                json!({"reason": "r", "victim_ip": "203.0.113.12", "protocol": "udp",
                    "dst_ports": [53], "action": "discard", "ttl_seconds": 120}),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
            // FlowSpec still requires a protocol with the same 422 as before.
            let (status, _) = send(
                &app,
                "/v1/mitigations",
                Some(bearer),
                json!({"reason": "r", "victim_ip": "203.0.113.13", "action": "discard",
                    "ttl_seconds": 120}),
            )
            .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        }

        /// Enforced creation adds the route; the ADR's 409s and the unconfirmed
        /// outcome surface through the API; withdrawal deletes the route with an
        /// audit entry, and a pending withdrawal blocks a new blackhole.
        #[tokio::test]
        async fn manual_blackhole_enforced_conflicts_and_withdrawal() {
            use crate::bgp::{BlackholeRoute, BlackholeSpeaker};
            let _metrics = METRICS_TEST_LOCK.lock().await;
            let repo = Arc::new(MockRepository::new());
            let speaker = Arc::new(FaultyBlackholes::default());
            let state = state(
                OperationMode::Enforced,
                repo.clone(),
                speaker.clone(),
                AuthMode::None,
            );
            let app = crate::api::create_test_router(state);
            let post = |victim: &'static str| {
                send(&app, "/v1/mitigations", None, create(victim, Some(victim)))
            };

            let (status, created) = post("203.0.113.10").await;
            assert_eq!(status, StatusCode::CREATED, "{created}");
            assert_eq!(created["origin_mode"], "enforced");
            assert!(created.get("announcement_outcome").is_none());
            assert_eq!(speaker.adds.load(SeqCst), 1);
            assert_eq!(
                speaker.routes().await[0].prefix().to_string(),
                "203.0.113.10/32"
            );

            let (status, conflict) = post("203.0.113.10").await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert!(
                conflict["error"].as_str().unwrap().contains("active owner"),
                "{conflict}"
            );

            let untracked = BlackholeRoute::new(
                "203.0.113.20/32".parse().unwrap(),
                "192.0.2.99".parse().unwrap(),
                vec![],
                vec![],
            )
            .unwrap();
            speaker.inner.announce_blackhole(&untracked).await.unwrap();
            let (status, conflict) = post("203.0.113.20").await;
            assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
            assert_eq!(repo.count_active_global().await.unwrap(), 1);

            speaker.fail_adds.store(true, SeqCst);
            let (status, unconfirmed) = post("203.0.113.30").await;
            assert_eq!(status, StatusCode::ACCEPTED, "{unconfirmed}");
            assert_eq!(unconfirmed["announcement_outcome"], "unconfirmed");
            speaker.fail_adds.store(false, SeqCst);

            // Withdrawal through the existing endpoint deletes the frozen route.
            let id = created["mitigation_id"].as_str().unwrap();
            let (status, withdrawn) = send(
                &app,
                &format!("/v1/mitigations/{id}/withdraw"),
                None,
                json!({"reason": "attack over"}),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{withdrawn}");
            assert_eq!(withdrawn["status"], "withdrawn");
            assert_eq!(withdrawn["blackhole"]["next_hop"], "192.0.2.66");
            assert_eq!(speaker.routes().await, [untracked]);
            let audit = repo
                .list_audit(&ListParams {
                    limit: 100,
                    ..Default::default()
                })
                .await
                .unwrap();
            assert!(audit.iter().any(|entry| entry.action == "withdraw"
                && entry.target_id.as_deref() == Some(id)
                && entry.details["reason"] == "anonymous: attack over"));

            // A withdrawal left pending blocks a new blackhole for the victim.
            let (status, second) = post("203.0.113.11").await;
            assert_eq!(status, StatusCode::CREATED, "{second}");
            speaker.withdraw_fault.store(1, SeqCst);
            let id = second["mitigation_id"].as_str().unwrap();
            let (status, _) = send(
                &app,
                &format!("/v1/mitigations/{id}/withdraw"),
                None,
                json!({"reason": "attack over"}),
            )
            .await;
            assert!(!status.is_success(), "{status}");
            let (status, conflict) = post("203.0.113.11").await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert!(
                conflict["error"]
                    .as_str()
                    .unwrap()
                    .contains("pending withdrawal"),
                "{conflict}"
            );
        }

        /// Refused blackholes count under blackhole-specific reasons and save nothing.
        #[tokio::test]
        async fn manual_blackhole_rejections_are_counted_by_reason() {
            let _metrics = METRICS_TEST_LOCK.lock().await;
            let repo = Arc::new(MockRepository::new());
            let mut state = state(
                OperationMode::DryRun,
                repo.clone(),
                Arc::new(FaultyBlackholes::default()),
                AuthMode::None,
            );
            Arc::get_mut(&mut state)
                .unwrap()
                .settings
                .blackhole
                .max_active_per_pop = 1;
            let app = crate::api::create_test_router(state);
            let count = |reason: &str| GUARDRAIL_REJECTIONS.with_label_values(&[reason]).get();
            let post = |victim: &'static str| {
                send(&app, "/v1/mitigations", None, create(victim, Some(victim)))
            };
            for (victim, reason) in [
                ("198.51.100.10", "BlackholeNotOwned"),
                ("127.0.0.1", "InvalidBlackhole"),
            ] {
                let before = count(reason);
                let (status, body) = post(victim).await;
                assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{victim}: {body}");
                assert_eq!(count(reason), before + 1.0, "{victim}");
            }
            assert_eq!(repo.count_active_global().await.unwrap(), 0);
            assert_eq!(post("203.0.113.10").await.0, StatusCode::CREATED);
            let before = count("BlackholeQuotaExceeded");
            let (status, body) = post("203.0.113.11").await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
            assert_eq!(count("BlackholeQuotaExceeded"), before + 1.0);
            assert_eq!(repo.count_active_global().await.unwrap(), 1);
        }

        fn blackhole_playbooks(ttl_seconds: u32) -> Playbooks {
            crate::config::parse_yaml(&format!(
                "playbooks:\n  - name: rtbh\n    match: {{vector: udp_flood}}\n    steps:\n      - {{action: blackhole, ttl_seconds: {ttl_seconds}}}\n"
            ))
            .unwrap()
        }

        /// A state whose `fastnetmon` source may trigger the blackhole playbook.
        async fn detector_state(
            mode: OperationMode,
            repo: Arc<MockRepository>,
            speaker: Arc<FaultyBlackholes>,
        ) -> Arc<AppState> {
            let mut state = state(mode, repo, speaker, AuthMode::None);
            Arc::get_mut(&mut state)
                .unwrap()
                .settings
                .blackhole
                .detector_sources = vec!["fastnetmon".into()];
            *state.playbooks.write().await = blackhole_playbooks(600);
            // FastNetMon sends no confidence, so it acts alone.
            state.correlation_config.write().await.enabled = false;
            state
        }

        /// The payload `scripts/prefixd-fastnetmon.sh` posts for a ban.
        fn fastnetmon_ban(source: &str, victim: &str) -> Value {
            json!({
                "event_id": uuid::Uuid::new_v4().to_string(),
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "source": source,
                "victim_ip": victim,
                "vector": "udp_flood",
                "action": "ban",
                "pps": 250000,
                "raw_details": {"raw": "incoming udp traffic: 900 mbps", "direction": "incoming", "original_action": "ban"},
            })
        }

        async fn get(app: &axum::Router, path: &str) -> (StatusCode, Value) {
            let response = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap();
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            )
        }

        /// FastNetMon ban to a dry-run blackhole with no RPC; a repeated ban extends
        /// it within the cap; another source is refused for creation and extension;
        /// the script's unban (list by victim, withdraw each) and the event unban
        /// both withdraw blackholes.
        #[tokio::test]
        async fn fastnetmon_event_drives_a_dry_run_blackhole_end_to_end() {
            let _metrics = METRICS_TEST_LOCK.lock().await;
            let repo = Arc::new(MockRepository::new());
            let speaker = Arc::new(FaultyBlackholes::default());
            let state = detector_state(OperationMode::DryRun, repo.clone(), speaker.clone()).await;
            let app = crate::api::create_test_router(state.clone());
            let victim = "203.0.113.10";
            let refused = || {
                GUARDRAIL_REJECTIONS
                    .with_label_values(&["BlackholeSourceNotAllowed"])
                    .get()
            };

            // A source outside blackhole.detector_sources is refused before any row.
            let before = refused();
            let (status, body) = send(
                &app,
                "/v1/events",
                None,
                fastnetmon_ban("dashboard", victim),
            )
            .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
            assert!(
                body["error"].as_str().unwrap().contains("detector_sources"),
                "{body}"
            );
            assert_eq!(refused(), before + 1.0);
            assert_eq!(repo.count_active_global().await.unwrap(), 0);

            let (status, body) = send(
                &app,
                "/v1/events",
                None,
                fastnetmon_ban("fastnetmon", victim),
            )
            .await;
            assert_eq!(status, StatusCode::ACCEPTED, "{body}");
            assert_eq!(body["status"], "accepted");
            assert!(body.get("announcement_outcome").is_none());
            let id = body["mitigation_id"].as_str().unwrap().to_owned();
            let stored = repo
                .get_mitigation(id.parse().unwrap())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stored.action_type, crate::domain::ActionType::Blackhole);
            assert_eq!(stored.origin_mode, Some(OperationMode::DryRun));
            assert_eq!(stored.vector, crate::domain::AttackVector::UdpFlood);
            assert_eq!(stored.customer_id.as_deref(), Some("customer-a"));
            assert!(stored.match_criteria.protocol.is_none());
            let created_expiry = stored.expires_at;
            // Dry-run sends nothing: no add and no route.
            assert_eq!(speaker.adds.load(SeqCst), 0);
            assert!(speaker.routes().await.is_empty());

            // A step beyond the cap (written past the gate) still extends only to now + max_ttl.
            *state.playbooks.write().await = blackhole_playbooks(86_400);
            let (status, body) = send(
                &app,
                "/v1/events",
                None,
                fastnetmon_ban("fastnetmon", victim),
            )
            .await;
            assert_eq!(status, StatusCode::ACCEPTED, "{body}");
            assert_eq!(body["status"], "extended");
            assert_eq!(body["mitigation_id"], id.as_str());
            let extended = repo
                .get_mitigation(id.parse().unwrap())
                .await
                .unwrap()
                .unwrap();
            let cap = chrono::Utc::now() + chrono::Duration::seconds(3600);
            assert!(extended.expires_at > created_expiry);
            assert!(extended.expires_at <= cap, "{}", extended.expires_at);
            assert!(extended.expires_at > cap - chrono::Duration::seconds(10));

            // Another source cannot extend it either.
            let (status, _) = send(
                &app,
                "/v1/events",
                None,
                fastnetmon_ban("dashboard", victim),
            )
            .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
            let unchanged = repo
                .get_mitigation(id.parse().unwrap())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(unchanged.expires_at, extended.expires_at);

            // The script's unban: list live mitigations for the victim, withdraw each.
            let (status, listed) = get(
                &app,
                &format!(
                    "/v1/mitigations?status=pending,active,escalated&victim_ip={victim}&limit=1000"
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{listed}");
            let ids: Vec<_> = listed["mitigations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m["mitigation_id"].as_str().unwrap().to_owned())
                .collect();
            assert_eq!(ids, std::slice::from_ref(&id));
            let (status, withdrawn) = send(
                &app,
                &format!("/v1/mitigations/{id}/withdraw"),
                None,
                json!({"operator_id": "fastnetmon", "reason": "FastNetMon unban"}),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{withdrawn}");
            assert_eq!(withdrawn["status"], "withdrawn");
            assert_eq!(withdrawn["action_type"], "blackhole");

            // An event unban with the ban's event ID withdraws the blackhole too.
            *state.playbooks.write().await = blackhole_playbooks(600);
            let ban = fastnetmon_ban("fastnetmon", "203.0.113.11");
            let (status, body) = send(&app, "/v1/events", None, ban.clone()).await;
            assert_eq!(status, StatusCode::ACCEPTED, "{body}");
            let mut unban = ban;
            unban["action"] = "unban".into();
            let (status, body) = send(&app, "/v1/events", None, unban).await;
            assert_eq!(status, StatusCode::ACCEPTED, "{body}");
            assert_eq!(body["status"], "withdrawn");
            assert_eq!(repo.count_active_global().await.unwrap(), 0);
            assert_eq!(speaker.adds.load(SeqCst), 0);
            assert_eq!(speaker.deletes.load(SeqCst), 0);
        }

        /// The unleased opt-in: an enforced detector blackhole adds the frozen route,
        /// health reports it unleased, and the unban deletes it.
        #[tokio::test]
        async fn enforced_detector_blackhole_runs_unleased_when_opted_in() {
            let _metrics = METRICS_TEST_LOCK.lock().await;
            let repo = Arc::new(MockRepository::new());
            let speaker = Arc::new(FaultyBlackholes::default());
            let state =
                detector_state(OperationMode::Enforced, repo.clone(), speaker.clone()).await;
            let app = crate::api::create_test_router(state);
            let (status, health) = get(&app, "/v1/health/detail").await;
            assert_eq!(status, StatusCode::OK, "{health}");
            assert_eq!(health["speaker"]["detector_unleased"], true);
            assert_eq!(health["speaker"]["capabilities"]["blackhole_lease"], false);
            let (status, body) = send(
                &app,
                "/v1/events",
                None,
                fastnetmon_ban("fastnetmon", "203.0.113.10"),
            )
            .await;
            assert_eq!(status, StatusCode::ACCEPTED, "{body}");
            assert_eq!(speaker.adds.load(SeqCst), 1);
            assert_eq!(
                speaker.routes().await[0].next_hop().to_string(),
                "192.0.2.66"
            );
            let id = body["mitigation_id"].as_str().unwrap();
            let (status, withdrawn) = send(
                &app,
                &format!("/v1/mitigations/{id}/withdraw"),
                None,
                json!({"reason": "FastNetMon unban"}),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{withdrawn}");
            assert!(speaker.routes().await.is_empty());
        }

        /// The enforced gate on playbook save and reload: refused without the lease or
        /// the unleased opt-in, accepted in dry-run; manual blackholes are unaffected.
        #[tokio::test]
        async fn enforced_playbook_save_and_reload_need_the_lease_or_an_opt_in() {
            let _metrics = METRICS_TEST_LOCK.lock().await;
            for mode in [OperationMode::Enforced, OperationMode::DryRun] {
                let dir = tempfile::tempdir().unwrap();
                let repo = Arc::new(MockRepository::new());
                let speaker = Arc::new(FaultyBlackholes::default());
                let mut state = state(mode, repo.clone(), speaker.clone(), AuthMode::None);
                Arc::get_mut(&mut state).unwrap().config_dir = dir.path().into();
                let app = crate::api::create_test_router(state.clone());
                let body = serde_json::to_value(blackhole_playbooks(600)).unwrap();
                let request = Request::put("/v1/config/playbooks")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap();
                let response = app.clone().oneshot(request).await.unwrap();
                let status = response.status();
                let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                    .await
                    .unwrap();
                let saved = dir.path().join("playbooks.yaml");
                let enforced = mode == OperationMode::Enforced;
                if enforced {
                    assert_eq!(status, StatusCode::BAD_REQUEST);
                    let text = String::from_utf8_lossy(&bytes);
                    assert!(text.contains("rustbgpd injection lease"), "{text}");
                    assert!(!saved.exists());
                } else {
                    assert_eq!(status, StatusCode::OK);
                    assert!(saved.exists());
                }
                // Reload of the same file: refused in enforced mode, playbooks unchanged.
                blackhole_playbooks(600).save(&saved).unwrap();
                let result = state.reload_config().await;
                assert_eq!(result.is_err(), enforced, "{mode:?}: {result:?}");
                assert_eq!(
                    state.playbooks.read().await.playbooks.len(),
                    usize::from(!enforced)
                );
                // A manual blackhole needs no lease in either mode.
                let (status, created) = send(
                    &app,
                    "/v1/mitigations",
                    None,
                    create("203.0.113.10", Some("203.0.113.10")),
                )
                .await;
                assert_eq!(status, StatusCode::CREATED, "{created}");
                assert_eq!(speaker.adds.load(SeqCst), usize::from(enforced));
            }
        }
    }
}

#[cfg(test)]
mod amplification_tests {
    //! ADR 028 slice 4: multi-rule playbook steps admitted per rule.
    use super::{AppError, AppState, Arc, EventResponse, RuleOutcome, handle_ban, handle_unban};
    use crate::bgp::MockAnnouncer;
    use crate::config::{
        BgpMode, DEFAULT_REFLECTOR_PORTS, Inventory, OperationMode, Playbooks, ReflectorPort,
        Settings,
    };
    use crate::db::{MitigationListParams, MockRepository, RepositoryTrait};
    use crate::domain::{
        ActionType, AttackEventInput, AttackVector, FragmentMatch, Mitigation, MitigationStatus,
    };
    use crate::error::PrefixdError;
    use uuid::Uuid;

    const VICTIM: &str = "203.0.113.10";
    const PLAYBOOKS: &str = r#"
playbooks:
  - name: udp_flood_police
    match: { vector: udp_flood }
    steps:
      - { action: police, rate_bps: 5000000, ttl_seconds: 120 }
  - name: udp_amplification
    match: { vector: udp_amplification }
    steps:
      - ttl_seconds: 300
        rules:
          - match: { src_ports: from_event }
            action: discard
          - match: { fragment: non_first }
            action: police
            rate_bps: 20000000
"#;

    struct Fixture {
        state: Arc<AppState>,
        repo: Arc<MockRepository>,
        speaker: Arc<MockAnnouncer>,
    }

    fn fixture(mode: OperationMode, tweak: impl FnOnce(&mut Settings, &mut Playbooks)) -> Fixture {
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(MockAnnouncer::new());
        fixture_on(repo, speaker, mode, tweak)
    }

    /// A controller over existing state, as after a restart or upgrade.
    fn fixture_on(
        repo: Arc<MockRepository>,
        speaker: Arc<MockAnnouncer>,
        mode: OperationMode,
        tweak: impl FnOnce(&mut Settings, &mut Playbooks),
    ) -> Fixture {
        let mut settings: Settings =
            crate::config::parse_yaml(include_str!("../../configs/prefixd.yaml")).unwrap();
        settings.bgp.mode = BgpMode::Mock;
        settings.mode = mode;
        settings.correlation.enabled = false;
        settings.guardrails.allow_fragment_match = true;
        let mut playbooks: Playbooks = crate::config::parse_yaml(PLAYBOOKS).unwrap();
        tweak(&mut settings, &mut playbooks);
        let parsed: Inventory =
            crate::config::parse_yaml(include_str!("../../configs/inventory.yaml")).unwrap();
        let inventory = Inventory::new(parsed.customers);
        let state = AppState::new(
            settings,
            inventory,
            playbooks,
            repo.clone(),
            speaker.clone(),
            ".".into(),
        )
        .unwrap();
        Fixture {
            state,
            repo,
            speaker,
        }
    }

    fn event(id: &str, vector: &str, src_ports: Option<&[u16]>) -> AttackEventInput {
        serde_json::from_value(serde_json::json!({
            "event_id": id, "timestamp": chrono::Utc::now(), "source": "amp-test",
            "victim_ip": VICTIM, "vector": vector, "top_src_ports": src_ports,
            "confidence": 0.9,
        }))
        .unwrap()
    }

    async fn ban(f: &Fixture, input: AttackEventInput) -> Result<EventResponse, PrefixdError> {
        handle_ban(f.state.clone(), input)
            .await
            .map(|(_, axum::Json(response))| response)
            .map_err(|AppError(error)| error)
    }

    async fn rows(f: &Fixture) -> Vec<Mitigation> {
        let params = MitigationListParams {
            limit: 100,
            ..Default::default()
        };
        let mut rows = f
            .repo
            .list_mitigations(None, None, None, None, &params)
            .await
            .unwrap();
        rows.sort_by_key(|m| (m.created_at, m.mitigation_id));
        rows
    }

    fn outcomes(response: &EventResponse) -> Vec<RuleOutcome> {
        response.rules.iter().map(|rule| rule.outcome).collect()
    }

    async fn get(f: &Fixture, id: Uuid) -> Mitigation {
        f.repo.get_mitigation(id).await.unwrap().unwrap()
    }

    #[tokio::test]
    async fn library_intersection_per_rule_admission_refresh_and_changed_set() {
        // Enforced admissions move process-global announcement series.
        let _metrics = crate::observability::metrics::METRICS_TEST_LOCK
            .lock()
            .await;
        use RuleOutcome::{Created, Extended};
        let f = fixture(OperationMode::Enforced, |_, _| {});
        // 4444 is not a reflector port: it is dropped, never matched.
        let first = ban(&f, event("e1", "udp_amplification", Some(&[123, 4444, 53])))
            .await
            .unwrap();
        assert_eq!(first.status, "accepted");
        assert_eq!(outcomes(&first), [Created, Created]);
        assert_eq!(first.mitigation_ids.len(), 2);
        assert_eq!(first.mitigation_id, Some(first.mitigation_ids[0]));
        let ports = get(&f, first.mitigation_ids[0]).await;
        assert_eq!(ports.vector, AttackVector::UdpAmplification);
        assert_eq!(ports.match_criteria.src_ports, [53, 123]);
        assert!(ports.match_criteria.dst_ports.is_empty());
        assert_eq!(ports.match_criteria.protocol, Some(17));
        assert_eq!(ports.action_type, ActionType::Discard);
        let fragments = get(&f, first.mitigation_ids[1]).await;
        assert_eq!(
            fragments.match_criteria.fragment,
            Some(FragmentMatch::NonFirst)
        );
        assert!(fragments.match_criteria.src_ports.is_empty());
        assert_eq!(fragments.action_type, ActionType::Police);
        assert_eq!(fragments.action_params.rate_bps, Some(20_000_000));
        assert_eq!(f.speaker.announced_count().await, 2);

        // A refresh reproducing both rules extends both.
        let refresh = ban(&f, event("e2", "udp_amplification", Some(&[53, 123])))
            .await
            .unwrap();
        assert_eq!(refresh.status, "extended");
        assert_eq!(outcomes(&refresh), [Extended, Extended]);
        assert_eq!(refresh.mitigation_ids, first.mitigation_ids);
        assert_eq!(rows(&f).await.len(), 2);

        // A changed port set is a new scope; the fragment rule is unchanged.
        let changed = ban(&f, event("e3", "udp_amplification", Some(&[123])))
            .await
            .unwrap();
        assert_eq!(outcomes(&changed), [Created, Extended]);
        assert_ne!(changed.mitigation_ids[0], first.mitigation_ids[0]);
        assert_eq!(changed.mitigation_ids[1], first.mitigation_ids[1]);
        assert_eq!(
            get(&f, changed.mitigation_ids[0])
                .await
                .match_criteria
                .src_ports,
            [123]
        );
        assert_eq!(rows(&f).await.len(), 3);
    }

    #[tokio::test]
    async fn library_ports_split_into_stable_chunks_of_max_ports() {
        // Enforced admissions move process-global announcement series.
        let _metrics = crate::observability::metrics::METRICS_TEST_LOCK
            .lock()
            .await;
        use RuleOutcome::{Created, Extended};
        let f = fixture(OperationMode::Enforced, |_, _| {});
        let library: Vec<u16> = DEFAULT_REFLECTOR_PORTS.iter().map(|(p, _)| *p).collect();
        assert_eq!(library.len(), 20);
        let mut reported: Vec<u16> = library.iter().rev().copied().collect();
        reported.push(4444);
        let first = ban(&f, event("c1", "udp_amplification", Some(&reported)))
            .await
            .unwrap();
        assert_eq!(
            outcomes(&first),
            [Created, Created, Created, Created, Created]
        );
        let mut chunks = Vec::new();
        for id in &first.mitigation_ids[..4] {
            chunks.push(get(&f, *id).await.match_criteria.src_ports);
        }
        // Sorted, then split at the default max_ports (5), FRR's per-component
        // limit: twenty library ports make four source-port rules.
        let expected: Vec<Vec<u16>> = library.chunks(5).map(<[u16]>::to_vec).collect();
        assert_eq!(chunks, expected);

        // The same set in another order and with duplicates maps to the same
        // identities: every rule extends and none is duplicated.
        let mut shuffled = library.clone();
        shuffled.rotate_left(7);
        shuffled.extend_from_slice(&[53, 123]);
        let again = ban(&f, event("c2", "udp_amplification", Some(&shuffled)))
            .await
            .unwrap();
        assert_eq!(
            outcomes(&again),
            [Extended, Extended, Extended, Extended, Extended]
        );
        assert_eq!(again.mitigation_ids, first.mitigation_ids);
        assert_eq!(rows(&f).await.len(), 5);
        assert_eq!(f.speaker.announced_count().await, 5);
    }

    #[tokio::test]
    async fn stored_eight_port_rules_outlive_a_lower_max_ports() {
        // Enforced admissions move process-global announcement series.
        let _metrics = crate::observability::metrics::METRICS_TEST_LOCK
            .lock()
            .await;
        use crate::bgp::{FlowSpecReader, FlowSpecWriter};
        use crate::scheduler::ReconciliationLoop;
        // Before the upgrade: max_ports 8 stores 8-port source lists.
        let before = fixture(OperationMode::Enforced, |settings, _| {
            settings.guardrails.max_ports = 8;
        });
        let library: Vec<u16> = DEFAULT_REFLECTOR_PORTS.iter().map(|(p, _)| *p).collect();
        let banned = ban(&before, event("old", "udp_amplification", Some(&library)))
            .await
            .unwrap();
        let ids = banned.mitigation_ids.clone();
        assert_eq!(ids.len(), 4);
        assert_eq!(get(&before, ids[0]).await.match_criteria.src_ports.len(), 8);
        assert_eq!(get(&before, ids[1]).await.match_criteria.src_ports.len(), 8);

        // After the upgrade: the default cap of 5, the same database and speaker.
        let f = fixture_on(
            before.repo.clone(),
            before.speaker.clone(),
            OperationMode::Enforced,
            |_, _| {},
        );
        assert_eq!(f.state.settings.guardrails.max_ports, 5);
        let reconciler = ReconciliationLoop::new(f.repo.clone(), f.speaker.clone(), 30, false)
            .with_app_state(f.state.clone());

        // A speaker restart loses every rule; repair re-announces them whole.
        for rule in f.speaker.list_active().await.unwrap() {
            f.speaker.withdraw(&rule).await.unwrap();
        }
        assert_eq!(f.speaker.announced_count().await, 0);
        reconciler.reconcile().await.unwrap();
        let announced = f.speaker.list_active().await.unwrap();
        assert_eq!(announced.len(), 4);
        assert_eq!(
            announced
                .iter()
                .filter(|rule| rule.nlri.src_ports.len() == 8)
                .count(),
            2
        );

        // TTL expiry withdraws an 8-port rule.
        let mut expiring = get(&f, ids[0]).await;
        expiring.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
        f.repo.update_mitigation(&expiring).await.unwrap();
        reconciler.reconcile().await.unwrap();
        assert_eq!(get(&f, ids[0]).await.status, MitigationStatus::Expired);

        // An operator withdrawal removes the other 8-port rule.
        let operator = super::withdraw_and_notify(
            &f.state,
            &get(&f, ids[1]).await,
            "operator",
            "op",
            "op: upgrade".into(),
        )
        .await
        .unwrap();
        assert_eq!(operator.status, MitigationStatus::Withdrawn);

        // The detector unban withdraws what the ban created and is still live.
        let mut unban = event("old", "udp_amplification", None);
        unban.action = "unban".into();
        let (_, axum::Json(response)) = handle_unban(f.state.clone(), unban)
            .await
            .map_err(|AppError(error)| error)
            .unwrap();
        assert_eq!(response.status, "withdrawn");
        for id in &ids[2..] {
            assert_eq!(get(&f, *id).await.status, MitigationStatus::Withdrawn);
        }
        assert_eq!(f.speaker.announced_count().await, 0);
    }

    #[tokio::test]
    async fn partial_admission_reports_each_rule_and_none_admitted_returns_first_error() {
        // Enforced admissions move process-global announcement series.
        let _metrics = crate::observability::metrics::METRICS_TEST_LOCK
            .lock()
            .await;
        // The quota admits one rule: the second is rejected and reported.
        let f = fixture(OperationMode::Enforced, |settings, _| {
            settings.quotas.max_active_per_pop = 1;
        });
        let partial = ban(&f, event("p1", "udp_amplification", Some(&[123])))
            .await
            .unwrap();
        assert_eq!(partial.status, "accepted");
        assert_eq!(
            outcomes(&partial),
            [RuleOutcome::Created, RuleOutcome::Rejected]
        );
        assert_eq!(partial.mitigation_ids.len(), 1);
        let rejected = &partial.rules[1];
        assert!(rejected.mitigation_id.is_none());
        assert!(rejected.reason.as_deref().unwrap().contains("quota"));
        assert_eq!(rows(&f).await.len(), 1);

        // Every rule refused: the first rule's error, as for one rule.
        let f = fixture(OperationMode::Enforced, |_, _| {});
        f.repo
            .insert_safelist(&format!("{VICTIM}/32"), "test", None)
            .await
            .unwrap();
        let error = ban(&f, event("p2", "udp_amplification", Some(&[123])))
            .await
            .unwrap_err();
        assert!(
            matches!(error, PrefixdError::GuardrailViolation(_)),
            "{error}"
        );
        assert!(rows(&f).await.is_empty());
        assert_eq!(f.speaker.announced_count().await, 0);
    }

    #[tokio::test]
    async fn dry_run_persists_every_rule_and_sends_no_rpc() {
        // Enforced admissions move process-global announcement series.
        let _metrics = crate::observability::metrics::METRICS_TEST_LOCK
            .lock()
            .await;
        let f = fixture(OperationMode::DryRun, |_, _| {});
        let response = ban(&f, event("d1", "udp_amplification", Some(&[123, 389])))
            .await
            .unwrap();
        assert_eq!(
            outcomes(&response),
            [RuleOutcome::Created, RuleOutcome::Created]
        );
        let saved = rows(&f).await;
        assert_eq!(saved.len(), 2);
        assert!(saved.iter().all(Mitigation::is_dry_run_origin));
        assert_eq!(saved[0].match_criteria.src_ports, [123, 389]);
        assert_eq!(f.speaker.announced_count().await, 0);
    }

    #[tokio::test]
    async fn no_usable_source_ports_or_playbook_falls_back_to_udp_flood() {
        // Enforced admissions move process-global announcement series.
        let _metrics = crate::observability::metrics::METRICS_TEST_LOCK
            .lock()
            .await;
        let empty_library = |settings: &mut Settings, _: &mut Playbooks| {
            settings.amplification.reflector_ports = Some(Vec::new());
        };
        let no_playbook = |_: &mut Settings, playbooks: &mut Playbooks| {
            playbooks
                .playbooks
                .retain(|p| p.name != "udp_amplification");
        };
        let keep = |_: &mut Settings, _: &mut Playbooks| {};
        type Tweak = Box<dyn FnOnce(&mut Settings, &mut Playbooks)>;
        let cases: [(&str, Option<&[u16]>, Tweak, &str); 4] = [
            (
                "foreign",
                Some(&[4444, 27015]),
                Box::new(keep),
                "no reflector source ports",
            ),
            ("absent", None, Box::new(keep), "no reflector source ports"),
            (
                "disabled",
                Some(&[123]),
                Box::new(empty_library),
                "no reflector source ports",
            ),
            (
                "unconfigured",
                Some(&[123]),
                Box::new(no_playbook),
                "no udp_amplification playbook",
            ),
        ];
        for (name, ports, tweak, why) in cases {
            let f = fixture(OperationMode::Enforced, tweak);
            let response = ban(&f, event(name, "udp_amplification", ports))
                .await
                .unwrap();
            assert_eq!(outcomes(&response), [RuleOutcome::Created], "{name}");
            let saved = rows(&f).await;
            assert_eq!(saved.len(), 1, "{name}");
            // Exactly today's udp_flood rule: police, service ports, no source ports.
            let rule = &saved[0];
            assert_eq!(rule.vector, AttackVector::UdpFlood, "{name}");
            assert_eq!(rule.action_type, ActionType::Police);
            assert_eq!(rule.action_params.rate_bps, Some(5_000_000));
            assert_eq!(rule.match_criteria.dst_ports, [53]);
            assert!(rule.match_criteria.src_ports.is_empty());
            assert!(rule.match_criteria.fragment.is_none());
            assert!(
                rule.reason
                    .contains(&format!("udp_amplification fallback: {why}")),
                "{name}: {}",
                rule.reason
            );
        }
        // Control: a library port is matched, not fallen back from.
        let f = fixture(OperationMode::Enforced, |settings, _| {
            settings.amplification.reflector_ports = Some(vec![ReflectorPort {
                port: 123,
                name: "ntp".into(),
            }]);
        });
        ban(&f, event("library", "udp_amplification", Some(&[123])))
            .await
            .unwrap();
        assert!(
            rows(&f)
                .await
                .iter()
                .all(|m| m.vector == AttackVector::UdpAmplification)
        );
    }

    #[tokio::test]
    async fn detector_unban_withdraws_every_rule_the_ban_created() {
        // Enforced admissions move process-global announcement series.
        let _metrics = crate::observability::metrics::METRICS_TEST_LOCK
            .lock()
            .await;
        let f = fixture(OperationMode::Enforced, |_, _| {});
        let banned = ban(&f, event("u1", "udp_amplification", Some(&[123])))
            .await
            .unwrap();
        let mut unban = event("u1", "udp_amplification", None);
        unban.action = "unban".into();
        let (_, axum::Json(response)) = handle_unban(f.state.clone(), unban)
            .await
            .map_err(|AppError(error)| error)
            .unwrap();
        assert_eq!(response.status, "withdrawn");
        assert_eq!(response.mitigation_ids, banned.mitigation_ids);
        for id in banned.mitigation_ids {
            assert_eq!(get(&f, id).await.status, MitigationStatus::Withdrawn);
        }
    }

    #[tokio::test]
    async fn oversized_top_src_ports_is_refused_before_any_state() {
        // Enforced admissions move process-global announcement series.
        let _metrics = crate::observability::metrics::METRICS_TEST_LOCK
            .lock()
            .await;
        let f = fixture(OperationMode::Enforced, |_, _| {});
        let too_many: Vec<u16> = (1..=65).collect();
        let error = ban(&f, event("big", "udp_amplification", Some(&too_many)))
            .await
            .unwrap_err();
        assert!(matches!(error, PrefixdError::InvalidRequest(_)), "{error}");
        assert_eq!(error.status_code(), axum::http::StatusCode::BAD_REQUEST);
        assert!(
            f.repo
                .find_ban_event_by_external_id("amp-test", "big")
                .await
                .unwrap()
                .is_none()
        );
        // Control: 64 entries are accepted.
        ban(&f, event("max", "udp_amplification", Some(&too_many[..64])))
            .await
            .unwrap();
    }
}
