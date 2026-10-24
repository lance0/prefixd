//! Side-effect-free manual FlowSpec preparation shared by creation and preview.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::sync::Arc;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;
use crate::api::auth::require_role;
use crate::auth::AuthSession;
use crate::domain::{
    ActionParams, ActionType, AttackVector, FlowSpecAction, FlowSpecNlri, MatchCriteria,
    Mitigation, MitigationIntent, MitigationRoute, OperatorRole, find_mitigation_owner,
};
use crate::error::PrefixdError;
use crate::guardrails::Guardrails;

use super::{
    CreateMitigationRequest, MAX_STRING_LEN, MAX_USERNAME_LEN, validate_ip, validate_string_len,
};

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FlowSpecAdmissionOutcome {
    /// Controller-side checks passed at observation time; no reservation or RPC.
    Admissible,
    Refused,
    /// A required safety read could not be completed. This never means safe.
    Unavailable,
}

#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FlowSpecAdmissionCheck {
    Input,
    Target,
    Ownership,
    Safelist,
    Guardrails,
    CreationRate,
    Capability,
    Lifetime,
    /// The read-only deadline covers inventory preparation and safety reads.
    Timeout,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FlowSpecAdmissionCandidate {
    pub victim_ip: String,
    pub customer_id: Option<String>,
    pub service_id: Option<String>,
    pub pop: String,
    /// Complete canonical traffic match; no component is dropped on refusal.
    pub scope: FlowSpecNlri,
    pub action: FlowSpecAction,
    /// Requested lifetime, subject to the optional absolute expiry ceiling.
    pub ttl_seconds: u32,
    pub expires_at_cap: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FlowSpecAdmissionPreview {
    pub outcome: FlowSpecAdmissionOutcome,
    pub checked_at: DateTime<Utc>,
    /// The controller's configured operation mode, not evidence of enforcement.
    pub mode: String,
    /// Always unobserved: preview makes no RPC and cannot detect a speaker-side
    /// owner conflict, availability, acceptance, export, or router installation.
    pub speaker_state: String,
    /// Present after input and inventory preparation, even if admission is refused.
    pub candidate: Option<FlowSpecAdmissionCandidate>,
    pub failed_check: Option<FlowSpecAdmissionCheck>,
    /// Safe refusal detail or a bounded unavailable message; never database diagnostics.
    pub reason: Option<String>,
}

pub(super) struct AdmissionFailure {
    pub check: FlowSpecAdmissionCheck,
    pub error: PrefixdError,
}

impl AdmissionFailure {
    fn at(check: FlowSpecAdmissionCheck) -> impl FnOnce(PrefixdError) -> Self {
        move |error| Self { check, error }
    }
}

pub(super) struct PreparedManualFlowSpec {
    intent: MitigationIntent,
    target: String,
    expires_at_cap: Option<DateTime<Utc>>,
}

impl PreparedManualFlowSpec {
    fn candidate(&self) -> FlowSpecAdmissionCandidate {
        let mut scope = FlowSpecNlri::from(&self.intent.match_criteria);
        // Preserve legacy host identity spelling internally; display the exact
        // canonical prefix encoded by the speaker without changing that identity.
        if let Ok(prefix) = scope.dst_prefix.parse::<ipnet::IpNet>() {
            scope.dst_prefix = prefix.to_string();
        }
        FlowSpecAdmissionCandidate {
            victim_ip: self.target.clone(),
            customer_id: self.intent.customer_id.clone(),
            service_id: self.intent.service_id.clone(),
            pop: self.intent.pop.clone(),
            scope,
            action: FlowSpecAction {
                action_type: self.intent.action_type,
                rate_bps: self.intent.action_params.rate_bps,
            },
            ttl_seconds: self.intent.ttl_seconds,
            expires_at_cap: self.expires_at_cap,
        }
    }
}

/// Creation calls this under the lifecycle mutex; preview does not. It mutates nothing.
pub(super) async fn prepare_manual_flowspec(
    state: &AppState,
    req: CreateMitigationRequest,
    operator_id: &str,
) -> Result<PreparedManualFlowSpec, AdmissionFailure> {
    use FlowSpecAdmissionCheck::{Input, Ownership, Target};
    state
        .verified_speaker_binding()
        .map_err(AdmissionFailure::at(Target))?;
    let parse = || -> crate::error::Result<_> {
        let destination = if req.victim_ip.contains('/') {
            crate::domain::parse_flowspec_destination(&req.victim_ip)
                .map_err(|error| PrefixdError::InvalidRequest(error.to_string()))?
        } else {
            validate_ip(&req.victim_ip).map(ipnet::IpNet::from)?
        };
        validate_string_len(&req.reason, "reason", MAX_STRING_LEN)?;
        validate_string_len(operator_id, "operator_id", MAX_USERNAME_LEN)?;
        let address = destination.addr();
        let protocol = match req.protocol.as_deref() {
            Some("udp") => Some(17),
            Some("tcp") => Some(6),
            Some("icmp") if address.is_ipv4() => Some(1),
            Some("icmpv6") if address.is_ipv6() => Some(58),
            Some(protocol @ ("icmp" | "icmpv6")) => {
                return Err(PrefixdError::InvalidRequest(format!(
                    "protocol '{protocol}' does not match victim IP address family"
                )));
            }
            Some("any" | "") => None,
            Some(protocol) => {
                return Err(PrefixdError::InvalidRequest(format!(
                    "invalid protocol '{protocol}', expected: udp, tcp, icmp, icmpv6, any"
                )));
            }
            None => {
                return Err(PrefixdError::InvalidRequest(
                    "protocol is required for FlowSpec".into(),
                ));
            }
        };
        let action_type = match req.action.as_str() {
            "discard" => ActionType::Discard,
            "police" => ActionType::Police,
            "blackhole" => return Err(PrefixdError::InvalidRequest(
                "blackhole admission preview is unsupported; use the dedicated creation workflow"
                    .into(),
            )),
            _ => {
                return Err(PrefixdError::InvalidRequest(format!(
                    "invalid action '{}', expected: discard, police, blackhole",
                    req.action
                )));
            }
        };
        FlowSpecAction {
            action_type,
            rate_bps: req.rate_bps,
        }
        .traffic_rate_bytes_per_second()
        .map_err(|error| PrefixdError::InvalidRequest(error.to_string()))?;
        Ok((destination, protocol, action_type))
    };
    let (destination, protocol, action_type) = parse().map_err(AdmissionFailure::at(Input))?;
    let is_subnet = destination.prefix_len() != destination.max_prefix_len();
    let target = if !req.victim_ip.contains('/') {
        req.victim_ip.clone()
    } else if is_subnet {
        destination.to_string()
    } else {
        destination.addr().to_string()
    };
    let inventory = state.inventory.read().await;
    let context = if is_subnet {
        // An invalid inventory is an error, never an unowned or admissible prefix.
        Some(
            inventory
                .lookup_prefix(&destination)
                .map_err(AdmissionFailure::at(Ownership))?
                .ok_or_else(|| AdmissionFailure {
                    check: Ownership,
                    error: PrefixdError::InvalidRequest(
                        "destination CIDR must fit within one inventory customer prefix without conflicting ownership".into(),
                    ),
                })?,
        )
    } else {
        inventory.lookup_ip(&target)
    };
    let customer_id = context.map(|context| context.customer_id);
    drop(inventory);
    let src_prefix = req
        .src_prefix
        .as_deref()
        .map(crate::domain::canonical_source_prefix)
        .transpose()
        .map_err(|error| AdmissionFailure {
            check: Input,
            error: PrefixdError::InvalidRequest(error.to_string()),
        })?;
    Ok(PreparedManualFlowSpec {
        target,
        expires_at_cap: req.expires_at_cap,
        intent: MitigationIntent {
            event_id: Uuid::new_v4(),
            customer_id,
            service_id: None,
            pop: state.settings.pop.clone(),
            match_criteria: MatchCriteria {
                dst_prefix: if req.victim_ip.contains('/') {
                    destination.to_string()
                } else {
                    format!("{}/{}", req.victim_ip, destination.prefix_len())
                },
                src_prefix,
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
        },
    })
}

/// Shared controller-side admission. It neither reserves capacity nor reads or
/// mutates speaker routes. Atomic persistence and owner-protected RPC remain later.
pub(super) async fn validate_manual_flowspec(
    state: &AppState,
    prepared: PreparedManualFlowSpec,
) -> Result<Mitigation, AdmissionFailure> {
    validate_manual_flowspec_on(state, prepared, state.repo.as_ref()).await
}

async fn validate_manual_flowspec_on(
    state: &AppState,
    prepared: PreparedManualFlowSpec,
    repo: &dyn crate::db::RepositoryTrait,
) -> Result<Mitigation, AdmissionFailure> {
    use FlowSpecAdmissionCheck::{
        Capability, CreationRate, Guardrails as Safety, Lifetime, Ownership, Safelist,
    };
    let intent = &prepared.intent;
    let owner = find_mitigation_owner(
        repo,
        &state.settings.pop,
        &MitigationRoute::new(
            intent.action_type,
            &intent.match_criteria,
            &intent.action_params,
        ),
        &intent.match_criteria.scope_hash_for(intent.action_type),
    )
    .await
    .map_err(AdmissionFailure::at(Ownership))?;
    if owner.is_some() {
        return Err(AdmissionFailure {
            check: Ownership,
            error: PrefixdError::Conflict("FlowSpec rule already has an active owner".into()),
        });
    }
    let guardrails = Guardrails::with_timers(
        state.settings.guardrails.clone(),
        state.settings.quotas.clone(),
        &state.settings.timers,
    );
    let is_safelisted = repo
        .is_safelisted(&intent.match_criteria.dst_prefix)
        .await
        .map_err(AdmissionFailure::at(Safelist))?;
    guardrails
        .validate(intent, repo, is_safelisted)
        .await
        .map_err(AdmissionFailure::at(Safety))?;
    repo.check_new_mitigation_rate(&intent.pop, state.settings.quotas.max_new_per_minute)
        .await
        .map_err(AdmissionFailure::at(CreationRate))?;
    let mut mitigation =
        Mitigation::from_intent(prepared.intent, prepared.target, AttackVector::Unknown);
    if let Some(cap) = prepared.expires_at_cap {
        mitigation.expires_at = mitigation.expires_at.min(cap);
        guardrails
            .validate_remaining_ttl(mitigation.expires_at - mitigation.created_at)
            .map_err(AdmissionFailure::at(Lifetime))?;
    }
    super::flowspec_rule_for_admission(state, &mut mitigation)
        .map_err(AdmissionFailure::at(Capability))?;
    Ok(mitigation)
}

/// An authenticated snapshot of controller-side checks, without saved intent.
#[utoipa::path(
    post,
    path = "/v1/mitigations/preview",
    tag = "mitigations",
    description = "Side-effect-free manual discard/police admission snapshot. Requires Operator. Uses creation's preparation and safety checks. No capacity reservation, saved intent, audit, event, or speaker RPC. Creation rechecks. This is not speaker acceptance, export or router enforcement. Like creation, requires the active controller.",
    request_body = CreateMitigationRequest,
    responses(
        (status = 200, description = "Controller-side checks passed at checked_at; nothing was saved", body = FlowSpecAdmissionPreview),
        (status = 400, description = "Invalid FlowSpec input; blackhole preview is unsupported", body = FlowSpecAdmissionPreview),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Operator role required"),
        (status = 409, description = "Conflicting target or owner", body = FlowSpecAdmissionPreview),
        (status = 422, description = "Guardrail refusal uses the preview response; malformed JSON shape uses the framework rejection body", body = FlowSpecAdmissionPreview),
        (status = 503, description = "Safety-read failures or the five-second read-only deadline use the preview response; standby middleware returns the standard error response", body = FlowSpecAdmissionPreview)
    )
)]
pub async fn preview_manual_flowspec(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Json(req): Json<CreateMitigationRequest>,
) -> Result<Response, StatusCode> {
    let auth_header = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let operator = require_role(&state, &auth_session, auth_header, OperatorRole::Operator)?;
    let mut candidate = None;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    // A read-only snapshot needs no lifecycle mutex: it mutates nothing, and
    // creation rechecks everything under the mutex. Not taking it keeps preview
    // from delaying detector ingest, expiry or withdrawal. Every awaited
    // operation is read-only, so cancellation leaves no uncertain mutation.
    // Keep any prepared candidate outside the future to retain it when a later
    // read stalls.
    let result = tokio::time::timeout_at(deadline, async {
        let prepared = prepare_manual_flowspec(&state, req, &operator.username).await?;
        candidate = Some(prepared.candidate());
        let repo = state
            .repo
            .clone()
            .for_bounded_reads(deadline)
            .map_err(AdmissionFailure::at(FlowSpecAdmissionCheck::Ownership))?;
        validate_manual_flowspec_on(&state, prepared, repo.as_ref())
            .await
            .map(|_| ())
    })
    .await
    .unwrap_or_else(|_| {
        Err(AdmissionFailure {
            check: FlowSpecAdmissionCheck::Timeout,
            error: PrefixdError::Internal("admission preview timed out".into()),
        })
    });
    let (status, outcome, failed_check, reason) = match result {
        Ok(()) => (
            StatusCode::OK,
            FlowSpecAdmissionOutcome::Admissible,
            None,
            None,
        ),
        Err(failure) if failure.error.status_code().is_client_error() => (
            failure.error.status_code(),
            FlowSpecAdmissionOutcome::Refused,
            Some(failure.check),
            Some(failure.error.to_string()),
        ),
        Err(failure) => (
            StatusCode::SERVICE_UNAVAILABLE,
            FlowSpecAdmissionOutcome::Unavailable,
            Some(failure.check),
            Some(if matches!(failure.check, FlowSpecAdmissionCheck::Timeout) {
                "Admission check timed out after five seconds. No intent was saved; retry the check."
            } else {
                "Admission safety checks are unavailable. No intent was saved; retry the check."
            }.into()),
        ),
    };
    Ok((
        status,
        Json(FlowSpecAdmissionPreview {
            outcome,
            checked_at: Utc::now(),
            mode: state.settings.mode.as_str().into(),
            speaker_state: "unobserved".into(),
            candidate,
            failed_check,
            reason,
        }),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::{
        FlowSpecAnnouncer, FlowSpecMatchSupport, FlowSpecReader, FlowSpecWriter, InjectionLeases,
        LeaseGeneration,
    };
    use crate::config::{AuthMode, BgpMode, Inventory, OperationMode, Playbooks, Settings};
    use crate::db::{ListParams, MitigationListParams, MockRepository, RepositoryTrait};
    use crate::domain::{FlowSpecRule, MitigationStatus};
    use axum::body::Body;
    use axum::http::Request;
    use serde_json::{Value, json};
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use tower::ServiceExt;

    struct NoRpcSpeaker {
        support: FlowSpecMatchSupport,
        calls: AtomicUsize,
    }

    impl NoRpcSpeaker {
        fn rpc<T>(&self) -> crate::error::Result<T> {
            self.calls.fetch_add(1, SeqCst);
            Err(PrefixdError::Internal(
                "preview called a speaker RPC".into(),
            ))
        }
    }

    impl FlowSpecAnnouncer for NoRpcSpeaker {
        fn backend(&self) -> &'static str {
            "mock"
        }
        fn match_support(&self) -> FlowSpecMatchSupport {
            self.support
        }
        fn reader(&self) -> Option<&dyn FlowSpecReader> {
            Some(self)
        }
        fn injection_leases(&self) -> Option<&dyn InjectionLeases> {
            Some(self)
        }
    }
    #[async_trait::async_trait]
    impl FlowSpecWriter for NoRpcSpeaker {
        async fn announce(&self, _rule: &FlowSpecRule) -> crate::error::Result<()> {
            self.rpc()
        }
        async fn announce_leased(
            &self,
            _rule: &FlowSpecRule,
            _lease_seconds: u32,
        ) -> crate::error::Result<LeaseGeneration> {
            self.rpc()
        }
        async fn withdraw(&self, _rule: &FlowSpecRule) -> crate::error::Result<()> {
            self.rpc()
        }
    }
    #[async_trait::async_trait]
    impl FlowSpecReader for NoRpcSpeaker {
        async fn list_active(&self) -> crate::error::Result<Vec<FlowSpecRule>> {
            self.rpc()
        }
    }
    #[async_trait::async_trait]
    impl InjectionLeases for NoRpcSpeaker {
        async fn live_lease(
            &self,
            _owner: &str,
        ) -> crate::error::Result<Option<Option<LeaseGeneration>>> {
            self.rpc()
        }
        async fn renew_lease(
            &self,
            _owner: &str,
            _generation: LeaseGeneration,
            _lease_seconds: u32,
        ) -> crate::error::Result<bool> {
            self.rpc()
        }
        fn lease_confirmed(&self) -> bool {
            false
        }
    }

    struct Fixture {
        state: Arc<AppState>,
        repo: Arc<MockRepository>,
        speaker: Arc<NoRpcSpeaker>,
        seeded_safelist: AtomicUsize,
        seeded_operators: AtomicUsize,
    }

    impl Fixture {
        fn settings() -> Settings {
            let mut settings: Settings =
                crate::config::parse_yaml(include_str!("../../../configs/prefixd.yaml")).unwrap();
            settings.http.auth.mode = AuthMode::None;
            settings.bgp.mode = BgpMode::Mock;
            settings.mode = OperationMode::DryRun;
            settings.guardrails.dst_prefix_minlen = 22;
            settings.guardrails.dst_prefix_minlen_v6 = Some(48);
            settings.guardrails.allow_src_prefix_match = true;
            settings.guardrails.allow_fragment_match = true;
            settings.guardrails.allow_packet_length_match = true;
            settings.quotas.max_active_per_customer = 20;
            settings.quotas.max_active_per_pop = 50;
            settings.quotas.max_active_global = 100;
            settings.quotas.max_new_per_minute = 100;
            settings
        }
        fn new(settings: Settings, support: FlowSpecMatchSupport) -> Self {
            let inventory: Inventory = serde_json::from_value(json!({"customers": [{
                "customer_id": "allocation", "name": "Allocation", "prefixes": ["203.0.112.0/22", "2001:db8::/32"]
            }]})).unwrap();
            let repo = Arc::new(MockRepository::new());
            let speaker = Arc::new(NoRpcSpeaker {
                support,
                calls: AtomicUsize::new(0),
            });
            let state = AppState::new(
                settings,
                inventory,
                Playbooks { playbooks: vec![] },
                repo.clone(),
                speaker.clone(),
                ".".into(),
            )
            .unwrap();
            Self {
                state,
                repo,
                speaker,
                seeded_safelist: AtomicUsize::new(0),
                seeded_operators: AtomicUsize::new(0),
            }
        }
        async fn post(&self, path: &str, body: &Value) -> (StatusCode, Value) {
            self.post_with_auth(path, body, None).await
        }
        async fn post_with_auth(
            &self,
            path: &str,
            body: &Value,
            auth: Option<(&str, &str)>,
        ) -> (StatusCode, Value) {
            let mut request = Request::post(path).header("content-type", "application/json");
            if let Some((name, value)) = auth {
                request = request.header(name, value);
            }
            let response = crate::api::create_test_router(self.state.clone())
                .oneshot(request.body(Body::from(body.to_string())).unwrap())
                .await
                .unwrap();
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            (
                status,
                serde_json::from_slice(&bytes)
                    .unwrap_or_else(|_| json!({"raw": String::from_utf8_lossy(&bytes)})),
            )
        }
        async fn seed_safelist(&self, source: &str) {
            self.repo
                .insert_safelist("203.0.113.10/32", source, None)
                .await
                .unwrap();
            self.seeded_safelist.fetch_add(1, SeqCst);
        }
        async fn assert_no_mutations(&self) {
            let mitigations = self
                .repo
                .list_mitigations(
                    None,
                    None,
                    None,
                    None,
                    &MitigationListParams {
                        limit: u32::MAX,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert!(mitigations.is_empty(), "mitigations: {}", mitigations.len());
            assert!(self.repo.list_audit(&all()).await.unwrap().is_empty());
            assert!(self.repo.list_events(&all()).await.unwrap().is_empty());
            assert!(
                self.repo
                    .pending_withdrawals(None)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                self.repo.list_safelist().await.unwrap().len(),
                self.seeded_safelist.load(SeqCst)
            );
            assert_eq!(
                self.repo.list_operators().await.unwrap().len(),
                self.seeded_operators.load(SeqCst)
            );
            assert!(
                self.repo
                    .list_signal_groups(&Default::default(), &all())
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(self.speaker.calls.load(SeqCst), 0);
        }
    }

    /// Mock listings `take(limit)`; the default limit of zero would list nothing.
    fn all() -> ListParams {
        ListParams {
            limit: u32::MAX,
            ..Default::default()
        }
    }

    /// Negative control: the helper must detect a real creation's writes.
    #[tokio::test]
    #[should_panic(expected = "mitigations: 1")]
    async fn no_mutation_check_detects_real_creation() {
        // The creation increments `MITIGATIONS_CREATED`.
        let _metrics = crate::observability::metrics::METRICS_TEST_LOCK
            .lock()
            .await;
        let fixture = Fixture::new(Fixture::settings(), FlowSpecMatchSupport::ALL);
        let (status, created) = fixture
            .post("/v1/mitigations", &request("203.0.113.10"))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        fixture.assert_no_mutations().await;
    }

    fn request(target: &str) -> Value {
        json!({"victim_ip": target, "protocol": "udp", "dst_ports": [443], "action": "discard", "ttl_seconds": 300, "reason": "operator preview"})
    }

    #[tokio::test]
    async fn preview_skips_the_lifecycle_mutex_and_bounds_preparation() {
        let fixture = Fixture::new(Fixture::settings(), FlowSpecMatchSupport::ALL);
        // A held lifecycle mutex (ingest, expiry, withdrawal) does not delay preview.
        let held = fixture.state.mitigation_lock.lock().await;
        let (status, result) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            fixture.post("/v1/mitigations/preview", &request("203.0.113.10")),
        )
        .await
        .expect("preview must not wait for the lifecycle mutex");
        assert_eq!(status, StatusCode::OK, "{result}");
        drop(held);
        fixture.assert_no_mutations().await;

        // A stalled preparation still ends at the five-second deadline.
        let inventory = fixture.state.inventory.write().await;
        let (status, result) = tokio::time::timeout(
            std::time::Duration::from_secs(7),
            fixture.post("/v1/mitigations/preview", &request("203.0.113.10")),
        )
        .await
        .expect("preview must time out while inventory preparation is blocked");
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(result["outcome"], "unavailable");
        assert_eq!(result["failed_check"], "timeout");
        assert!(result["candidate"].is_null());
        assert!(result["reason"].as_str().unwrap().contains("timed out"));
        fixture.assert_no_mutations().await;
        drop(inventory);
        let (status, _) = fixture
            .post("/v1/mitigations/preview", &request("203.0.113.10"))
            .await;
        assert_eq!(status, StatusCode::OK);
        fixture.assert_no_mutations().await;
    }

    #[tokio::test]
    async fn preview_and_creation_share_exact_host_cidr_source_and_extended_matches() {
        let _metrics = crate::observability::metrics::METRICS_TEST_LOCK
            .lock()
            .await;
        for mut body in [
            request("203.0.113.10"),
            request("203.0.112.0/22"),
            request("2001:db8:1234::/48"),
            request("2001:0DB8::10"),
            request("203.0.112.0/22"),
        ]
        .into_iter()
        .enumerate()
        {
            let (index, body) = &mut body;
            match index {
                0 => {
                    body["src_prefix"] = json!("198.51.100.9/24");
                    body["src_ports"] = json!([389, 123, 389]);
                    body["packet_length"] = json!({"min": 1000, "max": 1200});
                }
                1 => {
                    body["src_prefix"] = json!("198.51.100.9/24");
                    body["protocol"] = json!("tcp");
                }
                2 => {
                    body["src_prefix"] = json!("2001:db8:ffff::9/64");
                    body["src_ports"] = json!([53]);
                    body["packet_length"] = json!({"min": 1000, "max": 1200});
                    body["action"] = json!("police");
                    body["rate_bps"] = json!(8_000_000);
                }
                3 => {
                    body["protocol"] = json!("icmpv6");
                    body["dst_ports"] = json!([]);
                }
                4 => {
                    body["fragment"] = json!("non_first");
                    body["dst_ports"] = json!([]);
                }
                _ => unreachable!(),
            }
            let fixture = Fixture::new(Fixture::settings(), FlowSpecMatchSupport::ALL);
            let (status, preview) = fixture.post("/v1/mitigations/preview", body).await;
            assert_eq!(status, StatusCode::OK, "{preview}");
            assert_eq!(preview["outcome"], "admissible");
            assert_eq!(preview["speaker_state"], "unobserved");
            assert_eq!(preview["mode"], "dry-run");
            fixture.assert_no_mutations().await;
            let (status, created) = fixture.post("/v1/mitigations", body).await;
            assert_eq!(status, StatusCode::CREATED, "{created}");
            for key in [
                "dst_prefix",
                "src_prefix",
                "protocol",
                "dst_ports",
                "src_ports",
                "fragment",
                "packet_length",
            ] {
                // Empty optional components serialize differently in the two existing models.
                if preview["candidate"]["scope"].get(key).is_some() {
                    let actual = if key == "dst_prefix" {
                        json!(
                            created[key]
                                .as_str()
                                .unwrap()
                                .parse::<ipnet::IpNet>()
                                .unwrap()
                                .to_string()
                        )
                    } else {
                        created[key].clone()
                    };
                    assert_eq!(
                        preview["candidate"]["scope"][key], actual,
                        "{key}: {preview} {created}"
                    );
                }
            }
            assert_eq!(preview["candidate"]["customer_id"], created["customer_id"]);
            assert_eq!(
                preview["candidate"]["action"]["action_type"],
                created["action_type"]
            );
            assert_eq!(
                preview["candidate"]["action"]["rate_bps"],
                created["rate_bps"]
            );
            assert_eq!(fixture.speaker.calls.load(SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn preview_refusals_preserve_candidates_and_never_mutate() {
        for (kind, expected_status, check) in [
            ("prefix", StatusCode::UNPROCESSABLE_ENTITY, "guardrails"),
            ("safelist", StatusCode::UNPROCESSABLE_ENTITY, "guardrails"),
            ("ttl", StatusCode::UNPROCESSABLE_ENTITY, "guardrails"),
            ("quota", StatusCode::UNPROCESSABLE_ENTITY, "guardrails"),
            ("rate", StatusCode::UNPROCESSABLE_ENTITY, "creation_rate"),
            ("capability", StatusCode::BAD_REQUEST, "capability"),
            ("cap", StatusCode::UNPROCESSABLE_ENTITY, "lifetime"),
        ] {
            let mut settings = Fixture::settings();
            let mut body = request("203.0.112.0/22");
            let mut support = FlowSpecMatchSupport::ALL;
            match kind {
                "prefix" => settings.guardrails.dst_prefix_minlen = 32,
                "ttl" => body["ttl_seconds"] = json!(1),
                "quota" => settings.quotas.max_active_per_customer = 0,
                "rate" => settings.quotas.max_new_per_minute = 0,
                "capability" => {
                    support.source_prefix = false;
                    body["src_prefix"] = json!("198.51.100.9/24");
                }
                "cap" => {
                    body["expires_at_cap"] =
                        json!((Utc::now() + chrono::Duration::seconds(1)).to_rfc3339())
                }
                _ => {}
            }
            let fixture = Fixture::new(settings, support);
            if kind == "safelist" {
                fixture.seed_safelist("config").await;
            }
            let (status, preview) = fixture.post("/v1/mitigations/preview", &body).await;
            assert_eq!(status, expected_status, "{kind}: {preview}");
            assert_eq!(preview["outcome"], "refused");
            assert_eq!(preview["failed_check"], check);
            assert_eq!(
                preview["candidate"]["scope"]["dst_prefix"],
                "203.0.112.0/22"
            );
            assert_eq!(preview["candidate"]["scope"]["dst_ports"], json!([443]));
            fixture.assert_no_mutations().await;
        }
    }

    #[tokio::test]
    async fn unavailable_safety_reads_are_sanitized_and_never_safe() {
        for failure in ["owner", "safelist", "quota", "rate"] {
            let fixture = Fixture::new(Fixture::settings(), FlowSpecMatchSupport::ALL);
            match failure {
                "owner" => fixture.repo.fail_active_reads.store(true, SeqCst),
                "safelist" => fixture.repo.fail_safelist.store(true, SeqCst),
                "quota" => fixture.repo.fail_quota_reads.store(true, SeqCst),
                "rate" => fixture.repo.fail_creation_rate_reads.store(true, SeqCst),
                _ => unreachable!(),
            }
            let (status, preview) = fixture
                .post("/v1/mitigations/preview", &request("203.0.112.0/22"))
                .await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{preview}");
            assert_eq!(preview["outcome"], "unavailable");
            assert_eq!(
                preview["candidate"]["scope"]["dst_prefix"],
                "203.0.112.0/22"
            );
            assert!(!preview.to_string().contains("sensitive"));
            assert!(!preview.to_string().contains("diagnostic"));
            fixture.repo.fail_active_reads.store(false, SeqCst);
            fixture.assert_no_mutations().await;
        }
    }

    #[tokio::test]
    async fn successful_preview_does_not_reserve_or_bypass_fresh_creation_safety() {
        let _metrics = crate::observability::metrics::METRICS_TEST_LOCK
            .lock()
            .await;
        for change in ["safelist", "owner", "quota"] {
            let mut settings = Fixture::settings();
            settings.quotas.max_active_per_customer = 1;
            let fixture = Fixture::new(settings, FlowSpecMatchSupport::ALL);
            let body = request("203.0.112.0/22");
            let (status, _) = fixture.post("/v1/mitigations/preview", &body).await;
            assert_eq!(status, StatusCode::OK);
            fixture.assert_no_mutations().await;
            if change == "safelist" {
                fixture.seed_safelist("operator").await;
            } else {
                let target = if change == "owner" {
                    "203.0.112.0/22"
                } else {
                    "203.0.113.20"
                };
                let prepared = prepare_manual_flowspec(
                    &fixture.state,
                    serde_json::from_value(request(target)).unwrap(),
                    "test",
                )
                .await
                .ok()
                .unwrap();
                let mut mitigation = validate_manual_flowspec(&fixture.state, prepared)
                    .await
                    .ok()
                    .unwrap();
                mitigation.activate();
                fixture.repo.insert_mitigation(&mitigation).await.unwrap();
            }
            let (status, _) = fixture.post("/v1/mitigations", &body).await;
            assert_eq!(
                status,
                if change == "owner" {
                    StatusCode::CONFLICT
                } else {
                    StatusCode::UNPROCESSABLE_ENTITY
                }
            );
            assert_eq!(fixture.speaker.calls.load(SeqCst), 0);
            assert!(fixture.repo.list_audit(&all()).await.unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn preview_uses_all_recent_row_kinds_and_statuses_for_creation_rate() {
        let fixture = Fixture::new(Fixture::settings(), FlowSpecMatchSupport::ALL);
        let prepared = prepare_manual_flowspec(
            &fixture.state,
            serde_json::from_value(request("203.0.113.20")).unwrap(),
            "test",
        )
        .await
        .ok()
        .unwrap();
        let mut historical = validate_manual_flowspec(&fixture.state, prepared)
            .await
            .ok()
            .unwrap();
        historical.action_type = ActionType::Blackhole;
        historical.status = MitigationStatus::Withdrawn;
        fixture.repo.insert_mitigation(&historical).await.unwrap();
        assert!(
            fixture
                .repo
                .check_new_mitigation_rate(&fixture.state.settings.pop, 1)
                .await
                .is_err()
        );
        historical.created_at = Utc::now() - chrono::Duration::seconds(61);
        fixture.repo.update_mitigation(&historical).await.unwrap();
        fixture
            .repo
            .check_new_mitigation_rate(&fixture.state.settings.pop, 1)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn preview_refuses_pending_withdrawals_even_without_an_active_row() {
        let fixture = Fixture::new(Fixture::settings(), FlowSpecMatchSupport::ALL);
        let body = request("203.0.112.0/22");
        let prepared = prepare_manual_flowspec(
            &fixture.state,
            serde_json::from_value(body.clone()).unwrap(),
            "operator",
        )
        .await
        .ok()
        .unwrap();
        let mut mitigation = validate_manual_flowspec(&fixture.state, prepared)
            .await
            .ok()
            .unwrap();
        mitigation.activate();
        fixture.repo.insert_mitigation(&mitigation).await.unwrap();
        crate::domain::request_withdrawal(
            fixture.repo.as_ref(),
            &mitigation,
            false,
            "operator",
            "test",
            "cleanup".into(),
            false,
            None,
        )
        .await
        .unwrap();
        mitigation.status = MitigationStatus::Withdrawn;
        fixture.repo.update_mitigation(&mitigation).await.unwrap();
        let (status, preview) = fixture.post("/v1/mitigations/preview", &body).await;
        assert_eq!(status, StatusCode::CONFLICT, "{preview}");
        assert_eq!(preview["failed_check"], "ownership");
        assert!(
            preview["reason"]
                .as_str()
                .unwrap()
                .contains("pending withdrawal")
        );
        assert_eq!(
            fixture.repo.pending_withdrawals(None).await.unwrap().len(),
            1
        );
        assert!(fixture.repo.list_audit(&all()).await.unwrap().is_empty());
        assert_eq!(fixture.speaker.calls.load(SeqCst), 0);
    }

    #[tokio::test]
    async fn standby_preview_keeps_the_existing_active_controller_boundary() {
        let mut fixture = Fixture::new(Fixture::settings(), FlowSpecMatchSupport::ALL);
        Arc::get_mut(&mut fixture.state).unwrap().fence =
            Arc::new(crate::fence::ControllerFence::new(false));
        let (status, response) = fixture
            .post("/v1/mitigations/preview", &request("203.0.112.0/22"))
            .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(response["error"].as_str().unwrap().contains("standby"));
        assert!(response.get("outcome").is_none());
        fixture.assert_no_mutations().await;
    }

    #[tokio::test]
    async fn preview_invalid_input_and_blackholes_are_refused_without_writes() {
        for target in [
            "203.0.113.10/22",
            "2001:db8::1/48",
            "192.0.2.0/24",
            "bad",
            "203.0.112.0/33",
        ] {
            let fixture = Fixture::new(Fixture::settings(), FlowSpecMatchSupport::ALL);
            let (status, preview) = fixture
                .post("/v1/mitigations/preview", &request(target))
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{target}: {preview}");
            assert_eq!(preview["outcome"], "refused");
            fixture.assert_no_mutations().await;
        }
        let fixture = Fixture::new(Fixture::settings(), FlowSpecMatchSupport::ALL);
        let mut blackhole = request("203.0.113.10");
        blackhole["action"] = json!("blackhole");
        let (status, _) = fixture.post("/v1/mitigations/preview", &blackhole).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        fixture.assert_no_mutations().await;
    }

    #[tokio::test]
    async fn viewer_sessions_cannot_preview() {
        use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
        let mut settings = Fixture::settings();
        settings.http.auth.mode = AuthMode::Credentials;
        let fixture = Fixture::new(settings, FlowSpecMatchSupport::ALL);
        let hash = Argon2::default()
            .hash_password(
                b"preview-viewer-password",
                &SaltString::encode_b64(b"preview-viewer").unwrap(),
            )
            .unwrap()
            .to_string();
        fixture
            .repo
            .create_operator("preview-viewer", &hash, OperatorRole::Viewer, None)
            .await
            .unwrap();
        fixture.seeded_operators.fetch_add(1, SeqCst);
        let app = crate::api::create_test_router(fixture.state.clone());
        let login = app
            .clone()
            .oneshot(
                Request::post("/v1/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"username": "preview-viewer", "password": "preview-viewer-password"})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::OK);
        let cookie = login.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        // The session store belongs to this router, so reuse it.
        let response = app
            .oneshot(
                Request::post("/v1/mitigations/preview")
                    .header("content-type", "application/json")
                    .header("cookie", cookie)
                    .body(Body::from(request("203.0.112.0/22").to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("outcome"));
        fixture.assert_no_mutations().await;
    }

    #[tokio::test]
    async fn preview_requires_authentication_and_does_not_update_operational_metrics() {
        let _metrics = crate::observability::metrics::METRICS_TEST_LOCK
            .lock()
            .await;
        let mut settings = Fixture::settings();
        settings.http.auth.mode = AuthMode::None;
        let mut fixture = Fixture::new(settings, FlowSpecMatchSupport::ALL);
        let state = Arc::get_mut(&mut fixture.state).unwrap();
        state.settings.http.auth.mode = AuthMode::Bearer;
        state.bearer_token = Some("preview-test-token".into());
        let (status, _) = fixture
            .post("/v1/mitigations/preview", &request("203.0.112.0/22"))
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        fixture.assert_no_mutations().await;
        let (status, _) = fixture
            .post_with_auth(
                "/v1/mitigations/preview",
                &request("203.0.112.0/22"),
                Some(("authorization", "Bearer preview-test-token")),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        fixture.assert_no_mutations().await;
        let mut settings = Fixture::settings();
        settings.mode = OperationMode::Enforced;
        let fixture = Fixture::new(settings, FlowSpecMatchSupport::ALL);
        let created = crate::observability::metrics::MITIGATIONS_CREATED
            .with_label_values(&["discard", &fixture.state.settings.pop]);
        let refused =
            crate::observability::metrics::GUARDRAIL_REJECTIONS.with_label_values(&["Safelisted"]);
        let before = (created.get(), refused.get());
        let (status, preview) = fixture
            .post("/v1/mitigations/preview", &request("203.0.112.0/22"))
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(preview["mode"], "enforced");
        fixture.seed_safelist("config").await;
        let (status, _) = fixture
            .post("/v1/mitigations/preview", &request("203.0.112.0/22"))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!((created.get(), refused.get()), before);
        fixture.assert_no_mutations().await;
    }

    #[tokio::test]
    async fn creation_preserves_guardrail_counter_stages_while_preview_counts_nothing() {
        let _metrics = crate::observability::metrics::METRICS_TEST_LOCK
            .lock()
            .await;
        let labels = ["unknown", "TtlOutOfBounds", "NewMitigationRateExceeded"];
        let values = || {
            labels.map(|label| {
                crate::observability::metrics::GUARDRAIL_REJECTIONS
                    .with_label_values(&[label])
                    .get()
            })
        };
        for (failure, expected_label) in [
            ("guardrail_read", Some("unknown")),
            ("ttl", Some("TtlOutOfBounds")),
            ("cap", Some("TtlOutOfBounds")),
            ("rate", Some("NewMitigationRateExceeded")),
            ("rate_read", None),
            ("capability", None),
            ("input", None),
        ] {
            let mut settings = Fixture::settings();
            if failure == "rate" {
                settings.quotas.max_new_per_minute = 0;
            }
            let mut support = FlowSpecMatchSupport::ALL;
            if failure == "capability" {
                support.source_prefix = false;
            }
            let fixture = Fixture::new(settings, support);
            let mut body = request("203.0.112.0/22");
            match failure {
                "guardrail_read" => fixture.repo.fail_quota_reads.store(true, SeqCst),
                "rate_read" => fixture.repo.fail_creation_rate_reads.store(true, SeqCst),
                "ttl" => body["ttl_seconds"] = json!(1),
                "cap" => {
                    body["expires_at_cap"] =
                        json!((Utc::now() + chrono::Duration::seconds(1)).to_rfc3339())
                }
                "capability" => body["src_prefix"] = json!("198.51.100.0/24"),
                "input" => body["victim_ip"] = json!("bad"),
                _ => {}
            }
            let before = values();
            let (status, _) = fixture.post("/v1/mitigations/preview", &body).await;
            assert!(
                status.is_client_error() || status.is_server_error(),
                "{failure}"
            );
            assert_eq!(values(), before, "preview changed counters: {failure}");
            let (status, _) = fixture.post("/v1/mitigations", &body).await;
            assert!(
                status.is_client_error() || status.is_server_error(),
                "{failure}"
            );
            for (index, label) in labels.iter().enumerate() {
                assert_eq!(
                    values()[index],
                    before[index] + f64::from(u8::from(Some(*label) == expected_label)),
                    "creation {failure}: {label}"
                );
            }
            fixture.assert_no_mutations().await;
        }
    }

    #[derive(Clone, Default)]
    struct LogCapture(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for LogCapture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn rate_refused_creation_logs_the_admission_rejection_once() {
        // The refusal increments `GUARDRAIL_REJECTIONS{NewMitigationRateExceeded}`.
        let _metrics = crate::observability::metrics::METRICS_TEST_LOCK
            .lock()
            .await;
        let mut settings = Fixture::settings();
        settings.quotas.max_new_per_minute = 0;
        let fixture = Fixture::new(settings, FlowSpecMatchSupport::ALL);
        let capture = LogCapture::default();
        let writer = capture.clone();
        let _subscriber = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .json()
                .without_time()
                .with_writer(move || writer.clone())
                .finish(),
        );
        let (status, _) = fixture
            .post("/v1/mitigations/preview", &request("203.0.112.0/22"))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            !String::from_utf8_lossy(&capture.0.lock().unwrap()).contains("admission rejected"),
            "preview must not log a mutation refusal"
        );
        let (status, _) = fixture
            .post("/v1/mitigations", &request("203.0.112.0/22"))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let output = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        let events: Vec<Value> = output
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .filter(|event: &Value| {
                event["fields"]["message"] == "admission rejected new mitigation"
            })
            .collect();
        assert_eq!(events.len(), 1, "{output}");
        assert_eq!(events[0]["level"], "WARN");
        assert_eq!(events[0]["fields"]["pop"], fixture.state.settings.pop);
        assert_eq!(events[0]["fields"]["reason"], "NewMitigationRateExceeded");
        assert!(events[0]["fields"]["error"].is_string());
        fixture.assert_no_mutations().await;
    }
}
