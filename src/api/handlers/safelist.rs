use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;
use crate::api::auth::{require_auth, require_role};
use crate::auth::AuthSession;
use crate::error::PrefixdError;

use super::{MAX_STRING_LEN, MAX_USERNAME_LEN, validate_string_len};

fn validate_cidr(prefix: &str) -> Result<ipnet::IpNet, PrefixdError> {
    prefix
        .parse::<ipnet::IpNet>()
        .or_else(|_| prefix.parse::<IpAddr>().map(ipnet::IpNet::from))
        .map_err(|_| PrefixdError::InvalidRequest(format!("invalid prefix: '{}'", prefix)))
}

#[derive(Deserialize, ToSchema)]
pub struct AddSafelistRequest {
    #[serde(default)]
    #[allow(
        dead_code,
        reason = "Caller-supplied actor is ignored; request authentication determines the actor"
    )]
    operator_id: String,
    prefix: String,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct AddSafelistResponse {
    /// Live blackholes and non-host FlowSpec rules on this POP overlapping the
    /// entry that this request withdrew with `safelisted after admission`.
    withdrawn_mitigation_ids: Vec<Uuid>,
    /// Present when overlapping mitigations could not be found or withdrawn. The
    /// entry is stored either way; reconciliation retries enforced routes.
    #[serde(skip_serializing_if = "Option::is_none")]
    withdrawal_error: Option<String>,
}

/// Caller holds the lifecycle mutex and has stored the entry. Withdraws every
/// live blackhole or non-host FlowSpec rule on this POP overlapping `prefix`;
/// host FlowSpec admission policy is unchanged. A failed lookup withdraws nothing.
async fn withdraw_covered_mitigations(
    state: &AppState,
    prefix: ipnet::IpNet,
) -> AddSafelistResponse {
    let mut response = AddSafelistResponse {
        withdrawn_mitigation_ids: Vec::new(),
        withdrawal_error: None,
    };
    let found = async {
        let binding = state.verified_speaker_binding()?;
        let pending = state
            .repo
            .pending_withdrawals(Some(&state.settings.pop))
            .await?;
        let now = chrono::Utc::now();
        let covered = state
            .repo
            .active_mitigation_inventory(Some(&state.settings.pop))
            .await?
            .into_iter()
            .filter(|mitigation| {
                mitigation.pop == state.settings.pop
                    && mitigation.is_active()
                    && mitigation.expires_at > now
                    && !pending
                        .iter()
                        .any(|request| request.mitigation_id == mitigation.mitigation_id)
                    && mitigation
                        .match_criteria
                        .dst_prefix
                        .parse::<ipnet::IpNet>()
                        .is_ok_and(|destination| {
                            (mitigation.action_type == crate::domain::ActionType::Blackhole
                                || destination.prefix_len() < destination.max_prefix_len())
                                && (prefix.contains(&destination) || destination.contains(&prefix))
                        })
            })
            .collect::<Vec<_>>();
        Ok::<_, PrefixdError>((binding, covered))
    }
    .await;
    let (binding, covered) = match found {
        Ok(found) => found,
        Err(error) => {
            tracing::error!(target: "prefixd::api::handlers", %prefix, error = %error,
                "overlapping mitigation lookup failed after safelist add; nothing withdrawn");
            response.withdrawal_error =
                Some("overlapping mitigation lookup failed; nothing was withdrawn".into());
            return response;
        }
    };
    for mitigation in covered {
        match crate::domain::withdraw_safelisted(
            state.repo.as_ref(),
            state.announcer.as_ref(),
            state.is_dry_run(),
            &mitigation,
            binding,
        )
        .await
        {
            Ok(withdrawn) => {
                let _ = state
                    .ws_broadcast
                    .send(crate::ws::WsMessage::MitigationWithdrawn {
                        mitigation_id: withdrawn.mitigation_id.to_string(),
                    });
                state
                    .alerting
                    .read()
                    .await
                    .notify(crate::alerting::Alert::mitigation_withdrawn(&withdrawn));
                response
                    .withdrawn_mitigation_ids
                    .push(withdrawn.mitigation_id);
            }
            Err(error) => {
                tracing::error!(target: "prefixd::api::handlers", %prefix,
                    mitigation_id = %mitigation.mitigation_id, error = %error,
                    "failed to withdraw safelisted mitigation");
                response.withdrawal_error = Some(
                    "an overlapping mitigation was not withdrawn; reconciliation retries it".into(),
                );
            }
        }
    }
    response
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

/// Add a prefix to the safelist (admin only)
#[utoipa::path(
    post,
    path = "/v1/safelist",
    tag = "safelist",
    request_body = AddSafelistRequest,
    responses(
        (status = 201, description = "Safelist entry created; lists overlapping mitigations withdrawn", body = AddSafelistResponse),
        (status = 400, description = "Invalid prefix"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions")
    )
)]
pub async fn add_safelist(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Json(req): Json<AddSafelistRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    use crate::domain::OperatorRole;
    let operator = require_role(&state, &auth_session, auth_header, OperatorRole::Admin)?;
    let operator_id = operator.username;

    let prefix = validate_cidr(&req.prefix).map_err(|_| StatusCode::BAD_REQUEST)?;
    validate_string_len(&operator_id, "operator_id", MAX_USERNAME_LEN)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if let Some(ref reason) = req.reason {
        validate_string_len(reason, "reason", MAX_STRING_LEN)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
    }

    let _mitigation_guard = state.mitigation_lock.lock().await;
    state
        .repo
        .insert_safelist(&req.prefix, &operator_id, req.reason.as_deref())
        .await
        .map_err(|e| {
            tracing::error!(target: "prefixd::api::handlers", error = %e, "add_safelist failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::info!(target: "prefixd::api::handlers", prefix = %req.prefix, operator = %operator_id, "safelist entry added");
    let response = withdraw_covered_mitigations(&state, prefix).await;
    Ok((StatusCode::CREATED, Json(response)))
}

/// Remove a prefix from the safelist (admin only)
#[utoipa::path(
    delete,
    path = "/v1/safelist/{prefix}",
    tag = "safelist",
    params(
        ("prefix" = String, Path, description = "CIDR prefix to remove")
    ),
    responses(
        (status = 204, description = "Safelist entry removed"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Prefix not in safelist")
    )
)]
pub async fn remove_safelist(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Path(prefix): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    use crate::domain::OperatorRole;
    let _operator = require_role(&state, &auth_session, auth_header, OperatorRole::Admin)?;

    let removed = state.repo.remove_safelist(&prefix).await.map_err(|e| {
        tracing::error!(target: "prefixd::api::handlers", error = %e, "remove_safelist failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if removed {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::Ordering::SeqCst;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use crate::AppState;
    use crate::bgp::{
        BlackholeRoute, BlackholeSpeaker, FaultyBlackholes, FlowSpecReader, FlowSpecWriter,
    };
    use crate::config::{BlackholeConfig, OperationMode};
    use crate::db::{MockRepository, RepositoryTrait};
    use crate::domain::{
        ActionParams, ActionType, AttackVector, BlackholeRule, MatchCriteria, Mitigation,
        MitigationIntent, MitigationStatus, SAFELISTED_AFTER_ADMISSION,
    };

    struct Fixture {
        repo: Arc<MockRepository>,
        speaker: Arc<FaultyBlackholes>,
        state: Arc<AppState>,
    }

    fn config() -> BlackholeConfig {
        BlackholeConfig {
            enabled: true,
            next_hop_ipv4: Some("192.0.2.66".parse().unwrap()),
            communities: vec!["64512:1".into()],
            ..Default::default()
        }
    }

    fn fixture(mode: OperationMode) -> Fixture {
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(FaultyBlackholes::default());
        let mut settings: crate::config::Settings =
            crate::config::parse_yaml(include_str!("../../../configs/prefixd.yaml")).unwrap();
        settings.pop = "test".into();
        settings.bgp.mode = crate::config::BgpMode::Mock;
        settings.http.auth.mode = crate::config::AuthMode::None;
        settings.mode = mode;
        settings.blackhole = config();
        let state = AppState::new(
            settings,
            crate::config::Inventory::new(vec![]),
            crate::config::Playbooks { playbooks: vec![] },
            repo.clone(),
            speaker.clone(),
            ".".into(),
        )
        .unwrap();
        Fixture {
            repo,
            speaker,
            state,
        }
    }

    /// Live blackhole intent at `pop`, created in `origin` mode.
    fn blackhole(ip: &str, pop: &str, origin: OperationMode) -> Mitigation {
        let prefix = ipnet::IpNet::from(ip.parse::<std::net::IpAddr>().unwrap());
        let mut mitigation = Mitigation::from_intent(
            MitigationIntent {
                event_id: uuid::Uuid::new_v4(),
                customer_id: None,
                service_id: None,
                pop: pop.into(),
                match_criteria: MatchCriteria {
                    dst_prefix: prefix.to_string(),
                    ..Default::default()
                },
                action_type: ActionType::Blackhole,
                action_params: ActionParams {
                    blackhole: Some(BlackholeRule::from_config(&config(), prefix).unwrap()),
                    ..Default::default()
                },
                ttl_seconds: 600,
                reason: "test".into(),
            },
            ip.into(),
            AttackVector::Unknown,
        );
        mitigation.activate();
        mitigation.origin_mode = Some(origin);
        mitigation
    }

    fn route(mitigation: &Mitigation) -> BlackholeRoute {
        crate::domain::blackhole_rule(mitigation)
            .unwrap()
            .route()
            .unwrap()
    }

    fn flowspec(prefix: &str, pop: &str, origin: OperationMode) -> Mitigation {
        let mut mitigation = Mitigation::from_intent(
            MitigationIntent {
                event_id: uuid::Uuid::new_v4(),
                customer_id: Some("prefix-owner".into()),
                service_id: None,
                pop: pop.into(),
                match_criteria: MatchCriteria {
                    dst_prefix: prefix.into(),
                    protocol: Some(17),
                    dst_ports: vec![53],
                    ..Default::default()
                },
                action_type: ActionType::Discard,
                action_params: ActionParams::default(),
                ttl_seconds: 600,
                reason: "test".into(),
            },
            prefix.into(),
            AttackVector::UdpFlood,
        );
        mitigation.activate();
        mitigation.origin_mode = Some(origin);
        mitigation
    }

    impl Fixture {
        /// Persist `mitigation`; an enforced row's route is also on the speaker.
        async fn live(&self, mitigation: &Mitigation) {
            self.repo.insert_mitigation(mitigation).await.unwrap();
            if !mitigation.is_dry_run_origin() && mitigation.pop == "test" {
                if mitigation.action_type == ActionType::Blackhole {
                    self.speaker
                        .inner
                        .announce_blackhole(&route(mitigation))
                        .await
                        .unwrap();
                } else {
                    self.speaker
                        .inner
                        .announce(&crate::domain::mitigation_rule(mitigation).unwrap())
                        .await
                        .unwrap();
                }
            }
        }

        async fn safelist(&self, prefix: &str) -> (StatusCode, serde_json::Value) {
            let response = crate::api::create_test_router(self.state.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/safelist")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::json!({"prefix": prefix, "reason": "resolver"}).to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            (
                status,
                serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
            )
        }

        async fn status(&self, mitigation: &Mitigation) -> MitigationStatus {
            self.repo
                .get_mitigation(mitigation.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .status
        }

        async fn audit(&self, mitigation: &Mitigation) -> crate::observability::AuditEntry {
            self.repo
                .list_audit(&crate::db::ListParams {
                    limit: 100,
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_iter()
                .find(|entry| {
                    entry.action == "withdraw"
                        && entry.target_id.as_deref() == Some(&mitigation.mitigation_id.to_string())
                })
                .unwrap()
        }
    }

    fn ids(body: &serde_json::Value) -> Vec<String> {
        let mut ids: Vec<String> = body["withdrawn_mitigation_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| id.as_str().unwrap().to_string())
            .collect();
        ids.sort();
        ids
    }

    #[tokio::test]
    async fn safelisting_a_host_withdraws_its_live_blackhole() {
        let fx = fixture(OperationMode::Enforced);
        let victim = blackhole("203.0.113.10", "test", OperationMode::Enforced);
        fx.live(&victim).await;
        let (status, body) = fx.safelist("203.0.113.10/32").await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(ids(&body), [victim.mitigation_id.to_string()]);
        assert!(body.get("withdrawal_error").is_none());
        assert_eq!(fx.status(&victim).await, MitigationStatus::Withdrawn);
        assert_eq!(fx.speaker.deletes.load(SeqCst), 1);
        assert!(fx.speaker.routes().await.is_empty());
        // Audited as a system withdrawal with its reason and operation ID.
        let entry = fx.audit(&victim).await;
        assert!(matches!(
            entry.actor_type,
            crate::observability::ActorType::System
        ));
        assert_eq!(entry.details["reason"], SAFELISTED_AFTER_ADMISSION);
        assert!(entry.details["operation_id"].is_string());
    }

    #[tokio::test]
    async fn safelisting_inside_a_destination_prefix_withdraws_the_whole_rule() {
        for (destination, protected, outside) in [
            ("203.0.112.0/22", "203.0.113.10/32", "203.0.116.0/22"),
            ("2001:db8::/64", "2001:db8::abcd/128", "2001:db8:0:1::/64"),
        ] {
            let fx = fixture(OperationMode::Enforced);
            let affected = flowspec(destination, "test", OperationMode::Enforced);
            let unaffected = flowspec(outside, "test", OperationMode::Enforced);
            let foreign = flowspec(destination, "other-pop", OperationMode::Enforced);
            let host = flowspec(protected, "test", OperationMode::Enforced);
            for mitigation in [&affected, &unaffected, &foreign, &host] {
                fx.live(mitigation).await;
            }
            let mut unknown = crate::domain::mitigation_rule(&affected).unwrap();
            unknown.nlri.dst_ports = vec![123];
            fx.speaker.inner.announce(&unknown).await.unwrap();
            let (status, body) = fx.safelist(protected).await;
            assert_eq!(status, StatusCode::CREATED);
            assert_eq!(ids(&body), [affected.mitigation_id.to_string()]);
            assert!(body.get("withdrawal_error").is_none());
            assert_eq!(fx.status(&affected).await, MitigationStatus::Withdrawn);
            for mitigation in [&unaffected, &foreign, &host] {
                assert_eq!(fx.status(mitigation).await, MitigationStatus::Active);
            }
            let retained = fx.speaker.inner.list_active().await.unwrap();
            assert_eq!(retained.len(), 3);
            assert!(
                retained
                    .iter()
                    .any(|rule| rule.nlri_hash() == unknown.nlri_hash())
            );
            assert!(retained.iter().all(|rule| {
                rule.nlri_hash()
                    != crate::domain::mitigation_rule(&affected)
                        .unwrap()
                        .nlri_hash()
            }));
            let audit = fx.audit(&affected).await;
            assert_eq!(audit.details["reason"], SAFELISTED_AFTER_ADMISSION);
            assert_eq!(fx.speaker.flowspec_adds.load(SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn destination_prefix_foreign_owner_keeps_exact_pending_withdrawal() {
        let fx = fixture(OperationMode::Enforced);
        let mut affected = flowspec("203.0.112.0/22", "test", OperationMode::Enforced);
        affected.action_params.injection_owner = "prefixd-test".into();
        affected.scope_hash = affected.match_criteria.compute_scope_hash();
        fx.repo.insert_mitigation(&affected).await.unwrap();
        let own_rule = crate::domain::mitigation_rule(&affected).unwrap();
        let mut foreign_rule = own_rule.clone();
        foreign_rule.owner = "another-controller".into();
        fx.speaker
            .inner
            .announce_leased(&foreign_rule, 90)
            .await
            .unwrap();

        let (status, body) = fx.safelist("203.0.113.10").await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(ids(&body).is_empty());
        assert!(body["withdrawal_error"].is_string());
        let pending = fx.repo.pending_withdrawals(None).await.unwrap();
        let [request] = pending.as_slice() else {
            panic!("one pending withdrawal")
        };
        assert_eq!(
            serde_json::to_value(request.flowspec_rule().unwrap()).unwrap(),
            serde_json::to_value(&own_rule).unwrap(),
        );
        assert_eq!(request.reason, SAFELISTED_AFTER_ADMISSION);
        let retained_rules = fx.speaker.inner.list_active().await.unwrap();
        assert_eq!(retained_rules.len(), 1);
        assert_eq!(retained_rules[0].owner, foreign_rule.owner);
        assert_eq!(retained_rules[0].nlri_hash(), foreign_rule.nlri_hash());

        // Another insertion cannot replace the failed operation or split the rule.
        let (_, retried_body) = fx.safelist("203.0.113.0/24").await;
        assert!(ids(&retried_body).is_empty());
        let retained = fx.repo.pending_withdrawals(None).await.unwrap();
        assert_eq!(retained[0].operation_id, request.operation_id);
        assert_eq!(retained[0].rule_json, request.rule_json);
        assert_eq!(retained[0].actor, "safelist-recheck");
        assert_eq!(fx.speaker.flowspec_adds.load(SeqCst), 0);

        fx.speaker.inner.withdraw(&foreign_rule).await.unwrap();
        fx.speaker
            .inner
            .announce_leased(&own_rule, 90)
            .await
            .unwrap();
        crate::domain::execute_withdrawal(
            fx.repo.as_ref(),
            fx.speaker.as_ref(),
            false,
            request,
            None,
        )
        .await
        .unwrap();
        assert_eq!(fx.status(&affected).await, MitigationStatus::Withdrawn);
        assert!(fx.speaker.inner.list_active().await.unwrap().is_empty());
        assert_eq!(
            fx.audit(&affected).await.details["operation_id"],
            request.operation_id.to_string()
        );
    }

    #[tokio::test]
    async fn covering_prefix_withdraws_every_blackhole_inside_and_nothing_outside() {
        let fx = fixture(OperationMode::Enforced);
        let first = blackhole("203.0.113.1", "test", OperationMode::Enforced);
        let second = blackhole("203.0.113.254", "test", OperationMode::Enforced);
        let outside = blackhole("198.51.100.1", "test", OperationMode::Enforced);
        for mitigation in [&first, &second, &outside] {
            fx.live(mitigation).await;
        }
        let (status, body) = fx.safelist("203.0.113.0/24").await;
        assert_eq!(status, StatusCode::CREATED);
        let mut expected = vec![
            first.mitigation_id.to_string(),
            second.mitigation_id.to_string(),
        ];
        expected.sort();
        assert_eq!(ids(&body), expected);
        assert!(fx.status(&outside).await.is_active());
        assert_eq!(fx.speaker.routes().await, [route(&outside)]);
        assert_eq!(fx.speaker.deletes.load(SeqCst), 2);
    }

    #[tokio::test]
    async fn foreign_pop_blackhole_is_untouched() {
        let fx = fixture(OperationMode::Enforced);
        let foreign = blackhole("203.0.113.10", "other-pop", OperationMode::Enforced);
        fx.live(&foreign).await;
        let (status, body) = fx.safelist("203.0.113.0/24").await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(ids(&body).is_empty());
        assert!(fx.status(&foreign).await.is_active());
        assert!(fx.repo.pending_withdrawals(None).await.unwrap().is_empty());
        assert_eq!(fx.speaker.deletes.load(SeqCst), 0);
    }

    #[tokio::test]
    async fn lookup_failure_stores_the_entry_and_withdraws_nothing() {
        let fx = fixture(OperationMode::Enforced);
        let victim = blackhole("203.0.113.10", "test", OperationMode::Enforced);
        fx.live(&victim).await;
        fx.repo.fail_active_reads.store(true, SeqCst);
        let (status, body) = fx.safelist("203.0.113.10/32").await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(ids(&body).is_empty());
        assert!(
            body["withdrawal_error"]
                .as_str()
                .unwrap()
                .contains("nothing was withdrawn")
        );
        assert!(fx.repo.is_safelisted("203.0.113.10").await.unwrap());
        fx.repo.fail_active_reads.store(false, SeqCst);
        assert!(fx.status(&victim).await.is_active());
        assert!(fx.repo.pending_withdrawals(None).await.unwrap().is_empty());
        assert_eq!(fx.speaker.deletes.load(SeqCst), 0);
        assert_eq!(fx.speaker.routes().await, [route(&victim)]);
    }

    #[tokio::test]
    async fn dry_run_blackholes_are_retired_without_an_rpc() {
        // A simulation under an enforced controller, and any row in dry-run mode.
        for mode in [OperationMode::Enforced, OperationMode::DryRun] {
            let fx = fixture(mode);
            let simulated = blackhole("203.0.113.10", "test", OperationMode::DryRun);
            fx.live(&simulated).await;
            let (status, body) = fx.safelist("203.0.113.10").await;
            assert_eq!(status, StatusCode::CREATED);
            assert_eq!(ids(&body), [simulated.mitigation_id.to_string()]);
            assert_eq!(fx.status(&simulated).await, MitigationStatus::Withdrawn);
            assert_eq!(fx.speaker.deletes.load(SeqCst), 0);
            assert_eq!(
                fx.audit(&simulated).await.details["reason"],
                SAFELISTED_AFTER_ADMISSION
            );
        }
    }

    #[tokio::test]
    async fn failed_delete_keeps_immutable_intent_and_is_never_reannounced() {
        let fx = fixture(OperationMode::Enforced);
        let victim = blackhole("203.0.113.10", "test", OperationMode::Enforced);
        fx.live(&victim).await;
        fx.speaker.withdraw_fault.store(1, SeqCst);
        let (status, body) = fx.safelist("203.0.113.10/32").await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(ids(&body).is_empty());
        assert!(body["withdrawal_error"].is_string());
        let [request] = fx
            .repo
            .pending_withdrawals(None)
            .await
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(request.mitigation_id, victim.mitigation_id);
        assert_eq!(
            (request.actor_type.as_str(), request.actor.as_str()),
            ("system", "safelist-recheck")
        );
        assert_eq!(request.reason, SAFELISTED_AFTER_ADMISSION);
        let reconciler = crate::scheduler::ReconciliationLoop::new(
            fx.state.repo.clone(),
            fx.state.announcer.clone(),
            30,
            false,
        )
        .with_app_state(fx.state.clone());
        // While the delete keeps failing, the same intent stays pending and nothing is added.
        let _ = reconciler.reconcile().await;
        let [retained] = fx
            .repo
            .pending_withdrawals(None)
            .await
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(retained.operation_id, request.operation_id);
        assert_eq!(retained.reason, request.reason);
        assert_eq!(fx.speaker.adds.load(SeqCst), 0);
        // The retry completes the original operation.
        fx.speaker.withdraw_fault.store(0, SeqCst);
        reconciler.reconcile().await.unwrap();
        assert_eq!(fx.status(&victim).await, MitigationStatus::Withdrawn);
        assert!(fx.speaker.routes().await.is_empty());
        assert_eq!(fx.speaker.adds.load(SeqCst), 0);
        let entry = fx.audit(&victim).await;
        assert_eq!(
            entry.details["operation_id"],
            request.operation_id.to_string()
        );
        assert_eq!(entry.details["reason"], SAFELISTED_AFTER_ADMISSION);
    }

    #[tokio::test]
    async fn standby_refuses_safelist_add_and_withdraws_nothing() {
        let fx = fixture(OperationMode::Enforced);
        let victim = blackhole("203.0.113.10", "test", OperationMode::Enforced);
        fx.live(&victim).await;
        let fx = Fixture {
            state: fx
                .state
                .with_fence(Arc::new(crate::fence::ControllerFence::new(false)))
                .unwrap(),
            ..fx
        };
        let (status, _) = fx.safelist("203.0.113.10/32").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(!fx.repo.is_safelisted("203.0.113.10").await.unwrap());
        assert!(fx.status(&victim).await.is_active());
        assert_eq!(fx.speaker.deletes.load(SeqCst), 0);
    }

    #[test]
    fn test_validate_cidr_accepts_valid_values() {
        assert!(super::validate_cidr("203.0.113.0/24").is_ok());
        assert!(super::validate_cidr("2001:db8::/64").is_ok());
        assert!(super::validate_cidr("203.0.113.10").is_ok());
    }

    #[test]
    fn test_validate_cidr_rejects_invalid_masks() {
        assert!(super::validate_cidr("203.0.113.0/33").is_err());
        assert!(super::validate_cidr("2001:db8::/129").is_err());
        assert!(super::validate_cidr("203.0.113.0/not-a-mask").is_err());
    }
}
