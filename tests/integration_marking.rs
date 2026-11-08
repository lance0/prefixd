#![cfg(feature = "test-utils")]
mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use prefixd::{
    AppState,
    bgp::{FlowSpecReader, FlowSpecWriter, MockAnnouncer},
    config::{OperationMode, Settings},
    db::{MockRepository, RepositoryTrait},
    domain::{ActionParams, ActionType, FlowSpecAction, WithdrawalRequest},
    scheduler::ReconciliationLoop,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

fn settings() -> Settings {
    let mut value = common::test_settings();
    value.mode = OperationMode::Enforced;
    value.bgp.vpn_scopes=serde_json::from_value(json!({
        "V4":{"family":"ipv4","rd":"44407:40","route_targets":["44407:777"],"allow_source_only":true},
        "V6":{"family":"ipv6","rd":"44407:40","route_targets":["44407:777"],"allow_source_only":true}
    })).unwrap();
    value
}
fn state(repo: Arc<MockRepository>, speaker: Arc<MockAnnouncer>) -> Arc<AppState> {
    let mut inventory = common::test_inventory();
    inventory.customers[0]
        .prefixes
        .push("2001:db8:100::/48".into());
    AppState::new(
        settings(),
        inventory,
        common::test_playbooks(),
        repo,
        speaker,
        ".".into(),
    )
    .unwrap()
}
async fn post(app: &axum::Router, path: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::post(path)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"raw":String::from_utf8_lossy(&bytes)})),
    )
}
fn request(scope: &str, victim: &str, dscp: u8) -> Value {
    json!({"scope":scope,"rule":{"victim_ip":victim,"protocol":"udp","action":"mark","dscp":dscp,"ttl_seconds":300,"reason":"manual marking control"}})
}

#[test]
fn marking_params_are_exact_and_legacy_json_is_unchanged() {
    assert_eq!(
        serde_json::to_value(FlowSpecAction::discard()).unwrap(),
        json!({"action_type":"discard"})
    );
    assert_eq!(
        serde_json::to_value(ActionParams::default()).unwrap(),
        json!({})
    );
    for dscp in [0, 63] {
        let action = FlowSpecAction::mark(dscp);
        action.validate().unwrap();
        assert_eq!(
            action.extended_community().unwrap(),
            (0x8009u64 << 48) | u64::from(dscp)
        );
        let restored: FlowSpecAction =
            serde_json::from_value(serde_json::to_value(&action).unwrap()).unwrap();
        assert_eq!(restored.dscp, Some(dscp));
    }
    for action in [
        FlowSpecAction::mark(64),
        FlowSpecAction {
            action_type: ActionType::Mark,
            dscp: None,
            rate_bps: None,
        },
        FlowSpecAction {
            action_type: ActionType::Mark,
            dscp: Some(0),
            rate_bps: Some(8),
        },
        FlowSpecAction {
            action_type: ActionType::Discard,
            dscp: Some(0),
            rate_bps: None,
        },
        FlowSpecAction {
            action_type: ActionType::Police,
            dscp: Some(0),
            rate_bps: Some(8),
        },
    ] {
        assert!(action.validate().is_err());
    }
}

#[tokio::test]
async fn scoped_marking_persists_repairs_and_withdraws_exact_dscp_in_both_families() {
    let repo = Arc::new(MockRepository::new());
    let speaker = Arc::new(MockAnnouncer::new());
    let state = state(repo.clone(), speaker.clone());
    let app = prefixd::api::create_test_router(state.clone());
    for (scope, base) in [("V4", "203.0.113"), ("V6", "2001:db8:100::")] {
        for dscp in [0, 63] {
            let victim = if scope == "V4" {
                format!("{base}.{}", dscp + 10)
            } else {
                format!("{base}{}", dscp + 10)
            };
            let body = request(scope, &victim, dscp);
            let (status, preview) = post(&app, "/v1/vpn/mitigations/preview", body.clone()).await;
            assert_eq!(status, StatusCode::OK, "{preview}");
            assert_eq!(preview["candidate"]["action"]["dscp"], dscp);
            let (status, created) = post(&app, "/v1/vpn/mitigations", body).await;
            assert_eq!(status, StatusCode::CREATED, "{created}");
            assert_eq!(created["dscp"], dscp);
            let id = created["mitigation_id"].as_str().unwrap().parse().unwrap();
            let mut saved = repo.get_mitigation(id).await.unwrap().unwrap();
            let withdrawal = WithdrawalRequest::new(
                &saved,
                false,
                "operator",
                "test",
                "saved mark".into(),
                true,
            )
            .unwrap();
            let expected = withdrawal.flowspec_rule().unwrap();
            assert_eq!(expected.actions[0].dscp, Some(dscp));
            saved.action_params.dscp = Some(63 - dscp);
            assert_eq!(
                withdrawal.flowspec_rule().unwrap().actions[0].dscp,
                Some(dscp)
            );
            speaker.withdraw(&expected).await.unwrap();
            let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false)
                .with_app_state(state.clone());
            reconciler.reconcile().await.unwrap();
            let mut drifted = expected.clone();
            drifted.actions = vec![FlowSpecAction::mark(63 - dscp)];
            speaker.announce(&drifted).await.unwrap();
            reconciler.reconcile().await.unwrap();
            assert!(
                speaker
                    .list_active()
                    .await
                    .unwrap()
                    .iter()
                    .any(|rule| rule.nlri_hash() == expected.nlri_hash()
                        && rule.actions[0].dscp == Some(dscp))
            );
            let (status, _) = post(
                &app,
                &format!("/v1/mitigations/{id}/extend"),
                json!({"ttl_seconds":600,"reason":"not supported"}),
            )
            .await;
            assert_eq!(status, StatusCode::CONFLICT);
            let (status, withdrawn) = post(
                &app,
                &format!("/v1/mitigations/{id}/withdraw"),
                json!({"reason":"mark test complete"}),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{withdrawn}");
            assert!(speaker.list_active().await.unwrap().is_empty());
        }
    }
}

#[tokio::test]
async fn marking_refuses_wrong_parameters_global_and_source_only_before_persistence() {
    let repo = Arc::new(MockRepository::new());
    let speaker = Arc::new(MockAnnouncer::new());
    let app = prefixd::api::create_test_router(state(repo.clone(), speaker.clone()));
    for case in [
        "missing",
        "range",
        "rate",
        "discard-param",
        "global",
        "source",
    ] {
        let mut body = request("V4", "203.0.113.10", 0);
        let path = match case {
            "missing" => {
                body["rule"].as_object_mut().unwrap().remove("dscp");
                "/v1/vpn/mitigations"
            }
            "range" => {
                body["rule"]["dscp"] = json!(64);
                "/v1/vpn/mitigations"
            }
            "rate" => {
                body["rule"]["rate_bps"] = json!(8);
                "/v1/vpn/mitigations"
            }
            "discard-param" => {
                body["rule"]["action"] = json!("discard");
                "/v1/vpn/mitigations"
            }
            "global" => {
                body = body["rule"].clone();
                "/v1/mitigations"
            }
            _ => {
                body = json!({"scope":"V4","src_prefix":"198.51.100.0/24","protocol":"udp","action":"mark","ttl_seconds":30,"reason":"refuse source-only mark","confirm_destination_any":true});
                "/v1/vpn/source-rules"
            }
        };
        let (status, result) = post(&app, path, body).await;
        assert!(status.is_client_error(), "{case}: {status} {result}");
        assert!(
            repo.active_mitigations_for_pop(&settings().pop)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(speaker.list_active().await.unwrap().is_empty());
    }
    assert!(serde_json::from_str::<prefixd::config::PlaybookAction>("\"mark\"").is_err());
}

#[tokio::test]
async fn postgres_marking_roundtrip_preserves_action_scope_and_withdrawal_snapshot() {
    let context = common::TestContext::new().await;
    let speaker = Arc::new(MockAnnouncer::new());
    let mut inventory = common::test_inventory();
    inventory.customers[0]
        .prefixes
        .push("2001:db8:100::/48".into());
    let app = prefixd::api::create_test_router(
        AppState::new(
            settings(),
            inventory,
            common::test_playbooks(),
            context.repo.clone(),
            speaker,
            ".".into(),
        )
        .unwrap(),
    );
    for (scope, victim) in [("V4", "203.0.113.10"), ("V6", "2001:db8:100::10")] {
        let (status, created) = post(&app, "/v1/vpn/mitigations", request(scope, victim, 63)).await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let id = created["mitigation_id"].as_str().unwrap().parse().unwrap();
        let fresh = prefixd::db::Repository::new(context.pool.clone());
        let loaded = fresh.get_mitigation(id).await.unwrap().unwrap();
        assert_eq!(loaded.action_type, ActionType::Mark);
        assert_eq!(loaded.action_params.dscp, Some(63));
        assert_eq!(loaded.match_criteria.scope.as_ref().unwrap().name, scope);
        let (status, response) = post(
            &app,
            &format!("/v1/mitigations/{id}/withdraw"),
            json!({"reason":"mark persistence control"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        let payload: String =
            sqlx::query_scalar("SELECT rule_json FROM withdrawal_requests WHERE mitigation_id=$1")
                .bind(id)
                .fetch_one(&context.pool)
                .await
                .unwrap();
        let saved: prefixd::domain::FlowSpecRule = serde_json::from_str(&payload).unwrap();
        assert_eq!(saved.actions[0].dscp, Some(63));
        assert_eq!(
            saved.nlri.scope,
            loaded.match_criteria.scope.map(|scope| scope.identity)
        );
    }
}
