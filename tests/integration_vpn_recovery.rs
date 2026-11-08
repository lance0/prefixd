//! Fresh controller state + PostgreSQL + released speaker recovery, not process/crash qualification.
#![cfg(all(feature = "bgp-rustbgpd", feature = "test-utils", target_os = "linux"))]
mod common;
#[path = "common/rustbgpd.rs"]
mod fixture;

use std::{sync::Arc, time::Duration};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use prefixd::{
    AppState,
    api::create_test_router,
    bgp::{DaemonHealthObserver, FlowSpecReader, FlowSpecWriter, check_vpn_startup},
    config::{BgpMode, Customer, Inventory, OperationMode, Playbooks, PolicyProfile, Settings},
    db::{Repository, RepositoryTrait},
    domain::{FlowSpecRule, Mitigation, MitigationStatus, SpeakerTarget, mitigation_rule},
    error::PrefixdError,
    scheduler::ReconciliationLoop,
};
use serde_json::{Value, json};
use tower::ServiceExt;

fn settings(speaker: &fixture::Speaker) -> Settings {
    let mut value = common::test_settings();
    value.pop = "vpn-postgres-recovery".into();
    value.mode = OperationMode::Enforced;
    value.bgp.mode = BgpMode::Rustbgpd;
    value.bgp.rustbgpd = Some(speaker.config.clone());
    value.bgp.rustbgpd.as_mut().unwrap().leased_flowspec = false;
    value.bgp.vpn_scopes = serde_json::from_value(json!({
        "A4": {"family":"ipv4","rd":"44407:40","route_targets":["44407:777"]},
        "B4": {"family":"ipv4","rd":"44407:41","route_targets":["44407:778"]},
        "A6": {"family":"ipv6","rd":"44407:40","route_targets":["44407:777"]},
        "B6": {"family":"ipv6","rd":"44407:41","route_targets":["44407:778"]}
    }))
    .unwrap();
    value
}

fn inventory() -> Inventory {
    Inventory::new(vec![Customer {
        customer_id: "recovery-owner".into(),
        name: "Recovery owner".into(),
        prefixes: vec!["203.0.113.0/24".into(), "2001:db8:100::/48".into()],
        policy_profile: PolicyProfile::Normal,
        services: vec![],
    }])
}

async fn post(app: &axum::Router, path: &str, body: Value) -> Value {
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        app.clone().oneshot(
            Request::post(path)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        ),
    )
    .await
    .expect("bounded HTTP lifecycle request")
    .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        matches!(status, StatusCode::CREATED | StatusCode::OK),
        "{path}: {status} {value}"
    );
    value
}

fn payloads(rules: impl IntoIterator<Item = FlowSpecRule>) -> Vec<String> {
    let mut rows: Vec<_> = rules
        .into_iter()
        .map(|rule| serde_json::to_string(&rule).unwrap())
        .collect();
    rows.sort_unstable();
    rows
}

fn saved_rules(rows: &[Mitigation]) -> Vec<FlowSpecRule> {
    rows.iter()
        .map(|row| {
            assert_eq!(row.origin_mode, Some(OperationMode::Enforced));
            assert!(
                row.action_params.injection_owner.is_empty(),
                "this is unleased recovery"
            );
            mitigation_rule(row).unwrap()
        })
        .collect()
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and pinned Linux Docker speaker; run scripts/test-rustbgpd.sh"]
async fn released_vpn_postgres_fresh_controller_recovers_saved_scopes_and_withdraws_original_a() {
    let database = common::TestContext::new().await;
    let fixture = fixture::Speaker::start().await;
    let speaker = Arc::new(fixture.connect().await);
    let version = speaker.daemon_health().await.unwrap().version.unwrap();
    assert!(
        matches!(version.as_str(), "0.81.0" | "0.82.0"),
        "unqualified release {version}"
    );
    let mut configured = settings(&fixture);
    let target = SpeakerTarget::from_config(&configured.bgp).unwrap();
    let binding = database
        .repo
        .register_speaker_target(&configured.pop, &target, false)
        .await
        .unwrap();
    let mut initial = configured.clone();
    if version == "0.81.0" {
        // Global-only deployment is supported; separately prove that enabling VPN fails closed.
        initial.bgp.vpn_scopes.clear();
    } else {
        check_vpn_startup(
            &initial.bgp,
            &initial.pop,
            speaker.as_ref(),
            database.repo.as_ref(),
        )
        .await
        .unwrap();
    }
    let state = AppState::new(
        initial,
        inventory(),
        Playbooks { playbooks: vec![] },
        database.repo.clone(),
        speaker.clone(),
        ".".into(),
    )
    .unwrap()
    .with_speaker_binding(binding.clone())
    .unwrap();
    let old_state = Arc::downgrade(&state);
    let old_speaker = Arc::downgrade(&speaker);
    let app = create_test_router(state.clone());
    for (suffix, victim) in [("4", "203.0.113.10"), ("6", "2001:db8:100::10")] {
        let base = json!({"victim_ip":victim,"protocol":"udp","dst_ports":[53],"action":"discard","ttl_seconds":300,"reason":"persisted global control"});
        post(&app, "/v1/mitigations", base.clone()).await;
        if version == "0.82.0" {
            for scope in [format!("A{suffix}"), format!("B{suffix}")] {
                let mut rule = base.clone();
                if scope.starts_with('A') {
                    rule["action"] = json!("police");
                    rule["rate_bps"] = json!(8_000_000);
                }
                post(
                    &app,
                    "/v1/vpn/mitigations",
                    json!({"scope":scope,"rule":rule}),
                )
                .await;
            }
        }
    }
    if version == "0.81.0" {
        let before = [
            fixture.received_flow_spec(3, "0.0.0.0").await,
            fixture.received_flow_spec(4, "0.0.0.0").await,
        ];
        for name in ["A4", "A6"] {
            let scope = configured.bgp.resolve_scope(name).unwrap().unwrap();
            let error = speaker
                .validate_scope(Some(&scope.identity))
                .await
                .unwrap_err();
            assert!(
                matches!(error, PrefixdError::UnsupportedFlowSpecScope { family, .. } if family == scope.identity.family.afi_safi()),
                "{error}"
            );
            assert_eq!(fixture.received_flow_spec(3, "0.0.0.0").await, before[0]);
            assert_eq!(fixture.received_flow_spec(4, "0.0.0.0").await, before[1]);
        }
        assert!(matches!(
            check_vpn_startup(
                &configured.bgp,
                &configured.pop,
                speaker.as_ref(),
                database.repo.as_ref()
            )
            .await,
            Err(PrefixdError::UnsupportedFlowSpecScope { .. })
        ));
        assert_eq!(fixture.received_flow_spec(3, "0.0.0.0").await, before[0]);
        assert_eq!(fixture.received_flow_spec(4, "0.0.0.0").await, before[1]);
        let saved = database
            .repo
            .active_mitigations_for_pop(&configured.pop)
            .await
            .unwrap();
        assert_eq!(saved.len(), 2);
        assert!(saved.iter().all(|row| row.match_criteria.scope.is_none()));
        drop(app);
        drop(state);
        drop(speaker);
        assert!(old_state.upgrade().is_none() && old_speaker.upgrade().is_none());
        fixture.container.rm().await.unwrap();
        eprintln!(
            "0.81.0: VPN startup/family refusals preserve both PostgreSQL/global speaker controls"
        );
        return;
    }
    let saved = database
        .repo
        .active_mitigations_for_pop(&configured.pop)
        .await
        .unwrap();
    assert_eq!(saved.len(), 6);
    let expected = saved_rules(&saved);
    assert_eq!(
        payloads(speaker.list_active().await.unwrap()),
        payloads(expected.clone())
    );
    drop(app);
    drop(state);
    drop(speaker);
    assert!(
        old_state.upgrade().is_none() && old_speaker.upgrade().is_none(),
        "original controller state/router/client must be gone before recovery"
    );

    fixture.container.stop_with_timeout(Some(0)).await.unwrap();
    fixture.container.start().await.unwrap();
    fixture.ready().await;
    let fresh_speaker = Arc::new(fixture.connect().await);
    let fresh_repo: Arc<dyn RepositoryTrait> = Arc::new(Repository::new(database.pool.clone()));
    configured.bgp.default_scope =
        serde_json::from_value(json!({"ipv4":"B4","ipv6":"B6"})).unwrap();
    let fresh_binding = fresh_repo
        .register_speaker_target(
            &configured.pop,
            &SpeakerTarget::from_config(&configured.bgp).unwrap(),
            false,
        )
        .await
        .unwrap();
    assert_eq!(fresh_binding.target_id(), binding.target_id());
    check_vpn_startup(
        &configured.bgp,
        &configured.pop,
        fresh_speaker.as_ref(),
        fresh_repo.as_ref(),
    )
    .await
    .unwrap();
    assert!(
        fresh_speaker.list_active().await.unwrap().is_empty(),
        "after read-only startup registers both VPN families, the complete inventory proves daemon restart lost all injected routes"
    );
    assert_eq!(
        payloads(saved_rules(
            &fresh_repo
                .active_mitigations_for_pop(&configured.pop)
                .await
                .unwrap()
        )),
        payloads(expected.clone()),
        "PostgreSQL retained the original six payloads despite new defaults"
    );
    let fresh_state = AppState::new(
        configured.clone(),
        inventory(),
        Playbooks { playbooks: vec![] },
        fresh_repo.clone(),
        fresh_speaker.clone(),
        ".".into(),
    )
    .unwrap()
    .with_speaker_binding(fresh_binding)
    .unwrap();
    let reconciler = ReconciliationLoop::new(fresh_repo.clone(), fresh_speaker.clone(), 30, false)
        .with_app_state(fresh_state.clone());
    tokio::time::timeout(Duration::from_secs(20), reconciler.reconcile())
        .await
        .expect("bounded production reconciliation")
        .unwrap();
    assert_eq!(
        payloads(fresh_speaker.list_active().await.unwrap()),
        payloads(expected)
    );
    let fresh_app = create_test_router(fresh_state.clone());
    for original in saved.iter().filter(|row| {
        row.match_criteria
            .scope
            .as_ref()
            .is_some_and(|scope| scope.name.starts_with('A'))
    }) {
        post(
            &fresh_app,
            &format!("/v1/mitigations/{}/withdraw", original.mitigation_id),
            json!({"reason":"withdraw saved A after default change"}),
        )
        .await;
        let (payload, target, reason, actor_type, actor): (String, Option<uuid::Uuid>, String, String, String) = sqlx::query_as(
            "SELECT rule_json,target_id,reason,actor_type,actor FROM withdrawal_requests WHERE mitigation_id=$1",
        )
        .bind(original.mitigation_id)
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&payload).unwrap(),
            serde_json::to_value(mitigation_rule(original).unwrap()).unwrap()
        );
        assert_eq!(target, Some(binding.target_id()));
        assert_eq!(reason, "anonymous: withdraw saved A after default change");
        assert_eq!(actor_type, "operator");
        assert_eq!(actor, "anonymous");
        assert_eq!(
            fresh_repo
                .get_mitigation(original.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            MitigationStatus::Withdrawn
        );
    }
    let remaining: Vec<_> = saved
        .into_iter()
        .filter(|row| {
            row.match_criteria
                .scope
                .as_ref()
                .is_none_or(|scope| !scope.name.starts_with('A'))
        })
        .collect();
    assert_eq!(remaining.len(), 4);
    assert_eq!(
        payloads(fresh_speaker.list_active().await.unwrap()),
        payloads(saved_rules(&remaining)),
        "saved A withdrawal must leave global and B in both AFIs"
    );
    for row in remaining {
        post(
            &fresh_app,
            &format!("/v1/mitigations/{}/withdraw", row.mitigation_id),
            json!({"reason":"owned recovery fixture cleanup"}),
        )
        .await;
    }
    assert!(fresh_speaker.list_active().await.unwrap().is_empty());
    assert!(
        fresh_repo
            .active_mitigations_for_pop(&configured.pop)
            .await
            .unwrap()
            .is_empty()
    );
    drop(fresh_app);
    drop(reconciler);
    drop(fresh_state);
    drop(fresh_speaker);
    fixture.container.rm().await.unwrap();
    eprintln!(
        "0.82.0: fresh controller/PostgreSQL recovery restores exact global/A/B payloads in both AFIs; saved A withdrawal preserves global/B"
    );
}
