#![cfg(feature = "test-utils")]
mod common;

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use prefixd::{
    AppState,
    api::create_test_router,
    bgp::{FlowSpecReader, MockAnnouncer},
    config::{
        EventScope, OperationMode, Playbook, PlaybookAction, PlaybookMatch, PlaybookStep, Settings,
    },
    db::{MockRepository, RepositoryTrait},
    domain::{ActionType, AttackVector, VpnFlowSpecFamily, mitigation_rule},
    scheduler::ReconciliationLoop,
};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

async fn post(app: &axum::Router, path: &str, value: Value, expected: StatusCode) -> Value {
    let response = app
        .clone()
        .oneshot(
            Request::post(path)
                .header("content-type", "application/json")
                .body(Body::from(value.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(status, expected, "{path}: {body}");
    body
}

fn settings() -> Settings {
    let mut settings = common::test_settings();
    settings.mode = OperationMode::Enforced;
    settings.bgp.vpn_scopes = serde_json::from_value(json!({
        "V4": {"family":"ipv4","rd":"44407:40","route_targets":["44407:777"]},
        "V6": {"family":"ipv6","rd":"44407:40","route_targets":["44407:777"]},
        "NEXT4": {"family":"ipv4","rd":"44407:50","route_targets":["44407:778"]},
        "NEXT6": {"family":"ipv6","rd":"44407:50","route_targets":["44407:778"]}
    }))
    .unwrap();
    settings.bgp.default_scope = serde_json::from_value(json!({"ipv4":"V4","ipv6":"V6"})).unwrap();
    settings
}

fn state(
    settings: Settings,
    repo: Arc<MockRepository>,
    speaker: Arc<MockAnnouncer>,
) -> Arc<AppState> {
    let mut inventory = common::test_inventory();
    inventory.customers[0]
        .prefixes
        .push("2001:db8:100::/48".into());
    AppState::new(
        settings,
        inventory,
        common::test_playbooks(),
        repo,
        speaker,
        ".".into(),
    )
    .unwrap()
}

fn event(id: &str, victim: &str, action: &str) -> Value {
    json!({"event_id":id,"timestamp":chrono::Utc::now(),"source":"vpn-detector",
        "victim_ip":victim,"vector":"udp_flood","action":action})
}

#[tokio::test]
async fn automatic_family_defaults_snapshot_and_unban_original_scope_after_restart() {
    let repo = Arc::new(MockRepository::new());
    let speaker = Arc::new(MockAnnouncer::new());
    let mut settings = settings();
    let app = create_test_router(state(settings.clone(), repo.clone(), speaker.clone()));
    let victims = ["203.0.113.10", "2001:db8:100::10"];
    for (index, victim) in victims.iter().enumerate() {
        post(
            &app,
            "/v1/mitigations",
            json!({"victim_ip":victim,"protocol":"udp",
            "action":"police","rate_bps":10_000_000,"ttl_seconds":120,"reason":"global control"}),
            StatusCode::CREATED,
        )
        .await;
        post(
            &app,
            "/v1/events",
            event(&format!("original-{index}"), victim, "ban"),
            StatusCode::ACCEPTED,
        )
        .await;
    }
    let rules = speaker.list_active().await.unwrap();
    assert_eq!(rules.len(), 4);
    assert_eq!(
        rules
            .iter()
            .filter(|rule| rule.nlri.scope.is_none())
            .count(),
        2
    );
    assert_eq!(
        rules
            .iter()
            .filter(|rule| rule
                .nlri
                .scope
                .as_ref()
                .is_some_and(|scope| scope.rd() == "44407:40"))
            .count(),
        2
    );

    settings.bgp.default_scope =
        serde_json::from_value(json!({"ipv4":"NEXT4","ipv6":"NEXT6"})).unwrap();
    let restarted = state(settings, repo.clone(), speaker.clone());
    prefixd::bgp::check_vpn_startup(
        &restarted.settings.bgp,
        &restarted.settings.pop,
        speaker.as_ref(),
        repo.as_ref(),
    )
    .await
    .unwrap();
    let app = create_test_router(restarted);
    for (index, victim) in victims.iter().enumerate() {
        post(
            &app,
            "/v1/events",
            event(&format!("next-{index}"), victim, "ban"),
            StatusCode::ACCEPTED,
        )
        .await;
        post(
            &app,
            "/v1/events",
            event(&format!("original-{index}"), victim, "unban"),
            StatusCode::ACCEPTED,
        )
        .await;
    }
    let rules = speaker.list_active().await.unwrap();
    assert_eq!(rules.len(), 4);
    assert_eq!(
        rules
            .iter()
            .filter(|rule| rule.nlri.scope.is_none())
            .count(),
        2
    );
    assert!(
        rules
            .iter()
            .filter_map(|rule| rule.nlri.scope.as_ref())
            .all(|scope| scope.rd() == "44407:50")
    );
}

#[tokio::test]
async fn detector_cannot_select_scope_and_single_family_default_never_falls_back() {
    let repo = Arc::new(MockRepository::new());
    let speaker = Arc::new(MockAnnouncer::new());
    let mut settings = settings();
    settings.bgp.default_scope = "V4".into();
    let app = create_test_router(state(settings, repo, speaker.clone()));
    let request = event("wrong-family", "2001:db8:100::10", "ban");
    post(&app, "/v1/events", request.clone(), StatusCode::BAD_REQUEST).await;
    for field in ["scope", "vpn_scope", "vrf", "rd", "route_targets"] {
        let mut request = event("attempt-selector", "203.0.113.10", "ban");
        request[field] = json!("NEXT4");
        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/events")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
    assert!(speaker.list_active().await.unwrap().is_empty());
}

#[tokio::test]
async fn source_only_extension_keeps_short_ceiling_and_rechecks_source_safelist() {
    let repo = Arc::new(MockRepository::new());
    let speaker = Arc::new(MockAnnouncer::new());
    let mut settings = settings();
    settings.guardrails.allow_src_prefix_match = true;
    settings
        .bgp
        .vpn_scopes
        .get_mut("V4")
        .unwrap()
        .allow_source_only = true;
    let app = create_test_router(state(settings, repo.clone(), speaker));
    let admitted = post(
        &app,
        "/v1/vpn/source-rules",
        json!({"scope":"V4",
        "src_prefix":"198.51.100.0/24","protocol":"udp","action":"discard",
        "ttl_seconds":30,"reason":"source attack","confirm_destination_any":true}),
        StatusCode::CREATED,
    )
    .await;
    let id = admitted["mitigation_id"].as_str().unwrap();
    let report = app
        .clone()
        .oneshot(
            Request::get(format!("/v1/reports/incident?mitigation_id={id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        report.status(),
        StatusCode::BAD_REQUEST,
        "source-only rules have no destination incident target"
    );
    let extended = post(
        &app,
        &format!("/v1/mitigations/{id}/extend"),
        json!({"ttl_seconds":45,"reason":"short extension"}),
        StatusCode::OK,
    )
    .await;
    let created =
        chrono::DateTime::parse_from_rfc3339(admitted["created_at"].as_str().unwrap()).unwrap();
    let expires = chrono::DateTime::parse_from_rfc3339(
        extended["mitigation"]["expires_at"].as_str().unwrap(),
    )
    .unwrap();
    assert!(expires <= created + chrono::Duration::seconds(60));
    post(
        &app,
        &format!("/v1/mitigations/{id}/extend"),
        json!({"ttl_seconds":61,"reason":"must not escape source ceiling"}),
        StatusCode::BAD_REQUEST,
    )
    .await;
    repo.insert_safelist("198.51.100.128/25", "operator", None)
        .await
        .unwrap();
    post(
        &app,
        &format!("/v1/mitigations/{id}/extend"),
        json!({"ttl_seconds":50,"reason":"must not extend a protected source"}),
        StatusCode::UNPROCESSABLE_ENTITY,
    )
    .await;
    assert_eq!(
        repo.get_mitigation(id.parse().unwrap())
            .await
            .unwrap()
            .unwrap()
            .expires_at,
        expires
    );
}

#[tokio::test]
async fn source_only_policy_refusals_use_documented_statuses() {
    let repo = Arc::new(MockRepository::new());
    let speaker = Arc::new(MockAnnouncer::new());
    let mut configured = settings();
    configured.guardrails.allow_src_prefix_match = true;
    configured
        .bgp
        .vpn_scopes
        .get_mut("V4")
        .unwrap()
        .allow_source_only = true;
    configured.safelist.prefixes = vec!["198.51.100.0/25".into()];
    let app = create_test_router(state(configured, repo, speaker));
    post(
        &app,
        "/v1/vpn/source-rules",
        json!({"scope":"V4","src_prefix":"198.51.100.0/24","protocol":"udp",
            "action":"discard","ttl_seconds":30,"reason":"protected source",
            "confirm_destination_any":true}),
        StatusCode::UNPROCESSABLE_ENTITY,
    )
    .await;

    let repo = Arc::new(MockRepository::new());
    let speaker = Arc::new(MockAnnouncer::new());
    let mut configured = settings();
    configured.guardrails.allow_src_prefix_match = true;
    configured
        .bgp
        .vpn_scopes
        .get_mut("V4")
        .unwrap()
        .allow_source_only = true;
    let app = create_test_router(state(configured, repo, speaker));
    post(
        &app,
        "/v1/vpn/source-rules",
        json!({"scope":"V4","src_prefix":"198.51.0.0/16","protocol":"udp",
            "action":"discard","ttl_seconds":30,"reason":"too broad",
            "confirm_destination_any":true}),
        StatusCode::BAD_REQUEST,
    )
    .await;
}

#[tokio::test]
async fn automatic_family_map_can_select_global_for_one_family_explicitly() {
    let repo = Arc::new(MockRepository::new());
    let speaker = Arc::new(MockAnnouncer::new());
    let mut settings = settings();
    settings.bgp.default_scope =
        serde_json::from_value(json!({"ipv4":"global","ipv6":"V6"})).unwrap();
    let app = create_test_router(state(settings, repo, speaker.clone()));
    post(
        &app,
        "/v1/events",
        event("global-family", "203.0.113.10", "ban"),
        StatusCode::ACCEPTED,
    )
    .await;
    post(
        &app,
        "/v1/events",
        event("vpn-family", "2001:db8:100::10", "ban"),
        StatusCode::ACCEPTED,
    )
    .await;
    let rules = speaker.list_active().await.unwrap();
    assert_eq!(rules.len(), 2);
    assert!(
        rules
            .iter()
            .any(|rule| rule.nlri.scope.is_none() && !rule.nlri.dst_prefix.contains(':'))
    );
    assert!(rules.iter().any(|rule| {
        rule.nlri
            .scope
            .as_ref()
            .is_some_and(|scope| scope.family.afi_safi() == 14)
    }));
}

/// Health detail used to probe each VPN family on every request; a dashboard or
/// Viewer could drive one speaker RIB read per request per family.
#[tokio::test(start_paused = true)]
async fn health_detail_probes_each_vpn_family_once_per_window() {
    use prefixd::bgp::{FlowSpecAnnouncer, FlowSpecWriter};
    use prefixd::domain::{FlowSpecRule, VpnFlowSpecIdentity};
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    struct Probes(AtomicUsize);
    impl FlowSpecAnnouncer for Probes {
        fn backend(&self) -> &'static str {
            "probe-test"
        }
    }
    #[async_trait::async_trait]
    impl FlowSpecWriter for Probes {
        fn register_scope(&self, _: Option<&VpnFlowSpecIdentity>) -> prefixd::error::Result<()> {
            Ok(())
        }
        async fn validate_scope(
            &self,
            _: Option<&VpnFlowSpecIdentity>,
        ) -> prefixd::error::Result<()> {
            self.0.fetch_add(1, SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            Ok(())
        }
        async fn announce(&self, _: &FlowSpecRule) -> prefixd::error::Result<()> {
            panic!("health must not mutate")
        }
        async fn withdraw(&self, _: &FlowSpecRule) -> prefixd::error::Result<()> {
            panic!("health must not mutate")
        }
    }
    let speaker = Arc::new(Probes(AtomicUsize::new(0)));
    let app = create_test_router(
        AppState::new(
            settings(),
            common::test_inventory(),
            common::test_playbooks(),
            Arc::new(MockRepository::new()),
            speaker.clone(),
            ".".into(),
        )
        .unwrap(),
    );
    let health = || async {
        let response = app
            .clone()
            .oneshot(
                Request::get("/v1/health/detail")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        body["speaker"]["vpn_families"].clone()
    };
    // Five concurrent requests, then five more inside the same window.
    let concurrent = futures_util::future::join_all((0..5).map(|_| health())).await;
    for _ in 0..5 {
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        health().await;
    }
    assert_eq!(speaker.0.load(SeqCst), 2, "one probe per family per window");
    let families = concurrent[0].as_array().unwrap();
    assert_eq!(families.len(), 2);
    for family in families {
        assert_eq!(family["status"], "supported");
        assert!(
            family["observed_at"].is_string(),
            "a cached result is dated"
        );
    }
    tokio::time::advance(std::time::Duration::from_secs(6)).await;
    health().await;
    assert_eq!(speaker.0.load(SeqCst), 4, "an expired window probes again");
}

/// ADR 033: a detector prefix event inherits the automatic VPN default scope
/// exactly as a host event does, and the resolved scope is the saved snapshot.
fn prefix_settings() -> Settings {
    let mut settings = common::test_settings();
    settings.mode = OperationMode::Enforced;
    settings.guardrails.allow_detector_prefix = true;
    settings.guardrails.detector_prefix_sources = vec!["vpn-detector".into()];
    settings.guardrails.dst_prefix_minlen = 24;
    settings.guardrails.dst_prefix_maxlen = 32;
    settings.guardrails.dst_prefix_minlen_v6 = Some(48);
    settings.guardrails.dst_prefix_maxlen_v6 = Some(128);
    settings.bgp.vpn_scopes = serde_json::from_value(json!({
        "TRANSIT": {"family":"ipv4","rd":"44407:40","route_targets":["44407:777"]},
        "NEXT4": {"family":"ipv4","rd":"44407:41","route_targets":["44407:778"]}
    }))
    .unwrap();
    settings.bgp.default_scope = "TRANSIT".into();
    settings
}

fn prefix_state(
    settings: Settings,
    repo: Arc<MockRepository>,
    speaker: Arc<MockAnnouncer>,
) -> Arc<AppState> {
    let mut inventory = common::test_inventory();
    inventory.customers[0]
        .prefixes
        .push("2001:db8:100::/48".into());
    let mut playbooks = common::test_playbooks();
    playbooks.playbooks.push(Playbook {
        name: "carpet_udp".into(),
        match_criteria: PlaybookMatch {
            vector: AttackVector::UdpFlood,
            require_top_ports: true,
            scope: EventScope::Prefix,
        },
        correlation: None,
        steps: vec![PlaybookStep {
            action: Some(PlaybookAction::Discard),
            rate_bps: None,
            ttl_seconds: 120,
            require_confidence_at_least: None,
            require_persistence_seconds: None,
            rules: Vec::new(),
        }],
    });
    AppState::new(settings, inventory, playbooks, repo, speaker, ".".into()).unwrap()
}

fn prefix_event(id: &str, victim: &str, ports: &[u16]) -> Value {
    json!({"event_id":id,"timestamp":chrono::Utc::now(),"source":"vpn-detector",
        "victim_ip":victim,"vector":"udp_flood","action":"ban",
        "confidence":0.99,"top_dst_ports":ports})
}

#[tokio::test]
async fn detector_prefix_event_inherits_vpn_default_scope_and_snapshots_it() {
    let repo = Arc::new(MockRepository::new());
    let speaker = Arc::new(MockAnnouncer::new());
    let app = create_test_router(prefix_state(
        prefix_settings(),
        repo.clone(),
        speaker.clone(),
    ));
    let body = post(
        &app,
        "/v1/events",
        prefix_event("carpet", "203.0.113.0/24", &[53]),
        StatusCode::ACCEPTED,
    )
    .await;
    let id: Uuid = body["mitigation_id"].as_str().unwrap().parse().unwrap();
    let saved = repo.get_mitigation(id).await.unwrap().unwrap();
    assert_eq!(saved.match_criteria.dst_prefix, "203.0.113.0/24");
    assert_eq!(saved.match_criteria.protocol, Some(17));
    assert_eq!(saved.match_criteria.dst_ports, vec![53]);
    let snapshot = saved
        .match_criteria
        .scope
        .as_ref()
        .expect("the automatic default scope is part of the saved prefix mitigation");
    assert_eq!(snapshot.name, "TRANSIT");
    assert_eq!(snapshot.identity.family, VpnFlowSpecFamily::Ipv4);
    assert_eq!(snapshot.identity.rd(), "44407:40");
    assert_eq!(snapshot.route_targets, vec!["44407:777"]);
    assert_eq!(
        saved.scope_hash,
        saved.match_criteria.scope_hash_for(saved.action_type),
        "the stored identity is the scoped one, not a global hash"
    );

    let rules = speaker.list_active().await.unwrap();
    assert_eq!(rules.len(), 1);
    let rule = &rules[0];
    assert_eq!(rule.nlri.dst_prefix, "203.0.113.0/24");
    assert_eq!(rule.nlri.protocol, Some(17));
    assert_eq!(rule.nlri.dst_ports, vec![53]);
    assert_eq!(rule.actions[0].action_type, ActionType::Discard);
    let wire_scope = rule
        .nlri
        .scope
        .as_ref()
        .expect("a prefix rule under a VPN default scope is originated in that VRF");
    assert_eq!(wire_scope.family, VpnFlowSpecFamily::Ipv4);
    assert_eq!(wire_scope.rd(), "44407:40");
    assert_eq!(rule.route_targets, vec!["44407:777"]);
    assert_eq!(rule.nlri_hash(), saved.scope_hash);
}

#[tokio::test]
async fn ipv6_detector_prefix_under_ipv4_default_scope_is_refused_without_global_fallback() {
    let repo = Arc::new(MockRepository::new());
    let speaker = Arc::new(MockAnnouncer::new());
    let app = create_test_router(prefix_state(
        prefix_settings(),
        repo.clone(),
        speaker.clone(),
    ));
    let (status, body) = {
        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/events")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        prefix_event("carpet-v6", "2001:db8:100::/48", &[53]).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        (status, body)
    };
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("automatic default_scope family does not match"),
        "{body}"
    );
    assert!(
        repo.find_ban_event_by_external_id("vpn-detector", "carpet-v6")
            .await
            .unwrap()
            .is_none(),
        "the refused event is not consumed"
    );
    assert_eq!(repo.count_active_global().await.unwrap(), 0);
    assert!(
        speaker.list_active().await.unwrap().is_empty(),
        "a family mismatch must never fall back to a global announcement"
    );
}

#[tokio::test]
async fn detector_prefix_dry_run_uses_the_same_vpn_decision_without_a_speaker_call() {
    async fn decision(mode: OperationMode) -> (Value, Value, usize, Option<OperationMode>) {
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(MockAnnouncer::new());
        let mut settings = prefix_settings();
        settings.mode = mode;
        let app = create_test_router(prefix_state(settings, repo.clone(), speaker.clone()));
        let body = post(
            &app,
            "/v1/events",
            prefix_event("carpet", "203.0.113.0/24", &[53]),
            StatusCode::ACCEPTED,
        )
        .await;
        let id: Uuid = body["mitigation_id"].as_str().unwrap().parse().unwrap();
        let saved = repo.get_mitigation(id).await.unwrap().unwrap();
        let rule = mitigation_rule(&saved).unwrap();
        let origin_mode = saved.origin_mode;
        (
            body["status"].clone(),
            serde_json::to_value(&rule).unwrap(),
            speaker.list_active().await.unwrap().len(),
            origin_mode,
        )
    }

    let (dry_status, dry_rule, dry_announcements, dry_origin) =
        decision(OperationMode::DryRun).await;
    let (enforced_status, enforced_rule, enforced_announcements, enforced_origin) =
        decision(OperationMode::Enforced).await;
    assert_eq!(dry_status, enforced_status);
    assert_eq!(
        dry_rule, enforced_rule,
        "dry run resolves the same scoped rule as enforced mode"
    );
    assert_eq!(dry_rule["nlri"]["scope"]["rd"], "44407:40");
    assert_eq!(dry_rule["route_targets"], json!(["44407:777"]));
    assert_eq!(dry_announcements, 0, "dry run never calls the speaker");
    assert_eq!(enforced_announcements, 1);
    assert_eq!(dry_origin, Some(OperationMode::DryRun));
    assert_eq!(enforced_origin, Some(OperationMode::Enforced));
}

#[tokio::test]
async fn reconciliation_and_withdrawal_reuse_the_saved_prefix_scope_snapshot() {
    let repo = Arc::new(MockRepository::new());
    let speaker = Arc::new(MockAnnouncer::new());
    let initial = prefix_state(prefix_settings(), repo.clone(), speaker.clone());
    let app = create_test_router(initial.clone());
    let body = post(
        &app,
        "/v1/events",
        prefix_event("carpet", "203.0.113.0/24", &[53]),
        StatusCode::ACCEPTED,
    )
    .await;
    let id: Uuid = body["mitigation_id"].as_str().unwrap().parse().unwrap();
    let saved = repo.get_mitigation(id).await.unwrap().unwrap();
    assert_eq!(saved.match_criteria.scope.as_ref().unwrap().name, "TRANSIT");
    assert_eq!(speaker.list_active().await.unwrap().len(), 1);
    drop(app);

    // A daemon restart loses the rule; meanwhile the operator points the
    // automatic default at another IPv4 scope.
    speaker.restart().await;
    assert!(speaker.list_active().await.unwrap().is_empty());
    let mut changed = prefix_settings();
    changed.bgp.default_scope = "NEXT4".into();
    let restarted = prefix_state(changed, repo.clone(), speaker.clone());
    let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false)
        .with_app_state(restarted.clone());
    reconciler.reconcile().await.unwrap();

    let repaired = speaker.list_active().await.unwrap();
    assert_eq!(repaired.len(), 1);
    let rule = &repaired[0];
    assert_eq!(rule.nlri.dst_prefix, "203.0.113.0/24");
    assert_eq!(rule.nlri.protocol, Some(17));
    assert_eq!(rule.nlri.dst_ports, vec![53]);
    assert_eq!(rule.actions[0].action_type, ActionType::Discard);
    let scope = rule
        .nlri
        .scope
        .as_ref()
        .expect("repair keeps the admitted VPN scope");
    assert_eq!(
        scope.rd(),
        "44407:40",
        "repair uses the saved snapshot, not the new default scope"
    );
    assert_eq!(scope.family, VpnFlowSpecFamily::Ipv4);
    assert_eq!(rule.route_targets, vec!["44407:777"]);
    assert_eq!(rule.nlri_hash(), saved.scope_hash);

    // Withdrawal also follows the saved snapshot after the default changed.
    let app = create_test_router(restarted);
    let mut unban = prefix_event("carpet", "203.0.113.0/24", &[53]);
    unban["action"] = json!("unban");
    post(&app, "/v1/events", unban, StatusCode::ACCEPTED).await;
    assert!(
        speaker.list_active().await.unwrap().is_empty(),
        "the saved scoped rule was withdrawn; a rule built from the new default would not match"
    );
    assert!(!repo.get_mitigation(id).await.unwrap().unwrap().is_active());
}
