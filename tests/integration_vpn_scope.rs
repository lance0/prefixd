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
    config::{OperationMode, Settings},
    db::{MockRepository, RepositoryTrait},
};
use serde_json::{Value, json};
use tower::ServiceExt;

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
