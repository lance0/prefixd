mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use prefixd::{
    AppState,
    api::create_test_router,
    bgp::{FlowSpecReader, MockAnnouncer},
    config::{Customer, Inventory, OperationMode, PolicyProfile},
    db::{MockRepository, RepositoryTrait},
    domain::AttackVector,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

fn state(
    vector: AttackVector,
    relaxed_v6: bool,
) -> (Arc<AppState>, Arc<MockRepository>, Arc<MockAnnouncer>) {
    let repo = Arc::new(MockRepository::new());
    let speaker = Arc::new(MockAnnouncer::new());
    let mut settings = common::test_settings();
    settings.mode = OperationMode::Enforced;
    if relaxed_v6 {
        settings.guardrails.dst_prefix_minlen_v6 = Some(32);
    }
    let inventory = Inventory::new(vec![Customer {
        customer_id: "family-test".into(),
        name: "Address family test".into(),
        prefixes: vec!["203.0.113.0/24".into(), "2001:db8::/32".into()],
        policy_profile: PolicyProfile::Normal,
        services: vec![],
    }]);
    let mut playbooks = common::test_playbooks();
    playbooks.playbooks[0].match_criteria.vector = vector;
    let state = AppState::new(
        settings,
        inventory,
        playbooks,
        repo.clone(),
        speaker.clone(),
        ".".into(),
    )
    .unwrap();
    (state, repo, speaker)
}

fn prefix_state(
    allow_detector_prefix: bool,
    sources: Vec<&str>,
    prefixes: Vec<&str>,
) -> (Arc<AppState>, Arc<MockRepository>, Arc<MockAnnouncer>) {
    let repo = Arc::new(MockRepository::new());
    let speaker = Arc::new(MockAnnouncer::new());
    let mut settings = common::test_settings();
    settings.mode = OperationMode::Enforced;
    settings.guardrails.allow_detector_prefix = allow_detector_prefix;
    settings.guardrails.detector_prefix_sources = sources.into_iter().map(str::to_string).collect();
    settings.guardrails.dst_prefix_minlen = 24;
    settings.guardrails.dst_prefix_maxlen = 32;
    settings.guardrails.dst_prefix_minlen_v6 = Some(48);
    settings.guardrails.dst_prefix_maxlen_v6 = Some(128);
    let inventory = Inventory::new(vec![Customer {
        customer_id: "family-test".into(),
        name: "Address family test".into(),
        prefixes: prefixes.into_iter().map(str::to_string).collect(),
        policy_profile: PolicyProfile::Normal,
        services: vec![],
    }]);
    let mut playbooks = common::test_playbooks();
    playbooks.playbooks.push(prefixd::config::Playbook {
        name: "carpet_udp".into(),
        match_criteria: prefixd::config::PlaybookMatch {
            vector: AttackVector::UdpFlood,
            require_top_ports: true,
            scope: prefixd::config::EventScope::Prefix,
        },
        correlation: None,
        steps: vec![prefixd::config::PlaybookStep {
            action: Some(prefixd::config::PlaybookAction::Discard),
            rate_bps: None,
            ttl_seconds: 120,
            require_confidence_at_least: None,
            require_persistence_seconds: None,
            rules: Vec::new(),
        }],
    });
    let state = AppState::new(
        settings,
        inventory,
        playbooks,
        repo.clone(),
        speaker.clone(),
        ".".into(),
    )
    .unwrap();
    (state, repo, speaker)
}

async fn ingest_with_ports(
    state: Arc<AppState>,
    ip: &str,
    vector: AttackVector,
    event_id: &str,
    ports: &[u16],
) -> (StatusCode, Value) {
    let response = create_test_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "event_id": event_id,
                        "timestamp": "2026-10-17T00:00:00Z",
                        "source": "family-test",
                        "victim_ip": ip,
                        "vector": vector,
                        "confidence": 0.99,
                        "top_dst_ports": ports,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

async fn ingest(
    state: Arc<AppState>,
    ip: &str,
    vector: AttackVector,
    event_id: &str,
) -> (StatusCode, Value) {
    let response = create_test_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "event_id": event_id,
                        "timestamp": "2026-10-17T00:00:00Z",
                        "source": "family-test",
                        "victim_ip": ip,
                        "vector": vector,
                        "confidence": 0.99,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

async fn assert_automatic_host_rules(addresses: &[(&str, &str)], ipv6: bool) {
    for (vector, v4_protocol, v6_protocol) in [
        (AttackVector::UdpFlood, 17, 17),
        (AttackVector::SynFlood, 6, 6),
        (AttackVector::AckFlood, 6, 6),
        (AttackVector::IcmpFlood, 1, 58),
    ] {
        let protocol = if ipv6 { v6_protocol } else { v4_protocol };
        for &(ip, prefix) in addresses {
            let (state, repo, speaker) = state(vector, false);
            let (status, body) = ingest(state, ip, vector, "host").await;
            assert_eq!(status, StatusCode::ACCEPTED, "{vector} {ip}: {body}");
            let id: Uuid = body["mitigation_id"]
                .as_str()
                .expect("created mitigation")
                .parse()
                .unwrap();
            let mitigation = repo.get_mitigation(id).await.unwrap().unwrap();
            assert_eq!(mitigation.match_criteria.dst_prefix, prefix);
            assert_eq!(mitigation.match_criteria.protocol, Some(protocol));
            let event = repo
                .find_ban_event_by_external_id("family-test", "host")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(event.protocol, Some(i32::from(protocol)));
            let rules = speaker.list_active().await.unwrap();
            assert_eq!(rules.len(), 1);
            assert_eq!(rules[0].nlri.dst_prefix, prefix);
            assert_eq!(rules[0].nlri.protocol, Some(protocol));
        }
    }
}

#[tokio::test]
async fn automatic_ipv4_controls_remain_host_scoped() {
    assert_automatic_host_rules(&[("203.0.113.10", "203.0.113.10/32")], false).await;
}

#[tokio::test]
async fn automatic_ipv6_events_announce_only_family_correct_hosts() {
    assert_automatic_host_rules(
        &[
            ("2001:db8::10", "2001:db8::10/128"),
            (
                "2001:0DB8:0000:0000:0000:0000:0000:0010",
                "2001:db8::10/128",
            ),
        ],
        true,
    )
    .await;
}

#[tokio::test]
async fn expanded_ipv6_extends_one_host_even_with_relaxed_prefix_guardrails() {
    let (state, repo, speaker) = state(AttackVector::IcmpFlood, true);
    let (first_status, first) = ingest(
        state.clone(),
        "2001:db8::10",
        AttackVector::IcmpFlood,
        "first",
    )
    .await;
    assert_eq!(first_status, StatusCode::ACCEPTED);
    let (second_status, second) = ingest(
        state,
        "2001:0DB8:0000:0000:0000:0000:0000:0010",
        AttackVector::IcmpFlood,
        "second",
    )
    .await;
    assert_eq!(second_status, StatusCode::ACCEPTED);
    assert_eq!(second["status"], "extended");
    assert_eq!(first["mitigation_id"], second["mitigation_id"]);
    assert_eq!(repo.count_active_global().await.unwrap(), 1);
    let rules = speaker.list_active().await.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].nlri.dst_prefix, "2001:db8::10/128");
    assert_eq!(rules[0].nlri.protocol, Some(58));
}

#[tokio::test]
async fn invalid_destinations_are_rejected_before_event_or_speaker_mutation() {
    let (state, repo, speaker) = state(AttackVector::UdpFlood, false);
    for ip in [
        "invalid",
        "203.0.113.10/24",
        "2001:db8::10/32",
        "fe80::1%eth0",
    ] {
        let (status, _) = ingest(state.clone(), ip, AttackVector::UdpFlood, ip).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{ip}");
        assert!(
            repo.find_ban_event_by_external_id("family-test", ip)
                .await
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(repo.count_active_global().await.unwrap(), 0);
    assert!(speaker.list_active().await.unwrap().is_empty());
}

#[tokio::test]
async fn guarded_detector_prefix_announces_one_covering_rule() {
    let (state, repo, speaker) = prefix_state(true, vec!["family-test"], vec!["203.0.113.0/24"]);
    let (status, body) = ingest_with_ports(
        state,
        "203.0.113.0/24",
        AttackVector::UdpFlood,
        "carpet",
        &[53],
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let id: Uuid = body["mitigation_id"].as_str().unwrap().parse().unwrap();
    let mitigation = repo.get_mitigation(id).await.unwrap().unwrap();
    assert_eq!(mitigation.victim_ip, "203.0.113.0/24");
    assert_eq!(mitigation.match_criteria.dst_prefix, "203.0.113.0/24");
    assert_eq!(mitigation.match_criteria.protocol, Some(17));
    assert_eq!(mitigation.match_criteria.dst_ports, vec![53]);
    let rules = speaker.list_active().await.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].nlri.dst_prefix, "203.0.113.0/24");
    assert_eq!(rules[0].nlri.dst_ports, vec![53]);
}

#[tokio::test]
async fn detector_prefix_requires_flag_and_matching_source_before_persistence() {
    for (allowed, sources) in [(false, vec!["family-test"]), (true, vec!["other-detector"])] {
        let (state, repo, speaker) = prefix_state(allowed, sources, vec!["203.0.113.0/24"]);
        let (status, _) = ingest_with_ports(
            state,
            "203.0.113.0/24",
            AttackVector::UdpFlood,
            "carpet",
            &[53],
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            repo.find_ban_event_by_external_id("family-test", "carpet")
                .await
                .unwrap()
                .is_none()
        );
        assert!(speaker.list_active().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn detector_prefix_refuses_safelist_overlap_and_ambiguous_ownership() {
    let (state, repo, speaker) = prefix_state(true, vec!["family-test"], vec!["203.0.113.0/24"]);
    repo.insert_safelist("203.0.113.10/32", "test", None)
        .await
        .unwrap();
    let (status, _) = ingest_with_ports(
        state.clone(),
        "203.0.113.0/24",
        AttackVector::UdpFlood,
        "safelisted",
        &[53],
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(speaker.list_active().await.unwrap().is_empty());

    let (state, repo, speaker) = prefix_state(true, vec!["family-test"], vec!["203.0.113.0/24"]);
    let mut inventory = state.inventory.write().await;
    let mut second = inventory.customers[0].clone();
    second.customer_id = "other".into();
    second.prefixes = vec!["203.0.113.0/25".into()];
    inventory.customers.push(second);
    drop(inventory);
    let (status, _) = ingest_with_ports(
        state,
        "203.0.113.0/24",
        AttackVector::UdpFlood,
        "ambiguous",
        &[53],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(repo.count_active_global().await.unwrap(), 0);
    assert!(speaker.list_active().await.unwrap().is_empty());
}

#[tokio::test]
async fn detector_prefix_has_a_separate_customer_budget() {
    let (mut state, repo, speaker) = prefix_state(
        true,
        vec!["family-test"],
        vec!["203.0.113.0/24", "198.51.100.0/24"],
    );
    Arc::get_mut(&mut state)
        .unwrap()
        .settings
        .quotas
        .max_active_prefix_per_customer = 1;
    let (first, first_body) = ingest_with_ports(
        state.clone(),
        "203.0.113.0/24",
        AttackVector::UdpFlood,
        "first-prefix",
        &[53],
    )
    .await;
    assert_eq!(first, StatusCode::ACCEPTED, "{first_body}");
    let (second, second_body) = ingest_with_ports(
        state,
        "198.51.100.0/24",
        AttackVector::UdpFlood,
        "second-prefix",
        &[53],
    )
    .await;
    assert_eq!(second, StatusCode::UNPROCESSABLE_ENTITY, "{second_body}");
    assert_eq!(repo.count_active_global().await.unwrap(), 1);
    assert_eq!(speaker.list_active().await.unwrap().len(), 1);
}

#[tokio::test]
async fn detector_prefix_police_can_run_without_a_port() {
    let (state, repo, speaker) = prefix_state(true, vec!["family-test"], vec!["203.0.113.0/24"]);
    {
        let mut playbooks = state.playbooks.write().await;
        let prefix = playbooks
            .playbooks
            .iter_mut()
            .find(|playbook| playbook.name == "carpet_udp")
            .unwrap();
        prefix.match_criteria.require_top_ports = false;
        prefix.steps[0].action = Some(prefixd::config::PlaybookAction::Police);
        prefix.steps[0].rate_bps = Some(50_000_000);
    }
    let (status, body) = ingest_with_ports(
        state,
        "203.0.113.0/24",
        AttackVector::UdpFlood,
        "prefix-police",
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let id: Uuid = body["mitigation_id"].as_str().unwrap().parse().unwrap();
    let mitigation = repo.get_mitigation(id).await.unwrap().unwrap();
    assert_eq!(mitigation.match_criteria.dst_prefix, "203.0.113.0/24");
    assert_eq!(mitigation.match_criteria.protocol, Some(17));
    assert!(mitigation.match_criteria.dst_ports.is_empty());
    assert_eq!(mitigation.action_type, prefixd::domain::ActionType::Police);
    assert_eq!(speaker.list_active().await.unwrap().len(), 1);
}

#[tokio::test]
async fn detector_prefix_discard_without_a_port_is_refused() {
    let (state, _repo, speaker) = prefix_state(true, vec!["family-test"], vec!["203.0.113.0/24"]);
    let (status, body) = ingest_with_ports(
        state,
        "203.0.113.0/24",
        AttackVector::UdpFlood,
        "prefix-no-port",
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(body["status"], "accepted_no_playbook");
    assert!(speaker.list_active().await.unwrap().is_empty());
}

#[tokio::test]
async fn host_length_cidrs_are_normalized_before_inventory_lookup() {
    for (input, expected) in [
        ("203.0.113.10/32", "203.0.113.10"),
        ("2001:db8::10/128", "2001:db8::10"),
    ] {
        let (state, repo, speaker) = state(AttackVector::UdpFlood, false);
        let (status, body) = ingest(state, input, AttackVector::UdpFlood, input).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{input}: {body}");
        let id: Uuid = body["mitigation_id"].as_str().unwrap().parse().unwrap();
        let mitigation = repo.get_mitigation(id).await.unwrap().unwrap();
        assert_eq!(mitigation.victim_ip, expected);
        assert_eq!(
            mitigation.match_criteria.dst_prefix,
            format!(
                "{expected}/{}",
                if expected.contains(':') { 128 } else { 32 }
            )
        );
        assert_eq!(speaker.list_active().await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn prefix_safelist_rejection_does_not_consume_the_event_or_block_extension_checks() {
    let (state, repo, speaker) = prefix_state(true, vec!["family-test"], vec!["203.0.113.0/24"]);
    let (status, body) = ingest_with_ports(
        state.clone(),
        "203.0.113.0/24",
        AttackVector::UdpFlood,
        "first",
        &[53],
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let original = repo
        .get_mitigation(body["mitigation_id"].as_str().unwrap().parse().unwrap())
        .await
        .unwrap()
        .unwrap();

    repo.insert_safelist("203.0.113.0/24", "test", None)
        .await
        .unwrap();
    let (status, body) = ingest_with_ports(
        state.clone(),
        "203.0.113.0/24",
        AttackVector::UdpFlood,
        "would-be-extension",
        &[53],
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(repo.count_active_global().await.unwrap(), 1);
    assert_eq!(speaker.list_active().await.unwrap().len(), 1);
    let saved = repo
        .get_mitigation(original.mitigation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(saved.expires_at, original.expires_at);

    repo.remove_safelist("203.0.113.0/24").await.unwrap();
    let (status, body) = ingest_with_ports(
        state,
        "203.0.113.0/24",
        AttackVector::UdpFlood,
        "would-be-extension",
        &[53],
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
}

#[tokio::test]
async fn prefix_customer_transfer_is_rejected_before_extension() {
    let (state, repo, speaker) = prefix_state(true, vec!["family-test"], vec!["203.0.113.0/24"]);
    let (status, body) = ingest_with_ports(
        state.clone(),
        "203.0.113.0/24",
        AttackVector::UdpFlood,
        "owner-a",
        &[53],
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let original = repo
        .get_mitigation(body["mitigation_id"].as_str().unwrap().parse().unwrap())
        .await
        .unwrap()
        .unwrap();

    {
        let mut inventory = state.inventory.write().await;
        inventory.customers[0].customer_id = "new-owner".into();
    }
    let (status, body) = ingest_with_ports(
        state,
        "203.0.113.0/24",
        AttackVector::UdpFlood,
        "owner-b",
        &[53],
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(repo.count_active_global().await.unwrap(), 1);
    assert_eq!(speaker.list_active().await.unwrap().len(), 1);
    let saved = repo
        .get_mitigation(original.mitigation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(saved.customer_id.as_deref(), Some("family-test"));
    assert_eq!(saved.expires_at, original.expires_at);
}

async fn post(state: Arc<AppState>, uri: &str, body: Value) -> (StatusCode, Value) {
    let response = create_test_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

fn prefix_event(event_id: &str, victim: &str, ports: &[u16]) -> Value {
    json!({
        "event_id": event_id,
        "timestamp": "2026-10-17T00:00:00Z",
        "source": "family-test",
        "victim_ip": victim,
        "vector": "udp_flood",
        "confidence": 0.99,
        "top_dst_ports": ports,
    })
}

async fn ban_prefix(state: &Arc<AppState>, event_id: &str) -> Uuid {
    let (status, body) = post(
        state.clone(),
        "/v1/events",
        prefix_event(event_id, "203.0.113.0/24", &[53]),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    body["mitigation_id"].as_str().unwrap().parse().unwrap()
}

#[tokio::test]
async fn ipv6_detector_prefix_announces_one_covering_rule() {
    let (state, repo, speaker) = prefix_state(true, vec!["family-test"], vec!["2001:db8:100::/48"]);
    let (status, body) = post(
        state,
        "/v1/events",
        prefix_event("carpet-v6", "2001:db8:100::/48", &[53]),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let id: Uuid = body["mitigation_id"].as_str().unwrap().parse().unwrap();
    let mitigation = repo.get_mitigation(id).await.unwrap().unwrap();
    assert_eq!(mitigation.match_criteria.dst_prefix, "2001:db8:100::/48");
    assert_eq!(mitigation.match_criteria.protocol, Some(17));
    let rules = speaker.list_active().await.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].nlri.dst_prefix, "2001:db8:100::/48");
    assert_eq!(rules[0].nlri.dst_ports, vec![53]);
}

#[tokio::test]
async fn detector_prefix_outside_the_length_bounds_is_refused_before_persistence() {
    // The minimum is /24, so an owned /22 is still too broad.
    let (state, repo, speaker) = prefix_state(true, vec!["family-test"], vec!["203.0.112.0/22"]);
    let (status, body) = post(
        state,
        "/v1/events",
        prefix_event("too-wide", "203.0.112.0/22", &[53]),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(
        repo.find_ban_event_by_external_id("family-test", "too-wide")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(repo.count_active_global().await.unwrap(), 0);
    assert!(speaker.list_active().await.unwrap().is_empty());
}

#[tokio::test]
async fn detector_prefix_unban_by_event_id_withdraws_the_prefix_rule() {
    let (state, repo, speaker) = prefix_state(true, vec!["family-test"], vec!["203.0.113.0/24"]);
    let id = ban_prefix(&state, "carpet").await;
    let mut unban = prefix_event("carpet", "203.0.113.0/24", &[53]);
    unban["action"] = json!("unban");
    let (status, body) = post(state.clone(), "/v1/events", unban).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert!(!repo.get_mitigation(id).await.unwrap().unwrap().is_active());
    assert!(speaker.list_active().await.unwrap().is_empty());

    // An unknown prefix event ID is answered like a host one.
    let mut unknown = prefix_event("never-sent", "203.0.113.0/24", &[53]);
    unknown["action"] = json!("unban");
    let (status, body) = post(state, "/v1/events", unknown).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "not_found");
}

#[tokio::test]
async fn resent_detector_prefix_with_a_new_event_id_extends_the_same_rule() {
    let (state, repo, speaker) = prefix_state(true, vec!["family-test"], vec!["203.0.113.0/24"]);
    let id = ban_prefix(&state, "first").await;
    let (status, body) = post(
        state,
        "/v1/events",
        prefix_event("second", "203.0.113.0/24", &[53]),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "extended", "{body}");
    assert_eq!(body["mitigation_id"], id.to_string());
    assert_eq!(repo.count_active_global().await.unwrap(), 1);
    assert_eq!(speaker.list_active().await.unwrap().len(), 1);
}

#[tokio::test]
async fn batch_ingestion_admits_a_detector_prefix_event() {
    let (state, repo, speaker) = prefix_state(true, vec!["family-test"], vec!["203.0.113.0/24"]);
    let (status, body) = post(
        state,
        "/v1/events/batch",
        json!({ "events": [prefix_event("batched", "203.0.113.0/24", &[53])] }),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["accepted"], 1, "{body}");
    let id: Uuid = body["results"][0]["mitigation_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let mitigation = repo.get_mitigation(id).await.unwrap().unwrap();
    assert_eq!(mitigation.match_criteria.dst_prefix, "203.0.113.0/24");
    assert_eq!(speaker.list_active().await.unwrap().len(), 1);
}

#[tokio::test]
async fn host_event_inside_an_active_prefix_creates_its_own_host_rule() {
    let (state, repo, speaker) = prefix_state(true, vec!["family-test"], vec!["203.0.113.0/24"]);
    let prefix = ban_prefix(&state, "carpet").await;
    let (status, body) = post(
        state,
        "/v1/events",
        prefix_event("one-host", "203.0.113.10", &[53]),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let host: Uuid = body["mitigation_id"].as_str().unwrap().parse().unwrap();
    assert_ne!(host, prefix);
    let host = repo.get_mitigation(host).await.unwrap().unwrap();
    assert_eq!(host.match_criteria.dst_prefix, "203.0.113.10/32");
    assert!(
        repo.get_mitigation(prefix)
            .await
            .unwrap()
            .unwrap()
            .is_active()
    );
    assert_eq!(speaker.list_active().await.unwrap().len(), 2);
}

#[tokio::test]
async fn safelisting_a_host_inside_a_detector_prefix_withdraws_the_prefix_rule() {
    let (state, repo, speaker) = prefix_state(true, vec!["family-test"], vec!["203.0.113.0/24"]);
    let id = ban_prefix(&state, "carpet").await;
    let (status, body) = post(
        state,
        "/v1/safelist",
        json!({ "operator_id": "test", "prefix": "203.0.113.10/32", "reason": "sanctuary" }),
    )
    .await;
    assert!(status.is_success(), "{status} {body}");
    assert!(!repo.get_mitigation(id).await.unwrap().unwrap().is_active());
    assert!(speaker.list_active().await.unwrap().is_empty());
}

#[tokio::test]
async fn detector_prefix_police_never_renews_a_saved_portless_discard() {
    use prefixd::domain::{ActionParams, ActionType, MatchCriteria, Mitigation, MitigationIntent};
    let (state, repo, speaker) = prefix_state(true, vec!["family-test"], vec!["203.0.113.0/24"]);
    {
        let mut playbooks = state.playbooks.write().await;
        let prefix = playbooks
            .playbooks
            .iter_mut()
            .find(|playbook| playbook.name == "carpet_udp")
            .unwrap();
        prefix.match_criteria.require_top_ports = false;
        prefix.steps[0].action = Some(prefixd::config::PlaybookAction::Police);
        prefix.steps[0].rate_bps = Some(50_000_000);
    }
    // A manual protocol-only discard owns the same match: ownership is keyed
    // by match, not action.
    let mut manual = Mitigation::from_intent(
        MitigationIntent {
            event_id: Uuid::new_v4(),
            customer_id: Some("family-test".into()),
            service_id: None,
            pop: state.settings.pop.clone(),
            match_criteria: MatchCriteria {
                dst_prefix: "203.0.113.0/24".into(),
                protocol: Some(17),
                ..Default::default()
            },
            action_type: ActionType::Discard,
            action_params: ActionParams::default(),
            ttl_seconds: 120,
            reason: "manual portless discard".into(),
        },
        "203.0.113.0/24".into(),
        AttackVector::UdpFlood,
    );
    manual.activate();
    repo.admit_mitigation(
        &manual,
        &state.settings.quotas,
        &state.settings.blackhole,
        &prefixd::observability::CreationActor::Operator("admin".into()),
    )
    .await
    .unwrap();
    let (status, body) = post(
        state,
        "/v1/events",
        prefix_event("police", "203.0.113.0/24", &[]),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    let saved = repo
        .get_mitigation(manual.mitigation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(saved.expires_at, manual.expires_at);
    assert!(
        repo.find_ban_event_by_external_id("family-test", "police")
            .await
            .unwrap()
            .is_none()
    );
    assert!(speaker.list_active().await.unwrap().is_empty());
}

#[tokio::test]
async fn manual_cidrs_do_not_consume_or_check_the_detector_prefix_budget() {
    let (mut state, repo, _speaker) = prefix_state(
        true,
        vec!["family-test"],
        vec!["203.0.113.0/24", "198.51.100.0/24"],
    );
    Arc::get_mut(&mut state)
        .unwrap()
        .settings
        .quotas
        .max_active_prefix_per_customer = 1;
    let manual = |victim: &str, port: u16| {
        json!({
            "victim_ip": victim,
            "protocol": "udp",
            "dst_ports": [port],
            "action": "discard",
            "ttl_seconds": 300,
            "reason": "manual carpet response",
        })
    };
    for (victim, port) in [("203.0.113.0/24", 123), ("198.51.100.0/24", 123)] {
        let (status, body) = post(state.clone(), "/v1/mitigations", manual(victim, port)).await;
        assert!(status.is_success(), "{victim}: {status} {body}");
    }
    assert_eq!(
        repo.count_active_detector_prefix_by_customer("family-test")
            .await
            .unwrap(),
        0
    );
    // The detector still has its whole budget.
    ban_prefix(&state, "carpet").await;
    let (status, body) = post(
        state,
        "/v1/events",
        prefix_event("over-budget", "198.51.100.0/24", &[53]),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(
        body["error"]
            .as_str()
            .map(|e| e.contains("prefix_customer")),
        Some(true),
        "{body}"
    );
}

/// The same prefix event refuses identically in dry-run and enforced mode, and
/// dry run never reaches the speaker.
#[tokio::test]
async fn detector_prefix_refusals_match_in_dry_run_and_enforced_mode() {
    async fn outcomes(mode: OperationMode) -> (Vec<StatusCode>, usize) {
        let (mut state, repo, speaker) = prefix_state(
            true,
            vec!["family-test"],
            vec!["203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24"],
        );
        {
            let state = Arc::get_mut(&mut state).unwrap();
            state.settings.mode = mode;
            state.settings.quotas.max_active_prefix_per_customer = 1;
        }
        repo.insert_safelist("192.0.2.10/32", "test", None)
            .await
            .unwrap();
        let mut statuses = Vec::new();
        for (id, victim, ports) in [
            ("admitted", "203.0.113.0/24", &[53][..]),
            ("safelisted", "192.0.2.0/24", &[53][..]),
            ("over-quota", "198.51.100.0/24", &[53][..]),
            ("no-port-discard", "198.51.100.0/24", &[][..]),
        ] {
            let (status, body) =
                post(state.clone(), "/v1/events", prefix_event(id, victim, ports)).await;
            statuses.push(status);
            if id == "no-port-discard" {
                assert_eq!(body["status"], "accepted_no_playbook", "{mode:?}: {body}");
            }
        }
        (statuses, speaker.list_active().await.unwrap().len())
    }
    let (enforced, enforced_rules) = outcomes(OperationMode::Enforced).await;
    let (dry_run, dry_run_rules) = outcomes(OperationMode::DryRun).await;
    assert_eq!(
        enforced,
        vec![
            StatusCode::ACCEPTED,
            StatusCode::UNPROCESSABLE_ENTITY,
            StatusCode::UNPROCESSABLE_ENTITY,
            StatusCode::ACCEPTED,
        ]
    );
    assert_eq!(dry_run, enforced);
    assert_eq!(enforced_rules, 1);
    assert_eq!(dry_run_rules, 0, "dry run must not call the speaker");
}
