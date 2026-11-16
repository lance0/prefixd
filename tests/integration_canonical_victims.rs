//! Every ingest route stores one spelling of a victim, so correlation, the
//! victim filters and the unban lookup agree on it whatever form a detector
//! sends: zero-padded or uppercase IPv6, or an IPv4-mapped IPv6 host.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use prefixd::AppState;
use prefixd::api::create_test_router;
use prefixd::bgp::MockAnnouncer;
use prefixd::config::{Customer, Inventory, PolicyProfile};
use prefixd::correlation::{
    CorrelationConfig, SourceConfig, WebhookAdapter, WebhookAuth, WebhookFieldMap,
};
use prefixd::db::{
    EventListParams, ListParams, MitigationListParams, MockRepository, RepositoryTrait,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

const CANONICAL_V6: &str = "2001:db8:113::10";

/// Each non-canonical spelling a detector may send, with its canonical form.
const FORMS: [(&str, &str); 3] = [
    ("2001:0db8:0113::0010", CANONICAL_V6),
    ("2001:0DB8:113:0:0:0:0:10", CANONICAL_V6),
    ("::ffff:203.0.113.10", "203.0.113.10"),
];

struct Fixture {
    app: axum::Router,
    repo: Arc<MockRepository>,
}

async fn fixture(min_sources: u32) -> Fixture {
    let repo = Arc::new(MockRepository::new());
    let mut settings = common::test_settings();
    let source = |weight| SourceConfig {
        weight,
        r#type: "detector".into(),
        ..Default::default()
    };
    settings.correlation = CorrelationConfig {
        enabled: true,
        window_seconds: 300,
        min_sources,
        confidence_threshold: 0.1,
        sources: [
            ("fastnetmon".to_string(), source(1.0)),
            ("alertmanager".to_string(), source(1.0)),
            ("radware".to_string(), source(1.0)),
        ]
        .into(),
        default_weight: 1.0,
        ..Default::default()
    };
    let inventory = Inventory::new(vec![Customer {
        customer_id: "canonical".into(),
        name: "Canonical victims".into(),
        prefixes: vec!["203.0.113.0/24".into(), "2001:db8::/32".into()],
        policy_profile: PolicyProfile::Normal,
        services: vec![],
    }]);
    let state = AppState::new(
        settings,
        inventory,
        common::test_playbooks(),
        repo.clone(),
        Arc::new(MockAnnouncer::new()),
        ".".into(),
    )
    .unwrap();
    state.correlation_config.write().await.webhook_adapters = vec![WebhookAdapter {
        name: "radware".into(),
        description: "test".into(),
        enabled: true,
        auth: WebhookAuth::None,
        root_path: None,
        fields: WebhookFieldMap {
            victim_ip: "$.ip".into(),
            vector: Some("$.vector".into()),
            timestamp: None,
            bps: None,
            pps: None,
            confidence: Some("$.score".into()),
            source_id: Some("$.id".into()),
            top_dst_ports: None,
            top_src_ports: None,
            action: None,
        },
        vector_map: Default::default(),
        default_vector: None,
        confidence_scale: None,
        source_id_prefix: None,
        transforms: Default::default(),
    }];
    Fixture {
        app: create_test_router(state),
        repo,
    }
}

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn event(source: &str, victim: &str, id: &str, action: &str) -> Value {
    json!({
        "event_id": id, "timestamp": "2026-11-16T00:00:00Z", "source": source,
        "victim_ip": victim, "vector": "udp_flood", "confidence": 0.9, "action": action,
    })
}

fn fastnetmon(victim: &str, uuid: &str) -> Value {
    json!({
        "action": "ban", "ip": victim, "alert_scope": "host",
        "attack_details": {
            "attack_uuid": uuid, "attack_detection_source": "automatic",
            "incoming_udp_pps": 5000, "incoming_tcp_pps": 10, "incoming_syn_tcp_pps": 0,
            "incoming_icmp_pps": 0, "total_incoming_pps": 5010,
            "total_incoming_traffic_bits": 50000000,
        }
    })
}

fn alertmanager(victim: &str, fingerprint: &str) -> Value {
    json!({
        "version": "4", "status": "firing", "groupLabels": {}, "commonLabels": {},
        "commonAnnotations": {}, "externalURL": "http://alertmanager.example.com",
        "alerts": [{
            "status": "firing", "fingerprint": fingerprint,
            "labels": {"victim_ip": victim, "vector": "udp_flood", "severity": "critical"},
            "annotations": {}, "startsAt": "2026-11-16T00:00:00Z",
            "endsAt": "0001-01-01T00:00:00Z",
        }]
    })
}

/// Post one ban for `victim` through the named route.
async fn ban(app: &axum::Router, route: &str, victim: &str, id: &str) -> (StatusCode, Value) {
    match route {
        "events" => {
            send(
                app,
                "POST",
                "/v1/events",
                Some(event("fastnetmon", victim, id, "ban")),
            )
            .await
        }
        "batch" => {
            send(
                app,
                "POST",
                "/v1/events/batch",
                Some(json!({"events": [event("fastnetmon", victim, id, "ban")]})),
            )
            .await
        }
        "fastnetmon" => {
            send(
                app,
                "POST",
                "/v1/signals/fastnetmon",
                Some(fastnetmon(victim, id)),
            )
            .await
        }
        "alertmanager" => {
            send(
                app,
                "POST",
                "/v1/signals/alertmanager",
                Some(alertmanager(victim, id)),
            )
            .await
        }
        "webhook" => {
            send(
                app,
                "POST",
                "/v1/signals/webhook/radware",
                Some(json!({"id": id, "ip": victim, "vector": "udp_flood", "score": 0.9})),
            )
            .await
        }
        _ => unreachable!("{route}"),
    }
}

async fn stored_victims(repo: &MockRepository) -> Vec<String> {
    repo.list_events_filtered(&EventListParams {
        pagination: ListParams {
            limit: 100,
            ..Default::default()
        },
        ..Default::default()
    })
    .await
    .unwrap()
    .into_iter()
    .map(|event| event.victim_ip)
    .collect()
}

async fn mitigations(repo: &MockRepository) -> Vec<prefixd::domain::Mitigation> {
    repo.list_mitigations(
        None,
        None,
        None,
        None,
        &MitigationListParams {
            limit: 100,
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn every_ingest_route_stores_the_canonical_victim() {
    for route in ["events", "batch", "fastnetmon", "alertmanager", "webhook"] {
        for (sent, canonical) in FORMS {
            let fixture = fixture(1).await;
            let (status, body) = ban(&fixture.app, route, sent, "ban-1").await;
            assert!(status.is_success(), "{route} {sent}: {status} {body}");
            assert_eq!(
                stored_victims(&fixture.repo).await,
                [canonical],
                "{route} {sent}"
            );
            let created = mitigations(&fixture.repo).await;
            assert_eq!(created.len(), 1, "{route} {sent}: {body}");
            assert_eq!(created[0].victim_ip, canonical, "{route} {sent}");
            let suffix = if canonical.contains(':') { 128 } else { 32 };
            assert_eq!(
                created[0].match_criteria.dst_prefix,
                format!("{canonical}/{suffix}"),
                "{route} {sent}"
            );
        }
    }

    // An unban event is stored canonical too.
    let fixture = fixture(1).await;
    let (status, body) = ban(&fixture.app, "events", "2001:0DB8:0113::0010", "ban-1").await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let (status, body) = send(
        &fixture.app,
        "POST",
        "/v1/events",
        Some(event(
            "fastnetmon",
            "2001:0db8:0113::0010",
            "ban-1",
            "unban",
        )),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "withdrawn", "{body}");
    assert_eq!(
        stored_victims(&fixture.repo).await,
        [CANONICAL_V6, CANONICAL_V6]
    );
}

#[tokio::test]
async fn correlation_groups_one_victim_sent_in_two_spellings() {
    let fixture = fixture(2).await;
    let (status, body) = ban(&fixture.app, "alertmanager", CANONICAL_V6, "fp-1").await;
    assert!(status.is_success(), "{body}");
    assert!(
        mitigations(&fixture.repo).await.is_empty(),
        "one source is not enough"
    );

    let (status, body) = ban(&fixture.app, "fastnetmon", "2001:0db8:0113::0010", "uuid-1").await;
    assert!(status.is_success(), "{body}");
    let created = mitigations(&fixture.repo).await;
    assert_eq!(
        created.len(),
        1,
        "two sources for one victim meet min_sources: {body}"
    );
    assert_eq!(created[0].victim_ip, CANONICAL_V6);
    let (_, groups) = send(&fixture.app, "GET", "/v1/signal-groups", None).await;
    let groups = groups["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 1, "{groups:?}");
    assert_eq!(groups[0]["victim_ip"], CANONICAL_V6);
    assert_eq!(groups[0]["source_count"], 2);
}

#[tokio::test]
async fn victim_filters_match_every_spelling() {
    let fixture = fixture(1).await;
    let (status, body) = ban(&fixture.app, "fastnetmon", "2001:0db8:0113::0010", "uuid-1").await;
    assert!(status.is_success(), "{body}");
    let (status, body) = ban(&fixture.app, "events", "203.0.113.10", "v4-1").await;
    assert!(status.is_success(), "{body}");

    for (form, canonical) in FORMS.into_iter().chain([(CANONICAL_V6, CANONICAL_V6)]) {
        let query = form.replace(':', "%3A");
        let (status, body) = send(
            &fixture.app,
            "GET",
            &format!("/v1/mitigations?victim_ip={query}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{form}: {body}");
        let found = body["mitigations"].as_array().unwrap();
        assert_eq!(found.len(), 1, "{form}: {body}");
        assert_eq!(found[0]["victim_ip"], canonical, "{form}");

        let (status, body) = send(
            &fixture.app,
            "GET",
            &format!("/v1/ip/{query}/history"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{form}: {body}");
        assert_eq!(body["ip"], canonical, "{form}");
        assert_eq!(
            body["events"].as_array().unwrap().len(),
            1,
            "{form}: {body}"
        );
        assert_eq!(
            body["mitigations"].as_array().unwrap().len(),
            1,
            "{form}: {body}"
        );
    }
    // A value that is not an address still matches nothing rather than failing.
    let (status, body) = send(&fixture.app, "GET", "/v1/mitigations?victim_ip=bogus", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["mitigations"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn unban_lookup_finds_a_canonical_mitigation_extended_by_a_padded_ban() {
    let fixture = fixture(1).await;
    let (status, body) = ban(&fixture.app, "alertmanager", CANONICAL_V6, "fp-1").await;
    assert!(status.is_success(), "{body}");
    let created = mitigations(&fixture.repo).await;
    assert_eq!(created.len(), 1, "{body}");

    let (status, body) = ban(&fixture.app, "fastnetmon", "2001:0db8:0113::0010", "uuid-1").await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "extended", "{body}");
    let extended = mitigations(&fixture.repo).await;
    assert_eq!(extended.len(), 1);
    assert_ne!(extended[0].last_event_id, created[0].last_event_id);

    // The bundled script's unban looks the victim up as FastNetMon spells it.
    let (status, body) = send(
        &fixture.app,
        "GET",
        "/v1/mitigations?status=active&victim_ip=2001%3A0db8%3A0113%3A%3A0010",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let found = body["mitigations"].as_array().unwrap();
    assert_eq!(found.len(), 1, "{body}");
    assert_eq!(
        found[0]["mitigation_id"],
        created[0].mitigation_id.to_string()
    );
}

#[tokio::test]
async fn manual_flowspec_stores_the_canonical_victim_and_prefix() {
    for (sent, victim, prefix) in [
        ("2001:0DB8:0113::0010", CANONICAL_V6, "2001:db8:113::10/128"),
        (
            "2001:0DB8:0113::0010/128",
            CANONICAL_V6,
            "2001:db8:113::10/128",
        ),
        ("::ffff:203.0.113.10", "203.0.113.10", "203.0.113.10/32"),
        ("::ffff:203.0.113.10/128", "203.0.113.10", "203.0.113.10/32"),
    ] {
        let fixture = fixture(1).await;
        let (status, body) = send(
            &fixture.app,
            "POST",
            "/v1/mitigations",
            Some(json!({
                "victim_ip": sent, "protocol": "udp", "dst_ports": [53],
                "action": "discard", "ttl_seconds": 600, "reason": "canonical manual",
            })),
        )
        .await;
        assert!(status.is_success(), "{sent}: {status} {body}");
        let created = mitigations(&fixture.repo).await;
        assert_eq!(created.len(), 1, "{sent}");
        assert_eq!(created[0].victim_ip, victim, "{sent}");
        assert_eq!(created[0].match_criteria.dst_prefix, prefix, "{sent}");
    }
}
