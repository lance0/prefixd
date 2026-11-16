//! Source binding at every ingest route (ADR 034 §4): an ingest credential acts
//! only as the source it is bound to, Operators get no detector privilege, a
//! detector unban withdraws only what its source created for the victim on its
//! POP, and the configuration refusals hold at startup, reload and the editor.
//! These use the mock repository.

mod common;

use argon2::{Argon2, PasswordHasher};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use prefixd::AppState;
use prefixd::bgp::MockAnnouncer;
use prefixd::config::{AuthMode, Customer, Inventory, PolicyProfile, Settings};
use prefixd::correlation::{
    CorrelationConfig, MatchDimension, SourceConfig, SourceMode, WebhookAdapter, WebhookAuth,
    WebhookFieldMap,
};
use prefixd::db::{ListParams, MockRepository, RepositoryTrait};
use prefixd::domain::{MitigationStatus, OperatorRole, TokenScope};
use serde_json::{Value, json};
use std::process::Command;
use std::sync::Arc;
use tower::ServiceExt;
use tower_sessions::MemoryStore;

const PASSWORD: &str = "source-binding-test-password";

struct Fixture {
    app: Router,
    repo: Arc<MockRepository>,
    state: Arc<AppState>,
}

fn source(weight: f32) -> SourceConfig {
    SourceConfig {
        weight,
        r#type: "detector".into(),
        ..Default::default()
    }
}

fn webhook_adapter(name: &str, auth: WebhookAuth) -> WebhookAdapter {
    WebhookAdapter {
        name: name.into(),
        description: "test".into(),
        enabled: true,
        auth,
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
            action: Some("$.action".into()),
        },
        vector_map: Default::default(),
        default_vector: None,
        confidence_scale: None,
        source_id_prefix: None,
        transforms: Default::default(),
    }
}

fn settings(mode: AuthMode, pop: &str, min_sources: u32) -> Settings {
    let mut settings = common::test_settings();
    settings.pop = pop.into();
    settings.http.auth.mode = mode;
    if mode == AuthMode::Mtls {
        // Router-level requests stand for requests after native TLS verified
        // the client certificate; the paths are never opened here.
        settings.http.tls = Some(prefixd::config::TlsConfig {
            cert_path: "cert.pem".into(),
            key_path: "key.pem".into(),
            ca_path: Some("ca.pem".into()),
        });
    }
    settings.correlation = CorrelationConfig {
        enabled: true,
        window_seconds: 300,
        min_sources,
        confidence_threshold: 0.1,
        sources: [
            ("fastnetmon".to_string(), source(1.0)),
            ("alertmanager".to_string(), source(1.0)),
            ("radware".to_string(), source(1.0)),
            ("heavy".to_string(), source(3.0)),
            (
                "router-cpu".to_string(),
                SourceConfig {
                    mode: SourceMode::Corroborating,
                    match_dimensions: vec![MatchDimension::Pop],
                    ..source(1.0)
                },
            ),
        ]
        .into(),
        default_weight: 1.0,
        ..Default::default()
    };
    settings
}

async fn fixture_with(settings: Settings, repo: Arc<MockRepository>) -> Fixture {
    let inventory = Inventory::new(vec![Customer {
        customer_id: "bound".into(),
        name: "Source binding".into(),
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
    state.correlation_config.write().await.webhook_adapters =
        vec![webhook_adapter("radware", WebhookAuth::Bearer)];
    let app =
        prefixd::api::create_test_router_with_session_store(state.clone(), MemoryStore::default());
    Fixture { app, repo, state }
}

async fn fixture(mode: AuthMode) -> Fixture {
    fixture_with(
        settings(mode, "test-pop", 1),
        Arc::new(MockRepository::new()),
    )
    .await
}

async fn send(
    app: &Router,
    path: &str,
    auth: Option<(&str, &str)>,
    body: &Value,
) -> (StatusCode, Value) {
    let mut request = Request::post(path).header("content-type", "application/json");
    if let Some((name, value)) = auth {
        request = request.header(name, value);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
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

async fn login(app: &Router, repo: &MockRepository, username: &str, role: OperatorRole) -> String {
    let hash = Argon2::default()
        .hash_password_with_salt(PASSWORD.as_bytes(), b"source-binding-tests")
        .unwrap()
        .to_string();
    repo.create_operator(username, &hash, role, None)
        .await
        .unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::post("/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"username": username, "password": PASSWORD}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

fn event(source: &str, victim: &str, id: &str) -> Value {
    json!({
        "event_id": id, "timestamp": chrono::Utc::now(), "source": source,
        "victim_ip": victim, "vector": "udp_flood", "confidence": 0.9,
    })
}

fn unban(source: &str, victim: &str, id: &str) -> Value {
    let mut unban = event(source, victim, id);
    unban["action"] = "unban".into();
    unban
}

fn fastnetmon(victim: &str, uuid: &str, scope: &str) -> Value {
    json!({
        "action": "ban", "ip": victim, "alert_scope": scope,
        "attack_details": {
            "attack_uuid": uuid, "incoming_udp_pps": 5000, "total_incoming_pps": 5000,
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

/// What an ingest request left behind: events, mitigations and audit rows.
async fn written(repo: &MockRepository) -> (usize, usize, usize) {
    let all = ListParams {
        limit: 1000,
        ..Default::default()
    };
    (
        repo.list_events(&all).await.unwrap().len(),
        repo.list_mitigations(
            None,
            None,
            None,
            None,
            &prefixd::db::MitigationListParams {
                limit: 1000,
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .len(),
        repo.list_audit(&all).await.unwrap().len(),
    )
}

/// Every ingest route with the source it claims for a request, the body, and
/// the source a token needs there.
fn routes(victim: &str) -> Vec<(&'static str, Value, &'static str)> {
    vec![
        (
            "/v1/events",
            event("fastnetmon", victim, "e1"),
            "fastnetmon",
        ),
        (
            "/v1/events/batch",
            json!({"events": [event("fastnetmon", victim, "b1")]}),
            "fastnetmon",
        ),
        (
            "/v1/signals/fastnetmon",
            fastnetmon(victim, "u1", "host"),
            "fastnetmon",
        ),
        (
            "/v1/signals/fastnetmon",
            fastnetmon(victim, "u2", "hostgroup"),
            "fastnetmon-hostgroup",
        ),
        (
            "/v1/signals/alertmanager",
            alertmanager(victim, "f1"),
            "alertmanager",
        ),
        (
            "/v1/signals/webhook/radware",
            json!({"id": "w1", "ip": victim, "vector": "udp_flood", "score": 0.9}),
            "radware",
        ),
        (
            "/v1/signals/corroborator",
            json!({"source": "router-cpu", "pop": "test-pop", "confidence": 0.9}),
            "router-cpu",
        ),
    ]
}

/// Each route refuses an ingest token bound to another source, an Operator
/// session and an operator token with 403, and writes nothing. A token bound to
/// the route's source passes the same request. Negative control: on code that
/// trusted the claimed source, the mismatched requests succeed.
#[tokio::test]
async fn every_ingest_route_refuses_a_credential_not_bound_to_its_source() {
    for (path, body, needed) in routes("203.0.113.10") {
        let f = fixture(AuthMode::Credentials).await;
        let other = f
            .repo
            .mint_token_for_test("other", TokenScope::Ingest, Some("heavy"));
        let operator_token = f
            .repo
            .mint_token_for_test("automation", TokenScope::Operator, None);
        let session = login(&f.app, &f.repo, "ops", OperatorRole::Operator).await;
        let viewer = login(&f.app, &f.repo, "watcher", OperatorRole::Viewer).await;
        let before = written(&f.repo).await;
        for (label, auth) in [
            ("wrong-source token", ("authorization", bearer(&other))),
            ("operator token", ("authorization", bearer(&operator_token))),
            ("operator session", ("cookie", session.clone())),
            ("viewer session", ("cookie", viewer.clone())),
        ] {
            let (status, response) = send(&f.app, path, Some((auth.0, &auth.1)), &body).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path} {label}: {response}");
            let error = response["error"].as_str().unwrap();
            assert!(!error.contains("udp_flood"), "{error}");
            assert_eq!(written(&f.repo).await, before, "{path} {label} wrote state");
        }
        let (status, response) = send(&f.app, path, None, &body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}: {response}");

        // The wrong-source refusal names both sources and nothing else.
        let (_, response) = send(
            &f.app,
            path,
            Some(("authorization", &bearer(&other))),
            &body,
        )
        .await;
        let error = response["error"].as_str().unwrap();
        if path != "/v1/events/batch" {
            assert!(
                error.contains(&format!("{needed:?}")) && error.contains("bound to \"heavy\""),
                "{path}: {error}"
            );
        }

        let bound = f
            .repo
            .mint_token_for_test("bound", TokenScope::Ingest, Some(needed));
        let (status, response) = send(
            &f.app,
            path,
            Some(("authorization", &bearer(&bound))),
            &body,
        )
        .await;
        assert!(
            status.is_success(),
            "{path} bound token: {status} {response}"
        );
    }
}

/// The ingest routes grant an Admin any source, in every mode that has one:
/// an Admin session or admin token in `credentials`, the anonymous Admin in
/// `none`, every client certificate in `mtls`. The audit names the Admin.
#[tokio::test]
async fn admins_in_every_auth_mode_may_claim_any_source() {
    for mode in [AuthMode::None, AuthMode::Mtls, AuthMode::Credentials] {
        let f = fixture(mode).await;
        let credentials: Vec<(String, (&str, String))> = match mode {
            AuthMode::Credentials => vec![
                (
                    "admin".into(),
                    (
                        "cookie",
                        login(&f.app, &f.repo, "admin", OperatorRole::Admin).await,
                    ),
                ),
                (
                    "token:root".into(),
                    (
                        "authorization",
                        bearer(&f.repo.mint_token_for_test("root", TokenScope::Admin, None)),
                    ),
                ),
            ],
            AuthMode::None => vec![("anonymous".into(), ("x-none", String::new()))],
            AuthMode::Mtls => vec![("mtls-client".into(), ("x-none", String::new()))],
        };
        for (index, (actor, (name, value))) in credentials.into_iter().enumerate() {
            let victim = format!("203.0.113.{}", 20 + index);
            let (status, body) = send(
                &f.app,
                "/v1/events",
                Some((name, &value)),
                &event("fastnetmon", &victim, &format!("admin-{index}")),
            )
            .await;
            assert_eq!(status, StatusCode::ACCEPTED, "{mode:?} {actor}: {body}");
            let id: uuid::Uuid = body["mitigation_id"].as_str().unwrap().parse().unwrap();
            let audit = f
                .repo
                .list_audit(&ListParams {
                    limit: 100,
                    ..Default::default()
                })
                .await
                .unwrap();
            let create = audit
                .iter()
                .find(|entry| entry.target_id.as_deref() == Some(id.to_string().as_str()))
                .unwrap();
            let create = serde_json::to_value(create).unwrap();
            assert_eq!(create["actor_type"], "operator", "{mode:?}");
            assert_eq!(create["actor_id"], actor.as_str(), "{mode:?}");
            assert_eq!(create["details"]["source"], "fastnetmon", "{mode:?}");
        }
    }
}

/// A batch is authorized as a whole: one mismatched item refuses the request
/// and nothing is stored, while an unparsable item keeps its own rejection.
#[tokio::test]
async fn a_batch_with_one_mismatched_item_is_refused_whole() {
    let f = fixture(AuthMode::Credentials).await;
    let token = f
        .repo
        .mint_token_for_test("fnm", TokenScope::Ingest, Some("fastnetmon"));
    let auth = bearer(&token);
    let (status, body) = send(
        &f.app,
        "/v1/events/batch",
        Some(("authorization", &auth)),
        &json!({"events": [
            event("fastnetmon", "203.0.113.10", "ok-1"),
            event("radware", "203.0.113.11", "spoof-1"),
        ]}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body["error"].as_str().unwrap().contains("\"radware\""));
    assert_eq!(written(&f.repo).await, (0, 0, 0));

    let (status, body) = send(
        &f.app,
        "/v1/events/batch",
        Some(("authorization", &auth)),
        &json!({"events": [
            event("fastnetmon", "203.0.113.10", "ok-1"),
            {"source": "radware", "not": "an event"},
        ]}),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS, "{body}");
    assert_eq!(body["accepted"], 1, "{body}");
    assert_eq!(body["results"][1]["status"], "rejected", "{body}");
}

/// `min_sources` counts bound sources, and a weight is the bound source's: two
/// tokens bound to one source are one source, and a token cannot borrow a
/// heavier source's weight by naming it.
#[tokio::test]
async fn correlation_counts_and_weighs_bound_sources() {
    let f = fixture_with(
        settings(AuthMode::Credentials, "test-pop", 2),
        Arc::new(MockRepository::new()),
    )
    .await;
    let first = f
        .repo
        .mint_token_for_test("fnm-a", TokenScope::Ingest, Some("fastnetmon"));
    let second = f
        .repo
        .mint_token_for_test("fnm-b", TokenScope::Ingest, Some("fastnetmon"));
    let other = f
        .repo
        .mint_token_for_test("am", TokenScope::Ingest, Some("alertmanager"));
    let victim = "203.0.113.30";
    for (token, id) in [(&first, "a"), (&second, "b")] {
        let (status, body) = send(
            &f.app,
            "/v1/events",
            Some(("authorization", &bearer(token))),
            &event("fastnetmon", victim, id),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        assert!(
            body["mitigation_id"].is_null(),
            "one source is not two: {body}"
        );
    }
    // A token cannot add a second source by naming one.
    let (status, _) = send(
        &f.app,
        "/v1/events",
        Some(("authorization", &bearer(&first))),
        &event("alertmanager", victim, "c"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = send(
        &f.app,
        "/v1/signals/alertmanager",
        Some(("authorization", &bearer(&other))),
        &alertmanager(victim, "fp-1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["results"][0]["mitigation_id"].is_string(), "{body}");

    let groups = f
        .repo
        .list_signal_groups(
            &prefixd::correlation::SignalGroupFilter::default(),
            &ListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let group = groups.iter().find(|g| g.victim_ip == victim).unwrap();
    assert_eq!(group.source_count, 2);
    let links = f
        .repo
        .list_signal_group_events(group.group_id)
        .await
        .unwrap();
    assert!(
        links
            .iter()
            .all(|link| (link.source_weight - 1.0).abs() < f32::EPSILON),
        "every weight is the bound source's 1.0, never heavy's 3.0: {links:?}"
    );
}

/// A detector unban withdraws only the live mitigations its source created
/// for the victim on this POP. Another source's mitigation for the same
/// victim and a manual one are untouched. The victim is compared in
/// canonical form, a re-ban's extension is withdrawn, and with nothing left
/// the answer is a definitive `no_active_mitigation`. The withdrawal is
/// audited as the token.
#[tokio::test]
async fn detector_unban_withdraws_only_its_own_sources_mitigations() {
    let f = fixture(AuthMode::Credentials).await;
    let fnm = bearer(&f.repo.mint_token_for_test(
        "fnm-pop1",
        TokenScope::Ingest,
        Some("fastnetmon"),
    ));
    let am = bearer(&f.repo.mint_token_for_test(
        "am-pop1",
        TokenScope::Ingest,
        Some("alertmanager"),
    ));
    let admin = login(&f.app, &f.repo, "admin", OperatorRole::Admin).await;
    let victim = "2001:db8:113::10";

    let (_, ours) = send(
        &f.app,
        "/v1/events",
        Some(("authorization", &fnm)),
        &event("fastnetmon", victim, "ban-1"),
    )
    .await;
    let ours: uuid::Uuid = ours["mitigation_id"].as_str().unwrap().parse().unwrap();
    // A re-ban with a new event ID extends the same mitigation.
    let (_, again) = send(
        &f.app,
        "/v1/events",
        Some(("authorization", &fnm)),
        &event("fastnetmon", "2001:0db8:0113::0010", "ban-2"),
    )
    .await;
    assert_eq!(again["status"], "extended", "{again}");
    // Another source's mitigation for the same victim, on another port so it
    // is its own rule, and a manual one.
    let mut theirs = alertmanager(victim, "fp-1");
    theirs["alerts"][0]["labels"]["vector"] = "syn_flood".into();
    let (_, theirs) = send(
        &f.app,
        "/v1/signals/alertmanager",
        Some(("authorization", &am)),
        &theirs,
    )
    .await;
    let theirs: uuid::Uuid = theirs["results"][0]["mitigation_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let (status, manual) = send(
        &f.app,
        "/v1/mitigations",
        Some(("cookie", &admin)),
        &json!({"victim_ip": victim, "protocol": "tcp", "dst_ports": [443],
            "action": "discard", "ttl_seconds": 600, "reason": "manual"}),
    )
    .await;
    assert!(status.is_success(), "{manual}");
    let manual: uuid::Uuid = manual["mitigation_id"].as_str().unwrap().parse().unwrap();

    // The zero-padded spelling FastNetMon sends.
    let (status, body) = send(
        &f.app,
        "/v1/events",
        Some(("authorization", &fnm)),
        &unban("fastnetmon", "2001:0db8:0113::0010", "unban-1"),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "withdrawn", "{body}");
    assert_eq!(body["mitigation_ids"], json!([ours.to_string()]));
    let status_of = |id| {
        let repo = f.repo.clone();
        async move { repo.get_mitigation(id).await.unwrap().unwrap().status }
    };
    assert_eq!(status_of(ours).await, MitigationStatus::Withdrawn);
    assert_eq!(status_of(theirs).await, MitigationStatus::Active);
    assert_eq!(status_of(manual).await, MitigationStatus::Active);
    let audit = serde_json::to_value(
        f.repo
            .list_audit(&ListParams {
                limit: 100,
                ..Default::default()
            })
            .await
            .unwrap(),
    )
    .unwrap();
    let withdraw = audit
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["action"] == "withdraw" && e["target_id"] == ours.to_string())
        .unwrap_or_else(|| panic!("{audit}"));
    assert_eq!(withdraw["actor_type"], "detector");
    assert_eq!(withdraw["actor_id"], "token:fnm-pop1");

    // An unban after a lost one, or with nothing to match, is definitive.
    let (status, body) = send(
        &f.app,
        "/v1/events",
        Some(("authorization", &fnm)),
        &unban("fastnetmon", victim, "unban-2"),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "no_active_mitigation", "{body}");
    // The other source's unban for the victim withdraws its own, and only
    // for the vector it names: a resolved udp_flood alert leaves its
    // syn_flood mitigation.
    let resolved = |vector: &str| {
        let mut resolved = alertmanager(victim, &format!("fp-{vector}"));
        resolved["alerts"][0]["status"] = "resolved".into();
        resolved["alerts"][0]["labels"]["vector"] = vector.into();
        resolved
    };
    let (status, body) = send(
        &f.app,
        "/v1/signals/alertmanager",
        Some(("authorization", &am)),
        &resolved("udp_flood"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["results"][0]["status"], "no_active_mitigation",
        "{body}"
    );
    assert_eq!(status_of(theirs).await, MitigationStatus::Active);
    let (_, body) = send(
        &f.app,
        "/v1/signals/alertmanager",
        Some(("authorization", &am)),
        &resolved("syn_flood"),
    )
    .await;
    assert_eq!(body["results"][0]["status"], "withdrawn", "{body}");
    assert_eq!(status_of(theirs).await, MitigationStatus::Withdrawn);
    assert_eq!(status_of(manual).await, MitigationStatus::Active);
}

/// Two POPs share one database. A POP-A token is refused on POP B's
/// controller, and an unban on POP A never touches POP B's mitigation for the
/// same victim and source.
#[tokio::test]
async fn detector_unban_never_crosses_pops() {
    let repo = Arc::new(MockRepository::new());
    let pop_a = fixture_with(settings(AuthMode::Credentials, "pop-a", 1), repo.clone()).await;
    let pop_b = fixture_with(settings(AuthMode::Credentials, "pop-b", 1), repo.clone()).await;
    let (_, a_secret) = prefixd::auth::token::create(
        repo.as_ref(),
        prefixd::auth::token::NewToken {
            name: "fnm-a".into(),
            scope: TokenScope::Ingest,
            source: Some("fastnetmon".into()),
            pop: Some("pop-a".into()),
            expires_at: None,
        },
        "admin",
        chrono::Utc::now(),
    )
    .await
    .unwrap();
    let b_secret = repo.mint_token_for_test("fnm-b", TokenScope::Ingest, Some("fastnetmon"));
    let victim = "203.0.113.40";
    let (status, body) = send(
        &pop_b.app,
        "/v1/events",
        Some(("authorization", &bearer(&a_secret))),
        &event("fastnetmon", victim, "b-via-a"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (_, body) = send(
        &pop_b.app,
        "/v1/events",
        Some(("authorization", &bearer(&b_secret))),
        &event("fastnetmon", victim, "b-1"),
    )
    .await;
    let on_b: uuid::Uuid = body["mitigation_id"].as_str().unwrap().parse().unwrap();

    let (status, body) = send(
        &pop_a.app,
        "/v1/events",
        Some(("authorization", &bearer(&a_secret))),
        &unban("fastnetmon", victim, "a-unban"),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "no_active_mitigation", "{body}");
    assert_eq!(
        repo.get_mitigation(on_b).await.unwrap().unwrap().status,
        MitigationStatus::Active
    );
    let _ = (&pop_a.state, &pop_b.state);
}

/// The blackhole allowlist is authorization: an Operator cannot reach a
/// detector blackhole through any route, while a token bound to the
/// allowlisted source and an Admin can.
#[tokio::test]
async fn the_blackhole_allowlist_admits_a_bound_token_and_an_admin_only() {
    let mut settings = settings(AuthMode::Credentials, "test-pop", 1);
    settings.blackhole.enabled = true;
    settings.blackhole.next_hop_ipv4 = Some("192.0.2.66".parse().unwrap());
    settings.blackhole.detector_sources = vec!["fastnetmon".into()];
    settings.safelist.prefixes = vec!["10.0.0.0/8".into()];
    let f = fixture_with(settings, Arc::new(MockRepository::new())).await;
    let mut playbooks = common::test_playbooks();
    playbooks.playbooks[0].steps[0].action = Some(prefixd::config::PlaybookAction::Blackhole);
    playbooks.playbooks[0].steps[0].rate_bps = None;
    *f.state.playbooks.write().await = playbooks;
    let operator = login(&f.app, &f.repo, "ops", OperatorRole::Operator).await;
    let operator_token = f
        .repo
        .mint_token_for_test("automation", TokenScope::Operator, None);
    // Both spoofs are tried before asserting, so a regression shows each
    // route's outcome: through the event body and through the adapter route.
    let mut outcomes = Vec::new();
    for (auth, path, body) in [
        (
            ("cookie", operator.clone()),
            "/v1/events",
            event("fastnetmon", "203.0.113.50", "op-1"),
        ),
        (
            ("authorization", bearer(&operator_token)),
            "/v1/signals/fastnetmon",
            fastnetmon("203.0.113.51", "op-2", "host"),
        ),
    ] {
        let (status, response) = send(&f.app, path, Some((auth.0, &auth.1)), &body).await;
        outcomes.push((path, status, response["mitigation_id"].clone()));
    }
    assert_eq!(
        outcomes,
        [
            ("/v1/events", StatusCode::FORBIDDEN, Value::Null),
            ("/v1/signals/fastnetmon", StatusCode::FORBIDDEN, Value::Null),
        ]
    );
    assert_eq!(written(&f.repo).await, (0, 0, 0));

    let fnm = f
        .repo
        .mint_token_for_test("fnm", TokenScope::Ingest, Some("fastnetmon"));
    let admin = login(&f.app, &f.repo, "admin", OperatorRole::Admin).await;
    for (index, auth) in [("authorization", bearer(&fnm)), ("cookie", admin.clone())]
        .into_iter()
        .enumerate()
    {
        let (status, body) = send(
            &f.app,
            "/v1/signals/fastnetmon",
            Some((auth.0, &auth.1)),
            &fastnetmon(
                &format!("203.0.113.{}", 51 + index),
                &format!("ok-{index}"),
                "host",
            ),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let id = body["mitigation_id"].as_str().unwrap().parse().unwrap();
        let stored = f.repo.get_mitigation(id).await.unwrap().unwrap();
        assert_eq!(stored.action_type, prefixd::domain::ActionType::Blackhole);
    }
}

/// An HMAC adapter's verified signature is its own credential, bound to the
/// adapter name and audited as `webhook:<adapter>`; `Authorization` is ignored.
/// The secret must be in the environment, which a test can set only in a child
/// process.
#[tokio::test]
async fn an_hmac_adapter_signature_grants_its_name() {
    const SECRET: &str = "0123456789abcdef0123456789abcdef-signed";
    if !rerun_with(
        "an_hmac_adapter_signature_grants_its_name",
        &[("PREFIXD_WEBHOOK_TEST_SIGNED", SECRET)],
    ) {
        return;
    }
    let f = fixture(AuthMode::Credentials).await;
    f.state.correlation_config.write().await.webhook_adapters = vec![webhook_adapter(
        "signed",
        WebhookAuth::Hmac {
            secret_env: "PREFIXD_WEBHOOK_TEST_SIGNED".into(),
            header: "X-Signature-SHA256".into(),
            algorithm: "sha256".into(),
        },
    )];
    let body = json!({"id": "s1", "ip": "203.0.113.60", "vector": "udp_flood", "score": 0.9});
    let signature = {
        use hmac::{KeyInit, Mac};
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
        mac.update(body.to_string().as_bytes());
        hex::encode(mac.finalize().into_bytes())
    };
    let request = |signature: &str| {
        Request::post("/v1/signals/webhook/signed")
            .header("content-type", "application/json")
            .header("x-signature-sha256", signature)
            .header("authorization", "Bearer prefixd_not-a-real-token")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let response = f.app.clone().oneshot(request("00")).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = f.app.clone().oneshot(request(&signature)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mitigations = f
        .repo
        .list_mitigations(
            None,
            None,
            None,
            None,
            &prefixd::db::MitigationListParams {
                limit: 10,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(mitigations.len(), 1);
    let audit = serde_json::to_value(
        f.repo
            .list_audit(&ListParams {
                limit: 10,
                ..Default::default()
            })
            .await
            .unwrap(),
    )
    .unwrap();
    let create = &audit[0];
    assert_eq!(create["actor_type"], "detector", "{audit}");
    assert_eq!(create["actor_id"], "webhook:signed", "{audit}");
    assert_eq!(create["details"]["source"], "signed", "{audit}");
}

/// Run `test` again in a child process with `vars` set, because setting the
/// environment in-process needs `unsafe`. Returns true in the child, which
/// runs the test body; the parent asserts the child passed.
fn rerun_with(test: &str, vars: &[(&str, &str)]) -> bool {
    if std::env::var_os("PREFIXD_SOURCE_BINDING_CHILD").is_some() {
        return true;
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args([test, "--exact", "--test-threads=1"])
        .env("PREFIXD_SOURCE_BINDING_CHILD", "1")
        .envs(vars.iter().copied())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "{test} in a child: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    false
}

/// A correlation document with one adapter, for the refusal tests.
fn adapter_yaml(adapter: &str) -> String {
    format!(
        "enabled: true\nwebhook_adapters:\n  - name: radware\n    enabled: true\n{adapter}    fields:\n      victim_ip: \"$.ip\"\n"
    )
}

const LONG_SECRET: &str = "0123456789abcdef0123456789abcdef";

/// Each refused shape, its prefixd.yaml inputs and the text its error carries.
fn refused_shapes() -> Vec<(&'static str, String, AuthMode, Vec<String>, &'static str)> {
    let hmac = |env: &str| {
        format!(
            "    auth:\n      type: hmac\n      secret_env: {env}\n      header: X-Signature-SHA256\n"
        )
    };
    vec![
        (
            "auth none outside mode none",
            adapter_yaml("    auth:\n      type: none\n"),
            AuthMode::Credentials,
            vec![],
            "auth.type none",
        ),
        (
            "allowlisted hmac without source_id",
            adapter_yaml(&hmac("PREFIXD_WEBHOOK_GOOD")),
            AuthMode::Credentials,
            vec!["radware".into()],
            "fields.source_id",
        ),
        (
            "secret_env PATH",
            adapter_yaml(&hmac("PATH")),
            AuthMode::Credentials,
            vec![],
            "PREFIXD_WEBHOOK_",
        ),
        (
            "secret_env outside the namespace",
            adapter_yaml(&hmac("RADWARE_WEBHOOK_SECRET")),
            AuthMode::Credentials,
            vec![],
            "PREFIXD_WEBHOOK_",
        ),
        (
            "short secret",
            adapter_yaml(&hmac("PREFIXD_WEBHOOK_SHORT")),
            AuthMode::Credentials,
            vec![],
            "at least 32 bytes",
        ),
        (
            "adapter name outside the source pattern",
            adapter_yaml("    auth:\n      type: bearer\n")
                .replace("name: radware", "name: -radware"),
            AuthMode::Credentials,
            vec![],
            "name must match",
        ),
        (
            "unset secret",
            adapter_yaml(&hmac("PREFIXD_WEBHOOK_UNSET")),
            AuthMode::Credentials,
            vec![],
            "is not set",
        ),
    ]
}

/// Every refused shape is refused at startup (and by `prefixd --check`), on
/// reload and through `PUT /v1/config/correlation`, and the accepted shapes
/// pass all three. No error carries the secret's value.
#[tokio::test]
async fn correlation_refusals_hold_at_startup_reload_and_the_editor() {
    if !rerun_with(
        "correlation_refusals_hold_at_startup_reload_and_the_editor",
        &[
            ("PREFIXD_WEBHOOK_GOOD", LONG_SECRET),
            ("PREFIXD_WEBHOOK_SHORT", "short-secret-value"),
        ],
    ) {
        return;
    }
    for (label, document, mode, allowlist, wanted) in refused_shapes() {
        let mut running = settings(mode, "test-pop", 1);
        running.blackhole.detector_sources = allowlist.clone();
        running.correlation = CorrelationConfig::default();

        // Startup and --check read the files. JSON is YAML.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("prefixd.yaml"),
            serde_json::to_string(&running).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.path().join("inventory.yaml"), r#"{"customers":[]}"#).unwrap();
        std::fs::write(dir.path().join("playbooks.yaml"), r#"{"playbooks":[]}"#).unwrap();
        std::fs::write(dir.path().join("correlation.yaml"), &document).unwrap();
        let startup = prefixd::config::AppConfig::load(dir.path())
            .err()
            .unwrap_or_else(|| panic!("{label}: startup accepted it"))
            .to_string();
        assert!(startup.contains(wanted), "{label} startup: {startup}");
        let check = prefixd::config::AppConfig::check(dir.path());
        assert!(
            check.errors.iter().any(|error| error.contains(wanted)),
            "{label} --check: {:?}",
            check.errors
        );
        for text in [startup.as_str(), &check.errors.join("\n")] {
            assert!(!text.contains(LONG_SECRET) && !text.contains("short-secret-value"));
        }

        // Reload: a running controller with the same prefixd.yaml, reading
        // only correlation.yaml.
        let f = fixture_with(running.clone(), Arc::new(MockRepository::new())).await;
        let mut state = f.state.clone();
        drop(f);
        Arc::get_mut(&mut state).unwrap().config_dir = dir.path().into();
        for file in ["prefixd.yaml", "inventory.yaml", "playbooks.yaml"] {
            std::fs::remove_file(dir.path().join(file)).unwrap();
        }
        let reload = state.reload_config().await.unwrap_err().to_string();
        assert!(reload.contains(wanted), "{label} reload: {reload}");
        assert!(
            state.correlation_config.read().await.webhook_adapters.len() == 1,
            "{label}: a refused reload published nothing"
        );

        // The editor.
        let f = fixture_with(running, Arc::new(MockRepository::new())).await;
        let admin = match mode {
            AuthMode::Credentials => {
                Some(login(&f.app, &f.repo, "admin", OperatorRole::Admin).await)
            }
            _ => None,
        };
        let (config, _) = CorrelationConfig::from_yaml(&document).unwrap();
        let response = f
            .app
            .clone()
            .oneshot(
                Request::put("/v1/config/correlation")
                    .header("content-type", "application/json")
                    .header("cookie", admin.clone().unwrap_or_default())
                    .body(Body::from(serde_json::to_string(&config).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert_eq!(status, StatusCode::BAD_REQUEST, "{label} PUT: {body}");
        assert!(body.contains(wanted), "{label} PUT: {body}");
        assert!(!body.contains(LONG_SECRET) && !body.contains("short-secret-value"));
    }

    // Control: the accepted shapes pass the same validation.
    let ok_hmac = "    auth:\n      type: hmac\n      secret_env: PREFIXD_WEBHOOK_GOOD\n      header: X-Signature-SHA256\n";
    for (document, mode, allowlist) in [
        (
            adapter_yaml("    auth:\n      type: none\n"),
            AuthMode::None,
            vec![],
        ),
        (adapter_yaml(ok_hmac), AuthMode::Credentials, vec![]),
        (
            adapter_yaml("    auth:\n      type: bearer\n"),
            AuthMode::Credentials,
            vec!["radware".to_string()],
        ),
    ] {
        let (config, _) = CorrelationConfig::from_yaml(&document).unwrap();
        let errors = config.validate(&prefixd::correlation::IngestAuthorization {
            auth_mode: mode,
            detector_sources: &allowlist,
            prefix_sources: &[],
        });
        assert!(errors.is_empty(), "{document}: {errors:?}");
    }
}

/// Allowlist entries a token cannot carry are refused at load.
#[test]
fn allowlist_names_outside_the_token_source_pattern_are_refused() {
    for (key, value) in [
        ("blackhole.detector_sources", "Fast.Net"),
        ("guardrails.detector_prefix_sources", "-leading"),
    ] {
        let mut settings = settings(AuthMode::Credentials, "test-pop", 1);
        match key {
            "blackhole.detector_sources" => {
                settings.blackhole.detector_sources = vec![value.into()]
            }
            _ => {
                settings.guardrails.allow_detector_prefix = true;
                settings.guardrails.detector_prefix_sources = vec![value.into()];
            }
        }
        let errors = settings.validate_errors();
        assert!(
            errors
                .iter()
                .any(|error| error.contains(key) && error.contains("token source pattern")),
            "{key}: {errors:?}"
        );
    }
}

/// The prefix allowlist is authorization too, and a separate source: the host
/// token cannot reach prefix events under either name, while a token bound to
/// `fastnetmon-hostgroup` and an Admin reach the ordinary prefix guardrails.
#[tokio::test]
async fn the_prefix_allowlist_admits_only_its_bound_source_and_an_admin() {
    let mut settings = settings(AuthMode::Credentials, "test-pop", 1);
    settings.guardrails.allow_detector_prefix = true;
    settings.guardrails.detector_prefix_sources = vec!["fastnetmon-hostgroup".into()];
    settings.guardrails.dst_prefix_minlen = 24;
    let f = fixture_with(settings, Arc::new(MockRepository::new())).await;
    let host = bearer(&f.repo.mint_token_for_test(
        "fnm-host",
        TokenScope::Ingest,
        Some("fastnetmon"),
    ));
    let hostgroup = bearer(&f.repo.mint_token_for_test(
        "fnm-hostgroup",
        TokenScope::Ingest,
        Some("fastnetmon-hostgroup"),
    ));
    let operator = login(&f.app, &f.repo, "ops", OperatorRole::Operator).await;
    let admin = login(&f.app, &f.repo, "admin", OperatorRole::Admin).await;
    let prefix = |source: &str, id: &str| event(source, "203.0.113.0/24", id);

    for (auth, body, expected) in [
        (
            ("cookie", operator.as_str()),
            prefix("fastnetmon-hostgroup", "p1"),
            StatusCode::FORBIDDEN,
        ),
        (
            ("authorization", host.as_str()),
            prefix("fastnetmon-hostgroup", "p2"),
            StatusCode::FORBIDDEN,
        ),
        (
            ("authorization", host.as_str()),
            prefix("fastnetmon", "p3"),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
    ] {
        let (status, response) = send(&f.app, "/v1/events", Some(auth), &body).await;
        assert_eq!(status, expected, "{body}: {response}");
    }
    for (auth, id) in [
        (("authorization", hostgroup.as_str()), "p4"),
        (("cookie", admin.as_str()), "p5"),
    ] {
        let (status, response) = send(
            &f.app,
            "/v1/events",
            Some(auth),
            &prefix("fastnetmon-hostgroup", id),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{response}");
        assert_eq!(response["status"], "accepted_no_playbook", "{response}");
    }
}

/// A speaker that refuses deletes of TCP rules while `failing` is set: a
/// definite failure, so the unban carries on with the other deletes.
struct FailingTcpWithdrawals {
    inner: MockAnnouncer,
    failing: std::sync::atomic::AtomicBool,
}

impl prefixd::bgp::FlowSpecAnnouncer for FailingTcpWithdrawals {
    fn backend(&self) -> &'static str {
        "mock"
    }
    fn reader(&self) -> Option<&dyn prefixd::bgp::FlowSpecReader> {
        Some(self)
    }
    fn peer_observer(&self) -> Option<&dyn prefixd::bgp::PeerObserver> {
        Some(self)
    }
}

#[async_trait::async_trait]
impl prefixd::bgp::FlowSpecWriter for FailingTcpWithdrawals {
    async fn announce(&self, rule: &prefixd::domain::FlowSpecRule) -> prefixd::error::Result<()> {
        self.inner.announce(rule).await
    }
    async fn withdraw(&self, rule: &prefixd::domain::FlowSpecRule) -> prefixd::error::Result<()> {
        if rule.nlri.protocol == Some(6) && self.failing.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(prefixd::error::PrefixdError::InjectionOwnerMismatch {
                reason: prefixd::error::InjectionRefusalReason::OwnerMismatch,
                message: "seeded delete refusal".into(),
            });
        }
        self.inner.withdraw(rule).await
    }
}

#[async_trait::async_trait]
impl prefixd::bgp::FlowSpecReader for FailingTcpWithdrawals {
    async fn list_active(&self) -> prefixd::error::Result<Vec<prefixd::domain::FlowSpecRule>> {
        self.inner.list_active().await
    }
}

#[async_trait::async_trait]
impl prefixd::bgp::PeerObserver for FailingTcpWithdrawals {
    async fn session_status(&self) -> prefixd::error::Result<Vec<prefixd::bgp::PeerStatus>> {
        self.inner.session_status().await
    }
}

/// An enforced controller in credentials mode on the failing speaker.
async fn failing_fixture() -> (Fixture, Arc<FailingTcpWithdrawals>) {
    let repo = Arc::new(MockRepository::new());
    let speaker = Arc::new(FailingTcpWithdrawals {
        inner: MockAnnouncer::new(),
        failing: std::sync::atomic::AtomicBool::new(true),
    });
    // Its own POP keeps its metric labels apart from concurrent tests.
    let mut settings = settings(AuthMode::Credentials, "failing-pop", 1);
    settings.mode = prefixd::config::OperationMode::Enforced;
    let inventory = Inventory::new(vec![Customer {
        customer_id: "bound".into(),
        name: "Source binding".into(),
        prefixes: vec!["203.0.113.0/24".into()],
        policy_profile: PolicyProfile::Normal,
        services: vec![],
    }]);
    let state = AppState::new(
        settings,
        inventory,
        common::test_playbooks(),
        repo.clone(),
        speaker.clone(),
        ".".into(),
    )
    .unwrap();
    state.correlation_config.write().await.webhook_adapters =
        vec![webhook_adapter("radware", WebhookAuth::Bearer)];
    let app =
        prefixd::api::create_test_router_with_session_store(state.clone(), MemoryStore::default());
    (Fixture { app, repo, state }, speaker)
}

fn with_vector(mut event: Value, vector: &str) -> Value {
    event["vector"] = vector.into();
    event
}

async fn audit_for(repo: &MockRepository, action: &str, target: uuid::Uuid) -> Vec<Value> {
    serde_json::to_value(
        repo.list_audit(&ListParams {
            limit: 1000,
            ..Default::default()
        })
        .await
        .unwrap(),
    )
    .unwrap()
    .as_array()
    .unwrap()
    .iter()
    .filter(|entry| entry["action"] == action && entry["target_id"] == target.to_string())
    .cloned()
    .collect()
}

/// An unban that names a real vector withdraws only that attack's
/// mitigations for the victim; `unknown` keeps the whole victim, as the
/// FastNetMon script's unban needs. Negative control: without the vector
/// filter, the syn_flood unban also withdraws the udp_flood mitigation.
#[tokio::test]
async fn an_unban_vector_narrows_it_and_unknown_keeps_the_victim() {
    let f = fixture(AuthMode::Credentials).await;
    let fnm = bearer(
        &f.repo
            .mint_token_for_test("fnm", TokenScope::Ingest, Some("fastnetmon")),
    );
    let auth = Some(("authorization", fnm.as_str()));
    let victim = "203.0.113.70";
    let ban = |id: &str, vector: &str| with_vector(event("fastnetmon", victim, id), vector);
    let mut ids = Vec::new();
    for (id, vector) in [("u1", "udp_flood"), ("s1", "syn_flood")] {
        let (_, body) = send(&f.app, "/v1/events", auth, &ban(id, vector)).await;
        ids.push(
            body["mitigation_id"]
                .as_str()
                .unwrap()
                .parse::<uuid::Uuid>()
                .unwrap(),
        );
    }
    let (udp, syn) = (ids[0], ids[1]);
    let status_of = |id| {
        let repo = f.repo.clone();
        async move { repo.get_mitigation(id).await.unwrap().unwrap().status }
    };

    let (_, body) = send(
        &f.app,
        "/v1/events",
        auth,
        &with_vector(unban("fastnetmon", victim, "x1"), "syn_flood"),
    )
    .await;
    assert_eq!(body["mitigation_ids"], json!([syn.to_string()]), "{body}");
    assert_eq!(status_of(udp).await, MitigationStatus::Active);

    let (_, again) = send(&f.app, "/v1/events", auth, &ban("s2", "syn_flood")).await;
    let syn: uuid::Uuid = again["mitigation_id"].as_str().unwrap().parse().unwrap();
    let (_, body) = send(
        &f.app,
        "/v1/events",
        auth,
        &with_vector(unban("fastnetmon", victim, "x2"), "unknown"),
    )
    .await;
    let mut withdrawn: Vec<String> =
        serde_json::from_value(body["mitigation_ids"].clone()).unwrap();
    withdrawn.sort();
    let mut wanted = vec![udp.to_string(), syn.to_string()];
    wanted.sort();
    assert_eq!(withdrawn, wanted, "{body}");
}

/// One failed delete does not stop the others. Every selected mitigation's
/// withdrawal intent is recorded first, each delete is attempted, and a
/// failed or ambiguous one answers 503 with its intent pending. A retry
/// reuses that intent and never creates a second request. Reconciliation
/// completes it, and both the immediate and the reconciled withdrawal are
/// audited with the bound source and counted as `detector_unban`.
/// Negative control: stopping at the first failure leaves the second rule
/// unwithdrawn.
#[tokio::test]
async fn a_failed_delete_leaves_its_intent_pending_and_the_rest_withdrawn() {
    let (f, speaker) = failing_fixture().await;
    let fnm = bearer(
        &f.repo
            .mint_token_for_test("fnm", TokenScope::Ingest, Some("fastnetmon")),
    );
    let auth = Some(("authorization", fnm.as_str()));
    let victim = "203.0.113.71";
    let mut ids = Vec::new();
    // The TCP rule first, so a loop that stopped at a failure would never
    // reach the UDP rule.
    for (id, vector) in [("s1", "syn_flood"), ("u1", "udp_flood")] {
        let (status, body) = send(
            &f.app,
            "/v1/events",
            auth,
            &with_vector(event("fastnetmon", victim, id), vector),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        ids.push(
            body["mitigation_id"]
                .as_str()
                .unwrap()
                .parse::<uuid::Uuid>()
                .unwrap(),
        );
    }
    let (syn, udp) = (ids[0], ids[1]);
    let withdrawn_metric = |reason: &str| {
        prefixd::observability::metrics::MITIGATIONS_WITHDRAWN
            .with_label_values(&["police", "failing-pop", reason])
            .get()
    };
    let before = withdrawn_metric("detector_unban");

    for attempt in 0..2 {
        let (status, body) = send(
            &f.app,
            "/v1/events",
            auth,
            // The script's unban: no vector, the whole victim.
            &with_vector(
                unban("fastnetmon", victim, &format!("unban-{attempt}")),
                "unknown",
            ),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("withdrawal incomplete")
        );
        let pending = f.repo.pending_withdrawals(None).await.unwrap();
        assert_eq!(pending.len(), 1, "attempt {attempt}: {pending:?}");
        assert_eq!(pending[0].mitigation_id, syn);
        assert_eq!(pending[0].detector_source.as_deref(), Some("fastnetmon"));
    }
    let status_of = |id| {
        let repo = f.repo.clone();
        async move { repo.get_mitigation(id).await.unwrap().unwrap().status }
    };
    assert_eq!(status_of(udp).await, MitigationStatus::Withdrawn);
    assert_eq!(status_of(syn).await, MitigationStatus::Active);
    assert_eq!(withdrawn_metric("detector_unban"), before + 1.0);
    let immediate = audit_for(&f.repo, "withdraw", udp).await;
    assert_eq!(immediate.len(), 1);
    assert_eq!(immediate[0]["details"]["source"], "fastnetmon");
    assert_eq!(immediate[0]["actor_id"], "token:fnm");

    speaker
        .failing
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let reconciler =
        prefixd::scheduler::ReconciliationLoop::new(f.repo.clone(), speaker.clone(), 30, false)
            .with_app_state(f.state.clone());
    reconciler.reconcile().await.unwrap();
    assert_eq!(status_of(syn).await, MitigationStatus::Withdrawn);
    assert!(f.repo.pending_withdrawals(None).await.unwrap().is_empty());
    let reconciled = audit_for(&f.repo, "withdraw", syn).await;
    assert_eq!(reconciled.len(), 1, "{reconciled:?}");
    assert_eq!(reconciled[0]["details"]["source"], "fastnetmon");
    assert_eq!(reconciled[0]["actor_id"], "token:fnm");
}

/// An adapter unban reports what it did: `no_active_mitigation` is not
/// `withdrawn`, and a failed delete is an error counted as failed with a 503
/// the sender retries, never a 200 no-op. Negative control: the earlier
/// `withdrawn` and `withdrawn_noop` reporting fails both checks.
#[tokio::test]
async fn adapter_unbans_report_their_outcome_and_retry_failures() {
    let (f, _speaker) = failing_fixture().await;
    let am = bearer(
        &f.repo
            .mint_token_for_test("am", TokenScope::Ingest, Some("alertmanager")),
    );
    let radware = bearer(
        &f.repo
            .mint_token_for_test("rw", TokenScope::Ingest, Some("radware")),
    );
    let resolved = |victim: &str, fingerprint: &str| {
        let mut alert = alertmanager(victim, fingerprint);
        alert["alerts"][0]["status"] = "resolved".into();
        alert["alerts"][0]["labels"]["vector"] = "syn_flood".into();
        alert
    };

    // Nothing to withdraw: reported as such, 200.
    let (status, body) = send(
        &f.app,
        "/v1/signals/alertmanager",
        Some(("authorization", &am)),
        &resolved("203.0.113.72", "fp-none"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["results"][0]["status"], "no_active_mitigation",
        "{body}"
    );

    // A TCP rule whose delete fails: 503, counted as failed.
    let mut firing = alertmanager("203.0.113.72", "fp-r");
    firing["alerts"][0]["labels"]["vector"] = "syn_flood".into();
    let (status, body) = send(
        &f.app,
        "/v1/signals/alertmanager",
        Some(("authorization", &am)),
        &firing,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = send(
        &f.app,
        "/v1/signals/alertmanager",
        Some(("authorization", &am)),
        &resolved("203.0.113.72", "fp-r"),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["failed"], 1, "{body}");
    assert_eq!(body["results"][0]["status"], "error", "{body}");

    // The webhook adapter alike.
    let ban = json!({"id": "w-1", "ip": "203.0.113.73", "vector": "syn_flood", "score": 0.9});
    let (status, body) = send(
        &f.app,
        "/v1/signals/webhook/radware",
        Some(("authorization", &radware)),
        &ban,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mut unban = ban.clone();
    unban["action"] = "unban".into();
    unban["id"] = "w-2".into();
    let (status, body) = send(
        &f.app,
        "/v1/signals/webhook/radware",
        Some(("authorization", &radware)),
        &unban,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["failed"], 1, "{body}");
    assert_eq!(body["results"][0]["status"], "error", "{body}");
}

/// The triggering event's source owns a mitigation. When another source
/// extends it, that source's unban finds nothing, and the creator's unban
/// withdraws it. Negative control: matching on `last_event_id` too lets the
/// extender withdraw it.
#[tokio::test]
async fn an_extending_source_cannot_unban_the_creators_mitigation() {
    let f = fixture(AuthMode::Credentials).await;
    let fnm = bearer(
        &f.repo
            .mint_token_for_test("fnm", TokenScope::Ingest, Some("fastnetmon")),
    );
    let rw = bearer(
        &f.repo
            .mint_token_for_test("rw", TokenScope::Ingest, Some("radware")),
    );
    let victim = "203.0.113.74";
    let (_, created) = send(
        &f.app,
        "/v1/events",
        Some(("authorization", &fnm)),
        &event("fastnetmon", victim, "a-1"),
    )
    .await;
    let (_, extended) = send(
        &f.app,
        "/v1/events",
        Some(("authorization", &rw)),
        &event("radware", victim, "b-1"),
    )
    .await;
    assert_eq!(extended["status"], "extended", "{extended}");
    assert_eq!(extended["mitigation_id"], created["mitigation_id"]);

    let (_, body) = send(
        &f.app,
        "/v1/events",
        Some(("authorization", &rw)),
        &unban("radware", victim, "b-2"),
    )
    .await;
    assert_eq!(body["status"], "no_active_mitigation", "{body}");
    let (_, body) = send(
        &f.app,
        "/v1/events",
        Some(("authorization", &fnm)),
        &unban("fastnetmon", victim, "a-2"),
    )
    .await;
    assert_eq!(body["status"], "withdrawn", "{body}");
    assert_eq!(body["mitigation_ids"], json!([created["mitigation_id"]]));
}

/// A disabled adapter serves no requests, so it is no credential and the
/// ingest refusals skip it; enabled, the same adapter is refused.
#[test]
fn disabled_adapters_skip_the_ingest_refusals_until_enabled() {
    let document = "enabled: true\nwebhook_adapters:\n  - name: radware\n    enabled: false\n    auth:\n      type: hmac\n      secret_env: PATH\n      header: X-Signature-SHA256\n    fields:\n      victim_ip: \"$.ip\"\n  - name: lab\n    enabled: false\n    auth:\n      type: none\n    fields:\n      victim_ip: \"$.ip\"\n";
    let (mut config, _) = CorrelationConfig::from_yaml(document).unwrap();
    let ingest = prefixd::correlation::IngestAuthorization {
        auth_mode: AuthMode::Credentials,
        detector_sources: &["radware".to_string()],
        prefix_sources: &[],
    };
    assert!(
        config.validate(&ingest).is_empty(),
        "{:?}",
        config.validate(&ingest)
    );
    for adapter in &mut config.webhook_adapters {
        adapter.enabled = true;
    }
    let errors = config.validate(&ingest);
    for wanted in ["PREFIXD_WEBHOOK_", "fields.source_id", "auth.type none"] {
        assert!(
            errors.iter().any(|error| error.contains(wanted)),
            "{wanted}: {errors:?}"
        );
    }
}

/// Reload checks what it publishes against the next start's prefixd.yaml, not
/// only the running one: a prefixd.yaml that puts an HMAC adapter without
/// `fields.source_id` on an allowlist is refused, and the running
/// configuration is kept. Control: without the allowlist the same reload
/// publishes. Negative control: checking the running settings alone accepts
/// the refused reload.
#[tokio::test]
async fn reload_checks_the_correlation_against_the_next_prefixd_yaml() {
    if !rerun_with(
        "reload_checks_the_correlation_against_the_next_prefixd_yaml",
        &[("PREFIXD_WEBHOOK_GOOD", LONG_SECRET)],
    ) {
        return;
    }
    let document = adapter_yaml(
        "    auth:\n      type: hmac\n      secret_env: PREFIXD_WEBHOOK_GOOD\n      header: X-Signature-SHA256\n",
    );
    for (allowlist, refused) in [(vec!["radware".to_string()], true), (vec![], false)] {
        let mut running = settings(AuthMode::Credentials, "test-pop", 1);
        running.correlation = CorrelationConfig::default();
        let mut next = running.clone();
        next.blackhole.detector_sources = allowlist;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("prefixd.yaml"),
            serde_json::to_string(&next).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.path().join("correlation.yaml"), &document).unwrap();
        let f = fixture_with(running, Arc::new(MockRepository::new())).await;
        let mut state = f.state.clone();
        drop(f);
        Arc::get_mut(&mut state).unwrap().config_dir = dir.path().into();
        let result = state.reload_config().await;
        let adapters = state
            .correlation_config
            .read()
            .await
            .webhook_adapters
            .clone();
        if refused {
            let error = result.unwrap_err().to_string();
            assert!(error.contains("fields.source_id"), "{error}");
            assert!(
                matches!(adapters[0].auth, WebhookAuth::Bearer),
                "the running configuration is kept"
            );
        } else {
            result.unwrap();
            assert!(matches!(adapters[0].auth, WebhookAuth::Hmac { .. }));
        }
    }
}

/// An adapter on an allowlist reaches blackholes or prefix rules, and a
/// signed body has no nonce: a ban whose `fields.source_id` resolves to no ID
/// is refused with 400 before admission, so a replay cannot recreate the
/// mitigation. With an ID, the replay is a duplicate. Negative control:
/// without the check, the ID-less ban is admitted and its replay recreates
/// the mitigation.
#[tokio::test]
async fn an_allowlisted_adapter_refuses_bans_without_an_event_id() {
    const SECRET: &str = "0123456789abcdef0123456789abcdef-replay";
    if !rerun_with(
        "an_allowlisted_adapter_refuses_bans_without_an_event_id",
        &[("PREFIXD_WEBHOOK_TEST_SIGNED", SECRET)],
    ) {
        return;
    }
    let mut settings = settings(AuthMode::Credentials, "test-pop", 1);
    settings.blackhole.detector_sources = vec!["signed".into()];
    let f = fixture_with(settings, Arc::new(MockRepository::new())).await;
    f.state.correlation_config.write().await.webhook_adapters = vec![webhook_adapter(
        "signed",
        WebhookAuth::Hmac {
            secret_env: "PREFIXD_WEBHOOK_TEST_SIGNED".into(),
            header: "X-Signature-SHA256".into(),
            algorithm: "sha256".into(),
        },
    )];
    let post = |body: Value| {
        let app = f.app.clone();
        async move {
            use hmac::{KeyInit, Mac};
            let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
            mac.update(body.to_string().as_bytes());
            let response = app
                .oneshot(
                    Request::post("/v1/signals/webhook/signed")
                        .header("content-type", "application/json")
                        .header(
                            "x-signature-sha256",
                            hex::encode(mac.finalize().into_bytes()),
                        )
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap();
            (status, serde_json::from_slice::<Value>(&bytes).unwrap())
        }
    };
    for (label, body) in [
        (
            "missing",
            json!({"ip": "203.0.113.75", "vector": "udp_flood", "score": 0.9}),
        ),
        (
            "null",
            json!({"id": null, "ip": "203.0.113.75", "vector": "udp_flood", "score": 0.9}),
        ),
        (
            "object",
            json!({"id": {"x": 1}, "ip": "203.0.113.75", "vector": "udp_flood", "score": 0.9}),
        ),
    ] {
        for replay in 0..2 {
            let (status, response) = post(body.clone()).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{label} {replay}: {response}"
            );
            assert!(
                response["error"]
                    .as_str()
                    .unwrap()
                    .contains("fields.source_id")
            );
        }
    }
    assert_eq!(written(&f.repo).await, (0, 0, 0));

    let identified =
        json!({"id": "s-1", "ip": "203.0.113.75", "vector": "udp_flood", "score": 0.9});
    let (status, first) = post(identified.clone()).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert!(first["results"][0]["mitigation_id"].is_string(), "{first}");
    let (status, replayed) = post(identified).await;
    assert_eq!(status, StatusCode::OK, "{replayed}");
    assert_eq!(replayed["results"][0]["status"], "duplicate", "{replayed}");
    assert_eq!(
        written(&f.repo).await.1,
        1,
        "the replay made no second mitigation"
    );
}

/// A detector unban is counted as `detector_unban` whoever claims the source:
/// here the anonymous Admin of auth mode none, an operator actor.
#[tokio::test]
async fn an_admin_claimed_unban_counts_as_a_detector_unban() {
    let f = fixture_with(
        settings(AuthMode::None, "metric-pop", 1),
        Arc::new(MockRepository::new()),
    )
    .await;
    let counter = |reason: &str| {
        prefixd::observability::metrics::MITIGATIONS_WITHDRAWN
            .with_label_values(&["police", "metric-pop", reason])
            .get()
    };
    let (detector, operator) = (counter("detector_unban"), counter("operator"));
    let victim = "203.0.113.76";
    let (status, body) = send(
        &f.app,
        "/v1/events",
        None,
        &event("fastnetmon", victim, "m-1"),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let (_, body) = send(
        &f.app,
        "/v1/events",
        None,
        &unban("fastnetmon", victim, "m-2"),
    )
    .await;
    assert_eq!(body["status"], "withdrawn", "{body}");
    assert_eq!(counter("detector_unban"), detector + 1.0);
    assert_eq!(counter("operator"), operator);
}

const VECTOR_PLAYBOOKS: &str = r#"
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
  - name: syn_flood
    match: { vector: syn_flood }
    steps:
      - { action: discard, ttl_seconds: 120 }
  - name: ack_flood
    match: { vector: ack_flood }
    steps:
      - { action: police, rate_bps: 5000000, ttl_seconds: 120 }
  - name: icmp_flood
    match: { vector: icmp_flood }
    steps:
      - { action: discard, ttl_seconds: 120 }
"#;

async fn live_for(repo: &MockRepository, victim: &str) -> Vec<prefixd::domain::Mitigation> {
    repo.list_live_by_victim_and_source(victim, "test-pop", "fastnetmon")
        .await
        .unwrap()
}

/// The native FastNetMon adapter's unban withdraws what its ban created, even
/// when the unban's own payload would classify as another vector: the end of
/// an attack has other counters and often no packet dump. The reviewer's
/// probe: an amplification ban from the ntp-memcached dump, then the same
/// payload as an unban without the dump; and a SYN ban whose unban counters
/// read as an ACK flood. Negative control: classifying the unban's payload
/// again leaves the SYN rule live.
#[tokio::test]
async fn native_fastnetmon_unbans_withdraw_what_the_ban_created() {
    let f = fixture(AuthMode::Credentials).await;
    *f.state.playbooks.write().await =
        prefixd::config::Playbooks::from_yaml(VECTOR_PLAYBOOKS).unwrap();
    let fnm = bearer(
        &f.repo
            .mint_token_for_test("fnm", TokenScope::Ingest, Some("fastnetmon")),
    );
    let auth = Some(("authorization", fnm.as_str()));

    let ban: Value = serde_json::from_str(include_str!(
        "fixtures/fastnetmon/native-ntp-memcached.json"
    ))
    .unwrap();
    let victim = ban["ip"].as_str().unwrap().to_string();
    let (status, body) = send(&f.app, "/v1/signals/fastnetmon", auth, &ban).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let live = live_for(&f.repo, &victim).await;
    assert!(!live.is_empty());
    assert!(
        live.iter()
            .all(|m| m.vector == prefixd::domain::AttackVector::UdpAmplification),
        "{live:?}"
    );
    let mut unban = ban.clone();
    unban["action"] = "unban".into();
    unban
        .as_object_mut()
        .unwrap()
        .remove("packet_dump_detailed");
    let (status, body) = send(&f.app, "/v1/signals/fastnetmon", auth, &unban).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "withdrawn", "{body}");
    assert!(live_for(&f.repo, &victim).await.is_empty());

    let syn_victim = "203.0.113.77";
    let details = |syn: i64| {
        json!({
            "attack_uuid": "syn-ack-1", "incoming_tcp_pps": 10000,
            "incoming_syn_tcp_pps": syn, "total_incoming_pps": 10000,
        })
    };
    let ban = json!({"action": "ban", "ip": syn_victim, "alert_scope": "host",
        "attack_details": details(9000)});
    let (status, body) = send(&f.app, "/v1/signals/fastnetmon", auth, &ban).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(
        live_for(&f.repo, syn_victim).await[0].vector,
        prefixd::domain::AttackVector::SynFlood
    );
    let unban = json!({"action": "unban", "ip": syn_victim, "alert_scope": "host",
        "attack_details": details(1000)});
    let (_, body) = send(&f.app, "/v1/signals/fastnetmon", auth, &unban).await;
    assert_eq!(body["status"], "withdrawn", "{body}");
    assert!(live_for(&f.repo, syn_victim).await.is_empty());
}

/// UDP floods and amplification are one family for an unban: a
/// `udp_amplification` ban that fell back to a `udp_flood` rule (no
/// amplification playbook) is withdrawn by an amplification unban.
/// Negative control: without the family rule the unban finds nothing.
#[tokio::test]
async fn an_amplification_unban_withdraws_its_udp_flood_fallback() {
    let f = fixture(AuthMode::Credentials).await;
    let fnm = bearer(
        &f.repo
            .mint_token_for_test("fnm", TokenScope::Ingest, Some("fastnetmon")),
    );
    let auth = Some(("authorization", fnm.as_str()));
    let victim = "203.0.113.78";
    let mut ban = with_vector(event("fastnetmon", victim, "amp-1"), "udp_amplification");
    ban["top_src_ports"] = json!([123]);
    let (status, body) = send(&f.app, "/v1/events", auth, &ban).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let live = live_for(&f.repo, victim).await;
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].vector, prefixd::domain::AttackVector::UdpFlood);
    let (_, body) = send(
        &f.app,
        "/v1/events",
        auth,
        &with_vector(unban("fastnetmon", victim, "amp-2"), "udp_amplification"),
    )
    .await;
    assert_eq!(body["status"], "withdrawn", "{body}");
    assert!(live_for(&f.repo, victim).await.is_empty());
}

/// A captured unban replayed after a new ban reuses its original targets and
/// never selects again, so the new mitigation stays live. Negative control:
/// selecting again withdraws the new mitigation.
#[tokio::test]
async fn a_replayed_unban_cannot_withdraw_a_later_mitigation() {
    let f = fixture(AuthMode::Credentials).await;
    let fnm = bearer(
        &f.repo
            .mint_token_for_test("fnm", TokenScope::Ingest, Some("fastnetmon")),
    );
    let auth = Some(("authorization", fnm.as_str()));
    let victim = "203.0.113.79";
    let (_, first) = send(
        &f.app,
        "/v1/events",
        auth,
        &event("fastnetmon", victim, "b-1"),
    )
    .await;
    let (_, withdrawn) = send(
        &f.app,
        "/v1/events",
        auth,
        &unban("fastnetmon", victim, "u-1"),
    )
    .await;
    assert_eq!(withdrawn["mitigation_ids"], json!([first["mitigation_id"]]));
    let (_, second) = send(
        &f.app,
        "/v1/events",
        auth,
        &event("fastnetmon", victim, "b-2"),
    )
    .await;
    let second: uuid::Uuid = second["mitigation_id"].as_str().unwrap().parse().unwrap();

    let (status, replayed) = send(
        &f.app,
        "/v1/events",
        auth,
        &unban("fastnetmon", victim, "u-1"),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{replayed}");
    assert_eq!(replayed["event_id"], withdrawn["event_id"], "{replayed}");
    assert_eq!(replayed["mitigation_ids"], json!([first["mitigation_id"]]));
    assert_eq!(
        f.repo.get_mitigation(second).await.unwrap().unwrap().status,
        MitigationStatus::Active
    );

    // An unban that found nothing is remembered as nothing.
    let other = "203.0.113.80";
    let (_, empty) = send(
        &f.app,
        "/v1/events",
        auth,
        &unban("fastnetmon", other, "u-2"),
    )
    .await;
    assert_eq!(empty["status"], "no_active_mitigation", "{empty}");
    let (_, later) = send(
        &f.app,
        "/v1/events",
        auth,
        &event("fastnetmon", other, "b-3"),
    )
    .await;
    let (_, replayed) = send(
        &f.app,
        "/v1/events",
        auth,
        &unban("fastnetmon", other, "u-2"),
    )
    .await;
    assert_eq!(replayed["status"], "no_active_mitigation", "{replayed}");
    let later: uuid::Uuid = later["mitigation_id"].as_str().unwrap().parse().unwrap();
    assert!(
        f.repo
            .get_mitigation(later)
            .await
            .unwrap()
            .unwrap()
            .is_active()
    );
}

/// A speaker whose TCP deletes never return.
struct HangingTcpWithdrawals {
    inner: MockAnnouncer,
    hanging: std::sync::atomic::AtomicBool,
    deletes: std::sync::atomic::AtomicUsize,
}

impl prefixd::bgp::FlowSpecAnnouncer for HangingTcpWithdrawals {
    fn backend(&self) -> &'static str {
        "mock"
    }
    fn reader(&self) -> Option<&dyn prefixd::bgp::FlowSpecReader> {
        Some(self)
    }
    fn peer_observer(&self) -> Option<&dyn prefixd::bgp::PeerObserver> {
        Some(self)
    }
}

#[async_trait::async_trait]
impl prefixd::bgp::FlowSpecWriter for HangingTcpWithdrawals {
    async fn announce(&self, rule: &prefixd::domain::FlowSpecRule) -> prefixd::error::Result<()> {
        self.inner.announce(rule).await
    }
    async fn withdraw(&self, rule: &prefixd::domain::FlowSpecRule) -> prefixd::error::Result<()> {
        use std::sync::atomic::Ordering::SeqCst;
        self.deletes.fetch_add(1, SeqCst);
        if rule.nlri.protocol == Some(6) && self.hanging.load(SeqCst) {
            std::future::pending::<()>().await;
        }
        self.inner.withdraw(rule).await
    }
}

#[async_trait::async_trait]
impl prefixd::bgp::FlowSpecReader for HangingTcpWithdrawals {
    async fn list_active(&self) -> prefixd::error::Result<Vec<prefixd::domain::FlowSpecRule>> {
        self.inner.list_active().await
    }
}

#[async_trait::async_trait]
impl prefixd::bgp::PeerObserver for HangingTcpWithdrawals {
    async fn session_status(&self) -> prefixd::error::Result<Vec<prefixd::bgp::PeerStatus>> {
        self.inner.session_status().await
    }
}

/// A delete that times out is ambiguous, so the unban stops there: the
/// lifecycle mutex is held for one bounded attempt, not one per rule, and the
/// rest stay pending with their intents recorded. A resend of the same unban
/// reuses those targets and finishes them once the speaker answers, leaving a
/// mitigation banned in between. Time is paused, so the 3 s deadline elapses
/// without waiting. Negative controls: carrying on after a timeout attempts
/// the second delete too, and selecting again on the resend withdraws the
/// later mitigation.
#[tokio::test(start_paused = true)]
async fn an_ambiguous_delete_stops_the_unban_and_a_resend_finishes_it() {
    let repo = Arc::new(MockRepository::new());
    let speaker = Arc::new(HangingTcpWithdrawals {
        inner: MockAnnouncer::new(),
        hanging: std::sync::atomic::AtomicBool::new(true),
        deletes: std::sync::atomic::AtomicUsize::new(0),
    });
    let mut settings = settings(AuthMode::Credentials, "test-pop", 1);
    settings.mode = prefixd::config::OperationMode::Enforced;
    let state = AppState::new(
        settings,
        Inventory::new(vec![Customer {
            customer_id: "bound".into(),
            name: "Source binding".into(),
            prefixes: vec!["203.0.113.0/24".into()],
            policy_profile: PolicyProfile::Normal,
            services: vec![],
        }]),
        common::test_playbooks(),
        repo.clone(),
        speaker.clone(),
        ".".into(),
    )
    .unwrap();
    let app =
        prefixd::api::create_test_router_with_session_store(state.clone(), MemoryStore::default());
    let fnm = bearer(&repo.mint_token_for_test("fnm", TokenScope::Ingest, Some("fastnetmon")));
    let auth = Some(("authorization", fnm.as_str()));
    let victim = "203.0.113.81";
    let mut ids = Vec::new();
    for (id, vector) in [("s1", "syn_flood"), ("u1", "udp_flood")] {
        let (_, body) = send(
            &app,
            "/v1/events",
            auth,
            &with_vector(event("fastnetmon", victim, id), vector),
        )
        .await;
        ids.push(
            body["mitigation_id"]
                .as_str()
                .unwrap()
                .parse::<uuid::Uuid>()
                .unwrap(),
        );
    }
    let unban = with_vector(unban("fastnetmon", victim, "u-timeout"), "unknown");
    let (status, body) = send(&app, "/v1/events", auth, &unban).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(
        speaker.deletes.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the unban stopped at the timed-out delete"
    );
    let mut pending: Vec<_> = repo
        .pending_withdrawals(None)
        .await
        .unwrap()
        .into_iter()
        .map(|request| request.mitigation_id)
        .collect();
    pending.sort();
    let mut wanted = ids.clone();
    wanted.sort();
    assert_eq!(pending, wanted, "both intents are recorded");

    // A ban after the 503, of another rule, is not one of the unban's targets.
    *state.playbooks.write().await =
        prefixd::config::Playbooks::from_yaml(VECTOR_PLAYBOOKS).unwrap();
    let (_, later) = send(
        &app,
        "/v1/events",
        auth,
        &with_vector(event("fastnetmon", victim, "i1"), "icmp_flood"),
    )
    .await;
    let later: uuid::Uuid = later["mitigation_id"]
        .as_str()
        .unwrap_or_else(|| panic!("{later}"))
        .parse()
        .unwrap();

    speaker
        .hanging
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let (status, body) = send(&app, "/v1/events", auth, &unban).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    for id in ids {
        assert_eq!(
            repo.get_mitigation(id).await.unwrap().unwrap().status,
            MitigationStatus::Withdrawn
        );
    }
    assert!(repo.pending_withdrawals(None).await.unwrap().is_empty());
    assert_eq!(
        repo.get_mitigation(later).await.unwrap().unwrap().status,
        MitigationStatus::Active,
        "the resend completed only the original targets"
    );
}

/// Every HMAC adapter's unban needs an event ID, so a replay of it reuses its
/// targets. Negative control: without the check the ID-less unban runs.
#[tokio::test]
async fn an_hmac_unban_without_an_event_id_is_refused() {
    const SECRET: &str = "0123456789abcdef0123456789abcdef-unban";
    if !rerun_with(
        "an_hmac_unban_without_an_event_id_is_refused",
        &[("PREFIXD_WEBHOOK_TEST_SIGNED", SECRET)],
    ) {
        return;
    }
    let f = fixture(AuthMode::Credentials).await;
    f.state.correlation_config.write().await.webhook_adapters = vec![webhook_adapter(
        "signed",
        WebhookAuth::Hmac {
            secret_env: "PREFIXD_WEBHOOK_TEST_SIGNED".into(),
            header: "X-Signature-SHA256".into(),
            algorithm: "sha256".into(),
        },
    )];
    let body = json!({"ip": "203.0.113.82", "vector": "udp_flood", "action": "unban"});
    let signature = {
        use hmac::{KeyInit, Mac};
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
        mac.update(body.to_string().as_bytes());
        hex::encode(mac.finalize().into_bytes())
    };
    let response = f
        .app
        .clone()
        .oneshot(
            Request::post("/v1/signals/webhook/signed")
                .header("content-type", "application/json")
                .header("x-signature-sha256", signature)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    assert!(text.contains("every unban from an HMAC adapter"), "{text}");
    assert_eq!(written(&f.repo).await, (0, 0, 0));
}

/// The ingest extractor refuses a principal that cannot hold a grant before
/// the body is parsed: malformed JSON from an Operator gets 403 and without a
/// credential 401, not a parse error. Negative control: checking the
/// principal after extraction answers the parse error.
#[tokio::test]
async fn ingest_routes_refuse_the_principal_before_parsing_the_body() {
    let f = fixture(AuthMode::Credentials).await;
    let operator = bearer(
        &f.repo
            .mint_token_for_test("automation", TokenScope::Operator, None),
    );
    for path in ["/v1/events", "/v1/events/batch", "/v1/signals/corroborator"] {
        for (auth, expected) in [
            (Some(operator.as_str()), StatusCode::FORBIDDEN),
            (None, StatusCode::UNAUTHORIZED),
        ] {
            let mut request = Request::post(path).header("content-type", "application/json");
            if let Some(auth) = auth {
                request = request.header("authorization", auth);
            }
            let response = f
                .app
                .clone()
                .oneshot(request.body(Body::from("{not json")).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "{path} {auth:?}");
        }
    }
}
