//! Scoped API tokens at the HTTP boundary (ADR 034): credential precedence,
//! scopes, management, POP binding, every auth mode and secret exposure. These
//! use the mock repository; the PostgreSQL paths are in integration_postgres.rs.

mod common;

use argon2::{Argon2, PasswordHasher};
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use prefixd::AppState;
use prefixd::bgp::MockAnnouncer;
use prefixd::config::{AuthMode, OperationMode};
use prefixd::db::{ListParams, MockRepository, RepositoryTrait};
use prefixd::domain::{OperatorRole, TokenScope};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;
use tower_sessions::MemoryStore;
use utoipa::OpenApi;

const PASSWORD: &str = "api-token-test-password";

struct Fixture {
    app: Router,
    repo: Arc<MockRepository>,
    state: Arc<AppState>,
}

fn state(mode: AuthMode, pop: &str, repo: Arc<MockRepository>) -> Arc<AppState> {
    let mut settings = common::test_settings();
    settings.mode = OperationMode::Enforced;
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
    AppState::new(
        settings,
        common::test_inventory(),
        common::test_playbooks(),
        repo,
        Arc::new(MockAnnouncer::new()),
        ".".into(),
    )
    .unwrap()
}

fn fixture(mode: AuthMode) -> Fixture {
    let repo = Arc::new(MockRepository::new());
    let state = state(mode, "test-pop", repo.clone());
    let app =
        prefixd::api::create_test_router_with_session_store(state.clone(), MemoryStore::default());
    Fixture { app, repo, state }
}

async fn send(
    app: &Router,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&Value>,
) -> (StatusCode, HeaderMap, String) {
    let mut request = Request::builder().method(method).uri(path);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let body = match body {
        Some(body) => {
            request = request.header("content-type", "application/json");
            Body::from(body.to_string())
        }
        None => Body::empty(),
    };
    let response = app
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

async fn login(app: &Router, repo: &MockRepository, username: &str, role: OperatorRole) -> String {
    let hash = Argon2::default()
        .hash_password_with_salt(PASSWORD.as_bytes(), b"api-token-tests")
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

/// The routes an ingest token reaches (ADR 034 §3).
const INGEST_ROUTES: [(&str, &str); 6] = [
    ("post", "/v1/events"),
    ("post", "/v1/events/batch"),
    ("post", "/v1/signals/fastnetmon"),
    ("post", "/v1/signals/alertmanager"),
    ("post", "/v1/signals/webhook/{name}"),
    ("post", "/v1/signals/corroborator"),
];

/// Every documented `/v1` operation refuses an ingest token with 403 before it
/// reads the body, except the ingest routes, the public liveness and readiness
/// routes, and the session routes. The OpenAPI test proves the document lists
/// every routed operation, so a new route joins this sweep automatically.
#[tokio::test]
async fn ingest_tokens_reach_only_the_ingest_routes() {
    let fixture = fixture(AuthMode::Credentials);
    let token =
        fixture
            .repo
            .mint_token_for_test("fnm-pop1", TokenScope::Ingest, Some("fastnetmon"));
    let authorization = bearer(&token);
    let doc = serde_json::to_value(prefixd::api::ApiDoc::openapi()).unwrap();
    let mut swept = 0;
    for (path, item) in doc["paths"].as_object().unwrap() {
        if !path.starts_with("/v1/")
            || matches!(path.as_str(), "/v1/health" | "/v1/ready")
            || path.starts_with("/v1/auth/")
        {
            continue;
        }
        for method in item.as_object().unwrap().keys() {
            if !["get", "post", "put", "delete"].contains(&method.as_str())
                || INGEST_ROUTES.contains(&(method.as_str(), path.as_str()))
            {
                continue;
            }
            let concrete = path
                .replace("{id}", "00000000-0000-0000-0000-000000000000")
                .replace("{prefix}", "192.0.2.1%2F32")
                .replace("{ip}", "203.0.113.10")
                .replace("{name}", "fnm-pop1")
                .replace("{profile}", "a");
            let body = (method != "get").then(|| json!({}));
            let (status, _, response) = send(
                &fixture.app,
                &method.to_uppercase(),
                &concrete,
                &[("authorization", &authorization)],
                body.as_ref(),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{method} {path} must refuse an ingest token: {response}"
            );
            swept += 1;
        }
    }
    assert!(swept > 50, "the sweep covered only {swept} operations");
    // Nothing was written by any refused request.
    assert!(
        fixture
            .repo
            .list_audit(&ListParams {
                limit: 10,
                ..Default::default()
            })
            .await
            .unwrap()
            .is_empty()
    );

    // Control: the same token reaches every ingest route past authentication.
    let event = json!({
        "source": "fastnetmon", "victim_ip": "203.0.113.10", "vector": "udp_flood",
        "timestamp": chrono::Utc::now(), "pps": 50000, "top_dst_ports": [53],
        "confidence": 0.9, "event_id": "ingest-sweep"
    });
    let corroborator = json!({"source": "fastnetmon"});
    let fnm = json!({"action": "ban", "ip": "203.0.113.11"});
    let alerts = json!({"alerts": []});
    for (path, body) in [
        ("/v1/events", &event),
        ("/v1/events/batch", &json!({"events": [event.clone()]})),
        ("/v1/signals/fastnetmon", &fnm),
        ("/v1/signals/alertmanager", &alerts),
        ("/v1/signals/corroborator", &corroborator),
    ] {
        let (status, _, response) = send(
            &fixture.app,
            "POST",
            path,
            &[("authorization", &authorization)],
            Some(body),
        )
        .await;
        assert!(
            ![StatusCode::UNAUTHORIZED, StatusCode::FORBIDDEN].contains(&status),
            "{path}: {status} {response}"
        );
    }
}

/// An ingest token cannot read data or create or withdraw manual rules; an
/// operator token still can.
#[tokio::test]
async fn ingest_tokens_cannot_read_or_manage_rules_while_operator_tokens_can() {
    let fixture = fixture(AuthMode::Credentials);
    let ingest = bearer(&fixture.repo.mint_token_for_test(
        "fnm-ingest",
        TokenScope::Ingest,
        Some("fastnetmon"),
    ));
    let operator = bearer(&fixture.repo.mint_token_for_test(
        "automation",
        TokenScope::Operator,
        None,
    ));
    let rule = json!({"victim_ip": "203.0.113.10", "protocol": "udp", "dst_ports": [53],
        "action": "discard", "ttl_seconds": 120, "reason": "manual rule"});
    let (status, _, _) = send(
        &fixture.app,
        "POST",
        "/v1/mitigations",
        &[("authorization", &ingest)],
        Some(&rule),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, created) = send(
        &fixture.app,
        "POST",
        "/v1/mitigations",
        &[("authorization", &operator)],
        Some(&rule),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = serde_json::from_str::<Value>(&created).unwrap()["mitigation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    for (method, path) in [
        ("GET", "/v1/mitigations".to_string()),
        ("GET", format!("/v1/mitigations/{id}")),
        ("GET", "/v1/events".to_string()),
        ("GET", "/v1/audit".to_string()),
    ] {
        let (status, _, _) = send(
            &fixture.app,
            method,
            &path,
            &[("authorization", &ingest)],
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        let (status, _, _) = send(
            &fixture.app,
            method,
            &path,
            &[("authorization", &operator)],
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{path}");
    }
    let withdraw = json!({"reason": "done"});
    let path = format!("/v1/mitigations/{id}/withdraw");
    let (status, _, _) = send(
        &fixture.app,
        "POST",
        &path,
        &[("authorization", &ingest)],
        Some(&withdraw),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, body) = send(
        &fixture.app,
        "POST",
        &path,
        &[("authorization", &operator)],
        Some(&withdraw),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A 58-character token name is the longest whose actor ID, `token:<name>`,
/// fits every Operator mutation's 64-character actor check. Each mutation
/// succeeds and is audited under that actor; a 59-character name is refused at
/// creation.
#[tokio::test]
async fn the_longest_token_name_passes_every_operator_mutation() {
    let fixture = fixture(AuthMode::Credentials);
    let admin = login(
        &fixture.app,
        &fixture.repo,
        "token-admin",
        OperatorRole::Admin,
    )
    .await;
    let name = "a".repeat(58);
    let (status, _, created) = send(
        &fixture.app,
        "POST",
        "/v1/tokens",
        &[("cookie", &admin)],
        Some(&json!({"name": name, "scope": "admin"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let token = bearer(
        serde_json::from_str::<Value>(&created).unwrap()["token"]
            .as_str()
            .unwrap(),
    );
    let (status, _, refused) = send(
        &fixture.app,
        "POST",
        "/v1/tokens",
        &[("cookie", &admin)],
        Some(&json!({"name": "a".repeat(59), "scope": "admin"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    let auth = [("authorization", token.as_str())];
    let actor = format!("token:{name}");
    assert_eq!(actor.len(), 64);

    let mut ids = Vec::new();
    for ip in ["203.0.113.10", "203.0.113.11", "203.0.113.12"] {
        let rule = json!({"victim_ip": ip, "protocol": "udp", "dst_ports": [53],
            "action": "discard", "ttl_seconds": 120, "reason": "manual rule"});
        let (status, _, body) =
            send(&fixture.app, "POST", "/v1/mitigations", &auth, Some(&rule)).await;
        assert_eq!(status, StatusCode::CREATED, "create: {body}");
        ids.push(
            serde_json::from_str::<Value>(&body).unwrap()["mitigation_id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    let (status, _, body) = send(
        &fixture.app,
        "POST",
        "/v1/mitigations/acknowledge",
        &auth,
        Some(&json!({"mitigation_ids": [ids[0]]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "acknowledge: {body}");
    let (status, _, body) = send(
        &fixture.app,
        "POST",
        &format!("/v1/mitigations/{}/extend", ids[0]),
        &auth,
        Some(&json!({"ttl_seconds": 600, "reason": "attack continues"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "extend: {body}");
    let (status, _, body) = send(
        &fixture.app,
        "POST",
        &format!("/v1/mitigations/{}/withdraw", ids[0]),
        &auth,
        Some(&json!({"reason": "done"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "withdraw: {body}");
    let (status, _, body) = send(
        &fixture.app,
        "POST",
        "/v1/mitigations/withdraw",
        &auth,
        Some(&json!({"mitigation_ids": [ids[1], ids[2]], "reason": "done"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "bulk withdraw: {body}");
    let (status, _, body) = send(
        &fixture.app,
        "POST",
        "/v1/safelist",
        &auth,
        Some(&json!({"prefix": "203.0.113.200/32", "reason": "lab"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "safelist add: {body}");
    let (_, _, listed) = send(&fixture.app, "GET", "/v1/safelist", &auth, None).await;
    let listed: Value = serde_json::from_str(&listed).unwrap();
    let entry = listed
        .as_array()
        .or_else(|| listed["entries"].as_array())
        .unwrap()
        .iter()
        .find(|entry| entry["prefix"] == "203.0.113.200/32")
        .cloned()
        .unwrap();
    assert_eq!(entry["added_by"], actor.as_str());
    let (status, _, body) = send(
        &fixture.app,
        "DELETE",
        "/v1/safelist/203.0.113.200%2F32",
        &auth,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "safelist remove: {body}");

    let audit = fixture
        .repo
        .list_audit(&ListParams {
            limit: 100,
            ..Default::default()
        })
        .await
        .unwrap();
    let mutations: Vec<_> = audit
        .iter()
        .filter(|entry| entry.action != "api_token.create")
        .collect();
    // Create three, extend, withdraw, and bulk withdraw two.
    assert_eq!(mutations.len(), 7, "{mutations:?}");
    for entry in mutations {
        assert_eq!(entry.actor_id.as_deref(), Some(actor.as_str()), "{entry:?}");
    }
    let row = fixture
        .repo
        .get_mitigation(ids[0].parse().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.acknowledged_by.as_deref(), Some(actor.as_str()));
}

/// `/v1/tokens` needs an Admin session. Admin, operator and ingest tokens get
/// 403, an Operator session gets 403, and the create response is the only
/// place the secret appears.
#[tokio::test]
async fn token_management_needs_an_admin_session() {
    let fixture = fixture(AuthMode::Credentials);
    let admin = login(&fixture.app, &fixture.repo, "admin", OperatorRole::Admin).await;
    let operator = login(
        &fixture.app,
        &fixture.repo,
        "operator",
        OperatorRole::Operator,
    )
    .await;
    let admin_token = bearer(&fixture.repo.mint_token_for_test(
        "admin-token",
        TokenScope::Admin,
        None,
    ));
    let operator_token = bearer(&fixture.repo.mint_token_for_test(
        "operator-token",
        TokenScope::Operator,
        None,
    ));
    let create =
        json!({"name": "fnm-pop1", "scope": "ingest", "source": "fastnetmon", "pop": "test-pop"});
    for (name, value) in [
        ("authorization", admin_token.as_str()),
        ("authorization", operator_token.as_str()),
        ("cookie", operator.as_str()),
    ] {
        for (method, path, body) in [
            ("POST", "/v1/tokens", Some(&create)),
            ("GET", "/v1/tokens", None),
            ("POST", "/v1/tokens/admin-token/revoke", None),
        ] {
            let (status, _, _) = send(&fixture.app, method, path, &[(name, value)], body).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{name} {method} {path}");
        }
    }
    let (status, _, _) = send(&fixture.app, "GET", "/v1/tokens", &[], None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // The admin token still works elsewhere: it is not revoked by the refusal.
    let (status, _, _) = send(
        &fixture.app,
        "GET",
        "/v1/operators",
        &[("authorization", &admin_token)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, headers, created) = send(
        &fixture.app,
        "POST",
        "/v1/tokens",
        &[("cookie", &admin)],
        Some(&create),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(headers["cache-control"], "no-store");
    let created: Value = serde_json::from_str(&created).unwrap();
    let secret = created["token"].as_str().unwrap().to_owned();
    assert!(secret.starts_with("prefixd_") && secret.len() == 51);
    assert_eq!(created["name"], "fnm-pop1");
    assert_eq!(created["scope"], "ingest");
    assert_eq!(created["source"], "fastnetmon");
    assert_eq!(created["pop"], "test-pop");
    assert_eq!(created["created_by"], "admin");
    let hash = hex::encode(prefixd::auth::token::hash(&secret));
    // Name reuse is refused, revoked or not.
    let (status, _, _) = send(
        &fixture.app,
        "POST",
        "/v1/tokens",
        &[("cookie", &admin)],
        Some(&create),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _, list) = send(
        &fixture.app,
        "GET",
        "/v1/tokens",
        &[("cookie", &admin)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, revoked) = send(
        &fixture.app,
        "POST",
        "/v1/tokens/fnm-pop1/revoke",
        &[("cookie", &admin)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, again) = send(
        &fixture.app,
        "POST",
        "/v1/tokens/fnm-pop1/revoke",
        &[("cookie", &admin)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        revoked, again,
        "revoking a revoked token returns the same record"
    );
    let (status, _, _) = send(
        &fixture.app,
        "POST",
        "/v1/tokens/missing/revoke",
        &[("cookie", &admin)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, _, audit) = send(
        &fixture.app,
        "GET",
        "/v1/audit",
        &[("cookie", &admin)],
        None,
    )
    .await;
    assert!(audit.contains("api_token.create") && audit.contains("api_token.revoke"));
    for (label, body) in [("list", &list), ("revoke", &revoked), ("audit", &audit)] {
        assert!(!body.contains(&secret), "{label} leaked the secret");
        assert!(!body.contains(&hash), "{label} leaked the hash");
        assert!(!body.contains("token_hash"), "{label}: {body}");
    }
    let (status, _, body) = send(
        &fixture.app,
        "GET",
        "/v1/events",
        &[("authorization", &bearer(&secret))],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "revoked: {body}");
    assert!(body.contains("revoked"), "{body}");
}

/// Only `Authorization: Bearer` is a token credential and it replaces the
/// session: a bad token gets 401 beside a valid cookie, session-only routes
/// refuse it, and a `Basic` header from a proxy leaves the session in charge.
#[tokio::test]
async fn bearer_replaces_the_session_and_other_schemes_fall_through() {
    let fixture = fixture(AuthMode::Credentials);
    let cookie = login(
        &fixture.app,
        &fixture.repo,
        "dash-admin",
        OperatorRole::Admin,
    )
    .await;
    let token = fixture
        .repo
        .mint_token_for_test("automation", TokenScope::Operator, None);
    let (revoked, _) = prefixd::auth::token::generate().unwrap();
    fixture
        .repo
        .insert_token(&revoked, "revoked-one", TokenScope::Admin, None);
    prefixd::auth::token::revoke(
        fixture.repo.as_ref(),
        "revoked-one",
        "admin",
        chrono::Utc::now(),
    )
    .await
    .unwrap();
    let unknown = prefixd::auth::token::generate().unwrap().0;
    // Basic plus a valid session uses the session.
    let (status, _, me) = send(
        &fixture.app,
        "GET",
        "/v1/auth/me",
        &[("authorization", "Basic dXNlcjpwYXNz"), ("cookie", &cookie)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&me).unwrap()["username"],
        "dash-admin"
    );
    let (status, _, _) = send(
        &fixture.app,
        "GET",
        "/v1/tokens",
        &[("authorization", "Basic dXNlcjpwYXNz"), ("cookie", &cookie)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the session keeps Admin");
    // A bad Bearer never falls back to the valid session.
    for presented in [
        "Bearer not-a-token",
        &bearer(&unknown),
        &bearer(&revoked),
        "Bearer",
    ] {
        let (status, headers, body) = send(
            &fixture.app,
            "GET",
            "/v1/mitigations",
            &[("authorization", presented), ("cookie", &cookie)],
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{presented}: {body}");
        assert!(
            headers.get("set-cookie").is_none(),
            "the cookie was touched"
        );
    }
    // A valid Bearer acts as the token even beside the Admin session.
    let (status, _, _) = send(
        &fixture.app,
        "GET",
        "/v1/operators",
        &[("authorization", &bearer(&token)), ("cookie", &cookie)],
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "operator scope, not the Admin session"
    );
    // Session-only routes refuse a token, with or without the cookie.
    for headers in [
        vec![("authorization", bearer(&token))],
        vec![
            ("authorization", bearer(&token)),
            ("cookie", cookie.clone()),
        ],
    ] {
        let headers: Vec<_> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
        let (status, _, _) = send(&fixture.app, "GET", "/v1/auth/me", &headers, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    // Two Authorization headers are ambiguous, never a fallback.
    let (status, _, _) = send(
        &fixture.app,
        "GET",
        "/v1/mitigations",
        &[
            ("authorization", "Basic dXNlcjpwYXNz"),
            ("authorization", &bearer(&token)),
            ("cookie", &cookie),
        ],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// A browser keeps a stale session cookie while PostgreSQL is down. A token
/// request strips it before the session layer, so the token authenticates and
/// the cookie is left alone; without the Bearer header the same cookie fails.
#[tokio::test]
async fn bearer_with_a_stale_cookie_authenticates_during_a_session_store_outage() {
    let repo = Arc::new(MockRepository::new());
    let token = repo.mint_token_for_test("automation", TokenScope::Operator, None);
    let state = state(AuthMode::Credentials, "test-pop", repo.clone());
    // Nothing listens on port 1, so every session load fails.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(500))
        .connect_lazy("postgres://prefixd@127.0.0.1:1/prefixd")
        .unwrap();
    let auth_layer =
        prefixd::auth::create_auth_layer(pool, repo, AuthMode::Credentials, false).await;
    let app = prefixd::api::create_router(state, auth_layer);
    let cookie = format!("id={}", tower_sessions::session::Id::default());
    let (status, headers, body) = send(
        &app,
        "GET",
        "/v1/mitigations",
        &[("authorization", &bearer(&token)), ("cookie", &cookie)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        headers.get("set-cookie").is_none(),
        "the stale cookie was cleared"
    );
    // An invalid token is still 401, not a session-store 500.
    let (status, _, _) = send(
        &app,
        "GET",
        "/v1/mitigations",
        &[("authorization", "Bearer not-a-token"), ("cookie", &cookie)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Control: the cookie alone reaches the unreachable store and fails closed.
    let (status, _, _) = send(&app, "GET", "/v1/mitigations", &[("cookie", &cookie)], None).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

/// A storage error during the token lookup is 503, not 401.
#[tokio::test]
async fn a_token_store_outage_is_503_not_401() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .unwrap();
    pool.close().await;
    let mut settings = common::test_settings();
    settings.http.auth.mode = AuthMode::Credentials;
    let state = AppState::new(
        settings,
        common::test_inventory(),
        common::test_playbooks(),
        Arc::new(prefixd::db::Repository::new(pool)),
        Arc::new(MockAnnouncer::new()),
        ".".into(),
    )
    .unwrap();
    let app = prefixd::api::create_test_router(state);
    let (token, _) = prefixd::auth::token::generate().unwrap();
    let (status, _, body) = send(
        &app,
        "GET",
        "/v1/mitigations",
        &[("authorization", &bearer(&token))],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(body.contains("credential store unavailable"), "{body}");
    assert!(!body.contains(&token[8..]));
    // A malformed value never reaches storage, so it is 401 even now.
    let (status, _, _) = send(
        &app,
        "GET",
        "/v1/mitigations",
        &[("authorization", "Bearer not-a-token")],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// `none` mode is anonymous Admin and `mtls` mode is Admin for a verified
/// certificate; neither consults a token. Token management needs a session, so
/// neither mode can mint tokens through the API.
#[tokio::test]
async fn none_and_mtls_modes_ignore_tokens() {
    for mode in [AuthMode::None, AuthMode::Mtls] {
        let fixture = fixture(mode);
        let ingest =
            fixture
                .repo
                .mint_token_for_test("fnm-ingest", TokenScope::Ingest, Some("fastnetmon"));
        for authorization in [
            None,
            Some("Bearer not-a-token".to_string()),
            Some(bearer(&ingest)),
        ] {
            let headers: Vec<_> = authorization
                .iter()
                .map(|value| ("authorization", value.as_str()))
                .collect();
            let (status, _, body) =
                send(&fixture.app, "GET", "/v1/operators", &headers, None).await;
            assert_eq!(status, StatusCode::OK, "{mode:?} {authorization:?}: {body}");
        }
        let (status, _, _) = send(
            &fixture.app,
            "POST",
            "/v1/tokens",
            &[],
            Some(&json!({"name": "x", "scope": "admin"})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{mode:?}");
        assert!(
            fixture
                .repo
                .list_api_tokens(None)
                .await
                .unwrap()
                .iter()
                .all(|token| token.last_used_at.is_none()),
            "{mode:?} must not look tokens up"
        );
    }
}

/// A token bound to POP A works only on POP A's controller; a null-POP token
/// works on both. Both controllers share one repository, as POPs share one
/// database.
#[tokio::test]
async fn pop_bound_tokens_work_only_on_their_pop() {
    let repo = Arc::new(MockRepository::new());
    let mut secrets = Vec::new();
    for (name, pop) in [("pop-a-only", Some("pop-a")), ("any-pop", None)] {
        let (_, secret) = prefixd::auth::token::create(
            repo.as_ref(),
            prefixd::auth::token::NewToken {
                name: name.into(),
                scope: TokenScope::Operator,
                source: None,
                pop: pop.map(Into::into),
                expires_at: None,
            },
            "admin",
            chrono::Utc::now(),
        )
        .await
        .unwrap();
        secrets.push(secret);
    }
    for (pop, pop_a_status) in [("pop-a", StatusCode::OK), ("pop-b", StatusCode::FORBIDDEN)] {
        let app = prefixd::api::create_test_router(state(AuthMode::Credentials, pop, repo.clone()));
        let (status, _, body) = send(
            &app,
            "GET",
            "/v1/mitigations",
            &[("authorization", &bearer(&secrets[0]))],
            None,
        )
        .await;
        assert_eq!(status, pop_a_status, "{pop}: {body}");
        if status == StatusCode::FORBIDDEN {
            assert!(body.contains("bound to POP"), "{body}");
            assert!(body.contains("pop-a"), "{body}");
        }
        let (status, _, _) = send(
            &app,
            "GET",
            "/v1/mitigations",
            &[("authorization", &bearer(&secrets[1]))],
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "null POP on {pop}");
    }
}

/// The active controller stamps `last_used_at`; a standby reads the token but
/// writes nothing. The throttle itself is proven with controlled time in the
/// unit tests.
#[tokio::test]
async fn standby_skips_the_last_used_stamp() {
    for active in [false, true] {
        let repo = Arc::new(MockRepository::new());
        let token = repo.mint_token_for_test("automation", TokenScope::Operator, None);
        let state = state(AuthMode::Credentials, "test-pop", repo.clone())
            .with_fence(Arc::new(prefixd::fence::ControllerFence::new(active)))
            .unwrap();
        let app = prefixd::api::create_test_router(state);
        let (status, _, _) = send(
            &app,
            "GET",
            "/v1/mitigations",
            &[("authorization", &bearer(&token))],
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let stamped = repo.list_api_tokens(None).await.unwrap()[0].last_used_at;
        assert_eq!(stamped.is_some(), active, "active={active}");
    }
}

#[derive(Clone, Default)]
struct Logs(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Logs {
    type Writer = Logs;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// A seeded secret appears in no log line, error body, API or WebSocket
/// payload, or health detail, for successful, wrong-POP, revoked, expired,
/// unknown and malformed token requests. Revoked and expired tokens log their
/// name as a rotation signal.
#[tokio::test]
async fn seeded_token_secrets_never_leave_the_create_response() {
    const CHILD: &str = "PREFIXD_SEEDED_TOKEN_CHILD";
    const DONE: &str = "prefixd-seeded-token-completed";
    if std::env::var_os(CHILD).is_none() {
        // Tracing caches each callsite's interest process-wide, so capture
        // logs in a process that runs only this test.
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            tokio::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "seeded_token_secrets_never_leave_the_create_response",
                    "--test-threads=1",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .stdin(std::process::Stdio::null())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("child exceeded thirty seconds")
        .expect("child output");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stdout}\n{stderr}");
        assert!(
            stdout.lines().any(|line| line == DONE),
            "{stdout}\n{stderr}"
        );
        return;
    }
    let logs = Logs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let fixture = fixture(AuthMode::Credentials);
    let mut feed = fixture.state.ws_broadcast.subscribe();
    let admin = login(&fixture.app, &fixture.repo, "admin", OperatorRole::Admin).await;
    let mut secrets = Vec::new();
    for (name, pop) in [
        ("good", None),
        ("other-pop", Some("elsewhere")),
        ("revoked", None),
    ] {
        let body = json!({"name": name, "scope": "operator", "pop": pop});
        let (status, _, created) = send(
            &fixture.app,
            "POST",
            "/v1/tokens",
            &[("cookie", &admin)],
            Some(&body),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        secrets.push(
            serde_json::from_str::<Value>(&created).unwrap()["token"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    send(
        &fixture.app,
        "POST",
        "/v1/tokens/revoked/revoke",
        &[("cookie", &admin)],
        None,
    )
    .await;
    // An already expired token, stored directly: creation refuses a past expiry.
    let (expired, hash) = prefixd::auth::token::generate().unwrap();
    let now = chrono::Utc::now();
    let record = prefixd::domain::ApiToken {
        token_id: uuid::Uuid::new_v4(),
        name: "expired".into(),
        scope: TokenScope::Operator,
        source: None,
        pop: None,
        created_at: now - chrono::Duration::hours(2),
        created_by: "admin".into(),
        expires_at: Some(now - chrono::Duration::hours(1)),
        last_used_at: None,
        revoked_at: None,
        revoked_by: None,
    };
    let audit = prefixd::observability::AuditEntry::new(
        prefixd::observability::ActorType::Operator,
        Some("admin".into()),
        "api_token.create",
        Some("api_token"),
        Some("expired".into()),
        json!({}),
    );
    fixture
        .repo
        .create_api_token(&record, &hash, &audit)
        .await
        .unwrap();
    secrets.push(expired.clone());
    let unknown = prefixd::auth::token::generate().unwrap().0;
    let malformed = format!("{}!", secrets[0]);
    let mut bodies = Vec::new();
    for (presented, expected) in [
        (secrets[0].as_str(), StatusCode::OK),
        (secrets[1].as_str(), StatusCode::FORBIDDEN),
        (secrets[2].as_str(), StatusCode::UNAUTHORIZED),
        (expired.as_str(), StatusCode::UNAUTHORIZED),
        (unknown.as_str(), StatusCode::UNAUTHORIZED),
        (malformed.as_str(), StatusCode::UNAUTHORIZED),
    ] {
        for path in ["/v1/mitigations", "/v1/health/detail", "/v1/stats"] {
            let (status, _, body) = send(
                &fixture.app,
                "GET",
                path,
                &[("authorization", &bearer(presented))],
                None,
            )
            .await;
            assert_eq!(status, expected, "{path}");
            bodies.push(body);
        }
    }
    for path in ["/v1/tokens", "/v1/audit", "/v1/health/detail"] {
        bodies.push(
            send(&fixture.app, "GET", path, &[("cookie", &admin)], None)
                .await
                .2,
        );
    }
    let mut messages = Vec::new();
    while let Ok(message) = feed.try_recv() {
        messages.push(serde_json::to_string(&message).unwrap());
    }
    drop(_guard);
    let logs = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("revoked API token presented"), "{logs}");
    assert!(logs.contains("token=revoked"), "{logs}");
    assert!(logs.contains("expired API token presented"), "{logs}");
    assert!(logs.contains("token=expired"), "{logs}");
    assert!(logs.contains("API token bound to another POP"), "{logs}");
    for secret in secrets.iter().chain([&unknown, &malformed]) {
        let body = &secret[8..];
        let hash = hex::encode(prefixd::auth::token::hash(secret));
        for (label, text) in [("logs", &logs)]
            .into_iter()
            .chain(bodies.iter().map(|body| ("response", body)))
            .chain(messages.iter().map(|message| ("websocket", message)))
        {
            assert!(!text.contains(body), "{label} leaked a secret: {text}");
            assert!(!text.contains(&hash), "{label} leaked a hash: {text}");
        }
    }
    println!("\n{DONE}");
}

/// Every route that creates or changes a principal or its credentials.
fn identity_routes(target: &str) -> Vec<(&'static str, String, Option<Value>)> {
    vec![
        (
            "POST",
            "/v1/tokens".into(),
            Some(json!({"name": "minted", "scope": "admin"})),
        ),
        ("GET", "/v1/tokens".into(), None),
        ("POST", "/v1/tokens/existing/revoke".into(), None),
        (
            "POST",
            "/v1/operators".into(),
            Some(
                json!({"username": "minted-admin", "password": "minted-password", "role": "admin"}),
            ),
        ),
        (
            "PUT",
            format!("/v1/operators/{target}/password"),
            Some(json!({"new_password": "reset-password"})),
        ),
        ("DELETE", format!("/v1/operators/{target}"), None),
    ]
}

/// Identity management needs a signed-in session. An admin token, an mTLS
/// client and `none` mode each get 403 on every identity route, while the
/// admin token keeps the other Admin routes; an Admin session succeeds on
/// every identity route.
#[tokio::test]
async fn identity_routes_need_a_session() {
    for mode in [AuthMode::Credentials, AuthMode::Mtls, AuthMode::None] {
        let fixture = fixture(mode);
        let target = fixture
            .repo
            .create_operator("target", "x", OperatorRole::Operator, None)
            .await
            .unwrap()
            .operator_id
            .to_string();
        let admin = bearer(
            &fixture
                .repo
                .mint_token_for_test("existing", TokenScope::Admin, None),
        );
        let headers: Vec<(&str, &str)> = if mode == AuthMode::Credentials {
            vec![("authorization", admin.as_str())]
        } else {
            vec![]
        };
        for (method, path, body) in identity_routes(&target) {
            let (status, _, response) =
                send(&fixture.app, method, &path, &headers, body.as_ref()).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{mode:?} {method} {path}: {response}"
            );
        }
        assert_eq!(fixture.repo.list_operators().await.unwrap().len(), 1);
        assert_eq!(fixture.repo.list_api_tokens(None).await.unwrap().len(), 1);
        assert!(
            fixture.repo.list_api_tokens(None).await.unwrap()[0]
                .revoked_at
                .is_none()
        );
        // The same caller keeps every other Admin capability.
        let (status, _, _) = send(&fixture.app, "GET", "/v1/operators", &headers, None).await;
        assert_eq!(status, StatusCode::OK, "{mode:?}");
        let (status, _, body) = send(
            &fixture.app,
            "POST",
            "/v1/safelist",
            &headers,
            Some(&json!({"prefix": "203.0.113.201/32"})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{mode:?}: {body}");
    }

    // Control: an Admin session succeeds on every identity route.
    let fixture = fixture(AuthMode::Credentials);
    let cookie = login(&fixture.app, &fixture.repo, "admin", OperatorRole::Admin).await;
    let target = fixture
        .repo
        .create_operator("target", "x", OperatorRole::Operator, None)
        .await
        .unwrap()
        .operator_id
        .to_string();
    fixture
        .repo
        .mint_token_for_test("existing", TokenScope::Admin, None);
    for (method, path, body) in identity_routes(&target) {
        let (status, _, response) = send(
            &fixture.app,
            method,
            &path,
            &[("cookie", &cookie)],
            body.as_ref(),
        )
        .await;
        assert!(status.is_success(), "{method} {path}: {status} {response}");
    }
    // An Operator session may change only its own password.
    let operator = login(
        &fixture.app,
        &fixture.repo,
        "self-service",
        OperatorRole::Operator,
    )
    .await;
    let own = fixture
        .repo
        .get_operator_by_username("self-service")
        .await
        .unwrap()
        .unwrap()
        .operator_id;
    let admin_id = fixture
        .repo
        .get_operator_by_username("admin")
        .await
        .unwrap()
        .unwrap()
        .operator_id;
    let (status, _, _) = send(
        &fixture.app,
        "PUT",
        &format!("/v1/operators/{admin_id}/password"),
        &[("cookie", &operator)],
        Some(&json!({"new_password": "takeover-password"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Its own password, last: the change ends this session.
    let (status, _, _) = send(
        &fixture.app,
        "PUT",
        &format!("/v1/operators/{own}/password"),
        &[("cookie", &operator)],
        Some(&json!({"current_password": PASSWORD, "new_password": "rotated-password"})),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

async fn sign_in(app: &Router, username: &str, password: &str) -> StatusCode {
    send(
        app,
        "POST",
        "/v1/auth/login",
        &[],
        Some(&json!({"username": username, "password": password})),
    )
    .await
    .0
}

/// The attack the session rule closes: a stolen admin token tries to create an
/// Admin operator, reset an Admin's password and mint a replacement token, so
/// that it could sign in and survive revocation. Each step is refused, and
/// after the token is revoked nothing it attempted persists.
#[tokio::test]
async fn a_stolen_admin_token_cannot_outlive_its_revocation() {
    let fixture = fixture(AuthMode::Credentials);
    let cookie = login(&fixture.app, &fixture.repo, "victim", OperatorRole::Admin).await;
    let victim = fixture
        .repo
        .get_operator_by_username("victim")
        .await
        .unwrap()
        .unwrap()
        .operator_id;
    let (status, _, created) = send(
        &fixture.app,
        "POST",
        "/v1/tokens",
        &[("cookie", &cookie)],
        Some(&json!({"name": "automation", "scope": "admin"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let stolen = bearer(
        serde_json::from_str::<Value>(&created).unwrap()["token"]
            .as_str()
            .unwrap(),
    );
    let auth = [("authorization", stolen.as_str())];

    let (create, _, _) = send(
        &fixture.app,
        "POST",
        "/v1/operators",
        &auth,
        Some(&json!({"username": "backdoor", "password": "backdoor-password", "role": "admin"})),
    )
    .await;
    let (reset, _, _) = send(
        &fixture.app,
        "PUT",
        &format!("/v1/operators/{victim}/password"),
        &auth,
        Some(&json!({"new_password": "takeover-password"})),
    )
    .await;
    let (mint, _, _) = send(
        &fixture.app,
        "POST",
        "/v1/tokens",
        &auth,
        Some(&json!({"name": "replacement", "scope": "admin"})),
    )
    .await;
    assert_eq!(
        [create, reset, mint],
        [StatusCode::FORBIDDEN; 3],
        "create operator, reset password, mint token"
    );

    let (status, _, _) = send(
        &fixture.app,
        "POST",
        "/v1/tokens/automation/revoke",
        &[("cookie", &cookie)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Nothing the token attempted survives it.
    let (status, _, _) = send(&fixture.app, "GET", "/v1/operators", &auth, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the revoked token");
    assert_eq!(
        sign_in(&fixture.app, "backdoor", "backdoor-password").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        sign_in(&fixture.app, "victim", "takeover-password").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        sign_in(&fixture.app, "victim", PASSWORD).await,
        StatusCode::OK
    );
    let operators: Vec<_> = fixture
        .repo
        .list_operators()
        .await
        .unwrap()
        .into_iter()
        .map(|operator| operator.username)
        .collect();
    assert_eq!(operators, ["victim"]);
    let tokens = fixture.repo.list_api_tokens(None).await.unwrap();
    assert_eq!(tokens.len(), 1);
    assert!(tokens[0].revoked_at.is_some());
}
