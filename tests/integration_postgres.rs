use prefixd::bgp::{FlowSpecReader, FlowSpecWriter, PeerObserver};
mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use common::TestContext;
use prefixd::domain::MitigationStatus;

#[tokio::test]
async fn test_cli_operator_list_matches_shipped_schema() {
    async fn list(ctx: &TestContext, format: &str) -> String {
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            tokio::process::Command::new(env!("CARGO_BIN_EXE_prefixdctl"))
                .args(["--format", format, "operators", "list"])
                .env(
                    "DATABASE_URL",
                    &ctx.state.settings.storage.connection_string,
                )
                .env_remove("PREFIXD_API_TOKEN")
                .stdin(std::process::Stdio::null())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("CLI operator list completes within 15 seconds")
        .expect("run CLI operator list");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout).unwrap();
        for excluded in [
            "password_hash",
            "list-hash-null",
            "list-hash-login",
            "created_by",
            "list-private-creator",
        ] {
            assert!(
                !stdout.contains(excluded),
                "CLI exposes private operator data"
            );
        }
        stdout
    }

    let ctx = TestContext::new().await;
    assert_eq!(list(&ctx, "json").await, "[]\n");
    assert_eq!(list(&ctx, "table").await, "No operators found.\n");

    sqlx::query(
        "INSERT INTO operators \
         (operator_id, username, password_hash, role, created_at, created_by, last_login_at) \
         VALUES \
         ('00000000-0000-4000-8000-000000000001', 'list-admin', $1, 'admin', \
          '2026-01-01T01:02:03Z', 'list-private-creator', NULL), \
         ('00000000-0000-4000-8000-000000000002', 'list-viewer', $2, 'viewer', \
          '2026-01-02T04:05:06Z', 'list-private-creator', '2026-01-03T07:08:09Z')",
    )
    .bind("list-hash-null")
    .bind("list-hash-login")
    .execute(&ctx.pool)
    .await
    .unwrap();

    let json: serde_json::Value = serde_json::from_str(&list(&ctx, "json").await).unwrap();
    assert_eq!(
        json,
        serde_json::json!([
            {
                "id": "00000000-0000-4000-8000-000000000001",
                "username": "list-admin",
                "role": "admin",
                "created_at": "2026-01-01T01:02:03Z",
                "last_login": null
            },
            {
                "id": "00000000-0000-4000-8000-000000000002",
                "username": "list-viewer",
                "role": "viewer",
                "created_at": "2026-01-02T04:05:06Z",
                "last_login": "2026-01-03T07:08:09Z"
            }
        ])
    );
    assert_eq!(
        list(&ctx, "table").await,
        format!(
            "{:<36}  {:<20}  {:<8}  {:<20}  LAST LOGIN\n{}\n\
             {:<36}  {:<20}  {:<8}  {:<20}  never\n\
             {:<36}  {:<20}  {:<8}  {:<20}  2026-01-03 07:08:09\n",
            "ID",
            "USERNAME",
            "ROLE",
            "CREATED",
            "-".repeat(110),
            "00000000-0000-4000-8000-000000000001",
            "list-admin",
            "admin",
            "2026-01-01 01:02:03",
            "00000000-0000-4000-8000-000000000002",
            "list-viewer",
            "viewer",
            "2026-01-02 04:05:06"
        )
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn test_cli_operator_password_terminal() {
    use axum_login::AuthnBackend;
    use prefixd::auth::{AuthBackend, Credentials};

    let ctx = TestContext::new().await;
    let output = tokio::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/cli-password.py"
        ))
        .arg(env!("CARGO_BIN_EXE_prefixdctl"))
        .env(
            "DATABASE_URL",
            &ctx.state.settings.storage.connection_string,
        )
        .output()
        .await
        .expect("run CLI terminal regression");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let backend = AuthBackend::new(ctx.repo.clone(), prefixd::config::AuthMode::Credentials);
    for username in ["pty-admin", "pty-explicit"] {
        let operator = backend
            .authenticate(Credentials {
                username: username.to_string(),
                password: "pty-test-password".to_string(),
            })
            .await
            .unwrap()
            .expect("CLI-created operator authenticates through the real backend");
        assert!(operator.password_hash.starts_with("$argon2id$"));
    }
    for username in ["pty-empty", "pty-interrupt", "pty-eof", "pty-no-terminal"] {
        assert!(
            ctx.repo
                .get_operator_by_username(username)
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn test_full_event_to_mitigation_flow() {
    let ctx = TestContext::new().await;
    let app = ctx.router().await;

    // Ingest an event for a known IP
    let event_json = r#"{
        "timestamp": "2026-01-17T10:00:00Z",
        "source": "integration_test",
        "victim_ip": "203.0.113.10",
        "vector": "udp_flood",
        "bps": 500000000,
        "pps": 100000,
        "top_dst_ports": [53, 123],
        "confidence": 0.95
    }"#;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_json))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);

    // Verify mitigation was created in the database
    let mitigations = ctx
        .repo
        .list_mitigations(
            None,
            None,
            None,
            None,
            &prefixd::db::MitigationListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .expect("Failed to list mitigations");

    assert_eq!(mitigations.len(), 1);
    assert_eq!(mitigations[0].victim_ip, "203.0.113.10");
    assert_eq!(mitigations[0].status, MitigationStatus::Active);
}

#[tokio::test]
async fn test_mitigation_withdrawal() {
    let ctx = TestContext::new().await;
    let app = ctx.router().await;

    // First, create a mitigation via event
    let event_json = r#"{
        "timestamp": "2026-01-17T10:00:00Z",
        "source": "integration_test",
        "victim_ip": "203.0.113.10",
        "vector": "syn_flood",
        "bps": 100000000,
        "pps": 50000,
        "confidence": 0.9
    }"#;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_json))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);

    // Get the mitigation ID from the database
    let mitigations = ctx
        .repo
        .list_mitigations(
            None,
            None,
            None,
            None,
            &prefixd::db::MitigationListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .expect("Failed to list mitigations");

    assert_eq!(mitigations.len(), 1);
    let mitigation_id = mitigations[0].mitigation_id;

    // Withdraw the mitigation
    let withdraw_json = r#"{
        "operator_id": "test_operator",
        "reason": "Integration test withdrawal"
    }"#;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/mitigations/{}/withdraw", mitigation_id))
                .header("content-type", "application/json")
                .body(Body::from(withdraw_json))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify mitigation status changed
    let mitigation = ctx
        .repo
        .get_mitigation(mitigation_id)
        .await
        .expect("Failed to get mitigation")
        .expect("Mitigation not found");

    assert_eq!(mitigation.status, MitigationStatus::Withdrawn);
}

#[tokio::test]
async fn test_authenticated_withdrawal_audit_success_and_failure_boundaries() {
    use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
    use prefixd::{
        AppState,
        auth::create_auth_layer,
        bgp::{FlowSpecAnnouncer, MockAnnouncer},
        config::{AuthMode, OperationMode},
        domain::{
            ActionParams, ActionType, AttackVector, FlowSpecRule, MatchCriteria, Mitigation,
            MitigationIntent, OperatorRole, mitigation_rule,
        },
        error::{PrefixdError, Result},
    };
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
    };

    struct Speaker {
        inner: MockAnnouncer,
        failing_hash: String,
        fail: AtomicBool,
        deletes: AtomicUsize,
    }
    impl FlowSpecAnnouncer for Speaker {
        fn backend(&self) -> &'static str {
            "mock"
        }
    }
    #[async_trait::async_trait]
    impl FlowSpecWriter for Speaker {
        async fn announce(&self, rule: &FlowSpecRule) -> Result<()> {
            self.inner.announce(rule).await
        }

        async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()> {
            self.deletes.fetch_add(1, SeqCst);
            self.inner.withdraw(rule).await?;
            if rule.nlri_hash() == self.failing_hash && self.fail.load(SeqCst) {
                return Err(PrefixdError::BgpWithdrawalFailed(
                    "reply lost after delete".into(),
                ));
            }
            Ok(())
        }
    }

    async fn post(
        app: &axum::Router,
        cookie: &str,
        path: &str,
        payload: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("cookie", cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json = if body.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&body).unwrap()
        };
        (status, json)
    }

    async fn audits(app: &axum::Router, cookie: &str) -> Vec<serde_json::Value> {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/audit")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["has_more"], false);
        let entries = json["entries"].as_array().unwrap();
        assert_eq!(json["count"], entries.len());
        entries
            .iter()
            .filter(|entry| entry["action"] == "withdraw")
            .cloned()
            .collect()
    }

    let context = TestContext::new().await;
    let started_at = chrono::Utc::now();
    let salt = SaltString::encode_b64(b"postgres-audit-test").unwrap();
    let hash = Argon2::default()
        .hash_password(b"audit-test-password", &salt)
        .unwrap()
        .to_string();
    context
        .repo
        .create_operator("postgres-auditor", &hash, OperatorRole::Operator, None)
        .await
        .unwrap();
    let mut targets = Vec::new();
    for suffix in 10..16 {
        let mut mitigation = Mitigation::from_intent(
            MitigationIntent {
                event_id: uuid::Uuid::new_v4(),
                customer_id: None,
                service_id: None,
                pop: "test-pop".into(),
                match_criteria: MatchCriteria {
                    dst_prefix: format!("203.0.113.{suffix}/32"),
                    protocol: Some(17),
                    dst_ports: vec![53],
                },
                action_type: ActionType::Discard,
                action_params: ActionParams { rate_bps: None },
                ttl_seconds: 600,
                reason: "audit fixture".into(),
            },
            format!("203.0.113.{suffix}"),
            AttackVector::UdpFlood,
        );
        mitigation.activate();
        context.repo.insert_mitigation(&mitigation).await.unwrap();
        targets.push(mitigation);
    }
    let speaker = Arc::new(Speaker {
        inner: MockAnnouncer::new(),
        failing_hash: mitigation_rule(&targets[3]).nlri_hash(),
        fail: AtomicBool::new(true),
        deletes: AtomicUsize::new(0),
    });
    for mitigation in &targets {
        speaker
            .announce(&mitigation_rule(mitigation))
            .await
            .unwrap();
    }
    let mut settings = context.state.settings.clone();
    settings.mode = OperationMode::Enforced;
    settings.http.auth.mode = AuthMode::Credentials;
    let state = AppState::new(
        settings,
        common::test_inventory(),
        common::test_playbooks(),
        context.repo.clone(),
        speaker.clone(),
        ".".into(),
    )
    .unwrap();
    let auth = create_auth_layer(
        context.pool.clone(),
        context.repo.clone(),
        state.settings.http.auth.mode,
        false,
    )
    .await;
    let app = prefixd::api::create_router(state.clone(), auth);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/audit")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"username":"postgres-auditor","password":"audit-test-password"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response
        .headers()
        .get(axum::http::header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    assert!(audits(&app, &cookie).await.is_empty());
    let single_path =
        |index: usize| format!("/v1/mitigations/{}/withdraw", targets[index].mitigation_id);
    let payload = |reason: &str| serde_json::json!({"operator_id":"forged-admin", "reason":reason});
    let (status, _) = post(&app, &cookie, &single_path(0), payload("single reason")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(audits(&app, &cookie).await.len(), 1);
    let (status, result) = post(
        &app,
        &cookie,
        "/v1/mitigations/withdraw",
        serde_json::json!({
            "mitigation_ids":[targets[1].mitigation_id, targets[2].mitigation_id],
            "operator_id":"forged-admin", "reason":"bulk reason"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result["withdrawn"], 2);
    assert_eq!(result["failed"], 0);
    assert_eq!(audits(&app, &cookie).await.len(), 3);

    // The first deletion loses its reply; the independent second target must still complete.
    let (status, result) = post(
        &app,
        &cookie,
        "/v1/mitigations/withdraw",
        serde_json::json!({
            "mitigation_ids":[targets[3].mitigation_id, targets[4].mitigation_id],
            "operator_id":"forged-admin", "reason":"mixed batch"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result["withdrawn"], 1);
    assert_eq!(result["failed"], 1);
    assert_eq!(result["results"][0]["status"], "error");
    assert_eq!(result["results"][1]["status"], "withdrawn");
    let completed = audits(&app, &cookie).await;
    assert_eq!(completed.len(), 4);
    assert!(
        completed
            .iter()
            .all(|entry| entry["target_id"] != targets[3].mitigation_id.to_string())
    );
    let pending = context.repo.pending_withdrawals(None).await.unwrap();
    assert_eq!(pending.len(), 1);
    let ambiguous = &pending[0];
    assert_eq!(ambiguous.mitigation_id, targets[3].mitigation_id);
    assert_eq!(ambiguous.actor, "postgres-auditor");
    assert_eq!(ambiguous.reason, "postgres-auditor: mixed batch");
    assert_eq!(
        context
            .repo
            .get_mitigation(targets[3].mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        MitigationStatus::Active
    );
    speaker.fail.store(false, SeqCst);
    let (status, _) = post(
        &app,
        &cookie,
        &single_path(3),
        payload("replacement reason"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(audits(&app, &cookie).await.len(), 5);

    // Fail the audit INSERT after the terminal UPDATE, exercising the transaction rollback.
    sqlx::raw_sql("CREATE FUNCTION reject_withdrawal_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action = 'withdraw' THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_withdrawal_audit();")
        .execute(&context.pool).await.unwrap();
    let deletes_before = speaker.deletes.load(SeqCst);
    let mut updates = state.ws_broadcast.subscribe();
    let (status, _) = post(&app, &cookie, &single_path(5), payload("database failure")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(speaker.deletes.load(SeqCst), deletes_before + 1);
    assert_eq!(speaker.inner.announced_count().await, 0);
    assert!(updates.try_recv().is_err());
    assert_eq!(audits(&app, &cookie).await.len(), 5);
    assert_eq!(
        context
            .repo
            .get_mitigation(targets[5].mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        MitigationStatus::Active
    );
    let pending = context.repo.pending_withdrawals(None).await.unwrap();
    assert_eq!(pending.len(), 1);
    let failed_audit = &pending[0];
    assert_eq!(failed_audit.mitigation_id, targets[5].mitigation_id);
    assert_eq!(failed_audit.actor, "postgres-auditor");
    assert_eq!(failed_audit.reason, "postgres-auditor: database failure");
    assert!(failed_audit.completed_at.is_none());
    sqlx::query("DROP TRIGGER reject_audit ON audit_log")
        .execute(&context.pool)
        .await
        .unwrap();
    let (status, _) = post(
        &app,
        &cookie,
        &single_path(5),
        payload("replacement reason"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let completed = audits(&app, &cookie).await;
    assert_eq!(completed.len(), 6);
    assert!(
        context
            .repo
            .pending_withdrawals(None)
            .await
            .unwrap()
            .is_empty()
    );
    for (target, reason) in targets.iter().zip([
        "single reason",
        "bulk reason",
        "bulk reason",
        "mixed batch",
        "mixed batch",
        "database failure",
    ]) {
        let entries: Vec<_> = completed
            .iter()
            .filter(|entry| entry["target_id"] == target.mitigation_id.to_string())
            .collect();
        assert_eq!(entries.len(), 1);
        let entry = entries[0];
        assert_eq!(entry["actor_type"], "operator");
        assert_eq!(entry["actor_id"], "postgres-auditor");
        assert_eq!(entry["target_type"], "mitigation");
        assert_eq!(
            entry["details"]["reason"],
            format!("postgres-auditor: {reason}")
        );
        let timestamp =
            chrono::DateTime::parse_from_rfc3339(entry["timestamp"].as_str().unwrap()).unwrap();
        assert!(timestamp >= started_at && timestamp <= chrono::Utc::now());
        let (operation_id,): (uuid::Uuid,) = sqlx::query_as("SELECT operation_id FROM withdrawal_requests WHERE mitigation_id = $1 AND completed_at IS NOT NULL")
            .bind(target.mitigation_id).fetch_one(&context.pool).await.unwrap();
        assert_eq!(entry["details"]["operation_id"], operation_id.to_string());
        assert_eq!(
            context
                .repo
                .get_mitigation(target.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            MitigationStatus::Withdrawn
        );
    }
    for request in [ambiguous, failed_audit] {
        let entry = completed
            .iter()
            .find(|entry| entry["target_id"] == request.mitigation_id.to_string())
            .unwrap();
        assert_eq!(
            entry["details"]["operation_id"],
            request.operation_id.to_string()
        );
    }
    assert_eq!(speaker.inner.announced_count().await, 0);
    let deletes = speaker.deletes.load(SeqCst);
    for index in [3, 5] {
        let (status, _) = post(&app, &cookie, &single_path(index), payload("repeat")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    assert_eq!(speaker.deletes.load(SeqCst), deletes);
    assert_eq!(audits(&app, &cookie).await, completed);
}

#[tokio::test]
async fn test_pagination() {
    let ctx = TestContext::new().await;
    let app = ctx.router().await;

    // Create multiple mitigations by sending events for different IPs
    for i in 10..20 {
        let event_json = format!(
            r#"{{
                "timestamp": "2026-01-17T10:00:00Z",
                "source": "integration_test",
                "victim_ip": "203.0.113.{}",
                "vector": "udp_flood",
                "bps": 100000000,
                "pps": 50000,
                "top_dst_ports": [53],
                "confidence": 0.9
            }}"#,
            i
        );

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/events")
                    .header("content-type", "application/json")
                    .body(Body::from(event_json))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    // Test pagination - get first page
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations?limit=5&offset=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["count"], 5);

    // Test pagination - get second page
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations?limit=5&offset=5")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["count"], 5);
}

#[tokio::test]
async fn test_safelist_blocks_mitigation() {
    let ctx = TestContext::new().await;
    let app = ctx.router().await;

    // Add an IP to safelist
    ctx.repo
        .insert_safelist("203.0.113.10/32", "test", Some("Integration test"))
        .await
        .expect("Failed to add safelist entry");

    // Try to create mitigation for safelisted IP
    let event_json = r#"{
        "timestamp": "2026-01-17T10:00:00Z",
        "source": "integration_test",
        "victim_ip": "203.0.113.10",
        "vector": "udp_flood",
        "bps": 500000000,
        "pps": 100000,
        "confidence": 0.95
    }"#;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_json))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be rejected due to safelist (422 Unprocessable Entity for guardrail violations)
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Verify no mitigation was created
    let mitigations = ctx
        .repo
        .list_mitigations(
            None,
            None,
            None,
            None,
            &prefixd::db::MitigationListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .expect("Failed to list mitigations");

    assert_eq!(mitigations.len(), 0);
}

#[tokio::test]
async fn test_duplicate_event_extends_ttl() {
    let ctx = TestContext::new().await;
    let app = ctx.router().await;

    let event_json = r#"{
        "timestamp": "2026-01-17T10:00:00Z",
        "source": "integration_test",
        "victim_ip": "203.0.113.10",
        "vector": "udp_flood",
        "bps": 500000000,
        "pps": 100000,
        "top_dst_ports": [53],
        "confidence": 0.95
    }"#;

    // First event creates mitigation
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_json))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let first_mitigation_id = json["mitigation_id"].as_str().unwrap();

    // Get original expiry time
    let mitigations = ctx
        .repo
        .list_mitigations(
            None,
            None,
            None,
            None,
            &prefixd::db::MitigationListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .expect("Failed to list mitigations");
    let original_expires_at = mitigations[0].expires_at;

    // Small delay to ensure time difference
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Second event should extend TTL
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_json))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Same mitigation should be returned
    assert_eq!(json["mitigation_id"].as_str().unwrap(), first_mitigation_id);
    assert_eq!(json["status"], "extended");

    // Verify TTL was extended
    let mitigations = ctx
        .repo
        .list_mitigations(
            None,
            None,
            None,
            None,
            &prefixd::db::MitigationListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .expect("Failed to list mitigations");

    assert_eq!(mitigations.len(), 1);
    assert!(mitigations[0].expires_at > original_expires_at);
}

#[tokio::test]
async fn test_migration_applies_cleanly() {
    // This test verifies that migrations apply cleanly to a fresh database
    // The TestContext::new() already runs migrations, so if we get here without panic, it worked
    let _ctx = TestContext::new().await;

    // Additional verification: ensure all expected tables exist
    // (implicit - we can query mitigations, safelist, etc.)
}

#[tokio::test]
async fn test_timeseries_non_hour_bucket_alignment() {
    use chrono::{Duration, Timelike, Utc};
    use prefixd::domain::{
        ActionParams, ActionType, AttackEvent, AttackVector, MatchCriteria, Mitigation,
        MitigationStatus,
    };
    use uuid::Uuid;

    let ctx = TestContext::new().await;

    let now = Utc::now();
    let base = (now - Duration::minutes(30))
        .with_minute(17)
        .and_then(|dt| dt.with_second(0))
        .and_then(|dt| dt.with_nanosecond(0))
        .unwrap_or(now - Duration::minutes(30));

    let event_one = AttackEvent {
        event_id: Uuid::new_v4(),
        external_event_id: Some("evt-timeseries-1".to_string()),
        source: "integration_test".to_string(),
        event_timestamp: base,
        ingested_at: base,
        victim_ip: "203.0.113.200".to_string(),
        vector: "udp_flood".to_string(),
        protocol: Some(17),
        bps: Some(100_000_000),
        pps: Some(50_000),
        top_dst_ports_json: "[53]".to_string(),
        confidence: Some(0.9),
        action: "ban".to_string(),
        raw_details: None,
    };

    let event_two = AttackEvent {
        event_id: Uuid::new_v4(),
        external_event_id: Some("evt-timeseries-2".to_string()),
        source: "integration_test".to_string(),
        event_timestamp: base + Duration::minutes(6),
        ingested_at: base + Duration::minutes(6),
        victim_ip: "203.0.113.200".to_string(),
        vector: "udp_flood".to_string(),
        protocol: Some(17),
        bps: Some(120_000_000),
        pps: Some(60_000),
        top_dst_ports_json: "[53]".to_string(),
        confidence: Some(0.92),
        action: "ban".to_string(),
        raw_details: None,
    };

    ctx.repo
        .insert_event(&event_one)
        .await
        .expect("failed to insert first event");
    ctx.repo
        .insert_event(&event_two)
        .await
        .expect("failed to insert second event");

    let match_criteria = MatchCriteria {
        dst_prefix: "203.0.113.200/32".to_string(),
        protocol: Some(17),
        dst_ports: vec![53],
    };

    let mitigation = Mitigation {
        mitigation_id: Uuid::new_v4(),
        scope_hash: match_criteria.compute_scope_hash(),
        pop: "test-pop".to_string(),
        customer_id: Some("cust_integration".to_string()),
        service_id: Some("svc_web".to_string()),
        victim_ip: "203.0.113.200".to_string(),
        vector: AttackVector::UdpFlood,
        match_criteria,
        action_type: ActionType::Police,
        action_params: ActionParams {
            rate_bps: Some(10_000_000),
        },
        status: MitigationStatus::Active,
        created_at: base + Duration::minutes(4),
        updated_at: base + Duration::minutes(4),
        expires_at: base + Duration::minutes(64),
        withdrawn_at: None,
        triggering_event_id: event_one.event_id,
        last_event_id: event_two.event_id,
        escalated_from_id: None,
        reason: "timeseries alignment test".to_string(),
        rejection_reason: None,
        acknowledged_at: None,
        acknowledged_by: None,
        signal_group_id: None,
        origin_mode: None,
    };

    ctx.repo
        .insert_mitigation(&mitigation)
        .await
        .expect("failed to insert mitigation");

    let event_buckets = ctx
        .repo
        .timeseries_events(2, 5)
        .await
        .expect("failed to query event timeseries");
    let mitigation_buckets = ctx
        .repo
        .timeseries_mitigations(2, 5)
        .await
        .expect("failed to query mitigation timeseries");

    let event_total: i64 = event_buckets.iter().map(|b| b.count).sum();
    let mitigation_total: i64 = mitigation_buckets.iter().map(|b| b.count).sum();
    assert_eq!(event_total, 2);
    assert_eq!(mitigation_total, 1);

    assert!(
        event_buckets
            .iter()
            .any(|b| b.count > 0 && b.bucket.minute() != 0),
        "expected event counts in non-hour buckets"
    );
    assert!(
        mitigation_buckets
            .iter()
            .any(|b| b.count > 0 && b.bucket.minute() != 0),
        "expected mitigation counts in non-hour buckets"
    );
}

#[tokio::test]
async fn test_ttl_expiry() {
    use chrono::{Duration, Utc};
    use prefixd::bgp::MockAnnouncer;
    use prefixd::domain::{
        ActionParams, ActionType, AttackVector, FlowSpecAction, FlowSpecNlri, FlowSpecRule,
        MatchCriteria, Mitigation, MitigationStatus,
    };
    use prefixd::scheduler::ReconciliationLoop;
    use std::sync::Arc;
    use uuid::Uuid;

    let ctx = TestContext::new().await;

    // Create a shared MockAnnouncer so we can check withdrawals
    let announcer = Arc::new(MockAnnouncer::new());

    // Pre-announce a rule so we can verify it gets withdrawn
    let rule = FlowSpecRule::new(
        FlowSpecNlri {
            dst_prefix: "203.0.113.99/32".to_string(),
            protocol: Some(17),
            dst_ports: vec![53],
        },
        FlowSpecAction::police(10_000_000),
    );
    announcer.announce(&rule).await.expect("Failed to announce");
    assert_eq!(
        announcer.announced_count().await,
        1,
        "Should have 1 announced rule"
    );

    // Create a mitigation with expires_at in the past (already expired)
    let now = Utc::now();
    let expired_at = now - Duration::seconds(60); // 1 minute ago

    let mitigation = Mitigation {
        mitigation_id: Uuid::new_v4(),
        scope_hash: "test_expiry_hash".to_string(),
        pop: "test-pop".to_string(),
        customer_id: Some("cust_test".to_string()),
        service_id: None,
        victim_ip: "203.0.113.99".to_string(),
        vector: AttackVector::UdpFlood,
        match_criteria: MatchCriteria {
            dst_prefix: "203.0.113.99/32".to_string(),
            protocol: Some(17),
            dst_ports: vec![53],
        },
        action_type: ActionType::Police,
        action_params: ActionParams {
            rate_bps: Some(10_000_000),
        },
        status: MitigationStatus::Active, // Active but expired
        created_at: now - Duration::seconds(120),
        updated_at: now - Duration::seconds(60),
        expires_at: expired_at, // Already expired
        withdrawn_at: None,
        triggering_event_id: Uuid::new_v4(),
        last_event_id: Uuid::new_v4(),
        escalated_from_id: None,
        reason: "TTL expiry test".to_string(),
        rejection_reason: None,
        acknowledged_at: None,
        acknowledged_by: None,
        signal_group_id: None,
        origin_mode: None,
    };

    // Insert the expired mitigation
    ctx.repo
        .insert_mitigation(&mitigation)
        .await
        .expect("Failed to insert mitigation");

    // Create reconciliation loop and run it (dry_run=false to test withdrawals)
    let reconciler = ReconciliationLoop::new(
        ctx.repo.clone(),
        announcer.clone(),
        30,    // interval doesn't matter, we call reconcile() directly
        false, // NOT dry-run, so withdrawals happen
    );

    // Run reconciliation
    reconciler.reconcile().await.expect("Reconciliation failed");

    // Verify status changed
    let updated = ctx
        .repo
        .get_mitigation(mitigation.mitigation_id)
        .await
        .expect("Failed to get mitigation")
        .expect("Mitigation should exist");

    assert_eq!(updated.status, MitigationStatus::Expired);
    assert!(updated.withdrawn_at.is_some());

    // Verify BGP withdrawal happened
    assert_eq!(
        announcer.announced_count().await,
        0,
        "Rule should be withdrawn from announcer"
    );

    // Verify it no longer shows in find_expired (since it's now Expired, not Active)
    let expired_after = ctx
        .repo
        .find_expired_mitigations()
        .await
        .expect("Failed to find expired mitigations");

    assert_eq!(
        expired_after.len(),
        0,
        "Should find 0 expired mitigations after expiry"
    );
}

#[tokio::test]
async fn test_config_hot_reload() {
    use common::write_yaml;

    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");

    // Write initial inventory with 1 customer
    let initial_inventory = r#"
customers:
  - customer_id: cust_initial
    name: Initial Customer
    prefixes:
      - 10.0.0.0/24
    policy_profile: normal
    services: []
"#;
    write_yaml(temp_dir.path(), "inventory.yaml", initial_inventory);

    // Write initial playbooks with 1 playbook
    let initial_playbooks = r#"
playbooks:
  - name: udp_flood
    match:
      vector: udp_flood
      require_top_ports: false
    steps:
      - action: police
        rate_bps: 10000000
        ttl_seconds: 60
"#;
    write_yaml(temp_dir.path(), "playbooks.yaml", initial_playbooks);

    // Create context with our config dir
    let ctx = TestContext::with_config_dir(temp_dir.path()).await;

    // Verify initial state
    {
        let inv = ctx.state.inventory.read().await;
        assert_eq!(inv.customers.len(), 1);
        assert_eq!(inv.customers[0].customer_id, "cust_initial");
    }
    {
        let pb = ctx.state.playbooks.read().await;
        assert_eq!(pb.playbooks.len(), 1);
        assert_eq!(pb.playbooks[0].name, "udp_flood");
    }

    // Update inventory with 2 customers
    let updated_inventory = r#"
customers:
  - customer_id: cust_initial
    name: Initial Customer
    prefixes:
      - 10.0.0.0/24
    policy_profile: normal
    services: []
  - customer_id: cust_added
    name: Added Customer
    prefixes:
      - 10.1.0.0/24
    policy_profile: strict
    services: []
"#;
    write_yaml(temp_dir.path(), "inventory.yaml", updated_inventory);

    // Update playbooks with 2 playbooks
    let updated_playbooks = r#"
playbooks:
  - name: udp_flood
    match:
      vector: udp_flood
      require_top_ports: false
    steps:
      - action: police
        rate_bps: 10000000
        ttl_seconds: 60
  - name: syn_flood
    match:
      vector: syn_flood
      require_top_ports: false
    steps:
      - action: discard
        ttl_seconds: 120
"#;
    write_yaml(temp_dir.path(), "playbooks.yaml", updated_playbooks);

    // Call reload endpoint
    let app = ctx.router().await;
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/config/reload")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Parse response to verify what was reloaded
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let reload_resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let reloaded = reload_resp["reloaded"].as_array().unwrap();
    assert!(reloaded.iter().any(|v| v == "inventory"));
    assert!(reloaded.iter().any(|v| v == "playbooks"));

    // Verify new config is loaded
    {
        let inv = ctx.state.inventory.read().await;
        assert_eq!(
            inv.customers.len(),
            2,
            "Should have 2 customers after reload"
        );
        assert!(inv.customers.iter().any(|c| c.customer_id == "cust_added"));
    }
    {
        let pb = ctx.state.playbooks.read().await;
        assert_eq!(
            pb.playbooks.len(),
            2,
            "Should have 2 playbooks after reload"
        );
        assert!(pb.playbooks.iter().any(|p| p.name == "syn_flood"));
    }
}

// =============================================================================
// Signal Group Tests (Postgres-backed)
// =============================================================================

#[tokio::test]
async fn test_signal_group_insert_and_find() {
    use prefixd::correlation::engine::{CorrelationEngine, SignalGroupStatus};

    let ctx = TestContext::new().await;

    // Create a signal group
    let group = CorrelationEngine::create_group("203.0.113.10", "udp_flood", 300);
    let inserted = ctx
        .repo
        .insert_signal_group(&group)
        .await
        .expect("Failed to insert signal group");

    assert_eq!(inserted.group_id, group.group_id);
    assert_eq!(inserted.victim_ip, "203.0.113.10");
    assert_eq!(inserted.vector, "udp_flood");
    assert_eq!(inserted.status, SignalGroupStatus::Open);

    // Find the open group
    let found = ctx
        .repo
        .find_open_group("203.0.113.10", "udp_flood")
        .await
        .expect("Failed to find open group");
    assert!(found.is_some());
    assert_eq!(found.unwrap().group_id, group.group_id);

    // Different vector should not find anything
    let not_found = ctx
        .repo
        .find_open_group("203.0.113.10", "syn_flood")
        .await
        .expect("Failed to find open group");
    assert!(not_found.is_none());
}

#[tokio::test]
async fn test_signal_group_concurrent_insert_returns_existing() {
    use prefixd::correlation::engine::CorrelationEngine;

    let ctx = TestContext::new().await;

    // Create two groups for the same (victim_ip, vector)
    let group1 = CorrelationEngine::create_group("203.0.113.10", "udp_flood", 300);
    let group2 = CorrelationEngine::create_group("203.0.113.10", "udp_flood", 300);

    let inserted1 = ctx
        .repo
        .insert_signal_group(&group1)
        .await
        .expect("Failed to insert group 1");

    let inserted2 = ctx
        .repo
        .insert_signal_group(&group2)
        .await
        .expect("Failed to insert group 2");

    // Both should return the same group ID (the first one)
    assert_eq!(inserted1.group_id, inserted2.group_id);

    // Count should be 1
    let count = ctx
        .repo
        .count_open_groups()
        .await
        .expect("Failed to count open groups");
    assert_eq!(count, 1);
}

#[tokio::test]
async fn test_signal_group_truly_concurrent_insert_no_500() {
    use prefixd::correlation::engine::CorrelationEngine;

    let ctx = TestContext::new().await;
    let repo = ctx.repo.clone();

    // Spawn multiple concurrent inserts for the same (victim_ip, vector).
    // This tests the retry-on-conflict logic when the unique index
    // (idx_signal_groups_open_unique) causes a unique violation under true
    // concurrency. All inserts should succeed (return the same group), not 500.
    let mut handles = Vec::new();
    for _ in 0..10 {
        let repo = repo.clone();
        handles.push(tokio::spawn(async move {
            let group = CorrelationEngine::create_group("203.0.113.99", "udp_flood", 300);
            repo.insert_signal_group(&group).await
        }));
    }

    let mut group_ids = Vec::new();
    for handle in handles {
        let result = handle.await.expect("task panicked");
        let group = result.expect("insert_signal_group should not fail (no 500)");
        group_ids.push(group.group_id);
    }

    // All should return the same group ID
    let first = group_ids[0];
    for gid in &group_ids {
        assert_eq!(
            *gid, first,
            "all concurrent inserts should return the same group"
        );
    }

    // Only one open group should exist
    let count = ctx
        .repo
        .count_open_groups()
        .await
        .expect("Failed to count open groups");
    assert_eq!(count, 1, "exactly one open group should exist");
}

#[tokio::test]
async fn test_signal_group_add_events_and_list() {
    use prefixd::correlation::engine::CorrelationEngine;
    use prefixd::domain::AttackEvent;

    let ctx = TestContext::new().await;

    // Create events first
    let event1 = AttackEvent {
        event_id: uuid::Uuid::new_v4(),
        external_event_id: None,
        source: "fastnetmon".to_string(),
        event_timestamp: chrono::Utc::now(),
        ingested_at: chrono::Utc::now(),
        victim_ip: "203.0.113.10".to_string(),
        vector: "udp_flood".to_string(),
        protocol: Some(17),
        bps: Some(500_000_000),
        pps: Some(100_000),
        top_dst_ports_json: "[53]".to_string(),
        confidence: Some(0.9),
        action: "ban".to_string(),
        raw_details: None,
    };
    let event2 = AttackEvent {
        event_id: uuid::Uuid::new_v4(),
        external_event_id: None,
        source: "alertmanager".to_string(),
        event_timestamp: chrono::Utc::now(),
        ingested_at: chrono::Utc::now(),
        victim_ip: "203.0.113.10".to_string(),
        vector: "udp_flood".to_string(),
        protocol: Some(17),
        bps: None,
        pps: None,
        top_dst_ports_json: "[]".to_string(),
        confidence: Some(0.7),
        action: "ban".to_string(),
        raw_details: None,
    };

    ctx.repo.insert_event(&event1).await.unwrap();
    ctx.repo.insert_event(&event2).await.unwrap();

    // Create signal group
    let group = CorrelationEngine::create_group("203.0.113.10", "udp_flood", 300);
    let group = ctx.repo.insert_signal_group(&group).await.unwrap();

    // Add events to group
    let added1 = ctx
        .repo
        .add_event_to_group(group.group_id, event1.event_id, 1.0)
        .await
        .unwrap();
    assert!(added1);

    let added2 = ctx
        .repo
        .add_event_to_group(group.group_id, event2.event_id, 0.8)
        .await
        .unwrap();
    assert!(added2);

    // Duplicate add should return false
    let dup = ctx
        .repo
        .add_event_to_group(group.group_id, event1.event_id, 1.0)
        .await
        .unwrap();
    assert!(!dup);

    // List events in group
    let events = ctx
        .repo
        .list_signal_group_events(group.group_id)
        .await
        .unwrap();
    assert_eq!(events.len(), 2);
    // Verify denormalized fields
    assert!(
        events
            .iter()
            .any(|e| e.source.as_deref() == Some("fastnetmon"))
    );
    assert!(
        events
            .iter()
            .any(|e| e.source.as_deref() == Some("alertmanager"))
    );
}

#[tokio::test]
async fn test_signal_group_update_and_get() {
    use prefixd::correlation::engine::{CorrelationEngine, SignalGroupStatus};

    let ctx = TestContext::new().await;

    let group = CorrelationEngine::create_group("203.0.113.10", "udp_flood", 300);
    let group = ctx.repo.insert_signal_group(&group).await.unwrap();

    // Update the group
    let mut updated = group.clone();
    updated.derived_confidence = 0.85;
    updated.source_count = 3;
    updated.corroboration_met = true;
    updated.status = SignalGroupStatus::Resolved;

    ctx.repo.update_signal_group(&updated).await.unwrap();

    // Verify via get
    let fetched = ctx
        .repo
        .get_signal_group(group.group_id)
        .await
        .unwrap()
        .expect("Group should exist");

    assert!((fetched.derived_confidence - 0.85).abs() < 0.001);
    assert_eq!(fetched.source_count, 3);
    assert!(fetched.corroboration_met);
    assert_eq!(fetched.status, SignalGroupStatus::Resolved);
}

#[tokio::test]
async fn test_signal_group_list_with_filters() {
    use prefixd::correlation::engine::{CorrelationEngine, SignalGroupFilter, SignalGroupStatus};
    use prefixd::db::ListParams;

    let ctx = TestContext::new().await;

    // Create groups with different vectors
    let g1 = CorrelationEngine::create_group("203.0.113.10", "udp_flood", 300);
    ctx.repo.insert_signal_group(&g1).await.unwrap();

    let g2 = CorrelationEngine::create_group("203.0.113.10", "syn_flood", 300);
    ctx.repo.insert_signal_group(&g2).await.unwrap();

    let g3 = CorrelationEngine::create_group("203.0.113.11", "udp_flood", 300);
    ctx.repo.insert_signal_group(&g3).await.unwrap();

    // List all open groups
    let all = ctx
        .repo
        .list_signal_groups(
            &SignalGroupFilter {
                status: Some(SignalGroupStatus::Open),
                ..Default::default()
            },
            &ListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(all.len(), 3);

    // Filter by vector
    let udp = ctx
        .repo
        .list_signal_groups(
            &SignalGroupFilter {
                vector: Some("udp_flood".to_string()),
                ..Default::default()
            },
            &ListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(udp.len(), 2);

    // Pagination: limit 2
    let page1 = ctx
        .repo
        .list_signal_groups(
            &SignalGroupFilter::default(),
            &ListParams {
                limit: 2,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(page1.len(), 2);

    // Count
    let count = ctx.repo.count_open_groups().await.unwrap();
    assert_eq!(count, 3);
}

#[tokio::test]
async fn test_signal_group_different_vectors_separate() {
    use prefixd::correlation::engine::CorrelationEngine;

    let ctx = TestContext::new().await;

    // Same IP, different vectors → separate groups
    let g1 = CorrelationEngine::create_group("203.0.113.10", "udp_flood", 300);
    let g2 = CorrelationEngine::create_group("203.0.113.10", "syn_flood", 300);

    let inserted1 = ctx.repo.insert_signal_group(&g1).await.unwrap();
    let inserted2 = ctx.repo.insert_signal_group(&g2).await.unwrap();

    // Should be different groups
    assert_ne!(inserted1.group_id, inserted2.group_id);

    let count = ctx.repo.count_open_groups().await.unwrap();
    assert_eq!(count, 2);
}

#[tokio::test]
async fn test_withdrawal_intent_storage_failures_and_controller_restart() {
    use prefixd::{
        AppState,
        bgp::{FlowSpecAnnouncer, MockAnnouncer, PeerStatus},
        db::{Repository, RepositoryTrait, init_postgres_pool},
        domain::{
            ActionParams, ActionType, AttackVector, FlowSpecRule, MatchCriteria, Mitigation,
            MitigationIntent, mitigation_rule, request_withdrawal,
        },
        error::{PrefixdError, Result},
        scheduler::ReconciliationLoop,
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering::SeqCst},
    };

    struct Speaker {
        inner: MockAnnouncer,
        mode: AtomicUsize,
        deletes: AtomicUsize,
        adds: AtomicUsize,
    }
    impl FlowSpecAnnouncer for Speaker {
        fn backend(&self) -> &'static str {
            "mock"
        }
        fn reader(&self) -> Option<&dyn FlowSpecReader> {
            Some(self)
        }
        fn peer_observer(&self) -> Option<&dyn PeerObserver> {
            Some(self)
        }
    }

    #[async_trait::async_trait]
    impl FlowSpecWriter for Speaker {
        async fn announce(&self, rule: &FlowSpecRule) -> Result<()> {
            self.adds.fetch_add(1, SeqCst);
            self.inner.announce(rule).await
        }
        async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()> {
            self.deletes.fetch_add(1, SeqCst);
            self.inner.withdraw(rule).await?;
            if self.mode.load(SeqCst) == 1 {
                return Err(PrefixdError::BgpWithdrawalFailed(
                    "reply lost after delete".into(),
                ));
            }
            Ok(())
        }
    }
    #[async_trait::async_trait]
    impl FlowSpecReader for Speaker {
        async fn list_active(&self) -> Result<Vec<FlowSpecRule>> {
            self.inner.list_active().await
        }
    }
    #[async_trait::async_trait]
    impl PeerObserver for Speaker {
        async fn session_status(&self) -> Result<Vec<PeerStatus>> {
            Ok(vec![])
        }
    }
    let context = TestContext::new().await;
    let pool = context.pool.clone();
    let connection = context.state.settings.storage.connection_string.clone();
    let repo = Arc::new(Repository::new(pool.clone()));
    let speaker = Arc::new(Speaker {
        inner: MockAnnouncer::new(),
        mode: AtomicUsize::new(0),
        deletes: AtomicUsize::new(0),
        adds: AtomicUsize::new(0),
    });
    let mut mitigation = Mitigation::from_intent(
        MitigationIntent {
            event_id: uuid::Uuid::new_v4(),
            customer_id: None,
            service_id: None,
            pop: "test-pop".into(),
            match_criteria: MatchCriteria {
                dst_prefix: "203.0.113.10/32".into(),
                protocol: Some(17),
                dst_ports: vec![53],
            },
            action_type: ActionType::Discard,
            action_params: ActionParams { rate_bps: None },
            ttl_seconds: 600,
            reason: "test".into(),
        },
        "203.0.113.10".into(),
        AttackVector::UdpFlood,
    );
    mitigation.activate();
    repo.insert_mitigation(&mitigation).await.unwrap();
    speaker
        .inner
        .announce(&mitigation_rule(&mitigation))
        .await
        .unwrap();
    let mut settings = common::test_settings();
    settings.mode = prefixd::config::OperationMode::Enforced;
    let state = AppState::new(
        settings.clone(),
        common::test_inventory(),
        common::test_playbooks(),
        repo.clone(),
        speaker.clone(),
        ".".into(),
    )
    .unwrap();
    let app = prefixd::api::create_test_router(state.clone());
    let withdraw = || {
        Request::builder()
            .method("POST")
            .uri(format!(
                "/v1/mitigations/{}/withdraw",
                mitigation.mitigation_id
            ))
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"operator_id":"forged","reason":"original reason"}"#,
            ))
            .unwrap()
    };
    // Duplicate admission must not replace a speaker rule before the unique DB index rejects it.
    let mut expanded = mitigation.clone();
    expanded.mitigation_id = uuid::Uuid::new_v4();
    expanded.victim_ip = "2001:0DB8:0:0:0:0:0:1".into();
    expanded.match_criteria.dst_prefix = format!("{}/128", expanded.victim_ip);
    expanded.scope_hash = expanded.match_criteria.compute_scope_hash();
    repo.insert_mitigation(&expanded).await.unwrap();
    speaker
        .inner
        .announce(&mitigation_rule(&expanded))
        .await
        .unwrap();
    for (original, requested_ip) in [(&mitigation, "203.0.113.10"), (&expanded, "2001:db8::1")] {
        let before = repo
            .get_mitigation(original.mitigation_id)
            .await
            .unwrap()
            .unwrap();
        let payload = serde_json::json!({"victim_ip":requested_ip, "protocol":"udp", "dst_ports":[53],
            "action":"police", "rate_bps":800, "ttl_seconds":60, "reason":"duplicate must preserve discard"});
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/mitigations")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(speaker.adds.load(SeqCst), 0);
        assert_eq!(speaker.deletes.load(SeqCst), 0);
        let after = repo
            .get_mitigation(original.mitigation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.expires_at, before.expires_at);
        assert_eq!(after.updated_at, before.updated_at);
        assert_eq!(after.scope_hash, before.scope_hash);
        assert_eq!(after.action_type, ActionType::Discard);
        let routes = speaker.inner.list_active().await.unwrap();
        assert_eq!(routes.len(), 2);
        assert!(
            routes
                .iter()
                .all(|rule| rule.actions[0].action_type == ActionType::Discard)
        );
    }
    // Remove only this alias fixture so later assertions still describe one pending deletion.
    speaker
        .inner
        .withdraw(&mitigation_rule(&expanded))
        .await
        .unwrap();
    sqlx::query("DELETE FROM mitigations WHERE mitigation_id = $1")
        .bind(expanded.mitigation_id)
        .execute(&pool)
        .await
        .unwrap();
    // A failed authoritative owner inventory must reject admission before any speaker RPC.
    sqlx::query("ALTER TABLE mitigations RENAME TO hidden_mitigations")
        .execute(&pool)
        .await
        .unwrap();
    let manual = serde_json::json!({"victim_ip":"203.0.113.11", "protocol":"udp", "dst_ports":[53], "action":"discard", "ttl_seconds":60, "reason":"preflight fault"});
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mitigations")
                .header("content-type", "application/json")
                .body(Body::from(manual.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let event = serde_json::json!({"event_id":"preflight-failure", "timestamp":chrono::Utc::now(), "source":"test", "victim_ip":"203.0.113.11", "vector":"udp_flood", "pps":50000, "top_dst_ports":[53]});
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(speaker.adds.load(SeqCst), 0);
    assert_eq!(speaker.deletes.load(SeqCst), 0);
    assert!(
        repo.find_ban_event_by_external_id("test", "preflight-failure")
            .await
            .unwrap()
            .is_none()
    );
    sqlx::query("ALTER TABLE hidden_mitigations RENAME TO mitigations")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE FUNCTION reject_withdrawal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected storage failure'; END $$; CREATE TRIGGER reject_request BEFORE INSERT ON withdrawal_requests FOR EACH ROW EXECUTE FUNCTION reject_withdrawal();").execute(&pool).await.unwrap();
    assert_eq!(
        app.clone().oneshot(withdraw()).await.unwrap().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(speaker.deletes.load(SeqCst), 0);
    assert!(repo.pending_withdrawals(None).await.unwrap().is_empty());
    sqlx::query("DROP TRIGGER reject_request ON withdrawal_requests")
        .execute(&pool)
        .await
        .unwrap();
    speaker.mode.store(1, SeqCst);
    assert_eq!(
        app.clone().oneshot(withdraw()).await.unwrap().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(speaker.deletes.load(SeqCst), 1);
    assert_eq!(speaker.inner.announced_count().await, 0);
    let original = repo.pending_withdrawals(None).await.unwrap().pop().unwrap();
    assert!(original.speaker_delete_required);
    assert_eq!(original.actor, "anonymous");
    assert_eq!(original.reason, "anonymous: original reason");

    sqlx::query("CREATE TRIGGER reject_completion BEFORE UPDATE ON withdrawal_requests FOR EACH ROW EXECUTE FUNCTION reject_withdrawal()").execute(&pool).await.unwrap();
    speaker.mode.store(0, SeqCst);
    let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false)
        .with_app_state(state.clone());
    assert!(reconciler.reconcile().await.is_err());
    assert_eq!(
        repo.get_mitigation(mitigation.mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        MitigationStatus::Active
    );
    assert_eq!(repo.pending_withdrawals(None).await.unwrap().len(), 1);
    let audits: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'withdraw'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(audits, 0);
    assert_eq!(speaker.adds.load(SeqCst), 0);

    // An unavailable authoritative ledger must fail closed before either cleanup or repair.
    sqlx::query("ALTER TABLE withdrawal_requests RENAME TO hidden_withdrawal_requests")
        .execute(&pool)
        .await
        .unwrap();
    let deletes = speaker.deletes.load(SeqCst);
    assert!(reconciler.reconcile().await.is_err());
    assert_eq!(speaker.deletes.load(SeqCst), deletes);
    assert_eq!(speaker.adds.load(SeqCst), 0);
    sqlx::query("ALTER TABLE hidden_withdrawal_requests RENAME TO withdrawal_requests")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP TRIGGER reject_completion ON withdrawal_requests")
        .execute(&pool)
        .await
        .unwrap();
    // Simulate an existing table from before originating mode was recorded.
    sqlx::query("ALTER TABLE withdrawal_requests DROP COLUMN speaker_delete_required")
        .execute(&pool)
        .await
        .unwrap();
    drop(reconciler);
    drop(app);
    drop(state);
    drop(repo);
    pool.close().await;

    // Rebuild the repository and controller with a new pool; no in-memory request is retained.
    let restarted_pool = init_postgres_pool(&connection).await.unwrap();
    let restarted_repo = Arc::new(Repository::new(restarted_pool.clone()));
    let persisted = restarted_repo.pending_withdrawals(None).await.unwrap();
    assert_eq!(persisted.len(), 1);
    assert!(persisted[0].speaker_delete_required);
    let (tx, mut updates) = tokio::sync::broadcast::channel(4);
    let dry_run = ReconciliationLoop::new(restarted_repo.clone(), speaker.clone(), 30, true)
        .with_ws_broadcast(tx);
    let deletes_before = speaker.deletes.load(SeqCst);
    assert!(dry_run.reconcile().await.is_err());
    assert_eq!(speaker.deletes.load(SeqCst), deletes_before);
    assert!(updates.try_recv().is_err());
    assert!(
        restarted_repo
            .get_mitigation(mitigation.mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .is_active()
    );
    assert_eq!(
        restarted_repo
            .pending_withdrawals(None)
            .await
            .unwrap()
            .len(),
        1
    );
    let audits: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'withdraw'")
            .fetch_one(&restarted_pool)
            .await
            .unwrap();
    assert_eq!(audits, 0);

    let state = AppState::new(
        settings,
        common::test_inventory(),
        common::test_playbooks(),
        restarted_repo.clone(),
        speaker.clone(),
        ".".into(),
    )
    .unwrap();
    let reconciler = ReconciliationLoop::new(restarted_repo.clone(), speaker.clone(), 30, false)
        .with_app_state(state);
    reconciler.reconcile().await.unwrap();
    let withdrawn = restarted_repo
        .get_mitigation(mitigation.mitigation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(withdrawn.status, MitigationStatus::Withdrawn);
    assert_eq!(withdrawn.reason, original.reason);
    assert!(
        restarted_repo
            .pending_withdrawals(None)
            .await
            .unwrap()
            .is_empty()
    );
    let (actor, details): (String, String) =
        sqlx::query_as("SELECT actor_id, details_json FROM audit_log WHERE action = 'withdraw'")
            .fetch_one(&restarted_pool)
            .await
            .unwrap();
    assert_eq!(actor, "anonymous");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&details).unwrap()["operation_id"],
        original.operation_id.to_string()
    );
    let deletes = speaker.deletes.load(SeqCst);
    reconciler.reconcile().await.unwrap();
    assert_eq!(speaker.deletes.load(SeqCst), deletes);

    // A later lifecycle revision cannot be finalized by an old operation.
    mitigation.mitigation_id = uuid::Uuid::new_v4();
    mitigation.activate();
    restarted_repo.insert_mitigation(&mitigation).await.unwrap();
    let current = restarted_repo
        .get_mitigation(mitigation.mitigation_id)
        .await
        .unwrap()
        .unwrap();
    let stale = request_withdrawal(
        restarted_repo.as_ref(),
        &current,
        false,
        "operator",
        "alice",
        "stale".into(),
        true,
        None,
    )
    .await
    .unwrap();
    sqlx::query("UPDATE mitigations SET updated_at = updated_at + INTERVAL '1 second' WHERE mitigation_id = $1").bind(mitigation.mitigation_id).execute(&restarted_pool).await.unwrap();
    assert!(
        restarted_repo
            .finish_withdrawal(&stale)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        restarted_repo
            .get_mitigation(mitigation.mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .is_active()
    );
    let mut simulated = mitigation.clone();
    simulated.mitigation_id = uuid::Uuid::new_v4();
    simulated.match_criteria.dst_prefix = "203.0.113.11/32".into();
    simulated.scope_hash = simulated.match_criteria.compute_scope_hash();
    restarted_repo.insert_mitigation(&simulated).await.unwrap();
    let simulated = restarted_repo
        .get_mitigation(simulated.mitigation_id)
        .await
        .unwrap()
        .unwrap();
    let request = request_withdrawal(
        restarted_repo.as_ref(),
        &simulated,
        false,
        "operator",
        "alice",
        "simulation".into(),
        false,
        None,
    )
    .await
    .unwrap();
    let reconstructed = Repository::new(restarted_pool.clone());
    let persisted = reconstructed
        .pending_withdrawals(None)
        .await
        .unwrap()
        .into_iter()
        .find(|pending| pending.operation_id == request.operation_id)
        .unwrap();
    assert!(!persisted.speaker_delete_required);
    let deletes_before = speaker.deletes.load(SeqCst);
    prefixd::domain::execute_withdrawal(&reconstructed, speaker.as_ref(), true, &persisted, None)
        .await
        .unwrap();
    assert_eq!(speaker.deletes.load(SeqCst), deletes_before);
}

#[tokio::test]
async fn test_legacy_canonical_owners_finish_ttl_cleanup_after_last_live_owner() {
    use prefixd::{
        domain::{
            ActionParams, ActionType, AttackVector, MatchCriteria, Mitigation, MitigationIntent,
            mitigation_rule,
        },
        scheduler::ReconciliationLoop,
    };
    let context = TestContext::new().await;
    let mut first = Mitigation::from_intent(
        MitigationIntent {
            event_id: uuid::Uuid::new_v4(),
            customer_id: None,
            service_id: None,
            pop: "test-pop".into(),
            match_criteria: MatchCriteria {
                dst_prefix: "2001:db8::1/128".into(),
                protocol: Some(17),
                dst_ports: vec![53],
            },
            action_type: ActionType::Discard,
            action_params: ActionParams { rate_bps: None },
            ttl_seconds: 60,
            reason: "legacy".into(),
        },
        "2001:db8::1".into(),
        AttackVector::UdpFlood,
    );
    first.activate();
    first.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
    first.scope_hash = "historical compressed owner".into();
    let mut second = first.clone();
    second.mitigation_id = uuid::Uuid::new_v4();
    second.match_criteria.dst_prefix = "2001:0DB8:0:0:0:0:0:1/128".into();
    second.scope_hash = "historical expanded owner".into();
    second.expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);
    for owner in [&first, &second] {
        context.repo.insert_mitigation(owner).await.unwrap();
    }
    context
        .state
        .announcer
        .announce(&mitigation_rule(&first))
        .await
        .unwrap();
    let reconciler = ReconciliationLoop::new(
        context.repo.clone(),
        context.state.announcer.clone(),
        30,
        false,
    )
    .with_app_state(context.state.clone());
    assert!(reconciler.reconcile().await.is_err());
    assert_eq!(
        context
            .state
            .announcer
            .reader()
            .unwrap()
            .list_active()
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        context
            .repo
            .get_mitigation(first.mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .is_active()
    );
    second.expires_at = first.expires_at;
    context.repo.update_mitigation(&second).await.unwrap();
    reconciler.reconcile().await.unwrap();
    for owner in [&first, &second] {
        assert_eq!(
            context
                .repo
                .get_mitigation(owner.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            MitigationStatus::Expired
        );
    }
    assert!(
        context
            .state
            .announcer
            .reader()
            .unwrap()
            .list_active()
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        context
            .repo
            .pending_withdrawals(None)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn test_documented_retention_preserves_live_intent_and_referenced_history() {
    use prefixd::{
        domain::{
            ActionParams, ActionType, AttackEvent, AttackEventInput, AttackVector, MatchCriteria,
            Mitigation, MitigationIntent, mitigation_rule,
        },
        observability::{ActorType, AuditEntry},
    };
    enum RequestState {
        Missing,
        Pending,
        Completed(i64),
    }
    use RequestState::{Completed, Missing, Pending};
    let context = TestContext::new().await;
    let now = chrono::Utc::now();
    for (name, status, age_days, request, has_announcement) in [
        (
            "expired-completed",
            MitigationStatus::Expired,
            8,
            Completed(8),
            false,
        ),
        (
            "withdrawn-completed",
            MitigationStatus::Withdrawn,
            8,
            Completed(8),
            false,
        ),
        (
            "without-request",
            MitigationStatus::Withdrawn,
            8,
            Missing,
            false,
        ),
        (
            "active-pending",
            MitigationStatus::Active,
            8,
            Pending,
            false,
        ),
        (
            "terminal-pending",
            MitigationStatus::Withdrawn,
            8,
            Pending,
            false,
        ),
        (
            "pending-parent",
            MitigationStatus::Pending,
            8,
            Pending,
            false,
        ),
        (
            "active-completed",
            MitigationStatus::Active,
            8,
            Completed(8),
            false,
        ),
        (
            "recent-completed",
            MitigationStatus::Withdrawn,
            1,
            Completed(1),
            false,
        ),
        (
            "terminal-recent-completed",
            MitigationStatus::Expired,
            8,
            Completed(1),
            false,
        ),
        (
            "with-announcement",
            MitigationStatus::Expired,
            8,
            Completed(8),
            true,
        ),
    ] {
        let mut mitigation = Mitigation::from_intent(
            MitigationIntent {
                event_id: uuid::Uuid::new_v4(),
                customer_id: None,
                service_id: None,
                pop: "test-pop".into(),
                match_criteria: MatchCriteria {
                    dst_prefix: "203.0.113.10/32".into(),
                    protocol: Some(17),
                    dst_ports: vec![53],
                },
                action_type: ActionType::Discard,
                action_params: ActionParams { rate_bps: None },
                ttl_seconds: 60,
                reason: name.into(),
            },
            "203.0.113.10".into(),
            AttackVector::UdpFlood,
        );
        mitigation.scope_hash = name.into();
        mitigation.status = status;
        mitigation.created_at = now - chrono::Duration::days(age_days);
        mitigation.updated_at = mitigation.created_at;
        mitigation.expires_at = mitigation.created_at + chrono::Duration::seconds(60);
        context.repo.insert_mitigation(&mitigation).await.unwrap();
        let rule = mitigation_rule(&mitigation);
        if !matches!(request, Missing) {
            let completed_at = match request {
                Completed(days) => Some(now - chrono::Duration::days(days)),
                _ => None,
            };
            sqlx::query(
                r#"INSERT INTO withdrawal_requests (
                operation_id, mitigation_id, pop, nlri_hash, rule_json, mitigation_updated_at,
                terminal_status, actor_type, actor, reason, requested_at, completed_at
            ) SELECT $1, mitigation_id, pop, $3, $4, updated_at, 'withdrawn',
                'operator', 'retention-test', 'retention fixture', updated_at, $5
              FROM mitigations WHERE mitigation_id = $2"#,
            )
            .bind(uuid::Uuid::new_v4())
            .bind(mitigation.mitigation_id)
            .bind(rule.nlri_hash())
            .bind(serde_json::to_string(&rule).unwrap())
            .bind(completed_at)
            .execute(&context.pool)
            .await
            .unwrap();
        }
        if has_announcement {
            sqlx::query(
                r#"INSERT INTO flowspec_announcements (
                announcement_id, mitigation_id, pop, peer_name, peer_address,
                nlri_hash, nlri_json, action_json, status
            ) VALUES ($1, $2, 'test-pop', 'fixture', '127.0.0.1', $3, $4, $5, 'failed')"#,
            )
            .bind(uuid::Uuid::new_v4())
            .bind(mitigation.mitigation_id)
            .bind(rule.nlri_hash())
            .bind(serde_json::to_string(&rule.nlri).unwrap())
            .bind(serde_json::to_string(&rule.actions).unwrap())
            .execute(&context.pool)
            .await
            .unwrap();
        }
    }
    let group =
        prefixd::correlation::CorrelationEngine::create_group("203.0.113.10", "udp_flood", 300);
    context.repo.insert_signal_group(&group).await.unwrap();
    for (external_id, age_days) in [
        ("old-ingestion", 8),
        ("recent-ingestion", 1),
        ("old-triggering-event", 8),
        ("old-last-event", 8),
        ("old-group-event", 8),
        ("old-pruned-parent-event", 8),
    ] {
        let input: AttackEventInput = serde_json::from_value(serde_json::json!({
            "event_id":external_id, "timestamp":now - chrono::Duration::days(20), "source":"retention-test",
            "victim_ip":"203.0.113.10", "vector":"udp_flood"
        })).unwrap();
        let mut event = AttackEvent::from_input(input);
        event.ingested_at = now - chrono::Duration::days(age_days);
        context.repo.insert_event(&event).await.unwrap();
        match external_id {
            "old-triggering-event" => {
                sqlx::query("UPDATE mitigations SET triggering_event_id = $1 WHERE reason = 'active-pending'")
                    .bind(event.event_id).execute(&context.pool).await.unwrap();
            }
            "old-last-event" => {
                sqlx::query(
                    "UPDATE mitigations SET last_event_id = $1 WHERE reason = 'terminal-pending'",
                )
                .bind(event.event_id)
                .execute(&context.pool)
                .await
                .unwrap();
            }
            "old-pruned-parent-event" => {
                sqlx::query("UPDATE mitigations SET triggering_event_id = $1 WHERE reason = 'expired-completed'")
                    .bind(event.event_id).execute(&context.pool).await.unwrap();
            }
            "old-group-event" => {
                context
                    .repo
                    .add_event_to_group(group.group_id, event.event_id, 1.0)
                    .await
                    .unwrap();
            }
            _ => {}
        }
    }
    context
        .repo
        .insert_audit(&AuditEntry::new(
            ActorType::System,
            None,
            "retention-preserve",
            None,
            None,
            serde_json::json!({}),
        ))
        .await
        .unwrap();

    // Parent-only pruning from the previous guide fails on retained withdrawal references.
    let mut transaction = context.pool.begin().await.unwrap();
    let old_prune = sqlx::query("DELETE FROM mitigations WHERE status IN ('expired', 'withdrawn') AND updated_at < NOW() - INTERVAL '7 days' AND reason = 'expired-completed'")
        .execute(&mut *transaction).await.unwrap_err();
    assert_eq!(
        old_prune.as_database_error().unwrap().code().as_deref(),
        Some("23503")
    );
    assert_eq!(
        old_prune.as_database_error().unwrap().constraint(),
        Some("withdrawal_requests_mitigation_id_fkey")
    );
    transaction.rollback().await.unwrap();

    let guide = include_str!("../docs/how-to/troubleshooting.md");
    let (_, retention) = guide
        .split_once("<!-- database-retention-prune -->")
        .unwrap();
    let (_, block) = retention.split_once("```sql\n").unwrap();
    let (sql, remaining) = block.split_once("```").unwrap();
    assert!(sql.trim().starts_with("BEGIN;"));
    assert!(sql.trim().ends_with("COMMIT;"));
    sqlx::raw_sql(sql).execute(&context.pool).await.unwrap();
    let counts_query = "SELECT (SELECT COUNT(*) FROM mitigations), (SELECT COUNT(*) FROM withdrawal_requests), (SELECT COUNT(*) FROM events), (SELECT COUNT(*) FROM audit_log), (SELECT COUNT(*) FROM flowspec_announcements)";
    let after_first: (i64, i64, i64, i64, i64) = sqlx::query_as(counts_query)
        .fetch_one(&context.pool)
        .await
        .unwrap();
    sqlx::raw_sql(sql).execute(&context.pool).await.unwrap();
    let after_second: (i64, i64, i64, i64, i64) = sqlx::query_as(counts_query)
        .fetch_one(&context.pool)
        .await
        .unwrap();
    assert_eq!(after_second, after_first);

    let (_, vacuum) = remaining.split_once("```sql\n").unwrap();
    let (vacuum, _) = vacuum.split_once("```").unwrap();
    sqlx::raw_sql(vacuum).execute(&context.pool).await.unwrap();

    let parents: Vec<String> = sqlx::query_scalar("SELECT reason FROM mitigations ORDER BY reason")
        .fetch_all(&context.pool)
        .await
        .unwrap();
    assert_eq!(
        parents,
        [
            "active-completed",
            "active-pending",
            "pending-parent",
            "recent-completed",
            "terminal-pending",
            "terminal-recent-completed",
            "with-announcement"
        ]
    );
    let requests: Vec<String> = sqlx::query_scalar("SELECT mitigation.reason FROM withdrawal_requests AS request JOIN mitigations AS mitigation USING (mitigation_id) ORDER BY mitigation.reason")
        .fetch_all(&context.pool).await.unwrap();
    assert_eq!(
        requests,
        [
            "active-completed",
            "active-pending",
            "pending-parent",
            "recent-completed",
            "terminal-pending",
            "terminal-recent-completed"
        ]
    );
    let events: Vec<String> =
        sqlx::query_scalar("SELECT external_event_id FROM events ORDER BY external_event_id")
            .fetch_all(&context.pool)
            .await
            .unwrap();
    assert_eq!(
        events,
        [
            "old-group-event",
            "old-last-event",
            "old-triggering-event",
            "recent-ingestion"
        ]
    );
    let audit_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log")
        .fetch_one(&context.pool)
        .await
        .unwrap();
    let announcement_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM flowspec_announcements")
        .fetch_one(&context.pool)
        .await
        .unwrap();
    assert_eq!(audit_count, 1);
    assert_eq!(announcement_count, 1);
    let membership_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM signal_group_events")
        .fetch_one(&context.pool)
        .await
        .unwrap();
    assert_eq!(membership_count, 1);
}

struct InventorySpeaker {
    inner: prefixd::bgp::MockAnnouncer,
    announcements: std::sync::Mutex<Vec<String>>,
    withdrawals: std::sync::Mutex<Vec<String>>,
    reject_withdrawals: bool,
    session_reads: std::sync::atomic::AtomicUsize,
}

impl InventorySpeaker {
    fn new(reject_withdrawals: bool) -> Self {
        Self {
            inner: prefixd::bgp::MockAnnouncer::new(),
            announcements: std::sync::Mutex::new(Vec::new()),
            withdrawals: std::sync::Mutex::new(Vec::new()),
            reject_withdrawals,
            session_reads: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl prefixd::bgp::FlowSpecAnnouncer for InventorySpeaker {
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
impl prefixd::bgp::FlowSpecWriter for InventorySpeaker {
    async fn announce(&self, rule: &prefixd::domain::FlowSpecRule) -> prefixd::error::Result<()> {
        self.announcements.lock().unwrap().push(rule.nlri_hash());
        self.inner.announce(rule).await
    }
    async fn withdraw(&self, rule: &prefixd::domain::FlowSpecRule) -> prefixd::error::Result<()> {
        self.withdrawals.lock().unwrap().push(rule.nlri_hash());
        if self.reject_withdrawals {
            return Err(prefixd::error::PrefixdError::BgpWithdrawalFailed(
                "retained for retry".into(),
            ));
        }
        self.inner.withdraw(rule).await
    }
}
#[async_trait::async_trait]
impl prefixd::bgp::FlowSpecReader for InventorySpeaker {
    async fn list_active(&self) -> prefixd::error::Result<Vec<prefixd::domain::FlowSpecRule>> {
        self.inner.list_active().await
    }
}
#[async_trait::async_trait]
impl prefixd::bgp::PeerObserver for InventorySpeaker {
    async fn session_status(&self) -> prefixd::error::Result<Vec<prefixd::bgp::PeerStatus>> {
        self.session_reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner.session_status().await
    }
}

fn inventory_mitigation(
    prefix: &str,
    pop: &str,
    created_at: chrono::DateTime<chrono::Utc>,
    status: MitigationStatus,
) -> prefixd::domain::Mitigation {
    use prefixd::domain::{
        ActionParams, ActionType, AttackVector, MatchCriteria, Mitigation, MitigationIntent,
    };
    let mut mitigation = Mitigation::from_intent(
        MitigationIntent {
            event_id: uuid::Uuid::new_v4(),
            customer_id: None,
            service_id: None,
            pop: pop.into(),
            match_criteria: MatchCriteria {
                dst_prefix: prefix.into(),
                protocol: Some(17),
                dst_ports: vec![53],
            },
            action_type: ActionType::Discard,
            action_params: ActionParams { rate_bps: None },
            ttl_seconds: 3600,
            reason: "inventory correctness fixture".into(),
        },
        prefix.split('/').next().unwrap().into(),
        AttackVector::UdpFlood,
    );
    mitigation.status = status;
    mitigation.created_at = created_at;
    mitigation.updated_at = created_at;
    mitigation
}

#[tokio::test]
async fn test_public_mitigation_cursor_is_complete_filtered_and_strict() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use chrono::{DateTime, Duration, SecondsFormat, Utc};
    use std::collections::BTreeSet;
    use uuid::Uuid;

    async fn page(app: &axum::Router, uri: &str) -> serde_json::Value {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    let ctx = TestContext::new().await;
    let app = ctx.router().await;
    let empty = page(&app, "/v1/mitigations?limit=2").await;
    assert_eq!(empty["count"], 0);
    assert_eq!(empty["has_more"], false);
    assert!(empty["next_cursor"].is_null());

    let timestamp: DateTime<Utc> = "2026-10-18T12:00:00.123456Z".parse().unwrap();
    let pop_a = "Edge / β +1";
    let pop_b = "iad1";
    // Seven eligible ties, six independently excluded rows, and shuffled insertion order.
    for id in [7_u128, 1, 5, 2, 6, 3, 4, 8, 9, 10, 11, 12, 13] {
        let mut mitigation = inventory_mitigation(
            "203.0.113.10/32",
            if id % 2 == 0 { pop_b } else { pop_a },
            timestamp,
            if id % 2 == 0 {
                MitigationStatus::Escalated
            } else {
                MitigationStatus::Active
            },
        );
        mitigation.mitigation_id = Uuid::from_u128(id);
        mitigation.customer_id = Some("cursor_customer".into());
        mitigation.match_criteria.dst_ports = vec![1000 + u16::try_from(id).unwrap()];
        match id {
            8 => mitigation.created_at = timestamp - Duration::microseconds(1),
            9 => mitigation.created_at = timestamp + Duration::seconds(1),
            10 => mitigation.status = MitigationStatus::Withdrawn,
            11 => mitigation.customer_id = Some("other_customer".into()),
            12 => {
                mitigation.victim_ip = "203.0.113.11".into();
                mitigation.match_criteria.dst_prefix = "203.0.113.11/32".into();
            }
            _ => {}
        }
        mitigation.scope_hash = mitigation.match_criteria.compute_scope_hash();
        ctx.repo.insert_mitigation(&mitigation).await.unwrap();
    }
    // Acknowledgement is persisted separately from initial mitigation insertion.
    let acknowledged_ids: Vec<_> = (1..=12).map(Uuid::from_u128).collect();
    let acknowledged = ctx
        .repo
        .acknowledge_mitigations(&acknowledged_ids, "cursor-operator")
        .await
        .unwrap();
    assert_eq!(
        acknowledged.into_iter().collect::<BTreeSet<_>>(),
        acknowledged_ids.into_iter().collect::<BTreeSet<_>>(),
        "all twelve intended fixture rows must be acknowledged"
    );
    let start = timestamp.to_rfc3339_opts(SecondsFormat::Micros, true);
    let end = (timestamp + Duration::seconds(1)).to_rfc3339_opts(SecondsFormat::Micros, true);
    let filters = format!(
        "status=active,escalated&customer_id=cursor_customer&victim_ip=203.0.113.10&acknowledged=true&start={start}&end={end}"
    );
    let every_id: Vec<u128> = (1..=7).rev().collect();
    let mut scoped_sets = Vec::new();
    for (selected_pop, expected_ids) in [
        (None, every_id.clone()),
        (Some("all"), every_id),
        (Some(pop_a), vec![7, 5, 3, 1]),
        (Some(pop_b), vec![6, 4, 2]),
        (Some("unknown"), vec![]),
        (Some("IAD1"), vec![]),
        (Some(" "), vec![]),
    ] {
        let suffix = selected_pop
            .map(|pop| format!("&pop={}", urlencoding::encode(pop)))
            .unwrap_or_default();
        let expected_counts: Vec<_> = if expected_ids.is_empty() {
            vec![0]
        } else {
            expected_ids.chunks(2).map(|page| page.len()).collect()
        };
        let mut cursor = None;
        let mut ordered = Vec::new();
        let mut unique = BTreeSet::new();
        for (page_index, expected_count) in expected_counts.into_iter().enumerate() {
            let mut uri = format!("/v1/mitigations?limit=2&{filters}{suffix}");
            if let Some(value) = &cursor {
                uri.push_str(&format!("&cursor={value}"));
            }
            let json = page(&app, &uri).await;
            assert_eq!(
                json["count"],
                expected_count,
                "page {} cursor_present={} selected_pop={selected_pop:?}",
                page_index + 1,
                cursor.is_some()
            );
            for row in json["mitigations"].as_array().unwrap() {
                let id = Uuid::parse_str(row["mitigation_id"].as_str().unwrap()).unwrap();
                assert!(unique.insert(id), "duplicate mitigation across pages");
                assert_eq!(row["customer_id"], "cursor_customer");
                assert_eq!(row["victim_ip"], "203.0.113.10");
                assert!(row["acknowledged_at"].is_string());
                if let Some(pop) = selected_pop.filter(|pop| *pop != "all") {
                    assert_eq!(row["pop"], pop);
                }
                ordered.push(id);
            }
            cursor = json["next_cursor"].as_str().map(str::to_owned);
            assert_eq!(json["has_more"], cursor.is_some());
            if let Some(value) = &cursor {
                assert!(value.starts_with("m1."));
                assert!(value.len() <= 128);
            }
        }
        let expected: Vec<_> = expected_ids.into_iter().map(Uuid::from_u128).collect();
        assert_eq!(ordered, expected, "descending UUID breaks equal timestamps");
        assert_eq!(unique, expected.into_iter().collect());
        if selected_pop == Some(pop_a) || selected_pop == Some(pop_b) {
            scoped_sets.push(unique);
        }
        assert!(
            cursor.is_none(),
            "terminal page must not offer a continuation"
        );

        // A valid position below the smallest tied UUID returns an empty terminal page.
        let terminal = format!(
            "m1.{}",
            URL_SAFE_NO_PAD.encode(format!("{start}\n{}", Uuid::nil()))
        );
        let json = page(
            &app,
            &format!("/v1/mitigations?limit=2&{filters}{suffix}&cursor={terminal}"),
        )
        .await;
        assert_eq!(json["count"], 0);
        assert_eq!(json["has_more"], false);
        assert!(json["next_cursor"].is_null());
    }

    assert!(scoped_sets[0].is_disjoint(&scoped_sets[1]));
    assert_eq!(scoped_sets[0].len() + scoped_sets[1].len(), 7);

    // In the global listing, the third eligible row is lookahead; POP-a includes it as row two.
    sqlx::query("UPDATE mitigations SET match_json = '{' WHERE mitigation_id = $1")
        .bind(Uuid::from_u128(5))
        .execute(&ctx.pool)
        .await
        .unwrap();
    for suffix in [
        String::new(),
        "&pop=all".into(),
        format!("&pop={}", urlencoding::encode(pop_a)),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/mitigations?limit=2&{filters}{suffix}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "corrupt lookahead must fail the entire page, not masquerade as end of history"
        );
    }
    // SQL excludes another POP's corrupt row before strict domain decoding.
    let other_pop = page(
        &app,
        &format!("/v1/mitigations?limit=2&{filters}&pop={pop_b}"),
    )
    .await;
    assert_eq!(other_pop["count"], 2);
    assert_eq!(other_pop["has_more"], true);
    assert!(
        other_pop["mitigations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["pop"] == pop_b)
    );
}

#[tokio::test]
async fn test_reconciliation_recovers_every_tied_timestamp_once() {
    use chrono::Timelike;
    use prefixd::{
        AppState,
        domain::{FlowSpecAction, FlowSpecNlri, FlowSpecRule, mitigation_rule},
        scheduler::ReconciliationLoop,
    };
    use std::{collections::BTreeSet, sync::Arc};
    let context = TestContext::new().await;
    let created_at = chrono::Utc::now().with_nanosecond(0).unwrap();
    let mut local_keys = BTreeSet::new();
    for index in 0..1001 {
        let prefix = format!("198.18.{}.{}/32", index / 256, index % 256);
        let status = if index == 1000 {
            MitigationStatus::Escalated
        } else {
            MitigationStatus::Active
        };
        let mitigation = inventory_mitigation(&prefix, "test-pop", created_at, status);
        local_keys.insert(mitigation_rule(&mitigation).nlri_hash());
        context.repo.insert_mitigation(&mitigation).await.unwrap();
    }
    let foreign = inventory_mitigation(
        "203.0.113.254/32",
        "other-pop",
        created_at,
        MitigationStatus::Active,
    );
    context.repo.insert_mitigation(&foreign).await.unwrap();
    let (local_count, timestamp_count): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COUNT(DISTINCT created_at) FROM mitigations WHERE pop = 'test-pop'",
    )
    .fetch_one(&context.pool)
    .await
    .unwrap();
    assert_eq!((local_count, timestamp_count), (1001, 1));
    let version: String = sqlx::query_scalar("SELECT version()")
        .fetch_one(&context.pool)
        .await
        .unwrap();
    eprintln!(
        "PostgreSQL: {version}; local distinct NLRIs: {}; local rows: {local_count}; creation timestamps: {timestamp_count}; created_at: {created_at}",
        local_keys.len()
    );
    for scoped in [true, false] {
        let speaker = Arc::new(InventorySpeaker::new(false));
        let unknown = FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: "203.0.113.253/32".into(),
                protocol: None,
                dst_ports: vec![],
            },
            FlowSpecAction::discard(),
        );
        speaker.inner.announce(&unknown).await.unwrap();
        let mut expected = local_keys.clone();
        if !scoped {
            expected.insert(mitigation_rule(&foreign).nlri_hash());
        }
        let mut reconciler =
            ReconciliationLoop::new(context.repo.clone(), speaker.clone(), 30, false);
        if scoped {
            let state = AppState::new(
                common::test_settings(),
                common::test_inventory(),
                common::test_playbooks(),
                context.repo.clone(),
                speaker.clone(),
                ".".into(),
            )
            .unwrap();
            reconciler = reconciler.with_app_state(state);
        }
        reconciler.reconcile().await.unwrap();
        let calls = speaker.announcements.lock().unwrap().clone();
        assert_eq!(calls.len(), expected.len(), "scoped={scoped}");
        assert_eq!(calls.into_iter().collect::<BTreeSet<_>>(), expected);
        reconciler.reconcile().await.unwrap();
        assert_eq!(speaker.announcements.lock().unwrap().len(), expected.len());
        assert!(speaker.withdrawals.lock().unwrap().is_empty());
        let actual: BTreeSet<_> = speaker
            .list_active()
            .await
            .unwrap()
            .iter()
            .map(|rule| rule.nlri_hash())
            .collect();
        expected.insert(unknown.nlri_hash());
        assert_eq!(actual, expected);
    }
}

#[tokio::test]
async fn test_reconciliation_inventory_excludes_ineligible_owners() {
    use prefixd::{
        AppState,
        domain::{mitigation_rule, request_withdrawal},
        scheduler::ReconciliationLoop,
    };
    use std::{collections::BTreeSet, sync::Arc};
    let context = TestContext::new().await;
    let created_at = chrono::Utc::now();
    let active = inventory_mitigation(
        "192.0.2.1/32",
        "test-pop",
        created_at,
        MitigationStatus::Active,
    );
    let escalated = inventory_mitigation(
        "192.0.2.2/32",
        "test-pop",
        created_at,
        MitigationStatus::Escalated,
    );
    let foreign = inventory_mitigation(
        "192.0.2.3/32",
        "other-pop",
        created_at,
        MitigationStatus::Active,
    );
    let pending = inventory_mitigation(
        "192.0.2.4/32",
        "test-pop",
        created_at,
        MitigationStatus::Pending,
    );
    let mut expired = inventory_mitigation(
        "192.0.2.5/32",
        "test-pop",
        created_at,
        MitigationStatus::Active,
    );
    expired.expires_at = created_at - chrono::Duration::seconds(1);
    let deleting = inventory_mitigation(
        "192.0.2.6/32",
        "test-pop",
        created_at,
        MitigationStatus::Active,
    );
    for mitigation in [&active, &escalated, &foreign, &pending, &expired, &deleting] {
        context.repo.insert_mitigation(mitigation).await.unwrap();
    }
    let deleting = context
        .repo
        .get_mitigation(deleting.mitigation_id)
        .await
        .unwrap()
        .unwrap();
    request_withdrawal(
        context.repo.as_ref(),
        &deleting,
        false,
        "operator",
        "fixture",
        "pending withdrawal".into(),
        true,
        None,
    )
    .await
    .unwrap();
    for scoped in [true, false] {
        let speaker = Arc::new(InventorySpeaker::new(true));
        let mut expected = BTreeSet::from([
            mitigation_rule(&active).nlri_hash(),
            mitigation_rule(&escalated).nlri_hash(),
        ]);
        if !scoped {
            expected.insert(mitigation_rule(&foreign).nlri_hash());
        }
        let mut reconciler =
            ReconciliationLoop::new(context.repo.clone(), speaker.clone(), 30, false);
        if scoped {
            let state = AppState::new(
                common::test_settings(),
                common::test_inventory(),
                common::test_playbooks(),
                context.repo.clone(),
                speaker.clone(),
                ".".into(),
            )
            .unwrap();
            reconciler = reconciler.with_app_state(state);
        }
        // Deletions deliberately fail so expired and pending-delete rows remain status-active.
        assert!(reconciler.reconcile().await.is_err());
        let calls = speaker.announcements.lock().unwrap().clone();
        assert_eq!(calls.len(), expected.len());
        assert_eq!(calls.into_iter().collect::<BTreeSet<_>>(), expected);
        assert!(reconciler.reconcile().await.is_err());
        assert_eq!(speaker.announcements.lock().unwrap().len(), expected.len());
        let withdrawn: BTreeSet<_> = speaker
            .withdrawals
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .collect();
        assert_eq!(
            withdrawn,
            BTreeSet::from([
                mitigation_rule(&expired).nlri_hash(),
                mitigation_rule(&deleting).nlri_hash()
            ])
        );
        assert_eq!(
            context
                .repo
                .get_mitigation(pending.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            MitigationStatus::Pending
        );
    }
}

#[tokio::test]
async fn test_reconciliation_inventory_is_strict_and_isolates_foreign_corruption() {
    use prefixd::{AppState, scheduler::ReconciliationLoop};
    use std::sync::Arc;
    let context = TestContext::new().await;
    let created_at = chrono::Utc::now();
    let mut good = inventory_mitigation(
        "192.0.2.1/32",
        "test-pop",
        created_at,
        MitigationStatus::Active,
    );
    good.mitigation_id = uuid::Uuid::from_u128(1);
    let mut later_bad = inventory_mitigation(
        "192.0.2.2/32",
        "test-pop",
        created_at,
        MitigationStatus::Escalated,
    );
    later_bad.mitigation_id = uuid::Uuid::from_u128(2);
    let foreign = inventory_mitigation(
        "192.0.2.3/32",
        "other-pop",
        created_at,
        MitigationStatus::Active,
    );
    for mitigation in [&good, &later_bad, &foreign] {
        context.repo.insert_mitigation(mitigation).await.unwrap();
    }
    sqlx::query("UPDATE mitigations SET match_json = '{' WHERE mitigation_id = $1")
        .bind(foreign.mitigation_id)
        .execute(&context.pool)
        .await
        .unwrap();
    assert_eq!(
        context
            .repo
            .active_mitigation_inventory(Some("test-pop"))
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        context
            .repo
            .active_mitigations_for_pop("test-pop")
            .await
            .unwrap()
            .len(),
        2
    );
    let speaker = Arc::new(InventorySpeaker::new(false));
    let state = AppState::new(
        common::test_settings(),
        common::test_inventory(),
        common::test_playbooks(),
        context.repo.clone(),
        speaker.clone(),
        ".".into(),
    )
    .unwrap();
    ReconciliationLoop::new(context.repo.clone(), speaker.clone(), 30, false)
        .with_app_state(state)
        .reconcile()
        .await
        .unwrap();
    assert_eq!(speaker.announcements.lock().unwrap().len(), 2);
    assert!(
        context
            .repo
            .active_mitigation_inventory(None)
            .await
            .is_err()
    );
    let all_pop_speaker = Arc::new(InventorySpeaker::new(false));
    assert!(
        ReconciliationLoop::new(context.repo.clone(), all_pop_speaker.clone(), 30, false)
            .reconcile()
            .await
            .is_err()
    );
    assert!(all_pop_speaker.announcements.lock().unwrap().is_empty());

    sqlx::query("UPDATE mitigations SET match_json = $2 WHERE mitigation_id = $1")
        .bind(foreign.mitigation_id)
        .bind(serde_json::to_string(&foreign.match_criteria).unwrap())
        .execute(&context.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE mitigations SET match_json = '{' WHERE mitigation_id = $1")
        .bind(later_bad.mitigation_id)
        .execute(&context.pool)
        .await
        .unwrap();
    assert!(
        context
            .repo
            .active_mitigation_inventory(Some("test-pop"))
            .await
            .is_err()
    );
    let speaker = Arc::new(InventorySpeaker::new(false));
    let state = AppState::new(
        common::test_settings(),
        common::test_inventory(),
        common::test_playbooks(),
        context.repo.clone(),
        speaker.clone(),
        ".".into(),
    )
    .unwrap();
    assert!(
        ReconciliationLoop::new(context.repo.clone(), speaker.clone(), 30, false)
            .with_app_state(state)
            .reconcile()
            .await
            .is_err()
    );
    assert!(
        speaker.announcements.lock().unwrap().is_empty(),
        "malformed intent must prevent partial repairs"
    );
}

#[tokio::test]
async fn test_expiry_inventory_rejects_corrupt_owned_rows() {
    let context = TestContext::new().await;
    let now = chrono::Utc::now();
    let mut valid =
        inventory_mitigation("192.0.2.40/32", "test-pop", now, MitigationStatus::Active);
    valid.expires_at = now - chrono::Duration::seconds(10);
    let mut corrupt = inventory_mitigation(
        "192.0.2.41/32",
        "test-pop",
        now,
        MitigationStatus::Escalated,
    );
    corrupt.expires_at = valid.expires_at;
    for mitigation in [&valid, &corrupt] {
        context.repo.insert_mitigation(mitigation).await.unwrap();
    }
    sqlx::query("UPDATE mitigations SET match_json = '{' WHERE mitigation_id = $1")
        .bind(corrupt.mitigation_id)
        .execute(&context.pool)
        .await
        .unwrap();
    let version: String = sqlx::query_scalar("SELECT version()")
        .fetch_one(&context.pool)
        .await
        .unwrap();
    let expired_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mitigations WHERE pop = 'test-pop' AND status IN ('active', 'escalated') AND expires_at < NOW()",
    )
    .fetch_one(&context.pool)
    .await
    .unwrap();
    eprintln!("PostgreSQL: {version}; owned expired rows: {expired_rows}; corrupt owned rows: 1");
    assert_eq!(expired_rows, 2);
    let result = context.repo.find_expired_mitigations().await;
    assert!(
        result.is_err(),
        "strict expiry must reject the entire inventory, but returned {} of {expired_rows} owned rows",
        result.as_ref().map_or(0, Vec::len)
    );
    assert!(
        context
            .repo
            .expired_mitigation_inventory(Some("test-pop"))
            .await
            .is_err()
    );
    let speaker = std::sync::Arc::new(InventorySpeaker::new(false));
    let state = prefixd::AppState::new(
        common::test_settings(),
        common::test_inventory(),
        common::test_playbooks(),
        context.repo.clone(),
        speaker.clone(),
        ".".into(),
    )
    .unwrap();
    assert!(
        prefixd::scheduler::ReconciliationLoop::new(
            context.repo.clone(),
            speaker.clone(),
            30,
            false
        )
        .with_app_state(state)
        .reconcile()
        .await
        .is_err()
    );
    assert!(speaker.withdrawals.lock().unwrap().is_empty());
    assert!(speaker.announcements.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_expiry_inventory_scopes_before_decoding_and_expires_owned_rows() {
    use prefixd::{
        AppState,
        db::{MockRepository, RepositoryTrait},
        domain::mitigation_rule,
        scheduler::ReconciliationLoop,
    };
    use std::{collections::BTreeSet, sync::Arc};
    let context = TestContext::new().await;
    let now = chrono::Utc::now();
    let mut owned =
        inventory_mitigation("192.0.2.50/32", "test-pop", now, MitigationStatus::Active);
    owned.expires_at = now - chrono::Duration::seconds(10);
    let mut escalated = inventory_mitigation(
        "192.0.2.51/32",
        "test-pop",
        now,
        MitigationStatus::Escalated,
    );
    escalated.expires_at = owned.expires_at;
    let mut foreign =
        inventory_mitigation("192.0.2.52/32", "other-pop", now, MitigationStatus::Active);
    foreign.expires_at = owned.expires_at;
    let mut pending =
        inventory_mitigation("192.0.2.53/32", "test-pop", now, MitigationStatus::Pending);
    pending.expires_at = owned.expires_at;
    let future = inventory_mitigation("192.0.2.54/32", "test-pop", now, MitigationStatus::Active);
    let mut terminal =
        inventory_mitigation("192.0.2.55/32", "test-pop", now, MitigationStatus::Expired);
    terminal.expires_at = owned.expires_at;
    let expected = BTreeSet::from([owned.mitigation_id, escalated.mitigation_id]);
    let mut all_expected = expected.clone();
    all_expected.insert(foreign.mitigation_id);
    let mock: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    for repo in [&context.repo, &mock] {
        for mitigation in [&owned, &escalated, &foreign, &pending, &future, &terminal] {
            repo.insert_mitigation(mitigation).await.unwrap();
        }
        for (pop, expected) in [(Some("test-pop"), &expected), (None, &all_expected)] {
            let actual: BTreeSet<_> = repo
                .expired_mitigation_inventory(pop)
                .await
                .unwrap()
                .into_iter()
                .map(|mitigation| mitigation.mitigation_id)
                .collect();
            assert_eq!(&actual, expected);
        }
        assert_eq!(repo.find_expired_mitigations().await.unwrap().len(), 3);
    }
    sqlx::query("UPDATE mitigations SET match_json = '{' WHERE mitigation_id = $1")
        .bind(foreign.mitigation_id)
        .execute(&context.pool)
        .await
        .unwrap();
    assert_eq!(
        context
            .repo
            .expired_mitigation_inventory(Some("test-pop"))
            .await
            .unwrap()
            .len(),
        2
    );
    for pop in [Some("other-pop"), None] {
        assert!(
            context
                .repo
                .expired_mitigation_inventory(pop)
                .await
                .is_err()
        );
    }
    let speaker = Arc::new(InventorySpeaker::new(false));
    for mitigation in [&owned, &escalated, &foreign, &future] {
        speaker
            .inner
            .announce(&mitigation_rule(mitigation))
            .await
            .unwrap();
    }
    let state = AppState::new(
        common::test_settings(),
        common::test_inventory(),
        common::test_playbooks(),
        context.repo.clone(),
        speaker.clone(),
        ".".into(),
    )
    .unwrap();
    let reconciler = ReconciliationLoop::new(context.repo.clone(), speaker.clone(), 30, false)
        .with_app_state(state);
    reconciler.reconcile().await.unwrap();
    let withdrawals = speaker.withdrawals.lock().unwrap().clone();
    assert_eq!(withdrawals.len(), 2);
    assert_eq!(
        withdrawals.into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            mitigation_rule(&owned).nlri_hash(),
            mitigation_rule(&escalated).nlri_hash()
        ])
    );
    for mitigation in [&owned, &escalated] {
        assert_eq!(
            context
                .repo
                .get_mitigation(mitigation.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            MitigationStatus::Expired
        );
    }
    let foreign_status: String =
        sqlx::query_scalar("SELECT status FROM mitigations WHERE mitigation_id = $1")
            .bind(foreign.mitigation_id)
            .fetch_one(&context.pool)
            .await
            .unwrap();
    assert_eq!(foreign_status, "active");
    assert_eq!(
        context
            .repo
            .get_mitigation(pending.mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        MitigationStatus::Pending
    );
    assert_eq!(
        speaker
            .list_active()
            .await
            .unwrap()
            .iter()
            .map(|rule| rule.nlri_hash())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            mitigation_rule(&foreign).nlri_hash(),
            mitigation_rule(&future).nlri_hash()
        ])
    );
    reconciler.reconcile().await.unwrap();
    assert_eq!(speaker.withdrawals.lock().unwrap().len(), 2);
    assert!(speaker.announcements.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_expiry_failure_keeps_pending_cleanup_and_peer_refresh() {
    use prefixd::{
        domain::{mitigation_rule, request_withdrawal},
        scheduler::ReconciliationLoop,
    };
    use std::sync::{Arc, atomic::Ordering::Relaxed};
    let context = TestContext::new().await;
    let now = chrono::Utc::now();
    let pending = inventory_mitigation("192.0.2.60/32", "test-pop", now, MitigationStatus::Active);
    let mut corrupt = inventory_mitigation(
        "192.0.2.61/32",
        "other-pop",
        now,
        MitigationStatus::Escalated,
    );
    corrupt.expires_at = now - chrono::Duration::seconds(10);
    for mitigation in [&pending, &corrupt] {
        context.repo.insert_mitigation(mitigation).await.unwrap();
    }
    let pending = context
        .repo
        .get_mitigation(pending.mitigation_id)
        .await
        .unwrap()
        .unwrap();
    let request = request_withdrawal(
        context.repo.as_ref(),
        &pending,
        false,
        "operator",
        "expiry-fixture",
        "pending before expiry enumeration".into(),
        true,
        None,
    )
    .await
    .unwrap();
    sqlx::query("UPDATE mitigations SET match_json = '{' WHERE mitigation_id = $1")
        .bind(corrupt.mitigation_id)
        .execute(&context.pool)
        .await
        .unwrap();
    assert!(
        context
            .repo
            .expired_mitigation_inventory(None)
            .await
            .is_err()
    );
    let speaker = Arc::new(InventorySpeaker::new(false));
    for mitigation in [&pending, &corrupt] {
        speaker
            .inner
            .announce(&mitigation_rule(mitigation))
            .await
            .unwrap();
    }
    // Standalone enumeration spans POPs; the pending operation validates only its owner POP.
    let reconciler = ReconciliationLoop::new(context.repo.clone(), speaker.clone(), 30, false);
    let error = reconciler.reconcile().await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains(&corrupt.mitigation_id.to_string())
    );
    assert_eq!(
        context
            .repo
            .get_mitigation(pending.mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        MitigationStatus::Withdrawn
    );
    let completed: bool = sqlx::query_scalar(
        "SELECT completed_at IS NOT NULL FROM withdrawal_requests WHERE operation_id = $1",
    )
    .bind(request.operation_id)
    .fetch_one(&context.pool)
    .await
    .unwrap();
    assert!(completed);
    assert!(
        context
            .repo
            .pending_withdrawals(None)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        *speaker.withdrawals.lock().unwrap(),
        vec![mitigation_rule(&pending).nlri_hash()]
    );
    assert_eq!(
        speaker
            .list_active()
            .await
            .unwrap()
            .iter()
            .map(|rule| rule.nlri_hash())
            .collect::<Vec<_>>(),
        vec![mitigation_rule(&corrupt).nlri_hash()]
    );
    assert!(speaker.announcements.lock().unwrap().is_empty());
    assert_eq!(speaker.session_reads.load(Relaxed), 1);
    assert!(reconciler.reconcile().await.is_err());
    assert_eq!(speaker.withdrawals.lock().unwrap().len(), 1);
    assert!(speaker.announcements.lock().unwrap().is_empty());
    assert_eq!(speaker.session_reads.load(Relaxed), 2);
}

struct CreationSpeaker {
    pop: String,
    backend: &'static str,
    repo: std::sync::Arc<dyn prefixd::db::RepositoryTrait>,
    inner: prefixd::bgp::MockAnnouncer,
    mode: std::sync::atomic::AtomicUsize,
    adds: std::sync::atomic::AtomicUsize,
    deletes: std::sync::atomic::AtomicUsize,
    owners_at_rpc: std::sync::Mutex<Vec<Vec<uuid::Uuid>>>,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl CreationSpeaker {
    fn new(repo: std::sync::Arc<dyn prefixd::db::RepositoryTrait>, mode: usize) -> Self {
        Self {
            pop: "test-pop".into(),
            backend: "mock",
            repo,
            inner: prefixd::bgp::MockAnnouncer::new(),
            mode: std::sync::atomic::AtomicUsize::new(mode),
            adds: std::sync::atomic::AtomicUsize::new(0),
            deletes: std::sync::atomic::AtomicUsize::new(0),
            owners_at_rpc: std::sync::Mutex::new(Vec::new()),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        }
    }
}

impl prefixd::bgp::FlowSpecAnnouncer for CreationSpeaker {
    fn backend(&self) -> &'static str {
        self.backend
    }
    fn reader(&self) -> Option<&dyn prefixd::bgp::FlowSpecReader> {
        Some(self)
    }
    fn peer_observer(&self) -> Option<&dyn prefixd::bgp::PeerObserver> {
        Some(self)
    }
}

#[async_trait::async_trait]
impl FlowSpecWriter for CreationSpeaker {
    async fn announce(&self, rule: &prefixd::domain::FlowSpecRule) -> prefixd::error::Result<()> {
        use std::sync::atomic::Ordering::SeqCst;
        self.adds.fetch_add(1, SeqCst);
        let owners = self
            .repo
            .active_mitigations_for_pop(&self.pop)
            .await?
            .into_iter()
            .filter(|owner| prefixd::domain::mitigation_rule(owner).nlri_hash() == rule.nlri_hash())
            .map(|owner| owner.mitigation_id)
            .collect();
        self.owners_at_rpc.lock().unwrap().push(owners);
        let mode = self.mode.load(SeqCst);
        if mode == 3 {
            self.entered.notify_one();
            self.release.notified().await;
        }
        if mode == 1 {
            return Err(prefixd::error::PrefixdError::BgpAnnouncementFailed(
                "rejected before acceptance".into(),
            ));
        }
        self.inner.announce(rule).await?;
        if mode == 2 {
            return Err(prefixd::error::PrefixdError::BgpAnnouncementFailed(
                "timeout after acceptance".into(),
            ));
        }
        Ok(())
    }
    async fn withdraw(&self, rule: &prefixd::domain::FlowSpecRule) -> prefixd::error::Result<()> {
        self.deletes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.withdraw(rule).await
    }
}
#[async_trait::async_trait]
impl FlowSpecReader for CreationSpeaker {
    async fn list_active(&self) -> prefixd::error::Result<Vec<prefixd::domain::FlowSpecRule>> {
        self.inner.list_active().await
    }
}
#[async_trait::async_trait]
impl PeerObserver for CreationSpeaker {
    async fn session_status(&self) -> prefixd::error::Result<Vec<prefixd::bgp::PeerStatus>> {
        self.inner.session_status().await
    }
}

fn creation_state(
    context: &TestContext,
    speaker: std::sync::Arc<CreationSpeaker>,
    dry_run: bool,
) -> std::sync::Arc<prefixd::AppState> {
    let mut settings = context.state.settings.clone();
    settings.mode = if dry_run {
        prefixd::config::OperationMode::DryRun
    } else {
        prefixd::config::OperationMode::Enforced
    };
    prefixd::AppState::new(
        settings,
        common::test_inventory(),
        common::test_playbooks(),
        std::sync::Arc::new(prefixd::db::Repository::new(context.pool.clone())),
        speaker,
        ".".into(),
    )
    .unwrap()
}

fn creation_request(kind: &str, ip: &str, external_id: &str) -> Request<Body> {
    let (uri, payload) = if kind == "manual" {
        (
            "/v1/mitigations",
            serde_json::json!({
                "victim_ip": ip, "protocol":"udp", "dst_ports":[53], "action":"discard",
                "ttl_seconds":60, "reason":"creation safety fixture"
            }),
        )
    } else {
        (
            "/v1/events",
            serde_json::json!({
                "event_id":external_id, "timestamp":chrono::Utc::now(), "source":"creation-test",
                "victim_ip":ip, "vector":"udp_flood", "pps":50000, "top_dst_ports":[53], "confidence":0.9
            }),
        )
    };
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(payload.to_string()))
        .unwrap()
}

async fn creation_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn invalid_manual_actions_never_reach_postgres_or_the_speaker() {
    use std::sync::{Arc, atomic::Ordering::SeqCst};
    let context = TestContext::new().await;
    let speaker = Arc::new(CreationSpeaker::new(context.repo.clone(), 0));
    let state = creation_state(&context, speaker.clone(), false);
    let app = prefixd::api::create_test_router(state);
    for ip in ["203.0.113.10", "2001:db8::10"] {
        for (action, rate) in [
            ("police", None),
            ("police", Some(0)),
            ("police", Some(16_777_217)),
            ("police", Some(u64::MAX)),
            ("discard", Some(0)),
            ("discard", Some(8)),
        ] {
            let payload = serde_json::json!({"victim_ip":ip, "protocol":"udp", "action":action,
                "rate_bps":rate, "ttl_seconds":60, "reason":"invalid action fixture"});
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/mitigations")
                        .header("content-type", "application/json")
                        .body(Body::from(payload.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body = creation_json(response).await;
            assert!(
                body["error"]
                    .as_str()
                    .unwrap()
                    .starts_with("invalid request:")
            );
        }
    }
    let counts: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM mitigations), (SELECT COUNT(*) FROM events), (SELECT COUNT(*) FROM audit_log), (SELECT COUNT(*) FROM flowspec_announcements)"
    ).fetch_one(&context.pool).await.unwrap();
    assert_eq!(counts, (0, 0, 0, 0));
    assert_eq!(speaker.adds.load(SeqCst), 0);
    assert_eq!(speaker.deletes.load(SeqCst), 0);

    for (ip, action, rate) in [
        ("203.0.113.10", "discard", None),
        ("2001:db8::10", "police", Some(1)),
    ] {
        let payload = serde_json::json!({"victim_ip":ip, "protocol":"udp", "action":action,
            "rate_bps":rate, "ttl_seconds":60, "reason":"valid action control"});
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/mitigations")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = creation_json(response).await;
        let id = uuid::Uuid::parse_str(body["mitigation_id"].as_str().unwrap()).unwrap();
        assert_eq!(
            context
                .repo
                .get_mitigation(id)
                .await
                .unwrap()
                .unwrap()
                .action_params
                .rate_bps,
            rate
        );
    }
    assert_eq!(speaker.adds.load(SeqCst), 2);
}

#[tokio::test]
async fn test_creation_insert_failure_sends_no_rpc_and_retains_detector_id_gap() {
    use std::sync::{Arc, atomic::Ordering::SeqCst};
    let context = TestContext::new().await;
    let version: String = sqlx::query_scalar("SELECT version()")
        .fetch_one(&context.pool)
        .await
        .unwrap();
    eprintln!(
        "PostgreSQL: {version}; creation preparation trigger rejects INSERT after readable preflight"
    );
    let speaker = Arc::new(CreationSpeaker::new(context.repo.clone(), 0));
    let state = creation_state(&context, speaker.clone(), false);
    let mut updates = state.ws_broadcast.subscribe();
    let app = prefixd::api::create_test_router(state);
    // Reads and canonical-owner preflight succeed; only the final INSERT fails.
    sqlx::raw_sql("CREATE FUNCTION reject_creation() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'forced creation preparation failure'; END; $$ LANGUAGE plpgsql; CREATE TRIGGER reject_creation BEFORE INSERT ON mitigations FOR EACH ROW EXECUTE FUNCTION reject_creation();")
        .execute(&context.pool).await.unwrap();
    for kind in ["manual", "detector"] {
        let response = app
            .clone()
            .oneshot(creation_request(kind, "203.0.113.10", "failed-prepare"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(speaker.adds.load(SeqCst), 0, "kind={kind}");
        assert_eq!(context.repo.count_active_global().await.unwrap(), 0);
        while let Ok(message) = updates.try_recv() {
            assert!(!matches!(
                message,
                prefixd::ws::WsMessage::MitigationCreated { .. }
            ));
        }
    }
    assert!(
        context
            .repo
            .find_ban_event_by_external_id("creation-test", "failed-prepare")
            .await
            .unwrap()
            .is_some()
    );
    sqlx::query("DROP TRIGGER reject_creation ON mitigations")
        .execute(&context.pool)
        .await
        .unwrap();
    // This pre-existing ingestion gap is deliberately not repaired by deleting/replaying the event.
    let response = app
        .clone()
        .oneshot(creation_request(
            "detector",
            "203.0.113.10",
            "failed-prepare",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(speaker.adds.load(SeqCst), 0);
    for (kind, ip) in [("manual", "203.0.113.10"), ("detector", "203.0.113.11")] {
        let response = app
            .clone()
            .oneshot(creation_request(kind, ip, "fresh-prepare"))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if kind == "manual" {
                StatusCode::CREATED
            } else {
                StatusCode::ACCEPTED
            }
        );
        let body = creation_json(response).await;
        assert!(body.get("announcement_outcome").is_none());
        let id: uuid::Uuid = body["mitigation_id"].as_str().unwrap().parse().unwrap();
        assert_eq!(
            speaker.owners_at_rpc.lock().unwrap().last(),
            Some(&vec![id])
        );
        assert_eq!(
            context
                .repo
                .get_mitigation(id)
                .await
                .unwrap()
                .unwrap()
                .status,
            MitigationStatus::Active
        );
    }
}

#[tokio::test]
async fn test_creation_unconfirmed_intent_recovers_and_retires_without_reinjection() {
    use prefixd::scheduler::ReconciliationLoop;
    use std::sync::{Arc, atomic::Ordering::SeqCst};
    let context = TestContext::new().await;
    let speaker = Arc::new(CreationSpeaker::new(context.repo.clone(), 1));
    let state = creation_state(&context, speaker.clone(), false);
    let app = prefixd::api::create_test_router(state.clone());
    for (index, (kind, mode)) in [
        ("manual", 1),
        ("manual", 2),
        ("detector", 1),
        ("detector", 2),
    ]
    .into_iter()
    .enumerate()
    {
        let ip = format!("203.0.113.{}", 40 + index);
        speaker.mode.store(mode, SeqCst);
        let before = speaker.adds.load(SeqCst);
        let deletes_before = speaker.deletes.load(SeqCst);
        let mut updates = state.ws_broadcast.subscribe();
        let response = app
            .clone()
            .oneshot(creation_request(kind, &ip, &format!("uncertain-{index}")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = creation_json(response).await;
        assert_eq!(body["announcement_outcome"], "unconfirmed");
        assert_eq!(
            speaker.deletes.load(SeqCst),
            deletes_before,
            "creation must not compensate by deleting uncertain intent"
        );
        if kind == "detector" {
            let message = tokio::time::timeout(std::time::Duration::from_secs(1), updates.recv())
                .await
                .unwrap()
                .unwrap();
            let prefixd::ws::WsMessage::MitigationCreated { mitigation } = message else {
                panic!("committed desired intent must produce a created event");
            };
            assert_eq!(mitigation.status, "active");
            assert!(mitigation.announcement_outcome.is_none());
        }

        let id: uuid::Uuid = body["mitigation_id"].as_str().unwrap().parse().unwrap();
        assert_eq!(
            speaker.owners_at_rpc.lock().unwrap().last(),
            Some(&vec![id])
        );
        let original = context.repo.get_mitigation(id).await.unwrap().unwrap();
        assert_eq!(original.status, MitigationStatus::Active);
        assert_eq!(
            speaker.inner.list_active().await.unwrap().len(),
            usize::from(mode == 2)
        );
        let get = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/mitigations/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            creation_json(get)
                .await
                .get("announcement_outcome")
                .is_none(),
            "request-local outcome must not become persisted status"
        );
        let duplicate = app
            .clone()
            .oneshot(creation_request("manual", &ip, "ignored"))
            .await
            .unwrap();
        assert_eq!(duplicate.status(), StatusCode::CONFLICT);
        assert_eq!(speaker.adds.load(SeqCst), before + 1);
        let after = context.repo.get_mitigation(id).await.unwrap().unwrap();
        assert_eq!(after.expires_at, original.expires_at);
        assert_eq!(after.action_type, original.action_type);
        assert_eq!(
            after.action_params.rate_bps,
            original.action_params.rate_bps
        );
        speaker.mode.store(0, SeqCst);
        let recovered = creation_state(&context, speaker.clone(), false);
        let reconciler =
            ReconciliationLoop::new(recovered.repo.clone(), speaker.clone(), 30, false)
                .with_app_state(recovered.clone());
        reconciler.reconcile().await.unwrap();
        let repaired = before + 1 + usize::from(mode == 1);
        assert_eq!(speaker.adds.load(SeqCst), repaired);
        assert_eq!(speaker.inner.list_active().await.unwrap().len(), 1);
        reconciler.reconcile().await.unwrap();
        assert_eq!(speaker.adds.load(SeqCst), repaired);
        if mode == 1 {
            let mut expired = context.repo.get_mitigation(id).await.unwrap().unwrap();
            expired.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
            context.repo.update_mitigation(&expired).await.unwrap();
            reconciler.reconcile().await.unwrap();
            assert_eq!(
                context
                    .repo
                    .get_mitigation(id)
                    .await
                    .unwrap()
                    .unwrap()
                    .status,
                MitigationStatus::Expired
            );
        } else {
            let response = prefixd::api::create_test_router(recovered)
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/v1/mitigations/{id}/withdraw"))
                        .header("content-type", "application/json")
                        .body(Body::from(r#"{"reason":"uncertain intent cleanup"}"#))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                context
                    .repo
                    .get_mitigation(id)
                    .await
                    .unwrap()
                    .unwrap()
                    .status,
                MitigationStatus::Withdrawn
            );
        }
        assert!(speaker.inner.list_active().await.unwrap().is_empty());
        let deletes = speaker.deletes.load(SeqCst);
        reconciler.reconcile().await.unwrap();
        assert_eq!(speaker.adds.load(SeqCst), repaired);
        assert_eq!(speaker.deletes.load(SeqCst), deletes);
    }
}

#[tokio::test]
async fn test_creation_persisted_before_rpc_survives_controller_cancellation() {
    use prefixd::scheduler::ReconciliationLoop;
    use std::sync::{Arc, atomic::Ordering::SeqCst};
    let context = TestContext::new().await;
    for (index, kind) in ["manual", "detector"].into_iter().enumerate() {
        let speaker = Arc::new(CreationSpeaker::new(context.repo.clone(), 3));
        let state = creation_state(&context, speaker.clone(), false);
        let app = prefixd::api::create_test_router(state.clone());
        let ip = format!("203.0.113.{}", 60 + index);
        let task = tokio::spawn(async move {
            app.oneshot(creation_request(kind, &ip, "controller-cancel"))
                .await
        });
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            speaker.entered.notified(),
        )
        .await
        .expect("creation reaches the controlled RPC handoff");
        let owners = speaker
            .owners_at_rpc
            .lock()
            .unwrap()
            .last()
            .cloned()
            .unwrap();
        assert_eq!(
            owners.len(),
            1,
            "durable owner must exist before entering the RPC"
        );
        let id = owners[0];
        assert_eq!(
            context
                .repo
                .get_mitigation(id)
                .await
                .unwrap()
                .unwrap()
                .status,
            MitigationStatus::Active
        );
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(speaker.inner.list_active().await.unwrap().is_empty());
        speaker.mode.store(0, SeqCst);
        let reconstructed = creation_state(&context, speaker.clone(), false);
        let reconciler =
            ReconciliationLoop::new(reconstructed.repo.clone(), speaker.clone(), 30, false)
                .with_app_state(reconstructed.clone());
        reconciler.reconcile().await.unwrap();
        assert_eq!(speaker.adds.load(SeqCst), 2);
        assert_eq!(speaker.inner.list_active().await.unwrap().len(), 1);
        reconciler.reconcile().await.unwrap();
        assert_eq!(speaker.adds.load(SeqCst), 2);
        let mut expired = context.repo.get_mitigation(id).await.unwrap().unwrap();
        expired.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
        context.repo.update_mitigation(&expired).await.unwrap();
        reconciler.reconcile().await.unwrap();
        assert!(speaker.inner.list_active().await.unwrap().is_empty());
        reconciler.reconcile().await.unwrap();
        assert_eq!(speaker.adds.load(SeqCst), 2);
    }
}

#[tokio::test]
async fn test_creation_batch_accepts_unconfirmed_and_dry_run_keeps_its_contract() {
    use std::sync::{Arc, atomic::Ordering::SeqCst};
    let context = TestContext::new().await;
    let speaker = Arc::new(CreationSpeaker::new(context.repo.clone(), 1));
    let app = prefixd::api::create_test_router(creation_state(&context, speaker.clone(), false));
    let events: Vec<_> = (0..2).map(|index| serde_json::json!({
        "event_id":format!("batch-unconfirmed-{index}"), "timestamp":chrono::Utc::now(), "source":"creation-test",
        "victim_ip":format!("203.0.113.{}", 70 + index), "vector":"udp_flood", "pps":50000, "top_dst_ports":[53], "confidence":0.9
    })).collect();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events/batch")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({"events":events}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = creation_json(response).await;
    assert_eq!(body["accepted"], 2);
    assert_eq!(body["rejected"], 0);
    for result in body["results"].as_array().unwrap() {
        assert_eq!(result["announcement_outcome"], "unconfirmed");
        assert!(result["mitigation_id"].is_string());
        assert!(result.get("error").is_none());
    }
    let before = speaker.adds.load(SeqCst);
    let dry_app = prefixd::api::create_test_router(creation_state(&context, speaker.clone(), true));
    for (kind, ip) in [("manual", "203.0.113.80"), ("detector", "203.0.113.81")] {
        let response = dry_app
            .clone()
            .oneshot(creation_request(kind, ip, "dry-creation"))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if kind == "manual" {
                StatusCode::CREATED
            } else {
                StatusCode::ACCEPTED
            }
        );
        let body = creation_json(response).await;
        assert!(body.get("announcement_outcome").is_none());
        let id = body["mitigation_id"].as_str().unwrap().parse().unwrap();
        assert_eq!(
            context
                .repo
                .get_mitigation(id)
                .await
                .unwrap()
                .unwrap()
                .status,
            MitigationStatus::Active
        );
    }
    assert_eq!(speaker.adds.load(SeqCst), before);
    assert!(speaker.inner.list_active().await.unwrap().is_empty());
}

async fn public_list_page(app: &axum::Router, uri: &str) -> serde_json::Value {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{uri}");
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn test_public_list_cursors_are_complete_filtered_and_strict() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use chrono::{DateTime, Duration, SecondsFormat, Utc};
    use std::collections::BTreeSet;
    use uuid::Uuid;

    let ctx = TestContext::new().await;
    let app = ctx.router().await;
    let endpoints = [
        ("events", "events", "event_id", "e1."),
        ("audit", "entries", "audit_id", "a1."),
        ("signal-groups", "groups", "group_id", "s1."),
    ];
    for (endpoint, _, _, _) in endpoints {
        let empty = public_list_page(&app, &format!("/v1/{endpoint}?limit=2")).await;
        assert_eq!(empty["count"], 0);
        assert_eq!(empty["has_more"], false);
        assert!(empty["next_cursor"].is_null());
    }

    let timestamp: DateTime<Utc> = "2026-10-18T12:00:00.123456Z".parse().unwrap();
    // Seven ties, two eligible neighboring timestamps, and independent date/status/vector exclusions.
    for id in [7_u128, 1, 8, 5, 9, 2, 6, 3, 4, 10, 11, 12, 13] {
        let position = match id {
            8 => timestamp + Duration::microseconds(1),
            9 => timestamp - Duration::microseconds(1),
            10 => timestamp - Duration::seconds(2),
            11 => timestamp + Duration::seconds(2),
            13 => timestamp - Duration::milliseconds(500),
            _ => timestamp,
        };
        if id <= 11 {
            sqlx::query("INSERT INTO events (event_id, source, event_timestamp, ingested_at, victim_ip, vector) VALUES ($1, 'cursor', $2, $2, '203.0.113.10', 'udp_flood')")
                .bind(Uuid::from_u128(id)).bind(position).execute(&ctx.pool).await.unwrap();
            sqlx::query("INSERT INTO audit_log (audit_id, timestamp, actor_type, action, details_json) VALUES ($1, $2, 'system', 'cursor', '{}')")
                .bind(Uuid::from_u128(id)).bind(position).execute(&ctx.pool).await.unwrap();
        }
        sqlx::query("INSERT INTO signal_groups (group_id, victim_ip, vector, created_at, window_expires_at, status) VALUES ($1, $2, $3, $4, $4 + interval '1 hour', $5)")
            .bind(Uuid::from_u128(id)).bind(format!("203.0.113.{id}"))
            .bind(if id == 12 { "syn_flood" } else { "udp_flood" }).bind(position)
            .bind(if id == 13 { "expired" } else { "open" })
            .execute(&ctx.pool).await.unwrap();
    }
    let start = (timestamp - Duration::seconds(1)).to_rfc3339_opts(SecondsFormat::Micros, true);
    let end = (timestamp + Duration::seconds(2)).to_rfc3339_opts(SecondsFormat::Micros, true);
    for (endpoint, rows_key, id_key, prefix) in endpoints {
        let filters = if endpoint == "signal-groups" {
            format!("start={start}&end={end}&status=open&vector=udp_flood")
        } else {
            format!("start={start}&end={end}")
        };
        let mut cursor = None;
        let mut ordered = Vec::new();
        let mut unique = BTreeSet::new();
        for expected_count in [2, 2, 2, 2, 1] {
            let mut uri = format!("/v1/{endpoint}?limit=2&{filters}");
            if let Some(value) = &cursor {
                uri.push_str(&format!("&cursor={value}"));
            }
            let json = public_list_page(&app, &uri).await;
            assert_eq!(json["count"], expected_count, "{endpoint}");
            for row in json[rows_key].as_array().unwrap() {
                let id = Uuid::parse_str(row[id_key].as_str().unwrap()).unwrap();
                assert!(unique.insert(id), "duplicate {endpoint} row across pages");
                ordered.push(id);
            }
            cursor = json["next_cursor"].as_str().map(str::to_owned);
            assert_eq!(json["has_more"], cursor.is_some());
            if let Some(value) = &cursor {
                assert!(value.starts_with(prefix));
                assert!(value.len() <= 128);
            }
        }
        let expected = [8, 7, 6, 5, 4, 3, 2, 1, 9].map(Uuid::from_u128);
        assert_eq!(ordered, expected, "{endpoint} tuple order");
        assert_eq!(unique, expected.into_iter().collect());
        assert!(cursor.is_none());
        let terminal = format!(
            "{prefix}{}",
            URL_SAFE_NO_PAD.encode(format!("{start}\n{}", Uuid::nil()))
        );
        let empty = public_list_page(
            &app,
            &format!("/v1/{endpoint}?limit=2&{filters}&cursor={terminal}"),
        )
        .await;
        assert_eq!(empty["count"], 0);
        assert_eq!(empty["has_more"], false);
        assert!(empty["next_cursor"].is_null());
    }

    // Each date-excluded row would otherwise fall inside its own requested page.
    // Event JSONB exceeds serde_json's existing nesting limit; no schema constraints are changed.
    // Unknown group status is tested without a status filter so it is SQL-eligible.
    let corruptions = [
        (
            "events",
            "UPDATE events SET raw_details = (repeat('[', 130) || '0' || repeat(']', 130))::jsonb WHERE event_id = $1",
            "UPDATE events SET raw_details = NULL WHERE event_id = $1",
            "",
        ),
        (
            "audit",
            "UPDATE audit_log SET actor_type = 'invalid' WHERE audit_id = $1",
            "UPDATE audit_log SET actor_type = 'system' WHERE audit_id = $1",
            "",
        ),
        (
            "audit",
            "UPDATE audit_log SET schema_version = -1 WHERE audit_id = $1",
            "UPDATE audit_log SET schema_version = 1 WHERE audit_id = $1",
            "",
        ),
        (
            "audit",
            "UPDATE audit_log SET details_json = '{' WHERE audit_id = $1",
            "UPDATE audit_log SET details_json = '{}' WHERE audit_id = $1",
            "",
        ),
        (
            "signal-groups",
            "UPDATE signal_groups SET status = 'invalid' WHERE group_id = $1",
            "UPDATE signal_groups SET status = 'open' WHERE group_id = $1",
            "&vector=udp_flood",
        ),
        (
            "signal-groups",
            "UPDATE signal_groups SET primary_dimensions = '{\"customer_ids\":7}'::jsonb WHERE group_id = $1",
            "UPDATE signal_groups SET primary_dimensions = '{}'::jsonb WHERE group_id = $1",
            "&status=open&vector=udp_flood",
        ),
    ];
    for (endpoint, corrupt, restore, suffix) in corruptions {
        let ids = if corrupt.contains("SET primary_dimensions") {
            vec![8_u128, 6, 10, 12, 13]
        } else {
            vec![8_u128, 6, 10]
        };
        for id in ids {
            sqlx::query(corrupt)
                .bind(Uuid::from_u128(id))
                .execute(&ctx.pool)
                .await
                .unwrap();
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!(
                            "/v1/{endpoint}?limit=2&start={start}&end={end}{suffix}"
                        ))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                if id >= 10 {
                    StatusCode::OK
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                },
                "{endpoint} corrupt id {id}: {corrupt}"
            );
            if id >= 10 {
                // Removing only the applicable exclusion makes the same corrupt row fail.
                let included_uri = match id {
                    10 => format!("/v1/{endpoint}?limit=100&end={end}{suffix}"),
                    12 => format!("/v1/{endpoint}?limit=100&start={start}&end={end}&status=open"),
                    13 => {
                        format!("/v1/{endpoint}?limit=100&start={start}&end={end}&vector=udp_flood")
                    }
                    _ => unreachable!(),
                };
                let response = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .uri(included_uri)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            }
            sqlx::query(restore)
                .bind(Uuid::from_u128(id))
                .execute(&ctx.pool)
                .await
                .unwrap();
            public_list_page(
                &app,
                &format!("/v1/{endpoint}?limit=2&start={start}&end={end}{suffix}"),
            )
            .await;
        }
    }
}

#[tokio::test]
async fn test_public_list_cursors_reject_invalid_input() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let ctx = TestContext::new().await;
    let app = ctx.router().await;
    let timestamp = "2026-10-18T12:00:00Z";
    let id = "00000000-0000-0000-0000-000000000001";
    let encode = |value: &str| URL_SAFE_NO_PAD.encode(value.as_bytes());
    for (endpoint, prefix, kind) in [
        ("events", "e1.", "event"),
        ("audit", "a1.", "audit"),
        ("signal-groups", "s1.", "signal-group"),
    ] {
        let valid = encode(&format!("{timestamp}\n{id}"));
        let boundary = format!(
            "{prefix}{}",
            encode(&format!("2026-10-18T12:00:00.{}Z\n{id}", "0".repeat(35)))
        );
        let oversized = format!(
            "{prefix}{}",
            encode(&format!("2026-10-18T12:00:00.{}Z\n{id}", "0".repeat(36)))
        );
        assert_eq!(boundary.len(), 127);
        assert_eq!(oversized.len(), 129);
        public_list_page(&app, &format!("/v1/{endpoint}?cursor={boundary}")).await;
        let mut values = vec![
            String::new(),
            "garbage".into(),
            prefix.into(),
            format!("{prefix}!"),
            format!("{prefix}_w"),
            encode(timestamp),
            format!("{}2.{valid}", &prefix[..1]),
            format!("{prefix}{}", encode(timestamp)),
            format!("{prefix}{}", encode(&format!("bad-date\n{id}"))),
            format!("{prefix}{}", encode(&format!("{timestamp}\nbad-uuid"))),
            format!("{prefix}{}", encode(&format!("{timestamp}\n{id}\nextra"))),
            format!("{prefix}{valid}="),
            format!("{prefix}{valid}%0A"),
            format!("{prefix}{}", "A".repeat(125)),
            format!("{prefix}{}", "A".repeat(126)),
            format!("{prefix}%C3%A9"),
            oversized,
        ];
        for wrong in ["m1.", "e1.", "a1.", "s1."] {
            if wrong != prefix {
                values.push(format!("{wrong}{valid}"));
            }
        }
        // Alter unused trailing bits while leaving the decoded payload otherwise unchanged.
        let mut trailing = encode(&format!("2026-10-18T12:00:00+00:00\n{id}")).into_bytes();
        assert_eq!(trailing.last(), Some(&b'E'));
        *trailing.last_mut().unwrap() = b'F';
        values.push(format!("{prefix}{}", String::from_utf8(trailing).unwrap()));
        for value in values {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/{endpoint}?cursor={value}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "{endpoint}: {value:?}"
            );
            let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(
                json["error"]
                    .as_str()
                    .unwrap()
                    .contains(&format!("invalid {kind} cursor"))
            );
            assert!(
                json["error"]
                    .as_str()
                    .unwrap()
                    .contains(&format!("fresh {kind} listing"))
            );
        }
    }
}

#[tokio::test]
async fn test_signal_group_reads_propagate_corrupt_dimensions() {
    use prefixd::correlation::engine::{CorrelationEngine, EventDimensions};

    let ctx = TestContext::new().await;
    let group = CorrelationEngine::create_group("203.0.113.10", "udp_flood", 3600);
    ctx.repo.insert_signal_group(&group).await.unwrap();
    sqlx::query("UPDATE signal_groups SET primary_dimensions = 'null'::jsonb WHERE group_id = $1")
        .bind(group.group_id)
        .execute(&ctx.pool)
        .await
        .unwrap();
    assert!(ctx.repo.get_signal_group(group.group_id).await.is_err());
    assert!(
        ctx.repo
            .find_open_group(&group.victim_ip, &group.vector)
            .await
            .is_err()
    );
    assert!(ctx.repo.list_open_signal_groups().await.is_err());
    // SQL-selected candidates must decode before dimension matching, even if the probe is empty.
    assert!(
        ctx.repo
            .find_open_groups_by_dimensions(&None, &EventDimensions::default(), chrono::Utc::now())
            .await
            .is_err()
    );
    // The existing-group CTE path must not manufacture dimensions while resolving an insert.
    assert!(ctx.repo.insert_signal_group(&group).await.is_err());
    sqlx::query("UPDATE signal_groups SET window_expires_at = NOW() - interval '1 second' WHERE group_id = $1")
        .bind(group.group_id).execute(&ctx.pool).await.unwrap();
    assert!(ctx.repo.find_expired_signal_groups().await.is_err());
    sqlx::query("UPDATE signal_groups SET primary_dimensions = '{}'::jsonb WHERE group_id = $1")
        .bind(group.group_id)
        .execute(&ctx.pool)
        .await
        .unwrap();
    assert_eq!(
        ctx.repo.find_expired_signal_groups().await.unwrap().len(),
        1
    );
}

async fn quota_state(
    context: &TestContext,
    pop: &str,
    quotas: prefixd::config::QuotasConfig,
) -> (
    std::sync::Arc<prefixd::AppState>,
    std::sync::Arc<CreationSpeaker>,
) {
    let mut settings = context.state.settings.clone();
    settings.pop = pop.into();
    settings.quotas = quotas;
    settings.mode = prefixd::config::OperationMode::Enforced;
    settings.bgp.mode = prefixd::config::BgpMode::Gobgp;
    settings.bgp.gobgp_grpc = format!("http://{pop}.example:50051");
    let binding = context
        .repo
        .register_speaker_target(
            pop,
            &prefixd::domain::SpeakerTarget::from_config(&settings.bgp).unwrap(),
            false,
        )
        .await
        .unwrap();
    let mut speaker = CreationSpeaker::new(context.repo.clone(), 0);
    speaker.pop = pop.into();
    speaker.backend = "gobgp";
    let speaker = std::sync::Arc::new(speaker);
    let state = prefixd::AppState::new(
        settings,
        common::test_inventory(),
        common::test_playbooks(),
        context.repo.clone(),
        speaker.clone(),
        ".".into(),
    )
    .unwrap()
    .with_speaker_binding(binding)
    .unwrap();
    (state, speaker)
}

// Observe actual lock waiters. The admission namespace is production's fixed pair;
// the insert gate is fixture-owned and never used by production.
async fn wait_quota_lock(pool: &sqlx::PgPool, admission: bool, waiters: i64) {
    let (class, object) = if admission {
        (1886545528_i64, 1903522164_i64)
    } else {
        (7355, 2362)
    };
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pg_locks WHERE locktype = 'advisory' AND classid::bigint = $1 AND objid::bigint = $2 AND NOT granted AND database = (SELECT oid FROM pg_database WHERE datname = current_database())")
                .bind(class).bind(object).fetch_one(pool).await.unwrap();
            if count == waiters { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("requests must reach the observed quota/insert lock before release");
}

// These exact counter deltas need a process-local registry, independent of parallel tests.
async fn quota_metrics_child(test_name: &str) -> Option<String> {
    const CHILD: &str = "PREFIXD_QUOTA_METRICS_CHILD";
    let completion = format!("prefixd-quota-metrics-completed:{test_name}");
    if std::env::var(CHILD).ok().as_deref() == Some(test_name) {
        return Some(completion);
    }
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(90),
        tokio::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name, "--test-threads=1", "--nocapture"])
            .env(CHILD, test_name)
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("quota metrics child exceeded ninety seconds")
    .expect("quota metrics child output");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "quota metrics child failed ({:?})\n{stdout}\n{stderr}",
        output.status.code()
    );
    assert!(
        stdout.lines().any(|line| line == completion),
        "quota metrics child must run the selected test to completion"
    );
    None
}

#[tokio::test]
async fn test_shared_quota_http_serializes_two_pop_admissions() {
    use prefixd::observability::metrics::{EVENTS_REJECTED, GUARDRAIL_REJECTIONS};
    use std::sync::atomic::Ordering::SeqCst;
    let Some(completion) =
        quota_metrics_child("test_shared_quota_http_serializes_two_pop_admissions").await
    else {
        return;
    };
    for quota in ["global", "customer"] {
        for (first_kind, second_kind, first_status) in [
            ("manual", "detector", StatusCode::CREATED),
            ("detector", "manual", StatusCode::ACCEPTED),
        ] {
            let context = TestContext::new().await;
            let mut quotas = common::test_settings().quotas;
            if quota == "global" {
                quotas.max_active_global = 1;
            } else {
                quotas.max_active_per_customer = 1;
            }
            let (a, speaker_a) = quota_state(&context, "quota-a", quotas.clone()).await;
            let (b, speaker_b) = quota_state(&context, "quota-b", quotas).await;
            let app_a = prefixd::api::create_test_router(a);
            let app_b = prefixd::api::create_test_router(b);
            let guardrails = GUARDRAIL_REJECTIONS.with_label_values(&["QuotaExceeded"]);
            let rejected_events =
                EVENTS_REJECTED.with_label_values(&["creation-test", "guardrail"]);
            let before = (guardrails.get(), rejected_events.get());
            sqlx::raw_sql("CREATE FUNCTION gate_quota_insert() RETURNS trigger AS $$ BEGIN PERFORM pg_advisory_xact_lock(7355, 2362); RETURN NEW; END; $$ LANGUAGE plpgsql; CREATE TRIGGER gate_quota_insert BEFORE INSERT ON mitigations FOR EACH ROW EXECUTE FUNCTION gate_quota_insert();")
            .execute(&context.pool).await.unwrap();
            let mut gate = context.pool.begin().await.unwrap();
            sqlx::query("SELECT pg_advisory_xact_lock(7355, 2362)")
                .execute(&mut *gate)
                .await
                .unwrap();
            let first = tokio::spawn(async move {
                app_a
                    .oneshot(creation_request(first_kind, "203.0.113.10", "quota-a"))
                    .await
                    .unwrap()
            });
            wait_quota_lock(&context.pool, false, 1).await;
            let second = tokio::spawn(async move {
                app_b
                    .oneshot(creation_request(second_kind, "203.0.113.11", "quota-b"))
                    .await
                    .unwrap()
            });
            // The first request holds admission through INSERT; the second has completed
            // readable preflight and is waiting for its fresh authoritative counts.
            wait_quota_lock(&context.pool, true, 1).await;
            assert_eq!(speaker_a.adds.load(SeqCst) + speaker_b.adds.load(SeqCst), 0);
            assert_eq!(
                (guardrails.get(), rejected_events.get()),
                before,
                "both requests passed preflight without rejection"
            );
            gate.commit().await.unwrap();
            assert_eq!(first.await.unwrap().status(), first_status);
            let rejected = second.await.unwrap();
            assert_eq!(rejected.status(), StatusCode::UNPROCESSABLE_ENTITY);
            assert!(creation_json(rejected).await.to_string().contains(quota));
            assert_eq!(context.repo.count_active_global().await.unwrap(), 1);
            assert_eq!(speaker_a.adds.load(SeqCst), 1);
            assert_eq!(speaker_b.adds.load(SeqCst), 0);
            assert_eq!(speaker_a.owners_at_rpc.lock().unwrap()[0].len(), 1);
            assert_eq!(
                guardrails.get(),
                before.0 + 1.0,
                "quota={quota}, loser={second_kind}"
            );
            assert_eq!(
                rejected_events.get(),
                before.1 + if second_kind == "detector" { 1.0 } else { 0.0 },
                "only a rejected detector request increments the event counter"
            );
        }
    }
    println!("\n{completion}");
}

#[tokio::test]
async fn test_shared_quota_sequential_and_same_controller_controls() {
    use std::sync::atomic::Ordering::SeqCst;
    let context = TestContext::new().await;
    let mut quotas = common::test_settings().quotas;
    quotas.max_active_global = 1;
    let (state, speaker) = quota_state(&context, "quota-control", quotas).await;
    let app = prefixd::api::create_test_router(state);
    let first = app
        .clone()
        .oneshot(creation_request("manual", "203.0.113.10", "first"));
    let second = app
        .clone()
        .oneshot(creation_request("manual", "203.0.113.11", "second"));
    let (first, second) = tokio::join!(first, second);
    let first = first.unwrap();
    let winning_ip = if first.status() == StatusCode::CREATED {
        "203.0.113.10"
    } else {
        "203.0.113.11"
    };
    let mut statuses = [first.status().as_u16(), second.unwrap().status().as_u16()];
    statuses.sort();
    assert_eq!(statuses, [201, 422]);
    let response = app
        .clone()
        .oneshot(creation_request("detector", "203.0.113.12", "third"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let extended = app
        .oneshot(creation_request(
            "detector",
            winning_ip,
            "extend-at-capacity",
        ))
        .await
        .unwrap();
    assert_eq!(extended.status(), StatusCode::ACCEPTED);
    assert_eq!(creation_json(extended).await["status"], "extended");
    assert_eq!(context.repo.count_active_global().await.unwrap(), 1);
    assert_eq!(speaker.adds.load(SeqCst), 1);
}

fn assert_quota_error(result: prefixd::error::Result<()>, kind: &str, current: u32, max: u32) {
    match result.unwrap_err() {
        prefixd::error::PrefixdError::GuardrailViolation(
            prefixd::error::GuardrailError::QuotaExceeded {
                quota_type,
                current: observed,
                max: limit,
            },
        ) => assert_eq!((quota_type.as_str(), observed, limit), (kind, current, max)),
        error => panic!("expected quota error, got {error}"),
    }
}

#[tokio::test]
async fn test_shared_quota_postgres_mock_status_threshold_and_scope_parity() {
    let context = TestContext::new().await;
    for status in [
        MitigationStatus::Pending,
        MitigationStatus::Active,
        MitigationStatus::Escalated,
        MitigationStatus::Expired,
        MitigationStatus::Withdrawn,
        MitigationStatus::Rejected,
    ] {
        sqlx::query("DELETE FROM mitigations")
            .execute(&context.pool)
            .await
            .unwrap();
        let mock: std::sync::Arc<dyn prefixd::db::RepositoryTrait> =
            std::sync::Arc::new(prefixd::db::MockRepository::new());
        for repo in [&context.repo, &mock] {
            let mut existing =
                inventory_mitigation("203.0.113.10/32", "quota-a", chrono::Utc::now(), status);
            existing.customer_id = Some("customer-a".into());
            // Clock expiry does not release an active lifecycle slot.
            existing.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
            repo.insert_mitigation(&existing).await.unwrap();
            let mut candidate = inventory_mitigation(
                "203.0.113.11/32",
                "quota-a",
                chrono::Utc::now(),
                MitigationStatus::Active,
            );
            candidate.customer_id = Some("customer-a".into());
            let mut quotas = common::test_settings().quotas;
            quotas.max_active_per_customer = 1;
            quotas.max_active_per_pop = 1;
            quotas.max_active_global = 1;
            if status.is_active() {
                assert_quota_error(
                    repo.admit_mitigation(&candidate, &quotas).await,
                    "customer",
                    1,
                    1,
                );
                candidate.customer_id = None;
                assert_quota_error(
                    repo.admit_mitigation(&candidate, &quotas).await,
                    "pop",
                    1,
                    1,
                );
                candidate.pop = "quota-b".into();
                assert_quota_error(
                    repo.admit_mitigation(&candidate, &quotas).await,
                    "global",
                    1,
                    1,
                );
                existing.mitigation_id = uuid::Uuid::new_v4();
                existing.victim_ip = "203.0.113.13".into();
                existing.match_criteria.dst_prefix = "203.0.113.13/32".into();
                existing.scope_hash = existing.match_criteria.compute_scope_hash();
                repo.insert_mitigation(&existing).await.unwrap();
                candidate.customer_id = Some("customer-a".into());
                assert_quota_error(
                    repo.admit_mitigation(&candidate, &quotas).await,
                    "customer",
                    2,
                    1,
                );
                candidate.customer_id = None;
                candidate.pop = "quota-a".into();
                assert_quota_error(
                    repo.admit_mitigation(&candidate, &quotas).await,
                    "pop",
                    2,
                    1,
                );
                candidate.pop = "quota-b".into();
                assert_quota_error(
                    repo.admit_mitigation(&candidate, &quotas).await,
                    "global",
                    2,
                    1,
                );
            } else {
                repo.admit_mitigation(&candidate, &quotas).await.unwrap();
            }
        }
    }
    sqlx::query("DELETE FROM mitigations")
        .execute(&context.pool)
        .await
        .unwrap();
    let mock: std::sync::Arc<dyn prefixd::db::RepositoryTrait> =
        std::sync::Arc::new(prefixd::db::MockRepository::new());
    for repo in [&context.repo, &mock] {
        let mut candidate = inventory_mitigation(
            "203.0.113.12/32",
            "quota-a",
            chrono::Utc::now(),
            MitigationStatus::Active,
        );
        candidate.customer_id = Some("customer-a".into());
        let mut quotas = common::test_settings().quotas;
        quotas.max_active_per_customer = 0;
        assert_quota_error(
            repo.admit_mitigation(&candidate, &quotas).await,
            "customer",
            0,
            0,
        );
        candidate.customer_id = None;
        quotas.max_active_per_pop = 0;
        assert_quota_error(
            repo.admit_mitigation(&candidate, &quotas).await,
            "pop",
            0,
            0,
        );
        quotas.max_active_per_pop = 1;
        quotas.max_active_global = 0;
        assert_quota_error(
            repo.admit_mitigation(&candidate, &quotas).await,
            "global",
            0,
            0,
        );
        quotas.max_active_global = 10;
        repo.admit_mitigation(&candidate, &quotas).await.unwrap(); // None skips customer zero.
        candidate.mitigation_id = uuid::Uuid::new_v4();
        candidate.pop = "quota-b".into();
        candidate.customer_id = Some("customer-b".into());
        quotas.max_active_per_customer = 1;
        repo.admit_mitigation(&candidate, &quotas).await.unwrap(); // independent POP and customer.
        candidate.mitigation_id = uuid::Uuid::new_v4();
        candidate.customer_id = Some("customer-c".into());
        candidate.pop = "quota-c".into();
        repo.admit_mitigation(&candidate, &quotas).await.unwrap();
        assert_eq!(repo.count_active_global().await.unwrap(), 3);
    }
}

#[tokio::test]
async fn test_shared_quota_one_connection_overrides_repeatable_read() {
    use prefixd::db::RepositoryTrait;
    let context = TestContext::new().await;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET default_transaction_isolation = 'repeatable read'")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&context.state.settings.storage.connection_string)
        .await
        .unwrap();
    let repository = prefixd::db::Repository::new(pool.clone());
    let mut quotas = common::test_settings().quotas;
    quotas.max_active_global = 1;
    let candidate = inventory_mitigation(
        "203.0.113.10/32",
        "quota-b",
        chrono::Utc::now(),
        MitigationStatus::Active,
    );
    let mut gate = context.pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(1886545528, 1903522164)")
        .execute(&mut *gate)
        .await
        .unwrap();
    let admission =
        tokio::spawn(async move { repository.admit_mitigation(&candidate, &quotas).await });
    wait_quota_lock(&context.pool, true, 1).await;
    context
        .repo
        .insert_mitigation(&inventory_mitigation(
            "203.0.113.11/32",
            "quota-a",
            chrono::Utc::now(),
            MitigationStatus::Active,
        ))
        .await
        .unwrap();
    gate.commit().await.unwrap();
    assert_quota_error(admission.await.unwrap(), "global", 1, 1);
    sqlx::query("DELETE FROM mitigations")
        .execute(&context.pool)
        .await
        .unwrap();
    let repository = prefixd::db::Repository::new(pool.clone());
    repository
        .admit_mitigation(
            &inventory_mitigation(
                "203.0.113.12/32",
                "quota-b",
                chrono::Utc::now(),
                MitigationStatus::Active,
            ),
            &common::test_settings().quotas,
        )
        .await
        .unwrap();
    let default_isolation: String = sqlx::query_scalar("SHOW default_transaction_isolation")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(default_isolation, "repeatable read");
    pool.close().await;
}

async fn assert_quota_cleanup(context: &TestContext, pool: &sqlx::PgPool, retained_rows: i64) {
    // Returning the HTTP result and completing SQLx's queued rollback are separate
    // events. Observe pool recovery and absence of the transaction lock/row.
    tokio::time::timeout(std::time::Duration::from_secs(8), async {
        loop {
            let locks: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pg_locks WHERE locktype = 'advisory' AND classid::bigint = 1886545528 AND objid::bigint = 1903522164 AND database = (SELECT oid FROM pg_database WHERE datname = current_database())")
                .fetch_one(&context.pool).await.unwrap();
            if locks == 0 { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let mut connection = pool.acquire().await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mitigations").fetch_one(&mut *connection).await.unwrap();
        assert_eq!(count, retained_rows);
    }).await.expect("cancelled admission must release its lock, connection, and uncommitted row");
}

#[tokio::test]
async fn test_shared_quota_pool_wait_uses_whole_deadline() {
    use prefixd::db::RepositoryTrait;
    let context = TestContext::new().await;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .connect(&context.state.settings.storage.connection_string)
        .await
        .unwrap();
    let held = pool.acquire().await.unwrap();
    let repository = prefixd::db::Repository::new(pool.clone());
    let started = std::time::Instant::now();
    let error = repository
        .admit_mitigation(
            &inventory_mitigation(
                "203.0.113.10/32",
                "quota-a",
                chrono::Utc::now(),
                MitigationStatus::Active,
            ),
            &common::test_settings().quotas,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, prefixd::error::PrefixdError::Internal(ref message) if message == "mitigation admission timed out")
    );
    assert!(started.elapsed() >= std::time::Duration::from_secs(5));
    assert!(started.elapsed() < std::time::Duration::from_secs(7));
    drop(held);
    assert_quota_cleanup(&context, &pool, 0).await;
    pool.close().await;
}

#[tokio::test]
async fn test_shared_quota_lock_wait_times_out_without_rpc_or_blocking_other_pop_withdrawal() {
    use prefixd::observability::metrics::{EVENTS_REJECTED, GUARDRAIL_REJECTIONS};
    use std::sync::atomic::Ordering::SeqCst;
    let Some(completion) = quota_metrics_child(
        "test_shared_quota_lock_wait_times_out_without_rpc_or_blocking_other_pop_withdrawal",
    )
    .await
    else {
        return;
    };
    let guardrails = GUARDRAIL_REJECTIONS.with_label_values(&["QuotaExceeded"]);
    let rejected_events = EVENTS_REJECTED.with_label_values(&["creation-test", "guardrail"]);
    let before = (guardrails.get(), rejected_events.get());
    let context = TestContext::new().await;
    let (a, speaker_a) = quota_state(&context, "quota-a", common::test_settings().quotas).await;
    let (b, speaker_b) = quota_state(&context, "quota-b", common::test_settings().quotas).await;
    let existing = inventory_mitigation(
        "203.0.113.11/32",
        "quota-b",
        chrono::Utc::now(),
        MitigationStatus::Active,
    );
    context.repo.insert_mitigation(&existing).await.unwrap();
    speaker_b
        .announce(&prefixd::domain::mitigation_rule(&existing))
        .await
        .unwrap();
    let mut gate = context.pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(1886545528, 1903522164)")
        .execute(&mut *gate)
        .await
        .unwrap();
    let app_a = prefixd::api::create_test_router(a.clone());
    let started = std::time::Instant::now();
    let task = tokio::spawn(async move {
        app_a
            .oneshot(creation_request("detector", "203.0.113.10", "timeout"))
            .await
            .unwrap()
    });
    wait_quota_lock(&context.pool, true, 1).await;
    // A different controller's lifecycle mutex and row update remain independent.
    let withdrawn = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        prefixd::api::create_test_router(b).oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/mitigations/{}/withdraw",
                    existing.mitigation_id
                ))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"reason":"independent POP"}"#))
                .unwrap(),
        ),
    )
    .await
    .expect("independent withdrawal must complete while admission is locked")
    .unwrap();
    assert_eq!(withdrawn.status(), StatusCode::OK);
    assert_eq!(speaker_b.deletes.load(SeqCst), 1);
    let response = task.await.unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(started.elapsed() < std::time::Duration::from_secs(7));
    assert_eq!(speaker_a.adds.load(SeqCst), 0);
    // This controller still holds its lifecycle mutex during admission, but releases
    // it after the bounded failure. Do not claim zero local withdrawal interference.
    let _released =
        tokio::time::timeout(std::time::Duration::from_secs(1), a.mitigation_lock.lock())
            .await
            .unwrap();
    gate.commit().await.unwrap();
    assert_eq!(
        context
            .repo
            .get_mitigation(existing.mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        MitigationStatus::Withdrawn
    );
    assert_quota_cleanup(&context, &context.pool, 1).await;
    assert_eq!(
        (guardrails.get(), rejected_events.get()),
        before,
        "database and timeout failures are not quota or rejected-event metrics"
    );
    println!("\n{completion}");
}

#[tokio::test]
async fn test_shared_quota_count_failure_after_preflight_sends_no_rpc() {
    use prefixd::observability::metrics::{EVENTS_REJECTED, GUARDRAIL_REJECTIONS};
    use std::sync::atomic::Ordering::SeqCst;
    let Some(completion) =
        quota_metrics_child("test_shared_quota_count_failure_after_preflight_sends_no_rpc").await
    else {
        return;
    };
    let guardrails = GUARDRAIL_REJECTIONS.with_label_values(&["QuotaExceeded"]);
    let rejected_events = EVENTS_REJECTED.with_label_values(&["creation-test", "guardrail"]);
    let before = (guardrails.get(), rejected_events.get());
    let context = TestContext::new().await;
    let (state, speaker) = quota_state(&context, "quota-a", common::test_settings().quotas).await;
    let mut gate = context.pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(1886545528, 1903522164)")
        .execute(&mut *gate)
        .await
        .unwrap();
    let app = prefixd::api::create_test_router(state);
    let task = tokio::spawn(async move {
        app.oneshot(creation_request(
            "detector",
            "203.0.113.10",
            "count-failure",
        ))
        .await
        .unwrap()
    });
    wait_quota_lock(&context.pool, true, 1).await;
    // Preflight has succeeded. Only the authoritative transaction's count fails.
    sqlx::query("ALTER TABLE mitigations RENAME TO hidden_quota_mitigations")
        .execute(&context.pool)
        .await
        .unwrap();
    gate.commit().await.unwrap();
    assert_eq!(
        task.await.unwrap().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    sqlx::query("ALTER TABLE hidden_quota_mitigations RENAME TO mitigations")
        .execute(&context.pool)
        .await
        .unwrap();
    assert_eq!(speaker.adds.load(SeqCst), 0);
    assert_quota_cleanup(&context, &context.pool, 0).await;
    assert_eq!(
        (guardrails.get(), rejected_events.get()),
        before,
        "database and timeout failures are not quota or rejected-event metrics"
    );
    println!("\n{completion}");
}

#[tokio::test]
async fn test_shared_quota_statement_timeout_and_cancellation_roll_back() {
    use std::sync::atomic::Ordering::SeqCst;
    for cancel in [false, true] {
        let mut context = TestContext::new().await;
        let admission_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&context.state.settings.storage.connection_string)
            .await
            .unwrap();
        context.repo = std::sync::Arc::new(prefixd::db::Repository::new(admission_pool.clone()));
        let (state, speaker) =
            quota_state(&context, "quota-a", common::test_settings().quotas).await;
        sqlx::raw_sql("CREATE FUNCTION slow_quota_insert() RETURNS trigger AS $$ BEGIN PERFORM pg_sleep(30); RETURN NEW; END; $$ LANGUAGE plpgsql; CREATE TRIGGER slow_quota_insert BEFORE INSERT ON mitigations FOR EACH ROW EXECUTE FUNCTION slow_quota_insert();")
            .execute(&context.pool).await.unwrap();
        let app = prefixd::api::create_test_router(state);
        let started = std::time::Instant::now();
        let task = tokio::spawn(async move {
            app.oneshot(creation_request("manual", "203.0.113.10", "slow-insert"))
                .await
                .unwrap()
        });
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                let sleeping: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND wait_event = 'PgSleep' AND query LIKE '%INSERT INTO mitigations%')")
                    .fetch_one(&context.pool).await.unwrap();
                if sleeping { break; }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }).await.expect("INSERT must reach server-side sleep before cancellation");
        if cancel {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        } else {
            assert_eq!(
                task.await.unwrap().status(),
                StatusCode::INTERNAL_SERVER_ERROR
            );
            assert!(started.elapsed() < std::time::Duration::from_secs(7));
        }
        let cleanup_started = std::time::Instant::now();
        assert_quota_cleanup(&context, &admission_pool, 0).await;
        eprintln!(
            "cancel={cancel}: caller elapsed {:?}, observed rollback cleanup {:?}",
            started.elapsed(),
            cleanup_started.elapsed()
        );
        assert_eq!(speaker.adds.load(SeqCst), 0);
        admission_pool.close().await;
    }
}

#[tokio::test]
async fn checked_timestamps_reject_http_lookahead_corruption_without_unwinding() {
    use prefixd::domain::{AttackEvent, AttackEventInput};
    let ctx = TestContext::new().await;
    let app = ctx.router().await;
    let now = chrono::Utc::now();
    for id in [1, 2] {
        let input: AttackEventInput = serde_json::from_value(serde_json::json!({
            "timestamp": now, "source": "timestamp-fixture", "victim_ip": "203.0.113.10", "vector": "udp_flood",
        })).unwrap();
        let mut event = AttackEvent::from_input(input);
        event.event_id = uuid::Uuid::from_u128(id);
        event.ingested_at = now;
        ctx.repo.insert_event(&event).await.unwrap();
    }
    let page = public_list_page(&app, "/v1/events?limit=1").await;
    assert_eq!(page["count"], 1);
    assert_eq!(page["has_more"], true);
    for bad in ["infinity", "-infinity", "280000-01-01 00:00:00+00"] {
        // The older ID is the second fetched row: corruption must not be hidden by lookahead.
        sqlx::query(
            "UPDATE events SET event_timestamp = $1::text::timestamptz WHERE event_id = $2",
        )
        .bind(bad)
        .bind(uuid::Uuid::from_u128(1))
        .execute(&ctx.pool)
        .await
        .unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/events?limit=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "{bad}"
        );
    }
    sqlx::query("UPDATE events SET event_timestamp = $1")
        .bind(now)
        .execute(&ctx.pool)
        .await
        .unwrap();
    assert_eq!(
        public_list_page(&app, "/v1/events?limit=1").await["count"],
        1
    );
    let response = app.oneshot(Request::builder().method("POST").uri("/v1/events")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"timestamp":"infinity","source":"test","victim_ip":"203.0.113.10","vector":"udp_flood"}"#)).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn checked_timestamp_scoped_reconciliation_returns_errors_and_recovers() {
    use prefixd::domain::{mitigation_rule, request_withdrawal};
    use prefixd::scheduler::ReconciliationLoop;
    let ctx = TestContext::new().await;
    let now = chrono::Utc::now();
    let pending = inventory_mitigation("192.0.2.201/32", "test-pop", now, MitigationStatus::Active);
    let mut corrupt =
        inventory_mitigation("192.0.2.202/32", "test-pop", now, MitigationStatus::Active);
    corrupt.expires_at = now - chrono::Duration::seconds(10);
    ctx.repo.insert_mitigation(&pending).await.unwrap();
    let speaker = std::sync::Arc::new(InventorySpeaker::new(false));
    speaker
        .inner
        .announce(&mitigation_rule(&pending))
        .await
        .unwrap();
    let mut settings = common::test_settings();
    settings.pop = "test-pop".into();
    settings.mode = prefixd::config::OperationMode::Enforced;
    let state = prefixd::AppState::new(
        settings,
        common::test_inventory(),
        common::test_playbooks(),
        ctx.repo.clone(),
        speaker.clone(),
        ".".into(),
    )
    .unwrap();
    let reconciler =
        ReconciliationLoop::new(ctx.repo.clone(), speaker.clone(), 30, false).with_app_state(state);
    // A valid production-scoped poll converges before administratively corrupting an owned row.
    reconciler.reconcile().await.unwrap();
    assert!(speaker.announcements.lock().unwrap().is_empty());
    assert!(speaker.withdrawals.lock().unwrap().is_empty());
    ctx.repo.insert_mitigation(&corrupt).await.unwrap();
    speaker
        .inner
        .announce(&mitigation_rule(&corrupt))
        .await
        .unwrap();
    let pending = ctx
        .repo
        .get_mitigation(pending.mitigation_id)
        .await
        .unwrap()
        .unwrap();
    let request = request_withdrawal(
        ctx.repo.as_ref(),
        &pending,
        false,
        "operator",
        "timestamp-fixture",
        "owned pending withdrawal".into(),
        true,
        None,
    )
    .await
    .unwrap();
    let before: Vec<_> = speaker
        .list_active()
        .await
        .unwrap()
        .iter()
        .map(|rule| rule.nlri_hash())
        .collect();
    sqlx::query("UPDATE mitigations SET created_at='infinity'::timestamptz WHERE mitigation_id=$1")
        .bind(corrupt.mitigation_id)
        .execute(&ctx.pool)
        .await
        .unwrap();
    let error = reconciler.reconcile().await.unwrap_err();
    assert!(format!("{error:#}").contains("supported finite range"));
    // Ownership validation fails closed for this POP; no write may bypass the corrupt inventory.
    assert_eq!(
        ctx.repo
            .get_mitigation(pending.mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        MitigationStatus::Active
    );
    let retained = ctx
        .repo
        .pending_withdrawals(Some("test-pop"))
        .await
        .unwrap();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].operation_id, request.operation_id);
    assert!(retained[0].completed_at.is_none());
    assert_eq!(
        speaker
            .list_active()
            .await
            .unwrap()
            .iter()
            .map(|rule| rule.nlri_hash())
            .collect::<Vec<_>>(),
        before
    );
    assert!(speaker.announcements.lock().unwrap().is_empty());
    assert!(speaker.withdrawals.lock().unwrap().is_empty());
    sqlx::query("UPDATE mitigations SET created_at=$1 WHERE mitigation_id=$2")
        .bind(corrupt.created_at)
        .bind(corrupt.mitigation_id)
        .execute(&ctx.pool)
        .await
        .unwrap();
    // The same loop completes the original pending operation and expiry after repair.
    reconciler.reconcile().await.unwrap();
    assert_eq!(
        ctx.repo
            .get_mitigation(pending.mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        MitigationStatus::Withdrawn
    );
    assert_eq!(
        ctx.repo
            .get_mitigation(corrupt.mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        MitigationStatus::Expired
    );
    assert!(speaker.list_active().await.unwrap().is_empty());
    assert!(speaker.announcements.lock().unwrap().is_empty());
    let deletes = speaker.withdrawals.lock().unwrap().clone();
    assert_eq!(deletes.len(), 2);
    assert!(deletes.contains(&mitigation_rule(&pending).nlri_hash()));
    assert!(deletes.contains(&mitigation_rule(&corrupt).nlri_hash()));
    let completed: Vec<(uuid::Uuid, bool)> = sqlx::query_as(
        "SELECT operation_id, completed_at IS NOT NULL FROM withdrawal_requests WHERE mitigation_id IN ($1, $2)")
        .bind(pending.mitigation_id).bind(corrupt.mitigation_id).fetch_all(&ctx.pool).await.unwrap();
    assert_eq!(completed.len(), 2);
    assert!(completed.iter().all(|(_, done)| *done));
    assert!(
        completed
            .iter()
            .any(|(operation, _)| *operation == request.operation_id)
    );
    let active = inventory_mitigation("192.0.2.203/32", "test-pop", now, MitigationStatus::Active);
    ctx.repo.insert_mitigation(&active).await.unwrap();
    reconciler.reconcile().await.unwrap();
    assert_eq!(speaker.list_active().await.unwrap().len(), 1);
    assert_eq!(speaker.announcements.lock().unwrap().len(), 1);
    sqlx::query(
        "UPDATE mitigations SET created_at='-infinity'::timestamptz WHERE mitigation_id=$1",
    )
    .bind(active.mitigation_id)
    .execute(&ctx.pool)
    .await
    .unwrap();
    let error = reconciler.reconcile().await.unwrap_err();
    assert!(format!("{error:#}").contains("supported finite range"));
    assert_eq!(speaker.list_active().await.unwrap().len(), 1);
    assert_eq!(speaker.announcements.lock().unwrap().len(), 1);
    assert_eq!(speaker.withdrawals.lock().unwrap().len(), 2);
    sqlx::query("UPDATE mitigations SET created_at=$1 WHERE mitigation_id=$2")
        .bind(active.created_at)
        .bind(active.mitigation_id)
        .execute(&ctx.pool)
        .await
        .unwrap();
    reconciler.reconcile().await.unwrap();
    assert_eq!(speaker.announcements.lock().unwrap().len(), 1);
    assert_eq!(speaker.withdrawals.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn checked_timestamp_cli_rows_fail_with_database_errors_after_valid_controls() {
    let ctx = TestContext::new().await;
    sqlx::query("INSERT INTO operators (username,password_hash,role) VALUES ('timestamp-cli','unused','admin')")
        .execute(&ctx.pool).await.unwrap();
    for (args, table, fields) in [
        (
            vec!["operators", "list"],
            "operators",
            vec!["created_at", "last_login_at"],
        ),
        (vec!["migrations"], "schema_migrations", vec!["applied_at"]),
    ] {
        for field in fields {
            for bad in ["infinity", "-infinity", "280000-01-01 00:00:00+00"] {
                let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_prefixdctl"))
                    .args(&args)
                    .env(
                        "DATABASE_URL",
                        &ctx.state.settings.storage.connection_string,
                    )
                    .output()
                    .await
                    .unwrap();
                assert!(
                    output.status.success(),
                    "valid CLI must work before corrupting {table}.{field}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                // Names come only from the fixed fixture cases above, never request input.
                let update = format!("UPDATE {table} SET {field} = $1::text::timestamptz");
                sqlx::query(&update)
                    .bind(bad)
                    .execute(&ctx.pool)
                    .await
                    .unwrap();
                let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_prefixdctl"))
                    .args(&args)
                    .env(
                        "DATABASE_URL",
                        &ctx.state.settings.storage.connection_string,
                    )
                    .output()
                    .await
                    .unwrap();
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(!output.status.success());
                assert!(stderr.contains("database error"), "{stderr}");
                assert!(stderr.contains("supported finite range"), "{stderr}");
                assert!(!stderr.contains("panicked"), "{stderr}");
                let restore = format!("UPDATE {table} SET {field} = NOW()");
                sqlx::query(&restore).execute(&ctx.pool).await.unwrap();
            }
        }
    }
}

#[tokio::test]
async fn test_authenticated_timeseries_duration_overflow_matches_postgres_bounds() {
    use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
    use chrono::{DateTime, Duration, Utc};
    use prefixd::{
        AppState,
        auth::create_auth_layer,
        bgp::MockAnnouncer,
        config::AuthMode,
        domain::{AttackEvent, AttackEventInput, OperatorRole},
    };
    use std::{collections::BTreeMap, sync::Arc};

    async fn fetch(
        app: &axum::Router,
        cookie: &str,
        metric: &str,
        range: &str,
        bucket: &str,
    ) -> serde_json::Value {
        let uri = format!("/v1/stats/timeseries?metric={metric}&range={range}&bucket={bucket}");
        let response = app
            .clone()
            .oneshot(
                Request::get(&uri)
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    let ctx = TestContext::new().await;
    let salt = SaltString::encode_b64(b"timeseries-duration-test").unwrap();
    let hash = Argon2::default()
        .hash_password(b"timeseries-test-password", &salt)
        .unwrap()
        .to_string();
    ctx.repo
        .create_operator("timeseries-reader", &hash, OperatorRole::Viewer, None)
        .await
        .unwrap();
    let mut settings = ctx.state.settings.clone();
    settings.http.auth.mode = AuthMode::Credentials;
    let state = AppState::new(
        settings,
        common::test_inventory(),
        common::test_playbooks(),
        ctx.repo.clone(),
        Arc::new(MockAnnouncer::new()),
        ".".into(),
    )
    .unwrap();
    let auth = create_auth_layer(
        ctx.pool.clone(),
        ctx.repo.clone(),
        AuthMode::Credentials,
        false,
    )
    .await;
    let app = prefixd::api::create_router(state, auth);
    for metric in ["events", "mitigations"] {
        let response = app
            .clone()
            .oneshot(
                Request::get(format!(
                    "/v1/stats/timeseries?metric={metric}&range=4294967295d&bucket=4294967295h"
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let response = app
        .clone()
        .oneshot(
            Request::post("/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"username":"timeseries-reader","password":"timeseries-test-password"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response
        .headers()
        .get(axum::http::header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();

    let current_hour = || {
        sqlx::query_scalar::<_, DateTime<Utc>>(
            "SELECT date_bin('1 hour'::interval, NOW(), '1970-01-01 00:00:00+00'::timestamptz)",
        )
        .fetch_one(&ctx.pool)
    };
    let anchor = current_hour().await.unwrap();
    let mut expected_events = BTreeMap::new();
    for (index, (age_hours, minute)) in [(2, 5), (30, 5), (30, 10), (100, 5), (192, 5)]
        .into_iter()
        .enumerate()
    {
        let bucket = anchor - Duration::hours(age_hours);
        let created_at = bucket + Duration::minutes(minute);
        let mut event = AttackEvent::from_input(
            serde_json::from_value::<AttackEventInput>(serde_json::json!({
                "event_id": format!("timeseries-duration-{index}"),
                "timestamp": created_at,
                "source": "timeseries-test",
                "victim_ip": "203.0.113.200",
                "vector": "udp_flood",
            }))
            .unwrap(),
        );
        event.ingested_at = created_at;
        ctx.repo.insert_event(&event).await.unwrap();
        if age_hours < 168 {
            *expected_events.entry(bucket).or_insert(0_i64) += 1;
        }
    }
    let mut expected_mitigations = BTreeMap::new();
    for (index, (age_hours, minute)) in [(3, 5), (50, 5), (50, 10), (192, 5)]
        .into_iter()
        .enumerate()
    {
        let bucket = anchor - Duration::hours(age_hours);
        let created_at = bucket + Duration::minutes(minute);
        let mut mitigation = inventory_mitigation(
            &format!("203.0.113.{}/32", 150 + index),
            "test1",
            created_at,
            MitigationStatus::Expired,
        );
        mitigation.expires_at = created_at + Duration::hours(1);
        ctx.repo.insert_mitigation(&mitigation).await.unwrap();
        if age_hours < 168 {
            *expected_mitigations.entry(bucket).or_insert(0_i64) += 1;
        }
    }
    assert_eq!(expected_events.values().sum::<i64>(), 4);
    assert_eq!(expected_mitigations.values().sum::<i64>(), 3);

    let mut mitigation_buckets = None;
    for (metric, expected) in [
        ("events", &expected_events),
        ("mitigations", &expected_mitigations),
    ] {
        // This interval has one stable epoch bucket; equality cannot race an hourly boundary.
        let reference = fetch(&app, &cookie, metric, "168h", "4294967295m").await;
        assert_eq!(reference["metric"], metric);
        assert_eq!(
            reference["buckets"],
            serde_json::json!([{
                "bucket": DateTime::<Utc>::UNIX_EPOCH,
                "count": expected.values().sum::<i64>(),
            }])
        );
        if metric == "mitigations" {
            mitigation_buckets = Some(reference["buckets"].clone());
        }
        for range in ["178956971d", "536870912d", "4294967295d"] {
            let actual = fetch(&app, &cookie, metric, range, "4294967295m").await;
            assert_eq!(actual["metric"], metric);
            assert_eq!(
                actual["buckets"], reference["buckets"],
                "metric={metric} range={range}"
            );
        }
        for bucket in ["71582789h", "1073741824h", "4294967295h"] {
            let actual = fetch(&app, &cookie, metric, "168h", bucket).await;
            assert_eq!(actual["metric"], metric);
            assert_eq!(
                actual["buckets"], reference["buckets"],
                "metric={metric} bucket={bucket}"
            );
        }
        for range in ["168h", "178956971d", "536870912d"] {
            let before = current_hour().await.unwrap();
            let series = fetch(&app, &cookie, metric, range, "60m").await;
            let after = current_hour().await.unwrap();
            let buckets = series["buckets"].as_array().unwrap();
            assert_eq!(buckets.len(), 169);
            let last: DateTime<Utc> = buckets.last().unwrap()["bucket"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
            assert!(
                before <= last && last <= after,
                "DB time must bracket the last bucket"
            );
            let first = last - Duration::hours(168);
            let mut remaining = (*expected).clone();
            for (index, row) in buckets.iter().enumerate() {
                let timestamp: DateTime<Utc> = row["bucket"].as_str().unwrap().parse().unwrap();
                assert_eq!(
                    timestamp,
                    first + Duration::hours(i64::try_from(index).unwrap())
                );
                assert_eq!(
                    row["count"].as_i64().unwrap(),
                    remaining.remove(&timestamp).unwrap_or(0),
                    "metric={metric} range={range} bucket={timestamp}"
                );
            }
            assert!(
                remaining.is_empty(),
                "all seeded in-range buckets must be present"
            );
        }
    }
    let unknown = fetch(&app, &cookie, "unknown", "178956971d", "71582789h").await;
    assert_eq!(unknown["metric"], "unknown");
    assert_eq!(unknown["buckets"], mitigation_buckets.unwrap());
}

#[tokio::test]
async fn duplicate_acknowledgements_count_entries_and_update_each_postgres_row_once() {
    use prefixd::config::AuthMode;
    use std::sync::{Arc, atomic::Ordering::SeqCst};
    use uuid::Uuid;

    let context = TestContext::new().await;
    let speaker = Arc::new(CreationSpeaker::new(context.repo.clone(), 0));
    let mut state = creation_state(&context, speaker.clone(), false);
    let cached = Arc::get_mut(&mut state).unwrap();
    cached.settings.http.auth.mode = AuthMode::Bearer;
    cached.bearer_token = Some("duplicate-ack-token".into());
    let app = prefixd::api::create_test_router(state);
    let mut targets = Vec::new();
    for ip in ["203.0.113.10", "203.0.113.11", "203.0.113.12"] {
        let mut request = creation_request("manual", ip, "duplicate-ack-seed");
        request.headers_mut().insert(
            "authorization",
            axum::http::HeaderValue::from_static("Bearer duplicate-ack-token"),
        );
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let json = creation_json(response).await;
        targets.push(Uuid::parse_str(json["mitigation_id"].as_str().unwrap()).unwrap());
    }
    // Count actual UPDATE executions in this fixture's disposable database, across pool connections.
    sqlx::raw_sql(
        r#"
        CREATE TABLE ack_update_receipts (mitigation_id UUID NOT NULL);
        CREATE FUNCTION record_ack_update() RETURNS TRIGGER LANGUAGE plpgsql AS $$
        BEGIN
            INSERT INTO ack_update_receipts (mitigation_id) VALUES (NEW.mitigation_id);
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER capture_ack_update AFTER UPDATE OF acknowledged_at, acknowledged_by
            ON mitigations FOR EACH ROW EXECUTE FUNCTION record_ack_update();
    "#,
    )
    .execute(&context.pool)
    .await
    .unwrap();
    let original_rules = serde_json::to_value(speaker.list_active().await.unwrap()).unwrap();
    assert_eq!(original_rules.as_array().unwrap().len(), 3);
    assert_eq!(speaker.adds.load(SeqCst), 3);
    let params = prefixd::db::ListParams {
        limit: 10,
        ..Default::default()
    };
    let original_audit =
        serde_json::to_value(context.repo.list_audit(&params).await.unwrap()).unwrap();
    let mut expected_updates = [0_i64; 3];
    for (ids, succeeded, failed, changed, statuses) in [
        (
            vec![targets[0], targets[0], Uuid::nil()],
            2,
            1,
            Some(0),
            vec!["acknowledged", "acknowledged", "error"],
        ),
        (
            vec![targets[0], targets[0]],
            0,
            2,
            None,
            vec!["error", "error"],
        ),
        (vec![targets[1]], 1, 0, Some(1), vec!["acknowledged"]),
        (
            vec![targets[0], targets[1]],
            0,
            2,
            None,
            vec!["error", "error"],
        ),
    ] {
        let mut before = Vec::new();
        for id in &targets {
            before.push(context.repo.get_mitigation(*id).await.unwrap().unwrap());
        }
        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/mitigations/acknowledge")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer duplicate-ack-token")
                    .body(Body::from(
                        serde_json::json!({"mitigation_ids":ids, "operator_id":"forged-actor"})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = creation_json(response).await;
        assert_eq!(
            json["acknowledged"], succeeded,
            "acknowledged counter for {ids:?}"
        );
        assert_eq!(json["failed"], failed);
        assert_eq!(succeeded + failed, ids.len());
        let results = json["results"].as_array().unwrap();
        assert_eq!(results.len(), ids.len());
        for ((result, id), status) in results.iter().zip(&ids).zip(statuses) {
            assert_eq!(result["mitigation_id"], id.to_string());
            assert_eq!(result["status"], status);
            if status == "error" {
                assert_eq!(
                    result["error"],
                    "not found, already acknowledged, or rejected"
                );
            } else {
                assert!(result.get("error").is_none());
            }
        }
        if let Some(index) = changed {
            expected_updates[index] += 1;
        }
        for (index, previous) in before.iter().enumerate() {
            let row = context
                .repo
                .get_mitigation(previous.mitigation_id)
                .await
                .unwrap()
                .unwrap();
            let mut expected = previous.clone();
            if changed == Some(index) {
                assert!(previous.acknowledged_at.is_none());
                assert!(row.acknowledged_at.is_some());
                expected.acknowledged_at = row.acknowledged_at;
                expected.acknowledged_by = Some("bearer-token".into());
            }
            assert_eq!(
                serde_json::to_value(row).unwrap(),
                serde_json::to_value(expected).unwrap()
            );
            let updates: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM ack_update_receipts WHERE mitigation_id = $1",
            )
            .bind(previous.mitigation_id)
            .fetch_one(&context.pool)
            .await
            .unwrap();
            assert_eq!(
                updates, expected_updates[index],
                "one actual UPDATE per newly acknowledged row"
            );
        }
        assert_eq!(speaker.adds.load(SeqCst), 3);
        assert_eq!(speaker.deletes.load(SeqCst), 0);
        assert_eq!(
            serde_json::to_value(speaker.list_active().await.unwrap()).unwrap(),
            original_rules
        );
        assert_eq!(
            serde_json::to_value(context.repo.list_audit(&params).await.unwrap()).unwrap(),
            original_audit
        );
    }
}

async fn assert_history_and_incident_ids(app: &axum::Router, uris: &[String], ids: &[uuid::Uuid]) {
    for uri in uris {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "uri={uri}");
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        if uri.contains("/history") {
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let mut actual: Vec<uuid::Uuid> = value["mitigations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row["mitigation_id"].as_str().unwrap().parse().unwrap())
                .collect();
            let mut expected = ids.to_vec();
            actual.sort();
            expected.sort();
            assert_eq!(actual, expected);
        } else {
            let markdown = String::from_utf8(bytes.to_vec()).unwrap();
            assert!(markdown.contains(&format!("| Total Mitigations | {} |", ids.len())));
            for id in ids {
                assert!(
                    markdown.contains(&id.to_string()),
                    "missing mitigation {id} in {uri}"
                );
            }
        }
    }
}

#[tokio::test]
async fn test_ip_history_and_incident_fail_on_selected_corrupt_mitigations() {
    let context = TestContext::new().await;
    let app = context.router().await;
    let ip = "203.0.113.10";
    let created_at = chrono::Utc::now() - chrono::Duration::days(1);
    let mut ids = Vec::new();
    // Terminal rows allow repeated historical scopes. Distinct timestamps make
    // the unchanged SQL limit unambiguous without adding a new ordering contract.
    for offset in 0..100 {
        let mitigation = inventory_mitigation(
            "203.0.113.10/32",
            "test-pop",
            created_at + chrono::Duration::seconds(offset),
            MitigationStatus::Expired,
        );
        ids.push(mitigation.mitigation_id);
        context.repo.insert_mitigation(&mitigation).await.unwrap();
    }
    let outside_limit = inventory_mitigation(
        "203.0.113.10/32",
        "test-pop",
        created_at - chrono::Duration::seconds(1),
        MitigationStatus::Expired,
    );
    let foreign_ip = inventory_mitigation(
        "203.0.113.99/32",
        "test-pop",
        created_at + chrono::Duration::seconds(101),
        MitigationStatus::Expired,
    );
    for mitigation in [&outside_limit, &foreign_ip] {
        context.repo.insert_mitigation(mitigation).await.unwrap();
    }
    let uris = [
        format!("/v1/ip/{ip}/history?limit=100"),
        format!("/v1/reports/incident?ip={ip}"),
        format!("/v1/reports/incident?mitigation_id={}", ids[99]),
    ];
    // Valid controls include every selected ID in both public response formats.
    assert_history_and_incident_ids(&app, &uris, &ids).await;

    // The oldest selected row is still eligible; silently dropping it would
    // manufacture a successful partial history/report.
    let selected = ids[0];
    let original: (String, String, String) = sqlx::query_as(
        "SELECT match_json, action_params_json, status FROM mitigations WHERE mitigation_id = $1",
    )
    .bind(selected)
    .fetch_one(&context.pool)
    .await
    .unwrap();
    let original_row: serde_json::Value =
        sqlx::query_scalar("SELECT to_jsonb(m) FROM mitigations m WHERE mitigation_id = $1")
            .bind(selected)
            .fetch_one(&context.pool)
            .await
            .unwrap();
    for (kind, corruption) in [
        (
            "match JSON",
            "UPDATE mitigations SET match_json = '{' WHERE mitigation_id = $1",
        ),
        (
            "action JSON",
            "UPDATE mitigations SET action_params_json = '{' WHERE mitigation_id = $1",
        ),
        (
            "status",
            "UPDATE mitigations SET status = 'unknown' WHERE mitigation_id = $1",
        ),
    ] {
        sqlx::query(corruption)
            .bind(selected)
            .execute(&context.pool)
            .await
            .unwrap();
        for uri in &uris {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "corrupt {kind}, uri={uri}"
            );
        }
        sqlx::query("UPDATE mitigations SET match_json = $2, action_params_json = $3, status = $4 WHERE mitigation_id = $1")
            .bind(selected).bind(&original.0).bind(&original.1).bind(&original.2)
            .execute(&context.pool).await.unwrap();
        let restored: serde_json::Value =
            sqlx::query_scalar("SELECT to_jsonb(m) FROM mitigations m WHERE mitigation_id = $1")
                .bind(selected)
                .fetch_one(&context.pool)
                .await
                .unwrap();
        assert_eq!(restored, original_row, "exact restoration after {kind}");
        assert_history_and_incident_ids(&app, &uris, &ids).await;
    }

    for excluded in [&foreign_ip, &outside_limit] {
        sqlx::query("UPDATE mitigations SET match_json = '{' WHERE mitigation_id = $1")
            .bind(excluded.mitigation_id)
            .execute(&context.pool)
            .await
            .unwrap();
        assert_history_and_incident_ids(&app, &uris, &ids).await;
    }
    // Broadening only the requested history limit makes the same corrupt older
    // row eligible. The fixed incident-report limit remains 100.
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/ip/{ip}/history?limit=101"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
