mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use prefixd::{
    AppState,
    bgp::{
        FlowSpecAnnouncer, FlowSpecReader, FlowSpecWriter, MockAnnouncer, PeerObserver, PeerStatus,
    },
    config::{BgpMode, OperationMode, Settings},
    db::{RepositoryTrait, init_postgres_pool},
    domain::{
        ActionParams, ActionType, AttackEvent, AttackVector, FlowSpecRule, MatchCriteria,
        Mitigation, MitigationIntent, MitigationStatus, SpeakerTarget, VerifiedSpeakerBinding,
        WithdrawalRequest, execute_withdrawal, request_withdrawal,
    },
    error::Result,
    scheduler::ReconciliationLoop,
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering::SeqCst},
};
use tower::ServiceExt;
use uuid::Uuid;

fn settings(pop: &str, endpoint: &str) -> Settings {
    let mut settings = common::test_settings();
    settings.pop = pop.into();
    settings.mode = OperationMode::Enforced;
    settings.bgp.mode = BgpMode::Gobgp;
    settings.bgp.gobgp_grpc = endpoint.into();
    settings
}

#[tokio::test]
async fn external_repository_can_read_identity_and_issue_a_committed_binding() {
    let ctx = common::TestContext::new().await;
    let target =
        SpeakerTarget::from_config(&settings("external", "Speaker.EXAMPLE:80").bgp).unwrap();
    assert_eq!(target.backend(), "gobgp");
    assert_eq!(target.endpoint(), "http://speaker.example/");
    assert_eq!(target.namespace(), "GLOBAL");

    // This integration test is outside the library crate. The built-in issuer
    // commits registration first; an external issuer can then read and validate
    // the same stored identity using only the public API before issuing proof.
    let registered = ctx
        .repo
        .register_speaker_target("external", &target, false)
        .await
        .unwrap();
    let target_id: Uuid = sqlx::query_scalar(
        "SELECT t.target_id FROM speaker_targets t JOIN speaker_pop_bindings b USING (target_id)
         WHERE b.pop = $1 AND t.backend = $2 AND t.endpoint = $3 AND t.routing_namespace = $4",
    )
    .bind("external")
    .bind(target.backend())
    .bind(target.endpoint())
    .bind(target.namespace())
    .fetch_one(&ctx.pool)
    .await
    .unwrap();
    let issued = VerifiedSpeakerBinding::new("external".into(), target_id, target.clone());
    assert_eq!(issued.target_id(), registered.target_id());
    assert_eq!(issued.pop(), "external");
    issued.validate("external", &target, "gobgp").unwrap();
    assert!(issued.validate("foreign", &target, "gobgp").is_err());
}

fn mitigation(pop: &str, ip: &str) -> Mitigation {
    let mut mitigation = Mitigation::from_intent(
        MitigationIntent {
            event_id: Uuid::new_v4(),
            customer_id: None,
            service_id: None,
            pop: pop.into(),
            match_criteria: MatchCriteria {
                dst_prefix: format!("{ip}/32"),
                protocol: Some(17),
                dst_ports: vec![53],
                ..Default::default()
            },
            action_type: ActionType::Discard,
            action_params: ActionParams::default(),
            ttl_seconds: 600,
            reason: "ownership test".into(),
        },
        ip.into(),
        AttackVector::UdpFlood,
    );
    mitigation.activate();
    // PostgreSQL stores microseconds; keep the fixture's revision identical to its row.
    mitigation.updated_at =
        chrono::DateTime::from_timestamp_micros(mitigation.updated_at.timestamp_micros()).unwrap();
    mitigation
}

fn event(external_id: &str) -> AttackEvent {
    AttackEvent::from_input(serde_json::from_value(json!({
        "event_id": external_id, "timestamp": "2026-01-17T10:00:00Z", "source": "ownership-test",
        "victim_ip": "203.0.113.10", "vector": "udp_flood", "confidence": 0.99,
    })).unwrap())
}

#[derive(Default)]
struct CountingSpeaker {
    inner: MockAnnouncer,
    adds: AtomicUsize,
    deletes: AtomicUsize,
    reads: AtomicUsize,
    peers: AtomicUsize,
}

impl CountingSpeaker {
    fn calls(&self) -> usize {
        self.adds.load(SeqCst)
            + self.deletes.load(SeqCst)
            + self.reads.load(SeqCst)
            + self.peers.load(SeqCst)
    }
}
impl FlowSpecAnnouncer for CountingSpeaker {
    fn backend(&self) -> &'static str {
        "gobgp"
    }
    fn reader(&self) -> Option<&dyn FlowSpecReader> {
        Some(self)
    }
    fn peer_observer(&self) -> Option<&dyn PeerObserver> {
        Some(self)
    }
}
#[async_trait::async_trait]
impl FlowSpecWriter for CountingSpeaker {
    async fn announce(&self, rule: &FlowSpecRule) -> Result<()> {
        self.adds.fetch_add(1, SeqCst);
        self.inner.announce(rule).await
    }
    async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()> {
        self.deletes.fetch_add(1, SeqCst);
        self.inner.withdraw(rule).await
    }
}
#[async_trait::async_trait]
impl FlowSpecReader for CountingSpeaker {
    async fn list_active(&self) -> Result<Vec<FlowSpecRule>> {
        self.reads.fetch_add(1, SeqCst);
        self.inner.list_active().await
    }
}
#[async_trait::async_trait]
impl PeerObserver for CountingSpeaker {
    async fn session_status(&self) -> Result<Vec<PeerStatus>> {
        self.peers.fetch_add(1, SeqCst);
        Ok(vec![])
    }
}

async fn queue_snapshot(pool: &sqlx::PgPool, pop: &str) -> Vec<Value> {
    sqlx::query_scalar(
        "SELECT to_jsonb(w) FROM withdrawal_requests w WHERE pop = $1 ORDER BY operation_id",
    )
    .bind(pop)
    .fetch_all(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn target_registration_serializes_aliases_and_rejects_foreign_assignments() {
    let ctx = common::TestContext::new().await;
    // Events and safelist data alone do not imply prior speaker obligations.
    ctx.repo
        .insert_event(&event("bootstrap-only"))
        .await
        .unwrap();
    ctx.repo
        .insert_safelist("198.51.100.1/32", "test", None)
        .await
        .unwrap();
    let mut first = settings("pop-a", "Speaker.EXAMPLE:50051");
    first.bgp.mode = BgpMode::Sidecar;
    let target = SpeakerTarget::from_config(&first.bgp).unwrap();
    let alias = SpeakerTarget::from_config(&settings("pop-a", "http://speaker.example:50051/").bgp)
        .unwrap();
    let (one, two) = tokio::join!(
        ctx.repo.register_speaker_target("pop-a", &target, false),
        ctx.repo.register_speaker_target("pop-a", &alias, false)
    );
    let one = one.unwrap();
    assert_eq!(one.target_id(), two.unwrap().target_id());
    for adopt in [false, true] {
        assert!(
            ctx.repo
                .register_speaker_target("pop-b", &target, adopt)
                .await
                .is_err()
        );
        let other =
            SpeakerTarget::from_config(&settings("pop-a", "http://other.example:50051").bgp)
                .unwrap();
        assert!(
            ctx.repo
                .register_speaker_target("pop-a", &other, adopt)
                .await
                .is_err()
        );
    }
    let second =
        SpeakerTarget::from_config(&settings("pop-b", "http://other.example:50051").bgp).unwrap();
    let two = ctx
        .repo
        .register_speaker_target("pop-b", &second, false)
        .await
        .unwrap();
    assert_ne!(one.target_id(), two.target_id());
    let race =
        SpeakerTarget::from_config(&settings("race-a", "http://race.example:50051").bgp).unwrap();
    let (a, b) = tokio::join!(
        ctx.repo.register_speaker_target("race-a", &race, false),
        ctx.repo.register_speaker_target("race-b", &race, false)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);

    let mut secure = settings("secure", "unused");
    secure.bgp.mode = BgpMode::Rustbgpd;
    secure.bgp.rustbgpd = Some(prefixd::config::RustBgpdConfig {
        endpoint: "https://secure.example:50051".into(),
        bearer_token_env: "OLD_TOKEN".into(),
        ca_cert_path: Some("/old.pem".into()),
        client_cert_path: Some("/old-client.pem".into()),
        client_key_path: Some("/old-key.pem".into()),
    });
    let old = ctx
        .repo
        .register_speaker_target(
            "secure",
            &SpeakerTarget::from_config(&secure.bgp).unwrap(),
            false,
        )
        .await
        .unwrap();
    secure.bgp.rustbgpd.as_mut().unwrap().bearer_token_env = "NEW_TOKEN".into();
    secure.bgp.rustbgpd.as_mut().unwrap().ca_cert_path = Some("/new.pem".into());
    secure.bgp.rustbgpd.as_mut().unwrap().client_cert_path = Some("/new-client.pem".into());
    secure.bgp.rustbgpd.as_mut().unwrap().client_key_path = Some("/new-key.pem".into());
    secure.mode = OperationMode::DryRun;
    let rotated = ctx
        .repo
        .register_speaker_target(
            "secure",
            &SpeakerTarget::from_config(&secure.bgp).unwrap(),
            false,
        )
        .await
        .unwrap();
    assert_eq!(old.target_id(), rotated.target_id());
    let identities: String = sqlx::query_scalar("SELECT json_agg(t)::text FROM speaker_targets t")
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
    for secret in ["OLD_TOKEN", "NEW_TOKEN", "/old.pem", "/new.pem"] {
        assert!(!identities.contains(secret));
    }
    assert!(
        sqlx::query(
            "UPDATE speaker_targets SET endpoint = 'http://replacement/' WHERE target_id = $1"
        )
        .bind(one.target_id())
        .execute(&ctx.pool)
        .await
        .is_err()
    );
}

#[tokio::test]
async fn legacy_adoption_preserves_requests_and_survives_repeated_migrations() {
    let ctx = common::TestContext::new().await;
    let first = mitigation("legacy", "203.0.113.10");
    let second = mitigation("legacy", "203.0.113.11");
    for row in [&first, &second] {
        ctx.repo.insert_mitigation(row).await.unwrap();
    }
    request_withdrawal(
        ctx.repo.as_ref(),
        &first,
        true,
        "system",
        "scheduler",
        "TTL original".into(),
        true,
        None,
    )
    .await
    .unwrap();
    let completed = request_withdrawal(
        ctx.repo.as_ref(),
        &second,
        false,
        "operator",
        "original-actor",
        "original reason".into(),
        false,
        None,
    )
    .await
    .unwrap();
    execute_withdrawal(
        ctx.repo.as_ref(),
        &MockAnnouncer::new(),
        true,
        &completed,
        None,
    )
    .await
    .unwrap();
    sqlx::query("INSERT INTO flowspec_announcements (announcement_id, mitigation_id, pop, peer_name, peer_address, nlri_hash, nlri_json, action_json, status) VALUES ($1, $2, 'legacy', 'router', '192.0.2.1', 'old-key', '{}', '{}', 'pending')")
        .bind(Uuid::new_v4()).bind(first.mitigation_id).execute(&ctx.pool).await.unwrap();
    let before = queue_snapshot(&ctx.pool, "legacy").await;
    let announcements_before: Vec<Value> =
        sqlx::query_scalar("SELECT to_jsonb(a) FROM flowspec_announcements a")
            .fetch_all(&ctx.pool)
            .await
            .unwrap();
    let target =
        SpeakerTarget::from_config(&settings("legacy", "http://original.example:50051").bgp)
            .unwrap();
    assert!(
        ctx.repo
            .register_speaker_target("legacy", &target, false)
            .await
            .unwrap_err()
            .to_string()
            .contains("--adopt-legacy-speaker")
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM speaker_targets")
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
    assert_eq!(
        count, 0,
        "failed adoption must roll back target creation too"
    );
    let migrated = init_postgres_pool(&ctx.state.settings.storage.connection_string)
        .await
        .unwrap();
    assert_eq!(
        queue_snapshot(&migrated, "legacy").await,
        before,
        "migration replay must not adopt"
    );
    let adopted = ctx
        .repo
        .register_speaker_target("legacy", &target, true)
        .await
        .unwrap();
    let after = queue_snapshot(&ctx.pool, "legacy").await;
    for (original, bound) in before.iter().zip(&after) {
        let mut bound = bound.clone();
        assert_eq!(bound["target_id"], adopted.target_id().to_string());
        bound["target_id"] = Value::Null;
        assert_eq!(
            &bound, original,
            "only the previously NULL target may change"
        );
    }
    let announcements_after: Vec<Value> =
        sqlx::query_scalar("SELECT to_jsonb(a) FROM flowspec_announcements a")
            .fetch_all(&ctx.pool)
            .await
            .unwrap();
    assert_eq!(
        announcements_after, announcements_before,
        "adoption is not an announcement acknowledgement"
    );
    sqlx::raw_sql(include_str!("../migrations/001_initial.sql"))
        .execute(&ctx.pool)
        .await
        .unwrap();
    sqlx::raw_sql(include_str!("../migrations/013_withdrawal_requests.sql"))
        .execute(&ctx.pool)
        .await
        .unwrap();
    let restarted = init_postgres_pool(&ctx.state.settings.storage.connection_string)
        .await
        .unwrap();
    let repo = prefixd::db::Repository::new(restarted);
    for adopt in [false, true, true] {
        assert_eq!(
            repo.register_speaker_target("legacy", &target, adopt)
                .await
                .unwrap()
                .target_id(),
            adopted.target_id()
        );
    }
    assert_eq!(queue_snapshot(&ctx.pool, "legacy").await, after);
    let audits: Vec<String> = sqlx::query_scalar(
        "SELECT details_json FROM audit_log WHERE action = 'adopt_speaker_target'",
    )
    .fetch_all(&ctx.pool)
    .await
    .unwrap();
    assert_eq!(audits.len(), 1);
    assert!(!audits[0].contains("original.example"));
    assert_eq!(
        ctx.repo
            .get_mitigation(first.mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        MitigationStatus::Active
    );
    assert_eq!(
        ctx.repo
            .get_mitigation(second.mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        MitigationStatus::Withdrawn
    );

    // Even historical mitigations and announcement-only POP records need adoption.
    let mut historical = mitigation("history", "203.0.113.12");
    historical.withdraw(Some("old".into()));
    ctx.repo.insert_mitigation(&historical).await.unwrap();
    let history =
        SpeakerTarget::from_config(&settings("history", "http://history.example:50051").bgp)
            .unwrap();
    assert!(
        repo.register_speaker_target("history", &history, false)
            .await
            .is_err()
    );
    sqlx::query("UPDATE flowspec_announcements SET pop = 'announcement-only'")
        .execute(&ctx.pool)
        .await
        .unwrap();
    let orphan = SpeakerTarget::from_config(
        &settings("announcement-only", "http://announcement.example:50051").bgp,
    )
    .unwrap();
    assert!(
        repo.register_speaker_target("announcement-only", &orphan, false)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn bound_lifecycle_is_scoped_to_each_pop_and_reload_does_not_retarget() {
    let ctx = common::TestContext::new().await;
    let a_config = settings("pop-a", "http://a.example:50051");
    let b_config = settings("pop-b", "http://b.example:50051");
    let a_binding = ctx
        .repo
        .register_speaker_target(
            "pop-a",
            &SpeakerTarget::from_config(&a_config.bgp).unwrap(),
            false,
        )
        .await
        .unwrap();
    let b_binding = ctx
        .repo
        .register_speaker_target(
            "pop-b",
            &SpeakerTarget::from_config(&b_config.bgp).unwrap(),
            false,
        )
        .await
        .unwrap();
    let a = Arc::new(CountingSpeaker::default());
    let b = Arc::new(CountingSpeaker::default());
    let config_dir = tempfile::tempdir().unwrap();
    let a_state = AppState::new(
        a_config.clone(),
        common::test_inventory(),
        common::test_playbooks(),
        ctx.repo.clone(),
        a.clone(),
        config_dir.path().into(),
    )
    .unwrap()
    .with_speaker_binding(a_binding.clone())
    .unwrap();
    let b_state = AppState::new(
        b_config,
        common::test_inventory(),
        common::test_playbooks(),
        ctx.repo.clone(),
        b.clone(),
        ".".into(),
    )
    .unwrap()
    .with_speaker_binding(b_binding.clone())
    .unwrap();
    let mut expired_a = mitigation("pop-a", "203.0.113.10");
    let mut expired_b = mitigation("pop-b", "203.0.113.10");
    expired_a.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
    expired_b.expires_at = expired_a.expires_at;
    let active_a = mitigation("pop-a", "203.0.113.11");
    let active_b = mitigation("pop-b", "203.0.113.12");
    let pending_a = mitigation("pop-a", "203.0.113.13");
    let pending_b = mitigation("pop-b", "203.0.113.14");
    for row in [
        &expired_a, &expired_b, &active_a, &active_b, &pending_a, &pending_b,
    ] {
        ctx.repo.insert_mitigation(row).await.unwrap();
    }
    for (row, binding) in [(&pending_a, &a_binding), (&pending_b, &b_binding)] {
        let request = request_withdrawal(
            ctx.repo.as_ref(),
            row,
            false,
            "operator",
            "owner",
            "cleanup".into(),
            true,
            Some(binding),
        )
        .await
        .unwrap();
        assert_eq!(request.target_id, Some(binding.target_id()));
    }
    ReconciliationLoop::new(ctx.repo.clone(), a.clone(), 30, false)
        .with_app_state(a_state.clone())
        .reconcile()
        .await
        .unwrap();
    assert_eq!(a.adds.load(SeqCst), 1);
    assert_eq!(a.deletes.load(SeqCst), 2);
    assert_eq!(b.calls(), 0);
    assert_eq!(
        ctx.repo
            .get_mitigation(expired_a.mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        MitigationStatus::Expired
    );
    assert_eq!(
        ctx.repo
            .get_mitigation(pending_a.mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        MitigationStatus::Withdrawn
    );
    assert_eq!(
        ctx.repo
            .get_mitigation(expired_b.mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        MitigationStatus::Active
    );
    assert_eq!(
        ctx.repo
            .pending_withdrawals(Some("pop-b"))
            .await
            .unwrap()
            .len(),
        1
    );
    ReconciliationLoop::new(ctx.repo.clone(), b.clone(), 30, false)
        .with_app_state(b_state)
        .reconcile()
        .await
        .unwrap();
    assert_eq!(b.adds.load(SeqCst), 1);
    assert_eq!(b.deletes.load(SeqCst), 2);
    assert!(ctx.repo.pending_withdrawals(None).await.unwrap().is_empty());

    let mut edited = settings("pop-b", "http://changed.example:50051");
    edited.mode = OperationMode::DryRun;
    common::write_yaml(
        config_dir.path(),
        "prefixd.yaml",
        &serde_saphyr::to_string(&edited).unwrap(),
    );
    a_state.reload_config().await.unwrap();
    assert_eq!(a_state.settings.pop, "pop-a");
    assert_eq!(a_state.settings.bgp.gobgp_grpc, a_config.bgp.gobgp_grpc);
    assert_eq!(a_state.settings.mode, OperationMode::Enforced);
    assert_eq!(
        a_state
            .verified_speaker_binding()
            .unwrap()
            .unwrap()
            .target_id(),
        a_binding.target_id()
    );
    let reloaded = Settings::load(config_dir.path().join("prefixd.yaml")).unwrap();
    assert!(
        ctx.repo
            .register_speaker_target(
                &reloaded.pop,
                &SpeakerTarget::from_config(&reloaded.bgp).unwrap(),
                false
            )
            .await
            .is_err()
    );
    for path in ["/v1/config/settings", "/v1/health/detail"] {
        let response = prefixd::api::create_test_router(a_state.clone())
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        for private in [
            "a.example",
            "changed.example",
            "routing_namespace",
            "target_id",
        ] {
            assert!(!body.contains(private));
        }
    }
}

async fn assert_lifecycle_rejected(
    state: Arc<AppState>,
    speaker: &CountingSpeaker,
    mitigation: &Mitigation,
) {
    let app = prefixd::api::create_test_router(state.clone());
    let mut notifications = state.ws_broadcast.subscribe();
    for (path, body) in [
        (
            "/v1/events".into(),
            json!({"event_id":"new-ban", "timestamp":"2026-01-17T10:00:00Z", "source":"ownership-test", "victim_ip":"203.0.113.11", "vector":"udp_flood", "confidence":0.99}),
        ),
        (
            "/v1/events".into(),
            json!({"event_id":"original-ban", "timestamp":"2026-01-17T10:00:00Z", "source":"ownership-test", "victim_ip":"203.0.113.10", "vector":"udp_flood", "action":"unban"}),
        ),
        (
            "/v1/mitigations".into(),
            json!({"reason":"manual test", "victim_ip":"203.0.113.11", "protocol":"udp", "dst_ports":[53], "action":"discard", "ttl_seconds":120}),
        ),
        (
            format!("/v1/mitigations/{}/withdraw", mitigation.mitigation_id),
            json!({"reason":"withdraw test"}),
        ),
        (
            "/v1/mitigations/withdraw".into(),
            json!({"reason":"bulk test", "mitigation_ids":[mitigation.mitigation_id]}),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&path)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT, "{path}");
    }
    assert!(
        ReconciliationLoop::new(state.repo.clone(), state.announcer.clone(), 30, false)
            .with_app_state(state)
            .reconcile()
            .await
            .is_err()
    );
    assert_eq!(
        speaker.calls(),
        0,
        "no mutation, inventory or peer RPC is authorized"
    );
    assert!(notifications.try_recv().is_err());
}

#[tokio::test]
async fn real_backend_without_matching_verified_state_never_reaches_rpc() {
    let ctx = common::TestContext::new().await;
    let config = settings("guard", "http://private-target.example:50051");
    let speaker = Arc::new(CountingSpeaker::default());
    let original = event("original-ban");
    let mut row = mitigation("guard", "203.0.113.10");
    row.triggering_event_id = original.event_id;
    row.last_event_id = original.event_id;
    row.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
    ctx.repo.insert_event(&original).await.unwrap();
    ctx.repo.insert_mitigation(&row).await.unwrap();
    request_withdrawal(
        ctx.repo.as_ref(),
        &row,
        true,
        "system",
        "scheduler",
        "pending legacy".into(),
        true,
        None,
    )
    .await
    .unwrap();
    let state = AppState::new(
        config.clone(),
        common::test_inventory(),
        common::test_playbooks(),
        ctx.repo.clone(),
        speaker.clone(),
        ".".into(),
    )
    .unwrap();
    assert_lifecycle_rejected(state, &speaker, &row).await;
    assert!(
        ReconciliationLoop::new(ctx.repo.clone(), speaker.clone(), 30, false)
            .reconcile()
            .await
            .is_err()
    );
    assert_eq!(
        speaker.calls(),
        0,
        "unscoped real-speaker helpers also fail closed"
    );
    let binding = ctx
        .repo
        .register_speaker_target(
            "guard",
            &SpeakerTarget::from_config(&config.bgp).unwrap(),
            true,
        )
        .await
        .unwrap();
    let mut changed = AppState::new(
        config.clone(),
        common::test_inventory(),
        common::test_playbooks(),
        ctx.repo.clone(),
        speaker.clone(),
        ".".into(),
    )
    .unwrap()
    .with_speaker_binding(binding.clone())
    .unwrap();
    Arc::get_mut(&mut changed).unwrap().settings.bgp.gobgp_grpc =
        "http://changed.example:50051".into();
    assert_lifecycle_rejected(changed, &speaker, &row).await;
    for changed in [
        settings("guard", "http://changed.example:50051"),
        settings("foreign", "http://private-target.example:50051"),
    ] {
        let state = AppState::new(
            changed,
            common::test_inventory(),
            common::test_playbooks(),
            ctx.repo.clone(),
            speaker.clone(),
            ".".into(),
        )
        .unwrap();
        let error = state
            .with_speaker_binding(binding.clone())
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains("example"));
    }
    let shared = AppState::new(
        config,
        common::test_inventory(),
        common::test_playbooks(),
        ctx.repo.clone(),
        speaker.clone(),
        ".".into(),
    )
    .unwrap();
    let other_owner = shared.clone();
    assert!(
        shared
            .with_speaker_binding(binding)
            .err()
            .unwrap()
            .to_string()
            .contains("before sharing")
    );
    drop(other_owner);
    assert_eq!(speaker.calls(), 0);
    let events: i64 = sqlx::query_scalar("SELECT count(*) FROM events")
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
    assert_eq!(
        events, 1,
        "rejected detector requests must not consume event IDs"
    );
    assert_eq!(
        ctx.repo
            .get_mitigation(row.mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        MitigationStatus::Active
    );
    assert_eq!(
        ctx.repo
            .pending_withdrawals(Some("guard"))
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn fresh_queue_target_is_checked_before_rpc_and_finalization_even_during_adoption() {
    let ctx = common::TestContext::new().await;
    let a = SpeakerTarget::from_config(&settings("a", "http://a.example:50051").bgp).unwrap();
    let b = SpeakerTarget::from_config(&settings("b", "http://b.example:50051").bgp).unwrap();
    let a = ctx
        .repo
        .register_speaker_target("a", &a, false)
        .await
        .unwrap();
    let b = ctx
        .repo
        .register_speaker_target("b", &b, false)
        .await
        .unwrap();
    let row = mitigation("a", "203.0.113.10");
    ctx.repo.insert_mitigation(&row).await.unwrap();
    let mut request = WithdrawalRequest::new(
        &row,
        false,
        "operator",
        "original",
        "keep original reason".into(),
        true,
    )
    .unwrap();
    request.target_id = Some(a.target_id());
    // Corrupt persisted ownership independently of the caller's correct clone.
    sqlx::query("INSERT INTO withdrawal_requests (operation_id, mitigation_id, pop, nlri_hash, rule_json, mitigation_updated_at, terminal_status, actor_type, actor, reason, requested_at, speaker_delete_required, target_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)")
        .bind(request.operation_id).bind(request.mitigation_id).bind(&request.pop).bind(&request.nlri_hash)
        .bind(&request.rule_json).bind(request.mitigation_updated_at).bind(&request.terminal_status)
        .bind(&request.actor_type).bind(&request.actor).bind(&request.reason).bind(request.requested_at)
        .bind(request.speaker_delete_required).bind(b.target_id()).execute(&ctx.pool).await.unwrap();
    let before = queue_snapshot(&ctx.pool, "a").await;
    let speaker = CountingSpeaker::default();
    assert!(
        execute_withdrawal(ctx.repo.as_ref(), &speaker, false, &request, Some(&a))
            .await
            .is_err()
    );
    assert!(
        execute_withdrawal(ctx.repo.as_ref(), &speaker, false, &request, None)
            .await
            .is_err()
    );
    assert!(
        execute_withdrawal(ctx.repo.as_ref(), &speaker, false, &request, Some(&b))
            .await
            .is_err()
    );
    assert!(
        execute_withdrawal(
            ctx.repo.as_ref(),
            &MockAnnouncer::new(),
            false,
            &request,
            Some(&a)
        )
        .await
        .is_err()
    );
    assert_eq!(speaker.calls(), 0);
    assert!(
        ctx.repo
            .finish_withdrawal(&request)
            .await
            .unwrap()
            .is_none()
    );
    for adopt in [false, true] {
        let target =
            SpeakerTarget::from_config(&settings("a", "http://a.example:50051").bgp).unwrap();
        assert!(
            ctx.repo
                .register_speaker_target("a", &target, adopt)
                .await
                .is_err()
        );
    }
    assert!(
        sqlx::query("UPDATE withdrawal_requests SET target_id = $2 WHERE operation_id = $1")
            .bind(request.operation_id)
            .bind(a.target_id())
            .execute(&ctx.pool)
            .await
            .is_err()
    );
    assert_eq!(queue_snapshot(&ctx.pool, "a").await, before);
    assert_eq!(
        ctx.repo
            .get_mitigation(row.mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        MitigationStatus::Active
    );
    let completed: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action IN ('withdraw', 'expire', 'adopt_speaker_target')").fetch_one(&ctx.pool).await.unwrap();
    assert_eq!(completed, 0);
}

#[tokio::test]
async fn documented_drained_transfer_preserves_completed_history_and_allows_restart() {
    let ctx = common::TestContext::new().await;
    let original = SpeakerTarget::from_config(&settings("iad1", "old.example:50051").bgp).unwrap();
    let binding = ctx
        .repo
        .register_speaker_target("iad1", &original, false)
        .await
        .unwrap();
    let row = mitigation("iad1", "203.0.113.10");
    ctx.repo.insert_mitigation(&row).await.unwrap();
    let sql = include_str!("../docs/how-to/upgrading.md")
        .split("<!-- speaker-transfer-sql -->")
        .nth(1)
        .unwrap()
        .split("```sql\n")
        .nth(1)
        .unwrap()
        .split("```")
        .next()
        .unwrap()
        .replace(
            "00000000-0000-0000-0000-000000000001",
            &binding.target_id().to_string(),
        );
    // An active row and then a pending queue entry independently block the transfer.
    assert!(sqlx::raw_sql(&sql).execute(&ctx.pool).await.is_err());
    let request = request_withdrawal(
        ctx.repo.as_ref(),
        &row,
        false,
        "operator",
        "original-actor",
        "original reason".into(),
        true,
        Some(&binding),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE mitigations SET status = 'withdrawn' WHERE mitigation_id = $1")
        .bind(row.mitigation_id)
        .execute(&ctx.pool)
        .await
        .unwrap();
    assert!(sqlx::raw_sql(&sql).execute(&ctx.pool).await.is_err());
    sqlx::query("UPDATE mitigations SET status = 'active' WHERE mitigation_id = $1")
        .bind(row.mitigation_id)
        .execute(&ctx.pool)
        .await
        .unwrap();
    execute_withdrawal(
        ctx.repo.as_ref(),
        &CountingSpeaker::default(),
        false,
        &request,
        Some(&binding),
    )
    .await
    .unwrap();
    sqlx::query("INSERT INTO flowspec_announcements (announcement_id, mitigation_id, pop, peer_name, peer_address, nlri_hash, nlri_json, action_json, status) VALUES ($1, $2, 'iad1', 'router', '192.0.2.1', 'old-key', '{}', '{}', 'pending')")
        .bind(Uuid::new_v4()).bind(row.mitigation_id).execute(&ctx.pool).await.unwrap();
    assert!(sqlx::raw_sql(&sql).execute(&ctx.pool).await.is_err());
    sqlx::query("UPDATE flowspec_announcements SET status = 'withdrawn' WHERE pop = 'iad1'")
        .execute(&ctx.pool)
        .await
        .unwrap();
    let history = queue_snapshot(&ctx.pool, "iad1").await;
    let old_target: Value =
        sqlx::query_scalar("SELECT to_jsonb(t) FROM speaker_targets t WHERE target_id = $1")
            .bind(binding.target_id())
            .fetch_one(&ctx.pool)
            .await
            .unwrap();
    sqlx::raw_sql(&sql).execute(&ctx.pool).await.unwrap();
    let replacement =
        SpeakerTarget::from_config(&settings("iad1", "new-speaker.example:50051").bgp).unwrap();
    let restarted = ctx
        .repo
        .register_speaker_target("iad1", &replacement, false)
        .await
        .unwrap();
    assert_ne!(restarted.target_id(), binding.target_id());
    assert!(
        ctx.repo
            .register_speaker_target("iad1", &original, true)
            .await
            .is_err()
    );
    assert_eq!(queue_snapshot(&ctx.pool, "iad1").await, history);
    let old_target_after: Value =
        sqlx::query_scalar("SELECT to_jsonb(t) FROM speaker_targets t WHERE target_id = $1")
            .bind(binding.target_id())
            .fetch_one(&ctx.pool)
            .await
            .unwrap();
    assert_eq!(old_target_after, old_target);
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE action = 'transfer_speaker_target'",
    )
    .fetch_one(&ctx.pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn adoption_process_exits_before_factory_connection_and_mismatch_never_connects() {
    use std::{process::Stdio, time::Duration};
    let ctx = common::TestContext::new().await;
    let row = mitigation("process", "203.0.113.10");
    ctx.repo.insert_mitigation(&row).await.unwrap();
    let speaker_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    // Keeping the API address occupied also proves adoption never starts the server.
    let api_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = settings(
        "process",
        &format!("HTTP://{}", speaker_listener.local_addr().unwrap()),
    );
    config.http.listen = api_listener.local_addr().unwrap().to_string();
    let directory = tempfile::tempdir().unwrap();
    common::write_yaml(
        directory.path(),
        "prefixd.yaml",
        &serde_saphyr::to_string(&config).unwrap(),
    );
    common::write_yaml(
        directory.path(),
        "inventory.yaml",
        &serde_saphyr::to_string(&common::test_inventory()).unwrap(),
    );
    common::write_yaml(
        directory.path(),
        "playbooks.yaml",
        &serde_saphyr::to_string(&common::test_playbooks()).unwrap(),
    );
    let command = || {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_prefixd"));
        command
            .arg("--config")
            .arg(directory.path())
            .env(
                "DATABASE_URL",
                &ctx.state.settings.storage.connection_string,
            )
            .kill_on_drop(true);
        command
    };
    // A normal legacy startup must fail before even opening a TCP connection.
    let output = tokio::time::timeout(Duration::from_secs(15), command().output())
        .await
        .unwrap()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--adopt-legacy-speaker"));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), speaker_listener.accept())
            .await
            .is_err()
    );
    for _ in 0..2 {
        let output = tokio::time::timeout(
            Duration::from_secs(15),
            command().arg("--adopt-legacy-speaker").output(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), speaker_listener.accept())
                .await
                .is_err()
        );
        assert_eq!(
            ctx.repo
                .get_mitigation(row.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            MitigationStatus::Active
        );
    }
    let audits: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = 'adopt_speaker_target'")
            .fetch_one(&ctx.pool)
            .await
            .unwrap();
    assert_eq!(audits, 1, "repeated one-shot adoption is idempotent");
    // Positive control: the same binary with the verified original config reaches
    // the fake speaker listener in ordinary startup. No gRPC server is needed.
    let mut normal = command()
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let accepted = tokio::time::timeout(Duration::from_secs(10), speaker_listener.accept()).await;
    if normal.try_wait().unwrap().is_none() {
        normal.kill().await.unwrap();
    }
    normal.wait().await.unwrap();
    assert!(
        accepted.is_ok(),
        "the connection detector must observe a normal factory call"
    );
    drop(accepted);

    let changed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    config.bgp.gobgp_grpc = format!("http://{}", changed.local_addr().unwrap());
    common::write_yaml(
        directory.path(),
        "prefixd.yaml",
        &serde_saphyr::to_string(&config).unwrap(),
    );
    for adopt in [false, true] {
        let mut cmd = command();
        if adopt {
            cmd.arg("--adopt-legacy-speaker");
        }
        let output = tokio::time::timeout(Duration::from_secs(15), cmd.output())
            .await
            .unwrap()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("speaker target ownership"));
        assert!(!stderr.contains(&config.bgp.gobgp_grpc));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), changed.accept())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn enforced_startup_refuses_dry_run_intent_until_the_flag_retires_it_locally() {
    use std::{process::Stdio, time::Duration};
    let ctx = common::TestContext::new().await;
    let speaker_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = settings(
        "rehearsal",
        &format!("http://{}", speaker_listener.local_addr().unwrap()),
    );
    config.http.listen = api_listener.local_addr().unwrap().to_string();
    // Bind first so the simulated row is ordinary current state, not legacy state.
    ctx.repo
        .register_speaker_target(
            "rehearsal",
            &SpeakerTarget::from_config(&config.bgp).unwrap(),
            false,
        )
        .await
        .unwrap();
    let mut simulated = mitigation("rehearsal", "203.0.113.10");
    simulated.origin_mode = Some(OperationMode::DryRun);
    ctx.repo.insert_mitigation(&simulated).await.unwrap();
    let directory = tempfile::tempdir().unwrap();
    for (name, yaml) in [
        ("prefixd.yaml", serde_saphyr::to_string(&config).unwrap()),
        (
            "inventory.yaml",
            serde_saphyr::to_string(&common::test_inventory()).unwrap(),
        ),
        (
            "playbooks.yaml",
            serde_saphyr::to_string(&common::test_playbooks()).unwrap(),
        ),
    ] {
        common::write_yaml(directory.path(), name, &yaml);
    }
    let command = || {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_prefixd"));
        command
            .arg("--config")
            .arg(directory.path())
            .env(
                "DATABASE_URL",
                &ctx.state.settings.storage.connection_string,
            )
            .kill_on_drop(true);
        command
    };
    let no_connection = async || {
        tokio::time::timeout(Duration::from_millis(100), speaker_listener.accept())
            .await
            .is_err()
    };

    let output = tokio::time::timeout(Duration::from_secs(15), command().output())
        .await
        .unwrap()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("1 unexpired dry-run"), "{stderr}");
    assert!(stderr.contains("--retire-dry-run-intent"), "{stderr}");
    assert!(
        no_connection().await,
        "refusal precedes any speaker connection"
    );

    for _ in 0..2 {
        let output = tokio::time::timeout(
            Duration::from_secs(15),
            command().arg("--retire-dry-run-intent").output(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            no_connection().await,
            "retirement never contacts the speaker"
        );
    }
    let retired = ctx
        .repo
        .get_mitigation(simulated.mitigation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retired.status, MitigationStatus::Withdrawn);
    let (local_only, actor, completed): (bool, String, bool) = sqlx::query_as(
        "SELECT NOT speaker_delete_required, actor, completed_at IS NOT NULL FROM withdrawal_requests WHERE mitigation_id = $1",
    )
    .bind(simulated.mitigation_id)
    .fetch_one(&ctx.pool)
    .await
    .unwrap();
    assert!(local_only && completed);
    assert_eq!(actor, "retire-dry-run-intent");
    let audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE actor_type = 'system' AND actor_id = 'retire-dry-run-intent' AND action = 'withdraw' AND target_id = $1",
    )
    .bind(simulated.mitigation_id.to_string())
    .fetch_one(&ctx.pool)
    .await
    .unwrap();
    assert_eq!(audits, 1, "a repeated flag run retires nothing new");

    // Positive control: ordinary enforced startup now reaches the speaker.
    let mut normal = command()
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let accepted = tokio::time::timeout(Duration::from_secs(10), speaker_listener.accept()).await;
    if normal.try_wait().unwrap().is_none() {
        normal.kill().await.unwrap();
    }
    normal.wait().await.unwrap();
    assert!(accepted.is_ok(), "enforced startup proceeds once retired");
}

#[tokio::test]
async fn unknown_origin_tagging_is_audited_once_and_survives_migration_replay() {
    let ctx = common::TestContext::new().await;
    let legacy = mitigation("origin", "203.0.113.10");
    let mut terminal = mitigation("origin", "203.0.113.11");
    terminal.withdraw(Some("old".into()));
    let foreign = mitigation("other-origin", "203.0.113.12");
    for row in [&legacy, &terminal, &foreign] {
        assert_eq!(row.origin_mode, None);
        ctx.repo.insert_mitigation(row).await.unwrap();
    }
    // Simulate rows written before migration 015 existed.
    sqlx::query("UPDATE mitigations SET origin_mode = NULL")
        .execute(&ctx.pool)
        .await
        .unwrap();
    let pending = request_withdrawal(
        ctx.repo.as_ref(),
        &legacy,
        false,
        "operator",
        "upgrade-test",
        "pending across upgrade".into(),
        true,
        None,
    )
    .await
    .unwrap();
    let origin = |id: Uuid| {
        let pool = ctx.pool.clone();
        async move {
            sqlx::query_scalar::<_, Option<String>>(
                "SELECT origin_mode FROM mitigations WHERE mitigation_id = $1",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };

    for expected in [1, 0] {
        assert_eq!(
            ctx.repo
                .tag_unknown_origin("origin", OperationMode::Enforced)
                .await
                .unwrap(),
            expected
        );
    }
    assert_eq!(
        origin(legacy.mitigation_id).await.as_deref(),
        Some("enforced")
    );
    assert_eq!(
        origin(terminal.mitigation_id).await,
        None,
        "history is not rewritten"
    );
    assert_eq!(
        origin(foreign.mitigation_id).await,
        None,
        "other POPs are untouched"
    );
    let details: Vec<Value> = sqlx::query_scalar(
        "SELECT details_json::jsonb FROM audit_log WHERE action = 'tag_origin_mode' AND actor_type = 'system' AND target_id = 'origin'",
    )
    .fetch_all(&ctx.pool)
    .await
    .unwrap();
    assert_eq!(
        details,
        vec![json!({"origin_mode": "enforced", "tagged_mitigations": 1})]
    );

    // Replaying every migration keeps tags and does not imply acknowledgement.
    let announcements: i64 = sqlx::query_scalar("SELECT count(*) FROM flowspec_announcements")
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
    init_postgres_pool(&ctx.state.settings.storage.connection_string)
        .await
        .unwrap();
    assert_eq!(
        origin(legacy.mitigation_id).await.as_deref(),
        Some("enforced")
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM flowspec_announcements")
            .fetch_one(&ctx.pool)
            .await
            .unwrap(),
        announcements
    );
    assert!(
        sqlx::query("UPDATE mitigations SET origin_mode = 'dry_run' WHERE mitigation_id = $1")
            .bind(legacy.mitigation_id)
            .execute(&ctx.pool)
            .await
            .is_err(),
        "only configuration spellings are stored"
    );

    // Tagging left the revision intact, so the pending request still completes.
    let pending_after = ctx.repo.pending_withdrawals(Some("origin")).await.unwrap();
    assert_eq!(pending_after.len(), 1);
    assert_eq!(pending_after[0].operation_id, pending.operation_id);
    assert!(pending_after[0].speaker_delete_required);
    let speaker = MockAnnouncer::new();
    speaker
        .announce(&prefixd::domain::mitigation_rule(&legacy).unwrap())
        .await
        .unwrap();
    let done = execute_withdrawal(ctx.repo.as_ref(), &speaker, false, &pending, None)
        .await
        .unwrap();
    assert_eq!(done.status, MitigationStatus::Withdrawn);
}

#[tokio::test]
async fn withdrawal_rule_kind_replay_keeps_every_request_flowspec() {
    let ctx = common::TestContext::new().await;
    let pending = mitigation("kind", "203.0.113.20");
    let completed = mitigation("kind", "203.0.113.21");
    let speaker = MockAnnouncer::new();
    let mut requests = Vec::new();
    for row in [&pending, &completed] {
        ctx.repo.insert_mitigation(row).await.unwrap();
        speaker
            .announce(&prefixd::domain::mitigation_rule(row).unwrap())
            .await
            .unwrap();
        requests.push(
            request_withdrawal(
                ctx.repo.as_ref(),
                row,
                false,
                "operator",
                "kind-test",
                "written before migration 016".into(),
                true,
                None,
            )
            .await
            .unwrap(),
        );
    }
    execute_withdrawal(ctx.repo.as_ref(), &speaker, false, &requests[1], None)
        .await
        .unwrap();
    // Simulate a database from before migration 016.
    sqlx::query("ALTER TABLE withdrawal_requests DROP COLUMN rule_kind")
        .execute(&ctx.pool)
        .await
        .unwrap();
    let snapshot = || {
        let pool = ctx.pool.clone();
        async move {
            sqlx::query_scalar::<_, Value>(
                "SELECT jsonb_build_array(
                    (SELECT jsonb_agg(to_jsonb(m) ORDER BY mitigation_id) FROM mitigations m),
                    (SELECT jsonb_agg(to_jsonb(w) - 'rule_kind' ORDER BY operation_id)
                       FROM withdrawal_requests w),
                    (SELECT count(*) FROM flowspec_announcements),
                    (SELECT count(*) FROM audit_log))",
            )
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    let before = snapshot().await;

    // Replay is repeatable and only adds the column.
    for _ in 0..2 {
        init_postgres_pool(&ctx.state.settings.storage.connection_string)
            .await
            .unwrap();
    }
    assert_eq!(snapshot().await, before);
    let kinds: Vec<String> =
        sqlx::query_scalar("SELECT rule_kind FROM withdrawal_requests ORDER BY operation_id")
            .fetch_all(&ctx.pool)
            .await
            .unwrap();
    assert_eq!(kinds, ["flowspec", "flowspec"]);
    assert!(
        sqlx::query("UPDATE withdrawal_requests SET rule_kind = 'unicast'")
            .execute(&ctx.pool)
            .await
            .is_err(),
        "only known route kinds are stored"
    );

    // The replayed pending request still completes through the FlowSpec path.
    let pending_after = ctx.repo.pending_withdrawals(Some("kind")).await.unwrap();
    assert_eq!(pending_after.len(), 1);
    assert_eq!(pending_after[0].operation_id, requests[0].operation_id);
    assert_eq!(pending_after[0].rule_kind, "flowspec");
    let done = execute_withdrawal(ctx.repo.as_ref(), &speaker, false, &pending_after[0], None)
        .await
        .unwrap();
    assert_eq!(done.status, MitigationStatus::Withdrawn);
    assert_eq!(speaker.announced_count().await, 0);
}

#[tokio::test]
async fn one_shot_maintenance_refuses_while_another_instance_holds_the_fence() {
    use sqlx::Connection;
    use std::{str::FromStr, time::Duration};
    let ctx = common::TestContext::new().await;
    let mut config = settings("maintenance", "http://127.0.0.1:1");
    config.http.listen = "127.0.0.1:0".into();
    let binding = ctx
        .repo
        .register_speaker_target(
            "maintenance",
            &SpeakerTarget::from_config(&config.bgp).unwrap(),
            false,
        )
        .await
        .unwrap();
    let mut simulated = mitigation("maintenance", "203.0.113.10");
    simulated.origin_mode = Some(OperationMode::DryRun);
    ctx.repo.insert_mitigation(&simulated).await.unwrap();
    let directory = tempfile::tempdir().unwrap();
    for (name, yaml) in [
        ("prefixd.yaml", serde_saphyr::to_string(&config).unwrap()),
        (
            "inventory.yaml",
            serde_saphyr::to_string(&common::test_inventory()).unwrap(),
        ),
        (
            "playbooks.yaml",
            serde_saphyr::to_string(&common::test_playbooks()).unwrap(),
        ),
    ] {
        common::write_yaml(directory.path(), name, &yaml);
    }
    let run = async |flag: &str| {
        tokio::time::timeout(
            Duration::from_secs(15),
            tokio::process::Command::new(env!("CARGO_BIN_EXE_prefixd"))
                .arg("--config")
                .arg(directory.path())
                .arg(flag)
                .env(
                    "DATABASE_URL",
                    &ctx.state.settings.storage.connection_string,
                )
                .kill_on_drop(true)
                .output(),
        )
        .await
        .unwrap()
        .unwrap()
    };
    let options =
        sqlx::postgres::PgConnectOptions::from_str(&ctx.state.settings.storage.connection_string)
            .unwrap();
    let owner = binding.owner();
    let key = prefixd::fence::fence_lock_key(&owner);
    // Another instance holds this owner's fence.
    let holder = prefixd::fence::try_acquire(&options, key)
        .await
        .unwrap()
        .expect("test instance takes the fence");
    for flag in ["--retire-dry-run-intent", "--adopt-legacy-speaker"] {
        let output = run(flag).await;
        assert!(!output.status.success(), "{flag} ran beside a fence holder");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!(
                "another controller holds the fence for owner {owner}"
            )) && stderr.contains("stop it first"),
            "{flag}: {stderr}"
        );
    }
    let untouched = ctx
        .repo
        .get_mitigation(simulated.mitigation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(untouched.status, MitigationStatus::Active);

    // Once the holder stops, both modes run and release the fence on exit.
    holder.close().await.unwrap();
    for flag in ["--retire-dry-run-intent", "--adopt-legacy-speaker"] {
        let output = run(flag).await;
        assert!(
            output.status.success(),
            "{flag}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let retired = ctx
        .repo
        .get_mitigation(simulated.mitigation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retired.status, MitigationStatus::Withdrawn);
    assert!(
        prefixd::fence::try_acquire(&options, key)
            .await
            .unwrap()
            .is_some(),
        "one-shot modes release the fence when they exit"
    );
}
