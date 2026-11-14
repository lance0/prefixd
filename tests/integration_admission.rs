#![forbid(unsafe_code)]

mod common;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use prefixd::db::RepositoryTrait;
use std::sync::Arc;
use tower::ServiceExt;

fn request() -> Request<Body> {
    Request::post("/v1/mitigations/preview")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"victim_ip":"203.0.113.10","protocol":"udp","dst_ports":[53],"action":"discard","ttl_seconds":300,"reason":"inspect admission"}"#,
        ))
        .unwrap()
}

#[tokio::test]
async fn postgres_preview_deadline_recovers_pool_and_server_work_before_blocker_release() {
    assert_preview_pool_recovers(0).await;
}

#[tokio::test]
async fn postgres_preview_preserves_a_shorter_server_deadline() {
    assert_preview_pool_recovers(750).await;
}

async fn assert_preview_pool_recovers(server_timeout_ms: u32) {
    let ctx = common::TestContext::new().await;
    // Observer and blocker use ctx.pool. One preview connection makes even a
    // single stranded read visible, without relying on a large retry storm.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            ctx.pool
                .connect_options()
                .as_ref()
                .clone()
                .application_name("prefixd-admission-preview-test")
                .options([("statement_timeout", format!("{server_timeout_ms}ms"))]),
        )
        .await
        .unwrap();
    let state = prefixd::AppState::new(
        common::test_settings(),
        common::test_inventory(),
        common::test_playbooks(),
        Arc::new(prefixd::db::Repository::new(pool.clone())),
        Arc::new(prefixd::bgp::MockAnnouncer::new()),
        ".".into(),
    )
    .unwrap();
    let app = prefixd::api::create_test_router(state.clone());
    let mut held = ctx.pool.begin().await.unwrap();
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *held)
        .await
        .unwrap();
    sqlx::query("LOCK TABLE mitigations IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *held)
        .await
        .unwrap();

    // More attempts than pool capacity must recover before releasing the
    // blocker, rather than accumulating unusable connections or server queries.
    for attempt in 0..3 {
        let app = app.clone();
        let running = tokio::spawn(async move { app.oneshot(request()).await.unwrap() });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let waiting: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)) AND application_name = 'prefixd-admission-preview-test' AND query LIKE '%FROM mitigations WHERE%status IN%')",
                )
                .bind(blocker)
                .fetch_one(&ctx.pool)
                .await
                .unwrap();
                if waiting {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("preview must demonstrably wait on the held table lock after preparation");
        assert!(
            state.mitigation_lock.try_lock().is_ok(),
            "a blocked preview must not hold the lifecycle mutex"
        );

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(if server_timeout_ms == 0 { 7 } else { 2 }),
            running,
        )
        .await
        .expect("preview must return while the database blocker remains held")
        .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let blocked: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)) AND application_name = 'prefixd-admission-preview-test'",
        )
        .bind(blocker)
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
        eprintln!(
            "attempt={attempt}, blocked_preview_statements={blocked}, pool_size={}, pool_idle={}",
            pool.size(),
            pool.num_idle()
        );
        let (probe, timeout_setting): (i32, String) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            sqlx::query_as("SELECT 1::int, current_setting('statement_timeout')").fetch_one(&pool),
        )
        .await
        .expect("the one-connection pool must remain usable while the blocker is held")
        .unwrap();
        assert_eq!(probe, 1);
        assert_eq!(
            timeout_setting,
            if server_timeout_ms == 0 { "0" } else { "750ms" },
            "preview settings must not leak to normal reads"
        );
        assert_eq!(
            blocked, 0,
            "a timed-out preview must leave no blocked statement"
        );
        let result: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
        assert_eq!(result["outcome"], "unavailable");
        // PostgreSQL's earlier statement deadline bounds residual server work;
        // this is an unavailable ownership read, not the outer client deadline.
        assert_eq!(result["failed_check"], "ownership");
        assert_eq!(result["speaker_state"], "unobserved");
        assert_eq!(
            result["candidate"]["scope"]["dst_prefix"],
            "203.0.113.10/32"
        );
        assert_eq!(
            result["candidate"]["scope"]["dst_ports"],
            serde_json::json!([53])
        );
        assert_eq!(
            result["reason"],
            "Admission safety checks are unavailable. No intent was saved; retry the check."
        );
    }
    // An exhausted budget must refuse before issuing an unlimited statement.
    for remaining in [
        std::time::Duration::ZERO,
        std::time::Duration::from_micros(500),
    ] {
        let expired = Arc::new(prefixd::db::Repository::new(pool.clone()))
            .for_bounded_reads(tokio::time::Instant::now() + remaining)
            .unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            expired.count_active_flowspec_global(),
        )
        .await
        .expect("an exhausted server budget must not become a disabled timeout");
        assert!(matches!(
            result,
            Err(prefixd::error::PrefixdError::Database(
                sqlx::Error::PoolTimedOut
            ))
        ));
        let probe: i32 = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            sqlx::query_scalar("SELECT 1::int").fetch_one(&pool),
        )
        .await
        .expect("refusing an exhausted budget must release pool capacity")
        .unwrap();
        assert_eq!(probe, 1);
    }
    held.rollback().await.unwrap();

    let response = app.oneshot(request()).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a fresh preview must recover"
    );
    for table in ["mitigations", "audit_log", "events", "withdrawal_requests"] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&ctx.pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "preview unexpectedly changed {table}");
    }
    pool.close().await;
}

/// Bounded preview reads return their connections to the pool: repeated
/// previews must not open a new connection per read.
#[tokio::test]
async fn postgres_previews_reuse_pooled_connections() {
    const MAX_CONNECTIONS: u32 = 2;
    const PREVIEWS: usize = 10;
    let ctx = common::TestContext::new().await;
    let connects = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = connects.clone();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(MAX_CONNECTIONS)
        .after_connect(move |_, _| {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        })
        .connect_with(ctx.pool.connect_options().as_ref().clone())
        .await
        .unwrap();
    let state = prefixd::AppState::new(
        common::test_settings(),
        common::test_inventory(),
        common::test_playbooks(),
        Arc::new(prefixd::db::Repository::new(pool.clone())),
        Arc::new(prefixd::bgp::MockAnnouncer::new()),
        ".".into(),
    )
    .unwrap();
    let app = prefixd::api::create_test_router(state);
    for _ in 0..PREVIEWS {
        let response = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let opened = connects.load(std::sync::atomic::Ordering::SeqCst);
    eprintln!("previews={PREVIEWS}, connections_opened={opened}");
    assert!(
        opened <= MAX_CONNECTIONS as usize,
        "{PREVIEWS} previews opened {opened} connections"
    );
    // Transaction-local settings end with each read.
    let timeout: String = sqlx::query_scalar("SELECT current_setting('statement_timeout')")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(timeout, "0");
    pool.close().await;
}

fn source_only_quota_row(
    family: prefixd::domain::VpnFlowSpecFamily,
    rd: &str,
    source: &str,
) -> prefixd::domain::Mitigation {
    use prefixd::domain::*;
    let scope = VpnScopeSnapshot::new(
        "TRANSIT",
        VpnFlowSpecIdentity::new(family, rd).unwrap(),
        &["44407:777".into()],
    )
    .unwrap();
    let mut row = Mitigation::from_intent(
        MitigationIntent {
            event_id: uuid::Uuid::new_v4(),
            customer_id: None,
            service_id: None,
            pop: "vpn-quota".into(),
            match_criteria: MatchCriteria {
                scope: Some(scope),
                dst_prefix: String::new(),
                src_prefix: Some(source.into()),
                ..Default::default()
            },
            action_type: ActionType::Discard,
            action_params: ActionParams::default(),
            ttl_seconds: 60,
            reason: "source quota regression".into(),
        },
        "any".into(),
        AttackVector::Unknown,
    );
    row.activate();
    row
}

async fn exercise_atomic_source_only_quota(repo: Arc<dyn RepositoryTrait>) {
    use prefixd::domain::{MitigationStatus, VpnFlowSpecFamily};
    let settings = common::test_settings();
    let mut quotas = settings.quotas;
    quotas.source_only_limit = Some(1);
    let actor = prefixd::observability::CreationActor::Operator("quota-test".into());
    for (family, sources) in [
        (
            VpnFlowSpecFamily::Ipv4,
            ["198.51.100.0/24", "198.51.101.0/24"],
        ),
        (VpnFlowSpecFamily::Ipv6, ["2001:db9::/64", "2001:dba::/64"]),
    ] {
        let first = source_only_quota_row(family, "44407:40", sources[0]);
        let second = source_only_quota_row(family, "44407:40", sources[1]);
        // Both bypass API preflight. The repository lock must admit only one.
        let (left, right) = tokio::join!(
            repo.admit_mitigation(&first, &quotas, &settings.blackhole, &actor),
            repo.admit_mitigation(&second, &quotas, &settings.blackhole, &actor),
        );
        assert_ne!(left.is_ok(), right.is_ok(), "{left:?} {right:?}");
        let refusal = left
            .as_ref()
            .err()
            .or_else(|| right.as_ref().err())
            .unwrap();
        assert!(
            matches!(refusal, prefixd::error::PrefixdError::GuardrailViolation(prefixd::error::GuardrailError::QuotaExceeded { quota_type, .. }) if quota_type == "source_only")
        );
        let other = source_only_quota_row(family, "44407:41", sources[0]);
        repo.admit_mitigation(&other, &quotas, &settings.blackhole, &actor)
            .await
            .unwrap();
        let mut admitted = if left.is_ok() { first } else { second };
        admitted.status = MitigationStatus::Expired;
        repo.update_mitigation(&admitted).await.unwrap();
        let replacement = source_only_quota_row(family, "44407:40", sources[0]);
        repo.admit_mitigation(&replacement, &quotas, &settings.blackhole, &actor)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn postgres_source_only_quota_is_atomic_and_scoped() {
    let context = common::TestContext::new().await;
    exercise_atomic_source_only_quota(context.repo.clone()).await;
}

#[tokio::test]
async fn mock_source_only_quota_is_atomic_and_scoped() {
    exercise_atomic_source_only_quota(Arc::new(prefixd::db::MockRepository::new())).await;
}

async fn prefix_quota_row(
    repo: &dyn RepositoryTrait,
    prefix: &str,
    detector: bool,
) -> prefixd::domain::Mitigation {
    use prefixd::domain::*;
    let mut event_id = uuid::Uuid::new_v4();
    // Detector rows reference their persisted event; manual rows do not.
    if detector {
        let event = AttackEvent::from_input(
            serde_json::from_value(serde_json::json!({
                "timestamp": "2026-11-14T00:00:00Z",
                "source": "fastnetmon",
                "victim_ip": prefix,
                "vector": "udp_flood",
            }))
            .unwrap(),
        );
        repo.insert_event(&event).await.unwrap();
        event_id = event.event_id;
    }
    let mut row = Mitigation::from_intent(
        MitigationIntent {
            event_id,
            customer_id: Some("cust-prefix".into()),
            service_id: None,
            pop: "prefix-quota".into(),
            match_criteria: MatchCriteria {
                dst_prefix: prefix.into(),
                protocol: Some(17),
                dst_ports: vec![53],
                ..Default::default()
            },
            action_type: ActionType::Discard,
            action_params: ActionParams::default(),
            ttl_seconds: 60,
            reason: "prefix quota".into(),
        },
        prefix.into(),
        AttackVector::UdpFlood,
    );
    row.activate();
    row
}

/// The detector prefix budget is atomic, counts only detector-created non-host
/// rows and never caps manual CIDRs or host rules.
async fn exercise_atomic_detector_prefix_quota(repo: Arc<dyn RepositoryTrait>) {
    use prefixd::domain::MitigationStatus;
    use prefixd::observability::CreationActor;
    let settings = common::test_settings();
    let mut quotas = settings.quotas;
    quotas.max_active_prefix_per_customer = 1;
    let detector = CreationActor::Detector("fastnetmon".into());
    let operator = CreationActor::Operator("quota-test".into());
    let is_prefix_quota = |error: &prefixd::error::PrefixdError| matches!(error, prefixd::error::PrefixdError::GuardrailViolation(prefixd::error::GuardrailError::QuotaExceeded { quota_type, .. }) if quota_type == "prefix_customer");

    let first = prefix_quota_row(repo.as_ref(), "203.0.113.0/24", true).await;
    let second = prefix_quota_row(repo.as_ref(), "2001:db8:100::/48", true).await;
    // Both bypass API preflight. The repository lock must admit only one.
    let (left, right) = tokio::join!(
        repo.admit_mitigation(&first, &quotas, &settings.blackhole, &detector),
        repo.admit_mitigation(&second, &quotas, &settings.blackhole, &detector),
    );
    assert_ne!(left.is_ok(), right.is_ok(), "{left:?} {right:?}");
    assert!(is_prefix_quota(
        left.as_ref().err().or(right.as_ref().err()).unwrap()
    ));
    assert_eq!(
        repo.count_active_detector_prefix_by_customer("cust-prefix")
            .await
            .unwrap(),
        1
    );

    // Manual CIDRs admit past the budget and are not counted against it.
    for prefix in ["198.51.100.0/24", "2001:db8:200::/48"] {
        let manual = prefix_quota_row(repo.as_ref(), prefix, false).await;
        repo.admit_mitigation(&manual, &quotas, &settings.blackhole, &operator)
            .await
            .unwrap();
    }
    // A detector host rule is not a prefix rule.
    let host = prefix_quota_row(repo.as_ref(), "203.0.113.10/32", true).await;
    repo.admit_mitigation(&host, &quotas, &settings.blackhole, &detector)
        .await
        .unwrap();
    assert_eq!(
        repo.count_active_detector_prefix_by_customer("cust-prefix")
            .await
            .unwrap(),
        1
    );

    let mut admitted = if left.is_ok() { first } else { second };
    admitted.status = MitigationStatus::Expired;
    repo.update_mitigation(&admitted).await.unwrap();
    let replacement = prefix_quota_row(repo.as_ref(), "192.0.2.0/24", true).await;
    repo.admit_mitigation(&replacement, &quotas, &settings.blackhole, &detector)
        .await
        .unwrap();
}

#[tokio::test]
async fn postgres_detector_prefix_quota_is_atomic_and_detector_only() {
    let context = common::TestContext::new().await;
    exercise_atomic_detector_prefix_quota(context.repo.clone()).await;
}

#[tokio::test]
async fn mock_detector_prefix_quota_is_atomic_and_detector_only() {
    exercise_atomic_detector_prefix_quota(Arc::new(prefixd::db::MockRepository::new())).await;
}
