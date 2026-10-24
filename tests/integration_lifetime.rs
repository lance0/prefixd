#![forbid(unsafe_code)]

mod common;

use chrono::{Duration, Utc};
use prefixd::db::RepositoryTrait;
use prefixd::{
    config::OperationMode,
    db::Repository,
    domain::{
        ActionParams, ActionType, AttackVector, LifetimeExtension, MatchCriteria, Mitigation,
        MitigationIntent, WithdrawalRequest,
    },
    error::PrefixdError,
    fence::ControllerFence,
};
use uuid::Uuid;

async fn repeatable_read_repository(ctx: &common::TestContext) -> (Repository, sqlx::PgPool) {
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
        .connect_with(ctx.pool.connect_options().as_ref().clone())
        .await
        .unwrap();
    let isolation: String = sqlx::query_scalar("SHOW default_transaction_isolation")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(isolation, "repeatable read");
    (Repository::new(pool.clone()), pool)
}

async fn request(ctx: &common::TestContext) -> LifetimeExtension {
    let mut m = Mitigation::from_intent(
        MitigationIntent {
            event_id: Uuid::new_v4(),
            customer_id: Some("owner".into()),
            service_id: None,
            pop: "test-pop".into(),
            match_criteria: MatchCriteria {
                dst_prefix: "203.0.113.10/32".into(),
                protocol: Some(17),
                dst_ports: vec![53],
                ..Default::default()
            },
            action_type: ActionType::Discard,
            action_params: ActionParams::default(),
            ttl_seconds: 120,
            reason: "detector event".into(),
        },
        "203.0.113.10".into(),
        AttackVector::UdpFlood,
    );
    m.activate();
    m.origin_mode = Some(OperationMode::Enforced);
    ctx.repo.insert_mitigation(&m).await.unwrap();
    LifetimeExtension {
        expected: ctx
            .repo
            .get_mitigation(m.mitigation_id)
            .await
            .unwrap()
            .unwrap(),
        ttl_seconds: 600,
        actor: "alice".into(),
        reason: "attack continues".into(),
        target_id: None,
        fence_epoch: 0,
    }
}

async fn audit_count(ctx: &common::TestContext) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'extend'")
        .fetch_one(&ctx.pool)
        .await
        .unwrap()
}

/// Observe a real server lock wait before changing time/state; no sleep-based
/// assumption that the extension has reached its SELECT FOR UPDATE.
async fn wait_for_row_wait(ctx: &common::TestContext, blocker: i32) {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)) AND query LIKE 'SELECT * FROM mitigations%FOR UPDATE%')"
            ).bind(blocker).fetch_one(&ctx.pool).await.unwrap();
            if waiting { break; }
            tokio::task::yield_now().await;
        }
    }).await.expect("extension must demonstrably wait on the held mitigation row");
}

#[tokio::test]
async fn postgres_lifetime_update_and_authenticated_audit_commit_together_and_noop_is_unchanged() {
    let ctx = common::TestContext::new().await;
    let request = request(&ctx).await;
    let result = ctx
        .repo
        .extend_flowspec_lifetime(&request, &ControllerFence::new(true))
        .await
        .unwrap();
    assert!(result.extended);
    assert_eq!(result.previous_expires_at, request.expected.expires_at);
    let row: (String, String) =
        sqlx::query_as("SELECT actor_id, details_json FROM audit_log WHERE action = 'extend'")
            .fetch_one(&ctx.pool)
            .await
            .unwrap();
    assert_eq!(row.0, "alice");
    let details: serde_json::Value = serde_json::from_str(&row.1).unwrap();
    assert_eq!(
        details["expires_at"],
        serde_json::to_value(result.mitigation.expires_at).unwrap()
    );
    assert_eq!(
        details["previous_expires_at"],
        serde_json::to_value(request.expected.expires_at).unwrap()
    );
    let noop_request = LifetimeExtension {
        expected: result.mitigation.clone(),
        ttl_seconds: 30,
        ..request
    };
    let noop = ctx
        .repo
        .extend_flowspec_lifetime(&noop_request, &ControllerFence::new(true))
        .await
        .unwrap();
    assert!(!noop.extended);
    assert_eq!(noop.mitigation.updated_at, result.mitigation.updated_at);
    assert_eq!(audit_count(&ctx).await, 1);
    let target = prefixd::domain::SpeakerTarget::from_config(&{
        let mut settings = common::test_settings();
        settings.bgp.mode = prefixd::config::BgpMode::Gobgp;
        settings.bgp
    })
    .unwrap();
    let binding = ctx
        .repo
        .register_speaker_target("other-pop", &target, false)
        .await
        .unwrap();
    let wrong_target = LifetimeExtension {
        target_id: Some(binding.target_id()),
        ..noop_request
    };
    assert!(
        ctx.repo
            .extend_flowspec_lifetime(&wrong_target, &ControllerFence::new(true))
            .await
            .is_err()
    );
    assert_eq!(audit_count(&ctx).await, 1);
}

#[tokio::test]
async fn postgres_audit_failure_rolls_back_expiry_and_version() {
    let ctx = common::TestContext::new().await;
    let request = request(&ctx).await;
    sqlx::raw_sql("CREATE FUNCTION refuse_extension() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action = 'extend' THEN RAISE EXCEPTION 'test audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER refuse_extension BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION refuse_extension();")
        .execute(&ctx.pool).await.unwrap();
    assert!(
        ctx.repo
            .extend_flowspec_lifetime(&request, &ControllerFence::new(true))
            .await
            .is_err()
    );
    let saved = ctx
        .repo
        .get_mitigation(request.expected.mitigation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(saved.updated_at, request.expected.updated_at);
    assert_eq!(saved.expires_at, request.expected.expires_at);
    assert_eq!(audit_count(&ctx).await, 0);
}

#[tokio::test]
async fn postgres_expiry_while_waiting_on_row_lock_cannot_be_revived() {
    let ctx = common::TestContext::new().await;
    let mut request = request(&ctx).await;
    let (extension_repo, extension_pool) = repeatable_read_repository(&ctx).await;
    request.expected.expires_at = Utc::now() + Duration::milliseconds(900);
    ctx.repo.update_mitigation(&request.expected).await.unwrap();
    request.expected = ctx
        .repo
        .get_mitigation(request.expected.mitigation_id)
        .await
        .unwrap()
        .unwrap();
    let mut held = ctx.pool.begin().await.unwrap();
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *held)
        .await
        .unwrap();
    sqlx::query("SELECT mitigation_id FROM mitigations WHERE mitigation_id = $1 FOR UPDATE")
        .bind(request.expected.mitigation_id)
        .execute(&mut *held)
        .await
        .unwrap();
    let repo = extension_repo;
    let cloned = request.clone();
    let running = tokio::spawn(async move {
        repo.extend_flowspec_lifetime(&cloned, &ControllerFence::new(true))
            .await
    });
    wait_for_row_wait(&ctx, blocker).await;
    // Let the real database deadline pass only after proving the blocked state.
    sqlx::query("SELECT pg_sleep(GREATEST(0, EXTRACT(EPOCH FROM ($1::timestamptz - clock_timestamp()))) + 0.02)")
        .bind(request.expected.expires_at).execute(&ctx.pool).await.unwrap();
    held.commit().await.unwrap();
    let outcome = running.await.unwrap();
    assert!(
        matches!(&outcome, Err(PrefixdError::Conflict(_))),
        "unexpected extension result: {outcome:?}"
    );
    assert_eq!(
        ctx.repo
            .get_mitigation(request.expected.mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .expires_at,
        request.expected.expires_at
    );
    assert_eq!(audit_count(&ctx).await, 0);
    extension_pool.close().await;
}

#[tokio::test]
async fn postgres_safelist_and_withdrawal_committed_during_lock_wait_refuse_update() {
    for safelist in [false, true] {
        let ctx = common::TestContext::new().await;
        let (extension_repo, extension_pool) = repeatable_read_repository(&ctx).await;
        let request = request(&ctx).await;
        let mut held = ctx.pool.begin().await.unwrap();
        let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *held)
            .await
            .unwrap();
        sqlx::query("SELECT mitigation_id FROM mitigations WHERE mitigation_id = $1 FOR UPDATE")
            .bind(request.expected.mitigation_id)
            .execute(&mut *held)
            .await
            .unwrap();
        let repo = extension_repo;
        let cloned = request.clone();
        let running = tokio::spawn(async move {
            repo.extend_flowspec_lifetime(&cloned, &ControllerFence::new(true))
                .await
        });
        wait_for_row_wait(&ctx, blocker).await;
        if safelist {
            ctx.repo
                .insert_safelist("203.0.113.0/24", "bob", None)
                .await
                .unwrap();
        } else {
            // This transaction already owns the row, matching the lifecycle's
            // immutable withdrawal intent committed before extension resumes.
            let withdrawal = WithdrawalRequest::new(
                &request.expected,
                false,
                "operator",
                "bob",
                "withdraw".into(),
                true,
            )
            .unwrap();
            sqlx::query("INSERT INTO withdrawal_requests(operation_id, mitigation_id, pop, nlri_hash, rule_kind, rule_json, mitigation_updated_at, terminal_status, speaker_delete_required, actor_type, actor, reason, requested_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)")
                .bind(withdrawal.operation_id).bind(withdrawal.mitigation_id).bind(&withdrawal.pop).bind(&withdrawal.nlri_hash)
                .bind(&withdrawal.rule_kind).bind(&withdrawal.rule_json).bind(withdrawal.mitigation_updated_at).bind(&withdrawal.terminal_status)
                .bind(withdrawal.speaker_delete_required).bind(&withdrawal.actor_type).bind(&withdrawal.actor).bind(&withdrawal.reason).bind(withdrawal.requested_at)
                .execute(&mut *held).await.unwrap();
        }
        held.commit().await.unwrap();
        assert!(running.await.unwrap().is_err());
        assert_eq!(audit_count(&ctx).await, 0);
        assert_eq!(
            ctx.repo
                .get_mitigation(request.expected.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .expires_at,
            request.expected.expires_at
        );
        extension_pool.close().await;
    }
}

#[tokio::test]
async fn postgres_expiry_during_audit_wait_rolls_back_the_tentative_update() {
    let ctx = common::TestContext::new().await;
    let mut request = request(&ctx).await;
    request.expected.expires_at = Utc::now() + Duration::milliseconds(900);
    ctx.repo.update_mitigation(&request.expected).await.unwrap();
    request.expected = ctx
        .repo
        .get_mitigation(request.expected.mitigation_id)
        .await
        .unwrap()
        .unwrap();
    sqlx::raw_sql("CREATE FUNCTION hold_extension_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action = 'extend' THEN PERFORM pg_advisory_xact_lock(987654321); END IF; RETURN NEW; END $$; CREATE TRIGGER hold_extension_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION hold_extension_audit();")
        .execute(&ctx.pool).await.unwrap();
    let mut held = ctx.pool.begin().await.unwrap();
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *held)
        .await
        .unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(987654321)")
        .execute(&mut *held)
        .await
        .unwrap();
    let repo = ctx.repo.clone();
    let cloned = request.clone();
    let running = tokio::spawn(async move {
        repo.extend_flowspec_lifetime(&cloned, &ControllerFence::new(true))
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)) AND query LIKE '%INSERT INTO audit_log%')")
                .bind(blocker).fetch_one(&ctx.pool).await.unwrap();
            if waiting { break; } tokio::task::yield_now().await;
        }
    }).await.expect("audit insertion must be demonstrably blocked after the tentative expiry update");
    sqlx::query("SELECT pg_sleep(GREATEST(0, EXTRACT(EPOCH FROM ($1::timestamptz - clock_timestamp()))) + 0.02)")
        .bind(request.expected.expires_at).execute(&ctx.pool).await.unwrap();
    held.commit().await.unwrap();
    assert!(matches!(
        running.await.unwrap(),
        Err(PrefixdError::Conflict(_))
    ));
    let saved = ctx
        .repo
        .get_mitigation(request.expected.mitigation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(saved.expires_at, request.expected.expires_at);
    assert_eq!(saved.updated_at, request.expected.updated_at);
    assert_eq!(audit_count(&ctx).await, 0);
}

#[tokio::test]
async fn postgres_backward_clock_step_returns_noop_without_shortening_or_audit() {
    let ctx = common::TestContext::new().await;
    let request = request(&ctx).await;
    // This schema belongs only to this disposable database. Its isolated pool
    // shadows the clock with two deterministic samples; no host clock changes.
    sqlx::raw_sql("CREATE SCHEMA extension_clock; CREATE SEQUENCE extension_clock.calls; CREATE TABLE extension_clock.samples (sample bigint PRIMARY KEY, stamp timestamptz NOT NULL);")
        .execute(&ctx.pool).await.unwrap();
    sqlx::query("INSERT INTO extension_clock.samples(sample, stamp) VALUES (1, $1), (2, $2)")
        .bind(request.expected.expires_at - Duration::seconds(599))
        .bind(request.expected.expires_at - Duration::seconds(601))
        .execute(&ctx.pool)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE FUNCTION extension_clock.clock_timestamp() RETURNS timestamptz LANGUAGE SQL VOLATILE AS $$ WITH tick AS MATERIALIZED (SELECT LEAST(nextval('extension_clock.calls'), 2) AS sample) SELECT samples.stamp FROM extension_clock.samples samples JOIN tick USING (sample) $$;")
        .execute(&ctx.pool).await.unwrap();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET search_path = extension_clock, pg_catalog, public")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(ctx.pool.connect_options().as_ref().clone())
        .await
        .unwrap();
    let repo = Repository::new(pool.clone());
    let outcome = repo
        .extend_flowspec_lifetime(&request, &ControllerFence::new(true))
        .await
        .unwrap();
    assert!(
        !outcome.extended,
        "the write's clock sample yields a horizon covered by the saved expiry: {outcome:?}"
    );
    assert_eq!(outcome.mitigation.expires_at, request.expected.expires_at);
    assert_eq!(outcome.mitigation.updated_at, request.expected.updated_at);
    let saved = ctx
        .repo
        .get_mitigation(request.expected.mitigation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(saved.expires_at, request.expected.expires_at);
    assert_eq!(saved.updated_at, request.expected.updated_at);
    assert_eq!(audit_count(&ctx).await, 0);
    let samples: i64 = sqlx::query_scalar("SELECT last_value FROM extension_clock.calls")
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
    assert_eq!(
        samples, 3,
        "initial liveness, write decision and final liveness use the scripted clock"
    );
    pool.close().await;
}

#[tokio::test]
async fn postgres_blocked_preparation_recovers_pool_before_blocker_release() {
    let ctx = common::TestContext::new().await;
    let request = request(&ctx).await;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            ctx.pool
                .connect_options()
                .as_ref()
                .clone()
                .application_name("prefixd-lifetime-preparation-test"),
        )
        .await
        .unwrap();
    let mut settings = common::test_settings();
    settings.mode = OperationMode::Enforced;
    let inventory = serde_json::from_value(serde_json::json!({"customers": [{
        "customer_id": "owner", "name": "Owner", "prefixes": ["203.0.113.0/24"]
    }]}))
    .unwrap();
    let state = prefixd::AppState::new(
        settings,
        inventory,
        common::test_playbooks(),
        std::sync::Arc::new(Repository::new(pool.clone())),
        std::sync::Arc::new(prefixd::bgp::MockAnnouncer::new()),
        ".".into(),
    )
    .unwrap();
    let mut held = ctx.pool.begin().await.unwrap();
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *held)
        .await
        .unwrap();
    sqlx::query("LOCK TABLE mitigations IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *held)
        .await
        .unwrap();
    let id = request.expected.mitigation_id;
    // Three retries exceed this pool's capacity while the blocker stays held.
    for attempt in 0..3 {
        let cloned = state.clone();
        let running = tokio::spawn(async move {
            prefixd::domain::extend_flowspec_lifetime(
                &cloned,
                id,
                600,
                "alice".into(),
                "ongoing".into(),
            )
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let waiting: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)) AND application_name = 'prefixd-lifetime-preparation-test' AND query LIKE '%FROM mitigations WHERE mitigation_id = $1%')")
                    .bind(blocker).fetch_one(&ctx.pool).await.unwrap();
                if waiting { break; } tokio::task::yield_now().await;
            }
        }).await.expect("initial mitigation read must demonstrably wait on the held table lock");
        assert!(state.mitigation_lock.try_lock().is_err());
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(7), running)
            .await
            .unwrap()
            .unwrap();
        let blocked: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)) AND application_name = 'prefixd-lifetime-preparation-test'",
        ).bind(blocker).fetch_one(&ctx.pool).await.unwrap();
        eprintln!(
            "attempt={attempt}, blocked_lifetime_statements={blocked}, pool_size={}, pool_idle={}",
            pool.size(),
            pool.num_idle()
        );
        let (probe, timeout_setting): (i32, String) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            sqlx::query_as("SELECT 1::int, current_setting('statement_timeout')").fetch_one(&pool),
        )
        .await
        .expect("the lifetime pool must recover before the blocker is released")
        .unwrap();
        assert_eq!(probe, 1);
        assert_eq!(
            timeout_setting, "0",
            "read settings must not leak into mutation connections"
        );
        assert_eq!(
            blocked, 0,
            "lifetime preparation must leave no blocked server statement"
        );
        assert!(state.mitigation_lock.try_lock().is_ok());
        assert!(
            matches!(outcome, Err(PrefixdError::Database(sqlx::Error::Database(error))) if error.code().as_deref() == Some("57014")),
            "the server deadline must refuse the blocked read"
        );
        assert_eq!(audit_count(&ctx).await, 0);
    }
    held.rollback().await.unwrap();
    let unchanged = ctx.repo.get_mitigation(id).await.unwrap().unwrap();
    assert_eq!(unchanged.expires_at, request.expected.expires_at);
    assert_eq!(unchanged.updated_at, request.expected.updated_at);
    assert_eq!(audit_count(&ctx).await, 0);

    // The normal repository must still perform the atomic extension after the
    // read-only view has recovered; no statement deadline may leak to COMMIT.
    let outcome = prefixd::domain::extend_flowspec_lifetime(
        &state,
        id,
        600,
        "alice".into(),
        "fresh successful retry".into(),
    )
    .await
    .unwrap();
    assert!(outcome.extended);
    assert_eq!(outcome.previous_expires_at, request.expected.expires_at);
    assert!(outcome.mitigation.expires_at > request.expected.expires_at);
    assert_eq!(audit_count(&ctx).await, 1);
    let timeout_setting: String = sqlx::query_scalar("SELECT current_setting('statement_timeout')")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(timeout_setting, "0");
    pool.close().await;
}
