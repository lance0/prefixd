//! Retry evidence must commit with intent, and old ambiguous history stays inert.
mod common;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use prefixd::{
    AppState,
    api::create_test_router,
    db::{ListParams, init_postgres_pool},
    domain::{AttackEvent, AttackEventInput, EventOutcome},
};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tower::ServiceExt;

async fn context() -> common::TestContext {
    let mut ctx = common::TestContext::new().await;
    let mut settings = ctx.state.settings.clone();
    settings.mode = prefixd::config::OperationMode::Enforced;
    ctx.state = AppState::new(
        settings,
        common::test_inventory(),
        common::test_playbooks(),
        ctx.repo.clone(),
        Arc::new(prefixd::bgp::MockAnnouncer::new()),
        ".".into(),
    )
    .unwrap();
    ctx
}

fn event(id: &str) -> Value {
    json!({"event_id": id, "timestamp": "2026-11-16T00:00:00Z", "source": "retry-test",
        "victim_ip": "203.0.113.10", "vector": "udp_flood", "top_dst_ports": [53], "confidence": 0.9})
}

async fn post(state: Arc<AppState>, body: Value) -> (StatusCode, Value) {
    let response = create_test_router(state)
        .oneshot(
            Request::post("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    (
        status,
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap(),
    )
}

async fn stored(ctx: &common::TestContext, id: &str) -> AttackEvent {
    ctx.repo
        .find_ban_event_by_external_id("retry-test", id)
        .await
        .unwrap()
        .unwrap()
}

async fn install_journal_failure(ctx: &common::TestContext) {
    sqlx::raw_sql(
        "CREATE FUNCTION fail_ban_journal() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.outcome_mitigation_ids <> OLD.outcome_mitigation_ids THEN
                RAISE EXCEPTION 'seeded admission journal failure';
            END IF;
            RETURN NEW;
        END $$;
        CREATE TRIGGER fail_ban_journal BEFORE UPDATE ON events
        FOR EACH ROW EXECUTE FUNCTION fail_ban_journal();",
    )
    .execute(&ctx.pool)
    .await
    .unwrap();
}

async fn remove_journal_failure(ctx: &common::TestContext) {
    sqlx::raw_sql("DROP TRIGGER fail_ban_journal ON events; DROP FUNCTION fail_ban_journal();")
        .execute(&ctx.pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn postgres_admission_and_extension_roll_back_with_their_event_association() {
    let ctx = context().await;
    install_journal_failure(&ctx).await;
    let (status, body) = post(ctx.state.clone(), event("create")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    let failed = stored(&ctx, "create").await;
    assert_eq!(failed.outcome.outcome, EventOutcome::Failed);
    assert!(failed.outcome.outcome_mitigation_ids.is_empty());
    assert_eq!(ctx.repo.count_active_global().await.unwrap(), 0);
    let creates: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = 'create'")
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
    assert_eq!(
        creates, 0,
        "journal failure rolls back the creation audit too"
    );
    remove_journal_failure(&ctx).await;
    let (status, body) = post(ctx.state.clone(), event("create")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["event_id"], failed.event_id.to_string());
    let id = body["mitigation_id"].as_str().unwrap().parse().unwrap();
    let created = stored(&ctx, "create").await;
    assert_eq!(created.outcome.outcome_mitigation_ids, [id]);
    assert_eq!(created.outcome.outcome, EventOutcome::Mitigated);

    let mut before = ctx.repo.get_mitigation(id).await.unwrap().unwrap();
    before.expires_at = chrono::Utc::now() + chrono::Duration::seconds(30);
    ctx.repo.update_mitigation(&before).await.unwrap();
    let before = ctx.repo.get_mitigation(id).await.unwrap().unwrap();
    install_journal_failure(&ctx).await;
    let (status, body) = post(ctx.state.clone(), event("extend")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    let unchanged = ctx.repo.get_mitigation(id).await.unwrap().unwrap();
    assert_eq!(unchanged.expires_at, before.expires_at);
    assert_eq!(unchanged.last_event_id, before.last_event_id);
    assert!(
        stored(&ctx, "extend")
            .await
            .outcome
            .outcome_mitigation_ids
            .is_empty()
    );
    remove_journal_failure(&ctx).await;
    let (status, body) = post(ctx.state.clone(), event("extend")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "extended");
    let extended = stored(&ctx, "extend").await;
    assert_eq!(extended.outcome.outcome_mitigation_ids, [id]);
    assert_eq!(extended.outcome.outcome, EventOutcome::Extended);
    assert_eq!(ctx.repo.count_active_global().await.unwrap(), 1);
}

#[tokio::test]
async fn postgres_cancelled_event_before_admission_recovers_once() {
    let ctx = context().await;
    let mut held = ctx.pool.begin().await.unwrap();
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *held)
        .await
        .unwrap();
    sqlx::query("LOCK TABLE safelist IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *held)
        .await
        .unwrap();
    let running = tokio::spawn(post(ctx.state.clone(), event("interrupted")));
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity
                WHERE $1 = ANY(pg_blocking_pids(pid)) AND query LIKE '%FROM safelist%')",
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
    .expect("request reached the safelist read after storing the event");
    let before = stored(&ctx, "interrupted").await;
    assert!(before.ban_retryable);
    assert_eq!(before.outcome.outcome, EventOutcome::NotRecorded);
    assert_eq!(ctx.repo.count_active_global().await.unwrap(), 0);
    running.abort();
    assert!(running.await.unwrap_err().is_cancelled());
    held.rollback().await.unwrap();
    let (status, body) = tokio::time::timeout(
        Duration::from_secs(5),
        post(ctx.state.clone(), event("interrupted")),
    )
    .await
    .unwrap();
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["event_id"], before.event_id.to_string());
    assert_eq!(ctx.repo.count_active_global().await.unwrap(), 1);
    let (status, body) = post(ctx.state.clone(), event("interrupted")).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["event_outcome"]["outcome"], "mitigated");
    assert_eq!(
        ctx.repo
            .list_events(&ListParams {
                limit: 100,
                ..Default::default()
            })
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn postgres_failed_final_outcome_never_erases_committed_admission() {
    let ctx = context().await;
    sqlx::raw_sql(
        "CREATE FUNCTION fail_final_outcome() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.outcome IS NOT NULL THEN RAISE EXCEPTION 'seeded final outcome failure'; END IF;
            RETURN NEW;
        END $$;
        CREATE TRIGGER fail_final_outcome BEFORE UPDATE ON events
        FOR EACH ROW EXECUTE FUNCTION fail_final_outcome();",
    )
    .execute(&ctx.pool)
    .await
    .unwrap();
    let (status, body) = post(ctx.state.clone(), event("lost-outcome")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let saved = stored(&ctx, "lost-outcome").await;
    assert_eq!(saved.outcome.outcome, EventOutcome::NotRecorded);
    assert_eq!(
        serde_json::to_value(&saved.outcome.outcome_mitigation_ids).unwrap(),
        body["mitigation_ids"]
    );
    let (status, replay) = post(ctx.state.clone(), event("lost-outcome")).await;
    assert_eq!(status, StatusCode::CONFLICT, "{replay}");
    assert_eq!(
        replay["event_outcome"],
        serde_json::to_value(saved.outcome).unwrap()
    );
    assert_eq!(ctx.repo.count_active_global().await.unwrap(), 1);
    sqlx::raw_sql("DROP TRIGGER fail_final_outcome ON events; DROP FUNCTION fail_final_outcome();")
        .execute(&ctx.pool)
        .await
        .unwrap();
    ctx.repo
        .record_event_outcome(
            saved.event_id,
            &prefixd::domain::EventOutcomeRecord::new(
                EventOutcome::Failed,
                Some("503 Service Unavailable; see controller logs".into()),
                Vec::new(),
            ),
        )
        .await
        .unwrap();
    let failed = stored(&ctx, "lost-outcome").await;
    assert_eq!(
        serde_json::to_value(&failed.outcome.outcome_mitigation_ids).unwrap(),
        body["mitigation_ids"]
    );
    let (status, replay) = post(ctx.state.clone(), event("lost-outcome")).await;
    assert_eq!(status, StatusCode::CONFLICT, "{replay}");
    assert_eq!(
        replay["event_outcome"],
        serde_json::to_value(failed.outcome).unwrap()
    );
}

#[tokio::test]
async fn postgres_migration_preserves_ambiguous_legacy_extension_after_withdrawal() {
    let ctx = context().await;
    let (status, created) = post(ctx.state.clone(), event("original")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{created}");
    let (status, extension) = post(ctx.state.clone(), event("legacy-interrupted")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{extension}");
    // Reproduce the old cancellation boundary: extension committed, but its
    // outcome did not. A later extension overwrites last_event_id.
    sqlx::query(
        "UPDATE events SET outcome = NULL, outcome_reason = NULL, outcome_mitigation_ids = '{}'
        WHERE external_event_id = 'legacy-interrupted'",
    )
    .execute(&ctx.pool)
    .await
    .unwrap();
    let (status, later) = post(ctx.state.clone(), event("later-extension")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{later}");
    let mut unban = event("resolve");
    unban["action"] = json!("unban");
    let (status, body) = post(ctx.state.clone(), unban).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let id = created["mitigation_id"].as_str().unwrap().parse().unwrap();
    let withdrawn = ctx.repo.get_mitigation(id).await.unwrap().unwrap();
    assert_eq!(withdrawn.last_event_id.to_string(), later["event_id"]);
    assert_eq!(
        withdrawn.status,
        prefixd::domain::MitigationStatus::Withdrawn
    );
    let before = stored(&ctx, "legacy-interrupted").await;
    let audits_before = ctx
        .repo
        .list_audit(&ListParams {
            limit: 100,
            ..Default::default()
        })
        .await
        .unwrap()
        .len();

    sqlx::raw_sql(
        "ALTER TABLE events DROP COLUMN ban_retryable;
        DELETE FROM schema_migrations WHERE version = 26;",
    )
    .execute(&ctx.pool)
    .await
    .unwrap();
    for _ in 0..2 {
        init_postgres_pool(&ctx.state.settings.storage.connection_string)
            .await
            .unwrap()
            .close()
            .await;
    }
    let legacy = stored(&ctx, "legacy-interrupted").await;
    assert!(!legacy.ban_retryable);
    assert_eq!(legacy.event_id, before.event_id);
    assert_eq!(legacy.outcome, before.outcome);
    let (status, refused) = post(ctx.state.clone(), event("legacy-interrupted")).await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert!(
        refused["error"]
            .as_str()
            .unwrap()
            .contains("historical ban admission outcome is unknown")
    );
    assert!(refused.get("event_outcome").is_none());
    assert_eq!(ctx.repo.count_active_global().await.unwrap(), 0);
    assert_eq!(
        ctx.repo
            .get_mitigation(id)
            .await
            .unwrap()
            .unwrap()
            .updated_at,
        withdrawn.updated_at
    );
    assert_eq!(
        ctx.repo
            .list_audit(&ListParams {
                limit: 100,
                ..Default::default()
            })
            .await
            .unwrap()
            .len(),
        audits_before
    );
    assert_eq!(
        stored(&ctx, "legacy-interrupted").await.outcome,
        before.outcome
    );
    assert!(
        serde_json::to_value(&legacy)
            .unwrap()
            .get("ban_retryable")
            .is_none()
    );
    let schema = serde_json::to_value(<AttackEvent as utoipa::PartialSchema>::schema()).unwrap();
    assert!(!schema.to_string().contains("ban_retryable"));

    let fresh = AttackEvent::from_input(
        serde_json::from_value::<AttackEventInput>(event("fresh-interrupted")).unwrap(),
    );
    ctx.repo.insert_event(&fresh).await.unwrap();
    assert!(stored(&ctx, "fresh-interrupted").await.ban_retryable);
    let (status, resumed) = post(ctx.state.clone(), event("fresh-interrupted")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{resumed}");
    assert_eq!(resumed["event_id"], fresh.event_id.to_string());
}

#[tokio::test]
async fn postgres_retry_waits_for_a_cancelled_requests_inflight_commit() {
    let ctx = context().await;
    let mut held = ctx.pool.begin().await.unwrap();
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *held)
        .await
        .unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(77282, 3374)")
        .execute(&mut *held)
        .await
        .unwrap();
    sqlx::raw_sql(
        "CREATE FUNCTION hold_admission_commit() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN PERFORM pg_advisory_xact_lock(77282, 3374); RETURN NEW; END $$;
        CREATE CONSTRAINT TRIGGER hold_admission_commit AFTER INSERT ON mitigations
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hold_admission_commit();",
    )
    .execute(&ctx.pool)
    .await
    .unwrap();
    let running = tokio::spawn(post(ctx.state.clone(), event("commit-inflight")));
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity
                WHERE $1 = ANY(pg_blocking_pids(pid)) AND query = 'COMMIT')",
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
    .expect("admission sent COMMIT, whose deferred trigger is blocked");
    running.abort();
    assert!(running.await.unwrap_err().is_cancelled());
    let retry = tokio::spawn(post(ctx.state.clone(), event("commit-inflight")));
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity
                WHERE wait_event_type = 'Lock' AND query LIKE '%FOR UPDATE%'
                  AND query NOT LIKE '%pg_stat_activity%')",
            )
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
    .expect("duplicate lookup waits for the event's in-flight commit");
    held.commit().await.unwrap();
    let (status, body) = tokio::time::timeout(Duration::from_secs(5), retry)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["event_outcome"]["outcome"], "not_recorded");
    assert_eq!(
        body["event_outcome"]["outcome_mitigation_ids"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(ctx.repo.count_active_global().await.unwrap(), 1);
    assert_eq!(
        ctx.repo
            .list_events(&ListParams {
                limit: 100,
                ..Default::default()
            })
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn postgres_extension_waits_for_pending_withdrawal_commit_then_refuses() {
    let ctx = context().await;
    let (status, accepted) = post(ctx.state.clone(), event("original")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{accepted}");
    let id = accepted["mitigation_id"].as_str().unwrap().parse().unwrap();
    let before = ctx.repo.get_mitigation(id).await.unwrap().unwrap();
    let mut request = prefixd::domain::WithdrawalRequest::new(
        &before,
        false,
        "detector",
        "original-detector",
        "original resolve".into(),
        true,
    )
    .unwrap();
    request.detector_source = Some("retry-test".into());

    let mut barrier = ctx.pool.begin().await.unwrap();
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *barrier)
        .await
        .unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(77282, 3375)")
        .execute(&mut *barrier)
        .await
        .unwrap();
    sqlx::raw_sql(
        "CREATE FUNCTION hold_withdrawal_commit() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN PERFORM pg_advisory_xact_lock(77282, 3375); RETURN NEW; END $$;
        CREATE CONSTRAINT TRIGGER hold_withdrawal_commit AFTER INSERT ON withdrawal_requests
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hold_withdrawal_commit();",
    )
    .execute(&ctx.pool)
    .await
    .unwrap();
    // The unban protocol locks the selected row before storing immutable intent.
    // Reproduce its transaction boundary without a speaker RPC or wall-clock sleep.
    let mut unban = ctx.pool.begin().await.unwrap();
    sqlx::query("SELECT mitigation_id FROM mitigations WHERE mitigation_id = $1 FOR UPDATE")
        .bind(id)
        .execute(&mut *unban)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO withdrawal_requests
        (operation_id, mitigation_id, pop, nlri_hash, rule_json, mitigation_updated_at,
         terminal_status, actor_type, actor, reason, requested_at, speaker_delete_required,
         target_id, rule_kind, detector_source)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
    )
    .bind(request.operation_id)
    .bind(id)
    .bind(&request.pop)
    .bind(&request.nlri_hash)
    .bind(&request.rule_json)
    .bind(request.mitigation_updated_at)
    .bind(&request.terminal_status)
    .bind(&request.actor_type)
    .bind(&request.actor)
    .bind(&request.reason)
    .bind(request.requested_at)
    .bind(request.speaker_delete_required)
    .bind(request.target_id)
    .bind(&request.rule_kind)
    .bind(&request.detector_source)
    .execute(&mut *unban)
    .await
    .unwrap();
    let committing = tokio::spawn(async move { unban.commit().await });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity
                WHERE $1 = ANY(pg_blocking_pids(pid)) AND query = 'COMMIT')",
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
    .expect("withdrawal COMMIT reached the database barrier");
    committing.abort();
    assert!(committing.await.unwrap_err().is_cancelled());
    assert!(ctx.repo.pending_withdrawals(None).await.unwrap().is_empty());

    let extending = tokio::spawn(post(ctx.state.clone(), event("while-unban-commits")));
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity
                WHERE wait_event_type = 'Lock' AND query LIKE 'SELECT * FROM mitigations%FOR UPDATE'
                  AND query NOT LIKE '%pg_stat_activity%')",
            )
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
    .expect("ban read the old row then waited for the withdrawal transaction");
    barrier.commit().await.unwrap();
    let (status, refused) = tokio::time::timeout(Duration::from_secs(5), extending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{refused}");
    assert_eq!(ctx.repo.get_mitigation(id).await.unwrap().unwrap(), before);
    let failed = stored(&ctx, "while-unban-commits").await;
    assert_eq!(failed.outcome.outcome, EventOutcome::Failed);
    assert!(failed.outcome.outcome_mitigation_ids.is_empty());
    let pending = ctx.repo.pending_withdrawals(None).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].operation_id, request.operation_id);
    assert_eq!(pending[0].rule_json, request.rule_json);
    assert_eq!(pending[0].actor, request.actor);
    assert_eq!(pending[0].reason, request.reason);
    assert_eq!(pending[0].mitigation_updated_at, before.updated_at);
}

#[tokio::test]
async fn postgres_extension_checks_complete_snapshot_without_timestamp_change() {
    let ctx = context().await;
    let (status, accepted) = post(ctx.state.clone(), event("original")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{accepted}");
    let id = accepted["mitigation_id"].as_str().unwrap().parse().unwrap();
    let expected = ctx.repo.get_mitigation(id).await.unwrap().unwrap();
    let attempt = AttackEvent::from_input(
        serde_json::from_value::<AttackEventInput>(event("stale-owner")).unwrap(),
    );
    ctx.repo.insert_event(&attempt).await.unwrap();
    let mut proposed = expected.clone();
    proposed.extend_ttl(600, attempt.event_id);
    let mut changed = expected.clone();
    changed.action_params.injection_owner = "new-owner".into();
    ctx.repo.update_mitigation(&changed).await.unwrap();
    let changed = ctx.repo.get_mitigation(id).await.unwrap().unwrap();
    assert_eq!(changed.updated_at, expected.updated_at);
    assert!(matches!(
        ctx.repo
            .extend_mitigation_for_event(&expected, &proposed)
            .await,
        Err(prefixd::error::PrefixdError::BanAdmissionChanged),
    ));
    assert_eq!(ctx.repo.get_mitigation(id).await.unwrap().unwrap(), changed);
    assert!(
        stored(&ctx, "stale-owner")
            .await
            .outcome
            .outcome_mitigation_ids
            .is_empty()
    );
}

#[tokio::test]
async fn postgres_outcome_write_is_bounded_while_event_row_stays_locked() {
    let ctx = context().await;
    let (status, accepted) = post(ctx.state.clone(), event("held-outcome")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{accepted}");
    // Reproduce admission committed with no final outcome recorded yet.
    sqlx::query("UPDATE events SET outcome = NULL WHERE external_event_id = 'held-outcome'")
        .execute(&ctx.pool)
        .await
        .unwrap();
    let before = stored(&ctx, "held-outcome").await;
    assert_eq!(before.outcome.outcome_mitigation_ids.len(), 1);
    let mut held = ctx.pool.begin().await.unwrap();
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *held)
        .await
        .unwrap();
    sqlx::query("SELECT event_id FROM events WHERE event_id = $1 FOR UPDATE")
        .bind(before.event_id)
        .execute(&mut *held)
        .await
        .unwrap();
    let repo = ctx.repo.clone();
    let event_id = before.event_id;
    let writing = tokio::spawn(async move {
        repo.record_event_outcome(
            event_id,
            &prefixd::domain::EventOutcomeRecord::new(
                EventOutcome::Failed,
                Some("attempt interrupted".into()),
                Vec::new(),
            ),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity
                WHERE $1 = ANY(pg_blocking_pids(pid)) AND query LIKE 'UPDATE events SET outcome%')",
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
    .expect("outcome UPDATE reached the held event-row lock");
    let failed = tokio::time::timeout(Duration::from_secs(5), writing)
        .await
        .expect("server deadline bounds the write without releasing the blocker")
        .unwrap()
        .unwrap_err();
    let prefixd::error::PrefixdError::Database(sqlx::Error::Database(error)) = failed else {
        panic!("expected PostgreSQL timeout, got {failed}");
    };
    assert!(matches!(error.code().as_deref(), Some("55P03" | "57014")));
    held.rollback().await.unwrap();
    assert_eq!(stored(&ctx, "held-outcome").await.outcome, before.outcome);
}

#[tokio::test]
async fn postgres_duplicate_lookup_is_bounded_while_matching_event_stays_locked() {
    let ctx = context().await;
    let (status, accepted) = post(ctx.state.clone(), event("held-lookup")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{accepted}");
    let before = stored(&ctx, "held-lookup").await;
    let mut held = ctx.pool.begin().await.unwrap();
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *held)
        .await
        .unwrap();
    sqlx::query("SELECT event_id FROM events WHERE event_id = $1 FOR UPDATE")
        .bind(before.event_id)
        .execute(&mut *held)
        .await
        .unwrap();
    let repo = ctx.repo.clone();
    // Shorter than the repository's outer five-second deadline: removing the
    // server bounds must fail this watchdog, not succeed through that fallback.
    let watchdog = tokio::time::Instant::now() + Duration::from_millis(4500);
    let reading = tokio::spawn(async move {
        repo.find_ban_event_by_external_id("retry-test", "held-lookup")
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity
                WHERE $1 = ANY(pg_blocking_pids(pid)) AND query LIKE '%FROM events%FOR UPDATE%')",
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
    .expect("duplicate lookup reached the held event-row lock");
    let failed = tokio::time::timeout_at(watchdog, reading)
        .await
        .expect("server deadline returned while matching event remained locked")
        .unwrap()
        .unwrap_err();
    let prefixd::error::PrefixdError::Database(sqlx::Error::Database(error)) = failed else {
        panic!("expected PostgreSQL timeout, got {failed}");
    };
    assert!(matches!(error.code().as_deref(), Some("55P03" | "57014")));

    let (status, failed) = tokio::time::timeout(
        Duration::from_secs(6),
        post(ctx.state.clone(), event("held-lookup")),
    )
    .await
    .expect("HTTP lookup failure releases its lifecycle turn");
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{failed}");
    assert!(failed.get("event_outcome").is_none());
    assert!(ctx.state.mitigation_lock.try_lock().is_ok());
    let mut independent = event("independent-of-held-event");
    independent["victim_ip"] = json!("203.0.113.11");
    let (status, accepted) =
        tokio::time::timeout(Duration::from_secs(5), post(ctx.state.clone(), independent))
            .await
            .expect("independent admission progresses while the old event stays locked");
    assert_eq!(status, StatusCode::ACCEPTED, "{accepted}");
    held.rollback().await.unwrap();
    assert_eq!(stored(&ctx, "held-lookup").await.outcome, before.outcome);
}

#[tokio::test]
async fn postgres_duplicate_lookup_bounds_pool_acquisition() {
    let ctx = context().await;
    let mut held = Vec::new();
    for _ in 0..10 {
        held.push(ctx.pool.acquire().await.unwrap());
    }
    assert_eq!(ctx.pool.num_idle(), 0);
    let failed = tokio::time::timeout(
        Duration::from_secs(6),
        ctx.repo
            .find_ban_event_by_external_id("retry-test", "pool-held"),
    )
    .await
    .expect("outer lookup deadline bounds exhausted pool acquisition")
    .unwrap_err();
    assert!(matches!(
        failed,
        prefixd::error::PrefixdError::Database(sqlx::Error::PoolTimedOut)
    ));
    assert_eq!(
        ctx.pool.num_idle(),
        0,
        "connections were held until after the deadline"
    );
    drop(held);
    tokio::time::timeout(Duration::from_secs(5), ctx.pool.close())
        .await
        .expect("detached BEGIN result is cleaned up after cancellation");
}
