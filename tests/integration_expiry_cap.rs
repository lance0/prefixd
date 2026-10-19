mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use chrono::{DateTime, Duration, Utc};
use prefixd::{
    AppState,
    bgp::{FlowSpecAnnouncer, FlowSpecReader, FlowSpecWriter, MockAnnouncer},
    domain::{FlowSpecRule, MitigationStatus},
    error::Result,
    scheduler::ReconciliationLoop,
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
};
use tower::ServiceExt;

#[derive(Default)]
struct Speaker {
    inner: MockAnnouncer,
    announcements: AtomicUsize,
    pause_inventory: AtomicBool,
    inventory_entered: tokio::sync::Notify,
    inventory_release: tokio::sync::Notify,
}

impl FlowSpecAnnouncer for Speaker {
    fn backend(&self) -> &'static str {
        "mock"
    }
    fn reader(&self) -> Option<&dyn FlowSpecReader> {
        Some(self)
    }
}

#[async_trait::async_trait]
impl FlowSpecWriter for Speaker {
    async fn announce(&self, rule: &FlowSpecRule) -> Result<()> {
        self.announcements.fetch_add(1, SeqCst);
        self.inner.announce(rule).await
    }
    async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()> {
        self.inner.withdraw(rule).await
    }
}

#[async_trait::async_trait]
impl FlowSpecReader for Speaker {
    async fn list_active(&self) -> Result<Vec<FlowSpecRule>> {
        if self.pause_inventory.swap(false, SeqCst) {
            self.inventory_entered.notify_one();
            self.inventory_release.notified().await;
        }
        self.inner.list_active().await
    }
}

fn state(context: &common::TestContext, speaker: Arc<Speaker>) -> Arc<AppState> {
    let mut settings = context.state.settings.clone();
    settings.mode = prefixd::config::OperationMode::Enforced;
    settings.guardrails.min_ttl_seconds = Some(1);
    AppState::new(
        settings,
        common::test_inventory(),
        common::test_playbooks(),
        context.repo.clone(),
        speaker,
        ".".into(),
    )
    .unwrap()
}

fn request(ip: &str, cap: Option<DateTime<Utc>>) -> Request<Body> {
    let mut payload = json!({"victim_ip":ip, "protocol":"udp", "dst_ports":[53],
        "action":"discard", "ttl_seconds":60, "reason":"expiry cap fixture"});
    if let Some(cap) = cap {
        payload["expires_at_cap"] = json!(cap);
    }
    Request::builder()
        .method("POST")
        .uri("/v1/mitigations")
        .header("content-type", "application/json")
        .body(Body::from(payload.to_string()))
        .unwrap()
}

async fn body(response: axum::response::Response) -> Value {
    serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap()
}

async fn wait_for_blocked_query(pool: &sqlx::PgPool, table: &str) {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_locks l JOIN pg_class c ON c.oid=l.relation WHERE NOT l.granted AND c.relname=$1 AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database()))")
                .bind(table).fetch_one(pool).await.unwrap();
            if waiting { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("request must reach the controlled database lock");
}

async fn wait_until_expired(cap: DateTime<Utc>) {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while Utc::now() <= cap {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("wall-clock deadline must pass before releasing database work");
}

fn deadline_after(seconds: i64) -> DateTime<Utc> {
    DateTime::from_timestamp_micros((Utc::now() + Duration::seconds(seconds)).timestamp_micros())
        .unwrap()
}

#[tokio::test]
async fn manual_creation_caps_expiry_without_extending_or_weakening_ttl() {
    let context = common::TestContext::new().await;
    let speaker = Arc::new(Speaker::default());
    let state = state(&context, speaker.clone());
    let app = prefixd::api::create_test_router(state.clone());
    let before = deadline_after(0);
    for (index, cap) in [
        None,
        Some(before + Duration::seconds(40)),
        Some(before + Duration::hours(1)),
    ]
    .into_iter()
    .enumerate()
    {
        let response = app
            .clone()
            .oneshot(request(&format!("203.0.113.{}", 30 + index), cap))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let value = body(response).await;
        assert!(value.get("announcement_outcome").is_none());
        let id = value["mitigation_id"].as_str().unwrap().parse().unwrap();
        let mitigation = state.repo.get_mitigation(id).await.unwrap().unwrap();
        assert_eq!(
            mitigation.expires_at,
            if index == 1 {
                cap.unwrap()
            } else {
                mitigation.created_at + Duration::seconds(60)
            }
        );
    }
    let count = speaker.announcements.load(SeqCst);
    for cap in [
        Utc::now() - Duration::seconds(1),
        Utc::now() + Duration::milliseconds(500),
    ] {
        let response = app
            .clone()
            .oneshot(request("203.0.113.40", Some(cap)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
    assert_eq!(speaker.announcements.load(SeqCst), count);
    assert_eq!(state.repo.count_active_global().await.unwrap(), 3);
    let spec = body(
        app.oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap(),
    )
    .await;
    assert!(
        spec["components"]["schemas"]["CreateMitigationRequest"]["properties"]["expires_at_cap"]
            .is_object()
    );
}

#[tokio::test]
async fn expired_cap_after_preflight_wait_creates_nothing() {
    let context = common::TestContext::new().await;
    let speaker = Arc::new(Speaker::default());
    let state = state(&context, speaker.clone());
    let mut gate = context.pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE safelist IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *gate)
        .await
        .unwrap();
    let cap = deadline_after(2);
    let app = prefixd::api::create_test_router(state.clone());
    let task = tokio::spawn(async move {
        app.oneshot(request("203.0.113.50", Some(cap)))
            .await
            .unwrap()
    });
    wait_for_blocked_query(&context.pool, "safelist").await;
    wait_until_expired(cap).await;
    gate.commit().await.unwrap();
    assert_eq!(
        task.await.unwrap().status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(state.repo.count_active_global().await.unwrap(), 0);
    assert_eq!(speaker.announcements.load(SeqCst), 0);
}

#[tokio::test]
async fn expiry_during_insert_retains_intent_and_never_announces_it() {
    let context = common::TestContext::new().await;
    let speaker = Arc::new(Speaker::default());
    let state = state(&context, speaker.clone());
    let mut gate = context.pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE mitigations IN SHARE MODE")
        .execute(&mut *gate)
        .await
        .unwrap();
    let cap = deadline_after(2);
    let app = prefixd::api::create_test_router(state.clone());
    let task = tokio::spawn(async move {
        app.oneshot(request("203.0.113.51", Some(cap)))
            .await
            .unwrap()
    });
    wait_for_blocked_query(&context.pool, "mitigations").await;
    wait_until_expired(cap).await;
    gate.commit().await.unwrap();
    let response = task.await.unwrap();
    assert_eq!(
        speaker.announcements.load(SeqCst),
        0,
        "expired persisted intent must not start an RPC"
    );
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let value = body(response).await;
    assert_eq!(value["announcement_outcome"], "unconfirmed");
    let id = value["mitigation_id"].as_str().unwrap().parse().unwrap();
    assert_eq!(
        state
            .repo
            .get_mitigation(id)
            .await
            .unwrap()
            .unwrap()
            .expires_at,
        cap
    );
    assert_eq!(speaker.announcements.load(SeqCst), 0);
    let reconciler = ReconciliationLoop::new(state.repo.clone(), speaker.clone(), 30, false)
        .with_app_state(state.clone());
    reconciler.reconcile().await.unwrap();
    assert_eq!(
        state.repo.get_mitigation(id).await.unwrap().unwrap().status,
        MitigationStatus::Expired
    );
    reconciler.reconcile().await.unwrap();
    assert_eq!(speaker.announcements.load(SeqCst), 0);
}

#[tokio::test]
async fn repair_rechecks_expiry_after_pending_cleanup_read() {
    for action_drift in [false, true] {
        let context = common::TestContext::new().await;
        let speaker = Arc::new(Speaker::default());
        let state = state(&context, speaker.clone());
        let app = prefixd::api::create_test_router(state.clone());
        let value = body(app.oneshot(request("203.0.113.52", None)).await.unwrap()).await;
        let id = value["mitigation_id"].as_str().unwrap().parse().unwrap();
        let mut mitigation = state.repo.get_mitigation(id).await.unwrap().unwrap();
        let cap = deadline_after(2);
        mitigation.expires_at = cap;
        state.repo.update_mitigation(&mitigation).await.unwrap();
        let mut rule = prefixd::domain::mitigation_rule(&mitigation).unwrap();
        if action_drift {
            rule.actions = vec![prefixd::domain::FlowSpecAction::police(9)];
            speaker.inner.announce(&rule).await.unwrap();
        } else {
            speaker.inner.withdraw(&rule).await.unwrap();
        }
        let before = speaker.announcements.load(SeqCst);
        speaker.pause_inventory.store(true, SeqCst);
        let reconciler = Arc::new(
            ReconciliationLoop::new(state.repo.clone(), speaker.clone(), 30, false)
                .with_app_state(state.clone()),
        );
        let task = tokio::spawn({
            let reconciler = reconciler.clone();
            async move { reconciler.reconcile().await.unwrap() }
        });
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            speaker.inventory_entered.notified(),
        )
        .await
        .unwrap();
        let mut gate = context.pool.begin().await.unwrap();
        sqlx::query("LOCK TABLE withdrawal_requests IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *gate)
            .await
            .unwrap();
        speaker.inventory_release.notify_one();
        wait_for_blocked_query(&context.pool, "withdrawal_requests").await;
        wait_until_expired(cap).await;
        gate.commit().await.unwrap();
        task.await.unwrap();
        assert_eq!(speaker.announcements.load(SeqCst), before);
        reconciler.reconcile().await.unwrap();
        assert_eq!(speaker.announcements.load(SeqCst), before);
    }
}
