//! Controller fence (ADR 027): two controller instances share one disposable
//! PostgreSQL, each with its own fence connection and fake speaker.
mod common;

use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use sqlx::postgres::PgConnectOptions;
use tower::ServiceExt;

use common::{TestContext, test_inventory, test_playbooks};
use prefixd::AppState;
use prefixd::bgp::{
    FlowSpecAnnouncer, FlowSpecReader, FlowSpecWriter, MockAnnouncer, PeerObserver,
};
use prefixd::config::OperationMode;
use prefixd::domain::{FlowSpecRule, SpeakerTarget, VerifiedSpeakerBinding};
use prefixd::error::{PrefixdError, Result};
use prefixd::fence::{ControllerFence, FencedAnnouncer, fence_lock_key, maintain, try_acquire};
use prefixd::scheduler::ReconciliationLoop;

/// Fake speaker that counts every mutation RPC it receives.
#[derive(Default)]
struct CountingSpeaker {
    inner: MockAnnouncer,
    mutations: AtomicUsize,
}

impl FlowSpecAnnouncer for CountingSpeaker {
    fn backend(&self) -> &'static str {
        "mock"
    }
    fn reader(&self) -> Option<&dyn FlowSpecReader> {
        Some(&self.inner)
    }
    fn peer_observer(&self) -> Option<&dyn PeerObserver> {
        Some(&self.inner)
    }
}

#[async_trait]
impl FlowSpecWriter for CountingSpeaker {
    async fn announce(&self, rule: &FlowSpecRule) -> Result<()> {
        self.mutations.fetch_add(1, SeqCst);
        self.inner.announce(rule).await
    }
    async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()> {
        self.mutations.fetch_add(1, SeqCst);
        self.inner.withdraw(rule).await
    }
}

struct Instance {
    state: Arc<AppState>,
    speaker: Arc<CountingSpeaker>,
    fence: Arc<ControllerFence>,
    reconciler: ReconciliationLoop,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Instance {
    fn mutations(&self) -> usize {
        self.speaker.mutations.load(SeqCst)
    }

    async fn ingest(&self) -> StatusCode {
        let event = r#"{
            "timestamp": "2026-01-17T10:00:00Z",
            "source": "fence_test",
            "victim_ip": "203.0.113.10",
            "vector": "syn_flood",
            "bps": 100000000,
            "pps": 50000,
            "confidence": 0.9
        }"#;
        prefixd::api::create_test_router(self.state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/events")
                    .header("content-type", "application/json")
                    .body(Body::from(event))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    async fn readiness(&self) -> (StatusCode, serde_json::Value) {
        let response = prefixd::api::create_test_router(self.state.clone())
            .oneshot(
                Request::builder()
                    .uri("/v1/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    async fn wait_until(&self, active: bool, limit: Duration) -> Duration {
        let start = Instant::now();
        tokio::time::timeout(limit, self.fence.subscribe().wait_for(|a| *a == active))
            .await
            .unwrap_or_else(|_| panic!("fence did not become active={active} within {limit:?}"))
            .unwrap();
        start.elapsed()
    }
}

async fn binding(ctx: &TestContext) -> VerifiedSpeakerBinding {
    ctx.repo
        .register_speaker_target(
            &ctx.state.settings.pop,
            &SpeakerTarget::from_config(&ctx.state.settings.bgp).unwrap(),
            false,
        )
        .await
        .unwrap()
}

/// Start a controller the way `main` does. `fenced = false` is the negative
/// control: no lock acquisition, so the instance always runs active.
async fn start(ctx: &TestContext, fenced: bool, poll: Duration, check: Duration) -> Instance {
    let binding = binding(ctx).await;
    let speaker = Arc::new(CountingSpeaker::default());
    let options =
        PgConnectOptions::from_str(&ctx.state.settings.storage.connection_string).unwrap();
    let key = fence_lock_key(&binding.owner());
    let (fence, task) = if fenced {
        let held = try_acquire(&options, key).await.unwrap();
        let fence = Arc::new(ControllerFence::new(held.is_some()));
        let task = tokio::spawn(maintain(fence.clone(), options, key, held, poll, check));
        (fence, Some(task))
    } else {
        (Arc::new(ControllerFence::new(true)), None)
    };
    let mut settings = ctx.state.settings.clone();
    settings.mode = OperationMode::Enforced;
    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        ctx.repo.clone(),
        Arc::new(FencedAnnouncer::new(speaker.clone(), fence.clone())),
        ".".into(),
    )
    .unwrap()
    .with_speaker_binding(binding)
    .unwrap()
    .with_fence(fence.clone())
    .unwrap();
    let reconciler =
        ReconciliationLoop::new(state.repo.clone(), state.announcer.clone(), 30, false)
            .with_app_state(state.clone());
    Instance {
        state,
        speaker,
        fence,
        reconciler,
        task,
    }
}

/// Backend PID holding this owner's fence, through the single-bigint lock form.
async fn fence_holder(ctx: &TestContext, owner: &str) -> Option<i32> {
    let key = fence_lock_key(owner) as u64;
    sqlx::query_scalar(
        "SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted \
         AND objsubid = 1 AND classid::bigint = $1 AND objid::bigint = $2",
    )
    .bind((key >> 32) as i64)
    .bind((key & 0xffff_ffff) as i64)
    .fetch_optional(&ctx.pool)
    .await
    .unwrap()
}

const SLOW: Duration = Duration::from_secs(60);

/// Drive both instances through the same mutation opportunities: an event
/// ingest each, then a reconciliation each. Each fake speaker starts empty, so
/// any active instance repairs the persisted mitigation.
async fn exercise(first: &Instance, second: &Instance) -> (StatusCode, StatusCode) {
    let statuses = (first.ingest().await, second.ingest().await);
    let _ = first.reconciler.reconcile().await;
    let _ = second.reconciler.reconcile().await;
    statuses
}

#[tokio::test]
async fn exactly_one_controller_is_active_and_the_standby_sends_no_mutation() {
    let ctx = TestContext::new().await;
    let active = start(&ctx, true, SLOW, SLOW).await;
    let standby = start(&ctx, true, SLOW, SLOW).await;
    assert!(active.fence.is_active());
    assert!(!standby.fence.is_active());
    let owner = binding(&ctx).await.owner();
    assert!(fence_holder(&ctx, &owner).await.is_some());
    // Load balancers and detectors route by readiness, not liveness.
    assert_eq!(
        active.readiness().await,
        (StatusCode::OK, serde_json::json!({"status": "ready"}))
    );
    assert_eq!(
        standby.readiness().await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({"status": "standby"})
        )
    );

    let (first, second) = exercise(&active, &standby).await;
    assert_eq!(first, StatusCode::ACCEPTED);
    assert_eq!(second, StatusCode::SERVICE_UNAVAILABLE);
    assert!(active.mutations() > 0);
    assert_eq!(standby.mutations(), 0, "standby sent a mutation RPC");
    assert!(matches!(
        standby
            .reconciler
            .reconcile()
            .await
            .unwrap_err()
            .downcast_ref::<PrefixdError>(),
        Some(PrefixdError::Standby)
    ));
    assert_eq!(standby.mutations(), 0);
}

/// Negative control for the test above: without lock acquisition both
/// instances act on the same POP and both send mutation RPCs.
#[tokio::test]
async fn negative_control_without_the_fence_both_instances_mutate() {
    let ctx = TestContext::new().await;
    let first = start(&ctx, false, SLOW, SLOW).await;
    let second = start(&ctx, false, SLOW, SLOW).await;
    exercise(&first, &second).await;
    assert!(first.mutations() > 0);
    assert!(second.mutations() > 0, "both unfenced instances mutate");
}

#[tokio::test]
async fn standby_takes_over_within_the_poll_interval_when_the_active_instance_dies() {
    let ctx = TestContext::new().await;
    let poll = Duration::from_secs(1);
    let mut active = start(&ctx, true, poll, SLOW).await;
    let standby = start(&ctx, true, poll, SLOW).await;
    assert!(active.fence.is_active() && !standby.fence.is_active());

    // Killing the task drops its fence session; PostgreSQL releases the lock.
    active.task.take().unwrap().abort();
    let took = standby.wait_until(true, poll * 3).await;
    // One poll plus a connection setup allowance.
    assert!(
        took <= poll + Duration::from_millis(500),
        "takeover took {took:?}"
    );
    assert_eq!(standby.ingest().await, StatusCode::ACCEPTED);
    assert!(standby.mutations() > 0);
    assert_eq!(standby.readiness().await.0, StatusCode::OK);
}

#[tokio::test]
async fn dropping_the_fence_connection_forces_standby_then_reacquires() {
    let ctx = TestContext::new().await;
    let check = Duration::from_millis(200);
    let poll = Duration::from_secs(3);
    let instance = start(&ctx, true, poll, check).await;
    let owner = binding(&ctx).await.owner();
    let pid = fence_holder(&ctx, &owner).await.expect("lock held");

    let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
        .bind(pid)
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
    assert!(terminated);
    // Noticed within one check interval plus one check timeout.
    instance
        .wait_until(false, check * 2 + Duration::from_secs(1))
        .await;

    let before = instance.mutations();
    assert_eq!(instance.ingest().await, StatusCode::SERVICE_UNAVAILABLE);
    assert!(instance.reconciler.reconcile().await.is_err());
    let rule = prefixd::domain::FlowSpecRule::new(
        prefixd::domain::FlowSpecNlri {
            dst_prefix: "203.0.113.10/32".into(),
            protocol: Some(6),
            dst_ports: vec![80],
        },
        prefixd::domain::FlowSpecAction::discard(),
    );
    assert!(matches!(
        instance.state.announcer.announce(&rule).await,
        Err(PrefixdError::Standby)
    ));
    assert!(matches!(
        instance.state.announcer.withdraw(&rule).await,
        Err(PrefixdError::Standby)
    ));
    assert_eq!(
        instance.mutations(),
        before,
        "RPC after the loss was noticed"
    );

    // With no competitor, the poll reacquires on a new session.
    instance
        .wait_until(true, poll + Duration::from_secs(2))
        .await;
    let new_pid = fence_holder(&ctx, &owner).await.expect("lock reacquired");
    assert_ne!(new_pid, pid);
    assert_eq!(instance.ingest().await, StatusCode::ACCEPTED);
    assert!(instance.mutations() > before);
}

#[tokio::test]
async fn standby_refuses_mutation_requests_with_503_and_reports_standby() {
    let fence = Arc::new(ControllerFence::new(false));
    let state = AppState::new(
        common::test_settings(),
        test_inventory(),
        test_playbooks(),
        Arc::new(prefixd::db::MockRepository::new()),
        Arc::new(FencedAnnouncer::new(
            Arc::new(MockAnnouncer::new()),
            fence.clone(),
        )),
        ".".into(),
    )
    .unwrap()
    .with_fence(fence)
    .unwrap();
    let app = prefixd::api::create_test_router(state);
    let send = |method: &str, uri: &str, body: &str| {
        app.clone().oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
    };
    for (method, uri, body) in [
        ("POST", "/v1/events", "{}"),
        ("POST", "/v1/mitigations", "{}"),
        ("POST", "/v1/mitigations/withdraw", "{}"),
        ("POST", "/v1/safelist", "{}"),
        ("DELETE", "/v1/safelist/192.0.2.1%2F32", ""),
        ("POST", "/v1/signals/fastnetmon", "{}"),
    ] {
        let response = send(method, uri, body).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{method} {uri}"
        );
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(error["error"].as_str().unwrap().contains("standby"));
    }
    assert_eq!(
        send("GET", "/v1/mitigations", "").await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        send("GET", "/v1/health", "").await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        send("GET", "/v1/ready", "").await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let detail = send("GET", "/v1/health/detail", "").await.unwrap();
    assert_eq!(detail.status(), StatusCode::OK);
    let body = axum::body::to_bytes(detail.into_body(), 65536)
        .await
        .unwrap();
    let health: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(health["status"], "standby");
}

/// Readiness precedence: standby, then draining, then ready.
#[tokio::test]
async fn readiness_reports_standby_before_draining_before_ready() {
    async fn readiness(active: bool, shutting_down: bool) -> (StatusCode, serde_json::Value) {
        let fence = Arc::new(ControllerFence::new(active));
        let state = AppState::new(
            common::test_settings(),
            test_inventory(),
            test_playbooks(),
            Arc::new(prefixd::db::MockRepository::new()),
            Arc::new(FencedAnnouncer::new(
                Arc::new(MockAnnouncer::new()),
                fence.clone(),
            )),
            ".".into(),
        )
        .unwrap()
        .with_fence(fence)
        .unwrap();
        if shutting_down {
            state.trigger_shutdown();
        }
        let response = prefixd::api::create_test_router(state)
            .oneshot(
                Request::builder()
                    .uri("/v1/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }
    let unavailable = StatusCode::SERVICE_UNAVAILABLE;
    for (active, shutting_down, expected) in [
        (true, false, (StatusCode::OK, "ready")),
        (true, true, (unavailable, "draining")),
        (false, true, (unavailable, "standby")),
        (false, false, (unavailable, "standby")),
    ] {
        let (code, body) = readiness(active, shutting_down).await;
        assert_eq!((code, body["status"].as_str().unwrap()), expected);
    }
}

/// A real SIGTERM: readiness fails with `draining` at once, while the process
/// still runs and still holds the fence; the fence is released only on exit.
#[cfg(unix)]
#[tokio::test]
async fn shutdown_signal_drains_readiness_while_the_fence_is_held() {
    let ctx = TestContext::new().await;
    let owner = binding(&ctx).await.owner();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut settings = ctx.state.settings.clone();
    settings.http.listen = format!("127.0.0.1:{port}");
    settings.shutdown.drain_timeout_seconds = 5;
    let directory = tempfile::tempdir().unwrap();
    for (name, yaml) in [
        ("prefixd.yaml", serde_saphyr::to_string(&settings).unwrap()),
        (
            "inventory.yaml",
            serde_saphyr::to_string(&test_inventory()).unwrap(),
        ),
        (
            "playbooks.yaml",
            serde_saphyr::to_string(&test_playbooks()).unwrap(),
        ),
    ] {
        common::write_yaml(directory.path(), name, &yaml);
    }
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_prefixd"))
        .arg("--config")
        .arg(directory.path())
        .env("DATABASE_URL", &settings.storage.connection_string)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let url = format!("http://127.0.0.1:{port}/v1/ready");
    let readiness = async || {
        let response = reqwest::get(&url).await.ok()?;
        let code = response.status().as_u16();
        let body: serde_json::Value = response.json().await.ok()?;
        Some((code, body["status"].as_str()?.to_owned()))
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    while readiness().await != Some((200, "ready".into())) {
        assert!(Instant::now() < deadline, "controller never became ready");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let pid = child.id().unwrap().to_string();
    assert!(
        std::process::Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    while readiness().await != Some((503, "draining".into())) {
        assert!(Instant::now() < deadline, "readiness did not drain");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        child.try_wait().unwrap().is_none(),
        "exited before draining"
    );
    assert!(
        fence_holder(&ctx, &owner).await.is_some(),
        "the fence is held through the drain"
    );

    let status = tokio::time::timeout(Duration::from_secs(20), child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(status.success());
    let deadline = Instant::now() + Duration::from_secs(5);
    while fence_holder(&ctx, &owner).await.is_some() {
        assert!(Instant::now() < deadline, "fence not released on exit");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
