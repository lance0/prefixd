#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    reason = "Exercise individual settings without duplicating fixture defaults in each test"
)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use prefixd::bgp::{FlowSpecReader, FlowSpecWriter, PeerObserver};
use std::sync::Arc;
use tower::ServiceExt;

use prefixd::AppState;
use prefixd::api::create_test_router;
use prefixd::bgp::MockAnnouncer;
use prefixd::config::{
    AllowedPorts, Asset, AuthConfig, AuthMode, BgpConfig, BgpMode, Customer, GuardrailsConfig,
    HttpConfig, Inventory, ObservabilityConfig, Playbook, PlaybookAction, PlaybookMatch,
    PlaybookStep, Playbooks, QuotasConfig, RateLimitConfig, SafelistConfig, Service, Settings,
    ShutdownConfig, StorageConfig, TimersConfig,
};
use prefixd::db::{MockRepository, RepositoryTrait};
use prefixd::domain::AttackVector;

struct RecoveringWithdrawal {
    inner: MockAnnouncer,
    failing: std::sync::atomic::AtomicBool,
}

impl prefixd::bgp::FlowSpecAnnouncer for RecoveringWithdrawal {
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
impl prefixd::bgp::FlowSpecWriter for RecoveringWithdrawal {
    async fn announce(&self, rule: &prefixd::domain::FlowSpecRule) -> prefixd::error::Result<()> {
        self.inner.announce(rule).await
    }
    async fn withdraw(&self, rule: &prefixd::domain::FlowSpecRule) -> prefixd::error::Result<()> {
        if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
            self.inner.withdraw(rule).await?;
            return Err(prefixd::error::PrefixdError::BgpWithdrawalFailed(
                "temporary".into(),
            ));
        }
        self.inner.withdraw(rule).await
    }
}
#[async_trait::async_trait]
impl prefixd::bgp::FlowSpecReader for RecoveringWithdrawal {
    async fn list_active(&self) -> prefixd::error::Result<Vec<prefixd::domain::FlowSpecRule>> {
        self.inner.list_active().await
    }
}
#[async_trait::async_trait]
impl prefixd::bgp::PeerObserver for RecoveringWithdrawal {
    async fn session_status(&self) -> prefixd::error::Result<Vec<prefixd::bgp::PeerStatus>> {
        self.inner.session_status().await
    }
}

#[tokio::test]
async fn test_ambiguous_withdrawals_retry_without_reannouncement_or_consuming_new_event() {
    use prefixd::domain::MitigationStatus;
    use prefixd::scheduler::ReconciliationLoop;
    use std::sync::atomic::Ordering::SeqCst;

    for path_kind in ["bulk", "detector", "single", "expiry"] {
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(RecoveringWithdrawal {
            inner: MockAnnouncer::new(),
            failing: std::sync::atomic::AtomicBool::new(true),
        });
        let mut settings = test_settings();
        settings.mode = prefixd::config::OperationMode::Enforced;
        let state = AppState::new(
            settings,
            test_inventory(),
            test_playbooks(),
            repo.clone(),
            speaker.clone(),
            ".".into(),
        )
        .unwrap();
        let mut updates = state.ws_broadcast.subscribe();
        let app = create_test_router(state.clone());
        let event = serde_json::json!({
            "event_id": "retry-test", "timestamp": chrono::Utc::now(), "source": "test",
            "victim_ip": "203.0.113.10", "vector": "udp_flood", "pps": 50000,
            "top_dst_ports": [53], "confidence": 0.9,
        });
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
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let id: uuid::Uuid = json["mitigation_id"].as_str().unwrap().parse().unwrap();
        while updates.try_recv().is_ok() {}
        if path_kind == "expiry" {
            let mut mitigation = repo.get_mitigation(id).await.unwrap().unwrap();
            mitigation.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
            repo.update_mitigation(&mitigation).await.unwrap();
            prefixd::domain::request_withdrawal(
                repo.as_ref(),
                &mitigation,
                true,
                "system",
                "scheduler",
                "TTL expired".into(),
                true,
                None,
            )
            .await
            .unwrap();
        }
        let mut unban = event.clone();
        unban["action"] = "unban".into();
        let (path, payload) = match path_kind {
            "bulk" => (
                "/v1/mitigations/withdraw".into(),
                serde_json::json!({"mitigation_ids": [id], "operator_id": "forged", "reason": "retry test"}),
            ),
            "single" | "expiry" => (
                format!("/v1/mitigations/{id}/withdraw"),
                serde_json::json!({"operator_id": "forged", "reason": "retry test"}),
            ),
            _ => ("/v1/events".into(), unban),
        };
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        if path_kind == "bulk" {
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["failed"], 1);
        } else {
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        }
        assert_eq!(
            repo.get_mitigation(id).await.unwrap().unwrap().status,
            MitigationStatus::Active
        );
        assert_eq!(speaker.inner.announced_count().await, 0);
        assert!(updates.try_recv().is_err());
        let pending = repo.pending_withdrawals(None).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].actor,
            if path_kind == "detector" {
                "test"
            } else if path_kind == "expiry" {
                "scheduler"
            } else {
                "anonymous"
            }
        );

        // A controller tick occurs before any caller retries the withdrawal.
        let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false)
            .with_app_state(state.clone())
            .with_ws_broadcast(state.ws_broadcast.clone());
        assert!(reconciler.reconcile().await.is_err());
        assert_eq!(speaker.inner.announced_count().await, 0);
        assert!(updates.try_recv().is_err());
        let mut retry_event = event.clone();
        retry_event["event_id"] = "new-attack-during-delete".into();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/events")
                    .header("content-type", "application/json")
                    .body(Body::from(retry_event.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(
            repo.find_ban_event_by_external_id("test", "new-attack-during-delete")
                .await
                .unwrap()
                .is_none()
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/mitigations")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "victim_ip": "203.0.113.10", "protocol": "udp", "dst_ports": [53],
                            "action": "discard", "ttl_seconds": 60, "reason": "manual retry"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        speaker.failing.store(false, SeqCst);
        if path_kind == "expiry" {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header("content-type", "application/json")
                        .body(Body::from(payload.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        } else {
            reconciler.reconcile().await.unwrap();
        }
        assert_eq!(
            repo.get_mitigation(id).await.unwrap().unwrap().status,
            if path_kind == "expiry" {
                MitigationStatus::Expired
            } else {
                MitigationStatus::Withdrawn
            }
        );
        assert!(repo.pending_withdrawals(None).await.unwrap().is_empty());
        let notification = updates.try_recv().unwrap();
        if path_kind == "expiry" {
            assert!(
                matches!(notification, prefixd::ws::WsMessage::MitigationExpired { mitigation_id } if mitigation_id == id.to_string())
            );
        } else {
            assert!(
                matches!(notification, prefixd::ws::WsMessage::MitigationWithdrawn { mitigation_id } if mitigation_id == id.to_string())
            );
        }
        let audit = repo
            .list_audit(&prefixd::db::ListParams {
                limit: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        let audit: Vec<_> = audit
            .iter()
            .filter(|entry| {
                entry.action
                    == if path_kind == "expiry" {
                        "expire"
                    } else {
                        "withdraw"
                    }
            })
            .collect();
        assert_eq!(audit.len(), 1);
        assert_eq!(
            audit[0].actor_id.as_deref(),
            Some(pending[0].actor.as_str())
        );
        assert_eq!(audit[0].details["reason"], pending[0].reason);
        reconciler.reconcile().await.unwrap();
        assert!(updates.try_recv().is_err());
    }
}

#[tokio::test]
async fn test_repair_yields_to_operator_and_rechecks_stale_candidate() {
    use prefixd::{
        bgp::{FlowSpecAnnouncer, PeerStatus},
        domain::{
            ActionParams, ActionType, FlowSpecRule, MatchCriteria, Mitigation, MitigationIntent,
        },
        error::Result,
    };
    struct GatedRepair {
        inner: MockAnnouncer,
        started: tokio::sync::Notify,
        release: tokio::sync::Notify,
        repairs: std::sync::Mutex<Vec<String>>,
    }
    impl FlowSpecAnnouncer for GatedRepair {
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
    impl FlowSpecWriter for GatedRepair {
        async fn announce(&self, rule: &FlowSpecRule) -> Result<()> {
            self.repairs
                .lock()
                .unwrap()
                .push(rule.nlri.dst_prefix.clone());
            self.started.notify_one();
            self.release.notified().await;
            self.inner.announce(rule).await
        }
        async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()> {
            self.inner.withdraw(rule).await
        }
    }
    #[async_trait::async_trait]
    impl FlowSpecReader for GatedRepair {
        async fn list_active(&self) -> Result<Vec<FlowSpecRule>> {
            self.inner.list_active().await
        }
    }
    #[async_trait::async_trait]
    impl PeerObserver for GatedRepair {
        async fn session_status(&self) -> Result<Vec<PeerStatus>> {
            Ok(vec![])
        }
    }
    let repo = Arc::new(MockRepository::new());
    let speaker = Arc::new(GatedRepair {
        inner: MockAnnouncer::new(),
        started: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
        repairs: std::sync::Mutex::new(vec![]),
    });
    let mut targets = vec![];
    for suffix in [10, 11, 12] {
        let mut mitigation = Mitigation::from_intent(
            MitigationIntent {
                event_id: uuid::Uuid::new_v4(),
                customer_id: None,
                service_id: None,
                pop: "test1".into(),
                match_criteria: MatchCriteria {
                    dst_prefix: format!("203.0.113.{suffix}/32"),
                    protocol: Some(17),
                    dst_ports: vec![53],
                    ..Default::default()
                },
                action_type: ActionType::Discard,
                action_params: ActionParams::default(),
                ttl_seconds: 600,
                reason: "test".into(),
            },
            format!("203.0.113.{suffix}"),
            AttackVector::UdpFlood,
        );
        mitigation.activate();
        repo.insert_mitigation(&mitigation).await.unwrap();
        targets.push(mitigation);
    }
    let mut settings = test_settings();
    settings.mode = prefixd::config::OperationMode::Enforced;
    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo.clone(),
        speaker.clone(),
        ".".into(),
    )
    .unwrap();
    let app = create_test_router(state.clone());
    let reconciler =
        prefixd::scheduler::ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false)
            .with_app_state(state);
    let task = tokio::spawn(async move { reconciler.reconcile().await });
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        speaker.started.notified(),
    )
    .await
    .unwrap();
    let mut withdrawal = Box::pin(
        app.oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/mitigations/{}/withdraw",
                    targets[1].mitigation_id
                ))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"reason":"operator intervenes"}"#))
                .unwrap(),
        ),
    );
    // Poll once while the first repair owns the mutex, deterministically queueing the operator.
    assert!(futures_util::poll!(&mut withdrawal).is_pending());
    speaker.release.notify_one();
    let response = tokio::time::timeout(std::time::Duration::from_secs(2), withdrawal)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        speaker.started.notified(),
    )
    .await
    .unwrap();
    assert_eq!(
        *speaker.repairs.lock().unwrap(),
        ["203.0.113.12/32", "203.0.113.10/32"]
    );
    speaker.release.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        repo.get_mitigation(targets[1].mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        prefixd::domain::MitigationStatus::Withdrawn
    );
}

#[tokio::test]
async fn test_authenticated_single_and_bulk_withdrawals_record_session_actor() {
    use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
    use prefixd::domain::{
        ActionParams, ActionType, MatchCriteria, Mitigation, MitigationIntent, OperatorRole,
        mitigation_rule,
    };
    let repo = Arc::new(MockRepository::new());
    let salt = SaltString::encode_b64(b"withdrawal-audit-test").unwrap();
    let hash = Argon2::default()
        .hash_password(b"audit-test-password", &salt)
        .unwrap()
        .to_string();
    repo.create_operator("withdraw-auditor", &hash, OperatorRole::Operator, None)
        .await
        .unwrap();
    let speaker = Arc::new(MockAnnouncer::new());
    let mut targets = vec![];
    for suffix in [10, 11] {
        let mut mitigation = Mitigation::from_intent(
            MitigationIntent {
                event_id: uuid::Uuid::new_v4(),
                customer_id: None,
                service_id: None,
                pop: "test1".into(),
                match_criteria: MatchCriteria {
                    dst_prefix: format!("203.0.113.{suffix}/32"),
                    protocol: Some(17),
                    dst_ports: vec![53],
                    ..Default::default()
                },
                action_type: ActionType::Discard,
                action_params: ActionParams::default(),
                ttl_seconds: 600,
                reason: "test".into(),
            },
            format!("203.0.113.{suffix}"),
            AttackVector::UdpFlood,
        );
        mitigation.activate();
        repo.insert_mitigation(&mitigation).await.unwrap();
        prefixd::bgp::FlowSpecWriter::announce(
            speaker.as_ref(),
            &mitigation_rule(&mitigation).unwrap(),
        )
        .await
        .unwrap();
        targets.push(mitigation);
    }
    let mut settings = test_settings();
    settings.mode = prefixd::config::OperationMode::Enforced;
    settings.http.auth.mode = AuthMode::Credentials;
    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo.clone(),
        speaker,
        ".".into(),
    )
    .unwrap();
    let app = create_test_router(state);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"username":"withdraw-auditor","password":"audit-test-password"}"#,
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
    let first_path = format!("/v1/mitigations/{}/withdraw", targets[0].mitigation_id);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&first_path)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"reason":"no session"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    for (path, payload) in [
        (
            first_path,
            serde_json::json!({"operator_id":"forged-admin", "reason":"single reason"}),
        ),
        (
            "/v1/mitigations/withdraw".into(),
            serde_json::json!({"mitigation_ids":[targets[1].mitigation_id], "operator_id":"forged-admin", "reason":"bulk reason"}),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("cookie", &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let audit = repo
        .list_audit(&prefixd::db::ListParams {
            limit: 100,
            ..Default::default()
        })
        .await
        .unwrap();
    let audit: Vec<_> = audit
        .iter()
        .filter(|entry| entry.action == "withdraw")
        .collect();
    assert_eq!(audit.len(), 2);
    for (target, reason) in targets.iter().zip(["single reason", "bulk reason"]) {
        assert_eq!(
            repo.get_mitigation(target.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            prefixd::domain::MitigationStatus::Withdrawn
        );
        let entry = audit
            .iter()
            .find(|entry| {
                entry.target_id.as_deref() == Some(target.mitigation_id.to_string().as_str())
            })
            .unwrap();
        assert!(matches!(
            entry.actor_type,
            prefixd::observability::ActorType::Operator
        ));
        assert_eq!(entry.actor_id.as_deref(), Some("withdraw-auditor"));
        assert_eq!(
            entry.details["reason"],
            format!("withdraw-auditor: {reason}")
        );
    }
}

#[tokio::test]
async fn test_foreign_pop_cannot_delete_local_rule_or_receive_local_repair() {
    use prefixd::{
        domain::{
            ActionParams, ActionType, AttackEvent, AttackEventInput, MatchCriteria, Mitigation,
            MitigationIntent, MitigationStatus, mitigation_rule,
        },
        scheduler::ReconciliationLoop,
    };
    let repo = Arc::new(MockRepository::new());
    let speaker = Arc::new(MockAnnouncer::new());
    let event_json = serde_json::json!({"event_id":"foreign-pop", "timestamp":chrono::Utc::now(), "source":"test", "victim_ip":"203.0.113.10", "vector":"udp_flood", "pps":50000, "top_dst_ports":[53]});
    let event = AttackEvent::from_input(
        serde_json::from_value::<AttackEventInput>(event_json.clone()).unwrap(),
    );
    repo.insert_event(&event).await.unwrap();
    let mut local = Mitigation::from_intent(
        MitigationIntent {
            event_id: uuid::Uuid::new_v4(),
            customer_id: None,
            service_id: None,
            pop: "test1".into(),
            match_criteria: MatchCriteria {
                dst_prefix: "203.0.113.10/32".into(),
                protocol: Some(17),
                dst_ports: vec![53],
                ..Default::default()
            },
            action_type: ActionType::Discard,
            action_params: ActionParams::default(),
            ttl_seconds: 600,
            reason: "local".into(),
        },
        "203.0.113.10".into(),
        AttackVector::UdpFlood,
    );
    local.activate();
    repo.insert_mitigation(&local).await.unwrap();
    speaker
        .announce(&mitigation_rule(&local).unwrap())
        .await
        .unwrap();
    let mut foreign = local.clone();
    foreign.mitigation_id = uuid::Uuid::new_v4();
    foreign.pop = "other-pop".into();
    foreign.triggering_event_id = event.event_id;
    foreign.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
    repo.insert_mitigation(&foreign).await.unwrap();
    let mut missing_foreign = foreign.clone();
    missing_foreign.mitigation_id = uuid::Uuid::new_v4();
    missing_foreign.match_criteria.dst_prefix = "203.0.113.99/32".into();
    missing_foreign.scope_hash = missing_foreign.match_criteria.compute_scope_hash();
    missing_foreign.expires_at = local.expires_at;
    repo.insert_mitigation(&missing_foreign).await.unwrap();
    let mut settings = test_settings();
    settings.mode = prefixd::config::OperationMode::Enforced;
    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo.clone(),
        speaker.clone(),
        ".".into(),
    )
    .unwrap();
    let app = create_test_router(state.clone());
    let mut unban = event_json;
    unban["action"] = "unban".into();
    for (path, payload, bulk) in [
        (
            format!("/v1/mitigations/{}/withdraw", foreign.mitigation_id),
            serde_json::json!({"reason":"wrong controller"}),
            false,
        ),
        (
            "/v1/mitigations/withdraw".into(),
            serde_json::json!({"mitigation_ids":[foreign.mitigation_id], "reason":"wrong controller"}),
            true,
        ),
        ("/v1/events".into(), unban, false),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if bulk {
                StatusCode::OK
            } else {
                StatusCode::CONFLICT
            }
        );
        if bulk {
            let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            let response: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(response["failed"], 1);
            assert_eq!(
                response["results"][0]["error"],
                "mitigation belongs to another POP"
            );
        }
        assert_eq!(speaker.announced_count().await, 1);
        assert!(repo.pending_withdrawals(None).await.unwrap().is_empty());
        assert_eq!(
            repo.get_mitigation(foreign.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            MitigationStatus::Active
        );
    }
    let pending_foreign = prefixd::domain::request_withdrawal(
        repo.as_ref(),
        &foreign,
        false,
        "operator",
        "remote-operator",
        "remote cleanup".into(),
        true,
        None,
    )
    .await
    .unwrap();
    ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false)
        .with_app_state(state)
        .reconcile()
        .await
        .unwrap();
    assert_eq!(speaker.announced_count().await, 1);
    let pending = repo.pending_withdrawals(None).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].operation_id, pending_foreign.operation_id);
    assert_eq!(
        repo.get_mitigation(foreign.mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        MitigationStatus::Active
    );
}

#[tokio::test]
async fn test_disjoint_detector_ports_reject_without_mutating_mitigations_or_speaker() {
    use prefixd::domain::{ActionParams, ActionType, MatchCriteria, Mitigation, MitigationIntent};
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

    #[derive(Default)]
    struct MutationCounter {
        announces: AtomicUsize,
        withdraws: AtomicUsize,
    }

    impl prefixd::bgp::FlowSpecAnnouncer for MutationCounter {
        fn backend(&self) -> &'static str {
            "mock"
        }
    }

    #[async_trait::async_trait]
    impl FlowSpecWriter for MutationCounter {
        async fn announce(&self, _: &prefixd::domain::FlowSpecRule) -> prefixd::error::Result<()> {
            self.announces.fetch_add(1, SeqCst);
            Ok(())
        }

        async fn withdraw(&self, _: &prefixd::domain::FlowSpecRule) -> prefixd::error::Result<()> {
            self.withdraws.fetch_add(1, SeqCst);
            Ok(())
        }
    }

    for vector in [
        AttackVector::UdpFlood,
        AttackVector::SynFlood,
        AttackVector::AckFlood,
    ] {
        for correlation in [false, true] {
            for seed_ports in [None, Some(vec![53]), Some(vec![])] {
                let repo = Arc::new(MockRepository::new());
                let speaker = Arc::new(MutationCounter::default());
                if let Some(ports) = seed_ports {
                    let mut existing = Mitigation::from_intent(
                        MitigationIntent {
                            event_id: uuid::Uuid::new_v4(),
                            customer_id: Some("cust_test".into()),
                            service_id: Some("svc_dns".into()),
                            pop: "test1".into(),
                            match_criteria: MatchCriteria {
                                dst_prefix: "203.0.113.10/32".into(),
                                protocol: Some(if vector == AttackVector::UdpFlood {
                                    17
                                } else {
                                    6
                                }),
                                dst_ports: ports,
                                ..Default::default()
                            },
                            action_type: ActionType::Discard,
                            action_params: ActionParams::default(),
                            ttl_seconds: 30,
                            reason: "existing owner".into(),
                        },
                        "203.0.113.10".into(),
                        vector,
                    );
                    existing.activate();
                    repo.insert_mitigation(&existing).await.unwrap();
                }
                let params = prefixd::db::MitigationListParams {
                    limit: 10,
                    ..Default::default()
                };
                let before = serde_json::to_value(
                    repo.list_mitigations(None, None, None, None, &params)
                        .await
                        .unwrap(),
                )
                .unwrap();
                let mut settings = test_settings_with_correlation(correlation, 2, 0.5);
                settings.mode = prefixd::config::OperationMode::Enforced;
                let mut playbooks = test_playbooks();
                playbooks.playbooks[0].match_criteria.vector = vector;
                let state = AppState::new(
                    settings,
                    test_inventory(),
                    playbooks,
                    repo.clone(),
                    speaker.clone(),
                    ".".into(),
                )
                .unwrap();
                let app = create_test_router(state);
                let payload = serde_json::json!({
                    "event_id": "disjoint-ports", "source": "detector_a", "timestamp": chrono::Utc::now(),
                    "victim_ip": "203.0.113.10", "vector": vector, "pps": 50000,
                    "top_dst_ports": [80, 443], "confidence": 0.9
                });
                let response = app
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/v1/events")
                            .header("content-type", "application/json")
                            .body(Body::from(payload.to_string()))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let status = response.status();
                let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                    .await
                    .unwrap();
                let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
                let after = serde_json::to_value(
                    repo.list_mitigations(None, None, None, None, &params)
                        .await
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(
                    status,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "disjoint detector ports must be rejected: vector={vector:?}, correlation={correlation}, response={json}, rows={after}, announcements={}",
                    speaker.announces.load(SeqCst)
                );
                assert_eq!(
                    json["error"],
                    "guardrail violation: no allowed ports for service"
                );
                assert_eq!(
                    after, before,
                    "must neither insert an owner nor update an existing owner"
                );
                assert_eq!(speaker.announces.load(SeqCst), 0);
                assert_eq!(speaker.withdraws.load(SeqCst), 0);
            }
        }
    }
}

#[tokio::test]
async fn test_canonical_owner_preflight_preserves_existing_rule_and_reuses_detector_owner() {
    use prefixd::domain::{
        ActionParams, ActionType, MatchCriteria, Mitigation, MitigationIntent, mitigation_rule,
    };
    let repo = Arc::new(MockRepository::new());
    let speaker = Arc::new(MockAnnouncer::new());
    let mut existing = Mitigation::from_intent(
        MitigationIntent {
            event_id: uuid::Uuid::new_v4(),
            customer_id: None,
            service_id: None,
            pop: "test1".into(),
            match_criteria: MatchCriteria {
                dst_prefix: "203.0.113.10/32".into(),
                protocol: Some(17),
                dst_ports: vec![53],
                ..Default::default()
            },
            action_type: ActionType::Discard,
            action_params: ActionParams::default(),
            ttl_seconds: 30,
            reason: "original".into(),
        },
        "203.0.113.10".into(),
        AttackVector::UdpFlood,
    );
    existing.activate();
    existing.scope_hash = "historical raw scope hash".into();
    repo.insert_mitigation(&existing).await.unwrap();
    speaker
        .announce(&mitigation_rule(&existing).unwrap())
        .await
        .unwrap();
    let mut settings = test_settings();
    settings.mode = prefixd::config::OperationMode::Enforced;
    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo.clone(),
        speaker.clone(),
        ".".into(),
    )
    .unwrap();
    let app = create_test_router(state);
    let response = app.clone().oneshot(Request::builder().method("POST").uri("/v1/mitigations")
        .header("content-type", "application/json").body(Body::from(serde_json::json!({
            "victim_ip":"203.0.113.10", "protocol":"udp", "dst_ports":[53], "action":"police", "rate_bps":800,
            "ttl_seconds":600, "reason":"duplicate should not replace"
        }).to_string())).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        repo.get_mitigation(existing.mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .expires_at,
        existing.expires_at
    );
    let event = serde_json::json!({"event_id":"reuse-canonical", "timestamp":chrono::Utc::now(), "source":"test", "victim_ip":"203.0.113.10", "vector":"udp_flood", "pps":50000, "top_dst_ports":[53], "confidence":0.9});
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
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["status"], "extended");
    assert_eq!(
        response["mitigation_id"],
        existing.mitigation_id.to_string()
    );
    let extended = repo
        .get_mitigation(existing.mitigation_id)
        .await
        .unwrap()
        .unwrap();
    assert!(extended.expires_at > existing.expires_at);
    assert_eq!(extended.scope_hash, existing.scope_hash);
    assert_eq!(extended.action_type, ActionType::Discard);
    assert_eq!(
        speaker.list_active().await.unwrap()[0].actions[0].action_type,
        ActionType::Discard
    );
    let mut duplicate = extended.clone();
    duplicate.mitigation_id = uuid::Uuid::new_v4();
    duplicate.scope_hash = "second historical owner".into();
    duplicate.action_type = ActionType::Police;
    duplicate.action_params.rate_bps = Some(800);
    repo.insert_mitigation(&duplicate).await.unwrap();
    let mut event = event;
    event["event_id"] = "ambiguous-canonical".into();
    let response = app
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
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(
        repo.find_ban_event_by_external_id("test", "ambiguous-canonical")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        speaker.list_active().await.unwrap()[0].actions[0].action_type,
        ActionType::Discard
    );
}

fn test_settings() -> Settings {
    Settings {
        pop: "test1".to_string(),
        mode: prefixd::config::OperationMode::DryRun,
        http: HttpConfig {
            listen: "127.0.0.1:0".to_string(),
            auth: AuthConfig {
                mode: AuthMode::None,
                bearer_token_env: None,
            },
            rate_limit: RateLimitConfig::default(),
            tls: None,
            cors_origin: None,
        },
        bgp: BgpConfig {
            rustbgpd: None,
            mode: BgpMode::Mock,
            gobgp_grpc: "127.0.0.1:50051".to_string(),
            local_asn: 65000,
            router_id: "10.0.0.1".to_string(),
            neighbors: vec![],
        },
        guardrails: GuardrailsConfig {
            require_ttl: true,
            min_ttl_seconds: Some(30),
            max_ttl_seconds: Some(1800),
            dst_prefix_minlen: 32,
            dst_prefix_maxlen: 32,
            dst_prefix_minlen_v6: None,
            dst_prefix_maxlen_v6: None,
            max_ports: 8,
            allow_src_prefix_match: false,
            allow_tcp_flags_match: false,
            allow_fragment_match: false,
            allow_packet_length_match: false,
        },
        quotas: QuotasConfig {
            max_active_per_customer: 5,
            max_active_per_pop: 200,
            max_active_global: 500,
            max_new_per_minute: 30,
            max_announcements_per_peer: 100,
        },
        timers: TimersConfig {
            default_ttl_seconds: 120,
            min_ttl_seconds: 30,
            max_ttl_seconds: 1800,
            reconciliation_interval_seconds: 30,
            quiet_period_after_withdraw_seconds: 120,
        },
        storage: StorageConfig {
            connection_string: "postgres://unused:unused@localhost/unused".to_string(),
        },
        observability: ObservabilityConfig {
            log_format: prefixd::config::LogFormat::Pretty,
            log_level: "info".to_string(),
        },
        safelist: SafelistConfig { prefixes: vec![] },
        shutdown: ShutdownConfig::default(),
        alerting: Default::default(),
        correlation: Default::default(),
        blackhole: Default::default(),
    }
}

fn test_inventory() -> Inventory {
    Inventory::new(vec![Customer {
        customer_id: "cust_test".to_string(),
        name: "Test Customer".to_string(),
        prefixes: vec!["203.0.113.0/24".to_string()],
        policy_profile: prefixd::config::PolicyProfile::Normal,
        services: vec![Service {
            service_id: "svc_dns".to_string(),
            name: "DNS".to_string(),
            assets: vec![Asset {
                ip: "203.0.113.10".to_string(),
                role: Some("dns".to_string()),
                interface: None,
            }],
            allowed_ports: AllowedPorts {
                udp: vec![53],
                tcp: vec![53],
            },
        }],
    }])
}

fn test_playbooks() -> Playbooks {
    Playbooks {
        playbooks: vec![Playbook {
            name: "udp_flood_test".to_string(),
            match_criteria: PlaybookMatch {
                vector: AttackVector::UdpFlood,
                require_top_ports: false,
            },
            correlation: None,
            steps: vec![PlaybookStep {
                action: PlaybookAction::Police,
                rate_bps: Some(5_000_000),
                ttl_seconds: 120,
                require_confidence_at_least: None,
                require_persistence_seconds: None,
            }],
        }],
    }
}

async fn setup_app_with_config_dir(config_dir: std::path::PathBuf) -> axum::Router {
    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());

    let state = AppState::new(
        test_settings(),
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        config_dir,
    )
    .expect("failed to create app state");

    create_test_router(state)
}

async fn setup_app() -> axum::Router {
    setup_app_with_config_dir(std::path::PathBuf::from(".")).await
}

async fn setup_app_bearer_with_config_dir(config_dir: std::path::PathBuf) -> axum::Router {
    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let mut settings = test_settings_with_bearer();
    settings.http.auth.mode = AuthMode::Credentials;

    let mut state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        config_dir,
    )
    .expect("failed to create app state");

    let cached = Arc::get_mut(&mut state).expect("unshared test state");
    cached.settings.http.auth.mode = AuthMode::Bearer;
    cached.bearer_token = Some("test-secret-token-123".into());
    create_test_router(state)
}

#[tokio::test]
async fn test_health_endpoint() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Public health returns slim response
    assert!(json["status"].is_string(), "status should be a string");
    assert!(json["version"].is_string(), "version should be a string");
    assert!(
        json["auth_mode"].is_string(),
        "auth_mode should be a string"
    );
    // Sensitive fields should NOT be present on public health
    assert!(
        json["bgp_sessions"].is_null(),
        "bgp_sessions should not be on public health"
    );
    assert!(
        json["database"].is_null(),
        "database should not be on public health"
    );
}

#[tokio::test]
async fn test_health_detail_endpoint() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/health/detail")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["status"].is_string(), "status should be a string");
    assert!(json["version"].is_string(), "version should be a string");
    assert!(
        json["bgp_sessions"].is_object(),
        "bgp_sessions should be present on detail"
    );
    assert!(
        json["database"].is_string(),
        "database should be present on detail"
    );
    assert!(
        json["gobgp"].is_object(),
        "gobgp should be present on detail"
    );
    assert!(
        json["uptime_seconds"].is_number(),
        "uptime_seconds should be present on detail"
    );
}

#[tokio::test(start_paused = true)]
async fn health_distinguishes_unsupported_failed_empty_and_populated_peer_observation() {
    use prefixd::bgp::{FlowSpecAnnouncer, PeerStatus, SessionState};
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    struct HealthSpeaker {
        mode: usize,
        peer_calls: AtomicUsize,
        health_calls: AtomicUsize,
    }
    impl FlowSpecAnnouncer for HealthSpeaker {
        fn backend(&self) -> &'static str {
            "health-test"
        }
        fn daemon_health_observer(&self) -> Option<&dyn prefixd::bgp::DaemonHealthObserver> {
            if self.mode == 0 { None } else { Some(self) }
        }
        fn reader(&self) -> Option<&dyn FlowSpecReader> {
            if self.mode == 4 { None } else { Some(self) }
        }
        fn peer_observer(&self) -> Option<&dyn PeerObserver> {
            if self.mode == 0 { None } else { Some(self) }
        }
    }
    #[async_trait::async_trait]
    impl FlowSpecWriter for HealthSpeaker {
        async fn announce(&self, _: &prefixd::domain::FlowSpecRule) -> prefixd::error::Result<()> {
            panic!("health must not mutate rules")
        }
        async fn withdraw(&self, _: &prefixd::domain::FlowSpecRule) -> prefixd::error::Result<()> {
            panic!("health must not mutate rules")
        }
    }
    #[async_trait::async_trait]
    impl FlowSpecReader for HealthSpeaker {
        async fn list_active(&self) -> prefixd::error::Result<Vec<prefixd::domain::FlowSpecRule>> {
            panic!("health must not read the RIB")
        }
    }
    #[async_trait::async_trait]
    impl PeerObserver for HealthSpeaker {
        async fn session_status(&self) -> prefixd::error::Result<Vec<PeerStatus>> {
            self.peer_calls.fetch_add(1, SeqCst);
            match self.mode {
                1 => Err(prefixd::error::PrefixdError::BgpAnnouncementFailed(
                    "peer RPC failed".into(),
                )),
                2 => Ok(vec![]),
                3..=5 => Ok(vec![PeerStatus {
                    name: "router".into(),
                    address: "192.0.2.1".into(),
                    state: SessionState::Established,
                }]),
                _ => panic!("unsupported observer must not be called"),
            }
        }
    }
    #[async_trait::async_trait]
    impl prefixd::bgp::DaemonHealthObserver for HealthSpeaker {
        async fn daemon_health(&self) -> prefixd::error::Result<prefixd::bgp::DaemonHealth> {
            self.health_calls.fetch_add(1, SeqCst);
            if self.mode == 5 {
                return std::future::pending().await;
            }
            if self.mode == 1 {
                return Err(prefixd::error::PrefixdError::Internal(
                    "private upstream diagnostic".into(),
                ));
            }
            Ok(prefixd::bgp::DaemonHealth {
                version: if self.mode == 2 {
                    None
                } else {
                    Some("actual-daemon-version".into())
                },
                uptime_seconds: if self.mode == 2 { 0 } else { 123 },
                ready: self.mode != 4,
            })
        }
    }
    for mode in 0..6 {
        let speaker = Arc::new(HealthSpeaker {
            mode,
            peer_calls: AtomicUsize::new(0),
            health_calls: AtomicUsize::new(0),
        });
        let state = AppState::new(
            test_settings(),
            test_inventory(),
            test_playbooks(),
            Arc::new(MockRepository::new()),
            speaker.clone(),
            ".".into(),
        )
        .unwrap();
        let started = tokio::time::Instant::now();
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            create_test_router(state).oneshot(
                Request::builder()
                    .uri("/v1/health/detail")
                    .body(Body::empty())
                    .unwrap(),
            ),
        )
        .await
        .expect("daemon operational observation must finish within its budget")
        .unwrap();
        if mode == 5 {
            assert_eq!(started.elapsed(), std::time::Duration::from_secs(2));
        }
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["speaker"]["backend"], "health-test");
        assert_eq!(json["speaker"]["capabilities"]["rule_reader"], mode != 4);
        assert_eq!(json["speaker"]["capabilities"]["peer_observer"], mode != 0);
        assert_eq!(speaker.peer_calls.load(SeqCst), usize::from(mode != 0));
        assert_eq!(
            json["gobgp"]["status"],
            [
                "unsupported",
                "error",
                "connected",
                "connected",
                "connected",
                "connected"
            ][mode]
        );
        assert_eq!(
            json["status"],
            if matches!(mode, 1 | 4 | 5) {
                "degraded"
            } else {
                "healthy"
            }
        );
        assert_eq!(json["gobgp"]["error"].is_string(), mode == 1);
        assert_eq!(
            json["bgp_sessions"].as_object().unwrap().len(),
            usize::from(mode >= 3)
        );
        assert_eq!(json["speaker"]["capabilities"]["daemon_health"], mode != 0);
        assert_eq!(speaker.health_calls.load(SeqCst), usize::from(mode != 0));
        let daemon = &json["speaker"]["daemon"];
        assert_eq!(
            daemon["status"],
            if mode == 0 {
                "unsupported"
            } else if matches!(mode, 1 | 5) {
                "error"
            } else {
                "observed"
            }
        );
        if matches!(mode, 0 | 1 | 5) {
            for field in ["version", "uptime_seconds", "ready", "observed_at"] {
                assert!(daemon[field].is_null());
            }
        } else {
            assert!(
                daemon["observed_at"]
                    .as_str()
                    .unwrap()
                    .parse::<chrono::DateTime<chrono::Utc>>()
                    .is_ok()
            );
            assert_eq!(daemon["ready"], mode != 4);
            assert_eq!(daemon["uptime_seconds"], if mode == 2 { 0 } else { 123 });
            if mode == 2 {
                assert!(daemon["version"].is_null());
            } else {
                assert_eq!(daemon["version"], "actual-daemon-version");
            }
        }
        assert!(!json.to_string().contains("private upstream diagnostic"));
        if mode >= 3 {
            assert_eq!(json["bgp_sessions"]["router"], "established");
        }
    }
}

#[tokio::test]
async fn test_config_settings_endpoint() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/config/settings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["settings"].is_object(), "settings should be present");
    assert!(json["loaded_at"].is_string(), "loaded_at should be present");
    // Verify allowlist redaction: sensitive fields must not appear
    assert_eq!(
        json["settings"]["storage"]["connection_string"],
        "[redacted]"
    );
    assert!(
        json["settings"]["http"]["auth"]["bearer_token_env"].is_null(),
        "bearer_token_env should not be in allowlist"
    );
    assert!(
        json["settings"]["bgp"]["gobgp_grpc"].is_null(),
        "gobgp_grpc should not be in allowlist"
    );
    assert!(
        json["settings"]["bgp"]["router_id"].is_null(),
        "router_id should not be in allowlist"
    );
    assert_eq!(
        json["settings"]["observability"],
        serde_json::json!({ "log_format": "pretty", "log_level": "info" }),
        "observability should expose only the effective logging settings"
    );
}

#[tokio::test]
async fn metrics_remain_unauthenticated_on_the_private_api_listener() {
    prefixd::observability::init_metrics();
    let mut state = AppState::new(
        test_settings(),
        test_inventory(),
        test_playbooks(),
        Arc::new(MockRepository::new()),
        Arc::new(MockAnnouncer::new()),
        std::path::PathBuf::from("."),
    )
    .unwrap();
    let config = Arc::get_mut(&mut state).unwrap();
    config.settings.http.auth.mode = AuthMode::Bearer;
    config.bearer_token = Some("private-metrics-control-token".into());
    let app = create_test_router(state);

    let protected = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(protected.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let scrape = std::str::from_utf8(&body).unwrap();
    assert!(scrape.contains("# TYPE prefixd_reconciliation_runs_total counter"));
    assert!(scrape.contains("prefixd_reconciliation_runs_total{status=\"success\"}"));
}

#[tokio::test]
async fn test_rustbgpd_config_credentials_are_not_exposed() {
    let mut settings = test_settings();
    settings.bgp.mode = BgpMode::Rustbgpd;
    settings.bgp.rustbgpd = Some(prefixd::config::RustBgpdConfig {
        endpoint: "https://private-speaker.example:50051".into(),
        bearer_token_env: "PRIVATE_SPEAKER_TOKEN".into(),
        ca_cert_path: Some("/private/speaker-ca.pem".into()),
        client_cert_path: Some("/private/client.pem".into()),
        client_key_path: Some("/private/client-key.pem".into()),
    });
    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        Arc::new(MockRepository::new()),
        Arc::new(MockAnnouncer::new()),
        ".".into(),
    )
    .unwrap();
    let response = create_test_router(state)
        .oneshot(
            Request::builder()
                .uri("/v1/config/settings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["settings"]["bgp"]["mode"], "rustbgpd");
    assert!(json["settings"]["bgp"].get("rustbgpd").is_none());
    let body = String::from_utf8(body.to_vec()).unwrap();
    for private_value in [
        "private-speaker",
        "PRIVATE_SPEAKER_TOKEN",
        "/private/speaker-ca.pem",
        "/private/client.pem",
        "/private/client-key.pem",
    ] {
        assert!(!body.contains(private_value));
    }
}

#[tokio::test]
async fn test_config_inventory_endpoint() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/config/inventory")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["customers"].is_array(), "customers should be an array");
    assert!(
        json["total_customers"].is_number(),
        "total_customers should be a number"
    );
    assert!(
        json["total_services"].is_number(),
        "total_services should be a number"
    );
    assert!(
        json["total_assets"].is_number(),
        "total_assets should be a number"
    );
    assert!(json["loaded_at"].is_string(), "loaded_at should be present");
}

#[tokio::test]
async fn test_config_playbooks_endpoint() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/config/playbooks")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["playbooks"].is_array(), "playbooks should be an array");
    assert!(
        json["total_playbooks"].is_number(),
        "total_playbooks should be a number"
    );
    assert!(json["loaded_at"].is_string(), "loaded_at should be present");
}

#[tokio::test]
async fn test_list_mitigations_empty() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_ingest_event() {
    let app = setup_app().await;

    let event_json = r#"{
        "timestamp": "2026-01-16T14:00:00Z",
        "source": "test",
        "victim_ip": "203.0.113.10",
        "vector": "udp_flood",
        "bps": 100000000,
        "pps": 50000,
        "top_dst_ports": [53],
        "confidence": 0.9
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
}

#[tokio::test]
async fn test_list_mitigations_filters_by_victim_ip() {
    let app = setup_app().await;

    let event_a = r#"{
        "timestamp": "2026-01-16T14:00:00Z",
        "source": "test",
        "victim_ip": "203.0.113.10",
        "vector": "udp_flood",
        "pps": 50000
    }"#;
    let event_b = r#"{
        "timestamp": "2026-01-16T14:00:01Z",
        "source": "test",
        "victim_ip": "203.0.113.11",
        "vector": "syn_flood",
        "pps": 25000
    }"#;

    for body in [event_a, event_b] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/events")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations?victim_ip=203.0.113.10")
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

    assert_eq!(json["count"], 1);
    assert_eq!(json["mitigations"][0]["victim_ip"], "203.0.113.10");
}

#[tokio::test]
async fn test_bulk_withdraw_mitigations() {
    let app = setup_app().await;

    // Ingest two events for different IPs to create two mitigations
    let events = vec![
        r#"{
            "timestamp": "2026-01-16T14:00:00Z",
            "source": "test",
            "victim_ip": "203.0.113.20",
            "vector": "udp_flood",
            "pps": 50000
        }"#,
        r#"{
            "timestamp": "2026-01-16T14:00:01Z",
            "source": "test",
            "victim_ip": "203.0.113.21",
            "vector": "udp_flood",
            "pps": 25000
        }"#,
    ];

    for body in events {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/events")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    // Get mitigation IDs
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations")
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
    let mitigations = json["mitigations"].as_array().unwrap();
    assert!(
        mitigations.len() >= 2,
        "expected at least 2 mitigations, got {}",
        mitigations.len()
    );

    let id1 = mitigations[0]["mitigation_id"].as_str().unwrap();
    let id2 = mitigations[1]["mitigation_id"].as_str().unwrap();

    // Bulk withdraw both plus a fake ID
    let fake_id = "00000000-0000-0000-0000-000000000000";
    let withdraw_body = serde_json::json!({
        "mitigation_ids": [id1, id2, fake_id],
        "operator_id": "test_operator",
        "reason": "bulk test"
    });

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mitigations/withdraw")
                .header("content-type", "application/json")
                .body(Body::from(withdraw_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["withdrawn"], 2);
    assert_eq!(json["failed"], 1);
    assert_eq!(json["results"].as_array().unwrap().len(), 3);
}

// Auth tests with bearer token
fn test_settings_with_bearer() -> Settings {
    let mut settings = test_settings();
    settings.http.auth.mode = AuthMode::Bearer;
    settings.http.auth.bearer_token_env = Some("TEST_PREFIXD_TOKEN".to_string());
    settings
}

async fn setup_app_with_bearer() -> axum::Router {
    setup_app_bearer_with_config_dir(std::path::PathBuf::from(".")).await
}

#[tokio::test]
async fn test_bearer_startup_environment_boundary() {
    const CHILD: &str = "PREFIXD_BEARER_STARTUP_CASE";
    const TOKEN_ENV: &str = "PREFIXD_TEST_BEARER_STARTUP_TOKEN";
    const TOKEN: &str = "startup-boundary-token";
    if let Ok(case) = std::env::var(CHILD) {
        assert!(matches!(case.as_str(), "present" | "missing" | "empty"));
        let mut settings = test_settings_with_bearer();
        settings.http.auth.bearer_token_env = Some(TOKEN_ENV.into());
        let state = AppState::new(
            settings,
            test_inventory(),
            test_playbooks(),
            Arc::new(MockRepository::new()),
            Arc::new(MockAnnouncer::new()),
            ".".into(),
        );
        if case == "present" {
            let state = state.expect("present startup token must construct state");
            assert!(state.bearer_token.as_deref() == Some(TOKEN));
            let app = create_test_router(state);
            let response = app
                .clone()
                .oneshot(Request::get("/v1/mitigations").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            let response = app
                .oneshot(
                    Request::get("/v1/mitigations")
                        .header("authorization", format!("Bearer {TOKEN}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        } else {
            let expected = format!("auth.mode=bearer but {TOKEN_ENV} is not set or empty");
            assert!(
                matches!(state, Err(prefixd::error::PrefixdError::Config(message)) if message == expected),
                "missing or empty startup token must reject state construction before serving"
            );
        }
        println!("\nprefixd-bearer-startup-completed:{case}");
        return;
    }

    for case in ["present", "missing", "empty"] {
        let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "test_bearer_startup_environment_boundary",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(CHILD, case)
            .env_remove(TOKEN_ENV)
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true);
        match case {
            "present" => {
                command.env(TOKEN_ENV, TOKEN);
            }
            "empty" => {
                command.env(TOKEN_ENV, "");
            }
            _ => {}
        }
        let output = tokio::time::timeout(std::time::Duration::from_secs(15), command.output())
            .await
            .expect("bearer startup child exceeded fifteen seconds")
            .expect("bearer startup child output");
        let stdout = String::from_utf8_lossy(&output.stdout).replace(TOKEN, "[redacted]");
        let stderr = String::from_utf8_lossy(&output.stderr).replace(TOKEN, "[redacted]");
        assert!(
            output.status.success(),
            "bearer startup {case} child failed ({:?})\n{stdout}\n{stderr}",
            output.status.code()
        );
        let completion = format!("prefixd-bearer-startup-completed:{case}");
        assert!(
            stdout.lines().any(|line| line == completion),
            "bearer startup {case} child did not complete its assertions\n{stdout}\n{stderr}"
        );
    }
}

#[tokio::test]
async fn test_bearer_auth_missing_token_returns_401() {
    let app = setup_app_with_bearer().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_bearer_auth_invalid_token_returns_401() {
    let app = setup_app_with_bearer().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations")
                .header("Authorization", "Bearer wrong-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_bearer_auth_valid_token_returns_200() {
    let app = setup_app_with_bearer().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations")
                .header("Authorization", "Bearer test-secret-token-123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_public_endpoint_no_auth_required() {
    let app = setup_app_with_bearer().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_security_headers_present() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    assert_eq!(
        response
            .headers()
            .get("x-content-type-options")
            .map(|v| v.to_str().unwrap()),
        Some("nosniff")
    );
    assert_eq!(
        response
            .headers()
            .get("x-frame-options")
            .map(|v| v.to_str().unwrap()),
        Some("DENY")
    );
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .map(|v| v.to_str().unwrap()),
        Some("no-store")
    );
}

#[tokio::test]
async fn test_timeseries_returns_buckets() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/stats/timeseries?metric=mitigations&range=24h&bucket=1h")
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
    assert_eq!(json["metric"], "mitigations");
    // MockRepository returns empty buckets
    assert!(json["buckets"].is_array());
}

#[tokio::test]
async fn test_ip_history_returns_structure() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/ip/192.0.2.1/history")
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
    assert_eq!(json["ip"], "192.0.2.1");
    assert!(json["events"].is_array());
    assert!(json["mitigations"].is_array());
}

#[tokio::test]
async fn test_ip_history_rejects_invalid_ip() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/ip/not-an-ip/history")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_update_playbooks_validation_error_returns_400() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/config/playbooks")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"playbooks":[]}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_update_playbooks_invalid_json_returns_400() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/config/playbooks")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"playbooks":"not-an-array"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_update_playbooks_success_writes_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_dir = temp_dir.path().to_path_buf();
    let app = setup_app_with_config_dir(config_dir.clone()).await;

    let body = r#"{
        "playbooks": [{
            "name": "syn_discard_test",
            "match": { "vector": "syn_flood", "require_top_ports": true },
            "steps": [
                { "action": "police", "rate_bps": 3000000, "ttl_seconds": 90 },
                { "action": "discard", "ttl_seconds": 240, "require_confidence_at_least": 0.8, "require_persistence_seconds": 120 }
            ]
        }]
    }"#;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/config/playbooks")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let written = std::fs::read_to_string(config_dir.join("playbooks.yaml")).unwrap();
    assert!(written.contains("syn_discard_test"));
    assert!(written.contains("syn_flood"));
}

#[tokio::test]
async fn test_update_playbooks_bearer_operator_forbidden() {
    let app = setup_app_with_bearer().await;

    let body = r#"{
        "playbooks": [{
            "name": "test_playbook",
            "match": { "vector": "udp_flood" },
            "steps": [{ "action": "police", "rate_bps": 5000000, "ttl_seconds": 120 }]
        }]
    }"#;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/config/playbooks")
                .header("Authorization", "Bearer test-secret-token-123")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// ─── Alerting PUT tests ───

#[tokio::test]
async fn test_update_alerting_success() {
    let dir = tempfile::tempdir().unwrap();
    let app = setup_app_with_config_dir(dir.path().to_path_buf()).await;

    let body = serde_json::json!({
        "destinations": [
            {
                "type": "slack",
                "webhook_url": "https://hooks.slack.com/services/T/B/xxx",
                "channel": "#alerts"
            }
        ],
        "events": ["mitigation.created", "mitigation.withdrawn"]
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/config/alerting")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["destinations"][0]["type"], "slack");
    assert_eq!(json["destinations"][0]["webhook_url"], "***");
    assert_eq!(json["events"].as_array().unwrap().len(), 2);

    // Verify file was written
    let alerting_path = dir.path().join("alerting.yaml");
    assert!(alerting_path.exists());
}

#[tokio::test]
async fn test_update_alerting_validation_error() {
    let dir = tempfile::tempdir().unwrap();
    let app = setup_app_with_config_dir(dir.path().to_path_buf()).await;

    let body = serde_json::json!({
        "destinations": [
            {
                "type": "slack",
                "webhook_url": "",
                "channel": "#alerts"
            }
        ],
        "events": []
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/config/alerting")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_update_alerting_invalid_json() {
    let dir = tempfile::tempdir().unwrap();
    let app = setup_app_with_config_dir(dir.path().to_path_buf()).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/config/alerting")
                .header("content-type", "application/json")
                .body(Body::from("not json"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_update_alerting_operator_forbidden() {
    let dir = tempfile::tempdir().unwrap();
    let app = setup_app_bearer_with_config_dir(dir.path().to_path_buf()).await;

    let body = serde_json::json!({
        "destinations": [],
        "events": []
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/config/alerting")
                .header("Authorization", "Bearer test-secret-token-123")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_update_alerting_rejects_link_local_url() {
    let dir = tempfile::tempdir().unwrap();
    let app = setup_app_with_config_dir(dir.path().to_path_buf()).await;

    let body = serde_json::json!({
        "destinations": [
            {
                "type": "generic",
                "url": "https://169.254.169.254/latest/meta-data",
                "secret": "test",
                "headers": {}
            }
        ],
        "events": []
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/config/alerting")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn alert_destination_url_rejections_preserve_running_and_saved_config() {
    use prefixd::alerting::AlertingConfig;

    let dir = tempfile::tempdir().unwrap();
    let original = serde_json::json!({
        "destinations": [
            { "type": "slack", "webhook_url": "https://example.com/slack-secret" },
            { "type": "discord", "webhook_url": "https://example.com/discord-secret" },
            { "type": "teams", "webhook_url": "https://example.com/teams-secret" },
            {
                "type": "pagerduty", "events_url": "https://example.com/events",
                "routing_key": "original-routing-secret"
            },
            {
                "type": "generic", "url": "https://example.com/generic-secret",
                "secret": "original-signing-secret",
                "headers": { "Authorization": "original-header-secret" }
            }
        ],
        "events": ["mitigation.created"]
    });
    let config: AlertingConfig = serde_json::from_value(original.clone()).unwrap();
    assert!(config.validate().is_empty());
    let path = dir.path().join("alerting.yaml");
    config.save(&path).unwrap();
    let mut settings = test_settings();
    settings.alerting = config;
    let repo = Arc::new(MockRepository::new());
    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo.clone(),
        Arc::new(MockAnnouncer::new()),
        dir.path().to_path_buf(),
    )
    .unwrap();
    let app = create_test_router(state.clone());
    let request = |config: &serde_json::Value| {
        Request::builder()
            .method("PUT")
            .uri("/v1/config/alerting")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(config).unwrap()))
            .unwrap()
    };

    // Exercise the successful save path before checking rejection without mutation.
    let response = app.clone().oneshot(request(&original)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let current_service = state.alerting.read().await.clone();
    let current_config = serde_json::to_value(current_service.config()).unwrap();
    let loaded_at = *state.alerting_loaded_at.read().await;
    let saved = std::fs::read(&path).unwrap();
    let backup = std::fs::read(path.with_extension("yaml.bak")).unwrap();
    let audit_query = prefixd::db::ListParams {
        limit: 10,
        ..Default::default()
    };
    let audit = serde_json::to_value(repo.list_audit(&audit_query).await.unwrap()).unwrap();
    assert_eq!(
        audit.as_array().unwrap().len(),
        1,
        "positive save writes an audit row"
    );

    for (index, kind, field) in [
        (0, "slack", "webhook_url"),
        (1, "discord", "webhook_url"),
        (2, "teams", "webhook_url"),
        (3, "pagerduty", "events_url"),
        (4, "generic", "url"),
    ] {
        for host in [
            "[::1]",
            "[fe80::1]",
            "[::ffff:127.0.0.1]",
            "[::ffff:10.0.0.1]",
        ] {
            let mut incoming = original.clone();
            incoming["destinations"][index][field] =
                format!("https://user:request-secret@{host}/hook?token=request-secret").into();
            let response = app.clone().oneshot(request(&incoming)).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{kind}: {host}");
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                serde_json::json!({
                    "errors": [format!("destination[{index}] ({kind}): {field} host IP is not allowed")]
                })
            );
            let current = state.alerting.read().await.clone();
            assert!(Arc::ptr_eq(&current, &current_service));
            assert_eq!(
                serde_json::to_value(current.config()).unwrap(),
                current_config
            );
            assert_eq!(*state.alerting_loaded_at.read().await, loaded_at);
            assert_eq!(std::fs::read(&path).unwrap(), saved);
            assert_eq!(
                std::fs::read(path.with_extension("yaml.bak")).unwrap(),
                backup
            );
            assert_eq!(
                serde_json::to_value(AlertingConfig::load(&path).unwrap()).unwrap(),
                current_config
            );
            assert_eq!(
                serde_json::to_value(repo.list_audit(&audit_query).await.unwrap()).unwrap(),
                audit
            );
        }
    }
}

#[tokio::test]
async fn test_reload_config_reloads_alerting_yaml() {
    let dir = tempfile::tempdir().unwrap();
    let config_dir = dir.path().to_path_buf();
    let app = setup_app_with_config_dir(config_dir.clone()).await;

    std::fs::write(
        config_dir.join("alerting.yaml"),
        r##"
destinations:
  - type: slack
    webhook_url: https://hooks.slack.com/services/T/B/C
    channel: "#ops-alerts"
events:
  - mitigation.created
"##,
    )
    .unwrap();

    let response = app
        .clone()
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
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["reloaded"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "alerting")
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/config/alerting")
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
    assert_eq!(json["destinations"][0]["type"], "slack");
    assert_eq!(json["events"][0], "mitigation.created");
}

#[tokio::test]
async fn test_cursor_pagination_mitigations() {
    let app = setup_app().await;

    // Ingest 3 events to create 3 mitigations
    for i in 0..3 {
        let body = serde_json::json!({
            "timestamp": format!("2026-01-16T14:00:0{}Z", i),
            "source": "test",
            "victim_ip": format!("203.0.113.{}", 50 + i),
            "vector": "udp_flood",
            "pps": 50000
        });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/events")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    // Page 1: limit=2
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations?limit=2")
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
    assert_eq!(json["count"], 2);
    assert_eq!(json["has_more"], true);
    assert!(
        json["next_cursor"].is_string(),
        "next_cursor should be present"
    );

    // Page 2: use cursor
    let cursor = json["next_cursor"].as_str().unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/mitigations?limit=2&cursor={}", cursor))
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
    assert_eq!(json["count"], 1);
    assert_eq!(json["has_more"], false);
    assert!(json["next_cursor"].is_null(), "no more pages");
}

#[tokio::test]
async fn test_mitigation_cursor_preserves_ties_and_nanosecond_positions() {
    use chrono::{DateTime, Duration, SecondsFormat, Utc};
    use prefixd::domain::{
        ActionParams, ActionType, MatchCriteria, Mitigation, MitigationIntent, MitigationStatus,
    };
    use std::collections::BTreeSet;
    use uuid::Uuid;

    let (app, repo) = setup_app_correlation_with_repo(1, 0.5).await;
    let timestamp: DateTime<Utc> = "2026-10-18T12:00:00.123456789Z".parse().unwrap();
    let pop_a = "Edge / β +1";
    let pop_b = "iad1";
    // Interleave POPs and insert out of timestamp/UUID order; six rows fail other filters.
    for id in [2_u128, 7, 5, 3, 6, 4, 1, 8, 9, 10, 11, 12, 13] {
        let mut mitigation = Mitigation::from_intent(
            MitigationIntent {
                event_id: Uuid::new_v4(),
                customer_id: Some("cursor_customer".into()),
                service_id: None,
                pop: if id % 2 == 0 { pop_b } else { pop_a }.into(),
                match_criteria: MatchCriteria {
                    dst_prefix: "203.0.113.10/32".into(),
                    protocol: Some(17),
                    dst_ports: vec![1000 + u16::try_from(id).unwrap()],
                    ..Default::default()
                },
                action_type: ActionType::Discard,
                action_params: ActionParams::default(),
                ttl_seconds: 300,
                reason: "cursor fixture".into(),
            },
            "203.0.113.10".into(),
            AttackVector::UdpFlood,
        );
        mitigation.mitigation_id = Uuid::from_u128(id);
        mitigation.created_at = match id {
            2 => timestamp + Duration::nanoseconds(1),
            1 => timestamp - Duration::nanoseconds(1),
            8 => timestamp - Duration::nanoseconds(3),
            9 => timestamp + Duration::nanoseconds(2),
            _ => timestamp,
        };
        mitigation.status = if id % 2 == 0 {
            MitigationStatus::Escalated
        } else {
            MitigationStatus::Active
        };
        match id {
            10 => mitigation.status = MitigationStatus::Withdrawn,
            11 => mitigation.customer_id = Some("other_customer".into()),
            12 => {
                mitigation.victim_ip = "203.0.113.11".into();
                mitigation.match_criteria.dst_prefix = "203.0.113.11/32".into();
                mitigation.scope_hash = mitigation.match_criteria.compute_scope_hash();
            }
            _ => {}
        }
        repo.insert_mitigation(&mitigation).await.unwrap();
    }
    let acknowledged_ids: Vec<_> = (1..=12).map(Uuid::from_u128).collect();
    let acknowledged = repo
        .acknowledge_mitigations(&acknowledged_ids, "cursor-operator")
        .await
        .unwrap();
    assert_eq!(
        acknowledged.into_iter().collect::<BTreeSet<_>>(),
        acknowledged_ids.into_iter().collect::<BTreeSet<_>>()
    );
    let start = (timestamp - Duration::nanoseconds(2)).to_rfc3339_opts(SecondsFormat::Nanos, true);
    let end = (timestamp + Duration::nanoseconds(2)).to_rfc3339_opts(SecondsFormat::Nanos, true);
    let filters = format!(
        "status=active,escalated&customer_id=cursor_customer&victim_ip=203.0.113.10&acknowledged=true&start={start}&end={end}"
    );
    let every_id = vec![2_u128, 7, 6, 5, 4, 3, 1];
    let mut scoped_sets = Vec::new();
    for (selected_pop, expected_ids) in [
        (None, every_id.clone()),
        (Some("all"), every_id),
        (Some(pop_a), vec![7, 5, 3, 1]),
        (Some(pop_b), vec![2, 6, 4]),
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
        let mut ids = Vec::new();
        let mut unique = BTreeSet::new();
        for (page_index, expected_count) in expected_counts.into_iter().enumerate() {
            let mut uri = format!("/v1/mitigations?limit=2&{filters}{suffix}");
            if let Some(value) = &cursor {
                uri.push_str(&format!("&cursor={value}"));
            }
            let response = app
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
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
                ids.push(id);
            }
            cursor = json["next_cursor"].as_str().map(str::to_owned);
            assert_eq!(json["has_more"], cursor.is_some());
            if let Some(value) = &cursor {
                assert!(value.starts_with("m1."));
                assert!(value.len() <= 128);
            }
        }
        let expected: Vec<_> = expected_ids.into_iter().map(Uuid::from_u128).collect();
        assert_eq!(ids, expected);
        assert_eq!(unique, expected.into_iter().collect());
        assert!(cursor.is_none());
        if selected_pop == Some(pop_a) || selected_pop == Some(pop_b) {
            scoped_sets.push(unique);
        }
    }
    assert!(scoped_sets[0].is_disjoint(&scoped_sets[1]));
    assert_eq!(scoped_sets[0].len() + scoped_sets[1].len(), 7);
}

#[tokio::test]
async fn test_mitigation_pop_filter_rejects_empty_and_nul() {
    let app = setup_app().await;
    for value in ["", "%00", "iad%001"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/mitigations?pop={value}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "pop={value}");
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["error"]
                .as_str()
                .unwrap()
                .contains("invalid POP filter")
        );
    }
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations?pop=iad1&pop=other")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_mitigation_cursor_rejects_invalid_superseded_and_oversized_values() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let app = setup_app().await;
    let timestamp = "2026-10-18T12:00:00Z";
    let id = "00000000-0000-0000-0000-000000000001";
    let encode = |value: &str| URL_SAFE_NO_PAD.encode(value.as_bytes());
    // Chrono accepts RFC 3339 fractions beyond nanoseconds and ignores the extra zeros.
    // These otherwise valid payloads isolate the encoded-input length guard.
    let boundary_timestamp = format!("2026-10-18T12:00:00.{}Z", "0".repeat(35));
    let oversized_timestamp = format!("2026-10-18T12:00:00.{}Z", "0".repeat(36));
    for value in [&boundary_timestamp, &oversized_timestamp] {
        assert_eq!(
            chrono::DateTime::parse_from_rfc3339(value).unwrap(),
            chrono::DateTime::parse_from_rfc3339(timestamp).unwrap()
        );
    }
    let boundary_cursor = format!("m1.{}", encode(&format!("{boundary_timestamp}\n{id}")));
    let oversized_cursor = format!("m1.{}", encode(&format!("{oversized_timestamp}\n{id}")));
    assert_eq!(boundary_cursor.len(), 127);
    assert_eq!(oversized_cursor.len(), 129);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/mitigations?cursor={boundary_cursor}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let empty: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(empty["count"], 0);
    assert_eq!(empty["has_more"], false);
    assert!(empty["next_cursor"].is_null());
    let values = [
        String::new(),
        "garbage".into(),
        "m1.".into(),
        "m1.!".into(),
        "m1._w".into(),
        encode(timestamp),
        format!("m2.{}", encode(&format!("{timestamp}\n{id}"))),
        format!("m1.{}", encode(timestamp)),
        format!("m1.{}", encode(&format!("not-a-timestamp\n{id}"))),
        format!("m1.{}", encode(&format!("{timestamp}\nnot-a-uuid"))),
        format!("m1.{}", encode(&format!("{timestamp}\n{id}\nextra"))),
        format!("m1.{}=", encode(&format!("{timestamp}\n{id}"))),
        format!("m1.{}", "A".repeat(125)), // Exactly the encoded-input bound, but malformed.
        format!("m1.{}", "A".repeat(126)), // One byte beyond the bound.
        "m1.%C3%A9".into(),
        oversized_cursor,
    ];
    for value in values {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/mitigations?cursor={value}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "cursor {value:?}"
        );
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["error"]
                .as_str()
                .unwrap()
                .contains("invalid mitigation cursor")
        );
        assert!(
            json["error"]
                .as_str()
                .unwrap()
                .contains("fresh mitigation listing")
        );
    }
}

#[tokio::test]
async fn test_cursor_pagination_events() {
    let app = setup_app().await;

    // Ingest 3 events
    for i in 0..3 {
        let body = serde_json::json!({
            "timestamp": format!("2026-01-16T14:00:0{}Z", i),
            "source": "test",
            "victim_ip": format!("203.0.113.{}", 60 + i),
            "vector": "udp_flood",
            "pps": 50000
        });
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/events")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    // Page 1: limit=2
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/events?limit=2")
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
    assert_eq!(json["count"], 2);
    assert_eq!(json["has_more"], true);

    // Page 2
    let cursor = json["next_cursor"].as_str().unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/events?limit=2&cursor={}", cursor))
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
    assert_eq!(json["count"], 1);
    assert_eq!(json["has_more"], false);
}

#[tokio::test]
async fn test_date_range_filtering_events() {
    let app = setup_app().await;

    // Ingest event
    let body = r#"{
        "timestamp": "2026-01-16T14:00:00Z",
        "source": "test",
        "victim_ip": "203.0.113.70",
        "vector": "udp_flood",
        "pps": 50000
    }"#;
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    // Query with date range that includes the event
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/events?start=2020-01-01T00:00:00Z&end=2030-01-01T00:00:00Z")
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
    assert!(json["count"].as_u64().unwrap() >= 1);

    // Query with date range that excludes the event (future only)
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/events?start=2030-01-01T00:00:00Z")
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
    assert_eq!(json["count"], 0);
}

#[tokio::test]
async fn test_bulk_acknowledge_mitigations() {
    let app = setup_app().await;

    // Ingest 2 events
    for i in 0..2 {
        let body = serde_json::json!({
            "timestamp": format!("2026-01-16T14:00:0{}Z", i),
            "source": "test",
            "victim_ip": format!("203.0.113.{}", 80 + i),
            "vector": "udp_flood",
            "pps": 50000
        });
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/events")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    // Get mitigation IDs
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let mitigations = json["mitigations"].as_array().unwrap();
    assert!(mitigations.len() >= 2);

    let id1 = mitigations[0]["mitigation_id"].as_str().unwrap();
    let id2 = mitigations[1]["mitigation_id"].as_str().unwrap();
    let fake_id = "00000000-0000-0000-0000-000000000000";

    // Bulk acknowledge: 2 real + 1 fake
    let ack_body = serde_json::json!({
        "mitigation_ids": [id1, id2, fake_id],
        "operator_id": "test_operator"
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mitigations/acknowledge")
                .header("content-type", "application/json")
                .body(Body::from(ack_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["acknowledged"], 2);
    assert_eq!(json["failed"], 1);

    // Verify acknowledged filter: acknowledged=true
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations?acknowledged=true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["count"], 2);

    // acknowledged=false should return 0
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations?acknowledged=false")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["count"], 0);

    // Re-acknowledge should fail (already acknowledged)
    let ack_body = serde_json::json!({
        "mitigation_ids": [id1],
        "operator_id": "test_operator"
    });
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mitigations/acknowledge")
                .header("content-type", "application/json")
                .body(Body::from(ack_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["acknowledged"], 0);
    assert_eq!(json["failed"], 1);
}

// ---------------------------------------------------------------------------
// Event batch ingestion
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_batch_event_ingestion_all_accepted() {
    let app = setup_app().await;

    let body = serde_json::json!({
        "events": [
            {
                "timestamp": "2026-01-16T14:00:00Z",
                "source": "fastnetmon",
                "victim_ip": "203.0.113.200",
                "vector": "udp_flood",
                "pps": 50000
            },
            {
                "timestamp": "2026-01-16T14:00:01Z",
                "source": "fastnetmon",
                "victim_ip": "203.0.113.201",
                "vector": "syn_flood",
                "bps": 1000000000
            },
            {
                "timestamp": "2026-01-16T14:00:02Z",
                "source": "fastnetmon",
                "victim_ip": "203.0.113.202",
                "vector": "icmp_flood",
                "pps": 100000
            }
        ]
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events/batch")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["accepted"], 3);
    assert_eq!(json["rejected"], 0);
    let results = json["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
    for (i, r) in results.iter().enumerate() {
        assert_eq!(r["index"], i);
        assert!(r["event_id"].is_string());
        assert!(!r["status"].as_str().unwrap().contains("rejected"));
    }
}

#[tokio::test]
async fn test_batch_event_ingestion_partial_success() {
    let app = setup_app().await;

    let body = serde_json::json!({
        "events": [
            {
                "timestamp": "2026-01-16T14:00:00Z",
                "source": "fastnetmon",
                "victim_ip": "203.0.113.210",
                "vector": "udp_flood",
                "pps": 50000
            },
            {
                "timestamp": "2026-01-16T14:00:01Z",
                "source": "fastnetmon",
                "victim_ip": "not_an_ip",
                "vector": "syn_flood"
            },
            {
                "timestamp": "2026-01-16T14:00:02Z",
                "source": "fastnetmon",
                "victim_ip": "203.0.113.211",
                "vector": "ack_flood",
                "pps": 80000
            }
        ]
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events/batch")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::MULTI_STATUS);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["accepted"], 2);
    assert_eq!(json["rejected"], 1);
    let results = json["results"].as_array().unwrap();
    assert_eq!(results[1]["status"], "rejected");
    assert!(results[1]["error"].as_str().unwrap().contains("IP"));
}

#[tokio::test]
async fn test_batch_event_ingestion_empty_batch() {
    let app = setup_app().await;

    let body = serde_json::json!({ "events": [] });
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events/batch")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_batch_event_ingestion_exceeds_limit() {
    let app = setup_app().await;

    let events: Vec<serde_json::Value> = (0..101)
        .map(|i| {
            serde_json::json!({
                "timestamp": "2026-01-16T14:00:00Z",
                "source": "test",
                "victim_ip": format!("203.0.113.{}", i % 256),
                "vector": "udp_flood"
            })
        })
        .collect();

    let body = serde_json::json!({ "events": events });
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events/batch")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// Incident reports
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_incident_report_by_mitigation_id() {
    let app = setup_app().await;

    // Ingest event to create a mitigation
    let body = serde_json::json!({
        "timestamp": "2026-01-16T14:00:00Z",
        "source": "fastnetmon",
        "victim_ip": "203.0.113.230",
        "vector": "udp_flood",
        "bps": 5000000000i64,
        "pps": 500000
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let event_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let mitigation_id = event_json["mitigation_id"].as_str().unwrap_or_default();

    // Generate report by mitigation_id
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/reports/incident?mitigation_id={}",
                    mitigation_id
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let ct = response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.contains("text/markdown"));

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let markdown = String::from_utf8(body.to_vec()).unwrap();
    assert!(markdown.contains("# Incident Report"));
    assert!(markdown.contains("203.0.113.230"));
    assert!(markdown.contains("## Summary"));
    assert!(markdown.contains("## Timeline"));
    assert!(markdown.contains("## Events"));
    assert!(markdown.contains("## Mitigations"));
}

#[tokio::test]
async fn test_incident_report_by_ip() {
    let app = setup_app().await;

    // Ingest event
    let body = serde_json::json!({
        "timestamp": "2026-01-16T15:00:00Z",
        "source": "fastnetmon",
        "victim_ip": "203.0.113.231",
        "vector": "syn_flood",
        "bps": 2000000000i64
    });
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Generate report by IP
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/reports/incident?ip=203.0.113.231")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let markdown = String::from_utf8(body.to_vec()).unwrap();
    assert!(markdown.contains("# Incident Report"));
    assert!(markdown.contains("203.0.113.231"));
}

#[tokio::test]
async fn test_incident_report_missing_params() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/reports/incident")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// Per-destination event routing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_alerting_config_per_destination_events_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let alerting_path = dir.path().join("alerting.yaml");
    std::fs::write(
        &alerting_path,
        r#"
destinations:
  - type: generic
    url: "https://example.com/all"
  - type: generic
    url: "https://example.com/critical"
    events:
      - mitigation.created
      - mitigation.escalated
events:
  - mitigation.created
  - mitigation.withdrawn
"#,
    )
    .unwrap();

    let config = prefixd::alerting::AlertingConfig::load(&alerting_path).unwrap();
    assert_eq!(config.destinations.len(), 2);

    // First dest has no per-destination events
    assert!(config.destinations[0].events().is_empty());
    // Second dest has per-destination events
    assert_eq!(config.destinations[1].events().len(), 2);

    // Save and reload
    config.save(&alerting_path).unwrap();
    let reloaded = prefixd::alerting::AlertingConfig::load(&alerting_path).unwrap();
    assert_eq!(reloaded.destinations[1].events().len(), 2);
}

// ---------------------------------------------------------------------------
// Notification preferences API
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_notification_preferences_get_default() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/preferences")
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
    assert_eq!(json["muted_events"], serde_json::json!([]));
    assert_eq!(json["quiet_hours_start"], serde_json::Value::Null);
    assert_eq!(json["quiet_hours_end"], serde_json::Value::Null);
}

#[tokio::test]
async fn test_notification_preferences_put_invalid_hour() {
    let app = setup_app().await;

    let body = serde_json::json!({
        "muted_events": [],
        "quiet_hours_start": 25,
        "quiet_hours_end": 8,
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/preferences")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_notification_preferences_put_invalid_event() {
    let app = setup_app().await;

    let body = serde_json::json!({
        "muted_events": ["not.a.real.event"],
        "quiet_hours_start": null,
        "quiet_hours_end": null,
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/preferences")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_notification_preferences_put_accepts_legacy_escalated_event() {
    let app = setup_app().await;

    let body = serde_json::json!({
        "muted_events": ["mitigation.escalated"],
        "quiet_hours_start": null,
        "quiet_hours_end": null,
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/preferences")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_notification_preferences_put_half_configured_quiet_hours() {
    let app = setup_app().await;

    let body = serde_json::json!({
        "muted_events": [],
        "quiet_hours_start": 2,
        "quiet_hours_end": null,
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/preferences")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_notification_preferences_response_includes_null_quiet_hours() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/preferences")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let raw = String::from_utf8_lossy(&body);
    assert!(raw.contains("\"quiet_hours_start\":null"));
    assert!(raw.contains("\"quiet_hours_end\":null"));
}

// ==========================================================================
// Correlation integration tests
// ==========================================================================

fn test_settings_with_correlation(
    enabled: bool,
    min_sources: u32,
    confidence_threshold: f32,
) -> Settings {
    let mut settings = test_settings();
    settings.correlation = prefixd::correlation::CorrelationConfig {
        enabled,
        window_seconds: 300,
        min_sources,
        confidence_threshold,
        sources: {
            let mut m = std::collections::HashMap::new();
            m.insert(
                "detector_a".to_string(),
                prefixd::correlation::SourceConfig {
                    weight: 1.0,
                    r#type: "detector".to_string(),
                    confidence_mapping: std::collections::HashMap::new(),
                    ..Default::default()
                },
            );
            m.insert(
                "detector_b".to_string(),
                prefixd::correlation::SourceConfig {
                    weight: 1.5,
                    r#type: "detector".to_string(),
                    confidence_mapping: std::collections::HashMap::new(),
                    ..Default::default()
                },
            );
            m
        },
        default_weight: 1.0,
        ..Default::default()
    };
    settings
}

async fn setup_app_correlation(
    enabled: bool,
    min_sources: u32,
    confidence_threshold: f32,
) -> axum::Router {
    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let settings = test_settings_with_correlation(enabled, min_sources, confidence_threshold);

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("failed to create app state");

    create_test_router(state)
}

fn make_event_json(source: &str, victim_ip: &str, confidence: f32) -> String {
    format!(
        r#"{{
            "timestamp": "2026-01-16T14:00:00Z",
            "source": "{}",
            "victim_ip": "{}",
            "vector": "udp_flood",
            "bps": 100000000,
            "pps": 50000,
            "top_dst_ports": [53],
            "confidence": {}
        }}"#,
        source, victim_ip, confidence
    )
}

async fn post_event(app: &axum::Router, event_json: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_json.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    (status, json)
}

/// VAL-ENGINE-010: Single source triggers when min_sources=1 (backward compat)
#[tokio::test]
async fn test_correlation_min_sources_1_triggers_immediately() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    let (status, json) = post_event(&app, &event).await;

    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(json["status"], "accepted");
    assert!(
        json["mitigation_id"].is_string(),
        "should create mitigation with min_sources=1: {:?}",
        json
    );
}

/// VAL-ENGINE-009: min_sources=2 and one source does NOT create mitigation
#[tokio::test]
async fn test_correlation_min_sources_2_one_source_no_mitigation() {
    let app = setup_app_correlation(true, 2, 0.5).await;

    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    let (status, json) = post_event(&app, &event).await;

    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(json["status"], "accepted");
    assert!(
        json["mitigation_id"].is_null(),
        "should NOT create mitigation with 1 source when min_sources=2"
    );
}

/// VAL-ENGINE-009: min_sources=2 and two sources creates mitigation
#[tokio::test]
async fn test_correlation_min_sources_2_two_sources_creates_mitigation() {
    let app = setup_app_correlation(true, 2, 0.5).await;

    // First event from detector_a — no mitigation
    let event_a = make_event_json("detector_a", "203.0.113.10", 0.9);
    let (status_a, json_a) = post_event(&app, &event_a).await;
    assert_eq!(status_a, StatusCode::ACCEPTED);
    assert!(
        json_a["mitigation_id"].is_null(),
        "first source alone shouldn't trigger"
    );

    // Second event from detector_b — mitigation created
    let event_b = make_event_json("detector_b", "203.0.113.10", 0.8);
    let (status_b, json_b) = post_event(&app, &event_b).await;
    assert_eq!(status_b, StatusCode::ACCEPTED);
    assert_eq!(json_b["status"], "accepted");
    assert!(
        json_b["mitigation_id"].is_string(),
        "second source should trigger mitigation: {:?}",
        json_b
    );
}

/// VAL-ENGINE-020: Events bypass correlation when disabled
#[tokio::test]
async fn test_correlation_disabled_bypasses_entirely() {
    let app = setup_app_correlation(false, 2, 0.5).await;

    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    let (status, json) = post_event(&app, &event).await;

    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(json["status"], "accepted");
    assert!(
        json["mitigation_id"].is_string(),
        "should create mitigation immediately when correlation disabled"
    );
}

/// VAL-ENGINE-029: EventResponse shape unchanged
#[tokio::test]
async fn test_correlation_event_response_shape_unchanged() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    let (status, json) = post_event(&app, &event).await;

    assert_eq!(status, StatusCode::ACCEPTED);
    assert!(json["event_id"].is_string(), "event_id must be present");
    assert!(json["status"].is_string(), "status must be present");
    // mitigation_id may be string or null
    assert!(
        json["mitigation_id"].is_string() || json["mitigation_id"].is_null(),
        "mitigation_id must be string or null"
    );
}

/// VAL-ENGINE-013: Derived confidence must meet threshold
#[tokio::test]
async fn test_correlation_low_confidence_no_mitigation() {
    // Two sources but very low confidence with threshold 0.7
    let app = setup_app_correlation(true, 2, 0.7).await;

    let event_a = make_event_json("detector_a", "203.0.113.10", 0.3);
    post_event(&app, &event_a).await;

    let event_b = make_event_json("detector_b", "203.0.113.10", 0.3);
    let (status, json) = post_event(&app, &event_b).await;

    assert_eq!(status, StatusCode::ACCEPTED);
    assert!(
        json["mitigation_id"].is_null(),
        "low confidence should not trigger even with 2 sources: {:?}",
        json
    );
}

/// VAL-ENGINE-011: Duplicate source counts as one for corroboration
#[tokio::test]
async fn test_correlation_duplicate_source_counts_as_one() {
    let app = setup_app_correlation(true, 2, 0.5).await;

    // Two events from same source
    let event_a = make_event_json("detector_a", "203.0.113.10", 0.9);
    post_event(&app, &event_a).await;

    // Use a different event_id to avoid duplicate detection
    let event_b = make_event_json("detector_a", "203.0.113.10", 0.8);
    let (status, json) = post_event(&app, &event_b).await;

    assert_eq!(status, StatusCode::ACCEPTED);
    assert!(
        json["mitigation_id"].is_null(),
        "same source twice should count as 1 distinct, not trigger with min_sources=2"
    );
}

/// VAL-ENGINE-030: Batch endpoint works with correlation
#[tokio::test]
async fn test_correlation_batch_endpoint_independent_groups() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    let batch_json = r#"{
        "events": [
            {
                "timestamp": "2026-01-16T14:00:00Z",
                "source": "detector_a",
                "victim_ip": "203.0.113.10",
                "vector": "udp_flood",
                "bps": 100000000,
                "pps": 50000,
                "top_dst_ports": [53],
                "confidence": 0.9
            },
            {
                "timestamp": "2026-01-16T14:00:01Z",
                "source": "detector_a",
                "victim_ip": "203.0.113.11",
                "vector": "udp_flood",
                "bps": 50000000,
                "pps": 25000,
                "top_dst_ports": [53],
                "confidence": 0.8
            }
        ]
    }"#;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events/batch")
                .header("content-type", "application/json")
                .body(Body::from(batch_json))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be 202 (all accepted) with min_sources=1
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["accepted"], 2);
    // Each event should create a mitigation independently
    let results = json["results"].as_array().unwrap();
    assert!(results[0]["mitigation_id"].is_string());
    assert!(results[1]["mitigation_id"].is_string());
    // Different victim IPs = different mitigations
    assert_ne!(results[0]["mitigation_id"], results[1]["mitigation_id"]);
}

/// VAL-ENGINE-018 / VAL-ENGINE-033: Mitigation detail/list includes correlation context
#[tokio::test]
async fn test_correlation_mitigation_detail_includes_correlation() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    // Create a correlated mitigation
    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    let (_, event_json) = post_event(&app, &event).await;
    let mitigation_id = event_json["mitigation_id"].as_str().unwrap();

    // GET /v1/mitigations/{id}
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/mitigations/{}", mitigation_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Should have correlation field
    assert!(
        json["correlation"].is_object(),
        "correlation should be present: {:?}",
        json
    );
    let corr = &json["correlation"];
    assert!(corr["signal_group_id"].is_string());
    assert!(corr["derived_confidence"].is_number());
    assert!(corr["source_count"].is_number());
    assert!(corr["corroboration_met"].is_boolean());
    assert!(corr["contributing_sources"].is_array());
    assert!(corr["explanation"].is_string());
}

/// VAL-ENGINE-019: Non-correlated mitigation has null correlation
#[tokio::test]
async fn test_correlation_disabled_mitigation_no_correlation_field() {
    let app = setup_app_correlation(false, 1, 0.5).await;

    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    let (_, event_json) = post_event(&app, &event).await;
    let mitigation_id = event_json["mitigation_id"].as_str().unwrap();

    // GET /v1/mitigations/{id}
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/mitigations/{}", mitigation_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // correlation should be absent (skipped when None)
    assert!(
        json["correlation"].is_null(),
        "correlation should be null/absent when disabled: {:?}",
        json
    );
}

/// VAL-ENGINE-004: Signal group resolves when mitigation created
#[tokio::test]
async fn test_correlation_signal_group_resolves_on_mitigation() {
    let repo = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let settings = test_settings_with_correlation(true, 1, 0.5);

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo.clone(),
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("failed to create app state");

    let app = create_test_router(state);

    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    post_event(&app, &event).await;

    // Check that the signal group was resolved
    let groups = repo
        .list_signal_groups(
            &prefixd::correlation::SignalGroupFilter {
                status: Some(prefixd::correlation::SignalGroupStatus::Resolved),
                ..Default::default()
            },
            &prefixd::db::ListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(groups.len(), 1, "should have one resolved group");
    assert!(
        groups[0].corroboration_met,
        "corroboration_met should be true"
    );
    assert_eq!(groups[0].source_count, 1);
}

/// VAL-ENGINE-033: Mitigations list includes correlation summary
#[tokio::test]
async fn test_correlation_mitigations_list_includes_summary() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    post_event(&app, &event).await;

    // GET /v1/mitigations
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let mitigations = json["mitigations"].as_array().unwrap();
    assert!(!mitigations.is_empty());
    let corr = &mitigations[0]["correlation"];
    assert!(
        corr.is_object(),
        "list should include correlation summary: {:?}",
        mitigations[0]
    );
    // Lightweight summary fields are present
    assert!(corr["signal_group_id"].is_string());
    assert!(corr["derived_confidence"].is_number());
    assert!(corr["source_count"].is_number());
    assert!(corr["corroboration_met"].is_boolean());
    // Detail-only fields are absent (null) in list view
    assert!(
        corr.get("contributing_sources").is_none() || corr["contributing_sources"].is_null(),
        "contributing_sources should be absent in list view, got: {:?}",
        corr["contributing_sources"]
    );
    assert!(
        corr.get("explanation").is_none() || corr["explanation"].is_null(),
        "explanation should be absent in list view, got: {:?}",
        corr["explanation"]
    );
}

/// List vs detail consistency: detail endpoint has contributing_sources and explanation
#[tokio::test]
async fn test_correlation_detail_has_full_context_list_has_summary() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    let (_, event_json) = post_event(&app, &event).await;
    let mitigation_id = event_json["mitigation_id"].as_str().unwrap();

    // Detail endpoint should have full context
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/mitigations/{}", mitigation_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let detail: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let detail_corr = &detail["correlation"];
    assert!(
        detail_corr["contributing_sources"].is_array(),
        "detail should have contributing_sources"
    );
    assert!(
        detail_corr["explanation"].is_string(),
        "detail should have explanation"
    );
    assert!(
        !detail_corr["contributing_sources"]
            .as_array()
            .unwrap()
            .is_empty(),
        "detail contributing_sources should not be empty"
    );
    assert!(
        !detail_corr["explanation"].as_str().unwrap().is_empty(),
        "detail explanation should not be empty"
    );

    // List endpoint should have lightweight summary (no contributing_sources, no explanation)
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let list: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let list_corr = &list["mitigations"][0]["correlation"];
    assert!(
        list_corr["signal_group_id"].is_string(),
        "list should have signal_group_id"
    );
    assert!(
        list_corr["derived_confidence"].is_number(),
        "list should have derived_confidence"
    );
    assert!(
        list_corr.get("contributing_sources").is_none()
            || list_corr["contributing_sources"].is_null(),
        "list should NOT have contributing_sources"
    );
    assert!(
        list_corr.get("explanation").is_none() || list_corr["explanation"].is_null(),
        "list should NOT have explanation"
    );
}

/// VAL-CROSS-009: Corroborated mitigations pass through guardrails — safelisted IP rejected
#[tokio::test]
async fn test_correlation_guardrails_still_apply() {
    // Create app with safelist
    let repo = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let settings = test_settings_with_correlation(true, 1, 0.5);

    // Add IP to safelist
    repo.insert_safelist("203.0.113.10", "admin", Some("core router"))
        .await
        .unwrap();

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("failed to create app state");

    let app = create_test_router(state);

    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    let (status, json) = post_event(&app, &event).await;

    // Should be rejected by guardrails
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(json["error"].as_str().unwrap().contains("safelist"));
}

/// Fix: If guardrails reject a corroborated mitigation, the signal group must stay 'open'
/// (not incorrectly resolved). This verifies that group status is only set to 'resolved'
/// AFTER insert_mitigation() succeeds.
#[tokio::test]
async fn test_correlation_guardrails_reject_keeps_group_open() {
    let repo = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let settings = test_settings_with_correlation(true, 1, 0.5);

    // Add IP to safelist so guardrails will reject
    repo.insert_safelist("203.0.113.10", "admin", Some("core router"))
        .await
        .unwrap();

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo.clone(),
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("failed to create app state");

    let app = create_test_router(state);

    // Submit event — corroboration will be met (min_sources=1) but guardrails will reject
    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    let (status, _json) = post_event(&app, &event).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // Verify: signal group was created and is still 'open' (not 'resolved')
    let open_groups = repo
        .list_signal_groups(
            &prefixd::correlation::SignalGroupFilter {
                status: Some(prefixd::correlation::SignalGroupStatus::Open),
                ..Default::default()
            },
            &prefixd::db::ListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(open_groups.len(), 1, "should have one open group");

    // Also verify no resolved groups exist
    let resolved_groups = repo
        .list_signal_groups(
            &prefixd::correlation::SignalGroupFilter {
                status: Some(prefixd::correlation::SignalGroupStatus::Resolved),
                ..Default::default()
            },
            &prefixd::db::ListParams {
                limit: 100,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        resolved_groups.len(),
        0,
        "no groups should be resolved when guardrails reject"
    );

    // Verify the open group has corroboration_met = true (corroboration passed, but mitigation was rejected)
    assert!(
        open_groups[0].corroboration_met,
        "corroboration should be met even though guardrails rejected"
    );
}

// ── Signal Groups API Tests ────────────────────────────────────────────

/// Helper: create an app with correlation enabled and a shared repo reference
async fn setup_app_correlation_with_repo(
    min_sources: u32,
    confidence_threshold: f32,
) -> (axum::Router, Arc<dyn RepositoryTrait>) {
    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let settings = test_settings_with_correlation(true, min_sources, confidence_threshold);

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo.clone(),
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("failed to create app state");

    (create_test_router(state), repo)
}

/// VAL-ENGINE-016: GET /v1/signal-groups returns paginated list with cursor, has_more
#[tokio::test]
async fn test_signal_groups_list_basic() {
    let (app, _repo) = setup_app_correlation_with_repo(1, 0.5).await;

    // Ingest events to create signal groups
    let event1 = make_event_json("detector_a", "203.0.113.10", 0.9);
    let event2 = make_event_json("detector_a", "203.0.113.11", 0.8);
    post_event(&app, &event1).await;
    post_event(&app, &event2).await;

    // GET /v1/signal-groups
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["groups"].is_array());
    assert_eq!(json["groups"].as_array().unwrap().len(), 2);
    assert_eq!(json["count"], 2);
    assert!(!json["has_more"].as_bool().unwrap());
    assert!(json["next_cursor"].is_null());
}

/// VAL-ENGINE-016: Cursor pagination works correctly
#[tokio::test]
async fn test_signal_groups_list_pagination() {
    let (app, _repo) = setup_app_correlation_with_repo(1, 0.5).await;

    // Create 3 signal groups (3 different IPs)
    for i in 10..13 {
        let event = make_event_json("detector_a", &format!("203.0.113.{}", i), 0.9);
        post_event(&app, &event).await;
    }

    // Request page 1 with limit=2
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups?limit=2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["groups"].as_array().unwrap().len(), 2);
    assert_eq!(json["count"], 2);
    assert!(json["has_more"].as_bool().unwrap());
    let cursor = json["next_cursor"].as_str().unwrap();

    // Request page 2 using cursor
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/signal-groups?limit=2&cursor={}", cursor))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json2: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json2["groups"].as_array().unwrap().len(), 1);
    assert_eq!(json2["count"], 1);
    assert!(!json2["has_more"].as_bool().unwrap());
}

/// VAL-ENGINE-016: Status filter returns only matching groups
#[tokio::test]
async fn test_signal_groups_list_status_filter() {
    let (app, _repo) = setup_app_correlation_with_repo(1, 0.5).await;

    // Create events → signal groups with min_sources=1 → groups become resolved
    let event1 = make_event_json("detector_a", "203.0.113.10", 0.9);
    let event2 = make_event_json("detector_a", "203.0.113.11", 0.8);
    post_event(&app, &event1).await;
    post_event(&app, &event2).await;

    // With min_sources=1 and confidence above threshold, groups should be resolved
    // Filter for resolved
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups?status=resolved")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // All groups should be resolved since min_sources=1 and confidence >= 0.5
    for group in json["groups"].as_array().unwrap() {
        assert_eq!(group["status"], "resolved");
    }

    // Filter for open — should return 0 since all were resolved
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups?status=open")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["groups"].as_array().unwrap().len(), 0);
}

/// VAL-ENGINE-016: Vector filter returns only matching groups
#[tokio::test]
async fn test_signal_groups_list_vector_filter() {
    let (app, _repo) = setup_app_correlation_with_repo(1, 0.5).await;

    // Create events (all go through udp_flood playbook)
    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    post_event(&app, &event).await;

    // Filter for udp_flood (should match)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups?vector=udp_flood")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(!json["groups"].as_array().unwrap().is_empty());

    // Filter for syn_flood (should not match)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups?vector=syn_flood")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["groups"].as_array().unwrap().len(), 0);
}

/// VAL-ENGINE-032: Date range filter works with start/end params
#[tokio::test]
async fn test_signal_groups_list_date_range_filter() {
    let (app, _repo) = setup_app_correlation_with_repo(1, 0.5).await;

    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    post_event(&app, &event).await;

    // Use a future start date — should return 0 groups
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups?start=2099-01-01T00:00:00Z")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["groups"].as_array().unwrap().len(), 0);

    // Use a past start date — should return groups
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups?start=2020-01-01T00:00:00Z")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(!json["groups"].as_array().unwrap().is_empty());

    // Use a past end date — should return 0 groups
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups?end=2020-01-01T00:00:00Z")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["groups"].as_array().unwrap().len(), 0);
}

/// VAL-ENGINE-017: GET /v1/signal-groups/{id} returns group detail with contributing events
#[tokio::test]
async fn test_signal_group_detail_with_events() {
    let (app, _repo) = setup_app_correlation_with_repo(1, 0.5).await;

    // Create an event to generate a signal group
    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    post_event(&app, &event).await;

    // List groups to get the group ID
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let group_id = json["groups"][0]["group_id"].as_str().unwrap().to_string();

    // GET /v1/signal-groups/{id}
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/signal-groups/{}", group_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let detail: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Verify group metadata
    assert_eq!(detail["group_id"], group_id);
    assert_eq!(detail["victim_ip"], "203.0.113.10");
    assert_eq!(detail["vector"], "udp_flood");
    assert!(detail["derived_confidence"].is_number());
    assert!(detail["source_count"].is_number());
    assert!(detail["status"].is_string());
    assert!(detail["corroboration_met"].is_boolean());

    // Verify mitigation_id is present (min_sources=1, so mitigation was created)
    assert!(
        detail["mitigation_id"].is_string(),
        "Signal group detail should include mitigation_id when mitigation was created"
    );

    // Verify events list
    assert!(detail["events"].is_array());
    let events = detail["events"].as_array().unwrap();
    assert!(!events.is_empty());
    let ev = &events[0];
    assert!(ev["event_id"].is_string());
    assert!(ev["source_weight"].is_number());
    assert!(ev["source"].is_string());
    assert!(ev["confidence"].is_number());
    assert!(ev["ingested_at"].is_string());
}

/// Signal group detail has null mitigation_id when no mitigation was created
#[tokio::test]
async fn test_signal_group_detail_no_mitigation_id() {
    // Use min_sources=2 so first event alone does not trigger mitigation
    let (app, _repo) = setup_app_correlation_with_repo(2, 0.5).await;

    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    post_event(&app, &event).await;

    // Get the group ID
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let group_id = json["groups"][0]["group_id"].as_str().unwrap().to_string();

    // GET /v1/signal-groups/{id}
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/signal-groups/{}", group_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let detail: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // mitigation_id should be null since only one source submitted (need 2)
    assert!(
        detail["mitigation_id"].is_null(),
        "Signal group detail should have null mitigation_id when no mitigation exists"
    );
}

/// VAL-ENGINE-017: GET /v1/signal-groups/{id} returns 404 for unknown group
#[tokio::test]
async fn test_signal_group_detail_not_found() {
    let (app, _repo) = setup_app_correlation_with_repo(1, 0.5).await;

    let fake_id = uuid::Uuid::new_v4();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/signal-groups/{}", fake_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// VAL-ENGINE-016/017: Both endpoints require authentication (401 without)
#[tokio::test]
async fn test_signal_groups_auth_required() {
    // Create app with bearer auth
    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let mut settings = test_settings_with_correlation(true, 1, 0.5);
    settings.http.auth = prefixd::config::AuthConfig {
        mode: prefixd::config::AuthMode::Bearer,
        bearer_token_env: Some("TEST_PREFIXD_TOKEN".to_string()),
    };
    settings.http.auth.mode = AuthMode::Credentials;

    let mut state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("failed to create app state");

    let cached = Arc::get_mut(&mut state).expect("unshared test state");
    cached.settings.http.auth.mode = AuthMode::Bearer;
    cached.bearer_token = Some("test-secret-token-123".into());
    let app = create_test_router(state);

    // GET /v1/signal-groups without auth → 401
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // GET /v1/signal-groups/{id} without auth → 401
    let fake_id = uuid::Uuid::new_v4();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/signal-groups/{}", fake_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // GET /v1/signal-groups with auth → 200
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups")
                .header("authorization", "Bearer test-secret-token-123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// VAL-ENGINE-034: OpenAPI spec includes signal groups endpoints
#[tokio::test]
async fn test_openapi_includes_signal_groups() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let spec: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let paths = spec["paths"].as_object().unwrap();
    assert!(
        paths.contains_key("/v1/signal-groups"),
        "OpenAPI spec should include /v1/signal-groups"
    );
    assert!(
        paths.contains_key("/v1/signal-groups/{id}"),
        "OpenAPI spec should include /v1/signal-groups/{{id}}"
    );

    // Verify schemas are registered
    let schemas = spec["components"]["schemas"].as_object().unwrap();
    assert!(
        schemas.contains_key("SignalGroup"),
        "OpenAPI spec should include SignalGroup schema"
    );
    assert!(
        schemas.contains_key("SignalGroupEvent"),
        "OpenAPI spec should include SignalGroupEvent schema"
    );
    assert!(
        schemas.contains_key("SignalGroupsListResponse"),
        "OpenAPI spec should include SignalGroupsListResponse schema"
    );
    assert!(
        schemas.contains_key("SignalGroupDetailResponse"),
        "OpenAPI spec should include SignalGroupDetailResponse schema"
    );
    assert!(
        schemas.contains_key("CorrelationContext"),
        "OpenAPI spec should include CorrelationContext schema"
    );
    assert!(
        schemas.contains_key("CorrelationExplanation"),
        "OpenAPI spec should include CorrelationExplanation schema"
    );
    assert!(
        schemas.contains_key("SourceContribution"),
        "OpenAPI spec should include SourceContribution schema"
    );
}

/// VAL-ENGINE-017: Signal group detail with multiple contributing events
#[tokio::test]
async fn test_signal_group_detail_multiple_events() {
    // Use min_sources=2 so the group stays open after first event
    let (app, _repo) = setup_app_correlation_with_repo(2, 0.5).await;

    // Submit events from 2 different sources for same victim/vector
    let event1 = make_event_json("detector_a", "203.0.113.10", 0.9);
    let event2 = make_event_json("detector_b", "203.0.113.10", 0.7);
    post_event(&app, &event1).await;
    post_event(&app, &event2).await;

    // List groups — should have exactly 1 group
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json["groups"].as_array().unwrap().len(),
        1,
        "Should have exactly one signal group for same (victim_ip, vector)"
    );

    let group_id = json["groups"][0]["group_id"].as_str().unwrap().to_string();

    // Get detail
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/signal-groups/{}", group_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let detail: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Should have 2 contributing events
    let events = detail["events"].as_array().unwrap();
    assert_eq!(events.len(), 2, "Should have 2 contributing events");

    // Verify both sources are represented
    let sources: Vec<&str> = events.iter().filter_map(|e| e["source"].as_str()).collect();
    assert!(sources.contains(&"detector_a"));
    assert!(sources.contains(&"detector_b"));

    // Verify source_weight values
    for ev in events {
        assert!(ev["source_weight"].as_f64().unwrap() > 0.0);
    }
}

/// VAL-CROSS-012: Incident reports include correlation data
#[tokio::test]
async fn test_correlation_incident_report_includes_correlation() {
    let repo = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let settings = test_settings_with_correlation(true, 1, 0.5);

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo.clone(),
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("failed to create app state");

    let app = create_test_router(state);

    let event = make_event_json("detector_a", "203.0.113.10", 0.9);
    post_event(&app, &event).await;

    // Get incident report
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/reports/incident?ip=203.0.113.10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let md = String::from_utf8_lossy(&body);

    assert!(
        md.contains("## Correlation"),
        "incident report should include Correlation section: {}",
        md
    );
    assert!(
        md.contains("Derived Confidence"),
        "incident report should include derived confidence"
    );
    assert!(
        md.contains("Source Count"),
        "incident report should include source count"
    );
}

// ==========================================================================
// Alertmanager webhook adapter tests
// ==========================================================================

fn make_alertmanager_payload(alerts: &[serde_json::Value]) -> String {
    serde_json::json!({
        "version": "4",
        "status": "firing",
        "alerts": alerts,
        "groupLabels": {"alertname": "udp_flood"},
        "commonLabels": {},
        "commonAnnotations": {},
        "externalURL": "http://alertmanager.example.com"
    })
    .to_string()
}

fn make_alert(
    status: &str,
    victim_ip: &str,
    vector: &str,
    severity: &str,
    fingerprint: &str,
) -> serde_json::Value {
    serde_json::json!({
        "status": status,
        "labels": {
            "victim_ip": victim_ip,
            "vector": vector,
            "severity": severity,
            "alertname": "DDoS_Alert"
        },
        "annotations": {
            "bps": "100000000",
            "pps": "50000"
        },
        "startsAt": "2026-01-16T14:00:00Z",
        "endsAt": "0001-01-01T00:00:00Z",
        "generatorURL": "http://prometheus:9090/graph",
        "fingerprint": fingerprint
    })
}

async fn post_alertmanager(app: &axum::Router, payload: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/alertmanager")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    (status, json)
}

/// VAL-ADAPT-001: Valid Alertmanager v4 webhook accepted (returns 200, creates events)
#[tokio::test]
async fn test_alertmanager_valid_payload() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    let alert = make_alert("firing", "203.0.113.10", "udp_flood", "critical", "abc123");
    let payload = make_alertmanager_payload(&[alert]);

    let (status, json) = post_alertmanager(&app, &payload).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);
    assert_eq!(json["failed"], 0);
    assert_eq!(json["results"].as_array().unwrap().len(), 1);

    let result = &json["results"][0];
    assert_eq!(result["index"], 0);
    assert!(result["event_id"].is_string(), "should have event_id");
    // With min_sources=1, corroboration met → mitigation created
    assert!(
        result["status"].as_str().unwrap() != "error",
        "should not be error: {:?}",
        result
    );
}

/// VAL-ADAPT-002: Batched alerts processed individually (each creates a separate event)
#[tokio::test]
async fn test_alertmanager_batched_alerts() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    let alert1 = make_alert("firing", "203.0.113.10", "udp_flood", "critical", "fp1");
    let alert2 = make_alert("firing", "203.0.113.10", "udp_flood", "warning", "fp2");
    let alert3 = make_alert("firing", "203.0.113.10", "udp_flood", "info", "fp3");
    let payload = make_alertmanager_payload(&[alert1, alert2, alert3]);

    let (status, json) = post_alertmanager(&app, &payload).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 3);
    assert_eq!(json["failed"], 0);
    let results = json["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);

    // Each result should have an event_id
    for (i, r) in results.iter().enumerate() {
        assert_eq!(r["index"], i);
        assert!(
            r["event_id"].is_string(),
            "alert {} should have event_id",
            i
        );
    }
}

/// VAL-ADAPT-003: Vector from labels mapping (labels.vector takes priority over alertname)
#[tokio::test]
async fn test_alertmanager_vector_from_labels() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    // Test with labels.vector present
    let alert_with_vector = serde_json::json!({
        "status": "firing",
        "labels": {
            "victim_ip": "203.0.113.10",
            "vector": "udp_flood",
            "alertname": "should_not_use_this"
        },
        "annotations": {},
        "startsAt": "2026-01-16T14:00:00Z",
        "fingerprint": "vec_test_1"
    });
    let payload = make_alertmanager_payload(&[alert_with_vector]);
    let (status, json) = post_alertmanager(&app, &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);

    // Test with only alertname (fallback)
    let alert_with_alertname = serde_json::json!({
        "status": "firing",
        "labels": {
            "victim_ip": "203.0.113.10",
            "alertname": "syn_flood"
        },
        "annotations": {},
        "startsAt": "2026-01-16T14:00:00Z",
        "fingerprint": "vec_test_2"
    });
    let payload = make_alertmanager_payload(&[alert_with_alertname]);
    let (status, json) = post_alertmanager(&app, &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);

    // Test with neither → per-alert error
    let alert_no_vector = serde_json::json!({
        "status": "firing",
        "labels": {
            "victim_ip": "203.0.113.10"
        },
        "annotations": {},
        "startsAt": "2026-01-16T14:00:00Z",
        "fingerprint": "vec_test_3"
    });
    let payload = make_alertmanager_payload(&[alert_no_vector]);
    let (status, json) = post_alertmanager(&app, &payload).await;
    assert_eq!(status, StatusCode::OK);
    // The alert with missing vector should be reported as failed
    assert_eq!(json["failed"], 1);
    assert!(
        json["results"][0]["error"]
            .as_str()
            .unwrap()
            .contains("missing vector")
    );
}

/// VAL-ADAPT-004: Victim IP extraction with port stripping
#[tokio::test]
async fn test_alertmanager_victim_ip_port_stripping() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    // labels.victim_ip takes priority
    let alert_victim_ip = serde_json::json!({
        "status": "firing",
        "labels": {
            "victim_ip": "203.0.113.10",
            "instance": "10.0.0.1:9090",
            "vector": "udp_flood"
        },
        "annotations": {},
        "startsAt": "2026-01-16T14:00:00Z",
        "fingerprint": "ip_test_1"
    });
    let payload = make_alertmanager_payload(&[alert_victim_ip]);
    let (status, json) = post_alertmanager(&app, &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);

    // Fallback to instance with port stripping
    let alert_instance = serde_json::json!({
        "status": "firing",
        "labels": {
            "instance": "203.0.113.10:9090",
            "vector": "udp_flood"
        },
        "annotations": {},
        "startsAt": "2026-01-16T14:00:00Z",
        "fingerprint": "ip_test_2"
    });
    let payload = make_alertmanager_payload(&[alert_instance]);
    let (status, json) = post_alertmanager(&app, &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);

    // Missing both → per-alert error
    let alert_no_ip = serde_json::json!({
        "status": "firing",
        "labels": {
            "vector": "udp_flood"
        },
        "annotations": {},
        "startsAt": "2026-01-16T14:00:00Z",
        "fingerprint": "ip_test_3"
    });
    let payload = make_alertmanager_payload(&[alert_no_ip]);
    let (status, json) = post_alertmanager(&app, &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["failed"], 1);
    assert!(
        json["results"][0]["error"]
            .as_str()
            .unwrap()
            .contains("missing victim_ip")
    );
}

/// VAL-ADAPT-005: BPS/PPS from annotations parsed as optional i64
#[tokio::test]
async fn test_alertmanager_bps_pps_annotations() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    // With valid bps and pps
    let alert_with_metrics = serde_json::json!({
        "status": "firing",
        "labels": {
            "victim_ip": "203.0.113.10",
            "vector": "udp_flood"
        },
        "annotations": {
            "bps": "500000000",
            "pps": "1000000"
        },
        "startsAt": "2026-01-16T14:00:00Z",
        "fingerprint": "metrics_test_1"
    });
    let payload = make_alertmanager_payload(&[alert_with_metrics]);
    let (status, json) = post_alertmanager(&app, &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);

    // With non-numeric values (should be treated as None, not error)
    let alert_bad_metrics = serde_json::json!({
        "status": "firing",
        "labels": {
            "victim_ip": "203.0.113.10",
            "vector": "udp_flood"
        },
        "annotations": {
            "bps": "not_a_number",
            "pps": "also_bad"
        },
        "startsAt": "2026-01-16T14:00:00Z",
        "fingerprint": "metrics_test_2"
    });
    let payload = make_alertmanager_payload(&[alert_bad_metrics]);
    let (status, json) = post_alertmanager(&app, &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1); // Should still succeed

    // With missing annotations
    let alert_no_metrics = serde_json::json!({
        "status": "firing",
        "labels": {
            "victim_ip": "203.0.113.10",
            "vector": "udp_flood"
        },
        "annotations": {},
        "startsAt": "2026-01-16T14:00:00Z",
        "fingerprint": "metrics_test_3"
    });
    let payload = make_alertmanager_payload(&[alert_no_metrics]);
    let (status, json) = post_alertmanager(&app, &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);
}

/// VAL-ADAPT-006: Severity to confidence mapping
#[tokio::test]
async fn test_alertmanager_severity_confidence_mapping() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    // Test each severity level
    for (severity, _expected_confidence, fp) in [
        ("critical", 0.9, "sev_1"),
        ("warning", 0.7, "sev_2"),
        ("info", 0.5, "sev_3"),
    ] {
        let alert = serde_json::json!({
            "status": "firing",
            "labels": {
                "victim_ip": "203.0.113.10",
                "vector": "udp_flood",
                "severity": severity
            },
            "annotations": {},
            "startsAt": "2026-01-16T14:00:00Z",
            "fingerprint": fp
        });
        let payload = make_alertmanager_payload(&[alert]);
        let (status, json) = post_alertmanager(&app, &payload).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "severity={} should succeed",
            severity
        );
        assert_eq!(
            json["processed"], 1,
            "severity={} should be processed",
            severity
        );
    }

    // Missing severity → defaults to 0.5 (same as "info")
    let alert_no_severity = serde_json::json!({
        "status": "firing",
        "labels": {
            "victim_ip": "203.0.113.10",
            "vector": "udp_flood"
        },
        "annotations": {},
        "startsAt": "2026-01-16T14:00:00Z",
        "fingerprint": "sev_4"
    });
    let payload = make_alertmanager_payload(&[alert_no_severity]);
    let (status, json) = post_alertmanager(&app, &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);
}

/// VAL-ADAPT-007: Resolved alerts trigger withdraw (action="unban")
#[tokio::test]
async fn test_alertmanager_resolved_alerts_trigger_withdraw() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    // First fire an alert to create a mitigation
    let fire_alert = make_alert(
        "firing",
        "203.0.113.10",
        "udp_flood",
        "critical",
        "resolve_fp",
    );
    let payload = make_alertmanager_payload(&[fire_alert]);
    let (status, json) = post_alertmanager(&app, &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);

    // Now send resolved alert with same fingerprint
    let resolve_alert = make_alert(
        "resolved",
        "203.0.113.10",
        "udp_flood",
        "critical",
        "resolve_fp",
    );
    let payload = make_alertmanager_payload(&[resolve_alert]);
    let (status, json) = post_alertmanager(&app, &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);
    // The result should be withdrawal-related
    let result = &json["results"][0];
    assert!(
        result["status"].as_str().unwrap().starts_with("withdrawn"),
        "resolved alert should trigger withdraw: {:?}",
        result
    );
}

/// VAL-ADAPT-008: Fingerprint deduplication (same source + fingerprint = duplicate)
#[tokio::test]
async fn test_alertmanager_fingerprint_dedup() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    let alert = make_alert(
        "firing",
        "203.0.113.10",
        "udp_flood",
        "critical",
        "dedup_fp",
    );
    let payload = make_alertmanager_payload(std::slice::from_ref(&alert));

    // First request
    let (status1, json1) = post_alertmanager(&app, &payload).await;
    assert_eq!(status1, StatusCode::OK);
    assert_eq!(json1["processed"], 1);

    // Second request with same fingerprint → duplicate
    let payload2 = make_alertmanager_payload(&[alert]);
    let (status2, json2) = post_alertmanager(&app, &payload2).await;
    assert_eq!(status2, StatusCode::OK);
    // Duplicate should be detected
    let result = &json2["results"][0];
    assert_eq!(
        result["status"].as_str().unwrap(),
        "duplicate",
        "second submission of same fingerprint should be duplicate"
    );
}

/// VAL-ADAPT-009: Malformed payloads return 400 (not 500)
#[tokio::test]
async fn test_alertmanager_malformed_payload_returns_400() {
    let app = setup_app().await;

    // Invalid JSON
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/alertmanager")
                .header("content-type", "application/json")
                .body(Body::from("not valid json"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Wrong version
    let wrong_version = serde_json::json!({
        "version": "3",
        "status": "firing",
        "alerts": [{"status": "firing", "labels": {}, "annotations": {}}],
        "groupLabels": {},
        "commonLabels": {},
        "commonAnnotations": {},
        "externalURL": ""
    })
    .to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/alertmanager")
                .header("content-type", "application/json")
                .body(Body::from(wrong_version))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Missing required fields (alerts array)
    let missing_alerts = serde_json::json!({
        "version": "4",
        "status": "firing"
    })
    .to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/alertmanager")
                .header("content-type", "application/json")
                .body(Body::from(missing_alerts))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Empty alerts array
    let empty_alerts = serde_json::json!({
        "version": "4",
        "status": "firing",
        "alerts": [],
        "groupLabels": {},
        "commonLabels": {},
        "commonAnnotations": {},
        "externalURL": ""
    })
    .to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/alertmanager")
                .header("content-type", "application/json")
                .body(Body::from(empty_alerts))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// VAL-ADAPT-010: Authentication required (401 without auth)
#[tokio::test]
async fn test_alertmanager_auth_required() {
    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let mut settings = test_settings_with_correlation(true, 1, 0.5);
    settings.http.auth = prefixd::config::AuthConfig {
        mode: prefixd::config::AuthMode::Bearer,
        bearer_token_env: Some("TEST_PREFIXD_TOKEN".to_string()),
    };
    settings.http.auth.mode = AuthMode::Credentials;

    let mut state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("failed to create app state");

    let cached = Arc::get_mut(&mut state).expect("unshared test state");
    cached.settings.http.auth.mode = AuthMode::Bearer;
    cached.bearer_token = Some("test-secret-token-123".into());
    let app = create_test_router(state);

    let alert = make_alert("firing", "203.0.113.10", "udp_flood", "critical", "auth_fp");
    let payload = make_alertmanager_payload(&[alert]);

    // Without auth → 401
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/alertmanager")
                .header("content-type", "application/json")
                .body(Body::from(payload.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // With auth → 200
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/alertmanager")
                .header("content-type", "application/json")
                .header("authorization", "Bearer test-secret-token-123")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// VAL-ADAPT-018: Partial batch failure — mixed valid/invalid alerts
#[tokio::test]
async fn test_alertmanager_partial_batch_failure() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    let valid_alert = make_alert(
        "firing",
        "203.0.113.10",
        "udp_flood",
        "critical",
        "partial_1",
    );
    // Invalid: missing both victim_ip and instance
    let invalid_alert = serde_json::json!({
        "status": "firing",
        "labels": {
            "vector": "udp_flood"
        },
        "annotations": {},
        "startsAt": "2026-01-16T14:00:00Z",
        "fingerprint": "partial_2"
    });
    let valid_alert2 = make_alert(
        "firing",
        "203.0.113.10",
        "udp_flood",
        "warning",
        "partial_3",
    );
    let payload = make_alertmanager_payload(&[valid_alert, invalid_alert, valid_alert2]);

    let (status, json) = post_alertmanager(&app, &payload).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 2);
    assert_eq!(json["failed"], 1);

    let results = json["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
    // First and third should succeed
    assert!(
        results[0]["error"].is_null(),
        "first alert should succeed: {:?}",
        results[0]
    );
    // Second should have error
    assert!(
        results[1]["error"].is_string(),
        "second alert should fail: {:?}",
        results[1]
    );
    // Third should succeed
    assert!(
        results[2]["error"].is_null(),
        "third alert should succeed: {:?}",
        results[2]
    );
}

// ==========================================================================
// FastNetMon webhook adapter tests
// ==========================================================================

fn make_fastnetmon_payload(action: &str, ip: &str, attack_uuid: Option<&str>) -> String {
    let mut payload = serde_json::json!({
        "action": action,
        "ip": ip,
        "alert_scope": "host",
        "attack_details": {
            "attack_uuid": attack_uuid,
            "attack_severity": "middle",
            "attack_detection_source": "automatic",
            "attack_detection_threshold": "bytes per second",
            "attack_detection_threshold_direction": "incoming",
            "attack_start": "2026-01-16T14:00:00Z",
            "protocol_version": "IPv4",
            "host_group": "global",
            "host_network": "192.0.2.0/24",
            "incoming_udp_pps": 5000,
            "incoming_udp_traffic_bits": 50000000,
            "incoming_tcp_pps": 1000,
            "incoming_tcp_traffic_bits": 10000000,
            "incoming_syn_tcp_pps": 200,
            "incoming_syn_tcp_traffic_bits": 2000000,
            "incoming_icmp_pps": 100,
            "incoming_icmp_traffic_bits": 1000000,
            "incoming_ip_fragmented_pps": 0,
            "incoming_ip_fragmented_traffic_bits": 0,
            "total_incoming_pps": 6100,
            "total_incoming_traffic_bits": 61000000,
            "total_incoming_flows": 50,
            "total_outgoing_pps": 500,
            "total_outgoing_traffic_bits": 5000000,
            "total_outgoing_flows": 20
        }
    });
    // If attack_uuid is None, remove the field
    if attack_uuid.is_none() {
        payload["attack_details"]["attack_uuid"] = serde_json::Value::Null;
    }
    payload.to_string()
}

async fn post_fastnetmon(app: &axum::Router, payload: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/fastnetmon")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    (status, json)
}

/// Helper to setup app with FastNetMon source in correlation config with custom confidence mapping
async fn setup_app_fastnetmon_with_mapping(
    confidence_mapping: std::collections::HashMap<String, f32>,
) -> axum::Router {
    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let mut settings = test_settings_with_correlation(true, 1, 0.5);
    settings.correlation.sources.insert(
        "fastnetmon".to_string(),
        prefixd::correlation::SourceConfig {
            weight: 1.0,
            r#type: "detector".to_string(),
            confidence_mapping,
            ..Default::default()
        },
    );

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("failed to create app state");

    create_test_router(state)
}

/// VAL-ADAPT-011: Valid FastNetMon payload returns 202 with EventResponse shape
#[tokio::test]
async fn test_fastnetmon_valid_payload() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    let payload = make_fastnetmon_payload("ban", "203.0.113.10", Some("test-uuid-1"));
    let (status, json) = post_fastnetmon(&app, &payload).await;

    assert_eq!(status, StatusCode::ACCEPTED);
    assert!(json["event_id"].is_string(), "should have event_id");
    assert_eq!(
        json["status"], "accepted",
        "status should be 'accepted' (EventResponse shape)"
    );
    // mitigation_id should be present since min_sources=1 and confidence >= threshold
    assert!(
        json["mitigation_id"].is_string(),
        "should have mitigation_id with min_sources=1"
    );
}

#[tokio::test]
async fn test_fastnetmon_large_syn_counters_preserve_vector() {
    let scale = i64::MAX / 100;
    for (tcp_pps, syn_pps, expected) in [
        (i64::MAX, i64::MAX, "syn_flood"),
        (scale * 100, scale * 60, "ack_flood"),
        (scale * 100, scale * 61, "syn_flood"),
    ] {
        let (app, _repo) = setup_app_correlation_with_repo(1, 0.5).await;
        let mut payload: serde_json::Value = serde_json::from_str(&make_fastnetmon_payload(
            "ban",
            "203.0.113.10",
            Some("large-syn-counter"),
        ))
        .unwrap();
        let details = &mut payload["attack_details"];
        details["incoming_tcp_pps"] = tcp_pps.into();
        details["incoming_syn_tcp_pps"] = syn_pps.into();
        details["incoming_udp_pps"] = 0.into();
        details["incoming_icmp_pps"] = 0.into();
        details["total_incoming_pps"] = tcp_pps.into();

        let (status, accepted) = post_fastnetmon(&app, &payload.to_string()).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{expected}: {accepted}");
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/events")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let events = json["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["event_id"], accepted["event_id"]);
        assert_eq!(events[0]["source"], "fastnetmon");
        assert_eq!(events[0]["vector"], expected);
        assert_eq!(events[0]["pps"], tcp_pps);
    }
}

/// VAL-ADAPT-012: FastNetMon confidence mapping — default (ban=0.9, partial_block=0.7, alert=0.5)
#[tokio::test]
async fn test_fastnetmon_confidence_mapping_default() {
    // Test with ban action → default confidence 0.9
    let app = setup_app_correlation(true, 1, 0.5).await;

    let payload_ban = make_fastnetmon_payload("ban", "203.0.113.10", Some("conf-uuid-ban"));
    let (status, json) = post_fastnetmon(&app, &payload_ban).await;
    assert_eq!(status, StatusCode::ACCEPTED, "ban should succeed");
    assert!(json["event_id"].is_string(), "ban should have event_id");

    // Test partial_block
    let payload_partial =
        make_fastnetmon_payload("partial_block", "203.0.113.11", Some("conf-uuid-partial"));
    let (status, json) = post_fastnetmon(&app, &payload_partial).await;
    assert_eq!(status, StatusCode::ACCEPTED, "partial_block should succeed");
    assert!(
        json["event_id"].is_string(),
        "partial_block should have event_id"
    );

    // Test alert — confidence 0.5 which equals threshold, should succeed
    let payload_alert = make_fastnetmon_payload("alert", "203.0.113.12", Some("conf-uuid-alert"));
    let (status, json) = post_fastnetmon(&app, &payload_alert).await;
    assert_eq!(status, StatusCode::ACCEPTED, "alert should succeed");
    assert!(json["event_id"].is_string(), "alert should have event_id");
}

/// VAL-ADAPT-012: Config override changes confidence values
#[tokio::test]
async fn test_fastnetmon_confidence_mapping_override() {
    let mut mapping = std::collections::HashMap::new();
    mapping.insert("ban".to_string(), 0.6);
    mapping.insert("partial_block".to_string(), 0.4);
    mapping.insert("alert".to_string(), 0.2);

    let app = setup_app_fastnetmon_with_mapping(mapping).await;

    // With overridden mapping, ban now has confidence 0.6 (still above 0.5 threshold)
    let payload_ban = make_fastnetmon_payload("ban", "203.0.113.10", Some("override-uuid-ban"));
    let (status, json) = post_fastnetmon(&app, &payload_ban).await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "ban should succeed with override mapping"
    );
    assert!(
        json["event_id"].is_string(),
        "ban with override should have event_id"
    );
}

/// VAL-ADAPT-013: Malformed FastNetMon payload returns 400
#[tokio::test]
async fn test_fastnetmon_malformed_payload_returns_400() {
    let app = setup_app().await;

    // Invalid JSON
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/fastnetmon")
                .header("content-type", "application/json")
                .body(Body::from("not valid json"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Missing required 'ip' field
    let missing_ip = serde_json::json!({
        "action": "ban"
    })
    .to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/fastnetmon")
                .header("content-type", "application/json")
                .body(Body::from(missing_ip))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Missing required 'action' field
    let missing_action = serde_json::json!({
        "ip": "203.0.113.10"
    })
    .to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/fastnetmon")
                .header("content-type", "application/json")
                .body(Body::from(missing_action))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Empty ip
    let empty_ip = serde_json::json!({
        "action": "ban",
        "ip": ""
    })
    .to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/fastnetmon")
                .header("content-type", "application/json")
                .body(Body::from(empty_ip))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Invalid IP address
    let invalid_ip = serde_json::json!({
        "action": "ban",
        "ip": "not-an-ip"
    })
    .to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/fastnetmon")
                .header("content-type", "application/json")
                .body(Body::from(invalid_ip))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// VAL-ADAPT-017: Authentication required for FastNetMon endpoint
#[tokio::test]
async fn test_fastnetmon_auth_required() {
    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let mut settings = test_settings_with_correlation(true, 1, 0.5);
    settings.http.auth = prefixd::config::AuthConfig {
        mode: prefixd::config::AuthMode::Bearer,
        bearer_token_env: Some("TEST_PREFIXD_FNM_TOKEN".to_string()),
    };
    settings.http.auth.mode = AuthMode::Credentials;

    let mut state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("failed to create app state");

    let cached = Arc::get_mut(&mut state).expect("unshared test state");
    cached.settings.http.auth.mode = AuthMode::Bearer;
    cached.bearer_token = Some("fnm-test-token-456".into());
    let app = create_test_router(state);

    let payload = make_fastnetmon_payload("ban", "203.0.113.10", Some("auth-uuid"));

    // Without auth → 401
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/fastnetmon")
                .header("content-type", "application/json")
                .body(Body::from(payload.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // With auth → 202
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/fastnetmon")
                .header("content-type", "application/json")
                .header("authorization", "Bearer fnm-test-token-456")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

/// VAL-ENGINE-034: OpenAPI spec includes FastNetMon signal endpoint
#[tokio::test]
async fn test_openapi_includes_fastnetmon() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let spec: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let paths = spec["paths"].as_object().unwrap();
    assert!(
        paths.contains_key("/v1/signals/fastnetmon"),
        "OpenAPI spec should include /v1/signals/fastnetmon"
    );

    let schemas = spec["components"]["schemas"].as_object().unwrap();
    assert!(
        schemas.contains_key("FastNetMonPayload"),
        "OpenAPI spec should include FastNetMonPayload schema"
    );
    assert!(
        schemas.contains_key("FastNetMonAttackDetails"),
        "OpenAPI spec should include FastNetMonAttackDetails schema"
    );
}

/// FastNetMon events should be stored with source='fastnetmon'
#[tokio::test]
async fn test_fastnetmon_source_field() {
    let (app, _repo) = setup_app_correlation_with_repo(1, 0.5).await;

    let payload = make_fastnetmon_payload("ban", "203.0.113.10", Some("source-uuid"));
    let (status, _json) = post_fastnetmon(&app, &payload).await;
    assert_eq!(status, StatusCode::ACCEPTED);

    // Verify signal group has 'fastnetmon' source via the API
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/signal-groups")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let groups_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let groups = groups_json["groups"].as_array().unwrap();
    assert!(!groups.is_empty(), "should have at least one signal group");

    // List events and check source
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let events_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let events = events_json["events"].as_array().unwrap();
    assert!(!events.is_empty(), "should have at least one event");

    let event = &events[0];
    assert_eq!(
        event["source"], "fastnetmon",
        "event source should be 'fastnetmon'"
    );
}

/// VAL-ENGINE-034: OpenAPI spec includes alertmanager signal endpoint
#[tokio::test]
async fn test_openapi_includes_alertmanager() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let spec: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let paths = spec["paths"].as_object().unwrap();
    assert!(
        paths.contains_key("/v1/signals/alertmanager"),
        "OpenAPI spec should include /v1/signals/alertmanager"
    );

    let schemas = spec["components"]["schemas"].as_object().unwrap();
    assert!(
        schemas.contains_key("AlertmanagerWebhookPayload"),
        "OpenAPI spec should include AlertmanagerWebhookPayload schema"
    );
    assert!(
        schemas.contains_key("AlertmanagerWebhookResponse"),
        "OpenAPI spec should include AlertmanagerWebhookResponse schema"
    );
    assert!(
        schemas.contains_key("AlertmanagerAlert"),
        "OpenAPI spec should include AlertmanagerAlert schema"
    );
    assert!(
        schemas.contains_key("AlertmanagerAlertResult"),
        "OpenAPI spec should include AlertmanagerAlertResult schema"
    );
}

// ==========================================================================
// Correlation config API tests (VAL-ADAPT-014, VAL-ADAPT-015, VAL-ADAPT-016)
// ==========================================================================

/// VAL-ADAPT-014: GET /v1/config/correlation returns redacted config
#[tokio::test]
async fn test_get_correlation_config() {
    let app = setup_app_correlation(true, 2, 0.7).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/config/correlation")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let config = &json["config"];
    assert_eq!(config["enabled"], true);
    assert_eq!(config["window_seconds"], 300);
    assert_eq!(config["min_sources"], 2);
    // f32 → JSON f64 loses precision; compare approximately
    let ct = config["confidence_threshold"].as_f64().unwrap();
    assert!(
        (ct - 0.7).abs() < 0.001,
        "confidence_threshold ~ 0.7, got {ct}"
    );
    assert_eq!(config["default_weight"], 1.0);
    assert!(config["sources"].is_object(), "sources should be an object");
    assert!(
        config["sources"]["detector_a"].is_object(),
        "detector_a should be present"
    );
    assert_eq!(config["sources"]["detector_a"]["weight"], 1.0);
    assert_eq!(config["sources"]["detector_b"]["weight"], 1.5);
    assert!(json["loaded_at"].is_string(), "loaded_at should be present");
}

/// VAL-ADAPT-014: GET /v1/config/correlation returns default config when correlation is disabled
#[tokio::test]
async fn test_get_correlation_config_default() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/config/correlation")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let config = &json["config"];
    assert_eq!(config["enabled"], false);
    assert_eq!(config["min_sources"], 1);
    assert_eq!(config["confidence_threshold"], 0.5);
}

/// VAL-ADAPT-015: PUT /v1/config/correlation requires admin (403 for bearer/operator)
#[tokio::test]
async fn test_update_correlation_config_operator_forbidden() {
    let dir = tempfile::tempdir().unwrap();
    let app = setup_app_bearer_with_config_dir(dir.path().to_path_buf()).await;

    let body = serde_json::json!({
        "enabled": true,
        "window_seconds": 600,
        "min_sources": 2,
        "confidence_threshold": 0.7,
        "default_weight": 1.0,
        "sources": {}
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/config/correlation")
                .header("Authorization", "Bearer test-secret-token-123")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// VAL-ADAPT-015: PUT /v1/config/correlation succeeds for admin (auth_mode: none)
#[tokio::test]
async fn test_update_correlation_config_success() {
    let dir = tempfile::tempdir().unwrap();
    let app = setup_app_with_config_dir(dir.path().to_path_buf()).await;

    let body = serde_json::json!({
        "enabled": true,
        "window_seconds": 600,
        "min_sources": 3,
        "confidence_threshold": 0.8,
        "default_weight": 0.5,
        "sources": {
            "fastnetmon": {
                "weight": 2.0,
                "type": "detector",
                "confidence_mapping": {
                    "ban": 0.95
                }
            }
        }
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/config/correlation")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let config = &json["config"];
    assert_eq!(config["enabled"], true);
    assert_eq!(config["window_seconds"], 600);
    assert_eq!(config["min_sources"], 3);
    let ct = config["confidence_threshold"].as_f64().unwrap();
    assert!(
        (ct - 0.8).abs() < 0.001,
        "confidence_threshold ~ 0.8, got {ct}"
    );
    assert_eq!(config["default_weight"], 0.5);
    assert_eq!(config["sources"]["fastnetmon"]["weight"], 2.0);

    // Verify file was written
    let correlation_path = dir.path().join("correlation.yaml");
    assert!(
        correlation_path.exists(),
        "correlation.yaml should be written"
    );

    // Verify the file content round-trips correctly
    let saved_config = prefixd::correlation::CorrelationConfig::load(&correlation_path).unwrap();
    assert!(saved_config.enabled);
    assert_eq!(saved_config.window_seconds, 600);
    assert_eq!(saved_config.min_sources, 3);
}

/// PUT /v1/config/correlation with invalid JSON returns 400
#[tokio::test]
async fn test_update_correlation_config_invalid_json() {
    let dir = tempfile::tempdir().unwrap();
    let app = setup_app_with_config_dir(dir.path().to_path_buf()).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/config/correlation")
                .header("content-type", "application/json")
                .body(Body::from("not json"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// PUT /v1/config/correlation with validation errors returns 400
#[tokio::test]
async fn test_update_correlation_config_validation_error() {
    let dir = tempfile::tempdir().unwrap();
    let app = setup_app_with_config_dir(dir.path().to_path_buf()).await;

    let body = serde_json::json!({
        "enabled": true,
        "window_seconds": 0,
        "min_sources": 0,
        "confidence_threshold": 2.0,
        "default_weight": -1.0,
        "sources": {}
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/config/correlation")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let errors = json["errors"].as_array().unwrap();
    assert!(errors.len() >= 3, "should have multiple validation errors");
}

async fn correlation_config_request(
    app: &axum::Router,
    method: &str,
    path: &str,
    body: &str,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, json)
}

#[tokio::test]
async fn test_correlation_non_finite_json_edit_preserves_config() {
    let directory = tempfile::tempdir().unwrap();
    let app = setup_app_with_config_dir(directory.path().to_path_buf()).await;
    let (status, _) = correlation_config_request(
        &app,
        "PUT",
        "/v1/config/correlation",
        r#"{"confidence_threshold":0.75,"default_weight":2.0}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, original) = correlation_config_request(&app, "GET", "/v1/config/correlation", "").await;
    let path = directory.path().join("correlation.yaml");
    let original_bytes = std::fs::read(&path).unwrap();
    for payload in [
        r#"{"confidence_threshold":1e100}"#,
        r#"{"default_weight":1e100}"#,
        r#"{"sources":{"detector":{"weight":1e100}}}"#,
    ] {
        let (status, rejection) =
            correlation_config_request(&app, "PUT", "/v1/config/correlation", payload).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "accepted overflow payload: {payload}"
        );
        assert!(
            rejection["errors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|error| error.as_str().unwrap().contains("finite"))
        );
        assert_eq!(std::fs::read(&path).unwrap(), original_bytes);
        assert!(
            !path.with_extension("yaml.bak").exists(),
            "rejected edits must not reach save"
        );
        let (status, current) =
            correlation_config_request(&app, "GET", "/v1/config/correlation", "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            current, original,
            "rejected edit changed config or loaded_at"
        );
    }
}

#[tokio::test]
async fn test_correlation_non_finite_yaml_reload_preserves_config() {
    let directory = tempfile::tempdir().unwrap();
    let app = setup_app_with_config_dir(directory.path().to_path_buf()).await;
    let (status, _) = correlation_config_request(
        &app,
        "PUT",
        "/v1/config/correlation",
        r#"{"confidence_threshold":0.75,"default_weight":2.0}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, original) = correlation_config_request(&app, "GET", "/v1/config/correlation", "").await;
    let standalone = directory.path().join("correlation.yaml");
    for inline in [false, true] {
        if inline {
            std::fs::remove_file(&standalone).unwrap();
        }
        for value in [".nan", ".inf", "-.inf"] {
            for yaml in [
                format!("confidence_threshold: {value}\n"),
                format!("default_weight: {value}\n"),
                format!("sources:\n  detector:\n    weight: {value}\n"),
            ] {
                let (path, content) = if inline {
                    let mut settings = test_settings();
                    settings.correlation = serde_saphyr::from_str(&yaml).unwrap();
                    (
                        directory.path().join("prefixd.yaml"),
                        serde_saphyr::to_string(&settings).unwrap(),
                    )
                } else {
                    (standalone.clone(), yaml)
                };
                std::fs::write(&path, &content).unwrap();
                let (status, _) =
                    correlation_config_request(&app, "POST", "/v1/config/reload", "").await;
                assert_eq!(
                    status,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "accepted invalid reload: inline={inline}, value={value}"
                );
                assert_eq!(
                    std::fs::read_to_string(&path).unwrap(),
                    content,
                    "reload must not rewrite the supplied file"
                );
                let (status, current) =
                    correlation_config_request(&app, "GET", "/v1/config/correlation", "").await;
                assert_eq!(status, StatusCode::OK);
                assert_eq!(
                    current, original,
                    "invalid reload changed config or loaded_at"
                );
            }
        }
    }
}

/// VAL-ADAPT-016: POST /v1/config/reload refreshes correlation config from YAML
#[tokio::test]
async fn test_reload_picks_up_correlation_config() {
    let dir = tempfile::tempdir().unwrap();

    // Write initial prefixd.yaml with correlation disabled
    let initial_config = prefixd::correlation::CorrelationConfig::default();
    let correlation_path = dir.path().join("correlation.yaml");
    initial_config.save(&correlation_path).unwrap();

    let app = setup_app_with_config_dir(dir.path().to_path_buf()).await;

    // Verify initial config is disabled
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/config/correlation")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["config"]["enabled"], false);

    // Update the correlation.yaml file on disk
    let mut updated = prefixd::correlation::CorrelationConfig::default();
    updated.enabled = true;
    updated.min_sources = 3;
    updated.save(&correlation_path).unwrap();

    // Trigger reload
    let response = app
        .clone()
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
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let reloaded = json["reloaded"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert!(
        reloaded.contains(&"correlation".to_string()),
        "reload should include 'correlation': {:?}",
        reloaded
    );

    // Verify updated config
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/config/correlation")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["config"]["enabled"], true);
    assert_eq!(json["config"]["min_sources"], 3);
}

/// VAL-ADAPT-017: Unknown sources handled gracefully (default weight, not 500)
#[tokio::test]
async fn test_unknown_source_handled_gracefully() {
    let app = setup_app_correlation(true, 1, 0.5).await;

    // Submit event from an unknown source (not in the configured sources)
    let event_json = r#"{
        "timestamp": "2026-01-16T14:00:00Z",
        "source": "completely_unknown_detector",
        "victim_ip": "203.0.113.10",
        "vector": "udp_flood",
        "bps": 100000000,
        "pps": 50000,
        "top_dst_ports": [53],
        "confidence": 0.9
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

    assert_eq!(
        response.status(),
        StatusCode::ACCEPTED,
        "unknown source should be accepted (not 500)"
    );
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "accepted");
}

/// OpenAPI spec includes correlation config endpoints
#[tokio::test]
async fn test_openapi_includes_correlation_config() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let spec: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let paths = spec["paths"].as_object().unwrap();
    assert!(
        paths.contains_key("/v1/config/correlation"),
        "OpenAPI spec should include /v1/config/correlation"
    );

    let schemas = spec["components"]["schemas"].as_object().unwrap();
    assert!(
        schemas.contains_key("CorrelationConfig"),
        "OpenAPI spec should include CorrelationConfig schema"
    );
    assert!(
        schemas.contains_key("SourceConfig"),
        "OpenAPI spec should include SourceConfig schema"
    );
}

// =============================================================================
// Generic webhook adapter integration tests
// =============================================================================

async fn setup_app_with_webhooks(
    adapters: Vec<prefixd::correlation::WebhookAdapter>,
) -> axum::Router {
    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let settings = test_settings_with_correlation(true, 1, 0.5);

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("failed to create app state");

    {
        let mut cfg = state.correlation_config.write().await;
        cfg.webhook_adapters = adapters;
    }

    create_test_router(state)
}

fn basic_webhook_adapter(name: &str) -> prefixd::correlation::WebhookAdapter {
    use prefixd::correlation::{WebhookAdapter, WebhookAuth, WebhookFieldMap};
    WebhookAdapter {
        name: name.to_string(),
        description: "test".into(),
        enabled: true,
        auth: WebhookAuth::None,
        root_path: None,
        fields: WebhookFieldMap {
            victim_ip: "$.ip".into(),
            vector: Some("$.vector".into()),
            timestamp: None,
            bps: Some("$.bps".into()),
            pps: Some("$.pps".into()),
            confidence: Some("$.score".into()),
            source_id: Some("$.id".into()),
            top_dst_ports: None,
            action: None,
        },
        vector_map: Default::default(),
        default_vector: None,
        confidence_scale: None,
        source_id_prefix: None,
        transforms: Default::default(),
    }
}

async fn post_webhook(
    app: &axum::Router,
    name: &str,
    body: &str,
    extra_headers: &[(&str, &str)],
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder()
        .method("POST")
        .uri(format!("/v1/signals/webhook/{name}"))
        .header("content-type", "application/json");
    for (k, v) in extra_headers {
        req = req.header(*k, *v);
    }
    let response = app
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::json!({}));
    (status, json)
}

#[tokio::test]
async fn test_webhook_single_event_happy_path() {
    let app = setup_app_with_webhooks(vec![basic_webhook_adapter("radware")]).await;
    let body = r#"{
        "id": "alert-1",
        "ip": "203.0.113.5",
        "vector": "udp_flood",
        "bps": 100000,
        "pps": 500,
        "score": 0.9
    }"#;
    let (status, json) = post_webhook(&app, "radware", body, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);
    assert_eq!(json["failed"], 0);
    assert_eq!(json["results"][0]["index"], 0);
}

#[tokio::test]
async fn test_detector_adapters_audit_mitigation_creation() {
    let alertmanager = setup_app_correlation(true, 1, 0.5).await;
    let alert = make_alert("firing", "203.0.113.10", "udp_flood", "critical", "fp-1");
    let (_, json) = post_alertmanager(&alertmanager, &make_alertmanager_payload(&[alert])).await;
    let alertmanager_result = json["results"][0].clone();

    let fastnetmon = setup_app_correlation(true, 1, 0.5).await;
    let payload = make_fastnetmon_payload("ban", "203.0.113.10", Some("attack-1"));
    let (_, fastnetmon_result) = post_fastnetmon(&fastnetmon, &payload).await;

    let webhook = setup_app_with_webhooks(vec![basic_webhook_adapter("radware")]).await;
    let body = r#"{"id":"alert-1","ip":"203.0.113.10","vector":"udp_flood","bps":100000,"pps":500,"score":0.9}"#;
    let (_, json) = post_webhook(&webhook, "radware", body, &[]).await;
    let webhook_result = json["results"][0].clone();

    for (app, result, source) in [
        (&alertmanager, alertmanager_result, "alertmanager"),
        (&fastnetmon, fastnetmon_result, "fastnetmon"),
        (&webhook, webhook_result, "radware"),
    ] {
        assert!(result["mitigation_id"].is_string(), "{source}: {result}");
        let response = app
            .clone()
            .oneshot(Request::get("/v1/audit").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let audit: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let entries = audit["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1, "{source}: {entries:?}");
        let entry = &entries[0];
        assert_eq!(entry["action"], "create");
        assert_eq!(entry["actor_type"], "detector");
        assert_eq!(entry["actor_id"], source);
        assert_eq!(entry["target_id"], result["mitigation_id"]);
        assert_eq!(entry["details"]["event_id"], result["event_id"]);
        assert_eq!(entry["details"]["origin_mode"], "dry-run");
    }
}

#[tokio::test]
async fn test_webhook_numeric_mapping_failure_has_no_mutations_and_allows_corrected_retry() {
    use prefixd::correlation::WebhookTransform;

    let repo = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let mut settings = test_settings_with_correlation(true, 1, 0.5);
    settings.mode = prefixd::config::OperationMode::Enforced;
    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo.clone(),
        announcer.clone(),
        ".".into(),
    )
    .unwrap();
    let mut adapter = basic_webhook_adapter("numeric-retry");
    adapter.transforms.insert(
        "bps".into(),
        WebhookTransform::UnitConversion {
            multiplier: f64::MAX,
        },
    );
    state.correlation_config.write().await.webhook_adapters = vec![adapter];
    let app = create_test_router(state);
    let rejected = r#"{
        "id":"numeric-retry", "ip":"203.0.113.10", "vector":"udp_flood",
        "bps":2, "pps":50000, "score":0.9
    }"#;

    let (status, result) = post_webhook(&app, "numeric-retry", rejected, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result["processed"], 0);
    assert_eq!(result["failed"], 1);
    assert_eq!(result["results"][0]["status"], "error");
    assert!(
        result["results"][0]["error"]
            .as_str()
            .unwrap()
            .starts_with("invalid value for field 'bps'")
    );

    let params = prefixd::db::ListParams {
        limit: 10,
        ..Default::default()
    };
    assert!(repo.list_events(&params).await.unwrap().is_empty());
    assert!(repo.list_audit(&params).await.unwrap().is_empty());
    assert!(
        repo.list_signal_groups(&Default::default(), &params)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        repo.list_mitigations(
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
        .unwrap()
        .is_empty()
    );
    assert_eq!(announcer.announced_count().await, 0);

    let corrected = r#"{
        "id":"numeric-retry", "ip":"203.0.113.10", "vector":"udp_flood",
        "bps":0, "pps":50000, "score":0.9
    }"#;
    let (status, result) = post_webhook(&app, "numeric-retry", corrected, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result["processed"], 1);
    assert_eq!(result["failed"], 0);
    let events = repo.list_events(&params).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].bps, Some(0));
    assert_eq!(events[0].pps, Some(50000));
    assert_eq!(announcer.announced_count().await, 1);
}

#[tokio::test]
async fn test_webhook_name_not_configured_returns_404() {
    let app = setup_app_with_webhooks(vec![basic_webhook_adapter("radware")]).await;
    let body = r#"{"ip":"203.0.113.5"}"#;
    let (status, _json) = post_webhook(&app, "unknown", body, &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_webhook_disabled_adapter_returns_404() {
    let mut adapter = basic_webhook_adapter("radware");
    adapter.enabled = false;
    let app = setup_app_with_webhooks(vec![adapter]).await;
    let body = r#"{"ip":"203.0.113.5"}"#;
    let (status, _json) = post_webhook(&app, "radware", body, &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_webhook_invalid_name_returns_404() {
    let app = setup_app_with_webhooks(vec![]).await;
    // Path traversal attempt
    let body = r#"{}"#;
    let (status, _json) = post_webhook(&app, "UPPER", body, &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_webhook_missing_required_field_reports_error_in_result() {
    let app = setup_app_with_webhooks(vec![basic_webhook_adapter("radware")]).await;
    // Missing $.ip
    let body = r#"{"vector":"udp_flood"}"#;
    let (status, json) = post_webhook(&app, "radware", body, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 0);
    assert_eq!(json["failed"], 1);
    assert_eq!(json["results"][0]["status"], "error");
    let err = json["results"][0]["error"].as_str().unwrap();
    assert!(
        err.contains("victim_ip"),
        "error should mention field: {err}"
    );
}

#[tokio::test]
async fn test_webhook_root_path_iterates_batch() {
    let mut adapter = basic_webhook_adapter("batchy");
    adapter.root_path = Some("$.alerts[*]".into());
    let app = setup_app_with_webhooks(vec![adapter]).await;
    let body = r#"{
        "alerts": [
            {"id":"a","ip":"203.0.113.1","vector":"udp_flood"},
            {"id":"b","ip":"203.0.113.2","vector":"syn_flood"},
            {"id":"c","ip":"203.0.113.3","vector":"icmp_flood"}
        ]
    }"#;
    let (status, json) = post_webhook(&app, "batchy", body, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 3);
    assert_eq!(json["failed"], 0);
    assert_eq!(json["results"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn test_webhook_malformed_json_returns_400() {
    let app = setup_app_with_webhooks(vec![basic_webhook_adapter("radware")]).await;
    let body = r#"{not json"#;
    let (status, _json) = post_webhook(&app, "radware", body, &[]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// Only these cases require the handler to read a real process environment secret.
async fn webhook_hmac_child(test_name: &str, env_name: &str, secret: &str) -> Option<String> {
    const CHILD: &str = "PREFIXD_WEBHOOK_HMAC_CHILD";
    const SECRETS: [&str; 3] = [
        "PREFIXD_TEST_HMAC_SECRET_POS",
        "PREFIXD_TEST_HMAC_SECRET_NEG",
        "PREFIXD_TEST_HMAC_SECRET_MISS",
    ];
    let completion = format!("prefixd-hmac-completed:{test_name}");
    if std::env::var(CHILD).ok().as_deref() == Some(test_name) {
        assert!(
            std::env::var(env_name).ok().as_deref() == Some(secret),
            "HMAC child secret must be installed before startup"
        );
        for inherited in SECRETS {
            if inherited != env_name {
                assert!(
                    std::env::var_os(inherited).is_none(),
                    "HMAC child must not inherit another case's secret"
                );
            }
        }
        return Some(completion);
    }

    let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", test_name, "--test-threads=1", "--nocapture"])
        .env(CHILD, test_name)
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    for inherited in SECRETS {
        command.env_remove(inherited);
    }
    command.env(env_name, secret);
    let output = tokio::time::timeout(std::time::Duration::from_secs(15), command.output())
        .await
        .expect("HMAC child exceeded fifteen seconds")
        .expect("HMAC child output");
    let stdout = String::from_utf8_lossy(&output.stdout).replace(secret, "[redacted]");
    let stderr = String::from_utf8_lossy(&output.stderr).replace(secret, "[redacted]");
    assert!(
        output.status.success(),
        "HMAC child {test_name} failed ({:?})\n{stdout}\n{stderr}",
        output.status.code()
    );
    assert!(
        stdout.lines().any(|line| line == completion),
        "HMAC child {test_name} did not complete its assertions\n{stdout}\n{stderr}"
    );
    None
}

#[tokio::test]
async fn test_webhook_hmac_accepts_correct_signature() {
    use hmac::Mac;
    use prefixd::correlation::WebhookAuth;

    let env_name = "PREFIXD_TEST_HMAC_SECRET_POS";
    let secret = "super-secret";
    let Some(completed) = webhook_hmac_child(
        "test_webhook_hmac_accepts_correct_signature",
        env_name,
        secret,
    )
    .await
    else {
        return;
    };

    let mut adapter = basic_webhook_adapter("signed");
    adapter.auth = WebhookAuth::Hmac {
        secret_env: env_name.into(),
        header: "X-Signature-SHA256".into(),
        algorithm: "sha256".into(),
    };
    let app = setup_app_with_webhooks(vec![adapter]).await;

    let body = r#"{"ip":"203.0.113.5","vector":"udp_flood"}"#;
    let mut mac =
        <hmac::Hmac<sha2::Sha256> as hmac::KeyInit>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());

    let (status, json) = post_webhook(&app, "signed", body, &[("X-Signature-SHA256", &sig)]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);

    println!("\n{completed}");
}

#[tokio::test]
async fn test_webhook_hmac_rejects_wrong_signature() {
    use prefixd::correlation::WebhookAuth;

    let env_name = "PREFIXD_TEST_HMAC_SECRET_NEG";
    let secret = "super-secret";
    let Some(completed) = webhook_hmac_child(
        "test_webhook_hmac_rejects_wrong_signature",
        env_name,
        secret,
    )
    .await
    else {
        return;
    };

    let mut adapter = basic_webhook_adapter("signed2");
    adapter.auth = WebhookAuth::Hmac {
        secret_env: env_name.into(),
        header: "X-Signature-SHA256".into(),
        algorithm: "sha256".into(),
    };
    let app = setup_app_with_webhooks(vec![adapter]).await;

    let body = r#"{"ip":"203.0.113.5","vector":"udp_flood"}"#;
    let wrong_sig = "0".repeat(64);

    let (status, _json) =
        post_webhook(&app, "signed2", body, &[("X-Signature-SHA256", &wrong_sig)]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    println!("\n{completed}");
}

#[tokio::test]
async fn test_webhook_hmac_missing_header_returns_401() {
    use prefixd::correlation::WebhookAuth;

    let env_name = "PREFIXD_TEST_HMAC_SECRET_MISS";
    let secret = "super-secret";
    let Some(completed) = webhook_hmac_child(
        "test_webhook_hmac_missing_header_returns_401",
        env_name,
        secret,
    )
    .await
    else {
        return;
    };

    let mut adapter = basic_webhook_adapter("signed3");
    adapter.auth = WebhookAuth::Hmac {
        secret_env: env_name.into(),
        header: "X-Signature-SHA256".into(),
        algorithm: "sha256".into(),
    };
    let app = setup_app_with_webhooks(vec![adapter]).await;

    let body = r#"{"ip":"203.0.113.5"}"#;
    let (status, _json) = post_webhook(&app, "signed3", body, &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    println!("\n{completed}");
}

#[tokio::test]
async fn test_webhook_vector_map_and_scaling() {
    let mut adapter = basic_webhook_adapter("scaled");
    adapter.vector_map.insert("UDP".into(), "udp_flood".into());
    adapter.confidence_scale = Some(100.0);
    let app = setup_app_with_webhooks(vec![adapter]).await;

    let body = r#"{
        "id":"x",
        "ip":"203.0.113.5",
        "vector":"UDP",
        "score":77
    }"#;
    let (status, json) = post_webhook(&app, "scaled", body, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);
}

#[tokio::test]
async fn test_webhook_unit_conversion_transform_end_to_end() {
    use prefixd::correlation::WebhookTransform;
    let mut adapter = basic_webhook_adapter("megabit");
    adapter.transforms.insert(
        "bps".into(),
        WebhookTransform::UnitConversion {
            multiplier: 1_000_000.0,
        },
    );
    let app = setup_app_with_webhooks(vec![adapter]).await;

    // Detector reports bps=250 (intended Mbps); transform should yield 250M.
    let body = r#"{
        "id":"u1",
        "ip":"203.0.113.5",
        "vector":"udp_flood",
        "bps":250,
        "pps":1
    }"#;
    let (status, json) = post_webhook(&app, "megabit", body, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);
    // Verify the transform actually reshaped the bps value by inspecting the
    // ingested event surfaced via the events API.
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/v1/events")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let events: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = events["events"].as_array().expect("events array");
    let found = arr
        .iter()
        .find(|e| e["victim_ip"] == "203.0.113.5")
        .expect("ingested event");
    assert_eq!(found["bps"], 250_000_000);
}

#[tokio::test]
async fn test_webhook_regex_extract_transform_end_to_end() {
    use prefixd::correlation::WebhookTransform;
    let mut adapter = basic_webhook_adapter("regex");
    adapter.fields.vector = Some("$.description".into());
    adapter.default_vector = Some("unknown".into());
    adapter.transforms.insert(
        "vector".into(),
        WebhookTransform::RegexExtract {
            pattern: r"(\w+)_flood".into(),
            group: 0,
        },
    );
    let app = setup_app_with_webhooks(vec![adapter]).await;

    let body = r#"{
        "id":"r1",
        "ip":"203.0.113.6",
        "description":"Customer 12 hit by udp_flood at 50Gbps"
    }"#;
    let (status, json) = post_webhook(&app, "regex", body, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);

    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/v1/events")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let events: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = events["events"].as_array().expect("events array");
    let found = arr
        .iter()
        .find(|e| e["victim_ip"] == "203.0.113.6")
        .expect("ingested event");
    assert_eq!(found["vector"], "udp_flood");
}

#[tokio::test]
async fn test_webhook_computed_transform_end_to_end() {
    use prefixd::correlation::WebhookTransform;
    let mut adapter = basic_webhook_adapter("computed");
    adapter.fields.bps = None;
    adapter.transforms.insert(
        "bps".into(),
        WebhookTransform::Computed {
            paths: vec!["$.packets".into(), "$.avg_size".into()],
            scale: 8.0,
        },
    );
    let app = setup_app_with_webhooks(vec![adapter]).await;

    let body = r#"{
        "id":"c1",
        "ip":"203.0.113.7",
        "vector":"udp_flood",
        "packets": 500000,
        "avg_size": 1024,
        "pps": 100
    }"#;
    let (status, json) = post_webhook(&app, "computed", body, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["processed"], 1);

    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/v1/events")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let events: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = events["events"].as_array().expect("events array");
    let found = arr
        .iter()
        .find(|e| e["victim_ip"] == "203.0.113.7")
        .expect("ingested event");
    // 500_000 * 1024 * 8 = 4_096_000_000
    assert_eq!(found["bps"], 4_096_000_000_i64);
}

// ── Corroborating signals (ADR 021) ─────────────────────────────────

async fn setup_app_with_corroborating_source(
    source_name: &str,
    dims: Vec<prefixd::correlation::MatchDimension>,
    weight: f32,
) -> axum::Router {
    use prefixd::correlation::{SourceConfig, SourceMode};

    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let mut settings = test_settings_with_correlation(true, 2, 0.5);
    settings.correlation.sources.insert(
        source_name.to_string(),
        SourceConfig {
            weight,
            r#type: "telemetry".to_string(),
            confidence_mapping: std::collections::HashMap::new(),
            mode: SourceMode::Corroborating,
            match_dimensions: dims,
        },
    );

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("failed to create app state");

    create_test_router(state)
}

async fn post_corroborator(
    app: &axum::Router,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/corroborator")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::json!({}));
    (status, json)
}

#[tokio::test]
async fn test_corroborator_primary_source_rejected() {
    // Default source config (no mode) is primary; posting to corroborator
    // endpoint must be rejected.
    let app = setup_app_with_corroborating_source(
        "different-source",
        vec![prefixd::correlation::MatchDimension::Pop],
        0.5,
    )
    .await;
    let body = serde_json::json!({
        "source": "fastnetmon",  // configured as primary in base settings
        "pop": "test-pop"
    });
    let (status, _) = post_corroborator(&app, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_corroborator_requires_declared_dimension() {
    // Source declares match_dimensions=[pop] but signal doesn't carry pop → 400.
    let app = setup_app_with_corroborating_source(
        "router-cpu",
        vec![prefixd::correlation::MatchDimension::Pop],
        0.5,
    )
    .await;
    let body = serde_json::json!({
        "source": "router-cpu",
        "customer_id": "cust_1"  // wrong dimension
    });
    let (status, _) = post_corroborator(&app, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_corroborator_caches_when_no_matching_group() {
    // No primary events yet → signal is cached.
    let app = setup_app_with_corroborating_source(
        "router-cpu",
        vec![prefixd::correlation::MatchDimension::Pop],
        0.5,
    )
    .await;
    let body = serde_json::json!({
        "source": "router-cpu",
        "pop": "test-pop",
        "confidence": 0.7
    });
    let (status, json) = post_corroborator(&app, body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "cached");
    assert!(json["attached_group_ids"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_corroborator_attaches_to_matching_primary_group() {
    // 1) Primary event creates a signal group. 2) Corroborator with matching
    // dimension attaches and drives source_count to 2.
    use prefixd::correlation::{MatchDimension, SourceConfig, SourceMode};

    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let mut settings = test_settings_with_correlation(true, 2, 0.5);
    settings.correlation.sources.insert(
        "router-cpu".to_string(),
        SourceConfig {
            weight: 0.8,
            r#type: "telemetry".to_string(),
            confidence_mapping: std::collections::HashMap::new(),
            mode: SourceMode::Corroborating,
            match_dimensions: vec![MatchDimension::Pop],
        },
    );

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo.clone(),
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("state");
    let app = create_test_router(state);

    // Step 1: post a primary event — source_count=1, corroboration_met=false (min_sources=2)
    let event_body = serde_json::json!({
        "source": "fastnetmon",
        "vector": "udp_flood",
        "victim_ip": "203.0.113.10",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "confidence": 0.9,
        "action": "ban"
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    // Step 2: corroborator posts with matching pop
    let sig_body = serde_json::json!({
        "source": "router-cpu",
        "pop": "test1",
        "vector": "udp_flood",
        "confidence": 0.6
    });
    let resp2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/corroborator")
                .header("content-type", "application/json")
                .body(Body::from(sig_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp2.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["status"], "attached");
    assert_eq!(json["attached_group_ids"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn test_primary_event_rejects_corroborating_source_before_write() {
    use prefixd::correlation::{MatchDimension, SourceConfig, SourceMode};

    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let mut settings = test_settings_with_correlation(true, 1, 0.5);
    settings.correlation.sources.insert(
        "router-cpu".to_string(),
        SourceConfig {
            weight: 0.8,
            r#type: "telemetry".to_string(),
            confidence_mapping: std::collections::HashMap::new(),
            mode: SourceMode::Corroborating,
            match_dimensions: vec![MatchDimension::Pop],
        },
    );

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo.clone(),
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("state");
    let app = create_test_router(state);

    let event_body = serde_json::json!({
        "source": "router-cpu",
        "vector": "udp_flood",
        "victim_ip": "203.0.113.10",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "confidence": 0.9,
        "action": "ban"
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let stored = repo
        .list_events(&prefixd::db::ListParams::default())
        .await
        .unwrap();
    assert!(stored.is_empty(), "rejected event should not be persisted");
}

/// Router whose `router-cpu`, `alertmanager` and `fastnetmon` sources are
/// corroborating-only, alongside the primary `detector_a`.
fn setup_corroborating_ban_paths() -> (axum::Router, Arc<dyn RepositoryTrait>, Arc<MockAnnouncer>) {
    use prefixd::correlation::{MatchDimension, SourceConfig, SourceMode};

    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let mut settings = test_settings_with_correlation(true, 1, 0.5);
    // Enforced so announcement counts prove what reached the speaker.
    settings.mode = prefixd::config::OperationMode::Enforced;
    for source in ["router-cpu", "alertmanager", "fastnetmon"] {
        settings.correlation.sources.insert(
            source.to_string(),
            SourceConfig {
                weight: 0.8,
                r#type: "telemetry".to_string(),
                confidence_mapping: std::collections::HashMap::new(),
                mode: SourceMode::Corroborating,
                match_dimensions: vec![MatchDimension::Pop],
            },
        );
    }
    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo.clone(),
        announcer.clone(),
        std::path::PathBuf::from("."),
    )
    .expect("state");
    (create_test_router(state), repo, announcer)
}

fn corroborating_rejection(source: &str) -> String {
    format!(
        "invalid request: source '{source}' is configured as mode=corroborating and cannot post to /v1/events. Use POST /v1/signals/corroborator instead."
    )
}

async fn mitigation_count(repo: &Arc<dyn RepositoryTrait>) -> usize {
    repo.list_mitigations(
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
    .unwrap()
    .len()
}

#[tokio::test]
async fn test_batch_rejects_corroborating_ban_per_item() {
    let (app, repo, announcer) = setup_corroborating_ban_paths();
    let now = chrono::Utc::now().to_rfc3339();
    let body = serde_json::json!({
        "events": [
            {"timestamp": now, "source": "router-cpu", "victim_ip": "203.0.113.20",
             "vector": "udp_flood", "confidence": 0.9, "action": "ban", "event_id": "cpu-1"},
            {"timestamp": now, "source": "detector_a", "victim_ip": "203.0.113.21",
             "vector": "udp_flood", "confidence": 0.9, "action": "ban"},
            {"timestamp": now, "source": "router-cpu", "victim_ip": "203.0.113.20",
             "vector": "udp_flood", "action": "unban", "event_id": "cpu-1"}
        ]
    });
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events/batch")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::MULTI_STATUS);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["accepted"], 2, "{json}");
    assert_eq!(json["rejected"], 1, "{json}");
    let results = json["results"].as_array().unwrap();
    assert_eq!(results[0]["status"], "rejected");
    assert_eq!(results[0]["error"], corroborating_rejection("router-cpu"));
    assert!(results[1]["mitigation_id"].is_string(), "{json}");
    // Unban stays on the withdrawal path; nothing to withdraw here.
    assert_eq!(results[2]["status"], "not_found");

    let events = repo
        .list_events(&prefixd::db::ListParams::default())
        .await
        .unwrap();
    assert!(
        events.iter().all(|e| e.source != "router-cpu"),
        "corroborating ban must not be persisted"
    );
    assert_eq!(mitigation_count(&repo).await, 1);
    assert_eq!(announcer.announced_count().await, 1);
}

#[tokio::test]
async fn test_alertmanager_rejects_corroborating_source_ban() {
    let (app, repo, announcer) = setup_corroborating_ban_paths();
    let firing = make_alert("firing", "203.0.113.30", "udp_flood", "critical", "am-1");
    let (status, json) = post_alertmanager(&app, &make_alertmanager_payload(&[firing])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["failed"], 1, "{json}");
    assert_eq!(json["results"][0]["status"], "error");
    assert_eq!(
        json["results"][0]["error"],
        corroborating_rejection("alertmanager")
    );

    // Resolution still routes to withdrawal rather than the ban guard.
    let resolved = make_alert("resolved", "203.0.113.30", "udp_flood", "critical", "am-1");
    let (status, json) = post_alertmanager(&app, &make_alertmanager_payload(&[resolved])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["failed"], 0, "{json}");
    assert_eq!(json["results"][0]["status"], "withdrawn");

    let events = repo
        .list_events(&prefixd::db::ListParams::default())
        .await
        .unwrap();
    assert!(events.is_empty(), "corroborating ban must not be persisted");
    assert_eq!(mitigation_count(&repo).await, 0);
    assert_eq!(announcer.announced_count().await, 0);
}

#[tokio::test]
async fn test_fastnetmon_rejects_corroborating_source_ban() {
    let (app, repo, announcer) = setup_corroborating_ban_paths();
    let payload = make_fastnetmon_payload("ban", "203.0.113.40", Some("fnm-1"));
    let (status, json) = post_fastnetmon(&app, &payload).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], corroborating_rejection("fastnetmon"));
    assert_eq!(mitigation_count(&repo).await, 0);
    assert_eq!(announcer.announced_count().await, 0);
}

#[tokio::test]
async fn test_corroborator_does_not_match_via_undeclared_dimension() {
    use prefixd::correlation::{MatchDimension, SourceConfig, SourceMode};

    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let mut settings = test_settings_with_correlation(true, 2, 0.5);
    settings.correlation.sources.insert(
        "router-cpu".to_string(),
        SourceConfig {
            weight: 0.8,
            r#type: "telemetry".to_string(),
            confidence_mapping: std::collections::HashMap::new(),
            mode: SourceMode::Corroborating,
            match_dimensions: vec![MatchDimension::Pop],
        },
    );

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("state");
    let app = create_test_router(state);

    let event_body = serde_json::json!({
        "source": "fastnetmon",
        "vector": "udp_flood",
        "victim_ip": "203.0.113.10",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "confidence": 0.9,
        "action": "ban"
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    let sig_body = serde_json::json!({
        "source": "router-cpu",
        "pop": "wrong-pop",
        "customer_id": "cust_test",
        "vector": "udp_flood",
        "confidence": 0.6
    });
    let (status, json) = post_corroborator(&app, sig_body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "cached");
    assert!(json["attached_group_ids"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_corroborator_attaches_on_interface_dimension() {
    use prefixd::correlation::{MatchDimension, SourceConfig, SourceMode};

    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let mut settings = test_settings_with_correlation(true, 2, 0.5);
    settings.correlation.sources.insert(
        "router-iface".to_string(),
        SourceConfig {
            weight: 0.8,
            r#type: "telemetry".to_string(),
            confidence_mapping: std::collections::HashMap::new(),
            mode: SourceMode::Corroborating,
            match_dimensions: vec![MatchDimension::Interface],
        },
    );
    let inventory = Inventory::new(vec![Customer {
        customer_id: "cust_test".to_string(),
        name: "Test Customer".to_string(),
        prefixes: vec!["203.0.113.0/24".to_string()],
        policy_profile: prefixd::config::PolicyProfile::Normal,
        services: vec![Service {
            service_id: "svc_dns".to_string(),
            name: "DNS".to_string(),
            assets: vec![Asset {
                ip: "203.0.113.10".to_string(),
                role: Some("dns".to_string()),
                interface: Some("xe-0/0/0".to_string()),
            }],
            allowed_ports: AllowedPorts {
                udp: vec![53],
                tcp: vec![53],
            },
        }],
    }]);

    let state = AppState::new(
        settings,
        inventory,
        test_playbooks(),
        repo,
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("state");
    let app = create_test_router(state);

    let event_body = serde_json::json!({
        "source": "fastnetmon",
        "vector": "udp_flood",
        "victim_ip": "203.0.113.10",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "confidence": 0.9,
        "action": "ban"
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    let sig_body = serde_json::json!({
        "source": "router-iface",
        "interface": "xe-0/0/0",
        "vector": "udp_flood",
        "confidence": 0.6
    });
    let (status, json) = post_corroborator(&app, sig_body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "attached");
    assert_eq!(json["attached_group_ids"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn test_corroborator_alone_never_triggers_mitigation() {
    // Ingest two corroborators but zero primary events. Even if min_sources=1,
    // check_corroboration_with_primary must prevent a mitigation from firing.
    // Here we just verify that no signal group is created by corroborator-only.
    let app = setup_app_with_corroborating_source(
        "router-cpu",
        vec![prefixd::correlation::MatchDimension::Pop],
        1.0,
    )
    .await;
    for _ in 0..2 {
        let body = serde_json::json!({
            "source": "router-cpu",
            "pop": "test-pop"
        });
        let (status, json) = post_corroborator(&app, body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "cached");
    }
    // Listing signal groups should show none — corroborators alone don't
    // create groups.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/signal-groups?limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["groups"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_corroborator_rejected_when_correlation_disabled() {
    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let settings = test_settings_with_correlation(false, 1, 0.5);
    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("state");
    let app = create_test_router(state);

    let body = serde_json::json!({"source": "router-cpu", "pop": "x"});
    let (status, _) = post_corroborator(&app, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_expired_sweep_splits_attached_vs_unattached() {
    use chrono::{Duration, Utc};
    use prefixd::correlation::CorroboratingSignal;
    use uuid::Uuid;

    let repo = MockRepository::new();
    let now = Utc::now();

    // Unattached, expired — should count toward unattached_expired.
    repo.insert_corroborating_signal(&CorroboratingSignal {
        signal_id: Uuid::new_v4(),
        source: "router-cpu".to_string(),
        vector: Some("udp_flood".to_string()),
        customer_id: None,
        pop: Some("iad1".to_string()),
        service_id: None,
        interface: None,
        confidence: Some(0.5),
        weight: 0.5,
        ingested_at: now - Duration::seconds(600),
        expires_at: now - Duration::seconds(60),
        raw_details: None,
        attached_group_ids: vec![],
    })
    .await
    .unwrap();

    // Attached, expired — should count toward attached_expired, NOT the
    // cache-miss metric.
    repo.insert_corroborating_signal(&CorroboratingSignal {
        signal_id: Uuid::new_v4(),
        source: "router-cpu".to_string(),
        vector: Some("udp_flood".to_string()),
        customer_id: None,
        pop: Some("iad1".to_string()),
        service_id: None,
        interface: None,
        confidence: Some(0.5),
        weight: 0.5,
        ingested_at: now - Duration::seconds(600),
        expires_at: now - Duration::seconds(60),
        raw_details: None,
        attached_group_ids: vec![Uuid::new_v4()],
    })
    .await
    .unwrap();

    // Unattached, still fresh — should survive the sweep.
    repo.insert_corroborating_signal(&CorroboratingSignal {
        signal_id: Uuid::new_v4(),
        source: "router-cpu".to_string(),
        vector: Some("udp_flood".to_string()),
        customer_id: None,
        pop: Some("iad1".to_string()),
        service_id: None,
        interface: None,
        confidence: Some(0.5),
        weight: 0.5,
        ingested_at: now,
        expires_at: now + Duration::seconds(300),
        raw_details: None,
        attached_group_ids: vec![],
    })
    .await
    .unwrap();

    let stats = repo
        .delete_expired_corroborating_signals(now)
        .await
        .unwrap();
    assert_eq!(stats.unattached_total(), 1);
    assert_eq!(stats.unattached_expired.get("router-cpu"), Some(&1));
    assert_eq!(stats.attached_expired, 1);
    assert_eq!(repo.count_cached_corroborators(now).await.unwrap(), 1);
}

#[tokio::test]
async fn test_expired_sweep_attributes_per_source() {
    use chrono::{Duration, Utc};
    use prefixd::correlation::CorroboratingSignal;
    use uuid::Uuid;

    let repo = MockRepository::new();
    let now = Utc::now();

    // 2 expired unattached from router-cpu, 1 from pop-utilization
    for src in ["router-cpu", "router-cpu", "pop-utilization"] {
        repo.insert_corroborating_signal(&CorroboratingSignal {
            signal_id: Uuid::new_v4(),
            source: src.to_string(),
            vector: None,
            customer_id: None,
            pop: Some("iad1".to_string()),
            service_id: None,
            interface: None,
            confidence: Some(0.5),
            weight: 0.5,
            ingested_at: now - Duration::seconds(600),
            expires_at: now - Duration::seconds(60),
            raw_details: None,
            attached_group_ids: vec![],
        })
        .await
        .unwrap();
    }

    let stats = repo
        .delete_expired_corroborating_signals(now)
        .await
        .unwrap();
    assert_eq!(stats.unattached_expired.len(), 2);
    assert_eq!(stats.unattached_expired.get("router-cpu"), Some(&2));
    assert_eq!(stats.unattached_expired.get("pop-utilization"), Some(&1));
    assert_eq!(stats.attached_expired, 0);
}

#[tokio::test]
async fn test_count_cached_corroborators_by_source() {
    use chrono::{Duration, Utc};
    use prefixd::correlation::CorroboratingSignal;
    use uuid::Uuid;

    let repo = MockRepository::new();
    let now = Utc::now();

    // 3 unattached unexpired from a, 1 unattached unexpired from b,
    // 1 attached unexpired from a (excluded), 1 expired unattached from a
    // (excluded).
    let cases = [
        ("a", false, false, 0i64),    // unexpired, unattached
        ("a", false, false, 0),       // unexpired, unattached
        ("a", false, false, 0),       // unexpired, unattached
        ("b", false, false, 0),       // unexpired, unattached
        ("a", true, false, 0),        // attached -> excluded
        ("a", false, true, -3600i64), // expired -> excluded (insert with past expires_at)
    ];
    for (src, attached, expired, ingest_offset) in cases {
        repo.insert_corroborating_signal(&CorroboratingSignal {
            signal_id: Uuid::new_v4(),
            source: src.to_string(),
            vector: None,
            customer_id: None,
            pop: Some("iad1".to_string()),
            service_id: None,
            interface: None,
            confidence: Some(0.5),
            weight: 0.5,
            ingested_at: now + Duration::seconds(ingest_offset),
            expires_at: if expired {
                now - Duration::seconds(60)
            } else {
                now + Duration::seconds(300)
            },
            raw_details: None,
            attached_group_ids: if attached {
                vec![Uuid::new_v4()]
            } else {
                vec![]
            },
        })
        .await
        .unwrap();
    }

    let counts: std::collections::HashMap<String, u64> = repo
        .count_cached_corroborators_by_source(now)
        .await
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(counts.get("a"), Some(&3));
    assert_eq!(counts.get("b"), Some(&1));
}

#[tokio::test]
async fn test_corroborator_source_activity_merges_cache_rows() {
    use chrono::{Duration, Utc};
    use prefixd::correlation::CorroboratingSignal;
    use uuid::Uuid;

    let repo = MockRepository::new();
    let now = Utc::now();

    for (src, delta) in [
        ("router-cpu", 30),
        ("router-cpu", 60),
        ("pop-utilization", 15),
    ] {
        repo.insert_corroborating_signal(&CorroboratingSignal {
            signal_id: Uuid::new_v4(),
            source: src.to_string(),
            vector: None,
            customer_id: None,
            pop: Some("iad1".to_string()),
            service_id: None,
            interface: None,
            confidence: Some(0.5),
            weight: 0.5,
            ingested_at: now - Duration::seconds(delta),
            expires_at: now + Duration::seconds(300),
            raw_details: None,
            attached_group_ids: vec![],
        })
        .await
        .unwrap();
    }

    let activity = repo
        .corroborator_source_activity(now - Duration::minutes(10))
        .await
        .unwrap();
    let mut by_source: std::collections::HashMap<_, _> = activity
        .into_iter()
        .map(|r| (r.source.clone(), r))
        .collect();
    assert_eq!(by_source.len(), 2);
    let cpu = by_source.remove("router-cpu").unwrap();
    assert_eq!(cpu.count, 2);
    assert!(cpu.last_seen.is_some());
    assert_eq!(by_source.remove("pop-utilization").unwrap().count, 1);
}

#[tokio::test]
async fn test_late_corroborator_finalizes_with_playbook_override() {
    // PR B: a late corroborator can flip corroboration_met=true on its
    // own path, using the override resolved from the group's stored
    // playbook_name. We set up a group whose primary event lands below
    // the global threshold but above the playbook override threshold,
    // and confirm a corroborator promotes the flag.
    use prefixd::correlation::{
        MatchDimension, PlaybookCorrelationOverride, SourceConfig, SourceMode,
    };
    use prefixd::domain::AttackVector;

    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());

    // Global config: min_sources=3, threshold=0.9 — primary alone is far
    // from meeting it. The playbook override drops both to 2 / 0.5, so a
    // single corroborator (count → 2) should finalize.
    let mut settings = test_settings_with_correlation(true, 3, 0.9);
    settings.correlation.sources.insert(
        "router-cpu".to_string(),
        SourceConfig {
            weight: 0.6,
            r#type: "telemetry".to_string(),
            confidence_mapping: std::collections::HashMap::new(),
            mode: SourceMode::Corroborating,
            match_dimensions: vec![MatchDimension::Pop],
        },
    );

    let playbooks = Playbooks {
        playbooks: vec![Playbook {
            name: "udp_flood_test".to_string(),
            match_criteria: PlaybookMatch {
                vector: AttackVector::UdpFlood,
                require_top_ports: false,
            },
            correlation: Some(PlaybookCorrelationOverride {
                min_sources: Some(2),
                confidence_threshold: Some(0.5),
                ..Default::default()
            }),
            steps: vec![PlaybookStep {
                action: PlaybookAction::Police,
                rate_bps: Some(5_000_000),
                ttl_seconds: 120,
                require_confidence_at_least: None,
                require_persistence_seconds: None,
            }],
        }],
    };

    let state = AppState::new(
        settings,
        test_inventory(),
        playbooks,
        repo.clone(),
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("state");
    let app = create_test_router(state);

    // Step 1: primary event — group exists, playbook_name is set,
    // corroboration_met=false (single source against override min=2).
    let event_body = serde_json::json!({
        "source": "fastnetmon",
        "vector": "udp_flood",
        "victim_ip": "203.0.113.10",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "confidence": 0.7,
        "action": "ban"
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from(event_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    let groups_before = repo
        .list_signal_groups(
            &prefixd::correlation::engine::SignalGroupFilter::default(),
            &prefixd::db::ListParams {
                limit: 10,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(groups_before.len(), 1);
    let group = &groups_before[0];
    assert_eq!(group.playbook_name.as_deref(), Some("udp_flood_test"));
    assert!(
        !group.corroboration_met,
        "single primary event should not yet meet override threshold"
    );

    // Step 2: corroborator with matching pop → group now has 2 distinct
    // sources, derived_confidence above 0.5, override allows promotion.
    let sig_body = serde_json::json!({
        "source": "router-cpu",
        "pop": "test1",
        "vector": "udp_flood",
        "confidence": 0.6
    });
    let resp2 = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signals/corroborator")
                .header("content-type", "application/json")
                .body(Body::from(sig_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);

    let groups_after = repo
        .list_signal_groups(
            &prefixd::correlation::engine::SignalGroupFilter::default(),
            &prefixd::db::ListParams {
                limit: 10,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let group_after = &groups_after[0];
    assert!(
        group_after.corroboration_met,
        "late corroborator should finalize via playbook override"
    );
    assert_eq!(group_after.source_count, 2);
}

#[tokio::test]
async fn test_late_corroborator_skips_when_playbook_name_is_stale() {
    // If a group's stored playbook_name no longer resolves (admin removed
    // it from the live config), the corroborator path falls back to the
    // conservative v0.16.0 behavior: aggregates update on each ingest
    // but corroboration_met is *not* flipped from false -> true. We
    // exercise this end-to-end by:
    //   1) seeding an open group whose stored playbook name doesn't
    //      exist in the live playbook list,
    //   2) posting a corroborator that *would* satisfy the override if
    //      the playbook resolved, and
    //   3) asserting the flag stayed false even though source_count and
    //      derived_confidence advanced.
    use chrono::{Duration, Utc};
    use prefixd::correlation::engine::{PrimaryDimensions, SignalGroup, SignalGroupStatus};
    use prefixd::correlation::{MatchDimension, SourceConfig, SourceMode};
    use uuid::Uuid;

    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());

    // Global config that would never trigger on its own (min=3, 0.9).
    // No playbook named `no_such_playbook` is configured, so the stored
    // value won't resolve; conservative fallback should fire.
    //
    // We register two corroborating sources on the same dimension so a
    // pair of POSTs gets us source_count=2 — enough to *would-be*
    // satisfy a 2/0.5 override if the playbook resolved.
    let mut settings = test_settings_with_correlation(true, 3, 0.9);
    for src in ["router-cpu", "pop-utilization"] {
        settings.correlation.sources.insert(
            src.to_string(),
            SourceConfig {
                weight: 0.6,
                r#type: "telemetry".to_string(),
                confidence_mapping: std::collections::HashMap::new(),
                mode: SourceMode::Corroborating,
                match_dimensions: vec![MatchDimension::Pop],
            },
        );
    }

    // Seed a group as if a primary event already created it pointing at
    // a playbook that has since been removed from config.
    let now = Utc::now();
    let group_id = Uuid::new_v4();
    repo.insert_signal_group(&SignalGroup {
        group_id,
        victim_ip: "203.0.113.10".to_string(),
        vector: "udp_flood".to_string(),
        created_at: now,
        window_expires_at: now + Duration::seconds(300),
        derived_confidence: 0.7,
        source_count: 1,
        status: SignalGroupStatus::Open,
        corroboration_met: false,
        primary_dimensions: {
            let mut d = PrimaryDimensions::default();
            d.add_pop("test1".to_string());
            d
        },
        playbook_name: Some("no_such_playbook".to_string()),
    })
    .await
    .unwrap();
    // Make has_primary=true so the corroborator path is even allowed
    // to consider the group.
    repo.add_event_to_group(group_id, Uuid::new_v4(), 1.0)
        .await
        .unwrap();

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(), // does NOT contain "no_such_playbook"
        repo.clone(),
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("state");
    let app = create_test_router(state);

    // POST two corroborators from distinct sources matching on pop.
    // Without the stale-playbook guard, recompute_group_aggregates
    // would resolve the override and flip corroboration_met to true
    // (source_count reaches 2, derived_confidence above 0.5 override).
    // With the guard, both ingests advance aggregates but the flag
    // stays false.
    for src in ["router-cpu", "pop-utilization"] {
        let body = serde_json::json!({
            "source": src,
            "pop": "test1",
            "vector": "udp_flood",
            "confidence": 0.9
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/signals/corroborator")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    let group = repo.get_signal_group(group_id).await.unwrap().unwrap();
    assert_eq!(
        group.source_count, 2,
        "aggregates should still update on the corroborator path"
    );
    assert!(
        !group.corroboration_met,
        "stale playbook_name must keep the conservative no-flip behavior"
    );
}

// ── ADR 022: confidence decay over time ─────────────────────────────────

#[tokio::test]
async fn test_decay_refresh_lowers_derived_confidence() {
    // With two events of different ages and confidences, exponential decay
    // shifts the weighted average toward the fresher event. We seed:
    //   - Aged event: confidence=0.9, weight=1.0, age=~3 half-lives (180s)
    //   - Fresh event: confidence=0.1, weight=1.0, age=~0
    // Without decay: weighted avg = (0.9 + 0.1) / 2 = 0.5
    // With decay (HL=60): aged effective weight = 1.0 * 0.5^3 = 0.125
    //   ⇒ (0.9*0.125 + 0.1*1.0) / (0.125 + 1.0) = 0.2125 / 1.125 ≈ 0.189
    use chrono::{Duration, Utc};
    use prefixd::bgp::FlowSpecAnnouncer;
    use prefixd::correlation::engine::{PrimaryDimensions, SignalGroup, SignalGroupStatus};
    use prefixd::scheduler::ReconciliationLoop;
    use uuid::Uuid;

    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer: Arc<dyn FlowSpecAnnouncer> = Arc::new(MockAnnouncer::new());

    let mut settings = test_settings_with_correlation(true, 1, 0.0);
    settings.correlation.window_seconds = 3600;
    settings.correlation.confidence_decay_half_life_seconds = 60;

    let now = Utc::now();
    let aged_ingested_at = now - Duration::seconds(180); // 3 half-lives

    // Aged event: high confidence but old
    let aged_id = Uuid::new_v4();
    repo.insert_event(&prefixd::domain::AttackEvent {
        event_id: aged_id,
        external_event_id: None,
        source: "detector_a".to_string(),
        victim_ip: "203.0.113.10".to_string(),
        event_timestamp: aged_ingested_at,
        ingested_at: aged_ingested_at,
        vector: "udp_flood".to_string(),
        protocol: None,
        bps: None,
        pps: None,
        top_dst_ports_json: "[]".to_string(),
        confidence: Some(0.9),
        action: "ban".to_string(),
        raw_details: None,
    })
    .await
    .unwrap();

    // Fresh event: low confidence but recent
    let fresh_id = Uuid::new_v4();
    repo.insert_event(&prefixd::domain::AttackEvent {
        event_id: fresh_id,
        external_event_id: None,
        source: "detector_b".to_string(),
        victim_ip: "203.0.113.10".to_string(),
        event_timestamp: now,
        ingested_at: now,
        vector: "udp_flood".to_string(),
        protocol: None,
        bps: None,
        pps: None,
        top_dst_ports_json: "[]".to_string(),
        confidence: Some(0.1),
        action: "ban".to_string(),
        raw_details: None,
    })
    .await
    .unwrap();

    let group_id = Uuid::new_v4();
    repo.insert_signal_group(&SignalGroup {
        group_id,
        victim_ip: "203.0.113.10".to_string(),
        vector: "udp_flood".to_string(),
        created_at: aged_ingested_at,
        window_expires_at: now + Duration::seconds(1800),
        derived_confidence: 0.5, // pre-decay weighted average
        source_count: 2,
        status: SignalGroupStatus::Open,
        corroboration_met: false,
        primary_dimensions: PrimaryDimensions::default(),
        playbook_name: None,
    })
    .await
    .unwrap();
    repo.add_event_to_group(group_id, aged_id, 1.0)
        .await
        .unwrap();
    repo.add_event_to_group(group_id, fresh_id, 1.0)
        .await
        .unwrap();

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo.clone(),
        announcer.clone(),
        std::path::PathBuf::from("."),
    )
    .expect("state");

    let reconciler = ReconciliationLoop::new(repo.clone(), announcer.clone(), 30, true)
        .with_app_state(state.clone());
    reconciler.reconcile().await.expect("reconcile");

    let after = repo.get_signal_group(group_id).await.unwrap().unwrap();
    // Decay should shift average toward the fresh low-confidence event.
    // Expected ≈ 0.189, definitely < 0.5 (the undecayed average)
    assert!(
        after.derived_confidence < 0.35,
        "expected decayed confidence < 0.35, got {}",
        after.derived_confidence
    );
    assert!(
        after.derived_confidence > 0.1,
        "should not drop to floor of fresh event alone, got {}",
        after.derived_confidence
    );
    assert_eq!(
        after.source_count, 2,
        "source_count unaffected by decay (ADR 022)"
    );
}

#[tokio::test]
async fn test_decay_one_shot_corroboration_no_flap_back() {
    // corroboration_met=true is sticky: once set, decay-induced drops in
    // derived_confidence below the configured threshold must NOT flip
    // the flag back to false. We seed two events (one aged, one fresh)
    // so decay actually shifts the weighted average.
    use chrono::{Duration, Utc};
    use prefixd::bgp::FlowSpecAnnouncer;
    use prefixd::correlation::engine::{PrimaryDimensions, SignalGroup, SignalGroupStatus};
    use prefixd::scheduler::ReconciliationLoop;
    use uuid::Uuid;

    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer: Arc<dyn FlowSpecAnnouncer> = Arc::new(MockAnnouncer::new());

    let mut settings = test_settings_with_correlation(true, 1, 0.5);
    settings.correlation.window_seconds = 3600;
    settings.correlation.confidence_decay_half_life_seconds = 60;

    let now = Utc::now();
    let aged_ingested_at = now - Duration::seconds(300); // 5 half-lives

    // Aged event (conf=0.1, weight=1.0)
    let aged_id = Uuid::new_v4();
    repo.insert_event(&prefixd::domain::AttackEvent {
        event_id: aged_id,
        external_event_id: None,
        source: "detector_a".to_string(),
        victim_ip: "203.0.113.10".to_string(),
        event_timestamp: aged_ingested_at,
        ingested_at: aged_ingested_at,
        vector: "udp_flood".to_string(),
        protocol: None,
        bps: None,
        pps: None,
        top_dst_ports_json: "[]".to_string(),
        confidence: Some(0.1),
        action: "ban".to_string(),
        raw_details: None,
    })
    .await
    .unwrap();

    // Fresh event (conf=0.1, weight=1.0)
    let fresh_id = Uuid::new_v4();
    repo.insert_event(&prefixd::domain::AttackEvent {
        event_id: fresh_id,
        external_event_id: None,
        source: "detector_b".to_string(),
        victim_ip: "203.0.113.10".to_string(),
        event_timestamp: now,
        ingested_at: now,
        vector: "udp_flood".to_string(),
        protocol: None,
        bps: None,
        pps: None,
        top_dst_ports_json: "[]".to_string(),
        confidence: Some(0.1),
        action: "ban".to_string(),
        raw_details: None,
    })
    .await
    .unwrap();

    let group_id = Uuid::new_v4();
    repo.insert_signal_group(&SignalGroup {
        group_id,
        victim_ip: "203.0.113.10".to_string(),
        vector: "udp_flood".to_string(),
        created_at: aged_ingested_at,
        window_expires_at: now + Duration::seconds(1800),
        derived_confidence: 0.7, // was high when corroboration triggered
        source_count: 2,
        status: SignalGroupStatus::Open,
        corroboration_met: true, // already triggered earlier
        primary_dimensions: PrimaryDimensions::default(),
        playbook_name: None,
    })
    .await
    .unwrap();
    repo.add_event_to_group(group_id, aged_id, 1.0)
        .await
        .unwrap();
    repo.add_event_to_group(group_id, fresh_id, 1.0)
        .await
        .unwrap();

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo.clone(),
        announcer.clone(),
        std::path::PathBuf::from("."),
    )
    .expect("state");

    let reconciler = ReconciliationLoop::new(repo.clone(), announcer.clone(), 30, true)
        .with_app_state(state.clone());
    reconciler.reconcile().await.expect("reconcile");

    let after = repo.get_signal_group(group_id).await.unwrap().unwrap();
    // Both events have conf=0.1 so decayed average will be ~0.1 < 0.5 threshold
    assert!(
        after.derived_confidence < 0.5,
        "decay should drop confidence below the 0.5 threshold (got {})",
        after.derived_confidence
    );
    assert!(
        after.corroboration_met,
        "corroboration_met must stay true even when decay drops confidence below threshold"
    );
}

#[tokio::test]
async fn test_decay_disabled_does_not_touch_groups() {
    // With half_life_seconds=0, refresh_decayed_confidence is a no-op
    // even on groups with very old events.
    use chrono::{Duration, Utc};
    use prefixd::bgp::FlowSpecAnnouncer;
    use prefixd::correlation::engine::{PrimaryDimensions, SignalGroup, SignalGroupStatus};
    use prefixd::scheduler::ReconciliationLoop;
    use uuid::Uuid;

    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer: Arc<dyn FlowSpecAnnouncer> = Arc::new(MockAnnouncer::new());

    let settings = test_settings_with_correlation(true, 1, 0.5);
    assert_eq!(settings.correlation.confidence_decay_half_life_seconds, 0);

    let now = Utc::now();
    let event_id = Uuid::new_v4();
    repo.insert_event(&prefixd::domain::AttackEvent {
        event_id,
        external_event_id: None,
        source: "detector_a".to_string(),
        victim_ip: "203.0.113.10".to_string(),
        event_timestamp: now - Duration::seconds(3600),
        ingested_at: now - Duration::seconds(3600),
        vector: "udp_flood".to_string(),
        protocol: None,
        bps: None,
        pps: None,
        top_dst_ports_json: "[]".to_string(),
        confidence: Some(0.85),
        action: "ban".to_string(),
        raw_details: None,
    })
    .await
    .unwrap();

    let group_id = Uuid::new_v4();
    repo.insert_signal_group(&SignalGroup {
        group_id,
        victim_ip: "203.0.113.10".to_string(),
        vector: "udp_flood".to_string(),
        created_at: now - Duration::seconds(3600),
        window_expires_at: now + Duration::seconds(7200),
        derived_confidence: 0.85,
        source_count: 1,
        status: SignalGroupStatus::Open,
        corroboration_met: false,
        primary_dimensions: PrimaryDimensions::default(),
        playbook_name: None,
    })
    .await
    .unwrap();
    repo.add_event_to_group(group_id, event_id, 1.0)
        .await
        .unwrap();

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo.clone(),
        announcer.clone(),
        std::path::PathBuf::from("."),
    )
    .expect("state");

    let reconciler = ReconciliationLoop::new(repo.clone(), announcer.clone(), 30, true)
        .with_app_state(state.clone());
    reconciler.reconcile().await.expect("reconcile");

    let after = repo.get_signal_group(group_id).await.unwrap().unwrap();
    assert!(
        (after.derived_confidence - 0.85).abs() < 1e-3,
        "decay disabled ⇒ derived_confidence unchanged; got {}",
        after.derived_confidence
    );
}

#[tokio::test]
async fn test_cache_listing_endpoint_returns_unattached_signals() {
    use chrono::{Duration, Utc};
    use prefixd::correlation::{CorroboratingSignal, MatchDimension, SourceConfig, SourceMode};
    use uuid::Uuid;

    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let mut settings = test_settings_with_correlation(true, 1, 0.5);
    settings.correlation.sources.insert(
        "router-cpu".to_string(),
        SourceConfig {
            weight: 0.5,
            r#type: "telemetry".to_string(),
            confidence_mapping: std::collections::HashMap::new(),
            mode: SourceMode::Corroborating,
            match_dimensions: vec![MatchDimension::Pop],
        },
    );

    let now = Utc::now();
    repo.insert_corroborating_signal(&CorroboratingSignal {
        signal_id: Uuid::new_v4(),
        source: "router-cpu".to_string(),
        vector: Some("udp_flood".to_string()),
        customer_id: None,
        pop: Some("iad1".to_string()),
        service_id: None,
        interface: None,
        confidence: Some(0.5),
        weight: 0.5,
        ingested_at: now,
        expires_at: now + Duration::seconds(300),
        raw_details: None,
        attached_group_ids: vec![],
    })
    .await
    .unwrap();
    // Attached row that should NOT show up in the listing.
    repo.insert_corroborating_signal(&CorroboratingSignal {
        signal_id: Uuid::new_v4(),
        source: "router-cpu".to_string(),
        vector: Some("udp_flood".to_string()),
        customer_id: None,
        pop: Some("iad1".to_string()),
        service_id: None,
        interface: None,
        confidence: Some(0.5),
        weight: 0.5,
        ingested_at: now,
        expires_at: now + Duration::seconds(300),
        raw_details: None,
        attached_group_ids: vec![Uuid::new_v4()],
    })
    .await
    .unwrap();

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("state");
    let app = create_test_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/signals/corroborator/cache?limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let signals = json["signals"].as_array().unwrap();
    assert_eq!(signals.len(), 1, "attached signal should be excluded");
    assert_eq!(json["total"], 1);
    assert_eq!(json["by_source"][0]["source"], "router-cpu");
    assert_eq!(json["by_source"][0]["count"], 1);
}

#[tokio::test]
async fn test_cache_listing_endpoint_source_filter_scopes_aggregates() {
    // Regression: when `?source=` is passed, total + by_source must
    // also be filtered to that source. Otherwise clients see a `total`
    // that doesn't match the rows they were just handed.
    use chrono::{Duration, Utc};
    use prefixd::correlation::{CorroboratingSignal, MatchDimension, SourceConfig, SourceMode};
    use uuid::Uuid;

    let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
    let announcer = Arc::new(MockAnnouncer::new());
    let mut settings = test_settings_with_correlation(true, 1, 0.5);
    for src in ["router-cpu", "pop-utilization"] {
        settings.correlation.sources.insert(
            src.to_string(),
            SourceConfig {
                weight: 0.5,
                r#type: "telemetry".to_string(),
                confidence_mapping: std::collections::HashMap::new(),
                mode: SourceMode::Corroborating,
                match_dimensions: vec![MatchDimension::Pop],
            },
        );
    }

    // Three rows: 2 router-cpu, 1 pop-utilization. All unattached + unexpired.
    let now = Utc::now();
    for src in ["router-cpu", "router-cpu", "pop-utilization"] {
        repo.insert_corroborating_signal(&CorroboratingSignal {
            signal_id: Uuid::new_v4(),
            source: src.to_string(),
            vector: Some("udp_flood".to_string()),
            customer_id: None,
            pop: Some("iad1".to_string()),
            service_id: None,
            interface: None,
            confidence: Some(0.5),
            weight: 0.5,
            ingested_at: now,
            expires_at: now + Duration::seconds(300),
            raw_details: None,
            attached_group_ids: vec![],
        })
        .await
        .unwrap();
    }

    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo,
        announcer,
        std::path::PathBuf::from("."),
    )
    .expect("state");
    let app = create_test_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/signals/corroborator/cache?source=pop-utilization&limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let signals = json["signals"].as_array().unwrap();
    assert_eq!(signals.len(), 1);
    assert_eq!(json["total"], 1, "total must be scoped to ?source=");
    let by_source = json["by_source"].as_array().unwrap();
    assert_eq!(by_source.len(), 1);
    assert_eq!(by_source[0]["source"], "pop-utilization");
    assert_eq!(by_source[0]["count"], 1);
}

// ==========================================================================
// Integration tests for untested API endpoints
// ==========================================================================

// ─── Operators CRUD ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_list_operators() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/operators")
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
    assert_eq!(json["count"], 0);
    assert!(json["operators"].is_array());
}

#[tokio::test]
async fn test_create_operator() {
    let app = setup_app().await;

    let body = serde_json::json!({
        "username": "newadmin",
        "password": "supersecret",
        "role": "admin"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/operators")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let resp_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert_eq!(json["username"], "newadmin");
    assert_eq!(json["role"], "admin");
}

#[tokio::test]
async fn test_create_operator_duplicate() {
    let app = setup_app().await;

    let body = serde_json::json!({
        "username": "dupadmin",
        "password": "supersecret",
        "role": "admin"
    });

    // First create succeeds
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/operators")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Second create with same username fails with 409
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/operators")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_delete_operator() {
    let app = setup_app().await;

    // Create an operator to delete
    let create_body = serde_json::json!({
        "username": "delete_me",
        "password": "supersecret",
        "role": "admin"
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/operators")
                .header("content-type", "application/json")
                .body(Body::from(create_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let resp_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    let operator_id = json["operator_id"].as_str().unwrap();

    // Delete the operator
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/operators/{}", operator_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_delete_operator_not_found() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/operators/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_change_password() {
    let app = setup_app().await;

    // Create an operator
    let create_body = serde_json::json!({
        "username": "pwd_user",
        "password": "supersecret",
        "role": "admin"
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/operators")
                .header("content-type", "application/json")
                .body(Body::from(create_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let resp_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    let operator_id = json["operator_id"].as_str().unwrap();

    // Change password
    let pwd_body = serde_json::json!({
        "current_password": "supersecret",
        "new_password": "newsupersecret"
    });
    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/v1/operators/{}/password", operator_id))
                .header("content-type", "application/json")
                .body(Body::from(pwd_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_change_password_admin_reset_without_current() {
    let app = setup_app().await;

    // Create an operator
    let create_body = serde_json::json!({
        "username": "reset_user",
        "password": "supersecret",
        "role": "operator"
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/operators")
                .header("content-type", "application/json")
                .body(Body::from(create_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let resp_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    let operator_id = json["operator_id"].as_str().unwrap();

    // Admin reset without current_password (auth_mode=none → synthetic admin)
    let pwd_body = serde_json::json!({
        "new_password": "newsupersecret"
    });
    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/v1/operators/{}/password", operator_id))
                .header("content-type", "application/json")
                .body(Body::from(pwd_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

// ─── Safelist CRUD ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_list_safelist() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/safelist")
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
    assert!(json.is_array());
}

#[tokio::test]
async fn test_add_safelist() {
    let app = setup_app().await;

    let body = serde_json::json!({
        "operator_id": "test_operator",
        "prefix": "198.51.100.0/24",
        "reason": "test safelist"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/safelist")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_add_safelist_invalid_prefix() {
    let app = setup_app().await;

    let body = serde_json::json!({
        "operator_id": "test_operator",
        "prefix": "not-a-valid-cidr"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/safelist")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_remove_safelist() {
    let app = setup_app().await;

    // Add a safelist entry first
    let add_body = serde_json::json!({
        "operator_id": "test_operator",
        "prefix": "198.51.100.1"
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/safelist")
                .header("content-type", "application/json")
                .body(Body::from(add_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Remove it
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/safelist/198.51.100.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

/// Dashboard/CLI send the CIDR as a single percent-encoded path segment.
#[tokio::test]
async fn test_remove_safelist_percent_encoded_cidr() {
    let app = setup_app().await;

    let add_body = serde_json::json!({ "prefix": "203.0.113.9/32" });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/safelist")
                .header("content-type", "application/json")
                .body(Body::from(add_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/safelist/203.0.113.9%2F32")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

/// Proxies that decode `%2F` (or hand-written curl calls) send the CIDR with a
/// literal slash; the route must accept that form too.
#[tokio::test]
async fn test_remove_safelist_literal_slash_cidr() {
    let app = setup_app().await;

    let add_body = serde_json::json!({ "prefix": "203.0.113.10/32" });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/safelist")
                .header("content-type", "application/json")
                .body(Body::from(add_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/safelist/203.0.113.10/32")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_remove_safelist_not_found() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/safelist/198.51.100.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ─── Manual mitigate ───────────────────────────────────────────────────

mod manual_protocol {
    use super::*;
    use prefixd::domain::{ActionType, MitigationStatus, mitigation_rule};
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

    #[derive(Default)]
    struct Speaker {
        inner: MockAnnouncer,
        mutations: AtomicUsize,
    }

    impl prefixd::bgp::FlowSpecAnnouncer for Speaker {
        fn backend(&self) -> &'static str {
            "mock"
        }
        fn reader(&self) -> Option<&dyn FlowSpecReader> {
            Some(&self.inner)
        }
    }

    #[async_trait::async_trait]
    impl FlowSpecWriter for Speaker {
        async fn announce(
            &self,
            rule: &prefixd::domain::FlowSpecRule,
        ) -> prefixd::error::Result<()> {
            self.mutations.fetch_add(1, SeqCst);
            self.inner.announce(rule).await
        }
        async fn withdraw(
            &self,
            rule: &prefixd::domain::FlowSpecRule,
        ) -> prefixd::error::Result<()> {
            self.mutations.fetch_add(1, SeqCst);
            self.inner.withdraw(rule).await
        }
    }

    fn state(auth: AuthMode) -> (Arc<AppState>, Arc<MockRepository>, Arc<Speaker>) {
        let mut settings = test_settings();
        settings.mode = prefixd::config::OperationMode::Enforced;
        settings.http.auth.mode = auth;
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(Speaker::default());
        let state = AppState::new(
            settings,
            test_inventory(),
            test_playbooks(),
            repo.clone(),
            speaker.clone(),
            ".".into(),
        )
        .unwrap();
        (state, repo, speaker)
    }

    fn payload(ip: &str, protocol: &str) -> serde_json::Value {
        serde_json::json!({
            "victim_ip": ip, "protocol": protocol, "action": "discard",
            "ttl_seconds": 120, "reason": "manual protocol test"
        })
    }

    async fn post(state: Arc<AppState>, payload: serde_json::Value) -> axum::response::Response {
        create_test_router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/mitigations")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn assert_no_mutation(repo: &MockRepository, speaker: &Speaker) {
        assert!(
            repo.list_mitigations(
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
            .unwrap()
            .is_empty()
        );
        assert_eq!(speaker.mutations.load(SeqCst), 0);
    }

    #[tokio::test]
    async fn event_metadata_byte_boundaries_match_single_and_batch() {
        for batch in [false, true] {
            for field in ["source", "event_id"] {
                for unit in ["a", "é"] {
                    let (state, repo, speaker) = state(AuthMode::None);
                    let app = create_test_router(state);
                    let params = prefixd::db::ListParams {
                        limit: 10,
                        ..Default::default()
                    };
                    let boundary = unit.repeat(1024 / unit.len());
                    assert_eq!(boundary.len(), 1024);
                    for oversized in [false, true] {
                        let before = repo.list_events(&params).await.unwrap();
                        let value = format!("{boundary}{}", if oversized { "x" } else { "" });
                        assert_eq!(value.len(), if oversized { 1025 } else { 1024 });
                        let mut input = serde_json::json!({
                            "event_id": "metadata-boundary", "timestamp": chrono::Utc::now(),
                            "source": "metadata", "victim_ip": "203.0.113.10", "vector": "unknown"
                        });
                        input[field] = value.clone().into();
                        let request = if batch {
                            serde_json::json!({ "events": [input] })
                        } else {
                            input
                        };
                        let response = app
                            .clone()
                            .oneshot(
                                Request::builder()
                                    .method("POST")
                                    .uri(if batch {
                                        "/v1/events/batch"
                                    } else {
                                        "/v1/events"
                                    })
                                    .header("content-type", "application/json")
                                    .body(Body::from(request.to_string()))
                                    .unwrap(),
                            )
                            .await
                            .unwrap();
                        let expected = match (batch, oversized) {
                            (_, false) => StatusCode::ACCEPTED,
                            (true, true) => StatusCode::MULTI_STATUS,
                            (false, true) => StatusCode::BAD_REQUEST,
                        };
                        assert_eq!(
                            response.status(),
                            expected,
                            "{batch} {field} {unit} {oversized}"
                        );
                        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                            .await
                            .unwrap();
                        let result: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                        let saved = repo.list_events(&params).await.unwrap();
                        if oversized {
                            let error = if batch {
                                &result["results"][0]["error"]
                            } else {
                                &result["error"]
                            };
                            assert!(error.as_str().unwrap().contains(field));
                            assert_eq!(
                                serde_json::to_value(saved).unwrap(),
                                serde_json::to_value(before).unwrap()
                            );
                        } else {
                            assert_eq!(saved.len(), 1);
                            let stored = if field == "source" {
                                Some(saved[0].source.as_str())
                            } else {
                                saved[0].external_event_id.as_deref()
                            };
                            assert_eq!(stored, Some(value.as_str()));
                        }
                        if batch {
                            assert_eq!(result["accepted"], if oversized { 0 } else { 1 });
                            assert_eq!(result["rejected"], if oversized { 1 } else { 0 });
                        }
                        assert_no_mutation(repo.as_ref(), speaker.as_ref()).await;
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn event_batch_accepts_exactly_one_hundred_events() {
        use std::collections::BTreeSet;
        use uuid::Uuid;

        let (state, repo, speaker) = state(AuthMode::None);
        let events: Vec<_> = (0..100)
            .map(|index| {
                serde_json::json!({
                    "event_id": format!("batch-boundary-{index}"), "timestamp": chrono::Utc::now(),
                    "source": "batch-boundary", "victim_ip": "203.0.113.10", "vector": "unknown"
                })
            })
            .collect();
        let response = create_test_router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/events/batch")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "events": events }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let result: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result["accepted"], 100);
        assert_eq!(result["rejected"], 0);
        let results = result["results"].as_array().unwrap();
        assert_eq!(results.len(), 100);
        let returned: BTreeSet<_> = results
            .iter()
            .map(|item| Uuid::parse_str(item["event_id"].as_str().unwrap()).unwrap())
            .collect();
        assert_eq!(returned.len(), 100);
        let stored = repo
            .list_events(&prefixd::db::ListParams {
                limit: 101,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(stored.len(), 100);
        assert_eq!(
            stored
                .iter()
                .map(|event| event.event_id)
                .collect::<BTreeSet<_>>(),
            returned
        );
        assert_no_mutation(repo.as_ref(), speaker.as_ref()).await;
    }

    #[tokio::test]
    async fn u16_port_boundaries_for_event_and_manual_requests() {
        for manual in [false, true] {
            let (state, repo, speaker) = state(AuthMode::None);
            // Both deliberate empty lists leave detector ports unconstrained.
            state.inventory.write().await.customers[0].services[0].allowed_ports =
                AllowedPorts::default();
            let app = create_test_router(state);
            let params = prefixd::db::MitigationListParams {
                limit: 10,
                ..Default::default()
            };
            let event_params = prefixd::db::ListParams {
                limit: 10,
                ..Default::default()
            };
            for (index, (port, expected_port)) in [
                (serde_json::json!(0), Some(0_u16)),
                (serde_json::json!(65535), Some(65535)),
                (serde_json::json!(-1), None),
                (serde_json::json!(65536), None),
                (serde_json::json!(1.5), None),
                (serde_json::json!("53"), None),
            ]
            .into_iter()
            .enumerate()
            {
                let before = repo
                    .list_mitigations(None, None, None, None, &params)
                    .await
                    .unwrap();
                let before_events = repo.list_events(&event_params).await.unwrap();
                let mutations = speaker.mutations.load(SeqCst);
                let mut input = if manual {
                    payload("203.0.113.10", "udp")
                } else {
                    serde_json::json!({
                        "event_id": format!("port-boundary-{index}"), "timestamp": chrono::Utc::now(),
                        "source": "port-boundary", "victim_ip": "203.0.113.10", "vector": "udp_flood",
                        "pps": 50000, "confidence": 0.9
                    })
                };
                input[if manual { "dst_ports" } else { "top_dst_ports" }] =
                    serde_json::json!([port]);
                let response = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri(if manual {
                                "/v1/mitigations"
                            } else {
                                "/v1/events"
                            })
                            .header("content-type", "application/json")
                            .body(Body::from(input.to_string()))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let saved = repo
                    .list_mitigations(None, None, None, None, &params)
                    .await
                    .unwrap();
                let saved_events = repo.list_events(&event_params).await.unwrap();
                if let Some(port) = expected_port {
                    assert_eq!(
                        response.status(),
                        if manual {
                            StatusCode::CREATED
                        } else {
                            StatusCode::ACCEPTED
                        }
                    );
                    assert_eq!(saved.len(), before.len() + 1);
                    assert_eq!(
                        saved_events.len(),
                        before_events.len() + usize::from(!manual)
                    );
                    if !manual {
                        assert!(
                            saved_events
                                .iter()
                                .any(|event| event.top_dst_ports() == [port])
                        );
                    }
                    assert!(
                        saved
                            .iter()
                            .any(|mitigation| mitigation.match_criteria.dst_ports == [port])
                    );
                    assert!(
                        speaker
                            .inner
                            .list_active()
                            .await
                            .unwrap()
                            .iter()
                            .any(|rule| rule.nlri.dst_ports == [port])
                    );
                    assert_eq!(speaker.mutations.load(SeqCst), mutations + 1);
                } else {
                    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
                    assert_eq!(
                        serde_json::to_value(saved).unwrap(),
                        serde_json::to_value(before).unwrap()
                    );
                    assert_eq!(
                        serde_json::to_value(saved_events).unwrap(),
                        serde_json::to_value(before_events).unwrap()
                    );
                    assert_eq!(speaker.mutations.load(SeqCst), mutations);
                }
            }
        }
    }

    #[tokio::test]
    async fn invalid_actions_create_no_intent_or_speaker_mutation() {
        for ip in ["203.0.113.10", "2001:db8::10"] {
            for (action, rate, error) in [
                ("police", None, "requires rate_bps"),
                ("police", Some(0), "rate_bps > 0"),
                ("police", Some(16_777_217), "represented exactly"),
                ("police", Some(u64::MAX), "represented exactly"),
                ("discard", Some(0), "must not include rate_bps"),
                ("discard", Some(8), "must not include rate_bps"),
            ] {
                let (state, repo, speaker) = state(AuthMode::None);
                let mut request = payload(ip, "udp");
                request["action"] = action.into();
                request["rate_bps"] = serde_json::json!(rate);
                let response = post(state, request).await;
                assert_eq!(
                    response.status(),
                    StatusCode::BAD_REQUEST,
                    "{ip} {action} {rate:?}"
                );
                let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                    .await
                    .unwrap();
                let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert!(body["error"].as_str().unwrap().contains(error), "{body}");
                assert_no_mutation(repo.as_ref(), speaker.as_ref()).await;
            }
        }
    }

    #[tokio::test]
    async fn fractional_byte_rates_preserve_manual_intent() {
        for ip in ["203.0.113.10", "2001:db8::10"] {
            for rate in [1, 7, 8, 9, 16_777_216, 16_777_218] {
                let (state, repo, speaker) = state(AuthMode::None);
                let mut request = payload(ip, "udp");
                request["action"] = "police".into();
                request["rate_bps"] = rate.into();
                assert_eq!(post(state, request).await.status(), StatusCode::CREATED);
                let saved = repo
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
                assert_eq!(saved.len(), 1);
                assert_eq!(saved[0].action_type, ActionType::Police);
                assert_eq!(saved[0].action_params.rate_bps, Some(rate));
                let announced = speaker.inner.list_active().await.unwrap();
                assert_eq!(announced.len(), 1);
                assert_eq!(announced[0].actions[0].rate_bps, Some(rate));
                assert_eq!(speaker.mutations.load(SeqCst), 1);
            }
        }
    }

    #[tokio::test]
    async fn invalid_playbook_action_cannot_create_or_extend_an_owner() {
        for existing in [false, true] {
            for (action, rate) in [
                (PlaybookAction::Police, None),
                (PlaybookAction::Police, Some(0)),
                (PlaybookAction::Police, Some(16_777_217)),
                (PlaybookAction::Police, Some(u64::MAX)),
                (PlaybookAction::Discard, Some(8)),
            ] {
                let (state, repo, speaker) = state(AuthMode::None);
                if existing {
                    let mut request = payload("203.0.113.10", "udp");
                    request["dst_ports"] = serde_json::json!([53]);
                    request["ttl_seconds"] = 30.into();
                    assert_eq!(
                        post(state.clone(), request).await.status(),
                        StatusCode::CREATED
                    );
                }
                let params = prefixd::db::MitigationListParams {
                    limit: 10,
                    ..Default::default()
                };
                let before = serde_json::to_value(
                    repo.list_mitigations(None, None, None, None, &params)
                        .await
                        .unwrap(),
                )
                .unwrap();
                let mut playbooks = state.playbooks.write().await;
                playbooks.playbooks[0].steps[0].action = action;
                playbooks.playbooks[0].steps[0].rate_bps = rate;
                drop(playbooks);
                let request = serde_json::json!({
                    "event_id": "invalid-action", "timestamp": chrono::Utc::now(),
                    "source": "action-test", "victim_ip": "203.0.113.10", "vector": "udp_flood",
                    "pps": 50000, "top_dst_ports": [53], "confidence": 0.9
                });
                let response = create_test_router(state)
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/v1/events")
                            .header("content-type", "application/json")
                            .body(Body::from(request.to_string()))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
                assert!(
                    repo.find_ban_event_by_external_id("action-test", "invalid-action")
                        .await
                        .unwrap()
                        .is_none()
                );
                let after = serde_json::to_value(
                    repo.list_mitigations(None, None, None, None, &params)
                        .await
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(
                    after, before,
                    "invalid action must not extend the existing owner"
                );
                assert_eq!(speaker.mutations.load(SeqCst), usize::from(existing));
            }
        }
    }

    #[tokio::test]
    async fn valid_playbook_cannot_extend_a_historical_invalid_owner() {
        let (state, repo, speaker) = state(AuthMode::None);
        let mut request = payload("203.0.113.10", "udp");
        request["dst_ports"] = serde_json::json!([53]);
        assert_eq!(
            post(state.clone(), request).await.status(),
            StatusCode::CREATED
        );
        let params = prefixd::db::MitigationListParams {
            limit: 10,
            ..Default::default()
        };
        let mut owner = repo
            .list_mitigations(None, None, None, None, &params)
            .await
            .unwrap()
            .remove(0);
        owner.action_type = ActionType::Police;
        owner.action_params.rate_bps = Some(0);
        repo.update_mitigation(&owner).await.unwrap();
        let before =
            serde_json::to_value(repo.get_mitigation(owner.mitigation_id).await.unwrap()).unwrap();
        let event = serde_json::json!({
            "event_id":"historical-action", "timestamp":chrono::Utc::now(), "source":"action-test",
            "victim_ip":"203.0.113.10", "vector":"udp_flood", "pps":50000, "top_dst_ports":[53], "confidence":0.9
        });
        let response = create_test_router(state)
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
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            serde_json::to_value(repo.get_mitigation(owner.mitigation_id).await.unwrap()).unwrap(),
            before
        );
        assert!(
            repo.find_ban_event_by_external_id("action-test", "historical-action")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(speaker.mutations.load(SeqCst), 1);
    }

    #[tokio::test]
    async fn protocols_preserve_exact_intent_and_announcement() {
        let cases: &[(&str, &str, Option<u8>, &[u16])] = &[
            ("203.0.113.10", "icmp", Some(1), &[]),
            ("2001:db8::10", "icmpv6", Some(58), &[]),
            ("::ffff:203.0.113.10", "icmpv6", Some(58), &[]),
            (
                "203.0.113.10",
                "udp",
                Some(17),
                &[53, 80, 123, 443, 853, 5353, 8080, 9000],
            ),
            (
                "2001:db8::10",
                "udp",
                Some(17),
                &[53, 80, 123, 443, 853, 5353, 8080, 9000],
            ),
            ("203.0.113.10", "tcp", Some(6), &[80, 443]),
            ("2001:db8::10", "tcp", Some(6), &[80, 443]),
            ("203.0.113.10", "any", None, &[]),
            ("2001:db8::10", "any", None, &[]),
            ("203.0.113.10", "", None, &[]),
            ("2001:db8::10", "", None, &[]),
        ];
        for &(ip, protocol, expected_protocol, ports) in cases {
            for action in [ActionType::Discard, ActionType::Police] {
                let (state, repo, speaker) = state(AuthMode::None);
                let cap = chrono::Utc::now() + chrono::Duration::seconds(60);
                let ttl = match protocol {
                    "any" => 30,
                    "" => 1800,
                    _ => 120,
                };
                let mut request = payload(ip, protocol);
                request["dst_ports"] = serde_json::json!(ports);
                request["action"] = serde_json::json!(action);
                request["ttl_seconds"] = ttl.into();
                request["expires_at_cap"] = serde_json::json!(cap);
                let rate_bps = (action == ActionType::Police).then_some(10_000_000);
                if let Some(rate) = rate_bps {
                    request["rate_bps"] = rate.into();
                }
                let response = post(state, request).await;
                assert_eq!(
                    response.status(),
                    StatusCode::CREATED,
                    "{ip} {protocol} {action}"
                );
                let rows = repo
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
                assert_eq!(rows.len(), 1);
                let saved = &rows[0];
                assert_eq!(saved.victim_ip, ip);
                assert_eq!(
                    saved.match_criteria.dst_prefix,
                    format!("{ip}/{}", if ip.contains(':') { 128 } else { 32 })
                );
                assert_eq!(saved.match_criteria.protocol, expected_protocol);
                assert_eq!(saved.match_criteria.dst_ports, ports);
                assert_eq!(saved.action_type, action);
                assert_eq!(saved.action_params.rate_bps, rate_bps);
                assert_eq!(saved.status, MitigationStatus::Active);
                assert_eq!(
                    saved.expires_at,
                    cap.min(saved.created_at + chrono::Duration::seconds(ttl))
                );
                assert_eq!(speaker.mutations.load(SeqCst), 1);
                assert_eq!(
                    serde_json::to_value(speaker.inner.list_active().await.unwrap()).unwrap(),
                    serde_json::json!([mitigation_rule(saved).unwrap()])
                );
            }
        }
    }

    #[tokio::test]
    async fn invalid_protocols_and_families_cause_no_mutation() {
        for (ip, protocol, error) in [
            ("2001:db8::10", "icmp", "address family"),
            ("203.0.113.10", "icmpv6", "address family"),
            ("::ffff:203.0.113.10", "icmp", "address family"),
            ("2001:db8::10", "icmp6", "invalid protocol"),
            ("2001:db8::10", "ICMPv6", "invalid protocol"),
            ("203.0.113.10", "gre", "invalid protocol"),
            ("2001:db8::10", "58", "invalid protocol"),
            ("203.0.113.10", "1", "invalid protocol"),
            ("not-an-ip", "icmpv6", "invalid IP address"),
            ("2001:db8::10/128", "icmpv6", "invalid IP address"),
            ("[2001:db8::10]", "icmpv6", "invalid IP address"),
        ] {
            let (state, repo, speaker) = state(AuthMode::None);
            let response = post(state, payload(ip, protocol)).await;
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let rows = repo
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
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{ip} {protocol}: response={json}, rows={rows:?}, mutations={}",
                speaker.mutations.load(SeqCst)
            );
            assert!(json["error"].as_str().unwrap().contains(error), "{json}");
            assert_no_mutation(repo.as_ref(), speaker.as_ref()).await;
        }
    }

    #[tokio::test]
    async fn duplicate_acknowledgements_count_entries_without_remutating_rows() {
        use uuid::Uuid;
        let (mut app_state, repo, speaker) = state(AuthMode::None);
        let cached = Arc::get_mut(&mut app_state).unwrap();
        cached.settings.http.auth.mode = AuthMode::Bearer;
        cached.bearer_token = Some("duplicate-ack-token".into());
        let mut targets = Vec::new();
        for ip in ["203.0.113.10", "203.0.113.11", "203.0.113.12"] {
            let response = create_test_router(app_state.clone())
                .oneshot(
                    Request::post("/v1/mitigations")
                        .header("content-type", "application/json")
                        .header("authorization", "Bearer duplicate-ack-token")
                        .body(Body::from(payload(ip, "udp").to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);
            let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            targets.push(Uuid::parse_str(json["mitigation_id"].as_str().unwrap()).unwrap());
        }
        let original_rules =
            serde_json::to_value(speaker.inner.list_active().await.unwrap()).unwrap();
        assert_eq!(original_rules.as_array().unwrap().len(), 3);
        assert_eq!(speaker.mutations.load(SeqCst), 3);
        let params = prefixd::db::ListParams {
            limit: 10,
            ..Default::default()
        };
        let original_audit = serde_json::to_value(repo.list_audit(&params).await.unwrap()).unwrap();
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
                before.push(repo.get_mitigation(*id).await.unwrap().unwrap());
            }
            let response = create_test_router(app_state.clone())
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
            let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
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
            for (index, previous) in before.iter().enumerate() {
                let row = repo
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
            }
            assert_eq!(
                speaker.mutations.load(SeqCst),
                3,
                "acknowledgement must not issue speaker mutations"
            );
            assert_eq!(
                serde_json::to_value(speaker.inner.list_active().await.unwrap()).unwrap(),
                original_rules
            );
            assert_eq!(
                serde_json::to_value(repo.list_audit(&params).await.unwrap()).unwrap(),
                original_audit
            );
        }
    }

    #[tokio::test]
    async fn icmp_selectors_preserve_ttl_and_auth_guardrails() {
        for (ip, protocol) in [("203.0.113.10", "icmp"), ("2001:db8::10", "icmpv6")] {
            for ttl in [0, 29, 1801] {
                let (state, repo, speaker) = state(AuthMode::None);
                let mut request = payload(ip, protocol);
                request["ttl_seconds"] = ttl.into();
                assert_eq!(
                    post(state, request).await.status(),
                    StatusCode::UNPROCESSABLE_ENTITY
                );
                assert_no_mutation(repo.as_ref(), speaker.as_ref()).await;
            }
            for remaining in [-1, 29] {
                let (state, repo, speaker) = state(AuthMode::None);
                let mut request = payload(ip, protocol);
                request["expires_at_cap"] =
                    serde_json::json!(chrono::Utc::now() + chrono::Duration::seconds(remaining));
                assert_eq!(
                    post(state, request).await.status(),
                    StatusCode::UNPROCESSABLE_ENTITY
                );
                assert_no_mutation(repo.as_ref(), speaker.as_ref()).await;
            }
            let (state, repo, speaker) = state(AuthMode::Credentials);
            assert_eq!(
                post(state, payload(ip, protocol)).await.status(),
                StatusCode::UNAUTHORIZED
            );
            assert_no_mutation(repo.as_ref(), speaker.as_ref()).await;
        }
    }
}

#[tokio::test]
async fn test_create_mitigation() {
    let app = setup_app().await;

    let body = serde_json::json!({
        "operator_id": "test_operator",
        "reason": "manual mitigation",
        "victim_ip": "203.0.113.10",
        "protocol": "udp",
        "dst_ports": [53],
        "action": "discard",
        "ttl_seconds": 120
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mitigations")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_create_mitigation_safelisted() {
    let app = setup_app().await;

    // Safelist the victim IP first
    let safelist_body = serde_json::json!({
        "operator_id": "test_operator",
        "prefix": "203.0.113.10/32"
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/safelist")
                .header("content-type", "application/json")
                .body(Body::from(safelist_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Attempt to mitigate the safelisted IP
    let body = serde_json::json!({
        "operator_id": "test_operator",
        "reason": "manual mitigation",
        "victim_ip": "203.0.113.10",
        "protocol": "udp",
        "dst_ports": [53],
        "action": "discard",
        "ttl_seconds": 120
    });
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mitigations")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn test_create_mitigation_invalid_ip() {
    let app = setup_app().await;

    let body = serde_json::json!({
        "operator_id": "test_operator",
        "reason": "manual mitigation",
        "victim_ip": "not-an-ip",
        "protocol": "udp",
        "action": "discard",
        "ttl_seconds": 120
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mitigations")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_create_mitigation_invalid_protocol() {
    let app = setup_app().await;

    let body = serde_json::json!({
        "operator_id": "test_operator",
        "reason": "manual mitigation",
        "victim_ip": "203.0.113.10",
        "protocol": "gre",
        "action": "discard",
        "ttl_seconds": 120
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mitigations")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_create_mitigation_police_no_rate() {
    let app = setup_app().await;

    let body = serde_json::json!({
        "operator_id": "test_operator",
        "reason": "manual mitigation",
        "victim_ip": "203.0.113.10",
        "protocol": "udp",
        "action": "police",
        "ttl_seconds": 120
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mitigations")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ─── Audit log ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_list_audit() {
    let app = setup_app().await;

    // Ingest an event to generate an audit entry
    let event_json = r#"{
        "timestamp": "2026-01-16T14:00:00Z",
        "source": "test",
        "victim_ip": "203.0.113.10",
        "vector": "udp_flood",
        "pps": 50000
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

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/audit")
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
    assert!(json["count"].as_u64().is_some() || json["entries"].is_array());
}

#[tokio::test]
async fn test_list_audit_empty() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/audit")
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
    assert_eq!(json["count"], 0);
    assert_eq!(json["entries"].as_array().unwrap().len(), 0);
}

// ─── Stats ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_get_stats() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/stats")
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
    assert!(json["total_active"].is_number());
    assert!(json["total_mitigations"].is_number());
    assert!(json["total_events"].is_number());
    assert!(json["pops"].is_array());
}

// ─── Auth ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_get_me() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/auth/me")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Anonymous access does not create an authenticated operator session.
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_logout() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/logout")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

// ─── Single mitigation withdraw ────────────────────────────────────────

#[tokio::test]
async fn test_withdraw_single_mitigation() {
    let app = setup_app().await;

    // Ingest an event to create a mitigation
    let event_json = r#"{
        "timestamp": "2026-01-16T14:00:00Z",
        "source": "test",
        "victim_ip": "203.0.113.10",
        "vector": "udp_flood",
        "pps": 50000
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

    // Get the mitigation ID
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/mitigations")
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
    let mitigations = json["mitigations"].as_array().unwrap();
    assert!(!mitigations.is_empty());
    let mitigation_id = mitigations[0]["mitigation_id"].as_str().unwrap();

    // Withdraw it
    let withdraw_body = serde_json::json!({
        "operator_id": "test_operator",
        "reason": "manual withdraw"
    });
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/mitigations/{}/withdraw", mitigation_id))
                .header("content-type", "application/json")
                .body(Body::from(withdraw_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_withdraw_nonexistent_mitigation() {
    let app = setup_app().await;

    let withdraw_body = serde_json::json!({
        "operator_id": "test_operator",
        "reason": "withdraw nonexistent"
    });
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mitigations/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/withdraw")
                .header("content-type", "application/json")
                .body(Body::from(withdraw_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ─── Event ingestion edge cases ────────────────────────────────────────

#[tokio::test]
async fn test_ingest_event_malformed_json() {
    let app = setup_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/events")
                .header("content-type", "application/json")
                .body(Body::from("{ this is not valid json"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_ingest_event_missing_victim_ip() {
    let app = setup_app().await;

    let event_json = r#"{
        "timestamp": "2026-01-16T14:00:00Z",
        "source": "test",
        "vector": "udp_flood",
        "pps": 50000
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
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn test_ingest_event_unknown_vector() {
    let app = setup_app().await;

    // "unknown" is a valid AttackVector variant (deserializes) but matches
    // no playbook, so the event is accepted with status accepted_no_playbook.
    let event_json = r#"{
        "timestamp": "2026-01-16T14:00:00Z",
        "source": "test",
        "victim_ip": "203.0.113.10",
        "vector": "unknown",
        "pps": 50000
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
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "accepted_no_playbook");
    assert!(json["mitigation_id"].is_null());
}

#[tokio::test]
async fn test_openapi_creation_outcome_is_optional_and_manual_accepted_is_documented() {
    let app = setup_app().await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let document: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(document["paths"]["/v1/mitigations"]["post"]["responses"]["201"].is_object());
    assert!(document["paths"]["/v1/mitigations"]["post"]["responses"]["202"].is_object());
    assert!(document["paths"]["/v1/mitigations"]["post"]["responses"]["400"].is_object());
    let protocol =
        &document["components"]["schemas"]["CreateMitigationRequest"]["properties"]["protocol"];
    assert_eq!(protocol["example"], "icmpv6");
    let description = protocol["description"].as_str().unwrap();
    assert!(description.contains("IPv4 protocol 1"));
    assert!(description.contains("IPv6 protocol 58"));
    assert!(description.contains("address family"));
    assert_eq!(
        document["components"]["schemas"]["AnnouncementOutcome"]["enum"],
        serde_json::json!(["unconfirmed"])
    );
    for name in [
        "EventResponse",
        "MitigationResponse",
        "BatchEventResult",
        "AlertmanagerAlertResult",
        "WebhookEventResult",
    ] {
        let schema = &document["components"]["schemas"][name];
        assert!(
            schema["properties"]["announcement_outcome"].is_object(),
            "schema={name}"
        );
        if let Some(required) = schema["required"].as_array() {
            assert!(
                !required.iter().any(|field| field == "announcement_outcome"),
                "schema={name}"
            );
        }
    }
}

mod anonymous_auth {
    use super::*;
    use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
    use axum::Router;
    use axum_login::AuthnBackend;
    use prefixd::api::create_test_router_with_session_store;
    use prefixd::auth::{AuthBackend, Credentials};
    use prefixd::domain::OperatorRole;
    use std::io::Write;
    use std::sync::Mutex;
    use tower_sessions::{MemoryStore, SessionStore, session::Id};
    use tracing::instrument::WithSubscriber;

    const PASSWORD: &str = "anonymous-transition-password";

    fn router(mode: AuthMode, repo: Arc<MockRepository>, store: MemoryStore) -> Router {
        let mut settings = test_settings();
        // This fixture tests hybrid sessions, independently of host token variables.
        settings.http.auth.mode = if mode == AuthMode::Bearer {
            AuthMode::Credentials
        } else {
            mode
        };
        let mut state = AppState::new(
            settings,
            test_inventory(),
            test_playbooks(),
            repo,
            Arc::new(MockAnnouncer::new()),
            ".".into(),
        )
        .unwrap();
        if mode == AuthMode::Bearer {
            let state = Arc::get_mut(&mut state).expect("unshared test state");
            state.settings.http.auth.mode = mode;
            state.bearer_token = Some("session-control-token".into());
        }
        create_test_router_with_session_store(state, store)
    }

    async fn operator(repo: &MockRepository, username: &str) -> prefixd::domain::Operator {
        let salt = SaltString::encode_b64(b"anonymous-auth-test").unwrap();
        let hash = Argon2::default()
            .hash_password(PASSWORD.as_bytes(), &salt)
            .unwrap()
            .to_string();
        repo.create_operator(username, &hash, OperatorRole::Admin, None)
            .await
            .unwrap()
    }

    async fn request(
        app: &Router,
        method: &str,
        path: &str,
        cookie: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> axum::response::Response {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(cookie) = cookie {
            request = request.header("cookie", cookie);
        }
        let body = match body {
            Some(body) => {
                request = request.header("content-type", "application/json");
                Body::from(body.to_string())
            }
            None => Body::empty(),
        };
        app.clone()
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap()
    }

    async fn login(app: &Router, username: &str) -> String {
        let response = request(
            app,
            "POST",
            "/v1/auth/login",
            None,
            Some(serde_json::json!({"username":username,"password":PASSWORD})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    }

    mod credential_boundaries {
        use super::*;

        async fn public_body(
            response: axum::response::Response,
            expected: StatusCode,
            secrets: &[&str],
        ) -> String {
            assert_eq!(response.status(), expected);
            let body = axum::body::to_bytes(response.into_body(), 16_384)
                .await
                .unwrap();
            let text = String::from_utf8(body.to_vec()).unwrap();
            for secret in ["password_hash", "$argon2"]
                .into_iter()
                .chain(secrets.iter().copied())
            {
                assert!(
                    !text.contains(secret),
                    "credential response exposes a secret"
                );
            }
            text
        }

        #[tokio::test]
        async fn create_checks_username_bytes_ascii_policy_and_roles() {
            let repo = Arc::new(MockRepository::new());
            let admin = operator(&repo, "credential-create-admin").await;
            let app = router(AuthMode::Credentials, repo.clone(), MemoryStore::default());
            let cookie = login(&app, &admin.username).await;
            for (username, role, accepted) in [
                ("C".repeat(64), "operator", true),
                ("C".repeat(65), "operator", false),
                ("Az_09-".into(), "admin", true),
                ("credential-viewer".into(), "viewer", true),
                ("".into(), "operator", false),
                ("bad space".into(), "operator", false),
                ("bad/slash".into(), "operator", false),
                ("bad.dot".into(), "operator", false),
                ("badé".into(), "operator", false),
                ("bad\0name".into(), "operator", false),
                ("unknown-role".into(), "owner", false),
                ("empty-role".into(), "", false),
            ] {
                let response = request(
                    &app,
                    "POST",
                    "/v1/operators",
                    Some(&cookie),
                    Some(serde_json::json!({"username":username,"password":PASSWORD,"role":role})),
                )
                .await;
                let body = public_body(
                    response,
                    if accepted {
                        StatusCode::CREATED
                    } else {
                        StatusCode::BAD_REQUEST
                    },
                    &[PASSWORD, &admin.password_hash],
                )
                .await;
                let stored = repo.get_operator_by_username(&username).await.unwrap();
                assert_eq!(stored.is_some(), accepted);
                if let Some(stored) = stored {
                    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
                    assert_eq!(json.as_object().unwrap().len(), 6);
                    assert_eq!(json["operator_id"], stored.operator_id.to_string());
                    assert_eq!(json["username"], username);
                    assert_eq!(json["role"], role);
                    assert_eq!(json["created_by"], admin.username);
                    assert!(json["last_login_at"].is_null());
                    assert!(!body.contains(&stored.password_hash));
                }
            }
        }

        #[tokio::test]
        async fn create_password_boundaries_count_bytes_including_utf8() {
            let repo = Arc::new(MockRepository::new());
            let admin = operator(&repo, "credential-password-admin").await;
            let app = router(AuthMode::Credentials, repo.clone(), MemoryStore::default());
            let cookie = login(&app, &admin.username).await;
            for (index, (password, bytes, accepted)) in [
                ("Ab7!xyz".into(), 7, false),
                ("Ab8!wxyz".into(), 8, true),
                ("C9!".repeat(85) + "X", 256, true),
                ("C9!".repeat(85) + "XY", 257, false),
                ("é".repeat(3) + "!", 7, false),
                ("é".repeat(4), 8, true),
                ("é".repeat(128), 256, true),
                ("é".repeat(128) + "!", 257, false),
            ]
            .into_iter()
            .enumerate()
            {
                assert_eq!(password.len(), bytes);
                let username = format!("credential-create-byte-{index}");
                let response = request(&app, "POST", "/v1/operators", Some(&cookie), Some(
                    serde_json::json!({"username":username,"password":password,"role":"operator"})
                )).await;
                public_body(
                    response,
                    if accepted {
                        StatusCode::CREATED
                    } else {
                        StatusCode::BAD_REQUEST
                    },
                    &[&password, &admin.password_hash],
                )
                .await;
                let stored = repo.get_operator_by_username(&username).await.unwrap();
                assert_eq!(stored.is_some(), accepted);
                if let Some(stored) = stored {
                    let response = request(
                        &app,
                        "POST",
                        "/v1/auth/login",
                        None,
                        Some(serde_json::json!({"username":username,"password":password})),
                    )
                    .await;
                    let body = public_body(
                        response,
                        StatusCode::OK,
                        &[&password, &stored.password_hash],
                    )
                    .await;
                    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
                    assert_eq!(
                        json,
                        serde_json::json!({
                            "operator_id":stored.operator_id,"username":username,"role":"operator"
                        })
                    );
                }
            }
        }

        #[tokio::test]
        async fn login_validates_username_policy_and_password_bytes_without_create_minimum() {
            let repo = Arc::new(MockRepository::new());
            let seed = operator(&repo, "credential-login-seed").await;
            let app = router(AuthMode::Credentials, repo.clone(), MemoryStore::default());
            for (username, accepted) in [
                ("L".repeat(64), true),
                ("L".repeat(65), false),
                ("Login_09-".into(), true),
                ("".into(), false),
                ("login space".into(), false),
                ("login/slash".into(), false),
                ("login.dot".into(), false),
                ("loginé".into(), false),
                ("login\0name".into(), false),
            ] {
                let stored = repo
                    .create_operator(&username, &seed.password_hash, OperatorRole::Viewer, None)
                    .await
                    .unwrap();
                let response = request(
                    &app,
                    "POST",
                    "/v1/auth/login",
                    None,
                    Some(serde_json::json!({"username":username,"password":PASSWORD})),
                )
                .await;
                let body = public_body(
                    response,
                    if accepted {
                        StatusCode::OK
                    } else {
                        StatusCode::BAD_REQUEST
                    },
                    &[PASSWORD, &seed.password_hash],
                )
                .await;
                if accepted {
                    assert_eq!(
                        serde_json::from_str::<serde_json::Value>(&body).unwrap(),
                        serde_json::json!({
                            "operator_id":stored.operator_id,"username":username,"role":"viewer"
                        })
                    );
                }
                assert_eq!(
                    repo.get_operator_by_id(stored.operator_id)
                        .await
                        .unwrap()
                        .unwrap()
                        .password_hash,
                    stored.password_hash
                );
            }
            let salt = SaltString::encode_b64(b"credential-boundary-test").unwrap();
            for (index, (password, bytes, accepted)) in [
                (String::new(), 0, false),
                ("!".into(), 1, true),
                ("Ab7!xyz".into(), 7, true),
                ("L8!".repeat(85) + "X", 256, true),
                ("L8!".repeat(85) + "XY", 257, false),
                ("é".repeat(3) + "!", 7, true),
                ("é".repeat(128), 256, true),
                ("é".repeat(128) + "!", 257, false),
            ]
            .into_iter()
            .enumerate()
            {
                assert_eq!(password.len(), bytes);
                let hash = Argon2::default()
                    .hash_password(password.as_bytes(), &salt)
                    .unwrap()
                    .to_string();
                let username = format!("credential-login-byte-{index}");
                let stored = repo
                    .create_operator(&username, &hash, OperatorRole::Viewer, None)
                    .await
                    .unwrap();
                let response = request(
                    &app,
                    "POST",
                    "/v1/auth/login",
                    None,
                    Some(serde_json::json!({"username":username,"password":password})),
                )
                .await;
                // Exact successful fields exclude plaintext even for the one-byte password.
                let mut secrets = vec![hash.as_str()];
                if bytes > 1 {
                    secrets.push(password.as_str());
                }
                let body = public_body(
                    response,
                    if accepted {
                        StatusCode::OK
                    } else {
                        StatusCode::BAD_REQUEST
                    },
                    &secrets,
                )
                .await;
                if accepted {
                    assert_eq!(
                        serde_json::from_str::<serde_json::Value>(&body).unwrap(),
                        serde_json::json!({
                            "operator_id":stored.operator_id,"username":username,"role":"viewer"
                        })
                    );
                }
                assert_eq!(
                    repo.get_operator_by_id(stored.operator_id)
                        .await
                        .unwrap()
                        .unwrap()
                        .password_hash,
                    hash
                );
            }
        }

        #[tokio::test]
        async fn operator_management_requires_admin_and_prevents_self_deletion() {
            let repo = Arc::new(MockRepository::new());
            let admin = operator(&repo, "credential-management-admin").await;
            let app = router(AuthMode::Credentials, repo.clone(), MemoryStore::default());
            let admin_cookie = login(&app, &admin.username).await;
            let mut callers = vec![(None, StatusCode::UNAUTHORIZED)];
            for (username, role) in [
                ("credential-management-operator", OperatorRole::Operator),
                ("credential-management-viewer", OperatorRole::Viewer),
            ] {
                repo.create_operator(username, &admin.password_hash, role, None)
                    .await
                    .unwrap();
                callers.push((Some(login(&app, username).await), StatusCode::FORBIDDEN));
            }
            for (cookie, status) in callers {
                let response = request(&app, "POST", "/v1/operators", cookie.as_deref(), Some(
                    serde_json::json!({"username":"credential-denied-create","password":PASSWORD,"role":"admin"})
                )).await;
                public_body(response, status, &[PASSWORD, &admin.password_hash]).await;
                assert!(
                    repo.get_operator_by_username("credential-denied-create")
                        .await
                        .unwrap()
                        .is_none()
                );
                let response = request(
                    &app,
                    "DELETE",
                    &format!("/v1/operators/{}", admin.operator_id),
                    cookie.as_deref(),
                    None,
                )
                .await;
                public_body(response, status, &[&admin.password_hash]).await;
                let response = request(&app, "PUT", &format!("/v1/operators/{}/password", admin.operator_id), cookie.as_deref(), Some(
                    serde_json::json!({"current_password":PASSWORD,"new_password":"denied-password-marker"})
                )).await;
                public_body(
                    response,
                    status,
                    &[PASSWORD, "denied-password-marker", &admin.password_hash],
                )
                .await;
                assert_eq!(
                    repo.get_operator_by_id(admin.operator_id)
                        .await
                        .unwrap()
                        .unwrap()
                        .password_hash,
                    admin.password_hash
                );
            }
            let response = request(
                &app,
                "DELETE",
                &format!("/v1/operators/{}", admin.operator_id),
                Some(&admin_cookie),
                None,
            )
            .await;
            public_body(response, StatusCode::BAD_REQUEST, &[&admin.password_hash]).await;
            login(&app, &admin.username).await;
            let target = repo
                .get_operator_by_username("credential-management-viewer")
                .await
                .unwrap()
                .unwrap();
            let response = request(
                &app,
                "DELETE",
                &format!("/v1/operators/{}", target.operator_id),
                Some(&admin_cookie),
                None,
            )
            .await;
            assert!(
                public_body(response, StatusCode::NO_CONTENT, &[&target.password_hash])
                    .await
                    .is_empty()
            );
            assert!(
                repo.get_operator_by_id(target.operator_id)
                    .await
                    .unwrap()
                    .is_none()
            );
            let response = request(
                &app,
                "DELETE",
                &format!("/v1/operators/{}", target.operator_id),
                Some(&admin_cookie),
                None,
            )
            .await;
            public_body(response, StatusCode::NOT_FOUND, &[&target.password_hash]).await;
        }

        #[tokio::test]
        async fn self_password_changes_require_current_even_for_admin_and_preserve_rejections() {
            let repo = Arc::new(MockRepository::new());
            let seed = operator(&repo, "credential-self-seed").await;
            let app = router(AuthMode::Credentials, repo.clone(), MemoryStore::default());
            for (username, role) in [
                ("credential-self-viewer", OperatorRole::Viewer),
                ("credential-self-admin", OperatorRole::Admin),
            ] {
                let target = repo
                    .create_operator(username, &seed.password_hash, role.clone(), None)
                    .await
                    .unwrap();
                let cookie = login(&app, username).await;
                let path = format!("/v1/operators/{}/password", target.operator_id);
                for (current, new) in [
                    (None, "self-change-marker".to_string()),
                    (Some(""), "self-change-marker".to_string()),
                    (
                        Some("wrong-current-marker"),
                        "self-change-marker".to_string(),
                    ),
                    (Some(PASSWORD), "Ab7!xyz".to_string()),
                    (Some(PASSWORD), "S9!".repeat(85) + "XY"),
                    (Some(PASSWORD), "é".repeat(3) + "!"),
                    (Some(PASSWORD), "é".repeat(128) + "!"),
                ] {
                    let mut body = serde_json::json!({"new_password":new});
                    if let Some(current) = current {
                        body["current_password"] = current.into();
                    }
                    let response = request(&app, "PUT", &path, Some(&cookie), Some(body)).await;
                    public_body(
                        response,
                        StatusCode::BAD_REQUEST,
                        &[
                            PASSWORD,
                            &new,
                            &target.password_hash,
                            "wrong-current-marker",
                        ],
                    )
                    .await;
                    assert_eq!(
                        repo.get_operator_by_id(target.operator_id)
                            .await
                            .unwrap()
                            .unwrap()
                            .password_hash,
                        target.password_hash
                    );
                    login(&app, username).await;
                }
                let new = "é".repeat(4);
                assert_eq!(new.len(), 8);
                let response = request(
                    &app,
                    "PUT",
                    &path,
                    Some(&cookie),
                    Some(serde_json::json!({
                        "current_password":PASSWORD,"new_password":new
                    })),
                )
                .await;
                assert!(
                    public_body(
                        response,
                        StatusCode::NO_CONTENT,
                        &[PASSWORD, &new, &target.password_hash]
                    )
                    .await
                    .is_empty()
                );
                let changed = repo
                    .get_operator_by_id(target.operator_id)
                    .await
                    .unwrap()
                    .unwrap();
                assert_ne!(changed.password_hash, target.password_hash);
                for (password, status) in [
                    (PASSWORD, StatusCode::UNAUTHORIZED),
                    (new.as_str(), StatusCode::OK),
                ] {
                    let response = request(
                        &app,
                        "POST",
                        "/v1/auth/login",
                        None,
                        Some(serde_json::json!({"username":username,"password":password})),
                    )
                    .await;
                    let body = public_body(
                        response,
                        status,
                        &[
                            PASSWORD,
                            &new,
                            &target.password_hash,
                            &changed.password_hash,
                        ],
                    )
                    .await;
                    if status == StatusCode::OK {
                        assert_eq!(
                            serde_json::from_str::<serde_json::Value>(&body).unwrap(),
                            serde_json::json!({
                                "operator_id":target.operator_id,"username":username,"role":role.to_string()
                            })
                        );
                    }
                }
                let response = request(&app, "GET", "/v1/auth/me", Some(&cookie), None).await;
                public_body(
                    response,
                    StatusCode::UNAUTHORIZED,
                    &[&target.password_hash, &changed.password_hash],
                )
                .await;
            }
        }

        #[tokio::test]
        async fn other_user_password_changes_require_admin_and_missing_reset_is_not_found() {
            let repo = Arc::new(MockRepository::new());
            let admin = operator(&repo, "credential-reset-admin").await;
            let target = repo
                .create_operator(
                    "credential-reset-target",
                    &admin.password_hash,
                    OperatorRole::Operator,
                    None,
                )
                .await
                .unwrap();
            let app = router(AuthMode::Credentials, repo.clone(), MemoryStore::default());
            let path = format!("/v1/operators/{}/password", target.operator_id);
            for (username, role) in [
                ("credential-foreign-viewer", OperatorRole::Viewer),
                ("credential-foreign-operator", OperatorRole::Operator),
            ] {
                repo.create_operator(username, &admin.password_hash, role, None)
                    .await
                    .unwrap();
                let cookie = login(&app, username).await;
                let response = request(&app, "PUT", &path, Some(&cookie), Some(
                    serde_json::json!({"current_password":PASSWORD,"new_password":"foreign-change-marker"})
                )).await;
                public_body(
                    response,
                    StatusCode::FORBIDDEN,
                    &[PASSWORD, "foreign-change-marker", &target.password_hash],
                )
                .await;
                assert_eq!(
                    repo.get_operator_by_id(target.operator_id)
                        .await
                        .unwrap()
                        .unwrap()
                        .password_hash,
                    target.password_hash
                );
                login(&app, &target.username).await;
            }
            let new = "é".repeat(128);
            assert_eq!(new.len(), 256);
            let cookie = login(&app, &admin.username).await;
            let response = request(
                &app,
                "PUT",
                &path,
                Some(&cookie),
                Some(serde_json::json!({"new_password":new})),
            )
            .await;
            assert!(
                public_body(
                    response,
                    StatusCode::NO_CONTENT,
                    &[&new, &target.password_hash]
                )
                .await
                .is_empty()
            );
            let changed = repo
                .get_operator_by_id(target.operator_id)
                .await
                .unwrap()
                .unwrap();
            assert_ne!(changed.password_hash, target.password_hash);
            for (password, status) in [
                (PASSWORD, StatusCode::UNAUTHORIZED),
                (new.as_str(), StatusCode::OK),
            ] {
                let response = request(
                    &app,
                    "POST",
                    "/v1/auth/login",
                    None,
                    Some(serde_json::json!({"username":target.username,"password":password})),
                )
                .await;
                public_body(
                    response,
                    status,
                    &[
                        PASSWORD,
                        &new,
                        &target.password_hash,
                        &changed.password_hash,
                    ],
                )
                .await;
            }
            let response = request(
                &app,
                "PUT",
                &format!("/v1/operators/{}/password", uuid::Uuid::new_v4()),
                Some(&cookie),
                Some(serde_json::json!({"new_password":"missing-reset-marker"})),
            )
            .await;
            public_body(
                response,
                StatusCode::NOT_FOUND,
                &["missing-reset-marker", &changed.password_hash],
            )
            .await;
            assert_eq!(
                repo.get_operator_by_id(target.operator_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .password_hash,
                changed.password_hash
            );
            assert_eq!(
                repo.get_operator_by_id(admin.operator_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .password_hash,
                admin.password_hash
            );
        }
    }

    #[derive(Clone, Default)]
    struct TraceOutput(Arc<Mutex<Vec<u8>>>);

    impl Write for TraceOutput {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TraceOutput {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    impl TraceOutput {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
        fn clear(&self) {
            self.0.lock().unwrap().clear();
        }
        fn subscriber(&self) -> (tracing::Dispatch, tracing::Dispatch) {
            // Keep callsite registration independent of an uninstrumented test thread's default.
            let registration = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
            let capture = tracing::Dispatch::new(
                tracing_subscriber::fmt()
                    .json()
                    .without_time()
                    .with_max_level(tracing::Level::DEBUG)
                    .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
                    .with_writer(self.clone())
                    .finish(),
            );
            (capture, registration)
        }
    }

    #[test]
    fn uninstrumented_callsite_registration_preserves_capture() {
        const USER_ID: &str = "00000000-0000-4000-8000-000000000001";
        fn emit() {
            let span = tracing::info_span!("registration_control", user.id = tracing::field::Empty);
            span.record("user.id", USER_ID);
        }

        let output = TraceOutput::default();
        let (dispatch, _registration) = output.subscriber();
        let (registered, first_registration) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            assert!(tracing::dispatcher::get_default(|dispatch| {
                dispatch
                    .downcast_ref::<tracing::subscriber::NoSubscriber>()
                    .is_some()
            }));
            emit();
            registered.send(()).unwrap();
        });
        first_registration
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        worker.join().unwrap();
        assert!(output.text().is_empty());

        tracing::dispatcher::with_default(&dispatch, emit);
        assert!(
            output.text().contains(USER_ID),
            "registered synthetic span must retain captured user.id; output={}",
            output.text()
        );
        println!("uninstrumented registration followed by exact UUID capture passed");
    }

    #[tokio::test]
    async fn retained_credentials_are_anonymous_until_logout_deletes_the_shared_session() {
        let repo = Arc::new(MockRepository::new());
        let operator = operator(&repo, "mode-transition").await;
        let store = MemoryStore::default();
        let credentials = router(AuthMode::Credentials, repo.clone(), store.clone());
        let anonymous = router(AuthMode::None, repo.clone(), store.clone());
        let cookie = login(&credentials, &operator.username).await;
        let id: Id = cookie.split_once('=').unwrap().1.parse().unwrap();
        assert!(store.load(&id).await.unwrap().is_some());

        let output = TraceOutput::default();
        let (dispatch, _registration) = output.subscriber();
        let response = request(&credentials, "GET", "/v1/auth/me", Some(&cookie), None)
            .with_subscriber(dispatch.clone())
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["username"],
            operator.username
        );
        assert!(
            output.text().contains(&operator.operator_id.to_string()),
            "credential request must prove tracing capture is active"
        );
        output.clear();

        let response = request(&anonymous, "GET", "/v1/auth/me", Some(&cookie), None)
            .with_subscriber(dispatch.clone())
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(!response.headers().contains_key("set-cookie"));
        assert!(
            !output.text().contains(&operator.operator_id.to_string()),
            "anonymous requests must not record retained user.id"
        );
        // A mode change ignores the named session; explicit logout still owns deletion.
        assert!(store.load(&id).await.unwrap().is_some());

        let response = request(&anonymous, "POST", "/v1/mitigations", Some(&cookie), Some(serde_json::json!({
            "operator_id":"forged-admin", "reason":"anonymous intent", "victim_ip":"203.0.113.10",
            "protocol":"udp", "dst_ports":[53], "action":"discard", "ttl_seconds":120
        })))
            .with_subscriber(dispatch.clone())
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let mitigation_id =
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["mitigation_id"]
                .as_str()
                .unwrap()
                .to_owned();
        let response = request(
            &anonymous,
            "POST",
            &format!("/v1/mitigations/{mitigation_id}/withdraw"),
            Some(&cookie),
            Some(serde_json::json!({
                "operator_id":"forged-admin", "reason":"anonymous withdrawal"
            })),
        )
        .with_subscriber(dispatch.clone())
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let audit = repo
            .list_audit(&prefixd::db::ListParams {
                limit: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        let withdrawals: Vec<_> = audit
            .iter()
            .filter(|entry| entry.action == "withdraw")
            .collect();
        assert_eq!(withdrawals.len(), 1);
        assert_eq!(withdrawals[0].actor_id.as_deref(), Some("anonymous"));
        assert_eq!(
            withdrawals[0].details["reason"],
            "anonymous: anonymous withdrawal"
        );
        assert!(!output.text().contains(&operator.operator_id.to_string()));
        assert!(!output.text().contains("forged-admin"));

        let response = request(&anonymous, "POST", "/v1/auth/logout", Some(&cookie), None)
            .with_subscriber(dispatch)
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let removal = response.headers()["set-cookie"].to_str().unwrap();
        let cookie_name = cookie.split_once('=').unwrap().0;
        assert!(
            removal.starts_with(&format!("{cookie_name}=;")),
            "{removal}"
        );
        assert!(
            store.load(&id).await.unwrap().is_none(),
            "logout must delete the shared record, not just expire a browser cookie"
        );
        assert_eq!(
            request(&credentials, "GET", "/v1/auth/me", Some(&cookie), None)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert!(!output.text().contains(&operator.operator_id.to_string()));
    }

    #[tokio::test]
    async fn anonymous_login_is_forbidden_before_validation_or_throttling() {
        let repo = Arc::new(MockRepository::new());
        let operator = operator(&repo, "disabled-login").await;
        let store = MemoryStore::default();
        let anonymous = router(AuthMode::None, repo.clone(), store.clone());
        for password in ["", "wrong", PASSWORD, "wrong", "wrong", "wrong", "wrong"] {
            let response = request(
                &anonymous,
                "POST",
                "/v1/auth/login",
                None,
                Some(serde_json::json!({
                    "username":operator.username,"password":password
                })),
            )
            .await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert!(!response.headers().contains_key("set-cookie"));
        }
        assert!(
            repo.get_operator_by_id(operator.operator_id)
                .await
                .unwrap()
                .unwrap()
                .last_login_at
                .is_none()
        );
        let backend = AuthBackend::new(repo.clone(), AuthMode::None);
        assert!(
            backend
                .get_user(&operator.operator_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            backend
                .authenticate(Credentials {
                    username: operator.username.clone(),
                    password: PASSWORD.into()
                })
                .await
                .unwrap()
                .is_none()
        );
        // Disabled-mode attempts must not exhaust the same username's real login throttle.
        let credentials = router(AuthMode::Credentials, repo, store);
        let cookie = login(&credentials, &operator.username).await;
        assert_eq!(
            request(&credentials, "GET", "/v1/auth/me", Some(&cookie), None)
                .await
                .status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn credential_and_bearer_hybrid_sessions_keep_named_identity_and_logout() {
        for (mode, username) in [
            (AuthMode::Credentials, "credentials-control"),
            (AuthMode::Bearer, "bearer-session-control"),
        ] {
            let repo = Arc::new(MockRepository::new());
            let operator = operator(&repo, username).await;
            let store = MemoryStore::default();
            let app = router(mode, repo, store.clone());
            assert_eq!(
                request(&app, "GET", "/v1/auth/me", None, None)
                    .await
                    .status(),
                StatusCode::UNAUTHORIZED
            );
            let cookie = login(&app, username).await;
            let id: Id = cookie.split_once('=').unwrap().1.parse().unwrap();
            let response = request(&app, "GET", "/v1/auth/me", Some(&cookie), None).await;
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap()["operator_id"],
                operator.operator_id.to_string()
            );
            assert_eq!(
                request(&app, "GET", "/v1/mitigations", Some(&cookie), None)
                    .await
                    .status(),
                StatusCode::OK
            );
            assert_eq!(
                request(&app, "POST", "/v1/auth/logout", Some(&cookie), None)
                    .await
                    .status(),
                StatusCode::OK
            );
            assert!(store.load(&id).await.unwrap().is_none());
            assert_eq!(
                request(&app, "GET", "/v1/auth/me", Some(&cookie), None)
                    .await
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }
    }

    async fn websocket_status(
        app: Router,
        cookie: Option<&str>,
        dispatch: tracing::Dispatch,
    ) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        // axum spawns connection tasks; attach the subscriber inside each request.
        let app = app.layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                next.run(request).with_subscriber(dispatch.clone())
            },
        ));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let result = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
            let cookie = cookie.map(|value| format!("Cookie: {value}\r\n")).unwrap_or_default();
            stream.write_all(format!("GET /v1/ws/feed HTTP/1.1\r\nHost: {address}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n{cookie}\r\n").as_bytes()).await.unwrap();
            let mut bytes = Vec::new();
            while !bytes.ends_with(b"\r\n\r\n") {
                let byte = stream.read_u8().await.unwrap();
                bytes.push(byte);
                assert!(bytes.len() < 16_384, "bounded handshake headers");
            }
            String::from_utf8(bytes).unwrap()
        }).await;
        server.abort();
        let _ = server.await;
        result.unwrap()
    }

    #[tokio::test]
    async fn websocket_uses_anonymous_identity_for_a_retained_named_cookie() {
        let repo = Arc::new(MockRepository::new());
        let operator = operator(&repo, "websocket-control").await;
        let store = MemoryStore::default();
        let credentials = router(AuthMode::Credentials, repo.clone(), store.clone());
        let cookie = login(&credentials, &operator.username).await;
        let named_output = TraceOutput::default();
        let (named_dispatch, _named_registration) = named_output.subscriber();
        assert!(
            websocket_status(credentials.clone(), None, named_dispatch.clone())
                .await
                .starts_with("HTTP/1.1 401")
        );
        assert!(
            websocket_status(credentials, Some(&cookie), named_dispatch)
                .await
                .starts_with("HTTP/1.1 101")
        );
        assert!(
            named_output.text().contains("websocket-control"),
            "named WebSocket positive control"
        );
        let output = TraceOutput::default();
        let (dispatch, _registration) = output.subscriber();
        let anonymous = router(AuthMode::None, repo, store);
        assert!(
            websocket_status(anonymous.clone(), Some(&cookie), dispatch.clone())
                .await
                .starts_with("HTTP/1.1 101")
        );
        assert!(
            websocket_status(anonymous, None, dispatch)
                .await
                .starts_with("HTTP/1.1 101")
        );
        let traces = output.text();
        assert!(traces.contains("WebSocket connection established"));
        assert!(traces.contains("\"username\":\"anonymous\""));
        assert!(!traces.contains(&operator.username));
        assert!(!traces.contains(&operator.operator_id.to_string()));
    }

    #[tokio::test]
    async fn openapi_declares_disabled_login_forbidden() {
        let app = router(
            AuthMode::None,
            Arc::new(MockRepository::new()),
            MemoryStore::default(),
        );
        let response = request(&app, "GET", "/openapi.json", None, None).await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let spec: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(spec["paths"]["/v1/auth/login"]["post"]["responses"]["403"].is_object());
    }
}

#[tokio::test]
async fn test_public_list_cursor_mock_tuple_order_and_filters() {
    use chrono::{DateTime, Duration, SecondsFormat, Utc};
    use prefixd::correlation::engine::{CorrelationEngine, SignalGroupStatus};
    use prefixd::domain::{AttackEvent, AttackEventInput};
    use prefixd::observability::{ActorType, AuditEntry};
    use std::collections::BTreeSet;
    use uuid::Uuid;

    let (app, repo) = setup_app_correlation_with_repo(1, 0.5).await;
    let timestamp: DateTime<Utc> = "2026-10-18T12:00:00.123456789Z".parse().unwrap();
    for id in [7_u128, 1, 8, 5, 9, 2, 6, 3, 4, 10, 11, 12, 13] {
        let position = match id {
            8 => timestamp + Duration::nanoseconds(1),
            9 => timestamp - Duration::nanoseconds(1),
            10 => timestamp - Duration::seconds(2),
            11 => timestamp + Duration::seconds(2),
            _ => timestamp,
        };
        if id <= 11 {
            let mut event = AttackEvent::from_input(AttackEventInput {
                event_id: None,
                timestamp: position,
                source: "cursor".into(),
                victim_ip: "203.0.113.10".into(),
                vector: AttackVector::UdpFlood,
                bps: None,
                pps: None,
                top_dst_ports: None,
                confidence: None,
                action: "ban".into(),
                raw_details: None,
            });
            event.event_id = Uuid::from_u128(id);
            event.ingested_at = position;
            repo.insert_event(&event).await.unwrap();
            let mut entry = AuditEntry::new(
                ActorType::System,
                None,
                "cursor",
                None,
                None,
                serde_json::json!({}),
            );
            entry.audit_id = Uuid::from_u128(id);
            entry.timestamp = position;
            repo.insert_audit(&entry).await.unwrap();
        }
        let mut group = CorrelationEngine::create_group(
            &format!("203.0.113.{id}"),
            if id == 12 { "syn_flood" } else { "udp_flood" },
            3600,
        );
        group.group_id = Uuid::from_u128(id);
        group.created_at = position;
        if id == 13 {
            group.status = SignalGroupStatus::Expired;
        }
        repo.insert_signal_group(&group).await.unwrap();
    }
    let start = (timestamp - Duration::seconds(1)).to_rfc3339_opts(SecondsFormat::Nanos, true);
    let end = (timestamp + Duration::seconds(2)).to_rfc3339_opts(SecondsFormat::Nanos, true);
    for (endpoint, rows_key, id_key, prefix) in [
        ("events", "events", "event_id", "e1."),
        ("audit", "entries", "audit_id", "a1."),
        ("signal-groups", "groups", "group_id", "s1."),
    ] {
        let mut cursor = None;
        let mut ordered = Vec::new();
        let mut unique = BTreeSet::new();
        for expected_count in [2, 2, 2, 2, 1] {
            let mut uri = format!("/v1/{endpoint}?limit=2&start={start}&end={end}");
            if endpoint == "signal-groups" {
                uri.push_str("&status=open&vector=udp_flood");
            }
            if let Some(value) = &cursor {
                uri.push_str(&format!("&cursor={value}"));
            }
            let response = app
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["count"], expected_count, "{endpoint}");
            for row in json[rows_key].as_array().unwrap() {
                let id = Uuid::parse_str(row[id_key].as_str().unwrap()).unwrap();
                assert!(unique.insert(id), "{endpoint} duplicate");
                ordered.push(id);
            }
            cursor = json["next_cursor"].as_str().map(str::to_owned);
            assert_eq!(json["has_more"], cursor.is_some());
            if let Some(value) = &cursor {
                assert!(value.starts_with(prefix));
            }
        }
        assert_eq!(ordered, [8, 7, 6, 5, 4, 3, 2, 1, 9].map(Uuid::from_u128));
        assert!(cursor.is_none());
    }
}

mod list_filter_validation {
    use super::*;
    use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
    use axum::Router;
    use chrono::{DateTime, Duration, Utc};
    use prefixd::correlation::{CorrelationEngine, SignalGroupStatus};
    use prefixd::domain::{
        ActionParams, ActionType, AttackEvent, AttackEventInput, MatchCriteria, Mitigation,
        MitigationIntent, MitigationStatus, OperatorRole,
    };
    use prefixd::observability::{ActorType, AuditEntry};
    use serde_json::{Value, json};
    use uuid::Uuid;

    const ENDPOINTS: [(&str, &str, &str); 4] = [
        ("events", "events", "event_id"),
        ("audit", "entries", "audit_id"),
        ("mitigations", "mitigations", "mitigation_id"),
        ("signal-groups", "groups", "group_id"),
    ];

    fn router(repo: Arc<dyn RepositoryTrait>, mode: AuthMode) -> Router {
        let mut settings = test_settings();
        settings.http.auth.mode = if mode == AuthMode::Bearer {
            AuthMode::None
        } else {
            mode
        };
        let mut state = AppState::new(
            settings,
            test_inventory(),
            test_playbooks(),
            repo,
            Arc::new(MockAnnouncer::new()),
            ".".into(),
        )
        .unwrap();
        if mode == AuthMode::Bearer {
            let state = Arc::get_mut(&mut state).unwrap();
            state.settings.http.auth.mode = mode;
            state.bearer_token = Some("list-filter-token".into());
        }
        create_test_router(state)
    }

    async fn get(
        app: &Router,
        path: &str,
        header: Option<(&str, &str)>,
    ) -> axum::response::Response {
        let mut request = Request::builder().uri(path);
        if let Some((name, value)) = header {
            request = request.header(name, value);
        }
        app.clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn body(response: axum::response::Response) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn assert_invalid(response: axum::response::Response, field: &str, path: &str) {
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        let json = body(response).await;
        let message = json["error"].as_str().expect("structured error");
        assert!(message.starts_with("invalid request:"), "{path}: {json}");
        assert!(
            message.contains(&format!("invalid {field} filter")),
            "{path}: {json}"
        );
        assert_eq!(json.as_object().unwrap().len(), 1);
    }

    fn mitigation(id: u128, at: DateTime<Utc>, status: MitigationStatus) -> Mitigation {
        let ip = format!("203.0.113.{}", id + 10);
        let mut row = Mitigation::from_intent(
            MitigationIntent {
                event_id: Uuid::from_u128(id),
                customer_id: None,
                service_id: None,
                pop: "iad1".into(),
                match_criteria: MatchCriteria {
                    dst_prefix: format!("{ip}/32"),
                    protocol: Some(17),
                    dst_ports: vec![53],
                    ..Default::default()
                },
                action_type: ActionType::Discard,
                action_params: ActionParams::default(),
                ttl_seconds: 300,
                reason: "filter fixture".into(),
            },
            ip,
            AttackVector::UdpFlood,
        );
        row.mitigation_id = Uuid::from_u128(id);
        row.created_at = at;
        row.status = status;
        row
    }

    async fn dated_fixture() -> (Router, DateTime<Utc>) {
        let repo = Arc::new(MockRepository::new());
        let timestamp: DateTime<Utc> = "2026-10-18T12:00:00.123456789Z".parse().unwrap();
        for (id, delta) in [(1, -1), (2, 0), (3, 1)] {
            let at = timestamp + Duration::seconds(delta);
            let mut event = AttackEvent::from_input(AttackEventInput {
                event_id: None,
                timestamp: at,
                source: "filters".into(),
                victim_ip: "203.0.113.10".into(),
                vector: AttackVector::UdpFlood,
                bps: None,
                pps: None,
                top_dst_ports: None,
                confidence: None,
                action: "ban".into(),
                raw_details: None,
            });
            event.event_id = Uuid::from_u128(id);
            event.ingested_at = at;
            repo.insert_event(&event).await.unwrap();
            let mut entry =
                AuditEntry::new(ActorType::System, None, "filters", None, None, json!({}));
            entry.audit_id = Uuid::from_u128(id);
            entry.timestamp = at;
            repo.insert_audit(&entry).await.unwrap();
            repo.insert_mitigation(&mitigation(id, at, MitigationStatus::Active))
                .await
                .unwrap();
            let mut group = CorrelationEngine::create_group(
                &format!("203.0.113.{}", id + 10),
                "udp_flood",
                300,
            );
            group.group_id = Uuid::from_u128(id);
            group.created_at = at;
            repo.insert_signal_group(&group).await.unwrap();
        }
        (router(repo, AuthMode::None), timestamp)
    }

    #[tokio::test]
    async fn dates_preserve_omission_offsets_and_exact_boundaries() {
        let (app, at) = dated_fixture().await;
        let start = urlencoding::encode(&at.to_rfc3339()).into_owned();
        let end = urlencoding::encode(&(at + Duration::seconds(1)).to_rfc3339()).into_owned();
        let offset_start = urlencoding::encode("2026-10-18T17:30:00.123456789+05:30").into_owned();
        let offset_end = urlencoding::encode("2026-10-18T08:00:01.123456789-04:00").into_owned();
        let relaxed_start = urlencoding::encode("2026-10-18 12:00:00.123456789+0000").into_owned();
        for (endpoint, rows, id_key) in ENDPOINTS {
            for (query, expected) in [
                (String::new(), vec![3, 2, 1]),
                (format!("start={start}"), vec![3, 2]),
                (format!("end={start}"), vec![1]),
                (format!("start={start}&end={end}"), vec![2]),
                (format!("start={offset_start}"), vec![3, 2]),
                (format!("end={offset_end}"), vec![2, 1]),
                (format!("start={offset_start}&end={offset_end}"), vec![2]),
                (format!("start={relaxed_start}"), vec![3, 2]),
                (format!("start={start}&end={start}"), vec![]),
                (format!("start={end}&end={start}"), vec![]),
            ] {
                let path = format!("/v1/{endpoint}?{query}");
                let response = get(&app, &path, None).await;
                assert_eq!(response.status(), StatusCode::OK, "{path}");
                let json = body(response).await;
                let ids: Vec<_> = json[rows]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|row| Uuid::parse_str(row[id_key].as_str().unwrap()).unwrap())
                    .collect();
                assert_eq!(
                    ids,
                    expected
                        .iter()
                        .copied()
                        .map(Uuid::from_u128)
                        .collect::<Vec<_>>(),
                    "{path}"
                );
                assert_eq!(json["count"], expected.len(), "{path}");
                assert_eq!(json["has_more"], false);
                assert!(json["next_cursor"].is_null());
            }
        }
        for path in [
            "/v1/signal-groups?vector=unknown",
            "/v1/mitigations?pop=unknown",
        ] {
            let response = get(&app, path, None).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(body(response).await["count"], 0, "{path}");
        }
    }

    #[tokio::test]
    async fn statuses_preserve_each_value_and_valid_duplicates() {
        let repo = Arc::new(MockRepository::new());
        let at: DateTime<Utc> = "2026-10-18T12:00:00Z".parse().unwrap();
        let statuses = [
            MitigationStatus::Pending,
            MitigationStatus::Active,
            MitigationStatus::Escalated,
            MitigationStatus::Expired,
            MitigationStatus::Withdrawn,
            MitigationStatus::Rejected,
        ];
        for (index, status) in statuses.iter().copied().enumerate() {
            repo.insert_mitigation(&mitigation(index as u128 + 1, at, status))
                .await
                .unwrap();
        }
        for (index, status) in [
            SignalGroupStatus::Open,
            SignalGroupStatus::Resolved,
            SignalGroupStatus::Expired,
        ]
        .iter()
        .copied()
        .enumerate()
        {
            let mut group = CorrelationEngine::create_group(
                &format!("203.0.113.{}", index + 10),
                "udp_flood",
                300,
            );
            group.group_id = Uuid::from_u128(index as u128 + 1);
            group.created_at = at;
            group.status = status;
            repo.insert_signal_group(&group).await.unwrap();
        }
        let app = router(repo, AuthMode::None);
        for (endpoint, count) in [("mitigations", 6), ("signal-groups", 3)] {
            let response = get(&app, &format!("/v1/{endpoint}"), None).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(body(response).await["count"], count);
        }
        for (index, status) in statuses.iter().enumerate() {
            let response = get(&app, &format!("/v1/mitigations?status={status}"), None).await;
            assert_eq!(response.status(), StatusCode::OK);
            let json = body(response).await;
            assert_eq!(json["count"], 1, "{status}");
            assert_eq!(
                json["mitigations"][0]["mitigation_id"],
                Uuid::from_u128(index as u128 + 1).to_string()
            );
        }
        for (status, expected) in [
            ("active,escalated", vec![3, 2]),
            ("active,active", vec![2]),
            ("pending,active,pending", vec![2, 1]),
        ] {
            let response = get(
                &app,
                &format!("/v1/mitigations?status={}", urlencoding::encode(status)),
                None,
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            let json = body(response).await;
            let ids: Vec<_> = json["mitigations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| Uuid::parse_str(row["mitigation_id"].as_str().unwrap()).unwrap())
                .collect();
            assert_eq!(
                ids,
                expected
                    .into_iter()
                    .map(Uuid::from_u128)
                    .collect::<Vec<_>>(),
                "{status}"
            );
        }
        for status in ["open", "resolved", "expired"] {
            let response = get(&app, &format!("/v1/signal-groups?status={status}"), None).await;
            assert_eq!(response.status(), StatusCode::OK);
            let json = body(response).await;
            assert_eq!(json["count"], 1);
            assert_eq!(json["groups"][0]["status"], status);
        }
    }

    async fn unavailable_router() -> Router {
        // Every real list method fails on this closed pool; no network or database is needed.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .unwrap();
        pool.close().await;
        router(Arc::new(prefixd::db::Repository::new(pool)), AuthMode::None)
    }

    #[tokio::test]
    async fn invalid_dates_reject_before_repository_listing() {
        let app = unavailable_router().await;
        for (endpoint, _, _) in ENDPOINTS {
            let response = get(&app, &format!("/v1/{endpoint}"), None).await;
            assert_eq!(
                response.status(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "{endpoint}: unavailable-list positive control"
            );
            for field in ["start", "end"] {
                for value in [
                    "",
                    " ",
                    "not-a-date",
                    "2026-10-18",
                    "2026-13-01T00:00:00Z",
                    "2026-02-30T00:00:00Z",
                    "2026-10-18T12:00:00",
                    "0",
                ] {
                    let path = format!("/v1/{endpoint}?{field}={}", urlencoding::encode(value));
                    assert_invalid(get(&app, &path, None).await, field, &path).await;
                }
            }
            for (query, field) in [
                ("start=invalid&end=2026-10-18T12:00:00Z", "start"),
                ("start=2026-10-18T12:00:00Z&end=invalid", "end"),
            ] {
                let path = format!("/v1/{endpoint}?{query}");
                assert_invalid(get(&app, &path, None).await, field, &path).await;
            }
        }
    }

    #[tokio::test]
    async fn invalid_statuses_reject_before_repository_listing() {
        let app = unavailable_router().await;
        for (endpoint, values) in [
            (
                "mitigations",
                vec![
                    "",
                    " ",
                    ",",
                    "unknown",
                    "ACTIVE",
                    " active",
                    "active ",
                    ",active",
                    "active,",
                    "active,,escalated",
                    "active,unknown",
                    "unknown,active",
                    "active, active",
                    "active,\tactive",
                ],
            ),
            (
                "signal-groups",
                vec![
                    "",
                    "unknown",
                    "OPEN",
                    " open",
                    "open ",
                    "open,resolved",
                    "open,open",
                    ",open",
                    "open,",
                ],
            ),
        ] {
            let status = if endpoint == "mitigations" {
                "active"
            } else {
                "open"
            };
            let response = get(&app, &format!("/v1/{endpoint}?status={status}"), None).await;
            assert_eq!(
                response.status(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "{endpoint}: valid-status unavailable-list control"
            );
            for value in values {
                let path = format!("/v1/{endpoint}?status={}", urlencoding::encode(value));
                assert_invalid(get(&app, &path, None).await, "status", &path).await;
            }
        }
    }

    #[tokio::test]
    async fn authentication_and_audit_role_precede_filter_validation() {
        let app = router(Arc::new(MockRepository::new()), AuthMode::Bearer);
        for (endpoint, _, _) in ENDPOINTS {
            let mut queries = vec!["start=invalid", "end="];
            if endpoint == "mitigations" || endpoint == "signal-groups" {
                queries.push("status=unknown");
            }
            for query in queries {
                let path = format!("/v1/{endpoint}?{query}");
                assert_eq!(
                    get(&app, &path, None).await.status(),
                    StatusCode::UNAUTHORIZED,
                    "{path}"
                );
                let field = query.split('=').next().unwrap();
                assert_invalid(
                    get(
                        &app,
                        &path,
                        Some(("authorization", "Bearer list-filter-token")),
                    )
                    .await,
                    field,
                    &path,
                )
                .await;
            }
        }

        let repo = Arc::new(MockRepository::new());
        let password = "filter-validation-password";
        let hash = Argon2::default()
            .hash_password(
                password.as_bytes(),
                &SaltString::encode_b64(b"list-filter-test").unwrap(),
            )
            .unwrap()
            .to_string();
        repo.create_operator("filter-viewer", &hash, OperatorRole::Viewer, None)
            .await
            .unwrap();
        let viewer = router(repo, AuthMode::Credentials);
        let login = viewer
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"username":"filter-viewer", "password":password}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::OK);
        let cookie = login.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        for (endpoint, _, _) in ENDPOINTS {
            let path = format!("/v1/{endpoint}?start=invalid");
            let response = get(&viewer, &path, Some(("cookie", &cookie))).await;
            if endpoint == "audit" {
                assert_eq!(response.status(), StatusCode::FORBIDDEN);
            } else {
                assert_invalid(response, "start", &path).await;
            }
        }
    }

    #[tokio::test]
    async fn openapi_documents_invalid_optional_filters() {
        let app = router(Arc::new(MockRepository::new()), AuthMode::None);
        let response = get(&app, "/openapi.json", None).await;
        assert_eq!(response.status(), StatusCode::OK);
        let spec = body(response).await;
        for (endpoint, _, _) in ENDPOINTS {
            let operation = &spec["paths"][format!("/v1/{endpoint}")]["get"];
            assert_eq!(
                operation["responses"]["400"]["content"]["application/json"]["schema"]["$ref"],
                "#/components/schemas/ErrorResponse"
            );
            for name in ["start", "end"] {
                let parameter = operation["parameters"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|p| p["name"] == name)
                    .unwrap();
                let description = parameter["description"].as_str().unwrap();
                assert!(description.contains("RFC3339") && description.contains("invalid"));
            }
        }
    }
}

async fn confidence_test_app() -> (axum::Router, Arc<AppState>) {
    use prefixd::correlation::{MatchDimension, SourceConfig, SourceMode};
    let mut settings = test_settings_with_correlation(true, 1, 0.5);
    settings.mode = prefixd::config::OperationMode::Enforced;
    settings.correlation.sources.insert(
        "confidence-corrob".into(),
        SourceConfig {
            mode: SourceMode::Corroborating,
            match_dimensions: vec![MatchDimension::Pop],
            ..Default::default()
        },
    );
    let state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        Arc::new(MockRepository::new()),
        Arc::new(MockAnnouncer::new()),
        ".".into(),
    )
    .unwrap();
    state.correlation_config.write().await.webhook_adapters =
        vec![basic_webhook_adapter("confidence")];
    (create_test_router(state.clone()), state)
}

async fn confidence_state_snapshot(state: &AppState) -> serde_json::Value {
    let params = prefixd::db::ListParams {
        limit: 100,
        ..Default::default()
    };
    serde_json::json!({
        "events": state.repo.list_events(&params).await.unwrap(),
        "groups": state.repo.list_signal_groups(&Default::default(), &params).await.unwrap(),
        "cache": state.repo.list_cached_corroborators(chrono::Utc::now(), 100, None).await.unwrap(),
        "mitigations": state.repo.list_mitigations(None, None, None, None,
            &prefixd::db::MitigationListParams { limit: 100, ..Default::default() }).await.unwrap(),
        "rules": state.announcer.reader().unwrap().list_active().await.unwrap(),
    })
}

fn confidence_event(id: &str, value: &str, action: &str) -> String {
    format!(
        r#"{{"event_id":"{id}","timestamp":"2026-10-18T00:00:00Z","source":"detector_a","victim_ip":"203.0.113.10","vector":"udp_flood","pps":50000,"top_dst_ports":[53],"confidence":{value},"action":"{action}","raw_details":{{"secret":"private-confidence-payload"}}}}"#
    )
}

async fn post_confidence_json(
    app: &axum::Router,
    path: &str,
    body: String,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn confidence_http_rejections_preserve_state_and_same_id_retry() {
    let (app, state) = confidence_test_app().await;
    for (index, value) in ["-0.0000001", "1.0000001", "1e100"].iter().enumerate() {
        let id = format!("confidence-{index}");
        let before = confidence_state_snapshot(&state).await;
        let (status, error) =
            post_confidence_json(&app, "/v1/events", confidence_event(&id, value, "ban")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{value}: {error}");
        assert!(error.to_string().contains("confidence must be finite"));
        assert!(!error.to_string().contains("private-confidence-payload"));
        assert_eq!(confidence_state_snapshot(&state).await, before);
        let (status, response) =
            post_confidence_json(&app, "/v1/events", confidence_event(&id, "0.9", "ban")).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{response}");
        // The original active rule must survive an invalid unban with the same ID.
        let before = confidence_state_snapshot(&state).await;
        let (status, _) =
            post_confidence_json(&app, "/v1/events", confidence_event(&id, value, "unban")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(confidence_state_snapshot(&state).await, before);
    }
    assert!(
        !state
            .announcer
            .reader()
            .unwrap()
            .list_active()
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn confidence_optional_boundaries_and_mixed_batch_keep_existing_envelopes() {
    let (app, state) = confidence_test_app().await;
    for (index, value) in ["null", "0", "-0.0", "1"].iter().enumerate() {
        let (status, result) = post_confidence_json(
            &app,
            "/v1/events",
            confidence_event(&format!("boundary-{index}"), value, "ban"),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{value}: {result}");
    }
    let body = format!(
        r#"{{"events":[{},{},{}]}}"#,
        confidence_event("batch-invalid", "1e100", "ban"),
        confidence_event("batch-valid", "1", "ban"),
        confidence_event("batch-invalid", "0.9", "ban")
    );
    let (status, result) = post_confidence_json(&app, "/v1/events/batch", body).await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    assert_eq!(result["accepted"], 2);
    assert_eq!(result["rejected"], 1);
    assert_eq!(result["results"][0]["status"], "rejected");
    assert!(
        result["results"][0]["error"]
            .as_str()
            .unwrap()
            .contains("confidence must be finite")
    );
    assert!(
        state
            .repo
            .find_ban_event_by_external_id("detector_a", "batch-invalid")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn confidence_corroborator_rejections_precede_mutations() {
    let (app, state) = confidence_test_app().await;
    let (status, _) = post_confidence_json(
        &app,
        "/v1/events",
        confidence_event("open-primary", "0.2", "ban"),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(state.repo.count_open_groups().await.unwrap(), 1);
    let (status, _) = post_confidence_json(
        &app,
        "/v1/signals/corroborator",
        r#"{"source":"confidence-corrob","pop":"no-match","confidence":0.5}"#.into(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        state
            .repo
            .count_cached_corroborators(chrono::Utc::now())
            .await
            .unwrap(),
        1
    );
    for value in ["1e100", "-0.1", "1.1"] {
        let before = confidence_state_snapshot(&state).await;
        let body = format!(
            r#"{{"source":"confidence-corrob","pop":"test1","confidence":{value},"raw_details":{{"secret":"private-confidence-payload"}}}}"#
        );
        let (status, result) = post_confidence_json(&app, "/v1/signals/corroborator", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(result.to_string().contains("confidence must be finite"));
        assert!(!result.to_string().contains("private-confidence-payload"));
        assert_eq!(confidence_state_snapshot(&state).await, before);
    }
    for value in ["null", "0", "-0.0", "1"] {
        let body =
            format!(r#"{{"source":"confidence-corrob","pop":"no-match","confidence":{value}}}"#);
        let (status, result) = post_confidence_json(&app, "/v1/signals/corroborator", body).await;
        assert_eq!(status, StatusCode::OK, "{result}");
        assert_eq!(result["status"], "cached");
    }
}

#[tokio::test]
async fn confidence_webhook_preserves_normalization_before_shared_validation() {
    let (app, state) = confidence_test_app().await;
    state.correlation_config.write().await.webhook_adapters[0].confidence_scale = Some(100.0);
    for (index, (value, expected)) in [("1e100", 1.0), ("-10", 0.0), ("75", 0.75), ("200", 1.0)]
        .iter()
        .enumerate()
    {
        let id = format!("normalized-{index}");
        let body = format!(
            r#"{{"id":"{id}","ip":"203.0.113.10","vector":"udp_flood","pps":50000,"score":{value}}}"#
        );
        let (status, result) =
            post_confidence_json(&app, "/v1/signals/webhook/confidence", body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(result["processed"], 1, "{result}");
        assert_eq!(result["failed"], 0);
        let event = state
            .repo
            .find_ban_event_by_external_id("confidence", &id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(event.confidence, Some(*expected));
    }
}

mod reason_and_bulk_validation {
    use super::*;
    use axum::Router;
    use prefixd::db::{ListParams, MitigationListParams};
    use prefixd::domain::{
        ActionParams, ActionType, FlowSpecRule, MatchCriteria, Mitigation, MitigationIntent,
        MitigationStatus, mitigation_rule,
    };
    use prefixd::observability::ActorType;
    use serde_json::{Value, json};
    use uuid::Uuid;

    const OPERATIONS: [&str; 4] = ["manual", "single", "bulk", "safelist"];
    const TOKEN: &str = "reason-bulk-validation-token";

    struct Fixture {
        app: Router,
        repo: Arc<MockRepository>,
        speaker: Arc<MockAnnouncer>,
    }

    impl Fixture {
        fn new(mode: AuthMode) -> Self {
            let repo = Arc::new(MockRepository::new());
            let speaker = Arc::new(MockAnnouncer::new());
            let mut settings = test_settings();
            settings.mode = prefixd::config::OperationMode::Enforced;
            let mut state = AppState::new(
                settings,
                test_inventory(),
                test_playbooks(),
                repo.clone(),
                speaker.clone(),
                ".".into(),
            )
            .unwrap();
            // Set this fixture's cached bearer token without touching process environment.
            let state_mut = Arc::get_mut(&mut state).unwrap();
            state_mut.settings.http.auth.mode = mode;
            state_mut.bearer_token = (mode == AuthMode::Bearer).then(|| TOKEN.into());
            Self {
                app: create_test_router(state),
                repo,
                speaker,
            }
        }

        async fn seed(&self, count: u128) -> Vec<Mitigation> {
            let mut targets = Vec::new();
            for id in 1..=count {
                let ip = format!("198.18.0.{id}");
                let mut row = Mitigation::from_intent(
                    MitigationIntent {
                        event_id: Uuid::from_u128(id),
                        customer_id: None,
                        service_id: None,
                        pop: "test1".into(),
                        match_criteria: MatchCriteria {
                            dst_prefix: format!("{ip}/32"),
                            protocol: Some(17),
                            dst_ports: vec![53],
                            ..Default::default()
                        },
                        action_type: ActionType::Discard,
                        action_params: ActionParams::default(),
                        ttl_seconds: 300,
                        reason: "seed reason".into(),
                    },
                    ip,
                    AttackVector::UdpFlood,
                );
                row.mitigation_id = Uuid::from_u128(id);
                row.activate();
                self.repo.insert_mitigation(&row).await.unwrap();
                self.speaker
                    .announce(&mitigation_rule(&row).unwrap())
                    .await
                    .unwrap();
                targets.push(row);
            }
            targets
        }

        async fn post(
            &self,
            path: &str,
            payload: &Value,
            authorized: bool,
        ) -> axum::response::Response {
            let mut request = Request::post(path).header("content-type", "application/json");
            if authorized {
                request = request.header("authorization", format!("Bearer {TOKEN}"));
            }
            self.app
                .clone()
                .oneshot(request.body(Body::from(payload.to_string())).unwrap())
                .await
                .unwrap()
        }

        async fn snapshot(&self) -> Value {
            // Explicit limits observe every seeded row, including the 101-item rejection cases.
            let mut rows = self
                .repo
                .list_mitigations(
                    None,
                    None,
                    None,
                    None,
                    &MitigationListParams {
                        limit: 200,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            rows.sort_by_key(|row| row.mitigation_id);
            let params = ListParams {
                limit: 200,
                ..Default::default()
            };
            let pending: Vec<_> = self
                .repo
                .pending_withdrawals(None)
                .await
                .unwrap()
                .iter()
                .map(|request| format!("{request:?}"))
                .collect();
            json!({
                "mitigations": rows,
                "events": self.repo.list_events(&params).await.unwrap(),
                "audit": self.repo.list_audit(&params).await.unwrap(),
                "safelist": self.repo.list_safelist().await.unwrap(),
                "pending": pending,
                "rules": rules_value(self.speaker.list_active().await.unwrap()),
            })
        }
    }

    fn rules_value(mut rules: Vec<FlowSpecRule>) -> Value {
        rules.sort_by_key(FlowSpecRule::nlri_hash);
        serde_json::to_value(rules).unwrap()
    }

    fn request(operation: &str, id: Uuid, reason: Option<Value>) -> (String, Value) {
        let (path, mut payload) = match operation {
            "manual" => (
                "/v1/mitigations".into(),
                json!({
                    "victim_ip": "203.0.113.10", "protocol": "udp", "dst_ports": [53],
                    "action": "discard", "ttl_seconds": 120,
                }),
            ),
            "single" => (format!("/v1/mitigations/{id}/withdraw"), json!({})),
            "bulk" => (
                "/v1/mitigations/withdraw".into(),
                json!({"mitigation_ids": [id]}),
            ),
            "safelist" => ("/v1/safelist".into(), json!({"prefix": "198.51.100.1/32"})),
            _ => panic!("unknown test operation"),
        };
        payload["operator_id"] = json!("forged-actor");
        if let Some(reason) = reason {
            payload["reason"] = reason;
        }
        (path, payload)
    }

    async fn body(response: axum::response::Response) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn reason_byte_boundaries_preserve_data_and_reject_without_mutation() {
        let reasons = [
            (String::new(), 0, true),
            ("a".repeat(1023), 1023, true),
            ("a".repeat(1024), 1024, true),
            (format!("{}a", "é".repeat(511)), 1023, true),
            ("é".repeat(512), 1024, true),
            (format!("{}a", "é".repeat(512)), 1025, false),
            ("a".repeat(1025), 1025, false),
        ];
        for operation in OPERATIONS {
            for (reason, bytes, valid) in &reasons {
                assert_eq!(
                    reason.len(),
                    *bytes,
                    "fixture must exercise UTF-8 byte bounds"
                );
                let fixture = Fixture::new(AuthMode::None);
                let targets = fixture.seed(2).await;
                let before = fixture.snapshot().await;
                assert_eq!(before["mitigations"].as_array().unwrap().len(), 2);
                assert_eq!(before["rules"].as_array().unwrap().len(), 2);
                let (path, payload) =
                    request(operation, targets[0].mitigation_id, Some(json!(reason)));
                let response = fixture.post(&path, &payload, false).await;
                let context = format!(
                    "{operation}, {bytes} UTF-8 bytes, {} Unicode scalars",
                    reason.chars().count()
                );
                if !valid {
                    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{context}");
                    if operation == "manual" {
                        assert_eq!(
                            body(response).await["error"],
                            "invalid request: reason exceeds maximum length of 1024 bytes",
                            "{context}"
                        );
                    }
                    assert_eq!(fixture.snapshot().await, before, "{context}");
                    continue;
                }
                match operation {
                    "manual" => {
                        assert_eq!(response.status(), StatusCode::CREATED, "{context}");
                        let json = body(response).await;
                        let id = Uuid::parse_str(json["mitigation_id"].as_str().unwrap()).unwrap();
                        let row = fixture.repo.get_mitigation(id).await.unwrap().unwrap();
                        assert_eq!(row.reason, *reason);
                        assert_eq!(row.status, MitigationStatus::Active);
                        assert_eq!(fixture.speaker.announced_count().await, 3);
                    }
                    "single" | "bulk" => {
                        assert_eq!(response.status(), StatusCode::OK, "{context}");
                        let json = body(response).await;
                        if operation == "bulk" {
                            assert_eq!(json["withdrawn"], 1);
                            assert_eq!(json["failed"], 0);
                            assert_eq!(json["results"][0]["status"], "withdrawn");
                        }
                        let row = fixture
                            .repo
                            .get_mitigation(targets[0].mitigation_id)
                            .await
                            .unwrap()
                            .unwrap();
                        assert_eq!(row.status, MitigationStatus::Withdrawn);
                        assert_eq!(row.reason, format!("anonymous: {reason}"));
                        let audit = fixture
                            .repo
                            .list_audit(&ListParams {
                                limit: 200,
                                ..Default::default()
                            })
                            .await
                            .unwrap();
                        assert_eq!(audit.len(), 1);
                        assert!(matches!(audit[0].actor_type, ActorType::Operator));
                        assert_eq!(audit[0].actor_id.as_deref(), Some("anonymous"));
                        assert_eq!(
                            audit[0].target_id,
                            Some(targets[0].mitigation_id.to_string())
                        );
                        assert_eq!(audit[0].details["reason"], row.reason);
                        assert_eq!(audit[0].action, "withdraw");
                        assert_eq!(
                            rules_value(fixture.speaker.list_active().await.unwrap()),
                            rules_value(vec![mitigation_rule(&targets[1]).unwrap()])
                        );
                    }
                    "safelist" => {
                        assert_eq!(response.status(), StatusCode::CREATED, "{context}");
                        let entries = fixture.repo.list_safelist().await.unwrap();
                        assert_eq!(entries.len(), 1);
                        assert_eq!(entries[0].prefix, "198.51.100.1/32");
                        assert_eq!(entries[0].added_by, "anonymous");
                        assert_eq!(entries[0].reason.as_ref(), Some(reason));
                        assert_eq!(fixture.snapshot().await["rules"], before["rules"]);
                    }
                    _ => unreachable!(),
                }
                assert_eq!(
                    serde_json::to_value(
                        fixture
                            .repo
                            .get_mitigation(targets[1].mitigation_id)
                            .await
                            .unwrap()
                            .unwrap()
                    )
                    .unwrap(),
                    serde_json::to_value(&targets[1]).unwrap()
                );
                assert!(
                    fixture
                        .repo
                        .pending_withdrawals(None)
                        .await
                        .unwrap()
                        .is_empty()
                );
            }
        }
    }

    #[tokio::test]
    async fn missing_and_null_reasons_preserve_required_and_optional_json_fields() {
        for operation in OPERATIONS {
            for reason in [None, Some(Value::Null)] {
                let fixture = Fixture::new(AuthMode::None);
                let targets = fixture.seed(2).await;
                let before = fixture.snapshot().await;
                let (path, payload) = request(operation, targets[0].mitigation_id, reason);
                let response = fixture.post(&path, &payload, false).await;
                if operation == "safelist" {
                    assert_eq!(response.status(), StatusCode::CREATED);
                    let entries = fixture.repo.list_safelist().await.unwrap();
                    assert_eq!(entries.len(), 1);
                    assert_eq!(entries[0].reason, None);
                    assert_eq!(entries[0].added_by, "anonymous");
                    assert_eq!(
                        fixture.snapshot().await["mitigations"],
                        before["mitigations"]
                    );
                    assert_eq!(fixture.snapshot().await["rules"], before["rules"]);
                } else {
                    assert_eq!(
                        response.status(),
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "{operation}"
                    );
                    assert_eq!(fixture.snapshot().await, before, "{operation}");
                }
            }
        }
    }

    #[tokio::test]
    async fn bulk_list_length_boundaries_preserve_results_actor_and_unrelated_rules() {
        for operation in ["withdraw", "acknowledge"] {
            for count in [0, 1, 100, 101] {
                let fixture = Fixture::new(AuthMode::None);
                let targets = fixture.seed(101).await;
                let before = fixture.snapshot().await;
                assert_eq!(before["mitigations"].as_array().unwrap().len(), 101);
                assert_eq!(before["rules"].as_array().unwrap().len(), 101);
                let ids: Vec<_> = targets
                    .iter()
                    .take(count)
                    .map(|row| row.mitigation_id)
                    .collect();
                let payload = json!({"mitigation_ids": ids, "operator_id": "forged-actor", "reason": "bulk boundary"});
                let response = fixture
                    .post(&format!("/v1/mitigations/{operation}"), &payload, false)
                    .await;
                if count == 0 || count == 101 {
                    assert_eq!(
                        response.status(),
                        StatusCode::BAD_REQUEST,
                        "{operation}: {count}"
                    );
                    assert_eq!(fixture.snapshot().await, before, "{operation}: {count}");
                    continue;
                }
                assert_eq!(response.status(), StatusCode::OK, "{operation}: {count}");
                let json = body(response).await;
                let (counter, status) = if operation == "withdraw" {
                    ("withdrawn", "withdrawn")
                } else {
                    ("acknowledged", "acknowledged")
                };
                assert_eq!(json[counter], count);
                assert_eq!(json["failed"], 0);
                let results = json["results"].as_array().unwrap();
                assert_eq!(results.len(), count);
                for (result, id) in results.iter().zip(&ids) {
                    assert_eq!(result["mitigation_id"], id.to_string());
                    assert_eq!(result["status"], status);
                    assert!(result.get("error").is_none());
                }
                for (index, original) in targets.iter().enumerate() {
                    let row = fixture
                        .repo
                        .get_mitigation(original.mitigation_id)
                        .await
                        .unwrap()
                        .unwrap();
                    if index >= count {
                        assert_eq!(
                            serde_json::to_value(row).unwrap(),
                            serde_json::to_value(original).unwrap()
                        );
                    } else if operation == "withdraw" {
                        assert_eq!(row.status, MitigationStatus::Withdrawn);
                        assert_eq!(row.reason, "anonymous: bulk boundary");
                    } else {
                        assert_eq!(row.status, MitigationStatus::Active);
                        assert!(row.acknowledged_at.is_some());
                        assert_eq!(row.acknowledged_by.as_deref(), Some("anonymous"));
                        assert_eq!(row.reason, original.reason);
                    }
                }
                let remaining = if operation == "withdraw" { count } else { 0 };
                assert_eq!(
                    rules_value(fixture.speaker.list_active().await.unwrap()),
                    rules_value(
                        targets
                            .iter()
                            .skip(remaining)
                            .map(|target| mitigation_rule(target).unwrap())
                            .collect()
                    )
                );
                if operation == "withdraw" {
                    let audit = fixture
                        .repo
                        .list_audit(&ListParams {
                            limit: 200,
                            ..Default::default()
                        })
                        .await
                        .unwrap();
                    assert_eq!(audit.len(), count);
                    let mut recorded: Vec<_> = audit
                        .iter()
                        .map(|entry| {
                            assert_eq!(entry.action, "withdraw");
                            assert!(matches!(entry.actor_type, ActorType::Operator));
                            assert_eq!(entry.actor_id.as_deref(), Some("anonymous"));
                            assert_eq!(entry.details["reason"], "anonymous: bulk boundary");
                            Uuid::parse_str(entry.target_id.as_deref().unwrap()).unwrap()
                        })
                        .collect();
                    recorded.sort();
                    assert_eq!(recorded, ids);
                }
                assert!(
                    fixture
                        .repo
                        .pending_withdrawals(None)
                        .await
                        .unwrap()
                        .is_empty()
                );
            }
        }
    }

    #[tokio::test]
    async fn malformed_bulk_uuids_reject_before_any_partial_mutation() {
        let fixture = Fixture::new(AuthMode::None);
        let targets = fixture.seed(2).await;
        let before = fixture.snapshot().await;
        for operation in ["withdraw", "acknowledge"] {
            for invalid in [json!(""), json!("not-a-uuid"), json!(42), Value::Null] {
                let payload = json!({"mitigation_ids": [json!(targets[0].mitigation_id), invalid],
                    "operator_id": "forged-actor", "reason": "must not partially apply"});
                let response = fixture
                    .post(&format!("/v1/mitigations/{operation}"), &payload, false)
                    .await;
                assert_eq!(
                    response.status(),
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "{operation}"
                );
                assert_eq!(fixture.snapshot().await, before, "{operation}");
            }
        }
        let response = fixture
            .post(
                "/v1/mitigations/not-a-uuid/withdraw",
                &json!({"reason": "invalid path"}),
                false,
            )
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(fixture.snapshot().await, before);
    }

    #[tokio::test]
    async fn semantic_validation_and_extractor_errors_preserve_auth_precedence() {
        let fixture = Fixture::new(AuthMode::Bearer);
        let targets = fixture.seed(2).await;
        let before = fixture.snapshot().await;
        for operation in OPERATIONS {
            let (path, payload) = request(
                operation,
                targets[0].mitigation_id,
                Some(json!("a".repeat(1025))),
            );
            assert_eq!(
                fixture.post(&path, &payload, false).await.status(),
                StatusCode::UNAUTHORIZED,
                "{operation}"
            );
            let expected = if operation == "safelist" {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::BAD_REQUEST
            };
            assert_eq!(
                fixture.post(&path, &payload, true).await.status(),
                expected,
                "{operation}"
            );
        }
        for operation in ["withdraw", "acknowledge"] {
            let path = format!("/v1/mitigations/{operation}");
            for count in [0, 101] {
                let ids = vec![targets[0].mitigation_id; count];
                let payload = json!({"mitigation_ids": ids, "reason": "auth first"});
                assert_eq!(
                    fixture.post(&path, &payload, false).await.status(),
                    StatusCode::UNAUTHORIZED
                );
                assert_eq!(
                    fixture.post(&path, &payload, true).await.status(),
                    StatusCode::BAD_REQUEST
                );
            }
            let payload = json!({"mitigation_ids": [targets[0].mitigation_id, "invalid"], "reason": "extractor first"});
            for authorized in [false, true] {
                assert_eq!(
                    fixture.post(&path, &payload, authorized).await.status(),
                    StatusCode::UNPROCESSABLE_ENTITY
                );
            }
        }
        for authorized in [false, true] {
            assert_eq!(
                fixture
                    .post(
                        "/v1/mitigations/not-a-uuid/withdraw",
                        &json!({"reason": "extractor first"}),
                        authorized
                    )
                    .await
                    .status(),
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(fixture.snapshot().await, before);
    }
}

mod query_router_validator_boundaries {
    use super::*;
    use chrono::{Duration, Utc};
    use prefixd::correlation::{CorroboratingSignal, engine::CorrelationEngine};
    use prefixd::domain::{
        ActionParams, ActionType, AttackEvent, AttackEventInput, MatchCriteria, Mitigation,
        MitigationIntent,
    };
    use prefixd::observability::{ActorType, AuditEntry};
    use uuid::Uuid;

    async fn response_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn get_json(app: &axum::Router, uri: &str) -> serde_json::Value {
        let response = app
            .clone()
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        response_json(response).await
    }

    #[tokio::test]
    async fn general_list_and_ip_history_limits_use_real_rows() {
        let (app, repo) = setup_app_correlation_with_repo(1, 0.5).await;
        let now = Utc::now();
        for id in 1_u128..=1001 {
            let mut event = AttackEvent::from_input(AttackEventInput {
                event_id: None,
                timestamp: now,
                source: "query-boundary".into(),
                victim_ip: "203.0.113.10".into(),
                vector: AttackVector::UdpFlood,
                bps: None,
                pps: None,
                top_dst_ports: None,
                confidence: None,
                action: "ban".into(),
                raw_details: None,
            });
            event.event_id = Uuid::from_u128(id);
            event.ingested_at = now;
            repo.insert_event(&event).await.unwrap();
            let mut mitigation = Mitigation::from_intent(
                MitigationIntent {
                    event_id: event.event_id,
                    customer_id: None,
                    service_id: None,
                    pop: "test1".into(),
                    match_criteria: MatchCriteria {
                        dst_prefix: "203.0.113.10/32".into(),
                        protocol: Some(17),
                        dst_ports: vec![u16::try_from(id).unwrap()],
                        ..Default::default()
                    },
                    action_type: ActionType::Discard,
                    action_params: ActionParams::default(),
                    ttl_seconds: 300,
                    reason: "query boundary fixture".into(),
                },
                "203.0.113.10".into(),
                AttackVector::UdpFlood,
            );
            mitigation.mitigation_id = Uuid::from_u128(id);
            mitigation.created_at = now;
            repo.insert_mitigation(&mitigation).await.unwrap();
            // Explicit fixture entries: this test does not assume event ingestion writes audit rows.
            let mut audit = AuditEntry::new(
                ActorType::System,
                None,
                "query-boundary",
                None,
                None,
                serde_json::json!({}),
            );
            audit.audit_id = Uuid::from_u128(id);
            audit.timestamp = now;
            repo.insert_audit(&audit).await.unwrap();
            let mut group = CorrelationEngine::create_group(
                &format!("198.18.{}.{}", id / 256, id % 256),
                "udp_flood",
                3600,
            );
            group.group_id = Uuid::from_u128(id);
            group.created_at = now;
            assert_eq!(
                repo.insert_signal_group(&group).await.unwrap().group_id,
                group.group_id
            );
        }
        for (endpoint, rows_key, id_key, prefix) in [
            ("mitigations", "mitigations", "mitigation_id", "m1."),
            ("events", "events", "event_id", "e1."),
            ("audit", "entries", "audit_id", "a1."),
            ("signal-groups", "groups", "group_id", "s1."),
        ] {
            for (limit, count) in [
                (None, 100_usize),
                (Some("0"), 0),
                (Some("1"), 1),
                (Some("1000"), 1000),
                (Some("1001"), 1000),
                (Some("4294967295"), 1000),
            ] {
                let query = limit
                    .map(|value| format!("?limit={value}"))
                    .unwrap_or_default();
                let uri = format!("/v1/{endpoint}{query}");
                let page = get_json(&app, &uri).await;
                let rows = page[rows_key].as_array().unwrap();
                assert_eq!(page["count"], count, "{uri}");
                assert_eq!(rows.len(), count, "{uri}");
                assert_eq!(page["has_more"], true, "{uri}");
                for (index, row) in rows.iter().enumerate() {
                    assert_eq!(
                        row[id_key],
                        Uuid::from_u128(1001 - index as u128).to_string(),
                        "{uri}"
                    );
                }
                if count == 0 {
                    // Existing policy preserves zero; there is no last row to encode a cursor.
                    assert!(page["next_cursor"].is_null(), "{uri}");
                    continue;
                }
                let cursor = page["next_cursor"].as_str().unwrap();
                assert!(cursor.starts_with(prefix), "{uri}");
                if count == 1 || count == 1000 {
                    let next = get_json(
                        &app,
                        &format!("/v1/{endpoint}?limit={}&cursor={cursor}", limit.unwrap()),
                    )
                    .await;
                    let remaining = (1001 - count).min(count);
                    assert_eq!(next["count"], remaining);
                    assert_eq!(next[rows_key].as_array().unwrap().len(), remaining);
                    assert_eq!(
                        next[rows_key][0][id_key],
                        Uuid::from_u128((1001 - count) as u128).to_string()
                    );
                    assert_eq!(next["has_more"], count == 1);
                    assert_eq!(next["next_cursor"].is_string(), count == 1);
                }
            }
            for invalid in ["", "not-a-number", "-1", "1.5", "4294967296"] {
                let uri = format!("/v1/{endpoint}?limit={invalid}");
                let response = app
                    .clone()
                    .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
            }
        }
        for (query, expected) in [
            ("", 100_usize),
            ("?limit=0", 0),
            ("?limit=1", 1),
            ("?limit=1000", 1000),
            ("?limit=1001", 1000),
        ] {
            let uri = format!("/v1/ip/203.0.113.10/history{query}");
            let history = get_json(&app, &uri).await;
            assert_eq!(history["ip"], "203.0.113.10");
            for (key, id_key) in [("events", "event_id"), ("mitigations", "mitigation_id")] {
                let rows = history[key].as_array().unwrap();
                assert_eq!(rows.len(), expected, "{uri}: {key}");
                let ids: std::collections::BTreeSet<_> = rows
                    .iter()
                    .map(|row| {
                        Uuid::parse_str(row[id_key].as_str().unwrap())
                            .unwrap()
                            .as_u128()
                    })
                    .collect();
                assert_eq!(ids, (1..=expected as u128).collect(), "{uri}: {key}");
            }
        }
        for invalid in ["", "not-a-number", "-1", "1.5", "4294967296"] {
            let uri = format!("/v1/ip/203.0.113.10/history?limit={invalid}");
            let response = app
                .clone()
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        }
    }

    #[tokio::test]
    async fn preferences_quiet_hour_boundaries_preserve_state_and_extractor_auth_order() {
        let app = setup_app_with_bearer().await;
        for (start, end) in [
            (None, None),
            (Some(0), Some(23)),
            (Some(23), Some(0)),
            (Some(0), Some(0)),
            (Some(23), Some(23)),
        ] {
            let prefs = serde_json::json!({"muted_events": [], "quiet_hours_start": start, "quiet_hours_end": end});
            let response = app
                .clone()
                .oneshot(
                    Request::put("/v1/preferences")
                        .header("authorization", "Bearer test-secret-token-123")
                        .header("content-type", "application/json")
                        .body(Body::from(prefs.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let response = app
                .clone()
                .oneshot(
                    Request::get("/v1/preferences")
                        .header("authorization", "Bearer test-secret-token-123")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response_json(response).await, prefs);
        }
        for (start, end, expected) in [
            (
                serde_json::json!(-1),
                serde_json::json!(23),
                StatusCode::BAD_REQUEST,
            ),
            (
                serde_json::json!(24),
                serde_json::json!(0),
                StatusCode::BAD_REQUEST,
            ),
            (
                serde_json::json!(0),
                serde_json::json!(-1),
                StatusCode::BAD_REQUEST,
            ),
            (
                serde_json::json!(23),
                serde_json::json!(24),
                StatusCode::BAD_REQUEST,
            ),
            (
                serde_json::json!(0),
                serde_json::Value::Null,
                StatusCode::BAD_REQUEST,
            ),
            (
                serde_json::Value::Null,
                serde_json::json!(0),
                StatusCode::BAD_REQUEST,
            ),
            (
                serde_json::json!("0"),
                serde_json::json!(23),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                serde_json::json!(0),
                serde_json::json!(1.5),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                serde_json::json!(32768),
                serde_json::json!(23),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
        ] {
            let prefs = serde_json::json!({"muted_events": [], "quiet_hours_start": start, "quiet_hours_end": end});
            for authenticated in [false, true] {
                let mut request =
                    Request::put("/v1/preferences").header("content-type", "application/json");
                if authenticated {
                    request = request.header("authorization", "Bearer test-secret-token-123");
                }
                let response = app
                    .clone()
                    .oneshot(request.body(Body::from(prefs.to_string())).unwrap())
                    .await
                    .unwrap();
                let status = if !authenticated && expected == StatusCode::BAD_REQUEST {
                    StatusCode::UNAUTHORIZED
                } else {
                    expected
                };
                assert_eq!(
                    response.status(),
                    status,
                    "prefs={prefs}, authenticated={authenticated}"
                );
            }
            let response = app
                .clone()
                .oneshot(
                    Request::get("/v1/preferences")
                        .header("authorization", "Bearer test-secret-token-123")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response_json(response).await,
                serde_json::json!({"muted_events": [], "quiet_hours_start": 23, "quiet_hours_end": 23})
            );
        }
        for authenticated in [false, true] {
            let mut request =
                Request::put("/v1/preferences").header("content-type", "application/json");
            if authenticated {
                request = request.header("authorization", "Bearer test-secret-token-123");
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::from("{")).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        for method in ["GET", "PUT"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri("/v1/preferences")
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn incident_report_selector_and_query_extractor_boundaries() {
        let app = setup_app_with_bearer().await;
        let missing_id = Uuid::new_v4();
        for (query, expected, extracted) in [
            ("ip=203.0.113.10".to_owned(), StatusCode::OK, true),
            (
                format!("mitigation_id={missing_id}"),
                StatusCode::NOT_FOUND,
                true,
            ),
            (
                format!("mitigation_id={missing_id}&ip=203.0.113.10"),
                StatusCode::BAD_REQUEST,
                true,
            ),
            ("ip=not-an-ip".to_owned(), StatusCode::BAD_REQUEST, true),
            (
                "mitigation_id=not-a-uuid".to_owned(),
                StatusCode::BAD_REQUEST,
                false,
            ),
        ] {
            for authenticated in [false, true] {
                let mut request = Request::get(format!("/v1/reports/incident?{query}"));
                if authenticated {
                    request = request.header("authorization", "Bearer test-secret-token-123");
                }
                let response = app
                    .clone()
                    .oneshot(request.body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                let status = if !authenticated && extracted {
                    StatusCode::UNAUTHORIZED
                } else {
                    expected
                };
                assert_eq!(
                    response.status(),
                    status,
                    "{query}, authenticated={authenticated}"
                );
                if status == StatusCode::OK {
                    assert!(
                        response.headers()["content-type"]
                            .to_str()
                            .unwrap()
                            .contains("text/markdown")
                    );
                    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                        .await
                        .unwrap();
                    assert!(
                        String::from_utf8(body.to_vec())
                            .unwrap()
                            .contains("203.0.113.10")
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn corroborator_query_clamps_preserve_rows_and_activity_window() {
        let (app, repo) = setup_app_correlation_with_repo(1, 0.5).await;
        let now = Utc::now();
        for id in 1_u128..=1005 {
            let age = match id {
                1002 => Duration::minutes(2),
                1003 => Duration::minutes(90),
                1004 => Duration::hours(23),
                1005 => Duration::hours(25),
                _ => Duration::seconds(30),
            };
            repo.insert_corroborating_signal(&CorroboratingSignal {
                signal_id: Uuid::from_u128(id),
                source: "router-cpu".into(),
                vector: None,
                customer_id: None,
                pop: Some("test1".into()),
                service_id: None,
                interface: None,
                confidence: Some(0.5),
                weight: 0.5,
                ingested_at: now - age,
                expires_at: now + Duration::hours(1),
                raw_details: None,
                attached_group_ids: if id > 1001 {
                    vec![Uuid::new_v4()]
                } else {
                    vec![]
                },
            })
            .await
            .unwrap();
        }
        for (query, expected) in [
            ("", 100_usize),
            ("?limit=0", 1),
            ("?limit=1", 1),
            ("?limit=1000", 1000),
            ("?limit=1001", 1000),
            ("?limit=4294967295", 1000),
        ] {
            let page = get_json(&app, &format!("/v1/signals/corroborator/cache{query}")).await;
            let signals = page["signals"].as_array().unwrap();
            assert_eq!(signals.len(), expected, "{query}");
            assert_eq!(page["total"], 1001);
            assert_eq!(
                page["by_source"],
                serde_json::json!([{"source": "router-cpu", "count": 1001}])
            );
            for signal in signals {
                assert!(signal["attached_group_ids"].as_array().unwrap().is_empty());
                assert_eq!(signal["source"], "router-cpu");
            }
        }
        for (query, minutes, expected) in [
            ("", 60, 1002),
            ("?minutes=0", 1, 1001),
            ("?minutes=1", 1, 1001),
            ("?minutes=1440", 1440, 1004),
            ("?minutes=1441", 1440, 1004),
            ("?minutes=4294967295", 1440, 1004),
        ] {
            let before = Utc::now();
            let activity =
                get_json(&app, &format!("/v1/signals/corroborator/activity{query}")).await;
            let after = Utc::now();
            let since = activity["since"]
                .as_str()
                .unwrap()
                .parse::<chrono::DateTime<Utc>>()
                .unwrap();
            let window = Duration::minutes(minutes);
            assert!(
                since >= before - window && since <= after - window,
                "{query}"
            );
            assert_eq!(activity["sources"].as_array().unwrap().len(), 1);
            assert_eq!(activity["sources"][0]["source"], "router-cpu");
            assert_eq!(activity["sources"][0]["count"], expected, "{query}");
            assert_eq!(
                activity["sources"][0]["last_seen"],
                serde_json::json!(now - Duration::seconds(30))
            );
        }
        for (endpoint, parameter) in [("cache", "limit"), ("activity", "minutes")] {
            for invalid in ["", "not-a-number", "-1", "1.5", "4294967296"] {
                let uri = format!("/v1/signals/corroborator/{endpoint}?{parameter}={invalid}");
                let response = app
                    .clone()
                    .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
            }
        }
    }

    #[tokio::test]
    async fn playbook_name_and_ttl_edit_boundaries_preserve_rejected_config() {
        let directory = tempfile::tempdir().unwrap();
        let app = setup_app_with_config_dir(directory.path().to_path_buf()).await;
        let uri = "/v1/config/playbooks";
        let path = directory.path().join("playbooks.yaml");
        let initial = serde_json::to_string(&test_playbooks()).unwrap();
        let (status, _) = correlation_config_request(&app, "PUT", uri, &initial).await;
        assert_eq!(status, StatusCode::OK);

        for (name, ttl, error_field) in [
            ("a".repeat(128), 120, None),
            ("é".repeat(64), 120, None),
            ("a".repeat(129), 120, Some("name exceeds 128 bytes")),
            (
                format!("{}a", "é".repeat(64)),
                120,
                Some("name exceeds 128 bytes"),
            ),
            ("ttl-boundary".into(), 1, None),
            ("ttl-boundary".into(), 86_400, None),
            ("ttl-boundary".into(), 0, Some("ttl_seconds")),
            ("ttl-boundary".into(), 86_401, Some("ttl_seconds")),
        ] {
            let before = get_json(&app, uri).await;
            let before_bytes = std::fs::read(&path).unwrap();
            let before_backup = std::fs::read(path.with_extension("yaml.bak")).ok();
            let mut playbooks = test_playbooks();
            playbooks.playbooks[0].name = name.clone();
            playbooks.playbooks[0].steps[0].ttl_seconds = ttl;
            let payload = serde_json::to_string(&playbooks).unwrap();
            let (status, response) = correlation_config_request(&app, "PUT", uri, &payload).await;
            let current = get_json(&app, uri).await;

            if let Some(field) = error_field {
                assert_eq!(status, StatusCode::BAD_REQUEST, "name={name:?}, ttl={ttl}");
                assert!(
                    response["errors"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|error| { error.as_str().unwrap().contains(field) }),
                    "{response}"
                );
                assert_eq!(
                    current, before,
                    "rejection changed running config or loaded_at"
                );
                assert_eq!(std::fs::read(&path).unwrap(), before_bytes);
                assert_eq!(
                    std::fs::read(path.with_extension("yaml.bak")).ok(),
                    before_backup
                );
            } else {
                assert_eq!(status, StatusCode::OK, "name={name:?}, ttl={ttl}");
                assert_eq!(current, response);
                assert_eq!(current["total_playbooks"], 1);
                assert_eq!(current["playbooks"][0]["name"], name);
                assert_eq!(current["playbooks"][0]["steps"][0]["ttl_seconds"], ttl);
                let saved = Playbooks::load(&path).unwrap();
                assert_eq!(
                    serde_json::to_value(saved).unwrap(),
                    serde_json::to_value(&playbooks).unwrap()
                );
            }
        }
    }

    #[tokio::test]
    async fn correlation_adapter_name_edits_preserve_rejected_config() {
        let directory = tempfile::tempdir().unwrap();
        let app = setup_app_with_config_dir(directory.path().to_path_buf()).await;
        let uri = "/v1/config/correlation";
        let path = directory.path().join("correlation.yaml");
        let initial = prefixd::correlation::CorrelationConfig {
            enabled: true,
            webhook_adapters: vec![basic_webhook_adapter("original")],
            ..Default::default()
        };
        let (status, _) =
            correlation_config_request(&app, "PUT", uri, &serde_json::to_string(&initial).unwrap())
                .await;
        assert_eq!(status, StatusCode::OK);

        for (names, error_fragment) in [
            (vec!["a".to_owned(), "b".repeat(64)], None),
            (
                vec!["duplicate".into(), "duplicate".into()],
                Some("duplicate name"),
            ),
            (vec![String::new()], Some("name must match")),
            (vec!["Upper".into()], Some("name must match")),
            (vec!["a".repeat(65)], Some("name must match")),
        ] {
            let before = get_json(&app, uri).await;
            let before_bytes = std::fs::read(&path).unwrap();
            let before_backup = std::fs::read(path.with_extension("yaml.bak")).ok();
            let config = prefixd::correlation::CorrelationConfig {
                webhook_adapters: names
                    .iter()
                    .map(|name| basic_webhook_adapter(name))
                    .collect(),
                ..initial.clone()
            };
            let (status, response) = correlation_config_request(
                &app,
                "PUT",
                uri,
                &serde_json::to_string(&config).unwrap(),
            )
            .await;
            let current = get_json(&app, uri).await;

            if let Some(fragment) = error_fragment {
                assert_eq!(status, StatusCode::BAD_REQUEST, "names={names:?}");
                assert!(
                    response["errors"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|error| { error.as_str().unwrap().contains(fragment) }),
                    "{response}"
                );
                assert_eq!(
                    current, before,
                    "rejection changed running config or loaded_at"
                );
                assert_eq!(std::fs::read(&path).unwrap(), before_bytes);
                assert_eq!(
                    std::fs::read(path.with_extension("yaml.bak")).ok(),
                    before_backup
                );
            } else {
                assert_eq!(status, StatusCode::OK, "names={names:?}");
                let running_names: Vec<_> = current["config"]["webhook_adapters"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|adapter| adapter["name"].as_str().unwrap().to_owned())
                    .collect();
                assert_eq!(running_names, names);
                let saved = prefixd::correlation::CorrelationConfig::load(&path).unwrap();
                assert_eq!(
                    serde_json::to_value(saved).unwrap(),
                    serde_json::to_value(&config).unwrap()
                );
            }
        }
    }

    #[tokio::test]
    async fn alert_destination_byte_boundaries_preserve_rejected_config() {
        let directory = tempfile::tempdir().unwrap();
        let repo: Arc<dyn RepositoryTrait> = Arc::new(MockRepository::new());
        let state = AppState::new(
            test_settings(),
            test_inventory(),
            test_playbooks(),
            repo,
            Arc::new(MockAnnouncer::new()),
            directory.path().to_path_buf(),
        )
        .unwrap();
        let app = create_test_router(state.clone());
        let uri = "/v1/config/alerting";
        let path = directory.path().join("alerting.yaml");
        let initial = serde_json::json!({
            "destinations": [{"type": "generic", "url": "https://example.com/initial"}],
            "events": [],
        });
        let (status, _) = correlation_config_request(&app, "PUT", uri, &initial.to_string()).await;
        assert_eq!(status, StatusCode::OK);

        for (kind, field, maximum) in [
            ("slack", "webhook_url", 1_024),
            ("discord", "webhook_url", 1_024),
            ("teams", "webhook_url", 1_024),
            ("pagerduty", "events_url", 1_024),
            ("generic", "url", 1_024),
            ("telegram", "chat_id", 64),
        ] {
            for multibyte in [false, true] {
                for extra in [0, 1] {
                    let prefix = if kind == "telegram" {
                        ""
                    } else {
                        "https://example.com/"
                    };
                    let padding_len = maximum - prefix.len();
                    let padding = if multibyte {
                        format!(
                            "{}{}",
                            "é".repeat(padding_len / 2),
                            "a".repeat(padding_len % 2)
                        )
                    } else {
                        "a".repeat(padding_len)
                    };
                    let value = format!("{prefix}{padding}{}", "a".repeat(extra));
                    assert_eq!(value.len(), maximum + extra);
                    let mut destination = serde_json::json!({"type": kind});
                    destination[field] = serde_json::json!(value);
                    match kind {
                        "telegram" => {
                            destination["bot_token"] = serde_json::json!("boundary-test-token")
                        }
                        "pagerduty" => {
                            destination["routing_key"] = serde_json::json!("boundary-test-key")
                        }
                        _ => {}
                    }
                    let config: prefixd::alerting::AlertingConfig = serde_json::from_value(
                        serde_json::json!({"destinations": [destination], "events": []}),
                    )
                    .unwrap();
                    let expected = serde_json::to_value(&config).unwrap();
                    let before = get_json(&app, uri).await;
                    let before_running =
                        serde_json::to_value(state.alerting.read().await.config()).unwrap();
                    let before_loaded_at = *state.alerting_loaded_at.read().await;
                    let before_bytes = std::fs::read(&path).unwrap();
                    let before_backup = std::fs::read(path.with_extension("yaml.bak")).ok();
                    let (status, response) =
                        correlation_config_request(&app, "PUT", uri, &expected.to_string()).await;
                    let current = get_json(&app, uri).await;
                    let current_running =
                        serde_json::to_value(state.alerting.read().await.config()).unwrap();

                    if extra == 0 {
                        assert_eq!(
                            status,
                            StatusCode::OK,
                            "{kind}, multibyte={multibyte}: {response}"
                        );
                        assert_eq!(current, response);
                        assert_eq!(current_running, expected);
                        let saved = prefixd::alerting::AlertingConfig::load(&path).unwrap();
                        assert_eq!(serde_json::to_value(saved).unwrap(), expected);
                    } else {
                        assert_eq!(
                            status,
                            StatusCode::BAD_REQUEST,
                            "{kind}, multibyte={multibyte}"
                        );
                        let error_unit = format!("{field} exceeds {maximum} bytes");
                        assert!(
                            response["errors"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .any(|error| { error.as_str().unwrap().contains(&error_unit) }),
                            "{response}"
                        );
                        assert_eq!(current, before);
                        assert_eq!(current_running, before_running);
                        assert_eq!(*state.alerting_loaded_at.read().await, before_loaded_at);
                        assert_eq!(std::fs::read(&path).unwrap(), before_bytes);
                        assert_eq!(
                            std::fs::read(path.with_extension("yaml.bak")).ok(),
                            before_backup
                        );
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn shared_router_body_limit_accepts_exact_mib_and_rejects_one_more() {
        let (app, repo) = setup_app_correlation_with_repo(1, 0.5).await;
        const LIMIT: usize = 1024 * 1024;
        for declared in [false, true] {
            for (length, expected) in [
                (LIMIT, StatusCode::ACCEPTED),
                (LIMIT + 1, StatusCode::PAYLOAD_TOO_LARGE),
            ] {
                let external_id = format!("body-boundary-{declared}-{length}");
                let payload = serde_json::json!({
                    "event_id": external_id, "timestamp": Utc::now(), "source": "detector_a",
                    "victim_ip": "203.0.113.10", "vector": "udp_flood", "confidence": 0.9,
                    "bps": 100000000, "pps": 50000, "top_dst_ports": [53],
                });
                let mut body = payload.to_string();
                body.push_str(&" ".repeat(length - body.len()));
                assert_eq!(body.len(), length);
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(&body).unwrap(),
                    payload
                );
                let mut request =
                    Request::post("/v1/events").header("content-type", "application/json");
                if declared {
                    request = request.header("content-length", length.to_string());
                }
                let response = app
                    .clone()
                    .oneshot(request.body(Body::from(body)).unwrap())
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    expected,
                    "declared={declared}, length={length}"
                );
                let persisted = repo
                    .find_ban_event_by_external_id("detector_a", &external_id)
                    .await
                    .unwrap();
                assert_eq!(persisted.is_some(), expected == StatusCode::ACCEPTED);
            }
        }
    }
}

#[tokio::test]
async fn test_timeseries_duration_overflow_preserves_auth_and_shape() {
    let app = setup_app_with_bearer().await;
    for metric in ["mitigations", "events"] {
        for (range, bucket) in [
            ("178956971d", "71582789h"),
            ("536870912d", "1073741824h"),
            ("4294967295d", "4294967295h"),
            ("4294967296d", "4294967296h"),
            ("invalid", "invalid"),
            ("0h", "0m"),
        ] {
            let uri = format!("/v1/stats/timeseries?metric={metric}&range={range}&bucket={bucket}");
            let response = app
                .clone()
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
            let response = app
                .clone()
                .oneshot(
                    Request::get(&uri)
                        .header("authorization", "Bearer test-secret-token-123")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{uri}");
            let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["metric"], metric);
            // Mock checks routing/authentication only; PostgreSQL tests measure intervals.
            assert_eq!(json["buckets"], serde_json::json!([]));
        }
    }
}

/// Dry-run intent must stay a local simulation after a restart in enforced mode.
#[tokio::test]
async fn test_dry_run_mitigation_is_not_announced_after_switch_to_enforced() {
    use prefixd::domain::MitigationStatus;
    let repo = Arc::new(MockRepository::new());
    let speaker = Arc::new(MockAnnouncer::new());

    // Controller A: dry-run (the fixture default) admits a detector mitigation.
    let dry_run = AppState::new(
        test_settings(),
        test_inventory(),
        test_playbooks(),
        repo.clone(),
        speaker.clone(),
        ".".into(),
    )
    .unwrap();
    assert!(dry_run.is_dry_run());
    let event = serde_json::json!({"event_id":"dry-run-rehearsal", "timestamp":chrono::Utc::now(), "source":"test", "victim_ip":"203.0.113.10", "vector":"udp_flood", "pps":50000, "top_dst_ports":[53], "confidence":0.9});
    let response = create_test_router(dry_run)
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
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let id: uuid::Uuid = body["mitigation_id"].as_str().unwrap().parse().unwrap();
    let simulated = repo.get_mitigation(id).await.unwrap().unwrap();
    assert_eq!(simulated.status, MitigationStatus::Active);
    assert!(simulated.expires_at > chrono::Utc::now());
    assert_eq!(speaker.announced_count().await, 0, "dry-run sent no RPC");

    // Controller B: same database and speaker, restarted in enforced mode.
    let mut settings = test_settings();
    settings.mode = prefixd::config::OperationMode::Enforced;
    let enforced = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo.clone(),
        speaker.clone(),
        ".".into(),
    )
    .unwrap();
    assert!(!enforced.is_dry_run());
    prefixd::scheduler::ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false)
        .with_app_state(enforced)
        .reconcile()
        .await
        .unwrap();

    assert_eq!(
        speaker.announced_count().await,
        0,
        "first enforced reconciliation announced a dry-run simulation"
    );
}

fn dry_run_row(ttl_seconds: u32) -> prefixd::domain::Mitigation {
    use prefixd::domain::{ActionParams, ActionType, MatchCriteria, Mitigation, MitigationIntent};
    let mut mitigation = Mitigation::from_intent(
        MitigationIntent {
            event_id: uuid::Uuid::new_v4(),
            customer_id: None,
            service_id: None,
            pop: "test1".into(),
            match_criteria: MatchCriteria {
                dst_prefix: "203.0.113.10/32".into(),
                protocol: Some(17),
                dst_ports: vec![53],
                ..Default::default()
            },
            action_type: ActionType::Discard,
            action_params: ActionParams::default(),
            ttl_seconds,
            reason: "simulated".into(),
        },
        "203.0.113.10".into(),
        AttackVector::UdpFlood,
    );
    mitigation.activate();
    mitigation.origin_mode = Some(prefixd::config::OperationMode::DryRun);
    mitigation
}

fn enforced_state(repo: Arc<MockRepository>, speaker: Arc<MockAnnouncer>) -> Arc<AppState> {
    let mut settings = test_settings();
    settings.mode = prefixd::config::OperationMode::Enforced;
    AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo,
        speaker,
        ".".into(),
    )
    .unwrap()
}

#[tokio::test]
async fn test_enforced_expiry_of_dry_run_row_never_deletes_speaker_state() {
    use prefixd::domain::{MitigationStatus, mitigation_rule};
    let repo = Arc::new(MockRepository::new());
    let speaker = Arc::new(MockAnnouncer::new());
    let mut simulated = dry_run_row(600);
    simulated.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
    repo.insert_mitigation(&simulated).await.unwrap();
    // A rule with the same NLRI that prefixd never announced must survive the expiry.
    speaker
        .announce(&mitigation_rule(&simulated).unwrap())
        .await
        .unwrap();
    let state = enforced_state(repo.clone(), speaker.clone());
    prefixd::scheduler::ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false)
        .with_app_state(state)
        .reconcile()
        .await
        .unwrap();
    let expired = repo
        .get_mitigation(simulated.mitigation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(expired.status, MitigationStatus::Expired);
    assert_eq!(speaker.announced_count().await, 1, "no speaker deletion");
    assert!(repo.pending_withdrawals(None).await.unwrap().is_empty());
}

#[tokio::test]
async fn test_retiring_dry_run_intent_is_local_audited_and_unblocks_enforced_startup() {
    use prefixd::domain::{
        MitigationStatus, check_enforced_startup, dry_run_intent, retire_dry_run_intent,
    };
    let repo = Arc::new(MockRepository::new());
    let speaker = Arc::new(MockAnnouncer::new());
    let simulated = dry_run_row(600);
    repo.insert_mitigation(&simulated).await.unwrap();
    let mut enforced = dry_run_row(600);
    enforced.mitigation_id = uuid::Uuid::new_v4();
    enforced.match_criteria.dst_prefix = "203.0.113.11/32".into();
    enforced.scope_hash = enforced.match_criteria.compute_scope_hash();
    enforced.origin_mode = Some(prefixd::config::OperationMode::Enforced);
    repo.insert_mitigation(&enforced).await.unwrap();

    let refusal = check_enforced_startup(repo.as_ref(), "test1")
        .await
        .unwrap_err()
        .to_string();
    assert!(refusal.contains("1 unexpired dry-run"), "{refusal}");
    assert!(refusal.contains("--retire-dry-run-intent"), "{refusal}");
    // Other POPs are not this controller's intent.
    check_enforced_startup(repo.as_ref(), "other-pop")
        .await
        .unwrap();

    assert_eq!(
        retire_dry_run_intent(repo.as_ref(), "test1", None)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        retire_dry_run_intent(repo.as_ref(), "test1", None)
            .await
            .unwrap(),
        0,
        "single-shot: nothing left to retire"
    );
    check_enforced_startup(repo.as_ref(), "test1")
        .await
        .unwrap();
    assert!(
        dry_run_intent(repo.as_ref(), "test1")
            .await
            .unwrap()
            .is_empty()
    );
    let retired = repo
        .get_mitigation(simulated.mitigation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retired.status, MitigationStatus::Withdrawn);
    assert_eq!(
        repo.get_mitigation(enforced.mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        MitigationStatus::Active,
        "enforced intent is untouched"
    );
    let audit = repo
        .list_audit(&prefixd::db::ListParams {
            limit: 100,
            ..Default::default()
        })
        .await
        .unwrap();
    let retirements: Vec<_> = audit
        .iter()
        .filter(|entry| entry.actor_id.as_deref() == Some("retire-dry-run-intent"))
        .collect();
    assert_eq!(retirements.len(), 1);
    assert_eq!(retirements[0].action, "withdraw");
    assert_eq!(
        retirements[0].target_id.as_deref(),
        Some(simulated.mitigation_id.to_string().as_str())
    );

    // Zero speaker calls: retirement had no speaker, and enforced repair skips it.
    let state = enforced_state(repo.clone(), speaker.clone());
    prefixd::scheduler::ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false)
        .with_app_state(state)
        .reconcile()
        .await
        .unwrap();
    let announced = speaker.list_active().await.unwrap();
    assert_eq!(announced.len(), 1, "only enforced intent is repaired");
    assert_eq!(announced[0].nlri.dst_prefix, "203.0.113.11/32");
}

#[tokio::test]
async fn test_enforced_detector_event_does_not_extend_a_dry_run_simulation() {
    let repo = Arc::new(MockRepository::new());
    let speaker = Arc::new(MockAnnouncer::new());
    let simulated = dry_run_row(600);
    repo.insert_mitigation(&simulated).await.unwrap();
    let app = create_test_router(enforced_state(repo.clone(), speaker.clone()));
    let event = serde_json::json!({"event_id":"enforced-over-simulation", "timestamp":chrono::Utc::now(), "source":"test", "victim_ip":"203.0.113.10", "vector":"udp_flood", "pps":50000, "top_dst_ports":[53], "confidence":0.9});
    let response = app
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
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("--retire-dry-run-intent"));
    assert!(
        repo.find_ban_event_by_external_id("test", "enforced-over-simulation")
            .await
            .unwrap()
            .is_none(),
        "the detector event stays retryable"
    );
    let unchanged = repo
        .get_mitigation(simulated.mitigation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.expires_at, simulated.expires_at);
    assert_eq!(speaker.announced_count().await, 0);
}

#[tokio::test]
async fn test_mitigation_responses_expose_origin_mode_with_null_for_unknown() {
    use prefixd::config::OperationMode;
    let repo = Arc::new(MockRepository::new());
    let mut rows = Vec::new();
    for (i, mode) in [
        Some(OperationMode::DryRun),
        Some(OperationMode::Enforced),
        None,
    ]
    .into_iter()
    .enumerate()
    {
        let mut row = dry_run_row(600);
        row.match_criteria.dst_prefix = format!("203.0.113.{}/32", 20 + i);
        row.scope_hash = row.match_criteria.compute_scope_hash();
        row.origin_mode = mode;
        repo.insert_mitigation(&row).await.unwrap();
        rows.push(row);
    }
    let app = create_test_router(enforced_state(repo, Arc::new(MockAnnouncer::new())));
    let get = |uri: String| {
        let app = app.clone();
        async move {
            let response = app
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()
        }
    };

    let list = get("/v1/mitigations".into()).await;
    for (row, expected) in rows.iter().zip([
        serde_json::json!("dry-run"),
        serde_json::json!("enforced"),
        serde_json::Value::Null,
    ]) {
        let id = row.mitigation_id.to_string();
        let item = list["mitigations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["mitigation_id"] == id.as_str())
            .unwrap();
        // Unknown origin is an explicit null, not an omitted field.
        assert_eq!(item.get("origin_mode"), Some(&expected), "list {id}");
        let detail = get(format!("/v1/mitigations/{id}")).await;
        assert_eq!(detail.get("origin_mode"), Some(&expected), "detail {id}");
    }

    let spec = get("/openapi.json".into()).await;
    assert!(
        spec["components"]["schemas"]["MitigationResponse"]["properties"]["origin_mode"]
            .is_object()
    );
}

/// `prefixdctl mitigations list/get/withdraw` show a blackhole's route and withdraw it
/// by ID with an Operator bearer token, which cannot create one (ADR 027).
#[tokio::test]
async fn prefixdctl_lists_gets_and_withdraws_a_blackhole() {
    use prefixd::domain::{
        ActionParams, ActionType, MatchCriteria, MitigationIntent, MitigationStatus,
    };
    const TOKEN: &str = "cli-blackhole-token";
    let repo = Arc::new(MockRepository::new());
    let speaker = Arc::new(MockAnnouncer::new());
    let mut settings = test_settings();
    settings.mode = prefixd::config::OperationMode::Enforced;
    settings.http.auth.mode = AuthMode::Credentials;
    settings.blackhole.enabled = true;
    settings.blackhole.next_hop_ipv4 = Some("192.0.2.66".parse().unwrap());
    settings.blackhole.communities = vec!["64512:7".into()];
    let mut state = AppState::new(
        settings,
        test_inventory(),
        test_playbooks(),
        repo.clone(),
        speaker.clone(),
        ".".into(),
    )
    .unwrap();
    let cached = Arc::get_mut(&mut state).unwrap();
    cached.settings.http.auth.mode = AuthMode::Bearer;
    cached.bearer_token = Some(TOKEN.into());
    let mitigation = prefixd::guardrails::admit_blackhole(
        repo.as_ref(),
        &state.settings,
        &test_inventory(),
        MitigationIntent {
            event_id: uuid::Uuid::new_v4(),
            customer_id: None,
            service_id: None,
            pop: "test1".into(),
            match_criteria: MatchCriteria {
                dst_prefix: "203.0.113.10/32".into(),
                ..Default::default()
            },
            action_type: ActionType::Blackhole,
            action_params: ActionParams::default(),
            ttl_seconds: 600,
            reason: "manual blackhole".into(),
        },
        &prefixd::observability::CreationActor::Operator("admin".into()),
        speaker.as_ref(),
        None,
    )
    .await
    .unwrap()
    .mitigation;
    let id = mitigation.mitigation_id.to_string();
    let blackholes = prefixd::bgp::FlowSpecAnnouncer::blackhole(speaker.as_ref()).unwrap();
    assert_eq!(blackholes.list_blackholes().await.unwrap().routes.len(), 1);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, create_test_router(state))
            .await
            .unwrap();
    });
    let cli = |args: &[&str]| {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_prefixdctl"));
        command.args(["--api", &api, "--token", TOKEN]).args(args);
        let label = args.join(" ");
        async move {
            let output = command.output().await.unwrap();
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert!(
                output.status.success(),
                "{label}\n{stdout}\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
            stdout
        }
    };

    let list = cli(&["mitigations", "list"]).await;
    let row = list.lines().find(|line| line.starts_with(&id)).unwrap();
    assert!(
        row.contains("203.0.113.10") && row.contains("blackhole"),
        "{list}"
    );
    let get = cli(&["mitigations", "get", &id]).await;
    for line in [
        "Action:         blackhole",
        "Blackhole:      drops all traffic to the victim",
        "Next hop:       192.0.2.66",
        "Communities:    64512:7 65535:666",
    ] {
        assert!(get.contains(line), "{line}\n{get}");
    }
    let json: serde_json::Value =
        serde_json::from_str(&cli(&["--format", "json", "mitigations", "get", &id]).await).unwrap();
    assert_eq!(json["blackhole"]["next_hop"], "192.0.2.66");
    let withdrawn = cli(&[
        "mitigations",
        "withdraw",
        &id,
        "--reason",
        "attack over",
        "--operator",
        "cli",
    ])
    .await;
    assert!(withdrawn.contains(&format!("Withdrawn mitigation {id}")));
    assert_eq!(
        repo.get_mitigation(mitigation.mitigation_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        MitigationStatus::Withdrawn
    );
    assert!(
        blackholes
            .list_blackholes()
            .await
            .unwrap()
            .routes
            .is_empty()
    );
    server.abort();
}
