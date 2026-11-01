mod common;
#[cfg(all(feature = "bgp-rustbgpd", feature = "test-utils", target_os = "linux"))]
#[path = "common/rustbgpd.rs"]
mod speaker_fixture;
use chrono::Utc;
use prefixd::{
    bgp::{GuardedRule, GuardedStamp},
    config::OperationMode,
    domain::*,
    scrubber::*,
};
use uuid::Uuid;

fn profile() -> ScrubberProfile {
    ScrubberProfile {
        id: "fixture".into(),
        revision: "v1".into(),
        ipv4_target: Some("192.0.2.99".parse().unwrap()),
        ipv6_target: None,
        destinations: vec!["203.0.113.0/24".parse().unwrap()],
        router_peers: vec!["192.0.2.2".into()],
        policy_binding: "fixture-policy".into(),
        qualification_receipt: "isolated persistence fixture".into(),
        readiness_url: "https://127.0.0.1:1/readiness".into(),
        readiness_token_env: "PATH".into(),
        max_ttl_seconds: 300,
        max_active: 10,
        max_new_per_minute: 20,
        reserved_targets: vec![],
    }
}
fn diversion(pop: &str, host: u8) -> Diversion {
    Diversion {
        id: Uuid::new_v4(),
        controller_incarnation: Uuid::new_v4(),
        controller_epoch: 0,
        pop: pop.into(),
        customer_id: "cust_integration".into(),
        profile: profile().snapshot(),
        rule: GuardedRule {
            nlri: FlowSpecNlri {
                dst_prefix: format!("203.0.113.{host}/32"),
                protocol: Some(6),
                dst_ports: vec![443],
                ..Default::default()
            },
            target: "192.0.2.99".parse().unwrap(),
            owner: "prefixd.scrubber.fixture".into(),
            revision: 1,
        },
        created_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::seconds(60),
        actor: "fixture-admin".into(),
        reason: "isolated persistence control".into(),
        dry_run: false,
        status: DiversionStatus::Pending,
        withdrawal_reason: None,
        withdrawal_actor: None,
        windows: vec![],
        generation: None,
        last_error: None,
        export_observation: None,
    }
}
fn ordinary(pop: &str, prefix: &str) -> Mitigation {
    let mut row = Mitigation::from_intent(
        MitigationIntent {
            event_id: Uuid::new_v4(),
            customer_id: Some("cust_integration".into()),
            service_id: None,
            pop: pop.into(),
            match_criteria: MatchCriteria {
                dst_prefix: prefix.into(),
                protocol: Some(6),
                dst_ports: vec![443],
                ..Default::default()
            },
            action_type: ActionType::Discard,
            action_params: ActionParams::default(),
            ttl_seconds: 60,
            reason: "ordinary control".into(),
        },
        prefix.into(),
        AttackVector::Unknown,
    );
    row.origin_mode = Some(OperationMode::Enforced);
    row
}

#[tokio::test]
async fn postgres_serializes_diversion_conflicts_and_preserves_immutable_snapshots() {
    let context = common::TestContext::new().await;
    let pop = &context.state.settings.pop;
    let target = SpeakerTarget::from_config(&context.state.settings.bgp).unwrap();
    context
        .repo
        .register_speaker_target(pop, &target, false)
        .await
        .unwrap();
    let intent = diversion(pop, 40);
    let normal = ordinary(pop, "203.0.113.40/32");
    let profile = profile();
    let quotas = &context.state.settings.quotas;
    let actor = prefixd::observability::CreationActor::Operator("fixture-admin".into());
    let (redirect, normal_result) = tokio::join!(
        context.repo.admit_diversion(&intent, &profile, quotas),
        context
            .repo
            .admit_mitigation(&normal, quotas, &context.state.settings.blackhole, &actor)
    );
    assert_ne!(
        redirect.is_ok(),
        normal_result.is_ok(),
        "exactly one concurrent victim owner"
    );
    if let Err(error) = redirect {
        assert_eq!(error.status_code(), axum::http::StatusCode::CONFLICT);
    }
    if let Err(error) = normal_result {
        assert_eq!(error.status_code(), axum::http::StatusCode::CONFLICT);
    }
    let mut row = context
        .repo
        .admit_diversion(&diversion(pop, 41), &profile, quotas)
        .await
        .unwrap();
    assert!(row.rule.revision > 0);
    let mut changed = row.clone();
    changed.rule.target = "192.0.2.98".parse().unwrap();
    assert!(
        context
            .repo
            .save_diversion(&changed, "invalid_retarget")
            .await
            .is_err()
    );
    let retained = context.repo.get_diversion(row.id).await.unwrap().unwrap();
    assert_eq!(retained.rule.target, row.rule.target);
    row.windows.push(GuardedStamp {
        incarnation: 1,
        sequence: 1,
    });
    row.status = DiversionStatus::Withdrawing;
    row.withdrawal_reason = Some("fixture withdrawal".into());
    context
        .repo
        .save_diversion(&row, "scrubber_withdraw_requested")
        .await
        .unwrap();
    let restored = context.repo.get_diversion(row.id).await.unwrap().unwrap();
    assert_eq!(restored.windows, row.windows);
    assert_eq!(restored.status, DiversionStatus::Withdrawing);
    let cidr = ordinary(pop, "203.0.113.0/24");
    let error = context
        .repo
        .admit_mitigation(&cidr, quotas, &context.state.settings.blackhole, &actor)
        .await
        .unwrap_err();
    assert_eq!(
        error.status_code(),
        axum::http::StatusCode::CONFLICT,
        "CIDR cannot overlap pending diversion"
    );
    prefixd::db::init_postgres_pool(&context.state.settings.storage.connection_string)
        .await
        .unwrap()
        .close()
        .await;
    let restored = context.repo.get_diversion(row.id).await.unwrap().unwrap();
    assert_eq!(restored.rule.revision, row.rule.revision);
    assert_eq!(restored.windows, row.windows);
    let audits: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE target_id=$1 AND action='scrubber_admit'",
    )
    .bind(row.id.to_string())
    .fetch_one(&context.pool)
    .await
    .unwrap();
    assert_eq!(audits, 1, "admission and audit commit together");
}

#[cfg(all(feature = "bgp-rustbgpd", feature = "test-utils", target_os = "linux"))]
#[tokio::test]
#[ignore = "requires isolated pinned Linux Docker speaker; run scripts/test-rustbgpd.sh"]
async fn released_controller_lifecycle_uses_https_postgres_and_independent_guarded_leases() {
    use axum::{
        Router,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::get,
    };
    use prefixd::{
        AppState,
        bgp::GuardedFlowSpecSpeaker,
        fence::{ControllerFence, FencedAnnouncer},
    };
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering::SeqCst},
        },
        time::Duration,
    };

    if std::env::var("PREFIXD_RUSTBGPD_TEST_VERSION").unwrap_or("0.81.0".into()) != "0.81.0" {
        return;
    }
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let database = common::TestContext::new().await;
    let fixture = speaker_fixture::Speaker::start().await;
    let speaker = Arc::new(fixture.connect().await);
    let healthy_a = Arc::new(AtomicBool::new(true));
    let readiness_a = healthy_a.clone();
    let expected_token = std::env::var("PREFIXD_RUSTBGPD_TEST_TOKEN").unwrap();
    let monitor = Router::new().route("/{profile}", get(move |axum::extract::Path(id): axum::extract::Path<String>, headers: HeaderMap| {
        let healthy = readiness_a.clone();
        let token = expected_token.clone();
        async move {
            if headers.get("authorization").and_then(|h| h.to_str().ok()) != Some(format!("Bearer {token}").as_str()) {
                return StatusCode::UNAUTHORIZED.into_response();
            }
            axum::Json(serde_json::json!({"profile":id,"revision":"v1","policy_binding":"fixture-policy","observed_at":Utc::now(),"valid_until":Utc::now()+chrono::Duration::seconds(8),"process_ready":id!="a" || healthy.load(SeqCst),"filters_ready":true,"target_reachable":true,"capacity_available":true,"canary_passed":true,"export_isolated":true})).into_response()
        }
    }));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        include_bytes!("../src/bgp/testdata/transport-server-cert.pem").to_vec(),
        include_bytes!("../src/bgp/testdata/transport-server-key.pem").to_vec(),
    )
    .await
    .unwrap();
    let handle = axum_server::Handle::new();
    let server = tokio::spawn(
        axum_server::from_tcp_rustls(listener, tls)
            .unwrap()
            .handle(handle.clone())
            .serve(monitor.into_make_service()),
    );
    let mut settings = database.state.settings.clone();
    settings.mode = OperationMode::Enforced;
    settings.bgp.mode = prefixd::config::BgpMode::Rustbgpd;
    settings.bgp.rustbgpd = Some(fixture.config.clone());
    settings.scrubber = ScrubberConfig {
        enabled: true,
        readiness_ca_cert: Some(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("src/bgp/testdata/transport-ca.pem"),
        ),
        profiles: ["a", "b"]
            .into_iter()
            .map(|id| {
                let mut profile = profile();
                profile.id = id.into();
                profile.readiness_url = format!("https://{address}/{id}");
                profile.readiness_token_env = "PREFIXD_RUSTBGPD_TEST_TOKEN".into();
                profile
            })
            .collect(),
    };
    let binding = database
        .repo
        .register_speaker_target(
            &settings.pop,
            &SpeakerTarget::from_config(&settings.bgp).unwrap(),
            false,
        )
        .await
        .unwrap();
    let fence = Arc::new(ControllerFence::new(true));
    let announcer = Arc::new(FencedAnnouncer::new(speaker.clone(), fence.clone()));
    let state = AppState::new(
        settings.clone(),
        common::test_inventory(),
        common::test_playbooks(),
        database.repo.clone(),
        announcer.clone(),
        std::path::PathBuf::new(),
    )
    .unwrap()
    .with_speaker_binding(binding.clone())
    .unwrap()
    .with_fence(fence.clone())
    .unwrap();
    ScrubberController::check_startup(&state).await.unwrap();
    state.scrubber.tick(&state).await.unwrap();
    assert!(
        !state.scrubber.profiles().await["a"].armed,
        "startup never arms"
    );
    for id in ["a", "b"] {
        state
            .scrubber
            .arm(&state, id, "v1", "fixture-admin")
            .await
            .unwrap();
    }
    let mut admissions = Vec::new();
    for (id, host) in [("a", 50), ("b", 51)] {
        let mut request = prefixd::scrubber::api::CreateDiversion {
            profile: id.into(),
            scope: FlowSpecNlri {
                dst_prefix: format!("203.0.113.{host}/32"),
                protocol: Some(6),
                dst_ports: vec![443],
                ..Default::default()
            },
            ttl_seconds: 180,
            reason: "isolated control-plane lifecycle".into(),
            confirmation: None,
        };
        let preview = state
            .scrubber
            .prepare(&state, &request, "fixture-admin")
            .await
            .unwrap();
        assert_eq!(
            speaker.guarded_inventory().await.unwrap().len(),
            admissions.len(),
            "preview sends no mutation"
        );
        request.confirmation = Some(ScrubberController::confirmation(&preview).unwrap());
        let row = state
            .scrubber
            .create(&state, &request, "fixture-admin")
            .await
            .unwrap();
        assert_eq!(
            row.status,
            DiversionStatus::Active,
            "real released speaker read-back"
        );
        assert!(row.export_observation.is_some());
        assert!(!row.windows.is_empty());
        admissions.push(row);
    }
    assert_ne!(admissions[0].rule.owner, admissions[1].rule.owner);
    healthy_a.store(false, SeqCst);
    state.scrubber.tick(&state).await.unwrap();
    assert!(!state.scrubber.profiles().await["a"].armed);
    assert!(state.scrubber.profiles().await["b"].armed);
    assert_eq!(
        database
            .repo
            .get_diversion(admissions[0].id)
            .await
            .unwrap()
            .unwrap()
            .status,
        DiversionStatus::Withdrawing
    );
    assert!(
        state
            .scrubber
            .arm(&state, "a", "v1", "fixture-admin")
            .await
            .is_err(),
        "pending absence is insufficient for re-arm"
    );
    for _ in 0..16 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        state.scrubber.tick(&state).await.unwrap();
    }
    let inventory = speaker.guarded_inventory().await.unwrap();
    assert!(!inventory.has_key(&admissions[0].rule.nlri));
    assert!(
        inventory
            .iter()
            .any(|entry| entry.rule.same_admission(&admissions[1].rule)),
        "healthy profile continues after failed profile drains"
    );
    assert_eq!(
        database
            .repo
            .get_diversion(admissions[0].id)
            .await
            .unwrap()
            .unwrap()
            .status,
        DiversionStatus::Withdrawn
    );
    drop(state);
    // Stop every controller mutation. The released daemon must expire the
    // remaining profile's local rule without losing its durable obligation.
    tokio::time::sleep(Duration::from_secs(32)).await;
    assert!(
        speaker.guarded_inventory().await.unwrap().is_empty(),
        "controller-stop lease expiry is independent of reconciliation"
    );
    assert_eq!(
        database
            .repo
            .list_diversions(&settings.pop)
            .await
            .unwrap()
            .len(),
        1,
        "local expiry alone cannot release durable victim exclusion"
    );
    let restarted = AppState::new(
        settings,
        common::test_inventory(),
        common::test_playbooks(),
        database.repo.clone(),
        announcer,
        std::path::PathBuf::new(),
    )
    .unwrap()
    .with_speaker_binding(binding)
    .unwrap()
    .with_fence(fence)
    .unwrap();
    ScrubberController::check_startup(&restarted).await.unwrap();
    restarted.scrubber.tick(&restarted).await.unwrap();
    assert!(
        !restarted.scrubber.profiles().await["b"].armed,
        "restart drains rather than replaying retained intent"
    );
    for _ in 0..16 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        restarted.scrubber.tick(&restarted).await.unwrap();
    }
    assert!(speaker.guarded_inventory().await.unwrap().is_empty());
    assert!(
        database
            .repo
            .list_diversions(&restarted.settings.pop)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        !restarted.scrubber.profiles().await["b"].armed,
        "health recovery cannot re-arm"
    );
    handle.graceful_shutdown(Some(Duration::from_secs(1)));
    tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    fixture.container.rm().await.unwrap();
}
