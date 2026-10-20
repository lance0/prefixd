#![cfg(all(feature = "bgp-rustbgpd", feature = "test-utils", target_os = "linux"))]
mod common;
#[path = "common/speaker_contract.rs"]
mod contract;
#[path = "common/rustbgpd.rs"]
mod fixture;
use prefixd::{
    bgp::FlowSpecAnnouncer,
    domain::{FlowSpecAction, FlowSpecNlri, FlowSpecRule},
};

use prefixd::bgp::{DaemonHealthObserver, FlowSpecReader, FlowSpecWriter, PeerObserver};
fn fixture_settings(fixture: &fixture::Speaker, pop: &str) -> prefixd::config::Settings {
    let mut settings = common::test_settings();
    settings.pop = pop.into();
    settings.mode = prefixd::config::OperationMode::Enforced;
    settings.bgp.mode = prefixd::config::BgpMode::Rustbgpd;
    settings.bgp.rustbgpd = Some(prefixd::config::RustBgpdConfig {
        endpoint: fixture.endpoint.clone(),
        bearer_token_env: "PREFIXD_RUSTBGPD_TEST_TOKEN".into(),
        ca_cert_path: None,
        ..Default::default()
    });
    settings
}

fn rule() -> FlowSpecRule {
    FlowSpecRule::new(
        FlowSpecNlri {
            dst_prefix: "192.0.2.231/32".into(),
            protocol: Some(6),
            dst_ports: vec![443, 80],
            ..Default::default()
        },
        FlowSpecAction::discard(),
    )
}

#[tokio::test]
#[ignore = "requires Docker on Linux; run scripts/test-rustbgpd.sh"]
async fn live_rustbgpd_controller_roundtrip() {
    let fixture = fixture::Speaker::start().await;
    let speaker = fixture.connect().await;
    contract::run_readable_contract(&speaker).await.unwrap();
    let health = speaker.daemon_health().await.unwrap();
    let expected = std::env::var("PREFIXD_RUSTBGPD_TEST_VERSION").unwrap_or("0.78.0".into());
    assert_eq!(health.version.as_deref(), Some(expected.as_str()));
    assert!(health.ready);
}

#[tokio::test]
#[ignore = "requires Docker on Linux; run scripts/test-rustbgpd.sh"]
async fn live_rustbgpd_amplification_components_inject_read_and_delete() {
    let fixture = fixture::Speaker::start().await;
    let speaker = fixture.connect().await;
    let version = std::env::var("PREFIXD_RUSTBGPD_TEST_VERSION").unwrap_or("0.78.0".into());
    // The daemon's own rendering of the injected components (ADR 028 read-back column).
    let rules = contract::amplification_rules();
    for rule in &rules {
        speaker.announce(rule).await.unwrap();
    }
    for family in [3, 4] {
        let mut observed: Vec<Vec<(u32, String)>> = fixture
            .received_flow_spec(family, "0.0.0.0")
            .await
            .received_routes
            .into_iter()
            .map(|row| {
                row.route.unwrap().components[1..]
                    .iter()
                    .map(|c| (c.r#type, c.value.clone()))
                    .collect()
            })
            .collect();
        observed.sort();
        println!("rustbgpd {version} family {family} read-back: {observed:?}");
        let protocol = (3, "==17".to_string());
        assert_eq!(
            observed,
            [
                vec![protocol.clone()],
                vec![
                    protocol.clone(),
                    (6, "==11211".into()),
                    (10, ">=1000 & <=65535".into())
                ],
                vec![protocol.clone(), (6, "==53, ==123, ==389".into())],
                vec![protocol, (12, "0x0002/match".into())],
            ]
        );
    }
    for rule in &rules {
        speaker.withdraw(rule).await.unwrap();
    }
    contract::run_amplification_contract(&speaker)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires Docker on Linux; run scripts/test-rustbgpd.sh"]
async fn live_rustbgpd_blackhole_inject_read_delete_and_restart_loss() {
    use prefixd::bgp::BlackholeRoute;
    let fixture = fixture::Speaker::start().await;
    let speaker = fixture.connect().await;
    let capabilities = (&speaker as &dyn FlowSpecAnnouncer).capabilities();
    assert!(capabilities.blackhole && !capabilities.blackhole_lease);
    let blackhole = speaker.blackhole().unwrap();
    let empty = prefixd::bgp::BlackholeInventory::default();
    assert_eq!(blackhole.list_blackholes().await.unwrap(), empty);
    let route = |prefix: &str, next_hop: &str, extra: u32| {
        BlackholeRoute::new(
            prefix.parse().unwrap(),
            next_hop.parse().unwrap(),
            vec![(64512 << 16) | extra],
            vec![[64512, 666, extra]],
        )
        .unwrap()
    };
    let routes = [
        route("192.0.2.240/32", "192.0.2.66", 1),
        route("2001:db8::240/128", "2001:db8::66", 1),
    ];
    for expected in &routes {
        blackhole.announce_blackhole(expected).await.unwrap();
        // Retained local intent: the exact prefix, next hop and communities.
        assert!(
            blackhole
                .list_blackholes()
                .await
                .unwrap()
                .routes
                .contains(expected)
        );
        let next_hop = if expected.prefix().addr().is_ipv4() {
            "192.0.2.67"
        } else {
            "2001:db8::67"
        };
        let replaced = route(&expected.prefix().to_string(), next_hop, 2);
        blackhole.announce_blackhole(&replaced).await.unwrap();
        let listed = blackhole.list_blackholes().await.unwrap();
        assert_eq!(
            listed
                .routes
                .iter()
                .filter(|r| r.prefix() == expected.prefix())
                .collect::<Vec<_>>(),
            [&replaced]
        );
        blackhole
            .withdraw_blackhole(&expected.prefix(), "")
            .await
            .unwrap();
        assert_eq!(blackhole.list_blackholes().await.unwrap(), empty);
        // The daemon reports NOT_FOUND for the absent path.
        blackhole
            .withdraw_blackhole(&expected.prefix(), "")
            .await
            .unwrap();
    }

    // More routes than one page, so the walk follows the daemon's own tokens.
    let many: Vec<_> = (0..130)
        .map(|host| route(&format!("198.51.100.{host}/32"), "192.0.2.66", 1))
        .collect();
    for route in &many {
        blackhole.announce_blackhole(route).await.unwrap();
    }
    let listed = blackhole.list_blackholes().await.unwrap();
    assert_eq!(listed.routes.len(), many.len());
    assert!(many.iter().all(|route| listed.routes.contains(route)));
    for route in &many {
        blackhole
            .withdraw_blackhole(&route.prefix(), "")
            .await
            .unwrap();
    }

    // Injected paths are process-local: a restart loses them, and the read says so.
    for expected in &routes {
        blackhole.announce_blackhole(expected).await.unwrap();
    }
    // Another tool's local injections are reported as unrecognized, never an error.
    for (prefix, path_id, communities) in [
        ("192.0.2.250", 0, vec![]),
        ("192.0.2.240", 7, vec![prefixd::bgp::BLACKHOLE_COMMUNITY]),
    ] {
        fixture
            .add_raw_path(prefixd::bgp::rustbgpd_pb::AddPathRequest {
                prefix: prefix.into(),
                prefix_length: 32,
                next_hop: "192.0.2.66".into(),
                communities,
                path_id,
                ..Default::default()
            })
            .await;
    }
    let listed = blackhole.list_blackholes().await.unwrap();
    assert_eq!(listed.routes.len(), 2);
    assert!(routes.iter().all(|route| listed.routes.contains(route)));
    let mut foreign: Vec<_> = listed
        .unrecognized
        .iter()
        .map(|row| (row.prefix.to_string(), row.reason))
        .collect();
    foreign.sort();
    assert_eq!(
        foreign,
        [
            ("192.0.2.240/32".to_string(), "nonzero path_id"),
            (
                "192.0.2.250/32".to_string(),
                "missing BLACKHOLE or non-canonical communities"
            ),
        ]
    );
    fixture.container.stop_with_timeout(Some(0)).await.unwrap();
    assert!(blackhole.list_blackholes().await.is_err());
    fixture.container.start().await.unwrap();
    fixture.ready().await;
    assert_eq!(blackhole.list_blackholes().await.unwrap(), empty);
}

#[tokio::test]
#[ignore = "requires Docker on Linux; run scripts/test-rustbgpd.sh"]
async fn faithful_policing_and_historical_action_withdrawal() {
    let fixture = fixture::Speaker::start().await;
    let speaker = fixture.connect().await;
    contract::run_action_contract(&speaker).await.unwrap();
}

#[tokio::test]
#[ignore = "requires Docker on Linux; run scripts/test-rustbgpd.sh"]
async fn action_drift_reconciles_exactly_once() {
    let fixture = fixture::Speaker::start().await;
    let speaker = std::sync::Arc::new(fixture.connect().await);
    let settings = fixture_settings(&fixture, "action-drift-contract");
    contract::run_action_reconciliation_contract(speaker, &settings.bgp)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires Docker on Linux; run scripts/test-rustbgpd.sh"]
async fn live_rustbgpd_ttl_reconciliation() {
    use prefixd::{
        db::{MockRepository, RepositoryTrait},
        domain::{
            ActionParams, ActionType, AttackVector, MatchCriteria, Mitigation, MitigationIntent,
            MitigationStatus,
        },
        scheduler::ReconciliationLoop,
    };
    use std::sync::Arc;

    let fixture = fixture::Speaker::start().await;
    let speaker = Arc::new(fixture.connect().await);
    let repo = Arc::new(MockRepository::new());
    let settings = fixture_settings(&fixture, "live-test");
    let binding = repo
        .register_speaker_target(
            &settings.pop,
            &prefixd::domain::SpeakerTarget::from_config(&settings.bgp).unwrap(),
            false,
        )
        .await
        .unwrap();
    let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false)
        .with_speaker_binding(binding);
    for (ip, length) in [("192.0.2.232", 32), ("2001:db8::232", 128)] {
        let mut mitigation = Mitigation::from_intent(
            MitigationIntent {
                event_id: uuid::Uuid::new_v4(),
                customer_id: None,
                service_id: None,
                pop: "live-test".into(),
                match_criteria: MatchCriteria {
                    dst_prefix: format!("{ip}/{length}"),
                    protocol: Some(17),
                    dst_ports: vec![53],
                    ..Default::default()
                },
                action_type: ActionType::Discard,
                action_params: ActionParams::default(),
                ttl_seconds: 30,
                reason: "live TTL test".into(),
            },
            ip.into(),
            AttackVector::UdpFlood,
        );
        mitigation.activate();
        mitigation.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
        repo.insert_mitigation(&mitigation).await.unwrap();
        let rule = FlowSpecRule::new(
            (&mitigation.match_criteria).into(),
            FlowSpecAction::discard(),
        );
        speaker.announce(&rule).await.unwrap();
        assert!(
            speaker
                .list_active()
                .await
                .unwrap()
                .iter()
                .any(|r| r.nlri_hash() == rule.nlri_hash())
        );
        reconciler.reconcile().await.unwrap();
        assert_eq!(
            repo.get_mitigation(mitigation.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            MitigationStatus::Expired
        );
        assert!(
            !speaker
                .list_active()
                .await
                .unwrap()
                .iter()
                .any(|r| r.nlri_hash() == rule.nlri_hash())
        );
    }
}

struct PollingSpeaker {
    inner: std::sync::Arc<prefixd::bgp::RustBgpdAnnouncer>,
    inventory_gate: tokio::sync::RwLock<()>,
    observed: tokio::sync::Notify,
}

impl FlowSpecAnnouncer for PollingSpeaker {
    fn backend(&self) -> &'static str {
        "rustbgpd"
    }
    fn reader(&self) -> Option<&dyn FlowSpecReader> {
        Some(self)
    }
    fn peer_observer(&self) -> Option<&dyn PeerObserver> {
        Some(self)
    }
}

#[async_trait::async_trait]
impl FlowSpecWriter for PollingSpeaker {
    fn matches_nlri(
        &self,
        left: &prefixd::domain::FlowSpecNlri,
        right: &prefixd::domain::FlowSpecNlri,
    ) -> prefixd::error::Result<bool> {
        self.inner.matches_nlri(left, right)
    }

    async fn announce(&self, rule: &FlowSpecRule) -> prefixd::error::Result<()> {
        self.inner.announce(rule).await
    }
    async fn withdraw(&self, rule: &FlowSpecRule) -> prefixd::error::Result<()> {
        self.inner.withdraw(rule).await
    }
}
#[async_trait::async_trait]
impl FlowSpecReader for PollingSpeaker {
    async fn list_active(&self) -> prefixd::error::Result<Vec<FlowSpecRule>> {
        let _gate = self.inventory_gate.read().await;
        self.inner.list_active().await
    }
}
#[async_trait::async_trait]
impl PeerObserver for PollingSpeaker {
    async fn session_status(&self) -> prefixd::error::Result<Vec<prefixd::bgp::PeerStatus>> {
        let result = self.inner.session_status().await;
        self.observed.notify_one();
        result
    }
}

#[tokio::test]
#[ignore = "requires Docker on Linux; run scripts/test-rustbgpd.sh"]
async fn live_rustbgpd_restart_recovers_with_the_same_client_and_desired_state() {
    use prefixd::{
        db::{MockRepository, RepositoryTrait},
        domain::{
            ActionParams, ActionType, AttackVector, MatchCriteria, Mitigation, MitigationIntent,
            MitigationStatus,
        },
        observability::metrics,
        scheduler::ReconciliationLoop,
    };
    use std::{sync::Arc, time::Duration};
    let fixture = fixture::Speaker::start().await;
    let speaker = Arc::new(fixture.connect().await);
    let repo = Arc::new(MockRepository::new());
    let settings = fixture_settings(&fixture, "restart-test");
    let binding = repo
        .register_speaker_target(
            &settings.pop,
            &prefixd::domain::SpeakerTarget::from_config(&settings.bgp).unwrap(),
            false,
        )
        .await
        .unwrap();
    let mut desired = Vec::new();
    for (ip, length, action_type, rate_bps) in [
        ("192.0.2.233", 32, ActionType::Discard, None),
        ("2001:db8::233", 128, ActionType::Police, Some(8_000_000)),
    ] {
        let mut mitigation = Mitigation::from_intent(
            MitigationIntent {
                event_id: uuid::Uuid::new_v4(),
                customer_id: None,
                service_id: None,
                pop: "restart-test".into(),
                match_criteria: MatchCriteria {
                    dst_prefix: format!("{ip}/{length}"),
                    protocol: Some(17),
                    dst_ports: vec![53],
                    ..Default::default()
                },
                action_type,
                action_params: ActionParams {
                    rate_bps,
                    ..Default::default()
                },
                ttl_seconds: 300,
                reason: "restart test".into(),
            },
            ip.into(),
            AttackVector::UdpFlood,
        );
        mitigation.activate();
        repo.insert_mitigation(&mitigation).await.unwrap();
        let rule = FlowSpecRule::new(
            (&mitigation.match_criteria).into(),
            FlowSpecAction {
                action_type,
                rate_bps,
            },
        );
        speaker.announce(&rule).await.unwrap();
        desired.push((mitigation, rule));
    }
    let mut foreign = rule();
    foreign.nlri.dst_prefix = "198.51.100.233/32".into();
    speaker.announce(&foreign).await.unwrap();
    let observed = Arc::new(PollingSpeaker {
        inner: speaker.clone(),
        inventory_gate: tokio::sync::RwLock::new(()),
        observed: tokio::sync::Notify::new(),
    });
    let interval = Duration::from_secs(3);
    let reconciler = ReconciliationLoop::new(
        repo.clone(),
        observed.clone(),
        interval.as_secs() as u32,
        false,
    )
    .with_speaker_binding(binding.clone());
    let (shutdown, rx) = tokio::sync::broadcast::channel(1);
    let task = tokio::spawn(async move { reconciler.run(rx).await });
    tokio::time::timeout(interval, observed.observed.notified())
        .await
        .unwrap();
    assert_eq!(speaker.list_active().await.unwrap().len(), 3);

    // Hold only the poller while proving lost intent directly through the same channel.
    let gate = observed.inventory_gate.write().await;
    fixture.container.stop_with_timeout(Some(0)).await.unwrap();
    assert!(!matches!(
        tokio::time::timeout(Duration::from_secs(2), speaker.list_active()).await,
        Ok(Ok(_))
    ));
    fixture.container.start().await.unwrap();
    fixture.ready().await;
    assert!(speaker.list_active().await.unwrap().is_empty());
    for (mitigation, _) in &desired {
        assert_eq!(
            repo.get_mitigation(mitigation.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            MitigationStatus::Active
        );
    }
    speaker.announce(&foreign).await.unwrap();
    let before = metrics::RECONCILIATION_REPAIRS
        .with_label_values(&["success"])
        .get();
    drop(gate);
    tokio::time::timeout(interval, async {
        loop {
            let actual = speaker.list_active().await.unwrap();
            if actual.len() == 3 {
                for (_, expected) in &desired {
                    let restored = actual
                        .iter()
                        .find(|r| r.nlri_hash() == expected.nlri_hash())
                        .unwrap();
                    assert_eq!(restored.actions.len(), expected.actions.len());
                    for (actual, wanted) in restored.actions.iter().zip(&expected.actions) {
                        assert_eq!(actual.action_type, wanted.action_type);
                        assert_eq!(actual.rate_bps, wanted.rate_bps);
                    }
                }
                assert!(actual.iter().any(|r| r.nlri_hash() == foreign.nlri_hash()
                    && r.actions.len() == 1
                    && r.actions[0].action_type == foreign.actions[0].action_type
                    && r.actions[0].rate_bps == foreign.actions[0].rate_bps));
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("recovery within one configured interval after readiness");
    tokio::time::timeout(
        interval + Duration::from_secs(1),
        observed.observed.notified(),
    )
    .await
    .unwrap();
    // The following converged poll must not inject or withdraw anything.
    tokio::time::timeout(
        interval + Duration::from_secs(1),
        observed.observed.notified(),
    )
    .await
    .unwrap();
    assert_eq!(
        metrics::RECONCILIATION_REPAIRS
            .with_label_values(&["success"])
            .get(),
        before + 2.0
    );
    assert_eq!(speaker.list_active().await.unwrap().len(), 3);

    metrics::init_metrics();
    let state = prefixd::AppState::new(
        settings,
        common::test_inventory(),
        common::test_playbooks(),
        repo,
        speaker,
        ".".into(),
    )
    .unwrap()
    .with_speaker_binding(binding)
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, prefixd::api::create_test_router(state))
            .await
            .unwrap()
    });
    let scrape = reqwest::get(format!("http://{address}/metrics"))
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    for metric in [
        "prefixd_reconciliation_runs_total",
        "prefixd_reconciliation_repairs_total",
    ] {
        for status in ["success", "error"] {
            assert!(
                scrape.contains(&format!("{metric}{{status=\"{status}\"}}")),
                "missing actual status-labelled sample"
            );
        }
    }
    server.abort();
    shutdown.send(()).unwrap();
    task.await.unwrap();
}

async fn secure_controller_lifecycle(transport: &str) {
    use prefixd::bgp::RustBgpdAnnouncer;
    let fixture = fixture::Speaker::start_secure(transport).await;
    let speaker = fixture.connect().await;
    let mut rule = rule();
    for prefix in ["192.0.2.235/32", "2001:db8::235/128"] {
        rule.nlri.dst_prefix = prefix.into();
        speaker.announce(&rule).await.unwrap();
        assert!(
            speaker
                .list_active()
                .await
                .unwrap()
                .iter()
                .any(|active| active.nlri_hash() == rule.nlri_hash())
        );
        speaker.withdraw(&rule).await.unwrap();
    }
    if transport == "uds" {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let socket = fixture.config.unix_socket_path().unwrap().unwrap();
        let before = std::fs::metadata(&socket).unwrap();
        assert_eq!(before.mode() & 0o777, 0o600);
        eprintln!(
            "owner socket authenticated: uid={}, socket_mode={:o}",
            before.uid(),
            before.mode() & 0o777
        );
        assert_eq!(before.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(
            std::fs::metadata(socket.parent().unwrap()).unwrap().mode() & 0o777,
            0o700
        );
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660)).unwrap();
        assert!(RustBgpdAnnouncer::connect(&fixture.config).await.is_err());
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        fixture.container.stop_with_timeout(Some(0)).await.unwrap();
        fixture.container.start().await.unwrap();
        fixture.ready().await;
        assert_eq!(std::fs::metadata(&socket).unwrap().mode() & 0o777, 0o600);
        eprintln!(
            "owner socket recreated: before_inode={}, after_inode={}",
            before.ino(),
            std::fs::metadata(&socket).unwrap().ino()
        );
        speaker.announce(&rule).await.unwrap();
        speaker.withdraw(&rule).await.unwrap();
    } else {
        for invalid in ["missing", "wrong-ca", "wrong-client"] {
            let mut config = fixture.config.clone();
            match invalid {
                "missing" => {
                    config.client_cert_path = None;
                    config.client_key_path = None;
                    config.bearer_token_env = "PREFIXD_RUSTBGPD_TEST_TOKEN".into();
                }
                "wrong-ca" => {
                    config.ca_cert_path = Some(
                        concat!(
                            env!("CARGO_MANIFEST_DIR"),
                            "/src/bgp/testdata/server-cert.pem"
                        )
                        .into(),
                    )
                }
                "wrong-client" => {
                    config.client_cert_path = Some(
                        concat!(
                            env!("CARGO_MANIFEST_DIR"),
                            "/src/bgp/testdata/server-cert.pem"
                        )
                        .into(),
                    );
                    config.client_key_path = Some(
                        concat!(
                            env!("CARGO_MANIFEST_DIR"),
                            "/src/bgp/testdata/server-key.pem"
                        )
                        .into(),
                    );
                }
                _ => unreachable!(),
            }
            if let Ok(client) = RustBgpdAnnouncer::connect(&config).await {
                assert!(client.announce(&rule).await.is_err());
            }
        }
        fixture.assert_partial_tls_rejected().await;
    }
    assert!(speaker.list_active().await.unwrap().is_empty());
}

#[tokio::test]
#[ignore = "requires Docker on Linux; run scripts/test-rustbgpd.sh"]
async fn live_rustbgpd_owner_socket_lifecycle_and_recreation() {
    secure_controller_lifecycle("uds").await;
}

#[tokio::test]
#[ignore = "requires Docker on Linux; run scripts/test-rustbgpd.sh"]
async fn live_rustbgpd_native_mtls_lifecycle_and_rejected_credentials() {
    secure_controller_lifecycle("mtls").await;
}

#[tokio::test]
#[ignore = "requires Docker on Linux; run scripts/test-rustbgpd.sh"]
async fn live_rustbgpd_blackhole_enforced_lifecycle_restart_repair_and_expiry() {
    use prefixd::{
        config::{Customer, Inventory, PolicyProfile},
        db::{MockRepository, RepositoryTrait},
        domain::{ActionParams, ActionType, MatchCriteria, MitigationIntent, MitigationStatus},
        scheduler::ReconciliationLoop,
    };
    use std::sync::Arc;

    let fixture = fixture::Speaker::start().await;
    let speaker = Arc::new(fixture.connect().await);
    let repo = Arc::new(MockRepository::new());
    let mut settings = fixture_settings(&fixture, "blackhole-live");
    settings.blackhole = prefixd::config::BlackholeConfig {
        enabled: true,
        next_hop_ipv4: Some("192.0.2.66".parse().unwrap()),
        next_hop_ipv6: Some("2001:db8::66".parse().unwrap()),
        communities: vec!["64512:1".into()],
        ..Default::default()
    };
    let binding = repo
        .register_speaker_target(
            &settings.pop,
            &prefixd::domain::SpeakerTarget::from_config(&settings.bgp).unwrap(),
            false,
        )
        .await
        .unwrap();
    repo.insert_safelist("198.18.0.0/15", "config", None)
        .await
        .unwrap();
    prefixd::guardrails::check_blackhole_startup(
        &settings.blackhole,
        speaker.as_ref(),
        repo.as_ref(),
    )
    .await
    .unwrap();
    let inventory = Inventory::new(vec![Customer {
        customer_id: "blackhole-live".into(),
        name: "Blackhole live test".into(),
        prefixes: vec!["192.0.2.0/24".into(), "2001:db8::/48".into()],
        policy_profile: PolicyProfile::Normal,
        services: vec![],
    }]);
    let routes = || async {
        speaker
            .blackhole()
            .unwrap()
            .list_blackholes()
            .await
            .unwrap()
            .routes
    };
    let mut admitted = Vec::new();
    for prefix in ["192.0.2.241/32", "2001:db8::241/128"] {
        let admission = prefixd::guardrails::admit_blackhole(
            repo.as_ref(),
            &settings,
            &inventory,
            MitigationIntent {
                event_id: uuid::Uuid::new_v4(),
                customer_id: None,
                service_id: None,
                pop: settings.pop.clone(),
                match_criteria: MatchCriteria {
                    dst_prefix: prefix.into(),
                    ..Default::default()
                },
                action_type: ActionType::Blackhole,
                action_params: ActionParams::default(),
                ttl_seconds: 600,
                reason: "live blackhole lifecycle".into(),
            },
            prefixd::domain::AttackVector::Unknown,
            None,
            &prefixd::observability::CreationActor::Operator("admin".into()),
            speaker.as_ref(),
            Some(&binding),
            None,
        )
        .await
        .unwrap();
        assert!(!admission.unconfirmed);
        // Retained local intent holds exactly the frozen route.
        let frozen = prefixd::domain::blackhole_rule(&admission.mitigation)
            .unwrap()
            .route()
            .unwrap();
        assert!(routes().await.contains(&frozen));
        admitted.push((admission.mitigation, frozen));
    }
    assert_eq!(routes().await.len(), 2);

    // A daemon restart loses local intent; reconciliation re-adds the frozen routes.
    fixture.container.stop_with_timeout(Some(0)).await.unwrap();
    fixture.container.start().await.unwrap();
    fixture.ready().await;
    assert!(routes().await.is_empty());
    let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false)
        .with_speaker_binding(binding);
    reconciler.reconcile().await.unwrap();
    let restored = routes().await;
    assert_eq!(restored.len(), 2);
    for (_, frozen) in &admitted {
        assert!(restored.contains(frozen));
    }

    // TTL expiry withdraws through the immutable withdrawal path.
    for (mitigation, _) in &admitted {
        let mut expired = repo
            .get_mitigation(mitigation.mitigation_id)
            .await
            .unwrap()
            .unwrap();
        expired.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
        repo.update_mitigation(&expired).await.unwrap();
    }
    reconciler.reconcile().await.unwrap();
    assert!(routes().await.is_empty());
    for (mitigation, _) in &admitted {
        assert_eq!(
            repo.get_mitigation(mitigation.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            MitigationStatus::Expired
        );
    }
    assert!(repo.pending_withdrawals(None).await.unwrap().is_empty());
}

/// Lease length for the released-daemon lease tests: short, so expiry is quick.
const TEST_LEASE_SECONDS: u32 = 10;

struct LeasedHarness {
    fixture: fixture::Speaker,
    speaker: std::sync::Arc<prefixd::bgp::RustBgpdAnnouncer>,
    repo: std::sync::Arc<prefixd::db::MockRepository>,
    settings: prefixd::config::Settings,
    binding: prefixd::domain::VerifiedSpeakerBinding,
}

impl LeasedHarness {
    async fn start() -> Option<Self> {
        use prefixd::db::RepositoryTrait;
        let fixture = fixture::Speaker::start().await;
        if !fixture.has_injection_lease() {
            eprintln!(
                "rustbgpd {} has no injection lease; leased test skipped",
                fixture.version()
            );
            return None;
        }
        let speaker = std::sync::Arc::new(fixture.connect().await);
        let repo = std::sync::Arc::new(prefixd::db::MockRepository::new());
        let mut settings = fixture_settings(&fixture, "leased-live");
        settings.blackhole = leased_config();
        let binding = repo
            .register_speaker_target(
                &settings.pop,
                &prefixd::domain::SpeakerTarget::from_config(&settings.bgp).unwrap(),
                false,
            )
            .await
            .unwrap();
        repo.insert_safelist("198.18.0.0/15", "config", None)
            .await
            .unwrap();
        Some(Self {
            fixture,
            speaker,
            repo,
            settings,
            binding,
        })
    }

    /// What a controller does at startup: probe, adopt and refuse collisions.
    async fn controller(&self) -> std::sync::Arc<prefixd::domain::LeaseKeeper> {
        let keeper = std::sync::Arc::new(prefixd::domain::LeaseKeeper::new(
            self.binding.owner(),
            TEST_LEASE_SECONDS,
        ));
        assert!(keeper.recover(self.speaker.as_ref()).await.unwrap());
        prefixd::guardrails::check_blackhole_startup(
            &self.settings.blackhole,
            self.speaker.as_ref(),
            self.repo.as_ref(),
        )
        .await
        .unwrap();
        prefixd::guardrails::check_lease_startup(
            &self.settings.blackhole,
            self.speaker.as_ref(),
            self.repo.as_ref(),
            &self.settings.pop,
            &self.binding.owner(),
        )
        .await
        .unwrap();
        keeper
    }

    fn reconciler(
        &self,
        keeper: &std::sync::Arc<prefixd::domain::LeaseKeeper>,
    ) -> prefixd::scheduler::ReconciliationLoop {
        prefixd::scheduler::ReconciliationLoop::new(
            self.repo.clone(),
            self.speaker.clone(),
            30,
            false,
        )
        .with_speaker_binding(self.binding.clone())
        .with_lease(keeper.clone())
    }

    /// Our retained rows: (prefix, owner, generation, remaining ms).
    async fn ours(&self) -> Vec<(String, String, (u64, u64), u32)> {
        let owner = self.binding.owner();
        let mut rows: Vec<_> = self
            .fixture
            .raw_local_routes()
            .await
            .into_iter()
            .filter(|route| route.injection_owner == owner)
            .map(|route| {
                let generation = route.lease_generation.unwrap();
                (
                    format!("{}/{}", route.prefix, route.prefix_length),
                    route.injection_owner,
                    (generation.incarnation, generation.sequence),
                    route.lease_remaining_ms.unwrap(),
                )
            })
            .collect();
        rows.sort();
        rows
    }
}

fn leased_config() -> prefixd::config::BlackholeConfig {
    prefixd::config::BlackholeConfig {
        enabled: true,
        next_hop_ipv4: Some("192.0.2.66".parse().unwrap()),
        next_hop_ipv6: Some("2001:db8::66".parse().unwrap()),
        communities: vec!["64512:1".into()],
        leased: true,
        lease_seconds: TEST_LEASE_SECONDS,
        ..Default::default()
    }
}

/// Leased add and renewal; a prefixd restart within the lease adopts the live
/// generation with no duplicate state; a prefixd stop past the lease lets the
/// daemon expire the routes without any recorded withdrawal, and the restart
/// re-adds the still-active intent; a rustbgpd restart refuses the renewal and
/// the re-add adopts the new generation. Other owners' and unowned rows stay.
#[tokio::test]
#[ignore = "requires Docker on Linux; run scripts/test-rustbgpd.sh"]
async fn live_rustbgpd_leased_blackhole_renewal_restart_and_expiry() {
    use prefixd::{
        config::{Customer, Inventory, PolicyProfile},
        db::RepositoryTrait,
        domain::{ActionParams, ActionType, MatchCriteria, MitigationIntent, MitigationStatus},
    };
    use std::time::Duration;
    let Some(harness) = LeasedHarness::start().await else {
        return;
    };
    let owner = harness.binding.owner();
    let inventory = Inventory::new(vec![Customer {
        customer_id: "leased-live".into(),
        name: "Leased live test".into(),
        prefixes: vec!["192.0.2.0/24".into(), "2001:db8::/48".into()],
        policy_profile: PolicyProfile::Normal,
        services: vec![],
    }]);

    // Another controller's leased row and an unowned row: never modified.
    let foreign_path = |prefix: &str| prefixd::bgp::rustbgpd_pb::AddPathRequest {
        prefix: prefix.into(),
        prefix_length: 32,
        next_hop: "192.0.2.66".into(),
        communities: vec![prefixd::bgp::BLACKHOLE_COMMUNITY],
        ..Default::default()
    };
    let seed_foreign = || async {
        harness
            .fixture
            .add_raw_leased_path(foreign_path("192.0.2.250"), "other.controller", 3600)
            .await;
        harness
            .fixture
            .add_raw_path(foreign_path("192.0.2.251"))
            .await;
    };
    let foreign_rows = || async {
        let mut rows: Vec<_> = harness
            .fixture
            .raw_local_routes()
            .await
            .into_iter()
            .filter(|route| route.prefix.starts_with("192.0.2.25"))
            .map(|route| (route.prefix, route.injection_owner))
            .collect();
        rows.sort();
        rows
    };
    let expected_foreign = vec![
        ("192.0.2.250".to_string(), "other.controller".to_string()),
        ("192.0.2.251".to_string(), String::new()),
    ];
    seed_foreign().await;

    // Leased add, then renew.
    let keeper = harness.controller().await;
    assert!(
        (harness.speaker.as_ref() as &dyn FlowSpecAnnouncer)
            .capabilities()
            .blackhole_lease
    );
    let mut admitted = Vec::new();
    for prefix in ["192.0.2.241/32", "2001:db8::241/128"] {
        let admission = prefixd::guardrails::admit_blackhole(
            harness.repo.as_ref(),
            &harness.settings,
            &inventory,
            MitigationIntent {
                event_id: uuid::Uuid::new_v4(),
                customer_id: None,
                service_id: None,
                pop: harness.settings.pop.clone(),
                match_criteria: MatchCriteria {
                    dst_prefix: prefix.into(),
                    ..Default::default()
                },
                action_type: ActionType::Blackhole,
                action_params: ActionParams::default(),
                ttl_seconds: 600,
                reason: "live leased blackhole".into(),
            },
            prefixd::domain::AttackVector::Unknown,
            None,
            &prefixd::observability::CreationActor::Operator("admin".into()),
            harness.speaker.as_ref(),
            Some(&harness.binding),
            Some(&keeper),
        )
        .await
        .unwrap();
        assert!(!admission.unconfirmed);
        let rule = prefixd::domain::blackhole_rule(&admission.mitigation).unwrap();
        assert_eq!(rule.owner, owner);
        admitted.push(admission.mitigation);
    }
    let generation = keeper.generation().expect("adopted from the first add");
    let rows = harness.ours().await;
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .all(|row| row.2 == (generation.incarnation, generation.sequence))
    );
    keeper.renew_once(harness.speaker.as_ref()).await;
    let health = keeper.health();
    assert_eq!(health.state, prefixd::domain::LeaseState::Live);
    assert_eq!(health.last_renewal_result, Some("success"));
    // The renewal reset the deadline to now + lease_seconds.
    assert!(
        harness
            .ours()
            .await
            .iter()
            .all(|row| row.3 > (TEST_LEASE_SECONDS - 2) * 1000)
    );
    let reconciler = harness.reconciler(&keeper);
    keeper.take_readd();
    reconciler.reconcile().await.unwrap();
    assert_eq!(foreign_rows().await, expected_foreign);

    // prefixd restarts within the lease: the probe recovers the live generation,
    // and the startup re-add joins it with no duplicate state.
    let restarted = harness.controller().await;
    assert_eq!(restarted.generation(), Some(generation));
    let before = harness.ours().await;
    harness.reconciler(&restarted).reconcile().await.unwrap();
    assert!(
        !restarted.take_readd(),
        "joining the live lease is not a loss"
    );
    assert_eq!(restarted.generation(), Some(generation));
    let after = harness.ours().await;
    assert_eq!(
        after.iter().map(|row| (&row.0, &row.2)).collect::<Vec<_>>(),
        before
            .iter()
            .map(|row| (&row.0, &row.2))
            .collect::<Vec<_>>()
    );

    // prefixd stops past the lease: the daemon expires the owner's routes.
    tokio::time::sleep(Duration::from_secs(u64::from(TEST_LEASE_SECONDS) + 3)).await;
    assert!(
        harness.ours().await.is_empty(),
        "lease expiry removed the routes"
    );
    assert_eq!(foreign_rows().await, expected_foreign);
    // Expiry is not a prefixd withdrawal: the intent stays active and unaudited.
    assert!(
        harness
            .repo
            .pending_withdrawals(None)
            .await
            .unwrap()
            .is_empty()
    );
    for mitigation in &admitted {
        let stored = harness
            .repo
            .get_mitigation(mitigation.mitigation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.status, MitigationStatus::Active);
    }
    let audit = harness
        .repo
        .list_audit(&prefixd::db::ListParams {
            limit: 1000,
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(
        !audit
            .iter()
            .any(|entry| entry.action == "withdraw" || entry.action == "expire")
    );
    // The restart re-adds the still-active intent under a new generation.
    let returned = harness.controller().await;
    assert_eq!(
        returned.generation(),
        None,
        "an expired lease is not adopted"
    );
    harness.reconciler(&returned).reconcile().await.unwrap();
    let readded = returned.generation().unwrap();
    assert_ne!(readded, generation);
    assert_eq!(harness.ours().await.len(), 2);

    // rustbgpd restarts: the renewal is refused and the re-add adopts the new generation.
    harness
        .fixture
        .container
        .stop_with_timeout(Some(0))
        .await
        .unwrap();
    harness.fixture.container.start().await.unwrap();
    harness.fixture.ready().await;
    assert!(harness.ours().await.is_empty());
    returned.renew_once(harness.speaker.as_ref()).await;
    assert_eq!(returned.health().last_renewal_result, Some("not_live"));
    assert_eq!(
        returned.health().state,
        prefixd::domain::LeaseState::Expired
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), returned.readd_requested())
            .await
            .is_ok()
    );
    let reconciler = harness.reconciler(&returned);
    reconciler.reconcile().await.unwrap();
    let after_restart = returned.generation().unwrap();
    assert_ne!(after_restart.incarnation, readded.incarnation);
    let rows = harness.ours().await;
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .all(|row| row.2 == (after_restart.incarnation, after_restart.sequence))
    );
    returned.renew_once(harness.speaker.as_ref()).await;
    assert_eq!(returned.health().state, prefixd::domain::LeaseState::Live);

    // Withdrawal deletes under the recorded owner.
    for mitigation in &admitted {
        let current = harness
            .repo
            .get_mitigation(mitigation.mitigation_id)
            .await
            .unwrap()
            .unwrap();
        let request = prefixd::domain::request_withdrawal(
            harness.repo.as_ref(),
            &current,
            false,
            "operator",
            "alice",
            "attack over".into(),
            true,
            Some(&harness.binding),
        )
        .await
        .unwrap();
        prefixd::domain::execute_withdrawal(
            harness.repo.as_ref(),
            harness.speaker.as_ref(),
            false,
            &request,
            Some(&harness.binding),
        )
        .await
        .unwrap();
    }
    assert!(harness.ours().await.is_empty());
}

/// Before 0.79.0 the lease probe reports no capability, a leased configuration
/// refuses startup, and a leased add creates nothing and never falls back.
#[tokio::test]
#[ignore = "requires Docker on Linux; run scripts/test-rustbgpd.sh"]
async fn live_rustbgpd_without_lease_refuses_leased_startup() {
    use prefixd::bgp::BlackholeSpeaker;
    let fixture = fixture::Speaker::start().await;
    if fixture.has_injection_lease() {
        eprintln!(
            "rustbgpd {} has the injection lease; older-daemon test skipped",
            fixture.version()
        );
        return;
    }
    let speaker = fixture.connect().await;
    let repo = prefixd::db::MockRepository::new();
    prefixd::db::RepositoryTrait::insert_safelist(&repo, "198.18.0.0/15", "config", None)
        .await
        .unwrap();
    let keeper = prefixd::domain::LeaseKeeper::new("prefixd.old.0123456789abcdef".into(), 60);
    assert!(!keeper.recover(&speaker).await.unwrap());
    assert!(
        !(&speaker as &dyn FlowSpecAnnouncer)
            .capabilities()
            .blackhole_lease
    );
    let error = prefixd::guardrails::check_blackhole_startup(&leased_config(), &speaker, &repo)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("injection lease"), "{error}");
    let route = prefixd::bgp::BlackholeRoute::new(
        "192.0.2.242/32".parse().unwrap(),
        "192.0.2.66".parse().unwrap(),
        vec![],
        vec![],
    )
    .unwrap()
    .with_owner(keeper.owner());
    assert!(speaker.announce_leased_blackhole(&route, 60).await.is_err());
    assert_eq!(
        speaker.list_blackholes().await.unwrap(),
        prefixd::bgp::BlackholeInventory::default()
    );
}
