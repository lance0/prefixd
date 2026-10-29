use super::*;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering::SeqCst},
};
use tonic::{Response, Status};

/// Match components of a leased rule and the owner holding it.
type HeldOwner = (Vec<pb::FlowSpecComponent>, String);

#[derive(Clone, Default)]
struct Fake {
    rules: Arc<Mutex<Vec<pb::AddFlowSpecRequest>>>,
    mode: Arc<AtomicUsize>,
    refusal: Arc<Mutex<Option<Status>>>,
    attempts: Arc<AtomicUsize>,
    deletes: Arc<AtomicUsize>,
    health_calls: Arc<AtomicUsize>,
    families: Arc<Mutex<Vec<i32>>>,
    /// Injection owner per leased rule, by match components.
    owners: Arc<Mutex<Vec<HeldOwner>>>,
    leased: Arc<Mutex<Vec<pb::AddLeasedFlowSpecRequest>>>,
    delete_owners: Arc<Mutex<Vec<String>>>,
}

/// FlowSpec fake modes for the lease: a rolled-back daemon, and leased rows with no time left.
const FLOWSPEC_LEASE_UNIMPLEMENTED: usize = 30;
const FLOWSPEC_LEASE_EXPIRED: usize = 31;

impl Fake {
    fn owner_of(&self, components: &[pb::FlowSpecComponent]) -> String {
        self.owners
            .lock()
            .unwrap()
            .iter()
            .find(|(held, _)| held.as_slice() == components)
            .map(|(_, owner)| owner.clone())
            .unwrap_or_default()
    }
}

fn auth<T>(request: &Request<T>) -> std::result::Result<(), Status> {
    if request
        .metadata()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        != Some("Bearer test-secret")
    {
        return Err(Status::unauthenticated("denied"));
    }
    assert!(request.metadata().contains_key("grpc-timeout"));
    Ok(())
}

#[tonic::async_trait]
impl pb::control_service_server::ControlService for Fake {
    async fn get_health(
        &self,
        request: Request<pb::HealthRequest>,
    ) -> std::result::Result<Response<pb::HealthResponse>, Status> {
        self.health_calls.fetch_add(1, SeqCst);
        auth(&request)?;
        match self.mode.load(SeqCst) {
            20 => return Err(Status::unavailable("secret upstream diagnostic")),
            21 => return Err(Status::permission_denied("secret upstream diagnostic")),
            22 => {
                return Ok(Response::new(pb::HealthResponse {
                    healthy: false,
                    uptime_seconds: 0,
                    daemon_version: String::new(),
                    ..Default::default()
                }));
            }
            _ => {}
        }
        let daemon_version = match self.mode.load(SeqCst) {
            23 => "0.79.0",
            24 => "0.80.0",
            25 => "0.81.0-dev",
            _ => "observed-daemon-version",
        };
        Ok(Response::new(pb::HealthResponse {
            healthy: true,
            uptime_seconds: 123,
            daemon_version: daemon_version.into(),
            ..Default::default()
        }))
    }
}

#[test]
fn daemon_versions_parse_as_major_minor_patch() {
    assert_eq!(parse_version("0.79.0"), Some([0, 79, 0]));
    assert_eq!(parse_version("1.2.3-rc.1+build"), Some([1, 2, 3]));
    for bad in ["", "0.79", "0.79.0.1", "v0.79.0", "observed-daemon-version"] {
        assert_eq!(parse_version(bad), None, "{bad}");
    }
    assert!(parse_version("0.100.0").unwrap() > MINIMUM_DAEMON_VERSION);
}

#[tokio::test]
async fn startup_refuses_a_daemon_older_than_the_minimum_contract() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let fake = Fake::default();
    let incoming = futures_util::stream::unfold(listener, |listener| async {
        Some((listener.accept().await.map(|(stream, _)| stream), listener))
    });
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(pb::control_service_server::ControlServiceServer::new(
                fake.clone(),
            ))
            .serve_with_incoming(incoming),
    );
    let config = RustBgpdConfig {
        endpoint: format!("http://{address}"),
        bearer_token_env: "unused".into(),
        ..Default::default()
    };
    let speaker = RustBgpdAnnouncer::connect_with_token(&config, "test-secret")
        .await
        .unwrap();
    for mode in [24, 25] {
        fake.mode.store(mode, SeqCst);
        speaker.require_minimum_version().await.unwrap();
    }
    fake.mode.store(23, SeqCst);
    let error = speaker
        .require_minimum_version()
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        "rustbgpd 0.79.0 is older than the minimum 0.80.0; upgrade the speaker first"
    );
    // No version, an unreadable one or a failed read refuses too, without upstream detail.
    for (mode, expected) in [
        (22, "no readable version"),
        (0, "no readable version"),
        (21, "cannot read the rustbgpd version"),
    ] {
        fake.mode.store(mode, SeqCst);
        let error = speaker
            .require_minimum_version()
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{error}");
        assert!(!error.contains("secret"), "{error}");
    }
    server.abort();
}

#[tokio::test]
async fn authenticated_daemon_metadata_preserves_missing_zero_and_failed_observations() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let fake = Fake::default();
    let incoming = futures_util::stream::unfold(listener, |listener| async {
        Some((listener.accept().await.map(|(stream, _)| stream), listener))
    });
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(pb::control_service_server::ControlServiceServer::new(
                fake.clone(),
            ))
            .serve_with_incoming(incoming),
    );
    let config = RustBgpdConfig {
        endpoint: format!("http://{address}"),
        bearer_token_env: "unused".into(),
        ..Default::default()
    };
    let speaker = RustBgpdAnnouncer::connect_with_token(&config, "test-secret")
        .await
        .unwrap();
    let health = speaker.daemon_health().await.unwrap();
    assert_eq!(health.version.as_deref(), Some("observed-daemon-version"));
    assert_eq!(health.uptime_seconds, 123);
    assert!(health.ready);
    fake.mode.store(22, SeqCst);
    let health = speaker.daemon_health().await.unwrap();
    assert!(health.version.is_none());
    assert_eq!(health.uptime_seconds, 0);
    assert!(!health.ready);
    for (mode, expected_attempts) in [(20, 3), (21, 1)] {
        fake.mode.store(mode, SeqCst);
        let before = fake.health_calls.load(SeqCst);
        let error = speaker.daemon_health().await.unwrap_err().to_string();
        assert_eq!(fake.health_calls.load(SeqCst), before + expected_attempts);
        assert!(!error.contains("secret"));
    }
    fake.mode.store(0, SeqCst);
    let rejected = RustBgpdAnnouncer::connect_with_token(&config, "wrong-token")
        .await
        .unwrap();
    let before = fake.health_calls.load(SeqCst);
    assert!(rejected.daemon_health().await.is_err());
    assert_eq!(fake.health_calls.load(SeqCst), before + 1);
    server.abort();
}

#[tonic::async_trait]
impl pb::injection_service_server::InjectionService for Fake {
    async fn add_flow_spec(
        &self,
        request: Request<pb::AddFlowSpecRequest>,
    ) -> std::result::Result<Response<pb::AddFlowSpecResponse>, Status> {
        let attempt = self.attempts.fetch_add(1, SeqCst);
        auth(&request)?;
        if let Some(status) = self.refusal.lock().unwrap().clone() {
            return Err(status);
        }
        match self.mode.load(SeqCst) {
            1 => return Err(Status::unavailable("temporary")),
            2 => return Err(Status::invalid_argument("bad input")),
            3 => return Ok(Response::new(pb::AddFlowSpecResponse { outcome: 0 })),
            9 if attempt == 0 => return Err(Status::unavailable("once")),
            10 => return Err(Status::deadline_exceeded("deadline")),
            11 => tokio::time::sleep(Duration::from_secs(60)).await,
            _ => {}
        }
        let request = request.into_inner();
        assert!(matches!(request.afi_safi, 3 | 4));
        // The daemon requires strictly ascending component types and does not reorder.
        assert!(
            request
                .components
                .windows(2)
                .all(|c| c[0].r#type < c[1].r#type)
        );
        let mut rules = self.rules.lock().unwrap();
        let existing = rules.iter().position(|old| {
            old.afi_safi == request.afi_safi && old.components == request.components
        });
        let outcome = match existing {
            Some(index) if rules[index] == request => 3,
            Some(index) => {
                rules[index] = request;
                2
            }
            None => {
                rules.push(request);
                1
            }
        };
        Ok(Response::new(pb::AddFlowSpecResponse { outcome }))
    }

    async fn add_leased_flow_spec(
        &self,
        request: Request<pb::AddLeasedFlowSpecRequest>,
    ) -> std::result::Result<Response<pb::AddLeasedFlowSpecResponse>, Status> {
        auth(&request)?;
        if let Some(status) = self.refusal.lock().unwrap().clone() {
            return Err(status);
        }
        if self.mode.load(SeqCst) == FLOWSPEC_LEASE_UNIMPLEMENTED {
            return Err(Status::unimplemented("older daemon"));
        }
        let request = request.into_inner();
        self.leased.lock().unwrap().push(request.clone());
        let rule = request.rule.unwrap();
        self.owners
            .lock()
            .unwrap()
            .push((rule.components.clone(), request.lease.unwrap().owner));
        let mut rules = self.rules.lock().unwrap();
        rules.retain(|old| old.afi_safi != rule.afi_safi || old.components != rule.components);
        rules.push(rule);
        Ok(Response::new(pb::AddLeasedFlowSpecResponse {
            result: Some(pb::AddFlowSpecResponse { outcome: 1 }),
            generation: Some(LIVE),
        }))
    }

    async fn delete_flow_spec(
        &self,
        request: Request<pb::DeleteFlowSpecRequest>,
    ) -> std::result::Result<Response<pb::DeleteFlowSpecResponse>, Status> {
        self.deletes.fetch_add(1, SeqCst);
        auth(&request)?;
        if let Some(status) = self.refusal.lock().unwrap().clone() {
            return Err(status);
        }
        let request = request.into_inner();
        assert!(request.allow_missing);
        assert!(!request.override_owner, "prefixd never overrides the owner");
        self.delete_owners
            .lock()
            .unwrap()
            .push(request.owner.clone());
        if self
            .rules
            .lock()
            .unwrap()
            .iter()
            .any(|old| old.components == request.components)
            && self.owner_of(&request.components) != request.owner
        {
            return Err(Status::failed_precondition("key is held by another owner"));
        }
        match self.mode.load(SeqCst) {
            4 => return Err(Status::not_found("absent")),
            5 => return Ok(Response::new(pb::DeleteFlowSpecResponse { outcome: 0 })),
            _ => {}
        }
        let mut rules = self.rules.lock().unwrap();
        let before = rules.len();
        rules
            .retain(|old| old.afi_safi != request.afi_safi || old.components != request.components);
        Ok(Response::new(pb::DeleteFlowSpecResponse {
            outcome: if rules.len() == before { 2 } else { 1 },
        }))
    }
}

#[tonic::async_trait]
impl pb::rib_service_server::RibService for Fake {
    async fn list_flow_spec_routes(
        &self,
        request: Request<pb::ListFlowSpecRequest>,
    ) -> std::result::Result<Response<pb::ListFlowSpecResponse>, Status> {
        auth(&request)?;
        let request = request.into_inner();
        assert_eq!(request.received_peer_address, "0.0.0.0");
        assert!(request.advertised_peer_address.is_empty());
        self.families.lock().unwrap().push(request.afi_safi);
        let received_routes = self
            .rules
            .lock()
            .unwrap()
            .iter()
            .filter(|rule| rule.afi_safi == request.afi_safi)
            .map(|rule| {
                let Some(pb::flow_spec_action::Action::TrafficRate(rate)) = &rule.actions[0].action
                else {
                    panic!("expected rate action")
                };
                let mut components = rule.components.clone();
                super::tests::read_back(&mut components);
                if self.mode.load(SeqCst) == 8 {
                    components.push(pb::FlowSpecComponent {
                        r#type: 10,
                        value: ">80".into(),
                        ..Default::default()
                    });
                }
                let owner = self.owner_of(&rule.components);
                let leased = !owner.is_empty();
                pb::ReceivedFlowSpecRouteEntry {
                    route: Some(pb::FlowSpecRouteEntry {
                        components,
                        actions: rule.actions.clone(),
                        peer_address: "0.0.0.0".into(),
                        afi_safi: rule.afi_safi,
                        extended_communities: vec![
                            (0x8006_u64 << 48) | u64::from(rate.rate.to_bits()),
                        ],
                        injection_owner: owner,
                        lease_generation: leased.then_some(LIVE),
                        lease_remaining_ms: leased.then_some(
                            if self.mode.load(SeqCst) == FLOWSPEC_LEASE_EXPIRED {
                                0
                            } else {
                                59_000
                            },
                        ),
                        ..Default::default()
                    }),
                    selected: false,
                    validation: 3,
                    ..Default::default()
                }
            })
            .collect();
        Ok(Response::new(pb::ListFlowSpecResponse {
            received_view: self.mode.load(SeqCst) != 6,
            received_routes,
            ..Default::default()
        }))
    }
}

#[tonic::async_trait]
impl pb::neighbor_service_server::NeighborService for Fake {
    async fn list_neighbors(
        &self,
        request: Request<pb::ListNeighborsRequest>,
    ) -> std::result::Result<Response<pb::ListNeighborsResponse>, Status> {
        auth(&request)?;
        let mut neighbors = vec![pb::NeighborState {
            config: Some(pb::NeighborConfig {
                address: "192.0.2.1".into(),
                description: "shared edge".into(),
                ..Default::default()
            }),
            state: 6,
            stale: self.mode.load(SeqCst) == 7,
            ..Default::default()
        }];
        if self.mode.load(SeqCst) == 12 {
            neighbors.insert(
                0,
                pb::NeighborState {
                    config: Some(pb::NeighborConfig {
                        address: "192.0.2.2".into(),
                        description: "shared edge".into(),
                        ..Default::default()
                    }),
                    state: 1,
                    ..Default::default()
                },
            );
        }
        Ok(Response::new(pb::ListNeighborsResponse { neighbors }))
    }
}

fn rule(prefix: &str, rate: u64) -> FlowSpecRule {
    FlowSpecRule::new(
        FlowSpecNlri {
            dst_prefix: prefix.into(),
            protocol: Some(6),
            dst_ports: vec![443, 80, 80],
            ..Default::default()
        },
        if rate == 0 {
            FlowSpecAction::discard()
        } else {
            FlowSpecAction::police(rate)
        },
    )
}

#[tokio::test]
async fn authenticated_controller_rpc_contract() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let fake = Fake::default();
    let incoming = futures_util::stream::unfold(listener, |listener| async {
        Some((listener.accept().await.map(|(stream, _)| stream), listener))
    });
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(pb::injection_service_server::InjectionServiceServer::new(
                fake.clone(),
            ))
            .add_service(pb::rib_service_server::RibServiceServer::new(fake.clone()))
            .add_service(pb::neighbor_service_server::NeighborServiceServer::new(
                fake.clone(),
            ))
            .serve_with_incoming(incoming),
    );
    let config = RustBgpdConfig {
        endpoint: format!("http://{address}"),
        bearer_token_env: "unused".into(),
        ca_cert_path: None,
        ..Default::default()
    };
    let speaker = RustBgpdAnnouncer::connect_with_token(&config, "test-secret")
        .await
        .unwrap();
    let v4 = rule("192.0.2.231/32", 0);
    let v6 = rule("2001:0DB8:0:0:0:0:0:231/128", 8_000_000);
    for template in [&v4, &v6] {
        for actions in [
            vec![],
            vec![FlowSpecAction::discard(), FlowSpecAction::police(8)],
            vec![FlowSpecAction {
                action_type: crate::domain::ActionType::Police,
                rate_bps: None,
            }],
            vec![FlowSpecAction::police(0)],
            vec![FlowSpecAction::police(16_777_217)],
            vec![FlowSpecAction::police(u64::MAX)],
            vec![FlowSpecAction {
                action_type: crate::domain::ActionType::Discard,
                rate_bps: Some(8),
            }],
        ] {
            let mut invalid = template.clone();
            invalid.actions = actions;
            assert!(speaker.announce(&invalid).await.is_err());
            assert_eq!(fake.attempts.load(SeqCst), 0);
        }
    }
    speaker.announce(&v4).await.unwrap();
    speaker.announce(&v4).await.unwrap();
    speaker.announce(&v6).await.unwrap();
    for expected in [&v4, &v6] {
        let active = speaker.list_active().await.unwrap();
        let actual = active
            .iter()
            .find(|r| r.nlri_hash() == expected.nlri_hash())
            .unwrap();
        assert_eq!(actual.actions[0].rate_bps, expected.actions[0].rate_bps);
        assert_eq!(
            actual.actions[0].action_type,
            expected.actions[0].action_type
        );
    }
    assert!(fake.families.lock().unwrap().contains(&3));
    assert!(fake.families.lock().unwrap().contains(&4));
    let replacement = rule("192.0.2.231/32", 8_000);
    speaker.announce(&replacement).await.unwrap();
    let active = speaker.list_active().await.unwrap();
    assert_eq!(
        active
            .iter()
            .find(|r| r.nlri_hash() == replacement.nlri_hash())
            .unwrap()
            .actions[0]
            .rate_bps,
        Some(8_000)
    );
    assert_eq!(speaker.session_status().await.unwrap()[0].name, "192.0.2.1");
    fake.mode.store(12, SeqCst);
    let peers = speaker.session_status().await.unwrap();
    // Match the scheduler's peer-name label without sharing global test metrics.
    let sessions = prometheus::GaugeVec::new(
        prometheus::Opts::new("test_bgp_session_up", "Session state"),
        &["peer"],
    )
    .unwrap();
    for peer in peers {
        assert_eq!(peer.name, peer.address);
        sessions
            .with_label_values(&[&peer.name])
            .set(if peer.state.is_established() {
                1.0
            } else {
                0.0
            });
    }
    assert_eq!(sessions.with_label_values(&["192.0.2.2"]).get(), 0.0);
    assert_eq!(sessions.with_label_values(&["192.0.2.1"]).get(), 1.0);
    use prometheus::core::Collector;
    assert_eq!(sessions.collect()[0].get_metric().len(), 2);
    fake.mode.store(0, SeqCst);
    for (mode, expected_attempts) in [(1, 3), (2, 1), (3, 1), (10, 3)] {
        fake.mode.store(mode, SeqCst);
        fake.attempts.store(0, SeqCst);
        assert!(speaker.announce(&v4).await.is_err());
        assert_eq!(fake.attempts.load(SeqCst), expected_attempts);
    }
    fake.mode.store(9, SeqCst);
    fake.attempts.store(0, SeqCst);
    speaker.announce(&v4).await.unwrap();
    assert_eq!(fake.attempts.load(SeqCst), 2);
    fake.mode.store(4, SeqCst);
    speaker.withdraw(&v4).await.unwrap();
    fake.mode.store(5, SeqCst);
    assert!(speaker.withdraw(&v4).await.is_err());
    fake.mode.store(6, SeqCst);
    assert!(speaker.list_active().await.is_err());
    fake.mode.store(7, SeqCst);
    assert!(speaker.session_status().await.is_err());
    fake.mode.store(8, SeqCst);
    assert!(speaker.list_active().await.is_err());
    fake.mode.store(0, SeqCst);
    for rule in [&v4, &v6] {
        speaker.withdraw(rule).await.unwrap();
        speaker.withdraw(rule).await.unwrap();
    }
    assert!(speaker.list_active().await.unwrap().is_empty());
    let wrong_token = RustBgpdAnnouncer::connect_with_token(&config, "incorrect")
        .await
        .unwrap();
    fake.attempts.store(0, SeqCst);
    assert!(wrong_token.announce(&v4).await.is_err());
    assert_eq!(fake.attempts.load(SeqCst), 1);
    fake.mode.store(11, SeqCst);
    fake.attempts.store(0, SeqCst);
    tokio::time::pause();
    let start = tokio::time::Instant::now();
    assert!(speaker.announce(&v4).await.is_err());
    assert!(start.elapsed() >= Duration::from_secs(30));
    assert!(start.elapsed() <= Duration::from_secs(95));
    assert!((1..=3).contains(&fake.attempts.load(SeqCst)));
    tokio::time::resume();
    server.abort();
}

#[tokio::test]
async fn tls_verifies_the_server_certificate() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let incoming = futures_util::stream::unfold(listener, |listener| async {
        Some((listener.accept().await.map(|(stream, _)| stream), listener))
    });
    // This key belongs only to the local test server.
    let identity = tonic::transport::Identity::from_pem(
        include_bytes!("testdata/server-cert.pem"),
        include_bytes!("testdata/server-key.pem"),
    );
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .tls_config(tonic::transport::ServerTlsConfig::new().identity(identity))
            .unwrap()
            .add_service(pb::injection_service_server::InjectionServiceServer::new(
                Fake::default(),
            ))
            .serve_with_incoming(incoming),
    );
    let mut config = RustBgpdConfig {
        endpoint: format!("https://{address}"),
        bearer_token_env: "unused".into(),
        ca_cert_path: None,
        ..Default::default()
    };
    assert!(
        RustBgpdAnnouncer::connect_with_token(&config, "test-secret")
            .await
            .is_err()
    );
    config.ca_cert_path = Some(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/bgp/testdata/server-cert.pem"
        )
        .into(),
    );
    let speaker = RustBgpdAnnouncer::connect_with_token(&config, "test-secret")
        .await
        .unwrap();
    speaker.announce(&rule("192.0.2.231/32", 0)).await.unwrap();
    server.abort();
}

#[tokio::test]
async fn rejects_unsafe_transport_and_credentials() {
    for endpoint in [
        "http://192.0.2.1:50051",
        "http://localhost:50051",
        "ftp://127.0.0.1:50051",
        "http://user@127.0.0.1:50051",
    ] {
        let config = RustBgpdConfig {
            endpoint: endpoint.into(),
            bearer_token_env: "unused".into(),
            ca_cert_path: None,
            ..Default::default()
        };
        assert!(
            RustBgpdAnnouncer::connect_with_token(&config, "test-secret")
                .await
                .is_err()
        );
    }
    let config = RustBgpdConfig {
        endpoint: "http://127.0.0.1:1".into(),
        bearer_token_env: "PREFIXD_UNSET_TEST_TOKEN_7CA4".into(),
        ca_cert_path: None,
        ..Default::default()
    };
    for token in ["", "secret\n", "two words"] {
        assert!(
            RustBgpdAnnouncer::connect_with_token(&config, token)
                .await
                .is_err()
        );
    }
    assert!(RustBgpdAnnouncer::connect(&config).await.is_err());
}

#[tokio::test]
async fn complete_rpc_deadline_bounds_stalled_response_body() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let incoming = futures_util::stream::unfold(listener, |listener| async {
        Some((listener.accept().await.map(|(stream, _)| stream), listener))
    });
    let headers_sent = Arc::new(AtomicUsize::new(0));
    let observed = headers_sent.clone();
    // The real HTTP/2 response sends headers, then never sends body frames or trailers.
    let stall_body = tower::util::MapResponseLayer::new(
        move |mut response: tonic::codegen::http::Response<tonic::body::Body>| {
            observed.fetch_add(1, SeqCst);
            *response.body_mut() = tonic::body::Body::new(axum::body::Body::from_stream(
                futures_util::stream::pending::<
                    std::result::Result<axum::body::Bytes, std::io::Error>,
                >(),
            ));
            response
        },
    );
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .layer(stall_body)
            .add_service(pb::injection_service_server::InjectionServiceServer::new(
                Fake::default(),
            ))
            .add_service(pb::control_service_server::ControlServiceServer::new(
                Fake::default(),
            ))
            .serve_with_incoming(incoming),
    );
    // Omit the transport's header timeout so only the complete-RPC bound can end this call.
    let speaker = RustBgpdAnnouncer::new(
        Endpoint::from_shared(format!("http://{address}"))
            .unwrap()
            .connect()
            .await
            .unwrap(),
        Some("Bearer test-secret".parse().unwrap()),
    );
    tokio::time::pause();
    for daemon in [true, false] {
        headers_sent.store(0, SeqCst);
        let start = tokio::time::Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(95), async {
            if daemon {
                speaker.daemon_health().await.map(|_| ())
            } else {
                speaker.announce(&rule("192.0.2.231/32", 0)).await
            }
        })
        .await
        .expect("stalled unary body must not outlive all three RPC deadlines");
        assert!(result.unwrap_err().to_string().contains("DeadlineExceeded"));
        assert_eq!(headers_sent.load(SeqCst), 3);
        assert!(start.elapsed() >= Duration::from_secs(90));
        assert!(start.elapsed() < Duration::from_secs(91));
    }
    tokio::time::resume();
    server.abort();
}

#[tokio::test]
async fn secure_transport_configuration_rejects_partial_identity_without_leaking_paths() {
    for endpoint in [
        "https://127.0.0.1:1",
        "http://127.0.0.1:1",
        "unix:///private/socket",
    ] {
        for (cert, key) in [(Some("private-cert"), None), (None, Some("private-key"))] {
            let config = RustBgpdConfig {
                endpoint: endpoint.into(),
                client_cert_path: cert.map(str::to_owned),
                client_key_path: key.map(str::to_owned),
                ..Default::default()
            };
            let error = RustBgpdAnnouncer::connect(&config)
                .await
                .err()
                .unwrap()
                .to_string();
            assert!(error.contains("configured together"));
            assert!(!error.contains("private-"));
        }
    }
    let config = RustBgpdConfig {
        endpoint: "https://127.0.0.1:1".into(),
        client_cert_path: Some("private-cert".into()),
        client_key_path: Some("private-key".into()),
        ..Default::default()
    };
    let error = RustBgpdAnnouncer::connect(&config)
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(!error.contains("private-"));
}

#[cfg(unix)]
#[tokio::test]
async fn owner_socket_rejects_permissive_directory_socket_and_symlinks() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let path = directory.path().join("grpc.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(connect_owner_socket(&path).await.is_ok());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
    assert!(connect_owner_socket(&path).await.is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
    assert!(connect_owner_socket(&path).await.is_err());
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = directory.path().join("link.sock");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(connect_owner_socket(&link).await.is_err());
    drop(listener);
}

#[cfg(unix)]
#[tokio::test]
async fn owner_socket_rejects_ancestors_that_allow_untrusted_directory_replacement() {
    use std::os::unix::fs::PermissionsExt;
    let ancestor = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let private = ancestor.path().join("private");
    std::fs::create_dir(&private).unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = private.join("grpc.sock");
    let _listener = tokio::net::UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(ancestor.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(
        connect_owner_socket(&path).await.is_err(),
        "a private parent is replaceable through a non-sticky writable ancestor"
    );
    std::fs::set_permissions(ancestor.path(), std::fs::Permissions::from_mode(0o1777)).unwrap();
    assert!(connect_owner_socket(&path).await.is_ok());
    std::fs::set_permissions(ancestor.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
    assert!(connect_owner_socket(&path).await.is_ok());
    let alias = ancestor.path().join("alias");
    std::os::unix::fs::symlink(&private, &alias).unwrap();
    assert!(
        connect_owner_socket(&alias.join("grpc.sock"))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn native_mtls_presents_the_client_certificate() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let incoming = futures_util::stream::unfold(listener, |listener| async {
        Some((listener.accept().await.map(|(stream, _)| stream), listener))
    });
    let tls = tonic::transport::ServerTlsConfig::new()
        .identity(tonic::transport::Identity::from_pem(
            include_bytes!("testdata/transport-server-cert.pem"),
            include_bytes!("testdata/transport-server-key.pem"),
        ))
        .client_ca_root(tonic::transport::Certificate::from_pem(include_bytes!(
            "testdata/transport-ca.pem"
        )));
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(pb::injection_service_server::InjectionServiceServer::new(
                Fake::default(),
            ))
            .serve_with_incoming(incoming),
    );
    let path = |name: &str| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/bgp/testdata")
            .join(name)
            .to_str()
            .unwrap()
            .to_owned()
    };
    let mut config = RustBgpdConfig {
        endpoint: format!("https://{address}"),
        ca_cert_path: Some(path("transport-ca.pem")),
        ..Default::default()
    };
    if let Ok(client) = RustBgpdAnnouncer::connect_with_token(&config, "test-secret").await {
        assert!(client.announce(&rule("192.0.2.231/32", 0)).await.is_err());
    }
    config.client_cert_path = Some(path("transport-client-cert.pem"));
    config.client_key_path = Some(path("transport-client-key.pem"));
    let client = RustBgpdAnnouncer::connect_with_token(&config, "test-secret")
        .await
        .unwrap();
    client.announce(&rule("192.0.2.231/32", 0)).await.unwrap();
    server.abort();
}

#[tokio::test]
async fn initial_connection_bounds_a_stalled_tls_handshake() {
    use tokio::io::AsyncReadExt;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (hello_sent, hello_seen) = tokio::sync::oneshot::channel();
    let (release, hold) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut header = [0; 5];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 22, "TLS handshake record");
        let mut hello = vec![0; u16::from_be_bytes([header[3], header[4]]) as usize];
        stream.read_exact(&mut hello).await.unwrap();
        assert_eq!(hello[0], 1, "TLS ClientHello");
        hello_sent.send(()).unwrap();
        let _ = hold.await;
    });
    let config = RustBgpdConfig {
        endpoint: format!("https://{address}"),
        ..Default::default()
    };
    let mut connection =
        tokio::spawn(
            async move { RustBgpdAnnouncer::connect_with_token(&config, "test-secret").await },
        );
    tokio::time::timeout(Duration::from_secs(5), hello_seen)
        .await
        .expect("server must receive ClientHello before checking the TLS deadline")
        .unwrap();
    assert!(!connection.is_finished());
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(11)).await;
    let result = tokio::time::timeout(Duration::from_secs(1), &mut connection).await;
    tokio::time::resume();
    release.send(()).unwrap();
    server.await.unwrap();
    assert!(
        result.is_ok(),
        "stalled TLS negotiation exceeded the connection budget"
    );
    assert!(result.unwrap().unwrap().is_err());
}

/// Retained unicast local intent served one route per page, so a family with
/// several routes needs a complete token walk.
#[derive(Clone, Default)]
struct UnicastFake {
    paths: Arc<Mutex<Vec<pb::AddPathRequest>>>,
    mode: Arc<AtomicUsize>,
    refusal: Arc<Mutex<Option<Status>>>,
    pages: Arc<AtomicUsize>,
    /// Injection owner per prefix; absent for an unowned path.
    owners: Arc<Mutex<std::collections::HashMap<String, String>>>,
    plain_adds: Arc<AtomicUsize>,
    leased: Arc<Mutex<Vec<pb::AddLeasedPathRequest>>>,
    deletes_seen: Arc<Mutex<Vec<pb::DeletePathRequest>>>,
    renewals: Arc<Mutex<Vec<pb::RenewLeaseRequest>>>,
}

/// The fake daemon's one live generation.
const LIVE: pb::LeaseGeneration = pb::LeaseGeneration {
    incarnation: 0xfeed,
    sequence: 7,
};

const ABORT_SECOND_PAGE: usize = 1;
const DELETE_NOT_FOUND: usize = 2;
const DELETE_DENIED: usize = 3;
const DELETE_INTERNAL: usize = 4;
const LIST_UNIMPLEMENTED: usize = 5;
const VERSION_CHANGES: usize = 6;
const REPEATED_TOKEN: usize = 7;
/// A daemon rolled back below 0.79.0 after startup: every lease RPC is UNIMPLEMENTED.
const LEASE_UNIMPLEMENTED: usize = 8;
/// Ownership refusals on adds and deletes; renewal of a dead generation.
const PRECONDITION: usize = 9;
/// Leased rows and the lease report no time left.
const LEASE_EXPIRED: usize = 10;
/// A leased row without its generation.
const LEASE_INCONSISTENT: usize = 11;
/// Adds answer OK without an outcome (UNSPECIFIED, or no leased `result`).
const ADD_UNSPECIFIED: usize = 12;
/// Adds answer OK with an outcome value the contract does not define.
const ADD_UNKNOWN_VALUE: usize = 13;
/// Deletes answer OK with outcome UNSPECIFIED.
const DELETE_UNSPECIFIED: usize = 14;
const FOREIGN_BASE: usize = 100;

fn same_key(left: &pb::AddPathRequest, prefix: &str, length: u32) -> bool {
    left.prefix == prefix && left.prefix_length == length
}

impl UnicastFake {
    /// Upserts and returns the daemon's outcome against the previous local route.
    fn insert(&self, request: pb::AddPathRequest) -> pb::AddPathResponse {
        assert_eq!((request.origin, request.path_id), (0, 0));
        assert!(request.as_path.is_empty() && request.extended_communities.is_empty());
        assert!(request.local_pref.is_none() && request.med.is_none());
        assert!(
            request
                .communities
                .contains(&crate::bgp::BLACKHOLE_COMMUNITY)
        );
        let mut paths = self.paths.lock().unwrap();
        let outcome = match paths
            .iter()
            .find(|old| same_key(old, &request.prefix, request.prefix_length))
        {
            None => pb::PathInjectOutcome::Created,
            Some(old) if *old == request => pb::PathInjectOutcome::Unchanged,
            Some(_) => pb::PathInjectOutcome::Replaced,
        } as i32;
        paths.retain(|old| !same_key(old, &request.prefix, request.prefix_length));
        paths.push(request);
        pb::AddPathResponse {
            outcome: match self.mode.load(SeqCst) {
                ADD_UNSPECIFIED => pb::PathInjectOutcome::Unspecified as i32,
                ADD_UNKNOWN_VALUE => 99,
                _ => outcome,
            },
        }
    }
}

#[tonic::async_trait]
impl pb::injection_service_server::InjectionService for UnicastFake {
    async fn add_path(
        &self,
        request: Request<pb::AddPathRequest>,
    ) -> std::result::Result<Response<pb::AddPathResponse>, Status> {
        auth(&request)?;
        if let Some(status) = self.refusal.lock().unwrap().clone() {
            return Err(status);
        }
        if self.mode.load(SeqCst) == PRECONDITION {
            return Err(Status::failed_precondition("key is held by owner"));
        }
        self.plain_adds.fetch_add(1, SeqCst);
        Ok(Response::new(self.insert(request.into_inner())))
    }

    async fn add_leased_path(
        &self,
        request: Request<pb::AddLeasedPathRequest>,
    ) -> std::result::Result<Response<pb::AddLeasedPathResponse>, Status> {
        auth(&request)?;
        if let Some(status) = self.refusal.lock().unwrap().clone() {
            return Err(status);
        }
        match self.mode.load(SeqCst) {
            LEASE_UNIMPLEMENTED => return Err(Status::unimplemented("older daemon")),
            PRECONDITION => return Err(Status::failed_precondition("key is held by no owner")),
            _ => {}
        }
        let request = request.into_inner();
        self.leased.lock().unwrap().push(request.clone());
        let path = request.path.unwrap();
        self.owners
            .lock()
            .unwrap()
            .insert(path.prefix.clone(), request.lease.unwrap().owner);
        let result = self.insert(path);
        Ok(Response::new(pb::AddLeasedPathResponse {
            result: (self.mode.load(SeqCst) != ADD_UNSPECIFIED).then_some(result),
            generation: Some(LIVE),
        }))
    }

    async fn renew_lease(
        &self,
        request: Request<pb::RenewLeaseRequest>,
    ) -> std::result::Result<Response<pb::RenewLeaseResponse>, Status> {
        auth(&request)?;
        if let Some(status) = self.refusal.lock().unwrap().clone() {
            return Err(status);
        }
        match self.mode.load(SeqCst) {
            LEASE_UNIMPLEMENTED => return Err(Status::unimplemented("older daemon")),
            PRECONDITION => {
                return Err(Status::failed_precondition(
                    "lease generation is not live; re-add the owner's desired state",
                ));
            }
            _ => {}
        }
        let request = request.into_inner();
        self.renewals.lock().unwrap().push(request.clone());
        Ok(Response::new(pb::RenewLeaseResponse {
            generation: request.generation,
            lease_remaining_ms: request.lease_seconds * 1000,
        }))
    }

    async fn list_injection_leases(
        &self,
        request: Request<pb::ListInjectionLeasesRequest>,
    ) -> std::result::Result<Response<pb::ListInjectionLeasesResponse>, Status> {
        auth(&request)?;
        if self.mode.load(SeqCst) == LEASE_UNIMPLEMENTED {
            return Err(Status::unimplemented("older daemon"));
        }
        let owner = request.into_inner().owner;
        let held = self.owners.lock().unwrap().values().any(|o| *o == owner);
        Ok(Response::new(pb::ListInjectionLeasesResponse {
            leases: held
                .then(|| pb::InjectionLeaseEntry {
                    owner,
                    generation: Some(LIVE),
                    lease_seconds: 60,
                    lease_remaining_ms: if self.mode.load(SeqCst) == LEASE_EXPIRED {
                        0
                    } else {
                        59_000
                    },
                })
                .into_iter()
                .collect(),
        }))
    }

    async fn delete_path(
        &self,
        request: Request<pb::DeletePathRequest>,
    ) -> std::result::Result<Response<pb::DeletePathResponse>, Status> {
        auth(&request)?;
        if let Some(status) = self.refusal.lock().unwrap().clone() {
            return Err(status);
        }
        let request = request.into_inner();
        assert_eq!(request.path_id, 0);
        assert!(request.allow_missing, "deletes are idempotent");
        assert!(!request.override_owner, "prefixd never overrides the owner");
        self.deletes_seen.lock().unwrap().push(request.clone());
        match self.mode.load(SeqCst) {
            DELETE_NOT_FOUND => return Err(Status::not_found("absent")),
            DELETE_DENIED => return Err(Status::permission_denied("denied")),
            DELETE_INTERNAL => return Err(Status::internal("failed")),
            PRECONDITION => return Err(Status::failed_precondition("key is held by owner")),
            _ => {}
        }
        let mut paths = self.paths.lock().unwrap();
        let before = paths.len();
        paths.retain(|old| !same_key(old, &request.prefix, request.prefix_length));
        let outcome = if self.mode.load(SeqCst) == DELETE_UNSPECIFIED {
            pb::PathDeleteOutcome::Unspecified
        } else if paths.len() == before {
            pb::PathDeleteOutcome::NotPresent
        } else {
            pb::PathDeleteOutcome::Deleted
        };
        Ok(Response::new(pb::DeletePathResponse {
            outcome: outcome as i32,
        }))
    }
}

#[tonic::async_trait]
impl pb::rib_service_server::RibService for UnicastFake {
    async fn list_received_routes(
        &self,
        request: Request<pb::ListRoutesRequest>,
    ) -> std::result::Result<Response<pb::ListRoutesResponse>, Status> {
        auth(&request)?;
        let request = request.into_inner();
        assert_eq!(request.neighbor_address, "0.0.0.0");
        assert!(request.page_size > 0);
        self.pages.fetch_add(1, SeqCst);
        let mode = self.mode.load(SeqCst);
        if mode == LIST_UNIMPLEMENTED {
            return Err(Status::unimplemented("older daemon"));
        }
        let index: usize = if request.page_token.is_empty() {
            0
        } else if mode == ABORT_SECOND_PAGE {
            return Err(Status::aborted("route table changed"));
        } else {
            request.page_token[5..].parse().unwrap()
        };
        let ipv4 = request.afi_safi == pb::AddressFamily::Ipv4Unicast as i32;
        let family: Vec<_> = self
            .paths
            .lock()
            .unwrap()
            .iter()
            .filter(|path| path.prefix.contains('.') == ipv4)
            .cloned()
            .collect();
        let routes = family
            .get(index)
            .map(|path| {
                let mut route = pb::Route {
                    prefix: path.prefix.clone(),
                    prefix_length: path.prefix_length,
                    next_hop: path.next_hop.clone(),
                    peer_address: "0.0.0.0".into(),
                    local_pref: 100,
                    communities: path.communities.clone(),
                    large_communities: path.large_communities.clone(),
                    validation_state: "not_found".into(),
                    aspa_state: "unknown".into(),
                    best: true,
                    ..Default::default()
                };
                // Mutate one row per family; the others must still be returned.
                if mode >= FOREIGN_BASE && route.prefix.ends_with('2') {
                    mutate_row(&mut route, mode);
                }
                if let Some(owner) = self.owners.lock().unwrap().get(&path.prefix) {
                    route.injection_owner = owner.clone();
                    route.lease_generation = (mode != LEASE_INCONSISTENT).then_some(LIVE);
                    route.lease_remaining_ms = Some(if mode == LEASE_EXPIRED { 0 } else { 59_000 });
                }
                route
            })
            .into_iter()
            .collect();
        let next = index + 1;
        let next_page_token = match mode {
            _ if next >= family.len() => String::new(),
            REPEATED_TOKEN => "page-1".into(),
            _ => format!("page-{next}"),
        };
        Ok(Response::new(pb::ListRoutesResponse {
            routes,
            next_page_token,
            total_count: family.len() as u64,
            page_version: Some(pb::RoutePageVersion {
                epoch: 1,
                generation: if mode == VERSION_CHANGES {
                    index as u64
                } else {
                    7
                },
            }),
        }))
    }
}

const ATTRIBUTES: &str = "unexpected path attributes";
const COMMUNITIES: &str = "missing BLACKHOLE or non-canonical communities";
const NEXT_HOP: &str = "next hop is not a same-family unicast address";

/// Well-formed local rows that are not prefixd-shaped, with the reported reason.
const FOREIGN_ROWS: [(usize, &str); 17] = [
    (100, ATTRIBUTES),
    (101, ATTRIBUTES),
    (102, ATTRIBUTES),
    (103, ATTRIBUTES),
    (104, ATTRIBUTES),
    (105, ATTRIBUTES),
    (106, ATTRIBUTES),
    (107, ATTRIBUTES),
    (108, ATTRIBUTES),
    (109, ATTRIBUTES),
    (110, "nonzero path_id"),
    (111, COMMUNITIES),
    (112, COMMUNITIES),
    (113, "not a host route"),
    (114, NEXT_HOP),
    (115, NEXT_HOP),
    // rustbgpd reads an unspecified next hop as next-hop self, never an RTBH discard.
    (116, NEXT_HOP),
];

/// Rows the daemon cannot produce for this view; the read cannot be trusted.
const MALFORMED_ROWS: [usize; 7] = [200, 201, 202, 203, 204, 205, 206];

fn mutate_row(route: &mut pb::Route, case: usize) {
    let ipv4 = route.prefix.contains('.');
    match case {
        100 => route.origin = 2,
        101 => route.as_path = vec![64512],
        102 => route.local_pref_attr = Some(100),
        103 => route.med_attr = Some(0),
        104 => route.med = 10,
        105 => route.extended_communities = vec![1],
        106 => {
            route.aggregator = Some(pb::RouteAggregator {
                asn: 64512,
                router_id: "192.0.2.1".into(),
            })
        }
        107 => route.atomic_aggregate = true,
        108 => route.stale = true,
        109 => route.llgr_stale = true,
        110 => route.path_id = 1,
        111 => route
            .communities
            .retain(|c| *c != crate::bgp::BLACKHOLE_COMMUNITY),
        112 => route.communities.reverse(),
        113 => {
            (route.prefix, route.prefix_length) = if ipv4 {
                ("192.0.2.0".into(), 24)
            } else {
                ("2001:db8::".into(), 64)
            }
        }
        114 => route.next_hop = if ipv4 { "2001:db8::66" } else { "192.0.2.66" }.into(),
        115 => route.next_hop = if ipv4 { "224.0.0.1" } else { "ff02::1" }.into(),
        116 => route.next_hop = if ipv4 { "0.0.0.0" } else { "::" }.into(),
        200 => route.peer_address = "192.0.2.9".into(),
        201 => route.large_communities = vec!["1:2".into()],
        202 => route.prefix_length = 24,
        203 => route.prefix_length = if ipv4 { 33 } else { 129 },
        204 => route.prefix = if ipv4 { "2001:db8::9" } else { "192.0.2.9" }.into(),
        205 => route.prefix = "not-an-address".into(),
        206 => route.next_hop = "not-an-address".into(),
        _ => unreachable!(),
    }
}

async fn unicast_speaker() -> (RustBgpdAnnouncer, UnicastFake, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let fake = UnicastFake::default();
    let incoming = futures_util::stream::unfold(listener, |listener| async {
        Some((listener.accept().await.map(|(stream, _)| stream), listener))
    });
    let server = tonic::transport::Server::builder()
        .add_service(pb::injection_service_server::InjectionServiceServer::new(
            fake.clone(),
        ))
        .add_service(pb::rib_service_server::RibServiceServer::new(fake.clone()))
        .serve_with_incoming(incoming);
    let server = tokio::spawn(async move { server.await.unwrap() });
    let config = RustBgpdConfig {
        endpoint: format!("http://{address}"),
        bearer_token_env: "unused".into(),
        ..Default::default()
    };
    let speaker = RustBgpdAnnouncer::connect_with_token(&config, "test-secret")
        .await
        .unwrap();
    (speaker, fake, server)
}

fn blackhole(prefix: &str, next_hop: &str, extra: u32) -> BlackholeRoute {
    BlackholeRoute::new(
        prefix.parse().unwrap(),
        next_hop.parse().unwrap(),
        vec![64512 << 16 | extra],
        vec![[64512, 666, 1]],
    )
    .unwrap()
}

/// Two IPv4 and three IPv6 host routes, served one per page.
async fn seed_blackholes(speaker: &RustBgpdAnnouncer) -> Vec<BlackholeRoute> {
    let routes = vec![
        blackhole("192.0.2.1/32", "192.0.2.66", 1),
        blackhole("192.0.2.2/32", "192.0.2.66", 1),
        blackhole("2001:db8::1/128", "2001:db8::66", 1),
        blackhole("2001:db8::2/128", "2001:db8::66", 1),
        blackhole("2001:db8::3/128", "2001:db8::66", 1),
    ];
    for route in &routes {
        speaker.announce_blackhole(route).await.unwrap();
    }
    routes
}

#[tokio::test]
async fn blackhole_read_back_pages_to_completion_in_both_families() {
    let (speaker, fake, server) = unicast_speaker().await;
    assert!(speaker.blackhole().is_some());
    let mut expected = seed_blackholes(&speaker).await;
    assert_eq!(speaker.list_blackholes().await.unwrap().routes, expected);
    assert_eq!(fake.pages.load(SeqCst), 5, "one route per page");
    // Upsert replaces the attributes of the same host key.
    let replacement = blackhole("192.0.2.1/32", "192.0.2.67", 2);
    speaker.announce_blackhole(&replacement).await.unwrap();
    expected.remove(0);
    expected.insert(1, replacement);
    assert_eq!(speaker.list_blackholes().await.unwrap().routes, expected);
    for mode in [VERSION_CHANGES, REPEATED_TOKEN] {
        fake.mode.store(mode, SeqCst);
        assert!(speaker.list_blackholes().await.is_err());
    }
    server.abort();
}

#[tokio::test]
async fn blackhole_read_back_aborted_mid_walk_is_an_error() {
    let (speaker, fake, server) = unicast_speaker().await;
    seed_blackholes(&speaker).await;
    fake.mode.store(ABORT_SECOND_PAGE, SeqCst);
    assert!(speaker.list_blackholes().await.is_err());
    // The first page succeeded; ABORTED is not retried and nothing partial is returned.
    assert_eq!(fake.pages.load(SeqCst), 2);
    server.abort();
}

#[tokio::test]
async fn blackhole_empty_view_is_success_distinct_from_unsupported_and_failed() {
    let (speaker, fake, server) = unicast_speaker().await;
    assert_eq!(
        speaker.list_blackholes().await.unwrap(),
        crate::bgp::BlackholeInventory::default()
    );
    assert_eq!(fake.pages.load(SeqCst), 2, "one empty page per family");
    fake.mode.store(LIST_UNIMPLEMENTED, SeqCst);
    assert!(speaker.list_blackholes().await.is_err());
    let gobgp = crate::bgp::GoBgpAnnouncer::new("http://127.0.0.1:1".into());
    assert!(gobgp.blackhole().is_none());
    server.abort();
}

#[tokio::test]
async fn blackhole_unrecognized_local_rows_are_returned_not_dropped_or_errors() {
    let (speaker, fake, server) = unicast_speaker().await;
    let seeded = seed_blackholes(&speaker).await;
    let untouched: Vec<_> = seeded
        .iter()
        .filter(|route| !route.prefix().addr().to_string().ends_with('2'))
        .cloned()
        .collect();
    assert_eq!(untouched.len(), 3);
    for (case, reason) in FOREIGN_ROWS {
        fake.mode.store(case, SeqCst);
        let inventory = speaker
            .list_blackholes()
            .await
            .unwrap_or_else(|error| panic!("foreign row case {case} failed the read: {error}"));
        assert_eq!(inventory.routes, untouched, "case {case}");
        let expected: Vec<_> = if case == 113 {
            ["192.0.2.0/24", "2001:db8::/64"]
        } else {
            ["192.0.2.2/32", "2001:db8::2/128"]
        }
        .into_iter()
        .map(|prefix| crate::bgp::UnrecognizedRoute {
            prefix: prefix.parse().unwrap(),
            reason,
        })
        .collect();
        assert_eq!(inventory.unrecognized, expected, "case {case}");
    }
    server.abort();
}

#[tokio::test]
async fn blackhole_malformed_local_rows_fail_the_whole_read() {
    let (speaker, fake, server) = unicast_speaker().await;
    seed_blackholes(&speaker).await;
    for case in MALFORMED_ROWS {
        fake.mode.store(case, SeqCst);
        assert!(
            speaker.list_blackholes().await.is_err(),
            "malformed row case {case} was accepted"
        );
    }
    server.abort();
}

#[tokio::test]
async fn blackhole_delete_is_idempotent_and_not_found_is_an_error() {
    let (speaker, fake, server) = unicast_speaker().await;
    let routes = seed_blackholes(&speaker).await;
    let v4 = routes[0].prefix();
    // DELETED removes the route.
    speaker.withdraw_blackhole(&v4, "").await.unwrap();
    assert!(
        !speaker
            .list_blackholes()
            .await
            .unwrap()
            .routes
            .iter()
            .any(|route| route.prefix() == v4)
    );
    // NOT_PRESENT for the same key, as after a retry or a daemon restart, is absent.
    speaker.withdraw_blackhole(&v4, "").await.unwrap();
    assert!(
        fake.deletes_seen
            .lock()
            .unwrap()
            .iter()
            .all(|d| d.allow_missing)
    );
    // With allow_missing a 0.79.0 daemon never answers NOT_FOUND: it is an error,
    // as are other codes and a reply without an outcome.
    let v6 = routes[2].prefix();
    for mode in [
        DELETE_NOT_FOUND,
        DELETE_DENIED,
        DELETE_INTERNAL,
        DELETE_UNSPECIFIED,
    ] {
        fake.mode.store(mode, SeqCst);
        assert!(
            speaker.withdraw_blackhole(&v6, "").await.is_err(),
            "mode {mode}"
        );
    }
    fake.mode.store(0, SeqCst);
    assert_eq!(speaker.list_blackholes().await.unwrap().routes.len(), 3);
    assert!(
        speaker
            .withdraw_blackhole(&"2001:db8::/64".parse().unwrap(), "")
            .await
            .is_err()
    );
    assert_eq!(speaker.list_blackholes().await.unwrap().routes.len(), 3);
    server.abort();
}

#[tokio::test]
async fn blackhole_adds_report_the_daemon_outcome() {
    let (speaker, fake, server) = unicast_speaker().await;
    let route = blackhole("192.0.2.1/32", "192.0.2.66", 1);
    let replaced = blackhole("192.0.2.1/32", "192.0.2.67", 1);
    for (route, outcome) in [
        (&route, AddOutcome::Created),
        (&route, AddOutcome::Unchanged),
        (&replaced, AddOutcome::Replaced),
    ] {
        assert_eq!(speaker.announce_blackhole(route).await.unwrap(), outcome);
    }
    let leased = blackhole("192.0.2.2/32", "192.0.2.66", 1).with_owner(LEASE_OWNER);
    for outcome in [AddOutcome::Created, AddOutcome::Unchanged] {
        assert_eq!(
            speaker
                .announce_leased_blackhole(&leased, 60)
                .await
                .unwrap(),
            (live(), outcome)
        );
    }
    // No outcome is still an accepted add; an undefined value is an error.
    fake.mode.store(ADD_UNSPECIFIED, SeqCst);
    assert_eq!(
        speaker.announce_blackhole(&route).await.unwrap(),
        AddOutcome::Unknown
    );
    assert_eq!(
        speaker
            .announce_leased_blackhole(&leased, 60)
            .await
            .unwrap(),
        (live(), AddOutcome::Unknown)
    );
    fake.mode.store(ADD_UNKNOWN_VALUE, SeqCst);
    assert!(speaker.announce_blackhole(&route).await.is_err());
    assert!(
        speaker
            .announce_leased_blackhole(&leased, 60)
            .await
            .is_err()
    );
    server.abort();
}

#[tokio::test]
async fn amplification_components_inject_read_back_and_delete_through_rpc() {
    use crate::domain::{FragmentMatch, PacketLengthRange};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let fake = Fake::default();
    let incoming = futures_util::stream::unfold(listener, |listener| async {
        Some((listener.accept().await.map(|(stream, _)| stream), listener))
    });
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(pb::injection_service_server::InjectionServiceServer::new(
                fake.clone(),
            ))
            .add_service(pb::rib_service_server::RibServiceServer::new(fake.clone()))
            .serve_with_incoming(incoming),
    );
    let config = RustBgpdConfig {
        endpoint: format!("http://{address}"),
        bearer_token_env: "unused".into(),
        ..Default::default()
    };
    let speaker = RustBgpdAnnouncer::connect_with_token(&config, "test-secret")
        .await
        .unwrap();
    assert_eq!(
        (&speaker as &dyn FlowSpecAnnouncer)
            .capabilities()
            .flowspec_match,
        crate::bgp::FlowSpecMatchSupport::ALL
    );
    let mut rules = vec![];
    for prefix in ["192.0.2.1/32", "2001:db8::1/128"] {
        let mut ports = rule(prefix, 0);
        ports.nlri.protocol = Some(17);
        ports.nlri.dst_ports.clear();
        ports.nlri.src_ports = vec![389, 123];
        let mut length = ports.clone();
        length.nlri.packet_length = Some(PacketLengthRange {
            min: 468,
            max: 65535,
        });
        let mut fragment = ports.clone();
        fragment.nlri.src_ports.clear();
        fragment.nlri.fragment = Some(FragmentMatch::NonFirst);
        rules.extend([ports, length, fragment]);
    }
    for rule in &rules {
        speaker.announce(rule).await.unwrap();
    }
    let sent: Vec<Vec<(u32, String)>> = fake
        .rules
        .lock()
        .unwrap()
        .iter()
        .map(|request| {
            request.components[2..]
                .iter()
                .map(|c| (c.r#type, c.value.clone()))
                .collect()
        })
        .collect();
    let ports = (6, "=123, =389".to_string());
    let expected = vec![
        vec![ports.clone()],
        vec![ports, (10, ">=468 & <=65535".into())],
        vec![(12, "0x02".into())],
    ];
    assert_eq!(sent, [expected.clone(), expected].concat());
    let active = speaker.list_active().await.unwrap();
    assert_eq!(active.len(), rules.len());
    for rule in &rules {
        let observed = active
            .iter()
            .find(|r| r.nlri_hash() == rule.nlri_hash())
            .unwrap();
        assert!(speaker.matches_nlri(&rule.nlri, &observed.nlri).unwrap());
    }
    for rule in &rules {
        speaker.withdraw(rule).await.unwrap();
    }
    assert!(speaker.list_active().await.unwrap().is_empty());
    assert_eq!(fake.deletes.load(SeqCst), rules.len());
    server.abort();
}

const LEASE_OWNER: &str = "prefixd.pop-a.0123456789abcdef";

fn live() -> LeaseGeneration {
    LeaseGeneration {
        incarnation: LIVE.incarnation,
        sequence: LIVE.sequence,
    }
}

#[tokio::test]
async fn leased_blackhole_add_read_renew_and_delete_carry_the_owner() {
    let (speaker, fake, server) = unicast_speaker().await;
    let route = blackhole("192.0.2.1/32", "192.0.2.66", 1).with_owner(LEASE_OWNER);
    // Each add refuses the other kind before any RPC.
    assert!(speaker.announce_blackhole(&route).await.is_err());
    let unowned = blackhole("192.0.2.2/32", "192.0.2.66", 1);
    assert!(
        speaker
            .announce_leased_blackhole(&unowned, 60)
            .await
            .is_err()
    );
    assert!(fake.paths.lock().unwrap().is_empty());

    let generation = speaker
        .announce_leased_blackhole(&route, 45)
        .await
        .unwrap()
        .0;
    assert_eq!(generation, live());
    let sent = fake.leased.lock().unwrap()[0].lease.clone().unwrap();
    assert_eq!((sent.owner.as_str(), sent.lease_seconds), (LEASE_OWNER, 45));
    assert_eq!(fake.plain_adds.load(SeqCst), 0);
    // Read-back matches only under the recorded owner.
    let inventory = speaker.list_blackholes().await.unwrap();
    assert_eq!(inventory.routes, std::slice::from_ref(&route));
    assert_ne!(inventory.routes, [route.clone().with_owner("")]);

    assert_eq!(
        speaker.live_lease(LEASE_OWNER).await.unwrap(),
        Some(Some(generation))
    );
    assert!(speaker.lease_confirmed());
    assert_eq!(speaker.live_lease("other.owner").await.unwrap(), Some(None));
    assert!(
        speaker
            .renew_lease(LEASE_OWNER, generation, 45)
            .await
            .unwrap()
    );
    let renewal = fake.renewals.lock().unwrap()[0].clone();
    assert_eq!(
        (
            renewal.owner.as_str(),
            renewal.lease_seconds,
            renewal.generation
        ),
        (LEASE_OWNER, 45, Some(LIVE))
    );

    speaker
        .withdraw_blackhole(&route.prefix(), LEASE_OWNER)
        .await
        .unwrap();
    let delete = fake.deletes_seen.lock().unwrap()[0].clone();
    assert_eq!(delete.owner, LEASE_OWNER);
    assert!(!delete.override_owner);
    server.abort();
}

#[tokio::test]
async fn older_daemon_leased_rpcs_create_nothing_and_never_fall_back() {
    let _metrics = crate::observability::metrics::METRICS_TEST_LOCK
        .lock()
        .await;
    use crate::observability::metrics::{SPEAKER_CAPABILITY, update_speaker_metrics};
    let (speaker, fake, server) = unicast_speaker().await;
    let lease_capability = SPEAKER_CAPABILITY.with_label_values(&["rustbgpd", "blackhole_lease"]);
    update_speaker_metrics(&speaker);
    assert_eq!(lease_capability.get(), 0.0);
    let route = blackhole("192.0.2.1/32", "192.0.2.66", 1).with_owner(LEASE_OWNER);
    // Confirmed by a successful probe, then the daemon is rolled back.
    assert_eq!(speaker.live_lease(LEASE_OWNER).await.unwrap(), Some(None));
    assert!(speaker.lease_confirmed());
    update_speaker_metrics(&speaker);
    assert_eq!(lease_capability.get(), 1.0);
    fake.mode.store(LEASE_UNIMPLEMENTED, SeqCst);
    assert!(speaker.announce_leased_blackhole(&route, 60).await.is_err());
    assert!(
        !speaker.lease_confirmed(),
        "UNIMPLEMENTED withdraws the capability"
    );
    update_speaker_metrics(&speaker);
    assert_eq!(lease_capability.get(), 0.0);
    assert_eq!(fake.plain_adds.load(SeqCst), 0, "no AddPath fallback");
    assert!(fake.paths.lock().unwrap().is_empty());
    assert_eq!(speaker.live_lease(LEASE_OWNER).await.unwrap(), None);
    assert!(speaker.renew_lease(LEASE_OWNER, live(), 60).await.is_err());
    server.abort();
}

#[tokio::test]
async fn ownership_refusals_and_dead_generations_map_by_status_code() {
    let (speaker, fake, server) = unicast_speaker().await;
    let route = blackhole("192.0.2.1/32", "192.0.2.66", 1).with_owner(LEASE_OWNER);
    fake.mode.store(PRECONDITION, SeqCst);
    for error in [
        speaker
            .announce_leased_blackhole(&route, 60)
            .await
            .unwrap_err(),
        speaker
            .announce_blackhole(&blackhole("192.0.2.2/32", "192.0.2.66", 1))
            .await
            .unwrap_err(),
        speaker
            .withdraw_blackhole(&route.prefix(), LEASE_OWNER)
            .await
            .unwrap_err(),
    ] {
        assert!(
            matches!(error, PrefixdError::InjectionOwnerMismatch { .. }),
            "{error}"
        );
    }
    // The plain add reached the daemon and was refused there; nothing was created.
    assert!(fake.paths.lock().unwrap().is_empty());
    // On RenewLease the code means only "that generation is not live".
    assert!(!speaker.renew_lease(LEASE_OWNER, live(), 60).await.unwrap());
    server.abort();
}

fn refusal_status(reason: &str) -> Status {
    rich_refusal(Code::FailedPrecondition, "rustbgpd", reason)
}

fn rich_refusal(code: Code, domain: &str, reason: &str) -> Status {
    let info = ErrorInfo {
        domain: domain.into(),
        reason: reason.into(),
    };
    Status::with_details(
        code,
        "private upstream diagnostic",
        RpcStatus {
            code: code as i32,
            details: vec![prost_types::Any {
                type_url: "type.googleapis.com/google.rpc.ErrorInfo".into(),
                value: info.encode_to_vec(),
            }],
        }
        .encode_to_vec()
        .into(),
    )
}

#[test]
fn injection_refusal_details_require_one_matching_typed_reason() {
    for (wire, expected) in [
        ("OWNER_MISMATCH", InjectionRefusalReason::OwnerMismatch),
        ("KEY_UNOWNED", InjectionRefusalReason::KeyUnowned),
        (
            "GENERATION_NOT_LIVE",
            InjectionRefusalReason::GenerationNotLive,
        ),
    ] {
        assert_eq!(
            injection_refusal_reason(&refusal_status(wire)),
            Some(expected)
        );
    }
    let valid = refusal_status("OWNER_MISMATCH");
    let rich = RpcStatus::decode(valid.details()).unwrap();
    let mut mismatched_code = rich.clone();
    mismatched_code.code = Code::Ok as i32;
    let mut wrong_type = rich.clone();
    wrong_type.details[0].type_url = "untrusted/google.rpc.ErrorInfo".into();
    let mut malformed_info = rich.clone();
    malformed_info.details[0].value = vec![0xff];
    let mut contradictory = rich.clone();
    contradictory.details.push(
        RpcStatus::decode(refusal_status("KEY_UNOWNED").details())
            .unwrap()
            .details
            .remove(0),
    );
    let mut duplicate = rich.clone();
    duplicate.details.extend(rich.details.clone());
    let mut controls = vec![
        Status::failed_precondition("OWNER_MISMATCH"),
        Status::with_details(
            Code::FailedPrecondition,
            "OWNER_MISMATCH",
            vec![0xff].into(),
        ),
        rich_refusal(Code::InvalidArgument, "rustbgpd", "OWNER_MISMATCH"),
        rich_refusal(Code::FailedPrecondition, "other", "OWNER_MISMATCH"),
        refusal_status("A_NEW_REASON"),
    ];
    controls.extend(
        [
            mismatched_code,
            wrong_type,
            malformed_info,
            contradictory,
            duplicate,
        ]
        .map(|rich| {
            Status::with_details(
                Code::FailedPrecondition,
                "OWNER_MISMATCH",
                rich.encode_to_vec().into(),
            )
        }),
    );
    for status in controls {
        assert_eq!(injection_refusal_reason(&status), None, "{status:?}");
    }
}

#[tokio::test]
async fn typed_refusals_round_trip_over_grpc_without_mutating_routes() {
    let (speaker, fake, server) = unicast_speaker().await;
    let (flowspec, flow_fake, flow_server) = flowspec_speaker().await;
    let route = blackhole("192.0.2.1/32", "192.0.2.66", 1).with_owner(LEASE_OWNER);
    let flow = rule("192.0.2.1/32", 0).with_owner(LEASE_OWNER);
    for (status, expected) in [
        (
            refusal_status("OWNER_MISMATCH"),
            InjectionRefusalReason::OwnerMismatch,
        ),
        (
            refusal_status("KEY_UNOWNED"),
            InjectionRefusalReason::KeyUnowned,
        ),
        (
            refusal_status("GENERATION_NOT_LIVE"),
            InjectionRefusalReason::Unspecified,
        ),
        (
            rich_refusal(Code::FailedPrecondition, "other", "KEY_UNOWNED"),
            InjectionRefusalReason::Unspecified,
        ),
        (
            Status::failed_precondition("OWNER_MISMATCH"),
            InjectionRefusalReason::Unspecified,
        ),
        (
            refusal_status("A_NEW_REASON"),
            InjectionRefusalReason::Unspecified,
        ),
        (
            Status::with_details(
                Code::FailedPrecondition,
                "private upstream diagnostic",
                vec![0xff].into(),
            ),
            InjectionRefusalReason::Unspecified,
        ),
    ] {
        *fake.refusal.lock().unwrap() = Some(status.clone());
        *flow_fake.refusal.lock().unwrap() = Some(status);
        for error in [
            speaker
                .announce_leased_blackhole(&route, 60)
                .await
                .unwrap_err(),
            speaker
                .announce_blackhole(&blackhole("192.0.2.2/32", "192.0.2.66", 1))
                .await
                .unwrap_err(),
            speaker
                .withdraw_blackhole(&route.prefix(), LEASE_OWNER)
                .await
                .unwrap_err(),
            flowspec.announce_leased(&flow, 60).await.unwrap_err(),
            flowspec
                .announce(&rule("192.0.2.2/32", 0))
                .await
                .unwrap_err(),
            flowspec.withdraw(&flow).await.unwrap_err(),
        ] {
            assert!(
                matches!(error, PrefixdError::InjectionOwnerMismatch { reason, .. } if reason == expected),
                "{error}"
            );
            assert_eq!(error.status_code(), axum::http::StatusCode::CONFLICT);
            assert!(!error.to_string().contains("private upstream"));
        }
        assert!(!speaker.renew_lease(LEASE_OWNER, live(), 60).await.unwrap());
    }
    assert!(fake.paths.lock().unwrap().is_empty());
    assert!(fake.leased.lock().unwrap().is_empty());
    assert_eq!(fake.plain_adds.load(SeqCst), 0);
    assert!(flow_fake.rules.lock().unwrap().is_empty());
    assert!(flow_fake.leased.lock().unwrap().is_empty());
    server.abort();
    flow_server.abort();
}

#[tokio::test]
async fn leased_read_back_reports_expired_rows_and_rejects_partial_lease_fields() {
    let (speaker, fake, server) = unicast_speaker().await;
    let route = blackhole("192.0.2.1/32", "192.0.2.66", 1).with_owner(LEASE_OWNER);
    speaker.announce_leased_blackhole(&route, 60).await.unwrap();
    fake.mode.store(LEASE_EXPIRED, SeqCst);
    let inventory = speaker.list_blackholes().await.unwrap();
    assert!(inventory.routes.is_empty());
    assert_eq!(inventory.expired, [route]);
    // An expired lease is not adoptable: it cannot be renewed.
    assert_eq!(speaker.live_lease(LEASE_OWNER).await.unwrap(), Some(None));
    fake.mode.store(LEASE_INCONSISTENT, SeqCst);
    assert!(speaker.list_blackholes().await.is_err());
    server.abort();
}

async fn flowspec_speaker() -> (RustBgpdAnnouncer, Fake, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let fake = Fake::default();
    let incoming = futures_util::stream::unfold(listener, |listener| async {
        Some((listener.accept().await.map(|(stream, _)| stream), listener))
    });
    let server = tonic::transport::Server::builder()
        .add_service(pb::injection_service_server::InjectionServiceServer::new(
            fake.clone(),
        ))
        .add_service(pb::rib_service_server::RibServiceServer::new(fake.clone()))
        .serve_with_incoming(incoming);
    let server = tokio::spawn(async move { server.await.unwrap() });
    let config = RustBgpdConfig {
        endpoint: format!("http://{address}"),
        bearer_token_env: "unused".into(),
        ..Default::default()
    };
    let speaker = RustBgpdAnnouncer::connect_with_token(&config, "test-secret")
        .await
        .unwrap();
    (speaker, fake, server)
}

#[tokio::test]
async fn source_prefix_rpc_identity_delete_and_whole_inventory_failure() {
    let (speaker, fake, server) = flowspec_speaker().await;
    let mut rules = Vec::new();
    for (destination, sources) in [
        (
            "192.0.2.1/32",
            [
                None,
                Some("0.0.0.0/0"),
                Some("198.51.100.129/24"),
                Some("198.51.100.128/25"),
            ],
        ),
        (
            "2001:db8::1/128",
            [
                None,
                Some("::/0"),
                Some("2001:DB8:1::1/48"),
                Some("2001:db8:1::/64"),
            ],
        ),
    ] {
        for source in sources {
            let mut rule = rule(destination, 0);
            rule.nlri.src_prefix = source.map(str::to_owned);
            speaker.announce(&rule).await.unwrap();
            speaker.announce(&rule).await.unwrap();
            rules.push(rule);
        }
    }
    let active = speaker.list_active().await.unwrap();
    assert_eq!(active.len(), rules.len());
    for rule in &rules {
        let read = active
            .iter()
            .find(|read| read.nlri_hash() == rule.nlri_hash())
            .unwrap();
        assert!(speaker.matches_nlri(&rule.nlri, &read.nlri).unwrap());
    }
    // A malformed source at the end of an otherwise valid view fails the whole read.
    let index = fake
        .rules
        .lock()
        .unwrap()
        .iter()
        .position(|rule| rule.components.iter().any(|c| c.r#type == 2))
        .unwrap();
    fake.rules.lock().unwrap()[index].components[1].offset = 1;
    assert!(speaker.list_active().await.is_err());
    fake.rules.lock().unwrap()[index].components[1].offset = 0;
    for (index, rule) in rules.iter().enumerate() {
        speaker.withdraw(rule).await.unwrap();
        speaker.withdraw(rule).await.unwrap();
        let active = speaker.list_active().await.unwrap();
        assert_eq!(active.len(), rules.len() - index - 1);
        for remaining in &rules[index + 1..] {
            assert!(
                active
                    .iter()
                    .any(|read| read.nlri_hash() == remaining.nlri_hash())
            );
        }
    }
    server.abort();
}

#[tokio::test]
async fn leased_flowspec_adds_reads_and_deletes_under_the_recorded_owner() {
    let (speaker, fake, server) = flowspec_speaker().await;
    let leased = rule("192.0.2.1/32", 0).with_owner(LEASE_OWNER);
    // Each add refuses the other kind before any RPC.
    assert!(speaker.announce(&leased).await.is_err());
    assert!(
        speaker
            .announce_leased(&rule("192.0.2.2/32", 0), 60)
            .await
            .is_err()
    );
    assert_eq!(fake.attempts.load(SeqCst), 0);

    let generation = speaker.announce_leased(&leased, 45).await.unwrap();
    assert_eq!(generation, live());
    let sent = fake.leased.lock().unwrap()[0].clone();
    let lease = sent.lease.unwrap();
    assert_eq!(
        (lease.owner.as_str(), lease.lease_seconds),
        (LEASE_OWNER, 45)
    );
    assert_eq!(sent.rule.unwrap(), encode(&leased).unwrap());
    assert_eq!(fake.attempts.load(SeqCst), 0, "no AddFlowSpec");
    // An unleased rule beside it keeps the plain RPC and an empty owner.
    let unleased = rule("192.0.2.3/32", 0);
    speaker.announce(&unleased).await.unwrap();
    let mut owners: Vec<_> = speaker
        .list_active()
        .await
        .unwrap()
        .into_iter()
        .map(|rule| (rule.nlri.dst_prefix, rule.owner))
        .collect();
    owners.sort();
    assert_eq!(
        owners,
        [
            ("192.0.2.1/32".to_string(), LEASE_OWNER.to_string()),
            ("192.0.2.3/32".to_string(), String::new()),
        ]
    );
    // A leased row with no time left is lost intent, not a retained rule.
    fake.mode.store(FLOWSPEC_LEASE_EXPIRED, SeqCst);
    let remaining = speaker.list_active().await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert!(remaining[0].owner.is_empty());
    fake.mode.store(0, SeqCst);
    // Deletes pass the recorded owner; a mismatch is the daemon's refusal.
    assert!(matches!(
        speaker.withdraw(&rule("192.0.2.1/32", 0)).await,
        Err(PrefixdError::InjectionOwnerMismatch { .. })
    ));
    speaker.withdraw(&leased).await.unwrap();
    speaker.withdraw(&unleased).await.unwrap();
    assert_eq!(*fake.delete_owners.lock().unwrap(), ["", LEASE_OWNER, ""]);
    server.abort();
}

#[tokio::test]
async fn older_daemon_leased_flowspec_creates_nothing_and_never_falls_back() {
    let (speaker, fake, server) = flowspec_speaker().await;
    fake.mode.store(FLOWSPEC_LEASE_UNIMPLEMENTED, SeqCst);
    let leased = rule("192.0.2.1/32", 0).with_owner(LEASE_OWNER);
    assert!(speaker.announce_leased(&leased, 60).await.is_err());
    assert_eq!(fake.attempts.load(SeqCst), 0, "no AddFlowSpec fallback");
    assert!(fake.rules.lock().unwrap().is_empty());
    server.abort();
}

/// Export dispositions served two peers per page, whatever the request asks.
#[derive(Clone, Default)]
struct ExportFake {
    rows: Arc<Mutex<Vec<pb::PathExportDispositionEntry>>>,
    mode: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<pb::ListPathExportDispositionsRequest>>>,
    flowspec_requests: Arc<Mutex<Vec<pb::ListFlowSpecExportDispositionsRequest>>>,
    /// Later pages answer ABORTED this many times.
    aborts: Arc<AtomicUsize>,
}

const EXPORT_NO_ROUTE: usize = 1;
const EXPORT_NO_ROUTE_SECOND_PAGE: usize = 2;
const EXPORT_UNAVAILABLE: usize = 3;
const EXPORT_DENIED_SECOND_PAGE: usize = 4;
const EXPORT_REPEATED_TOKEN: usize = 5;
const EXPORT_REPEATED_PEER: usize = 6;
const EXPORT_ABORT_FIRST: usize = 7;

#[tonic::async_trait]
impl pb::injection_service_server::InjectionService for ExportFake {
    async fn list_flow_spec_export_dispositions(
        &self,
        request: Request<pb::ListFlowSpecExportDispositionsRequest>,
    ) -> std::result::Result<Response<pb::ListPathExportDispositionsResponse>, Status> {
        auth(&request)?;
        let (metadata, extensions, request) = request.into_parts();
        self.flowspec_requests.lock().unwrap().push(request.clone());
        self.list_path_export_dispositions(Request::from_parts(
            metadata,
            extensions,
            pb::ListPathExportDispositionsRequest {
                prefix: "203.0.113.1".into(),
                prefix_length: 32,
                path_id: 0,
                page_size: request.page_size,
                page_token: request.page_token,
                include_configured: request.include_configured,
            },
        ))
        .await
    }

    async fn list_path_export_dispositions(
        &self,
        request: Request<pb::ListPathExportDispositionsRequest>,
    ) -> std::result::Result<Response<pb::ListPathExportDispositionsResponse>, Status> {
        self.calls.fetch_add(1, SeqCst);
        auth(&request)?;
        let request = request.into_inner();
        self.requests.lock().unwrap().push(request.clone());
        let first = request.page_token.is_empty();
        let mode = self.mode.load(SeqCst);
        match mode {
            EXPORT_NO_ROUTE => return Err(Status::not_found("no local route")),
            EXPORT_NO_ROUTE_SECOND_PAGE if !first => {
                return Err(Status::not_found("no local route"));
            }
            EXPORT_UNAVAILABLE => return Err(Status::unavailable("speaker restarting")),
            EXPORT_DENIED_SECOND_PAGE if !first => {
                return Err(Status::permission_denied("denied"));
            }
            _ => {}
        }
        if (mode == EXPORT_ABORT_FIRST || !first) && self.aborts.load(SeqCst) > 0 {
            self.aborts.fetch_sub(1, SeqCst);
            return Err(Status::aborted("export walk changed"));
        }
        let rows = self.rows.lock().unwrap().clone();
        // A repeated-peer page restarts one row too early.
        let start = match (first, mode) {
            (true, _) => 0,
            (false, EXPORT_REPEATED_PEER) => 1,
            (false, _) => {
                rows.iter()
                    .position(|row| row.peer_address == request.page_token)
                    .unwrap()
                    + 1
            }
        };
        let page: Vec<_> = rows.iter().skip(start).take(2).cloned().collect();
        let more = start + page.len() < rows.len();
        let next_page_token = match mode {
            _ if !more => String::new(),
            EXPORT_REPEATED_TOKEN if !first => request.page_token,
            _ => page.last().unwrap().peer_address.clone(),
        };
        Ok(Response::new(pb::ListPathExportDispositionsResponse {
            peers: page,
            next_page_token,
        }))
    }
}

async fn export_speaker() -> (RustBgpdAnnouncer, ExportFake, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let fake = ExportFake::default();
    let incoming = futures_util::stream::unfold(listener, |listener| async {
        Some((listener.accept().await.map(|(stream, _)| stream), listener))
    });
    let server = tonic::transport::Server::builder()
        .add_service(pb::injection_service_server::InjectionServiceServer::new(
            fake.clone(),
        ))
        .serve_with_incoming(incoming);
    let server = tokio::spawn(async move { server.await.unwrap() });
    let config = RustBgpdConfig {
        endpoint: format!("http://{address}"),
        bearer_token_env: "unused".into(),
        ..Default::default()
    };
    let speaker = RustBgpdAnnouncer::connect_with_token(&config, "test-secret")
        .await
        .unwrap();
    (speaker, fake, server)
}

fn export_row(
    peer: &str,
    disposition: pb::PathExportDisposition,
    reason: &str,
    explain_code: &str,
) -> pb::PathExportDispositionEntry {
    pb::PathExportDispositionEntry {
        peer_address: peer.into(),
        disposition: disposition as i32,
        reason: reason.into(),
        explain_code: explain_code.into(),
        detail: format!("detail for {peer}"),
        advertised_path_id: u32::from(disposition == pb::PathExportDisposition::Committed),
        ..Default::default()
    }
}

/// Five peers, three pages: committed, two withheld reasons, pending.
fn export_rows() -> Vec<pb::PathExportDispositionEntry> {
    use pb::PathExportDisposition::{Committed, Pending, Withheld};
    vec![
        export_row("192.0.2.1", Committed, "", ""),
        export_row("192.0.2.2", Withheld, "export_policy", "policy_denied"),
        export_row(
            "192.0.2.3",
            Withheld,
            "family_suppressed:missing_ipv6_next_hop",
            "family_not_sendable",
        ),
        export_row("2001:db8::4", Pending, "not_yet_committed", ""),
        export_row("2001:db8::5", Withheld, "not_selected", ""),
    ]
}

#[tokio::test]
async fn export_dispositions_page_to_completion_and_keep_every_field() {
    let (speaker, fake, server) = export_speaker().await;
    assert!(speaker.export_observer().is_some());
    let expected = export_rows();
    *fake.rows.lock().unwrap() = expected.clone();
    let prefix: ipnet::IpNet = "2001:db8::7/128".parse().unwrap();
    let peers = speaker.blackhole_exports(&prefix).await.unwrap().unwrap();
    assert_eq!(fake.calls.load(SeqCst), 3, "two peers per page");
    let requests = fake.requests.lock().unwrap().clone();
    for (request, token) in requests.iter().zip(["", "192.0.2.2", "2001:db8::4"]) {
        assert_eq!(
            (
                request.prefix.as_str(),
                request.prefix_length,
                request.path_id
            ),
            ("2001:db8::7", 128, 0)
        );
        assert_eq!(request.page_size, ROUTE_PAGE_SIZE);
        assert!(
            request.include_configured,
            "configured peers must be part of every export page"
        );
        assert_eq!(request.page_token, token);
    }
    let dispositions: Vec<_> = peers.iter().map(|peer| peer.disposition).collect();
    use ExportDisposition::{Committed, Pending, Withheld};
    assert_eq!(
        dispositions,
        [Committed, Withheld, Withheld, Pending, Withheld]
    );
    for (peer, row) in peers.iter().zip(&expected) {
        assert_eq!(peer.peer_address, row.peer_address);
        assert_eq!(peer.reason, row.reason);
        assert_eq!(peer.explain_code, row.explain_code);
        assert_eq!(peer.detail, row.detail);
        assert_eq!(peer.advertised_path_id, row.advertised_path_id);
    }
    server.abort();
}

#[tokio::test]
async fn configured_peers_decode_for_both_export_rpcs_without_session_observation() {
    let (speaker, fake, server) = export_speaker().await;
    let mut rows = export_rows();
    rows[0] = export_row(
        "fe80::1",
        pb::PathExportDisposition::NotEstablished,
        "not_established",
        "",
    );
    rows[0].peer_interface = "eth0".into();
    *fake.rows.lock().unwrap() = rows;
    let nlri = FlowSpecNlri {
        dst_prefix: "203.0.113.1/32".into(),
        ..Default::default()
    };
    for read in [
        speaker
            .blackhole_exports(&"203.0.113.1/32".parse().unwrap())
            .await,
        speaker.flowspec_exports(&nlri).await,
    ] {
        let peers = read.unwrap().unwrap();
        assert_eq!(peers[0].disposition, ExportDisposition::NotEstablished);
        assert_eq!(peers[0].peer_address, "fe80::1%eth0");
        let evidence = crate::domain::BlackholeExportEvidence::from_read(
            &Ok(Some(peers)),
            None,
            chrono::Utc::now(),
        );
        let down = evidence.not_established_peers.unwrap();
        assert_eq!(down.len(), 1);
        assert_eq!(down[0].state, None);
        assert_eq!(evidence.counts.committed, 0);
        assert_eq!(evidence.counts.withheld, 3);
        assert_eq!(evidence.counts.pending, 1);
    }
    assert!(
        fake.requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request.include_configured)
    );
    assert!(
        fake.flowspec_requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request.include_configured)
    );
    server.abort();
}

/// A speaker-restart selection hold decodes as PENDING with its reason and is
/// reported as held, never committed.
#[tokio::test]
async fn selection_deferred_rows_decode_as_pending_and_are_never_committed() {
    use pb::PathExportDisposition::Pending;
    let (speaker, fake, server) = export_speaker().await;
    *fake.rows.lock().unwrap() = vec![
        export_row("192.0.2.1", Pending, "selection_deferred", ""),
        export_row("2001:db8::2", Pending, "selection_deferred", ""),
    ];
    let prefix: ipnet::IpNet = "192.0.2.7/32".parse().unwrap();
    let peers = speaker.blackhole_exports(&prefix).await.unwrap().unwrap();
    assert!(peers.iter().all(|peer| {
        peer.disposition == ExportDisposition::Pending && peer.reason == "selection_deferred"
    }));
    let evidence = crate::domain::BlackholeExportEvidence::from_read(
        &Ok(Some(peers)),
        None,
        chrono::Utc::now(),
    );
    assert_eq!(evidence.counts.committed, 0);
    assert_eq!(evidence.counts.pending, 2);
    assert_eq!(evidence.warning.unwrap().reason, "selection_deferred");
    server.abort();
}

/// ABORTED mid-walk discards the pages read and restarts once from the first
/// page; a second ABORTED is an error, never a partial or empty list.
#[tokio::test]
async fn export_walk_restarts_once_after_aborted() {
    let (speaker, fake, server) = export_speaker().await;
    *fake.rows.lock().unwrap() = export_rows();
    let prefix: ipnet::IpNet = "192.0.2.7/32".parse().unwrap();
    fake.aborts.store(1, SeqCst);
    let peers = speaker.blackhole_exports(&prefix).await.unwrap().unwrap();
    let addresses: Vec<_> = peers
        .iter()
        .map(|peer| peer.peer_address.as_str())
        .collect();
    let expected: Vec<_> = export_rows()
        .into_iter()
        .map(|row| row.peer_address)
        .collect();
    assert_eq!(addresses, expected, "one complete walk, no repeated rows");
    let tokens: Vec<_> = fake
        .requests
        .lock()
        .unwrap()
        .iter()
        .map(|request| request.page_token.clone())
        .collect();
    assert_eq!(tokens, ["", "192.0.2.2", "", "192.0.2.2", "2001:db8::4"]);

    fake.requests.lock().unwrap().clear();
    fake.aborts.store(2, SeqCst);
    let read = speaker.blackhole_exports(&prefix).await;
    assert!(read.is_err(), "repeated ABORTED: {read:?}");
    assert_eq!(fake.requests.lock().unwrap().len(), 4, "one restart only");
    server.abort();
}

/// An empty list is a successful read: no Established peer, not an error.
/// A missing route is `None`, and every failure is an error, never a list.
#[tokio::test]
async fn export_read_distinguishes_empty_absent_and_failed() {
    let (speaker, fake, server) = export_speaker().await;
    let prefix: ipnet::IpNet = "192.0.2.7/32".parse().unwrap();
    assert_eq!(
        speaker.blackhole_exports(&prefix).await.unwrap(),
        Some(vec![])
    );
    fake.mode.store(EXPORT_NO_ROUTE, SeqCst);
    assert_eq!(speaker.blackhole_exports(&prefix).await.unwrap(), None);

    *fake.rows.lock().unwrap() = export_rows();
    for mode in [
        EXPORT_NO_ROUTE_SECOND_PAGE,
        EXPORT_DENIED_SECOND_PAGE,
        EXPORT_REPEATED_TOKEN,
        EXPORT_REPEATED_PEER,
    ] {
        fake.mode.store(mode, SeqCst);
        let read = speaker.blackhole_exports(&prefix).await;
        assert!(read.is_err(), "mode {mode}: partial read {read:?}");
    }
    fake.mode.store(EXPORT_UNAVAILABLE, SeqCst);
    let before = fake.calls.load(SeqCst);
    assert!(speaker.blackhole_exports(&prefix).await.is_err());
    assert_eq!(fake.calls.load(SeqCst), before + 3, "transient retries");

    fake.mode.store(0, SeqCst);
    for malformed in [
        export_row(
            "not-an-address",
            pb::PathExportDisposition::Committed,
            "",
            "",
        ),
        export_row("192.0.2.9", pb::PathExportDisposition::Unspecified, "", ""),
        pb::PathExportDispositionEntry {
            disposition: 9,
            ..export_row("192.0.2.9", pb::PathExportDisposition::Committed, "", "")
        },
    ] {
        *fake.rows.lock().unwrap() = vec![malformed];
        assert!(speaker.blackhole_exports(&prefix).await.is_err());
    }
    // GoBGP has no export read: unsupported, which is neither empty nor failed.
    let gobgp = crate::bgp::GoBgpAnnouncer::new("http://127.0.0.1:1".into());
    assert!(gobgp.export_observer().is_none());
    assert!(
        !(&gobgp as &dyn FlowSpecAnnouncer)
            .capabilities()
            .blackhole_export
    );
    assert!(
        (&speaker as &dyn FlowSpecAnnouncer)
            .capabilities()
            .blackhole_export
    );
    server.abort();
}

#[tokio::test]
async fn flowspec_export_key_matches_add_for_both_families_and_scoped_peers() {
    for dst in ["203.0.113.1/32", "2001:db8::1/128"] {
        let (speaker, fake, server) = export_speaker().await;
        let mut rows = export_rows();
        rows[0].peer_address = "fe80::1".into();
        rows[0].peer_interface = "eth0".into();
        rows[1].peer_address = "fe80::1".into();
        rows[1].peer_interface = "eth1".into();
        rows.truncate(2);
        *fake.rows.lock().unwrap() = rows;
        let rule = FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: dst.into(),
                protocol: Some(17),
                dst_ports: vec![53, 123],
                src_ports: vec![53],
                ..Default::default()
            },
            FlowSpecAction::discard(),
        );
        let add = encode(&rule).unwrap();
        let peers = speaker.flowspec_exports(&rule.nlri).await.unwrap().unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].peer_address, "fe80::1%eth0");
        assert_eq!(peers[1].peer_address, "fe80::1%eth1");
        for request in fake.flowspec_requests.lock().unwrap().iter() {
            assert_eq!(request.afi_safi, add.afi_safi);
            assert_eq!(request.components, add.components);
            assert!(request.include_configured);
        }
        server.abort();
    }
}

#[tokio::test]
async fn flowspec_export_reads_refuse_partial_invalid_and_repeated_snapshots() {
    let nlri = FlowSpecNlri {
        dst_prefix: "203.0.113.1/32".into(),
        ..Default::default()
    };
    for mode in [
        EXPORT_NO_ROUTE_SECOND_PAGE,
        EXPORT_DENIED_SECOND_PAGE,
        EXPORT_REPEATED_TOKEN,
        EXPORT_REPEATED_PEER,
    ] {
        let (speaker, fake, server) = export_speaker().await;
        *fake.rows.lock().unwrap() = export_rows();
        fake.mode.store(mode, SeqCst);
        assert!(
            speaker.flowspec_exports(&nlri).await.is_err(),
            "mode {mode}"
        );
        server.abort();
    }
    let (speaker, fake, server) = export_speaker().await;
    fake.mode.store(EXPORT_NO_ROUTE, SeqCst);
    assert_eq!(speaker.flowspec_exports(&nlri).await.unwrap(), None);
    fake.mode.store(0, SeqCst);
    assert_eq!(speaker.flowspec_exports(&nlri).await.unwrap(), Some(vec![]));
    for invalid in [pb::PathExportDisposition::Unspecified as i32, 999] {
        let mut row = export_rows().remove(0);
        row.disposition = invalid;
        *fake.rows.lock().unwrap() = vec![row];
        assert!(speaker.flowspec_exports(&nlri).await.is_err());
    }
    server.abort();
}

#[tokio::test]
async fn flowspec_export_walk_restarts_once_even_when_first_page_is_aborted() {
    let nlri = FlowSpecNlri {
        dst_prefix: "203.0.113.1/32".into(),
        ..Default::default()
    };
    for mode in [0, EXPORT_ABORT_FIRST] {
        for aborts in [1, 2] {
            let (speaker, fake, server) = export_speaker().await;
            *fake.rows.lock().unwrap() = export_rows();
            fake.mode.store(mode, SeqCst);
            fake.aborts.store(aborts, SeqCst);
            let read = speaker.flowspec_exports(&nlri).await;
            if aborts == 1 {
                assert_eq!(read.unwrap().unwrap().len(), export_rows().len());
            } else {
                assert!(read.is_err());
            }
            let requests = fake.flowspec_requests.lock().unwrap();
            assert_eq!(
                requests
                    .iter()
                    .filter(|request| request.page_token.is_empty())
                    .count(),
                2
            );
            server.abort();
        }
    }
}
