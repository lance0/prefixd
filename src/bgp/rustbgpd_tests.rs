use super::*;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering::SeqCst},
};
use tonic::{Response, Status};

#[derive(Clone, Default)]
struct Fake {
    rules: Arc<Mutex<Vec<pb::AddFlowSpecRequest>>>,
    mode: Arc<AtomicUsize>,
    attempts: Arc<AtomicUsize>,
    health_calls: Arc<AtomicUsize>,
    families: Arc<Mutex<Vec<i32>>>,
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
        Ok(Response::new(pb::HealthResponse {
            healthy: true,
            uptime_seconds: 123,
            daemon_version: "observed-daemon-version".into(),
            ..Default::default()
        }))
    }
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
        assert_eq!(
            request
                .components
                .iter()
                .map(|c| c.r#type)
                .collect::<Vec<_>>(),
            [1, 3, 5]
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

    async fn delete_flow_spec(
        &self,
        request: Request<pb::DeleteFlowSpecRequest>,
    ) -> std::result::Result<Response<pb::DeleteFlowSpecResponse>, Status> {
        auth(&request)?;
        let request = request.into_inner();
        assert!(request.allow_missing);
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
                for component in &mut components {
                    component.value = component.value.replace('=', "==");
                }
                if self.mode.load(SeqCst) == 8 {
                    components.push(pb::FlowSpecComponent {
                        r#type: 10,
                        value: ">80".into(),
                        ..Default::default()
                    });
                }
                pb::ReceivedFlowSpecRouteEntry {
                    route: Some(pb::FlowSpecRouteEntry {
                        components,
                        actions: rule.actions.clone(),
                        peer_address: "0.0.0.0".into(),
                        afi_safi: rule.afi_safi,
                        extended_communities: vec![
                            (0x8006_u64 << 48) | u64::from(rate.rate.to_bits()),
                        ],
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
    let speaker = RustBgpdAnnouncer {
        channel: Endpoint::from_shared(format!("http://{address}"))
            .unwrap()
            .connect()
            .await
            .unwrap(),
        token: Some("Bearer test-secret".parse().unwrap()),
    };
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
    pages: Arc<AtomicUsize>,
}

const ABORT_SECOND_PAGE: usize = 1;
const DELETE_NOT_FOUND: usize = 2;
const DELETE_DENIED: usize = 3;
const DELETE_INTERNAL: usize = 4;
const LIST_UNIMPLEMENTED: usize = 5;
const VERSION_CHANGES: usize = 6;
const REPEATED_TOKEN: usize = 7;
const FOREIGN_BASE: usize = 100;

fn same_key(left: &pb::AddPathRequest, prefix: &str, length: u32) -> bool {
    left.prefix == prefix && left.prefix_length == length
}

#[tonic::async_trait]
impl pb::injection_service_server::InjectionService for UnicastFake {
    async fn add_path(
        &self,
        request: Request<pb::AddPathRequest>,
    ) -> std::result::Result<Response<pb::AddPathResponse>, Status> {
        auth(&request)?;
        let request = request.into_inner();
        assert_eq!((request.origin, request.path_id), (0, 0));
        assert!(request.as_path.is_empty() && request.extended_communities.is_empty());
        assert!(request.local_pref.is_none() && request.med.is_none());
        assert!(
            request
                .communities
                .contains(&crate::bgp::BLACKHOLE_COMMUNITY)
        );
        let mut paths = self.paths.lock().unwrap();
        paths.retain(|old| !same_key(old, &request.prefix, request.prefix_length));
        paths.push(request);
        Ok(Response::new(pb::AddPathResponse {}))
    }

    async fn delete_path(
        &self,
        request: Request<pb::DeletePathRequest>,
    ) -> std::result::Result<Response<pb::DeletePathResponse>, Status> {
        auth(&request)?;
        let request = request.into_inner();
        assert_eq!(request.path_id, 0);
        match self.mode.load(SeqCst) {
            DELETE_NOT_FOUND => return Err(Status::not_found("absent")),
            DELETE_DENIED => return Err(Status::permission_denied("denied")),
            DELETE_INTERNAL => return Err(Status::internal("failed")),
            _ => {}
        }
        let mut paths = self.paths.lock().unwrap();
        let before = paths.len();
        paths.retain(|old| !same_key(old, &request.prefix, request.prefix_length));
        if paths.len() == before {
            // The released daemon has no allow_missing: a missing path is NOT_FOUND.
            return Err(Status::not_found("no injected path"));
        }
        Ok(Response::new(pb::DeletePathResponse {}))
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
const FOREIGN_ROWS: [(usize, &str); 16] = [
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
async fn blackhole_delete_not_found_is_absent_and_other_codes_are_errors() {
    let (speaker, fake, server) = unicast_speaker().await;
    let routes = seed_blackholes(&speaker).await;
    let v4 = routes[0].prefix();
    speaker.withdraw_blackhole(&v4).await.unwrap();
    assert!(
        !speaker
            .list_blackholes()
            .await
            .unwrap()
            .routes
            .iter()
            .any(|route| route.prefix() == v4)
    );
    // The daemon now answers NOT_FOUND for the same key.
    speaker.withdraw_blackhole(&v4).await.unwrap();
    fake.mode.store(DELETE_NOT_FOUND, SeqCst);
    speaker.withdraw_blackhole(&v4).await.unwrap();
    let v6 = routes[2].prefix();
    for mode in [DELETE_DENIED, DELETE_INTERNAL] {
        fake.mode.store(mode, SeqCst);
        assert!(speaker.withdraw_blackhole(&v6).await.is_err());
    }
    fake.mode.store(0, SeqCst);
    assert_eq!(speaker.list_blackholes().await.unwrap().routes.len(), 4);
    assert!(
        speaker
            .withdraw_blackhole(&"2001:db8::/64".parse().unwrap())
            .await
            .is_err()
    );
    assert_eq!(speaker.list_blackholes().await.unwrap().routes.len(), 4);
    server.abort();
}
