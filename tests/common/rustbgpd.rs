#![allow(
    dead_code,
    reason = "owned fixture helpers are reused by independent integration targets"
)]
use prefixd::{
    bgp::{RustBgpdAnnouncer, rustbgpd_pb as pb},
    config::RustBgpdConfig,
};
use std::{
    net::TcpListener,
    os::unix::fs::{MetadataExt, PermissionsExt},
    time::Duration,
};
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    bollard::models::PortBinding,
    core::{AccessMode, ExecCommand, IntoContainerPort, Mount},
    runners::AsyncRunner,
};

pub struct Speaker {
    pub container: ContainerAsync<GenericImage>,
    pub endpoint: String,
    pub bgp_port: u16,
    pub peer_address: String,
    pub config: RustBgpdConfig,
    version: String,
    // Keep the owner-only configuration/token mount alive until container removal.
    _files: tempfile::TempDir,
}

impl Speaker {
    pub async fn start() -> Self {
        Self::start_secure("bearer").await
    }

    pub async fn start_secure(transport: &str) -> Self {
        Self::start_configured(transport, None, None).await
    }

    pub async fn start_peered(network: &str, peer: &str, peer_asn: u32) -> Self {
        Self::start_configured("bearer", Some((peer, peer_asn)), Some(network)).await
    }

    async fn start_configured(
        transport: &str,
        peer: Option<(&str, u32)>,
        network: Option<&str>,
    ) -> Self {
        let bridged = network.is_some();
        let version = std::env::var("PREFIXD_RUSTBGPD_TEST_VERSION").unwrap_or("0.78.0".into());
        let releases: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/rustbgpd/releases.json")).unwrap();
        let release = &releases[&version];
        let image = release["image"].as_str().expect("unknown test release");
        let (name, tag) = image.split_once(':').unwrap();
        eprintln!(
            "rustbgpd fixture: image={image}, source={}, host={}",
            release["source_commit"],
            std::env::consts::ARCH
        );
        let files = tempfile::tempdir().unwrap();
        std::fs::set_permissions(files.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = files.path().metadata().unwrap();
        let sockets: Vec<_> = (0..3)
            .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let ports: Vec<_> = sockets
            .iter()
            .map(|s| s.local_addr().unwrap().port())
            .collect();
        let token =
            std::env::var("PREFIXD_RUSTBGPD_TEST_TOKEN").expect("run scripts/test-rustbgpd.sh");
        let token_path = files.path().join("token");
        std::fs::write(&token_path, token).unwrap();
        std::fs::set_permissions(token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let runtime = files.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut config = RustBgpdConfig {
            endpoint: format!("http://127.0.0.1:{}", ports[2]),
            bearer_token_env: "PREFIXD_RUSTBGPD_TEST_TOKEN".into(),
            ..Default::default()
        };
        let auth = match transport {
            "bearer" => "token_file = \"/fixture/token\"\nprincipal = \"prefixd-test\"".to_owned(),
            "uds" => {
                config.endpoint = format!("unix://{}", runtime.join("grpc.sock").display());
                config.bearer_token_env.clear();
                "token_file = \"/fixture/token\"\nprincipal = \"prefixd-test\"".to_owned()
            }
            "mtls" => {
                for name in [
                    "transport-ca.pem",
                    "transport-server-cert.pem",
                    "transport-server-key.pem",
                    "transport-client-cert.pem",
                    "transport-client-key.pem",
                ] {
                    std::fs::copy(
                        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                            .join("src/bgp/testdata")
                            .join(name),
                        files.path().join(name),
                    )
                    .unwrap();
                    std::fs::set_permissions(
                        files.path().join(name),
                        std::fs::Permissions::from_mode(0o600),
                    )
                    .unwrap();
                }
                config.endpoint = format!("https://127.0.0.1:{}", ports[2]);
                config.bearer_token_env.clear();
                config.ca_cert_path = Some(
                    files
                        .path()
                        .join("transport-ca.pem")
                        .to_str()
                        .unwrap()
                        .into(),
                );
                config.client_cert_path = Some(
                    files
                        .path()
                        .join("transport-client-cert.pem")
                        .to_str()
                        .unwrap()
                        .into(),
                );
                config.client_key_path = Some(
                    files
                        .path()
                        .join("transport-client-key.pem")
                        .to_str()
                        .unwrap()
                        .into(),
                );
                "tls_cert_file = \"/fixture/transport-server-cert.pem\"\ntls_key_file = \"/fixture/transport-server-key.pem\"\ntls_client_ca_file = \"/fixture/transport-ca.pem\"".to_owned()
            }
            _ => panic!("unknown secure fixture transport"),
        };
        let peering = peer
            .map(|(address, asn)| {
                format!(
                    r#"
[flowspec]
validation = "off"
[policy.definitions.lab-import]
default_action = "permit"
[[policy.definitions.lab-import.statements]]
prefix = "0.0.0.0/0"
ge = 0
le = 32
action = "permit"
set_local_pref = 200
[[policy.definitions.lab-import.statements]]
prefix = "::/0"
ge = 0
le = 128
action = "permit"
set_local_pref = 200
[policy.definitions.lab-export]
default_action = "permit"
[policy]
import_chain = ["lab-import"]
export_chain = ["lab-export"]
[[neighbors]]
address = "{address}"
remote_asn = {asn}
description = "owned GoBGP peer"
families = ["ipv4_flowspec", "ipv6_flowspec"]
hold_time = 9
"#
                )
            })
            .unwrap_or_default();
        std::fs::write(
            files.path().join("config.toml"),
            format!(
                r#"config_epoch = 2
[global]
asn = 64512
router_id = "192.0.2.1"
{bgp_listen_addresses}
listen_port = {}
runtime_state_dir = "/fixture/runtime"
worker_threads = 2
ebgp_requires_policy = true
[global.telemetry]
prometheus_addr = "127.0.0.1:{}"
log_format = "text"
[global.telemetry.grpc_uds]
enabled = {}
mode = 0o600
access_mode = "read_write"
[global.telemetry.grpc_tcp]
address = "{listen_address}:{}"
access_mode = "read_write"
{}
[security.grpc.roles]
prefixd-test = "operator"
"rustbgpd:prefixd-test" = "operator"
{peering}
"#,
                if bridged { 179 } else { ports[0] },
                ports[1],
                transport == "uds",
                ports[2],
                auth,
                bgp_listen_addresses = if bridged {
                    ""
                } else {
                    "listen_addresses = [\"127.0.0.1\"]"
                },
                listen_address = if network.is_some() {
                    "0.0.0.0"
                } else {
                    "127.0.0.1"
                },
            ),
        )
        .unwrap();
        drop(sockets);
        let rpc_container_port = ports[2];
        let image = GenericImage::new(name, tag);
        let image = if bridged {
            image.with_exposed_port(ports[2].tcp())
        } else {
            image
        };
        let image = image
            .with_host_config_modifier(move |host| {
                host.cpuset_cpus = std::env::var("PREFIXD_TEST_CPUSET").ok();
                if bridged {
                    host.publish_all_ports = Some(false);
                    host.port_bindings = Some(
                        [(
                            format!("{rpc_container_port}/tcp"),
                            Some(vec![PortBinding {
                                host_ip: Some("127.0.0.1".into()),
                                host_port: Some(rpc_container_port.to_string()),
                            }]),
                        )]
                        .into_iter()
                        .collect(),
                    );
                }
            })
            .with_network(network.unwrap_or("host"))
            .with_user(format!("{}:{}", metadata.uid(), metadata.gid()))
            .with_mount(
                Mount::bind_mount(files.path().to_str().unwrap(), "/fixture")
                    .with_access_mode(AccessMode::ReadWrite),
            )
            .with_cmd(["rustbgpd", "/fixture/config.toml"]);
        let container = image
            .start()
            .await
            .expect("start pinned rustbgpd container");
        let mut check = container
            .exec(ExecCommand::new([
                "rustbgpd",
                "--check",
                "--strict",
                "/fixture/config.toml",
            ]))
            .await
            .unwrap();
        let output = check.stdout_to_vec().await.unwrap();
        let errors = check.stderr_to_vec().await.unwrap();
        let status = check.exit_code().await;
        if !matches!(status, Ok(Some(0))) {
            eprintln!(
                "daemon startup stdout: {}\ndaemon startup stderr: {}",
                String::from_utf8_lossy(&container.stdout_to_vec().await.unwrap_or_default()),
                String::from_utf8_lossy(&container.stderr_to_vec().await.unwrap_or_default())
            );
        }
        let status =
            status.expect("owned daemon config-check exit status (startup logs printed above)");
        assert_eq!(
            status,
            Some(0),
            "{}{}",
            String::from_utf8_lossy(&output),
            String::from_utf8_lossy(&errors)
        );
        if network.is_some() {
            config.endpoint = format!(
                "http://127.0.0.1:{}",
                container.get_host_port_ipv4(ports[2].tcp()).await.unwrap()
            );
        }
        let fixture = Self {
            container,
            endpoint: config.endpoint.clone(),
            bgp_port: if network.is_some() { 179 } else { ports[0] },
            peer_address: peer.map_or("127.0.0.1", |(address, _)| address).into(),
            config,
            version,
            _files: files,
        };
        fixture.ready().await;
        fixture
    }

    pub async fn ready(&self) {
        if !self.endpoint.starts_with("http://") {
            use prefixd::bgp::PeerObserver;
            tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    if let Ok(client) = RustBgpdAnnouncer::connect(&self.config).await
                        && client.session_status().await.is_ok()
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .expect("bounded secure controller readiness");
            return;
        }
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let endpoint = tonic::transport::Endpoint::from_shared(self.endpoint.clone())
                    .unwrap()
                    .connect_timeout(Duration::from_millis(250))
                    .timeout(Duration::from_secs(1));
                if let Ok(channel) = endpoint.connect().await {
                    let mut client = pb::control_service_client::ControlServiceClient::new(channel);
                    let mut request = tonic::Request::new(pb::HealthRequest {});
                    let token = std::env::var("PREFIXD_RUSTBGPD_TEST_TOKEN").unwrap();
                    request
                        .metadata_mut()
                        .insert("authorization", format!("Bearer {token}").parse().unwrap());
                    if let Ok(response) = client.get_health(request).await {
                        let health = response.into_inner();
                        assert_eq!(health.daemon_version, self.version);
                        if health.healthy {
                            break;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("bounded authenticated daemon readiness");
    }

    /// Raw retained candidate view for the isolated bearer-authenticated peer fixture.
    pub async fn received_flow_spec(&self, family: i32, peer: &str) -> pb::ListFlowSpecResponse {
        tokio::time::timeout(Duration::from_secs(3), async {
            let channel = tonic::transport::Endpoint::from_shared(self.endpoint.clone())
                .unwrap()
                .connect_timeout(Duration::from_secs(1))
                .timeout(Duration::from_secs(2))
                .connect()
                .await
                .unwrap();
            let mut request = tonic::Request::new(pb::ListFlowSpecRequest {
                afi_safi: family,
                received_peer_address: peer.into(),
                advertised_peer_address: String::new(),
            });
            request.set_timeout(Duration::from_secs(2));
            let token = std::env::var("PREFIXD_RUSTBGPD_TEST_TOKEN").unwrap();
            request
                .metadata_mut()
                .insert("authorization", format!("Bearer {token}").parse().unwrap());
            pb::rib_service_client::RibServiceClient::new(channel)
                .list_flow_spec_routes(request)
                .await
                .unwrap()
                .into_inner()
        })
        .await
        .expect("bounded raw received FlowSpec view")
    }

    pub async fn assert_partial_tls_rejected(&self) {
        let path = self._files.path().join("config.toml");
        let original = std::fs::read_to_string(&path).unwrap();
        let partial = original
            .lines()
            .filter(|line| !line.starts_with("tls_client_ca_file"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&path, partial).unwrap();
        let result = self
            .container
            .exec(ExecCommand::new([
                "rustbgpd",
                "--check",
                "--strict",
                "/fixture/config.toml",
            ]))
            .await;
        let mut result = result.unwrap();
        let _ = result.stdout_to_vec().await.unwrap();
        let status = result.exit_code().await.unwrap();
        std::fs::write(&path, original).unwrap();
        assert_ne!(status, Some(0));
    }

    pub async fn connect(&self) -> RustBgpdAnnouncer {
        RustBgpdAnnouncer::connect(&self.config).await.unwrap()
    }
}
