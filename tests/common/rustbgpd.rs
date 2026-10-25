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

/// Host route the unicast peered fixture's export policy denies, as an
/// RPKI-Invalid export filter would deny a blackhole.
pub const EXPORT_DENIED: &str = "203.0.113.99/32";
/// A configured neighbor with no listener behind it.
pub const UNREACHABLE_PEER: &str = "192.0.2.250";
/// Missing interface in the dedicated v0.80 observation fixture's own namespace.
pub const UNBOUND_INTERFACE: &str = "pd-unbound";

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
        Self::start_configured(transport, None, None, false, false).await
    }

    pub async fn start_peered(network: &str, peer: &str, peer_asn: u32) -> Self {
        Self::start_configured(
            "bearer",
            Some((peer, peer_asn)),
            Some(network),
            false,
            false,
        )
        .await
    }

    /// The peer also negotiates IPv4/IPv6 unicast. Export policy denies
    /// [`EXPORT_DENIED`], and [`UNREACHABLE_PEER`] is configured but never
    /// Established.
    pub async fn start_peered_unicast(network: &str, peer: &str, peer_asn: u32) -> Self {
        Self::start_configured("bearer", Some((peer, peer_asn)), Some(network), true, false).await
    }

    /// Missing-interface discovery, with no real BGP peer.
    /// Only this mode needs a raw-capable user; it has its own network namespace
    /// and disables Router Advertisement/Solicitation sending.
    pub async fn start_observation_neighbors() -> Self {
        Self::start_configured("bearer", None, Some("bridge"), false, true).await
    }

    async fn start_configured(
        transport: &str,
        peer: Option<(&str, u32)>,
        network: Option<&str>,
        unicast: bool,
        observation_neighbors: bool,
    ) -> Self {
        let bridged = network.is_some();
        let version = std::env::var("PREFIXD_RUSTBGPD_TEST_VERSION").unwrap_or("0.80.0".into());
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
{export_statements}
[policy]
import_chain = ["lab-import"]
export_chain = ["lab-export"]
[[neighbors]]
address = "{address}"
remote_asn = {asn}
description = "owned GoBGP peer"
families = [{families}]
hold_time = 9
{unicast_neighbors}
"#,
                    families = if unicast {
                        r#""ipv4_flowspec", "ipv6_flowspec", "ipv4_unicast", "ipv6_unicast""#
                    } else {
                        r#""ipv4_flowspec", "ipv6_flowspec""#
                    },
                    export_statements = if unicast {
                        format!(
                            "[[policy.definitions.lab-export.statements]]\nprefix = \"{EXPORT_DENIED}\"\naction = \"deny\""
                        )
                    } else {
                        String::new()
                    },
                    // IPv6 unicast over IPv4 eBGP is exported only with an IPv6 next hop.
                    unicast_neighbors = if unicast {
                        format!(
                            "local_ipv6_nexthop = \"2001:db8:0:1::1\"\n[[neighbors]]\naddress = \"{UNREACHABLE_PEER}\"\nremote_asn = 64999\ndescription = \"configured, never Established\"\nfamilies = [\"ipv4_unicast\"]\nhold_time = 9"
                        )
                    } else {
                        String::new()
                    },
                )
            })
            .unwrap_or_default();
        let observation_config = if observation_neighbors {
            let unbound = UNBOUND_INTERFACE;
            format!(
                r#"
[global.unnumbered]
router_advertisements = false
[flowspec]
validation = "off"
[policy.definitions.observation]
default_action = "permit"
[policy]
import_chain = ["observation"]
export_chain = ["observation"]
[[neighbors]]
interface = "{unbound}"
remote_asn = "external"
families = ["ipv4_flowspec", "ipv6_flowspec"]
"#
            )
        } else {
            String::new()
        };
        std::fs::write(
            files.path().join("config.toml"),
            format!(
                r#"config_epoch = 2
[global]
asn = 64512
router_id = "192.0.2.1"
{bgp_listen_addresses}
listen_port = {}
runtime_state_dir = "{runtime_state_dir}"
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
{observation_config}
"#,
                if bridged { 179 } else { ports[0] },
                ports[1],
                transport == "uds",
                ports[2],
                auth,
                // Discovery runs as root only in this isolated mode. Let it
                // create an owned state directory inside its container.
                runtime_state_dir = if observation_neighbors {
                    "/tmp/prefixd-observation-runtime"
                } else {
                    "/fixture/runtime"
                },
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
                if observation_neighbors {
                    host.cap_add = Some(vec!["NET_RAW".into()]);
                }
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
            .with_user(if observation_neighbors {
                "0:0".into()
            } else {
                format!("{}:{}", metadata.uid(), metadata.gid())
            })
            .with_mount(
                Mount::bind_mount(files.path().to_str().unwrap(), "/fixture")
                    .with_access_mode(AccessMode::ReadWrite),
            )
            .with_cmd(["rustbgpd", "/fixture/config.toml"]);
        let container = image
            .start()
            .await
            .expect("start pinned rustbgpd container");
        let check = container
            .exec(ExecCommand::new([
                "rustbgpd",
                "--check",
                "--strict",
                "/fixture/config.toml",
            ]))
            .await;
        let mut check = match check {
            Ok(check) => check,
            Err(error) => {
                Self::print_startup_logs(&container).await;
                panic!("owned daemon config-check could not start: {error}");
            }
        };
        let output = check.stdout_to_vec().await.unwrap();
        let errors = check.stderr_to_vec().await.unwrap();
        let status = check.exit_code().await;
        if !matches!(status, Ok(Some(0))) {
            Self::print_startup_logs(&container).await;
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

    async fn print_startup_logs(container: &ContainerAsync<GenericImage>) {
        eprintln!(
            "daemon startup stdout: {}\ndaemon startup stderr: {}",
            String::from_utf8_lossy(&container.stdout_to_vec().await.unwrap_or_default()),
            String::from_utf8_lossy(&container.stderr_to_vec().await.unwrap_or_default())
        );
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

    async fn raw_injection(
        &self,
    ) -> pb::injection_service_client::InjectionServiceClient<tonic::transport::Channel> {
        let channel = tonic::transport::Endpoint::from_shared(self.endpoint.clone())
            .unwrap()
            .connect_timeout(Duration::from_secs(1))
            .timeout(Duration::from_secs(2))
            .connect()
            .await
            .unwrap();
        pb::injection_service_client::InjectionServiceClient::new(channel)
    }

    fn authorized<T>(value: T) -> tonic::Request<T> {
        let mut request = tonic::Request::new(value);
        let token = std::env::var("PREFIXD_RUSTBGPD_TEST_TOKEN").unwrap();
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        request
    }

    /// Inject a local unicast path as another tool would, bypassing the adapter.
    pub async fn add_raw_path(&self, path: pb::AddPathRequest) {
        self.raw_injection()
            .await
            .add_path(Self::authorized(path))
            .await
            .unwrap();
    }

    /// Inject a leased path under another controller's owner, bypassing the adapter.
    pub async fn add_raw_leased_path(
        &self,
        path: pb::AddPathRequest,
        owner: &str,
        lease_seconds: u32,
    ) {
        self.raw_injection()
            .await
            .add_leased_path(Self::authorized(pb::AddLeasedPathRequest {
                path: Some(path),
                lease: Some(pb::InjectionLease {
                    owner: owner.into(),
                    lease_seconds,
                }),
            }))
            .await
            .unwrap();
    }

    /// Raw retained local unicast rows for both families, lease fields included.
    pub async fn raw_local_routes(&self) -> Vec<pb::Route> {
        let channel = tonic::transport::Endpoint::from_shared(self.endpoint.clone())
            .unwrap()
            .connect_timeout(Duration::from_secs(1))
            .timeout(Duration::from_secs(2))
            .connect()
            .await
            .unwrap();
        let mut routes = Vec::new();
        for family in [
            pb::AddressFamily::Ipv4Unicast as i32,
            pb::AddressFamily::Ipv6Unicast as i32,
        ] {
            routes.extend(
                pb::rib_service_client::RibServiceClient::new(channel.clone())
                    .list_received_routes(Self::authorized(pb::ListRoutesRequest {
                        neighbor_address: "0.0.0.0".into(),
                        afi_safi: family,
                        page_size: 1000,
                        ..Default::default()
                    }))
                    .await
                    .unwrap()
                    .into_inner()
                    .routes,
            );
        }
        routes
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
