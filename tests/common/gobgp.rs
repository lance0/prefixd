#![allow(
    dead_code,
    reason = "owned fixture helpers are reused by independent integration targets"
)]
//! Owned Linux fixtures. Never connect these tests to an operator's speaker.
use prefixd::bgp::{
    GoBgpAnnouncer,
    apipb::{self as pb, go_bgp_service_client::GoBgpServiceClient},
};
use std::{net::TcpListener, time::Duration};
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    bollard::models::PortBinding,
    core::{ExecCommand, IntoContainerPort, logs::LogFrame},
    runners::AsyncRunner,
};
use tonic::transport::{Channel, Endpoint};

const IMAGE_TAG: &str =
    "latest@sha256:42b8d0017237e388c55936efe1f23632365b24a31751f6e8815f93e12c4d18c2";

pub struct Speaker {
    pub container: ContainerAsync<GenericImage>,
    pub endpoint: String,
    pub bgp_port: u16,
    router_id: String,
    pub peer_address: String,
    listen_address: String,
}

impl Speaker {
    pub async fn start() -> Self {
        Self::with_router_id("192.0.2.10").await
    }

    pub async fn with_router_id(router_id: &str) -> Self {
        Self::start_configured(router_id, None).await
    }

    pub async fn on_network(network: &str) -> Self {
        Self::start_configured("192.0.2.20", Some(network)).await
    }

    async fn start_configured(router_id: &str, network: Option<&str>) -> Self {
        let sockets: Vec<_> = (0..2)
            .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let ports: Vec<_> = sockets
            .iter()
            .map(|socket| socket.local_addr().unwrap().port())
            .collect();
        let api_hosts = if network.is_some() {
            "--api-hosts=0.0.0.0:50051".into()
        } else {
            format!("--api-hosts=127.0.0.1:{}", ports[0])
        };
        drop(sockets);
        let bridged = network.is_some();
        let image = GenericImage::new("jauderho/gobgp", IMAGE_TAG);
        let image = if bridged {
            image.with_exposed_port(50051.tcp())
        } else {
            image
        };
        let image = image
            .with_network(network.unwrap_or("host"))
            .with_host_config_modifier(move |host| {
                host.cpuset_cpus = std::env::var("PREFIXD_TEST_CPUSET").ok();
                if bridged {
                    host.publish_all_ports = Some(false);
                    host.port_bindings = Some(
                        [(
                            "50051/tcp".into(),
                            Some(vec![PortBinding {
                                host_ip: Some("127.0.0.1".into()),
                                host_port: Some("0".into()),
                            }]),
                        )]
                        .into_iter()
                        .collect(),
                    );
                }
            })
            .with_log_consumer(|frame: &LogFrame| {
                eprint!("GoBGP fixture: {}", String::from_utf8_lossy(frame.bytes()));
            })
            .with_startup_timeout(Duration::from_secs(20))
            .with_cmd([
                "/usr/local/bin/gobgpd",
                "-p",
                "--pprof-disable",
                "--metrics-path=",
                "--cpus=2",
                &api_hosts,
            ]);
        let container = image.start().await.expect("start pinned GoBGP fixture");
        let api_port = if network.is_some() {
            container.get_host_port_ipv4(50051.tcp()).await.unwrap()
        } else {
            ports[0]
        };
        let fixture = Self {
            container,
            endpoint: format!("http://127.0.0.1:{api_port}"),
            bgp_port: if network.is_some() { 179 } else { ports[1] },
            peer_address: "127.0.0.1".into(),
            listen_address: if network.is_some() {
                "0.0.0.0"
            } else {
                "127.0.0.1"
            }
            .into(),
            router_id: router_id.into(),
        };
        let mut version = fixture
            .container
            .exec(ExecCommand::new(["/usr/local/bin/gobgpd", "--version"]))
            .await
            .unwrap();
        let output = version.stdout_to_vec().await.unwrap();
        assert_eq!(version.exit_code().await.unwrap(), Some(0));
        let version = String::from_utf8_lossy(&output);
        assert!(
            version.contains("version 4.10.0"),
            "unexpected pinned binary: {version}"
        );
        eprintln!("GoBGP fixture: image=jauderho/gobgp:{IMAGE_TAG}, {version}");
        fixture.configure().await;
        fixture
    }

    pub async fn client(&self) -> GoBgpServiceClient<Channel> {
        let endpoint = Endpoint::from_shared(self.endpoint.clone())
            .unwrap()
            .connect_timeout(Duration::from_millis(250))
            .timeout(Duration::from_secs(2));
        GoBgpServiceClient::new(endpoint.connect().await.expect("owned GoBGP endpoint"))
    }

    pub async fn configure(&self) {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let endpoint = Endpoint::from_shared(self.endpoint.clone())
                    .unwrap()
                    .connect_timeout(Duration::from_millis(250))
                    .timeout(Duration::from_secs(1));
                if let Ok(channel) = endpoint.connect().await {
                    let mut client = GoBgpServiceClient::new(channel);
                    if let Ok(response) = client.get_bgp(pb::GetBgpRequest {}).await {
                        let global = response.into_inner().global.expect("GoBGP global state");
                        if global.asn != 0 {
                            assert_eq!(global.asn, 65010, "unexpected existing fixture ASN");
                            assert_eq!(
                                global.router_id, self.router_id,
                                "unexpected existing fixture router ID"
                            );
                            assert_eq!(
                                global.listen_port,
                                i32::from(self.bgp_port),
                                "unexpected existing fixture BGP port"
                            );
                            assert_eq!(
                                global.listen_addresses.as_slice(),
                                std::slice::from_ref(&self.listen_address),
                                "unexpected existing fixture listen addresses"
                            );
                            return;
                        }
                        // GoBGP defines ASN zero as not started; a lost StartBgp reply is read back next poll.
                        let request = pb::StartBgpRequest {
                            global: Some(pb::Global {
                                asn: 65010,
                                router_id: self.router_id.clone(),
                                listen_port: self.bgp_port.into(),
                                listen_addresses: vec![self.listen_address.clone()],
                                ..Default::default()
                            }),
                        };
                        let _ = client.start_bgp(request).await;
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("bounded GoBGP StartBgp readiness");
    }

    pub async fn connect(&self) -> GoBgpAnnouncer {
        let mut announcer = GoBgpAnnouncer::new(self.endpoint.clone());
        announcer
            .connect()
            .await
            .expect("connect owned GoBGP fixture");
        announcer
    }

    pub async fn paths(&self, afi: i32, table: pb::TableType) -> Vec<pb::Path> {
        tokio::time::timeout(Duration::from_secs(3), async {
            let mut stream = self
                .client()
                .await
                .list_path(pb::ListPathRequest {
                    table_type: table as i32,
                    name: if table == pb::TableType::AdjIn {
                        self.peer_address.clone()
                    } else {
                        String::new()
                    },
                    family: Some(pb::Family { afi, safi: 133 }),
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner();
            let mut paths = Vec::new();
            while let Some(response) = stream.message().await.unwrap() {
                paths.extend(response.destination.expect("GoBGP destination").paths);
            }
            paths
        })
        .await
        .expect("bounded complete raw GoBGP inventory")
    }

    pub async fn peer_uptime(&self) -> (i64, i32) {
        tokio::time::timeout(Duration::from_secs(3), async {
            let mut stream = self
                .client()
                .await
                .list_peer(pb::ListPeerRequest {
                    address: self.peer_address.clone(),
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner();
            let peer = stream.message().await.unwrap().unwrap().peer.unwrap();
            assert!(stream.message().await.unwrap().is_none());
            let uptime = peer.timers.unwrap().state.unwrap().uptime.unwrap();
            (uptime.seconds, uptime.nanos)
        })
        .await
        .expect("bounded actual peer uptime")
    }

    pub async fn add_peer(&self, remote_port: u16, passive: bool) {
        self.add_peer_with_asn(remote_port, passive, 65010).await;
    }

    pub async fn add_peer_with_asn(&self, remote_port: u16, passive: bool, peer_asn: u32) {
        self.add_peer_with_safis(remote_port, passive, peer_asn, &[133])
            .await;
    }

    /// Both address families for each SAFI, for example 1 (unicast) and 133 (FlowSpec).
    pub async fn add_peer_with_safis(
        &self,
        remote_port: u16,
        passive: bool,
        peer_asn: u32,
        safis: &[i32],
    ) {
        self.client()
            .await
            .add_peer(pb::AddPeerRequest {
                peer: Some(pb::Peer {
                    conf: Some(pb::PeerConf {
                        neighbor_address: self.peer_address.clone(),
                        peer_asn,
                        ..Default::default()
                    }),
                    transport: Some(pb::Transport {
                        local_address: self.listen_address.clone(),
                        remote_port: remote_port.into(),
                        passive_mode: passive,
                        ..Default::default()
                    }),
                    timers: Some(pb::Timers {
                        config: Some(pb::TimersConfig {
                            connect_retry: 1,
                            hold_time: 9,
                            keepalive_interval: 3,
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    afi_safis: safis
                        .iter()
                        .flat_map(|&safi| [1, 2].map(|afi| pb::Family { afi, safi }))
                        .map(|family| pb::AfiSafi {
                            config: Some(pb::AfiSafiConfig {
                                family: Some(family),
                                enabled: true,
                            }),
                            ..Default::default()
                        })
                        .collect(),
                    ..Default::default()
                }),
            })
            .await
            .expect("configure isolated FlowSpec peer");
    }
}
