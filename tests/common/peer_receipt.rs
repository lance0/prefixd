//! Independent raw FlowSpec receipt oracles shared by owned peer fixtures.
use super::{contract, gobgp, rustbgpd};
use prefixd::{
    bgp::{apipb as go, rustbgpd_pb as rust},
    domain::{FlowSpecAction, FlowSpecNlri, FlowSpecRule},
};
use std::time::Duration;

fn rate_action(rate: f32) -> FlowSpecAction {
    let bits = f64::from(rate) * 8.0;
    assert!(
        bits.is_finite()
            && bits >= 0.0
            && bits.fract() == 0.0
            && bits < 18_446_744_073_709_551_616.0
    );
    if bits == 0.0 {
        FlowSpecAction::discard()
    } else {
        FlowSpecAction::police(bits as u64)
    }
}

// Independent raw oracles: do not reuse the adapter's local-reader decoder.
fn go_received(path: &go::Path, afi: i32, peer: &str) -> FlowSpecRule {
    assert_eq!(path.family, Some(go::Family { afi, safi: 133 }));
    assert_eq!(path.neighbor_ip, peer);
    let Some(go::nlri::Nlri::FlowSpec(nlri)) = &path.nlri.as_ref().unwrap().nlri else {
        panic!("missing received FlowSpec NLRI")
    };
    let mut result = FlowSpecNlri {
        dst_prefix: String::new(),
        protocol: None,
        dst_ports: vec![],
        ..Default::default()
    };
    let mut previous = 0;
    for rule in &nlri.rules {
        let kind = match rule.rule.as_ref().unwrap() {
            go::flow_spec_rule::Rule::IpPrefix(prefix) => {
                assert_eq!(prefix.r#type, 1);
                assert_eq!(prefix.offset, 0);
                let net: ipnet::IpNet = format!("{}/{}", prefix.prefix, prefix.prefix_len)
                    .parse()
                    .unwrap();
                assert_eq!(net, net.trunc());
                assert_eq!(net.addr().is_ipv4(), afi == 1);
                result.dst_prefix = net.to_string();
                1
            }
            go::flow_spec_rule::Rule::Component(component) => {
                assert!(matches!(component.r#type, 3 | 5));
                assert!(!component.items.is_empty());
                let mut values = vec![];
                for (index, item) in component.items.iter().enumerate() {
                    assert_eq!(
                        item.op & !0x30,
                        if index + 1 == component.items.len() {
                            0x81
                        } else {
                            0x01
                        }
                    );
                    values.push(item.value);
                }
                if component.r#type == 3 {
                    assert_eq!(values.len(), 1);
                    result.protocol = Some(u8::try_from(values[0]).unwrap());
                } else {
                    result.dst_ports = values
                        .into_iter()
                        .map(|value| u16::try_from(value).unwrap())
                        .collect();
                }
                component.r#type
            }
            go::flow_spec_rule::Rule::Mac(_) => panic!("unexpected MAC FlowSpec match"),
        };
        assert!(kind > previous);
        previous = kind;
    }
    assert!(!result.dst_prefix.is_empty());
    let mut actions = vec![];
    for attribute in &path.pattrs {
        if let Some(go::attribute::Attr::ExtendedCommunities(communities)) = &attribute.attr {
            for community in &communities.communities {
                let Some(go::extended_community::Extcom::TrafficRate(rate)) = &community.extcom
                else {
                    panic!("unexpected received action")
                };
                assert_eq!(rate.asn, 0);
                actions.push(rate_action(rate.rate));
            }
        }
    }
    assert_eq!(actions.len(), 1);
    FlowSpecRule {
        nlri: result,
        actions,
        owner: String::new(),
    }
}

fn equalities(value: &str) -> Vec<u16> {
    value
        .split(',')
        .map(|item| {
            let item = item.trim();
            item.strip_prefix("==")
                .or_else(|| item.strip_prefix('='))
                .expect("equality-only numeric match")
                .parse()
                .unwrap()
        })
        .collect()
}

fn rust_received(route: &rust::FlowSpecRouteEntry, family: i32, peer: &str) -> FlowSpecRule {
    assert_eq!(route.afi_safi, family);
    assert_eq!(route.peer_address, peer);
    assert_eq!(
        route.as_path,
        if peer == "0.0.0.0" {
            vec![]
        } else {
            vec![65010]
        }
    );
    assert!(route.communities.is_empty());
    let mut nlri = FlowSpecNlri {
        dst_prefix: String::new(),
        protocol: None,
        dst_ports: vec![],
        ..Default::default()
    };
    let mut previous = 0;
    for component in &route.components {
        assert!(component.r#type > previous);
        previous = component.r#type;
        assert_eq!(component.offset, 0);
        match component.r#type {
            1 => {
                assert!(component.value.is_empty());
                let net: ipnet::IpNet = component.prefix.parse().unwrap();
                assert_eq!(net, net.trunc());
                assert_eq!(net.addr().is_ipv4(), family == 3);
                nlri.dst_prefix = net.to_string();
            }
            3 => {
                assert!(component.prefix.is_empty());
                let values = equalities(&component.value);
                assert_eq!(values.len(), 1);
                nlri.protocol = Some(u8::try_from(values[0]).unwrap());
            }
            5 => {
                assert!(component.prefix.is_empty());
                nlri.dst_ports = equalities(&component.value);
            }
            _ => panic!("unexpected received match component"),
        }
    }
    assert!(!nlri.dst_prefix.is_empty());
    assert_eq!(route.actions.len(), 1);
    let Some(rust::flow_spec_action::Action::TrafficRate(rate)) = &route.actions[0].action else {
        panic!("expected exactly one rate action")
    };
    assert_eq!(
        route.extended_communities,
        vec![(0x8006_u64 << 48) | u64::from(rate.rate.to_bits())]
    );
    FlowSpecRule::new(nlri, rate_action(rate.rate))
}

pub(crate) async fn wait_go_received(fixture: &gobgp::Speaker, expected: &[FlowSpecRule]) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut actual = vec![];
            for afi in [1, 2] {
                actual.extend(
                    fixture
                        .paths(afi, go::TableType::AdjIn)
                        .await
                        .iter()
                        .map(|path| go_received(path, afi, &fixture.peer_address)),
                );
            }
            if contract::exact_inventory(&actual, expected).is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("exact dual-family GoBGP received routes");
}

pub(crate) async fn wait_rust_views(
    fixture: &rustbgpd::Speaker,
    local: &[FlowSpecRule],
    remote: &[FlowSpecRule],
) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut local_rules = vec![];
            let mut remote_rules = vec![];
            let mut selection = true;
            for family in [3, 4] {
                for peer in ["0.0.0.0", fixture.peer_address.as_str()] {
                    let view = fixture.received_flow_spec(family, peer).await;
                    assert!(view.received_view && !view.advertised_view && view.routes.is_empty());
                    for row in view.received_routes {
                        assert_eq!(row.path_id, 0);
                        assert_eq!(row.validation, 1);
                        assert!(!row.pending);
                        assert!(row.reason.is_empty());
                        let rule = rust_received(
                            row.route.as_ref().expect("received route payload"),
                            family,
                            peer,
                        );
                        if peer == "0.0.0.0" {
                            selection &= row.selected
                                != remote
                                    .iter()
                                    .any(|other| other.nlri_hash() == rule.nlri_hash());
                            local_rules.push(rule);
                        } else {
                            selection &= row.selected;
                            remote_rules.push(rule);
                        }
                    }
                }
            }
            if selection
                && contract::exact_inventory(&local_rules, local).is_ok()
                && contract::exact_inventory(&remote_rules, remote).is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("exact Rust local/received views and selected/nonselected provenance");
}

/// Two BGP namespaces on a unique owned bridge; only RPC reaches host loopback.
pub(crate) struct Pair {
    pub rust: rustbgpd::Speaker,
    pub go: gobgp::Speaker,
    pub network: String,
}

impl Pair {
    pub async fn start() -> Self {
        Self::start_with(false).await
    }

    /// Both speakers also negotiate IPv4/IPv6 unicast; see
    /// [`rustbgpd::Speaker::start_peered_unicast`].
    pub async fn start_unicast() -> Self {
        Self::start_with(true).await
    }

    async fn start_with(unicast: bool) -> Self {
        assert_ne!(
            std::env::var("TESTCONTAINERS_COMMAND").as_deref(),
            Ok("keep"),
            "peer qualification requires owned cleanup"
        );
        let network = format!("prefixd-peer-{}", uuid::Uuid::new_v4());
        eprintln!("owned peer network: {network}");
        let mut go = gobgp::Speaker::on_network(&network).await;
        let go_ip = go.container.get_bridge_ip_address().await.unwrap();
        let rust = if unicast {
            rustbgpd::Speaker::start_peered_unicast(&network, &go_ip.to_string(), 65010).await
        } else {
            rustbgpd::Speaker::start_peered(&network, &go_ip.to_string(), 65010).await
        };
        let rust_ip = rust.container.get_bridge_ip_address().await.unwrap();
        assert_ne!(rust_ip, go_ip);
        go.peer_address = rust_ip.to_string();
        go.add_peer_with_safis(179, false, 64512, if unicast { &[1, 133] } else { &[133] })
            .await;
        let pair = Self { rust, go, network };
        pair.assert_isolated().await;
        pair
    }

    pub async fn assert_isolated(&self) {
        for container in [&self.rust.container, &self.go.container] {
            let output = tokio::process::Command::new("docker")
                .args(["inspect", container.id()])
                .output()
                .await
                .unwrap();
            assert!(output.status.success());
            let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            let host = &value[0]["HostConfig"];
            assert_eq!(host["NetworkMode"], self.network);
            assert_eq!(host["PublishAllPorts"], false);
            let mappings = host["PortBindings"].as_object().unwrap();
            assert_eq!(mappings.len(), 1);
            let expected_rpc = mappings.keys().next().unwrap();
            assert_ne!(expected_rpc, "179/tcp");
            let settings = &value[0]["NetworkSettings"];
            let networks = settings["Networks"].as_object().unwrap();
            assert_eq!(networks.len(), 1);
            let actual_ip = networks[&self.network]["IPAddress"].as_str().unwrap();
            let expected_ip = if container.id() == self.rust.container.id() {
                &self.go.peer_address
            } else {
                &self.rust.peer_address
            };
            assert_eq!(actual_ip, expected_ip);
            let actual_ports = settings["Ports"].as_object().unwrap();
            let published: Vec<_> = actual_ports
                .iter()
                .filter(|(_, bindings)| !bindings.is_null())
                .collect();
            assert_eq!(published.len(), 1);
            assert_eq!(published[0].0, expected_rpc);
            for bindings in [mappings.get(expected_rpc).unwrap(), published[0].1] {
                let bindings = bindings.as_array().unwrap();
                assert_eq!(bindings.len(), 1);
                assert_eq!(bindings[0]["HostIp"], "127.0.0.1");
            }
            assert!(
                published[0].1[0]["HostPort"]
                    .as_str()
                    .unwrap()
                    .parse::<u16>()
                    .unwrap()
                    > 0
            );
            eprintln!(
                "owned peer isolation: container={}, network={}, bindings={mappings:?}",
                container.id(),
                self.network
            );
        }
    }

    pub async fn remove(self) {
        let Self { rust, go, network } = self;
        rust.container.rm().await.unwrap();
        go.container.rm().await.unwrap();
        wait_removed("network", &network).await;
    }
}

/// Require the exact owned-resource absence response, never a daemon/CLI failure.
pub(crate) async fn wait_removed(kind: &str, id: &str) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let output = tokio::process::Command::new("docker")
                .args([kind, "inspect", id])
                .output()
                .await
                .unwrap();
            if !output.status.success() {
                let error = String::from_utf8(output.stderr).unwrap();
                let error = error.trim();
                let expected = if kind == "network" {
                    vec![
                        format!("Error: No such network: {id}"),
                        format!("Error response from daemon: network {id} not found"),
                    ]
                } else {
                    vec![
                        format!("Error: No such container: {id}"),
                        format!("Error response from daemon: No such container: {id}"),
                        format!("Error: No such object: {id}"),
                    ]
                };
                assert!(
                    expected.iter().any(|message| error == message),
                    "unexpected Docker inspection failure: {error}"
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("owned resource removed");
}
