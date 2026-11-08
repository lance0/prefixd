//! Independent raw FlowSpec receipt oracles shared by owned peer fixtures.
use super::{contract, gobgp, rustbgpd};
use prefixd::{
    bgp::{apipb as go, rustbgpd_pb as rust},
    domain::{FlowSpecAction, FlowSpecNlri, FlowSpecRule, VpnFlowSpecFamily, VpnFlowSpecIdentity},
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
    go_received_scoped(path, afi, 133, peer)
}

fn go_rd(rd: &go::RouteDistinguisher) -> String {
    match rd.rd.as_ref().expect("VPN RD payload") {
        go::route_distinguisher::Rd::TwoOctetAsn(value) => {
            assert!(u16::try_from(value.admin).is_ok());
            format!("{}:{}", value.admin, value.assigned)
        }
        go::route_distinguisher::Rd::IpAddress(value) => {
            let address: std::net::Ipv4Addr = value.admin.parse().unwrap();
            assert!(u16::try_from(value.assigned).is_ok());
            format!("{address}:{}", value.assigned)
        }
        go::route_distinguisher::Rd::FourOctetAsn(value) => {
            let assigned = u16::try_from(value.assigned).unwrap();
            if value.admin <= u32::from(u16::MAX) {
                format!("0x0002{:08x}{assigned:04x}", value.admin)
            } else {
                format!("{}:{assigned}", value.admin)
            }
        }
    }
}

fn go_received_match(path: &go::Path, afi: i32, safi: i32, peer: &str) -> FlowSpecNlri {
    assert_eq!(path.family, Some(go::Family { afi, safi }));
    assert_eq!(path.neighbor_ip, peer);
    let (rules, scope) = match &path.nlri.as_ref().expect("received NLRI").nlri {
        Some(go::nlri::Nlri::FlowSpec(nlri)) if safi == 133 => (&nlri.rules, None),
        Some(go::nlri::Nlri::VpnFlowSpec(nlri)) if safi == 134 => {
            assert!(matches!(afi, 1 | 2));
            let family = if afi == 1 {
                VpnFlowSpecFamily::Ipv4
            } else {
                VpnFlowSpecFamily::Ipv6
            };
            (
                &nlri.rules,
                Some(
                    VpnFlowSpecIdentity::new(family, &go_rd(nlri.rd.as_ref().expect("VPN RD")))
                        .unwrap(),
                ),
            )
        }
        _ => panic!("wrong received FlowSpec family or NLRI kind"),
    };
    let mut result = FlowSpecNlri {
        scope,
        dst_prefix: String::new(),
        protocol: None,
        dst_ports: vec![],
        ..Default::default()
    };
    let mut previous = 0;
    for rule in rules {
        let kind = match rule.rule.as_ref().unwrap() {
            go::flow_spec_rule::Rule::IpPrefix(prefix) => {
                assert!(matches!(prefix.r#type, 1 | 2));
                assert_eq!(prefix.offset, 0);
                let net: ipnet::IpNet = format!("{}/{}", prefix.prefix, prefix.prefix_len)
                    .parse()
                    .unwrap();
                assert_eq!(net, net.trunc());
                assert_eq!(net.addr().is_ipv4(), afi == 1);
                if prefix.r#type == 1 {
                    result.dst_prefix = net.to_string();
                } else {
                    result.src_prefix = Some(net.to_string());
                }
                prefix.r#type
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
    assert!(
        !result.dst_prefix.is_empty() || (result.scope.is_some() && result.src_prefix.is_some())
    );
    result
}

fn go_received_scoped(path: &go::Path, afi: i32, safi: i32, peer: &str) -> FlowSpecRule {
    let result = go_received_match(path, afi, safi, peer);
    let mut actions = vec![];
    let mut targets = vec![];
    for attribute in &path.pattrs {
        if let Some(go::attribute::Attr::ExtendedCommunities(communities)) = &attribute.attr {
            for community in &communities.communities {
                match community
                    .extcom
                    .as_ref()
                    .expect("received extended community")
                {
                    go::extended_community::Extcom::TrafficRate(rate) => {
                        assert_eq!(rate.asn, 0);
                        actions.push(rate_action(rate.rate));
                    }
                    go::extended_community::Extcom::TwoOctetAsSpecific(target) if safi == 134 => {
                        assert!(target.is_transitive);
                        assert_eq!(target.sub_type, 2);
                        assert!(u16::try_from(target.asn).is_ok());
                        targets.push(format!("{}:{}", target.asn, target.local_admin));
                    }
                    go::extended_community::Extcom::Ipv4AddressSpecific(target) if safi == 134 => {
                        assert!(target.is_transitive);
                        assert_eq!(target.sub_type, 2);
                        let address: std::net::Ipv4Addr = target.address.parse().unwrap();
                        assert!(u16::try_from(target.local_admin).is_ok());
                        targets.push(format!("{address}:{}", target.local_admin));
                    }
                    go::extended_community::Extcom::FourOctetAsSpecific(target) if safi == 134 => {
                        assert!(target.is_transitive);
                        assert_eq!(target.sub_type, 2);
                        assert!(u16::try_from(target.local_admin).is_ok());
                        targets.push(format!(
                            "{}.{}:{}",
                            target.asn >> 16,
                            target.asn & 0xffff,
                            target.local_admin
                        ));
                    }
                    _ => panic!("unexpected received action or scope RT"),
                }
            }
        }
    }
    assert_eq!(actions.len(), 1);
    assert_eq!(!targets.is_empty(), safi == 134);
    FlowSpecRule {
        nlri: result,
        actions,
        owner: String::new(),
        route_targets: targets,
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
            1 | 2 => {
                assert!(component.value.is_empty());
                let net: ipnet::IpNet = component.prefix.parse().unwrap();
                assert_eq!(net, net.trunc());
                assert_eq!(net.addr().is_ipv4(), family == 3);
                if component.r#type == 1 {
                    nlri.dst_prefix = net.to_string();
                } else {
                    nlri.src_prefix = Some(net.to_string());
                }
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

/// Full wire comparison ignores only the local controller owner, which is not a BGP attribute.
pub(crate) fn exact_wire_inventory(actual: &[FlowSpecRule], expected: &[FlowSpecRule]) -> bool {
    actual.len() == expected.len()
        && expected.iter().all(|wanted| {
            actual
                .iter()
                .filter(|found| {
                    serde_json::to_value(&found.nlri).unwrap()
                        == serde_json::to_value(&wanted.nlri).unwrap()
                        && serde_json::to_value(&found.actions).unwrap()
                            == serde_json::to_value(&wanted.actions).unwrap()
                        && found.route_targets == wanted.route_targets
                })
                .count()
                == 1
        })
}

pub(crate) async fn wait_go_scoped_received(fixture: &gobgp::Speaker, expected: &[FlowSpecRule]) {
    let mut raw_views = vec![];
    let result =
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let mut actual = vec![];
                raw_views.clear();
                for afi in [1, 2] {
                    for safi in [133, 134] {
                        let paths = fixture
                            .paths_with_safi(afi, safi, go::TableType::AdjIn)
                            .await;
                        actual.extend(paths.iter().map(|path| {
                            go_received_scoped(path, afi, safi, &fixture.peer_address)
                        }));
                        raw_views.push((afi, safi, paths));
                    }
                }
                if exact_wire_inventory(&actual, expected) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await;
    for (afi, safi, paths) in raw_views {
        eprintln!("raw peer receipt AFI={afi} SAFI={safi}: {paths:?}");
    }
    result.expect("exact global/VPN peer receipt with RD, RT, action and no global leakage");
}

/// Exact expected action and scope bytes, independent of prefixd's action model.
pub(crate) struct BinaryWireRule {
    pub nlri: FlowSpecNlri,
    pub extended_communities: Vec<u64>,
    pub ipv6_extended_communities: Vec<[u8; 20]>,
}

/// GoBGP 4.11 ListPath serializes each attribute including its BGP header.
/// Attribute 16 contains eight-octet communities; RFC 5701 attribute 25 uses twenty.
fn binary_communities(attributes: &[Vec<u8>]) -> Result<(Vec<u64>, Vec<[u8; 20]>), &'static str> {
    if attributes.is_empty() {
        return Err("peer omitted binary path attributes");
    }
    let mut seen = [false; 256];
    let mut ordinary = vec![];
    let mut ipv6 = vec![];
    for attribute in attributes {
        if attribute.len() < 3 {
            return Err("truncated path attribute header");
        }
        let flags = attribute[0];
        let kind = attribute[1];
        if flags & 0x0f != 0 {
            return Err("reserved path attribute flag bits");
        }
        if std::mem::replace(&mut seen[usize::from(kind)], true) {
            return Err("duplicate path attribute type");
        }
        let (header, length) = if flags & 0x10 == 0 {
            (3, usize::from(attribute[2]))
        } else {
            if attribute.len() < 4 {
                return Err("truncated extended path attribute length");
            }
            (
                4,
                usize::from(u16::from_be_bytes([attribute[2], attribute[3]])),
            )
        };
        if attribute.len() != header + length {
            return Err("path attribute length mismatch");
        }
        let value = &attribute[header..];
        match kind {
            16 => {
                if flags & 0xc0 != 0xc0 || value.is_empty() || value.len() % 8 != 0 {
                    return Err("invalid extended communities attribute");
                }
                for bytes in value.as_chunks::<8>().0 {
                    ordinary.push(u64::from_be_bytes(*bytes));
                }
            }
            25 => {
                if flags & 0xc0 != 0xc0 || value.is_empty() || value.len() % 20 != 0 {
                    return Err("invalid IPv6 extended communities attribute");
                }
                for bytes in value.as_chunks::<20>().0 {
                    ipv6.push(*bytes);
                }
            }
            _ => {}
        }
    }
    ordinary.sort_unstable();
    ipv6.sort_unstable();
    Ok((ordinary, ipv6))
}

pub(crate) fn exact_binary_inventory(
    actual: &[(i32, i32, go::Path)],
    expected: &[BinaryWireRule],
    peer: &str,
) -> Result<(), &'static str> {
    if actual.len() != expected.len() {
        return Err("peer route cardinality mismatch");
    }
    let mut matched = vec![false; expected.len()];
    for (afi, safi, path) in actual {
        let nlri = go_received_match(path, *afi, *safi, peer);
        let wanted: Vec<_> = expected
            .iter()
            .enumerate()
            .filter(|(_, wanted)| {
                serde_json::to_value(&nlri).unwrap() == serde_json::to_value(&wanted.nlri).unwrap()
            })
            .collect();
        if wanted.len() != 1 {
            return Err("peer NLRI, family or RD mismatch");
        }
        let (index, wanted) = wanted[0];
        if std::mem::replace(&mut matched[index], true) {
            return Err("duplicate peer NLRI");
        }
        let (ordinary, ipv6) = binary_communities(&path.pattrs_binary)?;
        let mut expected_ordinary = wanted.extended_communities.clone();
        let mut expected_ipv6 = wanted.ipv6_extended_communities.clone();
        expected_ordinary.sort_unstable();
        expected_ipv6.sort_unstable();
        if ordinary != expected_ordinary || ipv6 != expected_ipv6 {
            return Err("peer action or scope RT bytes mismatch");
        }
    }
    Ok(())
}

/// Every AFI/SAFI is read even when no rule is expected there, exposing global leaks.
pub(crate) async fn wait_go_binary_received(fixture: &gobgp::Speaker, expected: &[BinaryWireRule]) {
    let mut actual = vec![];
    let mut failure = None;
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            actual.clear();
            for afi in [1, 2] {
                for safi in [133, 134] {
                    actual.extend(
                        fixture
                            .paths_with_binary_attributes(afi, safi, go::TableType::AdjIn)
                            .await
                            .into_iter()
                            .map(|path| (afi, safi, path)),
                    );
                }
            }
            match exact_binary_inventory(&actual, expected, &fixture.peer_address) {
                Ok(()) => break,
                Err(error) => failure = Some(error),
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    eprintln!("raw peer binary action receipt: {actual:?}");
    assert!(
        result.is_ok(),
        "exact binary peer action/scope receipt timed out: {failure:?}"
    );
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
    pub global_only: Option<gobgp::Speaker>,
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

    pub async fn start_vpn() -> Self {
        Self::start_mode(false, true).await
    }

    async fn start_with(unicast: bool) -> Self {
        Self::start_mode(unicast, false).await
    }

    async fn start_mode(unicast: bool, vpn: bool) -> Self {
        assert_ne!(
            std::env::var("TESTCONTAINERS_COMMAND").as_deref(),
            Ok("keep"),
            "peer qualification requires owned cleanup"
        );
        let network = format!("prefixd-peer-{}", uuid::Uuid::new_v4());
        eprintln!("owned peer network: {network}");
        let mut go = if vpn {
            gobgp::Speaker::on_vpn_network(&network, "192.0.2.20").await
        } else {
            gobgp::Speaker::on_network(&network).await
        };
        let mut global_only = if vpn {
            Some(gobgp::Speaker::on_vpn_network(&network, "192.0.2.21").await)
        } else {
            None
        };
        let go_ip = go.container.get_bridge_ip_address().await.unwrap();
        let rust = if let Some(global) = &global_only {
            rustbgpd::Speaker::start_peered_vpn(
                &network,
                &go_ip.to_string(),
                65010,
                &global
                    .container
                    .get_bridge_ip_address()
                    .await
                    .unwrap()
                    .to_string(),
            )
            .await
        } else if unicast {
            rustbgpd::Speaker::start_peered_unicast(&network, &go_ip.to_string(), 65010).await
        } else {
            rustbgpd::Speaker::start_peered(&network, &go_ip.to_string(), 65010).await
        };
        let rust_ip = rust.container.get_bridge_ip_address().await.unwrap();
        assert_ne!(rust_ip, go_ip);
        go.peer_address = rust_ip.to_string();
        go.add_peer_with_safis(
            179,
            false,
            64512,
            if vpn {
                &[133, 134]
            } else if unicast {
                &[1, 133]
            } else {
                &[133]
            },
        )
        .await;
        if let Some(global) = &mut global_only {
            global.peer_address = rust_ip.to_string();
            global.add_peer_with_safis(179, false, 64512, &[133]).await;
        }
        let pair = Self {
            rust,
            go,
            network,
            global_only,
        };
        pair.assert_isolated().await;
        pair
    }

    pub async fn assert_isolated(&self) {
        let mut containers = vec![
            (&self.rust.container, self.go.peer_address.clone()),
            (&self.go.container, self.rust.peer_address.clone()),
        ];
        if let Some(global) = &self.global_only {
            containers.push((
                &global.container,
                global
                    .container
                    .get_bridge_ip_address()
                    .await
                    .unwrap()
                    .to_string(),
            ));
        }
        for (container, expected_ip) in containers {
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
        let Self {
            rust,
            go,
            network,
            global_only,
        } = self;
        rust.container.rm().await.unwrap();
        go.container.rm().await.unwrap();
        if let Some(global) = global_only {
            global.container.rm().await.unwrap();
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn vpn_path() -> go::Path {
        go::Path {
            family: Some(go::Family { afi: 1, safi: 134 }),
            neighbor_ip: "192.0.2.1".into(),
            nlri: Some(go::Nlri {
                nlri: Some(go::nlri::Nlri::VpnFlowSpec(go::VpnFlowSpecNlri {
                    rd: Some(go::RouteDistinguisher {
                        rd: Some(go::route_distinguisher::Rd::TwoOctetAsn(
                            go::RouteDistinguisherTwoOctetAsn {
                                admin: 44407,
                                assigned: 40,
                            },
                        )),
                    }),
                    rules: vec![go::FlowSpecRule {
                        rule: Some(go::flow_spec_rule::Rule::IpPrefix(go::FlowSpecIpPrefix {
                            r#type: 1,
                            prefix: "203.0.113.10".into(),
                            prefix_len: 32,
                            offset: 0,
                        })),
                    }],
                })),
            }),
            pattrs: vec![go::Attribute {
                attr: Some(go::attribute::Attr::ExtendedCommunities(
                    go::ExtendedCommunitiesAttribute {
                        communities: vec![
                            go::ExtendedCommunity {
                                extcom: Some(go::extended_community::Extcom::TrafficRate(
                                    go::TrafficRateExtended { asn: 0, rate: 0.0 },
                                )),
                            },
                            go::ExtendedCommunity {
                                extcom: Some(go::extended_community::Extcom::TwoOctetAsSpecific(
                                    go::TwoOctetAsSpecificExtended {
                                        is_transitive: true,
                                        sub_type: 2,
                                        asn: 44407,
                                        local_admin: 777,
                                    },
                                )),
                            },
                        ],
                    },
                )),
            }],
            ..Default::default()
        }
    }

    fn binary_attribute(kind: u8, bytes: &[u8], extended: bool) -> Vec<u8> {
        let mut attribute = vec![if extended { 0xd0 } else { 0xc0 }, kind];
        if extended {
            attribute.extend(u16::try_from(bytes.len()).unwrap().to_be_bytes());
        } else {
            attribute.push(u8::try_from(bytes.len()).unwrap());
        }
        attribute.extend(bytes);
        attribute
    }

    #[test]
    fn binary_action_oracle_covers_five_actions_both_families_without_typed_actions() {
        let scope_rt = 0x0002_ad77_0000_0309u64;
        let discard = 0x8006_0000_0000_0000u64;
        let police = discard | u64::from(1_000_000f32.to_bits());
        let marking = 0x8009_0000_0000_002eu64;
        let redirect_vrf = 0x8008_ad77_0000_0378u64;
        let redirect_ipv4 = 0x010c_c000_0263_0000u64;
        let mut redirect_ipv6 = [0; 20];
        redirect_ipv6[1] = 0x0c;
        redirect_ipv6[2..18].copy_from_slice(
            &"2001:db8:ffff::66"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        for afi in [1, 2] {
            let mut path = vpn_path();
            path.family.as_mut().unwrap().afi = afi;
            // Old typed protobuf action variants cannot establish these receipts.
            path.pattrs.clear();
            if afi == 2 {
                let Some(go::nlri::Nlri::VpnFlowSpec(nlri)) = &mut path.nlri.as_mut().unwrap().nlri
                else {
                    panic!("test VPN NLRI")
                };
                let Some(go::flow_spec_rule::Rule::IpPrefix(prefix)) = &mut nlri.rules[0].rule
                else {
                    panic!("test destination")
                };
                prefix.prefix = "2001:db8::1".into();
                prefix.prefix_len = 128;
            }
            for action in [discard, police, marking, redirect_vrf, redirect_ipv4] {
                let mut ordinary = vec![scope_rt];
                let mut ipv6 = vec![];
                if action == redirect_ipv4 && afi == 2 {
                    ipv6.push(redirect_ipv6);
                } else {
                    ordinary.push(action);
                }
                let payload: Vec<_> = ordinary
                    .iter()
                    .flat_map(|value| value.to_be_bytes())
                    .collect();
                path.pattrs_binary = vec![binary_attribute(16, &payload, false)];
                if !ipv6.is_empty() {
                    path.pattrs_binary
                        .push(binary_attribute(25, &ipv6[0], true));
                }
                let expected = BinaryWireRule {
                    nlri: go_received_match(&path, afi, 134, "192.0.2.1"),
                    extended_communities: ordinary,
                    ipv6_extended_communities: ipv6,
                };
                let original = (afi, 134, path.clone());
                assert!(
                    exact_binary_inventory(
                        std::slice::from_ref(&original),
                        std::slice::from_ref(&expected),
                        "192.0.2.1"
                    )
                    .is_ok()
                );
                let mut wrong_action = original.clone();
                let attribute = wrong_action.2.pattrs_binary.last_mut().unwrap();
                *attribute.last_mut().unwrap() ^= 1;
                assert!(
                    exact_binary_inventory(
                        &[wrong_action],
                        std::slice::from_ref(&expected),
                        "192.0.2.1"
                    )
                    .is_err()
                );
                let mut wrong_rt = original.clone();
                wrong_rt.2.pattrs_binary[0][10] ^= 1;
                assert!(
                    exact_binary_inventory(
                        &[wrong_rt],
                        std::slice::from_ref(&expected),
                        "192.0.2.1"
                    )
                    .is_err()
                );
                let mut missing_binary = original;
                missing_binary.2.pattrs_binary.clear();
                assert!(
                    exact_binary_inventory(
                        &[missing_binary],
                        std::slice::from_ref(&expected),
                        "192.0.2.1"
                    )
                    .is_err()
                );
            }
        }
    }

    #[test]
    fn binary_community_parser_checks_headers_lengths_widths_and_duplicates() {
        let value = 0x0002_ad77_0000_0309u64.to_be_bytes();
        let ordinary = binary_attribute(16, &value, false);
        let ipv6 = binary_attribute(25, &[0x55; 20], false);
        assert_eq!(
            binary_communities(&[ordinary.clone(), ipv6]).unwrap(),
            (vec![u64::from_be_bytes(value)], vec![[0x55; 20]])
        );
        let long: Vec<_> = (0..32).flat_map(|_| value).collect();
        let extended = binary_attribute(16, &long, true);
        assert_eq!(
            binary_communities(&[extended]).unwrap().0,
            vec![u64::from_be_bytes(value); 32]
        );
        for malformed in [
            vec![],
            vec![0xc0, 16],
            vec![0xd0, 16, 0],
            vec![0xc0, 16, 8, 0],
            binary_attribute(16, &[0; 7], false),
            binary_attribute(25, &[0; 19], false),
            vec![0xc0, 16, 0],
        ] {
            assert!(binary_communities(&[malformed]).is_err());
        }
        let mut reserved = ordinary.clone();
        reserved[0] |= 1;
        assert!(binary_communities(&[reserved]).is_err());
        let mut non_transitive = ordinary.clone();
        non_transitive[0] = 0x80;
        assert!(binary_communities(&[non_transitive]).is_err());
        assert!(binary_communities(&[ordinary.clone(), ordinary]).is_err());
        assert!(binary_communities(&[]).is_err());
    }

    #[test]
    fn vpn_wire_oracle_rejects_wrong_rd_rt_and_family() {
        let original = vpn_path();
        let expected = go_received_scoped(&original, 1, 134, "192.0.2.1");
        assert!(exact_wire_inventory(
            std::slice::from_ref(&expected),
            std::slice::from_ref(&expected)
        ));
        let mut wrong_rd = original.clone();
        let Some(go::nlri::Nlri::VpnFlowSpec(nlri)) = &mut wrong_rd.nlri.as_mut().unwrap().nlri
        else {
            panic!("VPN test NLRI")
        };
        let Some(go::route_distinguisher::Rd::TwoOctetAsn(rd)) = &mut nlri.rd.as_mut().unwrap().rd
        else {
            panic!("test RD")
        };
        rd.assigned = 41;
        assert!(!exact_wire_inventory(
            &[go_received_scoped(&wrong_rd, 1, 134, "192.0.2.1")],
            std::slice::from_ref(&expected)
        ));
        let mut wrong_rt = original.clone();
        let Some(go::attribute::Attr::ExtendedCommunities(communities)) =
            &mut wrong_rt.pattrs[0].attr
        else {
            panic!("test attributes")
        };
        let Some(go::extended_community::Extcom::TwoOctetAsSpecific(target)) =
            &mut communities.communities[1].extcom
        else {
            panic!("test RT")
        };
        target.local_admin = 778;
        assert!(!exact_wire_inventory(
            &[go_received_scoped(&wrong_rt, 1, 134, "192.0.2.1")],
            std::slice::from_ref(&expected)
        ));
        let mut wrong_family = original.clone();
        wrong_family.family.as_mut().unwrap().afi = 2;
        assert!(
            std::panic::catch_unwind(|| go_received_scoped(&wrong_family, 2, 134, "192.0.2.1"))
                .is_err()
        );
        let mut global_fallback = original;
        global_fallback.family.as_mut().unwrap().safi = 133;
        assert!(
            std::panic::catch_unwind(|| go_received_scoped(&global_fallback, 1, 133, "192.0.2.1"))
                .is_err()
        );
    }
}
