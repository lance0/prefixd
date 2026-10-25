use super::*;

fn addressed(address: &str, interface: &str, state: pb::SessionState) -> pb::NeighborState {
    pb::NeighborState {
        config: Some(pb::NeighborConfig {
            address: address.into(),
            interface: interface.into(),
            ..Default::default()
        }),
        state: state as i32,
        ..Default::default()
    }
}

fn discovered(
    interface: &str,
    address: &str,
    discovery: pb::NeighborDiscoveryState,
    state: pb::SessionState,
) -> pb::NeighborState {
    pb::NeighborState {
        learned_peer_address: address.into(),
        discovery_state: discovery as i32,
        ..addressed("", interface, state)
    }
}

fn export(address: &str, interface: &str) -> pb::PathExportDispositionEntry {
    pb::PathExportDispositionEntry {
        peer_address: address.into(),
        peer_interface: interface.into(),
        disposition: pb::PathExportDisposition::Committed as i32,
        ..Default::default()
    }
}

#[test]
fn numbered_peers_keep_their_existing_identity() {
    for address in ["192.0.2.1", "2001:db8::1"] {
        let peer =
            decode_peer_status(addressed(address, "", pb::SessionState::Established)).unwrap();
        assert_eq!(peer.name, address);
        assert_eq!(peer.address, address);
        assert!(peer.state.is_established());
        assert_eq!(
            decode_export(export(address, "")).unwrap().peer_address,
            address
        );
    }
}

#[test]
fn shared_link_local_addresses_have_distinct_health_and_export_identities() {
    let peers = decode_peer_statuses(vec![
        addressed("fe80::1", "eth0", pb::SessionState::Established),
        addressed("fe80::1", "eth1", pb::SessionState::Idle),
    ])
    .unwrap();
    let sessions = prometheus::GaugeVec::new(
        prometheus::Opts::new("test_v080_peer_up", "Peer session"),
        &["peer"],
    )
    .unwrap();
    for peer in &peers {
        sessions
            .with_label_values(&[&peer.name])
            .set(if peer.state.is_established() {
                1.0
            } else {
                0.0
            });
    }
    assert_eq!(sessions.with_label_values(&["fe80::1%eth0"]).get(), 1.0);
    assert_eq!(sessions.with_label_values(&["fe80::1%eth1"]).get(), 0.0);
    for (peer, interface) in peers.iter().zip(["eth0", "eth1"]) {
        assert_eq!(peer.name, peer.address);
        assert_eq!(
            decode_export(export("fe80::1", interface))
                .unwrap()
                .peer_address,
            peer.address
        );
    }
}

#[test]
fn interface_only_metrics_keep_identity_across_discovery_and_rebinding() {
    use pb::{NeighborDiscoveryState as Discovery, SessionState as Session};
    let unbound = decode_peer_status(discovered(
        "swp1",
        "",
        Discovery::AwaitingDiscovery,
        Session::Idle,
    ))
    .unwrap();
    assert_eq!(unbound.name, "interface:swp1");
    assert_eq!(unbound.address, "interface:swp1");
    assert!(!unbound.state.is_established());
    for address in ["fe80::1", "fe80::2"] {
        let bound = decode_peer_status(discovered(
            "swp1",
            address,
            Discovery::Bound,
            Session::Established,
        ))
        .unwrap();
        assert_eq!(bound.name, unbound.name);
        assert_eq!(bound.address, format!("{address}%swp1"));
        assert_eq!(
            decode_export(export(address, "swp1")).unwrap().peer_address,
            bound.address
        );
    }
    for discovery in [Discovery::InterfaceMissing, Discovery::LinkDown] {
        let peer = decode_peer_status(discovered("swp1", "", discovery, Session::Idle)).unwrap();
        assert_eq!(peer.name, unbound.name);
        assert!(!peer.state.is_established());
    }
}

#[test]
fn interface_only_neighbors_on_two_links_do_not_alias() {
    let peers = decode_peer_statuses(
        ["swp1", "swp2"]
            .map(|interface| {
                discovered(
                    interface,
                    "fe80::1",
                    pb::NeighborDiscoveryState::Bound,
                    pb::SessionState::Established,
                )
            })
            .into(),
    )
    .unwrap();
    assert_ne!(peers[0].name, peers[1].name);
    assert_ne!(peers[0].address, peers[1].address);
}

#[test]
fn malformed_or_inconsistent_peer_identity_fails_the_complete_observation() {
    use pb::{NeighborDiscoveryState as Discovery, SessionState as Session};
    let mut stale = addressed("192.0.2.1", "", Session::Established);
    stale.stale = true;
    let mut unknown_discovery = discovered("swp1", "", Discovery::AwaitingDiscovery, Session::Idle);
    unknown_discovery.discovery_state = i32::MAX;
    for bad in [
        addressed("fe80::1", "", Session::Established),
        addressed("fe80::1%eth0", "eth0", Session::Established),
        addressed("fe80::1", "eth 0", Session::Established),
        addressed("192.0.2.1", "eth0", Session::Established),
        addressed("2001:db8::1", "eth0", Session::Established),
        discovered("", "", Discovery::AwaitingDiscovery, Session::Idle),
        discovered(
            "swp1",
            "",
            Discovery::AwaitingDiscovery,
            Session::Established,
        ),
        discovered("swp1", "", Discovery::Bound, Session::Established),
        discovered(
            "swp1",
            "2001:db8::1",
            Discovery::Bound,
            Session::Established,
        ),
        discovered("swp1", "fe80::1", Discovery::LinkDown, Session::Idle),
        discovered("swp1", "", Discovery::Unspecified, Session::Idle),
        stale,
        unknown_discovery,
    ] {
        assert!(
            decode_peer_statuses(vec![addressed("192.0.2.2", "", Session::Established), bad,])
                .is_err()
        );
    }
    let mut addressed_discovery = addressed("fe80::1", "eth0", Session::Established);
    addressed_discovery.discovery_state = Discovery::Bound as i32;
    assert!(decode_peer_status(addressed_discovery).is_err());
}

#[test]
fn duplicate_neighbor_or_endpoint_fails_the_complete_observation() {
    use pb::{NeighborDiscoveryState as Discovery, SessionState as Session};
    for pair in [
        [
            addressed("2001:db8::1", "", Session::Established),
            addressed("2001:DB8::0001", "", Session::Idle),
        ],
        [
            discovered("swp1", "fe80::1", Discovery::Bound, Session::Established),
            discovered("swp1", "fe80::2", Discovery::Bound, Session::Idle),
        ],
        [
            addressed("fe80::1", "swp1", Session::Established),
            discovered("swp1", "fe80::1", Discovery::Bound, Session::Idle),
        ],
    ] {
        assert!(decode_peer_statuses(pair.into()).is_err());
    }
}

#[test]
fn malformed_export_scope_is_unknown_instead_of_a_bare_peer_claim() {
    for (address, interface) in [
        ("fe80::1", ""),
        ("fe80::1%eth0", "eth0"),
        ("fe80::1", "eth\n0"),
        ("192.0.2.1", "eth0"),
        ("", "swp1"),
    ] {
        assert!(decode_export(export(address, interface)).is_err());
    }
}
