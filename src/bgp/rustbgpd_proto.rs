//! Generated rustbgpd client stubs (ADR 023).
//!
//! The proto is vendored from rustbgpd (`proto/rustbgpd.proto`, package
//! `rustbgpd.v1`) and is compiled only when the `bgp-rustbgpd` feature is on, so
//! the GoBGP and rustbgpd backends can coexist while the swap is validated.
#[cfg(feature = "bgp-rustbgpd")]
pub mod rustbgpd_pb {
    // We only need the client stubs plus the controller message types.
    #![allow(dead_code)]
    #![allow(clippy::enum_variant_names)]
    #![allow(clippy::large_enum_variant)]
    tonic::include_proto!("rustbgpd.v1");
}

/// Pins the FlowSpec controller surface `RustBgpdAnnouncer` depends on, so a
/// rustbgpd upgrade that renames or drops part of it fails here instead of in
/// production.
#[cfg(all(test, feature = "bgp-rustbgpd"))]
mod tests {
    use super::rustbgpd_pb as pb;

    #[test]
    fn announcement_contract_is_present() {
        let afi = pb::AddressFamily::Ipv4Flowspec as i32;
        assert_eq!(afi, 3);

        // announce: upsert, and the response reports what changed
        let add = pb::AddFlowSpecRequest {
            afi_safi: afi,
            components: Vec::new(),
            actions: Vec::new(),
            communities: Vec::new(),
            extended_communities: Vec::new(),
        };
        assert_eq!(add.afi_safi, afi);
        assert_eq!(pb::FlowSpecInjectOutcome::Created as i32, 1);
        assert_eq!(pb::FlowSpecInjectOutcome::Replaced as i32, 2);
        assert_eq!(pb::FlowSpecInjectOutcome::Unchanged as i32, 3);

        // withdraw: opt-in idempotency, so "already gone" can be treated as drift
        let delete = pb::DeleteFlowSpecRequest {
            afi_safi: afi,
            components: Vec::new(),
            allow_missing: true,
        };
        assert!(delete.allow_missing);
        assert_eq!(pb::FlowSpecDeleteOutcome::Deleted as i32, 1);
        assert_eq!(pb::FlowSpecDeleteOutcome::NotPresent as i32, 2);
    }

    #[test]
    fn reconciliation_views_are_present() {
        let afi = pb::AddressFamily::Ipv6Flowspec as i32;
        assert_eq!(afi, 4);

        // "0.0.0.0" selects the locally injected rules - exactly what was injected,
        // including rules a received candidate currently out-selects.
        let local = pb::ListFlowSpecRequest {
            afi_safi: afi,
            received_peer_address: "0.0.0.0".to_string(),
            advertised_peer_address: String::new(),
        };
        assert_eq!(local.received_peer_address, "0.0.0.0");

        // A named peer reads its committed post-export-policy Adj-RIB-Out.
        let advertised = pb::ListFlowSpecRequest {
            afi_safi: afi,
            received_peer_address: String::new(),
            advertised_peer_address: "192.0.2.1".to_string(),
        };
        assert_eq!(advertised.advertised_peer_address, "192.0.2.1");

        // Both modes are acknowledged explicitly: an older daemon ignores the
        // selector and would otherwise look like an empty Loc-RIB.
        let response = pb::ListFlowSpecResponse {
            routes: Vec::new(),
            received_routes: Vec::new(),
            received_view: true,
            advertised_view: true,
        };
        assert!(response.received_view);
        assert!(response.advertised_view);
    }

    #[test]
    fn controller_clients_are_generated() {
        use tonic::transport::Channel;
        fn assert_client<T>(_: fn(Channel) -> T) {}

        assert_client(pb::injection_service_client::InjectionServiceClient::new);
        assert_client(pb::rib_service_client::RibServiceClient::new);
        assert_client(pb::neighbor_service_client::NeighborServiceClient::new);
    }
}
