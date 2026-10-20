//! Generated rustbgpd client stubs (ADR 023).
//!
//! `proto/rustbgpd.proto` (package `rustbgpd.v1`) is the unmodified
//! `rustbgpd.proto` asset of the rustbgpd v0.79.0 release,
//! <https://github.com/lance0/rustbgpd/releases/download/v0.79.0/rustbgpd.proto>,
//! sha256 `21a7f5ca199184a0d4cf94414ed8dcfa49c660c1fbb8b4c79e076b9d7685dd62`.
//! `proto/rustbgpd.proto.sha256` is that release's checksum asset, and
//! `just proto` checks the file against it offline. To move the pin, download
//! both assets of the new release, run `shasum -a 256 --check` on them, copy both
//! here and update this comment.
//!
//! The generated stubs follow the pinned release, but the controller contract
//! does not: v0.76.0 is still the minimum daemon. Fields and RPCs newer than
//! that stay unset and unused until a change adopts them behind a version or
//! capability check. The stubs are compiled only when the `bgp-rustbgpd`
//! feature is on, so the GoBGP and rustbgpd backends can coexist.
#[cfg(feature = "bgp-rustbgpd")]
pub mod rustbgpd_pb {
    #![allow(
        clippy::allow_attributes_without_reason,
        reason = "Tonic-generated bindings emit lint attributes without reasons"
    )]
    #![allow(
        clippy::large_enum_variant,
        reason = "Preserve prost-generated oneof value types from the vendored speaker API"
    )]
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
            ..Default::default()
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
    fn blackhole_contract_is_present() {
        assert_eq!(pb::AddressFamily::Ipv4Unicast as i32, 1);
        assert_eq!(pb::AddressFamily::Ipv6Unicast as i32, 2);

        // upsert keyed on (prefix, prefix_length, path_id); before 0.79.0 the reply has no outcome
        let add = pb::AddPathRequest {
            prefix: "192.0.2.1".into(),
            prefix_length: 32,
            next_hop: "192.0.2.66".into(),
            as_path: Vec::new(),
            origin: 0,
            local_pref: None,
            med: None,
            communities: vec![0xFFFF_029A],
            extended_communities: Vec::new(),
            large_communities: Vec::new(),
            path_id: 0,
        };
        assert_eq!(add.path_id, 0);
        let _: pb::AddPathResponse = pb::AddPathResponse::default();

        // allow_missing is 0.79.0+ and stays unset: a missing path is NOT_FOUND
        let delete = pb::DeletePathRequest {
            prefix: add.prefix,
            prefix_length: 32,
            path_id: 0,
            ..Default::default()
        };
        assert!(!delete.allow_missing);
        assert_eq!(delete.prefix_length, 32);
        let _: pb::DeletePathResponse = pb::DeletePathResponse::default();

        // "0.0.0.0" selects retained local injections; the view is paged.
        let list = pb::ListRoutesRequest {
            neighbor_address: "0.0.0.0".into(),
            afi_safi: 1,
            page_size: 100,
            page_token: String::new(),
            ..Default::default()
        };
        assert_eq!(list.neighbor_address, "0.0.0.0");
        let page = pb::ListRoutesResponse {
            routes: Vec::new(),
            next_page_token: String::new(),
            total_count: 0,
            page_version: Some(pb::RoutePageVersion {
                epoch: 1,
                generation: 1,
            }),
        };
        assert!(page.next_page_token.is_empty());
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
