//! Released controller/RIB/wire receipt, not router forwarding or enforcement.
#![cfg(all(feature = "bgp-rustbgpd", feature = "test-utils", target_os = "linux"))]
mod common;
#[allow(
    dead_code,
    reason = "this peer target reuses only inventory and session helpers from the shared contract"
)]
#[path = "common/speaker_contract.rs"]
mod contract;
use common::gobgp;
#[path = "common/peer_receipt.rs"]
mod peer_receipt;
#[path = "common/rustbgpd.rs"]
mod rustbgpd;

use peer_receipt::{wait_go_received, wait_rust_views};
use prefixd::{
    bgp::{ExportDisposition, ExportObserver, FlowSpecWriter, PeerObserver},
    domain::{FlowSpecAction, FlowSpecNlri, FlowSpecRule},
};

fn rules() -> Vec<FlowSpecRule> {
    let mut rules: Vec<_> = [
        "192.0.2.240/32",
        "192.0.2.241/32",
        "2001:db8::240/128",
        "2001:db8::241/128",
    ]
    .into_iter()
    .enumerate()
    .map(|(index, prefix)| {
        FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: prefix.into(),
                protocol: Some(if index < 2 { 6 } else { 17 }),
                dst_ports: vec![80, 443],
                ..Default::default()
            },
            if index % 2 == 0 {
                FlowSpecAction::discard()
            } else {
                FlowSpecAction::police(8_000_000)
            },
        )
    })
    .collect();
    rules.extend(contract::source_prefix_rules());
    rules
}

async fn wait_flow_export(
    speaker: &prefixd::bgp::RustBgpdAnnouncer,
    nlri: &FlowSpecNlri,
    disposition: ExportDisposition,
    reason: &str,
) {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let peers = speaker.flowspec_exports(nlri).await.unwrap().unwrap();
            let established: Vec<_> = peers
                .iter()
                .filter(|peer| peer.disposition != ExportDisposition::NotEstablished)
                .collect();
            if established.len() == 1
                && established[0].disposition == disposition
                && established[0].reason == reason
            {
                eprintln!("FlowSpec export {}: {peers:?}", nlri.dst_prefix);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("settled FlowSpec export at the exact local match key");
}

#[tokio::test]
#[ignore = "requires isolated pinned Docker speakers; run scripts/test-rustbgpd.sh"]
async fn released_peers_receive_exact_routes_and_retain_nonselected_local_intent() {
    let pair = peer_receipt::Pair::start().await;
    let rust = &pair.rust;
    let go = &pair.go;
    let rust_client = rust.connect().await;
    let go_client = go.connect().await;
    contract::wait_peer_state(&rust_client, &rust.peer_address, true)
        .await
        .unwrap();
    contract::wait_peer_state(&go_client, &go.peer_address, true)
        .await
        .unwrap();
    let owned = rules();
    let unrelated = FlowSpecRule::new(
        FlowSpecNlri {
            dst_prefix: "198.51.100.250/32".into(),
            protocol: Some(1),
            dst_ports: vec![],
            ..Default::default()
        },
        FlowSpecAction::discard(),
    );
    rust_client.announce(&unrelated).await.unwrap();
    for rule in &owned {
        rust_client.announce(rule).await.unwrap();
    }
    let mut all = owned.clone();
    all.push(unrelated.clone());
    wait_go_received(go, &all).await;
    wait_rust_views(rust, &all, &[]).await;
    for rule in &owned {
        wait_flow_export(&rust_client, &rule.nlri, ExportDisposition::Committed, "").await;
    }
    for rule in &owned {
        rust_client.withdraw(rule).await.unwrap();
    }
    wait_go_received(go, std::slice::from_ref(&unrelated)).await;
    for rule in &owned {
        rust_client.announce(rule).await.unwrap();
    }
    wait_go_received(go, &all).await;

    // The explicit import policy assigns received routes LOCAL_PREF 200; local injection uses 100.
    let remote: Vec<_> = owned
        .iter()
        .cloned()
        .map(|mut rule| {
            rule.actions = vec![FlowSpecAction::police(32_000_000)];
            rule
        })
        .collect();
    for rule in &remote {
        go_client.announce(rule).await.unwrap();
    }
    wait_rust_views(rust, &all, &remote).await;
    contract::wait_inventory(&rust_client, &all).await.unwrap();
    for rule in &owned {
        wait_flow_export(
            &rust_client,
            &rule.nlri,
            ExportDisposition::Withheld,
            "not_selected",
        )
        .await;
    }
    for rule in &owned {
        rust_client.withdraw(rule).await.unwrap();
    }
    wait_rust_views(rust, std::slice::from_ref(&unrelated), &remote).await;
    for rule in &owned {
        rust_client.announce(rule).await.unwrap();
    }
    wait_rust_views(rust, &all, &remote).await;
    contract::wait_inventory(&rust_client, &all).await.unwrap();
    for rule in &remote {
        go_client.withdraw(rule).await.unwrap();
    }
    wait_rust_views(rust, &all, &[]).await;
    wait_go_received(go, &all).await;
    for rule in &owned {
        rust_client.withdraw(rule).await.unwrap();
    }
    contract::wait_inventory(&rust_client, std::slice::from_ref(&unrelated))
        .await
        .unwrap();
    wait_go_received(go, std::slice::from_ref(&unrelated)).await;
    pair.remove().await;
}

#[tokio::test]
#[ignore = "requires isolated pinned Docker speakers; run scripts/test-rustbgpd.sh"]
async fn owned_peer_bridge_cleans_up_after_test_failure() {
    let pair = peer_receipt::Pair::start().await;
    let network = pair.network.clone();
    let ids = [
        pair.rust.container.id().to_owned(),
        pair.go.container.id().to_owned(),
    ];
    let result = tokio::spawn(async move {
        let _owned_pair = pair;
        panic!("controlled fixture failure to verify panic-path cleanup");
    })
    .await;
    assert!(result.unwrap_err().is_panic());
    for id in &ids {
        peer_receipt::wait_removed("container", id).await;
    }
    peer_receipt::wait_removed("network", &network).await;
}

#[tokio::test]
#[ignore = "requires isolated pinned Docker speakers; run scripts/test-rustbgpd.sh"]
async fn released_peer_restart_reconciles_original_desired_state_without_extra_repairs() {
    use prefixd::{
        bgp::FlowSpecReader,
        db::{MockRepository, RepositoryTrait},
        domain::{
            ActionParams, AttackVector, MatchCriteria, Mitigation, MitigationIntent,
            MitigationStatus, SpeakerTarget, request_withdrawal,
        },
        observability::metrics,
        scheduler::ReconciliationLoop,
    };
    use std::sync::Arc;

    let pair = peer_receipt::Pair::start().await;
    let speaker = Arc::new(pair.rust.connect().await);
    let go_client = pair.go.connect().await;
    let repo = Arc::new(MockRepository::new());
    let mut settings = common::test_settings();
    settings.pop = "peer-restart".into();
    settings.bgp.mode = prefixd::config::BgpMode::Rustbgpd;
    settings.bgp.rustbgpd = Some(pair.rust.config.clone());
    let binding = repo
        .register_speaker_target(
            &settings.pop,
            &SpeakerTarget::from_config(&settings.bgp).unwrap(),
            false,
        )
        .await
        .unwrap();
    let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false)
        .with_speaker_binding(binding.clone());
    let desired = rules();
    let mut persisted = vec![];
    for rule in &desired {
        let action = &rule.actions[0];
        let mut mitigation = Mitigation::from_intent(
            MitigationIntent {
                event_id: uuid::Uuid::new_v4(),
                customer_id: None,
                service_id: None,
                pop: settings.pop.clone(),
                match_criteria: MatchCriteria {
                    dst_prefix: rule.nlri.dst_prefix.clone(),
                    src_prefix: rule.nlri.src_prefix.clone(),
                    protocol: rule.nlri.protocol,
                    dst_ports: rule.nlri.dst_ports.clone(),
                    ..Default::default()
                },
                action_type: action.action_type,
                action_params: ActionParams {
                    rate_bps: action.rate_bps,
                    ..Default::default()
                },
                ttl_seconds: 300,
                reason: "owned peer restart recovery".into(),
            },
            rule.nlri.dst_prefix.split('/').next().unwrap().into(),
            AttackVector::UdpFlood,
        );
        mitigation.activate();
        repo.insert_mitigation(&mitigation).await.unwrap();
        persisted.push(mitigation);
    }
    reconciler.reconcile().await.unwrap();
    contract::wait_peer_state(speaker.as_ref(), &pair.rust.peer_address, true)
        .await
        .unwrap();
    contract::wait_peer_state(&go_client, &pair.go.peer_address, true)
        .await
        .unwrap();
    contract::wait_inventory(speaker.as_ref(), &desired)
        .await
        .unwrap();
    wait_rust_views(&pair.rust, &desired, &[]).await;
    wait_go_received(&pair.go, &desired).await;

    // Restart only the process/container, retaining its mounted runtime directory.
    let before_rpc = pair
        .rust
        .container
        .get_host_port_ipv4(testcontainers::core::IntoContainerPort::tcp(
            pair.rust
                .endpoint
                .rsplit(':')
                .next()
                .unwrap()
                .parse::<u16>()
                .unwrap(),
        ))
        .await
        .unwrap();
    pair.rust
        .container
        .stop_with_timeout(Some(0))
        .await
        .unwrap();
    pair.rust.container.start().await.unwrap();
    let after_rpc = pair
        .rust
        .container
        .get_host_port_ipv4(testcontainers::core::IntoContainerPort::tcp(before_rpc))
        .await
        .unwrap();
    assert_eq!(
        after_rpc, before_rpc,
        "original RPC endpoint survives speaker restart"
    );
    pair.rust.ready().await;
    assert!(speaker.list_active().await.unwrap().is_empty());
    contract::wait_peer_state(speaker.as_ref(), &pair.rust.peer_address, true)
        .await
        .unwrap();
    contract::wait_peer_state(&go_client, &pair.go.peer_address, true)
        .await
        .unwrap();
    wait_rust_views(&pair.rust, &[], &[]).await;
    wait_go_received(&pair.go, &[]).await;
    for mitigation in &persisted {
        assert_eq!(
            repo.get_mitigation(mitigation.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            MitigationStatus::Active
        );
    }
    let repairs = metrics::RECONCILIATION_REPAIRS.with_label_values(&["success"]);
    let errors = metrics::RECONCILIATION_REPAIRS.with_label_values(&["error"]);
    let before = repairs.get();
    let errors_before = errors.get();
    reconciler.reconcile().await.unwrap();
    contract::wait_inventory(speaker.as_ref(), &desired)
        .await
        .unwrap();
    wait_rust_views(&pair.rust, &desired, &[]).await;
    wait_go_received(&pair.go, &desired).await;
    assert_eq!(repairs.get(), before + desired.len() as f64);
    reconciler.reconcile().await.unwrap();
    assert_eq!(repairs.get(), before + desired.len() as f64);
    assert_eq!(errors.get(), errors_before);

    for mitigation in &persisted {
        request_withdrawal(
            repo.as_ref(),
            mitigation,
            false,
            "system",
            "peer-test",
            "restart proof cleanup".into(),
            true,
            Some(&binding),
        )
        .await
        .unwrap();
    }
    reconciler.reconcile().await.unwrap();
    contract::wait_inventory(speaker.as_ref(), &[])
        .await
        .unwrap();
    wait_rust_views(&pair.rust, &[], &[]).await;
    wait_go_received(&pair.go, &[]).await;
    for mitigation in &persisted {
        assert_eq!(
            repo.get_mitigation(mitigation.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            MitigationStatus::Withdrawn
        );
    }
    pair.remove().await;
}

/// Released rustbgpd export dispositions toward one Established peer, joined
/// with a configured peer that never establishes. Committed is the peer's
/// Adj-RIB-Out only; this test makes no receipt or enforcement claim.
#[tokio::test]
#[ignore = "requires isolated pinned Docker speakers; run scripts/test-rustbgpd.sh"]
async fn released_blackhole_export_dispositions_join_established_and_configured_peers() {
    use prefixd::{
        bgp::{BlackholeRoute, BlackholeSpeaker, ExportDisposition, ExportObserver, PeerObserver},
        domain::BlackholeExportEvidence,
    };
    use std::time::Duration;

    let pair = peer_receipt::Pair::start_unicast().await;
    let speaker = pair.rust.connect().await;
    let go_address = pair.rust.peer_address.clone();
    let sessions = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let sessions = speaker.session_status().await.unwrap();
            let state = |address: &str| {
                sessions
                    .iter()
                    .find(|peer| peer.address == address)
                    .map(|peer| peer.state.is_established())
            };
            if sessions.len() == 2
                && state(&go_address) == Some(true)
                && state(rustbgpd::UNREACHABLE_PEER) == Some(false)
            {
                break sessions;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("one Established and one configured peer");

    let route = |prefix: &str, next_hop: &str| {
        BlackholeRoute::new(
            prefix.parse().unwrap(),
            next_hop.parse().unwrap(),
            vec![],
            vec![],
        )
        .unwrap()
    };
    let cases = [
        (
            route("192.0.2.240/32", "192.0.2.66"),
            ExportDisposition::Committed,
            "",
            "",
            None,
        ),
        (
            route("2001:db8::240/128", "2001:db8:ffff::66"),
            ExportDisposition::Committed,
            "",
            "",
            None,
        ),
        // How an RPKI-Invalid export filter reports a blackhole.
        (
            route(rustbgpd::EXPORT_DENIED, "192.0.2.66"),
            ExportDisposition::Withheld,
            "export_policy",
            "policy_denied",
            Some("export_policy"),
        ),
    ];
    for (route, ..) in &cases {
        speaker.announce_blackhole(route).await.unwrap();
    }
    for (route, disposition, reason, explain_code, warning) in &cases {
        let peers = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let peers = speaker
                    .blackhole_exports(&route.prefix())
                    .await
                    .unwrap()
                    .expect("local route present");
                if peers
                    .iter()
                    .all(|peer| peer.disposition != ExportDisposition::Pending)
                {
                    break peers;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("settled export disposition");
        eprintln!("export dispositions for {}: {peers:?}", route.prefix());
        // Configured peers are listed independently of the optional session read.
        assert_eq!(peers.len(), 2, "{peers:?}");
        let down = peers
            .iter()
            .find(|peer| peer.peer_address == rustbgpd::UNREACHABLE_PEER)
            .unwrap();
        assert_eq!(down.disposition, ExportDisposition::NotEstablished);
        assert_eq!(down.reason, "not_established");
        let peer = peers
            .iter()
            .find(|peer| peer.peer_address == go_address)
            .unwrap();
        assert_eq!(peer.peer_address, go_address);
        assert_eq!(peer.disposition, *disposition);
        assert_eq!(peer.reason, *reason);
        assert_eq!(peer.explain_code, *explain_code);
        assert_eq!(peer.advertised_path_id, 0);
        let evidence = BlackholeExportEvidence::from_read(
            &Ok(Some(peers.clone())),
            Some(&sessions),
            chrono::Utc::now(),
        );
        assert_eq!(evidence.warning.map(|warning| warning.reason), *warning);
        let not_established = evidence.not_established_peers.unwrap();
        assert_eq!(not_established.len(), 1);
        assert_eq!(not_established[0].peer_address, rustbgpd::UNREACHABLE_PEER);
        let without_sessions =
            BlackholeExportEvidence::from_read(&Ok(Some(peers.clone())), None, chrono::Utc::now());
        assert_eq!(without_sessions.counts, evidence.counts);
        assert_eq!(
            without_sessions.not_established_peers.unwrap()[0].state,
            None
        );
    }
    let flow = rules().remove(0);
    speaker.announce(&flow).await.unwrap();
    let exports = speaker.flowspec_exports(&flow.nlri).await.unwrap().unwrap();
    let down: Vec<_> = exports
        .iter()
        .filter(|peer| peer.disposition == ExportDisposition::NotEstablished)
        .collect();
    assert_eq!(
        down.len(),
        1,
        "released FlowSpec configured-peer roster: {exports:?}"
    );
    assert_eq!(down[0].peer_address, rustbgpd::UNREACHABLE_PEER);
    speaker.withdraw(&flow).await.unwrap();
    for (route, ..) in &cases {
        speaker
            .withdraw_blackhole(&route.prefix(), "")
            .await
            .unwrap();
    }
    // No local route at the key is absence, distinct from an empty export list.
    assert_eq!(
        speaker
            .blackhole_exports(&cases[0].0.prefix())
            .await
            .unwrap(),
        None
    );
    pair.remove().await;
}

/// HTTP admission through prefixd, released speaker, and negotiated peer RIB.
/// These are local intent and wire receipts; there is no router enforcement oracle.
#[tokio::test]
#[ignore = "requires isolated pinned Docker speakers; run scripts/test-rustbgpd.sh with version 0.82.0"]
async fn released_vpn_http_rules_reach_only_negotiated_peers_with_exact_scope() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use prefixd::{
        AppState,
        api::create_test_router,
        bgp::FlowSpecReader,
        config::{BgpMode, Customer, Inventory, OperationMode, Playbooks, PolicyProfile},
        db::{MockRepository, RepositoryTrait},
        domain::{SpeakerTarget, VpnFlowSpecFamily, VpnFlowSpecIdentity},
    };
    use serde_json::{Value, json};
    use std::sync::Arc;
    use tower::ServiceExt;

    // The minimum-release matrix keeps its existing global cases; this test
    // explicitly qualifies the released contract containing VPN families.
    if std::env::var("PREFIXD_RUSTBGPD_TEST_VERSION").as_deref() != Ok("0.82.0") {
        eprintln!("VPN wire receipt not applicable to this release; requires 0.82.0");
        return;
    }
    let pair = peer_receipt::Pair::start_vpn().await;
    let speaker = Arc::new(pair.rust.connect().await);
    let global_peer = pair.global_only.as_ref().unwrap();
    let mut settings = common::test_settings();
    settings.mode = OperationMode::Enforced;
    settings.bgp.mode = BgpMode::Rustbgpd;
    settings.bgp.rustbgpd = Some(pair.rust.config.clone());
    settings.guardrails.allow_src_prefix_match = true;
    settings.bgp.vpn_scopes = serde_json::from_value(json!({
        "TRANSIT": {"family":"ipv4","rd":"44407:40","route_targets":["44407:777"],"allow_source_only":true},
        "TRANSIT6": {"family":"ipv6","rd":"44407:41","route_targets":["44407:778"],"allow_source_only":true}
    })).unwrap();
    for (name, scope) in &settings.bgp.vpn_scopes {
        speaker
            .validate_scope(Some(&scope.snapshot(name).unwrap().identity))
            .await
            .unwrap();
    }
    let repo = Arc::new(MockRepository::new());
    let binding = repo
        .register_speaker_target(
            &settings.pop,
            &SpeakerTarget::from_config(&settings.bgp).unwrap(),
            false,
        )
        .await
        .unwrap();
    let inventory = Inventory::new(vec![Customer {
        customer_id: "wire-pilot".into(),
        name: "Wire pilot".into(),
        prefixes: vec!["203.0.113.0/24".into(), "2001:db8:100::/48".into()],
        policy_profile: PolicyProfile::Normal,
        services: vec![],
    }]);
    let state = AppState::new(
        settings,
        inventory,
        Playbooks { playbooks: vec![] },
        repo.clone(),
        speaker.clone(),
        ".".into(),
    )
    .unwrap()
    .with_speaker_binding(binding)
    .unwrap();
    let app = create_test_router(state);
    async fn post(app: &axum::Router, path: &str, body: Value, expected: StatusCode) -> Value {
        let response = app
            .clone()
            .oneshot(
                Request::post(path)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(status, expected, "{path}: {value}");
        value
    }
    for peer in [&pair.go, global_peer] {
        contract::wait_peer_state(&peer.connect().await, &peer.peer_address, true)
            .await
            .unwrap();
    }
    let expected_peers = [
        pair.rust.peer_address.clone(),
        global_peer
            .container
            .get_bridge_ip_address()
            .await
            .unwrap()
            .to_string(),
    ];
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            let peers = speaker.session_status().await.unwrap();
            if peers.len() == 2
                && expected_peers.iter().all(|address| {
                    peers
                        .iter()
                        .any(|peer| &peer.address == address && peer.state.is_established())
                })
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("both isolated peers Established");
    let mut created: Vec<(String, FlowSpecRule)> = vec![];
    let global=post(&app,"/v1/mitigations",json!({"victim_ip":"203.0.113.10","src_prefix":"198.51.100.0/24",
        "protocol":"udp","dst_ports":[443],"action":"discard","ttl_seconds":60,"reason":"global scope control"}),StatusCode::CREATED).await;
    created.push((
        global["mitigation_id"].as_str().unwrap().into(),
        FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: "203.0.113.10/32".into(),
                src_prefix: Some("198.51.100.0/24".into()),
                protocol: Some(17),
                dst_ports: vec![443],
                ..Default::default()
            },
            FlowSpecAction::discard(),
        ),
    ));
    let families = [
        (
            "TRANSIT",
            VpnFlowSpecFamily::Ipv4,
            "44407:40",
            "44407:777",
            ["203.0.113.10", "203.0.113.11"],
            ["198.51.100.0/24", "198.51.101.0/24"],
        ),
        (
            "TRANSIT6",
            VpnFlowSpecFamily::Ipv6,
            "44407:41",
            "44407:778",
            ["2001:db8:100::10", "2001:db8:100::11"],
            ["2001:db9::/64", "2001:db9:1::/64"],
        ),
    ];
    for (name, family, rd, rt, destinations, sources) in families {
        for (index, action) in ["discard", "police"].into_iter().enumerate() {
            let response=post(&app,"/v1/vpn/mitigations",json!({"scope":name,"rule":{
                "victim_ip":destinations[index],"src_prefix":sources[index],"protocol":"udp","dst_ports":[443],
                "action":action,"rate_bps":if index==0 {None} else {Some(8_000_000u64)},"ttl_seconds":60,"reason":"VPN wire receipt"}}),StatusCode::CREATED).await;
            created.push((
                response["mitigation_id"].as_str().unwrap().into(),
                FlowSpecRule::new(
                    FlowSpecNlri {
                        scope: Some(VpnFlowSpecIdentity::new(family, rd).unwrap()),
                        dst_prefix: format!(
                            "{}/{}",
                            destinations[index],
                            if family == VpnFlowSpecFamily::Ipv4 {
                                32
                            } else {
                                128
                            }
                        ),
                        src_prefix: Some(sources[index].into()),
                        protocol: Some(17),
                        dst_ports: vec![443],
                        ..Default::default()
                    },
                    if index == 0 {
                        FlowSpecAction::discard()
                    } else {
                        FlowSpecAction::police(8_000_000)
                    },
                )
                .with_route_targets(vec![rt.into()]),
            ));
        }
    }
    // Whole-VRF authorization includes protected destinations; source protection
    // still applies. The scoped source ranges are outside this owned inventory.
    repo.insert_safelist("203.0.113.10/32", "config", None)
        .await
        .unwrap();
    for (name, family, rd, rt, _, sources) in families {
        for (index, action) in ["discard", "police"].into_iter().enumerate() {
            let request = json!({"scope":name,"src_prefix":sources[index],"protocol":"udp","action":action,
                "rate_bps":if index==0 {None} else {Some(8_000_000u64)},"ttl_seconds":30,
                "confirm_destination_any":true,"reason":"source-only VPN wire receipt"});
            let preview = post(
                &app,
                "/v1/vpn/source-rules/preview",
                request.clone(),
                StatusCode::OK,
            )
            .await;
            assert_eq!(preview["candidate"]["destination"], "any");
            let response = post(&app, "/v1/vpn/source-rules", request, StatusCode::CREATED).await;
            created.push((
                response["mitigation_id"].as_str().unwrap().into(),
                FlowSpecRule::new(
                    FlowSpecNlri {
                        scope: Some(VpnFlowSpecIdentity::new(family, rd).unwrap()),
                        src_prefix: Some(sources[index].into()),
                        protocol: Some(17),
                        ..Default::default()
                    },
                    if index == 0 {
                        FlowSpecAction::discard()
                    } else {
                        FlowSpecAction::police(8_000_000)
                    },
                )
                .with_route_targets(vec![rt.into()]),
            ));
        }
    }
    loop {
        let expected: Vec<_> = created.iter().map(|(_, rule)| rule.clone()).collect();
        assert!(peer_receipt::exact_wire_inventory(
            &speaker.list_active().await.unwrap(),
            &expected
        ));
        peer_receipt::wait_go_scoped_received(&pair.go, &expected).await;
        let global: Vec<_> = expected
            .iter()
            .filter(|rule| rule.nlri.scope.is_none())
            .cloned()
            .collect();
        peer_receipt::wait_go_scoped_received(global_peer, &global).await;
        if created.is_empty() {
            break;
        }
        // Withdraw each scoped identity independently; retain the global control
        // until last so a cross-scope delete cannot masquerade as success.
        let (id, _) = created.remove(if created.len() > 1 { 1 } else { 0 });
        post(
            &app,
            &format!("/v1/mitigations/{id}/withdraw"),
            json!({"reason":"VPN receipt cleanup"}),
            StatusCode::OK,
        )
        .await;
    }
    pair.remove().await;
}

/// All five actions cross the HTTP/controller/guarded boundary before the peer
/// oracle reads serialized attributes. This qualifies neither VRF installation
/// nor the action's effect on traffic.
#[tokio::test]
#[ignore = "requires isolated pinned speakers and PostgreSQL; use rustbgpd 0.82.0"]
async fn released_vpn_five_actions_use_authenticated_admission_and_exact_peer_bytes() {
    use argon2::PasswordHasher;
    use axum::{
        Router,
        body::Body,
        http::{HeaderMap, Request, StatusCode},
        response::IntoResponse,
        routing::get,
    };
    use peer_receipt::{BinaryWireRule, wait_go_binary_received};
    use prefixd::{
        AppState,
        api::create_test_router,
        bgp::{FlowSpecReader, GuardedFlowSpecSpeaker, PeerObserver},
        config::{AuthMode, BgpMode, Customer, Inventory, OperationMode, Playbooks, PolicyProfile},
        domain::{OperatorRole, SpeakerTarget, VpnFlowSpecFamily, VpnFlowSpecIdentity},
        fence::{ControllerFence, FencedAnnouncer},
        scrubber::ScrubberController,
    };
    use serde_json::{Value, json};
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering::SeqCst},
        },
        time::Duration,
    };
    use tower::ServiceExt;

    let version = std::env::var("PREFIXD_RUSTBGPD_TEST_VERSION").unwrap_or("0.81.0".into());
    if version == "0.81.0" {
        let fixture = rustbgpd::Speaker::start().await;
        let speaker = fixture.connect().await;
        let global = FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: "203.0.113.20/32".into(),
                ..Default::default()
            },
            FlowSpecAction::discard(),
        );
        speaker.announce(&global).await.unwrap();
        let before = fixture.received_flow_spec(3, "0.0.0.0").await;
        assert_eq!(before.received_routes.len(), 1);
        for family in [VpnFlowSpecFamily::Ipv4, VpnFlowSpecFamily::Ipv6] {
            let scope = VpnFlowSpecIdentity::new(family, "44407:40").unwrap();
            assert!(matches!(speaker.validate_scope(Some(&scope)).await,
                Err(prefixd::error::PrefixdError::UnsupportedFlowSpecScope { family: refused, .. })
                if refused == family.afi_safi()));
            assert_eq!(fixture.received_flow_spec(3, "0.0.0.0").await, before);
        }
        speaker.withdraw(&global).await.unwrap();
        assert!(
            fixture
                .received_flow_spec(3, "0.0.0.0")
                .await
                .received_routes
                .is_empty()
        );
        fixture.container.rm().await.unwrap();
        eprintln!(
            "rustbgpd 0.81.0 negative control PASS: both VPN families refused with typed capability errors; seeded global rule unchanged"
        );
        return;
    }
    assert_eq!(
        version, "0.82.0",
        "all-five positive receipt requires released 0.82.0"
    );
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let database = common::TestContext::new().await;
    let pair = peer_receipt::Pair::start_vpn().await;
    let speaker = Arc::new(pair.rust.connect().await);
    let global_peer = pair.global_only.as_ref().unwrap();
    for peer in [&pair.go, global_peer] {
        contract::wait_peer_state(&peer.connect().await, &peer.peer_address, true)
            .await
            .unwrap();
    }
    let expected_peers = [
        pair.rust.peer_address.clone(),
        global_peer
            .container
            .get_bridge_ip_address()
            .await
            .unwrap()
            .to_string(),
    ];
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let peers = speaker.session_status().await.unwrap();
            if peers.len() == 2
                && expected_peers.iter().all(|address| {
                    peers
                        .iter()
                        .any(|peer| &peer.address == address && peer.state.is_established())
                })
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("both isolated peers Established");

    let accepted_monitor_reads = Arc::new(AtomicUsize::new(0));
    let count = accepted_monitor_reads.clone();
    let expected_token = std::env::var("PREFIXD_RUSTBGPD_TEST_TOKEN").unwrap();
    let monitor = Router::new().route(
        "/{profile}",
        get(
            move |axum::extract::Path(profile): axum::extract::Path<String>, headers: HeaderMap| {
                let token = expected_token.clone();
                let count = count.clone();
                async move {
                    let authorization = format!("Bearer {token}");
                    if headers
                        .get("authorization")
                        .and_then(|header| header.to_str().ok())
                        != Some(authorization.as_str())
                    {
                        return StatusCode::UNAUTHORIZED.into_response();
                    }
                    count.fetch_add(1, SeqCst);
                    axum::Json(json!({
                        "profile": profile,
                        "revision": "v1",
                        "policy_binding": "action-fixture",
                        "observed_at": chrono::Utc::now(),
                        "valid_until": chrono::Utc::now() + chrono::Duration::seconds(8),
                        "process_ready": true,
                        "filters_ready": true,
                        "target_reachable": true,
                        "capacity_available": true,
                        "canary_passed": true,
                        "export_isolated": true,
                    }))
                    .into_response()
                }
            },
        ),
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        include_bytes!("../src/bgp/testdata/transport-server-cert.pem").to_vec(),
        include_bytes!("../src/bgp/testdata/transport-server-key.pem").to_vec(),
    )
    .await
    .unwrap();
    let handle = axum_server::Handle::new();
    let monitor_task = tokio::spawn(
        axum_server::from_tcp_rustls(listener, tls)
            .unwrap()
            .handle(handle.clone())
            .serve(monitor.into_make_service()),
    );
    let monitor_client = reqwest::Client::builder()
        .https_only(true)
        .add_root_certificate(
            reqwest::Certificate::from_pem(include_bytes!("../src/bgp/testdata/transport-ca.pem"))
                .unwrap(),
        )
        .build()
        .unwrap();
    assert_eq!(
        monitor_client
            .get(format!("https://{address}/ip4"))
            .bearer_auth("wrong-token")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let mut settings = database.state.settings.clone();
    settings.mode = OperationMode::Enforced;
    settings.http.auth.mode = AuthMode::Credentials;
    settings.bgp.mode = BgpMode::Rustbgpd;
    settings.bgp.rustbgpd = Some(pair.rust.config.clone());
    settings.guardrails.allow_src_prefix_match = true;
    settings.bgp.vpn_scopes = serde_json::from_value(json!({
        "TRANSIT":{"family":"ipv4","rd":"44407:40","route_targets":["44407:777"]},
        "TRANSIT6":{"family":"ipv6","rd":"44407:41","route_targets":["44407:778"]}
    }))
    .unwrap();
    let profiles = [
        ("ip4", "TRANSIT", Some("192.0.2.99"), None, None),
        ("ip6", "TRANSIT6", None, Some("2001:db8:ffff::66"), None),
        ("rt4", "TRANSIT", None, None, Some("44407:888")),
        ("rt6", "TRANSIT6", None, None, Some("44407:888")),
    ];
    let profile_json:Vec<_>=profiles.into_iter().map(|(id,scope,ipv4,ipv6,rt)|json!({
        "id":id,"revision":"v1","scope":scope,"ipv4_target":ipv4,"ipv6_target":ipv6,
        "redirect_route_target":rt,"destinations":["203.0.113.0/24","2001:db8:100::/48"],
        "router_peers":[pair.rust.peer_address],"policy_binding":"action-fixture",
        "qualification_receipt":"owned HTTP/speaker/peer fixture; traffic enforcement unqualified",
        "readiness_url":format!("https://{address}/{id}"),"readiness_token_env":"PREFIXD_RUSTBGPD_TEST_TOKEN",
        "max_ttl_seconds":300,"max_active":10,"max_new_per_minute":20,"reserved_targets":[]
    })).collect();
    settings.scrubber=serde_json::from_value(json!({"enabled":true,"profiles":profile_json,
        "readiness_ca_cert":std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bgp/testdata/transport-ca.pem")})).unwrap();
    let binding = database
        .repo
        .register_speaker_target(
            &settings.pop,
            &SpeakerTarget::from_config(&settings.bgp).unwrap(),
            false,
        )
        .await
        .unwrap();
    let fence = Arc::new(ControllerFence::new(true));
    let announcer = Arc::new(FencedAnnouncer::new(speaker.clone(), fence.clone()));
    let inventory = Inventory::new(vec![Customer {
        customer_id: "action-pilot".into(),
        name: "Action pilot".into(),
        prefixes: vec!["203.0.113.0/24".into(), "2001:db8:100::/48".into()],
        policy_profile: PolicyProfile::Normal,
        services: vec![],
    }]);
    let state = AppState::with_pool(
        settings,
        inventory,
        Playbooks { playbooks: vec![] },
        database.repo.clone(),
        announcer,
        ".".into(),
        Some(database.pool.clone()),
    )
    .unwrap()
    .with_speaker_binding(binding)
    .unwrap()
    .with_fence(fence)
    .unwrap();
    ScrubberController::check_startup(&state).await.unwrap();
    let hash = argon2::Argon2::default()
        .hash_password_with_salt(b"vpn-action-fixture-password", b"vpn-action-fixture")
        .unwrap()
        .to_string();
    database
        .repo
        .create_operator("action-admin", &hash, OperatorRole::Admin, None)
        .await
        .unwrap();
    let app = create_test_router(state.clone());
    async fn request(
        app: &Router,
        method: &str,
        path: &str,
        body: Value,
        cookie: Option<&str>,
        status: StatusCode,
    ) -> (Value, Option<String>) {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if let Some(cookie) = cookie {
            request = request.header("cookie", cookie);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let actual = response.status();
        let cookie = response.headers().get("set-cookie").map(|header| {
            header
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned()
        });
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"raw":String::from_utf8_lossy(&bytes)}));
        assert_eq!(actual, status, "{method} {path}: {value}");
        (value, cookie)
    }
    request(
        &app,
        "POST",
        "/v1/scrubbers/ip4/arm",
        json!({"revision":"v1"}),
        None,
        StatusCode::UNAUTHORIZED,
    )
    .await;
    let (_, cookie) = request(
        &app,
        "POST",
        "/v1/auth/login",
        json!({"username":"action-admin","password":"vpn-action-fixture-password"}),
        None,
        StatusCode::OK,
    )
    .await;
    let cookie = cookie.unwrap();
    state.scrubber.tick(&state).await.unwrap();
    let scrubber_task = tokio::spawn({
        let state = state.clone();
        async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                tokio::time::timeout(Duration::from_secs(4), state.scrubber.tick(&state))
                    .await
                    .expect("fixture scrubber pass stays within the production pass budget")
                    .expect("fixture scrubber lifecycle pass succeeds");
            }
        }
    });
    for (id, _, _, _, _) in profiles {
        let (before, _) = request(
            &app,
            "GET",
            "/v1/scrubbers",
            Value::Null,
            Some(&cookie),
            StatusCode::OK,
        )
        .await;
        assert_eq!(before["profiles"][id]["armed"], false);
        request(
            &app,
            "POST",
            &format!("/v1/scrubbers/{id}/arm"),
            json!({"revision":"v1"}),
            Some(&cookie),
            StatusCode::OK,
        )
        .await;
    }
    assert!(accepted_monitor_reads.load(SeqCst) >= profiles.len());

    let mut expected = vec![];
    let mut ordinary = vec![];
    let mut diversions = vec![];
    let global_match = FlowSpecNlri {
        dst_prefix: "203.0.113.20/32".into(),
        src_prefix: Some("198.51.100.0/24".into()),
        protocol: Some(6),
        dst_ports: vec![443],
        ..Default::default()
    };
    let (global,_)=request(&app,"POST","/v1/mitigations",json!({"victim_ip":"203.0.113.20","src_prefix":"198.51.100.0/24",
        "protocol":"tcp","dst_ports":[443],"action":"discard","ttl_seconds":180,"reason":"global action control"}),Some(&cookie),StatusCode::CREATED).await;
    let global_id = global["mitigation_id"].as_str().unwrap().to_owned();
    expected.push(BinaryWireRule {
        nlri: global_match,
        extended_communities: vec![0x8006_0000_0000_0000],
        ipv6_extended_communities: vec![],
    });
    for (scope, family, rd, rt, raw_rt, destinations, source, ip_profile, rt_profile) in [
        (
            "TRANSIT",
            VpnFlowSpecFamily::Ipv4,
            "44407:40",
            "44407:777",
            0x0002_ad77_0000_0309u64,
            [
                "203.0.113.20",
                "203.0.113.21",
                "203.0.113.22",
                "203.0.113.23",
                "203.0.113.24",
            ],
            "198.51.100.0/24",
            "ip4",
            "rt4",
        ),
        (
            "TRANSIT6",
            VpnFlowSpecFamily::Ipv6,
            "44407:41",
            "44407:778",
            0x0002_ad77_0000_030au64,
            [
                "2001:db8:100::20",
                "2001:db8:100::21",
                "2001:db8:100::22",
                "2001:db8:100::23",
                "2001:db8:100::24",
            ],
            "2001:db9::/64",
            "ip6",
            "rt6",
        ),
    ] {
        for (index, action) in ["discard", "police", "mark", "redirect_ip", "redirect_vrf"]
            .into_iter()
            .enumerate()
        {
            let nlri = FlowSpecNlri {
                scope: Some(VpnFlowSpecIdentity::new(family, rd).unwrap()),
                dst_prefix: format!(
                    "{}/{}",
                    destinations[index],
                    if family == VpnFlowSpecFamily::Ipv4 {
                        32
                    } else {
                        128
                    }
                ),
                src_prefix: Some(source.into()),
                protocol: Some(6),
                dst_ports: vec![443],
                ..Default::default()
            };
            let mut communities = vec![raw_rt];
            let mut ipv6_communities = vec![];
            if index < 3 {
                let (created,_)=request(&app,"POST","/v1/vpn/mitigations",json!({"scope":scope,"rule":{
                    "victim_ip":destinations[index],"src_prefix":source,"protocol":"tcp","dst_ports":[443],"action":action,
                    "rate_bps":if index==1 {Some(8_000_000u64)} else {None},"dscp":if index==2 {Some(46u8)} else {None},
                    "ttl_seconds":180,"reason":"all-action VPN HTTP wire receipt"}}),Some(&cookie),StatusCode::CREATED).await;
                assert_eq!(created["vpn_scope"]["identity"]["rd"], rd);
                assert_eq!(created["vpn_scope"]["route_targets"], json!([rt]));
                if index == 2 {
                    assert_eq!(created["dscp"], 46);
                }
                ordinary.push((
                    created["mitigation_id"].as_str().unwrap().to_owned(),
                    nlri.clone(),
                ));
                communities.push(match index {
                    0 => 0x8006_0000_0000_0000,
                    1 => 0x8006_0000_0000_0000 | u64::from(1_000_000f32.to_bits()),
                    _ => 0x8009_0000_0000_002e,
                });
            } else {
                let profile = if index == 3 { ip_profile } else { rt_profile };
                let mut body = json!({"scope":scope,"diversion":{"profile":profile,"scope":{
                    "dst_prefix":nlri.dst_prefix,"src_prefix":source,"protocol":6,"dst_ports":[443]},
                    "ttl_seconds":180,"reason":"guarded all-action HTTP wire receipt","confirmation":null}});
                let before = speaker.guarded_inventory().await.unwrap().len();
                let (preview, _) = request(
                    &app,
                    "POST",
                    "/v1/vpn/diversions/preview",
                    body.clone(),
                    Some(&cookie),
                    StatusCode::OK,
                )
                .await;
                assert_eq!(
                    speaker.guarded_inventory().await.unwrap().len(),
                    before,
                    "preview cannot mutate guarded inventory"
                );
                body["diversion"]["confirmation"] = preview["confirmation"].clone();
                let (created, _) = request(
                    &app,
                    "POST",
                    "/v1/vpn/diversions",
                    body,
                    Some(&cookie),
                    StatusCode::ACCEPTED,
                )
                .await;
                assert_eq!(created["status"], "active", "{created}");
                assert_eq!(created["profile"]["scope"], scope);
                assert_eq!(created["rule"]["nlri"]["scope"]["rd"], rd);
                assert_eq!(created["rule"]["route_targets"], json!([rt]));
                assert!(
                    created["windows"]
                        .as_array()
                        .is_some_and(|windows| !windows.is_empty())
                );
                let id = created["id"].as_str().unwrap().to_owned();
                let (saved, _) = request(
                    &app,
                    "GET",
                    &format!("/v1/diversions/{id}"),
                    Value::Null,
                    Some(&cookie),
                    StatusCode::OK,
                )
                .await;
                assert_eq!(
                    saved["rule"], created["rule"],
                    "persisted admission payload is frozen"
                );
                if index == 4 {
                    assert_eq!(saved["rule"]["redirect_route_target"], "44407:888");
                    communities.push(0x8008_ad77_0000_0378);
                } else if family == VpnFlowSpecFamily::Ipv4 {
                    communities.push(0x010c_c000_0263_0000);
                } else {
                    let mut redirect = [0; 20];
                    redirect[1] = 0x0c;
                    redirect[2..18].copy_from_slice(
                        &"2001:db8:ffff::66"
                            .parse::<std::net::Ipv6Addr>()
                            .unwrap()
                            .octets(),
                    );
                    ipv6_communities.push(redirect);
                }
                diversions.push((id, nlri.clone(), saved["rule"].clone(), profile.to_owned()));
            }
            expected.push(BinaryWireRule {
                nlri,
                extended_communities: communities,
                ipv6_extended_communities: ipv6_communities,
            });
        }
    }
    assert_eq!(speaker.list_active().await.unwrap().len(), 7);
    assert_eq!(speaker.guarded_inventory().await.unwrap().len(), 4);
    // Exceed the monitor's eight-second TTL while peer observation does no lifecycle work.
    let reads_before_pause = accepted_monitor_reads.load(SeqCst);
    tokio::time::sleep(Duration::from_secs(9)).await;
    assert!(
        !scrubber_task.is_finished(),
        "periodic scrubber worker must remain live"
    );
    assert!(accepted_monitor_reads.load(SeqCst) >= reads_before_pause + profiles.len());
    let healthy = state.scrubber.profiles().await;
    for (id, _, _, _, _) in profiles {
        let profile = &healthy[id];
        assert!(
            profile.armed && profile.ready,
            "{id} must remain armed and ready after nine seconds"
        );
        assert_eq!(profile.readiness, prefixd::scrubber::ReadinessState::Ready);
        assert!(
            profile.latch_reason.is_none(),
            "{id}: {:?}",
            profile.latch_reason
        );
    }
    let active = database
        .repo
        .list_diversions(&state.settings.pop)
        .await
        .unwrap();
    assert_eq!(active.len(), 4);
    for (id, _, frozen, _) in &diversions {
        let saved = active.iter().find(|row| row.id.to_string() == *id).unwrap();
        assert_eq!(saved.status, prefixd::scrubber::DiversionStatus::Active);
        assert_eq!(serde_json::to_value(&saved.rule).unwrap(), *frozen);
    }
    assert_eq!(
        speaker.guarded_inventory().await.unwrap().len(),
        4,
        "periodic readiness renewal must retain all four original guarded rules"
    );
    eprintln!(
        "nine-second readiness survival control PASS: eight-second reports refreshed, all four profiles armed/ready and original guarded intents active"
    );
    // Independent local RPC evidence includes every raw action and scope RT.
    let mut local_count = 0;
    for family in [3, 4, 13, 14] {
        let view = pair.rust.received_flow_spec(family, "0.0.0.0").await;
        for row in view.received_routes {
            let route = row.route.unwrap();
            local_count += 1;
            let wanted: Vec<_> = expected
                .iter()
                .filter(|wanted| {
                    let rd = wanted.nlri.scope.as_ref().map_or("", |scope| scope.rd());
                    let afi = wanted
                        .nlri
                        .scope
                        .as_ref()
                        .map_or(3, |scope| scope.family.afi_safi());
                    afi == family
                        && rd == route.rd
                        && route.components.iter().any(|component| {
                            component.r#type == 1 && component.prefix == wanted.nlri.dst_prefix
                        })
                })
                .collect();
            assert_eq!(wanted.len(), 1, "unmatched local scoped payload {route:?}");
            let wanted = wanted[0];
            assert_eq!(
                route
                    .components
                    .iter()
                    .map(|component| component.r#type)
                    .collect::<Vec<_>>(),
                [1, 2, 3, 5]
            );
            assert_eq!(
                route.components[1].prefix,
                wanted.nlri.src_prefix.as_deref().unwrap()
            );
            assert_eq!(route.components[2].value.trim_start_matches('='), "6");
            assert_eq!(route.components[3].value.trim_start_matches('='), "443");
            let mut raw = route.extended_communities;
            raw.sort_unstable();
            let mut wanted_raw = wanted.extended_communities.clone();
            wanted_raw.sort_unstable();
            assert_eq!(raw, wanted_raw);
            assert_eq!(
                route.ipv6_extended_communities,
                wanted
                    .ipv6_extended_communities
                    .iter()
                    .map(|value| value.to_vec())
                    .collect::<Vec<_>>()
            );
        }
    }
    assert_eq!(local_count, expected.len());
    wait_go_binary_received(&pair.go, &expected).await;
    wait_go_binary_received(pair.global_only.as_ref().unwrap(), &expected[..1]).await;

    for (id, nlri, frozen, profile) in &diversions {
        tokio::time::timeout(Duration::from_secs(10), async {
        state.scrubber.tick(&state).await.unwrap();
        let held = speaker.guarded_inventory().await.unwrap();
        assert!(
            held.iter().any(
                |entry| entry.rule.nlri.compute_hash() == nlri.compute_hash()
                    && entry.remaining_ms > 11_000
            ),
            "withdrawal receipt must begin with a held rule whose lease outlives the 10-second peer deadline"
        );
        let (withdrawing, _) = request(
            &app,
            "POST",
            &format!("/v1/diversions/{id}/withdraw"),
            json!({"reason":"independent guarded action withdrawal"}),
            Some(&cookie),
            StatusCode::ACCEPTED,
        )
        .await;
        assert_eq!(withdrawing["status"], "withdrawing");
        assert_eq!(
            withdrawing["rule"], *frozen,
            "withdrawal preserves its original action and scope"
        );
        let index = expected
            .iter()
            .position(|wanted| {
                serde_json::to_value(&wanted.nlri).unwrap() == serde_json::to_value(nlri).unwrap()
            })
            .unwrap();
        expected.remove(index);
        wait_go_binary_received(&pair.go, &expected).await;
        wait_go_binary_received(pair.global_only.as_ref().unwrap(), &expected[..1]).await;
        let (profiles, _) = request(
            &app,
            "GET",
            "/v1/scrubbers",
            Value::Null,
            Some(&cookie),
            StatusCode::OK,
        )
        .await;
        assert_eq!(
            profiles["profiles"][profile.as_str()]["armed"],
            true,
            "successful manual withdrawal preserves healthy profile arming"
        );
        })
        .await
        .expect("held-rule read, withdrawal and peer absence share one 10-second budget");
    }
    tokio::time::timeout(
        Duration::from_secs(u64::from(prefixd::scrubber::WINDOW_SECONDS) + 10),
        async {
            loop {
                let rows = database
                    .repo
                    .list_diversions(&state.settings.pop)
                    .await
                    .unwrap();
                if rows
                    .iter()
                    .all(|row| row.status == prefixd::scrubber::DiversionStatus::Withdrawn)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        },
    )
    .await
    .expect("guarded withdrawal windows drained with exact local absence");
    assert!(speaker.guarded_inventory().await.unwrap().is_empty());
    for (id, _, frozen, _) in &diversions {
        let (closed, _) = request(
            &app,
            "GET",
            &format!("/v1/diversions/{id}"),
            Value::Null,
            Some(&cookie),
            StatusCode::OK,
        )
        .await;
        assert_eq!(closed["status"], "withdrawn");
        assert_eq!(closed["rule"], *frozen);
    }
    for (id, nlri) in ordinary {
        request(
            &app,
            "POST",
            &format!("/v1/mitigations/{id}/withdraw"),
            json!({"reason":"independent ordinary action withdrawal"}),
            Some(&cookie),
            StatusCode::OK,
        )
        .await;
        let index = expected
            .iter()
            .position(|wanted| {
                serde_json::to_value(&wanted.nlri).unwrap() == serde_json::to_value(&nlri).unwrap()
            })
            .unwrap();
        expected.remove(index);
        wait_go_binary_received(&pair.go, &expected).await;
    }
    request(
        &app,
        "POST",
        &format!("/v1/mitigations/{global_id}/withdraw"),
        json!({"reason":"last global control withdrawal"}),
        Some(&cookie),
        StatusCode::OK,
    )
    .await;
    wait_go_binary_received(&pair.go, &[]).await;
    wait_go_binary_received(pair.global_only.as_ref().unwrap(), &[]).await;
    assert!(speaker.list_active().await.unwrap().is_empty());
    eprintln!(
        "all-five VPN action receipt: both families, authenticated HTTP and HTTPS readiness, frozen guarded payloads, exact local/peer bytes, independent withdrawals and global-only peer control PASS; traffic enforcement unqualified"
    );
    scrubber_task.abort();
    assert!(
        scrubber_task.await.unwrap_err().is_cancelled(),
        "owned scrubber worker must be aborted and awaited before monitor teardown"
    );
    handle.graceful_shutdown(Some(Duration::from_secs(2)));
    monitor_task.await.unwrap().unwrap();
    pair.remove().await;
}

/// RFC 1997 standard communities from GoBGP's serialized path attributes.
fn standard_communities(attributes: &[Vec<u8>]) -> Vec<u32> {
    attributes
        .iter()
        .filter(|attribute| attribute.len() >= 3 && attribute[1] == 8)
        .flat_map(|attribute| {
            let header = if attribute[0] & 0x10 == 0 { 3 } else { 4 };
            attribute[header..]
                .as_chunks::<4>()
                .0
                .iter()
                .map(|bytes| u32::from_be_bytes(*bytes))
                .collect::<Vec<_>>()
        })
        .collect()
}

/// ADR 030 R9 speaker gate on a released daemon: the return leg's exact
/// guarded add, read-back and revision-fenced delete, and peer receipt in
/// which a community-matching export policy sends it only to router B.
#[tokio::test]
#[ignore = "requires isolated pinned Docker speakers; run scripts/test-rustbgpd.sh"]
async fn released_return_leg_reaches_only_its_peers_with_exact_bytes() {
    use prefixd::bgp::{FlowSpecReader, GuardedFlowSpecSpeaker, GuardedRule};
    use prefixd::scrubber::{ReturnLeg, ReturnTcpFlags, derive_return};
    use std::time::Duration;
    const COMMUNITY: u32 = (64496 << 16) | 100;
    let version = std::env::var("PREFIXD_RUSTBGPD_TEST_VERSION").unwrap_or("0.81.0".into());
    let pair = peer_receipt::Pair::start_return_leg("64496:100").await;
    let speaker = pair.rust.connect().await;
    let router_a = &pair.go;
    let router_b = pair.global_only.as_ref().unwrap();
    let router_b_address = router_b
        .container
        .get_bridge_ip_address()
        .await
        .unwrap()
        .to_string();
    let leg = ReturnLeg {
        router_peers: vec![router_b_address.clone()],
        policy_binding: "client-side-only-v1".into(),
        export_community: "64496:100".into(),
        tcp_flags: Some(ReturnTcpFlags::SynAck),
    };
    let owner = "prefixd.scrub.returnfixture";
    for (afi, family, victim, target, revision) in [
        (1, 3, "203.0.113.20/32", "192.0.2.99", 10),
        (2, 4, "2001:db8:100::20/128", "2001:db8::99", 20),
    ] {
        let inbound = GuardedRule {
            nlri: FlowSpecNlri {
                dst_prefix: victim.into(),
                protocol: Some(6),
                dst_ports: vec![443],
                ..Default::default()
            },
            route_targets: vec![],
            target: Some(target.parse().unwrap()),
            redirect_route_target: None,
            owner: owner.into(),
            revision,
            export_community: None,
        };
        let ret = derive_return(&inbound, Some(&leg)).unwrap().unwrap();
        let window = speaker.issue_window(owner, 30).await.unwrap();
        let generation = speaker.add_guarded(&ret, window.stamp, 30).await.unwrap();
        assert_eq!(
            speaker
                .add_guarded(&inbound, window.stamp, 30)
                .await
                .unwrap(),
            generation,
            "both legs share the owner generation"
        );
        // Local intent: exact components and the one standard community.
        let local = pair.rust.received_flow_spec(family, "0.0.0.0").await;
        let held: Vec<_> = local
            .received_routes
            .iter()
            .filter_map(|row| row.route.as_ref())
            .filter(|route| !route.communities.is_empty())
            .collect();
        assert_eq!(held.len(), 1);
        let components: Vec<_> = held[0]
            .components
            .iter()
            .map(|c| (c.r#type, c.prefix.as_str(), c.value.as_str()))
            .collect();
        eprintln!("return-leg local components {family}: {components:?}");
        assert_eq!(
            components.iter().map(|c| c.0).collect::<Vec<_>>(),
            [2, 3, 6, 9],
            "no destination component"
        );
        assert_eq!(components[0].1, victim);
        assert_eq!(held[0].communities, [COMMUNITY]);
        let inventory = speaker.guarded_inventory().await.unwrap();
        for expected in [&inbound, &ret] {
            assert!(
                inventory
                    .iter()
                    .any(|entry| entry.rule.same_admission(expected)
                        && entry.generation == generation
                        && entry.remaining_ms > 0)
            );
        }
        assert!(
            speaker.list_active().await.unwrap().is_empty(),
            "guarded rows, including the return leg, are not ordinary intent"
        );

        // Peer receipt: router B holds only the return leg, with the exact
        // NLRI and community bytes; router A holds only the inbound leg.
        let source: ipnet::IpNet = victim.parse().unwrap();
        let mut body = vec![2, source.prefix_len()];
        if afi == 2 {
            body.push(0);
        }
        body.extend(match source.addr() {
            std::net::IpAddr::V4(address) => address.octets().to_vec(),
            std::net::IpAddr::V6(address) => address.octets().to_vec(),
        });
        body.extend([3, 0x81, 6, 6, 0x91, 0x01, 0xbb, 9, 0x81, 0x12]);
        let mut expected_nlri = vec![u8::try_from(body.len()).unwrap()];
        expected_nlri.extend(&body);
        let receipt = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let b = router_b
                    .paths_with_binary_attributes(afi, 133, prefixd::bgp::apipb::TableType::AdjIn)
                    .await;
                let a = router_a
                    .paths_with_binary_attributes(afi, 133, prefixd::bgp::apipb::TableType::AdjIn)
                    .await;
                if b.len() == 1 && a.len() == 1 {
                    break (a, b);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("router A and router B each receive one rule");
        let (a, b) = receipt;
        eprintln!(
            "return-leg peer receipt {family}: B nlri={:02x?} communities={:?}; A communities={:?}",
            b[0].nlri_binary,
            standard_communities(&b[0].pattrs_binary),
            standard_communities(&a[0].pattrs_binary)
        );
        assert_eq!(b[0].nlri_binary, expected_nlri, "exact return-leg NLRI");
        assert_eq!(standard_communities(&b[0].pattrs_binary), [COMMUNITY]);
        assert!(
            standard_communities(&a[0].pattrs_binary).is_empty(),
            "inbound bytes carry no community"
        );
        assert_ne!(a[0].nlri_binary, b[0].nlri_binary);
        // Export evidence at each key matches the receipt.
        let exports = speaker.flowspec_exports(&ret.nlri).await.unwrap().unwrap();
        eprintln!("return-leg export dispositions {family}: {exports:?}");
        for peer in &exports {
            let committed = peer.disposition == ExportDisposition::Committed;
            assert_eq!(committed, peer.peer_address == router_b_address, "{peer:?}");
        }

        // Revision-fenced delete: another revision cannot remove either leg.
        for rule in [&ret, &inbound] {
            let mut stale = rule.clone();
            stale.revision += 1;
            assert!(speaker.delete_guarded(&stale).await.is_err());
        }
        speaker.delete_guarded(&ret).await.unwrap();
        speaker.delete_guarded(&ret).await.unwrap();
        let mut replacement = ret.clone();
        replacement.revision += 1;
        speaker
            .add_guarded(&replacement, window.stamp, 30)
            .await
            .unwrap();
        assert!(
            speaker.delete_guarded(&ret).await.is_err(),
            "a late delete cannot remove a newer admission at the return key"
        );
        speaker.delete_guarded(&replacement).await.unwrap();
        speaker.delete_guarded(&inbound).await.unwrap();
        assert!(speaker.guarded_inventory().await.unwrap().is_empty());
        tokio::time::timeout(Duration::from_secs(15), async {
            while !router_b
                .paths(afi, prefixd::bgp::apipb::TableType::AdjIn)
                .await
                .is_empty()
                || !router_a
                    .paths(afi, prefixd::bgp::apipb::TableType::AdjIn)
                    .await
                    .is_empty()
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("both routers lose both legs");
    }
    eprintln!(
        "rustbgpd {version} return-leg speaker gate PASS: guarded add/read-back, exact NLRI and community bytes, revision-fenced delete and community-scoped export to router B only; forwarding unqualified"
    );
    pair.remove().await;
}
