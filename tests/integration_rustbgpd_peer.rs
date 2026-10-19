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
    bgp::FlowSpecWriter,
    domain::{FlowSpecAction, FlowSpecNlri, FlowSpecRule},
};

fn rules() -> Vec<FlowSpecRule> {
    [
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
    .collect()
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
                    protocol: rule.nlri.protocol,
                    dst_ports: rule.nlri.dst_ports.clone(),
                    ..Default::default()
                },
                action_type: action.action_type,
                action_params: ActionParams {
                    rate_bps: action.rate_bps,
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
