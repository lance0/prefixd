//! Qualification against an owned, immutable GoBGP 4.10.0 fixture on Linux.
//! Run `scripts/test-gobgp.sh`; no ambient speaker endpoint is accepted.
#![cfg(target_os = "linux")]
#[path = "common/speaker_contract.rs"]
mod contract;
#[path = "common/gobgp.rs"]
mod fixture;

use prefixd::bgp::{FlowSpecReader, FlowSpecWriter, GoBgpAnnouncer};
use prefixd::domain::{FlowSpecAction, FlowSpecNlri, FlowSpecRule};
use std::time::Duration;

/// Test: Announce a rule, verify it appears in list_active()
#[tokio::test]
#[ignore = "requires Docker on Linux; run scripts/test-gobgp.sh"]
async fn test_announce_and_list_active() {
    let fixture = fixture::Speaker::start().await;
    // Readiness is repeatable even if the first StartBgp acknowledgement was lost.
    fixture.configure().await;
    let announcer = fixture.connect().await;
    contract::run_readable_contract(&announcer).await.unwrap();
}

#[tokio::test]
#[ignore = "requires Docker on Linux; run scripts/test-gobgp.sh"]
async fn faithful_policing_and_historical_action_withdrawal() {
    let fixture = fixture::Speaker::start().await;
    let speaker = fixture.connect().await;
    contract::run_action_contract(&speaker).await.unwrap();
    for afi in [1, 2] {
        assert!(
            fixture
                .paths(afi, prefixd::bgp::apipb::TableType::Global)
                .await
                .is_empty()
        );
    }
}

#[tokio::test]
#[ignore = "requires Docker on Linux; run scripts/test-gobgp.sh"]
async fn action_drift_reconciles_exactly_once() {
    let fixture = fixture::Speaker::start().await;
    let speaker = std::sync::Arc::new(fixture.connect().await);
    let config = prefixd::config::BgpConfig {
        mode: prefixd::config::BgpMode::Gobgp,
        gobgp_grpc: fixture.endpoint.clone(),
        local_asn: 65010,
        router_id: "192.0.2.10".into(),
        rustbgpd: None,
        neighbors: vec![],
    };
    contract::run_action_reconciliation_contract(speaker, &config)
        .await
        .unwrap();
    for afi in [1, 2] {
        assert!(
            fixture
                .paths(afi, prefixd::bgp::apipb::TableType::Global)
                .await
                .is_empty()
        );
    }
}

#[tokio::test]
#[ignore = "requires Docker on Linux; run scripts/test-gobgp.sh"]
async fn action_reconciliation_rejects_port_order_alias_without_mutation() {
    use prefixd::{
        db::{MockRepository, RepositoryTrait},
        domain::{
            ActionParams, ActionType, AttackVector, MatchCriteria, Mitigation, MitigationIntent,
            SpeakerTarget, mitigation_rule,
        },
        observability::metrics,
        scheduler::ReconciliationLoop,
    };
    let fixture = fixture::Speaker::start().await;
    let speaker = std::sync::Arc::new(fixture.connect().await);
    let config = prefixd::config::BgpConfig {
        mode: prefixd::config::BgpMode::Gobgp,
        gobgp_grpc: fixture.endpoint.clone(),
        local_asn: 65010,
        router_id: "192.0.2.10".into(),
        rustbgpd: None,
        neighbors: vec![],
    };
    for observed_action in [FlowSpecAction::discard(), FlowSpecAction::police(7)] {
        let repo = std::sync::Arc::new(MockRepository::new());
        let pop = "port-order-contract";
        let binding = repo
            .register_speaker_target(pop, &SpeakerTarget::from_config(&config).unwrap(), false)
            .await
            .unwrap();
        let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false)
            .with_speaker_binding(binding);
        let mut expected = Vec::new();
        for prefix in ["192.0.2.247/32", "2001:db8::247/128"] {
            let mut owner = Mitigation::from_intent(
                MitigationIntent {
                    event_id: uuid::Uuid::new_v4(),
                    customer_id: None,
                    service_id: None,
                    pop: pop.into(),
                    match_criteria: MatchCriteria {
                        dst_prefix: prefix.into(),
                        protocol: Some(17),
                        dst_ports: vec![443, 53],
                    },
                    action_type: ActionType::Discard,
                    action_params: ActionParams { rate_bps: None },
                    ttl_seconds: 300,
                    reason: "port order alias qualification".into(),
                },
                prefix.split('/').next().unwrap().into(),
                AttackVector::UdpFlood,
            );
            owner.activate();
            repo.insert_mitigation(&owner).await.unwrap();
            let desired = mitigation_rule(&owner).unwrap();
            let mut alias = desired.clone();
            alias.nlri.dst_ports.reverse();
            alias.actions = vec![observed_action.clone()];
            assert_eq!(desired.nlri_hash(), alias.nlri_hash());
            assert!(!speaker.matches_nlri(&desired.nlri, &alias.nlri).unwrap());
            speaker.announce(&alias).await.unwrap();
            let mut unknown = desired;
            unknown.nlri.dst_ports = vec![54];
            unknown.actions = vec![FlowSpecAction::police(1)];
            speaker.announce(&unknown).await.unwrap();
            expected.extend([alias, unknown]);
        }
        contract::wait_inventory(speaker.as_ref(), &expected)
            .await
            .unwrap();
        let successes = metrics::RECONCILIATION_REPAIRS.with_label_values(&["success"]);
        let errors = metrics::RECONCILIATION_REPAIRS.with_label_values(&["error"]);
        let announcements = metrics::ANNOUNCEMENTS_TOTAL.with_label_values(&["announced"]);
        let before = (successes.get(), errors.get(), announcements.get());
        for _ in 0..2 {
            assert!(reconciler.reconcile().await.is_err());
            contract::wait_inventory(speaker.as_ref(), &expected)
                .await
                .unwrap();
            assert_eq!((successes.get(), errors.get(), announcements.get()), before);
        }
        // These aliases are fixture-owned external rows, not the saved mitigation match.
        for rule in &expected {
            speaker.withdraw(rule).await.unwrap();
        }
        contract::wait_inventory(speaker.as_ref(), &[])
            .await
            .unwrap();
    }
    for afi in [1, 2] {
        assert!(
            fixture
                .paths(afi, prefixd::bgp::apipb::TableType::Global)
                .await
                .is_empty()
        );
    }
}

/// Use an isolated speaker: the unsupported local row deliberately blocks strict inventory.
#[tokio::test]
#[ignore = "requires Docker on Linux; run scripts/test-gobgp.sh"]
async fn test_local_provenance_and_unsupported_local_rule() {
    use prefixd::bgp::apipb::{self, flow_spec_rule, nlri};
    let fixture = fixture::Speaker::start().await;
    let announcer = fixture.connect().await;
    let rule = FlowSpecRule::new(
        FlowSpecNlri {
            dst_prefix: "198.51.100.211/32".into(),
            protocol: Some(17),
            dst_ports: vec![53],
        },
        FlowSpecAction::discard(),
    );
    announcer.announce(&rule).await.unwrap();
    let mut client = fixture.client().await;
    let family = apipb::Family { afi: 1, safi: 133 };
    let local_path = fixture
        .paths(1, apipb::TableType::Global)
        .await
        .into_iter()
        .find(|path| {
            path.nlri
                .as_ref()
                .and_then(|nlri| announcer.decode_flowspec_nlri(nlri).ok())
                .is_some_and(|nlri| nlri.compute_hash() == rule.nlri_hash())
        });
    let mut local_path = local_path.expect("injected path must appear in GLOBAL RIB");
    assert!(
        local_path.neighbor_ip.is_empty(),
        "GoBGP-local provenance uses an empty neighbor address"
    );
    assert!(
        local_path.uuid.is_empty(),
        "ListPath does not serialize injection UUIDs"
    );
    let Some(nlri::Nlri::FlowSpec(nlri)) = &mut local_path.nlri.as_mut().unwrap().nlri else {
        panic!("expected FlowSpec");
    };
    nlri.rules.push(apipb::FlowSpecRule {
        rule: Some(flow_spec_rule::Rule::Component(apipb::FlowSpecComponent {
            r#type: 6,
            items: vec![apipb::FlowSpecComponentItem {
                op: 0x81,
                value: 123,
            }],
        })),
    });
    let added = client
        .add_path(apipb::AddPathRequest {
            table_type: apipb::TableType::Global as i32,
            path: Some(local_path),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let observed = announcer.list_active().await;
    client
        .delete_path(apipb::DeletePathRequest {
            table_type: apipb::TableType::Global as i32,
            family: Some(family),
            uuid: added.uuid,
            ..Default::default()
        })
        .await
        .unwrap();
    announcer.withdraw(&rule).await.unwrap();
    assert!(observed.unwrap_err().to_string().contains("unsupported"));
    announcer
        .list_active()
        .await
        .expect("observation recovers once unsupported local rule is removed");
}

/// A real daemon restart, preserving the original client and desired repository.
#[tokio::test]
#[ignore = "requires Docker on Linux; run scripts/test-gobgp.sh"]
async fn restart_recovers_through_the_same_client_and_reconciler() {
    use prefixd::{
        db::{MockRepository, RepositoryTrait},
        domain::{ActionParams, AttackVector, MatchCriteria, Mitigation, MitigationIntent},
        scheduler::ReconciliationLoop,
    };
    use std::sync::Arc;
    let fixture = fixture::Speaker::start().await;
    let speaker = Arc::new(fixture.connect().await);
    let repo = Arc::new(MockRepository::new());
    let settings = prefixd::config::BgpConfig {
        mode: prefixd::config::BgpMode::Gobgp,
        gobgp_grpc: fixture.endpoint.clone(),
        local_asn: 65010,
        router_id: "192.0.2.10".into(),
        rustbgpd: None,
        neighbors: vec![],
    };
    let binding = repo
        .register_speaker_target(
            "restart-contract",
            &prefixd::domain::SpeakerTarget::from_config(&settings).unwrap(),
            false,
        )
        .await
        .unwrap();
    let desired: Vec<_> = contract::contract_rules().into_iter().take(2).collect();
    for rule in &desired {
        let mut mitigation = Mitigation::from_intent(
            MitigationIntent {
                event_id: uuid::Uuid::new_v4(),
                customer_id: None,
                service_id: None,
                pop: "restart-contract".into(),
                match_criteria: MatchCriteria {
                    dst_prefix: rule.nlri.dst_prefix.clone(),
                    protocol: rule.nlri.protocol,
                    dst_ports: rule.nlri.dst_ports.clone(),
                },
                action_type: rule.actions[0].action_type,
                action_params: ActionParams {
                    rate_bps: rule.actions[0].rate_bps,
                },
                ttl_seconds: 300,
                reason: "speaker restart qualification".into(),
            },
            rule.nlri.dst_prefix.split('/').next().unwrap().into(),
            AttackVector::UdpFlood,
        );
        mitigation.activate();
        repo.insert_mitigation(&mitigation).await.unwrap();
    }
    let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false)
        .with_speaker_binding(binding);
    reconciler.reconcile().await.unwrap();
    contract::wait_inventory(speaker.as_ref(), &desired)
        .await
        .unwrap();
    fixture.container.stop_with_timeout(Some(0)).await.unwrap();
    assert!(!matches!(
        tokio::time::timeout(Duration::from_secs(2), speaker.list_active()).await,
        Ok(Ok(_))
    ));
    fixture.container.start().await.unwrap();
    fixture.configure().await;
    contract::wait_inventory(speaker.as_ref(), &[])
        .await
        .unwrap();
    let mut foreign = desired[0].clone();
    foreign.nlri.dst_prefix = "198.51.100.240/32".into();
    speaker.announce(&foreign).await.unwrap();
    let before = prefixd::observability::metrics::RECONCILIATION_REPAIRS
        .with_label_values(&["success"])
        .get();
    reconciler.reconcile().await.unwrap();
    let mut expected = desired;
    expected.push(foreign);
    contract::wait_inventory(speaker.as_ref(), &expected)
        .await
        .unwrap();
    reconciler.reconcile().await.unwrap();
    assert_eq!(
        prefixd::observability::metrics::RECONCILIATION_REPAIRS
            .with_label_values(&["success"])
            .get(),
        before + 2.0
    );
    contract::wait_inventory(speaker.as_ref(), &expected)
        .await
        .unwrap();
}

fn received_rule(
    announcer: &GoBgpAnnouncer,
    path: &prefixd::bgp::apipb::Path,
    afi: i32,
) -> FlowSpecRule {
    use prefixd::bgp::apipb::{attribute, extended_community};
    let family = path.family.as_ref().expect("received FlowSpec family");
    assert_eq!((family.afi, family.safi), (afi, 133));
    assert_eq!(path.neighbor_ip, "127.0.0.1", "received provenance");
    let nlri = announcer
        .decode_flowspec_nlri(path.nlri.as_ref().unwrap())
        .unwrap();
    let mut rates = Vec::new();
    for attribute in &path.pattrs {
        if let Some(attribute::Attr::ExtendedCommunities(communities)) = &attribute.attr {
            for community in &communities.communities {
                let Some(extended_community::Extcom::TrafficRate(rate)) = &community.extcom else {
                    panic!("unexpected FlowSpec action community")
                };
                assert_eq!(rate.asn, 0);
                assert!(rate.rate.is_finite() && rate.rate >= 0.0);
                rates.push(rate.rate);
            }
        }
    }
    assert_eq!(rates.len(), 1, "exactly one received rate action");
    let bits = f64::from(rates[0]) * 8.0;
    assert!(bits.fract() == 0.0 && bits < 18_446_744_073_709_551_616.0);
    let action = if bits == 0.0 {
        FlowSpecAction::discard()
    } else {
        FlowSpecAction::police(bits as u64)
    };
    FlowSpecRule::new(nlri, action)
}

async fn set_local_preference(
    fixture: &fixture::Speaker,
    announcer: &GoBgpAnnouncer,
    rule: &FlowSpecRule,
    local_pref: u32,
) {
    use prefixd::bgp::apipb::{self as pb, attribute};
    let afi = if rule.nlri.dst_prefix.contains(':') {
        2
    } else {
        1
    };
    let mut path = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(path) = fixture
                .paths(afi, pb::TableType::Global)
                .await
                .into_iter()
                .find(|path| {
                    path.neighbor_ip.is_empty()
                        && announcer
                            .decode_flowspec_nlri(path.nlri.as_ref().unwrap())
                            .unwrap()
                            .compute_hash()
                            == rule.nlri_hash()
                })
            {
                break path;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("injected local path before preference replacement");
    path.pattrs
        .retain(|attribute| !matches!(attribute.attr, Some(attribute::Attr::LocalPref(_))));
    path.pattrs.push(pb::Attribute {
        attr: Some(attribute::Attr::LocalPref(pb::LocalPrefAttribute {
            local_pref,
        })),
    });
    fixture
        .client()
        .await
        .add_path(pb::AddPathRequest {
            table_type: pb::TableType::Global as i32,
            path: Some(path),
            ..Default::default()
        })
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires Docker on Linux; run scripts/test-gobgp.sh"]
async fn real_peers_receive_exact_actions_and_do_not_hide_nonselected_local_paths() {
    use prefixd::bgp::apipb as pb;
    let receiver = fixture::Speaker::with_router_id("192.0.2.11").await;
    let sender = fixture::Speaker::with_router_id("192.0.2.12").await;
    receiver.add_peer(sender.bgp_port, true).await;
    sender.add_peer(receiver.bgp_port, false).await;
    let receiver_client = receiver.connect().await;
    let sender_client = sender.connect().await;
    contract::wait_peer_state(&receiver_client, "127.0.0.1", true)
        .await
        .unwrap();
    contract::wait_peer_state(&sender_client, "127.0.0.1", true)
        .await
        .unwrap();
    let uptime = receiver.peer_uptime().await;
    let remote: Vec<_> = contract::contract_rules().into_iter().take(2).collect();
    let mut local = remote.clone();
    for (remote, local) in remote.iter().zip(&mut local) {
        local.actions = vec![FlowSpecAction::police(32_000_000)];
        receiver_client.announce(local).await.unwrap();
        sender_client.announce(remote).await.unwrap();
        set_local_preference(&receiver, &receiver_client, local, 50).await;
        set_local_preference(&sender, &sender_client, remote, 200).await;
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut received = Vec::new();
            let mut proven_nonselected = true;
            for afi in [1, 2] {
                let paths = receiver.paths(afi, pb::TableType::AdjIn).await;
                received.extend(
                    paths
                        .iter()
                        .map(|path| received_rule(&receiver_client, path, afi)),
                );
                let paths = receiver.paths(afi, pb::TableType::Global).await;
                let wanted = &remote[if afi == 1 { 0 } else { 1 }];
                proven_nonselected &= paths.len() == 2
                    && paths.iter().all(|path| {
                        path.family == Some(pb::Family { afi, safi: 133 })
                            && receiver_client
                                .decode_flowspec_nlri(path.nlri.as_ref().unwrap())
                                .unwrap()
                                .compute_hash()
                                == wanted.nlri_hash()
                    })
                    && paths
                        .iter()
                        .any(|path| path.neighbor_ip.is_empty() && !path.best)
                    && paths
                        .iter()
                        .any(|path| path.neighbor_ip == "127.0.0.1" && path.best);
            }
            if proven_nonselected && contract::exact_inventory(&received, &remote).is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("received/local coexistence and nonselected local paths");
    contract::wait_inventory(&receiver_client, &local)
        .await
        .unwrap();
    for rule in &remote {
        sender_client.withdraw(rule).await.unwrap();
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if receiver.paths(1, pb::TableType::AdjIn).await.is_empty()
                && receiver.paths(2, pb::TableType::AdjIn).await.is_empty()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("actual dual-family peer withdrawal");
    contract::wait_inventory(&receiver_client, &local)
        .await
        .unwrap();
    assert_eq!(
        receiver.peer_uptime().await,
        uptime,
        "withdrawal must not reset the session"
    );
    sender.container.stop_with_timeout(Some(0)).await.unwrap();
    contract::wait_peer_state(&receiver_client, "127.0.0.1", false)
        .await
        .unwrap();
    sender.container.start().await.unwrap();
    sender.configure().await;
    sender.add_peer(receiver.bgp_port, false).await;
    contract::wait_peer_state(&receiver_client, "127.0.0.1", true)
        .await
        .unwrap();
    contract::wait_peer_state(&sender_client, "127.0.0.1", true)
        .await
        .unwrap();
    contract::wait_inventory(&sender_client, &[]).await.unwrap();
    for rule in &remote {
        sender_client.announce(rule).await.unwrap();
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let mut received = Vec::new();
            for afi in [1, 2] {
                received.extend(
                    receiver
                        .paths(afi, pb::TableType::AdjIn)
                        .await
                        .iter()
                        .map(|path| received_rule(&receiver_client, path, afi)),
                );
            }
            if contract::exact_inventory(&received, &remote).is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("same-client replay reaches the peer after process restart");
    contract::wait_inventory(&receiver_client, &local)
        .await
        .unwrap();
}
