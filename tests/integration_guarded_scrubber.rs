#![cfg(all(feature = "bgp-rustbgpd", feature = "test-utils", target_os = "linux"))]
#[path = "common/rustbgpd.rs"]
mod fixture;
use prefixd::bgp::{FlowSpecReader, GuardedFlowSpecSpeaker, GuardedRule};
use prefixd::domain::FlowSpecNlri;
use std::time::Duration;

fn rule(prefix: &str, target: &str, owner: &str, revision: u64) -> GuardedRule {
    GuardedRule {
        route_targets: vec![],
        nlri: FlowSpecNlri {
            dst_prefix: prefix.into(),
            protocol: Some(6),
            dst_ports: vec![443],
            ..Default::default()
        },
        target: Some(target.parse().unwrap()),
        redirect_route_target: None,
        owner: owner.into(),
        revision,
    }
}

#[tokio::test]
#[ignore = "requires isolated pinned Linux Docker speaker; run scripts/test-rustbgpd.sh"]
async fn guarded_contract_preserves_targets_revisions_and_independent_owners() {
    let fixture = fixture::Speaker::start().await;
    let speaker = fixture.connect().await;
    let a = rule("192.0.2.1/32", "192.0.2.99", "prefixd.scrub.a", 1);
    let b = rule("2001:db8::2/128", "2001:db8::99", "prefixd.scrub.b", 2);
    let sibling = rule("192.0.2.3/32", "192.0.2.99", "prefixd.scrub.a", 3);
    let wa = speaker.issue_window(&a.owner, 30).await.unwrap();
    let wb = speaker.issue_window(&b.owner, 30).await.unwrap();
    let ga = speaker.add_guarded(&a, wa.stamp, 30).await.unwrap();
    let raw_v4 = fixture.received_flow_spec(3, "0.0.0.0").await;
    assert_eq!(
        raw_v4.received_routes[0]
            .route
            .as_ref()
            .unwrap()
            .extended_communities,
        [0x010c_c000_0263_0000]
    );
    assert_eq!(
        speaker.add_guarded(&sibling, wa.stamp, 30).await.unwrap(),
        ga
    );
    let gb = speaker.add_guarded(&b, wb.stamp, 30).await.unwrap();
    let raw_v6 = fixture.received_flow_spec(4, "0.0.0.0").await;
    assert_eq!(
        raw_v6.received_routes[0]
            .route
            .as_ref()
            .unwrap()
            .ipv6_extended_communities,
        [hex::decode("000c20010db80000000000000000000000990000").unwrap()]
    );
    assert_eq!(speaker.add_guarded(&a, wa.stamp, 30).await.unwrap(), ga);
    let inventory = speaker.guarded_inventory().await.unwrap();
    for expected in [&a, &b, &sibling] {
        assert!(
            inventory
                .iter()
                .any(|entry| entry.rule.same_admission(expected) && entry.remaining_ms > 0)
        );
    }
    assert!(
        speaker.list_active().await.unwrap().is_empty(),
        "guarded rows have a separate lifecycle"
    );
    // An old delete, a different owner and a changed target never affect siblings.
    let mut wrong = a.clone();
    wrong.revision = 99;
    assert!(speaker.delete_guarded(&wrong).await.is_err());
    let mut wrong = a.clone();
    wrong.owner = b.owner.clone();
    assert!(speaker.delete_guarded(&wrong).await.is_err());
    let mut wrong = a.clone();
    wrong.target = Some("192.0.2.98".parse().unwrap());
    assert!(speaker.add_guarded(&wrong, wa.stamp, 30).await.is_err());
    assert_eq!(speaker.guarded_inventory().await.unwrap().len(), 3);
    speaker.delete_guarded(&a).await.unwrap();
    speaker.delete_guarded(&a).await.unwrap();
    let mut replacement = a.clone();
    replacement.revision = 4;
    speaker
        .add_guarded(&replacement, wa.stamp, 30)
        .await
        .unwrap();
    assert!(
        speaker.delete_guarded(&a).await.is_err(),
        "late delete cannot remove replacement"
    );
    assert!(
        speaker
            .guarded_inventory()
            .await
            .unwrap()
            .iter()
            .any(|entry| entry.rule.same_admission(&replacement))
    );
    // Delay a formed request before handler receipt. Its expired authorization
    // cannot extend the owner's lease or recreate a withdrawn key.
    let expired = speaker.issue_window(&a.owner, 1).await.unwrap();
    speaker.delete_guarded(&replacement).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(
        speaker
            .add_guarded(&replacement, expired.stamp, 30)
            .await
            .is_err()
    );
    assert!(
        speaker
            .renew_guarded(&a.owner, ga, expired.stamp, 30)
            .await
            .is_err()
    );
    assert!(
        speaker
            .renew_guarded(&b.owner, gb, wb.stamp, 30)
            .await
            .unwrap()
            > 0
    );
    let remaining = speaker.guarded_inventory().await.unwrap();
    assert_eq!(remaining.len(), 2);
    assert!(
        remaining
            .iter()
            .any(|entry| entry.rule.same_admission(&sibling))
    );
    assert!(remaining.iter().any(|entry| entry.rule.same_admission(&b)));
    speaker.delete_guarded(&sibling).await.unwrap();
    speaker.delete_guarded(&b).await.unwrap();
    assert!(speaker.guarded_inventory().await.unwrap().is_empty());
    // Another tool's guarded rule is an occupied key, never ours, never a read failure.
    let foreign = rule("192.0.2.4/32", "192.0.2.99", "other.tool", 5);
    let wf = speaker.issue_window(&foreign.owner, 30).await.unwrap();
    speaker.add_guarded(&foreign, wf.stamp, 30).await.unwrap();
    assert!(speaker.list_active().await.unwrap().is_empty());
    let inventory = speaker.guarded_inventory().await.unwrap();
    assert!(inventory.is_empty());
    assert!(inventory.has_key(&foreign.nlri));
    speaker.delete_guarded(&foreign).await.unwrap();
    fixture.container.rm().await.unwrap();
}

/// Delayed-delete key reuse and pending-add withdrawal from the
/// scrubber-diversion contract. A "held" request is formed but not sent until
/// the stated point, so the daemon first receives it then.
#[tokio::test]
#[ignore = "requires isolated pinned Linux Docker speaker; run scripts/test-rustbgpd.sh"]
async fn held_guarded_mutations_cannot_remove_a_reused_key_or_outlive_their_window() {
    use prefixd::bgp::FlowSpecWriter;
    use prefixd::domain::{FlowSpecAction, FlowSpecRule};
    let fixture = fixture::Speaker::start().await;
    let speaker = fixture.connect().await;

    // Delayed delete D1, retry D2, then a new admission of the same key while a
    // same-owner sibling keeps the owner generation live.
    let owner = "prefixd.scrub.reuse";
    let sibling = rule("192.0.2.30/32", "192.0.2.99", owner, 10);
    let first = rule("192.0.2.31/32", "192.0.2.99", owner, 11);
    let window = speaker.issue_window(owner, 30).await.unwrap();
    let generation = speaker
        .add_guarded(&sibling, window.stamp, 30)
        .await
        .unwrap();
    assert_eq!(
        speaker.add_guarded(&first, window.stamp, 30).await.unwrap(),
        generation
    );
    let d1 = speaker.delete_guarded(&first);
    speaker.delete_guarded(&first).await.unwrap();
    assert!(
        !speaker
            .guarded_inventory()
            .await
            .unwrap()
            .has_key(&first.nlri)
    );
    let mut replacement = first.clone();
    replacement.revision = 12;
    assert_eq!(
        speaker
            .add_guarded(&replacement, window.stamp, 30)
            .await
            .unwrap(),
        generation,
        "the sibling keeps the owner generation live across key reuse"
    );
    assert!(
        d1.await.is_err(),
        "the held delete names the older admission revision"
    );
    let inventory = speaker.guarded_inventory().await.unwrap();
    assert!(
        inventory
            .iter()
            .any(|entry| entry.rule.same_admission(&replacement) && entry.remaining_ms > 0)
    );
    assert!(
        inventory
            .iter()
            .any(|entry| { entry.rule.same_admission(&sibling) && entry.generation == generation })
    );

    // Negative control: the owner-only legacy delete has no admission fence,
    // so the same held delete removes the replacement.
    let legacy = |prefix: &str| {
        FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: prefix.into(),
                protocol: Some(6),
                dst_ports: vec![443],
                ..Default::default()
            },
            FlowSpecAction::discard(),
        )
        .with_owner("legacy.reuse")
    };
    let (legacy_sibling, legacy_first) = (legacy("192.0.2.40/32"), legacy("192.0.2.41/32"));
    speaker.announce_leased(&legacy_sibling, 30).await.unwrap();
    speaker.announce_leased(&legacy_first, 30).await.unwrap();
    let d1 = speaker.withdraw(&legacy_first);
    speaker.withdraw(&legacy_first).await.unwrap();
    let held = |rules: &[FlowSpecRule], rule: &FlowSpecRule| {
        rules
            .iter()
            .any(|other| other.nlri_hash() == rule.nlri_hash())
    };
    assert!(!held(&speaker.list_active().await.unwrap(), &legacy_first));
    speaker.announce_leased(&legacy_first, 30).await.unwrap();
    assert!(held(&speaker.list_active().await.unwrap(), &legacy_first));
    d1.await.unwrap();
    let active = speaker.list_active().await.unwrap();
    assert!(
        !held(&active, &legacy_first),
        "the owner-only delete removes the replacement"
    );
    assert!(held(&active, &legacy_sibling));
    speaker.withdraw(&legacy_sibling).await.unwrap();

    // Pending-add withdrawal: an add held past the first delete recreates the
    // key while its window lives; only the window's expiry bars the replay.
    let owner = "prefixd.scrub.pending";
    let sibling = rule("192.0.2.50/32", "192.0.2.99", owner, 20);
    let pending = rule("192.0.2.51/32", "192.0.2.99", owner, 21);
    let short = speaker.issue_window(owner, 5).await.unwrap();
    let generation = speaker
        .add_guarded(&sibling, short.stamp, 30)
        .await
        .unwrap();
    let held_add = speaker.add_guarded(&pending, short.stamp, 30);
    speaker.delete_guarded(&pending).await.unwrap();
    assert!(
        !speaker
            .guarded_inventory()
            .await
            .unwrap()
            .has_key(&pending.nlri),
        "the initial delete reads absent"
    );
    assert_eq!(held_add.await.unwrap(), generation);
    assert!(
        speaker
            .guarded_inventory()
            .await
            .unwrap()
            .iter()
            .any(|entry| entry.rule.same_admission(&pending)),
        "negative control: a still-authorized add recreates the key after the absence read"
    );
    // Keep the sibling's lease beyond the short window.
    let long = speaker.issue_window(owner, 30).await.unwrap();
    speaker
        .renew_guarded(owner, generation, long.stamp, 30)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(u64::from(short.remaining_ms) + 500)).await;
    speaker.delete_guarded(&pending).await.unwrap();
    assert!(
        !speaker
            .guarded_inventory()
            .await
            .unwrap()
            .has_key(&pending.nlri)
    );
    assert!(
        speaker
            .add_guarded(&pending, short.stamp, 30)
            .await
            .is_err(),
        "a replay after the window cannot recreate the key"
    );
    let inventory = speaker.guarded_inventory().await.unwrap();
    assert!(!inventory.has_key(&pending.nlri));
    assert!(inventory.iter().any(|entry| {
        entry.rule.same_admission(&sibling)
            && entry.generation == generation
            && entry.remaining_ms > 0
    }));
    for rule in [
        &sibling,
        &replacement,
        &rule("192.0.2.30/32", "192.0.2.99", "prefixd.scrub.reuse", 10),
    ] {
        speaker.delete_guarded(rule).await.unwrap();
    }
    assert!(speaker.guarded_inventory().await.unwrap().is_empty());
    fixture.container.rm().await.unwrap();
}

#[tokio::test]
#[ignore = "requires isolated pinned Linux Docker speaker; run scripts/test-rustbgpd.sh"]
async fn guarded_vpn_scope_keeps_rd_targets_and_held_revision() {
    use prefixd::domain::{VpnFlowSpecFamily, VpnFlowSpecIdentity};
    let fixture = fixture::Speaker::start().await;
    let speaker = fixture.connect().await;
    let supported = std::env::var("PREFIXD_RUSTBGPD_TEST_VERSION").as_deref() == Ok("0.82.0");
    let window = speaker
        .issue_window("prefixd.scrub.vpnfixture", 30)
        .await
        .unwrap();
    for (family, global_family, prefix, target) in [
        (VpnFlowSpecFamily::Ipv4, 3, "192.0.2.21/32", "192.0.2.99"),
        (
            VpnFlowSpecFamily::Ipv6,
            4,
            "2001:db8::21/128",
            "2001:db8::99",
        ),
    ] {
        let global = rule(prefix, target, "prefixd.scrub.vpnfixture", 1);
        speaker
            .add_guarded(&global, window.stamp, 30)
            .await
            .unwrap();
        let mut a = global.clone();
        a.nlri.scope = Some(VpnFlowSpecIdentity::new(family, "44407:40").unwrap());
        a.route_targets = vec!["44407:777".into()];
        let mut b = a.clone();
        b.nlri.scope = Some(VpnFlowSpecIdentity::new(family, "44407:41").unwrap());
        if !supported {
            for error in [
                speaker.add_guarded(&a, window.stamp, 30).await.unwrap_err(),
                speaker.delete_guarded(&a).await.unwrap_err(),
            ] {
                assert!(
                    matches!(error, prefixd::error::PrefixdError::UnsupportedFlowSpecScope { backend: "rustbgpd", family: observed } if observed == family.afi_safi())
                );
            }
            assert!(speaker.guarded_inventory().await.is_err());
            let rows = fixture.received_flow_spec(global_family, "0.0.0.0").await;
            assert_eq!(rows.received_routes.len(), 1);
            let held = rows.received_routes[0].route.as_ref().unwrap();
            assert!(held.rd.is_empty());
            assert!(held.route_targets.is_empty());
            speaker.delete_guarded(&global).await.unwrap();
            continue;
        }
        speaker.add_guarded(&a, window.stamp, 30).await.unwrap();
        speaker.add_guarded(&b, window.stamp, 30).await.unwrap();
        let inventory = speaker.guarded_inventory().await.unwrap();
        for expected in [&global, &a, &b] {
            assert!(
                inventory
                    .iter()
                    .any(|entry| entry.rule.same_admission(expected))
            );
        }
        let mut replaced = a.clone();
        replaced.route_targets = vec!["44407:778".into()];
        assert!(
            speaker
                .add_guarded(&replaced, window.stamp, 30)
                .await
                .is_err()
        );
        assert!(
            speaker
                .guarded_inventory()
                .await
                .unwrap()
                .iter()
                .any(|entry| entry.rule.same_admission(&a))
        );
        speaker.delete_guarded(&a).await.unwrap();
        replaced.revision = 2;
        speaker
            .add_guarded(&replaced, window.stamp, 30)
            .await
            .unwrap();
        assert!(
            speaker.delete_guarded(&a).await.is_err(),
            "stale revision cannot delete replacement"
        );
        let inventory = speaker.guarded_inventory().await.unwrap();
        for expected in [&global, &replaced, &b] {
            assert!(
                inventory
                    .iter()
                    .any(|entry| entry.rule.same_admission(expected))
            );
        }
        speaker.delete_guarded(&b).await.unwrap();
        speaker.delete_guarded(&replaced).await.unwrap();
        speaker.delete_guarded(&global).await.unwrap();
        assert!(speaker.guarded_inventory().await.unwrap().is_empty());
    }
}

#[tokio::test]
#[ignore = "requires isolated pinned Linux Docker speaker; run scripts/test-rustbgpd.sh"]
async fn guarded_vpn_vrf_redirects_keep_action_and_scope_targets_separate() {
    use prefixd::domain::{VpnFlowSpecFamily, VpnFlowSpecIdentity};
    let fixture = fixture::Speaker::start().await;
    let speaker = fixture.connect().await;
    let supported = std::env::var("PREFIXD_RUSTBGPD_TEST_VERSION").as_deref() == Ok("0.82.0");
    let window = speaker
        .issue_window("prefixd.scrub.vrffixture", 30)
        .await
        .unwrap();
    for (family, global_family, prefix) in [
        (VpnFlowSpecFamily::Ipv4, 3, "192.0.2.22/32"),
        (VpnFlowSpecFamily::Ipv6, 4, "2001:db8::22/128"),
    ] {
        for (index, (target, expected_action)) in [
            ("44407:888", 0x8008_ad77_0000_0378u64),
            ("192.0.2.1:888", 0x8108_c000_0201_0378),
            ("0.44407:888", 0x8208_0000_ad77_0378),
        ]
        .into_iter()
        .enumerate()
        {
            let mut scoped = rule(prefix, "192.0.2.99", "prefixd.scrub.vrffixture", 1);
            scoped.revision = (index as u64) * 2 + 1;
            scoped.target = None;
            scoped.redirect_route_target = Some(target.into());
            scoped.nlri.scope = Some(VpnFlowSpecIdentity::new(family, "44407:40").unwrap());
            scoped.route_targets = vec!["44407:777".into()];
            if !supported {
                assert!(
                    speaker
                        .add_guarded(&scoped, window.stamp, 30)
                        .await
                        .is_err()
                );
                assert!(
                    fixture
                        .received_flow_spec(global_family, "0.0.0.0")
                        .await
                        .received_routes
                        .is_empty()
                );
                continue;
            }
            speaker
                .add_guarded(&scoped, window.stamp, 30)
                .await
                .unwrap();
            let raw = fixture
                .received_flow_spec(family.afi_safi(), "0.0.0.0")
                .await;
            let held = raw.received_routes[0].route.as_ref().unwrap();
            assert_eq!(held.route_targets, ["44407:777"]);
            assert_eq!(
                held.extended_communities,
                [
                    expected_action,
                    prefixd::domain::route_target_bytes("44407:777").unwrap()
                ]
            );
            assert!(
                speaker
                    .guarded_inventory()
                    .await
                    .unwrap()
                    .iter()
                    .any(|entry| entry.rule.same_admission(&scoped))
            );
            let mut replacement = scoped.clone();
            replacement.redirect_route_target = Some("44407:889".into());
            assert!(
                speaker
                    .add_guarded(&replacement, window.stamp, 30)
                    .await
                    .is_err()
            );
            speaker.delete_guarded(&scoped).await.unwrap();
            replacement.revision = scoped.revision + 1;
            speaker
                .add_guarded(&replacement, window.stamp, 30)
                .await
                .unwrap();
            assert!(speaker.delete_guarded(&scoped).await.is_err());
            assert!(
                speaker
                    .guarded_inventory()
                    .await
                    .unwrap()
                    .iter()
                    .any(|entry| entry.rule.same_admission(&replacement))
            );
            speaker.delete_guarded(&replacement).await.unwrap();
            assert!(speaker.guarded_inventory().await.unwrap().is_empty());
        }
    }
}
