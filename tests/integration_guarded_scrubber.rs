#![cfg(all(feature = "bgp-rustbgpd", feature = "test-utils", target_os = "linux"))]
#[path = "common/rustbgpd.rs"]
mod fixture;
use prefixd::bgp::{FlowSpecReader, GuardedFlowSpecSpeaker, GuardedRule, GuardedStamp};
use prefixd::domain::FlowSpecNlri;
use std::time::Duration;

fn rule(prefix: &str, target: &str, owner: &str, revision: u64) -> GuardedRule {
    GuardedRule {
        nlri: FlowSpecNlri {
            dst_prefix: prefix.into(),
            protocol: Some(6),
            dst_ports: vec![443],
            ..Default::default()
        },
        target: target.parse().unwrap(),
        owner: owner.into(),
        revision,
    }
}

#[tokio::test]
#[ignore = "requires isolated pinned Linux Docker speaker; run scripts/test-rustbgpd.sh"]
async fn guarded_contract_preserves_targets_revisions_and_independent_owners() {
    let fixture = fixture::Speaker::start().await;
    let speaker = fixture.connect().await;
    let version = std::env::var("PREFIXD_RUSTBGPD_TEST_VERSION").unwrap_or("0.81.0".into());
    let a = rule("192.0.2.1/32", "192.0.2.99", "scrubber.a", 1);
    if version != "0.81.0" {
        assert!(speaker.issue_window(&a.owner, 30).await.is_err());
        assert!(
            speaker
                .add_guarded(
                    &a,
                    GuardedStamp {
                        incarnation: 1,
                        sequence: 1
                    },
                    30
                )
                .await
                .is_err()
        );
        assert!(speaker.guarded_inventory().await.unwrap().is_empty());
        assert!(
            speaker.list_active().await.unwrap().is_empty(),
            "no legacy fallback"
        );
        fixture.container.rm().await.unwrap();
        return;
    }
    let b = rule("2001:db8::2/128", "2001:db8::99", "scrubber.b", 2);
    let sibling = rule("192.0.2.3/32", "192.0.2.99", "scrubber.a", 3);
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
    wrong.target = "192.0.2.98".parse().unwrap();
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
    if std::env::var("PREFIXD_RUSTBGPD_TEST_VERSION").unwrap_or("0.81.0".into()) != "0.81.0" {
        fixture.container.rm().await.unwrap();
        return;
    }

    // Delayed delete D1, retry D2, then a new admission of the same key while a
    // same-owner sibling keeps the owner generation live.
    let owner = "scrubber.reuse";
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
    let owner = "scrubber.pending";
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
        &rule("192.0.2.30/32", "192.0.2.99", "scrubber.reuse", 10),
    ] {
        speaker.delete_guarded(rule).await.unwrap();
    }
    assert!(speaker.guarded_inventory().await.unwrap().is_empty());
    fixture.container.rm().await.unwrap();
}
