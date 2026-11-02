#![cfg(all(feature = "bgp-rustbgpd", feature = "test-utils", target_os = "linux"))]
#[path = "common/rustbgpd.rs"]
mod fixture;
use prefixd::bgp::{FlowSpecReader, GuardedFlowSpecSpeaker, GuardedRule};
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
