use super::*;

fn route() -> pb::FlowSpecRouteEntry {
    pb::FlowSpecRouteEntry {
        components: vec![pb::FlowSpecComponent {
            r#type: 1,
            prefix: "192.0.2.1/32".into(),
            ..Default::default()
        }],
        actions: vec![pb::FlowSpecAction {
            action: Some(pb::flow_spec_action::Action::RedirectIp(
                pb::FlowSpecRedirectIp {
                    address: "192.0.2.99".into(),
                    copy: false,
                },
            )),
        }],
        peer_address: "0.0.0.0".into(),
        afi_safi: 3,
        extended_communities: vec![0x010c_c000_0263_0000],
        injection_owner: "guarded:profile.a".into(),
        lease_generation: Some(pb::LeaseGeneration {
            incarnation: 1,
            sequence: 1,
        }),
        lease_remaining_ms: Some(20_000),
        admission_revision: Some(7),
        ..Default::default()
    }
}

#[test]
fn guarded_readback_requires_exact_supported_action_and_lease_fields() {
    let valid = route();
    let decoded = decode_guarded(valid.clone(), 3).unwrap();
    assert_eq!(decoded.rule.owner, "profile.a");
    assert_eq!(decoded.rule.revision, 7);
    assert_eq!(decoded.rule.target.to_string(), "192.0.2.99");
    for case in 0..13 {
        let mut bad = valid.clone();
        match case {
            0 => bad.extended_communities[0] |= 1, // copy/reserved bits cannot disappear
            1 => bad.extended_communities.push(bad.extended_communities[0]),
            2 => bad.ipv6_extended_communities = vec![vec![0; 20]],
            3 => bad.admission_revision = None,
            4 => bad.admission_revision = Some(0),
            5 => bad.injection_owner = "ordinary".into(),
            6 => bad.lease_generation = None,
            7 => bad.lease_remaining_ms = None,
            8 => bad.communities = vec![1],
            9 => bad.as_path = vec![64512],
            10 => {
                bad.actions[0].action = Some(pb::flow_spec_action::Action::RedirectIp(
                    pb::FlowSpecRedirectIp {
                        address: "192.0.2.99".into(),
                        copy: true,
                    },
                ))
            }
            11 => bad.components[0].prefix = "192.0.2.0/24".into(),
            12 => bad.actions.clear(),
            _ => unreachable!(),
        }
        assert!(decode_guarded(bad, 3).is_err(), "case {case}");
    }
}
