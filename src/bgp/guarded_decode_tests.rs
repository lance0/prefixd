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

fn status(code: Code, domain: &str, reason: Option<&str>) -> tonic::Status {
    let details = reason.map(|reason| prost_types::Any {
        type_url: "type.googleapis.com/google.rpc.ErrorInfo".into(),
        value: ErrorInfo {
            reason: reason.into(),
            domain: domain.into(),
        }
        .encode_to_vec(),
    });
    let rich = RpcStatus {
        code: code as i32,
        details: details.into_iter().collect(),
    };
    tonic::Status::with_details(code, "private diagnostic", rich.encode_to_vec().into())
}

#[test]
fn guarded_refusals_name_their_cause_and_other_failures_stay_unconfirmed() {
    let precondition = |reason| status(Code::FailedPrecondition, "rustbgpd", Some(reason));
    for (refused, expected) in [
        (
            precondition("WINDOW_NOT_LIVE"),
            GuardedRefusal::WindowNotLive,
        ),
        (
            precondition("REVISION_MISMATCH"),
            GuardedRefusal::RevisionMismatch,
        ),
        (
            precondition("OWNER_MISMATCH"),
            GuardedRefusal::OwnerMismatch,
        ),
        (precondition("KEY_UNOWNED"), GuardedRefusal::KeyUnowned),
        (
            precondition("GENERATION_NOT_LIVE"),
            GuardedRefusal::GenerationNotLive,
        ),
        (
            tonic::Status::resource_exhausted("window cap"),
            GuardedRefusal::ResourceExhausted,
        ),
        (
            tonic::Status::invalid_argument("bad"),
            GuardedRefusal::InvalidArgument,
        ),
        (
            tonic::Status::unimplemented("old"),
            GuardedRefusal::Unimplemented,
        ),
        (
            tonic::Status::permission_denied("role"),
            GuardedRefusal::PermissionDenied,
        ),
    ] {
        assert_eq!(GuardedRefusal::of(&refused), Some(expected));
        let text = guarded_status_error("AddGuardedFlowSpec", &refused).to_string();
        assert!(
            text.contains(&format!("refused ({})", expected.as_str()))
                && text.contains("nothing changed")
                && !text.contains("private"),
            "{text}"
        );
    }
    for unknown in [
        tonic::Status::failed_precondition("WINDOW_NOT_LIVE"),
        status(Code::FailedPrecondition, "rustbgpd", None),
        precondition("A_NEW_REASON"),
        status(Code::FailedPrecondition, "other", Some("WINDOW_NOT_LIVE")),
        tonic::Status::unavailable("gone"),
        tonic::Status::deadline_exceeded("slow"),
        tonic::Status::cancelled("dropped"),
        tonic::Status::internal("panic"),
        tonic::Status::unknown("?"),
        tonic::Status::aborted("raced"),
    ] {
        assert_eq!(GuardedRefusal::of(&unknown), None, "{unknown:?}");
        let text = guarded_status_error("AddGuardedFlowSpec", &unknown).to_string();
        assert!(
            text.contains("outcome unconfirmed") && !text.contains("nothing changed"),
            "{text}"
        );
    }
}

#[test]
fn foreign_match_never_normalizes_scoped_fields_into_global_occupancy() {
    let baseline = route();
    assert_eq!(
        foreign_match(baseline.clone(), 3).unwrap().dst_prefix,
        "192.0.2.1/32"
    );
    let mut rd = baseline.clone();
    rd.rd = "44407:40".into();
    assert!(foreign_match(rd, 3).is_err());
    let mut targets = baseline;
    targets.route_targets = vec!["44407:777".into()];
    assert!(foreign_match(targets, 3).is_err());
}
