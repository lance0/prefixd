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
fn vpn_guarded_readback_preserves_scope_and_revision_payload() {
    use crate::domain::{VpnFlowSpecFamily, VpnFlowSpecIdentity};
    for (family, kind, prefix, target) in [
        (13, VpnFlowSpecFamily::Ipv4, "192.0.2.1/32", "192.0.2.99"),
        (
            14,
            VpnFlowSpecFamily::Ipv6,
            "2001:db8::1/128",
            "2001:db8::99",
        ),
    ] {
        let mut scoped = route();
        scoped.afi_safi = family;
        scoped.rd = "44407:40".into();
        scoped.route_targets = vec!["44407:777".into()];
        scoped.components[0].prefix = prefix.into();
        let ip: std::net::IpAddr = target.parse().unwrap();
        let mut action = vec![];
        match ip {
            std::net::IpAddr::V4(_) => action.push(0x010c_c000_0263_0000),
            std::net::IpAddr::V6(ip) => {
                let mut raw = vec![0, 12];
                raw.extend(ip.octets());
                raw.extend([0, 0]);
                scoped.ipv6_extended_communities = vec![raw];
            }
        }
        scoped.actions[0].action = Some(pb::flow_spec_action::Action::RedirectIp(
            pb::FlowSpecRedirectIp {
                address: target.into(),
                copy: false,
            },
        ));
        action.push(crate::domain::route_target_bytes("44407:777").unwrap());
        scoped.extended_communities = action;
        let decoded = decode_guarded(scoped.clone(), family).unwrap();
        assert_eq!(
            decoded.rule.nlri.scope,
            Some(VpnFlowSpecIdentity::new(kind, "44407:40").unwrap())
        );
        assert_eq!(decoded.rule.route_targets, ["44407:777"]);
        let encoded = encode_guarded(&decoded.rule).unwrap();
        assert_eq!(encoded.rd, "44407:40");
        assert_eq!(encoded.afi_safi, family);
        assert_eq!(encoded.route_targets, ["44407:777"]);
        assert!(encoded.extended_communities.is_empty());
        let mut changed = decoded.rule.clone();
        changed.route_targets = vec!["44407:778".into()];
        assert!(!decoded.rule.same_admission(&changed));
        changed = decoded.rule.clone();
        changed.nlri.scope = Some(VpnFlowSpecIdentity::new(kind, "44407:41").unwrap());
        assert!(!decoded.rule.same_admission(&changed));
        scoped.extended_communities.pop();
        assert!(
            decode_guarded(scoped, family).is_err(),
            "missing raw scope RT"
        );
    }
}

#[test]
fn guarded_duplicate_raw_targets_replay_without_typed_twins() {
    use crate::domain::{VpnFlowSpecFamily, VpnFlowSpecIdentity};
    let mut scoped = route();
    scoped.afi_safi = 13;
    scoped.rd = "44407:40".into();
    scoped.route_targets = vec!["44407:777".into(); 2];
    let rt = crate::domain::route_target_bytes("44407:777").unwrap();
    scoped.extended_communities.extend([rt, rt]);
    let decoded = decode_guarded(scoped.clone(), 13).unwrap();
    let encoded = encode_guarded(&decoded.rule).unwrap();
    assert!(encoded.route_targets.is_empty());
    assert_eq!(encoded.extended_communities, [rt, rt]);
    assert_eq!(
        foreign_match(scoped, 13).unwrap().scope,
        Some(VpnFlowSpecIdentity::new(VpnFlowSpecFamily::Ipv4, "44407:40").unwrap())
    );
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

#[cfg(feature = "test-utils")]
mod deadlines {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
    };
    use tokio::sync::{Mutex, Notify};

    #[derive(Clone, Default)]
    struct Service {
        mode: Arc<AtomicUsize>,
        probe_entered: Arc<Notify>,
        second_probe_entered: Arc<Notify>,
        mutation_entered: Arc<Notify>,
        guarded_mutations: Arc<AtomicUsize>,
        completed_mutations: Arc<AtomicUsize>,
        global_present: Arc<AtomicBool>,
    }

    impl Service {
        async fn mutate(&self) {
            self.guarded_mutations.fetch_add(1, SeqCst);
            self.mutation_entered.notify_one();
            if self.mode.load(SeqCst) == 2 {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            self.completed_mutations.fetch_add(1, SeqCst);
        }
    }

    #[tonic::async_trait]
    impl pb::rib_service_server::RibService for Service {
        async fn list_flow_spec_routes(
            &self,
            request: Request<pb::ListFlowSpecRequest>,
        ) -> std::result::Result<tonic::Response<pb::ListFlowSpecResponse>, tonic::Status> {
            let family = request.into_inner().afi_safi;
            self.probe_entered.notify_one();
            if family == 14 {
                self.second_probe_entered.notify_one();
            }
            match self.mode.load(SeqCst) {
                1 => std::future::pending::<()>().await,
                2 | 6 => tokio::time::sleep(Duration::from_secs(2)).await,
                3 => return Err(tonic::Status::invalid_argument("unsupported family")),
                4 => return Err(tonic::Status::unauthenticated("private diagnostic")),
                5 => return Err(tonic::Status::unavailable("private diagnostic")),
                _ => {}
            }
            Ok(tonic::Response::new(pb::ListFlowSpecResponse {
                received_view: true,
                ..Default::default()
            }))
        }
    }

    #[tonic::async_trait]
    impl pb::injection_service_server::InjectionService for Service {
        async fn issue_mutation_window(
            &self,
            _: Request<pb::IssueMutationWindowRequest>,
        ) -> std::result::Result<tonic::Response<pb::IssueMutationWindowResponse>, tonic::Status>
        {
            self.mutate().await;
            Ok(tonic::Response::new(pb::IssueMutationWindowResponse {
                window: Some(stamp().into()),
                window_remaining_ms: 30_000,
            }))
        }
        async fn add_guarded_flow_spec(
            &self,
            _: Request<pb::AddGuardedFlowSpecRequest>,
        ) -> std::result::Result<tonic::Response<pb::AddGuardedFlowSpecResponse>, tonic::Status>
        {
            self.mutate().await;
            Ok(tonic::Response::new(pb::AddGuardedFlowSpecResponse {
                result: Some(pb::AddFlowSpecResponse { outcome: 1 }),
                generation: Some(stamp().into()),
            }))
        }
        async fn renew_guarded_lease(
            &self,
            _: Request<pb::RenewGuardedLeaseRequest>,
        ) -> std::result::Result<tonic::Response<pb::RenewGuardedLeaseResponse>, tonic::Status>
        {
            self.mutate().await;
            Ok(tonic::Response::new(pb::RenewGuardedLeaseResponse {
                generation: Some(stamp().into()),
                lease_remaining_ms: 30_000,
            }))
        }
        async fn delete_guarded_flow_spec(
            &self,
            _: Request<pb::DeleteGuardedFlowSpecRequest>,
        ) -> std::result::Result<tonic::Response<pb::DeleteGuardedFlowSpecResponse>, tonic::Status>
        {
            self.mutate().await;
            Ok(tonic::Response::new(pb::DeleteGuardedFlowSpecResponse {
                outcome: 1,
            }))
        }
        async fn delete_flow_spec(
            &self,
            _: Request<pb::DeleteFlowSpecRequest>,
        ) -> std::result::Result<tonic::Response<pb::DeleteFlowSpecResponse>, tonic::Status>
        {
            self.global_present.store(false, SeqCst);
            Ok(tonic::Response::new(pb::DeleteFlowSpecResponse {
                outcome: 1,
            }))
        }
    }

    fn stamp() -> GuardedStamp {
        GuardedStamp {
            incarnation: 1,
            sequence: 1,
        }
    }

    fn scoped_rule() -> GuardedRule {
        let mut rule = decode_guarded(route(), 3).unwrap().rule;
        rule.nlri.scope =
            Some(VpnFlowSpecIdentity::new(VpnFlowSpecFamily::Ipv4, "44407:40").unwrap());
        rule.route_targets = vec!["44407:777".into()];
        rule
    }

    async fn fixture() -> (
        Arc<RustBgpdAnnouncer>,
        Service,
        tokio::task::JoinHandle<std::result::Result<(), tonic::transport::Error>>,
    ) {
        let service = Service::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let incoming = futures_util::stream::unfold(listener, |listener| async move {
            Some((listener.accept().await.map(|(stream, _)| stream), listener))
        });
        let server = tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(pb::rib_service_server::RibServiceServer::new(
                    service.clone(),
                ))
                .add_service(pb::injection_service_server::InjectionServiceServer::new(
                    service.clone(),
                ))
                .serve_with_incoming(incoming),
        );
        let channel = Endpoint::from_shared(format!("http://{address}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        (
            Arc::new(RustBgpdAnnouncer::new(channel, None)),
            service,
            server,
        )
    }

    async fn operation(speaker: &RustBgpdAnnouncer, rule: &GuardedRule, kind: u8) -> Result<()> {
        match kind {
            0 => speaker.validate_scope(rule.nlri.scope.as_ref()).await,
            1 => speaker.issue_window(&rule.owner, 30).await.map(|_| ()),
            2 => speaker.add_guarded(rule, stamp(), 30).await.map(|_| ()),
            3 => speaker
                .renew_guarded(&rule.owner, stamp(), stamp(), 30)
                .await
                .map(|_| ()),
            4 => speaker.delete_guarded(rule).await,
            _ => unreachable!(),
        }
    }

    #[tokio::test]
    async fn stalled_probes_release_caller_locks_without_guarded_mutation() {
        for kind in 0..5 {
            let (speaker, service, server) = fixture().await;
            let rule = scoped_rule();
            speaker.register_scope(rule.nlri.scope.as_ref()).unwrap();
            service.mode.store(1, SeqCst);
            service.global_present.store(true, SeqCst);
            // These caller locks model the runtime/admission guards held at the
            // production prepare, re-arm and withdrawal awaits.
            let runtime = Arc::new(Mutex::new(()));
            let lifecycle = Arc::new(Mutex::new(()));
            let held = (runtime.clone(), lifecycle.clone());
            let blocked_speaker = speaker.clone();
            let blocked = tokio::spawn(async move {
                let _runtime = held.0.lock().await;
                let _lifecycle = held.1.lock().await;
                let result = operation(&blocked_speaker, &rule, kind).await;
                (result, tokio::time::Instant::now())
            });
            service.probe_entered.notified().await;
            let unrelated_speaker = speaker.clone();
            let dispatch = Arc::new(Notify::new());
            let resume_dispatch = dispatch.clone();
            let unrelated = tokio::spawn(async move {
                let _lifecycle = lifecycle.lock().await;
                // Network I/O resumes on real time after the paused deadline assertion.
                resume_dispatch.notified().await;
                unrelated_speaker
                    .withdraw(&FlowSpecRule::new(
                        FlowSpecNlri {
                            dst_prefix: "192.0.2.2/32".into(),
                            ..Default::default()
                        },
                        FlowSpecAction::discard(),
                    ))
                    .await
            });
            tokio::time::pause();
            let started = tokio::time::Instant::now();
            let (result, completed) = blocked.await.unwrap();
            let error = result.unwrap_err();
            // Tokio 1.53.3 runtime/time/mod.rs documents at most 1 ms upward timer rounding.
            assert!(
                completed.duration_since(started)
                    <= GUARDED_RPC_DEADLINE + Duration::from_millis(1),
                "operation {kind}: completed after {:?}, current clock {:?}",
                completed.duration_since(started),
                started.elapsed()
            );
            assert!(!matches!(
                error,
                PrefixdError::UnsupportedFlowSpecScope { .. }
            ));
            assert_eq!(service.guarded_mutations.load(SeqCst), 0);
            tokio::time::resume();
            dispatch.notify_one();
            unrelated.await.unwrap().unwrap();
            assert!(
                !service.global_present.load(SeqCst),
                "queued global withdrawal made progress"
            );
            service.mode.store(0, SeqCst);
            assert_eq!(
                speaker
                    .renew_guarded("unrelated-owner", stamp(), stamp(), 30)
                    .await
                    .unwrap(),
                30_000
            );
            server.abort();
            let _ = server.await;
        }
    }

    #[tokio::test]
    async fn slow_probe_and_mutation_share_one_guarded_deadline() {
        let (speaker, service, server) = fixture().await;
        service.mode.store(2, SeqCst);
        let rule = scoped_rule();
        let caller = tokio::spawn(async move { speaker.add_guarded(&rule, stamp(), 30).await });
        service.probe_entered.notified().await;
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::time::resume();
        service.mutation_entered.notified().await;
        tokio::time::pause();
        let started = tokio::time::Instant::now();
        assert!(caller.await.unwrap().is_err());
        assert!(started.elapsed() <= Duration::from_secs(1));
        assert_eq!(service.guarded_mutations.load(SeqCst), 1);
        assert_eq!(service.completed_mutations.load(SeqCst), 0);
        tokio::time::resume();
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn owner_probes_share_one_deadline_across_both_families() {
        for kind in [1, 3] {
            let (speaker, service, server) = fixture().await;
            let rule = scoped_rule();
            speaker.register_scope(rule.nlri.scope.as_ref()).unwrap();
            speaker
                .register_scope(Some(
                    &VpnFlowSpecIdentity::new(VpnFlowSpecFamily::Ipv6, "44407:41").unwrap(),
                ))
                .unwrap();
            service.mode.store(6, SeqCst);
            let caller = tokio::spawn(async move { operation(&speaker, &rule, kind).await });
            service.probe_entered.notified().await;
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(2)).await;
            tokio::time::resume();
            service.second_probe_entered.notified().await;
            tokio::time::pause();
            let started = tokio::time::Instant::now();
            assert!(caller.await.unwrap().is_err());
            assert!(started.elapsed() <= Duration::from_secs(1));
            assert_eq!(service.guarded_mutations.load(SeqCst), 0);
            tokio::time::resume();
            server.abort();
            let _ = server.await;
        }
    }

    #[tokio::test]
    async fn guarded_probe_refusal_remains_distinct_from_auth_and_transport_failure() {
        let (speaker, service, server) = fixture().await;
        let rule = scoped_rule();
        for mode in [3, 4, 5] {
            service.mode.store(mode, SeqCst);
            let error = speaker.add_guarded(&rule, stamp(), 30).await.unwrap_err();
            assert_eq!(
                matches!(error, PrefixdError::UnsupportedFlowSpecScope { .. }),
                mode == 3
            );
            assert!(!error.to_string().contains("private diagnostic"));
            assert_eq!(service.guarded_mutations.load(SeqCst), 0);
        }
        server.abort();
        let _ = server.await;
    }
}
