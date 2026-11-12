use super::super::apipb::{
    AddPathResponse, DeletePathResponse, Destination, ListPathResponse, ListPeerResponse, Peer,
    PeerConf, PeerState,
};
use super::*;
use futures_util::{Stream, StreamExt};
use std::collections::VecDeque;
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::task::{Context, Poll};
use tonic::codegen::{BoxFuture, Service, http};
use tonic::{Request, Response, Status};

fn speaker() -> GoBgpAnnouncer {
    GoBgpAnnouncer::new("unused".into())
}

fn peer_row(address: &str, state: i32) -> ListPeerResponse {
    ListPeerResponse {
        peer: Some(Peer {
            conf: Some(PeerConf {
                neighbor_address: address.into(),
                ..Default::default()
            }),
            state: Some(PeerState {
                session_state: state,
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
}

fn rule(prefix: &str) -> FlowSpecRule {
    FlowSpecRule::new(
        FlowSpecNlri {
            dst_prefix: prefix.into(),
            protocol: Some(17),
            dst_ports: vec![53, 443, 65535],
            ..Default::default()
        },
        FlowSpecAction::police(1_000_000),
    )
}

fn path(prefix: &str) -> Path {
    speaker().build_flowspec_path(&rule(prefix)).unwrap()
}

fn row(paths: Vec<Path>) -> ListPathResponse {
    ListPathResponse {
        destination: Some(Destination {
            paths,
            ..Default::default()
        }),
    }
}

fn components(path: &mut Path) -> &mut Vec<ProtoFlowSpecRule> {
    let Some(nlri::Nlri::FlowSpec(nlri)) = &mut path.nlri.as_mut().unwrap().nlri else {
        panic!("fixture must contain FlowSpec");
    };
    &mut nlri.rules
}

fn component(path: &mut Path, index: usize) -> &mut FlowSpecComponent {
    let Some(flow_spec_rule::Rule::Component(component)) = &mut components(path)[index].rule else {
        panic!("fixture must contain numeric component");
    };
    component
}

fn prefix(path: &mut Path) -> &mut FlowSpecIpPrefix {
    let Some(flow_spec_rule::Rule::IpPrefix(prefix)) = &mut components(path)[0].rule else {
        panic!("fixture must contain destination");
    };
    prefix
}

fn communities(path: &mut Path) -> &mut Vec<ExtendedCommunity> {
    path.pattrs
        .iter_mut()
        .find_map(|attr| match &mut attr.attr {
            Some(attribute::Attr::ExtendedCommunities(ext)) => Some(&mut ext.communities),
            _ => None,
        })
        .unwrap()
}

fn rate(path: &mut Path) -> &mut TrafficRateExtended {
    let Some(extended_community::Extcom::TrafficRate(rate)) = &mut communities(path)[0].extcom
    else {
        panic!("fixture must contain traffic rate");
    };
    rate
}

#[test]
fn source_prefix_encodes_before_protocol_and_strictly_decodes() {
    for (destination, source, canonical) in [
        ("192.0.2.1/32", "198.51.100.129/24", "198.51.100.0/24"),
        ("2001:db8::1/128", "2001:DB8:1::1/48", "2001:db8:1::/48"),
        ("192.0.2.1/32", "0.0.0.0/0", "0.0.0.0/0"),
        ("2001:db8::1/128", "::/0", "::/0"),
    ] {
        let mut wanted = rule(destination);
        wanted.nlri.src_prefix = Some(source.into());
        // TCP is valid with source prefixes; ADR028's UDP restriction is independent.
        wanted.nlri.protocol = Some(6);
        let mut path = speaker().build_flowspec_path(&wanted).unwrap();
        let withdrawal = speaker()
            .build_flowspec_withdraw_path(&wanted.nlri)
            .unwrap();
        assert_eq!(path.nlri, withdrawal.nlri);
        let source = components(&mut path)[1].clone();
        let Some(flow_spec_rule::Rule::IpPrefix(prefix)) = source.rule else {
            panic!("source prefix expected")
        };
        let net: ipnet::IpNet = canonical.parse().unwrap();
        assert_eq!(
            (
                prefix.r#type,
                prefix.prefix_len,
                prefix.offset,
                prefix.prefix.as_str()
            ),
            (
                2,
                u32::from(net.prefix_len()),
                0,
                net.addr().to_string().as_str()
            )
        );
        let decoded = speaker().parse_flowspec_path(&path).unwrap();
        assert_eq!(decoded.nlri.src_prefix.as_deref(), Some(canonical));
        assert_eq!(decoded.nlri_hash(), wanted.nlri_hash());
        assert!(speaker().matches_nlri(&wanted.nlri, &decoded.nlri).unwrap());
        let base = path;
        for case in 0..8 {
            let mut bad = base.clone();
            let Some(flow_spec_rule::Rule::IpPrefix(prefix)) = &mut components(&mut bad)[1].rule
            else {
                unreachable!()
            };
            match case {
                0 => prefix.offset = 1,
                1 => prefix.prefix_len = 129,
                2 => prefix.prefix = "invalid".into(),
                3 => {
                    prefix.prefix = if destination.contains(':') {
                        "198.51.100.0"
                    } else {
                        "2001:db8::"
                    }
                    .into()
                }
                4 => prefix.r#type = 4,
                5 => {
                    prefix.prefix = if destination.contains(':') {
                        "2001:db8:1::1"
                    } else {
                        "198.51.100.1"
                    }
                    .into()
                }
                6 => {
                    let duplicate = components(&mut bad)[1].clone();
                    components(&mut bad).insert(2, duplicate);
                }
                7 => {
                    components(&mut bad).remove(0);
                }
                _ => unreachable!(),
            }
            // /0 with a nonzero address is also rejected as noncanonical read-back.
            assert!(
                speaker().parse_flowspec_path(&bad).is_err(),
                "{destination} source mutation {case}"
            );
        }
        let mut absent = wanted.clone();
        absent.nlri.src_prefix = None;
        assert!(!speaker().matches_nlri(&wanted.nlri, &absent.nlri).unwrap());
        for source in [
            "invalid",
            "192.0.2.0/33",
            if destination.contains(':') {
                "198.51.100.0/24"
            } else {
                "2001:db8::/64"
            },
        ] {
            wanted.nlri.src_prefix = Some(source.into());
            assert!(speaker().build_flowspec_path(&wanted).is_err());
            assert!(
                speaker()
                    .build_flowspec_withdraw_path(&wanted.nlri)
                    .is_err()
            );
            assert!(speaker().matches_nlri(&wanted.nlri, &absent.nlri).is_err());
        }
    }
}

#[test]
fn rejects_unrepresentable_local_matches() {
    let mutations: &[fn(&mut Path)] = &[
        |p| p.nlri = None,
        |p| p.nlri.as_mut().unwrap().nlri = None,
        |p| components(p).clear(),
        |p| components(p)[0].rule = None,
        |p| prefix(p).r#type = 2,
        |p| prefix(p).prefix = "not-an-address".into(),
        |p| prefix(p).prefix_len = 33,
        |p| prefix(p).offset = 1,
        |p| component(p, 1).r#type = 4,
        |p| component(p, 1).items.clear(),
        |p| {
            component(p, 1)
                .items
                .push(FlowSpecComponentItem { op: 0x81, value: 6 })
        },
        |p| component(p, 1).items[0].value = 256,
        |p| component(p, 2).items[0].value = 65536,
        |p| component(p, 2).items.clear(),
        |p| component(p, 2).items[0].op = 0x81,
        |p| component(p, 2).items.last_mut().unwrap().op = 0x01,
        |p| {
            let duplicate = components(p)[1].clone();
            components(p).push(duplicate);
        },
        |p| components(p).swap(1, 2),
        |p| p.family = None,
        |p| p.family.as_mut().unwrap().afi = AFI_IP6,
        |p| p.family.as_mut().unwrap().safi = 1,
        |p| p.is_withdraw = true,
    ];
    for (index, mutate) in mutations.iter().enumerate() {
        let mut p = path("192.0.2.1/32");
        mutate(&mut p);
        assert!(
            speaker().parse_flowspec_path(&p).is_err(),
            "mutation {index}"
        );
    }
    for op in [0, 0x01, 0x82, 0x83, 0xc1, 0x89, 0x181] {
        let mut p = path("192.0.2.1/32");
        component(&mut p, 1).items[0].op = op;
        assert!(
            speaker().parse_flowspec_path(&p).is_err(),
            "operator {op:#x}"
        );
    }
    let mut p = path("2001:db8::1/128");
    prefix(&mut p).prefix_len = 129;
    assert!(speaker().parse_flowspec_path(&p).is_err());
}

#[tokio::test]
async fn malformed_source_prefix_fails_the_complete_inventory() {
    let mut wanted = rule("192.0.2.1/32");
    wanted.nlri.src_prefix = Some("198.51.100.0/24".into());
    let mut bad = speaker().build_flowspec_path(&wanted).unwrap();
    let Some(flow_spec_rule::Rule::IpPrefix(source)) = &mut components(&mut bad)[1].rule else {
        unreachable!()
    };
    source.offset = 1;
    let fake = inventory(vec![
        (AFI_IP, Ok(vec![row(vec![path("192.0.2.2/32"), bad])])),
        (AFI_IP6, Ok(vec![])),
    ]);
    let (speaker, _server) = serve(fake).await;
    assert!(speaker.list_active().await.is_err());
}

#[test]
fn wire_width_bits_and_standard_path_attributes_preserve_matches() {
    use super::super::apipb::{
        AsPathAttribute, CommunitiesAttribute, LocalPrefAttribute, MultiExitDiscAttribute,
    };
    for destination in ["192.0.2.1/32", "2001:db8::1/128"] {
        let mut p = path(destination);
        component(&mut p, 1).items[0].op |= 0x30;
        component(&mut p, 2).items[1].op |= 0x10;
        p.pattrs.extend(
            [
                attribute::Attr::AsPath(AsPathAttribute::default()),
                attribute::Attr::LocalPref(LocalPrefAttribute { local_pref: 100 }),
                attribute::Attr::MultiExitDisc(MultiExitDiscAttribute { med: 10 }),
                attribute::Attr::Communities(CommunitiesAttribute {
                    communities: vec![65535],
                }),
            ]
            .into_iter()
            .map(|attr| Attribute { attr: Some(attr) }),
        );
        let decoded = speaker().parse_flowspec_path(&p).unwrap();
        assert_eq!(decoded.nlri_hash(), rule(destination).nlri_hash());
        assert_eq!(decoded.actions[0].rate_bps, Some(1_000_000));
    }
}

#[test]
fn traffic_rates_convert_before_integer_range_checks() {
    for (wire, expected) in [
        (0.0, None),
        (0.125, Some(1)),
        (1.5, Some(12)),
        (125_000.0, Some(1_000_000)),
        (2.0_f32.powi(60), Some(1_u64 << 63)),
    ] {
        let mut p = path("192.0.2.1/32");
        rate(&mut p).rate = wire;
        let action = &speaker().parse_flowspec_path(&p).unwrap().actions[0];
        assert_eq!(action.rate_bps, expected);
        assert_eq!(
            action.action_type,
            if expected.is_some() {
                ActionType::Police
            } else {
                ActionType::Discard
            }
        );
    }
    for wire in [
        f32::NAN,
        f32::INFINITY,
        f32::NEG_INFINITY,
        -1.0,
        0.1,
        f32::MIN_POSITIVE,
        2.0_f32.powi(61),
        f32::MAX,
    ] {
        let mut p = path("192.0.2.1/32");
        rate(&mut p).rate = wire;
        assert!(speaker().parse_flowspec_path(&p).is_err(), "rate {wire}");
    }
}

#[test]
fn rejects_missing_ambiguous_and_unsupported_actions() {
    use super::super::apipb::{TrafficActionExtended, TrafficRemarkExtended};
    let mutations: &[fn(&mut Path)] = &[
        |p| p.pattrs.clear(),
        |p| rate(p).asn = 65536,
        |p| communities(p).clear(),
        |p| communities(p)[0].extcom = None,
        |p| {
            let duplicate = communities(p)[0].clone();
            communities(p).push(duplicate);
        },
        |p| {
            communities(p).push(ExtendedCommunity {
                extcom: Some(extended_community::Extcom::TrafficAction(
                    TrafficActionExtended {
                        terminal: true,
                        sample: false,
                    },
                )),
            })
        },
        |p| {
            communities(p).push(ExtendedCommunity {
                extcom: Some(extended_community::Extcom::TrafficRemark(
                    TrafficRemarkExtended { dscp: 4 },
                )),
            })
        },
        |p| p.pattrs.push(Attribute { attr: None }),
        |p| {
            p.pattrs.push(Attribute {
                attr: Some(attribute::Attr::Ip6ExtendedCommunities(Default::default())),
            })
        },
    ];
    for (index, mutate) in mutations.iter().enumerate() {
        let mut p = path("192.0.2.1/32");
        mutate(&mut p);
        assert!(
            speaker().parse_flowspec_path(&p).is_err(),
            "mutation {index}"
        );
    }
}

// Minimal real gRPC service for the two read RPCs; production proto generation stays client-only.
type RpcStream<T> = Pin<Box<dyn Stream<Item = std::result::Result<T, Status>> + Send>>;

type PathReply = (i32, std::result::Result<Vec<ListPathResponse>, Status>);

#[derive(Clone, Default)]
struct Fake {
    paths: Arc<Mutex<VecDeque<PathReply>>>,
    peers: Vec<ListPeerResponse>,
    stream_error: bool,
    tail: Tail,
    delay_ipv4: bool,
    polled: Arc<tokio::sync::Notify>,
    polls: Arc<AtomicUsize>,
    adds: Arc<Mutex<Vec<AddPathRequest>>>,
    deletes: Arc<Mutex<Vec<DeletePathRequest>>>,
}

#[derive(Clone, Copy, Default)]
enum Tail {
    #[default]
    Finish,
    Stall,
    Trickle,
}

impl Fake {
    fn stream<T: Clone + Send + 'static>(&self, rows: Vec<T>) -> RpcStream<T> {
        let tail = self.tail;
        let polled = self.polled.clone();
        let polls = self.polls.clone();
        let last = rows.last().cloned();
        let rows = futures_util::stream::iter(rows.into_iter().map(Ok));
        let stream_error = self.stream_error;
        let end = futures_util::stream::unfold((), move |()| {
            let polled = polled.clone();
            let polls = polls.clone();
            let last = last.clone();
            async move {
                polls.fetch_add(1, SeqCst);
                polled.notify_one();
                if stream_error {
                    return Some((Err(Status::data_loss("error after rows")), ()));
                }
                match tail {
                    Tail::Finish => None,
                    Tail::Stall => std::future::pending().await,
                    Tail::Trickle => {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        Some((Ok(last.expect("trickle needs a row")), ()))
                    }
                }
            }
        });
        Box::pin(rows.chain(end))
    }
}

impl tonic::server::ServerStreamingService<ListPathRequest> for Fake {
    type Response = ListPathResponse;
    type ResponseStream = RpcStream<ListPathResponse>;
    type Future = BoxFuture<Response<Self::ResponseStream>, Status>;

    fn call(&mut self, request: Request<ListPathRequest>) -> Self::Future {
        let request = request.into_inner();
        assert_eq!(request.table_type, TableType::Global as i32);
        let family = request.family.unwrap();
        assert_eq!(family.safi, SAFI_FLOWSPEC);
        let (expected_afi, result) = self
            .paths
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected ListPath request");
        assert_eq!(family.afi, expected_afi);
        let mut fake = self.clone();
        Box::pin(async move {
            if fake.delay_ipv4 && family.afi == AFI_IP {
                fake.polled.notify_one();
                tokio::time::sleep(Duration::from_secs(20)).await;
                fake.tail = Tail::Finish;
            }
            Ok(Response::new(fake.stream(result?)))
        })
    }
}

impl tonic::server::ServerStreamingService<ListPeerRequest> for Fake {
    type Response = ListPeerResponse;
    type ResponseStream = RpcStream<ListPeerResponse>;
    type Future = BoxFuture<Response<Self::ResponseStream>, Status>;

    fn call(&mut self, _request: Request<ListPeerRequest>) -> Self::Future {
        let stream = self.stream(self.peers.clone());
        // Keep trickled rows valid; duplicate peers would fail before the deadline.
        let stream: RpcStream<ListPeerResponse> = if matches!(self.tail, Tail::Trickle) {
            Box::pin(stream.enumerate().map(|(index, row)| {
                row.map(|mut row| {
                    row.peer
                        .as_mut()
                        .unwrap()
                        .conf
                        .as_mut()
                        .unwrap()
                        .neighbor_address = format!("192.0.2.{}", index + 1);
                    row
                })
            }))
        } else {
            stream
        };
        Box::pin(async move { Ok(Response::new(stream)) })
    }
}

impl tonic::server::UnaryService<AddPathRequest> for Fake {
    type Response = AddPathResponse;
    type Future = BoxFuture<Response<Self::Response>, Status>;
    fn call(&mut self, request: Request<AddPathRequest>) -> Self::Future {
        self.adds.lock().unwrap().push(request.into_inner());
        Box::pin(async { Ok(Response::new(AddPathResponse::default())) })
    }
}

impl tonic::server::UnaryService<DeletePathRequest> for Fake {
    type Response = DeletePathResponse;
    type Future = BoxFuture<Response<Self::Response>, Status>;
    fn call(&mut self, request: Request<DeletePathRequest>) -> Self::Future {
        self.deletes.lock().unwrap().push(request.into_inner());
        Box::pin(async { Ok(Response::new(DeletePathResponse::default())) })
    }
}

impl Service<http::Request<tonic::body::Body>> for Fake {
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<tonic::body::Body>) -> Self::Future {
        let fake = self.clone();
        Box::pin(async move {
            let response = match request.uri().path() {
                "/api.GoBgpService/AddPath" => {
                    tonic::server::Grpc::new(tonic_prost::ProstCodec::<
                        AddPathResponse,
                        AddPathRequest,
                    >::default())
                    .unary(fake, request)
                    .await
                }
                "/api.GoBgpService/DeletePath" => {
                    tonic::server::Grpc::new(tonic_prost::ProstCodec::<
                        DeletePathResponse,
                        DeletePathRequest,
                    >::default())
                    .unary(fake, request)
                    .await
                }
                "/api.GoBgpService/ListPath" => {
                    tonic::server::Grpc::new(tonic_prost::ProstCodec::<
                        ListPathResponse,
                        ListPathRequest,
                    >::default())
                    .server_streaming(fake, request)
                    .await
                }
                "/api.GoBgpService/ListPeer" => {
                    tonic::server::Grpc::new(tonic_prost::ProstCodec::<
                        ListPeerResponse,
                        ListPeerRequest,
                    >::default())
                    .server_streaming(fake, request)
                    .await
                }
                other => panic!("unexpected RPC {other}"),
            };
            Ok(response)
        })
    }
}

impl tonic::server::NamedService for Fake {
    const NAME: &'static str = "api.GoBgpService";
}

struct Server(tokio::task::JoinHandle<std::result::Result<(), tonic::transport::Error>>);

impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn serve(fake: Fake) -> (GoBgpAnnouncer, Server) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let incoming = futures_util::stream::unfold(listener, |listener| async {
        Some((listener.accept().await.map(|(stream, _)| stream), listener))
    });
    let server = Server(tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(fake)
            .serve_with_incoming(incoming),
    ));
    let mut speaker = GoBgpAnnouncer::new(address.to_string());
    speaker.connect().await.unwrap();
    (speaker, server)
}

fn inventory(responses: Vec<PathReply>) -> Fake {
    Fake {
        paths: Arc::new(Mutex::new(responses.into())),
        ..Default::default()
    }
}

#[tokio::test]
async fn invalid_actions_never_announce_but_can_withdraw_the_exact_match() {
    let fake = Fake::default();
    let adds = fake.adds.clone();
    let deletes = fake.deletes.clone();
    let (speaker, _server) = serve(fake).await;
    for (prefix, afi) in [
        ("192.0.2.1/32", AFI_IP),
        ("2001:0DB8:0:0:0:0:0:1/128", AFI_IP6),
    ] {
        let mut historical = rule(prefix);
        let expected_nlri = speaker.build_flowspec_path(&historical).unwrap().nlri;
        let mut foreign = historical.clone();
        foreign.nlri.dst_ports = vec![54];
        let foreign_nlri = speaker.build_flowspec_path(&foreign).unwrap().nlri;
        for actions in [
            vec![],
            vec![FlowSpecAction::discard(), FlowSpecAction::police(8)],
            vec![FlowSpecAction {
                dscp: None,
                action_type: ActionType::Police,
                rate_bps: None,
            }],
            vec![FlowSpecAction::mark(0)],
            vec![FlowSpecAction::mark(63)],
            vec![FlowSpecAction {
                action_type: ActionType::Mark,
                dscp: None,
                rate_bps: Some(8),
            }],
            vec![FlowSpecAction::mark(64)],
            vec![FlowSpecAction::police(0)],
            vec![FlowSpecAction::police(16_777_217)],
            vec![FlowSpecAction::police(u64::MAX)],
            vec![FlowSpecAction {
                dscp: None,
                action_type: ActionType::Discard,
                rate_bps: Some(8),
            }],
        ] {
            historical.actions = actions;
            assert!(speaker.announce(&historical).await.is_err());
            assert!(adds.lock().unwrap().is_empty());
            speaker.withdraw(&historical).await.unwrap();
            let request = deletes.lock().unwrap().pop().unwrap();
            assert_eq!(request.table_type, TableType::Global as i32);
            assert!(request.uuid.is_empty());
            assert!(request.vrf_id.is_empty());
            let path = request.path.expect("never request family-wide deletion");
            assert_eq!(path.nlri, expected_nlri);
            assert_ne!(path.nlri, foreign_nlri);
            assert_eq!(
                path.family,
                Some(Family {
                    afi,
                    safi: SAFI_FLOWSPEC
                })
            );
            assert_eq!(request.family, path.family);
            assert!(path.is_withdraw);
            assert!(path.pattrs.is_empty());
            assert_eq!(path.source_asn, 0);
            assert!(path.source_id.is_empty());
            assert!(path.neighbor_ip.is_empty());
            assert_eq!(path.identifier, 0);
        }
    }
}

#[tokio::test]
async fn either_family_failure_fails_whole_inventory() {
    for failed_afi in [AFI_IP, AFI_IP6] {
        let mut requests = vec![];
        if failed_afi == AFI_IP6 {
            requests.push((AFI_IP, Ok(vec![row(vec![path("192.0.2.1/32")])])));
        }
        requests.push((failed_afi, Err(Status::unavailable("family failed"))));
        let (speaker, _server) = serve(inventory(requests)).await;
        assert!(
            speaker
                .list_active()
                .await
                .unwrap_err()
                .to_string()
                .contains("family failed")
        );
    }
}

#[tokio::test]
async fn valid_rows_then_stream_error_fail_inventory_and_peers() {
    let mut fake = inventory(vec![(AFI_IP, Ok(vec![row(vec![path("192.0.2.1/32")])]))]);
    fake.stream_error = true;
    fake.peers = vec![peer_row("192.0.2.1", 6)];
    let (speaker, _server) = serve(fake).await;
    assert!(
        speaker
            .list_active()
            .await
            .unwrap_err()
            .to_string()
            .contains("error after rows")
    );
    assert!(
        speaker
            .session_status()
            .await
            .unwrap_err()
            .to_string()
            .contains("error after rows")
    );
}

#[tokio::test]
async fn local_paths_need_neither_uuid_nor_best_and_remote_rows_are_not_decoded() {
    let mut local = path("192.0.2.1/32");
    local.source_asn = 65010;
    assert!(local.uuid.is_empty());
    assert!(!local.best);
    let remote = Path {
        neighbor_ip: "198.51.100.1".into(),
        best: true,
        ..Default::default()
    };
    let sentinel_is_remote = Path {
        neighbor_ip: "0.0.0.0".into(),
        ..Default::default()
    };
    let fake = inventory(vec![
        (
            AFI_IP,
            Ok(vec![row(vec![remote, local, sentinel_is_remote])]),
        ),
        (AFI_IP6, Ok(vec![row(vec![path("2001:db8::1/128")])])),
    ]);
    let requests = fake.paths.clone();
    let (speaker, _server) = serve(fake).await;
    let rules = speaker.list_active().await.unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].nlri_hash(), rule("192.0.2.1/32").nlri_hash());
    assert_eq!(rules[1].nlri_hash(), rule("2001:db8::1/128").nlri_hash());
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn malformed_local_rows_never_return_partial_success() {
    let mut unsupported = path("192.0.2.2/32");
    prefix(&mut unsupported).r#type = 2;
    let mut wrong_family = path("2001:db8::1/128");
    wrong_family.family.as_mut().unwrap().afi = AFI_IP;
    let mut no_action = path("192.0.2.2/32");
    no_action.pattrs.clear();
    for malformed in [
        ListPathResponse::default(),
        row(vec![Path::default()]),
        row(vec![unsupported]),
        row(vec![wrong_family]),
        row(vec![no_action]),
    ] {
        let fake = inventory(vec![(
            AFI_IP,
            Ok(vec![row(vec![path("192.0.2.1/32")]), malformed]),
        )]);
        let (speaker, _server) = serve(fake).await;
        assert!(speaker.list_active().await.is_err());
    }
}

#[tokio::test]
async fn peers_keep_addresses_as_identity() {
    let addresses = ["192.0.2.1", "192.0.2.2", "2001:db8::1", "fe80::1%eth0"];
    let fake = Fake {
        peers: addresses
            .into_iter()
            .map(|address| ListPeerResponse {
                peer: Some(Peer {
                    conf: Some(PeerConf {
                        neighbor_address: address.into(),
                        description: "same description".into(),
                        ..Default::default()
                    }),
                    state: Some(PeerState {
                        session_state: 6,
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
            })
            .collect(),
        ..Default::default()
    };
    let (speaker, _server) = serve(fake).await;
    let peers = speaker.session_status().await.unwrap();
    assert_eq!(peers.len(), addresses.len());
    for (peer, address) in peers.iter().zip(addresses) {
        assert_eq!(peer.name, address);
        assert_eq!(peer.address, address);
        assert_eq!(peer.state, SessionState::Established);
    }
}

#[tokio::test]
async fn malformed_peer_rows_fail_the_whole_observation() {
    for case in 0..7 {
        let good = peer_row("192.0.2.1", 6);
        let mut bad = peer_row("192.0.2.2", 1);
        match case {
            0 => bad.peer = None,
            1 => bad.peer.as_mut().unwrap().conf = None,
            2 => bad
                .peer
                .as_mut()
                .unwrap()
                .conf
                .as_mut()
                .unwrap()
                .neighbor_address
                .clear(),
            3 => bad.peer.as_mut().unwrap().state = None,
            4 => {
                bad.peer
                    .as_mut()
                    .unwrap()
                    .state
                    .as_mut()
                    .unwrap()
                    .session_state = 0
            }
            5 => {
                bad.peer
                    .as_mut()
                    .unwrap()
                    .state
                    .as_mut()
                    .unwrap()
                    .session_state = 7
            }
            6 => bad = good.clone(),
            _ => unreachable!(),
        }
        let (speaker, _server) = serve(Fake {
            peers: vec![good, bad],
            ..Default::default()
        })
        .await;
        assert!(
            speaker.session_status().await.is_err(),
            "malformed peer case {case}"
        );
    }
}

#[tokio::test]
async fn configured_down_peers_preserve_their_reported_state() {
    let states = [
        SessionState::Idle,
        SessionState::Connect,
        SessionState::Active,
        SessionState::OpenSent,
        SessionState::OpenConfirm,
        SessionState::Established,
    ];
    let (speaker, _server) = serve(Fake {
        peers: (1..=6)
            .map(|state| peer_row(&format!("192.0.2.{state}"), state))
            .collect(),
        ..Default::default()
    })
    .await;
    let observed = speaker.session_status().await.unwrap();
    assert_eq!(observed.len(), states.len());
    for (peer, state) in observed.iter().zip(states) {
        assert_eq!(peer.state, state);
    }
}

async fn assert_stream_deadline(peers: bool, tail: Tail) {
    let mut fake = inventory(vec![(AFI_IP, Ok(vec![row(vec![path("192.0.2.1/32")])]))]);
    fake.peers = vec![peer_row("192.0.2.1", 6)];
    if matches!(tail, Tail::Stall) {
        fake.paths.lock().unwrap()[0].1 = Ok(vec![]);
        fake.peers.clear();
    }
    fake.tail = tail;
    let polled = fake.polled.clone();
    let polls = fake.polls.clone();
    let (speaker, _server) = serve(fake).await;
    let call = tokio::spawn(async move {
        if peers {
            speaker.session_status().await.map(|_| ())
        } else {
            speaker.list_active().await.map(|_| ())
        }
    });
    // Wait for the real server to poll the body before controlling the clock.
    tokio::time::timeout(Duration::from_secs(5), polled.notified())
        .await
        .unwrap();
    tokio::time::pause();
    for expected in 2..=5 {
        tokio::time::advance(Duration::from_secs(6)).await;
        if matches!(tail, Tail::Trickle) {
            // Keep the runtime runnable so socket progress cannot auto-advance the paused clock.
            for _ in 0..10_000 {
                if polls.load(SeqCst) >= expected {
                    break;
                }
                tokio::task::yield_now().await;
            }
            assert!(
                polls.load(SeqCst) >= expected,
                "server must keep trickling before the deadline"
            );
        }
        assert!(!call.is_finished(), "observation ended before the deadline");
    }
    tokio::time::advance(Duration::from_secs(5)).await;
    assert!(!call.is_finished(), "observation ended before the deadline");
    tokio::time::advance(Duration::from_secs(1)).await;
    let result = tokio::time::timeout(Duration::from_secs(1), call)
        .await
        .expect("complete stream must finish at its deadline")
        .unwrap();
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("observation deadline exceeded")
    );
    tokio::time::resume();
}

#[tokio::test]
async fn list_path_deadline_bounds_stalled_body() {
    assert_stream_deadline(false, Tail::Stall).await;
}

#[tokio::test]
async fn list_path_deadline_bounds_trickling_rows() {
    assert_stream_deadline(false, Tail::Trickle).await;
}

#[tokio::test]
async fn list_peer_deadline_bounds_stalled_body() {
    assert_stream_deadline(true, Tail::Stall).await;
}

#[tokio::test]
async fn list_peer_deadline_bounds_trickling_rows() {
    assert_stream_deadline(true, Tail::Trickle).await;
}

#[tokio::test]
async fn list_path_deadline_is_shared_across_both_families() {
    let mut fake = inventory(vec![
        (AFI_IP, Ok(vec![row(vec![path("192.0.2.1/32")])])),
        (AFI_IP6, Ok(vec![])),
    ]);
    fake.delay_ipv4 = true;
    fake.tail = Tail::Stall;
    let polled = fake.polled.clone();
    let polls = fake.polls.clone();
    let (speaker, _server) = serve(fake).await;
    let call = tokio::spawn(async move { speaker.list_active().await });
    tokio::time::timeout(Duration::from_secs(5), polled.notified())
        .await
        .unwrap();
    tokio::time::pause();
    tokio::time::advance(Duration::from_millis(20_010)).await;
    for _ in 0..10_000 {
        if polls.load(SeqCst) == 2 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(polls.load(SeqCst), 2, "both family streams must have begun");
    tokio::time::advance(Duration::from_millis(8_990)).await;
    assert!(!call.is_finished());
    tokio::time::advance(Duration::from_secs(1)).await;
    let result = tokio::time::timeout(Duration::from_secs(1), call)
        .await
        .expect("second AFI must use the original deadline")
        .unwrap();
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("observation deadline exceeded")
    );
    tokio::time::resume();
}

/// GoBGP's own normalization on read-back: `NewFlowSpecComponent` sets end-of-list
/// on the last item and `NewFlowSpecComponentItem` sets the value-width bits.
fn gobgp_read_back(path: &mut Path) {
    for rule in components(path) {
        if let Some(flow_spec_rule::Rule::Component(component)) = &mut rule.rule {
            let last = component.items.len() - 1;
            for (index, item) in component.items.iter_mut().enumerate() {
                item.op |= if item.value > 0xff { 0x10 } else { 0 };
                item.op |= if index == last { 0x80 } else { 0 };
            }
        }
    }
}

fn items(path: &Path) -> Vec<(u32, Vec<(u32, u64)>)> {
    let Some(nlri::Nlri::FlowSpec(nlri)) = &path.nlri.as_ref().unwrap().nlri else {
        panic!("FlowSpec path expected");
    };
    nlri.rules
        .iter()
        .map(|rule| match &rule.rule {
            Some(flow_spec_rule::Rule::IpPrefix(prefix)) => (prefix.r#type, vec![]),
            Some(flow_spec_rule::Rule::Component(c)) => (
                c.r#type,
                c.items.iter().map(|item| (item.op, item.value)).collect(),
            ),
            _ => panic!("unexpected component"),
        })
        .collect()
}

#[tokio::test]
async fn announcements_set_recent_age_without_changing_readback_or_withdrawal() {
    let fake = Fake::default();
    let adds = fake.adds.clone();
    let deletes = fake.deletes.clone();
    let (speaker, _server) = serve(fake).await;
    for (destination, source) in [
        ("192.0.2.1/32", "198.51.100.0/24"),
        ("2001:db8::1/128", "2001:db8:1::/48"),
    ] {
        let mut wanted = rule(destination);
        wanted.nlri.src_prefix = Some(source.into());
        let before = chrono::Utc::now().timestamp();
        speaker.announce(&wanted).await.unwrap();
        let after = chrono::Utc::now().timestamp();
        let add = adds.lock().unwrap().pop().unwrap().path.unwrap();
        let age = add.age.as_ref().expect("announcement timestamp");
        assert!((before..=after).contains(&age.seconds));
        assert!((0..1_000_000_000).contains(&age.nanos));

        let mut observed = add.clone();
        gobgp_read_back(&mut observed);
        // Readback metadata does not become route identity or action.
        for age in [
            None,
            Some(prost_types::Timestamp::default()),
            Some(prost_types::Timestamp {
                seconds: after + 3600,
                nanos: 0,
            }),
        ] {
            observed.age = age;
            let decoded = speaker.parse_flowspec_path(&observed).unwrap();
            assert_eq!(decoded.nlri_hash(), wanted.nlri_hash());
            assert_eq!(decoded.nlri.src_prefix, wanted.nlri.src_prefix);
            assert_eq!(decoded.actions.len(), 1);
            assert_eq!(
                decoded.actions[0].action_type,
                wanted.actions[0].action_type
            );
            assert_eq!(decoded.actions[0].rate_bps, wanted.actions[0].rate_bps);
            assert!(decoded.owner.is_empty());
        }

        speaker.withdraw(&wanted).await.unwrap();
        let delete = deletes.lock().unwrap().pop().unwrap().path.unwrap();
        assert_eq!(delete.nlri, add.nlri);
        assert_eq!(delete.family, add.family);
        assert!(delete.age.is_none());
        assert!(delete.is_withdraw);
    }
}

#[tokio::test]
async fn amplification_components_encode_per_adr_and_read_back_strictly() {
    use crate::domain::{FragmentMatch, PacketLengthRange};
    let fake = Fake::default();
    let adds = fake.adds.clone();
    let deletes = fake.deletes.clone();
    let (speaker, _server) = serve(fake).await;
    for prefix in ["192.0.2.1/32", "2001:db8::1/128"] {
        let mut ports = rule(prefix);
        ports.nlri.dst_ports.clear();
        ports.nlri.src_ports = vec![123, 53, 53];
        let mut length = ports.clone();
        length.nlri.packet_length = Some(PacketLengthRange {
            min: 468,
            max: 65535,
        });
        let mut fragment = ports.clone();
        fragment.nlri.src_ports.clear();
        fragment.nlri.fragment = Some(FragmentMatch::NonFirst);
        // Not a valid rule (ADR 028 invariants), but it pins the full component order.
        let mut every = length.clone();
        every.nlri.dst_ports = vec![443];
        every.nlri.fragment = Some(FragmentMatch::NonFirst);
        let src = (6, vec![(0x01, 53), (0x01, 123)]);
        let len = (10, vec![(0x03, 468), (0x45, 65535)]);
        // 0x02 in both families: the IPv6-reserved bit 0x01 is never emitted.
        let frag = (12, vec![(0x01, 0x02)]);
        let pinned = [
            (&ports, vec![src.clone()]),
            (&length, vec![src.clone(), len.clone()]),
            (&fragment, vec![frag.clone()]),
            (&every, vec![(5, vec![(0x81, 443)]), src, len, frag]),
        ];
        for (rule, expected) in pinned {
            speaker.announce(rule).await.unwrap();
            speaker.withdraw(rule).await.unwrap();
            let add = adds.lock().unwrap().pop().unwrap().path.unwrap();
            let delete = deletes.lock().unwrap().pop().unwrap().path.unwrap();
            let sent = items(&add);
            assert_eq!(sent[..2], [(1, vec![]), (3, vec![(0x81, 17)])]);
            assert_eq!(sent[2..], expected);
            assert_eq!(items(&delete), sent);
            // Read back as the same canonical rule, and the same backend route.
            let mut observed = add;
            gobgp_read_back(&mut observed);
            let decoded = speaker.parse_flowspec_path(&observed).unwrap();
            assert_eq!(decoded.nlri_hash(), rule.nlri_hash());
            assert_eq!(decoded.nlri.packet_length, rule.nlri.packet_length);
            assert_eq!(decoded.nlri.fragment, rule.nlri.fragment);
            assert!(speaker.matches_nlri(&rule.nlri, &decoded.nlri).unwrap());
        }
        // One differing component is a different route.
        for (left, right) in [(&ports, &fragment), (&length, &ports)] {
            assert!(!speaker.matches_nlri(&left.nlri, &right.nlri).unwrap());
        }
        // Only the exact operators prefixd emits decode; anything else fails the read.
        let mut base = speaker.build_flowspec_path(&every).unwrap();
        gobgp_read_back(&mut base);
        let mutations: &[fn(&mut Path)] = &[
            |p| component(p, 3).items.reverse(),
            |p| component(p, 3).items[0].value = 123,
            |p| component(p, 3).items[0].op = 0x03,
            |p| component(p, 3).items[1].op |= 0x40,
            |p| component(p, 3).items[1].value = 65536,
            |p| component(p, 4).items.truncate(1),
            |p| component(p, 4).items[0].op = 0x01,
            |p| component(p, 4).items[0].op = 0x02,
            |p| component(p, 4).items[1].op = 0x85,
            |p| component(p, 4).items[1].op = 0xc4,
            |p| component(p, 4).items[1].value = 65536,
            |p| component(p, 5).items[0].value = 0x01,
            |p| component(p, 5).items[0].value = 0x06,
            |p| component(p, 5).items[0].op = 0x80,
            |p| component(p, 5).items[0].op = 0x83,
            |p| component(p, 5).items[0].op = 0xc1,
            |p| {
                let extra = component(p, 5).items[0];
                component(p, 5).items.insert(0, extra);
                component(p, 5).items[0].op = 0x01;
            },
            |p| component(p, 5).r#type = 13,
            |p| component(p, 3).r#type = 4,
            |p| components(p).swap(4, 5),
        ];
        assert!(speaker.parse_flowspec_path(&base).is_ok());
        for (index, mutate) in mutations.iter().enumerate() {
            let mut p = base.clone();
            mutate(&mut p);
            assert!(speaker.parse_flowspec_path(&p).is_err(), "mutation {index}");
        }
    }
}

#[tokio::test]
async fn tcp_flags_encode_and_read_back_exactly() {
    use crate::domain::{TcpFlag, TcpFlagsMatch};
    let fake = Fake::default();
    let adds = fake.adds.clone();
    let (speaker, _server) = serve(fake).await;
    let syn_ack = TcpFlagsMatch {
        set: [TcpFlag::Syn, TcpFlag::Ack].into(),
        not_set: Default::default(),
    };
    let syn_not_ack = TcpFlagsMatch {
        set: [TcpFlag::Syn].into(),
        not_set: [TcpFlag::Ack].into(),
    };
    for (prefix, source) in [
        ("192.0.2.1/32", "203.0.113.1/32"),
        ("2001:db8::1/128", "2001:db8:1::/48"),
    ] {
        let mut tcp = rule(prefix);
        tcp.nlri.protocol = Some(6);
        tcp.nlri.dst_ports.clear();
        for (flags, expected) in [
            (&syn_ack, vec![(0x01, 0x12)]),
            (&syn_not_ack, vec![(0x01, 0x02), (0x43, 0x10)]),
        ] {
            for src_prefix in [None, Some(source.to_owned())] {
                let mut flagged = tcp.clone();
                flagged.nlri.src_prefix = src_prefix;
                flagged.nlri.tcp_flags = Some(flags.clone());
                speaker.announce(&flagged).await.unwrap();
                let add = adds.lock().unwrap().pop().unwrap().path.unwrap();
                assert_eq!(items(&add).last().unwrap(), &(9, expected.clone()));
                let mut observed = add;
                gobgp_read_back(&mut observed);
                let decoded = speaker.parse_flowspec_path(&observed).unwrap();
                assert_eq!(decoded.nlri.tcp_flags.as_ref(), Some(flags));
                assert_eq!(decoded.nlri_hash(), flagged.nlri_hash());
                assert!(speaker.matches_nlri(&flagged.nlri, &decoded.nlri).unwrap());
                assert!(!speaker.matches_nlri(&tcp.nlri, &decoded.nlri).unwrap());
            }
        }
        // A foreign rule carrying type 9 never decodes as the same rule without it.
        let mut foreign = speaker.build_flowspec_path(&tcp).unwrap();
        components(&mut foreign).push(ProtoFlowSpecRule {
            rule: Some(flow_spec_rule::Rule::Component(FlowSpecComponent {
                r#type: 9,
                items: vec![FlowSpecComponentItem {
                    op: 0x01,
                    value: 0x12,
                }],
            })),
        });
        gobgp_read_back(&mut foreign);
        let decoded = speaker.parse_flowspec_path(&foreign).unwrap();
        assert_ne!(decoded.nlri_hash(), tcp.nlri_hash());
        assert!(!speaker.matches_nlri(&tcp.nlri, &decoded.nlri).unwrap());
        // Any other bitmask form is not prefixd's and fails the read.
        let mutations: &[fn(&mut Path)] = &[
            // Any-match (no match bit), a multi-bit NOT, zero and out-of-range values.
            |p| component(p, 2).items[0].op = 0x80,
            |p| component(p, 2).items[0].op = 0x83,
            |p| component(p, 2).items[0].value = 0,
            |p| component(p, 2).items[0].value = 0x100,
            |p| component(p, 2).items.clear(),
            // An ORed or misordered second term, and a contradiction.
            |p| {
                component(p, 2).items[0].op = 0x01;
                component(p, 2).items.push(FlowSpecComponentItem {
                    op: 0x83,
                    value: 0x10,
                });
            },
            |p| {
                component(p, 2).items[0].op = 0x03;
                component(p, 2).items[0].value = 0x10;
                component(p, 2).items.push(FlowSpecComponentItem {
                    op: 0xc1,
                    value: 0x02,
                });
            },
            |p| {
                component(p, 2).items[0].op = 0x01;
                component(p, 2).items.push(FlowSpecComponentItem {
                    op: 0xc3,
                    value: 0x02,
                });
            },
            // TCP flags on UDP or with no protocol.
            |p| component(p, 1).items[0].value = 17,
            |p| {
                components(p).remove(1);
            },
        ];
        assert!(speaker.parse_flowspec_path(&foreign).is_ok());
        for (index, mutate) in mutations.iter().enumerate() {
            let mut p = foreign.clone();
            mutate(&mut p);
            assert!(speaker.parse_flowspec_path(&p).is_err(), "mutation {index}");
        }
    }
}
