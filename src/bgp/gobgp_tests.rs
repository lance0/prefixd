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
                action_type: ActionType::Police,
                rate_bps: None,
            }],
            vec![FlowSpecAction::police(0)],
            vec![FlowSpecAction::police(16_777_217)],
            vec![FlowSpecAction::police(u64::MAX)],
            vec![FlowSpecAction {
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
    fake.peers = vec![ListPeerResponse {
        peer: Some(Peer::default()),
    }];
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
    let fake = Fake {
        peers: ["192.0.2.1", "192.0.2.2"]
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
    assert_eq!(peers.len(), 2);
    for (peer, address) in peers.iter().zip(["192.0.2.1", "192.0.2.2"]) {
        assert_eq!(peer.name, address);
        assert_eq!(peer.address, address);
        assert_eq!(peer.state, SessionState::Established);
    }
}

async fn assert_stream_deadline(peers: bool, tail: Tail) {
    let mut fake = inventory(vec![(AFI_IP, Ok(vec![row(vec![path("192.0.2.1/32")])]))]);
    fake.peers = vec![ListPeerResponse {
        peer: Some(Peer::default()),
    }];
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

#[tokio::test]
async fn amplification_components_fail_closed_before_any_rpc() {
    use crate::domain::{FragmentMatch, PacketLengthRange};
    let fake = Fake::default();
    let adds = fake.adds.clone();
    let deletes = fake.deletes.clone();
    let (speaker, _server) = serve(fake).await;
    for prefix in ["192.0.2.1/32", "2001:db8::1/128"] {
        let control = rule(prefix);
        let mut ports = control.clone();
        ports.nlri.src_ports = vec![123];
        let mut fragment = control.clone();
        fragment.nlri.fragment = Some(FragmentMatch::NonFirst);
        let mut length = ports.clone();
        length.nlri.packet_length = Some(PacketLengthRange {
            min: 468,
            max: 65535,
        });
        for extended in [ports, fragment, length] {
            for result in [
                speaker.announce(&extended).await,
                speaker.withdraw(&extended).await,
            ] {
                assert!(matches!(
                    result,
                    Err(PrefixdError::Internal(message)) if message.contains("not supported")
                ));
            }
        }
        assert!(adds.lock().unwrap().is_empty());
        assert!(deletes.lock().unwrap().is_empty());
        // Control: the same connection carries the rule without new components.
        speaker.announce(&control).await.unwrap();
        speaker.withdraw(&control).await.unwrap();
        assert_eq!(adds.lock().unwrap().drain(..).count(), 1);
        assert_eq!(deletes.lock().unwrap().drain(..).count(), 1);
    }
}
