use super::{
    AddOutcome, BlackholeInventory, BlackholeRoute, BlackholeSpeaker, DaemonHealth,
    DaemonHealthObserver, ExportDisposition, ExportObserver, FlowSpecAnnouncer,
    FlowSpecMatchSupport, FlowSpecReader, FlowSpecWriter, InjectionLeases, LeaseGeneration,
    PeerExport, PeerObserver, PeerStatus, SessionState, UnrecognizedRoute, rustbgpd_pb as pb,
};
use crate::{
    config::RustBgpdConfig,
    domain::{FlowSpecAction, FlowSpecNlri, FlowSpecRule, FragmentMatch, PacketLengthRange},
    error::{PrefixdError, Result},
};
use async_trait::async_trait;
use std::{future::Future, time::Duration};
use tonic::{
    Code, Request,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity},
};

pub struct RustBgpdAnnouncer {
    channel: Channel,
    token: Option<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>,
    /// The daemon last answered `ListInjectionLeases`; an `UNIMPLEMENTED` lease RPC clears it.
    lease_confirmed: std::sync::atomic::AtomicBool,
}

/// The oldest daemon prefixd runs against: 0.79.0 adds the injection lease
/// (rustbgpd ADR-0141).
const MINIMUM_DAEMON_VERSION: [u64; 3] = [0, 79, 0];

/// `major.minor.patch`, ignoring any pre-release or build suffix.
fn parse_version(version: &str) -> Option<[u64; 3]> {
    let core = version.split(['-', '+']).next()?;
    let parts: Vec<u64> = core
        .split('.')
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()
        .ok()?;
    parts.try_into().ok()
}

fn invalid(message: &str) -> PrefixdError {
    PrefixdError::Internal(format!("rustbgpd: {message}"))
}

impl RustBgpdAnnouncer {
    pub async fn connect(config: &RustBgpdConfig) -> anyhow::Result<Self> {
        let token = if config.bearer_token_env.is_empty() {
            String::new()
        } else {
            std::env::var(&config.bearer_token_env).map_err(|_| {
                anyhow::anyhow!("rustbgpd bearer token environment variable is missing")
            })?
        };
        let speaker = Self::connect_with_token(config, &token).await?;
        speaker.require_minimum_version().await?;
        Ok(speaker)
    }

    /// Startup contract check: refuse a daemon older than 0.79.0, or one whose
    /// version cannot be read, before any intent is read or written.
    async fn require_minimum_version(&self) -> anyhow::Result<()> {
        let version = self
            .daemon_health()
            .await
            .map_err(|error| anyhow::anyhow!("cannot read the rustbgpd version: {error}"))?
            .version
            .unwrap_or_default();
        let minimum = MINIMUM_DAEMON_VERSION
            .map(|part| part.to_string())
            .join(".");
        match parse_version(&version) {
            Some(parsed) if parsed >= MINIMUM_DAEMON_VERSION => Ok(()),
            Some(_) => anyhow::bail!(
                "rustbgpd {version} is older than the minimum {minimum}; upgrade the speaker first"
            ),
            None => anyhow::bail!(
                "rustbgpd reported no readable version ({version:?}); prefixd requires {minimum} or later"
            ),
        }
    }

    async fn connect_with_token(config: &RustBgpdConfig, token: &str) -> anyhow::Result<Self> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        anyhow::ensure!(
            config.client_cert_path.is_some() == config.client_key_path.is_some(),
            "rustbgpd client certificate and key must be configured together"
        );
        anyhow::ensure!(
            !token.chars().any(char::is_whitespace),
            "invalid rustbgpd bearer token"
        );
        let token = if token.is_empty() {
            None
        } else {
            let mut value: tonic::metadata::MetadataValue<_> = format!("Bearer {token}")
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid rustbgpd bearer token"))?;
            value.set_sensitive(true);
            Some(value)
        };
        if let Some(path) = config.unix_socket_path()? {
            anyhow::ensure!(
                config.ca_cert_path.is_none() && config.client_cert_path.is_none(),
                "TLS options are not valid for rustbgpd Unix sockets"
            );
            #[cfg(unix)]
            {
                let channel = Endpoint::from_static("http://[::]:50051")
                    .connect_timeout(Duration::from_secs(10))
                    .timeout(Duration::from_secs(30))
                    .connect_with_connector(tower::service_fn(move |_| {
                        let path = path.clone();
                        async move {
                            connect_owner_socket(&path)
                                .await
                                .map(hyper_util::rt::TokioIo::new)
                        }
                    }))
                    .await
                    .map_err(|_| anyhow::anyhow!("rustbgpd Unix connection failed"))?;
                return Ok(Self::new(channel, token));
            }
            #[cfg(not(unix))]
            anyhow::bail!("rustbgpd Unix sockets are unsupported on this platform");
        }
        anyhow::ensure!(
            !config.endpoint.contains(['@', '?', '#'])
                && !config
                    .endpoint
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control()),
            "invalid rustbgpd endpoint"
        );
        let uri: tonic::codegen::http::Uri = config
            .endpoint
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid rustbgpd endpoint"))?;
        anyhow::ensure!(
            uri.authority().is_some() && matches!(uri.path(), "" | "/"),
            "invalid rustbgpd endpoint"
        );
        let mut endpoint = Endpoint::from_shared(config.endpoint.clone())
            .map_err(|_| anyhow::anyhow!("invalid rustbgpd endpoint"))?
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30));
        match uri.scheme_str() {
            Some("http") => {
                let host = uri
                    .host()
                    .unwrap_or_default()
                    .trim_start_matches('[')
                    .trim_end_matches(']');
                anyhow::ensure!(
                    host.parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback()),
                    "plaintext rustbgpd requires a literal loopback address"
                );
                anyhow::ensure!(
                    config.ca_cert_path.is_none() && config.client_cert_path.is_none(),
                    "TLS options require HTTPS"
                );
                anyhow::ensure!(token.is_some(), "rustbgpd bearer token is required");
            }
            Some("https") => {
                anyhow::ensure!(
                    token.is_some() || config.client_cert_path.is_some(),
                    "rustbgpd bearer token or client certificate is required"
                );
                let mut tls = ClientTlsConfig::new()
                    .with_native_roots()
                    .timeout(Duration::from_secs(10));
                if let Some(path) = &config.ca_cert_path {
                    tls = tls.ca_certificate(Certificate::from_pem(read_tls_file(path).await?));
                }
                if let (Some(cert), Some(key)) = (&config.client_cert_path, &config.client_key_path)
                {
                    tls = tls.identity(Identity::from_pem(
                        read_tls_file(cert).await?,
                        read_tls_file(key).await?,
                    ));
                }
                endpoint = endpoint
                    .tls_config(tls)
                    .map_err(|_| anyhow::anyhow!("invalid rustbgpd TLS configuration"))?;
            }
            _ => anyhow::bail!("rustbgpd endpoint must use unix, http or https"),
        }
        let channel = tokio::time::timeout(Duration::from_secs(10), endpoint.connect())
            .await
            .map_err(|_| anyhow::anyhow!("rustbgpd connection timed out"))?
            .map_err(|_| anyhow::anyhow!("rustbgpd connection failed"))?;
        Ok(Self::new(channel, token))
    }

    fn new(
        channel: Channel,
        token: Option<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>,
    ) -> Self {
        Self {
            channel,
            token,
            lease_confirmed: Default::default(),
        }
    }

    fn request<T>(&self, value: T) -> Request<T> {
        let mut request = Request::new(value);
        request.set_timeout(Duration::from_secs(30));
        if let Some(token) = &self.token {
            request
                .metadata_mut()
                .insert("authorization", token.clone());
        }
        request
    }

    async fn rpc<T, F, Fut>(&self, operation: &str, call: F) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = std::result::Result<tonic::Response<T>, tonic::Status>>,
    {
        self.call(operation, call)
            .await
            .map_err(|status| failed(operation, &status))
    }

    /// Retries transient failures; the final status is returned so callers can
    /// branch on its code, never on its message.
    async fn call<T, F, Fut>(
        &self,
        operation: &str,
        mut call: F,
    ) -> std::result::Result<T, tonic::Status>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = std::result::Result<tonic::Response<T>, tonic::Status>>,
    {
        for attempt in 0..3 {
            let result = tokio::time::timeout(Duration::from_secs(30), call())
                .await
                .unwrap_or_else(|_| Err(tonic::Status::deadline_exceeded("RPC deadline elapsed")));
            match result {
                Ok(value) => return Ok(value.into_inner()),
                Err(status)
                    if attempt < 2
                        && matches!(status.code(), Code::Unavailable | Code::DeadlineExceeded) =>
                {
                    tracing::warn!(operation, attempt = attempt + 1, code = ?status.code(), "retrying rustbgpd RPC");
                    tokio::time::sleep(Duration::from_millis(100 << attempt)).await;
                }
                Err(status) => return Err(status),
            }
        }
        unreachable!()
    }

    /// A lease RPC answered `UNIMPLEMENTED`: the daemon was rolled back.
    fn lease_unsupported(&self, status: &tonic::Status) {
        if status.code() == Code::Unimplemented {
            self.lease_confirmed
                .store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Add or delete failure. `FAILED_PRECONDITION` is the daemon's ownership
    /// refusal (rustbgpd ADR-0141 §3): the key is held by another owner or by
    /// no owner, and nothing changed.
    fn mutation_error(&self, operation: &str, status: &tonic::Status) -> PrefixdError {
        self.lease_unsupported(status);
        if status.code() == Code::FailedPrecondition {
            PrefixdError::InjectionOwnerMismatch(format!(
                "rustbgpd refused {operation}: the key is held by another injection owner or by none"
            ))
        } else {
            failed(operation, status)
        }
    }
}

fn failed(operation: &str, status: &tonic::Status) -> PrefixdError {
    invalid(&format!("{operation} RPC failed: {:?}", status.code()))
}

fn generation(value: Option<pb::LeaseGeneration>) -> Result<LeaseGeneration> {
    value
        .map(|generation| LeaseGeneration {
            incarnation: generation.incarnation,
            sequence: generation.sequence,
        })
        .ok_or_else(|| invalid("missing lease generation"))
}

async fn read_tls_file(path: &str) -> anyhow::Result<Vec<u8>> {
    tokio::fs::read(path)
        .await
        .map_err(|_| anyhow::anyhow!("cannot read rustbgpd TLS credential file"))
}

#[cfg(unix)]
async fn connect_owner_socket(path: &std::path::Path) -> std::io::Result<tokio::net::UnixStream> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let denied = || {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "rustbgpd socket must be owner-only",
        )
    };
    let parent = path.parent().ok_or_else(denied)?;
    let uid = rustix::process::geteuid().as_raw();
    for ancestor in parent.ancestors() {
        let directory = tokio::fs::symlink_metadata(ancestor).await?;
        let mode = directory.mode();
        // Sticky directories protect entries owned by root or this trusted UID.
        if !directory.is_dir()
            || ![0, uid].contains(&directory.uid())
            || (mode & 0o022 != 0 && mode & 0o1000 == 0)
            || (ancestor == parent && (directory.uid() != uid || mode & 0o077 != 0))
        {
            return Err(denied());
        }
    }
    let socket = tokio::fs::symlink_metadata(path).await?;
    if !socket.file_type().is_socket()
        || socket.uid() != uid
        || socket.mode() & 0o077 != 0
        || tokio::fs::canonicalize(parent).await? != parent
    {
        return Err(denied());
    }
    let stream = tokio::net::UnixStream::connect(path).await?;
    if stream.peer_cred()?.uid() != uid {
        return Err(denied());
    }
    Ok(stream)
}

use super::RUSTBGPD_MAX_PORTS_PER_LIST as MAX_PORTS_PER_LIST;

/// Components in strictly ascending type order; the daemon does not reorder them.
fn encode_match(nlri: &FlowSpecNlri) -> Result<(i32, Vec<pb::FlowSpecComponent>)> {
    let prefix: ipnet::IpNet = nlri
        .dst_prefix
        .parse()
        .map_err(|_| invalid("invalid destination prefix"))?;
    if prefix != prefix.trunc() {
        return Err(invalid("destination prefix has host bits"));
    }
    let mut components = vec![pb::FlowSpecComponent {
        r#type: 1,
        prefix: prefix.to_string(),
        ..Default::default()
    }];
    if let Some(protocol) = nlri.protocol {
        components.push(pb::FlowSpecComponent {
            r#type: 3,
            value: format!("={protocol}"),
            ..Default::default()
        });
    }
    let mut ports = nlri.dst_ports.clone();
    ports.sort_unstable();
    // Source ports are an equality set (ADR 028); the eight-term cap applies to both lists.
    for (r#type, ports) in [
        (5, ports),
        (6, crate::domain::canonical_ports(&nlri.src_ports)),
    ] {
        if ports.len() > MAX_PORTS_PER_LIST {
            return Err(invalid("at most eight ports per list are supported"));
        }
        if !ports.is_empty() {
            components.push(pb::FlowSpecComponent {
                r#type,
                value: ports
                    .iter()
                    .map(|port| format!("={port}"))
                    .collect::<Vec<_>>()
                    .join(", "),
                ..Default::default()
            });
        }
    }
    if let Some(range) = nlri.packet_length {
        components.push(pb::FlowSpecComponent {
            r#type: 10,
            value: format!(">={} & <={}", range.min, range.max),
            ..Default::default()
        });
    }
    if let Some(fragment) = nlri.fragment {
        // The daemon always sets the match bit on injected bitmask terms.
        components.push(pb::FlowSpecComponent {
            r#type: 12,
            value: format!("{:#04x}", fragment.bitmask()),
            ..Default::default()
        });
    }
    let family = if prefix.addr().is_ipv4() {
        pb::AddressFamily::Ipv4Flowspec
    } else {
        pb::AddressFamily::Ipv6Flowspec
    };
    Ok((family as i32, components))
}

fn encode(rule: &FlowSpecRule) -> Result<pb::AddFlowSpecRequest> {
    let (afi_safi, components) = encode_match(&rule.nlri)?;
    if rule.actions.len() != 1 {
        return Err(invalid("exactly one traffic rate action is required"));
    }
    let rate = rule.actions[0]
        .traffic_rate_bytes_per_second()
        .map_err(|error| invalid(&error.to_string()))?;
    Ok(pb::AddFlowSpecRequest {
        afi_safi,
        components,
        actions: vec![pb::FlowSpecAction {
            action: Some(pb::flow_spec_action::Action::TrafficRate(
                pb::FlowSpecTrafficRate { rate },
            )),
        }],
        ..Default::default()
    })
}

fn numbers(value: &str) -> Result<Vec<u16>> {
    value
        .split(',')
        .map(|part| {
            let part = part.trim();
            part.strip_prefix("==")
                .or_else(|| part.strip_prefix('='))
                .ok_or_else(|| invalid("unsupported numeric expression"))?
                .parse()
                .map_err(|_| invalid("invalid numeric value"))
        })
        .collect()
}

fn decode(route: pb::FlowSpecRouteEntry, family: i32) -> Result<FlowSpecRule> {
    // Leased rows carry an owner, generation and remaining time together (rustbgpd ADR-0141 §3).
    let leased = !route.injection_owner.is_empty();
    if leased != route.lease_generation.is_some() || leased != route.lease_remaining_ms.is_some() {
        return Err(invalid("inconsistent local rule lease fields"));
    }
    if route.peer_address != "0.0.0.0"
        || route.afi_safi != family
        || !route.communities.is_empty()
        || !route.as_path.is_empty()
    {
        return Err(invalid("unsupported local route attributes"));
    }
    let mut nlri = FlowSpecNlri {
        dst_prefix: String::new(),
        protocol: None,
        dst_ports: vec![],
        ..Default::default()
    };
    let mut previous = 0;
    for component in &route.components {
        if component.r#type <= previous || component.offset != 0 {
            return Err(invalid("invalid component order or offset"));
        }
        previous = component.r#type;
        match component.r#type {
            1 if component.value.is_empty() => {
                let prefix: ipnet::IpNet = component
                    .prefix
                    .parse()
                    .map_err(|_| invalid("invalid destination prefix"))?;
                if prefix != prefix.trunc() || (prefix.addr().is_ipv4() != (family == 3)) {
                    return Err(invalid("invalid prefix family or host bits"));
                }
                nlri.dst_prefix = prefix.to_string();
            }
            3 if component.prefix.is_empty() => {
                let values = numbers(&component.value)?;
                if values.len() != 1 || values[0] > 255 {
                    return Err(invalid("unsupported protocol"));
                }
                nlri.protocol = Some(values[0] as u8);
            }
            5 if component.prefix.is_empty() => {
                nlri.dst_ports = numbers(&component.value)?;
                nlri.dst_ports.sort_unstable();
            }
            // ADR 028 components accept only the exact form the daemon renders for
            // prefixd's injection; any other operator, term or bit fails the read.
            6 if component.prefix.is_empty() => {
                let ports: Option<Vec<u16>> = component
                    .value
                    .split(", ")
                    .map(|term| term.strip_prefix("==")?.parse().ok())
                    .collect();
                nlri.src_ports = ports
                    .filter(|ports| {
                        ports.windows(2).all(|pair| pair[0] < pair[1])
                            && ports
                                .iter()
                                .map(|port| format!("=={port}"))
                                .collect::<Vec<_>>()
                                .join(", ")
                                == component.value
                    })
                    .ok_or_else(|| invalid("unsupported source port expression"))?;
            }
            10 if component.prefix.is_empty() => {
                let range = component
                    .value
                    .strip_prefix(">=")
                    .and_then(|value| value.split_once(" & <="))
                    .and_then(|(min, max)| {
                        Some(PacketLengthRange {
                            min: min.parse().ok()?,
                            max: max.parse().ok()?,
                        })
                    })
                    .filter(|range| format!(">={} & <={}", range.min, range.max) == component.value)
                    .ok_or_else(|| invalid("unsupported packet length expression"))?;
                nlri.packet_length = Some(range);
            }
            12 if component.prefix.is_empty() && component.value == "0x0002/match" => {
                nlri.fragment = Some(FragmentMatch::NonFirst);
            }
            _ => return Err(invalid("unsupported component")),
        }
    }
    if nlri.dst_prefix.is_empty() || route.actions.len() != 1 {
        return Err(invalid("missing destination or unsupported actions"));
    }
    let Some(pb::flow_spec_action::Action::TrafficRate(rate)) = &route.actions[0].action else {
        return Err(invalid("unsupported action"));
    };
    let bps = rate.rate as f64 * 8.0;
    if !bps.is_finite() || bps < 0.0 || bps >= u64::MAX as f64 || bps.fract() != 0.0 {
        return Err(invalid("invalid traffic rate"));
    }
    // rustbgpd exposes each traffic-rate both as a typed action and a raw EC.
    let expected_ec = (0x8006_u64 << 48) | u64::from(rate.rate.to_bits());
    if route.extended_communities.as_slice() != [expected_ec] {
        return Err(invalid("unsupported or inconsistent extended communities"));
    }
    let action = if bps == 0.0 {
        FlowSpecAction::discard()
    } else {
        FlowSpecAction::police(bps as u64)
    };
    let rule = FlowSpecRule::new(nlri, action).with_owner(route.injection_owner);
    encode(&rule)?;
    Ok(rule)
}

fn encode_blackhole(route: &BlackholeRoute) -> pb::AddPathRequest {
    // ORIGIN IGP, empty AS_PATH, no LOCAL_PREF or MED, path_id 0 (ADR 027).
    pb::AddPathRequest {
        prefix: route.prefix().addr().to_string(),
        prefix_length: route.prefix().prefix_len().into(),
        next_hop: route.next_hop().to_string(),
        origin: 0,
        communities: route.communities().to_vec(),
        large_communities: route
            .large_communities()
            .iter()
            .map(|[global, first, second]| format!("{global}:{first}:{second}"))
            .collect(),
        path_id: 0,
        ..Default::default()
    }
}

/// A reply without an outcome is still an accepted add; an unknown value is not.
fn path_add_outcome(operation: &str, response: Option<pb::AddPathResponse>) -> Result<AddOutcome> {
    match response.map(|response| pb::PathInjectOutcome::try_from(response.outcome)) {
        Some(Ok(pb::PathInjectOutcome::Created)) => Ok(AddOutcome::Created),
        Some(Ok(pb::PathInjectOutcome::Replaced)) => Ok(AddOutcome::Replaced),
        Some(Ok(pb::PathInjectOutcome::Unchanged)) => Ok(AddOutcome::Unchanged),
        None | Some(Ok(pb::PathInjectOutcome::Unspecified)) => {
            tracing::warn!(
                operation,
                "rustbgpd accepted the add without reporting an outcome"
            );
            Ok(AddOutcome::Unknown)
        }
        Some(Err(_)) => Err(invalid("unsupported rustbgpd injection outcome")),
    }
}

/// Malformed rows make the view untrustworthy and fail the whole read. A
/// well-formed local row that is not prefixd-shaped is returned as unrecognized.
fn decode_blackhole(
    route: pb::Route,
    family: i32,
    inventory: &mut BlackholeInventory,
) -> Result<()> {
    if route.peer_address != "0.0.0.0" {
        return Err(invalid("row outside the local intent view"));
    }
    let address: std::net::IpAddr = route
        .prefix
        .parse()
        .map_err(|_| invalid("invalid local route prefix"))?;
    if address.is_ipv4() != (family == pb::AddressFamily::Ipv4Unicast as i32) {
        return Err(invalid("local route family mismatch"));
    }
    let prefix = u8::try_from(route.prefix_length)
        .ok()
        .and_then(|length| ipnet::IpNet::new(address, length).ok())
        .filter(|prefix| *prefix == prefix.trunc())
        .ok_or_else(|| invalid("invalid local route prefix"))?;
    let next_hop: std::net::IpAddr = route
        .next_hop
        .parse()
        .map_err(|_| invalid("invalid local route next hop"))?;
    let large = route
        .large_communities
        .iter()
        .map(|value| {
            let parts = value
                .split(':')
                .map(str::parse)
                .collect::<std::result::Result<Vec<u32>, _>>();
            parts
                .ok()
                .and_then(|parts| <[u32; 3]>::try_from(parts).ok())
                .ok_or_else(|| invalid("invalid local route large community"))
        })
        .collect::<Result<Vec<_>>>()?;
    // Leased rows carry an owner, generation and remaining time together (rustbgpd ADR-0141 §3).
    let leased = !route.injection_owner.is_empty();
    if leased != route.lease_generation.is_some() || leased != route.lease_remaining_ms.is_some() {
        return Err(invalid("inconsistent local route lease fields"));
    }
    let reason = if route.path_id != 0 {
        "nonzero path_id"
    } else if prefix.prefix_len() != prefix.max_prefix_len() {
        "not a host route"
    } else if route.origin != 0
        || !route.as_path.is_empty()
        || route.local_pref_attr.is_some()
        || route.med_attr.is_some()
        || route.med != 0
        || !route.extended_communities.is_empty()
        || route.stale
        || route.llgr_stale
        || route.aggregator.is_some()
        || route.atomic_aggregate
    {
        "unexpected path attributes"
    } else {
        match BlackholeRoute::new(prefix, next_hop, route.communities.clone(), large.clone()) {
            Err(_) => "next hop is not a same-family unicast address",
            // prefixd injects canonical communities that include BLACKHOLE.
            Ok(decoded)
                if decoded.communities() == route.communities
                    && decoded.large_communities() == large =>
            {
                let decoded = decoded.with_owner(route.injection_owner);
                // Zero remaining means expired with its withdrawal pending: lost, not retained.
                if route.lease_remaining_ms == Some(0) {
                    inventory.expired.push(decoded);
                } else {
                    inventory.routes.push(decoded);
                }
                return Ok(());
            }
            Ok(_) => "missing BLACKHOLE or non-canonical communities",
        }
    };
    inventory
        .unrecognized
        .push(UnrecognizedRoute { prefix, reason });
    Ok(())
}

/// Explicit, so a daemon default change cannot alter the walk.
const ROUTE_PAGE_SIZE: u32 = 100;

impl FlowSpecAnnouncer for RustBgpdAnnouncer {
    fn backend(&self) -> &'static str {
        "rustbgpd"
    }
    fn blackhole(&self) -> Option<&dyn BlackholeSpeaker> {
        Some(self)
    }
    fn injection_leases(&self) -> Option<&dyn InjectionLeases> {
        Some(self)
    }
    fn reader(&self) -> Option<&dyn FlowSpecReader> {
        Some(self)
    }
    fn daemon_health_observer(&self) -> Option<&dyn DaemonHealthObserver> {
        Some(self)
    }

    fn peer_observer(&self) -> Option<&dyn PeerObserver> {
        Some(self)
    }
    fn export_observer(&self) -> Option<&dyn ExportObserver> {
        Some(self)
    }
    fn match_support(&self) -> FlowSpecMatchSupport {
        // Types 6, 10 and 12 parse and render alike in every supported release.
        FlowSpecMatchSupport::ALL
    }
}

#[async_trait]
impl FlowSpecWriter for RustBgpdAnnouncer {
    fn matches_nlri(&self, left: &FlowSpecNlri, right: &FlowSpecNlri) -> Result<bool> {
        Ok(encode_match(left)? == encode_match(right)?)
    }

    async fn announce(&self, rule: &FlowSpecRule) -> Result<()> {
        if !rule.owner.is_empty() {
            return Err(invalid("a leased rule needs AddLeasedFlowSpec"));
        }
        let payload = encode(rule)?;
        let response = self
            .call("AddFlowSpec", || async {
                pb::injection_service_client::InjectionServiceClient::new(self.channel.clone())
                    .add_flow_spec(self.request(payload.clone()))
                    .await
            })
            .await
            .map_err(|status| self.mutation_error("AddFlowSpec", &status))?;
        match pb::FlowSpecInjectOutcome::try_from(response.outcome) {
            Ok(
                pb::FlowSpecInjectOutcome::Created
                | pb::FlowSpecInjectOutcome::Replaced
                | pb::FlowSpecInjectOutcome::Unchanged,
            ) => {
                tracing::debug!(outcome = response.outcome, "rustbgpd injection accepted");
                Ok(())
            }
            _ => Err(invalid("unsupported rustbgpd injection outcome")),
        }
    }

    async fn announce_leased(
        &self,
        rule: &FlowSpecRule,
        lease_seconds: u32,
    ) -> Result<LeaseGeneration> {
        // Never AddFlowSpec: a rejected leased add creates nothing and never falls back.
        if rule.owner.is_empty() {
            return Err(invalid("a leased add needs an injection owner"));
        }
        let payload = pb::AddLeasedFlowSpecRequest {
            rule: Some(encode(rule)?),
            lease: Some(pb::InjectionLease {
                owner: rule.owner.clone(),
                lease_seconds,
            }),
        };
        let response = self
            .call("AddLeasedFlowSpec", || async {
                pb::injection_service_client::InjectionServiceClient::new(self.channel.clone())
                    .add_leased_flow_spec(self.request(payload.clone()))
                    .await
            })
            .await
            .map_err(|status| self.mutation_error("AddLeasedFlowSpec", &status))?;
        match response
            .result
            .map(|result| pb::FlowSpecInjectOutcome::try_from(result.outcome))
        {
            Some(Ok(
                pb::FlowSpecInjectOutcome::Created
                | pb::FlowSpecInjectOutcome::Replaced
                | pb::FlowSpecInjectOutcome::Unchanged,
            )) => generation(response.generation),
            _ => Err(invalid("unsupported rustbgpd leased injection outcome")),
        }
    }

    async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()> {
        let (afi_safi, components) = encode_match(&rule.nlri)?;
        // The recorded owner and never override_owner: a mismatch is FAILED_PRECONDITION.
        let payload = pb::DeleteFlowSpecRequest {
            afi_safi,
            components,
            allow_missing: true,
            owner: rule.owner.clone(),
            ..Default::default()
        };
        let response = self
            .call("DeleteFlowSpec", || {
                let mut client =
                    pb::injection_service_client::InjectionServiceClient::new(self.channel.clone());
                let request = self.request(payload.clone());
                async move {
                    match client.delete_flow_spec(request).await {
                        Err(status) if status.code() == Code::NotFound => {
                            Ok(tonic::Response::new(pb::DeleteFlowSpecResponse {
                                outcome: 2,
                            }))
                        }
                        result => result,
                    }
                }
            })
            .await
            .map_err(|status| self.mutation_error("DeleteFlowSpec", &status))?;
        match pb::FlowSpecDeleteOutcome::try_from(response.outcome) {
            Ok(pb::FlowSpecDeleteOutcome::Deleted | pb::FlowSpecDeleteOutcome::NotPresent) => {
                tracing::debug!(outcome = response.outcome, "rustbgpd withdrawal accepted");
                Ok(())
            }
            _ => Err(invalid("unsupported rustbgpd deletion outcome")),
        }
    }
}
#[async_trait]
impl FlowSpecReader for RustBgpdAnnouncer {
    async fn list_active(&self) -> Result<Vec<FlowSpecRule>> {
        let mut rules = vec![];
        for family in [3, 4] {
            let response = self
                .rpc("ListFlowSpecRoutes", || async {
                    pb::rib_service_client::RibServiceClient::new(self.channel.clone())
                        .list_flow_spec_routes(self.request(pb::ListFlowSpecRequest {
                            afi_safi: family,
                            received_peer_address: "0.0.0.0".into(),
                            advertised_peer_address: String::new(),
                        }))
                        .await
                })
                .await?;
            if !response.received_view || response.advertised_view || !response.routes.is_empty() {
                return Err(invalid("rustbgpd did not acknowledge local intent view"));
            }
            for row in response.received_routes {
                if !matches!(row.validation, 1 | 3) || row.path_id != 0 || !row.reason.is_empty() {
                    return Err(invalid("invalid local intent row"));
                }
                let route = row.route.ok_or_else(|| invalid("missing local route"))?;
                // Zero remaining means expired with its withdrawal pending: lost, not retained.
                let expired = route.lease_remaining_ms == Some(0);
                let rule = decode(route, family)?;
                if !expired {
                    rules.push(rule);
                }
            }
        }
        Ok(rules)
    }
}
#[async_trait]
impl BlackholeSpeaker for RustBgpdAnnouncer {
    async fn announce_blackhole(&self, route: &BlackholeRoute) -> Result<AddOutcome> {
        if !route.owner().is_empty() {
            return Err(invalid("a leased route needs AddLeasedPath"));
        }
        let payload = encode_blackhole(route);
        // OK is local Adj-RIB-In acceptance only.
        let response = self
            .call("AddPath", || async {
                pb::injection_service_client::InjectionServiceClient::new(self.channel.clone())
                    .add_path(self.request(payload.clone()))
                    .await
            })
            .await
            .map_err(|status| self.mutation_error("AddPath", &status))?;
        path_add_outcome("AddPath", Some(response))
    }

    async fn announce_leased_blackhole(
        &self,
        route: &BlackholeRoute,
        lease_seconds: u32,
    ) -> Result<(LeaseGeneration, AddOutcome)> {
        // Never AddPath: a rejected leased add creates nothing and never falls back.
        if route.owner().is_empty() {
            return Err(invalid("a leased add needs an injection owner"));
        }
        let payload = pb::AddLeasedPathRequest {
            path: Some(encode_blackhole(route)),
            lease: Some(pb::InjectionLease {
                owner: route.owner().into(),
                lease_seconds,
            }),
        };
        let response = self
            .call("AddLeasedPath", || async {
                pb::injection_service_client::InjectionServiceClient::new(self.channel.clone())
                    .add_leased_path(self.request(payload.clone()))
                    .await
            })
            .await
            .map_err(|status| self.mutation_error("AddLeasedPath", &status))?;
        let outcome = path_add_outcome("AddLeasedPath", response.result)?;
        Ok((generation(response.generation)?, outcome))
    }

    async fn withdraw_blackhole(&self, prefix: &ipnet::IpNet, owner: &str) -> Result<()> {
        super::require_host_route(prefix)?;
        // The recorded owner and never override_owner: a mismatch is FAILED_PRECONDITION.
        let payload = pb::DeletePathRequest {
            prefix: prefix.addr().to_string(),
            prefix_length: prefix.prefix_len().into(),
            path_id: 0,
            allow_missing: true,
            owner: owner.into(),
            ..Default::default()
        };
        let response = self
            .call("DeletePath", || async {
                pb::injection_service_client::InjectionServiceClient::new(self.channel.clone())
                    .delete_path(self.request(payload.clone()))
                    .await
            })
            .await
            .map_err(|status| self.mutation_error("DeletePath", &status))?;
        // allow_missing makes an absent route OK with NOT_PRESENT, so a retry or a
        // withdrawal after a daemon restart completes; NOT_FOUND is now an error.
        match pb::PathDeleteOutcome::try_from(response.outcome) {
            Ok(pb::PathDeleteOutcome::Deleted) => Ok(()),
            Ok(pb::PathDeleteOutcome::NotPresent) => {
                tracing::debug!(%prefix, "rustbgpd blackhole route already absent");
                Ok(())
            }
            _ => Err(invalid("unsupported rustbgpd deletion outcome")),
        }
    }

    async fn list_blackholes(&self) -> Result<BlackholeInventory> {
        let mut inventory = BlackholeInventory::default();
        for family in [
            pb::AddressFamily::Ipv4Unicast as i32,
            pb::AddressFamily::Ipv6Unicast as i32,
        ] {
            let mut page_token = String::new();
            let mut version = None;
            // A mutation mid-walk returns ABORTED, which fails the whole read.
            loop {
                let response = self
                    .rpc("ListReceivedRoutes", || async {
                        pb::rib_service_client::RibServiceClient::new(self.channel.clone())
                            .list_received_routes(self.request(pb::ListRoutesRequest {
                                neighbor_address: "0.0.0.0".into(),
                                afi_safi: family,
                                page_size: ROUTE_PAGE_SIZE,
                                page_token: page_token.clone(),
                                ..Default::default()
                            }))
                            .await
                    })
                    .await?;
                if *version.get_or_insert(response.page_version) != response.page_version {
                    return Err(invalid("local intent changed during the read"));
                }
                for route in response.routes {
                    decode_blackhole(route, family, &mut inventory)?;
                }
                if response.next_page_token.is_empty() {
                    break;
                }
                if response.next_page_token == page_token {
                    return Err(invalid("local intent read did not advance"));
                }
                page_token = response.next_page_token;
            }
        }
        Ok(inventory)
    }
}

#[async_trait]
impl InjectionLeases for RustBgpdAnnouncer {
    async fn live_lease(&self, owner: &str) -> Result<Option<Option<LeaseGeneration>>> {
        let request = pb::ListInjectionLeasesRequest {
            owner: owner.into(),
        };
        let response = match self
            .call("ListInjectionLeases", || async {
                pb::injection_service_client::InjectionServiceClient::new(self.channel.clone())
                    .list_injection_leases(self.request(request.clone()))
                    .await
            })
            .await
        {
            Ok(response) => response,
            Err(status) if status.code() == Code::Unimplemented => {
                self.lease_unsupported(&status);
                return Ok(None);
            }
            Err(status) => return Err(failed("ListInjectionLeases", &status)),
        };
        if response.leases.len() > 1 || response.leases.iter().any(|lease| lease.owner != owner) {
            return Err(invalid("lease listing ignored the owner filter"));
        }
        self.lease_confirmed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // Zero remaining is expired, withdrawal pending: not renewable, so not adopted.
        response
            .leases
            .into_iter()
            .find(|lease| lease.lease_remaining_ms > 0)
            .map(|lease| generation(lease.generation))
            .transpose()
            .map(Some)
    }

    async fn renew_lease(
        &self,
        owner: &str,
        generation: LeaseGeneration,
        lease_seconds: u32,
    ) -> Result<bool> {
        let request = pb::RenewLeaseRequest {
            owner: owner.into(),
            generation: Some(pb::LeaseGeneration {
                incarnation: generation.incarnation,
                sequence: generation.sequence,
            }),
            lease_seconds,
        };
        match self
            .call("RenewLease", || async {
                pb::injection_service_client::InjectionServiceClient::new(self.channel.clone())
                    .renew_lease(self.request(request.clone()))
                    .await
            })
            .await
        {
            Ok(_) => Ok(true),
            // On this RPC the code has one meaning: the generation is not live.
            Err(status) if status.code() == Code::FailedPrecondition => Ok(false),
            Err(status) => {
                self.lease_unsupported(&status);
                Err(failed("RenewLease", &status))
            }
        }
    }

    fn lease_confirmed(&self) -> bool {
        self.lease_confirmed
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait]
impl DaemonHealthObserver for RustBgpdAnnouncer {
    async fn daemon_health(&self) -> Result<DaemonHealth> {
        let response = self
            .rpc("GetHealth", || async {
                pb::control_service_client::ControlServiceClient::new(self.channel.clone())
                    .get_health(self.request(pb::HealthRequest {}))
                    .await
            })
            .await?;
        Ok(DaemonHealth {
            version: if response.daemon_version.is_empty() {
                None
            } else {
                Some(response.daemon_version)
            },
            uptime_seconds: response.uptime_seconds,
            ready: response.healthy,
        })
    }
}

fn decode_export(entry: pb::PathExportDispositionEntry) -> Result<PeerExport> {
    entry
        .peer_address
        .parse::<std::net::IpAddr>()
        .map_err(|_| invalid("invalid export peer address"))?;
    let disposition = match pb::PathExportDisposition::try_from(entry.disposition) {
        Ok(pb::PathExportDisposition::Committed) => ExportDisposition::Committed,
        Ok(pb::PathExportDisposition::Withheld) => ExportDisposition::Withheld,
        Ok(pb::PathExportDisposition::Pending) => ExportDisposition::Pending,
        _ => return Err(invalid("unknown export disposition")),
    };
    Ok(PeerExport {
        peer_address: entry.peer_address,
        disposition,
        reason: entry.reason,
        explain_code: entry.explain_code,
        detail: entry.detail,
        advertised_path_id: entry.advertised_path_id,
    })
}

#[async_trait]
impl ExportObserver for RustBgpdAnnouncer {
    async fn blackhole_exports(&self, prefix: &ipnet::IpNet) -> Result<Option<Vec<PeerExport>>> {
        let mut peers: Vec<PeerExport> = Vec::new();
        let mut page_token = String::new();
        loop {
            let request = pb::ListPathExportDispositionsRequest {
                prefix: prefix.addr().to_string(),
                prefix_length: prefix.prefix_len().into(),
                path_id: 0,
                page_size: ROUTE_PAGE_SIZE,
                page_token: page_token.clone(),
            };
            let response = match self
                .call("ListPathExportDispositions", || async {
                    pb::injection_service_client::InjectionServiceClient::new(self.channel.clone())
                        .list_path_export_dispositions(self.request(request.clone()))
                        .await
                })
                .await
            {
                Ok(response) => response,
                // No local route at the key. Mid-walk the route went away, so the
                // pages read so far are partial: that is an error, not absence.
                Err(status) if status.code() == Code::NotFound && page_token.is_empty() => {
                    return Ok(None);
                }
                Err(status) => return Err(failed("ListPathExportDispositions", &status)),
            };
            for entry in response.peers {
                let peer = decode_export(entry)?;
                if peers
                    .iter()
                    .any(|seen| seen.peer_address == peer.peer_address)
                {
                    return Err(invalid("export disposition read repeated a peer"));
                }
                peers.push(peer);
            }
            if response.next_page_token.is_empty() {
                return Ok(Some(peers));
            }
            if response.next_page_token == page_token {
                return Err(invalid("export disposition read did not advance"));
            }
            page_token = response.next_page_token;
        }
    }
}

#[async_trait]
impl PeerObserver for RustBgpdAnnouncer {
    async fn session_status(&self) -> Result<Vec<PeerStatus>> {
        let response = self
            .rpc("ListNeighbors", || async {
                pb::neighbor_service_client::NeighborServiceClient::new(self.channel.clone())
                    .list_neighbors(self.request(pb::ListNeighborsRequest {}))
                    .await
            })
            .await?;
        response
            .neighbors
            .into_iter()
            .map(|peer| {
                if peer.stale {
                    return Err(invalid("stale rustbgpd peer state"));
                }
                let config = peer
                    .config
                    .ok_or_else(|| invalid("missing peer configuration"))?;
                config
                    .address
                    .parse::<std::net::IpAddr>()
                    .map_err(|_| invalid("invalid peer address"))?;
                let state = match peer.state {
                    1 => SessionState::Idle,
                    2 => SessionState::Connect,
                    3 => SessionState::Active,
                    4 => SessionState::OpenSent,
                    5 => SessionState::OpenConfirm,
                    6 => SessionState::Established,
                    _ => return Err(invalid("unknown peer state")),
                };
                Ok(PeerStatus {
                    name: config.address.clone(),
                    address: config.address,
                    state,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::ActionType;

    #[test]
    fn default_max_ports_guardrail_fits_under_the_encoder_cap() {
        let guardrails: crate::config::GuardrailsConfig = crate::config::parse_yaml("{}").unwrap();
        // The default is FRR's five values per component, below the encoder cap.
        assert_eq!(guardrails.max_ports, 5);
        assert!(guardrails.max_ports <= MAX_PORTS_PER_LIST);
        let at_cap = FlowSpecNlri {
            dst_prefix: "192.0.2.1/32".into(),
            protocol: Some(17),
            dst_ports: (1..=8).collect(),
            src_ports: (11..=18).collect(),
            ..Default::default()
        };
        encode_match(&at_cap).unwrap();
        for over in [
            FlowSpecNlri {
                dst_ports: (1..=9).collect(),
                ..at_cap.clone()
            },
            FlowSpecNlri {
                src_ports: (11..=19).collect(),
                ..at_cap.clone()
            },
        ] {
            assert!(encode_match(&over).is_err());
        }
    }

    #[tokio::test]
    async fn match_identity_uses_the_same_canonicalization_as_add_and_delete() {
        let writer = RustBgpdAnnouncer::new(
            Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
            None,
        );
        for prefix in ["192.0.2.1/32", "2001:db8::1/128"] {
            let left = FlowSpecNlri {
                dst_prefix: prefix.into(),
                protocol: Some(17),
                dst_ports: vec![443, 53],
                ..Default::default()
            };
            let mut right = left.clone();
            right.dst_ports.reverse();
            if prefix.contains(':') {
                right.dst_prefix = "2001:0DB8:0:0:0:0:0:1/128".into();
            }
            assert!(writer.matches_nlri(&left, &right).unwrap());
            right.dst_ports = vec![443, 53, 53];
            assert!(!writer.matches_nlri(&left, &right).unwrap());
            right.dst_ports = left.dst_ports.clone();
            right.protocol = Some(6);
            assert!(!writer.matches_nlri(&left, &right).unwrap());
            right.dst_prefix = "invalid".into();
            assert!(writer.matches_nlri(&left, &right).is_err());
            assert!(writer.matches_nlri(&right, &left).is_err());
        }
    }

    #[test]
    fn action_boundaries_preserve_exact_rates_in_both_families() {
        for prefix in ["192.0.2.1/32", "2001:db8::1/128"] {
            let mut rule = FlowSpecRule::new(
                FlowSpecNlri {
                    dst_prefix: prefix.into(),
                    protocol: Some(17),
                    dst_ports: vec![53],
                    ..Default::default()
                },
                FlowSpecAction::discard(),
            );
            for action in std::iter::once(FlowSpecAction::discard()).chain(
                [1, 7, 8, 9, 16_777_216, 16_777_218, 1_000_000_000].map(FlowSpecAction::police),
            ) {
                rule.actions = vec![action.clone()];
                let encoded = encode(&rule).unwrap();
                let Some(pb::flow_spec_action::Action::TrafficRate(rate)) =
                    &encoded.actions[0].action
                else {
                    panic!("expected traffic rate");
                };
                let ec = (0x8006_u64 << 48) | u64::from(rate.rate.to_bits());
                let decoded = decode(
                    pb::FlowSpecRouteEntry {
                        components: encoded.components,
                        actions: encoded.actions,
                        afi_safi: encoded.afi_safi,
                        peer_address: "0.0.0.0".into(),
                        extended_communities: vec![ec],
                        ..Default::default()
                    },
                    encoded.afi_safi,
                )
                .unwrap();
                assert_eq!(decoded.actions[0].action_type, action.action_type);
                assert_eq!(decoded.actions[0].rate_bps, action.rate_bps);
            }
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
                rule.actions = actions;
                assert!(encode(&rule).is_err());
            }
        }
    }

    #[test]
    fn codec_roundtrip_and_rejects_lossy_values() {
        let rule = FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: "192.0.2.1/32".into(),
                protocol: Some(6),
                dst_ports: vec![443, 80],
                ..Default::default()
            },
            FlowSpecAction::police(8000),
        );
        let encoded = encode(&rule).unwrap();
        assert_eq!(
            encoded
                .components
                .iter()
                .map(|c| c.r#type)
                .collect::<Vec<_>>(),
            [1, 3, 5]
        );
        assert_eq!(encoded.components[2].value, "=80, =443");
        let mut route = pb::FlowSpecRouteEntry {
            components: encoded.components,
            actions: encoded.actions,
            peer_address: "0.0.0.0".into(),
            afi_safi: 3,
            extended_communities: vec![(0x8006_u64 << 48) | u64::from(1000.0_f32.to_bits())],
            ..Default::default()
        };
        route.components[2].value = "==80, ==443".into();
        assert_eq!(decode(route.clone(), 3).unwrap().nlri.dst_ports, [80, 443]);
        route.components[2].value = ">80".into();
        assert!(decode(route, 3).is_err());
        let mut bad = rule;
        bad.actions[0].rate_bps = Some(8001);
        assert!(encode(&bad).is_ok());
        bad.actions[0].rate_bps = Some(u64::MAX);
        assert!(encode(&bad).is_err());
    }

    /// Daemon read-back of `encode_match` output (`format_numeric_ops`, `format_bitmask_ops`).
    pub(super) fn read_back(components: &mut [pb::FlowSpecComponent]) {
        for component in components {
            component.value = match component.r#type {
                3 | 5 | 6 => component.value.replace('=', "=="),
                12 => format!(
                    "0x{:04x}/match",
                    u16::from_str_radix(&component.value[2..], 16).unwrap()
                ),
                _ => component.value.clone(),
            };
        }
    }

    fn route(rule: &FlowSpecRule) -> pb::FlowSpecRouteEntry {
        let encoded = encode(rule).unwrap();
        let mut components = encoded.components;
        read_back(&mut components);
        pb::FlowSpecRouteEntry {
            components,
            actions: encoded.actions,
            peer_address: "0.0.0.0".into(),
            afi_safi: encoded.afi_safi,
            extended_communities: vec![0x8006_u64 << 48],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn amplification_components_encode_per_adr_and_read_back_strictly() {
        use crate::domain::{FragmentMatch, PacketLengthRange};
        let writer = RustBgpdAnnouncer::new(
            Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
            None,
        );
        for prefix in ["192.0.2.1/32", "2001:db8::1/128"] {
            let udp = FlowSpecNlri {
                dst_prefix: prefix.into(),
                protocol: Some(17),
                ..Default::default()
            };
            let ports = FlowSpecNlri {
                src_ports: vec![123, 53, 53],
                ..udp.clone()
            };
            let length = FlowSpecNlri {
                packet_length: Some(PacketLengthRange {
                    min: 468,
                    max: 65535,
                }),
                ..ports.clone()
            };
            let fragment = FlowSpecNlri {
                fragment: Some(FragmentMatch::NonFirst),
                ..udp.clone()
            };
            // Not a valid rule (ADR 028 invariants), but it pins the full component order.
            let every = FlowSpecNlri {
                dst_ports: vec![443, 80],
                fragment: Some(FragmentMatch::NonFirst),
                ..length.clone()
            };
            let pinned: [(&FlowSpecNlri, &[(u32, &str)]); 4] = [
                (&ports, &[(6, "=53, =123")]),
                (&length, &[(6, "=53, =123"), (10, ">=468 & <=65535")]),
                // 0x02 in both families: the IPv6-reserved bit 0x01 is never emitted.
                (&fragment, &[(12, "0x02")]),
                (
                    &every,
                    &[
                        (5, "=80, =443"),
                        (6, "=53, =123"),
                        (10, ">=468 & <=65535"),
                        (12, "0x02"),
                    ],
                ),
            ];
            for (nlri, expected) in pinned {
                let (_, components) = encode_match(nlri).unwrap();
                let tail: Vec<_> = components[2..]
                    .iter()
                    .map(|c| (c.r#type, c.value.as_str()))
                    .collect();
                assert_eq!(tail, expected);
                assert_eq!(
                    components
                        .iter()
                        .map(|c| c.r#type)
                        .take(2)
                        .collect::<Vec<_>>(),
                    [1, 3]
                );
                // Read back as the same canonical rule, and the same backend route.
                let rule = FlowSpecRule::new(nlri.clone(), FlowSpecAction::discard());
                let decoded = decode(route(&rule), route(&rule).afi_safi).unwrap();
                assert_eq!(decoded.nlri_hash(), rule.nlri_hash());
                assert_eq!(
                    decoded.nlri.src_ports,
                    [53, 123][..nlri.src_ports.len().min(2)]
                );
                assert_eq!(decoded.nlri.packet_length, nlri.packet_length);
                assert_eq!(decoded.nlri.fragment, nlri.fragment);
                assert!(writer.matches_nlri(nlri, &decoded.nlri).unwrap());
            }
            // One differing component is a different route.
            for (left, right) in [
                (&ports, &udp),
                (
                    &ports,
                    &FlowSpecNlri {
                        src_ports: vec![53],
                        ..ports.clone()
                    },
                ),
                (&length, &ports),
                (
                    &length,
                    &FlowSpecNlri {
                        packet_length: Some(PacketLengthRange {
                            min: 468,
                            max: 1500,
                        }),
                        ..length.clone()
                    },
                ),
                (&fragment, &udp),
            ] {
                assert!(!writer.matches_nlri(left, right).unwrap());
                assert!(!writer.matches_nlri(right, left).unwrap());
            }
            let mut nine = ports.clone();
            nine.src_ports = (1..=9).collect();
            assert!(encode_match(&nine).is_err());
            // Only the exact rendered forms decode; anything else fails the whole read.
            let rule = FlowSpecRule::new(every.clone(), FlowSpecAction::discard());
            for (index, value) in [
                (3, "=53, =123"),
                (3, "==123, ==53"),
                (3, "==53, ==53, ==123"),
                (3, "==53,==123"),
                (3, "==53 & ==123"),
                (3, ">=53"),
                (3, "==1, ==2, ==3, ==4, ==5, ==6, ==7, ==8, ==9"),
                (4, ">468 & <=65535"),
                (4, ">=468, <=65535"),
                (4, ">=468 & <=65535 & <=1500"),
                (4, ">=0468 & <=65535"),
                (4, ">=468 & <=65536"),
                (5, "0x02"),
                (5, "0x0002"),
                (5, "0x0001/match"),
                (5, "0x0003/match"),
                (5, "!0x0002/match"),
                (5, "0x0002/match, 0x0004/match"),
            ] {
                let mut bad = route(&rule);
                bad.components[index].value = value.into();
                assert!(decode(bad, route(&rule).afi_safi).is_err(), "{value}");
            }
            for mutate in [
                // Unknown component types, descending order and a prefix-shaped value.
                |c: &mut Vec<pb::FlowSpecComponent>| c[5].r#type = 9,
                |c: &mut Vec<pb::FlowSpecComponent>| c[3].r#type = 4,
                |c: &mut Vec<pb::FlowSpecComponent>| c.swap(4, 5),
                |c: &mut Vec<pb::FlowSpecComponent>| c[5].prefix = "192.0.2.1/32".into(),
            ] {
                let mut bad = route(&rule);
                mutate(&mut bad.components);
                assert!(decode(bad, route(&rule).afi_safi).is_err());
            }
        }
    }
}

#[cfg(all(test, feature = "test-utils"))]
#[path = "rustbgpd_tests.rs"]
mod rpc_tests;
