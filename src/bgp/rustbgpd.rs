use super::{
    BlackholeRoute, BlackholeSpeaker, DaemonHealth, DaemonHealthObserver, FlowSpecAnnouncer,
    FlowSpecReader, FlowSpecWriter, PeerObserver, PeerStatus, SessionState, rustbgpd_pb as pb,
};
use crate::{
    config::RustBgpdConfig,
    domain::{FlowSpecAction, FlowSpecNlri, FlowSpecRule},
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
        Self::connect_with_token(config, &token).await
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
                return Ok(Self { channel, token });
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
        Ok(Self { channel, token })
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

    async fn rpc<T, F, Fut>(&self, operation: &str, mut call: F) -> Result<T>
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
                Err(status) => {
                    return Err(invalid(&format!(
                        "{operation} RPC failed: {:?}",
                        status.code()
                    )));
                }
            }
        }
        unreachable!()
    }
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
    if ports.len() > 8 {
        return Err(invalid("at most eight destination ports are supported"));
    }
    ports.sort_unstable();
    if !ports.is_empty() {
        components.push(pb::FlowSpecComponent {
            r#type: 5,
            value: ports
                .iter()
                .map(|port| format!("={port}"))
                .collect::<Vec<_>>()
                .join(", "),
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
    let rule = FlowSpecRule::new(nlri, action);
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

/// Strict: any attribute prefixd never injects fails the whole read.
fn decode_blackhole(route: pb::Route, family: i32) -> Result<BlackholeRoute> {
    if route.peer_address != "0.0.0.0"
        || route.origin != 0
        || !route.as_path.is_empty()
        || route.local_pref_attr.is_some()
        || route.med_attr.is_some()
        || route.med != 0
        || !route.extended_communities.is_empty()
        || route.path_id != 0
        || route.stale
        || route.llgr_stale
        || route.aggregator.is_some()
        || route.atomic_aggregate
    {
        return Err(invalid("unsupported local route attributes"));
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
        .ok_or_else(|| invalid("invalid local route prefix"))?;
    let next_hop = route
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
    let decoded = BlackholeRoute::new(prefix, next_hop, route.communities.clone(), large.clone())
        .map_err(|_| invalid("local route is not a blackhole host route"))?;
    // prefixd injects canonical communities including BLACKHOLE; anything else is foreign.
    if decoded.communities() != route.communities || decoded.large_communities() != large {
        return Err(invalid("unsupported local route communities"));
    }
    Ok(decoded)
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
    fn reader(&self) -> Option<&dyn FlowSpecReader> {
        Some(self)
    }
    fn daemon_health_observer(&self) -> Option<&dyn DaemonHealthObserver> {
        Some(self)
    }

    fn peer_observer(&self) -> Option<&dyn PeerObserver> {
        Some(self)
    }
}

#[async_trait]
impl FlowSpecWriter for RustBgpdAnnouncer {
    fn matches_nlri(&self, left: &FlowSpecNlri, right: &FlowSpecNlri) -> Result<bool> {
        Ok(encode_match(left)? == encode_match(right)?)
    }

    async fn announce(&self, rule: &FlowSpecRule) -> Result<()> {
        let payload = encode(rule)?;
        let response = self
            .rpc("AddFlowSpec", || async {
                pb::injection_service_client::InjectionServiceClient::new(self.channel.clone())
                    .add_flow_spec(self.request(payload.clone()))
                    .await
            })
            .await?;
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
    async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()> {
        let (afi_safi, components) = encode_match(&rule.nlri)?;
        let payload = pb::DeleteFlowSpecRequest {
            afi_safi,
            components,
            allow_missing: true,
        };
        let response = self
            .rpc("DeleteFlowSpec", || {
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
            .await?;
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
                rules.push(decode(
                    row.route.ok_or_else(|| invalid("missing local route"))?,
                    family,
                )?);
            }
        }
        Ok(rules)
    }
}
#[async_trait]
impl BlackholeSpeaker for RustBgpdAnnouncer {
    async fn announce_blackhole(&self, route: &BlackholeRoute) -> Result<()> {
        let payload = encode_blackhole(route);
        // AddPathResponse carries no outcome yet: OK is local Adj-RIB-In acceptance only.
        self.rpc("AddPath", || async {
            pb::injection_service_client::InjectionServiceClient::new(self.channel.clone())
                .add_path(self.request(payload.clone()))
                .await
        })
        .await?;
        Ok(())
    }

    async fn withdraw_blackhole(&self, prefix: &ipnet::IpNet) -> Result<()> {
        super::require_host_route(prefix)?;
        let payload = pb::DeletePathRequest {
            prefix: prefix.addr().to_string(),
            prefix_length: prefix.prefix_len().into(),
            path_id: 0,
        };
        self.rpc("DeletePath", || {
            let mut client =
                pb::injection_service_client::InjectionServiceClient::new(self.channel.clone());
            let request = self.request(payload.clone());
            async move {
                // DeletePath has no allow_missing; NOT_FOUND is its only "absent" reply.
                match client.delete_path(request).await {
                    Err(status) if status.code() == Code::NotFound => {
                        tracing::debug!("rustbgpd blackhole route already absent");
                        Ok(tonic::Response::new(pb::DeletePathResponse {}))
                    }
                    result => result,
                }
            }
        })
        .await?;
        Ok(())
    }

    async fn list_blackholes(&self) -> Result<Vec<BlackholeRoute>> {
        let mut routes = vec![];
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
                    routes.push(decode_blackhole(route, family)?);
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
        Ok(routes)
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

    #[tokio::test]
    async fn match_identity_uses_the_same_canonicalization_as_add_and_delete() {
        let writer = RustBgpdAnnouncer {
            channel: Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
            token: None,
        };
        for prefix in ["192.0.2.1/32", "2001:db8::1/128"] {
            let left = FlowSpecNlri {
                dst_prefix: prefix.into(),
                protocol: Some(17),
                dst_ports: vec![443, 53],
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
}

#[cfg(all(test, feature = "test-utils"))]
#[path = "rustbgpd_tests.rs"]
mod rpc_tests;
