use async_trait::async_trait;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tonic::transport::Channel;

use super::apipb::{
    AddPathRequest, Attribute, DeletePathRequest, ExtendedCommunitiesAttribute, ExtendedCommunity,
    Family, FlowSpecComponent, FlowSpecComponentItem, FlowSpecIpPrefix,
    FlowSpecNlri as ProtoFlowSpecNlri, FlowSpecRule as ProtoFlowSpecRule, ListPathRequest,
    ListPeerRequest, MpReachNlriAttribute, Nlri, OriginAttribute, Path, TableType,
    TrafficRateExtended, go_bgp_service_client::GoBgpServiceClient,
};
use super::apipb::{attribute, extended_community, flow_spec_rule, nlri};
use super::{
    FlowSpecAnnouncer, FlowSpecReader, FlowSpecWriter, PeerObserver, PeerStatus, SessionState,
};
#[cfg(test)]
use crate::domain::ActionType;
use crate::domain::{FlowSpecAction, FlowSpecNlri, FlowSpecRule, IpVersion};
use crate::error::{PrefixdError, Result};

const AFI_IP: i32 = 1;
const AFI_IP6: i32 = 2;
const SAFI_FLOWSPEC: i32 = 133;

// Timeout and retry configuration
const GRPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const GRPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RETRIES: u32 = 3;
const INITIAL_BACKOFF: Duration = Duration::from_millis(100);

/// GoBGP gRPC client for FlowSpec announcements
pub struct GoBgpAnnouncer {
    endpoint: String,
    client: Arc<RwLock<Option<GoBgpServiceClient<Channel>>>>,
}

impl GoBgpAnnouncer {
    pub fn new(endpoint: String) -> Self {
        Self {
            endpoint,
            client: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn connect(&mut self) -> Result<()> {
        let endpoint = if self.endpoint.starts_with("http") {
            self.endpoint.clone()
        } else {
            format!("http://{}", self.endpoint)
        };

        tracing::info!(endpoint = %endpoint, "connecting to GoBGP");

        let channel = Channel::from_shared(endpoint)
            .map_err(|e| PrefixdError::BgpSessionError {
                peer: "gobgp".to_string(),
                error: e.to_string(),
            })?
            .connect_timeout(GRPC_CONNECT_TIMEOUT)
            .timeout(GRPC_REQUEST_TIMEOUT)
            .connect()
            .await
            .map_err(|e| PrefixdError::BgpSessionError {
                peer: "gobgp".to_string(),
                error: e.to_string(),
            })?;

        let client = GoBgpServiceClient::new(channel);
        *self.client.write().await = Some(client);

        tracing::info!("connected to GoBGP");
        Ok(())
    }

    /// Execute a gRPC call with retry logic and exponential backoff
    async fn with_retry<F, Fut, T>(&self, operation: &str, mut f: F) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let mut last_error = None;
        let mut backoff = INITIAL_BACKOFF;

        for attempt in 1..=MAX_RETRIES {
            let result = tokio::time::timeout(GRPC_REQUEST_TIMEOUT, f())
                .await
                .unwrap_or_else(|_| {
                    Err(PrefixdError::BgpSessionError {
                        peer: "gobgp".to_string(),
                        error: format!("{operation} RPC deadline exceeded"),
                    })
                });
            match result {
                Ok(result) => return Ok(result),
                Err(e) => {
                    last_error = Some(e);
                    if attempt < MAX_RETRIES {
                        tracing::warn!(
                            operation = %operation,
                            attempt = attempt,
                            max_retries = MAX_RETRIES,
                            backoff_ms = backoff.as_millis(),
                            "gRPC call failed, retrying"
                        );
                        tokio::time::sleep(backoff).await;
                        backoff *= 2; // Exponential backoff
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            PrefixdError::Internal(format!(
                "{} failed after {} retries",
                operation, MAX_RETRIES
            ))
        }))
    }

    async fn get_client(&self) -> Result<GoBgpServiceClient<Channel>> {
        self.client
            .read()
            .await
            .clone()
            .ok_or_else(|| PrefixdError::BgpSessionError {
                peer: "gobgp".to_string(),
                error: "not connected".to_string(),
            })
    }

    /// Build a FlowSpec Path for GoBGP v4 API (uses typed oneof fields, not Any)
    fn build_flowspec_path(&self, rule: &FlowSpecRule) -> Result<Path> {
        let is_v6 = rule.nlri.ip_version() == IpVersion::V6;
        let afi = if is_v6 { AFI_IP6 } else { AFI_IP };

        let flowspec_nlri = if is_v6 {
            self.build_flowspec_nlri_v6(&rule.nlri)?
        } else {
            self.build_flowspec_nlri_v4(&rule.nlri)?
        };

        // Wrap FlowSpecNlri in the NLRI oneof
        let nlri = Nlri {
            nlri: Some(nlri::Nlri::FlowSpec(flowspec_nlri.clone())),
        };

        let family = Family {
            afi,
            safi: SAFI_FLOWSPEC,
        };

        let mut pattrs = self.build_path_attributes(&rule.actions)?;

        // GoBGP v4 requires MpReachNLRI with nexthop for FlowSpec
        // For FlowSpec, the nexthop is typically 0.0.0.0 (IPv4) or :: (IPv6)
        let mp_reach = MpReachNlriAttribute {
            family: Some(family),
            next_hops: vec![if is_v6 {
                "::".to_string()
            } else {
                "0.0.0.0".to_string()
            }],
            nlris: vec![Nlri {
                nlri: Some(nlri::Nlri::FlowSpec(flowspec_nlri)),
            }],
        };
        pattrs.push(Attribute {
            attr: Some(attribute::Attr::MpReach(mp_reach)),
        });

        Ok(Path {
            nlri: Some(nlri),
            pattrs,
            family: Some(family),
            ..Default::default()
        })
    }

    fn build_flowspec_withdraw_path(&self, nlri: &FlowSpecNlri) -> Result<Path> {
        let is_v6 = nlri.ip_version() == IpVersion::V6;
        let flowspec = if is_v6 {
            self.build_flowspec_nlri_v6(nlri)?
        } else {
            self.build_flowspec_nlri_v4(nlri)?
        };
        // Delete the specified local match even if its historical action is invalid.
        Ok(Path {
            nlri: Some(Nlri {
                nlri: Some(nlri::Nlri::FlowSpec(flowspec)),
            }),
            family: Some(Family {
                afi: if is_v6 { AFI_IP6 } else { AFI_IP },
                safi: SAFI_FLOWSPEC,
            }),
            is_withdraw: true,
            ..Default::default()
        })
    }

    fn build_flowspec_nlri_v4(&self, nlri: &FlowSpecNlri) -> Result<ProtoFlowSpecNlri> {
        refuse_unencoded_components(nlri)?;
        let (prefix_u32, prefix_len) = self.parse_prefix_v4(&nlri.dst_prefix)?;

        // Build FlowSpec NLRI components per RFC 5575 using typed FlowSpecRule
        let mut rules: Vec<ProtoFlowSpecRule> = Vec::new();

        // Type 1: Destination Prefix - use FlowSpecIPPrefix for proper encoding
        let prefix_bytes = prefix_u32.to_be_bytes();
        let addr = Ipv4Addr::new(
            prefix_bytes[0],
            prefix_bytes[1],
            prefix_bytes[2],
            prefix_bytes[3],
        );
        let dst_prefix = FlowSpecIpPrefix {
            r#type: 1, // FLOWSPEC_TYPE_DST_PREFIX
            prefix_len: prefix_len as u32,
            prefix: addr.to_string(),
            offset: 0, // IPv4 doesn't use offset
        };
        rules.push(ProtoFlowSpecRule {
            rule: Some(flow_spec_rule::Rule::IpPrefix(dst_prefix)),
        });

        // Type 3: IP Protocol (if specified)
        if let Some(proto) = nlri.protocol {
            let proto_component = FlowSpecComponent {
                r#type: 3, // FLOWSPEC_TYPE_IP_PROTO
                items: vec![FlowSpecComponentItem {
                    op: 0x81, // end-of-list + equals
                    value: proto as u64,
                }],
            };
            rules.push(ProtoFlowSpecRule {
                rule: Some(flow_spec_rule::Rule::Component(proto_component)),
            });
        }

        // Type 5: Destination Port
        if !nlri.dst_ports.is_empty() {
            let items: Vec<_> = nlri
                .dst_ports
                .iter()
                .enumerate()
                .map(|(i, &port)| {
                    let op = if i == nlri.dst_ports.len() - 1 {
                        0x81u32 // end-of-list + equals
                    } else {
                        0x01u32 // equals
                    };
                    FlowSpecComponentItem {
                        op,
                        value: port as u64,
                    }
                })
                .collect();

            let port_component = FlowSpecComponent {
                r#type: 5, // FLOWSPEC_TYPE_DST_PORT
                items,
            };
            rules.push(ProtoFlowSpecRule {
                rule: Some(flow_spec_rule::Rule::Component(port_component)),
            });
        }

        Ok(ProtoFlowSpecNlri { rules })
    }

    fn build_flowspec_nlri_v6(&self, nlri: &FlowSpecNlri) -> Result<ProtoFlowSpecNlri> {
        refuse_unencoded_components(nlri)?;
        let (addr, prefix_len) = self.parse_prefix_v6(&nlri.dst_prefix)?;

        // Build FlowSpec NLRI components for IPv6 per RFC 8956
        let mut rules: Vec<ProtoFlowSpecRule> = Vec::new();

        // Type 1: Destination Prefix (IPv6) - use FlowSpecIPPrefix for v6
        let dst_prefix_component = FlowSpecIpPrefix {
            r#type: 1, // FLOWSPEC_TYPE_DST_PREFIX
            prefix_len: prefix_len as u32,
            prefix: addr.to_string(),
            offset: 0,
        };
        rules.push(ProtoFlowSpecRule {
            rule: Some(flow_spec_rule::Rule::IpPrefix(dst_prefix_component)),
        });

        // Type 3: Next Header (equivalent to IP Protocol for IPv6)
        if let Some(proto) = nlri.protocol {
            let proto_component = FlowSpecComponent {
                r#type: 3, // FLOWSPEC_TYPE_IP_PROTO / NEXT_HEADER
                items: vec![FlowSpecComponentItem {
                    op: 0x81, // end-of-list + equals
                    value: proto as u64,
                }],
            };
            rules.push(ProtoFlowSpecRule {
                rule: Some(flow_spec_rule::Rule::Component(proto_component)),
            });
        }

        // Type 5: Destination Port
        if !nlri.dst_ports.is_empty() {
            let items: Vec<_> = nlri
                .dst_ports
                .iter()
                .enumerate()
                .map(|(i, &port)| {
                    let op = if i == nlri.dst_ports.len() - 1 {
                        0x81u32
                    } else {
                        0x01u32
                    };
                    FlowSpecComponentItem {
                        op,
                        value: port as u64,
                    }
                })
                .collect();

            let port_component = FlowSpecComponent { r#type: 5, items };
            rules.push(ProtoFlowSpecRule {
                rule: Some(flow_spec_rule::Rule::Component(port_component)),
            });
        }

        Ok(ProtoFlowSpecNlri { rules })
    }

    fn build_path_attributes(&self, actions: &[FlowSpecAction]) -> Result<Vec<Attribute>> {
        let [action] = actions else {
            return Err(PrefixdError::BgpAnnouncementFailed(
                "exactly one traffic rate action is required".into(),
            ));
        };
        let rate = action
            .traffic_rate_bytes_per_second()
            .map_err(|error| PrefixdError::BgpAnnouncementFailed(error.to_string()))?;
        let mut pattrs = Vec::new();

        // Origin attribute (IGP)
        let origin = OriginAttribute { origin: 0 };
        pattrs.push(Attribute {
            attr: Some(attribute::Attr::Origin(origin)),
        });

        let communities = vec![ExtendedCommunity {
            extcom: Some(extended_community::Extcom::TrafficRate(
                TrafficRateExtended { asn: 0, rate },
            )),
        }];
        pattrs.push(Attribute {
            attr: Some(attribute::Attr::ExtendedCommunities(
                ExtendedCommunitiesAttribute { communities },
            )),
        });

        Ok(pattrs)
    }

    pub fn parse_prefix_v4(&self, prefix: &str) -> Result<(u32, u8)> {
        let parts: Vec<&str> = prefix.split('/').collect();
        let ip = Ipv4Addr::from_str(parts[0]).map_err(|_| {
            PrefixdError::InvalidPrefix(format!("invalid IPv4 in prefix: {}", prefix))
        })?;
        let len: u8 = parts.get(1).unwrap_or(&"32").parse().map_err(|_| {
            PrefixdError::InvalidPrefix(format!("invalid prefix length: {}", prefix))
        })?;
        Ok((u32::from(ip), len))
    }

    pub fn parse_prefix_v6(&self, prefix: &str) -> Result<(Ipv6Addr, u8)> {
        let parts: Vec<&str> = prefix.split('/').collect();
        let ip = Ipv6Addr::from_str(parts[0]).map_err(|_| {
            PrefixdError::InvalidPrefix(format!("invalid IPv6 in prefix: {}", prefix))
        })?;
        let len: u8 = parts.get(1).unwrap_or(&"128").parse().map_err(|_| {
            PrefixdError::InvalidPrefix(format!("invalid prefix length: {}", prefix))
        })?;
        Ok((ip, len))
    }
}

/// Dropping a component would widen the rule, so refuse it before any RPC.
fn refuse_unencoded_components(nlri: &FlowSpecNlri) -> Result<()> {
    if nlri.is_extended() {
        return Err(PrefixdError::Internal(
            "GoBGP: source port, fragment and packet length matches are not supported".into(),
        ));
    }
    Ok(())
}

impl FlowSpecAnnouncer for GoBgpAnnouncer {
    fn backend(&self) -> &'static str {
        "gobgp"
    }
    fn reader(&self) -> Option<&dyn FlowSpecReader> {
        Some(self)
    }
    fn peer_observer(&self) -> Option<&dyn PeerObserver> {
        Some(self)
    }
}

#[async_trait]
impl FlowSpecWriter for GoBgpAnnouncer {
    async fn announce(&self, rule: &FlowSpecRule) -> Result<()> {
        let path = self.build_flowspec_path(rule)?;
        let nlri_hash = rule.nlri_hash();
        let dst_prefix = rule.nlri.dst_prefix.clone();

        tracing::info!(
            nlri_hash = %nlri_hash,
            dst_prefix = %dst_prefix,
            "announcing flowspec rule via GoBGP"
        );

        self.with_retry("AddPath", || async {
            let mut client = self.get_client().await?;
            let request = AddPathRequest {
                table_type: TableType::Global as i32,
                path: Some(path.clone()),
                vrf_id: String::new(),
            };

            client.add_path(request).await.map_err(|e| {
                PrefixdError::BgpAnnouncementFailed(format!("GoBGP AddPath failed: {}", e))
            })?;

            Ok(())
        })
        .await?;

        tracing::info!(
            nlri_hash = %nlri_hash,
            "flowspec rule announced"
        );

        Ok(())
    }
    async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()> {
        let path = self.build_flowspec_withdraw_path(&rule.nlri)?;
        let is_v6 = rule.nlri.ip_version() == IpVersion::V6;
        let afi = if is_v6 { AFI_IP6 } else { AFI_IP };
        let nlri_hash = rule.nlri_hash();
        let dst_prefix = rule.nlri.dst_prefix.clone();

        tracing::info!(
            nlri_hash = %nlri_hash,
            dst_prefix = %dst_prefix,
            ipv6 = is_v6,
            "withdrawing flowspec rule via GoBGP"
        );

        self.with_retry("DeletePath", || async {
            let mut client = self.get_client().await?;
            let request = DeletePathRequest {
                table_type: TableType::Global as i32,
                path: Some(path.clone()),
                vrf_id: String::new(),
                family: Some(Family {
                    afi,
                    safi: SAFI_FLOWSPEC,
                }),
                uuid: Vec::new(),
            };

            client.delete_path(request).await.map_err(|e| {
                PrefixdError::BgpWithdrawalFailed(format!("GoBGP DeletePath failed: {}", e))
            })?;

            Ok(())
        })
        .await?;

        tracing::info!(
            nlri_hash = %nlri_hash,
            "flowspec rule withdrawn"
        );

        Ok(())
    }
}
#[async_trait]
impl FlowSpecReader for GoBgpAnnouncer {
    async fn list_active(&self) -> Result<Vec<FlowSpecRule>> {
        self.observe("ListPath", async {
            let mut rules = self.list_active_for_afi(AFI_IP).await?;
            rules.extend(self.list_active_for_afi(AFI_IP6).await?);
            Ok(rules)
        })
        .await
    }
}
#[async_trait]
impl PeerObserver for GoBgpAnnouncer {
    async fn session_status(&self) -> Result<Vec<PeerStatus>> {
        self.observe("ListPeer", async {
            let mut client = self.get_client().await?;

            let request = ListPeerRequest {
                ..Default::default()
            };

            let mut stream = client
                .list_peer(request)
                .await
                .map_err(|e| PrefixdError::Internal(format!("GoBGP ListPeer failed: {}", e)))?
                .into_inner();

            let mut peers = Vec::new();

            while let Some(resp) = stream
                .message()
                .await
                .map_err(|e| PrefixdError::Internal(format!("GoBGP stream error: {}", e)))?
            {
                if let Some(peer) = resp.peer {
                    let state = peer
                        .state
                        .map(|s| match s.session_state {
                            1 => SessionState::Idle,
                            2 => SessionState::Connect,
                            3 => SessionState::Active,
                            4 => SessionState::OpenSent,
                            5 => SessionState::OpenConfirm,
                            6 => SessionState::Established,
                            _ => SessionState::Idle,
                        })
                        .unwrap_or(SessionState::Idle);

                    let name = peer
                        .conf
                        .as_ref()
                        .map(|c| c.neighbor_address.clone())
                        .unwrap_or_default();

                    peers.push(PeerStatus {
                        name: name.clone(),
                        address: name,
                        state,
                    });
                }
            }

            Ok(peers)
        })
        .await
    }
}

impl GoBgpAnnouncer {
    // Endpoint timeouts stop at response headers; observation must include every row and trailer.
    async fn observe<T>(
        &self,
        operation: &str,
        future: impl std::future::Future<Output = Result<T>>,
    ) -> Result<T> {
        tokio::time::timeout(GRPC_REQUEST_TIMEOUT, future)
            .await
            .unwrap_or_else(|_| {
                Err(PrefixdError::BgpSessionError {
                    peer: "gobgp".to_string(),
                    error: format!("{operation} observation deadline exceeded"),
                })
            })
    }

    /// Query FlowSpec RIB for a specific address family
    async fn list_active_for_afi(&self, afi: i32) -> Result<Vec<FlowSpecRule>> {
        let mut client = self.get_client().await?;
        let mut rules = Vec::new();

        let request = ListPathRequest {
            table_type: TableType::Global as i32,
            family: Some(Family {
                afi,
                safi: SAFI_FLOWSPEC,
            }),
            ..Default::default()
        };

        let mut stream = client
            .list_path(request)
            .await
            .map_err(|e| PrefixdError::Internal(format!("GoBGP ListPath failed: {}", e)))?
            .into_inner();

        while let Some(resp) = stream
            .message()
            .await
            .map_err(|e| PrefixdError::Internal(format!("GoBGP stream error: {}", e)))?
        {
            let dest = resp.destination.ok_or_else(|| {
                PrefixdError::Internal("GoBGP ListPath response has no destination".into())
            })?;
            for path in dest.paths {
                // GoBGP leaves neighbor_ip empty for local paths; UUID is absent even on API paths.
                if !path.neighbor_ip.is_empty() {
                    continue;
                }
                if path.family
                    != Some(Family {
                        afi,
                        safi: SAFI_FLOWSPEC,
                    })
                {
                    return Err(PrefixdError::Internal(
                        "GoBGP local path has wrong family".into(),
                    ));
                }
                rules.push(self.parse_flowspec_path(&path)?);
            }
        }

        Ok(rules)
    }

    /// Parse a FlowSpec path from GoBGP's RIB into our domain FlowSpecRule.
    /// This is the inverse of build_flowspec_path - used by reconciliation to compare
    /// desired state (DB) vs actual state (BGP RIB).
    /// Updated for GoBGP v4 API which uses typed oneof instead of Any.
    fn parse_flowspec_path(&self, path: &Path) -> Result<FlowSpecRule> {
        if path.is_withdraw {
            return Err(PrefixdError::Internal(
                "GoBGP local inventory contains a withdrawal".into(),
            ));
        }
        // 1. Parse NLRI (now a typed Nlri message with oneof)
        let nlri_wrapper = path
            .nlri
            .as_ref()
            .ok_or_else(|| PrefixdError::Internal("Path has no NLRI".to_string()))?;

        let flowspec_nlri = self.decode_flowspec_nlri(nlri_wrapper)?;

        let afi = match flowspec_nlri.ip_version() {
            IpVersion::V4 => AFI_IP,
            IpVersion::V6 => AFI_IP6,
        };
        if path.family
            != Some(Family {
                afi,
                safi: SAFI_FLOWSPEC,
            })
        {
            return Err(PrefixdError::Internal(
                "GoBGP local path NLRI/family mismatch".into(),
            ));
        }

        // 2. Parse path attributes for action (traffic-rate extended community)
        let action = self.parse_flowspec_action(&path.pattrs)?;

        Ok(FlowSpecRule::new(flowspec_nlri, action))
    }

    /// Decode FlowSpecNLRI from typed Nlri and extract match criteria
    /// GoBGP v4 uses oneof instead of Any for type safety
    pub fn decode_flowspec_nlri(&self, nlri_wrapper: &Nlri) -> Result<FlowSpecNlri> {
        // Extract FlowSpec from the oneof
        let proto_nlri = match &nlri_wrapper.nlri {
            Some(nlri::Nlri::FlowSpec(fs)) => fs,
            Some(other) => {
                return Err(PrefixdError::Internal(format!(
                    "Unexpected NLRI type: expected FlowSpec, got {:?}",
                    std::mem::discriminant(other)
                )));
            }
            None => {
                return Err(PrefixdError::Internal("NLRI has no inner type".to_string()));
            }
        };

        let mut dst_prefix = String::new();
        let mut protocol: Option<u8> = None;
        let mut dst_ports: Vec<u16> = Vec::new();

        let mut previous_type = 0;
        for rule in &proto_nlri.rules {
            let component_type = match &rule.rule {
                Some(flow_spec_rule::Rule::IpPrefix(prefix)) if prefix.r#type == 1 => {
                    let address = prefix.prefix.parse::<std::net::IpAddr>().map_err(|_| {
                        PrefixdError::Internal("GoBGP invalid destination address".into())
                    })?;
                    let max_len = if address.is_ipv4() { 32 } else { 128 };
                    if prefix.offset != 0 || prefix.prefix_len > max_len {
                        return Err(PrefixdError::Internal(
                            "GoBGP unsupported destination prefix length/offset".into(),
                        ));
                    }
                    dst_prefix = format!("{}/{}", prefix.prefix, prefix.prefix_len);
                    1
                }
                Some(flow_spec_rule::Rule::Component(component))
                    if matches!(component.r#type, 3 | 5) =>
                {
                    if component.items.is_empty()
                        || (component.r#type == 3 && component.items.len() != 1)
                    {
                        return Err(PrefixdError::Internal(
                            "GoBGP unsupported numeric component cardinality".into(),
                        ));
                    }
                    for (index, item) in component.items.iter().enumerate() {
                        let expected = if index + 1 == component.items.len() {
                            0x81
                        } else {
                            0x01
                        };
                        // Wire operand-width bits do not change equality semantics.
                        if item.op & !0x30 != expected {
                            return Err(PrefixdError::Internal(
                                "GoBGP unsupported numeric operator".into(),
                            ));
                        }
                        if component.r#type == 3 {
                            protocol = Some(u8::try_from(item.value).map_err(|_| {
                                PrefixdError::Internal("GoBGP protocol exceeds u8".into())
                            })?);
                        } else {
                            dst_ports.push(u16::try_from(item.value).map_err(|_| {
                                PrefixdError::Internal("GoBGP destination port exceeds u16".into())
                            })?);
                        }
                    }
                    component.r#type
                }
                _ => {
                    return Err(PrefixdError::Internal(
                        "GoBGP unsupported or missing FlowSpec component".into(),
                    ));
                }
            };
            if component_type <= previous_type {
                return Err(PrefixdError::Internal(
                    "GoBGP duplicate or unordered FlowSpec component".into(),
                ));
            }
            previous_type = component_type;
        }

        if dst_prefix.is_empty() {
            return Err(PrefixdError::Internal(
                "FlowSpec NLRI missing destination prefix".to_string(),
            ));
        }

        Ok(FlowSpecNlri {
            dst_prefix,
            protocol,
            dst_ports,
            ..Default::default()
        })
    }

    /// Parse extended communities to extract the FlowSpec action (traffic-rate)
    /// GoBGP v4 uses typed Attribute with oneof instead of Any
    fn parse_flowspec_action(&self, pattrs: &[Attribute]) -> Result<FlowSpecAction> {
        let mut action = None;
        for attr in pattrs {
            match &attr.attr {
                Some(attribute::Attr::ExtendedCommunities(ext_comm)) => {
                    for community in &ext_comm.communities {
                        let Some(extended_community::Extcom::TrafficRate(rate)) = &community.extcom
                        else {
                            return Err(PrefixdError::Internal(
                                "GoBGP unsupported or missing extended community".into(),
                            ));
                        };
                        if action.is_some() {
                            return Err(PrefixdError::Internal(
                                "GoBGP ambiguous traffic-rate actions".into(),
                            ));
                        }
                        let bits = f64::from(rate.rate) * 8.0;
                        // u64::MAX rounds up to 2^64 in f64, so the upper bound is exclusive.
                        if rate.asn > u16::MAX as u32
                            || !bits.is_finite()
                            || bits < 0.0
                            || bits >= 18_446_744_073_709_551_616.0
                            || bits.fract() != 0.0
                        {
                            return Err(PrefixdError::Internal("GoBGP traffic rate is not exactly representable in integer bits/sec".into()));
                        }
                        action = Some(if bits == 0.0 {
                            FlowSpecAction::discard()
                        } else {
                            FlowSpecAction::police(bits as u64)
                        });
                    }
                }
                Some(
                    attribute::Attr::Origin(_)
                    | attribute::Attr::AsPath(_)
                    | attribute::Attr::NextHop(_)
                    | attribute::Attr::MultiExitDisc(_)
                    | attribute::Attr::LocalPref(_)
                    | attribute::Attr::AtomicAggregate(_)
                    | attribute::Attr::Aggregator(_)
                    | attribute::Attr::Communities(_)
                    | attribute::Attr::OriginatorId(_)
                    | attribute::Attr::ClusterList(_)
                    | attribute::Attr::MpReach(_)
                    | attribute::Attr::As4Path(_)
                    | attribute::Attr::As4Aggregator(_)
                    | attribute::Attr::Aigp(_)
                    | attribute::Attr::LargeCommunities(_),
                ) => {}
                _ => {
                    return Err(PrefixdError::Internal(
                        "GoBGP unsupported or missing path attribute".into(),
                    ));
                }
            }
        }
        action.ok_or_else(|| PrefixdError::Internal("GoBGP missing traffic-rate action".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_announcer() -> GoBgpAnnouncer {
        GoBgpAnnouncer::new("127.0.0.1:50051".to_string())
    }

    #[tokio::test(start_paused = true)]
    async fn test_with_retry_bounds_pending_rpc_completion() {
        let announcer = make_announcer();
        let mut attempts = 0;
        let start = tokio::time::Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(95),
            announcer.with_retry("AddPath", || {
                attempts += 1;
                std::future::pending::<Result<()>>()
            }),
        )
        .await
        .expect("pending RPC completion must be bounded across retries");

        assert!(matches!(
            result,
            Err(PrefixdError::BgpSessionError { peer, error })
                if peer == "gobgp" && error == "AddPath RPC deadline exceeded"
        ));
        assert_eq!(attempts, 3);
        assert_eq!(start.elapsed(), Duration::from_millis(90_300));
    }

    // ==========================================================================
    // IPv4 Prefix Parsing Tests
    // ==========================================================================

    #[test]
    fn test_parse_prefix_v4_with_cidr() {
        let announcer = make_announcer();

        let (ip, len) = announcer.parse_prefix_v4("192.168.1.1/32").unwrap();
        assert_eq!(ip, 0xC0A80101); // 192.168.1.1
        assert_eq!(len, 32);

        let (ip, len) = announcer.parse_prefix_v4("10.0.0.0/8").unwrap();
        assert_eq!(ip, 0x0A000000); // 10.0.0.0
        assert_eq!(len, 8);

        let (ip, len) = announcer.parse_prefix_v4("203.0.113.0/24").unwrap();
        assert_eq!(ip, 0xCB007100); // 203.0.113.0
        assert_eq!(len, 24);
    }

    #[test]
    fn test_parse_prefix_v4_without_cidr() {
        let announcer = make_announcer();

        // Should default to /32
        let (ip, len) = announcer.parse_prefix_v4("192.168.1.1").unwrap();
        assert_eq!(ip, 0xC0A80101);
        assert_eq!(len, 32);
    }

    #[test]
    fn test_parse_prefix_v4_invalid() {
        let announcer = make_announcer();

        assert!(announcer.parse_prefix_v4("not-an-ip/32").is_err());
        assert!(announcer.parse_prefix_v4("300.0.0.1/32").is_err());
        assert!(announcer.parse_prefix_v4("192.168.1.1/abc").is_err());
    }

    // ==========================================================================
    // IPv6 Prefix Parsing Tests
    // ==========================================================================

    #[test]
    fn test_parse_prefix_v6_with_cidr() {
        let announcer = make_announcer();

        let (ip, len) = announcer.parse_prefix_v6("2001:db8::1/128").unwrap();
        assert_eq!(ip, Ipv6Addr::from_str("2001:db8::1").unwrap());
        assert_eq!(len, 128);

        let (ip, len) = announcer.parse_prefix_v6("2001:db8::/64").unwrap();
        assert_eq!(ip, Ipv6Addr::from_str("2001:db8::").unwrap());
        assert_eq!(len, 64);

        let (ip, len) = announcer.parse_prefix_v6("::1/128").unwrap();
        assert_eq!(ip, Ipv6Addr::LOCALHOST);
        assert_eq!(len, 128);
    }

    #[test]
    fn test_parse_prefix_v6_without_cidr() {
        let announcer = make_announcer();

        // Should default to /128
        let (ip, len) = announcer.parse_prefix_v6("2001:db8::1").unwrap();
        assert_eq!(ip, Ipv6Addr::from_str("2001:db8::1").unwrap());
        assert_eq!(len, 128);
    }

    #[test]
    fn test_parse_prefix_v6_invalid() {
        let announcer = make_announcer();

        assert!(announcer.parse_prefix_v6("not-an-ip/128").is_err());
        assert!(announcer.parse_prefix_v6("2001:db8::1/abc").is_err());
        // Too many segments
        assert!(
            announcer
                .parse_prefix_v6("2001:db8:1:2:3:4:5:6:7/64")
                .is_err()
        );
    }

    // ==========================================================================
    // NLRI Construction Tests
    // ==========================================================================

    #[test]
    fn test_build_flowspec_nlri_v4() {
        let announcer = make_announcer();

        let nlri = FlowSpecNlri {
            dst_prefix: "192.168.1.1/32".to_string(),
            protocol: Some(17), // UDP
            dst_ports: vec![53],
            ..Default::default()
        };

        let result = announcer.build_flowspec_nlri_v4(&nlri);
        assert!(result.is_ok());

        let proto_nlri = result.unwrap();
        // Should have dst prefix component, protocol component, port component
        assert!(!proto_nlri.rules.is_empty());
        assert_eq!(proto_nlri.rules.len(), 3); // dst, proto, port
    }

    #[test]
    fn test_build_flowspec_nlri_v4_multiple_ports() {
        let announcer = make_announcer();

        let nlri = FlowSpecNlri {
            dst_prefix: "10.0.0.1/32".to_string(),
            protocol: Some(6), // TCP
            dst_ports: vec![80, 443, 8080, 8443],
            ..Default::default()
        };

        let result = announcer.build_flowspec_nlri_v4(&nlri);
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_flowspec_nlri_v4_no_ports() {
        let announcer = make_announcer();

        let nlri = FlowSpecNlri {
            dst_prefix: "192.168.1.1/32".to_string(),
            protocol: Some(1), // ICMP
            dst_ports: vec![],
            ..Default::default()
        };

        let result = announcer.build_flowspec_nlri_v4(&nlri);
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_flowspec_nlri_v6() {
        let announcer = make_announcer();

        let nlri = FlowSpecNlri {
            dst_prefix: "2001:db8::1/128".to_string(),
            protocol: Some(17),
            dst_ports: vec![53],
            ..Default::default()
        };

        let result = announcer.build_flowspec_nlri_v6(&nlri);
        assert!(result.is_ok());

        let proto_nlri = result.unwrap();
        // Should have dst prefix (IpPrefix for v6), protocol component, port component
        assert!(!proto_nlri.rules.is_empty());
        assert_eq!(proto_nlri.rules.len(), 3);
    }

    // ==========================================================================
    // Path Attribute Tests
    // ==========================================================================

    #[test]
    fn test_build_path_attributes_discard() {
        let announcer = make_announcer();

        let actions = vec![FlowSpecAction {
            action_type: ActionType::Discard,
            rate_bps: None,
        }];

        let result = announcer.build_path_attributes(&actions);
        assert!(result.is_ok());

        let pattrs = result.unwrap();
        // Should have origin + extended communities
        assert!(!pattrs.is_empty());
    }

    #[test]
    fn test_build_path_attributes_police() {
        let announcer = make_announcer();

        let actions = vec![FlowSpecAction {
            action_type: ActionType::Police,
            rate_bps: Some(1_000_000_000), // 1 Gbps
        }];

        let result = announcer.build_path_attributes(&actions);
        assert!(result.is_ok());

        let pattrs = result.unwrap();
        assert!(!pattrs.is_empty());
    }

    #[test]
    fn test_build_path_attributes_empty() {
        let announcer = make_announcer();

        let actions: Vec<FlowSpecAction> = vec![];
        let result = announcer.build_path_attributes(&actions);
        assert!(result.is_err());
    }

    #[test]
    fn action_boundaries_preserve_exact_rates_in_both_families() {
        let announcer = make_announcer();
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
                let path = announcer.build_flowspec_path(&rule).unwrap();
                let parsed = announcer.parse_flowspec_path(&path).unwrap();
                assert_eq!(parsed.actions[0].action_type, action.action_type);
                assert_eq!(parsed.actions[0].rate_bps, action.rate_bps);
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
                assert!(announcer.build_flowspec_path(&rule).is_err());
            }
        }
    }

    // ==========================================================================
    // FlowSpec Path Tests
    // ==========================================================================

    #[test]
    fn test_build_flowspec_path_v4() {
        let announcer = make_announcer();

        let rule = FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: "192.168.1.1/32".to_string(),
                protocol: Some(17),
                dst_ports: vec![53],
                ..Default::default()
            },
            FlowSpecAction {
                action_type: ActionType::Discard,
                rate_bps: None,
            },
        );

        let result = announcer.build_flowspec_path(&rule);
        assert!(result.is_ok());

        let path = result.unwrap();
        assert!(path.nlri.is_some());
        assert!(path.family.is_some());

        let family = path.family.unwrap();
        assert_eq!(family.afi, AFI_IP);
        assert_eq!(family.safi, SAFI_FLOWSPEC);
    }

    #[test]
    fn test_build_flowspec_path_v6() {
        let announcer = make_announcer();

        let rule = FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: "2001:db8::1/128".to_string(),
                protocol: Some(17),
                dst_ports: vec![53],
                ..Default::default()
            },
            FlowSpecAction {
                action_type: ActionType::Police,
                rate_bps: Some(500_000_000),
            },
        );

        let result = announcer.build_flowspec_path(&rule);
        assert!(result.is_ok());

        let path = result.unwrap();
        let family = path.family.unwrap();
        assert_eq!(family.afi, AFI_IP6);
        assert_eq!(family.safi, SAFI_FLOWSPEC);
    }

    // ==========================================================================
    // AFI/SAFI Constants Tests
    // ==========================================================================

    #[test]
    fn test_afi_safi_constants() {
        // RFC 4760 values
        assert_eq!(AFI_IP, 1);
        assert_eq!(AFI_IP6, 2);
        // RFC 5575 FlowSpec SAFI
        assert_eq!(SAFI_FLOWSPEC, 133);
    }

    // ==========================================================================
    // FlowSpec Path Parsing Tests (roundtrip)
    // ==========================================================================

    #[test]
    fn test_parse_flowspec_path_roundtrip_ipv4_discard() {
        let announcer = make_announcer();

        // Build a path
        let original_rule = FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: "192.168.1.100/32".to_string(),
                protocol: Some(17), // UDP
                dst_ports: vec![53, 5353],
                ..Default::default()
            },
            FlowSpecAction {
                action_type: ActionType::Discard,
                rate_bps: None,
            },
        );

        let path = announcer.build_flowspec_path(&original_rule).unwrap();

        // Parse it back
        let parsed_rule = announcer.parse_flowspec_path(&path).unwrap();

        // Verify NLRI matches
        assert_eq!(parsed_rule.nlri.dst_prefix, original_rule.nlri.dst_prefix);
        assert_eq!(parsed_rule.nlri.protocol, original_rule.nlri.protocol);
        assert_eq!(parsed_rule.nlri.dst_ports, original_rule.nlri.dst_ports);

        // Verify action matches
        assert_eq!(parsed_rule.actions.len(), 1);
        assert_eq!(parsed_rule.actions[0].action_type, ActionType::Discard);
        assert_eq!(parsed_rule.actions[0].rate_bps, None);

        // Verify NLRI hash matches (critical for reconciliation)
        assert_eq!(parsed_rule.nlri_hash(), original_rule.nlri_hash());
    }

    #[test]
    fn test_parse_flowspec_path_roundtrip_ipv4_police() {
        let announcer = make_announcer();

        let original_rule = FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: "10.0.0.50/32".to_string(),
                protocol: Some(6), // TCP
                dst_ports: vec![80, 443, 8080],
                ..Default::default()
            },
            FlowSpecAction {
                action_type: ActionType::Police,
                rate_bps: Some(100_000_000), // 100 Mbps
            },
        );

        let path = announcer.build_flowspec_path(&original_rule).unwrap();
        let parsed_rule = announcer.parse_flowspec_path(&path).unwrap();

        assert_eq!(parsed_rule.nlri.dst_prefix, original_rule.nlri.dst_prefix);
        assert_eq!(parsed_rule.nlri.protocol, original_rule.nlri.protocol);
        assert_eq!(parsed_rule.nlri.dst_ports, original_rule.nlri.dst_ports);
        assert_eq!(parsed_rule.actions.len(), 1);
        assert_eq!(parsed_rule.actions[0].action_type, ActionType::Police);
        // Rate may have small rounding due to float conversion
        assert!(parsed_rule.actions[0].rate_bps.is_some());
        assert_eq!(parsed_rule.nlri_hash(), original_rule.nlri_hash());
    }

    #[test]
    fn test_parse_flowspec_path_roundtrip_ipv6() {
        let announcer = make_announcer();

        let original_rule = FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: "2001:db8::1/128".to_string(),
                protocol: Some(17),
                dst_ports: vec![53],
                ..Default::default()
            },
            FlowSpecAction {
                action_type: ActionType::Police,
                rate_bps: Some(500_000_000),
            },
        );

        let path = announcer.build_flowspec_path(&original_rule).unwrap();
        let parsed_rule = announcer.parse_flowspec_path(&path).unwrap();

        assert_eq!(parsed_rule.nlri.dst_prefix, original_rule.nlri.dst_prefix);
        assert_eq!(parsed_rule.nlri.protocol, original_rule.nlri.protocol);
        assert_eq!(parsed_rule.nlri.dst_ports, original_rule.nlri.dst_ports);
        assert_eq!(parsed_rule.nlri_hash(), original_rule.nlri_hash());
    }

    #[test]
    fn test_parse_flowspec_path_no_protocol_no_ports() {
        let announcer = make_announcer();

        // Minimal rule: just destination prefix
        let original_rule = FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: "203.0.113.50/32".to_string(),
                protocol: None,
                dst_ports: vec![],
                ..Default::default()
            },
            FlowSpecAction {
                action_type: ActionType::Discard,
                rate_bps: None,
            },
        );

        let path = announcer.build_flowspec_path(&original_rule).unwrap();
        let parsed_rule = announcer.parse_flowspec_path(&path).unwrap();

        assert_eq!(parsed_rule.nlri.dst_prefix, original_rule.nlri.dst_prefix);
        assert_eq!(parsed_rule.nlri.protocol, None);
        assert_eq!(parsed_rule.nlri.dst_ports, Vec::<u16>::new());
        assert_eq!(parsed_rule.nlri_hash(), original_rule.nlri_hash());
    }

    #[test]
    fn test_parse_flowspec_path_invalid_nlri_type() {
        use crate::bgp::apipb::IpAddressPrefix;

        let announcer = make_announcer();

        // Create a path with wrong NLRI type (IPAddressPrefix instead of FlowSpec)
        let path = Path {
            nlri: Some(Nlri {
                nlri: Some(nlri::Nlri::Prefix(IpAddressPrefix {
                    prefix_len: 32,
                    prefix: "192.168.1.1".to_string(),
                })),
            }),
            ..Default::default()
        };

        let result = announcer.parse_flowspec_path(&path);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unexpected NLRI type")
        );
    }

    #[test]
    fn test_parse_flowspec_path_missing_nlri() {
        let announcer = make_announcer();

        let path = Path {
            nlri: None,
            ..Default::default()
        };

        let result = announcer.parse_flowspec_path(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no NLRI"));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn make_announcer() -> GoBgpAnnouncer {
        GoBgpAnnouncer::new("127.0.0.1:50051".to_string())
    }

    // Strategy: valid IPv4 prefix string
    fn valid_ipv4_prefix() -> impl Strategy<Value = String> {
        (0u8..=255, 0u8..=255, 0u8..=255, 0u8..=255, 0u8..=32)
            .prop_map(|(a, b, c, d, len)| format!("{}.{}.{}.{}/{}", a, b, c, d, len))
    }

    // Strategy: valid IPv6 prefix string
    fn valid_ipv6_prefix() -> impl Strategy<Value = String> {
        (proptest::collection::vec(any::<u16>(), 8), 0u8..=128).prop_map(|(segs, len)| {
            let addr = format!(
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6], segs[7]
            );
            format!("{}/{}", addr, len)
        })
    }

    // Strategy: valid FlowSpecNlri with IPv4
    fn valid_flowspec_nlri_v4() -> impl Strategy<Value = FlowSpecNlri> {
        (
            valid_ipv4_prefix(),
            proptest::option::of(any::<u8>()),
            proptest::collection::vec(1u16..=65535, 0..=8),
        )
            .prop_map(|(dst_prefix, protocol, dst_ports)| FlowSpecNlri {
                dst_prefix,
                protocol,
                dst_ports,
                ..Default::default()
            })
    }

    // Strategy: valid FlowSpecNlri with IPv6
    fn valid_flowspec_nlri_v6() -> impl Strategy<Value = FlowSpecNlri> {
        (
            valid_ipv6_prefix(),
            proptest::option::of(any::<u8>()),
            proptest::collection::vec(1u16..=65535, 0..=8),
        )
            .prop_map(|(dst_prefix, protocol, dst_ports)| FlowSpecNlri {
                dst_prefix,
                protocol,
                dst_ports,
                ..Default::default()
            })
    }

    // Strategy: FlowSpecAction
    fn flowspec_action() -> impl Strategy<Value = FlowSpecAction> {
        prop_oneof![
            Just(FlowSpecAction {
                action_type: ActionType::Discard,
                rate_bps: None,
            }),
            (1u64..=0xff_ffff, 0u32..=40).prop_map(|(significand, shift)| FlowSpecAction {
                action_type: ActionType::Police,
                rate_bps: Some(significand << shift),
            }),
        ]
    }

    // ---- Prefix parsing: arbitrary strings must not panic ----

    proptest! {
        #[test]
        fn parse_prefix_v4_never_panics(s in "\\PC{0,100}") {
            let announcer = make_announcer();
            let _ = announcer.parse_prefix_v4(&s);
        }

        #[test]
        fn parse_prefix_v6_never_panics(s in "\\PC{0,200}") {
            let announcer = make_announcer();
            let _ = announcer.parse_prefix_v6(&s);
        }

        // ---- Valid prefixes roundtrip ----

        #[test]
        fn valid_ipv4_prefix_parses(prefix in valid_ipv4_prefix()) {
            let announcer = make_announcer();
            let result = announcer.parse_prefix_v4(&prefix);
            prop_assert!(result.is_ok(), "valid IPv4 prefix should parse: {}", prefix);
        }

        #[test]
        fn valid_ipv6_prefix_parses(prefix in valid_ipv6_prefix()) {
            let announcer = make_announcer();
            let result = announcer.parse_prefix_v6(&prefix);
            prop_assert!(result.is_ok(), "valid IPv6 prefix should parse: {}", prefix);
        }

        // ---- NLRI construction + decode roundtrip ----

        #[test]
        fn nlri_v4_roundtrip(nlri in valid_flowspec_nlri_v4()) {
            let announcer = make_announcer();
            let proto = announcer.build_flowspec_nlri_v4(&nlri).unwrap();

            let wrapper = Nlri {
                nlri: Some(nlri::Nlri::FlowSpec(proto)),
            };
            let parsed = announcer.decode_flowspec_nlri(&wrapper).unwrap();

            prop_assert_eq!(&parsed.dst_prefix, &nlri.dst_prefix);
            prop_assert_eq!(parsed.protocol, nlri.protocol);
            prop_assert_eq!(&parsed.dst_ports, &nlri.dst_ports);
        }

        #[test]
        fn nlri_v6_roundtrip(nlri in valid_flowspec_nlri_v6()) {
            let announcer = make_announcer();
            let proto = announcer.build_flowspec_nlri_v6(&nlri).unwrap();

            let wrapper = Nlri {
                nlri: Some(nlri::Nlri::FlowSpec(proto)),
            };
            let parsed = announcer.decode_flowspec_nlri(&wrapper).unwrap();

            prop_assert_eq!(&parsed.dst_prefix, &nlri.dst_prefix);
            prop_assert_eq!(parsed.protocol, nlri.protocol);
            prop_assert_eq!(&parsed.dst_ports, &nlri.dst_ports);
        }

        // ---- Full path roundtrip preserves nlri_hash ----

        #[test]
        fn flowspec_path_v4_roundtrip_preserves_hash(
            nlri in valid_flowspec_nlri_v4(),
            action in flowspec_action(),
        ) {
            let announcer = make_announcer();
            let rule = FlowSpecRule::new(nlri, action);
            let path = announcer.build_flowspec_path(&rule).unwrap();
            let parsed = announcer.parse_flowspec_path(&path).unwrap();

            prop_assert_eq!(parsed.nlri_hash(), rule.nlri_hash());
            prop_assert_eq!(&parsed.nlri.dst_prefix, &rule.nlri.dst_prefix);
            prop_assert_eq!(parsed.nlri.protocol, rule.nlri.protocol);
            prop_assert_eq!(&parsed.nlri.dst_ports, &rule.nlri.dst_ports);
        }

        // ---- Action roundtrip ----

        #[test]
        fn action_roundtrip_preserves_exact_rate(action in flowspec_action()) {
            let announcer = make_announcer();
            let pattrs = announcer.build_path_attributes(std::slice::from_ref(&action)).unwrap();
            let parsed = announcer.parse_flowspec_action(&pattrs).unwrap();

            prop_assert_eq!(parsed.action_type, action.action_type);
            prop_assert_eq!(parsed.rate_bps, action.rate_bps);
        }

        #[test]
        fn arbitrary_police_rates_roundtrip_exactly_or_are_rejected(bps in any::<u64>()) {
            let announcer = make_announcer();
            let attributes = announcer.build_path_attributes(&[FlowSpecAction::police(bps)]);
            // An IEEE f32 has 24 significant binary digits; scaling by eight is exact.
            let representable = bps != 0 && u64::BITS - bps.leading_zeros() - bps.trailing_zeros() <= 24;
            prop_assert_eq!(attributes.is_ok(), representable);
            if let Ok(attributes) = attributes {
                let action = announcer.parse_flowspec_action(&attributes).unwrap();
                prop_assert_eq!(action.action_type, ActionType::Police);
                prop_assert_eq!(action.rate_bps, Some(bps));
            }
        }
    }
}

#[cfg(test)]
#[path = "gobgp_tests.rs"]
mod readback_tests;
