use async_trait::async_trait;
use prost::Message;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::transport::Channel;

use super::apipb::{
    gobgp_api_client::GobgpApiClient, AddPathRequest, DeletePathRequest, Family,
    FlowSpecComponent, FlowSpecComponentItem, FlowSpecNlri as ProtoFlowSpecNlri,
    ListPathRequest, ListPeerRequest, OriginAttribute, Path, TableType, TrafficRateExtended,
    ExtendedCommunitiesAttribute,
};
use super::{FlowSpecAnnouncer, PeerStatus, SessionState};
use crate::domain::{ActionType, FlowSpecAction, FlowSpecNlri, FlowSpecRule};
use crate::error::{PrefixdError, Result};

const AFI_IP: i32 = 1;
const SAFI_FLOWSPEC: i32 = 133;

/// GoBGP gRPC client for FlowSpec announcements
pub struct GoBgpAnnouncer {
    endpoint: String,
    client: Arc<RwLock<Option<GobgpApiClient<Channel>>>>,
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
            .connect()
            .await
            .map_err(|e| PrefixdError::BgpSessionError {
                peer: "gobgp".to_string(),
                error: e.to_string(),
            })?;

        let client = GobgpApiClient::new(channel);
        *self.client.write().await = Some(client);

        tracing::info!("connected to GoBGP");
        Ok(())
    }

    async fn get_client(&self) -> Result<GobgpApiClient<Channel>> {
        self.client
            .read()
            .await
            .clone()
            .ok_or_else(|| PrefixdError::BgpSessionError {
                peer: "gobgp".to_string(),
                error: "not connected".to_string(),
            })
    }

    fn build_flowspec_path(&self, rule: &FlowSpecRule) -> Result<Path> {
        let nlri = self.build_flowspec_nlri(&rule.nlri)?;
        let pattrs = self.build_path_attributes(&rule.actions)?;

        Ok(Path {
            nlri: Some(nlri),
            pattrs,
            family: Some(Family {
                afi: AFI_IP,
                safi: SAFI_FLOWSPEC,
            }),
            ..Default::default()
        })
    }

    fn build_flowspec_nlri(&self, nlri: &FlowSpecNlri) -> Result<prost_types::Any> {
        let (prefix_u32, prefix_len) = self.parse_prefix(&nlri.dst_prefix)?;

        // Build FlowSpec NLRI components per RFC 5575 as Any
        let mut rules: Vec<prost_types::Any> = Vec::new();

        // Type 1: Destination Prefix
        let prefix_bytes = prefix_u32.to_be_bytes();
        let dst_prefix_component = FlowSpecComponent {
            r#type: 1, // FLOWSPEC_TYPE_DST_PREFIX
            items: vec![FlowSpecComponentItem {
                op: prefix_len as u32,
                value: u64::from_be_bytes([
                    0, 0, 0, 0,
                    prefix_bytes[0],
                    prefix_bytes[1],
                    prefix_bytes[2],
                    prefix_bytes[3],
                ]),
            }],
        };
        rules.push(self.encode_any("apipb.FlowSpecComponent", &dst_prefix_component)?);

        // Type 3: IP Protocol (if specified)
        if let Some(proto) = nlri.protocol {
            let proto_component = FlowSpecComponent {
                r#type: 3, // FLOWSPEC_TYPE_IP_PROTO
                items: vec![FlowSpecComponentItem {
                    op: 0x81, // end-of-list + equals
                    value: proto as u64,
                }],
            };
            rules.push(self.encode_any("apipb.FlowSpecComponent", &proto_component)?);
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
            rules.push(self.encode_any("apipb.FlowSpecComponent", &port_component)?);
        }

        let flowspec_nlri = ProtoFlowSpecNlri { rules };

        // Encode as Any
        let mut buf = Vec::new();
        flowspec_nlri.encode(&mut buf).map_err(|e| {
            PrefixdError::BgpAnnouncementFailed(format!("failed to encode NLRI: {}", e))
        })?;

        Ok(prost_types::Any {
            type_url: "type.googleapis.com/apipb.FlowSpecNLRI".to_string(),
            value: buf,
        })
    }

    fn build_path_attributes(&self, actions: &[FlowSpecAction]) -> Result<Vec<prost_types::Any>> {
        let mut pattrs = Vec::new();

        // Origin attribute (IGP)
        let origin = OriginAttribute { origin: 0 };
        pattrs.push(self.encode_any("apipb.OriginAttribute", &origin)?);

        // Extended communities for FlowSpec actions
        let mut communities = Vec::new();

        for action in actions {
            match action.action_type {
                ActionType::Discard => {
                    // Traffic-rate 0 = discard
                    let traffic_rate = TrafficRateExtended {
                        asn: 0,
                        rate: 0.0,
                    };
                    let mut buf = Vec::new();
                    traffic_rate.encode(&mut buf).map_err(|e| {
                        PrefixdError::BgpAnnouncementFailed(format!("encode error: {}", e))
                    })?;
                    communities.push(prost_types::Any {
                        type_url: "type.googleapis.com/apipb.TrafficRateExtended".to_string(),
                        value: buf,
                    });
                }
                ActionType::Police => {
                    if let Some(rate_bps) = action.rate_bps {
                        // Convert bps to bytes/sec for traffic-rate
                        let rate_bytes = (rate_bps / 8) as f32;
                        let traffic_rate = TrafficRateExtended {
                            asn: 0,
                            rate: rate_bytes,
                        };
                        let mut buf = Vec::new();
                        traffic_rate.encode(&mut buf).map_err(|e| {
                            PrefixdError::BgpAnnouncementFailed(format!("encode error: {}", e))
                        })?;
                        communities.push(prost_types::Any {
                            type_url: "type.googleapis.com/apipb.TrafficRateExtended".to_string(),
                            value: buf,
                        });
                    }
                }
            }
        }

        if !communities.is_empty() {
            let ext_comm = ExtendedCommunitiesAttribute { communities };
            pattrs.push(self.encode_any("apipb.ExtendedCommunitiesAttribute", &ext_comm)?);
        }

        Ok(pattrs)
    }

    fn encode_any<M: Message>(&self, type_name: &str, msg: &M) -> Result<prost_types::Any> {
        let mut buf = Vec::new();
        msg.encode(&mut buf)
            .map_err(|e| PrefixdError::BgpAnnouncementFailed(format!("encode error: {}", e)))?;
        Ok(prost_types::Any {
            type_url: format!("type.googleapis.com/{}", type_name),
            value: buf,
        })
    }

    fn parse_prefix(&self, prefix: &str) -> Result<(u32, u8)> {
        let parts: Vec<&str> = prefix.split('/').collect();
        let ip = Ipv4Addr::from_str(parts[0]).map_err(|_| {
            PrefixdError::InvalidPrefix(format!("invalid IP in prefix: {}", prefix))
        })?;
        let len: u8 = parts
            .get(1)
            .unwrap_or(&"32")
            .parse()
            .map_err(|_| PrefixdError::InvalidPrefix(format!("invalid prefix length: {}", prefix)))?;
        Ok((u32::from(ip), len))
    }
}

#[async_trait]
impl FlowSpecAnnouncer for GoBgpAnnouncer {
    async fn announce(&self, rule: &FlowSpecRule) -> Result<()> {
        let mut client = self.get_client().await?;
        let path = self.build_flowspec_path(rule)?;

        tracing::info!(
            nlri_hash = %rule.nlri_hash(),
            dst_prefix = %rule.nlri.dst_prefix,
            "announcing flowspec rule via GoBGP"
        );

        let request = AddPathRequest {
            table_type: TableType::Global as i32,
            path: Some(path),
            vrf_id: String::new(),
        };

        client.add_path(request).await.map_err(|e| {
            PrefixdError::BgpAnnouncementFailed(format!("GoBGP AddPath failed: {}", e))
        })?;

        tracing::info!(
            nlri_hash = %rule.nlri_hash(),
            "flowspec rule announced"
        );

        Ok(())
    }

    async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()> {
        let mut client = self.get_client().await?;
        let path = self.build_flowspec_path(rule)?;

        tracing::info!(
            nlri_hash = %rule.nlri_hash(),
            dst_prefix = %rule.nlri.dst_prefix,
            "withdrawing flowspec rule via GoBGP"
        );

        let request = DeletePathRequest {
            table_type: TableType::Global as i32,
            path: Some(path),
            vrf_id: String::new(),
            family: Some(Family {
                afi: AFI_IP,
                safi: SAFI_FLOWSPEC,
            }),
            uuid: Vec::new(),
        };

        client.delete_path(request).await.map_err(|e| {
            PrefixdError::BgpWithdrawalFailed(format!("GoBGP DeletePath failed: {}", e))
        })?;

        tracing::info!(
            nlri_hash = %rule.nlri_hash(),
            "flowspec rule withdrawn"
        );

        Ok(())
    }

    async fn list_active(&self) -> Result<Vec<FlowSpecRule>> {
        let mut client = self.get_client().await?;

        let request = ListPathRequest {
            table_type: TableType::Global as i32,
            family: Some(Family {
                afi: AFI_IP,
                safi: SAFI_FLOWSPEC,
            }),
            ..Default::default()
        };

        let mut stream = client.list_path(request).await.map_err(|e| {
            PrefixdError::Internal(format!("GoBGP ListPath failed: {}", e))
        })?.into_inner();

        let mut rules = Vec::new();

        while let Some(resp) = stream.message().await.map_err(|e| {
            PrefixdError::Internal(format!("GoBGP stream error: {}", e))
        })? {
            if let Some(dest) = resp.destination {
                for path in dest.paths {
                    if let Ok(rule) = self.parse_flowspec_path(&path) {
                        rules.push(rule);
                    }
                }
            }
        }

        Ok(rules)
    }

    async fn session_status(&self) -> Result<Vec<PeerStatus>> {
        let mut client = self.get_client().await?;

        let request = ListPeerRequest {
            ..Default::default()
        };

        let mut stream = client.list_peer(request).await.map_err(|e| {
            PrefixdError::Internal(format!("GoBGP ListPeer failed: {}", e))
        })?.into_inner();

        let mut peers = Vec::new();

        while let Some(resp) = stream.message().await.map_err(|e| {
            PrefixdError::Internal(format!("GoBGP stream error: {}", e))
        })? {
            if let Some(peer) = resp.peer {
                let state = peer.state.map(|s| match s.session_state {
                    1 => SessionState::Idle,
                    2 => SessionState::Connect,
                    3 => SessionState::Active,
                    4 => SessionState::OpenSent,
                    5 => SessionState::OpenConfirm,
                    6 => SessionState::Established,
                    _ => SessionState::Idle,
                }).unwrap_or(SessionState::Idle);

                let name = peer.conf.as_ref()
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
    }
}

impl GoBgpAnnouncer {
    fn parse_flowspec_path(&self, _path: &Path) -> Result<FlowSpecRule> {
        // Simplified parsing - full implementation would decode NLRI and attributes
        Err(PrefixdError::Internal("FlowSpec path parsing not fully implemented".to_string()))
    }
}
