use async_trait::async_trait;

use crate::domain::{FlowSpecNlri, FlowSpecRule};
use crate::error::Result;

#[derive(Debug, Clone)]
pub struct PeerStatus {
    pub name: String,
    pub address: String,
    pub state: SessionState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

impl SessionState {
    pub fn is_established(&self) -> bool {
        matches!(self, Self::Established)
    }
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "idle"),
            Self::Connect => write!(f, "connect"),
            Self::Active => write!(f, "active"),
            Self::OpenSent => write!(f, "opensent"),
            Self::OpenConfirm => write!(f, "openconfirm"),
            Self::Established => write!(f, "established"),
        }
    }
}

/// Required mutation contract: announcement is an upsert and withdrawal is idempotent.
/// Implementations must make retrying the same request safe after an ambiguous response.
/// Success acknowledges the backend's local mutation stage, not router enforcement.
#[async_trait]
pub trait FlowSpecWriter: Send + Sync {
    /// Whether both matches address the same backend-local route for upsert and delete.
    /// Writers that normalize match terms must use the same normalization here.
    fn matches_nlri(&self, left: &FlowSpecNlri, right: &FlowSpecNlri) -> Result<bool> {
        let prefix = |nlri: &FlowSpecNlri| {
            nlri.dst_prefix.parse::<ipnet::IpNet>().map_err(|_| {
                crate::error::PrefixdError::BgpAnnouncementFailed(
                    "invalid destination prefix".into(),
                )
            })
        };
        Ok(prefix(left)? == prefix(right)?
            && left.protocol == right.protocol
            && left.dst_ports == right.dst_ports)
    }

    async fn announce(&self, rule: &FlowSpecRule) -> Result<()>;
    async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()>;
}

/// Complete local-rule observation; errors must never become an empty inventory.
/// GoBGP observes accepted local RIB state after import policy; rustbgpd observes
/// retained local injection intent. Neither view proves export or enforcement.
#[async_trait]
pub trait FlowSpecReader: Send + Sync {
    async fn list_active(&self) -> Result<Vec<FlowSpecRule>>;
}

#[async_trait]
pub trait PeerObserver: Send + Sync {
    async fn session_status(&self) -> Result<Vec<PeerStatus>>;
}

/// Process metadata observed from the speaker, independently of peer sessions.
#[derive(Debug, Clone)]
pub struct DaemonHealth {
    pub version: Option<String>,
    pub uptime_seconds: u64,
    pub ready: bool,
}

#[async_trait]
pub trait DaemonHealthObserver: Send + Sync {
    async fn daemon_health(&self) -> Result<DaemonHealth>;
}

/// RFC 7999 BLACKHOLE, 65535:666. Every blackhole route carries it.
pub const BLACKHOLE_COMMUNITY: u32 = 0xFFFF_029A;

/// Unicast RTBH host route as the speaker holds it (ADR 027): an IPv4 `/32` or
/// IPv6 `/128`, a same-family unicast discard next hop and canonical (sorted,
/// unique) communities that always include BLACKHOLE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlackholeRoute {
    prefix: ipnet::IpNet,
    next_hop: std::net::IpAddr,
    communities: Vec<u32>,
    large_communities: Vec<[u32; 3]>,
}

impl BlackholeRoute {
    /// Adds BLACKHOLE and canonicalizes the communities.
    pub fn new(
        prefix: ipnet::IpNet,
        next_hop: std::net::IpAddr,
        mut communities: Vec<u32>,
        mut large_communities: Vec<[u32; 3]>,
    ) -> Result<Self> {
        let rejected = |message: &str| {
            Err(crate::error::PrefixdError::InvalidRequest(format!(
                "blackhole route: {message}"
            )))
        };
        require_host_route(&prefix)?;
        if prefix.addr().is_ipv4() != next_hop.is_ipv4() {
            return rejected("next hop family must match the prefix");
        }
        let unusable = match next_hop {
            std::net::IpAddr::V4(ip) => {
                ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast()
            }
            std::net::IpAddr::V6(ip) => ip.is_unspecified() || ip.is_multicast(),
        };
        if unusable {
            return rejected("next hop must be a nonzero unicast address");
        }
        communities.push(BLACKHOLE_COMMUNITY);
        communities.sort_unstable();
        communities.dedup();
        large_communities.sort_unstable();
        large_communities.dedup();
        Ok(Self {
            prefix,
            next_hop,
            communities,
            large_communities,
        })
    }

    pub fn prefix(&self) -> ipnet::IpNet {
        self.prefix
    }

    pub fn next_hop(&self) -> std::net::IpAddr {
        self.next_hop
    }

    pub fn communities(&self) -> &[u32] {
        &self.communities
    }

    pub fn large_communities(&self) -> &[[u32; 3]] {
        &self.large_communities
    }
}

/// Blackholes are exactly IPv4 `/32` or IPv6 `/128` (ADR 027).
pub fn require_host_route(prefix: &ipnet::IpNet) -> Result<()> {
    if prefix.prefix_len() != prefix.max_prefix_len() {
        return Err(crate::error::PrefixdError::InvalidRequest(
            "blackhole route: prefix must be an IPv4 /32 or IPv6 /128".into(),
        ));
    }
    Ok(())
}

/// A well-formed local route that is not prefixd-shaped, such as another tool's
/// injection. Callers report it and never touch it; it is not an observation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnrecognizedRoute {
    pub prefix: ipnet::IpNet,
    pub reason: &'static str,
}

/// Complete retained local unicast intent, split into prefixd-shaped blackholes
/// and unrecognized local routes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlackholeInventory {
    pub routes: Vec<BlackholeRoute>,
    pub unrecognized: Vec<UnrecognizedRoute>,
}

/// Optional unicast blackhole capability (ADR 027). Reading is mandatory: an
/// unreadable speaker cannot prove absence. Success is the backend's local RPC
/// acceptance or retained local intent, never export or router enforcement.
#[async_trait]
pub trait BlackholeSpeaker: Send + Sync {
    /// Upsert keyed on the host prefix; retrying after an ambiguous response is safe.
    async fn announce_blackhole(&self, route: &BlackholeRoute) -> Result<()>;
    /// Idempotent: an absent route is success.
    async fn withdraw_blackhole(&self, prefix: &ipnet::IpNet) -> Result<()>;
    /// Complete retained local intent for both families. A failed, partial or
    /// malformed read is an error, never an empty or truncated inventory.
    async fn list_blackholes(&self) -> Result<BlackholeInventory>;
}

/// Selected speaker: writing is required, observation is explicitly optional.
/// A production write-only backend still needs a durable reconciliation ledger.
pub trait FlowSpecAnnouncer: FlowSpecWriter {
    fn backend(&self) -> &'static str;

    fn reader(&self) -> Option<&dyn FlowSpecReader> {
        None
    }

    fn daemon_health_observer(&self) -> Option<&dyn DaemonHealthObserver> {
        None
    }

    fn peer_observer(&self) -> Option<&dyn PeerObserver> {
        None
    }

    fn blackhole(&self) -> Option<&dyn BlackholeSpeaker> {
        None
    }
}

/// Observation availability, not the success of a recent read or rule delivery.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema,
)]
pub struct SpeakerCapabilities {
    pub rule_reader: bool,
    pub peer_observer: bool,
    #[serde(default)]
    pub daemon_health: bool,
    #[serde(default)]
    pub blackhole: bool,
    /// Owner-scoped injection lease (ADR 027). No adapter supports it yet.
    #[serde(default)]
    pub blackhole_lease: bool,
}

impl dyn FlowSpecAnnouncer + '_ {
    pub fn capabilities(&self) -> SpeakerCapabilities {
        SpeakerCapabilities {
            rule_reader: self.reader().is_some(),
            peer_observer: self.peer_observer().is_some(),
            daemon_health: self.daemon_health_observer().is_some(),
            blackhole: self.blackhole().is_some(),
            blackhole_lease: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blackhole_capability_is_reported_only_by_supporting_backends() {
        let mock = crate::bgp::MockAnnouncer::new();
        let gobgp = crate::bgp::GoBgpAnnouncer::new("http://127.0.0.1:1".into());
        let mock: &dyn FlowSpecAnnouncer = &mock;
        let gobgp: &dyn FlowSpecAnnouncer = &gobgp;
        assert!(mock.capabilities().blackhole);
        // GoBGP is unsupported, which is not an empty blackhole inventory.
        assert!(gobgp.blackhole().is_none());
        assert!(!gobgp.capabilities().blackhole);
        for speaker in [mock, gobgp] {
            assert!(!speaker.capabilities().blackhole_lease);
        }
        let older: SpeakerCapabilities =
            serde_json::from_str(r#"{"rule_reader":true,"peer_observer":true}"#).unwrap();
        assert!(!older.blackhole && !older.blackhole_lease && !older.daemon_health);
    }

    #[test]
    fn blackhole_route_is_a_canonical_host_route_with_blackhole() {
        let v4: ipnet::IpNet = "192.0.2.1/32".parse().unwrap();
        let v6: ipnet::IpNet = "2001:db8::1/128".parse().unwrap();
        let route = BlackholeRoute::new(
            v4,
            "192.0.2.66".parse().unwrap(),
            vec![7, BLACKHOLE_COMMUNITY, 7],
            vec![[3, 2, 1], [1, 2, 3], [3, 2, 1]],
        )
        .unwrap();
        assert_eq!(route.communities(), [7, BLACKHOLE_COMMUNITY]);
        assert_eq!(route.large_communities(), [[1, 2, 3], [3, 2, 1]]);
        for (prefix, next_hop) in [
            ("192.0.2.0/24", "192.0.2.66"),
            ("2001:db8::/64", "2001:db8::66"),
            ("192.0.2.1/32", "2001:db8::66"),
            ("2001:db8::1/128", "192.0.2.66"),
            ("192.0.2.1/32", "0.0.0.0"),
            ("192.0.2.1/32", "255.255.255.255"),
            ("192.0.2.1/32", "224.0.0.1"),
            ("2001:db8::1/128", "::"),
            ("2001:db8::1/128", "ff02::1"),
        ] {
            let prefix = prefix.parse().unwrap();
            assert!(
                BlackholeRoute::new(prefix, next_hop.parse().unwrap(), vec![], vec![]).is_err()
            );
        }
        assert!(BlackholeRoute::new(v6, "2001:db8::66".parse().unwrap(), vec![], vec![]).is_ok());
    }

    #[test]
    fn default_match_identity_preserves_port_order_and_duplicate_terms() {
        let writer = crate::bgp::MockAnnouncer::new();
        for prefix in ["192.0.2.1/32", "2001:db8::1/128"] {
            let left = FlowSpecNlri {
                dst_prefix: prefix.into(),
                protocol: Some(17),
                dst_ports: vec![443, 53],
            };
            assert!(writer.matches_nlri(&left, &left).unwrap());
            let mut right = left.clone();
            if prefix.contains(':') {
                right.dst_prefix = "2001:0DB8:0:0:0:0:0:1/128".into();
                assert!(writer.matches_nlri(&left, &right).unwrap());
            }
            right.dst_ports.reverse();
            assert!(!writer.matches_nlri(&left, &right).unwrap());
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
}
