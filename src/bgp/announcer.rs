use async_trait::async_trait;

use crate::domain::{FlowSpecNlri, FlowSpecRule, canonical_ports};
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
        for nlri in [left, right] {
            if nlri.src_prefix.is_some() {
                nlri.validate().map_err(|error| {
                    crate::error::PrefixdError::BgpAnnouncementFailed(error.to_string())
                })?;
            }
        }
        let prefix = |nlri: &FlowSpecNlri| {
            nlri.dst_prefix.parse::<ipnet::IpNet>().map_err(|_| {
                crate::error::PrefixdError::BgpAnnouncementFailed(
                    "invalid destination prefix".into(),
                )
            })
        };
        let source = |nlri: &FlowSpecNlri| {
            nlri.src_prefix
                .as_deref()
                .map(crate::domain::canonical_source_prefix)
                .transpose()
                .map_err(|error| {
                    crate::error::PrefixdError::BgpAnnouncementFailed(error.to_string())
                })
        };
        Ok(prefix(left)? == prefix(right)?
            && source(left)? == source(right)?
            && left.protocol == right.protocol
            && left.dst_ports == right.dst_ports
            // Source ports are an equality set; speakers read them back ascending.
            && canonical_ports(&left.src_ports) == canonical_ports(&right.src_ports)
            && left.fragment == right.fragment
            && left.packet_length == right.packet_length)
    }

    /// Unleased upsert; a rule with an owner is refused before any RPC.
    async fn announce(&self, rule: &FlowSpecRule) -> Result<()>;
    /// Leased upsert under the rule's owner, returning the owner's live
    /// generation (ADR 027). It never falls back to `announce`. Backends
    /// without the injection lease refuse it.
    async fn announce_leased(
        &self,
        _rule: &FlowSpecRule,
        _lease_seconds: u32,
    ) -> Result<LeaseGeneration> {
        Err(crate::error::PrefixdError::Config(
            "the speaker has no leased FlowSpec injection".into(),
        ))
    }
    /// Idempotent delete; passes the rule's recorded owner where supported.
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

/// A local unicast route's export state toward one Established peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExportDisposition {
    /// In the peer's Adj-RIB-Out. Not proof that the peer received, accepted,
    /// installed or enforces the route: BGP reports none of these.
    Committed,
    /// Not exported to this peer; `reason` says why.
    Withheld,
    /// Export has not settled; `reason` names what is outstanding.
    Pending,
}

impl ExportDisposition {
    pub const ALL: [Self; 3] = [Self::Committed, Self::Withheld, Self::Pending];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Withheld => "withheld",
            Self::Pending => "pending",
        }
    }
}

/// One Established peer's export disposition, as the speaker reports it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
pub struct PeerExport {
    #[schema(example = "192.0.2.10")]
    pub peer_address: String,
    pub disposition: ExportDisposition,
    /// Bounded speaker reason code; empty when committed.
    #[schema(example = "export_policy")]
    pub reason: String,
    /// Stop code of the speaker's export explain ladder; empty when none applies.
    #[schema(example = "policy_denied")]
    pub explain_code: String,
    /// Speaker text; not a stable string.
    pub detail: String,
    /// Outbound Add-Path identifier when committed; 0 on single-best.
    pub advertised_path_id: u32,
}

/// Optional, read-only export observation of local routes and FlowSpec rules. It is
/// separate from every writer and mutates nothing.
#[async_trait]
pub trait ExportObserver: Send + Sync {
    /// Every Established peer's disposition of the blackhole at `prefix`
    /// (`path_id` 0), read to the last page. `None` when the speaker holds no
    /// local route at that key. Configured peers without a session are absent.
    /// A failed or partial read is an error, never an empty list.
    async fn blackhole_exports(&self, prefix: &ipnet::IpNet) -> Result<Option<Vec<PeerExport>>>;

    /// Every Established peer's disposition at the exact AddFlowSpec match key.
    /// Partial reads fail; `None` means the speaker holds no local rule.
    async fn flowspec_exports(
        &self,
        _nlri: &crate::domain::FlowSpecNlri,
    ) -> Result<Option<Vec<PeerExport>>> {
        Err(crate::error::PrefixdError::Internal(
            "FlowSpec export observation is unsupported".into(),
        ))
    }
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
    /// Injection owner (ADR 027); `""` for an unleased route. Part of equality,
    /// so a desired route matches only a row held by its recorded owner.
    owner: String,
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
            owner: String::new(),
        })
    }

    /// The same route held under an injection owner.
    pub fn with_owner(mut self, owner: impl Into<String>) -> Self {
        self.owner = owner.into();
        self
    }

    pub fn owner(&self) -> &str {
        &self.owner
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
    /// Leased rows whose lease has expired, withdrawal pending (remaining 0).
    /// They are lost intent, not retained routes.
    pub expired: Vec<BlackholeRoute>,
}

/// An owner's live lease generation (rustbgpd ADR-0141 §2). Held in memory only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
pub struct LeaseGeneration {
    pub incarnation: u64,
    pub sequence: u64,
}

/// Owner-scoped injection lease RPCs (ADR 027). Availability is not success.
#[async_trait]
pub trait InjectionLeases: Send + Sync {
    /// Process incarnation, when supported. Zero from older daemons is unknown;
    /// liveness alone never proves that an owner's lease remains live.
    async fn incarnation(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    /// `ListInjectionLeases(owner)`: `None` when the daemon does not implement
    /// leases, otherwise the owner's live generation if its lease has time left.
    async fn live_lease(&self, owner: &str) -> Result<Option<Option<LeaseGeneration>>>;
    /// `RenewLease`: `false` when the generation is not live, which never
    /// resurrects a lease. Any other failure is an error.
    async fn renew_lease(
        &self,
        owner: &str,
        generation: LeaseGeneration,
        lease_seconds: u32,
    ) -> Result<bool>;
    /// Whether the last lease probe of the connected daemon succeeded.
    fn lease_confirmed(&self) -> bool;
}

/// What an add did to the speaker's local route at its key (rustbgpd
/// `PathInjectOutcome`). Local RPC acceptance only, never export or enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AddOutcome {
    Created,
    Replaced,
    /// An identical local route was already held; nothing was redistributed.
    Unchanged,
    /// Accepted, but the speaker reported no outcome.
    Unknown,
}

/// Optional unicast blackhole capability (ADR 027). Reading is mandatory: an
/// unreadable speaker cannot prove absence. Success is the backend's local RPC
/// acceptance or retained local intent, never export or router enforcement.
#[async_trait]
pub trait BlackholeSpeaker: Send + Sync {
    /// Unleased upsert keyed on the host prefix; retrying after an ambiguous
    /// response is safe. A route with an owner is refused before any RPC.
    async fn announce_blackhole(&self, route: &BlackholeRoute) -> Result<AddOutcome>;
    /// Leased upsert under the route's owner, returning the owner's live
    /// generation. It never falls back to the unleased add: an unowned route is
    /// refused, and a failed leased add is an error with nothing created.
    async fn announce_leased_blackhole(
        &self,
        route: &BlackholeRoute,
        lease_seconds: u32,
    ) -> Result<(LeaseGeneration, AddOutcome)>;
    /// Idempotent delete passing the owner the route was added under (`""`
    /// unleased), never an override: an absent route is success.
    async fn withdraw_blackhole(&self, prefix: &ipnet::IpNet, owner: &str) -> Result<()>;
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

    fn injection_leases(&self) -> Option<&dyn InjectionLeases> {
        None
    }

    fn export_observer(&self) -> Option<&dyn ExportObserver> {
        None
    }

    fn flowspec_export_observer(&self) -> Option<&dyn ExportObserver> {
        None
    }

    /// ADR 028 components this adapter encodes. Defaults to none, so an adapter
    /// that has not opted in is refused instead of silently dropping a component.
    fn match_support(&self) -> FlowSpecMatchSupport {
        FlowSpecMatchSupport::default()
    }
}

/// ADR 028 match components a speaker can encode: availability, not delivery.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    utoipa::ToSchema,
)]
#[serde(default)]
pub struct FlowSpecMatchSupport {
    pub source_prefix: bool,
    pub source_ports: bool,
    pub fragment: bool,
    pub packet_length: bool,
}

impl FlowSpecMatchSupport {
    pub const ALL: Self = Self {
        source_prefix: true,
        source_ports: true,
        fragment: true,
        packet_length: true,
    };

    /// Refuses, before any RPC, a rule with a component this speaker cannot
    /// encode. Dropping the component instead would widen the rule.
    pub fn require(self, nlri: &FlowSpecNlri) -> Result<()> {
        for (present, supported, component) in [
            (
                nlri.src_prefix.is_some(),
                self.source_prefix,
                "source prefix",
            ),
            (!nlri.src_ports.is_empty(), self.source_ports, "source port"),
            (nlri.fragment.is_some(), self.fragment, "fragment"),
            (
                nlri.packet_length.is_some(),
                self.packet_length,
                "packet length",
            ),
        ] {
            if present && !supported {
                return Err(crate::error::PrefixdError::InvalidRequest(format!(
                    "the selected speaker cannot encode the {component} match"
                )));
            }
        }
        Ok(())
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
    /// Owner-scoped injection lease (ADR 027): the daemon answered
    /// `ListInjectionLeases`, which prefixd asks only when `blackhole.leased` is set.
    #[serde(default)]
    pub blackhole_lease: bool,
    /// Per-peer export dispositions of blackhole routes (rustbgpd
    /// `ListPathExportDispositions`); availability, not export.
    #[serde(default)]
    pub blackhole_export: bool,
    /// Exact-key per-peer FlowSpec export observation; availability, not export.
    #[serde(default)]
    pub flowspec_export: bool,
    /// ADR 028 match components the adapter encodes; all false when absent.
    #[serde(default)]
    pub flowspec_match: FlowSpecMatchSupport,
}

impl dyn FlowSpecAnnouncer + '_ {
    pub fn capabilities(&self) -> SpeakerCapabilities {
        SpeakerCapabilities {
            rule_reader: self.reader().is_some(),
            peer_observer: self.peer_observer().is_some(),
            daemon_health: self.daemon_health_observer().is_some(),
            blackhole: self.blackhole().is_some(),
            blackhole_lease: self
                .injection_leases()
                .is_some_and(|leases| leases.lease_confirmed()),
            blackhole_export: self.export_observer().is_some(),
            flowspec_export: self.flowspec_export_observer().is_some(),
            flowspec_match: self.match_support(),
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
        assert_eq!(older.flowspec_match, FlowSpecMatchSupport::default());
    }

    #[test]
    fn match_support_is_reported_and_refuses_each_unsupported_component() {
        use crate::domain::{FragmentMatch, PacketLengthRange};
        let mock = crate::bgp::MockAnnouncer::new();
        let gobgp = crate::bgp::GoBgpAnnouncer::new("http://127.0.0.1:1".into());
        for speaker in [&mock as &dyn FlowSpecAnnouncer, &gobgp] {
            assert_eq!(
                speaker.capabilities().flowspec_match,
                FlowSpecMatchSupport::ALL
            );
        }
        let json = serde_json::to_value(FlowSpecMatchSupport::ALL).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"source_prefix": true, "source_ports": true, "fragment": true, "packet_length": true})
        );
        let base = FlowSpecNlri {
            dst_prefix: "192.0.2.1/32".into(),
            protocol: Some(17),
            ..Default::default()
        };
        let cases = [
            (
                FlowSpecNlri {
                    src_prefix: Some("198.51.100.0/24".into()),
                    ..base.clone()
                },
                "source prefix",
            ),
            (
                FlowSpecNlri {
                    src_ports: vec![123],
                    ..base.clone()
                },
                "source port",
            ),
            (
                FlowSpecNlri {
                    fragment: Some(FragmentMatch::NonFirst),
                    ..base.clone()
                },
                "fragment",
            ),
            (
                FlowSpecNlri {
                    src_ports: vec![123],
                    packet_length: Some(PacketLengthRange {
                        min: 468,
                        max: 65535,
                    }),
                    ..base.clone()
                },
                "packet length",
            ),
        ];
        // The trait default supports nothing, so only legacy rules pass.
        let none = FlowSpecMatchSupport::default();
        none.require(&base).unwrap();
        let all = FlowSpecMatchSupport::ALL;
        let lacking = [
            FlowSpecMatchSupport {
                source_prefix: false,
                ..all
            },
            FlowSpecMatchSupport {
                source_ports: false,
                ..all
            },
            FlowSpecMatchSupport {
                fragment: false,
                ..all
            },
            FlowSpecMatchSupport {
                packet_length: false,
                ..all
            },
        ];
        for ((nlri, component), support) in cases.iter().zip(lacking) {
            all.require(nlri).unwrap();
            assert!(none.require(nlri).is_err());
            // Each flag gates exactly its own component.
            let error = support.require(nlri).unwrap_err().to_string();
            assert!(error.contains(&format!("{component} match")), "{error}");
        }
        lacking[3].require(&cases[1].0).unwrap();
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
                ..Default::default()
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
