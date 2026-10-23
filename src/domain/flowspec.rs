use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{ActionType, FragmentMatch, MatchCriteria, PacketLengthRange, canonical_ports};

/// IP version for FlowSpec rules
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

/// Unknown keys fail closed: ignoring a match key would widen the rule (ADR 028).
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct FlowSpecNlri {
    pub dst_prefix: String,
    /// Conventional source CIDR (RFC 8955/8956 type 2), with IPv6 offset 0.
    #[serde(
        default,
        with = "super::mitigation::canonical_source_prefix",
        skip_serializing_if = "Option::is_none"
    )]
    pub src_prefix: Option<String>,
    pub protocol: Option<u8>,
    pub dst_ports: Vec<u16>,
    /// UDP source ports (RFC 8955 type 6), an equality set stored sorted and
    /// deduplicated. Empty means absent.
    #[serde(
        default,
        with = "super::mitigation::canonical_src_ports",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub src_ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fragment: Option<FragmentMatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_length: Option<PacketLengthRange>,
}

/// A rule that violates the ADR 028 match invariants.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FlowSpecMatchError {
    #[error("source port, fragment and packet length matches require protocol 17 (UDP)")]
    RequiresUdp,
    #[error(
        "source ports and fragment cannot share a rule: ports never match a non-first fragment"
    )]
    SourcePortsWithFragment,
    #[error("packet length requires source ports")]
    PacketLengthWithoutSourcePorts,
    #[error("packet length {min}-{max} is invalid: min must exceed {floor} and not exceed max")]
    InvalidPacketLength { min: u16, max: u16, floor: u16 },
    #[error("destination must be a canonical IPv4 or IPv6 network CIDR")]
    InvalidDestinationPrefix,
    #[error("source prefix must be an IPv4 or IPv6 CIDR")]
    InvalidSourcePrefix,
    #[error("source and destination prefixes must use the same address family")]
    SourcePrefixFamilyMismatch,
}

/// Canonical network CIDR. Explicit /0 remains a component and an identity of its own.
pub fn canonical_source_prefix(prefix: &str) -> Result<String, FlowSpecMatchError> {
    prefix
        .parse::<ipnet::IpNet>()
        .map(|prefix| prefix.trunc().to_string())
        .map_err(|_| FlowSpecMatchError::InvalidSourcePrefix)
}

impl FlowSpecNlri {
    /// Detect IP version from the destination prefix
    pub fn ip_version(&self) -> IpVersion {
        if self.dst_prefix.contains(':') {
            IpVersion::V6
        } else {
            IpVersion::V4
        }
    }

    /// Whether any ADR 028 component (source ports, fragment, packet length) is present.
    pub fn is_extended(&self) -> bool {
        !self.src_ports.is_empty() || self.fragment.is_some() || self.packet_length.is_some()
    }

    /// The ADR 028 rule invariants. Rules without new components are not checked here.
    pub fn validate(&self) -> Result<(), FlowSpecMatchError> {
        if !self.is_extended() && self.src_prefix.is_none() {
            return Ok(());
        }
        let prefix: ipnet::IpNet = self
            .dst_prefix
            .parse()
            .map_err(|_| FlowSpecMatchError::InvalidDestinationPrefix)?;
        if prefix.addr() != prefix.network() {
            return Err(FlowSpecMatchError::InvalidDestinationPrefix);
        }
        if let Some(source) = &self.src_prefix {
            let source: ipnet::IpNet = source
                .parse()
                .map_err(|_| FlowSpecMatchError::InvalidSourcePrefix)?;
            if source.addr().is_ipv4() != prefix.addr().is_ipv4() {
                return Err(FlowSpecMatchError::SourcePrefixFamilyMismatch);
            }
        }
        // Source-prefix matching also applies to TCP, ICMP and any-protocol rules.
        if !self.is_extended() {
            return Ok(());
        }
        if self.protocol != Some(17) {
            return Err(FlowSpecMatchError::RequiresUdp);
        }
        if !self.src_ports.is_empty() && self.fragment.is_some() {
            return Err(FlowSpecMatchError::SourcePortsWithFragment);
        }
        if let Some(PacketLengthRange { min, max }) = self.packet_length {
            if self.src_ports.is_empty() {
                return Err(FlowSpecMatchError::PacketLengthWithoutSourcePorts);
            }
            // Smallest IP plus UDP header: a lower bound at or below it matches all UDP.
            let floor = if prefix.addr().is_ipv4() { 28 } else { 48 };
            if min <= floor || min > max {
                return Err(FlowSpecMatchError::InvalidPacketLength { min, max, floor });
            }
        }
        Ok(())
    }

    /// Shared scope, NLRI and ownership identity. Source-prefix rules use v3;
    /// ADR 028 rules without source keep v2 byte for byte. `None` preserves the
    /// original legacy hashes. Tags separate both namespaces from legacy input.
    pub(crate) fn extended_identity(&self) -> Option<String> {
        if !self.is_extended() && self.src_prefix.is_none() {
            return None;
        }
        let mut hasher = Sha256::new();
        hasher.update(if self.src_prefix.is_some() {
            b"prefixd:flowspec-match:v3\0"
        } else {
            b"prefixd:flowspec-match:v2\0"
        });
        match self.dst_prefix.parse::<ipnet::IpNet>() {
            Ok(prefix) => hasher.update(prefix.to_string().as_bytes()),
            Err(_) => hasher.update(self.dst_prefix.as_bytes()),
        }
        hasher.update(b"\0");
        if let Some(source) = &self.src_prefix {
            let source = canonical_source_prefix(source).unwrap_or_else(|_| source.clone());
            hasher.update([2]);
            hasher.update((source.len() as u32).to_be_bytes());
            hasher.update(source.as_bytes());
        }
        if let Some(protocol) = self.protocol {
            hasher.update([3, protocol]);
        }
        // Port fields are [type, count as u32, ports as u16], all big-endian.
        for (component, ports) in [(5u8, &self.dst_ports), (6, &self.src_ports)] {
            let ports = canonical_ports(ports);
            if !ports.is_empty() {
                hasher.update([component]);
                hasher.update((ports.len() as u32).to_be_bytes());
                for port in ports {
                    hasher.update(port.to_be_bytes());
                }
            }
        }
        if let Some(PacketLengthRange { min, max }) = self.packet_length {
            hasher.update([10]);
            hasher.update(min.to_be_bytes());
            hasher.update(max.to_be_bytes());
        }
        if let Some(fragment) = self.fragment {
            hasher.update([12, fragment.bitmask()]);
        }
        Some(hex::encode(&hasher.finalize()[..16]))
    }

    pub fn compute_hash(&self) -> String {
        if let Some(hash) = self.extended_identity() {
            return hash;
        }
        let mut hasher = Sha256::new();
        match self.dst_prefix.parse::<ipnet::IpNet>() {
            Ok(prefix) => hasher.update(prefix.to_string().as_bytes()),
            Err(_) => hasher.update(self.dst_prefix.as_bytes()),
        }
        if let Some(proto) = self.protocol {
            hasher.update([proto]);
        }
        let mut sorted_ports = self.dst_ports.clone();
        sorted_ports.sort();
        for port in &sorted_ports {
            hasher.update(port.to_be_bytes());
        }
        hex::encode(&hasher.finalize()[..16])
    }
}

impl From<&MatchCriteria> for FlowSpecNlri {
    fn from(criteria: &MatchCriteria) -> Self {
        Self {
            dst_prefix: criteria.dst_prefix.clone(),
            src_prefix: criteria
                .src_prefix
                .as_ref()
                .map(|source| canonical_source_prefix(source).unwrap_or_else(|_| source.clone())),
            protocol: criteria.protocol,
            dst_ports: criteria.dst_ports.clone(),
            src_ports: canonical_ports(&criteria.src_ports),
            fragment: criteria.fragment,
            packet_length: criteria.packet_length,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct FlowSpecAction {
    pub action_type: ActionType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_bps: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FlowSpecActionError {
    #[error("action 'police' requires rate_bps")]
    MissingPoliceRate,
    #[error("action 'police' requires rate_bps > 0")]
    ZeroPoliceRate,
    #[error(
        "police rate_bps {0} cannot be represented exactly as an f32 bytes/second traffic rate"
    )]
    InexactPoliceRate(u64),
    #[error("action 'discard' must not include rate_bps")]
    UnexpectedDiscardRate,
    #[error("action 'blackhole' is not a FlowSpec action")]
    NotFlowSpec,
}

impl FlowSpecAction {
    /// Encode the supported traffic-rate action without changing its bit rate.
    pub fn traffic_rate_bytes_per_second(&self) -> Result<f32, FlowSpecActionError> {
        match (self.action_type, self.rate_bps) {
            (ActionType::Discard, None) => Ok(0.0),
            (ActionType::Discard, Some(_)) => Err(FlowSpecActionError::UnexpectedDiscardRate),
            (ActionType::Police, None) => Err(FlowSpecActionError::MissingPoliceRate),
            (ActionType::Police, Some(0)) => Err(FlowSpecActionError::ZeroPoliceRate),
            (ActionType::Blackhole, _) => Err(FlowSpecActionError::NotFlowSpec),
            (ActionType::Police, Some(bps)) => {
                // Fractional bytes are valid; integer division would turn 1–7 bps into discard.
                let rate = (bps as f64 / 8.0) as f32;
                let decoded_bps = f64::from(rate) * 8.0;
                if decoded_bps >= u64::MAX as f64 || decoded_bps as u64 != bps {
                    return Err(FlowSpecActionError::InexactPoliceRate(bps));
                }
                Ok(rate)
            }
        }
    }

    pub fn police(rate_bps: u64) -> Self {
        Self {
            action_type: ActionType::Police,
            rate_bps: Some(rate_bps),
        }
    }

    pub fn discard() -> Self {
        Self {
            action_type: ActionType::Discard,
            rate_bps: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct FlowSpecRule {
    pub nlri: FlowSpecNlri,
    pub actions: Vec<FlowSpecAction>,
    /// Injection owner the rule was added under (ADR 027); `""` for an unleased
    /// rule. Absent from unleased rule JSON, so persisted rules are unchanged.
    /// Not part of the rule's identity.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub owner: String,
}

impl FlowSpecRule {
    pub fn new(nlri: FlowSpecNlri, action: FlowSpecAction) -> Self {
        Self {
            nlri,
            actions: vec![action],
            owner: String::new(),
        }
    }

    /// The same rule held under an injection owner.
    pub fn with_owner(mut self, owner: impl Into<String>) -> Self {
        self.owner = owner.into();
        self
    }

    pub fn nlri_hash(&self) -> String {
        self.nlri.compute_hash()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnnouncementStatus {
    Pending,
    Announced,
    Withdrawn,
    Failed,
}

impl AnnouncementStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Announced => "announced",
            Self::Withdrawn => "withdrawn",
            Self::Failed => "failed",
        }
    }
}

impl std::fmt::Display for AnnouncementStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unleased rules serialize exactly as before the owner existed; the owner
    /// never changes a rule's identity.
    #[test]
    fn rule_owner_is_absent_from_unleased_json_and_outside_identity() {
        let rule = FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: "192.0.2.1/32".into(),
                protocol: Some(17),
                ..Default::default()
            },
            FlowSpecAction::discard(),
        );
        let json = serde_json::to_string(&rule).unwrap();
        assert!(!json.contains("owner"), "{json}");
        let legacy: FlowSpecRule = serde_json::from_str(&json).unwrap();
        assert!(legacy.owner.is_empty());
        let leased = rule.clone().with_owner("prefixd.pop.0123456789abcdef");
        let json = serde_json::to_string(&leased).unwrap();
        assert!(
            json.ends_with(r#","owner":"prefixd.pop.0123456789abcdef"}"#),
            "{json}"
        );
        let parsed: FlowSpecRule = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.owner, leased.owner);
        assert_eq!(leased.nlri_hash(), rule.nlri_hash());
    }

    #[test]
    fn traffic_rate_preserves_exact_bit_rates_and_rejects_invalid_actions() {
        for bps in [
            1,
            7,
            8,
            9,
            16_777_216,
            16_777_218,
            1_000_000_000,
            1 << 63,
            u64::MAX - ((1 << 40) - 1),
        ] {
            let rate = FlowSpecAction::police(bps)
                .traffic_rate_bytes_per_second()
                .unwrap();
            assert!(rate > 0.0);
            assert_eq!((f64::from(rate) * 8.0) as u64, bps);
        }
        assert_eq!(
            FlowSpecAction::discard().traffic_rate_bytes_per_second(),
            Ok(0.0)
        );
        for (action, error) in [
            (
                FlowSpecAction {
                    action_type: ActionType::Police,
                    rate_bps: None,
                },
                FlowSpecActionError::MissingPoliceRate,
            ),
            (
                FlowSpecAction::police(0),
                FlowSpecActionError::ZeroPoliceRate,
            ),
            (
                FlowSpecAction::police(16_777_217),
                FlowSpecActionError::InexactPoliceRate(16_777_217),
            ),
            (
                FlowSpecAction::police(u64::MAX),
                FlowSpecActionError::InexactPoliceRate(u64::MAX),
            ),
            (
                FlowSpecAction {
                    action_type: ActionType::Discard,
                    rate_bps: Some(0),
                },
                FlowSpecActionError::UnexpectedDiscardRate,
            ),
            (
                FlowSpecAction {
                    action_type: ActionType::Discard,
                    rate_bps: Some(8),
                },
                FlowSpecActionError::UnexpectedDiscardRate,
            ),
            (
                FlowSpecAction {
                    action_type: ActionType::Blackhole,
                    rate_bps: None,
                },
                FlowSpecActionError::NotFlowSpec,
            ),
        ] {
            assert_eq!(action.traffic_rate_bytes_per_second(), Err(error));
        }
    }

    #[test]
    fn match_invariants_are_typed_errors_with_passing_controls() {
        let udp = |prefix: &str| FlowSpecNlri {
            dst_prefix: prefix.into(),
            protocol: Some(17),
            ..Default::default()
        };
        let range = |min, max| Some(PacketLengthRange { min, max });
        let mut cases = vec![];
        for (prefix, floor) in [("192.0.2.1/32", 28), ("2001:db8::1/128", 48)] {
            let ports = FlowSpecNlri {
                src_ports: vec![123],
                ..udp(prefix)
            };
            let fragment = FlowSpecNlri {
                fragment: Some(FragmentMatch::NonFirst),
                ..udp(prefix)
            };
            let length = |min, max| FlowSpecNlri {
                packet_length: range(min, max),
                ..ports.clone()
            };
            // Controls: each component alone, length with ports, and boundary ranges.
            cases.extend([
                (ports.clone(), Ok(())),
                (fragment.clone(), Ok(())),
                (length(floor + 1, 65535), Ok(())),
                (length(468, 468), Ok(())),
                (
                    length(floor, 65535),
                    Err(FlowSpecMatchError::InvalidPacketLength {
                        min: floor,
                        max: 65535,
                        floor,
                    }),
                ),
                (
                    length(469, 468),
                    Err(FlowSpecMatchError::InvalidPacketLength {
                        min: 469,
                        max: 468,
                        floor,
                    }),
                ),
                (
                    FlowSpecNlri {
                        src_ports: vec![123],
                        ..fragment.clone()
                    },
                    Err(FlowSpecMatchError::SourcePortsWithFragment),
                ),
                (
                    FlowSpecNlri {
                        packet_length: range(468, 65535),
                        ..fragment.clone()
                    },
                    Err(FlowSpecMatchError::PacketLengthWithoutSourcePorts),
                ),
                (
                    FlowSpecNlri {
                        packet_length: range(468, 65535),
                        ..udp(prefix)
                    },
                    Err(FlowSpecMatchError::PacketLengthWithoutSourcePorts),
                ),
            ]);
            for protocol in [None, Some(6)] {
                for rule in [&ports, &fragment, &length(468, 65535)] {
                    cases.push((
                        FlowSpecNlri {
                            protocol,
                            ..rule.clone()
                        },
                        Err(FlowSpecMatchError::RequiresUdp),
                    ));
                }
            }
        }
        for prefix in ["192.0.2.1/24", "2001:db8::1/64", "invalid"] {
            cases.push((
                FlowSpecNlri {
                    src_ports: vec![123],
                    ..udp(prefix)
                },
                Err(FlowSpecMatchError::InvalidDestinationPrefix),
            ));
        }
        // Rules without new components are outside these invariants, as before.
        cases.push((
            FlowSpecNlri {
                dst_prefix: "192.0.2.0/24".into(),
                protocol: Some(6),
                dst_ports: vec![443],
                ..Default::default()
            },
            Ok(()),
        ));
        for (rule, expected) in cases {
            assert_eq!(rule.validate(), expected, "{rule:?}");
        }
    }

    #[test]
    fn equivalent_ipv6_prefix_spellings_have_the_same_rule_identity() {
        let mut nlri = FlowSpecNlri {
            dst_prefix: "2001:0DB8:0:0:0:0:0:1/128".into(),
            protocol: Some(6),
            dst_ports: vec![443, 80],
            ..Default::default()
        };
        let hash = nlri.compute_hash();
        nlri.dst_prefix = "2001:db8::1/128".into();
        assert_eq!(nlri.compute_hash(), hash);
        nlri.dst_prefix = "2001:db8::2/128".into();
        assert_ne!(nlri.compute_hash(), hash);
    }

    #[test]
    fn source_prefix_is_canonical_and_does_not_require_udp() {
        for (destination, source, canonical) in [
            ("192.0.2.1/32", "198.51.100.129/24", "198.51.100.0/24"),
            (
                "2001:db8::1/128",
                "2001:0DB8:ABCD::1/48",
                "2001:db8:abcd::/48",
            ),
            ("192.0.2.1/32", "198.51.100.1/0", "0.0.0.0/0"),
            ("2001:db8::1/128", "2001:db8::1/0", "::/0"),
        ] {
            for protocol in [None, Some(1), Some(6), Some(17), Some(58)] {
                let nlri = FlowSpecNlri {
                    dst_prefix: destination.into(),
                    src_prefix: Some(source.into()),
                    protocol,
                    ..Default::default()
                };
                nlri.validate().unwrap();
                assert!(!nlri.is_extended());
                let encoded = serde_json::to_value(&nlri).unwrap();
                assert_eq!(encoded["src_prefix"], canonical);
                let restored: FlowSpecNlri = serde_json::from_value(encoded.clone()).unwrap();
                let criteria: MatchCriteria = serde_json::from_value(encoded).unwrap();
                assert_eq!(restored.src_prefix.as_deref(), Some(canonical));
                assert_eq!(restored.compute_hash(), nlri.compute_hash());
                assert_eq!(criteria.compute_scope_hash(), nlri.compute_hash());
                let absent = FlowSpecNlri {
                    src_prefix: None,
                    ..nlri
                };
                assert_ne!(restored.compute_hash(), absent.compute_hash());
            }
        }
    }

    #[test]
    fn invalid_source_matches_fail_closed_and_keep_amplification_invariants() {
        let base = FlowSpecNlri {
            dst_prefix: "192.0.2.1/32".into(),
            src_prefix: Some("198.51.100.0/24".into()),
            protocol: Some(6),
            ..Default::default()
        };
        for source in [
            "",
            "198.51.100.1",
            "198.51.100.0/33",
            "2001:db8::/129",
            "192.0.2.0/8-24",
            "bad",
        ] {
            let nlri = FlowSpecNlri {
                src_prefix: Some(source.into()),
                ..base.clone()
            };
            assert_eq!(
                nlri.validate(),
                Err(FlowSpecMatchError::InvalidSourcePrefix)
            );
            let json = serde_json::json!({"dst_prefix":"192.0.2.1/32", "src_prefix":source, "protocol":6, "dst_ports":[]});
            assert!(serde_json::from_value::<FlowSpecNlri>(json.clone()).is_err());
            assert!(serde_json::from_value::<MatchCriteria>(json).is_err());
        }
        let mixed = FlowSpecNlri {
            src_prefix: Some("2001:db8::/64".into()),
            ..base.clone()
        };
        assert_eq!(
            mixed.validate(),
            Err(FlowSpecMatchError::SourcePrefixFamilyMismatch)
        );
        for destination in ["", "192.0.2.1/24", "invalid"] {
            let nlri = FlowSpecNlri {
                dst_prefix: destination.into(),
                ..base.clone()
            };
            assert_eq!(
                nlri.validate(),
                Err(FlowSpecMatchError::InvalidDestinationPrefix)
            );
        }
        let mut amplification = FlowSpecNlri {
            src_ports: vec![123],
            ..base
        };
        assert_eq!(
            amplification.validate(),
            Err(FlowSpecMatchError::RequiresUdp)
        );
        amplification.protocol = Some(17);
        amplification.validate().unwrap();
        amplification.fragment = Some(FragmentMatch::NonFirst);
        assert_eq!(
            amplification.validate(),
            Err(FlowSpecMatchError::SourcePortsWithFragment)
        );
    }
}
