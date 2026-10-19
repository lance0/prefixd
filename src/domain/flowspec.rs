use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{ActionType, FragmentMatch, MatchCriteria, PacketLengthRange};

/// IP version for FlowSpec rules
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

/// Unknown keys fail closed: ignoring a match key would widen the rule (ADR 028).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowSpecNlri {
    pub dst_prefix: String,
    pub protocol: Option<u8>,
    pub dst_ports: Vec<u16>,
    /// UDP source ports (RFC 8955 type 6). Empty means absent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
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
    #[error("destination must be one IPv4 /32 or IPv6 /128 host")]
    NotHostPrefix,
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
        if !self.is_extended() {
            return Ok(());
        }
        let prefix: ipnet::IpNet = self
            .dst_prefix
            .parse()
            .map_err(|_| FlowSpecMatchError::NotHostPrefix)?;
        if prefix.prefix_len() != prefix.max_prefix_len() {
            return Err(FlowSpecMatchError::NotHostPrefix);
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

    /// ADR 028 identity, shared by the scope hash, NLRI hash and ownership key of a rule
    /// with any new component. `None` keeps the legacy hashes byte for byte. The tag
    /// keeps this input apart from legacy input, which starts with the prefix.
    pub(crate) fn extended_identity(&self) -> Option<String> {
        if !self.is_extended() {
            return None;
        }
        let mut hasher = Sha256::new();
        hasher.update(b"prefixd:flowspec-match:v2\0");
        match self.dst_prefix.parse::<ipnet::IpNet>() {
            Ok(prefix) => hasher.update(prefix.to_string().as_bytes()),
            Err(_) => hasher.update(self.dst_prefix.as_bytes()),
        }
        hasher.update(b"\0");
        if let Some(protocol) = self.protocol {
            hasher.update([3, protocol]);
        }
        // Port fields are [type, count as u32, ports as u16], all big-endian.
        for (component, ports) in [(5u8, &self.dst_ports), (6, &self.src_ports)] {
            let mut ports = ports.clone();
            ports.sort_unstable();
            ports.dedup();
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
            protocol: criteria.protocol,
            dst_ports: criteria.dst_ports.clone(),
            src_ports: criteria.src_ports.clone(),
            fragment: criteria.fragment,
            packet_length: criteria.packet_length,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowSpecRule {
    pub nlri: FlowSpecNlri,
    pub actions: Vec<FlowSpecAction>,
}

impl FlowSpecRule {
    pub fn new(nlri: FlowSpecNlri, action: FlowSpecAction) -> Self {
        Self {
            nlri,
            actions: vec![action],
        }
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
        for prefix in ["192.0.2.0/24", "2001:db8::/64", "invalid"] {
            cases.push((
                FlowSpecNlri {
                    src_ports: vec![123],
                    ..udp(prefix)
                },
                Err(FlowSpecMatchError::NotHostPrefix),
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
}
