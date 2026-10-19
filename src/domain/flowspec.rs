use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{ActionType, MatchCriteria};

/// IP version for FlowSpec rules
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowSpecNlri {
    pub dst_prefix: String,
    pub protocol: Option<u8>,
    pub dst_ports: Vec<u16>,
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

    pub fn compute_hash(&self) -> String {
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
    fn equivalent_ipv6_prefix_spellings_have_the_same_rule_identity() {
        let mut nlri = FlowSpecNlri {
            dst_prefix: "2001:0DB8:0:0:0:0:0:1/128".into(),
            protocol: Some(6),
            dst_ports: vec![443, 80],
        };
        let hash = nlri.compute_hash();
        nlri.dst_prefix = "2001:db8::1/128".into();
        assert_eq!(nlri.compute_hash(), hash);
        nlri.dst_prefix = "2001:db8::2/128".into();
        assert_ne!(nlri.compute_hash(), hash);
    }
}
