use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "TEXT", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum AttackVector {
    UdpFlood,
    SynFlood,
    AckFlood,
    IcmpFlood,
    Unknown,
}

impl AttackVector {
    pub fn to_protocol(&self) -> Option<u8> {
        match self {
            Self::UdpFlood => Some(17),
            Self::SynFlood | Self::AckFlood => Some(6),
            Self::IcmpFlood => Some(1),
            Self::Unknown => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UdpFlood => "udp_flood",
            Self::SynFlood => "syn_flood",
            Self::AckFlood => "ack_flood",
            Self::IcmpFlood => "icmp_flood",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for AttackVector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for AttackVector {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "udp_flood" => Ok(Self::UdpFlood),
            "syn_flood" => Ok(Self::SynFlood),
            "ack_flood" => Ok(Self::AckFlood),
            "icmp_flood" => Ok(Self::IcmpFlood),
            "unknown" => Ok(Self::Unknown),
            _ => Err(format!("unknown vector: {}", s)),
        }
    }
}

/// API input for attack events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackEventInput {
    #[serde(default)]
    pub event_id: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub victim_ip: String,
    pub vector: AttackVector,
    #[serde(default)]
    pub bps: Option<i64>,
    #[serde(default)]
    pub pps: Option<i64>,
    #[serde(default)]
    pub top_dst_ports: Option<Vec<u16>>,
    #[serde(default)]
    pub confidence: Option<f64>,
}

/// Internal event representation
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AttackEvent {
    pub event_id: Uuid,
    pub external_event_id: Option<String>,
    pub source: String,
    pub event_timestamp: DateTime<Utc>,
    pub ingested_at: DateTime<Utc>,
    pub victim_ip: String,
    pub vector: String,
    pub protocol: Option<i32>,
    pub bps: Option<i64>,
    pub pps: Option<i64>,
    pub top_dst_ports_json: String,
    pub confidence: Option<f64>,
}

impl AttackEvent {
    pub fn from_input(input: AttackEventInput) -> Self {
        let protocol = input.vector.to_protocol().map(|p| p as i32);
        let ports = input.top_dst_ports.clone().unwrap_or_default();

        Self {
            event_id: Uuid::new_v4(),
            external_event_id: input.event_id,
            source: input.source,
            event_timestamp: input.timestamp,
            ingested_at: Utc::now(),
            victim_ip: input.victim_ip,
            vector: input.vector.to_string(),
            protocol,
            bps: input.bps,
            pps: input.pps,
            top_dst_ports_json: serde_json::to_string(&ports).unwrap_or_default(),
            confidence: input.confidence,
        }
    }

    pub fn top_dst_ports(&self) -> Vec<u16> {
        serde_json::from_str(&self.top_dst_ports_json).unwrap_or_default()
    }

    pub fn attack_vector(&self) -> AttackVector {
        self.vector.parse().unwrap_or(AttackVector::Unknown)
    }
}
