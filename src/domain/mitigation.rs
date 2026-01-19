use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::FromRow;
use uuid::Uuid;

use super::AttackVector;
use crate::error::{PrefixdError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MitigationStatus {
    Pending,
    Active,
    Escalated,
    Expired,
    Withdrawn,
    Rejected,
}

impl MitigationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Escalated => "escalated",
            Self::Expired => "expired",
            Self::Withdrawn => "withdrawn",
            Self::Rejected => "rejected",
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::Pending | Self::Active | Self::Escalated)
    }
}

impl std::fmt::Display for MitigationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for MitigationStatus {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "active" => Ok(Self::Active),
            "escalated" => Ok(Self::Escalated),
            "expired" => Ok(Self::Expired),
            "withdrawn" => Ok(Self::Withdrawn),
            "rejected" => Ok(Self::Rejected),
            _ => Err(format!("unknown status: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    Police,
    Discard,
}

impl ActionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Police => "police",
            Self::Discard => "discard",
        }
    }
}

impl std::fmt::Display for ActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for ActionType {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "police" => Ok(Self::Police),
            "discard" => Ok(Self::Discard),
            _ => Err(format!("unknown action: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchCriteria {
    pub dst_prefix: String,
    pub protocol: Option<u8>,
    pub dst_ports: Vec<u16>,
}

impl MatchCriteria {
    pub fn compute_scope_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.dst_prefix.as_bytes());
        if let Some(proto) = self.protocol {
            hasher.update([proto]);
        }
        let mut sorted_ports = self.dst_ports.clone();
        sorted_ports.sort();
        sorted_ports.dedup(); // Remove duplicates for consistent hashing
        for port in &sorted_ports {
            hasher.update(port.to_be_bytes());
        }
        hex::encode(&hasher.finalize()[..16])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_bps: Option<u64>,
}

/// Intent produced by policy engine, before guardrails
#[derive(Debug, Clone)]
pub struct MitigationIntent {
    pub event_id: Uuid,
    pub customer_id: Option<String>,
    pub service_id: Option<String>,
    pub pop: String,
    pub match_criteria: MatchCriteria,
    pub action_type: ActionType,
    pub action_params: ActionParams,
    pub ttl_seconds: u32,
    pub reason: String,
}

/// Database row representation
#[derive(Debug, Clone, FromRow)]
pub struct MitigationRow {
    pub mitigation_id: Uuid,
    pub scope_hash: String,
    pub pop: String,
    pub customer_id: Option<String>,
    pub service_id: Option<String>,
    pub victim_ip: String,
    pub vector: String,
    pub match_json: String,
    pub action_type: String,
    pub action_params_json: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub withdrawn_at: Option<DateTime<Utc>>,
    pub triggering_event_id: Uuid,
    pub last_event_id: Uuid,
    pub escalated_from_id: Option<Uuid>,
    pub reason: Option<String>,
    pub rejection_reason: Option<String>,
}

/// Domain model for mitigation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mitigation {
    pub mitigation_id: Uuid,
    pub scope_hash: String,
    pub pop: String,
    pub customer_id: Option<String>,
    pub service_id: Option<String>,
    pub victim_ip: String,
    pub vector: AttackVector,
    pub match_criteria: MatchCriteria,
    pub action_type: ActionType,
    pub action_params: ActionParams,
    pub status: MitigationStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub withdrawn_at: Option<DateTime<Utc>>,
    pub triggering_event_id: Uuid,
    pub last_event_id: Uuid,
    pub escalated_from_id: Option<Uuid>,
    pub reason: String,
    pub rejection_reason: Option<String>,
}

impl Mitigation {
    pub fn from_intent(intent: MitigationIntent, victim_ip: String, vector: AttackVector) -> Self {
        let now = Utc::now();
        let scope_hash = intent.match_criteria.compute_scope_hash();
        let expires_at = now + Duration::seconds(intent.ttl_seconds as i64);

        Self {
            mitigation_id: Uuid::new_v4(),
            scope_hash,
            pop: intent.pop,
            customer_id: intent.customer_id,
            service_id: intent.service_id,
            victim_ip,
            vector,
            match_criteria: intent.match_criteria,
            action_type: intent.action_type,
            action_params: intent.action_params,
            status: MitigationStatus::Pending,
            created_at: now,
            updated_at: now,
            expires_at,
            withdrawn_at: None,
            triggering_event_id: intent.event_id,
            last_event_id: intent.event_id,
            escalated_from_id: None,
            reason: intent.reason,
            rejection_reason: None,
        }
    }

    pub fn from_row(row: MitigationRow) -> Result<Self> {
        let match_criteria: MatchCriteria = serde_json::from_str(&row.match_json).map_err(|e| {
            tracing::error!(
                mitigation_id = %row.mitigation_id,
                error = %e,
                "failed to parse match_json - possible data corruption"
            );
            PrefixdError::Internal(format!(
                "invalid match_json for mitigation {}: {}",
                row.mitigation_id, e
            ))
        })?;

        let action_params: ActionParams = match &row.action_params_json {
            Some(json) => serde_json::from_str(json).map_err(|e| {
                tracing::error!(
                    mitigation_id = %row.mitigation_id,
                    error = %e,
                    "failed to parse action_params_json - possible data corruption"
                );
                PrefixdError::Internal(format!(
                    "invalid action_params_json for mitigation {}: {}",
                    row.mitigation_id, e
                ))
            })?,
            None => ActionParams { rate_bps: None },
        };

        let vector = row.vector.parse().map_err(|_| {
            tracing::error!(
                mitigation_id = %row.mitigation_id,
                vector = %row.vector,
                "failed to parse vector - possible data corruption"
            );
            PrefixdError::Internal(format!(
                "invalid vector '{}' for mitigation {}",
                row.vector, row.mitigation_id
            ))
        })?;

        let action_type = row.action_type.parse().map_err(|_| {
            tracing::error!(
                mitigation_id = %row.mitigation_id,
                action_type = %row.action_type,
                "failed to parse action_type - possible data corruption"
            );
            PrefixdError::Internal(format!(
                "invalid action_type '{}' for mitigation {}",
                row.action_type, row.mitigation_id
            ))
        })?;

        let status = row.status.parse().map_err(|_| {
            tracing::error!(
                mitigation_id = %row.mitigation_id,
                status = %row.status,
                "failed to parse status - possible data corruption"
            );
            PrefixdError::Internal(format!(
                "invalid status '{}' for mitigation {}",
                row.status, row.mitigation_id
            ))
        })?;

        Ok(Self {
            mitigation_id: row.mitigation_id,
            scope_hash: row.scope_hash,
            pop: row.pop,
            customer_id: row.customer_id,
            service_id: row.service_id,
            victim_ip: row.victim_ip,
            vector,
            match_criteria,
            action_type,
            action_params,
            status,
            created_at: row.created_at,
            updated_at: row.updated_at,
            expires_at: row.expires_at,
            withdrawn_at: row.withdrawn_at,
            triggering_event_id: row.triggering_event_id,
            last_event_id: row.last_event_id,
            escalated_from_id: row.escalated_from_id,
            reason: row.reason.unwrap_or_default(),
            rejection_reason: row.rejection_reason,
        })
    }

    pub fn is_active(&self) -> bool {
        self.status.is_active()
    }

    pub fn extend_ttl(&mut self, ttl_seconds: u32, event_id: Uuid) {
        let new_expires = Utc::now() + Duration::seconds(ttl_seconds as i64);
        if new_expires > self.expires_at {
            self.expires_at = new_expires;
        }
        self.updated_at = Utc::now();
        self.last_event_id = event_id;
    }

    pub fn withdraw(&mut self, reason: Option<String>) {
        self.status = MitigationStatus::Withdrawn;
        self.withdrawn_at = Some(Utc::now());
        self.updated_at = Utc::now();
        if let Some(r) = reason {
            self.reason = r;
        }
    }

    pub fn expire(&mut self) {
        self.status = MitigationStatus::Expired;
        self.withdrawn_at = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    pub fn activate(&mut self) {
        self.status = MitigationStatus::Active;
        self.updated_at = Utc::now();
    }

    pub fn reject(&mut self, reason: String) {
        self.status = MitigationStatus::Rejected;
        self.rejection_reason = Some(reason);
        self.updated_at = Utc::now();
    }
}
