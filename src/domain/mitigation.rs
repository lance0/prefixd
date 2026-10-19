use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::FromRow;
use uuid::Uuid;

use super::AttackVector;
use crate::config::OperationMode;
use crate::error::{PrefixdError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MitigationStatus {
    Pending,
    Active,
    // Legacy state: no code path produces it. Kept so stored rows and old
    // API filters still parse, and live-state queries still cover old rows.
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
    /// Unicast host route, not a FlowSpec action (ADR 027).
    Blackhole,
}

impl ActionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Police => "police",
            Self::Discard => "discard",
            Self::Blackhole => "blackhole",
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
            "blackhole" => Ok(Self::Blackhole),
            _ => Err(format!("unknown action: {}", s)),
        }
    }
}

/// Unknown keys fail closed: ignoring a match key would widen the rule (ADR 028).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchCriteria {
    pub dst_prefix: String,
    pub protocol: Option<u8>,
    pub dst_ports: Vec<u16>,
    /// UDP source ports (RFC 8955 type 6), an equality set stored sorted and
    /// deduplicated. Empty means absent.
    #[serde(
        default,
        with = "canonical_src_ports",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub src_ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fragment: Option<FragmentMatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_length: Option<PacketLengthRange>,
}

/// Sorted, deduplicated ports: the one form source ports are stored, compared and hashed in.
pub fn canonical_ports(ports: &[u16]) -> Vec<u16> {
    let mut ports = ports.to_vec();
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Serde adapter: source ports are canonical whenever they are read or written.
pub(super) mod canonical_src_ports {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(ports: &[u16], serializer: S) -> Result<S::Ok, S::Error> {
        super::canonical_ports(ports).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u16>, D::Error> {
        Ok(super::canonical_ports(&Vec::deserialize(deserializer)?))
    }
}

/// Fragment match (RFC 8955 type 12). Only non-first fragments (IsF) are matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FragmentMatch {
    NonFirst,
}

impl FragmentMatch {
    /// The RFC 8955 bitmask, encoded with the match bit set. Never the IPv6-reserved 0x01.
    pub fn bitmask(self) -> u8 {
        match self {
            Self::NonFirst => 0x02,
        }
    }
}

/// One inclusive total-IP-length range (RFC 8955 type 10); both bounds are required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketLengthRange {
    pub min: u16,
    pub max: u16,
}

impl MatchCriteria {
    pub fn compute_scope_hash(&self) -> String {
        if let Some(hash) = super::FlowSpecNlri::from(self).extended_identity() {
            return hash;
        }
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

    /// Scope hash for `action_type`. FlowSpec keeps `compute_scope_hash` byte for byte;
    /// a blackhole is domain-separated so it never shares a FlowSpec scope.
    pub fn scope_hash_for(&self, action_type: ActionType) -> String {
        match action_type {
            ActionType::Police | ActionType::Discard => self.compute_scope_hash(),
            ActionType::Blackhole => blackhole_identity(&self.dst_prefix),
        }
    }
}

/// Identity of a blackhole host route: a kind tag plus the canonical prefix. Valid
/// prefixes never contain the tag, so no FlowSpec scope or NLRI hash input matches it.
pub(crate) fn blackhole_identity(prefix: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"prefixd:blackhole\0");
    match prefix.parse::<ipnet::IpNet>() {
        Ok(prefix) => hasher.update(prefix.to_string().as_bytes()),
        Err(_) => hasher.update(prefix.as_bytes()),
    }
    hex::encode(&hasher.finalize()[..16])
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActionParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_bps: Option<u64>,
    /// A blackhole's route, frozen at admission (ADR 027). Absent for FlowSpec,
    /// so FlowSpec rows serialize byte for byte as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blackhole: Option<super::BlackholeRule>,
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
    #[sqlx(try_from = "crate::db::CheckedTimestamp")]
    pub created_at: DateTime<Utc>,
    #[sqlx(try_from = "crate::db::CheckedTimestamp")]
    pub updated_at: DateTime<Utc>,
    #[sqlx(try_from = "crate::db::CheckedTimestamp")]
    pub expires_at: DateTime<Utc>,
    #[sqlx(try_from = "crate::db::CheckedTimestamp")]
    pub withdrawn_at: Option<DateTime<Utc>>,
    pub triggering_event_id: Uuid,
    pub last_event_id: Uuid,
    pub escalated_from_id: Option<Uuid>,
    pub reason: Option<String>,
    pub rejection_reason: Option<String>,
    #[sqlx(try_from = "crate::db::CheckedTimestamp")]
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub acknowledged_by: Option<String>,
    pub signal_group_id: Option<Uuid>,
    pub origin_mode: Option<String>,
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
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub acknowledged_by: Option<String>,
    /// FK to signal_groups table — set when this mitigation was created via
    /// the correlation engine's corroboration logic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_group_id: Option<Uuid>,
    /// Operation mode that admitted this row; immutable after creation.
    /// None only for rows that predate the column and are not yet tagged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_mode: Option<OperationMode>,
}

impl Mitigation {
    pub fn from_intent(intent: MitigationIntent, victim_ip: String, vector: AttackVector) -> Self {
        let now = Utc::now();
        let scope_hash = intent.match_criteria.scope_hash_for(intent.action_type);
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
            acknowledged_at: None,
            acknowledged_by: None,
            signal_group_id: None,
            origin_mode: None,
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
            None => ActionParams::default(),
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

        let origin_mode = match &row.origin_mode {
            Some(value) => Some(OperationMode::parse(value).ok_or_else(|| {
                PrefixdError::Internal(format!(
                    "invalid origin_mode '{}' for mitigation {}",
                    value, row.mitigation_id
                ))
            })?),
            None => None,
        };

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
            acknowledged_at: row.acknowledged_at,
            acknowledged_by: row.acknowledged_by,
            signal_group_id: row.signal_group_id,
            origin_mode,
        })
    }

    pub fn is_active(&self) -> bool {
        self.status.is_active()
    }

    /// A dry-run simulation is never desired speaker state, whatever the current mode.
    pub fn is_dry_run_origin(&self) -> bool {
        self.origin_mode == Some(OperationMode::DryRun)
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
