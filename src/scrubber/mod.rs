//! Manual, guarded scrubber diversion (ADR 030).
pub mod api;
mod config;
mod controller;
pub use config::*;
pub use controller::*;

use crate::bgp::{GuardedRule, GuardedStamp};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Diversion {
    pub id: Uuid,
    pub controller_incarnation: Uuid,
    pub controller_epoch: u64,
    pub pop: String,
    pub customer_id: String,
    pub profile: ProfileSnapshot,
    pub rule: GuardedRule,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub actor: String,
    pub reason: String,
    pub dry_run: bool,
    pub status: DiversionStatus,
    pub withdrawal_reason: Option<String>,
    #[serde(default)]
    pub withdrawal_actor: Option<String>,
    /// Every window used by an attempted add or renewal is durable before dispatch.
    pub windows: Vec<GuardedStamp>,
    pub generation: Option<GuardedStamp>,
    pub last_error: Option<String>,
    #[serde(default)]
    pub export_observation: Option<DiversionExportObservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DiversionExportObservation {
    pub observed_at: DateTime<Utc>,
    pub peers: Vec<crate::bgp::PeerExport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiversionStatus {
    Pending,
    Active,
    Withdrawing,
    Withdrawn,
    Simulated,
}

impl DiversionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Withdrawing => "withdrawing",
            Self::Withdrawn => "withdrawn",
            Self::Simulated => "simulated",
        }
    }
    pub fn outstanding(self) -> bool {
        matches!(self, Self::Pending | Self::Active | Self::Withdrawing)
    }
}

impl Diversion {
    pub fn immutable_snapshot(&self) -> crate::error::Result<serde_json::Value> {
        let mut value = serde_json::to_value(self)?;
        if let Some(object) = value.as_object_mut() {
            for field in [
                "status",
                "withdrawal_reason",
                "withdrawal_actor",
                "windows",
                "generation",
                "last_error",
                "export_observation",
            ] {
                object.remove(field);
            }
        }
        Ok(value)
    }
    pub fn victim(&self) -> String {
        self.rule
            .nlri
            .dst_prefix
            .parse::<ipnet::IpNet>()
            .expect("validated host diversion")
            .addr()
            .to_string()
    }
    pub fn audit(&self, action: &str) -> crate::observability::AuditEntry {
        let actor = if action == "scrubber_admit" {
            Some(self.actor.clone())
        } else if action.starts_with("scrubber_withdraw") {
            self.withdrawal_actor.clone()
        } else {
            None
        };
        let actor_type = if actor.is_some() {
            crate::observability::ActorType::Operator
        } else {
            crate::observability::ActorType::System
        };
        crate::observability::AuditEntry::new(
            actor_type,
            actor.or_else(|| Some("scrubber".into())),
            action,
            Some("scrubber_diversion"),
            Some(self.id.to_string()),
            serde_json::json!({"profile":self.profile.id,"revision":self.profile.revision,"victim":self.victim(),"target":self.rule.target,"admission_revision":self.rule.revision,"status":self.status,"admitted_by":self.actor,"withdrawal_requested_by":self.withdrawal_actor,"reason":self.withdrawal_reason.as_ref().unwrap_or(&self.reason)}),
        )
    }
}
