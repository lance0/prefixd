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
    /// Every window authorizing an attempted add is durable before dispatch.
    /// Renewals use the profile's current window and are not recorded here.
    pub windows: Vec<GuardedStamp>,
    pub generation: Option<GuardedStamp>,
    pub last_error: Option<String>,
    #[serde(default)]
    pub export_observation: Option<DiversionExportObservation>,
    /// The return leg of a pair (ADR 030 R3), part of the immutable snapshot
    /// with the inbound `rule`'s owner, target and admission revision. Absent,
    /// the diversion has no return leg.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_rule: Option<GuardedRule>,
    /// The return leg's own export evidence, with `export_observation`'s rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_export_observation: Option<DiversionExportObservation>,
}

/// Last per-peer export evidence. A recheck that finds the same peers keeps
/// `observed_at`; a failed or timed-out read keeps the earlier peers as
/// historical evidence and sets `error`. An empty `peers` with no `error` is a
/// successful empty observation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DiversionExportObservation {
    /// When these peers were first observed.
    pub observed_at: DateTime<Utc>,
    pub peers: Vec<crate::bgp::PeerExport>,
    /// The latest read failed; `peers` is historical.
    #[serde(default)]
    pub error: Option<String>,
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
    /// Durable lifecycle only moves forward, and the first withdrawal reason
    /// and requester are immutable once recorded.
    pub fn may_replace(&self, saved: &Self) -> bool {
        use DiversionStatus::*;
        (self.status == saved.status
            || matches!(
                (saved.status, self.status),
                (Pending, Active | Withdrawing) | (Active, Withdrawing) | (Withdrawing, Withdrawn)
            ))
            && (saved.withdrawal_reason.is_none()
                || saved.withdrawal_reason == self.withdrawal_reason)
            && (saved.withdrawal_actor.is_none() || saved.withdrawal_actor == self.withdrawal_actor)
    }
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
                "return_export_observation",
            ] {
                object.remove(field);
            }
        }
        Ok(value)
    }
    /// The inbound leg, then the return leg when the row is a pair.
    pub fn legs(&self) -> impl Iterator<Item = &GuardedRule> {
        std::iter::once(&self.rule).chain(&self.return_rule)
    }
    /// Both legs are valid and the return leg is exactly the one the frozen
    /// profile derives from the inbound leg.
    pub fn validate(&self) -> crate::error::Result<()> {
        // The inbound leg is a host-destination rule; only a return leg
        // carries a community and omits the destination.
        if self.rule.export_community.is_some() {
            return Err(crate::error::PrefixdError::Internal(
                "inconsistent scrubber inbound leg".into(),
            ));
        }
        self.rule.validate()?;
        match (
            derive_return(&self.rule, self.profile.return_leg.as_ref())?,
            &self.return_rule,
        ) {
            (None, None) => Ok(()),
            (Some(expected), Some(saved)) if expected.same_admission(saved) => Ok(()),
            _ => Err(crate::error::PrefixdError::Internal(
                "inconsistent scrubber return leg".into(),
            )),
        }
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
        let mut details = serde_json::json!({"profile":self.profile.id,"revision":self.profile.revision,"policy_binding":self.profile.policy_binding,"victim":self.victim(),"match":self.rule.nlri,"target":self.rule.target,"admission_revision":self.rule.revision,"generation":self.generation,"status":self.status,"admitted_by":self.actor,"withdrawal_requested_by":self.withdrawal_actor,"reason":self.withdrawal_reason.as_ref().unwrap_or(&self.reason)});
        if let Some(target) = &self.rule.redirect_route_target {
            if let Some(object) = details.as_object_mut() {
                object.remove("target");
            }
            details["redirect_route_target"] = serde_json::json!(target);
        }
        if let Some(leg) = &self.return_rule {
            details["return_match"] = serde_json::json!(leg.nlri);
            details["export_community"] = serde_json::json!(leg.export_community);
        }
        crate::observability::AuditEntry::new(
            actor_type,
            actor.or_else(|| Some("scrubber".into())),
            action,
            Some("scrubber_diversion"),
            Some(self.id.to_string()),
            details,
        )
    }
}
