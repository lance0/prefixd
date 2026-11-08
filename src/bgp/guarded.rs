//! Guarded, revision-fenced FlowSpec diversion. Separate from ordinary rate rules.
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::domain::FlowSpecNlri;
use crate::error::{PrefixdError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GuardedStamp {
    pub incarnation: u64,
    pub sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GuardedRule {
    pub nlri: FlowSpecNlri,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub route_targets: Vec<String>,
    #[schema(value_type = String, example = "192.0.2.99")]
    pub target: IpAddr,
    /// The profile owner without the speaker's `guarded:` namespace prefix.
    pub owner: String,
    /// Immutable per admission, independent of the shared owner generation.
    pub revision: u64,
}

pub fn validate_redirect_target(target: IpAddr) -> bool {
    match target {
        IpAddr::V4(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && ip.octets()[0] != 0
                && ip.octets()[0] < 240
                && !ip.is_broadcast()
        }
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && (ip.segments()[0] & 0xffc0) != 0xfe80
                && ip.to_ipv4().is_none()
        }
    }
}

impl GuardedRule {
    pub fn validate(&self) -> Result<()> {
        let prefix: ipnet::IpNet = self.nlri.dst_prefix.parse().map_err(|_| {
            PrefixdError::InvalidRequest("diversion requires a canonical host prefix".into())
        })?;
        if prefix.prefix_len() != prefix.max_prefix_len()
            || prefix.addr().is_ipv4() != self.target.is_ipv4()
            || !validate_redirect_target(self.target)
            || prefix.addr() == self.target
            || self.revision == 0
            || self.owner.is_empty()
            || self.owner.len() > 64
            || !self
                .owner
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
        {
            return Err(PrefixdError::InvalidRequest(
                "invalid host diversion, target, owner or admission revision".into(),
            ));
        }
        match &self.nlri.scope {
            Some(_) => {
                if self.route_targets.is_empty() {
                    return Err(PrefixdError::InvalidRequest(
                        "VPN diversion needs scope route targets".into(),
                    ));
                }
                for target in &self.route_targets {
                    crate::domain::route_target_bytes(target)
                        .map_err(|error| PrefixdError::InvalidRequest(error.to_string()))?;
                }
            }
            None if !self.route_targets.is_empty() => {
                return Err(PrefixdError::InvalidRequest(
                    "global diversion cannot carry scope route targets".into(),
                ));
            }
            None => {}
        }
        self.nlri
            .validate()
            .map_err(|error| PrefixdError::InvalidRequest(error.to_string()))
    }

    pub fn same_admission(&self, other: &Self) -> bool {
        self.owner == other.owner
            && self.revision == other.revision
            && self.target == other.target
            && self.route_targets == other.route_targets
            && self.nlri.compute_hash() == other.nlri.compute_hash()
    }
}

#[derive(Debug, Clone)]
pub struct GuardedObservation {
    pub rule: GuardedRule,
    pub generation: GuardedStamp,
    pub remaining_ms: u32,
}

#[derive(Debug, Clone, Default)]
pub struct GuardedInventory {
    pub entries: Vec<GuardedObservation>,
    /// Ordinary and foreign guarded local rules: occupied keys, never mistaken
    /// for absence, whose selectors also count for victim overlap checks.
    pub other_matches: Vec<FlowSpecNlri>,
}
impl std::ops::Deref for GuardedInventory {
    type Target = [GuardedObservation];
    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}
impl GuardedInventory {
    pub fn has_key(&self, nlri: &FlowSpecNlri) -> bool {
        let key = nlri.compute_hash();
        self.other_matches
            .iter()
            .any(|other| other.compute_hash() == key)
            || self
                .entries
                .iter()
                .any(|entry| entry.rule.nlri.compute_hash() == key)
    }
}

#[derive(Debug, Clone)]
pub struct IssuedWindow {
    pub stamp: GuardedStamp,
    pub remaining_ms: u32,
}

/// No fallback to ordinary leased or unleased mutations. All writes, including
/// renewal and window issuance, require the controller fence.
#[async_trait]
pub trait GuardedFlowSpecSpeaker: Send + Sync {
    async fn issue_window(&self, owner: &str, seconds: u32) -> Result<IssuedWindow>;
    async fn add_guarded(
        &self,
        rule: &GuardedRule,
        window: GuardedStamp,
        seconds: u32,
    ) -> Result<GuardedStamp>;
    async fn renew_guarded(
        &self,
        owner: &str,
        generation: GuardedStamp,
        window: GuardedStamp,
        seconds: u32,
    ) -> Result<u32>;
    async fn delete_guarded(&self, rule: &GuardedRule) -> Result<()>;
    /// Complete dual-family retained inventory. Expired rows remain distinguishable.
    async fn guarded_inventory(&self) -> Result<GuardedInventory>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_targets_refuse_unsafe_and_mapped_addresses() {
        for value in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fe80::1",
            "ff02::1",
            "::ffff:192.0.2.1",
            "::192.0.2.1",
        ] {
            assert!(!validate_redirect_target(value.parse().unwrap()), "{value}");
        }
        for value in ["192.0.2.99", "10.1.1.1", "2001:db8::99", "fd00::99"] {
            assert!(validate_redirect_target(value.parse().unwrap()), "{value}");
        }
    }
}
