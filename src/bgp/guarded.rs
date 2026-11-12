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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>, example = "192.0.2.99")]
    pub target: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_route_target: Option<String>,
    /// The profile owner without the speaker's `guarded:` namespace prefix.
    pub owner: String,
    /// Immutable per admission, independent of the shared owner generation.
    pub revision: u64,
    /// Standard community (`ASN:VALUE`) carried only by a diversion's return
    /// leg, so speaker export policy can scope it (ADR 030 R1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_community: Option<String>,
}

/// The canonical RFC 1997 value of a return-leg community, outside the
/// reserved `0:x` and well-known `65535:x` ranges.
pub fn export_community_value(text: &str) -> Option<u32> {
    let (high, low) = text.split_once(':')?;
    let (high, low): (u16, u16) = (high.parse().ok()?, low.parse().ok()?);
    (format!("{high}:{low}") == text && high != 0 && high != u16::MAX)
        .then_some((u32::from(high) << 16) | u32::from(low))
}

/// The only TCP-flags selector a return leg may carry: SYN and ACK set.
pub fn syn_ack() -> crate::domain::TcpFlagsMatch {
    crate::domain::TcpFlagsMatch {
        set: [crate::domain::TcpFlag::Syn, crate::domain::TcpFlag::Ack].into(),
        not_set: Default::default(),
    }
}

/// A diversion return leg's match (ADR 030 R2): a global host source, TCP,
/// optional canonical source ports, optional SYN+ACK and nothing else. It has
/// no destination component; ordinary rules never take this shape.
pub fn is_return_shape(nlri: &FlowSpecNlri) -> bool {
    nlri.scope.is_none()
        && nlri.dst_prefix.is_empty()
        && nlri.src_prefix.as_deref().is_some_and(|source| {
            source.parse::<ipnet::IpNet>().is_ok_and(|prefix| {
                prefix.prefix_len() == prefix.max_prefix_len() && prefix.to_string() == source
            })
        })
        && nlri.protocol == Some(6)
        && nlri.dst_ports.is_empty()
        && nlri.src_ports == crate::domain::canonical_ports(&nlri.src_ports)
        && nlri.src_ports.len() <= super::RUSTBGPD_MAX_PORTS_PER_LIST
        && nlri.fragment.is_none()
        && nlri.packet_length.is_none()
        && nlri
            .tcp_flags
            .as_ref()
            .is_none_or(|flags| *flags == syn_ack())
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
    /// The diversion victim: the inbound destination host, or the return
    /// leg's source host.
    pub fn victim(&self) -> Option<IpAddr> {
        let host = if self.export_community.is_some() {
            self.nlri.src_prefix.as_deref()?
        } else {
            &self.nlri.dst_prefix
        };
        host.parse::<ipnet::IpNet>()
            .ok()
            .map(|prefix| prefix.addr())
    }

    /// A return leg selects the victim as its source (ADR 030 R2).
    fn validate_return(&self) -> Result<()> {
        let victim = self.victim();
        if !is_return_shape(&self.nlri)
            || self
                .export_community
                .as_deref()
                .and_then(export_community_value)
                .is_none()
            || !self.route_targets.is_empty()
            || self.redirect_route_target.is_some()
            || self.revision == 0
            || !self.target.is_some_and(|target| {
                validate_redirect_target(target)
                    && victim.is_some_and(|victim| {
                        victim.is_ipv4() == target.is_ipv4() && victim != target
                    })
            })
        {
            return Err(PrefixdError::InvalidRequest(
                "invalid diversion return leg".into(),
            ));
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.export_community.is_some() {
            if self.owner.is_empty()
                || self.owner.len() > 64
                || !self
                    .owner
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
            {
                return Err(PrefixdError::InvalidRequest(
                    "invalid diversion return leg".into(),
                ));
            }
            return self.validate_return();
        }
        let prefix: ipnet::IpNet = self.nlri.dst_prefix.parse().map_err(|_| {
            PrefixdError::InvalidRequest("diversion requires a canonical host prefix".into())
        })?;
        if prefix.prefix_len() != prefix.max_prefix_len()
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
        match (self.target, &self.redirect_route_target) {
            (Some(target), None)
                if prefix.addr().is_ipv4() == target.is_ipv4()
                    && validate_redirect_target(target)
                    && prefix.addr() != target => {}
            (None, Some(target))
                if self.nlri.scope.is_some()
                    && crate::domain::canonical_route_target(target)
                        .is_ok_and(|canonical| canonical == *target) => {}
            _ => {
                return Err(PrefixdError::InvalidRequest(
                    "diversion requires exactly one valid IP or VRF route-target action".into(),
                ));
            }
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

    pub fn target_description(&self) -> Result<String> {
        match (self.target, &self.redirect_route_target) {
            (Some(target), None) => Ok(target.to_string()),
            (None, Some(target)) => Ok(format!("VRF RT {target}")),
            _ => Err(PrefixdError::InvalidRequest(
                "invalid diversion action target".into(),
            )),
        }
    }

    pub fn same_admission(&self, other: &Self) -> bool {
        self.owner == other.owner
            && self.revision == other.revision
            && self.target == other.target
            && self.redirect_route_target == other.redirect_route_target
            && self.route_targets == other.route_targets
            && self.export_community == other.export_community
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

    #[test]
    fn legacy_target_json_is_unchanged_and_redirect_targets_are_exclusive() {
        let legacy = serde_json::json!({
            "nlri": {"dst_prefix":"192.0.2.1/32","protocol":6,"dst_ports":[443]},
            "target":"192.0.2.99", "owner":"prefixd.scrub.fixture", "revision":7,
        });
        let rule: GuardedRule = serde_json::from_value(legacy.clone()).unwrap();
        rule.validate().unwrap();
        assert_eq!(serde_json::to_value(&rule).unwrap(), legacy);
        let mut vrf = rule.clone();
        vrf.target = None;
        vrf.redirect_route_target = Some("44407:888".into());
        assert!(vrf.validate().is_err(), "global VRF redirects stay refused");
        vrf.nlri.scope = Some(
            crate::domain::VpnFlowSpecIdentity::new(
                crate::domain::VpnFlowSpecFamily::Ipv4,
                "44407:40",
            )
            .unwrap(),
        );
        vrf.route_targets = vec!["44407:777".into()];
        vrf.validate().unwrap();
        assert_eq!(vrf.target_description().unwrap(), "VRF RT 44407:888");
        assert!(!vrf.same_admission(&rule));
        let encoded = serde_json::to_value(&vrf).unwrap();
        assert!(encoded.get("target").is_none());
        assert_eq!(encoded["redirect_route_target"], "44407:888");
        let restored: GuardedRule = serde_json::from_value(encoded).unwrap();
        assert!(vrf.same_admission(&restored));
        vrf.target = rule.target;
        assert!(
            vrf.validate().is_err(),
            "IP and VRF targets cannot be combined"
        );
        vrf.target = None;
        vrf.redirect_route_target = None;
        assert!(vrf.validate().is_err(), "a target is required");
    }
}
