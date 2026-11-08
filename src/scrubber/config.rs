use crate::bgp::validate_redirect_target;
use crate::error::{PrefixdError, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScrubberConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub profiles: Vec<ScrubberProfile>,
    #[serde(default)]
    pub readiness_ca_cert: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScrubberProfile {
    pub id: String,
    pub revision: String,
    #[serde(default = "global_scope", skip_serializing_if = "is_global_scope")]
    pub scope: String,
    pub ipv4_target: Option<IpAddr>,
    pub ipv6_target: Option<IpAddr>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "canonical_redirect"
    )]
    pub redirect_route_target: Option<String>,
    pub destinations: Vec<ipnet::IpNet>,
    pub router_peers: Vec<String>,
    pub policy_binding: String,
    pub qualification_receipt: String,
    pub readiness_url: String,
    pub readiness_token_env: String,
    pub max_ttl_seconds: u32,
    pub max_active: u32,
    pub max_new_per_minute: u32,
    #[serde(default)]
    pub reserved_targets: Vec<ipnet::IpNet>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfileSnapshot {
    pub id: String,
    pub revision: String,
    #[serde(default = "global_scope", skip_serializing_if = "is_global_scope")]
    pub scope: String,
    pub router_peers: Vec<String>,
    pub policy_binding: String,
    pub qualification_receipt: String,
    pub destinations: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_route_target: Option<String>,
}

fn canonical_redirect<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer)?
        .as_deref()
        .map(crate::domain::canonical_route_target)
        .transpose()
        .map_err(serde::de::Error::custom)
}

fn global_scope() -> String {
    "global".into()
}

fn is_global_scope(scope: &str) -> bool {
    scope == "global"
}

impl ScrubberProfile {
    pub fn target(&self, ipv4: bool) -> Result<Option<IpAddr>> {
        if self.redirect_route_target.is_some() {
            return Ok(None);
        }
        (if ipv4 {
            self.ipv4_target
        } else {
            self.ipv6_target
        })
        .map(Some)
        .ok_or_else(|| {
            PrefixdError::InvalidRequest("profile does not support this target family".into())
        })
    }
    pub fn matches_target(&self, rule: &crate::bgp::GuardedRule) -> bool {
        self.redirect_route_target == rule.redirect_route_target
            && self
                .target(rule.nlri.ip_version() == crate::domain::IpVersion::V4)
                .ok()
                == Some(rule.target)
    }
    pub fn snapshot(&self) -> ProfileSnapshot {
        ProfileSnapshot {
            id: self.id.clone(),
            revision: self.revision.clone(),
            scope: self.scope.clone(),
            router_peers: self.router_peers.clone(),
            policy_binding: self.policy_binding.clone(),
            qualification_receipt: self.qualification_receipt.clone(),
            destinations: self.destinations.iter().map(ToString::to_string).collect(),
            redirect_route_target: self.redirect_route_target.clone(),
        }
    }
}

impl ScrubberConfig {
    pub fn validate(&self) -> Result<()> {
        if self.enabled && self.profiles.is_empty() {
            return Err(PrefixdError::Config(
                "enabled scrubber diversion needs at least one profile".into(),
            ));
        }
        if self.profiles.len() > 32 {
            return Err(PrefixdError::Config(
                "at most 32 scrubber profiles are allowed".into(),
            ));
        }
        let mut names = std::collections::HashSet::new();
        for profile in &self.profiles {
            let url = reqwest::Url::parse(&profile.readiness_url)
                .map_err(|_| PrefixdError::Config("invalid scrubber readiness URL".into()))?;
            if !names.insert(&profile.id)
                || profile.id.is_empty()
                || profile.id.len() > 32
                || !profile
                    .id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
                || profile.revision.is_empty()
                || profile.revision.len() > 128
                || profile.policy_binding.is_empty()
                || profile.policy_binding.len() > 256
                || profile.qualification_receipt.is_empty()
                || profile.qualification_receipt.len() > 1024
                || profile.destinations.is_empty()
                || profile.router_peers.is_empty()
                || profile.router_peers.len() > 64
                || if let Some(target) = &profile.redirect_route_target {
                    profile.scope == "global"
                        || profile.ipv4_target.is_some()
                        || profile.ipv6_target.is_some()
                        || !crate::domain::canonical_route_target(target)
                            .is_ok_and(|canonical| canonical == *target)
                } else {
                    profile.ipv4_target.is_none() && profile.ipv6_target.is_none()
                }
                || profile.ipv4_target.is_some_and(|v| !v.is_ipv4())
                || profile.ipv6_target.is_some_and(|v| !v.is_ipv6())
                || profile
                    .ipv4_target
                    .into_iter()
                    .chain(profile.ipv6_target)
                    .any(|v| {
                        // A target inside its own destinations could divert
                        // the scrubber's traffic back through itself.
                        !validate_redirect_target(v)
                            || profile.reserved_targets.iter().any(|net| net.contains(&v))
                            || profile.destinations.iter().any(|net| net.contains(&v))
                    })
                || !(5..=3600).contains(&profile.max_ttl_seconds)
                || !(1..=1000).contains(&profile.max_active)
                || !(1..=1000).contains(&profile.max_new_per_minute)
                || url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
                || profile.readiness_token_env.is_empty()
            {
                return Err(PrefixdError::Config(
                    "invalid scrubber profile or readiness bounds".into(),
                ));
            }
            let mut peers = std::collections::HashSet::new();
            for peer in &profile.router_peers {
                let (address, interface) = peer
                    .split_once('%')
                    .map_or((peer.as_str(), None), |(a, i)| (a, Some(i)));
                let address: IpAddr = address
                    .parse()
                    .map_err(|_| PrefixdError::Config("invalid scrubber router peer".into()))?;
                let link_local =
                    matches!(address, IpAddr::V6(v) if v.segments()[0] & 0xffc0 == 0xfe80);
                if !peers.insert(peer)
                    || link_local != interface.is_some()
                    || interface.is_some_and(str::is_empty)
                {
                    return Err(PrefixdError::Config(
                        "ambiguous scrubber router peer identity".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}
