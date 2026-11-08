use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::domain::{IpVersion, VpnFlowSpecFamily, VpnFlowSpecIdentity, VpnScopeSnapshot};
use crate::error::{PrefixdError, Result};

use super::{BgpConfig, BgpMode};

/// Operator-owned VPN import scope; no detector may supply these attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "VpnScopeConfigInput")]
pub struct VpnScopeConfig {
    pub family: VpnFlowSpecFamily,
    pub rd: String,
    pub route_targets: Vec<String>,
    pub allow_source_only: bool,
    pub min_source_prefix_length: u8,
    pub max_source_only_ttl_seconds: u32,
    pub max_source_only_active: u32,
    pub infrastructure_prefixes: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VpnScopeConfigInput {
    family: VpnFlowSpecFamily,
    rd: String,
    route_targets: Vec<String>,
    #[serde(default)]
    allow_source_only: bool,
    #[serde(default)]
    min_source_prefix_length: Option<u8>,
    #[serde(default = "default_max_source_only_ttl_seconds")]
    max_source_only_ttl_seconds: u32,
    #[serde(default = "default_max_source_only_active")]
    max_source_only_active: u32,
    #[serde(default)]
    infrastructure_prefixes: Vec<String>,
}

impl From<VpnScopeConfigInput> for VpnScopeConfig {
    fn from(input: VpnScopeConfigInput) -> Self {
        Self {
            family: input.family,
            rd: input.rd,
            route_targets: input.route_targets,
            allow_source_only: input.allow_source_only,
            min_source_prefix_length: input.min_source_prefix_length.unwrap_or(
                match input.family {
                    VpnFlowSpecFamily::Ipv4 => 24,
                    VpnFlowSpecFamily::Ipv6 => 64,
                },
            ),
            max_source_only_ttl_seconds: input.max_source_only_ttl_seconds,
            max_source_only_active: input.max_source_only_active,
            infrastructure_prefixes: input.infrastructure_prefixes,
        }
    }
}

fn default_max_source_only_ttl_seconds() -> u32 {
    60
}

fn default_max_source_only_active() -> u32 {
    10
}

/// Automatic scope selection belongs to operator configuration, never detector input.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DefaultFlowSpecScope {
    Single(String),
    Families(DefaultFlowSpecScopeFamilies),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultFlowSpecScopeFamilies {
    pub ipv4: String,
    pub ipv6: String,
}

impl Default for DefaultFlowSpecScope {
    fn default() -> Self {
        Self::Single("global".into())
    }
}

impl From<String> for DefaultFlowSpecScope {
    fn from(name: String) -> Self {
        Self::Single(name)
    }
}

impl From<&str> for DefaultFlowSpecScope {
    fn from(name: &str) -> Self {
        Self::Single(name.into())
    }
}

impl DefaultFlowSpecScope {
    pub fn is_global(&self) -> bool {
        match self {
            Self::Single(name) => name == "global",
            Self::Families(names) => names.ipv4 == "global" && names.ipv6 == "global",
        }
    }

    fn name_for(&self, family: IpVersion) -> &str {
        match self {
            Self::Single(name) => name,
            Self::Families(names) => match family {
                IpVersion::V4 => &names.ipv4,
                IpVersion::V6 => &names.ipv6,
            },
        }
    }
}

fn invalid(message: impl Into<String>) -> PrefixdError {
    PrefixdError::Config(message.into())
}

impl VpnScopeConfig {
    pub fn snapshot(&self, name: &str) -> Result<VpnScopeSnapshot> {
        let identity = VpnFlowSpecIdentity::new(self.family, &self.rd)
            .map_err(|error| invalid(format!("invalid VPN scope {name}: {error}")))?;
        VpnScopeSnapshot::new(name, identity, &self.route_targets)
            .map_err(|error| invalid(format!("invalid VPN scope {name}: {error}")))
    }

    fn validate(&self, name: &str) -> Result<VpnScopeSnapshot> {
        let max_prefix_length = match self.family {
            VpnFlowSpecFamily::Ipv4 => 32,
            VpnFlowSpecFamily::Ipv6 => 128,
        };
        if !(1..=max_prefix_length).contains(&self.min_source_prefix_length) {
            return Err(invalid(format!(
                "VPN min_source_prefix_length must be between 1 and {max_prefix_length} for its family"
            )));
        }
        // Source-only traffic reaches every destination; keep its expiry short.
        if !(1..=300).contains(&self.max_source_only_ttl_seconds) {
            return Err(invalid(
                "VPN max_source_only_ttl_seconds must be between 1 and 300",
            ));
        }
        if self.max_source_only_active == 0 {
            return Err(invalid("VPN max_source_only_active must be nonzero"));
        }
        for prefix in &self.infrastructure_prefixes {
            let network = prefix.parse::<ipnet::IpNet>().map_err(|_| {
                invalid("VPN infrastructure_prefixes must contain canonical network CIDRs")
            })?;
            if network.addr().is_ipv4() != (self.family == VpnFlowSpecFamily::Ipv4) {
                return Err(invalid(
                    "VPN infrastructure_prefixes must use the scope address family",
                ));
            }
            if network.addr() != network.network() {
                return Err(invalid(
                    "VPN infrastructure_prefixes must contain canonical network CIDRs",
                ));
            }
        }
        self.snapshot(name)
    }
}

impl BgpConfig {
    pub fn validate_vpn_scopes(&self) -> Result<()> {
        if !self.vpn_scopes.is_empty() && !matches!(self.mode, BgpMode::Rustbgpd | BgpMode::Mock) {
            return Err(invalid("VPN FlowSpec requires the rustbgpd backend"));
        }
        let mut identities = HashSet::new();
        for (name, scope) in &self.vpn_scopes {
            if name == "global"
                || name.is_empty()
                || name.len() > 64
                || !name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
            {
                return Err(invalid(
                    "VPN scope names must be 1-64 ASCII letters, digits, dots, underscores or hyphens; global is reserved",
                ));
            }
            let snapshot = scope.validate(name)?;
            if !identities.insert(snapshot.identity) {
                return Err(invalid(
                    "VPN scope names must resolve to distinct family and RD identities",
                ));
            }
        }
        match &self.default_scope {
            DefaultFlowSpecScope::Single(name) => {
                self.resolve_scope(name)?;
            }
            DefaultFlowSpecScope::Families(_) => {
                self.resolve_default_scope_for(IpVersion::V4)?;
                self.resolve_default_scope_for(IpVersion::V6)?;
            }
        }
        Ok(())
    }

    pub fn resolve_scope(&self, name: &str) -> Result<Option<VpnScopeSnapshot>> {
        if name == "global" {
            return Ok(None);
        }
        let scope = self
            .vpn_scopes
            .get(name)
            .ok_or_else(|| invalid(format!("unknown VPN scope {name}")))?;
        scope.validate(name).map(Some)
    }

    pub fn resolve_default_scope(&self) -> Result<Option<VpnScopeSnapshot>> {
        match &self.default_scope {
            DefaultFlowSpecScope::Single(name) => self.resolve_scope(name),
            DefaultFlowSpecScope::Families(_) => Err(invalid(
                "default_scope selects by family; an address family is required",
            )),
        }
    }

    pub fn resolve_default_scope_for(&self, family: IpVersion) -> Result<Option<VpnScopeSnapshot>> {
        let scope = self.resolve_scope(self.default_scope.name_for(family))?;
        if let Some(scope) = &scope {
            let expected = match family {
                IpVersion::V4 => VpnFlowSpecFamily::Ipv4,
                IpVersion::V6 => VpnFlowSpecFamily::Ipv6,
            };
            if scope.identity.family != expected {
                return Err(PrefixdError::InvalidRequest(
                    "automatic default_scope family does not match the mitigation address family"
                        .into(),
                ));
            }
        }
        Ok(scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(extra: &str) -> std::result::Result<BgpConfig, serde_saphyr::Error> {
        crate::config::parse_yaml(&format!(
            "backend: rustbgpd\nlocal_asn: 65000\nrouter_id: 192.0.2.1\n{extra}"
        ))
    }

    #[test]
    fn documented_dual_stack_scope_example_is_valid() {
        #[derive(serde::Deserialize)]
        struct Example {
            bgp: BgpConfig,
        }
        let example: Example =
            crate::config::parse_yaml(include_str!("../../configs/vpn-scopes.yaml.example"))
                .unwrap();
        assert!(
            example
                .bgp
                .resolve_default_scope_for(IpVersion::V4)
                .unwrap()
                .is_some()
        );
        assert!(
            example
                .bgp
                .resolve_default_scope_for(IpVersion::V6)
                .unwrap()
                .is_some()
        );
    }

    const TRANSIT: &str = "vpn_scopes:\n  TRANSIT:\n    family: ipv4\n    rd: '44407:40'\n    route_targets: ['44407:777']\n";

    #[test]
    fn legacy_scope_is_global_and_new_fields_stay_absent() {
        let bgp = config("").unwrap();
        assert!(bgp.resolve_default_scope().unwrap().is_none());
        let json = serde_json::to_value(bgp).unwrap();
        assert!(json.get("default_scope").is_none());
        assert!(json.get("vpn_scopes").is_none());
    }

    #[test]
    fn automatic_defaults_resolve_each_family_without_global_fallback() {
        let dual = format!(
            "{TRANSIT}  TRANSIT6:\n    family: ipv6\n    rd: '44407:40'\n    route_targets: ['44407:777']\n"
        );
        let bgp = config(&format!(
            "default_scope: {{ipv4: TRANSIT, ipv6: TRANSIT6}}\n{dual}"
        ))
        .unwrap();
        assert_eq!(
            bgp.resolve_default_scope_for(IpVersion::V4)
                .unwrap()
                .unwrap()
                .name,
            "TRANSIT"
        );
        assert_eq!(
            bgp.resolve_default_scope_for(IpVersion::V6)
                .unwrap()
                .unwrap()
                .name,
            "TRANSIT6"
        );
        assert_eq!(
            serde_json::to_value(&bgp).unwrap()["default_scope"],
            serde_json::json!({"ipv4": "TRANSIT", "ipv6": "TRANSIT6"})
        );
        let mixed = config(&format!(
            "default_scope: {{ipv4: global, ipv6: TRANSIT6}}\n{dual}"
        ))
        .unwrap();
        assert!(
            mixed
                .resolve_default_scope_for(IpVersion::V4)
                .unwrap()
                .is_none()
        );
        assert!(
            mixed
                .resolve_default_scope_for(IpVersion::V6)
                .unwrap()
                .is_some()
        );
        let single = config(&format!("default_scope: TRANSIT\n{dual}")).unwrap();
        assert!(
            single
                .resolve_default_scope_for(IpVersion::V4)
                .unwrap()
                .is_some()
        );
        assert!(single.resolve_default_scope_for(IpVersion::V6).is_err());
        assert_eq!(
            serde_json::to_value(single).unwrap()["default_scope"],
            "TRANSIT"
        );
        let global = config("").unwrap();
        for family in [IpVersion::V4, IpVersion::V6] {
            assert!(global.resolve_default_scope_for(family).unwrap().is_none());
        }
        assert!(global.default_scope.is_global());
        assert!(DefaultFlowSpecScope::from("global").is_global());
        assert!(DefaultFlowSpecScope::from(String::from("global")).is_global());
        for selection in [
            "{ipv4: TRANSIT6, ipv6: TRANSIT}",
            "{ipv4: TRANSIT, ipv6: missing}",
            "{ipv4: TRANSIT}",
            "{ipv6: TRANSIT6}",
            "{ipv4: TRANSIT, ipv6: TRANSIT6, typo: global}",
        ] {
            assert!(
                config(&format!("default_scope: {selection}\n{dual}")).is_err(),
                "{selection}"
            );
        }
    }

    #[test]
    fn configured_scope_resolves_an_immutable_snapshot() {
        let bgp = config(&format!("default_scope: TRANSIT\n{TRANSIT}")).unwrap();
        let snapshot = bgp.resolve_default_scope().unwrap().unwrap();
        assert_eq!(snapshot.name, "TRANSIT");
        assert_eq!(snapshot.identity.rd(), "44407:40");
        assert_eq!(snapshot.route_targets, ["44407:777"]);
        let policy = &bgp.vpn_scopes["TRANSIT"];
        assert!(!policy.allow_source_only);
        assert_eq!(policy.min_source_prefix_length, 24);
        assert_eq!(policy.max_source_only_ttl_seconds, 60);
        assert_eq!(policy.max_source_only_active, 10);
    }

    #[test]
    fn ipv6_scope_has_family_specific_source_policy_defaults() {
        let ipv6 = TRANSIT.replace("family: ipv4", "family: ipv6");
        let bgp = config(&format!(
            "{ipv6}    infrastructure_prefixes: ['2001:db8::/32']\n"
        ))
        .unwrap();
        let policy = &bgp.vpn_scopes["TRANSIT"];
        assert_eq!(policy.family, VpnFlowSpecFamily::Ipv6);
        assert_eq!(policy.min_source_prefix_length, 64);
        assert_eq!(
            bgp.resolve_scope("TRANSIT")
                .unwrap()
                .unwrap()
                .identity
                .family,
            VpnFlowSpecFamily::Ipv6
        );
        assert!(config(&format!("{ipv6}    min_source_prefix_length: 128\n")).is_ok());
        assert!(config(&format!("{ipv6}    min_source_prefix_length: 129\n")).is_err());
        assert!(
            config(&format!(
                "{ipv6}    infrastructure_prefixes: ['192.0.2.0/24']\n"
            ))
            .is_err()
        );
    }

    #[test]
    fn scope_names_cannot_alias_the_same_wire_identity() {
        for rd in ["44407:40", "0x0000ad7700000028"] {
            let alias = format!(
                "{TRANSIT}  ALIAS:\n    family: ipv4\n    rd: '{rd}'\n    route_targets: ['44407:999']\n"
            );
            assert!(config(&alias).is_err(), "accepted duplicate identity {rd}");
        }
        let distinct = format!(
            "{TRANSIT}  OTHER:\n    family: ipv4\n    rd: '44407:41'\n    route_targets: ['44407:999']\n"
        );
        assert!(config(&distinct).is_ok());
    }

    #[test]
    fn source_only_policy_accepts_explicit_limits_and_infrastructure() {
        let bgp = config(&format!(
            "{TRANSIT}    allow_source_only: true\n    min_source_prefix_length: 28\n    max_source_only_ttl_seconds: 30\n    max_source_only_active: 2\n    infrastructure_prefixes: ['192.0.2.0/24']\n"
        ))
        .unwrap();
        let policy = &bgp.vpn_scopes["TRANSIT"];
        assert!(policy.allow_source_only);
        assert_eq!(policy.min_source_prefix_length, 28);
        assert_eq!(policy.max_source_only_ttl_seconds, 30);
        assert_eq!(policy.max_source_only_active, 2);
        assert_eq!(policy.infrastructure_prefixes, ["192.0.2.0/24"]);
    }

    #[test]
    fn invalid_scope_configuration_fails_before_admission() {
        for bad in [
            "default_scope: missing\n".to_string(),
            TRANSIT.replace("family: ipv4", "family: ipv5"),
            TRANSIT.replace("rd: '44407:40'", "rd: '65536:65536'"),
            TRANSIT.replace("['44407:777']", "[]"),
            TRANSIT.replace("['44407:777']", "['44407:777', '44407:777']"),
            TRANSIT.replace("TRANSIT:", "global:"),
            TRANSIT.replace("TRANSIT:", "'bad name':"),
            format!("{TRANSIT}    allow_source_onyl: true\n"),
            format!("{TRANSIT}    min_source_prefix_length: 0\n"),
            format!("{TRANSIT}    min_source_prefix_length: 33\n"),
            format!("{TRANSIT}    max_source_only_ttl_seconds: 0\n"),
            format!("{TRANSIT}    max_source_only_ttl_seconds: 301\n"),
            format!("{TRANSIT}    max_source_only_active: 0\n"),
            format!("{TRANSIT}    infrastructure_prefixes: ['192.0.2.1/24']\n"),
            format!("{TRANSIT}    infrastructure_prefixes: ['2001:db8::/32']\n"),
        ] {
            assert!(config(&bad).is_err(), "accepted {bad}");
        }
        for backend in ["gobgp", "sidecar"] {
            let yaml =
                format!("backend: {backend}\nlocal_asn: 65000\nrouter_id: 192.0.2.1\n{TRANSIT}");
            assert!(crate::config::parse_yaml::<BgpConfig>(&yaml).is_err());
        }
        assert!(config(TRANSIT).unwrap().resolve_scope("missing").is_err());
    }
}
