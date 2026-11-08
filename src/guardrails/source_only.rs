//! Explicit whole-VRF source-only authorization and source protection.

use crate::AppState;
use crate::domain::{ActionType, FlowSpecNlri, MatchCriteria, MitigationIntent};
use crate::error::PrefixdError;

/// Current source-only authorization; persisted wire scope cannot be retargeted.
pub(crate) fn source_only_policy<'a>(
    state: &'a AppState,
    criteria: &MatchCriteria,
) -> crate::error::Result<&'a crate::config::VpnScopeConfig> {
    let snapshot = criteria.scope.as_ref().ok_or_else(|| {
        PrefixdError::InvalidRequest("source-only rules require VPN scope".into())
    })?;
    let configured = state
        .settings
        .bgp
        .vpn_scopes
        .get(&snapshot.name)
        .ok_or_else(|| {
            PrefixdError::Conflict("persisted VPN scope is no longer configured".into())
        })?;
    if state.settings.bgp.resolve_scope(&snapshot.name)?.as_ref() != Some(snapshot) {
        return Err(PrefixdError::Conflict(
            "persisted VPN scope differs from configuration".into(),
        ));
    }
    if !configured.allow_source_only {
        return Err(PrefixdError::InvalidRequest(
            "VPN scope does not allow source-only rules".into(),
        ));
    }
    Ok(configured)
}

/// Reused before creation or extension; source-only exposure never inherits destination permission.
pub(crate) async fn validate_source_only(
    state: &AppState,
    intent: &MitigationIntent,
) -> crate::error::Result<()> {
    let policy = source_only_policy(state, &intent.match_criteria)?;
    let source = intent
        .match_criteria
        .src_prefix
        .as_deref()
        .ok_or_else(|| PrefixdError::InvalidRequest("source-only rules require src_prefix".into()))?
        .parse::<ipnet::IpNet>()
        .map_err(|_| PrefixdError::InvalidRequest("invalid source prefix".into()))?;
    FlowSpecNlri::from(&intent.match_criteria)
        .validate()
        .map_err(|error| PrefixdError::InvalidRequest(error.to_string()))?;
    if !matches!(intent.action_type, ActionType::Discard | ActionType::Police) {
        return Err(PrefixdError::InvalidRequest(
            "source-only rules support discard and police only".into(),
        ));
    }
    if source.prefix_len() < policy.min_source_prefix_length {
        return Err(PrefixdError::InvalidRequest(format!(
            "source-only prefix must be /{} or more specific",
            policy.min_source_prefix_length
        )));
    }
    if intent.ttl_seconds == 0 || intent.ttl_seconds > policy.max_source_only_ttl_seconds {
        return Err(PrefixdError::InvalidRequest(format!(
            "source-only TTL must be between 1 and {} seconds",
            policy.max_source_only_ttl_seconds
        )));
    }
    let overlap = |protected: ipnet::IpNet| {
        source.contains(&protected.addr()) || protected.contains(&source.addr())
    };
    for prefix in &state.settings.safelist.prefixes {
        let protected = prefix
            .parse::<ipnet::IpNet>()
            .or_else(|_| prefix.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))
            .map_err(|_| PrefixdError::Config("invalid configured safelist prefix".into()))?;
        if overlap(protected) {
            return Err(PrefixdError::GuardrailViolation(
                crate::error::GuardrailError::Safelisted {
                    ip: source.to_string(),
                },
            ));
        }
    }
    let inventory = state.inventory.read().await;
    inventory.validate()?;
    for customer in &inventory.customers {
        for prefix in &customer.prefixes {
            let protected = prefix
                .parse::<ipnet::IpNet>()
                .map_err(|_| PrefixdError::Config("invalid own prefix in inventory".into()))?;
            if overlap(protected) {
                return Err(PrefixdError::InvalidRequest(
                    "source-only prefix overlaps own address space".into(),
                ));
            }
        }
        for asset in customer.services.iter().flat_map(|service| &service.assets) {
            let address = asset
                .ip
                .parse::<std::net::IpAddr>()
                .map_err(|_| PrefixdError::Config("invalid own address in inventory".into()))?;
            if source.contains(&address) {
                return Err(PrefixdError::InvalidRequest(
                    "source-only prefix overlaps own address space".into(),
                ));
            }
        }
    }
    for prefix in &policy.infrastructure_prefixes {
        let protected = prefix
            .parse::<ipnet::IpNet>()
            .map_err(|_| PrefixdError::Config("invalid infrastructure prefix".into()))?;
        if overlap(protected) {
            return Err(PrefixdError::InvalidRequest(
                "source-only prefix overlaps infrastructure address space".into(),
            ));
        }
    }
    Ok(())
}
