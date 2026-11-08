//! Startup checks for configured and retained VPN scope.
use std::collections::HashSet;

use crate::config::BgpConfig;
use crate::db::RepositoryTrait;
use crate::domain::{VpnFlowSpecIdentity, VpnScopeSnapshot};
use crate::error::{PrefixdError, Result};

use super::FlowSpecAnnouncer;

fn retained_scope(
    config: &BgpConfig,
    identity: &VpnFlowSpecIdentity,
    targets: &[String],
) -> Result<()> {
    for (name, policy) in &config.vpn_scopes {
        let configured = policy.snapshot(name)?;
        if &configured.identity == identity && configured.route_targets == targets {
            return Ok(());
        }
    }
    Err(PrefixdError::Config(
        "drain outstanding VPN intent and withdrawals before removing or changing its RD/RT scope"
            .into(),
    ))
}

/// Reads retained intent before lease recovery or reconciliation can mutate a speaker.
pub async fn check_vpn_startup(
    config: &BgpConfig,
    pop: &str,
    speaker: &dyn FlowSpecAnnouncer,
    repo: &dyn RepositoryTrait,
) -> Result<()> {
    config.validate_vpn_scopes()?;
    let mut identities = HashSet::new();
    for (name, policy) in &config.vpn_scopes {
        identities.insert(policy.snapshot(name)?.identity);
    }
    for mitigation in repo.active_mitigations_for_pop(pop).await? {
        if let Some(saved) = mitigation.match_criteria.scope {
            check_named_snapshot(config, &saved)?;
            identities.insert(saved.identity);
        }
    }
    for operation in repo.pending_withdrawals(Some(pop)).await? {
        if operation.rule_kind == "flowspec" {
            let rule = operation.flowspec_rule()?;
            if let Some(identity) = rule.nlri.scope {
                retained_scope(config, &identity, &rule.route_targets)?;
                identities.insert(identity);
            }
        }
    }
    for diversion in repo.list_diversions(pop).await? {
        if diversion.status.outstanding()
            && let Some(identity) = diversion.rule.nlri.scope
        {
            retained_scope(config, &identity, &diversion.rule.route_targets)?;
            identities.insert(identity);
        }
    }
    for identity in identities {
        speaker.register_scope(Some(&identity))?;
        speaker.validate_scope(Some(&identity)).await?;
    }
    Ok(())
}

fn check_named_snapshot(config: &BgpConfig, saved: &VpnScopeSnapshot) -> Result<()> {
    match config.resolve_scope(&saved.name)? {
        Some(configured) if configured == *saved => Ok(()),
        _ => Err(PrefixdError::Config(
            "drain outstanding VPN mitigation before changing its scope snapshot".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> BgpConfig {
        crate::config::parse_yaml(
            "backend: mock\nlocal_asn: 65000\nrouter_id: 192.0.2.1\nvpn_scopes:\n  TRANSIT:\n    family: ipv4\n    rd: '44407:40'\n    route_targets: ['44407:777']\n",
        )
        .unwrap()
    }

    #[test]
    fn retained_scope_requires_the_original_wire_attributes() {
        let mut config = config();
        let saved = config.resolve_scope("TRANSIT").unwrap().unwrap();
        assert!(check_named_snapshot(&config, &saved).is_ok());
        config.vpn_scopes.get_mut("TRANSIT").unwrap().rd = "44407:41".into();
        assert!(retained_scope(&config, &saved.identity, &saved.route_targets).is_err());
        config.vpn_scopes.get_mut("TRANSIT").unwrap().rd = "44407:40".into();
        config.vpn_scopes.get_mut("TRANSIT").unwrap().route_targets = vec!["44407:778".into()];
        assert!(check_named_snapshot(&config, &saved).is_err());
        config.vpn_scopes.clear();
        assert!(check_named_snapshot(&config, &saved).is_err());
    }
}
