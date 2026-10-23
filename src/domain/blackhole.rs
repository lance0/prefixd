//! Blackhole lifecycle (ADR 027): the frozen route, the unleased pre-read and
//! the safelist recheck before every add.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::bgp::{AddOutcome, BlackholeRoute, BlackholeSpeaker, FlowSpecAnnouncer};
use crate::config::BlackholeConfig;
use crate::db::RepositoryTrait;
use crate::error::{PrefixdError, Result};

use super::{
    ActionType, LeaseKeeper, Mitigation, VerifiedSpeakerBinding, execute_withdrawal,
    request_withdrawal,
};

/// Reason recorded on the system withdrawal that replaces an add.
pub const SAFELISTED_AFTER_ADMISSION: &str = "safelisted after admission";

/// The route a blackhole was admitted with. It is stored in the row's action
/// parameters and as the `rule_json` of its withdrawal intent; repair and
/// deletion use it, never the current configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlackholeRule {
    pub prefix: ipnet::IpNet,
    pub next_hop: IpAddr,
    /// Canonical, including BLACKHOLE.
    pub communities: Vec<u32>,
    pub large_communities: Vec<[u32; 3]>,
    /// Injection owner the route was added under; `""` for an unleased route.
    pub owner: String,
}

impl BlackholeRule {
    /// Snapshot of the configured next hop and communities for `prefix`.
    pub fn from_config(config: &BlackholeConfig, prefix: ipnet::IpNet) -> Result<Self> {
        let next_hop = config.next_hop_for(prefix.addr()).ok_or_else(|| {
            PrefixdError::Config("no blackhole next hop for the victim's family".into())
        })?;
        let route = BlackholeRoute::new(
            prefix,
            next_hop,
            config.parsed_communities()?,
            config.parsed_large_communities()?,
        )?;
        Ok(Self {
            prefix: route.prefix(),
            next_hop: route.next_hop(),
            communities: route.communities().to_vec(),
            large_communities: route.large_communities().to_vec(),
            owner: String::new(),
        })
    }

    /// The route as the speaker holds it, under its recorded owner.
    pub fn route(&self) -> Result<BlackholeRoute> {
        Ok(BlackholeRoute::new(
            self.prefix,
            self.next_hop,
            self.communities.clone(),
            self.large_communities.clone(),
        )?
        .with_owner(self.owner.clone()))
    }

    /// Kind-discriminated identity, equal to the row's ownership key.
    pub fn identity(&self) -> String {
        super::blackhole_identity(&self.prefix.to_string())
    }
}

/// The frozen route of a blackhole row; a missing or mismatched route fails closed.
pub fn blackhole_rule(mitigation: &Mitigation) -> Result<BlackholeRule> {
    if mitigation.match_criteria.src_prefix.is_some() {
        return Err(PrefixdError::Internal(
            "blackhole mitigation contains a source prefix".into(),
        ));
    }
    if mitigation.action_type != ActionType::Blackhole {
        return Err(PrefixdError::Internal(
            "FlowSpec mitigation has no blackhole route".into(),
        ));
    }
    let rule = mitigation.action_params.blackhole.clone().ok_or_else(|| {
        PrefixdError::Internal(format!(
            "blackhole mitigation {} has no frozen route",
            mitigation.mitigation_id
        ))
    })?;
    if rule.identity() != super::blackhole_identity(&mitigation.match_criteria.dst_prefix) {
        return Err(PrefixdError::Internal(format!(
            "blackhole mitigation {} route does not match its prefix",
            mitigation.mitigation_id
        )));
    }
    Ok(rule)
}

/// Unleased pre-read before the first add (ADR 027 §5). The caller has found
/// no owner in the ledger, so any local route at the prefix is untracked:
/// prefixd-shaped or unrecognized, including another `path_id`. A failed read
/// is an error, never an empty speaker.
pub async fn refuse_untracked_route(
    speaker: &dyn BlackholeSpeaker,
    prefix: ipnet::IpNet,
) -> Result<()> {
    let inventory = speaker.list_blackholes().await?;
    if inventory
        .routes
        .iter()
        .chain(&inventory.expired)
        .any(|route| route.prefix() == prefix)
        || inventory
            .unrecognized
            .iter()
            .any(|row| row.prefix == prefix)
    {
        return Err(PrefixdError::Conflict(format!(
            "untracked local route for {prefix}; nothing was added"
        )));
    }
    Ok(())
}

/// What `announce_blackhole` did instead of failing.
#[derive(Debug)]
pub enum BlackholeAnnouncement {
    /// The speaker accepted the add (local RPC acceptance, not router enforcement).
    Announced(AddOutcome),
    /// The victim is safelisted now: nothing was added and the row was withdrawn.
    Withdrawn(Box<Mitigation>),
}

/// Caller holds the lifecycle mutex, runs in enforced mode and has re-read
/// `mitigation`. Rechecks the safelist immediately before the add: a failed
/// lookup sends nothing, and a now-safelisted victim gets an audited system
/// withdrawal through the immutable withdrawal path instead. The recorded
/// owner picks the add: `AddLeasedPath` under the controller's lease for an
/// owned route, `AddPath` for an unleased one. A failure never switches between them.
pub async fn announce_blackhole(
    repo: &dyn RepositoryTrait,
    announcer: &dyn FlowSpecAnnouncer,
    mitigation: &Mitigation,
    binding: Option<&VerifiedSpeakerBinding>,
    lease: Option<&LeaseKeeper>,
) -> Result<BlackholeAnnouncement> {
    let rule = blackhole_rule(mitigation)?;
    let route = rule.route()?;
    let speaker = announcer.blackhole().ok_or_else(|| {
        PrefixdError::Internal("speaker does not support blackhole routes".into())
    })?;
    if repo
        .is_safelisted(&route.prefix().addr().to_string())
        .await?
    {
        let withdrawn = withdraw_safelisted(repo, announcer, false, mitigation, binding).await?;
        return Ok(BlackholeAnnouncement::Withdrawn(Box::new(withdrawn)));
    }
    let start = std::time::Instant::now();
    let outcome = if rule.owner.is_empty() {
        speaker.announce_blackhole(&route).await?
    } else {
        let lease = lease
            .filter(|lease| lease.owner() == rule.owner)
            .ok_or_else(|| {
                PrefixdError::Config(format!(
                    "blackhole {} was added under injection owner {}, which this controller does not renew; \
                     it needs blackhole.leased and the same POP and speaker target",
                    rule.prefix, rule.owner
                ))
            })?;
        let (generation, outcome) = speaker
            .announce_leased_blackhole(&route, lease.lease_seconds())
            .await?;
        lease.observe_add(generation);
        outcome
    };
    let backend = crate::observability::metrics::backend_label(announcer.backend());
    crate::observability::metrics::ANNOUNCEMENTS_TOTAL
        .with_label_values(&[backend, "announced"])
        .inc();
    crate::observability::metrics::ANNOUNCEMENTS_LATENCY
        .with_label_values(&[backend])
        .observe(start.elapsed().as_secs_f64());
    record_announcement(repo, mitigation, &rule, outcome).await;
    Ok(BlackholeAnnouncement::Announced(outcome))
}

/// Audits what the add did at the speaker's local route. An `unchanged` re-add
/// changed nothing and is only logged: a leased re-add that keeps retrying
/// re-adds every held route each pass and would otherwise flood the audit log.
/// The route is already accepted: a failed audit write is logged, not returned.
async fn record_announcement(
    repo: &dyn RepositoryTrait,
    mitigation: &Mitigation,
    rule: &BlackholeRule,
    outcome: AddOutcome,
) {
    tracing::info!(mitigation_id = %mitigation.mitigation_id, prefix = %rule.prefix, ?outcome,
        "blackhole route accepted by the speaker");
    if outcome == AddOutcome::Unchanged {
        return;
    }
    let entry = crate::observability::AuditEntry::new(
        crate::observability::ActorType::System,
        Some("speaker".into()),
        "announce",
        Some("mitigation"),
        Some(mitigation.mitigation_id.to_string()),
        serde_json::json!({
            "prefix": rule.prefix.to_string(),
            "next_hop": rule.next_hop.to_string(),
            "owner": rule.owner,
            "outcome": outcome,
        }),
    );
    if let Err(error) = repo.insert_audit(&entry).await {
        tracing::warn!(mitigation_id = %mitigation.mitigation_id, error = %error,
            "failed to audit the blackhole add outcome");
    }
}

/// Caller holds the lifecycle mutex. Audited system withdrawal of a mitigation
/// whose destination overlaps the safelist, through the immutable withdrawal path. A
/// simulation, or any row in dry-run, is retired locally without an RPC.
pub async fn withdraw_safelisted(
    repo: &dyn RepositoryTrait,
    announcer: &dyn FlowSpecAnnouncer,
    dry_run: bool,
    mitigation: &Mitigation,
    binding: Option<&VerifiedSpeakerBinding>,
) -> Result<Mitigation> {
    let request = request_withdrawal(
        repo,
        mitigation,
        false,
        "system",
        "safelist-recheck",
        SAFELISTED_AFTER_ADMISSION.into(),
        !dry_run,
        binding,
    )
    .await?;
    tracing::warn!(mitigation_id = %mitigation.mitigation_id, operation_id = %request.operation_id,
        "mitigation destination safelisted after admission; withdrawing");
    let withdrawn = execute_withdrawal(repo, announcer, dry_run, &request, binding).await?;
    crate::observability::metrics::MITIGATIONS_WITHDRAWN
        .with_label_values(&[withdrawn.action_type.as_str(), &withdrawn.pop, "safelisted"])
        .inc();
    Ok(withdrawn)
}

/// Live blackholes at `pop` whose victim lies inside `prefix`, without a
/// pending withdrawal. A failed read is an error, never an empty result.
pub async fn covered_blackholes(
    repo: &dyn RepositoryTrait,
    pop: &str,
    prefix: ipnet::IpNet,
) -> Result<Vec<Mitigation>> {
    let pending = repo.pending_withdrawals(Some(pop)).await?;
    let now = chrono::Utc::now();
    Ok(repo
        .active_mitigations_for_pop(pop)
        .await?
        .into_iter()
        .filter(|m| {
            m.action_type == ActionType::Blackhole
                && m.pop == pop
                && m.expires_at > now
                && !pending.iter().any(|r| r.mitigation_id == m.mitigation_id)
                && m.match_criteria
                    .dst_prefix
                    .parse::<ipnet::IpNet>()
                    .is_ok_and(|victim| prefix.contains(&victim))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::ActionParams;

    #[test]
    fn frozen_route_is_stored_beside_unchanged_flowspec_params() {
        // FlowSpec rows serialize exactly as before the frozen route existed.
        for (params, json) in [
            (ActionParams::default(), "{}"),
            (
                ActionParams {
                    rate_bps: Some(8),
                    ..Default::default()
                },
                r#"{"rate_bps":8}"#,
            ),
        ] {
            assert_eq!(serde_json::to_string(&params).unwrap(), json);
            let parsed: ActionParams = serde_json::from_str(json).unwrap();
            assert!(parsed.blackhole.is_none());
        }
        let config = BlackholeConfig {
            enabled: true,
            next_hop_ipv4: Some("192.0.2.66".parse().unwrap()),
            communities: vec!["64512:1".into()],
            ..Default::default()
        };
        let rule = BlackholeRule::from_config(&config, "203.0.113.10/32".parse().unwrap()).unwrap();
        assert_eq!(
            serde_json::to_string(&rule).unwrap(),
            r#"{"prefix":"203.0.113.10/32","next_hop":"192.0.2.66","communities":[4227858433,4294902426],"large_communities":[],"owner":""}"#
        );
        // An unknown key in a persisted route fails closed.
        assert!(
            serde_json::from_str::<BlackholeRule>(
                r#"{"prefix":"203.0.113.10/32","next_hop":"192.0.2.66","communities":[],"large_communities":[],"owner":"","path_id":7}"#
            )
            .is_err()
        );
    }
}
