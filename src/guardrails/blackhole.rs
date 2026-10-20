//! Blackhole guardrails (ADR 027). Stricter than FlowSpec and independent of the
//! FlowSpec prefix bounds, which can be widened.

use std::net::IpAddr;

use uuid::Uuid;

use crate::bgp::FlowSpecAnnouncer;
use crate::config::{
    BlackholeConfig, Inventory, OperationMode, PlaybookAction, Playbooks, Settings,
};
use crate::db::RepositoryTrait;
use crate::domain::{
    ActionType, AttackVector, BlackholeAnnouncement, BlackholeRule, LeaseKeeper, Mitigation,
    MitigationIntent, MitigationRoute, VerifiedSpeakerBinding, announce_blackhole,
    complete_local_withdrawal, find_mitigation_owner, refuse_untracked_route, request_withdrawal,
};
use crate::error::{GuardrailError, PrefixdError, Result};
use crate::observability::CreationActor;

fn refused(reason: impl Into<String>) -> PrefixdError {
    PrefixdError::GuardrailViolation(GuardrailError::InvalidBlackhole {
        reason: reason.into(),
    })
}

/// Startup refusals that need the selected speaker and the stored safelist. They
/// apply in dry-run and enforced modes alike; a disabled feature checks nothing.
pub async fn check_blackhole_startup(
    config: &BlackholeConfig,
    speaker: &dyn FlowSpecAnnouncer,
    repo: &dyn RepositoryTrait,
) -> Result<()> {
    if !config.enabled {
        return Ok(());
    }
    if speaker.blackhole().is_none() {
        return Err(PrefixdError::Config(format!(
            "blackhole.enabled requires a speaker backend with the blackhole capability; {} has none",
            speaker.backend()
        )));
    }
    // Infrastructure addresses belong in the safelist; without one nothing protects them.
    if repo.list_safelist().await?.is_empty() {
        return Err(PrefixdError::Config(
            "blackhole.enabled requires a nonempty safelist".into(),
        ));
    }
    // A leased configuration never runs unleased.
    if config.leased && !speaker.capabilities().blackhole_lease {
        return Err(PrefixdError::Config(format!(
            "blackhole.leased requires the rustbgpd injection lease, which the {} speaker does not provide",
            speaker.backend()
        )));
    }
    Ok(())
}

/// Owners recorded on this POP's live blackhole rows and pending blackhole
/// withdrawals, by identity: the ledger's leased intent.
async fn ledger_owners(repo: &dyn RepositoryTrait, pop: &str) -> Result<Vec<(String, String)>> {
    let mut owners = Vec::new();
    for mitigation in repo.active_mitigations_for_pop(pop).await? {
        // A row without a frozen route has no recorded owner; reconciliation reports it.
        if mitigation.action_type == ActionType::Blackhole
            && let Ok(rule) = crate::domain::blackhole_rule(&mitigation)
        {
            owners.push((rule.identity(), rule.owner));
        }
    }
    for request in repo.pending_withdrawals(Some(pop)).await? {
        if let Some(rule) = request.blackhole_rule() {
            owners.push((rule.identity(), rule.owner));
        }
    }
    Ok(owners)
}

/// Lease refusals at startup (ADR 027, "Owner and lease"). Leased intent that
/// is live or awaiting withdrawal needs `blackhole.leased`, or nothing renews
/// it. With the lease on, the speaker must not hold live routes under this
/// controller's owner that the ledger neither desires nor is withdrawing: that
/// is a second controller with the same POP against this speaker.
pub async fn check_lease_startup(
    config: &BlackholeConfig,
    speaker: &dyn FlowSpecAnnouncer,
    repo: &dyn RepositoryTrait,
    pop: &str,
    owner: &str,
) -> Result<()> {
    let ledger = ledger_owners(repo, pop).await?;
    let leased = ledger.iter().filter(|(_, owner)| !owner.is_empty()).count();
    if leased > 0 && !(config.enabled && config.leased) {
        return Err(PrefixdError::Config(format!(
            "{leased} leased blackhole(s) at POP {pop} are active or awaiting withdrawal; \
             keep blackhole.enabled and blackhole.leased until they are withdrawn or expire"
        )));
    }
    if !(config.enabled && config.leased && speaker.capabilities().blackhole_lease) {
        return Ok(());
    }
    let Some(blackholes) = speaker.blackhole() else {
        return Ok(());
    };
    // A failed read refuses startup; it is never an empty speaker.
    let unexplained: Vec<_> = blackholes
        .list_blackholes()
        .await?
        .routes
        .into_iter()
        .filter(|route| {
            route.owner() == owner
                && !ledger.iter().any(|(identity, recorded)| {
                    recorded == owner
                        && *identity
                            == crate::domain::blackhole_identity(&route.prefix().to_string())
                })
        })
        .map(|route| route.prefix().to_string())
        .collect();
    if !unexplained.is_empty() {
        return Err(PrefixdError::Config(format!(
            "the speaker holds routes under injection owner {owner} that this controller's ledger \
             neither desires nor is withdrawing ({}); another controller with POP {pop} may be \
             using this speaker. Stop it, or let its lease expire",
            unexplained.join(", ")
        )));
    }
    Ok(())
}

/// Playbook refusals (ADR 027 §2) at startup and on every playbook reload or
/// save. A blackhole step needs the feature enabled and a TTL within the cap. In
/// enforced mode it also needs the rustbgpd injection lease, unless the operator
/// opted into unleased detector blackholes with a nonempty
/// `blackhole.detector_sources`. Dry-run is not gated by the lease.
pub fn check_blackhole_playbooks(
    settings: &Settings,
    blackhole_lease: bool,
    playbooks: &Playbooks,
) -> Result<()> {
    let config = &settings.blackhole;
    for playbook in &playbooks.playbooks {
        for step in &playbook.steps {
            if step.action != Some(PlaybookAction::Blackhole) {
                continue;
            }
            let name = &playbook.name;
            if !config.enabled {
                return Err(PrefixdError::Config(format!(
                    "playbook {name:?} has a blackhole step, but blackhole.enabled is false"
                )));
            }
            if step.ttl_seconds > config.max_ttl_seconds {
                return Err(PrefixdError::Config(format!(
                    "playbook {name:?} blackhole step ttl_seconds {} exceeds blackhole.max_ttl_seconds {}",
                    step.ttl_seconds, config.max_ttl_seconds
                )));
            }
            if settings.mode == OperationMode::Enforced
                && !blackhole_lease
                && config.detector_sources.is_empty()
            {
                return Err(PrefixdError::Config(format!(
                    "playbook {name:?} has a blackhole step, but the speaker does not provide the rustbgpd injection lease; \
                     list the detectors in blackhole.detector_sources to run detector blackholes unleased"
                )));
            }
        }
    }
    Ok(())
}

/// Enforced detector blackholes may run without the injection lease: a
/// controller stopped for longer than a blackhole's TTL leaves it announced
/// until the controller returns or an operator withdraws it.
pub fn detector_unleased(settings: &Settings, blackhole_lease: bool) -> bool {
    settings.mode == OperationMode::Enforced
        && settings.blackhole.enabled
        && !settings.blackhole.detector_sources.is_empty()
        && !blackhole_lease
}

/// Only an allowlisted event `source` may reach a blackhole step (ADR 027 §2).
pub fn check_detector_source(config: &BlackholeConfig, source: &str) -> Result<()> {
    if config
        .detector_sources
        .iter()
        .any(|allowed| allowed == source)
    {
        return Ok(());
    }
    Err(PrefixdError::GuardrailViolation(
        GuardrailError::BlackholeSourceNotAllowed {
            source_name: source.into(),
        },
    ))
}

/// Shape, TTL, address and next-hop checks that need no inventory or database.
fn check_intent(config: &BlackholeConfig, intent: &MitigationIntent) -> Result<IpAddr> {
    if intent.action_type != ActionType::Blackhole {
        return Err(refused("intent is not a blackhole"));
    }
    // The blackhole identity hashes only the prefix, so any other term would be dropped.
    let criteria = &intent.match_criteria;
    if criteria.protocol.is_some()
        || !criteria.dst_ports.is_empty()
        || !criteria.src_ports.is_empty()
        || criteria.fragment.is_some()
        || criteria.packet_length.is_some()
    {
        return Err(refused("a blackhole matches only the host prefix"));
    }
    if intent.action_params.rate_bps.is_some() {
        return Err(refused("a blackhole takes no rate"));
    }
    if intent.ttl_seconds == 0 {
        return Err(PrefixdError::GuardrailViolation(
            GuardrailError::TtlRequired,
        ));
    }
    if intent.ttl_seconds > config.max_ttl_seconds {
        return Err(PrefixdError::GuardrailViolation(
            GuardrailError::TtlOutOfBounds {
                ttl: intent.ttl_seconds,
                min: 1,
                max: config.max_ttl_seconds,
            },
        ));
    }
    let prefix: ipnet::IpNet = intent
        .match_criteria
        .dst_prefix
        .parse()
        .map_err(|_| refused("victim must be an IPv4 /32 or IPv6 /128"))?;
    if prefix.prefix_len() != prefix.max_prefix_len() {
        return Err(refused("victim must be an IPv4 /32 or IPv6 /128"));
    }
    let victim = prefix.addr();
    let unusable = victim.is_unspecified()
        || victim.is_loopback()
        || victim.is_multicast()
        || match victim {
            IpAddr::V4(ip) => ip.is_link_local() || ip.is_broadcast(),
            IpAddr::V6(ip) => ip.is_unicast_link_local() || ip.to_ipv4_mapped().is_some(),
        };
    if unusable {
        return Err(refused(format!("{victim} is not a usable host address")));
    }
    if [config.next_hop_ipv4, config.next_hop_ipv6].contains(&Some(victim)) {
        return Err(refused(format!(
            "{victim} is a configured blackhole next hop"
        )));
    }
    if config.next_hop_for(victim).is_none() {
        return Err(refused(format!(
            "no blackhole next hop is configured for the IPv{} family",
            if victim.is_ipv4() { 4 } else { 6 }
        )));
    }
    Ok(victim)
}

/// The result of `admit_blackhole`.
#[derive(Debug)]
pub struct BlackholeAdmission {
    pub mitigation: Mitigation,
    /// Enforced intent was committed, but this request did not see the add
    /// accepted: the add failed, the safelist lookup failed, or the victim was
    /// safelisted meanwhile and the row withdrawn. Reconciliation retries a
    /// retained row. Always false in dry-run, which sends nothing.
    pub unconfirmed: bool,
}

/// Shared manual and detector blackhole admission: the caller holds the
/// lifecycle mutex and has already authorized the request (a detector source is
/// checked against `blackhole.detector_sources` before this call). The victim must be owned in inventory and not
/// safelisted; quotas are enforced inside `admit_mitigation`. A live owner, a
/// pending withdrawal or (in enforced mode) an untracked local route at the
/// prefix returns `409` before persistence. The configured next hop and
/// communities are frozen into the row. Dry-run persists the row with its audit
/// entry and sends nothing; enforced mode persists first, then rechecks the
/// safelist and adds the route.
#[allow(
    clippy::too_many_arguments,
    reason = "Detector admission records the event vector and signal group with the row"
)]
pub async fn admit_blackhole(
    repo: &dyn RepositoryTrait,
    settings: &Settings,
    inventory: &Inventory,
    mut intent: MitigationIntent,
    vector: AttackVector,
    signal_group_id: Option<Uuid>,
    actor: &CreationActor,
    announcer: &dyn FlowSpecAnnouncer,
    binding: Option<&VerifiedSpeakerBinding>,
    lease: Option<&LeaseKeeper>,
) -> Result<BlackholeAdmission> {
    let config = &settings.blackhole;
    if !config.enabled {
        return Err(PrefixdError::GuardrailViolation(
            GuardrailError::BlackholeDisabled,
        ));
    }
    let address = check_intent(config, &intent)?;
    let victim = address.to_string();
    let Some(owner) = inventory.lookup_ip(&victim) else {
        return Err(PrefixdError::GuardrailViolation(GuardrailError::NotOwned {
            ip: victim,
        }));
    };
    if repo.is_safelisted(&victim).await? {
        return Err(PrefixdError::GuardrailViolation(
            GuardrailError::Safelisted { ip: victim },
        ));
    }
    intent.customer_id = Some(owner.customer_id);
    // Canonical spelling, so stored match and victim agree with the identity hash.
    let prefix = ipnet::IpNet::from(address);
    intent.match_criteria.dst_prefix = prefix.to_string();
    let route = MitigationRoute::new(
        intent.action_type,
        &intent.match_criteria,
        &intent.action_params,
    );
    let scope_hash = intent.match_criteria.scope_hash_for(ActionType::Blackhole);
    if find_mitigation_owner(repo, &intent.pop, &route, &scope_hash)
        .await?
        .is_some()
    {
        return Err(PrefixdError::Conflict(
            "blackhole route already has an active owner".into(),
        ));
    }
    let mut rule = BlackholeRule::from_config(config, prefix)?;
    let enforced = settings.mode == OperationMode::Enforced;
    if enforced {
        let speaker = announcer.blackhole().ok_or_else(|| {
            PrefixdError::Config(format!(
                "{} speaker has no blackhole capability",
                announcer.backend()
            ))
        })?;
        if config.leased {
            // The daemon checks ownership atomically in the add, so no pre-read.
            rule.owner = lease
                .ok_or_else(|| {
                    PrefixdError::Config("blackhole.leased needs the controller's lease".into())
                })?
                .owner()
                .into();
        } else {
            refuse_untracked_route(speaker, prefix).await?;
        }
    }
    intent.action_params.blackhole = Some(rule);
    let mut mitigation = Mitigation::from_intent(intent, victim, vector);
    mitigation.signal_group_id = signal_group_id;
    mitigation.activate();
    mitigation.origin_mode = Some(settings.mode);
    repo.admit_mitigation(&mitigation, &settings.quotas, config, actor)
        .await?;
    if !enforced {
        return Ok(BlackholeAdmission {
            mitigation,
            unconfirmed: false,
        });
    }
    Ok(
        match announce_blackhole(repo, announcer, &mitigation, binding, lease).await {
            Ok(BlackholeAnnouncement::Announced) => BlackholeAdmission {
                mitigation,
                unconfirmed: false,
            },
            Ok(BlackholeAnnouncement::Withdrawn(mitigation)) => BlackholeAdmission {
                mitigation: *mitigation,
                unconfirmed: true,
            },
            // Another owner, or none, holds the key: nothing was added. Retire the
            // row locally with an audit entry and no delete; never retry unleased.
            Err(PrefixdError::InjectionOwnerMismatch(reason)) => {
                tracing::warn!(mitigation_id = %mitigation.mitigation_id, reason,
                    "untracked local route at the blackhole prefix; retiring the new row");
                let request = request_withdrawal(
                    repo,
                    &mitigation,
                    false,
                    "system",
                    "admission",
                    UNTRACKED_AT_ADMISSION.into(),
                    false,
                    binding,
                )
                .await?;
                complete_local_withdrawal(repo, &request, binding).await?;
                return Err(PrefixdError::Conflict(format!(
                    "untracked local route for {prefix}; nothing was added"
                )));
            }
            Err(error) => {
                tracing::warn!(mitigation_id = %mitigation.mitigation_id, error = %error,
                    "blackhole intent retained after unconfirmed announcement");
                BlackholeAdmission {
                    mitigation,
                    unconfirmed: true,
                }
            }
        },
    )
}

/// Audit reason for a new row retired because the speaker refused its add.
pub const UNTRACKED_AT_ADMISSION: &str = "untracked local route at admission";

/// Extends a blackhole to at most `now + max_ttl_seconds`, whatever TTL the
/// extending event asks for.
pub fn extend_blackhole(
    config: &BlackholeConfig,
    mitigation: &mut Mitigation,
    ttl_seconds: u32,
    event_id: Uuid,
) -> Result<()> {
    if mitigation.action_type != ActionType::Blackhole {
        return Err(refused("mitigation is not a blackhole"));
    }
    if ttl_seconds == 0 {
        return Err(PrefixdError::GuardrailViolation(
            GuardrailError::TtlRequired,
        ));
    }
    mitigation.extend_ttl(ttl_seconds.min(config.max_ttl_seconds), event_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::{BlackholeSpeaker, FaultyBlackholes, InjectionLeases};
    use crate::config::{Customer, PolicyProfile};
    use crate::db::MockRepository;
    use crate::domain::{ActionParams, MatchCriteria, MitigationStatus};
    use std::sync::atomic::Ordering::SeqCst;

    fn settings() -> Settings {
        let settings: Settings = crate::config::parse_yaml(
            "pop: pop-a\nhttp: {listen: '127.0.0.1:0', auth: {mode: none}}\n\
             bgp: {backend: mock, local_asn: 65010, router_id: 192.0.2.1}\n\
             guardrails: {}\nquotas: {}\ntimers: {}\nobservability: {}\n\
             storage: {connection_string: 'postgres://unused'}\n\
             blackhole: {enabled: true, next_hop_ipv4: 192.0.2.66, next_hop_ipv6: '2001:db8:ffff::66'}\n",
        )
        .unwrap();
        settings.blackhole.validate().unwrap();
        settings
    }

    fn inventory(prefixes: &[&str]) -> Inventory {
        Inventory::new(vec![Customer {
            customer_id: "customer-a".into(),
            name: "Customer A".into(),
            prefixes: prefixes.iter().map(|prefix| prefix.to_string()).collect(),
            policy_profile: PolicyProfile::Normal,
            services: vec![],
        }])
    }

    fn intent(prefix: &str) -> MitigationIntent {
        MitigationIntent {
            event_id: Uuid::new_v4(),
            customer_id: None,
            service_id: None,
            pop: "pop-a".into(),
            match_criteria: MatchCriteria {
                dst_prefix: prefix.into(),
                ..Default::default()
            },
            action_type: ActionType::Blackhole,
            action_params: ActionParams::default(),
            ttl_seconds: 600,
            reason: "manual blackhole".into(),
        }
    }

    fn actor() -> CreationActor {
        CreationActor::Operator("admin".into())
    }

    async fn admit(
        repo: &MockRepository,
        settings: &Settings,
        inventory: &Inventory,
        intent: MitigationIntent,
    ) -> Result<Mitigation> {
        let speaker = crate::bgp::MockAnnouncer::new();
        admit_blackhole(
            repo,
            settings,
            inventory,
            intent,
            AttackVector::Unknown,
            None,
            &actor(),
            &speaker,
            None,
            None,
        )
        .await
        .map(|admission| admission.mitigation)
    }

    fn reason(error: PrefixdError) -> String {
        match error {
            PrefixdError::GuardrailViolation(GuardrailError::InvalidBlackhole { reason }) => reason,
            error => panic!("expected a blackhole refusal, got {error}"),
        }
    }

    /// The rejected intent saves no row or audit entry; the admitted intent, with
    /// only the rejected condition removed, then succeeds (negative control).
    async fn rejected_then_admitted(
        rejected: (&Settings, &Inventory, MitigationIntent),
        admitted: (&Settings, &Inventory, MitigationIntent),
    ) -> PrefixdError {
        let repo = MockRepository::new();
        let (settings, inventory, intent) = rejected;
        let error = admit(&repo, settings, inventory, intent).await.unwrap_err();
        assert_eq!(repo.count_active_global().await.unwrap(), 0, "{error}");
        assert!(
            repo.list_audit(&crate::db::ListParams {
                limit: 100,
                ..Default::default()
            })
            .await
            .unwrap()
            .is_empty()
        );
        let (settings, inventory, intent) = admitted;
        admit(&repo, settings, inventory, intent).await.unwrap();
        error
    }

    #[tokio::test]
    async fn dry_run_persists_an_audited_row_without_a_speaker() {
        let repo = MockRepository::new();
        let owned = inventory(&["203.0.113.0/24", "2001:db8::/48"]);
        for (prefix, canonical) in [
            ("203.0.113.10/32", "203.0.113.10/32"),
            ("2001:DB8:0::10/128", "2001:db8::10/128"),
        ] {
            // Admission takes no speaker, so it cannot send an RPC.
            let mitigation = admit(&repo, &settings(), &owned, intent(prefix))
                .await
                .unwrap();
            let stored = repo
                .get_mitigation(mitigation.mitigation_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stored.action_type, ActionType::Blackhole);
            assert_eq!(stored.status, MitigationStatus::Active);
            assert_eq!(stored.origin_mode, Some(OperationMode::DryRun));
            assert_eq!(stored.match_criteria.dst_prefix, canonical);
            assert_eq!(stored.customer_id.as_deref(), Some("customer-a"));
            assert_eq!(
                stored.scope_hash,
                stored.match_criteria.scope_hash_for(ActionType::Blackhole)
            );
        }
        let audit = repo
            .list_audit(&crate::db::ListParams {
                limit: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(audit.len(), 2);
    }

    fn enforced() -> Settings {
        let mut settings = settings();
        settings.mode = OperationMode::Enforced;
        settings.blackhole.communities = vec!["64512:1".into()];
        settings
    }

    async fn admit_enforced(
        repo: &MockRepository,
        speaker: &FaultyBlackholes,
        intent: MitigationIntent,
    ) -> Result<BlackholeAdmission> {
        let owned = inventory(&["203.0.113.0/24", "2001:db8::/48"]);
        admit_blackhole(
            repo,
            &enforced(),
            &owned,
            intent,
            AttackVector::Unknown,
            None,
            &actor(),
            speaker,
            None,
            None,
        )
        .await
    }

    #[tokio::test]
    async fn enforced_admission_persists_then_adds_the_frozen_route() {
        let _metrics = crate::observability::metrics::METRICS_TEST_LOCK
            .lock()
            .await;
        let repo = MockRepository::new();
        let speaker = FaultyBlackholes::default();
        for (prefix, next_hop) in [
            ("203.0.113.10/32", "192.0.2.66"),
            ("2001:db8::10/128", "2001:db8:ffff::66"),
        ] {
            let admission = admit_enforced(&repo, &speaker, intent(prefix))
                .await
                .unwrap();
            assert!(!admission.unconfirmed);
            let stored = repo
                .get_mitigation(admission.mitigation.mitigation_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stored.origin_mode, Some(OperationMode::Enforced));
            let frozen = crate::domain::blackhole_rule(&stored).unwrap();
            assert_eq!(frozen.next_hop.to_string(), next_hop);
            assert_eq!(
                frozen.communities,
                [(64512 << 16) | 1, crate::bgp::BLACKHOLE_COMMUNITY]
            );
            assert_eq!(frozen.owner, "");
            assert!(speaker.routes().await.contains(&frozen.route().unwrap()));
        }
        assert_eq!(speaker.adds.load(SeqCst), 2);
        // A failed add keeps the desired row for reconciliation and reports it unconfirmed.
        speaker.fail_adds.store(true, SeqCst);
        let admission = admit_enforced(&repo, &speaker, intent("203.0.113.11/32"))
            .await
            .unwrap();
        assert!(admission.unconfirmed);
        assert!(
            repo.get_mitigation(admission.mitigation.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .is_active()
        );
        assert_eq!(speaker.routes().await.len(), 2);
    }

    #[tokio::test]
    async fn untracked_local_route_returns_409_before_persistence_or_add() {
        use crate::bgp::{BlackholeRoute, BlackholeSpeaker, UnrecognizedRoute};
        let _metrics = crate::observability::metrics::METRICS_TEST_LOCK
            .lock()
            .await;
        let prefix: ipnet::IpNet = "203.0.113.10/32".parse().unwrap();
        for case in [
            "recognized",
            "nonzero path_id",
            "unexpected path attributes",
        ] {
            let repo = MockRepository::new();
            let speaker = FaultyBlackholes::default();
            if case == "recognized" {
                let route =
                    BlackholeRoute::new(prefix, "192.0.2.99".parse().unwrap(), vec![], vec![])
                        .unwrap();
                speaker.inner.announce_blackhole(&route).await.unwrap();
            } else {
                speaker
                    .unrecognized
                    .lock()
                    .unwrap()
                    .push(UnrecognizedRoute {
                        prefix,
                        reason: case,
                    });
            }
            let error = admit_enforced(&repo, &speaker, intent("203.0.113.10/32"))
                .await
                .unwrap_err();
            assert!(
                matches!(error, PrefixdError::Conflict(_)),
                "{case}: {error}"
            );
            assert_eq!(error.status_code(), axum::http::StatusCode::CONFLICT);
            assert_eq!(repo.count_active_global().await.unwrap(), 0, "{case}");
            assert_eq!(speaker.adds.load(SeqCst), 0, "{case}");
            // Negative control: another prefix is admitted and added.
            admit_enforced(&repo, &speaker, intent("203.0.113.12/32"))
                .await
                .unwrap();
            assert_eq!(speaker.adds.load(SeqCst), 1, "{case}");
        }
        // A failed pre-read is never an empty speaker: nothing persisted or added.
        let repo = MockRepository::new();
        let speaker = FaultyBlackholes::default();
        speaker.fail_reads.store(true, SeqCst);
        assert!(
            admit_enforced(&repo, &speaker, intent("203.0.113.10/32"))
                .await
                .is_err()
        );
        assert_eq!(repo.count_active_global().await.unwrap(), 0);
        assert_eq!(speaker.adds.load(SeqCst), 0);
    }

    #[tokio::test]
    async fn live_owner_and_pending_withdrawal_return_409_without_add() {
        let _metrics = crate::observability::metrics::METRICS_TEST_LOCK
            .lock()
            .await;
        let repo = MockRepository::new();
        let speaker = FaultyBlackholes::default();
        let first = admit_enforced(&repo, &speaker, intent("203.0.113.10/32"))
            .await
            .unwrap()
            .mitigation;
        let error = admit_enforced(&repo, &speaker, intent("203.0.113.10/32"))
            .await
            .unwrap_err();
        assert!(matches!(error, PrefixdError::Conflict(_)), "{error}");
        assert!(error.to_string().contains("active owner"), "{error}");
        speaker.withdraw_fault.store(1, SeqCst);
        let request = crate::domain::request_withdrawal(
            &repo,
            &first,
            false,
            "operator",
            "alice",
            "test".into(),
            true,
            None,
        )
        .await
        .unwrap();
        assert!(
            crate::domain::execute_withdrawal(&repo, &speaker, false, &request, None)
                .await
                .is_err()
        );
        let error = admit_enforced(&repo, &speaker, intent("203.0.113.10/32"))
            .await
            .unwrap_err();
        assert!(matches!(error, PrefixdError::Conflict(_)), "{error}");
        assert!(error.to_string().contains("pending withdrawal"), "{error}");
        assert_eq!(speaker.adds.load(SeqCst), 1);
        assert_eq!(repo.count_active_global().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn disabled_feature_refuses() {
        let owned = inventory(&["203.0.113.0/24"]);
        let mut disabled = settings();
        disabled.blackhole.enabled = false;
        let error = rejected_then_admitted(
            (&disabled, &owned, intent("203.0.113.10/32")),
            (&settings(), &owned, intent("203.0.113.10/32")),
        )
        .await;
        assert!(matches!(
            error,
            PrefixdError::GuardrailViolation(GuardrailError::BlackholeDisabled)
        ));
    }

    #[tokio::test]
    async fn ttl_is_required_and_capped_on_creation() {
        let owned = inventory(&["203.0.113.0/24"]);
        let settings = settings();
        let with_ttl = |ttl| MitigationIntent {
            ttl_seconds: ttl,
            ..intent("203.0.113.10/32")
        };
        let error = rejected_then_admitted(
            (&settings, &owned, with_ttl(0)),
            (&settings, &owned, with_ttl(1)),
        )
        .await;
        assert!(matches!(
            error,
            PrefixdError::GuardrailViolation(GuardrailError::TtlRequired)
        ));
        let error = rejected_then_admitted(
            (&settings, &owned, with_ttl(3601)),
            (&settings, &owned, with_ttl(3600)),
        )
        .await;
        assert!(matches!(
            error,
            PrefixdError::GuardrailViolation(GuardrailError::TtlOutOfBounds {
                ttl: 3601,
                min: 1,
                max: 3600
            })
        ));
        // The FlowSpec TTL bounds (max 1800 by default) do not cap a blackhole.
        assert_eq!(settings.timers.max_ttl_seconds, 1800);
    }

    #[tokio::test]
    async fn only_a_bare_host_route_is_accepted() {
        let owned = inventory(&["203.0.113.0/24"]);
        let settings = settings();
        let base = || intent("203.0.113.10/32");
        let mut flowspec = base();
        flowspec.action_type = ActionType::Discard;
        let mut protocol = base();
        protocol.match_criteria.protocol = Some(17);
        let mut ports = base();
        ports.match_criteria.dst_ports = vec![53];
        let mut src_ports = base();
        src_ports.match_criteria.src_ports = vec![123];
        let mut fragment = base();
        fragment.match_criteria.fragment = Some(crate::domain::FragmentMatch::NonFirst);
        let mut packet_length = base();
        packet_length.match_criteria.packet_length =
            Some(crate::domain::PacketLengthRange { min: 1, max: 1500 });
        let mut rate = base();
        rate.action_params.rate_bps = Some(1_000_000);
        for rejected in [
            flowspec,
            protocol,
            ports,
            src_ports,
            fragment,
            packet_length,
            rate,
            intent("203.0.113.0/24"),
            intent("203.0.113.10/31"),
            intent("not-an-address"),
        ] {
            let error =
                rejected_then_admitted((&settings, &owned, rejected), (&settings, &owned, base()))
                    .await;
            reason(error);
        }
    }

    #[tokio::test]
    async fn victim_must_be_a_usable_host_address() {
        // Inventory owns everything, so only the address check can refuse.
        let everything = inventory(&["0.0.0.0/0", "::/0"]);
        let settings = settings();
        for (victim, refusal) in [
            ("0.0.0.0/32", "usable host address"),
            ("127.0.0.1/32", "usable host address"),
            ("224.0.0.1/32", "usable host address"),
            ("169.254.1.1/32", "usable host address"),
            ("255.255.255.255/32", "usable host address"),
            ("::/128", "usable host address"),
            ("::1/128", "usable host address"),
            ("ff02::1/128", "usable host address"),
            ("fe80::1/128", "usable host address"),
            ("::ffff:203.0.113.10/128", "usable host address"),
            ("192.0.2.66/32", "configured blackhole next hop"),
            ("2001:db8:ffff::66/128", "configured blackhole next hop"),
        ] {
            let error = rejected_then_admitted(
                (&settings, &everything, intent(victim)),
                (&settings, &everything, intent("203.0.113.10/32")),
            )
            .await;
            assert!(reason(error).contains(refusal), "{victim}");
        }
    }

    #[tokio::test]
    async fn victim_family_needs_a_configured_next_hop() {
        let owned = inventory(&["2001:db8::/48"]);
        let mut ipv4_only = settings();
        ipv4_only.blackhole.next_hop_ipv6 = None;
        let error = rejected_then_admitted(
            (&ipv4_only, &owned, intent("2001:db8::10/128")),
            (&settings(), &owned, intent("2001:db8::10/128")),
        )
        .await;
        assert!(reason(error).contains("IPv6"));
    }

    #[tokio::test]
    async fn victim_must_be_owned_even_for_manual_requests() {
        let settings = settings();
        let error = rejected_then_admitted(
            (
                &settings,
                &inventory(&["198.51.100.0/24"]),
                intent("203.0.113.10/32"),
            ),
            (
                &settings,
                &inventory(&["203.0.113.0/24"]),
                intent("203.0.113.10/32"),
            ),
        )
        .await;
        assert!(matches!(
            error,
            PrefixdError::GuardrailViolation(GuardrailError::NotOwned { .. })
        ));
    }

    #[tokio::test]
    async fn safelisted_victim_is_refused() {
        let owned = inventory(&["203.0.113.0/24"]);
        let settings = settings();
        let repo = MockRepository::new();
        repo.insert_safelist("203.0.113.0/28", "test", None)
            .await
            .unwrap();
        let error = admit(&repo, &settings, &owned, intent("203.0.113.10/32"))
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            PrefixdError::GuardrailViolation(GuardrailError::Safelisted { .. })
        ));
        assert_eq!(repo.count_active_global().await.unwrap(), 0);
        // Negative control: outside the safelisted range, and after removal.
        admit(&repo, &settings, &owned, intent("203.0.113.20/32"))
            .await
            .unwrap();
        repo.remove_safelist("203.0.113.0/28").await.unwrap();
        admit(&repo, &settings, &owned, intent("203.0.113.10/32"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn blackhole_quotas_are_separate_from_flowspec() {
        let owned = inventory(&["203.0.113.0/24"]);
        for (quota_type, per_pop, global) in [("blackhole_pop", 1, 5), ("blackhole_global", 5, 1)] {
            let mut settings = settings();
            settings.blackhole.max_active_per_pop = per_pop;
            settings.blackhole.max_active_global = global;
            // A full customer, POP and global FlowSpec budget must still allow
            // a blackhole. Before quota separation this fails at customer.
            settings.quotas.max_active_per_customer = 1;
            settings.quotas.max_active_per_pop = 1;
            settings.quotas.max_active_global = 1;
            let repo = MockRepository::new();
            // A FlowSpec row never uses a blackhole slot.
            let mut flowspec = Mitigation::from_intent(
                MitigationIntent {
                    action_type: ActionType::Discard,
                    match_criteria: MatchCriteria {
                        dst_prefix: "203.0.113.9/32".into(),
                        protocol: Some(17),
                        dst_ports: vec![53],
                        ..Default::default()
                    },
                    ..intent("203.0.113.9/32")
                },
                "203.0.113.9".into(),
                AttackVector::UdpFlood,
            );
            flowspec.customer_id = Some("customer-a".into());
            flowspec.activate();
            repo.admit_mitigation(&flowspec, &settings.quotas, &settings.blackhole, &actor())
                .await
                .unwrap();
            admit(&repo, &settings, &owned, intent("203.0.113.10/32"))
                .await
                .unwrap();
            // Another POP has its own per-POP slot but shares the global one.
            let mut other_settings = settings.clone();
            other_settings.pop = "pop-b".into();
            let other_pop = MitigationIntent {
                pop: "pop-b".into(),
                ..intent("203.0.113.11/32")
            };
            let result = admit(&repo, &other_settings, &owned, other_pop).await;
            assert_eq!(result.is_ok(), quota_type == "blackhole_pop", "{result:?}");
            let error = admit(&repo, &settings, &owned, intent("203.0.113.12/32"))
                .await
                .unwrap_err();
            match error {
                PrefixdError::GuardrailViolation(GuardrailError::QuotaExceeded {
                    quota_type: observed,
                    current: 1,
                    max: 1,
                }) => assert_eq!(observed, quota_type),
                error => panic!("expected {quota_type}, got {error}"),
            }
            // Negative control: another FlowSpec rule still hits its own full
            // budget, while a released FlowSpec slot ignores the blackholes.
            let mut second = flowspec.clone();
            second.mitigation_id = Uuid::new_v4();
            second.match_criteria.dst_prefix = "203.0.113.8/32".into();
            second.scope_hash = second.match_criteria.compute_scope_hash();
            assert!(matches!(
                repo.admit_mitigation(&second, &settings.quotas, &settings.blackhole, &actor())
                    .await,
                Err(PrefixdError::GuardrailViolation(
                    GuardrailError::QuotaExceeded { .. }
                ))
            ));
            flowspec.withdraw(Some("release FlowSpec slot".into()));
            repo.update_mitigation(&flowspec).await.unwrap();
            repo.admit_mitigation(&second, &settings.quotas, &settings.blackhole, &actor())
                .await
                .unwrap();
        }
    }

    #[test]
    fn extension_is_capped_at_now_plus_max_ttl() {
        use chrono::{Duration, Utc};
        let config = settings().blackhole;
        let mut mitigation = Mitigation::from_intent(
            intent("203.0.113.10/32"),
            "203.0.113.10".into(),
            AttackVector::Unknown,
        );
        let event = Uuid::new_v4();
        extend_blackhole(&config, &mut mitigation, 86_400, event).unwrap();
        let cap = Utc::now() + Duration::seconds(3600);
        assert!(mitigation.expires_at <= cap);
        assert!(mitigation.expires_at > cap - Duration::seconds(5));
        assert_eq!(mitigation.last_event_id, event);
        // Negative control: a TTL inside the cap is honored as asked.
        let mut short = mitigation.clone();
        short.expires_at = Utc::now();
        extend_blackhole(&config, &mut short, 60, event).unwrap();
        assert!(short.expires_at <= Utc::now() + Duration::seconds(60));
        assert!(short.expires_at > Utc::now() + Duration::seconds(55));
        assert!(matches!(
            extend_blackhole(&config, &mut mitigation, 0, event),
            Err(PrefixdError::GuardrailViolation(
                GuardrailError::TtlRequired
            ))
        ));
        let mut flowspec = mitigation.clone();
        flowspec.action_type = ActionType::Discard;
        reason(extend_blackhole(&config, &mut flowspec, 60, event).unwrap_err());
    }

    #[tokio::test]
    async fn startup_refuses_without_capability_or_safelist() {
        let config = settings().blackhole;
        let mock = crate::bgp::MockAnnouncer::new();
        let gobgp = crate::bgp::GoBgpAnnouncer::new("http://127.0.0.1:1".into());
        let empty = MockRepository::new();
        let safelisted = MockRepository::new();
        safelisted
            .insert_safelist("192.0.2.0/24", "config", None)
            .await
            .unwrap();
        check_blackhole_startup(&config, &mock, &safelisted)
            .await
            .unwrap();
        let error = check_blackhole_startup(&config, &gobgp, &safelisted)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("blackhole capability") && error.contains("gobgp"),
            "{error}"
        );
        let error = check_blackhole_startup(&config, &mock, &empty)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("nonempty safelist"), "{error}");
        // Disabled checks nothing, so FlowSpec-only deployments are unaffected.
        check_blackhole_startup(&BlackholeConfig::default(), &gobgp, &empty)
            .await
            .unwrap();
        // No speaker provides the injection lease yet, so leased never runs unleased.
        let leased = BlackholeConfig {
            leased: true,
            ..config
        };
        let error = check_blackhole_startup(&leased, &mock, &safelisted)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("rustbgpd injection lease"), "{error}");
    }

    fn blackhole_playbooks(ttl_seconds: u32) -> Playbooks {
        crate::config::parse_yaml(&format!(
            "playbooks:\n  - name: rtbh\n    match: {{vector: udp_flood}}\n    steps:\n      - {{action: blackhole, ttl_seconds: {ttl_seconds}}}\n"
        ))
        .unwrap()
    }

    /// The enforced lease gate (startup, reload and save share this check).
    #[test]
    fn enforced_blackhole_steps_need_the_lease_or_an_unleased_opt_in() {
        let playbooks = blackhole_playbooks(1800);
        let dry_run = settings();
        let mut enforced = enforced();
        // Dry-run is not gated by the lease.
        check_blackhole_playbooks(&dry_run, false, &playbooks).unwrap();
        assert!(!detector_unleased(&dry_run, false));
        // Enforced without the lease and without an opt-in is refused, naming the lease.
        let error = check_blackhole_playbooks(&enforced, false, &playbooks)
            .unwrap_err()
            .to_string();
        assert!(error.contains("rustbgpd injection lease"), "{error}");
        assert!(!detector_unleased(&enforced, false));
        // The lease alone passes, and so does the unleased opt-in, which is reported.
        check_blackhole_playbooks(&enforced, true, &playbooks).unwrap();
        enforced.blackhole.detector_sources = vec!["fastnetmon".into()];
        check_blackhole_playbooks(&enforced, false, &playbooks).unwrap();
        assert!(detector_unleased(&enforced, false));
        assert!(!detector_unleased(&enforced, true));
        // A disabled feature refuses the step in either mode.
        for mut settings in [dry_run, enforced.clone()] {
            settings.blackhole.enabled = false;
            let error = check_blackhole_playbooks(&settings, true, &playbooks)
                .unwrap_err()
                .to_string();
            assert!(error.contains("blackhole.enabled is false"), "{error}");
            assert!(!detector_unleased(&settings, false));
        }
        // The step TTL is bounded by the cap.
        let error = check_blackhole_playbooks(&enforced, true, &blackhole_playbooks(3601))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("exceeds blackhole.max_ttl_seconds 3600"),
            "{error}"
        );
        // FlowSpec-only playbooks are unaffected.
        let flowspec: Playbooks = crate::config::parse_yaml(
            "playbooks:\n  - name: d\n    match: {vector: udp_flood}\n    steps:\n      - {action: discard, ttl_seconds: 60}\n",
        )
        .unwrap();
        let mut bare = enforced;
        bare.blackhole = BlackholeConfig::default();
        check_blackhole_playbooks(&bare, false, &flowspec).unwrap();
    }

    #[test]
    fn only_allowlisted_detector_sources_reach_a_blackhole() {
        let mut config = settings().blackhole;
        assert!(matches!(
            check_detector_source(&config, "fastnetmon"),
            Err(PrefixdError::GuardrailViolation(
                GuardrailError::BlackholeSourceNotAllowed { .. }
            ))
        ));
        config.detector_sources = vec!["fastnetmon".into()];
        check_detector_source(&config, "fastnetmon").unwrap();
        for refused in ["dashboard", "FastNetMon", "fastnetmon ", ""] {
            assert!(
                check_detector_source(&config, refused).is_err(),
                "{refused}"
            );
        }
    }

    /// The leased seam: a route recorded under an injection owner is never sent
    /// through the unleased add.
    #[tokio::test]
    async fn a_leased_route_never_falls_back_to_an_unleased_add() {
        let _metrics = crate::observability::metrics::METRICS_TEST_LOCK
            .lock()
            .await;
        let repo = MockRepository::new();
        let speaker = FaultyBlackholes::default();
        let mut mitigation = admit_enforced(&repo, &speaker, intent("203.0.113.10/32"))
            .await
            .unwrap()
            .mitigation;
        assert_eq!(speaker.adds.load(SeqCst), 1);
        mitigation.action_params.blackhole.as_mut().unwrap().owner =
            "prefixd.pop-a.0123456789abcdef".into();
        let error = announce_blackhole(&repo, &speaker, &mitigation, None, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("leased"), "{error}");
        assert_eq!(speaker.adds.load(SeqCst), 1);
        assert_eq!(speaker.leased_adds.load(SeqCst), 0);
    }

    const OWNER: &str = "prefixd.pop-a.0123456789abcdef";

    async fn admit_leased(
        repo: &MockRepository,
        speaker: &FaultyBlackholes,
        lease: Option<&LeaseKeeper>,
        prefix: &str,
    ) -> Result<BlackholeAdmission> {
        let mut settings = enforced();
        settings.blackhole.leased = true;
        admit_blackhole(
            repo,
            &settings,
            &inventory(&["203.0.113.0/24", "2001:db8::/48"]),
            intent(prefix),
            AttackVector::Unknown,
            None,
            &actor(),
            speaker,
            None,
            lease,
        )
        .await
    }

    /// Leased admission snapshots the owner, adds only through `AddLeasedPath`
    /// and adopts the returned generation; a failed leased add stays
    /// unconfirmed and is never retried through `AddPath`.
    #[tokio::test]
    async fn leased_admission_records_the_owner_and_never_falls_back() {
        let _metrics = crate::observability::metrics::METRICS_TEST_LOCK
            .lock()
            .await;
        let repo = MockRepository::new();
        let speaker = FaultyBlackholes::default();
        let lease = LeaseKeeper::new(OWNER.into(), 60);
        let admission = admit_leased(&repo, &speaker, Some(&lease), "203.0.113.10/32")
            .await
            .unwrap();
        assert!(!admission.unconfirmed);
        let rule = crate::domain::blackhole_rule(&admission.mitigation).unwrap();
        assert_eq!(rule.owner, OWNER);
        assert!(speaker.routes().await.contains(&rule.route().unwrap()));
        assert_eq!(speaker.routes().await[0].owner(), OWNER);
        assert_eq!(
            (speaker.adds.load(SeqCst), speaker.leased_adds.load(SeqCst)),
            (0, 1)
        );
        assert!(lease.generation().is_some());
        assert_eq!(*speaker.lease_seconds.lock().unwrap(), [60]);

        // An older daemon answers UNIMPLEMENTED: nothing is installed, the row
        // stays unconfirmed, and no plain AddPath is sent.
        speaker.fail_adds.store(true, SeqCst);
        let admission = admit_leased(&repo, &speaker, Some(&lease), "203.0.113.11/32")
            .await
            .unwrap();
        assert!(admission.unconfirmed);
        assert!(
            repo.get_mitigation(admission.mitigation.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .is_active()
        );
        assert_eq!(
            (speaker.adds.load(SeqCst), speaker.leased_adds.load(SeqCst)),
            (0, 2)
        );
        assert_eq!(speaker.routes().await.len(), 1);
        speaker.fail_adds.store(false, SeqCst);

        // The lease is configured but this controller has none: refuse, send nothing.
        let error = admit_leased(&repo, &speaker, None, "203.0.113.12/32")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("lease"), "{error}");
        assert_eq!(speaker.leased_adds.load(SeqCst), 2);

        // Every delete passes the owner recorded in rule_json, never the configuration.
        let request = crate::domain::request_withdrawal(
            &repo,
            &repo
                .get_mitigation(admission.mitigation.mitigation_id)
                .await
                .unwrap()
                .unwrap(),
            false,
            "operator",
            "alice",
            "attack over".into(),
            true,
            None,
        )
        .await
        .unwrap();
        assert_eq!(request.blackhole_rule().unwrap().owner, OWNER);
        crate::domain::execute_withdrawal(&repo, &speaker, false, &request, None)
            .await
            .unwrap();
        assert_eq!(*speaker.delete_owners.lock().unwrap(), [OWNER]);
    }

    /// A key another owner, or no owner, holds refuses the leased add. The new
    /// row is retired locally with an audit entry and no delete, and the
    /// request gets the untracked-route 409.
    #[tokio::test]
    async fn leased_add_on_an_untracked_key_retires_the_row_without_a_delete() {
        let _metrics = crate::observability::metrics::METRICS_TEST_LOCK
            .lock()
            .await;
        let repo = MockRepository::new();
        let speaker = FaultyBlackholes::default();
        let lease = LeaseKeeper::new(OWNER.into(), 60);
        let untracked = crate::bgp::BlackholeRoute::new(
            "203.0.113.20/32".parse().unwrap(),
            "192.0.2.99".parse().unwrap(),
            vec![],
            vec![],
        )
        .unwrap();
        speaker.inner.announce_blackhole(&untracked).await.unwrap();
        let error = admit_leased(&repo, &speaker, Some(&lease), "203.0.113.20/32")
            .await
            .unwrap_err();
        assert!(matches!(error, PrefixdError::Conflict(_)), "{error}");
        assert_eq!(error.status_code(), axum::http::StatusCode::CONFLICT);
        assert_eq!(repo.count_active_global().await.unwrap(), 0);
        let retired = repo
            .list_mitigations_by_ip("203.0.113.20", 10)
            .await
            .unwrap();
        assert_eq!(retired.len(), 1);
        assert_eq!(
            retired[0].status,
            crate::domain::MitigationStatus::Withdrawn
        );
        assert!(repo.pending_withdrawals(None).await.unwrap().is_empty());
        let audit = repo
            .list_audit(&crate::db::ListParams {
                limit: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(
            audit.iter().any(|entry| entry.action == "withdraw"
                && entry.details["reason"] == UNTRACKED_AT_ADMISSION)
        );
        // The untracked route is untouched, and nothing was retried unleased.
        assert_eq!(speaker.routes().await, [untracked]);
        assert_eq!(speaker.deletes.load(SeqCst), 0);
        assert_eq!(speaker.adds.load(SeqCst), 0);
    }

    /// Startup refuses to drop the lease under outstanding leased intent, and
    /// refuses routes under this owner that the ledger cannot explain.
    #[tokio::test]
    async fn lease_startup_refuses_disabling_and_unexplained_owner_routes() {
        let _metrics = crate::observability::metrics::METRICS_TEST_LOCK
            .lock()
            .await;
        let repo = MockRepository::new();
        let speaker = FaultyBlackholes::default();
        speaker.inner.live_lease(OWNER).await.unwrap();
        let mut config = enforced().blackhole;
        config.leased = true;
        check_lease_startup(&config, &speaker, &repo, "pop-a", OWNER)
            .await
            .unwrap();
        let lease = LeaseKeeper::new(OWNER.into(), 60);
        let admission = admit_leased(&repo, &speaker, Some(&lease), "203.0.113.10/32")
            .await
            .unwrap();
        // Desired intent explains the route; another owner's and unowned rows are not ours.
        let route = |prefix: &str| {
            crate::bgp::BlackholeRoute::new(
                prefix.parse().unwrap(),
                "192.0.2.99".parse().unwrap(),
                vec![],
                vec![],
            )
            .unwrap()
        };
        speaker
            .inner
            .announce_leased_blackhole(&route("203.0.113.30/32").with_owner("other.owner"), 60)
            .await
            .unwrap();
        speaker
            .inner
            .announce_blackhole(&route("203.0.113.31/32"))
            .await
            .unwrap();
        check_lease_startup(&config, &speaker, &repo, "pop-a", OWNER)
            .await
            .unwrap();
        for disabled in [
            BlackholeConfig {
                leased: false,
                ..config.clone()
            },
            BlackholeConfig {
                enabled: false,
                ..config.clone()
            },
        ] {
            let error = check_lease_startup(&disabled, &speaker, &repo, "pop-a", OWNER)
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains("blackhole.leased"), "{error}");
        }
        // Still refused while the withdrawal is pending.
        let request = crate::domain::request_withdrawal(
            &repo,
            &admission.mitigation,
            false,
            "operator",
            "alice",
            "attack over".into(),
            true,
            None,
        )
        .await
        .unwrap();
        let disabled = BlackholeConfig {
            leased: false,
            ..config.clone()
        };
        assert!(
            check_lease_startup(&disabled, &speaker, &repo, "pop-a", OWNER)
                .await
                .is_err()
        );
        crate::domain::execute_withdrawal(&repo, &speaker, false, &request, None)
            .await
            .unwrap();
        check_lease_startup(&disabled, &speaker, &repo, "pop-a", OWNER)
            .await
            .unwrap();
        // A route under this owner that no row desires or withdraws: a collision.
        speaker
            .inner
            .announce_leased_blackhole(&route("203.0.113.40/32").with_owner(OWNER), 60)
            .await
            .unwrap();
        let error = check_lease_startup(&config, &speaker, &repo, "pop-a", OWNER)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("203.0.113.40/32"), "{error}");
        // A failed read refuses rather than looking empty.
        speaker.inner.expire_lease(OWNER).await;
        speaker.fail_reads.store(true, SeqCst);
        assert!(
            check_lease_startup(&config, &speaker, &repo, "pop-a", OWNER)
                .await
                .is_err()
        );
    }
}
