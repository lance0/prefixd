//! Blackhole guardrails (ADR 027). Stricter than FlowSpec and independent of the
//! FlowSpec prefix bounds, which can be widened.

use std::net::IpAddr;

use uuid::Uuid;

use crate::bgp::FlowSpecAnnouncer;
use crate::config::{BlackholeConfig, Inventory, OperationMode, Settings};
use crate::db::RepositoryTrait;
use crate::domain::{ActionType, AttackVector, Mitigation, MitigationIntent};
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
    Ok(())
}

/// Shape, TTL, address and next-hop checks that need no inventory or database.
fn check_intent(config: &BlackholeConfig, intent: &MitigationIntent) -> Result<IpAddr> {
    if intent.action_type != ActionType::Blackhole {
        return Err(refused("intent is not a blackhole"));
    }
    if intent.match_criteria.protocol.is_some() || !intent.match_criteria.dst_ports.is_empty() {
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

/// Shared manual-blackhole admission: the caller holds the lifecycle mutex and has
/// already authorized the request. The victim must be owned in inventory and not
/// safelisted; quotas are enforced inside `admit_mitigation`. Dry-run persists the
/// row with its audit entry and sends nothing. Enforced mode refuses before
/// persistence until the lifecycle slice adds the announcement.
pub async fn admit_blackhole(
    repo: &dyn RepositoryTrait,
    settings: &Settings,
    inventory: &Inventory,
    mut intent: MitigationIntent,
    actor: &CreationActor,
) -> Result<Mitigation> {
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
    if settings.mode == OperationMode::Enforced {
        return Err(refused(
            "enforced blackhole announcement is not available in this release",
        ));
    }
    intent.customer_id = Some(owner.customer_id);
    // Canonical spelling, so stored match and victim agree with the identity hash.
    intent.match_criteria.dst_prefix = ipnet::IpNet::from(address).to_string();
    let mut mitigation = Mitigation::from_intent(intent, victim, AttackVector::Unknown);
    mitigation.activate();
    mitigation.origin_mode = Some(settings.mode);
    repo.admit_mitigation(&mitigation, &settings.quotas, config, actor)
        .await?;
    Ok(mitigation)
}

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
    use crate::config::{Customer, PolicyProfile};
    use crate::db::MockRepository;
    use crate::domain::{ActionParams, MatchCriteria, MitigationStatus};

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
                protocol: None,
                dst_ports: vec![],
            },
            action_type: ActionType::Blackhole,
            action_params: ActionParams { rate_bps: None },
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
        admit_blackhole(repo, settings, inventory, intent, &actor()).await
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

    #[tokio::test]
    async fn enforced_mode_refuses_before_persistence() {
        let owned = inventory(&["203.0.113.0/24"]);
        let mut enforced = settings();
        enforced.mode = OperationMode::Enforced;
        let error = rejected_then_admitted(
            (&enforced, &owned, intent("203.0.113.10/32")),
            (&settings(), &owned, intent("203.0.113.10/32")),
        )
        .await;
        assert!(reason(error).contains("enforced"));
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
        let mut rate = base();
        rate.action_params.rate_bps = Some(1_000_000);
        for rejected in [
            flowspec,
            protocol,
            ports,
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
            let repo = MockRepository::new();
            // A FlowSpec row never uses a blackhole slot.
            let mut flowspec = Mitigation::from_intent(
                MitigationIntent {
                    action_type: ActionType::Discard,
                    match_criteria: MatchCriteria {
                        dst_prefix: "203.0.113.9/32".into(),
                        protocol: Some(17),
                        dst_ports: vec![53],
                    },
                    ..intent("203.0.113.9/32")
                },
                "203.0.113.9".into(),
                AttackVector::UdpFlood,
            );
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
            // FlowSpec admission is unaffected by a full blackhole quota.
            let mut second = flowspec.clone();
            second.mitigation_id = Uuid::new_v4();
            second.match_criteria.dst_prefix = "203.0.113.8/32".into();
            second.scope_hash = second.match_criteria.compute_scope_hash();
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
    }
}
