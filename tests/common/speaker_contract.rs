//! Shared contract for complete local observation; this is not router enforcement.
use anyhow::{Context, Result, ensure};
use prefixd::{
    bgp::FlowSpecAnnouncer,
    domain::{FlowSpecAction, FlowSpecNlri, FlowSpecRule},
};
use std::time::Duration;

pub fn contract_rules() -> Vec<FlowSpecRule> {
    let mut rules: Vec<_> = [
        (
            "192.0.2.240/32",
            Some(6),
            vec![443, 80, 53, 22, 123, 8080, 8443, 25],
        ),
        (
            "2001:0DB8:0:0:0:0:0:240/128",
            Some(17),
            vec![443, 80, 53, 22, 123, 8080, 8443, 25],
        ),
        ("192.0.2.241/32", None, vec![]),
        ("2001:db8::241/128", None, vec![]),
        ("192.0.2.242/32", Some(1), vec![]),
        ("2001:db8::242/128", Some(58), vec![]),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (prefix, protocol, dst_ports))| {
        FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: prefix.into(),
                protocol,
                dst_ports,
                ..Default::default()
            },
            if index % 2 == 0 {
                FlowSpecAction::discard()
            } else {
                FlowSpecAction::police(8_000_000)
            },
        )
    })
    .collect();
    rules.extend(source_prefix_rules());
    rules.extend(destination_prefix_rules());
    rules
}

/// Same destination/protocol with absent, /0, network and host sources. Losing
/// type 2 collapses these identities and fails the shared cardinality oracle.
pub fn source_prefix_rules() -> Vec<FlowSpecRule> {
    let mut rules = Vec::new();
    for (destination, sources) in [
        (
            "192.0.2.248/32",
            [
                None,
                Some("0.0.0.0/0"),
                Some("198.51.100.0/24"),
                Some("198.51.100.128/25"),
                Some("198.51.100.1/32"),
            ],
        ),
        (
            "2001:db8::248/128",
            [
                None,
                Some("::/0"),
                Some("2001:db8:1::/48"),
                Some("2001:db8:1::/64"),
                Some("2001:db8:1::1/128"),
            ],
        ),
    ] {
        for source in sources {
            rules.push(FlowSpecRule::new(
                FlowSpecNlri {
                    dst_prefix: destination.into(),
                    src_prefix: source.map(str::to_owned),
                    protocol: Some(6),
                    dst_ports: vec![443],
                    ..Default::default()
                },
                FlowSpecAction::discard(),
            ));
        }
    }
    rules
}

/// Exact subnet destinations with the same port selector and both actions.
/// Source and extended components must survive alongside a non-host destination.
pub fn destination_prefix_rules() -> Vec<FlowSpecRule> {
    let mut rules = Vec::new();
    for (destination, source) in [
        ("203.0.112.0/22", "198.51.100.0/24"),
        ("2001:db8:1234::/48", "2001:db8:5678::/48"),
    ] {
        for extended in [false, true] {
            rules.push(FlowSpecRule::new(
                FlowSpecNlri {
                    dst_prefix: destination.into(),
                    src_prefix: extended.then(|| source.into()),
                    protocol: Some(17),
                    dst_ports: vec![53],
                    src_ports: if extended { vec![123, 389] } else { vec![] },
                    packet_length: extended.then_some(prefixd::domain::PacketLengthRange {
                        min: 468,
                        max: 65535,
                    }),
                    ..Default::default()
                },
                if extended {
                    FlowSpecAction::police(8_000_000)
                } else {
                    FlowSpecAction::discard()
                },
            ));
        }
    }
    rules
}

pub fn exact_inventory(actual: &[FlowSpecRule], expected: &[FlowSpecRule]) -> Result<()> {
    ensure!(
        actual.len() == expected.len(),
        "inventory cardinality: expected {}, observed {}",
        expected.len(),
        actual.len()
    );
    for wanted in expected {
        let matching: Vec<_> = actual
            .iter()
            .filter(|rule| rule.nlri_hash() == wanted.nlri_hash())
            .collect();
        ensure!(
            matching.len() == 1,
            "expected one NLRI {}, observed {}",
            wanted.nlri.dst_prefix,
            matching.len()
        );
        let found = matching[0];
        ensure!(
            found.nlri.dst_prefix.parse::<ipnet::IpNet>()?
                == wanted.nlri.dst_prefix.parse::<ipnet::IpNet>()?,
            "destination prefix mismatch"
        );
        ensure!(
            found.nlri.src_prefix == wanted.nlri.src_prefix,
            "source prefix mismatch for {}",
            wanted.nlri.dst_prefix
        );
        ensure!(
            found.nlri.protocol == wanted.nlri.protocol,
            "protocol mismatch for {}",
            wanted.nlri.dst_prefix
        );
        let mut actual_ports = found.nlri.dst_ports.clone();
        let mut expected_ports = wanted.nlri.dst_ports.clone();
        actual_ports.sort_unstable();
        expected_ports.sort_unstable();
        ensure!(
            actual_ports == expected_ports,
            "destination ports mismatch for {}",
            wanted.nlri.dst_prefix
        );
        ensure!(
            // Source ports are an equality set, read back ascending and unique.
            prefixd::domain::canonical_ports(&found.nlri.src_ports)
                == prefixd::domain::canonical_ports(&wanted.nlri.src_ports)
                && found.nlri.fragment == wanted.nlri.fragment
                && found.nlri.packet_length == wanted.nlri.packet_length,
            "source port, fragment or packet length mismatch for {}",
            wanted.nlri.dst_prefix
        );
        ensure!(
            found.actions.len() == wanted.actions.len(),
            "action cardinality mismatch for {}",
            wanted.nlri.dst_prefix
        );
        for (observed, expected) in found.actions.iter().zip(&wanted.actions) {
            ensure!(
                observed.action_type == expected.action_type
                    && observed.rate_bps == expected.rate_bps,
                "actions mismatch for {}: expected {:?}, observed {:?}",
                wanted.nlri.dst_prefix,
                wanted.actions,
                found.actions
            );
        }
    }
    Ok(())
}

pub async fn wait_inventory(
    speaker: &dyn FlowSpecAnnouncer,
    expected: &[FlowSpecRule],
) -> Result<()> {
    let reader = speaker
        .reader()
        .context("readable contract requires a rule reader")?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let actual = tokio::time::timeout(Duration::from_secs(5), reader.list_active())
            .await
            .context("complete local inventory deadline")?
            .context("complete local inventory failed")?;
        let comparison = exact_inventory(&actual, expected).and_then(|()| {
            for wanted in expected {
                let observed = actual
                    .iter()
                    .find(|rule| rule.nlri_hash() == wanted.nlri_hash())
                    .context("expected NLRI missing after complete comparison")?;
                ensure!(
                    speaker.matches_nlri(&wanted.nlri, &observed.nlri)?,
                    "observed match does not address the saved backend route"
                );
            }
            Ok(())
        });
        match comparison {
            Ok(()) => return Ok(()),
            Err(error) if tokio::time::Instant::now() >= deadline => return Err(error),
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
}

#[allow(
    dead_code,
    reason = "Only real speaker targets qualify traffic-rate encoding."
)]
pub async fn run_action_contract(speaker: &dyn FlowSpecAnnouncer) -> Result<()> {
    use prefixd::domain::ActionType;
    let mut wanted: Vec<_> = ["192.0.2.245/32", "2001:0DB8:0:0:0:0:0:245/128"]
        .into_iter()
        .map(|prefix| {
            FlowSpecRule::new(
                FlowSpecNlri {
                    dst_prefix: prefix.into(),
                    protocol: Some(17),
                    dst_ports: vec![53],
                    ..Default::default()
                },
                FlowSpecAction::police(1_000_000),
            )
        })
        .collect();
    // Same destinations but different matches protect against prefix/family-wide deletion.
    let foreign: Vec<_> = wanted
        .iter()
        .cloned()
        .map(|mut rule| {
            rule.nlri.dst_ports = vec![54];
            rule
        })
        .collect();
    for rule in &foreign {
        speaker.announce(rule).await?;
    }
    for rate in [1, 7, 8, 9, 1_000_000] {
        for rule in &mut wanted {
            rule.actions = vec![FlowSpecAction::police(rate)];
            speaker.announce(rule).await?;
        }
        let mut expected = foreign.clone();
        expected.extend(wanted.clone());
        wait_inventory(speaker, &expected)
            .await
            .context("exact fractional-byte police rate")?;
    }
    for actions in [
        vec![],
        vec![FlowSpecAction::discard(), FlowSpecAction::police(8)],
        vec![FlowSpecAction {
            action_type: ActionType::Police,
            rate_bps: None,
        }],
        vec![FlowSpecAction::police(0)],
        vec![FlowSpecAction::police(16_777_217)],
        vec![FlowSpecAction::police(u64::MAX)],
        vec![FlowSpecAction {
            action_type: ActionType::Discard,
            rate_bps: Some(8),
        }],
    ] {
        for rule in &wanted {
            speaker.announce(rule).await?;
        }
        let mut expected = foreign.clone();
        expected.extend(wanted.clone());
        wait_inventory(speaker, &expected).await?;
        for rule in &wanted {
            let mut historical = rule.clone();
            historical.actions = actions.clone();
            ensure!(
                speaker.announce(&historical).await.is_err(),
                "invalid action must not announce"
            );
        }
        wait_inventory(speaker, &expected)
            .await
            .context("invalid action preserves all installed rules")?;
        for rule in &wanted {
            let mut historical = rule.clone();
            historical.actions = actions.clone();
            speaker
                .withdraw(&historical)
                .await
                .context("withdraw historical invalid action")?;
            expected.retain(|expected| expected.nlri_hash() != rule.nlri_hash());
            wait_inventory(speaker, &expected)
                .await
                .context("withdraw only the exact local match")?;
        }
    }
    for rule in &foreign {
        speaker.withdraw(rule).await?;
    }
    wait_inventory(speaker, &[]).await
}

/// ADR 028 rules in both families: source ports, source ports with a packet
/// length, and non-first fragments, each beside an all-UDP rule for the same victim.
#[allow(
    dead_code,
    reason = "Peered targets do not repeat local match-encoding qualification."
)]
pub fn amplification_rules() -> Vec<FlowSpecRule> {
    use prefixd::domain::{FragmentMatch, PacketLengthRange};
    let mut rules = vec![];
    for prefix in ["192.0.2.247/32", "2001:0DB8:0:0:0:0:0:247/128"] {
        let udp = FlowSpecNlri {
            dst_prefix: prefix.into(),
            protocol: Some(17),
            ..Default::default()
        };
        rules.extend([
            FlowSpecRule::new(udp.clone(), FlowSpecAction::police(80_000_000)),
            FlowSpecRule::new(
                FlowSpecNlri {
                    src_ports: vec![389, 123, 53],
                    ..udp.clone()
                },
                FlowSpecAction::discard(),
            ),
            FlowSpecRule::new(
                FlowSpecNlri {
                    src_ports: vec![11211],
                    packet_length: Some(PacketLengthRange {
                        min: 1000,
                        max: 65535,
                    }),
                    ..udp.clone()
                },
                FlowSpecAction::discard(),
            ),
            FlowSpecRule::new(
                FlowSpecNlri {
                    fragment: Some(FragmentMatch::NonFirst),
                    ..udp
                },
                FlowSpecAction::police(20_000_000),
            ),
        ]);
    }
    rules
}

/// Injects, reads back as matching and deletes each ADR 028 rule. A speaker that
/// dropped a component would collapse two rules into one route and fail here.
#[allow(
    dead_code,
    reason = "Peered targets do not repeat local match-encoding qualification."
)]
pub async fn run_amplification_contract(speaker: &dyn FlowSpecAnnouncer) -> Result<()> {
    ensure!(
        speaker.capabilities().flowspec_match == prefixd::bgp::FlowSpecMatchSupport::ALL,
        "speaker must report every ADR 028 component"
    );
    wait_inventory(speaker, &[])
        .await
        .context("isolated initial inventory")?;
    let mut expected = amplification_rules();
    for rule in &expected {
        speaker.announce(rule).await.context("announce")?;
        speaker.announce(rule).await.context("duplicate announce")?;
    }
    wait_inventory(speaker, &expected)
        .await
        .context("extended rules read back as matching")?;
    // Delete one rule at a time; its siblings on the same victim must survive.
    for rule in amplification_rules().iter().rev() {
        speaker.withdraw(rule).await.context("withdraw")?;
        expected.retain(|other| other.nlri_hash() != rule.nlri_hash());
        wait_inventory(speaker, &expected)
            .await
            .context("withdraw only the exact extended rule")?;
    }
    Ok(())
}

pub async fn run_readable_contract(speaker: &dyn FlowSpecAnnouncer) -> Result<()> {
    wait_inventory(speaker, &[])
        .await
        .context("isolated initial inventory")?;
    let mut rules = contract_rules();
    for rule in &rules {
        speaker.announce(rule).await.context("announce")?;
        speaker.announce(rule).await.context("duplicate announce")?;
    }
    wait_inventory(speaker, &rules)
        .await
        .context("dual-family idempotent announce")?;
    for rule in &mut rules {
        rule.actions = match rule.actions[0].action_type {
            prefixd::domain::ActionType::Discard => vec![FlowSpecAction::police(16_000_000)],
            _ => vec![FlowSpecAction::discard()],
        };
        speaker.announce(rule).await.context("replace action")?;
        speaker
            .announce(rule)
            .await
            .context("duplicate replacement")?;
    }
    wait_inventory(speaker, &rules)
        .await
        .context("replacement preserves NLRI and exact actions")?;
    if let Some(observer) = speaker.peer_observer() {
        observer
            .session_status()
            .await
            .context("available peer observation")?;
    }
    for (index, rule) in rules.iter().enumerate() {
        speaker.withdraw(rule).await.context("withdraw")?;
        speaker.withdraw(rule).await.context("duplicate withdraw")?;
        wait_inventory(speaker, &rules[index + 1..])
            .await
            .context("withdraw only the exact source and destination match")?;
    }
    wait_inventory(speaker, &[])
        .await
        .context("idempotent withdrawal")?;
    for rule in &rules {
        speaker
            .announce(rule)
            .await
            .context("re-announce after withdrawal")?;
    }
    wait_inventory(speaker, &rules)
        .await
        .context("re-announcement")?;
    for rule in &rules {
        speaker.withdraw(rule).await?;
    }
    wait_inventory(speaker, &[])
        .await
        .context("final inventory")
}

#[allow(
    dead_code,
    reason = "Only real speaker targets qualify reconciliation against wire readback."
)]
pub async fn run_action_reconciliation_contract(
    speaker: std::sync::Arc<dyn FlowSpecAnnouncer>,
    config: &prefixd::config::BgpConfig,
) -> Result<()> {
    use prefixd::{
        db::{MockRepository, RepositoryTrait},
        domain::{
            ActionParams, AttackVector, MatchCriteria, Mitigation, MitigationIntent, SpeakerTarget,
            execute_withdrawal, mitigation_rule, request_withdrawal,
        },
        observability::metrics,
        scheduler::ReconciliationLoop,
    };
    let repo = std::sync::Arc::new(MockRepository::new());
    let pop = "action-drift-contract";
    let binding = repo
        .register_speaker_target(pop, &SpeakerTarget::from_config(config)?, false)
        .await?;
    let reconciler = ReconciliationLoop::new(repo.clone(), speaker.clone(), 30, false)
        .with_speaker_binding(binding.clone());
    let mut owners = Vec::new();
    let mut unknown = Vec::new();
    wait_inventory(speaker.as_ref(), &[]).await?;
    for prefix in ["192.0.2.246/32", "2001:0DB8:0:0:0:0:0:246/128"] {
        let mut owner = Mitigation::from_intent(
            MitigationIntent {
                event_id: uuid::Uuid::new_v4(),
                customer_id: None,
                service_id: None,
                pop: pop.into(),
                match_criteria: MatchCriteria {
                    dst_prefix: prefix.into(),
                    protocol: Some(17),
                    dst_ports: vec![443, 53],
                    ..Default::default()
                },
                action_type: prefixd::domain::ActionType::Discard,
                action_params: ActionParams::default(),
                ttl_seconds: 300,
                reason: "action drift qualification".into(),
            },
            prefix.split('/').next().unwrap().into(),
            AttackVector::UdpFlood,
        );
        owner.activate();
        repo.insert_mitigation(&owner).await?;
        let mut foreign_owner = owner.clone();
        foreign_owner.mitigation_id = uuid::Uuid::new_v4();
        foreign_owner.pop = "another-target".into();
        foreign_owner.action_type = prefixd::domain::ActionType::Police;
        foreign_owner.action_params.rate_bps = Some(8_000_000);
        repo.insert_mitigation(&foreign_owner).await?;
        let mut control = mitigation_rule(&owner).unwrap();
        control.nlri.dst_ports = vec![54];
        control.actions = vec![FlowSpecAction::police(1)];
        speaker.announce(&control).await?;
        unknown.push(control);
        let mut duplicate_term_control = mitigation_rule(&owner).unwrap();
        duplicate_term_control.nlri.dst_ports = vec![443, 53, 53];
        duplicate_term_control.actions = vec![FlowSpecAction::police(7)];
        speaker.announce(&duplicate_term_control).await?;
        unknown.push(duplicate_term_control);
        owners.push(owner);
    }
    for (wanted, drifted_action) in [
        (FlowSpecAction::discard(), FlowSpecAction::police(7)),
        (FlowSpecAction::police(1), FlowSpecAction::discard()),
        (FlowSpecAction::police(7), FlowSpecAction::police(8)),
        (FlowSpecAction::police(8), FlowSpecAction::police(9)),
        (FlowSpecAction::police(9), FlowSpecAction::police(1)),
    ] {
        let mut drifted = unknown.clone();
        let mut desired = unknown.clone();
        for owner in &mut owners {
            owner.action_type = wanted.action_type;
            owner.action_params.rate_bps = wanted.rate_bps;
            repo.update_mitigation(owner).await?;
            let rule = mitigation_rule(owner).unwrap();
            let mut changed = rule.clone();
            changed.actions = vec![drifted_action.clone()];
            speaker.announce(&changed).await?;
            drifted.push(changed);
            desired.push(rule);
        }
        wait_inventory(speaker.as_ref(), &drifted)
            .await
            .context("prove action-only drift before reconciliation")?;
        let successes = metrics::RECONCILIATION_REPAIRS.with_label_values(&["success"]);
        let errors = metrics::RECONCILIATION_REPAIRS.with_label_values(&["error"]);
        let announcements = metrics::ANNOUNCEMENTS_TOTAL
            .with_label_values(&[metrics::backend_label(speaker.backend()), "announced"]);
        let before = (successes.get(), errors.get(), announcements.get());
        reconciler.reconcile().await?;
        wait_inventory(speaker.as_ref(), &desired)
            .await
            .context("complete dual-family action repair")?;
        ensure!(
            (successes.get(), errors.get(), announcements.get())
                == (before.0 + 2.0, before.1, before.2 + 2.0),
            "each differing local action needs exactly one accepted repair"
        );
        reconciler.reconcile().await?;
        wait_inventory(speaker.as_ref(), &desired).await?;
        ensure!(
            (successes.get(), errors.get(), announcements.get())
                == (before.0 + 2.0, before.1, before.2 + 2.0),
            "converged poll must not repeat action repairs"
        );
    }
    let mut remaining: Vec<_> = owners
        .iter()
        .map(|owner| mitigation_rule(owner).unwrap())
        .chain(unknown.iter().cloned())
        .collect();
    for owner in &owners {
        // Delete through the immutable original persisted match, never a readback representation.
        ensure!(
            owner.match_criteria.dst_ports == vec![443, 53],
            "persisted port order changed"
        );
        let request = request_withdrawal(
            repo.as_ref(),
            owner,
            false,
            "operator",
            "contract",
            "withdraw repaired original intent".into(),
            true,
            Some(&binding),
        )
        .await?;
        execute_withdrawal(
            repo.as_ref(),
            speaker.as_ref(),
            false,
            &request,
            Some(&binding),
        )
        .await?;
        remaining.retain(|rule| rule.nlri_hash() != mitigation_rule(owner).unwrap().nlri_hash());
        wait_inventory(speaker.as_ref(), &remaining)
            .await
            .context("original saved intent deletes repaired rule")?;
    }
    reconciler.reconcile().await?;
    wait_inventory(speaker.as_ref(), &unknown)
        .await
        .context("withdrawn rules stay absent and unknown controls survive")?;
    for rule in &unknown {
        speaker.withdraw(rule).await?;
    }
    wait_inventory(speaker.as_ref(), &[]).await
}

#[allow(
    dead_code,
    reason = "Only peered backend targets exercise peer state transitions."
)]
pub async fn wait_peer_state(
    speaker: &dyn FlowSpecAnnouncer,
    address: &str,
    established: bool,
) -> Result<()> {
    let observer = speaker
        .peer_observer()
        .context("peer qualification requires observation")?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let peers = observer.session_status().await?;
            if peers.len() == 1
                && peers[0].address == address
                && peers[0].state.is_established() == established
            {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("bounded peer state transition")?
}
