//! The symmetric return leg (ADR 030 amendment, R9 controller gate).
use super::*;

fn return_leg() -> ReturnLeg {
    ReturnLeg {
        router_peers: vec!["192.0.2.3".into()],
        policy_binding: "client-side-v1".into(),
        export_community: "64496:100".into(),
        tcp_flags: Some(ReturnTcpFlags::SynAck),
    }
}

/// Profile `a` carries a return leg; profile `b` does not.
async fn pair_fixture() -> (Arc<AppState>, Arc<MockRepository>, Arc<Fake>) {
    let (mut state, repo, fake) = fixture(OperationMode::Enforced).await;
    let settings = &mut Arc::get_mut(&mut state).unwrap().settings;
    settings.scrubber.profiles[0].return_leg = Some(return_leg());
    settings.guardrails.allow_src_prefix_match = true;
    ready(&state).await;
    (state, repo, fake)
}

/// The inbound and return keys of a pair.
fn keys(row: &Diversion) -> (String, String) {
    (
        row.rule.nlri.compute_hash(),
        row.return_rule.as_ref().unwrap().nlri.compute_hash(),
    )
}

fn ordinary(state: &AppState, dst_prefix: &str, src_prefix: Option<&str>) -> Mitigation {
    let mut row = Mitigation::from_intent(
        MitigationIntent {
            event_id: Uuid::new_v4(),
            customer_id: Some("cust_example".into()),
            service_id: None,
            pop: state.settings.pop.clone(),
            match_criteria: MatchCriteria {
                dst_prefix: dst_prefix.into(),
                src_prefix: src_prefix.map(Into::into),
                protocol: Some(6),
                ..Default::default()
            },
            action_type: ActionType::Discard,
            action_params: ActionParams::default(),
            ttl_seconds: 60,
            reason: "ordinary fixture".into(),
        },
        dst_prefix.trim_end_matches("/32").into(),
        AttackVector::Unknown,
    );
    row.origin_mode = Some(OperationMode::Enforced);
    row
}

async fn admit_ordinary(
    state: &AppState,
    repo: &MockRepository,
    row: &Mitigation,
    quotas: &crate::config::QuotasConfig,
) -> Result<()> {
    repo.admit_mitigation(
        row,
        quotas,
        &state.settings.blackhole,
        &crate::observability::CreationActor::Operator("admin".into()),
    )
    .await
}

#[tokio::test]
async fn pair_confirms_both_legs_before_active_with_the_exact_return_shape() {
    let (state, repo, fake) = pair_fixture().await;
    let admission = confirmed(&state, "a", 20).await;
    let confirmation = admission.confirmation.clone().unwrap();
    assert!(
        confirmation.contains(
            "; return leg destination any {\"dst_prefix\":\"\",\"src_prefix\":\"203.0.113.20/32\""
        ) && confirmation.ends_with(" -> 192.0.2.99 community 64496:100 peers [\"192.0.2.3\"]"),
        "{confirmation}"
    );
    let row = state
        .scrubber
        .create(&state, &admission, "admin")
        .await
        .unwrap();
    assert_eq!(row.status, DiversionStatus::Active);
    let leg = row.return_rule.clone().unwrap();
    assert_eq!(leg.nlri.dst_prefix, "", "omitted, not /0");
    assert_eq!(leg.nlri.src_prefix.as_deref(), Some("203.0.113.20/32"));
    assert_eq!(leg.nlri.protocol, Some(6));
    assert!(leg.nlri.dst_ports.is_empty());
    assert_eq!(leg.nlri.src_ports, [443], "ports mirror exactly");
    assert_eq!(leg.nlri.tcp_flags, Some(crate::bgp::syn_ack()));
    assert_eq!(leg.export_community.as_deref(), Some("64496:100"));
    assert_eq!(
        (leg.revision, &leg.owner, leg.target),
        (row.rule.revision, &row.rule.owner, row.rule.target),
        "one row, one owner, one revision and one target"
    );
    assert!(
        row.rule.export_community.is_none(),
        "inbound bytes unchanged"
    );
    let (inbound, ret) = keys(&row);
    assert_ne!(inbound, ret);
    assert_eq!(
        *fake.added.lock().unwrap(),
        [ret.clone(), inbound.clone()],
        "the return leg first, then the inbound leg, in one pass"
    );
    let held = fake.guarded_inventory().await.unwrap();
    assert!(
        row.legs()
            .all(|leg| held.iter().any(|entry| entry.rule.same_admission(leg)))
    );
    assert_eq!(fake.export_reads.load(SeqCst), 2, "a pair costs two reads");
    assert!(row.export_observation.is_some() && row.return_export_observation.is_some());
    let audit = row.audit("scrubber_admit");
    assert_eq!(audit.details["export_community"], "64496:100");
    assert_eq!(
        audit.details["return_match"],
        serde_json::to_value(&leg.nlri).unwrap()
    );

    // The durable snapshot freezes both legs; neither can change.
    let saved = repo.get_diversion(row.id).await.unwrap().unwrap();
    saved.validate().unwrap();
    for case in 0..3 {
        let mut tampered = saved.clone();
        let leg = tampered.return_rule.as_mut().unwrap();
        match case {
            0 => leg.revision += 1,
            1 => leg.export_community = Some("64496:101".into()),
            _ => tampered.return_rule = None,
        }
        assert!(tampered.validate().is_err(), "case {case}");
        assert!(repo.save_diversion(&tampered, "invalid").await.is_err());
    }

    // A second victim's pair stays independent of the first return leg.
    let second = state
        .scrubber
        .create(&state, &confirmed(&state, "a", 21).await, "admin")
        .await
        .unwrap();
    assert_eq!(second.status, DiversionStatus::Active);

    // UDP creates the inbound leg alone.
    let mut udp = request("a", 22);
    udp.scope.protocol = Some(17);
    udp.scope.dst_ports = vec![53];
    let candidate = state.scrubber.prepare(&state, &udp, "admin").await.unwrap();
    assert!(candidate.return_rule.is_none());
    assert!(
        !ScrubberController::confirmation(&candidate)
            .unwrap()
            .contains("return leg")
    );

    // An any-protocol or source-selected TCP request is refused before any
    // speaker call; the same requests pass a profile without a return leg.
    let writes = fake.writes.load(SeqCst);
    let mut any = request("a", 23);
    any.scope.protocol = None;
    any.scope.dst_ports = vec![];
    let error = state
        .scrubber
        .prepare(&state, &any, "admin")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("explicit protocol"), "{error}");
    let mut sourced = request("a", 23);
    sourced.scope.src_prefix = Some("198.51.100.0/24".into());
    let error = state
        .scrubber
        .prepare(&state, &sourced, "admin")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("source-selected"), "{error}");
    for mut control in [any, sourced] {
        control.profile = "b".into();
        state
            .scrubber
            .prepare(&state, &control, "admin")
            .await
            .unwrap();
    }
    assert_eq!(fake.writes.load(SeqCst), writes);
}

#[tokio::test(start_paused = true)]
async fn refused_or_unknown_add_of_either_leg_drains_both_legs() {
    for (return_fails, applied) in [(true, false), (true, true), (false, false), (false, true)] {
        let (state, repo, fake) = pair_fixture().await;
        let request = confirmed(&state, "a", 20).await;
        let candidate = state
            .scrubber
            .prepare(&state, &request, "admin")
            .await
            .unwrap();
        let (inbound, ret) = keys(&candidate);
        let failing = if return_fails { &ret } else { &inbound };
        fake.fail_add
            .lock()
            .unwrap()
            .insert(failing.clone(), applied);
        let row = state
            .scrubber
            .create(&state, &request, "admin")
            .await
            .unwrap();
        let case = format!("return {return_fails}, applied {applied}");
        assert_eq!(row.status, DiversionStatus::Withdrawing, "{case}");
        assert!(!state.scrubber.profiles().await["a"].armed, "{case}");
        let attempted = if return_fails {
            vec![ret.clone()]
        } else {
            vec![ret.clone(), inbound.clone()]
        };
        assert_eq!(
            *fake.added.lock().unwrap(),
            attempted,
            "a failed return add is never followed by the inbound add: {case}"
        );
        let row = state
            .scrubber
            .withdraw(&state, row.id, "admin", None)
            .await
            .unwrap();
        assert_eq!(row.status, DiversionStatus::Withdrawing, "{case}");
        assert!(
            fake.rows.lock().unwrap().is_empty(),
            "early deletes restore ordinary routing: {case}"
        );
        tokio::time::advance(Duration::from_secs(u64::from(WINDOW_SECONDS) + 1)).await;
        let row = state
            .scrubber
            .withdraw(&state, row.id, "admin", None)
            .await
            .unwrap();
        assert_eq!(row.status, DiversionStatus::Withdrawn, "{case}");
        assert_eq!(
            fake.added.lock().unwrap().len(),
            attempted.len(),
            "withdrawing rows never re-add either leg: {case}"
        );
        assert!(
            repo.list_diversions(&state.settings.pop)
                .await
                .unwrap()
                .is_empty()
        );
    }
}

#[tokio::test(start_paused = true)]
async fn ambiguous_delete_of_either_leg_retries_the_exact_rule_and_keeps_intent() {
    for return_ambiguous in [false, true] {
        let (state, _repo, fake) = pair_fixture().await;
        let row = state
            .scrubber
            .create(&state, &confirmed(&state, "a", 20).await, "creator")
            .await
            .unwrap();
        let (inbound, ret) = keys(&row);
        let (ambiguous, other) = if return_ambiguous {
            (ret, inbound)
        } else {
            (inbound, ret)
        };
        fake.fail_delete.lock().unwrap().insert(ambiguous.clone());
        let row = state
            .scrubber
            .withdraw(&state, row.id, "first-admin", Some("investigated".into()))
            .await
            .unwrap();
        assert_eq!(row.status, DiversionStatus::Withdrawing);
        assert!(row.last_error.is_some());
        {
            let held = fake.rows.lock().unwrap();
            assert!(held.contains_key(&ambiguous) && !held.contains_key(&other));
        }
        tokio::time::advance(Duration::from_secs(u64::from(WINDOW_SECONDS) + 1)).await;
        // The repeated delete of the absent leg is NOT_PRESENT, so success.
        let row = state
            .scrubber
            .withdraw(&state, row.id, "second-admin", Some("rewritten".into()))
            .await
            .unwrap();
        assert_eq!(row.status, DiversionStatus::Withdrawn);
        assert_eq!(row.withdrawal_reason.as_deref(), Some("investigated"));
        assert_eq!(row.withdrawal_actor.as_deref(), Some("first-admin"));
        assert!(fake.rows.lock().unwrap().is_empty());
        assert_eq!(fake.added.lock().unwrap().len(), 2, "no fresh announcement");
    }
}

#[tokio::test(start_paused = true)]
async fn restart_with_one_leg_outstanding_drains_both_behind_the_server_window_cap() {
    for return_survives in [false, true] {
        let (state, repo, fake) = pair_fixture().await;
        let mut late = state
            .scrubber
            .prepare(&state, &request("a", 20), "original-admin")
            .await
            .unwrap();
        late.controller_incarnation = Uuid::new_v4();
        let mut row = repo
            .admit_diversion(
                &late,
                &state.settings.scrubber.profiles[0],
                &state.settings.quotas,
            )
            .await
            .unwrap();
        // The previous process added one leg before it stopped.
        let survivor = if return_survives {
            row.return_rule.clone().unwrap()
        } else {
            row.rule.clone()
        };
        fake.rows.lock().unwrap().insert(
            survivor.nlri.compute_hash(),
            (survivor, Instant::now() + Duration::from_secs(300)),
        );
        let mut runtime = state.scrubber.runtime.lock().await;
        state
            .scrubber
            .drive(&state, &mut runtime, &mut row)
            .await
            .unwrap();
        assert_eq!(row.status, DiversionStatus::Withdrawing);
        assert!(fake.rows.lock().unwrap().is_empty(), "early delete");
        tokio::time::advance(Duration::from_secs(u64::from(WINDOW_SECONDS) + 1)).await;
        state
            .scrubber
            .drive(&state, &mut runtime, &mut row)
            .await
            .unwrap();
        assert_eq!(
            row.status,
            DiversionStatus::Withdrawing,
            "another incarnation's windows may live longer"
        );
        tokio::time::advance(SERVER_WINDOW_CAP).await;
        state
            .scrubber
            .drive(&state, &mut runtime, &mut row)
            .await
            .unwrap();
        assert_eq!(row.status, DiversionStatus::Withdrawn);
        assert!(fake.added.lock().unwrap().is_empty(), "never re-added");
    }
}

#[tokio::test(start_paused = true)]
async fn foreign_rule_at_the_return_key_refuses_admission_and_is_never_deleted() {
    for guarded in [false, true] {
        let (state, _repo, fake) = pair_fixture().await;
        let request = confirmed(&state, "a", 20).await;
        let candidate = state
            .scrubber
            .prepare(&state, &request, "admin")
            .await
            .unwrap();
        let foreign = candidate.return_rule.unwrap();
        if guarded {
            let mut rule = foreign.clone();
            rule.owner = "another-tool".into();
            rule.revision = 999;
            fake.rows.lock().unwrap().insert(
                foreign.nlri.compute_hash(),
                (rule, Instant::now() + Duration::from_secs(600)),
            );
        } else {
            fake.other_matches
                .lock()
                .unwrap()
                .push(foreign.nlri.clone());
        }
        let row = state
            .scrubber
            .create(&state, &request, "admin")
            .await
            .unwrap();
        assert_eq!(row.status, DiversionStatus::Withdrawing);
        assert_eq!(fake.writes.load(SeqCst), 0, "no window, add or delete");
        tokio::time::advance(Duration::from_secs(u64::from(WINDOW_SECONDS) + 1)).await;
        let row = state
            .scrubber
            .withdraw(&state, row.id, "admin", None)
            .await
            .unwrap();
        assert_eq!(
            row.status,
            DiversionStatus::Withdrawing,
            "a foreign rule at a leg's key keeps withdrawal pending"
        );
        assert!(
            fake.guarded_inventory()
                .await
                .unwrap()
                .has_key(&foreign.nlri),
            "the foreign rule is never deleted"
        );
        assert!(fake.added.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn export_outside_either_legs_peer_set_fails_the_row() {
    // Inbound peers are 192.0.2.2; return peers are 192.0.2.3.
    for (return_leg, peer, drains) in [
        (false, "192.0.2.3", true),
        (true, "192.0.2.2", true),
        (false, "192.0.2.2", false),
        (true, "192.0.2.3", false),
    ] {
        let (state, _repo, fake) = pair_fixture().await;
        let request = confirmed(&state, "a", 20).await;
        let candidate = state
            .scrubber
            .prepare(&state, &request, "admin")
            .await
            .unwrap();
        let (inbound, ret) = keys(&candidate);
        let key = if return_leg { ret } else { inbound };
        fake.exports.lock().unwrap().insert(key, vec![peer.into()]);
        let row = state
            .scrubber
            .create(&state, &request, "admin")
            .await
            .unwrap();
        let case = format!("return {return_leg}, peer {peer}");
        if drains {
            assert_eq!(row.status, DiversionStatus::Withdrawing, "{case}");
            assert!(!state.scrubber.profiles().await["a"].armed, "{case}");
            continue;
        }
        assert_eq!(row.status, DiversionStatus::Active, "{case}");
        let (with, without) = if return_leg {
            (&row.return_export_observation, &row.export_observation)
        } else {
            (&row.export_observation, &row.return_export_observation)
        };
        assert_eq!(with.as_ref().unwrap().peers[0].peer_address, peer, "{case}");
        assert!(without.as_ref().unwrap().peers.is_empty(), "{case}");
    }
}

#[tokio::test(start_paused = true)]
async fn break_glass_removal_of_either_leg_withdraws_the_pair() {
    for return_removed in [false, true] {
        let (state, _repo, fake) = pair_fixture().await;
        let row = state
            .scrubber
            .create(&state, &confirmed(&state, "a", 20).await, "admin")
            .await
            .unwrap();
        let (inbound, ret) = keys(&row);
        fake.rows
            .lock()
            .unwrap()
            .remove(if return_removed { &ret } else { &inbound });
        let mut rows = vec![row];
        tokio::time::advance(Duration::from_secs(5)).await;
        ready(&state).await;
        let renewals = fake.renewals.load(SeqCst);
        renew_pass(&state, &mut rows).await;
        assert_eq!(rows[0].status, DiversionStatus::Withdrawing);
        assert_eq!(
            fake.renewals.load(SeqCst),
            renewals,
            "a partial pair that is its owner's only row sends no renewal"
        );
        assert!(!state.scrubber.profiles().await["a"].armed);
        renew_pass(&state, &mut rows).await;
        assert!(fake.rows.lock().unwrap().is_empty(), "both legs drain");
        assert_eq!(fake.added.lock().unwrap().len(), 2, "no repair");
    }
}

/// The owner lease is shared, so a healthy sibling's renewal in the failing
/// pass can extend the surviving leg once. The next pass still drains it.
#[tokio::test(start_paused = true)]
async fn break_glass_survivor_beside_a_healthy_sibling_drains_in_the_next_pass() {
    for return_removed in [false, true] {
        let (state, _repo, fake) = pair_fixture().await;
        let mut rows = vec![];
        for host in [20, 21] {
            rows.push(
                state
                    .scrubber
                    .create(&state, &confirmed(&state, "a", host).await, "admin")
                    .await
                    .unwrap(),
            );
        }
        let (inbound, ret) = keys(&rows[0]);
        let (removed, survivor) = if return_removed {
            (ret, inbound)
        } else {
            (inbound, ret)
        };
        fake.rows.lock().unwrap().remove(&removed);
        tokio::time::advance(Duration::from_secs(5)).await;
        ready(&state).await;
        let renewals = fake.renewals.load(SeqCst);
        renew_pass(&state, &mut rows).await;
        assert_eq!(rows[0].status, DiversionStatus::Withdrawing);
        assert_eq!(
            fake.renewals.load(SeqCst),
            renewals + 1,
            "the sibling's owner renewal also extends the survivor once"
        );
        assert!(fake.rows.lock().unwrap().contains_key(&survivor));
        renew_pass(&state, &mut rows).await;
        assert!(
            !fake.rows.lock().unwrap().contains_key(&survivor),
            "the next pass deletes the survivor"
        );
        assert_eq!(
            fake.renewals.load(SeqCst),
            renewals + 1,
            "no further renewal"
        );
    }
}

#[tokio::test]
async fn quotas_count_each_leg_and_creation_rate_counts_admissions() {
    let (mut state, repo, _fake) = pair_fixture().await;
    Arc::get_mut(&mut state).unwrap().settings.scrubber.profiles[0].max_active = 3;
    ready(&state).await;
    let pair = state
        .scrubber
        .create(&state, &confirmed(&state, "a", 20).await, "admin")
        .await
        .unwrap();
    assert_eq!(pair.status, DiversionStatus::Active);
    let error = state
        .scrubber
        .create(&state, &confirmed(&state, "a", 21).await, "admin")
        .await
        .unwrap_err();
    assert!(
        matches!(
            &error,
            PrefixdError::GuardrailViolation(crate::error::GuardrailError::QuotaExceeded { quota_type, current: 2, max: 3 }) if quota_type == "scrubber_profile"
        ),
        "{error}"
    );
    // One more inbound-only rule fits the profile's three.
    let mut udp = request("a", 22);
    udp.scope.protocol = Some(17);
    udp.scope.dst_ports = vec![53];
    let candidate = state.scrubber.prepare(&state, &udp, "admin").await.unwrap();
    udp.confirmation = Some(ScrubberController::confirmation(&candidate).unwrap());
    let single = state.scrubber.create(&state, &udp, "admin").await.unwrap();
    assert_eq!(single.status, DiversionStatus::Active);

    // Ordinary admission counts the pair as two rules against POP caps.
    let mut quotas = state.settings.quotas.clone();
    quotas.max_active_per_pop = 3;
    let other = ordinary(&state, "198.51.100.1/32", None);
    let error = admit_ordinary(&state, &repo, &other, &quotas)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("pop"), "{error}");
    // Negative control: counting rows (two) would have admitted it.
    quotas.max_active_per_pop = 4;
    admit_ordinary(&state, &repo, &other, &quotas)
        .await
        .unwrap();
}

#[tokio::test]
async fn victim_as_source_conflicts_refuse_both_admission_paths() {
    // Diversion path: a live ordinary rule whose source contains the victim.
    let (state, repo, _fake) = pair_fixture().await;
    let sourced = ordinary(&state, "198.51.100.1/32", Some("203.0.113.0/24"));
    admit_ordinary(&state, &repo, &sourced, &state.settings.quotas)
        .await
        .unwrap();
    let error = state
        .scrubber
        .create(&state, &confirmed(&state, "a", 20).await, "admin")
        .await
        .unwrap_err();
    assert!(matches!(error, PrefixdError::Conflict(_)), "{error}");
    // Negative control: a profile without a return leg is unaffected.
    let row = state
        .scrubber
        .create(&state, &confirmed(&state, "b", 20).await, "admin")
        .await
        .unwrap();
    assert_eq!(row.status, DiversionStatus::Active);

    // Mitigation path: an outstanding pair refuses a rule sourced from its victim.
    let (state, repo, _fake) = pair_fixture().await;
    let pair = state
        .scrubber
        .create(&state, &confirmed(&state, "a", 20).await, "admin")
        .await
        .unwrap();
    assert_eq!(pair.status, DiversionStatus::Active);
    let error = admit_ordinary(&state, &repo, &sourced, &state.settings.quotas)
        .await
        .unwrap_err();
    assert!(matches!(error, PrefixdError::Conflict(_)), "{error}");
    // A diversion sourced from the pair's victim is refused too.
    let mut diversion = request("b", 30);
    diversion.scope.src_prefix = Some("203.0.113.20/32".into());
    let candidate = state
        .scrubber
        .prepare(&state, &diversion, "admin")
        .await
        .unwrap();
    assert!(
        repo.admit_diversion(&candidate, &profile("b"), &state.settings.quotas)
            .await
            .is_err()
    );
    // Negative control: an inbound-only diversion admits the same rule.
    let (state, repo, _fake) = pair_fixture().await;
    let row = state
        .scrubber
        .create(&state, &confirmed(&state, "b", 20).await, "admin")
        .await
        .unwrap();
    assert_eq!(row.status, DiversionStatus::Active);
    admit_ordinary(&state, &repo, &sourced, &state.settings.quotas)
        .await
        .unwrap();

    // Observed local rule: a source containing the victim refuses only a pair.
    for (profile, status) in [
        ("a", DiversionStatus::Withdrawing),
        ("b", DiversionStatus::Active),
    ] {
        let (state, _repo, fake) = pair_fixture().await;
        fake.other_matches.lock().unwrap().push(FlowSpecNlri {
            dst_prefix: "198.51.100.1/32".into(),
            src_prefix: Some("203.0.113.0/24".into()),
            protocol: Some(6),
            ..Default::default()
        });
        let row = state
            .scrubber
            .create(&state, &confirmed(&state, profile, 20).await, "admin")
            .await
            .unwrap();
        assert_eq!(row.status, status, "profile {profile}");
    }
}

#[tokio::test]
async fn own_return_legs_index_by_source_while_others_affect_every_victim() {
    let (state, repo, _fake) = pair_fixture().await;
    let row = repo
        .admit_diversion(
            &state
                .scrubber
                .prepare(&state, &request("a", 20), "admin")
                .await
                .unwrap(),
            &state.settings.scrubber.profiles[0],
            &state.settings.quotas,
        )
        .await
        .unwrap();
    let other = state
        .scrubber
        .prepare(&state, &request("a", 21), "admin")
        .await
        .unwrap();
    let other_keys: Vec<_> = other.legs().map(|leg| leg.nlri.compute_hash()).collect();
    let observe = |leg: GuardedRule| GuardedInventory {
        entries: vec![GuardedObservation {
            rule: leg,
            generation: GuardedStamp {
                incarnation: 1,
                sequence: 1,
            },
            remaining_ms: 1000,
        }],
        other_matches: vec![],
    };
    let leg = row.return_rule.clone().unwrap();
    let inventory = observe(leg.clone());
    let index = Observed::new(&inventory, std::slice::from_ref(&row)).unwrap();
    assert!(
        !index.foreign_victim_overlap(&other, &other_keys).unwrap(),
        "a durable row's return leg is classified by its source host"
    );
    let own: Vec<_> = row.legs().map(|leg| leg.nlri.compute_hash()).collect();
    assert!(!index.foreign_victim_overlap(&row, &own).unwrap());
    assert!(
        index.foreign_victim_overlap(&row, &own[..1]).unwrap(),
        "it still affects its own victim"
    );
    // Negative control: without the durable explanation, the index treats the
    // destination-less return leg as affecting every victim.
    let unexplained = Observed::new(&inventory, &[]).unwrap();
    assert!(
        unexplained
            .foreign_victim_overlap(&other, &other_keys)
            .unwrap()
    );
    // Another revision or community is not this controller's return leg.
    for case in 0..2 {
        let mut changed = leg.clone();
        if case == 0 {
            changed.revision += 1;
        } else {
            changed.export_community = Some("64496:101".into());
        }
        let inventory = observe(changed);
        let index = Observed::new(&inventory, std::slice::from_ref(&row)).unwrap();
        assert!(
            index.foreign_victim_overlap(&other, &other_keys).unwrap(),
            "case {case}"
        );
    }
}

#[tokio::test]
async fn rows_and_profiles_without_a_return_leg_are_unchanged() {
    let (state, repo, fake) = pair_fixture().await;
    let row = state
        .scrubber
        .create(&state, &confirmed(&state, "b", 20).await, "admin")
        .await
        .unwrap();
    assert_eq!(row.status, DiversionStatus::Active);
    assert_eq!(fake.added.lock().unwrap().len(), 1);
    assert_eq!(fake.export_reads.load(SeqCst), 1);
    let text = serde_json::to_string(&repo.get_diversion(row.id).await.unwrap().unwrap()).unwrap();
    for field in [
        "return_rule",
        "return_export_observation",
        "return_leg",
        "export_community",
    ] {
        assert!(!text.contains(field), "{field} in {text}");
    }
    let restored: Diversion = serde_json::from_str(&text).unwrap();
    restored.validate().unwrap();
    assert_eq!(serde_json::to_string(&restored).unwrap(), text);
    assert_eq!(
        ScrubberController::confirmation(&row).unwrap(),
        format!(
            "{} -> 192.0.2.99 via b@fixture-v1",
            serde_json::to_string(&row.rule.nlri).unwrap()
        )
    );
    let audit = row.audit("scrubber_admit");
    assert!(audit.details.get("return_match").is_none());
    assert!(audit.details.get("export_community").is_none());
    assert!(
        serde_json::to_value(profile("b").snapshot())
            .unwrap()
            .get("return_leg")
            .is_none()
    );
}

#[test]
fn return_legs_need_a_global_ip_profile_peers_and_a_canonical_community() {
    let mut config = ScrubberConfig {
        enabled: true,
        profiles: vec![profile("a")],
        readiness_ca_cert: None,
    };
    config.profiles[0].return_leg = Some(return_leg());
    config.validate().unwrap();
    let invalid = |change: &dyn Fn(&mut ScrubberProfile)| {
        let mut config = config.clone();
        change(&mut config.profiles[0]);
        config.validate().is_err()
    };
    assert!(invalid(&|p| p.scope = "customer-a".into()), "VPN profile");
    assert!(invalid(&|p| {
        p.scope = "customer-a".into();
        p.ipv4_target = None;
        p.redirect_route_target = Some("44407:888".into());
    }));
    // Negative control: the same VRF profile without a return leg is valid.
    let mut vrf = config.clone();
    vrf.profiles[0].scope = "customer-a".into();
    vrf.profiles[0].ipv4_target = None;
    vrf.profiles[0].redirect_route_target = Some("44407:888".into());
    vrf.profiles[0].return_leg = None;
    vrf.validate().unwrap();
    for community in [
        "65535:1",
        "0:100",
        "64496",
        "64496:100:1",
        "064496:100",
        "64496:65536",
        "+64496:100",
        "NO_EXPORT",
    ] {
        assert!(
            invalid(&|p| p.return_leg.as_mut().unwrap().export_community = community.into()),
            "{community}"
        );
    }
    assert!(invalid(&|p| p
        .return_leg
        .as_mut()
        .unwrap()
        .router_peers
        .clear()));
    assert!(invalid(
        &|p| p.return_leg.as_mut().unwrap().router_peers = vec!["fe80::1".into()]
    ));
    assert!(invalid(&|p| p
        .return_leg
        .as_mut()
        .unwrap()
        .policy_binding
        .clear()));
    // The peer lists may overlap when one router carries both legs.
    let mut shared = config.clone();
    shared.profiles[0].return_leg.as_mut().unwrap().router_peers = vec!["192.0.2.2".into()];
    shared.validate().unwrap();
    assert!(invalid(&|p| p.max_active = 1), "a pair needs two rules");
    // Each profile's return legs need their own community.
    let mut second = profile("b");
    second.return_leg = Some(return_leg());
    let mut two = config.clone();
    two.profiles.push(second.clone());
    assert!(two.validate().is_err());
    second.return_leg.as_mut().unwrap().export_community = "64496:101".into();
    two.profiles[1] = second;
    two.validate().unwrap();
    // It must also differ from every configured blackhole community.
    let mut blackhole = crate::config::BlackholeConfig {
        communities: vec!["64496:100".into()],
        ..Default::default()
    };
    let bgp: crate::config::BgpConfig =
        crate::config::parse_yaml("backend: mock\nlocal_asn: 65000\nrouter_id: 192.0.2.1\n")
            .unwrap();
    assert!(config.validate_with(&blackhole, &bgp).is_err());
    blackhole.communities = vec!["64496:666".into()];
    config.validate_with(&blackhole, &bgp).unwrap();
    // Only `syn_ack` is a configurable selector.
    let yaml = "router_peers: [192.0.2.3]\npolicy_binding: v1\nexport_community: '64496:100'\n";
    let parsed: ReturnLeg =
        crate::config::parse_yaml(&format!("{yaml}tcp_flags: syn_ack")).unwrap();
    assert_eq!(parsed.tcp_flags, Some(ReturnTcpFlags::SynAck));
    assert!(crate::config::parse_yaml::<ReturnLeg>(&format!("{yaml}tcp_flags: syn")).is_err());
    assert!(crate::config::parse_yaml::<ReturnLeg>(&format!("{yaml}target: 192.0.2.98")).is_err());
}

#[tokio::test]
async fn omitted_tcp_flags_divert_all_mirrored_tcp_from_the_victim() {
    let (mut state, _repo, _fake) = pair_fixture().await;
    Arc::get_mut(&mut state).unwrap().settings.scrubber.profiles[0]
        .return_leg
        .as_mut()
        .unwrap()
        .tcp_flags = None;
    let mut wide = request("a", 20);
    wide.scope.dst_ports = vec![443, 80, 80];
    let row = state
        .scrubber
        .prepare(&state, &wide, "admin")
        .await
        .unwrap();
    let leg = row.return_rule.unwrap();
    assert_eq!(leg.nlri.tcp_flags, None);
    assert_eq!(leg.nlri.src_ports, [80, 443]);
}

#[test]
fn readiness_requires_the_return_leg_object_exactly_for_pair_profiles() {
    let now = Utc::now();
    let mut pair = profile("a");
    pair.return_leg = Some(return_leg());
    let report = |return_leg: serde_json::Value| {
        let mut value = serde_json::json!({"profile":"a","revision":"fixture-v1","policy_binding":"fixture-policy-v1","observed_at":now,"valid_until":now+chrono::Duration::seconds(8),"process_ready":true,"filters_ready":true,"target_reachable":true,"capacity_available":true,"canary_passed":true,"export_isolated":true});
        if !return_leg.is_null() {
            value["return_leg"] = return_leg;
        }
        serde_json::from_value::<Readiness>(value)
    };
    let leg = |binding: &str, isolated: bool, canary: bool| serde_json::json!({"policy_binding":binding,"export_isolated":isolated,"canary_passed":canary});
    let ready = report(leg("client-side-v1", true, true)).unwrap();
    assert!(ready.state(&pair, now).unwrap().ready);
    for (isolated, canary) in [(false, true), (true, false)] {
        let state = report(leg("client-side-v1", isolated, canary))
            .unwrap()
            .state(&pair, now)
            .unwrap();
        assert!(!state.ready);
        assert_eq!(state.readiness, ReadinessState::NotReady);
    }
    assert!(
        report(serde_json::Value::Null)
            .unwrap()
            .state(&pair, now)
            .is_err()
    );
    assert!(
        report(leg("other", true, true))
            .unwrap()
            .state(&pair, now)
            .is_err()
    );
    assert!(
        report(leg("client-side-v1", true, true))
            .unwrap()
            .state(&profile("a"), now)
            .is_err(),
        "a profile without a return leg refuses the object"
    );
    let mut extra = leg("client-side-v1", true, true);
    extra["loop_free"] = true.into();
    assert!(report(extra).is_err());
    // Negative control: the inbound-only report keeps working.
    assert!(
        report(serde_json::Value::Null)
            .unwrap()
            .state(&profile("a"), now)
            .unwrap()
            .ready
    );
}

#[tokio::test]
async fn an_inbound_leg_with_a_community_is_refused_before_victim_lookup() {
    let (state, _repo, _fake) = pair_fixture().await;
    let row = state
        .scrubber
        .prepare(&state, &request("a", 20), "admin")
        .await
        .unwrap();
    row.validate().unwrap();
    // A tampered inbound leg shaped like a return leg would otherwise pass
    // rule validation and reach `victim()` with an empty destination.
    let mut tampered = row.clone();
    tampered.rule = row.return_rule.clone().unwrap();
    assert!(tampered.rule.validate().is_ok());
    assert!(tampered.validate().is_err());
    let mut tampered = row;
    tampered.rule.export_community = Some("64496:100".into());
    assert!(tampered.validate().is_err());
}

#[tokio::test]
async fn guardrail_quota_reads_weight_a_pair_as_two_rules() {
    let (state, repo, _fake) = pair_fixture().await;
    for (profile, host) in [("a", 20), ("b", 21)] {
        state
            .scrubber
            .create(&state, &confirmed(&state, profile, host).await, "admin")
            .await
            .unwrap();
    }
    let pop = &state.settings.pop;
    assert_eq!(repo.count_active_flowspec_by_pop(pop).await.unwrap(), 3);
    assert_eq!(repo.count_active_flowspec_global().await.unwrap(), 3);
    assert_eq!(
        repo.count_active_flowspec_by_customer("cust_example")
            .await
            .unwrap(),
        3
    );
    let intent = MitigationIntent {
        event_id: Uuid::new_v4(),
        customer_id: Some("cust_example".into()),
        service_id: None,
        pop: pop.clone(),
        match_criteria: MatchCriteria {
            dst_prefix: "198.51.100.1/32".into(),
            protocol: Some(6),
            ..Default::default()
        },
        action_type: ActionType::Discard,
        action_params: ActionParams::default(),
        ttl_seconds: 60,
        reason: "ordinary fixture".into(),
    };
    let guardrails = |max_active_per_pop| {
        let mut quotas = state.settings.quotas.clone();
        quotas.max_active_per_pop = max_active_per_pop;
        crate::guardrails::Guardrails::with_timers(
            state.settings.guardrails.clone(),
            quotas,
            &state.settings.timers,
        )
    };
    let error = guardrails(3)
        .validate(&intent, repo.as_ref(), false)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("pop"), "{error}");
    // Negative control: counting rows (two) would have admitted it.
    guardrails(4)
        .validate(&intent, repo.as_ref(), false)
        .await
        .unwrap();
}

#[tokio::test]
async fn foreign_destination_less_rules_affect_every_victim_of_both_families() {
    let (state, _repo, fake) = pair_fixture().await;
    let row = state
        .scrubber
        .prepare(&state, &request("b", 20), "admin")
        .await
        .unwrap();
    let keys = [row.rule.nlri.compute_hash()];
    let mut v6 = row.clone();
    v6.rule.nlri.dst_prefix = "2001:db8::20/128".into();
    v6.rule.target = Some("2001:db8::99".parse().unwrap());
    // As the rustbgpd reader represents them: a source-bearing return shape
    // under another owner, and a match with no prefix component at all.
    let sourced = FlowSpecNlri {
        dst_prefix: String::new(),
        src_prefix: Some("198.51.100.1/32".into()),
        protocol: Some(6),
        src_ports: vec![443],
        tcp_flags: Some(crate::bgp::syn_ack()),
        ..Default::default()
    };
    let bare = FlowSpecNlri {
        dst_prefix: String::new(),
        protocol: Some(17),
        ..Default::default()
    };
    for (other, victims) in [(sourced, vec![&row]), (bare, vec![&row, &v6])] {
        let inventory = GuardedInventory {
            entries: vec![],
            other_matches: vec![other.clone()],
        };
        let index = Observed::new(&inventory, &[]).unwrap();
        for victim in victims {
            assert!(
                index.foreign_victim_overlap(victim, &keys).unwrap(),
                "{other:?} overlaps {}",
                victim.rule.nlri.dst_prefix
            );
        }
        assert!(index.has_key(&other.compute_hash()));
    }
    // End to end: a foreign destination-less rule refuses admission and is
    // never deleted.
    fake.other_matches.lock().unwrap().push(FlowSpecNlri {
        dst_prefix: String::new(),
        protocol: Some(17),
        ..Default::default()
    });
    let refused = state
        .scrubber
        .create(&state, &confirmed(&state, "b", 20).await, "admin")
        .await
        .unwrap();
    assert_eq!(refused.status, DiversionStatus::Withdrawing);
    assert_eq!(fake.writes.load(SeqCst), 0);
    assert_eq!(fake.other_matches.lock().unwrap().len(), 1);
}
