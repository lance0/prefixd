use super::*;
use crate::db::{MockRepository, RepositoryTrait};
use async_trait::async_trait;
use std::sync::{
    Mutex as StdMutex,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::SeqCst},
};

struct Fake {
    repo: Arc<MockRepository>,
    pop: String,
    rows: StdMutex<HashMap<String, (GuardedRule, Instant)>>,
    other_matches: StdMutex<Vec<FlowSpecNlri>>,
    windows: StdMutex<HashMap<u64, (String, Instant)>>,
    sequence: AtomicU64,
    writes: AtomicUsize,
    queue_add: AtomicBool,
    queued: StdMutex<Option<(GuardedRule, GuardedStamp)>>,
}
impl Fake {
    fn live_window(&self, owner: &str, stamp: GuardedStamp) -> Result<Instant> {
        self.windows
            .lock()
            .unwrap()
            .get(&stamp.sequence)
            .filter(|(held, until)| held == owner && *until > Instant::now())
            .map(|(_, until)| *until)
            .ok_or_else(|| PrefixdError::Conflict("window not live".into()))
    }
    fn release(&self) -> Result<()> {
        if let Some((rule, window)) = self.queued.lock().unwrap().take() {
            let until = self.live_window(&rule.owner, window)?;
            self.rows
                .lock()
                .unwrap()
                .insert(rule.nlri.compute_hash(), (rule, until));
        }
        Ok(())
    }
}
#[async_trait]
impl FlowSpecWriter for Fake {
    async fn announce(&self, _: &FlowSpecRule) -> Result<()> {
        panic!("no ordinary add fallback")
    }
    async fn withdraw(&self, _: &FlowSpecRule) -> Result<()> {
        panic!("no ordinary delete fallback")
    }
}
impl FlowSpecAnnouncer for Fake {
    fn backend(&self) -> &'static str {
        "rustbgpd"
    }
    fn guarded_flowspec(&self) -> Option<&dyn GuardedFlowSpecSpeaker> {
        Some(self)
    }
    fn flowspec_export_observer(&self) -> Option<&dyn ExportObserver> {
        Some(self)
    }
    fn match_support(&self) -> FlowSpecMatchSupport {
        FlowSpecMatchSupport::ALL
    }
}
#[async_trait]
impl ExportObserver for Fake {
    async fn blackhole_exports(&self, _: &ipnet::IpNet) -> Result<Option<Vec<PeerExport>>> {
        Ok(Some(vec![]))
    }
    async fn flowspec_exports(&self, _: &FlowSpecNlri) -> Result<Option<Vec<PeerExport>>> {
        Ok(Some(vec![]))
    }
}
#[async_trait]
impl GuardedFlowSpecSpeaker for Fake {
    async fn issue_window(&self, owner: &str, seconds: u32) -> Result<IssuedWindow> {
        if self
            .windows
            .lock()
            .unwrap()
            .values()
            .filter(|(held, until)| held == owner && *until > Instant::now())
            .count()
            >= 64
        {
            return Err(PrefixdError::Conflict(
                "live mutation window cap reached".into(),
            ));
        }
        self.writes.fetch_add(1, SeqCst);
        let sequence = self.sequence.fetch_add(1, SeqCst);
        self.windows.lock().unwrap().insert(
            sequence,
            (
                owner.into(),
                Instant::now() + Duration::from_secs(seconds.into()),
            ),
        );
        Ok(IssuedWindow {
            stamp: GuardedStamp {
                incarnation: 1,
                sequence,
            },
            remaining_ms: seconds * 1000,
        })
    }
    async fn add_guarded(
        &self,
        rule: &GuardedRule,
        window: GuardedStamp,
        _: u32,
    ) -> Result<GuardedStamp> {
        let durable = self.repo.list_diversions(&self.pop).await?;
        assert!(
            durable
                .iter()
                .any(|row| row.rule.same_admission(rule) && row.windows.contains(&window)),
            "window and revision must be durable before dispatch"
        );
        self.writes.fetch_add(1, SeqCst);
        let until = self.live_window(&rule.owner, window)?;
        if self.queue_add.load(SeqCst) {
            *self.queued.lock().unwrap() = Some((rule.clone(), window));
            return Err(PrefixdError::Internal("unknown add outcome".into()));
        }
        self.rows
            .lock()
            .unwrap()
            .insert(rule.nlri.compute_hash(), (rule.clone(), until));
        Ok(GuardedStamp {
            incarnation: 1,
            sequence: 1,
        })
    }
    async fn renew_guarded(
        &self,
        owner: &str,
        _: GuardedStamp,
        window: GuardedStamp,
        _: u32,
    ) -> Result<u32> {
        self.writes.fetch_add(1, SeqCst);
        let until = self.live_window(owner, window)?;
        for (rule, deadline) in self.rows.lock().unwrap().values_mut() {
            if rule.owner == owner {
                *deadline = until;
            }
        }
        Ok(30_000)
    }
    async fn delete_guarded(&self, rule: &GuardedRule) -> Result<()> {
        self.writes.fetch_add(1, SeqCst);
        let mut rows = self.rows.lock().unwrap();
        let key = rule.nlri.compute_hash();
        if rows
            .get(&key)
            .is_some_and(|(held, _)| held.owner != rule.owner || held.revision != rule.revision)
        {
            return Err(PrefixdError::Conflict("owner or revision mismatch".into()));
        }
        rows.remove(&key);
        Ok(())
    }
    async fn guarded_inventory(&self) -> Result<GuardedInventory> {
        let mut rows = self.rows.lock().unwrap();
        rows.retain(|_, (_, until)| *until > Instant::now());
        Ok(GuardedInventory {
            entries: rows
                .values()
                .map(|(rule, until)| GuardedObservation {
                    rule: rule.clone(),
                    generation: GuardedStamp {
                        incarnation: 1,
                        sequence: 1,
                    },
                    remaining_ms: (*until - Instant::now()).as_millis() as u32,
                })
                .collect(),
            other_matches: self.other_matches.lock().unwrap().clone(),
        })
    }
}

fn profile(id: &str) -> ScrubberProfile {
    ScrubberProfile {
        id: id.into(),
        revision: "fixture-v1".into(),
        ipv4_target: Some("192.0.2.99".parse().unwrap()),
        ipv6_target: None,
        destinations: vec!["203.0.113.0/24".parse().unwrap()],
        router_peers: vec!["192.0.2.2".into()],
        policy_binding: "fixture-policy-v1".into(),
        qualification_receipt: "isolated controller fixture; no router forwarding qualification"
            .into(),
        readiness_url: "https://127.0.0.1:1/readiness".into(),
        readiness_token_env: "PATH".into(),
        max_ttl_seconds: 3600,
        max_active: 10,
        max_new_per_minute: 20,
        reserved_targets: vec![],
    }
}
async fn fixture(mode: OperationMode) -> (Arc<AppState>, Arc<MockRepository>, Arc<Fake>) {
    let mut settings: crate::config::Settings =
        crate::config::parse_yaml(include_str!("../../configs/prefixd.yaml")).unwrap();
    settings.mode = mode;
    settings.http.auth.mode = crate::config::AuthMode::None;
    settings.bgp.mode = crate::config::BgpMode::Rustbgpd;
    settings.bgp.rustbgpd = Some(crate::config::RustBgpdConfig {
        endpoint: "http://127.0.0.1:50051".into(),
        ..Default::default()
    });
    settings.scrubber = ScrubberConfig {
        enabled: true,
        profiles: vec![profile("a"), profile("b")],
        readiness_ca_cert: None,
    };
    let repo = Arc::new(MockRepository::new());
    let fake = Arc::new(Fake {
        repo: repo.clone(),
        pop: settings.pop.clone(),
        rows: Default::default(),
        other_matches: Default::default(),
        windows: Default::default(),
        sequence: AtomicU64::new(1),
        writes: AtomicUsize::new(0),
        queue_add: AtomicBool::new(false),
        queued: Default::default(),
    });
    let binding = repo
        .register_speaker_target(
            &settings.pop,
            &SpeakerTarget::from_config(&settings.bgp).unwrap(),
            false,
        )
        .await
        .unwrap();
    let inventory: crate::config::Inventory =
        crate::config::parse_yaml(include_str!("../../configs/inventory.yaml")).unwrap();
    let playbooks =
        crate::config::parse_yaml(include_str!("../../configs/playbooks.yaml")).unwrap();
    let state = AppState::new(
        settings,
        crate::config::Inventory::new(inventory.customers),
        playbooks,
        repo.clone(),
        fake.clone(),
        std::path::PathBuf::new(),
    )
    .unwrap()
    .with_speaker_binding(binding)
    .unwrap();
    (state, repo, fake)
}
fn request(profile: &str, host: u8) -> super::super::api::CreateDiversion {
    super::super::api::CreateDiversion {
        profile: profile.into(),
        scope: FlowSpecNlri {
            dst_prefix: format!("203.0.113.{host}/32"),
            protocol: Some(6),
            dst_ports: vec![443],
            ..Default::default()
        },
        ttl_seconds: 60,
        reason: "isolated fixture".into(),
        confirmation: None,
    }
}
async fn confirmed(
    state: &AppState,
    profile: &str,
    host: u8,
) -> super::super::api::CreateDiversion {
    let mut request = request(profile, host);
    let row = state
        .scrubber
        .prepare(state, &request, "admin")
        .await
        .unwrap();
    request.confirmation = Some(ScrubberController::confirmation(&row).unwrap());
    request
}
async fn ready(state: &AppState) {
    let mut runtime = state.scrubber.runtime.lock().await;
    runtime.initialized = true;
    runtime.epoch = state.fence.with_observation_epoch(|epoch| epoch);
    for profile in runtime.profiles.values_mut() {
        *profile = ProfileState {
            armed: true,
            ready: true,
            readiness: ReadinessState::Ready,
            valid_until: Some(Instant::now() + Duration::from_secs(10)),
            observed_at: Some(Utc::now()),
            latch_reason: None,
        };
    }
}

#[tokio::test]
async fn dry_run_sends_no_window_add_renew_or_delete() {
    let (state, repo, fake) = fixture(OperationMode::DryRun).await;
    let request = confirmed(&state, "a", 20).await;
    let row = state
        .scrubber
        .create(&state, &request, "admin")
        .await
        .unwrap();
    assert_eq!(row.status, DiversionStatus::Simulated);
    state.scrubber.tick(&state).await.unwrap();
    state
        .scrubber
        .withdraw(&state, row.id, "admin")
        .await
        .unwrap();
    assert_eq!(fake.writes.load(SeqCst), 0);
    assert!(
        repo.list_diversions(&state.settings.pop)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn startup_is_unarmed_and_confirmation_is_exact() {
    let (state, repo, fake) = fixture(OperationMode::Enforced).await;
    let mut request = confirmed(&state, "a", 20).await;
    assert!(
        state
            .scrubber
            .create(&state, &request, "admin")
            .await
            .is_err()
    );
    ready(&state).await;
    request.confirmation = Some("different target".into());
    assert!(
        state
            .scrubber
            .create(&state, &request, "admin")
            .await
            .is_err()
    );
    assert_eq!(fake.writes.load(SeqCst), 0);
    assert!(
        repo.list_diversions(&state.settings.pop)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test(start_paused = true)]
async fn ambiguous_add_keeps_exclusion_until_window_barrier_and_final_absence() {
    let (state, repo, fake) = fixture(OperationMode::Enforced).await;
    ready(&state).await;
    fake.queue_add.store(true, SeqCst);
    let request = confirmed(&state, "a", 20).await;
    let row = state
        .scrubber
        .create(&state, &request, "admin")
        .await
        .unwrap();
    assert_eq!(row.status, DiversionStatus::Withdrawing);
    assert_eq!(row.windows.len(), 1);
    assert!(!state.scrubber.profiles().await["a"].armed);
    let row = state
        .scrubber
        .withdraw(&state, row.id, "admin")
        .await
        .unwrap();
    assert_eq!(row.status, DiversionStatus::Withdrawing);
    // A late add can recreate the key before its original window ends.
    tokio::time::advance(Duration::from_secs(10)).await;
    fake.release().unwrap();
    assert_eq!(fake.rows.lock().unwrap().len(), 1);
    let other = state
        .scrubber
        .prepare(&state, &self::request("b", 20), "admin")
        .await
        .unwrap();
    assert!(
        repo.admit_diversion(&other, &profile("b"), &state.settings.quotas)
            .await
            .is_err()
    );
    let row = state
        .scrubber
        .withdraw(&state, row.id, "admin")
        .await
        .unwrap();
    assert_eq!(row.status, DiversionStatus::Withdrawing);
    tokio::time::advance(Duration::from_secs(20)).await;
    let row = state
        .scrubber
        .withdraw(&state, row.id, "admin")
        .await
        .unwrap();
    assert_eq!(row.status, DiversionStatus::Withdrawn);
    assert!(fake.rows.lock().unwrap().is_empty());
    assert!(
        repo.list_diversions(&state.settings.pop)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        !state.scrubber.profiles().await["a"].armed,
        "absence cannot automatically re-arm"
    );
}

#[tokio::test]
async fn failed_profile_cannot_renew_through_a_healthy_profile() {
    let (state, _repo, fake) = fixture(OperationMode::Enforced).await;
    ready(&state).await;
    let mut a = state
        .scrubber
        .create(&state, &confirmed(&state, "a", 20).await, "admin")
        .await
        .unwrap();
    let mut b = state
        .scrubber
        .create(&state, &confirmed(&state, "b", 21).await, "admin")
        .await
        .unwrap();
    assert_ne!(a.rule.owner, b.rule.owner);
    let mut runtime = state.scrubber.runtime.lock().await;
    runtime
        .profiles
        .get_mut("a")
        .unwrap()
        .latch("readiness lost");
    state
        .scrubber
        .drive(&state, &mut runtime, &mut a)
        .await
        .unwrap();
    state
        .scrubber
        .drive(&state, &mut runtime, &mut b)
        .await
        .unwrap();
    assert_eq!(a.status, DiversionStatus::Withdrawing);
    let inventory = fake.guarded_inventory().await.unwrap();
    assert!(!inventory.has_key(&a.rule.nlri));
    assert!(inventory.has_key(&b.rule.nlri));
}

#[tokio::test(start_paused = true)]
async fn an_expired_report_latches_even_when_fresh_readiness_later_returns() {
    let (state, _repo, fake) = fixture(OperationMode::Enforced).await;
    ready(&state).await;
    let mut row = state
        .scrubber
        .create(&state, &confirmed(&state, "a", 20).await, "admin")
        .await
        .unwrap();
    tokio::time::advance(Duration::from_secs(11)).await;
    // An authenticated status read must latch the stale authorization in memory.
    assert!(!state.scrubber.profiles().await["a"].armed);
    {
        let mut runtime = state.scrubber.runtime.lock().await;
        let profile = runtime.profiles.get_mut("a").unwrap();
        profile.ready = true;
        profile.readiness = ReadinessState::Ready;
        profile.valid_until = Some(Instant::now() + Duration::from_secs(10));
        state
            .scrubber
            .drive(&state, &mut runtime, &mut row)
            .await
            .unwrap();
    }
    assert_eq!(row.status, DiversionStatus::Withdrawing);
    assert!(fake.guarded_inventory().await.unwrap().is_empty());
    let writes = fake.writes.load(SeqCst);
    assert!(
        state
            .scrubber
            .create(&state, &confirmed(&state, "a", 21).await, "admin")
            .await
            .is_err()
    );
    assert_eq!(
        fake.writes.load(SeqCst),
        writes,
        "fresh reports never re-arm a latched profile"
    );
}

#[tokio::test]
async fn storage_and_fence_loss_stop_renewal_and_latch_in_memory() {
    let (state, repo, fake) = fixture(OperationMode::Enforced).await;
    ready(&state).await;
    state
        .scrubber
        .create(&state, &confirmed(&state, "a", 20).await, "admin")
        .await
        .unwrap();
    let writes = fake.writes.load(SeqCst);
    repo.fail_diversion_reads.store(true, SeqCst);
    assert!(state.scrubber.tick(&state).await.is_err());
    assert!(!state.scrubber.profiles().await["a"].armed);
    assert_eq!(fake.writes.load(SeqCst), writes);
    repo.fail_diversion_reads.store(false, SeqCst);
    ready(&state).await;
    state.fence.set(false);
    state.scrubber.tick(&state).await.unwrap();
    assert!(!state.scrubber.profiles().await["a"].armed);
    assert_eq!(fake.writes.load(SeqCst), writes);
}

#[tokio::test(start_paused = true)]
async fn late_admission_from_an_old_controller_or_epoch_is_drained_without_add() {
    for previous_process in [true, false] {
        let (state, repo, fake) = fixture(OperationMode::Enforced).await;
        ready(&state).await;
        let mut late = state
            .scrubber
            .prepare(&state, &request("a", 20), "original-admin")
            .await
            .unwrap();
        if previous_process {
            let old_controller = ScrubberController::new(&state.settings).unwrap();
            late.controller_incarnation = old_controller.incarnation;
        } else {
            state.fence.set(false);
            state.fence.set(true);
        }
        // The new controller has already checked an empty durable inventory.
        ready(&state).await;
        let mut row = repo
            .admit_diversion(&late, &profile("a"), &state.settings.quotas)
            .await
            .unwrap();
        let mut runtime = state.scrubber.runtime.lock().await;
        state
            .scrubber
            .drive(&state, &mut runtime, &mut row)
            .await
            .unwrap();
        assert_eq!(row.status, DiversionStatus::Withdrawing);
        assert!(
            row.windows.is_empty(),
            "late commits never receive new authorization"
        );
        assert!(fake.guarded_inventory().await.unwrap().is_empty());
        assert!(fake.windows.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn unknown_same_owner_inventory_stops_renewal_without_deleting_foreign_intent() {
    let (state, _repo, fake) = fixture(OperationMode::Enforced).await;
    ready(&state).await;
    let a = state
        .scrubber
        .create(&state, &confirmed(&state, "a", 20).await, "admin")
        .await
        .unwrap();
    let mut unknown = a.rule.clone();
    unknown.nlri.dst_prefix = "203.0.113.99/32".into();
    unknown.revision += 999;
    fake.rows.lock().unwrap().insert(
        unknown.nlri.compute_hash(),
        (unknown.clone(), Instant::now() + Duration::from_secs(30)),
    );
    let writes = fake.writes.load(SeqCst);
    let b = state
        .scrubber
        .create(&state, &confirmed(&state, "a", 21).await, "admin")
        .await
        .unwrap();
    assert_eq!(b.status, DiversionStatus::Withdrawing);
    assert!(!state.scrubber.profiles().await["a"].armed);
    assert_eq!(
        fake.writes.load(SeqCst),
        writes,
        "unknown owned state cannot receive a lease renewal"
    );
    let observed = fake.guarded_inventory().await.unwrap();
    assert!(
        observed
            .iter()
            .any(|entry| entry.rule.same_admission(&unknown)),
        "untracked intent is retained for expiry, never broadly deleted"
    );
}

#[tokio::test]
async fn untracked_local_victim_overlaps_refuse_diversion_without_touching_foreign_rules() {
    for (prefix, guarded) in [
        ("203.0.113.20/32", false),
        ("203.0.113.0/24", false),
        ("203.0.113.20/32", true),
    ] {
        let (state, _repo, fake) = fixture(OperationMode::Enforced).await;
        ready(&state).await;
        let foreign = FlowSpecNlri {
            dst_prefix: prefix.into(),
            protocol: Some(17),
            dst_ports: vec![53],
            ..Default::default()
        };
        if guarded {
            let rule = GuardedRule {
                nlri: foreign.clone(),
                target: "192.0.2.98".parse().unwrap(),
                owner: "another-tool".into(),
                revision: 999,
            };
            fake.rows.lock().unwrap().insert(
                foreign.compute_hash(),
                (rule, Instant::now() + Duration::from_secs(30)),
            );
        } else {
            fake.other_matches.lock().unwrap().push(foreign.clone());
        }
        let row = state
            .scrubber
            .create(&state, &confirmed(&state, "a", 20).await, "admin")
            .await
            .unwrap();
        assert_eq!(row.status, DiversionStatus::Withdrawing);
        assert_eq!(
            fake.writes.load(SeqCst),
            0,
            "a different selector for the same victim cannot bypass exclusion"
        );
        assert!(fake.guarded_inventory().await.unwrap().has_key(&foreign));
        assert!(!state.scrubber.profiles().await["a"].armed);
    }
    let (state, _repo, fake) = fixture(OperationMode::Enforced).await;
    ready(&state).await;
    fake.other_matches.lock().unwrap().push(FlowSpecNlri {
        dst_prefix: "203.0.113.21/32".into(),
        ..Default::default()
    });
    let row = state
        .scrubber
        .create(&state, &confirmed(&state, "a", 20).await, "admin")
        .await
        .unwrap();
    assert_eq!(
        row.status,
        DiversionStatus::Active,
        "unaffected victims remain independent"
    );
}

#[tokio::test(start_paused = true)]
async fn withdrawal_retries_preserve_the_requesting_operator() {
    let (state, repo, _fake) = fixture(OperationMode::Enforced).await;
    ready(&state).await;
    let mut updates = state.ws_broadcast.subscribe();
    let row = state
        .scrubber
        .create(&state, &confirmed(&state, "a", 20).await, "creator")
        .await
        .unwrap();
    let crate::ws::WsMessage::DiversionUpdated { diversion } = updates.try_recv().unwrap() else {
        panic!("admission must publish its durable diversion snapshot")
    };
    assert_eq!(diversion.id, row.id);
    assert_eq!(
        repo.get_diversion(diversion.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        diversion.status
    );
    let row = state
        .scrubber
        .withdraw(&state, row.id, "withdrawing-admin")
        .await
        .unwrap();
    assert_eq!(row.withdrawal_actor.as_deref(), Some("withdrawing-admin"));
    tokio::time::advance(Duration::from_secs(30)).await;
    let row = state
        .scrubber
        .withdraw(&state, row.id, "retrying-admin")
        .await
        .unwrap();
    assert_eq!(row.status, DiversionStatus::Withdrawn);
    let row = repo.get_diversion(row.id).await.unwrap().unwrap();
    assert_eq!(row.actor, "creator");
    assert_eq!(row.withdrawal_actor.as_deref(), Some("withdrawing-admin"));
    let audit = row.audit("scrubber_withdrawn");
    assert_eq!(audit.actor_id.as_deref(), Some("withdrawing-admin"));
    assert_eq!(
        audit.details["match"],
        serde_json::to_value(&row.rule.nlri).unwrap()
    );
}

#[tokio::test]
async fn fresh_safelist_prevents_repair_and_ordinary_admission_conflicts() {
    let (state, repo, _fake) = fixture(OperationMode::Enforced).await;
    ready(&state).await;
    let mut row = state
        .scrubber
        .create(&state, &confirmed(&state, "a", 20).await, "admin")
        .await
        .unwrap();
    repo.insert_safelist("203.0.113.20/32", "admin", None)
        .await
        .unwrap();
    let mut runtime = state.scrubber.runtime.lock().await;
    state
        .scrubber
        .drive(&state, &mut runtime, &mut row)
        .await
        .unwrap();
    assert_eq!(row.status, DiversionStatus::Withdrawing);
    let mut ordinary = Mitigation::from_intent(
        MitigationIntent {
            event_id: Uuid::new_v4(),
            customer_id: Some("cust_example".into()),
            service_id: None,
            pop: state.settings.pop.clone(),
            match_criteria: MatchCriteria {
                dst_prefix: "203.0.113.20/32".into(),
                ..Default::default()
            },
            action_type: ActionType::Discard,
            action_params: ActionParams::default(),
            ttl_seconds: 60,
            reason: "conflicting intent".into(),
        },
        "203.0.113.20".into(),
        AttackVector::Unknown,
    );
    ordinary.origin_mode = Some(OperationMode::Enforced);
    assert!(
        repo.admit_mitigation(
            &ordinary,
            &state.settings.quotas,
            &state.settings.blackhole,
            &crate::observability::CreationActor::Operator("admin".into())
        )
        .await
        .is_err()
    );
}

#[test]
fn readiness_rejects_stale_future_wrong_profile_and_policy_reports() {
    let now = Utc::now();
    let profile = profile("a");
    for case in 0..8 {
        let mut report = Readiness {
            profile: "a".into(),
            revision: profile.revision.clone(),
            policy_binding: profile.policy_binding.clone(),
            observed_at: now,
            valid_until: now + chrono::Duration::seconds(8),
            process_ready: true,
            filters_ready: true,
            target_reachable: true,
            capacity_available: true,
            canary_passed: true,
            export_isolated: true,
        };
        match case {
            0 => {}
            1 => report.profile = "b".into(),
            2 => report.revision = "old".into(),
            3 => report.policy_binding = "other".into(),
            4 => report.observed_at = now + chrono::Duration::seconds(3),
            5 => report.valid_until = now,
            6 => report.valid_until = now + chrono::Duration::seconds(11),
            7 => report.canary_passed = false,
            _ => unreachable!(),
        }
        let result = report.state(&profile, now);
        if case == 0 {
            assert!(result.unwrap().ready);
        } else if case == 7 {
            assert!(!result.unwrap().ready);
        } else {
            assert!(result.is_err(), "case {case}");
        }
    }
}

#[tokio::test]
async fn manual_api_refuses_arbitrary_targets_and_operator_role() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let (state, _repo, fake) = fixture(OperationMode::DryRun).await;
    let router = crate::api::create_test_router(state.clone());
    let body = serde_json::json!({"profile":"a","scope":{"dst_prefix":"203.0.113.20/32","protocol":6,"dst_ports":[443]},"ttl_seconds":60,"reason":"fixture","target":"192.0.2.1"});
    let response = router
        .oneshot(
            Request::post("/v1/diversions/preview")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(fake.writes.load(SeqCst), 0);
    let (mut state, _repo, fake) = fixture(OperationMode::DryRun).await;
    let inner = Arc::get_mut(&mut state).unwrap();
    inner.settings.http.auth.mode = crate::config::AuthMode::Bearer;
    inner.bearer_token = Some("fixture-token".into());
    let router = crate::api::create_test_router(state);
    let mut body = body;
    body.as_object_mut().unwrap().remove("target");
    let response = router
        .oneshot(
            Request::post("/v1/diversions/preview")
                .header("authorization", "Bearer fixture-token")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "detector/operator tokens cannot divert traffic"
    );
    assert_eq!(fake.writes.load(SeqCst), 0);
}

#[tokio::test]
async fn profile_shares_windows_within_the_speaker_cap_and_refuses_retargeting() {
    let (mut state, _repo, fake) = fixture(OperationMode::Enforced).await;
    let settings = &mut Arc::get_mut(&mut state).unwrap().settings;
    settings.scrubber.profiles[0].max_active = 100;
    settings.scrubber.profiles[0].max_new_per_minute = 100;
    settings.quotas.max_active_per_customer = 100;
    settings.quotas.max_active_per_pop = 100;
    settings.quotas.max_active_global = 100;
    settings.quotas.max_new_per_minute = 100;
    ready(&state).await;
    for host in 20..100 {
        let row = state
            .scrubber
            .create(&state, &confirmed(&state, "a", host).await, "admin")
            .await
            .unwrap();
        assert_eq!(
            row.status,
            DiversionStatus::Active,
            "all configured capacity stays usable"
        );
    }
    assert_eq!(fake.rows.lock().unwrap().len(), 80);
    assert!(
        fake.windows.lock().unwrap().len() <= 64,
        "live windows must remain within the released owner cap"
    );
    Arc::get_mut(&mut state).unwrap().settings.scrubber.profiles[0].ipv4_target =
        Some("192.0.2.98".parse().unwrap());
    assert!(
        ScrubberController::check_startup(&state).await.is_err(),
        "outstanding snapshots prevent retargeting"
    );
}

// Uses the repository's long-lived private transport certificate. macOS's
// platform verifier imposes additional certificate validity policy; qualify
// this Linux service's HTTPS transport in the Linux fixture environment.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn authenticated_https_readiness_refuses_redirects_large_bodies_and_bad_credentials() {
    use axum::{
        Router,
        http::{
            HeaderMap, StatusCode,
            header::{AUTHORIZATION, LOCATION},
        },
        response::IntoResponse,
        routing::get,
    };
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let (state, _repo, _fake) = fixture(OperationMode::Enforced).await;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let mode = Arc::new(AtomicUsize::new(0));
    let redirected = Arc::new(AtomicUsize::new(0));
    let expected = state.scrubber.tokens["a"].clone();
    let handler_mode = mode.clone();
    let redirect_count = redirected.clone();
    let router=Router::new().route("/readiness",get(move |headers:HeaderMap| {
        let mode=handler_mode.clone();let expected=expected.clone();
        async move {
            if headers.get(AUTHORIZATION).and_then(|value|value.to_str().ok())!=Some(format!("Bearer {expected}").as_str()) { return StatusCode::UNAUTHORIZED.into_response(); }
            match mode.load(SeqCst) {
                1=>(StatusCode::FOUND,[(LOCATION,"/must-not-follow")]).into_response(),
                2=>"x".repeat(5000).into_response(),
                _=>axum::Json(serde_json::json!({"profile":"a","revision":"fixture-v1","policy_binding":"fixture-policy-v1","observed_at":Utc::now(),"valid_until":Utc::now()+chrono::Duration::seconds(8),"process_ready":true,"filters_ready":true,"target_reachable":true,"capacity_available":true,"canary_passed":true,"export_isolated":true})).into_response(),
            }
        }
    })).route("/must-not-follow",get(move || { let count=redirect_count.clone();async move {count.fetch_add(1,SeqCst);StatusCode::OK} }));
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        include_bytes!("../bgp/testdata/transport-server-cert.pem").to_vec(),
        include_bytes!("../bgp/testdata/transport-server-key.pem").to_vec(),
    )
    .await
    .unwrap();
    let handle = axum_server::Handle::new();
    let server = axum_server::from_tcp_rustls(listener, tls)
        .unwrap()
        .handle(handle.clone())
        .serve(router.into_make_service());
    let server = tokio::spawn(server);
    let mut settings = state.settings.clone();
    settings.scrubber.readiness_ca_cert = Some(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/bgp/testdata/transport-ca.pem"),
    );
    let mut controller = ScrubberController::new(&settings).unwrap();
    let mut profile = profile("a");
    profile.readiness_url = format!("https://{address}/readiness");
    assert!(controller.probe(&profile).await.unwrap().ready);
    mode.store(1, SeqCst);
    assert!(controller.probe(&profile).await.is_err());
    assert_eq!(
        redirected.load(SeqCst),
        0,
        "credentials and requests never follow redirects"
    );
    mode.store(2, SeqCst);
    assert!(controller.probe(&profile).await.is_err());
    mode.store(0, SeqCst);
    controller.tokens.insert("a".into(), "wrong-token".into());
    assert!(controller.probe(&profile).await.is_err());
    handle.graceful_shutdown(Some(Duration::from_secs(1)));
    tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
