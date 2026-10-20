//! Owner-scoped injection lease (ADR 027, rustbgpd ADR-0141): the live
//! generation, held in memory only, its renewal, and the full leased re-add
//! after the owner's state is lost.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::time::Instant;

use crate::bgp::{FlowSpecAnnouncer, InjectionLeases, LeaseGeneration};
use crate::error::{PrefixdError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    /// No generation held: nothing leased was added since startup.
    None,
    Live,
    /// The last renewal failed, but the lease may still be live.
    RenewalFailing,
    /// The daemon refused the generation, or renewals failed for a whole lease.
    Expired,
    /// Dry-run: renewal is a speaker mutation, so the lease is never renewed
    /// and leased routes lapse within one lease.
    NotRenewing,
}

impl LeaseState {
    pub const ALL: [Self; 5] = [
        Self::None,
        Self::Live,
        Self::RenewalFailing,
        Self::Expired,
        Self::NotRenewing,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Live => "live",
            Self::RenewalFailing => "renewal_failing",
            Self::Expired => "expired",
            Self::NotRenewing => "not_renewing",
        }
    }
}

/// Authenticated operational health of the lease.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct LeaseHealth {
    pub owner: String,
    pub lease_seconds: u32,
    pub state: LeaseState,
    pub generation: Option<LeaseGeneration>,
    /// Controller time of the last renewal attempt.
    pub last_renewal_at: Option<DateTime<Utc>>,
    /// success, not_live or error.
    pub last_renewal_result: Option<&'static str>,
}

#[derive(Debug)]
struct Held {
    generation: Option<LeaseGeneration>,
    state: LeaseState,
    /// Last proof the lease was live: a successful renewal or leased add.
    live_at: Option<Instant>,
    last_renewal: Option<(DateTime<Utc>, &'static str)>,
}

/// One per controller. Every leased add and renewal uses its owner and
/// `lease_seconds`, because any leased add moves the owner's whole deadline.
#[derive(Debug)]
pub struct LeaseKeeper {
    owner: String,
    lease_seconds: u32,
    held: Mutex<Held>,
    readd: AtomicBool,
    readd_requested: tokio::sync::Notify,
    /// False in dry-run, which sends no speaker mutation.
    renewing: bool,
}

impl LeaseKeeper {
    /// Starts with a full re-add pending: after a restart every active leased
    /// route is re-added under its recorded owner and joins the live lease.
    pub fn new(owner: String, lease_seconds: u32) -> Self {
        let keeper = Self {
            owner,
            lease_seconds,
            held: Mutex::new(Held {
                generation: None,
                state: LeaseState::None,
                live_at: None,
                last_renewal: None,
            }),
            readd: AtomicBool::new(true),
            readd_requested: tokio::sync::Notify::new(),
            renewing: true,
        };
        keeper.publish(LeaseState::None);
        keeper
    }

    /// Dry-run: the keeper probes and reports, but never renews.
    pub fn without_renewal(mut self) -> Self {
        self.renewing = false;
        self.publish(LeaseState::NotRenewing);
        self
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn lease_seconds(&self) -> u32 {
        self.lease_seconds
    }

    pub fn generation(&self) -> Option<LeaseGeneration> {
        self.held.lock().unwrap().generation
    }

    /// `lease_seconds / 3`: one lost renewal still leaves a third of the lease.
    pub fn renew_interval(&self) -> Duration {
        Duration::from_secs(u64::from(self.lease_seconds)) / 3
    }

    /// `ListInjectionLeases(owner)`: the capability probe, and the live
    /// generation after a prefixd restart. `false` when the daemon does not
    /// implement leases.
    pub async fn recover(&self, leases: &dyn InjectionLeases) -> Result<bool> {
        let Some(live) = leases.live_lease(&self.owner).await? else {
            return Ok(false);
        };
        if let Some(generation) = live {
            let mut held = self.held.lock().unwrap();
            if held.generation.is_none() {
                held.generation = Some(generation);
                held.state = LeaseState::Live;
                held.live_at = Some(Instant::now());
                drop(held);
                self.publish(self.state());
                tracing::info!(owner = %self.owner, ?generation, "adopted the live injection lease");
            }
        }
        Ok(true)
    }

    /// Every leased add returns the owner's live generation. A different one
    /// than held means the owner's earlier state may be gone: re-add it all.
    pub fn observe_add(&self, generation: LeaseGeneration) {
        let previous = {
            let mut held = self.held.lock().unwrap();
            held.state = LeaseState::Live;
            held.live_at = Some(Instant::now());
            held.generation.replace(generation)
        };
        self.publish(self.state());
        if previous.is_some_and(|previous| previous != generation) {
            tracing::warn!(owner = %self.owner, ?previous, ?generation,
                "injection lease generation changed; re-adding all active leased intent");
            self.request_readd();
        }
    }

    /// Wake the reconciler for a full leased re-add now, not on its next poll.
    pub fn request_readd(&self) {
        self.readd.store(true, Ordering::SeqCst);
        self.readd_requested.notify_one();
    }

    /// Keep a full re-add pending for the next pass without waking it.
    pub fn retry_readd(&self) {
        self.readd.store(true, Ordering::SeqCst);
    }

    pub fn take_readd(&self) -> bool {
        self.readd.swap(false, Ordering::SeqCst)
    }

    pub async fn readd_requested(&self) {
        self.readd_requested.notified().await
    }

    /// One `RenewLease` with its own deadline. It takes no lifecycle mutex and
    /// touches no database, and it never resurrects: a refused generation is
    /// dropped and a full re-add requested. A late reply is never a success.
    pub async fn renew_once(&self, leases: &dyn InjectionLeases) {
        if !self.renewing {
            return;
        }
        let Some(generation) = self.generation() else {
            return;
        };
        let result = tokio::time::timeout(
            self.renew_interval(),
            leases.renew_lease(&self.owner, generation, self.lease_seconds),
        )
        .await;
        let outcome = match result {
            Ok(Ok(true)) => "success",
            Ok(Ok(false)) => "not_live",
            // Not reached through the fenced speaker, which does not gate renewal.
            Ok(Err(PrefixdError::Standby)) => return,
            Ok(Err(error)) => {
                tracing::warn!(owner = %self.owner, error = %error, "injection lease renewal failed");
                "error"
            }
            Err(_) => {
                tracing::warn!(owner = %self.owner, "injection lease renewal missed its deadline");
                "error"
            }
        };
        crate::observability::metrics::INJECTION_LEASE_RENEWALS
            .with_label_values(&[outcome])
            .inc();
        let readd = {
            let mut held = self.held.lock().unwrap();
            held.last_renewal = Some((Utc::now(), outcome));
            // A newer generation from a concurrent add supersedes this result.
            if held.generation != Some(generation) {
                return;
            }
            match outcome {
                "success" => {
                    held.state = LeaseState::Live;
                    held.live_at = Some(Instant::now());
                    false
                }
                "not_live" => {
                    held.generation = None;
                    held.state = LeaseState::Expired;
                    true
                }
                _ => {
                    held.state = LeaseState::RenewalFailing;
                    false
                }
            }
        };
        self.publish(self.state());
        if readd {
            tracing::warn!(owner = %self.owner, ?generation,
                "injection lease is not live; re-adding all active leased intent");
            self.request_readd();
        }
    }

    fn state(&self) -> LeaseState {
        if !self.renewing {
            return LeaseState::NotRenewing;
        }
        let held = self.held.lock().unwrap();
        let lease = Duration::from_secs(u64::from(self.lease_seconds));
        match held.state {
            LeaseState::RenewalFailing
                if held
                    .live_at
                    .is_none_or(|live_at| live_at.elapsed() >= lease) =>
            {
                LeaseState::Expired
            }
            state => state,
        }
    }

    fn publish(&self, current: LeaseState) {
        for state in LeaseState::ALL {
            crate::observability::metrics::INJECTION_LEASE_STATE
                .with_label_values(&[state.as_str()])
                .set(f64::from(u8::from(state == current)));
        }
    }

    pub fn health(&self) -> LeaseHealth {
        let state = self.state();
        let held = self.held.lock().unwrap();
        LeaseHealth {
            owner: self.owner.clone(),
            lease_seconds: self.lease_seconds,
            state,
            generation: held.generation,
            last_renewal_at: held.last_renewal.map(|(at, _)| at),
            last_renewal_result: held.last_renewal.map(|(_, result)| result),
        }
    }
}

/// Sends one FlowSpec rule by its recorded owner: `AddLeasedFlowSpec` under
/// the controller's lease for an owned rule, `AddFlowSpec` for an unleased one.
/// A failure never switches between them.
pub async fn announce_flowspec(
    announcer: &dyn FlowSpecAnnouncer,
    rule: &crate::domain::FlowSpecRule,
    lease: Option<&LeaseKeeper>,
) -> Result<()> {
    if rule.owner.is_empty() {
        return announcer.announce(rule).await;
    }
    let lease = lease
        .filter(|lease| lease.owner() == rule.owner)
        .ok_or_else(|| {
            PrefixdError::Config(format!(
                "FlowSpec rule {} was added under injection owner {}, which this controller does not renew; \
                 it needs bgp.rustbgpd.leased_flowspec and the same POP and speaker target",
                rule.nlri.dst_prefix, rule.owner
            ))
        })?;
    let generation = announcer
        .announce_leased(rule, lease.lease_seconds())
        .await?;
    lease.observe_add(generation);
    Ok(())
}

/// The dedicated renewal task: about every `lease_seconds / 3` while a
/// generation is held, for the life of the process. It never waits for
/// reconciliation, the lifecycle mutex or the database.
pub async fn run_lease_renewals(
    keeper: std::sync::Arc<LeaseKeeper>,
    announcer: std::sync::Arc<dyn FlowSpecAnnouncer>,
) {
    let Some(leases) = announcer.injection_leases() else {
        return;
    };
    let mut interval = tokio::time::interval(keeper.renew_interval());
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        keeper.renew_once(leases).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::{BlackholeRoute, BlackholeSpeaker, FaultyBlackholes};
    use std::sync::atomic::Ordering::SeqCst;

    const OWNER: &str = "prefixd.pop-a.0123456789abcdef";

    fn route() -> BlackholeRoute {
        BlackholeRoute::new(
            "192.0.2.1/32".parse().unwrap(),
            "192.0.2.66".parse().unwrap(),
            vec![],
            vec![],
        )
        .unwrap()
        .with_owner(OWNER)
    }

    #[tokio::test]
    async fn renewal_success_keeps_the_generation_and_uses_lease_seconds() {
        let speaker = FaultyBlackholes::default();
        let keeper = LeaseKeeper::new(OWNER.into(), 45);
        assert!(keeper.take_readd(), "a restart re-adds once");
        // Nothing held: no renewal is sent.
        keeper.renew_once(&speaker).await;
        assert_eq!(speaker.renewals.load(SeqCst), 0);
        assert_eq!(keeper.health().state, LeaseState::None);
        let generation = speaker
            .announce_leased_blackhole(&route(), keeper.lease_seconds())
            .await
            .unwrap();
        keeper.observe_add(generation);
        assert!(!keeper.take_readd(), "a first add adopts without a re-add");
        for _ in 0..3 {
            keeper.renew_once(&speaker).await;
        }
        assert_eq!(*speaker.lease_seconds.lock().unwrap(), [45, 45, 45, 45]);
        let health = keeper.health();
        assert_eq!(health.state, LeaseState::Live);
        assert_eq!(health.generation, Some(generation));
        assert_eq!(health.last_renewal_result, Some("success"));
        assert!(!keeper.take_readd());
        assert_eq!(keeper.renew_interval(), Duration::from_secs(15));
    }

    #[tokio::test]
    async fn not_live_drops_the_generation_and_requests_a_full_readd_once() {
        let speaker = FaultyBlackholes::default();
        let keeper = LeaseKeeper::new(OWNER.into(), 60);
        keeper.take_readd();
        let generation = speaker
            .announce_leased_blackhole(&route(), 60)
            .await
            .unwrap();
        keeper.observe_add(generation);
        // The daemon restarted: renewal is refused and never resurrects the lease.
        speaker.inner.restart().await;
        keeper.renew_once(&speaker).await;
        assert!(keeper.take_readd());
        assert_eq!(keeper.generation(), None);
        assert_eq!(keeper.health().state, LeaseState::Expired);
        assert_eq!(keeper.health().last_renewal_result, Some("not_live"));
        // Nothing is renewed until a leased add starts the next generation.
        keeper.renew_once(&speaker).await;
        assert_eq!(speaker.renewals.load(SeqCst), 1);
        assert!(!keeper.take_readd());
        let next = speaker
            .announce_leased_blackhole(&route(), 60)
            .await
            .unwrap();
        assert_ne!(next, generation);
        keeper.observe_add(next);
        assert!(
            !keeper.take_readd(),
            "nothing was held, so the new generation is adopted"
        );
        assert_eq!(keeper.health().state, LeaseState::Live);
    }

    #[tokio::test]
    async fn a_different_generation_from_an_add_requests_a_full_readd() {
        let speaker = FaultyBlackholes::default();
        let keeper = LeaseKeeper::new(OWNER.into(), 60);
        keeper.take_readd();
        let generation = speaker
            .announce_leased_blackhole(&route(), 60)
            .await
            .unwrap();
        keeper.observe_add(generation);
        keeper.observe_add(generation);
        assert!(!keeper.take_readd(), "the same generation joins the lease");
        speaker.inner.expire_lease(OWNER).await;
        let next = speaker
            .announce_leased_blackhole(&route(), 60)
            .await
            .unwrap();
        keeper.observe_add(next);
        assert!(keeper.take_readd());
        // A late renewal of the old generation cannot undo the adopted one.
        assert_eq!(keeper.generation(), Some(next));
    }

    #[tokio::test]
    async fn failed_renewals_report_failing_then_expired() {
        let speaker = FaultyBlackholes::default();
        let keeper = LeaseKeeper::new(OWNER.into(), 5);
        keeper.take_readd();
        let generation = speaker
            .announce_leased_blackhole(&route(), 5)
            .await
            .unwrap();
        keeper.observe_add(generation);
        speaker.fail_renewals.store(true, SeqCst);
        keeper.renew_once(&speaker).await;
        assert_eq!(keeper.health().state, LeaseState::RenewalFailing);
        assert_eq!(keeper.health().last_renewal_result, Some("error"));
        assert!(
            !keeper.take_readd(),
            "a transport error is not proof of loss"
        );
        // A whole lease without proof of life is reported expired.
        keeper.held.lock().unwrap().live_at = Some(Instant::now() - Duration::from_secs(5));
        assert_eq!(keeper.health().state, LeaseState::Expired);
        assert_eq!(keeper.generation(), Some(generation));
    }

    /// Renewal never waits on the database or the fence: with the controller
    /// in standby, as a database outage forces it, the lease stays live.
    #[tokio::test]
    async fn renewal_continues_in_standby_and_without_the_database() {
        let inner = std::sync::Arc::new(crate::bgp::MockAnnouncer::new());
        let fence = std::sync::Arc::new(crate::fence::ControllerFence::new(true));
        let fenced = crate::fence::FencedAnnouncer::new(inner.clone(), fence.clone());
        let keeper = LeaseKeeper::new(OWNER.into(), 60);
        keeper.take_readd();
        keeper.observe_add(
            fenced
                .blackhole()
                .unwrap()
                .announce_leased_blackhole(&route(), 60)
                .await
                .unwrap(),
        );
        fence.set(false);
        for _ in 0..3 {
            keeper.renew_once(fenced.injection_leases().unwrap()).await;
            let health = keeper.health();
            assert_eq!(health.last_renewal_result, Some("success"), "{health:?}");
            assert_eq!(health.state, LeaseState::Live);
        }
        // Adds stay fenced.
        assert!(matches!(
            fenced
                .blackhole()
                .unwrap()
                .announce_leased_blackhole(&route(), 60)
                .await,
            Err(PrefixdError::Standby)
        ));
    }

    /// Dry-run reports the recovered lease honestly and never renews it.
    #[tokio::test]
    async fn dry_run_keeper_reports_not_renewing_and_sends_no_renewal() {
        let speaker = FaultyBlackholes::default();
        speaker
            .inner
            .announce_leased_blackhole(&route(), 60)
            .await
            .unwrap();
        let keeper = LeaseKeeper::new(OWNER.into(), 60).without_renewal();
        assert!(keeper.recover(&speaker).await.unwrap());
        assert!(keeper.generation().is_some());
        keeper.renew_once(&speaker).await;
        assert_eq!(speaker.renewals.load(SeqCst), 0);
        assert_eq!(keeper.health().state, LeaseState::NotRenewing);
    }

    #[tokio::test]
    async fn recovery_adopts_only_a_live_lease_and_reports_support() {
        let speaker = crate::bgp::MockAnnouncer::new();
        let keeper = LeaseKeeper::new(OWNER.into(), 60);
        assert!(keeper.recover(&speaker).await.unwrap());
        assert_eq!(keeper.generation(), None);
        let generation = speaker
            .announce_leased_blackhole(&route(), 60)
            .await
            .unwrap();
        let restarted = LeaseKeeper::new(OWNER.into(), 60);
        assert!(restarted.recover(&speaker).await.unwrap());
        assert_eq!(restarted.generation(), Some(generation));
        assert_eq!(restarted.health().state, LeaseState::Live);
        // Re-adding joins the recovered lease: no second re-add.
        assert!(restarted.take_readd());
        restarted.observe_add(
            speaker
                .announce_leased_blackhole(&route(), 60)
                .await
                .unwrap(),
        );
        assert!(!restarted.take_readd());
    }

    /// A renewal of g1 in flight while an add adopts g2: g1's late refusal
    /// neither drops g2 nor requests a second re-add.
    #[tokio::test]
    async fn a_late_refusal_of_a_superseded_generation_keeps_the_new_one() {
        struct Gated {
            inner: crate::bgp::MockAnnouncer,
            entered: tokio::sync::Notify,
            release: tokio::sync::Notify,
        }
        #[async_trait::async_trait]
        impl InjectionLeases for Gated {
            async fn live_lease(&self, owner: &str) -> Result<Option<Option<LeaseGeneration>>> {
                self.inner.live_lease(owner).await
            }
            async fn renew_lease(
                &self,
                owner: &str,
                generation: LeaseGeneration,
                lease_seconds: u32,
            ) -> Result<bool> {
                self.entered.notify_one();
                self.release.notified().await;
                self.inner
                    .renew_lease(owner, generation, lease_seconds)
                    .await
            }
            fn lease_confirmed(&self) -> bool {
                true
            }
        }
        let speaker = Gated {
            inner: crate::bgp::MockAnnouncer::new(),
            entered: Default::default(),
            release: Default::default(),
        };
        let keeper = LeaseKeeper::new(OWNER.into(), 60);
        keeper.take_readd();
        let first = speaker
            .inner
            .announce_leased_blackhole(&route(), 60)
            .await
            .unwrap();
        keeper.observe_add(first);
        let readd = async {
            speaker.entered.notified().await;
            speaker.inner.expire_lease(OWNER).await;
            let next = speaker
                .inner
                .announce_leased_blackhole(&route(), 60)
                .await
                .unwrap();
            keeper.observe_add(next);
            assert!(keeper.take_readd(), "the changed generation re-adds once");
            speaker.release.notify_one();
            next
        };
        let ((), next) = tokio::join!(keeper.renew_once(&speaker), readd);
        assert_ne!(next, first);
        assert_eq!(keeper.generation(), Some(next));
        assert_eq!(keeper.health().state, LeaseState::Live);
        assert!(!keeper.take_readd());
    }
}
