//! Owner-scoped injection lease (ADR 027, rustbgpd ADR-0141): the live
//! generation, held in memory only, its renewal, the full leased re-add after
//! the owner's state is lost, and the TTL bound that keeps a database outage
//! from renewing leased routes past every TTL (ADR 003).

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::time::Instant;

use crate::bgp::{FlowSpecAnnouncer, InjectionLeases, LeaseGeneration, RetryPolicy};
use crate::error::{PrefixdError, Result};

use super::{ActionType, Mitigation};

const RESTART_PROBE_INTERVAL: Duration = Duration::from_secs(2);

/// `LeaseHealth::renewal_stopped` value when the TTL bound, not a failure,
/// stopped renewal.
const TTL_BOUND: &str = "ttl_bound";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    /// No generation held: nothing leased was added since startup.
    None,
    Live,
    /// The last renewal failed, but the lease may still be live.
    RenewalFailing,
    /// The daemon refused the generation, renewals failed for a whole lease,
    /// or a lease has passed since renewal stopped at the TTL bound.
    Expired,
    /// Dry-run: renewal is a speaker mutation, so the lease is never renewed
    /// and leased routes lapse within one lease.
    NotRenewing,
    /// This controller is standby and stopped renewing at the TTL bound, so
    /// it cannot tell whether the active controller keeps the lease live.
    Standby,
}

impl LeaseState {
    pub const ALL: [Self; 6] = [
        Self::None,
        Self::Live,
        Self::RenewalFailing,
        Self::Expired,
        Self::NotRenewing,
        Self::Standby,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Live => "live",
            Self::RenewalFailing => "renewal_failing",
            Self::Expired => "expired",
            Self::NotRenewing => "not_renewing",
            Self::Standby => "standby",
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
    /// Local estimate from the last live observation, not remote installation
    /// evidence. Zero when expired; unknown with no lease, in dry-run or standby.
    pub remaining_seconds: Option<u64>,
    /// A held live or failing lease has missed two renewal intervals, or
    /// renewal stopped at the TTL bound. This does not prove remote expiry.
    pub renewal_overdue: bool,
    /// Local desired leased intent, not the remote RIB. Unknown until a
    /// successful inventory or committed leased write; failed reads preserve it.
    pub has_leased_intent: Option<bool>,
    /// Controller time of the last renewal attempt.
    pub last_renewal_at: Option<DateTime<Utc>>,
    /// success, not_live or error.
    pub last_renewal_result: Option<&'static str>,
    /// Latest `expires_at` of the routes this owner holds, from the last
    /// successful leased-intent read and every leased admission or extension
    /// committed since; renewal stops one margin after it. An empty leased set
    /// reports the read, and `None` means nothing has refreshed it since
    /// startup, when renewal is bounded to one margin after startup.
    pub renew_until: Option<DateTime<Utc>>,
    /// `ttl_bound` once renewal of a held generation stopped one margin after
    /// `renew_until`; `None` while renewal continues, with no generation held
    /// and in dry-run, which never renews at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renewal_stopped: Option<&'static str>,
}

/// One leased-intent deadline: the monotonic instant renewal checks, and the
/// wall clock it came from.
#[derive(Debug, Clone, Copy)]
struct RenewUntil {
    deadline: Instant,
    at: DateTime<Utc>,
}

impl RenewUntil {
    /// `None` (an empty leased set) bounds renewal to now. A past expiry, such
    /// as a row awaiting withdrawal, keeps its past deadline, so rereading it
    /// never grants a fresh margin; one older than the monotonic clock can
    /// represent falls back to `floor`.
    fn from_expiry(expires_at: Option<DateTime<Utc>>, floor: Instant) -> Self {
        let (now, instant) = (Utc::now(), Instant::now());
        let Some(expires_at) = expires_at else {
            return Self {
                deadline: instant,
                at: now,
            };
        };
        let deadline = match (expires_at - now).to_std() {
            Ok(remaining) => instant + remaining,
            Err(_) => (now - expires_at)
                .to_std()
                .ok()
                .and_then(|overdue| instant.checked_sub(overdue))
                .unwrap_or(floor)
                .min(instant),
        };
        Self {
            deadline,
            at: expires_at,
        }
    }

    fn later(self, other: Option<Self>) -> Self {
        match other {
            Some(other) if other.deadline > self.deadline => other,
            _ => self,
        }
    }
}

#[derive(Debug)]
struct Held {
    generation: Option<LeaseGeneration>,
    state: LeaseState,
    /// Last proof the lease was live: a successful renewal or leased add.
    live_at: Option<Instant>,
    last_renewal: Option<(DateTime<Utc>, &'static str)>,
    /// Latest leased-intent expiry a successful read saw, raised by every
    /// leased write since. Renewal stops one margin after it; `None` before
    /// the first read or write bounds it to startup.
    renew_until: Option<RenewUntil>,
    /// Leased writes since the last read was observed, so a read whose
    /// snapshot predates a write cannot lower the bound below it.
    written_since_read: Option<RenewUntil>,
    has_leased_intent: Option<bool>,
    /// Renewal stopped at the TTL bound and logged its one warning.
    ttl_bound: bool,
}

/// One per controller. Every leased add and renewal uses its owner and
/// `lease_seconds`, because any leased add moves the owner's whole deadline.
#[derive(Debug)]
pub struct LeaseKeeper {
    owner: String,
    lease_seconds: u32,
    /// How long renewal continues after `renew_until`:
    /// `max(lease, reconciliation interval + lease / 3)`, so a healthy
    /// reconciler always reads, and withdraws an expired row, before it stops.
    margin: Duration,
    /// Process start: renewal without a successful read is bounded to one
    /// margin after it.
    started: Instant,
    held: Mutex<Held>,
    readd: AtomicBool,
    readd_requested: tokio::sync::Notify,
    /// Wakes renewal at once when the bound is refreshed after a stop.
    renew_requested: tokio::sync::Notify,
    fence: Option<std::sync::Arc<crate::fence::ControllerFence>>,
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
            margin: Duration::from_secs(u64::from(lease_seconds)),
            started: Instant::now(),
            held: Mutex::new(Held {
                generation: None,
                state: LeaseState::None,
                live_at: None,
                last_renewal: None,
                renew_until: None,
                written_since_read: None,
                has_leased_intent: None,
                ttl_bound: false,
            }),
            readd: AtomicBool::new(true),
            readd_requested: tokio::sync::Notify::new(),
            renew_requested: tokio::sync::Notify::new(),
            fence: None,
            renewing: true,
        };
        keeper.publish(LeaseState::None);
        keeper
    }

    /// Renewal continues `max(lease, interval + lease / 3)` past `renew_until`,
    /// so with `lease_seconds` shorter than the reconciliation interval a
    /// healthy controller still reads before renewal would stop.
    pub fn with_reconcile_interval(mut self, interval_seconds: u32) -> Self {
        let lease = Duration::from_secs(u64::from(self.lease_seconds));
        self.margin = lease.max(Duration::from_secs(u64::from(interval_seconds)) + lease / 3);
        self
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

    /// Scrape-time warning even if the renewal task stopped running. Two
    /// intervals leave one interval before a full lease since the last proof.
    pub fn renewal_overdue(&self) -> bool {
        let held = self.held.lock().unwrap();
        self.renewal_overdue_with_held(&held)
    }

    fn renewal_overdue_with_held(&self, held: &Held) -> bool {
        !self.renewing
            || held.generation.is_none()
            || self.stopped_at_bound(held)
            || held
                .live_at
                .is_none_or(|at| at.elapsed() >= self.renew_interval() * 2)
    }

    fn lease_duration(&self) -> Duration {
        Duration::from_secs(u64::from(self.lease_seconds))
    }

    /// One successful read of leased intent, from the database, refreshes the
    /// TTL bound to `latest_expiry`, the latest `expires_at` among the routes
    /// this owner holds, or to the read itself for an empty leased set.
    /// Leased writes since the previous observation still count, because the
    /// read's snapshot may predate them.
    ///
    /// Renewal is deliberately independent of the database and the fence, so
    /// this bound is what keeps a database outage from extending the lease
    /// past every TTL: renewal stops one margin after it and the speaker
    /// removes the routes within one more lease.
    // ponytail: one reader (the reconciliation task) observes at a time; a
    // second concurrent reader would need per-read write tokens.
    pub fn observe_intent_expiry(&self, latest_expiry: Option<DateTime<Utc>>) {
        let read = RenewUntil::from_expiry(latest_expiry, self.started);
        let mut held = self.held.lock().unwrap();
        let written = held.written_since_read.take();
        held.has_leased_intent = Some(latest_expiry.is_some() || written.is_some());
        held.renew_until = Some(read.later(written));
        self.resume(held);
    }

    /// A committed leased admission or TTL extension raises the bound to its
    /// `expires_at` at once, so a row written after the last read cannot lapse
    /// inside its TTL while the next read is late.
    pub fn observe_leased_write(&self, mitigation: &Mitigation) {
        if !leased_by(mitigation, &self.owner) {
            return;
        }
        let written = RenewUntil::from_expiry(Some(mitigation.expires_at), self.started);
        let mut held = self.held.lock().unwrap();
        held.has_leased_intent = Some(true);
        held.written_since_read = Some(written.later(held.written_since_read));
        held.renew_until = Some(written.later(held.renew_until));
        self.resume(held);
    }

    /// After a stop at the bound, a refreshed bound renews at once rather than
    /// on the next tick.
    fn resume(&self, mut held: std::sync::MutexGuard<'_, Held>) {
        if !self.renewing || self.stopped_at_bound(&held) || !std::mem::take(&mut held.ttl_bound) {
            return;
        }
        let renew_until = held.renew_until.map(|bound| bound.at);
        drop(held);
        tracing::info!(owner = %self.owner, ?renew_until,
            "injection lease renewal resumed after leased intent refreshed the TTL bound");
        self.renew_requested.notify_one();
        self.publish(self.state());
    }

    /// The controller fence, read directly so a fence loss is reported even
    /// while reconciliation is blocked: a standby that stopped at the bound
    /// reports `standby`, not `expired`.
    pub fn with_fence(mut self, fence: std::sync::Arc<crate::fence::ControllerFence>) -> Self {
        self.fence = Some(fence);
        self
    }

    fn standby(&self) -> bool {
        self.fence.as_ref().is_some_and(|fence| !fence.is_active())
    }

    /// The outage has outlasted every leased route's TTL, so renewal stops
    /// rather than propping the routes up. A renewal is sent only if its own
    /// deadline ends by `renew_until + margin`, so no renewal the speaker
    /// accepts lands after that cutoff. Without a read or write, the bound is
    /// one margin after startup.
    fn stopped_at_bound(&self, held: &Held) -> bool {
        Instant::now() + self.renew_interval() > self.cutoff(held)
    }

    /// One lease after the cutoff has also passed: no leased route can still
    /// be within an accepted renewal, whatever the speaker held.
    fn lapsed_at_bound(&self, held: &Held) -> bool {
        Instant::now() > self.cutoff(held) + self.lease_duration()
    }

    fn cutoff(&self, held: &Held) -> Instant {
        held.renew_until
            .map_or(self.started, |bound| bound.deadline)
            + self.margin
    }

    /// One warning per outage, naming the bound rather than a renewal failure.
    fn report_ttl_bound(&self) {
        let renew_until = {
            let mut held = self.held.lock().unwrap();
            if std::mem::replace(&mut held.ttl_bound, true) {
                return;
            }
            held.renew_until.map(|bound| bound.at)
        };
        tracing::warn!(owner = %self.owner, renew_until = ?renew_until,
            "injection lease renewal stopped at the TTL bound: no successful database read \
             refreshed leased intent, so the speaker removes leased routes within one lease");
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

    /// Detect a daemon restart without waiting for renewal. Only the held
    /// generation captured before the read can be invalidated by its reply.
    pub async fn probe_restart(&self, leases: &dyn InjectionLeases) {
        let Some(generation) = self.generation() else {
            return;
        };
        let Ok(Ok(Some(incarnation))) =
            tokio::time::timeout(RESTART_PROBE_INTERVAL, leases.incarnation()).await
        else {
            return;
        };
        if incarnation == 0 || incarnation == generation.incarnation {
            return;
        }
        {
            let mut held = self.held.lock().unwrap();
            if held.generation != Some(generation) {
                return;
            }
            held.generation = None;
            held.state = LeaseState::Expired;
        }
        self.publish(self.state());
        tracing::warn!(owner = %self.owner, ?generation, incarnation,
            "speaker incarnation changed; re-adding all active leased intent");
        self.request_readd();
    }

    /// One `RenewLease` with its own deadline. It takes no lifecycle mutex and
    /// touches no database, and it never resurrects: a refused generation is
    /// dropped and a full re-add requested. Replies past the deadline fail;
    /// replies for superseded generations cannot restore the held lease.
    /// Renewal also stops at the TTL bound when no read refreshed it for a
    /// lease, so a database outage cannot outlive every TTL.
    pub async fn renew_once(&self, leases: &dyn InjectionLeases) {
        if !self.renewing {
            return;
        }
        let Some(generation) = self.generation() else {
            return;
        };
        if self.stopped_at_bound(&self.held.lock().unwrap()) {
            self.report_ttl_bound();
            self.publish(self.state());
            return;
        }
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
        self.state_with_held(&self.held.lock().unwrap())
    }

    fn state_with_held(&self, held: &Held) -> LeaseState {
        if !self.renewing {
            return LeaseState::NotRenewing;
        }
        let lease = self.lease_duration();
        match held.state {
            // A standby stopped at the bound cannot read leased intent; the
            // active controller may still keep the lease live.
            LeaseState::Live | LeaseState::RenewalFailing
                if self.standby() && self.stopped_at_bound(held) =>
            {
                LeaseState::Standby
            }
            LeaseState::RenewalFailing
                if held
                    .live_at
                    .is_none_or(|live_at| live_at.elapsed() >= lease) =>
            {
                LeaseState::Expired
            }
            // Renewal stopped at the TTL bound and even the last possible
            // renewal has lapsed: the speaker holds none of the leased routes.
            LeaseState::Live | LeaseState::RenewalFailing if self.lapsed_at_bound(held) => {
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

    /// The lease-state gauge is published where state changes and on every
    /// renewal tick, not here.
    pub fn health(&self) -> LeaseHealth {
        let held = self.held.lock().unwrap();
        let state = self.state_with_held(&held);
        // Only a held generation has a renewal to stop, as in `renew_once`.
        let stopped = self.renewing && held.generation.is_some() && self.stopped_at_bound(&held);
        LeaseHealth {
            owner: self.owner.clone(),
            lease_seconds: self.lease_seconds,
            state,
            generation: held.generation,
            remaining_seconds: match state {
                LeaseState::Live | LeaseState::RenewalFailing => held
                    .live_at
                    .map(|at| self.lease_duration().saturating_sub(at.elapsed()).as_secs()),
                LeaseState::Expired => Some(0),
                LeaseState::None | LeaseState::NotRenewing | LeaseState::Standby => None,
            },
            renewal_overdue: matches!(state, LeaseState::Live | LeaseState::RenewalFailing)
                && self.renewal_overdue_with_held(&held),
            has_leased_intent: held.has_leased_intent,
            last_renewal_at: held.last_renewal.map(|(at, _)| at),
            last_renewal_result: held.last_renewal.map(|(_, result)| result),
            renew_until: held.renew_until.map(|bound| bound.at),
            renewal_stopped: stopped.then_some(TTL_BOUND),
        }
    }
}

/// The latest `expires_at` among the rows `owner` added under its injection
/// lease: FlowSpec rules by their recorded `injection_owner`, leased blackholes
/// by their frozen route's owner. Dry-run and pending rows are never speaker
/// state, so they cannot extend another route's TTL bound.
pub fn leased_expiry(mitigations: &[Mitigation], owner: &str) -> Option<DateTime<Utc>> {
    mitigations
        .iter()
        .filter(|mitigation| leased_by(mitigation, owner))
        .map(|mitigation| mitigation.expires_at)
        .max()
}

fn leased_by(mitigation: &Mitigation, owner: &str) -> bool {
    mitigation.is_active()
        && !mitigation.is_dry_run_origin()
        && recorded_owner(mitigation) == Some(owner)
}

/// The injection owner a row's route was added under; `None` when unleased.
fn recorded_owner(mitigation: &Mitigation) -> Option<&str> {
    let owner = match mitigation.action_type {
        ActionType::Blackhole => mitigation
            .action_params
            .blackhole
            .as_ref()
            .map(|rule| rule.owner.as_str())?,
        _ => mitigation.action_params.injection_owner.as_str(),
    };
    (!owner.is_empty()).then_some(owner)
}

/// Sends one FlowSpec rule by its recorded owner: `AddLeasedFlowSpec` under
/// the controller's lease for an owned rule, `AddFlowSpec` for an unleased one.
/// A failure never switches between them.
///
/// The caller states who is waiting. `RetryPolicy::Bounded` is for a caller
/// holding the lifecycle mutex: one attempt inside the interactive deadline,
/// with reconciliation repairing the durable intent from there.
pub async fn announce_flowspec(
    announcer: &dyn FlowSpecAnnouncer,
    rule: &crate::domain::FlowSpecRule,
    lease: Option<&LeaseKeeper>,
    policy: RetryPolicy,
) -> Result<()> {
    if rule.owner.is_empty() {
        return match policy {
            RetryPolicy::Bounded => announcer.announce_bounded(rule).await,
            RetryPolicy::Durable => announcer.announce(rule).await,
        };
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
    let generation = match policy {
        RetryPolicy::Bounded => {
            announcer
                .announce_leased_bounded(rule, lease.lease_seconds())
                .await?
        }
        RetryPolicy::Durable => {
            announcer
                .announce_leased(rule, lease.lease_seconds())
                .await?
        }
    };
    lease.observe_add(generation);
    Ok(())
}

/// Independent renewal and restart-probe loops, for the life of the process.
/// Neither waits for reconciliation, the lifecycle mutex or the database;
/// a stalled renewal cannot delay restart detection.
pub async fn run_lease_renewals(
    keeper: std::sync::Arc<LeaseKeeper>,
    announcer: std::sync::Arc<dyn FlowSpecAnnouncer>,
) {
    let Some(leases) = announcer.injection_leases() else {
        return;
    };
    let renewals = async {
        let mut interval = tokio::time::interval(keeper.renew_interval());
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = keeper.renew_requested.notified() => {}
            }
            keeper.renew_once(leases).await;
        }
    };
    let probes = async {
        let mut interval = tokio::time::interval(RESTART_PROBE_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            keeper.probe_restart(leases).await;
        }
    };
    tokio::join!(renewals, probes);
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

    #[derive(Default)]
    struct Probe {
        incarnation: Option<u64>,
        fail: bool,
        block: bool,
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    #[async_trait::async_trait]
    impl InjectionLeases for Probe {
        async fn incarnation(&self) -> Result<Option<u64>> {
            self.entered.notify_one();
            if self.block {
                self.release.notified().await;
            }
            if self.fail {
                Err(PrefixdError::Internal("probe failed".into()))
            } else {
                Ok(self.incarnation)
            }
        }
        async fn live_lease(&self, _: &str) -> Result<Option<Option<LeaseGeneration>>> {
            unreachable!()
        }
        async fn renew_lease(&self, _: &str, _: LeaseGeneration, _: u32) -> Result<bool> {
            unreachable!()
        }
        fn lease_confirmed(&self) -> bool {
            true
        }
    }

    #[tokio::test(start_paused = true)]
    async fn health_intent_observation_preserves_unknown_and_failed_reads() {
        let repo = std::sync::Arc::new(crate::db::MockRepository::new());
        let keeper = std::sync::Arc::new(LeaseKeeper::new(OWNER.into(), 60));
        let reconciler = crate::scheduler::ReconciliationLoop::new(
            repo.clone(),
            std::sync::Arc::new(crate::bgp::MockAnnouncer::new()),
            30,
            false,
        )
        .with_lease(keeper.clone());
        assert_eq!(keeper.health().has_leased_intent, None);
        repo.fail_active_reads.store(true, SeqCst);
        assert!(reconciler.reconcile().await.is_err());
        assert_eq!(keeper.health().has_leased_intent, None);
        repo.fail_active_reads.store(false, SeqCst);
        reconciler.reconcile().await.unwrap();
        assert_eq!(keeper.health().has_leased_intent, Some(false));
        repo.fail_active_reads.store(true, SeqCst);
        assert!(reconciler.reconcile().await.is_err());
        assert_eq!(keeper.health().has_leased_intent, Some(false));
        keeper.observe_leased_write(&leased_rule(300));
        assert_eq!(keeper.health().has_leased_intent, Some(true));
        assert!(reconciler.reconcile().await.is_err());
        assert_eq!(keeper.health().has_leased_intent, Some(true));
    }

    #[tokio::test(start_paused = true)]
    async fn health_countdown_uses_last_live_observation_and_recovers() {
        let speaker = FaultyBlackholes::default();
        let keeper = LeaseKeeper::new(OWNER.into(), 60);
        keeper.observe_intent_expiry(Some(Utc::now() + chrono::Duration::minutes(10)));
        assert_eq!(keeper.health().remaining_seconds, None);
        keeper.observe_add(
            speaker
                .announce_leased_blackhole(&route(), 60)
                .await
                .unwrap()
                .0,
        );
        assert_eq!(keeper.health().remaining_seconds, Some(60));
        tokio::time::advance(Duration::from_secs(20)).await;
        speaker.fail_renewals.store(true, SeqCst);
        keeper.renew_once(&speaker).await;
        assert_eq!(keeper.health().state, LeaseState::RenewalFailing);
        assert_eq!(keeper.health().remaining_seconds, Some(40));
        assert!(!keeper.health().renewal_overdue);
        tokio::time::advance(Duration::from_secs(20)).await;
        keeper.renew_once(&speaker).await;
        assert_eq!(keeper.health().last_renewal_result, Some("error"));
        assert_eq!(keeper.health().remaining_seconds, Some(20));
        assert!(keeper.health().renewal_overdue);
        tokio::time::advance(Duration::from_secs(20)).await;
        assert_eq!(keeper.health().state, LeaseState::Expired);
        assert_eq!(keeper.health().remaining_seconds, Some(0));
        speaker.fail_renewals.store(false, SeqCst);
        keeper.observe_add(
            speaker
                .announce_leased_blackhole(&route(), 60)
                .await
                .unwrap()
                .0,
        );
        assert_eq!(keeper.health().state, LeaseState::Live);
        assert_eq!(keeper.health().remaining_seconds, Some(60));
        tokio::time::advance(Duration::from_secs(20)).await;
        keeper.renew_once(&speaker).await;
        assert_eq!(keeper.health().last_renewal_result, Some("success"));
        assert_eq!(keeper.health().remaining_seconds, Some(60));
    }

    #[tokio::test(start_paused = true)]
    async fn restart_probe_only_invalidates_a_known_changed_incarnation() {
        let generation = LeaseGeneration {
            incarnation: 42,
            sequence: 1,
        };
        for (incarnation, fail, block) in [
            (Some(42), false, false),
            (Some(0), false, false),
            (None, false, false),
            (Some(43), true, false),
            (Some(43), false, true),
            (Some(43), false, false),
        ] {
            let keeper = LeaseKeeper::new(OWNER.into(), 60);
            keeper.take_readd();
            keeper.observe_add(generation);
            let live_at = keeper.held.lock().unwrap().live_at;
            let probe = Probe {
                incarnation,
                fail,
                block,
                ..Default::default()
            };
            let changed = incarnation == Some(43) && !fail && !block;
            keeper.probe_restart(&probe).await;
            assert_eq!(
                keeper.generation(),
                if changed { None } else { Some(generation) }
            );
            assert_eq!(
                keeper.health().state,
                if changed {
                    LeaseState::Expired
                } else {
                    LeaseState::Live
                }
            );
            assert_eq!(keeper.take_readd(), changed);
            assert_eq!(keeper.held.lock().unwrap().live_at, live_at);
            assert!(keeper.health().last_renewal_at.is_none());
            assert!(keeper.health().last_renewal_result.is_none());
            if changed {
                keeper.readd_requested().await;
                keeper.probe_restart(&probe).await;
                assert!(
                    !keeper.take_readd(),
                    "no generation means no repeated recovery"
                );
            }
        }
    }

    #[tokio::test]
    async fn late_restart_probe_cannot_invalidate_a_concurrent_add_generation() {
        for next in [
            LeaseGeneration {
                incarnation: 42,
                sequence: 2,
            },
            LeaseGeneration {
                incarnation: 43,
                sequence: 1,
            },
        ] {
            let keeper = LeaseKeeper::new(OWNER.into(), 60);
            keeper.take_readd();
            keeper.observe_add(LeaseGeneration {
                incarnation: 42,
                sequence: 1,
            });
            let probe = Probe {
                incarnation: Some(43),
                block: true,
                ..Default::default()
            };
            let add = async {
                probe.entered.notified().await;
                keeper.observe_add(next);
                assert!(keeper.take_readd());
                probe.release.notify_one();
            };
            tokio::join!(keeper.probe_restart(&probe), add);
            assert_eq!(keeper.generation(), Some(next));
            assert_eq!(keeper.health().state, LeaseState::Live);
            assert!(!keeper.take_readd());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn restart_probe_does_not_restore_failed_renewal_health() {
        let speaker = FaultyBlackholes::default();
        speaker.inner.restart().await;
        let keeper = LeaseKeeper::new(OWNER.into(), 60);
        keeper.take_readd();
        keeper.observe_add(
            speaker
                .announce_leased_blackhole(&route(), 60)
                .await
                .unwrap()
                .0,
        );
        speaker.fail_renewals.store(true, SeqCst);
        keeper.renew_once(&speaker).await;
        let before = keeper.health();
        let live_at = keeper.held.lock().unwrap().live_at;
        tokio::time::advance(Duration::from_secs(60)).await;
        keeper.probe_restart(&speaker).await;
        assert_eq!(keeper.health().state, LeaseState::Expired);
        assert_eq!(keeper.health().last_renewal_at, before.last_renewal_at);
        assert_eq!(keeper.health().last_renewal_result, Some("error"));
        assert_eq!(keeper.held.lock().unwrap().live_at, live_at);
        assert!(!keeper.take_readd());
    }

    #[tokio::test(start_paused = true)]
    async fn restart_probe_runs_while_renewal_is_blocked_and_late_success_stays_expired() {
        let speaker = std::sync::Arc::new(FaultyBlackholes::default());
        let keeper = std::sync::Arc::new(LeaseKeeper::new(OWNER.into(), 60));
        keeper.take_readd();
        keeper.observe_add(
            speaker
                .announce_leased_blackhole(&route(), 60)
                .await
                .unwrap()
                .0,
        );
        speaker.block_renewals.store(true, SeqCst);
        let task = tokio::spawn(run_lease_renewals(keeper.clone(), speaker.clone()));
        speaker.renewal_entered.notified().await;
        speaker.inner.restart().await;
        tokio::time::advance(RESTART_PROBE_INTERVAL).await;
        tokio::time::timeout(Duration::from_millis(1), keeper.readd_requested())
            .await
            .unwrap();
        assert_eq!(speaker.renewals.load(SeqCst), 1);
        assert_eq!(keeper.generation(), None);
        assert_eq!(keeper.health().state, LeaseState::Expired);
        assert!(
            keeper.health().last_renewal_result.is_none(),
            "renewal still in flight"
        );
        assert!(keeper.take_readd());
        speaker.release_renewal.notify_one();
        tokio::task::yield_now().await;
        assert_eq!(keeper.health().last_renewal_result, Some("success"));
        assert_eq!(
            keeper.generation(),
            None,
            "late renewal cannot restore lost state"
        );
        assert_eq!(keeper.health().state, LeaseState::Expired);
        assert!(!keeper.take_readd());
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
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
            .unwrap()
            .0;
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
            .unwrap()
            .0;
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
            .unwrap()
            .0;
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
            .unwrap()
            .0;
        keeper.observe_add(generation);
        keeper.observe_add(generation);
        assert!(!keeper.take_readd(), "the same generation joins the lease");
        speaker.inner.expire_lease(OWNER).await;
        let next = speaker
            .announce_leased_blackhole(&route(), 60)
            .await
            .unwrap()
            .0;
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
            .unwrap()
            .0;
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

    /// A database outage that outlasts every leased TTL stops renewal one
    /// lease after the last read's latest `expires_at`, and says so without
    /// reporting a failure. rustbgpd removes the routes within one more lease.
    #[tokio::test(start_paused = true)]
    async fn renewal_stops_one_lease_after_the_last_leased_ttl() {
        let speaker = FaultyBlackholes::default();
        let keeper = LeaseKeeper::new(OWNER.into(), 60);
        keeper.take_readd();
        keeper.observe_add(
            speaker
                .announce_leased_blackhole(&route(), 60)
                .await
                .unwrap()
                .0,
        );
        let expires_at = Utc::now() + chrono::Duration::seconds(300);
        keeper.observe_intent_expiry(Some(expires_at));
        assert_eq!(keeper.health().renew_until, Some(expires_at));
        assert_eq!(keeper.health().renewal_stopped, None);
        // Every leased TTL still tolerates the outage: renewal continues.
        tokio::time::advance(Duration::from_secs(300)).await;
        keeper.renew_once(&speaker).await;
        assert_eq!(speaker.renewals.load(SeqCst), 1);
        let health = keeper.health();
        assert_eq!(health.renewal_stopped, None);
        assert_eq!(health.state, LeaseState::Live);
        // One lease past the last leased TTL: renewal stops, without a failed
        // attempt and without a failure result.
        tokio::time::advance(Duration::from_secs(61)).await;
        keeper.renew_once(&speaker).await;
        assert_eq!(speaker.renewals.load(SeqCst), 1);
        let health = keeper.health();
        assert_eq!(health.renewal_stopped, Some("ttl_bound"));
        assert_eq!(health.last_renewal_result, Some("success"));
        assert_eq!(health.state, LeaseState::Live);
        // One lease after the last possible renewal, the speaker holds none.
        tokio::time::advance(Duration::from_secs(61)).await;
        assert_eq!(keeper.health().state, LeaseState::Expired);
    }

    /// A read that finds no leased intent still bounds renewal: an empty set
    /// must not keep a lease alive indefinitely.
    #[tokio::test(start_paused = true)]
    async fn an_empty_leased_read_bounds_renewal_to_one_lease() {
        let speaker = FaultyBlackholes::default();
        let keeper = LeaseKeeper::new(OWNER.into(), 60);
        keeper.take_readd();
        keeper.observe_add(
            speaker
                .announce_leased_blackhole(&route(), 60)
                .await
                .unwrap()
                .0,
        );
        let read_at = Utc::now();
        keeper.observe_intent_expiry(None);
        let reported = keeper.health().renew_until.expect("the read is recorded");
        assert!(reported >= read_at && reported <= Utc::now());
        // The last renewal must end, deadline included, by the cutoff.
        tokio::time::advance(Duration::from_secs(39)).await;
        keeper.renew_once(&speaker).await;
        assert_eq!(speaker.renewals.load(SeqCst), 1);
        tokio::time::advance(Duration::from_secs(2)).await;
        keeper.renew_once(&speaker).await;
        assert_eq!(speaker.renewals.load(SeqCst), 1);
        assert_eq!(keeper.health().renewal_stopped, Some("ttl_bound"));
    }

    /// A new successful read refreshes the bound, so recovery resumes normal
    /// renewal of the same generation.
    #[tokio::test(start_paused = true)]
    async fn a_successful_read_resumes_renewal_after_the_ttl_bound() {
        let speaker = FaultyBlackholes::default();
        let keeper = LeaseKeeper::new(OWNER.into(), 60);
        keeper.take_readd();
        let generation = speaker
            .announce_leased_blackhole(&route(), 60)
            .await
            .unwrap()
            .0;
        keeper.observe_add(generation);
        keeper.observe_intent_expiry(Some(Utc::now() + chrono::Duration::seconds(30)));
        tokio::time::advance(Duration::from_secs(91)).await;
        keeper.renew_once(&speaker).await;
        assert_eq!(speaker.renewals.load(SeqCst), 0);
        assert_eq!(keeper.health().renewal_stopped, Some("ttl_bound"));
        keeper.observe_intent_expiry(Some(Utc::now() + chrono::Duration::seconds(600)));
        assert_eq!(keeper.health().renewal_stopped, None);
        keeper.renew_once(&speaker).await;
        assert_eq!(speaker.renewals.load(SeqCst), 1);
        let health = keeper.health();
        assert_eq!(health.state, LeaseState::Live);
        assert_eq!(health.generation, Some(generation));
        assert_eq!(health.last_renewal_result, Some("success"));
    }

    /// A standby renews without the fence, as the database outage forces, but
    /// follows the same bound: two processes cannot hold routes past every TTL.
    #[tokio::test(start_paused = true)]
    async fn standby_renewal_stops_at_the_ttl_bound() {
        let inner = std::sync::Arc::new(FaultyBlackholes::default());
        let fence = std::sync::Arc::new(crate::fence::ControllerFence::new(false));
        let fenced = crate::fence::FencedAnnouncer::new(inner.clone(), fence.clone());
        let keeper = LeaseKeeper::new(OWNER.into(), 60).with_fence(fence.clone());
        keeper.take_readd();
        keeper.observe_add(
            inner
                .announce_leased_blackhole(&route(), 60)
                .await
                .unwrap()
                .0,
        );
        keeper.observe_intent_expiry(Some(Utc::now() + chrono::Duration::seconds(30)));
        let leases = fenced.injection_leases().unwrap();
        tokio::time::advance(Duration::from_secs(30)).await;
        keeper.renew_once(leases).await;
        assert_eq!(inner.renewals.load(SeqCst), 1, "unfenced inside the TTL");
        tokio::time::advance(Duration::from_secs(61)).await;
        keeper.renew_once(leases).await;
        assert_eq!(inner.renewals.load(SeqCst), 1);
        let health = keeper.health();
        assert_eq!(health.renewal_stopped, Some("ttl_bound"));
        // The active controller may still keep the owner's lease live, so a
        // standby never derives `expired` from its own bound.
        assert_eq!(health.state, LeaseState::Standby);
        tokio::time::advance(Duration::from_secs(120)).await;
        assert_eq!(keeper.health().state, LeaseState::Standby);
        // The fence alone decides, with no reconciliation pass involved, so a
        // fence change during a stalled read is reported at once.
        fence.set(true);
        assert_eq!(keeper.health().state, LeaseState::Expired);
        fence.set(false);
        assert_eq!(keeper.health().state, LeaseState::Standby);
    }

    fn leased_rule(ttl_seconds: u32) -> Mitigation {
        let mut mitigation = Mitigation::from_intent(
            super::super::MitigationIntent {
                event_id: uuid::Uuid::new_v4(),
                customer_id: None,
                service_id: None,
                pop: "pop-a".into(),
                match_criteria: super::super::MatchCriteria {
                    dst_prefix: "192.0.2.10/32".into(),
                    ..Default::default()
                },
                action_type: ActionType::Discard,
                action_params: super::super::ActionParams {
                    injection_owner: OWNER.into(),
                    ..Default::default()
                },
                ttl_seconds,
                reason: "test".into(),
            },
            "192.0.2.10".into(),
            super::super::AttackVector::UdpFlood,
        );
        mitigation.activate();
        mitigation.origin_mode = Some(crate::config::OperationMode::Enforced);
        mitigation
    }

    /// A leased admission after the last read raises the bound at once: with
    /// the next read late, the new row keeps renewing until its own expiry,
    /// and a read whose snapshot predates the write cannot lower the bound.
    #[tokio::test(start_paused = true)]
    async fn a_leased_write_after_an_empty_read_renews_until_its_expiry() {
        let speaker = FaultyBlackholes::default();
        let keeper = LeaseKeeper::new(OWNER.into(), 60);
        keeper.take_readd();
        keeper.observe_add(
            speaker
                .announce_leased_blackhole(&route(), 60)
                .await
                .unwrap()
                .0,
        );
        keeper.observe_intent_expiry(None);
        let row = leased_rule(300);
        assert_eq!(keeper.health().has_leased_intent, Some(false));
        keeper.observe_leased_write(&row);
        assert_eq!(keeper.health().has_leased_intent, Some(true));
        assert_eq!(keeper.health().renew_until, Some(row.expires_at));
        // A read that started before the write committed saw no leased row.
        keeper.observe_intent_expiry(None);
        assert_eq!(keeper.health().has_leased_intent, Some(true));
        assert_eq!(keeper.health().renew_until, Some(row.expires_at));
        tokio::time::advance(Duration::from_secs(335)).await;
        keeper.renew_once(&speaker).await;
        assert_eq!(
            speaker.renewals.load(SeqCst),
            1,
            "ends inside expiry plus one lease"
        );
        tokio::time::advance(Duration::from_secs(10)).await;
        keeper.renew_once(&speaker).await;
        assert_eq!(speaker.renewals.load(SeqCst), 1);
        assert_eq!(keeper.health().renewal_stopped, Some("ttl_bound"));
        // Once that write was observed, a later read may lower the bound again.
        keeper.observe_intent_expiry(None);
        assert_eq!(keeper.health().has_leased_intent, Some(false));
        assert_ne!(keeper.health().renew_until, Some(row.expires_at));
    }

    /// A row past its TTL but not yet withdrawn keeps its past deadline:
    /// rereading it never grants a fresh margin.
    #[tokio::test(start_paused = true)]
    async fn rereading_an_overdue_row_never_extends_renewal() {
        let speaker = FaultyBlackholes::default();
        let keeper = LeaseKeeper::new(OWNER.into(), 60);
        keeper.take_readd();
        keeper.observe_add(
            speaker
                .announce_leased_blackhole(&route(), 60)
                .await
                .unwrap()
                .0,
        );
        tokio::time::advance(Duration::from_secs(10)).await;
        let overdue = Utc::now() - chrono::Duration::seconds(50);
        for _ in 0..3 {
            keeper.observe_intent_expiry(Some(overdue));
        }
        assert_eq!(keeper.health().renew_until, Some(overdue));
        keeper.renew_once(&speaker).await;
        assert_eq!(speaker.renewals.load(SeqCst), 0);
        assert_eq!(keeper.health().renewal_stopped, Some("ttl_bound"));
    }

    /// Unleased, dry-run and other owners' rows never raise the bound.
    #[test]
    fn only_this_owners_enforced_leased_writes_raise_the_bound() {
        let keeper = LeaseKeeper::new(OWNER.into(), 60);
        let mut unleased = leased_rule(300);
        unleased.action_params.injection_owner.clear();
        let mut dry_run = leased_rule(300);
        dry_run.origin_mode = Some(crate::config::OperationMode::DryRun);
        let mut foreign = leased_rule(300);
        foreign.action_params.injection_owner = "prefixd.pop-b.0123456789abcdef".into();
        for row in [&unleased, &dry_run, &foreign] {
            keeper.observe_leased_write(row);
        }
        assert_eq!(keeper.health().renew_until, None);
    }

    /// Refreshing the bound after a stop wakes renewal at once.
    #[tokio::test(start_paused = true)]
    async fn a_refreshed_bound_wakes_renewal_after_a_stop() {
        let speaker = FaultyBlackholes::default();
        let keeper = LeaseKeeper::new(OWNER.into(), 60);
        keeper.take_readd();
        keeper.observe_add(
            speaker
                .announce_leased_blackhole(&route(), 60)
                .await
                .unwrap()
                .0,
        );
        tokio::time::advance(Duration::from_secs(61)).await;
        keeper.renew_once(&speaker).await;
        assert_eq!(keeper.health().renewal_stopped, Some("ttl_bound"));
        let woken = tokio::time::timeout(Duration::ZERO, keeper.renew_requested.notified());
        assert!(woken.await.is_err(), "nothing refreshed the bound yet");
        keeper.observe_leased_write(&leased_rule(300));
        let woken = tokio::time::timeout(Duration::ZERO, keeper.renew_requested.notified());
        assert!(woken.await.is_ok());
        assert_eq!(keeper.health().renewal_stopped, None);
    }

    /// With `lease_seconds` below the reconciliation interval, renewal keeps
    /// `interval + lease / 3` after the bound, so a healthy controller reads
    /// again before it would stop.
    #[tokio::test(start_paused = true)]
    async fn the_margin_covers_a_reconciliation_interval_longer_than_the_lease() {
        let speaker = FaultyBlackholes::default();
        let keeper = LeaseKeeper::new(OWNER.into(), 30).with_reconcile_interval(120);
        keeper.take_readd();
        keeper.observe_add(
            speaker
                .announce_leased_blackhole(&route(), 30)
                .await
                .unwrap()
                .0,
        );
        keeper.observe_intent_expiry(None);
        tokio::time::advance(Duration::from_secs(119)).await;
        keeper.renew_once(&speaker).await;
        assert_eq!(speaker.renewals.load(SeqCst), 1);
        tokio::time::advance(Duration::from_secs(2)).await;
        keeper.renew_once(&speaker).await;
        assert_eq!(speaker.renewals.load(SeqCst), 1);
        assert_eq!(keeper.health().renewal_stopped, Some("ttl_bound"));
    }

    /// No generation held: nothing to renew, so nothing is reported stopped.
    #[tokio::test(start_paused = true)]
    async fn no_generation_reports_no_stopped_renewal() {
        let keeper = LeaseKeeper::new(OWNER.into(), 60);
        tokio::time::advance(Duration::from_secs(600)).await;
        let health = keeper.health();
        assert_eq!(health.renewal_stopped, None);
        assert_eq!(health.state, LeaseState::None);
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
                .unwrap()
                .0,
        );
        fence.set(false);
        for _ in 0..3 {
            keeper.renew_once(fenced.injection_leases().unwrap()).await;
            let health = keeper.health();
            assert_eq!(health.last_renewal_result, Some("success"), "{health:?}");
            assert_eq!(health.state, LeaseState::Live);
        }
        inner.restart().await;
        keeper
            .probe_restart(fenced.injection_leases().unwrap())
            .await;
        assert_eq!(keeper.generation(), None);
        assert!(
            keeper.take_readd(),
            "read-only restart probing stays unfenced"
        );
        // Adds stay fenced.
        assert!(matches!(
            fenced
                .blackhole()
                .unwrap()
                .announce_leased_blackhole(&route(), 60)
                .await,
            Err(PrefixdError::Standby)
        ));
        // One owner lease covers leased FlowSpec too: its adds stay fenced as well.
        let rule = crate::domain::FlowSpecRule::new(
            crate::domain::FlowSpecNlri {
                dst_prefix: "192.0.2.1/32".into(),
                protocol: Some(17),
                ..Default::default()
            },
            crate::domain::FlowSpecAction::discard(),
        )
        .with_owner(OWNER);
        assert!(matches!(
            crate::bgp::FlowSpecWriter::announce_leased(&fenced, &rule, 60).await,
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
        speaker.inner.restart().await;
        keeper.probe_restart(&speaker).await;
        assert_eq!(keeper.generation(), None);
        assert_eq!(keeper.health().state, LeaseState::NotRenewing);
        assert_eq!(speaker.renewals.load(SeqCst), 0);
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
            .unwrap()
            .0;
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
                .unwrap()
                .0,
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
            .unwrap()
            .0;
        keeper.observe_add(first);
        let readd = async {
            speaker.entered.notified().await;
            speaker.inner.expire_lease(OWNER).await;
            let next = speaker
                .inner
                .announce_leased_blackhole(&route(), 60)
                .await
                .unwrap()
                .0;
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
