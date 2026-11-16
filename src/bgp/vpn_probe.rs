//! Bounded VPN family capability probes for authenticated health and admission
//! pre-checks. VPN mutations still probe fresh inside the writer (ADR 032).
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use chrono::{DateTime, Utc};
use futures_util::future::{BoxFuture, FutureExt, Shared};
use tokio::time::Instant;

use crate::domain::{VpnFlowSpecFamily, VpnFlowSpecIdentity};
use crate::error::{PrefixdError, Result};

use super::FlowSpecWriter;

/// How long one probe result answers health, and a supported result answers admission.
pub const VPN_PROBE_TTL: Duration = Duration::from_secs(10);
/// Health's bound on one probe; a timeout is reported, and cached, as an error.
pub const VPN_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnProbe {
    /// supported, unsupported, or error.
    pub status: &'static str,
    /// When the probe that produced `status` finished.
    pub observed_at: DateTime<Utc>,
    finished: Instant,
}

impl VpnProbe {
    fn new(status: &'static str) -> Self {
        Self {
            status,
            observed_at: Utc::now(),
            finished: Instant::now(),
        }
    }

    pub fn error() -> Self {
        Self::new("error")
    }
}

type InFlight = Shared<BoxFuture<'static, VpnProbe>>;

#[derive(Default)]
struct Slot {
    last: Option<VpnProbe>,
    in_flight: Option<InFlight>,
}

impl Slot {
    fn fresh(&self) -> Option<VpnProbe> {
        self.last
            .filter(|probe| probe.finished.elapsed() < VPN_PROBE_TTL)
    }
}

/// The latest probe per family. Only probes made through this cache update it.
#[derive(Default)]
pub struct VpnProbeCache(Arc<Mutex<[Slot; 2]>>);

fn lock(slots: &Mutex<[Slot; 2]>) -> MutexGuard<'_, [Slot; 2]> {
    slots.lock().unwrap_or_else(|e| e.into_inner())
}

fn slot(family: VpnFlowSpecFamily) -> usize {
    match family {
        VpnFlowSpecFamily::Ipv4 => 0,
        VpnFlowSpecFamily::Ipv6 => 1,
    }
}

fn status(result: &Result<()>) -> &'static str {
    match result {
        Ok(()) => "supported",
        Err(PrefixdError::UnsupportedFlowSpecScope { .. }) => "unsupported",
        Err(_) => "error",
    }
}

impl VpnProbeCache {
    /// Health: any result younger than the window, else one bounded probe that
    /// concurrent callers share. Errors are cached too, so a stuck speaker costs
    /// one probe per window instead of one per request. The probe runs detached:
    /// a caller going away never aborts it or turns it into an error.
    pub async fn observe(
        &self,
        speaker: Arc<dyn FlowSpecWriter>,
        identity: &VpnFlowSpecIdentity,
    ) -> VpnProbe {
        let index = slot(identity.family);
        let in_flight = {
            let mut slots = lock(&self.0);
            let slot = &mut slots[index];
            if let Some(probe) = slot.fresh() {
                return probe;
            }
            slot.in_flight
                .get_or_insert_with(|| self.spawn(index, speaker, identity.clone()))
                .clone()
        };
        in_flight.await
    }

    fn spawn(
        &self,
        index: usize,
        speaker: Arc<dyn FlowSpecWriter>,
        identity: VpnFlowSpecIdentity,
    ) -> InFlight {
        let slots = self.0.clone();
        let task = tokio::spawn(async move {
            let result =
                tokio::time::timeout(VPN_PROBE_TIMEOUT, speaker.validate_scope(Some(&identity)))
                    .await
                    .unwrap_or_else(|_| {
                        Err(PrefixdError::BgpAnnouncementFailed(
                            "VPN capability probe timed out".into(),
                        ))
                    });
            let probe = VpnProbe::new(status(&result));
            let mut slots = lock(&slots);
            slots[index].last = Some(probe);
            slots[index].in_flight = None;
            probe
        });
        let slots = self.0.clone();
        async move {
            task.await.unwrap_or_else(|_| {
                // A panicked probe is an error; clear it so the next caller retries.
                let probe = VpnProbe::error();
                let mut slots = lock(&slots);
                slots[index].last = Some(probe);
                slots[index].in_flight = None;
                probe
            })
        }
        .boxed()
        .shared()
    }

    /// Forget a family's result after a failed VPN mutation, so the next health
    /// request or pre-check probes fresh. A mutation error is not necessarily a
    /// probe failure, so nothing is recorded in its place.
    pub fn invalidate(&self, family: VpnFlowSpecFamily) {
        lock(&self.0)[slot(family)].last = None;
    }

    /// Admission pre-check: only a supported result inside the window skips the
    /// probe. A cached error or unsupported result is probed again. A supported
    /// result came from `validate_scope` on this speaker, which already
    /// registered the family for inventory.
    pub async fn validate(
        &self,
        speaker: &dyn FlowSpecWriter,
        scope: Option<&VpnFlowSpecIdentity>,
    ) -> Result<()> {
        let Some(identity) = scope else {
            return speaker.validate_scope(None).await;
        };
        let index = slot(identity.family);
        if lock(&self.0)[index]
            .fresh()
            .is_some_and(|probe| probe.status == "supported")
        {
            return Ok(());
        }
        let result = speaker.validate_scope(scope).await;
        lock(&self.0)[index].last = Some(VpnProbe::new(status(&result)));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::FlowSpecRule;
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

    /// Counts probes; `mode` picks supported, unsupported, error or a stuck daemon.
    struct Speaker {
        mode: std::sync::Mutex<&'static str>,
        probes: AtomicUsize,
    }

    impl Speaker {
        fn new(mode: &'static str) -> Self {
            Self {
                mode: std::sync::Mutex::new(mode),
                probes: AtomicUsize::new(0),
            }
        }
        fn set(&self, mode: &'static str) {
            *self.mode.lock().unwrap() = mode;
        }
        fn probes(&self) -> usize {
            self.probes.load(SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl FlowSpecWriter for Speaker {
        fn register_scope(&self, _: Option<&VpnFlowSpecIdentity>) -> Result<()> {
            Ok(())
        }
        async fn validate_scope(&self, scope: Option<&VpnFlowSpecIdentity>) -> Result<()> {
            self.register_scope(scope)?;
            if scope.is_none() {
                return Ok(());
            }
            self.probes.fetch_add(1, SeqCst);
            let mode = *self.mode.lock().unwrap();
            tokio::time::sleep(Duration::from_millis(500)).await;
            match mode {
                "supported" => Ok(()),
                "unsupported" => Err(PrefixdError::UnsupportedFlowSpecScope {
                    backend: "test",
                    family: 13,
                }),
                "error" => Err(PrefixdError::BgpAnnouncementFailed("transport".into())),
                _ => std::future::pending().await,
            }
        }
        async fn announce(&self, _: &FlowSpecRule) -> Result<()> {
            panic!("probes must not mutate")
        }
        async fn withdraw(&self, _: &FlowSpecRule) -> Result<()> {
            panic!("probes must not mutate")
        }
    }

    fn v4() -> VpnFlowSpecIdentity {
        VpnFlowSpecIdentity::new(VpnFlowSpecFamily::Ipv4, "64500:40").unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn health_probes_once_per_window_and_dates_the_result() {
        let speaker = Arc::new(Speaker::new("supported"));
        let cache = VpnProbeCache::default();
        let first = cache.observe(speaker.clone(), &v4()).await;
        assert_eq!(first.status, "supported");
        tokio::time::advance(VPN_PROBE_TTL - Duration::from_millis(1)).await;
        let hit = cache.observe(speaker.clone(), &v4()).await;
        assert_eq!((hit, speaker.probes()), (first, 1), "cache hit");
        // An IPv6 scope has its own slot.
        let v6 = VpnFlowSpecIdentity::new(VpnFlowSpecFamily::Ipv6, "64500:40").unwrap();
        cache.observe(speaker.clone(), &v6).await;
        assert_eq!(speaker.probes(), 2);
        tokio::time::advance(Duration::from_millis(1)).await;
        speaker.set("error");
        let expired = cache.observe(speaker.clone(), &v4()).await;
        assert_eq!(speaker.probes(), 3, "expiry probes again");
        assert_eq!(
            expired.status, "error",
            "a failure is never reported as healthy"
        );
        assert!(expired.observed_at > first.observed_at);
    }

    #[tokio::test(start_paused = true)]
    async fn health_keeps_unsupported_error_and_timeout_distinct() {
        for (mode, status) in [
            ("unsupported", "unsupported"),
            ("error", "error"),
            ("stuck", "error"),
        ] {
            let speaker = Arc::new(Speaker::new(mode));
            let cache = VpnProbeCache::default();
            let started = Instant::now();
            assert_eq!(
                cache.observe(speaker.clone(), &v4()).await.status,
                status,
                "{mode}"
            );
            if mode == "stuck" {
                assert_eq!(started.elapsed(), VPN_PROBE_TIMEOUT);
            }
            // A stuck or failing speaker costs one probe per window, not per request.
            assert_eq!(cache.observe(speaker.clone(), &v4()).await.status, status);
            assert_eq!(speaker.probes(), 1, "{mode}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_health_requests_share_one_in_flight_probe() {
        for mode in ["supported", "stuck"] {
            let speaker = Arc::new(Speaker::new(mode));
            let cache = VpnProbeCache::default();
            let started = Instant::now();
            let identity = v4();
            let probes = futures_util::future::join_all(
                (0..8).map(|_| cache.observe(speaker.clone(), &identity)),
            )
            .await;
            assert_eq!(speaker.probes(), 1, "{mode}");
            assert!(probes.iter().all(|probe| *probe == probes[0]));
            assert!(started.elapsed() <= VPN_PROBE_TIMEOUT);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_caller_going_away_never_aborts_the_shared_probe() {
        // The speaker answers after 500 ms; the leading request leaves at 100 ms.
        for (mode, status, waited) in [
            ("supported", "supported", Duration::from_millis(500)),
            ("stuck", "error", VPN_PROBE_TIMEOUT),
        ] {
            let speaker = Arc::new(Speaker::new(mode));
            let cache = VpnProbeCache::default();
            let identity = v4();
            let started = Instant::now();
            let (leader, waiter) = tokio::join!(
                tokio::time::timeout(
                    Duration::from_millis(100),
                    cache.observe(speaker.clone(), &identity)
                ),
                async {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    cache.observe(speaker.clone(), &identity).await
                }
            );
            assert!(leader.is_err(), "leading request canceled");
            assert_eq!(waiter.status, status, "{mode}: the probe's own result");
            assert_eq!(started.elapsed(), waited, "{mode}");
            assert_eq!(speaker.probes(), 1, "{mode}: waiter joined the same probe");
        }
        // With nobody waiting, the detached probe still finishes and is cached.
        let speaker = Arc::new(Speaker::new("supported"));
        let cache = VpnProbeCache::default();
        let identity = v4();
        let gone = tokio::time::timeout(
            Duration::from_millis(100),
            cache.observe(speaker.clone(), &identity),
        )
        .await;
        assert!(gone.is_err());
        tokio::time::sleep(Duration::from_secs(1)).await;
        let later = cache.observe(speaker.clone(), &identity).await;
        assert_eq!((later.status, speaker.probes()), ("supported", 1));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_mutation_invalidates_the_cached_result() {
        let speaker = Arc::new(Speaker::new("supported"));
        let cache = VpnProbeCache::default();
        let v6 = VpnFlowSpecIdentity::new(VpnFlowSpecFamily::Ipv6, "64500:40").unwrap();
        cache.observe(speaker.clone(), &v4()).await;
        cache.observe(speaker.clone(), &v6).await;
        cache.invalidate(VpnFlowSpecFamily::Ipv4);
        speaker.set("error");
        assert_eq!(cache.observe(speaker.clone(), &v4()).await.status, "error");
        assert_eq!(speaker.probes(), 3, "the invalidated family probes again");
        assert_eq!(
            cache.observe(speaker.clone(), &v6).await.status,
            "supported"
        );
        assert_eq!(speaker.probes(), 3, "the other family stays cached");
        // An invalidated slot no longer lets admission skip its probe.
        speaker.set("supported");
        cache.invalidate(VpnFlowSpecFamily::Ipv6);
        cache.validate(&*speaker, Some(&v6)).await.unwrap();
        assert_eq!(speaker.probes(), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn admission_reuses_only_a_supported_result() {
        let speaker = Arc::new(Speaker::new("error"));
        let cache = VpnProbeCache::default();
        assert_eq!(cache.observe(speaker.clone(), &v4()).await.status, "error");
        // A cached failure never refuses admission by itself: it probes again.
        speaker.set("supported");
        cache.validate(&*speaker, Some(&v4())).await.unwrap();
        assert_eq!(speaker.probes(), 2);
        // Admission's success now answers health and the next pre-check.
        assert_eq!(
            cache.observe(speaker.clone(), &v4()).await.status,
            "supported"
        );
        cache.validate(&*speaker, Some(&v4())).await.unwrap();
        assert_eq!(speaker.probes(), 2, "supported pre-check reused");
        // After the window, a failed pre-check replaces the cached success.
        tokio::time::advance(VPN_PROBE_TTL).await;
        speaker.set("unsupported");
        assert!(matches!(
            cache.validate(&*speaker, Some(&v4())).await,
            Err(PrefixdError::UnsupportedFlowSpecScope { .. })
        ));
        assert_eq!(
            cache.observe(speaker.clone(), &v4()).await.status,
            "unsupported"
        );
        assert_eq!(speaker.probes(), 3);
        // A global rule needs no family probe.
        cache.validate(&*speaker, None).await.unwrap();
        assert_eq!(speaker.probes(), 3);
    }
}
