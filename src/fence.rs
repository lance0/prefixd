//! Controller fence (ADR 027): at most one active controller per owner.
//!
//! The lifecycle mutex is in-process, so a PostgreSQL session advisory lock held
//! on one dedicated connection decides which process may mutate the speaker.
//! Without the lock a controller stays in standby: it runs no scheduler work,
//! sends no speaker mutation and refuses mutation requests.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use sqlx::Connection;
use sqlx::postgres::{PgConnectOptions, PgConnection};
use tokio::sync::watch;

use crate::bgp::{
    BlackholeInventory, BlackholeRoute, BlackholeSpeaker, DaemonHealthObserver, FlowSpecAnnouncer,
    FlowSpecReader, FlowSpecWriter, PeerObserver,
};
use crate::domain::{FlowSpecNlri, FlowSpecRule};
use crate::error::{PrefixdError, Result};

/// A standby controller retries the lock this often.
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// The holder checks its fence session this often, each check bounded by the same time.
pub const CHECK_INTERVAL: Duration = Duration::from_secs(2);

/// Server-side keepalives bound how long PostgreSQL keeps a crashed host's
/// session, and so its lock: about 10 s idle plus three 5 s probes.
const FENCE_SESSION_SETUP: &str = "SELECT set_config('tcp_keepalives_idle', '10', false), \
     set_config('tcp_keepalives_interval', '5', false), \
     set_config('tcp_keepalives_count', '3', false)";

/// First 8 bytes, big-endian, of SHA-256 over the fence tag and the owner.
/// Used with the single-bigint advisory lock form, which cannot overlap the
/// two-integer quota lock.
pub fn fence_lock_key(owner: &str) -> i64 {
    let digest = Sha256::new()
        .chain_update(b"prefixd-controller-fence\0")
        .chain_update(owner.as_bytes())
        .finalize();
    let mut key = [0; 8];
    key.copy_from_slice(&digest[..8]);
    i64::from_be_bytes(key)
}

/// Whether this process holds the fence, shared by the API, scheduler and speaker writer.
#[derive(Debug)]
pub struct ControllerFence {
    active: watch::Sender<bool>,
}

impl ControllerFence {
    /// `true` only for unfenced fixtures or after the lock was taken.
    pub fn new(active: bool) -> Self {
        Self {
            active: watch::Sender::new(active),
        }
    }

    pub fn is_active(&self) -> bool {
        *self.active.borrow()
    }

    pub fn ensure_active(&self) -> Result<()> {
        if self.is_active() {
            Ok(())
        } else {
            Err(PrefixdError::Standby)
        }
    }

    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.active.subscribe()
    }

    pub(crate) fn set(&self, active: bool) {
        crate::observability::metrics::CONTROLLER_FENCE_ACTIVE.set(f64::from(u8::from(active)));
        // Notify only on a transition, so the steady-state checks wake no one.
        if self
            .active
            .send_if_modified(|current| std::mem::replace(current, active) != active)
        {
            if active {
                tracing::info!("controller fence acquired; controller is active");
            } else {
                tracing::warn!("controller fence not held; controller is in standby");
            }
        }
    }
}

/// Open a dedicated fence session outside the pool and try the lock once.
/// `None` means another session holds it.
pub async fn try_acquire(options: &PgConnectOptions, key: i64) -> Result<Option<PgConnection>> {
    let options = options.clone().application_name("prefixd-controller-fence");
    let mut connection = PgConnection::connect_with(&options).await?;
    sqlx::query(FENCE_SESSION_SETUP)
        .execute(&mut connection)
        .await?;
    let held: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(key)
        .fetch_one(&mut connection)
        .await?;
    if held {
        return Ok(Some(connection));
    }
    let _ = connection.close().await;
    Ok(None)
}

/// One-shot maintenance takes the fence once and refuses while a controller holds
/// it. Closing the returned session releases the lock.
pub async fn acquire_for_maintenance(
    options: &PgConnectOptions,
    owner: &str,
) -> Result<PgConnection> {
    try_acquire(options, fence_lock_key(owner))
        .await?
        .ok_or_else(|| {
            PrefixdError::Conflict(format!(
                "another controller holds the fence for owner {owner}; stop it first"
            ))
        })
}

/// Hold the fence, or poll for it, for the life of the process. Process exit
/// closes the session and releases the lock, so a graceful drain stays fenced.
/// On a failed check the controller enters standby at once and later reacquires
/// on a new session; an RPC already in flight runs to its own deadline.
pub async fn maintain(
    fence: Arc<ControllerFence>,
    options: PgConnectOptions,
    key: i64,
    mut held: Option<PgConnection>,
    poll: Duration,
    check: Duration,
) {
    loop {
        fence.set(held.is_some());
        match held.as_mut() {
            Some(connection) => {
                tokio::time::sleep(check).await;
                let probe = sqlx::query("SELECT 1").execute(&mut *connection);
                if !matches!(tokio::time::timeout(check, probe).await, Ok(Ok(_))) {
                    tracing::warn!("controller fence session check failed; the lock may be lost");
                    held = None;
                }
            }
            None => {
                tokio::time::sleep(poll).await;
                held = match tokio::time::timeout(poll, try_acquire(&options, key)).await {
                    Ok(Ok(connection)) => connection,
                    Ok(Err(error)) => {
                        tracing::warn!(error = %error, "controller fence acquisition failed");
                        None
                    }
                    Err(_) => {
                        tracing::warn!("controller fence acquisition timed out");
                        None
                    }
                };
            }
        }
    }
}

/// The one speaker-mutation choke point: no RPC starts without the fence.
/// Reads and observations pass through, so standby health stays observable.
pub struct FencedAnnouncer {
    inner: Arc<dyn FlowSpecAnnouncer>,
    fence: Arc<ControllerFence>,
}

impl FencedAnnouncer {
    pub fn new(inner: Arc<dyn FlowSpecAnnouncer>, fence: Arc<ControllerFence>) -> Self {
        Self { inner, fence }
    }
}

#[async_trait]
impl FlowSpecWriter for FencedAnnouncer {
    fn matches_nlri(&self, left: &FlowSpecNlri, right: &FlowSpecNlri) -> Result<bool> {
        self.inner.matches_nlri(left, right)
    }

    async fn announce(&self, rule: &FlowSpecRule) -> Result<()> {
        self.fence.ensure_active()?;
        self.inner.announce(rule).await
    }

    async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()> {
        self.fence.ensure_active()?;
        self.inner.withdraw(rule).await
    }
}

impl FlowSpecAnnouncer for FencedAnnouncer {
    fn backend(&self) -> &'static str {
        self.inner.backend()
    }

    fn reader(&self) -> Option<&dyn FlowSpecReader> {
        self.inner.reader()
    }

    fn daemon_health_observer(&self) -> Option<&dyn DaemonHealthObserver> {
        self.inner.daemon_health_observer()
    }

    fn peer_observer(&self) -> Option<&dyn PeerObserver> {
        self.inner.peer_observer()
    }

    /// Never the inner handle: blackhole writes go through the fence too.
    fn blackhole(&self) -> Option<&dyn BlackholeSpeaker> {
        self.inner
            .blackhole()
            .map(|_| self as &dyn BlackholeSpeaker)
    }
}

impl FencedAnnouncer {
    fn inner_blackhole(&self) -> Result<&dyn BlackholeSpeaker> {
        self.inner.blackhole().ok_or_else(|| {
            PrefixdError::Internal("speaker does not support blackhole routes".into())
        })
    }
}

#[async_trait]
impl BlackholeSpeaker for FencedAnnouncer {
    async fn announce_blackhole(&self, route: &BlackholeRoute) -> Result<()> {
        self.fence.ensure_active()?;
        self.inner_blackhole()?.announce_blackhole(route).await
    }

    async fn withdraw_blackhole(&self, prefix: &ipnet::IpNet) -> Result<()> {
        self.fence.ensure_active()?;
        self.inner_blackhole()?.withdraw_blackhole(prefix).await
    }

    async fn list_blackholes(&self) -> Result<BlackholeInventory> {
        self.inner_blackhole()?.list_blackholes().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fence_lock_key_is_pinned() {
        assert_eq!(
            fence_lock_key("prefixd.fra1.6bec5166e567c666"),
            -5_384_075_860_891_307_361
        );
        assert_eq!(
            fence_lock_key(&format!("prefixd.{}.adb02dd5cde4b473", "x".repeat(39))),
            -6_037_144_351_760_232_306
        );
    }

    #[tokio::test]
    async fn standby_writer_sends_no_rpc_but_still_reads() {
        let inner = Arc::new(crate::bgp::MockAnnouncer::new());
        let fence = Arc::new(ControllerFence::new(false));
        let writer = FencedAnnouncer::new(inner.clone(), fence.clone());
        let rule = FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: "192.0.2.1/32".into(),
                protocol: Some(17),
                dst_ports: vec![53],
            },
            crate::domain::FlowSpecAction::discard(),
        );
        assert!(matches!(
            writer.announce(&rule).await,
            Err(PrefixdError::Standby)
        ));
        assert!(matches!(
            writer.withdraw(&rule).await,
            Err(PrefixdError::Standby)
        ));
        assert_eq!(inner.announced_count().await, 0);
        assert!(writer.reader().is_some() && writer.peer_observer().is_some());
        fence.set(true);
        writer.announce(&rule).await.unwrap();
        assert_eq!(inner.announced_count().await, 1);
    }

    #[tokio::test]
    async fn standby_blackhole_writes_send_no_rpc_but_still_read() {
        let inner = Arc::new(crate::bgp::MockAnnouncer::new());
        let fence = Arc::new(ControllerFence::new(false));
        let writer = FencedAnnouncer::new(inner.clone(), fence.clone());
        let fenced = writer.blackhole().expect("capability passes through");
        assert!((&writer as &dyn FlowSpecAnnouncer).capabilities().blackhole);
        // The handle is the fenced wrapper, never the inner speaker's.
        assert!(std::ptr::addr_eq(
            fenced as *const dyn BlackholeSpeaker,
            &writer as *const FencedAnnouncer
        ));
        let route = BlackholeRoute::new(
            "192.0.2.1/32".parse().unwrap(),
            "192.0.2.66".parse().unwrap(),
            vec![],
            vec![],
        )
        .unwrap();
        let stored = || async { inner.list_blackholes().await.unwrap().routes.len() };
        assert!(matches!(
            fenced.announce_blackhole(&route).await,
            Err(PrefixdError::Standby)
        ));
        assert_eq!(stored().await, 0, "standby announce reached the speaker");
        fence.set(true);
        fenced.announce_blackhole(&route).await.unwrap();
        assert_eq!(stored().await, 1);
        fence.set(false);
        assert!(matches!(
            fenced.withdraw_blackhole(&route.prefix()).await,
            Err(PrefixdError::Standby)
        ));
        assert_eq!(stored().await, 1, "standby withdraw reached the speaker");
        // Reads stay available in standby.
        assert_eq!(fenced.list_blackholes().await.unwrap().routes.len(), 1);
    }
}
