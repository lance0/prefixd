use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{
    BlackholeInventory, BlackholeRoute, BlackholeSpeaker, FlowSpecAnnouncer, FlowSpecMatchSupport,
    FlowSpecReader, FlowSpecWriter, PeerObserver, PeerStatus, SessionState,
};
use crate::domain::FlowSpecRule;
use crate::error::Result;

/// Mock announcer for testing
#[derive(Debug, Default)]
pub struct MockAnnouncer {
    rules: Arc<RwLock<Vec<FlowSpecRule>>>,
    blackholes: RwLock<Vec<BlackholeRoute>>,
    peers: Vec<PeerStatus>,
    /// Test seam: report no ADR 028 match support, like an adapter that has not opted in.
    no_match_support: bool,
}

impl MockAnnouncer {
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            blackholes: RwLock::default(),
            peers: vec![PeerStatus {
                name: "mock-peer".to_string(),
                address: "127.0.0.1".to_string(),
                state: SessionState::Established,
            }],
            no_match_support: false,
        }
    }

    pub fn with_peers(peers: Vec<PeerStatus>) -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            blackholes: RwLock::default(),
            peers,
            no_match_support: false,
        }
    }

    /// Reports no ADR 028 match support, so callers must refuse extended rules.
    pub fn without_match_support() -> Self {
        Self {
            no_match_support: true,
            ..Self::new()
        }
    }

    pub async fn announced_count(&self) -> usize {
        self.rules.read().await.len()
    }
}

impl FlowSpecAnnouncer for MockAnnouncer {
    fn backend(&self) -> &'static str {
        "mock"
    }
    fn reader(&self) -> Option<&dyn FlowSpecReader> {
        Some(self)
    }
    fn peer_observer(&self) -> Option<&dyn PeerObserver> {
        Some(self)
    }
    fn blackhole(&self) -> Option<&dyn BlackholeSpeaker> {
        Some(self)
    }
    fn match_support(&self) -> FlowSpecMatchSupport {
        if self.no_match_support {
            FlowSpecMatchSupport::default()
        } else {
            FlowSpecMatchSupport::ALL
        }
    }
}

#[async_trait]
impl FlowSpecWriter for MockAnnouncer {
    async fn announce(&self, rule: &FlowSpecRule) -> Result<()> {
        let mut rules = self.rules.write().await;
        let hash = rule.nlri_hash();

        // Remove existing rule with same NLRI if present
        rules.retain(|r| r.nlri_hash() != hash);
        rules.push(rule.clone());

        tracing::debug!(nlri_hash = %hash, "mock: announced flowspec rule");
        Ok(())
    }
    async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()> {
        let mut rules = self.rules.write().await;
        let hash = rule.nlri_hash();
        let before = rules.len();
        rules.retain(|r| r.nlri_hash() != hash);

        if rules.len() < before {
            tracing::debug!(nlri_hash = %hash, "mock: withdrew flowspec rule");
        }
        Ok(())
    }
}
#[async_trait]
impl FlowSpecReader for MockAnnouncer {
    async fn list_active(&self) -> Result<Vec<FlowSpecRule>> {
        Ok(self.rules.read().await.clone())
    }
}
#[async_trait]
impl BlackholeSpeaker for MockAnnouncer {
    async fn announce_blackhole(&self, route: &BlackholeRoute) -> Result<()> {
        let mut routes = self.blackholes.write().await;
        routes.retain(|r| r.prefix() != route.prefix());
        routes.push(route.clone());
        Ok(())
    }
    async fn withdraw_blackhole(&self, prefix: &ipnet::IpNet) -> Result<()> {
        super::require_host_route(prefix)?;
        self.blackholes
            .write()
            .await
            .retain(|r| r.prefix() != *prefix);
        Ok(())
    }
    async fn list_blackholes(&self) -> Result<BlackholeInventory> {
        Ok(BlackholeInventory {
            routes: self.blackholes.read().await.clone(),
            unrecognized: vec![],
        })
    }
}
#[async_trait]
impl PeerObserver for MockAnnouncer {
    async fn session_status(&self) -> Result<Vec<PeerStatus>> {
        Ok(self.peers.clone())
    }
}

/// Test speaker with injectable blackhole faults; FlowSpec passes through.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct FaultyBlackholes {
    pub inner: MockAnnouncer,
    /// Every blackhole read fails, as an aborted or partial walk does.
    pub fail_reads: std::sync::atomic::AtomicBool,
    /// Every FlowSpec read fails.
    pub fail_flowspec_reads: std::sync::atomic::AtomicBool,
    /// Every add fails without changing the speaker.
    pub fail_adds: std::sync::atomic::AtomicBool,
    /// 1: a delete is rejected before removal; 2: removed, then the reply is lost.
    pub withdraw_fault: std::sync::atomic::AtomicUsize,
    /// Well-formed local routes that are not prefixd-shaped.
    pub unrecognized: std::sync::Mutex<Vec<super::UnrecognizedRoute>>,
    pub adds: std::sync::atomic::AtomicUsize,
    pub deletes: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl FaultyBlackholes {
    pub async fn routes(&self) -> Vec<BlackholeRoute> {
        self.inner.list_blackholes().await.unwrap().routes
    }
}

#[cfg(test)]
impl FlowSpecAnnouncer for FaultyBlackholes {
    fn backend(&self) -> &'static str {
        "mock"
    }
    fn reader(&self) -> Option<&dyn FlowSpecReader> {
        Some(self)
    }
    fn blackhole(&self) -> Option<&dyn BlackholeSpeaker> {
        Some(self)
    }
}

#[cfg(test)]
#[async_trait]
impl FlowSpecWriter for FaultyBlackholes {
    async fn announce(&self, rule: &FlowSpecRule) -> Result<()> {
        self.inner.announce(rule).await
    }
    async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()> {
        self.inner.withdraw(rule).await
    }
}

#[cfg(test)]
#[async_trait]
impl FlowSpecReader for FaultyBlackholes {
    async fn list_active(&self) -> Result<Vec<FlowSpecRule>> {
        if self
            .fail_flowspec_reads
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(crate::error::PrefixdError::BgpAnnouncementFailed(
                "FlowSpec read failed".into(),
            ));
        }
        self.inner.list_active().await
    }
}

#[cfg(test)]
#[async_trait]
impl BlackholeSpeaker for FaultyBlackholes {
    async fn announce_blackhole(&self, route: &BlackholeRoute) -> Result<()> {
        use std::sync::atomic::Ordering::SeqCst;
        self.adds.fetch_add(1, SeqCst);
        if self.fail_adds.load(SeqCst) {
            return Err(crate::error::PrefixdError::BgpAnnouncementFailed(
                "add failed".into(),
            ));
        }
        self.inner.announce_blackhole(route).await
    }
    async fn withdraw_blackhole(&self, prefix: &ipnet::IpNet) -> Result<()> {
        use std::sync::atomic::Ordering::SeqCst;
        self.deletes.fetch_add(1, SeqCst);
        let fault = self.withdraw_fault.load(SeqCst);
        if fault == 2 {
            self.inner.withdraw_blackhole(prefix).await?;
        }
        if fault != 0 {
            return Err(crate::error::PrefixdError::BgpWithdrawalFailed(
                "delete outcome unknown".into(),
            ));
        }
        self.inner.withdraw_blackhole(prefix).await
    }
    async fn list_blackholes(&self) -> Result<BlackholeInventory> {
        if self.fail_reads.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(crate::error::PrefixdError::BgpAnnouncementFailed(
                "ABORTED: local intent changed during the read".into(),
            ));
        }
        let mut inventory = self.inner.list_blackholes().await?;
        inventory.unrecognized = self.unrecognized.lock().unwrap().clone();
        Ok(inventory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{FlowSpecAction, FlowSpecNlri};

    #[tokio::test]
    async fn test_mock_announce_withdraw() {
        let announcer = MockAnnouncer::new();

        let rule = FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: "203.0.113.10/32".to_string(),
                protocol: Some(17),
                dst_ports: vec![53],
                ..Default::default()
            },
            FlowSpecAction::police(5_000_000),
        );

        announcer.announce(&rule).await.unwrap();
        assert_eq!(announcer.announced_count().await, 1);

        announcer.withdraw(&rule).await.unwrap();
        assert_eq!(announcer.announced_count().await, 0);
    }

    #[tokio::test]
    async fn mock_blackhole_upserts_by_prefix_and_withdraws_idempotently() {
        let announcer = MockAnnouncer::new();
        let speaker = announcer.blackhole().unwrap();
        let prefix: ipnet::IpNet = "2001:db8::1/128".parse().unwrap();
        let next_hop = "2001:db8::66".parse().unwrap();
        for extra in [vec![], vec![64512 << 16 | 1]] {
            let route = BlackholeRoute::new(prefix, next_hop, extra, vec![]).unwrap();
            speaker.announce_blackhole(&route).await.unwrap();
            assert_eq!(speaker.list_blackholes().await.unwrap().routes, [route]);
        }
        for _ in 0..2 {
            speaker.withdraw_blackhole(&prefix).await.unwrap();
        }
        assert!(speaker.list_blackholes().await.unwrap() == BlackholeInventory::default());
        assert!(
            speaker
                .withdraw_blackhole(&"2001:db8::/64".parse().unwrap())
                .await
                .is_err()
        );
        assert_eq!(announcer.announced_count().await, 0);
    }
}
