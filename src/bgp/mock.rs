use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{
    BlackholeRoute, BlackholeSpeaker, FlowSpecAnnouncer, FlowSpecReader, FlowSpecWriter,
    PeerObserver, PeerStatus, SessionState,
};
use crate::domain::FlowSpecRule;
use crate::error::Result;

/// Mock announcer for testing
#[derive(Debug, Default)]
pub struct MockAnnouncer {
    rules: Arc<RwLock<Vec<FlowSpecRule>>>,
    blackholes: RwLock<Vec<BlackholeRoute>>,
    peers: Vec<PeerStatus>,
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
        }
    }

    pub fn with_peers(peers: Vec<PeerStatus>) -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            blackholes: RwLock::default(),
            peers,
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
    async fn list_blackholes(&self) -> Result<Vec<BlackholeRoute>> {
        Ok(self.blackholes.read().await.clone())
    }
}
#[async_trait]
impl PeerObserver for MockAnnouncer {
    async fn session_status(&self) -> Result<Vec<PeerStatus>> {
        Ok(self.peers.clone())
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
            assert_eq!(speaker.list_blackholes().await.unwrap(), [route]);
        }
        for _ in 0..2 {
            speaker.withdraw_blackhole(&prefix).await.unwrap();
        }
        assert!(speaker.list_blackholes().await.unwrap().is_empty());
        assert!(
            speaker
                .withdraw_blackhole(&"2001:db8::/64".parse().unwrap())
                .await
                .is_err()
        );
        assert_eq!(announcer.announced_count().await, 0);
    }
}
