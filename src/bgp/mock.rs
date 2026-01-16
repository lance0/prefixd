use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{FlowSpecAnnouncer, PeerStatus, SessionState};
use crate::domain::FlowSpecRule;
use crate::error::Result;

/// Mock announcer for testing
#[derive(Debug, Default)]
pub struct MockAnnouncer {
    rules: Arc<RwLock<Vec<FlowSpecRule>>>,
    peers: Vec<PeerStatus>,
}

impl MockAnnouncer {
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
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
            peers,
        }
    }

    pub async fn announced_count(&self) -> usize {
        self.rules.read().await.len()
    }
}

#[async_trait]
impl FlowSpecAnnouncer for MockAnnouncer {
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

    async fn list_active(&self) -> Result<Vec<FlowSpecRule>> {
        Ok(self.rules.read().await.clone())
    }

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
}
