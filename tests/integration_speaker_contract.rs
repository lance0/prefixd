#[path = "common/speaker_contract.rs"]
mod contract;

use prefixd::{
    bgp::{FlowSpecAnnouncer, FlowSpecReader, FlowSpecWriter, MockAnnouncer},
    domain::FlowSpecRule,
};

#[tokio::test]
async fn mock_passes_readable_backend_contract() {
    let speaker = MockAnnouncer::new();
    contract::run_readable_contract(&speaker).await.unwrap();
    contract::wait_peer_state(&speaker, "127.0.0.1", true)
        .await
        .unwrap();
}

#[tokio::test]
async fn mock_passes_amplification_contract() {
    contract::run_amplification_contract(&MockAnnouncer::new())
        .await
        .unwrap();
}

struct MissingActions(MockAnnouncer);
impl FlowSpecAnnouncer for MissingActions {
    fn backend(&self) -> &'static str {
        "broken-mock"
    }
    fn reader(&self) -> Option<&dyn FlowSpecReader> {
        Some(self)
    }
}
#[async_trait::async_trait]
impl FlowSpecWriter for MissingActions {
    async fn announce(&self, rule: &FlowSpecRule) -> prefixd::error::Result<()> {
        self.0.announce(rule).await
    }
    async fn withdraw(&self, rule: &FlowSpecRule) -> prefixd::error::Result<()> {
        self.0.withdraw(rule).await
    }
}
#[async_trait::async_trait]
impl FlowSpecReader for MissingActions {
    async fn list_active(&self) -> prefixd::error::Result<Vec<FlowSpecRule>> {
        let mut rules = self.0.list_active().await?;
        for rule in &mut rules {
            rule.actions.clear();
        }
        Ok(rules)
    }
}
#[tokio::test(start_paused = true)]
async fn shared_oracle_rejects_a_broken_adapter() {
    let error = contract::run_readable_contract(&MissingActions(MockAnnouncer::new()))
        .await
        .unwrap_err();
    let diagnostic = format!("{error:#}");
    assert!(
        diagnostic.contains("dual-family idempotent announce"),
        "{diagnostic}"
    );
    assert!(
        diagnostic.contains("action cardinality mismatch"),
        "{diagnostic}"
    );
}
