use async_trait::async_trait;

use super::{FlowSpecAnnouncer, PeerStatus, SessionState};
use crate::domain::FlowSpecRule;
use crate::error::{PrefixdError, Result};

/// GoBGP gRPC client for FlowSpec announcements
pub struct GoBgpAnnouncer {
    endpoint: String,
    // TODO: Add tonic client when proto is generated
}

impl GoBgpAnnouncer {
    pub fn new(endpoint: String) -> Self {
        Self { endpoint }
    }

    pub async fn connect(&self) -> Result<()> {
        // TODO: Establish gRPC connection
        tracing::info!(endpoint = %self.endpoint, "connecting to GoBGP");
        Ok(())
    }
}

#[async_trait]
impl FlowSpecAnnouncer for GoBgpAnnouncer {
    async fn announce(&self, rule: &FlowSpecRule) -> Result<()> {
        // TODO: Implement via GoBGP gRPC API
        // gobgp.api.AddPath with FlowSpec NLRI
        tracing::info!(
            nlri_hash = %rule.nlri_hash(),
            dst_prefix = %rule.nlri.dst_prefix,
            "announcing flowspec rule"
        );
        Err(PrefixdError::BgpAnnouncementFailed(
            "GoBGP client not yet implemented".to_string(),
        ))
    }

    async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()> {
        // TODO: Implement via GoBGP gRPC API
        // gobgp.api.DeletePath with FlowSpec NLRI
        tracing::info!(
            nlri_hash = %rule.nlri_hash(),
            dst_prefix = %rule.nlri.dst_prefix,
            "withdrawing flowspec rule"
        );
        Err(PrefixdError::BgpWithdrawalFailed(
            "GoBGP client not yet implemented".to_string(),
        ))
    }

    async fn list_active(&self) -> Result<Vec<FlowSpecRule>> {
        // TODO: Implement via GoBGP gRPC API
        // gobgp.api.ListPath for FlowSpec AFI/SAFI
        Ok(vec![])
    }

    async fn session_status(&self) -> Result<Vec<PeerStatus>> {
        // TODO: Implement via GoBGP gRPC API
        // gobgp.api.ListPeer
        Ok(vec![PeerStatus {
            name: "gobgp".to_string(),
            address: self.endpoint.clone(),
            state: SessionState::Idle,
        }])
    }
}
