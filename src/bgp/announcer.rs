use async_trait::async_trait;

use crate::domain::FlowSpecRule;
use crate::error::Result;

#[derive(Debug, Clone)]
pub struct PeerStatus {
    pub name: String,
    pub address: String,
    pub state: SessionState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

impl SessionState {
    pub fn is_established(&self) -> bool {
        matches!(self, Self::Established)
    }
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "idle"),
            Self::Connect => write!(f, "connect"),
            Self::Active => write!(f, "active"),
            Self::OpenSent => write!(f, "opensent"),
            Self::OpenConfirm => write!(f, "openconfirm"),
            Self::Established => write!(f, "established"),
        }
    }
}

/// Trait for FlowSpec BGP announcements
#[async_trait]
pub trait FlowSpecAnnouncer: Send + Sync {
    /// Announce a FlowSpec rule
    async fn announce(&self, rule: &FlowSpecRule) -> Result<()>;

    /// Withdraw a FlowSpec rule
    async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()>;

    /// List currently announced FlowSpec rules
    async fn list_active(&self) -> Result<Vec<FlowSpecRule>>;

    /// Get BGP session status for all peers
    async fn session_status(&self) -> Result<Vec<PeerStatus>>;
}
