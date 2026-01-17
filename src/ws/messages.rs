use serde::Serialize;

use crate::api::handlers::{EventResponse, MitigationResponse};

/// WebSocket message types for real-time updates
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsMessage {
    /// A new mitigation was created
    MitigationCreated { mitigation: MitigationResponse },
    
    /// An existing mitigation was updated
    MitigationUpdated { mitigation: MitigationResponse },
    
    /// A mitigation expired due to TTL
    MitigationExpired { mitigation_id: String },
    
    /// A mitigation was manually withdrawn
    MitigationWithdrawn { mitigation_id: String },
    
    /// A new event was ingested
    EventIngested { event: EventResponse },
    
    /// Client fell behind, needs to resync
    ResyncRequired {},
}
