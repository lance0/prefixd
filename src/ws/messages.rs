use serde::Serialize;

use crate::api::handlers::MitigationResponse;

/// WebSocket message types for real-time updates.
///
/// Event ingestion is deliberately not a frame type: the feed carries
/// mitigation and scrubber lifecycle changes, while event lists keep their API
/// refresh. Add a frame type only together with a sender.
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

    /// A durable diversion admission or lifecycle transition.
    DiversionUpdated {
        diversion: Box<crate::scrubber::Diversion>,
    },

    /// Current bounded readiness and re-arm state for a configured profile.
    ScrubberUpdated {
        profile: String,
        state: crate::scrubber::ProfileState,
    },

    /// Client fell behind, needs to resync
    ResyncRequired {},
}
