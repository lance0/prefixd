use utoipa::OpenApi;

use super::handlers::{
    ErrorResponse, EventResponse, HealthResponse, MitigationResponse, MitigationsListResponse,
    ReloadResponse,
};
use crate::db::{GlobalStats, PopInfo, PopStats, SafelistEntry};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "prefixd API",
        version = "1.0.0",
        description = "BGP FlowSpec routing policy daemon for automated DDoS mitigation",
        license(name = "MIT"),
        contact(name = "prefixd")
    ),
    servers(
        (url = "/", description = "Local server")
    ),
    paths(
        super::handlers::health,
        super::handlers::ingest_event,
        super::handlers::list_mitigations,
        super::handlers::get_mitigation,
        super::handlers::get_stats,
        super::handlers::list_pops,
    ),
    components(
        schemas(
            EventResponse,
            MitigationResponse,
            MitigationsListResponse,
            HealthResponse,
            ErrorResponse,
            ReloadResponse,
            GlobalStats,
            PopStats,
            PopInfo,
            SafelistEntry,
        )
    ),
    tags(
        (name = "health", description = "Health and status endpoints"),
        (name = "events", description = "Attack event ingestion"),
        (name = "mitigations", description = "Mitigation management"),
        (name = "safelist", description = "Safelist management"),
        (name = "config", description = "Configuration management"),
        (name = "multi-pop", description = "Multi-POP coordination"),
    )
)]
pub struct ApiDoc;
