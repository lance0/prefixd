use utoipa::OpenApi;

use super::handlers::{
    ErrorResponse, EventResponse, HealthResponse, IpHistoryResponse, MitigationResponse,
    MitigationsListResponse, PublicHealthResponse, ReloadResponse, TimeseriesResponse,
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
        super::handlers::health_detail,
        super::handlers::ingest_event,
        super::handlers::list_mitigations,
        super::handlers::get_mitigation,
        super::handlers::get_stats,
        super::handlers::list_pops,
        super::handlers::get_config_settings,
        super::handlers::get_config_inventory,
        super::handlers::get_config_playbooks,
        super::handlers::update_playbooks,
        super::handlers::get_alerting_config,
        super::handlers::test_alerting,
        super::handlers::get_timeseries,
        super::handlers::get_ip_history,
    ),
    components(
        schemas(
            EventResponse,
            MitigationResponse,
            MitigationsListResponse,
            PublicHealthResponse,
            HealthResponse,
            ErrorResponse,
            ReloadResponse,
            GlobalStats,
            PopStats,
            PopInfo,
            SafelistEntry,
            TimeseriesResponse,
            IpHistoryResponse,
            crate::db::TimeseriesBucket,
        )
    ),
    tags(
        (name = "health", description = "Health and status endpoints"),
        (name = "events", description = "Attack event ingestion"),
        (name = "mitigations", description = "Mitigation management"),
        (name = "safelist", description = "Safelist management"),
        (name = "config", description = "Configuration management"),
        (name = "multi-pop", description = "Multi-POP coordination"),
        (name = "stats", description = "Statistics and timeseries"),
        (name = "ip-history", description = "IP history and context"),
    )
)]
pub struct ApiDoc;
