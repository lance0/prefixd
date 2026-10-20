use utoipa::OpenApi;

use super::handlers::{
    AddSafelistRequest, AddSafelistResponse, AlertmanagerAlert, AlertmanagerAlertResult,
    AlertmanagerWebhookPayload, AlertmanagerWebhookResponse, AnnouncementOutcome,
    AuditListResponse, BatchEventRequest, BatchEventResponse, BatchEventResult,
    BlackholeRouteResponse, BulkAcknowledgeRequest, BulkAcknowledgeResponse, BulkAcknowledgeResult,
    BulkWithdrawRequest, BulkWithdrawResponse, BulkWithdrawResult, ChangePasswordRequest,
    CorrelationContext, CreateMitigationRequest, CreateOperatorRequest, ErrorResponse,
    EventResponse, EventsListResponse, FastNetMonAttackDetails, FastNetMonPayload, HealthResponse,
    IpHistoryResponse, LoginRequest, LoginResponse, MitigationResponse, MitigationsListResponse,
    OperatorInfo, OperatorListResponse, PublicHealthResponse, ReloadResponse,
    SignalGroupDetailResponse, SignalGroupsListResponse, TimeseriesResponse, WebhookEventResult,
    WebhookResponse,
};
use crate::correlation::config::{CorrelationConfig, SourceConfig};
use crate::correlation::engine::{
    CorrelationExplanation, SignalGroup, SignalGroupEvent, SignalGroupStatus, SourceContribution,
};
use crate::correlation::webhook::{WebhookAdapter, WebhookAuth, WebhookFieldMap};
use crate::db::{GlobalStats, NotificationPreferences, PopInfo, PopStats, SafelistEntry};

#[derive(OpenApi)]
#[openapi(
    modifiers(&StandbyResponses),
    info(
        title = "prefixd API",
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
        super::handlers::ready,
        super::handlers::ingest_event,
        super::handlers::ingest_events_batch,
        super::handlers::list_mitigations,
        super::handlers::create_mitigation,
        super::handlers::get_mitigation,
        super::handlers::bulk_withdraw_mitigations,
        super::handlers::bulk_acknowledge_mitigations,
        super::handlers::list_events,
        super::handlers::list_audit,
        super::handlers::get_stats,
        super::handlers::list_pops,
        super::handlers::get_config_settings,
        super::handlers::get_config_inventory,
        super::handlers::get_config_playbooks,
        super::handlers::update_playbooks,
        super::handlers::get_alerting_config,
        super::handlers::update_alerting_config,
        super::handlers::test_alerting,
        super::handlers::get_timeseries,
        super::handlers::get_ip_history,
        super::handlers::get_notification_preferences,
        super::handlers::update_notification_preferences,
        super::handlers::generate_incident_report,
        super::handlers::list_signal_groups,
        super::handlers::get_signal_group,
        super::handlers::ingest_alertmanager,
        super::handlers::ingest_fastnetmon,
        super::handlers::ingest_webhook,
        super::handlers::ingest_corroborator,
        super::handlers::get_corroborator_activity,
        super::handlers::list_cached_corroborators_handler,
        super::handlers::get_correlation_config,
        super::handlers::update_correlation_config,
        super::handlers::login,
        super::handlers::logout,
        super::handlers::get_me,
        super::handlers::list_operators,
        super::handlers::create_operator,
        super::handlers::delete_operator,
        super::handlers::change_password,
        super::handlers::add_safelist,
        super::handlers::remove_safelist,
    ),
    components(
        schemas(
            EventResponse,
            super::handlers::EventRuleOutcome,
            super::handlers::RuleOutcome,
            AnnouncementOutcome,
            CreateMitigationRequest,
            MitigationResponse,
            BlackholeRouteResponse,
            MitigationsListResponse,
            PublicHealthResponse,
            HealthResponse,
            super::handlers::ReadinessResponse,
            super::handlers::ReadinessStatus,
            super::handlers::SpeakerHealth,
            super::handlers::DaemonHealthObservation,
            crate::domain::LeaseHealth,
            crate::domain::LeaseState,
            crate::bgp::LeaseGeneration,
            ErrorResponse,
            ReloadResponse,
            GlobalStats,
            PopStats,
            PopInfo,
            SafelistEntry,
            AddSafelistRequest,
            AddSafelistResponse,
            LoginRequest,
            LoginResponse,
            CreateOperatorRequest,
            ChangePasswordRequest,
            OperatorInfo,
            OperatorListResponse,
            TimeseriesResponse,
            IpHistoryResponse,
            BulkWithdrawRequest,
            BulkWithdrawResponse,
            BulkWithdrawResult,
            BulkAcknowledgeRequest,
            BulkAcknowledgeResponse,
            BulkAcknowledgeResult,
            BatchEventRequest,
            BatchEventResponse,
            BatchEventResult,
            EventsListResponse,
            AuditListResponse,
            crate::db::TimeseriesBucket,
            NotificationPreferences,
            CorrelationContext,
            SignalGroupsListResponse,
            SignalGroupDetailResponse,
            AlertmanagerWebhookPayload,
            AlertmanagerAlert,
            AlertmanagerWebhookResponse,
            AlertmanagerAlertResult,
            FastNetMonPayload,
            FastNetMonAttackDetails,
            SignalGroup,
            SignalGroupEvent,
            SignalGroupStatus,
            CorrelationExplanation,
            SourceContribution,
            CorrelationConfig,
            SourceConfig,
            WebhookAdapter,
            WebhookAuth,
            WebhookFieldMap,
            WebhookResponse,
            WebhookEventResult,
            super::handlers::CorroboratorInput,
            super::handlers::CorroboratorResponse,
            super::handlers::CorroboratorActivityResponse,
            super::handlers::CorroboratorActivityEntry,
            super::handlers::CachedCorroboratorsResponse,
            super::handlers::CachedCorroboratorBySource,
            crate::correlation::PrimaryDimensions,
            crate::correlation::MatchDimension,
            crate::correlation::SourceMode,
        )
    ),
    tags(
        (name = "health", description = "Health and status endpoints"),
        (name = "events", description = "Attack event ingestion"),
        (name = "auth", description = "Authentication and session management"),
        (name = "operators", description = "Operator account management"),
        (name = "mitigations", description = "Mitigation management"),
        (name = "safelist", description = "Safelist management"),
        (name = "config", description = "Configuration management"),
        (name = "multi-pop", description = "Multi-POP coordination"),
        (name = "stats", description = "Statistics and timeseries"),
        (name = "ip-history", description = "IP history and context"),
        (name = "preferences", description = "Notification preferences"),
        (name = "reports", description = "Incident reports"),
        (name = "signal-groups", description = "Signal group correlation management"),
        (name = "signals", description = "Signal adapter webhook endpoints"),
    )
)]
pub struct ApiDoc;

/// Every state-changing API operation can return 503 from a standby controller
/// (ADR 027). Login and logout are outside the fenced routes.
struct StandbyResponses;

impl utoipa::Modify for StandbyResponses {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        for (path, item) in openapi.paths.paths.iter_mut() {
            if path.starts_with("/v1/auth/") {
                continue;
            }
            for operation in [
                &mut item.post,
                &mut item.put,
                &mut item.delete,
                &mut item.patch,
            ]
            .into_iter()
            .flatten()
            {
                operation
                    .responses
                    .responses
                    .entry("503".into())
                    .or_insert_with(|| {
                        utoipa::openapi::Response::new(
                            "Controller is in standby: another controller holds this POP's fence",
                        )
                        .into()
                    });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_changing_operations_document_standby() {
        let doc = ApiDoc::openapi();
        let paths = &doc.paths.paths;
        let has_503 = |op: &Option<utoipa::openapi::path::Operation>| {
            op.as_ref()
                .is_some_and(|op| op.responses.responses.contains_key("503"))
        };
        assert!(has_503(&paths["/v1/mitigations"].post));
        assert!(has_503(&paths["/v1/events"].post));
        assert!(!has_503(&paths["/v1/mitigations"].get));
        assert!(!has_503(&paths["/v1/auth/login"].post));
        assert!(has_503(&paths["/v1/ready"].get));
        let schema =
            serde_json::to_value(&doc.components.as_ref().unwrap().schemas["ReadinessStatus"])
                .unwrap();
        assert_eq!(
            schema["enum"],
            serde_json::json!(["standby", "draining", "ready"])
        );
    }

    #[test]
    fn manual_blackhole_is_documented() {
        let doc = serde_json::to_value(ApiDoc::openapi()).unwrap();
        let schemas = &doc["components"]["schemas"];
        let blackhole = schemas["MitigationResponse"]["properties"]["blackhole"].to_string();
        assert!(
            blackhole.contains("#/components/schemas/BlackholeRouteResponse"),
            "{blackhole}"
        );
        let route = &schemas["BlackholeRouteResponse"];
        for field in ["next_hop", "communities", "large_communities"] {
            assert!(route["properties"][field].is_object(), "{field}");
        }
        assert!(schemas["CreateMitigationRequest"]["properties"]["confirm_victim_ip"].is_object());
        assert!(doc["paths"]["/v1/mitigations"]["post"]["responses"]["403"].is_object());
    }

    #[test]
    fn manual_amplification_match_is_documented() {
        let doc = serde_json::to_value(ApiDoc::openapi()).unwrap();
        let schemas = &doc["components"]["schemas"];
        for schema in ["CreateMitigationRequest", "MitigationResponse"] {
            for field in ["src_ports", "fragment", "packet_length"] {
                assert!(
                    schemas[schema]["properties"][field].is_object(),
                    "{schema}.{field}"
                );
            }
        }
        assert_eq!(
            schemas["FragmentMatch"]["enum"],
            serde_json::json!(["non_first"])
        );
        for bound in ["min", "max"] {
            assert!(schemas["PacketLengthRange"]["properties"][bound].is_object());
        }
    }

    #[test]
    fn info_version_comes_from_cargo() {
        assert_eq!(ApiDoc::openapi().info.version, env!("CARGO_PKG_VERSION"));
    }
}
