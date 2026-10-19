use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum PrefixdError {
    // API errors
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("rate limited, retry after {retry_after_seconds}s")]
    RateLimited { retry_after_seconds: u32 },

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("service shutting down")]
    ShuttingDown,

    #[error(
        "controller is in standby: another controller holds this POP's fence; retry against the active controller"
    )]
    Standby,

    // Domain errors
    #[error("duplicate event from {detector_source}: {external_id}")]
    DuplicateEvent {
        detector_source: String,
        external_id: String,
    },

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("mitigation not found: {0}")]
    MitigationNotFound(Uuid),

    #[error("invalid IP address: {0}")]
    InvalidIpAddress(String),

    #[error("invalid prefix: {0}")]
    InvalidPrefix(String),

    // Guardrail errors
    #[error("guardrail violation: {0}")]
    GuardrailViolation(GuardrailError),

    // Policy errors
    #[error("no playbook found for vector: {0}")]
    NoPlaybookFound(String),

    #[error("IP not owned by any customer: {0}")]
    IpNotOwned(String),

    // BGP errors
    #[error("BGP announcement failed: {0}")]
    BgpAnnouncementFailed(String),

    #[error("BGP withdrawal failed: {0}")]
    BgpWithdrawalFailed(String),

    #[error("BGP session error: peer={peer}, error={error}")]
    BgpSessionError { peer: String, error: String },

    // Storage errors
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    // Config errors
    #[error("configuration error: {0}")]
    Config(String),

    // Internal errors
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Error, Debug, Clone)]
pub enum GuardrailError {
    #[error("invalid FlowSpec action: {0}")]
    InvalidAction(#[source] crate::domain::FlowSpecActionError),

    #[error("TTL required but not provided")]
    TtlRequired,

    #[error("TTL {ttl}s out of bounds (min={min}, max={max})")]
    TtlOutOfBounds { ttl: u32, min: u32, max: u32 },

    #[error("destination prefix /{len} violates length constraint (min=/{min}, max=/{max})")]
    PrefixLengthViolation { len: u8, min: u8, max: u8 },

    #[error("IP {ip} is safelisted")]
    Safelisted { ip: String },

    #[error("IP {ip} not owned by any customer")]
    NotOwned { ip: String },

    #[error("too many ports: {count} (max={max})")]
    TooManyPorts { count: usize, max: usize },

    #[error("quota exceeded: {quota_type} ({current}/{max})")]
    QuotaExceeded {
        quota_type: String,
        current: u32,
        max: u32,
    },

    #[error(
        "new mitigation rate exceeded: {current} created at this POP in the last 60s (max_new_per_minute={max})"
    )]
    NewMitigationRateExceeded { current: u32, max: u32 },

    #[error("source prefix matching not allowed")]
    SrcPrefixNotAllowed,

    #[error("no allowed ports for service")]
    NoAllowedPorts,

    #[error("blackhole mitigations are disabled (blackhole.enabled=false)")]
    BlackholeDisabled,

    #[error("blackhole refused: {reason}")]
    InvalidBlackhole { reason: String },
}

pub type Result<T> = std::result::Result<T, PrefixdError>;

impl PrefixdError {
    pub fn status_code(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match self {
            Self::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::NotFound(_) | Self::MitigationNotFound(_) => StatusCode::NOT_FOUND,
            Self::ShuttingDown | Self::Standby => StatusCode::SERVICE_UNAVAILABLE,
            Self::DuplicateEvent { .. } | Self::Conflict(_) => StatusCode::CONFLICT,
            Self::GuardrailViolation(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::IpNotOwned(_) | Self::InvalidIpAddress(_) | Self::InvalidPrefix(_) => {
                StatusCode::BAD_REQUEST
            }
            Self::NoPlaybookFound(_) => StatusCode::UNPROCESSABLE_ENTITY,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
