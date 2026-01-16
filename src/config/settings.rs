use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub pop: String,
    #[serde(default = "default_mode")]
    pub mode: OperationMode,
    pub http: HttpConfig,
    pub bgp: BgpConfig,
    pub guardrails: GuardrailsConfig,
    pub quotas: QuotasConfig,
    pub timers: TimersConfig,
    pub escalation: EscalationConfig,
    pub storage: StorageConfig,
    pub observability: ObservabilityConfig,
    #[serde(default)]
    pub safelist: SafelistConfig,
    #[serde(default)]
    pub shutdown: ShutdownConfig,
}

fn default_mode() -> OperationMode {
    OperationMode::DryRun
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationMode {
    DryRun,
    Enforced,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    pub listen: String,
    pub auth: AuthConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    /// CA certificate for client verification (required for mTLS)
    pub ca_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub mode: AuthMode,
    #[serde(default)]
    pub bearer_token_env: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    Mtls,
    Bearer,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_events_per_second")]
    pub events_per_second: u32,
    #[serde(default = "default_burst")]
    pub burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            events_per_second: default_events_per_second(),
            burst: default_burst(),
        }
    }
}

fn default_events_per_second() -> u32 { 100 }
fn default_burst() -> u32 { 500 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpConfig {
    #[serde(default = "default_bgp_mode")]
    pub mode: BgpMode,
    pub gobgp_grpc: String,
    pub local_asn: u32,
    pub router_id: String,
    #[serde(default)]
    pub neighbors: Vec<BgpNeighbor>,
}

fn default_bgp_mode() -> BgpMode { BgpMode::Sidecar }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BgpMode {
    Sidecar,
    Mock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpNeighbor {
    pub name: String,
    pub address: String,
    pub peer_asn: u32,
    #[serde(default)]
    pub password_env: Option<String>,
    #[serde(default)]
    pub afi_safi: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardrailsConfig {
    #[serde(default = "default_true")]
    pub require_ttl: bool,
    #[serde(default = "default_32")]
    pub dst_prefix_minlen: u8,
    #[serde(default = "default_32")]
    pub dst_prefix_maxlen: u8,
    /// Minimum prefix length for IPv6 (default: 128)
    #[serde(default)]
    pub dst_prefix_minlen_v6: Option<u8>,
    /// Maximum prefix length for IPv6 (default: 128)
    #[serde(default)]
    pub dst_prefix_maxlen_v6: Option<u8>,
    #[serde(default = "default_max_ports")]
    pub max_ports: usize,
    #[serde(default)]
    pub allow_src_prefix_match: bool,
    #[serde(default)]
    pub allow_tcp_flags_match: bool,
    #[serde(default)]
    pub allow_fragment_match: bool,
    #[serde(default)]
    pub allow_packet_length_match: bool,
}

fn default_true() -> bool { true }
fn default_32() -> u8 { 32 }
fn default_max_ports() -> usize { 8 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotasConfig {
    #[serde(default = "default_max_per_customer")]
    pub max_active_per_customer: u32,
    #[serde(default = "default_max_per_pop")]
    pub max_active_per_pop: u32,
    #[serde(default = "default_max_global")]
    pub max_active_global: u32,
    #[serde(default = "default_max_new_per_minute")]
    pub max_new_per_minute: u32,
    #[serde(default = "default_max_per_peer")]
    pub max_announcements_per_peer: u32,
}

fn default_max_per_customer() -> u32 { 5 }
fn default_max_per_pop() -> u32 { 200 }
fn default_max_global() -> u32 { 500 }
fn default_max_new_per_minute() -> u32 { 30 }
fn default_max_per_peer() -> u32 { 100 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimersConfig {
    #[serde(default = "default_ttl")]
    pub default_ttl_seconds: u32,
    #[serde(default = "default_min_ttl")]
    pub min_ttl_seconds: u32,
    #[serde(default = "default_max_ttl")]
    pub max_ttl_seconds: u32,
    #[serde(default = "default_correlation_window")]
    pub correlation_window_seconds: u32,
    #[serde(default = "default_reconciliation_interval")]
    pub reconciliation_interval_seconds: u32,
    #[serde(default = "default_quiet_period")]
    pub quiet_period_after_withdraw_seconds: u32,
}

fn default_ttl() -> u32 { 120 }
fn default_min_ttl() -> u32 { 30 }
fn default_max_ttl() -> u32 { 1800 }
fn default_correlation_window() -> u32 { 300 }
fn default_reconciliation_interval() -> u32 { 30 }
fn default_quiet_period() -> u32 { 120 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_min_persistence")]
    pub min_persistence_seconds: u32,
    #[serde(default = "default_min_confidence")]
    pub min_confidence: f64,
    #[serde(default = "default_max_escalated_duration")]
    pub max_escalated_duration_seconds: u32,
}

fn default_min_persistence() -> u32 { 120 }
fn default_min_confidence() -> f64 { 0.7 }
fn default_max_escalated_duration() -> u32 { 1800 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "default_driver")]
    pub driver: StorageDriver,
    /// For SQLite: file path (e.g., "./data/prefixd.db")
    /// For Postgres: connection string (e.g., "postgres://user:pass@localhost/prefixd")
    pub path: String,
}

fn default_driver() -> StorageDriver { StorageDriver::Sqlite }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageDriver {
    Sqlite,
    Postgres,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    #[serde(default = "default_log_format")]
    pub log_format: LogFormat,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    pub audit_log_path: String,
    pub metrics_listen: String,
}

fn default_log_format() -> LogFormat { LogFormat::Json }
fn default_log_level() -> String { "info".to_string() }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Pretty,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SafelistConfig {
    #[serde(default)]
    pub prefixes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownConfig {
    #[serde(default = "default_drain_timeout")]
    pub drain_timeout_seconds: u32,
    #[serde(default = "default_true")]
    pub preserve_announcements: bool,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            drain_timeout_seconds: default_drain_timeout(),
            preserve_announcements: true,
        }
    }
}

fn default_drain_timeout() -> u32 { 30 }

impl Settings {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let settings: Settings = serde_yaml::from_str(&content)?;
        Ok(settings)
    }
}
