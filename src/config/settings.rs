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
    #[serde(default)]
    pub alerting: crate::alerting::AlertingConfig,
    #[serde(default)]
    pub correlation: crate::correlation::CorrelationConfig,
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
    /// CORS allowed origin (e.g., "http://localhost:3000"). Omit when using a reverse proxy.
    #[serde(default)]
    pub cors_origin: Option<String>,
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
    /// LDAP configuration (placeholder, not yet implemented)
    #[serde(default)]
    pub ldap: Option<LdapConfig>,
    /// RADIUS configuration (placeholder, not yet implemented)
    #[serde(default)]
    pub radius: Option<RadiusConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    /// Mutual TLS - client certificates required
    Mtls,
    /// Bearer token authentication (from environment variable)
    Bearer,
    /// Username/password authentication with PostgreSQL-backed sessions
    Credentials,
    /// No authentication (development only)
    None,
}

/// LDAP configuration (placeholder for future implementation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConfig {
    /// LDAP server URL (e.g., "ldaps://ldap.example.com:636")
    pub url: String,
    /// Bind DN for LDAP queries
    pub bind_dn: String,
    /// Environment variable containing bind password
    pub bind_password_env: String,
    /// Base DN for user searches
    pub user_base_dn: String,
    /// LDAP filter for user lookup (use {username} as placeholder)
    pub user_filter: String,
    /// Map LDAP groups to operator roles
    #[serde(default)]
    pub role_mapping: std::collections::HashMap<String, String>,
}

/// RADIUS configuration (placeholder for future implementation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadiusConfig {
    /// Primary RADIUS server (host:port)
    pub server: String,
    /// Secondary RADIUS server for failover
    #[serde(default)]
    pub secondary_server: Option<String>,
    /// Environment variable containing shared secret
    pub secret_env: String,
    /// Authentication timeout in seconds
    #[serde(default = "default_radius_timeout")]
    pub timeout_seconds: u32,
    /// Number of retries before failover
    #[serde(default = "default_radius_retries")]
    pub retries: u32,
    /// NAS identifier sent in Access-Request
    #[serde(default)]
    pub nas_identifier: Option<String>,
    /// Map RADIUS VSA or groups to operator roles
    #[serde(default)]
    pub role_mapping: std::collections::HashMap<String, String>,
}

fn default_radius_timeout() -> u32 {
    5
}

fn default_radius_retries() -> u32 {
    3
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

fn default_events_per_second() -> u32 {
    100
}
fn default_burst() -> u32 {
    500
}

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

fn default_bgp_mode() -> BgpMode {
    BgpMode::Sidecar
}

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
    /// Minimum TTL in seconds (default: from timers.min_ttl_seconds)
    #[serde(default)]
    pub min_ttl_seconds: Option<u32>,
    /// Maximum TTL in seconds (default: from timers.max_ttl_seconds)
    #[serde(default)]
    pub max_ttl_seconds: Option<u32>,
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

fn default_true() -> bool {
    true
}
fn default_32() -> u8 {
    32
}
fn default_max_ports() -> usize {
    8
}

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

fn default_max_per_customer() -> u32 {
    5
}
fn default_max_per_pop() -> u32 {
    200
}
fn default_max_global() -> u32 {
    500
}
fn default_max_new_per_minute() -> u32 {
    30
}
fn default_max_per_peer() -> u32 {
    100
}

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

fn default_ttl() -> u32 {
    120
}
fn default_min_ttl() -> u32 {
    30
}
fn default_max_ttl() -> u32 {
    1800
}
fn default_correlation_window() -> u32 {
    300
}
fn default_reconciliation_interval() -> u32 {
    30
}
fn default_quiet_period() -> u32 {
    120
}

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

fn default_min_persistence() -> u32 {
    120
}
fn default_min_confidence() -> f64 {
    0.7
}
fn default_max_escalated_duration() -> u32 {
    1800
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// PostgreSQL connection string (e.g., "postgres://user:pass@localhost/prefixd")
    pub connection_string: String,
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

fn default_log_format() -> LogFormat {
    LogFormat::Json
}
fn default_log_level() -> String {
    "info".to_string()
}

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

fn default_drain_timeout() -> u32 {
    30
}

impl Settings {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let settings: Settings = serde_yaml::from_str(&content)?;
        let correlation_errors = settings.correlation.validate();
        if !correlation_errors.is_empty() {
            return Err(anyhow::anyhow!(
                "invalid correlation config in settings: {}",
                correlation_errors.join("; ")
            ));
        }
        Ok(settings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid YAML for a Settings struct (no correlation section).
    const MINIMAL_SETTINGS_YAML: &str = r#"
pop: iad1
mode: dry-run
http:
  listen: "0.0.0.0:8080"
  auth:
    mode: none
bgp:
  mode: mock
  gobgp_grpc: "localhost:50051"
  local_asn: 65010
  router_id: "10.10.0.10"
guardrails:
  require_ttl: true
  dst_prefix_minlen: 32
  dst_prefix_maxlen: 32
  max_ports: 8
  allow_src_prefix_match: false
quotas:
  max_active_per_customer: 5
  max_active_per_pop: 200
  max_active_global: 500
  max_new_per_minute: 30
timers:
  default_ttl_seconds: 120
  min_ttl_seconds: 30
  max_ttl_seconds: 1800
  correlation_window_seconds: 300
  reconciliation_interval_seconds: 30
escalation:
  enabled: true
  min_persistence_seconds: 120
  min_confidence: 0.7
storage:
  connection_string: "postgres://user:pass@localhost/prefixd"
observability:
  log_format: pretty
  log_level: info
  audit_log_path: "./data/audit.jsonl"
  metrics_listen: "0.0.0.0:9090"
"#;

    #[test]
    fn test_settings_without_correlation_defaults_to_disabled() {
        let settings: Settings = serde_yaml::from_str(MINIMAL_SETTINGS_YAML).unwrap();
        assert!(!settings.correlation.enabled);
        assert_eq!(settings.correlation.window_seconds, 300);
        assert_eq!(settings.correlation.min_sources, 1);
        assert_eq!(settings.correlation.confidence_threshold, 0.5);
        assert!(settings.correlation.sources.is_empty());
        assert_eq!(settings.correlation.default_weight, 1.0);
    }

    #[test]
    fn test_settings_with_correlation_section() {
        let yaml = format!(
            "{}{}",
            MINIMAL_SETTINGS_YAML,
            r#"
correlation:
  enabled: true
  window_seconds: 600
  min_sources: 2
  confidence_threshold: 0.7
  default_weight: 0.5
  sources:
    fastnetmon:
      weight: 2.0
      type: detector
    alertmanager:
      weight: 0.8
      type: telemetry
"#
        );
        let settings: Settings = serde_yaml::from_str(&yaml).unwrap();
        assert!(settings.correlation.enabled);
        assert_eq!(settings.correlation.window_seconds, 600);
        assert_eq!(settings.correlation.min_sources, 2);
        assert_eq!(settings.correlation.confidence_threshold, 0.7);
        assert_eq!(settings.correlation.default_weight, 0.5);
        assert_eq!(settings.correlation.sources.len(), 2);
        assert_eq!(settings.correlation.sources["fastnetmon"].weight, 2.0);
        assert_eq!(
            settings.correlation.sources["fastnetmon"].r#type,
            "detector"
        );
    }

    #[test]
    fn test_settings_with_empty_correlation_section() {
        let yaml = format!(
            "{}{}",
            MINIMAL_SETTINGS_YAML,
            r#"
correlation: {}
"#
        );
        let settings: Settings = serde_yaml::from_str(&yaml).unwrap();
        // Empty section should still use defaults
        assert!(!settings.correlation.enabled);
        assert_eq!(settings.correlation.window_seconds, 300);
    }
}
