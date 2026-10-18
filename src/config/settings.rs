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

impl OperationMode {
    /// Configuration spelling, also persisted as a mitigation's origin mode.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DryRun => "dry-run",
            Self::Enforced => "enforced",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        [Self::DryRun, Self::Enforced]
            .into_iter()
            .find(|mode| mode.as_str() == value)
    }
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

impl HttpConfig {
    /// mTLS authorization trusts the native listener to verify client certificates.
    pub(crate) fn validate_auth_transport(&self) -> crate::error::Result<()> {
        if self.auth.mode != AuthMode::Mtls {
            return Ok(());
        }
        let tls = self.tls.as_ref().ok_or_else(|| {
            crate::error::PrefixdError::Config("auth.mode=mtls requires native http.tls".into())
        })?;
        for (field, path) in [
            ("cert_path", Some(tls.cert_path.as_str())),
            ("key_path", Some(tls.key_path.as_str())),
            ("ca_path", tls.ca_path.as_deref()),
        ] {
            if path.is_none_or(|path| path.trim().is_empty()) {
                return Err(crate::error::PrefixdError::Config(format!(
                    "auth.mode=mtls requires nonempty http.tls.{field}"
                )));
            }
        }
        Ok(())
    }
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
    /// Mutual TLS - client certificates required
    Mtls,
    /// Bearer token authentication (from environment variable)
    Bearer,
    /// Username/password authentication with PostgreSQL-backed sessions
    Credentials,
    /// No authentication (development only)
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

fn default_events_per_second() -> u32 {
    100
}
fn default_burst() -> u32 {
    500
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpConfig {
    #[serde(
        default = "default_bgp_mode",
        rename(deserialize = "backend"),
        alias = "mode"
    )]
    pub mode: BgpMode,
    #[serde(default)]
    pub gobgp_grpc: String,
    #[serde(default)]
    pub rustbgpd: Option<RustBgpdConfig>,
    pub local_asn: u32,
    pub router_id: String,
    #[serde(default)]
    pub neighbors: Vec<BgpNeighbor>,
}

fn default_bgp_mode() -> BgpMode {
    BgpMode::Rustbgpd
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BgpMode {
    Sidecar,
    Gobgp,
    Rustbgpd,
    Mock,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RustBgpdConfig {
    pub endpoint: String,
    #[serde(default)]
    pub bearer_token_env: String,
    #[serde(default)]
    pub ca_cert_path: Option<String>,
    #[serde(default)]
    pub client_cert_path: Option<String>,
    #[serde(default)]
    pub client_key_path: Option<String>,
}

impl RustBgpdConfig {
    /// Lexical identity survives socket recreation; never resolve a socket symlink.
    pub fn unix_socket_path(&self) -> Result<Option<std::path::PathBuf>> {
        if !self.endpoint.starts_with("unix:") {
            return Ok(None);
        }
        let path = self
            .endpoint
            .strip_prefix("unix://")
            .ok_or_else(|| anyhow::anyhow!("invalid rustbgpd Unix endpoint"))?;
        anyhow::ensure!(
            path.starts_with('/')
                && !path.contains(['@', '?', '#', '%', '\\', '\0'])
                && !path.chars().any(|c| c.is_whitespace() || c.is_control()),
            "invalid rustbgpd Unix endpoint"
        );
        let mut normalized = std::path::PathBuf::new();
        for component in std::path::Path::new(path).components() {
            match component {
                std::path::Component::RootDir | std::path::Component::Normal(_) => {
                    normalized.push(component.as_os_str())
                }
                std::path::Component::CurDir => {}
                _ => anyhow::bail!("invalid rustbgpd Unix endpoint"),
            }
        }
        anyhow::ensure!(
            normalized.file_name().is_some(),
            "invalid rustbgpd Unix endpoint"
        );
        Ok(Some(normalized))
    }
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
fn default_reconciliation_interval() -> u32 {
    30
}
fn default_quiet_period() -> u32 {
    120
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// PostgreSQL connection string (e.g., "postgres://user:pass@localhost/prefixd")
    pub connection_string: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityConfig {
    #[serde(default = "default_log_format")]
    pub log_format: LogFormat,
    #[serde(default = "default_log_level")]
    pub log_level: String,
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
#[serde(deny_unknown_fields)]
pub struct ShutdownConfig {
    #[serde(default = "default_drain_timeout")]
    pub drain_timeout_seconds: u32,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            drain_timeout_seconds: default_drain_timeout(),
        }
    }
}

fn default_drain_timeout() -> u32 {
    30
}

impl Settings {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let settings: Settings = crate::config::parse_yaml(&content)?;
        settings.http.validate_auth_transport()?;
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

    #[test]
    fn backend_selector_defaults_to_rustbgpd_and_selects_either_speaker() {
        let base = "local_asn: 65010\nrouter_id: 192.0.2.1\n";
        for (selector, expected) in [
            ("", BgpMode::Rustbgpd),
            ("backend: rustbgpd\n", BgpMode::Rustbgpd),
            ("backend: gobgp\n", BgpMode::Gobgp),
        ] {
            let config: BgpConfig =
                crate::config::parse_yaml(&format!("{base}{selector}")).unwrap();
            assert_eq!(config.mode, expected);
            assert_eq!(
                serde_json::to_value(&config).unwrap()["mode"],
                serde_json::to_value(expected).unwrap()
            );
        }
    }

    #[test]
    fn backend_selector_rejects_duplicate_and_unknown_values() {
        let base = "local_asn: 65010\nrouter_id: 192.0.2.1\n";
        for selector in [
            "backend: rustbgpd\nbackend: gobgp\n",
            "backend: rustbgpd\nmode: rustbgpd\n",
            "backend: exabgp\n",
        ] {
            assert!(crate::config::parse_yaml::<BgpConfig>(&format!("{base}{selector}")).is_err());
        }
    }

    #[test]
    fn shipped_speaker_examples_select_the_matching_backend() {
        for (yaml, expected) in [
            (
                include_str!("../../configs/prefixd.yaml"),
                BgpMode::Rustbgpd,
            ),
            (
                include_str!("../../configs/prefixd.yaml.example"),
                BgpMode::Rustbgpd,
            ),
            (
                include_str!("../../configs/prefixd-gobgp.yaml"),
                BgpMode::Gobgp,
            ),
        ] {
            let settings: Settings = crate::config::parse_yaml(yaml).unwrap();
            assert_eq!(settings.bgp.mode, expected);
            assert_eq!(settings.http.auth.mode, AuthMode::Credentials);
            assert_eq!(
                serde_json::to_value(settings.shutdown).unwrap(),
                serde_json::json!({ "drain_timeout_seconds": 30 })
            );
        }
    }

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
  reconciliation_interval_seconds: 30
storage:
  connection_string: "postgres://user:pass@localhost/prefixd"
observability:
  log_format: pretty
  log_level: info
"#;

    #[test]
    fn observability_only_configures_logging() {
        for (yaml, expected) in [
            (
                "{}",
                serde_json::json!({ "log_format": "json", "log_level": "info" }),
            ),
            (
                "log_format: pretty\nlog_level: debug\n",
                serde_json::json!({ "log_format": "pretty", "log_level": "debug" }),
            ),
        ] {
            let config: ObservabilityConfig = crate::config::parse_yaml(yaml).unwrap();
            assert_eq!(serde_json::to_value(config).unwrap(), expected);
        }
    }

    #[test]
    fn settings_reject_unknown_observability_keys_without_values() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("prefixd.yaml");
        for key in ["metrics_listen", "audit_log_path", "log_levle"] {
            let secret = "private-observability-value-must-not-appear";
            std::fs::write(&path, format!("{MINIMAL_SETTINGS_YAML}  {key}: {secret}\n")).unwrap();
            let error = Settings::load(&path).unwrap_err().to_string();
            assert!(error.contains("unknown field"), "{key}: {error}");
            assert!(error.contains(key), "{key}: {error}");
            assert!(!error.contains(secret), "{key}: configuration value leaked");
        }
    }

    #[test]
    fn shutdown_settings_preserve_drain_periods_and_exact_json() {
        assert_eq!(
            serde_json::to_value(ShutdownConfig::default()).unwrap(),
            serde_json::json!({ "drain_timeout_seconds": 30 })
        );
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("prefixd.yaml");
        for (shutdown, expected) in [
            ("", 30),
            ("shutdown: {}\n", 30),
            ("shutdown:\n  drain_timeout_seconds: 7\n", 7),
            ("shutdown:\n  drain_timeout_seconds: 0\n", 0),
        ] {
            std::fs::write(&path, format!("{MINIMAL_SETTINGS_YAML}{shutdown}")).unwrap();
            let settings = Settings::load(&path).unwrap();
            assert_eq!(settings.shutdown.drain_timeout_seconds, expected);
            assert_eq!(
                serde_json::to_value(settings.shutdown).unwrap(),
                serde_json::json!({ "drain_timeout_seconds": expected })
            );
        }
    }

    #[test]
    fn settings_reject_removed_and_unknown_shutdown_keys() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("prefixd.yaml");
        for (key, value) in [
            ("preserve_announcements", "false"),
            ("preserve_announcements", "true"),
            ("drain_timeot_seconds", "17"),
        ] {
            std::fs::write(
                &path,
                format!("{MINIMAL_SETTINGS_YAML}shutdown:\n  {key}: {value}\n"),
            )
            .unwrap();
            let error = Settings::load(&path).unwrap_err().to_string();
            assert!(error.contains("unknown field"), "{key}: {error}");
            assert!(error.contains(key), "{key}: {error}");
        }
    }

    #[test]
    fn test_settings_without_correlation_defaults_to_disabled() {
        let settings: Settings = crate::config::parse_yaml(MINIMAL_SETTINGS_YAML).unwrap();
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
        let settings: Settings = crate::config::parse_yaml(&yaml).unwrap();
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
        let settings: Settings = crate::config::parse_yaml(&yaml).unwrap();
        // Empty section should still use defaults
        assert!(!settings.correlation.enabled);
        assert_eq!(settings.correlation.window_seconds, 300);
    }
}
