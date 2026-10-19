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
    #[serde(default)]
    pub blackhole: BlackholeConfig,
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
#[serde(try_from = "BgpConfigInput")]
pub struct BgpConfig {
    pub mode: BgpMode,
    pub gobgp_grpc: String,
    pub rustbgpd: Option<RustBgpdConfig>,
    pub local_asn: u32,
    pub router_id: String,
    pub neighbors: Vec<BgpNeighbor>,
}

#[derive(Deserialize)]
struct BgpConfigInput {
    #[serde(default, rename = "backend", alias = "mode")]
    mode: Option<BgpMode>,
    #[serde(default)]
    gobgp_grpc: String,
    #[serde(default)]
    rustbgpd: Option<RustBgpdConfig>,
    local_asn: u32,
    router_id: String,
    #[serde(default)]
    neighbors: Vec<BgpNeighbor>,
}

impl TryFrom<BgpConfigInput> for BgpConfig {
    type Error = &'static str;

    /// An unset backend never moves a configured speaker. v0.19.1 defaulted to
    /// GoBGP and required `gobgp_grpc`, so that endpoint alone keeps GoBGP.
    fn try_from(input: BgpConfigInput) -> std::result::Result<Self, Self::Error> {
        let mode = match (input.mode, !input.gobgp_grpc.is_empty(), &input.rustbgpd) {
            (Some(mode), _, _) => mode,
            (None, true, Some(_)) => {
                return Err(
                    "bgp.backend is required when both bgp.gobgp_grpc and bgp.rustbgpd are set",
                );
            }
            (None, true, None) => BgpMode::Gobgp,
            (None, false, _) => BgpMode::Rustbgpd,
        };
        Ok(Self {
            mode,
            gobgp_grpc: input.gobgp_grpc,
            rustbgpd: input.rustbgpd,
            local_asn: input.local_asn,
            router_id: input.router_id,
            neighbors: input.neighbors,
        })
    }
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
    /// Cap on each port list (destination and source) separately. The default
    /// equals the rustbgpd encoder's per-list cap.
    #[serde(default = "default_max_ports")]
    pub max_ports: usize,
    /// Reserved (ADR 028): parsed so configurations load, has no effect.
    #[serde(default)]
    pub allow_src_prefix_match: bool,
    /// Reserved (ADR 028): parsed so configurations load, has no effect.
    #[serde(default)]
    pub allow_tcp_flags_match: bool,
    /// Admits rules with a non-first fragment match.
    #[serde(default)]
    pub allow_fragment_match: bool,
    /// Admits rules with a packet-length match.
    #[serde(default)]
    pub allow_packet_length_match: bool,
}

impl GuardrailsConfig {
    /// A rustbgpd `max_ports` above the encoder's per-list cap would save intent
    /// the encoder never announces. GoBGP has no per-list cap.
    pub fn validate_for_backend(&self, backend: BgpMode) -> Result<()> {
        let cap = crate::bgp::RUSTBGPD_MAX_PORTS_PER_LIST;
        anyhow::ensure!(
            backend != BgpMode::Rustbgpd || self.max_ports <= cap,
            "guardrails.max_ports is {} but the rustbgpd backend encodes at most {cap} ports per list; set guardrails.max_ports to {cap} or less",
            self.max_ports
        );
        Ok(())
    }

    /// Reserved flags set to true; startup warns once for each.
    pub fn reserved_flags_set(&self) -> Vec<&'static str> {
        [
            (
                "guardrails.allow_src_prefix_match",
                self.allow_src_prefix_match,
            ),
            (
                "guardrails.allow_tcp_flags_match",
                self.allow_tcp_flags_match,
            ),
        ]
        .into_iter()
        .filter_map(|(key, set)| set.then_some(key))
        .collect()
    }
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
#[serde(from = "ObservabilityInput")]
pub struct ObservabilityConfig {
    pub log_format: LogFormat,
    pub log_level: String,
}

/// Strict input that accepts and drops the removed keys listed in `REMOVED_KEYS`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservabilityInput {
    #[serde(default = "default_log_format")]
    log_format: LogFormat,
    #[serde(default = "default_log_level")]
    log_level: String,
    #[serde(default, rename = "audit_log_path")]
    _audit_log_path: Option<serde::de::IgnoredAny>,
    #[serde(default, rename = "metrics_listen")]
    _metrics_listen: Option<serde::de::IgnoredAny>,
}

impl From<ObservabilityInput> for ObservabilityConfig {
    fn from(input: ObservabilityInput) -> Self {
        Self {
            log_format: input.log_format,
            log_level: input.log_level,
        }
    }
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

/// Remotely triggered blackhole host routes (ADR 027). Off by default; every
/// key is validated at load whether or not the feature is enabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BlackholeConfig {
    pub enabled: bool,
    /// Discard next hop for IPv4 victims.
    pub next_hop_ipv4: Option<std::net::IpAddr>,
    /// Discard next hop for IPv6 victims.
    pub next_hop_ipv6: Option<std::net::IpAddr>,
    /// Standard communities (`ASN:value`) added to BLACKHOLE (65535:666).
    pub communities: Vec<String>,
    /// Large communities (`global:local1:local2`).
    pub large_communities: Vec<String>,
    /// Bounds manual requests and extensions; a nonzero TTL is always required.
    pub max_ttl_seconds: u32,
    /// Active blackholes at this POP, in addition to the general quotas.
    pub max_active_per_pop: u32,
    /// Active blackholes across all POPs sharing the database.
    pub max_active_global: u32,
}

impl Default for BlackholeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            next_hop_ipv4: None,
            next_hop_ipv6: None,
            communities: Vec::new(),
            large_communities: Vec::new(),
            max_ttl_seconds: 3600,
            max_active_per_pop: 10,
            max_active_global: 50,
        }
    }
}

/// RFC 1997 communities that can stop the route from reaching the router.
const REJECTED_BLACKHOLE_COMMUNITIES: [(u32, &str); 3] = [
    (0xFFFF_FF01, "NO_EXPORT"),
    (0xFFFF_FF02, "NO_ADVERTISE"),
    (0xFFFF_FF03, "NO_EXPORT_SUBCONFED"),
];

impl BlackholeConfig {
    /// Configured standard communities; BLACKHOLE is added by `BlackholeRoute`.
    pub fn parsed_communities(&self) -> crate::error::Result<Vec<u32>> {
        self.communities
            .iter()
            .map(|text| {
                let value = match parse_community_parts::<u16, 2>(text) {
                    Some([high, low]) => (u32::from(high) << 16) | u32::from(low),
                    None => {
                        return Err(blackhole_config_error(format!(
                            "communities entry {text:?} must be ASN:value with each part 0-65535"
                        )));
                    }
                };
                match REJECTED_BLACKHOLE_COMMUNITIES
                    .iter()
                    .find(|(rejected, _)| *rejected == value)
                {
                    Some((_, name)) => Err(blackhole_config_error(format!(
                        "communities must not include {name} ({text}); scope the route in router import or speaker export policy"
                    ))),
                    None => Ok(value),
                }
            })
            .collect()
    }

    pub fn parsed_large_communities(&self) -> crate::error::Result<Vec<[u32; 3]>> {
        self.large_communities
            .iter()
            .map(|text| {
                parse_community_parts::<u32, 3>(text).ok_or_else(|| {
                    blackhole_config_error(format!(
                        "large_communities entry {text:?} must be global:local1:local2 with each part 0-4294967295"
                    ))
                })
            })
            .collect()
    }

    /// The configured discard next hop for the victim's family.
    pub fn next_hop_for(&self, victim: std::net::IpAddr) -> Option<std::net::IpAddr> {
        if victim.is_ipv4() {
            self.next_hop_ipv4
        } else {
            self.next_hop_ipv6
        }
    }

    /// Static checks; the speaker capability and safelist are checked at startup
    /// by `guardrails::check_blackhole_startup`.
    pub fn validate(&self) -> crate::error::Result<()> {
        let communities = self.parsed_communities()?;
        let large_communities = self.parsed_large_communities()?;
        for (key, next_hop, ipv4) in [
            ("next_hop_ipv4", self.next_hop_ipv4, true),
            ("next_hop_ipv6", self.next_hop_ipv6, false),
        ] {
            let Some(next_hop) = next_hop else { continue };
            if next_hop.is_ipv4() != ipv4 {
                return Err(blackhole_config_error(format!(
                    "{key} must be an IPv{} address, got {next_hop}",
                    if ipv4 { 4 } else { 6 }
                )));
            }
            // The route constructor is the single definition of a usable next hop.
            crate::bgp::BlackholeRoute::new(
                ipnet::IpNet::from(next_hop),
                next_hop,
                communities.clone(),
                large_communities.clone(),
            )
            .map_err(|_| {
                blackhole_config_error(format!(
                    "{key} must be a nonzero unicast address, got {next_hop}"
                ))
            })?;
        }
        if self.max_ttl_seconds == 0 {
            return Err(blackhole_config_error(
                "max_ttl_seconds must be nonzero".into(),
            ));
        }
        if self.enabled && self.next_hop_ipv4.is_none() && self.next_hop_ipv6.is_none() {
            return Err(blackhole_config_error(
                "enabled requires next_hop_ipv4 or next_hop_ipv6".into(),
            ));
        }
        Ok(())
    }
}

fn blackhole_config_error(message: String) -> crate::error::PrefixdError {
    crate::error::PrefixdError::Config(format!("blackhole.{message}"))
}

/// Exactly `N` colon-separated decimal parts, each parsed as `T`.
fn parse_community_parts<T: std::str::FromStr + Copy + Default, const N: usize>(
    text: &str,
) -> Option<[T; N]> {
    let mut parts = [T::default(); N];
    let mut fields = text.split(':');
    for part in &mut parts {
        let field = fields.next()?;
        if field.is_empty() || !field.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        *part = field.parse().ok()?;
    }
    fields.next().is_none().then_some(parts)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(from = "ShutdownInput")]
pub struct ShutdownConfig {
    pub drain_timeout_seconds: u32,
}

/// Strict input that accepts and drops the removed key listed in `REMOVED_KEYS`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShutdownInput {
    #[serde(default = "default_drain_timeout")]
    drain_timeout_seconds: u32,
    #[serde(default, rename = "preserve_announcements")]
    _preserve_announcements: Option<serde::de::IgnoredAny>,
}

impl From<ShutdownInput> for ShutdownConfig {
    fn from(input: ShutdownInput) -> Self {
        Self {
            drain_timeout_seconds: input.drain_timeout_seconds,
        }
    }
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

/// Keys v0.19.1 shipped or documented that this release no longer uses. Each
/// loads, is ignored and is reported once; `DEPRECATED_CONFIG_REJECTED_IN` rejects
/// them. Any other unknown key keeps its section's existing behavior.
pub const REMOVED_KEYS: &[&str] = &[
    "escalation",
    "http.auth.ldap",
    "http.auth.radius",
    "timers.correlation_window_seconds",
    "observability.audit_log_path",
    "observability.metrics_listen",
    "shutdown.preserve_announcements",
];
pub const DEPRECATED_CONFIG_REJECTED_IN: &str = "0.21.0";

/// A legacy configuration form accepted by a compatibility rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigDeprecation {
    pub key: &'static str,
    pub message: &'static str,
}

impl Settings {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        Ok(Self::load_with_deprecations(path)?.0)
    }

    /// Loads settings and reports legacy forms, so startup can log them once.
    pub fn load_with_deprecations<P: AsRef<Path>>(
        path: P,
    ) -> Result<(Self, Vec<ConfigDeprecation>)> {
        let content = std::fs::read_to_string(path)?;
        let settings: Settings = crate::config::parse_yaml(&content)?;
        let deprecations = settings.deprecations(&content);
        settings.http.validate_auth_transport()?;
        settings.blackhole.validate()?;
        settings
            .guardrails
            .validate_for_backend(settings.bgp.mode)?;
        let correlation_errors = settings.correlation.validate();
        if !correlation_errors.is_empty() {
            return Err(anyhow::anyhow!(
                "invalid correlation config in settings: {}",
                correlation_errors.join("; ")
            ));
        }
        Ok((settings, deprecations))
    }

    /// Typed parsing has already accepted `content`; this untyped view only
    /// finds legacy keys.
    fn deprecations(&self, content: &str) -> Vec<ConfigDeprecation> {
        let document: serde_json::Value = crate::config::parse_yaml(content).unwrap_or_default();
        let present = |key: &str| {
            document
                .pointer(&format!("/{}", key.replace('.', "/")))
                .is_some()
        };
        let mut found: Vec<_> = REMOVED_KEYS
            .iter()
            .filter(|key| present(key))
            .map(|&key| ConfigDeprecation {
                key,
                message: "removed configuration key is ignored; delete it",
            })
            .collect();
        if self.bgp.mode == BgpMode::Gobgp && !present("bgp.backend") && !present("bgp.mode") {
            found.push(ConfigDeprecation {
                key: "bgp.backend",
                message: "bgp.backend is unset; keeping GoBGP because bgp.gobgp_grpc is set; add bgp.backend: gobgp",
            });
        }
        found
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
            let (settings, deprecations) = load_yaml(yaml).unwrap();
            assert_eq!(settings.bgp.mode, expected);
            // Shipped files pin the backend instead of relying on resolution.
            assert!(yaml.contains("\nbgp:\n") && yaml.contains("\n  backend: "));
            assert!(deprecations.is_empty(), "{deprecations:?}");
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
        for key in ["log_levle", "audit_log_paths", "metrics"] {
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
    fn settings_reject_unknown_shutdown_keys() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("prefixd.yaml");
        for (key, value) in [
            ("drain_timeot_seconds", "17"),
            ("preserve_announcement", "true"),
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

    fn load_yaml(yaml: &str) -> Result<(Settings, Vec<ConfigDeprecation>)> {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("prefixd.yaml");
        std::fs::write(&path, yaml).unwrap();
        Settings::load_with_deprecations(&path)
    }

    fn keys(deprecations: &[ConfigDeprecation]) -> Vec<&'static str> {
        deprecations.iter().map(|d| d.key).collect()
    }

    #[test]
    fn removed_keys_load_ignored_with_one_deprecation_each() {
        for (key, anchor, replacement) in [
            (
                "escalation",
                "storage:\n",
                "escalation:\n  enabled: true\n  min_confidence: 0.7\nstorage:\n",
            ),
            (
                "http.auth.ldap",
                "    mode: none\n",
                "    mode: none\n    ldap: {url: 'ldaps://ldap.invalid'}\n",
            ),
            (
                "http.auth.radius",
                "    mode: none\n",
                "    mode: none\n    radius: {server: 'radius.invalid:1812'}\n",
            ),
            (
                "timers.correlation_window_seconds",
                "  reconciliation_interval_seconds: 30\n",
                "  reconciliation_interval_seconds: 30\n  correlation_window_seconds: 300\n",
            ),
            (
                "observability.audit_log_path",
                "  log_level: info\n",
                "  log_level: info\n  audit_log_path: ./data/audit.jsonl\n",
            ),
            (
                "observability.metrics_listen",
                "  log_level: info\n",
                "  log_level: info\n  metrics_listen: 0.0.0.0:9090\n",
            ),
            (
                "shutdown.preserve_announcements",
                "storage:\n",
                "shutdown:\n  drain_timeout_seconds: 7\n  preserve_announcements: false\nstorage:\n",
            ),
        ] {
            assert!(MINIMAL_SETTINGS_YAML.contains(anchor), "{key}");
            let yaml = MINIMAL_SETTINGS_YAML.replacen(anchor, replacement, 1);
            let (settings, deprecations) = load_yaml(&yaml).unwrap();
            assert_eq!(keys(&deprecations), [key]);
            assert!(REMOVED_KEYS.contains(&key));
            let leaf = key.rsplit('.').next().unwrap();
            let json = serde_json::to_string(&settings).unwrap();
            assert!(!json.contains(leaf), "{key} must not round-trip: {json}");
        }
        assert!(load_yaml(MINIMAL_SETTINGS_YAML).unwrap().1.is_empty());
    }

    #[test]
    fn rustbgpd_refuses_max_ports_above_the_encoder_cap_at_load() {
        let shipped = include_str!("../../configs/prefixd.yaml");
        assert_eq!(shipped.matches("max_ports: 8\n").count(), 1);
        // The shipped rustbgpd config loads at the cap and is refused one above it.
        load_yaml(shipped).unwrap();
        let error = load_yaml(&shipped.replace("max_ports: 8\n", "max_ports: 9\n"))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("guardrails.max_ports is 9")
                && error.contains("encodes at most 8 ports per list"),
            "{error}"
        );
        // GoBGP and the mock have no per-list cap.
        let parse = |yaml: &str| crate::config::parse_yaml::<GuardrailsConfig>(yaml).unwrap();
        for (backend, max_ports, accepted) in [
            (BgpMode::Rustbgpd, 8, true),
            (BgpMode::Rustbgpd, 9, false),
            (BgpMode::Gobgp, 64, true),
            (BgpMode::Sidecar, 64, true),
            (BgpMode::Mock, 64, true),
        ] {
            let result = parse(&format!("max_ports: {max_ports}\n")).validate_for_backend(backend);
            assert_eq!(result.is_ok(), accepted, "{backend:?} {max_ports}");
        }
    }

    #[test]
    fn reserved_guardrail_flags_are_reported_for_the_startup_warning() {
        let parse = |yaml: &str| crate::config::parse_yaml::<GuardrailsConfig>(yaml).unwrap();
        assert_eq!(
            parse("allow_src_prefix_match: true\nallow_tcp_flags_match: true\n")
                .reserved_flags_set(),
            [
                "guardrails.allow_src_prefix_match",
                "guardrails.allow_tcp_flags_match"
            ]
        );
        assert_eq!(
            parse("allow_tcp_flags_match: true\n").reserved_flags_set(),
            ["guardrails.allow_tcp_flags_match"]
        );
        // Controls: unset, false, and the enforced opt-ins never warn.
        for yaml in [
            "{}",
            "allow_src_prefix_match: false\nallow_tcp_flags_match: false\n",
            "allow_fragment_match: true\nallow_packet_length_match: true\n",
        ] {
            assert!(parse(yaml).reserved_flags_set().is_empty(), "{yaml}");
        }
        // Shipped configurations neither warn nor opt in to the enforced flags.
        for shipped in [
            include_str!("../../configs/prefixd.yaml"),
            include_str!("../../configs/prefixd-gobgp.yaml"),
            include_str!("testdata/v0.19.1-prefixd.yaml"),
        ] {
            let guardrails = crate::config::parse_yaml::<Settings>(shipped)
                .unwrap()
                .guardrails;
            assert!(guardrails.reserved_flags_set().is_empty());
            assert!(!guardrails.allow_fragment_match && !guardrails.allow_packet_length_match);
            assert_eq!(guardrails.max_ports, 8);
        }
    }

    #[test]
    fn v0_19_1_shipped_config_loads_on_gobgp_with_deprecations() {
        let shipped = include_str!("testdata/v0.19.1-prefixd.yaml");
        let removed = [
            "escalation",
            "timers.correlation_window_seconds",
            "observability.audit_log_path",
            "observability.metrics_listen",
            "shutdown.preserve_announcements",
        ];
        let (settings, deprecations) = load_yaml(shipped).unwrap();
        assert_eq!(settings.bgp.mode, BgpMode::Sidecar);
        assert_eq!(keys(&deprecations), removed);
        let target = crate::domain::SpeakerTarget::from_config(&settings.bgp).unwrap();
        assert_eq!(target.backend, "gobgp");
        assert_eq!(target.endpoint, "http://gobgp:50051/");

        // v0.19.1 defaulted an omitted bgp.mode to GoBGP; that must not change.
        let implicit = shipped.replacen("  mode: sidecar\n", "", 1);
        let (settings, deprecations) = load_yaml(&implicit).unwrap();
        assert_eq!(settings.bgp.mode, BgpMode::Gobgp);
        assert_eq!(
            keys(&deprecations),
            [&removed[..], &["bgp.backend"]].concat()
        );
        let target = crate::domain::SpeakerTarget::from_config(&settings.bgp).unwrap();
        assert_eq!(target.backend, "gobgp");
    }

    #[test]
    fn backend_resolution_never_switches_a_configured_speaker() {
        let gobgp = "  gobgp_grpc: 127.0.0.1:50051\n";
        let rustbgpd = "  rustbgpd: {endpoint: 'unix:///run/rustbgpd/grpc.sock'}\n";
        let original = "  mode: mock\n  gobgp_grpc: \"localhost:50051\"\n";
        assert!(MINIMAL_SETTINGS_YAML.contains(original));
        for (selector, expected, warned) in [
            (String::new(), Some(BgpMode::Rustbgpd), false),
            (rustbgpd.to_owned(), Some(BgpMode::Rustbgpd), false),
            (gobgp.to_owned(), Some(BgpMode::Gobgp), true),
            (format!("{gobgp}{rustbgpd}"), None, false),
            (
                format!("  mode: sidecar\n{gobgp}"),
                Some(BgpMode::Sidecar),
                false,
            ),
            (
                format!("  backend: gobgp\n{gobgp}"),
                Some(BgpMode::Gobgp),
                false,
            ),
            (
                format!("  backend: rustbgpd\n{gobgp}{rustbgpd}"),
                Some(BgpMode::Rustbgpd),
                false,
            ),
            (
                format!("  backend: gobgp\n{gobgp}{rustbgpd}"),
                Some(BgpMode::Gobgp),
                false,
            ),
        ] {
            let yaml = MINIMAL_SETTINGS_YAML.replacen(original, &selector, 1);
            match (load_yaml(&yaml), expected) {
                (Ok((settings, deprecations)), Some(expected)) => {
                    assert_eq!(settings.bgp.mode, expected, "{selector}");
                    let expected_keys: &[&str] = if warned { &["bgp.backend"] } else { &[] };
                    assert_eq!(keys(&deprecations), expected_keys, "{selector}");
                }
                (Err(error), None) => assert!(
                    error.to_string().contains("bgp.backend is required"),
                    "{error}"
                ),
                (result, _) => panic!("{selector}: unexpected {result:?}"),
            }
        }
    }

    const BLACKHOLE_YAML: &str = "blackhole:\n  enabled: true\n  next_hop_ipv4: 192.0.2.66\n  next_hop_ipv6: '2001:db8::66'\n  communities: ['64496:666', '65535:666']\n  large_communities: ['64496:1:666']\n";

    #[test]
    fn blackhole_is_off_by_default_with_the_decided_caps() {
        let (settings, deprecations) = load_yaml(MINIMAL_SETTINGS_YAML).unwrap();
        assert!(deprecations.is_empty());
        assert_eq!(
            serde_json::to_value(&settings.blackhole).unwrap(),
            serde_json::json!({
                "enabled": false,
                "next_hop_ipv4": null,
                "next_hop_ipv6": null,
                "communities": [],
                "large_communities": [],
                "max_ttl_seconds": 3600,
                "max_active_per_pop": 10,
                "max_active_global": 50,
            })
        );
        let (settings, _) = load_yaml(&format!("{MINIMAL_SETTINGS_YAML}{BLACKHOLE_YAML}")).unwrap();
        let config = settings.blackhole;
        assert!(config.enabled);
        assert_eq!(
            config.parsed_communities().unwrap(),
            [(64496 << 16) | 666, crate::bgp::BLACKHOLE_COMMUNITY]
        );
        assert_eq!(
            config.parsed_large_communities().unwrap(),
            [[64496, 1, 666]]
        );
        assert_eq!(
            config.next_hop_for("203.0.113.10".parse().unwrap()),
            Some("192.0.2.66".parse().unwrap())
        );
        assert_eq!(
            config.next_hop_for("2001:db8::10".parse().unwrap()),
            Some("2001:db8::66".parse().unwrap())
        );
    }

    #[test]
    fn blackhole_settings_refuse_unsafe_or_malformed_values() {
        let valid = format!("{MINIMAL_SETTINGS_YAML}{BLACKHOLE_YAML}");
        // Negative control: the unmodified block loads.
        load_yaml(&valid).unwrap();
        for (from, to, expected) in [
            (
                "next_hop_ipv4: 192.0.2.66",
                "next_hop_ipv4: '2001:db8::1'",
                "blackhole.next_hop_ipv4 must be an IPv4 address",
            ),
            (
                "next_hop_ipv6: '2001:db8::66'",
                "next_hop_ipv6: 192.0.2.1",
                "blackhole.next_hop_ipv6 must be an IPv6 address",
            ),
            (
                "next_hop_ipv4: 192.0.2.66",
                "next_hop_ipv4: 0.0.0.0",
                "nonzero unicast",
            ),
            (
                "next_hop_ipv4: 192.0.2.66",
                "next_hop_ipv4: 255.255.255.255",
                "nonzero unicast",
            ),
            (
                "next_hop_ipv4: 192.0.2.66",
                "next_hop_ipv4: 224.0.0.1",
                "nonzero unicast",
            ),
            (
                "next_hop_ipv6: '2001:db8::66'",
                "next_hop_ipv6: '::'",
                "nonzero unicast",
            ),
            (
                "next_hop_ipv6: '2001:db8::66'",
                "next_hop_ipv6: 'ff02::1'",
                "nonzero unicast",
            ),
            ("'64496:666'", "'65535:65281'", "must not include NO_EXPORT"),
            (
                "'64496:666'",
                "'65535:65282'",
                "must not include NO_ADVERTISE",
            ),
            // rustbgpd suppresses NO_EXPORT_SUBCONFED toward eBGP exactly like
            // NO_EXPORT (`no_export_export_suppressed` in its
            // crates/rib/src/manager/distribution/mod.rs, pinned by
            // `no_export_predicate_pins`), so it would also keep the route from
            // reaching an eBGP-facing router.
            (
                "'64496:666'",
                "'65535:65283'",
                "must not include NO_EXPORT_SUBCONFED",
            ),
            ("'64496:666'", "'65536:1'", "communities entry"),
            ("'64496:666'", "'64496:666:1'", "communities entry"),
            ("'64496:666'", "'64496'", "communities entry"),
            ("'64496:666'", "'+1:2'", "communities entry"),
            ("'64496:666'", "'no-export'", "communities entry"),
            ("'64496:666'", "''", "communities entry"),
            ("'64496:1:666'", "'64496:666'", "large_communities entry"),
            (
                "'64496:1:666'",
                "'4294967296:1:1'",
                "large_communities entry",
            ),
            ("'64496:1:666'", "'1:2:3:4'", "large_communities entry"),
            (
                "  enabled: true\n",
                "  enabled: true\n  max_ttl_seconds: 0\n",
                "blackhole.max_ttl_seconds must be nonzero",
            ),
            (
                "  enabled: true\n",
                "  enabled: true\n  leased: true\n",
                "unknown field",
            ),
        ] {
            assert!(valid.contains(from), "{from}");
            let error = load_yaml(&valid.replacen(from, to, 1))
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected), "{to}: {error}");
        }
        // Control: the refusal matches the exact well-known value, not its low half.
        let config = load_yaml(&valid.replacen("'64496:666'", "'64496:65283'", 1))
            .unwrap()
            .0
            .blackhole;
        assert!(
            config
                .parsed_communities()
                .unwrap()
                .contains(&((64496 << 16) | 65283))
        );
        // Enablement needs a next hop; with one family configured it loads.
        let neither = valid
            .replacen("  next_hop_ipv4: 192.0.2.66\n", "", 1)
            .replacen("  next_hop_ipv6: '2001:db8::66'\n", "", 1);
        let error = load_yaml(&neither).unwrap_err().to_string();
        assert!(
            error.contains("blackhole.enabled requires next_hop_ipv4 or next_hop_ipv6"),
            "{error}"
        );
        load_yaml(&valid.replacen("  next_hop_ipv6: '2001:db8::66'\n", "", 1)).unwrap();
        // Disabled still validates every key, but needs no next hop.
        load_yaml(&neither.replacen("enabled: true", "enabled: false", 1)).unwrap();
        let error = load_yaml(
            &valid
                .replacen("enabled: true", "enabled: false", 1)
                .replacen("'64496:666'", "'65535:65281'", 1),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("NO_EXPORT"), "{error}");
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
