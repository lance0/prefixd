use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

/// Configuration for the multi-signal correlation engine.
///
/// When `enabled` is false (the default), the correlation engine is bypassed
/// and events follow the direct path to policy evaluation — identical to
/// pre-correlation behavior.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CorrelationConfig {
    /// Whether the correlation engine is active.
    #[serde(default)]
    pub enabled: bool,

    /// Time window (in seconds) for grouping signals by (victim_ip, vector).
    /// Events arriving within this window are added to the same signal group.
    #[serde(default = "default_window_seconds")]
    pub window_seconds: u32,

    /// Global minimum number of distinct sources required before a signal group
    /// can trigger a mitigation. Set to 1 for backward-compatible single-source
    /// behavior.
    #[serde(default = "default_min_sources")]
    pub min_sources: u32,

    /// Global minimum derived confidence threshold. A signal group must reach
    /// this threshold (in addition to `min_sources`) before triggering.
    #[serde(default = "default_confidence_threshold")]
    pub confidence_threshold: f32,

    /// Per-source configuration: weight and type for known detection sources.
    #[serde(default)]
    pub sources: HashMap<String, SourceConfig>,

    /// Default weight assigned to events from sources not listed in `sources`.
    #[serde(default = "default_weight")]
    pub default_weight: f32,

    /// Generic webhook adapters, each exposed at `POST /v1/signals/webhook/{name}`.
    /// See `docs/configuration.md` for the schema.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub webhook_adapters: Vec<super::webhook::WebhookAdapter>,
}

/// Whether a signal source is allowed to create / trigger mitigations on its
/// own (`Primary`) or can only corroborate signal groups created by primary
/// sources (`Corroborating`). See ADR 021.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum SourceMode {
    #[default]
    Primary,
    Corroborating,
}

/// Dimensions a corroborating signal can present for matching to open signal
/// groups. Every group aggregates the same dimensions from its primary events
/// (via inventory lookup) and a corroborator matches if ANY of its present
/// dimensions equals the group's corresponding dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MatchDimension {
    CustomerId,
    Pop,
    ServiceId,
    Interface,
}

impl MatchDimension {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CustomerId => "customer_id",
            Self::Pop => "pop",
            Self::ServiceId => "service_id",
            Self::Interface => "interface",
        }
    }
}

/// Configuration for a single detection/signal source.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SourceConfig {
    /// Weight applied to events from this source when computing derived
    /// confidence. Higher weight = more influence on the weighted average.
    #[serde(default = "default_weight")]
    pub weight: f32,

    /// Descriptive type of the source (e.g., "detector", "telemetry", "manual").
    #[serde(default)]
    pub r#type: String,

    /// Optional per-action confidence mapping. Keys are action types (e.g.,
    /// "ban", "partial_block", "alert") and values are confidence scores (0.0–1.0).
    /// Used by signal adapters (e.g., FastNetMon) to map action types to confidence.
    #[serde(default)]
    pub confidence_mapping: HashMap<String, f32>,

    /// Whether this source can trigger mitigations on its own (`primary`) or
    /// only corroborates existing signal groups (`corroborating`). Defaults
    /// to `primary` for backward compatibility.
    #[serde(default)]
    pub mode: SourceMode,

    /// For corroborating sources: which dimensions this source supplies when
    /// sending signals. Must be non-empty when `mode: corroborating`.
    /// Ignored for primary sources.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub match_dimensions: Vec<MatchDimension>,
}

impl Default for SourceConfig {
    fn default() -> Self {
        Self {
            weight: default_weight(),
            r#type: String::new(),
            confidence_mapping: HashMap::new(),
            mode: SourceMode::Primary,
            match_dimensions: Vec::new(),
        }
    }
}

/// Per-playbook correlation override. When present on a playbook, these values
/// override the global `min_sources` and `confidence_threshold` for events
/// matching that playbook.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PlaybookCorrelationOverride {
    /// Override for the minimum number of distinct sources.
    #[serde(default)]
    pub min_sources: Option<u32>,

    /// Override for the minimum derived confidence threshold.
    #[serde(default)]
    pub confidence_threshold: Option<f32>,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            window_seconds: default_window_seconds(),
            min_sources: default_min_sources(),
            confidence_threshold: default_confidence_threshold(),
            sources: HashMap::new(),
            default_weight: default_weight(),
            webhook_adapters: Vec::new(),
        }
    }
}

fn default_window_seconds() -> u32 {
    300
}

fn default_min_sources() -> u32 {
    1
}

fn default_confidence_threshold() -> f32 {
    0.5
}

fn default_weight() -> f32 {
    1.0
}

impl CorrelationConfig {
    /// Resolve the effective weight for a given source name.
    /// Returns the configured weight if the source is known, or `default_weight` otherwise.
    pub fn source_weight(&self, source: &str) -> f32 {
        self.sources
            .get(source)
            .map(|s| s.weight)
            .unwrap_or(self.default_weight)
    }

    /// Resolve the `SourceMode` for a given source name. Unknown sources default
    /// to `Primary` for backward-compatibility with v0.15.0 and earlier.
    pub fn source_mode(&self, source: &str) -> SourceMode {
        self.sources
            .get(source)
            .map(|s| s.mode)
            .unwrap_or(SourceMode::Primary)
    }

    /// Resolve the `match_dimensions` declared for a corroborating source.
    /// Returns an empty slice for unknown / primary sources.
    pub fn match_dimensions(&self, source: &str) -> &[MatchDimension] {
        self.sources
            .get(source)
            .map(|s| s.match_dimensions.as_slice())
            .unwrap_or(&[])
    }

    /// Resolve effective min_sources, using a per-playbook override if provided.
    pub fn effective_min_sources(
        &self,
        playbook_override: Option<&PlaybookCorrelationOverride>,
    ) -> u32 {
        playbook_override
            .and_then(|o| o.min_sources)
            .unwrap_or(self.min_sources)
    }

    /// Resolve effective confidence_threshold, using a per-playbook override if provided.
    pub fn effective_confidence_threshold(
        &self,
        playbook_override: Option<&PlaybookCorrelationOverride>,
    ) -> f32 {
        playbook_override
            .and_then(|o| o.confidence_threshold)
            .unwrap_or(self.confidence_threshold)
    }

    /// Resolve confidence for a given source and action type using the per-source
    /// `confidence_mapping`. Falls back to `default_confidence_mapping` if no
    /// source-specific mapping is configured.
    pub fn source_action_confidence(&self, source: &str, action: &str) -> f32 {
        if let Some(source_config) = self.sources.get(source) {
            if let Some(&confidence) = source_config.confidence_mapping.get(action) {
                return confidence;
            }
        }
        // Default mapping: ban=0.9, partial_block=0.7, alert=0.5
        default_confidence_mapping(action)
    }

    /// Load correlation config from a YAML file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: CorrelationConfig = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    /// Save correlation config to a YAML file with atomic write and backup.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("invalid correlation config path"))?;
        let tmp_path = parent.join(format!(
            ".{}.tmp-{}",
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("correlation.yaml"),
            uuid::Uuid::new_v4()
        ));

        // Refuse to operate on symlink paths for defense-in-depth.
        if std::fs::symlink_metadata(path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(anyhow::anyhow!(
                "refusing to write correlation config through symlink"
            ));
        }

        if path.exists() {
            let bak = path.with_extension("yaml.bak");
            if std::fs::symlink_metadata(&bak)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
            {
                return Err(anyhow::anyhow!(
                    "refusing to write correlation backup through symlink"
                ));
            }
            std::fs::copy(path, &bak)?;
        }

        let yaml = serde_yaml::to_string(self)?;
        let mut tmp_file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)?;

        tmp_file.write_all(yaml.as_bytes())?;
        tmp_file.sync_all()?;
        drop(tmp_file);

        std::fs::rename(&tmp_path, path).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp_path);
        })?;

        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }

        Ok(())
    }

    /// Validate the correlation config. Returns a list of validation errors (empty = valid).
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        if self.window_seconds == 0 {
            errors.push("window_seconds must be > 0".to_string());
        }

        if self.min_sources == 0 {
            errors.push("min_sources must be >= 1".to_string());
        }

        if self.confidence_threshold < 0.0 || self.confidence_threshold > 1.0 {
            errors.push("confidence_threshold must be between 0.0 and 1.0".to_string());
        }

        if self.default_weight < 0.0 {
            errors.push("default_weight must be >= 0.0".to_string());
        }

        for (name, source) in &self.sources {
            if source.weight < 0.0 {
                errors.push(format!("source '{}': weight must be >= 0.0", name));
            }
            for (action, &confidence) in &source.confidence_mapping {
                if !(0.0..=1.0).contains(&confidence) {
                    errors.push(format!(
                        "source '{}': confidence_mapping '{}' must be between 0.0 and 1.0",
                        name, action
                    ));
                }
            }
            match source.mode {
                SourceMode::Primary => {
                    if !source.match_dimensions.is_empty() {
                        errors.push(format!(
                            "source '{}': match_dimensions is only valid for mode=corroborating",
                            name
                        ));
                    }
                }
                SourceMode::Corroborating => {
                    if source.match_dimensions.is_empty() {
                        errors.push(format!(
                            "source '{}': match_dimensions must be non-empty when mode=corroborating",
                            name
                        ));
                    }
                }
            }
        }

        let mut seen_names = std::collections::HashSet::new();
        for adapter in &self.webhook_adapters {
            if !super::webhook::is_valid_name(&adapter.name) {
                errors.push(format!(
                    "webhook_adapter '{}': name must match [a-z0-9-]{{1,64}}",
                    adapter.name
                ));
            }
            if !seen_names.insert(adapter.name.clone()) {
                errors.push(format!(
                    "webhook_adapter '{}': duplicate name",
                    adapter.name
                ));
            }
            if let Err(e) = super::webhook::CompiledAdapter::compile(adapter) {
                errors.push(format!(
                    "webhook_adapter '{}': invalid JSONPath: {}",
                    adapter.name, e
                ));
            }

            if let Some(scale) = adapter.confidence_scale {
                if !scale.is_finite() || scale <= 0.0_f32 {
                    errors.push(format!(
                        "webhook_adapter '{}': confidence_scale must be a finite value > 0 (got {})",
                        adapter.name, scale
                    ));
                }
            }

            if let super::webhook::WebhookAuth::Hmac {
                secret_env,
                header,
                algorithm,
            } = &adapter.auth
            {
                if secret_env.trim().is_empty() {
                    errors.push(format!(
                        "webhook_adapter '{}': auth.secret_env must not be empty for HMAC",
                        adapter.name
                    ));
                }
                if header.trim().is_empty() {
                    errors.push(format!(
                        "webhook_adapter '{}': auth.header must not be empty for HMAC",
                        adapter.name
                    ));
                }
                if algorithm != "sha256" {
                    errors.push(format!(
                        "webhook_adapter '{}': auth.algorithm must be \"sha256\" (got \"{}\")",
                        adapter.name, algorithm
                    ));
                }
            }
        }

        errors
    }

    /// Return an allowlist-redacted view of the config suitable for API responses.
    /// Following ADR 014: only explicitly safe fields are included.
    pub fn redacted(&self) -> serde_json::Value {
        let sources: serde_json::Map<String, serde_json::Value> = self
            .sources
            .iter()
            .map(|(name, source)| {
                (
                    name.clone(),
                    serde_json::json!({
                        "weight": source.weight,
                        "type": source.r#type,
                        "confidence_mapping": source.confidence_mapping,
                        "mode": source.mode,
                        "match_dimensions": source.match_dimensions,
                    }),
                )
            })
            .collect();

        let webhook_adapters: Vec<serde_json::Value> = self
            .webhook_adapters
            .iter()
            .map(|a| {
                let auth_json = match &a.auth {
                    super::webhook::WebhookAuth::Hmac {
                        secret_env,
                        header,
                        algorithm,
                    } => serde_json::json!({
                        "type": "hmac",
                        "secret_env": secret_env,
                        "header": header,
                        "algorithm": algorithm,
                    }),
                    super::webhook::WebhookAuth::Bearer => serde_json::json!({ "type": "bearer" }),
                    super::webhook::WebhookAuth::None => serde_json::json!({ "type": "none" }),
                };
                serde_json::json!({
                    "name": a.name,
                    "description": a.description,
                    "enabled": a.enabled,
                    "auth": auth_json,
                    "root_path": a.root_path,
                    "fields": a.fields,
                    "vector_map": a.vector_map,
                    "default_vector": a.default_vector,
                    "confidence_scale": a.confidence_scale,
                    "source_id_prefix": a.source_id_prefix,
                })
            })
            .collect();

        serde_json::json!({
            "enabled": self.enabled,
            "window_seconds": self.window_seconds,
            "min_sources": self.min_sources,
            "confidence_threshold": self.confidence_threshold,
            "default_weight": self.default_weight,
            "sources": sources,
            "webhook_adapters": webhook_adapters,
        })
    }
}

/// Default confidence mapping for FastNetMon action types.
fn default_confidence_mapping(action: &str) -> f32 {
    match action {
        "ban" => 0.9,
        "partial_block" => 0.7,
        "alert" => 0.5,
        _ => 0.5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = CorrelationConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.window_seconds, 300);
        assert_eq!(config.min_sources, 1);
        assert_eq!(config.confidence_threshold, 0.5);
        assert!(config.sources.is_empty());
        assert_eq!(config.default_weight, 1.0);
    }

    #[test]
    fn test_deserialize_empty_yaml() {
        // Missing correlation section should result in defaults
        let yaml = "";
        let config: CorrelationConfig = serde_yaml::from_str(yaml).unwrap_or_default();
        assert!(!config.enabled);
        assert_eq!(config.window_seconds, 300);
        assert_eq!(config.min_sources, 1);
    }

    #[test]
    fn test_deserialize_minimal_enabled() {
        let yaml = r#"
enabled: true
"#;
        let config: CorrelationConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.enabled);
        assert_eq!(config.window_seconds, 300);
        assert_eq!(config.min_sources, 1);
        assert_eq!(config.confidence_threshold, 0.5);
        assert!(config.sources.is_empty());
        assert_eq!(config.default_weight, 1.0);
    }

    #[test]
    fn test_deserialize_full_config() {
        let yaml = r#"
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
  dashboard:
    weight: 1.0
    type: manual
"#;
        let config: CorrelationConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.enabled);
        assert_eq!(config.window_seconds, 600);
        assert_eq!(config.min_sources, 2);
        assert_eq!(config.confidence_threshold, 0.7);
        assert_eq!(config.default_weight, 0.5);
        assert_eq!(config.sources.len(), 3);
        assert_eq!(config.sources["fastnetmon"].weight, 2.0);
        assert_eq!(config.sources["fastnetmon"].r#type, "detector");
        assert_eq!(config.sources["alertmanager"].weight, 0.8);
        assert_eq!(config.sources["dashboard"].weight, 1.0);
    }

    #[test]
    fn test_source_weight_known() {
        let mut config = CorrelationConfig::default();
        config.sources.insert(
            "fastnetmon".to_string(),
            SourceConfig {
                weight: 2.0,
                r#type: "detector".to_string(),
                confidence_mapping: HashMap::new(),
                ..Default::default()
            },
        );
        assert_eq!(config.source_weight("fastnetmon"), 2.0);
    }

    #[test]
    fn test_source_weight_unknown_uses_default() {
        let config = CorrelationConfig::default();
        assert_eq!(config.source_weight("unknown_detector"), 1.0);
    }

    #[test]
    fn test_source_weight_unknown_uses_custom_default() {
        let config = CorrelationConfig {
            default_weight: 0.5,
            ..Default::default()
        };
        assert_eq!(config.source_weight("unknown"), 0.5);
    }

    #[test]
    fn test_effective_min_sources_no_override() {
        let config = CorrelationConfig {
            min_sources: 2,
            ..Default::default()
        };
        assert_eq!(config.effective_min_sources(None), 2);
    }

    #[test]
    fn test_effective_min_sources_with_override() {
        let config = CorrelationConfig {
            min_sources: 2,
            ..Default::default()
        };
        let override_ = PlaybookCorrelationOverride {
            min_sources: Some(3),
            confidence_threshold: None,
        };
        assert_eq!(config.effective_min_sources(Some(&override_)), 3);
    }

    #[test]
    fn test_effective_min_sources_with_none_override() {
        let config = CorrelationConfig {
            min_sources: 2,
            ..Default::default()
        };
        let override_ = PlaybookCorrelationOverride {
            min_sources: None,
            confidence_threshold: None,
        };
        assert_eq!(config.effective_min_sources(Some(&override_)), 2);
    }

    #[test]
    fn test_effective_confidence_threshold_no_override() {
        let config = CorrelationConfig {
            confidence_threshold: 0.7,
            ..Default::default()
        };
        assert_eq!(config.effective_confidence_threshold(None), 0.7);
    }

    #[test]
    fn test_effective_confidence_threshold_with_override() {
        let config = CorrelationConfig {
            confidence_threshold: 0.5,
            ..Default::default()
        };
        let override_ = PlaybookCorrelationOverride {
            min_sources: None,
            confidence_threshold: Some(0.8),
        };
        assert_eq!(config.effective_confidence_threshold(Some(&override_)), 0.8);
    }

    #[test]
    fn test_playbook_correlation_override_deserialize() {
        let yaml = r#"
min_sources: 3
confidence_threshold: 0.9
"#;
        let override_: PlaybookCorrelationOverride = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(override_.min_sources, Some(3));
        assert_eq!(override_.confidence_threshold, Some(0.9));
    }

    #[test]
    fn test_playbook_correlation_override_partial() {
        let yaml = r#"
min_sources: 2
"#;
        let override_: PlaybookCorrelationOverride = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(override_.min_sources, Some(2));
        assert_eq!(override_.confidence_threshold, None);
    }

    #[test]
    fn test_playbook_correlation_override_empty() {
        let yaml = "{}";
        let override_: PlaybookCorrelationOverride = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(override_.min_sources, None);
        assert_eq!(override_.confidence_threshold, None);
    }

    #[test]
    fn test_settings_without_correlation_section() {
        // Simulates parsing a prefixd.yaml that has no correlation key.
        // The CorrelationConfig field uses #[serde(default)] so this must not fail.
        let yaml = r#"
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
        // This will be tested via the Settings struct after we add the field
        let _config: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
    }

    #[test]
    fn test_settings_with_correlation_section() {
        // Simulates parsing a prefixd.yaml that includes a correlation section
        let yaml = r#"
enabled: true
window_seconds: 120
min_sources: 3
confidence_threshold: 0.8
sources:
  netflow:
    weight: 1.5
    type: telemetry
"#;
        let config: CorrelationConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.enabled);
        assert_eq!(config.window_seconds, 120);
        assert_eq!(config.min_sources, 3);
        assert_eq!(config.confidence_threshold, 0.8);
        assert_eq!(config.sources.len(), 1);
        assert_eq!(config.sources["netflow"].weight, 1.5);
    }

    #[test]
    fn test_source_action_confidence_default_mapping() {
        let config = CorrelationConfig::default();
        assert_eq!(config.source_action_confidence("fastnetmon", "ban"), 0.9);
        assert_eq!(
            config.source_action_confidence("fastnetmon", "partial_block"),
            0.7
        );
        assert_eq!(config.source_action_confidence("fastnetmon", "alert"), 0.5);
        assert_eq!(
            config.source_action_confidence("fastnetmon", "unknown_action"),
            0.5
        );
    }

    #[test]
    fn test_source_action_confidence_override() {
        let mut config = CorrelationConfig::default();
        let mut mapping = HashMap::new();
        mapping.insert("ban".to_string(), 0.95);
        mapping.insert("alert".to_string(), 0.3);
        config.sources.insert(
            "fastnetmon".to_string(),
            SourceConfig {
                weight: 1.0,
                r#type: "detector".to_string(),
                confidence_mapping: mapping,
                ..Default::default()
            },
        );
        // Overridden values
        assert_eq!(config.source_action_confidence("fastnetmon", "ban"), 0.95);
        assert_eq!(config.source_action_confidence("fastnetmon", "alert"), 0.3);
        // Not overridden — falls back to default
        assert_eq!(
            config.source_action_confidence("fastnetmon", "partial_block"),
            0.7
        );
    }

    #[test]
    fn test_source_action_confidence_unknown_source() {
        let config = CorrelationConfig::default();
        // Unknown source gets default mapping
        assert_eq!(
            config.source_action_confidence("unknown_source", "ban"),
            0.9
        );
    }

    #[test]
    fn test_confidence_mapping_deserialization() {
        let yaml = r#"
enabled: true
sources:
  fastnetmon:
    weight: 1.0
    type: detector
    confidence_mapping:
      ban: 0.95
      partial_block: 0.8
      alert: 0.3
"#;
        let config: CorrelationConfig = serde_yaml::from_str(yaml).unwrap();
        let fnm = &config.sources["fastnetmon"];
        assert_eq!(fnm.confidence_mapping["ban"], 0.95);
        assert_eq!(fnm.confidence_mapping["partial_block"], 0.8);
        assert_eq!(fnm.confidence_mapping["alert"], 0.3);
    }

    #[test]
    fn test_validate_valid_config() {
        let config = CorrelationConfig::default();
        let errors = config.validate();
        assert!(errors.is_empty(), "default config should be valid");
    }

    #[test]
    fn test_validate_invalid_config() {
        let config = CorrelationConfig {
            window_seconds: 0,
            min_sources: 0,
            confidence_threshold: 2.0,
            default_weight: -1.0,
            ..Default::default()
        };
        let errors = config.validate();
        assert!(
            errors.len() >= 4,
            "should have at least 4 errors: {:?}",
            errors
        );
    }

    #[test]
    fn test_validate_invalid_source_weight() {
        let mut config = CorrelationConfig::default();
        config.sources.insert(
            "bad_source".to_string(),
            SourceConfig {
                weight: -0.5,
                r#type: "detector".to_string(),
                confidence_mapping: HashMap::new(),
                ..Default::default()
            },
        );
        let errors = config.validate();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("bad_source"));
    }

    #[test]
    fn test_validate_invalid_confidence_mapping() {
        let mut config = CorrelationConfig::default();
        let mut mapping = HashMap::new();
        mapping.insert("ban".to_string(), 1.5);
        config.sources.insert(
            "fnm".to_string(),
            SourceConfig {
                weight: 1.0,
                r#type: "detector".to_string(),
                confidence_mapping: mapping,
                ..Default::default()
            },
        );
        let errors = config.validate();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("confidence_mapping"));
    }

    #[test]
    fn test_redacted_includes_safe_fields() {
        let mut config = CorrelationConfig {
            enabled: true,
            ..Default::default()
        };
        config.sources.insert(
            "fastnetmon".to_string(),
            SourceConfig {
                weight: 2.0,
                r#type: "detector".to_string(),
                confidence_mapping: HashMap::new(),
                ..Default::default()
            },
        );
        let redacted = config.redacted();
        assert_eq!(redacted["enabled"], true);
        assert_eq!(redacted["window_seconds"], 300);
        assert_eq!(redacted["min_sources"], 1);
        assert_eq!(redacted["confidence_threshold"], 0.5);
        assert_eq!(redacted["default_weight"], 1.0);
        assert_eq!(redacted["sources"]["fastnetmon"]["weight"], 2.0);
        assert_eq!(redacted["sources"]["fastnetmon"]["type"], "detector");
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("correlation.yaml");

        let mut config = CorrelationConfig {
            enabled: true,
            min_sources: 3,
            ..Default::default()
        };
        config.sources.insert(
            "test".to_string(),
            SourceConfig {
                weight: 1.5,
                r#type: "detector".to_string(),
                confidence_mapping: HashMap::new(),
                ..Default::default()
            },
        );

        config.save(&path).unwrap();
        assert!(path.exists());

        let loaded = CorrelationConfig::load(&path).unwrap();
        assert!(loaded.enabled);
        assert_eq!(loaded.min_sources, 3);
        assert_eq!(loaded.sources["test"].weight, 1.5);
    }

    fn webhook_adapter_for_tests() -> super::super::webhook::WebhookAdapter {
        super::super::webhook::WebhookAdapter {
            name: "radware".into(),
            description: String::new(),
            enabled: true,
            auth: super::super::webhook::WebhookAuth::Hmac {
                secret_env: "RADWARE_SECRET".into(),
                header: "X-Signature-SHA256".into(),
                algorithm: "sha256".into(),
            },
            root_path: None,
            fields: super::super::webhook::WebhookFieldMap {
                victim_ip: "$.target.ip".into(),
                vector: None,
                timestamp: None,
                bps: None,
                pps: None,
                confidence: None,
                source_id: None,
                top_dst_ports: None,
                action: None,
            },
            vector_map: HashMap::new(),
            default_vector: None,
            confidence_scale: None,
            source_id_prefix: None,
        }
    }

    #[test]
    fn validate_rejects_nonpositive_confidence_scale() {
        let mut config = CorrelationConfig::default();
        let mut adapter = webhook_adapter_for_tests();
        adapter.confidence_scale = Some(0.0);
        config.webhook_adapters.push(adapter);
        let errors = config.validate();
        assert!(
            errors.iter().any(|e| e.contains("confidence_scale")),
            "expected confidence_scale error, got {errors:?}"
        );
    }

    #[test]
    fn validate_rejects_non_finite_confidence_scale() {
        let mut config = CorrelationConfig::default();
        let mut adapter = webhook_adapter_for_tests();
        adapter.confidence_scale = Some(f32::INFINITY);
        config.webhook_adapters.push(adapter);
        let errors = config.validate();
        assert!(
            errors.iter().any(|e| e.contains("confidence_scale")),
            "expected confidence_scale error, got {errors:?}"
        );
    }

    #[test]
    fn validate_rejects_empty_hmac_secret_env() {
        let mut config = CorrelationConfig::default();
        let mut adapter = webhook_adapter_for_tests();
        adapter.auth = super::super::webhook::WebhookAuth::Hmac {
            secret_env: "   ".into(),
            header: "X-Signature-SHA256".into(),
            algorithm: "sha256".into(),
        };
        config.webhook_adapters.push(adapter);
        let errors = config.validate();
        assert!(
            errors.iter().any(|e| e.contains("secret_env")),
            "expected secret_env error, got {errors:?}"
        );
    }

    #[test]
    fn validate_rejects_empty_hmac_header() {
        let mut config = CorrelationConfig::default();
        let mut adapter = webhook_adapter_for_tests();
        adapter.auth = super::super::webhook::WebhookAuth::Hmac {
            secret_env: "SECRET".into(),
            header: String::new(),
            algorithm: "sha256".into(),
        };
        config.webhook_adapters.push(adapter);
        let errors = config.validate();
        assert!(
            errors.iter().any(|e| e.contains("auth.header")),
            "expected auth.header error, got {errors:?}"
        );
    }

    #[test]
    fn validate_rejects_unknown_hmac_algorithm() {
        let mut config = CorrelationConfig::default();
        let mut adapter = webhook_adapter_for_tests();
        adapter.auth = super::super::webhook::WebhookAuth::Hmac {
            secret_env: "SECRET".into(),
            header: "X-Signature-SHA256".into(),
            algorithm: "sha512".into(),
        };
        config.webhook_adapters.push(adapter);
        let errors = config.validate();
        assert!(
            errors.iter().any(|e| e.contains("auth.algorithm")),
            "expected auth.algorithm error, got {errors:?}"
        );
    }

    #[test]
    fn validate_accepts_valid_webhook_adapter() {
        let mut config = CorrelationConfig::default();
        let mut adapter = webhook_adapter_for_tests();
        adapter.confidence_scale = Some(100.0);
        config.webhook_adapters.push(adapter);
        let errors = config.validate();
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    // ── Corroborating source mode + match_dimensions ──────────────────

    #[test]
    fn default_source_mode_is_primary() {
        let src: SourceConfig = serde_yaml::from_str("weight: 1.0\ntype: detector").unwrap();
        assert_eq!(src.mode, SourceMode::Primary);
        assert!(src.match_dimensions.is_empty());
    }

    #[test]
    fn source_mode_corroborating_deserializes() {
        let yaml = r#"
weight: 0.5
type: telemetry
mode: corroborating
match_dimensions: [customer_id, pop]
"#;
        let src: SourceConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(src.mode, SourceMode::Corroborating);
        assert_eq!(
            src.match_dimensions,
            vec![MatchDimension::CustomerId, MatchDimension::Pop]
        );
    }

    #[test]
    fn validate_rejects_corroborating_without_match_dimensions() {
        let mut config = CorrelationConfig::default();
        config.sources.insert(
            "router-cpu".into(),
            SourceConfig {
                weight: 0.5,
                r#type: "telemetry".into(),
                confidence_mapping: HashMap::new(),
                mode: SourceMode::Corroborating,
                match_dimensions: vec![],
            },
        );
        let errors = config.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("match_dimensions must be non-empty")),
            "expected match_dimensions error, got {errors:?}"
        );
    }

    #[test]
    fn validate_rejects_match_dimensions_on_primary() {
        let mut config = CorrelationConfig::default();
        config.sources.insert(
            "fastnetmon".into(),
            SourceConfig {
                weight: 1.0,
                r#type: "detector".into(),
                confidence_mapping: HashMap::new(),
                mode: SourceMode::Primary,
                match_dimensions: vec![MatchDimension::Pop],
            },
        );
        let errors = config.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("only valid for mode=corroborating")),
            "expected primary-mode error, got {errors:?}"
        );
    }

    #[test]
    fn validate_accepts_valid_corroborating_source() {
        let mut config = CorrelationConfig::default();
        config.sources.insert(
            "router-cpu".into(),
            SourceConfig {
                weight: 0.5,
                r#type: "telemetry".into(),
                confidence_mapping: HashMap::new(),
                mode: SourceMode::Corroborating,
                match_dimensions: vec![MatchDimension::Pop, MatchDimension::CustomerId],
            },
        );
        let errors = config.validate();
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn source_mode_unknown_source_defaults_primary() {
        let config = CorrelationConfig::default();
        assert_eq!(config.source_mode("never-heard-of-it"), SourceMode::Primary);
        assert!(config.match_dimensions("never-heard-of-it").is_empty());
    }

    #[test]
    fn redacted_includes_mode_and_match_dimensions() {
        let mut config = CorrelationConfig::default();
        config.sources.insert(
            "router-cpu".into(),
            SourceConfig {
                weight: 0.5,
                r#type: "telemetry".into(),
                confidence_mapping: HashMap::new(),
                mode: SourceMode::Corroborating,
                match_dimensions: vec![MatchDimension::Pop],
            },
        );
        let redacted = config.redacted();
        assert_eq!(redacted["sources"]["router-cpu"]["mode"], "corroborating");
        let dims = &redacted["sources"]["router-cpu"]["match_dimensions"];
        assert_eq!(dims[0], "pop");
    }

    #[test]
    fn invalid_match_dimension_value_fails_deserialize() {
        let yaml = r#"
weight: 0.5
mode: corroborating
match_dimensions: [customer_id, bogus_dimension]
"#;
        let res: Result<SourceConfig, _> = serde_yaml::from_str(yaml);
        assert!(res.is_err(), "expected deserialize error");
    }
}
