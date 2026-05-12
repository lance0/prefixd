//! Generic webhook adapter.
//!
//! Accepts arbitrary JSON payloads from any detector or telemetry source and
//! maps them to [`AttackEventInput`] via operator-defined JSONPath expressions.
//!
//! Adapters are configured per-name in `correlation.yaml` and reachable at
//! `POST /v1/signals/webhook/{name}`. Each adapter specifies:
//!
//! - `fields`: JSONPath -> event field mapping
//! - `auth`: HMAC, bearer, or none
//! - `root_path`: optional iterator for batched payloads
//! - `vector_map`: optional detector-vector string normalization
//! - `confidence_scale`: optional divisor for extracted confidence
//!
//! See `docs/configuration.md` for the full schema and examples.

use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json_path::JsonPath;
use sha2::Sha256;
use std::collections::HashMap;
use subtle::ConstantTimeEq;

use crate::domain::{AttackEventInput, AttackVector};

type HmacSha256 = Hmac<Sha256>;

/// Webhook adapter spec loaded from correlation.yaml.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct WebhookAdapter {
    /// URL-path segment: lowercase alphanumerics and hyphens.
    pub name: String,

    /// Human-readable description.
    #[serde(default)]
    pub description: String,

    /// Whether the adapter is active. Disabled adapters return 404.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Authentication scheme for this adapter.
    pub auth: WebhookAuth,

    /// Optional JSONPath to extract an array of alert nodes from the payload.
    /// If absent, the whole payload is treated as a single event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_path: Option<String>,

    /// JSONPath mapping for event fields. `victim_ip` is required.
    pub fields: WebhookFieldMap,

    /// Optional normalization map for the `vector` string extracted from payload.
    /// Keys are the raw detector strings, values are prefixd vector names
    /// (udp_flood, syn_flood, ack_flood, icmp_flood, unknown).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub vector_map: HashMap<String, String>,

    /// Fallback vector when `fields.vector` is missing or not in `vector_map`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_vector: Option<String>,

    /// If set, the extracted confidence value is divided by this. Useful when
    /// a detector reports confidence on a 0-100 scale (set `confidence_scale: 100`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_scale: Option<f32>,

    /// Optional prefix prepended to extracted `source_id` values (for dedup).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id_prefix: Option<String>,

    /// Optional per-field transforms applied after JSONPath extraction.
    /// The key is the event field name (`bps`, `pps`, `confidence`, `vector`).
    /// Transforms run after `vector_map` and before `confidence_scale`. See
    /// [`WebhookTransform`].
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub transforms: HashMap<String, WebhookTransform>,
}

/// Operator-defined transform applied to an extracted field value.
///
/// Three variants cover the common shapes that map cleanly to detector
/// payloads in the wild:
///
/// - `unit_conversion` — multiply a numeric value by a constant (Mbps→bps,
///   kpps→pps, percentage→ratio, etc.).
/// - `regex_extract` — pull a capture group out of a string (extract a vector
///   name from a free-form alert description).
/// - `computed` — replace the extracted value with the product of one or more
///   JSONPath extractions, scaled by a constant (derive `bps` from packets ×
///   packet_size × 8).
///
/// Each field can have at most one transform; transforms are applied
/// post-JSONPath but pre-validation. For `computed`, the field's primary
/// JSONPath is bypassed in favor of the transform's `paths`. Numeric
/// transforms on null/missing values are a no-op (the field stays `None`).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WebhookTransform {
    /// Multiply the extracted numeric value by `multiplier`. Useful for unit
    /// conversion: `Mbps → bps` is `multiplier: 1_000_000`. NaN/infinite
    /// multipliers are rejected at compile time.
    UnitConversion { multiplier: f64 },

    /// Apply `pattern` to the extracted string value and replace it with the
    /// capture group identified by `group` (defaults to 0 = whole match). If
    /// the pattern does not match or the group index is out of range, the
    /// field is set to `None` (treated as "missing"). The regex is compiled
    /// once at adapter registration.
    RegexExtract {
        pattern: String,
        #[serde(default)]
        group: usize,
    },

    /// Bypass the primary JSONPath for this field and instead compute its
    /// value as `scale * Π(extract(path_i))` where each path resolves to a
    /// numeric node. Any path that resolves to null or a non-number causes
    /// the field to be `None`. Useful for fields not directly present in the
    /// payload: e.g. derive `bps = packets * avg_size_bytes * 8` from a
    /// payload that only carries `packets` and `avg_size_bytes`.
    Computed {
        paths: Vec<String>,
        #[serde(default = "default_scale")]
        scale: f64,
    },
}

fn default_scale() -> f64 {
    1.0
}

/// JSONPath expressions for each mapped event field.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct WebhookFieldMap {
    /// Required: JSONPath that extracts the victim IP string.
    pub victim_ip: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vector: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bps: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pps: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_dst_ports: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}

/// Authentication scheme for a webhook adapter.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum WebhookAuth {
    /// HMAC-SHA256 signature verification. Secret loaded from `secret_env`.
    Hmac {
        /// Env var name holding the HMAC secret (never serialized in config views).
        secret_env: String,
        /// Request header carrying the hex-encoded HMAC digest.
        #[serde(default = "default_hmac_header")]
        header: String,
        /// Hash algorithm. Only `sha256` supported in v1.
        #[serde(default = "default_hmac_algorithm")]
        algorithm: String,
    },
    /// Authenticated session (reuses the global auth backend).
    Bearer,
    /// No authentication. Insecure; use only in trusted networks.
    None,
}

fn default_true() -> bool {
    true
}

fn default_hmac_header() -> String {
    "X-Signature-SHA256".to_string()
}

fn default_hmac_algorithm() -> String {
    "sha256".to_string()
}

/// Error produced when mapping a single payload node to an `AttackEventInput`.
#[derive(Debug, thiserror::Error)]
pub enum MapError {
    #[error("invalid JSONPath expression '{path}' for field '{field}': {source}")]
    InvalidPath {
        field: String,
        path: String,
        source: serde_json_path::ParseError,
    },
    #[error("required field '{0}' missing from payload")]
    MissingRequired(&'static str),
    #[error("field '{field}' has wrong type in payload (expected {expected})")]
    WrongType {
        field: &'static str,
        expected: &'static str,
    },
    #[error("invalid IP address '{0}' in payload")]
    InvalidIp(String),
    #[error("invalid timestamp '{0}' in payload")]
    InvalidTimestamp(String),
    #[error("invalid value for field '{field}' (expected {expected})")]
    InvalidValue {
        field: &'static str,
        expected: &'static str,
    },
    #[error("invalid regex '{pattern}' in transform for field '{field}': {source}")]
    InvalidRegex {
        field: String,
        pattern: String,
        source: regex::Error,
    },
    #[error("invalid transform multiplier '{value}' for field '{field}' (must be finite)")]
    InvalidMultiplier { field: String, value: f64 },
    #[error(
        "transform for field '{0}' is not allowed (only bps, pps, confidence, vector supported)"
    )]
    UnsupportedTransformField(String),
    #[error(
        "transform variant '{variant}' is not allowed on field '{field}' (expected a {expected} field)"
    )]
    TransformTypeMismatch {
        field: String,
        variant: &'static str,
        expected: &'static str,
    },
}

/// Validate that a webhook adapter name is safe for use as a URL path segment.
///
/// Allowed: `[a-z0-9-]{1,64}` (lowercase alphanumerics + hyphens).
pub fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Compiled JSONPath expressions for a single adapter.
///
/// Caching these lets the hot path (event ingestion) skip re-parsing on every
/// request. Build once at adapter registration or per-request if the config
/// changes often.
pub struct CompiledAdapter {
    pub root: Option<JsonPath>,
    pub victim_ip: JsonPath,
    pub vector: Option<JsonPath>,
    pub timestamp: Option<JsonPath>,
    pub bps: Option<JsonPath>,
    pub pps: Option<JsonPath>,
    pub confidence: Option<JsonPath>,
    pub source_id: Option<JsonPath>,
    pub top_dst_ports: Option<JsonPath>,
    pub action: Option<JsonPath>,
    pub transforms: HashMap<String, CompiledTransform>,
}

/// Pre-validated transform, with regex/JSONPath pre-parsed.
pub enum CompiledTransform {
    UnitConversion { multiplier: f64 },
    RegexExtract { regex: Regex, group: usize },
    Computed { paths: Vec<JsonPath>, scale: f64 },
}

const NUMERIC_FIELDS: &[&str] = &["bps", "pps", "confidence"];
const STRING_FIELDS: &[&str] = &["vector"];
const ALLOWED_TRANSFORM_FIELDS: &[&str] = &["bps", "pps", "confidence", "vector"];

impl CompiledAdapter {
    pub fn compile(adapter: &WebhookAdapter) -> Result<Self, MapError> {
        let compile_opt =
            |field: &'static str, path: &Option<String>| -> Result<Option<JsonPath>, MapError> {
                match path.as_ref() {
                    Some(p) => match JsonPath::parse(p) {
                        Ok(j) => Ok(Some(j)),
                        Err(source) => Err(MapError::InvalidPath {
                            field: field.to_string(),
                            path: p.clone(),
                            source,
                        }),
                    },
                    None => Ok(None),
                }
            };

        Ok(Self {
            root: compile_opt("root_path", &adapter.root_path)?,
            victim_ip: JsonPath::parse(&adapter.fields.victim_ip).map_err(|source| {
                MapError::InvalidPath {
                    field: "victim_ip".to_string(),
                    path: adapter.fields.victim_ip.clone(),
                    source,
                }
            })?,
            vector: compile_opt("vector", &adapter.fields.vector)?,
            timestamp: compile_opt("timestamp", &adapter.fields.timestamp)?,
            bps: compile_opt("bps", &adapter.fields.bps)?,
            pps: compile_opt("pps", &adapter.fields.pps)?,
            confidence: compile_opt("confidence", &adapter.fields.confidence)?,
            source_id: compile_opt("source_id", &adapter.fields.source_id)?,
            top_dst_ports: compile_opt("top_dst_ports", &adapter.fields.top_dst_ports)?,
            action: compile_opt("action", &adapter.fields.action)?,
            transforms: compile_transforms(&adapter.transforms)?,
        })
    }
}

fn compile_transforms(
    raw: &HashMap<String, WebhookTransform>,
) -> Result<HashMap<String, CompiledTransform>, MapError> {
    let mut out = HashMap::with_capacity(raw.len());
    for (field, transform) in raw {
        if !ALLOWED_TRANSFORM_FIELDS.contains(&field.as_str()) {
            return Err(MapError::UnsupportedTransformField(field.clone()));
        }
        let compiled = match transform {
            WebhookTransform::UnitConversion { multiplier } => {
                if !NUMERIC_FIELDS.contains(&field.as_str()) {
                    return Err(MapError::TransformTypeMismatch {
                        field: field.clone(),
                        variant: "unit_conversion",
                        expected: "numeric (bps, pps, or confidence)",
                    });
                }
                if !multiplier.is_finite() {
                    return Err(MapError::InvalidMultiplier {
                        field: field.clone(),
                        value: *multiplier,
                    });
                }
                CompiledTransform::UnitConversion {
                    multiplier: *multiplier,
                }
            }
            WebhookTransform::RegexExtract { pattern, group } => {
                if !STRING_FIELDS.contains(&field.as_str()) {
                    return Err(MapError::TransformTypeMismatch {
                        field: field.clone(),
                        variant: "regex_extract",
                        expected: "string (vector)",
                    });
                }
                let regex = Regex::new(pattern).map_err(|source| MapError::InvalidRegex {
                    field: field.clone(),
                    pattern: pattern.clone(),
                    source,
                })?;
                CompiledTransform::RegexExtract {
                    regex,
                    group: *group,
                }
            }
            WebhookTransform::Computed { paths, scale } => {
                if !NUMERIC_FIELDS.contains(&field.as_str()) {
                    return Err(MapError::TransformTypeMismatch {
                        field: field.clone(),
                        variant: "computed",
                        expected: "numeric (bps, pps, or confidence)",
                    });
                }
                if !scale.is_finite() {
                    return Err(MapError::InvalidMultiplier {
                        field: field.clone(),
                        value: *scale,
                    });
                }
                let compiled_paths: Vec<JsonPath> = paths
                    .iter()
                    .map(|p| {
                        JsonPath::parse(p).map_err(|source| MapError::InvalidPath {
                            field: field.clone(),
                            path: p.clone(),
                            source,
                        })
                    })
                    .collect::<Result<_, _>>()?;
                CompiledTransform::Computed {
                    paths: compiled_paths,
                    scale: *scale,
                }
            }
        };
        out.insert(field.clone(), compiled);
    }
    Ok(out)
}

/// Extract zero or more `AttackEventInput`s from a payload using adapter rules.
///
/// If the adapter has a `root_path`, each matching JSON node produces one event.
/// Otherwise the whole body is mapped once.
pub fn map_payload(
    adapter: &WebhookAdapter,
    compiled: &CompiledAdapter,
    body: &Value,
) -> Vec<Result<AttackEventInput, MapError>> {
    let nodes: Vec<&Value> = match &compiled.root {
        Some(root) => root.query(body).all().into_iter().collect(),
        None => vec![body],
    };

    nodes
        .into_iter()
        .map(|n| map_one(adapter, compiled, n))
        .collect()
}

fn map_one(
    adapter: &WebhookAdapter,
    compiled: &CompiledAdapter,
    node: &Value,
) -> Result<AttackEventInput, MapError> {
    let victim_ip_val = compiled
        .victim_ip
        .query(node)
        .at_most_one()
        .ok()
        .flatten()
        .ok_or(MapError::MissingRequired("victim_ip"))?;
    let victim_ip = victim_ip_val
        .as_str()
        .ok_or(MapError::WrongType {
            field: "victim_ip",
            expected: "string",
        })?
        .to_string();
    if victim_ip.parse::<std::net::IpAddr>().is_err() {
        return Err(MapError::InvalidIp(victim_ip));
    }

    let timestamp = match compiled.timestamp.as_ref() {
        Some(p) => match p.query(node).at_most_one().ok().flatten() {
            Some(v) => {
                let s = v.as_str().ok_or(MapError::WrongType {
                    field: "timestamp",
                    expected: "string",
                })?;
                s.parse::<DateTime<Utc>>()
                    .map_err(|_| MapError::InvalidTimestamp(s.to_string()))?
            }
            None => Utc::now(),
        },
        None => Utc::now(),
    };

    let vector = {
        let raw = compiled
            .vector
            .as_ref()
            .and_then(|p| p.query(node).at_most_one().ok().flatten())
            .and_then(|v| v.as_str().map(|s| s.to_string()));
        let transformed = apply_string_transform(raw, compiled.transforms.get("vector"));
        resolve_vector(adapter, transformed.as_deref())
    };

    let bps = extract_numeric(&compiled.bps, node, compiled.transforms.get("bps"))?;
    let pps = extract_numeric(&compiled.pps, node, compiled.transforms.get("pps"))?;

    let confidence_raw = compiled
        .confidence
        .as_ref()
        .and_then(|p| p.query(node).at_most_one().ok().flatten())
        .and_then(|v| v.as_f64());
    let confidence_after_transform =
        apply_numeric_transform(confidence_raw, node, compiled.transforms.get("confidence"));
    let confidence = confidence_after_transform.map(|c| {
        let scaled = adapter.confidence_scale.map(|s| c / s as f64).unwrap_or(c);
        (scaled as f32).clamp(0.0, 1.0)
    });

    let event_id = compiled
        .source_id
        .as_ref()
        .and_then(|p| p.query(node).at_most_one().ok().flatten())
        .and_then(|v| match v {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        })
        .map(|s| match &adapter.source_id_prefix {
            Some(pfx) => format!("{pfx}{s}"),
            None => s,
        });

    let top_dst_ports = compiled
        .top_dst_ports
        .as_ref()
        .and_then(|p| p.query(node).at_most_one().ok().flatten())
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_u64())
                .filter(|&x| x <= u16::MAX as u64)
                .map(|x| x as u16)
                .collect::<Vec<u16>>()
        });

    let action = match compiled
        .action
        .as_ref()
        .and_then(|p| p.query(node).at_most_one().ok().flatten())
    {
        None | Some(Value::Null) => "ban".to_string(),
        Some(Value::String(s)) if s == "ban" || s == "unban" => s.clone(),
        Some(_) => {
            return Err(MapError::InvalidValue {
                field: "action",
                expected: "\"ban\" or \"unban\"",
            });
        }
    };

    Ok(AttackEventInput {
        event_id,
        timestamp,
        source: adapter.name.clone(),
        victim_ip,
        vector,
        bps,
        pps,
        top_dst_ports,
        confidence,
        action,
        raw_details: Some(node.clone()),
    })
}

fn extract_numeric(
    path: &Option<JsonPath>,
    node: &Value,
    transform: Option<&CompiledTransform>,
) -> Result<Option<i64>, MapError> {
    // Computed transforms bypass the primary JSONPath entirely.
    if let Some(CompiledTransform::Computed { paths, scale }) = transform {
        return Ok(compute_product(paths, *scale, node).map(|f| f as i64));
    }

    let raw_f64 = path
        .as_ref()
        .and_then(|p| p.query(node).at_most_one().ok().flatten())
        .and_then(|v| match v {
            Value::Number(n) => n.as_f64(),
            _ => None,
        });

    let after = apply_numeric_transform(raw_f64, node, transform);
    Ok(after.map(|f| f as i64))
}

fn apply_numeric_transform(
    raw: Option<f64>,
    node: &Value,
    transform: Option<&CompiledTransform>,
) -> Option<f64> {
    match transform {
        None => raw,
        Some(CompiledTransform::UnitConversion { multiplier }) => raw.map(|v| v * multiplier),
        Some(CompiledTransform::Computed { paths, scale }) => compute_product(paths, *scale, node),
        // RegexExtract is rejected at compile time for numeric fields.
        Some(CompiledTransform::RegexExtract { .. }) => raw,
    }
}

fn apply_string_transform(
    raw: Option<String>,
    transform: Option<&CompiledTransform>,
) -> Option<String> {
    match (raw, transform) {
        (raw, None) => raw,
        (Some(s), Some(CompiledTransform::RegexExtract { regex, group })) => regex
            .captures(&s)
            .and_then(|caps| caps.get(*group))
            .map(|m| m.as_str().to_string()),
        (None, _) => None,
        // UnitConversion / Computed are rejected at compile time for string fields.
        (raw, Some(_)) => raw,
    }
}

fn compute_product(paths: &[JsonPath], scale: f64, node: &Value) -> Option<f64> {
    let mut product = scale;
    for p in paths {
        let v = p.query(node).at_most_one().ok().flatten()?;
        let n = match v {
            Value::Number(n) => n.as_f64()?,
            _ => return None,
        };
        product *= n;
    }
    if product.is_finite() {
        Some(product)
    } else {
        None
    }
}

fn resolve_vector(adapter: &WebhookAdapter, raw: Option<&str>) -> AttackVector {
    let normalized: Option<String> = raw.and_then(|r| {
        adapter
            .vector_map
            .get(r)
            .cloned()
            .or_else(|| Some(r.to_string()))
    });
    match normalized {
        Some(s) => s
            .parse::<AttackVector>()
            .unwrap_or_else(|_| fallback_vector(adapter)),
        None => fallback_vector(adapter),
    }
}

fn fallback_vector(adapter: &WebhookAdapter) -> AttackVector {
    adapter
        .default_vector
        .as_ref()
        .and_then(|s| s.parse::<AttackVector>().ok())
        .unwrap_or(AttackVector::Unknown)
}

/// Verify an HMAC-SHA256 signature header against a request body.
///
/// The header value is expected to be a hex-encoded digest, optionally
/// prefixed with `sha256=` (GitHub-style). Comparison is constant-time.
pub fn verify_hmac_sha256(secret: &[u8], body: &[u8], header_value: &str) -> bool {
    let expected_hex = header_value.strip_prefix("sha256=").unwrap_or(header_value);
    let Ok(expected) = hex::decode(expected_hex.trim()) else {
        return false;
    };

    let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
        return false;
    };
    mac.update(body);
    let computed = mac.finalize().into_bytes();

    computed.ct_eq(&expected).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn basic_adapter() -> WebhookAdapter {
        WebhookAdapter {
            name: "test".into(),
            description: String::new(),
            enabled: true,
            auth: WebhookAuth::None,
            root_path: None,
            fields: WebhookFieldMap {
                victim_ip: "$.target.ip".into(),
                vector: Some("$.alert_type".into()),
                timestamp: Some("$.time".into()),
                bps: Some("$.metrics.bps".into()),
                pps: Some("$.metrics.pps".into()),
                confidence: Some("$.score".into()),
                source_id: Some("$.id".into()),
                top_dst_ports: Some("$.ports".into()),
                action: Some("$.action".into()),
            },
            vector_map: HashMap::new(),
            default_vector: None,
            confidence_scale: None,
            source_id_prefix: None,
            transforms: HashMap::new(),
        }
    }

    #[test]
    fn valid_name_rules() {
        assert!(is_valid_name("radware"));
        assert!(is_valid_name("fastnetmon-v2"));
        assert!(is_valid_name("detector-99"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("Upper"));
        assert!(!is_valid_name("has space"));
        assert!(!is_valid_name("has/slash"));
        assert!(!is_valid_name(&"a".repeat(65)));
    }

    #[test]
    fn maps_all_fields_happy_path() {
        let adapter = basic_adapter();
        let compiled = CompiledAdapter::compile(&adapter).unwrap();
        let body = json!({
            "id": "alert-42",
            "target": { "ip": "203.0.113.5" },
            "alert_type": "udp_flood",
            "time": "2026-01-01T00:00:00Z",
            "metrics": { "bps": 100000, "pps": 200 },
            "score": 0.85,
            "ports": [53, 123],
            "action": "ban",
        });

        let results = map_payload(&adapter, &compiled, &body);
        assert_eq!(results.len(), 1);
        let event = results.into_iter().next().unwrap().unwrap();
        assert_eq!(event.event_id.as_deref(), Some("alert-42"));
        assert_eq!(event.victim_ip, "203.0.113.5");
        assert_eq!(event.vector, AttackVector::UdpFlood);
        assert_eq!(event.bps, Some(100000));
        assert_eq!(event.pps, Some(200));
        assert_eq!(event.confidence, Some(0.85));
        assert_eq!(event.top_dst_ports, Some(vec![53, 123]));
        assert_eq!(event.action, "ban");
        assert_eq!(event.source, "test");
    }

    #[test]
    fn missing_victim_ip_errors() {
        let adapter = basic_adapter();
        let compiled = CompiledAdapter::compile(&adapter).unwrap();
        let body = json!({ "alert_type": "udp_flood" });
        let results = map_payload(&adapter, &compiled, &body);
        assert!(matches!(
            results.into_iter().next().unwrap(),
            Err(MapError::MissingRequired("victim_ip"))
        ));
    }

    #[test]
    fn invalid_action_value_is_rejected() {
        let mut adapter = basic_adapter();
        adapter.fields.action = Some("$.action".into());
        let compiled = CompiledAdapter::compile(&adapter).unwrap();
        let body = json!({
            "target": { "ip": "203.0.113.5" },
            "alert_type": "udp_flood",
            "action": "resolved"
        });
        let results = map_payload(&adapter, &compiled, &body);
        assert!(matches!(
            results.into_iter().next().unwrap(),
            Err(MapError::InvalidValue {
                field: "action",
                ..
            })
        ));
    }

    #[test]
    fn missing_action_defaults_to_ban() {
        let mut adapter = basic_adapter();
        adapter.fields.action = Some("$.action".into());
        let compiled = CompiledAdapter::compile(&adapter).unwrap();
        let body = json!({
            "target": { "ip": "203.0.113.5" },
            "alert_type": "udp_flood"
        });
        let event = map_payload(&adapter, &compiled, &body)
            .into_iter()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(event.action, "ban");
    }

    #[test]
    fn invalid_ip_errors() {
        let adapter = basic_adapter();
        let compiled = CompiledAdapter::compile(&adapter).unwrap();
        let body = json!({ "target": { "ip": "not-an-ip" } });
        let results = map_payload(&adapter, &compiled, &body);
        assert!(matches!(
            results.into_iter().next().unwrap(),
            Err(MapError::InvalidIp(_))
        ));
    }

    #[test]
    fn root_path_produces_multiple_events() {
        let mut adapter = basic_adapter();
        adapter.root_path = Some("$.alerts[*]".into());
        let compiled = CompiledAdapter::compile(&adapter).unwrap();
        let body = json!({
            "alerts": [
                { "target": { "ip": "203.0.113.1" }, "alert_type": "udp_flood" },
                { "target": { "ip": "203.0.113.2" }, "alert_type": "syn_flood" },
                { "target": { "ip": "203.0.113.3" }, "alert_type": "icmp_flood" },
            ]
        });
        let results = map_payload(&adapter, &compiled, &body);
        assert_eq!(results.len(), 3);
        let ips: Vec<_> = results.into_iter().map(|r| r.unwrap().victim_ip).collect();
        assert_eq!(ips, vec!["203.0.113.1", "203.0.113.2", "203.0.113.3"]);
    }

    #[test]
    fn vector_map_normalizes_values() {
        let mut adapter = basic_adapter();
        adapter
            .vector_map
            .insert("UDP_FLOOD".into(), "udp_flood".into());
        adapter
            .vector_map
            .insert("TCP_SYN".into(), "syn_flood".into());
        let compiled = CompiledAdapter::compile(&adapter).unwrap();
        for (input, expected) in [
            ("UDP_FLOOD", AttackVector::UdpFlood),
            ("TCP_SYN", AttackVector::SynFlood),
        ] {
            let body = json!({ "target": { "ip": "203.0.113.9" }, "alert_type": input });
            let results = map_payload(&adapter, &compiled, &body);
            let event = results.into_iter().next().unwrap().unwrap();
            assert_eq!(event.vector, expected, "input={input}");
        }
    }

    #[test]
    fn default_vector_fallback_when_not_mapped() {
        let mut adapter = basic_adapter();
        adapter.default_vector = Some("unknown".into());
        let compiled = CompiledAdapter::compile(&adapter).unwrap();
        let body = json!({ "target": { "ip": "203.0.113.9" }, "alert_type": "GARBAGE" });
        let event = map_payload(&adapter, &compiled, &body)
            .into_iter()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(event.vector, AttackVector::Unknown);
    }

    #[test]
    fn confidence_scaling_and_clamping() {
        let mut adapter = basic_adapter();
        adapter.confidence_scale = Some(100.0);
        let compiled = CompiledAdapter::compile(&adapter).unwrap();
        let body = json!({
            "target": { "ip": "203.0.113.9" },
            "score": 75,
        });
        let event = map_payload(&adapter, &compiled, &body)
            .into_iter()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(event.confidence, Some(0.75));

        // Over-range value clamps to 1.0
        let body = json!({ "target": { "ip": "203.0.113.9" }, "score": 500 });
        let event = map_payload(&adapter, &compiled, &body)
            .into_iter()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(event.confidence, Some(1.0));
    }

    #[test]
    fn source_id_prefix_applied() {
        let mut adapter = basic_adapter();
        adapter.source_id_prefix = Some("radware-".into());
        let compiled = CompiledAdapter::compile(&adapter).unwrap();
        let body = json!({
            "id": "alert-7",
            "target": { "ip": "203.0.113.9" },
        });
        let event = map_payload(&adapter, &compiled, &body)
            .into_iter()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(event.event_id.as_deref(), Some("radware-alert-7"));
    }

    #[test]
    fn invalid_jsonpath_fails_compile() {
        let mut adapter = basic_adapter();
        adapter.fields.victim_ip = "not a path".into();
        assert!(matches!(
            CompiledAdapter::compile(&adapter),
            Err(MapError::InvalidPath { .. })
        ));
    }

    #[test]
    fn hmac_verify_accepts_correct_signature() {
        let secret = b"s3cret-key";
        let body = br#"{"alerts":[{"id":1}]}"#;
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(body);
        let sig = hex::encode(mac.finalize().into_bytes());
        assert!(verify_hmac_sha256(secret, body, &sig));
        assert!(verify_hmac_sha256(secret, body, &format!("sha256={sig}")));
    }

    #[test]
    fn hmac_verify_rejects_wrong_signature() {
        let secret = b"s3cret-key";
        let body = br#"{"x":1}"#;
        // Valid-length but wrong digest
        let wrong = "0".repeat(64);
        assert!(!verify_hmac_sha256(secret, body, &wrong));
        // Mangled body
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(body);
        let sig = hex::encode(mac.finalize().into_bytes());
        assert!(!verify_hmac_sha256(secret, br#"{"x":2}"#, &sig));
    }

    #[test]
    fn hmac_verify_rejects_malformed_hex() {
        assert!(!verify_hmac_sha256(b"key", b"body", "not-hex!!"));
        assert!(!verify_hmac_sha256(b"key", b"body", ""));
    }

    #[test]
    fn unit_conversion_scales_bps() {
        let mut adapter = basic_adapter();
        adapter.transforms.insert(
            "bps".into(),
            WebhookTransform::UnitConversion {
                multiplier: 1_000_000.0,
            },
        );
        let compiled = CompiledAdapter::compile(&adapter).unwrap();
        let body = json!({
            "target": { "ip": "203.0.113.5" },
            "metrics": { "bps": 250, "pps": 50 },
        });
        let event = map_payload(&adapter, &compiled, &body)
            .into_iter()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(event.bps, Some(250_000_000));
        assert_eq!(event.pps, Some(50)); // untransformed
    }

    #[test]
    fn unit_conversion_scales_pps_and_confidence() {
        let mut adapter = basic_adapter();
        adapter.transforms.insert(
            "pps".into(),
            WebhookTransform::UnitConversion { multiplier: 1000.0 },
        );
        adapter.transforms.insert(
            "confidence".into(),
            WebhookTransform::UnitConversion { multiplier: 0.01 },
        );
        let compiled = CompiledAdapter::compile(&adapter).unwrap();
        let body = json!({
            "target": { "ip": "203.0.113.5" },
            "metrics": { "bps": 1, "pps": 7 },
            "score": 42,
        });
        let event = map_payload(&adapter, &compiled, &body)
            .into_iter()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(event.pps, Some(7_000));
        assert_eq!(event.confidence, Some(0.42));
    }

    #[test]
    fn unit_conversion_passes_through_missing_values() {
        let mut adapter = basic_adapter();
        adapter.transforms.insert(
            "bps".into(),
            WebhookTransform::UnitConversion {
                multiplier: 1_000_000.0,
            },
        );
        let compiled = CompiledAdapter::compile(&adapter).unwrap();
        let body = json!({ "target": { "ip": "203.0.113.5" } });
        let event = map_payload(&adapter, &compiled, &body)
            .into_iter()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(event.bps, None);
    }

    #[test]
    fn regex_extract_pulls_vector_from_description() {
        let mut adapter = basic_adapter();
        adapter.fields.vector = Some("$.description".into());
        adapter.transforms.insert(
            "vector".into(),
            WebhookTransform::RegexExtract {
                pattern: r"(\w+)_flood".into(),
                group: 0,
            },
        );
        let compiled = CompiledAdapter::compile(&adapter).unwrap();
        let body = json!({
            "target": { "ip": "203.0.113.5" },
            "description": "Detected: udp_flood at 250Gbps targeting customer-42",
        });
        let event = map_payload(&adapter, &compiled, &body)
            .into_iter()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(event.vector, AttackVector::UdpFlood);
    }

    #[test]
    fn regex_extract_uses_named_group() {
        let mut adapter = basic_adapter();
        adapter.fields.vector = Some("$.description".into());
        adapter.transforms.insert(
            "vector".into(),
            WebhookTransform::RegexExtract {
                pattern: r"type=(?P<v>\w+_flood)".into(),
                group: 1,
            },
        );
        let compiled = CompiledAdapter::compile(&adapter).unwrap();
        let body = json!({
            "target": { "ip": "203.0.113.5" },
            "description": "alert id=42 type=syn_flood severity=high",
        });
        let event = map_payload(&adapter, &compiled, &body)
            .into_iter()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(event.vector, AttackVector::SynFlood);
    }

    #[test]
    fn regex_extract_no_match_falls_back_to_default() {
        let mut adapter = basic_adapter();
        adapter.fields.vector = Some("$.description".into());
        adapter.default_vector = Some("unknown".into());
        adapter.transforms.insert(
            "vector".into(),
            WebhookTransform::RegexExtract {
                pattern: r"(\w+)_flood".into(),
                group: 0,
            },
        );
        let compiled = CompiledAdapter::compile(&adapter).unwrap();
        let body = json!({
            "target": { "ip": "203.0.113.5" },
            "description": "benign traffic spike on customer-7",
        });
        let event = map_payload(&adapter, &compiled, &body)
            .into_iter()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(event.vector, AttackVector::Unknown);
    }

    #[test]
    fn computed_derives_bps_from_packets_and_size() {
        let mut adapter = basic_adapter();
        adapter.fields.bps = None;
        adapter.transforms.insert(
            "bps".into(),
            WebhookTransform::Computed {
                paths: vec!["$.packets".into(), "$.avg_size".into()],
                scale: 8.0,
            },
        );
        let compiled = CompiledAdapter::compile(&adapter).unwrap();
        let body = json!({
            "target": { "ip": "203.0.113.5" },
            "packets": 1_000_000,
            "avg_size": 512,
        });
        let event = map_payload(&adapter, &compiled, &body)
            .into_iter()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(event.bps, Some(4_096_000_000));
    }

    #[test]
    fn computed_missing_path_yields_none() {
        let mut adapter = basic_adapter();
        adapter.fields.bps = None;
        adapter.transforms.insert(
            "bps".into(),
            WebhookTransform::Computed {
                paths: vec!["$.packets".into(), "$.missing".into()],
                scale: 8.0,
            },
        );
        let compiled = CompiledAdapter::compile(&adapter).unwrap();
        let body = json!({
            "target": { "ip": "203.0.113.5" },
            "packets": 100,
        });
        let event = map_payload(&adapter, &compiled, &body)
            .into_iter()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(event.bps, None);
    }

    #[test]
    fn invalid_regex_rejected_at_compile_time() {
        let mut adapter = basic_adapter();
        adapter.transforms.insert(
            "vector".into(),
            WebhookTransform::RegexExtract {
                pattern: "[".into(),
                group: 0,
            },
        );
        assert!(matches!(
            CompiledAdapter::compile(&adapter),
            Err(MapError::InvalidRegex { .. })
        ));
    }

    #[test]
    fn non_finite_multiplier_rejected_at_compile_time() {
        let mut adapter = basic_adapter();
        adapter.transforms.insert(
            "bps".into(),
            WebhookTransform::UnitConversion {
                multiplier: f64::NAN,
            },
        );
        assert!(matches!(
            CompiledAdapter::compile(&adapter),
            Err(MapError::InvalidMultiplier { .. })
        ));
    }

    #[test]
    fn unsupported_transform_field_rejected() {
        let mut adapter = basic_adapter();
        adapter.transforms.insert(
            "victim_ip".into(),
            WebhookTransform::UnitConversion { multiplier: 1.0 },
        );
        assert!(matches!(
            CompiledAdapter::compile(&adapter),
            Err(MapError::UnsupportedTransformField(_))
        ));
    }

    #[test]
    fn transform_type_mismatch_rejected() {
        // unit_conversion on string field
        let mut adapter = basic_adapter();
        adapter.transforms.insert(
            "vector".into(),
            WebhookTransform::UnitConversion { multiplier: 1.0 },
        );
        assert!(matches!(
            CompiledAdapter::compile(&adapter),
            Err(MapError::TransformTypeMismatch { .. })
        ));

        // regex_extract on numeric field
        let mut adapter = basic_adapter();
        adapter.transforms.insert(
            "bps".into(),
            WebhookTransform::RegexExtract {
                pattern: r"\d+".into(),
                group: 0,
            },
        );
        assert!(matches!(
            CompiledAdapter::compile(&adapter),
            Err(MapError::TransformTypeMismatch { .. })
        ));
    }

    #[test]
    fn unit_conversion_after_confidence_scale_clamps() {
        // Operator sets confidence_scale=100 (percentage -> ratio) AND a
        // unit_conversion multiplier that would push the value past 1.0.
        // Clamping happens after both, so the final value is 1.0.
        let mut adapter = basic_adapter();
        adapter.confidence_scale = Some(100.0);
        adapter.transforms.insert(
            "confidence".into(),
            WebhookTransform::UnitConversion { multiplier: 10.0 },
        );
        let compiled = CompiledAdapter::compile(&adapter).unwrap();
        let body = json!({
            "target": { "ip": "203.0.113.5" },
            "score": 50,
        });
        let event = map_payload(&adapter, &compiled, &body)
            .into_iter()
            .next()
            .unwrap()
            .unwrap();
        // raw=50, transform: *10 = 500, scale: /100 = 5.0, clamp: 1.0
        assert_eq!(event.confidence, Some(1.0));
    }

    #[test]
    fn transforms_round_trip_through_yaml() {
        let mut adapter = basic_adapter();
        adapter.transforms.insert(
            "bps".into(),
            WebhookTransform::UnitConversion {
                multiplier: 1_000_000.0,
            },
        );
        adapter.transforms.insert(
            "vector".into(),
            WebhookTransform::RegexExtract {
                pattern: r"(\w+)_flood".into(),
                group: 0,
            },
        );
        adapter.transforms.insert(
            "pps".into(),
            WebhookTransform::Computed {
                paths: vec!["$.x".into(), "$.y".into()],
                scale: 2.0,
            },
        );
        let yaml = serde_yaml::to_string(&adapter).unwrap();
        assert!(yaml.contains("unit_conversion"));
        assert!(yaml.contains("regex_extract"));
        assert!(yaml.contains("computed"));
        let parsed: WebhookAdapter = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.transforms.len(), 3);
        // Sanity-check one round-tripped value.
        match parsed.transforms.get("bps").unwrap() {
            WebhookTransform::UnitConversion { multiplier } => assert_eq!(*multiplier, 1e6),
            _ => panic!("expected UnitConversion"),
        }
    }
}
