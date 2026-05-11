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
}

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
        })
    }
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
        resolve_vector(adapter, raw.as_deref())
    };

    let bps = extract_i64(&compiled.bps, node)?;
    let pps = extract_i64(&compiled.pps, node)?;

    let confidence_raw = compiled
        .confidence
        .as_ref()
        .and_then(|p| p.query(node).at_most_one().ok().flatten())
        .and_then(|v| v.as_f64())
        .map(|x| x as f32);
    let confidence = confidence_raw.map(|c| {
        let scaled = adapter.confidence_scale.map(|s| c / s).unwrap_or(c);
        scaled.clamp(0.0, 1.0)
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

fn extract_i64(path: &Option<JsonPath>, node: &Value) -> Result<Option<i64>, MapError> {
    let Some(p) = path.as_ref() else {
        return Ok(None);
    };
    let Some(v) = p.query(node).at_most_one().ok().flatten() else {
        return Ok(None);
    };
    match v {
        Value::Number(n) => Ok(n.as_i64().or_else(|| n.as_f64().map(|f| f as i64))),
        Value::Null => Ok(None),
        _ => Ok(None),
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
}
