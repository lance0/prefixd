mod discord;
mod generic;
mod opsgenie;
mod pagerduty;
mod slack;
mod teams;
mod telegram;

use crate::domain::Mitigation;
use anyhow::Result;
use once_cell::sync::Lazy;
use prometheus::CounterVec;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

pub static ALERTS_SENT: Lazy<CounterVec> = Lazy::new(|| {
    prometheus::register_counter_vec!(
        "prefixd_alerts_sent_total",
        "Total webhook alerts sent",
        &["destination", "status"]
    )
    .unwrap()
});

const MAX_IN_FLIGHT_ALERT_TASKS: usize = 64;

/// Alert event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AlertEventType {
    #[serde(rename = "mitigation.created")]
    MitigationCreated,
    #[serde(rename = "mitigation.escalated")]
    MitigationEscalated,
    #[serde(rename = "mitigation.withdrawn")]
    MitigationWithdrawn,
    #[serde(rename = "mitigation.expired")]
    MitigationExpired,
    #[serde(rename = "config.reloaded")]
    ConfigReloaded,
    #[serde(rename = "guardrail.rejected")]
    GuardrailRejected,
}

impl AlertEventType {
    pub const ALL: &[AlertEventType] = &[
        Self::MitigationCreated,
        Self::MitigationEscalated,
        Self::MitigationWithdrawn,
        Self::MitigationExpired,
        Self::ConfigReloaded,
        Self::GuardrailRejected,
    ];

    pub const ALL_STRINGS: &[&str] = &[
        "mitigation.created",
        "mitigation.escalated",
        "mitigation.withdrawn",
        "mitigation.expired",
        "config.reloaded",
        "guardrail.rejected",
    ];
}

impl std::fmt::Display for AlertEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MitigationCreated => write!(f, "mitigation.created"),
            Self::MitigationEscalated => write!(f, "mitigation.escalated"),
            Self::MitigationWithdrawn => write!(f, "mitigation.withdrawn"),
            Self::MitigationExpired => write!(f, "mitigation.expired"),
            Self::ConfigReloaded => write!(f, "config.reloaded"),
            Self::GuardrailRejected => write!(f, "guardrail.rejected"),
        }
    }
}

/// Alert severity
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

impl AlertSeverity {
    pub fn color_hex(&self) -> u32 {
        match self {
            Self::Info => 0x36a64f,
            Self::Warning => 0xff9900,
            Self::Critical => 0xff0000,
        }
    }

    pub fn color_str(&self) -> &'static str {
        match self {
            Self::Info => "#36a64f",
            Self::Warning => "#ff9900",
            Self::Critical => "#ff0000",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

/// Alert payload sent to all destinations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub event_type: AlertEventType,
    pub severity: AlertSeverity,
    pub title: String,
    pub message: String,
    pub source: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitigation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub victim_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vector: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pop: Option<String>,
}

impl Alert {
    pub fn mitigation_created(m: &Mitigation) -> Self {
        Self {
            event_type: AlertEventType::MitigationCreated,
            severity: AlertSeverity::Warning,
            title: "Mitigation Created".into(),
            message: format!(
                "{} mitigation for {} ({}) in {}",
                m.action_type, m.victim_ip, m.vector, m.pop
            ),
            source: "prefixd".into(),
            timestamp: chrono::Utc::now(),
            mitigation_id: Some(m.mitigation_id.to_string()),
            victim_ip: Some(m.victim_ip.clone()),
            customer_id: m.customer_id.clone(),
            vector: Some(m.vector.to_string()),
            action_type: Some(m.action_type.to_string()),
            pop: Some(m.pop.clone()),
        }
    }

    pub fn mitigation_escalated(m: &Mitigation) -> Self {
        Self {
            event_type: AlertEventType::MitigationEscalated,
            severity: AlertSeverity::Critical,
            title: "Mitigation Escalated".into(),
            message: format!(
                "Escalated to {} for {} — attack persisting",
                m.action_type, m.victim_ip
            ),
            source: "prefixd".into(),
            timestamp: chrono::Utc::now(),
            mitigation_id: Some(m.mitigation_id.to_string()),
            victim_ip: Some(m.victim_ip.clone()),
            customer_id: m.customer_id.clone(),
            vector: Some(m.vector.to_string()),
            action_type: Some(m.action_type.to_string()),
            pop: Some(m.pop.clone()),
        }
    }

    pub fn mitigation_withdrawn(m: &Mitigation) -> Self {
        Self {
            event_type: AlertEventType::MitigationWithdrawn,
            severity: AlertSeverity::Info,
            title: "Mitigation Withdrawn".into(),
            message: format!("Withdrawn {} for {}", m.action_type, m.victim_ip),
            source: "prefixd".into(),
            timestamp: chrono::Utc::now(),
            mitigation_id: Some(m.mitigation_id.to_string()),
            victim_ip: Some(m.victim_ip.clone()),
            customer_id: m.customer_id.clone(),
            vector: Some(m.vector.to_string()),
            action_type: Some(m.action_type.to_string()),
            pop: Some(m.pop.clone()),
        }
    }

    pub fn mitigation_expired(m: &Mitigation) -> Self {
        Self {
            event_type: AlertEventType::MitigationExpired,
            severity: AlertSeverity::Info,
            title: "Mitigation Expired".into(),
            message: format!("TTL expired for {} ({})", m.victim_ip, m.vector),
            source: "prefixd".into(),
            timestamp: chrono::Utc::now(),
            mitigation_id: Some(m.mitigation_id.to_string()),
            victim_ip: Some(m.victim_ip.clone()),
            customer_id: m.customer_id.clone(),
            vector: Some(m.vector.to_string()),
            action_type: Some(m.action_type.to_string()),
            pop: Some(m.pop.clone()),
        }
    }

    pub fn config_reloaded(items: &[String]) -> Self {
        Self {
            event_type: AlertEventType::ConfigReloaded,
            severity: AlertSeverity::Info,
            title: "Config Reloaded".into(),
            message: format!("Reloaded: {}", items.join(", ")),
            source: "prefixd".into(),
            timestamp: chrono::Utc::now(),
            mitigation_id: None,
            victim_ip: None,
            customer_id: None,
            vector: None,
            action_type: None,
            pop: None,
        }
    }

    pub fn test_alert() -> Self {
        Self {
            event_type: AlertEventType::MitigationCreated,
            severity: AlertSeverity::Info,
            title: "Test Alert".into(),
            message: "This is a test alert from prefixd".into(),
            source: "prefixd".into(),
            timestamp: chrono::Utc::now(),
            mitigation_id: None,
            victim_ip: Some("203.0.113.1".into()),
            customer_id: Some("test_customer".into()),
            vector: Some("udp_flood".into()),
            action_type: Some("discard".into()),
            pop: Some("test".into()),
        }
    }
}

/// Configuration for a single alert destination
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DestinationConfig {
    Slack {
        webhook_url: String,
        #[serde(default)]
        channel: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        events: Vec<AlertEventType>,
    },
    Discord {
        webhook_url: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        events: Vec<AlertEventType>,
    },
    Teams {
        webhook_url: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        events: Vec<AlertEventType>,
    },
    Telegram {
        bot_token: String,
        chat_id: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        events: Vec<AlertEventType>,
    },
    Pagerduty {
        routing_key: String,
        #[serde(default = "default_pagerduty_url")]
        events_url: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        events: Vec<AlertEventType>,
    },
    Opsgenie {
        api_key: String,
        #[serde(default = "default_opsgenie_region")]
        region: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        events: Vec<AlertEventType>,
    },
    Generic {
        url: String,
        #[serde(default)]
        secret: Option<String>,
        #[serde(default)]
        headers: HashMap<String, String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        events: Vec<AlertEventType>,
    },
}

fn default_pagerduty_url() -> String {
    "https://events.pagerduty.com/v2/enqueue".into()
}

fn default_opsgenie_region() -> String {
    "us".into()
}

impl DestinationConfig {
    pub fn destination_type(&self) -> &'static str {
        match self {
            Self::Slack { .. } => "slack",
            Self::Discord { .. } => "discord",
            Self::Teams { .. } => "teams",
            Self::Telegram { .. } => "telegram",
            Self::Pagerduty { .. } => "pagerduty",
            Self::Opsgenie { .. } => "opsgenie",
            Self::Generic { .. } => "generic",
        }
    }

    pub fn events(&self) -> &[AlertEventType] {
        match self {
            Self::Slack { events, .. }
            | Self::Discord { events, .. }
            | Self::Teams { events, .. }
            | Self::Telegram { events, .. }
            | Self::Pagerduty { events, .. }
            | Self::Opsgenie { events, .. }
            | Self::Generic { events, .. } => events,
        }
    }

    /// Return a redacted copy for API exposure
    pub fn redacted(&self) -> serde_json::Value {
        let events = self.events();
        let events_value: serde_json::Value = if events.is_empty() {
            serde_json::Value::Array(vec![])
        } else {
            serde_json::to_value(events).unwrap_or_default()
        };
        let mut obj = match self {
            Self::Slack { channel, .. } => serde_json::json!({
                "type": "slack",
                "webhook_url": "***",
                "channel": channel,
            }),
            Self::Discord { .. } => serde_json::json!({
                "type": "discord",
                "webhook_url": "***",
            }),
            Self::Teams { .. } => serde_json::json!({
                "type": "teams",
                "webhook_url": "***",
            }),
            Self::Telegram { chat_id, .. } => serde_json::json!({
                "type": "telegram",
                "bot_token": "***",
                "chat_id": chat_id,
            }),
            Self::Pagerduty { events_url, .. } => serde_json::json!({
                "type": "pagerduty",
                "routing_key": "***",
                "events_url": events_url,
            }),
            Self::Opsgenie { region, .. } => serde_json::json!({
                "type": "opsgenie",
                "api_key": "***",
                "region": region,
            }),
            Self::Generic {
                url: _, headers, ..
            } => {
                let redacted_headers: HashMap<_, _> = headers
                    .keys()
                    .cloned()
                    .map(|k| (k, "***".to_string()))
                    .collect();
                serde_json::json!({
                    "type": "generic",
                    "url": "***",
                    "secret": "***",
                    "headers": redacted_headers,
                })
            }
        };
        if !events.is_empty() {
            obj["events"] = events_value;
        }
        obj
    }
}

const REDACTED: &str = "***";

/// Top-level alerting config
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AlertingConfig {
    #[serde(default)]
    pub destinations: Vec<DestinationConfig>,
    #[serde(default)]
    pub events: Vec<AlertEventType>,
}

impl AlertingConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: AlertingConfig = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("invalid alerting config path"))?;
        let tmp_path = parent.join(format!(
            ".{}.tmp-{}",
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("alerting.yaml"),
            uuid::Uuid::new_v4()
        ));

        if std::fs::symlink_metadata(path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(anyhow::anyhow!(
                "refusing to write alerting config through symlink"
            ));
        }

        if path.exists() {
            let bak = path.with_extension("yaml.bak");
            if std::fs::symlink_metadata(&bak)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
            {
                return Err(anyhow::anyhow!(
                    "refusing to write alerting backup through symlink"
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

    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        for (i, dest) in self.destinations.iter().enumerate() {
            let ctx = format!("destination[{}] ({})", i, dest.destination_type());
            match dest {
                DestinationConfig::Slack { webhook_url, .. } => {
                    if webhook_url.is_empty() || webhook_url == REDACTED {
                        errors.push(format!("{}: webhook_url is required", ctx));
                    } else if webhook_url.len() > 1024 {
                        errors.push(format!("{}: webhook_url exceeds 1024 chars", ctx));
                    } else {
                        validate_destination_url(webhook_url, "webhook_url", &ctx, &mut errors);
                    }
                }
                DestinationConfig::Discord { webhook_url, .. } => {
                    if webhook_url.is_empty() || webhook_url == REDACTED {
                        errors.push(format!("{}: webhook_url is required", ctx));
                    } else if webhook_url.len() > 1024 {
                        errors.push(format!("{}: webhook_url exceeds 1024 chars", ctx));
                    } else {
                        validate_destination_url(webhook_url, "webhook_url", &ctx, &mut errors);
                    }
                }
                DestinationConfig::Teams { webhook_url, .. } => {
                    if webhook_url.is_empty() || webhook_url == REDACTED {
                        errors.push(format!("{}: webhook_url is required", ctx));
                    } else if webhook_url.len() > 1024 {
                        errors.push(format!("{}: webhook_url exceeds 1024 chars", ctx));
                    } else {
                        validate_destination_url(webhook_url, "webhook_url", &ctx, &mut errors);
                    }
                }
                DestinationConfig::Telegram {
                    bot_token, chat_id, ..
                } => {
                    if bot_token.is_empty() || bot_token == REDACTED {
                        errors.push(format!("{}: bot_token is required", ctx));
                    }
                    if chat_id.is_empty() {
                        errors.push(format!("{}: chat_id is required", ctx));
                    } else if chat_id.len() > 64 {
                        errors.push(format!("{}: chat_id exceeds 64 chars", ctx));
                    }
                }
                DestinationConfig::Pagerduty {
                    routing_key,
                    events_url,
                    ..
                } => {
                    if routing_key.is_empty() || routing_key == REDACTED {
                        errors.push(format!("{}: routing_key is required", ctx));
                    }
                    if events_url.is_empty() {
                        errors.push(format!("{}: events_url is required", ctx));
                    } else if events_url.len() > 1024 {
                        errors.push(format!("{}: events_url exceeds 1024 chars", ctx));
                    } else {
                        validate_destination_url(events_url, "events_url", &ctx, &mut errors);
                    }
                }
                DestinationConfig::Opsgenie {
                    api_key, region, ..
                } => {
                    if api_key.is_empty() || api_key == REDACTED {
                        errors.push(format!("{}: api_key is required", ctx));
                    }
                    if region != "us" && region != "eu" {
                        errors.push(format!("{}: region must be 'us' or 'eu'", ctx));
                    }
                }
                DestinationConfig::Generic { url, .. } => {
                    if url.is_empty() || url == REDACTED {
                        errors.push(format!("{}: url is required", ctx));
                    } else if url.len() > 1024 {
                        errors.push(format!("{}: url exceeds 1024 chars", ctx));
                    } else {
                        validate_destination_url(url, "url", &ctx, &mut errors);
                    }
                }
            }
        }

        errors
    }

    /// Merge redacted secret sentinel values with real secrets from the current config.
    /// Returns errors if a "***" value has no matching existing destination to inherit from.
    pub fn merge_secrets(&mut self, current: &AlertingConfig) -> Vec<String> {
        let mut errors = Vec::new();

        for (i, dest) in self.destinations.iter_mut().enumerate() {
            let ctx = format!("destination[{}] ({})", i, dest.destination_type());
            match dest {
                DestinationConfig::Slack {
                    webhook_url,
                    channel,
                    ..
                } => {
                    if webhook_url.as_str() == REDACTED {
                        let channel_match = channel.clone();
                        let exact_matches: Vec<String> = current
                            .destinations
                            .iter()
                            .filter_map(|d| match d {
                                DestinationConfig::Slack {
                                    webhook_url: u,
                                    channel: existing_channel,
                                    ..
                                } => {
                                    if channel_match.is_some() && channel_match == *existing_channel
                                    {
                                        return Some(u.clone());
                                    }
                                    None
                                }
                                _ => None,
                            })
                            .collect();

                        let matches = if exact_matches.is_empty() {
                            current
                                .destinations
                                .iter()
                                .filter_map(|d| match d {
                                    DestinationConfig::Slack { webhook_url: u, .. } => {
                                        Some(u.clone())
                                    }
                                    _ => None,
                                })
                                .collect::<Vec<_>>()
                        } else {
                            exact_matches
                        };

                        match matches.as_slice() {
                            [u] => *webhook_url = u.clone(),
                            [] => errors.push(format!(
                                "{}: cannot resolve redacted webhook_url — no matching existing Slack destination",
                                ctx
                            )),
                            _ => errors.push(format!(
                                "{}: ambiguous redacted webhook_url — multiple matching Slack destinations",
                                ctx
                            )),
                        }
                    }
                }
                DestinationConfig::Discord { webhook_url, .. } => {
                    if webhook_url.as_str() == REDACTED {
                        let matches: Vec<String> = current
                            .destinations
                            .iter()
                            .filter_map(|d| match d {
                                DestinationConfig::Discord { webhook_url: u, .. } => {
                                    Some(u.clone())
                                }
                                _ => None,
                            })
                            .collect();
                        match matches.as_slice() {
                            [u] => *webhook_url = u.clone(),
                            [] => errors.push(format!(
                                "{}: cannot resolve redacted webhook_url — no existing Discord destination",
                                ctx
                            )),
                            _ => errors.push(format!(
                                "{}: ambiguous redacted webhook_url — multiple Discord destinations",
                                ctx
                            )),
                        }
                    }
                }
                DestinationConfig::Teams { webhook_url, .. } => {
                    if webhook_url.as_str() == REDACTED {
                        let matches: Vec<String> = current
                            .destinations
                            .iter()
                            .filter_map(|d| match d {
                                DestinationConfig::Teams { webhook_url: u, .. } => Some(u.clone()),
                                _ => None,
                            })
                            .collect();
                        match matches.as_slice() {
                            [u] => *webhook_url = u.clone(),
                            [] => errors.push(format!(
                                "{}: cannot resolve redacted webhook_url — no existing Teams destination",
                                ctx
                            )),
                            _ => errors.push(format!(
                                "{}: ambiguous redacted webhook_url — multiple Teams destinations",
                                ctx
                            )),
                        }
                    }
                }
                DestinationConfig::Telegram {
                    bot_token, chat_id, ..
                } => {
                    if bot_token.as_str() == REDACTED {
                        let cid = chat_id.clone();
                        let matches: Vec<String> = current
                            .destinations
                            .iter()
                            .filter_map(|d| match d {
                                DestinationConfig::Telegram {
                                    bot_token: t,
                                    chat_id: c,
                                    ..
                                } if c == &cid => Some(t.clone()),
                                _ => None,
                            })
                            .collect();
                        match matches.as_slice() {
                            [t] => *bot_token = t.clone(),
                            [] => errors.push(format!(
                                "{}: cannot resolve redacted bot_token — no existing Telegram destination with chat_id={}",
                                ctx, chat_id
                            )),
                            _ => errors.push(format!(
                                "{}: ambiguous redacted bot_token — multiple Telegram destinations with chat_id={}",
                                ctx, chat_id
                            )),
                        }
                    }
                }
                DestinationConfig::Pagerduty {
                    routing_key,
                    events_url,
                    ..
                } => {
                    if routing_key.as_str() == REDACTED {
                        let eu = events_url.clone();
                        let matches: Vec<String> = current
                            .destinations
                            .iter()
                            .filter_map(|d| match d {
                                DestinationConfig::Pagerduty {
                                    routing_key: k,
                                    events_url: e,
                                    ..
                                } if e == &eu => Some(k.clone()),
                                _ => None,
                            })
                            .collect();
                        match matches.as_slice() {
                            [k] => *routing_key = k.clone(),
                            [] => errors.push(format!(
                                "{}: cannot resolve redacted routing_key — no existing PagerDuty destination with events_url={}",
                                ctx, events_url
                            )),
                            _ => errors.push(format!(
                                "{}: ambiguous redacted routing_key — multiple PagerDuty destinations with events_url={}",
                                ctx, events_url
                            )),
                        }
                    }
                }
                DestinationConfig::Opsgenie {
                    api_key, region, ..
                } => {
                    if api_key.as_str() == REDACTED {
                        let r = region.clone();
                        let matches: Vec<String> = current
                            .destinations
                            .iter()
                            .filter_map(|d| match d {
                                DestinationConfig::Opsgenie {
                                    api_key: k,
                                    region: reg,
                                    ..
                                } if reg == &r => Some(k.clone()),
                                _ => None,
                            })
                            .collect();
                        match matches.as_slice() {
                            [k] => *api_key = k.clone(),
                            [] => errors.push(format!(
                                "{}: cannot resolve redacted api_key — no existing OpsGenie destination for region={}",
                                ctx, region
                            )),
                            _ => errors.push(format!(
                                "{}: ambiguous redacted api_key — multiple OpsGenie destinations for region={}",
                                ctx, region
                            )),
                        }
                    }
                }
                DestinationConfig::Generic { secret, url, .. } => {
                    if secret.as_deref() == Some(REDACTED) {
                        let u = url.clone();
                        let matches: Vec<String> = if u == REDACTED {
                            // URL is also redacted — match by uniqueness among Generic destinations
                            current
                                .destinations
                                .iter()
                                .filter_map(|d| match d {
                                    DestinationConfig::Generic {
                                        secret: Some(s), ..
                                    } => Some(s.clone()),
                                    _ => None,
                                })
                                .collect()
                        } else {
                            current
                                .destinations
                                .iter()
                                .filter_map(|d| match d {
                                    DestinationConfig::Generic {
                                        secret: Some(s),
                                        url: existing_url,
                                        ..
                                    } if existing_url == &u => Some(s.clone()),
                                    _ => None,
                                })
                                .collect()
                        };
                        match matches.as_slice() {
                            [s] => *secret = Some(s.clone()),
                            [] => errors.push(format!(
                                "{}: cannot resolve redacted secret — no existing Generic destination for url={}",
                                ctx, url
                            )),
                            _ => errors.push(format!(
                                "{}: ambiguous redacted secret — multiple Generic destinations for url={}",
                                ctx, url
                            )),
                        }
                    }
                }
            }
        }

        errors
    }
}

fn validate_destination_url(value: &str, field: &str, ctx: &str, errors: &mut Vec<String>) {
    let parsed = match reqwest::Url::parse(value) {
        Ok(url) => url,
        Err(_) => {
            errors.push(format!("{}: {} must be a valid URL", ctx, field));
            return;
        }
    };

    if parsed.scheme() != "https" {
        errors.push(format!("{}: {} must use https", ctx, field));
        return;
    }

    let Some(host) = parsed.host_str() else {
        errors.push(format!("{}: {} must include a host", ctx, field));
        return;
    };

    let host_lower = host.to_ascii_lowercase();
    if host_lower == "localhost" || host_lower.ends_with(".localhost") {
        errors.push(format!("{}: {} host is not allowed", ctx, field));
        return;
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_private_or_local_ip(ip) {
            errors.push(format!("{}: {} host IP is not allowed", ctx, field));
        }
    }
}

fn is_private_or_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unicast_link_local()
                || v6.is_unique_local()
                || v6.is_multicast()
                || v6.is_unspecified()
                || is_ipv6_documentation(v6)
        }
    }
}

fn is_ipv6_documentation(v6: std::net::Ipv6Addr) -> bool {
    let segments = v6.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8
}

/// The alerting service that dispatches to all configured destinations
pub struct AlertingService {
    config: AlertingConfig,
    http_client: reqwest::Client,
    in_flight: Arc<Semaphore>,
}

impl AlertingService {
    pub fn new(config: AlertingConfig) -> Arc<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        Arc::new(Self {
            config,
            http_client,
            in_flight: Arc::new(Semaphore::new(MAX_IN_FLIGHT_ALERT_TASKS)),
        })
    }

    pub fn config(&self) -> &AlertingConfig {
        &self.config
    }

    /// Fire an alert to all destinations (non-blocking, spawns background tasks)
    pub fn notify(self: &Arc<Self>, alert: Alert) {
        if !self.config.destinations.is_empty() && self.has_any_recipient(&alert.event_type) {
            let permit = match Arc::clone(&self.in_flight).try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    tracing::warn!(
                        event_type = %alert.event_type,
                        "dropping alert because alert worker queue is saturated"
                    );
                    return;
                }
            };
            let this = Arc::clone(self);
            tokio::spawn(async move {
                let _permit = permit;
                this.dispatch(&alert).await;
            });
        }
    }

    fn should_send(&self, dest: &DestinationConfig, event_type: &AlertEventType) -> bool {
        let dest_events = dest.events();
        if !dest_events.is_empty() {
            return dest_events.contains(event_type);
        }
        self.config.events.is_empty() || self.config.events.contains(event_type)
    }

    fn has_any_recipient(&self, event_type: &AlertEventType) -> bool {
        self.config
            .destinations
            .iter()
            .any(|d| self.should_send(d, event_type))
    }

    /// Send to all destinations, collecting results
    pub async fn dispatch(&self, alert: &Alert) -> Vec<(String, Result<(), String>)> {
        let mut results = Vec::new();
        for dest in &self.config.destinations {
            if !self.should_send(dest, &alert.event_type) {
                continue;
            }
            let dest_type = dest.destination_type().to_string();
            let result = self.send_with_retry(dest, alert).await;
            let status = if result.is_ok() { "success" } else { "error" };
            ALERTS_SENT
                .with_label_values(&[dest_type.as_str(), status])
                .inc();
            if let Err(ref e) = result {
                tracing::warn!(destination = %dest_type, error = %e, "alert delivery failed");
            }
            results.push((dest_type, result));
        }
        results
    }

    async fn send_with_retry(&self, dest: &DestinationConfig, alert: &Alert) -> Result<(), String> {
        let mut last_err = String::new();
        for attempt in 0..3u32 {
            if attempt > 0 {
                let delay = Duration::from_secs(1 << attempt);
                tokio::time::sleep(delay).await;
            }
            match self.send_once(dest, alert).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    last_err = e;
                    tracing::debug!(
                        destination = %dest.destination_type(),
                        attempt = attempt + 1,
                        error = %last_err,
                        "alert delivery attempt failed"
                    );
                }
            }
        }
        Err(last_err)
    }

    async fn send_once(&self, dest: &DestinationConfig, alert: &Alert) -> Result<(), String> {
        match dest {
            DestinationConfig::Slack {
                webhook_url,
                channel,
                ..
            } => slack::send(&self.http_client, webhook_url, channel.as_deref(), alert).await,
            DestinationConfig::Discord { webhook_url, .. } => {
                discord::send(&self.http_client, webhook_url, alert).await
            }
            DestinationConfig::Teams { webhook_url, .. } => {
                teams::send(&self.http_client, webhook_url, alert).await
            }
            DestinationConfig::Telegram {
                bot_token, chat_id, ..
            } => telegram::send(&self.http_client, bot_token, chat_id, alert).await,
            DestinationConfig::Pagerduty {
                routing_key,
                events_url,
                ..
            } => pagerduty::send(&self.http_client, events_url, routing_key, alert).await,
            DestinationConfig::Opsgenie {
                api_key, region, ..
            } => opsgenie::send(&self.http_client, api_key, region, alert).await,
            DestinationConfig::Generic {
                url,
                secret,
                headers,
                ..
            } => generic::send(&self.http_client, url, secret.as_deref(), headers, alert).await,
        }
    }
}

impl Default for AlertingService {
    fn default() -> Self {
        Self {
            config: AlertingConfig::default(),
            http_client: reqwest::Client::new(),
            in_flight: Arc::new(Semaphore::new(MAX_IN_FLIGHT_ALERT_TASKS)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_event_type_display() {
        assert_eq!(
            AlertEventType::MitigationCreated.to_string(),
            "mitigation.created"
        );
        assert_eq!(
            AlertEventType::MitigationExpired.to_string(),
            "mitigation.expired"
        );
    }

    fn test_dest() -> DestinationConfig {
        DestinationConfig::Slack {
            webhook_url: "https://hooks.slack.com/test".into(),
            channel: None,
            events: vec![],
        }
    }

    #[test]
    fn test_should_send_empty_filter() {
        let svc = AlertingService::default();
        let dest = test_dest();
        assert!(svc.should_send(&dest, &AlertEventType::MitigationCreated));
    }

    #[test]
    fn test_should_send_global_filter() {
        let config = AlertingConfig {
            destinations: vec![],
            events: vec![AlertEventType::MitigationCreated],
        };
        let svc = AlertingService {
            config,
            http_client: reqwest::Client::new(),
            in_flight: Arc::new(Semaphore::new(MAX_IN_FLIGHT_ALERT_TASKS)),
        };
        let dest = test_dest();
        assert!(svc.should_send(&dest, &AlertEventType::MitigationCreated));
        assert!(!svc.should_send(&dest, &AlertEventType::MitigationExpired));
    }

    #[test]
    fn test_should_send_per_destination_override() {
        let config = AlertingConfig {
            destinations: vec![],
            events: vec![
                AlertEventType::MitigationCreated,
                AlertEventType::MitigationExpired,
            ],
        };
        let svc = AlertingService {
            config,
            http_client: reqwest::Client::new(),
            in_flight: Arc::new(Semaphore::new(MAX_IN_FLIGHT_ALERT_TASKS)),
        };
        // Dest overrides global: only escalated
        let dest = DestinationConfig::Slack {
            webhook_url: "https://hooks.slack.com/test".into(),
            channel: None,
            events: vec![AlertEventType::MitigationEscalated],
        };
        assert!(!svc.should_send(&dest, &AlertEventType::MitigationCreated));
        assert!(svc.should_send(&dest, &AlertEventType::MitigationEscalated));
        assert!(!svc.should_send(&dest, &AlertEventType::MitigationExpired));
    }

    #[test]
    fn test_should_send_dest_empty_inherits_global() {
        let config = AlertingConfig {
            destinations: vec![],
            events: vec![AlertEventType::MitigationCreated],
        };
        let svc = AlertingService {
            config,
            http_client: reqwest::Client::new(),
            in_flight: Arc::new(Semaphore::new(MAX_IN_FLIGHT_ALERT_TASKS)),
        };
        let dest = test_dest(); // events: vec![] -> inherits global
        assert!(svc.should_send(&dest, &AlertEventType::MitigationCreated));
        assert!(!svc.should_send(&dest, &AlertEventType::MitigationExpired));
    }

    #[test]
    fn test_destination_config_redacted() {
        let dest = DestinationConfig::Slack {
            webhook_url: "https://hooks.slack.com/secret".into(),
            channel: Some("#alerts".into()),
            events: vec![],
        };
        let redacted = dest.redacted();
        assert_eq!(redacted["webhook_url"], "***");
        assert_eq!(redacted["channel"], "#alerts");
    }

    #[test]
    fn test_alert_serialization() {
        let alert = Alert::test_alert();
        let json = serde_json::to_string(&alert).unwrap();
        assert!(json.contains("mitigation.created"));
        assert!(json.contains("203.0.113.1"));
    }

    #[test]
    fn test_validate_empty_config_ok() {
        let config = AlertingConfig::default();
        assert!(config.validate().is_empty());
    }

    #[test]
    fn test_validate_missing_webhook_url() {
        let config = AlertingConfig {
            destinations: vec![DestinationConfig::Slack {
                webhook_url: "".into(),
                channel: None,
                events: vec![],
            }],
            events: vec![],
        };
        let errors = config.validate();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("webhook_url is required"));
    }

    #[test]
    fn test_validate_redacted_sentinel_rejected() {
        let config = AlertingConfig {
            destinations: vec![DestinationConfig::Discord {
                webhook_url: "***".into(),
                events: vec![],
            }],
            events: vec![],
        };
        let errors = config.validate();
        assert!(errors[0].contains("webhook_url is required"));
    }

    #[test]
    fn test_validate_telegram_missing_fields() {
        let config = AlertingConfig {
            destinations: vec![DestinationConfig::Telegram {
                bot_token: "".into(),
                chat_id: "".into(),
                events: vec![],
            }],
            events: vec![],
        };
        let errors = config.validate();
        assert_eq!(errors.len(), 2);
    }

    #[test]
    fn test_validate_opsgenie_bad_region() {
        let config = AlertingConfig {
            destinations: vec![DestinationConfig::Opsgenie {
                api_key: "key123".into(),
                region: "ap".into(),
                events: vec![],
            }],
            events: vec![],
        };
        let errors = config.validate();
        assert!(errors[0].contains("region must be"));
    }

    #[test]
    fn test_validate_rejects_non_https_webhook() {
        let config = AlertingConfig {
            destinations: vec![DestinationConfig::Slack {
                webhook_url: "http://example.com/hook".into(),
                channel: None,
                events: vec![],
            }],
            events: vec![],
        };
        let errors = config.validate();
        assert!(errors.iter().any(|e| e.contains("must use https")));
    }

    #[test]
    fn test_validate_rejects_link_local_url() {
        let config = AlertingConfig {
            destinations: vec![DestinationConfig::Generic {
                url: "https://169.254.169.254/latest/meta-data".into(),
                secret: None,
                headers: HashMap::new(),
                events: vec![],
            }],
            events: vec![],
        };
        let errors = config.validate();
        assert!(errors.iter().any(|e| e.contains("host IP is not allowed")));
    }

    #[test]
    fn test_merge_secrets_preserves_existing() {
        let current = AlertingConfig {
            destinations: vec![DestinationConfig::Slack {
                webhook_url: "https://hooks.slack.com/real-secret".into(),
                channel: Some("#alerts".into()),
                events: vec![],
            }],
            events: vec![],
        };
        let mut incoming = AlertingConfig {
            destinations: vec![DestinationConfig::Slack {
                webhook_url: "***".into(),
                channel: Some("#new-channel".into()),
                events: vec![],
            }],
            events: vec![],
        };
        let errors = incoming.merge_secrets(&current);
        assert!(errors.is_empty());
        if let DestinationConfig::Slack {
            webhook_url,
            channel,
            ..
        } = &incoming.destinations[0]
        {
            assert_eq!(webhook_url, "https://hooks.slack.com/real-secret");
            assert_eq!(channel.as_deref(), Some("#new-channel"));
        } else {
            panic!("expected Slack");
        }
    }

    #[test]
    fn test_merge_secrets_new_dest_with_redacted_fails() {
        let current = AlertingConfig::default();
        let mut incoming = AlertingConfig {
            destinations: vec![DestinationConfig::Discord {
                webhook_url: "***".into(),
                events: vec![],
            }],
            events: vec![],
        };
        let errors = incoming.merge_secrets(&current);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("cannot resolve"));
    }

    #[test]
    fn test_merge_secrets_generic_by_url() {
        let current = AlertingConfig {
            destinations: vec![DestinationConfig::Generic {
                url: "https://example.com/hook".into(),
                secret: Some("real-secret".into()),
                headers: HashMap::new(),
                events: vec![],
            }],
            events: vec![],
        };
        let mut incoming = AlertingConfig {
            destinations: vec![DestinationConfig::Generic {
                url: "https://example.com/hook".into(),
                secret: Some("***".into()),
                headers: HashMap::new(),
                events: vec![],
            }],
            events: vec![],
        };
        let errors = incoming.merge_secrets(&current);
        assert!(errors.is_empty());
        if let DestinationConfig::Generic { secret, .. } = &incoming.destinations[0] {
            assert_eq!(secret.as_deref(), Some("real-secret"));
        }
    }

    #[test]
    fn test_merge_secrets_ambiguous_discord() {
        let current = AlertingConfig {
            destinations: vec![
                DestinationConfig::Discord {
                    webhook_url: "https://discord.com/api/webhooks/one".into(),
                    events: vec![],
                },
                DestinationConfig::Discord {
                    webhook_url: "https://discord.com/api/webhooks/two".into(),
                    events: vec![],
                },
            ],
            events: vec![],
        };
        let mut incoming = AlertingConfig {
            destinations: vec![DestinationConfig::Discord {
                webhook_url: "***".into(),
                events: vec![],
            }],
            events: vec![],
        };
        let errors = incoming.merge_secrets(&current);
        assert!(errors.iter().any(|e| e.contains("ambiguous")));
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let config = AlertingConfig {
            destinations: vec![
                DestinationConfig::Slack {
                    webhook_url: "https://hooks.slack.com/test".into(),
                    channel: Some("#test".into()),
                    events: vec![],
                },
                DestinationConfig::Generic {
                    url: "https://example.com".into(),
                    secret: None,
                    headers: HashMap::new(),
                    events: vec![],
                },
            ],
            events: vec![AlertEventType::MitigationCreated],
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alerting.yaml");
        config.save(&path).unwrap();
        let loaded = AlertingConfig::load(&path).unwrap();
        assert_eq!(loaded.destinations.len(), 2);
        assert_eq!(loaded.events.len(), 1);
    }

    #[test]
    fn test_generic_redaction_masks_header_values() {
        let mut headers = HashMap::new();
        headers.insert(
            "Authorization".to_string(),
            "Bearer super-secret".to_string(),
        );
        headers.insert("X-Api-Key".to_string(), "abc123".to_string());

        let dest = DestinationConfig::Generic {
            url: "https://example.invalid/webhook".to_string(),
            secret: Some("super-secret".to_string()),
            headers,
            events: vec![],
        };

        let redacted = dest.redacted();
        let redacted_headers = redacted["headers"].as_object().unwrap();
        assert_eq!(redacted_headers["Authorization"], "***");
        assert_eq!(redacted_headers["X-Api-Key"], "***");
        assert_eq!(redacted["secret"], "***");
    }
}
