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
    // Never emitted: no code path escalates a mitigation. Kept so stored
    // destination filters and notification mutes that list it still parse.
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

    /// Values accepted when validating saved preferences, including the
    /// never-emitted `mitigation.escalated`, so existing mutes still save.
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

/// Configuration for a single alert destination. Each secret is given inline
/// or through its `*_env` key, which names an environment variable read when
/// an alert is sent. Configuration never holds the variable's value.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DestinationConfig {
    Slack {
        #[serde(default, skip_serializing_if = "String::is_empty")]
        webhook_url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        webhook_url_env: Option<String>,
        #[serde(default)]
        channel: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        events: Vec<AlertEventType>,
    },
    Discord {
        #[serde(default, skip_serializing_if = "String::is_empty")]
        webhook_url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        webhook_url_env: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        events: Vec<AlertEventType>,
    },
    Teams {
        #[serde(default, skip_serializing_if = "String::is_empty")]
        webhook_url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        webhook_url_env: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        events: Vec<AlertEventType>,
    },
    Telegram {
        #[serde(default, skip_serializing_if = "String::is_empty")]
        bot_token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bot_token_env: Option<String>,
        chat_id: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        events: Vec<AlertEventType>,
    },
    Pagerduty {
        #[serde(default, skip_serializing_if = "String::is_empty")]
        routing_key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        routing_key_env: Option<String>,
        #[serde(default = "default_pagerduty_url")]
        events_url: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        events: Vec<AlertEventType>,
    },
    Opsgenie {
        #[serde(default, skip_serializing_if = "String::is_empty")]
        api_key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        api_key_env: Option<String>,
        #[serde(default = "default_opsgenie_region")]
        region: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        events: Vec<AlertEventType>,
    },
    Generic {
        #[serde(default, skip_serializing_if = "String::is_empty")]
        url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        url_env: Option<String>,
        #[serde(default)]
        secret: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secret_env: Option<String>,
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

    /// Each secret's field name, inline value and `*_env` variable name.
    fn secrets(&self) -> Vec<(&'static str, Option<&str>, Option<&str>)> {
        match self {
            Self::Slack {
                webhook_url,
                webhook_url_env,
                ..
            }
            | Self::Discord {
                webhook_url,
                webhook_url_env,
                ..
            }
            | Self::Teams {
                webhook_url,
                webhook_url_env,
                ..
            } => vec![("webhook_url", Some(webhook_url), webhook_url_env.as_deref())],
            Self::Telegram {
                bot_token,
                bot_token_env,
                ..
            } => vec![("bot_token", Some(bot_token), bot_token_env.as_deref())],
            Self::Pagerduty {
                routing_key,
                routing_key_env,
                ..
            } => vec![("routing_key", Some(routing_key), routing_key_env.as_deref())],
            Self::Opsgenie {
                api_key,
                api_key_env,
                ..
            } => vec![("api_key", Some(api_key), api_key_env.as_deref())],
            Self::Generic {
                url,
                url_env,
                secret,
                secret_env,
                ..
            } => vec![
                ("url", Some(url), url_env.as_deref()),
                ("secret", secret.as_deref(), secret_env.as_deref()),
            ],
        }
    }

    /// Errors for `*_env` keys, naming the key and variable but never a value.
    fn env_errors(&self, ctx: &str) -> Vec<String> {
        let mut errors = Vec::new();
        for (field, value, env) in self.secrets() {
            let Some(env) = env else { continue };
            if value.is_some_and(|value| !value.is_empty()) {
                errors.push(format!(
                    "{ctx}: set {field} or {field}_env, not both; edit alerting.yaml"
                ));
            } else if std::env::var(env).unwrap_or_default().is_empty() {
                errors.push(format!(
                    "{ctx}: {field}_env names environment variable '{env}', which is not set or empty"
                ));
            }
        }
        errors
    }

    /// What this destination's `*_env` keys are bound to: its type, each
    /// variable name, and the non-secret field that picks where a value is
    /// sent. `None` without `*_env` keys.
    fn env_binding(&self) -> Option<serde_json::Value> {
        let envs: Vec<_> = self
            .secrets()
            .into_iter()
            .filter_map(|(field, _, env)| env.map(|env| (field, env)))
            .collect();
        if envs.is_empty() {
            return None;
        }
        let target = match self {
            Self::Telegram { chat_id, .. } => chat_id.as_str(),
            Self::Pagerduty { events_url, .. } => events_url,
            Self::Opsgenie { region, .. } => region,
            Self::Generic {
                url, url_env: None, ..
            } => url,
            // The variable is itself the destination URL.
            _ => "",
        };
        Some(serde_json::json!([self.destination_type(), envs, target]))
    }

    /// Whether this running destination has `binding`. A redacted inline
    /// generic URL stands for this destination's own URL, which the redacted
    /// merge then restores, so the variable still goes where it went before.
    fn binds(&self, binding: &serde_json::Value) -> bool {
        let Some(mut own) = self.env_binding() else {
            return false;
        };
        if binding[2] == REDACTED && matches!(self, Self::Generic { url_env: None, .. }) {
            own[2] = REDACTED.into();
        }
        own == *binding
    }

    /// A redacted `***` beside a `*_env` key stands for the variable, so it is
    /// cleared instead of inherited from the running destination.
    fn clear_env_sentinels(&mut self) {
        fn clear(value: &mut String, env: &Option<String>) {
            if env.is_some() && value == REDACTED {
                value.clear();
            }
        }
        match self {
            Self::Slack {
                webhook_url,
                webhook_url_env,
                ..
            }
            | Self::Discord {
                webhook_url,
                webhook_url_env,
                ..
            }
            | Self::Teams {
                webhook_url,
                webhook_url_env,
                ..
            } => clear(webhook_url, webhook_url_env),
            Self::Telegram {
                bot_token,
                bot_token_env,
                ..
            } => clear(bot_token, bot_token_env),
            Self::Pagerduty {
                routing_key,
                routing_key_env,
                ..
            } => clear(routing_key, routing_key_env),
            Self::Opsgenie {
                api_key,
                api_key_env,
                ..
            } => clear(api_key, api_key_env),
            Self::Generic {
                url,
                url_env,
                secret,
                secret_env,
                ..
            } => {
                clear(url, url_env);
                if secret_env.is_some() && secret.as_deref() == Some(REDACTED) {
                    *secret = None;
                }
            }
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
        // Variable names are not secret; show where each value comes from.
        for (field, _, env) in self.secrets() {
            if let Some(env) = env {
                obj[format!("{field}_env")] = env.into();
            }
        }
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
        let config: AlertingConfig = crate::config::parse_secret_yaml(&content)?;
        let errors = config.load_errors();
        anyhow::ensure!(errors.is_empty(), "{}", errors.join("; "));
        Ok(config)
    }

    /// `${VAR}` placeholders, missing secrets and unusable `*_env` keys, which
    /// startup and reload refuse. Messages name keys and variables, never values.
    pub fn load_errors(&self) -> Vec<String> {
        let mut errors = self.placeholder_errors();
        errors.extend(self.secret_errors());
        errors
    }

    fn placeholder_errors(&self) -> Vec<String> {
        self.destinations
            .iter()
            .enumerate()
            .flat_map(|(i, dest)| {
                let ctx = destination_ctx(i, dest);
                serde_json::to_value(dest)
                    .map(|value| crate::config::env_placeholder_errors(&value))
                    .unwrap_or_default()
                    .into_iter()
                    .map(move |error| format!("{ctx}: {error}"))
            })
            .collect()
    }

    /// Missing secrets and unusable `*_env` keys only. Generic `secret` is optional.
    fn secret_errors(&self) -> Vec<String> {
        let mut errors = Vec::new();
        for (i, dest) in self.destinations.iter().enumerate() {
            let ctx = destination_ctx(i, dest);
            for (field, value, env) in dest.secrets() {
                if env.is_none() && field != "secret" && value.is_none_or(str::is_empty) {
                    errors.push(format!("{ctx}: {field} or {field}_env is required"));
                }
            }
            errors.extend(dest.env_errors(&ctx));
        }
        errors
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

        let yaml = serde_saphyr::to_string(self)?;
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
        let mut errors = self.placeholder_errors();

        for (i, dest) in self.destinations.iter().enumerate() {
            let ctx = destination_ctx(i, dest);
            let env_errors = dest.env_errors(&ctx);
            if !env_errors.is_empty() {
                errors.extend(env_errors);
                continue;
            }
            match dest {
                DestinationConfig::Slack {
                    webhook_url,
                    webhook_url_env,
                    ..
                }
                | DestinationConfig::Discord {
                    webhook_url,
                    webhook_url_env,
                    ..
                }
                | DestinationConfig::Teams {
                    webhook_url,
                    webhook_url_env,
                    ..
                } => {
                    let webhook_url =
                        &resolve_secret(webhook_url, webhook_url_env).unwrap_or_default();
                    if webhook_url.is_empty() || webhook_url == REDACTED {
                        errors.push(format!("{}: webhook_url is required", ctx));
                    } else if webhook_url.len() > 1024 {
                        errors.push(format!("{}: webhook_url exceeds 1024 bytes", ctx));
                    } else {
                        validate_destination_url(webhook_url, "webhook_url", &ctx, &mut errors);
                    }
                }
                DestinationConfig::Telegram {
                    bot_token,
                    bot_token_env,
                    chat_id,
                    ..
                } => {
                    let bot_token = &resolve_secret(bot_token, bot_token_env).unwrap_or_default();
                    if bot_token.is_empty() || bot_token == REDACTED {
                        errors.push(format!("{}: bot_token is required", ctx));
                    }
                    if chat_id.is_empty() {
                        errors.push(format!("{}: chat_id is required", ctx));
                    } else if chat_id.len() > 64 {
                        errors.push(format!("{}: chat_id exceeds 64 bytes", ctx));
                    }
                }
                DestinationConfig::Pagerduty {
                    routing_key,
                    routing_key_env,
                    events_url,
                    ..
                } => {
                    let routing_key =
                        &resolve_secret(routing_key, routing_key_env).unwrap_or_default();
                    if routing_key.is_empty() || routing_key == REDACTED {
                        errors.push(format!("{}: routing_key is required", ctx));
                    }
                    if events_url.is_empty() {
                        errors.push(format!("{}: events_url is required", ctx));
                    } else if events_url.len() > 1024 {
                        errors.push(format!("{}: events_url exceeds 1024 bytes", ctx));
                    } else {
                        validate_destination_url(events_url, "events_url", &ctx, &mut errors);
                    }
                }
                DestinationConfig::Opsgenie {
                    api_key,
                    api_key_env,
                    region,
                    ..
                } => {
                    let api_key = &resolve_secret(api_key, api_key_env).unwrap_or_default();
                    if api_key.is_empty() || api_key == REDACTED {
                        errors.push(format!("{}: api_key is required", ctx));
                    }
                    if region != "us" && region != "eu" {
                        errors.push(format!("{}: region must be 'us' or 'eu'", ctx));
                    }
                }
                DestinationConfig::Generic { url, url_env, .. } => {
                    let url = &resolve_secret(url, url_env).unwrap_or_default();
                    if url.is_empty() || url == REDACTED {
                        errors.push(format!("{}: url is required", ctx));
                    } else if url.len() > 1024 {
                        errors.push(format!("{}: url exceeds 1024 bytes", ctx));
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
            dest.clear_env_sentinels();
            let ctx = destination_ctx(i, dest);
            // The editor may keep an existing `*_env` key, never add or retarget
            // one: a new variable name or destination would send that variable,
            // such as DATABASE_URL, wherever the request says. This runs before
            // any environment lookup, so a refusal reveals nothing about one.
            if let Some(binding) = dest.env_binding()
                && !current
                    .destinations
                    .iter()
                    .any(|existing| existing.binds(&binding))
            {
                errors.push(format!(
                    "{ctx}: set *_env keys in alerting.yaml on the controller host; the editor \
                     keeps one only for an unchanged destination"
                ));
                continue;
            }
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
                                    webhook_url_env: None,
                                    channel: existing_channel,
                                    ..
                                } if !u.is_empty() => {
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
                                    DestinationConfig::Slack {
                                        webhook_url: u,
                                        webhook_url_env: None,
                                        ..
                                    } if !u.is_empty() => Some(u.clone()),
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
                                DestinationConfig::Discord {
                                    webhook_url: u,
                                    webhook_url_env: None,
                                    ..
                                } if !u.is_empty() => Some(u.clone()),
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
                                DestinationConfig::Teams {
                                    webhook_url: u,
                                    webhook_url_env: None,
                                    ..
                                } if !u.is_empty() => Some(u.clone()),
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
                                    bot_token_env: None,
                                    chat_id: c,
                                    ..
                                } if c == &cid && !t.is_empty() => Some(t.clone()),
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
                                    routing_key_env: None,
                                    events_url: e,
                                    ..
                                } if e == &eu && !k.is_empty() => Some(k.clone()),
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
                                    api_key_env: None,
                                    region: reg,
                                    ..
                                } if reg == &r && !k.is_empty() => Some(k.clone()),
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
                DestinationConfig::Generic {
                    secret,
                    url,
                    url_env,
                    headers,
                    ..
                } => {
                    let redacted_headers: Vec<String> = headers
                        .iter()
                        .filter(|(_, value)| value.as_str() == REDACTED)
                        .map(|(key, _)| key.clone())
                        .collect();
                    let redacted_url = url_env.is_none() && url == REDACTED;
                    if !redacted_url
                        && secret.as_deref() != Some(REDACTED)
                        && redacted_headers.is_empty()
                    {
                        continue;
                    }
                    // One running destination supplies every redacted value, so
                    // a `***` is never saved literally. An env-backed URL
                    // matches by variable; a redacted inline URL by uniqueness.
                    let matches: Vec<&DestinationConfig> = current
                        .destinations
                        .iter()
                        .filter(|d| match d {
                            DestinationConfig::Generic {
                                url: existing_url,
                                url_env: existing_url_env,
                                ..
                            } => match url_env {
                                Some(_) => existing_url_env == url_env,
                                None if url == REDACTED => existing_url_env.is_none(),
                                None => existing_url_env.is_none() && existing_url == url,
                            },
                            _ => false,
                        })
                        .collect();
                    let [
                        DestinationConfig::Generic {
                            url: existing_url,
                            secret: existing_secret,
                            secret_env: existing_secret_env,
                            headers: existing_headers,
                            ..
                        },
                    ] = matches.as_slice()
                    else {
                        errors.push(if matches.is_empty() {
                            format!(
                                "{ctx}: cannot resolve redacted url, secret or headers — no matching existing Generic destination"
                            )
                        } else {
                            format!(
                                "{ctx}: ambiguous redacted url, secret or headers — multiple matching Generic destinations"
                            )
                        });
                        continue;
                    };
                    if redacted_url {
                        *url = existing_url.clone();
                    }
                    if secret.as_deref() == Some(REDACTED) {
                        if existing_secret_env.is_some() {
                            errors.push(format!(
                                "{ctx}: cannot resolve redacted secret — the matching destination reads it from secret_env"
                            ));
                        } else {
                            // An absent or empty signing secret stays absent or empty.
                            *secret = existing_secret.clone();
                        }
                    }
                    for key in redacted_headers {
                        match existing_headers.get(&key) {
                            Some(value) => {
                                headers.insert(key, value.clone());
                            }
                            None => errors.push(format!(
                                "{ctx}: cannot resolve redacted header {key} — the matching destination has no such header"
                            )),
                        }
                    }
                }
            }
        }

        errors
    }
}

fn destination_ctx(i: usize, dest: &DestinationConfig) -> String {
    format!("destination[{i}] ({})", dest.destination_type())
}

/// The secret's value: the named environment variable when `env` is set,
/// otherwise the inline value. The error names the variable, never a value.
fn resolve_secret(value: &str, env: &Option<String>) -> Result<String, String> {
    match env {
        Some(env) => std::env::var(env)
            .ok()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("environment variable '{env}' is not set or empty")),
        None => Ok(value.to_string()),
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

    let host_lower = host.trim_end_matches('.').to_ascii_lowercase();
    if host_lower == "localhost" || host_lower.ends_with(".localhost") {
        errors.push(format!("{}: {} host is not allowed", ctx, field));
        return;
    }

    let literal = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = literal.parse::<IpAddr>() {
        if is_private_or_local_ip(ip.to_canonical()) {
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
                webhook_url_env,
                channel,
                ..
            } => {
                let webhook_url = resolve_secret(webhook_url, webhook_url_env)?;
                slack::send(&self.http_client, &webhook_url, channel.as_deref(), alert).await
            }
            DestinationConfig::Discord {
                webhook_url,
                webhook_url_env,
                ..
            } => {
                let webhook_url = resolve_secret(webhook_url, webhook_url_env)?;
                discord::send(&self.http_client, &webhook_url, alert).await
            }
            DestinationConfig::Teams {
                webhook_url,
                webhook_url_env,
                ..
            } => {
                let webhook_url = resolve_secret(webhook_url, webhook_url_env)?;
                teams::send(&self.http_client, &webhook_url, alert).await
            }
            DestinationConfig::Telegram {
                bot_token,
                bot_token_env,
                chat_id,
                ..
            } => {
                let bot_token = resolve_secret(bot_token, bot_token_env)?;
                telegram::send(&self.http_client, &bot_token, chat_id, alert).await
            }
            DestinationConfig::Pagerduty {
                routing_key,
                routing_key_env,
                events_url,
                ..
            } => {
                let routing_key = resolve_secret(routing_key, routing_key_env)?;
                pagerduty::send(&self.http_client, events_url, &routing_key, alert).await
            }
            DestinationConfig::Opsgenie {
                api_key,
                api_key_env,
                region,
                ..
            } => {
                let api_key = resolve_secret(api_key, api_key_env)?;
                opsgenie::send(&self.http_client, &api_key, region, alert).await
            }
            DestinationConfig::Generic {
                url,
                url_env,
                secret,
                secret_env,
                headers,
                ..
            } => {
                let url = resolve_secret(url, url_env)?;
                let secret = match secret_env {
                    Some(_) => Some(resolve_secret("", secret_env)?),
                    None => secret.clone(),
                };
                generic::send(&self.http_client, &url, secret.as_deref(), headers, alert).await
            }
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

    #[test]
    fn test_stored_config_with_legacy_escalated_event_still_parses() {
        let dest: DestinationConfig = serde_json::from_value(serde_json::json!({
            "type": "generic",
            "url": "https://example.com/hook",
            "events": ["mitigation.escalated"],
        }))
        .unwrap();
        let DestinationConfig::Generic { events, .. } = dest else {
            panic!("expected generic destination");
        };
        assert_eq!(events, vec![AlertEventType::MitigationEscalated]);
        assert!(AlertEventType::ALL_STRINGS.contains(&"mitigation.escalated"));
    }

    fn test_dest() -> DestinationConfig {
        DestinationConfig::Slack {
            webhook_url: "https://hooks.slack.com/test".into(),
            webhook_url_env: None,
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
            webhook_url_env: None,
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
            webhook_url_env: None,
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
                webhook_url_env: None,
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
                webhook_url_env: None,
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
                bot_token_env: None,
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
                api_key_env: None,
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
                webhook_url_env: None,
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
                url_env: None,
                secret: None,
                secret_env: None,
                headers: HashMap::new(),
                events: vec![],
            }],
            events: vec![],
        };
        let errors = config.validate();
        assert!(errors.iter().any(|e| e.contains("host IP is not allowed")));
    }

    #[test]
    fn destination_url_validation_covers_literal_address_classes() {
        let destinations = [
            ("slack", "webhook_url"),
            ("discord", "webhook_url"),
            ("teams", "webhook_url"),
            ("pagerduty", "events_url"),
            ("generic", "url"),
        ];
        let mut cases = vec![
            (
                "not a URL with request-secret".to_string(),
                Some("must be a valid URL"),
            ),
            (
                "https://[::1/request-secret".to_string(),
                Some("must be a valid URL"),
            ),
            (
                "http://example.com/request-secret".to_string(),
                Some("must use https"),
            ),
            (
                "ftp://example.com/request-secret".to_string(),
                Some("must use https"),
            ),
            (
                "https://localhost/request-secret".to_string(),
                Some("host is not allowed"),
            ),
            (
                "https://sub.LOCALHOST/request-secret".to_string(),
                Some("host is not allowed"),
            ),
            (
                "https://localhost./request-secret".to_string(),
                Some("host is not allowed"),
            ),
            (
                "https://sub.LOCALHOST./request-secret".to_string(),
                Some("host is not allowed"),
            ),
        ];
        for host in [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "224.0.0.1",
            "255.255.255.255",
            "192.0.2.1",
            "0.0.0.0",
            "2130706433",
            "[::1]",
            "[0:0:0:0:0:0:0:1]",
            "[fe80::1]",
            "[fc00::1]",
            "[fdff::1]",
            "[::]",
            "[ff02::1]",
            "[2001:db8::1]",
            "[::ffff:10.0.0.1]",
            "[::ffff:172.16.0.1]",
            "[::ffff:192.168.0.1]",
            "[::ffff:127.0.0.1]",
            "[::ffff:7f00:1]",
            "[::ffff:169.254.169.254]",
            "[::ffff:224.0.0.1]",
            "[::ffff:255.255.255.255]",
            "[::ffff:192.0.2.1]",
            "[::ffff:0.0.0.0]",
        ] {
            cases.push((
                format!("https://user:request-secret@{host}/hook?token=request-secret"),
                Some("host IP is not allowed"),
            ));
        }
        for host in [
            "example.com",
            "alerts.example.com",
            "8.8.8.8",
            "[2606:4700:4700::1111]",
            "[::ffff:8.8.8.8]",
        ] {
            cases.push((format!("https://{host}/hook?token=request-secret"), None));
        }

        for (kind, field) in destinations {
            for (url, rejection) in &cases {
                let mut destination = serde_json::json!({ "type": kind });
                destination[field] = url.clone().into();
                if kind == "pagerduty" {
                    destination["routing_key"] = "routing-secret".into();
                }
                let config: AlertingConfig = serde_json::from_value(serde_json::json!({
                    "destinations": [destination],
                }))
                .unwrap();
                let expected = rejection
                    .map(|message| format!("destination[0] ({kind}): {field} {message}"))
                    .into_iter()
                    .collect::<Vec<_>>();
                assert_eq!(config.validate(), expected, "{kind}: {url}");
            }
        }
    }

    #[test]
    fn test_merge_secrets_preserves_existing() {
        let current = AlertingConfig {
            destinations: vec![DestinationConfig::Slack {
                webhook_url: "https://hooks.slack.com/real-secret".into(),
                webhook_url_env: None,
                channel: Some("#alerts".into()),
                events: vec![],
            }],
            events: vec![],
        };
        let mut incoming = AlertingConfig {
            destinations: vec![DestinationConfig::Slack {
                webhook_url: "***".into(),
                webhook_url_env: None,
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
                webhook_url_env: None,
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
                url_env: None,
                secret: Some("real-secret".into()),
                secret_env: None,
                headers: HashMap::new(),
                events: vec![],
            }],
            events: vec![],
        };
        let mut incoming = AlertingConfig {
            destinations: vec![DestinationConfig::Generic {
                url: "https://example.com/hook".into(),
                url_env: None,
                secret: Some("***".into()),
                secret_env: None,
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
                    webhook_url_env: None,
                    events: vec![],
                },
                DestinationConfig::Discord {
                    webhook_url: "https://discord.com/api/webhooks/two".into(),
                    webhook_url_env: None,
                    events: vec![],
                },
            ],
            events: vec![],
        };
        let mut incoming = AlertingConfig {
            destinations: vec![DestinationConfig::Discord {
                webhook_url: "***".into(),
                webhook_url_env: None,
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
                    webhook_url_env: None,
                    channel: Some("#test".into()),
                    events: vec![],
                },
                DestinationConfig::Generic {
                    url: "https://example.com".into(),
                    url_env: None,
                    secret: None,
                    secret_env: None,
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
            url_env: None,
            secret: Some("super-secret".to_string()),
            secret_env: None,
            headers,
            events: vec![],
        };

        let redacted = dest.redacted();
        let redacted_headers = redacted["headers"].as_object().unwrap();
        assert_eq!(redacted_headers["Authorization"], "***");
        assert_eq!(redacted_headers["X-Api-Key"], "***");
        assert_eq!(redacted["secret"], "***");
    }

    /// A variable every test environment sets, so tests need no `set_var`.
    const PRESENT_ENV: &str = "PATH";
    const MISSING_ENV: &str = "PREFIXD_TEST_UNSET_ALERT_SECRET";

    #[test]
    fn env_backed_secret_is_read_at_use_and_never_stored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alerting.yaml");
        std::fs::write(
            &path,
            format!(
                "destinations:\n  - type: pagerduty\n    routing_key_env: {PRESENT_ENV}\n  \
                 - type: generic\n    url: https://example.com/hook\n    secret_env: {PRESENT_ENV}\n"
            ),
        )
        .unwrap();
        let config = AlertingConfig::load(&path).unwrap();
        assert!(config.validate().is_empty(), "{:?}", config.validate());
        let DestinationConfig::Pagerduty {
            routing_key,
            routing_key_env,
            ..
        } = &config.destinations[0]
        else {
            panic!("expected PagerDuty");
        };
        assert!(routing_key.is_empty());
        assert_eq!(
            resolve_secret(routing_key, routing_key_env).unwrap(),
            std::env::var(PRESENT_ENV).unwrap()
        );

        let redacted = config.destinations[0].redacted();
        assert_eq!(redacted["routing_key"], "***");
        assert_eq!(redacted["routing_key_env"], PRESENT_ENV);
        assert_eq!(config.destinations[1].redacted()["secret_env"], PRESENT_ENV);

        config.save(&path).unwrap();
        let saved = std::fs::read_to_string(&path).unwrap();
        assert!(saved.contains(&format!("routing_key_env: {PRESENT_ENV}")));
        assert!(!saved.contains(&std::env::var(PRESENT_ENV).unwrap()));
        assert!(!saved.contains("routing_key:"));
    }

    #[test]
    fn unusable_env_keys_name_key_and_variable_never_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alerting.yaml");
        for (yaml, expected) in [
            (
                format!("destinations:\n  - type: opsgenie\n    api_key_env: {MISSING_ENV}\n"),
                format!(
                    "destination[0] (opsgenie): api_key_env names environment variable \
                     '{MISSING_ENV}', which is not set or empty"
                ),
            ),
            (
                format!(
                    "destinations:\n  - type: telegram\n    chat_id: '1'\n    \
                     bot_token: inline-secret-canary\n    bot_token_env: {PRESENT_ENV}\n"
                ),
                "destination[0] (telegram): set bot_token or bot_token_env, not both; edit \
                 alerting.yaml"
                    .into(),
            ),
        ] {
            std::fs::write(&path, &yaml).unwrap();
            let error = format!("{:#}", AlertingConfig::load(&path).unwrap_err());
            assert_eq!(error, expected);
            assert!(!error.contains("inline-secret-canary"));
            let config: AlertingConfig = crate::config::parse_yaml(&yaml).unwrap();
            assert_eq!(config.validate(), vec![expected]);
        }

        // Defaults let a destination omit its secret; loading still requires one.
        std::fs::write(&path, "destinations:\n  - type: pagerduty\n").unwrap();
        assert_eq!(
            format!("{:#}", AlertingConfig::load(&path).unwrap_err()),
            "destination[0] (pagerduty): routing_key or routing_key_env is required"
        );
        std::fs::write(
            &path,
            "destinations:\n  - type: generic\n    url: https://example.com/hook\n",
        )
        .unwrap();
        assert!(
            AlertingConfig::load(&path).is_ok(),
            "generic secret is optional"
        );
    }

    /// Source keys the loaded config does not serialize back, such as a typo
    /// that serde ignores.
    fn dropped_keys(source: &serde_json::Value, loaded: &serde_json::Value) -> Vec<String> {
        match (source, loaded) {
            (serde_json::Value::Object(source), serde_json::Value::Object(loaded)) => source
                .iter()
                .flat_map(|(key, value)| match loaded.get(key) {
                    Some(loaded) => dropped_keys(value, loaded),
                    None => vec![key.clone()],
                })
                .collect(),
            (serde_json::Value::Array(source), serde_json::Value::Array(loaded)) => source
                .iter()
                .zip(loaded)
                .flat_map(|(source, loaded)| dropped_keys(source, loaded))
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Every YAML block in the alerting guide parses. Each `destinations`
    /// example loads with no ignored key and fails validation only because the
    /// variables it names are unset here.
    #[test]
    fn alerting_guide_examples_load() {
        let guide = include_str!("../../docs/how-to/alerting.md");
        let blocks: Vec<String> = guide
            .split("```yaml\n")
            .skip(1)
            .map(|rest| {
                let block = rest.split("```").next().unwrap();
                let indent = block
                    .lines()
                    .filter(|line| !line.trim().is_empty())
                    .map(|line| line.len() - line.trim_start().len())
                    .min()
                    .unwrap_or(0);
                block
                    .lines()
                    .map(|line| line.get(indent..).unwrap_or(""))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .collect();
        let check = |yaml: &str| -> Result<bool, String> {
            let source: serde_json::Value =
                crate::config::parse_yaml(yaml).map_err(|e| e.to_string())?;
            if source.get("destinations").is_none() {
                return Ok(false);
            }
            let config: AlertingConfig =
                crate::config::parse_secret_yaml(yaml).map_err(|e| e.to_string())?;
            let dropped = dropped_keys(&source, &serde_json::to_value(&config).unwrap());
            if !dropped.is_empty() {
                return Err(format!("ignored keys {dropped:?}"));
            }
            // An unset variable stops validation of its destination, so check
            // a copy with each `*_env` key replaced by an inline fixture.
            let mut inline = serde_json::to_value(&config).unwrap();
            for dest in inline["destinations"].as_array_mut().unwrap() {
                let dest = dest.as_object_mut().unwrap();
                let envs: Vec<String> = dest
                    .keys()
                    .filter(|key| key.ends_with("_env"))
                    .cloned()
                    .collect();
                for env in envs {
                    dest.remove(&env);
                    let field = env.trim_end_matches("_env");
                    let fixture = if field.ends_with("url") {
                        "https://example.com/hook"
                    } else {
                        "fixture"
                    };
                    dest.insert(field.into(), fixture.into());
                }
            }
            let inline: AlertingConfig = serde_json::from_value(inline).unwrap();
            let errors = inline.validate();
            if errors.is_empty() {
                Ok(true)
            } else {
                Err(errors.join("; "))
            }
        };
        let mut alerting = 0;
        for block in &blocks {
            match check(block) {
                Ok(is_alerting) => alerting += usize::from(is_alerting),
                Err(error) => panic!("{error} in guide example:\n{block}"),
            }
        }
        assert!(alerting >= 10, "only {alerting} alerting examples found");

        // Negative controls: a typo serde ignores, a URL validation refuses,
        // and a bad non-secret field beside an unset variable.
        assert!(
            check("destinations:\n  - type: slack\n    webhook_url_env: X\n    chanel: a\n")
                .is_err()
        );
        assert!(
            check("destinations:\n  - type: discord\n    webhook_url: http://example.com/h\n")
                .is_err()
        );
        assert!(
            check(
                "destinations:\n  - type: opsgenie\n    api_key_env: UNSET_X\n    region: mars\n"
            )
            .is_err()
        );
    }

    #[test]
    fn placeholder_values_are_refused_by_load_and_validate() {
        let yaml =
            "destinations:\n  - type: pagerduty\n    routing_key: \"${PAGERDUTY_ROUTING_KEY}\"\n";
        // Negative control: the parser alone accepts the literal placeholder,
        // which earlier releases then sent as the routing key.
        let config: AlertingConfig = crate::config::parse_yaml(yaml).unwrap();
        let expected = "destination[0] (pagerduty): routing_key looks like ${VAR} substitution, which \
                        prefixd does not perform; set the value, or use the matching *_env key \
                        where one exists";
        assert_eq!(config.validate(), vec![expected.to_string()]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alerting.yaml");
        std::fs::write(&path, yaml).unwrap();
        assert_eq!(
            format!("{:#}", AlertingConfig::load(&path).unwrap_err()),
            expected
        );
    }

    #[test]
    fn redacted_sentinel_beside_env_key_keeps_the_variable() {
        let current = AlertingConfig {
            destinations: vec![DestinationConfig::Pagerduty {
                routing_key: String::new(),
                routing_key_env: Some(PRESENT_ENV.into()),
                events_url: default_pagerduty_url(),
                events: vec![],
            }],
            events: vec![],
        };
        let mut incoming: AlertingConfig = serde_json::from_value(serde_json::json!({
            "destinations": [current.destinations[0].redacted()],
        }))
        .unwrap();
        assert!(incoming.merge_secrets(&current).is_empty());
        assert!(incoming.validate().is_empty());
        assert_eq!(
            serde_json::to_value(&incoming).unwrap(),
            serde_json::to_value(&current).unwrap()
        );
    }

    fn editor_merge(current: &AlertingConfig, incoming: serde_json::Value) -> Vec<String> {
        let mut incoming: AlertingConfig = serde_json::from_value(incoming).unwrap();
        let mut errors = incoming.merge_secrets(current);
        if errors.is_empty() {
            errors = incoming.validate();
        }
        errors
    }

    #[test]
    fn editor_cannot_add_or_retarget_env_keys() {
        let current: AlertingConfig = serde_json::from_value(serde_json::json!({
            "destinations": [{ "type": "pagerduty", "routing_key_env": PRESENT_ENV }],
        }))
        .unwrap();
        let refused = "destination[0] (pagerduty): set *_env keys in alerting.yaml on the \
                       controller host; the editor keeps one only for an unchanged destination";
        let retargeted = serde_json::json!({
            "destinations": [{
                "type": "pagerduty",
                "routing_key_env": PRESENT_ENV,
                "events_url": "https://attacker.example/x",
            }],
        });
        // Negative control: the payload is otherwise valid, so without the
        // binding check the editor would send the variable to that URL.
        let control: AlertingConfig = serde_json::from_value(retargeted.clone()).unwrap();
        assert!(control.validate().is_empty());
        assert_eq!(editor_merge(&current, retargeted), vec![refused]);
        for env in [MISSING_ENV, "DATABASE_URL"] {
            // Refused before any lookup, so the error does not reveal whether
            // the variable exists.
            let added = serde_json::json!({
                "destinations": [{ "type": "pagerduty", "routing_key_env": env }],
            });
            assert_eq!(
                editor_merge(&AlertingConfig::default(), added),
                vec![refused]
            );
        }
        let kept = serde_json::json!({ "destinations": [current.destinations[0].redacted()] });
        assert!(editor_merge(&current, kept).is_empty());
    }

    #[test]
    fn redacted_merge_ignores_env_backed_candidates() {
        let current: AlertingConfig = serde_json::from_value(serde_json::json!({
            "destinations": [
                { "type": "slack", "webhook_url_env": PRESENT_ENV },
                { "type": "slack", "webhook_url": "https://hooks.slack.com/inline" },
                { "type": "pagerduty", "routing_key_env": PRESENT_ENV },
                { "type": "pagerduty", "routing_key": "inline-routing-key" },
                {
                    "type": "generic", "url_env": PRESENT_ENV,
                    "secret": "env-url-signing-secret",
                },
                {
                    "type": "generic", "url": "https://example.com/hook",
                    "secret": "inline-url-signing-secret",
                },
            ],
        }))
        .unwrap();
        let mut incoming: AlertingConfig = serde_json::from_value(serde_json::json!({
            "destinations": current.destinations.iter().map(|d| d.redacted()).collect::<Vec<_>>(),
        }))
        .unwrap();
        assert!(incoming.merge_secrets(&current).is_empty());
        // Generic `url` has no redacted merge, so only the other secrets compare.
        for (index, dest) in incoming.destinations.iter().enumerate().take(4) {
            assert_eq!(
                serde_json::to_value(dest).unwrap(),
                serde_json::to_value(&current.destinations[index]).unwrap()
            );
        }
        let secrets: Vec<_> = incoming.destinations[4..]
            .iter()
            .map(|dest| match dest {
                DestinationConfig::Generic { secret, .. } => secret.clone(),
                _ => panic!("expected generic"),
            })
            .collect();
        assert_eq!(
            secrets,
            [
                Some("env-url-signing-secret".to_string()),
                Some("inline-url-signing-secret".to_string())
            ]
        );
    }

    #[tokio::test]
    async fn delivery_errors_omit_the_request_url() {
        let url = "https://127.0.0.1:1/hook-secret-canary";
        let client = reqwest::Client::new();
        // Negative control: reqwest's own error text carries the URL.
        let raw = client.get(url).send().await.unwrap_err();
        assert!(raw.to_string().contains("hook-secret-canary"), "{raw}");
        let error = generic::send(&client, url, None, &HashMap::new(), &Alert::test_alert())
            .await
            .unwrap_err();
        assert!(error.starts_with("webhook request failed"), "{error}");
        assert!(!error.contains("hook-secret-canary"), "{error}");
    }

    #[test]
    fn redacted_generic_headers_are_inherited_or_refused() {
        let current: AlertingConfig = serde_json::from_value(serde_json::json!({
            "destinations": [{
                "type": "generic", "url_env": PRESENT_ENV, "secret": "signing-secret",
                "headers": { "Authorization": "Bearer header-secret" },
            }],
        }))
        .unwrap();
        let redacted = serde_json::json!({ "destinations": [current.destinations[0].redacted()] });
        // Negative control: the earlier merge cleared only the URL sentinel and
        // left headers alone, so the editor saved and sent `Authorization: ***`.
        let mut control: AlertingConfig = serde_json::from_value(redacted.clone()).unwrap();
        control.destinations[0].clear_env_sentinels();
        let DestinationConfig::Generic { headers, .. } = &control.destinations[0] else {
            panic!("expected generic");
        };
        assert_eq!(headers["Authorization"], REDACTED);

        let mut incoming: AlertingConfig = serde_json::from_value(redacted.clone()).unwrap();
        assert!(incoming.merge_secrets(&current).is_empty());
        assert_eq!(
            serde_json::to_value(&incoming).unwrap(),
            serde_json::to_value(&current).unwrap()
        );

        let mut added = redacted.clone();
        added["destinations"][0]["headers"]["X-New"] = REDACTED.into();
        assert_eq!(
            editor_merge(&current, added),
            [
                "destination[0] (generic): cannot resolve redacted header X-New — the matching \
              destination has no such header"
            ]
        );
        let mut twice = current.clone();
        twice.destinations.push(current.destinations[0].clone());
        assert_eq!(
            editor_merge(&twice, redacted),
            [
                "destination[0] (generic): ambiguous redacted url, secret or headers — multiple \
              matching Generic destinations"
            ]
        );
    }

    #[test]
    fn unchanged_generic_without_signing_secret_round_trips() {
        for secret in [None, Some("")] {
            let current = AlertingConfig {
                destinations: vec![DestinationConfig::Generic {
                    url: String::new(),
                    url_env: Some(PRESENT_ENV.into()),
                    secret: secret.map(String::from),
                    secret_env: None,
                    headers: HashMap::new(),
                    events: vec![],
                }],
                events: vec![],
            };
            let redacted = current.destinations[0].redacted();
            // Negative control: GET reports `***` even without a signing secret.
            assert_eq!(redacted["secret"], REDACTED);
            let mut incoming: AlertingConfig =
                serde_json::from_value(serde_json::json!({ "destinations": [redacted] })).unwrap();
            let errors = incoming.merge_secrets(&current);
            assert!(errors.is_empty(), "{secret:?}: {errors:?}");
            assert_eq!(
                serde_json::to_value(&incoming).unwrap(),
                serde_json::to_value(&current).unwrap()
            );
        }
    }

    #[test]
    fn generic_inline_url_with_secret_env_round_trips() {
        let current: AlertingConfig = serde_json::from_value(serde_json::json!({
            "destinations": [{
                "type": "generic", "url": "https://example.com/hook", "secret_env": PRESENT_ENV,
            }],
        }))
        .unwrap();
        let redacted = current.destinations[0].redacted();
        assert_eq!(redacted["url"], REDACTED);
        let incoming: AlertingConfig =
            serde_json::from_value(serde_json::json!({ "destinations": [redacted.clone()] }))
                .unwrap();
        // Negative control: the redacted URL does not equal the running one, so
        // exact binding alone refused this unchanged destination.
        assert_ne!(
            incoming.destinations[0].env_binding(),
            current.destinations[0].env_binding()
        );
        assert!(
            editor_merge(&current, serde_json::json!({ "destinations": [redacted] })).is_empty()
        );
        let mut merged = incoming;
        assert!(merged.merge_secrets(&current).is_empty());
        assert_eq!(
            serde_json::to_value(&merged).unwrap(),
            serde_json::to_value(&current).unwrap()
        );

        // With two inline-URL generic destinations the redacted URL is ambiguous.
        let mut two = current.clone();
        two.destinations.push(
            serde_json::from_value(serde_json::json!({
                "type": "generic", "url": "https://example.net/other",
            }))
            .unwrap(),
        );
        let redacted = serde_json::json!({ "destinations": [two.destinations[0].redacted()] });
        assert_eq!(
            editor_merge(&two, redacted),
            [
                "destination[0] (generic): ambiguous redacted url, secret or headers — multiple \
              matching Generic destinations"
            ]
        );
    }
}
