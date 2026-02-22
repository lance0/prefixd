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
    },
    Discord {
        webhook_url: String,
    },
    Teams {
        webhook_url: String,
    },
    Telegram {
        bot_token: String,
        chat_id: String,
    },
    Pagerduty {
        routing_key: String,
        #[serde(default = "default_pagerduty_url")]
        events_url: String,
    },
    Opsgenie {
        api_key: String,
        #[serde(default = "default_opsgenie_region")]
        region: String,
    },
    Generic {
        url: String,
        #[serde(default)]
        secret: Option<String>,
        #[serde(default)]
        headers: HashMap<String, String>,
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

    /// Return a redacted copy for API exposure
    pub fn redacted(&self) -> serde_json::Value {
        match self {
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
            Self::Generic { url, headers, .. } => {
                let redacted_headers: HashMap<_, _> = headers
                    .keys()
                    .cloned()
                    .map(|k| (k, "***".to_string()))
                    .collect();
                serde_json::json!({
                    "type": "generic",
                    "url": url,
                    "secret": "***",
                    "headers": redacted_headers,
                })
            }
        }
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
                    }
                }
                DestinationConfig::Discord { webhook_url } => {
                    if webhook_url.is_empty() || webhook_url == REDACTED {
                        errors.push(format!("{}: webhook_url is required", ctx));
                    } else if webhook_url.len() > 1024 {
                        errors.push(format!("{}: webhook_url exceeds 1024 chars", ctx));
                    }
                }
                DestinationConfig::Teams { webhook_url } => {
                    if webhook_url.is_empty() || webhook_url == REDACTED {
                        errors.push(format!("{}: webhook_url is required", ctx));
                    } else if webhook_url.len() > 1024 {
                        errors.push(format!("{}: webhook_url exceeds 1024 chars", ctx));
                    }
                }
                DestinationConfig::Telegram { bot_token, chat_id } => {
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
                } => {
                    if routing_key.is_empty() || routing_key == REDACTED {
                        errors.push(format!("{}: routing_key is required", ctx));
                    }
                    if events_url.is_empty() {
                        errors.push(format!("{}: events_url is required", ctx));
                    } else if events_url.len() > 1024 {
                        errors.push(format!("{}: events_url exceeds 1024 chars", ctx));
                    }
                }
                DestinationConfig::Opsgenie { api_key, region } => {
                    if api_key.is_empty() || api_key == REDACTED {
                        errors.push(format!("{}: api_key is required", ctx));
                    }
                    if region != "us" && region != "eu" {
                        errors.push(format!("{}: region must be 'us' or 'eu'", ctx));
                    }
                }
                DestinationConfig::Generic { url, .. } => {
                    if url.is_empty() {
                        errors.push(format!("{}: url is required", ctx));
                    } else if url.len() > 1024 {
                        errors.push(format!("{}: url exceeds 1024 chars", ctx));
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
                DestinationConfig::Slack { webhook_url, .. } => {
                    if webhook_url.as_str() == REDACTED {
                        let found = current.destinations.iter().find_map(|d| match d {
                            DestinationConfig::Slack { webhook_url: u, .. } => Some(u.clone()),
                            _ => None,
                        });
                        match found {
                            Some(u) => *webhook_url = u,
                            None => errors.push(format!("{}: cannot resolve redacted webhook_url — no existing Slack destination", ctx)),
                        }
                    }
                }
                DestinationConfig::Discord { webhook_url } => {
                    if webhook_url.as_str() == REDACTED {
                        let found = current.destinations.iter().find_map(|d| match d {
                            DestinationConfig::Discord { webhook_url: u } => Some(u.clone()),
                            _ => None,
                        });
                        match found {
                            Some(u) => *webhook_url = u,
                            None => errors.push(format!("{}: cannot resolve redacted webhook_url — no existing Discord destination", ctx)),
                        }
                    }
                }
                DestinationConfig::Teams { webhook_url } => {
                    if webhook_url.as_str() == REDACTED {
                        let found = current.destinations.iter().find_map(|d| match d {
                            DestinationConfig::Teams { webhook_url: u } => Some(u.clone()),
                            _ => None,
                        });
                        match found {
                            Some(u) => *webhook_url = u,
                            None => errors.push(format!("{}: cannot resolve redacted webhook_url — no existing Teams destination", ctx)),
                        }
                    }
                }
                DestinationConfig::Telegram { bot_token, chat_id } => {
                    if bot_token.as_str() == REDACTED {
                        let cid = chat_id.clone();
                        let found = current.destinations.iter().find_map(|d| match d {
                            DestinationConfig::Telegram {
                                bot_token: t,
                                chat_id: c,
                            } if c == &cid => Some(t.clone()),
                            _ => None,
                        });
                        match found {
                            Some(t) => *bot_token = t,
                            None => errors.push(format!("{}: cannot resolve redacted bot_token — no existing Telegram destination with chat_id={}", ctx, chat_id)),
                        }
                    }
                }
                DestinationConfig::Pagerduty {
                    routing_key,
                    events_url,
                } => {
                    if routing_key.as_str() == REDACTED {
                        let eu = events_url.clone();
                        let found = current.destinations.iter().find_map(|d| match d {
                            DestinationConfig::Pagerduty {
                                routing_key: k,
                                events_url: e,
                            } if e == &eu => Some(k.clone()),
                            _ => None,
                        });
                        match found {
                            Some(k) => *routing_key = k,
                            None => errors.push(format!("{}: cannot resolve redacted routing_key — no existing PagerDuty destination", ctx)),
                        }
                    }
                }
                DestinationConfig::Opsgenie { api_key, region } => {
                    if api_key.as_str() == REDACTED {
                        let r = region.clone();
                        let found = current.destinations.iter().find_map(|d| match d {
                            DestinationConfig::Opsgenie {
                                api_key: k,
                                region: reg,
                            } if reg == &r => Some(k.clone()),
                            _ => None,
                        });
                        match found {
                            Some(k) => *api_key = k,
                            None => errors.push(format!("{}: cannot resolve redacted api_key — no existing OpsGenie destination for region={}", ctx, region)),
                        }
                    }
                }
                DestinationConfig::Generic { secret, url, .. } => {
                    if secret.as_deref() == Some(REDACTED) {
                        let u = url.clone();
                        let found = current.destinations.iter().find_map(|d| match d {
                            DestinationConfig::Generic {
                                secret: s,
                                url: existing_url,
                                ..
                            } if existing_url == &u => s.clone(),
                            _ => None,
                        });
                        match found {
                            Some(s) => *secret = Some(s),
                            None => errors.push(format!("{}: cannot resolve redacted secret — no existing Generic destination for url={}", ctx, url)),
                        }
                    }
                }
            }
        }

        errors
    }
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
        if !self.config.destinations.is_empty() && self.should_send(&alert.event_type) {
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

    fn should_send(&self, event_type: &AlertEventType) -> bool {
        self.config.events.is_empty() || self.config.events.contains(event_type)
    }

    /// Send to all destinations, collecting results
    pub async fn dispatch(&self, alert: &Alert) -> Vec<(String, Result<(), String>)> {
        let mut results = Vec::new();
        for dest in &self.config.destinations {
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
            } => slack::send(&self.http_client, webhook_url, channel.as_deref(), alert).await,
            DestinationConfig::Discord { webhook_url } => {
                discord::send(&self.http_client, webhook_url, alert).await
            }
            DestinationConfig::Teams { webhook_url } => {
                teams::send(&self.http_client, webhook_url, alert).await
            }
            DestinationConfig::Telegram { bot_token, chat_id } => {
                telegram::send(&self.http_client, bot_token, chat_id, alert).await
            }
            DestinationConfig::Pagerduty {
                routing_key,
                events_url,
            } => pagerduty::send(&self.http_client, events_url, routing_key, alert).await,
            DestinationConfig::Opsgenie { api_key, region } => {
                opsgenie::send(&self.http_client, api_key, region, alert).await
            }
            DestinationConfig::Generic {
                url,
                secret,
                headers,
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

    #[test]
    fn test_should_send_empty_filter() {
        let svc = AlertingService::default();
        assert!(svc.should_send(&AlertEventType::MitigationCreated));
    }

    #[test]
    fn test_should_send_filtered() {
        let config = AlertingConfig {
            destinations: vec![],
            events: vec![AlertEventType::MitigationCreated],
        };
        let svc = AlertingService {
            config,
            http_client: reqwest::Client::new(),
            in_flight: Arc::new(Semaphore::new(MAX_IN_FLIGHT_ALERT_TASKS)),
        };
        assert!(svc.should_send(&AlertEventType::MitigationCreated));
        assert!(!svc.should_send(&AlertEventType::MitigationExpired));
    }

    #[test]
    fn test_destination_config_redacted() {
        let dest = DestinationConfig::Slack {
            webhook_url: "https://hooks.slack.com/secret".into(),
            channel: Some("#alerts".into()),
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
            }],
            events: vec![],
        };
        let errors = config.validate();
        assert!(errors[0].contains("region must be"));
    }

    #[test]
    fn test_merge_secrets_preserves_existing() {
        let current = AlertingConfig {
            destinations: vec![DestinationConfig::Slack {
                webhook_url: "https://hooks.slack.com/real-secret".into(),
                channel: Some("#alerts".into()),
            }],
            events: vec![],
        };
        let mut incoming = AlertingConfig {
            destinations: vec![DestinationConfig::Slack {
                webhook_url: "***".into(),
                channel: Some("#new-channel".into()),
            }],
            events: vec![],
        };
        let errors = incoming.merge_secrets(&current);
        assert!(errors.is_empty());
        if let DestinationConfig::Slack {
            webhook_url,
            channel,
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
            }],
            events: vec![],
        };
        let mut incoming = AlertingConfig {
            destinations: vec![DestinationConfig::Generic {
                url: "https://example.com/hook".into(),
                secret: Some("***".into()),
                headers: HashMap::new(),
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
    fn test_save_and_load_roundtrip() {
        let config = AlertingConfig {
            destinations: vec![
                DestinationConfig::Slack {
                    webhook_url: "https://hooks.slack.com/test".into(),
                    channel: Some("#test".into()),
                },
                DestinationConfig::Generic {
                    url: "https://example.com".into(),
                    secret: None,
                    headers: HashMap::new(),
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
        };

        let redacted = dest.redacted();
        let redacted_headers = redacted["headers"].as_object().unwrap();
        assert_eq!(redacted_headers["Authorization"], "***");
        assert_eq!(redacted_headers["X-Api-Key"], "***");
        assert_eq!(redacted["secret"], "***");
    }
}
