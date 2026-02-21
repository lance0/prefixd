mod discord;
mod generic;
mod opsgenie;
mod pagerduty;
mod slack;
mod teams;
mod telegram;

use crate::domain::Mitigation;
use once_cell::sync::Lazy;
use prometheus::CounterVec;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

pub static ALERTS_SENT: Lazy<CounterVec> = Lazy::new(|| {
    prometheus::register_counter_vec!(
        "prefixd_alerts_sent_total",
        "Total webhook alerts sent",
        &["destination", "status"]
    )
    .unwrap()
});

/// Alert event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
            Self::Generic { url, headers, .. } => serde_json::json!({
                "type": "generic",
                "url": url,
                "secret": "***",
                "headers": headers,
            }),
        }
    }
}

/// Top-level alerting config in prefixd.yaml
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AlertingConfig {
    #[serde(default)]
    pub destinations: Vec<DestinationConfig>,
    #[serde(default)]
    pub events: Vec<AlertEventType>,
}

/// The alerting service that dispatches to all configured destinations
pub struct AlertingService {
    config: AlertingConfig,
    http_client: reqwest::Client,
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
        })
    }

    pub fn config(&self) -> &AlertingConfig {
        &self.config
    }

    /// Fire an alert to all destinations (non-blocking, spawns background tasks)
    pub fn notify(self: &Arc<Self>, alert: Alert) {
        if !self.config.destinations.is_empty() && self.should_send(&alert.event_type) {
            let this = Arc::clone(self);
            tokio::spawn(async move {
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
}
