use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::domain::Mitigation;
use crate::error::{PrefixdError, Result};

/// Alerting configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AlertingConfig {
    #[serde(default)]
    pub slack: Option<SlackConfig>,
    #[serde(default)]
    pub pagerduty: Option<PagerDutyConfig>,
    #[serde(default)]
    pub generic_webhook: Option<GenericWebhookConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackConfig {
    pub webhook_url: String,
    #[serde(default = "default_channel")]
    pub channel: String,
    #[serde(default)]
    pub username: Option<String>,
}

fn default_channel() -> String {
    "#alerts".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagerDutyConfig {
    pub routing_key: String,
    #[serde(default = "default_pagerduty_url")]
    pub events_url: String,
}

fn default_pagerduty_url() -> String {
    "https://events.pagerduty.com/v2/enqueue".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericWebhookConfig {
    pub url: String,
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
}

/// Alert severity levels
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

/// Alert payload
#[derive(Debug, Clone, Serialize)]
pub struct Alert {
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
    pub metadata: serde_json::Value,
}

impl Alert {
    pub fn new(severity: AlertSeverity, title: &str, message: &str) -> Self {
        Self {
            severity,
            title: title.to_string(),
            message: message.to_string(),
            source: "prefixd".to_string(),
            timestamp: chrono::Utc::now(),
            mitigation_id: None,
            victim_ip: None,
            customer_id: None,
            metadata: serde_json::json!({}),
        }
    }

    pub fn from_mitigation(mitigation: &Mitigation, title: &str, message: &str) -> Self {
        Self {
            severity: AlertSeverity::Warning,
            title: title.to_string(),
            message: message.to_string(),
            source: "prefixd".to_string(),
            timestamp: chrono::Utc::now(),
            mitigation_id: Some(mitigation.mitigation_id.to_string()),
            victim_ip: Some(mitigation.victim_ip.clone()),
            customer_id: mitigation.customer_id.clone(),
            metadata: serde_json::json!({
                "vector": mitigation.vector.to_string(),
                "action_type": mitigation.action_type.to_string(),
                "pop": mitigation.pop,
            }),
        }
    }

    pub fn mitigation_created(mitigation: &Mitigation) -> Self {
        Self::from_mitigation(
            mitigation,
            "Mitigation Created",
            &format!(
                "{} mitigation for {} ({})",
                mitigation.action_type, mitigation.victim_ip, mitigation.vector
            ),
        )
    }

    pub fn mitigation_escalated(mitigation: &Mitigation) -> Self {
        let mut alert = Self::from_mitigation(
            mitigation,
            "Mitigation Escalated",
            &format!(
                "Escalated to {} for {} - attack persisting",
                mitigation.action_type, mitigation.victim_ip
            ),
        );
        alert.severity = AlertSeverity::Critical;
        alert
    }
}

/// Alerting client for sending webhooks
pub struct AlertingClient {
    config: AlertingConfig,
    http_client: reqwest::Client,
}

impl AlertingClient {
    pub fn new(config: AlertingConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        Self {
            config,
            http_client,
        }
    }

    pub async fn send(&self, alert: &Alert) -> Result<()> {
        let mut errors = Vec::new();

        if let Some(ref slack) = self.config.slack {
            if let Err(e) = self.send_slack(slack, alert).await {
                errors.push(format!("slack: {}", e));
            }
        }

        if let Some(ref pagerduty) = self.config.pagerduty {
            if let Err(e) = self.send_pagerduty(pagerduty, alert).await {
                errors.push(format!("pagerduty: {}", e));
            }
        }

        if let Some(ref webhook) = self.config.generic_webhook {
            if let Err(e) = self.send_generic_webhook(webhook, alert).await {
                errors.push(format!("webhook: {}", e));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(PrefixdError::Internal(format!(
                "alerting errors: {}",
                errors.join(", ")
            )))
        }
    }

    async fn send_slack(&self, config: &SlackConfig, alert: &Alert) -> Result<()> {
        let color = match alert.severity {
            AlertSeverity::Info => "#36a64f",
            AlertSeverity::Warning => "#ff9900",
            AlertSeverity::Critical => "#ff0000",
        };

        let payload = serde_json::json!({
            "channel": config.channel,
            "username": config.username.as_deref().unwrap_or("prefixd"),
            "attachments": [{
                "color": color,
                "title": alert.title,
                "text": alert.message,
                "fields": [
                    {
                        "title": "Severity",
                        "value": format!("{:?}", alert.severity),
                        "short": true
                    },
                    {
                        "title": "Victim IP",
                        "value": alert.victim_ip.as_deref().unwrap_or("N/A"),
                        "short": true
                    }
                ],
                "ts": alert.timestamp.timestamp()
            }]
        });

        let response = self
            .http_client
            .post(&config.webhook_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| PrefixdError::Internal(format!("slack request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(PrefixdError::Internal(format!(
                "slack returned {}",
                response.status()
            )));
        }

        Ok(())
    }

    async fn send_pagerduty(&self, config: &PagerDutyConfig, alert: &Alert) -> Result<()> {
        let severity = match alert.severity {
            AlertSeverity::Info => "info",
            AlertSeverity::Warning => "warning",
            AlertSeverity::Critical => "critical",
        };

        let payload = serde_json::json!({
            "routing_key": config.routing_key,
            "event_action": "trigger",
            "dedup_key": alert.mitigation_id.as_deref().unwrap_or(&alert.title),
            "payload": {
                "summary": alert.message,
                "source": alert.source,
                "severity": severity,
                "timestamp": alert.timestamp.to_rfc3339(),
                "custom_details": {
                    "victim_ip": alert.victim_ip,
                    "customer_id": alert.customer_id,
                    "metadata": alert.metadata
                }
            }
        });

        let response = self
            .http_client
            .post(&config.events_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| PrefixdError::Internal(format!("pagerduty request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(PrefixdError::Internal(format!(
                "pagerduty returned {}",
                response.status()
            )));
        }

        Ok(())
    }

    async fn send_generic_webhook(
        &self,
        config: &GenericWebhookConfig,
        alert: &Alert,
    ) -> Result<()> {
        let mut request = self.http_client.post(&config.url).json(alert);

        for (key, value) in &config.headers {
            request = request.header(key, value);
        }

        let response = request
            .send()
            .await
            .map_err(|e| PrefixdError::Internal(format!("webhook request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(PrefixdError::Internal(format!(
                "webhook returned {}",
                response.status()
            )));
        }

        Ok(())
    }
}

impl Default for AlertingClient {
    fn default() -> Self {
        Self::new(AlertingConfig::default())
    }
}
