use super::{Alert, AlertEventType};

pub async fn send(
    client: &reqwest::Client,
    events_url: &str,
    routing_key: &str,
    alert: &Alert,
) -> Result<(), String> {
    let payload = build_payload(alert, routing_key);

    let response = client
        .post(events_url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("pagerduty request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("pagerduty returned {} — {}", status, body));
    }

    Ok(())
}

pub fn build_payload(alert: &Alert, routing_key: &str) -> serde_json::Value {
    let event_action = match alert.event_type {
        AlertEventType::MitigationWithdrawn | AlertEventType::MitigationExpired => "resolve",
        _ => "trigger",
    };

    let dedup_key = alert.mitigation_id.as_deref().unwrap_or(&alert.title);

    let mut custom_details = serde_json::json!({
        "event_type": alert.event_type.to_string(),
    });

    if let Some(ref ip) = alert.victim_ip {
        custom_details["victim_ip"] = serde_json::json!(ip);
    }
    if let Some(ref vector) = alert.vector {
        custom_details["vector"] = serde_json::json!(vector);
    }
    if let Some(ref customer) = alert.customer_id {
        custom_details["customer_id"] = serde_json::json!(customer);
    }
    if let Some(ref action) = alert.action_type {
        custom_details["action_type"] = serde_json::json!(action);
    }
    if let Some(ref pop) = alert.pop {
        custom_details["pop"] = serde_json::json!(pop);
    }

    serde_json::json!({
        "routing_key": routing_key,
        "event_action": event_action,
        "dedup_key": dedup_key,
        "payload": {
            "summary": format!("{}: {}", alert.title, alert.message),
            "source": alert.source,
            "severity": alert.severity.label(),
            "timestamp": alert.timestamp.to_rfc3339(),
            "component": "prefixd",
            "custom_details": custom_details,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pagerduty_trigger_payload() {
        let alert = Alert::test_alert();
        let payload = build_payload(&alert, "test-routing-key");
        assert_eq!(payload["routing_key"], "test-routing-key");
        assert_eq!(payload["event_action"], "trigger");
        assert!(
            payload["payload"]["summary"]
                .as_str()
                .unwrap()
                .contains("Test Alert")
        );
    }

    #[test]
    fn test_pagerduty_resolve_on_withdraw() {
        let mut alert = Alert::test_alert();
        alert.event_type = AlertEventType::MitigationWithdrawn;
        let payload = build_payload(&alert, "key");
        assert_eq!(payload["event_action"], "resolve");
    }

    #[test]
    fn test_pagerduty_resolve_on_expire() {
        let mut alert = Alert::test_alert();
        alert.event_type = AlertEventType::MitigationExpired;
        let payload = build_payload(&alert, "key");
        assert_eq!(payload["event_action"], "resolve");
    }
}
