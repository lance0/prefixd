use super::{Alert, AlertEventType};

pub async fn send(
    client: &reqwest::Client,
    events_url: &str,
    routing_key: &str,
    alert: &Alert,
) -> Result<(), String> {
    for payload in build_requests(alert, routing_key) {
        let response = client
            .post(events_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("pagerduty request failed: {}", e.without_url()))?;

        if !response.status().is_success() {
            let status = response.status();
            return Err(super::platform_error("pagerduty", status));
        }
    }

    Ok(())
}

/// The events to post for this alert. A withdrawal or expiry resolves its
/// mitigation's incident. A test alert triggers one and immediately resolves
/// it with the same deduplication key, because PagerDuty has no test event and
/// an operator asked only for a delivery check.
pub fn build_requests(alert: &Alert, routing_key: &str) -> Vec<serde_json::Value> {
    let mut requests = vec![build_payload(alert, routing_key)];
    if alert.event_type == AlertEventType::Test {
        requests.push(build_resolve_payload(alert, routing_key));
    }
    requests
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

    if alert.dry_run {
        custom_details["dry_run"] = serde_json::json!(true);
    }
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

/// A resolve for the same deduplication key as `alert`, used to close the
/// incident a test alert opened.
pub fn build_resolve_payload(alert: &Alert, routing_key: &str) -> serde_json::Value {
    let mut payload = build_payload(alert, routing_key);
    payload["event_action"] = serde_json::json!("resolve");
    payload
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
    fn test_alert_triggers_then_resolves_the_same_incident() {
        let alert = Alert::test_alert();
        let requests = build_requests(&alert, "key");
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0]["event_action"], "trigger");
        assert_eq!(requests[1]["event_action"], "resolve");
        assert_eq!(
            requests[0]["dedup_key"],
            alert.mitigation_id.as_deref().unwrap()
        );
        assert_eq!(requests[1]["dedup_key"], requests[0]["dedup_key"]);
    }

    #[test]
    fn test_pagerduty_resolve_on_withdraw() {
        let mut alert = Alert::test_alert();
        alert.event_type = AlertEventType::MitigationWithdrawn;
        let payload = build_payload(&alert, "key");
        assert_eq!(payload["event_action"], "resolve");
        assert_eq!(build_requests(&alert, "key").len(), 1);
    }

    #[test]
    fn test_pagerduty_resolve_on_expire() {
        let mut alert = Alert::test_alert();
        alert.event_type = AlertEventType::MitigationExpired;
        let payload = build_payload(&alert, "key");
        assert_eq!(payload["event_action"], "resolve");
        assert_eq!(build_requests(&alert, "key").len(), 1);
    }

    #[test]
    fn dry_run_mitigation_is_annotated_in_custom_details() {
        let mut alert = Alert::test_alert();
        alert.event_type = AlertEventType::MitigationCreated;
        assert!(build_payload(&alert, "key")["payload"]["custom_details"]["dry_run"].is_null());
        alert.dry_run = true;
        let payload = build_payload(&alert, "key");
        assert_eq!(
            payload["payload"]["custom_details"]["dry_run"],
            serde_json::json!(true)
        );
    }
}
