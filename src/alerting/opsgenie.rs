use super::{Alert, AlertEventType};

/// One Opsgenie API call: an alert create or a close by alias.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Create,
    Close,
}

#[derive(Debug, Clone)]
pub struct Request {
    pub action: Action,
    pub url: String,
    pub payload: serde_json::Value,
}

pub async fn send(
    client: &reqwest::Client,
    api_key: &str,
    region: &str,
    alert: &Alert,
) -> Result<(), String> {
    for request in build_requests(alert, region) {
        let response = client
            .post(&request.url)
            .header("Authorization", format!("GenieKey {}", api_key))
            .json(&request.payload)
            .send()
            .await
            .map_err(|e| format!("opsgenie request failed: {}", e.without_url()))?;

        let status = response.status();
        // A close for an alert that is already closed reaches the intended
        // state; Opsgenie answers 404 once nothing is open for the alias.
        if request.action == Action::Close && status.as_u16() == 404 {
            continue;
        }
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(format!("opsgenie returned {} — {}", status, body));
        }
    }

    Ok(())
}

/// The calls this alert needs. A withdrawal or expiry closes the mitigation's
/// alert by alias. A test alert creates an alert and closes it immediately,
/// because Opsgenie has no test event and an operator asked only for a
/// delivery check. Every other event creates an alert.
pub fn build_requests(alert: &Alert, region: &str) -> Vec<Request> {
    let base = base_url(region);
    let alias = alias(alert);
    let resolved = matches!(
        alert.event_type,
        AlertEventType::MitigationWithdrawn | AlertEventType::MitigationExpired
    );
    let mut requests = Vec::new();
    if !resolved {
        requests.push(Request {
            action: Action::Create,
            url: format!("{}/v2/alerts", base),
            payload: build_payload(alert),
        });
    }
    if resolved || alert.event_type == AlertEventType::Test {
        requests.push(Request {
            action: Action::Close,
            url: close_url(base, alias),
            payload: build_close_payload(alert),
        });
    }
    requests
}

fn base_url(region: &str) -> &'static str {
    match region {
        "eu" => "https://api.eu.opsgenie.com",
        _ => "https://api.opsgenie.com",
    }
}

/// The alert's stable identity in Opsgenie: the mitigation ID when there is
/// one, so a close reaches the alert its creation opened.
fn alias(alert: &Alert) -> &str {
    alert.mitigation_id.as_deref().unwrap_or(&alert.title)
}

pub fn close_url(base: &str, alias: &str) -> String {
    format!(
        "{}/v2/alerts/{}/close?identifierType=alias",
        base,
        urlencoding::encode(alias)
    )
}

pub fn build_payload(alert: &Alert) -> serde_json::Value {
    let priority = match alert.severity {
        super::AlertSeverity::Critical => "P1",
        super::AlertSeverity::Warning => "P3",
        super::AlertSeverity::Info => "P5",
    };

    let event = alert.event_type.to_string();
    let mut tags = vec!["prefixd", event.as_str()];
    if alert.dry_run {
        tags.push("dry-run");
    }

    let mut details = serde_json::Map::new();
    if alert.dry_run {
        details.insert("dry_run".into(), serde_json::json!(true));
    }
    if let Some(ref ip) = alert.victim_ip {
        details.insert("victim_ip".into(), serde_json::json!(ip));
    }
    if let Some(ref vector) = alert.vector {
        details.insert("vector".into(), serde_json::json!(vector));
    }
    if let Some(ref customer) = alert.customer_id {
        details.insert("customer_id".into(), serde_json::json!(customer));
    }
    if let Some(ref action) = alert.action_type {
        details.insert("action_type".into(), serde_json::json!(action));
    }
    if let Some(ref pop) = alert.pop {
        details.insert("pop".into(), serde_json::json!(pop));
    }

    serde_json::json!({
        "message": format!("{}: {}", alert.title, alert.message),
        "alias": alias(alert),
        "description": alert.message,
        "source": alert.source,
        "priority": priority,
        "tags": tags,
        "details": details,
    })
}

pub fn build_close_payload(alert: &Alert) -> serde_json::Value {
    serde_json::json!({
        "source": alert.source,
        "note": format!("{}: {}", alert.title, alert.message),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opsgenie_payload_structure() {
        let alert = Alert::test_alert();
        let payload = build_payload(&alert);
        assert_eq!(payload["priority"], "P5"); // test alert is Info severity
        assert_eq!(payload["source"], "prefixd");
        let tags = payload["tags"].as_array().unwrap();
        assert!(tags.len() >= 2);
    }

    #[test]
    fn created_alert_is_created_and_not_closed() {
        let mut alert = Alert::test_alert();
        alert.event_type = AlertEventType::MitigationCreated;
        alert.mitigation_id = Some("abc".into());
        let requests = build_requests(&alert, "us");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].action, Action::Create);
        assert_eq!(requests[0].url, "https://api.opsgenie.com/v2/alerts");
        assert_eq!(requests[0].payload["alias"], "abc");
    }

    #[test]
    fn withdrawn_and_expired_alerts_close_by_alias_instead_of_creating() {
        for event_type in [
            AlertEventType::MitigationWithdrawn,
            AlertEventType::MitigationExpired,
        ] {
            let mut alert = Alert::test_alert();
            alert.event_type = event_type;
            alert.mitigation_id = Some("abc".into());
            let requests = build_requests(&alert, "eu");
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].action, Action::Close);
            assert_eq!(
                requests[0].url,
                "https://api.eu.opsgenie.com/v2/alerts/abc/close?identifierType=alias"
            );
            assert_eq!(requests[0].payload["source"], "prefixd");
            assert!(requests[0].payload.get("alias").is_none());
        }
    }

    #[test]
    fn test_alert_creates_then_closes_the_same_alias() {
        let alert = Alert::test_alert();
        let requests = build_requests(&alert, "us");
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].action, Action::Create);
        assert_eq!(requests[0].payload["alias"], "Test Alert");
        assert_eq!(requests[1].action, Action::Close);
        assert_eq!(
            requests[1].url,
            "https://api.opsgenie.com/v2/alerts/Test%20Alert/close?identifierType=alias"
        );
    }

    #[test]
    fn close_url_escapes_the_alias() {
        assert_eq!(
            close_url("https://api.opsgenie.com", "id/with?chars"),
            "https://api.opsgenie.com/v2/alerts/id%2Fwith%3Fchars/close?identifierType=alias"
        );
    }

    #[test]
    fn dry_run_is_annotated_in_details_and_tags() {
        let mut alert = Alert::test_alert();
        alert.event_type = AlertEventType::MitigationCreated;
        assert!(build_payload(&alert)["details"].get("dry_run").is_none());
        alert.dry_run = true;
        let payload = build_payload(&alert);
        assert_eq!(payload["details"]["dry_run"], serde_json::json!(true));
        assert!(
            payload["tags"]
                .as_array()
                .unwrap()
                .iter()
                .any(|tag| tag == "dry-run")
        );
    }
}
