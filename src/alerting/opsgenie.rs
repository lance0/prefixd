use super::Alert;

pub async fn send(
    client: &reqwest::Client,
    api_key: &str,
    region: &str,
    alert: &Alert,
) -> Result<(), String> {
    let base_url = match region {
        "eu" => "https://api.eu.opsgenie.com",
        _ => "https://api.opsgenie.com",
    };
    let url = format!("{}/v2/alerts", base_url);
    let payload = build_payload(alert);

    let response = client
        .post(&url)
        .header("Authorization", format!("GenieKey {}", api_key))
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("opsgenie request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("opsgenie returned {} — {}", status, body));
    }

    Ok(())
}

pub fn build_payload(alert: &Alert) -> serde_json::Value {
    let priority = match alert.severity {
        super::AlertSeverity::Critical => "P1",
        super::AlertSeverity::Warning => "P3",
        super::AlertSeverity::Info => "P5",
    };

    let alias = alert.mitigation_id.as_deref().unwrap_or(&alert.title);

    let mut details = serde_json::Map::new();
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
        "alias": alias,
        "description": alert.message,
        "source": alert.source,
        "priority": priority,
        "tags": ["prefixd", alert.event_type.to_string()],
        "details": details,
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
}
