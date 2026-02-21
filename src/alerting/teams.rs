use super::Alert;

pub async fn send(
    client: &reqwest::Client,
    webhook_url: &str,
    alert: &Alert,
) -> Result<(), String> {
    let payload = build_payload(alert);

    let response = client
        .post(webhook_url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("teams request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("teams returned {} — {}", status, body));
    }

    Ok(())
}

/// Build an Adaptive Card payload for Power Automate / Teams Workflows webhook
pub fn build_payload(alert: &Alert) -> serde_json::Value {
    let mut facts = vec![
        serde_json::json!({"title": "Severity", "value": alert.severity.label()}),
        serde_json::json!({"title": "Event", "value": alert.event_type.to_string()}),
    ];

    if let Some(ref ip) = alert.victim_ip {
        facts.push(serde_json::json!({"title": "Victim IP", "value": ip}));
    }
    if let Some(ref vector) = alert.vector {
        facts.push(serde_json::json!({"title": "Vector", "value": vector}));
    }
    if let Some(ref customer) = alert.customer_id {
        facts.push(serde_json::json!({"title": "Customer", "value": customer}));
    }
    if let Some(ref pop) = alert.pop {
        facts.push(serde_json::json!({"title": "POP", "value": pop}));
    }
    if let Some(ref mid) = alert.mitigation_id {
        facts.push(serde_json::json!({"title": "Mitigation ID", "value": mid}));
    }

    serde_json::json!({
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "contentUrl": null,
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {
                        "type": "TextBlock",
                        "size": "Large",
                        "weight": "Bolder",
                        "text": alert.title,
                        "color": match alert.severity {
                            super::AlertSeverity::Critical => "Attention",
                            super::AlertSeverity::Warning => "Warning",
                            super::AlertSeverity::Info => "Good",
                        }
                    },
                    {
                        "type": "TextBlock",
                        "text": alert.message,
                        "wrap": true
                    },
                    {
                        "type": "FactSet",
                        "facts": facts
                    },
                    {
                        "type": "TextBlock",
                        "text": format!("prefixd | {}", alert.timestamp.to_rfc3339()),
                        "size": "Small",
                        "isSubtle": true
                    }
                ]
            }
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_teams_payload_structure() {
        let alert = Alert::test_alert();
        let payload = build_payload(&alert);
        assert_eq!(payload["type"], "message");
        let attachments = payload["attachments"].as_array().unwrap();
        assert_eq!(attachments.len(), 1);
        assert_eq!(
            attachments[0]["contentType"],
            "application/vnd.microsoft.card.adaptive"
        );
        let body = attachments[0]["content"]["body"].as_array().unwrap();
        assert!(body.len() >= 3);
    }
}
