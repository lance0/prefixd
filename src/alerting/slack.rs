use super::Alert;

pub async fn send(
    client: &reqwest::Client,
    webhook_url: &str,
    channel: Option<&str>,
    alert: &Alert,
) -> Result<(), String> {
    let payload = build_payload(alert, channel);

    let response = client
        .post(webhook_url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("slack request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("slack returned {} — {}", status, body));
    }

    Ok(())
}

pub fn build_payload(alert: &Alert, channel: Option<&str>) -> serde_json::Value {
    let mut fields = vec![
        serde_json::json!({
            "type": "mrkdwn",
            "text": format!("*Severity:* {}", alert.severity.label())
        }),
        serde_json::json!({
            "type": "mrkdwn",
            "text": format!("*Event:* {}", alert.event_type)
        }),
    ];

    if let Some(ref ip) = alert.victim_ip {
        fields.push(serde_json::json!({
            "type": "mrkdwn",
            "text": format!("*Victim IP:* `{}`", ip)
        }));
    }

    if let Some(ref vector) = alert.vector {
        fields.push(serde_json::json!({
            "type": "mrkdwn",
            "text": format!("*Vector:* {}", vector)
        }));
    }

    if let Some(ref customer) = alert.customer_id {
        fields.push(serde_json::json!({
            "type": "mrkdwn",
            "text": format!("*Customer:* {}", customer)
        }));
    }

    if let Some(ref pop) = alert.pop {
        fields.push(serde_json::json!({
            "type": "mrkdwn",
            "text": format!("*POP:* {}", pop)
        }));
    }

    let mut blocks = vec![
        serde_json::json!({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": alert.title,
                "emoji": true
            }
        }),
        serde_json::json!({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": alert.message
            }
        }),
        serde_json::json!({
            "type": "section",
            "fields": fields
        }),
        serde_json::json!({
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": format!("prefixd | {}", alert.timestamp.to_rfc3339())
            }]
        }),
    ];

    if let Some(ref mid) = alert.mitigation_id {
        blocks.push(serde_json::json!({
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": format!("Mitigation ID: `{}`", mid)
            }]
        }));
    }

    let mut payload = serde_json::json!({
        "text": format!("{}: {}", alert.title, alert.message),
        "blocks": blocks,
    });

    if let Some(ch) = channel {
        payload["channel"] = serde_json::json!(ch);
    }

    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slack_payload_structure() {
        let alert = Alert::test_alert();
        let payload = build_payload(&alert, Some("#test"));
        assert_eq!(payload["channel"], "#test");
        let blocks = payload["blocks"].as_array().unwrap();
        assert!(blocks.len() >= 3);
        assert_eq!(blocks[0]["type"], "header");
        assert_eq!(blocks[1]["type"], "section");
    }
}
