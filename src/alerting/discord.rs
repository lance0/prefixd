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
        .map_err(|e| format!("discord request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("discord returned {} — {}", status, body));
    }

    Ok(())
}

pub fn build_payload(alert: &Alert) -> serde_json::Value {
    let mut fields = Vec::new();

    if let Some(ref ip) = alert.victim_ip {
        fields.push(
            serde_json::json!({"name": "Victim IP", "value": format!("`{}`", ip), "inline": true}),
        );
    }
    if let Some(ref vector) = alert.vector {
        fields.push(serde_json::json!({"name": "Vector", "value": vector, "inline": true}));
    }
    if let Some(ref action) = alert.action_type {
        fields.push(serde_json::json!({"name": "Action", "value": action, "inline": true}));
    }
    if let Some(ref customer) = alert.customer_id {
        fields.push(serde_json::json!({"name": "Customer", "value": customer, "inline": true}));
    }
    if let Some(ref pop) = alert.pop {
        fields.push(serde_json::json!({"name": "POP", "value": pop, "inline": true}));
    }

    let embed = serde_json::json!({
        "title": alert.title,
        "description": alert.message,
        "color": alert.severity.color_hex(),
        "fields": fields,
        "footer": {"text": "prefixd"},
        "timestamp": alert.timestamp.to_rfc3339(),
    });

    serde_json::json!({
        "username": "prefixd",
        "embeds": [embed],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discord_payload_structure() {
        let alert = Alert::test_alert();
        let payload = build_payload(&alert);
        assert_eq!(payload["username"], "prefixd");
        let embeds = payload["embeds"].as_array().unwrap();
        assert_eq!(embeds.len(), 1);
        assert_eq!(embeds[0]["title"], "Test Alert");
        assert!(embeds[0]["color"].as_u64().unwrap() > 0);
    }
}
