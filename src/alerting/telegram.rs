use super::Alert;

pub async fn send(
    client: &reqwest::Client,
    bot_token: &str,
    chat_id: &str,
    alert: &Alert,
) -> Result<(), String> {
    let url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token);
    let text = build_message(alert);

    let payload = serde_json::json!({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": true,
    });

    let response = client
        .post(&url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("telegram request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("telegram returned {} — {}", status, body));
    }

    Ok(())
}

pub fn build_message(alert: &Alert) -> String {
    let icon = match alert.severity {
        super::AlertSeverity::Critical => "\u{1F534}",
        super::AlertSeverity::Warning => "\u{1F7E0}",
        super::AlertSeverity::Info => "\u{1F7E2}",
    };

    let mut lines = vec![
        format!("{} <b>{}</b>", icon, html_escape(&alert.title)),
        String::new(),
        html_escape(&alert.message),
        String::new(),
    ];

    if let Some(ref ip) = alert.victim_ip {
        lines.push(format!(
            "<b>Victim IP:</b> <code>{}</code>",
            html_escape(ip)
        ));
    }
    if let Some(ref vector) = alert.vector {
        lines.push(format!("<b>Vector:</b> {}", html_escape(vector)));
    }
    if let Some(ref action) = alert.action_type {
        lines.push(format!("<b>Action:</b> {}", html_escape(action)));
    }
    if let Some(ref customer) = alert.customer_id {
        lines.push(format!("<b>Customer:</b> {}", html_escape(customer)));
    }
    if let Some(ref pop) = alert.pop {
        lines.push(format!("<b>POP:</b> {}", html_escape(pop)));
    }
    if let Some(ref mid) = alert.mitigation_id {
        lines.push(format!(
            "<b>Mitigation:</b> <code>{}</code>",
            html_escape(mid)
        ));
    }

    lines.push(String::new());
    lines.push(format!(
        "<i>prefixd | {}</i>",
        alert.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
    ));

    lines.join("\n")
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telegram_message_structure() {
        let alert = Alert::test_alert();
        let msg = build_message(&alert);
        assert!(msg.contains("<b>Test Alert</b>"));
        assert!(msg.contains("<code>203.0.113.1</code>"));
        assert!(msg.contains("prefixd"));
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
    }
}
