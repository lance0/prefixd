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
    send_to(client, api_key, base_url(region), alert).await
}

async fn send_to(
    client: &reqwest::Client,
    api_key: &str,
    base: &str,
    alert: &Alert,
) -> Result<(), String> {
    for request in requests_at(alert, base) {
        let action = match request.action {
            Action::Create => "create",
            Action::Close => "close",
        };
        // Bound the entire asynchronous action, including response reads and polling.
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let response = client
                .post(&request.url)
                .header("Authorization", format!("GenieKey {}", api_key))
                .json(&request.payload)
                .send()
                .await
                .map_err(|_| "opsgenie request failed".to_string())?;
            if !response.status().is_success() {
                return Err(super::platform_error("opsgenie", response.status()));
            }
            if response.status() != reqwest::StatusCode::ACCEPTED {
                return Err("opsgenie response did not confirm acceptance".into());
            }
            let body = bounded_json(response).await?;
            let request_id = body["requestId"]
                .as_str()
                .filter(|id| !id.is_empty() && id.len() <= 128)
                .ok_or("opsgenie response missing request ID")?;
            let url = format!(
                "{base}/v2/alerts/requests/{}",
                urlencoding::encode(request_id)
            );
            loop {
                let response = client
                    .get(&url)
                    .header("Authorization", format!("GenieKey {}", api_key))
                    .send()
                    .await
                    .map_err(|_| "opsgenie status request failed".to_string())?;
                // Request status may not be visible yet; this is NOT a close success.
                if response.status() != reqwest::StatusCode::NOT_FOUND {
                    if !response.status().is_success() {
                        return Err(super::platform_error("opsgenie", response.status()));
                    }
                    let body = bounded_json(response).await?;
                    match body["data"]["isSuccess"].as_bool() {
                        Some(true) => return Ok(()),
                        Some(false) => {
                            return Err(
                                "opsgenie asynchronous action failed (response body omitted)"
                                    .into(),
                            );
                        }
                        None => return Err("opsgenie status response missing result".into()),
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
        })
        .await
        .map_err(|_| format!("opsgenie {action} confirmation timed out"))??;
    }
    Ok(())
}

async fn bounded_json(mut response: reqwest::Response) -> Result<serde_json::Value, String> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "opsgenie response read failed")?
    {
        if body.len() + chunk.len() > 16 * 1024 {
            return Err("opsgenie response exceeds 16384 bytes".into());
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| "opsgenie returned invalid JSON".into())
}

/// The calls this alert needs. A withdrawal or expiry closes the mitigation's
/// alert by alias. A test alert creates an alert and closes it after confirmation,
/// because Opsgenie has no test event and an operator asked only for a
/// delivery check. Every other event creates an alert.
#[cfg(test)]
pub fn build_requests(alert: &Alert, region: &str) -> Vec<Request> {
    requests_at(alert, base_url(region))
}

fn requests_at(alert: &Alert, base: &str) -> Vec<Request> {
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

    type Replies = std::sync::Arc<tokio::sync::Mutex<std::collections::VecDeque<(u16, String)>>>;
    type Calls = std::sync::Arc<tokio::sync::Mutex<Vec<(String, serde_json::Value)>>>;

    async fn mock(replies: Vec<(u16, String)>) -> (String, Calls, tokio::task::JoinHandle<()>) {
        let replies: Replies = std::sync::Arc::new(tokio::sync::Mutex::new(replies.into()));
        let calls: Calls = Default::default();
        let app = axum::Router::new().fallback({
            let calls = calls.clone();
            move |uri: axum::http::Uri, body: String| {
                let replies = replies.clone();
                let calls = calls.clone();
                async move {
                    calls.lock().await.push((
                        uri.to_string(),
                        serde_json::from_str(&body).unwrap_or_default(),
                    ));
                    let (status, body) = replies
                        .lock()
                        .await
                        .pop_front()
                        .unwrap_or((404, String::new()));
                    (axum::http::StatusCode::from_u16(status).unwrap(), body)
                }
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (base, calls, server)
    }

    fn accepted(id: &str) -> (u16, String) {
        (202, serde_json::json!({"requestId": id}).to_string())
    }

    fn completed(success: bool) -> (u16, String) {
        (
            200,
            serde_json::json!({"data": {"isSuccess": success, "status": "secret-canary"}})
                .to_string(),
        )
    }

    #[tokio::test]
    async fn test_waits_for_create_then_confirms_close() {
        let (base, calls, server) = mock(vec![
            accepted("create"),
            (404, String::new()),
            completed(true),
            accepted("close"),
            completed(true),
        ])
        .await;
        let alert = Alert::test_alert();
        send_to(&reqwest::Client::new(), "secret", &base, &alert)
            .await
            .unwrap();
        let calls = calls.lock().await;
        assert_eq!(calls.len(), 5);
        assert_eq!(calls[0].0, "/v2/alerts");
        assert_eq!(calls[1].0, "/v2/alerts/requests/create");
        assert_eq!(calls[2].0, "/v2/alerts/requests/create");
        assert_eq!(
            calls[3].0,
            format!(
                "/v2/alerts/{}/close?identifierType=alias",
                alert.mitigation_id.as_deref().unwrap()
            )
        );
        assert_eq!(calls[4].0, "/v2/alerts/requests/close");
        server.abort();
    }

    #[tokio::test]
    async fn asynchronous_failures_are_errors_without_echoing_response() {
        for replies in [
            vec![accepted("create"), completed(false)],
            vec![
                accepted("create"),
                completed(true),
                accepted("close"),
                completed(false),
            ],
        ] {
            let (base, _, server) = mock(replies).await;
            let error = send_to(
                &reqwest::Client::new(),
                "secret",
                &base,
                &Alert::test_alert(),
            )
            .await
            .unwrap_err();
            assert_eq!(
                error,
                "opsgenie asynchronous action failed (response body omitted)"
            );
            server.abort();
        }
    }

    #[tokio::test]
    async fn lifecycle_close_is_confirmed_and_404_is_not_success() {
        for event in [
            AlertEventType::MitigationWithdrawn,
            AlertEventType::MitigationExpired,
        ] {
            for (replies, success) in [
                (vec![accepted("close"), completed(true)], true),
                (vec![(404, "secret-canary".into())], false),
            ] {
                let (base, calls, server) = mock(replies).await;
                let mut alert = Alert::test_alert();
                alert.event_type = event;
                alert.mitigation_id = Some("stable-mitigation".into());
                let result = send_to(&reqwest::Client::new(), "secret", &base, &alert).await;
                assert_eq!(result.is_ok(), success);
                assert!(calls.lock().await[0].0.contains("/stable-mitigation/close"));
                server.abort();
            }
        }
    }

    #[tokio::test]
    async fn malformed_and_oversized_responses_fail_safely() {
        for reply in [
            (202, "secret-canary".into()),
            (202, "x".repeat(16385)),
            (202, "{}".into()),
            (500, "secret-canary".repeat(10000)),
        ] {
            let (base, _, server) = mock(vec![reply]).await;
            let error = send_to(
                &reqwest::Client::new(),
                "secret",
                &base,
                &Alert::test_alert(),
            )
            .await
            .unwrap_err();
            assert!(!error.contains("secret-canary"));
            assert!(error.len() < 100);
            server.abort();
        }
    }

    #[tokio::test]
    async fn pending_request_times_out_without_attempting_close() {
        let (base, calls, server) = mock(vec![accepted("pending")]).await;
        let error = send_to(
            &reqwest::Client::new(),
            "secret",
            &base,
            &Alert::test_alert(),
        )
        .await
        .unwrap_err();
        assert_eq!(error, "opsgenie create confirmation timed out");
        assert!(
            calls
                .lock()
                .await
                .iter()
                .all(|(path, _)| !path.contains("/close"))
        );
        server.abort();
    }

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
        assert_eq!(
            requests[0].payload["alias"],
            alert.mitigation_id.as_deref().unwrap()
        );
        assert_eq!(requests[1].action, Action::Close);
        assert_eq!(
            requests[1].url,
            close_url(
                "https://api.opsgenie.com",
                alert.mitigation_id.as_deref().unwrap()
            )
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
