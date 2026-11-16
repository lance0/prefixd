use super::{Alert, AlertEventType, Failure};

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
) -> Result<(), Failure> {
    send_to(client, api_key, base_url(region), alert).await
}

/// Lifecycle creates and closes trust Opsgenie's 202: confirming each would
/// turn a close of an alert an operator already closed by hand into a failed,
/// retried delivery and multiply API calls during a mass expiry. Only the test
/// sequence confirms each step, because its close must follow a processed
/// create and its result claims the alert is gone.
pub(super) async fn send_to(
    client: &reqwest::Client,
    api_key: &str,
    base: &str,
    alert: &Alert,
) -> Result<(), Failure> {
    let confirm = alert.event_type == AlertEventType::Test;
    for request in requests_at(alert, base) {
        let action = match request.action {
            Action::Create => "create",
            Action::Close => "close",
        };
        // One 10-second deadline bounds each complete action, POST included.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        let post = client
            .post(&request.url)
            .header("Authorization", format!("GenieKey {}", api_key))
            .json(&request.payload)
            .send();
        let response = tokio::time::timeout_at(deadline, post)
            .await
            .map_err(|_| Failure {
                error: format!("opsgenie {action} request timed out"),
                retry: true,
            })?
            .map_err(|e| super::request_failure("opsgenie", e))?;
        let status = response.status();
        if status != reqwest::StatusCode::ACCEPTED {
            return Err(status_failure(status));
        }
        if confirm {
            tokio::time::timeout_at(deadline, confirm_request(client, api_key, base, response))
                .await
                .map_err(|_| Failure {
                    error: format!("opsgenie {action} confirmation timed out"),
                    retry: true,
                })??;
        }
    }
    Ok(())
}

/// Opsgenie acknowledges an action only with 202, so any other success is final.
fn status_failure(status: reqwest::StatusCode) -> Failure {
    if status.is_success() {
        return Failure::permanent("opsgenie response did not confirm acceptance");
    }
    super::platform_failure("opsgenie", status)
}

/// Poll the accepted request's status until Opsgenie reports its outcome.
async fn confirm_request(
    client: &reqwest::Client,
    api_key: &str,
    base: &str,
    response: reqwest::Response,
) -> Result<(), Failure> {
    let body = bounded_json(response).await?;
    let request_id = body["requestId"]
        .as_str()
        .filter(|id| !id.is_empty() && id.len() <= 128)
        .ok_or_else(|| Failure {
            error: "opsgenie response missing request ID".into(),
            retry: false,
        })?;
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
            .map_err(|e| super::request_failure("opsgenie status", e))?;
        // Observed behavior, not a documented contract: Opsgenie answers 404
        // until the request's status is visible. It is never a close success.
        if response.status() != reqwest::StatusCode::NOT_FOUND {
            if !response.status().is_success() {
                return Err(status_failure(response.status()));
            }
            let body = bounded_json(response).await?;
            return match body["data"]["isSuccess"].as_bool() {
                Some(true) => Ok(()),
                Some(false) => Err(Failure {
                    error: "opsgenie asynchronous action failed (response body omitted)".into(),
                    retry: false,
                }),
                None => Err(Failure {
                    error: "opsgenie status response missing result".into(),
                    retry: false,
                }),
            };
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

async fn bounded_json(mut response: reqwest::Response) -> Result<serde_json::Value, Failure> {
    let failure = |error: &str, retry| Failure {
        error: error.into(),
        retry,
    };
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| failure("opsgenie response read failed", true))?
    {
        if body.len() + chunk.len() > 16 * 1024 {
            return Err(failure("opsgenie response exceeds 16384 bytes", false));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| failure("opsgenie returned invalid JSON", false))
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
            let failure = send_to(
                &reqwest::Client::new(),
                "secret",
                &base,
                &Alert::test_alert(),
            )
            .await
            .unwrap_err();
            assert_eq!(
                failure.error,
                "opsgenie asynchronous action failed (response body omitted)"
            );
            assert!(!failure.retry);
            server.abort();
        }
    }

    fn lifecycle(event: AlertEventType) -> Alert {
        let mut alert = Alert::test_alert();
        alert.event_type = event;
        alert.mitigation_id = Some("stable-mitigation".into());
        alert
    }

    #[tokio::test]
    async fn lifecycle_actions_trust_the_202_without_polling() {
        // An alert an operator already closed by hand still answers the close
        // with 202; only its request status would report failure. The mock
        // answers any further call with 404, so a poll would fail the send.
        for event in [
            AlertEventType::MitigationCreated,
            AlertEventType::MitigationWithdrawn,
            AlertEventType::MitigationExpired,
        ] {
            let (base, calls, server) = mock(vec![accepted("already-closed")]).await;
            send_to(&reqwest::Client::new(), "secret", &base, &lifecycle(event))
                .await
                .unwrap();
            let calls = calls.lock().await;
            assert_eq!(calls.len(), 1, "{event}: {calls:?}");
            assert!(!calls[0].0.contains("/requests/"));
            server.abort();
        }
    }

    #[tokio::test]
    async fn lifecycle_rejections_retry_only_when_transient() {
        for (status, retry) in [
            (404, false),
            (422, false),
            (200, false),
            (429, true),
            (503, true),
        ] {
            let (base, calls, server) = mock(vec![(status, "secret-canary".into())]).await;
            let failure = send_to(
                &reqwest::Client::new(),
                "secret",
                &base,
                &lifecycle(AlertEventType::MitigationWithdrawn),
            )
            .await
            .unwrap_err();
            assert_eq!(failure.retry, retry, "{status}: {}", failure.error);
            assert!(!failure.error.contains("secret-canary"));
            assert!(calls.lock().await[0].0.contains("/stable-mitigation/close"));
            server.abort();
        }
    }

    #[tokio::test]
    async fn hung_request_is_a_retryable_request_failure_not_a_confirmation_timeout() {
        // Accept connections and never answer.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(200))
            .build()
            .unwrap();
        let failure = send_to(&client, "secret", &base, &Alert::test_alert())
            .await
            .unwrap_err();
        assert!(
            failure.error.starts_with("opsgenie request failed: "),
            "{}",
            failure.error
        );
        assert!(!failure.error.contains(&base), "{}", failure.error);
        assert!(failure.retry);
        server.abort();
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
            .unwrap_err()
            .error;
            assert!(!error.contains("secret-canary"));
            assert!(error.len() < 100);
            server.abort();
        }
    }

    #[tokio::test]
    async fn pending_request_times_out_without_attempting_close() {
        let (base, calls, server) = mock(vec![accepted("pending")]).await;
        let failure = send_to(
            &reqwest::Client::new(),
            "secret",
            &base,
            &Alert::test_alert(),
        )
        .await
        .unwrap_err();
        assert_eq!(failure.error, "opsgenie create confirmation timed out");
        assert!(failure.retry);
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
