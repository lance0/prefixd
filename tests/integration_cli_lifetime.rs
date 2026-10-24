#![forbid(unsafe_code)]

use axum::{
    Json, Router,
    http::{HeaderMap, StatusCode},
    routing::post,
};

#[tokio::test]
async fn cli_extends_with_authenticated_request_and_reports_saved_noop_and_refused_outcomes() {
    let id = "7f72a903-63d1-4a4a-a5db-0517e0a7df1d";
    let previous = "2026-10-24T12:05:00Z";
    let extended_expiry = "2026-10-24T12:10:00Z";
    for (status, extended, error) in [
        (StatusCode::OK, true, None),
        (StatusCode::OK, false, None),
        (StatusCode::FORBIDDEN, false, Some("Operator role required")),
        (StatusCode::CONFLICT, false, Some("withdrawal pending")),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            false,
            Some("current TTL policy refuses longer exposure"),
        ),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            false,
            Some("refresh mitigation and audit before retrying"),
        ),
    ] {
        let saved = if extended { extended_expiry } else { previous };
        let response = match error {
            Some(error) => serde_json::json!({ "error": error }),
            None => serde_json::json!({
                "extended": extended,
                "previous_expires_at": previous,
                "mitigation": {
                    "mitigation_id": id, "status": "active", "customer_id": "owner",
                    "victim_ip": "203.0.113.10", "vector": "udp_flood",
                    "action_type": "discard", "rate_bps": null,
                    "created_at": "2026-10-24T12:00:00Z", "expires_at": saved,
                    "scope_hash": "exact-saved-rule"
                }
            }),
        };
        let (sent, mut requests) = tokio::sync::mpsc::unbounded_channel();
        let app = Router::new().route(
            &format!("/v1/mitigations/{id}/extend"),
            post(
                move |headers: HeaderMap, Json(body): Json<serde_json::Value>| {
                    let response = response.clone();
                    let sent = sent.clone();
                    async move {
                        sent.send((headers, body)).unwrap();
                        (status, Json(response))
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        for format in ["table", "json"] {
            let output = tokio::time::timeout(
                std::time::Duration::from_secs(15),
                tokio::process::Command::new(env!("CARGO_BIN_EXE_prefixdctl"))
                    .args([
                        "--api",
                        &api,
                        "--token",
                        "extension-test-token",
                        "--format",
                        format,
                        "mitigations",
                        "extend",
                        id,
                        "--ttl-seconds",
                        "600",
                        "--reason",
                        "attack continues",
                    ])
                    .stdin(std::process::Stdio::null())
                    .kill_on_drop(true)
                    .output(),
            )
            .await
            .unwrap()
            .unwrap();
            let (headers, body) = requests.try_recv().unwrap();
            assert_eq!(headers["authorization"], "Bearer extension-test-token");
            assert_eq!(
                body,
                serde_json::json!({ "ttl_seconds": 600, "reason": "attack continues" })
            );
            let stdout = String::from_utf8(output.stdout).unwrap();
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert_eq!(output.status.success(), status.is_success(), "{stderr}");
            if let Some(error) = error {
                assert!(stdout.is_empty(), "{stdout}");
                assert!(stderr.contains(&status.as_u16().to_string()), "{stderr}");
                assert!(stderr.contains(error), "{stderr}");
            } else if format == "json" {
                let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
                assert_eq!(json["extended"], extended);
                assert_eq!(json["previous_expires_at"], previous);
                assert_eq!(json["mitigation"]["mitigation_id"], id);
                assert_eq!(json["mitigation"]["expires_at"], saved);
            } else {
                assert!(stdout.contains(if extended { "extended" } else { "unchanged" }));
                assert!(stdout.contains(id));
                assert!(stdout.contains(&format!("Previous expiry: {previous}")));
                assert!(stdout.contains(&format!("Saved expiry:    {saved}")));
            }
        }
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }
}
