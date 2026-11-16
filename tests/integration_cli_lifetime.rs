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

/// Help names the API, token and cookie variables but never prints their
/// values; reqwest sends URL userinfo in `PREFIXD_API` as Basic auth.
#[test]
fn cli_help_hides_credential_environment_values() {
    const SENTINEL: &str = "hunter2-help-canary";
    const TOKEN: &str = "prefixd_helpcanarytokenAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    for flag in ["--help", "-h", "help"] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_prefixdctl"))
            .arg(flag)
            .env(
                "PREFIXD_API",
                format!("http://operator:{SENTINEL}@127.0.0.1:8080"),
            )
            .env("PREFIXD_TOKEN", TOKEN)
            .env("PREFIXD_API_TOKEN", SENTINEL)
            .env("PREFIXD_SESSION_COOKIE", SENTINEL)
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(output.status.success(), "{flag}");
        for name in ["PREFIXD_API", "PREFIXD_TOKEN", "PREFIXD_SESSION_COOKIE"] {
            assert!(stdout.contains(name), "{flag}: {stdout}");
        }
        for secret in [SENTINEL, TOKEN] {
            assert!(!stdout.contains(secret), "{flag}: {stdout}");
            assert!(!stderr.contains(secret), "{flag}: {stderr}");
        }
    }
    for subcommand in [["tokens", "--help"], ["tokens", "create"]] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_prefixdctl"))
            .args(subcommand)
            .args(if subcommand[1] == "create" {
                &["--help"][..]
            } else {
                &[][..]
            })
            .env("PREFIXD_TOKEN", TOKEN)
            .output()
            .unwrap();
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.status.success(), "{combined}");
        assert!(!combined.contains(TOKEN), "{combined}");
    }
}

/// A token and a session cookie together are a usage error before any request,
/// from flags or the environment. Only the old variable set warns by name.
#[test]
fn cli_refuses_two_credentials_and_warns_about_the_old_variable() {
    const TOKEN: &str = "prefixd_twocredentialscanaryAAAAAAAAAAAAAAAAAAAAAAA";
    const COOKIE: &str = "id=two-credentials-cookie-canary";
    // Nothing listens on port 1; a request would fail with "request failed".
    let run = |args: &[&str], env: &[(&str, &str)]| {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_prefixdctl"));
        command
            .args(["--api", "http://127.0.0.1:1"])
            .args(args)
            .env_remove("PREFIXD_TOKEN")
            .env_remove("PREFIXD_API_TOKEN")
            .env_remove("PREFIXD_SESSION_COOKIE");
        for (name, value) in env {
            command.env(name, value);
        }
        let output = command.output().unwrap();
        (
            output.status.code(),
            String::from_utf8(output.stderr).unwrap(),
        )
    };
    type Case<'a> = (&'a [&'a str], &'a [(&'a str, &'a str)]);
    let cases: [Case; 3] = [
        (
            &["--token", TOKEN, "--session-cookie", COOKIE, "status"],
            &[],
        ),
        (
            &["status"],
            &[("PREFIXD_TOKEN", TOKEN), ("PREFIXD_SESSION_COOKIE", COOKIE)],
        ),
        (
            &["--session-cookie", COOKIE, "status"],
            &[("PREFIXD_TOKEN", TOKEN)],
        ),
    ];
    for (args, env) in cases {
        let (code, stderr) = run(args, env);
        assert_eq!(code, Some(2), "{args:?}: {stderr}");
        assert!(stderr.contains("not both"), "{stderr}");
        assert!(!stderr.contains("request failed"), "{stderr}");
        assert!(
            !stderr.contains(TOKEN) && !stderr.contains(COOKIE),
            "{stderr}"
        );
    }
    // A token with URL userinfo would send two Authorization headers.
    for (args, env) in [
        (
            vec!["--api", "http://operator:secret@127.0.0.1:1", "status"],
            vec![("PREFIXD_TOKEN", TOKEN)],
        ),
        (
            vec!["--token", TOKEN, "status"],
            vec![("PREFIXD_API", "http://operator@127.0.0.1:1")],
        ),
    ] {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_prefixdctl"));
        command
            .args(&args)
            .env_remove("PREFIXD_TOKEN")
            .env_remove("PREFIXD_API_TOKEN")
            .env_remove("PREFIXD_SESSION_COOKIE")
            .env_remove("PREFIXD_API");
        for (name, value) in &env {
            command.env(name, value);
        }
        let output = command.output().unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(output.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(
            stderr.contains("cannot be combined with user:password"),
            "{stderr}"
        );
        assert!(!stderr.contains("request failed"), "{stderr}");
        assert!(
            !stderr.contains(TOKEN) && !stderr.contains("secret"),
            "{stderr}"
        );
    }
    // A malformed duration is a usage error, never a panic.
    let (code, stderr) = run(
        &[
            "tokens",
            "create",
            "--name",
            "x",
            "--scope",
            "admin",
            "--expires-in",
            "5µ",
        ],
        &[],
    );
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("invalid duration"), "{stderr}");
    // A duration that parses but would overflow the expiry timestamp.
    let (code, stderr) = run(
        &[
            "tokens",
            "create",
            "--name",
            "x",
            "--scope",
            "admin",
            "--expires-in",
            "100000000000000s",
        ],
        &[],
    );
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("at most 36525d"), "{stderr}");
    // Control: one credential reaches the request.
    let (code, stderr) = run(&["status"], &[("PREFIXD_TOKEN", TOKEN)]);
    assert_eq!(code, Some(1), "{stderr}");
    assert!(stderr.contains("request failed"), "{stderr}");
    assert!(!stderr.contains("no longer read"), "{stderr}");

    let (_, stderr) = run(&["status"], &[("PREFIXD_API_TOKEN", TOKEN)]);
    assert!(
        stderr.contains("PREFIXD_API_TOKEN is set but no longer read"),
        "{stderr}"
    );
    assert!(!stderr.contains(TOKEN), "{stderr}");
    // Both set: the new variable is read and nothing warns.
    let (_, stderr) = run(
        &["status"],
        &[("PREFIXD_API_TOKEN", TOKEN), ("PREFIXD_TOKEN", TOKEN)],
    );
    assert!(!stderr.contains("no longer read"), "{stderr}");
}
