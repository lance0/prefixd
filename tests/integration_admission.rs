#![forbid(unsafe_code)]

mod common;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use tower::ServiceExt;

#[tokio::test]
async fn postgres_preview_deadline_releases_lifecycle_lock_while_safety_read_is_blocked() {
    let ctx = common::TestContext::new().await;
    let app = ctx.router().await;
    let mut held = ctx.pool.begin().await.unwrap();
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *held)
        .await
        .unwrap();
    sqlx::query("LOCK TABLE mitigations IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *held)
        .await
        .unwrap();

    let running = tokio::spawn(async move {
        app.oneshot(
            Request::post("/v1/mitigations/preview")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"victim_ip":"203.0.113.10","protocol":"udp","dst_ports":[53],"action":"discard","ttl_seconds":300,"reason":"inspect admission"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap()
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)) AND query LIKE '%FROM mitigations WHERE%status IN%')",
            )
            .bind(blocker)
            .fetch_one(&ctx.pool)
            .await
            .unwrap();
            if waiting {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("preview must demonstrably wait on the held table lock after preparation");
    assert!(ctx.state.mitigation_lock.try_lock().is_err());

    let response = tokio::time::timeout(std::time::Duration::from_secs(7), running)
        .await
        .expect("preview must return while the database blocker remains held")
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let result: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    assert_eq!(result["outcome"], "unavailable");
    assert_eq!(result["failed_check"], "timeout");
    assert_eq!(result["speaker_state"], "unobserved");
    assert_eq!(
        result["candidate"]["scope"]["dst_prefix"],
        "203.0.113.10/32"
    );
    assert_eq!(
        result["candidate"]["scope"]["dst_ports"],
        serde_json::json!([53])
    );
    assert!(result["reason"].as_str().unwrap().contains("timed out"));
    assert!(
        ctx.state.mitigation_lock.try_lock().is_ok(),
        "the lifecycle lock must release before the database blocker"
    );
    held.rollback().await.unwrap();

    for table in ["mitigations", "audit_log", "events", "withdrawal_requests"] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&ctx.pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "preview unexpectedly changed {table}");
    }
}
