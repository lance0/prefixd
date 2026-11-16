//! Each stored event records what ingestion did with it, and every refusal is
//! audited, including refusals before storage that leave no event row.
mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use prefixd::{
    AppState,
    api::create_test_router,
    bgp::MockAnnouncer,
    config::OperationMode,
    db::{ListParams, MockRepository, RepositoryTrait},
    domain::{AttackEvent, AttackEventInput, EventOutcome},
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

fn state(mode: OperationMode) -> (Arc<AppState>, Arc<MockRepository>) {
    let repo = Arc::new(MockRepository::new());
    let mut settings = common::test_settings();
    settings.mode = mode;
    let state = AppState::new(
        settings,
        common::test_inventory(),
        common::test_playbooks(),
        repo.clone(),
        Arc::new(MockAnnouncer::new()),
        ".".into(),
    )
    .unwrap();
    (state, repo)
}

fn event(id: &str, victim: &str, vector: &str) -> Value {
    json!({
        "event_id": id, "timestamp": "2026-11-14T00:00:00Z", "source": "outcome-test",
        "victim_ip": victim, "vector": vector, "bps": 1_000_000_000, "pps": 100_000,
        "top_dst_ports": [53], "confidence": 0.95,
    })
}

async fn send(
    state: &Arc<AppState>,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
        .unwrap();
    let response = create_test_router(state.clone())
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn post(state: &Arc<AppState>, body: Value) -> (StatusCode, Value) {
    send(state, "POST", "/v1/events", Some(body)).await
}

/// The listed event for a detector event ID.
async fn listed(state: &Arc<AppState>, external: &str) -> Value {
    let (status, body) = send(state, "GET", "/v1/events?limit=100", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["external_event_id"] == external)
        .cloned()
        .unwrap_or_else(|| panic!("no event {external}: {body}"))
}

async fn rejections(repo: &MockRepository) -> Vec<Value> {
    let params = ListParams {
        limit: 100,
        ..Default::default()
    };
    repo.list_audit(&params)
        .await
        .unwrap()
        .into_iter()
        .filter(|entry| entry.action == "reject")
        .map(|entry| serde_json::to_value(entry).unwrap())
        .collect()
}

/// The fields an event had before outcomes were recorded.
fn without_outcome(mut event: Value) -> Value {
    let fields = event.as_object_mut().unwrap();
    for key in ["event_id", "external_event_id", "ingested_at"] {
        fields.remove(key);
    }
    for key in ["outcome", "outcome_reason", "outcome_mitigation_ids"] {
        fields.remove(key);
    }
    event
}

#[tokio::test]
async fn refused_event_is_distinguishable_from_a_mitigated_one_and_audited() {
    let (state, repo) = state(OperationMode::Enforced);
    let (status, mitigated) = post(&state, event("mitigated", "203.0.113.10", "udp_flood")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{mitigated}");
    repo.insert_safelist("203.0.113.11/32", "test", None)
        .await
        .unwrap();
    let (status, refused) = post(&state, event("refused", "203.0.113.11", "udp_flood")).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{refused}");

    let mitigated_row = listed(&state, "mitigated").await;
    let refused_row = listed(&state, "refused").await;
    // Negative control: without the outcome fields, as on earlier controllers,
    // the refused event's row is indistinguishable from the mitigated one.
    let mut control = without_outcome(refused_row.clone());
    control["victim_ip"] = mitigated_row["victim_ip"].clone();
    assert_eq!(control, without_outcome(mitigated_row.clone()));

    assert_eq!(mitigated_row["outcome"], "mitigated");
    assert_eq!(
        mitigated_row["outcome_mitigation_ids"],
        json!([mitigated["mitigation_id"]])
    );
    assert_eq!(mitigated_row["outcome_reason"], Value::Null);
    assert_eq!(refused_row["outcome"], "safelisted");
    assert_eq!(refused_row["outcome_reason"], refused["error"]);
    assert_eq!(refused_row["outcome_mitigation_ids"], json!([]));

    let audit = rejections(&repo).await;
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert_eq!(audit[0]["target_type"], "event");
    assert_eq!(audit[0]["target_id"], refused_row["event_id"]);
    // Auth mode none: the anonymous Admin claimed the source.
    assert_eq!(audit[0]["actor_type"], "operator");
    assert_eq!(audit[0]["actor_id"], "anonymous");
    assert_eq!(audit[0]["details"]["source"], "outcome-test");
    let details = &audit[0]["details"];
    assert_eq!(details["outcome"], "safelisted");
    assert_eq!(details["guardrail"], "Safelisted");
    assert_eq!(details["stored"], true);
    assert_eq!(details["external_event_id"], "refused");
    assert_eq!(details["reason"], refused["error"]);
    assert!(
        details["reason"]
            .as_str()
            .unwrap()
            .contains("203.0.113.11/32 is safelisted")
    );
}

#[tokio::test]
async fn each_handled_outcome_is_recorded_once() {
    let (state, repo) = state(OperationMode::Enforced);
    let (_, first) = post(&state, event("first", "203.0.113.10", "udp_flood")).await;
    let (status, _) = post(&state, event("again", "203.0.113.10", "udp_flood")).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (status, _) = post(&state, event("unowned", "198.51.100.1", "udp_flood")).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (status, body) = post(&state, event("no-playbook", "203.0.113.10", "icmp_flood")).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(body["status"], "accepted_no_playbook");

    let extended = listed(&state, "again").await;
    assert_eq!(extended["outcome"], "extended");
    assert_eq!(
        extended["outcome_mitigation_ids"],
        json!([first["mitigation_id"]])
    );
    let unowned = listed(&state, "unowned").await;
    assert_eq!(unowned["outcome"], "not_owned");
    assert_eq!(
        unowned["outcome_reason"],
        "destination is not in the inventory"
    );
    let no_playbook = listed(&state, "no-playbook").await;
    assert_eq!(no_playbook["outcome"], "no_playbook");
    assert!(
        no_playbook["outcome_reason"]
            .as_str()
            .unwrap()
            .contains("icmp_flood")
    );

    // A detector unban records the withdrawal on its own event.
    let mut unban = event("first", "203.0.113.10", "udp_flood");
    unban["action"] = "unban".into();
    let (status, body) = post(&state, unban).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let (_, list) = send(&state, "GET", "/v1/events?outcome=withdrawn", None).await;
    assert_eq!(list["count"], 1, "{list}");
    assert_eq!(list["events"][0]["event_id"], body["event_id"]);
    assert_eq!(list["events"][0]["action"], "unban");
    assert_eq!(
        list["events"][0]["outcome_mitigation_ids"],
        json!([first["mitigation_id"]])
    );

    // Written once: a later outcome never replaces a recorded one.
    let id = listed(&state, "unowned").await["event_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    repo.record_event_outcome(
        id,
        &prefixd::domain::EventOutcomeRecord::new(EventOutcome::Mitigated, None, Vec::new()),
    )
    .await
    .unwrap();
    assert_eq!(listed(&state, "unowned").await["outcome"], "not_owned");
    assert!(rejections(&repo).await.is_empty());
}

#[tokio::test]
async fn dry_run_and_quota_refusals_are_recorded() {
    let (state, repo) = state(OperationMode::DryRun);
    let (status, body) = post(&state, event("simulated", "203.0.113.10", "udp_flood")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let simulated = listed(&state, "simulated").await;
    assert_eq!(simulated["outcome"], "dry_run");
    assert_eq!(
        simulated["outcome_mitigation_ids"],
        json!([body["mitigation_id"]])
    );

    let (state, repo_full) = {
        let repo = Arc::new(MockRepository::new());
        let mut settings = common::test_settings();
        settings.mode = OperationMode::Enforced;
        settings.quotas.max_active_per_customer = 1;
        let state = AppState::new(
            settings,
            common::test_inventory(),
            common::test_playbooks(),
            repo.clone(),
            Arc::new(MockAnnouncer::new()),
            ".".into(),
        )
        .unwrap();
        (state, repo)
    };
    let (status, _) = post(&state, event("one", "203.0.113.10", "udp_flood")).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (status, refused) = post(&state, event("two", "203.0.113.11", "udp_flood")).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{refused}");
    let row = listed(&state, "two").await;
    assert_eq!(row["outcome"], "guardrail_rejected");
    // The reason names the quota so the operator knows what to change.
    assert!(
        row["outcome_reason"]
            .as_str()
            .unwrap()
            .contains("quota exceeded: customer"),
        "{row}"
    );
    let audit = rejections(&repo_full).await;
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert_eq!(audit[0]["details"]["guardrail"], "QuotaExceeded");
    assert!(rejections(&repo).await.is_empty());
}

#[tokio::test]
async fn refusal_before_storage_is_audited_and_the_event_stays_retryable() {
    let (state, repo) = state(OperationMode::Enforced);
    let prefix = || event("carpet", "203.0.113.0/24", "udp_flood");
    let (status, body) = post(&state, prefix()).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    let (_, list) = send(&state, "GET", "/v1/events", None).await;
    assert_eq!(list["count"], 0, "no event row before admission: {list}");

    let audit = rejections(&repo).await;
    assert_eq!(audit.len(), 1, "{audit:?}");
    let details = &audit[0]["details"];
    assert_eq!(details["stored"], false);
    assert_eq!(details["outcome"], "guardrail_rejected");
    assert_eq!(details["guardrail"], "DetectorPrefixNotAllowed");
    assert_eq!(details["victim_ip"], "203.0.113.0/24");
    assert_eq!(details["external_event_id"], "carpet");
    assert!(
        details["reason"]
            .as_str()
            .unwrap()
            .contains("guardrails.allow_detector_prefix=true")
    );

    // A malformed request is not a refusal and is not audited.
    let mut invalid = event("bad", "203.0.113.10", "udp_flood");
    invalid["confidence"] = json!(2.0);
    let (status, _) = post(&state, invalid).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // A duplicate is not a refusal either.
    let (status, _) = post(&state, event("dup", "203.0.113.10", "udp_flood")).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (status, _) = post(&state, event("dup", "203.0.113.10", "udp_flood")).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(rejections(&repo).await.len(), 1);
}

#[tokio::test]
async fn outcome_filter_is_server_side_and_reports_unrecorded_events() {
    let (state, repo) = state(OperationMode::Enforced);
    // An event stored before outcomes were recorded.
    let legacy: AttackEventInput =
        serde_json::from_value(event("legacy", "203.0.113.10", "udp_flood")).unwrap();
    repo.insert_event(&AttackEvent::from_input(legacy))
        .await
        .unwrap();
    post(&state, event("ok", "203.0.113.10", "udp_flood")).await;
    post(&state, event("unowned", "198.51.100.1", "udp_flood")).await;

    let ids = |body: &Value| -> Vec<String> {
        body["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event["external_event_id"].as_str().unwrap().to_string())
            .collect()
    };
    let (status, body) = send(&state, "GET", "/v1/events?outcome=not_recorded", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(ids(&body), ["legacy"]);
    assert_eq!(body["events"][0]["outcome"], "not_recorded");
    assert_eq!(body["events"][0]["outcome_mitigation_ids"], json!([]));
    let (_, body) = send(
        &state,
        "GET",
        "/v1/events?outcome=mitigated,not_owned",
        None,
    )
    .await;
    assert_eq!(ids(&body), ["unowned", "ok"]);
    let (_, body) = send(&state, "GET", "/v1/events?outcome=safelisted", None).await;
    assert_eq!(body["count"], 0);

    for bad in ["", "mitigated,", "Mitigated", "refused"] {
        let (status, body) = send(&state, "GET", &format!("/v1/events?outcome={bad}"), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
        assert!(body["error"].as_str().unwrap().contains("not_recorded"));
    }
}

#[tokio::test]
async fn batch_items_record_their_own_outcomes() {
    let (state, repo) = state(OperationMode::Enforced);
    repo.insert_safelist("203.0.113.11/32", "test", None)
        .await
        .unwrap();
    let (status, body) = send(
        &state,
        "POST",
        "/v1/events/batch",
        Some(json!({"events": [
            event("batch-ok", "203.0.113.10", "udp_flood"),
            event("batch-safe", "203.0.113.11", "udp_flood"),
        ]})),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS, "{body}");
    assert_eq!(listed(&state, "batch-ok").await["outcome"], "mitigated");
    assert_eq!(listed(&state, "batch-safe").await["outcome"], "safelisted");
    assert_eq!(rejections(&repo).await.len(), 1);
}

#[tokio::test]
async fn refused_unban_records_a_conflict_and_is_audited() {
    let (state, repo) = state(OperationMode::Enforced);
    let (_, ban) = post(&state, event("foreign", "203.0.113.10", "udp_flood")).await;
    let id = ban["mitigation_id"].as_str().unwrap().parse().unwrap();
    // A second live owner of the same rule, created later, makes withdrawing
    // the first a conflict.
    let mut owner = repo.get_mitigation(id).await.unwrap().unwrap();
    owner.mitigation_id = uuid::Uuid::new_v4();
    owner.created_at += chrono::Duration::seconds(1);
    repo.insert_mitigation(&owner).await.unwrap();

    let mut unban = event("foreign", "203.0.113.10", "udp_flood");
    unban["action"] = "unban".into();
    let (status, body) = post(&state, unban).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let (_, list) = send(&state, "GET", "/v1/events?outcome=conflict", None).await;
    assert_eq!(list["count"], 1, "{list}");
    let row = &list["events"][0];
    assert_eq!(row["action"], "unban");
    assert_eq!(row["outcome_reason"], body["error"]);
    let audit = rejections(&repo).await;
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert_eq!(audit[0]["target_id"], row["event_id"]);
    assert_eq!(audit[0]["details"]["outcome"], "conflict");
    assert_eq!(audit[0]["details"]["guardrail"], "Conflict");
    assert_eq!(audit[0]["details"]["stored"], true);
    // Only mitigations whose withdrawal intent was recorded are the unban's
    // targets; both were refused here, so none is linked or replayed.
    assert_eq!(row["outcome_mitigation_ids"], json!([]));
    assert!(repo.pending_withdrawals(None).await.unwrap().is_empty());
}

/// A prefix playbook whose step has rules cannot produce a narrow prefix match.
/// Load refuses it; the policy check behind it must record a refusal, not
/// `no_playbook`, even though the response stays `accepted_no_playbook`.
#[tokio::test]
async fn prefix_rules_refusal_after_storage_is_a_guardrail_refusal_and_audited() {
    use prefixd::config::{
        EventScope, Playbook, PlaybookAction, PlaybookMatch, PlaybookRule, PlaybookRuleMatch,
        PlaybookStep,
    };
    let repo = Arc::new(MockRepository::new());
    let mut settings = common::test_settings();
    settings.mode = OperationMode::Enforced;
    settings.guardrails.allow_detector_prefix = true;
    settings.guardrails.detector_prefix_sources = vec!["outcome-test".into()];
    settings.guardrails.dst_prefix_minlen = 24;
    let mut playbooks = common::test_playbooks();
    playbooks.playbooks.push(Playbook {
        name: "carpet_rules".into(),
        match_criteria: PlaybookMatch {
            vector: prefixd::domain::AttackVector::UdpFlood,
            require_top_ports: true,
            scope: EventScope::Prefix,
        },
        correlation: None,
        steps: vec![PlaybookStep {
            action: None,
            rate_bps: None,
            ttl_seconds: 120,
            require_confidence_at_least: None,
            require_persistence_seconds: None,
            rules: vec![PlaybookRule {
                match_criteria: PlaybookRuleMatch {
                    fragment: Some(prefixd::domain::FragmentMatch::NonFirst),
                    ..Default::default()
                },
                action: PlaybookAction::Police,
                rate_bps: Some(1_000_000),
            }],
        }],
    });
    let state = AppState::new(
        settings,
        common::test_inventory(),
        playbooks,
        repo.clone(),
        Arc::new(MockAnnouncer::new()),
        ".".into(),
    )
    .unwrap();
    let (status, body) = post(&state, event("carpet", "203.0.113.0/24", "udp_flood")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "accepted_no_playbook");
    let row = listed(&state, "carpet").await;
    assert_eq!(row["outcome"], "guardrail_rejected", "{row}");
    assert!(
        row["outcome_reason"]
            .as_str()
            .unwrap()
            .contains("prefix rules require a protocol and at least one destination port")
    );
    let audit = rejections(&repo).await;
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert_eq!(audit[0]["target_id"], row["event_id"]);
    assert_eq!(audit[0]["details"]["guardrail"], "PrefixMatchRequiresPorts");
    assert_eq!(audit[0]["details"]["stored"], true);
}

#[tokio::test]
async fn corroboration_not_met_is_recorded() {
    let repo = Arc::new(MockRepository::new());
    let mut settings = common::test_settings();
    settings.mode = OperationMode::Enforced;
    settings.correlation.enabled = true;
    settings.correlation.min_sources = 2;
    let state = AppState::new(
        settings,
        common::test_inventory(),
        common::test_playbooks(),
        repo.clone(),
        Arc::new(MockAnnouncer::new()),
        ".".into(),
    )
    .unwrap();
    let (status, body) = post(&state, event("lonely", "203.0.113.10", "udp_flood")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "accepted");
    assert_eq!(body["mitigation_id"], Value::Null);
    let row = listed(&state, "lonely").await;
    assert_eq!(row["outcome"], "awaiting_corroboration");
    assert!(
        row["outcome_reason"]
            .as_str()
            .unwrap()
            .starts_with("corroboration not met: 1 source(s)")
    );
    assert!(rejections(&repo).await.is_empty());
}

#[tokio::test]
async fn server_error_after_storage_is_failed_and_summarized() {
    let (mut state, repo) = state(OperationMode::Enforced);
    // Leased FlowSpec without the controller's lease fails admission with a
    // server-side configuration error after the event is stored.
    Arc::get_mut(&mut state).unwrap().settings.bgp.rustbgpd =
        Some(prefixd::config::RustBgpdConfig {
            leased_flowspec: true,
            ..Default::default()
        });
    let (status, body) = post(&state, event("broken", "203.0.113.10", "udp_flood")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    let row = listed(&state, "broken").await;
    assert_eq!(row["outcome"], "failed");
    assert_eq!(
        row["outcome_reason"],
        "500 Internal Server Error; see controller logs"
    );
    assert!(!row.to_string().contains("injection lease"));
    assert!(rejections(&repo).await.is_empty());
}

#[tokio::test]
async fn fastnetmon_adapter_events_record_outcomes() {
    let (state, repo) = state(OperationMode::Enforced);
    repo.insert_safelist("203.0.113.11/32", "test", None)
        .await
        .unwrap();
    let fastnetmon = |ip: &str, uuid: &str| {
        json!({
            "action": "ban", "ip": ip, "alert_scope": "host",
            "attack_details": {
                "attack_uuid": uuid, "attack_severity": "high",
                "attack_detection_source": "automatic", "attack_direction": "incoming",
                "attack_protocol": "udp", "host_network": "203.0.113.0/24",
                "incoming_udp_pps": 50000, "incoming_udp_traffic_bits": 500000000,
                "total_incoming_pps": 50000, "total_incoming_traffic_bits": 500000000,
            }
        })
    };
    for (ip, uuid) in [("203.0.113.10", "fnm-ok"), ("203.0.113.11", "fnm-safe")] {
        let (status, body) = send(
            &state,
            "POST",
            "/v1/signals/fastnetmon",
            Some(fastnetmon(ip, uuid)),
        )
        .await;
        assert!(
            status.is_success() || status.is_client_error(),
            "{status}: {body}"
        );
    }
    let (_, list) = send(&state, "GET", "/v1/events", None).await;
    let outcome = |uuid: &str| {
        list["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event["external_event_id"] == uuid)
            .map(|event| event["outcome"].clone())
            .unwrap_or_else(|| panic!("no event {uuid}: {list}"))
    };
    assert_eq!(outcome("fnm-ok"), "mitigated");
    assert_eq!(outcome("fnm-safe"), "safelisted");
    assert_eq!(rejections(&repo).await.len(), 1);
}
