//! Real PostgreSQL, released adapters and local/received RIBs; logical controller reconstruction.
//! No OS-process-kill, router forwarding or seamless-cutover claim.
#![cfg(all(feature = "bgp-rustbgpd", feature = "test-utils", target_os = "linux"))]
mod common;
#[allow(
    dead_code,
    reason = "the cutover target reuses only inventory and peer-state contract helpers"
)]
#[path = "common/speaker_contract.rs"]
mod contract;
#[path = "common/peer_receipt.rs"]
mod peer_receipt;
#[path = "common/rustbgpd.rs"]
mod rustbgpd;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use chrono::{DateTime, Utc};
use common::gobgp;
use futures_util::FutureExt;
use prefixd::{
    AppState,
    bgp::{
        FlowSpecAnnouncer, FlowSpecReader, FlowSpecWriter, PeerObserver, PeerStatus,
        apipb as go_api,
    },
    config::{AuthMode, BgpMode, OperationMode, Settings},
    db::{Repository, RepositoryTrait},
    domain::{
        ActionParams, ActionType, FlowSpecAction, FlowSpecNlri, FlowSpecRule, MatchCriteria,
        Mitigation, MitigationStatus, SpeakerTarget, mitigation_rule,
    },
    error::{PrefixdError, Result},
    scheduler::ReconciliationLoop,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    panic::AssertUnwindSafe,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
    },
    time::Duration,
};
use tower::ServiceExt;
use uuid::Uuid;

const POP: &str = "test-pop";
const MIN_TTL: i64 = 30;

/// Faults lose a successful daemon reply, never replace the real speaker/RIB.
struct UncertainSpeaker {
    inner: Arc<dyn FlowSpecAnnouncer>,
    lose_add: AtomicBool,
    lose_delete: AtomicBool,
    adds: AtomicUsize,
    deletes: AtomicUsize,
}

impl UncertainSpeaker {
    fn new(inner: Arc<dyn FlowSpecAnnouncer>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            lose_add: AtomicBool::new(false),
            lose_delete: AtomicBool::new(false),
            adds: AtomicUsize::new(0),
            deletes: AtomicUsize::new(0),
        })
    }
    fn calls(&self) -> (usize, usize) {
        (self.adds.load(SeqCst), self.deletes.load(SeqCst))
    }
}

impl FlowSpecAnnouncer for UncertainSpeaker {
    fn backend(&self) -> &'static str {
        self.inner.backend()
    }
    fn reader(&self) -> Option<&dyn FlowSpecReader> {
        Some(self)
    }
    fn peer_observer(&self) -> Option<&dyn PeerObserver> {
        Some(self)
    }
}
#[async_trait::async_trait]
impl FlowSpecWriter for UncertainSpeaker {
    async fn announce(&self, rule: &FlowSpecRule) -> Result<()> {
        self.adds.fetch_add(1, SeqCst);
        self.inner.announce(rule).await?;
        if self.lose_add.swap(false, SeqCst) {
            return Err(PrefixdError::BgpAnnouncementFailed(
                "fixture lost successful Add reply".into(),
            ));
        }
        Ok(())
    }
    async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()> {
        self.deletes.fetch_add(1, SeqCst);
        self.inner.withdraw(rule).await?;
        if self.lose_delete.swap(false, SeqCst) {
            return Err(PrefixdError::BgpAnnouncementFailed(
                "fixture lost successful Delete reply".into(),
            ));
        }
        Ok(())
    }
}
#[async_trait::async_trait]
impl FlowSpecReader for UncertainSpeaker {
    async fn list_active(&self) -> Result<Vec<FlowSpecRule>> {
        self.inner.reader().unwrap().list_active().await
    }
}
#[async_trait::async_trait]
impl PeerObserver for UncertainSpeaker {
    async fn session_status(&self) -> Result<Vec<PeerStatus>> {
        self.inner.peer_observer().unwrap().session_status().await
    }
}

struct Controller {
    state: Arc<AppState>,
    app: Router,
    speaker: Arc<UncertainSpeaker>,
    target_id: Uuid,
}

impl Controller {
    async fn start(pool: &PgPool, settings: Settings, speaker: Arc<UncertainSpeaker>) -> Self {
        let repo: Arc<dyn RepositoryTrait> = Arc::new(Repository::new(pool.clone()));
        let target = SpeakerTarget::from_config(&settings.bgp).unwrap();
        let binding = repo
            .register_speaker_target(POP, &target, false)
            .await
            .unwrap();
        let target_id = binding.target_id();
        let state = AppState::new(
            settings,
            common::test_inventory(),
            common::test_playbooks(),
            repo,
            speaker.clone(),
            ".".into(),
        )
        .unwrap()
        .with_speaker_binding(binding)
        .unwrap();
        let app = prefixd::api::create_test_router(state.clone());
        Self {
            state,
            app,
            speaker,
            target_id,
        }
    }
    async fn post(&self, path: &str, body: Value) -> axum::response::Response {
        let token = std::env::var("PREFIXD_RUSTBGPD_TEST_TOKEN").unwrap();
        self.app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }
    async fn reconcile(&self) {
        ReconciliationLoop::new(self.state.repo.clone(), self.speaker.clone(), 30, false)
            .with_app_state(self.state.clone())
            .reconcile()
            .await
            .unwrap();
    }
    fn stop(self) {
        // This fixture has no background reconciler or listener; consuming all handles stops it.
        self.state.trigger_shutdown();
    }
}

fn settings(context: &common::TestContext) -> Settings {
    let mut settings = context.state.settings.clone();
    settings.mode = OperationMode::Enforced;
    settings.http.auth.mode = AuthMode::Bearer;
    settings.http.auth.bearer_token_env = Some("PREFIXD_RUSTBGPD_TEST_TOKEN".into());
    settings.guardrails.dst_prefix_minlen_v6 = Some(128);
    settings.guardrails.dst_prefix_maxlen_v6 = Some(128);
    settings
}

fn payload(rule: &FlowSpecRule, ttl: i64, reason: &str) -> Value {
    let net: ipnet::IpNet = rule.nlri.dst_prefix.parse().unwrap();
    let protocol = match rule.nlri.protocol {
        None => "any",
        Some(6) => "tcp",
        Some(17) => "udp",
        Some(1) => "icmp",
        _ => panic!("unrepresentable cutover protocol"),
    };
    assert_eq!(
        net.prefix_len(),
        if net.addr().is_ipv4() { 32 } else { 128 }
    );
    json!({ "victim_ip": net.addr().to_string(), "protocol": protocol,
        "dst_ports": rule.nlri.dst_ports, "action": rule.actions[0].action_type.as_str(),
        "rate_bps": rule.actions[0].rate_bps, "ttl_seconds": ttl, "reason": reason })
}

async fn response_json(response: axum::response::Response) -> Value {
    serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap()
}

fn owned_rules() -> Vec<FlowSpecRule> {
    [
        "203.0.113.80/32",
        "203.0.113.81/32",
        "2001:db8::80/128",
        "2001:db8::81/128",
    ]
    .into_iter()
    .enumerate()
    .map(|(index, prefix)| {
        FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: prefix.into(),
                protocol: Some(17),
                dst_ports: vec![53, 123],
            },
            if index % 2 == 0 {
                FlowSpecAction::discard()
            } else {
                FlowSpecAction::police(8_000_000)
            },
        )
    })
    .collect()
}

fn raw_go_prefix(path: &go_api::Path) -> String {
    let Some(go_api::nlri::Nlri::FlowSpec(nlri)) = &path.nlri.as_ref().unwrap().nlri else {
        panic!("expected raw FlowSpec NLRI");
    };
    let prefixes: Vec<_> = nlri
        .rules
        .iter()
        .filter_map(|rule| match &rule.rule {
            Some(go_api::flow_spec_rule::Rule::IpPrefix(prefix)) => Some(prefix),
            _ => None,
        })
        .collect();
    assert_eq!(prefixes.len(), 1);
    assert_eq!(prefixes[0].r#type, 1);
    format!("{}/{}", prefixes[0].prefix, prefixes[0].prefix_len)
}

fn raw_go_as_path(path: &go_api::Path) -> Vec<u32> {
    path.pattrs
        .iter()
        .filter_map(|attribute| match &attribute.attr {
            Some(go_api::attribute::Attr::AsPath(path)) => Some(path),
            _ => None,
        })
        .flat_map(|path| path.segments.iter())
        .flat_map(|segment| {
            assert_eq!(segment.r#type, go_api::as_segment::Type::AsSequence as i32);
            segment.numbers.iter().copied()
        })
        .collect()
}

async fn assert_go_provenance(go: &gobgp::Speaker, owned: &[FlowSpecRule], unknown: &FlowSpecRule) {
    let mut received = Vec::new();
    let mut accepted = Vec::new();
    for afi in [1, 2] {
        received.extend(go.paths(afi, go_api::TableType::AdjIn).await);
        accepted.extend(go.paths(afi, go_api::TableType::Global).await);
    }
    let reflected: Vec<_> = received
        .iter()
        .filter(|path| raw_go_prefix(path) == unknown.nlri.dst_prefix)
        .collect();
    assert_eq!(reflected.len(), 1);
    assert_eq!(reflected[0].neighbor_ip, go.peer_address);
    assert_eq!(raw_go_as_path(reflected[0]), [64512, 65010]);
    let local: Vec<_> = accepted
        .iter()
        .filter(|path| raw_go_prefix(path) == unknown.nlri.dst_prefix)
        .collect();
    assert_eq!(
        local.len(),
        1,
        "the bounced own-AS path must not enter Go's global RIB"
    );
    assert!(local[0].neighbor_ip.is_empty());
    assert!(raw_go_as_path(local[0]).is_empty());
    assert!(local[0].best);
    assert_eq!(accepted.len(), owned.len() + 1);
    for rule in owned {
        let paths: Vec<_> = accepted
            .iter()
            .filter(|path| raw_go_prefix(path) == rule.nlri.dst_prefix)
            .collect();
        assert_eq!(paths.len(), 1);
        assert!(paths[0].best && !paths[0].filtered && !paths[0].stale);
        assert_eq!(paths[0].neighbor_ip, go.peer_address);
        assert_eq!(raw_go_as_path(paths[0]), [64512]);
    }
}

/// The complete administrative snapshot is the source of recreated data, never API pages.
struct Snapshot {
    raw: Value,
    intents: Vec<SavedIntent>,
    target_id: Uuid,
}

#[derive(Clone, serde::Deserialize)]
struct SavedIntent {
    mitigation_id: Uuid,
    pop: String,
    status: MitigationStatus,
    expires_at: DateTime<Utc>,
    match_json: String,
    action_type: ActionType,
    action_params_json: Option<String>,
    reason: Option<String>,
}

impl SavedIntent {
    fn rule(&self) -> FlowSpecRule {
        let criteria: MatchCriteria = serde_json::from_str(&self.match_json).unwrap();
        let params: ActionParams = self
            .action_params_json
            .as_deref()
            .map(|json| serde_json::from_str(json).unwrap())
            .unwrap_or(ActionParams { rate_bps: None });
        FlowSpecRule::new(
            FlowSpecNlri::from(&criteria),
            FlowSpecAction::from((self.action_type, &params)),
        )
    }
}

impl Snapshot {
    fn pending_cancellation(&self, row: &SavedIntent) -> bool {
        self.raw["withdrawals"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|request| request["completed_at"].is_null())
            .any(|request| {
                let rule: FlowSpecRule =
                    serde_json::from_str(request["rule_json"].as_str().unwrap()).unwrap();
                request["mitigation_id"] == row.mitigation_id.to_string()
                    || canonical_key(&rule) == canonical_key(&row.rule())
            })
    }

    async fn capture(pool: &PgPool, directory: &Path, name: &str) -> Self {
        let guide = include_str!("../docs/how-to/speaker-cutover.md");
        let start = guide
            .find("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;")
            .unwrap();
        let block = &guide[start..];
        let end = block.find("COMMIT;").unwrap() + "COMMIT;".len();
        let sql = block[..end].replace(":'cutover_pop'", "'test-pop'");
        let rows = sqlx::raw_sql(&sql).fetch_all(pool).await.unwrap();
        assert_eq!(rows.len(), 1, "one complete repeatable-read snapshot");
        let raw: Value = rows[0].get(0);
        assert_eq!(raw["pop"], POP);
        let bytes = serde_json::to_vec(&raw).unwrap();
        let path = directory.join(format!("{name}.json"));
        let mut file = File::create(&path).unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
        let hash = hex::encode(Sha256::digest(&bytes));
        let mut checksum = File::create(directory.join(format!("{name}.sha256"))).unwrap();
        writeln!(checksum, "{hash}  {name}.json").unwrap();
        checksum.sync_all().unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(std::fs::read(path).unwrap())),
            hash
        );
        let target_id = raw["binding"]["target_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let intents = serde_json::from_value(raw["mitigations"].clone()).unwrap();
        Self {
            raw,
            intents,
            target_id,
        }
    }
}

fn canonical_key(rule: &FlowSpecRule) -> String {
    let mut nlri = rule.nlri.clone();
    nlri.dst_ports.sort_unstable();
    nlri.dst_ports.dedup();
    nlri.compute_hash()
}

fn journal(path: &Path, entry: Value) {
    // Reopen for every append so the retained journal is also usable after interruption.
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    serde_json::to_writer(&mut file, &entry).unwrap();
    writeln!(file).unwrap();
    file.sync_all().unwrap();
}

fn transfer_sql(old: Uuid, destination: &SpeakerTarget) -> String {
    include_str!("../docs/how-to/upgrading.md")
        .split("<!-- speaker-transfer-sql -->")
        .nth(1)
        .unwrap()
        .split("```sql\n")
        .nth(1)
        .unwrap()
        .split("```")
        .next()
        .unwrap()
        .replace("'iad1'", "'test-pop'")
        .replace("00000000-0000-0000-0000-000000000001", &old.to_string())
        .replace("'gobgp'", &format!("'{}'", destination.backend()))
        .replace("http://new-speaker.example:50051/", destination.endpoint())
        .replace("'jsmith'", "'cutover-operator'")
}

async fn transfer(
    pool: &PgPool,
    snapshot: &Snapshot,
    destination: &SpeakerTarget,
    journal_path: &Path,
) -> Uuid {
    journal(
        journal_path,
        json!({"stage":"transfer-request", "source_target":snapshot.target_id,
        "destination_backend":destination.backend(), "destination_endpoint":destination.endpoint()}),
    );
    sqlx::raw_sql(&transfer_sql(snapshot.target_id, destination))
        .execute(pool)
        .await
        .unwrap();
    // Treat the successful transaction's reply as lost; recover only from binding plus audit.
    let target: Uuid =
        sqlx::query_scalar("SELECT target_id FROM speaker_pop_bindings WHERE pop = $1")
            .bind(POP)
            .fetch_one(pool)
            .await
            .unwrap();
    let audit: Value = sqlx::query_scalar("SELECT to_jsonb(a) FROM audit_log a WHERE action = 'transfer_speaker_target' AND target_id = $1 ORDER BY timestamp DESC LIMIT 1")
        .bind(target.to_string()).fetch_one(pool).await.unwrap();
    let details: Value = serde_json::from_str(audit["details_json"].as_str().unwrap()).unwrap();
    assert_eq!(details["old_target_id"], snapshot.target_id.to_string());
    assert_eq!(details["new_target_id"], target.to_string());
    assert_eq!(audit["actor_id"], "cutover-operator");
    assert!(
        sqlx::raw_sql(&transfer_sql(snapshot.target_id, destination))
            .execute(pool)
            .await
            .is_err(),
        "an old expected binding must not create a duplicate transfer audit"
    );
    journal(
        journal_path,
        json!({"stage":"transfer-recovered", "audit":audit, "target_id":target}),
    );
    target
}

async fn completed_history(pool: &PgPool) -> Vec<Value> {
    sqlx::query_scalar("SELECT to_jsonb(w) FROM withdrawal_requests w WHERE completed_at IS NOT NULL ORDER BY operation_id")
        .fetch_all(pool).await.unwrap()
}

async fn drain(
    controller: &Controller,
    pool: &PgPool,
    snapshot: &Snapshot,
    operation: Uuid,
    journal_path: &Path,
    interrupt: bool,
) {
    let eligible: Vec<_> = snapshot
        .intents
        .iter()
        .filter(|row| {
            matches!(
                row.status,
                MitigationStatus::Active | MitigationStatus::Escalated
            ) && !snapshot.pending_cancellation(row)
        })
        .collect();
    for (index, row) in eligible.iter().enumerate() {
        let reason = format!("speaker-cutover:{operation}:{}:drain", row.mitigation_id);
        journal(
            journal_path,
            json!({"stage":"withdraw-request", "old_id":row.mitigation_id,
            "source_target":snapshot.target_id, "reason":reason, "actor":"bearer-token"}),
        );
        if interrupt && index == 0 {
            controller.speaker.lose_delete.store(true, SeqCst);
        }
        let response = controller
            .post(
                &format!("/v1/mitigations/{}/withdraw", row.mitigation_id),
                json!({"reason":reason, "operator_id":"forged-operator"}),
            )
            .await;
        if interrupt && index == 0 {
            assert!(response.status().is_server_error());
            let pending = controller
                .state
                .repo
                .pending_withdrawals(Some(POP))
                .await
                .unwrap();
            let interrupted = pending
                .iter()
                .find(|request| request.mitigation_id == row.mitigation_id)
                .unwrap();
            assert_eq!(interrupted.target_id, Some(snapshot.target_id));
            assert_eq!(interrupted.actor, "bearer-token");
            assert!(interrupted.reason.contains(&reason));
            // A pending old-target operation blocks even after its daemon delete succeeded.
            let target = SpeakerTarget::from_config(&controller.state.settings.bgp).unwrap();
            assert!(
                sqlx::raw_sql(&transfer_sql(snapshot.target_id, &target))
                    .execute(pool)
                    .await
                    .is_err()
            );
        } else {
            assert_eq!(response.status(), StatusCode::OK);
        }
        let status = response.status().as_u16();
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        journal(
            journal_path,
            json!({"stage":"withdraw-response", "old_id":row.mitigation_id,
            "http_status":status, "body":String::from_utf8(body.to_vec()).unwrap()}),
        );
    }
}

fn mapped_id(journal_path: &Path, marker: &str) -> Option<Uuid> {
    let recorded: std::collections::HashSet<Uuid> = std::fs::read_to_string(journal_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|entry| entry["stage"] == "mapping" && entry["marker"] == marker)
        .map(|entry| entry["new_id"].as_str().unwrap().parse().unwrap())
        .collect();
    assert!(
        recorded.len() <= 1,
        "ambiguous journal mapping must stop cutover"
    );
    recorded.into_iter().next()
}

fn record_mapping(journal_path: &Path, original: &SavedIntent, marker: &str, row: &Mitigation) {
    if mapped_id(journal_path, marker).is_none() {
        journal(
            journal_path,
            json!({"stage":"mapping", "old_id":original.mitigation_id,
            "marker":marker, "new_id":row.mitigation_id, "expiry":row.expires_at,
            "original_expiry":original.expires_at}),
        );
    }
}

async fn resolve_marker(
    controller: &Controller,
    pool: &PgPool,
    original: &SavedIntent,
    marker: &str,
    journal_path: &Path,
) -> std::result::Result<Option<Mitigation>, &'static str> {
    // Withdrawal can replace reason: retain the flushed mapping as authority after later mutations.
    let recorded_id = mapped_id(journal_path, marker);
    // Deliberately no status filter: a completed/withdrawn result must never be recreated.
    let ids: Vec<Uuid> = sqlx::query_scalar("SELECT mitigation_id FROM mitigations WHERE pop = $1 AND (reason = $2 OR mitigation_id = $3) ORDER BY created_at, mitigation_id")
        .bind(POP).bind(marker).bind(recorded_id).fetch_all(pool).await.unwrap();
    assert!(ids.len() <= 1, "ambiguous marker must stop cutover");
    let Some(id) = ids.first() else {
        let requested = std::fs::read_to_string(journal_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .any(|entry| {
                entry["stage"] == "create-request" && entry["request"]["reason"] == marker
            });
        if requested || recorded_id.is_some() {
            return Err(
                "prior request has no resolvable ID or marker; stop for administrative history inspection",
            );
        }
        return Ok(None);
    };
    if let Some(recorded_id) = recorded_id {
        assert_eq!(
            *id, recorded_id,
            "the durable mapping must resolve its exact row"
        );
    }
    let row = controller
        .state
        .repo
        .get_mitigation(*id)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(row.mitigation_id, original.mitigation_id);
    assert_eq!(row.pop, original.pop);
    contract::exact_inventory(&[mitigation_rule(&row)], &[original.rule()]).unwrap();
    assert!(
        row.expires_at <= original.expires_at,
        "a resume cannot extend the original deadline"
    );
    let request = std::fs::read_to_string(journal_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|entry| entry["stage"] == "create-request" && entry["request"]["reason"] == marker)
        .expect("the request must have been flushed before its RPC")["request"]
        .clone();
    let cap: DateTime<Utc> = serde_json::from_value(request["expires_at_cap"].clone()).unwrap();
    assert_eq!(cap, original.expires_at);
    let requested_ttl = request["ttl_seconds"].as_i64().unwrap();
    assert!((MIN_TTL..=1800).contains(&requested_ttl));
    assert_eq!(
        row.expires_at,
        (row.created_at + chrono::Duration::seconds(requested_ttl)).min(cap),
        "persisted expiry must match the exact admitted request, not a fresh lifetime on resume"
    );
    assert!(
        controller
            .state
            .repo
            .pending_withdrawals(Some(POP))
            .await
            .unwrap()
            .iter()
            .all(|request| request.mitigation_id != row.mitigation_id),
        "pending cleanup blocks recreation"
    );
    Ok(Some(row))
}

fn recreation_ttl(
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> std::result::Result<i64, &'static str> {
    if expires_at <= now {
        return Err("expired");
    }
    let remaining = (expires_at - now).num_seconds();
    if remaining < MIN_TTL {
        return Err("below-minimum");
    }
    Ok(remaining.min(1800))
}

#[test]
fn recreation_ttl_respects_minimum_and_absolute_ceiling() {
    let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    for (nanoseconds, expected) in [
        (-1, Err("expired")),
        (0, Err("expired")),
        (1, Err("below-minimum")),
        (29_000_000_000, Err("below-minimum")),
        (29_999_999_999, Err("below-minimum")),
        (30_000_000_000, Ok(30)),
        (30_999_999_999, Ok(30)),
        (1_800_999_999_999, Ok(1800)),
        (1_801_000_000_000, Ok(1800)),
    ] {
        let expires_at = now + chrono::Duration::nanoseconds(nanoseconds);
        let actual = recreation_ttl(expires_at, now);
        assert_eq!(actual, expected, "remaining nanoseconds: {nanoseconds}");
        if let Ok(ttl) = actual {
            assert!(now + chrono::Duration::seconds(ttl) <= expires_at);
        }
    }
}

#[test]
fn slow_setup_can_expire_both_short_candidates() {
    let captured_at = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let resumed_at = captured_at + chrono::Duration::seconds(46);
    let decisions = [30, 45]
        .map(|ttl| recreation_ttl(captured_at + chrono::Duration::seconds(ttl), resumed_at));
    assert_eq!(decisions, [Err("expired"), Err("expired")]);
}

async fn recreate(
    controller: &Controller,
    pool: &PgPool,
    snapshot: &Snapshot,
    operation: Uuid,
    journal_path: &Path,
    lose_first_reply: bool,
) -> Vec<Mitigation> {
    let mut recreated = Vec::new();
    for original in &snapshot.intents {
        if !matches!(
            original.status,
            MitigationStatus::Active | MitigationStatus::Escalated
        ) {
            continue;
        }
        if snapshot.pending_cancellation(original) {
            journal(
                journal_path,
                json!({"stage":"skip", "old_id":original.mitigation_id,
                "reason":"pending-cancellation", "original_expiry":original.expires_at}),
            );
            continue;
        }
        let marker = format!(
            "speaker-cutover:{operation}:{}:create",
            original.mitigation_id
        );
        if original.expires_at <= Utc::now() {
            controller.reconcile().await;
            journal(
                journal_path,
                json!({"stage":"skip", "old_id":original.mitigation_id,
                "reason":"expired", "original_expiry":original.expires_at}),
            );
            continue;
        }
        if let Some(row) = resolve_marker(controller, pool, original, &marker, journal_path)
            .await
            .unwrap()
        {
            record_mapping(journal_path, original, &marker, &row);
            journal(
                journal_path,
                json!({"stage":"resume-existing", "old_id":original.mitigation_id, "new_id":row.mitigation_id, "status":row.status, "expiry":row.expires_at}),
            );
            recreated.push(row);
            continue;
        }
        let ttl = match recreation_ttl(original.expires_at, Utc::now()) {
            Ok(ttl) => ttl,
            Err(reason) => {
                if reason == "expired" {
                    controller.reconcile().await;
                }
                journal(
                    journal_path,
                    json!({"stage":"skip", "old_id":original.mitigation_id,
                    "reason":reason, "original_expiry":original.expires_at}),
                );
                continue;
            }
        };
        let mut request = payload(&original.rule(), ttl, &marker);
        request["expires_at_cap"] = json!(original.expires_at);
        journal(
            journal_path,
            json!({"stage":"create-request", "operation":operation,
            "old_id":original.mitigation_id, "original_reason":original.reason,
            "original_actor":"unknown", "actor":"bearer-token", "source_target":snapshot.target_id,
            "destination_target":controller.target_id, "request":request}),
        );
        if lose_first_reply && recreated.is_empty() {
            controller.speaker.lose_add.store(true, SeqCst);
        }
        let response = controller.post("/v1/mitigations", request).await;
        if lose_first_reply && recreated.is_empty() {
            assert_eq!(response.status(), StatusCode::ACCEPTED);
            drop(response); // Controller task completed; the operator never consumes its HTTP reply.
            journal(
                journal_path,
                json!({"stage":"create-reply-lost", "old_id":original.mitigation_id}),
            );
            return recreated; // Stop before discovering its new ID; a new controller resumes the journal.
        } else {
            assert_eq!(response.status(), StatusCode::CREATED);
            journal(
                journal_path,
                json!({"stage":"create-response", "old_id":original.mitigation_id,
                "response":response_json(response).await}),
            );
        }
        let row = resolve_marker(controller, pool, original, &marker, journal_path)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, MitigationStatus::Active);
        record_mapping(journal_path, original, &marker, &row);
        recreated.push(row);
    }
    recreated
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and pinned Rust/Go speakers; run scripts/test-speaker-cutover.sh"]
async fn authenticated_maintenance_cutover_and_rollback_preserve_intent_and_deadlines() {
    let context = common::TestContext::new().await;
    let version: String = sqlx::query_scalar("SELECT version()")
        .fetch_one(&context.pool)
        .await
        .unwrap();
    let directory: PathBuf = tempfile::Builder::new()
        .prefix("prefixd-speaker-cutover-")
        .tempdir()
        .unwrap()
        .keep();
    let journal_path = directory.join("journal.jsonl");
    eprintln!(
        "cutover receipt: {}; PostgreSQL: {version}; configured minimum TTL: {MIN_TTL}s",
        directory.display()
    );
    let pair = peer_receipt::Pair::start().await;
    let rust = &pair.rust;
    let go = &pair.go;
    let rust_client = Arc::new(rust.connect().await);
    let go_client = Arc::new(go.connect().await);
    contract::wait_peer_state(rust_client.as_ref(), &rust.peer_address, true)
        .await
        .unwrap();
    contract::wait_peer_state(go_client.as_ref(), &go.peer_address, true)
        .await
        .unwrap();
    let unknown = FlowSpecRule::new(
        FlowSpecNlri {
            dst_prefix: "198.51.100.250/32".into(),
            protocol: Some(1),
            dst_ports: vec![],
        },
        FlowSpecAction::discard(),
    );
    go_client.announce(&unknown).await.unwrap();
    let mut go_settings = settings(&context);
    go_settings.bgp.mode = BgpMode::Gobgp;
    go_settings.bgp.gobgp_grpc = go.endpoint.clone();
    let mut rust_settings = settings(&context);
    rust_settings.bgp.mode = BgpMode::Rustbgpd;
    rust_settings.bgp.rustbgpd = Some(rust.config.clone());
    let go_speaker = UncertainSpeaker::new(go_client.clone());
    let rust_speaker = UncertainSpeaker::new(rust_client.clone());
    let source = Controller::start(&context.pool, go_settings.clone(), go_speaker.clone()).await;
    // An older binary silently ignores unknown request fields: fail before draining it.
    let schema = response_json(
        source
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/openapi.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert!(
        schema["components"]["schemas"]["CreateMitigationRequest"]["properties"]["expires_at_cap"]
            .is_object(),
        "deployed manual API must advertise its absolute expiry cap before any drain"
    );
    let unauthorized = source
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mitigations")
                .header("content-type", "application/json")
                .body(Body::from(
                    payload(&owned_rules()[0], 600, "unauthorized").to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(go_speaker.calls(), (0, 0));
    let mut originals = Vec::new();
    for (index, rule) in owned_rules().iter().enumerate() {
        let response = source
            .post(
                "/v1/mitigations",
                payload(rule, 600, &format!("original intent {index}")),
            )
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        originals.push(response_json(response).await);
    }
    // Real deadlines cross expiry/the configured minimum; a slow setup may expire both.
    let mut short_ids = Vec::<Uuid>::new();
    for (index, ttl) in [30, 45].into_iter().enumerate() {
        let rule = FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: format!("203.0.113.{}/32", 90 + index),
                protocol: Some(17),
                dst_ports: vec![53],
            },
            FlowSpecAction::discard(),
        );
        let response = source
            .post(
                "/v1/mitigations",
                payload(&rule, ttl, &format!("deadline case {index}")),
            )
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        short_ids.push(
            response_json(response).await["mitigation_id"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
        );
    }
    let cancelled_rule = FlowSpecRule::new(
        FlowSpecNlri {
            dst_prefix: "2001:db8::82/128".into(),
            protocol: Some(17),
            dst_ports: vec![53, 123],
        },
        FlowSpecAction::discard(),
    );
    let admitted = source
        .post(
            "/v1/mitigations",
            payload(&cancelled_rule, 600, "subsequently cancelled intent"),
        )
        .await;
    assert_eq!(admitted.status(), StatusCode::CREATED);
    let cancelled_id: Uuid = response_json(admitted).await["mitigation_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    go_speaker.lose_delete.store(true, SeqCst);
    let cancellation = source
        .post(
            &format!("/v1/mitigations/{cancelled_id}/withdraw"),
            json!({"reason":"preexisting operator cancellation", "operator_id":"forged-operator"}),
        )
        .await;
    assert!(cancellation.status().is_server_error());
    let cancellation_request = source
        .state
        .repo
        .pending_withdrawals(Some(POP))
        .await
        .unwrap()
        .into_iter()
        .find(|request| request.mitigation_id == cancelled_id)
        .unwrap();
    assert_eq!(cancellation_request.actor, "bearer-token");
    assert!(
        cancellation_request
            .reason
            .contains("preexisting operator cancellation")
    );
    assert_eq!(
        source
            .state
            .repo
            .get_mitigation(cancelled_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        MitigationStatus::Active
    );
    let first = Snapshot::capture(&context.pool, &directory, "go-source").await;
    assert_eq!(first.intents.len(), owned_rules().len() + 3);
    let saved_cancellation = first.raw["withdrawals"]
        .as_array()
        .unwrap()
        .iter()
        .find(|request| request["operation_id"] == cancellation_request.operation_id.to_string())
        .unwrap()
        .clone();
    let cancelled_intent = first
        .intents
        .iter()
        .find(|row| row.mitigation_id == cancelled_id)
        .unwrap();
    assert!(first.pending_cancellation(cancelled_intent));
    // The eligibility fence covers mitigation ID and canonical aliases independently.
    let mut key_alias = (*cancelled_intent).clone();
    key_alias.mitigation_id = Uuid::new_v4();
    key_alias.match_json = json!({"dst_prefix":"2001:0DB8:0:0:0:0:0:82/128",
        "protocol":17, "dst_ports":[123, 53, 53]})
    .to_string();
    assert!(
        first.pending_cancellation(&key_alias),
        "pending canonical scope excludes another raw owner ID"
    );
    let mut id_alias = (*cancelled_intent).clone();
    id_alias.match_json =
        json!({"dst_prefix":"203.0.113.99/32", "protocol":17, "dst_ports":[53]}).to_string();
    assert!(
        first.pending_cancellation(&id_alias),
        "pending target ID excludes an altered rule snapshot"
    );
    let mut keys = std::collections::HashSet::new();
    for original in &first.intents {
        assert_eq!(original.pop, POP);
        assert!(matches!(
            original.status,
            MitigationStatus::Active | MitigationStatus::Escalated
        ));
        assert!(
            keys.insert(original.rule().nlri_hash()),
            "canonical owner conflict blocks drain"
        );
        payload(&original.rule(), 600, "representability preflight");
    }
    let mut source_rules: Vec<_> = first
        .intents
        .iter()
        .filter(|row| !first.pending_cancellation(row))
        .map(SavedIntent::rule)
        .collect();
    source_rules.push(unknown.clone());
    contract::wait_inventory(go_client.as_ref(), &source_rules)
        .await
        .unwrap();
    peer_receipt::wait_rust_views(rust, &[], &source_rules).await;
    let operation = Uuid::new_v4();
    drain(
        &source,
        &context.pool,
        &first,
        operation,
        &journal_path,
        true,
    )
    .await;
    let pending = source
        .state
        .repo
        .pending_withdrawals(Some(POP))
        .await
        .unwrap();
    assert!(
        pending
            .iter()
            .any(|request| request.operation_id == cancellation_request.operation_id)
    );
    let original_operation = pending
        .iter()
        .find(|request| request.mitigation_id != cancelled_id)
        .unwrap()
        .operation_id;
    source.stop();
    // Reconstruct a controller against the same source; durable cleanup survives the interruption.
    let resumed = Controller::start(&context.pool, go_settings.clone(), go_speaker.clone()).await;
    resumed.reconcile().await;
    assert!(
        resumed
            .state
            .repo
            .pending_withdrawals(Some(POP))
            .await
            .unwrap()
            .is_empty()
    );
    let history = completed_history(&context.pool).await;
    assert_eq!(history.len(), first.intents.len());
    let mut completed_cancellation = history
        .iter()
        .find(|request| request["operation_id"] == cancellation_request.operation_id.to_string())
        .unwrap()
        .clone();
    assert!(!completed_cancellation["completed_at"].is_null());
    completed_cancellation["completed_at"] = Value::Null;
    assert_eq!(
        completed_cancellation, saved_cancellation,
        "cleanup preserves the original operation, target, actor and reason"
    );
    assert!(
        history
            .iter()
            .any(|row| row["operation_id"] == original_operation.to_string())
    );
    assert!(
        history
            .iter()
            .all(|row| row["target_id"] == first.target_id.to_string())
    );
    let source_calls = go_speaker.calls();
    resumed.reconcile().await;
    assert_eq!(
        go_speaker.calls(),
        source_calls,
        "quiet source cleanup repeat"
    );
    contract::wait_inventory(go_client.as_ref(), std::slice::from_ref(&unknown))
        .await
        .unwrap();
    peer_receipt::wait_rust_views(rust, &[], std::slice::from_ref(&unknown)).await;
    resumed.stop();
    let old_target: Value =
        sqlx::query_scalar("SELECT to_jsonb(t) FROM speaker_targets t WHERE target_id = $1")
            .bind(first.target_id)
            .fetch_one(&context.pool)
            .await
            .unwrap();
    let rust_target = SpeakerTarget::from_config(&rust_settings.bgp).unwrap();
    let new_target = transfer(&context.pool, &first, &rust_target, &journal_path).await;
    assert_ne!(new_target, first.target_id);
    let destination =
        Controller::start(&context.pool, rust_settings.clone(), rust_speaker.clone()).await;
    assert_eq!(destination.target_id, new_target);
    // Delayed recreation skips both short rows, even if setup already expired both.
    let short_deadline = first
        .intents
        .iter()
        .map(|row| row.expires_at)
        .min()
        .unwrap();
    if let Ok(wait) = (short_deadline - Utc::now()).to_std() {
        tokio::time::sleep(wait + Duration::from_millis(100)).await;
    }
    let interrupted = recreate(
        &destination,
        &context.pool,
        &first,
        operation,
        &journal_path,
        true,
    )
    .await;
    assert!(
        interrupted.is_empty(),
        "lost reply interrupts before recording a new ID"
    );
    destination.stop();
    let destination =
        Controller::start(&context.pool, rust_settings.clone(), rust_speaker.clone()).await;
    let migrated = recreate(
        &destination,
        &context.pool,
        &first,
        operation,
        &journal_path,
        false,
    )
    .await;
    assert_eq!(migrated.len(), 4);
    assert!(
        migrated
            .iter()
            .all(|row| canonical_key(&mitigation_rule(row)) != canonical_key(&cancelled_rule)),
        "preexisting cancellation must not be replayed on the new target"
    );
    assert!(
        migrated.iter().all(|row| first
            .intents
            .iter()
            .all(|original| original.mitigation_id != row.mitigation_id)),
        "an original Withdrawn row must not masquerade as recreated intent"
    );
    let destination_calls = rust_speaker.calls();
    let repeated = recreate(
        &destination,
        &context.pool,
        &first,
        operation,
        &journal_path,
        false,
    )
    .await;
    assert_eq!(
        repeated
            .iter()
            .map(|row| row.mitigation_id)
            .collect::<Vec<_>>(),
        migrated
            .iter()
            .map(|row| row.mitigation_id)
            .collect::<Vec<_>>()
    );
    destination.reconcile().await;
    destination.reconcile().await;
    assert_eq!(
        rust_speaker.calls(),
        destination_calls,
        "resume and readable repair remain quiet"
    );
    let migrated_rules: Vec<_> = migrated.iter().map(mitigation_rule).collect();
    contract::exact_inventory(&migrated_rules, &owned_rules()).unwrap();
    contract::wait_inventory(rust_client.as_ref(), &migrated_rules)
        .await
        .unwrap();
    let mut expected_received = migrated_rules.clone();
    expected_received.push(unknown.clone());
    if let Err(original_panic) =
        AssertUnwindSafe(peer_receipt::wait_go_received(go, &expected_received))
            .catch_unwind()
            .await
    {
        let diagnostics = async {
            let _ = std::fs::write(
                directory.join("expected-received.json"),
                serde_json::to_vec(&expected_received).unwrap(),
            );
            for afi in [1, 2] {
                for (name, table) in [
                    ("adj-in", prefixd::bgp::apipb::TableType::AdjIn),
                    ("global", prefixd::bgp::apipb::TableType::Global),
                ] {
                    let paths = go.paths(afi, table).await;
                    let _ = std::fs::write(
                        directory.join(format!("go-{name}-afi-{afi}.txt")),
                        format!("{paths:#?}"),
                    );
                }
            }
            for family in [3, 4] {
                for (name, peer) in [
                    ("local", "0.0.0.0"),
                    ("received", rust.peer_address.as_str()),
                ] {
                    let routes = rust.received_flow_spec(family, peer).await;
                    let _ = std::fs::write(
                        directory.join(format!("rust-{name}-family-{family}.txt")),
                        format!("{routes:#?}"),
                    );
                }
            }
            for (name, speaker) in [
                ("rust", rust_client.as_ref() as &dyn FlowSpecAnnouncer),
                ("go", go_client.as_ref() as &dyn FlowSpecAnnouncer),
            ] {
                let result = speaker.peer_observer().unwrap().session_status().await;
                let text = match result {
                    Ok(peers) => format!("{peers:#?}"),
                    Err(_) => "session observation failed".into(),
                };
                let _ = std::fs::write(directory.join(format!("{name}-sessions.txt")), text);
            }
        };
        // Write each observation immediately; a later RPC/timeout must preserve the original failure.
        let result = AssertUnwindSafe(tokio::time::timeout(Duration::from_secs(12), diagnostics))
            .catch_unwind()
            .await;
        let status = match result {
            Ok(Ok(())) => "complete",
            Ok(Err(_)) => "diagnostic deadline elapsed",
            Err(_) => "diagnostic observation panicked",
        };
        let _ = std::fs::write(directory.join("diagnostic-status.txt"), status);
        std::panic::resume_unwind(original_panic);
    }
    assert_go_provenance(go, &migrated_rules, &unknown).await;
    peer_receipt::wait_rust_views(rust, &migrated_rules, std::slice::from_ref(&unknown)).await;
    assert_eq!(completed_history(&context.pool).await, history);
    let reverse = Snapshot::capture(&context.pool, &directory, "rust-source").await;
    assert_eq!(
        reverse.intents.len(),
        first.intents.len() + migrated.len(),
        "history retained in complete rollback snapshot"
    );
    let rollback_operation = Uuid::new_v4();
    drain(
        &destination,
        &context.pool,
        &reverse,
        rollback_operation,
        &journal_path,
        false,
    )
    .await;
    contract::wait_inventory(rust_client.as_ref(), &[])
        .await
        .unwrap();
    peer_receipt::wait_go_received(go, std::slice::from_ref(&unknown)).await;
    destination.stop();
    let go_target = SpeakerTarget::from_config(&go_settings.bgp).unwrap();
    let restored_target = transfer(&context.pool, &reverse, &go_target, &journal_path).await;
    assert_eq!(restored_target, first.target_id);
    let rollback = Controller::start(&context.pool, go_settings, go_speaker.clone()).await;
    let restored = recreate(
        &rollback,
        &context.pool,
        &reverse,
        rollback_operation,
        &journal_path,
        false,
    )
    .await;
    assert_eq!(restored.len(), 4);
    assert!(
        restored
            .iter()
            .all(|row| canonical_key(&mitigation_rule(row)) != canonical_key(&cancelled_rule)),
        "rollback must not resurrect the original cancelled scope"
    );
    let mut restored_rules: Vec<_> = restored.iter().map(mitigation_rule).collect();
    contract::exact_inventory(&restored_rules, &owned_rules()).unwrap();
    restored_rules.push(unknown.clone());
    contract::wait_inventory(go_client.as_ref(), &restored_rules)
        .await
        .unwrap();
    peer_receipt::wait_rust_views(rust, &[], &restored_rules).await;
    let rollback_calls = go_speaker.calls();
    recreate(
        &rollback,
        &context.pool,
        &reverse,
        rollback_operation,
        &journal_path,
        false,
    )
    .await;
    rollback.reconcile().await;
    assert_eq!(go_speaker.calls(), rollback_calls);
    let old_target_after: Value =
        sqlx::query_scalar("SELECT to_jsonb(t) FROM speaker_targets t WHERE target_id = $1")
            .bind(first.target_id)
            .fetch_one(&context.pool)
            .await
            .unwrap();
    assert_eq!(old_target_after, old_target);
    for original in &originals {
        let id: Uuid = original["mitigation_id"].as_str().unwrap().parse().unwrap();
        assert_eq!(
            rollback
                .state
                .repo
                .get_mitigation(id)
                .await
                .unwrap()
                .unwrap()
                .status,
            MitigationStatus::Withdrawn
        );
    }
    let final_snapshot = Snapshot::capture(&context.pool, &directory, "rollback-source").await;
    drain(
        &rollback,
        &context.pool,
        &final_snapshot,
        Uuid::new_v4(),
        &journal_path,
        false,
    )
    .await;
    let terminal_calls = go_speaker.calls();
    let terminal_resume = recreate(
        &rollback,
        &context.pool,
        &reverse,
        rollback_operation,
        &journal_path,
        false,
    )
    .await;
    assert!(
        terminal_resume
            .iter()
            .all(|row| row.status == MitigationStatus::Withdrawn)
    );
    assert_eq!(
        go_speaker.calls(),
        terminal_calls,
        "all-status marker lookup never recreates terminal results"
    );
    rollback.reconcile().await;
    contract::wait_inventory(go_client.as_ref(), std::slice::from_ref(&unknown))
        .await
        .unwrap();
    peer_receipt::wait_rust_views(rust, &[], std::slice::from_ref(&unknown)).await;
    let expected_cleanup = first.intents.len() + migrated.len() + restored.len();
    assert_eq!(
        completed_history(&context.pool).await.len(),
        expected_cleanup
    );
    let final_history = completed_history(&context.pool).await;
    assert!(
        history
            .iter()
            .all(|original| final_history.contains(original)),
        "original completed cleanup and target identities remain immutable across rollback"
    );
    // With no recorded new ID, a later reason change makes a lost reply unresolved.
    // The test observes that later withdrawal administratively; the operator journal does not.
    let unresolved_journal = directory.join("unresolved-journal.jsonl");
    let original = reverse
        .intents
        .iter()
        .find(|row| row.status == MitigationStatus::Active)
        .unwrap();
    let marker = format!(
        "speaker-cutover:{}:{}:create",
        Uuid::new_v4(),
        original.mitigation_id
    );
    let mut request = payload(
        &original.rule(),
        (original.expires_at - Utc::now()).num_seconds(),
        &marker,
    );
    request["expires_at_cap"] = json!(original.expires_at);
    journal(
        &unresolved_journal,
        json!({"stage":"create-request", "request":request}),
    );
    let lost = rollback.post("/v1/mitigations", request).await;
    assert_eq!(lost.status(), StatusCode::CREATED);
    drop(lost);
    let id: Uuid =
        sqlx::query_scalar("SELECT mitigation_id FROM mitigations WHERE pop = $1 AND reason = $2")
            .bind(POP)
            .bind(&marker)
            .fetch_one(&context.pool)
            .await
            .unwrap();
    let withdrawn = rollback
        .post(
            &format!("/v1/mitigations/{id}/withdraw"),
            json!({"reason":"later operator cleanup"}),
        )
        .await;
    assert_eq!(withdrawn.status(), StatusCode::OK);
    let before_unresolved = go_speaker.calls();
    assert!(
        resolve_marker(
            &rollback,
            &context.pool,
            original,
            &marker,
            &unresolved_journal
        )
        .await
        .is_err()
    );
    assert_eq!(
        go_speaker.calls(),
        before_unresolved,
        "an absent mutable marker cannot authorize retry"
    );
    rollback.reconcile().await;
    contract::wait_inventory(go_client.as_ref(), std::slice::from_ref(&unknown))
        .await
        .unwrap();
    peer_receipt::wait_rust_views(rust, &[], std::slice::from_ref(&unknown)).await;
    assert_eq!(
        completed_history(&context.pool).await.len(),
        expected_cleanup + 1
    );
    let audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE action = 'transfer_speaker_target'",
    )
    .fetch_one(&context.pool)
    .await
    .unwrap();
    assert_eq!(audits, 2);
    let journal_text = std::fs::read_to_string(&journal_path).unwrap();
    let entries: Vec<Value> = journal_text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(entries.iter().any(|entry| entry["reason"] == "expired"));
    for id in short_ids {
        assert!(
            entries
                .iter()
                .any(|entry| entry["stage"] == "skip" && entry["old_id"] == id.to_string())
        );
        assert!(
            !entries.iter().any(
                |entry| entry["stage"] == "create-request" && entry["old_id"] == id.to_string()
            )
        );
    }
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry["stage"] == "mapping")
            .count(),
        8
    );
    journal(
        &journal_path,
        json!({"stage":"complete", "transfers":2, "recreated":8,
        "scope":"exact local rules and actual received peer control-plane state; no forwarding claim"}),
    );
    rollback.stop();
    pair.remove().await;
}
