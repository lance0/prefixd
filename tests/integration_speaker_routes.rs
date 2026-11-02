mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use prefixd::{
    AppState,
    api::create_test_router,
    bgp::{FlowSpecAnnouncer, FlowSpecReader, FlowSpecWriter, PeerObserver, PeerStatus},
    config::{AuthMode, OperationMode},
    db::{MockRepository, RepositoryTrait},
    domain::{
        FlowSpecAction, FlowSpecNlri, FlowSpecRule, FragmentMatch, OperatorRole, PacketLengthRange,
    },
    error::{PrefixdError, Result},
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering::SeqCst},
};
use tower::ServiceExt;

const TOKEN: &str = "speaker-inventory-token";

struct InventorySpeaker {
    backend: &'static str,
    // Empty, populated, failed or unsupported.
    mode: AtomicUsize,
    reads: AtomicUsize,
}

impl InventorySpeaker {
    fn new(backend: &'static str, mode: usize) -> Arc<Self> {
        Arc::new(Self {
            backend,
            mode: AtomicUsize::new(mode),
            reads: AtomicUsize::new(0),
        })
    }
}

impl FlowSpecAnnouncer for InventorySpeaker {
    fn backend(&self) -> &'static str {
        self.backend
    }
    fn reader(&self) -> Option<&dyn FlowSpecReader> {
        if self.mode.load(SeqCst) == 3 {
            None
        } else {
            Some(self)
        }
    }
    fn peer_observer(&self) -> Option<&dyn PeerObserver> {
        Some(self)
    }
}

#[async_trait::async_trait]
impl FlowSpecWriter for InventorySpeaker {
    async fn announce(&self, _: &FlowSpecRule) -> Result<()> {
        panic!("inventory must not announce")
    }
    async fn withdraw(&self, _: &FlowSpecRule) -> Result<()> {
        panic!("inventory must not withdraw")
    }
}

#[async_trait::async_trait]
impl PeerObserver for InventorySpeaker {
    async fn session_status(&self) -> Result<Vec<PeerStatus>> {
        panic!("inventory must not depend on peer health")
    }
}

#[async_trait::async_trait]
impl FlowSpecReader for InventorySpeaker {
    async fn list_active(&self) -> Result<Vec<FlowSpecRule>> {
        self.reads.fetch_add(1, SeqCst);
        match self.mode.load(SeqCst) {
            0 => Ok(vec![]),
            1 => Ok(rules()),
            2 => Err(PrefixdError::Internal(
                "partial inventory: upstream-secret-diagnostic".into(),
            )),
            _ => panic!("unsupported observation must not be called"),
        }
    }
}

fn rules() -> Vec<FlowSpecRule> {
    vec![
        FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: "203.0.113.10/32".into(),
                src_prefix: Some("198.51.100.0/24".into()),
                protocol: Some(17),
                dst_ports: vec![443],
                src_ports: vec![53, 123],
                packet_length: Some(PacketLengthRange {
                    min: 1000,
                    max: 1500,
                }),
                ..Default::default()
            },
            FlowSpecAction::police(125_000),
        )
        .with_owner("flow-owner"),
        FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: "2001:db8::10/128".into(),
                src_prefix: Some("2001:db8:2::/64".into()),
                protocol: Some(17),
                fragment: Some(FragmentMatch::NonFirst),
                ..Default::default()
            },
            FlowSpecAction::discard(),
        )
        .with_owner("v6-owner"),
        FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: "203.0.113.11/32".into(),
                protocol: Some(6),
                dst_ports: vec![80, 443],
                ..Default::default()
            },
            FlowSpecAction::discard(),
        ),
    ]
}

fn state(speaker: Arc<InventorySpeaker>) -> Arc<AppState> {
    AppState::new(
        common::test_settings(),
        common::test_inventory(),
        common::test_playbooks(),
        Arc::new(MockRepository::new()),
        speaker,
        ".".into(),
    )
    .unwrap()
}

async fn body(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn route_inventory_authenticates_before_reading_the_speaker() {
    let speaker = InventorySpeaker::new("mock", 0);
    let mut state = state(speaker.clone());
    let settings = Arc::get_mut(&mut state).unwrap();
    settings.settings.http.auth.mode = AuthMode::Bearer;
    settings.bearer_token = Some(TOKEN.into());
    let app = create_test_router(state);
    for token in [None, Some("wrong-token")] {
        let mut request = Request::builder().uri("/v1/speaker/routes");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(speaker.reads.load(SeqCst), 0);
    }
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/speaker/routes")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body(response).await["routes"], serde_json::json!([]));
    assert_eq!(speaker.reads.load(SeqCst), 1);
}

#[tokio::test]
async fn route_inventory_distinguishes_unsupported_failed_empty_and_populated() {
    for (mode, expected) in [
        (0, StatusCode::OK),
        (1, StatusCode::OK),
        (2, StatusCode::BAD_GATEWAY),
        (3, StatusCode::NOT_IMPLEMENTED),
    ] {
        let speaker = InventorySpeaker::new("mock", mode);
        let response = create_test_router(state(speaker.clone()))
            .oneshot(
                Request::builder()
                    .uri("/v1/speaker/routes")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        let json = body(response).await;
        assert!(!json.to_string().contains("upstream-secret-diagnostic"));
        match mode {
            0 => assert_eq!(json["routes"], serde_json::json!([])),
            1 => {
                assert_eq!(json["routes"], serde_json::to_value(rules()).unwrap());
                assert!(json["routes"][2].get("owner").is_none());
                assert!(json["routes"][2]["nlri"].get("src_prefix").is_none());
            }
            2 | 3 => {
                assert!(json.get("routes").is_none());
                assert!(json["error"].as_str().unwrap().contains(if mode == 3 {
                    "unsupported"
                } else {
                    "failed"
                }));
            }
            _ => unreachable!(),
        }
        assert_eq!(speaker.reads.load(SeqCst), usize::from(mode != 3));
    }
}

#[tokio::test]
async fn local_inventory_scope_is_explicit_and_reads_work_unbound_in_standby_and_dry_run() {
    for (backend, scope) in [
        ("rustbgpd", "retained_local_flow_spec_intent"),
        ("gobgp", "accepted_local_flow_spec_rib"),
        ("mock", "adapter_local_flow_spec"),
    ] {
        for mode in [OperationMode::DryRun, OperationMode::Enforced] {
            let speaker = InventorySpeaker::new(backend, 1);
            let mut state = state(speaker);
            Arc::get_mut(&mut state).unwrap().settings.mode = mode;
            let state = state
                .with_fence(Arc::new(prefixd::fence::ControllerFence::new(false)))
                .unwrap();
            assert!(state.verified_speaker_binding().is_err() || backend == "mock");
            let response = create_test_router(state)
                .oneshot(
                    Request::builder()
                        .uri("/v1/speaker/routes")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let json = body(response).await;
            assert_eq!(json["backend"], backend);
            assert_eq!(json["observation_scope"], scope);
            assert_eq!(json["routes"], serde_json::to_value(rules()).unwrap());
        }
    }
}

#[tokio::test]
async fn viewer_sessions_can_observe_local_rules() {
    use argon2::{Argon2, PasswordHasher};
    const PASSWORD: &str = "inventory-viewer-password";
    let repo = Arc::new(MockRepository::new());
    let hash = Argon2::default()
        .hash_password_with_salt(PASSWORD.as_bytes(), b"inventory-viewer")
        .unwrap()
        .to_string();
    repo.create_operator("inventory-viewer", &hash, OperatorRole::Viewer, None)
        .await
        .unwrap();
    let mut settings = common::test_settings();
    settings.http.auth.mode = AuthMode::Credentials;
    let state = AppState::new(
        settings,
        common::test_inventory(),
        common::test_playbooks(),
        repo,
        InventorySpeaker::new("mock", 0),
        ".".into(),
    )
    .unwrap();
    let app = create_test_router(state);
    let login = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "username":"inventory-viewer", "password":PASSWORD
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let cookie = login.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/speaker/routes")
                .header("cookie", cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[test]
fn openapi_documents_read_scope_and_failure_outcomes() {
    use utoipa::OpenApi;
    let spec = serde_json::to_value(prefixd::api::ApiDoc::openapi()).unwrap();
    let operation = &spec["paths"]["/v1/speaker/routes"]["get"];
    for code in ["200", "401", "501", "502"] {
        assert!(operation["responses"].get(code).is_some(), "{code}");
    }
    assert!(operation["responses"].get("503").is_none());
    assert!(
        operation["description"]
            .as_str()
            .unwrap()
            .contains("Authenticated")
    );
    let properties = &spec["components"]["schemas"]["FlowSpecNlri"]["properties"];
    for field in [
        "dst_prefix",
        "src_prefix",
        "protocol",
        "dst_ports",
        "src_ports",
        "fragment",
        "packet_length",
    ] {
        assert!(properties.get(field).is_some(), "{field}");
    }
}

#[tokio::test]
async fn cli_reports_local_rules_and_never_turns_failed_observation_into_empty_json() {
    let speaker = InventorySpeaker::new("rustbgpd", 1);
    let mut state = state(speaker.clone());
    let config = Arc::get_mut(&mut state).unwrap();
    config.settings.http.auth.mode = AuthMode::Bearer;
    config.bearer_token = Some(TOKEN.into());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, create_test_router(state))
            .await
            .unwrap()
    });
    for mode in 0..=3 {
        speaker.mode.store(mode, SeqCst);
        for format in ["json", "table"] {
            let output = tokio::time::timeout(
                std::time::Duration::from_secs(15),
                tokio::process::Command::new(env!("CARGO_BIN_EXE_prefixdctl"))
                    .args([
                        "--api",
                        &api,
                        "--token",
                        TOKEN,
                        "--format",
                        format,
                        "speaker",
                        "list-routes",
                    ])
                    .stdin(std::process::Stdio::null())
                    .kill_on_drop(true)
                    .output(),
            )
            .await
            .unwrap()
            .unwrap();
            let stdout = String::from_utf8(output.stdout).unwrap();
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert!(
                !stdout.contains("upstream-secret-diagnostic")
                    && !stderr.contains("upstream-secret-diagnostic")
            );
            assert_eq!(output.status.success(), mode < 2, "{stdout}\n{stderr}");
            if mode >= 2 {
                assert!(stdout.is_empty(), "{stdout}");
                assert!(stderr.contains(if mode == 3 { "501" } else { "502" }));
                assert!(stderr.contains(if mode == 3 { "unsupported" } else { "failed" }));
            } else if format == "json" {
                let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
                assert_eq!(json["backend"], "rustbgpd");
                assert_eq!(json["observation_scope"], "retained_local_flow_spec_intent");
                assert_eq!(
                    json["routes"],
                    if mode == 0 {
                        serde_json::json!([])
                    } else {
                        serde_json::to_value(rules()).unwrap()
                    }
                );
            } else if mode == 0 {
                assert!(stdout.contains("No local FlowSpec rules observed."));
            } else {
                for detail in [
                    "203.0.113.10/32",
                    "from 198.51.100.0/24",
                    "src 53,123",
                    "dst 443",
                    "len 1000-1500",
                    "police 125000 bps",
                    "flow-owner",
                    "2001:db8::10/128",
                    "from 2001:db8:2::/64",
                    "non-first fragments",
                    "discard",
                    "v6-owner",
                    "tcp dst 80,443",
                ] {
                    assert!(stdout.contains(detail), "missing {detail}: {stdout}");
                }
                assert!(stdout.contains("no router enforcement proof"));
            }
        }
    }
    server.abort();
    let _ = server.await;
}
