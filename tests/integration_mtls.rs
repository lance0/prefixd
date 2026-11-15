mod common;

use std::{path::Path, process::Stdio, sync::Arc, time::Duration};

use axum::{body::Body, http::Request};
use prefixd::{
    AppState,
    bgp::MockAnnouncer,
    config::{AuthMode, BgpMode, Settings, TlsConfig},
    db::MockRepository,
};
use tower::ServiceExt;

fn mtls_settings() -> Settings {
    let mut settings = common::test_settings();
    settings.http.auth.mode = AuthMode::Mtls;
    settings.http.tls = Some(TlsConfig {
        cert_path: "/private-fixture/server.pem".into(),
        key_path: "/private-fixture/key.pem".into(),
        ca_path: Some("/private-fixture/client-ca.pem".into()),
    });
    settings
}

/// The local-only test certificate, serving as its own client CA.
fn fixture_tls() -> TlsConfig {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bgp/testdata");
    TlsConfig {
        cert_path: fixture.join("server-cert.pem").to_string_lossy().into(),
        key_path: fixture.join("server-key.pem").to_string_lossy().into(),
        ca_path: Some(fixture.join("server-cert.pem").to_string_lossy().into()),
    }
}

fn invalid_settings() -> Vec<(&'static str, Settings)> {
    let mut cases = Vec::new();
    let mut missing_tls = mtls_settings();
    missing_tls.http.tls = None;
    cases.push(("http.tls", missing_tls));
    let mut missing_ca = mtls_settings();
    missing_ca.http.tls.as_mut().unwrap().ca_path = None;
    cases.push(("http.tls.ca_path", missing_ca));
    for empty in ["", " \t\n"] {
        for field in ["cert_path", "key_path", "ca_path"] {
            let mut settings = mtls_settings();
            let tls = settings.http.tls.as_mut().unwrap();
            let expected = match field {
                "cert_path" => {
                    tls.cert_path = empty.into();
                    "http.tls.cert_path"
                }
                "key_path" => {
                    tls.key_path = empty.into();
                    "http.tls.key_path"
                }
                _ => {
                    tls.ca_path = Some(empty.into());
                    "http.tls.ca_path"
                }
            };
            cases.push((expected, settings));
        }
    }
    cases
}

fn assert_config_error(error: &str, field: &str) {
    assert!(error.contains("auth.mode=mtls"), "{error}");
    assert!(error.contains(field), "{error}");
    assert!(!error.contains("private-fixture"), "{error}");
}

fn write_settings(directory: &Path, settings: &Settings) {
    common::write_yaml(
        directory,
        "prefixd.yaml",
        &serde_saphyr::to_string(settings).unwrap(),
    );
}

fn construct_state(settings: Settings, with_pool: bool) -> prefixd::error::Result<Arc<AppState>> {
    let repo = Arc::new(MockRepository::new());
    let speaker = Arc::new(MockAnnouncer::new());
    if with_pool {
        AppState::with_pool(
            settings,
            common::test_inventory(),
            common::test_playbooks(),
            repo,
            speaker,
            ".".into(),
            None,
        )
    } else {
        AppState::new(
            settings,
            common::test_inventory(),
            common::test_playbooks(),
            repo,
            speaker,
            ".".into(),
        )
    }
}

#[test]
fn invalid_mtls_settings_are_rejected_when_loaded() {
    let directory = tempfile::tempdir().unwrap();
    for (field, settings) in invalid_settings() {
        write_settings(directory.path(), &settings);
        let error = Settings::load(directory.path().join("prefixd.yaml"))
            .expect_err("invalid mTLS transport must fail config loading");
        assert_config_error(&error.to_string(), field);
    }
}

#[tokio::test]
async fn invalid_mtls_settings_are_rejected_by_both_state_constructors() {
    for (field, settings) in invalid_settings() {
        for with_pool in [false, true] {
            let error = construct_state(settings.clone(), with_pool)
                .err()
                .expect("invalid mTLS transport must fail state construction");
            assert_config_error(&error.to_string(), field);
        }
    }
}

#[tokio::test]
async fn valid_auth_transport_combinations_preserve_existing_modes() {
    let directory = tempfile::tempdir().unwrap();
    for mode in [
        AuthMode::None,
        AuthMode::Bearer,
        AuthMode::Credentials,
        AuthMode::Mtls,
    ] {
        for tls_enabled in [false, true] {
            if mode == AuthMode::Mtls && !tls_enabled {
                continue;
            }
            let mut settings = mtls_settings();
            settings.http.auth.mode = mode;
            if !tls_enabled {
                settings.http.tls = None;
            } else if mode != AuthMode::Mtls {
                settings.http.tls.as_mut().unwrap().ca_path = None;
            }
            // Reuse an existing nonempty process variable without mutating global env.
            settings.http.auth.bearer_token_env = Some("PATH".into());
            write_settings(directory.path(), &settings);
            Settings::load(directory.path().join("prefixd.yaml")).unwrap();
            for with_pool in [false, true] {
                let state = construct_state(settings.clone(), with_pool).unwrap();
                if mode == AuthMode::Mtls {
                    // Router-level control represents a request after native TLS verification.
                    let response = prefixd::api::create_test_router(state)
                        .oneshot(Request::get("/v1/operators").body(Body::empty()).unwrap())
                        .await
                        .unwrap();
                    assert_eq!(response.status(), axum::http::StatusCode::OK);
                }
            }
        }
    }
}

fn daemon(directory: &Path, database: &str) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_prefixd"));
    command
        .arg("--config")
        .arg(directory)
        .env("DATABASE_URL", database)
        .kill_on_drop(true);
    command
}

fn write_app_files(directory: &Path) {
    common::write_yaml(
        directory,
        "inventory.yaml",
        &serde_saphyr::to_string(&common::test_inventory()).unwrap(),
    );
    common::write_yaml(
        directory,
        "playbooks.yaml",
        &serde_saphyr::to_string(&common::test_playbooks()).unwrap(),
    );
}

#[tokio::test]
async fn invalid_mtls_daemon_exits_before_database_speaker_or_listener_startup() {
    let directory = tempfile::tempdir().unwrap();
    write_app_files(directory.path());
    let database = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let speaker = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    // An occupied HTTP address must not obscure the earlier configuration error.
    let http = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let database_url = format!(
        "postgres://probe:probe@{}/prefixd",
        database.local_addr().unwrap()
    );
    for (field, mut settings) in invalid_settings() {
        settings.http.listen = http.local_addr().unwrap().to_string();
        settings.bgp.mode = BgpMode::Gobgp;
        settings.bgp.gobgp_grpc = speaker.local_addr().unwrap().to_string();
        write_settings(directory.path(), &settings);
        for connection in ["invalid database URL", database_url.as_str()] {
            let mut command = daemon(directory.path(), connection);
            let output = tokio::select! {
                output = tokio::time::timeout(Duration::from_secs(5), command.output()) => output.unwrap().unwrap(),
                _ = database.accept() => panic!("invalid mTLS configuration reached the database"),
                _ = speaker.accept() => panic!("invalid mTLS configuration reached the speaker"),
            };
            assert!(!output.status.success());
            assert_config_error(&String::from_utf8_lossy(&output.stderr), field);
            for listener in [&database, &speaker] {
                assert!(
                    tokio::time::timeout(Duration::from_millis(25), listener.accept())
                        .await
                        .is_err()
                );
            }
        }
    }
    // Positive control: complete mTLS configuration with readable files
    // permits dependency startup, so the connection probe detects the same
    // binary when validation succeeds.
    let mut settings = mtls_settings();
    settings.http.tls = Some(fixture_tls());
    write_settings(directory.path(), &settings);
    let mut child = daemon(directory.path(), &database_url)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let connected = tokio::time::timeout(Duration::from_secs(5), database.accept()).await;
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    assert!(
        connected.is_ok(),
        "valid configuration must reach the database probe"
    );
}

#[tokio::test]
async fn valid_native_mtls_requires_a_client_certificate_and_retains_admin_access() {
    let ctx = common::TestContext::new().await;
    let directory = tempfile::tempdir().unwrap();
    write_app_files(directory.path());
    let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = reservation.local_addr().unwrap();
    let mut settings = mtls_settings();
    settings.http.listen = address.to_string();
    settings.http.tls = Some(fixture_tls());
    write_settings(directory.path(), &settings);
    // The existing local-only certificate has no restricted EKU; trust it directly
    // for this server/client control without adding another certificate fixture.
    let cert = include_bytes!("../src/bgp/testdata/server-cert.pem");
    let key = include_bytes!("../src/bgp/testdata/server-key.pem");
    let identity =
        reqwest::Identity::from_pem(&[cert.as_slice(), key.as_slice()].concat()).unwrap();
    let trusted = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(cert).unwrap())
        .identity(identity)
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let anonymous = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(cert).unwrap())
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    drop(reservation);
    let mut child = daemon(
        directory.path(),
        &ctx.state.settings.storage.connection_string,
    )
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .spawn()
    .unwrap();
    let endpoint = format!("https://{address}");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if trusted
                .get(format!("{endpoint}/v1/health"))
                .send()
                .await
                .is_ok()
            {
                break;
            }
            assert!(
                child.try_wait().unwrap().is_none(),
                "mTLS daemon exited before readiness"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("mTLS daemon did not become ready");
    assert!(
        anonymous
            .get(format!("{endpoint}/v1/health"))
            .send()
            .await
            .is_err()
    );
    let response = trusted
        .get(format!("{endpoint}/v1/operators"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}
