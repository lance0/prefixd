use chrono::{DateTime, Utc};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tokio::sync::{RwLock, broadcast};

use crate::alerting::AlertingService;
use crate::bgp::FlowSpecAnnouncer;
use crate::config::{AuthMode, Inventory, Playbooks, Settings};
use crate::correlation::CorrelationConfig;
use crate::db::RepositoryTrait;
use crate::domain::{SpeakerTarget, VerifiedSpeakerBinding, binding_mismatch};
use crate::error::{PrefixdError, Result};
use crate::ws::WsMessage;
use sqlx::PgPool;

/// Shared application state
pub struct AppState {
    pub settings: Settings,
    pub inventory: RwLock<Inventory>,
    pub playbooks: RwLock<Playbooks>,
    pub repo: Arc<dyn RepositoryTrait>,
    pub announcer: Arc<dyn FlowSpecAnnouncer>,
    pub shutdown_tx: broadcast::Sender<()>,
    /// WebSocket broadcast channel for real-time updates
    pub ws_broadcast: broadcast::Sender<WsMessage>,
    /// Cached bearer token (loaded at startup to avoid per-request env lookups)
    pub bearer_token: Option<String>,
    /// Server start time for uptime calculation
    pub start_time: Instant,
    /// Timestamp when inventory was last loaded/reloaded
    pub inventory_loaded_at: RwLock<DateTime<Utc>>,
    /// Timestamp when playbooks were last loaded/reloaded
    pub playbooks_loaded_at: RwLock<DateTime<Utc>>,
    /// Alerting service for webhook notifications (RwLock for hot-swap on config update)
    pub alerting: Arc<RwLock<Arc<AlertingService>>>,
    /// Timestamp when alerting config was last loaded
    pub alerting_loaded_at: RwLock<DateTime<Utc>>,
    /// Correlation engine configuration (RwLock for hot-reload)
    pub correlation_config: RwLock<CorrelationConfig>,
    /// Timestamp when correlation config was last loaded
    pub correlation_loaded_at: RwLock<DateTime<Utc>>,
    /// PostgreSQL pool for metrics (None in tests with MockRepository)
    pub db_pool: Option<PgPool>,
    /// Serializes lifecycle reads, speaker RPCs and commits within one controller.
    /// The interprocess guard is `fence`; this mutex does not cross processes.
    pub mitigation_lock: tokio::sync::Mutex<()>,
    /// Advisory-lock fence state (ADR 027). Standalone fixtures run unfenced (active).
    pub fence: Arc<crate::fence::ControllerFence>,
    /// The controller's injection lease when `blackhole.leased` is on (ADR 027).
    pub lease: Option<Arc<crate::domain::LeaseKeeper>>,
    /// The last reconciliation pass's blackhole export evidence (observation only).
    pub export_evidence: crate::domain::ExportEvidenceStore,
    /// FlowSpec uses the same epoch-fenced snapshot contract as blackholes.
    pub flowspec_export_evidence: crate::domain::ExportEvidenceStore,
    pub scrubber: crate::scrubber::ScrubberController,
    /// Directory containing config files (for hot-reload)
    pub config_dir: PathBuf,
    shutting_down: AtomicBool,
    speaker_binding: Option<VerifiedSpeakerBinding>,
}

impl AppState {
    pub fn new(
        settings: Settings,
        inventory: Inventory,
        playbooks: Playbooks,
        repo: Arc<dyn RepositoryTrait>,
        announcer: Arc<dyn FlowSpecAnnouncer>,
        config_dir: PathBuf,
    ) -> Result<Arc<Self>> {
        Self::with_pool(
            settings, inventory, playbooks, repo, announcer, config_dir, None,
        )
    }

    pub fn with_pool(
        settings: Settings,
        inventory: Inventory,
        playbooks: Playbooks,
        repo: Arc<dyn RepositoryTrait>,
        announcer: Arc<dyn FlowSpecAnnouncer>,
        config_dir: PathBuf,
        db_pool: Option<PgPool>,
    ) -> Result<Arc<Self>> {
        settings.http.validate_auth_transport()?;
        let (shutdown_tx, _) = broadcast::channel(1);
        let ws_broadcast = crate::ws::create_broadcast();
        let alerting = AlertingService::new(settings.alerting.clone());

        // Load bearer token at startup (avoids per-request env lookups)
        let bearer_token = if matches!(settings.http.auth.mode, AuthMode::Bearer) {
            let env_var = settings
                .http
                .auth
                .bearer_token_env
                .as_deref()
                .unwrap_or("PREFIXD_API_TOKEN");

            match std::env::var(env_var) {
                Ok(token) if !token.is_empty() => {
                    tracing::info!(env_var = %env_var, "loaded bearer token from environment");
                    Some(token)
                }
                _ => {
                    return Err(PrefixdError::Config(format!(
                        "auth.mode=bearer but {} is not set or empty",
                        env_var
                    )));
                }
            }
        } else {
            None
        };

        let correlation_config = settings.correlation.clone();
        let scrubber = crate::scrubber::ScrubberController::new(&settings)?;

        Ok(Arc::new(Self {
            settings,
            inventory: RwLock::new(inventory),
            playbooks: RwLock::new(playbooks),
            repo,
            announcer,
            shutdown_tx,
            ws_broadcast,
            bearer_token,
            alerting: Arc::new(RwLock::new(alerting)),
            alerting_loaded_at: RwLock::new(Utc::now()),
            correlation_config: RwLock::new(correlation_config),
            correlation_loaded_at: RwLock::new(Utc::now()),
            start_time: Instant::now(),
            inventory_loaded_at: RwLock::new(Utc::now()),
            playbooks_loaded_at: RwLock::new(Utc::now()),
            mitigation_lock: tokio::sync::Mutex::new(()),
            fence: Arc::new(crate::fence::ControllerFence::new(true)),
            lease: None,
            export_evidence: Default::default(),
            flowspec_export_evidence: Default::default(),
            scrubber,
            db_pool,
            config_dir,
            shutting_down: AtomicBool::new(false),
            speaker_binding: None,
        }))
    }

    /// Install the repository's startup proof before sharing state with any task.
    pub fn with_speaker_binding(
        mut self: Arc<Self>,
        binding: VerifiedSpeakerBinding,
    ) -> Result<Arc<Self>> {
        binding.validate(
            &self.settings.pop,
            &SpeakerTarget::from_config(&self.settings.bgp)?,
            self.announcer.backend(),
        )?;
        let state = Arc::get_mut(&mut self).ok_or_else(|| {
            PrefixdError::Internal(
                "speaker binding must be installed before sharing application state".into(),
            )
        })?;
        state.speaker_binding = Some(binding);
        Ok(self)
    }

    /// Install the process fence before sharing state; the announcer must be fenced by it too.
    pub fn with_fence(
        mut self: Arc<Self>,
        fence: Arc<crate::fence::ControllerFence>,
    ) -> Result<Arc<Self>> {
        let state = Arc::get_mut(&mut self).ok_or_else(|| {
            PrefixdError::Internal(
                "fence must be installed before sharing application state".into(),
            )
        })?;
        state.fence = fence;
        Ok(self)
    }

    /// Install the injection lease before sharing state.
    pub fn with_lease(
        mut self: Arc<Self>,
        lease: Arc<crate::domain::LeaseKeeper>,
    ) -> Result<Arc<Self>> {
        let state = Arc::get_mut(&mut self).ok_or_else(|| {
            PrefixdError::Internal(
                "lease must be installed before sharing application state".into(),
            )
        })?;
        state.lease = Some(lease);
        Ok(self)
    }

    /// Cheap local assertion; startup registration does the persistent validation.
    /// Only an explicitly selected mock paired with a mock speaker may be unbound.
    pub fn verified_speaker_binding(&self) -> Result<Option<&VerifiedSpeakerBinding>> {
        match &self.speaker_binding {
            Some(binding) => {
                binding.validate(
                    &self.settings.pop,
                    &SpeakerTarget::from_config(&self.settings.bgp)?,
                    self.announcer.backend(),
                )?;
                Ok(Some(binding))
            }
            None if self.settings.bgp.mode == crate::config::BgpMode::Mock
                && self.announcer.backend() == "mock" =>
            {
                Ok(None)
            }
            None => Err(binding_mismatch()),
        }
    }

    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    pub fn trigger_shutdown(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
        let _ = self.shutdown_tx.send(());
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }

    pub fn is_dry_run(&self) -> bool {
        matches!(self.settings.mode, crate::config::OperationMode::DryRun)
    }

    pub fn playbooks_path(&self) -> PathBuf {
        self.config_dir.join("playbooks.yaml")
    }

    pub fn alerting_path(&self) -> PathBuf {
        self.config_dir.join("alerting.yaml")
    }

    pub fn correlation_path(&self) -> PathBuf {
        self.config_dir.join("correlation.yaml")
    }

    /// Reload inventory, playbooks, correlation and alerting, all or nothing.
    ///
    /// Every present file is loaded and validated before any is published, so a
    /// failed reload leaves the running configuration unchanged. Lifecycle
    /// operations and config edits see the old set or the new set, never a mix:
    /// the lifecycle lock is taken first, then the editors' write guards, the
    /// same order the handlers use.
    pub async fn reload_config(&self) -> Result<ReloadReport> {
        let present = |name: &str| {
            let path = self.config_dir.join(name);
            path.exists().then_some(path)
        };
        let _mitigation_guard = self.mitigation_lock.lock().await;
        let mut playbooks_guard = self.playbooks.write().await;
        let mut alerting_guard = self.alerting.write().await;

        let inventory = present("inventory.yaml")
            .map(|path| Inventory::load(&path).map_err(|e| config_error("inventory", e)))
            .transpose()?;
        let playbooks = present("playbooks.yaml")
            .map(|path| {
                let playbooks = Playbooks::load(&path).map_err(|e| config_error("playbooks", e))?;
                let errors =
                    playbooks.check_settings(&self.settings, self.announcer.capabilities());
                if errors.is_empty() {
                    Ok(playbooks)
                } else {
                    Err(config_error("playbooks", errors.join("; ")))
                }
            })
            .transpose()?;
        let settings = present("prefixd.yaml")
            .map(|path| Settings::load(&path).map_err(|e| config_error("prefixd.yaml", e)))
            .transpose()?;
        let correlation_file = present("correlation.yaml")
            .map(|path| {
                CorrelationConfig::load(&path).map_err(|e| config_error("correlation.yaml", e))
            })
            .transpose()?;
        let alerting = present("alerting.yaml")
            .map(|path| {
                crate::alerting::AlertingConfig::load(&path)
                    .map_err(|e| config_error("alerting", e))
            })
            .transpose()?;
        let restart_required = match &settings {
            Some(file) => self.restart_required(file, alerting.is_some())?,
            None => Vec::new(),
        };
        let correlation = correlation_file.or(settings.map(|s| s.correlation));

        // Everything validated: publish.
        let now = Utc::now();
        let mut reloaded = Vec::new();
        if let Some(inventory) = inventory {
            *self.inventory.write().await = inventory;
            *self.inventory_loaded_at.write().await = now;
            reloaded.push("inventory".to_string());
        }
        if let Some(playbooks) = playbooks {
            *playbooks_guard = playbooks;
            *self.playbooks_loaded_at.write().await = now;
            reloaded.push("playbooks".to_string());
        }
        if let Some(correlation) = correlation {
            *self.correlation_config.write().await = correlation;
            *self.correlation_loaded_at.write().await = now;
            reloaded.push("correlation".to_string());
        }
        if let Some(alerting) = alerting {
            *alerting_guard = AlertingService::new(alerting);
            *self.alerting_loaded_at.write().await = now;
            reloaded.push("alerting".to_string());
        }
        tracing::info!(reloaded = ?reloaded, "reloaded configuration");
        if !restart_required.is_empty() {
            // Key names only; values may hold secrets.
            tracing::warn!(keys = ?restart_required, "prefixd.yaml changes need a restart");
        }
        Ok(ReloadReport {
            reloaded,
            restart_required,
        })
    }

    /// `prefixd.yaml` keys whose file value differs from the running settings.
    /// Correlation is hot-reloaded, as is alerting when `alerting.yaml` supplies it.
    fn restart_required(&self, file: &Settings, alerting_file: bool) -> Result<Vec<String>> {
        let to_value = |settings: &Settings| {
            let mut value = serde_json::to_value(settings)
                .map_err(|e| PrefixdError::Internal(format!("settings: {e}")))?;
            if let Some(object) = value.as_object_mut() {
                object.remove("correlation");
                if alerting_file {
                    object.remove("alerting");
                }
            }
            Ok::<_, PrefixdError>(value)
        };
        let mut keys = Vec::new();
        diff_keys("", &to_value(&self.settings)?, &to_value(file)?, &mut keys);
        Ok(keys)
    }
}

/// What a successful reload published and what still needs a restart.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReloadReport {
    pub reloaded: Vec<String>,
    pub restart_required: Vec<String>,
}

fn config_error(file: &str, error: impl std::fmt::Display) -> PrefixdError {
    PrefixdError::Config(format!("{file}: {error}"))
}

/// Dotted paths whose values differ; a key present on one side only differs.
fn diff_keys(path: &str, a: &serde_json::Value, b: &serde_json::Value, out: &mut Vec<String>) {
    use serde_json::Value;
    match (a, b) {
        (Value::Object(a), Value::Object(b)) => {
            let keys: std::collections::BTreeSet<&String> = a.keys().chain(b.keys()).collect();
            for key in keys {
                let path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                match (a.get(key), b.get(key)) {
                    (Some(a), Some(b)) => diff_keys(&path, a, b, out),
                    _ => out.push(path),
                }
            }
        }
        _ if a != b => out.push(path.to_string()),
        _ => {}
    }
}
