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
    /// same order the handlers use. Inventory has no editor, so it is parsed before the locks are taken.
    pub async fn reload_config(&self) -> std::result::Result<ReloadReport, ReloadError> {
        let present = |name: &str| {
            let path = self.config_dir.join(name);
            path.exists().then_some(path)
        };
        let inventory = present("inventory.yaml")
            .map(|path| Inventory::load(&path).map_err(|e| invalid("inventory.yaml", e)))
            .transpose()?;

        let _mitigation_guard = self.mitigation_lock.lock().await;
        let mut playbooks_guard = self.playbooks.write().await;
        let mut alerting_guard = self.alerting.write().await;
        let mut correlation_guard = self.correlation_config.write().await;

        let playbooks = present("playbooks.yaml")
            .map(|path| {
                let playbooks = Playbooks::load(&path).map_err(|e| invalid("playbooks.yaml", e))?;
                let errors =
                    playbooks.check_settings(&self.settings, self.announcer.capabilities());
                if errors.is_empty() {
                    Ok(playbooks)
                } else {
                    Err(invalid("playbooks.yaml", errors.join("; ")))
                }
            })
            .transpose()?;
        let settings = present("prefixd.yaml")
            .map(|path| Settings::load(&path).map_err(|e| invalid("prefixd.yaml", e)))
            .transpose()?;
        let correlation_file = present("correlation.yaml")
            .map(|path| CorrelationConfig::load(&path).map_err(|e| invalid("correlation.yaml", e)))
            .transpose()?;
        let alerting = present("alerting.yaml")
            .map(|path| {
                let alerting = crate::alerting::AlertingConfig::load(&path)
                    .map_err(|e| invalid("alerting.yaml", e))?;
                let errors = alerting.validate();
                if errors.is_empty() {
                    Ok(alerting)
                } else {
                    Err(invalid("alerting.yaml", errors.join("; ")))
                }
            })
            .transpose()?;
        let restart_required = match &settings {
            // Without `alerting.yaml`, inline alerting applies only at startup;
            // compare it with what is running, which an earlier reload may have set.
            Some(file) => {
                self.restart_required(file, alerting.is_none().then(|| alerting_guard.config()))?
            }
            None => Vec::new(),
        };
        let correlation = correlation_file.or(settings.map(|s| s.correlation));

        // Everything validated. Take the remaining guards, then publish with no
        // further await, so a canceled reload cannot publish only some sections.
        let mut inventory_guard = self.inventory.write().await;
        let mut inventory_loaded_at = self.inventory_loaded_at.write().await;
        let mut playbooks_loaded_at = self.playbooks_loaded_at.write().await;
        let mut correlation_loaded_at = self.correlation_loaded_at.write().await;
        let mut alerting_loaded_at = self.alerting_loaded_at.write().await;
        let now = Utc::now();
        let mut reloaded = Vec::new();
        if let Some(inventory) = inventory {
            *inventory_guard = inventory;
            *inventory_loaded_at = now;
            reloaded.push("inventory".to_string());
        }
        if let Some(playbooks) = playbooks {
            *playbooks_guard = playbooks;
            *playbooks_loaded_at = now;
            reloaded.push("playbooks".to_string());
        }
        if let Some(correlation) = correlation {
            *correlation_guard = correlation;
            *correlation_loaded_at = now;
            reloaded.push("correlation".to_string());
        }
        if let Some(alerting) = alerting {
            *alerting_guard = AlertingService::new(alerting);
            *alerting_loaded_at = now;
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
    /// Correlation is hot-reloaded. Alerting is compared with `running_alerting`
    /// when given, and skipped when `alerting.yaml` hot-reloads it.
    fn restart_required(
        &self,
        file: &Settings,
        running_alerting: Option<&crate::alerting::AlertingConfig>,
    ) -> Result<Vec<String>> {
        use crate::alerting::AlertingConfig;
        let internal = |e: serde_json::Error| PrefixdError::Internal(format!("settings: {e}"));
        let to_value = |settings: &Settings, alerting: Option<&AlertingConfig>| {
            let mut value = serde_json::to_value(settings).map_err(internal)?;
            if let Some(object) = value.as_object_mut() {
                object.remove("correlation");
                object.remove("alerting");
                if let Some(alerting) = alerting {
                    let alerting = serde_json::to_value(alerting).map_err(internal)?;
                    object.insert("alerting".into(), alerting);
                }
            }
            Ok::<_, PrefixdError>(value)
        };
        let running = to_value(&self.settings, running_alerting)?;
        let new = to_value(file, running_alerting.map(|_| &file.alerting))?;
        let mut keys = Vec::new();
        diff_keys("", &running, &new, &mut keys);
        Ok(keys)
    }
}

/// What a successful reload published and what still needs a restart.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReloadReport {
    pub reloaded: Vec<String>,
    pub restart_required: Vec<String>,
}

/// Why a reload failed. Nothing was published either way.
#[derive(Debug, thiserror::Error)]
pub enum ReloadError {
    /// A present file failed to load or validate.
    #[error("{file}: {detail}")]
    Invalid { file: &'static str, detail: String },
    #[error(transparent)]
    Internal(#[from] PrefixdError),
}

impl ReloadError {
    /// Operator-facing message. Loader text is echoed only for files that hold
    /// no secrets: `prefixd.yaml` and `alerting.yaml` errors can quote values.
    pub fn public_message(&self) -> String {
        match self {
            Self::Invalid { file, detail }
                if matches!(*file, "inventory.yaml" | "playbooks.yaml") =>
            {
                format!(
                    "reload failed: {file} is invalid: {detail}; running configuration unchanged"
                )
            }
            Self::Invalid { file, .. } => format!(
                "reload failed: {file} is invalid; running configuration unchanged; see controller log"
            ),
            Self::Internal(_) => {
                "reload failed; running configuration unchanged; see controller log".to_string()
            }
        }
    }
}

fn invalid(file: &'static str, error: impl std::fmt::Display) -> ReloadError {
    ReloadError::Invalid {
        file,
        detail: error.to_string(),
    }
}

/// Dotted paths whose values differ. A key on one side only reports its
/// parent, because map keys can be operator data.
fn diff_keys(path: &str, a: &serde_json::Value, b: &serde_json::Value, out: &mut Vec<String>) {
    use serde_json::Value;
    match (a, b) {
        (Value::Object(a), Value::Object(b)) => {
            let same_keys = a.len() == b.len() && a.keys().all(|key| b.contains_key(key));
            if !same_keys && !path.is_empty() {
                out.push(path.to_string());
                return;
            }
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

#[cfg(test)]
mod tests {
    use super::diff_keys;
    use serde_json::json;

    fn diff(a: serde_json::Value, b: serde_json::Value) -> Vec<String> {
        let mut out = Vec::new();
        diff_keys("", &a, &b, &mut out);
        out
    }

    #[test]
    fn diff_keys_reports_dotted_paths_and_never_values() {
        let running = json!({"timers": {"a": 1, "b": {"c": "x"}}, "pop": "p1", "list": [1]});
        assert!(diff(running.clone(), running.clone()).is_empty());
        assert_eq!(
            diff(
                running.clone(),
                json!({"timers": {"a": 1, "b": {"c": "y"}}, "pop": "p1", "list": [1]})
            ),
            ["timers.b.c"]
        );
        assert_eq!(
            diff(
                running.clone(),
                json!({"timers": {"a": 1, "b": {"c": "x"}}, "pop": "p1", "list": [2]})
            ),
            ["list"]
        );
        // Added and removed keys name the parent, not the (possibly data) key.
        assert_eq!(
            diff(
                running.clone(),
                json!({"timers": {"a": 1, "b": {"c": "x", "secret-name": 1}}, "pop": "p1", "list": [1]})
            ),
            ["timers.b"]
        );
        assert_eq!(
            diff(
                running.clone(),
                json!({"timers": {"b": {"c": "x"}}, "pop": "p1", "list": [1]})
            ),
            ["timers"]
        );
        // A top-level key is a schema field name.
        assert_eq!(
            diff(
                running,
                json!({"timers": {"a": 1, "b": {"c": "x"}}, "list": [1]})
            ),
            ["pop"]
        );
    }
}
