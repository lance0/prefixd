use super::*;
use crate::{
    AppState,
    bgp::*,
    config::OperationMode,
    domain::*,
    error::{PrefixdError, Result},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::{sync::Mutex, time::Instant};

/// Every window this controller issues expires within this interval of issue.
pub const WINDOW_SECONDS: u32 = 30;
/// rustbgpd's cap on any window's lifetime (ADR-0144 `H`). Draining intent that
/// another controller process admitted waits this long, because that process
/// may have issued longer windows than this one.
const SERVER_WINDOW_CAP: Duration = Duration::from_secs(120);
/// Lifecycle passes start this often. A pass still running after its budget is
/// cancelled and latches every profile, so consecutive renewals of one owner
/// are at most a period plus a budget apart.
const PASS_PERIOD_SECONDS: u64 = 5;
const PASS_BUDGET_SECONDS: u64 = 4;
/// A renewal caps the owner's deadline at its window's expiry. Reuse a cached
/// window only while it outlives the next renewal by a margin.
const WINDOW_REUSE: Duration = Duration::from_secs(PASS_PERIOD_SECONDS + PASS_BUDGET_SECONDS + 3);
/// Export reads stop this long after a pass starts, leaving the rest of the
/// budget to persist changes. Unread rows keep their earlier evidence.
const EXPORT_BUDGET: Duration = Duration::from_secs(3);
/// One export read never waits longer than this.
const EXPORT_READ: Duration = Duration::from_secs(2);

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessState {
    Ready,
    NotReady,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, Serialize, utoipa::ToSchema)]
pub struct ProfileState {
    pub armed: bool,
    pub ready: bool,
    pub readiness: ReadinessState,
    pub observed_at: Option<DateTime<Utc>>,
    pub latch_reason: Option<String>,
    #[serde(skip)]
    #[schema(ignore)]
    valid_until: Option<Instant>,
}

impl ProfileState {
    fn eligible(&self) -> bool {
        self.armed && self.ready && self.valid_until.is_some_and(|until| Instant::now() < until)
    }
    fn latch(&mut self, reason: &str) {
        if self.armed || self.latch_reason.is_none() {
            self.latch_reason = Some(reason.into());
        }
        self.armed = false;
    }
}

#[derive(Default)]
struct Runtime {
    profiles: HashMap<String, ProfileState>,
    drains: HashMap<Uuid, Instant>,
    windows: HashMap<String, (GuardedStamp, Instant)>,
    initialized: bool,
    epoch: Option<u64>,
    /// Rotates export reads so a fixed budget cannot always skip the same rows.
    export_cursor: usize,
}

/// One guarded inventory read, parsed once so per-row checks stay linear.
struct Observed<'a> {
    /// Destination and key of every local rule, guarded or ordinary.
    selectors: Vec<(ipnet::IpNet, String)>,
    /// Key to guarded entry.
    guarded: HashMap<String, &'a GuardedObservation>,
}

impl<'a> Observed<'a> {
    fn new(inventory: &'a GuardedInventory) -> Result<Self> {
        let mut selectors = Vec::with_capacity(inventory.len() + inventory.other_matches.len());
        let mut guarded = HashMap::with_capacity(inventory.len());
        for nlri in inventory
            .iter()
            .map(|entry| &entry.rule.nlri)
            .chain(inventory.other_matches.iter())
        {
            let prefix = nlri
                .dst_prefix
                .parse::<ipnet::IpNet>()
                .map_err(|_| PrefixdError::Internal("invalid local speaker inventory".into()))?;
            selectors.push((prefix, nlri.compute_hash()));
        }
        for (entry, (_, key)) in inventory.iter().zip(&selectors) {
            guarded.insert(key.clone(), entry);
        }
        Ok(Self { selectors, guarded })
    }
    /// Another local rule, guarded or ordinary, affects this row's victim.
    fn foreign_victim_overlap(&self, row: &Diversion, key: &str) -> Result<bool> {
        let victim = row
            .rule
            .nlri
            .dst_prefix
            .parse::<ipnet::IpNet>()
            .map_err(|_| PrefixdError::Internal("invalid saved diversion".into()))?
            .addr();
        Ok(self
            .selectors
            .iter()
            .any(|(prefix, other)| prefix.contains(&victim) && other != key))
    }
    fn has_key(&self, key: &str) -> bool {
        self.selectors.iter().any(|(_, other)| other == key)
    }
}

/// The safelist read once per pass, with the repository's overlap semantics.
fn safelisted(entries: &[crate::db::SafelistEntry], victim: std::net::IpAddr) -> Result<bool> {
    for entry in entries {
        let prefix = entry
            .prefix
            .parse::<ipnet::IpNet>()
            .or_else(|_| {
                entry
                    .prefix
                    .parse::<std::net::IpAddr>()
                    .map(ipnet::IpNet::from)
            })
            .map_err(|_| PrefixdError::Internal("invalid safelist prefix".into()))?;
        if prefix.contains(&victim) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Replace export evidence, keeping unchanged evidence and its first
/// observation time so a steady pass writes nothing. A failed read keeps the
/// last successful peers as historical evidence beside the error.
fn observe_exports(row: &mut Diversion, result: std::result::Result<Vec<PeerExport>, &str>) {
    let previous = row.export_observation.take();
    let next = match result {
        Ok(peers) => DiversionExportObservation {
            observed_at: Utc::now(),
            peers,
            error: None,
        },
        Err(error) => DiversionExportObservation {
            error: Some(error.into()),
            ..previous.clone().unwrap_or(DiversionExportObservation {
                observed_at: Utc::now(),
                peers: vec![],
                error: None,
            })
        },
    };
    row.export_observation = Some(match previous {
        Some(previous) if previous.peers == next.peers && previous.error == next.error => previous,
        _ => next,
    });
}

/// The persisted lifecycle fields a pass may change.
fn lifecycle(
    row: &Diversion,
) -> (
    DiversionStatus,
    Option<GuardedStamp>,
    Option<String>,
    Option<String>,
    Option<DiversionExportObservation>,
) {
    (
        row.status,
        row.generation,
        row.withdrawal_reason.clone(),
        row.last_error.clone(),
        row.export_observation.clone(),
    )
}

pub struct ScrubberController {
    incarnation: Uuid,
    runtime: Mutex<Runtime>,
    client: reqwest::Client,
    tokens: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Readiness {
    profile: String,
    revision: String,
    policy_binding: String,
    observed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    process_ready: bool,
    filters_ready: bool,
    target_reachable: bool,
    capacity_available: bool,
    canary_passed: bool,
    export_isolated: bool,
}

impl Readiness {
    fn state(self, profile: &ScrubberProfile, now: DateTime<Utc>) -> Result<ProfileState> {
        if self.profile != profile.id
            || self.revision != profile.revision
            || self.policy_binding != profile.policy_binding
            || self.observed_at > now + chrono::Duration::seconds(2)
            || self.valid_until <= now
            || self.valid_until <= self.observed_at
            || self.valid_until - self.observed_at > chrono::Duration::seconds(10)
        {
            return Err(PrefixdError::InvalidRequest(
                "stale or mismatched scrubber readiness".into(),
            ));
        }
        let ready = self.process_ready
            && self.filters_ready
            && self.target_reachable
            && self.capacity_available
            && self.canary_passed
            && self.export_isolated;
        Ok(ProfileState {
            ready,
            readiness: if ready {
                ReadinessState::Ready
            } else {
                ReadinessState::NotReady
            },
            observed_at: Some(self.observed_at),
            valid_until: Some(
                Instant::now()
                    + (self.valid_until - now)
                        .to_std()
                        .map_err(|_| PrefixdError::InvalidRequest("expired readiness".into()))?,
            ),
            ..Default::default()
        })
    }
}

impl ScrubberController {
    /// A profile may not disappear or retarget while its original withdrawal
    /// obligations remain. Startup stays unarmed even when configuration agrees.
    pub async fn check_startup(state: &AppState) -> Result<()> {
        let rows = state.repo.list_diversions(&state.settings.pop).await?;
        for row in rows {
            if !state.settings.scrubber.enabled || state.settings.mode != OperationMode::Enforced {
                return Err(PrefixdError::Config(
                    "drain enforced diversions before disabling scrubbers or changing mode".into(),
                ));
            }
            let profile = Self::profile(state, &row.profile.id).map_err(|_| {
                PrefixdError::Config(
                    "drain outstanding diversion before removing its profile".into(),
                )
            })?;
            if profile.snapshot() != row.profile
                || profile.target(row.rule.target.is_ipv4())? != row.rule.target
                || Self::owner(state, &profile.id)? != row.rule.owner
            {
                return Err(PrefixdError::Config(
                    "drain outstanding diversion before changing its profile or policy binding"
                        .into(),
                ));
            }
        }
        Ok(())
    }

    pub fn new(settings: &crate::config::Settings) -> Result<Self> {
        settings.scrubber.validate()?;
        let mut runtime = Runtime::default();
        let mut tokens = HashMap::new();
        for profile in &settings.scrubber.profiles {
            crate::observability::metrics::SCRUBBER_READY
                .with_label_values(&[&profile.id])
                .set(0.0);
            crate::observability::metrics::SCRUBBER_ARMED
                .with_label_values(&[&profile.id])
                .set(0.0);
            runtime.profiles.insert(
                profile.id.clone(),
                ProfileState {
                    latch_reason: Some("startup: explicit re-arm required".into()),
                    ..Default::default()
                },
            );
            if settings.scrubber.enabled && settings.mode == OperationMode::Enforced {
                let token = std::env::var(&profile.readiness_token_env)
                    .ok()
                    .filter(|v| !v.is_empty() && v.len() <= 4096 && !v.contains(['\r', '\n']))
                    .ok_or_else(|| {
                        PrefixdError::Config(
                            "scrubber readiness credential is missing or invalid".into(),
                        )
                    })?;
                tokens.insert(profile.id.clone(), token);
            }
        }
        let mut client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .https_only(true);
        if let Some(path) = &settings.scrubber.readiness_ca_cert {
            let pem = std::fs::read(path).map_err(|_| {
                PrefixdError::Config("cannot read scrubber readiness CA certificate".into())
            })?;
            if pem.len() > 262_144 {
                return Err(PrefixdError::Config(
                    "scrubber readiness CA certificate is too large".into(),
                ));
            }
            let certificate = reqwest::Certificate::from_pem(&pem).map_err(|_| {
                PrefixdError::Config("invalid scrubber readiness CA certificate".into())
            })?;
            client = client.add_root_certificate(certificate);
        }
        let client = client.build().map_err(|_| {
            PrefixdError::Config("cannot initialize scrubber readiness client".into())
        })?;
        Ok(Self {
            incarnation: Uuid::new_v4(),
            runtime: Mutex::new(runtime),
            client,
            tokens,
        })
    }

    fn profile<'a>(state: &'a AppState, id: &str) -> Result<&'a ScrubberProfile> {
        if !state.settings.scrubber.enabled {
            return Err(PrefixdError::Conflict(
                "scrubber diversion is disabled".into(),
            ));
        }
        state
            .settings
            .scrubber
            .profiles
            .iter()
            .find(|p| p.id == id)
            .ok_or_else(|| PrefixdError::NotFound("unknown scrubber profile".into()))
    }

    async fn probe(&self, profile: &ScrubberProfile) -> Result<ProfileState> {
        let token = self
            .tokens
            .get(&profile.id)
            .ok_or_else(|| PrefixdError::Config("readiness credential unavailable".into()))?;
        let mut response = self
            .client
            .get(&profile.readiness_url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|_| PrefixdError::Internal("scrubber readiness unavailable".into()))?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(PrefixdError::Internal("scrubber readiness refused".into()));
        }
        let mut body = vec![];
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| PrefixdError::Internal("scrubber readiness read failed".into()))?
        {
            if body.len() + chunk.len() > 4096 {
                return Err(PrefixdError::Internal(
                    "scrubber readiness response too large".into(),
                ));
            }
            body.extend(chunk);
        }
        let report: Readiness = serde_json::from_slice(&body)
            .map_err(|_| PrefixdError::Internal("invalid scrubber readiness response".into()))?;
        report.state(profile, Utc::now())
    }

    fn latch_all(runtime: &mut Runtime, reason: &str) {
        runtime.windows.clear();
        for (id, profile) in runtime.profiles.iter_mut() {
            profile.latch(reason);
            crate::observability::metrics::SCRUBBER_ARMED
                .with_label_values(&[id])
                .set(0.0);
        }
        Self::publish_profiles(&runtime.profiles);
    }

    fn publish_profiles(profiles: &HashMap<String, ProfileState>) {
        for (id, profile) in profiles {
            let fresh = profile
                .valid_until
                .is_some_and(|until| Instant::now() < until);
            crate::observability::metrics::SCRUBBER_READY
                .with_label_values(&[id])
                .set(f64::from(u8::from(profile.ready && fresh)));
            crate::observability::metrics::SCRUBBER_ARMED
                .with_label_values(&[id])
                .set(f64::from(u8::from(profile.armed)));
        }
    }

    fn failed(runtime: &mut Runtime, row: &mut Diversion, reason: &str) {
        if let Some(profile) = runtime.profiles.get_mut(&row.profile.id) {
            profile.latch(reason);
        }
        runtime.windows.remove(&row.profile.id);
        row.status = DiversionStatus::Withdrawing;
        row.withdrawal_reason.get_or_insert(reason.into());
        row.last_error = Some("local lifecycle could not be confirmed".into());
        crate::observability::metrics::SCRUBBER_LIFECYCLE_FAILURES.inc();
        Self::publish_profiles(&runtime.profiles);
    }

    fn expire_readiness(runtime: &mut Runtime) {
        for (id, profile) in &mut runtime.profiles {
            if !profile
                .valid_until
                .is_some_and(|until| Instant::now() < until)
            {
                profile.ready = false;
                profile.readiness = ReadinessState::Unknown;
                if profile.armed {
                    profile.latch("readiness expired; explicit re-arm required");
                    runtime.windows.remove(id);
                }
            }
        }
    }

    fn ensure_epoch(state: &AppState, runtime: &mut Runtime) -> Result<()> {
        let epoch = state.fence.with_observation_epoch(|epoch| epoch);
        if epoch.is_none() || epoch != runtime.epoch {
            Self::latch_all(runtime, "controller ownership changed");
            return Err(PrefixdError::Standby);
        }
        Ok(())
    }

    pub async fn profiles(&self) -> HashMap<String, ProfileState> {
        let mut runtime = self.runtime.lock().await;
        Self::expire_readiness(&mut runtime);
        Self::publish_profiles(&runtime.profiles);
        runtime.profiles.clone()
    }

    pub async fn arm(&self, state: &AppState, id: &str, revision: &str, actor: &str) -> Result<()> {
        let profile = Self::profile(state, id)?;
        if profile.revision != revision {
            return Err(PrefixdError::Conflict("profile revision changed".into()));
        }
        let fresh = self.probe(profile).await?;
        let mut runtime = self.runtime.lock().await;
        Self::expire_readiness(&mut runtime);
        let _guard = state.mitigation_lock.lock().await;
        state.fence.ensure_active()?;
        state.verified_speaker_binding()?;
        if !runtime.initialized
            || !fresh.ready
            || !fresh
                .valid_until
                .is_some_and(|until| Instant::now() < until)
            || state
                .repo
                .list_diversions(&state.settings.pop)
                .await?
                .iter()
                .any(|row| row.profile.id == id)
        {
            return Err(PrefixdError::Conflict(
                "re-arm requires fresh readiness and completed local withdrawal".into(),
            ));
        }
        if runtime
            .profiles
            .get(id)
            .is_some_and(|profile| profile.armed)
        {
            return Err(PrefixdError::Conflict("profile is already armed".into()));
        }
        // Successful issue proves the released guarded entry point, without adding a rule.
        let speaker = state
            .announcer
            .guarded_flowspec()
            .ok_or_else(|| PrefixdError::Config("guarded FlowSpec unsupported".into()))?;
        let owner = Self::owner(state, id)?;
        if speaker
            .guarded_inventory()
            .await?
            .iter()
            .any(|entry| entry.rule.owner == owner)
        {
            return Err(PrefixdError::Conflict(
                "profile owner still holds guarded intent; re-arm is refused".into(),
            ));
        }
        Self::ensure_epoch(state, &mut runtime)?;
        speaker.issue_window(&owner, WINDOW_SECONDS).await?;
        state
            .repo
            .insert_audit(&crate::observability::AuditEntry::new(
                crate::observability::ActorType::Operator,
                Some(actor.into()),
                "scrubber_arm",
                Some("scrubber_profile"),
                Some(id.into()),
                serde_json::json!({"revision":revision}),
            ))
            .await?;
        Self::ensure_epoch(state, &mut runtime)?;
        if !fresh
            .valid_until
            .is_some_and(|until| Instant::now() < until)
        {
            return Err(PrefixdError::Conflict(
                "readiness expired before re-arm".into(),
            ));
        }
        runtime.profiles.insert(
            id.into(),
            ProfileState {
                armed: true,
                latch_reason: None,
                ..fresh
            },
        );
        runtime.windows.remove(id);
        Self::publish_profiles(&runtime.profiles);
        let _ = state
            .ws_broadcast
            .send(crate::ws::WsMessage::ScrubberUpdated {
                profile: id.into(),
                state: runtime.profiles[id].clone(),
            });
        Ok(())
    }

    fn owner(state: &AppState, id: &str) -> Result<String> {
        let binding = state
            .verified_speaker_binding()?
            .ok_or_else(|| PrefixdError::Config("scrubber needs a registered speaker".into()))?;
        let hash = Sha256::new()
            .chain_update(binding.owner().as_bytes())
            .chain_update(b"\0scrubber\0")
            .chain_update(id.as_bytes())
            .finalize();
        Ok(format!("prefixd.scrub.{}", hex::encode(&hash[..16])))
    }

    pub async fn prepare(
        &self,
        state: &AppState,
        req: &super::api::CreateDiversion,
        actor: &str,
    ) -> Result<Diversion> {
        let profile = Self::profile(state, &req.profile)?;
        state.verified_speaker_binding()?;
        let mut nlri = req.scope.clone();
        let prefix: ipnet::IpNet = nlri
            .dst_prefix
            .parse()
            .map_err(|_| PrefixdError::InvalidRequest("diversion needs a host CIDR".into()))?;
        nlri.dst_prefix = prefix.to_string();
        if prefix.prefix_len() != prefix.max_prefix_len()
            || !profile
                .destinations
                .iter()
                .any(|net| net.contains(&prefix.addr()))
            || req.ttl_seconds == 0
            || req.ttl_seconds > profile.max_ttl_seconds
            || req.reason.trim().is_empty()
            || req.reason.len() > 1024
        {
            return Err(PrefixdError::InvalidRequest(
                "invalid diversion host, lifetime or reason".into(),
            ));
        }
        nlri.dst_ports = canonical_ports(&nlri.dst_ports);
        nlri.src_ports = canonical_ports(&nlri.src_ports);
        nlri.src_prefix = nlri
            .src_prefix
            .as_deref()
            .map(canonical_source_prefix)
            .transpose()
            .map_err(|e| PrefixdError::InvalidRequest(e.to_string()))?;
        let context = state
            .inventory
            .read()
            .await
            .lookup_prefix(&prefix)?
            .ok_or_else(|| {
                PrefixdError::InvalidRequest(
                    "diversion requires unambiguous inventory ownership".into(),
                )
            })?;
        let criteria: MatchCriteria = serde_json::from_value(serde_json::to_value(&nlri)?)?;
        let intent = MitigationIntent {
            event_id: Uuid::new_v4(),
            customer_id: Some(context.customer_id.clone()),
            service_id: None,
            pop: state.settings.pop.clone(),
            match_criteria: criteria,
            action_type: ActionType::Discard,
            action_params: ActionParams::default(),
            ttl_seconds: req.ttl_seconds,
            reason: req.reason.clone(),
        };
        crate::guardrails::Guardrails::with_timers(
            state.settings.guardrails.clone(),
            state.settings.quotas.clone(),
            &state.settings.timers,
        )
        .validate(
            &intent,
            state.repo.as_ref(),
            state.repo.is_safelisted(&nlri.dst_prefix).await?,
        )
        .await?;
        let rule = GuardedRule {
            nlri,
            target: profile.target(prefix.addr().is_ipv4())?,
            owner: Self::owner(state, &profile.id)?,
            revision: 1,
        };
        rule.validate()?;
        Ok(Diversion {
            id: Uuid::new_v4(),
            controller_incarnation: self.incarnation,
            controller_epoch: state
                .fence
                .with_observation_epoch(|epoch| epoch)
                .unwrap_or_default(),
            pop: state.settings.pop.clone(),
            customer_id: context.customer_id,
            profile: profile.snapshot(),
            rule,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(req.ttl_seconds.into()),
            actor: actor.into(),
            reason: req.reason.clone(),
            dry_run: state.settings.mode == OperationMode::DryRun,
            status: if state.settings.mode == OperationMode::DryRun {
                DiversionStatus::Simulated
            } else {
                DiversionStatus::Pending
            },
            withdrawal_reason: None,
            withdrawal_actor: None,
            windows: vec![],
            generation: None,
            last_error: None,
            export_observation: None,
        })
    }

    pub fn confirmation(row: &Diversion) -> Result<String> {
        Ok(format!(
            "{} -> {} via {}@{}",
            serde_json::to_string(&row.rule.nlri)?,
            row.rule.target,
            row.profile.id,
            row.profile.revision
        ))
    }

    pub async fn create(
        &self,
        state: &AppState,
        req: &super::api::CreateDiversion,
        actor: &str,
    ) -> Result<Diversion> {
        let mut runtime = self.runtime.lock().await;
        Self::expire_readiness(&mut runtime);
        let _guard = state.mitigation_lock.lock().await;
        state.fence.ensure_active()?;
        if state.settings.mode == OperationMode::Enforced {
            Self::ensure_epoch(state, &mut runtime)?;
        }
        let row = match self.prepare(state, req, actor).await {
            Ok(row) => row,
            Err(error) => {
                if error.status_code().is_server_error() {
                    Self::latch_all(&mut runtime, "durable admission checks unavailable");
                }
                return Err(error);
            }
        };
        if req.confirmation.as_deref() != Some(Self::confirmation(&row)?.as_str()) {
            return Err(PrefixdError::InvalidRequest(
                "confirm the complete match, target and profile revision from preview".into(),
            ));
        }
        if !row.dry_run
            && (!runtime.initialized
                || !runtime
                    .profiles
                    .get(&row.profile.id)
                    .is_some_and(ProfileState::eligible))
        {
            return Err(PrefixdError::Conflict(
                "profile must be ready and explicitly armed".into(),
            ));
        }
        let admitted = state
            .repo
            .admit_diversion(
                &row,
                Self::profile(state, &row.profile.id)?,
                &state.settings.quotas,
            )
            .await;
        let mut row = match admitted {
            Ok(row) => row,
            Err(error) => {
                if error.status_code().is_server_error() {
                    Self::latch_all(&mut runtime, "durable admission outcome unknown");
                }
                return Err(error);
            }
        };
        if !row.dry_run {
            if let Err(error) = self.drive(state, &mut runtime, &mut row).await {
                if state.fence.with_observation_epoch(|epoch| epoch) != runtime.epoch {
                    return Err(PrefixdError::Standby);
                }
                Self::failed(
                    &mut runtime,
                    &mut row,
                    "admission could not be confirmed; explicit re-arm required",
                );
                tracing::warn!(code = %error.status_code(), "scrubber admission latched");
                if let Err(error) = state.repo.save_diversion(&row, "scrubber_latched").await {
                    Self::latch_all(&mut runtime, "durable withdrawal unavailable");
                    return Err(error);
                }
            }
            Self::ensure_epoch(state, &mut runtime)?;
        }
        let _ = state
            .ws_broadcast
            .send(crate::ws::WsMessage::DiversionUpdated {
                diversion: row.clone(),
            });
        Ok(row)
    }

    pub async fn withdraw(
        &self,
        state: &AppState,
        id: Uuid,
        actor: &str,
        reason: Option<String>,
    ) -> Result<Diversion> {
        if reason
            .as_deref()
            .is_some_and(|reason| reason.trim().is_empty() || reason.len() > 1024)
        {
            return Err(PrefixdError::InvalidRequest(
                "reason must contain text and be at most 1024 UTF-8 bytes".into(),
            ));
        }
        let mut runtime = self.runtime.lock().await;
        let _guard = state.mitigation_lock.lock().await;
        state.fence.ensure_active()?;
        if state.settings.mode == OperationMode::Enforced {
            Self::ensure_epoch(state, &mut runtime)?;
        }
        let mut row = state
            .repo
            .get_diversion(id)
            .await?
            .ok_or_else(|| PrefixdError::NotFound("unknown diversion".into()))?;
        if row.pop != state.settings.pop {
            return Err(PrefixdError::Conflict(
                "diversion belongs to another POP".into(),
            ));
        }
        if row.status.outstanding() {
            row.status = DiversionStatus::Withdrawing;
            // The first withdrawal reason and requester are immutable.
            if row.withdrawal_reason.is_none() {
                row.withdrawal_reason =
                    Some(reason.unwrap_or_else(|| format!("operator withdrawal by {actor}")));
            }
            row.withdrawal_actor.get_or_insert(actor.into());
            state
                .repo
                .save_diversion(&row, "scrubber_withdraw_requested")
                .await?;
            if let Err(error) = self.drive(state, &mut runtime, &mut row).await {
                Self::ensure_epoch(state, &mut runtime)?;
                let before = lifecycle(&row);
                Self::failed(&mut runtime, &mut row, "withdrawal could not be confirmed");
                tracing::warn!(code = %error.status_code(), "scrubber withdrawal remains pending");
                if before != lifecycle(&row)
                    && let Err(error) = state
                        .repo
                        .save_diversion(&row, "scrubber_withdraw_unconfirmed")
                        .await
                {
                    Self::latch_all(&mut runtime, "durable withdrawal unavailable");
                    return Err(error);
                }
            }
            Self::ensure_epoch(state, &mut runtime)?;
        }
        let _ = state
            .ws_broadcast
            .send(crate::ws::WsMessage::DiversionUpdated {
                diversion: row.clone(),
            });
        Ok(row)
    }

    /// Reconcile one row outside a lifecycle pass: admission or withdrawal.
    async fn drive(
        &self,
        state: &AppState,
        runtime: &mut Runtime,
        row: &mut Diversion,
    ) -> Result<()> {
        let durable = if row.status == DiversionStatus::Withdrawing {
            vec![]
        } else {
            state.repo.list_diversions(&state.settings.pop).await?
        };
        let deadline = Instant::now() + EXPORT_READ;
        match self
            .reconcile(
                state,
                runtime,
                std::slice::from_mut(row),
                &durable,
                deadline,
            )
            .await?
            .pop()
            .flatten()
        {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Whether durable intent still authorizes a live diversion.
    fn authorized(
        &self,
        state: &AppState,
        runtime: &Runtime,
        inventory: &crate::config::Inventory,
        safelist: &[crate::db::SafelistEntry],
        row: &Diversion,
    ) -> Result<bool> {
        let prefix: ipnet::IpNet = row
            .rule
            .nlri
            .dst_prefix
            .parse()
            .map_err(|_| PrefixdError::InvalidRequest("invalid saved diversion".into()))?;
        Ok(row.controller_incarnation == self.incarnation
            && Some(row.controller_epoch) == runtime.epoch
            && runtime
                .profiles
                .get(&row.profile.id)
                .is_some_and(ProfileState::eligible)
            && row.expires_at > Utc::now()
            && Self::profile(state, &row.profile.id).is_ok_and(|p| {
                p.snapshot() == row.profile
                    && p.target(row.rule.target.is_ipv4()).ok() == Some(row.rule.target)
            })
            && Self::owner(state, &row.profile.id)? == row.rule.owner
            && !safelisted(safelist, prefix.addr())?
            && inventory
                .lookup_prefix(&prefix)?
                .is_some_and(|owner| owner.customer_id == row.customer_id))
    }

    /// One serialized lifecycle step over durable rows. It reads the guarded
    /// inventory once, issues at most one window and one renewal per owner,
    /// reads back once and bounds export reads by `export_deadline`. Speaker
    /// work therefore grows with the number of profiles, not diversions.
    ///
    /// Returns each row's failure for the caller to latch. Authorization loss
    /// and a slow or failed export read are not failures: the first withdraws
    /// the row and the second degrades its evidence. `Err` applies to every row.
    async fn reconcile(
        &self,
        state: &AppState,
        runtime: &mut Runtime,
        rows: &mut [Diversion],
        durable: &[Diversion],
        export_deadline: Instant,
    ) -> Result<Vec<Option<PrefixdError>>> {
        use DiversionStatus::{Active, Pending, Withdrawing, Withdrawn};
        let conflict = |reason: &str| Some(PrefixdError::Conflict(reason.into()));
        Self::expire_readiness(runtime);
        state.fence.ensure_active()?;
        state.verified_speaker_binding()?;
        let speaker = state
            .announcer
            .guarded_flowspec()
            .ok_or_else(|| PrefixdError::Config("guarded FlowSpec unsupported".into()))?;
        Self::ensure_epoch(state, runtime)?;
        let mut failures: Vec<Option<PrefixdError>> = rows.iter().map(|_| None).collect();
        let before: Vec<_> = rows.iter().map(lifecycle).collect();

        // Durable withdrawal precedes any delete for intent that lost authorization.
        if rows.iter().any(|row| row.status != Withdrawing) {
            let safelist = state.repo.list_safelist().await?;
            let authorized = {
                let inventory = state.inventory.read().await;
                rows.iter()
                    .map(|row| {
                        Ok(row.status == Withdrawing
                            || self.authorized(state, runtime, &inventory, &safelist, row)?)
                    })
                    .collect::<Result<Vec<_>>>()?
            };
            for ((row, failure), authorized) in rows.iter_mut().zip(&mut failures).zip(authorized) {
                if authorized {
                    continue;
                }
                row.status = Withdrawing;
                row.withdrawal_reason.get_or_insert(
                    "readiness, lifetime, ownership or configuration no longer authorizes diversion"
                        .into(),
                );
                if let Err(error) = state
                    .repo
                    .save_diversion(row, "scrubber_withdraw_requested")
                    .await
                {
                    *failure = Some(error);
                }
            }
        }

        // Delete early to restore ordinary routing, but retain durable exclusion
        // until old adds are unable to commit and a final exact delete/read passes.
        let mut finalize = vec![];
        for (index, row) in rows.iter().enumerate() {
            if failures[index].is_some() || row.status != Withdrawing {
                continue;
            }
            // Only this process's windows have a known lifetime.
            let wait = if row.controller_incarnation == self.incarnation {
                Duration::from_secs(WINDOW_SECONDS.into())
            } else {
                SERVER_WINDOW_CAP
            };
            let barrier = *runtime
                .drains
                .entry(row.id)
                .or_insert_with(|| Instant::now() + wait);
            match speaker.delete_guarded(&row.rule).await {
                Ok(()) if Instant::now() >= barrier => finalize.push(index),
                Ok(()) => {}
                Err(error) => failures[index] = Some(error),
            }
        }

        let live: Vec<usize> = (0..rows.len())
            .filter(|&index| failures[index].is_none() && rows[index].status != Withdrawing)
            .collect();
        if live.is_empty() && finalize.is_empty() {
            return Ok(failures);
        }
        let inventory = match speaker.guarded_inventory().await {
            Ok(inventory) => inventory,
            Err(error) => {
                tracing::warn!(code = %error.status_code(), "guarded inventory unavailable");
                for &index in live.iter().chain(&finalize) {
                    failures[index] = conflict("guarded inventory unavailable");
                }
                return Ok(failures);
            }
        };
        let observed = Observed::new(&inventory)?;
        for index in finalize {
            let row = &mut rows[index];
            if observed.has_key(&row.rule.nlri.compute_hash()) {
                failures[index] = conflict("diversion withdrawal is not confirmed");
                continue;
            }
            row.status = Withdrawn;
            row.last_error = None;
            Self::ensure_epoch(state, runtime)?;
            match state.repo.save_diversion(row, "scrubber_withdrawn").await {
                Ok(()) => {
                    runtime.drains.remove(&row.id);
                }
                Err(error) => failures[index] = Some(error),
            }
        }
        if live.is_empty() {
            return Ok(failures);
        }

        // Adopt an owner only when its complete inventory matches this
        // controller's durable intent.
        let mut known: HashMap<&str, std::collections::HashSet<(String, u64, std::net::IpAddr)>> =
            HashMap::new();
        let mut disputed = std::collections::HashSet::new();
        for intent in durable {
            known
                .entry(intent.rule.owner.as_str())
                .or_default()
                .insert((
                    intent.rule.nlri.compute_hash(),
                    intent.rule.revision,
                    intent.rule.target,
                ));
            if intent.controller_incarnation != self.incarnation
                || Some(intent.controller_epoch) != runtime.epoch
            {
                disputed.insert(intent.rule.owner.as_str());
            }
        }
        for (key, entry) in &observed.guarded {
            if known
                .get(entry.rule.owner.as_str())
                .is_some_and(|admissions| {
                    !admissions.contains(&(key.clone(), entry.rule.revision, entry.rule.target))
                })
            {
                disputed.insert(entry.rule.owner.as_str());
            }
        }
        let mut owners: HashMap<String, Vec<usize>> = HashMap::new();
        for &index in &live {
            let row = &mut rows[index];
            let key = row.rule.nlri.compute_hash();
            let existing = observed.guarded.get(&key);
            failures[index] = if disputed.contains(row.rule.owner.as_str())
                || !known.contains_key(row.rule.owner.as_str())
            {
                conflict("guarded owner inventory disagrees with this controller's durable intent")
            } else if observed.foreign_victim_overlap(row, &key)? {
                conflict("another local rule affects the diversion victim")
            } else if existing.is_none() && observed.has_key(&key) {
                conflict("diversion key is held by ordinary or foreign intent")
            } else if existing.is_some_and(|existing| {
                !existing.rule.same_admission(&row.rule)
                    || existing.remaining_ms == 0
                    || row
                        .generation
                        .is_some_and(|generation| generation != existing.generation)
            }) {
                conflict("guarded ownership or generation does not match durable intent")
            } else if existing.is_none() && row.status == Active {
                conflict("active diversion lost its speaker generation; drain and re-arm")
            } else if !runtime
                .profiles
                .get(&row.profile.id)
                .is_some_and(ProfileState::eligible)
            {
                conflict("scrubber readiness expired before dispatch")
            } else if existing.is_none() && row.windows.len() >= 2048 {
                conflict("diversion mutation history exhausted")
            } else {
                None
            };
            if failures[index].is_none() {
                if let Some(existing) = existing {
                    row.generation = Some(existing.generation);
                }
                owners
                    .entry(row.profile.id.clone())
                    .or_default()
                    .push(index);
            }
        }

        let mut mutated = vec![];
        for (profile, members) in owners {
            let owner = rows[members[0]].rule.owner.clone();
            let window = match self.window(runtime, speaker, &profile, &owner).await {
                Ok(window) => window,
                Err(error) => {
                    tracing::warn!(code = %error.status_code(), "scrubber window unavailable");
                    for &index in &members {
                        failures[index] = conflict("mutation window unavailable");
                    }
                    continue;
                }
            };
            // A window authorizing an add is durable before dispatch, so an
            // unknown outcome stays bounded by a recorded authorization.
            let mut adds = vec![];
            let mut renewals = vec![];
            for &index in &members {
                let row = &mut rows[index];
                if row.generation.is_some() {
                    renewals.push(index);
                    continue;
                }
                if row.windows.last() != Some(&window) {
                    row.windows.push(window);
                }
                match state.repo.save_diversion(row, "scrubber_window").await {
                    Ok(()) => adds.push(index),
                    Err(error) => failures[index] = Some(error),
                }
            }
            state.fence.ensure_active()?;
            Self::ensure_epoch(state, runtime)?;
            let eligible = runtime
                .profiles
                .get(&profile)
                .is_some_and(ProfileState::eligible);
            for &index in adds.iter().chain(&renewals) {
                if !eligible || rows[index].expires_at <= Utc::now() {
                    failures[index] = conflict(
                        "scrubber readiness or diversion lifetime expired before mutation",
                    );
                }
            }
            renewals.retain(|&index| failures[index].is_none());
            adds.retain(|&index| failures[index].is_none());
            // The owner's rules share one generation and one lease deadline.
            let generation = renewals.first().and_then(|&index| rows[index].generation);
            let uniform = renewals
                .iter()
                .all(|&index| rows[index].generation == generation);
            if let (Some(generation), true) = (generation, uniform) {
                match speaker
                    .renew_guarded(&owner, generation, window, WINDOW_SECONDS)
                    .await
                {
                    Ok(_) => mutated.extend(&renewals),
                    Err(error) => {
                        tracing::warn!(code = %error.status_code(), "scrubber renewal failed");
                        for &index in renewals.iter().chain(&adds) {
                            failures[index] = conflict("guarded renewal failed");
                        }
                        continue;
                    }
                }
            } else if !renewals.is_empty() {
                for &index in renewals.iter().chain(&adds) {
                    failures[index] = conflict("guarded owner reports several generations");
                }
                continue;
            }
            for index in adds {
                match speaker
                    .add_guarded(&rows[index].rule, window, WINDOW_SECONDS)
                    .await
                {
                    Ok(generation) => {
                        rows[index].generation = Some(generation);
                        mutated.push(index);
                    }
                    Err(error) => failures[index] = Some(error),
                }
            }
        }
        if mutated.is_empty() {
            return Ok(failures);
        }

        let inventory = match speaker.guarded_inventory().await {
            Ok(inventory) => inventory,
            Err(error) => {
                tracing::warn!(code = %error.status_code(), "guarded read-back unavailable");
                for &index in &mutated {
                    failures[index] = conflict("guarded read-back unavailable");
                }
                return Ok(failures);
            }
        };
        let observed = Observed::new(&inventory)?;
        let mut confirmed = vec![];
        for index in mutated {
            let row = &rows[index];
            let key = row.rule.nlri.compute_hash();
            if observed.foreign_victim_overlap(row, &key)? {
                failures[index] = conflict("local victim overlap appeared during mutation");
            } else if !observed.guarded.get(&key).is_some_and(|entry| {
                entry.rule.same_admission(&row.rule)
                    && entry.remaining_ms > 0
                    && Some(entry.generation) == row.generation
            }) {
                failures[index] = conflict("guarded add is not confirmed by read-back");
            } else {
                confirmed.push(index);
            }
        }

        // Read new admissions first, then rotate established rows across passes.
        let Some(exports) = state.announcer.flowspec_export_observer() else {
            for index in confirmed {
                failures[index] = Some(PrefixdError::Config(
                    "scrubber export observation unsupported".into(),
                ));
            }
            return Ok(failures);
        };
        let (new, mut established): (Vec<usize>, Vec<usize>) = confirmed
            .iter()
            .partition(|&&index| rows[index].status == Pending);
        if !established.is_empty() {
            let start = runtime.export_cursor % established.len();
            established.rotate_left(start);
        }
        let mut read = 0;
        for &index in new.iter().chain(&established) {
            let now = Instant::now();
            if now >= export_deadline {
                break;
            }
            let row = &mut rows[index];
            let result = match tokio::time::timeout_at(
                export_deadline.min(now + EXPORT_READ),
                exports.flowspec_exports(&row.rule.nlri),
            )
            .await
            {
                Ok(Ok(Some(peers))) => Ok(peers),
                Ok(Ok(None)) => Err("scrubber export inventory unavailable"),
                Ok(Err(_)) => Err("scrubber export observation failed"),
                Err(_) => Err("scrubber export observation timed out"),
            };
            if row.status != Pending {
                read += 1;
            }
            if result.as_ref().is_ok_and(|peers| {
                peers.iter().any(|peer| {
                    peer.disposition == ExportDisposition::Committed
                        && !row.profile.router_peers.contains(&peer.peer_address)
                })
            }) {
                failures[index] = conflict("diversion exported outside configured router scope");
                continue;
            }
            observe_exports(row, result);
        }
        runtime.export_cursor = runtime.export_cursor.wrapping_add(read);

        // Persist only real transitions; a steady renewal writes nothing.
        Self::ensure_epoch(state, runtime)?;
        for index in confirmed {
            if failures[index].is_some() {
                continue;
            }
            let row = &mut rows[index];
            row.status = Active;
            row.last_error = None;
            let (status, generation, ..) = &before[index];
            let action = if *status != Active {
                "scrubber_observed_local"
            } else if *generation != row.generation {
                "scrubber_generation"
            } else {
                "scrubber_export_observed"
            };
            if before[index] != lifecycle(row)
                && let Err(error) = state.repo.save_diversion(row, action).await
            {
                failures[index] = Some(error);
            }
        }
        Ok(failures)
    }

    /// A profile's cached window, or a fresh one when the cache would expire
    /// before the next renewal could run.
    async fn window(
        &self,
        runtime: &mut Runtime,
        speaker: &dyn GuardedFlowSpecSpeaker,
        profile: &str,
        owner: &str,
    ) -> Result<GuardedStamp> {
        let started = Instant::now();
        if let Some((stamp, until)) = runtime.windows.get(profile)
            && *until > started + WINDOW_REUSE
        {
            return Ok(*stamp);
        }
        let issued = speaker.issue_window(owner, WINDOW_SECONDS).await?;
        // Anchor the conservative cache horizon before the RPC, rather than
        // adding network delay to the server's remaining time.
        let until =
            started + Duration::from_millis(issued.remaining_ms.saturating_sub(1000).into());
        runtime
            .windows
            .insert(profile.into(), (issued.stamp, until));
        Ok(issued.stamp)
    }

    pub async fn tick(&self, state: &AppState) -> Result<()> {
        if !state.settings.scrubber.enabled || state.settings.mode == OperationMode::DryRun {
            return Ok(());
        }
        let started = Instant::now();
        let probes = futures_util::future::join_all(
            state
                .settings
                .scrubber
                .profiles
                .iter()
                .map(|p| async move { (&p.id, self.probe(p).await) }),
        )
        .await;
        self.pass(state, probes, started + EXPORT_BUDGET).await
    }

    /// Apply readiness probes, then reconcile every outstanding row once.
    async fn pass(
        &self,
        state: &AppState,
        probes: Vec<(&String, Result<ProfileState>)>,
        export_deadline: Instant,
    ) -> Result<()> {
        let mut runtime = self.runtime.lock().await;
        // A fresh report cannot erase a gap in readiness since the last pass.
        Self::expire_readiness(&mut runtime);
        let epoch = state.fence.with_observation_epoch(|epoch| epoch);
        if epoch.is_none() || runtime.epoch.is_some() && runtime.epoch != epoch {
            Self::latch_all(&mut runtime, "controller ownership lost");
        }
        runtime.epoch = epoch;
        if epoch.is_none() {
            return Ok(());
        }
        let _guard = state.mitigation_lock.lock().await;
        state.verified_speaker_binding()?;
        let mut rows = match state.repo.list_diversions(&state.settings.pop).await {
            Ok(rows) => rows,
            Err(error) => {
                Self::latch_all(&mut runtime, "durable intent unavailable");
                return Err(error);
            }
        };
        for (id, probe) in probes {
            let current = runtime
                .profiles
                .get_mut(id)
                .expect("configured profile state");
            let before = (current.armed, current.readiness);
            match probe {
                Ok(fresh) => {
                    current.ready = fresh.ready;
                    current.readiness = fresh.readiness;
                    current.observed_at = fresh.observed_at;
                    current.valid_until = fresh.valid_until;
                    if !current.ready {
                        current.latch("scrubber not ready");
                    }
                }
                Err(_) => {
                    current.ready = false;
                    current.readiness = ReadinessState::Unknown;
                    current.valid_until = None;
                    current.latch("scrubber readiness unknown");
                }
            }
            if before != (current.armed, current.readiness) {
                let audit = crate::observability::AuditEntry::new(
                    crate::observability::ActorType::System,
                    Some("scrubber".into()),
                    "scrubber_readiness",
                    Some("scrubber_profile"),
                    Some(id.clone()),
                    serde_json::json!({"revision":Self::profile(state,id)?.revision,"state":current}),
                );
                if let Err(error) = state.repo.insert_audit(&audit).await {
                    Self::latch_all(&mut runtime, "readiness audit unavailable");
                    return Err(error);
                }
            }
        }
        if !runtime.initialized {
            Self::latch_all(&mut runtime, "startup drain: explicit re-arm required");
            runtime.initialized = true;
        }
        for profile in &state.settings.scrubber.profiles {
            for status in [
                DiversionStatus::Pending,
                DiversionStatus::Active,
                DiversionStatus::Withdrawing,
            ] {
                crate::observability::metrics::SCRUBBER_INTENTS
                    .with_label_values(&[profile.id.as_str(), status.as_str()])
                    .set(
                        rows.iter()
                            .filter(|row| row.profile.id == profile.id && row.status == status)
                            .count() as f64,
                    );
            }
        }
        let before: Vec<_> = rows.iter().map(lifecycle).collect();
        let durable = rows.clone();
        let failures = match self
            .reconcile(state, &mut runtime, &mut rows, &durable, export_deadline)
            .await
        {
            Ok(failures) => failures,
            Err(error) => {
                tracing::warn!(code = %error.status_code(), "scrubber lifecycle pass failed");
                rows.iter()
                    .map(|_| Some(PrefixdError::Internal("lifecycle pass failed".into())))
                    .collect()
            }
        };
        for ((mut row, failure), before) in rows.into_iter().zip(failures).zip(before) {
            if let Some(error) = failure {
                if state.fence.with_observation_epoch(|epoch| epoch) != runtime.epoch {
                    return Err(PrefixdError::Standby);
                }
                tracing::warn!(code = %error.status_code(), "scrubber lifecycle latched");
                let unchanged = lifecycle(&row);
                Self::failed(
                    &mut runtime,
                    &mut row,
                    "diversion lifecycle failed; explicit re-arm required",
                );
                if unchanged != lifecycle(&row)
                    && let Err(storage) = state.repo.save_diversion(&row, "scrubber_latched").await
                {
                    Self::latch_all(&mut runtime, "durable withdrawal unavailable");
                    return Err(storage);
                }
            }
            if before != lifecycle(&row) {
                let _ = state
                    .ws_broadcast
                    .send(crate::ws::WsMessage::DiversionUpdated { diversion: row });
            }
        }
        Self::publish_profiles(&runtime.profiles);
        for (id, profile) in &runtime.profiles {
            let _ = state
                .ws_broadcast
                .send(crate::ws::WsMessage::ScrubberUpdated {
                    profile: id.clone(),
                    state: profile.clone(),
                });
        }
        Ok(())
    }

    pub async fn run(state: Arc<AppState>) {
        let mut shutdown = state.subscribe_shutdown();
        let mut interval = tokio::time::interval(Duration::from_secs(PASS_PERIOD_SECONDS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _=shutdown.recv()=>break,
                _=interval.tick()=>{
                    if !matches!(tokio::time::timeout(Duration::from_secs(PASS_BUDGET_SECONDS),state.scrubber.tick(&state)).await,Ok(Ok(()))) {
                        Self::latch_all(&mut *state.scrubber.runtime.lock().await,"scrubber reconciliation incomplete");
                        crate::observability::metrics::SCRUBBER_LIFECYCLE_FAILURES.inc();
                        tracing::warn!("scrubber profiles latched after incomplete reconciliation");
                    }
                }
            }
        }
    }
}
