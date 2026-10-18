use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::bgp::FlowSpecAnnouncer;
use crate::db::RepositoryTrait;
use crate::error::{PrefixdError, Result};

use super::{FlowSpecAction, FlowSpecNlri, FlowSpecRule, Mitigation, MitigationStatus};

/// Immutable deletion intent; an uncertain RPC must never turn it back into an announcement.
#[derive(Debug, Clone, FromRow)]
pub struct WithdrawalRequest {
    pub operation_id: Uuid,
    pub mitigation_id: Uuid,
    pub pop: String,
    pub nlri_hash: String,
    pub rule_json: String,
    #[sqlx(try_from = "crate::db::CheckedTimestamp")]
    pub mitigation_updated_at: DateTime<Utc>,
    pub terminal_status: String,
    pub speaker_delete_required: bool,
    pub actor_type: String,
    pub actor: String,
    pub reason: String,
    #[sqlx(try_from = "crate::db::CheckedTimestamp")]
    pub requested_at: DateTime<Utc>,
    #[sqlx(try_from = "crate::db::CheckedTimestamp")]
    pub completed_at: Option<DateTime<Utc>>,
    /// NULL only for legacy or explicitly unbound mock/test operations.
    pub target_id: Option<Uuid>,
}

impl WithdrawalRequest {
    pub fn new(
        mitigation: &Mitigation,
        expired: bool,
        actor_type: &str,
        actor: &str,
        reason: String,
        speaker_delete_required: bool,
    ) -> Result<Self> {
        let rule = mitigation_rule(mitigation);
        Ok(Self {
            operation_id: Uuid::new_v4(),
            mitigation_id: mitigation.mitigation_id,
            pop: mitigation.pop.clone(),
            nlri_hash: rule.nlri_hash(),
            rule_json: serde_json::to_string(&rule)?,
            mitigation_updated_at: mitigation.updated_at,
            terminal_status: if expired { "expired" } else { "withdrawn" }.into(),
            speaker_delete_required,
            actor_type: actor_type.into(),
            actor: actor.into(),
            reason,
            requested_at: Utc::now(),
            completed_at: None,
            target_id: None,
        })
    }

    pub fn audit_entry(&self) -> crate::observability::AuditEntry {
        use crate::observability::{ActorType, AuditEntry};
        let actor_type = match self.actor_type.as_str() {
            "operator" => ActorType::Operator,
            "detector" => ActorType::Detector,
            _ => ActorType::System,
        };
        AuditEntry::new(
            actor_type,
            Some(self.actor.clone()),
            if self.is_expiry() {
                "expire"
            } else {
                "withdraw"
            },
            Some("mitigation"),
            Some(self.mitigation_id.to_string()),
            serde_json::json!({"reason": self.reason, "operation_id": self.operation_id}),
        )
    }

    pub fn is_expiry(&self) -> bool {
        self.terminal_status == "expired"
    }
}

pub fn mitigation_rule(mitigation: &Mitigation) -> FlowSpecRule {
    FlowSpecRule::new(
        FlowSpecNlri::from(&mitigation.match_criteria),
        FlowSpecAction::from((mitigation.action_type, &mitigation.action_params)),
    )
}

/// Caller holds the controller's lifecycle mutex through preparation, RPC and finalization.
#[allow(
    clippy::too_many_arguments,
    reason = "Persist immutable withdrawal metadata together with its verified speaker target"
)]
pub async fn request_withdrawal(
    repo: &dyn RepositoryTrait,
    mitigation: &Mitigation,
    expired: bool,
    actor_type: &str,
    actor: &str,
    reason: String,
    speaker_delete_required: bool,
    binding: Option<&super::VerifiedSpeakerBinding>,
) -> Result<WithdrawalRequest> {
    let mut request = WithdrawalRequest::new(
        mitigation,
        expired,
        actor_type,
        actor,
        reason,
        // A simulation was never sent to the speaker, so its deletion stays local in any mode.
        speaker_delete_required && !mitigation.is_dry_run_origin(),
    )?;
    request.target_id = binding.map(super::VerifiedSpeakerBinding::target_id);
    if let Some(binding) = binding {
        binding.validate_request(&request.pop, request.target_id)?;
    }
    check_withdrawal_owner(repo, &request).await?;
    repo.begin_withdrawal(&request).await
}

pub(crate) fn ownership_key(rule: &FlowSpecRule) -> String {
    let mut nlri = rule.nlri.clone();
    nlri.dst_ports.sort_unstable();
    nlri.dst_ports.dedup();
    nlri.compute_hash()
}

/// Caller holds the lifecycle mutex; reject ambiguous or deleting owners before consuming an event ID.
pub async fn find_mitigation_owner(
    repo: &dyn RepositoryTrait,
    pop: &str,
    rule: &FlowSpecRule,
    scope_hash: &str,
) -> Result<Option<Mitigation>> {
    let pending = repo.pending_withdrawals(Some(pop)).await?;
    let key = ownership_key(rule);
    let owners: Vec<_> = repo
        .active_mitigations_for_pop(pop)
        .await?
        .into_iter()
        .filter(|owner| {
            owner.scope_hash == scope_hash
                || owner.match_criteria.compute_scope_hash() == scope_hash
                || ownership_key(&mitigation_rule(owner)) == key
        })
        .collect();
    for request in pending {
        let pending_rule: FlowSpecRule = serde_json::from_str(&request.rule_json)?;
        if ownership_key(&pending_rule) == key
            || owners
                .iter()
                .any(|owner| owner.mitigation_id == request.mitigation_id)
        {
            return Err(PrefixdError::Conflict(
                "FlowSpec rule has a pending withdrawal".into(),
            ));
        }
    }
    if owners.len() > 1 {
        return Err(PrefixdError::Conflict(
            "FlowSpec rule has multiple active owners".into(),
        ));
    }
    Ok(owners.into_iter().next())
}

async fn check_withdrawal_owner(
    repo: &dyn RepositoryTrait,
    request: &WithdrawalRequest,
) -> Result<()> {
    let current = repo
        .get_mitigation(request.mitigation_id)
        .await?
        .ok_or(PrefixdError::MitigationNotFound(request.mitigation_id))?;
    if !current.is_active()
        || current.pop != request.pop
        || current.updated_at != request.mitigation_updated_at
        || mitigation_rule(&current).nlri_hash() != request.nlri_hash
    {
        return Err(PrefixdError::Conflict(
            "withdrawal intent no longer matches mitigation".into(),
        ));
    }
    let key = ownership_key(&mitigation_rule(&current));
    let now = Utc::now();
    if repo
        .active_mitigations_for_pop(&request.pop)
        .await?
        .iter()
        .any(|owner| {
            owner.mitigation_id != request.mitigation_id
                && owner.expires_at > now
                && ownership_key(&mitigation_rule(owner)) == key
        })
    {
        return Err(PrefixdError::Conflict(
            "FlowSpec rule has another active owner".into(),
        ));
    }
    Ok(())
}

pub async fn execute_withdrawal(
    repo: &dyn RepositoryTrait,
    announcer: &dyn FlowSpecAnnouncer,
    dry_run: bool,
    request: &WithdrawalRequest,
    binding: Option<&super::VerifiedSpeakerBinding>,
) -> Result<Mitigation> {
    finish_withdrawal_request(repo, Some(announcer), dry_run, request, binding).await
}

/// Complete a request that needs no speaker deletion, without a speaker connection.
pub async fn complete_local_withdrawal(
    repo: &dyn RepositoryTrait,
    request: &WithdrawalRequest,
    binding: Option<&super::VerifiedSpeakerBinding>,
) -> Result<Mitigation> {
    finish_withdrawal_request(repo, None, false, request, binding).await
}

async fn finish_withdrawal_request(
    repo: &dyn RepositoryTrait,
    announcer: Option<&dyn FlowSpecAnnouncer>,
    dry_run: bool,
    request: &WithdrawalRequest,
    binding: Option<&super::VerifiedSpeakerBinding>,
) -> Result<Mitigation> {
    let validate_target = |request: &WithdrawalRequest| match binding {
        Some(binding) => {
            if let Some(announcer) = announcer {
                binding.validate_backend(announcer.backend())?;
            }
            binding.validate_request(&request.pop, request.target_id)
        }
        None if announcer.is_none_or(|announcer| announcer.backend() == "mock")
            && request.target_id.is_none() =>
        {
            Ok(())
        }
        None => Err(super::binding_mismatch()),
    };
    validate_target(request)?;
    let request = repo
        .pending_withdrawals(Some(&request.pop))
        .await?
        .into_iter()
        .find(|pending| {
            pending.operation_id == request.operation_id
                && pending.mitigation_id == request.mitigation_id
        })
        .ok_or_else(|| {
            PrefixdError::Conflict("withdrawal operation is no longer pending".into())
        })?;
    // Do not trust the caller's clone: validate the freshly fetched persisted intent.
    validate_target(&request)?;
    if request.speaker_delete_required && dry_run {
        return Err(PrefixdError::Conflict(
            "pending withdrawal requires enforced mode".into(),
        ));
    }
    if request.speaker_delete_required && announcer.is_none() {
        return Err(PrefixdError::Conflict(
            "pending withdrawal requires a speaker deletion".into(),
        ));
    }
    check_withdrawal_owner(repo, &request).await?;
    let rule: FlowSpecRule = serde_json::from_str(&request.rule_json)?;
    if rule.nlri_hash() != request.nlri_hash {
        return Err(PrefixdError::Internal(
            "withdrawal rule identity does not match persisted intent".into(),
        ));
    }
    let start = std::time::Instant::now();
    if request.speaker_delete_required
        && let Some(announcer) = announcer
    {
        announcer.withdraw(&rule).await?;
    }
    let rpc_seconds = start.elapsed().as_secs_f64();
    let mitigation = repo.finish_withdrawal(&request).await?.ok_or_else(|| {
        PrefixdError::Conflict("withdrawal completion no longer matches mitigation".into())
    })?;
    if request.speaker_delete_required {
        crate::observability::metrics::ANNOUNCEMENTS_TOTAL
            .with_label_values(&["withdrawn"])
            .inc();
        crate::observability::metrics::ANNOUNCEMENTS_LATENCY.observe(rpc_seconds);
    }
    debug_assert!(matches!(
        mitigation.status,
        MitigationStatus::Withdrawn | MitigationStatus::Expired
    ));
    Ok(mitigation)
}

pub const RETIRE_DRY_RUN_FLAG: &str = "--retire-dry-run-intent";

/// Live dry-run simulations at `pop` without a pending withdrawal. Expired rows and
/// pending requests are left to the scheduler, which completes them locally.
pub async fn dry_run_intent(repo: &dyn RepositoryTrait, pop: &str) -> Result<Vec<Mitigation>> {
    let pending = repo.pending_withdrawals(Some(pop)).await?;
    let now = Utc::now();
    Ok(repo
        .active_mitigations_for_pop(pop)
        .await?
        .into_iter()
        .filter(|m| {
            m.is_dry_run_origin()
                && m.expires_at > now
                && !pending.iter().any(|r| r.mitigation_id == m.mitigation_id)
        })
        .collect())
}

/// Enforced mode must not inherit simulations as desired speaker state.
pub async fn check_enforced_startup(repo: &dyn RepositoryTrait, pop: &str) -> Result<()> {
    let count = dry_run_intent(repo, pop).await?.len();
    if count > 0 {
        return Err(PrefixdError::Conflict(format!(
            "{count} unexpired dry-run mitigation(s) at POP {pop} would become enforced intent; \
             retire them locally once with {RETIRE_DRY_RUN_FLAG}"
        )));
    }
    Ok(())
}

/// Retire every live simulation through an audited, local-only withdrawal; no speaker call.
pub async fn retire_dry_run_intent(
    repo: &dyn RepositoryTrait,
    pop: &str,
    binding: Option<&super::VerifiedSpeakerBinding>,
) -> Result<usize> {
    let intent = dry_run_intent(repo, pop).await?;
    for mitigation in &intent {
        let request = request_withdrawal(
            repo,
            mitigation,
            false,
            "system",
            "retire-dry-run-intent",
            "dry-run simulation retired before enforced operation".into(),
            false,
            binding,
        )
        .await?;
        complete_local_withdrawal(repo, &request, binding).await?;
        tracing::info!(mitigation_id = %mitigation.mitigation_id, operation_id = %request.operation_id,
            "retired dry-run mitigation locally");
    }
    Ok(intent.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bgp::{FlowSpecWriter, MockAnnouncer},
        db::MockRepository,
        domain::{ActionParams, ActionType, AttackVector, MatchCriteria, MitigationIntent},
    };

    fn mitigation(prefix: &str) -> Mitigation {
        let mut mitigation = Mitigation::from_intent(
            MitigationIntent {
                event_id: Uuid::new_v4(),
                customer_id: None,
                service_id: None,
                pop: "test".into(),
                match_criteria: MatchCriteria {
                    dst_prefix: prefix.into(),
                    protocol: Some(17),
                    dst_ports: vec![53],
                },
                action_type: ActionType::Discard,
                action_params: ActionParams { rate_bps: None },
                ttl_seconds: 60,
                reason: "test".into(),
            },
            prefix.split('/').next().unwrap().into(),
            AttackVector::UdpFlood,
        );
        mitigation.activate();
        mitigation
    }

    #[tokio::test]
    async fn canonical_shared_owner_blocks_delete_before_intent_or_rpc() {
        let repo = MockRepository::new();
        let first = mitigation("2001:db8::1/128");
        let second = mitigation("2001:0DB8:0:0:0:0:0:1/128");
        repo.insert_mitigation(&first).await.unwrap();
        repo.insert_mitigation(&second).await.unwrap();
        assert_eq!(
            mitigation_rule(&first).nlri_hash(),
            mitigation_rule(&second).nlri_hash()
        );
        assert!(matches!(
            request_withdrawal(
                &repo,
                &first,
                false,
                "operator",
                "alice",
                "test".into(),
                true,
                None
            )
            .await,
            Err(PrefixdError::Conflict(_))
        ));
        assert!(repo.pending_withdrawals(None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn scope_alias_cannot_extend_a_pending_withdrawal() {
        let repo = MockRepository::new();
        let mut original = mitigation("192.0.2.1/32");
        original.match_criteria.dst_ports = vec![53, 53];
        original.scope_hash = original.match_criteria.compute_scope_hash();
        repo.insert_mitigation(&original).await.unwrap();
        request_withdrawal(
            &repo,
            &original,
            false,
            "operator",
            "alice",
            "test".into(),
            true,
            None,
        )
        .await
        .unwrap();
        let candidate = mitigation("192.0.2.1/32");
        assert_eq!(candidate.scope_hash, original.scope_hash);
        assert_ne!(
            mitigation_rule(&candidate).nlri_hash(),
            mitigation_rule(&original).nlri_hash()
        );
        assert!(matches!(
            find_mitigation_owner(
                &repo,
                "test",
                &mitigation_rule(&candidate),
                &candidate.scope_hash
            )
            .await,
            Err(PrefixdError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn dry_run_preserves_enforced_intent_and_only_completes_explicit_simulation() {
        let repo = MockRepository::new();
        let speaker = MockAnnouncer::new();
        let enforced = mitigation("192.0.2.1/32");
        repo.insert_mitigation(&enforced).await.unwrap();
        speaker.announce(&mitigation_rule(&enforced)).await.unwrap();
        let request = request_withdrawal(
            &repo,
            &enforced,
            false,
            "operator",
            "alice",
            "enforced".into(),
            true,
            None,
        )
        .await
        .unwrap();
        let retried = request_withdrawal(
            &repo,
            &enforced,
            false,
            "operator",
            "bob",
            "dry-run retry".into(),
            false,
            None,
        )
        .await
        .unwrap();
        assert!(retried.speaker_delete_required);
        assert!(
            execute_withdrawal(&repo, &speaker, true, &retried, None)
                .await
                .is_err()
        );
        assert_eq!(speaker.announced_count().await, 1);
        assert!(
            repo.get_mitigation(enforced.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .is_active()
        );
        assert_eq!(repo.pending_withdrawals(None).await.unwrap().len(), 1);
        execute_withdrawal(&repo, &speaker, false, &request, None)
            .await
            .unwrap();
        assert_eq!(speaker.announced_count().await, 0);

        let simulated = mitigation("192.0.2.2/32");
        repo.insert_mitigation(&simulated).await.unwrap();
        let request = request_withdrawal(
            &repo,
            &simulated,
            false,
            "operator",
            "alice",
            "simulation".into(),
            false,
            None,
        )
        .await
        .unwrap();
        assert!(!request.speaker_delete_required);
        assert_eq!(
            execute_withdrawal(&repo, &speaker, true, &request, None)
                .await
                .unwrap()
                .status,
            MitigationStatus::Withdrawn
        );
        assert!(repo.pending_withdrawals(None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn original_operation_and_revision_fence_completion_and_repeated_requests() {
        let repo = MockRepository::new();
        let speaker = MockAnnouncer::new();
        let mut mitigation = mitigation("192.0.2.1/32");
        repo.insert_mitigation(&mitigation).await.unwrap();
        speaker
            .announce(&mitigation_rule(&mitigation))
            .await
            .unwrap();
        let request = request_withdrawal(
            &repo,
            &mitigation,
            false,
            "operator",
            "alice",
            "first reason".into(),
            true,
            None,
        )
        .await
        .unwrap();
        let repeated = request_withdrawal(
            &repo,
            &mitigation,
            true,
            "system",
            "scheduler",
            "TTL expired".into(),
            false,
            None,
        )
        .await
        .unwrap();
        assert_eq!(repeated.operation_id, request.operation_id);
        assert_eq!(repeated.actor, "alice");
        assert_eq!(repeated.reason, "first reason");
        assert!(!repeated.is_expiry());
        let mut stale = request.clone();
        stale.operation_id = Uuid::new_v4();
        assert!(repo.finish_withdrawal(&stale).await.unwrap().is_none());
        assert!(
            execute_withdrawal(&repo, &speaker, false, &stale, None)
                .await
                .is_err()
        );
        assert_eq!(speaker.announced_count().await, 1);
        mitigation.extend_ttl(120, Uuid::new_v4());
        repo.update_mitigation(&mitigation).await.unwrap();
        assert!(repo.finish_withdrawal(&request).await.unwrap().is_none());
        assert!(
            execute_withdrawal(&repo, &speaker, false, &request, None)
                .await
                .is_err()
        );
        assert_eq!(speaker.announced_count().await, 1);
        assert!(
            repo.get_mitigation(mitigation.mitigation_id)
                .await
                .unwrap()
                .unwrap()
                .is_active()
        );
        assert_eq!(repo.pending_withdrawals(None).await.unwrap().len(), 1);
    }
}
