//! Explicit operator extension of existing FlowSpec intent. No speaker mutation.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::AppState;
use crate::config::OperationMode;
use crate::error::{GuardrailError, PrefixdError, Result};
use crate::observability::{ActorType, AuditEntry};

use super::{ActionType, Mitigation, MitigationIntent, MitigationRoute, MitigationStatus};

/// A checked snapshot and authenticated request for an atomic expiry update.
#[derive(Debug, Clone)]
pub struct LifetimeExtension {
    pub expected: Mitigation,
    pub ttl_seconds: u32,
    pub actor: String,
    pub reason: String,
    pub target_id: Option<Uuid>,
    pub fence_epoch: u64,
}

/// The stored result; an unchanged horizon writes neither a revision nor audit.
#[derive(Debug, Clone)]
pub struct LifetimeExtensionOutcome {
    pub mitigation: Mitigation,
    pub previous_expires_at: DateTime<Utc>,
    pub extended: bool,
}

impl LifetimeExtension {
    /// Repositories repeat eligibility and revision checks after acquiring their lock.
    pub(crate) fn validate_current(&self, current: &Mitigation, now: DateTime<Utc>) -> Result<()> {
        validate_live(current, &self.expected.pop, now)?;
        if current.mitigation_id != self.expected.mitigation_id
            || current.updated_at != self.expected.updated_at
            || current.expires_at != self.expected.expires_at
            || current.scope_hash != self.expected.scope_hash
        {
            return Err(PrefixdError::Conflict(
                "mitigation changed before lifetime extension".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn ensure_fence(&self, fence: &crate::fence::ControllerFence) -> Result<()> {
        fence.with_observation_epoch(|epoch| {
            if epoch == Some(self.fence_epoch) {
                Ok(())
            } else {
                Err(PrefixdError::Standby)
            }
        })
    }

    pub(crate) fn audit(&self, updated: &Mitigation) -> AuditEntry {
        let mut entry = AuditEntry::new(
            ActorType::Operator,
            Some(self.actor.clone()),
            "extend",
            Some("mitigation"),
            Some(updated.mitigation_id.to_string()),
            serde_json::json!({
                "pop": updated.pop,
                "victim_ip": updated.victim_ip,
                "previous_expires_at": self.expected.expires_at,
                "expires_at": updated.expires_at,
                "ttl_seconds": self.ttl_seconds,
                "reason": self.reason,
            }),
        );
        entry.timestamp = updated.updated_at;
        entry
    }
}

fn validate_live(mitigation: &Mitigation, pop: &str, now: DateTime<Utc>) -> Result<()> {
    if mitigation.pop != pop
        || !matches!(
            mitigation.status,
            MitigationStatus::Active | MitigationStatus::Escalated
        )
        || !matches!(
            mitigation.action_type,
            ActionType::Discard | ActionType::Police
        )
        || mitigation.origin_mode != Some(OperationMode::Enforced)
        || mitigation.expires_at <= now
        || mitigation.withdrawn_at.is_some()
    {
        return Err(PrefixdError::Conflict(
            "lifetime extension requires a live ordinary FlowSpec rule on this POP".into(),
        ));
    }
    Ok(())
}

/// Extend desired lifetime under the same lifecycle lock as withdrawal and reload.
/// The speaker's retained rule, export and enforcement remain independently observed.
pub async fn extend_flowspec_lifetime(
    state: &AppState,
    id: Uuid,
    ttl_seconds: u32,
    actor: String,
    reason: String,
) -> Result<LifetimeExtensionOutcome> {
    if reason.trim().is_empty() || reason.len() > 1024 {
        return Err(PrefixdError::InvalidRequest(
            "reason must contain text and be at most 1024 UTF-8 bytes".into(),
        ));
    }
    // Only read-only preparation is cancellable. Return the guard with the
    // checked request so the repository mutation and COMMIT remain serialized.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    let (_guard, request) = tokio::time::timeout_at(deadline, async {
        let guard = state.mitigation_lock.lock().await;
        let fence_epoch = state
            .fence
            .with_observation_epoch(|epoch| epoch)
            .ok_or(PrefixdError::Standby)?;
        if state.settings.mode != OperationMode::Enforced {
            return Err(PrefixdError::Conflict(
                "lifetime extension requires enforced mode; simulations cannot be extended".into(),
            ));
        }
        let binding = state.verified_speaker_binding()?;
        let read_repo = state.repo.clone().for_bounded_reads(deadline)?;
        let expected = read_repo
            .get_mitigation(id)
            .await?
            .ok_or(PrefixdError::MitigationNotFound(id))?;
        validate_live(&expected, &state.settings.pop, Utc::now())?;
        let rule = super::mitigation_rule(&expected)?;
        if let Some(binding) = binding {
            if !rule.owner.is_empty() && rule.owner != binding.owner() {
                return Err(super::binding_mismatch());
            }
        }
        let owner = super::find_mitigation_owner(
            read_repo.as_ref(),
            &state.settings.pop,
            &MitigationRoute::of(&expected),
            &expected.scope_hash,
        )
        .await?;
        if owner.is_none_or(|owner| {
            owner.mitigation_id != expected.mitigation_id || owner.updated_at != expected.updated_at
        }) {
            return Err(PrefixdError::Conflict(
                "mitigation no longer uniquely owns this FlowSpec match".into(),
            ));
        }
        let destination = super::parse_flowspec_destination(&expected.match_criteria.dst_prefix)
            .map_err(|error| PrefixdError::InvalidRequest(error.to_string()))?;
        let inventory = state.inventory.read().await;
        let context = if destination.prefix_len() == destination.max_prefix_len() {
            inventory.lookup_ip(&expected.victim_ip)
        } else {
            // An invalid inventory refuses the extension, never an unowned prefix.
            inventory.lookup_prefix(&destination)?
        };
        if context.is_none_or(|context| {
            expected.customer_id.as_deref() != Some(context.customer_id.as_str())
                || expected
                    .service_id
                    .as_deref()
                    .is_some_and(|service| context.service_id.as_deref() != Some(service))
        }) {
            return Err(PrefixdError::Conflict(
                "destination inventory ownership changed or is unavailable".into(),
            ));
        }
        drop(inventory);
        let configured_safelisted =
            state
                .settings
                .safelist
                .prefixes
                .iter()
                .try_fold(false, |overlap, configured| {
                    let prefix = configured
                        .parse::<ipnet::IpNet>()
                        .or_else(|_| {
                            configured
                                .parse::<std::net::IpAddr>()
                                .map(ipnet::IpNet::from)
                        })
                        .map_err(|_| {
                            PrefixdError::Config("invalid configured safelist prefix".into())
                        })?;
                    Ok::<_, PrefixdError>(
                        overlap || prefix.contains(&destination) || destination.contains(&prefix),
                    )
                })?;
        let safelisted =
            read_repo.is_safelisted(&destination.to_string()).await? || configured_safelisted;
        let intent = MitigationIntent {
            event_id: expected.triggering_event_id,
            customer_id: expected.customer_id.clone(),
            service_id: expected.service_id.clone(),
            pop: expected.pop.clone(),
            match_criteria: expected.match_criteria.clone(),
            action_type: expected.action_type,
            action_params: expected.action_params.clone(),
            ttl_seconds,
            reason: expected.reason.clone(),
        };
        let guardrails = crate::guardrails::Guardrails::with_timers(
            state.settings.guardrails.clone(),
            state.settings.quotas.clone(),
            &state.settings.timers,
        );
        guardrails.validate_rule(&intent, safelisted)?;
        guardrails.validate_remaining_ttl(chrono::Duration::seconds(ttl_seconds.into()))?;
        // Unlike new admission, extension does not consume another quota/rate slot.
        state.announcer.match_support().require(&rule.nlri)?;
        validate_live(&expected, &state.settings.pop, Utc::now())?;
        state.verified_speaker_binding()?;
        let request = LifetimeExtension {
            expected,
            ttl_seconds,
            actor,
            reason,
            target_id: binding.map(super::VerifiedSpeakerBinding::target_id),
            fence_epoch,
        };
        request.ensure_fence(&state.fence)?;
        Ok::<_, PrefixdError>((guard, request))
    }).await.map_err(|_| PrefixdError::Internal(
        "lifetime read-only preparation timed out; refresh mitigation and audit before retrying".into(),
    ))??;
    state
        .repo
        .extend_flowspec_lifetime(&request, &state.fence)
        .await
}

pub(crate) fn extension_safelisted(target: &str) -> PrefixdError {
    PrefixdError::GuardrailViolation(GuardrailError::Safelisted { ip: target.into() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bgp::{FlowSpecReader, FlowSpecWriter, MockAnnouncer},
        config::{AuthMode, BgpMode, Inventory, Playbooks, Settings},
        db::{ListParams, MockRepository, RepositoryTrait},
        domain::{ActionParams, AttackVector, MatchCriteria, WithdrawalRequest},
    };
    use std::sync::{Arc, atomic::Ordering::Relaxed};

    fn rule(prefix: &str) -> Mitigation {
        let mut m = Mitigation::from_intent(
            MitigationIntent {
                event_id: Uuid::new_v4(),
                customer_id: Some("owner".into()),
                service_id: None,
                pop: "test-pop".into(),
                match_criteria: MatchCriteria {
                    dst_prefix: prefix.into(),
                    protocol: Some(17),
                    dst_ports: vec![53],
                    src_prefix: Some(
                        if prefix.contains(':') {
                            "2001:db8:ffff::/48"
                        } else {
                            "192.0.2.0/24"
                        }
                        .into(),
                    ),
                    src_ports: vec![123],
                    ..Default::default()
                },
                action_type: ActionType::Police,
                action_params: ActionParams {
                    rate_bps: Some(8_000_000),
                    ..Default::default()
                },
                ttl_seconds: 120,
                reason: "original detector reason".into(),
            },
            prefix.split('/').next().unwrap().into(),
            AttackVector::UdpFlood,
        );
        m.activate();
        m.origin_mode = Some(OperationMode::Enforced);
        m
    }

    fn state(
        repo: Arc<MockRepository>,
        speaker: Arc<dyn crate::bgp::FlowSpecAnnouncer>,
        configure: impl FnOnce(&mut Settings),
    ) -> Arc<AppState> {
        let mut settings: Settings =
            serde_saphyr::from_str(include_str!("../../configs/prefixd.yaml")).unwrap();
        settings.pop = "test-pop".into();
        settings.mode = OperationMode::Enforced;
        settings.http.auth.mode = AuthMode::None;
        settings.bgp.mode = BgpMode::Mock;
        settings.guardrails.dst_prefix_minlen = 24;
        settings.guardrails.dst_prefix_minlen_v6 = Some(48);
        settings.guardrails.dst_prefix_maxlen_v6 = Some(128);
        settings.guardrails.allow_src_prefix_match = true;
        settings.quotas.max_active_global = 1;
        settings.quotas.max_active_per_pop = 1;
        settings.quotas.max_active_per_customer = 1;
        settings.quotas.max_new_per_minute = 1;
        configure(&mut settings);
        let inventory: Inventory = serde_json::from_value(serde_json::json!({"customers":[{
            "customer_id":"owner","name":"Owner","prefixes":["203.0.113.0/24","2001:db8:1234::/48"],"services":[]
        }]})).unwrap();
        AppState::new(
            settings,
            inventory,
            Playbooks { playbooks: vec![] },
            repo,
            speaker,
            ".".into(),
        )
        .unwrap()
    }

    async fn audits(repo: &MockRepository) -> Vec<AuditEntry> {
        repo.list_audit(&ListParams {
            limit: 100,
            ..Default::default()
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn extension_at_full_quota_preserves_exact_rule_and_speaker_for_both_families() {
        for prefix in [
            "203.0.113.10/32",
            "203.0.113.0/24",
            "2001:db8:1234::10/128",
            "2001:db8:1234::/48",
        ] {
            let repo = Arc::new(MockRepository::new());
            let speaker = Arc::new(MockAnnouncer::new());
            let state = state(repo.clone(), speaker.clone(), |_| {});
            let mut m = rule(prefix);
            if prefix.ends_with("/32") {
                m.action_type = ActionType::Discard;
                m.action_params.rate_bps = None;
                m.scope_hash = m.match_criteria.scope_hash_for(m.action_type);
            }
            if prefix.ends_with("/48") {
                m.status = MitigationStatus::Escalated;
            }
            repo.insert_mitigation(&m).await.unwrap();
            speaker
                .announce(&super::super::mitigation_rule(&m).unwrap())
                .await
                .unwrap();
            let routes = speaker.list_active().await.unwrap();
            let result = extend_flowspec_lifetime(
                &state,
                m.mitigation_id,
                600,
                "alice".into(),
                "attack continues".into(),
            )
            .await
            .unwrap();
            assert!(result.extended);
            assert!(result.mitigation.expires_at > m.expires_at);
            assert_eq!(repo.count_active_global().await.unwrap(), 1);
            let mut before = serde_json::to_value(&m).unwrap();
            let mut after = serde_json::to_value(&result.mitigation).unwrap();
            for key in ["updated_at", "expires_at"] {
                before.as_object_mut().unwrap().remove(key);
                after.as_object_mut().unwrap().remove(key);
            }
            assert_eq!(before, after);
            assert_eq!(
                serde_json::to_value(routes).unwrap(),
                serde_json::to_value(speaker.list_active().await.unwrap()).unwrap()
            );
            let audit = audits(&repo).await;
            assert_eq!(audit.len(), 1);
            assert_eq!(audit[0].actor_id.as_deref(), Some("alice"));
            assert_eq!(audit[0].action, "extend");
            assert_eq!(
                audit[0].details["previous_expires_at"],
                serde_json::to_value(m.expires_at).unwrap()
            );
            assert_eq!(
                audit[0].details["expires_at"],
                serde_json::to_value(result.mitigation.expires_at).unwrap()
            );
            let noop = extend_flowspec_lifetime(
                &state,
                m.mitigation_id,
                120,
                "alice".into(),
                "check".into(),
            )
            .await
            .unwrap();
            assert!(!noop.extended);
            assert_eq!(noop.mitigation.updated_at, result.mitigation.updated_at);
            assert_eq!(audits(&repo).await.len(), 1);
        }
    }

    #[tokio::test]
    async fn eligibility_bounds_and_current_policy_fail_closed_without_mutation() {
        for variant in 0..19 {
            let repo = Arc::new(MockRepository::new());
            let mut m = rule("203.0.113.10/32");
            match variant {
                0 => m.status = MitigationStatus::Pending,
                1 => m.status = MitigationStatus::Withdrawn,
                2 => m.action_type = ActionType::Blackhole,
                3 => m.origin_mode = None,
                4 => m.origin_mode = Some(OperationMode::DryRun),
                5 => m.pop = "foreign".into(),
                6 => m.expires_at = Utc::now(),
                7 => m.customer_id = None,
                8 => m.customer_id = Some("new-owner".into()),
                14 => m.service_id = Some("former-service".into()),
                16 => m.status = MitigationStatus::Expired,
                17 => m.withdrawn_at = Some(Utc::now()),
                _ => {}
            }
            let state = state(
                repo.clone(),
                Arc::new(MockAnnouncer::new()),
                |s| match variant {
                    9 => s.mode = OperationMode::DryRun,
                    10 => s.guardrails.allow_src_prefix_match = false,
                    11 => s.safelist.prefixes = vec!["203.0.113.0/24".into()],
                    12 => s.guardrails.require_ttl = false,
                    15 => s.guardrails.max_ports = 0,
                    _ => {}
                },
            );
            repo.insert_mitigation(&m).await.unwrap();
            let before = serde_json::to_value(&m).unwrap();
            let ttl = if variant == 12 {
                0
            } else if variant == 13 {
                u32::MAX
            } else if variant == 18 {
                1
            } else {
                600
            };
            assert!(
                extend_flowspec_lifetime(
                    &state,
                    m.mitigation_id,
                    ttl,
                    "alice".into(),
                    "check".into()
                )
                .await
                .is_err(),
                "variant {variant}"
            );
            assert_eq!(
                before,
                serde_json::to_value(repo.get_mitigation(m.mitigation_id).await.unwrap().unwrap())
                    .unwrap()
            );
            assert!(audits(&repo).await.is_empty());
        }
    }

    #[tokio::test]
    async fn withdrawal_safety_errors_and_audit_failure_preserve_state() {
        for variant in 0..6 {
            let repo = Arc::new(MockRepository::new());
            let m = rule("203.0.113.0/24");
            let state = state(repo.clone(), Arc::new(MockAnnouncer::new()), |_| {});
            repo.insert_mitigation(&m).await.unwrap();
            match variant {
                0 => {
                    repo.begin_withdrawal(
                        &WithdrawalRequest::new(
                            &m,
                            false,
                            "operator",
                            "bob",
                            "withdraw".into(),
                            true,
                        )
                        .unwrap(),
                    )
                    .await
                    .unwrap();
                }
                1 => {
                    repo.fail_safelist.store(true, Relaxed);
                }
                2 => {
                    repo.fail_active_reads.store(true, Relaxed);
                }
                3 => {
                    repo.fail_extension_audit.store(true, Relaxed);
                }
                4 => {
                    repo.insert_safelist("203.0.113.10/32", "bob", None)
                        .await
                        .unwrap();
                }
                5 => {
                    let mut duplicate = m.clone();
                    duplicate.mitigation_id = Uuid::new_v4();
                    repo.insert_mitigation(&duplicate).await.unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                extend_flowspec_lifetime(
                    &state,
                    m.mitigation_id,
                    600,
                    "alice".into(),
                    "check".into()
                )
                .await
                .is_err()
            );
            assert_eq!(
                repo.get_mitigation(m.mitigation_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .expires_at,
                m.expires_at
            );
            assert!(audits(&repo).await.is_empty());
        }
    }

    #[tokio::test]
    async fn concurrent_extensions_serialize_and_blank_reason_never_noops() {
        let repo = Arc::new(MockRepository::new());
        let m = rule("203.0.113.10/32");
        let state = state(repo.clone(), Arc::new(MockAnnouncer::new()), |_| {});
        repo.insert_mitigation(&m).await.unwrap();
        assert!(
            extend_flowspec_lifetime(&state, m.mitigation_id, 30, "alice".into(), "  ".into())
                .await
                .is_err()
        );
        let (a, b) = tokio::join!(
            extend_flowspec_lifetime(&state, m.mitigation_id, 600, "alice".into(), "first".into()),
            extend_flowspec_lifetime(&state, m.mitigation_id, 120, "bob".into(), "second".into())
        );
        assert!(a.unwrap().extended);
        assert!(!b.unwrap().extended);
        assert_eq!(audits(&repo).await.len(), 1);
    }
    #[tokio::test]
    async fn expiry_and_ownership_are_rechecked_after_inventory_await() {
        for expire in [true, false] {
            let repo = Arc::new(MockRepository::new());
            let mut m = rule("203.0.113.10/32");
            m.expires_at = Utc::now() + chrono::Duration::seconds(if expire { 1 } else { 120 });
            let state = state(repo.clone(), Arc::new(MockAnnouncer::new()), |_| {});
            repo.insert_mitigation(&m).await.unwrap();
            let mut inventory = state.inventory.write().await;
            let cloned = state.clone();
            let id = m.mitigation_id;
            let running = tokio::spawn(async move {
                extend_flowspec_lifetime(&cloned, id, 600, "alice".into(), "check".into()).await
            });
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while repo.lifecycle_read_counts().1 == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            if expire {
                tokio::time::sleep(
                    (m.expires_at - Utc::now()).to_std().unwrap_or_default()
                        + std::time::Duration::from_millis(10),
                )
                .await;
            } else {
                *inventory = Inventory::new(vec![]);
            }
            drop(inventory);
            assert!(running.await.unwrap().is_err());
            assert_eq!(
                repo.get_mitigation(id).await.unwrap().unwrap().expires_at,
                m.expires_at
            );
            assert!(audits(&repo).await.is_empty());
        }
    }

    #[tokio::test]
    async fn authenticated_endpoint_enforces_roles_reason_and_records_session_actor() {
        use crate::domain::OperatorRole;
        use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
        use axum::{
            body::{Body, to_bytes},
            http::{Request, StatusCode},
        };
        use tower::ServiceExt;
        let repo = Arc::new(MockRepository::new());
        let m = rule("203.0.113.10/32");
        repo.insert_mitigation(&m).await.unwrap();
        let hash = Argon2::default()
            .hash_password(
                b"test-password",
                &SaltString::encode_b64(b"extension-test-salt").unwrap(),
            )
            .unwrap()
            .to_string();
        for (name, role) in [
            ("viewer", OperatorRole::Viewer),
            ("alice", OperatorRole::Operator),
        ] {
            repo.create_operator(name, &hash, role, None).await.unwrap();
        }
        let state = state(repo.clone(), Arc::new(MockAnnouncer::new()), |s| {
            s.http.auth.mode = AuthMode::Credentials
        });
        let app = crate::api::create_test_router(state);
        let spec = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/openapi.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let spec: serde_json::Value =
            serde_json::from_slice(&to_bytes(spec.into_body(), 2_000_000).await.unwrap()).unwrap();
        assert!(spec["paths"]["/v1/mitigations/{id}/extend"]["post"].is_object());
        assert!(spec["components"]["schemas"]["ExtendMitigationRequest"].is_object());
        assert!(spec["components"]["schemas"]["ExtendMitigationResponse"].is_object());
        let uri = format!("/v1/mitigations/{}/extend", m.mitigation_id);
        let call = |cookie: Option<String>, body: &str| {
            let mut request = Request::builder()
                .method("POST")
                .uri(&uri)
                .header("content-type", "application/json");
            if let Some(cookie) = cookie {
                request = request.header("cookie", cookie);
            }
            request.body(Body::from(body.to_owned())).unwrap()
        };
        assert_eq!(
            app.clone()
                .oneshot(call(None, r#"{"ttl_seconds":600,"reason":"test"}"#))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        for (name, expected) in [("viewer", StatusCode::FORBIDDEN), ("alice", StatusCode::OK)] {
            let login = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/auth/login")
                        .header("content-type", "application/json")
                        .body(Body::from(format!(
                            r#"{{"username":"{name}","password":"test-password"}}"#
                        )))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(login.status(), StatusCode::OK);
            let cookie = login
                .headers()
                .get("set-cookie")
                .unwrap()
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned();
            if name == "alice" {
                for (body, status) in [
                    (r#"{"ttl_seconds":600}"#, StatusCode::UNPROCESSABLE_ENTITY),
                    (
                        r#"{"ttl_seconds":600,"reason":"  "}"#,
                        StatusCode::BAD_REQUEST,
                    ),
                    (
                        r#"{"ttl_seconds":0,"reason":"test"}"#,
                        StatusCode::UNPROCESSABLE_ENTITY,
                    ),
                    (
                        r#"{"ttl_seconds":600,"reason":"test","actor":"forged"}"#,
                        StatusCode::UNPROCESSABLE_ENTITY,
                    ),
                ] {
                    assert_eq!(
                        app.clone()
                            .oneshot(call(Some(cookie.clone()), body))
                            .await
                            .unwrap()
                            .status(),
                        status
                    );
                }
            }
            let response = app
                .clone()
                .oneshot(call(
                    Some(cookie),
                    r#"{"ttl_seconds":600,"reason":"attack continues"}"#,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
            if name == "alice" {
                let body: serde_json::Value =
                    serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap())
                        .unwrap();
                assert_eq!(body["extended"], true);
            }
        }
        let audit = audits(&repo).await;
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].actor_id.as_deref(), Some("alice"));
    }

    #[tokio::test]
    async fn extension_never_calls_add_delete_or_lease_renew() {
        use crate::bgp::{
            FlowSpecAnnouncer, FlowSpecMatchSupport, InjectionLeases, LeaseGeneration,
        };
        use crate::domain::FlowSpecRule;
        use std::sync::atomic::AtomicUsize;
        #[derive(Default)]
        struct Writes(AtomicUsize);
        impl FlowSpecAnnouncer for Writes {
            fn backend(&self) -> &'static str {
                "mock"
            }
            fn match_support(&self) -> FlowSpecMatchSupport {
                FlowSpecMatchSupport::ALL
            }
            fn injection_leases(&self) -> Option<&dyn InjectionLeases> {
                Some(self)
            }
        }
        #[async_trait::async_trait]
        impl FlowSpecWriter for Writes {
            async fn announce(&self, _: &FlowSpecRule) -> Result<()> {
                self.0.fetch_add(1, Relaxed);
                Ok(())
            }
            async fn announce_leased(&self, _: &FlowSpecRule, _: u32) -> Result<LeaseGeneration> {
                self.0.fetch_add(1, Relaxed);
                Err(PrefixdError::Internal("unexpected leased add".into()))
            }
            async fn withdraw(&self, _: &FlowSpecRule) -> Result<()> {
                self.0.fetch_add(1, Relaxed);
                Ok(())
            }
        }
        #[async_trait::async_trait]
        impl InjectionLeases for Writes {
            async fn live_lease(&self, _: &str) -> Result<Option<Option<LeaseGeneration>>> {
                Ok(None)
            }
            async fn renew_lease(&self, _: &str, _: LeaseGeneration, _: u32) -> Result<bool> {
                self.0.fetch_add(1, Relaxed);
                Ok(true)
            }
            fn lease_confirmed(&self) -> bool {
                false
            }
        }
        let repo = Arc::new(MockRepository::new());
        let speaker = Arc::new(Writes::default());
        let state = state(repo.clone(), speaker.clone(), |_| {});
        let m = rule("203.0.113.10/32");
        repo.insert_mitigation(&m).await.unwrap();
        extend_flowspec_lifetime(
            &state,
            m.mitigation_id,
            600,
            "alice".into(),
            "ongoing".into(),
        )
        .await
        .unwrap();
        extend_flowspec_lifetime(&state, m.mitigation_id, 30, "alice".into(), "noop".into())
            .await
            .unwrap();
        assert_eq!(speaker.0.load(Relaxed), 0);
        // Negative control: an idempotent writer call changes the spy even when
        // a speaker's final route inventory would have remained identical.
        speaker
            .announce(&super::super::mitigation_rule(&m).unwrap())
            .await
            .unwrap();
        assert_ne!(speaker.0.load(Relaxed), 0);
    }

    #[tokio::test]
    async fn extended_fragment_and_length_selectors_survive_unchanged() {
        for fragment in [false, true] {
            let repo = Arc::new(MockRepository::new());
            let mut m = rule("2001:db8:1234::/48");
            m.match_criteria.packet_length = Some(crate::domain::PacketLengthRange {
                min: 512,
                max: 1400,
            });
            if fragment {
                m.match_criteria.fragment = Some(crate::domain::FragmentMatch::NonFirst);
                m.match_criteria.src_ports.clear();
                m.match_criteria.dst_ports.clear();
                m.match_criteria.packet_length = None;
            }
            m.scope_hash = m.match_criteria.scope_hash_for(m.action_type);
            let state = state(repo.clone(), Arc::new(MockAnnouncer::new()), |s| {
                s.guardrails.allow_fragment_match = true;
                s.guardrails.allow_packet_length_match = true;
            });
            repo.insert_mitigation(&m).await.unwrap();
            let result = extend_flowspec_lifetime(
                &state,
                m.mitigation_id,
                600,
                "alice".into(),
                "ongoing".into(),
            )
            .await
            .unwrap();
            assert_eq!(
                serde_json::to_value(result.mitigation.match_criteria).unwrap(),
                serde_json::to_value(m.match_criteria).unwrap()
            );
        }
    }

    #[tokio::test]
    async fn fence_loss_and_regain_during_await_refuses_even_an_unchanged_horizon() {
        let repo = Arc::new(MockRepository::new());
        let m = rule("203.0.113.10/32");
        let state = state(repo.clone(), Arc::new(MockAnnouncer::new()), |_| {});
        repo.insert_mitigation(&m).await.unwrap();
        let held = state.inventory.write().await;
        let cloned = state.clone();
        let id = m.mitigation_id;
        let running = tokio::spawn(async move {
            extend_flowspec_lifetime(&cloned, id, 30, "alice".into(), "check".into()).await
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while repo.lifecycle_read_counts().1 == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        state.fence.set(false);
        state.fence.set(true);
        drop(held);
        assert!(matches!(running.await.unwrap(), Err(PrefixdError::Standby)));
        assert_eq!(
            repo.get_mitigation(id).await.unwrap().unwrap().updated_at,
            m.updated_at
        );
        assert!(audits(&repo).await.is_empty());
    }
    #[tokio::test]
    async fn preparation_timeout_releases_lifecycle_lock_without_waiting_for_inventory() {
        let repo = Arc::new(MockRepository::new());
        let m = rule("203.0.113.10/32");
        let state = state(repo.clone(), Arc::new(MockAnnouncer::new()), |_| {});
        repo.insert_mitigation(&m).await.unwrap();
        let inventory = state.inventory.write().await;
        let cloned = state.clone();
        let id = m.mitigation_id;
        let running = tokio::spawn(async move {
            extend_flowspec_lifetime(&cloned, id, 600, "alice".into(), "ongoing".into()).await
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while repo.lifecycle_read_counts().1 == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            state.mitigation_lock.try_lock().is_err(),
            "preparation must own the lifecycle lock before the timeout"
        );
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(7), running)
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(outcome, Err(PrefixdError::Internal(message)) if message.contains("preparation timed out"))
        );
        // Inventory remains blocked: only the preparation deadline can release
        // the lifecycle guard, allowing withdrawal/expiry work to proceed.
        assert!(state.mitigation_lock.try_lock().is_ok());
        assert_eq!(
            repo.get_mitigation(id).await.unwrap().unwrap().expires_at,
            m.expires_at
        );
        assert!(audits(&repo).await.is_empty());
        drop(inventory);
        assert!(
            extend_flowspec_lifetime(&state, id, 600, "alice".into(), "retry".into())
                .await
                .unwrap()
                .extended
        );
    }
}
