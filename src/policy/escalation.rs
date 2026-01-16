use chrono::{Duration, Utc};

use crate::config::{EscalationConfig, PolicyProfile};
use crate::domain::{ActionType, Mitigation, MitigationStatus};

/// Escalation decision for a mitigation
#[derive(Debug, Clone)]
pub enum EscalationDecision {
    /// No escalation needed
    None,
    /// Escalate to discard
    Escalate { reason: String },
    /// Cannot escalate (policy forbids or max duration exceeded)
    Blocked { reason: String },
}

/// Evaluates whether a mitigation should escalate from police to discard
pub struct EscalationEvaluator {
    config: EscalationConfig,
}

impl EscalationEvaluator {
    pub fn new(config: EscalationConfig) -> Self {
        Self { config }
    }

    /// Evaluate if mitigation should escalate
    pub fn evaluate(
        &self,
        mitigation: &Mitigation,
        policy_profile: PolicyProfile,
        latest_confidence: Option<f64>,
    ) -> EscalationDecision {
        // Only active police mitigations can escalate
        if mitigation.status != MitigationStatus::Active {
            return EscalationDecision::None;
        }

        if mitigation.action_type != ActionType::Police {
            return EscalationDecision::None;
        }

        // Check if escalation is globally enabled
        if !self.config.enabled {
            return EscalationDecision::Blocked {
                reason: "escalation disabled globally".to_string(),
            };
        }

        // Check policy profile
        if policy_profile == PolicyProfile::Strict {
            return EscalationDecision::Blocked {
                reason: "customer policy_profile=strict forbids escalation".to_string(),
            };
        }

        // Check persistence (time since creation)
        let persistence = Utc::now() - mitigation.created_at;
        let min_persistence = Duration::seconds(self.config.min_persistence_seconds as i64);

        if persistence < min_persistence {
            return EscalationDecision::None;
        }

        // Check confidence threshold
        let confidence = latest_confidence.unwrap_or(0.0);
        if confidence < self.config.min_confidence {
            return EscalationDecision::None;
        }

        // Check max escalated duration (don't escalate if we'd exceed limit)
        // This prevents indefinite discard rules
        let max_escalated = Duration::seconds(self.config.max_escalated_duration_seconds as i64);
        let remaining_ttl = mitigation.expires_at - Utc::now();

        if remaining_ttl > max_escalated {
            return EscalationDecision::Blocked {
                reason: format!(
                    "remaining TTL {}s exceeds max_escalated_duration {}s",
                    remaining_ttl.num_seconds(),
                    self.config.max_escalated_duration_seconds
                ),
            };
        }

        EscalationDecision::Escalate {
            reason: format!(
                "persistence={}s >= {}s, confidence={:.2} >= {:.2}",
                persistence.num_seconds(),
                self.config.min_persistence_seconds,
                confidence,
                self.config.min_confidence
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{ActionParams, MatchCriteria, AttackVector};
    use uuid::Uuid;

    fn test_config() -> EscalationConfig {
        EscalationConfig {
            enabled: true,
            min_persistence_seconds: 120,
            min_confidence: 0.7,
            max_escalated_duration_seconds: 1800,
        }
    }

    fn test_mitigation(created_seconds_ago: i64, action: ActionType) -> Mitigation {
        let now = Utc::now();
        Mitigation {
            mitigation_id: Uuid::new_v4(),
            scope_hash: "test".to_string(),
            pop: "test".to_string(),
            customer_id: Some("cust_1".to_string()),
            service_id: None,
            victim_ip: "203.0.113.10".to_string(),
            vector: AttackVector::UdpFlood,
            match_criteria: MatchCriteria {
                dst_prefix: "203.0.113.10/32".to_string(),
                protocol: Some(17),
                dst_ports: vec![53],
            },
            action_type: action,
            action_params: ActionParams { rate_bps: Some(5_000_000) },
            status: MitigationStatus::Active,
            created_at: now - Duration::seconds(created_seconds_ago),
            updated_at: now,
            expires_at: now + Duration::seconds(300),
            withdrawn_at: None,
            triggering_event_id: Uuid::new_v4(),
            last_event_id: Uuid::new_v4(),
            escalated_from_id: None,
            reason: "test".to_string(),
            rejection_reason: None,
        }
    }

    #[test]
    fn test_no_escalation_if_not_persisted() {
        let evaluator = EscalationEvaluator::new(test_config());
        let mitigation = test_mitigation(60, ActionType::Police); // Only 60s old

        let decision = evaluator.evaluate(&mitigation, PolicyProfile::Normal, Some(0.9));
        assert!(matches!(decision, EscalationDecision::None));
    }

    #[test]
    fn test_no_escalation_if_low_confidence() {
        let evaluator = EscalationEvaluator::new(test_config());
        let mitigation = test_mitigation(200, ActionType::Police); // 200s old

        let decision = evaluator.evaluate(&mitigation, PolicyProfile::Normal, Some(0.5));
        assert!(matches!(decision, EscalationDecision::None));
    }

    #[test]
    fn test_escalates_when_conditions_met() {
        let evaluator = EscalationEvaluator::new(test_config());
        let mitigation = test_mitigation(200, ActionType::Police);

        let decision = evaluator.evaluate(&mitigation, PolicyProfile::Normal, Some(0.9));
        assert!(matches!(decision, EscalationDecision::Escalate { .. }));
    }

    #[test]
    fn test_strict_profile_blocks_escalation() {
        let evaluator = EscalationEvaluator::new(test_config());
        let mitigation = test_mitigation(200, ActionType::Police);

        let decision = evaluator.evaluate(&mitigation, PolicyProfile::Strict, Some(0.9));
        assert!(matches!(decision, EscalationDecision::Blocked { .. }));
    }

    #[test]
    fn test_discard_does_not_escalate() {
        let evaluator = EscalationEvaluator::new(test_config());
        let mitigation = test_mitigation(200, ActionType::Discard);

        let decision = evaluator.evaluate(&mitigation, PolicyProfile::Normal, Some(0.9));
        assert!(matches!(decision, EscalationDecision::None));
    }
}
