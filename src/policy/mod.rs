mod correlation;
mod escalation;

pub use correlation::*;
pub use escalation::*;

use crate::config::{AllowedPorts, IpContext, PlaybookAction, Playbooks};

use crate::domain::{
    ActionParams, ActionType, AttackEvent, AttackVector, MatchCriteria, MitigationIntent,
};
use crate::error::{PrefixdError, Result};

pub struct PolicyEngine {
    playbooks: Playbooks,
    pop: String,
    default_ttl: u32,
}

impl PolicyEngine {
    pub fn new(playbooks: Playbooks, pop: String, default_ttl: u32) -> Self {
        Self {
            playbooks,
            pop,
            default_ttl,
        }
    }

    pub fn evaluate(&self, event: &AttackEvent, context: Option<&IpContext>) -> Result<MitigationIntent> {
        let vector = event.attack_vector();
        let ports = event.top_dst_ports();
        let has_ports = !ports.is_empty();

        // Find matching playbook
        let playbook = self
            .playbooks
            .find_playbook(vector, has_ports)
            .ok_or_else(|| PrefixdError::NoPlaybookFound(vector.to_string()))?;

        // Get initial step
        let step = self
            .playbooks
            .get_initial_step(playbook)
            .ok_or_else(|| PrefixdError::NoPlaybookFound(format!("{} (no steps)", vector)))?;

        // Compute allowed ports intersection
        let dst_ports = self.compute_port_intersection(&ports, context, vector);

        // Build match criteria
        let match_criteria = MatchCriteria {
            dst_prefix: format!("{}/32", event.victim_ip),
            protocol: vector.to_protocol(),
            dst_ports,
        };

        // Build action
        let (action_type, action_params) = match step.action {
            PlaybookAction::Police => (
                ActionType::Police,
                ActionParams {
                    rate_bps: step.rate_bps,
                },
            ),
            PlaybookAction::Discard => (ActionType::Discard, ActionParams { rate_bps: None }),
        };

        let ttl = if step.ttl_seconds > 0 {
            step.ttl_seconds
        } else {
            self.default_ttl
        };

        let reason = format!(
            "{} to {} (playbook: {})",
            vector,
            context
                .and_then(|c| c.service_name.as_deref())
                .unwrap_or("unknown service"),
            playbook.name
        );

        Ok(MitigationIntent {
            event_id: event.event_id,
            customer_id: context.map(|c| c.customer_id.clone()),
            service_id: context.and_then(|c| c.service_id.clone()),
            pop: self.pop.clone(),
            match_criteria,
            action_type,
            action_params,
            ttl_seconds: ttl,
            reason,
        })
    }

    fn compute_port_intersection(
        &self,
        event_ports: &[u16],
        context: Option<&IpContext>,
        vector: AttackVector,
    ) -> Vec<u16> {
        let default_ports = AllowedPorts::default();
        let allowed = context.map(|c| &c.allowed_ports).unwrap_or(&default_ports);

        let allowed_for_proto = match vector {
            AttackVector::UdpFlood => &allowed.udp,
            AttackVector::SynFlood | AttackVector::AckFlood => &allowed.tcp,
            _ => return event_ports.to_vec(),
        };

        if allowed_for_proto.is_empty() {
            // No service-level port restriction, use event ports
            return event_ports.to_vec();
        }

        if event_ports.is_empty() {
            // No event ports, use allowed ports
            return allowed_for_proto.clone();
        }

        // Intersection
        event_ports
            .iter()
            .filter(|p| allowed_for_proto.contains(p))
            .copied()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Playbook, PlaybookMatch, PlaybookStep};
    use crate::domain::AttackVector;
    use uuid::Uuid;

    fn test_playbooks() -> Playbooks {
        Playbooks {
            playbooks: vec![Playbook {
                name: "udp_flood_test".to_string(),
                match_criteria: PlaybookMatch {
                    vector: AttackVector::UdpFlood,
                    require_top_ports: false,
                },
                steps: vec![PlaybookStep {
                    action: PlaybookAction::Police,
                    rate_bps: Some(5_000_000),
                    ttl_seconds: 120,
                    require_confidence_at_least: None,
                    require_persistence_seconds: None,
                }],
            }],
        }
    }

    #[test]
    fn test_evaluate_produces_intent() {
        let engine = PolicyEngine::new(test_playbooks(), "iad1".to_string(), 120);

        let event = AttackEvent {
            event_id: Uuid::new_v4(),
            external_event_id: None,
            source: "test".to_string(),
            event_timestamp: chrono::Utc::now(),
            ingested_at: chrono::Utc::now(),
            victim_ip: "203.0.113.10".to_string(),
            vector: "udp_flood".to_string(),
            protocol: Some(17),
            bps: Some(100_000_000),
            pps: Some(50_000),
            top_dst_ports_json: "[53]".to_string(),
            confidence: Some(0.9),
        };

        let intent = engine.evaluate(&event, None).unwrap();

        assert_eq!(intent.match_criteria.dst_prefix, "203.0.113.10/32");
        assert_eq!(intent.action_type, ActionType::Police);
        assert_eq!(intent.action_params.rate_bps, Some(5_000_000));
    }
}
