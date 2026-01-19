use crate::domain::{AttackEvent, Mitigation};

/// Result of correlating an event with existing mitigations
#[derive(Debug, Clone)]
pub enum CorrelationResult {
    /// Exact scope match - same victim, vector, and ports
    ExactMatch {
        mitigation_id: uuid::Uuid,
        action: CorrelationAction,
    },
    /// Same victim and vector, but different ports
    RelatedMatch {
        mitigation_id: uuid::Uuid,
        port_relationship: PortRelationship,
        action: CorrelationAction,
    },
    /// No existing mitigation for this scope
    NewScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortRelationship {
    /// Event ports are a superset of mitigation ports
    Superset,
    /// Event ports are a subset of mitigation ports
    Subset,
    /// Event ports partially overlap with mitigation ports
    Overlap,
    /// Event ports are completely different
    Disjoint,
}

#[derive(Debug, Clone)]
pub enum CorrelationAction {
    /// Extend TTL on existing mitigation
    ExtendTtl,
    /// Replace existing mitigation with expanded scope
    Replace,
    /// Keep existing mitigation, ignore event
    KeepExisting,
    /// Create parallel mitigation for disjoint ports
    CreateParallel,
}

/// Correlates incoming events with existing mitigations
pub struct EventCorrelator {
    #[allow(dead_code)]
    correlation_window_seconds: u32,
}

impl EventCorrelator {
    pub fn new(correlation_window_seconds: u32) -> Self {
        Self {
            correlation_window_seconds,
        }
    }

    /// Correlate an event against active mitigations for the same victim
    pub fn correlate(
        &self,
        event: &AttackEvent,
        active_mitigations: &[Mitigation],
    ) -> CorrelationResult {
        let event_ports: std::collections::HashSet<u16> =
            event.top_dst_ports().into_iter().collect();
        let event_vector = event.attack_vector();

        // Find mitigations for the same victim
        let victim_mitigations: Vec<_> = active_mitigations
            .iter()
            .filter(|m| m.victim_ip == event.victim_ip)
            .collect();

        if victim_mitigations.is_empty() {
            return CorrelationResult::NewScope;
        }

        // Check for exact scope match first
        for m in &victim_mitigations {
            if m.vector == event_vector {
                let mitigation_ports: std::collections::HashSet<u16> =
                    m.match_criteria.dst_ports.iter().copied().collect();

                if event_ports == mitigation_ports {
                    return CorrelationResult::ExactMatch {
                        mitigation_id: m.mitigation_id,
                        action: CorrelationAction::ExtendTtl,
                    };
                }
            }
        }

        // Check for related matches (same vector, different ports)
        for m in &victim_mitigations {
            if m.vector == event_vector {
                let mitigation_ports: std::collections::HashSet<u16> =
                    m.match_criteria.dst_ports.iter().copied().collect();

                let relationship = self.compare_ports(&event_ports, &mitigation_ports);
                let action = self.decide_action(&relationship);

                return CorrelationResult::RelatedMatch {
                    mitigation_id: m.mitigation_id,
                    port_relationship: relationship,
                    action,
                };
            }
        }

        // No match for this vector
        CorrelationResult::NewScope
    }

    fn compare_ports(
        &self,
        event_ports: &std::collections::HashSet<u16>,
        mitigation_ports: &std::collections::HashSet<u16>,
    ) -> PortRelationship {
        if event_ports.is_empty() || mitigation_ports.is_empty() {
            return PortRelationship::Disjoint;
        }

        let event_superset = mitigation_ports.is_subset(event_ports);
        let event_subset = event_ports.is_subset(mitigation_ports);
        let has_overlap = event_ports.intersection(mitigation_ports).count() > 0;

        match (event_superset, event_subset, has_overlap) {
            (true, true, _) => PortRelationship::Subset, // Equal sets
            (true, false, _) => PortRelationship::Superset,
            (false, true, _) => PortRelationship::Subset,
            (false, false, true) => PortRelationship::Overlap,
            (false, false, false) => PortRelationship::Disjoint,
        }
    }

    fn decide_action(&self, relationship: &PortRelationship) -> CorrelationAction {
        match relationship {
            // Event covers more ports - expand mitigation
            PortRelationship::Superset => CorrelationAction::Replace,
            // Event covers fewer ports - existing mitigation is sufficient
            PortRelationship::Subset => CorrelationAction::KeepExisting,
            // Partial overlap - extend TTL (could also expand, but conservative)
            PortRelationship::Overlap => CorrelationAction::ExtendTtl,
            // Completely different ports - create separate mitigation
            PortRelationship::Disjoint => CorrelationAction::CreateParallel,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{ActionParams, ActionType, AttackVector, MatchCriteria, MitigationStatus};
    use chrono::Utc;
    use uuid::Uuid;

    fn test_event(victim_ip: &str, ports: Vec<u16>) -> AttackEvent {
        AttackEvent {
            event_id: Uuid::new_v4(),
            external_event_id: None,
            source: "test".to_string(),
            event_timestamp: Utc::now(),
            ingested_at: Utc::now(),
            victim_ip: victim_ip.to_string(),
            vector: "udp_flood".to_string(),
            protocol: Some(17),
            bps: Some(100_000_000),
            pps: Some(50_000),
            top_dst_ports_json: serde_json::to_string(&ports).unwrap(),
            confidence: Some(0.9),
        }
    }

    fn test_mitigation(victim_ip: &str, ports: Vec<u16>) -> Mitigation {
        let now = Utc::now();
        Mitigation {
            mitigation_id: Uuid::new_v4(),
            scope_hash: "test".to_string(),
            pop: "test".to_string(),
            customer_id: Some("cust_1".to_string()),
            service_id: None,
            victim_ip: victim_ip.to_string(),
            vector: AttackVector::UdpFlood,
            match_criteria: MatchCriteria {
                dst_prefix: format!("{}/32", victim_ip),
                protocol: Some(17),
                dst_ports: ports,
            },
            action_type: ActionType::Police,
            action_params: ActionParams {
                rate_bps: Some(5_000_000),
            },
            status: MitigationStatus::Active,
            created_at: now,
            updated_at: now,
            expires_at: now + chrono::Duration::seconds(300),
            withdrawn_at: None,
            triggering_event_id: Uuid::new_v4(),
            last_event_id: Uuid::new_v4(),
            escalated_from_id: None,
            reason: "test".to_string(),
            rejection_reason: None,
        }
    }

    #[test]
    fn test_exact_match() {
        let correlator = EventCorrelator::new(300);
        let event = test_event("203.0.113.10", vec![53, 123]);
        let mitigation = test_mitigation("203.0.113.10", vec![53, 123]);

        let result = correlator.correlate(&event, &[mitigation]);
        assert!(matches!(
            result,
            CorrelationResult::ExactMatch {
                action: CorrelationAction::ExtendTtl,
                ..
            }
        ));
    }

    #[test]
    fn test_superset_replaces() {
        let correlator = EventCorrelator::new(300);
        let event = test_event("203.0.113.10", vec![53, 123, 161]);
        let mitigation = test_mitigation("203.0.113.10", vec![53, 123]);

        let result = correlator.correlate(&event, &[mitigation]);
        assert!(matches!(
            result,
            CorrelationResult::RelatedMatch {
                port_relationship: PortRelationship::Superset,
                action: CorrelationAction::Replace,
                ..
            }
        ));
    }

    #[test]
    fn test_subset_keeps_existing() {
        let correlator = EventCorrelator::new(300);
        let event = test_event("203.0.113.10", vec![53]);
        let mitigation = test_mitigation("203.0.113.10", vec![53, 123]);

        let result = correlator.correlate(&event, &[mitigation]);
        assert!(matches!(
            result,
            CorrelationResult::RelatedMatch {
                port_relationship: PortRelationship::Subset,
                action: CorrelationAction::KeepExisting,
                ..
            }
        ));
    }

    #[test]
    fn test_disjoint_creates_parallel() {
        let correlator = EventCorrelator::new(300);
        let event = test_event("203.0.113.10", vec![161, 162]);
        let mitigation = test_mitigation("203.0.113.10", vec![53, 123]);

        let result = correlator.correlate(&event, &[mitigation]);
        assert!(matches!(
            result,
            CorrelationResult::RelatedMatch {
                port_relationship: PortRelationship::Disjoint,
                action: CorrelationAction::CreateParallel,
                ..
            }
        ));
    }

    #[test]
    fn test_new_scope_for_different_victim() {
        let correlator = EventCorrelator::new(300);
        let event = test_event("203.0.113.20", vec![53]);
        let mitigation = test_mitigation("203.0.113.10", vec![53]);

        let result = correlator.correlate(&event, &[mitigation]);
        assert!(matches!(result, CorrelationResult::NewScope));
    }
}
