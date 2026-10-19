use std::net::IpAddr;

use crate::config::{AllowedPorts, IpContext, Playbooks};

use crate::domain::{ActionParams, AttackEvent, AttackVector, MatchCriteria, MitigationIntent};
use crate::error::{GuardrailError, PrefixdError, Result};

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

    pub fn evaluate(
        &self,
        event: &AttackEvent,
        context: Option<&IpContext>,
    ) -> Result<MitigationIntent> {
        let victim_ip: IpAddr = event
            .victim_ip
            .parse()
            .map_err(|_| PrefixdError::InvalidIpAddress(event.victim_ip.clone()))?;
        let prefix_len = if victim_ip.is_ipv4() { 32 } else { 128 };
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
        // An empty intersection must not turn explicit detector ports into a wildcard.
        if !ports.is_empty() && dst_ports.is_empty() {
            return Err(PrefixdError::GuardrailViolation(
                GuardrailError::NoAllowedPorts,
            ));
        }

        // Build match criteria
        let match_criteria = MatchCriteria {
            dst_prefix: format!("{victim_ip}/{prefix_len}"),
            protocol: vector.to_protocol_for(victim_ip),
            dst_ports,
            ..Default::default()
        };

        // Build action
        let action = step.flowspec_action();
        action.traffic_rate_bytes_per_second().map_err(|error| {
            PrefixdError::GuardrailViolation(GuardrailError::InvalidAction(error))
        })?;
        let action_type = action.action_type;
        let action_params = ActionParams {
            rate_bps: action.rate_bps,
            ..Default::default()
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
    use crate::config::{Playbook, PlaybookAction, PlaybookMatch, PlaybookStep, PolicyProfile};
    use crate::domain::{ActionType, AttackVector};
    use uuid::Uuid;

    fn make_event(victim_ip: &str, vector: &str, ports: &[u16]) -> AttackEvent {
        AttackEvent {
            event_id: Uuid::new_v4(),
            external_event_id: None,
            source: "test_detector".to_string(),
            event_timestamp: chrono::Utc::now(),
            ingested_at: chrono::Utc::now(),
            victim_ip: victim_ip.to_string(),
            vector: vector.to_string(),
            protocol: Some(17),
            bps: Some(100_000_000),
            pps: Some(50_000),
            top_dst_ports_json: serde_json::to_string(ports).unwrap(),
            confidence: Some(0.9),
            action: "ban".to_string(),
            raw_details: None,
        }
    }

    fn make_context(customer_id: &str, udp_ports: Vec<u16>, tcp_ports: Vec<u16>) -> IpContext {
        IpContext {
            customer_id: customer_id.to_string(),
            customer_name: format!("Customer {}", customer_id),
            policy_profile: PolicyProfile::Normal,
            service_id: Some("svc_1".to_string()),
            service_name: Some("Test Service".to_string()),
            interface: None,
            allowed_ports: AllowedPorts {
                udp: udp_ports,
                tcp: tcp_ports,
            },
        }
    }

    fn test_playbooks() -> Playbooks {
        Playbooks {
            playbooks: vec![
                Playbook {
                    name: "udp_flood_police".to_string(),
                    match_criteria: PlaybookMatch {
                        vector: AttackVector::UdpFlood,
                        require_top_ports: false,
                    },
                    correlation: None,
                    steps: vec![PlaybookStep {
                        action: PlaybookAction::Police,
                        rate_bps: Some(5_000_000),
                        ttl_seconds: 120,
                        require_confidence_at_least: None,
                        require_persistence_seconds: None,
                    }],
                },
                Playbook {
                    name: "syn_flood_discard".to_string(),
                    match_criteria: PlaybookMatch {
                        vector: AttackVector::SynFlood,
                        require_top_ports: false,
                    },
                    correlation: None,
                    steps: vec![PlaybookStep {
                        action: PlaybookAction::Discard,
                        rate_bps: None,
                        ttl_seconds: 60,
                        require_confidence_at_least: None,
                        require_persistence_seconds: None,
                    }],
                },
            ],
        }
    }

    #[test]
    fn policy_uses_canonical_host_scope_and_family_correct_protocol() {
        for (vector, v4_protocol, v6_protocol) in [
            (AttackVector::UdpFlood, 17, 17),
            (AttackVector::SynFlood, 6, 6),
            (AttackVector::AckFlood, 6, 6),
            (AttackVector::IcmpFlood, 1, 58),
        ] {
            let mut playbooks = test_playbooks();
            playbooks.playbooks[0].match_criteria.vector = vector;
            let engine = PolicyEngine::new(playbooks, "iad1".into(), 120);
            for (ip, prefix, protocol) in [
                ("203.0.113.10", "203.0.113.10/32", v4_protocol),
                ("2001:db8::10", "2001:db8::10/128", v6_protocol),
                (
                    "2001:0DB8:0000:0000:0000:0000:0000:0010",
                    "2001:db8::10/128",
                    v6_protocol,
                ),
            ] {
                let event = make_event(ip, vector.as_str(), &[]);
                let intent = engine.evaluate(&event, None).unwrap();
                assert_eq!(intent.match_criteria.dst_prefix, prefix);
                assert_eq!(intent.match_criteria.protocol, Some(protocol));
            }
        }
    }

    #[test]
    fn policy_rejects_invalid_or_prefixed_victims() {
        let engine = PolicyEngine::new(test_playbooks(), "iad1".into(), 120);
        for ip in [
            "invalid",
            "203.0.113.10/24",
            "2001:db8::10/32",
            "fe80::1%eth0",
        ] {
            let event = make_event(ip, "udp_flood", &[53]);
            assert!(matches!(
                engine.evaluate(&event, None),
                Err(PrefixdError::InvalidIpAddress(_))
            ));
        }
    }

    // ==========================================================================
    // Basic Evaluation Tests
    // ==========================================================================

    #[test]
    fn test_evaluate_udp_flood_police() {
        let engine = PolicyEngine::new(test_playbooks(), "iad1".to_string(), 120);
        let event = make_event("203.0.113.10", "udp_flood", &[53]);

        let intent = engine.evaluate(&event, None).unwrap();

        assert_eq!(intent.match_criteria.dst_prefix, "203.0.113.10/32");
        assert_eq!(intent.action_type, ActionType::Police);
        assert_eq!(intent.action_params.rate_bps, Some(5_000_000));
        assert_eq!(intent.ttl_seconds, 120);
        assert_eq!(intent.pop, "iad1");
    }

    #[test]
    fn test_evaluate_syn_flood_discard() {
        let engine = PolicyEngine::new(test_playbooks(), "lax1".to_string(), 120);
        let event = make_event("10.0.0.1", "syn_flood", &[443]);

        let intent = engine.evaluate(&event, None).unwrap();

        assert_eq!(intent.match_criteria.dst_prefix, "10.0.0.1/32");
        assert_eq!(intent.action_type, ActionType::Discard);
        assert_eq!(intent.action_params.rate_bps, None);
        assert_eq!(intent.ttl_seconds, 60);
        assert_eq!(intent.pop, "lax1");
    }

    #[test]
    fn test_evaluate_with_context() {
        let engine = PolicyEngine::new(test_playbooks(), "iad1".to_string(), 120);
        let event = make_event("192.168.1.1", "udp_flood", &[53, 80, 443]);
        let context = make_context("cust_123", vec![53, 123], vec![]);

        let intent = engine.evaluate(&event, Some(&context)).unwrap();

        assert_eq!(intent.customer_id, Some("cust_123".to_string()));
        assert_eq!(intent.service_id, Some("svc_1".to_string()));
        // Port intersection: event [53,80,443] ∩ allowed [53,123] = [53]
        assert_eq!(intent.match_criteria.dst_ports, vec![53]);
    }

    #[test]
    fn test_evaluate_no_matching_playbook() {
        let engine = PolicyEngine::new(test_playbooks(), "iad1".to_string(), 120);
        let event = make_event("10.0.0.1", "icmp_flood", &[]);

        let result = engine.evaluate(&event, None);
        assert!(result.is_err());
    }

    // ==========================================================================
    // Port Intersection Tests
    // ==========================================================================

    #[test]
    fn test_port_intersection_with_allowed_ports() {
        let engine = PolicyEngine::new(test_playbooks(), "iad1".to_string(), 120);

        // Event has ports [53, 80, 443], service allows [53, 123]
        let event_ports = vec![53, 80, 443];
        let context = make_context("cust", vec![53, 123], vec![]);

        let result =
            engine.compute_port_intersection(&event_ports, Some(&context), AttackVector::UdpFlood);
        assert_eq!(result, vec![53]);
    }

    #[test]
    fn test_port_intersection_no_overlap() {
        let engine = PolicyEngine::new(test_playbooks(), "iad1".to_string(), 120);

        // Event has ports [80, 443], service allows [53, 123] - no overlap
        let event_ports = vec![80, 443];
        let context = make_context("cust", vec![53, 123], vec![]);

        let result =
            engine.compute_port_intersection(&event_ports, Some(&context), AttackVector::UdpFlood);
        assert!(result.is_empty());
    }

    #[test]
    fn test_port_intersection_no_service_restriction() {
        let engine = PolicyEngine::new(test_playbooks(), "iad1".to_string(), 120);

        // Service has no port restrictions - use event ports
        let event_ports = vec![53, 80, 443];
        let context = make_context("cust", vec![], vec![]);

        let result =
            engine.compute_port_intersection(&event_ports, Some(&context), AttackVector::UdpFlood);
        assert_eq!(result, event_ports);
    }

    #[test]
    fn test_port_intersection_no_event_ports() {
        let engine = PolicyEngine::new(test_playbooks(), "iad1".to_string(), 120);

        // Event has no ports - use service allowed ports
        let event_ports: Vec<u16> = vec![];
        let context = make_context("cust", vec![53, 123], vec![]);

        let result =
            engine.compute_port_intersection(&event_ports, Some(&context), AttackVector::UdpFlood);
        assert_eq!(result, vec![53, 123]);
    }

    #[test]
    fn test_port_intersection_tcp_vector() {
        let engine = PolicyEngine::new(test_playbooks(), "iad1".to_string(), 120);

        // TCP vector should use TCP ports from context
        let event_ports = vec![80, 443, 8080];
        let context = make_context("cust", vec![53], vec![80, 443]);

        let result =
            engine.compute_port_intersection(&event_ports, Some(&context), AttackVector::SynFlood);
        assert_eq!(result, vec![80, 443]);
    }

    #[test]
    fn test_port_intersection_no_context() {
        let engine = PolicyEngine::new(test_playbooks(), "iad1".to_string(), 120);

        // No context - use event ports directly
        let event_ports = vec![53, 80, 443];

        let result = engine.compute_port_intersection(&event_ports, None, AttackVector::UdpFlood);
        assert_eq!(result, event_ports);
    }

    #[test]
    fn policy_port_scope_preserves_constraints_and_intentional_wildcards() {
        for vector in [
            AttackVector::UdpFlood,
            AttackVector::SynFlood,
            AttackVector::AckFlood,
        ] {
            let mut playbooks = test_playbooks();
            playbooks.playbooks[0].match_criteria.vector = vector;
            let engine = PolicyEngine::new(playbooks, "test".into(), 120);
            for ip in ["203.0.113.10", "2001:db8::10"] {
                for (event_ports, service_ports, expected) in [
                    (vec![80, 443], vec![53, 123], None),
                    (vec![53, 80], vec![53, 123], Some(vec![53])),
                    (vec![53, 123], vec![], Some(vec![53, 123])),
                    (vec![], vec![53, 123], Some(vec![53, 123])),
                    (vec![], vec![], Some(vec![])),
                ] {
                    let context = make_context("customer", service_ports.clone(), service_ports);
                    let event = make_event(ip, vector.as_str(), &event_ports);
                    let result = engine.evaluate(&event, Some(&context));
                    match expected {
                        Some(ports) => assert_eq!(result.unwrap().match_criteria.dst_ports, ports),
                        None => assert!(matches!(
                            result,
                            Err(PrefixdError::GuardrailViolation(
                                GuardrailError::NoAllowedPorts
                            ))
                        )),
                    }
                }
                for ports in [vec![53, 123], vec![]] {
                    let event = make_event(ip, vector.as_str(), &ports);
                    assert_eq!(
                        engine
                            .evaluate(&event, None)
                            .unwrap()
                            .match_criteria
                            .dst_ports,
                        ports
                    );
                }
            }
        }
    }

    #[test]
    fn policy_preserves_other_vectors_port_selection() {
        for vector in [AttackVector::IcmpFlood, AttackVector::Unknown] {
            let mut playbooks = test_playbooks();
            playbooks.playbooks[0].match_criteria.vector = vector;
            let engine = PolicyEngine::new(playbooks, "test".into(), 120);
            let context = make_context("customer", vec![53], vec![53]);
            let event = make_event("203.0.113.10", vector.as_str(), &[80, 443]);
            assert_eq!(
                engine
                    .evaluate(&event, Some(&context))
                    .unwrap()
                    .match_criteria
                    .dst_ports,
                [80, 443]
            );
        }
    }

    // ==========================================================================
    // Protocol Detection Tests
    // ==========================================================================

    #[test]
    fn test_match_criteria_protocol() {
        let engine = PolicyEngine::new(test_playbooks(), "iad1".to_string(), 120);

        // UDP flood should have protocol 17
        let udp_event = make_event("10.0.0.1", "udp_flood", &[53]);
        let udp_intent = engine.evaluate(&udp_event, None).unwrap();
        assert_eq!(udp_intent.match_criteria.protocol, Some(17));

        // SYN flood should have protocol 6
        let syn_event = make_event("10.0.0.1", "syn_flood", &[443]);
        let syn_intent = engine.evaluate(&syn_event, None).unwrap();
        assert_eq!(syn_intent.match_criteria.protocol, Some(6));
    }

    // ==========================================================================
    // Default TTL Tests
    // ==========================================================================

    #[test]
    fn test_default_ttl_used_when_step_ttl_zero() {
        let playbooks = Playbooks {
            playbooks: vec![Playbook {
                name: "test".to_string(),
                match_criteria: PlaybookMatch {
                    vector: AttackVector::UdpFlood,
                    require_top_ports: false,
                },
                correlation: None,
                steps: vec![PlaybookStep {
                    action: PlaybookAction::Discard,
                    rate_bps: None,
                    ttl_seconds: 0, // Zero - should use default
                    require_confidence_at_least: None,
                    require_persistence_seconds: None,
                }],
            }],
        };

        let engine = PolicyEngine::new(playbooks, "iad1".to_string(), 300);
        let event = make_event("10.0.0.1", "udp_flood", &[53]);

        let intent = engine.evaluate(&event, None).unwrap();
        assert_eq!(intent.ttl_seconds, 300); // Uses default
    }

    #[test]
    fn test_step_ttl_overrides_default() {
        let engine = PolicyEngine::new(test_playbooks(), "iad1".to_string(), 300);
        let event = make_event("10.0.0.1", "udp_flood", &[53]);

        let intent = engine.evaluate(&event, None).unwrap();
        assert_eq!(intent.ttl_seconds, 120); // Uses step TTL, not default 300
    }
}
