use std::net::IpAddr;

use crate::config::{
    AllowedPorts, AmplificationConfig, IpContext, Playbook, PlaybookStep, Playbooks, SrcPortsSpec,
};

use crate::domain::{
    ActionParams, ActionType, AttackEvent, AttackVector, FlowSpecAction, MatchCriteria,
    MitigationIntent, canonical_ports,
};
use crate::error::{GuardrailError, PrefixdError, Result};

/// Policy output for one event: one intent per rule, admitted per rule (ADR 028).
#[derive(Debug)]
pub struct PolicyDecision {
    /// The vector the mitigations record: `udp_flood` when an amplification
    /// event fell back.
    pub vector: AttackVector,
    pub intents: Vec<MitigationIntent>,
}

pub struct PolicyEngine {
    playbooks: Playbooks,
    pop: String,
    default_ttl: u32,
    reflector_ports: Vec<u16>,
    max_ports: usize,
}

impl PolicyEngine {
    pub fn new(playbooks: Playbooks, pop: String, default_ttl: u32) -> Self {
        Self {
            playbooks,
            pop,
            default_ttl,
            reflector_ports: AmplificationConfig::default().library_ports(),
            max_ports: crate::config::default_max_ports(),
        }
    }

    /// The reflector-port library `from_event` rules intersect with, and the
    /// per-rule source-port cap (`guardrails.max_ports`) they are split by.
    pub fn with_amplification(mut self, reflector_ports: Vec<u16>, max_ports: usize) -> Self {
        self.reflector_ports = reflector_ports;
        self.max_ports = max_ports;
        self
    }

    pub fn evaluate(
        &self,
        event: &AttackEvent,
        context: Option<&IpContext>,
    ) -> Result<PolicyDecision> {
        let victim_ip: IpAddr = event
            .victim_ip
            .parse()
            .map_err(|_| PrefixdError::InvalidIpAddress(event.victim_ip.clone()))?;
        let vector = event.attack_vector();
        let why = match self.evaluate_as(event, context, victim_ip, vector) {
            Ok(Some(intents)) => return Ok(PolicyDecision { vector, intents }),
            Ok(None) => "no reflector source ports",
            Err(PrefixdError::NoPlaybookFound(_)) if vector == AttackVector::UdpAmplification => {
                "no udp_amplification playbook"
            }
            Err(error) => return Err(error),
        };
        // An amplification event is never less mitigated than a UDP flood (ADR 028).
        let fallback = AttackVector::UdpFlood;
        let mut intents = self
            .evaluate_as(event, context, victim_ip, fallback)?
            .ok_or_else(|| PrefixdError::NoPlaybookFound(fallback.to_string()))?;
        for intent in &mut intents {
            intent
                .reason
                .push_str(&format!(" [udp_amplification fallback: {why}]"));
        }
        Ok(PolicyDecision {
            vector: fallback,
            intents,
        })
    }

    /// `None` when a `from_event` rule has no library ports to match.
    fn evaluate_as(
        &self,
        event: &AttackEvent,
        context: Option<&IpContext>,
        victim_ip: IpAddr,
        vector: AttackVector,
    ) -> Result<Option<Vec<MitigationIntent>>> {
        let prefix_len = if victim_ip.is_ipv4() { 32 } else { 128 };
        let dst_prefix = format!("{victim_ip}/{prefix_len}");
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
        let service = context
            .and_then(|c| c.service_name.as_deref())
            .unwrap_or("unknown service");

        if !step.rules.is_empty() {
            return self.rule_intents(event, context, dst_prefix, vector, playbook, step, service);
        }
        let action = step.flowspec_action().ok_or_else(|| {
            PrefixdError::NoPlaybookFound(format!("{vector} (step has no action)"))
        })?;

        let reason = format!("{} to {} (playbook: {})", vector, service, playbook.name);
        // A blackhole matches only the host prefix: no protocol, ports or rate (ADR 027).
        if action.action_type == ActionType::Blackhole {
            let host = MatchCriteria {
                dst_prefix,
                ..Default::default()
            };
            return Ok(Some(vec![
                self.intent(event, context, host, action, step, reason)?,
            ]));
        }

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
            dst_prefix,
            protocol: vector.to_protocol_for(victim_ip),
            dst_ports,
            ..Default::default()
        };
        Ok(Some(vec![self.intent(
            event,
            context,
            match_criteria,
            action,
            step,
            reason,
        )?]))
    }

    /// One intent per rule of a `rules` step, in playbook order. A `from_event`
    /// rule yields one intent per chunk of at most `max_ports` sorted library
    /// ports, so a repeated port set maps to the same identities.
    #[allow(
        clippy::too_many_arguments,
        reason = "private helper sharing evaluate_as's resolved inputs"
    )]
    fn rule_intents(
        &self,
        event: &AttackEvent,
        context: Option<&IpContext>,
        dst_prefix: String,
        vector: AttackVector,
        playbook: &Playbook,
        step: &PlaybookStep,
        service: &str,
    ) -> Result<Option<Vec<MitigationIntent>>> {
        let event_ports = self.library_ports(event);
        let mut intents = Vec::new();
        for (k, rule) in step.rules.iter().enumerate() {
            let port_sets = match &rule.match_criteria.src_ports {
                None => vec![Vec::new()],
                Some(SrcPortsSpec::Static(ports)) => vec![canonical_ports(ports)],
                Some(SrcPortsSpec::FromEvent(_)) if event_ports.is_empty() => return Ok(None),
                Some(SrcPortsSpec::FromEvent(_)) => event_ports
                    .chunks(self.max_ports.max(1))
                    .map(<[u16]>::to_vec)
                    .collect(),
            };
            for ports in port_sets {
                let reason = format!(
                    "{} to {} (playbook: {}, rule {})",
                    vector, service, playbook.name, k
                );
                intents.push(self.intent(
                    event,
                    context,
                    rule.match_for(dst_prefix.clone(), ports),
                    rule.flowspec_action(),
                    step,
                    reason,
                )?);
            }
        }
        Ok(Some(intents))
    }

    /// The event's source ports in the reflector-port library, sorted and
    /// deduplicated. Ports outside it are dropped: the library is the operator's
    /// statement of which source ports are safe to match.
    fn library_ports(&self, event: &AttackEvent) -> Vec<u16> {
        let (kept, dropped): (Vec<u16>, Vec<u16>) = event
            .top_src_ports()
            .into_iter()
            .partition(|port| self.reflector_ports.contains(port));
        if !dropped.is_empty() {
            tracing::info!(event_id = %event.event_id, dropped = ?canonical_ports(&dropped),
                "source ports outside the reflector-port library dropped");
        }
        canonical_ports(&kept)
    }

    fn intent(
        &self,
        event: &AttackEvent,
        context: Option<&IpContext>,
        match_criteria: MatchCriteria,
        action: FlowSpecAction,
        step: &PlaybookStep,
        reason: String,
    ) -> Result<MitigationIntent> {
        if action.action_type != ActionType::Blackhole {
            action.traffic_rate_bytes_per_second().map_err(|error| {
                PrefixdError::GuardrailViolation(GuardrailError::InvalidAction(error))
            })?;
        }
        let ttl = if step.ttl_seconds > 0 {
            step.ttl_seconds
        } else {
            self.default_ttl
        };
        Ok(MitigationIntent {
            event_id: event.event_id,
            customer_id: context.map(|c| c.customer_id.clone()),
            service_id: context.and_then(|c| c.service_id.clone()),
            pop: self.pop.clone(),
            match_criteria,
            action_type: action.action_type,
            action_params: ActionParams {
                rate_bps: action.rate_bps,
                ..Default::default()
            },
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
            AttackVector::UdpFlood | AttackVector::UdpAmplification => &allowed.udp,
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
            top_src_ports_json: None,
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
                        action: Some(PlaybookAction::Police),
                        rate_bps: Some(5_000_000),
                        ttl_seconds: 120,
                        require_confidence_at_least: None,
                        require_persistence_seconds: None,
                        rules: Vec::new(),
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
                        action: Some(PlaybookAction::Discard),
                        rate_bps: None,
                        ttl_seconds: 60,
                        require_confidence_at_least: None,
                        require_persistence_seconds: None,
                        rules: Vec::new(),
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
                let intent = engine.evaluate(&event, None).unwrap().intents.remove(0);
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

    #[test]
    fn blackhole_step_builds_a_bare_host_intent() {
        let mut playbooks = test_playbooks();
        playbooks.playbooks[0].steps[0] = PlaybookStep {
            action: Some(PlaybookAction::Blackhole),
            rate_bps: None,
            ttl_seconds: 1800,
            rules: vec![],
            require_confidence_at_least: None,
            require_persistence_seconds: None,
        };
        let engine = PolicyEngine::new(playbooks, "iad1".into(), 120);
        // Detector ports outside the allowed set would refuse a FlowSpec step.
        let context = make_context("cust_123", vec![123], vec![]);
        let event = make_event("2001:db8::10", "udp_flood", &[53]);
        let decision = engine.evaluate(&event, Some(&context)).unwrap();
        assert_eq!(decision.intents.len(), 1);
        let intent = &decision.intents[0];
        assert_eq!(intent.action_type, ActionType::Blackhole);
        let criteria = &intent.match_criteria;
        assert_eq!(criteria.dst_prefix, "2001:db8::10/128");
        assert!(criteria.protocol.is_none() && criteria.dst_ports.is_empty());
        assert!(criteria.src_ports.is_empty() && criteria.fragment.is_none());
        assert_eq!(intent.action_params.rate_bps, None);
        assert_eq!(intent.ttl_seconds, 1800);
    }

    // ==========================================================================
    // Basic Evaluation Tests
    // ==========================================================================

    #[test]
    fn test_evaluate_udp_flood_police() {
        let engine = PolicyEngine::new(test_playbooks(), "iad1".to_string(), 120);
        let event = make_event("203.0.113.10", "udp_flood", &[53]);

        let intent = engine.evaluate(&event, None).unwrap().intents.remove(0);

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

        let intent = engine.evaluate(&event, None).unwrap().intents.remove(0);

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

        let intent = engine
            .evaluate(&event, Some(&context))
            .unwrap()
            .intents
            .remove(0);

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
                        Some(ports) => {
                            assert_eq!(result.unwrap().intents[0].match_criteria.dst_ports, ports)
                        }
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
                        engine.evaluate(&event, None).unwrap().intents[0]
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
                engine.evaluate(&event, Some(&context)).unwrap().intents[0]
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
        let udp_intent = engine.evaluate(&udp_event, None).unwrap().intents.remove(0);
        assert_eq!(udp_intent.match_criteria.protocol, Some(17));

        // SYN flood should have protocol 6
        let syn_event = make_event("10.0.0.1", "syn_flood", &[443]);
        let syn_intent = engine.evaluate(&syn_event, None).unwrap().intents.remove(0);
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
                    action: Some(PlaybookAction::Discard),
                    rate_bps: None,
                    ttl_seconds: 0, // Zero - should use default
                    require_confidence_at_least: None,
                    require_persistence_seconds: None,
                    rules: Vec::new(),
                }],
            }],
        };

        let engine = PolicyEngine::new(playbooks, "iad1".to_string(), 300);
        let event = make_event("10.0.0.1", "udp_flood", &[53]);

        let intent = engine.evaluate(&event, None).unwrap().intents.remove(0);
        assert_eq!(intent.ttl_seconds, 300); // Uses default
    }

    #[test]
    fn test_step_ttl_overrides_default() {
        let engine = PolicyEngine::new(test_playbooks(), "iad1".to_string(), 300);
        let event = make_event("10.0.0.1", "udp_flood", &[53]);

        let intent = engine.evaluate(&event, None).unwrap().intents.remove(0);
        assert_eq!(intent.ttl_seconds, 120); // Uses step TTL, not default 300
    }

    #[test]
    fn rules_steps_chunk_by_max_ports_and_keep_static_lists_whole() {
        let playbooks: Playbooks = crate::config::parse_yaml(
            "playbooks:\n  - name: amp\n    match: {vector: udp_amplification}\n    steps:\n      - ttl_seconds: 0\n        rules:\n          - match: {src_ports: from_event}\n            action: discard\n          - match: {src_ports: [11211, 11211], packet_length: {min: 1000, max: 65535}}\n            action: discard\n",
        )
        .unwrap();
        let engine = PolicyEngine::new(playbooks, "iad1".into(), 90)
            .with_amplification(vec![17, 19, 53, 123, 389], 2);
        let mut event = make_event("2001:db8::10", "udp_amplification", &[80]);
        event.top_src_ports_json = Some("[389, 9, 123, 17, 53, 19, 53]".into());
        let decision = engine.evaluate(&event, None).unwrap();
        assert_eq!(decision.vector, AttackVector::UdpAmplification);
        let ports: Vec<_> = decision
            .intents
            .iter()
            .map(|i| i.match_criteria.src_ports.clone())
            .collect();
        assert_eq!(ports, [vec![17, 19], vec![53, 123], vec![389], vec![11211]]);
        for (k, intent) in decision.intents.iter().enumerate() {
            // Reflection rules never match the spoofed destination ports.
            assert!(intent.match_criteria.dst_ports.is_empty());
            assert_eq!(intent.match_criteria.dst_prefix, "2001:db8::10/128");
            assert_eq!(intent.match_criteria.protocol, Some(17));
            assert_eq!(intent.ttl_seconds, 90);
            let rule = if k < 3 { 0 } else { 1 };
            assert!(
                intent
                    .reason
                    .ends_with(&format!("(playbook: amp, rule {rule})"))
            );
        }
        assert!(decision.intents[3].match_criteria.packet_length.is_some());
    }
}
