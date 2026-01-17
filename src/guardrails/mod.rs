use std::net::IpAddr;

use crate::config::{GuardrailsConfig, QuotasConfig};
use crate::db::RepositoryTrait;
use crate::domain::{MatchCriteria, MitigationIntent};
use crate::error::{GuardrailError, PrefixdError, Result};

pub struct Guardrails {
    config: GuardrailsConfig,
    quotas: QuotasConfig,
}

impl Guardrails {
    pub fn new(config: GuardrailsConfig, quotas: QuotasConfig) -> Self {
        Self { config, quotas }
    }

    pub async fn validate(
        &self,
        intent: &MitigationIntent,
        repo: &dyn RepositoryTrait,
        is_safelisted: bool,
    ) -> Result<()> {
        // Check safelist
        if is_safelisted {
            let ip = &intent.match_criteria.dst_prefix;
            return Err(PrefixdError::GuardrailViolation(GuardrailError::Safelisted {
                ip: ip.clone(),
            }));
        }

        // Check TTL
        self.validate_ttl(intent.ttl_seconds)?;

        // Check prefix length
        self.validate_prefix_length(&intent.match_criteria)?;

        // Check port count
        self.validate_port_count(&intent.match_criteria)?;

        // Check quotas
        self.validate_quotas(intent, repo).await?;

        Ok(())
    }

    fn validate_ttl(&self, ttl: u32) -> Result<()> {
        if self.config.require_ttl && ttl == 0 {
            return Err(PrefixdError::GuardrailViolation(GuardrailError::TtlRequired));
        }
        // TODO: Add min/max TTL bounds enforcement (see ROADMAP v1.3)
        Ok(())
    }

    fn validate_prefix_length(&self, criteria: &MatchCriteria) -> Result<()> {
        // Use proper IP address parsing instead of contains(':') heuristic
        // This correctly handles IPv4-mapped IPv6 and invalid strings
        let is_v6 = criteria
            .dst_prefix
            .split('/')
            .next()
            .and_then(|ip| ip.parse::<IpAddr>().ok())
            .map(|addr| addr.is_ipv6())
            .unwrap_or(false);
        let prefix_len = extract_prefix_length(&criteria.dst_prefix, is_v6);

        // Use IPv6-specific limits if configured, otherwise default to /128
        let (min, max) = if is_v6 {
            (
                self.config.dst_prefix_minlen_v6.unwrap_or(128),
                self.config.dst_prefix_maxlen_v6.unwrap_or(128),
            )
        } else {
            (self.config.dst_prefix_minlen, self.config.dst_prefix_maxlen)
        };

        if prefix_len < min || prefix_len > max {
            return Err(PrefixdError::GuardrailViolation(
                GuardrailError::PrefixLengthViolation {
                    len: prefix_len,
                    min,
                    max,
                },
            ));
        }

        Ok(())
    }

    fn validate_port_count(&self, criteria: &MatchCriteria) -> Result<()> {
        if criteria.dst_ports.len() > self.config.max_ports {
            return Err(PrefixdError::GuardrailViolation(GuardrailError::TooManyPorts {
                count: criteria.dst_ports.len(),
                max: self.config.max_ports,
            }));
        }
        Ok(())
    }

    async fn validate_quotas(&self, intent: &MitigationIntent, repo: &dyn RepositoryTrait) -> Result<()> {
        // Customer quota
        if let Some(ref cid) = intent.customer_id {
            let count = repo.count_active_by_customer(cid).await?;
            if count >= self.quotas.max_active_per_customer {
                return Err(PrefixdError::GuardrailViolation(GuardrailError::QuotaExceeded {
                    quota_type: "customer".to_string(),
                    current: count,
                    max: self.quotas.max_active_per_customer,
                }));
            }
        }

        // POP quota
        let pop_count = repo.count_active_by_pop(&intent.pop).await?;
        if pop_count >= self.quotas.max_active_per_pop {
            return Err(PrefixdError::GuardrailViolation(GuardrailError::QuotaExceeded {
                quota_type: "pop".to_string(),
                current: pop_count,
                max: self.quotas.max_active_per_pop,
            }));
        }

        // Global quota
        let global_count = repo.count_active_global().await?;
        if global_count >= self.quotas.max_active_global {
            return Err(PrefixdError::GuardrailViolation(GuardrailError::QuotaExceeded {
                quota_type: "global".to_string(),
                current: global_count,
                max: self.quotas.max_active_global,
            }));
        }

        Ok(())
    }
}

fn extract_prefix_length(prefix: &str, is_v6: bool) -> u8 {
    let default = if is_v6 { 128 } else { 32 };
    prefix
        .split('/')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> (GuardrailsConfig, QuotasConfig) {
        (
            GuardrailsConfig {
                require_ttl: true,
                dst_prefix_minlen: 32,
                dst_prefix_maxlen: 32,
                dst_prefix_minlen_v6: None,
                dst_prefix_maxlen_v6: None,
                max_ports: 8,
                allow_src_prefix_match: false,
                allow_tcp_flags_match: false,
                allow_fragment_match: false,
                allow_packet_length_match: false,
            },
            QuotasConfig {
                max_active_per_customer: 5,
                max_active_per_pop: 200,
                max_active_global: 500,
                max_new_per_minute: 30,
                max_announcements_per_peer: 100,
            },
        )
    }

    fn relaxed_config() -> (GuardrailsConfig, QuotasConfig) {
        (
            GuardrailsConfig {
                require_ttl: false,
                dst_prefix_minlen: 24,
                dst_prefix_maxlen: 32,
                dst_prefix_minlen_v6: Some(64),
                dst_prefix_maxlen_v6: Some(128),
                max_ports: 16,
                allow_src_prefix_match: true,
                allow_tcp_flags_match: true,
                allow_fragment_match: true,
                allow_packet_length_match: true,
            },
            QuotasConfig {
                max_active_per_customer: 100,
                max_active_per_pop: 1000,
                max_active_global: 5000,
                max_new_per_minute: 100,
                max_announcements_per_peer: 500,
            },
        )
    }

    // ==========================================================================
    // Prefix Length Extraction Tests
    // ==========================================================================

    #[test]
    fn test_prefix_length_extraction_ipv4() {
        assert_eq!(extract_prefix_length("192.168.1.1/32", false), 32);
        assert_eq!(extract_prefix_length("192.168.1.0/24", false), 24);
        assert_eq!(extract_prefix_length("10.0.0.0/8", false), 8);
        assert_eq!(extract_prefix_length("0.0.0.0/0", false), 0);
    }

    #[test]
    fn test_prefix_length_extraction_ipv4_no_cidr() {
        // Should default to /32 for IPv4
        assert_eq!(extract_prefix_length("192.168.1.1", false), 32);
        assert_eq!(extract_prefix_length("10.0.0.1", false), 32);
    }

    #[test]
    fn test_prefix_length_extraction_ipv6() {
        assert_eq!(extract_prefix_length("2001:db8::1/128", true), 128);
        assert_eq!(extract_prefix_length("2001:db8::/64", true), 64);
        assert_eq!(extract_prefix_length("2001:db8::/48", true), 48);
        assert_eq!(extract_prefix_length("::/0", true), 0);
    }

    #[test]
    fn test_prefix_length_extraction_ipv6_no_cidr() {
        // Should default to /128 for IPv6
        assert_eq!(extract_prefix_length("2001:db8::1", true), 128);
        assert_eq!(extract_prefix_length("::1", true), 128);
    }

    // ==========================================================================
    // TTL Validation Tests
    // ==========================================================================

    #[test]
    fn test_validate_ttl_required_with_zero() {
        let (config, quotas) = test_config();
        let guardrails = Guardrails::new(config, quotas);

        let result = guardrails.validate_ttl(0);
        assert!(result.is_err());
        match result.unwrap_err() {
            PrefixdError::GuardrailViolation(GuardrailError::TtlRequired) => {}
            _ => panic!("Expected TtlRequired error"),
        }
    }

    #[test]
    fn test_validate_ttl_required_with_value() {
        let (config, quotas) = test_config();
        let guardrails = Guardrails::new(config, quotas);

        assert!(guardrails.validate_ttl(60).is_ok());
        assert!(guardrails.validate_ttl(3600).is_ok());
        assert!(guardrails.validate_ttl(1).is_ok());
    }

    #[test]
    fn test_validate_ttl_not_required() {
        let (config, quotas) = relaxed_config();
        let guardrails = Guardrails::new(config, quotas);

        // Zero TTL should be allowed when not required
        assert!(guardrails.validate_ttl(0).is_ok());
        assert!(guardrails.validate_ttl(60).is_ok());
    }

    // ==========================================================================
    // Prefix Length Validation Tests
    // ==========================================================================

    #[test]
    fn test_validate_prefix_length_ipv4_valid() {
        let (config, quotas) = test_config();
        let guardrails = Guardrails::new(config, quotas);

        let valid = MatchCriteria {
            dst_prefix: "203.0.113.10/32".to_string(),
            protocol: Some(17),
            dst_ports: vec![53],
        };
        assert!(guardrails.validate_prefix_length(&valid).is_ok());
    }

    #[test]
    fn test_validate_prefix_length_ipv4_too_short() {
        let (config, quotas) = test_config();
        let guardrails = Guardrails::new(config, quotas);

        let invalid = MatchCriteria {
            dst_prefix: "203.0.113.0/24".to_string(),
            protocol: Some(17),
            dst_ports: vec![53],
        };
        let result = guardrails.validate_prefix_length(&invalid);
        assert!(result.is_err());
        match result.unwrap_err() {
            PrefixdError::GuardrailViolation(GuardrailError::PrefixLengthViolation { len, min, max }) => {
                assert_eq!(len, 24);
                assert_eq!(min, 32);
                assert_eq!(max, 32);
            }
            _ => panic!("Expected PrefixLengthViolation error"),
        }
    }

    #[test]
    fn test_validate_prefix_length_ipv4_relaxed() {
        let (config, quotas) = relaxed_config();
        let guardrails = Guardrails::new(config, quotas);

        // /24 should be allowed with relaxed config (min=24, max=32)
        let valid_24 = MatchCriteria {
            dst_prefix: "203.0.113.0/24".to_string(),
            protocol: Some(17),
            dst_ports: vec![53],
        };
        assert!(guardrails.validate_prefix_length(&valid_24).is_ok());

        // /32 should still be valid
        let valid_32 = MatchCriteria {
            dst_prefix: "203.0.113.10/32".to_string(),
            protocol: Some(17),
            dst_ports: vec![53],
        };
        assert!(guardrails.validate_prefix_length(&valid_32).is_ok());

        // /16 should fail (below min)
        let invalid = MatchCriteria {
            dst_prefix: "203.0.0.0/16".to_string(),
            protocol: Some(17),
            dst_ports: vec![53],
        };
        assert!(guardrails.validate_prefix_length(&invalid).is_err());
    }

    #[test]
    fn test_validate_prefix_length_ipv6_default() {
        let (config, quotas) = test_config();
        let guardrails = Guardrails::new(config, quotas);

        // Default IPv6 is /128 only
        let valid = MatchCriteria {
            dst_prefix: "2001:db8::1/128".to_string(),
            protocol: Some(17),
            dst_ports: vec![53],
        };
        assert!(guardrails.validate_prefix_length(&valid).is_ok());

        let invalid = MatchCriteria {
            dst_prefix: "2001:db8::/64".to_string(),
            protocol: Some(17),
            dst_ports: vec![53],
        };
        assert!(guardrails.validate_prefix_length(&invalid).is_err());
    }

    #[test]
    fn test_validate_prefix_length_ipv6_relaxed() {
        let (config, quotas) = relaxed_config();
        let guardrails = Guardrails::new(config, quotas);

        // /64 should be allowed with relaxed config
        let valid_64 = MatchCriteria {
            dst_prefix: "2001:db8::/64".to_string(),
            protocol: Some(17),
            dst_ports: vec![53],
        };
        assert!(guardrails.validate_prefix_length(&valid_64).is_ok());

        // /128 should still be valid
        let valid_128 = MatchCriteria {
            dst_prefix: "2001:db8::1/128".to_string(),
            protocol: Some(17),
            dst_ports: vec![53],
        };
        assert!(guardrails.validate_prefix_length(&valid_128).is_ok());

        // /48 should fail (below min of 64)
        let invalid = MatchCriteria {
            dst_prefix: "2001:db8::/48".to_string(),
            protocol: Some(17),
            dst_ports: vec![53],
        };
        assert!(guardrails.validate_prefix_length(&invalid).is_err());
    }

    // ==========================================================================
    // Port Count Validation Tests
    // ==========================================================================

    #[test]
    fn test_validate_port_count_within_limit() {
        let (config, quotas) = test_config();
        let guardrails = Guardrails::new(config, quotas);

        let valid = MatchCriteria {
            dst_prefix: "203.0.113.10/32".to_string(),
            protocol: Some(17),
            dst_ports: vec![53, 80, 443, 8080],
        };
        assert!(guardrails.validate_port_count(&valid).is_ok());
    }

    #[test]
    fn test_validate_port_count_at_limit() {
        let (config, quotas) = test_config();
        let guardrails = Guardrails::new(config, quotas);

        let valid = MatchCriteria {
            dst_prefix: "203.0.113.10/32".to_string(),
            protocol: Some(17),
            dst_ports: vec![1, 2, 3, 4, 5, 6, 7, 8], // exactly 8
        };
        assert!(guardrails.validate_port_count(&valid).is_ok());
    }

    #[test]
    fn test_validate_port_count_exceeds_limit() {
        let (config, quotas) = test_config();
        let guardrails = Guardrails::new(config, quotas);

        let invalid = MatchCriteria {
            dst_prefix: "203.0.113.10/32".to_string(),
            protocol: Some(17),
            dst_ports: vec![1, 2, 3, 4, 5, 6, 7, 8, 9], // 9 ports
        };
        let result = guardrails.validate_port_count(&invalid);
        assert!(result.is_err());
        match result.unwrap_err() {
            PrefixdError::GuardrailViolation(GuardrailError::TooManyPorts { count, max }) => {
                assert_eq!(count, 9);
                assert_eq!(max, 8);
            }
            _ => panic!("Expected TooManyPorts error"),
        }
    }

    #[test]
    fn test_validate_port_count_empty() {
        let (config, quotas) = test_config();
        let guardrails = Guardrails::new(config, quotas);

        let valid = MatchCriteria {
            dst_prefix: "203.0.113.10/32".to_string(),
            protocol: Some(17),
            dst_ports: vec![],
        };
        assert!(guardrails.validate_port_count(&valid).is_ok());
    }

    #[test]
    fn test_validate_port_count_relaxed_limit() {
        let (config, quotas) = relaxed_config();
        let guardrails = Guardrails::new(config, quotas);

        let valid = MatchCriteria {
            dst_prefix: "203.0.113.10/32".to_string(),
            protocol: Some(17),
            dst_ports: (1..=16).collect(), // 16 ports
        };
        assert!(guardrails.validate_port_count(&valid).is_ok());

        let invalid = MatchCriteria {
            dst_prefix: "203.0.113.10/32".to_string(),
            protocol: Some(17),
            dst_ports: (1..=17).collect(), // 17 ports
        };
        assert!(guardrails.validate_port_count(&invalid).is_err());
    }

    // ==========================================================================
    // IPv6 Detection Tests
    // ==========================================================================

    #[test]
    fn test_ipv6_detection() {
        // These should be detected as IPv6
        assert!("2001:db8::1/128".contains(':'));
        assert!("::1".contains(':'));
        assert!("fe80::1%eth0".contains(':'));

        // These should not be detected as IPv6
        assert!(!"192.168.1.1/32".contains(':'));
        assert!(!"10.0.0.1".contains(':'));
    }
}
