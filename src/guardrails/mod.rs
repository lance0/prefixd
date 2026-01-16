use crate::config::{GuardrailsConfig, QuotasConfig};
use crate::db::Repository;
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
        repo: &Repository,
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

        // Note: min/max TTL should come from timers config, passed separately
        Ok(())
    }

    fn validate_prefix_length(&self, criteria: &MatchCriteria) -> Result<()> {
        let prefix_len = extract_prefix_length(&criteria.dst_prefix);

        if prefix_len < self.config.dst_prefix_minlen || prefix_len > self.config.dst_prefix_maxlen {
            return Err(PrefixdError::GuardrailViolation(
                GuardrailError::PrefixLengthViolation {
                    len: prefix_len,
                    min: self.config.dst_prefix_minlen,
                    max: self.config.dst_prefix_maxlen,
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

    async fn validate_quotas(&self, intent: &MitigationIntent, repo: &Repository) -> Result<()> {
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

fn extract_prefix_length(prefix: &str) -> u8 {
    prefix
        .split('/')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(32)
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

    #[test]
    fn test_prefix_length_extraction() {
        assert_eq!(extract_prefix_length("192.168.1.1/32"), 32);
        assert_eq!(extract_prefix_length("192.168.1.0/24"), 24);
        assert_eq!(extract_prefix_length("192.168.1.1"), 32);
    }

    #[test]
    fn test_validate_prefix_length() {
        let (config, quotas) = test_config();
        let guardrails = Guardrails::new(config, quotas);

        let valid = MatchCriteria {
            dst_prefix: "203.0.113.10/32".to_string(),
            protocol: Some(17),
            dst_ports: vec![53],
        };
        assert!(guardrails.validate_prefix_length(&valid).is_ok());

        let invalid = MatchCriteria {
            dst_prefix: "203.0.113.0/24".to_string(),
            protocol: Some(17),
            dst_ports: vec![53],
        };
        assert!(guardrails.validate_prefix_length(&invalid).is_err());
    }
}
