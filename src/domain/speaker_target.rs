use uuid::Uuid;

use crate::config::{BgpConfig, BgpMode};
use crate::error::{PrefixdError, Result};

/// Configuration identity of a speaker, not proof of remote exclusivity.
/// Credentials, TLS files and controller operation mode are deliberately absent.
#[derive(Clone, PartialEq, Eq)]
pub struct SpeakerTarget {
    pub(crate) backend: &'static str,
    pub(crate) endpoint: String,
    pub(crate) namespace: &'static str,
}

// Keep connection coordinates out of accidental diagnostics and API errors.
impl std::fmt::Debug for SpeakerTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpeakerTarget")
            .field("backend", &self.backend)
            .finish_non_exhaustive()
    }
}

impl SpeakerTarget {
    pub fn from_config(config: &BgpConfig) -> Result<Self> {
        let (backend, endpoint) = match config.mode {
            BgpMode::Sidecar | BgpMode::Gobgp => ("gobgp", config.gobgp_grpc.as_str()),
            BgpMode::Rustbgpd => (
                "rustbgpd",
                config
                    .rustbgpd
                    .as_ref()
                    .ok_or_else(|| {
                        PrefixdError::Config("rustbgpd speaker configuration is required".into())
                    })?
                    .endpoint
                    .as_str(),
            ),
            BgpMode::Mock => {
                return Ok(Self {
                    backend: "mock",
                    endpoint: "in-process".into(),
                    namespace: "GLOBAL",
                });
            }
        };
        if backend == "rustbgpd" {
            let path = config
                .rustbgpd
                .as_ref()
                .expect("configuration checked above")
                .unix_socket_path()
                .map_err(|_| PrefixdError::Config("invalid rustbgpd Unix endpoint".into()))?;
            if let Some(path) = path {
                return Ok(Self {
                    backend,
                    endpoint: format!("unix://{}", path.display()),
                    namespace: "GLOBAL",
                });
            }
        }
        let invalid = || {
            PrefixdError::Config("invalid speaker endpoint: use a credential-free HTTP(S) address without userinfo, path prefix, query or fragment".into())
        };
        // Reject even empty userinfo/query/fragment and URL-parser whitespace repair.
        if endpoint.is_empty()
            || endpoint.contains(['@', '?', '#'])
            || endpoint.chars().any(char::is_whitespace)
        {
            return Err(invalid());
        }
        let address = if endpoint.contains("://") {
            endpoint.to_owned()
        } else {
            format!("http://{endpoint}")
        };
        let url = reqwest::Url::parse(&address).map_err(|_| invalid())?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || url.path() != "/"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid());
        }
        Ok(Self {
            backend,
            endpoint: url.to_string(),
            namespace: "GLOBAL",
        })
    }

    pub fn backend(&self) -> &'static str {
        self.backend
    }

    /// Normalized, credential-free endpoint for repository identity storage.
    /// Connection coordinates must stay out of public API responses and diagnostics.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Routing namespace included in the persistent target identity.
    pub fn namespace(&self) -> &'static str {
        self.namespace
    }
}

/// Startup consistency evidence issued by a trusted repository implementation.
/// This is not an authorization token or an interprocess lease.
#[derive(Debug, Clone)]
pub struct VerifiedSpeakerBinding {
    pop: String,
    target_id: Uuid,
    target: SpeakerTarget,
}

impl VerifiedSpeakerBinding {
    /// Issue a binding after repository registration has committed successfully.
    ///
    /// The trusted repository must first persist or validate the POP's exclusive
    /// target assignment and complete any required legacy adoption atomically.
    /// This constructor performs no persistence or ownership verification itself;
    /// callers must not use it to bypass registration.
    pub fn new(pop: String, target_id: Uuid, target: SpeakerTarget) -> Self {
        Self {
            pop,
            target_id,
            target,
        }
    }

    pub fn pop(&self) -> &str {
        &self.pop
    }
    pub fn target_id(&self) -> Uuid {
        self.target_id
    }

    /// Stable controller owner for this POP and verified target (ADR 027).
    pub fn owner(&self) -> String {
        controller_owner(&self.pop, self.target_id)
    }

    pub fn validate(&self, pop: &str, target: &SpeakerTarget, backend: &str) -> Result<()> {
        if self.pop != pop || self.target != *target || self.target.backend != backend {
            return Err(binding_mismatch());
        }
        Ok(())
    }

    pub fn validate_backend(&self, backend: &str) -> Result<()> {
        if self.target.backend != backend {
            return Err(binding_mismatch());
        }
        Ok(())
    }

    pub fn validate_request(&self, pop: &str, target_id: Option<Uuid>) -> Result<()> {
        if self.pop != pop || target_id != Some(self.target_id) {
            return Err(binding_mismatch());
        }
        Ok(())
    }
}

/// `prefixd.` + sanitized POP prefix + `.` + 16 hex of SHA-256(POP, NUL, target UUID).
/// Always 1 to 64 bytes of `[A-Za-z0-9._-]`; the hash keeps POPs with equal prefixes apart.
pub fn controller_owner(pop: &str, target_id: Uuid) -> String {
    use sha2::{Digest, Sha256};
    const MAX_OWNER_BYTES: usize = 64;
    let digest = Sha256::new()
        .chain_update(pop.as_bytes())
        .chain_update([0])
        .chain_update(target_id.hyphenated().to_string().as_bytes())
        .finalize();
    let hash = &hex::encode(digest)[..16];
    // Every kept character is one ASCII byte, so a character budget is a byte budget.
    let budget = MAX_OWNER_BYTES - "prefixd.".len() - ".".len() - hash.len();
    let prefix: String = pop
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .take(budget)
        .collect();
    format!("prefixd.{prefix}.{hash}")
}

pub(crate) fn binding_mismatch() -> PrefixdError {
    PrefixdError::Conflict("speaker target ownership is missing or mismatched".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(endpoint: &str) -> BgpConfig {
        BgpConfig {
            mode: BgpMode::Sidecar,
            gobgp_grpc: endpoint.into(),
            rustbgpd: None,
            local_asn: 65000,
            router_id: "192.0.2.1".into(),
            neighbors: vec![],
        }
    }

    #[test]
    fn aliases_and_credentials_do_not_change_target_identity() {
        let original = SpeakerTarget::from_config(&config("Speaker.EXAMPLE:50051")).unwrap();
        let mut alias = config("http://speaker.example:50051/");
        alias.mode = BgpMode::Gobgp;
        alias.local_asn = 65001;
        assert_eq!(original, SpeakerTarget::from_config(&alias).unwrap());
        assert_eq!(
            original,
            SpeakerTarget::from_config(&config("HTTP://Speaker.EXAMPLE:50051/")).unwrap()
        );
        assert_eq!(
            SpeakerTarget::from_config(&config("http://speaker.example:80")).unwrap(),
            SpeakerTarget::from_config(&config("speaker.example")).unwrap()
        );
        assert_eq!(
            SpeakerTarget::from_config(&config("[0:0:0:0:0:0:0:1]:50051")).unwrap(),
            SpeakerTarget::from_config(&config("http://[::1]:50051")).unwrap()
        );
        alias.mode = BgpMode::Rustbgpd;
        alias.rustbgpd = Some(crate::config::RustBgpdConfig {
            endpoint: "https://speaker.example:50051".into(),
            bearer_token_env: "ORIGINAL_TOKEN".into(),
            ca_cert_path: Some("/original.pem".into()),
            ..Default::default()
        });
        let before = SpeakerTarget::from_config(&alias).unwrap();
        alias.rustbgpd.as_mut().unwrap().bearer_token_env = "ROTATED_TOKEN".into();
        alias.rustbgpd.as_mut().unwrap().ca_cert_path = Some("/rotated.pem".into());
        assert_eq!(before, SpeakerTarget::from_config(&alias).unwrap());
        assert_ne!(original, before);
        assert!(!format!("{before:?}").contains("speaker.example"));
    }

    #[test]
    fn unix_target_survives_credential_rotation_and_normalizes_paths() {
        let mut settings = config("unused");
        settings.mode = BgpMode::Rustbgpd;
        settings.rustbgpd = Some(crate::config::RustBgpdConfig {
            endpoint: "unix:///run/prefixd/./grpc.sock".into(),
            ..Default::default()
        });
        let original = SpeakerTarget::from_config(&settings).unwrap();
        assert_eq!(original.endpoint(), "unix:///run/prefixd/grpc.sock");
        let secure = settings.rustbgpd.as_mut().unwrap();
        secure.endpoint = "unix:///run/prefixd/grpc.sock".into();
        secure.bearer_token_env = "ROTATED".into();
        assert_eq!(original, SpeakerTarget::from_config(&settings).unwrap());
        for endpoint in [
            "unix://host/socket",
            "unix:///run/../secret",
            "unix:///run/socket?secret",
            "unix:///run/%73ocket",
            "unix:///",
        ] {
            settings.rustbgpd.as_mut().unwrap().endpoint = endpoint.into();
            let error = SpeakerTarget::from_config(&settings)
                .unwrap_err()
                .to_string();
            assert!(!error.contains("secret"));
        }
    }

    #[test]
    fn controller_owner_derivation_is_pinned_sanitized_and_bounded() {
        let target = Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
        assert_eq!(
            controller_owner("fra1", target),
            "prefixd.fra1.6bec5166e567c666"
        );
        // Each disallowed character, multibyte included, becomes one '-'; the hash
        // still covers the original POP bytes.
        assert_eq!(
            controller_owner("Frankfurt DC #1/\u{e9}\u{e9}", target),
            "prefixd.Frankfurt-DC--1---.65565e0a0021abfc"
        );
        let long = controller_owner(&"x".repeat(100), target);
        assert_eq!(long, format!("prefixd.{}.adb02dd5cde4b473", "x".repeat(39)));
        assert_eq!(long.len(), 64);
        // Truncation alone cannot merge two POPs.
        assert_ne!(
            long,
            controller_owner(&format!("{}y", "x".repeat(99)), target)
        );
        assert_ne!(
            controller_owner("fra1", target),
            controller_owner("fra1", Uuid::nil())
        );
        for pop in ["", "fra1", "a.b", "\u{1F600}", &"\u{e9}".repeat(80)] {
            let owner = controller_owner(pop, target);
            assert!((1..=64).contains(&owner.len()), "{owner}");
            assert!(
                owner
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
                "{owner}"
            );
        }
    }

    #[test]
    fn endpoint_secrets_and_invalid_addresses_are_rejected_without_echoing_them() {
        for endpoint in [
            "http://secret@host:50051",
            "http://@host:50051",
            "http://host?secret",
            "http://host#secret",
            "http://host?",
            "http://host#",
            "http://host/ secret",
            "http://host/secret",
            "https://host/%73ecret",
            "unix:///secret",
            "",
        ] {
            let error = SpeakerTarget::from_config(&config(endpoint))
                .unwrap_err()
                .to_string();
            assert!(!error.contains("secret"));
            assert!(!error.contains(endpoint) || endpoint.is_empty());
        }
    }
}
