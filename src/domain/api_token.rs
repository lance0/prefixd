use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::MAX_USERNAME_LEN;

/// What an API token may reach (ADR 034 §3). `ingest` is not a role: it
/// reaches only the ingest routes and requires a bound source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum TokenScope {
    Ingest,
    Operator,
    Admin,
}

impl TokenScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ingest => "ingest",
            Self::Operator => "operator",
            Self::Admin => "admin",
        }
    }
}

impl std::fmt::Display for TokenScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for TokenScope {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ingest" => Ok(Self::Ingest),
            "operator" => Ok(Self::Operator),
            "admin" => Ok(Self::Admin),
            _ => Err("scope must be ingest, operator or admin".into()),
        }
    }
}

/// The audit actor ID for a token, `token:<name>`.
pub const TOKEN_ACTOR_PREFIX: &str = "token:";

/// Longest token name: `token:<name>` must fit [`MAX_USERNAME_LEN`].
pub const MAX_TOKEN_NAME_LEN: usize = MAX_USERNAME_LEN - TOKEN_ACTOR_PREFIX.len();

/// Names match `^[a-z0-9][a-z0-9-]{0,57}$`, as the `api_tokens` CHECK does.
pub fn is_valid_token_name(name: &str) -> bool {
    (1..=MAX_TOKEN_NAME_LEN).contains(&name.len())
        && name
            .bytes()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

/// Sources match `^[a-z0-9][a-z0-9_-]{0,63}$`, as the `api_tokens` CHECK does.
pub fn is_valid_token_source(source: &str) -> bool {
    (1..=64).contains(&source.len())
        && source
            .bytes()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && source
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
}

/// A stored API token. The secret and its hash are never part of this record,
/// so nothing that serializes it can expose them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct ApiToken {
    pub token_id: Uuid,
    pub name: String,
    pub scope: TokenScope,
    /// The detector source an `ingest` token is bound to; null otherwise
    pub source: Option<String>,
    /// The POP whose controllers accept the token; null means every POP that
    /// shares the database
    pub pop: Option<String>,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<String>,
}

impl ApiToken {
    /// The audit actor ID, `token:<name>`.
    pub fn actor_id(&self) -> String {
        format!("{TOKEN_ACTOR_PREFIX}{}", self.name)
    }

    /// Whether the token has expired at `now`. Expiry is optional.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|expires| expires <= now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_sources_match_the_storage_patterns() {
        assert_eq!(MAX_TOKEN_NAME_LEN, 58);
        for valid in ["fnm-pop1", "a", "0", &"a".repeat(58)] {
            assert!(is_valid_token_name(valid), "{valid}");
        }
        for invalid in [
            "",
            "-lead",
            "Upper",
            "under_score",
            "dot.ted",
            "sp ace",
            &"a".repeat(59),
        ] {
            assert!(!is_valid_token_name(invalid), "{invalid}");
        }
        for valid in ["fastnetmon", "fastnetmon-hostgroup", "a_b", &"s".repeat(64)] {
            assert!(is_valid_token_source(valid), "{valid}");
        }
        for invalid in ["", "_lead", "Upper", "dot.ted", &"s".repeat(65)] {
            assert!(!is_valid_token_source(invalid), "{invalid}");
        }
    }

    #[test]
    fn the_longest_name_fits_the_actor_limit() {
        let mut token = ApiToken {
            token_id: Uuid::nil(),
            name: "a".repeat(MAX_TOKEN_NAME_LEN),
            scope: TokenScope::Operator,
            source: None,
            pop: None,
            created_at: Utc::now(),
            created_by: "admin".into(),
            expires_at: None,
            last_used_at: None,
            revoked_at: None,
            revoked_by: None,
        };
        assert_eq!(token.actor_id().len(), MAX_USERNAME_LEN);
        token.name.push('a');
        assert!(token.actor_id().len() > MAX_USERNAME_LEN);
    }
}
