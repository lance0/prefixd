use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Operator {
    pub operator_id: Uuid,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: OperatorRole,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<String>,
    pub last_login_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum OperatorRole {
    Viewer,
    Operator,
    Admin,
}

impl OperatorRole {
    /// Check if this role has at least the permissions of the required role
    pub fn has_permission(&self, required: &OperatorRole) -> bool {
        self >= required
    }
}

impl std::fmt::Display for OperatorRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OperatorRole::Viewer => write!(f, "viewer"),
            OperatorRole::Operator => write!(f, "operator"),
            OperatorRole::Admin => write!(f, "admin"),
        }
    }
}

impl std::str::FromStr for OperatorRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "viewer" => Ok(OperatorRole::Viewer),
            "operator" => Ok(OperatorRole::Operator),
            "admin" => Ok(OperatorRole::Admin),
            _ => Err(format!("invalid role: {}", s)),
        }
    }
}

/// Response type for API (excludes sensitive fields)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorResponse {
    pub operator_id: Uuid,
    pub username: String,
    pub role: OperatorRole,
    pub created_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

impl From<Operator> for OperatorResponse {
    fn from(op: Operator) -> Self {
        Self {
            operator_id: op.operator_id,
            username: op.username,
            role: op.role,
            created_at: op.created_at,
            last_login_at: op.last_login_at,
        }
    }
}

/// Longest username, and longest audit actor ID, that every Operator mutation
/// accepts.
pub const MAX_USERNAME_LEN: usize = 64;

/// Actor IDs prefixd records for principals that are not operator accounts.
/// No username may take one, in any case, so audit rows and `created_by`
/// cannot confuse an operator with the local CLI, `none` mode or an mTLS
/// client.
pub const RESERVED_USERNAMES: [&str; 3] = ["prefixdctl", "anonymous", "mtls-client"];

/// Usernames match `^[A-Za-z0-9_-]{1,64}$` and are not reserved, the rule the
/// API, `prefixdctl operators create` and the `operators` table CHECK share.
/// `token:` and `webhook:` actor IDs therefore cannot collide with a username
/// either.
pub fn is_valid_username(value: &str) -> bool {
    (1..=MAX_USERNAME_LEN).contains(&value.len())
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        && !RESERVED_USERNAMES
            .iter()
            .any(|reserved| value.eq_ignore_ascii_case(reserved))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames_match_the_shared_pattern() {
        for valid in ["alice_1", "ops-admin", "A", &"a".repeat(64)] {
            assert!(is_valid_username(valid), "{valid}");
        }
        for invalid in [
            "",
            "bad space",
            "no/slash",
            "token:name",
            "webhook:name",
            "caf\u{e9}",
            &"a".repeat(65),
            "prefixdctl",
            "anonymous",
            "mtls-client",
            "Anonymous",
            "MTLS-CLIENT",
        ] {
            assert!(!is_valid_username(invalid), "{invalid}");
        }
    }
}
