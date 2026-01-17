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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OperatorRole {
    Operator,
    Admin,
}

impl std::fmt::Display for OperatorRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OperatorRole::Operator => write!(f, "operator"),
            OperatorRole::Admin => write!(f, "admin"),
        }
    }
}

impl std::str::FromStr for OperatorRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
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
