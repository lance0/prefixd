use serde::Deserialize;
use std::fmt;

/// A credential that must be explicitly exposed for authentication or storage.
/// It deliberately does not implement `Serialize` or dereference to a string.
#[derive(Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_formatting_redacts_and_exposure_preserves_the_value() {
        let secret: SecretString = serde_json::from_str("\"seeded-secret\"").unwrap();
        assert_eq!(secret.expose_secret(), "seeded-secret");
        assert_eq!(format!("{secret:?}"), "[redacted]");
        assert_eq!(format!("{secret}"), "[redacted]");
    }
}
