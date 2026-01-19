use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;
use uuid::Uuid;

/// Actor types for audit log entries
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    System,
    Detector,
    Operator,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub audit_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub schema_version: u32,
    pub actor_type: ActorType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    pub details: serde_json::Value,
}

impl AuditEntry {
    pub fn new(
        actor_type: ActorType,
        actor_id: Option<String>,
        action: &str,
        target_type: Option<&str>,
        target_id: Option<String>,
        details: serde_json::Value,
    ) -> Self {
        Self {
            audit_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            schema_version: 1,
            actor_type,
            actor_id,
            action: action.to_string(),
            target_type: target_type.map(String::from),
            target_id,
            details,
        }
    }

    /// Create entry for event ingestion
    pub fn event_ingested(source: &str, event_id: Uuid, victim_ip: &str, vector: &str) -> Self {
        Self::new(
            ActorType::Detector,
            Some(source.to_string()),
            "ingest",
            Some("event"),
            Some(event_id.to_string()),
            serde_json::json!({
                "victim_ip": victim_ip,
                "vector": vector
            }),
        )
    }

    /// Create entry for mitigation announcement
    pub fn mitigation_announced(mitigation_id: Uuid, victim_ip: &str, action_type: &str) -> Self {
        Self::new(
            ActorType::System,
            None,
            "announce",
            Some("mitigation"),
            Some(mitigation_id.to_string()),
            serde_json::json!({
                "victim_ip": victim_ip,
                "action_type": action_type
            }),
        )
    }

    /// Create entry for mitigation withdrawal
    pub fn mitigation_withdrawn(
        mitigation_id: Uuid,
        reason: &str,
        operator_id: Option<&str>,
    ) -> Self {
        let actor_type = if operator_id.is_some() {
            ActorType::Operator
        } else {
            ActorType::System
        };

        Self::new(
            actor_type,
            operator_id.map(String::from),
            "withdraw",
            Some("mitigation"),
            Some(mitigation_id.to_string()),
            serde_json::json!({ "reason": reason }),
        )
    }

    /// Create entry for mitigation escalation
    pub fn mitigation_escalated(mitigation_id: Uuid, from_action: &str, to_action: &str) -> Self {
        Self::new(
            ActorType::System,
            None,
            "escalate",
            Some("mitigation"),
            Some(mitigation_id.to_string()),
            serde_json::json!({
                "from_action": from_action,
                "to_action": to_action
            }),
        )
    }

    /// Create entry for guardrail rejection
    pub fn guardrail_rejected(event_id: Uuid, reason: &str) -> Self {
        Self::new(
            ActorType::System,
            None,
            "reject",
            Some("event"),
            Some(event_id.to_string()),
            serde_json::json!({ "reason": reason }),
        )
    }

    /// Create entry for safelist change
    pub fn safelist_added(prefix: &str, operator_id: &str, reason: Option<&str>) -> Self {
        Self::new(
            ActorType::Operator,
            Some(operator_id.to_string()),
            "safelist_add",
            Some("safelist"),
            Some(prefix.to_string()),
            serde_json::json!({ "reason": reason }),
        )
    }

    pub fn safelist_removed(prefix: &str, operator_id: Option<&str>) -> Self {
        Self::new(
            ActorType::Operator,
            operator_id.map(String::from),
            "safelist_remove",
            Some("safelist"),
            Some(prefix.to_string()),
            serde_json::json!({}),
        )
    }
}

/// Audit log writer (JSON Lines format)
pub struct AuditLogWriter {
    writer: Mutex<BufWriter<File>>,
}

impl AuditLogWriter {
    pub fn new<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;

        Ok(Self {
            writer: Mutex::new(BufWriter::new(file)),
        })
    }

    pub fn write(&self, entry: &AuditEntry) -> std::io::Result<()> {
        let json = serde_json::to_string(entry)?;
        let mut writer = self.writer.lock().unwrap();
        writeln!(writer, "{}", json)?;
        writer.flush()?;
        Ok(())
    }

    pub fn write_batch(&self, entries: &[AuditEntry]) -> std::io::Result<()> {
        let mut writer = self.writer.lock().unwrap();
        for entry in entries {
            let json = serde_json::to_string(entry)?;
            writeln!(writer, "{}", json)?;
        }
        writer.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_audit_entry_serialization() {
        let entry =
            AuditEntry::event_ingested("fastnetmon", Uuid::new_v4(), "203.0.113.10", "udp_flood");

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"action\":\"ingest\""));
        assert!(json.contains("\"actor_type\":\"detector\""));
    }

    #[test]
    fn test_audit_log_writer() {
        let temp_file = NamedTempFile::new().unwrap();
        let writer = AuditLogWriter::new(temp_file.path()).unwrap();

        let entry = AuditEntry::event_ingested("test", Uuid::new_v4(), "203.0.113.10", "udp_flood");

        writer.write(&entry).unwrap();

        let contents = std::fs::read_to_string(temp_file.path()).unwrap();
        assert!(contents.contains("ingest"));
        assert!(contents.ends_with('\n'));
    }
}
