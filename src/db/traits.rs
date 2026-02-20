use async_trait::async_trait;
use uuid::Uuid;

use crate::domain::{AttackEvent, Mitigation, MitigationStatus, Operator, OperatorRole};
use crate::error::Result;
use crate::observability::AuditEntry;

use super::{GlobalStats, PopInfo, SafelistEntry, TimeseriesBucket};

#[async_trait]
pub trait RepositoryTrait: Send + Sync {
    // Events
    async fn insert_event(&self, event: &AttackEvent) -> Result<()>;
    /// Find the most recent ban event by external_event_id.
    /// Used for duplicate detection (ban) and correlation (unban).
    /// Note: Event IDs are hashed from IP|direction, so the same IP can have
    /// multiple ban/unban cycles over time. This returns only ban events,
    /// ordered by most recent first.
    async fn find_ban_event_by_external_id(
        &self,
        source: &str,
        external_id: &str,
    ) -> Result<Option<AttackEvent>>;
    async fn list_events(&self, limit: u32, offset: u32) -> Result<Vec<AttackEvent>>;

    // Audit Log
    async fn insert_audit(&self, entry: &AuditEntry) -> Result<()>;
    async fn list_audit(&self, limit: u32, offset: u32) -> Result<Vec<AuditEntry>>;

    // Mitigations
    async fn insert_mitigation(&self, m: &Mitigation) -> Result<()>;
    async fn update_mitigation(&self, m: &Mitigation) -> Result<()>;
    async fn get_mitigation(&self, id: Uuid) -> Result<Option<Mitigation>>;
    async fn find_active_by_scope(&self, scope_hash: &str, pop: &str)
    -> Result<Option<Mitigation>>;
    async fn find_active_by_victim(&self, victim_ip: &str) -> Result<Vec<Mitigation>>;
    async fn find_active_by_triggering_event(&self, event_id: Uuid) -> Result<Option<Mitigation>>;
    async fn list_mitigations(
        &self,
        status_filter: Option<&[MitigationStatus]>,
        customer_id: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Mitigation>>;
    async fn count_active_by_customer(&self, customer_id: &str) -> Result<u32>;
    async fn count_active_by_pop(&self, pop: &str) -> Result<u32>;
    async fn count_active_global(&self) -> Result<u32>;
    async fn find_expired_mitigations(&self) -> Result<Vec<Mitigation>>;

    // Safelist
    async fn insert_safelist(
        &self,
        prefix: &str,
        added_by: &str,
        reason: Option<&str>,
    ) -> Result<()>;
    async fn remove_safelist(&self, prefix: &str) -> Result<bool>;
    async fn list_safelist(&self) -> Result<Vec<SafelistEntry>>;
    async fn is_safelisted(&self, ip: &str) -> Result<bool>;

    // Multi-POP coordination
    async fn list_pops(&self) -> Result<Vec<PopInfo>>;
    async fn get_stats(&self) -> Result<GlobalStats>;
    async fn list_mitigations_all_pops(
        &self,
        status_filter: Option<&[MitigationStatus]>,
        customer_id: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Mitigation>>;

    // Timeseries
    async fn timeseries_mitigations(
        &self,
        range_hours: u32,
        bucket_minutes: u32,
    ) -> Result<Vec<TimeseriesBucket>>;
    async fn timeseries_events(
        &self,
        range_hours: u32,
        bucket_minutes: u32,
    ) -> Result<Vec<TimeseriesBucket>>;

    // IP history
    async fn list_events_by_ip(&self, ip: &str, limit: u32) -> Result<Vec<AttackEvent>>;
    async fn list_mitigations_by_ip(&self, ip: &str, limit: u32) -> Result<Vec<Mitigation>>;

    // Operators
    async fn get_operator_by_username(&self, username: &str) -> Result<Option<Operator>>;
    async fn get_operator_by_id(&self, id: Uuid) -> Result<Option<Operator>>;
    async fn create_operator(
        &self,
        username: &str,
        password_hash: &str,
        role: OperatorRole,
        created_by: Option<&str>,
    ) -> Result<Operator>;
    async fn update_operator_last_login(&self, id: Uuid) -> Result<()>;
    async fn update_operator_password(&self, id: Uuid, password_hash: &str) -> Result<()>;
    async fn delete_operator(&self, id: Uuid) -> Result<bool>;
    async fn list_operators(&self) -> Result<Vec<Operator>>;
}
