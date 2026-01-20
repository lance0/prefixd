use async_trait::async_trait;
use chrono::Utc;
use std::sync::Mutex;
use uuid::Uuid;

use super::{GlobalStats, PopInfo, PopStats, RepositoryTrait, SafelistEntry};
use crate::domain::{AttackEvent, Mitigation, MitigationStatus, Operator, OperatorRole};
use crate::error::Result;
use crate::observability::AuditEntry;

pub struct MockRepository {
    events: Mutex<Vec<AttackEvent>>,
    mitigations: Mutex<Vec<Mitigation>>,
    safelist: Mutex<Vec<SafelistEntry>>,
    audit: Mutex<Vec<AuditEntry>>,
    operators: Mutex<Vec<Operator>>,
}

impl MockRepository {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            mitigations: Mutex::new(Vec::new()),
            safelist: Mutex::new(Vec::new()),
            audit: Mutex::new(Vec::new()),
            operators: Mutex::new(Vec::new()),
        }
    }
}

impl Default for MockRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RepositoryTrait for MockRepository {
    async fn insert_event(&self, event: &AttackEvent) -> Result<()> {
        self.events.lock().unwrap().push(event.clone());
        Ok(())
    }

    async fn find_ban_event_by_external_id(
        &self,
        source: &str,
        external_id: &str,
    ) -> Result<Option<AttackEvent>> {
        let events = self.events.lock().unwrap();
        // Find the most recent ban event with matching source and external_id
        Ok(events
            .iter()
            .rev() // Most recent first
            .find(|e| {
                e.source == source
                    && e.external_event_id.as_deref() == Some(external_id)
                    && e.action == "ban"
            })
            .cloned())
    }

    async fn list_events(&self, limit: u32, offset: u32) -> Result<Vec<AttackEvent>> {
        let events = self.events.lock().unwrap();
        Ok(events
            .iter()
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect())
    }

    async fn insert_audit(&self, entry: &AuditEntry) -> Result<()> {
        self.audit.lock().unwrap().push(entry.clone());
        Ok(())
    }

    async fn list_audit(&self, limit: u32, offset: u32) -> Result<Vec<AuditEntry>> {
        let audit = self.audit.lock().unwrap();
        Ok(audit
            .iter()
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect())
    }

    async fn insert_mitigation(&self, m: &Mitigation) -> Result<()> {
        self.mitigations.lock().unwrap().push(m.clone());
        Ok(())
    }

    async fn update_mitigation(&self, m: &Mitigation) -> Result<()> {
        let mut mitigations = self.mitigations.lock().unwrap();
        if let Some(existing) = mitigations
            .iter_mut()
            .find(|x| x.mitigation_id == m.mitigation_id)
        {
            *existing = m.clone();
        }
        Ok(())
    }

    async fn get_mitigation(&self, id: Uuid) -> Result<Option<Mitigation>> {
        let mitigations = self.mitigations.lock().unwrap();
        Ok(mitigations.iter().find(|m| m.mitigation_id == id).cloned())
    }

    async fn find_active_by_scope(
        &self,
        scope_hash: &str,
        pop: &str,
    ) -> Result<Option<Mitigation>> {
        let mitigations = self.mitigations.lock().unwrap();
        Ok(mitigations
            .iter()
            .find(|m| {
                m.scope_hash == scope_hash
                    && m.pop == pop
                    && matches!(
                        m.status,
                        MitigationStatus::Pending
                            | MitigationStatus::Active
                            | MitigationStatus::Escalated
                    )
            })
            .cloned())
    }

    async fn find_active_by_victim(&self, victim_ip: &str) -> Result<Vec<Mitigation>> {
        let mitigations = self.mitigations.lock().unwrap();
        Ok(mitigations
            .iter()
            .filter(|m| {
                m.victim_ip == victim_ip
                    && matches!(
                        m.status,
                        MitigationStatus::Pending
                            | MitigationStatus::Active
                            | MitigationStatus::Escalated
                    )
            })
            .cloned()
            .collect())
    }

    async fn find_active_by_triggering_event(&self, event_id: Uuid) -> Result<Option<Mitigation>> {
        let mitigations = self.mitigations.lock().unwrap();
        Ok(mitigations
            .iter()
            .find(|m| {
                m.triggering_event_id == event_id
                    && matches!(
                        m.status,
                        MitigationStatus::Pending
                            | MitigationStatus::Active
                            | MitigationStatus::Escalated
                    )
            })
            .cloned())
    }

    async fn list_mitigations(
        &self,
        status_filter: Option<&[MitigationStatus]>,
        customer_id: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Mitigation>> {
        let mitigations = self.mitigations.lock().unwrap();
        Ok(mitigations
            .iter()
            .filter(|m| {
                let status_ok = status_filter
                    .map(|statuses| statuses.contains(&m.status))
                    .unwrap_or(true);
                let customer_ok = customer_id
                    .map(|cid| m.customer_id.as_deref() == Some(cid))
                    .unwrap_or(true);
                status_ok && customer_ok
            })
            .skip(offset as usize)
            .take(limit as usize)
            .cloned()
            .collect())
    }

    async fn count_active_by_customer(&self, customer_id: &str) -> Result<u32> {
        let mitigations = self.mitigations.lock().unwrap();
        Ok(mitigations
            .iter()
            .filter(|m| {
                m.customer_id.as_deref() == Some(customer_id)
                    && matches!(
                        m.status,
                        MitigationStatus::Pending
                            | MitigationStatus::Active
                            | MitigationStatus::Escalated
                    )
            })
            .count() as u32)
    }

    async fn count_active_by_pop(&self, pop: &str) -> Result<u32> {
        let mitigations = self.mitigations.lock().unwrap();
        Ok(mitigations
            .iter()
            .filter(|m| {
                m.pop == pop
                    && matches!(
                        m.status,
                        MitigationStatus::Pending
                            | MitigationStatus::Active
                            | MitigationStatus::Escalated
                    )
            })
            .count() as u32)
    }

    async fn count_active_global(&self) -> Result<u32> {
        let mitigations = self.mitigations.lock().unwrap();
        Ok(mitigations
            .iter()
            .filter(|m| {
                matches!(
                    m.status,
                    MitigationStatus::Pending
                        | MitigationStatus::Active
                        | MitigationStatus::Escalated
                )
            })
            .count() as u32)
    }

    async fn find_expired_mitigations(&self) -> Result<Vec<Mitigation>> {
        let now = Utc::now();
        let mitigations = self.mitigations.lock().unwrap();
        Ok(mitigations
            .iter()
            .filter(|m| {
                matches!(
                    m.status,
                    MitigationStatus::Active | MitigationStatus::Escalated
                ) && m.expires_at < now
            })
            .cloned()
            .collect())
    }

    async fn insert_safelist(
        &self,
        prefix: &str,
        added_by: &str,
        reason: Option<&str>,
    ) -> Result<()> {
        let mut safelist = self.safelist.lock().unwrap();
        safelist.retain(|e| e.prefix != prefix);
        safelist.push(SafelistEntry {
            prefix: prefix.to_string(),
            added_at: Utc::now(),
            added_by: added_by.to_string(),
            reason: reason.map(String::from),
            expires_at: None,
        });
        Ok(())
    }

    async fn remove_safelist(&self, prefix: &str) -> Result<bool> {
        let mut safelist = self.safelist.lock().unwrap();
        let len_before = safelist.len();
        safelist.retain(|e| e.prefix != prefix);
        Ok(safelist.len() < len_before)
    }

    async fn list_safelist(&self) -> Result<Vec<SafelistEntry>> {
        Ok(self.safelist.lock().unwrap().clone())
    }

    async fn is_safelisted(&self, ip: &str) -> Result<bool> {
        use ipnet::{Ipv4Net, Ipv6Net};
        use std::net::IpAddr;
        use std::str::FromStr;

        let entries = self.safelist.lock().unwrap();
        let ip_addr: IpAddr = match IpAddr::from_str(ip) {
            Ok(addr) => addr,
            Err(_) => return Ok(false),
        };

        for entry in entries.iter() {
            match ip_addr {
                IpAddr::V4(v4) => {
                    if let Ok(prefix) = Ipv4Net::from_str(&entry.prefix) {
                        if prefix.contains(&v4) {
                            return Ok(true);
                        }
                    }
                }
                IpAddr::V6(v6) => {
                    if let Ok(prefix) = Ipv6Net::from_str(&entry.prefix) {
                        if prefix.contains(&v6) {
                            return Ok(true);
                        }
                    }
                }
            }
            if entry.prefix == ip {
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn list_pops(&self) -> Result<Vec<PopInfo>> {
        let mitigations = self.mitigations.lock().unwrap();
        let mut pop_map = std::collections::HashMap::new();

        for m in mitigations.iter() {
            let entry = pop_map.entry(m.pop.clone()).or_insert((0u32, 0u32));
            entry.1 += 1;
            if matches!(m.status, MitigationStatus::Active) {
                entry.0 += 1;
            }
        }

        Ok(pop_map
            .into_iter()
            .map(|(pop, (active, total))| PopInfo {
                pop,
                active_mitigations: active,
                total_mitigations: total,
            })
            .collect())
    }

    async fn get_stats(&self) -> Result<GlobalStats> {
        let mitigations = self.mitigations.lock().unwrap();
        let events = self.events.lock().unwrap();

        let total_active = mitigations
            .iter()
            .filter(|m| matches!(m.status, MitigationStatus::Active))
            .count() as u32;

        let mut pop_map = std::collections::HashMap::new();
        for m in mitigations.iter() {
            let entry = pop_map.entry(m.pop.clone()).or_insert((0u32, 0u32));
            entry.1 += 1;
            if matches!(m.status, MitigationStatus::Active) {
                entry.0 += 1;
            }
        }

        let pops = pop_map
            .into_iter()
            .map(|(pop, (active, total))| PopStats { pop, active, total })
            .collect();

        Ok(GlobalStats {
            total_active,
            total_mitigations: mitigations.len() as u32,
            total_events: events.len() as u32,
            pops,
        })
    }

    async fn list_mitigations_all_pops(
        &self,
        status_filter: Option<&[MitigationStatus]>,
        customer_id: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Mitigation>> {
        self.list_mitigations(status_filter, customer_id, limit, offset)
            .await
    }

    // Operator methods
    async fn get_operator_by_username(&self, username: &str) -> Result<Option<Operator>> {
        let operators = self.operators.lock().unwrap();
        Ok(operators.iter().find(|o| o.username == username).cloned())
    }

    async fn get_operator_by_id(&self, id: Uuid) -> Result<Option<Operator>> {
        let operators = self.operators.lock().unwrap();
        Ok(operators.iter().find(|o| o.operator_id == id).cloned())
    }

    async fn create_operator(
        &self,
        username: &str,
        password_hash: &str,
        role: OperatorRole,
        created_by: Option<&str>,
    ) -> Result<Operator> {
        let op = Operator {
            operator_id: Uuid::new_v4(),
            username: username.to_string(),
            password_hash: password_hash.to_string(),
            role,
            created_at: Utc::now(),
            created_by: created_by.map(String::from),
            last_login_at: None,
        };
        self.operators.lock().unwrap().push(op.clone());
        Ok(op)
    }

    async fn update_operator_last_login(&self, id: Uuid) -> Result<()> {
        let mut operators = self.operators.lock().unwrap();
        if let Some(op) = operators.iter_mut().find(|o| o.operator_id == id) {
            op.last_login_at = Some(Utc::now());
        }
        Ok(())
    }

    async fn list_operators(&self) -> Result<Vec<Operator>> {
        Ok(self.operators.lock().unwrap().clone())
    }
}
