use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

use super::{
    GlobalStats, ListParams, NotificationPreferences, PopInfo, PopStats, RepositoryTrait,
    SafelistEntry, TimeseriesBucket,
};
use crate::correlation::engine::{
    CorroboratingSignal, EventDimensions, SignalGroup, SignalGroupEvent, SignalGroupFilter,
    SignalGroupStatus,
};
use crate::domain::{AttackEvent, Mitigation, MitigationStatus, Operator, OperatorRole};
use crate::error::Result;
use crate::observability::AuditEntry;

pub struct MockRepository {
    events: Mutex<Vec<AttackEvent>>,
    mitigations: Mutex<Vec<Mitigation>>,
    safelist: Mutex<Vec<SafelistEntry>>,
    audit: Mutex<Vec<AuditEntry>>,
    operators: Mutex<Vec<Operator>>,
    notification_prefs: Mutex<HashMap<Uuid, NotificationPreferences>>,
    signal_groups: Mutex<Vec<SignalGroup>>,
    signal_group_events: Mutex<Vec<MockGroupEventLink>>,
    corroborating_signals: Mutex<Vec<CorroboratingSignal>>,
}

/// Mock-only junction-table row:
/// (group_id, event_id, source_weight, is_corroborating,
///  denorm_source, denorm_confidence, denorm_ingested_at).
type MockGroupEventLink = (
    Uuid,
    Uuid,
    f32,
    bool,
    Option<String>,
    Option<f32>,
    Option<chrono::DateTime<chrono::Utc>>,
);

impl MockRepository {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            mitigations: Mutex::new(Vec::new()),
            safelist: Mutex::new(Vec::new()),
            audit: Mutex::new(Vec::new()),
            operators: Mutex::new(Vec::new()),
            notification_prefs: Mutex::new(HashMap::new()),
            signal_groups: Mutex::new(Vec::new()),
            signal_group_events: Mutex::new(Vec::new()),
            corroborating_signals: Mutex::new(Vec::new()),
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

    async fn list_events(&self, params: &ListParams) -> Result<Vec<AttackEvent>> {
        let events = self.events.lock().unwrap();
        Ok(events
            .iter()
            .rev()
            .filter(|e| params.cursor.is_none_or(|c| e.ingested_at < c))
            .filter(|e| params.start.is_none_or(|s| e.ingested_at >= s))
            .filter(|e| params.end.is_none_or(|end| e.ingested_at < end))
            .take(params.limit as usize)
            .cloned()
            .collect())
    }

    async fn insert_audit(&self, entry: &AuditEntry) -> Result<()> {
        self.audit.lock().unwrap().push(entry.clone());
        Ok(())
    }

    async fn list_audit(&self, params: &ListParams) -> Result<Vec<AuditEntry>> {
        let audit = self.audit.lock().unwrap();
        Ok(audit
            .iter()
            .rev()
            .filter(|e| params.cursor.is_none_or(|c| e.timestamp < c))
            .filter(|e| params.start.is_none_or(|s| e.timestamp >= s))
            .filter(|e| params.end.is_none_or(|end| e.timestamp < end))
            .take(params.limit as usize)
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
        victim_ip: Option<&str>,
        acknowledged: Option<bool>,
        params: &ListParams,
    ) -> Result<Vec<Mitigation>> {
        let mitigations = self.mitigations.lock().unwrap();
        Ok(mitigations
            .iter()
            .rev()
            .filter(|m| {
                let status_ok = status_filter
                    .map(|statuses| statuses.contains(&m.status))
                    .unwrap_or(true);
                let customer_ok = customer_id
                    .map(|cid| m.customer_id.as_deref() == Some(cid))
                    .unwrap_or(true);
                let ip_ok = victim_ip.map(|ip| m.victim_ip == ip).unwrap_or(true);
                let ack_ok = acknowledged.is_none_or(|ack| {
                    if ack {
                        m.acknowledged_at.is_some()
                    } else {
                        m.acknowledged_at.is_none()
                    }
                });
                let cursor_ok = params.cursor.is_none_or(|c| m.created_at < c);
                let start_ok = params.start.is_none_or(|s| m.created_at >= s);
                let end_ok = params.end.is_none_or(|e| m.created_at < e);
                status_ok && customer_ok && ip_ok && ack_ok && cursor_ok && start_ok && end_ok
            })
            .take(params.limit as usize)
            .cloned()
            .collect())
    }

    async fn acknowledge_mitigations(&self, ids: &[Uuid], operator_id: &str) -> Result<Vec<Uuid>> {
        let mut mitigations = self.mitigations.lock().unwrap();
        let now = Utc::now();
        let mut acknowledged = Vec::new();
        for m in mitigations.iter_mut() {
            if ids.contains(&m.mitigation_id)
                && m.acknowledged_at.is_none()
                && !matches!(m.status, MitigationStatus::Rejected)
            {
                m.acknowledged_at = Some(now);
                m.acknowledged_by = Some(operator_id.to_string());
                acknowledged.push(m.mitigation_id);
            }
        }
        Ok(acknowledged)
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
        victim_ip: Option<&str>,
        acknowledged: Option<bool>,
        params: &ListParams,
    ) -> Result<Vec<Mitigation>> {
        self.list_mitigations(status_filter, customer_id, victim_ip, acknowledged, params)
            .await
    }

    // Timeseries (mock returns empty)
    async fn timeseries_mitigations(
        &self,
        _range_hours: u32,
        _bucket_minutes: u32,
    ) -> Result<Vec<TimeseriesBucket>> {
        Ok(vec![])
    }

    async fn timeseries_events(
        &self,
        _range_hours: u32,
        _bucket_minutes: u32,
    ) -> Result<Vec<TimeseriesBucket>> {
        Ok(vec![])
    }

    // IP history
    async fn list_events_by_ip(&self, ip: &str, limit: u32) -> Result<Vec<AttackEvent>> {
        let events = self.events.lock().unwrap();
        Ok(events
            .iter()
            .filter(|e| e.victim_ip == ip)
            .take(limit as usize)
            .cloned()
            .collect())
    }

    async fn list_mitigations_by_ip(&self, ip: &str, limit: u32) -> Result<Vec<Mitigation>> {
        let mitigations = self.mitigations.lock().unwrap();
        Ok(mitigations
            .iter()
            .filter(|m| m.victim_ip == ip)
            .take(limit as usize)
            .cloned()
            .collect())
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

    async fn update_operator_password(&self, id: Uuid, password_hash: &str) -> Result<()> {
        let mut operators = self.operators.lock().unwrap();
        if let Some(op) = operators.iter_mut().find(|o| o.operator_id == id) {
            op.password_hash = password_hash.to_string();
        }
        Ok(())
    }

    async fn delete_operator(&self, id: Uuid) -> Result<bool> {
        let mut operators = self.operators.lock().unwrap();
        let len_before = operators.len();
        operators.retain(|o| o.operator_id != id);
        Ok(operators.len() < len_before)
    }

    async fn list_operators(&self) -> Result<Vec<Operator>> {
        Ok(self.operators.lock().unwrap().clone())
    }

    async fn get_notification_preferences(
        &self,
        operator_id: Uuid,
    ) -> Result<Option<NotificationPreferences>> {
        Ok(self
            .notification_prefs
            .lock()
            .unwrap()
            .get(&operator_id)
            .cloned())
    }

    async fn upsert_notification_preferences(
        &self,
        operator_id: Uuid,
        prefs: &NotificationPreferences,
    ) -> Result<()> {
        self.notification_prefs
            .lock()
            .unwrap()
            .insert(operator_id, prefs.clone());
        Ok(())
    }

    // ── Signal groups ──────────────────────────────────────────────────

    async fn insert_signal_group(&self, group: &SignalGroup) -> Result<SignalGroup> {
        let mut groups = self.signal_groups.lock().unwrap();
        // Check for existing open group (simulates ON CONFLICT behavior)
        if let Some(existing) = groups.iter().find(|g| {
            g.victim_ip == group.victim_ip
                && g.vector == group.vector
                && g.status == SignalGroupStatus::Open
                && g.window_expires_at > Utc::now()
        }) {
            return Ok(existing.clone());
        }
        groups.push(group.clone());
        Ok(group.clone())
    }

    async fn update_signal_group(&self, group: &SignalGroup) -> Result<()> {
        let mut groups = self.signal_groups.lock().unwrap();
        if let Some(existing) = groups.iter_mut().find(|g| g.group_id == group.group_id) {
            *existing = group.clone();
        }
        Ok(())
    }

    async fn get_signal_group(&self, group_id: Uuid) -> Result<Option<SignalGroup>> {
        let groups = self.signal_groups.lock().unwrap();
        Ok(groups.iter().find(|g| g.group_id == group_id).cloned())
    }

    async fn find_open_group(&self, victim_ip: &str, vector: &str) -> Result<Option<SignalGroup>> {
        let groups = self.signal_groups.lock().unwrap();
        Ok(groups
            .iter()
            .find(|g| {
                g.victim_ip == victim_ip
                    && g.vector == vector
                    && g.status == SignalGroupStatus::Open
                    && g.window_expires_at > Utc::now()
            })
            .cloned())
    }

    async fn add_event_to_group(
        &self,
        group_id: Uuid,
        event_id: Uuid,
        source_weight: f32,
    ) -> Result<bool> {
        let mut links = self.signal_group_events.lock().unwrap();
        if links
            .iter()
            .any(|(gid, eid, _, _, _, _, _)| *gid == group_id && *eid == event_id)
        {
            return Ok(false);
        }
        links.push((group_id, event_id, source_weight, false, None, None, None));
        Ok(true)
    }

    async fn list_signal_group_events(&self, group_id: Uuid) -> Result<Vec<SignalGroupEvent>> {
        let links = self.signal_group_events.lock().unwrap();
        let events = self.events.lock().unwrap();

        Ok(links
            .iter()
            .filter(|(gid, _, _, _, _, _, _)| *gid == group_id)
            .map(
                |(gid, eid, weight, is_corroborating, dsource, dconf, dts)| {
                    let event = events.iter().find(|e| e.event_id == *eid);
                    SignalGroupEvent {
                        group_id: *gid,
                        event_id: *eid,
                        source_weight: *weight,
                        is_corroborating: *is_corroborating,
                        source: event.map(|e| e.source.clone()).or_else(|| dsource.clone()),
                        confidence: event.and_then(|e| e.confidence).or(*dconf),
                        ingested_at: event.map(|e| e.ingested_at).or(*dts),
                    }
                },
            )
            .collect())
    }

    async fn list_signal_groups(
        &self,
        filter: &SignalGroupFilter,
        params: &ListParams,
    ) -> Result<Vec<SignalGroup>> {
        let groups = self.signal_groups.lock().unwrap();
        Ok(groups
            .iter()
            .rev()
            .filter(|g| filter.status.is_none_or(|s| g.status == s))
            .filter(|g| filter.vector.as_ref().is_none_or(|v| &g.vector == v))
            .filter(|g| filter.start.is_none_or(|s| g.created_at >= s))
            .filter(|g| filter.end.is_none_or(|e| g.created_at < e))
            .filter(|g| params.cursor.is_none_or(|c| g.created_at < c))
            .take(params.limit as usize)
            .cloned()
            .collect())
    }

    async fn count_open_groups(&self) -> Result<u32> {
        let groups = self.signal_groups.lock().unwrap();
        Ok(groups
            .iter()
            .filter(|g| g.status == SignalGroupStatus::Open)
            .count() as u32)
    }

    async fn find_expired_signal_groups(&self) -> Result<Vec<SignalGroup>> {
        let now = Utc::now();
        let groups = self.signal_groups.lock().unwrap();
        Ok(groups
            .iter()
            .filter(|g| g.status == SignalGroupStatus::Open && g.window_expires_at <= now)
            .cloned()
            .collect())
    }

    async fn find_open_groups_by_dimensions(
        &self,
        vector: &Option<String>,
        dims: &EventDimensions,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<SignalGroup>> {
        let groups = self.signal_groups.lock().unwrap();
        Ok(groups
            .iter()
            .filter(|g| g.status == SignalGroupStatus::Open && g.window_expires_at > now)
            .filter(|g| vector.as_ref().is_none_or(|v| &g.vector == v))
            .filter(|g| g.primary_dimensions.matches_probe(dims))
            .cloned()
            .collect())
    }

    async fn find_mitigation_id_by_signal_group(
        &self,
        signal_group_id: Uuid,
    ) -> Result<Option<Uuid>> {
        let mitigations = self.mitigations.lock().unwrap();
        Ok(mitigations
            .iter()
            .find(|m| m.signal_group_id == Some(signal_group_id))
            .map(|m| m.mitigation_id))
    }

    // Corroborating signals (ADR 021)

    async fn add_corroborator_event_to_group(
        &self,
        group_id: Uuid,
        signal: &CorroboratingSignal,
    ) -> Result<bool> {
        let mut links = self.signal_group_events.lock().unwrap();
        if links
            .iter()
            .any(|(gid, eid, _, _, _, _, _)| *gid == group_id && *eid == signal.signal_id)
        {
            return Ok(false);
        }
        links.push((
            group_id,
            signal.signal_id,
            signal.weight,
            true,
            Some(signal.source.clone()),
            signal.confidence,
            Some(signal.ingested_at),
        ));
        Ok(true)
    }

    async fn group_has_primary_event(&self, group_id: Uuid) -> Result<bool> {
        let links = self.signal_group_events.lock().unwrap();
        Ok(links
            .iter()
            .any(|(gid, _, _, is_corr, _, _, _)| *gid == group_id && !*is_corr))
    }

    async fn insert_corroborating_signal(&self, signal: &CorroboratingSignal) -> Result<()> {
        self.corroborating_signals
            .lock()
            .unwrap()
            .push(signal.clone());
        Ok(())
    }

    async fn find_matching_corroborators(
        &self,
        vector: &str,
        dims: &EventDimensions,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<CorroboratingSignal>> {
        let cache = self.corroborating_signals.lock().unwrap();
        Ok(cache
            .iter()
            .filter(|s| s.expires_at > now)
            .filter(|s| s.vector.as_deref().is_none_or(|v| v == vector))
            .filter(|s| {
                s.customer_id
                    .as_ref()
                    .is_some_and(|c| dims.customer_ids.contains(c))
                    || s.pop.as_ref().is_some_and(|p| dims.pops.contains(p))
                    || s.service_id
                        .as_ref()
                        .is_some_and(|sid| dims.service_ids.contains(sid))
                    || s.interface
                        .as_ref()
                        .is_some_and(|i| dims.interfaces.contains(i))
            })
            .cloned()
            .collect())
    }

    async fn mark_corroborator_attached(&self, signal_id: Uuid, group_id: Uuid) -> Result<()> {
        let mut cache = self.corroborating_signals.lock().unwrap();
        if let Some(s) = cache.iter_mut().find(|s| s.signal_id == signal_id)
            && !s.attached_group_ids.contains(&group_id)
        {
            s.attached_group_ids.push(group_id);
        }
        Ok(())
    }

    async fn delete_expired_corroborating_signals(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64> {
        let mut cache = self.corroborating_signals.lock().unwrap();
        let before = cache.len();
        cache.retain(|s| s.expires_at > now);
        Ok((before - cache.len()) as u64)
    }

    async fn count_cached_corroborators(&self, now: chrono::DateTime<chrono::Utc>) -> Result<u64> {
        let cache = self.corroborating_signals.lock().unwrap();
        Ok(cache
            .iter()
            .filter(|s| s.expires_at > now && s.attached_group_ids.is_empty())
            .count() as u64)
    }

    async fn list_cached_corroborators(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        limit: i64,
    ) -> Result<Vec<CorroboratingSignal>> {
        let cache = self.corroborating_signals.lock().unwrap();
        Ok(cache
            .iter()
            .filter(|s| s.expires_at > now && s.attached_group_ids.is_empty())
            .take(limit.max(0) as usize)
            .cloned()
            .collect())
    }
}
