use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{
    AddOutcome, BlackholeInventory, BlackholeRoute, BlackholeSpeaker, ExportDisposition,
    ExportObserver, FlowSpecAnnouncer, FlowSpecMatchSupport, FlowSpecReader, FlowSpecWriter,
    InjectionLeases, LeaseGeneration, PeerExport, PeerObserver, PeerStatus, SessionState,
};
use crate::domain::FlowSpecRule;
use crate::error::{InjectionRefusalReason, PrefixdError, Result};

/// Daemon-side lease table (rustbgpd ADR-0141): one live generation per owner.
#[derive(Debug, Default)]
struct MockLeases {
    incarnation: u64,
    sequence: u64,
    live: std::collections::HashMap<String, LeaseGeneration>,
    confirmed: bool,
}

/// Mock announcer for testing
#[derive(Debug, Default)]
pub struct MockAnnouncer {
    rules: Arc<RwLock<Vec<FlowSpecRule>>>,
    blackholes: RwLock<Vec<BlackholeRoute>>,
    leases: std::sync::Mutex<MockLeases>,
    peers: Vec<PeerStatus>,
    /// Test seam: report no ADR 028 match support, like an adapter that has not opted in.
    no_match_support: bool,
    no_vpn_support: bool,
    /// Test seam: export reads for these prefixes return this instead; `Err`
    /// fails the read.
    export_overrides: std::sync::Mutex<ExportOverrides>,
    flowspec_export_overrides: std::sync::Mutex<ExportOverrides<String>>,
    /// Test seam: every export read stalls and never completes.
    pub stall_exports: std::sync::atomic::AtomicBool,
}

type ExportOverrides<K = ipnet::IpNet> =
    std::collections::HashMap<K, std::result::Result<Vec<PeerExport>, String>>;

impl MockAnnouncer {
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            blackholes: RwLock::default(),
            leases: Default::default(),
            peers: vec![PeerStatus {
                name: "mock-peer".to_string(),
                address: "127.0.0.1".to_string(),
                state: SessionState::Established,
            }],
            no_match_support: false,
            no_vpn_support: false,
            export_overrides: Default::default(),
            flowspec_export_overrides: Default::default(),
            stall_exports: Default::default(),
        }
    }

    pub fn with_peers(peers: Vec<PeerStatus>) -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            blackholes: RwLock::default(),
            leases: Default::default(),
            peers,
            no_match_support: false,
            no_vpn_support: false,
            export_overrides: Default::default(),
            flowspec_export_overrides: Default::default(),
            stall_exports: Default::default(),
        }
    }

    /// Reports no ADR 028 match support, so callers must refuse extended rules.
    pub fn without_match_support() -> Self {
        Self {
            no_match_support: true,
            ..Self::new()
        }
    }

    /// Reports a scope-unaware speaker without changing global behavior.
    pub fn without_vpn_support() -> Self {
        Self {
            no_vpn_support: true,
            ..Self::new()
        }
    }

    fn validate_flowspec_key(&self, nlri: &crate::domain::FlowSpecNlri) -> Result<()> {
        self.register_scope(nlri.scope.as_ref())?;
        if nlri.scope.is_some() {
            nlri.validate()
                .map_err(|error| PrefixdError::InvalidRequest(error.to_string()))?;
        }
        Ok(())
    }

    /// Export reads for `prefix` return `exports`, or fail with the message.
    pub fn set_exports(
        &self,
        prefix: ipnet::IpNet,
        exports: std::result::Result<Vec<PeerExport>, String>,
    ) {
        self.export_overrides
            .lock()
            .unwrap()
            .insert(prefix, exports);
    }

    /// Exact-key FlowSpec export result for failure and withholding controls.
    pub fn set_flowspec_exports(
        &self,
        nlri: &crate::domain::FlowSpecNlri,
        exports: std::result::Result<Vec<PeerExport>, String>,
    ) {
        self.flowspec_export_overrides
            .lock()
            .unwrap()
            .insert(nlri.compute_hash(), exports);
    }

    pub async fn announced_count(&self) -> usize {
        self.rules.read().await.len()
    }

    /// The owner's lease deadline passed: the daemon withdraws everything it added.
    pub async fn expire_lease(&self, owner: &str) {
        self.leases.lock().unwrap().live.remove(owner);
        self.blackholes.write().await.retain(|r| r.owner() != owner);
        self.rules.write().await.retain(|r| r.owner != owner);
    }

    /// Join the owner's live lease or start the next generation.
    fn join_lease(&self, owner: &str) -> LeaseGeneration {
        let mut leases = self.leases.lock().unwrap();
        let next = LeaseGeneration {
            incarnation: leases.incarnation,
            sequence: leases.sequence + 1,
        };
        let generation = *leases.live.entry(owner.into()).or_insert(next);
        leases.sequence = leases.sequence.max(generation.sequence);
        generation
    }

    /// A daemon restart loses every route, rule and lease; generations start over.
    pub async fn restart(&self) {
        {
            let mut leases = self.leases.lock().unwrap();
            leases.live.clear();
            leases.incarnation += 1;
        }
        self.blackholes.write().await.clear();
        self.rules.write().await.clear();
    }

    fn owner_mismatch(operation: &str, held_owner: Option<&str>) -> PrefixdError {
        PrefixdError::InjectionOwnerMismatch {
            reason: match held_owner {
                Some("") => InjectionRefusalReason::KeyUnowned,
                Some(_) => InjectionRefusalReason::OwnerMismatch,
                None => InjectionRefusalReason::Unspecified,
            },
            message: format!("mock refused {operation}; nothing changed"),
        }
    }
}

impl FlowSpecAnnouncer for MockAnnouncer {
    fn backend(&self) -> &'static str {
        "mock"
    }
    fn reader(&self) -> Option<&dyn FlowSpecReader> {
        Some(self)
    }
    fn peer_observer(&self) -> Option<&dyn PeerObserver> {
        Some(self)
    }
    fn blackhole(&self) -> Option<&dyn BlackholeSpeaker> {
        Some(self)
    }
    fn injection_leases(&self) -> Option<&dyn InjectionLeases> {
        Some(self)
    }
    fn export_observer(&self) -> Option<&dyn ExportObserver> {
        Some(self)
    }
    fn flowspec_export_observer(&self) -> Option<&dyn ExportObserver> {
        Some(self)
    }
    fn match_support(&self) -> FlowSpecMatchSupport {
        if self.no_match_support {
            FlowSpecMatchSupport::default()
        } else {
            FlowSpecMatchSupport::ALL
        }
    }
}

#[async_trait]
impl FlowSpecWriter for MockAnnouncer {
    fn register_scope(&self, scope: Option<&crate::domain::VpnFlowSpecIdentity>) -> Result<()> {
        if self.no_vpn_support {
            super::announcer::require_global_scope("mock", scope)
        } else {
            Ok(())
        }
    }

    async fn announce(&self, rule: &FlowSpecRule) -> Result<()> {
        self.validate_flowspec_key(&rule.nlri)?;
        super::announcer::validate_add_scope(rule)?;
        for action in &rule.actions {
            action
                .validate()
                .map_err(|error| PrefixdError::InvalidRequest(error.to_string()))?;
        }
        let mut rules = self.rules.write().await;
        let hash = rule.nlri_hash();
        if !rule.owner.is_empty()
            || rules
                .iter()
                .any(|r| r.nlri_hash() == hash && !r.owner.is_empty())
        {
            return Err(Self::owner_mismatch(
                "AddFlowSpec",
                rules
                    .iter()
                    .find(|r| r.nlri_hash() == hash)
                    .map(|r| r.owner.as_str()),
            ));
        }

        // Remove existing rule with same NLRI if present
        rules.retain(|r| r.nlri_hash() != hash);
        rules.push(rule.clone());

        tracing::debug!(nlri_hash = %hash, "mock: announced flowspec rule");
        Ok(())
    }
    async fn announce_leased(
        &self,
        rule: &FlowSpecRule,
        _lease_seconds: u32,
    ) -> Result<LeaseGeneration> {
        self.validate_flowspec_key(&rule.nlri)?;
        super::announcer::validate_add_scope(rule)?;
        for action in &rule.actions {
            action
                .validate()
                .map_err(|error| PrefixdError::InvalidRequest(error.to_string()))?;
        }
        let mut rules = self.rules.write().await;
        let hash = rule.nlri_hash();
        if rule.owner.is_empty()
            || rules
                .iter()
                .any(|r| r.nlri_hash() == hash && r.owner != rule.owner)
        {
            return Err(Self::owner_mismatch(
                "AddLeasedFlowSpec",
                rules
                    .iter()
                    .find(|r| r.nlri_hash() == hash)
                    .map(|r| r.owner.as_str()),
            ));
        }
        let generation = self.join_lease(&rule.owner);
        rules.retain(|r| r.nlri_hash() != hash);
        rules.push(rule.clone());
        Ok(generation)
    }
    async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()> {
        self.validate_flowspec_key(&rule.nlri)?;
        let mut rules = self.rules.write().await;
        let hash = rule.nlri_hash();
        if rules
            .iter()
            .any(|r| r.nlri_hash() == hash && r.owner != rule.owner)
        {
            return Err(Self::owner_mismatch(
                "DeleteFlowSpec",
                rules
                    .iter()
                    .find(|r| r.nlri_hash() == hash)
                    .map(|r| r.owner.as_str()),
            ));
        }
        let before = rules.len();
        rules.retain(|r| r.nlri_hash() != hash);

        if rules.len() < before {
            tracing::debug!(nlri_hash = %hash, "mock: withdrew flowspec rule");
        }
        Ok(())
    }
}
#[async_trait]
impl FlowSpecReader for MockAnnouncer {
    async fn list_active(&self) -> Result<Vec<FlowSpecRule>> {
        Ok(self.rules.read().await.clone())
    }
}
/// The daemon's upsert, reporting the outcome against the previous local route.
fn upsert_blackhole(routes: &mut Vec<BlackholeRoute>, route: &BlackholeRoute) -> AddOutcome {
    let outcome = match routes.iter().find(|r| r.prefix() == route.prefix()) {
        None => AddOutcome::Created,
        Some(old) if old == route => AddOutcome::Unchanged,
        Some(_) => AddOutcome::Replaced,
    };
    routes.retain(|r| r.prefix() != route.prefix());
    routes.push(route.clone());
    outcome
}

#[async_trait]
impl BlackholeSpeaker for MockAnnouncer {
    async fn announce_blackhole(&self, route: &BlackholeRoute) -> Result<AddOutcome> {
        let mut routes = self.blackholes.write().await;
        if !route.owner().is_empty()
            || routes
                .iter()
                .any(|r| r.prefix() == route.prefix() && !r.owner().is_empty())
        {
            return Err(Self::owner_mismatch(
                "AddPath",
                routes
                    .iter()
                    .find(|r| r.prefix() == route.prefix())
                    .map(|r| r.owner()),
            ));
        }
        Ok(upsert_blackhole(&mut routes, route))
    }
    async fn announce_leased_blackhole(
        &self,
        route: &BlackholeRoute,
        _lease_seconds: u32,
    ) -> Result<(LeaseGeneration, AddOutcome)> {
        let mut routes = self.blackholes.write().await;
        if route.owner().is_empty()
            || routes
                .iter()
                .any(|r| r.prefix() == route.prefix() && r.owner() != route.owner())
        {
            return Err(Self::owner_mismatch(
                "AddLeasedPath",
                routes
                    .iter()
                    .find(|r| r.prefix() == route.prefix())
                    .map(|r| r.owner()),
            ));
        }
        let generation = self.join_lease(route.owner());
        Ok((generation, upsert_blackhole(&mut routes, route)))
    }
    async fn withdraw_blackhole(&self, prefix: &ipnet::IpNet, owner: &str) -> Result<()> {
        super::require_host_route(prefix)?;
        let mut routes = self.blackholes.write().await;
        if routes
            .iter()
            .any(|r| r.prefix() == *prefix && r.owner() != owner)
        {
            return Err(Self::owner_mismatch(
                "DeletePath",
                routes
                    .iter()
                    .find(|r| r.prefix() == *prefix)
                    .map(|r| r.owner()),
            ));
        }
        routes.retain(|r| r.prefix() != *prefix);
        Ok(())
    }
    async fn list_blackholes(&self) -> Result<BlackholeInventory> {
        Ok(BlackholeInventory {
            routes: self.blackholes.read().await.clone(),
            ..Default::default()
        })
    }
}
#[async_trait]
impl InjectionLeases for MockAnnouncer {
    async fn incarnation(&self) -> Result<Option<u64>> {
        Ok(Some(self.leases.lock().unwrap().incarnation))
    }

    async fn live_lease(&self, owner: &str) -> Result<Option<Option<LeaseGeneration>>> {
        let mut leases = self.leases.lock().unwrap();
        leases.confirmed = true;
        Ok(Some(leases.live.get(owner).copied()))
    }
    async fn renew_lease(
        &self,
        owner: &str,
        generation: LeaseGeneration,
        _lease_seconds: u32,
    ) -> Result<bool> {
        Ok(self.leases.lock().unwrap().live.get(owner) == Some(&generation))
    }
    /// Like a daemon, confirmed only once probed.
    fn lease_confirmed(&self) -> bool {
        self.leases.lock().unwrap().confirmed
    }
}
/// Synthetic: a held route is committed to every Established mock peer.
#[async_trait]
impl ExportObserver for MockAnnouncer {
    async fn flowspec_exports(
        &self,
        nlri: &crate::domain::FlowSpecNlri,
    ) -> Result<Option<Vec<PeerExport>>> {
        if self.stall_exports.load(std::sync::atomic::Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        if let Some(exports) = self
            .flowspec_export_overrides
            .lock()
            .unwrap()
            .get(&nlri.compute_hash())
        {
            return exports.clone().map(Some).map_err(PrefixdError::Internal);
        }
        if !self
            .rules
            .read()
            .await
            .iter()
            .any(|rule| rule.nlri_hash() == nlri.compute_hash())
        {
            return Ok(None);
        }
        Ok(Some(
            self.peers
                .iter()
                .filter(|peer| !peer.address.starts_with("interface:"))
                .map(|peer| PeerExport {
                    peer_address: peer.address.clone(),
                    disposition: if peer.state.is_established() {
                        ExportDisposition::Committed
                    } else {
                        ExportDisposition::NotEstablished
                    },
                    reason: if peer.state.is_established() {
                        String::new()
                    } else {
                        "not_established".into()
                    },
                    explain_code: String::new(),
                    detail: String::new(),
                    advertised_path_id: 0,
                })
                .collect(),
        ))
    }

    async fn blackhole_exports(&self, prefix: &ipnet::IpNet) -> Result<Option<Vec<PeerExport>>> {
        if self.stall_exports.load(std::sync::atomic::Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        if let Some(exports) = self.export_overrides.lock().unwrap().get(prefix) {
            return exports.clone().map(Some).map_err(PrefixdError::Internal);
        }
        if !self
            .blackholes
            .read()
            .await
            .iter()
            .any(|route| route.prefix() == *prefix)
        {
            return Ok(None);
        }
        Ok(Some(
            self.peers
                .iter()
                .filter(|peer| !peer.address.starts_with("interface:"))
                .map(|peer| PeerExport {
                    peer_address: peer.address.clone(),
                    disposition: if peer.state.is_established() {
                        ExportDisposition::Committed
                    } else {
                        ExportDisposition::NotEstablished
                    },
                    reason: if peer.state.is_established() {
                        String::new()
                    } else {
                        "not_established".into()
                    },
                    explain_code: String::new(),
                    detail: String::new(),
                    advertised_path_id: 0,
                })
                .collect(),
        ))
    }
}
#[async_trait]
impl PeerObserver for MockAnnouncer {
    async fn session_status(&self) -> Result<Vec<PeerStatus>> {
        Ok(self.peers.clone())
    }
}

/// Test speaker with injectable blackhole faults; FlowSpec passes through.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct FaultyBlackholes {
    pub inner: MockAnnouncer,
    /// Every blackhole read fails, as an aborted or partial walk does.
    pub fail_reads: std::sync::atomic::AtomicBool,
    /// Every FlowSpec read fails.
    pub fail_flowspec_reads: std::sync::atomic::AtomicBool,
    /// Every add fails without changing the speaker.
    pub fail_adds: std::sync::atomic::AtomicBool,
    /// A route to insert immediately before an add, simulating a writer racing admission.
    pub before_add: std::sync::Mutex<Option<BlackholeRoute>>,
    /// 1: a delete is rejected before removal; 2: removed, then the reply is lost.
    pub withdraw_fault: std::sync::atomic::AtomicUsize,
    /// Well-formed local routes that are not prefixd-shaped.
    pub unrecognized: std::sync::Mutex<Vec<super::UnrecognizedRoute>>,
    /// Leased rows reported with no lease time left.
    pub expired: std::sync::Mutex<Vec<BlackholeRoute>>,
    pub adds: std::sync::atomic::AtomicUsize,
    pub deletes: std::sync::atomic::AtomicUsize,
    /// Leased adds, counted apart from `adds` (plain `AddPath`).
    pub leased_adds: std::sync::atomic::AtomicUsize,
    /// The owner every delete passed, in order.
    pub delete_owners: std::sync::Mutex<Vec<String>>,
    /// `lease_seconds` of every leased add and renewal, in order.
    pub lease_seconds: std::sync::Mutex<Vec<u32>>,
    /// Every renewal fails with a transport error.
    pub fail_renewals: std::sync::atomic::AtomicBool,
    /// A renewal stays in flight until the test releases it.
    pub block_renewals: std::sync::atomic::AtomicBool,
    pub renewal_entered: tokio::sync::Notify,
    pub release_renewal: tokio::sync::Notify,
    pub renewals: std::sync::atomic::AtomicUsize,
    /// Plain `AddFlowSpec` and leased FlowSpec adds, counted apart.
    pub flowspec_adds: std::sync::atomic::AtomicUsize,
    pub leased_flowspec_adds: std::sync::atomic::AtomicUsize,
    /// The owner every FlowSpec delete passed, in order.
    pub flowspec_delete_owners: std::sync::Mutex<Vec<String>>,
}

#[cfg(test)]
impl FaultyBlackholes {
    async fn inject_before_add(&self) {
        let route = self.before_add.lock().unwrap().take();
        if let Some(route) = route {
            let mut routes = self.inner.blackholes.write().await;
            upsert_blackhole(&mut routes, &route);
        }
    }

    pub async fn routes(&self) -> Vec<BlackholeRoute> {
        self.inner.list_blackholes().await.unwrap().routes
    }
}

#[cfg(test)]
impl FlowSpecAnnouncer for FaultyBlackholes {
    fn backend(&self) -> &'static str {
        "mock"
    }
    fn reader(&self) -> Option<&dyn FlowSpecReader> {
        Some(self)
    }
    fn blackhole(&self) -> Option<&dyn BlackholeSpeaker> {
        Some(self)
    }
    fn injection_leases(&self) -> Option<&dyn InjectionLeases> {
        Some(self)
    }
    fn export_observer(&self) -> Option<&dyn ExportObserver> {
        self.inner.export_observer()
    }
}

#[cfg(test)]
#[async_trait]
impl InjectionLeases for FaultyBlackholes {
    async fn incarnation(&self) -> Result<Option<u64>> {
        self.inner.incarnation().await
    }

    async fn live_lease(&self, owner: &str) -> Result<Option<Option<LeaseGeneration>>> {
        self.inner.live_lease(owner).await
    }
    async fn renew_lease(
        &self,
        owner: &str,
        generation: LeaseGeneration,
        lease_seconds: u32,
    ) -> Result<bool> {
        use std::sync::atomic::Ordering::SeqCst;
        self.renewals.fetch_add(1, SeqCst);
        if self.block_renewals.load(SeqCst) {
            self.renewal_entered.notify_one();
            self.release_renewal.notified().await;
            return Ok(true);
        }
        self.lease_seconds.lock().unwrap().push(lease_seconds);
        if self.fail_renewals.load(SeqCst) {
            return Err(PrefixdError::BgpAnnouncementFailed(
                "renewal transport failed".into(),
            ));
        }
        self.inner
            .renew_lease(owner, generation, lease_seconds)
            .await
    }
    fn lease_confirmed(&self) -> bool {
        self.inner.lease_confirmed()
    }
}

#[cfg(test)]
#[async_trait]
impl FlowSpecWriter for FaultyBlackholes {
    fn register_scope(&self, scope: Option<&crate::domain::VpnFlowSpecIdentity>) -> Result<()> {
        self.inner.register_scope(scope)
    }

    async fn announce(&self, rule: &FlowSpecRule) -> Result<()> {
        self.flowspec_adds
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.announce(rule).await
    }
    async fn announce_leased(
        &self,
        rule: &FlowSpecRule,
        lease_seconds: u32,
    ) -> Result<LeaseGeneration> {
        use std::sync::atomic::Ordering::SeqCst;
        self.leased_flowspec_adds.fetch_add(1, SeqCst);
        self.lease_seconds.lock().unwrap().push(lease_seconds);
        if self.fail_adds.load(SeqCst) {
            // As UNIMPLEMENTED from a rolled-back daemon: nothing is created.
            return Err(PrefixdError::BgpAnnouncementFailed(
                "AddLeasedFlowSpec RPC failed: Unimplemented".into(),
            ));
        }
        self.inner.announce_leased(rule, lease_seconds).await
    }
    async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()> {
        self.flowspec_delete_owners
            .lock()
            .unwrap()
            .push(rule.owner.clone());
        self.inner.withdraw(rule).await
    }
}

#[cfg(test)]
#[async_trait]
impl FlowSpecReader for FaultyBlackholes {
    async fn list_active(&self) -> Result<Vec<FlowSpecRule>> {
        if self
            .fail_flowspec_reads
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(crate::error::PrefixdError::BgpAnnouncementFailed(
                "FlowSpec read failed".into(),
            ));
        }
        self.inner.list_active().await
    }
}

#[cfg(test)]
#[async_trait]
impl BlackholeSpeaker for FaultyBlackholes {
    async fn announce_blackhole(&self, route: &BlackholeRoute) -> Result<AddOutcome> {
        use std::sync::atomic::Ordering::SeqCst;
        self.adds.fetch_add(1, SeqCst);
        if self.fail_adds.load(SeqCst) {
            return Err(crate::error::PrefixdError::BgpAnnouncementFailed(
                "add failed".into(),
            ));
        }
        self.inject_before_add().await;
        self.inner.announce_blackhole(route).await
    }
    async fn announce_leased_blackhole(
        &self,
        route: &BlackholeRoute,
        lease_seconds: u32,
    ) -> Result<(LeaseGeneration, AddOutcome)> {
        use std::sync::atomic::Ordering::SeqCst;
        self.leased_adds.fetch_add(1, SeqCst);
        self.lease_seconds.lock().unwrap().push(lease_seconds);
        if self.fail_adds.load(SeqCst) {
            // As UNIMPLEMENTED from a rolled-back daemon: nothing is created.
            return Err(crate::error::PrefixdError::BgpAnnouncementFailed(
                "AddLeasedPath RPC failed: Unimplemented".into(),
            ));
        }
        self.inject_before_add().await;
        self.inner
            .announce_leased_blackhole(route, lease_seconds)
            .await
    }
    async fn withdraw_blackhole(&self, prefix: &ipnet::IpNet, owner: &str) -> Result<()> {
        use std::sync::atomic::Ordering::SeqCst;
        self.deletes.fetch_add(1, SeqCst);
        self.delete_owners.lock().unwrap().push(owner.into());
        let fault = self.withdraw_fault.load(SeqCst);
        if fault == 2 {
            self.inner.withdraw_blackhole(prefix, owner).await?;
        }
        if fault != 0 {
            return Err(crate::error::PrefixdError::BgpWithdrawalFailed(
                "delete outcome unknown".into(),
            ));
        }
        self.inner.withdraw_blackhole(prefix, owner).await
    }
    async fn list_blackholes(&self) -> Result<BlackholeInventory> {
        if self.fail_reads.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(crate::error::PrefixdError::BgpAnnouncementFailed(
                "ABORTED: local intent changed during the read".into(),
            ));
        }
        let mut inventory = self.inner.list_blackholes().await?;
        inventory.unrecognized = self.unrecognized.lock().unwrap().clone();
        inventory.expired = self.expired.lock().unwrap().clone();
        Ok(inventory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{FlowSpecAction, FlowSpecNlri};

    #[tokio::test]
    async fn synthetic_historical_mark_cleanup_keeps_scope_owner_and_withdrawal_metadata() {
        use crate::db::{MockRepository, RepositoryTrait};
        use crate::domain::{
            ActionParams, ActionType, AttackVector, MatchCriteria, Mitigation, MitigationIntent,
            MitigationStatus, VpnFlowSpecFamily, VpnFlowSpecIdentity, VpnScopeSnapshot,
            execute_withdrawal, mitigation_rule, request_withdrawal,
        };
        for (family, destination, source) in [
            (VpnFlowSpecFamily::Ipv4, "192.0.2.1/32", "198.51.100.0/24"),
            (
                VpnFlowSpecFamily::Ipv6,
                "2001:db8::1/128",
                "2001:db8:bad::/64",
            ),
        ] {
            for source_only in [false, true] {
                let repo = MockRepository::new();
                let speaker = MockAnnouncer::new();
                let global = FlowSpecRule::new(
                    FlowSpecNlri {
                        dst_prefix: destination.into(),
                        src_prefix: Some(source.into()),
                        protocol: Some(17),
                        dst_ports: vec![53],
                        ..Default::default()
                    },
                    FlowSpecAction::discard(),
                );
                speaker.announce(&global).await.unwrap();
                let mut siblings = Vec::new();
                for rd in ["44407:40", "44407:41"] {
                    let mut sibling = global.clone();
                    sibling.nlri.scope = Some(VpnFlowSpecIdentity::new(family, rd).unwrap());
                    sibling.route_targets = vec!["44407:777".into()];
                    if source_only {
                        sibling.nlri.dst_prefix.clear();
                    }
                    speaker.announce(&sibling).await.unwrap();
                    siblings.push(sibling);
                }
                let key = if source_only { &siblings[0] } else { &global };
                let scope = key.nlri.scope.clone().map(|identity| {
                    VpnScopeSnapshot::new("TRANSIT", identity, &key.route_targets).unwrap()
                });
                let params = ActionParams {
                    dscp: Some(46),
                    ..Default::default()
                };
                let mut historical = Mitigation::from_intent(
                    MitigationIntent {
                        event_id: uuid::Uuid::new_v4(),
                        customer_id: Some("fixture".into()),
                        service_id: None,
                        pop: "fixture".into(),
                        match_criteria: MatchCriteria {
                            scope,
                            dst_prefix: key.nlri.dst_prefix.clone(),
                            src_prefix: key.nlri.src_prefix.clone(),
                            protocol: key.nlri.protocol,
                            dst_ports: key.nlri.dst_ports.clone(),
                            ..Default::default()
                        },
                        action_type: ActionType::Mark,
                        action_params: params,
                        ttl_seconds: 60,
                        reason: "synthetic historical mark fixture".into(),
                    },
                    destination.into(),
                    AttackVector::Unknown,
                );
                historical.activate();
                historical.origin_mode = Some(crate::config::OperationMode::Enforced);
                let payload = mitigation_rule(&historical).unwrap();
                assert!(
                    speaker
                        .announce(&payload)
                        .await
                        .unwrap_err()
                        .to_string()
                        .contains("requires a VPN destination")
                );
                let mut leased = payload.clone();
                leased.owner = "historical-owner".into();
                assert!(
                    speaker
                        .announce_leased(&leased, 60)
                        .await
                        .unwrap_err()
                        .to_string()
                        .contains("requires a VPN destination")
                );
                historical.action_params.dscp = Some(64);
                historical.action_params.rate_bps = Some(8);
                let payload = mitigation_rule(&historical).unwrap();
                // Current admission cannot create this shape; seed it only as a cleanup invariant.
                speaker
                    .rules
                    .write()
                    .await
                    .iter_mut()
                    .find(|held| held.nlri_hash() == key.nlri_hash())
                    .unwrap()
                    .actions = payload.actions.clone();
                let mut wrong_owner = payload.clone();
                wrong_owner.owner = "foreign-owner".into();
                assert!(speaker.withdraw(&wrong_owner).await.is_err());
                assert_eq!(speaker.list_active().await.unwrap().len(), 3);
                repo.insert_mitigation(&historical).await.unwrap();
                let request = request_withdrawal(
                    &repo,
                    &historical,
                    false,
                    "operator",
                    "original-actor",
                    "original-reason".into(),
                    true,
                    None,
                )
                .await
                .unwrap();
                let retried = request_withdrawal(
                    &repo,
                    &historical,
                    false,
                    "operator",
                    "retry-actor",
                    "retry-reason".into(),
                    true,
                    None,
                )
                .await
                .unwrap();
                assert_eq!(retried.operation_id, request.operation_id);
                assert_eq!(retried.actor, "original-actor");
                assert_eq!(retried.reason, "original-reason");
                assert_eq!(retried.rule_json, request.rule_json);
                let finished = execute_withdrawal(&repo, &speaker, false, &retried, None)
                    .await
                    .unwrap();
                assert_eq!(finished.status, MitigationStatus::Withdrawn);
                let held = speaker.list_active().await.unwrap();
                assert_eq!(held.len(), 2);
                assert!(held.iter().all(|held| held.nlri_hash() != key.nlri_hash()));
                for sibling in std::iter::once(&global)
                    .chain(&siblings)
                    .filter(|rule| rule.nlri_hash() != key.nlri_hash())
                {
                    assert!(
                        held.iter()
                            .any(|held| held.nlri_hash() == sibling.nlri_hash())
                    );
                }
                assert!(
                    repo.pending_withdrawals(Some("fixture"))
                        .await
                        .unwrap()
                        .is_empty()
                );
            }
        }
    }

    #[tokio::test]
    async fn invalid_mark_payload_refuses_add_but_keeps_exact_key_cleanup() {
        let speaker = MockAnnouncer::new();
        let global = FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: "192.0.2.1/32".into(),
                ..Default::default()
            },
            FlowSpecAction::discard(),
        );
        speaker.announce(&global).await.unwrap();
        let mut scoped = global.clone();
        scoped.nlri.scope = Some(
            crate::domain::VpnFlowSpecIdentity::new(
                crate::domain::VpnFlowSpecFamily::Ipv4,
                "44407:40",
            )
            .unwrap(),
        );
        scoped.route_targets = vec!["44407:777".into()];
        scoped.actions = vec![FlowSpecAction::mark(46)];
        speaker.announce(&scoped).await.unwrap();
        scoped.actions[0].dscp = None;
        assert!(speaker.announce(&scoped).await.is_err());
        assert_eq!(speaker.list_active().await.unwrap().len(), 2);
        speaker.withdraw(&scoped).await.unwrap();
        let retained = speaker.list_active().await.unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].nlri_hash(), global.nlri_hash());
    }

    #[tokio::test]
    async fn vpn_keys_and_attributes_are_isolated_and_unsupported_scope_cannot_mutate() {
        use crate::domain::{VpnFlowSpecFamily, VpnFlowSpecIdentity};
        let speaker = MockAnnouncer::new();
        let global = FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: "192.0.2.1/32".into(),
                ..Default::default()
            },
            FlowSpecAction::discard(),
        );
        speaker.announce(&global).await.unwrap();
        let mut scoped = Vec::new();
        for rd in ["44407:40", "44407:41"] {
            let mut rule = global.clone();
            rule.nlri.scope = Some(VpnFlowSpecIdentity::new(VpnFlowSpecFamily::Ipv4, rd).unwrap());
            rule.route_targets = vec!["44407:777".into()];
            assert!(!speaker.matches_nlri(&global.nlri, &rule.nlri).unwrap());
            speaker.announce(&rule).await.unwrap();
            scoped.push(rule);
        }
        assert_eq!(speaker.list_active().await.unwrap().len(), 3);
        let mut replacement = scoped[0].clone();
        replacement.route_targets = vec!["44407:778".into()];
        speaker.announce(&replacement).await.unwrap();
        assert_eq!(speaker.list_active().await.unwrap().len(), 3);
        speaker.withdraw(&replacement).await.unwrap();
        let remaining = speaker.list_active().await.unwrap();
        assert_eq!(remaining.len(), 2);
        assert!(
            remaining
                .iter()
                .any(|rule| rule.nlri_hash() == global.nlri_hash())
        );
        assert!(
            remaining
                .iter()
                .any(|rule| rule.nlri_hash() == scoped[1].nlri_hash())
        );
        let unsupported = MockAnnouncer::without_vpn_support();
        assert!(matches!(
            unsupported.announce(&scoped[0]).await,
            Err(PrefixdError::UnsupportedFlowSpecScope { .. })
        ));
        assert!(unsupported.list_active().await.unwrap().is_empty());
        let mut invalid = scoped[0].clone();
        invalid.route_targets.clear();
        assert!(speaker.announce(&invalid).await.is_err());
        assert_eq!(speaker.list_active().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_mock_announce_withdraw() {
        let announcer = MockAnnouncer::new();

        let rule = FlowSpecRule::new(
            FlowSpecNlri {
                dst_prefix: "203.0.113.10/32".to_string(),
                protocol: Some(17),
                dst_ports: vec![53],
                ..Default::default()
            },
            FlowSpecAction::police(5_000_000),
        );

        announcer.announce(&rule).await.unwrap();
        assert_eq!(announcer.announced_count().await, 1);

        announcer.withdraw(&rule).await.unwrap();
        assert_eq!(announcer.announced_count().await, 0);
    }

    #[tokio::test]
    async fn mock_blackhole_upserts_by_prefix_and_withdraws_idempotently() {
        let announcer = MockAnnouncer::new();
        let speaker = announcer.blackhole().unwrap();
        let prefix: ipnet::IpNet = "2001:db8::1/128".parse().unwrap();
        let next_hop = "2001:db8::66".parse().unwrap();
        for extra in [vec![], vec![64512 << 16 | 1]] {
            let route = BlackholeRoute::new(prefix, next_hop, extra, vec![]).unwrap();
            speaker.announce_blackhole(&route).await.unwrap();
            assert_eq!(speaker.list_blackholes().await.unwrap().routes, [route]);
        }
        for _ in 0..2 {
            speaker.withdraw_blackhole(&prefix, "").await.unwrap();
        }
        assert!(speaker.list_blackholes().await.unwrap() == BlackholeInventory::default());
        assert!(
            speaker
                .withdraw_blackhole(&"2001:db8::/64".parse().unwrap(), "")
                .await
                .is_err()
        );
        assert_eq!(announcer.announced_count().await, 0);
    }
}
