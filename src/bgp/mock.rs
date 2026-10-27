use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{
    AddOutcome, BlackholeInventory, BlackholeRoute, BlackholeSpeaker, ExportDisposition,
    ExportObserver, FlowSpecAnnouncer, FlowSpecMatchSupport, FlowSpecReader, FlowSpecWriter,
    InjectionLeases, LeaseGeneration, PeerExport, PeerObserver, PeerStatus, SessionState,
};
use crate::domain::FlowSpecRule;
use crate::error::{PrefixdError, Result};

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

    fn owner_mismatch(operation: &str) -> PrefixdError {
        PrefixdError::InjectionOwnerMismatch(format!(
            "mock refused {operation}: the key is held by another injection owner or by none"
        ))
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
    async fn announce(&self, rule: &FlowSpecRule) -> Result<()> {
        let mut rules = self.rules.write().await;
        let hash = rule.nlri_hash();
        if !rule.owner.is_empty()
            || rules
                .iter()
                .any(|r| r.nlri_hash() == hash && !r.owner.is_empty())
        {
            return Err(Self::owner_mismatch("AddFlowSpec"));
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
        let mut rules = self.rules.write().await;
        let hash = rule.nlri_hash();
        if rule.owner.is_empty()
            || rules
                .iter()
                .any(|r| r.nlri_hash() == hash && r.owner != rule.owner)
        {
            return Err(Self::owner_mismatch("AddLeasedFlowSpec"));
        }
        let generation = self.join_lease(&rule.owner);
        rules.retain(|r| r.nlri_hash() != hash);
        rules.push(rule.clone());
        Ok(generation)
    }
    async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()> {
        let mut rules = self.rules.write().await;
        let hash = rule.nlri_hash();
        if rules
            .iter()
            .any(|r| r.nlri_hash() == hash && r.owner != rule.owner)
        {
            return Err(Self::owner_mismatch("DeleteFlowSpec"));
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
            return Err(Self::owner_mismatch("AddPath"));
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
            return Err(Self::owner_mismatch("AddLeasedPath"));
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
            return Err(Self::owner_mismatch("DeletePath"));
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
                .filter(|peer| peer.state.is_established())
                .map(|peer| PeerExport {
                    peer_address: peer.address.clone(),
                    disposition: ExportDisposition::Committed,
                    reason: String::new(),
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
                .filter(|peer| peer.state.is_established())
                .map(|peer| PeerExport {
                    peer_address: peer.address.clone(),
                    disposition: ExportDisposition::Committed,
                    reason: String::new(),
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
