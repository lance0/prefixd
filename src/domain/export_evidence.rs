//! Per-peer export evidence for active mitigations: the speaker's export
//! dispositions joined with its peer sessions. Observation only.
//!
//! A committed disposition means the route is in that peer's Adj-RIB-Out. It
//! does not prove the peer received, accepted, installed or enforces it.

use std::collections::HashMap;
use std::sync::RwLock;

use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::bgp::{ExportDisposition, PeerExport, PeerStatus};

/// What is known about one blackhole's export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExportObservation {
    /// Read to the last page.
    Observed,
    /// The speaker holds no local route at the key; reconciliation repairs it.
    NoLocalRoute,
    /// The read failed or was partial: export is unknown, not empty.
    Error,
    /// The speaker cannot report export (GoBGP).
    Unsupported,
    /// Not read yet: no reconciliation pass has observed this blackhole.
    NotObserved,
}

/// A configured peer without an Established session: it is exported nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct NotEstablishedPeer {
    pub peer_address: String,
    /// Optional separately observed FSM state, such as `active` or `idle`.
    pub state: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, ToSchema)]
pub struct DispositionCounts {
    pub committed: usize,
    pub withheld: usize,
    pub pending: usize,
}

impl DispositionCounts {
    fn add(&mut self, disposition: ExportDisposition) {
        match disposition {
            ExportDisposition::Committed => self.committed += 1,
            ExportDisposition::Withheld => self.withheld += 1,
            ExportDisposition::Pending => self.pending += 1,
            ExportDisposition::NotEstablished => {}
        }
    }

    pub fn get(&self, disposition: ExportDisposition) -> usize {
        match disposition {
            ExportDisposition::Committed => self.committed,
            ExportDisposition::Withheld => self.withheld,
            ExportDisposition::Pending => self.pending,
            ExportDisposition::NotEstablished => 0,
        }
    }
}

/// Bounded reasons an observed blackhole is committed to no Established peer.
/// They are the `reason` label of `prefixd_blackhole_unexported`.
pub const UNEXPORTED_REASONS: [&str; 12] = [
    "no_established_peer",
    "export_policy",
    "family_suppressed",
    "family_not_negotiated",
    "not_selected",
    "outbound_prefix_limit",
    "exact_export_rejected",
    "export_rule",
    "pending",
    "selection_deferred",
    "mixed",
    "other",
];

/// An observed blackhole committed to no Established peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ExportWarning {
    /// One of the bounded unexported reasons.
    #[schema(example = "export_policy")]
    pub reason: &'static str,
    pub message: &'static str,
}

fn unexported(peers: &[PeerExport]) -> ExportWarning {
    let base = |peer: &PeerExport| peer.reason.split(':').next().unwrap_or_default().to_owned();
    let reason = match peers {
        [] => "no_established_peer",
        // Graceful Restart selection deferral after a speaker restart.
        _ if peers.iter().all(|peer| {
            peer.disposition == ExportDisposition::Pending && base(peer) == "selection_deferred"
        }) =>
        {
            "selection_deferred"
        }
        _ if peers
            .iter()
            .all(|peer| peer.disposition == ExportDisposition::Pending) =>
        {
            "pending"
        }
        [first, ..]
            if peers.iter().all(|peer| {
                peer.disposition == ExportDisposition::Withheld && base(peer) == base(first)
            }) =>
        {
            let first = base(first);
            // The withheld reason codes rustbgpd documents.
            UNEXPORTED_REASONS[1..8]
                .iter()
                .find(|known| **known == first)
                .copied()
                .unwrap_or("other")
        }
        _ => "mixed",
    };
    let message = match reason {
        "no_established_peer" => "No peer session is Established, so no router is sent the route.",
        "export_policy" => {
            "Export policy denies it toward every Established peer; check the speaker's export policy."
        }
        "family_suppressed" => {
            "Every Established session withholds its address family, for example an IPv6 \
             route on a session without an IPv6 next hop."
        }
        "family_not_negotiated" => "No Established session negotiated its address family.",
        "not_selected" => "Another path for the prefix is selected toward every Established peer.",
        "outbound_prefix_limit" => "Every Established peer's outbound prefix limit is reached.",
        "exact_export_rejected" => "Every Established session refuses its exact encoding.",
        "export_rule" => "Another export rule stops it toward every Established peer.",
        "pending" => "Export to every Established peer has not settled yet.",
        "selection_deferred" => {
            "The speaker accepted it but holds it from selection after a speaker restart \
             until its Graceful Restart peers send End-of-RIB or the restart window expires."
        }
        "mixed" => "It is withheld or pending toward every Established peer; see each peer.",
        _ => {
            "It is withheld from every Established peer for an unclassified reason; see each peer."
        }
    };
    ExportWarning { reason, message }
}

/// Export evidence shared by blackholes and FlowSpec; the schema name is retained for compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct BlackholeExportEvidence {
    pub status: ExportObservation,
    /// Retained evidence from before the controller last lost ownership.
    pub historical: bool,
    /// Controller time of the read; preserved with historical rows on a failed
    /// refresh. Null when not observed or unsupported.
    pub observed_at: Option<DateTime<Utc>>,
    /// One row per Established peer from a complete read, possibly historical.
    pub peers: Vec<PeerExport>,
    /// Configured peers without an Established session. A complete export read
    /// supplies addressed peers even when optional session observation failed.
    /// Null when neither read establishes membership: unknown, not none.
    pub not_established_peers: Option<Vec<NotEstablishedPeer>>,
    pub counts: DispositionCounts,
    /// Present when an observed route is committed to no Established peer.
    /// On `error`, the last complete read's warning, kept so health does not flap.
    pub warning: Option<ExportWarning>,
    pub error: Option<String>,
}

impl BlackholeExportEvidence {
    pub fn unobserved(status: ExportObservation) -> Self {
        Self {
            status,
            historical: false,
            observed_at: None,
            peers: vec![],
            not_established_peers: None,
            counts: DispositionCounts::default(),
            warning: None,
            error: None,
        }
    }

    /// One read's evidence. `sessions` is the pass's peer read, if it succeeded.
    pub fn from_read(
        read: &crate::error::Result<Option<Vec<PeerExport>>>,
        sessions: Option<&[PeerStatus]>,
        observed_at: DateTime<Utc>,
    ) -> Self {
        let not_established_peers = sessions.map(|sessions| {
            sessions
                .iter()
                .filter(|peer| !peer.state.is_established())
                .map(|peer| NotEstablishedPeer {
                    peer_address: peer.address.clone(),
                    state: Some(peer.state.to_string()),
                })
                .collect()
        });
        let mut evidence = Self {
            observed_at: Some(observed_at),
            not_established_peers,
            ..Self::unobserved(ExportObservation::Observed)
        };
        match read {
            Ok(Some(peers)) => {
                // Export rows fence addressed membership; ListNeighbors only
                // enriches FSM state and supplies interfaces awaiting discovery.
                let mut down = Vec::new();
                for peer in peers {
                    if peer.disposition == ExportDisposition::NotEstablished {
                        down.push(NotEstablishedPeer {
                            peer_address: peer.peer_address.clone(),
                            state: sessions.and_then(|sessions| {
                                sessions
                                    .iter()
                                    .find(|session| {
                                        session.address == peer.peer_address
                                            && !session.state.is_established()
                                    })
                                    .map(|session| session.state.to_string())
                            }),
                        });
                        continue;
                    }
                    evidence.counts.add(peer.disposition);
                    evidence.peers.push(peer.clone());
                }
                down.extend(
                    evidence
                        .not_established_peers
                        .iter()
                        .flatten()
                        .filter(|peer| peer.peer_address.starts_with("interface:"))
                        .filter(|peer| {
                            !peers.iter().any(|row| {
                                row.peer_address
                                    .split_once('%')
                                    .is_some_and(|(_, interface)| {
                                        peer.peer_address.strip_prefix("interface:")
                                            == Some(interface)
                                    })
                            })
                        })
                        .cloned(),
                );
                evidence.not_established_peers = Some(down);
                if evidence.counts.committed == 0 {
                    evidence.warning = Some(unexported(&evidence.peers));
                }
            }
            Ok(None) => evidence.status = ExportObservation::NoLocalRoute,
            Err(error) => {
                evidence.status = ExportObservation::Error;
                evidence.error = Some(error.to_string());
            }
        }
        evidence
    }
}

/// An observed blackhole committed to no Established peer, for health.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct UnexportedBlackhole {
    pub mitigation_id: Uuid,
    #[schema(example = "203.0.113.10/32")]
    pub prefix: String,
    #[serde(flatten)]
    pub warning: ExportWarning,
}

/// Authenticated health summary of the last export observation pass.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, ToSchema)]
pub struct BlackholeExportSummary {
    /// At least part of this snapshot predates the last loss of ownership.
    pub historical: bool,
    /// Controller time of the last pass that observed export; null before one.
    pub observed_at: Option<DateTime<Utc>>,
    /// Active enforced blackholes in that pass.
    pub blackholes: usize,
    /// Peer dispositions summed over the observed blackholes.
    pub counts: DispositionCounts,
    /// Blackholes whose read failed: export unknown.
    pub errors: usize,
    /// Blackholes the speaker held no local route for.
    pub no_local_route: usize,
    /// Observed blackholes committed to no Established peer.
    pub unexported: Vec<UnexportedBlackhole>,
}

/// FlowSpec export health, using the same evidence semantics as blackholes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, ToSchema)]
pub struct FlowSpecExportSummary {
    pub historical: bool,
    pub observed_at: Option<DateTime<Utc>>,
    pub rules: usize,
    pub counts: DispositionCounts,
    pub errors: usize,
    pub no_local_route: usize,
    pub unexported: Vec<UnexportedBlackhole>,
}

impl From<BlackholeExportSummary> for FlowSpecExportSummary {
    fn from(summary: BlackholeExportSummary) -> Self {
        Self {
            historical: summary.historical,
            observed_at: summary.observed_at,
            rules: summary.blackholes,
            counts: summary.counts,
            errors: summary.errors,
            no_local_route: summary.no_local_route,
            unexported: summary.unexported,
        }
    }
}

#[derive(Debug, Default)]
struct Snapshot {
    inventory_error: Option<String>,
    observed_at: Option<DateTime<Utc>>,
    epoch: Option<u64>,
    routes: HashMap<Uuid, StoredEvidence>,
}

#[derive(Debug)]
struct StoredEvidence {
    prefix: String,
    evidence: BlackholeExportEvidence,
    epoch: u64,
}

/// The last pass's evidence, held in memory. Reconciliation replaces it once
/// per pass; API and health reads never call the speaker.
#[derive(Debug, Default)]
pub struct ExportEvidenceStore(RwLock<Snapshot>);

impl ExportEvidenceStore {
    /// Replace the snapshot with one pass's evidence, by mitigation ID, with prefix.
    pub fn replace(
        &self,
        observed_at: DateTime<Utc>,
        epoch: u64,
        routes: HashMap<Uuid, (String, BlackholeExportEvidence)>,
    ) {
        let mut snapshot = self.0.write().unwrap_or_else(|poison| poison.into_inner());
        let routes = routes
            .into_iter()
            .map(|(id, (prefix, mut evidence))| {
                let mut route_epoch = epoch;
                if evidence.status == ExportObservation::Error
                    && let Some(previous) = snapshot.routes.get(&id)
                    && previous.epoch != epoch
                {
                    // A failed refresh cannot turn evidence from a previous owner into current data.
                    let error = evidence.error;
                    evidence = previous.evidence.clone();
                    evidence.status = ExportObservation::Error;
                    evidence.error = error;
                    route_epoch = previous.epoch;
                }
                (
                    id,
                    StoredEvidence {
                        prefix,
                        evidence,
                        epoch: route_epoch,
                    },
                )
            })
            .collect();
        *snapshot = Snapshot {
            inventory_error: None,
            observed_at: Some(observed_at),
            epoch: Some(epoch),
            routes,
        };
    }

    /// The candidate set is unknown: keep prior complete observations, never an empty set.
    pub fn inventory_failed(&self, error: String) {
        self.0
            .write()
            .unwrap_or_else(|poison| poison.into_inner())
            .inventory_error = Some(error);
    }

    pub fn get(&self, mitigation_id: Uuid, epoch: Option<u64>) -> Option<BlackholeExportEvidence> {
        let snapshot = self.0.read().unwrap_or_else(|poison| poison.into_inner());
        let mut evidence = match snapshot.routes.get(&mitigation_id) {
            Some(stored) => {
                let mut evidence = stored.evidence.clone();
                evidence.historical = epoch != Some(stored.epoch);
                evidence
            }
            None if snapshot.inventory_error.is_some() => {
                BlackholeExportEvidence::unobserved(ExportObservation::Error)
            }
            None => return None,
        };
        if let Some(error) = &snapshot.inventory_error {
            evidence.status = ExportObservation::Error;
            evidence.error = Some(error.clone());
            if !evidence.historical {
                evidence.counts = Default::default();
            }
        }
        Some(evidence)
    }

    pub fn summary(&self, epoch: Option<u64>) -> BlackholeExportSummary {
        self.summarize(epoch, true)
    }

    /// Attempted read errors still count, but historical dispositions and
    /// warnings are not presented as current; ownership loss invents no RPC failure.
    pub fn current_summary(&self, epoch: Option<u64>) -> BlackholeExportSummary {
        self.summarize(epoch, false)
    }

    fn summarize(&self, epoch: Option<u64>, with_historical: bool) -> BlackholeExportSummary {
        let snapshot = self.0.read().unwrap_or_else(|poison| poison.into_inner());
        let mut summary = BlackholeExportSummary {
            historical: snapshot.observed_at.is_some() && snapshot.epoch != epoch,
            observed_at: snapshot.observed_at,
            blackholes: snapshot.routes.len(),
            ..Default::default()
        };
        for (id, stored) in &snapshot.routes {
            let evidence = &stored.evidence;
            let historical = epoch != Some(stored.epoch);
            summary.historical |= historical;
            match evidence.status {
                ExportObservation::Error => summary.errors += 1,
                ExportObservation::NoLocalRoute => summary.no_local_route += 1,
                _ => {}
            }
            if historical && !with_historical {
                continue;
            }
            if snapshot.inventory_error.is_none() {
                summary.counts.committed += evidence.counts.committed;
                summary.counts.withheld += evidence.counts.withheld;
                summary.counts.pending += evidence.counts.pending;
            }
            if let Some(warning) = &evidence.warning {
                summary.unexported.push(UnexportedBlackhole {
                    mitigation_id: *id,
                    prefix: stored.prefix.clone(),
                    warning: warning.clone(),
                });
            }
        }
        if snapshot.inventory_error.is_some() {
            // One inventory-level failure when no candidate keys are known yet.
            summary.errors = snapshot.routes.len().max(1);
        }
        summary.unexported.sort_by(|a, b| a.prefix.cmp(&b.prefix));
        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::SessionState;

    #[test]
    fn bound_interfaces_keep_percent_in_their_identity() {
        let sessions = ["eth%0", "0"].map(|interface| PeerStatus {
            name: format!("interface:{interface}"),
            address: format!("interface:{interface}"),
            state: SessionState::Idle,
        });
        let evidence = BlackholeExportEvidence::from_read(
            &Ok(Some(vec![peer(
                "fe80::1%eth%0",
                ExportDisposition::Committed,
                "",
            )])),
            Some(&sessions),
            Utc::now(),
        );
        assert_eq!(
            evidence.not_established_peers,
            Some(vec![NotEstablishedPeer {
                peer_address: "interface:0".into(),
                state: Some("idle".into()),
            }])
        );
        assert_eq!(evidence.counts.committed, 1);
    }

    #[test]
    fn configured_export_membership_survives_missing_or_raced_sessions() {
        use ExportDisposition::{Committed, NotEstablished};
        let peers = vec![
            peer("fe80::1%eth0", Committed, ""),
            peer("fe80::1%eth1", NotEstablished, "not_established"),
        ];
        let sessions = [
            PeerStatus {
                name: "eth0".into(),
                address: "fe80::1%eth0".into(),
                state: SessionState::Active,
            },
            PeerStatus {
                name: "eth1".into(),
                address: "fe80::1%eth1".into(),
                state: SessionState::Established,
            },
            PeerStatus {
                name: "stale".into(),
                address: "192.0.2.99".into(),
                state: SessionState::Idle,
            },
            PeerStatus {
                name: "interface:swp1".into(),
                address: "interface:swp1".into(),
                state: SessionState::Idle,
            },
            PeerStatus {
                name: "interface:eth0".into(),
                address: "interface:eth0".into(),
                state: SessionState::Idle,
            },
            PeerStatus {
                name: "interface:eth1".into(),
                address: "interface:eth1".into(),
                state: SessionState::Idle,
            },
        ];
        for sessions in [None, Some(sessions.as_slice())] {
            let evidence =
                BlackholeExportEvidence::from_read(&Ok(Some(peers.clone())), sessions, Utc::now());
            assert_eq!(evidence.peers, peers[..1]);
            assert_eq!(
                evidence.counts,
                DispositionCounts {
                    committed: 1,
                    withheld: 0,
                    pending: 0
                }
            );
            assert!(evidence.warning.is_none());
            let down = evidence.not_established_peers.unwrap();
            assert_eq!(
                down[0],
                NotEstablishedPeer {
                    peer_address: "fe80::1%eth1".into(),
                    state: None
                }
            );
            assert_eq!(down.len(), if sessions.is_some() { 2 } else { 1 });
            if sessions.is_some() {
                assert_eq!(
                    down[1],
                    NotEstablishedPeer {
                        peer_address: "interface:swp1".into(),
                        state: Some("idle".into())
                    }
                );
            }
        }
        let all_down =
            BlackholeExportEvidence::from_read(&Ok(Some(peers[1..].to_vec())), None, Utc::now());
        assert_eq!(all_down.counts, DispositionCounts::default());
        assert!(all_down.peers.is_empty());
        assert_eq!(all_down.warning.unwrap().reason, "no_established_peer");
        let withheld = peer("192.0.2.1", ExportDisposition::Withheld, "export_policy");
        let denied = BlackholeExportEvidence::from_read(
            &Ok(Some(vec![withheld.clone(), peers[1].clone()])),
            None,
            Utc::now(),
        );
        assert_eq!(denied.warning.unwrap().reason, "export_policy");
        let empty =
            BlackholeExportEvidence::from_read(&Ok(Some(vec![])), Some(&sessions), Utc::now());
        assert!(
            empty
                .not_established_peers
                .unwrap()
                .iter()
                .all(|peer| peer.peer_address.starts_with("interface:"))
        );
    }

    fn peer(address: &str, disposition: ExportDisposition, reason: &str) -> PeerExport {
        PeerExport {
            peer_address: address.into(),
            disposition,
            reason: reason.into(),
            explain_code: String::new(),
            detail: String::new(),
            advertised_path_id: 0,
        }
    }

    fn reason(peers: Vec<PeerExport>) -> Option<&'static str> {
        BlackholeExportEvidence::from_read(&Ok(Some(peers)), None, Utc::now())
            .warning
            .map(|warning| warning.reason)
    }

    #[test]
    fn a_failed_refresh_preserves_historical_rows_until_each_route_is_read_again() {
        let store = ExportEvidenceStore::default();
        let ids = [Uuid::new_v4(), Uuid::new_v4()];
        let observed_at = Utc::now();
        let committed = BlackholeExportEvidence::from_read(
            &Ok(Some(vec![peer(
                "192.0.2.1",
                ExportDisposition::Committed,
                "",
            )])),
            None,
            observed_at,
        );
        let routes = || {
            ids.into_iter()
                .map(|id| (id, ("192.0.2.10/32".into(), committed.clone())))
                .collect()
        };
        store.replace(observed_at, 0, routes());
        assert!(!store.get(ids[0], Some(0)).unwrap().historical);
        for epoch in [None, Some(1)] {
            let historical = store.get(ids[0], epoch).unwrap();
            assert!(historical.historical);
            assert_eq!(historical.observed_at, Some(observed_at));
            assert_eq!(historical.peers, committed.peers);
            assert!(store.summary(epoch).historical);
        }

        let later = observed_at + chrono::Duration::seconds(30);
        let failed = BlackholeExportEvidence::from_read(
            &Err(crate::error::PrefixdError::Internal(
                "speaker unavailable".into(),
            )),
            None,
            later,
        );
        store.replace(
            later,
            1,
            [
                (ids[0], ("192.0.2.10/32".into(), failed)),
                (ids[1], ("192.0.2.11/32".into(), committed.clone())),
            ]
            .into(),
        );
        let historical = store.get(ids[0], Some(1)).unwrap();
        assert_eq!(historical.status, ExportObservation::Error);
        assert!(historical.historical);
        assert_eq!(historical.observed_at, Some(observed_at));
        assert_eq!(historical.peers, committed.peers);
        assert_eq!(historical.counts, committed.counts);
        assert_eq!(
            historical.error.as_deref(),
            Some("internal error: speaker unavailable")
        );
        assert!(
            !store.get(ids[1], Some(1)).unwrap().historical,
            "freshness is per route"
        );
        assert!(store.summary(Some(1)).historical);
        assert_eq!(store.summary(Some(1)).errors, 1);

        let missing = BlackholeExportEvidence::from_read(&Ok(None), None, later);
        store.replace(
            later,
            1,
            [(ids[0], ("192.0.2.10/32".into(), missing))].into(),
        );
        let current = store.get(ids[0], Some(1)).unwrap();
        assert!(!current.historical);
        assert_eq!(current.status, ExportObservation::NoLocalRoute);
        assert_eq!(current.observed_at, Some(later));
        assert!(current.peers.is_empty());
        assert!(!store.summary(Some(1)).historical);
    }

    #[test]
    fn committed_to_no_established_peer_warns_with_a_bounded_reason() {
        use ExportDisposition::{Committed, Pending, Withheld};
        assert_eq!(
            reason(vec![
                peer("192.0.2.1", Committed, ""),
                peer("192.0.2.2", Withheld, "export_policy"),
            ]),
            None
        );
        assert_eq!(reason(vec![]), Some("no_established_peer"));
        let cases = [
            (vec![("export_policy", Withheld)], "export_policy"),
            (
                vec![
                    ("family_suppressed:missing_ipv6_next_hop", Withheld),
                    ("family_suppressed:other", Withheld),
                ],
                "family_suppressed",
            ),
            (
                vec![("exact_export_rejected:missing_ipv6_next_hop", Withheld)],
                "exact_export_rejected",
            ),
            (vec![("not_yet_committed", Pending)], "pending"),
            (
                vec![
                    ("selection_deferred", Pending),
                    ("selection_deferred", Pending),
                ],
                "selection_deferred",
            ),
            (
                vec![
                    ("selection_deferred", Pending),
                    ("not_yet_committed", Pending),
                ],
                "pending",
            ),
            (
                vec![("selection_deferred", Pending), ("export_policy", Withheld)],
                "mixed",
            ),
            (
                vec![("export_policy", Withheld), ("not_selected", Withheld)],
                "mixed",
            ),
            (
                vec![("export_policy", Withheld), ("outbound_resync", Pending)],
                "mixed",
            ),
            (vec![("a_future_code", Withheld)], "other"),
        ];
        for (rows, expected) in cases {
            let peers = rows
                .into_iter()
                .enumerate()
                .map(|(index, (code, disposition))| {
                    peer(&format!("192.0.2.{index}"), disposition, code)
                })
                .collect();
            assert_eq!(reason(peers), Some(expected));
            assert!(UNEXPORTED_REASONS.contains(&expected));
        }
    }

    /// Operator text describes local send-side state only.
    #[test]
    fn warning_text_never_claims_installation_or_enforcement() {
        for reason in UNEXPORTED_REASONS {
            let peers = match reason {
                "no_established_peer" => vec![],
                "pending" => vec![peer("192.0.2.1", ExportDisposition::Pending, "x")],
                "selection_deferred" => vec![peer(
                    "192.0.2.1",
                    ExportDisposition::Pending,
                    "selection_deferred",
                )],
                "mixed" => vec![
                    peer("192.0.2.1", ExportDisposition::Pending, "x"),
                    peer("192.0.2.2", ExportDisposition::Withheld, "x"),
                ],
                "other" => vec![peer("192.0.2.1", ExportDisposition::Withheld, "new")],
                code => vec![peer("192.0.2.1", ExportDisposition::Withheld, code)],
            };
            let warning = unexported(&peers);
            assert_eq!(warning.reason, reason);
            let text = warning.message.to_lowercase();
            assert!(
                !text.contains("install") && !text.contains("enforc"),
                "{text}"
            );
        }
        assert_eq!(
            unexported(&[peer(
                "192.0.2.1",
                ExportDisposition::Withheld,
                "export_policy"
            )])
            .message,
            "Export policy denies it toward every Established peer; check the speaker's export policy."
        );
    }

    #[test]
    fn failed_read_and_missing_route_are_not_empty_success() {
        let sessions = [
            PeerStatus {
                name: "192.0.2.1".into(),
                address: "192.0.2.1".into(),
                state: SessionState::Established,
            },
            PeerStatus {
                name: "192.0.2.2".into(),
                address: "192.0.2.2".into(),
                state: SessionState::Active,
            },
        ];
        let now = Utc::now();
        let failed = BlackholeExportEvidence::from_read(
            &Err(crate::error::PrefixdError::Internal("read failed".into())),
            Some(&sessions),
            now,
        );
        assert_eq!(failed.status, ExportObservation::Error);
        assert_eq!(failed.warning, None, "unknown export is not unexported");
        assert_eq!(failed.error.as_deref(), Some("internal error: read failed"));
        let missing = BlackholeExportEvidence::from_read(&Ok(None), None, now);
        assert_eq!(missing.status, ExportObservation::NoLocalRoute);
        assert_eq!(missing.warning, None);
        assert_eq!(missing.not_established_peers, None);
        let empty = BlackholeExportEvidence::from_read(
            &Ok(Some(vec![peer(
                "192.0.2.2",
                ExportDisposition::NotEstablished,
                "not_established",
            )])),
            Some(&sessions),
            now,
        );
        assert_eq!(empty.status, ExportObservation::Observed);
        assert_eq!(empty.warning.unwrap().reason, "no_established_peer");
        assert_eq!(
            empty.not_established_peers.unwrap(),
            [NotEstablishedPeer {
                peer_address: "192.0.2.2".into(),
                state: Some("active".into()),
            }]
        );

        let store = ExportEvidenceStore::default();
        assert_eq!(store.summary(Some(0)), BlackholeExportSummary::default());
        let ids = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
        store.replace(
            now,
            0,
            [
                (ids[0], ("192.0.2.10/32".to_owned(), failed)),
                (
                    ids[1],
                    (
                        "192.0.2.11/32".to_owned(),
                        BlackholeExportEvidence::from_read(&Ok(Some(vec![])), None, now),
                    ),
                ),
                (ids[2], ("192.0.2.12/32".to_owned(), missing)),
            ]
            .into(),
        );
        let summary = store.summary(Some(0));
        assert_eq!(
            (summary.blackholes, summary.errors, summary.no_local_route),
            (3, 1, 1)
        );
        assert_eq!(summary.unexported.len(), 1);
        assert_eq!(summary.unexported[0].mitigation_id, ids[1]);
        assert_eq!(
            store.get(ids[0], Some(0)).unwrap().status,
            ExportObservation::Error
        );
    }
}
