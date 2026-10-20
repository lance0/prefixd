//! Per-peer export evidence for active blackholes: the speaker's export
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
    /// Session state, such as `active` or `idle`.
    pub state: String,
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
        }
    }

    pub fn get(&self, disposition: ExportDisposition) -> usize {
        match disposition {
            ExportDisposition::Committed => self.committed,
            ExportDisposition::Withheld => self.withheld,
            ExportDisposition::Pending => self.pending,
        }
    }
}

/// Bounded reasons an observed blackhole is committed to no Established peer.
/// They are the `reason` label of `prefixd_blackhole_unexported`.
pub const UNEXPORTED_REASONS: [&str; 11] = [
    "no_established_peer",
    "export_policy",
    "family_suppressed",
    "family_not_negotiated",
    "not_selected",
    "outbound_prefix_limit",
    "exact_export_rejected",
    "export_rule",
    "pending",
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
            "Export policy denies it toward every Established peer. A blackhole /32 or /128 is \
             usually RPKI-Invalid: check for an export filter that drops RPKI-Invalid routes."
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
        "mixed" => "It is withheld or pending toward every Established peer; see each peer.",
        _ => {
            "It is withheld from every Established peer for an unclassified reason; see each peer."
        }
    };
    ExportWarning { reason, message }
}

/// Export evidence for one active blackhole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct BlackholeExportEvidence {
    pub status: ExportObservation,
    /// Controller time of the read; null when not observed or unsupported.
    pub observed_at: Option<DateTime<Utc>>,
    /// One row per Established peer, from a complete read; empty otherwise.
    pub peers: Vec<PeerExport>,
    /// Configured peers without an Established session. Null when the session
    /// read failed or is unsupported: unknown, not none.
    pub not_established_peers: Option<Vec<NotEstablishedPeer>>,
    pub counts: DispositionCounts,
    /// Present when an observed route is committed to no Established peer.
    pub warning: Option<ExportWarning>,
    pub error: Option<String>,
}

impl BlackholeExportEvidence {
    pub fn unobserved(status: ExportObservation) -> Self {
        Self {
            status,
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
                    state: peer.state.to_string(),
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
                for peer in peers {
                    evidence.counts.add(peer.disposition);
                }
                if evidence.counts.committed == 0 {
                    evidence.warning = Some(unexported(peers));
                }
                evidence.peers = peers.clone();
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

#[derive(Debug, Default)]
struct Snapshot {
    observed_at: Option<DateTime<Utc>>,
    routes: HashMap<Uuid, (String, BlackholeExportEvidence)>,
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
        routes: HashMap<Uuid, (String, BlackholeExportEvidence)>,
    ) {
        *self.0.write().unwrap_or_else(|poison| poison.into_inner()) = Snapshot {
            observed_at: Some(observed_at),
            routes,
        };
    }

    pub fn get(&self, mitigation_id: Uuid) -> Option<BlackholeExportEvidence> {
        self.0
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .routes
            .get(&mitigation_id)
            .map(|(_, evidence)| evidence.clone())
    }

    pub fn summary(&self) -> BlackholeExportSummary {
        let snapshot = self.0.read().unwrap_or_else(|poison| poison.into_inner());
        let mut summary = BlackholeExportSummary {
            observed_at: snapshot.observed_at,
            blackholes: snapshot.routes.len(),
            ..Default::default()
        };
        for (id, (prefix, evidence)) in &snapshot.routes {
            match evidence.status {
                ExportObservation::Error => summary.errors += 1,
                ExportObservation::NoLocalRoute => summary.no_local_route += 1,
                _ => {}
            }
            summary.counts.committed += evidence.counts.committed;
            summary.counts.withheld += evidence.counts.withheld;
            summary.counts.pending += evidence.counts.pending;
            if let Some(warning) = &evidence.warning {
                summary.unexported.push(UnexportedBlackhole {
                    mitigation_id: *id,
                    prefix: prefix.clone(),
                    warning: warning.clone(),
                });
            }
        }
        summary.unexported.sort_by(|a, b| a.prefix.cmp(&b.prefix));
        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::SessionState;

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
        assert!(
            unexported(&[peer(
                "192.0.2.1",
                ExportDisposition::Withheld,
                "export_policy"
            )])
            .message
            .contains("RPKI-Invalid")
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
        let empty = BlackholeExportEvidence::from_read(&Ok(Some(vec![])), Some(&sessions), now);
        assert_eq!(empty.status, ExportObservation::Observed);
        assert_eq!(empty.warning.unwrap().reason, "no_established_peer");
        assert_eq!(
            empty.not_established_peers.unwrap(),
            [NotEstablishedPeer {
                peer_address: "192.0.2.2".into(),
                state: "active".into(),
            }]
        );

        let store = ExportEvidenceStore::default();
        assert_eq!(store.summary(), BlackholeExportSummary::default());
        let ids = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
        store.replace(
            now,
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
        let summary = store.summary();
        assert_eq!(
            (summary.blackholes, summary.errors, summary.no_local_route),
            (3, 1, 1)
        );
        assert_eq!(summary.unexported.len(), 1);
        assert_eq!(summary.unexported[0].mitigation_id, ids[1]);
        assert_eq!(store.get(ids[0]).unwrap().status, ExportObservation::Error);
    }
}
