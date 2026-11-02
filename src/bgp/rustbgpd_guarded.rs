use super::*;
#[cfg(test)]
#[path = "guarded_decode_tests.rs"]
mod tests;
use crate::bgp::{
    GuardedFlowSpecSpeaker, GuardedInventory, GuardedObservation, GuardedRule, GuardedStamp,
    IssuedWindow,
};

impl From<GuardedStamp> for pb::MutationWindow {
    fn from(value: GuardedStamp) -> Self {
        Self {
            incarnation: value.incarnation,
            sequence: value.sequence,
        }
    }
}
impl From<GuardedStamp> for pb::LeaseGeneration {
    fn from(value: GuardedStamp) -> Self {
        Self {
            incarnation: value.incarnation,
            sequence: value.sequence,
        }
    }
}

fn generation(value: Option<pb::LeaseGeneration>) -> Result<GuardedStamp> {
    let value = value
        .filter(|v| v.incarnation != 0 && v.sequence != 0)
        .ok_or_else(|| invalid("missing guarded lease generation"))?;
    Ok(GuardedStamp {
        incarnation: value.incarnation,
        sequence: value.sequence,
    })
}

fn encode_guarded(rule: &GuardedRule) -> Result<pb::AddFlowSpecRequest> {
    rule.validate()?;
    let (afi_safi, components) = encode_match(&rule.nlri)?;
    Ok(pb::AddFlowSpecRequest {
        afi_safi,
        components,
        actions: vec![pb::FlowSpecAction {
            action: Some(pb::flow_spec_action::Action::RedirectIp(
                pb::FlowSpecRedirectIp {
                    address: rule.target.to_string(),
                    copy: false,
                },
            )),
        }],
        ..Default::default()
    })
}

/// prefixd's scrubber owners all live in this namespace. A guarded rule of any
/// other owner is foreign: never deleted, never prefixd intent, and never a
/// reason to fail a read. A malformed row of ours still fails the read.
const OWNER_NAMESPACE: &str = "prefixd.scrub.";

pub(super) fn foreign_guarded(route: &pb::FlowSpecRouteEntry) -> bool {
    route
        .injection_owner
        .strip_prefix("guarded:")
        .is_some_and(|owner| !owner.starts_with(OWNER_NAMESPACE))
}

/// Only the match of a foreign guarded rule: its action, target and other
/// attributes belong to another owner. Its key still counts as occupied.
fn foreign_match(route: pb::FlowSpecRouteEntry, family: i32) -> Result<FlowSpecNlri> {
    let route = pb::FlowSpecRouteEntry {
        components: route.components,
        peer_address: route.peer_address,
        afi_safi: route.afi_safi,
        extended_communities: vec![0x8006_u64 << 48],
        actions: vec![pb::FlowSpecAction {
            action: Some(pb::flow_spec_action::Action::TrafficRate(
                pb::FlowSpecTrafficRate { rate: 0.0 },
            )),
        }],
        ..Default::default()
    };
    Ok(decode(route, family)?.nlri)
}

/// A definitive guarded refusal: the daemon changed nothing (rustbgpd v0.81
/// guarded FlowSpec mutations). Every other failure is an unconfirmed outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GuardedRefusal {
    InvalidArgument,
    WindowNotLive,
    RevisionMismatch,
    OwnerMismatch,
    KeyUnowned,
    GenerationNotLive,
    ResourceExhausted,
    Unimplemented,
    PermissionDenied,
}

impl GuardedRefusal {
    pub(super) fn of(status: &tonic::Status) -> Option<Self> {
        Some(match status.code() {
            Code::InvalidArgument => Self::InvalidArgument,
            Code::ResourceExhausted => Self::ResourceExhausted,
            Code::Unimplemented => Self::Unimplemented,
            Code::PermissionDenied => Self::PermissionDenied,
            // A precondition refusal without a known typed reason stays unconfirmed.
            Code::FailedPrecondition => match error_reason(status)?.as_str() {
                "WINDOW_NOT_LIVE" => Self::WindowNotLive,
                "REVISION_MISMATCH" => Self::RevisionMismatch,
                "OWNER_MISMATCH" => Self::OwnerMismatch,
                "KEY_UNOWNED" => Self::KeyUnowned,
                "GENERATION_NOT_LIVE" => Self::GenerationNotLive,
                _ => return None,
            },
            _ => return None,
        })
    }

    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "invalid_argument",
            Self::WindowNotLive => "window_not_live",
            Self::RevisionMismatch => "revision_mismatch",
            Self::OwnerMismatch => "owner_mismatch",
            Self::KeyUnowned => "key_unowned",
            Self::GenerationNotLive => "generation_not_live",
            Self::ResourceExhausted => "resource_exhausted",
            Self::Unimplemented => "unimplemented",
            Self::PermissionDenied => "permission_denied",
        }
    }
}

/// Both kinds fail closed; the text names the cause for diagnosis.
pub(super) fn guarded_status_error(operation: &str, status: &tonic::Status) -> PrefixdError {
    match GuardedRefusal::of(status) {
        Some(refusal) => {
            tracing::warn!(
                operation,
                reason = refusal.as_str(),
                "rustbgpd refused guarded call"
            );
            invalid(&format!(
                "{operation} refused ({}); nothing changed",
                refusal.as_str()
            ))
        }
        None => {
            tracing::warn!(operation, code = ?status.code(), "rustbgpd guarded outcome unconfirmed");
            invalid(&format!(
                "{operation} outcome unconfirmed ({:?}); resolve by read-back, never legacy retry",
                status.code()
            ))
        }
    }
}

pub(super) fn decode_guarded(
    mut route: pb::FlowSpecRouteEntry,
    family: i32,
) -> Result<GuardedObservation> {
    let owner = route
        .injection_owner
        .strip_prefix("guarded:")
        .ok_or_else(|| invalid("guarded rule has no guarded owner"))?
        .to_owned();
    let revision = route
        .admission_revision
        .filter(|v| *v != 0)
        .ok_or_else(|| invalid("guarded rule has no admission revision"))?;
    let generation = generation(route.lease_generation.take())?;
    let remaining_ms = route
        .lease_remaining_ms
        .take()
        .ok_or_else(|| invalid("missing guarded lease time"))?;
    let [action] = route.actions.as_slice() else {
        return Err(invalid("guarded rule requires one target-IP action"));
    };
    let Some(pb::flow_spec_action::Action::RedirectIp(target)) = &action.action else {
        return Err(invalid("guarded rule requires a target-IP action"));
    };
    let address: std::net::IpAddr = target
        .address
        .parse()
        .map_err(|_| invalid("invalid redirect target"))?;
    if target.copy {
        return Err(invalid("copy action is unsupported"));
    }
    let (extended, ipv6_extended) = match address {
        std::net::IpAddr::V4(ip) => (
            vec![u64::from_be_bytes([
                1,
                12,
                ip.octets()[0],
                ip.octets()[1],
                ip.octets()[2],
                ip.octets()[3],
                0,
                0,
            ])],
            vec![],
        ),
        std::net::IpAddr::V6(ip) => {
            let mut raw = vec![0, 12];
            raw.extend(ip.octets());
            raw.extend([0, 0]);
            (vec![], vec![raw])
        }
    };
    if route.extended_communities != extended || route.ipv6_extended_communities != ipv6_extended {
        return Err(invalid("inconsistent redirect action bytes"));
    }
    // Validate every match and remaining route attribute through the strict
    // ordinary decoder, after accounting for the complete guarded action above.
    route.injection_owner.clear();
    route.admission_revision = None;
    route.ipv6_extended_communities.clear();
    route.extended_communities = vec![0x8006_u64 << 48];
    route.actions = vec![pb::FlowSpecAction {
        action: Some(pb::flow_spec_action::Action::TrafficRate(
            pb::FlowSpecTrafficRate { rate: 0.0 },
        )),
    }];
    let decoded = decode(route, family)?;
    let rule = GuardedRule {
        nlri: decoded.nlri,
        target: address,
        owner,
        revision,
    };
    rule.validate()?;
    Ok(GuardedObservation {
        rule,
        generation,
        remaining_ms,
    })
}

impl RustBgpdAnnouncer {
    async fn guarded_call<T>(
        &self,
        operation: &'static str,
        call: impl Future<Output = std::result::Result<tonic::Response<T>, tonic::Status>>,
    ) -> Result<T> {
        match tokio::time::timeout(Duration::from_secs(3), call).await {
            Ok(Ok(response)) => Ok(response.into_inner()),
            Ok(Err(status)) => Err(guarded_status_error(operation, &status)),
            Err(_) => Err(invalid(&format!(
                "{operation} outcome unconfirmed after deadline; resolve by read-back"
            ))),
        }
    }

    async fn raw_guarded_inventory(&self) -> Result<GuardedInventory> {
        let mut entries = vec![];
        let mut other_keys = vec![];
        let mut keys = std::collections::HashSet::new();
        for family in [3, 4] {
            let mut client = pb::rib_service_client::RibServiceClient::new(self.channel.clone());
            let response = self
                .guarded_call(
                    "ListFlowSpecRoutes",
                    client.list_flow_spec_routes(self.request(pb::ListFlowSpecRequest {
                        afi_safi: family,
                        received_peer_address: "0.0.0.0".into(),
                        advertised_peer_address: String::new(),
                    })),
                )
                .await?;
            if !response.received_view || response.advertised_view || !response.routes.is_empty() {
                return Err(invalid("missing guarded local intent view"));
            }
            for row in response.received_routes {
                if !matches!(row.validation, 1 | 3) || row.path_id != 0 || !row.reason.is_empty() {
                    return Err(invalid("invalid guarded local intent row"));
                }
                let route = row.route.ok_or_else(|| invalid("missing local route"))?;
                if foreign_guarded(&route) {
                    let key = foreign_match(route, family)?.compute_hash();
                    if !keys.insert(key.clone()) {
                        return Err(invalid("repeated local key"));
                    }
                    other_keys.push(key);
                } else if route.injection_owner.starts_with("guarded:")
                    || route.admission_revision.is_some()
                {
                    let observation = decode_guarded(route, family)?;
                    if !keys.insert(observation.rule.nlri.compute_hash()) {
                        return Err(invalid("repeated guarded key"));
                    }
                    entries.push(observation);
                } else {
                    let ordinary = decode(route, family)?;
                    let key = ordinary.nlri.compute_hash();
                    if !keys.insert(key.clone()) {
                        return Err(invalid("repeated local key"));
                    }
                    other_keys.push(key);
                }
            }
        }
        Ok(GuardedInventory {
            entries,
            other_keys,
        })
    }
}

#[async_trait]
impl GuardedFlowSpecSpeaker for RustBgpdAnnouncer {
    async fn issue_window(&self, owner: &str, seconds: u32) -> Result<IssuedWindow> {
        if !(1..=120).contains(&seconds)
            || owner.is_empty()
            || owner.len() > 64
            || !owner
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
        {
            return Err(invalid("invalid mutation window request"));
        }
        let mut client =
            pb::injection_service_client::InjectionServiceClient::new(self.channel.clone());
        let response = self
            .guarded_call(
                "IssueMutationWindow",
                client.issue_mutation_window(self.request(pb::IssueMutationWindowRequest {
                    owner: owner.into(),
                    window_seconds: seconds,
                })),
            )
            .await?;
        let window = response
            .window
            .filter(|v| v.incarnation != 0 && v.sequence != 0)
            .ok_or_else(|| invalid("missing mutation window"))?;
        if response.window_remaining_ms == 0 || response.window_remaining_ms > seconds * 1000 {
            return Err(invalid("invalid mutation window lifetime"));
        }
        Ok(IssuedWindow {
            stamp: GuardedStamp {
                incarnation: window.incarnation,
                sequence: window.sequence,
            },
            remaining_ms: response.window_remaining_ms,
        })
    }

    async fn add_guarded(
        &self,
        rule: &GuardedRule,
        window: GuardedStamp,
        seconds: u32,
    ) -> Result<GuardedStamp> {
        let payload = encode_guarded(rule)?;
        let mut client =
            pb::injection_service_client::InjectionServiceClient::new(self.channel.clone());
        let response = self
            .guarded_call(
                "AddGuardedFlowSpec",
                client.add_guarded_flow_spec(self.request(pb::AddGuardedFlowSpecRequest {
                    rule: Some(payload),
                    lease: Some(pb::InjectionLease {
                        owner: rule.owner.clone(),
                        lease_seconds: seconds,
                    }),
                    window: Some(window.into()),
                    revision: rule.revision,
                })),
            )
            .await?;
        match response
            .result
            .map(|r| pb::FlowSpecInjectOutcome::try_from(r.outcome))
        {
            Some(Ok(pb::FlowSpecInjectOutcome::Created | pb::FlowSpecInjectOutcome::Unchanged)) => {
                generation(response.generation)
            }
            _ => Err(invalid("invalid guarded add outcome")),
        }
    }

    async fn renew_guarded(
        &self,
        owner: &str,
        current: GuardedStamp,
        window: GuardedStamp,
        seconds: u32,
    ) -> Result<u32> {
        let mut client =
            pb::injection_service_client::InjectionServiceClient::new(self.channel.clone());
        let response = self
            .guarded_call(
                "RenewGuardedLease",
                client.renew_guarded_lease(self.request(pb::RenewGuardedLeaseRequest {
                    owner: owner.into(),
                    generation: Some(current.into()),
                    lease_seconds: seconds,
                    window: Some(window.into()),
                })),
            )
            .await?;
        if generation(response.generation)? != current
            || response.lease_remaining_ms == 0
            || response.lease_remaining_ms > 120_000
        {
            return Err(invalid("invalid guarded renewal"));
        }
        Ok(response.lease_remaining_ms)
    }

    async fn delete_guarded(&self, rule: &GuardedRule) -> Result<()> {
        let payload = encode_guarded(rule)?;
        let mut client =
            pb::injection_service_client::InjectionServiceClient::new(self.channel.clone());
        let response = self
            .guarded_call(
                "DeleteGuardedFlowSpec",
                client.delete_guarded_flow_spec(self.request(pb::DeleteGuardedFlowSpecRequest {
                    afi_safi: payload.afi_safi,
                    components: payload.components,
                    owner: rule.owner.clone(),
                    revision: rule.revision,
                })),
            )
            .await?;
        match pb::FlowSpecDeleteOutcome::try_from(response.outcome) {
            Ok(pb::FlowSpecDeleteOutcome::Deleted | pb::FlowSpecDeleteOutcome::NotPresent) => {
                Ok(())
            }
            _ => Err(invalid("invalid guarded delete outcome")),
        }
    }

    async fn guarded_inventory(&self) -> Result<GuardedInventory> {
        self.raw_guarded_inventory().await
    }
}
