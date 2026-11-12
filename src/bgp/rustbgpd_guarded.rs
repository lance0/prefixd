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
    // A validated rule with a community is a return leg (ADR 030 R2).
    let communities = rule
        .export_community
        .as_deref()
        .map(|text| {
            crate::bgp::export_community_value(text)
                .ok_or_else(|| invalid("invalid return-leg community"))
        })
        .transpose()?;
    let (afi_safi, components) = encode_components(&rule.nlri, communities.is_some())?;
    let (route_targets, extended_communities) =
        encode_scope_targets(rule.nlri.scope.as_ref(), &rule.route_targets)?;
    let action = match (rule.target, &rule.redirect_route_target) {
        (Some(target), None) => pb::flow_spec_action::Action::RedirectIp(pb::FlowSpecRedirectIp {
            address: target.to_string(),
            copy: false,
        }),
        (None, Some(target)) => pb::flow_spec_action::Action::Redirect(pb::FlowSpecRedirect {
            route_target: target.clone(),
        }),
        _ => return Err(invalid("invalid guarded redirect target")),
    };
    Ok(pb::AddFlowSpecRequest {
        afi_safi,
        components,
        rd: rule
            .nlri
            .scope
            .as_ref()
            .map(|scope| scope.rd().to_owned())
            .unwrap_or_default(),
        route_targets,
        extended_communities,
        communities: communities.into_iter().collect(),
        actions: vec![pb::FlowSpecAction {
            action: Some(action),
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
fn scope_rt_bytes(route: &pb::FlowSpecRouteEntry) -> Result<Vec<u64>> {
    let mut targets = route
        .route_targets
        .iter()
        .map(|target| {
            crate::domain::route_target_bytes(target).map_err(|error| invalid(&error.to_string()))
        })
        .collect::<Result<Vec<_>>>()?;
    targets.sort_unstable();
    Ok(targets)
}

fn raw_scope_targets(communities: &[u64]) -> Vec<u64> {
    communities
        .iter()
        .copied()
        .filter(|community| {
            let bytes = community.to_be_bytes();
            matches!(bytes[0], 0..=2) && bytes[1] == 2
        })
        .collect()
}

/// The match of a global local rule without a destination component that is
/// not prefixd's own return leg (ADR 030 R5). prefixd never injects that
/// shape except as a scrubber return leg, so only the key matters: it occupies
/// the key and affects every victim of its family. Its path attributes and
/// actions belong to another owner and are not checked, but its match
/// components are still decoded strictly: an unsupported component fails the
/// whole read, which is fail-closed.
fn destination_less(route: &pb::FlowSpecRouteEntry, family: i32) -> Result<Option<FlowSpecNlri>> {
    if !matches!(family, 3 | 4)
        || route
            .components
            .iter()
            .any(|component| component.r#type == 1)
        || !route.rd.is_empty()
    {
        return Ok(None);
    }
    decode_components(&route.components, family, None).map(Some)
}

fn foreign_match(route: pb::FlowSpecRouteEntry, family: i32) -> Result<FlowSpecNlri> {
    if let Some(nlri) = destination_less(&route, family)? {
        return Ok(nlri);
    }
    let mut extended_communities = vec![0x8006_u64 << 48];
    extended_communities.extend(raw_scope_targets(&route.extended_communities));
    let route = pb::FlowSpecRouteEntry {
        components: route.components,
        peer_address: route.peer_address,
        afi_safi: route.afi_safi,
        rd: route.rd,
        route_targets: route.route_targets,
        extended_communities,
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
        return Err(invalid("guarded rule requires one redirect action"));
    };
    let (target, redirect_route_target, mut extended, ipv6_extended) = match &action.action {
        Some(pb::flow_spec_action::Action::RedirectIp(target)) => {
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
            (Some(address), None, extended, ipv6_extended)
        }
        Some(pb::flow_spec_action::Action::Redirect(target)) => {
            let canonical = crate::domain::canonical_route_target(&target.route_target)
                .map_err(|error| invalid(&error.to_string()))?;
            let mut bytes = crate::domain::route_target_bytes(&canonical)
                .map_err(|error| invalid(&error.to_string()))?
                .to_be_bytes();
            bytes[0] |= 0x80;
            bytes[1] = 8;
            (
                None,
                Some(canonical),
                vec![u64::from_be_bytes(bytes)],
                vec![],
            )
        }
        _ => {
            return Err(invalid(
                "guarded rule requires a target-IP or VRF redirect action",
            ));
        }
    };
    let scope_targets = scope_rt_bytes(&route)?;
    extended.extend(&scope_targets);
    if route.extended_communities != extended || route.ipv6_extended_communities != ipv6_extended {
        return Err(invalid("inconsistent redirect action bytes"));
    }
    // Only a return leg carries a community: exactly one, under a scrubber
    // owner. The controller then requires a durable row's exact community and
    // revision before treating it as prefixd intent (ADR 030 R2).
    let export_community = match route.communities.as_slice() {
        [] => None,
        [value] if owner.starts_with(OWNER_NAMESPACE) => {
            Some(format!("{}:{}", value >> 16, value & 0xffff))
        }
        _ => return Err(invalid("unsupported guarded communities")),
    };
    if let Some(export_community) = export_community {
        if !matches!(family, 3 | 4)
            || route.peer_address != "0.0.0.0"
            || route.afi_safi != family
            || !route.rd.is_empty()
            || !scope_targets.is_empty()
            || !route.as_path.is_empty()
        {
            return Err(invalid("unsupported return-leg attributes"));
        }
        let rule = GuardedRule {
            nlri: decode_components(&route.components, family, None)?,
            route_targets: vec![],
            target,
            redirect_route_target,
            owner,
            revision,
            export_community: Some(export_community),
        };
        rule.validate()?;
        return Ok(GuardedObservation {
            rule,
            generation,
            remaining_ms,
        });
    }
    // Validate every match and remaining route attribute through the strict
    // ordinary decoder, after accounting for the complete guarded action above.
    route.injection_owner.clear();
    route.admission_revision = None;
    route.ipv6_extended_communities.clear();
    route.extended_communities = vec![0x8006_u64 << 48];
    route.extended_communities.extend(scope_targets);
    route.actions = vec![pb::FlowSpecAction {
        action: Some(pb::flow_spec_action::Action::TrafficRate(
            pb::FlowSpecTrafficRate { rate: 0.0 },
        )),
    }];
    let decoded = decode(route, family)?;
    let rule = GuardedRule {
        nlri: decoded.nlri,
        route_targets: decoded.route_targets,
        target,
        redirect_route_target,
        owner,
        revision,
        export_community: None,
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
        families: &[i32],
        call: impl Future<Output = std::result::Result<tonic::Response<T>, tonic::Status>>,
    ) -> Result<T> {
        let deadline = tokio::time::Instant::now() + GUARDED_RPC_DEADLINE;
        let deadline_error = || {
            invalid(&format!(
                "{operation} outcome unconfirmed after deadline; resolve by read-back"
            ))
        };
        let attempt = async {
            for family in families {
                self.probe_vpn_family(*family).await?;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(deadline_error());
            }
            call.await
                .map(tonic::Response::into_inner)
                .map_err(|status| guarded_status_error(operation, &status))
        };
        match tokio::time::timeout_at(deadline, attempt).await {
            Ok(result) => result,
            Err(_) => Err(deadline_error()),
        }
    }

    async fn raw_guarded_inventory(&self) -> Result<GuardedInventory> {
        let mut entries = vec![];
        let mut other_matches = vec![];
        let mut keys = std::collections::HashSet::new();
        for family in self.inventory_families() {
            let mut client = pb::rib_service_client::RibServiceClient::new(self.channel.clone());
            let response = self
                .guarded_call(
                    "ListFlowSpecRoutes",
                    &[],
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
                    let nlri = foreign_match(route, family)?;
                    if !keys.insert((family, nlri.compute_hash())) {
                        return Err(invalid("repeated local key"));
                    }
                    other_matches.push(nlri);
                } else if route.injection_owner.starts_with("guarded:")
                    || route.admission_revision.is_some()
                {
                    let observation = decode_guarded(route, family)?;
                    if !keys.insert((family, observation.rule.nlri.compute_hash())) {
                        return Err(invalid("repeated guarded key"));
                    }
                    entries.push(observation);
                } else {
                    let nlri = match destination_less(&route, family)? {
                        Some(nlri) => nlri,
                        None => decode(route, family)?.nlri,
                    };
                    if !keys.insert((family, nlri.compute_hash())) {
                        return Err(invalid("repeated local key"));
                    }
                    other_matches.push(nlri);
                }
            }
        }
        Ok(GuardedInventory {
            entries,
            other_matches,
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
        let families: Vec<_> = self
            .inventory_families()
            .into_iter()
            .filter(|family| *family >= 13)
            .collect();
        let mut client =
            pb::injection_service_client::InjectionServiceClient::new(self.channel.clone());
        let response = self
            .guarded_call(
                "IssueMutationWindow",
                &families,
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
                rule.nlri
                    .scope
                    .as_ref()
                    .map(|scope| scope.family.afi_safi())
                    .as_slice(),
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
        let families: Vec<_> = self
            .inventory_families()
            .into_iter()
            .filter(|family| *family >= 13)
            .collect();
        let mut client =
            pb::injection_service_client::InjectionServiceClient::new(self.channel.clone());
        let response = self
            .guarded_call(
                "RenewGuardedLease",
                &families,
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
                rule.nlri
                    .scope
                    .as_ref()
                    .map(|scope| scope.family.afi_safi())
                    .as_slice(),
                client.delete_guarded_flow_spec(self.request(pb::DeleteGuardedFlowSpecRequest {
                    afi_safi: payload.afi_safi,
                    components: payload.components,
                    rd: payload.rd,
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
