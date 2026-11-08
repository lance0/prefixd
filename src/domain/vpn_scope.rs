use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum VpnFlowSpecFamily {
    Ipv4,
    Ipv6,
}

impl VpnFlowSpecFamily {
    pub fn afi_safi(self) -> i32 {
        match self {
            Self::Ipv4 => 13,
            Self::Ipv6 => 14,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VpnScopeError {
    #[error("RD must be ASN16:u32, IPv4:u16, ASN32:u16 or 0x plus 16 hexadecimal digits")]
    InvalidRd,
    #[error("originated RD must have type 0, 1 or 2")]
    UnsupportedRdType,
    #[error("route target must be ASN16:u32, IPv4:u16 or ASN32:u16 (including asdot+)")]
    InvalidRouteTarget,
    #[error("VPN scope requires at least one route target")]
    MissingRouteTargets,
    #[error("VPN scope contains duplicate route targets")]
    DuplicateRouteTarget,
    #[error("VPN scope name must be nonempty and cannot be global")]
    InvalidName,
}

/// Canonical text preserves the complete RD encoding, including small-ASN type 2.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(try_from = "VpnIdentityInput")]
pub struct VpnFlowSpecIdentity {
    pub family: VpnFlowSpecFamily,
    rd: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VpnIdentityInput {
    family: VpnFlowSpecFamily,
    rd: String,
}

impl TryFrom<VpnIdentityInput> for VpnFlowSpecIdentity {
    type Error = VpnScopeError;

    fn try_from(value: VpnIdentityInput) -> Result<Self, Self::Error> {
        Self::new(value.family, &value.rd)
    }
}

impl VpnFlowSpecIdentity {
    pub fn new(family: VpnFlowSpecFamily, rd: &str) -> Result<Self, VpnScopeError> {
        Ok(Self {
            family,
            rd: canonical_route_distinguisher(rd)?,
        })
    }

    pub fn rd(&self) -> &str {
        &self.rd
    }

    pub fn rd_bytes(&self) -> [u8; 8] {
        // Construction and deserialization both canonicalize the private RD.
        route_distinguisher_bytes(&self.rd).expect("validated VPN route distinguisher")
    }
}

/// Immutable resolved scope; the configuration name is display context, not identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(try_from = "VpnScopeInput")]
pub struct VpnScopeSnapshot {
    pub name: String,
    pub identity: VpnFlowSpecIdentity,
    pub route_targets: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VpnScopeInput {
    name: String,
    identity: VpnFlowSpecIdentity,
    route_targets: Vec<String>,
}

impl TryFrom<VpnScopeInput> for VpnScopeSnapshot {
    type Error = VpnScopeError;

    fn try_from(value: VpnScopeInput) -> Result<Self, Self::Error> {
        Self::new(value.name, value.identity, &value.route_targets)
    }
}

impl VpnScopeSnapshot {
    pub fn new(
        name: impl Into<String>,
        identity: VpnFlowSpecIdentity,
        route_targets: &[String],
    ) -> Result<Self, VpnScopeError> {
        let name = name.into();
        if name.trim().is_empty() || name == "global" {
            return Err(VpnScopeError::InvalidName);
        }
        Ok(Self {
            name,
            identity,
            route_targets: canonical_route_targets(route_targets)?,
        })
    }

    pub fn validate(&self) -> Result<(), VpnScopeError> {
        Self::new(&self.name, self.identity.clone(), &self.route_targets).map(|_| ())
    }
}

pub fn route_distinguisher_bytes(value: &str) -> Result<[u8; 8], VpnScopeError> {
    let bytes = if let Some(raw) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        if raw.len() != 16 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(VpnScopeError::InvalidRd);
        }
        u64::from_str_radix(raw, 16)
            .map_err(|_| VpnScopeError::InvalidRd)?
            .to_be_bytes()
    } else {
        parse_administrator(value, false).ok_or(VpnScopeError::InvalidRd)?
    };
    if u16::from_be_bytes([bytes[0], bytes[1]]) > 2 {
        return Err(VpnScopeError::UnsupportedRdType);
    }
    Ok(bytes)
}

pub fn canonical_route_distinguisher(value: &str) -> Result<String, VpnScopeError> {
    let bytes = route_distinguisher_bytes(value)?;
    Ok(match bytes[1] {
        0 => format!(
            "{}:{}",
            u16::from_be_bytes([bytes[2], bytes[3]]),
            u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])
        ),
        1 => format!(
            "{}:{}",
            Ipv4Addr::new(bytes[2], bytes[3], bytes[4], bytes[5]),
            u16::from_be_bytes([bytes[6], bytes[7]])
        ),
        _ if bytes[2..4] == [0, 0] => format!("0x{:016x}", u64::from_be_bytes(bytes)),
        _ => format!(
            "{}:{}",
            u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
            u16::from_be_bytes([bytes[6], bytes[7]])
        ),
    })
}

pub fn route_target_bytes(value: &str) -> Result<u64, VpnScopeError> {
    let mut bytes = parse_administrator(value, true).ok_or(VpnScopeError::InvalidRouteTarget)?;
    bytes[0] = bytes[1];
    bytes[1] = 2;
    Ok(u64::from_be_bytes(bytes))
}

pub fn canonical_route_target(value: &str) -> Result<String, VpnScopeError> {
    let bytes = route_target_bytes(value)?.to_be_bytes();
    Ok(match bytes[0] {
        0 => format!(
            "{}:{}",
            u16::from_be_bytes([bytes[2], bytes[3]]),
            u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])
        ),
        1 => format!(
            "{}:{}",
            Ipv4Addr::new(bytes[2], bytes[3], bytes[4], bytes[5]),
            u16::from_be_bytes([bytes[6], bytes[7]])
        ),
        _ => format!(
            "{}.{}:{}",
            u16::from_be_bytes([bytes[2], bytes[3]]),
            u16::from_be_bytes([bytes[4], bytes[5]]),
            u16::from_be_bytes([bytes[6], bytes[7]])
        ),
    })
}

pub fn canonical_route_targets(values: &[String]) -> Result<Vec<String>, VpnScopeError> {
    if values.is_empty() {
        return Err(VpnScopeError::MissingRouteTargets);
    }
    let mut targets = values
        .iter()
        .map(|value| Ok((route_target_bytes(value)?, canonical_route_target(value)?)))
        .collect::<Result<Vec<_>, VpnScopeError>>()?;
    targets.sort_unstable_by_key(|(bytes, _)| *bytes);
    if targets.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(VpnScopeError::DuplicateRouteTarget);
    }
    Ok(targets.into_iter().map(|(_, text)| text).collect())
}

fn parse_administrator(value: &str, allow_asdot: bool) -> Option<[u8; 8]> {
    let (admin, assigned) = value.split_once(':')?;
    let assigned: u32 = assigned.parse().ok()?;
    if let Ok(ip) = admin.parse::<Ipv4Addr>() {
        let [a, b, c, d] = ip.octets();
        let [e, f] = u16::try_from(assigned).ok()?.to_be_bytes();
        return Some([0, 1, a, b, c, d, e, f]);
    }
    let asdot = allow_asdot.then(|| admin.split_once('.')).flatten();
    let asn: u32 = if let Some((high, low)) = asdot {
        (u32::from(high.parse::<u16>().ok()?) << 16) | u32::from(low.parse::<u16>().ok()?)
    } else {
        admin.parse().ok()?
    };
    if let Ok(asn) = u16::try_from(asn)
        && asdot.is_none()
    {
        let [a, b] = asn.to_be_bytes();
        let [c, d, e, f] = assigned.to_be_bytes();
        Some([0, 0, a, b, c, d, e, f])
    } else {
        let [a, b, c, d] = asn.to_be_bytes();
        let [e, f] = u16::try_from(assigned).ok()?.to_be_bytes();
        Some([0, 2, a, b, c, d, e, f])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_rd_keeps_wire_identity_and_serde_cannot_bypass_validation() {
        for (input, canonical, raw) in [
            ("065000:000100", "65000:100", 0x0000_fde8_0000_0064u64),
            ("0X0000FDE800000064", "65000:100", 0x0000_fde8_0000_0064),
            ("192.0.2.1:100", "192.0.2.1:100", 0x0001_c000_0201_0064),
            ("4200000000:100", "4200000000:100", 0x0002_fa56_ea00_0064),
            (
                "0X00020000FDE80064",
                "0x00020000fde80064",
                0x0002_0000_fde8_0064,
            ),
        ] {
            let identity = VpnFlowSpecIdentity::new(VpnFlowSpecFamily::Ipv4, input).unwrap();
            assert_eq!(identity.rd(), canonical);
            assert_eq!(u64::from_be_bytes(identity.rd_bytes()), raw);
            let decoded: VpnFlowSpecIdentity = serde_json::from_value(serde_json::json!({
                "family": "ipv4", "rd": input,
            }))
            .unwrap();
            assert_eq!(decoded, identity);
        }
        assert_ne!(
            VpnFlowSpecIdentity::new(VpnFlowSpecFamily::Ipv4, "65000:100").unwrap(),
            VpnFlowSpecIdentity::new(VpnFlowSpecFamily::Ipv4, "0x00020000fde80064").unwrap(),
        );
        assert_eq!(
            canonical_route_distinguisher("65535:4294967295").unwrap(),
            "65535:4294967295"
        );
        assert_eq!(
            canonical_route_distinguisher("4294967295:65535").unwrap(),
            "4294967295:65535"
        );
        for invalid in [
            "",
            "0x",
            "0x0003000000000001",
            "0x+0020000fde80064",
            "65536:65536",
            "192.0.2.1:65536",
            "1.2:3",
            "4294967296:1",
        ] {
            assert!(canonical_route_distinguisher(invalid).is_err(), "{invalid}");
            assert!(
                serde_json::from_value::<VpnFlowSpecIdentity>(serde_json::json!({
                    "family": "ipv4", "rd": invalid,
                }))
                .is_err()
            );
        }
    }

    #[test]
    fn targets_preserve_as4_and_reject_encoded_duplicates() {
        for (input, canonical, raw) in [
            ("65000:777", "65000:777", 0x0002_fde8_0000_0309u64),
            ("192.0.2.1:9", "192.0.2.1:9", 0x0102_c000_0201_0009),
            ("65536:9", "1.0:9", 0x0202_0001_0000_0009),
            ("0.65000:9", "0.65000:9", 0x0202_0000_fde8_0009),
        ] {
            assert_eq!(canonical_route_target(input).unwrap(), canonical);
            assert_eq!(route_target_bytes(input).unwrap(), raw);
        }
        assert_ne!(
            route_target_bytes("65000:9").unwrap(),
            route_target_bytes("0.65000:9").unwrap()
        );
        assert_eq!(
            canonical_route_targets(&["1.0:9".into(), "65536:9".into()]),
            Err(VpnScopeError::DuplicateRouteTarget)
        );
        assert_eq!(
            canonical_route_targets(&[]),
            Err(VpnScopeError::MissingRouteTargets)
        );
        for invalid in [
            "",
            "65000",
            "192.0.2.1:65536",
            "65536:65536",
            "65536.0:9",
            "0.65536:9",
            "1.2.3:9",
            "4294967296:1",
            "0x0002fde800000309",
        ] {
            assert!(canonical_route_target(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn scope_round_trip_normalizes_targets_and_keeps_family_generic() {
        let scope: VpnScopeSnapshot = serde_json::from_value(serde_json::json!({
            "name": "TRANSIT", "identity": {"family": "ipv6", "rd": "65000:1"},
            "route_targets": ["1.0:9", "65000:777"],
        }))
        .unwrap();
        assert_eq!(scope.identity.family.afi_safi(), 14);
        assert_eq!(scope.route_targets, ["65000:777", "1.0:9"]);
        let restored: VpnScopeSnapshot =
            serde_json::from_value(serde_json::to_value(&scope).unwrap()).unwrap();
        assert_eq!(scope, restored);
        for name in ["", " ", "global"] {
            assert!(
                VpnScopeSnapshot::new(name, scope.identity.clone(), &scope.route_targets).is_err()
            );
        }
        let mut malformed = serde_json::to_value(scope).unwrap();
        malformed["route_targets"] = serde_json::json!(["1.0:9", "65536:9"]);
        assert!(serde_json::from_value::<VpnScopeSnapshot>(malformed).is_err());
    }
}
