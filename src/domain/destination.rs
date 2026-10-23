use ipnet::IpNet;

/// A malformed manual FlowSpec destination must never widen into another network.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DestinationError {
    #[error("destination must be an IPv4 or IPv6 address or CIDR")]
    Invalid,
    #[error("destination has nonzero host bits; use {network} to explicitly target that network")]
    HostBits { network: IpNet },
}

/// Parse a literal address or an exact network, rejecting implicit widening.
/// Admission still needs prefix-length, whole-prefix ownership and safelist checks.
pub fn parse_flowspec_destination(value: &str) -> Result<IpNet, DestinationError> {
    let prefix = if value.contains('/') {
        value
            .parse::<IpNet>()
            .map_err(|_| DestinationError::Invalid)?
    } else {
        IpNet::from(
            value
                .parse::<std::net::IpAddr>()
                .map_err(|_| DestinationError::Invalid)?,
        )
    };
    if prefix.addr() != prefix.network() {
        return Err(DestinationError::HostBits {
            network: prefix.trunc(),
        });
    }
    Ok(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_is_exact_and_canonical_in_both_families() {
        for (input, expected) in [
            ("203.0.113.10", "203.0.113.10/32"),
            ("203.0.112.0/22", "203.0.112.0/22"),
            ("2001:0DB8:0001::/48", "2001:db8:1::/48"),
            ("2001:0DB8::1", "2001:db8::1/128"),
            ("::/0", "::/0"),
        ] {
            assert_eq!(
                parse_flowspec_destination(input).unwrap().to_string(),
                expected
            );
        }
        for (input, network) in [
            ("203.0.113.1/22", "203.0.112.0/22"),
            ("2001:db8:1::1/48", "2001:db8:1::/48"),
        ] {
            assert_eq!(
                parse_flowspec_destination(input),
                Err(DestinationError::HostBits {
                    network: network.parse().unwrap()
                })
            );
        }
        for invalid in [
            "",
            "203.0.113.1/33",
            "2001:db8::/129",
            "203.0.113.1/",
            "example.com",
            "203.0.113.1/24/32",
        ] {
            assert_eq!(
                parse_flowspec_destination(invalid),
                Err(DestinationError::Invalid)
            );
        }
    }
}
