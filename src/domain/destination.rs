use ipnet::IpNet;

/// A malformed manual FlowSpec destination must never widen into another network.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DestinationError {
    #[error("destination must be an IPv4 or IPv6 address or CIDR")]
    Invalid,
    #[error("destination has nonzero host bits; use {network} to explicitly target that network")]
    HostBits { network: IpNet },
}

/// Whether a valid destination string denotes a non-host prefix. Invalid
/// values return false; callers parse and reject them separately.
pub fn is_prefix_destination(value: &str) -> bool {
    parse_flowspec_destination(value)
        .is_ok_and(|destination| destination.prefix_len() != destination.max_prefix_len())
}

/// The one stored and compared spelling of an event destination (RFC 5952
/// text): IPv6 lowercase and zero-compressed, an IPv4-mapped IPv6 host as its
/// IPv4 address, a full-length prefix as its bare address and any other prefix
/// as its canonical CIDR. Every key on the victim string depends on it.
pub fn canonical_destination(value: &str) -> Result<String, DestinationError> {
    let destination = parse_flowspec_destination(value)?;
    Ok(
        if destination.prefix_len() == destination.max_prefix_len() {
            destination.addr().to_canonical().to_string()
        } else {
            destination.to_string()
        },
    )
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
    fn canonical_destination_has_one_spelling_per_destination() {
        for (input, expected) in [
            ("2001:0db8:0113::0010", "2001:db8:113::10"),
            (
                "2001:0DB8:0113:0000:0000:0000:0000:0010",
                "2001:db8:113::10",
            ),
            ("2001:DB8:113::10/128", "2001:db8:113::10"),
            ("::ffff:203.0.113.10", "203.0.113.10"),
            ("::FFFF:CB00:710A", "203.0.113.10"),
            ("203.0.113.10/32", "203.0.113.10"),
            ("203.0.113.10", "203.0.113.10"),
            ("2001:0DB8:0001::/48", "2001:db8:1::/48"),
            ("203.0.112.0/22", "203.0.112.0/22"),
        ] {
            assert_eq!(canonical_destination(input).unwrap(), expected, "{input}");
        }
        for invalid in ["", "203.0.113.010", "203.0.113.1/24", "example.com"] {
            assert!(canonical_destination(invalid).is_err(), "{invalid}");
        }
    }

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
