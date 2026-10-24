use anyhow::Result;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inventory {
    pub customers: Vec<Customer>,
    #[serde(skip)]
    ip_index_v4: HashMap<Ipv4Addr, (String, Option<String>, Option<String>)>,
    #[serde(skip)]
    ip_index_v6: HashMap<Ipv6Addr, (String, Option<String>, Option<String>)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Customer {
    pub customer_id: String,
    pub name: String,
    pub prefixes: Vec<String>,
    #[serde(default = "default_policy_profile")]
    pub policy_profile: PolicyProfile,
    #[serde(default)]
    pub services: Vec<Service>,
}

fn default_policy_profile() -> PolicyProfile {
    PolicyProfile::Normal
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyProfile {
    Strict,
    Normal,
    Relaxed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub service_id: String,
    pub name: String,
    #[serde(default)]
    pub assets: Vec<Asset>,
    #[serde(default)]
    pub allowed_ports: AllowedPorts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub ip: String,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub interface: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AllowedPorts {
    #[serde(default)]
    pub udp: Vec<u16>,
    #[serde(default)]
    pub tcp: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct IpContext {
    pub customer_id: String,
    pub customer_name: String,
    pub policy_profile: PolicyProfile,
    pub service_id: Option<String>,
    pub service_name: Option<String>,
    pub interface: Option<String>,
    pub allowed_ports: AllowedPorts,
}

impl Inventory {
    pub fn new(customers: Vec<Customer>) -> Self {
        let mut inv = Self {
            customers,
            ip_index_v4: HashMap::new(),
            ip_index_v6: HashMap::new(),
        };
        inv.build_index();
        inv
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let mut inventory: Inventory = crate::config::parse_yaml(&content)?;
        inventory.validate()?;
        inventory.build_index();
        Ok(inventory)
    }

    /// Reject prefixes and asset addresses that lookups would otherwise skip.
    /// Whole-prefix ownership needs every customer's networks to judge overlap.
    pub fn validate(&self) -> crate::error::Result<()> {
        for customer in &self.customers {
            for prefix in &customer.prefixes {
                parse_prefix(&customer.customer_id, prefix)?;
            }
            for asset in customer.services.iter().flat_map(|service| &service.assets) {
                parse_asset(&customer.customer_id, &asset.ip)?;
            }
        }
        Ok(())
    }

    fn build_index(&mut self) {
        self.ip_index_v4.clear();
        self.ip_index_v6.clear();
        for customer in &self.customers {
            for service in &customer.services {
                for asset in &service.assets {
                    if let Ok(ip) = Ipv4Addr::from_str(&asset.ip) {
                        self.ip_index_v4.insert(
                            ip,
                            (
                                customer.customer_id.clone(),
                                Some(service.service_id.clone()),
                                asset.interface.clone(),
                            ),
                        );
                    } else if let Ok(ip) = Ipv6Addr::from_str(&asset.ip) {
                        self.ip_index_v6.insert(
                            ip,
                            (
                                customer.customer_id.clone(),
                                Some(service.service_id.clone()),
                                asset.interface.clone(),
                            ),
                        );
                    }
                }
            }
        }
    }

    pub fn lookup_ip(&self, ip_str: &str) -> Option<IpContext> {
        // Try to parse as either IPv4 or IPv6
        let ip: IpAddr = ip_str.parse().ok()?;

        match ip {
            IpAddr::V4(ipv4) => self.lookup_ipv4(ipv4),
            IpAddr::V6(ipv6) => self.lookup_ipv6(ipv6),
        }
    }

    /// Attribute a whole network to one customer, never to its first asset.
    /// One configured prefix must contain it; another customer's overlapping
    /// prefix or enclosed asset makes ownership ambiguous. Service data belongs
    /// to individual assets and is deliberately absent from this context.
    ///
    /// An unparseable entry anywhere is an error, never a lost or ambiguous
    /// owner: callers must not withdraw or admit on a partial view.
    pub fn lookup_prefix(&self, prefix: &IpNet) -> crate::error::Result<Option<IpContext>> {
        self.validate()?;
        let mut owner = None;
        for customer in &self.customers {
            for configured in &customer.prefixes {
                if parse_prefix(&customer.customer_id, configured)?.contains(prefix) {
                    if owner.is_some_and(|id| id != customer.customer_id) {
                        return Ok(None);
                    }
                    owner = Some(customer.customer_id.as_str());
                }
            }
        }
        let Some(owner) = owner else {
            return Ok(None);
        };
        for customer in &self.customers {
            if customer.customer_id == owner {
                continue;
            }
            for configured in &customer.prefixes {
                let configured = parse_prefix(&customer.customer_id, configured)?;
                if prefix.contains(&configured) || configured.contains(prefix) {
                    return Ok(None);
                }
            }
            for asset in customer.services.iter().flat_map(|service| &service.assets) {
                if prefix.contains(&parse_asset(&customer.customer_id, &asset.ip)?) {
                    return Ok(None);
                }
            }
        }
        Ok(self.build_context(owner, None, None))
    }

    fn lookup_ipv4(&self, ip: Ipv4Addr) -> Option<IpContext> {
        // Check direct asset match first
        if let Some((customer_id, service_id, interface)) = self.ip_index_v4.get(&ip) {
            return self.build_context(customer_id, service_id.as_deref(), interface.clone());
        }

        // Fall back to prefix match
        for customer in &self.customers {
            for prefix_str in &customer.prefixes {
                if let Ok(prefix) = Ipv4Net::from_str(prefix_str) {
                    if prefix.contains(&ip) {
                        return self.build_context(&customer.customer_id, None, None);
                    }
                }
            }
        }

        None
    }

    fn lookup_ipv6(&self, ip: Ipv6Addr) -> Option<IpContext> {
        // Check direct asset match first
        if let Some((customer_id, service_id, interface)) = self.ip_index_v6.get(&ip) {
            return self.build_context(customer_id, service_id.as_deref(), interface.clone());
        }

        // Fall back to prefix match
        for customer in &self.customers {
            for prefix_str in &customer.prefixes {
                if let Ok(prefix) = Ipv6Net::from_str(prefix_str) {
                    if prefix.contains(&ip) {
                        return self.build_context(&customer.customer_id, None, None);
                    }
                }
            }
        }

        None
    }

    fn build_context(
        &self,
        customer_id: &str,
        service_id: Option<&str>,
        interface: Option<String>,
    ) -> Option<IpContext> {
        let customer = self
            .customers
            .iter()
            .find(|c| c.customer_id == customer_id)?;

        let (svc_id, svc_name, allowed_ports) = if let Some(sid) = service_id {
            let service = customer.services.iter().find(|s| s.service_id == sid);
            if let Some(svc) = service {
                (
                    Some(svc.service_id.clone()),
                    Some(svc.name.clone()),
                    svc.allowed_ports.clone(),
                )
            } else {
                (None, None, AllowedPorts::default())
            }
        } else {
            (None, None, AllowedPorts::default())
        };

        Some(IpContext {
            customer_id: customer.customer_id.clone(),
            customer_name: customer.name.clone(),
            policy_profile: customer.policy_profile,
            service_id: svc_id,
            service_name: svc_name,
            interface,
            allowed_ports,
        })
    }

    pub fn is_owned(&self, ip_str: &str) -> bool {
        self.lookup_ip(ip_str).is_some()
    }
}

fn parse_prefix(customer_id: &str, prefix: &str) -> crate::error::Result<IpNet> {
    prefix.parse().map_err(|_| {
        crate::error::PrefixdError::Config(format!(
            "inventory customer {customer_id}: invalid prefix {prefix:?}"
        ))
    })
}

fn parse_asset(customer_id: &str, ip: &str) -> crate::error::Result<IpAddr> {
    ip.parse().map_err(|_| {
        crate::error::PrefixdError::Config(format!(
            "inventory customer {customer_id}: invalid asset IP {ip:?}"
        ))
    })
}

#[cfg(test)]
mod prefix_tests {
    use super::*;

    fn customer(id: &str, prefixes: &[&str]) -> Customer {
        Customer {
            customer_id: id.into(),
            name: id.into(),
            prefixes: prefixes.iter().map(|p| (*p).into()).collect(),
            policy_profile: PolicyProfile::Normal,
            services: vec![],
        }
    }

    #[test]
    fn whole_prefix_needs_one_containing_owner_and_no_conflicting_prefix_or_asset() {
        let target: IpNet = "203.0.112.0/22".parse().unwrap();
        let owner = customer("owner", &["203.0.112.0/22", "2001:db8::/32"]);
        let inv = Inventory::new(vec![owner.clone()]);
        let context = inv.lookup_prefix(&target).unwrap().unwrap();
        assert_eq!(context.customer_id, "owner");
        assert!(context.service_id.is_none());
        assert!(context.interface.is_none());
        assert!(context.allowed_ports.udp.is_empty());
        assert!(
            inv.lookup_prefix(&"2001:db8:1::/48".parse().unwrap())
                .unwrap()
                .is_some()
        );
        for competing in [
            customer("other", &["203.0.115.0/24"]),
            customer("other", &["203.0.0.0/16"]),
        ] {
            assert!(
                Inventory::new(vec![owner.clone(), competing])
                    .lookup_prefix(&target)
                    .unwrap()
                    .is_none()
            );
        }
        let mut asset_owner = customer("other", &[]);
        asset_owner.services.push(Service {
            service_id: "svc".into(),
            name: "svc".into(),
            assets: vec![Asset {
                ip: "203.0.115.254".into(),
                role: None,
                interface: None,
            }],
            allowed_ports: AllowedPorts::default(),
        });
        assert!(
            Inventory::new(vec![owner, asset_owner])
                .lookup_prefix(&target)
                .unwrap()
                .is_none()
        );
        let partial = customer("owner", &["203.0.112.0/23", "203.0.114.0/23"]);
        assert!(
            Inventory::new(vec![partial])
                .lookup_prefix(&target)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn invalid_prefix_or_asset_fails_load_and_lookup() {
        let owner = customer("owner", &["203.0.112.0/22"]);
        let mut hostname_asset = customer("other", &[]);
        hostname_asset.services.push(Service {
            service_id: "svc".into(),
            name: "svc".into(),
            assets: vec![Asset {
                ip: "web.example.net".into(),
                role: None,
                interface: None,
            }],
            allowed_ports: AllowedPorts::default(),
        });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inventory.yaml");
        for (other, bad) in [
            (customer("other", &["198.51.100.0/33"]), "198.51.100.0/33"),
            (hostname_asset, "web.example.net"),
        ] {
            let inv = Inventory::new(vec![owner.clone(), other]);
            let error = inv
                .lookup_prefix(&"203.0.112.0/22".parse().unwrap())
                .unwrap_err();
            assert!(error.to_string().contains(bad), "{error}");
            std::fs::write(&path, serde_json::to_string(&inv).unwrap()).unwrap();
            let error = Inventory::load(&path).unwrap_err();
            assert!(error.to_string().contains(bad), "{error}");
        }
    }
}
