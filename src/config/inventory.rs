use anyhow::Result;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inventory {
    pub customers: Vec<Customer>,
    #[serde(skip)]
    ip_index: HashMap<Ipv4Addr, (String, Option<String>)>,
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

fn default_policy_profile() -> PolicyProfile { PolicyProfile::Normal }

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
    pub allowed_ports: AllowedPorts,
}

impl Inventory {
    pub fn new(customers: Vec<Customer>) -> Self {
        let mut inv = Self {
            customers,
            ip_index: HashMap::new(),
        };
        inv.build_index();
        inv
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let mut inventory: Inventory = serde_yaml::from_str(&content)?;
        inventory.build_index();
        Ok(inventory)
    }

    fn build_index(&mut self) {
        self.ip_index.clear();
        for customer in &self.customers {
            for service in &customer.services {
                for asset in &service.assets {
                    if let Ok(ip) = Ipv4Addr::from_str(&asset.ip) {
                        self.ip_index.insert(
                            ip,
                            (customer.customer_id.clone(), Some(service.service_id.clone())),
                        );
                    }
                }
            }
        }
    }

    pub fn lookup_ip(&self, ip_str: &str) -> Option<IpContext> {
        let ip = Ipv4Addr::from_str(ip_str).ok()?;

        // Check direct asset match first
        if let Some((customer_id, service_id)) = self.ip_index.get(&ip) {
            return self.build_context(customer_id, service_id.as_deref());
        }

        // Fall back to prefix match
        for customer in &self.customers {
            for prefix_str in &customer.prefixes {
                if let Ok(prefix) = Ipv4Net::from_str(prefix_str) {
                    if prefix.contains(&ip) {
                        return self.build_context(&customer.customer_id, None);
                    }
                }
            }
        }

        None
    }

    fn build_context(&self, customer_id: &str, service_id: Option<&str>) -> Option<IpContext> {
        let customer = self.customers.iter().find(|c| c.customer_id == customer_id)?;

        let (svc_id, svc_name, allowed_ports) = if let Some(sid) = service_id {
            let service = customer.services.iter().find(|s| s.service_id == sid);
            if let Some(svc) = service {
                (Some(svc.service_id.clone()), Some(svc.name.clone()), svc.allowed_ports.clone())
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
            allowed_ports,
        })
    }

    pub fn is_owned(&self, ip_str: &str) -> bool {
        self.lookup_ip(ip_str).is_some()
    }
}
