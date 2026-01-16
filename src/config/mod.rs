mod settings;
mod inventory;
mod playbooks;

pub use settings::*;
pub use inventory::*;
pub use playbooks::*;

use anyhow::Result;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub settings: Settings,
    pub inventory: Inventory,
    pub playbooks: Playbooks,
}

impl AppConfig {
    pub fn load(config_dir: &Path) -> Result<Self> {
        let settings = Settings::load(config_dir.join("prefixd.yaml"))?;
        let inventory = Inventory::load(config_dir.join("inventory.yaml"))?;
        let playbooks = Playbooks::load(config_dir.join("playbooks.yaml"))?;

        Ok(Self {
            settings,
            inventory,
            playbooks,
        })
    }
}
