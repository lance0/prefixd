use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::domain::AttackVector;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbooks {
    pub playbooks: Vec<Playbook>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    pub name: String,
    #[serde(rename = "match")]
    pub match_criteria: PlaybookMatch,
    pub steps: Vec<PlaybookStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookMatch {
    pub vector: AttackVector,
    #[serde(default)]
    pub require_top_ports: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookStep {
    pub action: PlaybookAction,
    #[serde(default)]
    pub rate_bps: Option<u64>,
    pub ttl_seconds: u32,
    #[serde(default)]
    pub require_confidence_at_least: Option<f64>,
    #[serde(default)]
    pub require_persistence_seconds: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlaybookAction {
    Police,
    Discard,
}

impl Playbooks {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let playbooks: Playbooks = serde_yaml::from_str(&content)?;
        Ok(playbooks)
    }

    pub fn find_playbook(&self, vector: AttackVector, has_ports: bool) -> Option<&Playbook> {
        self.playbooks.iter().find(|p| {
            p.match_criteria.vector == vector && (!p.match_criteria.require_top_ports || has_ports)
        })
    }

    pub fn get_initial_step<'a>(&self, playbook: &'a Playbook) -> Option<&'a PlaybookStep> {
        playbook.steps.first()
    }

    pub fn get_escalation_step<'a>(
        &self,
        playbook: &'a Playbook,
        confidence: Option<f64>,
        persistence_seconds: u32,
    ) -> Option<&'a PlaybookStep> {
        playbook.steps.iter().skip(1).find(move |step| {
            let confidence_ok = step
                .require_confidence_at_least
                .map(|min| confidence.unwrap_or(0.0) >= min)
                .unwrap_or(true);
            let persistence_ok = step
                .require_persistence_seconds
                .map(|min| persistence_seconds >= min)
                .unwrap_or(true);
            confidence_ok && persistence_ok
        })
    }
}
