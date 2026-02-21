use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

use crate::domain::AttackVector;

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Playbooks {
    pub playbooks: Vec<Playbook>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Playbook {
    pub name: String,
    #[serde(rename = "match")]
    pub match_criteria: PlaybookMatch,
    pub steps: Vec<PlaybookStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PlaybookMatch {
    pub vector: AttackVector,
    #[serde(default)]
    pub require_top_ports: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
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

    /// Validate all playbook rules, returning a list of errors (empty = valid).
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        let mut names = HashSet::new();

        if self.playbooks.is_empty() {
            errors.push("at least one playbook is required".to_string());
            return errors;
        }

        for (i, pb) in self.playbooks.iter().enumerate() {
            let ctx = format!("playbook[{}] ({:?})", i, pb.name);

            if pb.name.is_empty() {
                errors.push(format!("{}: name is required", ctx));
            } else if pb.name.len() > 128 {
                errors.push(format!("{}: name exceeds 128 characters", ctx));
            } else if !names.insert(&pb.name) {
                errors.push(format!("{}: duplicate name", ctx));
            }

            if pb.steps.is_empty() {
                errors.push(format!("{}: at least one step is required", ctx));
                continue;
            }

            // First step must not have escalation requirements
            if let Some(first) = pb.steps.first() {
                if first.require_confidence_at_least.is_some()
                    || first.require_persistence_seconds.is_some()
                {
                    errors.push(format!(
                        "{}: first step must not have escalation requirements",
                        ctx
                    ));
                }
            }

            for (j, step) in pb.steps.iter().enumerate() {
                let step_ctx = format!("{} step[{}]", ctx, j);

                if step.ttl_seconds == 0 || step.ttl_seconds > 86400 {
                    errors.push(format!(
                        "{}: ttl_seconds must be 1..=86400, got {}",
                        step_ctx, step.ttl_seconds
                    ));
                }

                if step.action == PlaybookAction::Police {
                    match step.rate_bps {
                        None | Some(0) => {
                            errors
                                .push(format!("{}: police action requires rate_bps > 0", step_ctx));
                        }
                        _ => {}
                    }
                }

                if let Some(conf) = step.require_confidence_at_least {
                    if !(0.0..=1.0).contains(&conf) {
                        errors.push(format!(
                            "{}: require_confidence_at_least must be 0.0..=1.0, got {}",
                            step_ctx, conf
                        ));
                    }
                }
            }
        }

        errors
    }

    /// Save playbooks to a YAML file, creating a .bak backup first.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();

        // Backup existing file
        if path.exists() {
            let bak = path.with_extension("yaml.bak");
            std::fs::copy(path, &bak)?;
        }

        let yaml = serde_yaml::to_string(self)?;
        std::fs::write(path, yaml)?;
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_playbook() -> Playbook {
        Playbook {
            name: "test_playbook".to_string(),
            match_criteria: PlaybookMatch {
                vector: AttackVector::UdpFlood,
                require_top_ports: false,
            },
            steps: vec![PlaybookStep {
                action: PlaybookAction::Police,
                rate_bps: Some(5_000_000),
                ttl_seconds: 120,
                require_confidence_at_least: None,
                require_persistence_seconds: None,
            }],
        }
    }

    #[test]
    fn test_validate_valid_playbooks() {
        let pb = Playbooks {
            playbooks: vec![valid_playbook()],
        };
        assert!(pb.validate().is_empty());
    }

    #[test]
    fn test_validate_empty_playbooks() {
        let pb = Playbooks { playbooks: vec![] };
        let errors = pb.validate();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("at least one playbook"));
    }

    #[test]
    fn test_validate_duplicate_names() {
        let mut p1 = valid_playbook();
        let mut p2 = valid_playbook();
        p1.name = "dup".to_string();
        p2.name = "dup".to_string();
        p2.match_criteria.vector = AttackVector::SynFlood;
        let pb = Playbooks {
            playbooks: vec![p1, p2],
        };
        let errors = pb.validate();
        assert!(errors.iter().any(|e| e.contains("duplicate name")));
    }

    #[test]
    fn test_validate_empty_steps() {
        let mut p = valid_playbook();
        p.steps.clear();
        let pb = Playbooks { playbooks: vec![p] };
        let errors = pb.validate();
        assert!(errors.iter().any(|e| e.contains("at least one step")));
    }

    #[test]
    fn test_validate_police_requires_rate() {
        let mut p = valid_playbook();
        p.steps[0].rate_bps = None;
        let pb = Playbooks { playbooks: vec![p] };
        let errors = pb.validate();
        assert!(errors.iter().any(|e| e.contains("rate_bps > 0")));
    }

    #[test]
    fn test_validate_ttl_bounds() {
        let mut p = valid_playbook();
        p.steps[0].ttl_seconds = 0;
        let pb = Playbooks { playbooks: vec![p] };
        let errors = pb.validate();
        assert!(errors.iter().any(|e| e.contains("ttl_seconds")));

        let mut p2 = valid_playbook();
        p2.steps[0].ttl_seconds = 86401;
        let pb2 = Playbooks {
            playbooks: vec![p2],
        };
        assert!(!pb2.validate().is_empty());
    }

    #[test]
    fn test_validate_confidence_bounds() {
        let mut p = valid_playbook();
        p.steps.push(PlaybookStep {
            action: PlaybookAction::Discard,
            rate_bps: None,
            ttl_seconds: 300,
            require_confidence_at_least: Some(1.5),
            require_persistence_seconds: None,
        });
        let pb = Playbooks { playbooks: vec![p] };
        let errors = pb.validate();
        assert!(errors.iter().any(|e| e.contains("confidence")));
    }

    #[test]
    fn test_validate_first_step_no_escalation() {
        let mut p = valid_playbook();
        p.steps[0].require_confidence_at_least = Some(0.5);
        let pb = Playbooks { playbooks: vec![p] };
        let errors = pb.validate();
        assert!(errors.iter().any(|e| e.contains("first step")));
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let pb = Playbooks {
            playbooks: vec![valid_playbook()],
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("playbooks.yaml");
        pb.save(&path).unwrap();
        let loaded = Playbooks::load(&path).unwrap();
        assert_eq!(loaded.playbooks.len(), 1);
        assert_eq!(loaded.playbooks[0].name, "test_playbook");
    }

    #[test]
    fn test_save_creates_backup() {
        let pb = Playbooks {
            playbooks: vec![valid_playbook()],
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("playbooks.yaml");
        // First save (no backup yet)
        pb.save(&path).unwrap();
        assert!(!dir.path().join("playbooks.yaml.bak").exists());
        // Second save creates backup
        pb.save(&path).unwrap();
        assert!(dir.path().join("playbooks.yaml.bak").exists());
    }
}
