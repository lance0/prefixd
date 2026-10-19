use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

use crate::bgp::FlowSpecMatchSupport;
use crate::config::GuardrailsConfig;
use crate::domain::{
    ActionType, AttackVector, FlowSpecAction, FlowSpecNlri, FragmentMatch, MatchCriteria,
    PacketLengthRange, canonical_ports,
};

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Playbooks {
    pub playbooks: Vec<Playbook>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Playbook {
    pub name: String,
    #[serde(rename = "match")]
    pub match_criteria: PlaybookMatch,
    /// Per-playbook correlation override. When present, overrides global
    /// correlation `min_sources` and `confidence_threshold` for events
    /// matching this playbook.
    #[serde(default)]
    pub correlation: Option<crate::correlation::PlaybookCorrelationOverride>,
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
    /// The single rule's action. Absent when the step carries `rules`, so a
    /// binary that predates `rules` refuses the step instead of widening it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<PlaybookAction>,
    #[serde(default)]
    pub rate_bps: Option<u64>,
    pub ttl_seconds: u32,
    /// Narrowed rules, each admitted as its own mitigation (ADR 028). Valid
    /// only in `udp_amplification` playbooks; the step's TTL applies to each.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<PlaybookRule>,
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
    /// RTBH host route (ADR 027): the victim's /32 or /128 only, with no rate.
    Blackhole,
}

impl PlaybookAction {
    fn flowspec(self, rate_bps: Option<u64>) -> FlowSpecAction {
        FlowSpecAction {
            action_type: match self {
                Self::Police => ActionType::Police,
                Self::Discard => ActionType::Discard,
                Self::Blackhole => ActionType::Blackhole,
            },
            rate_bps,
        }
    }
}

/// One rule of a multi-rule step. Unknown keys fail closed: ignoring a match
/// key would widen the rule.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PlaybookRule {
    #[serde(rename = "match")]
    pub match_criteria: PlaybookRuleMatch,
    pub action: PlaybookAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_bps: Option<u64>,
}

/// Narrowing components of a rule. Every rule matches UDP to the victim host.
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PlaybookRuleMatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_ports: Option<SrcPortsSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fragment: Option<FragmentMatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_length: Option<PacketLengthRange>,
}

/// `from_event`, or a static list the operator wrote (not limited to the library).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(untagged)]
pub enum SrcPortsSpec {
    FromEvent(FromEvent),
    Static(Vec<u16>),
}

/// The event's source ports intersected with the reflector-port library.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FromEvent {
    FromEvent,
}

impl PlaybookStep {
    /// The single-rule action; `None` for a `rules` step.
    pub fn flowspec_action(&self) -> Option<FlowSpecAction> {
        self.action.map(|action| action.flowspec(self.rate_bps))
    }

    /// Settings-independent checks, run at load, save and validation.
    fn check(&self, vector: AttackVector) -> std::result::Result<(), String> {
        match (self.flowspec_action(), self.rules.as_slice()) {
            // A blackhole drops all traffic to the victim, so it never combines
            // with the narrowed source-port rules of an amplification playbook.
            (Some(action), []) if action.action_type == ActionType::Blackhole => {
                if vector == AttackVector::UdpAmplification {
                    return Err(
                        "a blackhole step is not valid in udp_amplification playbooks".into(),
                    );
                }
                match self.rate_bps {
                    Some(_) => Err("a blackhole step takes no rate_bps".into()),
                    None => Ok(()),
                }
            }
            (Some(action), []) => action
                .traffic_rate_bytes_per_second()
                .map(|_| ())
                .map_err(|error| error.to_string()),
            (None, []) => Err("a step needs an action or rules".into()),
            (Some(_), _) => Err("a step has an action or rules, not both".into()),
            (None, rules) => {
                if vector != AttackVector::UdpAmplification {
                    return Err("rules are valid only in udp_amplification playbooks".into());
                }
                if self.rate_bps.is_some() {
                    return Err("rate_bps belongs on each rule of a rules step".into());
                }
                for (k, rule) in rules.iter().enumerate() {
                    rule.check()
                        .map_err(|error| format!("rule[{k}]: {error}"))?;
                }
                Ok(())
            }
        }
    }
}

impl PlaybookRule {
    pub fn flowspec_action(&self) -> FlowSpecAction {
        self.action.flowspec(self.rate_bps)
    }

    /// The rule for one victim host and one source-port set: UDP plus the
    /// rule's narrowing components, with no destination ports.
    pub fn match_for(&self, dst_prefix: String, src_ports: Vec<u16>) -> MatchCriteria {
        MatchCriteria {
            dst_prefix,
            protocol: Some(17),
            src_ports,
            fragment: self.match_criteria.fragment,
            packet_length: self.match_criteria.packet_length,
            ..Default::default()
        }
    }

    /// One representative rule per family; `from_event` stands in as one port.
    fn samples(&self) -> [MatchCriteria; 2] {
        let ports = match &self.match_criteria.src_ports {
            None => Vec::new(),
            Some(SrcPortsSpec::FromEvent(_)) => vec![0],
            Some(SrcPortsSpec::Static(ports)) => canonical_ports(ports),
        };
        [
            self.match_for("192.0.2.1/32".into(), ports.clone()),
            self.match_for("2001:db8::1/128".into(), ports),
        ]
    }

    fn check(&self) -> std::result::Result<(), String> {
        if self.action == PlaybookAction::Blackhole {
            return Err("a rule cannot blackhole; a blackhole is a step of its own".into());
        }
        self.flowspec_action()
            .traffic_rate_bytes_per_second()
            .map_err(|error| error.to_string())?;
        let narrowing = &self.match_criteria;
        if narrowing.src_ports == Some(SrcPortsSpec::Static(Vec::new())) {
            return Err("src_ports must not be empty".into());
        }
        if narrowing.src_ports.is_none()
            && narrowing.fragment.is_none()
            && narrowing.packet_length.is_none()
        {
            return Err("a rule needs src_ports, fragment or packet_length".into());
        }
        for sample in self.samples() {
            FlowSpecNlri::from(&sample)
                .validate()
                .map_err(|error| format!("{} ({})", error, sample.dst_prefix))?;
        }
        Ok(())
    }
}

impl Playbooks {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let playbooks: Playbooks = crate::config::parse_yaml(&content)?;
        playbooks.validate_steps()?;
        Ok(playbooks)
    }

    fn validate_steps(&self) -> Result<()> {
        for (i, playbook) in self.playbooks.iter().enumerate() {
            for (j, step) in playbook.steps.iter().enumerate() {
                step.check(playbook.match_criteria.vector)
                    .map_err(|error| {
                        anyhow::anyhow!("playbook[{i}] ({:?}) step[{j}]: {error}", playbook.name)
                    })?;
            }
        }
        Ok(())
    }

    /// Rule checks that depend on settings and the selected speaker (ADR 028):
    /// the fragment and packet-length opt-ins, `max_ports` for static source
    /// ports, and speaker capability. Startup, reload and save run them in
    /// dry-run and enforced modes alike. Returns every error found.
    /// Every settings- and speaker-dependent playbook check, shared by startup,
    /// reload and save: the ADR 028 match checks and the ADR 027 blackhole
    /// enablement, TTL cap and lease gate. Returns every error found.
    pub fn check_settings(
        &self,
        settings: &crate::config::Settings,
        speaker: crate::bgp::SpeakerCapabilities,
    ) -> Vec<String> {
        let mut errors = self.check_match_settings(&settings.guardrails, speaker.flowspec_match);
        if let Err(error) =
            crate::guardrails::check_blackhole_playbooks(settings, speaker.blackhole_lease, self)
        {
            errors.push(error.to_string());
        }
        errors
    }

    pub fn check_match_settings(
        &self,
        guardrails: &GuardrailsConfig,
        support: FlowSpecMatchSupport,
    ) -> Vec<String> {
        let mut errors = Vec::new();
        for (i, playbook) in self.playbooks.iter().enumerate() {
            for (j, step) in playbook.steps.iter().enumerate() {
                for (k, rule) in step.rules.iter().enumerate() {
                    let ctx = format!("playbook[{i}] ({:?}) step[{j}] rule[{k}]", playbook.name);
                    let narrowing = &rule.match_criteria;
                    if narrowing.fragment.is_some() && !guardrails.allow_fragment_match {
                        errors.push(format!(
                            "{ctx}: fragment needs guardrails.allow_fragment_match: true"
                        ));
                    }
                    if narrowing.packet_length.is_some() && !guardrails.allow_packet_length_match {
                        errors.push(format!(
                            "{ctx}: packet_length needs guardrails.allow_packet_length_match: true"
                        ));
                    }
                    if let Some(SrcPortsSpec::Static(ports)) = &narrowing.src_ports {
                        let count = canonical_ports(ports).len();
                        if count > guardrails.max_ports {
                            errors.push(format!(
                                "{ctx}: src_ports has {count} ports; guardrails.max_ports is {}",
                                guardrails.max_ports
                            ));
                        }
                    }
                    if let Err(error) = support.require(&FlowSpecNlri::from(&rule.samples()[0])) {
                        errors.push(format!("{ctx}: {error}"));
                    }
                }
            }
        }
        errors
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
                errors.push(format!("{}: name exceeds 128 bytes", ctx));
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

                if let Err(error) = step.check(pb.match_criteria.vector) {
                    errors.push(format!("{step_ctx}: {error}"));
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
        self.validate_steps()?;
        let path = path.as_ref();
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("invalid playbooks path"))?;
        let tmp_path = parent.join(format!(
            ".{}.tmp-{}",
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("playbooks.yaml"),
            uuid::Uuid::new_v4()
        ));

        // Refuse to operate on symlink paths for defense-in-depth.
        if std::fs::symlink_metadata(path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(anyhow::anyhow!(
                "refusing to write playbooks through symlink"
            ));
        }

        // Backup existing file
        if path.exists() {
            let bak = path.with_extension("yaml.bak");
            if std::fs::symlink_metadata(&bak)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
            {
                return Err(anyhow::anyhow!(
                    "refusing to write playbooks backup through symlink"
                ));
            }
            std::fs::copy(path, &bak)?;
        }

        let yaml = serde_saphyr::to_string(self)?;
        let mut tmp_file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)?;

        tmp_file.write_all(yaml.as_bytes())?;
        tmp_file.sync_all()?;
        drop(tmp_file);

        std::fs::rename(&tmp_path, path).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp_path);
        })?;

        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }

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
            correlation: None,
            steps: vec![PlaybookStep {
                action: Some(PlaybookAction::Police),
                rate_bps: Some(5_000_000),
                ttl_seconds: 120,
                require_confidence_at_least: None,
                require_persistence_seconds: None,
                rules: Vec::new(),
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
        assert!(errors.iter().any(|e| e.contains("requires rate_bps")));
    }

    #[test]
    fn action_validation_covers_load_save_and_later_steps() {
        for (action, rate) in [
            (PlaybookAction::Police, None),
            (PlaybookAction::Police, Some(0)),
            (PlaybookAction::Police, Some(16_777_217)),
            (PlaybookAction::Police, Some(u64::MAX)),
            (PlaybookAction::Discard, Some(0)),
            (PlaybookAction::Discard, Some(8)),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("playbooks.yaml");
            let original = Playbooks {
                playbooks: vec![valid_playbook()],
            };
            original.save(&path).unwrap();
            let original_bytes = std::fs::read(&path).unwrap();
            let mut invalid = original;
            let mut step = invalid.playbooks[0].steps[0].clone();
            step.action = Some(action);
            step.rate_bps = rate;
            invalid.playbooks[0].steps.push(step);
            assert!(!invalid.validate().is_empty());
            assert!(invalid.save(&path).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), original_bytes);
            assert!(!path.with_extension("yaml.bak").exists());
            std::fs::write(&path, serde_saphyr::to_string(&invalid).unwrap()).unwrap();
            assert!(
                Playbooks::load(&path)
                    .unwrap_err()
                    .to_string()
                    .contains("step[1]")
            );
        }
        for rate in [1, 7, 8, 9, 16_777_216, 16_777_218, 1_000_000_000] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("playbooks.yaml");
            let mut valid = Playbooks {
                playbooks: vec![valid_playbook()],
            };
            valid.playbooks[0].steps[0].rate_bps = Some(rate);
            assert!(valid.validate().is_empty());
            valid.save(&path).unwrap();
            assert_eq!(
                Playbooks::load(&path).unwrap().playbooks[0].steps[0].rate_bps,
                Some(rate)
            );
        }
    }

    #[test]
    fn blackhole_step_parses_and_refuses_a_rate() {
        let yaml = |extra: &str| {
            format!(
                "playbooks:\n  - name: rtbh\n    match:\n      vector: udp_flood\n    steps:\n      - action: blackhole\n        ttl_seconds: 1800\n{extra}"
            )
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("playbooks.yaml");
        std::fs::write(&path, yaml("")).unwrap();
        let loaded = Playbooks::load(&path).unwrap();
        let step = &loaded.playbooks[0].steps[0];
        assert_eq!(step.action, Some(PlaybookAction::Blackhole));
        assert_eq!(
            step.flowspec_action().unwrap().action_type,
            ActionType::Blackhole
        );
        assert!(loaded.validate().is_empty());
        loaded.save(&path).unwrap();
        // A rate is refused on load, validation and save.
        std::fs::write(&path, yaml("        rate_bps: 1000000\n")).unwrap();
        let error = Playbooks::load(&path).unwrap_err().to_string();
        assert!(
            error.contains("blackhole step takes no rate_bps"),
            "{error}"
        );
        let mut invalid = loaded.clone();
        invalid.playbooks[0].steps[0].rate_bps = Some(1_000_000);
        assert!(invalid.validate()[0].contains("takes no rate_bps"));
        assert!(invalid.save(&path).is_err());
        // An unknown action is refused.
        std::fs::write(&path, yaml("").replace("blackhole", "rtbh")).unwrap();
        assert!(Playbooks::load(&path).is_err());
    }

    /// A blackhole drops all traffic, so it never combines with `rules` or an
    /// amplification playbook, on load, validation and save.
    #[test]
    fn blackhole_never_combines_with_rules_or_amplification() {
        let rule =
            "        rules:\n          - match: {src_ports: [123]}\n            action: ACTION\n";
        let playbook = |vector: &str, step: &str| {
            format!(
                "playbooks:\n  - name: rtbh\n    match:\n      vector: {vector}\n    steps:\n      - ttl_seconds: 600\n{step}"
            )
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("playbooks.yaml");
        for (yaml, expected) in [
            (
                playbook(
                    "udp_amplification",
                    &format!(
                        "        action: blackhole\n{}",
                        rule.replace("ACTION", "discard")
                    ),
                ),
                "an action or rules, not both",
            ),
            (
                playbook("udp_amplification", &rule.replace("ACTION", "blackhole")),
                "a rule cannot blackhole",
            ),
            (
                playbook("udp_amplification", "        action: blackhole\n"),
                "not valid in udp_amplification playbooks",
            ),
        ] {
            std::fs::write(&path, &yaml).unwrap();
            let error = Playbooks::load(&path).unwrap_err().to_string();
            assert!(error.contains(expected), "{error}");
            let parsed: Playbooks = crate::config::parse_yaml(&yaml).unwrap();
            assert!(
                parsed.validate().iter().any(|e| e.contains(expected)),
                "{expected}"
            );
            assert!(parsed.save(dir.path().join("saved.yaml")).is_err());
        }
        // Negative control: the same rule with a FlowSpec action, and a blackhole
        // step in another vector, both load.
        std::fs::write(
            &path,
            playbook("udp_amplification", &rule.replace("ACTION", "discard")),
        )
        .unwrap();
        Playbooks::load(&path).unwrap();
        std::fs::write(&path, playbook("udp_flood", "        action: blackhole\n")).unwrap();
        Playbooks::load(&path).unwrap();
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
            action: Some(PlaybookAction::Discard),
            rate_bps: None,
            ttl_seconds: 300,
            require_confidence_at_least: Some(1.5),
            require_persistence_seconds: None,
            rules: Vec::new(),
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

    #[cfg(unix)]
    #[test]
    fn test_save_rejects_symlink_target() {
        use std::os::unix::fs::symlink;

        let pb = Playbooks {
            playbooks: vec![valid_playbook()],
        };
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.yaml");
        std::fs::write(&target, "playbooks: []").unwrap();
        let link = dir.path().join("playbooks.yaml");
        symlink(&target, &link).unwrap();

        assert!(pb.save(&link).is_err());
    }

    #[test]
    fn test_playbook_without_correlation_override() {
        let yaml = r#"
playbooks:
  - name: test
    match:
      vector: udp_flood
    steps:
      - action: police
        rate_bps: 5000000
        ttl_seconds: 120
"#;
        let playbooks: Playbooks = crate::config::parse_yaml(yaml).unwrap();
        assert!(playbooks.playbooks[0].correlation.is_none());
    }

    #[test]
    fn test_playbook_with_correlation_override() {
        let yaml = r#"
playbooks:
  - name: corroborated_udp
    match:
      vector: udp_flood
    correlation:
      min_sources: 2
      confidence_threshold: 0.7
    steps:
      - action: police
        rate_bps: 5000000
        ttl_seconds: 120
"#;
        let playbooks: Playbooks = crate::config::parse_yaml(yaml).unwrap();
        let corr = playbooks.playbooks[0].correlation.as_ref().unwrap();
        assert_eq!(corr.min_sources, Some(2));
        assert_eq!(corr.confidence_threshold, Some(0.7));
    }

    #[test]
    fn test_playbook_with_partial_correlation_override() {
        let yaml = r#"
playbooks:
  - name: partial_override
    match:
      vector: syn_flood
    correlation:
      min_sources: 3
    steps:
      - action: discard
        ttl_seconds: 300
"#;
        let playbooks: Playbooks = crate::config::parse_yaml(yaml).unwrap();
        let corr = playbooks.playbooks[0].correlation.as_ref().unwrap();
        assert_eq!(corr.min_sources, Some(3));
        assert_eq!(corr.confidence_threshold, None);
    }

    #[test]
    fn test_playbook_roundtrip_with_correlation() {
        use crate::correlation::PlaybookCorrelationOverride;

        let pb = Playbooks {
            playbooks: vec![Playbook {
                name: "test_corr".to_string(),
                match_criteria: PlaybookMatch {
                    vector: AttackVector::UdpFlood,
                    require_top_ports: false,
                },
                correlation: Some(PlaybookCorrelationOverride {
                    min_sources: Some(2),
                    confidence_threshold: Some(0.8),
                    ..Default::default()
                }),
                steps: vec![PlaybookStep {
                    action: Some(PlaybookAction::Police),
                    rate_bps: Some(5_000_000),
                    ttl_seconds: 120,
                    require_confidence_at_least: None,
                    require_persistence_seconds: None,
                    rules: Vec::new(),
                }],
            }],
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("playbooks.yaml");
        pb.save(&path).unwrap();
        let loaded = Playbooks::load(&path).unwrap();
        let corr = loaded.playbooks[0].correlation.as_ref().unwrap();
        assert_eq!(corr.min_sources, Some(2));
        assert_eq!(corr.confidence_threshold, Some(0.8));
    }

    fn amplification(rules: &str) -> String {
        format!(
            "playbooks:\n  - name: amp\n    match: {{vector: udp_amplification}}\n    steps:\n      - ttl_seconds: 300\n        rules:\n{rules}"
        )
    }

    /// Parse, then the load/save check; errors from either are returned.
    fn check(yaml: &str) -> std::result::Result<Playbooks, String> {
        let playbooks: Playbooks = crate::config::parse_yaml(yaml).map_err(|e| e.to_string())?;
        playbooks.validate_steps().map_err(|e| e.to_string())?;
        let errors = playbooks.validate();
        if !errors.is_empty() {
            return Err(errors.join("; "));
        }
        Ok(playbooks)
    }

    /// The commented examples in the shipped playbooks.yaml, uncommented.
    fn shipped_examples() -> Vec<String> {
        let shipped = include_str!("../../configs/playbooks.yaml");
        let mut examples = Vec::new();
        let mut current: Option<String> = None;
        for line in shipped.lines() {
            match (&mut current, line.strip_prefix("  # ")) {
                (None, Some(rest)) if rest.starts_with("- name:") => {
                    current = Some(format!("playbooks:\n  {rest}\n"));
                }
                (Some(example), Some(rest)) => example.push_str(&format!("  {rest}\n")),
                (Some(_), None) => examples.extend(current.take()),
                (None, None) => {}
                (None, Some(_)) => {}
            }
        }
        examples.extend(current);
        examples
    }

    #[test]
    fn shipped_amplification_examples_load_once_uncommented() {
        // The active shipped file has no multi-rule step, so default installs,
        // the dashboard editor and older releases see no change.
        let active: Playbooks =
            crate::config::parse_yaml(include_str!("../../configs/playbooks.yaml")).unwrap();
        assert!(
            active
                .playbooks
                .iter()
                .all(|p| p.steps.iter().all(|s| s.rules.is_empty()))
        );
        let examples = shipped_examples();
        assert_eq!(examples.len(), 2);
        let settings: crate::config::Settings =
            crate::config::parse_yaml(include_str!("../../configs/prefixd.yaml")).unwrap();
        let mut opted_in = settings.guardrails.clone();
        opted_in.allow_fragment_match = true;
        opted_in.allow_packet_length_match = true;
        for (example, flag) in examples
            .iter()
            .zip(["allow_fragment_match", "allow_packet_length_match"])
        {
            let playbooks = check(example).unwrap();
            assert_eq!(
                playbooks.playbooks[0].match_criteria.vector,
                AttackVector::UdpAmplification
            );
            // Shipped settings leave the opt-in off, so the example says to set it.
            let errors =
                playbooks.check_match_settings(&settings.guardrails, FlowSpecMatchSupport::ALL);
            assert!(errors.len() == 1 && errors[0].contains(flag), "{errors:?}");
            assert!(
                playbooks
                    .check_match_settings(&opted_in, FlowSpecMatchSupport::ALL)
                    .is_empty()
            );
        }
        // Decisions recorded: the source-port rule discards, fragments are policed.
        let rules = &check(&examples[0]).unwrap().playbooks[0].steps[0].rules;
        assert_eq!(
            rules[0].match_criteria.src_ports,
            Some(SrcPortsSpec::FromEvent(FromEvent::FromEvent))
        );
        assert_eq!(rules[0].action, PlaybookAction::Discard);
        assert_eq!(
            rules[1].match_criteria.fragment,
            Some(FragmentMatch::NonFirst)
        );
        assert_eq!(rules[1].action, PlaybookAction::Police);
    }

    #[test]
    fn rules_steps_fail_closed_at_load_and_save() {
        let valid = [
            "          - match: {src_ports: from_event}\n            action: discard\n",
            "          - match: {src_ports: [11211, 11211]}\n            action: discard\n",
            "          - match: {src_ports: [11211], packet_length: {min: 1000, max: 65535}}\n            action: discard\n",
            "          - match: {fragment: non_first}\n            action: police\n            rate_bps: 1000000\n",
        ];
        for rules in valid {
            let playbooks = check(&amplification(rules)).unwrap();
            // Save and load keep the step byte for byte.
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("playbooks.yaml");
            playbooks.save(&path).unwrap();
            let loaded = Playbooks::load(&path).unwrap();
            assert_eq!(
                serde_json::to_value(&loaded).unwrap(),
                serde_json::to_value(&playbooks).unwrap()
            );
        }
        let invalid = [
            (
                "          - match: {}\n            action: discard\n",
                "needs src_ports",
            ),
            (
                "          - match: {src_ports: []}\n            action: discard\n",
                "must not be empty",
            ),
            (
                "          - match: {src_ports: from_event, fragment: non_first}\n            action: discard\n",
                "cannot share a rule",
            ),
            (
                "          - match: {packet_length: {min: 1000, max: 65535}}\n            action: discard\n",
                "requires source ports",
            ),
            // Valid for IPv4 (floor 28) but not for IPv6 (floor 48).
            (
                "          - match: {src_ports: [123], packet_length: {min: 40, max: 65535}}\n            action: discard\n",
                "2001:db8::1/128",
            ),
            (
                "          - match: {src_ports: from_event}\n            action: police\n",
                "requires rate_bps",
            ),
            // Unknown keys fail closed: ignoring them would widen the rule.
            (
                "          - match: {src_ports: from_event, dst_ports: [80]}\n            action: discard\n",
                "dst_ports",
            ),
            (
                "          - match: {src_ports: from_event}\n            action: discard\n            ttl_seconds: 5\n",
                "ttl_seconds",
            ),
            (
                "          - match: {src_ports: any}\n            action: discard\n",
                "untagged enum SrcPortsSpec",
            ),
        ];
        for (rules, expected) in invalid {
            let error = check(&amplification(rules)).unwrap_err();
            assert!(error.contains(expected), "{expected}: {error}");
        }
        // Step shape: rules replace the action, only under udp_amplification.
        let rules = "        rules:\n          - match: {src_ports: from_event}\n            action: discard\n";
        for (vector, step, expected) in [
            ("udp_flood", rules.to_string(), "only in udp_amplification"),
            (
                "udp_amplification",
                format!("        action: discard\n{rules}"),
                "not both",
            ),
            (
                "udp_amplification",
                "        rate_bps: 5\n".to_string() + rules,
                "each rule",
            ),
            (
                "udp_amplification",
                String::new(),
                "needs an action or rules",
            ),
        ] {
            let yaml = format!(
                "playbooks:\n  - name: p\n    match: {{vector: {vector}}}\n    steps:\n      - ttl_seconds: 300\n{step}"
            );
            let error = check(&yaml).unwrap_err();
            assert!(error.contains(expected), "{expected}: {error}");
            // Save refuses too, leaving nothing on disk.
            if let Ok(playbooks) = crate::config::parse_yaml::<Playbooks>(&yaml) {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("playbooks.yaml");
                assert!(playbooks.save(&path).is_err());
                assert!(!path.exists());
            }
        }
    }

    #[test]
    fn match_settings_refuse_opt_ins_port_caps_and_unsupported_speakers() {
        let yaml = amplification(
            "          - match: {fragment: non_first}\n            action: police\n            rate_bps: 1000000\n          - match: {src_ports: [1, 2, 3, 4, 5, 6], packet_length: {min: 100, max: 200}}\n            action: discard\n          - match: {src_ports: from_event}\n            action: discard\n",
        );
        let playbooks = check(&yaml).unwrap();
        let mut guardrails: crate::config::GuardrailsConfig =
            crate::config::parse_yaml("{}").unwrap();
        let errors = playbooks.check_match_settings(&guardrails, FlowSpecMatchSupport::ALL);
        assert_eq!(errors.len(), 3, "{errors:?}");
        assert!(errors[0].contains("rule[0]: fragment needs guardrails.allow_fragment_match"));
        assert!(errors[1].contains("rule[1]: packet_length needs"));
        assert!(errors[2].contains("rule[1]: src_ports has 6 ports; guardrails.max_ports is 5"));
        // Accepting control: opted in and within the cap.
        guardrails.allow_fragment_match = true;
        guardrails.allow_packet_length_match = true;
        guardrails.max_ports = 6;
        assert!(
            playbooks
                .check_match_settings(&guardrails, FlowSpecMatchSupport::ALL)
                .is_empty()
        );
        // A speaker that cannot encode a component refuses every rule using it,
        // including from_event, whose ports are only known per event.
        let errors = playbooks.check_match_settings(&guardrails, FlowSpecMatchSupport::default());
        assert_eq!(errors.len(), 3, "{errors:?}");
        assert!(errors.iter().all(|e| e.contains("cannot encode")));
        let legacy: Playbooks =
            crate::config::parse_yaml(include_str!("../../configs/playbooks.yaml")).unwrap();
        assert!(
            legacy
                .check_match_settings(&guardrails, FlowSpecMatchSupport::default())
                .is_empty()
        );
    }

    /// Older binaries must refuse rather than widen: their step requires
    /// `action`, and their vector enum lacks `udp_amplification`. These mirror
    /// the shapes released before multi-rule steps.
    #[test]
    fn older_binary_shapes_refuse_rules_and_the_new_vector() {
        #[derive(Debug, Deserialize)]
        #[allow(dead_code, reason = "fixture mirrors the released schema")]
        struct OldPlaybooks {
            playbooks: Vec<OldPlaybook>,
        }
        #[derive(Debug, Deserialize)]
        #[allow(dead_code, reason = "fixture mirrors the released schema")]
        struct OldPlaybook {
            name: String,
            #[serde(rename = "match")]
            match_criteria: OldMatch,
            steps: Vec<OldStep>,
        }
        #[derive(Debug, Deserialize)]
        #[allow(dead_code, reason = "fixture mirrors the released schema")]
        struct OldMatch {
            vector: OldVector,
        }
        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum OldVector {
            UdpFlood,
            SynFlood,
            AckFlood,
            IcmpFlood,
            Unknown,
        }
        #[derive(Debug, Deserialize)]
        #[allow(dead_code, reason = "fixture mirrors the released schema")]
        struct OldStep {
            action: PlaybookAction,
            ttl_seconds: u32,
        }
        for example in shipped_examples() {
            check(&example).unwrap();
            let error = crate::config::parse_yaml::<OldPlaybooks>(&example)
                .unwrap_err()
                .to_string();
            assert!(error.contains("udp_amplification"), "{error}");
            // Even under an old vector, a rules step has no action and is refused.
            let renamed = example.replace("vector: udp_amplification", "vector: udp_flood");
            let error = crate::config::parse_yaml::<OldPlaybooks>(&renamed)
                .unwrap_err()
                .to_string();
            assert!(error.contains("action"), "{error}");
        }
        // Control: the old shape reads the active shipped file and what this
        // binary saves for legacy steps.
        let shipped = include_str!("../../configs/playbooks.yaml");
        crate::config::parse_yaml::<OldPlaybooks>(shipped).unwrap();
        let legacy: Playbooks = crate::config::parse_yaml(shipped).unwrap();
        let saved = serde_saphyr::to_string(&legacy).unwrap();
        crate::config::parse_yaml::<OldPlaybooks>(&saved).unwrap();
    }
}
