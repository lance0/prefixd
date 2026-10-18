mod inventory;
mod playbooks;
mod settings;

pub use inventory::*;
pub use playbooks::*;
pub use settings::*;

use anyhow::Result;
use std::path::Path;

/// Fixed parsing policy for operator-owned configuration. No includes or interpolation.
pub(crate) fn parse_yaml<'de, T: serde::Deserialize<'de>>(
    content: &'de str,
) -> Result<T, serde_saphyr::Error> {
    serde_saphyr::from_str_with_options(
        content,
        serde_saphyr::options! {
            strict_booleans: true,
            merge_keys: serde_saphyr::MergeKeyPolicy::AsOrdinary,
            duplicate_keys: serde_saphyr::DuplicateKeyPolicy::Error,
            with_snippet: false,
        },
    )
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub settings: Settings,
    pub inventory: Inventory,
    pub playbooks: Playbooks,
    /// Legacy `prefixd.yaml` forms to log once tracing is initialized.
    pub deprecations: Vec<ConfigDeprecation>,
}

impl AppConfig {
    pub fn load(config_dir: &Path) -> Result<Self> {
        let (mut settings, deprecations) =
            Settings::load_with_deprecations(config_dir.join("prefixd.yaml"))?;
        match crate::correlation::CorrelationConfig::load(config_dir.join("correlation.yaml")) {
            Ok(correlation) => settings.correlation = correlation,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) => {}
            Err(error) => return Err(error),
        }
        let inventory = Inventory::load(config_dir.join("inventory.yaml"))?;
        let playbooks = Playbooks::load(config_dir.join("playbooks.yaml"))?;

        Ok(Self {
            settings,
            inventory,
            playbooks,
            deprecations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        let mut settings: Settings =
            crate::config::parse_yaml(include_str!("../../configs/prefixd.yaml")).unwrap();
        settings.correlation.confidence_threshold = 0.5;
        std::fs::write(
            directory.path().join("prefixd.yaml"),
            serde_saphyr::to_string(&settings).unwrap(),
        )
        .unwrap();
        std::fs::write(
            directory.path().join("inventory.yaml"),
            include_str!("../../configs/inventory.yaml"),
        )
        .unwrap();
        std::fs::write(
            directory.path().join("playbooks.yaml"),
            include_str!("../../configs/playbooks.yaml"),
        )
        .unwrap();
        directory
    }

    #[test]
    fn startup_prefers_persisted_standalone_correlation() {
        let directory = fixture();
        std::fs::write(
            directory.path().join("correlation.yaml"),
            "confidence_threshold: 0.625\n",
        )
        .unwrap();
        let config = AppConfig::load(directory.path()).unwrap();
        assert_eq!(config.settings.correlation.confidence_threshold, 0.625);
    }

    #[test]
    fn startup_uses_inline_correlation_when_standalone_is_absent() {
        let directory = fixture();
        let config = AppConfig::load(directory.path()).unwrap();
        assert_eq!(config.settings.correlation.confidence_threshold, 0.5);
    }

    #[test]
    fn startup_rejects_malformed_standalone_correlation() {
        let directory = fixture();
        std::fs::write(
            directory.path().join("correlation.yaml"),
            "confidence_threshold: [",
        )
        .unwrap();
        assert!(AppConfig::load(directory.path()).is_err());
    }

    #[test]
    fn startup_rejects_invalid_standalone_correlation() {
        let directory = fixture();
        std::fs::write(
            directory.path().join("correlation.yaml"),
            "window_seconds: 0\n",
        )
        .unwrap();
        let error = AppConfig::load(directory.path()).unwrap_err();
        assert!(error.to_string().contains("window_seconds must be > 0"));
    }

    #[test]
    fn startup_rejects_unreadable_standalone_correlation() {
        let directory = fixture();
        std::fs::create_dir(directory.path().join("correlation.yaml")).unwrap();
        assert!(AppConfig::load(directory.path()).is_err());
    }

    #[test]
    fn startup_still_validates_inline_settings_before_standalone_override() {
        let directory = fixture();
        let path = directory.path().join("prefixd.yaml");
        let mut settings: Settings =
            crate::config::parse_yaml(&std::fs::read_to_string(&path).unwrap()).unwrap();
        settings.correlation.window_seconds = 0;
        std::fs::write(path, serde_saphyr::to_string(&settings).unwrap()).unwrap();
        std::fs::write(
            directory.path().join("correlation.yaml"),
            "confidence_threshold: 0.625\n",
        )
        .unwrap();
        assert!(AppConfig::load(directory.path()).is_err());
    }
    fn assert_yaml_roundtrip<T>(input: &str)
    where
        T: serde::de::DeserializeOwned + serde::Serialize,
    {
        let original: T = parse_yaml(input).unwrap();
        let saved = serde_saphyr::to_string(&original).unwrap();
        let restored: T = parse_yaml(&saved).unwrap();
        assert_eq!(
            serde_json::to_value(original).unwrap(),
            serde_json::to_value(restored).unwrap()
        );
    }

    #[test]
    fn yaml_shipped_typed_configuration_roundtrips() {
        for input in [
            include_str!("../../configs/prefixd.yaml"),
            include_str!("../../configs/prefixd-gobgp.yaml"),
            include_str!("../../configs/prefixd.yaml.example"),
        ] {
            assert_yaml_roundtrip::<Settings>(input);
        }
        assert_yaml_roundtrip::<Inventory>(include_str!("../../configs/inventory.yaml"));
        assert_yaml_roundtrip::<Playbooks>(include_str!("../../configs/playbooks.yaml"));
        assert_yaml_roundtrip::<crate::correlation::CorrelationConfig>(include_str!(
            "../../configs/correlation.yaml"
        ));
        assert_yaml_roundtrip::<crate::alerting::AlertingConfig>(
            r#"
destinations:
  - type: slack
    webhook_url: https://example.invalid/secret
    channel: null
    events: [mitigation.created]
  - type: generic
    url: https://example.invalid/webhook
    secret: '00123'
    headers: {Authorization: 'Bearer secret'}
events: [config.reloaded]
"#,
        );
    }

    #[test]
    fn yaml_typed_tags_anchors_scalars_and_nulls() {
        let input = r#"
customers:
  - customer_id: !!str 00123
    name: 'off'
    prefixes: [!!str '2001:db8::/32']
    policy_profile: strict
    services:
      - service_id: web
        name: Web
        allowed_ports: {tcp: &ports [80, 443], udp: *ports}
        assets: [{ip: '2001:db8::1', role: null}]
"#;
        let inventory: Inventory = parse_yaml(input).unwrap();
        let customer = &inventory.customers[0];
        assert_eq!(customer.customer_id, "00123");
        assert_eq!(customer.name, "off");
        assert_eq!(customer.policy_profile, PolicyProfile::Strict);
        assert_eq!(customer.services[0].allowed_ports.tcp, vec![80, 443]);
        assert_eq!(customer.services[0].allowed_ports.udp, vec![80, 443]);
        assert_eq!(customer.services[0].assets[0].role, None);
        assert_yaml_roundtrip::<Inventory>(input);
        let tagged: PolicyProfile = parse_yaml("!strict").unwrap();
        assert_eq!(tagged, PolicyProfile::Strict);
        let action: PlaybookAction = parse_yaml("!discard").unwrap();
        assert_eq!(
            serde_json::to_value(action).unwrap(),
            serde_json::json!("discard")
        );
    }

    #[test]
    fn yaml_guardrails_do_not_accept_legacy_booleans_or_expand_merges() {
        assert!(parse_yaml::<GuardrailsConfig>("require_ttl: off").is_err());
        // Without merge expansion the typed guardrail default remains mandatory TTL.
        // Expanding the merge would instead disable it, so this detects policy drift.
        let parsed: GuardrailsConfig =
            parse_yaml("<<: &unsafe_defaults {require_ttl: false}\n").unwrap();
        assert!(parsed.require_ttl);
    }

    #[test]
    fn yaml_rejects_duplicates_malformed_and_multiple_documents() {
        for input in [
            "enabled: true\nenabled: false\n",
            "sources: {detector: {weight: 1}, detector: {weight: 2}}\n",
            "enabled: true\n---\nenabled: false\n",
            "enabled: [\n",
        ] {
            assert!(parse_yaml::<crate::correlation::CorrelationConfig>(input).is_err());
        }
    }

    #[test]
    fn yaml_parse_errors_omit_secret_neighbors() {
        for input in [
            "storage: {connection_string: 'SECRET_CANARY'}\nhttp: [\n",
            "storage: {connection_string: 'SECRET_CANARY'}\nmode: invalid-mode\n",
        ] {
            let error = parse_yaml::<Settings>(input).unwrap_err();
            assert!(!format!("{error}").contains("SECRET_CANARY"));
            assert!(!format!("{error:?}").contains("SECRET_CANARY"));
        }
    }
    #[cfg(unix)]
    fn assert_yaml_save_contract<T>(value: &T, save: impl Fn(&Path) -> anyhow::Result<()>)
    where
        T: serde::de::DeserializeOwned + serde::Serialize,
    {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yaml");
        let backup = path.with_extension("yaml.bak");
        let original = "# exact original configuration bytes\n";
        std::fs::write(&path, original).unwrap();
        save(&path).unwrap();
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), original);
        let restored: T = parse_yaml(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(value).unwrap(),
            serde_json::to_value(restored).unwrap()
        );

        let protected = directory.path().join("protected");
        std::fs::write(&protected, "untouched").unwrap();
        std::fs::remove_file(&path).unwrap();
        symlink(&protected, &path).unwrap();
        assert!(save(&path).is_err());
        assert_eq!(std::fs::read_to_string(&protected).unwrap(), "untouched");
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, original).unwrap();
        std::fs::remove_file(&backup).unwrap();
        symlink(&protected, &backup).unwrap();
        assert!(save(&path).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        assert_eq!(std::fs::read_to_string(&protected).unwrap(), "untouched");
    }

    #[test]
    #[cfg(unix)]
    fn yaml_three_save_paths_preserve_roundtrips_backups_and_symlink_rejection() {
        let playbooks: Playbooks =
            parse_yaml(include_str!("../../configs/playbooks.yaml")).unwrap();
        assert_yaml_save_contract(&playbooks, |path| playbooks.save(path));
        let correlation: crate::correlation::CorrelationConfig =
            parse_yaml(include_str!("../../configs/correlation.yaml")).unwrap();
        assert_yaml_save_contract(&correlation, |path| correlation.save(path));
        let alerting: crate::alerting::AlertingConfig = parse_yaml(
            "destinations: [{type: generic, url: 'https://example.invalid', secret: '00123'}]",
        )
        .unwrap();
        assert_yaml_save_contract(&alerting, |path| alerting.save(path));
    }
}
