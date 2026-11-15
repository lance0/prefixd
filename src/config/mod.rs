mod inventory;
mod playbooks;
mod settings;
mod vpn_scope;

pub use inventory::*;
pub use playbooks::*;
pub use settings::*;
pub use vpn_scope::*;

use anyhow::{Context, Result};
use std::path::Path;

/// Fixed parsing policy for operator-owned configuration. No includes or interpolation.
fn yaml_options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        strict_booleans: true,
        merge_keys: serde_saphyr::MergeKeyPolicy::AsOrdinary,
        duplicate_keys: serde_saphyr::DuplicateKeyPolicy::Error,
        with_snippet: false,
    }
}

pub(crate) fn parse_yaml<'de, T: serde::Deserialize<'de>>(
    content: &'de str,
) -> Result<T, serde_saphyr::Error> {
    serde_saphyr::from_str_with_options(content, yaml_options())
}

/// [`parse_yaml`] for files that hold secrets: `prefixd.yaml`,
/// `correlation.yaml` and `alerting.yaml`. Serde errors can quote the
/// offending value, so the error keeps only the key path, line, column and
/// what was expected. Keys the type does not know are returned instead of
/// being dropped silently; only their paths are read, never their values.
pub(crate) fn parse_secret_yaml<T: serde::de::DeserializeOwned>(
    content: &str,
) -> Result<(T, Vec<String>)> {
    let mut path = None;
    let mut unknown_keys = Vec::new();
    let value =
        serde_saphyr::with_deserializer_from_str_with_options(content, yaml_options(), |de| {
            let mut record = |ignored: serde_ignored::Path<'_>| {
                unknown_keys.push(unknown_key_path(&ignored));
            };
            let de = serde_ignored::Deserializer::new(de, &mut record);
            serde_path_to_error::deserialize::<_, T>(de).map_err(|error| {
                path = Some(error.path().to_string());
                error.into_inner()
            })
        })
        .map_err(|error| anyhow::anyhow!(redacted_yaml_error(path.as_deref(), &error)))?;
    Ok((value, unknown_keys))
}

/// serde_ignored writes a sequence index as `destinations.0` and marks every
/// `Option` it descends through with a `?` segment. Report
/// `destinations[0].chanel`, matching the key paths parse errors use.
fn unknown_key_path(path: &serde_ignored::Path<'_>) -> String {
    let raw = path.to_string();
    let mut key = String::new();
    for segment in raw.split('.') {
        if segment.is_empty() || segment == "?" {
            continue;
        }
        match segment.parse::<usize>() {
            Ok(index) => key.push_str(&format!("[{index}]")),
            Err(_) => {
                if !key.is_empty() {
                    key.push('.');
                }
                key.push_str(segment);
            }
        }
    }
    if key.is_empty() { raw } else { key }
}

fn redacted_yaml_error(path: Option<&str>, error: &serde_saphyr::Error) -> String {
    use serde_saphyr::Error as E;
    // A flow-style typo such as `{token_env:SECRET}` parses as one key, so key
    // text stops at its first `:`.
    let key = |key: &str| key.split(':').next().unwrap_or_default().to_string();
    // Keys, types and expectations only; serde's own value-quoting text is
    // dropped. `Message` is a custom error, which prefixd's own validation
    // writes; secret fields are plain strings with no custom deserializer.
    let what = match error {
        E::Message { msg, .. } => msg.clone(),
        E::SerdeUnknownField { field, .. } => format!("unknown field `{}`", key(field)),
        E::SerdeMissingField { field, .. } => format!("missing field `{field}`"),
        E::DuplicateMappingKey { key: Some(k), .. } => format!("duplicate key `{}`", key(k)),
        E::SerdeInvalidType { expected, .. } => format!("invalid type, expected {expected}"),
        E::SerdeInvalidValue { expected, .. } => format!("invalid value, expected {expected}"),
        E::SerdeUnknownVariant { expected, .. } => {
            format!("unknown variant, expected one of {}", expected.join(", "))
        }
        E::InvalidScalar { ty, .. } => format!("invalid {ty}"),
        E::Unexpected { expected, .. } => format!("expected {expected}"),
        E::InvalidBooleanStrict { .. } => "expected true or false".to_string(),
        E::NullIntoString { .. } => "expected a string, found null".to_string(),
        E::ExternallyTaggedEnumExpectedScalarOrMapping { .. } => {
            "expected a scalar or mapping".to_string()
        }
        E::ExternalMessage { .. } | E::IndentationError { .. } | E::Eof { .. } => {
            "YAML syntax error".to_string()
        }
        _ => "invalid value".to_string(),
    };
    let mut message = match path.filter(|path| *path != ".") {
        Some(path) => format!("{}: {what}", key(path)),
        None => what,
    };
    if let Some(location) = error.location() {
        message.push_str(&format!(
            " at line {} column {}",
            location.line(),
            location.column()
        ));
    }
    message
}

/// Key paths of string values written as `${VAR}`. The loader never expands
/// them, so each would be used literally; values are not echoed.
pub(crate) fn env_placeholder_errors(value: &serde_json::Value) -> Vec<String> {
    fn walk(path: &str, value: &serde_json::Value, errors: &mut Vec<String>) {
        match value {
            serde_json::Value::String(s) if s.starts_with("${") && s.ends_with('}') => {
                errors.push(format!(
                    "{path} looks like ${{VAR}} substitution, which prefixd does not perform; \
                     set the value, or use the matching *_env key where one exists"
                ))
            }
            serde_json::Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    walk(&format!("{path}[{i}]"), item, errors);
                }
            }
            serde_json::Value::Object(map) => {
                for (key, item) in map {
                    let path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{path}.{key}")
                    };
                    walk(&path, item, errors);
                }
            }
            _ => {}
        }
    }
    let mut errors = Vec::new();
    walk("", value, &mut errors);
    errors
}

/// A configuration key the loader does not know: either a typo or a key from
/// another release. Only the path is collected; values are never read, so
/// nothing secret can reach a warning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownKey {
    /// The file it appeared in: `prefixd.yaml`, `correlation.yaml` or
    /// `alerting.yaml`.
    pub file: &'static str,
    /// The full key path, such as `guardrails.max_port`.
    pub key: String,
}

impl std::fmt::Display for UnknownKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}: unknown key `{}`; ignored in this release, refused in the next",
            self.file, self.key
        )
    }
}

/// Startup checks `--check-config` cannot run because each needs a live
/// speaker or database. Printed on every check so a clean exit is not read as
/// coverage of them.
pub const CHECK_CONFIG_SKIPPED: &[&str] = &[
    "playbook checks against the speaker's FlowSpec match and blackhole-lease capabilities",
    "blackhole, VPN scope and injection-lease support checks",
    "scrubber readiness and outstanding-diversion checks",
    "database registration, fencing and migrations",
];

/// Validation of a configuration directory without PostgreSQL or a speaker.
#[derive(Debug, Default)]
pub struct ConfigCheck {
    /// Every error, each already naming its file, in startup's redacted text.
    pub errors: Vec<String>,
    /// Keys the loader ignores, which startup warns about.
    pub unknown_keys: Vec<UnknownKey>,
    /// Other configuration-only warnings, such as unreachable prefix playbooks.
    pub warnings: Vec<String>,
    /// Files parsed and checked.
    pub validated: Vec<&'static str>,
}

impl ConfigCheck {
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }

    /// The one-line success summary; `--check-config` prints it and exits 0.
    pub fn summary(&self) -> String {
        format!(
            "configuration OK: {} validated, {} unknown key(s) ignored",
            self.validated.join(", "),
            self.unknown_keys.len()
        )
    }
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub settings: Settings,
    pub inventory: Inventory,
    pub playbooks: Playbooks,
    /// The file alerting came from: `alerting.yaml` or `prefixd.yaml`.
    pub alerting_source: &'static str,
    /// Keys the loaded files contain but this release ignores. Startup warns
    /// about each; the next release refuses them.
    pub unknown_keys: Vec<UnknownKey>,
}

impl AppConfig {
    pub fn load(config_dir: &Path) -> Result<Self> {
        let path = |name: &str| config_dir.join(name);
        let failed = |name: &str| format!("failed to load {}", path(name).display());
        let (mut settings, unknown_keys) = Settings::load_with_unknown_keys(path("prefixd.yaml"))
            .with_context(|| failed("prefixd.yaml"))?;
        let mut unknown_keys: Vec<UnknownKey> = unknown_keys
            .into_iter()
            .map(|key| UnknownKey {
                file: "prefixd.yaml",
                key,
            })
            .collect();
        match crate::correlation::CorrelationConfig::load_with_unknown_keys(path(
            "correlation.yaml",
        )) {
            Ok((correlation, keys)) => {
                settings.correlation = correlation;
                unknown_keys.extend(keys.into_iter().map(|key| UnknownKey {
                    file: "correlation.yaml",
                    key,
                }));
            }
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) => {}
            Err(error) => return Err(error.context(failed("correlation.yaml"))),
        }
        // A present alerting.yaml replaces inline alerting. Either one gets the
        // destination checks reload and the alerting editor apply.
        let mut alerting_source = "prefixd.yaml";
        match crate::alerting::AlertingConfig::load_with_unknown_keys(path("alerting.yaml")) {
            Ok((alerting, keys)) => {
                settings.alerting = alerting;
                alerting_source = "alerting.yaml";
                unknown_keys.extend(keys.into_iter().map(|key| UnknownKey {
                    file: "alerting.yaml",
                    key,
                }));
            }
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) => {}
            Err(error) => return Err(error.context(failed("alerting.yaml"))),
        }
        let errors = settings.alerting.validate();
        if !errors.is_empty() {
            anyhow::bail!(
                "{}: alerting: {}",
                failed(alerting_source),
                errors.join("; ")
            );
        }
        let inventory =
            Inventory::load(path("inventory.yaml")).with_context(|| failed("inventory.yaml"))?;
        let playbooks =
            Playbooks::load(path("playbooks.yaml")).with_context(|| failed("playbooks.yaml"))?;

        Ok(Self {
            settings,
            inventory,
            playbooks,
            alerting_source,
            unknown_keys,
        })
    }

    /// Validate every file startup loads and report all errors, without
    /// connecting to PostgreSQL or the speaker. Checks that need a live
    /// speaker are listed in [`CHECK_CONFIG_SKIPPED`] instead of being faked.
    pub fn check(config_dir: &Path) -> ConfigCheck {
        let path = |name: &str| config_dir.join(name);
        let failed = |name: &str| format!("failed to load {}", path(name).display());
        let mut check = ConfigCheck::default();

        let mut settings = None;
        match std::fs::read_to_string(path("prefixd.yaml")) {
            Err(error) => check
                .errors
                .push(format!("{}: {error}", failed("prefixd.yaml"))),
            Ok(content) => match Settings::from_yaml(&content) {
                Ok((loaded, keys)) => {
                    check.validated.push("prefixd.yaml");
                    check
                        .unknown_keys
                        .extend(keys.into_iter().map(|key| UnknownKey {
                            file: "prefixd.yaml",
                            key,
                        }));
                    for error in loaded.validate_errors() {
                        check
                            .errors
                            .push(format!("{}: {error}", failed("prefixd.yaml")));
                    }
                    settings = Some(loaded);
                }
                Err(error) => check
                    .errors
                    .push(format!("{}: {error:#}", failed("prefixd.yaml"))),
            },
        }
        // Startup refuses before connecting when neither source names a
        // database; that gate reads the same environment override.
        if let Some(loaded) = &settings
            && loaded.storage.connection_string.is_empty()
            && std::env::var("DATABASE_URL")
                .ok()
                .filter(|url| !url.is_empty())
                .is_none()
        {
            check
                .errors
                .push("set DATABASE_URL or storage.connection_string".to_string());
        }

        match std::fs::read_to_string(path("correlation.yaml")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => check
                .errors
                .push(format!("{}: {error}", failed("correlation.yaml"))),
            Ok(content) => match crate::correlation::CorrelationConfig::from_yaml(&content) {
                Ok((correlation, keys)) => {
                    check.validated.push("correlation.yaml");
                    check
                        .unknown_keys
                        .extend(keys.into_iter().map(|key| UnknownKey {
                            file: "correlation.yaml",
                            key,
                        }));
                    let errors = correlation.validate();
                    if !errors.is_empty() {
                        check.errors.push(format!(
                            "{}: invalid correlation config: {}",
                            failed("correlation.yaml"),
                            errors.join("; ")
                        ));
                    }
                }
                Err(error) => check
                    .errors
                    .push(format!("{}: {error:#}", failed("correlation.yaml"))),
            },
        }

        // A present alerting.yaml replaces inline alerting, exactly as startup
        // resolves it before validating the effective destinations.
        let mut alerting_source = "prefixd.yaml";
        match std::fs::read_to_string(path("alerting.yaml")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => check
                .errors
                .push(format!("{}: {error}", failed("alerting.yaml"))),
            Ok(content) => match crate::alerting::AlertingConfig::from_yaml(&content) {
                Ok((alerting, keys)) => {
                    check.validated.push("alerting.yaml");
                    alerting_source = "alerting.yaml";
                    check
                        .unknown_keys
                        .extend(keys.into_iter().map(|key| UnknownKey {
                            file: "alerting.yaml",
                            key,
                        }));
                    let errors = alerting.load_errors();
                    if !errors.is_empty() {
                        check.errors.push(format!(
                            "{}: {}",
                            failed("alerting.yaml"),
                            errors.join("; ")
                        ));
                    }
                    if let Some(settings) = settings.as_mut() {
                        settings.alerting = alerting;
                    }
                }
                Err(error) => check
                    .errors
                    .push(format!("{}: {error:#}", failed("alerting.yaml"))),
            },
        }
        if let Some(settings) = &settings {
            let errors = settings.alerting.validate();
            if !errors.is_empty() {
                check.errors.push(format!(
                    "{}: alerting: {}",
                    failed(alerting_source),
                    errors.join("; ")
                ));
            }
        }

        for name in ["inventory.yaml", "playbooks.yaml"] {
            match std::fs::read_to_string(path(name)) {
                Err(error) => check.errors.push(format!("{}: {error}", failed(name))),
                Ok(content) if name == "inventory.yaml" => match Inventory::from_yaml(&content) {
                    Ok(_) => check.validated.push("inventory.yaml"),
                    Err(error) => check
                        .errors
                        .push(format!("{}: {error:#}", failed("inventory.yaml"))),
                },
                Ok(content) => match Playbooks::from_yaml(&content) {
                    Ok(playbooks) => {
                        check.validated.push("playbooks.yaml");
                        if let Some(settings) = &settings {
                            check.warnings.extend(
                                playbooks
                                    .prefix_scope_warnings(&settings.guardrails)
                                    .into_iter()
                                    .map(|warning| format!("playbooks.yaml: {warning}")),
                            );
                        }
                    }
                    Err(error) => check
                        .errors
                        .push(format!("{}: {error:#}", failed("playbooks.yaml"))),
                },
            }
        }

        check
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sections `Settings` requires, with values that pass every cross-check.
    const REQUIRED: &[(&str, &str)] = &[
        (
            "http",
            "http: {listen: '127.0.0.1:8080', auth: {mode: none}}",
        ),
        ("bgp", "bgp: {local_asn: 65010, router_id: 192.0.2.1}"),
        ("guardrails", "guardrails: {require_ttl: true}"),
        ("quotas", "quotas: {max_active_per_customer: 20}"),
        ("timers", "timers: {default_ttl_seconds: 120}"),
        ("observability", "observability: {log_level: info}"),
    ];

    /// A document with every required section: `overrides` replace the
    /// sections they name, and anything else is appended as a new section.
    fn settings_document(overrides: &[(&str, &str)]) -> String {
        let mut document = String::from("pop: iad1\n");
        for (name, default) in REQUIRED {
            let text = overrides
                .iter()
                .find(|(other, _)| other == name)
                .map_or(*default, |(_, text)| *text);
            document.push_str(text);
            document.push('\n');
        }
        for (name, text) in overrides {
            if !REQUIRED.iter().any(|(required, _)| required == name) {
                document.push_str(text);
                document.push('\n');
            }
        }
        document
    }

    fn settings_unknown_keys(document: &str) -> Vec<String> {
        Settings::from_yaml(document)
            .expect("document must parse")
            .1
    }

    /// A typo in every section that this release only warns about is reported
    /// with its full key path. Sections that already reject unknown keys have
    /// their own test below.
    #[test]
    fn unknown_keys_are_reported_with_their_section_path() {
        let cases = [
            (
                "settings",
                "root",
                "guardrailsx: {max_port: 1}",
                "guardrailsx",
            ),
            (
                "http",
                "http",
                "http: {listen: '127.0.0.1:8080', auth: {mode: none}, max_body: 1}",
                "http.max_body",
            ),
            (
                "auth",
                "http",
                "http: {listen: '127.0.0.1:8080', auth: {mode: none, token: x}}",
                "http.auth.token",
            ),
            (
                "guardrails",
                "guardrails",
                "guardrails: {max_port: 5}",
                "guardrails.max_port",
            ),
            (
                "quotas",
                "quotas",
                "quotas: {maxactive: 2}",
                "quotas.maxactive",
            ),
            ("timers", "timers", "timers: {ttl: 120}", "timers.ttl"),
            (
                "storage",
                "storage",
                "storage: {dsn: postgres://ignored}",
                "storage.dsn",
            ),
            (
                "safelist",
                "safelist",
                "safelist: {prefix: [10.0.0.0/8]}",
                "safelist.prefix",
            ),
            (
                "alerting",
                "alerting",
                "alerting: {event: [mitigation.created]}",
                "alerting.event",
            ),
            (
                "correlation",
                "correlation",
                "correlation: {windows: 30}",
                "correlation.windows",
            ),
        ];
        for (section, name, text, expected) in cases {
            let document = settings_document(&[(name, text)]);
            assert_eq!(
                settings_unknown_keys(&document),
                vec![expected.to_string()],
                "{section}"
            );
        }
    }

    /// `bgp`, `observability`, `blackhole`, `amplification` and `shutdown`
    /// already refuse unknown keys; the following release extends that refusal
    /// to every section.
    #[test]
    fn strict_sections_still_refuse_unknown_keys_by_path() {
        let cases = [
            (
                "bgp",
                "bgp",
                "bgp: {local_asn: 65010, router_id: 192.0.2.1, asn: 65010}",
                "asn",
            ),
            (
                "observability",
                "observability",
                "observability: {log_levle: info}",
                "log_levle",
            ),
            (
                "blackhole",
                "blackhole",
                "blackhole: {lease_second: 60}",
                "lease_second",
            ),
            (
                "amplification",
                "amplification",
                "amplification: {port: 53}",
                "port",
            ),
            (
                "shutdown",
                "shutdown",
                "shutdown: {drain_timeout_second: 30}",
                "drain_timeout_second",
            ),
            ("scrubber", "scrubber", "scrubber: {profile: []}", "profile"),
        ];
        for (section, name, text, key) in cases {
            let document = settings_document(&[(name, text)]);
            let error = Settings::from_yaml(&document).unwrap_err();
            let error = format!("{error:#}");
            assert!(
                error.contains(&format!("unknown field `{key}`")),
                "{section}: {error}"
            );
        }
    }

    /// Destination variants are internally tagged, so the alerting module
    /// checks their keys: a `chanel:` typo is reported under its destination.
    #[test]
    fn alerting_destination_typos_are_reported_with_their_path() {
        let document = settings_document(&[(
            "alerting",
            "alerting:\n  destinations:\n    - type: slack\n      \
             webhook_url: https://example.invalid/hook\n      chanel: ops",
        )]);
        assert_eq!(
            settings_unknown_keys(&document),
            vec!["alerting.destinations[0].chanel"]
        );
        let (_, keys) = crate::alerting::AlertingConfig::from_yaml(
            "destinations:\n  - type: generic\n    url: https://example.invalid/hook\n    event: mitigation.created\n",
        )
        .unwrap();
        assert_eq!(keys, vec!["destinations[0].event"]);
    }

    /// Unknown-key reports carry the path only: a typo beside a secret never
    /// repeats the secret, inline or in `alerting.yaml`.
    #[test]
    fn unknown_keys_never_report_values() {
        const CANARY: &str = "hunter2-canary";
        let alerting = format!(
            "alerting:\n  destinations:\n    - type: generic\n      \
             url: https://example.invalid/hook?token={CANARY}\n      chanel: ops"
        );
        let inline = settings_document(&[("alerting", alerting.as_str())]);
        let keys = settings_unknown_keys(&inline);
        assert_eq!(keys, vec!["alerting.destinations[0].chanel"]);
        assert!(!keys.join(" ").contains(CANARY));
        let (_, keys) = crate::alerting::AlertingConfig::from_yaml(&format!(
            "destinations:\n  - type: generic\n    url: https://example.invalid/hook?token={CANARY}\n    chanel: ops\n"
        ))
        .unwrap();
        assert_eq!(keys, vec!["destinations[0].chanel"]);
        assert!(!keys.join(" ").contains(CANARY));
        // The value of an unknown key is never read, so it cannot leak either.
        let keys = settings_unknown_keys(&settings_document(&[(
            "guardrails",
            &format!("guardrails: {{max_port: {CANARY}}}"),
        )]));
        assert_eq!(keys, vec!["guardrails.max_port"]);
        assert!(!keys.join(" ").contains(CANARY));
    }

    /// The configuration the repository ships has no key this release would
    /// only warn about, so an upgrade from a shipped file is quiet.
    #[test]
    fn shipped_configurations_have_no_unknown_keys() {
        for (name, document) in [
            ("prefixd.yaml", include_str!("../../configs/prefixd.yaml")),
            (
                "prefixd-gobgp.yaml",
                include_str!("../../configs/prefixd-gobgp.yaml"),
            ),
            (
                "prefixd.yaml.example",
                include_str!("../../configs/prefixd.yaml.example"),
            ),
        ] {
            let (_, keys) = Settings::from_yaml(document).expect(name);
            assert!(keys.is_empty(), "{name}: {keys:?}");
        }
        let (_, keys) = crate::correlation::CorrelationConfig::from_yaml(include_str!(
            "../../configs/correlation.yaml"
        ))
        .unwrap();
        assert!(keys.is_empty(), "correlation.yaml: {keys:?}");
    }

    /// The check accepts a valid directory and names what it validated.
    #[test]
    fn check_accepts_a_valid_directory() {
        let directory = fixture();
        let check = AppConfig::check(directory.path());
        assert!(check.is_ok(), "{:?}", check.errors);
        assert!(check.unknown_keys.is_empty());
        assert_eq!(
            check.validated,
            vec!["prefixd.yaml", "inventory.yaml", "playbooks.yaml"]
        );
        let summary = check.summary();
        assert!(summary.contains("configuration OK"), "{summary}");
        assert!(summary.contains("prefixd.yaml"), "{summary}");
    }

    /// Every error is reported, not just the first, and unknown keys are
    /// reported beside them.
    #[test]
    fn check_reports_all_errors_and_unknown_keys() {
        let directory = fixture();
        let mut settings: Settings =
            parse_yaml(include_str!("../../configs/prefixd.yaml")).unwrap();
        settings.correlation.confidence_threshold = 0.5;
        settings.quotas.max_active_prefix_per_customer = 0;
        settings.blackhole.lease_seconds = 2;
        let mut document = serde_saphyr::to_string(&settings).unwrap();
        document.push_str("guardrailsx: {max_port: 1}\n");
        std::fs::write(directory.path().join("prefixd.yaml"), document).unwrap();
        std::fs::write(
            directory.path().join("correlation.yaml"),
            "close_after: 5\n",
        )
        .unwrap();

        let check = AppConfig::check(directory.path());
        assert!(!check.is_ok());
        let keys: Vec<_> = check
            .unknown_keys
            .iter()
            .map(|key| key.to_string())
            .collect();
        assert_eq!(
            keys,
            vec![
                "prefixd.yaml: unknown key `guardrailsx`; ignored in this release, refused in the next",
                "correlation.yaml: unknown key `close_after`; ignored in this release, refused in the next",
            ]
        );
        assert_eq!(check.errors.len(), 2, "{:?}", check.errors);
        let errors = check.errors.join("\n");
        assert!(
            errors.contains("quotas.max_active_prefix_per_customer must be nonzero"),
            "{errors}"
        );
        assert!(
            errors.contains("blackhole.lease_seconds must be 5..=3600, got 2"),
            "{errors}"
        );
        for error in &check.errors {
            assert!(
                error.starts_with(&format!(
                    "failed to load {}",
                    directory.path().join("prefixd.yaml").display()
                )),
                "{error}"
            );
        }
    }

    /// `alerting.yaml` replaces inline alerting, exactly as startup resolves it,
    /// and its unknown keys are reported under that file.
    #[test]
    fn check_reports_standalone_alerting_unknown_keys_and_errors() {
        let directory = fixture();
        std::fs::write(
            directory.path().join("alerting.yaml"),
            "destinations:\n  - type: generic\n    url: http://example.invalid/hook\n    chanel: ops\n",
        )
        .unwrap();
        let check = AppConfig::check(directory.path());
        assert!(!check.is_ok());
        assert_eq!(
            check
                .unknown_keys
                .iter()
                .map(|key| key.to_string())
                .collect::<Vec<_>>(),
            vec![
                "alerting.yaml: unknown key `destinations[0].chanel`; ignored in this release, refused in the next"
            ]
        );
        assert_eq!(check.errors.len(), 1, "{:?}", check.errors);
        assert!(
            check.errors[0].contains("alerting.yaml"),
            "{:?}",
            check.errors
        );
        assert!(
            check.errors[0].contains("url must use https"),
            "{:?}",
            check.errors
        );
    }

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
    fn startup_rejects_unreadable_standalone_alerting() {
        let directory = fixture();
        assert_eq!(
            AppConfig::load(directory.path()).unwrap().alerting_source,
            "prefixd.yaml"
        );
        std::fs::create_dir(directory.path().join("alerting.yaml")).unwrap();
        let error = format!("{:#}", AppConfig::load(directory.path()).unwrap_err());
        assert!(error.contains("alerting.yaml"), "{error}");
    }

    #[test]
    fn startup_rejects_invalid_standalone_correlation() {
        let directory = fixture();
        std::fs::write(
            directory.path().join("correlation.yaml"),
            "window_seconds: 0\n",
        )
        .unwrap();
        let error = format!("{:#}", AppConfig::load(directory.path()).unwrap_err());
        assert!(error.contains("correlation.yaml"), "{error}");
        assert!(error.contains("window_seconds must be > 0"), "{error}");
    }

    /// A startup error names the file and the unknown key.
    #[test]
    fn startup_error_names_file_and_unknown_key() {
        let directory = fixture();
        let path = directory.path().join("playbooks.yaml");
        let playbooks = std::fs::read_to_string(&path).unwrap().replacen(
            "    match:\n",
            "    match:\n      source: fastnetmon\n",
            1,
        );
        std::fs::write(&path, playbooks).unwrap();
        let error = format!("{:#}", AppConfig::load(directory.path()).unwrap_err());
        assert!(error.contains("playbooks.yaml"), "{error}");
        assert!(error.contains("unknown field `source`"), "{error}");
    }

    fn alerting(url: &str) -> String {
        format!("destinations:\n  - type: generic\n    url: \"{url}\"\n")
    }

    /// Startup applies reload's destination checks before contacting PostgreSQL
    /// or the speaker, and the error names the key, never the URL.
    #[test]
    fn startup_rejects_unsafe_standalone_alerting_destinations() {
        for (url, reason) in [
            (
                "http://example.com/hook?token=request-secret",
                "url must use https",
            ),
            (
                "https://10.0.0.1/hook?token=request-secret",
                "url host IP is not allowed",
            ),
        ] {
            let directory = fixture();
            let path = directory.path().join("alerting.yaml");
            std::fs::write(&path, alerting(url)).unwrap();
            // The low-level loader, the old startup path, accepts the URL.
            crate::alerting::AlertingConfig::load(&path).unwrap();
            let error = format!("{:#}", AppConfig::load(directory.path()).unwrap_err());
            assert!(error.contains("alerting.yaml"), "{error}");
            assert!(error.contains(reason), "{error}");
            assert!(!error.contains("request-secret"), "{error}");
        }
    }

    #[test]
    fn startup_rejects_unsafe_inline_alerting_destination() {
        let directory = fixture();
        let path = directory.path().join("prefixd.yaml");
        let mut settings: Settings =
            crate::config::parse_yaml(&std::fs::read_to_string(&path).unwrap()).unwrap();
        settings.alerting =
            crate::config::parse_yaml(&alerting("http://example.com/hook?token=request-secret"))
                .unwrap();
        std::fs::write(&path, serde_saphyr::to_string(&settings).unwrap()).unwrap();
        // The low-level settings loader accepts the URL.
        Settings::load(&path).unwrap();
        let error = format!("{:#}", AppConfig::load(directory.path()).unwrap_err());
        assert!(error.contains("prefixd.yaml: alerting:"), "{error}");
        assert!(error.contains("url must use https"), "{error}");
        assert!(!error.contains("request-secret"), "{error}");

        // A valid alerting.yaml replaces the inline section, so startup proceeds.
        std::fs::write(
            directory.path().join("alerting.yaml"),
            alerting("https://example.com/hook"),
        )
        .unwrap();
        let config = AppConfig::load(directory.path()).unwrap();
        assert_eq!(config.alerting_source, "alerting.yaml");
        assert_eq!(config.settings.alerting.destinations.len(), 1);
        assert!(config.settings.alerting.validate().is_empty());
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
    #[test]
    fn secret_file_parse_errors_name_path_and_location_never_value() {
        const CANARY: &str = "hunter2-canary";
        let check = |error: anyhow::Error, raw: String, expected: &str| {
            // Negative control: the plain parser's error quotes the value.
            assert!(raw.contains(CANARY), "control lost its canary: {raw}");
            let error = format!("{error:#}");
            assert_eq!(error, expected);
            assert!(!error.contains(CANARY));
        };
        let yaml = format!("pop: iad1\nmode: {CANARY}\n");
        check(
            parse_secret_yaml::<Settings>(&yaml).unwrap_err(),
            parse_yaml::<Settings>(&yaml).unwrap_err().to_string(),
            "mode: unknown variant, expected one of dry-run, enforced at line 2 column 7",
        );
        let yaml = format!("destinations: [{{type: {CANARY}}}]\n");
        check(
            parse_secret_yaml::<crate::alerting::AlertingConfig>(&yaml).unwrap_err(),
            parse_yaml::<crate::alerting::AlertingConfig>(&yaml)
                .unwrap_err()
                .to_string(),
            "destinations[0].type: unknown variant, expected one of slack, discord, teams, \
             telegram, pagerduty, opsgenie, generic at line 1 column 17",
        );
        let yaml = format!("webhook_adapters: [{{name: a, auth: {{type: {CANARY}}}}}]\n");
        check(
            parse_secret_yaml::<crate::correlation::CorrelationConfig>(&yaml).unwrap_err(),
            parse_yaml::<crate::correlation::CorrelationConfig>(&yaml)
                .unwrap_err()
                .to_string(),
            "webhook_adapters[0].auth.type: unknown variant, expected one of hmac, bearer, none \
             at line 1 column 37",
        );
        // Syntax, boolean and null failures keep their location but no text.
        for (yaml, expected) in [
            (
                format!("pop: iad1\nhttp: {{listen: \"{CANARY}"),
                "http: YAML syntax error at line 2 column 16",
            ),
            (
                format!("pop: iad1\nguardrails: {{require_ttl: {CANARY}}}\n"),
                "guardrails.require_ttl: expected true or false at line 2 column 27",
            ),
            (
                "pop: ~\n".to_string(),
                "pop: expected a string, found null at line 1 column 6",
            ),
            (
                // A flow-style typo parses as one key; key text stops at `:`.
                format!("pop: iad1\nobservability: {{log_levle:{CANARY}}}\n"),
                "observability.log_levle: unknown field `log_levle` at line 2 column 17",
            ),
        ] {
            let error = format!("{:#}", parse_secret_yaml::<Settings>(&yaml).unwrap_err());
            assert_eq!(error, expected);
        }
        // prefixd's own `try_from` messages pass through unchanged, so a
        // custom deserializer that formats its input shows up in review.
        assert_eq!(
            format!(
                "{:#}",
                parse_secret_yaml::<Settings>(
                    "pop: iad1\nmode: dry-run\nhttp: {listen: x, auth: {mode: none}}\n\
                     bgp: {gobgp_grpc: x, local_asn: 1, router_id: 192.0.2.1}\n"
                )
                .unwrap_err()
            ),
            "bgp: bgp.backend is required when bgp.gobgp_grpc is set; add bgp.backend: gobgp \
             to keep the GoBGP speaker at line 4 column 6"
        );
        // Scalar failures name the type, as the plain parser does.
        assert_eq!(
            format!(
                "{:#}",
                parse_secret_yaml::<Settings>(&format!(
                    "pop: iad1\nstorage: {{connection_string: [\"postgres://a:{CANARY}@db\"]}}\n"
                ))
                .unwrap_err()
            ),
            "storage.connection_string: expected string scalar at line 2 column 30"
        );
        // Key names are not values, so unknown and missing keys stay named.
        assert_eq!(
            format!(
                "{:#}",
                parse_secret_yaml::<Settings>(&format!(
                    "pop: iad1\nobservability: {{log_levle: {CANARY}}}\n"
                ))
                .unwrap_err()
            ),
            "observability.log_levle: unknown field `log_levle` at line 2 column 17"
        );
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
