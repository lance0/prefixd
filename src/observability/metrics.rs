use once_cell::sync::Lazy;
use prometheus::{
    Counter, CounterVec, Encoder, Gauge, GaugeVec, HistogramVec, TextEncoder, register_counter,
    register_counter_vec, register_gauge, register_gauge_vec, register_histogram_vec,
};

// Event metrics
pub static EVENTS_INGESTED: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "prefixd_events_ingested_total",
        "Total number of attack events ingested",
        &["source", "vector"]
    )
    .unwrap()
});

pub static EVENTS_REJECTED: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "prefixd_events_rejected_total",
        "Total number of attack events rejected at ingest",
        &["source", "reason"]
    )
    .unwrap()
});

// Mitigation metrics
pub static MITIGATIONS_ACTIVE: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "prefixd_mitigations_active",
        "Number of currently active mitigations",
        &["action_type", "pop"]
    )
    .unwrap()
});

pub static MITIGATIONS_CREATED: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "prefixd_mitigations_created_total",
        "Total number of mitigations created",
        &["action_type", "pop"]
    )
    .unwrap()
});

pub static MITIGATIONS_EXPIRED: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "prefixd_mitigations_expired_total",
        "Total number of mitigations expired",
        &["action_type", "pop"]
    )
    .unwrap()
});

pub static MITIGATIONS_WITHDRAWN: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "prefixd_mitigations_withdrawn_total",
        "Total number of mitigations withdrawn",
        &["action_type", "pop", "reason"]
    )
    .unwrap()
});

// BGP metrics
pub static ANNOUNCEMENTS_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "prefixd_announcements_total",
        "Total number of BGP announcements",
        &["backend", "status"]
    )
    .unwrap()
});

pub static ANNOUNCEMENTS_LATENCY: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "prefixd_announcements_latency_seconds",
        "BGP announcement latency in seconds",
        &["backend"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
    )
    .unwrap()
});

pub static BGP_SESSION_UP: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "prefixd_bgp_session_up",
        "BGP session state (1 = established, 0 = down)",
        &["backend", "peer"]
    )
    .unwrap()
});

pub static SPEAKER_CAPABILITY: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "prefixd_speaker_capability",
        "Selected speaker capability (1 = available, 0 = unsupported or unconfirmed); not current health or router enforcement",
        &["backend", "capability"]
    )
    .unwrap()
});

/// Bound labels even when a third-party adapter supplies its own backend name.
pub fn backend_label(backend: &str) -> &'static str {
    match backend {
        "rustbgpd" => "rustbgpd",
        "gobgp" => "gobgp",
        "mock" => "mock",
        _ => "other",
    }
}

/// Cheap local capability reads only; a scrape never probes the speaker.
pub fn update_speaker_metrics(speaker: &dyn crate::bgp::FlowSpecAnnouncer) {
    let backend = backend_label(speaker.backend());
    for status in ["announced", "withdrawn"] {
        ANNOUNCEMENTS_TOTAL.with_label_values(&[backend, status]);
    }
    ANNOUNCEMENTS_LATENCY.with_label_values(&[backend]);
    let capabilities = speaker.capabilities();
    for (capability, available) in [
        ("rule_reader", capabilities.rule_reader),
        ("peer_observer", capabilities.peer_observer),
        ("daemon_health", capabilities.daemon_health),
        ("blackhole", capabilities.blackhole),
        ("blackhole_lease", capabilities.blackhole_lease),
        ("blackhole_export", capabilities.blackhole_export),
        ("flowspec_export", capabilities.flowspec_export),
        (
            "flowspec_source_prefix",
            capabilities.flowspec_match.source_prefix,
        ),
        (
            "flowspec_source_ports",
            capabilities.flowspec_match.source_ports,
        ),
        ("flowspec_fragment", capabilities.flowspec_match.fragment),
        (
            "flowspec_packet_length",
            capabilities.flowspec_match.packet_length,
        ),
    ] {
        SPEAKER_CAPABILITY
            .with_label_values(&[backend, capability])
            .set(f64::from(u8::from(available)));
    }
}

// Guardrail metrics
pub static GUARDRAIL_REJECTIONS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "prefixd_guardrail_rejections_total",
        "Total number of guardrail rejections",
        &["reason"]
    )
    .unwrap()
});

/// Bounded rule categories; exact scopes belong in responses and audit entries.
pub static EVENT_RULE_QUOTA_REJECTIONS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "prefixd_event_rule_quota_rejections_total",
        "Event rules refused by active quotas, by quota, match kind and action",
        &["quota_type", "rule_kind", "action_type"]
    )
    .unwrap()
});

// Controller fence metrics (ADR 027)
pub static CONTROLLER_FENCE_ACTIVE: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "prefixd_controller_fence_active",
        "1 while this controller holds its POP's fence and may mutate the speaker, 0 in standby"
    )
    .unwrap()
});

/// 1 when enforced detector blackholes run without the rustbgpd injection lease (ADR 027).
pub static BLACKHOLE_DETECTOR_UNLEASED: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "prefixd_blackhole_detector_unleased",
        "1 when enforced detector blackholes run without the rustbgpd injection lease and can outlive a stopped controller"
    )
    .unwrap()
});

/// Unleased admissions that replaced an untracked local route, by configured POP.
pub static BLACKHOLE_REPLACED: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "prefixd_blackhole_replaced_total",
        "Unleased blackhole admissions that replaced an untracked local route, by POP",
        &["pop"]
    )
    .unwrap()
});

/// Injection lease renewals by result: success, not_live (FAILED_PRECONDITION) or error (ADR 027).
pub static INJECTION_LEASE_RENEWALS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "prefixd_injection_lease_renewals_total",
        "RenewLease results for this controller's injection owner: success, not_live or error",
        &["result"]
    )
    .unwrap()
});

/// One-hot injection lease state: none, live, renewal_failing or expired (ADR 027).
pub static INJECTION_LEASE_STATE: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "prefixd_injection_lease_state",
        "1 for this controller's current injection lease state (none, live, renewal_failing, expired), 0 for the others",
        &["state"]
    )
    .unwrap()
});

/// Established-peer export dispositions summed over active enforced blackholes,
/// from the last reconciliation pass. Committed is Adj-RIB-Out, not enforcement.
pub static BLACKHOLE_EXPORT_PEERS: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "prefixd_blackhole_export_peers",
        "Established-peer export dispositions (committed, withheld, pending) summed over active blackholes; committed means the peer's Adj-RIB-Out, not router enforcement",
        &["disposition"]
    )
    .unwrap()
});

/// Active enforced blackholes committed to no Established peer, by bounded reason.
pub static BLACKHOLE_UNEXPORTED: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "prefixd_blackhole_unexported",
        "Active blackholes the speaker committed to no Established peer at the last reconciliation pass, by reason",
        &["reason"]
    )
    .unwrap()
});

/// Active enforced blackholes whose export read failed at the last pass.
pub static BLACKHOLE_EXPORT_READ_ERRORS: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "prefixd_blackhole_export_read_errors",
        "Active blackholes whose export disposition read failed at the last reconciliation pass; their export is unknown"
    )
    .unwrap()
});

/// Established-peer dispositions summed over active enforced FlowSpec rules.
pub static FLOWSPEC_EXPORT_PEERS: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "prefixd_flowspec_export_peers",
        "Established-peer export dispositions summed over active FlowSpec rules; committed means Adj-RIB-Out, not enforcement",
        &["disposition"]
    ).unwrap()
});

/// FlowSpec rules committed to no Established peer, by the closed reason set.
pub static FLOWSPEC_UNEXPORTED: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "prefixd_flowspec_unexported",
        "Active FlowSpec rules committed to no Established peer at the last reconciliation pass, by reason",
        &["reason"]
    ).unwrap()
});

/// Failed FlowSpec export reads in the last pass: current export is unknown.
pub static FLOWSPEC_EXPORT_READ_ERRORS: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "prefixd_flowspec_export_read_errors",
        "FlowSpec export read failures; unknown inventory counts retained rules or one inventory-level failure before any keys are known"
    )
    .unwrap()
});

/// Publish only evidence belonging to the held ownership epoch. The caller keeps
/// the fence read lock through publication and, for HTTP, encoding the scrape.
pub fn update_export_metrics(state: &crate::state::AppState, epoch: Option<u64>) {
    for (store, peers, unexported, errors) in [
        (
            &state.export_evidence,
            &*BLACKHOLE_EXPORT_PEERS,
            &*BLACKHOLE_UNEXPORTED,
            &*BLACKHOLE_EXPORT_READ_ERRORS,
        ),
        (
            &state.flowspec_export_evidence,
            &*FLOWSPEC_EXPORT_PEERS,
            &*FLOWSPEC_UNEXPORTED,
            &*FLOWSPEC_EXPORT_READ_ERRORS,
        ),
    ] {
        let summary = store.current_summary(epoch);
        for disposition in crate::bgp::ExportDisposition::ALL {
            peers
                .with_label_values(&[disposition.as_str()])
                .set(summary.counts.get(disposition) as f64);
        }
        for reason in crate::domain::UNEXPORTED_REASONS {
            let count = summary
                .unexported
                .iter()
                .filter(|route| route.warning.reason == reason)
                .count();
            unexported.with_label_values(&[reason]).set(count as f64);
        }
        errors.set(summary.errors as f64);
    }
}

// Reconciliation metrics
pub static RECONCILIATION_RUNS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "prefixd_reconciliation_runs_total",
        "Total number of reconciliation loop runs",
        &["status"]
    )
    .unwrap()
});

pub static RECONCILIATION_REPAIRS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "prefixd_reconciliation_repairs_total",
        "Missing or differing-action local announcement repair attempts, by RPC outcome (not router enforcement)",
        &["status"]
    )
    .unwrap()
});

/// Serializes unit tests that assert on these process-global series.
#[cfg(test)]
pub(crate) static METRICS_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub static UNKNOWN_LOCAL_ROUTES: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "prefixd_unknown_local_routes",
        "Local speaker routes prefixd does not own, reported and never modified, from the last successful read",
        &["kind"]
    )
    .unwrap()
});

pub static RECONCILIATION_ACTIVE_COUNT: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "prefixd_reconciliation_active_count",
        "Number of active mitigations seen during last reconciliation",
        &["pop"]
    )
    .unwrap()
});

// Config reload metrics
pub static CONFIG_RELOADS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "prefixd_config_reload_total",
        "Total number of configuration reloads",
        &["status"]
    )
    .unwrap()
});

// Escalation metrics
pub static ESCALATIONS_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "prefixd_escalations_total",
        "Total number of mitigations escalated",
        &["from_action", "to_action", "pop"]
    )
    .unwrap()
});

// Database metrics
pub static ROW_PARSE_ERRORS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "prefixd_db_row_parse_errors_total",
        "Count of database rows that failed to parse",
        &["table"]
    )
    .unwrap()
});

// Database pool metrics
pub static DB_POOL_SIZE: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "prefixd_db_pool_connections",
        "Database connection pool size",
        &["state"]
    )
    .unwrap()
});

// HTTP metrics
pub static HTTP_REQUESTS_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "prefixd_http_requests_total",
        "Total HTTP requests",
        &["method", "route", "status_class"]
    )
    .unwrap()
});

pub static HTTP_REQUEST_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "prefixd_http_request_duration_seconds",
        "HTTP request duration in seconds",
        &["method", "route", "status_class"],
        vec![
            0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0
        ]
    )
    .unwrap()
});

pub static HTTP_IN_FLIGHT: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "prefixd_http_in_flight_requests",
        "In-flight HTTP requests",
        &["method", "route"]
    )
    .unwrap()
});

// ── Correlation engine metrics ─────────────────────────────────────────

/// Total signal groups created, by status and vector.
pub static SIGNAL_GROUPS_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "prefixd_signal_groups_total",
        "Total number of signal groups created",
        &["status", "vector"]
    )
    .unwrap()
});

/// Histogram of source count per signal group (observed when group resolves/expires).
pub static SIGNAL_GROUP_SOURCES: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "prefixd_signal_group_sources",
        "Number of distinct sources per signal group",
        &["vector"],
        vec![1.0, 2.0, 3.0, 4.0, 5.0, 8.0, 10.0]
    )
    .unwrap()
});

/// Histogram of derived confidence values per signal group.
pub static CORRELATION_CONFIDENCE: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "prefixd_correlation_confidence",
        "Derived confidence of signal groups",
        &["vector"],
        vec![0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    )
    .unwrap()
});

/// Counter for signal groups that met corroboration requirements.
pub static CORROBORATION_MET_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "prefixd_corroboration_met_total",
        "Total signal groups that met corroboration requirements",
        &["vector"]
    )
    .unwrap()
});

/// Counter for signal groups that expired without meeting corroboration.
pub static CORROBORATION_TIMEOUT_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "prefixd_corroboration_timeout_total",
        "Total signal groups that expired without meeting corroboration",
        &["vector"]
    )
    .unwrap()
});

/// Counter for corroborating signals ingested (before any match check).
pub static CORROBORATOR_INGESTED_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "prefixd_corroborator_ingested_total",
        "Total corroborating signals ingested via /v1/signals/corroborator",
        &["source"]
    )
    .unwrap()
});

/// Counter for corroborating signals successfully attached to a signal group,
/// either immediately at ingest or later by cache drain.
pub static CORROBORATOR_ATTACHED_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "prefixd_corroborator_attached_total",
        "Total corroborating signals attached to a signal group",
        &["source"]
    )
    .unwrap()
});

/// Counter for corroborating signals that expired without ever attaching
/// to a signal group (swept by the cache reaper).
pub static CORROBORATOR_EXPIRED_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "prefixd_corroborator_expired_total",
        "Corroborating signals removed by cache sweep without ever attaching",
        &["source"]
    )
    .unwrap()
});

/// Currently-cached, unattached, unexpired corroborating signals by source.
/// Updated by the reconcile loop every tick after the sweep. Operators can
/// alert on this gauge growing without bound (e.g. a source posting heavily
/// while no matching primary event ever lands).
pub static CORROBORATOR_CACHE_SIZE: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "prefixd_corroborator_cache_size",
        "Currently-cached unattached corroborating signals, by source",
        &["source"]
    )
    .unwrap()
});

/// Counter of confidence-decay refresh sweeps performed by the
/// reconciliation loop (one sample per tick, regardless of how many groups
/// were refreshed). Useful as a heartbeat for ADR 022 plumbing.
pub static SIGNAL_GROUP_DECAY_REFRESHES_TOTAL: Lazy<Counter> = Lazy::new(|| {
    register_counter!(
        "prefixd_signal_group_decay_refreshes_total",
        "Number of reconcile-loop ticks that refreshed decayed confidence for open signal groups"
    )
    .unwrap()
});

/// Generate Prometheus metrics output
pub fn gather_metrics() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

/// Initialize all metrics (forces lazy statics to be created). The configured
/// POP's replacement counter is exported at zero so increase() sees its first
/// replacement.
pub fn init_metrics(pop: &str) {
    // Touch all lazy statics to initialize them
    Lazy::force(&crate::alerting::ALERTS_SENT);
    Lazy::force(&EVENTS_INGESTED);
    Lazy::force(&EVENTS_REJECTED);
    Lazy::force(&MITIGATIONS_ACTIVE);
    Lazy::force(&MITIGATIONS_CREATED);
    Lazy::force(&MITIGATIONS_EXPIRED);
    Lazy::force(&MITIGATIONS_WITHDRAWN);
    Lazy::force(&ANNOUNCEMENTS_TOTAL);
    Lazy::force(&ANNOUNCEMENTS_LATENCY);
    Lazy::force(&BGP_SESSION_UP);
    Lazy::force(&SPEAKER_CAPABILITY);
    Lazy::force(&GUARDRAIL_REJECTIONS);
    Lazy::force(&EVENT_RULE_QUOTA_REJECTIONS);
    Lazy::force(&CONTROLLER_FENCE_ACTIVE);
    Lazy::force(&BLACKHOLE_DETECTOR_UNLEASED);
    BLACKHOLE_REPLACED.with_label_values(&[pop]);
    for result in ["success", "not_live", "error"] {
        INJECTION_LEASE_RENEWALS.with_label_values(&[result]);
    }
    for state in crate::domain::LeaseState::ALL {
        INJECTION_LEASE_STATE.with_label_values(&[state.as_str()]);
    }
    for disposition in crate::bgp::ExportDisposition::ALL {
        BLACKHOLE_EXPORT_PEERS.with_label_values(&[disposition.as_str()]);
        FLOWSPEC_EXPORT_PEERS.with_label_values(&[disposition.as_str()]);
    }
    for reason in crate::domain::UNEXPORTED_REASONS {
        BLACKHOLE_UNEXPORTED.with_label_values(&[reason]);
        FLOWSPEC_UNEXPORTED.with_label_values(&[reason]);
    }
    Lazy::force(&BLACKHOLE_EXPORT_READ_ERRORS);
    Lazy::force(&FLOWSPEC_EXPORT_READ_ERRORS);
    Lazy::force(&RECONCILIATION_RUNS);
    Lazy::force(&RECONCILIATION_REPAIRS);
    for status in ["success", "error"] {
        RECONCILIATION_RUNS.with_label_values(&[status]);
        RECONCILIATION_REPAIRS.with_label_values(&[status]);
    }
    Lazy::force(&RECONCILIATION_ACTIVE_COUNT);
    Lazy::force(&UNKNOWN_LOCAL_ROUTES);
    Lazy::force(&CONFIG_RELOADS);
    Lazy::force(&ESCALATIONS_TOTAL);
    Lazy::force(&ROW_PARSE_ERRORS);
    Lazy::force(&DB_POOL_SIZE);
    Lazy::force(&HTTP_REQUESTS_TOTAL);
    Lazy::force(&HTTP_REQUEST_DURATION);
    Lazy::force(&HTTP_IN_FLIGHT);
    // Correlation engine metrics
    Lazy::force(&SIGNAL_GROUPS_TOTAL);
    Lazy::force(&SIGNAL_GROUP_SOURCES);
    Lazy::force(&CORRELATION_CONFIDENCE);
    Lazy::force(&CORROBORATION_MET_TOTAL);
    Lazy::force(&CORROBORATION_TIMEOUT_TOTAL);
    Lazy::force(&CORROBORATOR_INGESTED_TOTAL);
    Lazy::force(&CORROBORATOR_ATTACHED_TOTAL);
    Lazy::force(&CORROBORATOR_EXPIRED_TOTAL);
    Lazy::force(&CORROBORATOR_CACHE_SIZE);
    Lazy::force(&SIGNAL_GROUP_DECAY_REFRESHES_TOTAL);
}

/// Update database pool metrics from sqlx pool stats
pub fn update_db_pool_metrics(pool: &sqlx::PgPool) {
    let size = pool.size() as f64;
    let idle = pool.num_idle() as f64;
    let active = size - idle;
    DB_POOL_SIZE.with_label_values(&["active"]).set(active);
    DB_POOL_SIZE.with_label_values(&["idle"]).set(idle);
    DB_POOL_SIZE.with_label_values(&["total"]).set(size);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::{FlowSpecAnnouncer, FlowSpecWriter, InjectionLeases, MockAnnouncer};

    #[test]
    fn init_exports_the_configured_pop_replacement_counter_at_zero() {
        super::init_metrics("init-zero-pop");
        let expected = r#"prefixd_blackhole_replaced_total{pop="init-zero-pop"} 0"#;
        assert!(super::gather_metrics().lines().any(|line| line == expected));
    }

    #[tokio::test]
    async fn speaker_metrics_bound_labels_and_report_actual_capabilities_without_probing() {
        let _guard = METRICS_TEST_LOCK.lock().await;
        struct WriteOnly;
        impl FlowSpecAnnouncer for WriteOnly {
            fn backend(&self) -> &'static str {
                "third-party-speaker"
            }
        }
        #[async_trait::async_trait]
        impl FlowSpecWriter for WriteOnly {
            async fn announce(&self, _: &crate::domain::FlowSpecRule) -> crate::error::Result<()> {
                unreachable!("a scrape must not mutate the speaker")
            }
            async fn withdraw(&self, _: &crate::domain::FlowSpecRule) -> crate::error::Result<()> {
                unreachable!("a scrape must not mutate the speaker")
            }
        }
        for backend in ["rustbgpd", "gobgp", "mock"] {
            assert_eq!(backend_label(backend), backend);
        }
        assert_eq!(backend_label("third-party-speaker"), "other");
        assert_eq!(backend_label("another-private-name"), "other");
        update_speaker_metrics(&WriteOnly);
        for capability in [
            "rule_reader",
            "peer_observer",
            "blackhole",
            "blackhole_lease",
        ] {
            assert_eq!(
                SPEAKER_CAPABILITY
                    .with_label_values(&["other", capability])
                    .get(),
                0.0
            );
        }
        let speaker = MockAnnouncer::new();
        update_speaker_metrics(&speaker);
        assert!(!speaker.lease_confirmed(), "a scrape must not probe leases");
        for (capability, expected) in [
            ("rule_reader", 1.0),
            ("peer_observer", 1.0),
            ("daemon_health", 0.0),
            ("blackhole", 1.0),
            ("blackhole_lease", 0.0),
            ("blackhole_export", 1.0),
            ("flowspec_export", 1.0),
            ("flowspec_source_prefix", 1.0),
            ("flowspec_source_ports", 1.0),
            ("flowspec_fragment", 1.0),
            ("flowspec_packet_length", 1.0),
        ] {
            assert_eq!(
                SPEAKER_CAPABILITY
                    .with_label_values(&["mock", capability])
                    .get(),
                expected
            );
        }
        speaker.live_lease("metrics-test").await.unwrap();
        update_speaker_metrics(&speaker);
        assert_eq!(
            SPEAKER_CAPABILITY
                .with_label_values(&["mock", "blackhole_lease"])
                .get(),
            1.0
        );
        let scrape = gather_metrics();
        assert!(
            scrape.contains(r#"prefixd_announcements_total{backend="other",status="announced"} 0"#)
        );
        assert!(
            scrape.contains(r#"prefixd_announcements_latency_seconds_count{backend="other"} 0"#)
        );
        assert!(!scrape.contains("third-party-speaker"));
        assert!(!scrape.contains("another-private-name"));
    }
}
