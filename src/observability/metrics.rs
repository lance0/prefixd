use once_cell::sync::Lazy;
use prometheus::{
    CounterVec, Encoder, GaugeVec, HistogramVec, TextEncoder, register_counter_vec,
    register_gauge_vec, register_histogram_vec,
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
        &["peer", "status"]
    )
    .unwrap()
});

pub static ANNOUNCEMENTS_LATENCY: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "prefixd_announcements_latency_seconds",
        "BGP announcement latency in seconds",
        &["peer"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
    )
    .unwrap()
});

pub static BGP_SESSION_UP: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "prefixd_bgp_session_up",
        "BGP session state (1 = established, 0 = down)",
        &["peer"]
    )
    .unwrap()
});

// Guardrail metrics
pub static GUARDRAIL_REJECTIONS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "prefixd_guardrail_rejections_total",
        "Total number of guardrail rejections",
        &["reason"]
    )
    .unwrap()
});

// Reconciliation metrics
pub static RECONCILIATION_RUNS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "prefixd_reconciliation_runs_total",
        "Total number of reconciliation loop runs",
        &["status"]
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

/// Generate Prometheus metrics output
pub fn gather_metrics() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

/// Initialize all metrics (forces lazy statics to be created)
pub fn init_metrics() {
    // Touch all lazy statics to initialize them
    Lazy::force(&EVENTS_INGESTED);
    Lazy::force(&EVENTS_REJECTED);
    Lazy::force(&MITIGATIONS_ACTIVE);
    Lazy::force(&MITIGATIONS_CREATED);
    Lazy::force(&MITIGATIONS_EXPIRED);
    Lazy::force(&MITIGATIONS_WITHDRAWN);
    Lazy::force(&ANNOUNCEMENTS_TOTAL);
    Lazy::force(&ANNOUNCEMENTS_LATENCY);
    Lazy::force(&BGP_SESSION_UP);
    Lazy::force(&GUARDRAIL_REJECTIONS);
    Lazy::force(&RECONCILIATION_RUNS);
    Lazy::force(&CONFIG_RELOADS);
    Lazy::force(&ESCALATIONS_TOTAL);
    Lazy::force(&ROW_PARSE_ERRORS);
    Lazy::force(&DB_POOL_SIZE);
    Lazy::force(&HTTP_REQUESTS_TOTAL);
    Lazy::force(&HTTP_REQUEST_DURATION);
    Lazy::force(&HTTP_IN_FLIGHT);
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
