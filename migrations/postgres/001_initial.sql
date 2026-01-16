-- prefixd initial schema for PostgreSQL

CREATE TABLE IF NOT EXISTS events (
    event_id UUID PRIMARY KEY,
    external_event_id TEXT,
    source TEXT NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL,
    victim_ip TEXT NOT NULL,
    vector TEXT NOT NULL,
    protocol INTEGER,
    bps BIGINT,
    pps BIGINT,
    top_dst_ports_json TEXT NOT NULL DEFAULT '[]',
    confidence REAL,
    schema_version INTEGER NOT NULL DEFAULT 1,
    UNIQUE(source, external_event_id)
);

CREATE INDEX IF NOT EXISTS idx_events_victim_ingested ON events(victim_ip, ingested_at);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source, ingested_at);

CREATE TABLE IF NOT EXISTS mitigations (
    mitigation_id UUID PRIMARY KEY,
    scope_hash TEXT NOT NULL,
    pop TEXT NOT NULL,
    customer_id TEXT,
    service_id TEXT,
    victim_ip TEXT NOT NULL,
    vector TEXT NOT NULL,
    schema_version INTEGER NOT NULL DEFAULT 1,
    match_json TEXT NOT NULL,
    action_type TEXT NOT NULL,
    action_params_json TEXT,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    withdrawn_at TIMESTAMPTZ,
    triggering_event_id UUID NOT NULL,
    last_event_id UUID NOT NULL,
    escalated_from_id UUID,
    reason TEXT,
    rejection_reason TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_mitigations_active_scope
    ON mitigations(scope_hash, pop)
    WHERE status IN ('pending', 'active', 'escalated');

CREATE INDEX IF NOT EXISTS idx_mitigations_expires
    ON mitigations(expires_at)
    WHERE status IN ('active', 'escalated');

CREATE INDEX IF NOT EXISTS idx_mitigations_customer
    ON mitigations(customer_id, status);

CREATE INDEX IF NOT EXISTS idx_mitigations_victim
    ON mitigations(victim_ip, status);

CREATE TABLE IF NOT EXISTS flowspec_announcements (
    announcement_id UUID PRIMARY KEY,
    mitigation_id UUID NOT NULL REFERENCES mitigations(mitigation_id),
    pop TEXT NOT NULL,
    peer_name TEXT NOT NULL,
    peer_address TEXT NOT NULL,
    nlri_hash TEXT NOT NULL,
    nlri_json TEXT NOT NULL,
    action_json TEXT NOT NULL,
    status TEXT NOT NULL,
    announced_at TIMESTAMPTZ,
    withdrawn_at TIMESTAMPTZ,
    last_error TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_announcements_mitigation
    ON flowspec_announcements(mitigation_id);

CREATE INDEX IF NOT EXISTS idx_announcements_peer_status
    ON flowspec_announcements(peer_address, status);

CREATE INDEX IF NOT EXISTS idx_announcements_nlri
    ON flowspec_announcements(nlri_hash);

CREATE TABLE IF NOT EXISTS audit_log (
    audit_id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    schema_version INTEGER NOT NULL DEFAULT 1,
    actor_type TEXT NOT NULL,
    actor_id TEXT,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    details_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_type, actor_id);

CREATE TABLE IF NOT EXISTS safelist (
    prefix TEXT PRIMARY KEY,
    added_at TIMESTAMPTZ NOT NULL,
    added_by TEXT NOT NULL,
    reason TEXT,
    expires_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_safelist_expires ON safelist(expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS config_snapshots (
    snapshot_id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    config_hash TEXT NOT NULL,
    config_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_config_timestamp ON config_snapshots(timestamp);
