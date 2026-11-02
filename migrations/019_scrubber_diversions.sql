-- Separate immutable diversion snapshots; ordinary traffic-rate rows keep their shape.
CREATE SEQUENCE IF NOT EXISTS scrubber_admission_revision;
CREATE TABLE IF NOT EXISTS scrubber_diversions (
    id UUID PRIMARY KEY,
    pop TEXT NOT NULL REFERENCES speaker_pop_bindings(pop),
    victim INET NOT NULL,
    customer_id TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    profile_revision TEXT NOT NULL,
    admission_revision BIGINT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK(status IN ('pending','active','withdrawing','withdrawn','simulated')),
    created_at TIMESTAMPTZ NOT NULL,
    snapshot_json TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS scrubber_diversions_live_victim
    ON scrubber_diversions(pop, victim) WHERE status IN ('pending','active','withdrawing');
