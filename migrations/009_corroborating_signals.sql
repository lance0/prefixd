-- Migration 009: Corroborating signals for the correlation engine (ADR 021)
--
-- Introduces a new class of signals that cannot trigger mitigations on their
-- own but can strengthen existing signal groups. These signals don't carry a
-- victim_ip; they match groups via lighter dimensions (customer_id, pop,
-- service_id, interface) extracted from the group's primary events.

-- Each attachment in signal_group_events is now tagged as primary or
-- corroborating, for audit trail, UI display, and the "group must have >= 1
-- primary event to trigger" invariant in check_corroboration.
ALTER TABLE signal_group_events
    ADD COLUMN IF NOT EXISTS is_corroborating BOOLEAN NOT NULL DEFAULT false;

-- Aggregated dimensions contributed by primary events in this signal group.
-- JSONB of the form {"customer_ids": [...], "pops": [...],
--                    "service_ids": [...], "interfaces": [...]}
-- Updated on each primary event ingest. Corroborators match a group iff they
-- share at least one populated dimension value.
ALTER TABLE signal_groups
    ADD COLUMN IF NOT EXISTS primary_dimensions JSONB NOT NULL DEFAULT '{}'::jsonb;

-- Denormalized corroborator metadata. These are NULL for primary-event rows
-- (the data is resolved via JOIN events). For corroborator rows, they hold
-- the fields needed by list_signal_group_events so the UI/explanation can
-- display the contributing source without chasing back to corroborating_signals.
ALTER TABLE signal_group_events
    ADD COLUMN IF NOT EXISTS corroborator_signal_id UUID;
ALTER TABLE signal_group_events
    ADD COLUMN IF NOT EXISTS corroborator_source TEXT;
ALTER TABLE signal_group_events
    ADD COLUMN IF NOT EXISTS corroborator_confidence REAL;

-- Floating cache for corroborating signals that arrive before any matching
-- primary signal group exists. Signals persist until they attach to a group
-- (which moves them into signal_group_events) or expire via cache sweep.
CREATE TABLE IF NOT EXISTS corroborating_signals (
    signal_id          UUID PRIMARY KEY,
    source             TEXT NOT NULL,
    vector             TEXT,               -- optional; when set, narrows matching
    customer_id        TEXT,
    pop                TEXT,
    service_id         TEXT,
    interface          TEXT,
    confidence         REAL,
    weight             REAL NOT NULL,      -- frozen at ingest from correlation config
    ingested_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL,
    raw_details        JSONB,
    attached_group_ids UUID[] NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_corr_signals_expires
    ON corroborating_signals (expires_at);

CREATE INDEX IF NOT EXISTS idx_corr_signals_dims
    ON corroborating_signals (customer_id, pop, service_id, interface);
