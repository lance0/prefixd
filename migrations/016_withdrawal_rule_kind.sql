-- Record which route kind a withdrawal deletes (ADR 027). Every request written
-- before this column is FlowSpec, so the default states a fact rather than an
-- inference. Replay rewrites no mitigation row and creates no announcement or
-- speaker acknowledgement.
ALTER TABLE withdrawal_requests
    ADD COLUMN IF NOT EXISTS rule_kind TEXT NOT NULL DEFAULT 'flowspec'
        CHECK (rule_kind IN ('flowspec', 'blackhole'));
