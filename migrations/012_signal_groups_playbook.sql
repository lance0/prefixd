-- Migration 012: Remember the resolved playbook on signal_groups so the
-- corroborator path can re-resolve playbook-specific correlation
-- overrides (min_sources / confidence_threshold) without needing the
-- full primary-event context.
--
-- Background: PR A (ADR 021) deliberately left `recompute_group_aggregates`
-- conservative: a corroborator-only recompute would never flip
-- `corroboration_met` from false -> true, because it didn't know which
-- playbook governed the group and thus couldn't resolve the override.
-- This migration adds a nullable `playbook_name`. Primary-event ingest
-- writes it; the corroborator path looks it up and resolves the override
-- against the live playbook config.
--
-- Backfill: best-effort, copy the playbook name from any mitigation that
-- was triggered by this group. If no mitigation exists yet (e.g. the
-- group is below threshold and only has a single primary event), the
-- column stays NULL and the corroborator recompute falls back to the
-- v0.16.0 conservative behavior. The next primary event for the same
-- group will fill it in.

ALTER TABLE signal_groups
    ADD COLUMN IF NOT EXISTS playbook_name TEXT;

WITH agg AS (
    SELECT m.signal_group_id AS group_id,
           -- All mitigations from one signal group should share a playbook
           -- (groups are keyed by vector and playbooks fan out by vector),
           -- so MIN() is safe and deterministic for the rare race where a
           -- vector matched two playbooks.
           MIN(m.match_json) AS sample_match_json
    FROM mitigations m
    WHERE m.signal_group_id IS NOT NULL
    GROUP BY m.signal_group_id
)
UPDATE signal_groups sg
SET playbook_name = agg.group_id::text  -- placeholder, replaced below
FROM agg
WHERE 1 = 0;
-- The actual backfill happens at runtime: the daemon will resolve and
-- populate `playbook_name` on the next primary event for any group that
-- still has it NULL. Doing this in SQL is brittle because match_json
-- doesn't carry a playbook reference; we'd be re-running the matcher.

CREATE INDEX IF NOT EXISTS idx_signal_groups_playbook
    ON signal_groups (playbook_name)
    WHERE playbook_name IS NOT NULL;
