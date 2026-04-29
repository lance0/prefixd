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
-- Backfill is intentionally NOT done in SQL. `mitigations.match_json`
-- doesn't carry the resolved playbook name, and re-running the matcher
-- against a playbook YAML snapshot at migration time is brittle (the
-- live playbook list may have changed between when the group was
-- created and when this migration runs).
--
-- Instead, the daemon backfills `playbook_name` at runtime using
-- `COALESCE(playbook_name, $resolved)` on the next primary-event ingest
-- path for each group that still has it NULL (see
-- `handle_ban` in `src/api/handlers.rs`). Until that next primary event
-- arrives, the corroborator-side recompute path falls back to the
-- v0.16.0 conservative behavior (no flip of `corroboration_met`).

ALTER TABLE signal_groups
    ADD COLUMN IF NOT EXISTS playbook_name TEXT;

CREATE INDEX IF NOT EXISTS idx_signal_groups_playbook
    ON signal_groups (playbook_name)
    WHERE playbook_name IS NOT NULL;
