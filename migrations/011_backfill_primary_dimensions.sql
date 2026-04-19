-- Migration 011: Backfill signal_groups.primary_dimensions for pre-existing
-- open groups.
--
-- Migration 009 (ADR 021) added signal_groups.primary_dimensions with a
-- default of '{}'::jsonb. Primary-event ingest populates it from the
-- IpContext lookup, but rows that existed before this migration stay
-- empty forever. The corroborator attach path (/v1/signals/corroborator)
-- and the cache-drain path (on primary ingest) match exclusively on
-- primary_dimensions, so corroborating signals can never attach to such
-- in-flight groups until another primary event happens to update them.
--
-- We derive dimensions best-effort from the group's related mitigations
-- (customer_id, pop, service_id). That covers the common case where an
-- open group already produced a mitigation. Interface is not available
-- pre-upgrade (new inventory field introduced in ADR 021 remediations)
-- and is left empty; a later primary event will fill it in. Open groups
-- with no associated mitigation yet are left as-is (honest empty state).

WITH agg AS (
    SELECT m.signal_group_id AS group_id,
           ARRAY_REMOVE(ARRAY_AGG(DISTINCT m.customer_id), NULL) AS customer_ids,
           ARRAY_REMOVE(ARRAY_AGG(DISTINCT m.pop), NULL)         AS pops,
           ARRAY_REMOVE(ARRAY_AGG(DISTINCT m.service_id), NULL)  AS service_ids
    FROM mitigations m
    WHERE m.signal_group_id IS NOT NULL
    GROUP BY m.signal_group_id
)
UPDATE signal_groups sg
SET primary_dimensions = jsonb_build_object(
    'customer_ids', COALESCE(to_jsonb(agg.customer_ids), '[]'::jsonb),
    'pops',         COALESCE(to_jsonb(agg.pops),         '[]'::jsonb),
    'service_ids',  COALESCE(to_jsonb(agg.service_ids),  '[]'::jsonb),
    'interfaces',   '[]'::jsonb
)
FROM agg
WHERE sg.group_id = agg.group_id
  AND sg.status = 'open'
  AND (sg.primary_dimensions IS NULL OR sg.primary_dimensions = '{}'::jsonb);
