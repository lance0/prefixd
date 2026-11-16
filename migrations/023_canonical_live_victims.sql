-- Migration 023: one spelling for the victims of live state.
--
-- Ingestion now stores every victim in canonical form: IPv6 lowercase and
-- zero-compressed (RFC 5952), and an IPv4-mapped IPv6 host as its IPv4
-- address. Earlier releases stored a host victim as the detector sent it, so
-- a zero-padded IPv6 victim no longer matches the canonical filter, unban
-- lookup or correlation key.
--
-- Only live rows are rewritten, because they are what correlation and the
-- detector unban key on: pending, active and escalated mitigations and
-- open signal groups. Events, audit rows and ended mitigations are history and
-- keep the spelling the detector sent. The rewrite touches only victim_ip,
-- never match_json, scope_hash or any withdrawal intent, and it implies no
-- speaker or router change. Live rows are bounded by the quotas, so the
-- update is small and takes row locks only.
--
-- PostgreSQL prints an IPv6 inet host in RFC 5952 form, as Rust does, except
-- for addresses with an embedded IPv4 part. Those are left as stored: a live
-- IPv4-mapped victim keeps the IPv6 rule it was created with, and rewriting
-- its victim to IPv4 would split the victim from its rule. A value that is not
-- an address is skipped, and an open group whose canonical key already has an
-- open group keeps its old spelling until its window closes, so the unique
-- open-group index never refuses the migration. Replaying the file changes
-- nothing.

DO $$
DECLARE
    live RECORD;
    canonical TEXT;
BEGIN
    FOR live IN
        SELECT 'mitigation' AS kind, mitigation_id AS id, victim_ip, NULL::text AS vector
        FROM mitigations
        WHERE status IN ('pending', 'active', 'escalated')
          AND strpos(victim_ip, ':') > 0 AND strpos(victim_ip, '/') = 0
        UNION ALL
        SELECT 'group', group_id, victim_ip, vector
        FROM signal_groups
        WHERE status = 'open'
          AND strpos(victim_ip, ':') > 0 AND strpos(victim_ip, '/') = 0
    LOOP
        BEGIN
            canonical := host(live.victim_ip::inet);
        EXCEPTION WHEN invalid_text_representation THEN
            canonical := NULL;
        END;
        IF strpos(canonical, '.') > 0 THEN
            canonical := NULL;
        END IF;
        CONTINUE WHEN canonical IS NULL OR canonical = live.victim_ip;
        IF live.kind = 'mitigation' THEN
            UPDATE mitigations SET victim_ip = canonical WHERE mitigation_id = live.id;
        ELSE
            UPDATE signal_groups SET victim_ip = canonical
            WHERE group_id = live.id
              AND NOT EXISTS (
                  SELECT 1 FROM signal_groups other
                  WHERE other.status = 'open' AND other.victim_ip = canonical
                    AND other.vector = live.vector
              );
        END IF;
    END LOOP;
END
$$;

-- History keeps the detector's spelling, so lookups by address compare in
-- inet form instead: one address matches whatever text spelled it. The
-- function is NULL for text that is not an address (`any`, an empty target),
-- so a lookup never fails on such a row. Its EXCEPTION block starts a
-- subtransaction, which a parallel worker cannot, so it is PARALLEL
-- RESTRICTED: a parallel index build or query keeps it in the leader. The
-- indexes keep IP history and incident reports from scanning all history;
-- building the events index takes time proportional to the stored events,
-- during which ingest waits. The upgrade guide gives the same function and a
-- CONCURRENTLY build to run before the window, which makes these no-ops.
-- Nothing reads idx_events_victim_ingested once events are matched by
-- address, so it is dropped to offset the new index's write cost.
CREATE OR REPLACE FUNCTION prefixd_victim_inet(victim TEXT) RETURNS inet
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL RESTRICTED
SET search_path = pg_catalog AS $$
BEGIN
    RETURN victim::inet;
EXCEPTION WHEN invalid_text_representation THEN
    RETURN NULL;
END
$$;
CREATE INDEX IF NOT EXISTS idx_events_victim_inet
    ON events (prefixd_victim_inet(victim_ip), ingested_at);
DROP INDEX IF EXISTS idx_events_victim_ingested;
CREATE INDEX IF NOT EXISTS idx_mitigations_victim_inet
    ON mitigations (prefixd_victim_inet(victim_ip), created_at);
