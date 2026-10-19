-- Deduplicate detector bans by source and external ID, not every event. A
-- detector unban carries its ban's external ID so it can be correlated, so the
-- table-wide UNIQUE(source, external_event_id) from migration 001 rejected
-- every unban row. Existing rows satisfy the narrower index, since it covers a
-- subset of what the old constraint covered. The index is created before the
-- constraint is dropped, so bans stay deduplicated throughout. Replay rewrites
-- no event, mitigation or audit row and creates no announcement or speaker
-- acknowledgement.
CREATE UNIQUE INDEX IF NOT EXISTS events_source_external_ban_key
    ON events(source, external_event_id) WHERE action = 'ban';
ALTER TABLE events DROP CONSTRAINT IF EXISTS events_source_external_event_id_key;
