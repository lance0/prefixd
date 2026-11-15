-- What ingestion did with each stored event. Existing rows keep NULL, which the
-- API reports as not_recorded: replay never infers an outcome for an older
-- event, rewrites no event, mitigation or audit row, and creates no
-- announcement or speaker acknowledgement. The columns are nullable or have a
-- constant default, so adding them does not rewrite the table.
ALTER TABLE events ADD COLUMN IF NOT EXISTS outcome TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS outcome_reason TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS outcome_mitigation_ids UUID[] NOT NULL DEFAULT '{}';
