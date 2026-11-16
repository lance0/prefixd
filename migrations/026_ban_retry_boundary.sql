-- Historical incomplete attempts may have extended a mitigation whose later
-- updates erased the event link. Never infer that those attempts did nothing.
-- The constant default is metadata-only; the current binary explicitly marks
-- new events whose admissions atomically retain their mitigation IDs.
ALTER TABLE events ADD COLUMN IF NOT EXISTS ban_retryable BOOLEAN NOT NULL DEFAULT FALSE;
