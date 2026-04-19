ALTER TABLE signal_group_events
    ADD COLUMN IF NOT EXISTS corroborator_ingested_at TIMESTAMPTZ;

UPDATE signal_group_events AS sge
SET corroborator_ingested_at = cs.ingested_at
FROM corroborating_signals AS cs
WHERE sge.is_corroborating = true
  AND sge.corroborator_ingested_at IS NULL
  AND sge.corroborator_signal_id = cs.signal_id;
