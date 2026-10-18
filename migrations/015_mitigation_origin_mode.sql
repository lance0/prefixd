-- Record the operation mode that admitted each mitigation. NULL means the row
-- predates this column; replay never infers a mode, an announcement or a
-- speaker acknowledgement. Startup tags unknown live rows with an audit entry.
ALTER TABLE mitigations
    ADD COLUMN IF NOT EXISTS origin_mode TEXT
        CHECK (origin_mode IN ('dry-run', 'enforced'));
