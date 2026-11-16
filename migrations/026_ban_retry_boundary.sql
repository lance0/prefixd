-- Historical incomplete attempts may have extended a mitigation whose later
-- updates erased the event link. Their original admission POP is unknown.
-- The current binary records a new ban's immutable POP with its initial INSERT;
-- only that POP may resume it, and all admitted mitigation IDs remain atomic.
ALTER TABLE events ADD COLUMN IF NOT EXISTS ban_admission_pop TEXT;
