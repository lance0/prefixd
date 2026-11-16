-- Migration 025: the replay record of a detector unban.
--
-- A detector unban stores its POP and the mitigations it withdraws on its own
-- event row, in the same insert, before it records any withdrawal intent. A
-- resend or replay of the unban's event ID on that POP reuses exactly that set
-- and never selects again. NULL on every ban and on unbans stored before this
-- migration, which a resend therefore selects afresh. Adding nullable columns
-- without a default rewrites no row and holds the lock only for the catalog
-- change.
ALTER TABLE events ADD COLUMN IF NOT EXISTS unban_pop TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS unban_target_ids UUID[];
