-- Source ports a detector reported for an event (ADR 028). NULL means the
-- detector sent none; '[]' means it sent an empty list. Replay adds only the
-- nullable column: it rewrites no event or mitigation row and creates no
-- announcement or speaker acknowledgement.
ALTER TABLE events ADD COLUMN IF NOT EXISTS top_src_ports_json TEXT;
