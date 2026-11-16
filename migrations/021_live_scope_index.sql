-- Live mitigation intent is active and escalated. Migration 001 also covered
-- pending, which no release has stored, so a stored pending row kept its scope
-- and refused every new admission for that scope and POP. The narrower
-- predicate covers a subset of the rows the old index already kept unique, so
-- rebuilding it cannot fail on existing data and rewrites no row.
DROP INDEX IF EXISTS idx_mitigations_active_scope;
CREATE UNIQUE INDEX idx_mitigations_active_scope
    ON mitigations(scope_hash, pop)
    WHERE status IN ('active', 'escalated');
