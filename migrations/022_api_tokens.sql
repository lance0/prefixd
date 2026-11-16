-- Named, hashed, revocable API tokens replace the shared bearer token. Only the
-- SHA-256 of a token is stored; the plaintext is shown once, at creation. A
-- name is never reused, so the audit actor `token:<name>` stays unambiguous,
-- and its 58-character cap keeps that actor within 64 characters.
CREATE TABLE IF NOT EXISTS api_tokens (
    token_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,57}$'),
    token_hash   BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    scope        TEXT NOT NULL CHECK (scope IN ('ingest', 'operator', 'admin')),
    source       TEXT CHECK (source ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
    pop          TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by   TEXT NOT NULL,
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    revoked_by   TEXT,
    CHECK ((scope = 'ingest') = (source IS NOT NULL))
);

-- `token:` and `webhook:` actor IDs cannot collide with a username. Refuse to
-- add the constraint over existing usernames instead of rewriting them; the
-- error rolls this migration back and the controller does not start.
DO $$
DECLARE
    invalid BIGINT;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'operators'::regclass AND conname = 'operators_username_format'
    ) THEN
        SELECT count(*) INTO invalid FROM operators
        WHERE username !~ '^[A-Za-z0-9_-]{1,64}$';
        IF invalid > 0 THEN
            RAISE EXCEPTION '% operator username(s) fall outside [A-Za-z0-9_-], 1 to 64 characters; rename them before upgrading (docs/how-to/upgrading.md#operator-usernames)', invalid;
        END IF;
        ALTER TABLE operators ADD CONSTRAINT operators_username_format
            CHECK (username ~ '^[A-Za-z0-9_-]{1,64}$');
    END IF;
END;
$$;
