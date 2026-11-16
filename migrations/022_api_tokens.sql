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

-- `token:` and `webhook:` actor IDs cannot collide with a username, and no
-- operator may take a name prefixd records for another principal (the local
-- CLI, `none` mode, an mTLS client). Roles must be ones the controller knows,
-- so an unknown role is never read as a default. Refuse to add either
-- constraint over existing rows instead of rewriting them; the error rolls this
-- migration back and the controller does not start.
DO $$
DECLARE
    invalid BIGINT;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'operators'::regclass AND conname = 'operators_username_format'
    ) THEN
        SELECT count(*) INTO invalid FROM operators
        WHERE username !~ '^[A-Za-z0-9_-]{1,64}$'
           OR lower(username) IN ('prefixdctl', 'anonymous', 'mtls-client');
        IF invalid > 0 THEN
            RAISE EXCEPTION '% operator username(s) fall outside [A-Za-z0-9_-], 1 to 64 characters, or use a reserved name (prefixdctl, anonymous, mtls-client); rename them before upgrading (docs/how-to/upgrading.md#operator-usernames)', invalid;
        END IF;
        ALTER TABLE operators ADD CONSTRAINT operators_username_format
            CHECK (username ~ '^[A-Za-z0-9_-]{1,64}$'
                AND lower(username) NOT IN ('prefixdctl', 'anonymous', 'mtls-client'));
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'operators'::regclass AND conname = 'operators_role_known'
    ) THEN
        SELECT count(*) INTO invalid FROM operators
        WHERE role NOT IN ('admin', 'operator', 'viewer');
        IF invalid > 0 THEN
            RAISE EXCEPTION '% operator(s) have a role other than admin, operator or viewer; correct them before upgrading (docs/how-to/upgrading.md#operator-roles)', invalid;
        END IF;
        ALTER TABLE operators ADD CONSTRAINT operators_role_known
            CHECK (role IN ('admin', 'operator', 'viewer'));
    END IF;
END;
$$;
