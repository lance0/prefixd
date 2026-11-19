ALTER TABLE operators
    ADD COLUMN oidc_issuer TEXT,
    ADD COLUMN oidc_subject TEXT,
    ADD COLUMN oidc_expires_at TIMESTAMPTZ,
    ADD CHECK ((oidc_issuer IS NULL) = (oidc_expires_at IS NULL)),
    ADD UNIQUE (oidc_issuer, oidc_subject),
    ADD CHECK ((oidc_issuer IS NULL) = (oidc_subject IS NULL)),
    ADD CHECK (oidc_issuer IS NULL OR password_hash LIKE 'oidc:%');

-- Keep the local-operator format and reserved audit actors from migration 022.
-- Only an issuer-bound row may use the external actor namespace.
ALTER TABLE operators DROP CONSTRAINT operators_username_format,
    ADD CONSTRAINT operators_username_format CHECK (
        (oidc_issuer IS NULL AND username ~ '^[A-Za-z0-9_-]{1,64}$'
            AND lower(username) NOT IN ('prefixdctl', 'anonymous', 'mtls-client'))
        OR (oidc_issuer IS NOT NULL AND username = 'oidc:' || operator_id::text)
    );
