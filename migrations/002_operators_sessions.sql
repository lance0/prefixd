-- Operators table for dashboard authentication
CREATE TABLE IF NOT EXISTS operators (
    operator_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'operator',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by TEXT,
    last_login_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_operators_username ON operators(username);

-- Sessions table for tower-sessions-sqlx-store
-- Uses tower_sessions schema as expected by the library
CREATE SCHEMA IF NOT EXISTS tower_sessions;

CREATE TABLE IF NOT EXISTS tower_sessions.session (
    id TEXT PRIMARY KEY NOT NULL,
    data BYTEA NOT NULL,
    expiry_date TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tower_sessions_expiry ON tower_sessions.session(expiry_date);
