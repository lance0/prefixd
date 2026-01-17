-- Operators table for dashboard authentication
CREATE TABLE operators (
    operator_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'operator',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by TEXT,
    last_login_at TIMESTAMPTZ
);

CREATE INDEX idx_operators_username ON operators(username);

-- Sessions table for tower-sessions-sqlx-store
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    data BYTEA NOT NULL,
    expiry_date TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_sessions_expiry ON sessions(expiry_date);
