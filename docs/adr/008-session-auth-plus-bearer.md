# ADR 008: Hybrid Auth -- Session Cookies + Bearer Tokens

## Status

Accepted

## Date

2026-01-28

## Context

prefixd has two types of clients:

1. **Browser dashboard** -- humans clicking through the UI, need login/logout, CSRF protection
2. **API clients** -- detectors (FastNetMon), CLI (`prefixdctl`), scripts -- need stateless auth

Session cookies are the right fit for browsers (HttpOnly, Secure, SameSite=Strict). Bearer tokens are the right fit for API clients (stateless, easy to rotate, works in headers).

Forcing browser users to manage bearer tokens is bad UX. Forcing API clients to do cookie-based login flows is bad DX.

## Decision

Support both auth mechanisms simultaneously:

- **Session auth**: `POST /v1/auth/login` creates a session cookie. Dashboard uses this. Stored in PostgreSQL via `tower-sessions-sqlx-store`.
- **Bearer auth**: `Authorization: Bearer <token>` header. CLI and detectors use this. Token configured in `prefixd.yaml`.
- **Auth mode `none`**: Disables all auth checks (for dev/lab environments).

Route protection:
- Public routes (health, login, metrics) -- no auth required
- Session routes (logout, me, WebSocket) -- session cookie required
- API routes (events, mitigations, etc.) -- session OR bearer accepted

```rust
// Handlers check auth via helper:
let operator = require_auth(&state, &auth_session, headers).await?;
// Returns Ok if valid session cookie OR valid bearer token
```

## Consequences

**Positive:**
- Dashboard users get proper browser auth (login form, session management, CSRF protection)
- API clients get simple token auth (one header, no state)
- Both can coexist -- a browser user and a detector can hit the same endpoint
- Auth mode `none` keeps the dev experience frictionless

**Negative:**
- Two auth paths means two things to test and secure
- Session storage in PostgreSQL adds a table and cleanup job
- Bearer token is currently a single shared secret (no per-client tokens yet)

**Future:**
- Per-client API keys with scopes and rotation
- LDAP/AD integration for session auth
- OIDC/SAML for enterprise SSO

## Amendment: auth mode names

`credentials` and `bearer` describe which non-session credential is accepted,
not whether sessions work. `credentials` accepts session cookies only and
rejects `Authorization: Bearer`, so the CLI cannot use it. `bearer` accepts the
token and existing sessions, which makes it the hybrid mode this ADR describes;
session users keep their own roles. The single `PREFIXD_API_TOKEN` remains an
operator-level shared secret, so it can ingest, read and withdraw for every
holder and cannot name a detector source in audit. Named, scoped tokens remain
future work.
