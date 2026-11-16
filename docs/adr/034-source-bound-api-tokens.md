# ADR 034: Source-Bound Scoped API Tokens

## Status

Proposed 2026-11-15 and accepted 2026-11-15. Amended 2026-11-16: identity
management needs a session, and three resolution details are settled; see
[Amendment: identity management needs a session](#amendment-identity-management-needs-a-session).
Amended again 2026-11-16: a detector unban names its victim, and adapter
secrets live in a fixed namespace; see
[Amendment: unban by victim](#amendment-unban-by-victim).

This ADR amends [ADR 008](008-session-auth-plus-bearer.md): named, hashed,
revocable API tokens replace the shared bearer token, and the `bearer` auth mode
is removed. It also amends the source allowlists in
[ADR 027](027-blackhole-mitigations.md) §2 and
[ADR 033](033-detector-prefix-mitigations.md) §1, which become authorization
keyed on an authenticated source rather than label filters. It extends
[ADR 019](019-signal-adapter-architecture.md),
[ADR 020](020-generic-webhook-adapter.md) and
[ADR 021](021-corroborating-signals.md).

The choices this ADR settles are listed under [Decisions](#decisions).

## Context

### Every ingest credential can claim any detector

prefixd grants detector privileges by the event's `source` name:

- `blackhole.detector_sources` admits a playbook blackhole step (ADR 027 §2).
  A manual blackhole needs Admin.
- `guardrails.detector_prefix_sources` admits a detector prefix event (ADR 033).
- Correlation counts distinct sources against `min_sources`, weights each
  event by `correlation.sources.<name>.weight`, and lets only a source
  configured `mode: corroborating` attach corroborating signals
  ([ADR 018](018-multi-signal-correlation-engine.md),
  [ADR 021](021-corroborating-signals.md)).
- `unban` finds the ban by `(source, event_id)`.

Nothing authenticates the source.

- `/v1/events`, `/v1/events/batch` and `/v1/signals/corroborator` read it from
  the request body.
- The FastNetMon, Alertmanager and generic webhook adapters set it from the
  route, but they accept any Operator credential.

Ingestion needs only the Operator role, and the shared bearer token is an
Operator credential. So any CLI user, detector host or Operator session can post
`{"source": "fastnetmon", ...}` and get a detector blackhole, which a manual
request can only get with Admin. The same credential can also:

- claim a prefix-allowlisted source;
- satisfy `min_sources` by posting under several labels;
- borrow a high-weight source's weight;
- send an `unban` for another detector's event ID.

The dashboard's mitigate-now dialog shows the same weakness from the other
side. It posts `source: "dashboard"` to `/v1/events`, so an operator's click is
audited as the detector `dashboard` rather than as the operator, and it counts
as a distinct correlation source.

The detector credential is also too broad. A FastNetMon host holding the shared
token is a full Operator: it can create manual FlowSpec rules, withdraw any
mitigation and read everything. The bundled Community script needs those
rights today, because its unban looks up the victim in `/v1/mitigations` and
calls `/withdraw`.

The token is a single unnamed secret that the controller reads from
`PREFIXD_API_TOKEN` at startup. It cannot be revoked without a restart, and
every request made with it is audited as `bearer-token`. In `credentials` mode,
which is the recommended mode and the shipped Compose default, no bearer token
is accepted at all, so a detector cannot authenticate without an operator
session.

### The interim fix was the wrong shape

An interim patch made `/v1/events` require Admin whenever the body named an
allowlisted source. Independent review blocked it for three reasons:

1. The adapter routes still accepted any Operator credential and bound the
   source themselves, so the shared token could still reach a detector
   blackhole through `/v1/signals/fastnetmon`.
2. The gate keyed on the label, not the privilege. Once `fastnetmon` was
   allowlisted, every ban from the bundled script got 403, host FlowSpec bans
   included.
3. Its migration paths were the native adapter (Advanced-only and host-only),
   `auth.mode: none`, or an Admin password on the detector host.

The fix is to authenticate the source.

## Decision

### 1. Token model

A token is a named database row with one scope. Token management is described
in [section 9](#9-management-surfaces).

- **Format.** The token is `prefixd_` followed by 43 base64url characters
  encoding 32 bytes from the operating system's CSPRNG. One library function
  generates tokens for both the API and the CLI. The fixed prefix lets secret
  scanners recognize a leaked token. A presented value that does not match the
  format is refused before any database query.
- **Hash.** The row stores the SHA-256 of the full token (32 bytes) under a
  unique index, and the request path looks the token up by that hash.
  - The secret carries 256 bits of randomness, so a stolen hash gives no
    practical preimage, and salting or a slow KDF adds nothing.
  - Argon2 is right for passwords, which have low entropy. Here it would cost
    tens of milliseconds and megabytes of memory on every ingest request, and
    a salted hash cannot be indexed, so each token would also need a lookup
    identifier. A peppered HMAC would add key management for no gain at this
    entropy.
  - The indexed lookup needs no constant-time comparison, because a caller
    cannot steer the SHA-256 of a guessed value toward a stored hash.
- **Shown once.** The plaintext appears only in the create response. It is
  never stored, logged or retrievable afterward. The controller's global
  `Cache-Control: no-store` header already covers the create response.
- **Name.** Names match `^[a-z0-9][a-z0-9-]{0,57}$` and are unique across all
  rows, revoked ones included. The 58-character cap keeps the actor ID
  `token:<name>` within the 64-character limit (`MAX_USERNAME_LEN`) that every
  Operator mutation enforces on its actor. A name is never reused, so audit
  history stays unambiguous.
- **POP.** `pop` is optional. A token with a `pop` authenticates only on
  controllers whose `pop` setting matches, and is refused elsewhere with 403
  naming the bound POP. A null `pop` means any POP that shares the database.
  This matters because several POPs can share one PostgreSQL database
  ([section 11](#11-storage)).
- **Expiry.** `expires_at` is optional, and tokens do not expire by default. A
  detector token that expires during an attack leaves the attack
  unmitigated, so expiry is an explicit choice made at creation.
- **Revocation.** Revoking sets `revoked_at` and `revoked_by` and keeps the
  row. It takes effect on the next request, because every token request reads
  the row and no in-memory cache needs invalidating.
- **Last used.** On the active controller, a successful authentication updates
  `last_used_at` at most once a minute per token. The write is best-effort and
  never fails the request. A standby skips the write, since a standby mutates
  nothing.
- **Failures.** Unknown, revoked and expired tokens get 401. The error names
  `revoked` or `expired`, which tells the holder nothing they do not already
  know. A revoked or expired token is also logged at warn level with its name,
  as a rotation signal. A database error during lookup returns 503, never
  401, so a storage outage does not look like a credential problem.

### 2. Credential resolution

An axum extractor, `AuthPrincipal`, resolves the request's identity once per
request and stores it in the request extensions. `require_auth` and
`require_role` stay synchronous and read that principal. Only token requests
add a database read: sessions already read the session store today.

```rust
enum Principal {
    Operator(Operator),                  // session, operator or admin token, mTLS, none
    Ingest { token: String, source: String, pop: Option<String> },
}
```

Precedence, in every mode that accepts tokens:

- **Bearer only.** Only `Authorization: Bearer` is a token credential.
  Requests with other schemes, such as `Basic` added by a proxy in front of the
  dashboard, fall through to the session. The dashboard proxy forwards every
  header, so the dashboard keeps working behind proxy Basic auth.
- **A Bearer header replaces the session.** The session is never loaded: the
  `Cookie` header is stripped before the session layer. An invalid token gets
  401 even when a valid session cookie is also present; the request never falls
  back from a bad token to a session. Stripping also means a stale cookie
  during a database outage cannot turn a valid token request into a 500, and a
  failed session load cannot clear the browser's cookie.
- **HMAC adapter routes ignore `Authorization`.** The adapter secret is their
  credential ([section 4](#4-one-enforcement-point-for-every-ingest-route)).
- **Session-only routes.** The WebSocket feed and the `/v1/auth/*` routes stay
  session-only.

`prefixdctl` never sends both credentials. Passing `--token` (or
`PREFIXD_TOKEN`) together with `--session-cookie` is a usage error.

Tokens are verified in `credentials` mode. `none` mode stays anonymous Admin
and ignores credentials. `mtls` mode is covered in
[section 7](#7-mtls-and-none-mode).

### 3. Scopes

| Scope | Role equivalent | Reaches |
| --- | --- | --- |
| `ingest` | none | `POST /v1/events`, `POST /v1/events/batch`, `POST /v1/signals/fastnetmon`, `POST /v1/signals/alertmanager`, `POST /v1/signals/webhook/{name}` for `auth.type: bearer` adapters, and `POST /v1/signals/corroborator`. It has no read access, and it requires a bound `source`. |
| `operator` | Operator | Every route the Operator role reaches today, except the ingest routes ([section 4](#4-one-enforcement-point-for-every-ingest-route)) |
| `admin` | Admin | Every route the Admin role reaches, except identity management ([amended](#amendment-identity-management-needs-a-session)) |

An ingest token is not a role in the `Viewer < Operator < Admin` order.
`require_auth` and `require_role` refuse `Principal::Ingest` with 403, and only
`authorize_ingest` accepts it. Any route that does not call `authorize_ingest`
is therefore closed to ingest tokens, so a new route needs a deliberate change
before an ingest token can reach it.

Token management (`/v1/tokens`) requires an Admin session or the local CLI.
No token can call it, admin tokens included. If a stolen admin token could mint
replacements, revoking it would not evict the attacker. The 2026-11-16
amendment extends the rule to all identity management and refuses ingest
tokens at extraction
([amendment](#amendment-identity-management-needs-a-session)).

A token's `source` matches `^[a-z0-9][a-z0-9_-]{0,63}$`. Several tokens may share
a source: two FastNetMon instances, `fnm-pop1` and `fnm-pop2`, can both be bound
to `fastnetmon`. They count as one correlation source, because they are the same
detector type.

A read-only `viewer` token scope is not part of this decision.

### 4. One enforcement point for every ingest route

Every ingest route calls one function before any validation that touches
state:

```rust
fn authorize_ingest(principal: &Principal, claimed: &str) -> Result<SourceGrant, PrefixdError>;
```

| Principal | Rule | Grant |
| --- | --- | --- |
| Ingest token | `claimed` must equal the token's source. POP binding was already checked at verification ([section 1](#1-token-model)). | bound to that source |
| Admin (session or admin token), mTLS, `none` | any `claimed` | bound to `claimed` |
| Operator (session or operator token) | refused | none |
| Viewer | refused, as today | none |

`SourceGrant` and its constructors live in one auth module: `authorize_ingest`,
the HMAC adapter verification, and a `#[cfg(test)]` constructor. The field is
private to that module, so no handler can build a grant.

`handle_ban`, `handle_unban` and the corroborator write path each take a
`SourceGrant`, and set the event's or signal's `source` from it. No route can
reach admission or a correlation write without passing the check. The
source-keyed checks all read the granted source:

- `check_detector_source`;
- `check_detector_prefix`;
- correlation weight;
- `min_sources` counting;
- corroborating mode;
- the unban lookup.

Each route supplies `claimed` as follows:

| Route | `claimed` |
| --- | --- |
| `POST /v1/events` | body `source` |
| `POST /v1/events/batch` | each item's `source`. The whole batch is authorized before any item runs. One mismatched item refuses the request with 403, and nothing is stored or actuated. Items that fail to parse have no source to authorize, so they keep their per-item rejection and never actuate. |
| `POST /v1/signals/fastnetmon`, host payload | `fastnetmon` |
| `POST /v1/signals/fastnetmon`, total-hostgroup payload (native hostgroup adapter) | `fastnetmon-hostgroup` ([section 12](#12-bundled-fastnetmon-scripts)) |
| `POST /v1/signals/alertmanager` | `alertmanager` |
| `POST /v1/signals/webhook/{name}`, `auth.type: bearer` | the adapter name |
| `POST /v1/signals/webhook/{name}`, `auth.type: hmac` | No principal is involved. The adapter's own secret is a credential bound to the adapter name, and a verified signature yields the grant. |
| `POST /v1/signals/corroborator` | body `source` |

A mismatch is `PrefixdError::SourceNotBound { claimed, bound }`, status 403. Its
message names the claimed source and, for a token, the bound source, for
example `source "fastnetmon" is not bound to this credential (bound to
"radware")`. For an Operator principal, it says that ingest routes need an
ingest token. It echoes no other request field. The rejection metric is
labeled with the bound source, never the claimed one, so a caller cannot
inflate label cardinality.

Several effects follow from that one rule:

- **Blackhole and prefix allowlists.** These become authorization. Only an
  ingest token bound to an allowlisted source, the HMAC adapter of that name,
  or an Admin can reach them. Neither an Operator session nor an operator
  token can reach them through any route.
- **Correlation.** Each distinct source in a group is a distinct bound
  credential or an Admin claim, so `min_sources: 2` now needs two credentials
  bound to different sources. Weights and corroborating mode apply to the bound
  source.
- **Unban.** *Replaced by
  [unban by victim](#amendment-unban-by-victim) on 2026-11-16.*
  `handle_unban` resolves the ban event by `(granted source,
  event_id)`. It then withdraws the active mitigations whose
  `triggering_event_id` or `last_event_id` is that event. Matching on
  `last_event_id` covers a mitigation that a later ban extended. A mitigation
  that source A created and source B later extended can be withdrawn by
  either source's unban; that case is listed in the
  [threat model](#threat-model). To withdraw a detector's mitigation,
  operators use `POST /v1/mitigations/{id}/withdraw`, which keeps its
  confirmation, reason and audit trail.
- **Operators.** Operators and operator tokens lose every ingest route. The
  dashboard's mitigate-now flow moves to the manual mitigation API
  ([section 10](#10-mitigate-now-is-retired)). No source name is reserved.

### 5. Configuration refusals

The refusals below depend on two files. Webhook adapters and source modes
live in the correlation configuration. The auth mode and both allowlists,
`blackhole.detector_sources` and `guardrails.detector_prefix_sources`, live in
`prefixd.yaml`.

`CorrelationConfig::validate` therefore takes the auth mode and both
allowlists as arguments. It runs whenever either input changes:

- at startup;
- on reload of either file;
- on the Admin route `PUT /v1/config/correlation`.

Without this, adding an HMAC adapter's name to an allowlist in `prefixd.yaml`
would bypass the `source_id` refusal. An Admin cannot reintroduce a refused
shape at runtime through any of these paths.

- **Unauthenticated webhook adapters.** A webhook adapter with
  `auth.type: none` would let anyone who can reach the controller claim the
  adapter's source, so it is refused unless `http.auth.mode` is `none`. This
  turns the existing "lab use only" warning into a rule.
- **Replayable HMAC adapters.** An HMAC adapter that is named in
  `blackhole.detector_sources` or `guardrails.detector_prefix_sources` must
  map `fields.source_id`, or it is refused. With an event ID, a replayed
  signed ban gets 409. Without one, every replay would get a fresh ID and
  recreate the mitigation, and HMAC carries no timestamp or nonce.
- **Allowlist names a token cannot carry.** Entries in
  `blackhole.detector_sources` and `guardrails.detector_prefix_sources` must
  match the token-source pattern, or the configuration is refused at load.
  Every allowlisted source is then one a credential can be bound to.
- **Removed settings.** `http.auth.mode: bearer` and
  `http.auth.bearer_token_env` are refused, as
  [section 8](#8-the-shared-token-and-the-bearer-mode-are-removed)
  describes. `REMOVED_KEYS` records a removal version for each key, so the
  error names the right release instead of a hard-coded 0.20.0.

### 6. Audit and actor identity

The guardrails read the event's `source`. Admission uses only the actor's kind,
never its ID, so the actor ID can name the credential without changing
privilege:

| Principal | Actor type | Actor ID |
| --- | --- | --- |
| Ingest token | `detector` | `token:<name>` |
| HMAC webhook adapter | `detector` | `webhook:<adapter>` |
| Operator or admin token | `operator` | `token:<name>` |
| Session | `operator` | username |
| mTLS client | `operator` | `mtls-client` |
| `none` mode | `operator` | `anonymous` |

The same identity applies to the withdrawal that a detector unban performs.
*Amended 2026-11-16 ([unban by victim](#amendment-unban-by-victim)):* that withdrawal also records the bound source, so
its completion audit carries `details.source` and it counts as
`detector_unban` whoever completes it.

- **Detector audit rows.** Rows for detector-created mitigations carry the
  bound source in their details.
- **Admin claims.** When an Admin posts an event, the row is attributed to the
  Admin, not to the source the Admin claimed.
- **Consumers.** The audit log page, a mitigation's creator display and
  `GET /v1/audit` actor filters all see these IDs. The CHANGELOG names them.

`token:` and `webhook:` cannot collide with a username. The API already
restricts usernames to `[A-Za-z0-9_-]`. `prefixdctl operators create` gains the
same validation, and migration 022 adds a matching `CHECK` on
`operators.username` ([section 11](#11-storage)).

Token management writes its own audit rows:

- **Action:** `api_token.create` or `api_token.revoke`.
- **Target:** target type `api_token`, target ID the token name.
- **Details:** the scope, source, POP and expiry. Never the secret or its
  hash.
- **Actor:** the Admin session's username, or `prefixdctl` for the local CLI.

The ingest warning log carries the token name, the bound source and the
claimed source.

### 7. mTLS and none mode

In `mtls` mode, every client certificate is Admin, and tokens are not
consulted. An mTLS client therefore keeps an Admin grant for any source. That
adds no power, because the same certificate can already create a manual
blackhole. The gap stays open until certificate-to-role mapping exists. That
mapping, tracked separately, will map each certificate to a scope (and, for
ingest, a source) through the same `authorize_ingest`. Until it lands,
deployments that need per-detector least privilege use `credentials` mode with
ingest tokens.

`none` mode stays anonymous Admin. Under mTLS, webhook adapters with
`auth.type: none` and `bearer` behave the same, so refusing `none` there costs
nothing.

### 8. The shared token and the `bearer` mode are removed

The shared token is the credential that caused this problem. It is unnamed,
cannot be revoked at runtime and is audited as one identity. Under section 4 it
could carry no detector privilege at all. Kept as an operator-scope credential,
it would be a second token path that is worse than an operator token in every
respect. It is removed, not deprecated.

- **Refused at load.** `http.auth.mode: bearer` is refused at load and by
  `prefixd --check`, with an error that points to the upgrade guide.
  `credentials` now covers operator sessions and API tokens.
- **Removed key.** `http.auth.bearer_token_env` joins the removed keys.
- **Run the check first.** A refused configuration stops startup. With leased
  FlowSpec, rustbgpd withdraws leased rules within one lease while no
  controller runs, so run `prefixd --check` before restarting.
- **The controller stops reading `PREFIXD_API_TOKEN`.** If the variable is
  still set at startup, the controller logs a warning that names the variable
  and never its value, and it starts normally. Refusing would put the
  controller in a crash loop over a stale variable and drop leased
  mitigations.
- **Client variable renamed.** The client-side variable becomes
  `PREFIXD_TOKEN`, the name the FastNetMon script already uses. Running
  `prefixdctl` inside the controller container then does not set the variable
  the controller warns about. When `PREFIXD_API_TOKEN` is set but
  `PREFIXD_TOKEN` is not, `prefixdctl` warns that the old variable is no longer
  read. A stale shell then gets a clear message instead of a bare 401.
- **The intended break.** Operator sessions and operator tokens lose every
  ingest route.

### 9. Management surfaces

#### Admin API

These routes require an Admin session. They are registered in
`src/api/routes.rs` and in OpenAPI. The operator account routes need a session
too ([amendment](#amendment-identity-management-needs-a-session)).

| Route | Effect |
| --- | --- |
| `POST /v1/tokens` | Body `{name, scope, source?, pop?, expires_at?}`. Returns 201 with the record and `token`, the only time the plaintext appears. |
| `GET /v1/tokens` | Lists every token, revoked ones included: name, scope, source, POP, created, created by, last used, expires and revoked. Returns no secret or hash. |
| `POST /v1/tokens/{name}/revoke` | Revokes the token and returns the record. Revoking an already revoked token returns the same record. |

#### CLI

The CLI writes to the local database, like `prefixdctl operators`, using
`DATABASE_URL`:

```bash
prefixdctl tokens create --name fnm-pop1 --scope ingest --source fastnetmon [--pop pop1] [--expires-in 90d]
prefixdctl tokens list [--created-by <username>]
prefixdctl tokens revoke fnm-pop1
```

- `create` prints the token once on stdout and includes it in `--format json`.
- Each command writes its audit row in the same transaction, with actor
  `prefixdctl`. Database access already outranks Admin, as it does for
  `operators create`.
- An API transport for the CLI is out of scope.

#### Dashboard

Administration gets an **API tokens** tab next to **Users**, visible to Admins
only.

- **Table.** It shows name, scope, bound source, POP, created, created by, last
  used, expires and revoked, with active tokens first.
- **Create dialog.** It takes:
  - a name;
  - a scope;
  - a source, required for `ingest`. It suggests `fastnetmon`,
    `fastnetmon-hostgroup`, `alertmanager`, the enabled bearer webhook
    adapters and the configured correlation sources, and it accepts any valid
    name.
  - an optional POP;
  - an optional expiry.
- **Result.** On success, the dialog shows the token once, with a copy button
  and a ready-to-paste snippet for the chosen source, drawn from
  [section 13](#13-credential-delivery-per-detector):
  - the FastNetMon script's token file and `/etc/default/prefixd` lines;
  - Alertmanager `http_config.authorization.credentials_file`;
  - a bearer header for a webhook or Grafana;
  - a `curl -K -` test that keeps the token off argv.

  The API base comes from the page origin, as in
  [ADR 006](006-runtime-url-derivation.md).
- **Secret handling.** The secret lives only in component state. It is
  cleared when the dialog closes, and it is never written to the SWR cache,
  the URL, browser storage or the console. Closing the dialog before copying
  asks for confirmation.
- **Revoke.** Revoking needs a confirmation that names the token, its source
  and its last use.
- **Accessibility.** Keyboard access, visible focus and both color themes
  follow the existing admin components.

#### Offboarding

Deleting or demoting an operator does not revoke the tokens that operator
created, because tokens belong to the deployment, not to a session. To offboard
someone, list their tokens with `prefixdctl tokens list --created-by <username>`
or filter the dashboard table by creator, then revoke or rotate each one.

#### Bootstrap on a fresh stack

There is no default or shared secret. The operator creates the first admin with
the existing in-container command, and creates the first detector tokens the
same way, in whichever Compose service the deployment runs (`prefixd-rustbgpd`
or `prefixd-gobgp`):

```bash
docker compose exec prefixd-rustbgpd prefixdctl operators create --username admin --role admin
docker compose exec prefixd-rustbgpd prefixdctl tokens create --name fnm-pop1 --scope ingest --source fastnetmon
```

After that, the dashboard manages tokens. A token passed through environment
variables at init is rejected, because it would be the same shared-secret shape
this decision removes. The Compose file and `.env.example` drop
`PREFIXD_API_TOKEN`.

#### Rotation

1. Create a new token under a new name.
2. Update the detector.
3. Confirm that the new token's last-used time advances.
4. Revoke the old token.

Several tokens may share a source, so the old and new tokens overlap without a
gap.

After a leak, revoke the token first, then review `GET /v1/audit` for actor
`token:<name>`, including configuration changes, and revert what the token
changed.

### 10. Mitigate-now is retired

The dashboard no longer posts events. The mitigate-now action opens the
existing manual FlowSpec dialog, prefilled from the playbook that matches the
chosen vector: protocol, ports, action and rate. It submits
`POST /v1/mitigations` as the operator who clicked, so the mitigation goes
through manual admission and is audited under that operator's name.

The `dashboard` source is dropped everywhere: the dialog, the shipped
`configs/correlation.yaml`, the documentation and the tests. A blackhole stays
Admin-only through the manual API, as before.

### 11. Storage

#### Migration 022

Migration 022 runs under the append-only runner. Migration 021 is taken by an
index change in flight.

```sql
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
```

The same migration adds `CHECK (username ~ '^[A-Za-z0-9_-]{1,64}$')` to
`operators`. Before adding it, the migration counts the rows that violate the
pattern. If any do, it raises an error that names the count and points to the
upgrade guide. The migration's transaction then rolls back and the controller
does not start, so no username is rewritten silently. The upgrade guide gives
the query to run before upgrading.

The migration touches no existing mitigation, event, pending operation or audit
row, and it implies no remote acknowledgement. Persistence goes through
`RepositoryTrait`, with a mock implementation for tests.

#### One-way release and version skew

The release is one-way.

- A controller that includes the runner refuses a database that records a
  migration it does not know.
- Rolling back means restoring the pre-upgrade backup, which also discards
  every token minted since.
- A 0.27.0 or older binary has no such check, so it starts against the
  migrated schema. It ignores `api_tokens`, reads `PREFIXD_API_TOKEN` again
  and reopens the source spoof. A downgrade is therefore a security
  regression, not only a schema question, and the upgrade notes say so.

A rolling replacement does not keep detector credentials working.

- An old controller in `bearer` mode accepts only the shared token. One in
  `credentials` mode accepts no bearer credential at all.
- The new controller accepts only database tokens.
- Detectors therefore switch credentials when the active controller changes.

#### Shared database

Several POPs can share one PostgreSQL database. Controllers sharing a database
upgrade together, because the first upgraded controller migrates the schema
for all of them. A shared-database fleet therefore needs one maintenance window
per database, not per POP.

Tokens are global to the database. Bind each detector token to its POP with
`--pop`, unless the detector really serves every POP on that database.

### 12. Bundled FastNetMon scripts

The bundled script becomes an `ingest` client.

#### Token handling

- The script reads the token from `PREFIXD_TOKEN_FILE`, a file with mode 0400
  owned by the FastNetMon user. It falls back to `PREFIXD_TOKEN` from
  `/etc/default/prefixd`, which should be mode 0600.
- curl reads the `Authorization` header from a config passed on stdin
  (`curl -K -`), never from argv. That keeps the token out of `ps` and
  `/proc/*/cmdline`.
- Every POST sets `--connect-timeout` (`EVENT_CONNECT_TIMEOUT_SECONDS`,
  default 5) and `--max-time` (`EVENT_MAX_TIME_SECONDS`, default 15). Each
  attempt is therefore bounded, and so is the time a ban holds its lock. The
  current script sets neither.

*The state file and lock below are replaced by
[unban by victim](#amendment-unban-by-victim) on 2026-11-16; the token
handling above stands.*

#### Ban

- **Saving the event ID.** Before the first POST, the script writes the
  generated `event_id` to
  `${PREFIXD_STATE_DIR:-/var/lib/prefixd-fastnetmon}/<victim-ip>`. It writes a
  temporary file and renames it, so retries and the later unban share the ID.
- **Lock.** The script holds an exclusive `flock` on `<victim-ip>.lock` for its
  whole retry loop.
- **Unwritable state directory.** If the directory is not writable, the script
  still POSTs the ban and logs that the unban for this address will not pair.

#### Unban

1. The script takes the same lock, so it posts only after any ban still
   retrying for that address has finished. It waits at most the ban's worst
   case: `EVENT_POST_ATTEMPTS × (EVENT_MAX_TIME_SECONDS +
   EVENT_POST_DELAY_SECONDS)`. If the wait times out, the unban exits non-zero
   without posting, logs the timeout, and keeps the state file. The rule then
   runs to its TTL unless an operator withdraws it.
2. It reads the state file and posts
   `{"action": "unban", "source": "fastnetmon", "event_id": <id>, ...}` to
   `/v1/events`. Like a ban, it retries only on connection errors and 503.
3. It removes the state file only on a definitive outcome. Every 2xx counts as
   definitive once the lock was acquired, because no ban for that address can
   still be retrying: a withdrawal, `no_active_mitigation` and `not_found`.
4. It keeps the file in two cases: a 4xx, so a corrected rerun can still pair,
   or a lock wait that timed out.

The lock does not order the two processes. FastNetMon starts the ban and unban
scripts independently. An unban spawned at nearly the same moment as its ban
can take the lock first, find no state file, and exit as described under
"No state file" below, leaving the rule to its TTL. Real ban and unban
notifications are separated by the ban time, so this race needs nearly
simultaneous calls. Tests and the CI lane must wait for the ban's outcome
before triggering the unban.

#### Edge cases

- **No state file.** If state was lost, or the ban was sent before the
  upgrade, the script logs that fact and exits 0. The rule expires at its TTL,
  or an operator withdraws it from the dashboard.
- **New ban for the same address.** It overwrites the file. Unban then
  withdraws through `last_event_id` ([section 4](#4-one-enforcement-point-for-every-ingest-route)).
- **Removed settings.** The script no longer reads mitigations or withdraws
  them, so `GET /v1/mitigations`, `PREFIXD_OPERATOR`, `UNBAN_QUERY_*` and
  `WITHDRAW_*` are gone. `BAN_POST_ATTEMPTS` and `BAN_POST_DELAY_SECONDS`
  become `EVENT_POST_ATTEMPTS` and `EVENT_POST_DELAY_SECONDS`, which cover
  both ban and unban.

#### FastNetMon Advanced

Advanced runs a per-host notify script and a separate per-hostgroup notify
script, configured with `notify_script_path` and `notify_script_hostgroup_path`
([vendor docs](https://fastnetmon.com/docs-fnm-advanced/fastnetmon-advanced-callback-scripts/)).
The hostgroup script always receives JSON.

- **Host script.** The bundled script gains a JSON mode for Advanced's host
  script, which runs with `notify_script_format: json`. Its contract and token
  handling are the same as above.
- **Hostgroup script.** It posts prefix events under its own source,
  `fastnetmon-hostgroup`, with its own token. That source is the one operators
  list in `guardrails.detector_prefix_sources`.
- **Native hostgroup adapter.** When it lands (tracked separately), it claims
  `fastnetmon-hostgroup` for total-hostgroup payloads.

The trade-off is deliberate. Adding `fastnetmon` to the prefix allowlist would
hand prefix power to every FastNetMon host token, the Community host scripts
included. A separate source costs a second token and a second correlation
source entry. In exchange, revoking or scoping prefix authority never touches
host mitigation. Prefix events already form their own correlation groups
(ADR 033 §4), so the separate source does not split a group.

### 13. Credential delivery per detector

The controller accepts an ingest credential in exactly two forms:

- **Bearer header.** `Authorization: Bearer prefixd_...`, carrying an ingest
  token.
- **HMAC signature.** The generic webhook adapter's per-adapter HMAC
  (ADR 020): a hex HMAC-SHA256 of the raw body, with an optional `sha256=`
  prefix. The adapter's secret is the credential, bound to the adapter name.

The controller accepts no HTTP Basic auth, and no secret in a URL path, query
string or request body. Such secrets leak through access logs: the shipped
nginx configuration uses the default format, which logs the full request line.
They also leak through proxy logs, the detector's own configuration store and
error reports. A sender that cannot send a header uses a relay.

| Integration | Route and source | How it presents the credential |
| --- | --- | --- |
| FastNetMon Community | `/v1/events`, `fastnetmon` | The bundled notify script sends a bearer token from its token file. Community's only HTTP-capable path is the notify script ([config](https://github.com/pavel-odintsov/fastnetmon/blob/master/src/fastnetmon.conf)). The script makes the HTTP call itself, so FastNetMon never needs to carry a secret. |
| FastNetMon Advanced, host alerts | `/v1/events`, `fastnetmon` | The per-host notify script in JSON mode, with a bearer token from a file. |
| FastNetMon Advanced, total-hostgroup alerts | `/v1/events`, or the native hostgroup adapter once it lands; source `fastnetmon-hostgroup` | The per-hostgroup notify script, with its own bearer token from a file. |
| FastNetMon Advanced, native web callback | `/v1/signals/fastnetmon`, through a relay only | The callback documents only an enabled flag and a URL: no header, Basic, HMAC or client-certificate option ([web callbacks](https://fastnetmon.com/docs-fnm-advanced/fastnetmon-advanced-web-callbacks/)). It cannot carry a credential, so use the notify scripts. If the callback is required, run a localhost relay. |
| Alertmanager | `/v1/signals/alertmanager`, `alertmanager` | `webhook_configs[].http_config.authorization` with `type: Bearer` and `credentials_file` ([configuration](https://prometheus.io/docs/alerting/latest/configuration/)). Alertmanager does not sign webhooks. Use one token per receiver or cluster. `tls_config` supports a custom CA and client certificates. |
| Grafana alerting | `/v1/signals/webhook/{name}`, the adapter name | A bearer token (`authorization_scheme` and `authorization_credentials`) with `auth.type: bearer`, or HMAC with `auth.type: hmac`. Grafana's HMAC with `timestampHeader` set signs `"<timestamp>:" + body`, which the current verifier does not accept, so configure Grafana HMAC without `timestampHeader` ([webhook notifier](https://grafana.com/docs/grafana/latest/alerting/configure-notifications/manage-contact-points/integrations/webhook-notifier/), [hmac.go](https://github.com/grafana/alerting/blob/main/http/hmac.go)). |
| Kentik | `/v1/signals/webhook/{name}`, the adapter name | A bearer token as a custom header on a Custom Webhook channel ([custom headers](https://new.kentik.com/custom-webhook-header-enhancement-ZRJBK)), entered in the Kentik portal and stored by Kentik. HMAC and client-certificate support are not documented, so restrict the source address at the proxy as defense in depth. |
| Andrisoft Wanguard | `/v1/events` or a bearer webhook adapter | Wanguard has no generic webhook action. Its "execute a command or script" response runs a script ([response actions](https://docs.andrisoft.com/wanguard/9.0/Configuration__Network__Policy__Response.html)), which sends a bearer token from a file, as for FastNetMon Community. |
| sFlow-RT | `/v1/events` or a bearer webhook adapter | A custom sFlow-RT script calls `http2()` with an `Authorization` header and reads the token with `getenv()` ([reference](https://sflow-rt.com/reference.php)). |
| Generic webhook, `auth.type: hmac` | `/v1/signals/webhook/{name}`, the adapter name | The sender signs with the secret in `secret_env`, as today. A signer that uses GitHub-style `X-Hub-Signature-256: sha256=<hex>` already matches the verifier. |
| Generic webhook, `auth.type: bearer` | the same | An ingest token bound to the adapter name. A token bound to another source gets 403. |
| Generic webhook, `auth.type: none` | the same | Refused outside `none` mode ([section 5](#5-configuration-refusals)). |
| Corroborating pushers | `/v1/signals/corroborator`, the corroborating source | A bearer ingest token bound to that source. |
| `prefixdctl` | the operator and admin API | `PREFIXD_TOKEN` (preferred over `--token` on the command line) carries an operator or admin token. `send-corroborator` needs an ingest token bound to its `--source`, or an Admin session. `tokens` uses the local database path. |

#### Senders that cannot send a header

A sender that cannot send a header never gets a weaker path on the controller:
no source trusted from its network address, no unauthenticated route, no shared
token and no URL secret. It uses one of these, in order of preference:

1. **A notify or response script,** when the product offers one: FastNetMon,
   Wanguard.
2. **A generic webhook adapter with HMAC,** if the sender signs.
3. **A localhost relay** on the detector host. The relay accepts the callback
   on `127.0.0.1` only, adds `Authorization: Bearer` from a 0400 token file and
   forwards it to the controller over TLS. It logs no headers. The FastNetMon
   Advanced native callback is the one known sender that needs this.

An IP allowlist is defense in depth, never authentication.

#### Open lab checks

The checks below are open and unverified. Nothing in this ADR claims their
outcome:

- FastNetMon Advanced:
  - whether `user:pass@` in `web_callback_url` is sent as Basic auth;
  - whether the callback validates HTTPS certificates, and against which CA
    store;
  - whether the callback URL is logged;
  - whether total-hostgroup alerts reach `web_callback_url` at all;
  - whether `fcli set blackhole` fires the callback and the scripts.
- FastNetMon Community image:
  - whether it ships `curl`;
  - whether it ships `flock(1)`;
  - whether the stdin of a manual ban matches an automatic ban's;
  - whether `fastnetmon_api_client ban` can re-ban an address that is already
    banned.

### 14. Secret exposure

A token must not appear in:

- **CLI help.** `--token`, `--session-cookie` and `--api` already hide their
  environment values in help. Keep that, and document `PREFIXD_TOKEN` or a
  token file as the preferred input over `--token`, which lands in shell
  history.
- **Process arguments.** The bundled scripts and documentation examples pass
  the header to curl through `-K -`, never through `-H` on argv.
- **Logs and tracing fields.** This includes the token hash. Log lines carry
  the token name only.
- **Error bodies.** This includes `SourceNotBound` and the 401 bodies.
- **Other outputs.** `prefixd --check` output, health detail, WebSocket
  messages, and every API response except the create response.
- **Dashboard storage.** The secret stays in component state only, as
  described in [section 9](#9-management-surfaces).
- **URLs.** No route accepts a token in a URL
  ([section 13](#13-credential-delivery-per-detector)).

Tests seed a recognizable secret and assert that it does not appear in:

- `prefixdctl --help` output, with the secret in the environment;
- the argv of the curl processes the bundled script starts;
- controller logs for successful, mismatched, revoked and malformed token
  requests;
- API responses other than create.

### 15. What the interim patch becomes

The closed interim patch is not merged. Its parts move into the
implementation:

- **Tests.** The body-source claim tests for a blackhole-allowlisted source, a
  prefix-allowlisted source and batch ingestion stay. Their credentials become
  an operator token, an Operator session and a mismatched ingest token. The
  batch case now expects a whole-request 403 with no rows, not a per-item 207.
  The adapter-route test that asserted the shared token reaches a detector
  blackhole becomes a negative control. The patch's own negative control, which
  shows the spoof succeeding on unpatched code, is kept.
- **Error.** `SourceBindingRequired` becomes `SourceNotBound`, worded as in
  section 4.
- **Upgrade notes.** The patch's skeleton becomes the release's "Source-bound
  ingest tokens" upgrade section.

### 16. Qualification

- **Community in CI.** FastNetMon Community is qualified in CI, in a lane
  tracked separately. The lane runs the official image,
  `ghcr.io/pavel-odintsov/fastnetmon-community`, pinned by digest (GPL-2.0, no
  license needed). It drives the bundled script with
  `fastnetmon_api_client ban <ip>` and `unban <ip>`. Those calls reach the
  same per-host action function as a detected attack, without depending on
  detection timing. The stdin they produce may differ from a detected
  attack's; that is an open check in
  [section 13](#13-credential-delivery-per-detector). The lane waits for each
  ban's outcome before it triggers the unban
  ([section 12](#12-bundled-fastnetmon-scripts)). The lane asserts:
  - the ban creates a mitigation;
  - the unban withdraws it;
  - a token bound to another source gets 403;
  - the token never appears in argv.

  The extending re-ban case runs the bundled script directly, with two bans
  and then an unban. Whether `fastnetmon_api_client` can re-ban an address
  that is already banned is not yet known (an open check in section 13).
- **Advanced by hand.** FastNetMon Advanced needs a license that renews
  against the vendor's servers, so it is qualified by hand under a trial
  license, with a dated receipt for the host and hostgroup scripts.

### 17. Out of scope

- Certificate-to-role mapping for mTLS, including certificate-to-source
  binding through `authorize_ingest`.
- OIDC, SAML or other SSO for dashboard sessions.
- A `viewer` token scope, and a route that describes the calling token.
- Per-token rate limits. The existing per-class limits apply, and detectors
  behind one proxy share its address's bucket.
- Webhook HMAC replay protection, including Grafana's timestamped signatures.
  The signature has no timestamp or nonce.
- An API transport for `prefixdctl tokens`.
- Recording the token on event rows. The audit actor and the log carry it.

## Operator migration

Plan one maintenance window per database: one per POP for separate databases,
or one for every POP sharing a database. Detector credentials change when the
controller does.

### 1. Before the window

- Back up the database.
- Run the upgrade guide's username query. Rename any operator whose username
  falls outside `[A-Za-z0-9_-]`.
- Inventory every client that holds the shared token:
  - detector hosts and shims;
  - Alertmanager and Grafana contact points;
  - CI jobs.
- **Custom detector scripts.** *Amended 2026-11-16 ([unban by victim](#amendment-unban-by-victim)): the unban names
  the victim, not the ban's `event_id`, and no state directory is staged.*
  Any custom notify script that reads
  `/v1/mitigations` or calls `/withdraw` breaks under an ingest token. Rewrite
  its unban as an event `unban` with the ban's `event_id`, as
  [section 12](#12-bundled-fastnetmon-scripts) describes, or give its
  withdrawal step to an operator. Treat a known pilot's custom script as a
  release-readiness item.
- **Test harnesses** need two tokens each, one ingest and one operator,
  because an ingest token cannot read. This covers `scripts/chaos-test.sh`,
  `lab/interop/run-frr.sh` with `flowspec_frr.py`, `scripts/test-browser.py`
  and the shared fixtures in `tests/common`. Harnesses that pre-generate the
  shared secret switch to minting tokens after the migration.
- Decide one token name, source and POP per detector, and one operator token
  per automation.
- Stage the new FastNetMon script and its token file path (no state
  directory since the [unban by victim](#amendment-unban-by-victim)
  amendment).
- Record the planned cutover time.

### 2. Configuration

- Set `http.auth.mode: credentials` and delete `bearer_token_env`.
- Remove `PREFIXD_API_TOKEN` from the controller's environment.
- Change every webhook adapter with `auth.type: none` to `hmac` or `bearer`.
- Map `fields.source_id` on HMAC adapters that appear in an allowlist.
- Drop any `dashboard` entry from `correlation.yaml`.
- Run `prefixd --check`.

### 3. Cutover

1. Stop every old controller on the database.
2. Start the new ones. The first to start applies migrations 021 and 022.
3. If no admin account exists, create one with `prefixdctl operators create`
   in the `prefixd-rustbgpd` or `prefixd-gobgp` service.
4. Mint one ingest token per detector, and the operator tokens for
   automation and harnesses, with `prefixdctl tokens create`.

### 4. Detectors

Install each token and the new script. Detectors get 401 until their token is
in place, and FastNetMon does not repeat a ban it failed to deliver, so keep
this step short.

### 5. Verification

- Check that each token's last-used time advances under Administration, API
  tokens.
- Check that the controller's startup log has no `PREFIXD_API_TOKEN` warning.

### 6. Bans from before the cutover

Their unbans cannot pair. List them with
`GET /v1/events?source=fastnetmon&end=<cutover time>`. Each event's outcome
names the mitigations it created. Withdraw those that are still active, or let
them expire.

### Rollback

Rollback means restoring the backup from step 1. Do not start an older binary
against the migrated database: a 0.27.0 or older controller would accept the
shared token again and reopen the spoof.

## Threat model

**The spoof.** Any holder of an Operator credential could claim any detector
source: through the event body on any Operator credential, and through the
adapter routes with the shared bearer token. That claim reached:

- Admin-only blackholes;
- detector prefix rules;
- correlation thresholds and weights;
- another detector's unban.

A compromised detector host held a full Operator credential.

**Closed:**

- Source claims on every ingest route, by one typed check.
- Detector privileges for Operator sessions and operator tokens.
- Cross-POP use of a POP-bound token on a shared database.
- Token self-replication through the management API, including through a
  new Admin operator or a password reset
  ([amendment](#amendment-identity-management-needs-a-session)).
- Unauthenticated webhook adapters outside lab mode.
- Replay of signed bans on blackhole-capable or prefix-capable HMAC
  adapters, by required event IDs.
- The unnamed shared secret, which could not be revoked.
- `credentials` mode leaving detectors without a credential.
- Token exposure through CLI help and process arguments.

A compromised detector token can act only as its own source.

**Remains:**

- **A stolen ingest token** carries its source's full detector power within
  the guardrails, including blackholes when the source is allowlisted.
  Revocation is immediate. Detection relies on the last-used time, the
  revoked-token warning and the audit trail.
- **Cross-source extension.** *Replaced by [unban by victim](#amendment-unban-by-victim):* only the source that
  created a mitigation withdraws it by unban; a source that extended it gets
  `no_active_mitigation`.
- **Transport.** A token sent over plain HTTP can be captured, so production
  deployments use TLS.
- **mTLS.** Every certificate is Admin until certificate-to-role mapping
  exists.
- **Admin claims.** An Admin can post any source, and can already change the
  allowlists.
- **Database write access** can insert a token hash, but it already grants
  full control.
- **HMAC replay** of non-allowlisted adapters' bodies, and of any signed body
  whose event ID has not yet been seen.
- **Storage on the detector host.** The token file and any relay
  configuration are only as safe as their permissions.

## Consequences

**Positive:**

- Detector privileges follow an authenticated identity. The blackhole and
  prefix allowlists become authorization, and correlation counts credentials,
  not labels.
- A detector host holds a least-privilege credential. It can create and unban
  only its own source's events, and it cannot read data or create manual
  rules.
- Operator actions are audited under the operator who acted, and dashboard
  clicks no longer count as a detector.
- Tokens are named, POP-scoped, revocable at runtime and audited by name, and
  they work in the recommended `credentials` mode.
- One typed check covers every ingest route, and new routes are closed to
  ingest tokens by default.

**Negative:**

- **The release breaks existing setups.**
  - `bearer` mode, the shared token and mitigate-now's event path are gone.
  - Every detector and automation needs a new credential, and the FastNetMon
    script changes.
  - *Replaced by [unban by victim](#amendment-unban-by-victim):* bans the old script sent before the upgrade pair
    with the new unban by victim.
- **Rollback.** Migration 022 makes the release one-way, and a downgrade
  reopens the spoof.
- **Database dependency.** Token requests add one indexed read. During a
  database outage, ingestion fails anyway, and token requests return 503.
- **Prefix setups.** They need a second source, `fastnetmon-hostgroup`, with
  its own token.
- **mTLS.** Deployments keep all-Admin clients until the certificate-mapping
  follow-up lands.

## Implementation

The work ships in one release, as stacked PRs that are never released
separately:

1. **Tokens and credential resolution.**
   - migration 022, `RepositoryTrait` methods and the shared token generator;
   - `AuthPrincipal`, with Bearer-only precedence and cookie stripping;
   - token verification, including POP binding;
   - the session-only admin API and `prefixdctl tokens`, plus username
     validation in `operators create`;
   - removal of `bearer` mode, `bearer_token_env` and the controller's read of
     `PREFIXD_API_TOKEN`, with the startup warning;
   - renaming the client variable to `PREFIXD_TOKEN`, with a warning when only
     the old one is set, and making the CLI refuse a token and a session
     cookie together.
2. **Source enforcement.**
   - `authorize_ingest` and `SourceGrant` on every ingest route and the
     corroborator write path;
   - unban by triggering or last event (*replaced by [unban by victim](#amendment-unban-by-victim)*);
   - the configuration refusals at all three entry points;
   - the new actor identity;
   - the FastNetMon scripts;
   - the tests carried over from the interim patch.
3. **Dashboard.**
   - the API tokens tab and its snippets;
   - mitigate-now moved onto the manual FlowSpec dialog;
   - `dashboard` removed from the shipped configuration.

Compatibility surfaces to update:

- [configuration](../reference/configuration.md): auth modes, removed keys,
  webhook `auth.type` and the allowlists;
- [API](../reference/api.md): auth, the token routes, 403 `SourceNotBound` and
  the actor IDs;
- [CLI](../reference/cli.md);
- the [FastNetMon](../how-to/detectors/fastnetmon.md),
  [webhook](../how-to/detectors/generic-webhook.md) and
  [corroborating signals](../how-to/detectors/corroborating-signals.md)
  guides;
- the [upgrade guide](../how-to/upgrading.md);
- the Compose file, `.env.example`, the lab configurations and the harness
  scripts;
- the CHANGELOG upgrade notes and security entries.

Tests cover:

- **Ingest token limits.** An ingest token cannot read data, or create or
  withdraw manual rules. An operator token still can create and withdraw.
  Operator sessions and operator tokens get 403 on every ingest route.
- **Source binding.**
  - Each route refuses a mismatched source with 403 and writes no event,
    mitigation or audit row.
  - Adapter routes accept only a token bound to their name.
  - A hostgroup payload needs a token bound to `fastnetmon-hostgroup`.
  - A batch with one mismatched item is refused as a whole, and an item that
    fails to parse keeps its per-item rejection.
  - The allowlists refuse an operator and admit a bound token and an Admin.
  - `min_sources` and weights use the bound source.
  - An unban cannot cross sources at creation, and it withdraws an extended
    mitigation through `last_event_id`. *Replaced by [unban by victim](#amendment-unban-by-victim):* an unban withdraws
    what its source created, an extension by another source does not let
    that source withdraw it, and a vector narrows it.
- **Credential precedence.**
  - A Bearer header with a stale cookie, during a database outage, still
    authenticates the token and leaves the cookie intact.
  - A Basic header with a valid session uses the session.
  - HMAC routes ignore `Authorization`.
  - `prefixdctl` refuses a token and a session cookie together.
- **POP binding (cross-POP).**
  - A token bound to POP A is refused on POP B's controller on a shared
    database.
  - A null-POP token works on both.
  - A token bound to POP A cannot unban POP B's events.
- **Token lifecycle.**
  - A 58-character token name produces an actor ID that passes withdraw,
    bulk withdraw, acknowledge, extend, manual create and safelist mutations.
    A 59-character name is refused at creation.
  - Admin tokens get 403 on `/v1/tokens`.
  - Revoked, expired and malformed tokens get 401, and a storage error gets
    503.
  - `last_used_at` writes are throttled and skipped on a standby.
- **Configuration refusals.** At startup, on reload and through
  `PUT /v1/config/correlation`, the controller refuses:
  - `bearer` mode;
  - `bearer_token_env`, with the right removal version;
  - webhook `auth.type: none` outside `none` mode, and (*amended,
    [unban by victim](#amendment-unban-by-victim)*) an adapter name outside the source pattern, a `secret_env` outside
    `PREFIXD_WEBHOOK_` or shorter than 32 bytes, and an ID-less ban from an
    allowlisted adapter;
  - an allowlisted HMAC adapter without `source_id`;
  - allowlist names outside the token-source pattern.
- **Migration 022.** It refuses to apply over a username outside the pattern,
  and replays cleanly on a migrated database.
- **Secret exposure.** The seeded-secret tests in
  [section 14](#14-secret-exposure).

Negative controls show the spoof succeeding on the unpatched code through
`/v1/events` and through `/v1/signals/fastnetmon`.

## Decisions

1. **The shared token, `auth.mode: bearer` and `bearer_token_env` are removed
   outright.** There is no bridge release, because detectors need ingest
   tokens either way.
2. **The audit actor ID is the credential**, for example `token:<name>`, and
   detector rows carry the bound source in their details
   ([section 6](#6-audit-and-actor-identity)).
3. **A batch is authorized as a whole.** One mismatched source refuses the
   whole request with 403.
4. **Webhook `auth.type: none` is refused unless `http.auth.mode` is `none`**,
   at every configuration entry point.
5. **Mitigate-now moves to `POST /v1/mitigations`.** Ingest routes close to
   Operator sessions and operator tokens, and no `dashboard` source is
   reserved.
6. **Token management** goes through an Admin session or the local CLI. The
   CLI path is local-database only for now. The 2026-11-16 amendment extends
   this to all identity management.
7. **Expiry is optional**, with no default.
8. **No HTTP Basic auth, and no secret in a URL path or query string.** A
   sender that cannot send a header uses a script or a localhost relay
   ([section 13](#13-credential-delivery-per-detector)).

## Amendment: identity management needs a session

Amended 2026-11-16.

### Context

Section 3 closes `/v1/tokens` to every token so that revoking a stolen admin
token evicts the attacker. The operator account routes left that eviction
open. An admin token reached `POST /v1/operators` and
`PUT /v1/operators/{id}/password`, so a stolen admin token could create an
Admin operator, or reset an Admin's password, sign in with a session and mint
tokens from it. Revoking the original token would then evict nobody.

Implementation also settled three details the decision left open.

### Decision

**Identity management needs a signed-in session or the local CLI.** It covers
every route that creates or changes a principal or its credentials:

| Route | Session |
| --- | --- |
| `POST /v1/tokens`, `GET /v1/tokens`, `POST /v1/tokens/{name}/revoke` | Admin |
| `POST /v1/operators` | Admin |
| `DELETE /v1/operators/{id}` | Admin |
| `PUT /v1/operators/{id}/password` | Admin for any operator; any role for its own password |

prefixd has no role-change route and no route that revokes another
operator's sessions. `POST /v1/auth/logout` ends only the caller's own session
and is session-only already.

- **Every token is refused** with 403, admin tokens included.
- **mTLS clients and `none` mode are refused** with 403 as well. Neither is a
  signed-in session: an mTLS client is Admin by certificate and `none` mode is
  anonymous Admin. Deny by default keeps their identity changes on the local
  CLI.
- **Admin tokens keep every other Admin capability**, including listing
  operators.
- **The CLI** (`prefixdctl operators` and `prefixdctl tokens`) stays the
  database path, which already outranks Admin.

**Ingest tokens are refused at extraction.** The principal extractor every
non-ingest route uses refuses an ingest token with 403 before the route reads
its body. The ingest routes extract a separate ingest principal. Without this,
a route that parses its body before calling `require_role` answers an ingest
token with 400 or 422 rather than 403, so nothing would show that the token
was refused. `require_auth` and `require_role` still refuse ingest tokens.

**Several `Authorization` headers with a Bearer among them get 401.** A
request carries one credential. Choosing one of several headers would let a
proxy's header and a client's header disagree about who is calling, so such a
request is refused rather than resolved.

### Consequences

- A stolen admin token can no longer create an Admin operator, reset a
  password or mint a token. Once it is revoked, no credential it could create
  survives it. Configuration it changed while valid, such as an alerting
  destination, stays until an operator reverts it, so the response to a leak
  includes an audit review.
- Automation that managed operators with a token, an mTLS certificate or
  `none` mode moves to `prefixdctl operators` or an Admin session.
- `none` mode loses operator management through the API; operators there are
  managed with `prefixdctl`.

## Amendment: unban by victim

Amended 2026-11-16.

### Context

Section 4's unban resolved the ban event by `(granted source, event_id)`, so
the bundled FastNetMon script had to remember each ban's `event_id` until its
unban. Section 12 built that memory out of a per-victim state file, a `flock`
held across the ban's retries, a wait budget for the unban, rules for when to
keep or delete the file, and a documented race in which an unban started at
nearly the same moment as its ban could run first and leave the rule to its
TTL. The state was also lost whenever the FastNetMon host was rebuilt, and a
ban sent before the upgrade could never pair.

The security property the event ID provided does not need it. What must hold
is that an ingest token cannot read data and cannot withdraw anything outside
its own source. Scoping the unban to the bound source keeps that.

Implementation also found that `PUT /v1/config/correlation`, which an admin
token reaches, could point an HMAC adapter's `secret_env` at a guessable
variable such as `PATH`. A stolen admin token could then keep posting signed
events as that adapter after the token was revoked.

### Decision

**A detector unban names its victim.** The server withdraws the live
mitigations for that victim on the controller's POP whose triggering event came
from the granted source. It compares the victim in canonical form, so a
zero-padded IPv6 unban matches a canonically stored mitigation. It replaces the
unban bullet in section 4 and the state file and lock in section 12.

- Mitigations another source created for the same victim, and manual
  mitigations, are never touched.
- An unban after an extending re-ban withdraws the mitigation, and so does an
  unban after a lost earlier unban. No client state is needed.
- With nothing to withdraw the answer is the definitive
  `no_active_mitigation`; `not_found` and `ignored_no_event_id` are gone.
- The unban's `event_id` and `vector` select nothing. The unban is still
  stored as an event, and the withdrawal is audited as the credential with the
  reason `Detector unban: <source>`.
- A POP-bound token cannot unban another POP's mitigation: it is refused on
  that POP's controller, and a controller's unban considers only its own POP.

The bundled script posts ban and unban to `/v1/events` with its ingest token,
read from `PREFIXD_TOKEN_FILE` or `PREFIXD_TOKEN` and passed to curl on stdin.
It keeps the per-attempt timeouts and retries on 503 and transport errors, and
it has no state directory and no `flock`. It takes the victim from `$1`, never
from stdin, because a manual IPv6 ban's stdin says `IP: 0.0.0.0`. It needs only
bash and curl, since the FastNetMon Community image ships neither `jq` nor
`python3`.

**Adapter secrets live in a fixed namespace.** An HMAC adapter's `secret_env`
must name a variable starting with `PREFIXD_WEBHOOK_` whose value is at least
32 bytes. Section 5's refusals apply it at startup, on reload and through
`PUT /v1/config/correlation`. Config tuning stays automatable, and a changed
configuration can only reach secrets an operator put in that namespace.

**The native FastNetMon adapter claims by scope.** A host alert claims
`fastnetmon`; any other `alert_scope` claims `fastnetmon-hostgroup`, so a
host-only token never reaches hostgroup ingestion.

### Consequences

- The threat model's cross-source extension case narrows: if source A creates
  a mitigation and source B extends it, only A's unban withdraws it.
- An unban that names a vector other than `unknown` withdraws only that
  vector's mitigations for the victim, so a resolved Alertmanager alert for one
  attack leaves the source's others; `unknown` keeps the whole victim, which
  the FastNetMon script needs because its unban carries no attack details.
- With correlation, the triggering event is whichever event met the group's
  threshold, so only that event's source withdraws the mitigation by unban.
- Withdrawal intent is recorded for every selected mitigation before any
  delete, and a failed or ambiguous delete answers 503 with the intent
  pending, so one failure cannot strand the rest and a resend is idempotent.
  The request keeps the bound source (migration 024) for the completion audit
  and the `detector_unban` metric, whoever completes it.
- An adapter named in an allowlist refuses a ban that has no event ID, since
  only the ID makes a replayed signed ban a duplicate.
- Bans sent before the upgrade pair with the new unban, because the mitigation
  records its triggering event and that event its source.
- Not delivered with this amendment: the section 12 hostgroup script and the
  JSON mode for FastNetMon Advanced's host script. Advanced's hostgroup notify
  contract is not yet qualified (section 13's open checks). Until it is, a
  hostgroup shim posts prefix events with its own `fastnetmon-hostgroup` token,
  as the FastNetMon guide shows.
