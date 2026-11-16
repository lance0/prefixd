# ADR 034: Source-Bound Scoped API Tokens

## Status

Proposed 2026-11-15. Amends [ADR 008](008-session-auth-plus-bearer.md): named,
hashed, revocable API tokens replace the shared bearer token, and the `bearer`
auth mode is removed. Amends the source allowlists of
[ADR 027](027-blackhole-mitigations.md) §2 and
[ADR 033](033-detector-prefix-mitigations.md) §1, which become authorization
keyed on an authenticated source instead of label filters. Extends
[ADR 019](019-signal-adapter-architecture.md),
[ADR 020](020-generic-webhook-adapter.md) and
[ADR 021](021-corroborating-signals.md). Nothing in this ADR is implemented
yet. The [owner decisions](#owner-decisions) section lists the choices that
need confirmation before implementation starts.

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

The source is not authenticated. `/v1/events`, `/v1/events/batch` and
`/v1/signals/corroborator` read it from the request body. The FastNetMon,
Alertmanager and generic webhook adapters set it from the route, but they
accept any Operator credential. Ingestion needs only the Operator role, and the
shared bearer token is Operator. So any CLI user, detector host or Operator
session can post `{"source": "fastnetmon", ...}` and get a detector blackhole
that a manual request reserves for Admin. The same credential can claim a
prefix-allowlisted source, satisfy `min_sources` by posting under several
labels, borrow a high-weight source's weight, or send an `unban` for another
detector's event ID.

The detector credential is also too broad. A FastNetMon host holding the shared
token is a full Operator: it can create manual FlowSpec rules, withdraw any
mitigation and read everything. The bundled Community script needs those
rights today, because its unban lists `/v1/mitigations` by victim and calls
`/withdraw`.

The token is a single unnamed secret read from `PREFIXD_API_TOKEN` at startup.
It cannot be revoked without a restart, and every request it makes is audited
as `bearer-token`. In `credentials` mode, the recommended mode and the
shipped Compose default, no bearer token is accepted at all, so a detector
cannot authenticate without an operator session.

### The interim fix was the wrong shape

An interim patch made `/v1/events` require Admin when the body named an
allowlisted source. Independent review blocked it:

1. The adapter routes still accepted any Operator credential and then bound
   the source themselves, so the shared token still reached a detector
   blackhole through `/v1/signals/fastnetmon`.
2. The gate keyed on the label, not the privilege. Once `fastnetmon` was
   allowlisted, every ban from the bundled script, including host FlowSpec
   bans, got 403.
3. Its migration paths were the native adapter (Advanced-only, host-only),
   `auth.mode: none`, or an Admin password on the detector host.

The fix is to authenticate the source.

## Decision

### 1. Token model

A token is a named database row with one scope. Admins create, list and
revoke tokens at runtime without a restart.

- **Format.** `prefixd_` followed by 43 base64url characters encoding 32 bytes
  from the operating system CSPRNG. The fixed prefix lets secret scanners
  recognize a leaked token. A presented value that does not match the format
  is refused before any database query.
- **Hash.** The row stores SHA-256 of the full token, 32 bytes, under a unique
  index, and the request path looks the token up by that hash. The secret is
  256 bits of randomness, so a stolen hash gives no practical preimage, and
  salting or a slow KDF adds nothing. Argon2 is right for passwords, which are
  low-entropy, but it would cost tens of milliseconds and megabytes of memory
  on every ingest request, and a salted hash cannot be indexed, so each
  token would also need a lookup identifier. A peppered HMAC would add
  key management for no gain at this entropy.
- **Shown once.** The plaintext appears only in the create response and is
  never stored, logged or retrievable. Create responses carry
  `Cache-Control: no-store`.
- **Name.** `^[a-z0-9][a-z0-9-]{0,63}$`, unique across all rows, including
  revoked ones. Names are never reused, so audit history stays unambiguous.
- **Expiry.** `expires_at` is optional, and tokens do not expire by default.
  A detector token that expires during an attack leaves the attack
  unmitigated, so expiry is an explicit choice made at creation.
- **Revocation.** Revoking sets `revoked_at` and `revoked_by` and keeps the
  row. It takes effect on the next request, because every request reads the
  row. There is no in-memory cache to invalidate.
- **Last used.** `last_used_at` is updated on successful authentication at
  most once a minute per token, as a best-effort write that never fails the
  request. It is accurate to about 60 seconds.
- **Failures.** Unknown, revoked and expired tokens get 401. The error names
  `revoked` or `expired`, which tells the holder nothing they do not already
  know. A database error during lookup returns 503, never 401, so a storage
  outage does not look like a credential problem.

Tokens are verified in `credentials` mode. `none` mode stays anonymous Admin
and ignores credentials. `mtls` mode stays as described in
[section 4](#4-mtls-and-none-mode).

An `Authorization` header, when present, is the request's credential. If it is
invalid, the request gets 401 even when a session cookie is also present; the
controller does not fall back from a bad token to a session. WebSocket and
`/v1/auth/*` session routes remain session-only.

#### Audit

Token management is Admin-only. Every create and revoke writes an audit row:
action `api_token.create` or `api_token.revoke`, target type `api_token`,
target ID the token name, and details holding the scope, source and expiry,
never the secret. The actor is whoever made the change: the admin's username
or `token:<name>`, or `prefixdctl` for the local CLI path in
[section 6](#6-management-surfaces).

Requests made with an operator or admin token are audited with actor type
`operator` and actor ID `token:<name>`, replacing `bearer-token`. Usernames
cannot contain `:`, so the namespace cannot collide.

A detector-created mitigation keeps actor type `detector` and actor ID equal to
the bound source. The source is the identity that guardrails, correlation and
the dashboard key on. The audit details add `credential: "token:<name>"`, so
revocation forensics can tell which token posted. The ingest warning log
carries the token name, the bound source and the claimed source.

### 2. Scopes

| Scope | Role equivalent | Reaches |
| --- | --- | --- |
| `ingest` | none | `POST /v1/events`, `POST /v1/events/batch`, `POST /v1/signals/fastnetmon`, `POST /v1/signals/alertmanager`, `POST /v1/signals/webhook/{name}` for `auth.type: bearer` adapters, and `POST /v1/signals/corroborator`. Nothing else, no reads. Requires a bound `source`. |
| `operator` | Operator | Every route the Operator role reaches today, with ingest limited as in section 3 |
| `admin` | Admin | Every route the Admin role reaches, including token management |

An ingest token is not a role in the `Viewer < Operator < Admin` order. The
request principal becomes:

```rust
enum Principal {
    Operator(Operator),                         // session, operator/admin token, mTLS, none
    Ingest { token: String, source: String },
}
```

`require_auth` and `require_role` refuse `Principal::Ingest` with 403. Only
`authorize_ingest` accepts it, so a route that does not call it is closed to
ingest tokens by default, and a new route needs a deliberate change before an
ingest token can reach it.

A token's `source` matches `^[a-z0-9][a-z0-9_-]{0,63}$` and cannot be
`dashboard`. Several tokens may share a source; two FastNetMon instances,
`fnm-pop1` and `fnm-pop2`, are both bound to `fastnetmon`. They count as one
correlation source, because they are one detector type.

A read-only `viewer` token scope is not part of this decision.

### 3. One enforcement point for every ingest route

Every ingest route calls one function before any validation that touches
state:

```rust
fn authorize_ingest(principal: &Principal, claimed: &str) -> Result<SourceGrant, PrefixdError>;
```

| Principal | Rule | Grant |
| --- | --- | --- |
| Ingest token | `claimed` must equal the token's source | bound to that source |
| Admin (session, admin token, mTLS, `none`) | any `claimed` | bound to `claimed` |
| Operator (session or operator token) | `claimed` must be `dashboard` | bound to `dashboard` |
| Viewer | refused, as today | none |

`SourceGrant` has a private field, so only `authorize_ingest` and the HMAC
adapter path below can build one. `handle_ban` and `handle_unban` take a
`SourceGrant` and set the event's `source` from it. A route cannot reach
admission without the check, and the source-keyed checks
(`check_detector_source`, `check_detector_prefix`, correlation weight,
`min_sources` counting, corroborating mode and the unban lookup) all read the
granted source. Each route supplies `claimed` as follows:

| Route | `claimed` |
| --- | --- |
| `POST /v1/events` | body `source` |
| `POST /v1/events/batch` | each item's `source`. The whole batch is authorized before any item runs; one mismatched item refuses the request with 403 and nothing is stored or actuated. |
| `POST /v1/signals/fastnetmon` | `fastnetmon` |
| `POST /v1/signals/alertmanager` | `alertmanager` |
| `POST /v1/signals/webhook/{name}`, `auth.type: bearer` | the adapter name |
| `POST /v1/signals/webhook/{name}`, `auth.type: hmac` | no principal: the adapter's own secret is a credential bound to the adapter name, and the verified signature yields the grant |
| `POST /v1/signals/corroborator` | body `source` |

A mismatch is `PrefixdError::SourceNotBound { claimed, bound }`, status 403.
Its message names the claimed source and, for a token, its bound source:
`source "fastnetmon" is not bound to this credential (bound to "radware")`. For
an Operator principal, it says that only `dashboard` may be posted and that
detector sources need an ingest token. It echoes no other request field.
The rejection metric is labeled with the bound source, never the claimed one,
so a caller cannot inflate label cardinality.

The effects follow from that one rule:

- **Blackhole and prefix allowlists.** These are now authorization: only an
  ingest token bound to an allowlisted source, the HMAC adapter of that name,
  or an Admin can reach them. Neither the shared token nor an Operator session
  reaches them through any route.
- **Correlation.** Each distinct source in a group is a distinct bound
  credential or an Admin claim. `min_sources: 2` now needs two credentials
  bound to different sources. Weights and corroborating mode apply to the
  bound source.
- **Unban.** An ingest token can withdraw only what its own source created,
  because the lookup key is `(granted source, event_id)`. Operators who need to
  withdraw a detector's mitigation use `POST /v1/mitigations/{id}/withdraw`,
  which keeps its confirmation, reason and audit trail.
- **Dashboard.** The mitigate-now dialog posts `source: "dashboard"` under an
  Operator session and keeps working. `dashboard` is reserved: configuration
  load refuses it in `blackhole.detector_sources`,
  `guardrails.detector_prefix_sources` and as a `mode: corroborating` source,
  and the database refuses it as a token source. It may keep a correlation
  weight.
- **Unauthenticated webhook adapters.** `auth.type: none` would let anyone who
  can reach the controller claim the adapter's source. Configuration load
  refuses it unless `http.auth.mode` is `none`, which turns the existing
  "lab use only" warning into a rule.

A source that appears in an allowlist but does not match the token-source
pattern can be claimed only by an Admin.

### 4. mTLS and none mode

In `mtls` mode, every client certificate is Admin, and tokens are not
consulted. An mTLS client therefore keeps an Admin grant for any source. That
grants nothing new: the same certificate can already create a manual
blackhole. The gap stays open until certificate-to-role mapping exists. That
follow-up maps a certificate to a scope and, for ingest, a source, and goes
through the same `authorize_ingest`. Until then, deployments that need
per-detector least privilege use `credentials` mode with ingest tokens.

`none` mode is anonymous Admin, as today.

### 5. The shared token and the `bearer` mode are removed

The shared token is the credential that caused this problem. It is unnamed,
cannot be revoked at runtime, is audited as one identity and, under section 3,
could carry no detector privilege at all. A reduced version scoped to operator
would be a second token path in `require_role` that is worse than an operator
token in every respect. It is removed, not deprecated:

- `http.auth.mode: bearer` is refused at load and by `prefixd --check`, with an
  error pointing to the upgrade guide. `credentials` now means operator
  sessions plus API tokens.
- `http.auth.bearer_token_env` is added to the removed-keys table and refused
  while present.
- The controller no longer reads `PREFIXD_API_TOKEN`. If the variable is set
  at startup, the controller logs a warning that names the variable and never
  its value, so stale deployment config is visible.
- Operator sessions and the former shared token lose detector privileges on
  every route. This is the intended break.

`prefixdctl --token` and its client-side `PREFIXD_API_TOKEN` variable stay: the
variable holds whichever API token the CLI presents, which is now an operator
or admin token.

### 6. Management surfaces

**Admin API**, Admin only, registered in `src/api/routes.rs` and OpenAPI:

| Route | Effect |
| --- | --- |
| `POST /v1/tokens` | Body `{name, scope, source?, expires_at?}`. Returns 201 with the record and `token`, the only time the plaintext appears. |
| `GET /v1/tokens` | Lists all tokens, revoked included: name, scope, source, created, created by, last used, expires, revoked. No secret or hash. |
| `POST /v1/tokens/{name}/revoke` | Revokes the token and returns the record. Revoking an already revoked token returns the same record. |

**CLI**, a local database path like `prefixdctl operators`, using
`DATABASE_URL`:

```bash
prefixdctl tokens create --name fnm-pop1 --scope ingest --source fastnetmon [--expires-in 90d]
prefixdctl tokens list
prefixdctl tokens revoke fnm-pop1
```

`create` prints the token once on stdout and includes it in `--format json`.
Each command writes its audit row in the same transaction, with actor
`prefixdctl`. Database access already outranks Admin, as it does for
`operators create`. Remote automation uses the admin API with an admin token.

**Dashboard.** Administration gets an **API tokens** tab next to **Users**,
shown to Admins only:

- The table shows name, scope, bound source, created, last used, expires and
  revoked, with active tokens first.
- The create dialog takes a name, a scope, a source (required for `ingest`;
  it suggests `fastnetmon`, `alertmanager`, enabled webhook adapter names and
  configured correlation sources, and accepts any valid name) and an optional
  expiry.
- On success, the dialog shows the token once, with a copy button and a
  ready-to-paste snippet for the chosen source:
  - the FastNetMon script's `/etc/default/prefixd` lines (`PREFIXD_API`,
    `PREFIXD_TOKEN`);
  - Alertmanager's webhook receiver authorization settings, in the form that
    section 9 records once verified;
  - a webhook `Authorization: Bearer` header;
  - a `curl` test.

  The API base comes from the page origin, as in
  [ADR 006](006-runtime-url-derivation.md). The secret lives only in
  component state. It is cleared when the dialog closes and is never written
  to the SWR cache, the URL, browser storage or the console. Closing the
  dialog asks for confirmation if the token has not been copied.
- Revoke needs a confirmation that names the token, its source and its last
  use. Keyboard access, visible focus and both color themes follow the
  existing admin components.

**Bootstrap on a fresh stack.** There is no default or shared secret. The
operator creates the first admin with the existing in-container command, and
the first detector tokens the same way:

```bash
docker compose exec prefixd-rustbgpd prefixdctl operators create --username admin --role admin
docker compose exec prefixd-rustbgpd prefixdctl tokens create --name fnm-pop1 --scope ingest --source fastnetmon
```

After that, tokens can be managed from the dashboard. A token passed in
through environment variables at init would be the same shared-secret shape
this decision removes, and is rejected. The Compose file and `.env.example`
drop `PREFIXD_API_TOKEN`.

**Rotation.** Create a new token under a new name, update the detector,
confirm that the new token's `last used` advances, then revoke the old one.
Several tokens may share a source, so the two overlap with no gap.

### 7. Storage

Migration 021 adds one table under the append-only runner:

```sql
CREATE TABLE IF NOT EXISTS api_tokens (
    token_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,63}$'),
    token_hash   BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    scope        TEXT NOT NULL CHECK (scope IN ('ingest', 'operator', 'admin')),
    source       TEXT CHECK (source ~ '^[a-z0-9][a-z0-9_-]{0,63}$' AND source <> 'dashboard'),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by   TEXT NOT NULL,
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    revoked_by   TEXT,
    CHECK ((scope = 'ingest') = (source IS NOT NULL))
);
```

The migration touches no existing row, pending operation or audit entry, and
does not imply any remote acknowledgement. Persistence goes through
`RepositoryTrait` with a mock implementation for tests.

The release is one-way. A controller that includes the runner refuses a
database that records a migration it does not know, so rolling back means
restoring the pre-upgrade backup, which also discards every token minted since.
A 0.27.0 or older binary has no such check and starts against the migrated
schema. It ignores `api_tokens`, reads `PREFIXD_API_TOKEN` again and reopens
the source spoof. Downgrade is therefore a security regression, not only a
schema question, and the upgrade notes say so.

A rolling replacement is not credential-compatible. The old active controller
accepts only the shared token, and the new one accepts only database tokens.
Detectors switch credentials when the active controller changes. See the
[operator migration](#operator-migration).

### 8. Bundled FastNetMon script

The script becomes an `ingest` client:

- **Ban.** Before the first POST, the script writes the generated `event_id` to
  `${PREFIXD_STATE_DIR:-/var/lib/prefixd-fastnetmon}/<victim-ip>`, writing a
  temporary file and renaming it, so a retried POST and the later unban use the
  same ID.
- **Unban.** The script reads that file and posts
  `{"action": "unban", "source": "fastnetmon", "event_id": <id>, ...}` to
  `/v1/events`. It retries only on connection errors and 503, like a ban, and
  removes the file after any 2xx, including `not_found` and
  `no_active_mitigation`. It keeps the file after a 4xx, so a corrected rerun
  can still pair. With no file (state lost, or a ban sent before the upgrade),
  it logs that fact and exits 0. The rule then expires at its TTL, or an
  operator withdraws it from the dashboard. A new ban for the same address
  overwrites the file.
- **Removed.** The script no longer reads mitigations or withdraws: the
  `GET /v1/mitigations` lookup, `PREFIXD_OPERATOR`, `UNBAN_QUERY_*` and
  `WITHDRAW_*` are gone. `BAN_POST_ATTEMPTS` and `BAN_POST_DELAY_SECONDS`
  become `EVENT_POST_ATTEMPTS` and `EVENT_POST_DELAY_SECONDS`, which cover ban
  and unban.
- **Configuration.** `/etc/default/prefixd` holds `PREFIXD_API` and
  `PREFIXD_TOKEN`, an ingest token bound to `fastnetmon`, with mode 0600 and
  owned by the FastNetMon user. That user must be able to write the state
  directory.

A ban sent by the old script before the upgrade has a random event ID that the
new script never recorded, so its unban does nothing and the rule runs to its
TTL. Operators either accept that or withdraw those rules once after cutover.

The native `/v1/signals/fastnetmon` adapter uses the same token. A prefix shim
that posts total-hostgroup events to `/v1/events`, and the native hostgroup
adapter when it lands, use an ingest token bound to the prefix-allowlisted
source. A separate token per shim keeps revocation independent.

### 9. Credential delivery per detector

The controller accepts an ingest credential in one of two forms:

- **Bearer header (preferred):** `Authorization: Bearer prefixd_...`, carrying
  an ingest token.
- **HMAC signature:** the generic webhook adapter's existing per-adapter HMAC
  (ADR 020). The adapter's secret is the credential, bound to the adapter
  name. Use it for senders that sign request bodies.

The controller does not accept a token in a query string, URL path or request
body. Those leak through access logs, proxy logs, browser history and error
reports, and the dashboard would have to display a secret-bearing URL.
Whether to accept `Authorization: Basic` with the token as the password, for
senders that support only basic auth, is decided once the detector
capabilities below are verified. It is the same secret in a different header
encoding, so it is no weaker than a bearer header.

| Integration | Route and source | How it presents the credential |
| --- | --- | --- |
| FastNetMon Community | `/v1/events`, `fastnetmon` | The bundled notify script sends `Authorization: Bearer $PREFIXD_TOKEN` from `/etc/default/prefixd` (mode 0600). The script runs on the detector host, so FastNetMon itself never needs to carry a secret. |
| FastNetMon Advanced, host alerts | `/v1/signals/fastnetmon`, `fastnetmon` | TODO: unverified. Confirm, with a cited source, whether FastNetMon Advanced's JSON callback can send a custom `Authorization` header, basic auth or a signature. If it can send a header, use a bearer ingest token. If it cannot, use the relay below. |
| FastNetMon Advanced, total-hostgroup alerts | the native hostgroup adapter when it lands, or a shim to `/v1/events`, bound to the prefix-allowlisted source | Same callback mechanism as host alerts, with the same TODO. Until the native adapter exists, the shim is a relay that holds its own ingest token. |
| Alertmanager | `/v1/signals/alertmanager`, `alertmanager` | TODO: unverified. Confirm, with a cited source, the webhook receiver's authorization settings: a bearer credential, whether it can be read from a file, and basic auth. If a bearer credential is supported, the dashboard snippet uses it, preferring a file over an inline secret. |
| Generic webhook, `auth.type: hmac` | `/v1/signals/webhook/{name}`, the adapter name | The sender signs the body with the adapter's secret, held in the environment variable named by `secret_env`. This is unchanged and needs no token. Which vendors sign, and how, is recorded per vendor in the webhook guide. |
| Generic webhook, `auth.type: bearer` | the same | An ingest token bound to the adapter name, sent as `Authorization: Bearer`. A token bound to another source gets 403. |
| Generic webhook, `auth.type: none` | the same | Refused outside `none` mode (section 3). |
| Corroborating pushers | `/v1/signals/corroborator`, the configured corroborating source | A bearer ingest token bound to that source. |
| `prefixdctl` | the admin and operator API | `--token` or the `PREFIXD_API_TOKEN` client variable sends a bearer operator or admin token. `send-corroborator` needs an ingest token bound to its `--source`, or an admin token. `tokens` uses the local database path (section 6). |

**A sender that cannot carry a per-detector secret** never gets a weaker
controller-side path, such as a source trusted from the network address, an
unauthenticated route or a shared default token. It uses one of these, in
order of preference:

1. **A generic webhook adapter with HMAC**, if the sender can sign.
2. **A relay next to the detector** that receives the sender's callback on
   loopback or a private interface, adds `Authorization: Bearer`, and forwards
   it to the controller over TLS. The bundled FastNetMon notify script is this
   pattern, and a prefix shim is another. The relay host stores the token in a
   0600 file. The relay accepts callbacks only from the detector's address and
   logs no headers.
3. **A reverse proxy in front of the controller** that injects the header for
   one route, and only for the detector's source address over a private
   network. This ties the credential to a network location. The proxy
   configuration then holds the secret, so it gets the same file permissions
   and secret handling. Use it only when the first two options are not
   possible, and record that choice in the deployment's notes.

If a detector can do none of these, it cannot be an authenticated prefixd
source. It may still alert a human, who acts from the dashboard.

### 10. What the interim patch becomes

The closed interim patch is not merged. Its parts move into the implementation:

- **Tests.** The body-source claim tests for a blackhole-allowlisted source, a
  prefix-allowlisted source and batch ingestion stay. Their credentials become
  an operator token, an Operator session and a mismatched ingest token, and
  the batch case expects a whole-request 403 with no rows instead of a per-item
  207. Its adapter-route test, which asserted that the shared token reaches a
  detector blackhole, is inverted into a negative control. Its negative
  control showing that the spoof succeeds on unpatched code is kept.
- **Error.** `SourceBindingRequired` becomes `SourceNotBound`, with the wording
  in section 3.
- **Upgrade notes.** Its skeleton becomes the release's "Source-bound ingest
  tokens" upgrade section.

### 11. Out of scope

- **Certificate-to-role mapping for mTLS**, including certificate-to-source
  binding through `authorize_ingest`.
- **OIDC, SAML or other SSO** for dashboard sessions.
- **A `viewer` token scope**, and a token self-description route.
- **Per-token rate limits.** The existing per-class limits apply.
- **Webhook HMAC replay protection.** The signature has no timestamp or nonce.
  This is an existing gap.
- **A `prefixdctl tokens` API transport** for remote CLI management.
- **Recording the token on event rows.** The audit details and the log carry
  it.

## Operator migration

Plan one maintenance window per POP. The detectors' credentials change when the
controller does.

1. **Before.** Back up the database. List every client that holds
   `PREFIXD_API_TOKEN`: detector hosts, shims, Alertmanager, scripts and CI
   jobs. Decide one token name and one bound source for each detector, and one
   operator or admin token for each automation. Stage the new FastNetMon
   script and its state directory.
2. **Configuration.** Set `http.auth.mode: credentials` and delete
   `bearer_token_env`. Change any webhook adapter with `auth.type: none` to
   `hmac` or `bearer`. Remove `dashboard` from any detector allowlist. Run
   `prefixd --check`.
3. **Cutover.** Stop the old controller and start the new one, which applies
   migration 021. If no admin account exists, create one with
   `prefixdctl operators create`. Mint one ingest token per detector with
   `prefixdctl tokens create`, and operator or admin tokens for automation.
4. **Detectors.** Install each token and the new script. Expect 401 from
   detectors until their token is in place; FastNetMon does not repeat a ban
   it failed to deliver, so keep this step short.
5. **Verify.** In Administration, under API tokens, check that each token's
   `last used` advances. Check that the controller no longer warns that
   `PREFIXD_API_TOKEN` is set, then remove the variable from the deployment.
6. **Old bans.** Withdraw, or let expire, the rules created by the old script
   before cutover; their unbans cannot pair.

Rollback means restoring the backup taken in step 1. Do not start an older
binary against the migrated database: a 0.27.0 or older controller would
accept the shared token again and reopen the spoof.

## Threat model

**The spoof.** Any holder of an Operator credential, or the shared bearer
token on every route, could claim any detector source. That reached Admin-only
blackholes, detector prefix rules, correlation thresholds and weights, and
another detector's unban, through the event body or the adapter routes. A
compromised detector host was a full Operator.

**Closed:**

- Source claims on every ingest route, through one typed check.
- Detector privileges for Operator sessions and the shared token.
- Unauthenticated webhook adapters outside lab mode.
- The unnamed, unrevocable shared secret.
- The gap where `credentials` mode left detectors no credential.

A compromised detector token can now act only as its own source.

**Remains:**

- **A stolen ingest token** carries its source's full detector power within
  the guardrails. That includes blackholes when the source is allowlisted, and
  unban of that source's own mitigations. Revocation is immediate; detection
  depends on `last used` and the audit trail.
- **Transport.** A token sent over plain HTTP can be captured. Production
  deployments use TLS.
- **mTLS.** Every certificate is Admin until certificate-to-role mapping
  exists.
- **Admin claims.** An Admin can post any source. Admin can already change the
  allowlists.
- **Database write access** can insert a token hash. It already grants full
  control.
- **Webhook HMAC** bodies can be replayed.
- **Detector hosts** store the token in a file, so its permissions matter.

## Consequences

**Positive:**

- Detector privileges follow an authenticated identity. The blackhole and
  prefix allowlists become authorization, and correlation counts credentials,
  not labels.
- A detector host holds a least-privilege credential that cannot read,
  withdraw other rules or create manual rules.
- Tokens are named, revocable at runtime, audited by name and work in the
  recommended `credentials` mode.
- One typed check covers every ingest route, and new routes are closed to
  ingest tokens by default.

**Negative:**

- This is a breaking release. `bearer` mode and the shared token are gone,
  every detector and automation needs a new credential, and the FastNetMon
  script changes. Bans the old script sent before the upgrade cannot be
  unbanned by the new one.
- Migration 021 makes the release one-way, and a downgrade reopens the spoof.
- Every authenticated API request does one indexed database read. During a
  database outage, ingestion fails anyway, and token requests return 503.
- mTLS deployments keep all-Admin clients until the follow-up lands.

## Implementation

Ship in one release, as stacked PRs that do not release separately:

1. Migration 021, `RepositoryTrait` methods, `Principal`, token verification
   in `credentials` mode, the admin API, `prefixdctl tokens`, removal of
   `bearer` mode and `bearer_token_env`, and the startup warning.
2. `authorize_ingest` and `SourceGrant` on every ingest route, the reserved
   `dashboard` source, the configuration refusals, the FastNetMon script, and
   the carried-over tests.
3. The dashboard API tokens tab and snippets.

Compatibility surfaces to update: [configuration](../reference/configuration.md)
(auth modes, removed keys, webhook `auth.type`, allowlists),
[API](../reference/api.md) (auth, token routes, 403 `SourceNotBound`),
[CLI](../reference/cli.md), the
[FastNetMon](../how-to/detectors/fastnetmon.md),
[webhook](../how-to/detectors/generic-webhook.md) and
[corroborating signals](../how-to/detectors/corroborating-signals.md) guides,
the [upgrade guide](../how-to/upgrading.md), the Compose file,
`.env.example`, lab configurations, and CHANGELOG upgrade notes and security
entries.

Tests cover each case:

- An ingest token cannot create or withdraw manual rules, or read anything.
- An operator token can still create and withdraw manual rules.
- Each route refuses a mismatched source with 403 and writes no event,
  mitigation or audit row.
- Adapter routes accept only a token bound to their name.
- A batch with one mismatched item is refused as a whole.
- An Operator session can post only `dashboard`.
- The allowlists refuse an Operator and admit a bound token and an Admin.
- `min_sources` and weights use the bound source.
- An unban cannot cross sources.
- Revoked, expired and malformed tokens get 401, and a storage error gets 503.
- `last_used_at` writes are throttled.
- The create response returns the plaintext once, and no log line contains it.
- Configuration load refuses `bearer` mode, `bearer_token_env`, `dashboard` in
  an allowlist, and webhook `auth.type: none` outside `none` mode.

Negative controls show the spoof succeeding through `/v1/events` and through
`/v1/signals/fastnetmon` on the unpatched code.

## Owner decisions

The ADR chooses a default for each of these:

1. **Remove the shared token outright** (chosen), or keep it for one release as
   an operator-scope bridge with no detector privileges and a deprecation
   warning. A bridge would not shorten the detector cutover, because detectors
   need ingest tokens either way.
2. **Detector audit attribution.** The chosen default keeps the actor ID as the
   source and adds the token name in details. The alternative records the
   token name as the actor ID, which changes what the audit and dashboard
   filters show for detector-created mitigations.
3. **Batch authorization.** The chosen default refuses the whole request on one
   mismatched item. The alternative is the interim patch's per-item 207.
4. **Webhook `auth.type: none`.** The chosen default refuses it outside `none`
   mode. The alternative keeps it with the warning, which leaves an open source
   claim.
5. **Operator event ingest.** The chosen default allows only `dashboard`. The
   alternative moves mitigate-now to the manual mitigation API and closes
   ingest routes to Operators entirely.
6. **CLI transport.** The chosen default is local database only. The
   alternative also offers an admin API transport for remote management.
7. **Expiry default.** The chosen default is none. The alternative is a
   mandatory or default expiry for operator and admin tokens only.
8. **Basic auth.** Decide whether to accept `Authorization: Basic` carrying
   the token as the password. This depends on the outstanding detector
   capability checks in section 9. The default is not to accept it until a
   supported detector needs it.
