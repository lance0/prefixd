# ADR 020: Generic Webhook Adapter

## Status

Accepted

## Date

2026-04-18

## Context

ADR 019 established a pattern of dedicated signal-adapter endpoints per detector, with the first two being Alertmanager (`/v1/signals/alertmanager`) and FastNetMon (`/v1/signals/fastnetmon`). Each native adapter is 150-300 LOC of Rust: payload structs, label mapping, confidence heuristics, integration tests.

That pattern works well for systems prefixd will be tightly coupled to, but it doesn't scale to the long tail of detectors — internal abuse systems, commercial DDoS appliances (Radware, NETSCOUT, A10), cloud platforms (GCP Cloud Armor, AWS Shield events), and bespoke signal pipelines. Operators shouldn't have to fork prefixd to wire in a new detector that speaks JSON.

Key questions:

1. **How does an operator integrate a new detector without touching Rust?**
2. **What mapping language do we use?** JSONPath, JMESPath, dotted paths, custom DSL?
3. **How is authentication configured per adapter?** Bearer token alone is weak for webhooks; most mature systems expect HMAC.
4. **How do we keep configuration safe?** YAML secrets are dangerous; the API must not leak shared secrets.
5. **How does batching work?** Many detectors POST an array of alerts in a single request (like Alertmanager's native format).
6. **What happens to the existing Alertmanager/FastNetMon adapters?** Do we migrate them to the generic pattern, keep them separate, or both?

## Decision

### Configuration-driven adapters in `correlation.yaml`

Webhook adapters are declared in the existing `correlation.yaml`, alongside other correlation-engine configuration:

```yaml
webhook_adapters:
  - name: radware
    enabled: true
    auth:
      type: hmac
      secret_env: RADWARE_WEBHOOK_SECRET
      header: X-Signature-SHA256
      algorithm: sha256
    root_path: "$.alerts[*]"
    fields:
      victim_ip: "$.target.ip"
      vector: "$.alert_type"
      bps: "$.traffic.bps"
      confidence: "$.score"
    vector_map:
      UDP_FLOOD: udp_flood
    default_vector: unknown
    confidence_scale: 100
```

Each adapter becomes reachable at `POST /v1/signals/webhook/{name}`, where `name` is an operator-chosen segment matching `[a-z0-9-]{1,64}`. The handler compiles the JSONPath expressions at resolution time, verifies authentication, parses the body, and feeds each mapped event through the standard `handle_ban` / `handle_unban` pipeline — identical to every other signal adapter.

### JSONPath for field mapping (RFC 9535)

We chose **JSONPath** over alternatives:

| Language | Pros | Cons |
|---|---|---|
| **JSONPath** (chosen) | RFC 9535 standardized, widely recognized (Kubernetes, Splunk, Prometheus), mature Rust crate (`serde_json_path`), handles arrays/filters | Non-trivial syntax (`$.a[*].b`) |
| Dotted paths (e.g. `a.b.c`) | Minimal dependency, simple | No array iteration, no filters, operators will outgrow it quickly |
| JMESPath | Also standardized, good Rust support | Less familiar outside AWS ecosystem |
| Custom DSL | Full control | Yet another syntax for operators to learn; no ecosystem |

JSONPath strikes the right balance: operators already know it from Kubernetes, it handles the common "array of alerts in one webhook" shape via `root_path: "$.alerts[*]"`, and `serde_json_path` is pure Rust with no C dependencies.

### Three authentication modes per adapter

- **`hmac`** (recommended) — HMAC-SHA256 over the raw request body. Secret loaded from an environment variable named in `auth.secret_env`; the secret is never embedded in YAML, never returned from the API, and never logged. Comparison is constant-time via the `subtle` crate. The hex digest may be prefixed with `sha256=` (GitHub-style).
- **`bearer`** — Reuses the global session / bearer backend. Convenient when the detector can already authenticate as an operator.
- **`none`** — No authentication. Intended for lab or trusted-network use; logged with a warning at startup.

Per-adapter auth was chosen over a single global scheme because mature webhook producers (GitHub, Stripe, Radware, etc.) overwhelmingly use HMAC, but internal detectors often only know how to send a bearer token.

### Secret handling

Secrets are **only** loaded from environment variables referenced by `auth.secret_env`. The YAML file carries the env-var name, not the secret itself. The config API (`GET /v1/config/correlation`) returns the env-var name; the secret value is neither readable via the API nor written to any audit log.

### Endpoint shape: `/v1/signals/webhook/{name}`

We chose a name-keyed endpoint rather than a single `/v1/signals/webhook` with an adapter-identifier in the payload or a query string. Reasons:

- **Discoverability** — Each adapter has a stable URL that operators can configure in detector UIs.
- **Observability** — Metrics and access logs naturally group by adapter path.
- **Validation** — Name is validated against `[a-z0-9-]{1,64}` on the hot path, preventing any path-traversal or injection. Unknown / disabled names return 404.

### No migration of existing adapters

Alertmanager and FastNetMon adapters keep their dedicated endpoints and Rust code. Their payloads have source-specific semantics (Alertmanager's `status: resolved` → unban, FastNetMon's `action: ban/partial_block/alert` → confidence mapping) that would be awkward to express purely through JSONPath. The generic adapter is for *new* integrations; the native adapters remain the reference for deeply-integrated detectors.

### Batching via `root_path`

When `root_path` is set, the JSONPath is evaluated against the payload and each matching node becomes one `AttackEventInput`. This mirrors how Alertmanager ships N alerts per webhook. Partial failures are reported per-event in the response (same shape as the Alertmanager handler); the overall HTTP status is 200 for well-formed payloads so the sender doesn't retry the whole batch.

## Consequences

### Positive

- **New integrations without a Rust change** — Operators add a `webhook_adapters` entry, reload config, and start sending events. No PR, no rebuild.
- **Covers the long tail** — Commercial appliances, internal tools, and cloud alerting all share the same mental model.
- **Reuses the existing pipeline** — Guardrails, correlation, policy, BGP, audit: all identical to other adapters.
- **Safe by default** — Name validation prevents URL abuse; HMAC is the documented default; constant-time compare; secrets never leave the environment.
- **Tested** — 13 unit tests (mapping, HMAC) + 11 integration tests (happy path, auth, batching, failures) on the first cut.

### Negative

- **Less type safety than native adapters** — A malformed payload shape produces a 400 or a per-event error result instead of a compile-time check. Mitigated by tests and by validating JSONPath expressions at config load.
- **Operators must understand JSONPath** — Documented with examples in `docs/configuration.md`; most operators already know the basics from Kubernetes.
- **No transform functions yet** — Unit conversion, regex extraction, and computed fields are not supported. Deferred to a follow-up; most detectors already emit numeric values and vector strings that the mapping can pass through directly.

### Neutral

- **Adapter weight registration** — For correlation weighting, operators add the adapter's name to the existing `sources:` map. Unlisted adapters fall back to `default_weight`.
- **HMAC algorithm fixed at SHA-256** — SHA-512 / Blake3 can be added later without breaking the config schema (extend the `algorithm` enum).
- **Adapters are hot-reloadable** — Changes to `webhook_adapters` take effect on `POST /v1/config/reload`, same as sources and playbooks.
