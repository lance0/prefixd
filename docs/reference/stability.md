# Compatibility and stability

prefixd is pre-1.0. Operator interfaces still need deliberate changes and
release notes. The `/v1/` HTTP namespace has its own
[versioning policy](api-versioning.md); it does not mean the daemon has shipped
version 1.0 or every speaker has equivalent capabilities.

## Interfaces to review

| Surface | Compatibility includes |
|---|---|
| Configuration | YAML keys, defaults, aliases, environment variables, validation, reload behavior and secret redaction. |
| HTTP and WebSocket | Routes, JSON fields/types/enum values, status codes, authentication, authorization, pagination and message meaning. |
| CLI | Commands, flags, exit status and JSON output. Human tables may change; automation should use JSON. |
| Metrics | Family names, types, units, label names and the meaning of label values. |
| Structured logs | Operational event meaning and structured fields used to correlate rules, operations, peers and failures. |
| Persisted state | Database migrations, pending obligations and supported upgrade/rollback procedures. |
| Speaker integration | Backend selection, supported rule/action shapes and what an acknowledgement or observation proves. |

For JSON logs, preserve the meaning of fields such as `mitigation_id`,
`nlri_hash`, `pop`, `operation` and `error` when changing an existing event.
There is no versioned event-ID registry today. Free-form error text and debug
messages are not a machine-readable error schema. A change in an operational
event's meaning or correlation fields still needs a release note; do not silently
repurpose a field or hide a failed operation behind a success message.

Local mutation acceptance, retained speaker intent, exported advertisements and
router enforcement are different observations. Preserve that distinction in API,
metrics, logs and UI text. See [speaker backends](speaker-backends.md).

## Change policy

- Preserve the existing HTTP-v1 compatibility and deprecation rules. Additive
  response fields require clients to tolerate unknown fields; adding an enum
  value also needs a documented interpretation for older clients.
- For other pre-1.0 surfaces, prefer compatible additions and aliases. Announce
  an intentional removal or default change in a minor release with an upgrade
  and rollback procedure. State when an alias will be removed rather than
  silently changing its meaning.
- Document safety or security corrections immediately. Explain rejected inputs
  and any operator action; an unsafe behavior is not a promise to preserve it.
- Review migrations against both existing data and repeated startup. Never
  discard pending cleanup or manufacture an acknowledgement during an upgrade.
- Public Rust implementation traits can evolve before 1.0. Describe required
  source migrations; retaining a type name alone does not establish compatibility.
- Scope performance, scale and interoperability claims to dated receipts naming
  the tested source, daemon/build identity, topology, workload and result. Keep
  failed runs. Unit tests and local intent do not prove router enforcement.

## Release notes

Add a descriptive [changelog fragment](../../changelog.d/README.md) whenever one
of these interfaces or its observable behavior changes. Include defaults,
compatibility impact and migration steps when relevant. Use public PR references;
do not publish private tracker IDs, operator hostnames, user paths or credentials.

CI validates fragments and conservatively checks changes to runtime code,
configuration, schema, dependencies and deployment files. It cannot infer whether
a code change alters behavior. A process-only or internal change may omit a
fragment with a specific `Changelog: not needed: <reason>` in its PR description;
that rationale is part of review. Documentation-only and test-only changes do
not require empty notes. An existing unrelated fragment does not cover a new PR.

Run `python3 scripts/assemble-changelog.py --check` before submitting a PR.
For committed changes, `python3 scripts/check-changelog.py --base origin/main`
checks note presence; CI additionally reads a no-change rationale from the PR
event. Neither command substitutes for the implementation's relevant checks.
