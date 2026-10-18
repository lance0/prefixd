# Cookbook

Choose a complete prefixd procedure for a task you run today.

Each recipe starts from the local stack in the [quickstart](../tutorials/quickstart.md),
uses the shipped configuration, and states the evidence behind it. A recipe
covers controller and speaker behaviour only: none of them proves that a router
installed or enforced a rule.

| Recipe | When this is you | Proven by |
|--------|------------------|-----------|
| [Manual mitigation and withdrawal](manual-mitigation.md) | You need to mitigate one target by hand, then withdraw it with a reason the audit log keeps | Both profiles in the [dated profile qualification](../reference/qualification/speaker-profiles-2026-10-18.md): exact local rules, withdrawal, original actor and reason, rule absence |
| [Dry-run rollout](dry-run-rollout.md) | You want to watch policy decisions on real signals before prefixd announces anything | The controller test suite runs in dry-run by default; a reconciliation unit test checks that dry-run sends no speaker call. The mode switch itself is not in a dated qualification. |

## Flows without a recipe yet

These paths work and have controller tests, but no dated end-to-end receipt
yet. Use their how-to guides until one exists:

- **FastNetMon notify script:** its vector mapping is tested with a stub `curl`,
  not a running FastNetMon. See [FastNetMon](../how-to/detectors/fastnetmon.md).
- **Generic webhook adapters:** covered by controller integration tests. See
  [generic webhooks](../how-to/detectors/generic-webhook.md).
- **Corroborating signals:** see [corroborating signals](../how-to/detectors/corroborating-signals.md).

## Conventions

- Addresses come from the documentation ranges (RFC 5737, RFC 3849) and the
  shipped [inventory](../../configs/inventory.yaml). Substitute your own.
- Commands run from the repository root against the `rustbgpd` profile. For the
  `gobgp` profile, replace the `prefixd-rustbgpd` service with `prefixd-gobgp`
  and use the GoBGP command shown in each recipe.
- The shipped config uses `credentials` authentication, so API calls carry a
  session cookie from `POST /v1/auth/login`. In `bearer` mode, send
  `Authorization: Bearer` instead; see [authentication](../how-to/deployment.md#authentication-setup).
- Response bodies are trimmed with `jq`. Install it, or drop the filter and
  read the full JSON.
