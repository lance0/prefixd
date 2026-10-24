# Extend a FlowSpec mitigation

Use **Extend lifetime** on a mitigation's detail page when the attack still
requires its existing filter. Operator or Admin access is required. The rule can
have been created by a detector or an operator; this action always records the
operator's identity and explanation.

1. Confirm the complete match and action, current expiry and enforcement evidence
   on the detail page. An extension retains every selector and rate.
2. Choose the requested **remaining lifetime in seconds** and inspect the new
   expiry estimate. For example, requesting 600 seconds at 12:00 produces about
   12:10, even if the old expiry was 12:05.
3. Enter why the rule needs more time and confirm. The database clock determines
   the saved horizon. If the current expiry is already later, the response is an
   explicit no-op with no revision or extension audit entry.
4. Inspect the refreshed expiry and audit. A saved extension records old and new
   expiry, requested TTL, reason and authenticated actor. The original creation
   reason and event history remain intact.

Only unexpired active/escalated discard or police intent admitted in enforced
mode is eligible, on the current POP and speaker binding. The controller must
still be active and enforced. Pending rules, blackholes, expired/withdrawn rules,
unknown origin and simulations are refused. A withdrawal already in progress
wins over extension.

The current inventory must identify the entire destination as belonging to the
saved customer, and any saved service must still match. Unattributed legacy
rules cannot be extended. The controller rechecks safelists and current TTL,
prefix, port and match opt-ins, including source-prefix matching. Tightened
policy can refuse longer exposure even when reconciliation retains a previously
admitted rule. Correct ownership or policy deliberately before trying again;
recreating a broader rule is not part of this workflow.

A precise validation or safety refusal describes the correction needed. If the
request loses its connection or returns an unavailable outcome, refresh the
mitigation and audit before retrying: the database may have committed the
extension even though the reply was lost.

This changes saved desired lifetime only. It creates no new quota slot and sends
no add, delete or lease renewal to the speaker. Local speaker acceptance, retained
intent, peer export and router enforcement remain separate evidence. TTL cleanup
requires a running controller; a stopped controller can leave routes at the
speaker. The optional initial `expires_at_cap` is a creation-only cap, not a
permanent extension ceiling. See the [API contract](../reference/api.md#extend-flowspec-lifetime)
and [upgrade guidance](upgrading.md).

To bound the lifetime of each ordinary FlowSpec row, set the optional nonzero
`guardrails.max_lifetime_seconds`. New admissions, detector refreshes and operator
extensions cannot save an expiry later than the row's original `created_at` plus
that limit. Requests exceeding it are refused, not truncated. Existing expiry is
never shortened, and an already sufficient horizon remains a no-op. With the
setting omitted, repeated extensions retain their existing behavior. This is a
per-rule limit, not a ban on new mitigations for the same destination after expiry;
blackholes keep their separate policy. Changing the setting requires a controller
restart. It does not add a speaker-enforced deadline.

## Operational references

[Wanguard's response policy](https://docs.andrisoft.com/wanguard/latest/Configuration__Network__Policy__Response.html)
supports changing an anomaly's expiration time and driving BGP FlowSpec response.
[FastNetMon's configuration reference](https://fastnetmon.com/docs-fnm-advanced/fastnetmon-advanced-configuration-options/)
documents positive FlowSpec ban duration and expiry-driven withdrawal. These
provide operator context for explicit lifetime control. The prefixd contract
above uses its own controller/database safety boundary; it makes no claim that
those products share the same semantics or audit guarantees.
