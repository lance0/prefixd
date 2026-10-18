# Change BGP speakers and roll back

Use a maintenance window to move between GoBGP and rustbgpd while keeping the
same POP. The procedure drains rules on the original speaker, stops the
controller, transfers its target binding and recreates eligible intent on the
new speaker. **There is a mitigation gap.** Arrange upstream protection for it.

Run one controller and use each physical speaker exclusively. Database target
bindings do not fence another process or tool. Keep the original speaker
available until its cleanup is verified. ExaBGP has no supported production
adapter; this procedure does not admit it or translate unsupported rules.

## 1. Prepare and pause mutations

Keep PostgreSQL, inventory, safelist and guardrails available. Back up the
database and configuration. Record controller/speaker versions, immutable image
digests, POP, old/new normalized target identities and current operator. Prepare
the destination's peers and policy using the [backend reference](../reference/speaker-backends.md).
Preserve the FlowSpec-only family configuration, import policy and export policy;
do not enable unicast or RTBH as part of this change.

Before draining, verify that the **deployed controller** implements the expiry
cap; a rustbgpd version alone does not establish this prefixd capability:

```bash
set -o pipefail
curl --fail --silent --show-error "$PREFIXD_API/openapi.json" |
  jq -e '.components.schemas.CreateMitigationRequest.properties.expires_at_cap | type == "object"'
```

Stop if the schema cannot be retrieved or the field is absent. Upgrade the
controller on its original binding first. Older binaries can silently ignore an
unknown `expires_at_cap` field and return success while extending the deadline.

Use an owner-only Unix socket or authenticated TLS for rustbgpd. GoBGP's RPC
listener must remain in its private management namespace. Test destination
connectivity and its actual peer sessions without starting a second controller.
Do not create rules on the destination yet.

Pause **all** detector inputs, webhooks, manual creation and TTL extensions, and
wait for in-flight requests to finish. Keep the original controller running for
cleanup. Expiry can continue; it does not extend a rule's lifetime. Rules can
remain on the speaker while the controller is stopped because application TTL
is not a speaker lease.

## 2. Save one complete snapshot

Use an administrative PostgreSQL connection. API timestamp pagination is not a
consistent cutover snapshot. Set `CUTOVER_POP`. Run this block once in Bash; any
failure aborts it. Do not continue on a failed command. An existing directory or
output file is rejected; resumption reuses the retained snapshot:

```bash
(
set -euo pipefail
set -o noclobber
umask 077
mkdir cutover
psql "$DATABASE_URL" -XqAt -v ON_ERROR_STOP=1 -v cutover_pop="$CUTOVER_POP" \
  > cutover/snapshot.json <<'SQL'
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
WITH binding AS (
    SELECT b.pop, t.* FROM speaker_pop_bindings b
    JOIN speaker_targets t USING (target_id) WHERE b.pop = :'cutover_pop'
), owned AS (
    SELECT * FROM mitigations WHERE pop = :'cutover_pop'
)
SELECT jsonb_build_object(
    'snapshot_at', transaction_timestamp(),
    'pop', :'cutover_pop',
    'binding', (SELECT to_jsonb(b) FROM binding b),
    'mitigations', COALESCE((SELECT jsonb_agg(to_jsonb(m)) FROM owned m), '[]'::jsonb),
    'withdrawals', COALESCE((SELECT jsonb_agg(to_jsonb(w)) FROM withdrawal_requests w
                           WHERE pop = :'cutover_pop'), '[]'::jsonb),
    'announcements', COALESCE((SELECT jsonb_agg(to_jsonb(a)) FROM flowspec_announcements a
                             WHERE pop = :'cutover_pop'), '[]'::jsonb),
    'audit', COALESCE((SELECT jsonb_agg(to_jsonb(a)) FROM audit_log a
                      WHERE (a.target_type = 'mitigation' AND a.target_id IN
                             (SELECT mitigation_id::text FROM owned))
                         OR (a.target_type = 'speaker_target' AND a.target_id IN
                             (SELECT target_id::text FROM binding))), '[]'::jsonb)
);
COMMIT;
SQL
jq -e '.binding != null and (.mitigations | type == "array")' cutover/snapshot.json
sha256sum cutover/snapshot.json > cutover/snapshot.sha256
)
```

Retain the raw snapshot, database backup and relevant external logs. The audit
selection contains available target/mitigation entries, not every detector or
external audit event. An original manual actor may be unavailable; record it as
unknown rather than substituting the migration operator.

Preflight every candidate before draining. Recreate only snapshot rows that were
Active/Escalated, remain unexpired and have no pending withdrawal for their ID
or canonical rule. Raw Pending
rows are not established admitted intent; preserve them for investigation and
resolve them before target transfer. Expired/Withdrawn/Rejected rows remain
history. Do not insert or reactivate rows directly in SQL.

The manual API supports this mapping:

| Persisted intent | Manual creation |
| --- | --- |
| IPv4 `/32` or IPv6 `/128` | Canonical host in `victim_ip` |
| Protocol absent / 6 / 17 / 1 | `any` / `tcp` / `udp` / `icmp` |
| Destination ports | Same set, within current guardrails |
| Discard | `action: discard` |
| Police | `action: police`, identical exact integer `rate_bps` |
| Original absolute expiry | `expires_at_cap` |

Protocol 58 is not representable by this manual API. Broader prefixes, other
protocols/actions and lossy policing rates block this workflow; do not silently
translate them. Check canonical uniqueness, destination conflicts, destination
speaker contents, current safelist/quotas and minimum remaining TTL. A rule that
expires or falls below minimum during maintenance must be skipped, not extended.

## 3. Journal, drain and verify the original speaker

Create a cutover UUID and an append-only journal in the private directory. Before
each request, record and flush the cutover ID, original mitigation ID, original
expiry and reason, source/destination target IDs, canonical rule/action, exact
request and current authenticated operator. Use a unique request reason marker
`speaker-cutover:<cutover_uuid>:<original_id>:drain` for withdrawal and
`speaker-cutover:<cutover_uuid>:<original_id>:create` for recreation; retain the
original reason separately. Withdrawal updates the old row's reason, so phase
markers must differ. Flush each journal append before sending its request and after
recording its response, for example with `sync -f cutover/journal.jsonl` on Linux.
Keep one writer and retain the directory across restarts.

Withdraw original active intent through the authenticated API with a maintenance
reason. Let durable pending withdrawals complete; check their `completed_at` and
original `target_id`. A failed request is not proof that the speaker did nothing.
Keep existing cleanup operations and IDs rather than creating new ones.

Compare exact owned rules/actions with the original speaker's local view, and
verify withdrawal on the actual receiving peer. Unknown local rules must remain
untouched. Stop if observation is incomplete, cleanup is pending or a received
rule remains unexplained. Peer health alone is not installation/withdrawal proof.

For the pinned rustbgpd releases, query **both** families. The synthetic peer
`0.0.0.0` returns retained local intent, including nonselected paths:

```bash
rbgp --addr "$RUST_ADDR" --json flowspec received 0.0.0.0 --family ipv4_flowspec
rbgp --addr "$RUST_ADDR" --json flowspec received 0.0.0.0 --family ipv6_flowspec
```

Add `--token-file "$TOKEN_FILE"` when using bearer authentication. Query an
actual peer address instead of `0.0.0.0` for its received routes. Compare structured
component details and raw action communities; human-readable rates can round.

For HTTPS, add `--tls-ca "$CA_FILE"`; native mTLS also requires
`--tls-cert "$CLIENT_CERT" --tls-key "$CLIENT_KEY"`. Use
`--tls-server-name "$TLS_NAME"` when the validated certificate name differs from
the endpoint host. Run owner-only Unix-socket inspection under the configured
UID and in the socket's namespace, for example inside the speaker container;
do not loosen socket-volume permissions to make host inspection work.

For GoBGP 4.10.0:

```bash
gobgp -u "$GO_HOST" -p "$GO_PORT" -j global rib -a ipv4-flowspec
gobgp -u "$GO_HOST" -p "$GO_PORT" -j global rib -a ipv6-flowspec
gobgp -u "$GO_HOST" -p "$GO_PORT" -j neighbor "$PEER_IP" adj-in -a ipv4-flowspec
gobgp -u "$GO_HOST" -p "$GO_PORT" -j neighbor "$PEER_IP" adj-in -a ipv6-flowspec
```

Local GoBGP paths have no peer address; inspect every path, including non-best
paths. Use the receiving daemon's view to verify actual receipt/withdrawal.

## 4. Stop, transfer and start

Stop the controller after successful drain. Use the
[drained target-transfer transaction](upgrading.md#drained-target-transfer) with
the unchanged POP, expected old target ID and exact normalized destination
backend/endpoint. It rejects active/Pending intent, pending cleanup, unresolved
announcement history and another POP's target. It does not verify remote
deletion: the preceding speaker/peer checks are required.

Keep the transfer audit and its result in the journal. If the transaction reply
is lost, inspect the binding and audit before retrying. Never rewrite immutable
target identities, old withdrawal targets or completed history.

Select the destination backend and matching configuration/profile, then start
one controller. Verify its selected backend, ownership binding, authentication,
health and actual sessions before recreation. Switching profiles also requires
the corresponding speaker/container namespace; do not leave the old controller
running. Detector inputs remain paused.

## 5. Recreate eligible intent without extending expiry

Recheck each candidate against the original snapshot, journal, current database
and destination speaker. Calculate an integer requested TTL no greater than its
remaining lifetime and configured maximum. Skip expired/below-minimum rows;
never round upward to pass the minimum. Supply the original precise timestamp
as `expires_at_cap`, so request/validation delays cannot restart its lifetime:

```json
{
  "reason": "speaker-cutover:<cutover_uuid>:<original_id>:create",
  "victim_ip": "2001:db8::10",
  "protocol": "udp",
  "dst_ports": [53],
  "action": "police",
  "rate_bps": 10000000,
  "ttl_seconds": 120,
  "expires_at_cap": "2026-10-18T01:00:00Z"
}
```

Send it to authenticated `POST /v1/mitigations`. The timestamp above illustrates
the shape; use the actual original expiry. Save every returned new ID and full
response. Both `201` and `202` describe committed desired intent; `202` with
`announcement_outcome: unconfirmed` requires investigation of exact local state
and may mean the deadline elapsed during persistence without an announcement.
Neither status proves peer receipt or router enforcement.

New rows have new mitigation/event IDs. Customer context is recomputed from
current inventory; manual creation does not restore original service/vector or
signal-group context. Keep those originals in the snapshot/journal, along with
the old-to-new ID mapping and skipped-row reasons.

After each accepted creation, compare persisted expiry (no later than original),
canonical action and complete local rule state, then actual receiving-peer state.
Preserve unknown rules. Complete the ID mapping and verification before resuming
inputs. Later detector events can extend expiry normally; the cap governs initial
recreation, not all future events.

## Resume and roll back

| Interruption | Resume rule |
| --- | --- |
| Before drain | Keep the source binding; repeat eligibility checks against retained snapshot. |
| During drain | Inspect original durable cleanup operations; finish them on the source before transfer. |
| Transfer reply lost | Inspect binding and transfer audit; do not infer commit from connection failure. |
| Recorded new ID exists | Resolve that ID first, including terminal status; compare its POP, rule/action and expiry with the journal. |
| Creation reply lost, no recorded ID | Inspect **all statuses** for the exact unique `:create` reason marker, excluding original snapshot IDs, and compare POP, canonical rule/action and expiry against the journal. |
| One matching created row | Record its ID; verify cleanup/local/peer state before proceeding. Never recreate pending cleanup. |
| No matching row after a lost reply | Stop for administrative history inspection. A later withdrawal can overwrite the reason, so absence of the marker does not prove that no creation committed. Do not automatically retry. |
| Multiple matches, conflict or unexplained remote rule | Stop and reconcile the evidence; a `409` alone is not proof of the same operation. |
| Original deadline elapsed | Skip recreation and finish cleanup, without renewing lifetime. |

Reason markers aid investigation; they are mutable fields, not server-side
idempotency keys. A fsynced returned-ID mapping survives later reason changes.
Without that mapping, unidentifiable acceptance remains a stop condition.

Rollback repeats this maintenance procedure in reverse, with a fresh consistent
snapshot of the **current** target and new operation journal. Drain current rules,
stop the controller, transfer the binding back and recreate only still-eligible
intent capped by its current/original deadline. Preserve both sets of history.
Restoring a database backup does not undo speaker RPCs and can resurrect withdrawn
intent; it is not a rollback mechanism for this procedure.

## Controller API pinning

The supported Rust controller contract requires rustbgpd **at least v0.76.0**.
Use an exact qualified version and immutable image digest from the
[released fixture inventory](../../tests/fixtures/rustbgpd/releases.json), not a
floating daemon tag. The CI matrix covers the listed releases' local controller
contract. A newer release or a promoted RPC inventory does not automatically
qualify a deployment, transport, family, router vendor or dataplane. Add a dated
receipt for the actual versions, topology and operations tested before widening
that claim.
