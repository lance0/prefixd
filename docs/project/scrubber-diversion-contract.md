# Redirect-to-IP speaker contract and qualification plan

**Status:** Proposed prerequisite for [ADR 030](../adr/030-scrubber-diversion.md).
**Checked:** 2026-10-23 against prefixd `010c86b` and released rustbgpd `v0.79.0`
(`60cb5c9910eb1380661dd4c80d55563b2d80099a`).

[Issue #305](https://github.com/lance0/prefixd/issues/305) asks for diversion to a
scrubber and source-prefix selection. Source-prefix matching shipped in
[PR #307](https://github.com/lance0/prefixd/pull/307). Redirect-to-IP still needs
the contract and qualification below. This plan enables no action and leaves
ADR 030 Proposed. Its first runtime slice keeps host destinations, manual
admission, configured targets and the readiness/withdrawal latch from that ADR.

## Released boundary and remaining dependencies

The [latest published rustbgpd release](https://github.com/lance0/rustbgpd/releases/tag/v0.79.0)
was still `v0.79.0` on the check date. Inspect released code before changing this
table; unreleased upstream changes cannot satisfy a release gate.

| Boundary | Evidence at the pinned revisions | Required before enforced diversion |
| --- | --- | --- |
| Match selection | prefixd supports source-prefix selection; existing manual destinations are hosts | Preserve canonical match identity and source guardrails; broader destination support needs its own admission design |
| Target action | rustbgpd has typed VRF redirect and raw eight-byte communities; prefixd's adapters require traffic-rate | Agree lossless target-IP add and read-back; preserve target, family and copy flag without substituting a VRF or legacy next hop |
| IPv6 target | `AddFlowSpecRequest.extended_communities` holds `uint64` values | Carry the twenty-byte IPv6-specific community through add, retained read-back and export |
| Ownership | Released leased add and delete check the exact owner; owner/key caps are 64 live owners and 16,384 keys per owner | Allocate disjoint owners for ordinary mitigations and each profile; refuse new profile activation/admission at capacity |
| Delayed mutation | A leased add joins or creates a lease in the RIB turn after the API queues it | Prevent an old queued add or renewal from extending or recreating diversion after its server-enforced authorization expires |
| Controller lifecycle | prefixd uses one `LeaseKeeper` for ordinary leased FlowSpec and blackholes | Give each profile its own renewal eligibility, generation and persistent ownership snapshot |
| Router installation | Existing controller receipts establish local lifecycle and peer receipt for supported actions | Qualify the target encoding, installed forwarding path, clean return and removal on the exact router/driver release |

The released
[protobuf](https://github.com/lance0/rustbgpd/blob/v0.79.0/proto/rustbgpd.proto)
defines the action, ownership and cap semantics. Its
[injection handler](https://github.com/lance0/rustbgpd/blob/v0.79.0/crates/api/src/injection_service.rs)
accepts raw IPv4 action bytes and queues leased adds. In prefixd, inspect
[`encode` and `decode`](../../src/bgp/rustbgpd.rs),
[`LeaseKeeper`](../../src/domain/lease.rs) and
[`startup`](../../src/main.rs) when implementing the corresponding changes.
Raw IPv4 transport removes one encoding obstacle; it leaves the other gates in
this table open. An IPv4-only product decision needs an ADR amendment and the
same ownership, failure and forwarding controls.

## Contract to agree upstream

The following requirements describe prefixd's dependency. They do not assign
protobuf field numbers or claim that rustbgpd implements a proposed RPC.

### Action and rollback refusal

1. Represent redirect-to-IP separately from VRF redirect and MP_REACH next-hop
   selection. Preserve an address family, target address and copy flag. The
   speaker may support copying; prefixd's first release permits one same-family
   target and `copy=false`.
2. Emit one canonical action community. Reject duplicate target actions,
   conflicting typed/raw representations and mixtures with traffic-rate,
   marking, VRF or legacy redirect at prefixd admission. Keep opaque communities
   distinguishable from typed actions in speaker observation.
3. Return the full retained action bytes alongside typed interpretation, for
   both target families. A prefixd decoder must reject an inconsistent or
   unrepresentable inventory as an observation failure. It must preserve the
   last valid evidence and block repair; it must not discard the unknown action
   and reconcile against an empty result.
4. Use mutation entry points whose contract requires the bounded authorization
   and admission fencing below, including deletion. An older daemon must return
   `UNIMPLEMENTED` without changing state.
   Adding an optional protobuf field to an existing add or delete method is insufficient:
   old servers can ignore unknown fields. A startup capability read supplements
   this guarantee; it cannot close a rollback race between the read and mutation.
5. Preserve the exact `(AFI/SAFI, canonical components)` key and recorded owner
   through add, read-back and idempotent delete. Carry an immutable admission
   revision alongside that key and owner: retries keep the same revision, and a
   new admission uses a fresh revision even for the same match and owner. This
   revision is separate from the shared owner lease generation and is not part
   of the BGP NLRI. A target or profile change does not create a separate NLRI
   key. Changing an active action requires confirmed withdrawal through the
   [pending-mutation barrier](#finalize-withdrawal-behind-a-pending-mutation-barrier)
   and a fresh admission under ADR 030's victim-level exclusion.

### Canonical action vectors

The [redirect-to-IP draft, revision 16](https://datatracker.ietf.org/doc/html/draft-ietf-idr-flowspec-redirect-ip-16#section-2)
specifies these layouts. IPv4 uses an eight-byte community; IPv6 uses twenty
bytes. `C=0` diverts; `C=1` copies. Originators clear the other fifteen local
administrator bits; receivers ignore those reserved bits. prefixd's stricter
originating and owned-inventory policy can reject noncanonical bytes without
changing the router's protocol receive requirements.

| Target | Divert (`C=0`), hexadecimal octets | Copy control (`C=1`) |
| --- | --- | --- |
| `192.0.2.10` | `01 0c c0 00 02 0a 00 00` | Change the final octet to `01` |
| `2001:db8::10` | `00 0c 20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 10 00 00` | Change the final octet to `01` |

These documentation addresses are codec fixtures, not deployment targets.
Test the whole BGP path attribute as well: carry IPv6-specific communities in
the [RFC 5701 attribute, type 25](https://www.rfc-editor.org/rfc/rfc5701.html#section-3),
with twenty bytes per community, rather than a truncated `uint64` value.
Round-trip both vectors through injection, retained read-back and a receiving
peer. Distinguish the target action from `0x800c` traffic-rate-packets,
`0x000d` IPv6 VRF redirect and legacy `0x0800` next-hop redirect. The
[IANA registry](https://www.iana.org/assignments/bgp-extended-communities)
lists these mechanisms separately.

## Bound queued adds and renewals at the server

The existing `lease_seconds` begins at RIB application time. Consider a request
that enters the queue, times out at the client, and executes after the
controller stops. It can start a fresh lease then. A second retry can execute
later still. Request cancellation and a gRPC timeout do not prove the absence
of either mutation. Bounding only time spent in the RIB queue also leaves time
before server receipt unresolved.

One concrete option for upstream review is an expiring **mutation window**:

1. The controller obtains an opaque, server-issued window for an owner. Issuing
   it creates no route and does not renew existing routes. The server binds it
   to its process incarnation, owner and a fixed monotonic expiry, with a
   configured maximum lifetime `H`. A join/renew window names the expected live
   generation. An initial-add window may start at most one generation; retries
   bind to that generation and cannot resurrect it after expiry.
2. A new leased-add/renew contract requires that window. At the mutation's
   commit point, the speaker rejects an expired or wrong-owner/process window
   without changing the lease table, ownership index or RIB. Queued work carries
   that original expiry; dispatch, queue retry and response loss cannot reset it.
3. An accepted mutation cannot extend the owner's deadline beyond the window's
   expiry, including an unchanged add. Expired work cannot create a generation.
   A fresh window alone cannot revive a dead generation; recovery still requires
   an authorized add after a complete inventory and fresh profile readiness.
4. The speaker must prevent legacy add/renew paths from bypassing the window
   limit and legacy deletes from bypassing admission fencing for an owner using
   this contract. Merely changing prefixd's call site
   leaves the server invariant incomplete. Preserve this exclusion across
   restart, for example through a configured owner namespace, while ordinary
   callers keep their existing contract under separate owners.
5. A profile with a withdrawal latch stops obtaining windows, adding and
   renewing. Retries retain the original action/owner/window. A retry after
   window expiry requires a new readiness and durable-intent decision; an
   unknown outcome alone never authorizes one.

If the controller stops at `t_stop`, every window it received and used before
that stop expires no later than `t_stop + H`. Let `W_max` be the maximum expiry
of those windows. A delayed window-issuance request cannot
extend existing state by itself, and a dead controller cannot use its response
to send a new mutation. Thus even work delayed before server receipt cannot
renew or recreate diversion beyond `W_max`. This argument
depends on the commit-time checks and legacy-path exclusion above; a client
deadline alone supplies neither. Upstream may choose a smaller equivalent
contract, provided it proves the same invariant across retries and rollback.

The window bounds lease authorization, not actual router removal. Record:

```text
maximum expiry of all windows authorizing sent mutations (W_max)
  + measured/qualified lease-expiry application lag
  = local retained-intent removal bound under the stated failure model

local removal
  + separately qualified export, convergence and router cleanup lag
  = forwarding-removal bound for the tested topology
```

An indefinitely stalled RIB or router has no finite application/removal bound.
If the receipt cannot bound either lag under its failure model, report that
layer as unbounded or unknown. A route with zero lease time remaining still
needs confirmed local absence and separate router evidence.

### Finalize withdrawal behind a pending-mutation barrier

A successful delete and an empty read do not finalize withdrawal while an
earlier add can still commit. A delayed request can recreate that exact key
using a valid window, including when another rule keeps the profile's owner
generation live. Bounded eventual expiry does not make the earlier absence
check final.

Persist withdrawal intent and stop adds for the selected key before draining
it. Durably record each window authorizing a sent add before dispatch, including
requests with unknown outcomes. Keep the original operation, rule, owner and
victim exclusion pending until every such add is unable to commit. Establish
that barrier either by acknowledged server-side invalidation checked at commit,
or by proving all windows that could authorize those adds have expired on the
server. Invalidating a key's outstanding add authorization must not remove a
legitimate sibling rule or kill its live owner generation. Client cancellation,
an RPC deadline and an initial absence read provide no barrier.

After that barrier, perform a final idempotent delete under the recorded owner
and admission revision, then obtain a complete local inventory confirming
absence. At commit, deletion must compare that revision with the stored rule:
an old delete cannot remove a newer admission under the same key and owner.
An absent rule remains an idempotent result for its original withdrawal.
Every retry retains the original withdrawal intent and admission revision.

The released `DeleteFlowSpecRequest` carries only match and owner, so its delete
contract does not provide this fence. A delete delayed before handler receipt
can arrive after a retry reports success, the rule appears absent and a new
admission reuses the key. Without revision fencing, that delayed delete can
remove the new rule. A live same-owner sibling prevents relying on owner lease
generation turnover. An upstream alternative must prove every outstanding
delete is server-invalidated or otherwise unable to commit before key reuse;
client timeout, cancellation and a successful retry are insufficient proof.

Only after the add barrier, final deletion/absence and delete fencing or drain
may prefixd finalize local withdrawal, release victim exclusion or permit a
target/profile change or operator re-arm. A failed read, uncertain authorization
or foreign owner keeps the operation pending; recovery must re-establish these
conditions from durable state. Router removal remains a separate evidence
layer. Apply this ordering to explicit withdrawal, TTL expiry, readiness loss,
configuration drain and rollback preparation.

## Required qualification cases

Implement the speaker cases upstream, release that contract, then pin it in
prefixd's owned fixtures with the controller cases below. Test each supported
target family. Retain failed runs, exact requests/responses, daemon revisions,
image digests and timestamps. These outcomes are acceptance criteria, not
results recorded here.

| Case | Required evidence |
| --- | --- |
| Canonical add/read/peer receipt | Exact vectors above, typed/raw agreement, full canonical source/destination match, owner and nonzero live generation |
| Unsupported server/family | Old daemon or unsupported family refuses the mutation; complete inventory proves no new key, lease extension or unleased fallback |
| Invalid action | Copy, reserved-bit injection, cross-family target, duplicate/conflicting actions and malformed IPv6 length fail prefixd's supported contract before mutation |
| Exact deletion | Delete using the recorded owner and admission revision removes only that admitted match; repeated delete reports absent; sibling sources/ports remain; foreign, unowned or newer-admission refusal changes no state |
| Pending-add withdrawal | Keep another rule under the same owner live. Delay an add before handler receipt, delete its key and observe absence, then deliver the still-authorized add. The negative control recreates the key before its window expires. Withdrawal stays pending and victim exclusion/re-arm stay blocked until invalidation or expiry prevents every outstanding add from committing, followed by a final owner-checked delete and complete absence check. Replay the old add again: it cannot recreate the key; the sibling remains live |
| Delayed delete and key reuse | Keep a same-owner sibling and lease generation live. Hold delete D1 before handler receipt, complete retry D2 and confirm absence, then admit the same key under a fresh admission revision. Deliver D1: it cannot remove the new rule or affect the sibling. The old owner-only delete contract is the negative control and removes the replacement. If qualifying a drain alternative, key reuse stays blocked until every outstanding delete is provably unable to commit |
| Queue after timeout | Stall the RIB, enqueue add, lose the client response, stop the controller, expire the window, then resume; the old add cannot start or extend a lease |
| Delayed retry and renewal | Queue duplicate adds and a renewal through window expiry; resume in different orders; none extends or recreates state past the original window |
| Delay before handler receipt | Hold an already formed request outside the API until its window expires; the server refuses it even though its handler just started |
| Generation/restart | Old-window and old-generation mutations fail after lease expiry or daemon restart; an explicit new admission after inventory/readiness can create a fresh generation |
| Independent profiles | Keep ordinary FlowSpec/blackhole and profile B renewing while profile A latches; A expires and drains, B remains live, and each lease/read shows its own owner |
| Storage or leadership loss | Lose the durable-intent read or fence while profile A has an in-flight add; A stops window acquisition and renewal, latches/drains on recovery and does not replay without re-arm |
| Observation failure | Unsupported action, inconsistent bytes, partial/failed inventory and expired rows remain distinguishable from confirmed absence; no repair or foreign deletion follows |
| Cap exhaustion | Owner/key exhaustion refuses admission with unchanged existing routes; profile removal cannot recycle an owner while live or pending intent remains |

For the stalled-queue cases, include a negative control against the old leased
add contract: release a queued add after its client timeout and record that it
can start a later lease. Keep that control in an isolated fixture. No live
operator route or existing lab belongs in this experiment.

## Qualify forwarding after the contract passes

The [FRR 10.4 guide](https://docs.frrouting.org/en/stable-10.4/bgp.html#flowspec)
documents installation limitations, including the missing Netfilter driver.
Before building the canary topology, identify a released installation path
that supports the selected encoding and match. If the chosen FRR build only
receives a rule, retain a control-plane-only result and select or implement a
separate qualified installation path. Do not add an unrequested traffic-rate
action to accommodate a router's installation behavior.

Use the topology, traffic and failure controls in
[ADR 030's qualification plan](../adr/030-scrubber-diversion.md#qualification-and-slices).
For each case, retain separate observations of local intent removal, exported
withdrawal, receiver RIB, installed PBR/FIB state and dirty/clean traffic. Record
the last successful mutation and window expiry when measuring controller-stop
behavior. Include the still-renewing profile control from the table above.

Only after these dependencies pass should a runtime PR add persisted profiles
and action snapshots, readiness/re-arm, manual operator workflow and metrics.
Link each PR and its receipt to ADR 030's slices. Keep redirect disabled until
the required backend/family/profile gates pass; source-prefix selection alone
does not complete issue #305.
