# Speaker backends

prefixd owns mitigation policy, guardrails, and desired state. The selected BGP
daemon owns peer sessions and protocol distribution. rustbgpd is the preferred
integration target and the standard build/profile choice; GoBGP remains an
explicit choice in the same binary.

## Current boundary

`FlowSpecAnnouncer` remains the selected `Arc<dyn FlowSpecAnnouncer>` facade.
Its required `FlowSpecWriter` contract provides announce/upsert and idempotent
withdraw: repeating a request after an ambiguous response must be safe.
`reader()` optionally exposes `FlowSpecReader`; `peer_observer()` optionally
exposes `PeerObserver`. Availability is derived from these accessors. All three
current adapters provide both observers.

Without a reader, reconciliation still loads the strict complete desired
inventory and updates status gauges, but performs no announcement repairs.
Independent TTL and pending-withdrawal cleanup continue. A supported reader
failure fails the pass and increments the run error counter; it never becomes
an empty inventory. Unsupported peer observation skips peer metric updates;
a failed observation also retains the last successful metric values.

`blackhole()` optionally exposes `BlackholeSpeaker` for unicast RTBH host routes
([ADR 027](../adr/027-blackhole-mitigations.md)): upsert, idempotent delete and
complete read-back of retained local intent for both families. Only rustbgpd
provides it. It injects with unleased `AddPath` (ORIGIN IGP, empty AS_PATH,
`path_id` 0, BLACKHOLE `65535:666` plus the route's communities), or with
`AddLeasedPath` for a route recorded under an injection owner. It never sends
one after the other fails. Each add logs rustbgpd's outcome (`created`,
`replaced`, `unchanged`, or `unknown` when the daemon reports none) and
records it in an `announce` audit entry unless it is `unchanged`. It deletes with `DeletePath` passing the
recorded owner, `allow_missing` and never `override_owner`: `DELETED` and
`NOT_PRESENT` are success, while `NOT_FOUND`, an unreported outcome and
`FAILED_PRECONDITION` (another owner, or none, holds the key) are errors, and
reads `ListReceivedRoutes(neighbor 0.0.0.0)` for each unicast family to the
last page. Each route carries its `injection_owner`, so a desired route
matches only a row held by its recorded owner. A leased row with
`lease_remaining_ms` 0 is reported as expired, not retained, and a row whose
owner, generation and remaining time are not all set or all unset fails the
read.
The read returns prefixd-shaped blackholes separately from unrecognized local
routes. An unrecognized route is well formed but not prefixd-shaped, for
example another tool's injection, a nonzero `path_id`, a missing BLACKHOLE or
extra path attributes. It carries its prefix and a reason, so callers can report
it without touching it. `ABORTED` mid-walk, a changed page version, any other
error or a malformed row fails the whole read. A malformed row has a non-local
peer, an unparseable prefix, next hop or large community, host bits or a
family mismatch. GoBGP returns `None`, which is unsupported rather than empty.
The controller uses it for the
[blackhole lifecycle](#blackhole-lifecycle-and-reconciliation).

`match_support()` reports which [ADR 028](../adr/028-amplification-matches.md)
match components the adapter encodes: UDP source ports (type 6), a non-first
fragment (type 12, bit `0x02` with the match bit) and one packet-length range
(type 10). The default is none. rustbgpd, GoBGP and the mock report all three
in both families. Before any speaker RPC, and before persistence in dry-run
and enforced modes, the controller refuses a rule with a component the
selected speaker does not encode. It never drops the component, because that
would widen the rule. Both adapters emit components in ascending type order and
decode only the forms they emit: any other operator, term or bit fails the
whole read. No API, playbook or detector creates these components yet.

Health detail adds `speaker.backend` and availability booleans under
`speaker.capabilities`: `rule_reader`, `peer_observer`, `daemon_health`,
`blackhole`, `blackhole_lease`, `blackhole_export` and the `flowspec_match`
object (`source_ports`, `fragment`, `packet_length`). `blackhole_export` is
true when the adapter reads per-peer [export evidence](#export-evidence),
which only rustbgpd does. `blackhole_lease` is true only
after the rustbgpd adapter's `ListInjectionLeases` probe succeeded, which
prefixd asks only with `blackhole.leased`; an `UNIMPLEMENTED` lease RPC from a
rolled-back daemon clears it. It is false for GoBGP. The legacy `gobgp`
component reports `unsupported` without an error when peer observation is absent,
`error` when it fails, and `connected` when it succeeds (even with zero peers).
`bgp_sessions` remains the same peer-name/state map. Missing optional observation
alone does not make overall health degraded. Health does not probe the RIB.
Rust's authenticated `GetHealth` supplies `speaker.daemon` version, process
uptime, readiness and successful observation time. Missing version remains null;
zero uptime is valid. Unsupported GoBGP process metadata and failed probes have
no invented values. The dashboard labels controller metadata separately and
records successful browser receipt on a monotonic clock separately from server observation time and
marks cached health older than three five-second poll intervals stale for every
backend, hiding cached healthy peer badges. Server/browser clock skew does not
determine freshness. Fetch errors hide cached observations. CLI status
also labels daemon metadata explicitly. Uptime is an observation, not a unique
boot identifier or a restart/replay trigger.

These fields describe API availability and peer observation, not announcement,
export, or enforcement confirmation. Export is reported separately, for
blackholes only, under `speaker.blackhole_exports`.

`prefixdctl peers` fails explicitly on unsupported or failed peer observation;
successful JSON remains the peer map. Status and dashboard clients tolerate older
health responses without `speaker` metadata. The dashboard distinguishes
unsupported observation, observation errors, and a successful empty peer list.

| Backend | Runtime selection | Read-back / peers | Status |
|---------|-------------------|-------------------|--------|
| rustbgpd | `backend: rustbgpd` (default without `gobgp_grpc`) | Retained local intent / neighbor states | Primary profile; released controller qualification below |
| GoBGP | `backend: gobgp` | Accepted local RIB / neighbor states | Selectable profile |
| Mock | `mock` | In-memory / synthetic | Automated testing only |
| Generic HTTP shim | Planned | Capability-dependent | Requires durable announcement ledger |
| ExaBGP or another daemon | Planned adapter or shim | Must be verified | No support or interoperability claim yet |

FRR, BIRD, and OpenBGPD are not selectable backends today. A router accepting a
FlowSpec route is distinct from a daemon exposing the origination/control API
prefixd needs. Each proposed adapter needs that evidence before implementation.

## Persistent target ownership

Before constructing a speaker client, startup registers or validates one
credential-free target identity for the configured POP. Each target may belong to
only one POP in that database. Lifecycle entrypoints require this verified binding;
new withdrawal requests retain its immutable target UUID, and retry execution
checks both the caller and the freshly loaded pending row before any speaker RPC.
Only explicitly selected mock fixtures can run without a binding.

Existing speaker history needs a one-time, original-target adoption. See the
[upgrade procedure](../how-to/upgrading.md#speaker-ownership-upgrade) before
restarting an existing deployment. Reload does not change the running POP, speaker
configuration or controller mode. Credential rotation preserves identity; target
changes need an explicit drained transfer. These bindings assume one controller
per POP and exclusive physical-target use, not process leases or DNS-alias fencing.
HTTP(S) addresses may have only a root path: gRPC discards endpoint path prefixes,
so they cannot distinguish targets and are rejected before registration.

External repository implementations can read the normalized identity through
`SpeakerTarget::{backend, endpoint, namespace}` and issue a binding with the
public `VerifiedSpeakerBinding::new` constructor; its fields remain private.
Repositories are trusted issuers. They must serialize ownership registration,
persist or validate the exclusive POP/target assignment, finish any legacy
adoption atomically, and commit before constructing the binding. The constructor
performs no database checks. The result is startup consistency evidence, not an
authorization token or an interprocess lease. Keep endpoint coordinates out of
API responses and diagnostics.

`RepositoryTrait::register_speaker_target` defaults to an explicit unsupported
error so existing repository implementations remain source-compatible. They must
implement this contract before real-speaker startup can succeed; the default
never issues a binding or silently disables ownership checks.

## Traffic-rate actions

Both writers accept one action: discard without a rate, or police with a positive
integer bit rate that round-trips exactly through the `f32` bytes/second wire
representation. Fractional bytes are preserved, so 1–7 bits/second remain police
actions. Invalid actions are rejected before manual or detector intent is saved
or extended; startup, reload and playbook edits apply the same rate policy.

Withdrawals use the exact local match and do not depend on its saved action.
This allows cleanup of historical zero, missing or imprecise policing rates.
It does not change the exclusive speaker ownership requirement.

## GoBGP read-back

GoBGP inventory reads both IPv4 and IPv6 FlowSpec GLOBAL tables, including
nonselected local paths. In GoBGP v4.10.0, an empty `neighbor_ip` identifies
GoBGP-local provenance; received paths are excluded before decoding. UUIDs are
not populated by ListPath and do not identify ownership. Local paths from other
controllers are not distinguished from prefixd's paths; unknown rules are never
deleted by reconciliation. These provenance fields follow the pinned
[GoBGP v4.10.0 serializer](https://github.com/osrg/gobgp/blob/da824d99912e02124b53741245ee4186c381adcc/pkg/server/grpc_server.go#L214).

This is the accepted local RIB, not retained pre-policy injection intent. Global
import policy can reject an injected route, so successful AddPath alone does not
prove it appears in this inventory; see the pinned
[AddPath policy processing](https://github.com/osrg/gobgp/blob/da824d99912e02124b53741245ee4186c381adcc/pkg/server/server.go#L1323).

Both family streams must finish successfully, including trailers. Any family
failure or malformed/unsupported local row fails the entire observation; no
partial inventory is returned. The complete dual-family read and each peer read
have a 30-second deadline, including response bodies. Destination prefixes,
optional protocol equality, destination-port equality lists, and one traffic-rate
action are supported. Byte rates convert to bits/sec before exact integer/range
validation; zero means discard. Missing or ambiguous actions and extra match or
action semantics are errors. Unsupported unrelated local rules can therefore
block reconciliation observation and require operator attention.

## rustbgpd configuration

Normal `cargo build` includes rustbgpd. Local Compose uses owner-authenticated UDS:

```yaml
bgp:
  backend: rustbgpd
  rustbgpd:
    endpoint: "unix:///run/rustbgpd/grpc.sock"
  local_asn: 65010
  router_id: "10.10.0.10"
```

Both processes must run as the same UID. The immediate directory must be 0700
and the socket 0600, owned by that UID, without symlink traversal. The client
checks filesystem ownership and the server's Unix peer identity on connection
and reconnect. This path authenticates rustbgpd's implicit local operator.
Do not share the private volume with unrelated containers. Every ancestor must
be owned by root or the controller UID and prevent untrusted directory
replacement; writable ancestors require the sticky bit. Root and the controller
UID are trusted to maintain these paths. A listener declaring `token_file` also
requires `bearer_token_env` in prefixd.

### Remote mTLS

For a remote speaker, verify its certificate against a trusted CA and hostname,
and present the operator client identity:

```yaml
bgp:
  backend: rustbgpd
  rustbgpd:
    endpoint: "https://speaker.example:50051"
    ca_cert_path: "/etc/prefixd/credentials/server-ca.pem"
    client_cert_path: "/etc/prefixd/credentials/client.pem"
    client_key_path: "/etc/prefixd/credentials/client.key"
  local_asn: 65010
  router_id: "10.10.0.10"
```

Mount credentials read-only and readable by controller UID 999. The server
certificate needs the endpoint hostname in its SAN. Configure rustbgpd with all
three server TLS fields (`tls_cert_file`, `tls_key_file`, `tls_client_ca_file`).
Map the verified client certificate principal to `operator` under
`[security.grpc.roles]`, rather than configuring a TCP listener principal.
rustbgpd uses the full first `rustbgpd:` URI SAN, otherwise an email SAN or
Subject CN; prefixd sends no principal header. For example, a client with URI
SAN `rustbgpd:prefixd` needs:

```toml
[global.telemetry.grpc_tcp]
address = "0.0.0.0:50051"
tls_cert_file = "/etc/rustbgpd/credentials/server.pem"
tls_key_file = "/etc/rustbgpd/credentials/server.key"
tls_client_ca_file = "/etc/rustbgpd/credentials/client-ca.pem"

[security.grpc.roles]
"rustbgpd:prefixd" = "operator"
```

No hostname or certificate verification bypass is supported. The client
certificate and key must be supplied together. A server requiring bearer
credentials additionally needs `bearer_token_env` in prefixd. TLS fields are
rejected on plaintext and Unix endpoints. Changing the socket path changes
persistent target ownership; socket recreation and credential rotation do not.

Loopback TCP remains available for isolated local deployments with
`endpoint: http://127.0.0.1:50051` and
`bearer_token_env: PREFIXD_RUSTBGPD_TOKEN`. Set that environment variable to the
server's private token-file contents; its configured principal needs `operator`.
Plain HTTP accepts only literal loopback IPs, not hostnames or container DNS.
Tokens and credential paths remain absent from settings API responses.

The Compose GoBGP profile binds its unauthenticated management listener only to
loopback in a namespace shared with its controller. Neither profile publishes a
management port. Recreate the GoBGP/controller pair together when replacing its
namespace owner. Selecting a different profile on existing state requires the
[upgrade and rollback procedure](../how-to/upgrading.md).

Initial network connections and TLS handshakes have a ten-second budget;
complete RPC attempts are bounded separately.

`proto/rustbgpd.proto` is the unmodified `rustbgpd.proto` asset of the
rustbgpd `v0.79.0` release, checked offline against the release's sha256 by
`just proto`. The controller message fields prefixd uses were checked against
it. This is a protocol baseline, not proof that an arbitrary binary reporting
that version has passed the deployment or router tests. The stubs follow the
pinned release, and v0.79.0 is the minimum daemon. At startup prefixd reads
the version that `GetHealth` reports and refuses a daemon older than v0.79.0,
or one that reports no readable version, with "upgrade the speaker first".
Fields and RPCs added after the minimum stay unset and unused until a change
adopts them and raises the minimum. A daemon rolled back while prefixd runs is
still caught at runtime: an `UNIMPLEMENTED` lease RPC withdraws the lease
capability and the leased add creates nothing.

## Released controller qualification

The scoped controller promotion is released: v0.79.0 is the minimum controller
contract version and the current qualification pin. CI runs the lifecycle, TTL
and restart suite against the v0.79.0 immutable image reference in
[releases.json](../../tests/fixtures/rustbgpd/releases.json). Image OCI source
revisions match the dereferenced release-tag commits. This qualifies the local
controller boundary on Linux amd64, independently of router interoperability.

Run the same isolated suite locally with Docker available:

```bash
scripts/test-rustbgpd.sh
```

Fixtures bind ephemeral loopback ports, create an owner-only bearer token, and
remove their containers and token files afterward. They reuse the existing
client/channel and desired-state repository across a forced speaker-process
restart, prove local intent was lost, and verify exact dual-family actions are
restored by the running poller within its configured interval after readiness.
The next converged poll performs no repairs. Unknown local keys are preserved.

On a speaker restart, prefixd's active database rows remain desired state. The
next successful inventory poll repairs missing rules sequentially; there is no
additional restart detector or concurrent replay fan-out. Recovery time includes
speaker readiness, polling and RPC completion, so the configured interval alone
is not a wall-clock SLA under failures or a large backlog.

Monitor `prefixd_reconciliation_repairs_total{status="success"}` for repaired
local intent and `{status="error"}` for rejected repairs. Repair errors also make
`prefixd_reconciliation_runs_total{status="error"}` increase; other missing
rules are still attempted. For example, alert on
`increase(prefixd_reconciliation_repairs_total{status="error"}[5m]) > 0`, and
investigate unexpected repair spikes after restarts. These metrics report local
RPC outcomes, not downstream enforcement or a confirmed restart count.

## Rule and reconciliation semantics

Automatic detector intent uses IPv4 `/32` and IPv6 `/128` host destinations.
ICMP floods use protocol 1 for IPv4 and 58 for IPv6 before reaching either
speaker adapter. The manual mitigation API accepts `icmp` for IPv4 protocol 1
and `icmpv6` for IPv6 protocol 58; cross-family choices return `400` before
persistence or speaker mutation.

The rustbgpd adapter supports destination prefix, optional protocol, equality
lists of destination ports, and discard or traffic policing. Components are sent in RFC
type order. Policing uses bits/sec in prefixd and floating-point bytes/sec in
the daemon; rates that cannot be represented exactly are rejected. Unsupported matches or
actions must produce an error instead of being dropped during decoding.

Add is an upsert; reapplying unchanged intent succeeds. Delete requests opt into
`allow_missing`, so an already absent rule is success. Unknown mutation outcomes
and missing read-view acknowledgements are errors, including an empty response
from an older daemon that ignored the selector.

Both address families are read from retained local intent with
`received_peer_address = "0.0.0.0"`. A nonselected local rule still exists and
must not trigger repeated injection. No received peer's rule is withdrawn by
this API. Other controllers sharing local injection are not distinguished by an
ownership marker; unknown local rules are currently reported, not deleted.

New detector and manual mitigations are persisted as Active desired intent before
announcement. Speaker errors retain that row for readable recovery and return a
request-local unconfirmed outcome; they do not prove rejection or delete intent.
Active status and creation notifications describe desired state, while successful
announcement metrics describe local RPC acceptance. This is not the full durable
desired/acknowledged revision ledger or write-only recovery contract.

Reconciliation reads the complete desired owner inventory for its POP. Malformed
persisted rows fail the pass before repairs begin. Pending creation rows are
excluded from repairs and status-active counts; expired and pending-withdrawal
rows remain counted until their terminal transition but cannot be re-announced.
Expiry enumeration also filters POP before decoding and fails on malformed
eligible owned rows. Existing durable withdrawals are still attempted when expiry
enumeration fails; every withdrawal retains its independent ownership validation.

The scheduler compares NLRI identity and exact supported traffic-rate actions.
A missing rule or a differing discard/policing action is repaired with an upsert;
the next converged poll sends no announcement. Pending and expired siblings still
count when checking unique ownership. Ambiguous owners or invalid desired actions
block their own ownership key while independent repairs continue. Multiple local
rows for one NLRI or unsupported observed actions fail the complete observation
stage before any repair; withdrawal cleanup remains independent. Ownership checks
treat repeated identical port terms as equivalent, while observation preserves
their distinct NLRI identity. The writer also confirms that an observed match
addresses the saved backend route before accepting convergence or repairing it.
GoBGP preserves port-term order: a reordered alias is rejected without a write.
rustbgpd uses the same sorted-port encoding for comparison, injection and deletion.
Repairs retain the saved match so its immutable withdrawal intent remains valid.

Action repair assumes one running controller per POP and exclusive administration
of its physical speaker target. The persistent binding is consistency evidence,
not a process fence; the advisory-lock controller fence keeps a second
controller that shares the database in standby. Neither reader distinguishes an external controller's local
rule with the same match from action drift; such shared-writer protection is not
provided. Unknown matches and other POPs' desired rows do not authorize writes.
GoBGP import policy must preserve supported actions for convergence. Successful
injection does not prove retained post-policy state, export-policy acceptance,
router receipt, or traffic enforcement.

Mandatory TTLs are enforced by the running controller. Losing prefixd does not
drop a separate daemon's router sessions or automatically expire its rules.
Monitor controller availability and restore reconciliation after failure. A
controller lease or coupled lifecycle needs its own design and failure tests.

## Withdrawal recovery

Detector unban, operator single/bulk withdrawal and TTL expiry persist immutable
deletion intent before RPC. An error keeps that intent pending, suppresses repair
of its rule and retries cleanup on the same target. State, original-actor audit
and operation completion commit atomically after confirmed deletion. Conflicting
owners and foreign POPs cannot authorize deletion; stale local requests are
rejected before sending a new RPC.

Canonical ownership includes legacy prefix spellings. New manual duplicates
return 409 before speaker mutation; detector events reuse one existing owner.
Ambiguous multiple owners are rejected. An expired legacy sibling cannot delete
a live owner's rule; after the last owner expires, cleanup retires all rows.
Pending enforced-mode cleanup remains pending in dry-run and resumes when
enforcement returns; dry-run never supplies a deletion acknowledgement.

Independent housekeeping and peer observations continue after failed mutations.
Each scheduler mutation rechecks the current row and pending intent under the
shared lifecycle mutex; the mutex is released before the next rule. Both gRPC adapters
bound complete mutation responses, including body and trailers, to 30 seconds
per attempt, with at most three attempts.

Active mitigation gauges count local database status, including expired or
pending rows awaiting confirmed cleanup; they are not proof of enforcement.
rustbgpd session observations use peer addresses as unique names, so neighbors
sharing a description retain separate metric series.

This is a fixed-target, single-controller contract. Drain pending requests before
changing targets or downgrading; see [the upgrade guide](../how-to/upgrading.md#pending-withdrawals-and-rollback).
Application status and local speaker intent do not prove router enforcement.

## Blackhole lifecycle and reconciliation

Blackhole host routes ([ADR 027](../adr/027-blackhole-mitigations.md)) are
owned through prefixd's database ledger, meaning an enforced row or pending
withdrawal for this POP and target. With `blackhole.leased`, a route is also
held under the controller's injection owner, which the speaker checks on
every add and delete. Admission freezes the configured next hop, communities
and owner (empty for an unleased route) into the row; repair and withdrawal
use that frozen route, so a configuration change affects only new
blackholes.

The add outcome compares the add with the speaker's previous local route at
the key. It is local RPC acceptance, not export or enforcement. A re-add of a
route the speaker still holds, such as the leased re-add after a controller
restart or each retry of a partial re-add, is `unchanged`: it is logged but
writes no audit entry, so retries cannot flood the audit log. After a speaker
restart the same re-add is `created` and audited. A `replaced` outcome on an unleased
admission means a local route appeared at the prefix after the pre-read; it is
logged as an error and the audit entry records it.

Enforced admission returns `409` without persisting or adding when the prefix
already has a live owner or has a pending withdrawal. Unleased admission also
returns `409` when the prefix holds a local route that the ledger does not
own. A pre-read of the speaker detects that untracked route, whether
prefixd-shaped or unrecognized, including another `path_id` at the prefix; a
failed pre-read persists nothing. Leased admission skips the pre-read: the
speaker refuses a leased add on a key held by another owner or by none
atomically, and prefixd then returns `409` and withdraws the new row locally,
audited as `untracked local route at admission`, without a delete. Otherwise
the row is persisted first, then added. Immediately before every add, at
admission and on each repair, prefixd rechecks the safelist under the
lifecycle mutex. A failed lookup sends nothing. A victim safelisted since
admission gets a system withdrawal with the reason `safelisted after
admission` instead of an add.

Withdrawal intent records `rule_kind` `blackhole` and the frozen route with
its owner. Detector unban, operator withdrawal, TTL expiry and the safelist
withdrawal delete through `DeletePath` with that owner and `allow_missing`,
where `NOT_PRESENT` means absent, so a retry, a controller restart or a
speaker restart completes the withdrawal. A
failed or ambiguous delete stays pending with its original actor, reason and
operation ID, and its key blocks repair until the deletion is confirmed. A
pending blackhole withdrawal does not block FlowSpec admission or repair, and
the reverse.

A delete that rustbgpd refuses with `FAILED_PRECONDITION` found the route held
by another injection owner, or by none. prefixd never overrides the owner, so
the withdrawal stays pending: each reconciliation pass retries it and logs the
failure, `prefixd_reconciliation_runs_total{status="error"}` increases, and the
victim's key stays blocked. To resolve it, read the holder with `rbgp`'s local
route listing, which shows the owner. If it is another controller using this
POP's owner, stop that controller. If an operator or another tool added the
route, decide whether it should stay: to remove it, delete it on the speaker
with its own owner (or, deliberately, `rbgp`'s `--override-owner`). The next
pass then sees `NOT_PRESENT` and completes the withdrawal with its original
actor, reason and operation ID. Do not edit the withdrawal row.

Reconciliation compares the blackhole desired set with `list_blackholes` in a
stage separate from FlowSpec, so a failed read of one family never stops the
other. It runs when `blackhole.enabled` is true or the ledger holds a
blackhole. Only live, unexpired, enforced-origin intent of this POP with a
single owner and no pending withdrawal is repaired, with the safelist recheck.
A failed or partial read repairs nothing and gives no unknown-route verdict;
withdrawal cleanup continues. A route at a desired prefix whose next hop or
communities differ from the frozen route is replaced. A desired prefix that
also holds an unrecognized local row is reported as a repair error and left
alone. Recognized routes outside the ledger, including other POPs' routes,
routes of other injection owners, and every unrecognized row are logged and
counted in `prefixd_unknown_local_routes{kind="blackhole"}`, never modified.
One exception: a recognized route that exactly matches the frozen route
(prefix, next hop, communities and owner) of a terminal, enforced-origin
blackhole row of this POP, with no live row or pending withdrawal for the
prefix, was left behind by prefixd. Enforced reconciliation deletes it under
its recorded owner and audits the
deletion with the reason `orphaned after controller downtime`; dry-run only
reports it. Overdue live rows are expired through the normal withdrawal path
first. The FlowSpec stage sets `kind="flowspec"` for the unknown local rules
it already logs.

### Injection lease

With `blackhole.leased` ([configuration](configuration.md#leased-blackholes)),
the controller holds one owner-scoped lease (rustbgpd ADR-0141), keyed on the
same owner as the [controller fence](../adr/027-blackhole-mitigations.md#controller-fence).
At startup `ListInjectionLeases(owner)` is the capability probe and recovers
a live generation; a lease with no time left is not adopted. Every leased add
returns the owner's live generation, which prefixd holds in memory. A
dedicated task sends `RenewLease(owner, generation, lease_seconds)` about
every `lease_seconds / 3`, each with that interval as its deadline. It takes
no lifecycle mutex and no database access, and it is not gated by the
controller fence: renewal only extends routes this owner already holds and
can never add or resurrect one, so a database outage that puts the controller
in standby does not let leased blackholes lapse mid-attack. Adds, deletes and
re-adds stay fenced. A late reply counts as a failed renewal. In dry-run the
controller never renews, because `RenewLease` is a speaker mutation; health
reports the lease as `not_renewing`, and routes left by an enforced run lapse
within one lease.

`FAILED_PRECONDITION` from `RenewLease` means the generation is not live: the
lease expired or rustbgpd restarted. prefixd drops the generation and wakes
reconciliation at once for a full leased re-add of every active, enforced,
unexpired leased blackhole, with the safelist recheck and treating present
routes as missing. A leased add that returns a different generation, and a
read showing one of this owner's rows with `lease_remaining_ms` 0, trigger
the same re-add. Startup always runs one: each add joins a live lease, which
is how a restarted prefixd adopts the routes it left. A re-add that does not
complete stays pending for the next pass. Lease expiry removes rustbgpd's
local intent only and is not a prefixd withdrawal; the rows stay active until
their TTL, an unban or an operator withdraws them.

With `bgp.rustbgpd.leased_flowspec`
([configuration](configuration.md#leased-flowspec)), FlowSpec rules use the
same lease: `AddLeasedFlowSpec` for rules recorded under the owner, never
`AddFlowSpec` after a failure, and `DeleteFlowSpec` with the recorded owner
and never `override_owner`. The FlowSpec read sets each rule's owner from
`injection_owner`, so a desired rule matches only under its recorded owner,
and drops leased rows with `lease_remaining_ms` 0 as lost. Another owner's
rule at a desired match is a repair error, counted as unknown and never
touched. A requested re-add is taken once per pass and applied by both
stages: the FlowSpec stage runs first, then the blackhole stage. A loss that
the blackhole stage detects later in the same pass, such as an expired row,
forces the blackhole re-add at once; that re-add adopts the new generation
and requests another pass immediately, which re-adds the FlowSpec rules.

The lease probe, adds and renewals run against rustbgpd 0.79.0 and later.
`scripts/test-rustbgpd.sh` runs the leased lifecycle for blackholes and
FlowSpec (add and renew, a prefixd restart within the lease, expiry after
prefixd stops, and a rustbgpd restart) only when
`PREFIXD_RUSTBGPD_TEST_VERSION` is 0.79.0 or later, and proves the refused
startup on earlier releases.

### Export evidence

Each step of this ladder is separate evidence, and none implies the next:

| Step | What shows it | Backends |
| --- | --- | --- |
| Desired intent | An active row in prefixd's database | All |
| Local RPC acceptance | A successful add | All |
| Retained local intent, or accepted local RIB | The reconciliation read-back | rustbgpd (retained intent), GoBGP (accepted RIB) |
| Committed to a peer's Adj-RIB-Out | `export_evidence` on the blackhole, `committed` | rustbgpd, blackholes only |
| Router receipt and installation | Not observed by prefixd; the [FRR receipts](qualification/blackhole-frr-2026-10-19.md) are lab evidence only | None |
| Router enforcement | Not observed | None |

Once per reconciliation pass, after the blackhole stage, prefixd reads
rustbgpd's `InjectionService.ListPathExportDispositions` for each active,
enforced-origin blackhole of this POP (the stage's repair candidates), keyed
on its host prefix and `path_id` 0, and walks every page. It also uses the
pass's `ListNeighbors` read. The reads run one at a time within a 10-second
budget per pass, so a stalled speaker cannot hold up expiry; a read the budget
cuts off reports an error. A failed or cut-off read keeps the blackhole's
warning from its last complete read, so a transient error neither clears nor
raises degraded health. The pass keeps the result in memory. The mitigation
detail API, health detail and metrics read that snapshot and never call the
speaker. The read is observation only: it sends no route mutation and adds no
writer behavior, and a standby controller reads nothing because it runs no
reconciliation.

rustbgpd lists one row per Established peer:

- `committed`: the route is in that peer's Adj-RIB-Out, committed to its
  outbound path. BGP carries no acceptance signal, so this does not mean the
  peer received, accepted, installed or enforces the route. Operator text
  never calls it installed or enforced.
- `withheld`: not exported to that peer, with a bounded `reason`
  (`export_policy`, `family_suppressed:<reason>`, `family_not_negotiated`,
  `not_selected`, `outbound_prefix_limit`, `exact_export_rejected[:<reason>]`
  or `export_rule`) and the export explain ladder's `explain_code`.
- `pending`: export has not settled (`selection_deferred`, `outbound_resync`,
  `orf_pending` or `not_yet_committed`).

A configured peer without an Established session is absent from that list.
Absent is not withheld: prefixd joins the list with the session read and
reports such peers as `not_established_peers`, which is null, not empty, when
the session read failed.

A failed or partial read is an observation error. `NOT_FOUND` on the first page
means the speaker holds no local route at the key (`no_local_route`, which
reconciliation repairs); any error after the first page, a repeated page token
or peer, or an unknown disposition fails the whole read. An error is never
reported as no peers or as success, and it is distinct from a successful empty
list, which means no peer is Established. GoBGP reports `unsupported`.

An observed blackhole committed to no Established peer, because every listed
peer is withheld or pending or none is Established, is exported to no router.
Health detail lists it under `speaker.blackhole_exports.unexported` with a
bounded reason and degrades `status`; `prefixd_blackhole_unexported{reason}`
counts it and the shipped `PrefixdBlackholeNotExported` alert fires after five
minutes. A speaker export policy that denies the route shows as `withheld`
with reason `export_policy` and explain code `policy_denied`, and `detail`
names the policy. rustbgpd has no RPKI-specific reason, and at 0.79.0 an
RPKI-Invalid filter does not cause it for prefixd's blackholes, which carry
no AS_PATH and validate NotFound (see [RPKI filters](#router-and-speaker-requirements)).

FlowSpec has no equivalent RPC, so FlowSpec rules carry no export evidence.

`tests/integration_rustbgpd_peer.rs` reads the dispositions from a released
rustbgpd peered with GoBGP over IPv4 and IPv6 unicast: `committed` for both
families, `withheld`/`export_policy`/`policy_denied` for a prefix the export
policy denies, a configured neighbor that never establishes reported as not
Established rather than withheld, and absence after the delete.

### Router and speaker requirements

Over an IPv4-transport session, rustbgpd sends IPv6 blackholes to an eBGP peer
only when that neighbor sets `local_ipv6_nexthop`; without it the add succeeds
but the route is silently withheld. On eBGP, rustbgpd also replaces prefixd's
frozen next hop with its own (the session address, or `local_ipv6_nexthop` for
IPv6), so the router's import policy
must match BLACKHOLE (`65535:666`) and set a discard next hop itself. The
[FRR blackhole receipt](qualification/blackhole-frr-2026-10-19.md) shows both.
prefixd refuses `0.0.0.0` and `::` as configured next hops, which speakers
commonly read as next-hop-self, as `AddPath` does from rustbgpd 0.79.0: RTBH
needs the discard next hop that the edge routers map to null. A local row with
an unspecified next hop is reported as unrecognized, never adopted.

**RPKI filters.** A blackhole `/32` or `/128` is longer than its covering
ROA's maxLength, so wherever it is validated with an origin AS it is
RPKI-Invalid. rustbgpd 0.79.0 validates injected routes, but prefixd injects
with an empty AS_PATH, which has no origin AS, so rustbgpd stores them as
NotFound and its own Invalid export filters pass them. A router that
receives the route validates it with the speaker's AS as origin, and a
policy there that drops RPKI-Invalid before it accepts BLACKHOLE drops every
blackhole silently: the add succeeds and nothing reaches the edge. Match
BLACKHOLE ahead of any Invalid filter, or exempt the RTBH sessions, on every
validating hop, then test one ban end to end. The
[RPKI blackhole receipt](qualification/blackhole-rpki-frr-2026-10-20.md)
shows each case at rustbgpd 0.79.0 and FRR 10.7.1. With rustbgpd, a speaker
export filter that withholds a blackhole shows in
[export evidence](#export-evidence) as `withheld` with reason
`export_policy`; a filter on a downstream router does not.

## Remaining backend work

Both readable adapters have shared contracts, released-daemon CI, secure
profiles, restart recovery and durable withdrawal cleanup. Optional observation
and health availability metadata are implemented.

Vendor forwarding qualification and a complete desired/acknowledged announcement
ledger remain open. A write-only backend needs
verified reconciliation and restart replay before shipping. ExaBGP, a generic
HTTP shim, exec transport and runtime plugin loading are not supported today.

## Contributor and certification gates

Custom `RepositoryTrait` implementations must provide the strict
`expired_mitigation_inventory` boundary. The legacy required expiry method remains
available, but the new boundary reports unsupported until explicitly implemented.

Add an adapter module, its config subsection, and a factory entry. Implement required writing and explicitly opt into supported observers. Test exact RPC
or transport payloads, authentication, transient and permanent failures, rule
identity, replacement, repeated delete, both families, and action read-back.
Run against a pinned real daemon before calling the adapter supported. Record
router evidence separately and include restart/TTL behavior in the release gate.

The existing `gobgp` health field and `apipb` export remain compatibility
surfaces. They do not select the active backend. Production write-only adapters
remain gated on the durable announcement ledger and verified recovery semantics.


## Readable backend qualification

`tests/common/speaker_contract.rs` contains the shared async lifecycle oracle used
by Mock, GoBGP and rustbgpd. It checks complete local inventory cardinality,
canonical IPv4/IPv6 destinations, optional protocols, eight destination ports,
exact discard/police actions, duplicate announcement/withdrawal, action replacement
and re-announcement. The ordinary Rust test suite includes a deliberately broken
Mock reader whose missing actions must fail that oracle with a useful diagnostic.
A readable third-party adapter can call `run_readable_contract(&adapter)` against
an isolated empty speaker; unsupported observation must not be faked as an empty
inventory. Peer transitions and process restart require backend-owned fixtures.

Run the real fixtures on Linux with Docker:

```sh
scripts/test-gobgp.sh
scripts/test-rustbgpd.sh
```

The GoBGP fixture pins image digest
`sha256:42b8d0017237e388c55936efe1f23632365b24a31751f6e8815f93e12c4d18c2`
and verifies the binary reports 4.10.0. Raw and API end-to-end tests create their
own containers and reserve ephemeral loopback listeners; they ignore ambient
speaker endpoints. Readiness, raw streams and peer convergence are bounded.
Optional `PREFIXD_TEST_CPUSET` applies to the fixture containers.

The GoBGP peer case observes actual dual-family receipt and withdrawal, checks
session continuity, forces a received route to win over an existing local path,
and verifies the local reader still returns that nonselected local path. It also
checks peer loss and recovery after a real process restart using the original
clients. A separate restart case rebuilds GoBGP state through the real reconciler
without deleting unrelated local rules. Existing rustbgpd TTL and same-client
restart cases remain in its released-image matrix. CI retains logs on success
and failure; an unavailable image or daemon fails qualification.

The separate `integration_rustbgpd_peer` target adds a pinned rustbgpd↔GoBGP
fixture. Both speakers use BGP port 179 inside separate containers on a uniquely owned bridge.
Only their RPC ports are published to ephemeral host-loopback ports; neither
speaker targets the host's BGP port. Both sides negotiate
only IPv4/IPv6 FlowSpec. Its raw received-route checks cover exact discard and
police actions, withdrawal/re-announcement and preservation of unrelated local
intent. An explicit lab import policy prefers the GoBGP candidate, so the test
also checks real selected peer rows against nonselected synthetic local rows
and the production local reader. It runs through `scripts/test-rustbgpd.sh` for
each pinned rustbgpd release; source presence alone is not a successful run.
The peer restart case preserves desired rows and the client endpoint, verifies
lost local and peer receipt, then checks exact dual-family recovery, a quiet
subsequent poll and durable withdrawal cleanup.

These tests observe local acceptance and daemon-to-daemon BGP receipt. They do
not establish router enforcement or vendor forwarding. Receipt in a real
router's FlowSpec table is checked separately for each speaker against FRR by
the [FlowSpec interop lab](../../lab/README.md#flowspec-interop-lab-maintained);
that is also control-plane evidence only. ExaBGP and other
write-only backends are not qualified by this readable suite.
