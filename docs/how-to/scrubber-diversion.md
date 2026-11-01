# Manual scrubber diversion

Scrubber diversion is disabled by default. It uses rustbgpd v0.81.0's guarded
FlowSpec methods to redirect selected traffic for one owned host to a configured,
same-family IP target. It does not configure the scrubber or its clean return
path. The first workflow is manual and requires an administrator; detector and
playbook actions cannot request diversion.

The controller fixtures qualify local intent, ownership and failure handling.
They do not qualify forwarding on an unspecified router. FRR 10.7's
[FlowSpec documentation](https://docs.frrouting.org/en/stable-10.7/bgp.html#limitations-known-issues)
still identifies its missing Netfilter installation driver. A received BGP rule
alone cannot establish installed redirection. Do not combine a traffic-rate
action with redirect to work around a receiver's limitations.

## Configure a profile

Add the following section to `prefixd.yaml`, replacing the documentation
addresses and receipt with a qualification for the actual ingress router,
scrubber, target resolution and clean return path. Destinations must also belong
unambiguously to one customer in `inventory.yaml`.

```yaml
scrubber:
  enabled: false
  # Optional additional CA for the HTTPS readiness monitor.
  readiness_ca_cert: null
  profiles:
    - id: scrubber-a
      revision: qualified-v1
      ipv4_target: 192.0.2.99
      ipv6_target: "2001:db8::99"
      destinations: [203.0.113.0/24, "2001:db8:1234::/48"]
      router_peers: [192.0.2.2]
      policy_binding: ingress-only-v1
      qualification_receipt: receipts/router-scrubber-a-qualified-v1.json
      readiness_url: https://monitor.example.net/scrubber-a
      readiness_token_env: SCRUBBER_A_READINESS_TOKEN
      max_ttl_seconds: 300
      max_active: 10
      max_new_per_minute: 10
      reserved_targets: [192.0.2.1/32]
```

An omitted target family is unsupported. Targets must be unicast literals;
unspecified, loopback, link-local, multicast, mapped IPv6, IPv4 `0/8` and `240/4`
and configured reserved targets are refused. The target cannot equal the victim.
Private targets are allowed when explicitly configured. Router identities must
retain the interface scope of link-local peers.

Install an export policy that permits diversion only toward the frozen ingress
peer set, with matching receiver import and interface policy. The readiness
monitor must verify that policy binding. Keep clean return traffic outside the
redirect's ingress scope, and qualify target reachability, filtering, capacity,
MTU and loop avoidance externally. The receipt field records an operator's
qualification reference; prefixd does not independently certify its contents.

Set the readiness credential in the controller's environment, install any
private monitor CA, then enable the profile configuration and restart. Each
profile gets a distinct guarded lease owner, separate from ordinary FlowSpec,
blackholes and other profiles. Ordinary leasing settings need not be enabled.
Only rustbgpd supports this workflow. An older daemon refuses the new RPCs;
prefixd does not retry through ordinary leased or unleased methods.

Profiles start unarmed. A restart with outstanding diversion first drains that
saved intent; it cannot silently resume attracting traffic. Disabling scrubbers,
changing mode, removing a profile or changing its frozen profile/policy snapshot
is refused at startup until its outstanding withdrawals have completed. Profile
settings require a restart; inventory/playbook reload does not replace them.

## Supply authenticated readiness

The configured HTTPS endpoint must return `200` with JSON of this shape. The
timestamps below illustrate an eight-second validity interval; a copied stale
report is refused.

```json
{
  "profile": "scrubber-a",
  "revision": "qualified-v1",
  "policy_binding": "ingress-only-v1",
  "observed_at": "2026-11-01T08:00:00Z",
  "valid_until": "2026-11-01T08:00:08Z",
  "process_ready": true,
  "filters_ready": true,
  "target_reachable": true,
  "capacity_available": true,
  "canary_passed": true,
  "export_isolated": true
}
```

The monitor receives a bearer credential from the configured environment
variable. Reports must match the profile revision and policy binding. All six
checks must pass, validity must be at most ten seconds, and observation time may
be at most two seconds in the future. A BGP session or ping does not substitute
for these checks. The monitor owns the checks and their canary scope.

Requests have a two-second timeout, a 4 KiB response limit and no redirects.
The controller polls every five seconds, with a four-second lifecycle-pass
budget. A failed, stale, malformed or mismatched report, storage failure, lost
controller fence or incomplete pass latches affected profiles unarmed. New
adds and renewals then stop. Healthy profiles use independent owners and cannot
extend an unhealthy profile's lease. Recovery never clears the latch by itself.

## Preview, confirm and withdraw

Use **Scrubbers** in the dashboard: inspect the configured targets and readiness,
explicitly re-arm the profile, then preview a host match and confirm the exact
traffic selector, target and profile revision. Editing a field invalidates that
preview. Withdrawal returns traffic to ordinary routing, potentially exposing
the victim to attack again; there is no automatic discard, blackhole or fallback.

The CLI offers the same workflow. Administrative requests may use a cookie from
an authenticated administrator session through `PREFIXD_SESSION_COOKIE`.
Ordinary bearer tokens retain their Operator role and cannot divert traffic.

```bash
prefixdctl scrubbers list
prefixdctl scrubbers arm scrubber-a --revision qualified-v1
prefixdctl diversions preview --file diversion.json
prefixdctl diversions create --file diversion.json --confirmation '<exact preview confirmation>'
prefixdctl diversions list
prefixdctl diversions get <id>
prefixdctl diversions withdraw <id>
```

`diversion.json` contains a profile name, never an arbitrary target, owner,
community, health URL or lease generation:

```json
{
  "profile": "scrubber-a",
  "scope": {"dst_prefix": "203.0.113.20/32", "protocol": 6, "dst_ports": [443]},
  "ttl_seconds": 60,
  "reason": "Manual diversion during an investigated attack"
}
```

The API exposes authenticated `GET /v1/scrubbers`, administrator-only
`POST /v1/scrubbers/{profile}/arm`, `POST /v1/diversions/preview` and
`POST /v1/diversions`, plus list/detail and administrator withdrawal at
`POST /v1/diversions/{id}/withdraw`. Preview reserves nothing and sends no speaker
RPC. Creation repeats the checks. Existing ownership, safelist, source/match,
lifetime, customer/POP/global quota and creation-rate limits still apply; profile
caps can only narrow them. Live and pending diversion excludes every other
mitigation affecting that victim, including an overlapping destination CIDR.

Dry-run records a simulation and sends no window, add, renewal or delete.
Simulations do not acquire a speaker lease or reserve a live victim. Every
enforced admission persists its exact match, target, owner, profile/policy
snapshot, originating controller and leadership epoch, and unique admission
revision before mutation. Late database commits from an earlier controller or
leadership epoch are drained, never replayed under fresh authorization.

## Read the evidence and failure state

`pending` is durable intent awaiting local confirmation; `active` means the
exact guarded revision was observed locally. The last timestamped per-peer
export observation is separate. `committed` means Adj-RIB-Out, not router receipt
or forwarding. Readiness is the external monitor's bounded attestation for its
tested path, not proof that every victim packet is scrubbed.

Unknown add outcomes and every withdrawal remain durable. The controller stops
issuing authorization for that admission, deletes its exact revision early,
then waits a full thirty seconds on a monotonic clock before the final exact
delete and complete local absence check. A restarted controller waits the full
interval again. Client cancellation, wall-clock jumps and an initial empty read
cannot release victim exclusion. Revision-fenced deletion prevents a late old
delete from removing a newer admission under a still-live sibling lease.

The thirty-second mutation window bounds authorization, not a router removal
deadline. RIB queue lag, speaker loss and remote Graceful Restart can extend
retention. Unavailable or inconsistent observation stays pending. The controller
does not override foreign owners or guess that an unknown rule disappeared.
An untracked rule under a profile's own owner also blocks re-arm and renewal;
it is retained for lease expiry rather than broadly deleted.

Audit entries retain actor, operation, profile and admission revision.
Authenticated health reports readiness and latch state. Prometheus uses bounded
configured-profile labels for `prefixd_scrubber_ready`,
`prefixd_scrubber_armed` and `prefixd_scrubber_intents`; lifecycle pass failures
use `prefixd_scrubber_lifecycle_failures_total`. Addresses and operation IDs are
not metric labels.

The authenticated WebSocket feed publishes durable `diversion_updated`
transitions and `scrubber_updated` readiness/re-arm observations. The dashboard
refreshes these resources from the API and also polls every five seconds;
missed-feed resync refreshes both resources.

Before rollback, withdraw every enforced diversion, wait for confirmed local
absence, and verify router removal separately. Keep the durable snapshots and
withdrawal records. An older controller does not understand their exclusion
obligations. See [ADR 030](../adr/030-scrubber-diversion.md), the
[speaker contract](../project/scrubber-diversion-contract.md) and rustbgpd's
[released guarded contract](https://github.com/lance0/rustbgpd/blob/v0.81.0/docs/adr/0144-guarded-flowspec-mutations.md).
