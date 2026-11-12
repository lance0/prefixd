# Manual scrubber diversion

Scrubber diversion is disabled by default. Global IP-target diversion uses
guarded FlowSpec methods available in rustbgpd 0.81.0 or later. VPN diversion
requires rustbgpd 0.82.0 or later, a named VPN scope and a successful family 13/14
probe. It redirects selected traffic for one owned host to a configured,
same-family IP target or scrubbing VRF route target. It does not configure the
scrubber, VRFs or the clean return path. The first workflow is manual and requires an administrator; detector and
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

For redirect-to-VRF, replace both IP targets with one action route target.
This VPN-only action requires rustbgpd 0.82.0 and a successful family 13 or 14
probe for the [configured VPN scope](vpn-flowspec.md#configure-scope):

```yaml
      scope: TRANSIT
      redirect_route_target: "44407:888"
      # Omit ipv4_target and ipv6_target.
```

The configured VPN scope's RD and scope RT (for example `44407:777`) identify
where the receiver imports the mitigation rule. `redirect_route_target` selects
the scrubbing VRF used by the redirect action. These are different attributes:
scope RTs use subtype `0x02`; redirect-to-VRF uses RFC 8955/RFC 7674 types
`0x80`, `0x81` or `0x82` with subtype `0x08`. AS2, IPv4-administrator and AS4
forms are supported, including `0.ASN:value` to preserve a small-ASN AS4 form.
The controller requires a named VPN scope for this action and rejects a profile
mixing IP targets and a VRF action target. Global IP-target diversion keeps its
existing behavior.
No API payload can supply an arbitrary action target.

The same guarded admission, readiness, revision and withdrawal rules apply to
both action types. For a VRF target, the monitor's `target_reachable` and canary
checks must establish the configured scrubbing-VRF import, forwarding and clean
return path. A ping, BGP session or local RPC acceptance cannot establish those
properties. Qualify the receiver's redirect action and loop avoidance per
platform and software release. The dashboard, preview confirmation, saved rule
and audit identify this action as `VRF RT ...` separately from scope RTs.
Changing the action target requires draining the held admission, then creating
a new revision; retries and pending withdrawals retain the original target.

For IP-target profiles, an omitted target family is unsupported. Targets must be unicast literals;
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

### Add a symmetric return leg

Without a return leg, diversion covers one direction only. A stateful scrubber
that validates TCP handshakes must also see the victim's responses. A global
IP-target profile can add the
[return leg from ADR 030](../adr/030-scrubber-diversion.md#amendment-symmetric-return-leg):

```yaml
    - id: scrubber-a
      revision: qualified-v2
      ipv4_target: 192.0.2.99
      router_peers: [192.0.2.2]          # router A, internet ingress
      policy_binding: ingress-only-v2
      # ...other fields as above
      return_leg:
        router_peers: [192.0.2.3]        # router B, client side
        policy_binding: client-side-only-v1
        export_community: "64496:100"
        tcp_flags: syn_ack               # optional
```

For an inbound request with `protocol: 6`, the controller derives a second rule
for the same victim. It has no destination component, the victim as its source
host, protocol 6, the inbound destination ports as source ports and, when
`tcp_flags: syn_ack` is set, a SYN+ACK selector. It uses the profile's target,
owner and admission revision, and it carries `export_community`. Without
`tcp_flags`, it diverts all of the victim's TCP traffic from those ports to
the scrubber. Other protocols create the inbound leg alone. A request that omits
the protocol, or a TCP request with `src_prefix`, is refused. Requests cannot
supply the return leg or its flags, and VPN or redirect-to-VRF profiles refuse
`return_leg`.

`export_community` must be a canonical `ASN:VALUE` outside `0:x` and `65535:x`,
and different from any community the speaker attaches for another purpose. It
is the only attribute that lets speaker export policy tell the legs apart.
Inbound rules keep their bytes and carry no community. Configure rustbgpd to
send rules with the community only to the return routers and to deny them to
the inbound routers. For example:

```toml
[policy.definitions.inbound-only]
default_action = "permit"
[[policy.definitions.inbound-only.statements]]
match_community = ["64496:100"]
action = "deny"

[policy.definitions.return-only]
default_action = "deny"
[[policy.definitions.return-only.statements]]
match_community = ["64496:100"]
action = "permit"
```

Bind `inbound-only` with `export_policy_chain` on router A and `return-only` on
router B. Both peer lists may name the same router when it carries both legs on
different interfaces; prefixd cannot observe interface scope, so the receipt
must cover that topology. The released fixtures prove this export isolation on
rustbgpd 0.81.0 and 0.82.0 and the exact return-leg bytes received by a peer.
They do not prove that router B installs a rule without a destination: RFC 8955
§6 and RFC 9117 validation differ by receiver. Qualify router B's acceptance,
installed rules and counters, and precedence against an overlapping
destination-keyed discard for another host before enabling the return leg.

Clean output from each leg must re-enter outside that leg's FlowSpec ingress
scope or in a separate clean routing domain. Clean return output still has the
victim as source and the selected flags; re-entering router B inside the return
leg's ingress scope redirects it again. The target route must not resolve
through either leg's ingress scope.

A pair is one diversion with one owner, one revision, one readiness state and
one latch. Both legs are added in one lifecycle pass, the return leg first, and
the diversion becomes `active` only when one read-back shows both. A refused or
unknown add of either leg, a missing leg, a leg with another revision or
generation, or an export of either leg outside its own peer list latches the
profile and drains both legs. Withdrawal deletes the inbound leg, then the
return leg, and keeps victim exclusion until both keys are confirmed absent.
Renewal extends the profile owner's whole lease, so when another healthy
diversion of the same profile renews in the pass that finds a leg missing, the
surviving leg is extended once; the next pass deletes it. A pair counts as two
rules against `max_active` and the customer, POP and global quotas, so a
profile with `return_leg` needs `max_active` of at least 2; the creation rate
counts one admission. Each profile's `export_community` must be unique and
differ from every configured blackhole community. A pair is also refused while
any live or pending rule has a source containing the victim, and such rules are
refused while the pair is outstanding.

A destination-less local rule that is not one of this controller's return legs,
whether held by another tool's guarded owner or unowned, occupies its key and
counts as affecting every victim of its family, or of both families when it has
no prefix component. It refuses diversion, keeps any withdrawal at its key
pending and is never deleted; it does not fail the guarded inventory read. The
ordinary FlowSpec reconciler's local inventory read still fails on an unowned
local rule it cannot decode, including one without a destination, as it did
before return legs.

Adding, removing or changing `return_leg` requires a new profile `revision`.
Startup refuses the change while the profile has outstanding diversion.

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

For a profile with a return leg, the report must also contain this object, and
a report for a profile without one must omit it:

```json
"return_leg": {
  "policy_binding": "client-side-only-v1",
  "export_isolated": true,
  "canary_passed": true
}
```

`policy_binding` must equal the return leg's configured binding.
`export_isolated` attests that return-leg rules reach only the return routers
and inbound rules never reach them, unless a router is in both lists.
`canary_passed` attests that a canary TCP connection completed its handshake
through both legs and that the scrubber saw each canary packet exactly once in
each direction; seeing one twice indicates a loop. A missing, unexpected or
mismatched object makes the profile `unknown`, and a failed check makes the
whole profile `not_ready`. Either drains both legs.

The monitor receives a bearer credential from the configured environment
variable. Reports must match the profile revision and policy binding. All six
checks, and both return-leg checks where configured, must pass, validity must
be at most ten seconds, and observation time may be at most two seconds in the
future. A BGP session or ping does not substitute
for these checks. The monitor owns the checks and their canary scope.

Requests have a two-second timeout, a 4 KiB response limit and no redirects.
The controller polls every five seconds, with a four-second lifecycle-pass
budget. Each pass reads the guarded inventory once, issues at most one mutation
window and one renewal per profile, and reads the result back once, so speaker
work grows with profiles rather than diversions. It reuses a window only while
at least twelve seconds remain, longer than the gap between two renewals.
Per-peer export reads stop three seconds into the pass and rotate across
passes; a slow or failed read marks that diversion's export evidence as
historical without latching. A pass writes and audits a diversion only when its
status, generation or export evidence changes. A failed, stale, malformed or
mismatched report, storage failure, lost controller fence, failed renewal, lost
ownership or incomplete pass latches affected profiles unarmed. New
adds and renewals then stop. Healthy profiles use independent owners and cannot
extend an unhealthy profile's lease. Recovery never clears the latch by itself.

## Preview, confirm and withdraw

Use **Scrubbers** in the dashboard: inspect the configured targets and readiness,
explicitly re-arm the profile, then preview a host match and confirm the exact
traffic selector, target and profile revision. For a pair, the preview and the
confirmation string also cover the return leg, shown as `destination: any` with
its source host, ports, flags, peers and community. Editing a field invalidates
that preview. Withdrawal returns traffic to ordinary routing, potentially exposing
the victim to attack again; there is no automatic discard, blackhole or fallback.

The CLI offers the same workflow. Administrative requests use a cookie from an
authenticated administrator session through `--session-cookie` or
`PREFIXD_SESSION_COOKIE`. Obtain one by signing in with
[`POST /v1/auth/login`](../reference/api.md#login), then pass the returned
`Set-Cookie` name and value as a Cookie header, for example
`PREFIXD_SESSION_COOKIE='id=...'`. Treat it as a credential. Ordinary bearer
tokens retain their Operator role and cannot divert traffic.

```bash
prefixdctl scrubbers list
prefixdctl scrubbers arm scrubber-a --revision qualified-v1
prefixdctl diversions preview --file diversion.json
prefixdctl diversions create --file diversion.json --confirmation '<exact preview confirmation>'
prefixdctl diversions list
prefixdctl diversions get <id>
prefixdctl diversions withdraw <id> --reason 'Attack ended; verified at the edge'
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
Observed local rules from another tool also refuse diversion when they affect
the victim, even with a different traffic selector; prefixd leaves them untouched.

Dry-run records a simulation and sends no window, add, renewal or delete.
Simulations do not acquire a speaker lease or reserve a live victim. Every
enforced admission persists its exact match, target, owner, profile/policy
snapshot, originating controller and leadership epoch, and unique admission
revision before mutation. Late database commits from an earlier controller or
leadership epoch are drained, never replayed under fresh authorization.

## Read the evidence and failure state

`pending` is durable intent awaiting local confirmation; `active` means the
exact guarded revision was observed locally, for both legs of a pair. The last
timestamped per-peer export observation is separate, and a pair keeps one for
each leg (`export_observation` and `return_export_observation`). A pair costs
two export reads. `committed` means Adj-RIB-Out, not router receipt
or forwarding. Readiness is the external monitor's bounded attestation for its
tested path, not proof that every victim packet is scrubbed.

Unknown add outcomes and every withdrawal remain durable. The controller stops
issuing authorization for that admission, deletes its exact revision early,
then waits on a monotonic clock before the final exact delete and complete local
absence check: thirty seconds, its own window lifetime, for intent it admitted,
or rustbgpd's 120-second window cap for intent another controller process
admitted, including after a restart. Client cancellation, wall-clock jumps and an initial empty read
cannot release victim exclusion. Revision-fenced deletion prevents a late old
delete from removing a newer admission under a still-live sibling lease.

The mutation window bounds authorization, not a router removal deadline. RIB queue lag, speaker loss and remote Graceful Restart can extend
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
obligations. A controller without return-leg support refuses a configuration
containing `return_leg`, and refuses to start while any diversion admitted
under such a profile is outstanding; follow the
[upgrade guide](upgrading.md#downgrading-with-scrubber-return-legs) first. See [ADR 030](../adr/030-scrubber-diversion.md), the
[speaker contract](../project/scrubber-diversion-contract.md) and rustbgpd's
[released guarded contract](https://github.com/lance0/rustbgpd/blob/v0.82.0/docs/adr/0144-guarded-flowspec-mutations.md)
and [VPN FlowSpec design](https://github.com/lance0/rustbgpd/blob/v0.82.0/docs/adr/0146-vpn-flowspec.md).
