# Originate VPN FlowSpec

VPN FlowSpec selects an RD and scope route targets for a mitigation. The receiving
PE imports those RTs into its VRF; prefixd and rustbgpd do not create VRFs. This
path requires rustbgpd 0.82.0 and a successful read-only probe of family 13
(IPv4) or 14 (IPv6). Global FlowSpec keeps the 0.81.0 minimum. GoBGP refuses
VPN requests before an RPC.

The current implementation covers discard, police and guarded target-IP or
VRF route-target scrubber diversion. Marking remains the next action slice.
[The scrubber procedure](scrubber-diversion.md) distinguishes scope RTs from
the configured redirect action RT and describes readiness requirements.
IPv6 prefixes use offset zero. Nonzero IPv6 prefix offsets are outside the
CIDR model and fail the pinned GoBGP 4.11.0 interoperability check.

## Configure scope

Merge this section into `prefixd.yaml`, preserving the existing transport and
credentials. `configs/vpn-scopes.yaml.example` contains the same BGP example.

```yaml
bgp:
  backend: rustbgpd
  local_asn: 44407
  router_id: 192.0.2.1
  rustbgpd:
    endpoint: http://127.0.0.1:50051
    bearer_token_env: PREFIXD_RUSTBGPD_TOKEN
    leased_flowspec: true
  default_scope:
    ipv4: TRANSIT
    ipv6: TRANSIT6
  vpn_scopes:
    TRANSIT:
      family: ipv4
      rd: "44407:40"
      route_targets: ["44407:777"]
      allow_source_only: false
    TRANSIT6:
      family: ipv6
      rd: "44407:40"
      route_targets: ["44407:777"]
      allow_source_only: false
```

A string `default_scope: TRANSIT` selects one named family. A family mismatch
refuses admission; it never falls back to global. The two-family mapping above
selects each family explicitly. Omitting the default retains global automatic
mitigation. Detectors cannot supply routing scope, RD or RT selectors; keep
unrelated detector metadata in `raw_details`.

BGP settings require a controller restart; Config → Reload does not change
these settings. New admissions snapshot the name, family, exact RD encoding and
RTs. Existing rules, expiry and pending withdrawals use their saved snapshot.
Drain outstanding intent before removing a scope or changing its RD/RTs.
Changing the automatic default affects new admissions only. A VPN default
refuses blackhole playbooks rather than injecting global RTBH.

The receiving peer must enable `l3vpn_ipv4_flowspec` and/or
`l3vpn_ipv6_flowspec` and import `44407:777` into TRANSIT. Configure that policy
outside prefixd. Different RDs or RTs do not prove separate traffic domains;
guarded diversion retains cross-scope victim exclusion.

## Preview and create

Authenticated operator requests use dedicated VPN endpoints so older
controllers refuse the endpoint instead of ignoring a scope selector.
`POST /v1/vpn/mitigations/preview` accepts:

```json
{
  "scope": "TRANSIT",
  "rule": {
    "victim_ip": "203.0.113.10",
    "protocol": "udp",
    "action": "discard",
    "ttl_seconds": 30,
    "reason": "Confirmed attack in TRANSIT"
  }
}
```

Submit the same body to `POST /v1/vpn/mitigations` after an admissible preview
acknowledges the requested scope. CLI create and dashboard submission repeat
that scope-aware preview before creation and never retry through a global
endpoint. Destination ownership, safelist, prefix, port, TTL and quota controls
still apply. A source-plus-destination match also requires
`guardrails.allow_src_prefix_match: true`.

```bash
prefixdctl mitigations preview 203.0.113.10 --scope TRANSIT \
  --protocol udp --action discard --ttl-seconds 30 --reason 'Confirmed attack'
prefixdctl mitigations create 203.0.113.10 --scope TRANSIT \
  --protocol udp --action discard --ttl-seconds 30 --reason 'Confirmed attack'
```

Use an IPv6 scope and destination for VPNv6. Withdrawal and lifetime extension
select the mitigation ID and retain the original wire identity. Local intent,
RPC acceptance, peer export and receiver enforcement are separate evidence.

## Guarded scrubber scope

Set `scope: TRANSIT` (or `TRANSIT6`) on an existing qualified scrubber profile.
Omission retains global diversion. The profile scope must match the victim
family; use a profile for each family. Keep the existing readiness, policy
binding, revision, arm and canary requirements. A configured scope does not
qualify the receiving VRF or a clean return path.

VPN preview/creation uses `/v1/vpn/diversions/preview` and
`/v1/vpn/diversions`, with `{"scope":"TRANSIT","diversion":{...}}` around the
existing diversion request. The client requires an acknowledgment of the
profile scope and exact scoped rule before it can create. It never retries
through the global endpoint.

Use that envelope in the request file for the CLI too:

```sh
prefixdctl diversions preview --file vpn-diversion.json > preview.json
prefixdctl diversions create --file vpn-diversion.json \
  --confirmation "$(jq -r '.confirmation' preview.json)"
```

Creation repeats the scoped preview and compares the full confirmation with
what the operator supplied. If the target, match, RD, RTs or profile revision
changed, review a new preview before confirming again. The CLI refuses malformed
envelopes or missing scope acknowledgments; it does not fall back to global.

## Source-only rules

Source-only is a distinct manual VPN operation with no destination component.
An explicit destination `/0` remains a different wire identity. Enabling
`allow_source_only: true` accepts that the rule affects traffic to every
destination in that VRF, including safelisted destinations.

The source must not overlap a safelist entry, inventory-owned range or asset,
or the scope's `infrastructure_prefixes`. Configure all infrastructure ranges
that need source protection. Source-match opt-in remains required. Scope policy
fields are:

| Field | Default and limit |
| --- | --- |
| `min_source_prefix_length` | IPv4 24, IPv6 64; require that prefix length or more specific |
| `max_source_only_ttl_seconds` | 60; configurable from 1 to 300, subject to stricter existing TTL limits |
| `max_source_only_active` | 10 active rules per POP and scope identity; existing quotas also apply |
| `infrastructure_prefixes` | Empty list; canonical same-family network CIDRs |

An extension cannot exceed the short source-only lifetime ceiling measured
from original creation. Source-only supports discard and police; marking and
redirects remain refused. Global source-only is refused.

`POST /v1/vpn/source-rules/preview` accepts this body without confirmation;
creation through `/v1/vpn/source-rules` requires the explicit confirmation:

```json
{
  "scope": "TRANSIT",
  "src_prefix": "198.51.100.0/24",
  "protocol": "udp",
  "action": "discard",
  "ttl_seconds": 30,
  "reason": "Confirmed remote attack sources",
  "confirm_destination_any": true
}
```

The preview displays `destination: any`. The CLI requires
`--source-only --src-prefix ... --scope ...`, an explicit TTL and
`--confirm-destination-any` for creation. Receiver validation of destination-less
rules varies by platform under [RFC 8955 section 6](https://www.rfc-editor.org/rfc/rfc8955.html#section-6)
and [RFC 9117](https://www.rfc-editor.org/rfc/rfc9117.html). The pilot must establish
router acceptance; controller encoding does not establish installation.

## Observe and upgrade

API responses, CLI output, dashboard detail and local inventory show scope
family, RD and RTs. Authenticated health reports fresh configured-family probes
as supported, unsupported or error. A transport/authentication error is not
an unsupported answer. The bounded `prefixd_flowspec_active_by_family` gauge
counts desired ordinary mitigations by routing family; it does not count
installed router rules and has no arbitrary RD/RT labels. Speaker acceptance,
withdrawal and unknown-route logs include `routing_scope` and `route_targets`;
acceptance still means the local RPC boundary.

Scope RT changes replace a plain or same-owner leased payload on its existing
key. Guarded payload changes require withdrawal of the held revision, confirmed
absence and fresh admission. RD changes create another key; retire the original
explicitly. Configuration changes do not perform those transitions for you.
One owner's lease and speaker key cap span all its RDs and families.

Drain VPN mitigations, diversions and pending withdrawals on the original
speaker target before downgrading the controller. A rolled-back or unreachable
speaker cannot authorize VPN mutation or replay; prefixd retains intent/error
state and never converts it to global FlowSpec. TTL expiry still needs the
running controller for unleased rules. With leased rules, expiry is owner-wide
and depends on renewal stopping.

This workflow establishes controller intent and speaker behavior. No IOS XR
installation, wrong-RT isolation or traffic enforcement is claimed. Record
separate platform/release/action receipts for the ASR9901 pilot and later
platforms. See [ADR 032](../adr/032-vpn-flowspec-scope.md) and the
[backend evidence boundaries](../reference/speaker-backends.md).
