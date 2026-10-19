# Amplification FlowSpec rules at FRR — 2026-10-19 UTC

This receipt qualifies [ADR 028](../../adr/028-amplification-matches.md) slice 7:
prefixd `udp_amplification` rules, announced by rustbgpd and by GoBGP over IPv4
and IPv6 FlowSpec, received by FRR with the expected source-port (type 6),
packet-length (type 10) and fragment (type 12) components and actions. Every
claim below is scoped to the versions and topology listed here. It is
control-plane evidence in FRR's BGP table. FRR installed no filter for any
rule, no packets were forwarded, and it says nothing about any other router.

## Setup

| Item | Value |
| --- | --- |
| Runs | rustbgpd leg 2026-10-19T23:36:57Z (58 s); GoBGP leg 23:37:55Z (65 s). Local, Linux 7.0.0-30-generic, containerlab 0.74.3, lab nodes pinned to eight CPUs |
| prefixd | 0.20.0, local image `sha256:4867892c352a…` built from main `f2ca3d4` (#271) plus this change's lab files |
| Speakers | rustbgpd 0.78.0, `ghcr.io/lance0/rustbgpd:0.78.0@sha256:1082f37a562e8c5b3728b24294a40748559c8d9afa9c68688d4b934a4637d9c7`; GoBGP 4.10.0, `jauderho/gobgp:latest@sha256:42b8d0017237e388c55936efe1f23632365b24a31751f6e8815f93e12c4d18c2` |
| Router | FRR 10.7.1, `quay.io/frrouting/frr:10.7.1@sha256:e995beaa50fdc9edb35eadcfefa29b7f062cc06f2b812613789b68fa541554d2` |
| Topology | [`frr-rustbgpd.clab.yml`](../../../lab/interop/frr-rustbgpd.clab.yml) and [`frr-gobgp.clab.yml`](../../../lab/interop/frr-gobgp.clab.yml): one eBGP session over IPv4 (speaker AS 65010 at 10.0.0.1, FRR AS 65002 at 10.0.0.2) with IPv4 and IPv6 FlowSpec |
| prefixd settings | [`prefixd-rustbgpd.yaml`](../../../lab/interop/configs/prefixd-rustbgpd.yaml) and [`prefixd-gobgp.yaml`](../../../lab/interop/configs/prefixd-gobgp.yaml): `max_ports: 8`, `allow_fragment_match: true`, `allow_packet_length_match: true`, built-in reflector-port library |
| Playbooks | [`playbooks.yaml`](../../../lab/interop/configs/playbooks.yaml): `udp_amplification` discards `src_ports: from_event` and polices `fragment: non_first` at 20 Mbit/s (ADR 028's shipped example, 300 s TTL). `udp_amplification_length` adds `packet_length: {min: 1000, max: 65535}` with a 30 s TTL; events that carry `top_dst_ports` select it (`require_top_ports`) |
| Driver | [`amplification_frr.py`](../../../lab/interop/amplification_frr.py) through `just interop-frr-amplification`. Each ban is a FastNetMon-shaped `POST /v1/events` with `"vector": "udp_amplification"` and `top_src_ports`; each unban is the same event ID with `"action": "unban"` |

After each step the driver waits until FRR's IPv4 and IPv6 FlowSpec tables
hold exactly the expected rules. It reads `show bgp <afi> flowspec json` and
`show bgp <afi> flowspec detail json`. Each path must be FRR's valid best path
from 10.0.0.1. A rule matches on every component FRR reports (destination,
protocol, source ports, packet length, fragment and any other) and on the
traffic-rate action, so a missing or extra component is a mismatch. The
table and detail views must agree on destination, protocol and destination
port; the narrowing components are compared from the detail view, and both
views are kept in the receipt.

FRR 10.7.1 renders the new components this way (whitespace removed by the
oracle):

| Component | prefixd intent | FRR JSON |
| --- | --- | --- |
| Source port (6) | `src_ports: [123, 11211]` | `"srcp": "= 123 , = 11211 "` |
| Packet length (10) | `packet_length: {min: 1000, max: 65535}` | `"pktlen": ">= 1000 , <= 65535 "` |
| Fragment (12) | `fragment: non_first` | `"pktfrag": "= 2"` (IsF, bit 0x02, with the match bit) |
| Discard | `action: discard` | `"ecomlist": "FS:rate 0.000000"` |
| Police 20 Mbit/s | `action: police, rate_bps: 20000000` | `"ecomlist": "FS:rate 2500000.000000"` |

FRR prints each value's comparison operator but not the AND bit
(`bgp_flowspec_op_decode` in FRR 10.7.1). The receipt therefore cannot tell
`>=1000 AND <=65535` from `>=1000 OR <=65535`, or an OR list of source ports
from an AND list. The speaker encoding of those bits is covered by ADR 028
slice 2's codec and released-daemon tests, not by this receipt.

## Results

Both legs passed all nine steps with the same outcomes. An earlier pair of
runs at 23:29Z and 23:30Z, with the same image and without the step 03 check
of the NOTIFICATION code, passed with the same outcomes.

| Claim | IPv4 | IPv6 | Evidence |
| --- | --- | --- | --- |
| FRR receives the source-port rule with discard | 203.0.113.60/32 | 2001:db8:113::60/128 | Step 01: an event with `top_src_ports: [11211, 123]`. Table key `to 203.0.113.60/32 proto = 17  srcp = 123 , = 11211 /15`, action `FS:rate 0.000000`; IPv6 `to 2001:db8:113::60/128/off 0 proto = 17  srcp = 123 , = 11211 /28` |
| FRR receives the IsF fragment rule with police | Yes | Yes | Step 01: `to 203.0.113.60/32 proto = 17  pktfrag = 2/12` and `to 2001:db8:113::60/128/off 0 proto = 17  pktfrag = 2/25`, action `FS:rate 2500000.000000` |
| FRR receives the source-port rule with packet length | 203.0.113.63/32 | 2001:db8:113::63/128 | Step 08: `to 203.0.113.63/32 proto = 17  srcp = 11211  pktlen >= 1000 , <= 65535 /20` and `to 2001:db8:113::63/128/off 0 proto = 17  srcp = 11211  pktlen >= 1000 , <= 65535 /33`, discard |
| A 20-port report reaches FRR as four source-port rules plus one fragment rule, at `max_ports: 5` | Yes | Yes | Step 05: `srcp = 17 , = 19 , = 53 , = 111 , = 123`, `= 137 , = 161 , = 389 , = 427 , = 520`, `= 1434 , = 1900 , = 3283 , = 3702 , = 5353`, `= 5683 , = 10001 , = 11211 , = 33848 , = 37810`, and `pktfrag = 2`, per family. prefixd's response listed five mitigation IDs per event, in playbook order |
| **Negative result:** at `max_ports: 8`, FRR resets the session | Yes | Yes | Step 03: see [Five-value limit](#five-value-limit) |
| Removed on detector unban | Yes | Yes | Steps 02 and 07: one unban per victim withdrew every rule from that event (2 and 5 per family); both tables empty |
| Removed on TTL expiry | Yes | Yes | Step 08: the 30 s rules were present, then absent 34.2 s after the events on both legs; all four API statuses `expired` |
| Returns after a speaker restart through prefixd repair | Yes | Yes | Step 06: `docker stop` emptied FRR; after `docker start` all ten rules returned, and `prefixd_reconciliation_repairs_total{status="success"}` rose by 10 |
| FRR installs a filter | No | No | See [Filter installation](#filter-installation) |

### Five-value limit

FRR 10.7.1 accepts at most five values in one numeric component
(`BGP_PBR_MATCH_VAL_MAX` in `bgpd/bgp_pbr.h`, checked by
`bgp_flowspec_op_decode` during NLRI validation). With prefixd's default
`max_ports: 8`, a 20-port report becomes source-port rules of 8, 8 and 4 values.
In step 03 FRR refused the 8-value rules as malformed and reset the session:

- FRR `show bgp neighbors 10.0.0.1 json`: `"lastResetDueTo": "BGP Notification send"`,
  `"lastErrorCodeSubcode": "0309"`,
  `"lastNotificationReason": "UPDATE Message Error/Optional Attribute Error"`,
  `connectionsDropped` 0 to 1.
- rustbgpd log: `"BGP NOTIFICATION","peer":"10.0.0.2","direction":"received","code":3,"subcode":9`.
- GoBGP log: `"msg":"Peer Down" ... "Reason":"notification-received code 3(update) subcode 9(optional attribute error)"`.
- No poll during the step saw a rule with more than five source ports at FRR.

A reset drops every route on the session, including unrelated rules, and the
speaker re-sends the same NLRI on reconnect. In an earlier exploratory
rustbgpd run (image built from main `cbd0d41`, same FRR), the session reset
again about 10 and 30 s after the first, until the rules were withdrawn. The step then unbanned both victims, and
the session came back with empty tables. The rest of the scenario restarted
prefixd with a copy of the configuration in which only `max_ports` was 5.

Operators peering prefixd's speaker with FRR 10.7.1 must keep
`guardrails.max_ports` at 5 or lower. FRR applies the check to every numeric
component, so destination-port lists are subject to it too; that was not
exercised here.

### Filter installation

The driver set `local-install eth1` under both FlowSpec address families at
runtime, before any rule arrived; the shared `frr.conf` is unchanged. FRR
then reported every rule `not installed in PBR`: the two-port discard and
fragment police rules of step 01, and the single-port, packet-length discard
and fragment police rules of step 08 (two rules per family in each step):

```text
BGP flowspec entry: (flags 0x418)
	Destination Address 203.0.113.63/32
	IP Protocol = 17
	Source Port = 11211
	Packet Length >= 1000 , <= 65535
	FS:rate 0.000000
	received for 00:00:00
	not installed in PBR
```

`show pbr ipset`, `show pbr iptable` and `show pbr rule` were empty, `ip rule`
and `ip -6 rule` showed only the kernel defaults, and the FRR image has no
`iptables`, `ip6tables`, `ipset` or `nft`. FRR's documentation says it installs
only discard and redirect, and only one value or one range per component. This
lab did not establish why the single-port discard rule was not installed. No
action is claimed as installed at FRR.

## Negative controls

- **Different source-port set.** After step 01 the driver compared FRR's
  rules against the expected set with the first rule's ports reduced to one.
  The oracle reported a mismatch, as it did for the expected set plus a
  never-announced rule (203.0.113.99 from port 123) and for the expected set
  without the fragment rule.
- **Never-announced rules are absent.** The exact-set comparison after every
  step fails on any rule FRR holds that the step did not expect. Steps 02, 03,
  07, 08 and 09 required both tables to be empty.
- **Widened rule.** The released speakers cannot be made to drop a component,
  so `lab/interop/test_amplification_frr.py` edits captured FRR output instead.
  Removing `srcp`, `pktlen` or `pktfrag` from a rule, changing a component,
  adding `dstp`, or swapping the two actions is rejected. With the oracle
  patched to ignore every component except destination, protocol and
  destination port, those tests fail, as does the test on the unedited
  capture.
- **Fragment opt-in.** Step 09 ran a second prefixd with a copy of the running
  configuration in which only `allow_fragment_match` was false. It exited with
  status 1 before serving:
  `Error: playbooks.yaml: playbook[1] ("udp_amplification_length") step[0] rule[1]: fragment needs guardrails.allow_fragment_match: true; playbook[2] ("udp_amplification") step[0] rule[1]: fragment needs guardrails.allow_fragment_match: true`.
  The running controller, with the flag true, is the accepting control. FRR's
  tables stayed empty.

## Behavior that differed from ADR 028's assumptions

- **The default `max_ports: 8` is not usable with FRR 10.7.1.** ADR 028's FRR
  row says FRR "installs one value or one range"; its receive path refuses more
  than five values and resets the session. This is the five-value limit above.
- **FRR does not show the AND bit**, so this receipt proves operators and values
  per component, not how they combine.
- **FRR installed nothing**, including a single-port discard rule with
  `local-install` set.
- **Detector unban logs a warning.** Each unban logged `failed to insert unban
  event` (duplicate `events_source_external_event_id_key`) because it reuses
  the ban's external event ID. The withdrawal itself succeeded and was audited.

## Rerun

```bash
just interop-frr-amplification            # both legs; or: just interop-frr-amplification gobgp
# or, with an existing prefixd:interop image and pinned CPUs:
taskset -c 28-31,60-63 lab/interop/run-frr.sh rustbgpd amplification
```

Receipts land in `target/interop/frr-<speaker>-amplification-<UTC stamp>/` with
`receipt.json`, `summary.md`, `commands.log`, the raw FRR JSON before and after
each step, the `local-install` text views and neighbor state under `frr/`, and
container logs. The lab always destroys itself. CI does not run this scenario;
the Interop workflow runs the FlowSpec legs, which share `frr.conf`,
`playbooks.yaml` and the prefixd lab configurations. Both FlowSpec legs (8/8)
and the rustbgpd blackhole scenario (8/8) passed again with this change at
23:31Z.
