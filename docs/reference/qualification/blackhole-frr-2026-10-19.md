# Blackhole host routes at FRR — 2026-10-19 UTC

This receipt qualifies [ADR 027](../../adr/027-blackhole-mitigations.md) slice 7:
prefixd manual blackholes, announced by rustbgpd over IPv4 and IPv6 unicast,
received and installed as discard by FRR. Every claim below is scoped to the
versions and topology listed here. It is control-plane and FIB evidence inside
an FRR container: no packets were forwarded, and it says nothing about any
other router.

## Setup

| Item | Value |
| --- | --- |
| Run | 2026-10-19T21:25:48Z, local, Linux 7.0.0-30-generic, containerlab 0.74.3, lab nodes pinned to eight CPUs |
| prefixd | 0.20.0, local image `sha256:7cd08af4c52db22364c99592370d2bf109ccff2e785e69c1873770f6ae7e6d64` built from main `7ee9413` sources |
| Speaker | rustbgpd 0.78.0, `ghcr.io/lance0/rustbgpd:0.78.0@sha256:1082f37a562e8c5b3728b24294a40748559c8d9afa9c68688d4b934a4637d9c7` |
| Router | FRR 10.7.1, `quay.io/frrouting/frr:10.7.1@sha256:e995beaa50fdc9edb35eadcfefa29b7f062cc06f2b812613789b68fa541554d2` |
| Topology | [`lab/interop/frr-rustbgpd.clab.yml`](../../../lab/interop/frr-rustbgpd.clab.yml): one eBGP session over IPv4 (speaker AS 65010 at 10.0.0.1, FRR AS 65002 at 10.0.0.2) carrying IPv4/IPv6 FlowSpec and IPv4/IPv6 unicast |
| prefixd blackhole settings | next hops 192.0.2.66 and 2001:db8:ffff::66, extra community `65010:666`; BLACKHOLE `65535:666` is always added |
| FRR import policy | [`frr.conf`](../../../lab/interop/configs/frr.conf): route-maps `RTBH-IN-V4`/`RTBH-IN-V6` permit only routes matching `65535:666` and set the next hop to 192.0.2.1 or 2001:db8:ffff::1, which are static `blackhole` routes; everything else is denied |
| Driver | [`blackhole_frr.py`](../../../lab/interop/blackhole_frr.py) through `just interop-frr-blackhole`; an Admin session creates each blackhole with `POST /v1/mitigations` and `"action": "blackhole"` |

prefixd's configured next hops deliberately do not resolve at FRR. Only the
route-map makes a route discard, which is what the negative control relies on.

For each host route the driver reads three views and reduces them to a state:

- `show bgp <afi> unicast <prefix> json` (FRR's BGP table),
- `show ip[v6] route <prefix> json` (zebra's RIB, including FIB flags),
- `ip -j route show exact <prefix>` in the FRR container (the kernel FIB).

**discard** means exactly one valid best path from 10.0.0.1 carrying exactly
`65010:666`, `65535:666` and `no-export`; one selected, installed zebra route
whose FIB next hops are all blackhole; and one kernel route of type
`blackhole`. **absent** means none of the three views has the prefix.
**stale** is discard with FRR holding the path as a Graceful Restart helper.
Anything else is **other**.

## Results

All eight steps passed. The lab ran in 86 s, after a 212 s pinned image build.
A confirmation run at 22:01:53Z, with the same image, the final harness and
containers pinned by `docker update`, passed all eight steps with the same
states in 87 s.

| Claim | IPv4 | IPv6 | Evidence |
| --- | --- | --- | --- |
| FRR receives the host route with the expected communities | 203.0.113.50/32 | 2001:db8:113::50/128 | Step 01: both `POST /v1/mitigations` returned `201`, and each response's frozen `blackhole` object had the configured next hop and `["65010:666", "65535:666"]`. FRR's path is valid best from 10.0.0.1 with community string `65010:666 blackhole no-export` |
| FRR installs it as discard | Yes | Yes | Step 01: BGP next hop rewritten to 192.0.2.1 or 2001:db8:ffff::1, zebra route `bgp`, installed, resolved recursively to a `blackhole` FIB next hop; kernel `{"type": "blackhole", "dst": "203.0.113.50", "protocol": "bgp"}` and `{"type": "blackhole", "dst": "2001:db8:113::50", "dev": "lo", "protocol": "bgp"}` |
| Removed on withdrawal | Yes | Yes | Step 05: `POST /v1/mitigations/{id}/withdraw`; absent at FRR in 0.3 s; API status `withdrawn` |
| Removed on TTL expiry | Yes | Yes | Step 06: 203.0.113.51 and 2001:db8:113::51 with `ttl_seconds: 15` were discard, then absent 18.5 s after creation; API status `expired` |
| Returns after a speaker restart through prefixd repair | Yes | Yes | Step 04: see [Speaker restart](#speaker-restart). The `prefixd_reconciliation_repairs_total{status="success"}` counter rose by 2 |
| **Negative case:** persists after prefixd stops while the speaker stays up | Persists | Persists | Step 07: see [Controller stopped](#controller-stopped-known-gap) |

### Speaker restart

`docker stop` on the speaker ended the session. FRR kept both routes as
**stale** discard: valid, `"stale": true`, still installed in zebra and the
kernel as blackhole. This is FRR acting as a Graceful Restart helper, as ADR 027
anticipates. After `docker start`, the driver recorded each state change:

| Seconds after start | 203.0.113.50/32 | 2001:db8:113::50/128 |
| --- | --- | --- |
| 0.4 | other | absent |
| 1.2 | discard | discard |

Once the new session's End-of-RIB arrived, FRR flushed the stale paths. Until
prefixd's reconciliation (5 s interval in the lab) re-added the routes, both
host routes were briefly not installed as discard. The window was under one
second in this run. Two other passing runs of the same scenario saw both
routes absent for about 1.6 s (from 1.3 s to 2.9 s and from 1.1 s to 2.7 s
after start). The window depends on when the reconciliation tick lands. How long FRR retains stale routes while the speaker stays down is
bounded by the Graceful Restart timers and was not measured here.

### Controller stopped (known gap)

A manual blackhole is unleased. 203.0.113.52/32 and 2001:db8:113::52/128 were
created with `ttl_seconds: 20` (latest `expires_at` 21:26:39Z). prefixd was then
stopped with `SIGTERM` while rustbgpd stayed up. 30 s after `expires_at`, both
routes were still **discard** at FRR. Nothing expires a manual blackhole without
the controller; this is the gap ADR 027 records under *Controller stopped,
speaker up*. When prefixd started again it expired both, and they were absent at
FRR 1.6 s after the restart was issued, with API status `expired`. Monitor
controller availability independently of BGP health.

## Negative controls

- **Absence is detected.** 203.0.113.99/32 and 2001:db8:113::99/128 were never
  announced. The baseline and step 01 classify both as absent, as did the final
  check.
- **Discard depends on the route-map.** Step 02 removed both import route-maps
  and ran `clear bgp <afi> unicast 10.0.0.1 soft in`. The discard check then
  failed for both families, and the step passes only on that failure:
  - IPv4 was received with rustbgpd's next hop 10.0.0.1. It was installed as an
    ordinary route via `eth1`, and the kernel showed `gateway 10.0.0.1 dev eth1`,
    not `blackhole`.
  - IPv6 was received with next hop 2001:db8:0:1::1, which does not resolve.
    The path was not valid, and zebra and the kernel had no route.

  Step 03 restored the route-maps, and both routes were discard again.
- **Oracle unit tests.** `lab/interop/test_blackhole_frr.py` rejects a missing
  view, wrong or extra communities, a foreign peer, an invalid or duplicated
  path, an uninstalled zebra route and a route installed via the link. It runs
  without a lab, with every `just interop-frr*` recipe.

## Behavior that differed from ADR 027's assumptions

- **FRR adds `no-export`.** FRR 10.7.1 adds `NO_EXPORT` to a received route
  carrying BLACKHOLE (RFC 7999 section 3.2). prefixd injects no `NO_EXPORT`,
  as the ADR requires. The prefixd response lists only `65010:666` and
  `65535:666`, and the addition is FRR's own.
- **IPv6 over an IPv4 session needs `local_ipv6_nexthop`.** Without that rustbgpd
  neighbor setting, rustbgpd 0.78.0 accepted the IPv6 `AddPath` but sent no
  IPv6 unicast route to FRR over the IPv4-transport session, and logged no
  warning. rustbgpd's changelog documents this rule for eBGP IPv6 next hops:
  `local_ipv6_nexthop`, then the local socket address, otherwise suppress. The
  lab sets `local_ipv6_nexthop = "2001:db8:0:1::1"`, and FRR then received
  2001:db8:0:1::1 as the IPv6 next hop. For IPv4, rustbgpd sent next hop
  10.0.0.1, its own session address, not prefixd's injected 192.0.2.66. This
  matches the ADR's warning that an eBGP router must not rely on the injected
  value.
- **Graceful Restart keeps the blackhole through a speaker outage.** FRR kept
  the stale discard routes while the speaker was down, instead of withdrawing
  them. A short gap opened only after reconnection, between End-of-RIB and
  prefixd's repair.

## Rerun

```bash
just interop-frr-blackhole
# or, with an existing prefixd:interop image and pinned CPUs:
taskset -c 28-31,60-63 lab/interop/run-frr.sh rustbgpd blackhole
```

The receipt lands in `target/interop/frr-rustbgpd-blackhole-<UTC stamp>/` with
`receipt.json`, `summary.md`, `commands.log`, the raw BGP, zebra and kernel
JSON for each prefix and step under `frr/`, and container logs. The lab always
destroys itself. CI does not run this scenario yet; the Interop workflow runs
the FlowSpec legs, which share `frr.conf`.
