# Blackhole host routes under RPKI at FRR — 2026-10-20 UTC

This receipt extends the [FRR blackhole receipt](blackhole-frr-2026-10-19.md)
with RPKI origin validation, at the speaker and at the receiving router. It
asks one question: does a prefixd ban still reach the RTBH peer when the
blackhole host route is RPKI-Invalid for its origin? Every claim is scoped to
the versions and topology below. It is control-plane and FIB evidence inside
an FRR container: no packets were forwarded, and it says nothing about any
other router or speaker.

## Setup

| Item | Value |
| --- | --- |
| Run | 2026-10-20T21:30:43Z, local, Linux 7.0.0-30-generic, containerlab 0.74.3, lab nodes pinned to eight CPUs |
| prefixd | 0.20.0, local image `sha256:0977fe14515521ad519c78c1d9c1b3c810b0e5c36d192e7a2bf6ee92841962d8` built from commit `bb9658c`, which adds the add-outcome audit and `allow_missing` deletes |
| Speaker | rustbgpd 0.79.0, `ghcr.io/lance0/rustbgpd:0.79.0@sha256:b2054d0ce98f3c8299b8de5be1920cd88a1ab2c85e02766927e487be0c60f8ff` |
| Router | FRR 10.7.1, `quay.io/frrouting/frr:10.7.1@sha256:e995beaa50fdc9edb35eadcfefa29b7f062cc06f2b812613789b68fa541554d2`, bgpd loaded with `-M rpki` |
| RTR cache | StayRTR 0.6.4, `rpki/stayrtr@sha256:cdb93c0b661d97179a5525e00caf7d9e693a04da3b9002f7e24bebb194d9a77b`, serving [`rpki-vrps.json`](../../../lab/interop/configs/rpki-vrps.json): 203.0.113.0/24 maxLength 24 and 2001:db8:113::/48 maxLength 48, both AS 65010 |
| Topology | [`frr-rustbgpd.clab.yml`](../../../lab/interop/frr-rustbgpd.clab.yml): the 2026-10-19 topology plus the `rtr` node; rustbgpd (AS 65010) and FRR (AS 65002) both use the cache |
| Speaker export | [`rustbgpd.toml`](../../../lab/interop/configs/rustbgpd.toml): the export chain is `reject-rpki-invalid` (deny `match_rpki_validation = "invalid"`), then `distribute-mitigation`, for the whole run |
| Driver | [`blackhole_frr.py`](../../../lab/interop/blackhole_frr.py) through `run-frr.sh rustbgpd blackhole`; steps 09 to 13 are new |

The ROAs are the lab customer's own: they authorize AS 65010 for the
customer's aggregates only, so every `/32` and `/128` inside them is longer
than maxLength and RPKI-Invalid for AS 65010. rustbgpd's own table confirms
this: `rbgp rpki validate <prefix> 65010` returned `invalid` with
`authorizes: false` for both ban prefixes and the control prefix. Its cache
listing showed one IPv4 and one IPv6 VRP, connected.

## Results

All thirteen steps passed in one run. Steps 01 to 08 repeat the 2026-10-19
scenario on rustbgpd 0.79.0 with RPKI and the Invalid export filter active at
the speaker, and passed with the same expected states.

| Claim | IPv4 | IPv6 | Evidence |
| --- | --- | --- | --- |
| A ban passes a speaker export filter that drops Invalid | 203.0.113.53/32 discard | 2001:db8:113::53/128 discard | Step 09. rustbgpd stores both injected routes as `not_found`, not `invalid`: prefixd injects with an empty AS_PATH, and rustbgpd 0.79.0 takes the origin AS from the AS_PATH, so there is no origin to validate. Each route's audit entry recorded `created` |
| The speaker filter is live | 203.0.113.54/32 absent | — | Step 09 control: the same host route with BLACKHOLE, added with `rbgp rib add --as-path 65010`, was stored as `invalid` and never reached FRR, including 3 s after the ban routes arrived |
| FRR rates the received ban Invalid | Yes | Yes | Step 10: `rpkiValidationState: "invalid"` on the path from 10.0.0.1, AS_PATH `65010` |
| A ban survives an Invalid filter placed after the BLACKHOLE permit | discard | discard | Step 10: `route-map RTBH-IN-V4/V6 deny 15` with `match rpki invalid`, after `permit 10` that matches `65535:666` |
| **Negative control:** an Invalid filter ahead of the BLACKHOLE permit drops the ban | absent | absent | Step 11: `deny 5` with `match rpki invalid`; both prefixes left the BGP table, zebra and the kernel |
| Removing that filter restores the ban | discard | discard | Step 12 |
| Withdrawal | absent | absent | Step 13, API status `withdrawn` |
| Speaker-restart repairs are new routes | `created`, `created` | `created`, `created` | Step 04: the first add and the repair after the restart each audited `created`, because the restart lost the route |

## What this means for operators

- **At rustbgpd 0.79.0**, a speaker-side export filter that drops RPKI-Invalid
  routes does not drop prefixd's blackholes, because they carry no AS_PATH and
  are `not_found`. That rests on prefixd's empty AS_PATH and on how rustbgpd
  0.79.0 derives the origin; a speaker that rates local routes with its own AS
  as origin would rate them Invalid.
- **At a router that validates**, the ban is RPKI-Invalid, because the router
  sees the speaker's AS as origin. Any policy there that drops Invalid
  before it accepts BLACKHOLE drops every ban silently, while prefixd reports
  the add as accepted. Put the BLACKHOLE match ahead of the Invalid filter (or
  exempt the RTBH sessions), as in step 10.

## Not covered

- Other routers' default ROV behavior, and any packet forwarding.
- A rustbgpd export chain that matches Invalid together with BLACKHOLE, or
  per-neighbor chains. rustbgpd persists runtime policy changes to its config
  file, which this lab mounts read-only, so the speaker filter was fixed for
  the whole run and could not be toggled.
- Leased blackholes. This lab runs unleased manual blackholes, so it shows no
  `unchanged` re-add; the released-daemon and unit tests cover that.

## Rerun

```bash
just interop-frr-blackhole
# or, with an existing prefixd:interop image and pinned CPUs:
taskset -c 28-31,60-63 lab/interop/run-frr.sh rustbgpd blackhole
```

The receipt directory adds `rpki-speaker-caches.json`, and `receipt.json`
records the speaker's export chain, `rbgp rpki validate` output, stored
validation states, FRR's per-path RPKI state and the audited add outcomes.
