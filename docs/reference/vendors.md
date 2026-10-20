# Vendor Capability Matrix

FlowSpec support varies significantly across router vendors, platforms, and software versions. This page documents what has been tested with prefixd and known limitations.

The Juniper and Arista reports below used **GoBGP**, not rustbgpd. Selecting
the rustbgpd default does not extend these historical reports to that speaker or
prove forwarding-plane enforcement. FRR has dated receipts for each speaker from
the [FlowSpec interop lab](../../lab/README.md#flowspec-interop-lab-maintained).
Requalify your exact speaker, router version, address family and action, and
retain dated command and result receipts. FRR RIB receipt alone is
control-plane evidence.

## Support Matrix

| Capability | Juniper (Junos/Evolved) | Arista (EOS) | Cisco (IOS-XR) | Nokia (SR OS) | FRR |
|---|---|---|---|---|---|
| **BGP FlowSpec IPv4** | Verified | Verified | Expected | Expected | Verified |
| **BGP FlowSpec IPv6** | Verified | Expected | Expected | Expected | Verified |
| **Discard action** | Verified | Verified | Expected | Expected | Verified |
| **Rate-limit (police) action** | Verified | Not working (under investigation) | Expected | Expected | Verified |
| **Redirect-to-VRF** | Supported (untested) | Supported (untested) | Supported (untested) | Supported (untested) | Not supported |
| **Redirect-to-IP** | Supported (untested) | Supported (untested) | Supported (untested) | Not supported | Not supported |
| **Reconciliation (re-announce)** | Verified | Expected | Expected | Expected | Verified |
| **Withdraw** | Verified | Expected | Expected | Expected | Verified |
| **TTL expiry** | Verified | Expected | Expected | Expected | Verified |
| **Multiple FlowSpec rules** | Verified | Expected | Expected | Expected | Verified |
| **Destination port matching** | Verified | Verified | Expected | Expected | Verified |
| **Protocol matching** | Verified | Verified | Expected | Expected | Verified |
| **Source port matching** | Expected | Expected | Expected | Expected | Verified, at most 5 ports per rule ([receipt](qualification/amplification-frr-2026-10-19.md)) |
| **Packet length matching** | Expected | Expected (needs a TCAM length field) | Expected | Expected | Verified ([receipt](qualification/amplification-frr-2026-10-19.md)) |
| **Non-first fragment matching** | Expected (enhanced-ip MPCs) | Expected (IPv4 only) | Expected (IPv4 only) | Expected | Verified, IPv4 and IPv6 ([receipt](qualification/amplification-frr-2026-10-19.md)) |

The last three rows are the [ADR 028](../adr/028-amplification-matches.md)
amplification components. They come from vendor documentation, summarized in
[ADR 028 section 7](../adr/028-amplification-matches.md#7-router-reality). Only
FRR has a prefixd receipt for them: the
[FRR amplification receipt](qualification/amplification-frr-2026-10-19.md)
shows FRR 10.7.1 receiving each component with the expected action from
rustbgpd 0.78.0 and GoBGP 4.10.0, in both families. FRR accepts at most five
values per component: a rule with more makes it reset the session, so keep
`guardrails.max_ports` at 5 or lower toward FRR. FRR installed none of these
rules as a filter.
prefixd keeps source-port and fragment matches in separate rules, which EOS
requires, and matches only IsF (non-first fragments), the one fragment bit every
documented platform supports for IPv4. Expect IOS-XR and EOS to reject or
ignore the IPv6 fragment rule. FRR installs filters only for discard and
redirect actions.

The FRR column is control-plane receipt only. It holds for rustbgpd 0.77.0,
0.78.0 and 0.79.0 and for GoBGP 4.10.0 with FRR 10.7.1 (see [FRR](#frr--verified-control-plane)).
The Nokia column is SR OS, which is untested. SR Linux does not support FlowSpec
(see [SR Linux](#nokia-sr-linux--not-supported)).

**Legend:**
- **Verified** — Tested end-to-end with prefixd in a lab or production environment
- **Expected** — Vendor documentation indicates support; not yet tested with prefixd
- **Not working** — Tested but not functioning; investigation ongoing
- **Not supported** — Vendor/platform does not support this feature
- **Supported (untested)** — Vendor supports it, but prefixd does not implement this action yet

## Tested Environments

### Juniper — Verified

| Detail | Value |
|---|---|
| Platform | PTX10002 (cJunosEvolved container) |
| Software | Junos Evolved 25.4R1.13-EVO |
| Lab method | Containerlab + cJunosEvolved |
| BGP session | eBGP with GoBGP (AS 65010 ↔ AS 65003) |
| AFI-SAFI | IPv4 FlowSpec only (ipv4-flowspec) |

**Verified operations:** Event ingestion → policy evaluation → GoBGP announce → Junos `inetflow.0` → rate-limit/discard applied → withdraw → rule removed → TTL expiry → automatic withdrawal.

**Known quirks:**
- GoBGP must advertise **only** `ipv4-flowspec` AFI-SAFI to Junos. If `inet-unicast` is also advertised, Junos rejects the session with Open Message Error subcode 7.
- The `no-validate` option is required on the import policy neighbor to accept FlowSpec without validation against unicast routes.
- "License key missing; requires 'BGP' license" warning appears on cJunosEvolved — this is cosmetic only, FlowSpec still works.
- The `FXP0ADDR` management IP token in cJunos startup config must be spelled exactly `FXP0ADDR` (not `FXP0ADDRESS`).

**Reference configuration:**
```junos
set policy-options policy-statement FLOWSPEC-IMPORT term accept-all then accept
set routing-options flow validation
set routing-options flow term-order standard
set protocols bgp group FLOWSPEC type external
set protocols bgp group FLOWSPEC import FLOWSPEC-IMPORT
set protocols bgp group FLOWSPEC peer-as 65010
set protocols bgp group FLOWSPEC neighbor 10.10.1.10 family inet flow no-validate FLOWSPEC-IMPORT
```

### Arista — Partially Verified

| Detail | Value |
|---|---|
| Platform | 7280SR2A (production hardware) |
| Software | EOS 4.33.5M |
| BGP session | eBGP with GoBGP |
| Reported by | Community user (Neptune Networks) |

**Verified operations:** FlowSpec announce, discard action, withdraw, destination port matching, protocol matching.

**Not working:** Rate-limit (police) action — rules are accepted by EOS but traffic policing is not applied. Under investigation; may be a platform-specific hardware table limitation on the 7280SR2A or an EOS configuration requirement.

**Known quirks:**
- FlowSpec must be explicitly enabled per address family (`address-family flow-spec ipv4`).
- TCAM capacity varies by platform and profile. Check `show hardware capacity` if rules are silently dropped.
- Some older EOS versions (< 4.20) do not support FlowSpec at all.

**Reference configuration:**
```eos
router bgp 65000
  neighbor 10.10.1.10 remote-as 65010
  !
  address-family flow-spec ipv4
    neighbor 10.10.1.10 activate
  !
  address-family flow-spec ipv6
    neighbor 10.10.1.10 activate
```

### FRR — Verified (control plane)

| Detail | Value |
|---|---|
| Platform | Container (native Linux), `quay.io/frrouting/frr:10.7.1`, digest-pinned |
| Lab method | Containerlab 0.74.3, [`lab/interop/`](../../lab/interop/) |
| BGP session | eBGP, speaker AS 65010 ↔ FRR AS 65002; IPv4 and IPv6 FlowSpec, plus IPv4 and IPv6 unicast for blackholes with rustbgpd |
| Driver | prefixd's HTTP API (bearer auth); FRR `show bgp ipv4\|ipv6 flowspec [detail] json` |

Receipts, attributed per speaker:

| Date (UTC) | Speaker | prefixd | Where | Result |
|---|---|---|---|---|
| 2026-10-18 | rustbgpd 0.77.0 (released image, digest-pinned) | 0.19.1, commit `dfaa4e08e0ed` | Local run, Linux 7.0.0-30 | Pass, 8/8 steps |
| 2026-10-18 | GoBGP 4.10.0 (`jauderho/gobgp` digest pinned by CI) | 0.19.1, commit `dfaa4e08e0ed` | Local run, Linux 7.0.0-30 | Pass, 8/8 steps |
| 2026-10-18 | rustbgpd 0.78.0 (released image, digest-pinned) | 0.19.1, commit `c3d86201e341` | Local run, Linux 7.0.0-30 | Pass, 8/8 steps |
| 2026-10-20 | rustbgpd 0.79.0 (released image, digest-pinned) | 0.20.0, commit `ad568df713cd` | Local run, Linux 7.0.0-30 | Pass, 8/8 steps |
| 2026-10-18 | rustbgpd 0.77.0 | 0.19.1, PR merge commit `1810bdb595e6` | [Interop run 39161305632](https://github.com/lance0/prefixd/actions/runs/39161305632), ubuntu-latest, Linux 6.17.0-1022-azure | Pass, 8/8 steps |
| 2026-10-18 | GoBGP 4.10.0 | 0.19.1, PR merge commit `1810bdb595e6` | [Interop run 39161305632](https://github.com/lance0/prefixd/actions/runs/39161305632), ubuntu-latest, Linux 6.17.0-1022-azure | Pass, 8/8 steps |

Each run asserted the exact FRR rule set (destination, protocol, destination
port and `FS:rate` traffic-rate action) after each step: manual discard, manual
police (8 Mbit/s as `FS:rate 1000000.000000`), a detector `udp_flood` event
policed by playbook (`FS:rate 625000.000000`), operator withdrawal, 15 s TTL
expiry, a speaker stop and start restored by prefixd reconciliation (two
repairs counted), an IPv6 `/128` discard, and a final withdrawal of everything.
CI repeats both legs in the [Interop workflow](../../.github/workflows/interop.yml)
and keeps each run's receipt as an artifact.

Blackhole host routes ([ADR 027](../adr/027-blackhole-mitigations.md)) have a
separate [FRR blackhole receipt](qualification/blackhole-frr-2026-10-19.md):
rustbgpd 0.78.0 to FRR 10.7.1 over unicast, with an import route-map that
rewrites BLACKHOLE routes to a static discard next hop. It covers FRR's BGP
table, zebra RIB and the container's kernel FIB, not packet forwarding.

Amplification rules ([ADR 028](../adr/028-amplification-matches.md)) have a
separate [FRR amplification receipt](qualification/amplification-frr-2026-10-19.md):
rustbgpd 0.78.0 and GoBGP 4.10.0 to FRR 10.7.1, IPv4 and IPv6. FRR received
source-port discard rules, with and without a packet-length range, and IsF
fragment police rules, with the exact components. They were removed on
detector unban and TTL expiry and restored by prefixd repair after a speaker
restart. It is BGP-table evidence only.

**Known quirks:**
- FRR 10.7.1 accepts at most five values in one FlowSpec component. A rule with more (prefixd's earlier default `max_ports: 8` allowed eight source ports; the default is now 5) makes FRR send NOTIFICATION 3/9 and reset the session, dropping every route on it.
- FRR's FlowSpec text and JSON omit the AND bit, so `>=1000 AND <=65535` and an OR list render alike.
- With `local-install` set at runtime, FRR 10.7.1 in the lab container still reported every amplification rule `not installed in PBR`.
- FRR FlowSpec support is control-plane only by default — it receives and installs routes in the BGP table but does not program iptables/nftables rules without additional configuration. The lab output shows `not installed in PBR`.
- FRR renders discard as `FS:rate 0.000000` and IPv6 destinations with an offset, for example `2001:db8:113::10/128/off 0`.
- Useful for protocol-level testing but not for dataplane enforcement without extra setup.

### Cisco IOS-XR — Not Yet Tested

| Detail | Value |
|---|---|
| Target platforms | ASR 9000, NCS 5500/5700 |
| Expected software | IOS-XR 6.5+ |
| Lab method | XRd container (planned) |

**Expected reference configuration:**
```cisco
router bgp 65000
  neighbor 10.10.1.10
    remote-as 65010
    address-family ipv4 flowspec
```

**Known considerations (from vendor docs):**
- FlowSpec validation against unicast routes is enabled by default; may need `flowspec validation disable` depending on topology.
- `hw-module profile tcam` adjustments may be needed on NCS platforms.
- Rate-limit actions use QoS policy maps internally.

### Nokia SR OS — Expected (untested)

| Detail | Value |
|---|---|
| Target platforms | 7750 SR |
| Expected software | SR OS 19+ |

Untested: a lab run needs a licensed SR-SIM image from Nokia, which this
project does not have.

**Known considerations (from vendor docs):**
- FlowSpec is configured under `configure router bgp group <name> family flow-ipv4`.
- Rate-limit actions are supported via filter policies.

### Nokia SR Linux — Not supported

SR Linux 25.10.1 has no BGP FlowSpec address family. This was probed on
2026-10-18 with [`lab/interop/srlinux-probe.clab.yml`](../../lab/interop/srlinux-probe.clab.yml):
SR Linux `ghcr.io/nokia/srlinux:25.10.1` (7220 IXR-D2L) peered over eBGP with
released rustbgpd 0.77.0. rustbgpd offered `ipv4_unicast`, `ipv4_flowspec` and
`ipv6_flowspec`.

- The CLI rejects FlowSpec families at the BGP and group level:

  ```text
  # set / network-instance default protocols bgp afi-safi ipv4-flowspec admin-state enable
  Error: Failed to parse value 'ipv4-flowspec' for key 'afi-safi-name' (node 'afi-safi') - Invalid value "ipv4-flowspec": Must be ipv4-unicast|ipv6-unicast|evpn|route-target
  # set / network-instance default protocols bgp group prefixd afi-safi ipv6-flowspec admin-state enable
  Error: Failed to parse value 'ipv6-flowspec' for key 'afi-safi-name' (node 'afi-safi') - Invalid value "ipv6-flowspec": Must be ipv4-unicast|ipv6-unicast|evpn|route-target
  ```

- The YANG base `srl_nokia-comm:bgp-address-family` in the image defines only
  `ipv4-unicast`, `ipv6-unicast`, `l3vpn-ipv4-unicast`, `l3vpn-ipv6-unicast`,
  `ipv4-labeled-unicast`, `ipv6-labeled-unicast`, `evpn`, `ipv4-mvpn`,
  `ipv6-mvpn`, `route-target`, `srte-policy-ipv4`, `srte-policy-ipv6` and
  `link-state`.
- Capability negotiation: the session established, and rustbgpd reported
  `Negotiated Families: ipv4_unicast`. SR Linux listed
  `Cap Sent/Recv: ROUTE_REFRESH 4-OCTET_ASN MP_BGP GRACEFUL_RESTART`.
- With a discard rule for 203.0.113.10/32 UDP/53 in rustbgpd's local FlowSpec
  table, `rbgp flowspec advertised 10.0.0.2 -a ipv4_flowspec` returned
  `No FlowSpec routes`. SR Linux reported 0 received BGP routes.

The probe is not a CI leg because there is nothing to install.

## Testing Your Router

Start with the [quickstart](../tutorials/quickstart.md) for the rustbgpd profile,
authentication and same-origin API access through `http://localhost`. Existing
databases retain their [speaker ownership binding](../how-to/upgrading.md#speaker-ownership-upgrade);
profile selection does not change it.

To investigate the historical GoBGP path on a **fresh, isolated** test deployment:

```bash
# Replace the documentation peer in configs/gobgp.conf before starting.
# GoBGP listens on BGP port 179, AS 65010; its RPC port is private.

# Start the explicit compatibility profile; do not enable rustbgpd alongside it.
docker compose --profile gobgp up -d --pull always --no-build

# Inspect local session and accepted FlowSpec RIB state.
docker compose exec gobgp gobgp neighbor
docker compose exec gobgp gobgp global rib -a ipv4-flowspec
docker compose exec gobgp gobgp global rib -a ipv6-flowspec
```

Create an administrator as described in the quickstart, using service
`prefixd-gobgp`, and sign in to the dashboard. Configure inventory and playbooks
for the test victim, then create and withdraw a test mitigation through the
authenticated UI. For detector ingestion, follow the
[API input and authentication reference](api.md), rather than sending an
unauthenticated request to the unpublished controller port.

Check the rule on the receiving router, its action and removal independently:

```text
Juniper: show route table inetflow.0
Arista:  show bgp flow-spec ipv4
Cisco:   show bgp ipv4 flowspec
FRR:     show bgp ipv4 flowspec
```

For FRR, `just interop-frr` runs the maintained
[FlowSpec interop lab](../../lab/README.md#flowspec-interop-lab-maintained)
for both speakers and writes a dated receipt. The
[legacy Containerlab examples](../../lab/README.md#legacy-topologies) remain
GoBGP-specific; their helper script needs repair before it can provide current
qualification.

## Contributing Test Results

If you've tested prefixd with a router not listed here, please open an issue with:

1. Router vendor, platform, and software version
2. Which actions work (discard, rate-limit, redirect)
3. Any quirks or configuration requirements
4. Whether you're willing to be credited

We'll update this matrix with your findings.
