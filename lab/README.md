# prefixd Lab Environment

Containerlab topologies for testing FlowSpec with routers.

## FlowSpec interop lab (maintained)

`interop/` holds the lab that CI runs in the
[Interop workflow](../.github/workflows/interop.yml). It drives prefixd's
HTTP API and checks the exact rules FRR receives. Its layout follows
rustbgpd's M22 FlowSpec lab.

```
prefixd ── loopback gRPC ── speaker (AS 65010, 10.0.0.1) ── eBGP ── FRR 10.7.1 (AS 65002, 10.0.0.2)
   └── loopback ── PostgreSQL           (one network namespace)
```

| Leg | Topology | Speaker image |
|-----|----------|---------------|
| rustbgpd | `interop/frr-rustbgpd.clab.yml` | `ghcr.io/lance0/rustbgpd:0.78.0`, digest-pinned |
| GoBGP | `interop/frr-gobgp.clab.yml` | `jauderho/gobgp` digest that CI pins as 4.10.0 |

Both speakers negotiate IPv4 and IPv6 FlowSpec with FRR; rustbgpd also
negotiates IPv4 and IPv6 unicast for the blackhole scenario below. After each step,
`interop/flowspec_frr.py` waits up to 60 s for FRR's IPv4 and IPv6 tables to
hold exactly the expected rules. It reads `show bgp <family> flowspec json`
and `... detail json`. A rule matches on destination, protocol, destination
port and traffic-rate action (`FS:rate <bytes/s>`, where 0 is discard). Each
path must be FRR's valid best path from the speaker. The steps are:

1. Manual discard: UDP/53 to 203.0.113.10.
2. Manual police at 8 Mbit/s: TCP/80 to 203.0.113.20, shown as `FS:rate 1000000.000000`.
3. Detector event: a `udp_flood` event for 203.0.113.30 with UDP/123. The lab
   playbook polices it at 5 Mbit/s (`FS:rate 625000.000000`).
4. Operator withdrawal of the discard. The rule leaves FRR and the API reports `withdrawn`.
5. TTL expiry: a 15 s discard appears, then leaves FRR, and the API reports `expired`.
6. Speaker restart: `docker stop` empties FRR. After `docker start`, prefixd's
   reconciliation restores both active rules, and its
   `prefixd_reconciliation_repairs_total{status="success"}` counter rises by at least two.
7. IPv6 discard: UDP/53 to 2001:db8:113::10/128.
8. Withdraw everything. Both tables end empty.

On a mismatch, the step fails and prints a unified diff of the expected and
observed rules. Run it locally with Docker and containerlab:

```bash
just interop-frr            # both legs; or: just interop-frr gobgp
CLAB="sudo containerlab" just interop-frr   # if you are not in clab_admins
```

The recipe builds `prefixd:interop` from the working tree and runs the oracle's
negative controls (`lab/interop/test_flowspec_frr.py`). It then runs
`lab/interop/run-frr.sh` for each leg. The script destroys any leftover lab,
writes per-run secrets under `lab/interop/.run/`, deploys, tests, collects logs
and always destroys the lab. It deletes the secrets afterwards and fails the run,
deleting the receipt, if a secret reached it. The receipt lands in `target/interop/frr-<speaker>-<UTC stamp>/`:

| File | Contents |
|------|----------|
| `receipt.json` | Result, date, versions (prefixd, commit, speaker, FRR, containerlab, kernel), image references and per-step expectations |
| `summary.md` | Step table; CI appends it to the job summary |
| `commands.log` | Every API request and docker command, without credentials |
| `frr/` | Raw FRR JSON before and after every step |
| `logs/` | prefixd, speaker, FRR and PostgreSQL logs |

This is control-plane evidence: FRR stores the rules in its BGP table and does
not program a dataplane here. Recorded results are in the
[vendor matrix](../docs/reference/vendors.md#frr--verified-control-plane).
The lab does not touch the Compose stack or other labs. It uses its own lab
names and the management subnets 172.31.231.0/24 and 172.31.232.0/24.

### Blackhole scenario (rustbgpd)

`just interop-frr-blackhole` runs `run-frr.sh rustbgpd blackhole`, which
qualifies [ADR 027](../docs/adr/027-blackhole-mitigations.md) host routes at
FRR. The same topology carries them over IPv4 and IPv6 unicast. FRR's import
route-maps `RTBH-IN-V4` and `RTBH-IN-V6` accept only routes carrying BLACKHOLE
(`65535:666`), rewrite the next hop to 192.0.2.1 or 2001:db8:ffff::1, and
static `blackhole` routes for those addresses make zebra install the host
route as discard. prefixd's own configured next hops (192.0.2.66 and
2001:db8:ffff::66) do not resolve at FRR, so without the route-map nothing is
installed as discard.

`interop/blackhole_frr.py` creates an Admin with `prefixdctl`, logs in and
creates each blackhole through `POST /v1/mitigations`. For every watched
prefix it reads `show bgp <afi> unicast <prefix> json`, `show ip[v6] route
<prefix> json` and the FRR container's `ip -j route show exact <prefix>`. A
prefix is *discard* when FRR holds one valid best path from the speaker with
exactly `65010:666` and `65535:666`, zebra has selected and installed it with
only blackhole FIB next hops, and the kernel route has type `blackhole`. It is
*absent* when none of the three views has it, and *stale* when it is discard
but FRR holds the path only as a Graceful Restart helper. FRR adds `no-export`
to every route carrying BLACKHOLE (RFC 7999 section 3.2), so the oracle expects
it at FRR but not in prefixd's response. Over the IPv4 session rustbgpd sends
IPv6 unicast only because the lab sets `local_ipv6_nexthop`; without it the
IPv6 routes are suppressed. The steps are:

1. Baseline and negative control: the victims and two never-announced host
   routes are absent.
2. IPv4 and IPv6 blackholes for 203.0.113.50 and 2001:db8:113::50 become discard.
3. Negative control: unbinding both route-maps leaves the routes received but
   not discard. Rebinding restores discard.
4. Speaker restart: while the speaker is stopped FRR keeps both routes as
   stale discard. After the speaker starts, the step records each state
   change until prefixd repair restores both as discard, and the repairs
   counter rises by at least two.
5. Operator withdrawal removes both routes.
6. A 15 s TTL blackhole per family appears, then expires and is removed.
7. Negative case: a 20 s blackhole per family stays discard at FRR for 30 s past
   its expiry while prefixd is stopped and the speaker is up. Manual blackholes
   are unleased, so nothing expires them without the controller. Restarting
   prefixd expires and removes them.

The receipt lands in `target/interop/frr-rustbgpd-blackhole-<UTC stamp>/`, with
raw BGP, zebra and kernel JSON per prefix under `frr/`. It is control-plane and
FIB evidence inside the FRR container; no packets are forwarded.

## Nokia

**SR Linux.** `interop/srlinux-probe.clab.yml` peers SR Linux 25.10.1 with
rustbgpd 0.78.0. It is a manual probe, not a CI leg. SR Linux does not support
BGP FlowSpec. The [vendor matrix](../docs/reference/vendors.md#nokia-sr-linux--not-supported)
records the commands and output.

**SR OS.** No lab is provided. The containerised SR OS (SR-SIM) needs an image
and licence from Nokia, and none is available to this project. SR OS stays
untested.

## Legacy topologies

The topologies below use the explicit **GoBGP compatibility profile**. They
do not qualify rustbgpd or prove dataplane enforcement. For the primary stack,
use the [rustbgpd quickstart](../docs/tutorials/quickstart.md). Use the startup
commands below only for a fresh, isolated lab; changing an existing deployment's
target does not change its existing [speaker ownership binding](../docs/how-to/upgrading.md#speaker-ownership-upgrade).

## Lab Options

| Lab | Router | Virtualization | Notes |
|-----|--------|----------------|-------|
| `frr-flowspec.clab.yml` | FRR | None (native container) | Works everywhere |
| `cjunos-flowspec.clab.yml` | cJunosEvolved | KVM (Intel or AMD) | **Recommended for Juniper testing** |
| `vjunos-flowspec.clab.yml` | vJunos-router | Nested KVM | Bare metal only (no VMs) |

## cJunosEvolved Lab (Juniper PTX)

cJunosEvolved is a containerized Junos Evolved router emulating a PTX10002-36QDD. It peers with the prefixd docker-compose GoBGP instance over a shared Docker network.

```
prefixd -> prefixd-gobgp (AS 65010) -> cJunosEvolved (AS 65003)
                 │                            │
                 └── clab-mgmt-evo network ───┘
                     172.30.31.0/24
```

### Prerequisites

1. **KVM support**: `ls /dev/kvm`
2. **Download cJunosEvolved** from [Juniper](https://support.juniper.net/support/downloads/?p=cjunos-evolved) (free, no account)
3. **Load image**: `docker load -i cJunosEvolved-25.4R1.13-EVO.tar.gz`
4. **GoBGP compatibility stack running**, from the repository root:
   `docker compose --profile gobgp up -d --pull always --no-build`.
   Do not also enable the rustbgpd profile.

### Quick Start

```bash
# Deploy cJunos lab
cd lab
sudo clab deploy -t cjunos-flowspec.clab.yml

# First configure configs/gobgp.conf with this lab's neighbor 172.30.31.3,
# peer AS 65003 and IPv4 FlowSpec family; the shipped peer is a placeholder.
# Connect prefixd-gobgp to clab network
docker network connect clab-mgmt-evo prefixd-gobgp --ip 172.30.31.10

# Restart GoBGP after editing its config (same container/network namespace)
docker restart prefixd-gobgp

# Wait ~3-5 min for cJunos to boot, then verify BGP session
docker exec prefixd-gobgp gobgp neighbor
# Should show 172.30.31.3 as Established

# Inject test FlowSpec rule
docker exec prefixd-gobgp gobgp global rib add -a ipv4-flowspec \
  match destination 192.168.1.100/32 protocol tcp destination-port 80 \
  then discard

# Verify on cJunos (admin/admin@123)
ssh admin@172.30.31.3
show route table inetflow.0
```

### Important Notes

- cJunos shows "License key missing; requires 'BGP' license" - this is a warning only, FlowSpec still works
- GoBGP neighbors must be configured with `family ipv4-flowspec` ONLY - cJunos rejects `inet-unicast` capability in the Open message (Open Message Error subcode 7)
- The `FXP0ADDR` token in startup config is replaced by the entrypoint with the mgmt IP (note: it's `FXP0ADDR`, NOT `FXP0ADDRESS`)
- Boot time is ~3 minutes on modern hardware

### Cleanup

```bash
docker network disconnect clab-mgmt-evo prefixd-gobgp
sudo clab destroy -t cjunos-flowspec.clab.yml --cleanup
```

## FRR Lab

FRR (Free Range Routing) runs natively in containers without KVM. Works on any Linux host.

### Quick Start

```bash
# Start prefixd stack first
docker compose --profile gobgp up -d --pull always --no-build

# Configure configs/gobgp.conf with the FRR neighbor and AS from frr-bgpd.conf;
# the shipped peer is a documentation placeholder.

# Deploy FRR lab
cd lab
sudo clab deploy -t frr-flowspec.clab.yml

# Connect prefixd-gobgp to lab network with a fixed IP
docker network connect clab-mgmt prefixd-gobgp --ip 172.30.30.10

# Restart GoBGP to pick up FRR neighbor from configs/gobgp.conf
docker restart prefixd-gobgp

# Verify BGP session
docker exec prefixd-gobgp gobgp neighbor

# Check FlowSpec in FRR
docker exec clab-frr-flowspec-router vtysh -c "show bgp ipv4 flowspec"
```

### Cleanup

```bash
docker network disconnect clab-mgmt prefixd-gobgp
sudo clab destroy -t frr-flowspec.clab.yml --cleanup
```

---

## vJunos-router Lab

> **Warning**: vJunos-router **cannot run inside a VM** (documented Juniper limitation).
> It requires a bare-metal server with KVM (Intel VMX or AMD-V).
> If you're running in a VM or cloud instance, use cJunosEvolved or FRR instead.

See `vjunos-flowspec.clab.yml` for the topology definition.

---

## Resource Requirements

| Router | RAM | CPU | Boot Time | KVM Required |
|--------|-----|-----|-----------|--------------|
| FRR | 256 MB | 1 core | Instant | No |
| cJunosEvolved | 8 GB | 4 cores | ~3-5 min | Yes |
| vJunos-router | 5 GB | 4 cores | ~10 min | Yes (bare metal) |

## Legacy helper script

`test-flowspec.sh` is historical and is **not a current qualification gate**.
It still defaults to the unpublished `http://localhost:8080`, probes obsolete
`/healthz`, omits the required event timestamp, builds bearer headers through
unsafe shell word splitting, and reads mitigation `id` instead of
`mitigation_id`. Optional router checks also do not fail when receipt is absent.
Setting an endpoint alone does not repair this flow or authenticate it against
the default credentials-mode deployment. Repair these checks before relying on
its announce/withdraw result.

For router receipt, use the [FlowSpec interop lab](#flowspec-interop-lab-maintained).
For maintained controller tests, use the owned fixtures in
[`scripts/test-gobgp.sh`](../scripts/test-gobgp.sh) and
[`scripts/test-rustbgpd.sh`](../scripts/test-rustbgpd.sh). They create separate
containers and do not attach to this lab. Hardware/vendor qualification still
needs explicit receiving-router and forwarding checks with retained receipts.

## Troubleshooting

### cJunos: Open Message Error
GoBGP is advertising `inet-unicast` alongside `inet-flow`. Configure the neighbor in `gobgp.conf` with only `ipv4-flowspec` AFI-SAFI.

### cJunos: ZTP running / config not applied
The startup config must use `FXP0ADDR` (not `FXP0ADDRESS`) for the management IP token.

### vJunos: stuck booting in VM
vJunos does not support nested virtualization. Use cJunosEvolved or FRR instead.

### BGP session stuck in Active/Idle
Check network connectivity between containers and ensure both sides are on the same Docker network.
