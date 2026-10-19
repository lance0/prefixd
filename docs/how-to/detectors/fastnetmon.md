# FastNetMon Community Integration

This guide covers integrating FastNetMon Community Edition with prefixd for automated FlowSpec-based DDoS mitigation.

## Overview

FastNetMon detects DDoS attacks via NetFlow/sFlow analysis and calls a notify script when attacks are detected. The `prefixd-fastnetmon.sh` script bridges FastNetMon to prefixd's HTTP APIs (event ingest + mitigation withdraw).

```
FastNetMon → notify script → prefixd → BGP speaker (rustbgpd by default, or GoBGP) → routers (FlowSpec)
```

## Prerequisites

- FastNetMon Community Edition installed and configured
- prefixd running with API accessible
- `curl` installed (`jq` and/or `python3` are recommended for richer JSON handling)
- Network connectivity from FastNetMon to prefixd API

## Installation

1. Copy the notify script to the FastNetMon host:

```bash
sudo cp scripts/prefixd-fastnetmon.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/prefixd-fastnetmon.sh
```

2. Configure environment variables in `/etc/default/prefixd`:

```bash
# prefixd API endpoint
PREFIXD_API="http://prefixd-host:8080"

# Bearer token for authentication (if auth.mode=bearer)
PREFIXD_TOKEN="your-api-token"

# Operator ID written to withdrawal audit trail (optional)
PREFIXD_OPERATOR="fastnetmon"

# Log file location (optional)
PREFIXD_LOG="/var/log/prefixd-fastnetmon.log"

# Unban lookup retries to handle ban/unban race windows (optional)
UNBAN_QUERY_RETRIES="5"
UNBAN_QUERY_DELAY_SECONDS="1"

# Ban delivery attempts on a connection error or 503 (optional)
BAN_POST_ATTEMPTS="3"
BAN_POST_DELAY_SECONDS="1"
```

FastNetMon runs the script once per ban and never repeats it. The script
therefore retries the same event, with the same `event_id`, when prefixd cannot
be reached or answers `503` (a standby or draining controller). It stops after
`BAN_POST_ATTEMPTS` attempts in total. It never retries a `4xx`: a `409` means
that event ID already arrived. A `409` after a retried connection error usually
means the first attempt reached prefixd. Point `PREFIXD_API` at the active
controller, or at a load balancer that routes by `GET /v1/ready`; see
[controller fence and rolling deploys](../upgrading.md#controller-fence-and-rolling-deploys).

3. Configure FastNetMon to use the script. Edit `/etc/fastnetmon.conf`:

```ini
notify_script_path = /usr/local/bin/prefixd-fastnetmon.sh
```

`notify_script_path` is the only notify-script setting in FastNetMon Community. The script file must exist when FastNetMon starts, or notifications are disabled.

4. Restart FastNetMon:

```bash
sudo systemctl restart fastnetmon
```

## How It Works

### Ban Flow

1. FastNetMon detects attack on victim IP
2. Calls script with args: `$1=IP $2=direction $3=pps $4=ban` and writes the attack details to its stdin
3. Script generates a unique UUID `event_id` for each ban occurrence
4. Sends `POST /v1/events` with `action: "ban"`, retrying a connection error or
   `503` up to `BAN_POST_ATTEMPTS` times with the same `event_id`
5. prefixd evaluates playbook, creates mitigation, announces FlowSpec

### Unban Flow

1. FastNetMon attack subsides
2. Calls script with args: `$1=IP $2=direction $3=pps $4=unban`; no attack details are sent
3. Script queries `GET /v1/mitigations?status=pending,active,escalated&victim_ip=<ip>`
4. Script withdraws each matching mitigation via `POST /v1/mitigations/{id}/withdraw`
5. Script retries lookup briefly to handle ban/unban races

### Idempotency

Each ban uses a unique `event_id`, which prevents permanent duplicate collisions after a ban→withdraw→re-ban cycle and allows ongoing attacks to extend TTL through scope matching.

Unban correlation is done by querying active mitigations for the victim IP and withdrawing them directly.

### Blackholes (RTBH)

FastNetMon Community users usually mitigate with remotely triggered blackhole
(RTBH) host routes. prefixd turns a ban into a blackhole when the matching
playbook's step is `action: blackhole` and the event's `source` is listed in
`blackhole.detector_sources`
([ADR 027](../../adr/027-blackhole-mitigations.md)). A blackhole drops all
traffic to the victim, so it is opt-in at every layer. In `prefixd.yaml`:

```yaml
blackhole:
  enabled: true
  next_hop_ipv4: 192.0.2.66        # the routers' discard next hop
  next_hop_ipv6: "2001:db8::66"
  max_ttl_seconds: 3600
  detector_sources: [fastnetmon]   # the script posts source "fastnetmon"
```

Blackholes need the rustbgpd backend and a nonempty safelist; see the
[blackhole configuration](../../reference/configuration.md#blackhole). In
`playbooks.yaml`, one playbook per vector the script sends (`udp_flood`,
`syn_flood`, `ack_flood`, `icmp_flood` and `unknown`). The first playbook that
matches a vector wins, so put blackhole playbooks before FlowSpec ones for the
same vector, or replace them:

```yaml
playbooks:
  - name: fastnetmon_rtbh_udp
    match:
      vector: udp_flood
    steps:
      - action: blackhole
        ttl_seconds: 1900   # at or above FastNetMon's ban_time
```

A blackhole step takes no `rate_bps` and matches only the victim's `/32` or
`/128`. A ban from any other source, such as the dashboard's mitigate-now
dialog (`source: "dashboard"`), gets `422` instead of a blackhole. A repeated
ban extends the blackhole, capped at `blackhole.max_ttl_seconds` from now. The
script's unban withdraws blackholes like any other mitigation: it lists the
victim's live mitigations and withdraws each one.

**Rehearse in dry-run first.** In `mode: dry-run`, the same configuration
creates and audits the blackhole, shows it in the dashboard and API, and sends
nothing to the speaker.

**Enforced mode and the injection lease.** The rustbgpd injection lease lets
the speaker remove a dead controller's routes on its own. It has not shipped
in any rustbgpd release, so enforced detector blackholes run without it.
Startup and playbook reload or save refuse a blackhole step in enforced mode
unless `detector_sources` is nonempty; a nonempty list is the opt-in. Startup
then logs a warning, health detail reports `speaker.detector_unleased: true`
and `prefixd_blackhole_detector_unleased` is `1`.

**The remaining gap.** TTL expiry needs the running controller. If prefixd
stays down while rustbgpd keeps running, detector blackholes stay announced
until prefixd returns or an operator withdraws them on the speaker, and the
victim stays unreachable. When prefixd returns, reconciliation expires overdue
blackholes at once and removes routes left behind by blackholes that already
ended, with the audit reason `orphaned after controller downtime`. Routes
prefixd cannot match exactly to its own records are reported, never deleted.
Monitor the controller independently of BGP health with the
[down alerts](../grafana.md#alert-rules).

**Router and speaker requirements.** On eBGP, rustbgpd replaces prefixd's
next hop with its own, so the router's import policy must match BLACKHOLE
(`65535:666`) and set a discard next hop itself. Over an IPv4 session, set
`local_ipv6_nexthop` on the rustbgpd neighbor, or IPv6 blackholes are silently
withheld; the [FRR blackhole receipt](../../reference/qualification/blackhole-frr-2026-10-19.md)
shows both.

#### Blackhole TTL

FastNetMon Community calls the script once on ban and once on unban, with no
refresh in between, and skips detection for a host it already considers
banned. If prefixd expired a blackhole before FastNetMon's `ban_time`, the
host would stay unprotected until that ban ended. Keep:

```text
ban_time  <=  playbook blackhole step ttl_seconds  <=  blackhole.max_ttl_seconds
```

FastNetMon's shipped `ban_time` is 1900 seconds, and
`blackhole.max_ttl_seconds` defaults to 3600. With FastNetMon's default
`unban_only_if_attack_finished = on`, an IPv4 unban can come later than
`ban_time` while the attack continues, without calling the script again.
prefixd still expires the blackhole at its TTL in that case, so attack traffic
can reach the victim until FastNetMon unbans and bans it again. That gap is
accepted rather than allowing uncapped blackholes.

## Vector Detection

On ban, the script first reads FastNetMon's own `Attack protocol:` line, the
protocol with the most packets toward the victim:

| `Attack protocol:` | prefixd Vector |
|--------------------|----------------|
| `udp`              | `udp_flood` (or `udp_amplification`, below) |
| `icmp`             | `icmp_flood`   |
| `tcp`              | `syn_flood` with a `syn` token, else `ack_flood` with an `ack` token, else `unknown` |

Background SYN counters or TCP ACK samples in the dump therefore cannot turn a
UDP flood into a TCP rule. Only when the line is missing or says `unknown` does
the script infer the vector from tokens in the attack details:

| Detail token                       | prefixd Vector |
|------------------------------------|----------------|
| `syn` / `syn_` / `tcp_syn`         | `syn_flood`    |
| `ack` / `ack_` / `tcp_ack`         | `ack_flood`    |
| `icmp` / `icmp_`                   | `icmp_flood`   |
| `udp` / `udp_`                     | `udp_flood`    |
| Other / no signal                  | `unknown`      |

Rules that keep the mapping honest:

- Lines reporting a **zero metric** (`outgoing udp traffic: 0 mbps` or `incoming tcp syn pps: 0 packets per second`) are ignored — FastNetMon lists every protocol it tracks, and idle counters must not select a vector.
- TCP flag tokens are matched before `udp` for mixed floods.
- Protocol tokens are bounded by non-alphanumeric characters, including underscores: `tcp_ack` matches ACK, while `packets` and `Attack_type: udp_flood` do not.

### UDP amplification

When the vector is `udp_flood`, the script also reads the sampled packets
FastNetMon writes under `Attack traffic dump`, one line per packet:

```text
2026-10-19 14:02:00.000000 198.51.100.10:123 > 203.0.113.10:40000 protocol: udp frag: 0  packets: 1 size: 486 bytes ttl: 54 sample ratio: 1024
```

It sums sampled UDP packets per source port, weighted by `packets`, and keeps
each port whose share of sampled UDP packets is at least
`PREFIXD_SRC_PORT_MIN_SHARE` (default `0.2`), ranked by share, at most 64.
If any port qualifies, the event is sent as `udp_amplification` with those
ports in `top_src_ports`; prefixd then keeps only ports in its
[reflector-port library](../../reference/configuration.md#amplification).
Otherwise the event stays `udp_flood`, as it does for a dump with no UDP
lines, lines that do not parse, or an invalid `PREFIXD_SRC_PORT_MIN_SHARE`.
TCP and ICMP attacks are never sent as amplification. IPv6 dumps work the
same way; the port follows the last colon of the source address.

The dump holds at most `ban_details_records_count` packets (20 in FastNetMon's
shipped `fastnetmon.conf`, 50 in its code default), so shares are coarse
samples, not a ranked attack summary. Without a `udp_amplification` playbook,
or when no port is in the library, prefixd handles the event as `udp_flood`.
The default library includes 53: a source-port rule containing it also drops
the victim's replies from external DNS resolvers while it is live.

```bash
# Optional: the share of sampled UDP packets a source port needs (above 0, at most 1)
PREFIXD_SRC_PORT_MIN_SHARE="0.2"
```

### Native JSON endpoint

`POST /v1/signals/fastnetmon` takes FastNetMon's JSON callback directly. When
the attack is UDP-dominant and the payload carries `packet_dump_detailed`,
prefixd applies the same rule with `amplification.min_src_port_share` and keeps
only library ports. See the
[API reference](../../reference/api.md#fastnetmon-webhook).

## Testing

Test the script manually:

```bash
# Simulate ban
echo "Attack details: UDP flood" | /usr/local/bin/prefixd-fastnetmon.sh 192.0.2.1 incoming 1000000 ban

# Check prefixd
curl http://prefixd:8080/v1/mitigations?status=active

# Simulate unban
echo "" | /usr/local/bin/prefixd-fastnetmon.sh 192.0.2.1 incoming 0 unban
```

## Troubleshooting

### Check logs

```bash
tail -f /var/log/prefixd-fastnetmon.log
```

### Common issues

1. **Connection refused**: Verify `PREFIXD_API` is reachable
1. **503 Service Unavailable**: `PREFIXD_API` reaches a standby controller; route
   it to the controller whose `GET /v1/ready` returns `200`
2. **401 Unauthorized**: Check `PREFIXD_TOKEN` matches prefixd config
3. **422 Unprocessable**: Victim IP not in prefixd inventory, or a blackhole
   playbook matched and `source` is not in `blackhole.detector_sources`
4. **No mitigation created**: Check playbooks match the vector
5. **400 on withdraw**: Ensure script sends `operator_id` (set `PREFIXD_OPERATOR`, default: `fastnetmon`)

### Debug mode

Add `set -x` at the top of the script for verbose output.

## Advanced: Custom Vector Mapping

Edit the script's vector detection section to change the mapping. The vector
must be one prefixd accepts (`udp_flood`, `udp_amplification`, `syn_flood`,
`ack_flood`, `icmp_flood` or `unknown`) and needs a matching playbook. Use
`udp_amplification` with `top_src_ports` for reflection attacks rather than a
per-protocol name; the script already does this from the packet dump.

## Security Considerations

1. **Token security**: Store `PREFIXD_TOKEN` in `/etc/default/prefixd` with restricted permissions:
   ```bash
   sudo chmod 600 /etc/default/prefixd
   ```

2. **Network security**: Use TLS for production deployments (configure `PREFIXD_API=https://...`)

3. **Log rotation**: Configure logrotate for `/var/log/prefixd-fastnetmon.log`
