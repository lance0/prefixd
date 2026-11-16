# FastNetMon Integration

This guide covers integrating FastNetMon with prefixd for automated FlowSpec or
guarded host-blackhole mitigation. The bundled notify script follows the
Community Edition notify interface. FastNetMon Advanced can also post its JSON
callback to the [native JSON endpoint](#native-json-endpoint); its hostgroup
alerts are not mapped yet (see below).

## Carpet bombing and prefix events

FastNetMon **Advanced** can detect aggregate traffic for a total hostgroup and
emit `alert_scope: "hostgroup"` with `hostgroup_networks`; per-network hostgroups
use a separate, undocumented notify shape. The current native adapter and the
Community notify script are host-only: they require a single `ip` and do not
map a hostgroup payload. Do not point a hostgroup action at this adapter yet.

prefixd's `/v1/events` endpoint can accept a canonical CIDR when
`guardrails.allow_detector_prefix` is true and the event's `source` is in
`detector_prefix_sources`. The source is the one the caller's ingest token is
bound to, so the allowlist is authorization: list `fastnetmon-hostgroup`, and
give the shim its own token bound to that source. A host token bound to
`fastnetmon` then cannot send prefix events, and revoking prefix authority
never touches host mitigation
([ADR 034](../../adr/034-source-bound-api-tokens.md)). A hostgroup with one
network can be mapped to that event by an external shim. The published total-hostgroup
payload carries no port list, so a prefix discard playbook is not usable and
only a portless `udp_flood` prefix police playbook applies. TCP prefix police
needs a destination port.

prefixd does not yet complete the FastNetMon integration for prefixes: the
native hostgroup adapter is separate follow-up work, and no router platform is
qualified for prefix rules.
Multiple networks in one hostgroup need separate events with distinct event
IDs. See [ADR 033](../../adr/033-detector-prefix-mitigations.md).

A shim posts one event per attacked network, reading its token from a file
and handing the header to curl on stdin so it never appears in `ps`:

```bash
printf 'header = "Authorization: Bearer %s"\n' "$(cat /etc/prefixd/hostgroup.token)" |
  curl -K - -X POST "${PREFIXD_API}/v1/events" \
    -H "Content-Type: application/json" \
    -d '{
      "event_id": "fnm-hostgroup-customer-a-1731574800",
      "timestamp": "2026-11-14T09:00:00Z",
      "source": "fastnetmon-hostgroup",
      "victim_ip": "203.0.113.0/24",
      "vector": "udp_flood",
      "pps": 4200000,
      "confidence": 0.9
    }'
```

Treat `400`, `403` and `422` as final and never resend a refused prefix as a
host event. An IPv4-mapped prefix is refused with `400`. To unban, post an
event with `"action": "unban"` and the same `source` and `victim_ip`; prefixd
withdraws the live mitigations that source created for that prefix.

Portless UDP police is an owner-approved exception, not an operator-confirmed
requirement. It is one shared rate bucket for all UDP to the whole prefix,
legitimate DNS and QUIC included. Size `rate_bps` for the prefix's normal
aggregate UDP traffic, not a per-host figure, and measure how the router
allocates the policer (per interface, line card or system) during
qualification before relying on it.

## Overview

FastNetMon detects DDoS attacks via NetFlow/sFlow analysis and calls a notify script when attacks are detected. The `prefixd-fastnetmon.sh` script posts each ban and unban to prefixd as an event, with an ingest token bound to the `fastnetmon` source.

```
FastNetMon → notify script → prefixd → BGP speaker → routers
```

### Choose the mitigation owner

Use the notify script below when prefixd should own mitigation. prefixd applies
inventory ownership, safelists, quotas and TTL limits, evaluates playbooks, and
records mitigation and withdrawal audit history. It supports FlowSpec through
rustbgpd or GoBGP, and opt-in host blackholes through rustbgpd. The dashboard
shows desired intent and the available speaker evidence; neither local RPC
acceptance nor peer health proves router enforcement.

FastNetMon also has a native rustbgpd action for direct RTBH:

```text
FastNetMon → rustbgpd injection API → routers
```

As checked on 2026-10-27, [the native action was merged upstream](https://github.com/pavel-odintsov/fastnetmon/pull/1097)
that day and is absent from the latest published FastNetMon release,
[`v1.2.9`](https://github.com/pavel-odintsov/fastnetmon/releases/tag/v1.2.9).
It requires a source build containing that change, with
`-DENABLE_RUSTBGPD_SUPPORT=ON`, plus `rustbgpd = on` at runtime. It announces
IPv4 `/32` and IPv6 `/128` blackholes, optionally IPv4 customer subnets, and
offers experimental injection leases with `rustbgpd_lease = on`. See
[FastNetMon's native-action guide at the merged revision](https://github.com/pavel-odintsov/fastnetmon/blob/5686208f28f2eef36b5329dd9595e79a3da38a89/docs/rustbgpd_integration.md)
for its build, transport, router-policy and lease requirements.

The native action sends FastNetMon's bans directly to rustbgpd. Those bans do
not pass through prefixd's admission checks or create prefixd mitigation and
audit records. Choose this path when FastNetMon should own RTBH; use the notify
path when prefixd should apply its policy and own the route lifecycle.

Detector playbooks can select police (rate-limit), discard or a guarded host
blackhole. DSCP marking, redirect-to-IP/VRF and optional source-prefix matching
are manual/VPN-scrubber operations, not playbook actions.

### Keep one writer per speaker target

prefixd requires exclusive administration of its physical speaker target.
Do not enable FastNetMon's native action against that same target, even with
disjoint prefixes. Use separate speaker targets if both systems must inject
routes independently. See
[persistent target ownership](../../reference/speaker-backends.md#persistent-target-ownership).

The following conflict behavior was checked against prefixd source and
rustbgpd `v0.80.1`; it does not qualify a shared-target deployment:

- Normal add/delete calls refuse a leased route held by another owner,
  including calls with no owner. A leased add also cannot adopt an unowned
  route. When such a route already occupies a prefix, prefixd's leased
  blackhole admission returns `409`, retires the new database row locally and
  sends no delete.
  Keep FastNetMon's lease owner distinct from prefixd's; sharing an owner
  removes this protection.
- Before unleased admission, prefixd reads local routes and returns `409`
  without saving or adding if the prefix already has an untracked route.
  This pre-read cannot fence another writer: a later unleased add can replace
  an unowned route, and an unleased delete can remove it. A prefixd admission
  race or reconciliation repair that returns `replaced` increments
  `prefixd_blackhole_replaced_total{pop}` and triggers `PrefixdBlackholeReplaced`.
  That counter records replacements performed by prefixd, not every external
  overwrite; see the
  [replacement-conflict alert](../grafana.md#replacement-conflict-alert).
- When blackhole reconciliation runs, a successful inventory read reports
  routes outside prefixd's ledger in
  `prefixd_unknown_local_routes{kind="blackhole"}`. Unknown and foreign-owner
  routes are left alone. The documented exception is cleanup of a route that
  exactly matches a terminal prefixd-owned snapshot; unleased routes carry no
  writer identity. See
  [blackhole reconciliation](../../reference/speaker-backends.md#blackhole-lifecycle-and-reconciliation)
  for the exact ownership and orphan-cleanup rules.

## Prerequisites

- FastNetMon Community or Advanced installed and configured
- prefixd running with API accessible
- `bash` and `curl` on the FastNetMon host; nothing else
- Network connectivity from FastNetMon to prefixd API

## Installation

1. Copy the notify script to the FastNetMon host. The host needs `bash` and
   `curl` only:

```bash
sudo cp scripts/prefixd-fastnetmon.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/prefixd-fastnetmon.sh
```

2. Create an ingest token bound to `fastnetmon` on the controller. The secret
   is printed once, on stdout, so write it straight to a file:

```bash
(umask 077; prefixdctl tokens create --name fnm-pop1 --scope ingest --source fastnetmon --pop iad1 > fnm-pop1.token)
```

   Copy the file to the FastNetMon host, install it where only the FastNetMon
   user can read it, and delete the copies:

```bash
sudo install -d -m 0755 /etc/prefixd
sudo install -m 0400 -o fastnetmon fnm-pop1.token /etc/prefixd/fastnetmon.token
rm fnm-pop1.token
```

   An ingest token cannot read data or withdraw anything; it can post events
   only as `fastnetmon`. See [API tokens](../../reference/cli.md#api-tokens)
   for rotation and revocation.

3. Configure the script in `/etc/default/prefixd`:

```bash
# prefixd API endpoint, required: the HTTPS ingress in front of the controller
PREFIXD_API="https://prefixd-host:8443"

# The ingest token file (preferred), or PREFIXD_TOKEN with the token itself
PREFIXD_TOKEN_FILE="/etc/prefixd/fastnetmon.token"

# Only for a controller with http.auth.mode none: run without a token
# PREFIXD_AUTH_MODE="none"

# Log file location (optional)
PREFIXD_LOG="/var/log/prefixd-fastnetmon.log"

# Delivery attempts for a ban or unban on a connection error or 503 (optional)
EVENT_POST_ATTEMPTS="3"
EVENT_POST_DELAY_SECONDS="1"

# Per-attempt bounds in seconds, at least 1 (optional)
EVENT_CONNECT_TIMEOUT_SECONDS="5"
EVENT_MAX_TIME_SECONDS="15"
```

`PREFIXD_API` has no default: the script logs an error and posts nothing
until it is set. Point it at the HTTPS ingress in front of the controller. On
the Compose stack, which does not publish the controller's port 8080, that is
nginx; use its plain `http://<compose-host>` on port 80 only across a trusted
management segment, because the token travels in the clear. On that stack,
`scripts/compose-bootstrap.sh` has already minted an ingest token bound to
`fastnetmon` into `.prefixd/fastnetmon.token`; install that file as the token
file above. That token has no POP binding, so every controller sharing the
database accepts it; mint one with `--pop` for a multi-POP deployment.

The script sources `/etc/default/prefixd` when it exists; variables set there
override the process environment. `PREFIXD_TOKEN_FILE` wins over
`PREFIXD_TOKEN`; if you keep the token in `/etc/default/prefixd` instead, make
that file mode 0600. The script hands the `Authorization` header to curl in a
config on stdin (`curl -K -`), so the token never appears in `ps` or
`/proc/*/cmdline`, and it refuses a malformed token without logging it.

FastNetMon runs the script once per ban and once per unban and never repeats
it. The script therefore retries the same event, with the same `event_id`,
when prefixd cannot be reached or answers `503` (including a standby or draining
controller, or a mitigation that changed during admission). It stops after
`EVENT_POST_ATTEMPTS` attempts in total, each bounded by the two timeouts.
It never retries a `4xx`, except that a retried
ban meeting its own event ID as `409` counts as recorded intent only when
`event_outcome` says `mitigated`, `extended` or `dry_run` and lists mitigation
IDs. It logs `INTENT_RECORDED`, which does not prove current enforcement;
refused or interrupted outcomes remain errors. It refuses to run at all without a token, unless
`PREFIXD_AUTH_MODE=none`. A `403` means the token
is not bound to `fastnetmon`, or is bound to another POP. A `409` on a ban
means the event ID already arrived, or the rule conflicts with speaker or
injection ownership; read the error text. A `503` can be returned after the
event row was stored. New incomplete attempts resume with the same event ID;
committed intent returns `409` with its recorded outcome. Historical ambiguous
attempts are refused with an unknown-outcome conflict; inspect them before
authorizing a new event ID. Check `GET /v1/mitigations`, not just the event. Point `PREFIXD_API` at the active
controller, or at a load balancer that routes by `GET /v1/ready`; see
[controller fence and rolling deploys](../upgrading.md#controller-fence-and-rolling-deploys).

4. Configure FastNetMon to use the script. Edit `/etc/fastnetmon.conf`:

```ini
notify_script_path = /usr/local/bin/prefixd-fastnetmon.sh
```

`notify_script_path` is the only notify-script setting in FastNetMon Community. The script file must exist when FastNetMon starts, or notifications are disabled.

5. Restart FastNetMon:

```bash
sudo systemctl restart fastnetmon
```

## How It Works

### Ban Flow

1. FastNetMon detects attack on victim IP
2. Calls script with args: `$1=IP $2=direction $3=pps $4=ban` and writes the attack details to its stdin
3. Script generates a unique UUID `event_id` for each ban occurrence. The
   victim always comes from `$1`: a manual IPv6 ban's stdin says
   `IP: 0.0.0.0`.
4. Sends `POST /v1/events` with `action: "ban"` and numeric `confidence: 0.9`, retrying a connection error or
   `503` up to `EVENT_POST_ATTEMPTS` times with the same `event_id`
5. prefixd stores the event, applies ownership, correlation and playbook gates,
   then admits a mitigation and attempts the announcement; any gate can stop the
   ban without a mitigation

The script assigns `0.9` to a ban, matching the native JSON adapter's default
ban confidence. This lets a single ban meet the shipped correlation settings
(`min_sources: 1`, `confidence_threshold: 0.5`). Inventory ownership, playbooks
and guardrails still apply; a stricter correlation policy may require more
signals. The `sources.fastnetmon.confidence_mapping` setting applies to
`POST /v1/signals/fastnetmon`, not this script's `POST /v1/events` payload.

Older copies of the script omit confidence. With correlation enabled, missing
confidence counts as zero: the API can accept and record the event without
creating a mitigation. Copy the updated script to the FastNetMon host when
upgrading; updating only the prefixd container does not replace it.

The script distinguishes a recorded event from an admitted mitigation: a 2xx
response without `mitigation_id` logs `NO_MITIGATION (<code>, status=...)`
instead of `SUCCESS (<code>, status=...)`. Read the response body:

| HTTP | Body | Meaning | Next check |
|------|------|---------|------------|
| 202 | `accepted` with `mitigation_id` | mitigation created | `announcement_outcome` and speaker export state |
| 202 | `extended` with `mitigation_id` | existing mitigation extended | — |
| 202 | `accepted` without `mitigation_id` | correlation threshold or source count not met | effective `correlation.yaml`, confidence, group window |
| 202 | `accepted_no_mitigation` | victim not in the effective inventory | `/etc/prefixd/inventory.yaml` in the controller |
| 202 | `accepted_no_playbook` | policy produced no rule: no playbook matched, or its initial step has no action | effective `playbooks.yaml` |
| 400 | `error` | invalid event, or a VPN default scope refused a blackhole | error text; `default_scope`/`vpn_scopes` |
| 403 | `error` | the token is not bound to `fastnetmon`, or is bound to another POP | `prefixdctl tokens list` |
| 422 | `error` | guardrail or VPN scope refused; the event may still be recorded | error text: safelist, quota, `l3vpn` capability |
| 429 | `error` | event rate limit | `http.rate_limit`; wait |
| 409 | `error`, optional `event_outcome` | completed duplicate, historical unknown outcome, speaker binding or owner conflict | recorded outcome and mitigation IDs; unknown historical admission needs operator inspection |
| 503 | `error` | controller unavailable, withdrawal incomplete, or a mitigation changed during admission | the script retries the same event ID; inspect the final response if retries exhaust |

`SUCCESS` means prefixd committed mitigation intent (created or extended) and
returned its ID; it does not prove the speaker exported the rule or a router
installed it. Check `announcement_outcome` and the speaker export state.
`NO_MITIGATION` is a warning, not a retry: the script still exits 0 because
retrying cannot change these gates. Peers being down does not suppress
mitigation rows: prefixd records the intent and reports the announcement as
`unconfirmed`.

The shipped safelist covers `10.0.0.0/8` and `192.168.0.0/16`; an owned victim
inside either range is refused with 422. Use a real owned prefix for lab tests;
a TEST-NET address is unowned unless you add it to the effective inventory.

Compose keeps `inventory.yaml`, `playbooks.yaml` and `correlation.yaml` in the
`prefixd-config` volume. Editing the copies under `configs/` in the checkout
does not change the running controller; read `/etc/prefixd/` inside the
controller (or use the dashboard editors). See the
[quickstart configuration notes](../../tutorials/quickstart.md#configuration-and-persistence).

### Unban Flow

1. FastNetMon attack subsides
2. Calls script with args: `$1=IP $2=direction $3=pps $4=unban`; no attack details are sent
3. Script sends `POST /v1/events` with `action: "unban"`, `source: "fastnetmon"`
   and the victim from `$1`, retrying a connection error or `503` like a ban
4. prefixd withdraws every live mitigation for that victim on its POP that
   `fastnetmon` created, comparing the address in canonical form, and answers
   `withdrawn` with their IDs. With none left it answers
   `no_active_mitigation`, which the script logs as `NO_MITIGATION` and treats
   as done. If a delete fails or its outcome is unknown, prefixd answers
   `503` with the withdrawal intent recorded; the script resends the same
   event, and prefixd reuses the pending intent.

Other sources' mitigations for the same victim and manual mitigations are
never touched. The script keeps no state: a re-ban that extended a mitigation,
an unban after a lost earlier unban, and a ban sent before an upgrade all pair
by victim. The withdrawal is audited as the token, `token:<name>`, with the
reason `Detector unban: fastnetmon`.

### Idempotency

Each ban uses a unique `event_id`, which prevents permanent duplicate collisions after a ban→withdraw→re-ban cycle and allows ongoing attacks to extend TTL through scope matching.

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
`udp_amplification`, `syn_flood`, `ack_flood`, `icmp_flood` and `unknown`).
`udp_amplification` without its own playbook falls back to the `udp_flood`
playbook. The first playbook that matches a vector wins, so put blackhole
playbooks before FlowSpec ones for the same vector, or replace them:

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
`/128`. The allowlist is authorization: only a token bound to `fastnetmon`
(or an Admin) can post as that source, and a ban from any other source gets
`422` instead of a blackhole. A repeated ban extends the blackhole, capped at
`blackhole.max_ttl_seconds` from now. The script's unban withdraws blackholes
like any other mitigation that `fastnetmon` created for the victim.

**Rehearse in dry-run first.** In `mode: dry-run`, the same configuration
creates and audits the blackhole, shows it in the dashboard and API, and sends
nothing to the speaker.

**Enforced mode and the injection lease.** The rustbgpd injection lease lets
the speaker remove a dead controller's routes on its own. With rustbgpd, set
`blackhole.leased: true`: enforced detector blackholes are then
added under the controller's lease, and if prefixd stops, rustbgpd removes
them within `blackhole.lease_seconds` (60 by default). See
[leased blackholes](../../reference/configuration.md#leased-blackholes).
Without the lease, startup and playbook reload or save refuse a blackhole step
in enforced mode unless `detector_sources` is nonempty; a nonempty list is the
opt-in to unleased detector blackholes. Startup then logs a warning, health
detail reports `speaker.detector_unleased: true` and
`prefixd_blackhole_detector_unleased` is `1`.

**The remaining gap without the lease.** TTL expiry needs the running
controller. If prefixd stays down while rustbgpd keeps running, unleased
detector blackholes stay announced
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
shows both. prefixd refuses `0.0.0.0` and `::` as next hops, which speakers
commonly read as next-hop-self: RTBH needs the discard next hop that the edge
routers map to null.

**RPKI filters.** A blackhole `/32` or `/128` is longer than its covering
ROA's maxLength, so a router that validates it with the speaker's AS as
origin rates it RPKI-Invalid. A policy there that drops Invalid before it
accepts BLACKHOLE drops every blackhole silently: the ban succeeds in prefixd
and nothing reaches the edge. Match BLACKHOLE ahead of any Invalid filter, or
exempt the RTBH sessions, then test one ban end to end; the
[RPKI blackhole receipt](../../reference/qualification/blackhole-rpki-frr-2026-10-20.md)
shows both orders at FRR.

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
- Protocol tokens are bounded by non-alphanumeric characters, including
  underscores: `tcp_ack` matches ACK, while `Attack_type` does not match `ack`.
  A value such as `Attack_type: udp_flood` still contains a separate `udp`
  token and selects `udp_flood`.

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
# Simulate ban for an address the effective inventory owns.
echo "Attack details: UDP flood" | /usr/local/bin/prefixd-fastnetmon.sh 203.0.113.10 incoming 1000000 ban

# The outcome, with the mitigation ID, is in the script log.
tail -n 2 /var/log/prefixd-fastnetmon.log

# Simulate unban
/usr/local/bin/prefixd-fastnetmon.sh 203.0.113.10 incoming 0 unban </dev/null
```

### Interop lane

`just interop-fastnetmon` runs FastNetMon Community 1.2.9 with this script
against prefixd, rustbgpd and FRR, and CI runs it on every change to the
script. The [dated receipt](../../reference/qualification/fastnetmon-community-2026-11-16.md)
lists what it covers. Two of its findings matter for an install:

- The official `fastnetmon-community` container image has no `curl`; add it,
  as the lane's image does.
- A manual `fastnetmon_api_client ban` sends all-zero counters, so the script
  sends vector `unknown`. It creates a mitigation only if a playbook matches
  `unknown`, as the shipped `unknown_conservative` does.

FastNetMon Advanced is not qualified; the receipt lists the open items and
the manual procedure.

## Troubleshooting

### Check logs

```bash
tail -f /var/log/prefixd-fastnetmon.log
```

### Common issues

1. **Connection refused**: Verify `PREFIXD_API` is reachable
1. **503 Service Unavailable**: `PREFIXD_API` reaches a standby controller; route
   it to the controller whose `GET /v1/ready` returns `200`
2. **401 Unauthorized**: the token is not a valid API token, or it was
   revoked or expired; the error names which. A value from the removed
   `PREFIXD_API_TOKEN` is refused as malformed
3. **403 Forbidden**: the token is not an ingest token bound to `fastnetmon`
   (the error names the bound source), or it is bound to another POP. An
   operator token cannot post events
3. **422 Unprocessable**: A guardrail refused the mitigation, for example a
   safelisted victim, a quota, an unsupported VPN scope, or a blackhole
   playbook whose `source` is not in `blackhole.detector_sources`. An unowned
   victim is not a 422: it returns `202 accepted_no_mitigation`.
4. **No mitigation created**: Read the `NO_MITIGATION` or `SUCCESS` line in the
   script log and map its `status` with the table under [Ban Flow](#ban-flow).
   A `202` with no `mitigation_id` can mean correlation is not met, the victim
   is unowned, or no playbook matched; update older scripts that omit
   confidence.
5. **Unban says `NO_MITIGATION`**: nothing that `fastnetmon` created for the
   victim is live on this POP; it may have expired, been withdrawn, or been
   created by another source.

### Debug mode

Add `set -x` at the top of the script for verbose output.

## Advanced: Custom Vector Mapping

Edit the script's vector detection section to change the mapping. The vector
must be one prefixd accepts (`udp_flood`, `udp_amplification`, `syn_flood`,
`ack_flood`, `icmp_flood` or `unknown`) and needs a matching playbook. Use
`udp_amplification` with `top_src_ports` for reflection attacks rather than a
per-protocol name; the script already does this from the packet dump.

## Security Considerations

1. **Token security**: Keep the ingest token in a 0400 file owned by the
   FastNetMon user and point `PREFIXD_TOKEN_FILE` at it. The token can post
   events only as `fastnetmon`; revoke it with `prefixdctl tokens revoke` if
   the host is compromised.

2. **Network security**: Use TLS for production deployments (configure `PREFIXD_API=https://...`)

3. **Log rotation**: Configure logrotate for `/var/log/prefixd-fastnetmon.log`
