# FastNetMon Community interop — 2026-11-16 UTC

This receipt qualifies the FastNetMon Community notify path: FastNetMon
Community 1.2.9 runs prefixd's bundled `scripts/prefixd-fastnetmon.sh`, which
posts to prefixd, which announces through rustbgpd to FRR. It also answers the
FastNetMon Community lab checks that
[ADR 034 §13](../../adr/034-source-bound-api-tokens.md#open-lab-checks) left
open. Every claim is scoped to the versions, configuration and topology below.
It is control-plane evidence in FRR's BGP table: no packets were forwarded, FRR
installed no filter, and it says nothing about any other router or about
FastNetMon Advanced.

The lane runs prefixd in `none` auth mode, because source-bound ingest tokens
([ADR 034](../../adr/034-source-bound-api-tokens.md)) have not landed. It
therefore qualifies the notify contract and the route lifecycle, not detector
authentication. The token assertions and negative controls in ADR 034 §16 are
not covered here.

## Setup

| Item | Value |
| --- | --- |
| Run | 2026-11-16T04:25:06Z, local, Linux 7.0.0-30-generic, containerlab 0.74.3, lab nodes pinned to 16 CPUs, on this change's final lane code. Ten steps, 33.5 s of steps |
| CI | The Interop job `FastNetMon Community (rustbgpd/FRR)` runs the same lane on every head of a change that touches `lab/**` or the notify script, and nightly. This receipt's text was written before the run on its own head; the change's description links that run |
| prefixd | 0.27.0, local image `sha256:71c99a06881d…` built from main `583e200` plus this change's lab files |
| FastNetMon | Community 1.2.9, `ghcr.io/pavel-odintsov/fastnetmon-community:1.2.9@sha256:c154b5b5fd74286719c1c1b97d02157a559926b7749fb5afa958d5faccbd5a0e` (index digest, image built 2026-05-31). [`fastnetmon.Dockerfile`](../../../lab/interop/fastnetmon.Dockerfile) adds `curl` with an unversioned `apt-get install`, so each build takes Ubuntu 24.04's current package: `curl 8.5.0-2ubuntu10.16` in this run. The lane records the installed version in `receipt.json` |
| Speaker | rustbgpd 0.83.0, `ghcr.io/lance0/rustbgpd:0.83.0@sha256:79a6a584b59dae0574a8f5240a4e8f68454fdfede1b7fe31ed446fcf92a30979` |
| Router | FRR 10.7.1, `quay.io/frrouting/frr:10.7.1@sha256:e995beaa50fdc9edb35eadcfefa29b7f062cc06f2b812613789b68fa541554d2` |
| Topology | [`fastnetmon-rustbgpd.clab.yml`](../../../lab/interop/fastnetmon-rustbgpd.clab.yml): the FRR lab's eBGP session (speaker AS 65010 at 10.0.0.1, FRR AS 65002 at 10.0.0.2, IPv4 and IPv6 FlowSpec). FastNetMon shares prefixd's network namespace, so the script posts to `http://127.0.0.1:8080` |
| FastNetMon settings | [`fastnetmon.conf`](../../../lab/interop/configs/fastnetmon.conf): NetFlow on UDP 2055, `threshold_pps = 1000`, `ban_for_pps = on`, `ban_time = 20` with `unban_only_if_attack_finished = on`, networks `203.0.113.0/24` and `2001:db8:113::/48`, `notify_script_path` the bundled script, ExaBGP and GoBGP off |
| prefixd settings | [`prefixd-fastnetmon.yaml`](../../../lab/interop/configs/prefixd-fastnetmon.yaml) (`auth.mode: none`, correlation `min_sources: 1`) and [`playbooks-fastnetmon.yaml`](../../../lab/interop/configs/playbooks-fastnetmon.yaml): `unknown` polices at 1 Mbit/s, `udp_flood` at 5 Mbit/s, both 600 s |
| Driver | [`fastnetmon_frr.py`](../../../lab/interop/fastnetmon_frr.py) through [`run-fastnetmon.sh`](../../../lab/interop/run-fastnetmon.sh) (`just interop-fastnetmon`) |

Each trigger waits for the script's outcome line in its own log
(`SUCCESS`, `NO_MITIGATION` or `ERROR` for a ban; `Withdrew`, nothing found
or `ERROR` for an unban) before the next trigger. The wait is bounded at 60 s,
or at 100 s (twice `ban_time` plus 60 s) for FastNetMon's own unban. The step
then reads the mitigation from prefixd and waits until FRR's IPv4 and IPv6
FlowSpec tables hold exactly the expected rules. The oracle is
[`flowspec_frr.parse_frr`](../../../lab/interop/flowspec_frr.py): every path
must be FRR's valid best path from 10.0.0.1, the table and detail views must
agree, and a rule matches on every component FRR reports and on the action.

## Results

| Step | Trigger | prefixd | FRR |
| --- | --- | --- | --- |
| 01 api-ban | `fastnetmon_api_client ban 203.0.113.10` | Script `SUCCESS (202, status=accepted)`; vector `unknown`, police 1 Mbit/s, no protocol or port | `to 203.0.113.10/32`, `FS:rate 125000.000000` |
| 02 api-unban | `fastnetmon_api_client unban 203.0.113.10` | Script withdrew that mitigation; status `withdrawn` | Both tables empty |
| 03 api-reban-extends | `ban 203.0.113.20` twice | First `accepted`, second `extended`: same mitigation ID, later `expires_at` | One rule, `to 203.0.113.20/32` |
| 04 api-reban-unban | `unban 203.0.113.20` | Withdrawn | Empty |
| 05 script-reban-extends | The script run directly, twice, with a captured UDP flood on stdin ([fixture](../../../lab/interop/fixtures/fastnetmon/udp-flood.txt)) | `accepted`, then `extended` on the same mitigation; `udp_flood`, police 5 Mbit/s | `to 203.0.113.40/32 proto =17 dstp =53,=123`, `FS:rate 625000.000000` |
| 06 script-unban | The script with `unban` | Withdrawn | Empty |
| 07 ipv6-api-ban | `ban 2001:db8:113::10` | `accepted`; `dst_prefix` `2001:db8:113::10/128`, `victim_ip` stored as `2001:0db8:0113::0010` (see below) | `to 2001:db8:113::10/128/off 0`, `FS:rate 125000.000000` |
| 08 ipv6-api-unban | `unban 2001:db8:113::10` | Withdrawn | Empty |
| 09 netflow-detected-ban | NetFlow v5 UDP flood toward 203.0.113.30, port 80 ([`netflow_v5.py`](../../../lab/interop/netflow_v5.py)); the exporter stops once the ban's outcome is logged | FastNetMon detected 3625 pps incoming and ran the script with real attack details; `udp_flood`, police 5 Mbit/s, event `pps` 3625, `raw_details.direction` `incoming` | `to 203.0.113.30/32 proto =17 dstp =53,=123`, `FS:rate 625000.000000` |
| 10 detected-timer-unban | None: FastNetMon's cleanup thread | The script withdrew the mitigation; the audit withdrawal reason is `anonymous: FastNetMon unban for 203.0.113.30 (direction=incoming)`, and the script log holds one ban for the address | Empty |

**Step 09's rule does not cover the flood.** The flood targets UDP port 80.
The script sends no destination ports, and for a portless UDP flood prefixd
uses the service's allowed UDP ports, 53 and 123 in
[`inventory.yaml`](../../../lab/interop/configs/inventory.yaml). The rule at
FRR therefore polices UDP to ports 53 and 123 and leaves the port 80 flood
unmatched. The step qualifies the notify path and the route lifecycle, not that
the resulting rule matches the attack. A manual ban carries no protocol, so its
rule matches only the destination.

Step 09 took 2.3 s from starting the exporter to FRR holding the rule:
FastNetMon crossed `threshold_pps`, collected `ban_details_records_count`
(20) flow records in 0.51 s, then ran the script. This is one synthetic flow
pattern at one threshold, not a detection-quality or timing claim.

Step 10 is FastNetMon's own unban of a detected ban. FastNetMon logged
`Call script for ban client: 203.0.113.30` at 04:25:20.263 and
`Call script for unban client: 203.0.113.30` at 04:25:45.262, 25 s later:
`ban_time` of 20 s, then the next wakeup of the cleanup thread, which runs every
`ban_time / 2` seconds. The exporter had stopped, so the attack counted as
finished. The step took 25.2 s. The withdrawal reason carries the direction
FastNetMon passed (`incoming`); the probe below records the call's full
arguments and stdin.

### Seeded failures

**Unreachable controller.** With the script's `PREFIXD_API` pointed at port
8081, where nothing listens, the lane failed at its first step (run
2026-11-16T03:38:00Z, exit 1):

```text
FAIL: 01-api-ban: the script reported ERROR (None, status=None), expected SUCCESS with status=accepted: ERROR (000, curl=7):
```

The script had logged two `not accepted (curl=7, http=000)` retries before
its `ERROR` line.

**Secret in the receipt.** `finish()` in `run-fastnetmon.sh` refuses the
receipt if any value in `lab_secrets` appears in it; the database password and
speaker token are there, and `ingest_credential()` appends any credential it
mints. With `ingest_credential()` changed once to append a fresh random value
and write it to `seeded-leak.txt` in the receipt, every step passed and the run
still failed (2026-11-16T04:14:12Z, exit 1), with the receipt deleted:

```text
[10-detected-timer-unban] PASS in 23.1s
a lab secret reached the receipt; deleting it
receipt: target/interop/fastnetmon-rustbgpd-20261116T041412Z (exit 1)
```

**Failure before any ban.** With the driver pointed once at a missing
FastNetMon container, step 01 failed before FastNetMon wrote any attack
details. `finish()` still collected the logs, destroyed the lab, removed the
per-run credentials and scanned the receipt (2026-11-16T04:24:45Z, exit 1):

```text
FAIL: Command '['docker', 'exec', '-i', 'prefixd-fnm-missing', '/opt/fastnetmon-community/app/bin/fastnetmon_api_client', 'ban', '203.0.113.10']' returned non-zero exit status 1.
receipt: target/interop/fastnetmon-rustbgpd-20261116T042445Z (exit 1)
```

With `collect()`'s earlier `[ -e "$file" ] && mv …` loop, the same failure
printed no receipt line. The unmatched glob made that test `collect()`'s
status, `set -e` stopped `finish()`, and all five `prefixd-fnm-*`
containers and the run directory's credential files were left behind.

**Outcome parser.** The unit tests in
[`test_fastnetmon_frr.py`](../../../lab/interop/test_fastnetmon_frr.py) cover
the outcome parser. With its per-victim check removed, the test that a ban for
203.0.113.1 is not 203.0.113.10's outcome fails.

## FastNetMon Community lab checks

The answers come from
[`fastnetmon-probe.sh`](../../../lab/interop/fastnetmon-probe.sh), run at
2026-11-16T04:10:43Z. It starts one container, `prefixd-fnm-probe`, from the
lane's image with the lane's `fastnetmon.conf`, whose notify script only
records each call:

```bash
#!/bin/bash
# Records each notify call's arguments and stdin.
n=$(date +%s%N)
printf '%s\n' "$@" > /calls/$n.args
cat > /calls/$n.stdin
```

Its [verbatim transcript](../../../lab/interop/fixtures/fastnetmon/probe-1.2.9/transcript.txt)
and every [recorded call](../../../lab/interop/fixtures/fastnetmon/probe-1.2.9/calls/)
are committed byte for byte; the excerpts below are copied from the transcript.
Rerun it with `lab/interop/fastnetmon-probe.sh OUT_DIR` for a new FastNetMon
version. The lane's stdin fixture `udp-flood.txt` is an earlier probe's
detected-ban stdin with the victim changed to 203.0.113.40 and trailing
whitespace removed.

### Tools in the image

```text
$ docker run --rm --cpuset-cpus 24-31,56-63 --entrypoint bash ghcr.io/pavel-odintsov/fastnetmon-community:1.2.9@sha256:c154b5b5fd74286719c1c1b97d02157a559926b7749fb5afa958d5faccbd5a0e -c 'for c in curl flock jq python3 wget bash uuidgen mktemp mv awk; do printf "%s: " "$c"; command -v "$c" || echo MISSING; done'
curl: MISSING
flock: /usr/bin/flock
jq: MISSING
python3: MISSING
wget: /usr/bin/wget
bash: /usr/bin/bash
uuidgen: MISSING
mktemp: /usr/bin/mktemp
mv: /usr/bin/mv
awk: /usr/bin/awk
[exit 0]
```

The lane's derived image has `/usr/bin/curl` and `/var/log/fastnetmon_attacks`,
and still lacks `jq`, `python3`, `uuidgen` and `/var/lib/prefixd-fastnetmon`
(transcript, second command).

- **curl:** not shipped. An operator running the official image must add it,
  as the lane's image does.
- **jq and python3:** not shipped, so the script builds JSON with its
  `grep` and `sed` fallback. That fallback joins the attack details into one
  line: prefixd's `raw_details.raw` for step 09 is the details with newlines
  replaced by spaces.
- **State directory:** `/var/lib/prefixd-fastnetmon` does not exist; a script
  that keeps state there must create it.
- **Attack details folder:** the official image lacks
  `/var/log/fastnetmon_attacks`, so FastNetMon logs
  `Can't print attack details to file` on every ban. The derived image creates
  it, and the lane's receipt keeps the files FastNetMon writes there.

### flock(1)

```text
$ docker exec prefixd-fnm-probe bash -c 'flock --version'
flock from util-linux 2.39.3
[exit 0]

$ docker exec prefixd-fnm-probe bash -c 'flock -x /tmp/l -c "touch /tmp/held; sleep 5" & until [ -e /tmp/held ]; do sleep 0.1; done; start=$(date +%s%N); flock -w 1 -x /tmp/l true; rc=$?; echo "flock -w 1 -x returned $rc after $(( ($(date +%s%N) - start) / 1000000 )) ms"; wait'
flock -w 1 -x returned 1 after 1001 ms
[exit 0]
```

`flock -w` gives up after its timeout with status 1 while another process
holds the lock.

### curl reads its config from stdin

```text
$ docker exec prefixd-fnm-probe bash -c 'printf "url = \"http://127.0.0.1:9/from-stdin-config\"\n" | curl -sS -K - --connect-timeout 2'
curl: (7) Failed to connect to 127.0.0.1 port 9 after 0 ms: Couldn't connect to server
[exit 7]
```

The URL exists only in the config on stdin, and curl connected to it, so
`curl -K -` reads options from stdin; a header passed the same way stays out of
argv.

### `fastnetmon_api_client ban` runs the notify script

Yes. `ExecuteBan` adds the address to the ban list and calls
`call_blackhole_actions_per_host`, which starts the notify script on a
detached thread (`src/api.cpp` and `src/fastnetmon_logic.cpp` at v1.2.9). The
probe's recorded calls, in order:

```text
$ sh -c 'for f in *.args; do printf "%s: " "$f"; tr "\n" " " <"$f"; echo; done; wc -c *.stdin; md5sum *.stdin'
01-203.0.113.50-ban.args: 203.0.113.50 other 0 ban
02-203.0.113.50-ban.args: 203.0.113.50 other 0 ban
03-203.0.113.50-unban.args: 203.0.113.50 other 0 unban
04-2001-0db8-0113--0010-ban.args: 2001:0db8:0113::0010 other 0 ban
05-2001-0db8-0113--0010-unban.args: 2001:0db8:0113::0010 other 0 unban
06-203.0.113.60-ban.args: 203.0.113.60 incoming 3625 ban
07-203.0.113.60-unban.args: 203.0.113.60 incoming 3625 unban
1350 01-203.0.113.50-ban.stdin
1350 02-203.0.113.50-ban.stdin
   0 03-203.0.113.50-unban.stdin
1345 04-2001-0db8-0113--0010-ban.stdin
   0 05-2001-0db8-0113--0010-unban.stdin
5607 06-203.0.113.60-ban.stdin
   0 07-203.0.113.60-unban.stdin
9652 total
507ecac6464619b296a84622e3f8fbdf  01-203.0.113.50-ban.stdin
507ecac6464619b296a84622e3f8fbdf  02-203.0.113.50-ban.stdin
d41d8cd98f00b204e9800998ecf8427e  03-203.0.113.50-unban.stdin
6f6569c479ba072c686cac0caa09c769  04-2001-0db8-0113--0010-ban.stdin
d41d8cd98f00b204e9800998ecf8427e  05-2001-0db8-0113--0010-unban.stdin
8796dd2a3794a42d80649982641c9bd4  06-203.0.113.60-ban.stdin
d41d8cd98f00b204e9800998ecf8427e  07-203.0.113.60-unban.stdin
[exit 0]
```

(The transcript keeps a trailing space after each argument list, and after
the second `Query failed` below; the excerpts drop it.)

| Call | Arguments | Stdin |
| --- | --- | --- |
| Manual ban, IPv4 | `203.0.113.50 other 0 ban` | 1350 bytes, all-zero counters |
| Manual ban, IPv6 | `2001:0db8:0113::0010 other 0 ban` | 1345 bytes; first line `IP: 0.0.0.0` |
| Manual unban | `<ip> other 0 unban` | empty |
| Detected ban (NetFlow) | `203.0.113.60 incoming 3625 ban` | 5607 bytes, real counters and flows |
| Detected unban (FastNetMon's timer) | `203.0.113.60 incoming 3625 unban`: the direction and pps of the ban | empty |

`d41d8cd98f00b204e9800998ecf8427e` is the MD5 of empty input: no unban gets
stdin data. FastNetMon runs the unban script without a pipe, so it inherits
the daemon's stdin, `/dev/null` in the container. FastNetMon starts each
script on its own thread and does not wait for it, so a ban and an unban are
independent processes.

`fastnetmon_api_client` exits 0 even when FastNetMon refuses the call; read its
output, not its exit status:

```text
$ docker exec prefixd-fnm-probe /opt/fastnetmon-community/app/bin/fastnetmon_api_client ban 198.51.100.1
Query failed This IP does not belong to our subnets
[exit 0]

$ docker exec prefixd-fnm-probe /opt/fastnetmon-community/app/bin/fastnetmon_api_client unban 203.0.113.50
[exit 0]

$ docker exec prefixd-fnm-probe /opt/fastnetmon-community/app/bin/fastnetmon_api_client unban 203.0.113.50
Query failed
[exit 0]
```

The second unban found no ban (FastNetMon logged
`API: Could not find IPv4 address in ban list`) and ran no script. A manual
ban never expires on FastNetMon's timer: the unban loop skips entries whose
detection source is manual, so only `unban` removes it.

### Manual and automatic stdin differ

No, a manual ban's stdin does not match a detected one
([`01-…-ban.stdin`](../../../lab/interop/fixtures/fastnetmon/probe-1.2.9/calls/01-203.0.113.50-ban.stdin)
and [`06-…-ban.stdin`](../../../lab/interop/fixtures/fastnetmon/probe-1.2.9/calls/06-203.0.113.60-ban.stdin)).
Both are built by the same code: the attack description,
`Attack traffic dump`, then `Flow dump`. A manual ban has no counters, packets
or flows:

| Line | Manual ban | Detected ban |
| --- | --- | --- |
| `Attack type:` | `unknown` | `udp_flood` |
| `Attack direction:` | `other` | `incoming` |
| `Attack protocol:` | `unknown` | `udp` |
| Counters | all 0 | measured (3625 pps, 14 mbps) |
| `Attack traffic dump` | empty | 20 sampled flow lines |
| `Flow dump` | `manually triggered attack`, no trailing newline | per-protocol flow table |
| `IP:` for IPv6 | `0.0.0.0` (FastNetMon prints the unset IPv4 field) | not exercised |

So the script maps every manual ban to vector `unknown` with `pps` 0. A
manual ban creates a mitigation only if prefixd has an `unknown` playbook;
the shipped `configs/playbooks.yaml` has one (`unknown_conservative`). The
script must take the victim from `$1`, never from the `IP:` line.

### Re-banning an address that is already banned

Yes. `ExecuteBan` does not check the ban list. Calls 01 and 02 above are two
`fastnetmon_api_client ban 203.0.113.50` calls: identical arguments and the
same stdin MD5, `507ecac6464619b296a84622e3f8fbdf`. The ban list kept one entry:

```text
$ docker exec prefixd-fnm-probe /opt/fastnetmon-community/app/bin/fastnetmon_api_client get_banlist
203.0.113.50/32
[exit 0]
```

Lane step 03 shows prefixd extending the mitigation. A repeated detection is
different. During a 45 s flood above the threshold, FastNetMon called the
script once, then unbanned only after the flood stopped:

```text
$ python3 -I lab/interop/netflow_v5.py 172.17.0.3:2055 203.0.113.60 --seconds 45
[exit 0]

notify calls during the 45 s flood: 1
notify calls after the flood and the timer unban: 2
```

FastNetMon's log for that address:

```text
2026-11-16 04:10:50,158 [INFO] We have detected attack for 203.0.113.60 using packets per second threshold in direction unknown host group: global
2026-11-16 04:10:51,159 [INFO] Call script for ban client: 203.0.113.60
2026-11-16 04:11:14,158 [INFO] Skip unban operation for 203.0.113.60 because attack is still active
2026-11-16 04:11:24,158 [INFO] Skip unban operation for 203.0.113.60 because attack is still active
2026-11-16 04:11:34,158 [INFO] Skip unban operation for 203.0.113.60 because attack is still active
2026-11-16 04:11:44,158 [INFO] Skip unban operation for 203.0.113.60 because attack is still active
2026-11-16 04:11:54,158 [INFO] Call script for unban client: 203.0.113.60
```

### Detection from replayed flow

Yes. With `netflow = on`, the lab networks in `networks_list` and
`threshold_pps = 1000`, a NetFlow v5 export of 20 UDP flows of 1000 packets
each per second toward one host was detected within 2.3 s (lane step 09) and
about 1 s after the probe's export began (log above).
FastNetMon reported `3625 pps 14 mbps` from its five-second average, then
waited for 20 flow records before calling the script. The exporter is a
standard-library Python generator of Cisco's fixed NetFlow v5 layout, so CI
needs no softflowd or pcap tooling. sFlow, mirror capture and IPFIX were not
exercised.

### IPv6 victims

FastNetMon passes IPv6 victims zero-padded, `2001:0db8:0113::0010` (calls 04
and 05). prefixd canonicalizes the rule's destination (`2001:db8:113::10/128`)
but stores `victim_ip` as received. The script's unban lookup still matched,
because it queries `victim_ip` with the same spelling. An operator or another
source filtering on the canonical form would not find the mitigation. Because
the filter is an exact text match, a mitigation first created with the
canonical spelling and extended by a FastNetMon ban would not be found by
FastNetMon's unban either; that case was not exercised. The lane records the
stored spelling and does not pin it.

## FastNetMon Advanced: unqualified

Nothing about FastNetMon Advanced is qualified by this receipt or by CI.

**Why it is not in CI.** Advanced
(`fastnetmon/fastnetmon-advanced`, 2.0.385 on 2026-11-16) needs a license.
Production licenses run on a 14-day term renewed daily against the vendor's
license servers, and the offline license file is limited to annual and 100G
licenses and is invalidated by a change of IP address, CPU model or count, or
memory ([licensing server](https://fastnetmon.com/fastnetmon-advanced-licensing-server/)).
Ephemeral CI runners cannot hold either. The official Docker Compose
deployment is labeled for testing and evaluation only and needs MongoDB or a
compatible store.

**Unqualified items:**

- The per-host notify script in JSON mode (`notify_script_format: json`),
  which ADR 034 §12 makes the primary Advanced path. The bundled script has no
  JSON mode yet.
- The per-hostgroup notify script (`notify_script_hostgroup_path`) and prefix
  events from total hostgroups.
- The native web callback (`web_callback_url`) into `/v1/signals/fastnetmon`,
  and whether `user:pass@` in the URL becomes Basic auth, whether the callback
  validates HTTPS certificates and against which store, and whether it logs the
  URL. ADR 034 routes this callback through a localhost relay.
- Whether total-hostgroup alerts reach `web_callback_url`.
- Whether `fcli set blackhole <ip>` runs the callback and the scripts.
- How a license is provisioned into the Compose deployment.

**Manual qualification procedure.** Run it on a host that keeps its license
binding, with a trial license from `installer -activate_coupon`:

1. Deploy Advanced next to the FRR lab: the speaker and FRR from
   `fastnetmon-rustbgpd.clab.yml`, prefixd with `prefixd-fastnetmon.yaml`, and
   Advanced's own BGP integration off so prefixd stays the only writer.
2. Configure the host notify script in JSON mode and the hostgroup notify
   script, each with its own token once source-bound tokens land.
3. Trigger a host ban with `fcli set blackhole 203.0.113.10` and with a
   NetFlow flood from `netflow_v5.py`; record each script's arguments and
   stdin, the prefixd mitigation and FRR's tables, then unban and record the
   withdrawal.
4. Point `web_callback_url` at a local receiver that prints headers, with
   `http://u:p@127.0.0.1:8080/...` and with an HTTPS URL on a self-signed
   certificate, to answer the callback checks above.
5. Trigger a total-hostgroup alert and record which outputs fire.
6. Write a dated receipt beside this one with the Advanced version, image
   digest and every command and output.
