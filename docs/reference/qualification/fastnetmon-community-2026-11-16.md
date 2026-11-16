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
| Run | 2026-11-16T03:40:59Z, local, Linux 7.0.0-30-generic, containerlab 0.74.3, lab nodes pinned to 16 CPUs. Ten steps, 7 s of steps |
| prefixd | 0.27.0, local image `sha256:71c99a06881d…` built from main `583e200` plus this change's lab files |
| FastNetMon | Community 1.2.9, `ghcr.io/pavel-odintsov/fastnetmon-community:1.2.9@sha256:c154b5b5fd74286719c1c1b97d02157a559926b7749fb5afa958d5faccbd5a0e` (index digest, image built 2026-05-31), plus Ubuntu's `curl 8.5.0-2ubuntu10.16` ([`fastnetmon.Dockerfile`](../../../lab/interop/fastnetmon.Dockerfile)) |
| Speaker | rustbgpd 0.83.0, `ghcr.io/lance0/rustbgpd:0.83.0@sha256:79a6a584b59dae0574a8f5240a4e8f68454fdfede1b7fe31ed446fcf92a30979` |
| Router | FRR 10.7.1, `quay.io/frrouting/frr:10.7.1@sha256:e995beaa50fdc9edb35eadcfefa29b7f062cc06f2b812613789b68fa541554d2` |
| Topology | [`fastnetmon-rustbgpd.clab.yml`](../../../lab/interop/fastnetmon-rustbgpd.clab.yml): the FRR lab's eBGP session (speaker AS 65010 at 10.0.0.1, FRR AS 65002 at 10.0.0.2, IPv4 and IPv6 FlowSpec). FastNetMon shares prefixd's network namespace, so the script posts to `http://127.0.0.1:8080` |
| FastNetMon settings | [`fastnetmon.conf`](../../../lab/interop/configs/fastnetmon.conf): NetFlow on UDP 2055, `threshold_pps = 1000`, `ban_for_pps = on`, `ban_time = 1900`, networks `203.0.113.0/24` and `2001:db8:113::/48`, `notify_script_path` the bundled script, ExaBGP and GoBGP off |
| prefixd settings | [`prefixd-fastnetmon.yaml`](../../../lab/interop/configs/prefixd-fastnetmon.yaml) (`auth.mode: none`, correlation `min_sources: 1`) and [`playbooks-fastnetmon.yaml`](../../../lab/interop/configs/playbooks-fastnetmon.yaml): `unknown` polices at 1 Mbit/s, `udp_flood` at 5 Mbit/s, both 600 s |
| Driver | [`fastnetmon_frr.py`](../../../lab/interop/fastnetmon_frr.py) through [`run-fastnetmon.sh`](../../../lab/interop/run-fastnetmon.sh) (`just interop-fastnetmon`); the Interop workflow runs the same lane as `FastNetMon Community (rustbgpd/FRR)` |

Each trigger waits for the script's outcome line in its own log
(`SUCCESS`, `NO_MITIGATION` or `ERROR` for a ban; `Withdrew`, nothing found
or `ERROR` for an unban), bounded at 60 s, before the next trigger. The step
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
| 09 netflow-detected-ban | NetFlow v5 UDP flood toward 203.0.113.30 ([`netflow_v5.py`](../../../lab/interop/netflow_v5.py)) | FastNetMon detected 3625 pps incoming and ran the script with real attack details; `udp_flood`, police 5 Mbit/s, event `pps` 3625, `raw_details.direction` `incoming` | `to 203.0.113.30/32 proto =17 dstp =53,=123`, `FS:rate 625000.000000` |
| 10 detected-api-unban | `unban 203.0.113.30` | Withdrawn | Empty |

A portless UDP flood takes the lab service's allowed UDP ports (53 and 123
in [`inventory.yaml`](../../../lab/interop/configs/inventory.yaml)); a
manual ban carries no protocol, so its rule matches only the destination.

Step 09 took 2.4 s from starting the exporter to FRR holding the rule:
FastNetMon crossed `threshold_pps`, collected `ban_details_records_count`
(20) flow records in 0.73 s, then ran the script. This is one synthetic flow
pattern at one threshold, not a detection-quality or timing claim.

### Seeded failure

With the script's `PREFIXD_API` pointed at port 8081, where nothing listens,
the lane failed at its first step (run 2026-11-16T03:38:00Z, exit 1):

```text
FAIL: 01-api-ban: the script reported ERROR (None, status=None), expected SUCCESS with status=accepted: ERROR (000, curl=7):
```

The script had logged two `not accepted (curl=7, http=000)` retries before
its `ERROR` line. The unit tests in
[`test_fastnetmon_frr.py`](../../../lab/interop/test_fastnetmon_frr.py)
cover the outcome parser; with its per-victim check removed, the test that a
ban for 203.0.113.1 is not 203.0.113.10's outcome fails.

## FastNetMon Community lab checks

Each answer comes from the pinned 1.2.9 image unless it says otherwise. The
argument and stdin answers also come from a probe container, run on
2026-11-16 with the lane's FastNetMon settings, whose notify script recorded
each call:

```bash
#!/bin/bash
n=$(date +%s%N)
printf '%s\n' "$@" > /captures/$n.args
cat > /captures/$n.stdin
```

The probe ran `fastnetmon_api_client ban 203.0.113.50` twice, `unban
203.0.113.50` twice, `ban 198.51.100.1` (outside `networks_list`), `ban
2001:db8:113::10`, and a NetFlow flood toward 203.0.113.60 with
`netflow_v5.py`. A fresh probe then ran a 45 s flood toward 203.0.113.60 to
check re-detection. The lane's
stdin fixture is the probe's detected-ban stdin with the victim changed to
203.0.113.40 and trailing whitespace removed.

### Tools in the image

```text
$ docker run --rm --entrypoint sh <pinned image> -c 'for c in curl flock jq python3 wget bash uuidgen; do printf "%s: " $c; command -v $c || echo MISSING; done'
curl: MISSING
flock: /usr/bin/flock
jq: MISSING
python3: MISSING
wget: /usr/bin/wget
bash: /usr/bin/bash
uuidgen: MISSING
```

- **curl:** not shipped. The lane's derived image adds Ubuntu 24.04's `curl`
  (8.5.0); an operator running the official image needs the same.
- **flock(1):** shipped, `flock from util-linux 2.39.3`. `flock -w 1 -x`
  on a held lock returned 1 after one second.
- **jq and python3:** not shipped, so the script builds JSON with its
  `grep` and `sed` fallback. That fallback joins the attack details into one
  line: prefixd's `raw_details.raw` for step 09 is the details with newlines
  replaced by spaces.
- Also present: `mktemp`, `mv`, `awk`, `/proc/sys/kernel/random/uuid` (the
  script's event ID source). `curl -K -` reads a config from stdin in 8.5.0.
  `/var/lib/prefixd-fastnetmon` does not exist.
- The image lacks `/var/log/fastnetmon_attacks`, so FastNetMon logs
  `Can't print attack details to file` on every ban. The derived image
  creates it, and the receipt keeps the files FastNetMon writes there.

### `fastnetmon_api_client ban` runs the notify script

Yes. `ExecuteBan` adds the address to the ban list and calls
`call_blackhole_actions_per_host`, which starts the notify script on a
detached thread (`src/api.cpp` and `src/fastnetmon_logic.cpp` at v1.2.9).
FastNetMon's log shows `Call script for ban client: 203.0.113.10`. A probe
container with the same image and settings, whose notify script saved its
arguments and stdin, recorded these arguments; the lane's script log and
prefixd events agree on the pps and direction:

| Ban | Arguments |
| --- | --- |
| Manual, IPv4 | `203.0.113.50 other 0 ban` |
| Manual, IPv6 | `2001:0db8:0113::0010 other 0 ban` |
| Detected (NetFlow) | `203.0.113.60 incoming 3625 ban` |
| Manual unban | `203.0.113.50 other 0 unban` |
| Detected unban | Not recorded. From the source, the direction and pps stored with the ban |

Other behavior that matters to the script:

- `fastnetmon_api_client` exits 0 even when FastNetMon refuses the call. It
  prints `Query failed This IP does not belong to our subnets` for an address
  outside `networks_list`, and `Query failed` for an unban of an address that
  is not banned. Read its output, not its exit status.
- A manual ban is never unbanned by FastNetMon's timer: the unban loop skips
  entries whose detection source is manual. Only `unban` removes it.
- The unban script gets no stdin data. FastNetMon runs it without a pipe,
  so it inherits the daemon's stdin (`/dev/null` in the container).
- FastNetMon starts each script on its own thread and does not wait for it,
  so a ban and an unban are independent processes.

### Manual and automatic stdin differ

No, a manual ban's stdin does not match an automatic one. Both are built by
the same code: the attack description, `Attack traffic dump`, then
`Flow dump`. A manual ban has no counters, packets or flows:

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

Yes. `ExecuteBan` does not check the ban list: a second
`fastnetmon_api_client ban` for a banned address runs the script again with
identical arguments and byte-identical stdin (same MD5), and the ban list keeps
one entry. Step 03 shows prefixd extending the mitigation. A repeated detection
is different: during a 45 s flood above the threshold, FastNetMon detected and
banned the address once and called the script once.

### Detection from replayed flow

Yes. With `netflow = on`, the lab networks in `networks_list` and
`threshold_pps = 1000`, a NetFlow v5 export of 20 UDP flows of 1000 packets
each per second toward one host was detected within 2.4 s (step 09).
FastNetMon reported `3625 pps 14 mbps` from its five-second average, then
waited for 20 flow records before calling the script. The exporter is a
standard-library Python generator of Cisco's fixed NetFlow v5 layout, so CI
needs no softflowd or pcap tooling. sFlow, mirror capture and IPFIX were not
exercised.

### IPv6 victims

FastNetMon passes IPv6 victims zero-padded, `2001:0db8:0113::0010`. prefixd
canonicalizes the rule's destination (`2001:db8:113::10/128`) but stores
`victim_ip` as received. The script's unban lookup still matched, because it
queries `victim_ip` with the same spelling. An operator or another source
filtering on the canonical form would not find the mitigation. Because the
filter is an exact text match, a mitigation first created with the canonical
spelling and extended by a FastNetMon ban would not be found by FastNetMon's
unban either; that case was not exercised. The lane records the stored
spelling and does not pin it.

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
