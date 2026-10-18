# Dry-run rollout

Run the full decision pipeline without announcing anything, review what it
would have done, then switch to enforcement without replaying the rehearsal.

**When this is you:** you're connecting a detector or changing playbooks and
want to see which mitigations prefixd would create before any rule reaches the
speaker. Dry-run is global: it applies to every source and playbook.

**Proven by:** the controller integration suite runs in dry-run by default, and
a reconciliation unit test checks that dry-run sends no speaker call.
Integration tests check that enforced reconciliation never announces a dry-run
mitigation. Against PostgreSQL and the real binary, they check that enforced
startup refuses rehearsal intent until the retirement flag clears it without
contacting the speaker. The dated profile qualification ran in enforced mode
and does not cover the switch.

## 1. Start in dry-run

Set the mode in the profile's main config before you start the controller:
`configs/prefixd.yaml` for `rustbgpd`, `configs/prefixd-gobgp.yaml` for `gobgp`.

```yaml
mode: dry-run
```

If this deployment already ran enforced and has active rules, stop here. Follow
the [upgrade guide](../how-to/upgrading.md#pending-withdrawals-and-rollback)
first: dry-run cannot withdraw rules that were announced in enforced mode.

Start the stack, or restart the controller if it's already running. Config
reload doesn't change the mode:

```bash
docker compose --profile rustbgpd up -d --pull always --no-build
docker compose --profile rustbgpd restart prefixd-rustbgpd
```

Sign in as in the [manual mitigation recipe](manual-mitigation.md#1-sign-in),
then confirm the running mode:

```bash
curl -sS -b cookies.txt http://localhost/v1/config/settings | jq .settings.mode
```

The result must be `"dry-run"`. If it still reads `"enforced"`, the container
kept an older copy of the file; recreate it with
`docker compose --profile rustbgpd up -d --force-recreate --no-deps prefixd-rustbgpd`.

## 2. Send signals

Point your detector at prefixd, or send a sample event for a shipped inventory
address:

```bash
curl -sS -b cookies.txt -X POST http://localhost/v1/events \
  -H 'Content-Type: application/json' \
  -d '{"timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
       "source":"fastnetmon","victim_ip":"203.0.113.10",
       "vector":"udp_flood","bps":5000000000,"confidence":0.9}'
```

A `202` with `"status": "accepted"` and a `mitigation_id` means policy created
a mitigation. The shipped `udp_flood_police_first` playbook selects its first
step: police at 5 Mbps for 120 seconds. Other statuses, such as
`accepted_no_mitigation`, mean policy or correlation chose not to act; see
[ingest attack event](../reference/api.md#ingest-attack-event).

Guardrails still apply. A safelisted target returns `422` exactly as it does in
enforced mode.

## 3. Review what would have been announced

```bash
curl -sS -b cookies.txt \
  'http://localhost/v1/mitigations?status=active' \
  | jq '.mitigations[] | {mitigation_id, victim_ip, action_type, rate_bps, expires_at}'
```

The dashboard shows the same mitigations, and Prometheus records the same
creation metrics. The speaker's local state stays empty:

```bash
docker compose exec rustbgpd rbgp --addr unix:///run/rustbgpd/grpc.sock \
  --json flowspec received 0.0.0.0 --family ipv4_flowspec
```

Adjust playbooks, inventory or correlation until the list matches what you
expect, and repeat this step.

## 4. Clear the rehearsal before enforcing

Each mitigation records the mode that created it. Rehearsal mitigations are
never announced, even after you switch modes, and enforced startup refuses to
run while any are still unexpired. To clear them, withdraw them in dry-run or
wait until their TTLs expire, then confirm that none remain:

```bash
curl -sS -b cookies.txt \
  'http://localhost/v1/mitigations?status=pending,active,escalated' | jq .count
```

The count must be `0`. Withdrawals made in dry-run stay local simulations and
never reach the speaker. You can skip this step and use the retirement flag in
step 5 instead.

## 5. Switch to enforced

Set `mode: enforced` in the same file, restart the controller, and confirm the
mode as in step 1:

```bash
docker compose --profile rustbgpd restart prefixd-rustbgpd
curl -sS -b cookies.txt http://localhost/v1/config/settings | jq .settings.mode
```

If rehearsal mitigations remain, the controller exits instead. Its log names the
count and `--retire-dry-run-intent`. Run the flag once with the same
configuration. It withdraws each rehearsal mitigation locally, with an audit
entry, and exits without contacting the speaker. Then start the controller
again:

```bash
docker compose --profile rustbgpd logs --tail 20 prefixd-rustbgpd
docker compose --profile rustbgpd run --rm --no-deps prefixd-rustbgpd \
  --config /etc/prefixd --retire-dry-run-intent
docker compose --profile rustbgpd up -d prefixd-rustbgpd
```

Sessions are stored in PostgreSQL, so your cookie survives the restart. From
now on, new mitigations are announced.
To go back to dry-run later, withdraw active rules and drain pending cleanup
first, as the [upgrade guide](../how-to/upgrading.md#pending-withdrawals-and-rollback)
describes.
