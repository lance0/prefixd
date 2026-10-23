# Manual mitigation and withdrawal

Mitigate one target by hand, confirm the speaker holds the rule, then withdraw
it and read the audit entry.

**When this is you:** a detector missed an attack, or you want to rehearse the
operator path before an incident. You mitigate through the same guardrails a
detector uses and leave a reason behind for the next shift.

**Proven by:** the [dated profile qualification](../reference/qualification/speaker-profiles-2026-10-18.md)
ran this flow against published images on both profiles: exact local rules,
withdrawal with the original actor and reason, and absence of the rule
afterwards. Its documentation peers stayed Idle, so it says nothing about
router export or enforcement.

## 1. Sign in

Start the stack and create an administrator with the [quickstart](../tutorials/quickstart.md).
The `operator` role is enough for this recipe. Save a session cookie:

```bash
curl -sS -c cookies.txt -X POST http://localhost/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"your_password_here"}'
```

A successful login returns your username and role.

## 2. Check that the guardrails reject a protected target

The shipped config safelists `10.0.0.0/8`. Ask for a mitigation inside it:

```bash
curl -sS -b cookies.txt -X POST http://localhost/v1/mitigations \
  -H 'Content-Type: application/json' \
  -d '{"reason":"guardrail check","victim_ip":"10.0.0.5","protocol":"udp",
       "dst_ports":[53],"action":"discard","ttl_seconds":120}'
```

The controller returns `422` before it saves intent or calls the speaker:

```json
{"error":"guardrail violation: IP 10.0.0.5/32 is safelisted"}
```

A TTL outside 30 to 1800 seconds, more than 8 ports or a full quota fails the
same way. See [guardrails](../reference/configuration.md#guardrails).

## 3. Create the mitigation

Police UDP port 53 to 8 Mbps on a shipped inventory address for five minutes:

```bash
curl -sS -b cookies.txt -X POST http://localhost/v1/mitigations \
  -H 'Content-Type: application/json' \
  -d '{"reason":"manual drill","victim_ip":"203.0.113.10","protocol":"udp",
       "dst_ports":[53],"action":"police","rate_bps":8000000,
       "ttl_seconds":300}' | tee mitigation.json | jq '{mitigation_id, status, expires_at}'
MITIGATION_ID=$(jq -r .mitigation_id mitigation.json)
```

Expect one of these outcomes:

- **`201` with `"status": "active"`:** prefixd saved intent and the speaker
  accepted the local request.
- **`202` with `"announcement_outcome": "unconfirmed"`:** intent is saved, but
  the speaker call failed or timed out. Don't resubmit; reconciliation retries
  the announcement.
- **`409`:** an active mitigation already owns this rule. Find it with
  `GET /v1/mitigations?victim_ip=203.0.113.10`.

The dashboard's **Mitigations** page shows the same rule with its expiry.

### Subnet destination

When an attack targets a port across an entire allocation, use **Create
FlowSpec rule** and enter the complete **Destination IP or CIDR**. The preview
shows the full prefix, protocol, ports, action and TTL before submission.

For example, to discard UDP port 443 across `203.0.112.0/22`:

1. Configure a single customer prefix containing that entire `/22`. Resolve
   overlapping allocations and assets owned by other customers first.
2. Explicitly set `guardrails.dst_prefix_minlen: 22` while retaining
   `dst_prefix_maxlen: 32`, then restart with those settings. Defaults refuse
   subnets. For an IPv6 `/48`, use `dst_prefix_minlen_v6: 48` and
   `dst_prefix_maxlen_v6: 128`.
3. Check that no configured or API safelist entry overlaps the range. A single
   protected host inside it refuses the whole rule.
4. Submit the aligned network, precise protocol/port and a short TTL:

```bash
curl -sS -b cookies.txt -X POST http://localhost/v1/mitigations \
  -H 'Content-Type: application/json' \
  -d '{"reason":"UDP port 443 attack across the allocation",
       "victim_ip":"203.0.112.0/22","protocol":"udp","dst_ports":[443],
       "action":"discard","ttl_seconds":300}'
```

`203.0.113.10/22` is refused with a suggestion for `203.0.112.0/22`; prefixd
never clears destination host bits silently. IPv6 works the same way, for
example `2001:db8:1234::/48`. Source-prefix and amplification selectors retain
their existing opt-ins and protocol/family checks.

One CIDR consumes one quota slot. A police rate covers the matching flow
across the whole destination, not a separate allowance per address. Withdrawal
and expiry remove that exact rule. Safelisting a host inside it requests
withdrawal of the entire rule; prefixd does not create split replacements.

Use the mitigation detail page and its **Report** action for CIDRs. These show
that exact target; host history and host events are not aggregated into a subnet
report. The speaker read-back below establishes local state only. Before a
controller downgrade, withdraw CIDR rules and finish pending withdrawals on
the original target. Detector ingestion and RTBH still accept only host IPs.

## 4. Check the speaker's local state

rustbgpd reports prefixd's rules as retained local intent:

```bash
docker compose exec rustbgpd rbgp --addr unix:///run/rustbgpd/grpc.sock \
  --json flowspec received 0.0.0.0 --family ipv4_flowspec
```

On the `gobgp` profile, read GoBGP's accepted local RIB instead:

```bash
docker compose exec gobgp gobgp global rib -a ipv4-flowspec
```

Either listing shows the rule for `203.0.113.10/32`. Neither proves that a peer
received it or that a router installed it.

## 5. Withdraw with a reason

```bash
curl -sS -b cookies.txt -X POST \
  "http://localhost/v1/mitigations/$MITIGATION_ID/withdraw" \
  -H 'Content-Type: application/json' \
  -d '{"reason":"drill complete"}' | jq '{mitigation_id, status, withdrawn_at}'
```

prefixd saves the withdrawal intent, actor and reason before it calls the
speaker. A successful delete returns `"status": "withdrawn"`. If the speaker
call fails, the request returns an error, the mitigation keeps its status, and
reconciliation retries the same deletion with the original actor and reason.
It never re-announces a rule with pending withdrawal.

In the dashboard, **Withdraw** on a mitigation's detail page opens a
confirmation dialog with an optional reason, then sends the same request.

## 6. Read the audit entry and confirm absence

```bash
curl -sS -b cookies.txt 'http://localhost/v1/audit?limit=5' \
  | jq '.entries[] | {action, actor_id, target_id, details}'
```

The newest entry has `"action": "withdraw"`, your username as `actor_id`, the
mitigation ID as `target_id`, and a `details.reason` of `admin: drill complete`.
The entry before it has `"action": "create"` for the same `target_id`, with
your username as `actor_id` and the rule's scope, action, TTL and origin mode in
`details`.

Repeat the step 4 command: the rule for `203.0.113.10/32` is gone.

## If something goes wrong

- **`401`:** the cookie expired or the login failed. Repeat step 1.
- **`403`:** your account has the `viewer` role; this recipe needs `operator`
  or `admin`.
- **`500` on withdrawal:** check `docker compose logs prefixd-rustbgpd rustbgpd`.
  The withdrawal stays pending and retries; see
  [withdrawal recovery](../reference/speaker-backends.md#withdrawal-recovery).
- **Anything else:** see [troubleshooting](../how-to/troubleshooting.md).
