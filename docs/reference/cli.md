# CLI Reference

`prefixdctl` is the command-line tool for interacting with prefixd.

## Installation

The CLI is built alongside the daemon:

```bash
cargo build --release
./target/release/prefixdctl --help
```

Or use the Docker image:

```bash
docker run --rm ghcr.io/lance0/prefixd:latest prefixdctl --help
```

## Configuration

### Environment Variables

```bash
export PREFIXD_API=http://localhost         # API endpoint (nginx entrypoint)
export PREFIXD_API_TOKEN=your-token-here    # Bearer token
```

### Command-Line Options

```bash
prefixdctl -a http://localhost -t $TOKEN <command>

# Direct daemon access (without nginx)
prefixdctl -a http://127.0.0.1:8080 -t $TOKEN <command>
```

| Option | Env Var | Description |
|--------|---------|-------------|
| `-a, --api` | `PREFIXD_API` | API endpoint URL |
| `-t, --token` | `PREFIXD_API_TOKEN` | Bearer token for authentication |
| `-f, --format` | - | Output format: `table` (default) or `json` |

HTTP command examples below assume bearer mode with a configured token. The CLI
does not perform session login; the default Compose credentials mode needs a
session-capable client such as curl.

---

## Daemon startup options

The daemon, `prefixd`, accepts `--adopt-legacy-speaker` with `--config PATH`.
This one-shot command adopts existing database history onto its verified original
speaker configuration, audits the change and exits before connecting to the
speaker or starting the API. It cannot force a different target or replace an
existing assignment. Follow the backup and stop procedure in the
[speaker ownership upgrade guide](../how-to/upgrading.md#speaker-ownership-upgrade)
before using it. This is not a `prefixdctl` command.

`prefixd --retire-dry-run-intent` is the other one-shot option. It retires this
POP's unexpired dry-run mitigations through audited, local-only withdrawals and
exits before connecting to the speaker or starting the API. Enforced startup
refuses to run until it does. It can't be combined with
`--adopt-legacy-speaker`; see
[mitigation origin mode](../how-to/upgrading.md#mitigation-origin-mode).

## Commands

### Status

```bash
# Overview of daemon status
prefixdctl status

# Illustrative output with rustbgpd:
# Status: healthy
# Active Mitigations: 12
# Speaker: rustbgpd
#   Daemon version: <rustbgpd-version>
#   Daemon uptime: 43200s
#   Daemon ready: true
#   Observed at: 2026-10-18T12:00:00Z
#
# Components:
#   ● Database: connected
#   ● Peer observation: connected
#
# BGP Sessions:
#   ● 192.0.2.1 - established
#   ● 192.0.2.2 - established
```

### Peers

```bash
# BGP session status
prefixdctl peers

# Illustrative output:
# PEER                            STATE
# --------------------------------------------------
# 192.0.2.1                       established
# 192.0.2.2                       established
```

---

## Mitigations

### List Mitigations

```bash
# Newest mitigations in every status (up to --limit, default 50)
prefixdctl mitigations list

# Filter by status
prefixdctl mitigations list --status active
prefixdctl mitigations list --status expired

# Filter by customer
prefixdctl mitigations list --customer acme

# Combine filters
prefixdctl mitigations list --status active --customer acme

# Limit results
prefixdctl mitigations list --limit 50

# JSON output
prefixdctl -f json mitigations list
```

### Get Mitigation

```bash
prefixdctl mitigations get <id>

# Example output:
# ID:          abc123
# Status:      Active
# Customer:    acme
# Destination: 203.0.113.10/32
# Protocol:    UDP
# Ports:       !53
# Action:      police (10 Mbps)
# TTL:         120s (expires in 45s)
# Created:     2026-01-18T10:30:00Z
```

### Withdraw Mitigation

```bash
# Withdraw with reason
prefixdctl mitigations withdraw <id> --reason "false positive"

# Example output:
# Mitigation abc123 withdrawn
```

---

## Operators

### Create Operator

Operator commands connect directly to PostgreSQL and require `DATABASE_URL`.
Omit `--password` for hidden input on a controlling terminal. Without a terminal,
the prompt fails; `--password` requires an explicit value for noninteractive use.
An explicit value can appear in shell history and process arguments.

```bash
# Hidden interactive password prompt
prefixdctl operators create --username admin --role admin

# Explicit value (consider shell history and process visibility)
prefixdctl operators create --username jsmith --role operator --password "$OPERATOR_PASSWORD"

# Roles: admin, operator, viewer
```

### List Operators

```bash
prefixdctl operators list

# Example output:
# USERNAME    ROLE      CREATED
# admin       admin     2026-01-15T08:00:00Z
# jsmith      operator  2026-01-16T14:30:00Z
```

---

## Safelist

The safelist prevents mitigations on protected IPs (infrastructure, etc.).

### List Safelist

```bash
prefixdctl safelist list

# Example output:
# PREFIX          REASON              ADDED BY    ADDED
# 10.0.0.1/32     Router loopback     admin       2026-01-15
# 10.0.0.2/32     DNS resolver        admin       2026-01-15
```

### Add to Safelist

```bash
prefixdctl safelist add 10.0.0.1/32 --reason "router loopback"
```

### Remove from Safelist

```bash
prefixdctl safelist remove 10.0.0.1/32
```

---

## Operations

### Reload Configuration

Hot-reload inventory and playbooks without restarting:

```bash
prefixdctl reload

# Example output:
# Configuration reloaded
# Inventory: 150 customers, 2340 assets
# Playbooks: 12 policies
```

### Show Applied Migrations

```bash
# Requires DATABASE_URL to be set
prefixdctl migrations
```

### Send a Corroborating Signal

Post a [corroborating signal](../how-to/detectors/corroborating-signals.md)
from a source configured with `mode: corroborating` in
`correlation.yaml`. Useful for ad-hoc testing or for coarse telemetry
scripts that don't carry a victim `/32`.

```bash
prefixdctl send-corroborator \
  --source router-cpu \
  --pop iad1 \
  --customer-id cust_42 \
  --confidence 0.6 \
  --vector udp_flood
```

At least one of `--customer-id`, `--pop`, `--service-id`, `--interface`
is required. The source's configured `match_dimensions` determine which
of these the server actually accepts. JSON output mode
(`prefixdctl -f json send-corroborator …`) returns the raw response
including `signal_id` and `attached_group_ids`.

---

## Output Formats

### Table (default)

Human-readable tables:

```bash
prefixdctl mitigations list

# ID        STATUS    CUSTOMER  DESTINATION       ACTION    TTL
# abc123    Active    acme      203.0.113.10/32   police    45s
# def456    Active    acme      203.0.113.20/32   discard   120s
```

### JSON

Machine-readable JSON:

```bash
prefixdctl -f json mitigations list

# [
#   {
#     "id": "abc123",
#     "status": "active",
#     "customer_id": "acme",
#     "dst_prefix": "203.0.113.10/32",
#     "action": "police",
#     "rate_bps": 10000000,
#     "ttl_remaining_seconds": 45
#   }
# ]
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Connection failed |
| 3 | Authentication failed |
| 4 | Not found |
| 5 | Validation error |

---

## Examples

### Respond to False Positive

```bash
# Check mitigation details
prefixdctl mitigations get abc123

# Withdraw if false positive
prefixdctl mitigations withdraw abc123 --reason "customer confirmed legitimate traffic"

# Add to safelist to prevent future mitigations
prefixdctl safelist add 203.0.113.10/32 --reason "high-traffic legitimate service"
```

### Monitor During Attack

```bash
# Watch active mitigations
watch -n 5 'prefixdctl mitigations list --status active'

# Check BGP session health
prefixdctl peers

# Get detailed status
prefixdctl status
```

### Automation

```bash
# JSON output for scripting
ACTIVE=$(prefixdctl -f json mitigations list --status active | jq length)
echo "Active mitigations: $ACTIVE"

# Bulk operations
prefixdctl -f json mitigations list --status active | \
  jq -r '.[].id' | \
  xargs -I {} prefixdctl mitigations withdraw {} --reason "bulk cleanup"
```
