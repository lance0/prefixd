# FastNetMon Community Integration

This guide covers integrating FastNetMon Community Edition with prefixd for automated FlowSpec-based DDoS mitigation.

## Overview

FastNetMon detects DDoS attacks via NetFlow/sFlow analysis and calls a notify script when attacks are detected. The `prefixd-fastnetmon.sh` script bridges FastNetMon to prefixd's HTTP APIs (event ingest + mitigation withdraw).

```
FastNetMon → notify_script → prefixd → GoBGP → Routers (FlowSpec)
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
```

3. Configure FastNetMon to use the script. Edit `/etc/fastnetmon.conf`:

```ini
notify_script_path = /usr/local/bin/prefixd-fastnetmon.sh
notify_script_pass_details = on
```

4. Restart FastNetMon:

```bash
sudo systemctl restart fastnetmon
```

## How It Works

### Ban Flow

1. FastNetMon detects attack on victim IP
2. Calls script with args: `$1=IP $2=direction $3=pps $4=ban`
3. Script generates a unique UUID `event_id` for each ban occurrence
4. Sends `POST /v1/events` with `action: "ban"`
5. prefixd evaluates playbook, creates mitigation, announces FlowSpec

### Unban Flow

1. FastNetMon attack subsides
2. Calls script with args: `$1=IP $2=direction $3=pps $4=unban`
3. Script queries `GET /v1/mitigations?status=pending,active,escalated&victim_ip=<ip>`
4. Script withdraws each matching mitigation via `POST /v1/mitigations/{id}/withdraw`
5. Script retries lookup briefly to handle ban/unban races

### Idempotency

Each ban uses a unique `event_id`, which prevents permanent duplicate collisions after a ban→withdraw→re-ban cycle and allows ongoing attacks to extend TTL through scope matching.

Unban correlation is done by querying active mitigations for the victim IP and withdrawing them directly.

## Vector Detection

The script infers attack vectors from FastNetMon's stdin details:

| FastNetMon Detail | prefixd Vector |
|------------------|----------------|
| Contains "udp"   | `udp_flood`    |
| Contains "syn"   | `syn_flood`    |
| Contains "ack"   | `ack_flood`    |
| Contains "icmp"  | `icmp_flood`   |
| Other            | `unknown`      |

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
2. **401 Unauthorized**: Check `PREFIXD_TOKEN` matches prefixd config
3. **422 Unprocessable**: Victim IP not in prefixd inventory
4. **No mitigation created**: Check playbooks match the vector
5. **400 on withdraw**: Ensure script sends `operator_id` (set `PREFIXD_OPERATOR`, default: `fastnetmon`)

### Debug mode

Add `set -x` at the top of the script for verbose output.

## Advanced: Custom Vector Mapping

Edit the script's vector detection section to add custom mappings:

```bash
# Add DNS amplification detection
if [[ "$RAW_LOWER" == *"port 53"* ]] && [[ "$RAW_LOWER" == *"udp"* ]]; then
    VECTOR="dns_amplification"
fi
```

Note: Custom vectors require matching playbook rules in prefixd.

## Security Considerations

1. **Token security**: Store `PREFIXD_TOKEN` in `/etc/default/prefixd` with restricted permissions:
   ```bash
   sudo chmod 600 /etc/default/prefixd
   ```

2. **Network security**: Use TLS for production deployments (configure `PREFIXD_API=https://...`)

3. **Log rotation**: Configure logrotate for `/var/log/prefixd-fastnetmon.log`
