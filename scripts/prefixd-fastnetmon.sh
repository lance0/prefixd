#!/bin/bash
# FastNetMon Community → prefixd integration
# Install: cp prefixd-fastnetmon.sh /usr/local/bin/ && chmod +x /usr/local/bin/prefixd-fastnetmon.sh
# Configure in /etc/fastnetmon.conf: notify_script_path = /usr/local/bin/prefixd-fastnetmon.sh
#
# Args from FastNetMon:
#   $1 = victim IP address
#   $2 = direction (incoming/outgoing)
#   $3 = packets per second
#   $4 = action (ban/unban)
# Attack details come via stdin

set -euo pipefail

# Configuration - override via environment or /etc/default/prefixd
PREFIXD_API="${PREFIXD_API:-http://localhost:8080}"
PREFIXD_TOKEN="${PREFIXD_TOKEN:-}"
LOG_FILE="${PREFIXD_LOG:-/var/log/prefixd-fastnetmon.log}"

# Args
IP="${1:-}"
DIRECTION="${2:-incoming}"
PPS="${3:-0}"
ACTION="${4:-ban}"

log() {
    echo "$(date -Iseconds) $*" >> "$LOG_FILE"
}

# Validate required args
if [[ -z "$IP" ]]; then
    log "ERROR: No victim IP provided"
    exit 1
fi

# Read attack details from stdin (FastNetMon sends details here)
RAW_DETAILS=""
if [[ ! -t 0 ]]; then
    RAW_DETAILS=$(cat)
fi

# Map FastNetMon action to prefixd action
API_ACTION="ban"
[[ "$ACTION" == "unban" ]] && API_ACTION="unban"

# Compute stable event ID for idempotency and unban matching
# Hash: victim_ip|direction - same hash for ban and unban so we can match them
#
# Note: This assumes FastNetMon has one active ban per IP/direction at a time.
# If the same IP is banned again after an unban, we get the same event_id,
# which is correct - prefixd only checks for duplicate *ban* events, so
# ban→unban→ban cycles work correctly.
EVENT_ID=$(echo -n "${IP}|${DIRECTION}" | sha256sum | cut -d' ' -f1)

# Infer attack vector from raw details
VECTOR="unknown"
RAW_LOWER=$(echo "$RAW_DETAILS" | tr '[:upper:]' '[:lower:]')
if [[ "$RAW_LOWER" == *"udp"* ]]; then
    VECTOR="udp_flood"
elif [[ "$RAW_LOWER" == *"syn"* ]]; then
    VECTOR="syn_flood"
elif [[ "$RAW_LOWER" == *"ack"* ]]; then
    VECTOR="ack_flood"
elif [[ "$RAW_LOWER" == *"icmp"* ]]; then
    VECTOR="icmp_flood"
fi

# Build JSON payload
TIMESTAMP=$(date -u +%FT%TZ)

# Use jq if available, otherwise build manually
if command -v jq &> /dev/null; then
    PAYLOAD=$(jq -n \
        --arg event_id "$EVENT_ID" \
        --arg timestamp "$TIMESTAMP" \
        --arg source "fastnetmon" \
        --arg victim_ip "$IP" \
        --arg vector "$VECTOR" \
        --arg action "$API_ACTION" \
        --argjson pps "${PPS:-0}" \
        --arg raw "$RAW_DETAILS" \
        --arg direction "$DIRECTION" \
        '{
            event_id: $event_id,
            timestamp: $timestamp,
            source: $source,
            victim_ip: $victim_ip,
            vector: $vector,
            action: $action,
            pps: $pps,
            raw_details: {
                raw: $raw,
                direction: $direction,
                original_action: $action
            }
        }')
else
    # Fallback: manual JSON construction (escape raw details)
    RAW_ESCAPED=$(echo "$RAW_DETAILS" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\n/\\n/g' | tr '\n' ' ')
    PAYLOAD=$(cat <<EOF
{
    "event_id": "$EVENT_ID",
    "timestamp": "$TIMESTAMP",
    "source": "fastnetmon",
    "victim_ip": "$IP",
    "vector": "$VECTOR",
    "action": "$API_ACTION",
    "pps": ${PPS:-0},
    "raw_details": {
        "raw": "$RAW_ESCAPED",
        "direction": "$DIRECTION"
    }
}
EOF
)
fi

# Build auth header
AUTH_HEADER=""
if [[ -n "$PREFIXD_TOKEN" ]]; then
    AUTH_HEADER="-H \"Authorization: Bearer $PREFIXD_TOKEN\""
fi

# Send to prefixd
log "Sending $API_ACTION for $IP ($VECTOR, ${PPS} pps)"

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$PREFIXD_API/v1/events" \
    -H "Content-Type: application/json" \
    ${PREFIXD_TOKEN:+-H "Authorization: Bearer $PREFIXD_TOKEN"} \
    -d "$PAYLOAD" 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [[ "$HTTP_CODE" =~ ^2 ]]; then
    log "SUCCESS ($HTTP_CODE): $BODY"
else
    log "ERROR ($HTTP_CODE): $BODY"
    exit 1
fi
