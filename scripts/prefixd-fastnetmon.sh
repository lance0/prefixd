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
PREFIXD_OPERATOR="${PREFIXD_OPERATOR:-fastnetmon}"
LOG_FILE="${PREFIXD_LOG:-/var/log/prefixd-fastnetmon.log}"
UNBAN_QUERY_RETRIES="${UNBAN_QUERY_RETRIES:-5}"
UNBAN_QUERY_DELAY_SECONDS="${UNBAN_QUERY_DELAY_SECONDS:-1}"

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

if [[ -z "$PREFIXD_OPERATOR" ]]; then
    log "ERROR: PREFIXD_OPERATOR must not be empty"
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

# Build auth header args
AUTH_ARGS=()
if [[ -n "$PREFIXD_TOKEN" ]]; then
    AUTH_ARGS+=(-H "Authorization: Bearer $PREFIXD_TOKEN")
fi

# Handle unban: query prefixd for the active mitigation, then withdraw it
if [[ "$API_ACTION" == "unban" ]]; then
    log "Querying active mitigations for $IP to withdraw"
    ATTEMPT=1
    MITIGATION_IDS=""
    while [[ "$ATTEMPT" -le "$UNBAN_QUERY_RETRIES" ]]; do
        RESPONSE=$(curl -sS -G -w "\n%{http_code}" \
            "$PREFIXD_API/v1/mitigations" \
            -H "Content-Type: application/json" \
            --data-urlencode "status=pending,active,escalated" \
            --data-urlencode "victim_ip=$IP" \
            --data-urlencode "limit=1000" \
            "${AUTH_ARGS[@]}" 2>&1)

        HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
        BODY=$(echo "$RESPONSE" | head -n -1)

        if [[ ! "$HTTP_CODE" =~ ^2 ]]; then
            log "ERROR querying mitigations ($HTTP_CODE): $BODY"
            exit 1
        fi

        if command -v jq &> /dev/null; then
            MITIGATION_IDS=$(echo "$BODY" | jq -r '.mitigations[]?.mitigation_id // empty' 2>/dev/null || true)
        elif command -v python3 &> /dev/null; then
            MITIGATION_IDS=$(printf '%s' "$BODY" | python3 -c 'import json,sys; data=json.load(sys.stdin); print("\n".join(m.get("mitigation_id","") for m in data.get("mitigations", []) if m.get("mitigation_id")))' 2>/dev/null || true)
        else
            MITIGATION_IDS=$(echo "$BODY" | grep -oE '"mitigation_id"[[:space:]]*:[[:space:]]*"[^"]+"' | cut -d'"' -f4 || true)
        fi

        if [[ -n "$MITIGATION_IDS" ]]; then
            break
        fi

        if [[ "$ATTEMPT" -lt "$UNBAN_QUERY_RETRIES" ]]; then
            log "No active mitigations found for $IP (attempt $ATTEMPT/$UNBAN_QUERY_RETRIES), retrying in ${UNBAN_QUERY_DELAY_SECONDS}s"
            sleep "$UNBAN_QUERY_DELAY_SECONDS"
        fi
        ATTEMPT=$((ATTEMPT + 1))
    done

    if [[ -z "$MITIGATION_IDS" ]]; then
        log "No active mitigations found for $IP after $UNBAN_QUERY_RETRIES attempts, nothing to withdraw"
        exit 0
    fi

    WITHDRAW_FAILED=0
    for MID in $MITIGATION_IDS; do
        REASON="FastNetMon unban for $IP (direction=$DIRECTION)"
        if command -v jq &> /dev/null; then
            W_PAYLOAD=$(jq -n --arg operator "$PREFIXD_OPERATOR" --arg reason "$REASON" '{"operator_id": $operator, "reason": $reason}')
        elif command -v python3 &> /dev/null; then
            W_PAYLOAD=$(python3 -c 'import json,sys; print(json.dumps({"operator_id": sys.argv[1], "reason": sys.argv[2]}))' "$PREFIXD_OPERATOR" "$REASON")
        else
            OP_ESCAPED=$(echo "$PREFIXD_OPERATOR" | sed 's/\\/\\\\/g; s/"/\\"/g')
            REASON_ESCAPED=$(echo "$REASON" | sed 's/\\/\\\\/g; s/"/\\"/g')
            W_PAYLOAD="{\"operator_id\":\"$OP_ESCAPED\",\"reason\":\"$REASON_ESCAPED\"}"
        fi

        W_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
            "$PREFIXD_API/v1/mitigations/$MID/withdraw" \
            -H "Content-Type: application/json" \
            "${AUTH_ARGS[@]}" \
            -d "$W_PAYLOAD" 2>&1)

        W_HTTP=$(echo "$W_RESPONSE" | tail -n1)
        W_BODY=$(echo "$W_RESPONSE" | head -n -1)

        if [[ "$W_HTTP" =~ ^2 ]]; then
            log "SUCCESS: Withdrew mitigation $MID for $IP ($W_HTTP)"
        else
            log "ERROR withdrawing $MID ($W_HTTP): $W_BODY"
            WITHDRAW_FAILED=1
        fi
    done

    [[ "$WITHDRAW_FAILED" -eq 1 ]] && exit 1
    exit 0
fi

# Handle ban: generate a unique event ID per occurrence
EVENT_ID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen 2>/dev/null || python3 -c "import uuid; print(uuid.uuid4())")

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

# Send to prefixd
log "Sending $API_ACTION for $IP ($VECTOR, ${PPS} pps, event_id=$EVENT_ID)"

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$PREFIXD_API/v1/events" \
    -H "Content-Type: application/json" \
    "${AUTH_ARGS[@]}" \
    -d "$PAYLOAD" 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [[ "$HTTP_CODE" =~ ^2 ]]; then
    log "SUCCESS ($HTTP_CODE): $BODY"
else
    log "ERROR ($HTTP_CODE): $BODY"
    exit 1
fi
