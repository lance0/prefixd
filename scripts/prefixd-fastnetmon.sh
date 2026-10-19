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
BAN_POST_ATTEMPTS="${BAN_POST_ATTEMPTS:-3}"
BAN_POST_DELAY_SECONDS="${BAN_POST_DELAY_SECONDS:-1}"

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
RAW_LOWER=$(printf '%s' "$RAW_DETAILS" | tr '[:upper:]' '[:lower:]')

# FastNetMon lists every protocol it tracks, including idle ones (e.g.
# "outgoing udp traffic: 0 mbps"). Lines reporting a zero metric carry no
# attack signal, so drop them before matching -- otherwise a SYN flood whose
# details also mention udp at 0 mbps was mislabelled as udp_flood. Details
# without a metric (e.g. "attack type: syn_flood") always survive.
ZERO_METRIC_RE='(^|[^0-9.])0+(\.0+)?[[:space:]]*(mbps|kbps|gbps|bps|pps|kpps|mpps|fps|flows|packets[[:space:]]+per[[:space:]]+second)([^[:alnum:]_]|$)'
RAW_SIGNAL=$(printf '%s\n' "$RAW_LOWER" | grep -vE "$ZERO_METRIC_RE" || true)

# Token boundaries keep "ack" out of "packets" and "attack_type" while
# preserving "syn_flood"/"tcp_syn".
has_token() {
    grep -qE "(^|[^[:alnum:]])$1([^[:alnum:]]|\$)" <<< "$RAW_SIGNAL"
}

# FastNetMon's own verdict comes first: "Attack protocol: tcp|udp|icmp|unknown",
# the protocol with the most packets toward the victim. Background SYN
# counters or TCP ACK samples must not turn a UDP flood into a TCP rule.
ATTACK_PROTOCOL=$(printf '%s\n' "$RAW_LOWER" | awk '/^attack protocol:/ { print $3; exit }' || true)
case "$ATTACK_PROTOCOL" in
    udp) VECTOR="udp_flood" ;;
    icmp) VECTOR="icmp_flood" ;;
    tcp)
        if has_token syn; then
            VECTOR="syn_flood"
        elif has_token ack; then
            VECTOR="ack_flood"
        fi
        ;;
    # No usable protocol line: infer from tokens, TCP flags before udp.
    *)
        if has_token syn; then
            VECTOR="syn_flood"
        elif has_token ack; then
            VECTOR="ack_flood"
        elif has_token icmp; then
            VECTOR="icmp_flood"
        elif has_token udp; then
            VECTOR="udp_flood"
        fi
        ;;
esac

# Reflector source ports (ADR 028). FastNetMon writes one line per sampled
# packet between "Attack traffic dump" and "Flow dump", such as
#   2026-10-19 12:00:00.000000 192.0.2.1:123 > 198.51.100.7:40000 protocol: udp frag: 0  packets: 1 size: 468 bytes ttl: 54 sample ratio: 1
# Sum sampled UDP packets per source port and keep ports whose share is at
# least PREFIXD_SRC_PORT_MIN_SHARE, ranked by share, at most 64. prefixd keeps
# only ports in its reflector-port library. Any parse trouble leaves the
# vector as udp_flood with no ports.
SRC_PORTS=""
if [[ "$VECTOR" == "udp_flood" ]]; then
    SRC_PORTS=$(printf '%s\n' "$RAW_DETAILS" | awk -v share="${PREFIXD_SRC_PORT_MIN_SHARE:-0.2}" '
        BEGIN { if (share !~ /^(0?\.[0-9]+|1(\.0*)?)$/ || share + 0 <= 0) exit 1 }
        /^Attack traffic dump/ { dump = 1; next }
        /^Flow dump/ { dump = 0 }
        !dump { next }
        {
            src = ""; proto = ""; packets = ""
            for (i = 2; i < NF; i++) {
                if ($i == ">") src = $(i - 1)
                else if ($i == "protocol:") proto = $(i + 1)
                else if ($i == "packets:") packets = $(i + 1)
            }
            if (proto != "udp" || packets !~ /^[0-9]+$/) next
            n = split(src, part, ":")
            port = part[n]
            if (n < 2 || port !~ /^[0-9]+$/ || port + 0 > 65535) next
            count[port + 0] += packets
            total += packets
        }
        END {
            if (total <= 0) exit
            for (port in count) if (count[port] >= share * total) print count[port], port
        }' | sort -k1,1nr -k2,2n | head -n 64 | awk '{ printf "%s%s", sep, $2; sep = "," }') || SRC_PORTS=""
    if [[ "$SRC_PORTS" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
        VECTOR="udp_amplification"
    else
        SRC_PORTS=""
    fi
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
        --arg src_ports "$SRC_PORTS" \
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
        } + (if $src_ports == "" then {} else {top_src_ports: ($src_ports | split(",") | map(tonumber))} end)')
else
    # Fallback: manual JSON construction (escape raw details)
    RAW_ESCAPED=$(echo "$RAW_DETAILS" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\n/\\n/g' | tr '\n' ' ')
    SRC_PORTS_FIELD=""
    [[ -n "$SRC_PORTS" ]] && SRC_PORTS_FIELD="\"top_src_ports\": [$SRC_PORTS],"
    PAYLOAD=$(cat <<EOF
{
    "event_id": "$EVENT_ID",
    "timestamp": "$TIMESTAMP",
    "source": "fastnetmon",
    "victim_ip": "$IP",
    "vector": "$VECTOR",
    $SRC_PORTS_FIELD
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

# FastNetMon calls ban once. Retry the same event (same event_id) only when it
# never reached prefixd or a standby or draining controller refused it with 503.
# Any 4xx is final: 409 means this event ID already arrived.
ATTEMPT=1
while true; do
    CURL_STATUS=0
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$PREFIXD_API/v1/events" \
        -H "Content-Type: application/json" \
        "${AUTH_ARGS[@]}" \
        -d "$PAYLOAD" 2>&1) || CURL_STATUS=$?

    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | head -n -1)

    if [[ "$CURL_STATUS" -eq 0 && "$HTTP_CODE" =~ ^2 ]]; then
        log "SUCCESS ($HTTP_CODE): $BODY"
        exit 0
    fi
    if [[ ( "$CURL_STATUS" -ne 0 || "$HTTP_CODE" == "503" ) && "$ATTEMPT" -lt "$BAN_POST_ATTEMPTS" ]]; then
        log "Ban for $IP not accepted (curl=$CURL_STATUS, http=$HTTP_CODE), attempt $ATTEMPT/$BAN_POST_ATTEMPTS; retrying in ${BAN_POST_DELAY_SECONDS}s"
        sleep "$BAN_POST_DELAY_SECONDS"
        ATTEMPT=$((ATTEMPT + 1))
        continue
    fi
    log "ERROR ($HTTP_CODE, curl=$CURL_STATUS): $BODY"
    exit 1
done
