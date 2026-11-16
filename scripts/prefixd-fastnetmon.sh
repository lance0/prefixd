#!/bin/bash
# FastNetMon Community -> prefixd integration, as an ingest client (ADR 034).
# Install: cp prefixd-fastnetmon.sh /usr/local/bin/ && chmod +x /usr/local/bin/prefixd-fastnetmon.sh
# Configure in /etc/fastnetmon.conf: notify_script_path = /usr/local/bin/prefixd-fastnetmon.sh
#
# Args from FastNetMon:
#   $1 = victim IP address (IPv6 may be zero-padded; prefixd stores it canonical)
#   $2 = direction (incoming/outgoing)
#   $3 = packets per second
#   $4 = action (ban/unban)
# A ban's attack details come on stdin. The victim always comes from $1: a
# manual ban's stdin says "IP: 0.0.0.0" for an IPv6 victim.
#
# Both actions post an event to /v1/events under source "fastnetmon" with an
# ingest token bound to that source. An unban names the victim; prefixd
# withdraws the live mitigations fastnetmon created for it on that POP, so the
# script keeps no state between ban and unban.
#
# Needs bash and curl only. The token is read from PREFIXD_TOKEN_FILE, or from
# PREFIXD_TOKEN, and handed to curl in a config on stdin (curl -K -), never on
# its command line.

set -euo pipefail

# Configuration - environment, or /etc/default/prefixd when present.
PREFIXD_DEFAULTS_FILE="${PREFIXD_DEFAULTS_FILE:-/etc/default/prefixd}"
if [[ -r "$PREFIXD_DEFAULTS_FILE" ]]; then
    # shellcheck source=/dev/null
    . "$PREFIXD_DEFAULTS_FILE"
fi

PREFIXD_API="${PREFIXD_API:-http://localhost:8080}"
PREFIXD_TOKEN_FILE="${PREFIXD_TOKEN_FILE:-}"
PREFIXD_TOKEN="${PREFIXD_TOKEN:-}"
# "none" only for a controller with http.auth.mode none, which needs no token.
PREFIXD_AUTH_MODE="${PREFIXD_AUTH_MODE:-credentials}"
LOG_FILE="${PREFIXD_LOG:-/var/log/prefixd-fastnetmon.log}"
EVENT_POST_ATTEMPTS="${EVENT_POST_ATTEMPTS:-3}"
EVENT_POST_DELAY_SECONDS="${EVENT_POST_DELAY_SECONDS:-1}"
EVENT_CONNECT_TIMEOUT_SECONDS="${EVENT_CONNECT_TIMEOUT_SECONDS:-5}"
EVENT_MAX_TIME_SECONDS="${EVENT_MAX_TIME_SECONDS:-15}"

# Args
IP="${1:-}"
DIRECTION="${2:-incoming}"
PPS="${3:-0}"
ACTION="${4:-ban}"

log() {
    echo "$(date -u +%Y-%m-%dT%H:%M:%S%z) $*" >> "$LOG_FILE"
}

if ! command -v curl &> /dev/null; then
    log "ERROR: curl is required"
    exit 1
fi

if [[ -z "$IP" ]]; then
    log "ERROR: No victim IP provided"
    exit 1
fi
# Only address characters reach the JSON body; prefixd validates the rest.
if [[ ! "$IP" =~ ^[0-9A-Fa-f:.]+$ ]]; then
    log "ERROR: victim IP has unexpected characters"
    exit 1
fi
[[ "$PPS" =~ ^[0-9]+$ ]] || PPS=0

for setting in EVENT_POST_ATTEMPTS EVENT_POST_DELAY_SECONDS EVENT_CONNECT_TIMEOUT_SECONDS EVENT_MAX_TIME_SECONDS; do
    if [[ ! "${!setting}" =~ ^[0-9]+$ ]]; then
        log "ERROR: $setting must be a whole number"
        exit 1
    fi
done
# curl reads 0 as "no limit", which would leave an attempt unbounded; a zero
# retry delay is fine.
for setting in EVENT_CONNECT_TIMEOUT_SECONDS EVENT_MAX_TIME_SECONDS; do
    if [[ "${!setting}" =~ ^0+$ ]]; then
        log "ERROR: $setting must be at least 1"
        exit 1
    fi
done

# The token file wins over the variable. Its value is never logged.
TOKEN="$PREFIXD_TOKEN"
if [[ -n "$PREFIXD_TOKEN_FILE" ]]; then
    if [[ ! -r "$PREFIXD_TOKEN_FILE" ]]; then
        log "ERROR: PREFIXD_TOKEN_FILE is not readable"
        exit 1
    fi
    TOKEN=$(tr -d '[:space:]' < "$PREFIXD_TOKEN_FILE")
fi
# A token is prefixd_ and base64url; anything else could break the curl config.
if [[ -n "$TOKEN" && ! "$TOKEN" =~ ^prefixd_[A-Za-z0-9_-]+$ ]]; then
    log "ERROR: the token is malformed"
    exit 1
fi
# Without a token every event would get 401; say so before FastNetMon's one call.
if [[ -z "$TOKEN" && "$PREFIXD_AUTH_MODE" != "none" ]]; then
    log "ERROR: no token: set PREFIXD_TOKEN_FILE or PREFIXD_TOKEN (PREFIXD_AUTH_MODE=none only for a controller without authentication)"
    exit 1
fi

API_ACTION="ban"
[[ "$ACTION" == "unban" ]] && API_ACTION="unban"

# A JSON string body: backslash, quote and control characters escaped.
json_escape() {
    local s
    s=$(printf '%s' "$1" | tr -d '\000-\010\013\014\016-\037\177')
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
}

# The curl config on stdin: the Authorization header, when there is a token.
curl_config() {
    if [[ -n "$TOKEN" ]]; then
        printf 'header = "Authorization: Bearer %s"\n' "$TOKEN"
    fi
}

EVENT_ID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen 2>/dev/null || true)
if [[ -z "$EVENT_ID" ]]; then
    EVENT_ID=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n' \
        | sed -E 's/^(.{8})(.{4})(.{4})(.{4})(.{12})$/\1-\2-\3-\4-\5/')
fi
TIMESTAMP=$(date -u +%FT%TZ)
VECTOR="unknown"
SRC_PORTS=""
RAW_DETAILS=""

if [[ "$API_ACTION" == "ban" ]]; then
    # Attack details come on stdin for a ban only; an unban gets none.
    if [[ ! -t 0 ]]; then
        RAW_DETAILS=$(cat)
    fi

    # Infer attack vector from raw details
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
fi

# A Community ban carries the same 0.9 confidence as the native FastNetMon
# JSON adapter's default ban mapping. /v1/events does not apply that mapping
# itself; omitted confidence counts as zero in correlation.
if [[ "$API_ACTION" == "ban" ]]; then
    SRC_PORTS_FIELD=""
    [[ -n "$SRC_PORTS" ]] && SRC_PORTS_FIELD="\"top_src_ports\":[$SRC_PORTS],"
    PAYLOAD="{\"event_id\":\"$EVENT_ID\",\"timestamp\":\"$TIMESTAMP\",\"source\":\"fastnetmon\",\
\"victim_ip\":\"$IP\",\"vector\":\"$VECTOR\",$SRC_PORTS_FIELD\"action\":\"ban\",\"pps\":$PPS,\
\"confidence\":0.9,\"raw_details\":{\"raw\":\"$(json_escape "$RAW_DETAILS")\",\
\"direction\":\"$(json_escape "$DIRECTION")\"}}"
else
    PAYLOAD="{\"event_id\":\"$EVENT_ID\",\"timestamp\":\"$TIMESTAMP\",\"source\":\"fastnetmon\",\
\"victim_ip\":\"$IP\",\"vector\":\"unknown\",\"action\":\"unban\",\"pps\":$PPS,\
\"raw_details\":{\"direction\":\"$(json_escape "$DIRECTION")\"}}"
fi

log "Sending $API_ACTION for $IP ($VECTOR, ${PPS} pps, event_id=$EVENT_ID)"

# FastNetMon runs the script once per ban and once per unban and never repeats
# it. Retry the same event (same event_id) only when it never reached prefixd
# or a standby or draining controller answered 503; any 4xx is final. Each
# attempt is bounded by the connect and total timeouts.
ATTEMPT=1
while true; do
    CURL_STATUS=0
    RESPONSE=$(curl_config | curl -sS -K - -w "\n%{http_code}" \
        --connect-timeout "$EVENT_CONNECT_TIMEOUT_SECONDS" \
        --max-time "$EVENT_MAX_TIME_SECONDS" \
        -X POST "$PREFIXD_API/v1/events" \
        -H "Content-Type: application/json" \
        --data-binary "$PAYLOAD" 2>&1) || CURL_STATUS=$?

    HTTP_CODE=$(printf '%s\n' "$RESPONSE" | tail -n1)
    BODY=$(printf '%s' "$RESPONSE" | sed '$d')

    if [[ "$CURL_STATUS" -eq 0 && "$HTTP_CODE" =~ ^2 ]]; then
        # A 2xx only proves the event was accepted. A ban can be recorded
        # without a mitigation (ownership, correlation, playbooks), and an
        # unban can find nothing live to withdraw; both say so in `status`.
        STATUS=$(printf '%s' "$BODY" | grep -oE '"status"[[:space:]]*:[[:space:]]*"[^"]+"' | head -n 1 | cut -d'"' -f4 || true)
        MITIGATION_ID=$(printf '%s' "$BODY" | grep -oE '"mitigation_id"[[:space:]]*:[[:space:]]*"[^"]+"' | head -n 1 | cut -d'"' -f4 || true)
        if [[ -z "$MITIGATION_ID" ]]; then
            log "NO_MITIGATION ($HTTP_CODE, status=${STATUS:-unknown}): $BODY"
            exit 0
        fi
        log "SUCCESS ($HTTP_CODE, status=${STATUS:-unknown}): $BODY"
        exit 0
    fi
    # A retried ban whose earlier attempt reached prefixd before timing out
    # or getting 503 meets its own event ID: the ban was delivered.
    if [[ "$API_ACTION" == "ban" && "$ATTEMPT" -gt 1 && "$HTTP_CODE" == "409" \
        && "$BODY" == *"duplicate event from fastnetmon: $EVENT_ID"* ]]; then
        log "NO_MITIGATION ($HTTP_CODE, status=delivered_by_earlier_attempt): $BODY"
        exit 0
    fi
    if [[ ( "$CURL_STATUS" -ne 0 || "$HTTP_CODE" == "503" ) && "$ATTEMPT" -lt "$EVENT_POST_ATTEMPTS" ]]; then
        log "${API_ACTION^} for $IP not accepted (curl=$CURL_STATUS, http=$HTTP_CODE), attempt $ATTEMPT/$EVENT_POST_ATTEMPTS; retrying in ${EVENT_POST_DELAY_SECONDS}s"
        sleep "$EVENT_POST_DELAY_SECONDS"
        ATTEMPT=$((ATTEMPT + 1))
        continue
    fi
    log "ERROR ($HTTP_CODE, curl=$CURL_STATUS): $BODY"
    exit 1
done
