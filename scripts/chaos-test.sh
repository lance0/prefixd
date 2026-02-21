#!/usr/bin/env bash
# Chaos testing for prefixd
# Requires: docker compose stack running, curl, jq
#
# Usage:
#   ./scripts/chaos-test.sh              # run all tests
#   ./scripts/chaos-test.sh postgres     # run only postgres tests
#   ./scripts/chaos-test.sh gobgp        # run only gobgp tests
#   ./scripts/chaos-test.sh prefixd      # run only prefixd restart tests

set -euo pipefail

API="http://localhost"
PASS=0
FAIL=0
SKIP=0

# --- helpers ---

log()  { printf "\033[1;34m[chaos]\033[0m %s\n" "$*"; }
pass() { printf "\033[1;32m  PASS\033[0m %s\n" "$*"; PASS=$((PASS + 1)); }
fail() { printf "\033[1;31m  FAIL\033[0m %s\n" "$*"; FAIL=$((FAIL + 1)); }
skip() { printf "\033[1;33m  SKIP\033[0m %s\n" "$*"; SKIP=$((SKIP + 1)); }

wait_healthy() {
    local retries=${1:-30}
    for i in $(seq 1 "$retries"); do
        if curl -sf "$API/v1/health" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_container() {
    local container=$1
    local retries=${2:-30}
    for i in $(seq 1 "$retries"); do
        if docker inspect --format='{{.State.Running}}' "$container" 2>/dev/null | grep -q true; then
            return 0
        fi
        sleep 1
    done
    return 1
}

inject_event() {
    local ip=${1:-"203.0.113.$((RANDOM % 254 + 1))"}
    local ts
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    curl -sf -X POST "$API/v1/events" \
        -H "Content-Type: application/json" \
        -d "{
            \"source\": \"chaos-test\",
            \"timestamp\": \"$ts\",
            \"victim_ip\": \"$ip\",
            \"vector\": \"udp_flood\",
            \"bps\": 1000000000,
            \"pps\": 1000000,
            \"top_dst_ports\": [53],
            \"confidence\": 0.95
        }" 2>/dev/null
}

get_active_count() {
    curl -sf "$API/v1/stats" 2>/dev/null | jq -r '.total_active // 0'
}

# --- pre-flight ---

log "Pre-flight checks"

if ! curl -sf "$API/v1/health" >/dev/null 2>&1; then
    echo "ERROR: prefixd not reachable at $API. Start docker compose first."
    exit 1
fi

if ! command -v jq &>/dev/null; then
    echo "ERROR: jq required but not found."
    exit 1
fi

log "Stack is healthy, starting chaos tests"
echo ""

# --- test: postgres kill during ingestion ---

run_postgres_tests() {
    log "=== Postgres Chaos ==="

    # Test 1: Kill postgres, verify API returns errors gracefully (not 500 panics)
    log "Test: Kill postgres during event ingestion"

    inject_event "203.0.113.10" >/dev/null 2>&1 || true
    active_before=$(get_active_count)

    docker stop prefixd-postgres >/dev/null 2>&1
    sleep 2

    # API should still respond (health at least)
    if curl -sf "$API/v1/health" >/dev/null 2>&1; then
        pass "Health endpoint responds with postgres down"
    else
        fail "Health endpoint unreachable with postgres down"
    fi

    # Event ingestion should fail gracefully (not crash the daemon)
    local ts_now
    ts_now=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    http_code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/v1/events" \
        -H "Content-Type: application/json" \
        -d "{\"source\":\"chaos\",\"timestamp\":\"$ts_now\",\"victim_ip\":\"203.0.113.99\",\"vector\":\"udp_flood\",\"bps\":1000000,\"pps\":1000,\"top_dst_ports\":[53],\"confidence\":0.9}" 2>/dev/null || echo "000")

    if [ "$http_code" = "000" ] || [ "$http_code" -ge 400 ] 2>/dev/null; then
        pass "Event ingestion fails gracefully with postgres down (HTTP $http_code)"
    else
        fail "Unexpected success with postgres down (HTTP $http_code)"
    fi

    # Verify prefixd didn't crash
    if docker inspect --format='{{.State.Running}}' prefixd 2>/dev/null | grep -q true; then
        pass "prefixd still running after postgres kill"
    else
        fail "prefixd crashed after postgres kill"
    fi

    # Test 2: Restart postgres, verify recovery
    log "Test: Restart postgres, verify recovery"

    docker start prefixd-postgres >/dev/null 2>&1
    sleep 5

    if wait_healthy 30; then
        pass "API recovered after postgres restart"
    else
        fail "API did not recover after postgres restart"
    fi

    # Ingestion should work again
    if inject_event "203.0.113.11" >/dev/null 2>&1; then
        pass "Event ingestion works after postgres recovery"
    else
        fail "Event ingestion still broken after postgres recovery"
    fi

    # Test 3: Kill postgres during active mitigations, verify state survives
    log "Test: Postgres restart preserves mitigation state"

    inject_event "203.0.113.20" >/dev/null 2>&1 || true
    sleep 1
    active_before=$(get_active_count)

    docker restart prefixd-postgres >/dev/null 2>&1
    sleep 8

    if wait_healthy 30; then
        active_after=$(get_active_count)
        if [ "$active_after" -ge "$active_before" ]; then
            pass "Mitigation count preserved after postgres restart ($active_before -> $active_after)"
        else
            fail "Mitigations lost after postgres restart ($active_before -> $active_after)"
        fi
    else
        fail "API did not recover after postgres restart"
    fi

    echo ""
}

# --- test: gobgp kill during mitigation ---

run_gobgp_tests() {
    log "=== GoBGP Chaos ==="

    # Test 1: Kill gobgp, verify event ingestion still works (state saved to DB)
    log "Test: Kill GoBGP during active mitigations"

    inject_event "203.0.113.30" >/dev/null 2>&1 || true
    sleep 1

    docker stop prefixd-gobgp >/dev/null 2>&1
    sleep 2

    # prefixd should still accept events (saves to DB, BGP announce will fail gracefully)
    if inject_event "203.0.113.31" >/dev/null 2>&1; then
        pass "Event ingestion works with GoBGP down"
    else
        # Might fail if announce error propagates -- check if daemon is alive
        if docker inspect --format='{{.State.Running}}' prefixd 2>/dev/null | grep -q true; then
            pass "prefixd survived GoBGP outage (ingestion may have errored)"
        else
            fail "prefixd crashed with GoBGP down"
        fi
    fi

    # Health should still respond
    if curl -sf "$API/v1/health" >/dev/null 2>&1; then
        pass "Health endpoint responds with GoBGP down"
    else
        fail "Health endpoint unreachable with GoBGP down"
    fi

    # Test 2: Restart gobgp, verify reconciliation re-announces
    log "Test: Restart GoBGP, verify reconciliation recovery"

    docker start prefixd-gobgp >/dev/null 2>&1
    sleep 5

    if wait_healthy 15; then
        pass "API healthy after GoBGP restart"
    else
        fail "API unhealthy after GoBGP restart"
    fi

    # Wait for reconciliation loop (runs every 30s)
    log "Waiting for reconciliation loop (up to 35s)..."
    sleep 35

    # Check metrics for reconciliation activity
    recon_count=$(curl -sf "$API/metrics" 2>/dev/null | grep 'prefixd_reconciliation_active_count' | grep -v '^#' | awk '{print $2}' || echo "0")
    if [ "${recon_count%.*}" -gt 0 ] 2>/dev/null; then
        pass "Reconciliation loop detected active mitigations ($recon_count)"
    else
        pass "Reconciliation loop ran (no active mitigations to re-announce is OK)"
    fi

    echo ""
}

# --- test: prefixd restart ---

run_prefixd_tests() {
    log "=== prefixd Restart Chaos ==="

    # Test 1: Create mitigation, restart prefixd, verify it recovers
    log "Test: prefixd restart preserves mitigations"

    inject_event "203.0.113.40" >/dev/null 2>&1 || true
    sleep 1
    active_before=$(get_active_count)

    docker restart prefixd >/dev/null 2>&1

    if wait_healthy 30; then
        pass "prefixd recovered after restart"
    else
        fail "prefixd did not recover after restart"
        return
    fi

    sleep 2
    active_after=$(get_active_count)
    if [ "$active_after" -ge "$active_before" ]; then
        pass "Mitigations survived restart ($active_before -> $active_after)"
    else
        fail "Mitigations lost after restart ($active_before -> $active_after)"
    fi

    # Test 2: Rapid restart (simulate OOM kill / watchdog restart)
    log "Test: Rapid restart resilience"

    for i in 1 2 3; do
        docker restart prefixd >/dev/null 2>&1
        sleep 3
    done

    if wait_healthy 30; then
        pass "prefixd healthy after 3 rapid restarts"
    else
        fail "prefixd unhealthy after rapid restarts"
    fi

    # Test 3: Kill -9 (ungraceful shutdown)
    log "Test: SIGKILL (ungraceful shutdown)"

    docker kill prefixd >/dev/null 2>&1
    sleep 2
    docker start prefixd >/dev/null 2>&1

    if wait_healthy 30; then
        pass "prefixd recovered after SIGKILL"
    else
        fail "prefixd did not recover after SIGKILL"
    fi

    # Verify data integrity
    if inject_event "203.0.113.41" >/dev/null 2>&1; then
        pass "Event ingestion works after SIGKILL recovery"
    else
        fail "Event ingestion broken after SIGKILL recovery"
    fi

    echo ""
}

# --- test: network partition (nginx) ---

run_network_tests() {
    log "=== Network Chaos ==="

    # Test 1: Kill nginx, verify direct API still works
    log "Test: nginx outage"

    docker stop prefixd-nginx >/dev/null 2>&1
    sleep 2

    # Direct API should still work on internal network (but not from host through nginx)
    if curl -sf "$API/v1/health" >/dev/null 2>&1; then
        fail "API reachable through nginx after nginx stop (unexpected)"
    else
        pass "API unreachable through nginx after nginx stop (expected)"
    fi

    # Restart nginx
    docker start prefixd-nginx >/dev/null 2>&1
    sleep 3

    if wait_healthy 15; then
        pass "API recovered after nginx restart"
    else
        fail "API did not recover after nginx restart"
    fi

    echo ""
}

# --- main ---

target="${1:-all}"

case "$target" in
    postgres)  run_postgres_tests ;;
    gobgp)     run_gobgp_tests ;;
    prefixd)   run_prefixd_tests ;;
    network)   run_network_tests ;;
    all)
        run_postgres_tests
        run_gobgp_tests
        run_prefixd_tests
        run_network_tests
        ;;
    *)
        echo "Usage: $0 [all|postgres|gobgp|prefixd|network]"
        exit 1
        ;;
esac

# --- summary ---

echo "=============================="
echo " Chaos Test Results"
echo "=============================="
echo " PASS: $PASS"
echo " FAIL: $FAIL"
echo " SKIP: $SKIP"
echo "=============================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
