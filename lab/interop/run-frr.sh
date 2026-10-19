#!/usr/bin/env bash
# Deploy, drive and destroy the prefixd -> speaker -> FRR interop lab.
#
#   lab/interop/run-frr.sh rustbgpd|gobgp [flowspec|blackhole]
#
# The default scenario is FlowSpec (flowspec_frr.py). The blackhole scenario
# (blackhole_frr.py, rustbgpd only) qualifies ADR 027 host routes at FRR.
#
# Needs Docker, containerlab and python3, and an image tagged prefixd:interop
# (`just interop-frr` builds it). CLAB selects the containerlab command; CI uses
# "sudo containerlab". The dated receipt lands in target/interop/ unless
# PREFIXD_INTEROP_RECEIPTS names another directory. Lab containers are pinned to
# this script's CPU affinity, so `taskset` limits the whole lab.
#
# Lifecycle (destroy, pre-pull with retry, deploy, test, always destroy) is
# adapted from rustbgpd's .github/actions/run-interop-test, without its retry:
# a flaky attempt here should stay visible.
set -euo pipefail

speaker="${1:?usage: run-frr.sh rustbgpd|gobgp [flowspec|blackhole]}"
scenario="${2:-flowspec}"
case "$speaker" in rustbgpd | gobgp) ;; *) echo "unknown speaker: $speaker" >&2; exit 2 ;; esac
case "$speaker/$scenario" in */flowspec | rustbgpd/blackhole) ;;
    *) echo "unsupported scenario for $speaker: $scenario" >&2; exit 2 ;; esac

cd "$(dirname "$0")/../.."
clab="${CLAB:-containerlab}"
lab="prefixd-frr-${speaker}"
topology="lab/interop/frr-${speaker}.clab.yml"
run="lab/interop/.run/${lab}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
suffix="${scenario#flowspec}"
receipt="${PREFIXD_INTEROP_RECEIPTS:-target/interop}/frr-${speaker}${suffix:+-$suffix}-${stamp}"
node() { echo "clab-${lab}-$1"; }

docker image inspect prefixd:interop >/dev/null \
    || { echo "prefixd:interop image missing; run: just interop-frr" >&2; exit 2; }

destroy() { $clab destroy -t "$topology" --cleanup >/dev/null 2>&1 || true; }

collect() {
    mkdir -p "$receipt/logs"
    docker exec "$(node controller)" cat /tmp/prefixd.log >"$receipt/logs/prefixd.log" 2>&1 || true
    for name in speaker frr postgres; do
        docker logs "$(node "$name")" >"$receipt/logs/${name}.log" 2>&1 || true
    done
}

finish() {
    local status=$?
    trap - EXIT
    collect
    destroy
    rm -rf "$run"
    # The receipt is uploaded from CI: refuse it if any per-run secret leaked.
    if grep -rqF -e "$api_token" -e "$speaker_token" -e "$db_password" -e "$admin_password" "$receipt"; then
        echo "a lab secret reached the receipt; deleting it" >&2
        rm -rf "$receipt"
        status=1
    fi
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -f "$receipt/summary.md" ]; then
        cat "$receipt/summary.md" >>"$GITHUB_STEP_SUMMARY"
    fi
    echo "receipt: $receipt (exit $status)"
    exit "$status"
}

destroy
rm -rf "$run"
mkdir -p "$run" "$receipt"
chmod 0700 "$run"

# Per-run lab secrets. They stay in the run directory and container
# environment, are removed on exit and are never written to the receipt.
secret() { python3 -c 'import secrets; print(secrets.token_hex(32))'; }
db_password="$(secret)"
api_token="$(secret)"
speaker_token="$(secret)"
admin_password="$(secret)"
printf 'POSTGRES_PASSWORD=%s\n' "$db_password" >"$run/postgres.env"
{
    printf 'DATABASE_URL=postgres://prefixd:%s@127.0.0.1:5432/prefixd\n' "$db_password"
    printf 'PREFIXD_API_TOKEN=%s\n' "$api_token"
    printf 'PREFIXD_RUSTBGPD_TOKEN=%s\n' "$speaker_token"
    printf 'PREFIXD_LAB_ADMIN_PASSWORD=%s\n' "$admin_password"
} >"$run/prefixd.env"
printf '%s\n' "$api_token" >"$run/api.token"
printf '%s\n' "$admin_password" >"$run/admin.password"
# The released rustbgpd image runs as UID 999 and must read its token file.
printf '%s\n' "$speaker_token" >"$run/rustbgpd.token"
chmod 0644 "$run/rustbgpd.token"
trap finish EXIT

# Pull missing pinned images with bounded retries before deploy.
for image in $(awk '$1 == "image:" { print $2 }' "$topology" | sort -u); do
    [ "$image" = prefixd:interop ] && continue
    docker image inspect "$image" >/dev/null 2>&1 && continue
    for attempt in 1 2 3; do
        timeout 180 docker pull -q "$image" >/dev/null && break
        [ "$attempt" = 3 ] && { echo "pull failed: $image" >&2; exit 1; }
        sleep $((attempt * 10))
    done
done

$clab deploy -t "$topology"
# Containers do not inherit this script's affinity, and `sudo containerlab`
# drops the environment, so pin them here rather than in the topology.
cpus="$(taskset -pc $$ | sed 's/.*: //')"
docker ps -q --filter "label=containerlab=${lab}" | xargs docker update --cpuset-cpus "$cpus" >/dev/null

for _ in $(seq 60); do
    docker exec "$(node postgres)" pg_isready -q -h 127.0.0.1 -U prefixd && break
    sleep 1
done
# The blackhole scenario stops and restarts prefixd through this PID file.
docker exec -d "$(node controller)" sh -c 'echo $$ >/tmp/prefixd.pid; exec prefixd --config /etc/prefixd >>/tmp/prefixd.log 2>&1'

extra=()
[ "$scenario" = blackhole ] \
    && extra=(--controller "$(node controller)" --admin-password-file "$run/admin.password")
python3 -I "lab/interop/${scenario}_frr.py" \
    --speaker "$speaker" \
    --api "http://$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(node postgres)"):8080" \
    --token-file "$run/api.token" \
    --frr "$(node frr)" \
    --speaker-container "$(node speaker)" \
    --topology "$topology" \
    --receipt "$receipt" \
    "${extra[@]}"
