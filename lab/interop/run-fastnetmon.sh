#!/usr/bin/env bash
# Deploy, drive and destroy the FastNetMon Community -> prefixd -> rustbgpd ->
# FRR interop lane (fastnetmon-rustbgpd.clab.yml, driven by fastnetmon_frr.py).
#
#   lab/interop/run-fastnetmon.sh
#
# Needs Docker, containerlab and python3, and an image tagged prefixd:interop
# (`just interop-fastnetmon` builds it). This script builds the FastNetMon image
# from fastnetmon.Dockerfile. CLAB selects the containerlab command; CI uses
# "sudo containerlab". The dated receipt lands in target/interop/ unless
# PREFIXD_INTEROP_RECEIPTS names another directory. Lab containers are pinned to
# this script's CPU affinity. The lifecycle matches run-frr.sh: destroy,
# pre-pull with retry, deploy, test, always destroy, and no retry of the test.
set -euo pipefail

cd "$(dirname "$0")/../.."
clab="${CLAB:-containerlab}"
lab="prefixd-fnm"
topology="lab/interop/fastnetmon-rustbgpd.clab.yml"
run="lab/interop/.run/${lab}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
receipt="${PREFIXD_INTEROP_RECEIPTS:-target/interop}/fastnetmon-rustbgpd-${stamp}"
node() { echo "${lab}-$1"; }

docker image inspect prefixd:interop >/dev/null \
    || { echo "prefixd:interop image missing; run: just interop-fastnetmon" >&2; exit 2; }

destroy() { $clab destroy -t "$topology" --cleanup >/dev/null 2>&1 || true; }

collect() {
    mkdir -p "$receipt/logs" "$receipt/fastnetmon"
    docker exec "$(node controller)" cat /tmp/prefixd.log >"$receipt/logs/prefixd.log" 2>&1 || true
    for name in speaker frr postgres; do
        docker logs "$(node "$name")" >"$receipt/logs/${name}.log" 2>&1 || true
    done
    docker exec "$(node fastnetmon)" cat /var/log/fastnetmon.log >"$receipt/logs/fastnetmon.log" 2>&1 || true
    docker exec "$(node fastnetmon)" cat /var/log/prefixd-fastnetmon.log \
        >"$receipt/logs/prefixd-fastnetmon.log" 2>&1 || true
    # The attack details FastNetMon writes for each ban: the notify script's stdin.
    # Their names carry colons, which CI artifact upload refuses.
    docker cp "$(node fastnetmon):/var/log/fastnetmon_attacks/." "$receipt/fastnetmon/" >/dev/null 2>&1 || true
    # With no files the glob stays literal; an `&&` test here would make that
    # collect()'s status and stop finish() under set -e.
    for file in "$receipt"/fastnetmon/*:*; do
        if [ -e "$file" ]; then mv "$file" "${file//:/-}"; fi
    done
}

finish() {
    local status=$?
    trap - EXIT
    collect
    destroy
    rm -rf "$run"
    # The receipt is uploaded from CI: refuse it if any per-run secret leaked.
    local patterns=() value
    for value in "${lab_secrets[@]}"; do patterns+=(-e "$value"); done
    if grep -rqF "${patterns[@]}" "$receipt"; then
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

# The one place the lane's detector credential is decided. Every file exists
# before deploy so its bind mount resolves; mint_credentials fills them in
# place once the controller has applied its migrations.
ingest_credential() {
    {
        printf 'PREFIXD_API=http://127.0.0.1:8080\n'
        printf 'PREFIXD_TOKEN_FILE=/etc/prefixd/fastnetmon.token\n'
        printf 'PREFIXD_LOG=/var/log/prefixd-fastnetmon.log\n'
    } >"$run/fastnetmon.defaults"
    chmod 0644 "$run/fastnetmon.defaults"
    # FastNetMon runs the script as root in this image; 0444 lets the
    # bind-mounted file be read whatever the container's user mapping.
    : >"$run/fastnetmon.token"
    chmod 0444 "$run/fastnetmon.token"
    : >"$run/api.token"
    : >"$run/wrong.token"
}
# The bundled script holds an ingest token bound to fastnetmon, read from a
# token file. The driver holds an operator token for reads, and an ingest token
# bound to another source for the negative control. Each joins lab_secrets,
# which finish() checks the receipt against. A create fails until migration
# 022 ran.
mint_credentials() {
    local script_token="" driver_token="" wrong_token=""
    for _ in $(seq 60); do
        script_token="$(docker exec "$(node controller)" prefixdctl tokens create \
            --name fnm-script --scope ingest --source fastnetmon 2>/dev/null)" && break
        sleep 1
    done
    [ -n "$script_token" ] || { echo "could not mint the script token" >&2; exit 1; }
    driver_token="$(docker exec "$(node controller)" prefixdctl tokens create \
        --name fnm-driver --scope operator)"
    wrong_token="$(docker exec "$(node controller)" prefixdctl tokens create \
        --name fnm-wrong-source --scope ingest --source radware)"
    lab_secrets+=("$script_token" "$driver_token" "$wrong_token")
    # In place, so the bind-mounted files keep their inodes.
    printf '%s\n' "$script_token" >"$run/fastnetmon.token"
    printf '%s\n' "$driver_token" >"$run/api.token"
    printf '%s\n' "$wrong_token" >"$run/wrong.token"
}

destroy
rm -rf "$run"
mkdir -p "$run" "$receipt"
chmod 0700 "$run"

# Per-run lab secrets. They stay in the run directory and container
# environment, are removed on exit and are never written to the receipt; every
# one goes in lab_secrets, which finish() checks the receipt against.
secret() { python3 -c 'import secrets; print(secrets.token_hex(32))'; }
db_password="$(secret)"
speaker_token="$(secret)"
lab_secrets=("$db_password" "$speaker_token")
printf 'POSTGRES_PASSWORD=%s\n' "$db_password" >"$run/postgres.env"
{
    printf 'DATABASE_URL=postgres://prefixd:%s@127.0.0.1:5432/prefixd\n' "$db_password"
    printf 'PREFIXD_RUSTBGPD_TOKEN=%s\n' "$speaker_token"
} >"$run/prefixd.env"
# The released rustbgpd image runs as UID 999 and must read its token file.
printf '%s\n' "$speaker_token" >"$run/rustbgpd.token"
chmod 0644 "$run/rustbgpd.token"
ingest_credential
trap finish EXIT

# Pull missing pinned images with bounded retries before deploy.
for image in $(awk '$1 == "image:" { print $2 }' "$topology" | sort -u) \
    "$(awk '$1 == "FROM" { print $2 }' lab/interop/fastnetmon.Dockerfile)"; do
    case "$image" in prefixd:interop | prefixd-fastnetmon:interop) continue ;; esac
    docker image inspect "$image" >/dev/null 2>&1 && continue
    for attempt in 1 2 3; do
        timeout 180 docker pull -q "$image" >/dev/null && break
        [ "$attempt" = 3 ] && { echo "pull failed: $image" >&2; exit 1; }
        sleep $((attempt * 10))
    done
done
# No build context: the Dockerfile copies nothing. Its apt step reaches the
# Ubuntu archive, so retry like the pulls.
for attempt in 1 2 3; do
    timeout 600 docker build -q -t prefixd-fastnetmon:interop - <lab/interop/fastnetmon.Dockerfile >/dev/null && break
    [ "$attempt" = 3 ] && { echo "FastNetMon image build failed" >&2; exit 1; }
    sleep $((attempt * 10))
done

$clab deploy -t "$topology"
# Containers do not inherit this script's affinity, and `sudo containerlab`
# drops the environment, so pin them here rather than in the topology.
cpus="$(taskset -pc $$ | sed 's/.*: //')"
docker ps -q --filter "label=containerlab=${lab}" | xargs docker update --cpuset-cpus "$cpus" >/dev/null

for attempt in $(seq 60); do
    docker exec "$(node postgres)" pg_isready -q -h 127.0.0.1 -U prefixd && break
    [ "$attempt" = 60 ] && { echo "PostgreSQL not ready within 60s" >&2; exit 1; }
    sleep 1
done
docker exec -d "$(node controller)" sh -c 'exec prefixd --config /etc/prefixd >>/tmp/prefixd.log 2>&1'
mint_credentials

python3 -I lab/interop/fastnetmon_frr.py \
    --speaker rustbgpd \
    --api "http://$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(node postgres)"):8080" \
    --token-file "$run/api.token" \
    --wrong-token-file "$run/wrong.token" \
    --frr "$(node frr)" \
    --speaker-container "$(node speaker)" \
    --fastnetmon "$(node fastnetmon)" \
    --topology "$topology" \
    --receipt "$receipt"
