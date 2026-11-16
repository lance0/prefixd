#!/usr/bin/env bash
# Answer the FastNetMon Community lab checks against the lane's image and write
# a verbatim transcript plus every notify call FastNetMon made.
#
#   lab/interop/fastnetmon-probe.sh OUT_DIR
#
# One container, prefixd-fnm-probe, runs FastNetMon with the lane's
# fastnetmon.conf, but its notify script only records each call's arguments and
# stdin. OUT_DIR gets transcript.txt (each command, its output and exit status)
# and calls/NN-<ip>-<action>.{args,stdin}. Needs Docker and python3; the
# container is pinned to this script's CPU affinity.
# The single-quoted commands expand inside the container, not here.
# shellcheck disable=SC2016
set -euo pipefail

mkdir -p "${1:?usage: fastnetmon-probe.sh OUT_DIR}"
out="$(cd "$1" && pwd)"
cd "$(dirname "$0")/../.."
name=prefixd-fnm-probe
base="$(awk '$1 == "FROM" { print $2 }' lab/interop/fastnetmon.Dockerfile)"
image=prefixd-fastnetmon:interop
client=/opt/fastnetmon-community/app/bin/fastnetmon_api_client
cpus="$(taskset -pc $$ | sed 's/.*: //')"
docker rm -f "$name" >/dev/null 2>&1 || true
work="$(mktemp -d)"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT
rm -rf "$out/calls"
mkdir -p "$out/calls" "$work/calls"
chmod 0777 "$work/calls"
transcript="$out/transcript.txt"
: >"$transcript"

# Record a command and its output verbatim, with the exit status.
# Single-quote an argument that the shell would split or expand.
quote() {
    case "$1" in
        *[[:space:]\"\'\$\;\&\|\<\>\*\(\)]*) printf "'%s'" "${1//\'/\'\\\'\'}" ;;
        *) printf '%s' "$1" ;;
    esac
}
probe() {
    local status=0 output arg line='$'
    output="$("$@" 2>&1)" || status=$?
    for arg in "$@"; do line+=" $(quote "$arg")"; done
    { printf '%s\n' "$line"; [ -n "$output" ] && printf '%s\n' "$output"; printf '[exit %s]\n\n' "$status"; } >>"$transcript"
}
in_probe() { probe docker exec "$name" bash -c "$1"; }
calls() { find "$work/calls" -name '*.args' | wc -l; }
wait_calls() {
    local want="$1" deadline=$((SECONDS + ${2:-30}))
    until [ "$(calls)" -ge "$want" ]; do
        [ "$SECONDS" -lt "$deadline" ] || { echo "probe: expected $want notify calls, saw $(calls)" >&2; exit 1; }
        sleep 1
    done
}

cat >"$work/notify.sh" <<'EOF'
#!/bin/bash
# Records each notify call's arguments and stdin.
n=$(date +%s%N)
printf '%s\n' "$@" > /calls/$n.args
cat > /calls/$n.stdin
EOF
chmod 0755 "$work/notify.sh"

timeout 600 docker build -q -t "$image" - <lab/interop/fastnetmon.Dockerfile >/dev/null
{
    printf 'FastNetMon Community probe, %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'base image: %s\n' "$base"
    printf 'probe image: %s %s\n\n' "$image" "$(docker image inspect -f '{{.Id}}' "$image")"
} >>"$transcript"

tools='for c in curl flock jq python3 wget bash uuidgen mktemp mv awk; do printf "%s: " "$c"; command -v "$c" || echo MISSING; done'
probe docker run --rm --cpuset-cpus "$cpus" --entrypoint bash "$base" -c "$tools"
probe docker run --rm --cpuset-cpus "$cpus" --entrypoint bash "$image" -c "$tools; ls -d /var/lib/prefixd-fastnetmon /var/log/fastnetmon_attacks"

docker run -d --name "$name" --cpuset-cpus "$cpus" \
    -v "$PWD/lab/interop/configs/fastnetmon.conf:/etc/fastnetmon.conf:ro" \
    -v "$PWD/lab/interop/configs/fastnetmon-networks:/etc/networks_list:ro" \
    -v "$work/notify.sh:/usr/local/bin/prefixd-fastnetmon.sh:ro" \
    -v "$work/calls:/calls" "$image" >/dev/null
deadline=$((SECONDS + 30))
until output="$(timeout 5 docker exec "$name" "$client" get_banlist 2>&1)" && [[ "$output" != *"Query failed"* ]]; do
    [ "$SECONDS" -lt "$deadline" ] || { printf 'probe: FastNetMon API readiness timed out: %s\n' "$output" >&2; exit 1; }
    sleep 1
done

in_probe 'flock --version'
# The holder takes the lock, signals through a file, then holds it 5 s.
in_probe 'flock -x /tmp/l -c "touch /tmp/held; sleep 5" & until [ -e /tmp/held ]; do sleep 0.1; done; start=$(date +%s%N); flock -w 1 -x /tmp/l true; rc=$?; echo "flock -w 1 -x returned $rc after $(( ($(date +%s%N) - start) / 1000000 )) ms"; wait'
in_probe 'printf "url = \"http://127.0.0.1:9/from-stdin-config\"\n" | curl -sS -K - --connect-timeout 2'

probe docker exec "$name" "$client" ban 203.0.113.50
wait_calls 1
probe docker exec "$name" "$client" ban 203.0.113.50
wait_calls 2
probe docker exec "$name" "$client" get_banlist
probe docker exec "$name" "$client" ban 198.51.100.1
probe docker exec "$name" "$client" unban 203.0.113.50
wait_calls 3
probe docker exec "$name" "$client" unban 203.0.113.50
probe docker exec "$name" "$client" ban 2001:db8:113::10
wait_calls 4
probe docker exec "$name" "$client" unban 2001:db8:113::10
wait_calls 5

# A 45 s NetFlow flood: one ban while it lasts, then FastNetMon's own unban
# once ban_time has passed and the attack has finished.
before="$(calls)"
probe python3 -I lab/interop/netflow_v5.py "$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$name"):2055" 203.0.113.60 --seconds 45
echo "notify calls during the 45 s flood: $(($(calls) - before))" >>"$transcript"
ban_time="$(awk '$1 == "ban_time" { print $3 }' lab/interop/configs/fastnetmon.conf)"
wait_calls $((before + 2)) $((ban_time * 2 + 60))
printf 'notify calls after the flood and the timer unban: %s\n\n' "$(($(calls) - before))" >>"$transcript"
in_probe "grep -E 'detected attack|Call script|Skip unban|API' /var/log/fastnetmon.log"

# Name the calls in order and record their hashes.
i=0
for args in $(find "$work/calls" -name '*.args' | sort); do
    i=$((i + 1))
    label="$(printf '%02d-%s-%s' "$i" "$(sed -n 1p "$args" | tr ':' '-')" "$(sed -n 4p "$args")")"
    cp "$args" "$out/calls/$label.args"
    cp "${args%.args}.stdin" "$out/calls/$label.stdin"
done
(cd "$out/calls" && probe sh -c 'for f in *.args; do printf "%s: " "$f"; tr "\n" " " <"$f"; echo; done; wc -c *.stdin; md5sum *.stdin')
echo "probe: $transcript"
