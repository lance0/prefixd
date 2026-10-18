#!/usr/bin/env bash
# Start one release image and check it reports the expected identity.
#
# Usage: scripts/release-smoke-image.sh prefixd|prefixd-dashboard IMAGE VERSION [REVISION]
#   prefixd            labels, `prefixd --version`, `prefixdctl --version`, runs as 999
#   prefixd-dashboard  labels, then the server answers GET /login within 60 seconds
# The daemon needs PostgreSQL and a speaker to start; the speaker suites in
# ci.yml cover that path, so this checks the shipped binaries only.
set -euo pipefail

fail() {
    echo "::error::$*" >&2
    exit 1
}

kind="${1:?usage: scripts/release-smoke-image.sh KIND IMAGE VERSION [REVISION]}"
image="${2:?missing IMAGE}"
version="${3:?missing VERSION}"
revision="${4:-}"

label() {
    docker image inspect "$image" --format "{{index .Config.Labels \"org.opencontainers.image.$1\"}}"
}
[ "$(label version)" = "$version" ] || fail "$image version label is '$(label version)', expected $version"
if [ -n "$revision" ]; then
    [ "$(label revision)" = "$revision" ] || fail "$image revision label is '$(label revision)', expected $revision"
fi

case "$kind" in
prefixd)
    reported="$(docker run --rm "$image" --version)"
    [ "$reported" = "prefixd $version" ] || fail "$image reports '$reported', expected 'prefixd $version'"
    reported="$(docker run --rm --entrypoint prefixdctl "$image" --version)"
    [ "$reported" = "prefixdctl $version" ] || fail "$image reports '$reported', expected 'prefixdctl $version'"
    [ "$(docker run --rm --entrypoint id "$image" -u)" = 999 ] || fail "$image does not run as uid 999"
    ;;
prefixd-dashboard)
    cid="$(docker run -d -p 127.0.0.1::3000 "$image")"
    trap 'docker rm -f "$cid" >/dev/null' EXIT
    port="$(docker port "$cid" 3000/tcp | head -n1)"
    port="${port##*:}"
    code=000
    for _ in $(seq 60); do
        code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/login" || true)"
        case "$code" in 2?? | 3??) break ;; esac
        sleep 1
    done
    case "$code" in 2?? | 3??) ;; *)
        docker logs "$cid" >&2 || true
        fail "$image answered GET /login with HTTP $code"
        ;;
    esac
    ;;
*) fail "unknown image kind $kind" ;;
esac
echo "ok: $kind image $image $version"
