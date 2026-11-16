#!/usr/bin/env bash
# Bootstrap a fresh Compose stack: create the first administrator and mint the
# first API tokens in the running controller service.
#
# Usage: scripts/compose-bootstrap.sh rustbgpd|gobgp
#
# - Creates an Admin operator (PREFIXD_ADMIN_USER, default "admin") at a hidden
#   password prompt, unless an Admin already exists.
# - Mints an ingest token bound to source "fastnetmon" for the detector and an
#   operator-scope token for prefixdctl, each into its own file under
#   PREFIXD_TOKEN_DIR (default .prefixd in the repository root). The directory
#   is 0700 and each file 0600; a token file that already exists is kept.
#
# Each secret goes from prefixdctl's stdout straight to its file; this script
# never prints a token or passes one on a command line.

set -euo pipefail

profile=${1:-}
case "$profile" in
    rustbgpd | gobgp) ;;
    *)
        echo "usage: $0 rustbgpd|gobgp" >&2
        exit 2
        ;;
esac
service="prefixd-$profile"

# Compose reads docker-compose.yml and .env from the repository root.
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
token_dir=${PREFIXD_TOKEN_DIR:-$root/.prefixd}
admin=${PREFIXD_ADMIN_USER:-admin}

compose() { docker compose --profile "$profile" "$@"; }

if [[ -z "$(compose ps --status running --quiet "$service")" ]]; then
    echo "error: $service is not running; start it with:" >&2
    echo "  docker compose --profile $profile up -d --pull always --no-build" >&2
    exit 1
fi

umask 077
mkdir -p "$token_dir"
chmod 0700 "$token_dir"

# Read the whole list first: a failed listing must stop here, not look empty.
operators=$(compose exec -T "$service" prefixdctl --format json operators list)
if grep -q '"role": "admin"' <<<"$operators"; then
    echo "An Admin operator already exists; skipping operator creation."
else
    echo "Creating Admin operator '$admin'; choose its dashboard password."
    # Needs a terminal for the hidden prompt; without one prefixdctl refuses.
    compose exec "$service" prefixdctl operators create --username "$admin" --role admin
fi

temporary=
trap 'rm -f "$temporary"' EXIT
stamp=$(date -u +%Y%m%d-%H%M%S)

# mint FILE TOKEN-CREATE-ARGS...
mint() {
    local file=$token_dir/$1
    shift
    if [[ -e "$file" ]]; then
        echo "Keeping existing $file; delete it to mint a new token."
        return
    fi
    temporary=$(mktemp "$token_dir/.token.XXXXXX")
    compose exec -T "$service" prefixdctl tokens create "$@" >"$temporary"
    # stdout carries only the secret; anything else is not a token.
    if ! grep -qxE 'prefixd_[A-Za-z0-9_-]{43}' "$temporary"; then
        echo "error: prefixdctl did not print a token for $file" >&2
        exit 1
    fi
    mv "$temporary" "$file"
    temporary=
    echo "Wrote $file"
}

mint fastnetmon.token --name "fastnetmon-$stamp" --scope ingest --source fastnetmon
mint cli.token --name "cli-$stamp" --scope operator

cat <<EOF

Next steps:
  # prefixdctl in the controller, with the operator token:
  export PREFIXD_TOKEN="\$(cat $token_dir/cli.token)"
  docker compose exec -e PREFIXD_TOKEN $service prefixdctl status

  # The detector's ingest token, bound to source "fastnetmon":
  #   $token_dir/fastnetmon.token
EOF
