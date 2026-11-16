#!/usr/bin/env bash
# Bootstrap a fresh Compose stack without any shared or default secret.
#
# Usage:
#   scripts/compose-bootstrap.sh env              before the first `up`
#   scripts/compose-bootstrap.sh rustbgpd|gobgp   once the controller runs
#
# env: writes a random POSTGRES_PASSWORD into the repository's .env (mode
#   0600), which Compose requires. It keeps a password .env already sets, and
#   refuses when a PostgreSQL volume already exists, since that database keeps
#   the password it was created with.
#
# rustbgpd|gobgp: in the running controller service,
# - creates an Admin operator (PREFIXD_ADMIN_USER, default "admin") at a
#   hidden password prompt, unless an Admin already exists;
# - mints an ingest token bound to source "fastnetmon" for the detector and an
#   operator-scope token for prefixdctl into fastnetmon.token and cli.token
#   under PREFIXD_TOKEN_DIR (default .prefixd in the repository root; a
#   relative path is taken from the caller's directory). The directory is 0700,
#   each file 0600, and each token's name is recorded in <file>.name.
# - A rerun keeps existing token files, resets their mode to 0600, and checks
#   with `prefixdctl tokens verify` that each file holds a live token of this
#   database with the expected scope, source and recorded name.
#
# Each secret goes from prefixdctl's stdout straight to its file; this script
# never prints a token or passes one on a command line.

set -euo pipefail

die() {
    echo "error: $*" >&2
    exit 1
}

mode=${1:-}
case "$mode" in
    env | rustbgpd | gobgp) ;;
    *)
        echo "usage: $0 env|rustbgpd|gobgp" >&2
        exit 2
        ;;
esac

# Resolve a relative token directory before leaving the caller's directory.
token_dir=${PREFIXD_TOKEN_DIR:-}
if [[ -n "$token_dir" && "$token_dir" != /* ]]; then
    token_dir=$PWD/$token_dir
fi
# Compose reads docker-compose.yml and .env from the repository root.
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
token_dir=${token_dir:-$root/.prefixd}
umask 077

if [[ "$mode" == env ]]; then
    # The shell environment beats .env for every Compose command, so an
    # exported value would initialize PostgreSQL with a password .env lacks.
    [[ -z "${POSTGRES_PASSWORD+set}" ]] ||
        die "POSTGRES_PASSWORD is set in your environment, and it overrides .env for every Compose command; run 'unset POSTGRES_PASSWORD', rerun this, and keep it unset for later Compose commands"
    env_file=$root/.env
    [[ ! -L "$env_file" ]] || die "$env_file is a symbolic link; edit the intended file directly"
    # One env run at a time, from the first read of .env through the write:
    # two concurrent runs would both find no password and both append one.
    env_lock=$root/.env.lock
    if ! mkdir "$env_lock" 2>/dev/null; then
        [[ ! -d "$env_lock" || -L "$env_lock" ]] ||
            die "another 'env' run holds $env_lock; if none is running, remove that directory and rerun"
        die "cannot create the lock directory $env_lock; check that you may write to $root"
    fi
    trap 'rmdir "$env_lock"' EXIT
    assignment='^[[:space:]]*(export[[:space:]]+)?POSTGRES_PASSWORD='
    if [[ -e "$env_file" ]] && current=$(grep -E "$assignment" "$env_file"); then
        [[ "$current" != *$'\n'* ]] || die "$env_file sets POSTGRES_PASSWORD more than once; keep one"
        case "${current#*=}" in
            "" | '""' | "''")
                die "POSTGRES_PASSWORD in $env_file is empty; on an existing stack set the password its database was created with, otherwise delete the line and rerun"
                ;;
            prefixd_secret | your-secure-password)
                echo "warning: POSTGRES_PASSWORD is a published example value; PostgreSQL is not published, but change it in the database and in $env_file when you can" >&2
                ;;
        esac
        chmod 0600 "$env_file"
        echo "Kept the POSTGRES_PASSWORD in $env_file; mode 0600."
        exit 0
    fi
    # A database created earlier keeps its password; a new one would lock the
    # controller out of it. Compose needs some value only to name the project.
    project=$(POSTGRES_PASSWORD=unused docker compose config --format yaml | sed -n '1s/^name: //p') ||
        die "cannot read the Compose project name; check that Docker runs and that you may use it"
    [[ -n "$project" ]] || die "cannot read the Compose project name"
    # A failed listing is not an empty one: it must never lead to a new password.
    volumes=$(docker volume ls -q --filter "label=com.docker.compose.project=$project" \
        --filter label=com.docker.compose.volume=postgres-data) ||
        die "cannot list Docker volumes, so cannot tell whether a database already exists; check that Docker runs and that you may use it, then rerun"
    if [[ -n "$volumes" ]]; then
        die "Compose project $project already has a PostgreSQL volume, created with an earlier password. Set POSTGRES_PASSWORD in $env_file to that password (prefixd_secret if it was never set) instead"
    fi
    password=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
    [[ ${#password} -eq 64 ]] || die "could not read 32 random bytes"
    touch "$env_file"
    chmod 0600 "$env_file"
    if [[ -s "$env_file" && -n "$(tail -c 1 "$env_file")" ]]; then
        printf '\n' >>"$env_file"
    fi
    printf 'POSTGRES_PASSWORD=%s\n' "$password" >>"$env_file"
    echo "Wrote a random POSTGRES_PASSWORD to $env_file (mode 0600). The database is created with it, so keep it."
    exit 0
fi

service="prefixd-$mode"
compose() { docker compose --profile "$mode" "$@"; }

if [[ -z "$(compose ps --status running --quiet "$service")" ]]; then
    die "$service is not running; start it with: docker compose --profile $mode up -d --pull always --no-build"
fi

mkdir -p "$token_dir"
chmod 0700 "$token_dir"

# One run at a time: two concurrent runs would both mint, and the later rename
# would leave the first token live but stored nowhere. mkdir is atomic, and
# portable where flock(1) is not installed.
lock=$token_dir/.lock
if ! mkdir "$lock" 2>/dev/null; then
    [[ ! -d "$lock" || -L "$lock" ]] ||
        die "another bootstrap holds $lock; if none is running, remove that directory and rerun"
    die "cannot create the lock directory $lock; check that you own $token_dir and that nothing else is named .lock there"
fi
temporary=
trap 'rm -f "$temporary"; rmdir "$lock"' EXIT

# Read the whole list first: a failed listing must stop here, not look empty.
operators=$(compose exec -T "$service" prefixdctl --format json operators list)
compact=$(tr -d '[:space:]' <<<"$operators")
if [[ "$compact" == *'"role":"admin"'* ]]; then
    echo "An Admin operator already exists; skipping operator creation."
else
    admin=${PREFIXD_ADMIN_USER:-admin}
    echo "Creating Admin operator '$admin'; choose its dashboard password."
    # Needs a terminal for the hidden prompt; without one prefixdctl refuses.
    compose exec "$service" prefixdctl operators create --username "$admin" --role admin
fi

# The canonical form prefixd accepts: prefixd_ and 43 base64url characters
# encoding 32 bytes, whose last character carries no stray bits; one line.
token_line=$'^prefixd_[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]\n$'

# A kept file must still hold a live token of this database, with the scope and
# source this script gives it: `down -v` deletes every token, and a swapped,
# emptied or truncated file must not pass. prefixdctl reads the secret on
# stdin and prints only its record.
check_kept() {
    local file=$1 scope=$2 source=$3 record name expected
    chmod 0600 "$file"
    record=$(compose exec -T "$service" prefixdctl --format json tokens verify <"$file") ||
        die "$file does not hold a live token of this database (see the error above; docker compose down -v deletes tokens); delete $file and $file.name, then rerun"
    record=$(tr -d '[:space:]' <<<"$record")
    name=${record#*\"name\":\"}
    name=${name%%\"*}
    local want="an $scope token"
    if [[ "$source" == - ]]; then
        expected='"source":null'
    else
        expected="\"source\":\"$source\""
        want+=" bound to $source"
    fi
    [[ "$record" == *"\"scope\":\"$scope\""* && "$record" == *"$expected"* ]] ||
        die "$file holds token '$name', which is not $want; were the token files swapped? Delete $file and $file.name, then rerun"
    if [[ -f "$file.name" ]]; then
        chmod 0600 "$file.name"
        [[ "$(<"$file.name")" == "$name" ]] ||
            die "$file holds token '$name', but $file.name records '$(<"$file.name")'; delete both, then rerun"
    else
        echo "warning: $file has no recorded name; it holds token '$name'" >&2
    fi
    echo "Keeping $file (token '$name')."
}

# mint FILE NAME SCOPE SOURCE (- for none)
mint() {
    local file=$token_dir/$1 name=$2 scope=$3 source=$4 content
    if [[ -e "$file" ]]; then
        check_kept "$file" "$scope" "$source"
        return
    fi
    local args=(--name "$name" --scope "$scope")
    [[ "$source" == - ]] || args+=(--source "$source")
    local revoke="docker compose exec $service prefixdctl tokens revoke $name"
    temporary=$(mktemp "$token_dir/.token.XXXXXX")
    compose exec -T "$service" prefixdctl tokens create "${args[@]}" >"$temporary" ||
        die "minting '$name' failed; if 'prefixdctl tokens list' shows it, revoke it: $revoke"
    # Keep trailing newlines: the output must be exactly one token line.
    content=$(
        cat "$temporary"
        printf x
    )
    if [[ ! "${content%x}" =~ $token_line ]] ||
        ! printf '%s\n' "$name" >"$file.name" ||
        ! mv "$temporary" "$file"; then
        rm -f "$file.name"
        die "token '$name' was minted but not stored; revoke it: $revoke"
    fi
    temporary=
    echo "Wrote $file (token '$name')."
}

stamp=$(date -u +%Y%m%d-%H%M%S)
mint fastnetmon.token "fastnetmon-$stamp" ingest fastnetmon
mint cli.token "cli-$stamp" operator -

cat <<EOF

Next steps:
  # prefixdctl in the controller, reading the operator token on stdin:
  docker compose exec -T -e PREFIXD_TOKEN_FILE=/dev/stdin $service prefixdctl status < $token_dir/cli.token

  # The detector's ingest token, bound to source "fastnetmon":
  #   $token_dir/fastnetmon.token
EOF
