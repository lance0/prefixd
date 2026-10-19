#!/usr/bin/env bash
# Prepare the release PR's changes for X.Y.Z in the current checkout:
#   - set the Cargo.toml [package] version and refresh Cargo.lock, which must
#     then change only the prefixd entry;
#   - roll CHANGELOG.md's [Unreleased] entries into `## [X.Y.Z] - <UTC date>`
#     under a fresh empty [Unreleased], and move the compare links at the end;
#   - preview the release body with scripts/release-notes.py;
#   - print the checks that stay manual.
# Refuses when tracked files have changes, X.Y.Z is not greater than the
# current version, or [Unreleased] is empty. It commits and pushes nothing.
#
# Usage: scripts/release-prepare.sh X.Y.Z
#        scripts/release-prepare.sh --selftest   (runs against a temp copy of HEAD)
set -euo pipefail

scripts="$(cd "$(dirname "$0")" && pwd)"
self="$scripts/$(basename "$0")"

fail() {
    echo "error: $*" >&2
    exit 1
}

package_version() {
    python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["package"]["version"])'
}

selftest() {
    local repo cur next
    repo="$(git -C "$scripts" rev-parse --show-toplevel)"
    tmp="$(mktemp -d)" # global: the EXIT trap runs after this function returns
    trap 'rm -rf "$tmp"' EXIT
    mkdir "$tmp/r"
    git -C "$repo" archive HEAD | tar -x -C "$tmp/r"
    cd "$tmp/r"
    cur="$(package_version)"
    next="$(python3 -c 'import sys; v = sys.argv[1].split("-")[0].split("."); print(f"{v[0]}.{v[1]}.{int(v[2]) + 1}")' "$cur")"
    cat >CHANGELOG.md <<EOF
# Changelog

## [Unreleased]

## [$cur] - 2026-01-01

- Older entry.

[Unreleased]: https://github.com/lance0/prefixd/compare/v$cur...HEAD
[$cur]: https://github.com/lance0/prefixd/compare/v0.0.1...v$cur
EOF
    git init --quiet
    git add --all
    git -c user.name=selftest -c user.email=selftest@example.invalid commit --quiet -m base
    git tag "v$cur"
    commit() { git -c user.name=selftest -c user.email=selftest@example.invalid commit --quiet --all -m "$1"; }
    refuse() {
        local why="$1" before
        shift
        before="$(git diff)"
        if "$self" "$@" >"$tmp/out" 2>&1; then
            cat "$tmp/out"
            fail "selftest: expected refusal ($why)"
        fi
        grep -q "$why" "$tmp/out" || fail "selftest: wrong refusal for '$why': $(cat "$tmp/out")"
        [ "$(git diff)" = "$before" ] || fail "selftest: refusal changed files ($why)"
        echo "ok: refuses $* ($why)"
    }

    refuse "is empty" "$next"
    sed -i 's/^## \[Unreleased\]$/&\n\nA summary.\n\n### Fixed\n\n- A fix./' CHANGELOG.md
    commit unreleased
    refuse "not greater" "$cur"
    refuse "not greater" "0.0.1"
    refuse "not greater" "$cur-rc.1"
    refuse "not X.Y.Z" "1.2"
    echo >>README.md
    refuse "uncommitted" "$next"
    git checkout --quiet README.md

    "$self" "$next" >"$tmp/out" || {
        cat "$tmp/out"
        fail "selftest: prepare $next failed"
    }
    [ "$(package_version)" = "$next" ] || fail "selftest: Cargo.toml version is not $next"
    [ "$(git diff --numstat Cargo.lock)" = "$(printf '1\t1\tCargo.lock')" ] || fail "selftest: Cargo.lock diff"
    python3 - "$cur" "$next" "$(date -u +%F)" <<'EOF' || fail "selftest: CHANGELOG.md roll"
import sys
cur, new, day = sys.argv[1:]
want = f"""# Changelog

## [Unreleased]

## [{new}] - {day}

A summary.

### Fixed

- A fix.

## [{cur}] - 2026-01-01

- Older entry.

[Unreleased]: https://github.com/lance0/prefixd/compare/v{new}...HEAD
[{new}]: https://github.com/lance0/prefixd/compare/v{cur}...v{new}
[{cur}]: https://github.com/lance0/prefixd/compare/v0.0.1...v{cur}
"""
got = open("CHANGELOG.md").read()
assert got == want, got
EOF
    grep -q "^A summary.$" "$tmp/out" || fail "selftest: release-notes preview missing"
    echo "ok: prepares $next"
    echo "release-prepare selftest: ok"
}

if [ "${1:-}" = --selftest ]; then
    selftest
    exit 0
fi

new="${1:?usage: scripts/release-prepare.sh X.Y.Z}"
[[ "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || fail "$new is not X.Y.Z (no leading v)"
cd "$(git rev-parse --show-toplevel)"
[ -z "$(git status --porcelain --untracked-files=no)" ] ||
    fail "tracked files have uncommitted changes; start from a clean checkout"

cur="$(package_version)"
python3 - "$cur" "$new" <<'EOF' || fail "$new is not greater than the current version $cur"
import re, sys

def key(v):
    core, _, pre = v.partition("-")
    ids = [(0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split(".")] if pre else []
    # A prerelease sorts before its final release.
    return [int(n) for n in core.split(".")], not pre, ids

cur, new = sys.argv[1:]
sys.exit(0 if key(new) > key(cur) else 1)
EOF

previous="$("$scripts/release-notes.py" --tag-info "v$new" | sed -n 's/^previous=//p')"
python3 - "$new" "$(date -u +%F)" "$previous" <<'EOF' || exit 1
import re, sys

new, day, previous = sys.argv[1:]
text = open("CHANGELOG.md", encoding="utf-8").read()
m = re.search(r"^## \[Unreleased\]\n(.*?)(?=^## |^\[Unreleased\]: |\Z)", text, re.M | re.S)
if not m:
    sys.exit("error: CHANGELOG.md has no '## [Unreleased]' section")
body = m.group(1).strip("\n")
if not body.strip():
    sys.exit("error: CHANGELOG.md [Unreleased] section is empty; add the release's entries first")
text = text[: m.start()] + f"## [Unreleased]\n\n## [{new}] - {day}\n\n{body}\n\n" + text[m.end() :]
link = re.search(r"^\[Unreleased\]: (\S+)/compare/\S+$", text, re.M)
if link:
    lines = f"[Unreleased]: {link.group(1)}/compare/v{new}...HEAD"
    if previous:
        lines += f"\n[{new}]: {link.group(1)}/compare/{previous}...v{new}"
    text = text[: link.start()] + lines + text[link.end() :]
open("CHANGELOG.md", "w", encoding="utf-8").write(text)
EOF

# [package] comes first in Cargo.toml; the tomllib read below confirms the edit.
sed -i "0,/^version = \"$cur\"\$/s//version = \"$new\"/" Cargo.toml
[ "$(package_version)" = "$new" ] || fail "could not set the Cargo.toml [package] version to $new"

cargo update --workspace --quiet
lock_diff="$(git diff -U1 Cargo.lock)"
if [ "$(git diff --numstat Cargo.lock)" != "$(printf '1\t1\tCargo.lock')" ] ||
    [[ "$lock_diff" != *$'\n name = "prefixd"\n-version = '* ]]; then
    fail "Cargo.lock changed more than the prefixd version; inspect git diff Cargo.lock"
fi

echo "--- release body preview (scripts/release-notes.py $new) ---"
"$scripts/release-notes.py" "$new"
cat <<EOF
--- prepared $cur -> $new; nothing is committed ---
Still check by hand before opening "chore(release): prepare v$new":
  - README.md Status line names v$new and is accurate.
  - docs/how-to/upgrading.md has a section for ${previous:-the previous release} -> $new.
  - /openapi.json reports info.version $new (it comes from CARGO_PKG_VERSION).
  - Review the CHANGELOG section against: git log ${previous:-<previous tag>}..HEAD --oneline
  - Move current examples that pin the previous version; leave history alone.
EOF
