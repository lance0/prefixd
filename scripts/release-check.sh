#!/usr/bin/env bash
# Fail closed unless TAG may publish COMMIT:
#   - TAG is vX.Y.Z (optionally -prerelease) and equals the Cargo.toml version
#     recorded in COMMIT;
#   - an existing TAG resolves to COMMIT (skipped when DRY_RUN=1, where the tag
#     name is derived from Cargo.toml and may name an older release);
#   - COMMIT is on origin/main;
#   - a ci.yml push run on main succeeded for exactly COMMIT.
#
# Usage: scripts/release-check.sh vX.Y.Z [COMMIT]   (COMMIT defaults to TAG)
# Needs full Git history and an authenticated gh. GITHUB_REPOSITORY overrides
# the repository that gh would otherwise infer from the checkout.
set -euo pipefail

fail() {
    echo "::error::$*" >&2
    exit 1
}

tag="${1:?usage: scripts/release-check.sh vX.Y.Z [COMMIT]}"
commit="$(git rev-parse --verify "${2:-$tag}^{commit}")" || fail "cannot resolve ${2:-$tag}"

[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || fail "tag $tag is not vX.Y.Z"

cargo_version="$(git show "$commit:Cargo.toml" |
    python3 -c 'import sys, tomllib; print(tomllib.loads(sys.stdin.read())["package"]["version"])')"
[ "${tag#v}" = "$cargo_version" ] ||
    fail "tag $tag does not match Cargo.toml version $cargo_version at $commit"
echo "ok: $tag matches Cargo.toml version at $commit"

if [ "${DRY_RUN:-}" = 1 ]; then
    echo "dry run: not checking where an existing $tag points"
elif tag_commit="$(git rev-parse --verify --quiet "refs/tags/$tag^{commit}")"; then
    [ "$tag_commit" = "$commit" ] || fail "$tag points at $tag_commit, not $commit"
    echo "ok: $tag points at $commit"
fi

git fetch --quiet --no-tags origin +refs/heads/main:refs/remotes/origin/main
git merge-base --is-ancestor "$commit" refs/remotes/origin/main ||
    fail "$commit is not on main; tag only a commit that landed on main"
echo "ok: $commit is on main"

repo="${GITHUB_REPOSITORY:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}"
successes="$(gh api "repos/$repo/actions/workflows/ci.yml/runs?head_sha=$commit&branch=main&event=push&status=success&per_page=1" --jq .total_count)"
[ "$successes" -gt 0 ] ||
    fail "no successful ci.yml push run on main for $commit; wait for exact-main CI before tagging"
echo "ok: ci.yml passed on main for $commit"
