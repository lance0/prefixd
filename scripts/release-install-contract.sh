#!/usr/bin/env bash
# Check that a GitHub Release's published artifacts install and start.
#
# Usage: scripts/release-install-contract.sh vX.Y.Z [ASSET_DIR]
#   Without ASSET_DIR, downloads the release's assets with gh (a draft release
#   needs a token with write access to the repository to be visible).
#
# Checks:
#   - SHA256SUMS verifies, and lists every asset except itself and image-digests.txt;
#   - the tarball's prefixd and prefixdctl run and report the release version;
#   - the SBOM is CycloneDX JSON;
#   - each image in image-digests.txt resolves to the recorded digest by its
#     X.Y.Z tag and, for a final release, its X.Y tag; the digest-pinned image
#     passes scripts/release-smoke-image.sh.
set -euo pipefail

fail() {
    echo "::error::$*" >&2
    exit 1
}

tag="${1:?usage: scripts/release-install-contract.sh vX.Y.Z [ASSET_DIR]}"
version="${tag#v}"
smoke="$(cd "$(dirname "$0")" && pwd)/release-smoke-image.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

dir="${2:-}"
if [ -z "$dir" ]; then
    dir="$work/assets"
    gh release download "$tag" --dir "$dir"
fi
cd "$dir"

sha256sum --check --strict SHA256SUMS
for f in *; do
    case "$f" in SHA256SUMS | image-digests.txt) continue ;; esac
    awk -v f="$f" '$2 == f { found = 1 } END { exit !found }' SHA256SUMS ||
        fail "$f is not covered by SHA256SUMS"
done
echo "ok: SHA256SUMS covers and verifies every asset"

mkdir "$work/bin"
tar -xzf prefixd-linux-amd64.tar.gz -C "$work/bin"
reported="$("$work/bin/prefixdctl" --version)"
[ "$reported" = "prefixdctl $version" ] || fail "tarball prefixdctl reports '$reported'"
reported="$("$work/bin/prefixd" --version)"
[ "$reported" = "prefixd $version" ] || fail "tarball prefixd reports '$reported'"
echo "ok: tarball binaries run"

jq -e '.bomFormat == "CycloneDX"' prefixd-sbom.cdx.json >/dev/null || fail "prefixd-sbom.cdx.json is not CycloneDX"
echo "ok: SBOM is CycloneDX"

tags=("$version")
[[ "$version" == *-* ]] || tags+=("${version%.*}")
images=0
while read -r repo digest; do
    [ -n "$repo" ] || continue
    [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "bad digest '$digest' for $repo"
    for t in "${tags[@]}"; do
        got="$(docker buildx imagetools inspect "$repo:$t" --format '{{json .Manifest}}' | jq -r .digest)"
        [ "$got" = "$digest" ] || fail "$repo:$t is $got, release records $digest"
    done
    docker pull --quiet "$repo@$digest" >/dev/null
    "$smoke" "${repo##*/}" "$repo@$digest" "$version"
    images=$((images + 1))
done <image-digests.txt
[ "$images" -eq 2 ] || fail "image-digests.txt lists $images images, expected 2"
echo "ok: $tag release install contract"
