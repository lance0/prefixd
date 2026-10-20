# Release checklist

Follow this page for every prefixd release. A release publishes:

- the `prefixd` and `prefixd-dashboard` images on `ghcr.io/lance0`, tagged
  `X.Y.Z` and `X.Y`;
- a Linux amd64 tarball holding `prefixd` and `prefixdctl`;
- a CycloneDX SBOM;
- `SHA256SUMS` and the image digests.

The release is automatic once the release PR merges. When `ci.yml` passes on
the `main` commit that sets a new Cargo.toml version, the
[release workflow](../../.github/workflows/release.yml) tags that commit
`vX.Y.Z` and publishes the GitHub Release as `github-actions[bot]`. Merging the
release PR is the approval; there is no tag push or draft to publish by hand.

Never force-push `main`, move, delete or re-create a pushed tag, or overwrite a
release. If a tag can't release, fix forward with the next patch version.

## Steps

1. **Prepare.** From a clean, up-to-date `main` checkout on a new branch:

   ```bash
   just release-prepare X.Y.Z
   ```

   [`scripts/release-prepare.sh`](../../scripts/release-prepare.sh) sets the
   Cargo.toml version, runs `cargo update --workspace` and checks that
   Cargo.lock changed only the `prefixd` entry. It rolls `## [Unreleased]` into
   `## [X.Y.Z] - <today, UTC>` under a fresh empty `## [Unreleased]`, moves the
   compare links at the end of the CHANGELOG and previews the release body. It
   refuses a dirty tree, a version that isn't greater than the current one, and
   an empty `[Unreleased]` section. It commits and pushes nothing. Then finish
   the manual items it prints; see [Version bump points](#version-bump-points).

2. **Release PR.** Open a PR titled `chore(release): prepare vX.Y.Z`. Its body
   records the [preconditions](#preconditions): `just gate`, the rustbgpd
   fixture pins and the upgrade proof, plus the release-notes preview. Review
   it like any other PR.

   Changes to `release.yml`, `release-install-contract.yml` or the
   `scripts/release-*` files land in their own PR first, never in the release
   PR. After that PR merges and its `main` CI passes,
   [dry-run](#dry-run) the release workflow on `main`.

3. **Merge.** Merging is the release decision. When `ci.yml`'s push run on the
   merge commit succeeds, the release workflow starts from that run. Matching
   file contents on another commit don't count. Watch it with
   `gh run list --workflow release.yml --limit 3` and
   `gh run watch <run-id> --exit-status`. Its jobs run in order, and each needs
   the previous one:
   - `verify` resolves the tag from the Cargo version at the merge commit. It
     stops quietly if that commit didn't change the version, the tag already
     exists or the CHANGELOG has no dated section. Otherwise it runs
     `scripts/release-check.sh`: the tag equals the Cargo version, the commit
     is on `main` and its `ci.yml` push run succeeded. It also refuses a
     version that already has a release, then extracts the notes.
   - `binaries` builds on Debian 12 (glibc 2.36) and produces the tarball,
     SBOM and `SHA256SUMS`.
   - `tag` creates the annotated `vX.Y.Z` tag on the merge commit.
   - `images` builds each image, smoke-tests it, then pushes `X.Y.Z` and `X.Y`
     and records the digest. `latest` stays with ci.yml's `main` images.
   - `release` publishes the GitHub Release. Its title is the tag, and its body
     is the CHANGELOG section, the digests and `SHA256SUMS`, then a compare
     link to the previous final release. A final release is marked latest
     unless a newer final release exists; an `X.Y.Z-rc.N` version is marked as
     a prerelease.
   - `install-contract` checks the published release; see step 4.

   A failure before `tag` creates nothing. A failure at or after `tag` leaves
   the version spent. See [Stop or recover](#stop-or-recover) for both.

4. **Verify.** Each image's version tags resolve to the digest in the release:

   ```bash
   docker buildx imagetools inspect ghcr.io/lance0/prefixd:X.Y.Z
   docker buildx imagetools inspect ghcr.io/lance0/prefixd-dashboard:X.Y
   ```

   The [install contract](../../.github/workflows/release-install-contract.yml)
   runs as the last job of the release run. It runs
   `scripts/release-install-contract.sh`, which checks:
   - every asset verifies against `SHA256SUMS`;
   - the tarball binaries run and report `X.Y.Z`;
   - the SBOM is CycloneDX;
   - both images resolve to the recorded digests and pass the image smoke
     test.

   If it didn't run, or after any rerun, start it by hand:

   ```bash
   gh workflow run release-install-contract.yml -f tag=vX.Y.Z
   ```

## Stop or recover

- **Before merge**, nothing has happened; close or fix the PR.
- **To stop a release in flight**, cancel the release run before its `tag` job
  (`gh run cancel <run-id>`). Nothing is tagged or pushed until then. Don't
  cancel after `tag`: the tag exists and the version is spent.
- **A transient failure** (registry, runner, network): rerun the failed jobs
  with `gh run rerun <run-id> --failed`. The rerun keeps the verified tag and
  commit. Rerunning `images` rebuilds and can move the version
  tags to a new digest; the release records the final digests. Don't use
  "Re-run all jobs": `verify` sees the existing tag and stops.
- **A bad release or a failure that a rerun can't fix:** don't re-tag, delete
  the tag or edit published assets. Fix forward: land the fix and release the
  next patch version through a new release PR. Say what went wrong in its
  CHANGELOG section.
- **If CI fails on the release commit,** rerun the failed CI jobs if the
  failure is transient; a passing rerun starts the release. If the release
  commit itself is broken, land the fix and then release a new version. Only
  the commit that sets a version can tag itself. To release an existing later
  commit instead, the owner can push the tag by hand:

  ```bash
  git tag -a vX.Y.Z -m "vX.Y.Z" <sha>
  git push origin vX.Y.Z
  ```

  A pushed tag runs the same workflow and checks: that commit must carry the
  version, be on `main` and have passed `ci.yml`.

## Dry run

A manual dispatch of the release workflow is a dry run at the chosen ref:

```bash
gh workflow run release.yml --ref main
```

It takes the tag name from that ref's Cargo.toml, runs `release-check.sh`
without checking where an existing tag points, and runs every build, smoke
test and body assembly. It creates no tag, pushes no image and creates no
release. The run summary shows the release body it would publish. The ref's
commit must be on `main` with a passing `ci.yml` push run, so a PR branch
can't be dry-run.

## Preconditions

Check these on the release candidate before opening the release PR:

- [ ] `just gate` passes. It runs formatting, both Clippy and test feature sets,
      MSRV, the release build, the dashboard checks, advisories, cargo-deny and
      the speaker fixtures. Record the command and its result in the release PR.
- [ ] All rustbgpd fixture pins pass. `just gate` runs them through
      `just speakers`. To rerun them alone:

      ```bash
      PREFIXD_RUSTBGPD_TEST_VERSION=0.76.0 scripts/test-rustbgpd.sh
      PREFIXD_RUSTBGPD_TEST_VERSION=0.77.0 scripts/test-rustbgpd.sh
      PREFIXD_RUSTBGPD_TEST_VERSION=0.78.0 scripts/test-rustbgpd.sh
      PREFIXD_RUSTBGPD_TEST_VERSION=0.79.0 scripts/test-rustbgpd.sh
      ```

      Use the pins in ci.yml's `rustbgpd` matrix if they have moved.
- [ ] The upgrade proof passes. Upgrade from the previous release tag to the
      candidate with a real previous-release database. Build that database
      from the tag; it should hold active manual and detector mitigations and a
      withdrawn one. Follow the [upgrade guide](../how-to/upgrading.md) as
      written. Record the outcome in the release PR:
      - migrations apply;
      - any required adoption step runs once;
      - authenticated health is healthy;
      - the first reconciliation succeeds without repairs;
      - the same mitigation IDs stay active;
      - the speaker RIB is unchanged.

      The guide must have a section for this version pair.
- [ ] Known limitations are reviewed and stated in the release notes.

## CHANGELOG section

`just release-prepare` rolls the section;
[`scripts/release-notes.py`](../../scripts/release-notes.py) extracts it as
the release body. The workflow fails closed, or doesn't tag, when the section
is missing, undated or empty.

- [ ] The heading reads `## [X.Y.Z] - YYYY-MM-DD`, with no leading `v`. The
      date is the UTC day `release-prepare` ran; correct it if the PR merges
      on a later day.
- [ ] An optional short summary paragraph may open the section, before the
      first `###` group. It leads the release body.
- [ ] Keep the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) groups
      already in use: `### Upgrade notes` first when an upgrade needs operator
      action, then `Security`, `Added`, `Changed`, `Fixed` and `Documentation`.
      Upgrade notes link the matching [upgrade guide](../how-to/upgrading.md)
      section.
- [ ] Review `git log vPREV..HEAD --oneline`. List every user- or
      operator-visible change under the new version and none under an older
      one. Changes to configuration, API JSON, WebSocket messages, CLI output,
      metrics and log fields need an entry.
- [ ] Preview the release body: `scripts/release-notes.py X.Y.Z`. It joins
      hard-wrapped lines, because GitHub renders each newline as a line break.

## Version bump points

`just release-prepare` covers the first two; the rest stay manual.

- [ ] `Cargo.toml` `[package] version` is `X.Y.Z`.
- [ ] `git diff Cargo.lock` changes only the `prefixd` package version.
- [ ] The README **Status** line names the new release and is accurate.
- [ ] The [upgrade guide](../how-to/upgrading.md) has a section for the
      previous release → `X.Y.Z`.
- [ ] The OpenAPI document at `/openapi.json` reports `info.version` `X.Y.Z`.
      It must take that version from Cargo (`CARGO_PKG_VERSION`), not a
      literal in `src/api/openapi.rs`.
- [ ] `prefixdctl --version` and the health endpoints' `version` field already
      come from Cargo; spot-check one.
- [ ] Search for the previous version in current examples, such as pinned
      images in the upgrade and deployment guides, and move only current ones.
      Leave historical records unchanged.
