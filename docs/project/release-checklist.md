# Release checklist

Follow this page for every prefixd release. A release publishes:

- the `prefixd` and `prefixd-dashboard` images on `ghcr.io/lance0`, tagged
  `X.Y.Z` and `X.Y`;
- a Linux amd64 tarball holding `prefixd` and `prefixdctl`;
- a CycloneDX SBOM;
- `SHA256SUMS` and the image digests.

The tag-triggered [release workflow](../../.github/workflows/release.yml)
publishes the images and creates a **draft** GitHub Release. The owner approves
the tag push and publishes the draft; no automation does either.

Never force-push `main`, move or re-create a pushed tag, or overwrite a release.
If a pushed tag can't release, fix forward with the next patch version.

## Preconditions

Check these on the release candidate before opening the release PR:

- [ ] `just gate` passes. It runs formatting, both Clippy and test feature sets,
      MSRV, the release build, the dashboard checks, advisories, cargo-deny and
      the speaker fixtures. Record the command and its result in the release PR.
- [ ] Both rustbgpd fixture pins pass. `just gate` runs them through
      `just speakers`. To rerun them alone:

      ```bash
      PREFIXD_RUSTBGPD_TEST_VERSION=0.76.0 scripts/test-rustbgpd.sh
      PREFIXD_RUSTBGPD_TEST_VERSION=0.77.0 scripts/test-rustbgpd.sh
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

[`scripts/release-notes.py`](../../scripts/release-notes.py) extracts the
section that becomes the release body. It fails closed when the section is
missing, undated or empty.

- [ ] Rename the completed `## [Unreleased]` entries to
      `## [X.Y.Z] - YYYY-MM-DD`, with no leading `v` and the UTC date of the
      planned tag. Leave a fresh, empty `## [Unreleased]` above it.
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

- [ ] `Cargo.toml` `[package] version` is `X.Y.Z`.
- [ ] Run `cargo update --workspace`. Afterwards `git diff Cargo.lock` changes
      only the `prefixd` package version.
- [ ] The README **Status** line names the new release and is accurate.
- [ ] The OpenAPI document at `/openapi.json` reports `info.version` `X.Y.Z`.
      It must take that version from Cargo (`CARGO_PKG_VERSION`), not a
      literal in `src/api/openapi.rs`.
- [ ] `prefixdctl --version` and the health endpoints' `version` field already
      come from Cargo; spot-check one.
- [ ] Search for the previous version in current examples, such as pinned
      images in the upgrade and deployment guides, and move only current ones.
      Leave historical records unchanged.

## Release steps

1. **Release PR.** Open a PR with the bump and the CHANGELOG roll, titled
   `chore(release): prepare vX.Y.Z`. Its body records `just gate`, both fixture
   pins, the upgrade proof and the release-notes preview. Review it like any
   other PR.
2. **Merge.** Merge the release PR once its checks pass. Note the merge commit
   SHA; that commit is the one you tag.
3. **Exact-main CI.** Wait for `ci.yml`'s push run on that exact commit to
   succeed. Matching file contents on another commit don't count:

   ```bash
   gh run list --workflow ci.yml --branch main --commit <sha>
   ```

   If this cycle changed `release.yml`, `release-install-contract.yml` or the
   `scripts/release-*` files, dry-run the release workflow too. A dispatch
   runs every job at `main` but pushes no image and creates no release:

   ```bash
   gh workflow run release.yml --ref main
   ```

4. **Owner-approved tag.** With the owner's explicit approval, push an
   annotated tag for the release commit:

   ```bash
   git tag -a vX.Y.Z -m "vX.Y.Z" <sha>
   git push origin vX.Y.Z
   ```

5. **Release workflow.** Watch the run (`gh run watch <run-id> --exit-status`).
   It runs these jobs in order, and each needs the previous one:
   - `verify` runs `scripts/release-check.sh`. It checks that the tag equals
     the Cargo version, the tag points at the commit, the commit is on `main`
     and its `ci.yml` push run succeeded. Then it extracts the notes.
   - `binaries` builds on Debian 12 (glibc 2.36) and produces the tarball,
     SBOM and `SHA256SUMS`.
   - `images` builds each image, smoke-tests it, then pushes `X.Y.Z` and `X.Y`
     and records the digest. `latest` stays with ci.yml's `main` images.
   - `release` creates the draft with the notes, digests, checksums and assets.

   A failure before `images` pushed anything publishes nothing. Rerunning a
   failed `images` job rebuilds the image and can move the version tags to a
   new digest. The draft records the final digests; verify against those.
6. **Verify digests.** Each image's version tags resolve to the digest in the
   draft:

   ```bash
   docker buildx imagetools inspect ghcr.io/lance0/prefixd:X.Y.Z
   docker buildx imagetools inspect ghcr.io/lance0/prefixd-dashboard:X.Y
   ```

7. **Install contract.** The
   [install contract](../../.github/workflows/release-install-contract.yml)
   runs after a successful tag-triggered release. It runs
   `scripts/release-install-contract.sh`, which checks:
   - every asset verifies against `SHA256SUMS`;
   - the tarball binaries run and report `X.Y.Z`;
   - the SBOM is CycloneDX;
   - both images resolve to the recorded digests and pass the image smoke
     test.

   If the contract didn't run, or after any rerun, start it by hand:

   ```bash
   gh workflow run release-install-contract.yml -f tag=vX.Y.Z
   ```

8. **Owner publishes.** The owner reviews the draft's notes, assets and
   digests, then publishes it. Publishing is the owner's step:

   ```bash
   gh release edit vX.Y.Z --draft=false
   ```
