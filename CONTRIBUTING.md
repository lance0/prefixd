# Contributing to prefixd

Thanks for your interest in contributing!

## Getting Started

### Prerequisites

- Rust 1.89+ (`rustup update stable`)
- Docker and Docker Compose
- PostgreSQL 14+ (or use Docker)
- protobuf compiler (`protoc`)
- [just](https://just.systems/), `cargo-audit` and `cargo-deny`
- Bun 1.4.3 and native Node.js 26.12.0 for the dashboard
- [uv](https://docs.astral.sh/uv/) for `just python`, which runs the pinned ruff

CI checks the locked dependency graph on Linux with Rust 1.89.0, including
development dependencies, alongside the current stable tests and lints. To
repeat the minimum-compiler checks with that toolchain installed:

```bash
cargo +1.89.0 check --locked --bins --features bgp-rustbgpd
cargo +1.89.0 check --locked --all-targets --all-features
cargo +1.89.0 check --locked --no-default-features --bins
```

The production Docker builder pins Rust 1.99.1 and its image digest in
`Dockerfile`. That build toolchain is separate from the minimum supported compiler.

### Setup

```bash
# Clone
git clone https://github.com/lance0/prefixd.git
cd prefixd

# Build
cargo build --locked

# Run tests; Docker must be available for disposable PostgreSQL fixtures
cargo test --locked --features test-utils
```

For a running controller and dashboard, follow the
[rustbgpd quickstart](docs/tutorials/quickstart.md), including its separate
prebuilt-image and source-build commands. The Compose speaker RPC endpoints are
private to the selected profile; a host `cargo run` cannot use those example
addresses unchanged.

### Running Integration Tests

The speaker scripts create and clean up their own pinned Docker fixtures. They
do not use the Compose stack or an existing router lab. Run them from the
repository root with Docker available:

```bash
# Controller tests, including disposable PostgreSQL fixtures
cargo test --locked --features test-utils

# Released rustbgpd controller and receiving-peer fixtures
scripts/test-rustbgpd.sh
PREFIXD_RUSTBGPD_TEST_VERSION=0.76.0 scripts/test-rustbgpd.sh

# GoBGP fixtures
scripts/test-gobgp.sh
```

---

## Development Workflow

### Local verification

Run `just gate` before opening a PR with substantive code changes. It runs
Rust and Python formatting, Python lint, both locked Rust test
and Clippy feature combinations, minimum-compiler checks, the release build,
frozen dashboard install/types/tests/build, advisory checks and the owned GoBGP
and rustbgpd 0.76.0/0.77.0/0.78.0 fixtures, sequentially. It needs Docker and the tools
listed above; it does not install missing tools or Rust toolchains.
Prose-only changes need affected-link checks and `git diff --check`.

Use `just --list` for focused checks such as `just fmt`, `just python`,
`just clippy`, `just test-fast`, `just msrv` or `just frontend`. Recipes expose ordinary
commands, and CI shares them while retaining separate jobs and speaker versions.
The Rust advisory recipe keeps CI's explicit unfixed `rsa` exception; warnings
remain visible.

The gate preserves caller `CARGO_BUILD_JOBS` and `CARGO_TARGET_DIR`. On a shared
host, allocate CPUs and set existing worker controls such as
`VITEST_MAX_WORKERS` before starting it; `PREFIXD_TEST_CPUSET` separately
restricts the owned speaker containers. Coordinate other builds yourself.

This manual gate is broader than the optional hooks below. Image builds and
publication, release/SBOM operations, long labs, performance/fuzz work and
owned authenticated browser qualification remain separate checks.

### Branch Naming

- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation
- `refactor/description` - Code refactoring

### Commit Messages

Use `type(scope): imperative summary` for commits and PR titles, following
[Conventional Commits](https://www.conventionalcommits.org/). Choose the affected
module as the scope and write the summary as an instruction:

```
feat(bgp): add IPv6 FlowSpec support
fix(bgp): handle GoBGP reconnection correctly
docs(deploy): update deployment guide for GoBGP v4
refactor(guardrails): extract guardrails into separate module
test(scheduler): add integration tests for reconciliation
```

### Pull Requests

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. For substantive code, run `just gate` and change-specific checks. For prose-only
   changes, check affected links and run `git diff --check`.
5. Submit PR against `main`

PRs should:
- Pass CI (tests, clippy, fmt)
- Include tests for new functionality
- Update documentation if needed
- Have a clear description

---

## Code Style

### Formatting

```bash
# Format code
cargo fmt --all

# Check formatting
just fmt
```

### Linting

The library, daemon and CLI crate roots forbid unsafe code and deny
`clippy::allow_attributes_without_reason`. Give every handwritten `allow` or
`expect` a specific `reason = "..."` and place it on the narrowest relevant item.
Keep any necessary generated-code exceptions inside their protobuf wrapper;
retain them only for an actual compiler diagnostic.

```bash
# Run clippy
just clippy
```

### Dependency policy

Install `cargo-deny` and run
`cargo deny --workspace --all-features --locked check advisories bans licenses sources`
for the backend dependency gate. `deny.toml` checks development/build dependencies,
licenses and sources, rejects wildcard requirements, and keeps duplicate versions
visible as warnings. Reassess the exact certificate-data license exceptions on
version changes. The separate full-lock Rust advisory audit retains the RSA exception for SQLx's
optional, uncompiled MySQL dependency. Cargo-deny's selected graph does not
currently include it; passing cargo-deny is not an exception-free full-lock audit.
The Rust advisory and frontend `bun audit` checks remain required in CI.

### Optional Git hooks

With `just` and either `prek` or Python `pre-commit` installed, enable both
configured stages:

```bash
prek install --hook-type pre-commit --hook-type pre-push
# Or:
pre-commit install --hook-type pre-commit --hook-type pre-push
```

Commit hooks check formatting without rewriting files, run ruff for Python inputs
and run locked all-feature Clippy for Rust inputs. Push hooks run locked all-feature library and binary
unit tests. Manifests, lockfiles, protobufs and Cargo/toolchain configuration
also trigger lint/tests; prose-only changes skip Rust builds. These quick hooks
do not run Docker, MSRV or frontend checks and do not replace `just gate`.

---

## Project Structure

```
src/
├── alerting/      # Webhook alerting (Slack, Discord, Teams, PagerDuty, etc.)
├── api/           # HTTP handlers and routes
├── bgp/           # Speaker traits, rustbgpd and GoBGP adapters
├── config/        # YAML configuration parsing
├── db/            # PostgreSQL repository
├── domain/        # Core types (AttackEvent, Mitigation, etc.)
├── guardrails/    # Safety validation
├── observability/ # Metrics, logging
├── policy/        # Policy engine, playbooks
├── scheduler/     # Reconciliation loop
├── auth/          # Authentication (sessions, operators)
├── ws/            # WebSocket handler
├── error.rs       # Error types
├── state.rs       # Shared application state
├── lib.rs         # Public module exports
└── main.rs        # CLI and startup

tests/
├── integration_*.rs  # Integration tests (testcontainers)
└── ...

frontend/         # Next.js dashboard
docs/             # Documentation
configs/          # Example configuration files
proto/            # Speaker protobuf definitions
```

---

## Testing

### Unit Tests

```bash
# Run unit tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_name
```

### Integration Tests

```bash
# Requires Docker
cargo test --locked --features test-utils

# Owned speaker fixtures (Docker; independent of Compose)
scripts/test-rustbgpd.sh
scripts/test-gobgp.sh
```

### Dashboard tests

Run `bun run test` in `frontend/`. Pure validation, formatting and API tests
that do not use the DOM select `// @vitest-environment node`; interaction tests
keep jsdom and the real React components, providers and Radix controls. Avoid
paying for a browser environment in tests that do not need one.

The fake controller's `settle()` flushes resolved responses and React effects
with async `act`. It does not wait for a real timer or advance polling clocks;
tests of expiry and retries must control those clocks explicitly.

Withdrawal interaction tests control the clock so their exact mutation-refresh
counts cannot include an unrelated five-second SWR poll during a slow render.
Their waits advance UI timers inside `act`; a separate API-hook test verifies
the real hook polls at five seconds. Keep those polling assertions separate
from withdrawal request, duplicate-submission and retry assertions.

For slow-runner investigation, set `VITEST_MAX_WORKERS=1` and restrict CPU
availability as well. On Linux, `taskset -c 0 bun run test` pins execution to
CPU 0 when that CPU is allowed; an owned container's `--cpus` quota can simulate
a smaller CPU share. A worker limit alone does not throttle execution. Compare
the same runtime, lockfile, quota and selected tests, and retain failing results
before changing either the tests or their time budgets.

The speaker-health, withdrawal-confirmation, manual-mitigation and notification
preferences form suites use a local 10-second test budget. Their cold React and
Radix renders plus accessibility queries can exceed Vitest's 5-second default
under a 0.125-CPU quota, including after removing unnecessary fixture timers.
These suites retain full components, request assertions, focus checks and
failure/retry coverage. Other suites keep Vitest's default budget; do not raise
the global timeout to compensate for a slow integration file.

### Test Coverage

```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Generate coverage
cargo tarpaulin --out Html
```

---

## Documentation

### Code Comments

- Document public APIs with `///` doc comments
- Explain "why" not "what" in inline comments
- Use `// TODO:` for future work

### Markdown

- Keep docs in `docs/` directory
- Update README.md for user-facing changes
- Update CHANGELOG.md for releases

### Architecture Decision Records

We document significant design decisions in [docs/adr/](docs/adr/). When making a change that affects the system's architecture (new dependency, new pattern, structural change), add an ADR following the existing format. See [ADR README](docs/adr/README.md) for the index and existing format.

---

## Release Process

Follow the [release checklist](docs/project/release-checklist.md). In short:

1. Run `just release-prepare X.Y.Z` on a branch. It bumps the version,
   refreshes Cargo.lock and rolls the CHANGELOG; finish the manual items it
   prints.
2. Open `chore(release): prepare vX.Y.Z`. It must pass `just gate`, both
   rustbgpd fixture pins and the upgrade proof, as recorded in its body.
3. Merge it. When `ci.yml` passes on the merge commit, the release workflow
   tags it `vX.Y.Z` and publishes the images and the GitHub Release.
4. Verify the image digests and the install contract.

Never re-tag, move a tag or overwrite a release; fix forward with a patch
version. A manual dispatch of the release workflow is a dry run that publishes
nothing.

---

## Getting Help

- Open an issue for bugs or feature requests
- Check existing issues before creating new ones
- Be respectful and constructive

---

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

### Dashboard checks

Use Bun 1.4.3 and Node.js 26.12.0 with the committed `frontend/bun.lock`.
Run tests with native Node.js 26.12.0; production containers build and run with Bun:

```bash
cd frontend
bun install --frozen-lockfile
bun run lint
bun run typecheck
bun run test
bun run build
bun audit
```

The dashboard always uses the configured API. Keep response fixtures in tests;
`NEXT_PUBLIC_MOCK_MODE` is retired. `bun run lint` runs Oxlint with the vendored
anti-slop rules in `frontend/tools/oxlint/anti-slop/`; it must report no errors
or warnings. Fix findings rather than suppressing them. Tests replace the
controller with `frontend/__tests__/support/fake-controller.tsx` behind the real
fetch path instead of mocking modules. Automated browser CI remains frontend
tooling work. Production builds enforce TypeScript checks; `bun run typecheck`
runs them independently.
