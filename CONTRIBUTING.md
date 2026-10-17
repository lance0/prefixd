# Contributing to prefixd

Thanks for your interest in contributing!

## Getting Started

### Prerequisites

- Rust 1.85+ (`rustup update stable`)
- Docker and Docker Compose
- PostgreSQL 14+ (or use Docker)
- protobuf compiler (`protoc`)

### Setup

```bash
# Clone
git clone https://github.com/lance0/prefixd.git
cd prefixd

# Start dependencies
docker compose up -d postgres gobgp

# Build
cargo build

# Run tests
cargo test --features test-utils

# Run with example config
cargo run -- --config ./configs
```

### Running Integration Tests

Integration tests require Docker (testcontainers):

```bash
# All tests including integration
cargo test --features test-utils

# GoBGP integration tests (requires gobgp container)
docker compose up -d gobgp
cargo test --test integration_gobgp -- --ignored
```

---

## Development Workflow

### Branch Naming

- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation
- `refactor/description` - Code refactoring

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(bgp): add IPv6 FlowSpec support
fix(bgp): handle GoBGP reconnection correctly
docs(deploy): update the GoBGP deployment guide
refactor(policy): extract shared guardrails
test(reconcile): cover speaker recovery
```

### Pull Requests

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and lints
5. Submit PR against `main`

PRs should:
- Pass CI (tests, clippy, fmt)
- Include tests for new functionality
- Update documentation if needed
- Have a clear description

### Compatibility and release notes

Review the [stability policy](docs/reference/stability.md) for changes to
configuration, API/CLI behavior, metrics, structured logs or persisted state.
Add a descriptive fragment under [changelog.d/](changelog.d/README.md) instead of
editing `CHANGELOG.md` in parallel with other PRs. Name public interfaces and
public PR references; keep private tracker IDs and operator details out of notes.

```bash
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 scripts/assemble-changelog.py --check
# Check committed changes against the current base branch:
python3 scripts/check-changelog.py --base origin/main
```

CI conservatively requires a new or updated fragment for interface candidate
paths. For an internal/process-only change, put
`Changelog: not needed: <specific reason>` in the PR description and explain why
the observable interfaces and behavior are preserved. This rationale is reviewed;
the checker cannot infer semantics. Documentation/test-only changes need no empty
release note. Editing the PR description reruns CI with the updated rationale.
Run these alongside the relevant Rust and dashboard checks.

---

## Code Style

### Formatting

```bash
# Format code
cargo fmt

# Check formatting
cargo fmt -- --check
```

### Linting

```bash
# Run clippy
cargo clippy --all-targets --all-features -- -D warnings
```

### Pre-commit Hooks

Optional but recommended:

```bash
# Install pre-commit
pip install pre-commit
pre-commit install

# Hooks run automatically on commit
```

---

## Project Structure

```
src/
├── alerting/      # Webhook alerting (Slack, Discord, Teams, PagerDuty, etc.)
├── api/           # HTTP handlers and routes
├── bgp/           # GoBGP client, FlowSpec construction
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
proto/            # GoBGP protobuf definitions
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
cargo test --features test-utils

# GoBGP tests (slower, require container)
cargo test --test integration_gobgp -- --ignored
```

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
- Add a changelog fragment for operator-visible changes; assemble notes for releases

### Architecture Decision Records

We document significant design decisions in [docs/adr/](docs/adr/). When making a change that affects the system's architecture (new dependency, new pattern, structural change), add an ADR following the existing format. See [ADR README](docs/adr/README.md) for the index and template.

---

## Release Process

Releases are tagged from `main`:

```bash
# Validate, then assemble fragments into the existing Unreleased section.
python3 scripts/assemble-changelog.py --check
python3 scripts/assemble-changelog.py
# Review the diff; the assembler consumes fragments only after writing succeeds.
# Update version in Cargo.toml
# Roll the reviewed Unreleased notes into the release section in CHANGELOG.md
# Commit and tag
git tag v0.14.1
git push origin v0.14.1
```

CI builds and publishes:
- GitHub Release with binaries
- Docker image to ghcr.io

---

## Getting Help

- Open an issue for bugs or feature requests
- Check existing issues before creating new ones
- Be respectful and constructive

---

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

### Dashboard checks

Use Bun 1.3.14 with the committed `frontend/bun.lock`:

```bash
cd frontend
bun install --frozen-lockfile
bun run test
bun run build
bun audit
```

The dashboard always uses the configured API. Keep response fixtures in tests;
`NEXT_PUBLIC_MOCK_MODE` is retired. `next lint` was removed upstream; replacement
ESLint/type-check checks and a browser harness remain frontend tooling work.
