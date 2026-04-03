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
feat: add IPv6 FlowSpec support
fix: handle GoBGP reconnection correctly
docs: update deployment guide for GoBGP v4
refactor: extract guardrails into separate module
test: add integration tests for reconciliation
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
- Update CHANGELOG.md for releases

### Architecture Decision Records

We document significant design decisions in [docs/adr/](docs/adr/). When making a change that affects the system's architecture (new dependency, new pattern, structural change), add an ADR following the existing format. See [ADR README](docs/adr/README.md) for the index and template.

---

## Release Process

Releases are tagged from `main`:

```bash
# Update version in Cargo.toml
# Update CHANGELOG.md
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
