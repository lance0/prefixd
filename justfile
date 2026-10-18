# Local verification. Tool installation, publication and browser fixtures are separate.
export RUSTUP_AUTO_INSTALL := "0"
msrv_toolchain := "1.89.0"

# Show the focused checks.
default:
    just --list

# Run substantive code pre-PR checks sequentially; Docker is required.
gate:
    just fmt
    just clippy
    just test
    just msrv
    just build
    just frontend
    just audit
    just deny
    just speakers

# Check formatting without rewriting source.
fmt:
    cargo fmt --all -- --check

clippy-gobgp:
    cargo clippy --locked --no-default-features --all-targets -- -D warnings

clippy-all:
    cargo clippy --locked --all-targets --all-features -- -D warnings

clippy:
    just clippy-gobgp
    just clippy-all

test-gobgp:
    cargo test --locked --no-default-features --features test-utils

test-all:
    cargo test --locked --all-features

# Exclude the PostgreSQL row fixture here; full test recipes still run it.
# Focused library and CLI tests for the optional push hook; no Docker fixtures.
test-fast:
    cargo test --locked --all-features --lib --bins -- --skip db::repository::checked_timestamp_rows

test:
    just test-gobgp
    just test-all

# Requires this exact installed toolchain; never installs one implicitly.
msrv:
    cargo +{{msrv_toolchain}} check --locked --bins --features bgp-rustbgpd
    cargo +{{msrv_toolchain}} check --locked --all-targets --all-features
    cargo +{{msrv_toolchain}} check --locked --no-default-features --bins

build:
    cargo build --locked --release

# Native Node runs tests and CLI tools; production containers build/run with Bun.
[working-directory: "frontend"]
frontend:
    bun install --frozen-lockfile
    bun run lint
    bun run typecheck
    bun run test
    bun run build

# Match CI's sole unfixed advisory exception. rsa is an optional, uncompiled
# sqlx MySQL dependency. Other vulnerabilities fail; advisory warnings stay visible.
audit-rust:
    cargo audit --ignore RUSTSEC-2023-0071

# Check the dependency policy alongside the advisory-only audit.
deny:
    cargo deny --workspace --all-features --locked check advisories bans licenses sources

[working-directory: "frontend"]
audit-frontend:
    bun install --frozen-lockfile
    bun audit

audit:
    just audit-rust
    just audit-frontend

# These scripts own and clean up pinned fixtures, independently of Compose/labs.
test-gobgp-speaker:
    scripts/test-gobgp.sh

test-rustbgpd-speaker:
    scripts/test-rustbgpd.sh

speakers:
    just test-gobgp-speaker
    PREFIXD_RUSTBGPD_TEST_VERSION=0.76.0 just test-rustbgpd-speaker
    PREFIXD_RUSTBGPD_TEST_VERSION=0.77.0 just test-rustbgpd-speaker
