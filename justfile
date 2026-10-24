# Local verification. Tool installation, publication and browser fixtures are separate.
export RUSTUP_AUTO_INSTALL := "0"
msrv_toolchain := "1.89.0"
fuzz_toolchain := "nightly-2026-07-07"
ruff_version := "0.16.0"
prometheus_image := "prom/prometheus:v3.15.0"

# Show the focused checks.
default:
    just --list

# Run substantive code pre-PR checks sequentially; Docker is required.
gate:
    just fmt
    just python
    just test-load-script
    just alerts
    just proto
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

# Lint and format-check every Python file against ruff.toml; uvx fetches the pinned ruff.
python:
    uvx ruff@{{ruff_version}} check .
    uvx ruff@{{ruff_version}} format --check .

# Validate HTTP workload interpretation using only tiny owned loopback fixtures; requires hey.
test-load-script:
    bash -n scripts/load-test.sh
    python3 scripts/test-load-test.py

# Validate the Prometheus alert rules and run their unit tests with pinned promtool.
alerts:
    docker run --rm ${PREFIXD_TEST_CPUSET:+--cpuset-cpus "$PREFIXD_TEST_CPUSET"} -v "$PWD/grafana:/rules:ro" --entrypoint promtool {{prometheus_image}} check rules /rules/prometheus-alerts.yml
    docker run --rm ${PREFIXD_TEST_CPUSET:+--cpuset-cpus "$PREFIXD_TEST_CPUSET"} -v "$PWD/grafana:/rules:ro" --entrypoint promtool {{prometheus_image}} test rules /rules/prometheus-alerts.test.yml

# Offline: the pinned rustbgpd proto must match its release checksum asset.
[working-directory: "proto"]
proto:
    sha256sum --check --strict rustbgpd.proto.sha256

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

# Execute every Criterion body once, without collecting performance measurements.
bench-smoke:
    cargo test --locked --bench benchmarks -- --test

# Requires the pinned nightly and cargo-fuzz 0.13.2; no speaker or database is used.
fuzz-smoke:
    cargo +{{fuzz_toolchain}} fetch --locked --manifest-path fuzz/Cargo.toml
    cargo +{{fuzz_toolchain}} fuzz run --dev --target-dir "${CARGO_TARGET_DIR:-target}/fuzz-smoke" fuzz_prefix_parse -- -max_total_time=30 -timeout=5 -rss_limit_mb=2048 -max_len=4096
    cargo +{{fuzz_toolchain}} fuzz run --dev --target-dir "${CARGO_TARGET_DIR:-target}/fuzz-smoke" fuzz_nlri_decode -- -max_total_time=30 -timeout=5 -rss_limit_mb=2048 -max_len=4096

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

# Audit both locked graphs with CI's sole unfixed exception: rsa is an optional,
# uncompiled sqlx MySQL dependency. Other vulnerabilities fail; warnings stay visible.
audit-rust:
    cargo audit --ignore RUSTSEC-2023-0071
    cargo audit --file fuzz/Cargo.lock --ignore RUSTSEC-2023-0071

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
    PREFIXD_RUSTBGPD_TEST_VERSION=0.79.0 just test-rustbgpd-speaker

# Needs Docker and containerlab; set CLAB="sudo containerlab" outside clab_admins. Not in gate.
# Run the prefixd -> speaker -> FRR FlowSpec interop lab and write dated receipts.
interop-frr *speakers="rustbgpd gobgp":
    docker build --build-arg CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}" -t prefixd:interop .
    python3 -m unittest discover -s lab/interop -p 'test_*.py'
    for speaker in {{speakers}}; do lab/interop/run-frr.sh "$speaker"; done

# Qualify prefixd blackhole host routes at FRR through rustbgpd (ADR 027) and write a dated receipt.
interop-frr-blackhole:
    docker build --build-arg CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}" -t prefixd:interop .
    python3 -m unittest discover -s lab/interop -p 'test_*.py'
    lab/interop/run-frr.sh rustbgpd blackhole

# Qualify amplification FlowSpec rules (ADR 028) at FRR and write dated receipts.
interop-frr-amplification *speakers="rustbgpd gobgp":
    docker build --build-arg CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}" -t prefixd:interop .
    python3 -m unittest discover -s lab/interop -p 'test_*.py'
    for speaker in {{speakers}}; do lab/interop/run-frr.sh "$speaker" amplification; done

# Merging the release PR tags and publishes the release once main CI passes.
# Prepare a release PR: version bump, Cargo.lock and CHANGELOG roll; commits nothing.
release-prepare version:
    scripts/release-prepare.sh {{version}}
