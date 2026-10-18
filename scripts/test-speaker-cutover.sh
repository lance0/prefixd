#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Isolated immutable speaker fixtures and one disposable PostgreSQL instance.
# PREFIXD_TEST_CPUSET optionally restricts containers on shared hosts.
export PREFIXD_RUSTBGPD_TEST_TOKEN="${PREFIXD_RUSTBGPD_TEST_TOKEN:-$(python3 -c 'import secrets; print(secrets.token_hex(32))')}"
cargo test --locked --features bgp-rustbgpd,test-utils --test integration_speaker_cutover -- --ignored --test-threads=1 --nocapture
