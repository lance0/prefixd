#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Nonpeered fixtures use host loopback; peered fixtures use an owned bridge
# with only authenticated RPC published to host loopback.
# PREFIXD_TEST_CPUSET optionally restricts the fixture containers on shared hosts.
export PREFIXD_RUSTBGPD_TEST_TOKEN="${PREFIXD_RUSTBGPD_TEST_TOKEN:-$(python3 -c 'import secrets; print(secrets.token_hex(32))')}"
cargo test --locked --features bgp-rustbgpd,test-utils --test integration_rustbgpd --test integration_rustbgpd_peer --test integration_vpn_recovery --test integration_guarded_scrubber --test integration_scrubber_store -- --ignored --test-threads=1 --nocapture
