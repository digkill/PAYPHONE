#!/usr/bin/env bash
# Single-connection acceptance check; does not alter host networking.
set -euo pipefail
cd "$(dirname "$0")/../.."
export PAYPHONE_BENCH_MIN_MBPS="${PAYPHONE_BENCH_MIN_MBPS:-200}"
export PAYPHONE_BENCH_MAX_LOSS_PCT="${PAYPHONE_BENCH_MAX_LOSS_PCT:-0.1}"
exec cargo run --release -p payphone-transport --example bench_datagrams -- 1 "${2:-300}" "${1:-120}"
