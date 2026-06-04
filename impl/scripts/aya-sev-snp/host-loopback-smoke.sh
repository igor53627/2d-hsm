#!/usr/bin/env bash
# Host-only vsock loopback (no VM). Same as manual test on aya with CID=1.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${HSM_BIN:-/root/2d-hsm/impl/rust/enclave-protocol/target/debug/enclave-vsock-staging}"
PORT="${TWOD_HSM_VSOCK_PORT:-5000}"

if [[ ! -x "$BIN" ]]; then
  echo "Build first: cd impl/rust/enclave-protocol && cargo build --bin enclave-vsock-staging --features staging-vsock"
  exit 1
fi

pkill -f '[/]enclave-vsock-staging' 2>/dev/null || true
sleep 2

env TWOD_HSM_VSOCK_CID=1 "TWOD_HSM_VSOCK_PORT=$PORT" nohup "$BIN" >/tmp/enclave-vsock-staging.log 2>&1 &
sleep 1
grep -q listening /tmp/enclave-vsock-staging.log || { cat /tmp/enclave-vsock-staging.log; exit 1; }

export VSOCK_CID=1
export TWOD_HSM_VSOCK_PORT="$PORT"
export VSOCK_SMOKE_MEASUREMENT_MARKER=prod-enclave-v1
export VSOCK_SMOKE_TIMEOUT=5
export VSOCK_SMOKE_LABEL=host-loopback-smoke
python3 "$SCRIPT_DIR/vsock_smoke_client.py"

pkill -f '[/]enclave-vsock-staging' 2>/dev/null || true
echo "host-loopback-smoke: passed"