#!/usr/bin/env bash
# From aya host: vsock connect to confidential guest (QEMU guest-cid)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUEST_CID="${GUEST_CID:-42}"
export GUEST_CID
export TWOD_HSM_VSOCK_PORT="${TWOD_HSM_VSOCK_PORT:-5000}"
# Staging GET_MEASUREMENT uses prod-enclave-v1; production profile uses enclave-measurement-placeholder.
export VSOCK_SMOKE_MEASUREMENT_MARKER="${VSOCK_SMOKE_MEASUREMENT_MARKER:-prod-enclave-v1}"
export VSOCK_SMOKE_LABEL="${VSOCK_SMOKE_LABEL:-host-guest-vsock-smoke}"

exec python3 "$SCRIPT_DIR/vsock_smoke_client.py"