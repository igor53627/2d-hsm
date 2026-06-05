#!/usr/bin/env bash
# TASK-5 Phase 2: production enclave + lab PQ seal (pq_signing_ready).
set -euo pipefail

export VM_FLAKE_ATTR="${VM_FLAKE_ATTR:-vm-production-lab}"
export VSOCK_SMOKE_MEASUREMENT_MARKER="${VSOCK_SMOKE_MEASUREMENT_MARKER:-enclave-measurement-placeholder}"
export VSOCK_SMOKE_REQUIRE_PQ_READY="${VSOCK_SMOKE_REQUIRE_PQ_READY:-1}"

exec "$(cd "$(dirname "$0")" && pwd)/run-nix-vm-guest-smoke.sh" "$@"