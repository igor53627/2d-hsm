#!/usr/bin/env bash
# TASK-5 Phase 1: production enclave-vsock in NixOS guest (lab trust VK).
set -euo pipefail

export VM_FLAKE_ATTR="${VM_FLAKE_ATTR:-vm-production}"
export VSOCK_SMOKE_MEASUREMENT_MARKER="${VSOCK_SMOKE_MEASUREMENT_MARKER:-enclave-measurement-placeholder}"

exec "$(cd "$(dirname "$0")" && pwd)/run-nix-vm-guest-smoke.sh" "$@"