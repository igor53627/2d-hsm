#!/usr/bin/env bash
# TASK-5 Phase 1: production enclave-vsock in NixOS guest (lab trust VK).
set -euo pipefail

export VM_FLAKE_ATTR="${VM_FLAKE_ATTR:-vm-production}"
export VM_LINK="${VM_LINK:-/tmp/vm-hsm-runner-prod}"
export NIX_DISK_IMAGE="${NIX_DISK_IMAGE:-/tmp/vm-hsm-smoke-prod.qcow2}"
export VM_HSM_LOG="${VM_HSM_LOG:-/tmp/vm-hsm-guest-smoke-prod.log}"
export VSOCK_SMOKE_MEASUREMENT_MARKER="${VSOCK_SMOKE_MEASUREMENT_MARKER:-enclave-measurement-placeholder}"

exec "$(cd "$(dirname "$0")" && pwd)/run-nix-vm-guest-smoke.sh" "$@"