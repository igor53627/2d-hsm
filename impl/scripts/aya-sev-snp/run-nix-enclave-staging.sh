#!/usr/bin/env bash
# Build (or reuse) Nix enclave-staging and run vsock smokes on aya.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FLAKE_DIR="$ROOT/impl/nix/vm-hsm"
# shellcheck source=smoke-cache-lib.sh
source "$SCRIPT_DIR/smoke-cache-lib.sh"

OUT_LINK="${NIX_ENCLAVE_STAGING_LINK:-$(twod_hsm_cache_nix)/enclave-staging}"

if ! command -v nix >/dev/null; then
  echo "nix not found; install Determinate Nix first" >&2
  exit 1
fi

cd "$FLAKE_DIR"

echo "[1/3] nix .#enclave-staging -> $OUT_LINK"
OUT_LINK="$(twod_hsm_nix_ensure "$FLAKE_DIR" enclave-staging enclave-staging)"

export HSM_BIN="$OUT_LINK/bin/enclave-vsock-staging"
echo "[2/3] host-loopback-smoke (HSM_BIN=$HSM_BIN)"
"$ROOT/impl/scripts/aya-sev-snp/host-loopback-smoke.sh"

if [ "${RUN_GUEST_SMOKE:-0}" = "1" ]; then
  echo "[3/3] host-guest-vsock-smoke"
  "$ROOT/impl/scripts/aya-sev-snp/host-guest-vsock-smoke.sh"
else
  echo "[3/3] skip host-guest-vsock-smoke (set RUN_GUEST_SMOKE=1 to enable)"
fi

echo "run-nix-enclave-staging: passed"