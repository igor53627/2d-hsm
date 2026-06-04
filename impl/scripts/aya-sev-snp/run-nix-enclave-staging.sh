#!/usr/bin/env bash
# Build (or reuse) Nix enclave-staging and run vsock smokes on aya.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
FLAKE_DIR="$ROOT/impl/nix/vm-hsm"
OUT_LINK="${NIX_ENCLAVE_STAGING_LINK:-/root/enclave-staging}"

if command -v nix >/dev/null; then
  # shellcheck source=/dev/null
  [ -e /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh ] \
    && . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
fi

if ! command -v nix >/dev/null; then
  echo "nix not found; install Determinate Nix first" >&2
  exit 1
fi

cd "$FLAKE_DIR"
if [ -d "$ROOT/.git" ]; then
  git -C "$ROOT" add -f impl/nix/vm-hsm impl/rust/enclave-protocol/Cargo.lock \
    impl/rust/enclave-protocol/Cargo.toml \
    impl/rust/enclave-protocol/src/bin/enclave_vsock.rs \
    impl/rust/enclave-protocol/src/lib.rs 2>/dev/null || true
fi

echo "[1/3] nix build .#enclave-staging -> $OUT_LINK"
nix build .#enclave-staging --out-link "$OUT_LINK"

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