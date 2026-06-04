#!/usr/bin/env bash
# Phase B: NixOS vm-hsm in QEMU + host→guest vsock GET_MEASUREMENT smoke.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FLAKE_DIR="$ROOT/impl/nix/vm-hsm"
VM_FLAKE_ATTR="${VM_FLAKE_ATTR:-vm}"
VM_LINK="${VM_LINK:-/tmp/vm-hsm-runner}"
DISK_IMAGE="${NIX_DISK_IMAGE:-/tmp/vm-hsm-smoke.qcow2}"
GUEST_CID="${GUEST_CID:-42}"
TWOD_HSM_VSOCK_PORT="${TWOD_HSM_VSOCK_PORT:-5000}"
BOOT_TIMEOUT_SEC="${BOOT_TIMEOUT_SEC:-180}"
LOG="${VM_HSM_LOG:-/tmp/vm-hsm-guest-smoke.log}"
VM_PID_FILE="${VM_PID_FILE:-${DISK_IMAGE}.pid}"

if command -v nix >/dev/null; then
  [ -e /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh ] \
    && . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
fi

cleanup() {
  if [[ -f "$VM_PID_FILE" ]]; then
    old_pid="$(cat "$VM_PID_FILE" 2>/dev/null || true)"
    if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
      kill "$old_pid" 2>/dev/null || true
      wait "$old_pid" 2>/dev/null || true
    fi
    rm -f "$VM_PID_FILE"
  fi
}
trap cleanup EXIT

cleanup
: >"$LOG"

cd "$FLAKE_DIR"
echo "[1/4] nix build .#${VM_FLAKE_ATTR} -> $VM_LINK"
nix build ".#${VM_FLAKE_ATTR}" --out-link "$VM_LINK"

RUNNER=""
for candidate in "$VM_LINK"/bin/run-*-vm "$VM_LINK"/bin/*run*nixos*; do
  if [ -e "$candidate" ]; then
    RUNNER=$(readlink -f "$candidate")
    break
  fi
done
if [ -z "$RUNNER" ] || [ ! -x "$RUNNER" ]; then
  echo "could not find run-nixos-vm under $VM_LINK/bin" >&2
  ls -la "$VM_LINK/bin" >&2 || true
  exit 1
fi
echo "[2/4] starting NixOS vm-hsm (runner=$RUNNER, disk=$DISK_IMAGE, cid=$GUEST_CID)"

export NIX_DISK_IMAGE="$DISK_IMAGE"
# Headless on servers (no GTK); vsock for host↔guest smoke.
export QEMU_OPTS="${QEMU_OPTS:-} -display none -device vhost-vsock-pci,guest-cid=${GUEST_CID}"

nohup "$RUNNER" </dev/null >>"$LOG" 2>&1 &
VM_PID=$!
echo "$VM_PID" >"$VM_PID_FILE"
echo "VM pid=$VM_PID log=$LOG pidfile=$VM_PID_FILE"

echo "[3/4] waiting for guest vsock (up to ${BOOT_TIMEOUT_SEC}s)"
deadline=$((SECONDS + BOOT_TIMEOUT_SEC))
ok=0
while [ "$SECONDS" -lt "$deadline" ]; do
  if ! kill -0 "$VM_PID" 2>/dev/null; then
    echo "VM process exited early; tail log:" >&2
    tail -40 "$LOG" >&2 || true
    exit 1
  fi
  # Enclave logs go to journal, not always serial — probe vsock directly.
  if GUEST_CID="$GUEST_CID" TWOD_HSM_VSOCK_PORT="$TWOD_HSM_VSOCK_PORT" "$SCRIPT_DIR/host-guest-vsock-smoke.sh" 2>/dev/null; then
    ok=1
    break
  fi
  sleep 5
done

if [ "$ok" != 1 ]; then
  echo "guest vsock smoke timed out; log tail:" >&2
  tail -100 "$LOG" >&2 || true
  exit 1
fi

echo "[4/4] host-guest-vsock-smoke: passed (NixOS vm-hsm, .#${VM_FLAKE_ATTR})"