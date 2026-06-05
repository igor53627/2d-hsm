#!/usr/bin/env bash
# Phase B: NixOS vm-hsm in QEMU + host→guest vsock GET_MEASUREMENT smoke.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FLAKE_DIR="$ROOT/impl/nix/vm-hsm"
# shellcheck source=smoke-cache-lib.sh
source "$SCRIPT_DIR/smoke-cache-lib.sh"

VM_FLAKE_ATTR="${VM_FLAKE_ATTR:-vm}"
VM_LINK="${VM_LINK:-$(twod_hsm_nix_vm_link "$VM_FLAKE_ATTR")}"
DISK_IMAGE="${NIX_DISK_IMAGE:-$(twod_hsm_nix_vm_disk "$VM_FLAKE_ATTR")}"
GUEST_CID="${GUEST_CID:-42}"
TWOD_HSM_VSOCK_PORT="${TWOD_HSM_VSOCK_PORT:-5000}"
BOOT_TIMEOUT_SEC="${BOOT_TIMEOUT_SEC:-180}"
LOG="${VM_HSM_LOG:-/tmp/vm-hsm-guest-smoke-${VM_FLAKE_ATTR}.log}"
VM_PID_FILE="${VM_PID_FILE:-${DISK_IMAGE}.pid}"

twod_hsm_ensure_python_cbor2

twod_hsm_kill_vm_pid_if_ours() {
  local pid=$1
  [[ -n "$pid" ]] || return 0
  kill -0 "$pid" 2>/dev/null || return 0
  local cmdline=""
  if [[ -r "/proc/${pid}/cmdline" ]]; then
    cmdline="$(tr '\0' ' ' <"/proc/${pid}/cmdline")"
  fi
  if [[ "$cmdline" == *qemu-system* ]] || [[ "$cmdline" == *run-*-vm* ]] || [[ "$cmdline" == *run*nixos* ]]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
}

cleanup() {
  if [[ -f "$VM_PID_FILE" ]]; then
    old_pid="$(cat "$VM_PID_FILE" 2>/dev/null || true)"
    twod_hsm_kill_vm_pid_if_ours "$old_pid"
    rm -f "$VM_PID_FILE"
  fi
}
trap cleanup EXIT

cleanup
twod_hsm_stop_stale_qemu
: >"$LOG"

cd "$FLAKE_DIR"
echo "[1/4] nix .#${VM_FLAKE_ATTR} -> $VM_LINK"
VM_LINK="$(twod_hsm_nix_ensure "$FLAKE_DIR" "$VM_FLAKE_ATTR" "vm-hsm-runner-${VM_FLAKE_ATTR}")"

RUNNER="$(twod_hsm_find_vm_runner "$VM_LINK")"
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
  if GUEST_CID="$GUEST_CID" TWOD_HSM_VSOCK_PORT="$TWOD_HSM_VSOCK_PORT" \
    "$SCRIPT_DIR/host-guest-vsock-smoke.sh" 2>/dev/null; then
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