#!/usr/bin/env bash
# Copy enclave-vsock-staging into running guest and start listener (VMADDR_CID_ANY)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=smoke-cache-lib.sh
source "$SCRIPT_DIR/smoke-cache-lib.sh"

SSH_PORT="${SSH_PORT:-2222}"
VM_HOST="${VM_HOST:-127.0.0.1}"
SSH_OPTS="$(twod_hsm_ssh_opts)"
ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
BIN="${HSM_BIN:-$(twod_hsm_default_hsm_bin "$ROOT")}"
GUEST_DIR="${GUEST_DIR:-/opt/2d-hsm}"
WAIT_READY="${GUEST_WAIT_READY:-0}"
READY_TIMEOUT="${GUEST_READY_TIMEOUT:-60}"

[[ -x "$BIN" ]] || { echo "Missing binary: $BIN"; exit 1; }

echo "Waiting for guest SSH on port ${SSH_PORT}..."
if ! twod_hsm_wait_guest_ssh "$SSH_PORT" "$READY_TIMEOUT" "" "$WAIT_READY"; then
  echo "guest-start-hsm: SSH/ready timeout" >&2
  exit 1
fi

ssh $SSH_OPTS -p "$SSH_PORT" "ubuntu@${VM_HOST}" \
  "sudo mkdir -p ${GUEST_DIR} && sudo chown ubuntu:ubuntu ${GUEST_DIR}"
# Upload via /tmp (avoids permission errors overwriting prior smoke binaries).
scp $SSH_OPTS -P "$SSH_PORT" "$BIN" "ubuntu@${VM_HOST}:/tmp/enclave-vsock-staging.upload"
ssh $SSH_OPTS -p "$SSH_PORT" "ubuntu@${VM_HOST}" \
  "sudo install -m755 -o ubuntu -g ubuntu /tmp/enclave-vsock-staging.upload ${GUEST_DIR}/enclave-vsock-staging && rm -f /tmp/enclave-vsock-staging.upload"

ssh $SSH_OPTS -p "$SSH_PORT" "ubuntu@${VM_HOST}" \
  "pkill -f '[/]enclave-vsock-staging' 2>/dev/null || true; \
   nohup env TWOD_HSM_VSOCK_CID=42 TWOD_HSM_VSOCK_PORT=5000 \
   ${GUEST_DIR}/enclave-vsock-staging > /tmp/enclave-vsock-staging.log 2>&1 & \
   sleep 2; grep listening /tmp/enclave-vsock-staging.log || cat /tmp/enclave-vsock-staging.log"

echo "guest-start-hsm: server should be listening inside SEV guest"