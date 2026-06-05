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
BIN="${HSM_BIN:-$(twod_hsm_snp_hsm_bin "$ROOT")}"
GUEST_DIR="${GUEST_DIR:-/opt/2d-hsm}"
# Inside the VM, bind VMADDR_CID_ANY; host still connects to QEMU guest-cid (default 42).
BIND_CID="${TWOD_HSM_VSOCK_BIND_CID:-4294967295}"
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

if ! ssh $SSH_OPTS -p "$SSH_PORT" "ubuntu@${VM_HOST}" bash -s <<GUEST_START
set -e
pkill -f '[/]enclave-vsock-staging' 2>/dev/null || true
: > /tmp/enclave-vsock-staging.log
nohup env TWOD_HSM_VSOCK_CID=${BIND_CID} TWOD_HSM_VSOCK_PORT=5000 \
  ${GUEST_DIR}/enclave-vsock-staging >>/tmp/enclave-vsock-staging.log 2>&1 </dev/null &
sleep 3
cat /tmp/enclave-vsock-staging.log
pgrep -fa enclave-vsock-staging
GUEST_START
then
  echo "guest-start-hsm: failed to start enclave in guest" >&2
  exit 1
fi

echo "guest-start-hsm: server should be listening inside SEV guest"