#!/usr/bin/env bash
# Copy enclave-vsock-staging into running guest and start listener (VMADDR_CID_ANY)
set -euo pipefail

SSH_PORT="${SSH_PORT:-2222}"
VM_HOST="${VM_HOST:-localhost}"
BIN="${HSM_BIN:-/root/2d-hsm/impl/rust/enclave-protocol/target/debug/enclave-vsock-staging}"
GUEST_DIR="${GUEST_DIR:-/opt/2d-hsm}"

[[ -x "$BIN" ]] || { echo "Missing binary: $BIN"; exit 1; }

echo "Waiting for guest SSH on port ${SSH_PORT}..."
for i in $(seq 1 60); do
  if ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no -p "$SSH_PORT" "ubuntu@${VM_HOST}" "echo ok" 2>/dev/null; then
    break
  fi
  sleep 5
  [[ "$i" == 60 ]] && { echo "SSH timeout"; exit 1; }
done

ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "ubuntu@${VM_HOST}" "sudo mkdir -p ${GUEST_DIR} && sudo chown ubuntu:ubuntu ${GUEST_DIR}"
scp -o StrictHostKeyChecking=no -P "$SSH_PORT" "$BIN" "ubuntu@${VM_HOST}:${GUEST_DIR}/enclave-vsock-staging"

ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "ubuntu@${VM_HOST}" \
  "pkill -f '[/]enclave-vsock-staging' 2>/dev/null || true; \
   nohup env 2D_HSM_VSOCK_CID=4294967295 2D_HSM_VSOCK_PORT=5000 \
   ${GUEST_DIR}/enclave-vsock-staging > /tmp/enclave-vsock-staging.log 2>&1 & \
   sleep 2; grep listening /tmp/enclave-vsock-staging.log || cat /tmp/enclave-vsock-staging.log"

echo "guest-start-hsm: server should be listening inside SEV guest"