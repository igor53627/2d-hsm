#!/usr/bin/env bash
# Full SEV-SNP attested guest producer smoke (TASK-122 AC#3 full staging evidence)
#
# Starts a SEV-SNP guest VM, launches the staging enclave INSIDE the attested
# guest, then exercises all 4 producer commands via:
#   Elixir Chain.ProducerHsm.Wire → UDS → relay → vsock CID=42 → enclave
#
# This yields complete AC#3 evidence: 2D Elixir producer client → attested
# SEV-SNP guest enclave → real launch measurement + real ML-DSA-65 signature.
set -euo pipefail

SCRIPT_DIR="/root/2d-hsm/impl/scripts/aya-sev-snp"
SMOKE_DIR="/root/producer_smoke"
SSH_OPTS="-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null"

echo "=== Kill any prior VM/enclave/relay ==="
pkill -f 'qemu-system-x86_64.*guest-cid' 2>/dev/null || true
pkill -f '[/]enclave-vsock-staging' 2>/dev/null || true
pkill -f vsock_uds_relay 2>/dev/null || true
sleep 2

echo "=== Start SEV-SNP guest VM (CID=42, SSH :2222) ==="
cd "$SCRIPT_DIR"
DISK=vm-disk.qcow2 CLOUDINIT=cloud-init.iso \
  SEV_MODE=snp MEMORY=4096 VCPUS=2 \
  setsid ./run-guest-vm.sh >/tmp/guest-vm.log 2>&1 </dev/null &
VM_PID=$!
echo "Guest VM PID: $VM_PID"
sleep 5
if ! kill -0 "$VM_PID" 2>/dev/null; then
  echo "VM exited early:"; cat /tmp/guest-vm.log; exit 1
fi

echo "=== Wait for guest SSH (port 2222, up to 90s) ==="
GUEST_READY=0
for i in $(seq 1 90); do
  if ssh $SSH_OPTS -p 2222 ubuntu@127.0.0.1 "echo guest_ready" 2>/dev/null | grep -q guest_ready; then
    echo "Guest SSH up after ${i}s"
    GUEST_READY=1
    break
  fi
  sleep 1
  if ! kill -0 "$VM_PID" 2>/dev/null; then
    echo "VM died during SSH wait:"; tail -20 /tmp/guest-vm.log; exit 1
  fi
done
if [ "$GUEST_READY" -ne 1 ]; then
  echo "Guest SSH timeout (90s)"; tail -20 /tmp/guest-vm.log; exit 1
fi

echo "=== Start enclave inside SEV-SNP guest ==="
HSM_BIN=/root/2d-hsm/impl/rust/enclave-protocol/target/debug/enclave-vsock-staging \
  ./guest-start-hsm.sh 2>&1

echo "=== Start vsock↔UDS relay → CID=42 ==="
rm -f /tmp/phsm.sock
setsid python3 "$SMOKE_DIR/vsock_uds_relay.py" /tmp/phsm.sock 42 5000 >/tmp/relay.log 2>&1 </dev/null &
sleep 1
cat /tmp/relay.log

echo "=== Run Elixir producer smoke (via relay → CID=42 attested guest) ==="
cd "$SMOKE_DIR"
/opt/elixir-1.16/bin/elixir producer_vsock_smoke.exs 2>&1
SMOKE_EXIT=$?

echo "=== Cleanup ==="
pkill -f vsock_uds_relay 2>/dev/null || true
kill "$VM_PID" 2>/dev/null || true
pkill -f 'qemu-system-x86_64.*guest-cid' 2>/dev/null || true

echo "=== Guest VM log (last 10 lines) ==="
tail -10 /tmp/guest-vm.log

exit $SMOKE_EXIT
