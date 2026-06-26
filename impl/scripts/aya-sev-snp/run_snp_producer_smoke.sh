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

case "${1:-}" in
  -h|--help)
    cat <<'USAGE'
Full SEV-SNP attested guest producer smoke (TASK-122 AC#3).
Starts a SEV-SNP guest VM (guest-cid=42, SSH :2222), launches the staging enclave
inside the attested guest, and drives all 4 producer commands via the Elixir
client through a vsock<->UDS relay.

Requires SEV-SNP hardware and the /root/2d-hsm staging layout (hard-coded paths);
it starts and kills a guest VM, so run it ONLY on an exclusive staging host.
USAGE
    exit 0
    ;;
esac

SCRIPT_DIR="/root/2d-hsm/impl/scripts/aya-sev-snp"
SMOKE_DIR="/root/producer_smoke"
SSH_OPTS="-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null"
GUEST_CID=42
VM_PIDFILE=/tmp/snp_producer_smoke_vm.pid
VM_PID=""
RELAY_PID=""
# Tear down via tracked PIDs (the VM is setsid-launched, so VM_PID is its process
# group leader) — never a global `pkill qemu`, which would also kill unrelated SNP
# guests that share the qemu cmdline (guest CID cannot disambiguate them).
cleanup() {
  [ -n "$RELAY_PID" ] && kill "$RELAY_PID" 2>/dev/null || true
  if [ -n "$VM_PID" ]; then
    kill -- -"$VM_PID" 2>/dev/null || kill "$VM_PID" 2>/dev/null || true
  fi
  rm -f "$VM_PIDFILE"
}
trap cleanup EXIT

echo "=== Tear down a prior run of THIS smoke (tracked pid-file, not global pkill) ==="
if [ -f "$VM_PIDFILE" ]; then
  kill -- -"$(cat "$VM_PIDFILE")" 2>/dev/null || true
  rm -f "$VM_PIDFILE"
fi
sleep 1

echo "=== Start SEV-SNP guest VM (CID=42, SSH :2222) ==="
cd "$SCRIPT_DIR"
DISK=vm-disk.qcow2 CLOUDINIT=cloud-init.iso \
  SEV_MODE=snp MEMORY=4096 VCPUS=2 \
  setsid ./run-guest-vm.sh >/tmp/guest-vm.log 2>&1 </dev/null &
VM_PID=$!
echo "$VM_PID" > "$VM_PIDFILE"
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
RELAY_PID=$!
sleep 1
cat /tmp/relay.log

echo "=== Run Elixir producer smoke (via relay → CID=42 attested guest) ==="
cd "$SMOKE_DIR"
SMOKE_EXIT=0
/opt/elixir-1.16/bin/elixir producer_vsock_smoke.exs 2>&1 || SMOKE_EXIT=$?

echo "=== Cleanup (handled by the EXIT trap: tracked VM process group + relay) ==="

echo "=== Guest VM log (last 10 lines) ==="
tail -10 /tmp/guest-vm.log

exit $SMOKE_EXIT
