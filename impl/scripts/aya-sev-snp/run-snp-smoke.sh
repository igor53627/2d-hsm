#!/usr/bin/env bash
# End-to-end: SEV-SNP guest + enclave-vsock-staging + host GET_MEASUREMENT
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export QEMU_BIN="${QEMU_BIN:-/opt/qemu-snp/bin/qemu-system-x86_64}"
export SEV_MODE="${SEV_MODE:-snp}"
export MEMORY="${MEMORY:-2048}"
export VCPUS="${VCPUS:-2}"
export GUEST_CID="${GUEST_CID:-42}"
export HSM_BIN="${HSM_BIN:-/root/2d-hsm/impl/rust/enclave-protocol/target/debug/enclave-vsock-staging}"

if [[ ! -x "$QEMU_BIN" ]] || ! "$QEMU_BIN" -object help 2>&1 | grep -q sev-snp-guest; then
  echo "Run ./install-qemu-snp.sh first (need sev-snp-guest)"
  exit 1
fi

[[ -f vm-disk.qcow2 ]] || ./setup-guest-image.sh
[[ -x "$HSM_BIN" ]] || {
  echo "Build: cd impl/rust/enclave-protocol && cargo build --bin enclave-vsock-staging --features staging-vsock"
  exit 1
}

killall qemu-system-x86_64 2>/dev/null || true
sleep 2

LOG=/tmp/hsm-snp-qemu.log
nohup ./run-guest-vm.sh >"$LOG" 2>&1 &
QEMU_PID=$!
echo "QEMU pid=$QEMU_PID log=$LOG"

for i in $(seq 1 90); do
  if grep -qE "does not accept value|failed to initialize|Error while" "$LOG" 2>/dev/null; then
    tail -20 "$LOG"
    exit 1
  fi
  if ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null \
    -p 2222 ubuntu@localhost "echo ok" 2>/dev/null; then
    break
  fi
  sleep 5
  [[ "$i" == 90 ]] && { tail -30 "$LOG"; exit 1; }
done

./guest-start-hsm.sh
./host-guest-vsock-smoke.sh
echo "run-snp-smoke: all passed (SEV_MODE=$SEV_MODE)"