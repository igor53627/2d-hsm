#!/usr/bin/env bash
# End-to-end: SEV-SNP guest + enclave-vsock-staging + host GET_MEASUREMENT
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$SCRIPT_DIR"
# shellcheck source=smoke-cache-lib.sh
source "$SCRIPT_DIR/smoke-cache-lib.sh"

export QEMU_BIN="${QEMU_BIN:-/opt/qemu-snp/bin/qemu-system-x86_64}"
export SEV_MODE="${SEV_MODE:-snp}"
export MEMORY="${MEMORY:-2048}"
export VCPUS="${VCPUS:-2}"
export GUEST_CID="${GUEST_CID:-42}"
export SNP_BIOS
SNP_BIOS="$(twod_hsm_snp_ovmf_path)"
export HSM_BIN
HSM_BIN="$(twod_hsm_snp_hsm_bin "$ROOT")"

if [[ ! -x "$QEMU_BIN" ]] || ! "$QEMU_BIN" -object help 2>&1 | grep -q sev-snp-guest; then
  echo "Run ./install-qemu-snp.sh first (need sev-snp-guest)" >&2
  exit 1
fi

use_golden=0
if [[ -f "$(twod_hsm_snp_golden_disk)" ]]; then
  use_golden=1
  export TWOD_HSM_SKIP_CLOUDINIT=1
fi
if ! twod_hsm_snp_prepare_work_disk "$SCRIPT_DIR"; then
  ./setup-guest-image.sh
  twod_hsm_snp_prepare_work_disk "$SCRIPT_DIR"
  use_golden=0
  unset TWOD_HSM_SKIP_CLOUDINIT
fi
if [[ "$use_golden" != "1" ]]; then
  ci_iso="$(twod_hsm_snp_cloudinit_iso)"
  [[ -f "$ci_iso" ]] && ln -sf "$ci_iso" "${SCRIPT_DIR}/cloud-init.iso"
fi

[[ -x "$HSM_BIN" ]] || {
  echo "Missing HSM binary: $HSM_BIN (run ./warm-smoke-cache.sh)" >&2
  exit 1
}

twod_hsm_stop_stale_qemu

QEMU_PID=""
cleanup() {
  if [[ -n "$QEMU_PID" ]] && kill -0 "$QEMU_PID" 2>/dev/null; then
    kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

LOG=/tmp/hsm-snp-qemu.log
: >"$LOG"
nohup ./run-guest-vm.sh >"$LOG" 2>&1 &
QEMU_PID=$!
echo "QEMU pid=$QEMU_PID log=$LOG bios=$SNP_BIOS"

ready_timeout="$(twod_hsm_snp_ssh_ready_timeout)"
# Golden disk: SSH is enough (ready marker may be absent on older bakes).
require_ready=0

if ! twod_hsm_wait_guest_ssh 2222 "$ready_timeout" "$LOG" "$require_ready"; then
  echo "run-snp-smoke: guest SSH/ready timeout (${ready_timeout}s)" >&2
  echo "  Hint: ./warm-smoke-cache.sh (bakes golden disk + fixes cloud-init)" >&2
  exit 1
fi

export HSM_BIN GUEST_WAIT_READY=0 GUEST_READY_TIMEOUT=30
export VSOCK_SMOKE_REQUIRE_PQ_READY="${VSOCK_SMOKE_REQUIRE_PQ_READY:-1}"
./guest-start-hsm.sh
./host-guest-vsock-smoke.sh
echo "run-snp-smoke: all passed (SEV_MODE=$SEV_MODE)"